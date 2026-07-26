"use strict";

const { randomId } = require("../lib/crypto");
const { encodeJson } = require("../lib/lists");

// Append-only security log.
//
// What must never reach this table: access, refresh, or ID tokens; authorization
// codes; session cookies; `state`, `nonce`, or PKCE verifiers; client secrets;
// private keys; passwords. A log that records a credential turns read access to
// the log into the credential itself.
//
// `metadata` is therefore filtered rather than trusted. The check is by key name
// against a deny list, so a new call site cannot leak a secret by naming a field
// carelessly. It is a backstop, not a licence to pass secrets.

const FORBIDDEN_METADATA_KEYS = [
  "token",
  "secret",
  "password",
  "code",
  "nonce",
  "state",
  "verifier",
  "challenge",
  "cookie",
  "authorization",
  "jwk",
  "key",
  "assertion",
  "ticket",
  "credential"
];

const MAX_METADATA_LENGTH = 4000;

function isForbiddenKey(key) {
  const name = String(key).toLowerCase();
  // Substring rather than exact match: `client_secret`, `refresh_token`, and
  // `code_verifier` all have to be caught.
  return FORBIDDEN_METADATA_KEYS.some((forbidden) => name.includes(forbidden));
}

/** Strips forbidden keys at every depth and replaces the value with a marker. */
function sanitizeMetadata(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (depth > 4) return "[too deep]";
  if (Array.isArray(value)) return value.slice(0, 50).map((entry) => sanitizeMetadata(entry, depth + 1));
  if (typeof value === "object") {
    const result = {};
    for (const [key, entry] of Object.entries(value)) {
      // `token_endpoint_auth_method` and `grant_types` name a mechanism rather
      // than a secret, and are worth keeping in an audit trail. They are
      // allow-listed explicitly so the deny list can stay blunt.
      const allowed = ["token_endpoint_auth_method", "token_use", "grant_types", "codeChallengeMethod"];
      if (!allowed.includes(key) && isForbiddenKey(key)) {
        result[key] = "[redacted]";
        continue;
      }
      result[key] = sanitizeMetadata(entry, depth + 1);
    }
    return result;
  }
  if (typeof value === "string") return value.length > 500 ? `${value.slice(0, 500)}…` : value;
  return value;
}

/** Truncates a user agent; the full string is of no forensic value at length. */
function truncate(value, max) {
  const text = String(value || "").trim();
  if (!text) return null;
  return text.length > max ? text.slice(0, max) : text;
}

function createAuditService({ prisma, logger = console, enabled = true } = {}) {
  /**
   * Records an event.
   *
   * Never throws. An audit write failing must not fail the operation being
   * audited — refusing a login because a log insert failed would turn a logging
   * problem into an outage. The failure is reported to the process log instead.
   */
  async function record({
    action,
    actorUserId = null,
    targetUserId = null,
    targetType = "system",
    targetId = null,
    metadata = null,
    ipAddress = null,
    userAgent = null
  } = {}) {
    if (!enabled || !action) return null;
    try {
      const sanitized = metadata ? sanitizeMetadata(metadata) : null;
      let metadataJson = encodeJson(sanitized);
      if (metadataJson && metadataJson.length > MAX_METADATA_LENGTH) {
        metadataJson = encodeJson({ truncated: true });
      }
      return await prisma.auditLog.create({
        data: {
          id: randomId(),
          action: String(action).slice(0, 100),
          actorUserId: actorUserId || null,
          targetUserId: targetUserId || null,
          targetType: String(targetType || "system").slice(0, 50),
          targetId: targetId ? String(targetId).slice(0, 200) : null,
          metadataJson,
          ipAddress: truncate(ipAddress, 64),
          userAgent: truncate(userAgent, 300)
        }
      });
    } catch (error) {
      logger.error?.(`[audit] failed to record ${action}: ${error.message}`);
      return null;
    }
  }

  async function list({ take = 100, skip = 0, action = "", userId = "" } = {}) {
    const where = {};
    if (action) where.action = String(action);
    if (userId) where.OR = [{ actorUserId: String(userId) }, { targetUserId: String(userId) }];
    const [records, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: "desc" },
        take: Math.min(Math.max(Number(take) || 100, 1), 500),
        skip: Math.max(Number(skip) || 0, 0)
      }),
      prisma.auditLog.count({ where })
    ]);
    return { entries: records, total };
  }

  /**
   * Deletes entries older than the retention window. Not called automatically:
   * how long a security log is kept is a policy and sometimes a legal question,
   * so it is the operator's to make.
   */
  async function prune({ olderThanDays = 365 } = {}) {
    const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);
    return prisma.auditLog.deleteMany({ where: { createdAt: { lt: cutoff } } });
  }

  return { list, prune, record };
}

module.exports = { createAuditService, sanitizeMetadata };

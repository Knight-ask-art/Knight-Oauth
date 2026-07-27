"use strict";

const { hashToken, randomId, randomToken } = require("../lib/crypto");
const { decodeJson, encodeJson } = require("../lib/lists");

// Browser sessions at this issuer.
//
// This is the authentication an authorization request is measured against: it is
// what `auth_time` reports, what `max_age` and `prompt=login` are compared
// against, and what `sid` in an ID token identifies.
//
// The cookie value is stored only as a SHA-256 hash. A session identifier is a
// bearer credential — anyone holding it is the user — so a database dump, a log
// line, or a backup must not be enough to impersonate someone. The lookup is by
// hash, which costs one indexed read and no more than storing it plainly would.
//
// Session fixation is handled by never reusing an identifier across a privilege
// change: logging in issues a new one and destroys the old, so a value planted
// before authentication is worthless after it.

// Two names for one cookie, and which is used depends on the scheme.
//
// `__Host-` is a browser-enforced contract, not decoration (RFC 6265bis section
// 4.1.3.2): a cookie whose name carries it is rejected unless it is Secure, has
// Path=/, and has *no* Domain attribute. The last one is the point. Without it,
// anything under the same registrable domain — a user-content subdomain, a
// dangling CNAME, an XSS on app.example.com while the issuer is on
// auth.example.com — can send `Set-Cookie: koauth_session=...; Domain=example.com;
// Path=/account/password`, and RFC 6265 section 5.4 has the browser serialise
// the longer path first, so the planted value is the one this server reads.
//
// The prefix is only legal on Secure cookies, so a local http deployment keeps
// the bare name — where the attack needs a sibling host on the same domain that
// http://127.0.0.1 does not have.
const SESSION_COOKIE = "koauth_session";
const SESSION_COOKIE_SECURE = `__Host-${SESSION_COOKIE}`;

function createSessionService({ prisma, config, auditLog, now = () => new Date() } = {}) {
  const defaultTtlSeconds = config?.ttl?.sessionSeconds ?? 24 * 60 * 60;
  const rememberTtlSeconds = config?.ttl?.rememberMeSeconds ?? 30 * 24 * 60 * 60;
  // `Secure` follows the issuer's scheme rather than NODE_ENV: a production
  // deployment on https gets it, and a local http deployment must not, or the
  // browser silently discards the cookie and nobody can log in.
  const secureCookies = String(config?.publicBaseUrl || "").startsWith("https:");
  const cookieName = secureCookies ? SESSION_COOKIE_SECURE : SESSION_COOKIE;

  function cookieOptions(maxAgeMs) {
    return {
      httpOnly: true,
      // Lax, not Strict. The authorization endpoint is reached by a
      // cross-site top-level redirect from the relying party, and Strict would
      // withhold the cookie on exactly that navigation, breaking every login
      // that starts at a client. CSRF is handled by tokens, not by SameSite.
      sameSite: "lax",
      secure: secureCookies,
      path: "/",
      maxAge: maxAgeMs
    };
  }

  /**
   * Clears both spellings. The unprefixed one is never read once the prefixed
   * one is in use, but leaving it in the browser until it expires would be
   * untidy at best and confusing to anyone reading their own cookie jar.
   */
  function clearSessionCookie(res) {
    res?.clearCookie?.(cookieName, { path: "/" });
    if (secureCookies) res?.clearCookie?.(SESSION_COOKIE, { path: "/" });
  }

  function toSession(record) {
    if (!record) return null;
    return {
      id: record.id,
      userId: record.userId || null,
      data: decodeJson(record.dataJson, {}) || {},
      expiresAt: record.expiresAt,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      // `authTime` is when this session authenticated, which is what OIDC
      // `auth_time` must report — not the time of the current request.
      authTime: record.createdAt
    };
  }

  async function find(sid) {
    const raw = String(sid || "").trim();
    if (!raw) return null;
    const record = await prisma.session.findUnique({ where: { sidHash: hashToken(raw) } });
    if (!record) return null;
    if (record.expiresAt <= now()) {
      // Expiry is enforced on read as well as by the sweeper, so a stale row can
      // never authenticate a request even if pruning has not run.
      await prisma.session.deleteMany({ where: { id: record.id } });
      return null;
    }
    return toSession(record);
  }

  /**
   * Creates an authenticated session and returns the cookie value.
   *
   * The caller is expected to destroy any existing session first; `login` below
   * does that. The raw value is returned once and never stored.
   */
  async function create({ userId, remember = false, data = {}, ipAddress, userAgent } = {}) {
    const sid = randomToken();
    const ttlSeconds = remember ? rememberTtlSeconds : defaultTtlSeconds;
    const record = await prisma.session.create({
      data: {
        id: randomId(),
        sidHash: hashToken(sid),
        userId: userId || null,
        dataJson: encodeJson({ ...data, remember: Boolean(remember) }),
        ipAddress: ipAddress ? String(ipAddress).slice(0, 64) : null,
        userAgent: userAgent ? String(userAgent).slice(0, 300) : null,
        expiresAt: new Date(now().getTime() + ttlSeconds * 1000)
      }
    });
    return { sid, session: toSession(record), maxAgeMs: ttlSeconds * 1000 };
  }

  /**
   * Signs a user in: destroys whatever session the browser presented and issues
   * a fresh one. Replacing the identifier at the privilege boundary is what
   * closes session fixation.
   */
  async function login({ res, currentSid, userId, remember = false, ipAddress, userAgent } = {}) {
    if (currentSid) {
      await prisma.session.deleteMany({ where: { sidHash: hashToken(currentSid) } });
    }
    const { sid, session, maxAgeMs } = await create({ userId, remember, ipAddress, userAgent });
    res?.cookie?.(cookieName, sid, cookieOptions(maxAgeMs));
    return { sid, session };
  }

  /**
   * Signs a user out.
   *
   * Per-client OIDC sessions are revoked with a reason so back-channel logout
   * has something to send. Refresh-token rows are not rewritten here. The
   * revoked OIDC session makes them inactive at exchange and introspection,
   * while retaining their family history for replay detection. Ending every
   * grant is a separate, explicit action.
   */
  async function logout({ res, sid, reason = "user_logout" } = {}) {
    const raw = String(sid || "").trim();
    if (!raw) {
      clearSessionCookie(res);
      return { loggedOut: false, sessionId: null };
    }
    const sidHash = hashToken(raw);
    const timestamp = now();
    const record = await prisma.$transaction(async (transaction) => {
      const current = await transaction.session.findUnique({ where: { sidHash } });
      if (!current) return null;

      // Session is the shared first lock for browser logout, remote revoke, and
      // account-wide credential revocation. OIDC follows in the same
      // transaction, so either failure rolls both state changes back.
      const removed = await transaction.session.deleteMany({
        where: { id: current.id, sidHash }
      });
      if (!removed.count) return null;
      await transaction.oidcSession.updateMany({
        where: { sessionId: current.id, revokedAt: null },
        data: { revokedAt: timestamp, revocationReason: reason }
      });
      return current;
    });

    if (record) {
      await auditLog?.record({
        action: "session.logout",
        actorUserId: record.userId,
        targetType: "session",
        targetId: record.id,
        metadata: { reason }
      });
    }

    clearSessionCookie(res);
    return { loggedOut: Boolean(record), sessionId: record?.id || null };
  }

  /** Merges values into session data. Small, non-secret state only. */
  async function update({ sessionId, data }) {
    const record = await prisma.session.findUnique({ where: { id: String(sessionId) } });
    if (!record) return null;
    const merged = { ...(decodeJson(record.dataJson, {}) || {}), ...(data || {}) };
    return toSession(
      await prisma.session.update({
        where: { id: record.id },
        data: { dataJson: encodeJson(merged) }
      })
    );
  }

  /**
   * Extends a session's expiry on activity, so an active user is not signed out
   * mid-task. The cookie is re-issued to match. Only refreshes past the halfway
   * point of the window, to avoid a database write on every request.
   */
  async function touch({ res, sid, session }) {
    if (!session) return null;
    const ttlSeconds = session.data?.remember ? rememberTtlSeconds : defaultTtlSeconds;
    const remaining = session.expiresAt.getTime() - now().getTime();
    if (remaining > (ttlSeconds * 1000) / 2) return session;

    const expiresAt = new Date(now().getTime() + ttlSeconds * 1000);
    const record = await prisma.session.update({
      where: { id: session.id },
      data: { expiresAt }
    });
    res?.cookie?.(cookieName, sid, cookieOptions(ttlSeconds * 1000));
    return toSession(record);
  }

  /** Every active session for a user, for a "signed in on these devices" view. */
  async function listForUser(userId) {
    const records = await prisma.session.findMany({
      where: { userId: String(userId || ""), expiresAt: { gt: now() } },
      orderBy: { createdAt: "desc" }
    });
    return records.map((record) => ({
      id: record.id,
      ipAddress: record.ipAddress,
      userAgent: record.userAgent,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt
    }));
  }

  /** Ends one session by id — for signing out a device from another device. */
  async function revoke({ sessionId, userId, reason = "user_revoked" } = {}) {
    const id = String(sessionId || "");
    const ownerId = String(userId || "");
    const timestamp = now();
    const record = await prisma.$transaction(async (transaction) => {
      const current = await transaction.session.findFirst({
        where: { id, userId: ownerId }
      });
      if (!current) return null;

      const removed = await transaction.session.deleteMany({
        where: { id: current.id, userId: ownerId }
      });
      if (!removed.count) return null;
      await transaction.oidcSession.updateMany({
        where: { sessionId: current.id, revokedAt: null },
        data: { revokedAt: timestamp, revocationReason: reason }
      });
      return current;
    });
    if (!record) return { revoked: false };
    return { revoked: true, sessionId: record.id };
  }

  async function pruneExpired() {
    return prisma.session.deleteMany({ where: { expiresAt: { lt: now() } } });
  }

  return {
    SESSION_COOKIE,
    /** The name actually in use, which depends on whether the issuer is https. */
    cookieName,
    cookieOptions,
    create,
    find,
    listForUser,
    login,
    logout,
    pruneExpired,
    revoke,
    touch,
    update
  };
}

module.exports = { SESSION_COOKIE, SESSION_COOKIE_SECURE, createSessionService };

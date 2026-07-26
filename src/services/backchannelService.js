"use strict";

const { randomId } = require("../lib/crypto");
const { signJwt } = require("../lib/jwt");

// OpenID Connect Back-Channel Logout 1.0.
//
// When a session ends, each client that has one is sent a signed logout token
// server-to-server, so it can drop its own session rather than discovering the
// logout on its next token refresh.
//
// Delivery is queued rather than attempted inline. A client whose endpoint is
// slow or down must not be able to hold up the user's logout, and a logout that
// silently fails because one client was unreachable is worse than one retried in
// the background. Rows are the queue; `deliveredAt` is the completion marker.

const LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

function createBackchannelService({
  prisma,
  config,
  clients,
  keys,
  auditLog,
  fetchImpl = globalThis.fetch,
  now = () => new Date()
} = {}) {
  const issuer = config.issuer;
  const settings = config.backchannel || {};
  const maxAttempts = settings.maxAttempts ?? 10;
  const retrySeconds = settings.retrySeconds ?? 60;
  const timeoutMs = settings.timeoutMs ?? 5000;

  /**
   * Queues a logout notification.
   *
   * Returns false when the client registered no endpoint — most clients do not,
   * and that is not a failure. The `jti` is minted here rather than at delivery
   * so a retry re-sends the same token: the spec requires a recipient to reject a
   * replayed `jti`, and a new one per attempt would look like a fresh event.
   */
  async function enqueue({ clientId, sessionId, userId, subject, reason = "logout" }) {
    const client = await clients.findByClientId(clientId);
    if (!client?.backchannelLogoutUri) return false;

    await prisma.backchannelLogout.create({
      data: {
        id: randomId(),
        clientId: client.clientId,
        sessionId: String(sessionId),
        userId: String(userId),
        subject: String(subject),
        reason: String(reason).slice(0, 100),
        jti: randomId()
      }
    });
    return true;
  }

  /**
   * Builds the logout token (Back-Channel Logout 1.0 section 2.4).
   *
   * `nonce` is prohibited — its presence is how a recipient tells a logout token
   * from an ID token, and accepting one where the other is expected is exactly
   * the confusion the prohibition prevents. `events` carries the logout event URI
   * with an empty member object.
   */
  async function buildLogoutToken(record) {
    const keyRing = await keys.ensureKeyRing();
    const issuedAt = Math.floor(now().getTime() / 1000);
    return signJwt({
      key: keyRing.activeKey,
      header: { typ: "logout+jwt" },
      claims: {
        iss: issuer,
        aud: record.clientId,
        iat: issuedAt,
        // Short-lived: this is delivered immediately and never held by a browser.
        exp: issuedAt + 120,
        jti: record.jti,
        events: { [LOGOUT_EVENT]: {} },
        sub: record.subject,
        sid: record.sessionId
      }
    });
  }

  /**
   * Sends one queued notification.
   *
   * A non-2xx response or a network error is recorded and left for a retry. Only
   * `attempts` exhaustion stops it, and the row stays for inspection — a logout
   * a client never acknowledged is something an operator should be able to see.
   */
  async function deliver(record) {
    const client = await clients.findByClientId(record.clientId);
    if (!client?.backchannelLogoutUri) {
      // The client dropped its endpoint after the row was queued; nothing to do.
      await prisma.backchannelLogout.update({
        where: { id: record.id },
        data: { deliveredAt: now(), lastError: "The client no longer registers a logout endpoint" }
      });
      return { delivered: false, reason: "no_endpoint" };
    }

    const token = await buildLogoutToken(record);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let status = 0;
    let failure = null;
    try {
      const response = await fetchImpl(client.backchannelLogoutUri, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          // The spec requires the request not be cached by an intermediary.
          "cache-control": "no-cache, no-store"
        },
        body: new URLSearchParams({ logout_token: token }).toString(),
        signal: controller.signal,
        redirect: "manual"
      });
      status = response.status;
      if (status < 200 || status >= 300) failure = `The endpoint answered ${status}`;
    } catch (error) {
      // The message may name a host, which is the client's own endpoint and not
      // sensitive. The token itself is never recorded.
      failure = error?.name === "AbortError" ? "The request timed out" : String(error?.message || "delivery failed");
    } finally {
      clearTimeout(timer);
    }

    const attempts = record.attempts + 1;
    if (!failure) {
      await prisma.backchannelLogout.update({
        where: { id: record.id },
        data: { attempts, lastAttemptAt: now(), deliveredAt: now(), lastError: null }
      });
      return { delivered: true, status };
    }

    await prisma.backchannelLogout.update({
      where: { id: record.id },
      data: { attempts, lastAttemptAt: now(), lastError: failure.slice(0, 300) }
    });
    if (attempts >= maxAttempts) {
      await auditLog?.record({
        action: "oauth.backchannel.exhausted",
        targetType: "client",
        targetId: record.clientId,
        metadata: { attempts, status }
      });
    }
    return { delivered: false, reason: failure, status };
  }

  /**
   * Delivers what is due: never attempted, or last attempted longer than the
   * retry interval ago and not yet out of attempts.
   */
  async function flush({ limit = 20 } = {}) {
    const cutoff = new Date(now().getTime() - retrySeconds * 1000);
    const pending = await prisma.backchannelLogout.findMany({
      where: {
        deliveredAt: null,
        attempts: { lt: maxAttempts },
        OR: [{ lastAttemptAt: null }, { lastAttemptAt: { lt: cutoff } }]
      },
      orderBy: { createdAt: "asc" },
      take: limit
    });

    let delivered = 0;
    let failed = 0;
    for (const record of pending) {
      // Sequential rather than concurrent: a burst of parallel POSTs from an
      // authorization server to many client endpoints is hard to distinguish from
      // an attack, and the queue is not latency-critical.
      const result = await deliver(record);
      if (result.delivered) delivered += 1;
      else failed += 1;
    }
    return { attempted: pending.length, delivered, failed };
  }

  /** Drops delivered rows and ones that ran out of attempts long ago. */
  async function pruneDelivered({ keepSeconds = 7 * 24 * 60 * 60 } = {}) {
    const cutoff = new Date(now().getTime() - keepSeconds * 1000);
    return prisma.backchannelLogout.deleteMany({
      where: {
        OR: [
          { deliveredAt: { lt: cutoff } },
          { attempts: { gte: maxAttempts }, lastAttemptAt: { lt: cutoff } }
        ]
      }
    });
  }

  return { LOGOUT_EVENT, buildLogoutToken, deliver, enqueue, flush, pruneDelivered };
}

module.exports = { LOGOUT_EVENT, createBackchannelService };

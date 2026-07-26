"use strict";

// Fixed-window rate limiting for the endpoints that cost something to answer.
//
// OAUTH_LOGIN_RATE_LIMIT_PER_MINUTE and OAUTH_TOKEN_RATE_LIMIT_PER_MINUTE were
// read, range-checked, and documented in .env.example long before anything
// consumed them. An operator could set them, watch the boot validate the
// values, and reasonably conclude they had a limiter; README and compose.yml
// both refer to "the rate limiter" as a thing that exists. This is that thing.
//
// Why it matters more here than on a typical form: every unauthenticated entry
// point below runs one full scrypt, and these parameters are deliberately
// expensive — N=2^17, r=8, which is 128 MiB of working set and, measured on a
// developer laptop, a little under 300 ms. `POST /login` pays it even for an
// address that does not exist, because paying it is what stops the response
// time from revealing whether the account is real. So the cost cannot be
// removed; it has to be metered.
//
// A fixed window rather than a sliding one or a token bucket: it is a Map, an
// integer, and a timestamp. The burst it permits at a window boundary — up to
// 2x the limit across two adjacent windows — is not worth a more elaborate
// structure here, where the limit exists to bound resource use rather than to
// shape traffic precisely.
//
// Single-process by design. A self-hosted issuer is one process; several
// replicas each get their own window, so the effective limit multiplies by the
// replica count. That is a deliberate floor, not an oversight — a shared
// counter would mean Redis, and this project has six production dependencies.
//
// The IP half of the key is only as trustworthy as TRUST_PROXY. With
// `trust proxy` enabled, Express reads the left-most X-Forwarded-For entry,
// which the client writes; .env.example already warns about this.

const DEFAULT_WINDOW_MS = 60_000;

// Above this many live keys, drop the expired ones. Sweeping on every request
// would be O(n) per request; this makes it amortised and bounds the Map by
// roughly the number of distinct callers within one window.
const SWEEP_AT = 10_000;

/**
 * A fixed-window counter.
 *
 * `hit` returns what the caller needs to answer with: whether the request is
 * allowed, and when the window resets.
 */
function createCounter({ windowMs = DEFAULT_WINDOW_MS, now = () => Date.now() } = {}) {
  const windows = new Map();

  function sweep(at) {
    for (const [key, entry] of windows) {
      if (entry.resetAt <= at) windows.delete(key);
    }
  }

  function hit(key, limit) {
    const at = now();
    if (windows.size > SWEEP_AT) sweep(at);

    const entry = windows.get(key);
    if (!entry || entry.resetAt <= at) {
      windows.set(key, { count: 1, resetAt: at + windowMs });
      return { allowed: true, remaining: limit - 1, retryAfterSeconds: Math.ceil(windowMs / 1000) };
    }

    entry.count += 1;
    const retryAfterSeconds = Math.max(1, Math.ceil((entry.resetAt - at) / 1000));
    return {
      allowed: entry.count <= limit,
      remaining: Math.max(0, limit - entry.count),
      retryAfterSeconds
    };
  }

  return { hit, get size() {
    return windows.size;
  } };
}

/**
 * The endpoints that are metered, and what identifies a caller at each.
 *
 * Two keys per rule, both counted and both required to pass. An IP alone lets
 * anyone with a botnet spread an attack across addresses; an identifier alone
 * lets one host work through a list of accounts a few tries each. Neither key
 * on its own bounds what the other permits.
 *
 * The identifier is folded to lower case because the accounts it names are
 * matched case-insensitively — otherwise `Ada@x` and `ada@x` are two budgets
 * for one account.
 */
function buildRules(security) {
  const login = security.loginRateLimitPerMinute;
  const token = security.tokenRateLimitPerMinute;

  return [
    // Runs a full scrypt on every request, including for an unknown identifier.
    { method: "POST", path: "/login", limit: login, identify: (body) => body.identifier },
    // Hashes before it knows whether the address is free, and must keep doing
    // so: hashing only for a free address would make response time answer
    // "is this address taken".
    { method: "POST", path: "/register", limit: login, identify: (body) => body.email },
    // Burns a hash for an unknown address so the timing does not distinguish it.
    { method: "POST", path: "/forgot-password", limit: login, identify: (body) => body.email },
    // No second key. The only caller-supplied value here is the reset token,
    // and it is a poor one twice over: it is a credential, so keying on it
    // would hold live tokens in memory for the length of a window, and every
    // guess is a different token, so the per-identifier budget would never be
    // spent by the brute force it would exist to slow. The address is bounded
    // by /forgot-password above; this one is bounded by the caller's.
    { method: "POST", path: "/reset-password", limit: login },
    // Cheap per request, but it sends mail, and mail costs someone else money
    // and reputation.
    { method: "POST", path: "/verify-email/resend", limit: login, identify: (body) => body.identifier },
    // Not scrypt — this one is about brute-forcing a code or a refresh token,
    // so the ceiling is much higher and the answer has to be JSON.
    {
      method: "POST",
      path: "/oauth2/token",
      limit: token,
      json: true,
      identify: (body) => body.client_id
    }
  ];
}

function clientAddress(req) {
  return req.ip || req.socket?.remoteAddress || "unknown";
}

function createRateLimitMiddleware({ config, logger = console, now = () => Date.now() } = {}) {
  const rules = buildRules(config.security);
  const counter = createCounter({ now });
  const byPath = new Map(rules.map((rule) => [rule.path, rule]));

  return function rateLimitMiddleware(req, res, next) {
    const rule = byPath.get(req.path);
    if (!rule || req.method !== rule.method) return next();

    const address = clientAddress(req);
    const identifier = rule.identify
      ? String(rule.identify(req.body || {}) || "")
          .trim()
          .toLowerCase()
      : "";

    // Both keys are hit, not short-circuited: a caller who is over one limit
    // should still count against the other, or the cheaper key becomes a way to
    // avoid being counted on the expensive one.
    const results = [counter.hit(`${rule.path}|ip|${address}`, rule.limit)];
    if (identifier) results.push(counter.hit(`${rule.path}|id|${identifier}`, rule.limit));

    const blocked = results.find((result) => !result.allowed);
    if (!blocked) return next();

    // Deliberately not logging the identifier: this fires on exactly the
    // requests most likely to carry someone else's address or a live token.
    logger.warn?.(`[rate-limit] ${req.method} ${req.path} from ${address} exceeded ${rule.limit}/min`);

    res.set("Retry-After", String(blocked.retryAfterSeconds));
    res.set("Cache-Control", "no-store");

    if (rule.json) {
      // 429 is the status; `slow_down` is the closest registered OAuth error
      // code (RFC 8628 section 3.5) and reads correctly here. A client that
      // does not recognise it still has the status and Retry-After.
      return res.status(429).json({
        error: "slow_down",
        error_description: "Too many requests. Retry after the interval in the Retry-After header."
      });
    }

    return res.status(429).render("error", {
      title: "Too many attempts",
      heading: "Too many attempts",
      message: `Wait ${blocked.retryAfterSeconds} seconds and try again.`,
      status: 429
    });
  };
}

module.exports = { createCounter, createRateLimitMiddleware, buildRules };

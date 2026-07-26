"use strict";

const { invalidRequest } = require("./errors");

// Redirect URI rules, per RFC 6749 section 3.1.2, RFC 8252, and OIDC Core.
//
// The previous Knight-internal issuer required every redirect URI to be HTTPS.
// That is correct for a confidential web client and wrong for everything else:
// RFC 8252 section 7.3 explicitly provides for http on the loopback interface
// for native apps, and section 7.1 for private-use URI schemes. Rejecting those
// makes the issuer unusable for a desktop or mobile client and blocks local
// development, so the rule is per-URI rather than global.
//
// What is never allowed, on any scheme:
//   * a fragment      — the authorization response appends to the query/fragment
//   * userinfo        — credentials in a redirect target are a phishing vector
//   * a relative URI  — the comparison below is exact string matching

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1", "localhost"]);

/** Loopback per RFC 8252 section 7.3. `localhost` is accepted for developer ergonomics. */
function isLoopbackHost(hostname) {
  return LOOPBACK_HOSTS.has(String(hostname || "").toLowerCase());
}

/**
 * A private-use URI scheme for a native app, per RFC 8252 section 7.1
 * (e.g. `com.example.app:/oauth2redirect`). The spec recommends a scheme based
 * on a domain name the app controls, so a dot is required: this keeps the rule
 * from accepting bare schemes like `javascript:` or `data:`.
 */
function isPrivateUseScheme(protocol) {
  const scheme = String(protocol || "").replace(/:$/, "").toLowerCase();
  if (!scheme || !scheme.includes(".")) return false;
  return /^[a-z][a-z0-9+.-]*$/.test(scheme);
}

const FORBIDDEN_SCHEMES = new Set([
  "javascript:",
  "data:",
  "vbscript:",
  "file:",
  "blob:",
  "about:"
]);

/**
 * Parses and validates a redirect URI.
 *
 * @param {string} value
 * @param {object} [options]
 * @param {boolean} [options.allowInsecureHttp] permit http on a non-loopback host.
 *   Off by default. A deployment behind a trusted proxy during development can
 *   enable it; production should not.
 * @returns {string} the normalized URI to store and compare against
 */
function parseRedirectUri(value, { allowInsecureHttp = false, name = "redirect_uri" } = {}) {
  const text = String(value || "").trim();
  if (!text) throw invalidRequest(`${name} is required`);
  if (text.length > 2000) throw invalidRequest(`${name} is too long`);

  let url;
  try {
    url = new URL(text);
  } catch {
    throw invalidRequest(`${name} must be an absolute URI`);
  }

  if (FORBIDDEN_SCHEMES.has(url.protocol)) {
    throw invalidRequest(`${name} uses a forbidden scheme`);
  }
  if (url.hash) {
    throw invalidRequest(`${name} must not contain a fragment`);
  }
  if (url.username || url.password) {
    throw invalidRequest(`${name} must not contain userinfo`);
  }

  if (url.protocol === "https:") return url.toString();

  if (url.protocol === "http:") {
    if (isLoopbackHost(url.hostname) || allowInsecureHttp) return url.toString();
    throw invalidRequest(`${name} must use HTTPS unless it targets the loopback interface`);
  }

  if (isPrivateUseScheme(url.protocol)) return url.toString();

  throw invalidRequest(`${name} scheme is not supported`);
}

/**
 * Exact match, per RFC 6749 section 3.1.2.3 — no prefix, wildcard, or
 * subdomain matching, which is how redirect-based account takeover happens.
 *
 * The one carve-out is RFC 8252 section 7.3: a native app on loopback cannot
 * predict the port the OS will hand it, so a registered loopback URI matches a
 * request that differs only in port. Scheme, host, path, and query must still
 * match exactly.
 */
function redirectUriMatches(registered, requested) {
  if (registered === requested) return true;

  let left;
  let right;
  try {
    left = new URL(registered);
    right = new URL(requested);
  } catch {
    return false;
  }

  // Both sides normalised, which is what the exact-match rule was always meant
  // to compare.
  //
  // A registered URI has already been through parseRedirectUri, so it is stored
  // in WHATWG-normalised form; the requested one was compared as the raw string
  // the client sent. That asymmetry is not stricter than exact matching, it is
  // just inconsistent: `https://rp.example:443/cb`, `https://RP.example/cb`, and
  // a registered `https://rp.example` written without its trailing slash all
  // denote the registered endpoint and were all refused.
  //
  // This does not widen what a client can reach. `new URL().toString()` is the
  // same parse a browser applies to the Location header, so the normalised form
  // and the raw one always denote the same destination — a request can only
  // match a registration it was already equivalent to. What it normalises is
  // scheme and host case, a default port stated explicitly, an empty path, and
  // dot-segments; a fragment or userinfo survives it and still fails to match,
  // which is what RFC 6749 section 3.1.2 wants.
  if (left.toString() === right.toString()) return true;

  if (left.protocol !== "http:" || right.protocol !== "http:") return false;
  if (!isLoopbackHost(left.hostname) || !isLoopbackHost(right.hostname)) return false;
  // `localhost` and `127.0.0.1` are different hosts for this comparison; only
  // the port is allowed to float.
  return (
    left.hostname.toLowerCase() === right.hostname.toLowerCase() &&
    left.pathname === right.pathname &&
    left.search === right.search
  );
}

/** Finds the registered URI a request matches, or null. */
function findMatchingRedirectUri(registeredUris, requested) {
  const text = String(requested || "").trim();
  if (!text) return null;
  return (registeredUris || []).find((registered) => redirectUriMatches(registered, text)) || null;
}

/**
 * Validates an absolute HTTPS URL for a non-redirect purpose (issuer base URL,
 * back-channel logout endpoint, logo URI). These are server-to-server or
 * display URLs where there is no native-app carve-out to make.
 */
function parseHttpsUrl(value, name, { required = false, allowHttp = false } = {}) {
  const text = String(value || "").trim();
  if (!text) {
    if (required) throw invalidRequest(`${name} is required`);
    return "";
  }
  let url;
  try {
    url = new URL(text);
  } catch {
    throw invalidRequest(`${name} must be an absolute URL`);
  }
  const httpAllowed = allowHttp || isLoopbackHost(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && httpAllowed)) {
    throw invalidRequest(`${name} must use HTTPS`);
  }
  if (url.hash || url.username || url.password) {
    throw invalidRequest(`${name} must not contain userinfo or a fragment`);
  }
  return url.toString();
}

/** Strips trailing slashes so an issuer identifier compares byte-for-byte. */
function normalizeIssuer(value) {
  return String(value || "").replace(/\/+$/, "");
}

/**
 * Builds an authorization error redirect (RFC 6749 section 4.1.2.1). `state` is
 * echoed only when the client sent it.
 *
 * `issuer` is required, and required for the same reason the success path sets
 * it: RFC 9207 section 2 says `iss` accompanies *every* authorization response,
 * and section 2.4 tells the client to reject one that arrives without it. A
 * client that trusts our discovery document — which advertises
 * `authorization_response_iss_parameter_supported` — has been told to do
 * exactly that, so an error response missing `iss` does not degrade to "an
 * error the client can read". oauth4webapi, which openid-client is built on,
 * validates `iss` before it looks at `error`, so the relying party sees a
 * library fault instead of `access_denied` — at the one moment its error path
 * most needs to work.
 *
 * It throws rather than defaulting when omitted: a missing `iss` is invisible
 * in the response body and only shows up as an unexplained client-side failure,
 * which is precisely the kind of silence this argument exists to prevent.
 */
function buildErrorRedirect(redirectUri, { error, errorDescription, state, issuer }) {
  if (!issuer) {
    throw new TypeError("buildErrorRedirect requires an issuer: RFC 9207 applies to error responses too");
  }
  const target = new URL(redirectUri);
  target.searchParams.set("error", error);
  if (errorDescription) target.searchParams.set("error_description", errorDescription);
  if (state) target.searchParams.set("state", state);
  target.searchParams.set("iss", normalizeIssuer(issuer));
  return target.toString();
}

module.exports = {
  buildErrorRedirect,
  findMatchingRedirectUri,
  isLoopbackHost,
  isPrivateUseScheme,
  normalizeIssuer,
  parseHttpsUrl,
  parseRedirectUri,
  redirectUriMatches
};

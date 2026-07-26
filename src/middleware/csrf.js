"use strict";

const { randomToken, safeEqual } = require("../lib/crypto");

// CSRF protection for the browser-facing forms.
//
// The token is a double-submit cookie: an httpOnly cookie the browser sends
// automatically, compared against a value the form carries. An attacker's page
// can cause the cookie to be sent but cannot read it to fill in the field.
//
// The OAuth protocol endpoints are deliberately exempt, and that is not a gap:
//   * /oauth2/token, /introspect, /revoke, /register authenticate the *client*
//     with its own credentials, not with the user's cookie. A cross-site POST
//     without those credentials fails anyway, and requiring a CSRF token would
//     break every conformant client library, none of which sends one.
//   * /oauth2/backchannel-logout-style callbacks are server-to-server.
//   * /oauth2/authorize is required to accept POST as well as GET (OIDC Core
//     section 3.1.2.1, a MUST). The form that posts it belongs to the relying
//     party, so it is cross-site by construction: it carries no cookie of ours
//     and cannot read a token to submit. Protecting it does not make the
//     endpoint safer — the GET form has exactly the same capability and never
//     had a token either — it only makes POST fail with a 403 the client
//     cannot interpret. What a forged request could actually achieve is
//     bounded by the next step: reaching /oauth2/authorize renders a consent
//     screen, and the decision that grants anything is the POST to
//     /oauth2/consent, which is same-origin and stays protected.
//
// SameSite=Lax on the session cookie is a second layer, but it cannot be the
// only one: it does not cover a top-level cross-site POST in every browser.

const CSRF_COOKIE = "koauth_csrf";

/** Endpoints authenticated by client credentials or a bearer token, not a cookie. */
const PROTOCOL_ENDPOINTS = new Set([
  "/oauth2/authorize",
  "/oauth2/token",
  "/oauth2/introspect",
  "/oauth2/revoke",
  "/oauth2/userinfo",
  "/oauth2/register"
]);

function isProtocolEndpoint(pathname) {
  if (PROTOCOL_ENDPOINTS.has(pathname)) return true;
  // RFC 7592 client management is /oauth2/register/{client_id}, authenticated by
  // the registration access token.
  return pathname.startsWith("/oauth2/register/");
}

function createCsrfMiddleware({ secureCookies = false } = {}) {
  return function csrfMiddleware(req, res, next) {
    let token = req.cookies?.[CSRF_COOKIE];
    if (!token) {
      token = randomToken();
      res.cookie(CSRF_COOKIE, token, {
        httpOnly: true,
        sameSite: "lax",
        secure: secureCookies,
        path: "/"
      });
      if (req.cookies) req.cookies[CSRF_COOKIE] = token;
    }
    res.locals.csrfToken = token;

    const mutating = ["POST", "PUT", "PATCH", "DELETE"].includes(req.method);
    if (mutating && !isProtocolEndpoint(req.path)) {
      const supplied = String(req.body?._csrf || req.get("x-csrf-token") || "");
      if (!supplied || !safeEqual(supplied, token)) {
        return res.status(403).render("error", {
          title: "Request rejected",
          heading: "That form could not be verified",
          message:
            "The page you submitted from was out of date, or the request did not come from this site. Reload the page and try again.",
          status: 403
        });
      }
    }
    return next();
  };
}

module.exports = { CSRF_COOKIE, createCsrfMiddleware, isProtocolEndpoint };

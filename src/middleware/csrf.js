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

// The same `__Host-` reasoning as the session cookie, and it matters more here.
//
// A double-submit token defends by being unguessable to another origin. An
// attacker who can *write* the cookie does not have to guess: they plant
// `Set-Cookie: koauth_csrf=KNOWN; Domain=example.com; Path=/account/password`
// from any host under the registrable domain, RFC 6265 section 5.4 serialises
// the longer path first, and a cross-site POST carrying `_csrf=KNOWN` then
// compares equal to it. The whole mechanism is gone, and what is left is
// SameSite=Lax on its own — which the comment above already says cannot be the
// only layer.
//
// `__Host-` closes it because a browser rejects a cookie with that prefix if it
// carries a Domain attribute, and without one the cookie belongs to the host
// that set it and is never sent here.
const CSRF_COOKIE = "koauth_csrf";
const CSRF_COOKIE_SECURE = `__Host-${CSRF_COOKIE}`;

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
  const cookieName = secureCookies ? CSRF_COOKIE_SECURE : CSRF_COOKIE;

  return function csrfMiddleware(req, res, next) {
    // No fallback to the unprefixed name. A token is cheap to reissue — the
    // line below does it whenever one is absent — so the only cost of switching
    // is that a form rendered before the change fails once, which is what the
    // refusal page already tells the caller to do something about. Reading the
    // old name would instead keep the planted-cookie path open for as long as
    // the fallback existed.
    let token = req.cookies?.[cookieName];
    if (!token) {
      token = randomToken();
      res.cookie(cookieName, token, {
        httpOnly: true,
        sameSite: "lax",
        secure: secureCookies,
        path: "/"
      });
      if (req.cookies) req.cookies[cookieName] = token;
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

module.exports = { CSRF_COOKIE, CSRF_COOKIE_SECURE, createCsrfMiddleware, isProtocolEndpoint };

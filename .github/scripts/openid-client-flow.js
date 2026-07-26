#!/usr/bin/env node
// Drives a complete authorization code flow using the real `openid-client`
// library rather than hand-rolled HTTP assertions.
//
//   node .github/scripts/openid-client-flow.js http://127.0.0.1:3010
//
// flow.js is a client I wrote. It can share my own misreadings of the
// specification: a wrong claim check, a missing signature verification, a
// state comparison that silently accepts absence. This script hands the same
// surface to the reference Node relying party, so every validation that runs is
// the library's, not mine. Discovery, authorization URL construction, the code
// grant (including ID-token claim and signature checks), UserInfo, refresh,
// introspection, and revocation all go through openid-client.
//
// The browser half — register, log in, consent — is still done by hand, because
// that is HTML forms bound to a session cookie, not something a token library
// covers. Once consent redirects, the callback URL is handed to the library and
// the rest of the flow is its responsibility.
//
// Required environment (same as flow.js):
//   FLOW_CLIENT_ID       matching an OAUTH_STATIC_CLIENTS entry
//   FLOW_CLIENT_SECRET   the same entry's secret
//   FLOW_REDIRECT_URI    the same entry's redirect_uri
//
// No token, code, secret, cookie, PKCE verifier, state, or nonce is ever printed.
// A CI log is a public artifact on a public repository. Only the shape of a value
// is reported — its presence, its length, whether two values differ.

const crypto = require("node:crypto");

const BASE = (process.argv[2] || "http://127.0.0.1:3010").replace(/\/+$/, "");
const CLIENT_ID = process.env.FLOW_CLIENT_ID;
const CLIENT_SECRET = process.env.FLOW_CLIENT_SECRET;
const REDIRECT_URI = process.env.FLOW_REDIRECT_URI;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
  console.error(
    "FLOW_CLIENT_ID, FLOW_CLIENT_SECRET and FLOW_REDIRECT_URI must all be set,\n" +
      "and must match an OAUTH_STATIC_CLIENTS entry the server imported at boot."
  );
  process.exitCode = 1;
  return;
}

let failures = 0;
let checks = 0;

function check(name, condition, detail) {
  checks += 1;
  if (condition) {
    console.log(`  ok    ${name}`);
    return true;
  }
  failures += 1;
  console.log(`  FAIL  ${name}`);
  if (detail !== undefined) console.log(`        ${detail}`);
  return false;
}

// A single mutable cookie jar, because the browser half of this flow is a
// session: login sets a cookie that /oauth2/authorize and /oauth2/consent both
// have to see, and the CSRF token is bound to it.
const jar = new Map();

function cookieHeader() {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

function storeCookies(response) {
  const raw = response.headers.getSetCookie?.() || [];
  for (const line of raw) {
    const [pair] = line.split(";");
    const index = pair.indexOf("=");
    if (index > 0) jar.set(pair.slice(0, index).trim(), pair.slice(index + 1).trim());
  }
}

async function visit(pathname, options = {}) {
  const url = pathname.startsWith("http") ? pathname : `${BASE}${pathname}`;
  const headers = { ...(options.headers || {}) };
  if (jar.size) headers.cookie = cookieHeader();
  const response = await fetch(url, { redirect: "manual", ...options, headers });
  storeCookies(response);
  const text = await response.text();
  return { response, text };
}

// Repeated fields, not a comma-joined value. `new URLSearchParams({scope: [a,b]})`
// produces "scope=a%2Cb" — one value containing a comma — while an HTML checkbox
// group sends the field once per box. The consent form is a checkbox group.
function form(fields) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) {
    for (const item of Array.isArray(value) ? value : [value]) body.append(key, item);
  }
  return body.toString();
}

function post(pathname, fields) {
  return visit(pathname, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form(fields)
  });
}

function csrfFrom(html) {
  return /name="_csrf" value="([^"]+)"/.exec(html)?.[1];
}

// openid-client is ESM-only (`"type": "module"`). This repository is CommonJS,
// so the import is dynamic. That is the supported interop, not a workaround.
async function loadClient() {
  return import("openid-client");
}

async function main() {
  console.log(`driving an authorization code flow via openid-client against ${BASE}\n`);

  const client = await loadClient();

  // A fresh address per run, so the script is idempotent: a second run against
  // the same database must not fail because the account already exists.
  const email = `oidc-${crypto.randomBytes(8).toString("hex")}@ci.invalid`;
  const password = crypto.randomBytes(24).toString("base64url");

  // --- Discover -------------------------------------------------------------
  //
  // The library fetches /.well-known/openid-configuration, checks that the
  // returned issuer matches the URL we pointed it at, and builds a Configuration
  // that every subsequent call uses. If the discovery document is wrong, nothing
  // after this works — which is the point of starting here rather than hardcoding
  // the token endpoint.
  console.log("discovery");
  let config;
  {
    try {
      config = await client.discovery(
        new URL(BASE),
        CLIENT_ID,
        CLIENT_SECRET,
        // The server defaults confidential clients to client_secret_basic. The
        // library's default is client_secret_post, so this must be stated.
        client.ClientSecretBasic(CLIENT_SECRET),
        {
          // The CI issuer is http://127.0.0.1. Production deployments are HTTPS;
          // this flag is only for the local/CI case and is what the library
          // documents for that situation.
          execute: [client.allowInsecureRequests, client.enableNonRepudiationChecks]
        }
      );
      check("openid-client discovers the issuer", true);
    } catch (error) {
      check("openid-client discovers the issuer", false, error?.message);
      throw error;
    }

    const metadata = config.serverMetadata();
    check(
      "the discovered issuer matches the base URL",
      metadata.issuer === BASE,
      `issuer ${metadata.issuer}`
    );
    check("authorization_endpoint is advertised", Boolean(metadata.authorization_endpoint));
    check("token_endpoint is advertised", Boolean(metadata.token_endpoint));
    check("userinfo_endpoint is advertised", Boolean(metadata.userinfo_endpoint));
    check("jwks_uri is advertised", Boolean(metadata.jwks_uri));
    check("introspection_endpoint is advertised", Boolean(metadata.introspection_endpoint));
    check("revocation_endpoint is advertised", Boolean(metadata.revocation_endpoint));
    check(
      "S256 is the advertised PKCE method",
      metadata.supportsPKCE("S256"),
      "supportsPKCE(S256) returned false"
    );
    check(
      "authorization responses carry iss (RFC 9207)",
      metadata.authorization_response_iss_parameter_supported === true
    );
  }

  // --- Register and log in -------------------------------------------------
  console.log("\naccount");
  {
    const page = await visit("/register");
    check("the registration form is served", page.response.status === 200, `status ${page.response.status}`);
    const token = csrfFrom(page.text);
    check("the form carries a CSRF token", Boolean(token));

    const created = await post("/register", {
      _csrf: token,
      email,
      name: "CI OpenID Client",
      password
    });
    // 200 whether or not the address was free: the two answers are identical by
    // design, so that registering cannot be used to enumerate accounts.
    check("registering is accepted", created.response.status === 200, `status ${created.response.status}`);

    // Registration establishes no session, so signing in is a separate step.
    const loginPage = await visit("/login");
    const signedIn = await post("/login", {
      _csrf: csrfFrom(loginPage.text),
      identifier: email,
      password
    });
    check(
      "the new account can sign in",
      signedIn.response.status === 302,
      `status ${signedIn.response.status} — registration did not create a usable account`
    );

    const account = await visit("/account");
    check("the new session reaches a protected page", account.response.status === 200, `status ${account.response.status}`);
  }

  // --- Authorization request ----------------------------------------------
  //
  // PKCE verifier/challenge, state, and nonce are all produced by the library.
  // buildAuthorizationUrl is what a real RP calls; the only thing we do with the
  // resulting URL is open it in our cookie-bearing session.
  console.log("\nauthorization");
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  const state = client.randomState();
  const nonce = client.randomNonce();
  let callbackUrl;

  {
    const authorizationUrl = client.buildAuthorizationUrl(config, {
      redirect_uri: REDIRECT_URI,
      scope: "openid profile email offline_access",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      nonce
    });
    check(
      "openid-client builds an authorization URL against this issuer",
      authorizationUrl.origin === new URL(BASE).origin &&
        authorizationUrl.pathname === "/oauth2/authorize",
      String(authorizationUrl)
    );

    const started = await visit(authorizationUrl.href);
    check(
      "an authenticated user is sent to consent",
      started.response.status === 302 &&
        /^\/oauth2\/consent\?request=/.test(started.response.headers.get("location") || ""),
      `status ${started.response.status} location ${started.response.headers.get("location")}`
    );

    const consent = await visit(started.response.headers.get("location"));
    check("the consent screen renders", consent.response.status === 200, `status ${consent.response.status}`);
    check(
      "the consent screen names the redirect origin",
      consent.text.includes(new URL(REDIRECT_URI).origin),
      "the page did not show where the result would be sent"
    );

    const requestToken = /name="request" value="([^"]+)"/.exec(consent.text)?.[1];
    check("the consent form carries the request token", Boolean(requestToken));

    const approved = await post("/oauth2/consent", {
      _csrf: csrfFrom(consent.text),
      request: requestToken,
      decision: "allow",
      scope_selection: "1",
      scope: ["profile", "email", "offline_access"]
    });
    check(
      "approving redirects to the client",
      approved.response.status === 302,
      `status ${approved.response.status}`
    );

    const location = approved.response.headers.get("location") || "";
    check("the redirect goes to the registered URI", location.startsWith(REDIRECT_URI), "redirected somewhere else");
    callbackUrl = new URL(location);
  }

  // --- Token exchange -----------------------------------------------------
  //
  // authorizationCodeGrant does the full RP-side work: validates `state` and
  // `iss` on the callback, exchanges the code with PKCE, checks the ID token's
  // iss/aud/nonce/exp, and — because enableNonRepudiationChecks was set above —
  // verifies the ID token signature against the issuer's JWKS. A hand-rolled
  // client can miss any one of those; this library does not.
  console.log("\ntoken");
  let tokens;
  let subject;
  {
    try {
      tokens = await client.authorizationCodeGrant(config, callbackUrl, {
        pkceCodeVerifier: codeVerifier,
        expectedState: state,
        expectedNonce: nonce,
        idTokenExpected: true
      });
      check("openid-client exchanges the code for tokens", true);
    } catch (error) {
      check("openid-client exchanges the code for tokens", false, error?.message);
      // Without tokens nothing below is meaningful, but the remaining checks
      // still run so a partial failure is reported as many FAILs rather than
      // a single throw that hides how far the flow got.
      tokens = null;
    }

    if (tokens) {
      check("an access token was issued", Boolean(tokens.access_token));
      check("token_type is bearer", String(tokens.token_type).toLowerCase() === "bearer", String(tokens.token_type));
      check("an ID token was issued", Boolean(tokens.id_token));
      check("offline_access produced a refresh token", Boolean(tokens.refresh_token));

      const claims = tokens.claims();
      check("the ID token has a subject", Boolean(claims?.sub));
      check("the ID token issuer matches", claims?.iss === BASE, `iss ${claims?.iss}`);
      check(
        "the ID token audience is this client",
        claims?.aud === CLIENT_ID || (Array.isArray(claims?.aud) && claims.aud.includes(CLIENT_ID)),
        `aud ${claims?.aud}`
      );
      check("the ID token nonce matches the request", claims?.nonce === nonce);
      check("the approved email scope produced the claim", claims?.email === email, `email claim ${claims?.email}`);
      subject = claims?.sub;
    } else {
      for (const name of [
        "an access token was issued",
        "token_type is bearer",
        "an ID token was issued",
        "offline_access produced a refresh token",
        "the ID token has a subject",
        "the ID token issuer matches",
        "the ID token audience is this client",
        "the ID token nonce matches the request",
        "the approved email scope produced the claim"
      ]) {
        check(name, false, "skipped: the code exchange never succeeded");
      }
    }
  }

  // --- UserInfo -----------------------------------------------------------
  console.log("\nuserinfo");
  {
    if (!tokens?.access_token || !subject) {
      check("openid-client fetches UserInfo", false, "skipped: no access token or subject from the code exchange");
      check("userinfo returns the approved email", false, "skipped");
      check("userinfo subject matches the ID token", false, "skipped");
    } else {
      let info;
      try {
        info = await client.fetchUserInfo(config, tokens.access_token, subject);
        check("openid-client fetches UserInfo", true);
      } catch (error) {
        check("openid-client fetches UserInfo", false, error?.message);
        info = null;
      }
      check("userinfo returns the approved email", info?.email === email, `email ${info?.email}`);
      // fetchUserInfo already asserts sub === expectedSubject. Restating it here
      // makes a failure visible as a named check rather than only as a throw.
      check("userinfo subject matches the ID token", info?.sub === subject);
    }
  }

  // --- Refresh ------------------------------------------------------------
  console.log("\nrefresh");
  let rotatedRefresh;
  {
    if (!tokens?.refresh_token) {
      for (const name of [
        "openid-client refreshes the access token",
        "a new access token is issued",
        "the refresh token is rotated"
      ]) {
        check(name, false, "skipped: no refresh token from the code exchange");
      }
    } else {
      let refreshed;
      try {
        refreshed = await client.refreshTokenGrant(config, tokens.refresh_token);
        check("openid-client refreshes the access token", true);
      } catch (error) {
        check("openid-client refreshes the access token", false, error?.message);
        refreshed = null;
      }
      check("a new access token is issued", Boolean(refreshed?.access_token));
      rotatedRefresh = refreshed?.refresh_token;
      check(
        "the refresh token is rotated",
        Boolean(rotatedRefresh) && rotatedRefresh !== tokens.refresh_token
      );
    }
  }

  // --- Introspection ------------------------------------------------------
  //
  // RFC 7662. The library authenticates as the client and validates that the
  // response carries a boolean `active`. This is the first time CI exercises
  // /oauth2/introspect through a real client library.
  console.log("\nintrospection");
  {
    if (!tokens?.access_token) {
      check("openid-client introspects the access token", false, "skipped: no access token");
      check("the access token is active", false, "skipped");
      check("introspection returns this client_id", false, "skipped");
      check("introspection returns the subject", false, "skipped");
    } else {
      let result;
      try {
        result = await client.tokenIntrospection(config, tokens.access_token);
        check("openid-client introspects the access token", true);
      } catch (error) {
        check("openid-client introspects the access token", false, error?.message);
        result = null;
      }
      check("the access token is active", result?.active === true, `active ${result?.active}`);
      check("introspection returns this client_id", result?.client_id === CLIENT_ID, `client_id ${result?.client_id}`);
      check("introspection returns the subject", Boolean(result?.sub) && result.sub === subject, `sub ${result?.sub}`);
    }
  }

  // --- Revocation ---------------------------------------------------------
  //
  // RFC 7009. Revoking the rotated-out refresh token is intentional: after
  // rotation the previous token is already unusable for refresh, but the
  // endpoint must still accept the request and return 200 (the library checks
  // that). Then the current refresh token is revoked, and a subsequent refresh
  // with it must fail — that is the behaviour a client relies on at logout.
  console.log("\nrevocation");
  {
    if (!tokens?.refresh_token) {
      check("openid-client revokes a refresh token", false, "skipped: no refresh token");
      check("a revoked refresh token cannot be used", false, "skipped");
    } else {
      try {
        // Prefer the current (rotated) token so the "cannot be used after
        // revoke" check below has something meaningful to try. Fall back to the
        // original if rotation did not happen.
        const toRevoke = rotatedRefresh || tokens.refresh_token;
        await client.tokenRevocation(config, toRevoke);
        check("openid-client revokes a refresh token", true);
      } catch (error) {
        check("openid-client revokes a refresh token", false, error?.message);
      }

      const stillCurrent = rotatedRefresh || tokens.refresh_token;
      try {
        await client.refreshTokenGrant(config, stillCurrent);
        check(
          "a revoked refresh token cannot be used",
          false,
          "the refresh succeeded after revocation"
        );
      } catch {
        check("a revoked refresh token cannot be used", true);
      }
    }
  }

  console.log(`\n${checks - failures}/${checks} checks passed`);
  if (failures > 0) {
    console.log(`${failures} failed`);
    // exitCode, not exit(): calling exit() while fetch's keep-alive sockets are
    // closing aborts the process on Windows and truncates this output.
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(`\nthe openid-client flow could not complete: ${error?.message}`);
  process.exitCode = 1;
});

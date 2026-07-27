#!/usr/bin/env node
// Probes a running issuer the way a third-party client library would.
//
//   node .github/scripts/probe.js http://127.0.0.1:3010
//
// This exists because the test suite and this script fail for different reasons.
// The suite mounts the Express app in-process on SQLite; this talks HTTP to a
// real server, over a real socket, against whichever database it was started
// with. Everything it asserts is reachable without an account, because a fresh
// boot has none and dynamic registration is off by default — so it checks the
// metadata a client reads before it can do anything, and the protocol errors it
// must handle when something is wrong.
//
// No secrets, tokens, or authorization codes are printed. A CI log is a public
// artifact on a public repository.

const BASE = (process.argv[2] || "http://127.0.0.1:3010").replace(/\/+$/, "");

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

async function get(pathname, options = {}) {
  const response = await fetch(`${BASE}${pathname}`, { redirect: "manual", ...options });
  const text = await response.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { response, text, json };
}

async function main() {
  console.log(`probing ${BASE}\n`);

  // --- Health --------------------------------------------------------------
  // /healthz reports unavailable when the signing key cannot be resolved. A 200
  // here means the server booted far enough to have a key, which on a first boot
  // means it generated and stored one.
  console.log("health");
  {
    const { response, json } = await get("/healthz");
    check("/healthz returns 200", response.status === 200, `status ${response.status}`);
    check("status is ok", json?.status === "ok", JSON.stringify(json));
    check("at least one signing key is loaded", (json?.keys ?? 0) >= 1, `keys ${json?.keys}`);
  }

  // --- Discovery -----------------------------------------------------------
  // The first thing a client library fetches. Every value it advertises has to
  // match what the server does: a client that is told about a capability will
  // attempt it, so a wrong entry here is worse than a missing one.
  console.log("\ndiscovery");
  let oidc;
  {
    const { response, json } = await get("/.well-known/openid-configuration");
    check("openid-configuration returns 200", response.status === 200, `status ${response.status}`);
    oidc = json || {};

    check("issuer matches the address it was fetched from", oidc.issuer === BASE, `issuer ${oidc.issuer}`);

    for (const field of [
      "authorization_endpoint",
      "token_endpoint",
      "userinfo_endpoint",
      "jwks_uri"
    ]) {
      check(`${field} is present and absolute`, typeof oidc[field] === "string" && oidc[field].startsWith(BASE), String(oidc[field]));
    }

    // RFC 7636. `plain` provides no protection against an interception attack.
    check(
      "only S256 PKCE is advertised",
      JSON.stringify(oidc.code_challenge_methods_supported) === JSON.stringify(["S256"]),
      JSON.stringify(oidc.code_challenge_methods_supported)
    );

    // RFC 9207. The authorization response carries `iss`; a client can only use
    // it to detect a mix-up attack if it is told to expect it.
    check("RFC 9207 iss support is advertised", oidc.authorization_response_iss_parameter_supported === true);

    // A symmetric or absent signature would let anyone holding the client secret
    // — or nothing at all — mint an ID token.
    const algs = oidc.id_token_signing_alg_values_supported || [];
    check("ID token algorithms exclude HS256 and none", !algs.includes("HS256") && !algs.includes("none"), JSON.stringify(algs));
    check("at least one ID token algorithm is offered", algs.length >= 1);

    // The implicit flow puts tokens in the URL fragment, where they reach logs
    // and browser history.
    check(
      "only the code response type is offered",
      JSON.stringify(oidc.response_types_supported) === JSON.stringify(["code"]),
      JSON.stringify(oidc.response_types_supported)
    );

    check("openid is a supported scope", (oidc.scopes_supported || []).includes("openid"), JSON.stringify(oidc.scopes_supported));
  }

  // RFC 8414. A pure OAuth 2.0 client library looks here and not at the OIDC
  // path, so serving only one of the two locks out half the ecosystem.
  {
    const { response, json } = await get("/.well-known/oauth-authorization-server");
    check("oauth-authorization-server returns 200", response.status === 200, `status ${response.status}`);
    check("both documents agree on the issuer", json?.issuer === oidc.issuer, `${json?.issuer} vs ${oidc.issuer}`);
    check("both documents agree on the token endpoint", json?.token_endpoint === oidc.token_endpoint);
  }

  // --- JWKS ----------------------------------------------------------------
  // How a client verifies a token it was given. A private component leaking here
  // would hand out the ability to forge tokens, so that is checked explicitly.
  console.log("\njwks");
  {
    const { response, json } = await get(new URL(oidc.jwks_uri || `${BASE}/oauth2/jwks`).pathname);
    check("jwks returns 200", response.status === 200, `status ${response.status}`);
    const keys = json?.keys || [];
    check("jwks publishes at least one key", keys.length >= 1);
    check("every key has a kid", keys.every((key) => typeof key.kid === "string" && key.kid.length > 0));
    check("every key declares use=sig", keys.every((key) => key.use === undefined || key.use === "sig"));
    // RSA private components. `d` alone is the private exponent; the rest are
    // the CRT factors.
    const leaked = ["d", "p", "q", "dp", "dq", "qi"];
    check(
      "no private key material is published",
      keys.every((key) => leaked.every((field) => key[field] === undefined)),
      "a private component appeared in the public JWKS"
    );
  }

  // --- Protocol errors -----------------------------------------------------
  // A client library's error path is exercised as often as its success path, and
  // these are the shapes RFC 6749 requires. Getting them wrong makes a failure
  // undiagnosable from the client side.
  console.log("\nerror handling");
  {
    // Section 4.1.2.1: an unknown client must not be reported by redirecting,
    // because the redirect target cannot be trusted yet. That would be an open
    // redirect.
    const { response } = await get(
      "/oauth2/authorize?response_type=code&client_id=definitely-not-a-registered-client&redirect_uri=https%3A%2F%2Fattacker.example%2Fcb&scope=openid"
    );
    check(
      "an unknown client is not redirected",
      response.status < 300 || response.status >= 400,
      `status ${response.status} location ${response.headers.get("location")}`
    );
    const location = response.headers.get("location") || "";
    check("nothing is sent to the unvalidated redirect_uri", !location.includes("attacker.example"), location);
  }

  {
    // Section 5.2: an invalid grant_type is a 400 with a JSON `error` code, not
    // a 500 and not an HTML page.
    const { response, json } = await get("/oauth2/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "not-a-real-grant" }).toString()
    });
    check("an unsupported grant_type is a 4xx", response.status >= 400 && response.status < 500, `status ${response.status}`);
    check("the error body is JSON with an error code", typeof json?.error === "string", JSON.stringify(json));
  }

  {
    // RFC 6750 section 3: a 401 must carry WWW-Authenticate, which is how a
    // client knows to refresh rather than to give up.
    const { response } = await get("/oauth2/userinfo");
    check("userinfo without a token is 401", response.status === 401, `status ${response.status}`);
    check(
      "the 401 carries a Bearer challenge",
      (response.headers.get("www-authenticate") || "").toLowerCase().includes("bearer"),
      String(response.headers.get("www-authenticate"))
    );
  }

  // These endpoints are easy to miss in an edge rule because they are not part
  // of the interactive browser flow. Probe them without credentials: the exact
  // OAuth error may vary with deployment policy, but the transport boundary may
  // not. A Cloudflare challenge, proxy redirect, cacheable error, or CSRF cookie
  // would break a conforming machine client before authentication is attempted.
  const machineEndpoints = [
    {
      name: "introspection",
      pathname: "/oauth2/introspect",
      options: {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: ""
      }
    },
    {
      name: "revocation",
      pathname: "/oauth2/revoke",
      options: {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: ""
      }
    },
    {
      name: "dynamic registration",
      pathname: "/oauth2/register",
      options: {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}"
      }
    },
    {
      name: "registration management",
      pathname: "/oauth2/register/probe-client",
      options: { method: "GET" }
    }
  ];

  for (const probe of machineEndpoints) {
    const { response, json } = await get(probe.pathname, probe.options);
    const prefix = `${probe.name} unauthenticated response`;
    check(
      `${prefix} is a 4xx`,
      response.status >= 400 && response.status < 500,
      `status ${response.status}`
    );
    check(
      `${prefix} is JSON`,
      (response.headers.get("content-type") || "").includes("application/json") &&
        typeof json?.error === "string",
      `content-type ${response.headers.get("content-type") || "missing"}`
    );
    check(
      `${prefix} sends no-store`,
      (response.headers.get("cache-control") || "").includes("no-store"),
      `cache-control ${response.headers.get("cache-control") || "missing"}`
    );
    check(
      `${prefix} sets no browser cookie`,
      !response.headers.has("set-cookie"),
      "a Set-Cookie header was present"
    );
    check(`${prefix} is not redirected`, response.status < 300 || response.status >= 400);
  }

  // --- Caching -------------------------------------------------------------
  // RFC 6749 section 5.1. A cached token response is a token served to whoever
  // asks next through a shared proxy.
  console.log("\ncache headers");
  {
    const { response } = await get("/oauth2/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "not-a-real-grant" }).toString()
    });
    check(
      "the token endpoint sends no-store",
      (response.headers.get("cache-control") || "").includes("no-store"),
      String(response.headers.get("cache-control"))
    );
  }

  console.log(`\n${checks - failures}/${checks} checks passed`);
  if (failures > 0) {
    console.log(`${failures} failed`);
    // `process.exitCode` rather than `process.exit()`. Calling exit() while
    // fetch's keep-alive sockets are still closing aborts the process on Windows
    // (a libuv assertion) — which truncates this output and reports a signal
    // instead of 1. Setting the code lets the sockets drain and exit normally.
    process.exitCode = 1;
  }
}

main().catch((error) => {
  // A connection error here usually means the server exited during boot; the
  // caller prints its log.
  console.error(`\nthe probe could not complete: ${error?.message}`);
  process.exitCode = 1;
});

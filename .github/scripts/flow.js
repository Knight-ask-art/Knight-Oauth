#!/usr/bin/env node
// Drives a complete authorization code flow against a running issuer, the way a
// third-party relying party would.
//
//   node .github/scripts/flow.js http://127.0.0.1:3010
//
// This is the check that probe.js cannot make. probe.js stays on the
// unauthenticated surface — metadata, JWKS, error shapes — because it must work
// against any instance. This one registers an account, logs in, consents, and
// exchanges a code, so it needs a client it is allowed to use. The caller
// supplies one through OAUTH_STATIC_CLIENTS, which is imported at boot as an
// already-approved client.
//
// Required environment:
//   FLOW_CLIENT_ID       matching an OAUTH_STATIC_CLIENTS entry
//   FLOW_CLIENT_SECRET   the same entry's secret
//   FLOW_REDIRECT_URI    the same entry's redirect_uri
//
// What it proves that the in-process suite does not: the flow works over real
// HTTP, on the database the server was actually started with, through whatever
// sits in front of it. The suite mounts the Express app directly on SQLite, so it
// cannot see a cookie dropped by a proxy, a Postgres-only constraint, or a
// session that does not survive a real socket.
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
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { response, text, json };
}

// Repeated fields, not a comma-joined value. `new URLSearchParams({scope: [a,b]})`
// produces "scope=a%2Cb" — one value containing a comma — while an HTML checkbox
// group sends the field once per box. The consent form is a checkbox group, so
// the comma-joined version arrives as a single bogus scope token and the grant
// silently comes back missing everything but `openid`. This cost real debugging
// time once; it is the reason this helper exists.
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

function pkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

// A JWT's payload, for asserting on claims. Deliberately not a signature check:
// verifying properly needs the JWKS and a JOSE implementation, and this script
// has no dependencies. The signature is covered by the unit suite; what matters
// here is that the claims a relying party reads are present and correct.
function claims(jwt) {
  const part = String(jwt).split(".")[1];
  if (!part) return {};
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

async function main() {
  console.log(`driving an authorization code flow against ${BASE}\n`);

  // A fresh address per run, so the script is idempotent: a second run against
  // the same database must not fail because the account already exists. Random
  // rather than a counter because two jobs may share a database.
  const email = `flow-${crypto.randomBytes(8).toString("hex")}@ci.invalid`;
  const password = crypto.randomBytes(24).toString("base64url");

  // --- Register and log in -------------------------------------------------
  console.log("account");
  {
    const page = await visit("/register");
    check("the registration form is served", page.response.status === 200, `status ${page.response.status}`);
    const token = csrfFrom(page.text);
    check("the form carries a CSRF token", Boolean(token));

    const created = await post("/register", {
      _csrf: token,
      email,
      name: "CI Flow",
      password
    });
    // 200 either way, by design: registering a free address and registering one
    // already taken render the identical page, because a 302-with-a-cookie next
    // to a 200 would answer "does this address exist" from the status line
    // alone. Nothing here can distinguish them, which is the point — the sign-in
    // below is what proves the account was actually created.
    check("registering is accepted", created.response.status === 200, `status ${created.response.status}`);

    // A separate, explicit step, for the same reason: registration establishes
    // no session.
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

  // --- Authorization request ------------------------------------------------
  console.log("\nauthorization");
  const { verifier, challenge } = pkce();
  const state = crypto.randomBytes(16).toString("base64url");
  const nonce = crypto.randomBytes(16).toString("base64url");
  let code;

  {
    const query = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid profile email offline_access",
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    const started = await visit(`/oauth2/authorize?${query}`);
    check(
      "an authenticated user is sent to consent",
      started.response.status === 302 &&
        /^\/oauth2\/consent\?request=/.test(started.response.headers.get("location") || ""),
      `status ${started.response.status} location ${started.response.headers.get("location")}`
    );

    const consent = await visit(started.response.headers.get("location"));
    check("the consent screen renders", consent.response.status === 200, `status ${consent.response.status}`);
    // The origin the tokens are going to is the answer to "who am I giving this
    // to", so it has to be on the page a user is asked to approve.
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

    const callback = new URL(location);
    // RFC 6749 section 4.1.2: state is round-tripped so the client can match the
    // response to the request it made. A mismatch is a CSRF.
    check("state is returned unchanged", callback.searchParams.get("state") === state);
    // RFC 9207, and the reason the discovery flag was added: a client that talks
    // to more than one issuer needs to know which one answered.
    check(
      "the response carries iss",
      callback.searchParams.get("iss") === BASE,
      `iss ${callback.searchParams.get("iss")}`
    );
    code = callback.searchParams.get("code");
    check("an authorization code was issued", Boolean(code));
  }

  // --- Token exchange -------------------------------------------------------
  console.log("\ntoken");
  let accessToken;
  let refreshToken;
  {
    const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
    const exchanged = await visit("/oauth2/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basic}`
      },
      body: form({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier
      })
    });

    check("the code is exchanged for tokens", exchanged.response.status === 200, `status ${exchanged.response.status}`);
    // RFC 6749 section 5.1. A cached token response is a token handed to whoever
    // uses the shared cache next.
    check(
      "the token response is no-store",
      (exchanged.response.headers.get("cache-control") || "").includes("no-store"),
      String(exchanged.response.headers.get("cache-control"))
    );

    const body = exchanged.json || {};
    accessToken = body.access_token;
    refreshToken = body.refresh_token;
    check("an access token was issued", Boolean(accessToken));
    check("token_type is Bearer", body.token_type === "Bearer", String(body.token_type));
    check("an ID token was issued", Boolean(body.id_token));
    // offline_access was requested and approved, so its absence is a real defect
    // rather than a policy choice.
    check("offline_access produced a refresh token", Boolean(refreshToken));

    const idToken = claims(body.id_token);
    // OIDC Core section 3.1.3.7: these are the checks a relying party performs
    // before it trusts an ID token at all.
    check("the ID token issuer matches", idToken.iss === BASE, `iss ${idToken.iss}`);
    check("the ID token audience is this client", idToken.aud === CLIENT_ID, `aud ${idToken.aud}`);
    check("the ID token nonce matches the request", idToken.nonce === nonce);
    check("the ID token has a subject", Boolean(idToken.sub));
    check("the ID token expires", typeof idToken.exp === "number" && idToken.exp > 0);
    // The email scope was approved, so the claim it grants must be there.
    check("the approved email scope produced the claim", idToken.email === email, `email claim ${idToken.email}`);
  }

  // --- UserInfo -------------------------------------------------------------
  console.log("\nuserinfo");
  {
    const info = await visit("/oauth2/userinfo", {
      headers: { authorization: `Bearer ${accessToken}` }
    });
    check("the access token is accepted", info.response.status === 200, `status ${info.response.status}`);
    // OIDC Core section 5.3.2: UserInfo MUST return sub.
    check("userinfo returns sub", Boolean(info.json?.sub));
    check("userinfo returns the approved email", info.json?.email === email, `email ${info.json?.email}`);

    // The scope that was NOT approved must not leak a claim. Consent is only
    // meaningful if withholding a scope actually withholds the data.
    check(
      "no claim appears for a scope that was never granted",
      info.json?.phone_number === undefined && info.json?.address === undefined,
      "a claim outside the approved scopes reached userinfo"
    );
  }

  // --- Refresh --------------------------------------------------------------
  console.log("\nrefresh");
  {
    const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
    const refreshed = await visit("/oauth2/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basic}`
      },
      body: form({ grant_type: "refresh_token", refresh_token: refreshToken })
    });
    check("the refresh token is accepted", refreshed.response.status === 200, `status ${refreshed.response.status}`);
    const rotated = refreshed.json?.refresh_token;
    check("a new access token is issued", Boolean(refreshed.json?.access_token));
    // Rotation is on by default. The new token must differ, or "rotation" is a
    // setting that does nothing.
    check("the refresh token is rotated", Boolean(rotated) && rotated !== refreshToken);

    // The heart of refresh-token replay detection: presenting the old token
    // after rotation must fail, because a token used twice means it leaked.
    //
    // Guarded on rotation actually having happened. Without the guard this check
    // passes for the wrong reason whenever the refresh above failed — a rejected
    // replay proves nothing if the token was never rotated out in the first
    // place. That false pass showed up while testing this script against a
    // deliberately wrong client secret.
    if (!rotated) {
      check(
        "replaying the rotated-out refresh token is rejected",
        false,
        "skipped: the refresh never succeeded, so there is no rotated-out token to replay"
      );
    } else {
      const replayed = await visit("/oauth2/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${basic}`
        },
        body: form({ grant_type: "refresh_token", refresh_token: refreshToken })
      });
      check(
        "replaying the rotated-out refresh token is rejected",
        replayed.response.status >= 400,
        `status ${replayed.response.status} — a used refresh token was accepted a second time`
      );
    }
  }

  // --- Single use ----------------------------------------------------------
  console.log("\nreplay");
  {
    // RFC 6749 section 4.1.2: an authorization code is single-use. This is the
    // one a scoped updateMany can get wrong in a way no unit test on a double
    // would notice, and it is database behaviour — which is why running it
    // against Postgres as well as SQLite is the point.
    //
    // Guarded on the first exchange having succeeded, for the same reason as the
    // refresh replay above: if the code was never redeemed, a rejected second
    // attempt says nothing about single use.
    if (!accessToken) {
      check(
        "reusing the authorization code is rejected",
        false,
        "skipped: the first exchange never succeeded, so the code was never used once"
      );
    } else {
      const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
      const again = await visit("/oauth2/token", {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${basic}`
        },
        body: form({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          code_verifier: verifier
        })
      });
      check(
        "reusing the authorization code is rejected",
        again.response.status >= 400,
        `status ${again.response.status} — the code was accepted twice`
      );
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
  console.error(`\nthe flow could not complete: ${error?.message}`);
  process.exitCode = 1;
});

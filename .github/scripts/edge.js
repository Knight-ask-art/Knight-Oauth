#!/usr/bin/env node
// Drives the protocol paths a compliant relying party reaches that the happy
// path never does.
//
//   node .github/scripts/edge.js http://127.0.0.1:3010
//
// probe.js stays on the unauthenticated surface. flow.js and
// openid-client-flow.js drive the authorization code flow to a successful
// token — every check in them is on the path where nothing goes wrong and the
// user says yes. That leaves four paths uncovered, and all four are ones a
// standard client library exercises as a matter of course:
//
//   1. The user declines. RFC 9207 section 2 requires `iss` on every
//      authorization response, errors included, and section 2.4 requires the
//      client to reject a response without it. oauth4webapi — which is what
//      openid-client is built on, and what the README recommends first — checks
//      `iss` before it looks at `error`, so a missing one turns every "cancel"
//      into a library-level failure the RP cannot diagnose.
//   2. The authorization endpoint over POST. OIDC Core section 3.1.2.1 makes
//      supporting both GET and POST a MUST. An RP that posts a form gets
//      whatever the CSRF layer decides, and it never sees the login page.
//   3. `prompt=login`. This is how an RP forces re-authentication before a
//      sensitive operation. Getting it wrong does not degrade to "ignored" — the
//      whole authorization fails.
//   4. Back-channel logout. The `sid` in the logout token has to be the `sid`
//      the RP indexed when it accepted the ID token (Back-Channel Logout 1.0
//      section 2.4). If the two are different values the RP looks up a session
//      that does not exist and the user stays logged in, while the issuer
//      records a successful delivery.
//
// Each of these is invisible to the suite for the same reason: the assertions
// live at the HTTP round-trip level — a redirect's query string, a status code
// a middleware chose, a redirect chain that does not terminate, a token
// delivered to a listener out of band.
//
// Required environment:
//   FLOW_CLIENT_ID       matching an OAUTH_STATIC_CLIENTS entry
//   FLOW_CLIENT_SECRET   the same entry's secret
//   FLOW_REDIRECT_URI    the same entry's redirect_uri
//   EDGE_LOGOUT_URI      the same entry's backchannel_logout_uri, which must be
//                        a loopback address: this script binds its port and
//                        stands in for the relying party receiving the logout.
//
// No token, code, secret, cookie, PKCE verifier, state, or nonce is ever
// printed. A CI log is a public artifact on a public repository. Session
// identifiers are compared, never shown — whether two values are equal is the
// entire finding, and the values themselves identify a live session.

const crypto = require("node:crypto");
const http = require("node:http");

const BASE = (process.argv[2] || "http://127.0.0.1:3010").replace(/\/+$/, "");
const CLIENT_ID = process.env.FLOW_CLIENT_ID;
const CLIENT_SECRET = process.env.FLOW_CLIENT_SECRET;
const REDIRECT_URI = process.env.FLOW_REDIRECT_URI;
const LOGOUT_URI = process.env.EDGE_LOGOUT_URI;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI || !LOGOUT_URI) {
  console.error(
    "FLOW_CLIENT_ID, FLOW_CLIENT_SECRET, FLOW_REDIRECT_URI and EDGE_LOGOUT_URI must all be set,\n" +
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

// One cookie jar for the browser half of the flow: login sets a cookie that
// /oauth2/authorize and /oauth2/consent both have to see, and the CSRF token is
// bound to it.
const jar = new Map();
const cookieHeader = () => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

function storeCookies(response) {
  for (const line of response.headers.getSetCookie?.() || []) {
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
  return { response, text: await response.text() };
}

// Repeated fields rather than a comma-joined value, for the same reason flow.js
// carries this helper: the consent form is a checkbox group.
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

const csrfFrom = (html) => /name="_csrf" value="([^"]+)"/.exec(html)?.[1];
const nextFrom = (html) => /name="next" value="([^"]*)"/.exec(html)?.[1];
const requestFrom = (html) => /name="request" value="([^"]+)"/.exec(html)?.[1];

function pkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  return {
    verifier,
    challenge: crypto.createHash("sha256").update(verifier).digest("base64url")
  };
}

function claimsOf(jwt) {
  const part = String(jwt).split(".")[1];
  if (!part) return {};
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

function authorizeQuery(extra = {}) {
  const { verifier, challenge } = pkce();
  const state = crypto.randomBytes(16).toString("base64url");
  const nonce = crypto.randomBytes(16).toString("base64url");
  const query = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid profile email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...extra
  });
  return { query, verifier, state, nonce };
}

// The relying party's logout endpoint. Started before the flow so a delivery
// that arrives early is still captured, and closed in a finally so a failure
// anywhere above does not leave the process holding the port open.
function startLogoutReceiver(uri) {
  const url = new URL(uri);
  const tokens = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      const token = new URLSearchParams(body).get("logout_token");
      let header = null;
      let claims = null;
      if (token) {
        const [rawHeader, rawClaims] = token.split(".");
        try {
          header = JSON.parse(Buffer.from(rawHeader, "base64url").toString("utf8"));
          claims = JSON.parse(Buffer.from(rawClaims, "base64url").toString("utf8"));
        } catch {
          /* a malformed token is reported by the checks below, not here */
        }
      }
      tokens.push({ method: req.method, contentType: req.headers["content-type"], header, claims });
      // 200 so the issuer records the delivery as successful. A retry would
      // re-send the same jti and tell us nothing new.
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
  });

  const ready = new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(Number(url.port), url.hostname, resolve);
  });

  return {
    tokens,
    ready,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

async function main() {
  console.log(`driving the protocol edge paths against ${BASE}\n`);

  const receiver = startLogoutReceiver(LOGOUT_URI);
  try {
    await receiver.ready;
  } catch (error) {
    console.error(
      `could not bind the logout receiver on ${LOGOUT_URI}: ${error?.message}\n` +
        "EDGE_LOGOUT_URI must be a loopback address this script can listen on."
    );
    process.exitCode = 1;
    return;
  }

  try {
    // A fresh address per run, so a second run against the same database does
    // not fail because the account already exists.
    const email = `edge-${crypto.randomBytes(8).toString("hex")}@ci.invalid`;
    const password = crypto.randomBytes(24).toString("base64url");

    // --- Account ------------------------------------------------------------
    console.log("account");
    {
      const page = await visit("/register");
      check("the registration form is served", page.response.status === 200, `status ${page.response.status}`);
      const created = await post("/register", {
        _csrf: csrfFrom(page.text),
        email,
        name: "CI Edge",
        password
      });
      check(
        "registering redirects to the account page",
        created.response.status === 302 && created.response.headers.get("location") === "/account",
        `status ${created.response.status} location ${created.response.headers.get("location")}`
      );
    }

    // --- The authorization endpoint over POST -------------------------------
    //
    // OIDC Core section 3.1.2.1: the authorization endpoint MUST support GET and
    // POST. A relying party that posts a form is a normal relying party, and the
    // form it posts is cross-site by construction — it comes from the RP's
    // origin, not the issuer's — so it carries no CSRF cookie and cannot know a
    // CSRF token. Exempting the endpoint costs nothing: the GET form has the
    // same capability and no protection either, and the decision that matters is
    // the consent POST, which is same-origin and stays protected.
    console.log("\nPOST /oauth2/authorize");
    {
      const { query } = authorizeQuery();
      const posted = await visit("/oauth2/authorize", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: query.toString()
      });
      check(
        "the authorization endpoint accepts POST",
        posted.response.status !== 403,
        `status ${posted.response.status} — a cross-site form POST from a relying party cannot carry a CSRF token, ` +
          "so a 403 here means the endpoint supports GET only"
      );
      check(
        "POST reaches the same decision as GET",
        posted.response.status === 302 || posted.response.status === 200,
        `status ${posted.response.status}`
      );
    }

    // --- The user declines --------------------------------------------------
    console.log("\ndeclining");
    {
      const { query, state } = authorizeQuery();
      const started = await visit(`/oauth2/authorize?${query}`);
      const consentPath = started.response.headers.get("location") || "";
      check(
        "an authenticated user is sent to consent",
        started.response.status === 302 && /^\/oauth2\/consent\?request=/.test(consentPath),
        `status ${started.response.status} location ${consentPath}`
      );

      const consent = await visit(consentPath);
      const denied = await post("/oauth2/consent", {
        _csrf: csrfFrom(consent.text),
        request: requestFrom(consent.text),
        decision: "deny"
      });
      check("declining redirects to the client", denied.response.status === 302, `status ${denied.response.status}`);

      const location = denied.response.headers.get("location") || "";
      check("the decline goes to the registered URI", location.startsWith(REDIRECT_URI), "redirected somewhere else");

      const callback = new URL(location);
      // RFC 6749 section 4.1.2.1.
      check(
        "the error is access_denied",
        callback.searchParams.get("error") === "access_denied",
        `error ${callback.searchParams.get("error")}`
      );
      check("state is returned unchanged", callback.searchParams.get("state") === state);
      // RFC 9207 section 2 — "in all authorization responses", not only the
      // successful ones. Discovery advertises
      // authorization_response_iss_parameter_supported, which is what tells a
      // client to require it.
      check(
        "the error response carries iss",
        callback.searchParams.get("iss") === BASE,
        `iss ${callback.searchParams.get("iss") ?? "absent"} — discovery advertises RFC 9207 support, and ` +
          "oauth4webapi checks iss before it reads error, so without it every cancellation " +
          "surfaces to the relying party as a library fault rather than as access_denied"
      );
    }

    // --- prompt=login -------------------------------------------------------
    //
    // The redirect chain is followed by hand, filling in the login form when it
    // is served, because the failure this covers is a chain that does not
    // terminate — something no single request can show.
    console.log("\nprompt=login");
    {
      const { query } = authorizeQuery({ prompt: "login" });
      let target = `/oauth2/authorize?${query}`;
      let submissions = 0;
      let outcome = null;
      const trail = [];

      for (let hop = 0; hop < 12 && !outcome; hop += 1) {
        const step = await visit(target);
        const location = step.response.headers.get("location");
        const path = target.split("?")[0];
        trail.push(`${step.response.status} ${path}${location ? " -> " + location.split("?")[0] : ""}`);

        if (step.response.status === 302 && location) {
          // Reaching the client, with a code or an error, is a terminating
          // outcome either way: the chain resolved.
          if (location.startsWith(REDIRECT_URI)) {
            outcome = "the client was reached";
            break;
          }
          target = location;
          continue;
        }

        if (step.response.status === 200 && path === "/login") {
          submissions += 1;
          // Twice is already more than a user would accept. A third means the
          // form is being served in a cycle rather than because re-authentication
          // was genuinely required.
          if (submissions > 2) {
            outcome = null;
            break;
          }
          const submitted = await post("/login", {
            _csrf: csrfFrom(step.text),
            identifier: email,
            password,
            next: nextFrom(step.text) || ""
          });
          const next = submitted.response.headers.get("location");
          trail.push(`${submitted.response.status} POST /login${next ? " -> " + next.split("?")[0] : ""}`);
          if (submitted.response.status !== 302 || !next) {
            outcome = `the login form rejected the credentials (${submitted.response.status})`;
            break;
          }
          target = next;
          continue;
        }

        if (step.response.status === 200 && path === "/oauth2/consent") {
          outcome = "the consent screen was reached";
          break;
        }

        outcome = `stopped at ${step.response.status} ${path}`;
        break;
      }

      check(
        "prompt=login terminates after the user re-authenticates",
        Boolean(outcome),
        outcome === null
          ? "the redirect chain never resolved:\n        " +
            trail.join("\n        ") +
            "\n        prompt=login is how a relying party forces re-authentication before a " +
            "sensitive operation; a chain that does not terminate fails the whole authorization"
          : undefined
      );
      if (outcome) console.log(`        ${outcome}`);
    }

    // --- Back-channel logout ------------------------------------------------
    //
    // Runs last: it ends the session the checks above rely on.
    console.log("\nback-channel logout");
    {
      const { query, verifier, nonce } = authorizeQuery();
      const started = await visit(`/oauth2/authorize?${query}`);
      const consentPath = started.response.headers.get("location") || "";
      let idClaims = {};

      if (started.response.status === 302 && consentPath.startsWith("/oauth2/consent")) {
        const consent = await visit(consentPath);
        const approved = await post("/oauth2/consent", {
          _csrf: csrfFrom(consent.text),
          request: requestFrom(consent.text),
          decision: "allow",
          scope_selection: "1",
          scope: ["profile", "email"]
        });
        const callback = new URL(approved.response.headers.get("location") || `${REDIRECT_URI}`);
        const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
        const exchanged = await visit("/oauth2/token", {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            authorization: `Basic ${basic}`
          },
          body: form({
            grant_type: "authorization_code",
            code: callback.searchParams.get("code"),
            redirect_uri: REDIRECT_URI,
            code_verifier: verifier
          })
        });
        let body = {};
        try {
          body = JSON.parse(exchanged.text);
        } catch {
          /* reported by the check below */
        }
        idClaims = body.id_token ? claimsOf(body.id_token) : {};
        check("a session was established to log out of", Boolean(idClaims.sub), `status ${exchanged.response.status}`);
        check("the ID token carries sid", Boolean(idClaims.sid), "no sid claim, so an RP has nothing to index the session by");
      } else {
        check("a session was established to log out of", false, `authorize returned ${started.response.status}`);
        check("the ID token carries sid", false, "skipped: no token was issued");
      }

      const account = await visit("/account");
      const loggedOut = await post("/logout", { _csrf: csrfFrom(account.text) });
      check("logging out is accepted", loggedOut.response.status === 302, `status ${loggedOut.response.status}`);

      // Delivery is a scheduled pass, not a synchronous send, so this waits.
      // OAUTH_BACKCHANNEL_RETRY_SECONDS has a floor of 15, so the window has to
      // clear one full interval with room for the request itself.
      const deadline = Date.now() + 45_000;
      while (!receiver.tokens.length && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 500));
      }

      const delivered = receiver.tokens[receiver.tokens.length - 1];
      if (!check("a logout token is delivered to the client", Boolean(delivered), "nothing arrived within 45s")) {
        check("the logout token identifies the session the ID token named", false, "skipped: nothing was delivered");
      } else {
        // Back-Channel Logout 1.0 section 2.4. The other members are asserted
        // because a token that is right about sid and wrong about these is just
        // as unusable, and because they are cheap to get wrong in a refactor.
        check(
          "the logout token is typed logout+jwt",
          delivered.header?.typ === "logout+jwt",
          `typ ${delivered.header?.typ}`
        );
        check(
          "the logout token carries the logout event",
          Boolean(delivered.claims?.events?.["http://schemas.openid.net/event/backchannel-logout"]),
          JSON.stringify(delivered.claims?.events)
        );
        // Section 2.4 prohibits nonce: its presence is how a recipient tells a
        // logout token from an ID token.
        check("the logout token carries no nonce", delivered.claims?.nonce === undefined);
        check(
          "the logout token names the same subject",
          Boolean(idClaims.sub) && delivered.claims?.sub === idClaims.sub,
          "the subject does not match the one the ID token carried"
        );
        // The finding. An RP indexes its session by the ID token's sid and looks
        // it up by the logout token's sid; if they are different values the
        // lookup misses, the user stays logged in, and the issuer records a
        // successful delivery.
        check(
          "the logout token identifies the session the ID token named",
          Boolean(idClaims.sid) && delivered.claims?.sid === idClaims.sid,
          "the logout token's sid is not the value the ID token carried, so a relying party that " +
            "indexed its session by the ID token's sid finds nothing to end — the delivery " +
            "succeeds and the user stays logged in"
        );
      }
    }
  } finally {
    await receiver.close();
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
  console.error(`\nthe edge-path run could not complete: ${error?.message}`);
  process.exitCode = 1;
});

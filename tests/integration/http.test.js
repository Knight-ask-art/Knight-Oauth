"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { after, before, describe, it } = require("node:test");
const request = require("supertest");

const { withDatabase } = require("../helpers/database");
const { loadEnv } = require("../../src/config/env");
const { createApp } = require("../../src/app");
const { createAccountService } = require("../../src/services/accountService");
const { createAuditService } = require("../../src/services/auditService");
const { createClientService } = require("../../src/services/clientService");
const { createScopeRegistry } = require("../../src/lib/scopes");
const { buildRules } = require("../../src/middleware/rateLimit");

// The HTTP suite.
//
// The other integration suite drives the services directly, which proves the
// protocol logic. It cannot prove any of this: that the routes are mounted at the
// paths discovery advertises, that the middleware runs in an order where CSRF
// actually sees a parsed body, or that a template renders at all. An EJS view
// throws on an undefined bare identifier, so a page whose controller forgot a
// local is a 500 that no service-level test can see.
//
// Everything below therefore goes through the real app: real routes, real
// session cookies, real CSRF tokens, real rendering.

const PASSWORD = "correct-horse-battery-staple";

/**
 * Pulls the CSRF token out of a rendered form.
 *
 * The double-submit token is in a cookie the agent already carries and in the
 * form, and a POST needs the pair to match. Reading it from the HTML is exactly
 * what a browser does, so a mismatch between what is issued and what is expected
 * shows up here rather than in production.
 */
function csrfFrom(html) {
  const match = /name="_csrf" value="([^"]+)"/.exec(html);
  assert.ok(match, "the rendered page carried no CSRF token");
  return match[1];
}

function pkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  return {
    verifier,
    challenge: crypto.createHash("sha256").update(verifier, "ascii").digest("base64url")
  };
}

describe("the HTTP surface", () => {
  let db;
  let app;
  let config;
  let accounts;
  let clients;
  let confidential;
  let confidentialSecret;
  let publicClient;
  let sentMail;

  // A signed-in browser, and a second one that is signed in as an administrator.
  let user;
  let admin;

  before(async () => {
    db = await withDatabase();

    config = loadEnv({
      PUBLIC_BASE_URL: "http://127.0.0.1:3010",
      OAUTH_ALLOW_GENERATED_KEYS: "true",
      // Every request in this suite arrives from one address, so the shipped
      // default of 10 sign-ins a minute throttles the suite itself rather than
      // anything under test. Raised here and asserted properly further down,
      // where an app is built with a deliberately tiny limit.
      OAUTH_LOGIN_RATE_LIMIT_PER_MINUTE: "1000",
      OAUTH_TOKEN_RATE_LIMIT_PER_MINUTE: "10000",
      OAUTH_CLIENT_REQUIRE_APPROVAL: "false",
      OAUTH_DYNAMIC_REGISTRATION_ENABLED: "true",
      OAUTH_REGISTRATION_ACCESS_TOKEN: "registration-token-at-least-32-characters",
      OAUTH_CUSTOM_SCOPES: JSON.stringify([
        { name: "credits.read", description: "Read your credit balance", claims: ["knight_uid"] },
        // Restricted, so there is a scope a signed-in non-admin cannot
        // authorize. That is the one way to reach a protocol error at
        // /oauth2/authorize/continue rather than at /oauth2/authorize: an
        // anonymous request is sent to the login page before the scope is ever
        // checked, so the refusal happens on the way back.
        { name: "ledger.admin", description: "Administer the ledger", adminOnly: true }
      ])
    });

    sentMail = [];
    const mailer = {
      sendEmailVerification: async (message) => sentMail.push({ kind: "verify", ...message }),
      sendPasswordReset: async (message) => sentMail.push({ kind: "reset", ...message }),
      sendExistingAccountNotice: async (message) => sentMail.push({ kind: "exists", ...message })
    };

    // Quiet: the error handler logs a stack for every 5xx, and a suite that
    // deliberately triggers one would bury a real failure in noise.
    const logger = { error() {}, warn() {}, info() {} };
    const auditLog = createAuditService({ prisma: db.prisma, logger });

    app = createApp({ env: config, prisma: db.prisma, logger, mailer, auditLog });

    const services = app.locals.services;
    accounts = services.accounts;
    clients = services.clients;

    // Two accounts. The first to register becomes ADMIN by default, which is
    // also what gives the admin pages someone to be rendered for.
    const first = await accounts.register({ email: "admin@example.com", password: PASSWORD, username: "admin" });
    await accounts.setRole({ userId: first.account.id, role: "ADMIN" });
    const second = await accounts.register({ email: "user@example.com", password: PASSWORD, username: "user" });
    await accounts.setAttributes({ userId: second.account.id, attributes: { knight_uid: 4242 } });

    const web = await clients.create(
      {
        name: "Third Party Web App",
        clientType: "confidential",
        redirectUris: ["https://rp.example/callback"],
        postLogoutRedirectUris: ["https://rp.example/signed-out"],
        scopes: ["openid", "profile", "email", "offline_access", "credits.read", "ledger.admin"],
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    confidential = web.client;
    confidentialSecret = web.clientSecret;

    const native = await clients.create(
      {
        name: "Native App",
        clientType: "public",
        redirectUris: ["http://127.0.0.1/callback"],
        scopes: ["openid", "profile"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "none",
        requireConsent: false
      },
      { status: "APPROVED" }
    );
    publicClient = native.client;

    user = await signIn("user@example.com");
    admin = await signIn("admin@example.com");
  });

  after(async () => {
    await db?.close();
  });

  /** Signs in through the real form and returns the agent holding the cookies. */
  async function signIn(email) {
    const agent = request.agent(app);
    const page = await agent.get("/login").expect(200);
    const response = await agent
      .post("/login")
      .type("form")
      .send({ _csrf: csrfFrom(page.text), identifier: email, password: PASSWORD })
      .expect(302);
    assert.equal(response.headers.location, "/account", `signing in as ${email} did not land on the account page`);
    return agent;
  }

  // --- Discovery ------------------------------------------------------------

  it("serves both discovery documents at the advertised paths", async () => {
    // A plain OAuth 2.0 library looks for RFC 8414's path and an OIDC library
    // looks for Discovery 1.0's. Serving one and not the other is a support
    // question rather than an error, which is why both are asserted.
    for (const path of ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]) {
      const response = await request(app).get(path).expect(200);
      assert.equal(response.body.issuer, config.issuer);
      assert.equal(response.body.authorization_endpoint, `${config.issuer}/oauth2/authorize`);
      assert.equal(response.body.token_endpoint, `${config.issuer}/oauth2/token`);
      assert.equal(response.body.jwks_uri, `${config.issuer}/oauth2/jwks`);
      // Every endpoint the document names must be one this server actually
      // mounts. A metadata document that points at a 404 is worse than an
      // absent one: the client configures itself and then fails at runtime.
      //
      // The probe has to use the method the endpoint accepts. The token,
      // introspection, revocation, and registration endpoints are POST-only —
      // that is correct, since none of them is safe to trigger with a link — so a
      // GET there answers 404 for the honest reason that no GET route exists.
      const POST_ONLY = new Set([
        "token_endpoint",
        "introspection_endpoint",
        "revocation_endpoint",
        "registration_endpoint",
        "pushed_authorization_request_endpoint",
        "device_authorization_endpoint"
      ]);
      for (const [key, value] of Object.entries(response.body)) {
        if (!key.endsWith("_endpoint") && key !== "jwks_uri") continue;
        const pathname = new URL(value).pathname;
        const mounted = POST_ONLY.has(key)
          ? await request(app).post(pathname).type("form").send({})
          : await request(app).get(pathname);
        assert.notEqual(mounted.status, 404, `${key} points at ${value}, which is not mounted`);
      }
    }
  });

  it("advertises the capabilities it actually exercises", async () => {
    // A capability the server uses but does not advertise is the harder failure
    // to find: `iss` is added to every authorization response (RFC 9207), and a
    // relying party is only told to expect and validate it by this flag. Without
    // it a strict client sees an unadvertised parameter, and a lenient one never
    // performs the mix-up check the parameter exists for.
    const { body } = await request(app).get("/.well-known/openid-configuration").expect(200);
    assert.equal(body.authorization_response_iss_parameter_supported, true);

    // Conversely, nothing may be advertised that is not implemented. Only S256
    // is accepted, so `plain` must not appear however permissive the config is.
    assert.deepEqual(body.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(body.response_types_supported, ["code"]);
    // HS256 would let any client holding its own secret mint a token this server
    // accepts as its own; `none` would remove signatures altogether.
    assert.ok(!body.id_token_signing_alg_values_supported.includes("HS256"));
    assert.ok(!body.id_token_signing_alg_values_supported.includes("none"));
  });

  it("serves the key set at both paths, with the registered media type", async () => {
    for (const path of ["/oauth2/jwks", "/.well-known/jwks.json"]) {
      const response = await request(app).get(path).expect(200);
      // RFC 7517 section 8.5. Some libraries check it.
      assert.match(response.headers["content-type"], /application\/jwk-set\+json/);
      assert.ok(Array.isArray(response.body.keys) && response.body.keys.length > 0);
      // A private key reaching this document would be the worst possible bug in
      // this project, so it is asserted rather than assumed.
      for (const key of response.body.keys) {
        for (const field of ["d", "p", "q", "dp", "dq", "qi", "k"]) {
          assert.equal(key[field], undefined, `the public key set leaked "${field}"`);
        }
      }
    }
  });

  it("answers a cross-origin request on the endpoints a browser client reads", async () => {
    // A single-page application fetches these from the browser. `*` is safe
    // here only because none of them authenticates by cookie — which is the
    // property this asserts: no credentials are ever allowed.
    for (const path of ["/.well-known/openid-configuration", "/oauth2/jwks", "/oauth2/token"]) {
      const preflight = await request(app).options(path).expect(204);
      assert.equal(preflight.headers["access-control-allow-origin"], "*");
      assert.equal(preflight.headers["access-control-allow-credentials"], undefined);
    }
  });

  it("reports its health, including where the signing keys came from", async () => {
    const response = await request(app).get("/healthz").expect(200);
    assert.equal(response.body.status, "ok");
    assert.ok(response.body.keys >= 1);
  });

  // --- The browser pages ----------------------------------------------------
  //
  // Each of these renders a template. The assertion that matters is the status
  // code: an EJS view throws on an undefined bare identifier, so a controller
  // that forgot a local is a 500 here and nowhere else.

  it("renders every page reachable without signing in", async () => {
    const pages = [
      ["/", /A standalone OAuth 2.0/],
      ["/login", /Sign in/],
      ["/register", /Create an account/],
      ["/forgot-password", /Reset your password/],
      ["/reset-password?token=nope", /Choose a new password/]
    ];
    for (const [path, expected] of pages) {
      const response = await request(app).get(path).expect(200);
      assert.match(response.text, expected, `${path} did not render as expected`);
      // The minimum a user is told must be the one that will be enforced.
      if (/password/.test(response.text) && /At least/.test(response.text)) {
        assert.match(response.text, new RegExp(`At least ${config.accounts.minPasswordLength} characters`));
      }
    }
  });

  it("renders every page that requires signing in", async () => {
    const pages = [
      ["/account", /Your account/],
      ["/account/applications", /Your applications/]
    ];
    for (const [path, expected] of pages) {
      const response = await user.get(path).expect(200);
      assert.match(response.text, expected, `${path} did not render as expected`);
    }
  });

  it("renders the administrative pages, and only for an administrator", async () => {
    for (const path of ["/admin/applications", "/admin/users"]) {
      const allowed = await admin.get(path).expect(200);
      assert.match(allowed.text, /Third Party Web App|admin@example.com/);
      // A non-administrator gets a page saying so, not a redirect loop and not
      // a stack trace.
      const refused = await user.get(path).expect(403);
      assert.match(refused.text, /do not have access/);
    }
  });

  it("sends a signed-out visitor to sign in, and back to where they were going", async () => {
    const response = await request(app).get("/account/applications").expect(302);
    assert.equal(response.headers.location, "/login?next=%2Faccount%2Fapplications");
  });

  it("will not use an off-site destination as a post-login redirect", async () => {
    // Echoing `next` back as a redirect would make the sign-in page an open
    // redirect, which is how a phishing flow borrows a trusted domain.
    const agent = request.agent(app);
    const page = await agent.get("/login").expect(200);
    for (const target of ["https://evil.example/steal", "//evil.example/steal"]) {
      const response = await agent
        .post("/login")
        .type("form")
        .send({ _csrf: csrfFrom(page.text), identifier: "user@example.com", password: PASSWORD, next: target })
        .expect(302);
      assert.equal(response.headers.location, "/account");
    }
  });

  it("renders a 404 as a page for a browser and as JSON for a protocol path", async () => {
    const page = await request(app).get("/no-such-page").expect(404);
    assert.match(page.text, /nothing here/i);
    const json = await request(app).get("/oauth2/no-such-endpoint").expect(404);
    assert.equal(json.body.error, "not_found");
  });

  // --- Security headers and CSRF --------------------------------------------

  it("sets a content security policy the pages can actually run under", async () => {
    const response = await request(app).get("/login").expect(200);
    const csp = response.headers["content-security-policy"];
    assert.ok(csp, "no content security policy was set");
    // No unsafe-inline, for either scripts or styles. This is the assertion that
    // keeps someone from "fixing" a style problem by widening the policy: if an
    // inline style is added to a view, the brand stylesheet below is the place
    // for it.
    assert.doesNotMatch(csp, /unsafe-inline/);
    assert.doesNotMatch(csp, /unsafe-eval/);
    assert.match(csp, /form-action 'self'/);
    assert.match(csp, /frame-ancestors 'none'/);
    // And nothing in any view may be an inline script or style, or the policy
    // above silently breaks the page.
    for (const path of ["/", "/login", "/register", "/forgot-password"]) {
      const page = await request(app).get(path).expect(200);
      assert.doesNotMatch(page.text, /<script(?![^>]*\bsrc=)/i, `${path} contains an inline script`);
      assert.doesNotMatch(page.text, /<style/i, `${path} contains an inline style`);
    }
    assert.equal(response.headers["x-powered-by"], undefined);
  });

  it("serves the operator's brand colour as a real stylesheet", async () => {
    // Inline would be dropped by the policy above without a word, so the one
    // configurable value that reaches CSS is served as a file.
    const response = await request(app).get("/static/css/brand.css").expect(200);
    assert.match(response.headers["content-type"], /text\/css/);
    assert.match(response.text, /--brand:/);
    const page = await request(app).get("/login").expect(200);
    assert.match(page.text, /href="\/static\/css\/brand\.css"/);
  });

  it("refuses a form post that carries no CSRF token", async () => {
    // This is the assertion that catches the middleware being reordered. CSRF
    // has to run after the body parser; put it before and it reads an empty
    // body, finds no token, and — depending on how it is written — either
    // rejects everything or passes everything. Both cases fail here.
    const response = await user
      .post("/account/profile")
      .type("form")
      .send({ name: "No Token" })
      .expect(403);
    assert.match(response.text, /could not be verified/);

    const stolen = await user
      .post("/account/profile")
      .type("form")
      .send({ _csrf: "not-the-right-token", name: "Wrong Token" })
      .expect(403);
    assert.match(stolen.text, /could not be verified/);
  });

  it("exempts the protocol endpoints from CSRF, because clients do not send one", async () => {
    // A conformant client library sends no CSRF token to the token endpoint and
    // never will. Requiring one there breaks every client; the endpoint is safe
    // because it authenticates the client with its own credentials rather than
    // with a cookie.
    const response = await request(app)
      .post("/oauth2/token")
      .type("form")
      .send({ grant_type: "authorization_code", code: "nonsense" });
    assert.notEqual(response.status, 403);
    assert.equal(response.body.error, "invalid_client");
  });

  // --- The full authorization code flow, over HTTP --------------------------

  it("runs an authorization code flow the way a client library drives it", async () => {
    const { verifier, challenge } = pkce();
    const state = crypto.randomBytes(16).toString("base64url");
    const nonce = crypto.randomBytes(16).toString("base64url");

    const authorizeQuery = new URLSearchParams({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "openid profile email offline_access credits.read",
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    // The client requires consent, so an authenticated user is sent to the
    // consent screen rather than straight back.
    const redirected = await user.get(`/oauth2/authorize?${authorizeQuery}`).expect(302);
    assert.match(redirected.headers.location, /^\/oauth2\/consent\?request=/);

    const consent = await user.get(redirected.headers.location).expect(200);
    assert.match(consent.text, /Third Party Web App/);
    // The origin the result is going to, which is the answer to "who am I
    // actually giving this to".
    assert.match(consent.text, /https:\/\/rp\.example/);
    assert.match(consent.text, /Read your credit balance/, "a deployment's own scope had no description");

    const requestToken = /name="request" value="([^"]+)"/.exec(consent.text)[1];
    const approved = await user
      .post("/oauth2/consent")
      .type("form")
      .send({
        _csrf: csrfFrom(consent.text),
        request: requestToken,
        decision: "allow",
        scope_selection: "1",
        scope: ["profile", "email", "offline_access", "credits.read"]
      })
      .expect(302);

    const callback = new URL(approved.headers.location);
    assert.equal(callback.origin + callback.pathname, "https://rp.example/callback");
    assert.equal(callback.searchParams.get("state"), state);
    // RFC 9207: the issuer in the authorization response, so a client can tell
    // which server answered when it talks to more than one.
    assert.equal(callback.searchParams.get("iss"), config.issuer);
    const code = callback.searchParams.get("code");
    assert.ok(code);

    const tokens = await request(app)
      .post("/oauth2/token")
      .type("form")
      .auth(confidential.clientId, confidentialSecret)
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: confidential.redirectUris[0],
        code_verifier: verifier
      })
      .expect(200);

    // RFC 6749 section 5.1: a cached token response is a token handed to the
    // next user of a shared cache.
    assert.match(tokens.headers["cache-control"], /no-store/);
    assert.equal(tokens.body.token_type, "Bearer");
    assert.ok(tokens.body.access_token);
    assert.ok(tokens.body.id_token);
    assert.ok(tokens.body.refresh_token, "offline_access was approved but no refresh token was issued");

    const userinfo = await request(app)
      .get("/oauth2/userinfo")
      .set("authorization", `Bearer ${tokens.body.access_token}`)
      .expect(200);
    // OIDC Core section 5.3.2: UserInfo MUST return `sub`.
    assert.ok(userinfo.body.sub);
    assert.equal(userinfo.body.email, "user@example.com");
    assert.equal(userinfo.body.knight_uid, 4242, "a configured custom claim did not reach UserInfo");

    // Section 5.3.1 also permits the token in a form-encoded POST body.
    const posted = await request(app)
      .post("/oauth2/userinfo")
      .type("form")
      .send({ access_token: tokens.body.access_token })
      .expect(200);
    assert.equal(posted.body.sub, userinfo.body.sub);

    const introspection = await request(app)
      .post("/oauth2/introspect")
      .type("form")
      .auth(confidential.clientId, confidentialSecret)
      .send({ token: tokens.body.access_token })
      .expect(200);
    assert.equal(introspection.body.active, true);

    await request(app)
      .post("/oauth2/revoke")
      .type("form")
      .auth(confidential.clientId, confidentialSecret)
      .send({ token: tokens.body.refresh_token })
      .expect(200);

    // RFC 7009 section 2.2: an unknown token is still a 200. A client cannot be
    // asked to distinguish "already revoked" from "never existed".
    await request(app)
      .post("/oauth2/revoke")
      .type("form")
      .auth(confidential.clientId, confidentialSecret)
      .send({ token: "never-existed" })
      .expect(200);
  });

  it("challenges a UserInfo request that carries no token", async () => {
    // RFC 6750 section 3: without a challenge some client libraries will not
    // retry, so a missing header is a compatibility bug rather than cosmetic.
    const response = await request(app).get("/oauth2/userinfo").expect(401);
    assert.match(response.headers["www-authenticate"], /^Bearer /);
    assert.equal(response.body.error, "invalid_token");
  });

  it("skips consent for a client that does not require it", async () => {
    const { challenge } = pkce();
    const query = new URLSearchParams({
      client_id: publicClient.clientId,
      redirect_uri: publicClient.redirectUris[0],
      response_type: "code",
      scope: "openid profile",
      state: "native-state",
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    const response = await user.get(`/oauth2/authorize?${query}`).expect(302);
    const target = new URL(response.headers.location);
    assert.equal(target.origin + target.pathname, "http://127.0.0.1/callback");
    assert.ok(target.searchParams.get("code"));
  });

  it("sends an unauthenticated authorization request to sign in and resumes it", async () => {
    const agent = request.agent(app);
    const { challenge } = pkce();
    const query = new URLSearchParams({
      client_id: publicClient.clientId,
      redirect_uri: publicClient.redirectUris[0],
      response_type: "code",
      scope: "openid",
      state: "resume-state",
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    const toLogin = await agent.get(`/oauth2/authorize?${query}`).expect(302);
    assert.match(toLogin.headers.location, /^\/login\?next=/);
    const next = new URL(toLogin.headers.location, config.publicBaseUrl).searchParams.get("next");
    assert.match(next, /^\/oauth2\/authorize\/continue\?request=/);

    const page = await agent.get(toLogin.headers.location).expect(200);
    const signedIn = await agent
      .post("/login")
      .type("form")
      .send({ _csrf: csrfFrom(page.text), identifier: "user@example.com", password: PASSWORD, next })
      .expect(302);
    assert.equal(signedIn.headers.location, next);

    // The parked request is re-evaluated on arrival rather than trusted: the
    // user who signed in may not be the one it was parked for.
    const resumed = await agent.get(next).expect(302);
    const target = new URL(resumed.headers.location);
    assert.equal(target.origin + target.pathname, "http://127.0.0.1/callback");
    assert.ok(target.searchParams.get("code"));
    assert.equal(target.searchParams.get("state"), "resume-state");
  });

  it("delivers an authorization error by redirect only once the redirect_uri is validated", async () => {
    // Getting this backwards turns the authorization endpoint into an open
    // redirect, so both halves are asserted.
    const unregistered = await user
      .get(`/oauth2/authorize?client_id=${confidential.clientId}&redirect_uri=https://evil.example/x&response_type=code&scope=openid`)
      .expect(400);
    assert.match(unregistered.text, /could not be completed/i);
    assert.doesNotMatch(unregistered.headers.location || "", /evil\.example/);

    // A validated redirect_uri with an unsupported response_type is the
    // client's error to receive, per RFC 6749 section 4.1.2.1.
    const registered = await user
      .get(
        `/oauth2/authorize?client_id=${confidential.clientId}` +
          `&redirect_uri=${encodeURIComponent(confidential.redirectUris[0])}` +
          "&response_type=token&scope=openid&state=err"
      )
      .expect(302);
    const target = new URL(registered.headers.location);
    assert.equal(target.origin + target.pathname, "https://rp.example/callback");
    assert.equal(target.searchParams.get("error"), "unsupported_response_type");
    assert.equal(target.searchParams.get("state"), "err");
  });

  it("accepts an authorization request by POST", async () => {
    // OIDC Core section 3.1.2.1 allows it, and a client with a long request
    // sends it that way.
    const { challenge } = pkce();
    const response = await user
      .post("/oauth2/authorize")
      .type("form")
      .send({
        _csrf: "not-needed-here",
        client_id: publicClient.clientId,
        redirect_uri: publicClient.redirectUris[0],
        response_type: "code",
        scope: "openid",
        state: "post-state",
        code_challenge: challenge,
        code_challenge_method: "S256"
      });
    // OIDC Core section 3.1.2.1 makes supporting POST a MUST. The form that
    // sends it belongs to the relying party, so it is cross-site by
    // construction: it carries no cookie of ours and cannot read a token to put
    // in `_csrf`. 403 is therefore the failure mode worth naming — the previous
    // `assert.ok([302, 403].includes(...))` accepted the endpoint being GET-only
    // and the requirement being met equally, which is how this went unnoticed.
    assert.equal(
      response.status,
      302,
      `expected a redirect, got ${response.status}` +
        (response.status === 403
          ? ": a relying party's cross-site form POST cannot carry a CSRF token, so this means POST is unsupported"
          : "")
    );
  });

  // --- Self-service: withdrawing access ------------------------------------

  it("lets a user see what has access and take it back", async () => {
    // The route the previous implementation never mounted, which meant a user
    // could grant access and had no way to withdraw it.
    const page = await user.get("/account").expect(200);
    assert.match(page.text, /Third Party Web App/, "the granted application was not listed");
    assert.match(page.text, /Remove access/);

    const revoked = await user
      .post("/account/grants/revoke")
      .type("form")
      .send({ _csrf: csrfFrom(page.text), client_id: confidential.clientId })
      .expect(302);
    assert.equal(revoked.headers.location, "/account?notice=access-revoked");

    // Following the redirect rather than re-requesting /account, because the
    // confirmation lives in the query string the redirect carries.
    const after = await user.get(revoked.headers.location).expect(200);
    assert.doesNotMatch(after.text, /Third Party Web App/);
    assert.match(after.text, /no longer has access/);
  });

  it("marks the session the user is looking at, and offers no way to end it here", async () => {
    const page = await user.get("/account").expect(200);
    assert.match(page.text, /this device/, "the current session was not marked");
    // Ending the session you are viewing the page in, from that page, is
    // indistinguishable from a bug. Signing out is in the header.
    const sessionForms = page.text.match(/name="session_id" value="([^"]+)"/g) || [];
    assert.ok(sessionForms.every((form) => !form.includes('value="all"') || sessionForms.length > 1));
  });

  it("lets a user register an application and shows the secret exactly once", async () => {
    const page = await user.get("/account/applications").expect(200);
    const created = await user
      .post("/account/applications")
      .type("form")
      .send({
        _csrf: csrfFrom(page.text),
        name: "My New App",
        client_type: "confidential",
        redirect_uris: "https://mine.example/callback",
        scope: "openid profile",
        grant_types: "authorization_code"
      })
      .expect(200);

    assert.match(created.text, /My New App is registered/);
    const secret = /Client secret<\/label>\s*<code class="secret">([^<]+)</.exec(created.text);
    assert.ok(secret, "no client secret was shown");
    assert.ok(secret[1].length >= 32);

    // Revisiting cannot show it again: only a hash is stored.
    const revisited = await user.get("/account/applications").expect(200);
    assert.doesNotMatch(revisited.text, new RegExp(secret[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(revisited.text, /My New App/);
  });

  it("will not let one user touch another user's application", async () => {
    const page = await admin.get("/account/applications").expect(200);
    // `admin` did not register it, so ownership is checked here rather than
    // trusted from the form.
    const response = await admin
      .post("/account/applications/delete")
      .type("form")
      .send({ _csrf: csrfFrom(page.text), client_id: confidential.clientId })
      .expect(403);
    assert.match(response.text, /not yours|went wrong/i);
    assert.ok(await clients.findByClientId(confidential.clientId), "the client was deleted anyway");
  });

  // --- Registration, recovery, verification --------------------------------

  it("reports unavailable once the database is gone", async () => {
    // The check used to answer from memory.
    //
    // `provider.jwks()` resolves from a key ring ensureKeyRing caches on first
    // use, and verifyBoot fills it before the port opens — so after boot this
    // endpoint returned a constant. A deployment whose database had gone
    // answered every real request with a 500 while /healthz stayed 200: the
    // compose healthcheck stayed green, no restart fired, and a load balancer
    // kept sending traffic to it. It reported that the process was running,
    // which was never the question.
    //
    // On its own database, because the way to test this is to take the database
    // away and the rest of the suite still needs one.
    const own = await withDatabase();
    const quiet = { error() {}, warn() {}, info() {} };
    const isolated = createApp({
      env: loadEnv({ PUBLIC_BASE_URL: "http://127.0.0.1:3010", OAUTH_ALLOW_GENERATED_KEYS: "true" }),
      prisma: own.prisma,
      logger: quiet,
      mailer: {
        sendEmailVerification: async () => {},
        sendPasswordReset: async () => {},
        sendExistingAccountNotice: async () => {}
      },
      auditLog: createAuditService({ prisma: own.prisma, logger: quiet })
    });

    const healthy = await request(isolated).get("/healthz").expect(200);
    assert.equal(healthy.body.status, "ok");

    await own.close();

    const unavailable = await request(isolated).get("/healthz").expect(503);
    assert.equal(unavailable.body.status, "unavailable");
  });

  it("meters only paths that a route actually serves", async () => {
    // A rule naming a path nothing is mounted at is silently dead: no error, no
    // warning, just a limit that never applies. That is the same shape as the
    // defect the limiter itself was written to fix — a setting with no
    // consumer — one level up, and renaming a route is all it would take.
    //
    // 404 is the only status this rejects. A CSRF refusal or a protocol error
    // both prove the route is there, which is the whole question.
    for (const rule of buildRules(config.security)) {
      const response = await request(app).post(rule.path).type("form").send({});
      assert.notEqual(response.status, 404, `${rule.path} is rate limited but no route serves it`);
    }
  });

  it("enforces the configured login rate limit through the real app", async () => {
    // The point of this test is not that a counter counts.
    //
    // OAUTH_LOGIN_RATE_LIMIT_PER_MINUTE and OAUTH_TOKEN_RATE_LIMIT_PER_MINUTE
    // were parsed, range-checked, documented in .env.example, and referred to
    // by README and compose.yml as "the rate limiter" while nothing in the
    // codebase read either one. A unit test on the middleware would have passed
    // throughout. So this builds an app the ordinary way, from a config whose
    // only distinguishing feature is a tiny limit, and drives it over HTTP: it
    // fails if the middleware is not mounted, if it is mounted where the body
    // is not parsed yet, or if it ignores the configured value.
    const quiet = { error() {}, warn() {}, info() {} };
    const limited = createApp({
      env: loadEnv({
        PUBLIC_BASE_URL: "http://127.0.0.1:3010",
        OAUTH_ALLOW_GENERATED_KEYS: "true",
        OAUTH_LOGIN_RATE_LIMIT_PER_MINUTE: "2"
      }),
      prisma: db.prisma,
      logger: quiet,
      mailer: {
        sendEmailVerification: async () => {},
        sendPasswordReset: async () => {},
        sendExistingAccountNotice: async () => {}
      },
      auditLog: createAuditService({ prisma: db.prisma, logger: quiet })
    });

    const agent = request.agent(limited);
    const page = await agent.get("/login").expect(200);
    const token = csrfFrom(page.text);
    const attempt = () =>
      agent
        .post("/login")
        .type("form")
        .send({ _csrf: token, identifier: "user@example.com", password: "not-the-right-password" });

    // Wrong on purpose: a rejected sign-in still pays for a full scrypt, which
    // is the cost being metered.
    await attempt();
    await attempt();

    const blocked = await attempt().expect(429);
    assert.ok(blocked.headers["retry-after"], "a 429 has to say when it is worth trying again");
    assert.match(blocked.text, /too many attempts/i);
  });

  it("registers an account without signing it in, and the account then works", async () => {
    const agent = request.agent(app);
    const page = await agent.get("/register").expect(200);
    const response = await agent
      .post("/register")
      .type("form")
      .send({
        _csrf: csrfFrom(page.text),
        email: "fresh@example.com",
        username: "fresh",
        name: "Fresh Account",
        password: PASSWORD
      })
      .expect(200);
    assert.match(response.text, /Check your email/);

    // Registration establishes no session, and cannot: a free address that came
    // back with a cookie next to a taken one that did not is distinguishable
    // from the response line alone, without reading a word of either page.
    const cookies = response.headers["set-cookie"] || [];
    assert.ok(
      !cookies.some((cookie) => cookie.startsWith("koauth_session=")),
      "registering handed out a session cookie, which is the enumeration tell"
    );

    // Signing in is the separate, explicit step — and it works, so the account
    // really was created.
    const login = await agent.get("/login").expect(200);
    await agent
      .post("/login")
      .type("form")
      .send({ _csrf: csrfFrom(login.text), identifier: "fresh@example.com", password: PASSWORD })
      .expect(302);
    const account = await agent.get("/account").expect(200);
    assert.match(account.text, /fresh@example\.com/);
  });

  it("answers a registration for an existing address exactly as it answers a new one", async () => {
    // An authorization server that reveals whether an address is registered is
    // an account-enumeration oracle, so the two responses must be the same page.
    //
    // Compared byte for byte, the way the password-reset test below does it.
    // Asserting a 200 and the absence of /already|taken|exists/ was what this
    // did before, and it let the actual difference through untouched: a free
    // address answered 302 with a session cookie while a taken one answered 200
    // HTML. Nothing about the wording was ever the problem.
    const responses = [];
    for (const email of ["user@example.com", "not-registered-yet@example.com"]) {
      const agent = request.agent(app);
      const page = await agent.get("/register").expect(200);
      const response = await agent
        .post("/register")
        .type("form")
        .send({ _csrf: csrfFrom(page.text), email, password: PASSWORD })
        .expect(200);
      responses.push(
        response.text
          // The CSRF token differs by construction.
          .replace(/value="[^"]*"/g, "")
          // The page echoes the address the caller submitted, which they
          // already know. Normalised so the comparison is about everything else.
          .replaceAll(email, "{address}")
      );
    }
    assert.equal(responses[0], responses[1], "the two answers differ, which reveals whether the address exists");
  });

  it("answers a password reset for an unknown address the same way as a known one", async () => {
    const responses = [];
    for (const email of ["user@example.com", "nobody-at-all@example.com"]) {
      const agent = request.agent(app);
      const page = await agent.get("/forgot-password").expect(200);
      const response = await agent
        .post("/forgot-password")
        .type("form")
        .send({ _csrf: csrfFrom(page.text), email })
        .expect(200);
      // Strip the token, which differs by construction, and compare the rest.
      responses.push(response.text.replace(/value="[^"]*"/g, ""));
    }
    assert.equal(responses[0], responses[1], "the two answers differ, which reveals whether the address exists");
  });

  it("completes a password reset through the emailed link", async () => {
    sentMail.length = 0;
    const agent = request.agent(app);
    const forgot = await agent.get("/forgot-password").expect(200);
    await agent
      .post("/forgot-password")
      .type("form")
      .send({ _csrf: csrfFrom(forgot.text), email: "fresh@example.com" })
      .expect(200);

    const message = sentMail.find((entry) => entry.kind === "reset");
    assert.ok(message, "no reset message was sent");
    // The service hands the mailer the raw token and lets the mail layer build the
    // URL, so this is the token a real deployment would put in the link.
    const token = message.token;
    assert.ok(token, "the reset message carried no token");

    const page = await agent.get(`/reset-password?token=${encodeURIComponent(token)}`).expect(200);
    const done = await agent
      .post("/reset-password")
      .type("form")
      .send({ _csrf: csrfFrom(page.text), token, password: "a-brand-new-passphrase-here" })
      .expect(200);
    assert.match(done.text, /password has been changed/i);

    // Single use.
    const replay = await agent.get("/reset-password?token=" + encodeURIComponent(token)).expect(200);
    const refused = await agent
      .post("/reset-password")
      .type("form")
      .send({ _csrf: csrfFrom(replay.text), token, password: "yet-another-passphrase" })
      .expect(400);
    assert.match(refused.text, /not valid|already/i);
  });

  it("says the same thing whether or not a sign-in attempt matched", async () => {
    const agent = request.agent(app);
    const page = await agent.get("/login").expect(200);
    const csrf = csrfFrom(page.text);
    const wrongPassword = await agent
      .post("/login")
      .type("form")
      .send({ _csrf: csrf, identifier: "user@example.com", password: "not-the-password" })
      .expect(401);
    const noSuchAccount = await agent
      .post("/login")
      .type("form")
      .send({ _csrf: csrf, identifier: "nobody@example.com", password: "not-the-password" })
      .expect(401);
    assert.match(wrongPassword.text, /do not match/);
    assert.equal(
      wrongPassword.text.replace(/value="[^"]*"/g, ""),
      noSuchAccount.text.replace(/value="[^"]*"/g, "")
    );
  });

  it("signs a user out and drops the session", async () => {
    // This account's password was replaced by the reset above, so the old one has
    // to be refused and the new one has to work. Both are asserted here, because
    // a reset that leaves the previous password usable is the failure that would
    // otherwise look like a passing reset test.
    const stale = request.agent(app);
    const stalePage = await stale.get("/login").expect(200);
    await stale
      .post("/login")
      .type("form")
      .send({ _csrf: csrfFrom(stalePage.text), identifier: "fresh@example.com", password: PASSWORD })
      .expect(401);

    const fresh = request.agent(app);
    const page = await fresh.get("/login").expect(200);
    await fresh
      .post("/login")
      .type("form")
      .send({ _csrf: csrfFrom(page.text), identifier: "fresh@example.com", password: "a-brand-new-passphrase-here" })
      .expect(302);

    const account = await fresh.get("/account").expect(200);
    const out = await fresh
      .post("/logout")
      .type("form")
      .send({ _csrf: csrfFrom(account.text) })
      .expect(302);
    assert.equal(out.headers.location, "/");
    // The session is gone, not merely forgotten by the page. The cookie is still
    // in the agent's jar, so this proves the server dropped the record rather
    // than the browser dropping the cookie.
    await fresh.get("/account").expect(302);
  });

  // --- Administration -------------------------------------------------------

  it("lets an administrator approve, disable, and delete an application", async () => {
    const submitted = await clients.create(
      {
        name: "Awaiting Review",
        clientType: "confidential",
        redirectUris: ["https://review.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"]
      },
      { status: "PENDING" }
    );

    const page = await admin.get("/admin/applications").expect(200);
    assert.match(page.text, /Awaiting Review/);
    assert.match(page.text, /pending/);

    const approved = await admin
      .post("/admin/applications/approve")
      .type("form")
      .send({ _csrf: csrfFrom(page.text), client_id: submitted.client.clientId })
      .expect(200);
    // Approving a confidential client mints its secret, shown exactly once.
    assert.match(approved.text, /Awaiting Review is approved/);
    assert.match(approved.text, /Client secret/);

    const disabled = await admin
      .post("/admin/applications/status")
      .type("form")
      .send({ _csrf: csrfFrom(approved.text), client_id: submitted.client.clientId, status: "DISABLED" })
      .expect(302);
    assert.equal(disabled.headers.location, "/admin/applications?notice=status-changed");

    const listing = await admin.get("/admin/applications").expect(200);
    const removed = await admin
      .post("/admin/applications/delete")
      .type("form")
      .send({ _csrf: csrfFrom(listing.text), client_id: submitted.client.clientId })
      .expect(302);
    assert.equal(removed.headers.location, "/admin/applications?notice=application-deleted");
    assert.equal(await clients.findByClientId(submitted.client.clientId), null);
  });

  it("refuses to let an administrator disable or demote themselves", async () => {
    // Locking yourself out of the only administrative surface is not
    // recoverable through the UI.
    const page = await admin.get("/admin/users").expect(200);
    const self = await accounts.findByEmail("admin@example.com");

    for (const [path, body] of [
      ["/admin/users/status", { user_id: self.id, status: "DISABLED" }],
      ["/admin/users/role", { user_id: self.id, role: "USER" }]
    ]) {
      const response = await admin
        .post(path)
        .type("form")
        .send({ _csrf: csrfFrom(page.text), ...body })
        .expect(400);
      assert.match(response.text, /cannot change your own/i);
    }

    const unchanged = await accounts.findByEmail("admin@example.com");
    assert.equal(unchanged.role, "ADMIN");
    assert.equal(unchanged.status, "ACTIVE");
  });

  it("lets an administrator search accounts and change another one's role", async () => {
    const found = await admin.get("/admin/users?q=user@example.com").expect(200);
    assert.match(found.text, /user@example\.com/);
    assert.doesNotMatch(found.text, /fresh@example\.com/, "the search returned an account it should not have");

    const target = await accounts.findByEmail("fresh@example.com");
    const changed = await admin
      .post("/admin/users/role")
      .type("form")
      .send({ _csrf: csrfFrom(found.text), user_id: target.id, role: "ADMIN" })
      .expect(302);
    assert.equal(changed.headers.location, "/admin/users?notice=role-changed");
    assert.equal((await accounts.findById(target.id)).role, "ADMIN");
  });

  it("returns a protocol error raised after sign-in to the client, not to the browser", async () => {
    // The refusal has to reach the relying party. Rendering it on the issuer
    // left the client with no answer at all: the user saw a page here, and the
    // authorization request it was waiting on simply never came back.
    //
    // `ledger.admin` is the lever. An anonymous request is sent to the login
    // page before the scope is checked, so the refusal happens on the way back,
    // at /oauth2/authorize/continue — by which point the redirect_uri has been
    // matched against the client's registrations and the error is the client's
    // to receive.
    const agent = request.agent(app);
    const { challenge } = pkce();
    const query = new URLSearchParams({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "openid ledger.admin",
      state: "continue-error",
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    const started = await agent.get(`/oauth2/authorize?${query}`).expect(302);
    const loginUrl = new URL(started.headers.location, "http://127.0.0.1:3010");
    assert.equal(loginUrl.pathname, "/login", "an anonymous request must reach the login page first");
    const continueUrl = loginUrl.searchParams.get("next");
    assert.ok(continueUrl?.startsWith("/oauth2/authorize/continue"));

    const page = await agent.get("/login").expect(200);
    await agent
      .post("/login")
      .type("form")
      .send({ _csrf: csrfFrom(page.text), identifier: "user@example.com", password: PASSWORD })
      .expect(302);

    // user@example.com is not an admin, so resolveAuthorization refuses the
    // scope on this pass.
    const refused = await agent.get(continueUrl).expect(302);
    const target = new URL(refused.headers.location);
    assert.equal(target.origin + target.pathname, "https://rp.example/callback", "the client was not told");
    assert.equal(target.searchParams.get("error"), "invalid_scope");
    assert.equal(target.searchParams.get("state"), "continue-error");
    // RFC 9207 applies to this response like any other.
    assert.equal(target.searchParams.get("iss"), "http://127.0.0.1:3010");
  });

  // --- Dynamic client registration -----------------------------------------

  it("rejects a registration with the RFC 7591 code for what was wrong with it", async () => {
    // Section 3.2.2 gives registration its own codes, and a client branches on
    // them the same way a token client branches on invalid_grant. Answering a
    // well-formed document with a bad field the same way as a malformed request
    // — `invalid_request` for both — tells the caller only that something,
    // somewhere in twenty fields, was not right.
    const post = (body) =>
      request(app)
        .post("/oauth2/register")
        .set("authorization", "Bearer registration-token-at-least-32-characters")
        .send(body);

    const badRedirect = await post({
      client_name: "Bad Redirect",
      redirect_uris: ["https://rp.example/cb#fragment"]
    }).expect(400);
    assert.equal(badRedirect.body.error, "invalid_redirect_uri");

    const noRedirect = await post({ client_name: "No Redirect", redirect_uris: [] }).expect(400);
    assert.equal(noRedirect.body.error, "invalid_redirect_uri");

    const badScope = await post({
      client_name: "Bad Scope",
      redirect_uris: ["https://rp.example/cb"],
      scope: "openid not-a-registered-scope"
    }).expect(400);
    assert.equal(badScope.body.error, "invalid_client_metadata");

    // A grant the token endpoint does not implement. Accepting it here meant a
    // client could register for client_credentials, read it back in its own
    // metadata, and find out at the first request that the endpoint has only
    // two branches and neither is that one.
    const badGrant = await post({
      client_name: "Bad Grant",
      redirect_uris: ["https://rp.example/cb"],
      grant_types: ["client_credentials"]
    }).expect(400);
    assert.equal(badGrant.body.error, "invalid_client_metadata");
    assert.match(badGrant.body.error_description, /client_credentials/);
  });

  it("registers a client dynamically and manages it with the returned token", async () => {
    // RFC 7591 and 7592. This is what an off-the-shelf client that self-registers
    // does, and the initial access token is what keeps the endpoint from being
    // open to anyone.
    const registered = await request(app)
      .post("/oauth2/register")
      .set("authorization", "Bearer registration-token-at-least-32-characters")
      .send({
        client_name: "Self Registered",
        redirect_uris: ["https://self.example/callback"],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid profile",
        token_endpoint_auth_method: "client_secret_basic"
      })
      .expect(201);

    assert.ok(registered.body.client_id);
    assert.ok(registered.body.client_secret);
    assert.ok(registered.body.registration_access_token);
    assert.match(registered.body.registration_client_uri, /\/oauth2\/register\//);
    assert.match(registered.headers["cache-control"], /no-store/);

    const token = registered.body.registration_access_token;
    const uri = new URL(registered.body.registration_client_uri).pathname;

    const read = await request(app).get(uri).set("authorization", `Bearer ${token}`).expect(200);
    assert.equal(read.body.client_id, registered.body.client_id);
    // Section 3.2.1: the secret is returned at registration and not again.
    assert.equal(read.body.client_secret, undefined);

    const updated = await request(app)
      .put(uri)
      .set("authorization", `Bearer ${token}`)
      .send({
        client_id: registered.body.client_id,
        client_name: "Renamed",
        redirect_uris: ["https://self.example/callback", "https://self.example/other"],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid profile"
      })
      .expect(200);
    assert.equal(updated.body.client_name, "Renamed");
    assert.equal(updated.body.redirect_uris.length, 2);

    // Another client's token must not work on this one.
    await request(app).get(uri).set("authorization", "Bearer wrong-token").expect(401);
    await request(app).get(uri).expect(401);

    // Section 2.3: 204, no body.
    await request(app).delete(uri).set("authorization", `Bearer ${token}`).expect(204);
    await request(app).get(uri).set("authorization", `Bearer ${token}`).expect(401);
  });

  it("refuses dynamic registration without the initial access token", async () => {
    const response = await request(app)
      .post("/oauth2/register")
      .send({ client_name: "Uninvited", redirect_uris: ["https://uninvited.example/callback"] })
      .expect(401);
    assert.match(response.headers["www-authenticate"] || "", /Bearer/);
  });

  // --- RP-initiated logout --------------------------------------------------

  it("shows an interstitial for a logout GET with no id_token_hint", async () => {
    // RP-Initiated Logout arrives as a GET, and a GET that ends a session can be
    // triggered by any page that can make the browser navigate. The spec allows
    // the interstitial for exactly that reason.
    const agent = await signIn("user@example.com");
    const page = await agent
      .get(
        `/oauth2/logout?client_id=${confidential.clientId}` +
          `&post_logout_redirect_uri=${encodeURIComponent("https://rp.example/signed-out")}&state=bye`
      )
      .expect(200);
    assert.match(page.text, /Sign out/);
    assert.match(page.text, /Third Party Web App is asking/);
    // Still signed in: the page asked rather than acted.
    await agent.get("/account").expect(200);

    const out = await agent
      .post("/oauth2/logout")
      .type("form")
      .send({
        _csrf: csrfFrom(page.text),
        client_id: confidential.clientId,
        post_logout_redirect_uri: "https://rp.example/signed-out",
        state: "bye"
      })
      .expect(302);
    const target = new URL(out.headers.location);
    assert.equal(target.origin + target.pathname, "https://rp.example/signed-out");
    assert.equal(target.searchParams.get("state"), "bye");
    await agent.get("/account").expect(302);
  });

  it("refuses an unregistered post-logout redirect", async () => {
    const agent = await signIn("user@example.com");
    const page = await agent
      .get(
        `/oauth2/logout?client_id=${confidential.clientId}` +
          `&post_logout_redirect_uri=${encodeURIComponent("https://evil.example/x")}`
      )
      .expect(200);
    const out = await agent
      .post("/oauth2/logout")
      .type("form")
      .send({
        _csrf: csrfFrom(page.text),
        client_id: confidential.clientId,
        post_logout_redirect_uri: "https://evil.example/x"
      })
      .expect(302);
    // Signed out, but sent home rather than to an unregistered destination.
    assert.equal(out.headers.location, "/");
  });

  it("honours a logout redirect for a visitor who is already signed out", async () => {
    // Otherwise a client's sign-out flow dead-ends on this server's page.
    const response = await request(app)
      .get(
        `/oauth2/logout?client_id=${confidential.clientId}` +
          `&post_logout_redirect_uri=${encodeURIComponent("https://rp.example/signed-out")}`
      )
      .expect(302);
    assert.match(response.headers.location, /^https:\/\/rp\.example\/signed-out/);
  });
});

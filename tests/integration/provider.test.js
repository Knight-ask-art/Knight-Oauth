"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { after, before, describe, it } = require("node:test");

const { withDatabase } = require("../helpers/database");
const { loadEnv } = require("../../src/config/env");
const { createScopeRegistry } = require("../../src/lib/scopes");
const { hashToken } = require("../../src/lib/crypto");
const { decodeJwt } = require("../../src/lib/jwt");
const { createAccountService } = require("../../src/services/accountService");
const { createAuditService } = require("../../src/services/auditService");
const { createBackchannelService } = require("../../src/services/backchannelService");
const { createClientService } = require("../../src/services/clientService");
const { createKeyService } = require("../../src/services/keyService");
const { createProviderService } = require("../../src/services/providerService");
const { createSessionService } = require("../../src/services/sessionService");

// The compatibility suite.
//
// Every assertion here stands for something a third-party client library does
// unconditionally, so a failure means a stock relying party breaks against this
// issuer. The flow is driven exactly as a client would drive it — parse the
// authorization request, log in, consent, redeem the code at the token endpoint,
// call UserInfo with the bearer token — rather than by calling internals in an
// order no client would use.

/** PKCE as a client library generates it (RFC 7636 section 4). */
function pkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier, "ascii").digest("base64url");
  return { verifier, challenge };
}

function basicAuth(clientId, clientSecret) {
  // RFC 6749 section 2.3.1: form-urlencode both halves before base64.
  const encoded = Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`
  ).toString("base64");
  return { authorization: `Basic ${encoded}` };
}

describe("OAuth 2.0 and OpenID Connect provider", () => {
  let db;
  let prisma;
  let config;
  let scopeRegistry;
  let accounts;
  let sessions;
  let clients;
  let keys;
  let provider;
  let backchannelPosts;

  let account;
  let session;
  let confidential;
  let confidentialSecret;
  let publicClient;

  before(async () => {
    db = await withDatabase();
    prisma = db.prisma;

    config = loadEnv({
      PUBLIC_BASE_URL: "http://127.0.0.1:3010",
      DATABASE_PROVIDER: db.provider,
      DATABASE_URL: db.url,
      OAUTH_ALLOW_GENERATED_KEYS: "true",
      OAUTH_CLIENT_REQUIRE_APPROVAL: "false",
      OAUTH_DYNAMIC_REGISTRATION_ENABLED: "true",
      OAUTH_REGISTRATION_ACCESS_TOKEN: "registration-token-at-least-32-characters",
      // A deployment-specific scope, to prove the extension path works through
      // configuration alone rather than through anything in the core.
      OAUTH_CUSTOM_SCOPES: JSON.stringify([
        {
          name: "credits.read",
          description: "Read your credit balance",
          claims: ["knight_uid"]
        },
        {
          name: "credits.admin",
          description: "Administer credits",
          adminOnly: true,
          introspectionClaim: "credits_admin"
        },
        {
          name: "legacy.admin",
          description: "Legacy administration without a live authority claim",
          adminOnly: true
        }
      ])
    });

    const auditLog = createAuditService({ prisma, logger: { error() {} } });
    scopeRegistry = createScopeRegistry({ customScopes: config.customScopes });
    accounts = createAccountService({ prisma, config, auditLog });
    sessions = createSessionService({ prisma, config, auditLog });
    clients = createClientService({ prisma, config, scopeRegistry, auditLog });
    keys = createKeyService({ prisma, config: config.signing });

    backchannelPosts = [];
    const backchannel = createBackchannelService({
      prisma,
      config,
      clients,
      keys,
      auditLog,
      fetchImpl: async (url, init) => {
        backchannelPosts.push({ url, body: init.body });
        return { status: 200 };
      }
    });

    provider = createProviderService({
      prisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog,
      backchannel
    });

    const registered = await accounts.register({
      email: "owner@example.com",
      password: "correct-horse-battery-staple",
      username: "owner",
      name: "Ada Lovelace"
    });
    account = registered.account;
    await accounts.setAttributes({ userId: account.id, attributes: { knight_uid: 4242 } });
    account = await accounts.findById(account.id);

    const login = await sessions.login({ userId: account.id });
    session = login.session;

    const created = await clients.create(
      {
        name: "Third Party Web App",
        clientType: "confidential",
        redirectUris: ["https://rp.example/callback"],
        postLogoutRedirectUris: ["https://rp.example/signed-out"],
        backchannelLogoutUri: "https://rp.example/backchannel-logout",
        scopes: ["openid", "profile", "email", "offline_access", "credits.read"],
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    confidential = created.client;
    confidentialSecret = created.clientSecret;

    const nativeApp = await clients.create(
      {
        name: "Native App",
        clientType: "public",
        // RFC 8252: a native app registers a loopback redirect.
        redirectUris: ["http://127.0.0.1/callback"],
        scopes: ["openid", "profile", "offline_access"],
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "none",
        requireConsent: false
      },
      { status: "APPROVED" }
    );
    publicClient = nativeApp.client;
  });

  after(async () => {
    await db?.close();
  });

  /** Drives a full authorization request through to a redirect carrying a code. */
  async function authorize(
    overrides = {},
    { client = confidential, approve = true, browserSession = session, authorizationAccount = account } = {}
  ) {
    const challenge = overrides.code_challenge === undefined ? pkce() : null;
    const params = {
      client_id: client.clientId,
      redirect_uri: client.redirectUris[0],
      response_type: "code",
      scope: "openid profile email",
      ...(challenge ? { code_challenge: challenge.challenge, code_challenge_method: "S256" } : {}),
      ...overrides
    };
    const request = await provider.parseAuthorizationRequest(params);
    const requestToken = await provider.persistAuthorizationRequest(request);

    const loaded = await provider.loadAuthorizationRequest(requestToken);
    const decision = await provider.resolveAuthorization({
      request: loaded,
      account: authorizationAccount,
      session: browserSession
    });

    const approvedScopes = Object.prototype.hasOwnProperty.call(overrides, "approvedScopes")
      ? overrides.approvedScopes
      : decision.action === "consent"
        ? loaded.scopes
        : null;
    const result = approve
      ? await provider.completeAuthorization({
          requestToken,
          account: authorizationAccount,
          session: browserSession,
          approvedScopes
        })
      : await provider.denyAuthorization({ requestToken });

    const url = new URL(result.redirectUrl);
    return {
      decision,
      verifier: challenge?.verifier || null,
      code: url.searchParams.get("code"),
      state: url.searchParams.get("state"),
      iss: url.searchParams.get("iss"),
      error: url.searchParams.get("error"),
      redirectUri: params.redirect_uri,
      url
    };
  }

  // --- Discovery ----------------------------------------------------------

  it("publishes discovery metadata a client library can configure itself from", async () => {
    const document = await provider.discoveryDocument();

    // A client compares `issuer` byte-for-byte against the ID token `iss`.
    assert.equal(document.issuer, "http://127.0.0.1:3010");
    assert.equal(document.authorization_endpoint, "http://127.0.0.1:3010/oauth2/authorize");
    assert.equal(document.token_endpoint, "http://127.0.0.1:3010/oauth2/token");
    assert.equal(document.userinfo_endpoint, "http://127.0.0.1:3010/oauth2/userinfo");
    assert.equal(document.jwks_uri, "http://127.0.0.1:3010/oauth2/jwks");

    assert.deepEqual(document.response_types_supported, ["code"]);
    assert.deepEqual(document.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(document.grant_types_supported, ["authorization_code", "refresh_token"]);

    // The three client authentication methods. A library defaulting to
    // client_secret_post — many do — must find it advertised here.
    assert.deepEqual(document.token_endpoint_auth_methods_supported, [
      "client_secret_basic",
      "client_secret_post",
      "none"
    ]);

    // A configured custom scope appears without the core knowing what it means.
    assert.ok(document.scopes_supported.includes("credits.read"));
    assert.ok(document.claims_supported.includes("sub"));
    assert.ok(document.claims_supported.includes("knight_uid"));

    // Dynamic registration is advertised only when it is enabled.
    assert.equal(document.registration_endpoint, "http://127.0.0.1:3010/oauth2/register");
  });

  it("serves RFC 8414 metadata for a plain OAuth 2.0 client", async () => {
    const document = await provider.authorizationServerMetadata();
    assert.equal(document.issuer, "http://127.0.0.1:3010");
    assert.equal(document.token_endpoint, "http://127.0.0.1:3010/oauth2/token");
    // `claims_supported` is an OIDC concept and does not belong in this document.
    assert.equal(document.claims_supported, undefined);
  });

  it("publishes only public key material in JWKS", async () => {
    const jwks = await provider.jwks();
    assert.ok(Array.isArray(jwks.keys) && jwks.keys.length >= 1);
    for (const key of jwks.keys) {
      assert.ok(key.kid, "every published key needs a kid so a client can select one");
      // A private component in JWKS would leak the signing key to the world.
      for (const field of ["d", "p", "q", "dp", "dq", "qi", "k"]) {
        assert.equal(key[field], undefined, `JWKS must not publish the private component "${field}"`);
      }
    }
  });

  // --- Authorization request ----------------------------------------------

  it("accepts an authorization request with no state and no nonce", async () => {
    // RFC 6749 makes `state` RECOMMENDED and OIDC Core makes `nonce` OPTIONAL for
    // the code flow. A PKCE-only client sends neither; rejecting it locks out
    // conformant libraries.
    const request = await provider.parseAuthorizationRequest({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "openid",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256"
    });
    assert.equal(request.state, null);
    assert.equal(request.nonce, null);
    assert.deepEqual(request.scopes, ["openid"]);
  });

  it("accepts a plain OAuth 2.0 request that does not ask for openid", async () => {
    const request = await provider.parseAuthorizationRequest({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "credits.read",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256"
    });
    assert.equal(request.isOidc, false);
    assert.deepEqual(request.scopes, ["credits.read"]);
  });

  it("drops an unknown scope instead of failing the request", async () => {
    const request = await provider.parseAuthorizationRequest({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "openid profile no_such_scope",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256"
    });
    assert.deepEqual(request.scopes, ["openid", "profile"]);
    assert.deepEqual(request.unknownScopes, ["no_such_scope"]);
  });

  it("refuses to report an unregistered redirect_uri by redirecting to it", async () => {
    await assert.rejects(
      provider.parseAuthorizationRequest({
        client_id: confidential.clientId,
        redirect_uri: "https://attacker.example/collect",
        response_type: "code",
        scope: "openid"
      }),
      (error) => {
        assert.equal(error.code, "invalid_request");
        // Redirecting here would be the open redirect the exact-match rule exists
        // to prevent, so no redirect target may be attached.
        assert.equal(error.redirectValidated, undefined);
        return true;
      }
    );
  });

  it("reports an unsupported response_type as a redirect once the client checks out", async () => {
    await assert.rejects(
      provider.parseAuthorizationRequest({
        client_id: confidential.clientId,
        redirect_uri: confidential.redirectUris[0],
        response_type: "token",
        scope: "openid",
        state: "abc"
      }),
      (error) => {
        assert.equal(error.code, "unsupported_response_type");
        // RFC 6749 section 4.1.2.1: deliverable to the client, with `state`.
        assert.equal(error.redirectValidated, true);
        assert.equal(error.redirectUri, confidential.redirectUris[0]);
        assert.equal(error.state, "abc");
        return true;
      }
    );
  });

  it("requires PKCE from a public client", async () => {
    await assert.rejects(
      provider.parseAuthorizationRequest({
        client_id: publicClient.clientId,
        redirect_uri: publicClient.redirectUris[0],
        response_type: "code",
        scope: "openid"
      }),
      /public client must use PKCE/
    );
  });

  it("rejects a code_challenge_method other than S256", async () => {
    await assert.rejects(
      provider.parseAuthorizationRequest({
        client_id: confidential.clientId,
        redirect_uri: confidential.redirectUris[0],
        response_type: "code",
        scope: "openid",
        code_challenge: pkce().verifier,
        code_challenge_method: "plain"
      }),
      /code_challenge_method must be S256/
    );
  });

  it("floats the loopback port a native app listens on", async () => {
    // RFC 8252 section 7.3: the port of a loopback redirect is chosen at runtime,
    // so it must not be part of the comparison.
    const { verifier, challenge } = pkce();
    const request = await provider.parseAuthorizationRequest({
      client_id: publicClient.clientId,
      redirect_uri: "http://127.0.0.1:54321/callback",
      response_type: "code",
      scope: "openid",
      code_challenge: challenge,
      code_challenge_method: "S256"
    });
    // The requested form is carried forward, because the token request must send
    // back exactly what the authorization request used.
    assert.equal(request.redirectUri, "http://127.0.0.1:54321/callback");
    assert.ok(verifier);
  });

  // --- prompt and max_age -------------------------------------------------

  it("answers prompt=none with login_required when nobody is signed in", async () => {
    const request = await provider.parseAuthorizationRequest({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "openid",
      prompt: "none",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256"
    });
    await assert.rejects(
      provider.resolveAuthorization({ request, account: null, session: null }),
      (error) => {
        assert.equal(error.code, "login_required");
        return true;
      }
    );
  });

  it("rejects prompt=none combined with a prompt that needs the user", async () => {
    await assert.rejects(
      provider.parseAuthorizationRequest({
        client_id: confidential.clientId,
        redirect_uri: confidential.redirectUris[0],
        response_type: "code",
        scope: "openid",
        prompt: "none login",
        code_challenge: pkce().challenge,
        code_challenge_method: "S256"
      }),
      /prompt=none cannot be combined/
    );
  });

  it("asks for consent again when prompt=consent, even with a stored grant", async () => {
    await provider.upsertGrant({
      userId: account.id,
      clientId: confidential.clientId,
      scopes: ["openid", "profile"]
    });
    const { decision } = await authorize({ prompt: "consent", scope: "openid profile" });
    assert.equal(decision.action, "consent");
    assert.equal(decision.reason, "prompt_consent");
  });

  it("sends the user back to sign in when the session is older than max_age", async () => {
    const request = await provider.parseAuthorizationRequest({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "openid",
      max_age: "0",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256"
    });
    const stale = { ...session, authTime: new Date(Date.now() - 60_000) };
    const decision = await provider.resolveAuthorization({ request, account, session: stale });
    assert.equal(decision.action, "login");
    assert.equal(decision.reason, "max_age");
  });

  it("stops asking once the user has re-authenticated for a prompt=login request", async () => {
    // The parked request is what makes this reachable at all. `prompt=login`
    // lives in the stored row, so re-reading it after the login page returns the
    // same answer as before: the user signs in, comes back to
    // /oauth2/authorize/continue, is sent to /login again, and the login page —
    // seeing a session — redirects straight back. The browser ends that with
    // ERR_TOO_MANY_REDIRECTS, so `prompt=login` does not degrade to "ignored",
    // it fails the whole authorization. Asserting only the first decision, as a
    // test on the request in isolation does, cannot see the second hop.
    const request = await provider.parseAuthorizationRequest({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "openid",
      prompt: "login",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256"
    });
    const requestToken = await provider.persistAuthorizationRequest(request);
    const parked = await provider.loadAuthorizationRequest(requestToken);

    const first = await provider.resolveAuthorization({ request: parked, account, session });
    assert.equal(first.action, "login", "the session predates the request, so it must ask");
    assert.equal(first.reason, "prompt_login");

    // What signing in again produces: a session whose authTime is later than the
    // moment the request was parked.
    const reauthenticated = { ...session, authTime: new Date(parked.createdAt.getTime() + 1_000) };
    const second = await provider.resolveAuthorization({ request: parked, account, session: reauthenticated });
    assert.notEqual(second.action, "login", "asking a second time is the redirect loop");
  });

  it("skips consent for a client configured not to require it", async () => {
    const request = await provider.parseAuthorizationRequest({
      client_id: publicClient.clientId,
      redirect_uri: publicClient.redirectUris[0],
      response_type: "code",
      scope: "openid profile",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256"
    });
    const decision = await provider.resolveAuthorization({ request, account, session });
    assert.equal(decision.action, "issue");
  });

  // --- The authorization code flow ----------------------------------------

  it("completes an authorization code exchange with PKCE", async () => {
    const authorized = await authorize({ state: "client-state-123", nonce: "client-nonce-456" });
    assert.ok(authorized.code);
    assert.equal(authorized.state, "client-state-123");
    // RFC 9207: `iss` in the response is how a client with several issuers
    // detects a mix-up attack.
    assert.equal(authorized.iss, "http://127.0.0.1:3010");

    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: authorized.code,
        redirect_uri: authorized.redirectUri,
        code_verifier: authorized.verifier
      }
    });

    assert.equal(tokens.token_type, "Bearer");
    assert.equal(tokens.expires_in, config.ttl.accessTokenSeconds);
    assert.equal(tokens.scope, "openid profile email");
    assert.ok(tokens.access_token);
    assert.ok(tokens.id_token);
    // No offline_access was requested, so no refresh token is issued.
    assert.equal(tokens.refresh_token, undefined);

    const idToken = decodeJwt(tokens.id_token).payload;
    assert.equal(idToken.iss, "http://127.0.0.1:3010");
    assert.equal(idToken.sub, account.id);
    assert.equal(idToken.aud, confidential.clientId);
    assert.equal(idToken.azp, confidential.clientId);
    assert.equal(idToken.nonce, "client-nonce-456");
    assert.ok(Number.isInteger(idToken.auth_time));
    assert.ok(idToken.at_hash, "at_hash binds the ID token to its access token");
    assert.ok(idToken.sid, "sid is what makes back-channel logout addressable");
    // The claims the granted scopes release.
    assert.equal(idToken.name, "Ada Lovelace");
    assert.equal(idToken.preferred_username, "owner");
    assert.equal(idToken.email, "owner@example.com");

    const header = decodeJwt(tokens.id_token).header;
    assert.ok(header.kid, "a client selects the verification key by kid");
    assert.equal(header.alg, (await keys.ensureKeyRing()).activeKey.alg);
  });

  it("rolls back authorization completion when storing the code fails", async () => {
    const browser = await sessions.login({ userId: account.id });
    const challenge = pkce();
    const request = await provider.parseAuthorizationRequest({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "openid",
      state: "retry-after-code-write-failure",
      code_challenge: challenge.challenge,
      code_challenge_method: "S256"
    });
    const requestToken = await provider.persistAuthorizationRequest(request);

    let failNextCodeCreate = true;
    const transactionClient = (client) =>
      new Proxy(client, {
        get(target, prop) {
          if (prop === "authorizationCode") {
            return new Proxy(target.authorizationCode, {
              get(model, method) {
                if (method === "create") {
                  return async (...args) => {
                    if (failNextCodeCreate) {
                      failNextCodeCreate = false;
                      throw new Error("simulated authorization-code write failure");
                    }
                    return model.create(...args);
                  };
                }
                const value = model[method];
                return typeof value === "function" ? value.bind(model) : value;
              }
            });
          }
          const value = target[prop];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const failingPrisma = new Proxy(prisma, {
      get(target, prop) {
        if (prop === "$transaction") {
          return (callback, ...args) =>
            target.$transaction((tx) => callback(transactionClient(tx)), ...args);
        }
        const value = target[prop];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const failingProvider = createProviderService({
      prisma: failingPrisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    await assert.rejects(
      failingProvider.completeAuthorization({
        requestToken,
        account,
        session: browser.session
      }),
      /simulated authorization-code write failure/
    );

    const afterFailure = await prisma.authorizationRequest.findUnique({
      where: { requestTokenHash: hashToken(requestToken) }
    });
    assert.equal(afterFailure.consumedAt, null, "the failed code write consumed the request");
    assert.equal(
      await prisma.oidcSession.findUnique({
        where: {
          sessionId_clientId: {
            sessionId: browser.session.id,
            clientId: confidential.clientId
          }
        }
      }),
      null,
      "the failed code write left a partial OIDC session"
    );
    assert.equal(
      await prisma.authorizationCode.count({
        where: { sessionId: browser.session.id, clientId: confidential.clientId }
      }),
      0
    );

    const retried = await provider.completeAuthorization({
      requestToken,
      account,
      session: browser.session
    });
    const retriedCode = new URL(retried.redirectUrl).searchParams.get("code");
    assert.ok(retriedCode, "the same request was not retryable");

    const afterRetry = await prisma.authorizationRequest.findUnique({
      where: { id: afterFailure.id }
    });
    assert.ok(afterRetry.consumedAt, "the successful retry did not consume the request");
    assert.ok(
      await prisma.oidcSession.findUnique({
        where: {
          sessionId_clientId: {
            sessionId: browser.session.id,
            clientId: confidential.clientId
          }
        }
      }),
      "the successful retry did not establish its OIDC session"
    );
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: retriedCode,
        redirect_uri: confidential.redirectUris[0],
        code_verifier: challenge.verifier
      }
    });
    assert.ok(tokens.access_token, "the retried request produced an unusable authorization code");
  });

  it("does not recreate an active client session after the grant is withdrawn", async () => {
    const revocable = await clients.create(
      {
        name: "Consent Withdrawal Race",
        clientType: "confidential",
        redirectUris: ["https://consent-race.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    const browser = await sessions.login({ userId: account.id });
    const challenge = pkce();
    const request = await provider.parseAuthorizationRequest({
      client_id: revocable.client.clientId,
      redirect_uri: revocable.client.redirectUris[0],
      response_type: "code",
      scope: "openid",
      code_challenge: challenge.challenge,
      code_challenge_method: "S256"
    });
    const requestToken = await provider.persistAuthorizationRequest(request);

    let withdrawBeforeTransaction = true;
    const racingPrisma = new Proxy(prisma, {
      get(target, property) {
        if (property === "$transaction") {
          return async (callback, ...args) => {
            if (withdrawBeforeTransaction) {
              withdrawBeforeTransaction = false;
              await provider.revokeGrant({
                userId: account.id,
                clientId: revocable.client.clientId,
                reason: "concurrent_user_revocation"
              });
            }
            return target.$transaction(callback, ...args);
          };
        }
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const racingProvider = createProviderService({
      prisma: racingPrisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    await assert.rejects(
      racingProvider.completeAuthorization({
        requestToken,
        account,
        session: browser.session
      }),
      (error) => {
        assert.equal(error.code, "access_denied");
        return true;
      }
    );

    const storedRequest = await prisma.authorizationRequest.findUnique({
      where: { requestTokenHash: hashToken(requestToken) }
    });
    assert.equal(storedRequest.consumedAt, null, "a rejected completion consumed the request");
    assert.equal(
      await prisma.authorizationCode.count({
        where: { userId: account.id, clientId: revocable.client.clientId }
      }),
      0,
      "a code was issued after the grant was withdrawn"
    );
    assert.equal(
      await prisma.oidcSession.count({
        where: { userId: account.id, clientId: revocable.client.clientId, revokedAt: null }
      }),
      0,
      "grant withdrawal was undone by recreating an active OIDC session"
    );
  });

  it("does not reactivate a withdrawn stored grant without fresh consent", async () => {
    const revocable = await clients.create(
      {
        name: "Stored Grant Withdrawal",
        clientType: "confidential",
        redirectUris: ["https://stored-grant.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    await authorize({ scope: "openid" }, { client: revocable.client });

    const challenge = pkce();
    const request = await provider.parseAuthorizationRequest({
      client_id: revocable.client.clientId,
      redirect_uri: revocable.client.redirectUris[0],
      response_type: "code",
      scope: "openid",
      code_challenge: challenge.challenge,
      code_challenge_method: "S256"
    });
    const requestToken = await provider.persistAuthorizationRequest(request);
    const loaded = await provider.loadAuthorizationRequest(requestToken);
    const decision = await provider.resolveAuthorization({ request: loaded, account, session });
    assert.equal(decision.action, "issue", "the regression requires stored-grant reuse");

    await provider.revokeGrant({
      userId: account.id,
      clientId: revocable.client.clientId,
      reason: "withdrawn_after_resolution"
    });

    await assert.rejects(
      provider.completeAuthorization({ requestToken, account, session, approvedScopes: null }),
      (error) => {
        assert.equal(error.code, "access_denied");
        return true;
      }
    );
    const grant = await prisma.grant.findUnique({
      where: { userId_clientId: { userId: account.id, clientId: revocable.client.clientId } }
    });
    assert.ok(grant.revokedAt, "silent completion reactivated the withdrawn grant");
  });

  it("does not issue a code from a stale browser-session snapshot", async () => {
    const client = await clients.create(
      {
        name: "Stale Browser Session",
        clientType: "confidential",
        redirectUris: ["https://stale-session.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        isFirstParty: true,
        requireConsent: false
      },
      { status: "APPROVED" }
    );
    const browser = await sessions.create({ userId: account.id });
    const challenge = pkce();
    const request = await provider.parseAuthorizationRequest({
      client_id: client.client.clientId,
      redirect_uri: client.client.redirectUris[0],
      response_type: "code",
      scope: "openid",
      code_challenge: challenge.challenge,
      code_challenge_method: "S256"
    });
    const requestToken = await provider.persistAuthorizationRequest(request);
    await prisma.session.delete({ where: { id: browser.session.id } });

    await assert.rejects(
      provider.completeAuthorization({
        requestToken,
        account,
        session: browser.session,
        approvedScopes: null
      }),
      (error) => {
        assert.equal(error.code, "access_denied");
        return true;
      }
    );
    assert.equal(
      await prisma.authorizationCode.count({
        where: { sessionId: browser.session.id, clientId: client.client.clientId }
      }),
      0,
      "a deleted browser session still produced an authorization code"
    );
  });

  it("checks authorization-request expiry in the consume operation", async () => {
    const client = await clients.create(
      {
        name: "Authorization Request Boundary",
        clientType: "confidential",
        redirectUris: ["https://request-boundary.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        isFirstParty: true,
        requireConsent: false
      },
      { status: "APPROVED" }
    );
    const challenge = pkce();
    const request = await provider.parseAuthorizationRequest({
      client_id: client.client.clientId,
      redirect_uri: client.client.redirectUris[0],
      response_type: "code",
      scope: "openid",
      code_challenge: challenge.challenge,
      code_challenge_method: "S256"
    });
    const requestToken = await provider.persistAuthorizationRequest(request);
    const boundary = new Date(Date.now() + 60_000);
    await prisma.authorizationRequest.update({
      where: { requestTokenHash: hashToken(requestToken) },
      data: { expiresAt: boundary }
    });

    let clockReads = 0;
    const boundaryProvider = createProviderService({
      prisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } }),
      now: () => {
        clockReads += 1;
        return clockReads === 1
          ? new Date(boundary.getTime() - 1)
          : new Date(boundary.getTime() + 1);
      }
    });

    await assert.rejects(
      boundaryProvider.completeAuthorization({ requestToken, account, session, approvedScopes: null }),
      (error) => {
        assert.equal(error.code, "invalid_request");
        return true;
      }
    );
    const stored = await prisma.authorizationRequest.findUnique({
      where: { requestTokenHash: hashToken(requestToken) }
    });
    assert.equal(stored.consumedAt, null, "an expired request was consumed after its pre-check");
  });

  it("checks authorization-request expiry when recording a denial", async () => {
    const challenge = pkce();
    const request = await provider.parseAuthorizationRequest({
      client_id: confidential.clientId,
      redirect_uri: confidential.redirectUris[0],
      response_type: "code",
      scope: "openid",
      code_challenge: challenge.challenge,
      code_challenge_method: "S256"
    });
    const requestToken = await provider.persistAuthorizationRequest(request);
    const boundary = new Date(Date.now() + 60_000);
    await prisma.authorizationRequest.update({
      where: { requestTokenHash: hashToken(requestToken) },
      data: { expiresAt: boundary }
    });

    let clockReads = 0;
    const boundaryProvider = createProviderService({
      prisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } }),
      now: () => {
        clockReads += 1;
        return clockReads === 1
          ? new Date(boundary.getTime() - 1)
          : new Date(boundary.getTime() + 1);
      }
    });

    await assert.rejects(
      boundaryProvider.denyAuthorization({ requestToken }),
      (error) => {
        assert.equal(error.code, "invalid_request");
        return true;
      }
    );
    const stored = await prisma.authorizationRequest.findUnique({
      where: { requestTokenHash: hashToken(requestToken) }
    });
    assert.equal(stored.consumedAt, null, "an expired denial consumed the request");
  });

  it("rechecks admin-only scope eligibility immediately before issuing a code", async () => {
    const adminClient = await clients.create(
      {
        name: "Authorization Eligibility Boundary",
        clientType: "confidential",
        redirectUris: ["https://authorization-eligibility.example/callback"],
        scopes: ["openid", "credits.admin"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    await authorize({ scope: "openid credits.admin" }, { client: adminClient.client });

    const challenge = pkce();
    const request = await provider.parseAuthorizationRequest({
      client_id: adminClient.client.clientId,
      redirect_uri: adminClient.client.redirectUris[0],
      response_type: "code",
      scope: "openid credits.admin",
      code_challenge: challenge.challenge,
      code_challenge_method: "S256"
    });
    const requestToken = await provider.persistAuthorizationRequest(request);
    const loaded = await provider.loadAuthorizationRequest(requestToken);
    assert.equal(
      (await provider.resolveAuthorization({ request: loaded, account, session })).action,
      "issue"
    );

    await prisma.user.update({ where: { id: account.id }, data: { role: "USER" } });
    try {
      await assert.rejects(
        provider.completeAuthorization({ requestToken, account, session, approvedScopes: null }),
        (error) => {
          assert.equal(error.code, "invalid_scope");
          return true;
        }
      );
    } finally {
      await prisma.user.update({ where: { id: account.id }, data: { role: "ADMIN" } });
    }
  });

  it("does not issue a code to a callback removed after authorization resolution", async () => {
    const client = await clients.create(
      {
        name: "Authorization Callback Removal",
        clientType: "confidential",
        redirectUris: ["https://authorization-callback.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    await authorize({ scope: "openid" }, { client: client.client });

    const challenge = pkce();
    const request = await provider.parseAuthorizationRequest({
      client_id: client.client.clientId,
      redirect_uri: client.client.redirectUris[0],
      response_type: "code",
      scope: "openid",
      code_challenge: challenge.challenge,
      code_challenge_method: "S256"
    });
    const requestToken = await provider.persistAuthorizationRequest(request);
    const loaded = await provider.loadAuthorizationRequest(requestToken);
    assert.equal(
      (await provider.resolveAuthorization({ request: loaded, account, session })).action,
      "issue"
    );
    await prisma.oAuthClient.update({
      where: { clientId: client.client.clientId },
      data: { redirectUris: "https://authorization-callback.example/replacement" }
    });

    await assert.rejects(
      provider.completeAuthorization({ requestToken, account, session, approvedScopes: null }),
      (error) => {
        assert.equal(error.code, "access_denied");
        return true;
      }
    );
  });

  it("accepts client_secret_post as well as client_secret_basic", async () => {
    // Registered for basic, so post must be refused — but the parse path is what
    // is under test, and a client registered for post must be able to use it.
    const authorized = await authorize();
    await assert.rejects(
      provider.token({
        headers: {},
        body: {
          grant_type: "authorization_code",
          code: authorized.code,
          redirect_uri: authorized.redirectUri,
          code_verifier: authorized.verifier,
          client_id: confidential.clientId,
          client_secret: confidentialSecret
        }
      }),
      /must authenticate with client_secret_basic/
    );

    const posting = await clients.create(
      {
        name: "Post Auth Client",
        clientType: "confidential",
        redirectUris: ["https://post.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_post",
        requireConsent: false
      },
      { status: "APPROVED" }
    );
    const flow = await authorize({ scope: "openid" }, { client: posting.client });
    const tokens = await provider.token({
      headers: {},
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier,
        client_id: posting.client.clientId,
        client_secret: posting.clientSecret
      }
    });
    assert.ok(tokens.access_token);
  });

  it("lets a public client redeem a code with PKCE and no secret", async () => {
    const flow = await authorize({ scope: "openid profile" }, { client: publicClient });
    const tokens = await provider.token({
      headers: {},
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier,
        client_id: publicClient.clientId
      }
    });
    assert.ok(tokens.access_token);
    assert.ok(tokens.id_token);
  });

  it("rejects a client secret presented in both the header and the body", async () => {
    const flow = await authorize();
    await assert.rejects(
      provider.token({
        headers: basicAuth(confidential.clientId, confidentialSecret),
        body: {
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: flow.redirectUri,
          code_verifier: flow.verifier,
          client_id: confidential.clientId,
          client_secret: confidentialSecret
        }
      }),
      /once, not in both/
    );
  });

  it("makes an authorization code single-use and revokes what came of a replay", async () => {
    const flow = await authorize({ scope: "openid offline_access" });
    const body = {
      grant_type: "authorization_code",
      code: flow.code,
      redirect_uri: flow.redirectUri,
      code_verifier: flow.verifier
    };
    const headers = basicAuth(confidential.clientId, confidentialSecret);

    const first = await provider.token({ headers, body });
    assert.ok(first.refresh_token, "offline_access was granted, so a refresh token is issued");

    await assert.rejects(provider.token({ headers, body }), (error) => {
      assert.equal(error.code, "invalid_grant");
      return true;
    });

    // The replay means the code leaked, so the refresh token from the first
    // redemption must no longer work either.
    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: first.refresh_token }
      }),
      /revoked|not valid|session has been ended/
    );
  });

  it("revokes and audits a replay that arrives as a race rather than as a repeat", async () => {
    // Two places discover a spent code, and only one of them used to act on it.
    //
    // The test above hits the pre-read: by the time the second request looked,
    // the row already carried `usedAt`. An attacker holding a stolen code does
    // not wait — they race the real client, so both requests read `usedAt: null`
    // and the conditional update picks a winner. The loser used to get a bare
    // invalid_grant with nothing revoked and nothing audited, which meant the
    // detection was missing from exactly the case it exists for.
    //
    // The race is made deterministic by spending the code between this
    // request's read and its update, which is what the other request would do.
    const raced = (client) => {
      const codes = new Proxy(client.authorizationCode, {
        get(target, prop) {
          if (prop !== "findUnique") {
            const value = target[prop];
            return typeof value === "function" ? value.bind(target) : value;
          }
          return async (args) => {
            const row = await target.findUnique(args);
            if (row && !row.usedAt) {
              await target.updateMany({ where: { id: row.id, usedAt: null }, data: { usedAt: new Date() } });
            }
            // The snapshot this request read, before the other one landed.
            return row;
          };
        }
      });
      return new Proxy(client, {
        get(target, prop) {
          if (prop === "authorizationCode") return codes;
          const value = target[prop];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    };

    const headers = basicAuth(confidential.clientId, confidentialSecret);

    // A live token for this session and client, which is what the revocation
    // has to reach.
    const first = await authorize({ scope: "openid offline_access" });
    const issued = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: first.code,
        redirect_uri: first.redirectUri,
        code_verifier: first.verifier
      }
    });
    assert.ok(issued.refresh_token);

    const racingProvider = createProviderService({
      prisma: raced(prisma),
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {}, warn() {}, info() {} } })
    });

    const before = await prisma.auditLog.count({ where: { action: "oauth.code.replayed" } });

    const second = await authorize({ scope: "openid" });
    await assert.rejects(
      racingProvider.token({
        headers,
        body: {
          grant_type: "authorization_code",
          code: second.code,
          redirect_uri: second.redirectUri,
          code_verifier: second.verifier
        }
      }),
      (error) => {
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );

    assert.equal(
      await prisma.auditLog.count({ where: { action: "oauth.code.replayed" } }),
      before + 1,
      "losing the race for a code is a replay, and an operator has to be able to see it"
    );

    // The point of the revocation: whatever the first redemption produced is
    // no longer usable, because a code being redeemed twice means it leaked.
    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: issued.refresh_token }
      }),
      /revoked|not valid|session has been ended/
    );
  });

  it("rejects a code redeemed by a different client", async () => {
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize({ scope: "openid" }, { browserSession: browser.session });
    const other = await clients.create(
      {
        name: "Other Client",
        clientType: "confidential",
        redirectUris: ["https://other.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic"
      },
      { status: "APPROVED" }
    );
    await assert.rejects(
      provider.token({
        headers: basicAuth(other.client.clientId, other.clientSecret),
        body: {
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: flow.redirectUri,
          code_verifier: flow.verifier
        }
      }),
      (error) => {
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );
  });

  it("rejects a mismatched redirect_uri at the token endpoint", async () => {
    const flow = await authorize();
    await assert.rejects(
      provider.token({
        headers: basicAuth(confidential.clientId, confidentialSecret),
        body: {
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: "https://rp.example/other",
          code_verifier: flow.verifier
        }
      }),
      /redirect_uri does not match/
    );
  });

  it("rejects a wrong code_verifier", async () => {
    const flow = await authorize();
    await assert.rejects(
      provider.token({
        headers: basicAuth(confidential.clientId, confidentialSecret),
        body: {
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: flow.redirectUri,
          code_verifier: crypto.randomBytes(32).toString("base64url")
        }
      }),
      /code_verifier does not match/
    );
  });

  it("refuses to let a missing code_verifier bypass PKCE", async () => {
    // The downgrade attack: present no verifier and hope the check is skipped.
    const flow = await authorize();
    await assert.rejects(
      provider.token({
        headers: basicAuth(confidential.clientId, confidentialSecret),
        body: {
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: flow.redirectUri
        }
      }),
      /code_verifier is required/
    );
  });

  it("rechecks current client scopes before exchanging an authorization code", async () => {
    const scopedClient = await clients.create(
      {
        name: "Code Scope Downgrade",
        clientType: "confidential",
        redirectUris: ["https://code-scope-downgrade.example/callback"],
        scopes: ["openid", "credits.read"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    const flow = await authorize(
      { scope: "openid credits.read" },
      { client: scopedClient.client }
    );
    await prisma.oAuthClient.update({
      where: { clientId: scopedClient.client.clientId },
      data: { allowedScopes: "openid" }
    });

    await assert.rejects(
      provider.token({
        headers: basicAuth(scopedClient.client.clientId, scopedClient.clientSecret),
        body: {
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: flow.redirectUri,
          code_verifier: flow.verifier
        }
      }),
      (error) => {
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );
    const code = await prisma.authorizationCode.findUnique({
      where: { codeHash: hashToken(flow.code) }
    });
    assert.equal(code.usedAt, null, "client-scope downgrade burned a code before rejecting it");
  });

  it("does not exchange a code after its callback registration is removed", async () => {
    const callbackClient = await clients.create(
      {
        name: "Code Callback Removal",
        clientType: "confidential",
        redirectUris: ["https://code-callback.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    const flow = await authorize({ scope: "openid" }, { client: callbackClient.client });
    await prisma.oAuthClient.update({
      where: { clientId: callbackClient.client.clientId },
      data: { redirectUris: "https://code-callback.example/replacement" }
    });

    await assert.rejects(
      provider.token({
        headers: basicAuth(callbackClient.client.clientId, callbackClient.clientSecret),
        body: {
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: flow.redirectUri,
          code_verifier: flow.verifier
        }
      }),
      (error) => {
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );
  });

  it("rechecks admin-only scope eligibility before exchanging an authorization code", async () => {
    const user = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email: `code-admin-${crypto.randomUUID()}@example.test`,
        role: "ADMIN",
        status: "ACTIVE"
      }
    });
    const authorizationAccount = accounts.toAccount(user);
    const browserSession = (await sessions.create({ userId: user.id })).session;
    const adminClient = await clients.create(
      {
        name: "Code Admin Downgrade",
        clientType: "confidential",
        redirectUris: ["https://code-admin-downgrade.example/callback"],
        scopes: ["openid", "credits.admin"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    const flow = await authorize(
      { scope: "openid credits.admin" },
      { client: adminClient.client, authorizationAccount, browserSession }
    );
    await prisma.user.update({ where: { id: user.id }, data: { role: "USER" } });

    await assert.rejects(
      provider.token({
        headers: basicAuth(adminClient.client.clientId, adminClient.clientSecret),
        body: {
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: flow.redirectUri,
          code_verifier: flow.verifier
        }
      }),
      (error) => {
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );
  });

  // --- Refresh tokens -----------------------------------------------------

  it("rotates a refresh token and revokes the family on a replay", async () => {
    const flow = await authorize({ scope: "openid profile offline_access" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const first = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    assert.ok(first.refresh_token);

    const second = await provider.token({
      headers,
      body: { grant_type: "refresh_token", refresh_token: first.refresh_token }
    });
    assert.ok(second.refresh_token);
    assert.notEqual(second.refresh_token, first.refresh_token, "the token must rotate");
    // OIDC Core section 12.2: an ID token from a refresh carries no nonce.
    assert.equal(decodeJwt(second.id_token).payload.nonce, undefined);

    // Replaying the retired token means it leaked; the whole family goes.
    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: first.refresh_token }
      }),
      /revoked/
    );
    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: second.refresh_token }
      }),
      /revoked/
    );
  });

  it("rolls back a refresh rotation when issuing the replacement fails", async () => {
    const flow = await authorize({ scope: "openid offline_access" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const first = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    let failNextCreate = true;
    const failingRefreshModel = (model) =>
      new Proxy(model, {
        get(target, prop) {
          if (prop === "create") {
            return async (...args) => {
              if (failNextCreate) {
                failNextCreate = false;
                throw new Error("simulated replacement-token write failure");
              }
              return target.create(...args);
            };
          }
          const value = target[prop];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const transactionClient = (client) =>
      new Proxy(client, {
        get(target, prop) {
          if (prop === "refreshToken") return failingRefreshModel(target.refreshToken);
          const value = target[prop];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const failingPrisma = new Proxy(prisma, {
      get(target, prop) {
        if (prop === "refreshToken") return failingRefreshModel(target.refreshToken);
        if (prop === "$transaction") {
          return (callback, ...args) =>
            target.$transaction((tx) => callback(transactionClient(tx)), ...args);
        }
        const value = target[prop];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const failingProvider = createProviderService({
      prisma: failingPrisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    await assert.rejects(
      failingProvider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: first.refresh_token }
      }),
      /simulated replacement-token write failure/
    );

    const retried = await provider.token({
      headers,
      body: { grant_type: "refresh_token", refresh_token: first.refresh_token }
    });
    assert.ok(retried.refresh_token, "the original token must remain usable after a rolled-back write");
  });

  it("reuses one refresh token without partial writes when rotation is disabled", async () => {
    const nonRotatingConfig = {
      ...config,
      security: { ...config.security, rotateRefreshTokens: false }
    };
    const nonRotatingProvider = createProviderService({
      prisma,
      config: nonRotatingConfig,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });
    const flow = await authorize({ scope: "openid offline_access" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const initial = await nonRotatingProvider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const original = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashToken(initial.refresh_token) }
    });
    assert.ok(original);

    let failNextSessionTouch = true;
    const failingOidcSessionModel = (model) =>
      new Proxy(model, {
        get(target, method) {
          if (method === "updateMany") {
            return async (...args) => {
              if (failNextSessionTouch) {
                failNextSessionTouch = false;
                throw new Error("simulated session-touch failure");
              }
              return target.updateMany(...args);
            };
          }
          const value = target[method];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const transactionClient = (client) =>
      new Proxy(client, {
        get(target, property) {
          if (property === "oidcSession") return failingOidcSessionModel(target.oidcSession);
          const value = target[property];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const failingPrisma = new Proxy(prisma, {
      get(target, prop) {
        if (prop === "oidcSession") return failingOidcSessionModel(target.oidcSession);
        if (prop === "$transaction") {
          return (callback, ...args) =>
            target.$transaction((tx) => callback(transactionClient(tx)), ...args);
        }
        const value = target[prop];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const partiallyFailingProvider = createProviderService({
      prisma: failingPrisma,
      config: nonRotatingConfig,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    await assert.rejects(
      partiallyFailingProvider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: initial.refresh_token }
      }),
      /simulated session-touch failure/
    );
    assert.equal(
      await prisma.refreshToken.count({ where: { parentTokenId: original.id } }),
      0,
      "a failed non-rotating exchange left a partial refresh-token write"
    );

    const replayAuditBefore = await prisma.auditLog.count({ where: { action: "oauth.refresh.replayed" } });
    const firstRetry = await nonRotatingProvider.token({
      headers,
      body: { grant_type: "refresh_token", refresh_token: initial.refresh_token }
    });
    const secondRetry = await nonRotatingProvider.token({
      headers,
      body: { grant_type: "refresh_token", refresh_token: initial.refresh_token }
    });
    assert.equal(firstRetry.refresh_token, undefined);
    assert.equal(secondRetry.refresh_token, undefined);
    assert.equal(
      await prisma.refreshToken.count({ where: { parentTokenId: original.id } }),
      0,
      "non-rotating reuse created unnecessary sibling tokens"
    );
    const reusable = await prisma.refreshToken.findUnique({ where: { id: original.id } });
    assert.equal(reusable.usedAt, null);
    assert.equal(reusable.revokedAt, null);
    assert.equal(
      await prisma.auditLog.count({ where: { action: "oauth.refresh.replayed" } }),
      replayAuditBefore,
      "non-rotating mode cannot classify reuse as replay"
    );
  });

  it("does not issue from a non-rotating refresh token revoked after the initial read", async () => {
    const nonRotatingConfig = {
      ...config,
      security: { ...config.security, rotateRefreshTokens: false }
    };
    const nonRotatingProvider = createProviderService({
      prisma,
      config: nonRotatingConfig,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });
    const flow = await authorize({ scope: "openid offline_access" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const initial = await nonRotatingProvider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    let revokeAfterRead = true;
    const revokingRefreshModel = new Proxy(prisma.refreshToken, {
      get(target, property) {
        if (property === "findUnique") {
          return async (args) => {
            const row = await target.findUnique(args);
            if (row && revokeAfterRead) {
              revokeAfterRead = false;
              await target.updateMany({
                where: { familyId: row.familyId, revokedAt: null },
                data: { revokedAt: new Date() }
              });
            }
            return row;
          };
        }
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const revokingPrisma = new Proxy(prisma, {
      get(target, property) {
        if (property === "refreshToken") return revokingRefreshModel;
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const racingProvider = createProviderService({
      prisma: revokingPrisma,
      config: nonRotatingConfig,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });
    const issuedBefore = await prisma.auditLog.count({ where: { action: "oauth.token.issued" } });

    await assert.rejects(
      racingProvider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: initial.refresh_token }
      }),
      (error) => {
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );
    assert.equal(revokeAfterRead, false, "the revocation race was not exercised");
    assert.equal(
      await prisma.auditLog.count({ where: { action: "oauth.token.issued" } }),
      issuedBefore,
      "a revoked non-rotating refresh token was recorded as a successful issuance"
    );
  });

  it("refuses a refresh scope that exceeds the original grant", async () => {
    const flow = await authorize({ scope: "openid offline_access" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    await assert.rejects(
      provider.token({
        headers,
        body: {
          grant_type: "refresh_token",
          refresh_token: tokens.refresh_token,
          scope: "openid email offline_access"
        }
      }),
      (error) => {
        assert.equal(error.code, "invalid_scope");
        return true;
      }
    );
  });

  it("allows a refresh to narrow its scope", async () => {
    const flow = await authorize({ scope: "openid profile email offline_access" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const narrowed = await provider.token({
      headers,
      body: {
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        scope: "openid offline_access"
      }
    });
    assert.equal(narrowed.scope, "openid offline_access");
  });

  it("drops live admin authority after downgrade without reviving it through refresh rotation", async () => {
    const user = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email: `refresh-admin-${crypto.randomUUID()}@example.test`,
        role: "ADMIN",
        status: "ACTIVE"
      }
    });
    const authorizationAccount = accounts.toAccount(user);
    const browserSession = (await sessions.create({ userId: user.id })).session;
    const adminClient = await clients.create(
      {
        name: "Refresh Admin Downgrade",
        clientType: "confidential",
        redirectUris: ["https://refresh-admin-downgrade.example/callback"],
        scopes: ["openid", "offline_access", "credits.admin"],
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    const flow = await authorize(
      { scope: "openid offline_access credits.admin" },
      { client: adminClient.client, authorizationAccount, browserSession }
    );
    const headers = basicAuth(adminClient.client.clientId, adminClient.clientSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    const beforeDowngrade = await provider.introspect({
      headers,
      body: { token: tokens.access_token }
    });
    assert.equal(beforeDowngrade.active, true);
    assert.equal(beforeDowngrade.credits_admin, true);
    assert.equal(beforeDowngrade.iss, config.issuer);
    assert.equal(beforeDowngrade.sub, user.id);
    assert.equal(beforeDowngrade.aud, config.issuer);
    assert.equal(beforeDowngrade.client_id, adminClient.client.clientId);
    assert.equal(beforeDowngrade.token_use, "access");
    assert.equal(beforeDowngrade.scope, "openid offline_access credits.admin");
    assert.ok(beforeDowngrade.sid);
    assert.ok(beforeDowngrade.jti);
    assert.ok(Number.isInteger(beforeDowngrade.iat));
    assert.ok(Number.isInteger(beforeDowngrade.exp));

    const rotated = await provider.token({
      headers,
      body: { grant_type: "refresh_token", refresh_token: tokens.refresh_token }
    });
    const rotatedBeforeDowngrade = await provider.introspect({
      headers,
      body: { token: rotated.access_token }
    });
    assert.equal(rotatedBeforeDowngrade.active, true);
    assert.equal(rotatedBeforeDowngrade.credits_admin, true);

    await prisma.user.update({ where: { id: user.id }, data: { role: "USER" } });

    const originalAccess = await provider.introspect({ headers, body: { token: tokens.access_token } });
    const rotatedAccess = await provider.introspect({ headers, body: { token: rotated.access_token } });
    const refresh = await provider.introspect({
      headers,
      body: { token: rotated.refresh_token, token_type_hint: "refresh_token" }
    });
    assert.equal(originalAccess.active, true);
    assert.equal(originalAccess.credits_admin, false);
    assert.equal(rotatedAccess.active, true);
    assert.equal(rotatedAccess.credits_admin, false);
    assert.equal(refresh.active, false);
    await assert.rejects(
      provider.userinfo({ accessToken: rotated.access_token }),
      (error) => {
        assert.equal(error.code, "invalid_token");
        return true;
      }
    );
    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: rotated.refresh_token }
      }),
      (error) => {
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );
    const afterRejectedRefresh = await provider.introspect({
      headers,
      body: { token: rotated.access_token }
    });
    assert.equal(afterRejectedRefresh.active, true);
    assert.equal(afterRejectedRefresh.credits_admin, false);
  });

  it("keeps a restricted scope fail-closed when no live introspection claim represents it", async () => {
    const user = await prisma.user.create({
      data: {
        id: crypto.randomUUID(),
        email: `legacy-admin-${crypto.randomUUID()}@example.test`,
        role: "ADMIN",
        status: "ACTIVE"
      }
    });
    const authorizationAccount = accounts.toAccount(user);
    const browserSession = (await sessions.create({ userId: user.id })).session;
    const legacyClient = await clients.create(
      {
        name: "Legacy Restricted Scope",
        clientType: "confidential",
        redirectUris: ["https://legacy-admin.example/callback"],
        scopes: ["openid", "legacy.admin"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    const flow = await authorize(
      { scope: "openid legacy.admin" },
      { client: legacyClient.client, authorizationAccount, browserSession }
    );
    const headers = basicAuth(legacyClient.client.clientId, legacyClient.clientSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    assert.equal(
      (await provider.introspect({ headers, body: { token: tokens.access_token } })).active,
      true
    );

    await prisma.user.update({ where: { id: user.id }, data: { role: "USER" } });
    assert.deepEqual(
      await provider.introspect({ headers, body: { token: tokens.access_token } }),
      { active: false }
    );
  });

  it("fails refresh, UserInfo, and introspection closed after client scope removal", async () => {
    const scopedClient = await clients.create(
      {
        name: "Refresh Client Scope Removal",
        clientType: "confidential",
        redirectUris: ["https://refresh-client-scope.example/callback"],
        scopes: ["openid", "offline_access", "credits.read"],
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    const flow = await authorize(
      { scope: "openid offline_access credits.read" },
      { client: scopedClient.client }
    );
    const headers = basicAuth(scopedClient.client.clientId, scopedClient.clientSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    await prisma.oAuthClient.update({
      where: { clientId: scopedClient.client.clientId },
      data: { allowedScopes: "openid offline_access" }
    });

    const access = await provider.introspect({ headers, body: { token: tokens.access_token } });
    const refresh = await provider.introspect({
      headers,
      body: { token: tokens.refresh_token, token_type_hint: "refresh_token" }
    });
    assert.equal(access.active, false);
    assert.equal(refresh.active, false);
    await assert.rejects(
      provider.userinfo({ accessToken: tokens.access_token }),
      (error) => {
        assert.equal(error.code, "invalid_token");
        return true;
      }
    );
    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: tokens.refresh_token }
      }),
      (error) => {
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );
  });

  it("stops a refresh token working once the user revokes the grant", async () => {
    const revocable = await clients.create(
      {
        name: "Revocable Client",
        clientType: "confidential",
        redirectUris: ["https://revoke.example/callback"],
        scopes: ["openid", "offline_access"],
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: false
      },
      { status: "APPROVED" }
    );
    const flow = await authorize({ scope: "openid offline_access" }, { client: revocable.client });
    const headers = basicAuth(revocable.client.clientId, revocable.clientSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    const { revoked } = await provider.revokeGrant({
      userId: account.id,
      clientId: revocable.client.clientId
    });
    assert.equal(revoked, true);

    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: tokens.refresh_token }
      }),
      /revoked/
    );
  });

  it("rolls back every credential when grant withdrawal fails", async () => {
    const revocable = await clients.create(
      {
        name: "Transactional Revocation Client",
        clientType: "confidential",
        redirectUris: ["https://transactional-revoke.example/callback"],
        scopes: ["openid", "offline_access"],
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: false
      },
      { status: "APPROVED" }
    );
    const headers = basicAuth(revocable.client.clientId, revocable.clientSecret);
    const issuedFlow = await authorize({ scope: "openid offline_access" }, { client: revocable.client });
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: issuedFlow.code,
        redirect_uri: issuedFlow.redirectUri,
        code_verifier: issuedFlow.verifier
      }
    });
    const pendingFlow = await authorize({ scope: "openid offline_access" }, { client: revocable.client });

    let failed = false;
    const transactionClient = (client) =>
      new Proxy(client, {
        get(target, property) {
          if (property === "oidcSession") {
            return new Proxy(target.oidcSession, {
              get(model, method) {
                if (method === "updateMany") {
                  return async (...args) => {
                    if (!failed) {
                      failed = true;
                      throw new Error("simulated grant-revocation failure");
                    }
                    return model.updateMany(...args);
                  };
                }
                const value = model[method];
                return typeof value === "function" ? value.bind(model) : value;
              }
            });
          }
          const value = target[property];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const failingPrisma = new Proxy(prisma, {
      get(target, property) {
        if (property === "$transaction") {
          return (callback, ...args) => target.$transaction((tx) => callback(transactionClient(tx)), ...args);
        }
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const failingProvider = createProviderService({
      prisma: failingPrisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    await assert.rejects(
      failingProvider.revokeGrant({ userId: account.id, clientId: revocable.client.clientId }),
      /simulated grant-revocation failure/
    );
    assert.equal(failed, true);

    const grant = await prisma.grant.findUnique({
      where: { userId_clientId: { userId: account.id, clientId: revocable.client.clientId } }
    });
    const refresh = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashToken(tokens.refresh_token) }
    });
    const code = await prisma.authorizationCode.findUnique({
      where: { codeHash: hashToken(pendingFlow.code) }
    });
    const oidcSession = await prisma.oidcSession.findUnique({
      where: { sessionId_clientId: { sessionId: session.id, clientId: revocable.client.clientId } }
    });
    assert.equal(grant.revokedAt, null, "the grant was partially revoked");
    assert.equal(refresh.revokedAt, null, "the refresh token was partially revoked");
    assert.equal(code.usedAt, null, "the authorization code was partially consumed");
    assert.equal(oidcSession.revokedAt, null, "the OIDC session was partially revoked");

    assert.equal(
      (await provider.revokeGrant({ userId: account.id, clientId: revocable.client.clientId })).revoked,
      true,
      "the rolled-back withdrawal could not be retried"
    );
  });

  it("rolls back grant withdrawal when its back-channel outbox write fails", async () => {
    const revocable = await clients.create(
      {
        name: "Transactional Logout Outbox Client",
        clientType: "confidential",
        redirectUris: ["https://transactional-outbox.example/callback"],
        backchannelLogoutUri: "https://transactional-outbox.example/logout",
        scopes: ["openid", "offline_access"],
        grantTypes: ["authorization_code", "refresh_token"],
        tokenEndpointAuthMethod: "client_secret_basic",
        requireConsent: false
      },
      { status: "APPROVED" }
    );
    const browser = await sessions.create({ userId: account.id });
    const headers = basicAuth(revocable.client.clientId, revocable.clientSecret);
    const issuedFlow = await authorize(
      { scope: "openid offline_access" },
      { client: revocable.client, browserSession: browser.session }
    );
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: issuedFlow.code,
        redirect_uri: issuedFlow.redirectUri,
        code_verifier: issuedFlow.verifier
      }
    });
    const pendingFlow = await authorize(
      { scope: "openid offline_access" },
      { client: revocable.client, browserSession: browser.session }
    );
    const oidcSession = await prisma.oidcSession.findUnique({
      where: {
        sessionId_clientId: {
          sessionId: browser.session.id,
          clientId: revocable.client.clientId
        }
      }
    });

    let failOutboxWrite = true;
    const transactionClient = (client) =>
      new Proxy(client, {
        get(target, property) {
          if (property === "backchannelLogout") {
            return new Proxy(target.backchannelLogout, {
              get(model, method) {
                if (method === "create") {
                  return async (...args) => {
                    if (failOutboxWrite) {
                      failOutboxWrite = false;
                      throw new Error("simulated grant outbox failure");
                    }
                    return model.create(...args);
                  };
                }
                const value = model[method];
                return typeof value === "function" ? value.bind(model) : value;
              }
            });
          }
          const value = target[property];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const failingPrisma = new Proxy(prisma, {
      get(target, property) {
        if (property === "$transaction") {
          return (callback, ...args) =>
            target.$transaction((tx) => callback(transactionClient(tx)), ...args);
        }
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const failingBackchannel = createBackchannelService({ prisma, config, clients, keys });
    const failingProvider = createProviderService({
      prisma: failingPrisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } }),
      backchannel: failingBackchannel
    });

    await assert.rejects(
      failingProvider.revokeGrant({ userId: account.id, clientId: revocable.client.clientId }),
      /simulated grant outbox failure/
    );
    assert.equal(failOutboxWrite, false, "the outbox failure was not exercised");

    const grant = await prisma.grant.findUnique({
      where: { userId_clientId: { userId: account.id, clientId: revocable.client.clientId } }
    });
    const refresh = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashToken(tokens.refresh_token) }
    });
    const pendingCode = await prisma.authorizationCode.findUnique({
      where: { codeHash: hashToken(pendingFlow.code) }
    });
    assert.equal(grant.revokedAt, null, "the grant committed without its outbox intent");
    assert.equal(refresh.revokedAt, null, "refresh revocation committed without its outbox intent");
    assert.equal(pendingCode.usedAt, null, "code containment committed without its outbox intent");
    assert.equal(
      (await prisma.oidcSession.findUnique({ where: { id: oidcSession.id } })).revokedAt,
      null,
      "OIDC revocation committed without its outbox intent"
    );
    assert.equal(
      await prisma.backchannelLogout.count({ where: { sessionId: oidcSession.id } }),
      0,
      "the failed transaction left a partial outbox row"
    );

    assert.equal(
      (await provider.revokeGrant({ userId: account.id, clientId: revocable.client.clientId })).revoked,
      true
    );
    assert.equal(
      await prisma.backchannelLogout.count({ where: { sessionId: oidcSession.id } }),
      1,
      "the successful retry did not commit its logout intent"
    );
  });

  it("rejects an unsupported grant type", async () => {
    await assert.rejects(
      provider.token({
        headers: basicAuth(confidential.clientId, confidentialSecret),
        body: { grant_type: "password", username: "owner", password: "x" }
      }),
      (error) => {
        assert.equal(error.code, "unsupported_grant_type");
        return true;
      }
    );
  });

  // --- UserInfo -----------------------------------------------------------

  it("returns sub from UserInfo, as OIDC Core section 5.3.2 requires", async () => {
    const flow = await authorize({ scope: "openid profile email" });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    const claims = await provider.userinfo({ accessToken: tokens.access_token });
    // The single most important assertion in this file: a client library is told
    // to compare this against the ID token's `sub` and to reject a mismatch.
    assert.equal(claims.sub, account.id);
    assert.equal(claims.sub, decodeJwt(tokens.id_token).payload.sub);
    assert.equal(claims.email, "owner@example.com");
    assert.equal(claims.email_verified, false);
    assert.equal(claims.name, "Ada Lovelace");
    assert.equal(claims.preferred_username, "owner");
  });

  it("returns a handoff username without using it as the local account key", async () => {
    const registered = await accounts.register({
      email: "external-profile@example.com",
      password: "external-profile-password"
    });
    const externalAccount = await accounts.setAttributes({
      userId: registered.account.id,
      attributes: { external_preferred_username: "knight-member" }
    });
    const externalSession = (await sessions.login({ userId: externalAccount.id })).session;
    const flow = await authorize(
      { scope: "openid profile" },
      { authorizationAccount: externalAccount, browserSession: externalSession }
    );
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    const claims = await provider.userinfo({ accessToken: tokens.access_token });
    assert.equal(claims.preferred_username, "knight-member");
    assert.equal((await provider.introspect({ headers, body: { token: tokens.access_token } })).username, "knight-member");
    assert.equal(externalAccount.username, null, "the upstream display username became a local binding key");
  });

  it("releases only the claims the granted scopes cover", async () => {
    const flow = await authorize({ scope: "openid" });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const claims = await provider.userinfo({ accessToken: tokens.access_token });
    assert.equal(claims.sub, account.id);
    assert.equal(claims.email, undefined, "email was not granted");
    assert.equal(claims.name, undefined, "profile was not granted");
  });

  it("releases a deployment's custom claim through its configured scope", async () => {
    const flow = await authorize({ scope: "openid credits.read" });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const claims = await provider.userinfo({ accessToken: tokens.access_token });
    // The core knows nothing about `knight_uid`; configuration alone put it here.
    assert.equal(claims.knight_uid, 4242);
    assert.ok(tokens.scope.includes("credits.read"));
  });

  it("refuses an ID token presented as an access token", async () => {
    const flow = await authorize({ scope: "openid" });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    await assert.rejects(provider.userinfo({ accessToken: tokens.id_token }), (error) => {
      assert.equal(error.code, "invalid_token");
      return true;
    });
  });

  it("stops answering UserInfo once the session behind the token has been ended", async () => {
    // An access token is a self-contained JWT, so a resource server checking it
    // offline cannot know it was revoked. That is a real trade-off and the
    // README makes it. This endpoint is not covered by it: it belongs to the
    // issuer, it is already reading the database for the account, and `sid` is
    // in the claims it just verified.
    //
    // Without the check, a user who ends a device from /account is shown that
    // it is signed out while the token taken from it keeps returning their
    // email and name for the rest of its lifetime — and the same token handed
    // to introspection came back inactive, so the issuer disagreed with itself
    // about one token.
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize(
      { scope: "openid profile email" },
      { browserSession: browser.session }
    );
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    const before = await provider.userinfo({ accessToken: tokens.access_token });
    assert.equal(before.email, "owner@example.com", "the token has to work before it is revoked");

    const ended = await provider.endSessions({
      sessionId: browser.session.id,
      userId: account.id,
      reason: "user_revoked"
    });
    assert.equal(ended.revoked, true);

    const introspected = await provider.introspect({
      headers,
      body: { token: tokens.access_token }
    });
    assert.equal(introspected.active, false, "introspection already reported this");

    await assert.rejects(provider.userinfo({ accessToken: tokens.access_token }), (error) => {
      assert.equal(error.code, "invalid_token");
      return true;
    });
  });

  it("fails closed when the session behind an access token is missing", async () => {
    const flow = await authorize({ scope: "openid profile" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const sid = decodeJwt(tokens.access_token).payload.sid;
    assert.ok(sid, "a user access token must identify its server-side session");

    await prisma.oidcSession.delete({ where: { id: sid } });

    await assert.rejects(
      provider.userinfo({ accessToken: tokens.access_token }),
      /session.*(ended|available)/i
    );
    const inspected = await provider.introspect({
      headers,
      body: { token: tokens.access_token, token_type_hint: "access_token" }
    });
    assert.deepEqual(inspected, { active: false });
  });

  it("does not consume an authorization code when its OIDC session is missing", async () => {
    const flow = await authorize({ scope: "openid" });
    const record = await prisma.authorizationCode.findUnique({
      where: { codeHash: hashToken(flow.code) }
    });
    await prisma.oidcSession.deleteMany({
      where: { sessionId: record.sessionId, clientId: confidential.clientId }
    });

    await assert.rejects(
      provider.token({
        headers: basicAuth(confidential.clientId, confidentialSecret),
        body: {
          grant_type: "authorization_code",
          code: flow.code,
          redirect_uri: flow.redirectUri,
          code_verifier: flow.verifier
        }
      }),
      /session has been ended/i
    );

    const untouched = await prisma.authorizationCode.findUnique({ where: { id: record.id } });
    assert.equal(untouched.usedAt, null, "a failed session check burned the authorization code");
  });

  it("fails refresh exchange and introspection closed when the OIDC session is missing", async () => {
    const flow = await authorize({ scope: "openid offline_access" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const sid = decodeJwt(tokens.access_token).payload.sid;
    await prisma.oidcSession.delete({ where: { id: sid } });

    const inspected = await provider.introspect({
      headers,
      body: { token: tokens.refresh_token, token_type_hint: "refresh_token" }
    });
    assert.deepEqual(inspected, { active: false });

    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: tokens.refresh_token }
      }),
      /session has been ended/i
    );
    const stored = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashToken(tokens.refresh_token) }
    });
    assert.equal(stored.usedAt, null, "the missing-session refresh was consumed");
    assert.ok(stored.revokedAt, "the unusable refresh family was not revoked");
  });

  it("refuses UserInfo for a token issued without openid", async () => {
    const flow = await authorize({ scope: "credits.read" });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    await assert.rejects(
      provider.userinfo({ accessToken: tokens.access_token }),
      /not issued with the openid scope/
    );
  });

  it("refuses a token signed by a key this issuer does not know", async () => {
    const { generateKey, signJwt, createKeyRing } = require("../../src/lib/jwt");
    const foreign = generateKey({ alg: "ES256" });
    const ring = createKeyRing({
      keys: [{ kid: foreign.kid, alg: foreign.alg, privateJwk: foreign.privateKey.export({ format: "jwk" }) }]
    });
    const forged = signJwt({
      key: ring.activeKey,
      claims: {
        iss: "http://127.0.0.1:3010",
        sub: account.id,
        aud: "http://127.0.0.1:3010",
        client_id: confidential.clientId,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 600,
        scope: "openid profile email",
        token_use: "access"
      }
    });
    await assert.rejects(provider.userinfo({ accessToken: forged }), /Unknown JWT key id/);
  });

  // --- Introspection ------------------------------------------------------

  it("introspects an access token for the client it was issued to", async () => {
    const flow = await authorize({ scope: "openid profile" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    const introspected = await provider.introspect({
      headers,
      body: { token: tokens.access_token }
    });
    assert.equal(introspected.active, true);
    assert.equal(introspected.sub, account.id);
    assert.equal(introspected.client_id, confidential.clientId);
    assert.equal(introspected.scope, "openid profile");
    assert.equal(introspected.token_type, "Bearer");
    assert.equal(account.role, "ADMIN");
    assert.equal(introspected.credits_admin, false, "an admin without the scope gained live authority");
    assert.ok(Number.isInteger(introspected.exp));
  });

  it("reports live admin authority false for an ordinary user", async () => {
    const registered = await accounts.register({
      email: `ordinary-${crypto.randomUUID()}@example.test`,
      password: "ordinary-user-password"
    });
    assert.equal(registered.account.role, "USER");
    const browserSession = (await sessions.create({ userId: registered.account.id })).session;
    const flow = await authorize(
      { scope: "openid" },
      { authorizationAccount: registered.account, browserSession }
    );
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    const introspected = await provider.introspect({
      headers,
      body: { token: tokens.access_token }
    });
    assert.equal(introspected.active, true);
    assert.equal(introspected.credits_admin, false);
  });

  it("tells another client nothing about a token that is not theirs", async () => {
    const flow = await authorize({ scope: "openid" });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const nosy = await clients.create(
      {
        name: "Nosy Client",
        clientType: "confidential",
        redirectUris: ["https://nosy.example/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic"
      },
      { status: "APPROVED" }
    );
    const result = await provider.introspect({
      headers: basicAuth(nosy.client.clientId, nosy.clientSecret),
      body: { token: tokens.access_token }
    });
    // RFC 7662 section 2.2: nothing but `active: false`.
    assert.deepEqual(result, { active: false });
  });

  it("reports an unknown token as inactive rather than as an error", async () => {
    const result = await provider.introspect({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: { token: "not-a-token-this-server-ever-issued" }
    });
    assert.deepEqual(result, { active: false });
  });

  it("introspects a refresh token even with the wrong type hint", async () => {
    const flow = await authorize({ scope: "openid offline_access" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const result = await provider.introspect({
      headers,
      // Deliberately wrong: the hint is an optimization, not a filter.
      body: { token: tokens.refresh_token, token_type_hint: "access_token" }
    });
    assert.equal(result.active, true);
    assert.equal(result.token_use, "refresh");
  });

  // --- Revocation ---------------------------------------------------------

  it("revokes a refresh token and still answers for an unknown one", async () => {
    const flow = await authorize({ scope: "openid offline_access" });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    await provider.revoke({ headers, body: { token: tokens.refresh_token } });
    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: tokens.refresh_token }
      }),
      /revoked/
    );

    // RFC 7009 section 2.2: an unknown token is a success, so the endpoint cannot
    // be used to test whether a token is valid.
    const result = await provider.revoke({ headers, body: { token: "unknown-token" } });
    assert.deepEqual(result, { revoked: true });
  });

  it("revokes an access token centrally and retires its session refresh token", async () => {
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize(
      { scope: "openid offline_access" },
      { browserSession: browser.session }
    );
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    assert.equal(
      (await provider.introspect({ headers, body: { token: tokens.access_token } })).active,
      true
    );
    await provider.revoke({ headers, body: { token: tokens.access_token } });
    assert.equal(
      (await provider.introspect({ headers, body: { token: tokens.access_token } })).active,
      false
    );
    await assert.rejects(
      provider.token({
        headers,
        body: { grant_type: "refresh_token", refresh_token: tokens.refresh_token }
      }),
      /revoked/
    );
  });

  it("does not swallow a storage failure while revoking an access token", async () => {
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize({ scope: "openid" }, { browserSession: browser.session });
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const failingPrisma = new Proxy(prisma, {
      get(target, property) {
        if (property === "oidcSession") {
          return new Proxy(target.oidcSession, {
            get(model, method) {
              if (method === "findUnique") {
                return async () => {
                  throw new Error("simulated access-token revocation storage failure");
                };
              }
              const value = model[method];
              return typeof value === "function" ? value.bind(model) : value;
            }
          });
        }
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const failingProvider = createProviderService({
      prisma: failingPrisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    await assert.rejects(
      failingProvider.revoke({ headers, body: { token: tokens.access_token } }),
      /simulated access-token revocation storage failure/
    );
  });

  it("revokes a refresh family under the shared Client, User, Grant lock order", async () => {
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize(
      { scope: "openid offline_access" },
      { browserSession: browser.session }
    );
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const tokens = await provider.token({
      headers,
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    const trace = [];
    const traceLock = (sql) => {
      if (sql.includes('"oauth_clients"')) trace.push("client");
      else if (sql.includes('"users"')) trace.push("user");
      else if (sql.includes('"grants"')) trace.push("grant");
    };
    const transactionClient = (client) =>
      new Proxy(client, {
        get(target, property) {
          if (property === "$executeRawUnsafe" || property === "$queryRawUnsafe") {
            return async (sql, ...args) => {
              traceLock(sql);
              return target[property](sql, ...args);
            };
          }
          if (property === "refreshToken") {
            return new Proxy(target.refreshToken, {
              get(model, method) {
                if (method === "updateMany") {
                  return async (...args) => {
                    trace.push("refresh");
                    return model.updateMany(...args);
                  };
                }
                const value = model[method];
                return typeof value === "function" ? value.bind(model) : value;
              }
            });
          }
          const value = target[property];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const tracedPrisma = new Proxy(prisma, {
      get(target, property) {
        if (property === "$transaction") {
          return (callback, ...args) =>
            target.$transaction((tx) => callback(transactionClient(tx)), ...args);
        }
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const tracedProvider = createProviderService({
      prisma: tracedPrisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    await tracedProvider.revoke({ headers, body: { token: tokens.refresh_token } });
    assert.deepEqual(
      trace,
      ["client", "user", "grant", "refresh"],
      "family revocation did not share issuance's stable lock contract"
    );
  });

  it("rolls back both halves of code-replay containment when one write fails", async () => {
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize(
      { scope: "openid offline_access" },
      { browserSession: browser.session }
    );
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const body = {
      grant_type: "authorization_code",
      code: flow.code,
      redirect_uri: flow.redirectUri,
      code_verifier: flow.verifier
    };
    const tokens = await provider.token({ headers, body });
    const oidcSessionId = decodeJwt(tokens.access_token).payload.sid;

    let failOidcWrite = true;
    const transactionClient = (client) =>
      new Proxy(client, {
        get(target, property) {
          if (property === "oidcSession") {
            return new Proxy(target.oidcSession, {
              get(model, method) {
                if (method === "updateMany") {
                  return async (...args) => {
                    if (failOidcWrite) {
                      failOidcWrite = false;
                      throw new Error("simulated code-replay containment failure");
                    }
                    return model.updateMany(...args);
                  };
                }
                const value = model[method];
                return typeof value === "function" ? value.bind(model) : value;
              }
            });
          }
          const value = target[property];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const failingPrisma = new Proxy(prisma, {
      get(target, property) {
        if (property === "$transaction") {
          return (callback, ...args) =>
            target.$transaction((tx) => callback(transactionClient(tx)), ...args);
        }
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const failingProvider = createProviderService({
      prisma: failingPrisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    await assert.rejects(
      failingProvider.token({ headers, body }),
      /simulated code-replay containment failure/
    );
    assert.equal(failOidcWrite, false, "the injected containment failure was not exercised");

    const refreshAfterFailure = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashToken(tokens.refresh_token) }
    });
    const oidcAfterFailure = await prisma.oidcSession.findUnique({ where: { id: oidcSessionId } });
    assert.equal(refreshAfterFailure.revokedAt, null, "refresh containment committed by itself");
    assert.equal(oidcAfterFailure.revokedAt, null, "OIDC containment committed by itself");

    await assert.rejects(provider.token({ headers, body }), (error) => {
      assert.equal(error.code, "invalid_grant");
      return true;
    });
    assert.ok(
      (await prisma.refreshToken.findUnique({ where: { id: refreshAfterFailure.id } })).revokedAt,
      "a retry did not contain the refresh family"
    );
    assert.ok(
      (await prisma.oidcSession.findUnique({ where: { id: oidcSessionId } })).revokedAt,
      "a retry did not contain the OIDC session"
    );
  });

  // --- Grant management ---------------------------------------------------

  it("lists the applications a user has authorized, with readable permissions", async () => {
    const grants = await provider.listGrantsForUser(account.id);
    assert.ok(grants.length >= 1);
    const entry = grants.find((grant) => grant.clientId === confidential.clientId);
    assert.ok(entry, "the client the user authorized must appear");
    assert.equal(entry.clientName, "Third Party Web App");
    // `openid` is not a user-visible permission, so it is not listed.
    assert.ok(!entry.permissions.some((permission) => permission.name === "openid"));
    assert.ok(entry.permissions.every((permission) => permission.description));
  });

  // --- Logout -------------------------------------------------------------

  it("merges two consents that arrive at the same moment instead of losing one", async () => {
    // Two halves, and they fail on different engines.
    //
    // The quiet one — two widenings that both read the same row and each write
    // their own merge over it, so one scope is silently dropped — interleaves in
    // the event loop at the awaits, so it shows on SQLite too. Verified: with
    // the fix reverted, this test fails on SQLite.
    //
    // The loud one needs PostgreSQL. `grants` carries
    // @@unique([userId, clientId]), and two inserts racing means an unhandled
    // P2002 reaching oauthController, which only redirects errors it recognises
    // as protocol errors — so a raw {"error":"server_error"} appears in the
    // browser. Prisma opens one connection to SQLite and the application is a
    // single writer, so that insert race cannot happen there. It is the postgres
    // job that exercises it.
    const client = await clients.create(
      {
        name: "Two Tabs",
        clientType: "confidential",
        redirectUris: ["https://tabs.example/callback"],
        scopes: ["openid", "profile", "email"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "client_secret_basic"
      },
      { status: "APPROVED" }
    );

    const [first, second] = await Promise.all([
      provider.upsertGrant({ userId: account.id, clientId: client.client.clientId, scopes: ["openid", "profile"] }),
      provider.upsertGrant({ userId: account.id, clientId: client.client.clientId, scopes: ["openid", "email"] })
    ]);
    assert.ok(first && second, "neither call may fail; the loser used to reach the browser as server_error");

    const rows = await prisma.grant.findMany({
      where: { userId: account.id, clientId: client.client.clientId }
    });
    assert.equal(rows.length, 1, "the unique constraint means one row, so two inserts is the bug");

    const stored = rows[0].scopes;
    assert.match(stored, /\bprofile\b/, "the first consent was dropped");
    assert.match(stored, /\bemail\b/, "the second consent was dropped");
  });

  it("will not end a session that belongs to someone else", async () => {
    // `sessionId` reaches endSessions from `req.body.session_id`. With the
    // queries matching on it alone, any signed-in user could end another user's
    // OIDC sessions across every client — and fire a back-channel logout to
    // each of them — by submitting an identifier that was not theirs. The
    // caller passed `userId` and its own comment said the call was scoped by
    // it; only the audit entry ever read it.
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize({ scope: "openid" }, { browserSession: browser.session });
    await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });

    const live = await prisma.oidcSession.count({
      where: { sessionId: browser.session.id, revokedAt: null }
    });
    assert.ok(live >= 1, "a live session is needed for the attempt to mean anything");

    const result = await provider.endSessions({
      sessionId: browser.session.id,
      userId: "some-other-user-entirely",
      reason: "user_revoked"
    });
    assert.equal(result.revoked, false, "a stranger's browser session was deleted");
    assert.equal(result.notified, 0, "a stranger's session was notified");
    assert.equal(
      await prisma.oidcSession.count({
        where: { sessionId: browser.session.id, revokedAt: null }
      }),
      live,
      "a stranger's session was revoked"
    );
    assert.ok(
      await prisma.session.findUnique({ where: { id: browser.session.id } }),
      "a stranger's browser session was deleted"
    );
  });

  it("refuses to end sessions without an owner to scope the revocation to", async () => {
    // An absent scope is the defect itself, so it fails loudly rather than
    // falling back to matching every user — which is what it used to do.
    const browser = await sessions.create({ userId: account.id });
    await assert.rejects(
      () => provider.endSessions({ sessionId: browser.session.id }),
      /requires a userId/
    );
  });

  it("rolls browser and OIDC sessions back when the logout outbox write fails", async () => {
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize({ scope: "openid" }, { browserSession: browser.session });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const oidcSessionId = decodeJwt(tokens.id_token).payload.sid;

    let failOutboxWrite = true;
    const transactionClient = (client) =>
      new Proxy(client, {
        get(target, property) {
          if (property === "backchannelLogout") {
            return new Proxy(target.backchannelLogout, {
              get(model, method) {
                if (method === "create") {
                  return async (...args) => {
                    if (failOutboxWrite) {
                      failOutboxWrite = false;
                      throw new Error("simulated browser logout outbox failure");
                    }
                    return model.create(...args);
                  };
                }
                const value = model[method];
                return typeof value === "function" ? value.bind(model) : value;
              }
            });
          }
          const value = target[property];
          return typeof value === "function" ? value.bind(target) : value;
        }
      });
    const failingPrisma = new Proxy(prisma, {
      get(target, property) {
        if (property === "$transaction") {
          return (callback, ...args) =>
            target.$transaction((tx) => callback(transactionClient(tx)), ...args);
        }
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const failingProvider = createProviderService({
      prisma: failingPrisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } }),
      backchannel: createBackchannelService({ prisma, config, clients, keys })
    });

    await assert.rejects(
      failingProvider.endSessions({ sessionId: browser.session.id, userId: account.id }),
      /simulated browser logout outbox failure/
    );
    assert.equal(failOutboxWrite, false, "the logout outbox failure was not exercised");
    assert.ok(
      await prisma.session.findUnique({ where: { id: browser.session.id } }),
      "the browser credential was deleted without a durable logout intent"
    );
    assert.equal(
      (await prisma.oidcSession.findUnique({ where: { id: oidcSessionId } })).revokedAt,
      null,
      "the OIDC session was revoked without a durable logout intent"
    );
    assert.equal(
      await prisma.backchannelLogout.count({ where: { sessionId: oidcSessionId } }),
      0,
      "the failed logout left a partial outbox row"
    );

    const retried = await provider.endSessions({
      sessionId: browser.session.id,
      userId: account.id
    });
    assert.equal(retried.revoked, true);
    assert.ok(retried.notified >= 1);
    assert.equal(await prisma.session.findUnique({ where: { id: browser.session.id } }), null);
    assert.ok((await prisma.oidcSession.findUnique({ where: { id: oidcSessionId } })).revokedAt);
    assert.equal(
      await prisma.backchannelLogout.count({ where: { sessionId: oidcSessionId } }),
      1
    );
  });

  it("notifies a client by back channel when the session ends", async () => {
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize({ scope: "openid" }, { browserSession: browser.session });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    // The value the relying party indexed its session by when it accepted the
    // ID token. Captured here so the logout token can be compared against it
    // rather than merely inspected for a well-formed-looking identifier.
    const idTokenSid = decodeJwt(tokens.id_token).payload.sid;
    assert.ok(idTokenSid);

    const before = backchannelPosts.length;
    const { revoked, notified } = await provider.endSessions({
      sessionId: browser.session.id,
      userId: account.id
    });
    assert.equal(revoked, true);
    assert.ok(notified >= 1, "a client with a registered endpoint must be queued");
    assert.equal(
      await prisma.session.findUnique({ where: { id: browser.session.id } }),
      null,
      "ending the browser session left its bearer credential active"
    );

    const backchannel = createBackchannelService({
      prisma,
      config,
      clients,
      keys,
      fetchImpl: async (url, init) => {
        backchannelPosts.push({ url, body: init.body });
        return { status: 200 };
      }
    });
    const flushed = await backchannel.flush();
    assert.ok(flushed.delivered >= 1);
    assert.ok(backchannelPosts.length > before);

    const posted = backchannelPosts.at(-1);
    assert.equal(posted.url, "https://rp.example/backchannel-logout");
    const logoutToken = new URLSearchParams(posted.body).get("logout_token");
    const payload = decodeJwt(logoutToken).payload;
    assert.equal(payload.iss, "http://127.0.0.1:3010");
    assert.equal(payload.aud, confidential.clientId);
    assert.equal(payload.sub, account.id);
    assert.ok(payload.events["http://schemas.openid.net/event/backchannel-logout"]);
    // A logout token must carry no nonce: its absence is how a recipient tells it
    // apart from an ID token.
    assert.equal(payload.nonce, undefined);
    assert.equal(decodeJwt(logoutToken).header.typ, "logout+jwt");
    // Back-Channel Logout 1.0 section 2.4: the same session identifier the ID
    // token published. Asserting only that `sid` is present passes just as
    // happily on the wrong random id — and the wrong one delivers a
    // well-formed token that no relying party can act on, so the issuer records
    // a successful logout while the user stays signed in.
    assert.equal(
      payload.sid,
      idTokenSid,
      "the logout token must name the session the ID token named, or the relying party ends nothing"
    );
  });

  it("honours a registered post_logout_redirect_uri and refuses an unregistered one", async () => {
    const allowed = await provider.resolveLogoutRedirect({
      clientId: confidential.clientId,
      postLogoutRedirectUri: "https://rp.example/signed-out",
      state: "logout-state"
    });
    assert.equal(allowed, "https://rp.example/signed-out?state=logout-state");

    const refused = await provider.resolveLogoutRedirect({
      clientId: confidential.clientId,
      postLogoutRedirectUri: "https://attacker.example/collect"
    });
    assert.equal(refused, null, "an unregistered URI would make this an open redirect");
  });

  it("reads an expired id_token_hint, because that is the normal case at logout", async () => {
    const login = await sessions.login({ userId: account.id });
    const flow = await authorize(
      { scope: "openid" },
      { client: publicClient }
    );
    const tokens = await provider.token({
      headers: {},
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier,
        client_id: publicClient.clientId
      }
    });
    const hint = await provider.readIdTokenHint(tokens.id_token);
    assert.equal(hint.clientId, publicClient.clientId);
    assert.equal(hint.sub, account.id);
    assert.ok(login.session);
  });

  // --- Consent ------------------------------------------------------------

  it("records a declined authorization as access_denied", async () => {
    const denied = await authorize({ state: "deny-state" }, { approve: false });
    assert.equal(denied.error, "access_denied");
    assert.equal(denied.state, "deny-state");
    assert.equal(denied.code, null);
    // RFC 9207 section 2 covers every authorization response, not only the
    // successful ones, and section 2.4 has the client reject one that arrives
    // without `iss`. Discovery advertises support unconditionally, so an error
    // response missing it does not reach the client as `access_denied` at all —
    // oauth4webapi checks `iss` before it reads `error`, and the relying party
    // gets an unexplained library fault instead.
    assert.equal(denied.iss, "http://127.0.0.1:3010", "an error response carries iss too");
  });

  it("issues only the scopes the user approved", async () => {
    const flow = await authorize({
      scope: "openid profile email",
      prompt: "consent",
      approvedScopes: ["profile"]
    });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    // `openid` rides along because it is not a permission the user declines
    // separately — it only means "issue an ID token".
    assert.equal(tokens.scope, "openid profile");
    const claims = await provider.userinfo({ accessToken: tokens.access_token });
    assert.equal(claims.name, "Ada Lovelace");
    assert.equal(claims.email, undefined, "email was declined");
  });

  // --- Housekeeping -------------------------------------------------------

  it("retains used codes for replay containment and prunes them after the risk window", async () => {
    const browser = await sessions.create({ userId: account.id });
    const usedFlow = await authorize(
      { scope: "openid" },
      { browserSession: browser.session }
    );
    await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: usedFlow.code,
        redirect_uri: usedFlow.redirectUri,
        code_verifier: usedFlow.verifier
      }
    });
    const usedCode = await prisma.authorizationCode.findUnique({
      where: { codeHash: hashToken(usedFlow.code) }
    });

    const unusedFlow = await authorize(
      { scope: "openid" },
      { browserSession: browser.session }
    );
    const unusedCode = await prisma.authorizationCode.findUnique({
      where: { codeHash: hashToken(unusedFlow.code) }
    });
    await prisma.authorizationCode.update({
      where: { id: unusedCode.id },
      data: { expiresAt: new Date(Date.now() - 1000) }
    });

    const first = await provider.pruneExpired();
    assert.ok(Number.isInteger(first.authorizationRequests));
    assert.ok(Number.isInteger(first.refreshTokens));
    assert.ok(
      await prisma.authorizationCode.findUnique({ where: { id: usedCode.id } }),
      "a fresh used code was removed before its descendants could expire"
    );
    assert.equal(
      await prisma.authorizationCode.findUnique({ where: { id: unusedCode.id } }),
      null,
      "an unused expired code was retained"
    );

    const replayWindowSeconds = Math.max(
      config.ttl.accessTokenSeconds,
      config.ttl.refreshTokenSeconds
    );
    await prisma.authorizationCode.update({
      where: { id: usedCode.id },
      data: { usedAt: new Date(Date.now() - replayWindowSeconds * 1000 - 1000) }
    });
    const second = await provider.pruneExpired();
    assert.ok(second.codes >= 1);
    assert.equal(
      await prisma.authorizationCode.findUnique({ where: { id: usedCode.id } }),
      null,
      "a used code outlived every credential it could contain"
    );
  });

  it("still contains a code replay after housekeeping runs", async () => {
    const browser = await sessions.create({ userId: account.id });
    const flow = await authorize(
      { scope: "openid offline_access" },
      { browserSession: browser.session }
    );
    const headers = basicAuth(confidential.clientId, confidentialSecret);
    const body = {
      grant_type: "authorization_code",
      code: flow.code,
      redirect_uri: flow.redirectUri,
      code_verifier: flow.verifier
    };
    const tokens = await provider.token({ headers, body });
    const code = await prisma.authorizationCode.findUnique({
      where: { codeHash: hashToken(flow.code) }
    });
    const oidcSessionId = decodeJwt(tokens.access_token).payload.sid;

    await provider.pruneExpired();
    assert.ok(
      await prisma.authorizationCode.findUnique({ where: { id: code.id } }),
      "housekeeping removed the replay detector while descendants were live"
    );

    await assert.rejects(provider.token({ headers, body }), (error) => {
      assert.equal(error.code, "invalid_grant");
      return true;
    });
    assert.ok(
      (await prisma.refreshToken.findUnique({
        where: { tokenHash: hashToken(tokens.refresh_token) }
      })).revokedAt,
      "the post-prune replay did not revoke its refresh family"
    );
    assert.ok(
      (await prisma.oidcSession.findUnique({ where: { id: oidcSessionId } })).revokedAt,
      "the post-prune replay did not revoke its OIDC session"
    );
  });

  it("keeps session revocation state for the longest token lifetime", async () => {
    const flow = await authorize({ scope: "openid" });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const candidate = await prisma.oidcSession.findUnique({
      where: { id: decodeJwt(tokens.access_token).payload.sid }
    });
    assert.ok(candidate, "the test needs an OIDC session to age");

    const ninetyMinutesAgo = new Date(Date.now() - 90 * 60 * 1000);
    await prisma.oidcSession.update({
      where: { id: candidate.id },
      data: { lastSeenAt: ninetyMinutesAgo }
    });

    const unevenTtlProvider = createProviderService({
      prisma,
      config: {
        ...config,
        ttl: { ...config.ttl, accessTokenSeconds: 2 * 60 * 60, refreshTokenSeconds: 60 * 60 }
      },
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });
    await unevenTtlProvider.pruneExpired();

    assert.ok(
      await prisma.oidcSession.findUnique({ where: { id: candidate.id } }),
      "an access token can still reference this session for another 30 minutes"
    );
  });

  it("keeps OIDC state while its remembered browser session is still active", async () => {
    const browser = await sessions.create({ userId: account.id, remember: true });
    const flow = await authorize(
      { scope: "openid" },
      { browserSession: browser.session }
    );
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const oidcSession = await prisma.oidcSession.findUnique({
      where: { id: decodeJwt(tokens.access_token).payload.sid }
    });
    await prisma.oidcSession.update({
      where: { id: oidcSession.id },
      data: { lastSeenAt: new Date(Date.now() - 2 * 60 * 60 * 1000) }
    });

    const shortTokenProvider = createProviderService({
      prisma,
      config: {
        ...config,
        ttl: { ...config.ttl, accessTokenSeconds: 60 * 60, refreshTokenSeconds: 60 * 60 }
      },
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });
    await shortTokenProvider.pruneExpired();
    assert.ok(
      await prisma.oidcSession.findUnique({ where: { id: oidcSession.id } }),
      "pruning broke logout fan-out for an active remembered browser session"
    );

    await prisma.session.delete({ where: { id: browser.session.id } });
    await shortTokenProvider.pruneExpired();
    assert.equal(await prisma.oidcSession.findUnique({ where: { id: oidcSession.id } }), null);
  });

  it("does not prune an OIDC session refreshed after the stale candidate read", async () => {
    const browser = await sessions.create({ userId: account.id, remember: false });
    const flow = await authorize({ scope: "openid" }, { browserSession: browser.session });
    const tokens = await provider.token({
      headers: basicAuth(confidential.clientId, confidentialSecret),
      body: {
        grant_type: "authorization_code",
        code: flow.code,
        redirect_uri: flow.redirectUri,
        code_verifier: flow.verifier
      }
    });
    const oidcSession = await prisma.oidcSession.findUnique({
      where: { id: decodeJwt(tokens.access_token).payload.sid }
    });
    await prisma.session.delete({ where: { id: browser.session.id } });
    await prisma.oidcSession.update({
      where: { id: oidcSession.id },
      data: { lastSeenAt: new Date(Date.now() - 2 * 60 * 60 * 1000) }
    });

    let refreshedBeforeDelete = false;
    const racingOidcSessions = new Proxy(prisma.oidcSession, {
      get(target, property) {
        if (property === "deleteMany") {
          return async (args) => {
            if (!refreshedBeforeDelete && args?.where?.id?.in?.includes(oidcSession.id)) {
              refreshedBeforeDelete = true;
              await target.update({
                where: { id: oidcSession.id },
                data: { lastSeenAt: new Date() }
              });
            }
            return target.deleteMany(args);
          };
        }
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const racingPrisma = new Proxy(prisma, {
      get(target, property) {
        if (property === "oidcSession") return racingOidcSessions;
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
    const shortTokenProvider = createProviderService({
      prisma: racingPrisma,
      config: {
        ...config,
        ttl: { ...config.ttl, accessTokenSeconds: 60 * 60, refreshTokenSeconds: 60 * 60 }
      },
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    await shortTokenProvider.pruneExpired();
    assert.equal(refreshedBeforeDelete, true, "the delete race was not exercised");
    assert.ok(
      await prisma.oidcSession.findUnique({ where: { id: oidcSession.id } }),
      "pruning deleted a session that became active after candidate selection"
    );
  });

  it("stores no code, token, or verifier in the clear", async () => {
    // The strongest structural guarantee in this design: a database dump cannot
    // be replayed against the issuer.
    const codes = await prisma.authorizationCode.findMany();
    for (const code of codes) {
      assert.equal(code.codeHash.length, 64, "SHA-256 hex, not the code");
      assert.equal(code.codeChallengeMethod === null || code.codeChallengeMethod === "S256", true);
    }
    const refreshTokens = await prisma.refreshToken.findMany();
    for (const token of refreshTokens) {
      assert.equal(token.tokenHash.length, 64);
    }
    const requests = await prisma.authorizationRequest.findMany();
    for (const request of requests) {
      assert.equal(request.requestTokenHash.length, 64);
    }
    // The audit trail must not have recorded any of it either.
    const logs = await prisma.auditLog.findMany();
    for (const entry of logs) {
      const json = entry.metadataJson || "";
      assert.ok(!/"(token|code|secret|verifier|nonce|state)"\s*:/.test(json), `audit metadata leaked: ${json}`);
    }
  });
});

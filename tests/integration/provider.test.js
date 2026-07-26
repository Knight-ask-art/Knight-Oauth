"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { after, before, describe, it } = require("node:test");

const { withDatabase } = require("../helpers/database");
const { loadEnv } = require("../../src/config/env");
const { createScopeRegistry } = require("../../src/lib/scopes");
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
  async function authorize(overrides = {}, { client = confidential, approve = true } = {}) {
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
    const decision = await provider.resolveAuthorization({ request: loaded, account, session });

    const result = approve
      ? await provider.completeAuthorization({
          requestToken,
          account,
          session,
          approvedScopes: overrides.approvedScopes || null
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

  it("rejects a code redeemed by a different client", async () => {
    const flow = await authorize({ scope: "openid" });
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
    assert.ok(Number.isInteger(introspected.exp));
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

  it("notifies a client by back channel when the session ends", async () => {
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
    // The value the relying party indexed its session by when it accepted the
    // ID token. Captured here so the logout token can be compared against it
    // rather than merely inspected for a well-formed-looking identifier.
    const idTokenSid = decodeJwt(tokens.id_token).payload.sid;
    assert.ok(idTokenSid);

    const before = backchannelPosts.length;
    const { notified } = await provider.endSessions({ sessionId: session.id, userId: account.id });
    assert.ok(notified >= 1, "a client with a registered endpoint must be queued");

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

  it("prunes spent and expired protocol records", async () => {
    const result = await provider.pruneExpired();
    assert.ok(result.codes >= 1, "used codes are removed");
    assert.ok(Number.isInteger(result.authorizationRequests));
    assert.ok(Number.isInteger(result.refreshTokens));
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

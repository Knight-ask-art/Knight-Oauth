"use strict";

const { hashToken, randomId, randomToken, s256Challenge, safeEqual } = require("../lib/crypto");
const { decodeScopes, encodeScopes } = require("../lib/lists");
const { leftHalfHash, signJwt, verifyJwt } = require("../lib/jwt");
const {
  accessDenied,
  consentRequired,
  invalidGrant,
  invalidRequest,
  invalidScope,
  invalidToken,
  loginRequired,
  unsupportedGrantType,
  unsupportedResponseType
} = require("../lib/errors");
const { buildErrorRedirect } = require("../lib/uri");

class RefreshReplayDetected extends Error {}
class CodeReplayDetected extends Error {}
class RefreshStateRejected extends Error {
  constructor(reason, protocolError) {
    super(protocolError.message);
    this.reason = reason;
    this.protocolError = protocolError;
  }
}

// The OAuth 2.0 / OpenID Connect provider.
//
// Interoperability is the point of this file. A relying party using any
// conformant library must work against this issuer without special-casing it,
// which means the protocol details below are not stylistic choices:
//
//   * UserInfo returns `sub`. OIDC Core section 5.3.2 requires it, and a library
//     that verifies the response `sub` matches the ID token `sub` — as the spec
//     tells it to — fails outright without it. The previous implementation
//     returned `{ id, uid, username, name, avatar }` and no `sub` at all.
//
//   * `state` and `nonce` are optional. RFC 6749 makes `state` RECOMMENDED and
//     OIDC Core makes `nonce` OPTIONAL for the code flow. Requiring them, as the
//     previous implementation did, rejects clients that correctly rely on PKCE.
//
//   * `openid` is not required. Without it this is a plain OAuth 2.0
//     authorization server, which is a supported configuration, not an error.
//
//   * Authorization codes are single-use and short-lived; refresh tokens rotate
//     and a replayed token revokes its whole family.
//
// Anything that could authenticate a request is stored only as a SHA-256 hash.
// The tables hold no codes, no tokens, no cookies, and no PKCE verifiers.

const CODE_CHALLENGE_METHODS = ["S256"];
const MAX_OPAQUE_LENGTH = 2048;

/** Seconds since the epoch, as every JWT time claim is expressed. */
function epoch(date) {
  return Math.floor(date.getTime() / 1000);
}

/**
 * Validates an opaque client-supplied value (`state`, `nonce`).
 *
 * Returned verbatim when present and null when absent. A cap is applied because
 * these are echoed into a redirect URL, and an unbounded value is a way to force
 * a URL past what a browser or proxy will accept.
 */
function optionalOpaque(value, name) {
  if (value === undefined || value === null || value === "") return null;
  const raw = String(value);
  if (raw.length > MAX_OPAQUE_LENGTH) throw invalidRequest(`${name} is too long`);
  return raw;
}

/** `prompt` is a space-delimited set (OIDC Core section 3.1.2.1). */
function parsePrompt(value) {
  const prompts = decodeScopes(String(value || ""));
  const known = new Set(["none", "login", "consent", "select_account"]);
  for (const prompt of prompts) {
    if (!known.has(prompt)) throw invalidRequest(`Unsupported prompt value: ${prompt}`);
  }
  // `none` means "do not interact with the user", so combining it with a value
  // that requires interaction is contradictory. OIDC Core says so explicitly.
  if (prompts.includes("none") && prompts.length > 1) {
    throw invalidRequest("prompt=none cannot be combined with other prompt values");
  }
  return prompts;
}

function parseMaxAge(value) {
  if (value === undefined || value === null || value === "") return null;
  const seconds = Number(value);
  if (!Number.isInteger(seconds) || seconds < 0) throw invalidRequest("max_age must be a non-negative integer");
  return seconds;
}

function createProviderService({
  prisma,
  config,
  scopeRegistry,
  clients,
  accounts,
  sessions,
  keys,
  auditLog,
  backchannel,
  now = () => new Date()
} = {}) {
  const issuer = config.issuer;
  const ttl = config.ttl;
  const requireNonce = Boolean(config?.security?.requireNonceForIdToken);
  const rotateRefreshTokens = config?.security?.rotateRefreshTokens !== false;
  const clockToleranceSeconds = ttl.clockToleranceSeconds || 0;
  const databaseProvider = config?.database?.provider || "sqlite";

  function endpoint(pathname) {
    return `${issuer}${pathname}`;
  }

  // PostgreSQL needs explicit row locks: a plain read at READ COMMITTED does not
  // serialize a later credential issuance with a concurrent administrative
  // change. SQLite has no SELECT ... FOR UPDATE, so a no-op UPDATE takes its
  // database write lock without changing application data or @updatedAt fields.
  // Every credential transition uses these in the same order:
  // Client -> User -> Grant -> Browser Session -> Refresh/Code -> OIDC Session.
  async function lockClient(database, clientId) {
    const id = String(clientId || "");
    if (!id) return null;
    if (databaseProvider === "postgresql") {
      await database.$queryRawUnsafe(
        'SELECT "client_id" FROM "oauth_clients" WHERE "client_id" = $1 FOR UPDATE',
        id
      );
    } else {
      await database.$executeRawUnsafe(
        'UPDATE "oauth_clients" SET "client_id" = "client_id" WHERE "client_id" = ?',
        id
      );
    }
    return clients.toClient(await database.oAuthClient.findUnique({ where: { clientId: id } }));
  }

  async function lockUser(database, userId) {
    const id = String(userId || "");
    if (!id) return null;
    if (databaseProvider === "postgresql") {
      await database.$queryRawUnsafe('SELECT "id" FROM "users" WHERE "id" = $1 FOR UPDATE', id);
    } else {
      await database.$executeRawUnsafe('UPDATE "users" SET "id" = "id" WHERE "id" = ?', id);
    }
    return accounts.toAccount(await database.user.findUnique({ where: { id } }));
  }

  async function lockGrant(database, { userId, clientId }) {
    const owner = String(userId || "");
    const client = String(clientId || "");
    if (!owner || !client) return null;
    if (databaseProvider === "postgresql") {
      await database.$queryRawUnsafe(
        'SELECT "id" FROM "grants" WHERE "user_id" = $1 AND "client_id" = $2 FOR UPDATE',
        owner,
        client
      );
    } else {
      await database.$executeRawUnsafe(
        'UPDATE "grants" SET "id" = "id" WHERE "user_id" = ? AND "client_id" = ?',
        owner,
        client
      );
    }
    return database.grant.findUnique({
      where: { userId_clientId: { userId: owner, clientId: client } }
    });
  }

  async function lockBrowserSession(database, { sessionId, userId, validAt = null }) {
    const id = String(sessionId || "");
    const owner = String(userId || "");
    if (!id || !owner) return null;
    if (databaseProvider === "postgresql") {
      await database.$queryRawUnsafe(
        'SELECT "id" FROM "sessions" WHERE "id" = $1 AND "user_id" = $2 FOR UPDATE',
        id,
        owner
      );
    } else {
      await database.$executeRawUnsafe(
        'UPDATE "sessions" SET "id" = "id" WHERE "id" = ? AND "user_id" = ?',
        id,
        owner
      );
    }
    const record = await database.session.findUnique({ where: { id } });
    if (!record || record.userId !== owner) return null;
    if (validAt && record.expiresAt <= validAt) return null;
    return record;
  }

  function assertAuthorizationClientEligible(client, scopes, redirectUri) {
    if (!client || client.status !== clients.STATUS.APPROVED) {
      throw accessDenied("This application is no longer permitted to sign users in");
    }
    if (!client.allowedGrantTypes.includes("authorization_code")) {
      throw accessDenied("This application is no longer permitted to use authorization codes");
    }
    if (!scopeRegistry.covers(client.allowedScopes, scopes)) {
      throw invalidScope("This application is no longer permitted to request one or more approved scopes");
    }
    try {
      clients.resolveRedirectUri(client, redirectUri);
    } catch {
      throw accessDenied("This application's callback is no longer registered");
    }
  }

  function assertTokenClientEligible(client, scopes, grantType, redirectUri = null) {
    if (
      !client ||
      client.status !== clients.STATUS.APPROVED ||
      !client.allowedGrantTypes.includes(grantType) ||
      !scopeRegistry.covers(client.allowedScopes, scopes)
    ) {
      throw invalidGrant("The authorization is no longer valid for this client");
    }
    if (redirectUri) {
      try {
        clients.resolveRedirectUri(client, redirectUri);
      } catch {
        throw invalidGrant("The authorization callback is no longer registered for this client");
      }
    }
  }

  function assertTokenAccountEligible(account, scopes) {
    if (!account || account.status === accounts.STATUS.DISABLED) {
      throw invalidGrant("That account is no longer available");
    }
    try {
      scopeRegistry.assertAllowedForUser(account, scopes);
    } catch {
      throw invalidGrant("The authorization is no longer permitted for this account");
    }
  }

  function scopesRemainAllowed(account, client, grant, scopes) {
    if (!account || account.status === accounts.STATUS.DISABLED) return false;
    if (!client || client.status !== clients.STATUS.APPROVED) return false;
    if (!scopeRegistry.covers(client.allowedScopes, scopes)) return false;
    if (!grant || grant.revokedAt || !scopeRegistry.covers(decodeScopes(grant.scopes), scopes)) return false;
    try {
      scopeRegistry.assertAllowedForUser(account, scopes);
      return true;
    } catch {
      return false;
    }
  }

  // --- Discovery -----------------------------------------------------------

  /**
   * OpenID Provider metadata (OIDC Discovery 1.0 section 3) served at
   * /.well-known/openid-configuration.
   *
   * A client library reads this to configure itself, so an inaccurate entry here
   * is worse than a missing feature: the client will attempt something the server
   * does not do. Every value is derived from what is actually implemented.
   */
  async function discoveryDocument() {
    const keyRing = await keys.ensureKeyRing();
    return {
      issuer,
      authorization_endpoint: endpoint("/oauth2/authorize"),
      token_endpoint: endpoint("/oauth2/token"),
      userinfo_endpoint: endpoint("/oauth2/userinfo"),
      jwks_uri: endpoint("/oauth2/jwks"),
      introspection_endpoint: endpoint("/oauth2/introspect"),
      revocation_endpoint: endpoint("/oauth2/revoke"),
      end_session_endpoint: endpoint("/oauth2/logout"),
      ...(clients.dynamicRegistrationEnabled
        ? { registration_endpoint: endpoint("/oauth2/register") }
        : {}),
      scopes_supported: scopeRegistry.supported,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      // Every algorithm in the key ring, so a client can verify a token signed
      // by any published key rather than only the active one.
      id_token_signing_alg_values_supported: keyRing.algorithms,
      userinfo_signing_alg_values_supported: ["none"],
      token_endpoint_auth_methods_supported: clients.supportedAuthMethods,
      claims_supported: scopeRegistry.claimsSupported,
      claims_parameter_supported: false,
      request_parameter_supported: false,
      request_uri_parameter_supported: false,
      // RFC 7636. Only S256: `plain` provides no protection against an
      // interception attack, so it is not offered.
      code_challenge_methods_supported: CODE_CHALLENGE_METHODS,
      // RFC 9207. The authorization response carries `iss`, and a client that
      // validates it needs to be told so: an RP that sees an unadvertised
      // parameter may reject the response, and one that is never told cannot
      // detect a mix-up attack it would otherwise catch.
      authorization_response_iss_parameter_supported: true,
      backchannel_logout_supported: true,
      backchannel_logout_session_supported: true,
      frontchannel_logout_supported: false,
      require_pkce: config?.security?.requirePkce !== false,
      service_documentation: config?.branding?.supportUrl || undefined,
      ui_locales_supported: ["en", "zh-CN"]
    };
  }

  /**
   * RFC 8414 authorization server metadata, at
   * /.well-known/oauth-authorization-server.
   *
   * Served as well as the OIDC document because a pure OAuth 2.0 client library
   * looks here and not at the OIDC path.
   */
  async function authorizationServerMetadata() {
    const document = await discoveryDocument();
    const { claims_supported: _claims, ...rest } = document;
    return rest;
  }

  async function jwks() {
    const keyRing = await keys.ensureKeyRing();
    return keyRing.jwks;
  }

  // --- Authorization request ----------------------------------------------

  /**
   * Parses and validates an authorization request.
   *
   * Errors split into two kinds, and getting the split wrong is a real
   * vulnerability. Until the client and its redirect_uri are both validated,
   * nothing may be reported by redirecting — that would be an open redirect.
   * Only after both check out can an error go back to the client per RFC 6749
   * section 4.1.2.1. `redirectValidated` on the result is what tells the caller
   * which mode it is in.
   */
  async function parseAuthorizationRequest(params = {}) {
    const clientId = String(params.client_id || "").trim();
    if (!clientId) throw invalidRequest("client_id is required");

    const client = await clients.requireActiveClient(clientId);
    // Throws rather than redirects: a redirect_uri that does not match cannot be
    // used to deliver the error.
    const redirectUri = clients.resolveRedirectUri(client, params.redirect_uri);

    // From here on, an error may be delivered to redirectUri.
    const context = { client, redirectUri, redirectValidated: true, state: null };

    try {
      context.state = optionalOpaque(params.state, "state");
      const nonce = optionalOpaque(params.nonce, "nonce");

      const responseType = String(params.response_type || "").trim();
      if (!responseType) throw invalidRequest("response_type is required");
      if (responseType !== "code") {
        // The implicit and hybrid flows put tokens in the browser's URL. Current
        // OAuth 2.0 Security BCP guidance is against them, so only `code` is
        // implemented rather than partially supported.
        throw unsupportedResponseType(`Unsupported response_type "${responseType}". Only "code" is supported.`);
      }
      clients.assertGrantAllowed(client, "authorization_code");

      const parsedScopes = scopeRegistry.parse(params.scope);
      const granted = clients.filterScopes(client, parsedScopes.granted);
      // A request that names only scopes this client cannot have is an error; a
      // request that names some it cannot have proceeds with the rest, and the
      // token response reports what was actually granted.
      if (!granted.length) {
        throw invalidScope(
          parsedScopes.requested.length
            ? "None of the requested scopes are available to this client"
            : "scope is required"
        );
      }

      const isOidc = granted.includes("openid");
      if (isOidc && requireNonce && !nonce) {
        throw invalidRequest("nonce is required for an OpenID Connect request on this server");
      }

      const pkce = parsePkce(params, { client });
      const prompts = parsePrompt(params.prompt);
      const maxAge = parseMaxAge(params.max_age);

      return {
        ...context,
        responseType,
        scopes: granted,
        requestedScopes: parsedScopes.requested,
        unknownScopes: parsedScopes.unknown,
        isOidc,
        state: context.state,
        nonce,
        codeChallenge: pkce.challenge,
        codeChallengeMethod: pkce.method,
        prompts,
        maxAge,
        loginHint: String(params.login_hint || "").trim().slice(0, 254) || null,
        idTokenHint: String(params.id_token_hint || "").trim() || null
      };
    } catch (error) {
      // Attach what the caller needs to deliver this as a redirect.
      error.redirectUri = redirectUri;
      error.state = context.state;
      error.redirectValidated = true;
      throw error;
    }
  }

  /**
   * PKCE (RFC 7636).
   *
   * Mandatory for a public client always, and for a confidential client when
   * configured — which is the default, following current OAuth 2.0 Security BCP
   * guidance that PKCE applies to all clients rather than only public ones.
   */
  function parsePkce(params, { client }) {
    const challenge = String(params.code_challenge || "").trim();
    const method = String(params.code_challenge_method || "").trim() || (challenge ? "S256" : "");

    if (!challenge) {
      if (client.requiresPkce) {
        throw invalidRequest(
          client.isPublic
            ? "code_challenge is required: a public client must use PKCE"
            : "code_challenge is required on this server"
        );
      }
      return { challenge: null, method: null };
    }

    if (!CODE_CHALLENGE_METHODS.includes(method)) {
      throw invalidRequest(`code_challenge_method must be S256`);
    }
    // A base64url SHA-256 digest is exactly 43 characters. Checking the shape
    // here turns a silent later mismatch into an immediate, diagnosable error.
    if (!/^[A-Za-z0-9\-._~]{43}$/.test(challenge)) {
      throw invalidRequest("code_challenge is not a valid S256 challenge");
    }
    return { challenge, method };
  }

  /**
   * Parks a validated authorization request and returns the opaque token that
   * identifies it through login and consent. Only its hash is stored.
   */
  async function persistAuthorizationRequest(request) {
    const token = randomToken();
    await prisma.authorizationRequest.create({
      data: {
        id: randomId(),
        requestTokenHash: hashToken(token),
        clientId: request.client.clientId,
        redirectUri: request.redirectUri,
        responseType: request.responseType,
        state: request.state,
        nonce: request.nonce,
        codeChallenge: request.codeChallenge,
        codeChallengeMethod: request.codeChallengeMethod,
        scopes: encodeScopes(request.scopes),
        prompt: request.prompts.join(" "),
        maxAge: request.maxAge,
        loginHint: request.loginHint,
        expiresAt: new Date(now().getTime() + ttl.authorizationRequestSeconds * 1000)
      }
    });
    return token;
  }

  async function loadAuthorizationRequest(token) {
    const raw = String(token || "").trim();
    if (!raw) return null;
    const record = await prisma.authorizationRequest.findUnique({
      where: { requestTokenHash: hashToken(raw) }
    });
    if (!record || record.consumedAt || record.expiresAt <= now()) return null;

    const client = await clients.findByClientId(record.clientId);
    if (!client || client.status !== clients.STATUS.APPROVED) return null;

    return {
      id: record.id,
      client,
      redirectUri: record.redirectUri,
      responseType: record.responseType,
      state: record.state,
      nonce: record.nonce,
      codeChallenge: record.codeChallenge,
      codeChallengeMethod: record.codeChallengeMethod,
      scopes: decodeScopes(record.scopes),
      prompts: decodeScopes(record.prompt),
      maxAge: record.maxAge,
      loginHint: record.loginHint,
      expiresAt: record.expiresAt,
      // When the request was parked. `resolveAuthorization` compares it against
      // the session's `authTime` to tell a session the user just re-established
      // from the one they arrived with — which is the only thing that makes
      // `prompt=login` terminate.
      createdAt: record.createdAt
    };
  }

  /**
   * Decides what has to happen before a code can be issued: authenticate,
   * ask for consent, or neither.
   */
  async function resolveAuthorization({ request, account, session }) {
    const prompts = request.prompts || [];

    if (!account || !session) {
      // prompt=none means the client wants no user interaction, so an
      // unauthenticated user is reported as `login_required` rather than shown a
      // login page (OIDC Core section 3.1.2.6).
      if (prompts.includes("none")) throw loginRequired("The user is not signed in");
      return { action: "login", reason: "no_session" };
    }

    if (account.status === accounts.STATUS.DISABLED) {
      throw accessDenied("That account has been disabled");
    }

    // Whether the user authenticated *for this request* rather than before it.
    //
    // Without this distinction `prompt=login` cannot terminate. The demand lives
    // in the stored request, so re-reading it after the login page yields the
    // same answer as before — the user signs in, comes back to
    // /oauth2/authorize/continue, is sent to /login again, and because a session
    // now exists the login page redirects straight back. That is a redirect loop
    // the browser ends with ERR_TOO_MANY_REDIRECTS, and `prompt=login` is how a
    // relying party forces re-authentication before a sensitive operation, so it
    // fails the whole authorization rather than degrading to "ignored".
    //
    // A request only carries `createdAt` once it has been parked, which is
    // exactly the first pass through: no timestamp means the user has not been
    // asked yet, so the demand stands.
    const reauthenticated =
      Boolean(request.createdAt) && session.authTime.getTime() > new Date(request.createdAt).getTime();

    // prompt=login forces re-authentication even for an active session.
    if (prompts.includes("login") && !reauthenticated) {
      return { action: "login", reason: "prompt_login" };
    }

    // max_age caps how long ago authentication may have happened. The same guard
    // applies, and for the same reason: `max_age=0` is satisfiable only at the
    // instant of login, so comparing elapsed time alone sends a user who has
    // just authenticated back to authenticate again, forever.
    //
    // The trade-off, stated rather than left implicit: a user who authenticated
    // *for this request* is accepted even if they then took longer to come back
    // than `max_age` allows. The window is bounded by the request's own TTL
    // (`OAUTH_AUTHORIZATION_REQUEST_TTL`, 600s by default, 3600s at most), after
    // which the parked request no longer loads at all. Refusing instead would
    // make `max_age=0` — which clients send to mean "re-authenticate now" —
    // impossible to satisfy, since any round trip through the login page takes
    // longer than zero seconds.
    if (request.maxAge !== null && request.maxAge !== undefined && !reauthenticated) {
      const age = (now().getTime() - session.authTime.getTime()) / 1000;
      if (age > request.maxAge) {
        if (prompts.includes("none")) throw loginRequired("The session is older than max_age");
        return { action: "login", reason: "max_age" };
      }
    }

    // A scope the account may not authorize at all (e.g. an admin-only scope on a
    // non-admin account) is refused before consent is asked for.
    scopeRegistry.assertAllowedForUser(account, request.scopes);

    const grant = await findActiveGrant({ userId: account.id, clientId: request.client.clientId });
    const grantedScopes = grant ? decodeScopes(grant.scopes) : [];
    const missing = scopeRegistry.beyond(grantedScopes, request.scopes);

    const consentForced = prompts.includes("consent");
    // A client configured not to require consent — a first-party application the
    // deployment already trusts — skips the screen entirely, and only an explicit
    // `prompt=consent` overrides that. For every other client the screen appears
    // the first time and again whenever the request reaches past what the stored
    // grant covers, so widening a grant is always something the user agreed to.
    const needsConsent =
      consentForced || (request.client.requireConsent && (!grant || missing.length > 0));

    if (needsConsent) {
      if (prompts.includes("none")) {
        throw consentRequired("This request needs the user's consent");
      }
      return { action: "consent", reason: consentForced ? "prompt_consent" : "scopes", missing };
    }

    return { action: "issue", reason: null, grant };
  }

  async function findActiveGrant({ userId, clientId }) {
    return prisma.grant.findFirst({
      where: { userId, clientId, revokedAt: null }
    });
  }

  /**
   * Records or widens the user's decision to trust a client.
   *
   * Read, merge, write — which is a race, and one SQLite hid. Prisma opens a
   * single connection to it and the whole application is one writer, so two
   * consents arriving together were serialised into correctness. PostgreSQL has
   * no such funnel, and `grants` carries @@unique([userId, clientId]): two tabs
   * finishing consent at the same moment both found no row, both inserted, and
   * the loser got an unhandled P2002. oauthController only redirects an error
   * it recognises as a protocol error, so a raw `{"error":"server_error"}`
   * appeared in the browser.
   *
   * The other half was quieter. Two widenings that both found the same existing
   * row each wrote their own merge over it, and whichever landed second won
   * outright — one tab granting `profile` and another granting `email` left the
   * user with one of them and no indication the other was dropped.
   *
   * So: compare-and-swap on `version`, which the column already existed for.
   * A write that finds the version it read has moved re-reads and merges on top
   * of the winner rather than over it, and an insert that loses the unique
   * constraint becomes a widening of the row that beat it. Both halves converge
   * on the union, which is what the user actually agreed to.
   */
  async function upsertGrant({ userId, clientId, scopes, database = prisma }) {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const existing = await database.grant.findUnique({
        where: { userId_clientId: { userId, clientId } }
      });
      const merged = scopeRegistry.sort([
        ...(existing && !existing.revokedAt ? decodeScopes(existing.scopes) : []),
        ...scopes
      ]);

      if (!existing) {
        try {
          return await database.grant.create({
            data: { id: randomId(), userId, clientId, scopes: encodeScopes(merged) }
          });
        } catch (error) {
          // P2002 is Prisma's unique-constraint violation: someone inserted the
          // row between the read above and this write. Their scopes are now the
          // ones to merge on top of, so go round again rather than fail.
          if (error?.code !== "P2002") throw error;
          continue;
        }
      }

      const claimed = await database.grant.updateMany({
        where: { id: existing.id, version: existing.version },
        data: {
          scopes: encodeScopes(merged),
          revokedAt: null,
          // The version increments on every change, so a stored grant can be
          // told apart from the one a token was issued under — and so this
          // update can tell whether it is writing over what it read.
          version: existing.version + 1
        }
      });
      if (claimed.count) {
        return database.grant.findUnique({ where: { id: existing.id } });
      }
    }

    // Four consecutive losses means sustained contention on one (user, client)
    // pair, which no real consent flow produces. Failing is better than looping.
    throw new Error("The grant could not be recorded because it was being changed concurrently");
  }

  /**
   * Issues an authorization code and marks the request consumed, so one
   * authorization request can never yield two codes.
   */
  async function issueCode({ request, account, session, scopes, explicitConsent }) {
    const code = randomToken();
    const consumedAt = now();
    const issued = await prisma.$transaction(async (database) => {
      const currentClient = await lockClient(database, request.client.clientId);
      assertAuthorizationClientEligible(currentClient, scopes, request.redirectUri);

      const currentAccount = await lockUser(database, account?.id);
      if (!currentAccount || currentAccount.status === accounts.STATUS.DISABLED) {
        throw accessDenied("That account is no longer available");
      }
      scopeRegistry.assertAllowedForUser(currentAccount, scopes);

      let grant = await lockGrant(database, {
        userId: currentAccount.id,
        clientId: currentClient.clientId
      });
      if (explicitConsent || !currentClient.requireConsent) {
        grant = await upsertGrant({
          userId: currentAccount.id,
          clientId: currentClient.clientId,
          scopes,
          database
        });
      }
      if (!grant || grant.revokedAt || !scopeRegistry.covers(decodeScopes(grant.scopes), scopes)) {
        throw accessDenied("Access for this application is no longer authorized");
      }

      const browserSession = await lockBrowserSession(database, {
        sessionId: session?.id,
        userId: currentAccount.id,
        validAt: consumedAt
      });
      if (!browserSession) {
        throw accessDenied("The signed-in browser session is no longer available");
      }

      const consumed = await database.authorizationRequest.updateMany({
        where: { id: request.id, consumedAt: null, expiresAt: { gt: consumedAt } },
        data: { consumedAt }
      });
      if (!consumed.count) {
        throw invalidRequest("This authorization request has expired or already been completed");
      }

      // The per-client session view backs `sid`, session status, and
      // back-channel logout fan-out.
      const established = await database.oidcSession.upsert({
        where: {
          sessionId_clientId: { sessionId: browserSession.id, clientId: currentClient.clientId }
        },
        create: {
          id: randomId(),
          sessionId: browserSession.id,
          clientId: currentClient.clientId,
          userId: currentAccount.id,
          authTime: browserSession.createdAt,
          lastSeenAt: consumedAt
        },
        update: {
          userId: currentAccount.id,
          authTime: browserSession.createdAt,
          lastSeenAt: consumedAt,
          revokedAt: null,
          revocationReason: null
        }
      });

      await database.authorizationCode.create({
        data: {
          id: randomId(),
          codeHash: hashToken(code),
          clientId: currentClient.clientId,
          redirectUri: request.redirectUri,
          nonce: request.nonce,
          codeChallenge: request.codeChallenge,
          codeChallengeMethod: request.codeChallengeMethod,
          scopes: encodeScopes(scopes),
          userId: currentAccount.id,
          sessionId: browserSession.id,
          authTime: browserSession.createdAt,
          expiresAt: new Date(consumedAt.getTime() + ttl.authorizationCodeSeconds * 1000)
        }
      });
      return { oidcSession: established, account: currentAccount, client: currentClient };
    });

    await auditLog?.record({
      action: "oauth.code.issued",
      actorUserId: issued.account.id,
      targetType: "client",
      targetId: issued.client.clientId,
      metadata: { scopes, sid: issued.oidcSession.id }
    });

    const redirect = new URL(request.redirectUri);
    redirect.searchParams.set("code", code);
    if (request.state) redirect.searchParams.set("state", request.state);
    // OIDC Core section 3.1.3.7 note: `iss` in the response lets a client with
    // several issuers tell which one answered (RFC 9207), defending against
    // mix-up attacks.
    redirect.searchParams.set("iss", issuer);

    return { redirectUrl: redirect.toString() };
  }

  /** Completes an authorization after login and, if needed, consent. */
  async function completeAuthorization({ requestToken, account, session, approvedScopes = null }) {
    const request = await loadAuthorizationRequest(requestToken);
    if (!request) throw invalidRequest("This sign-in request has expired. Start again from the application.");

    const explicitConsent = approvedScopes !== null;
    const scopes = explicitConsent
      ? scopeRegistry.sort(request.scopes.filter((scope) => approvedScopes.includes(scope)))
      : request.scopes;

    // `openid` is not a permission the user can decline separately — it only
    // means "issue an ID token" — so it rides along whenever it was requested.
    if (request.scopes.includes("openid") && !scopes.includes("openid")) scopes.unshift("openid");

    if (!scopes.length) {
      return {
        redirectUrl: buildErrorRedirect(request.redirectUri, {
          error: "access_denied",
          errorDescription: "The user declined the request",
          state: request.state,
          issuer
        })
      };
    }

    scopeRegistry.assertAllowedForUser(account, scopes);
    return issueCode({ request, account, session, scopes, explicitConsent });
  }

  /** Records the user's refusal as an `access_denied` redirect (RFC 6749 4.1.2.1). */
  async function denyAuthorization({ requestToken }) {
    const request = await loadAuthorizationRequest(requestToken);
    if (!request) throw invalidRequest("This sign-in request has expired");
    const claimTime = now();
    const consumed = await prisma.authorizationRequest.updateMany({
      where: { id: request.id, consumedAt: null, expiresAt: { gt: claimTime } },
      data: { consumedAt: claimTime }
    });
    if (!consumed.count) {
      throw invalidRequest("This sign-in request has expired or already been completed");
    }
    return {
      redirectUrl: buildErrorRedirect(request.redirectUri, {
        error: "access_denied",
        errorDescription: "The user declined the request",
        state: request.state,
        issuer
      })
    };
  }

  // --- Token endpoint ------------------------------------------------------

  async function token({ headers, body }) {
    const grantType = String(body?.grant_type || "").trim();
    if (!grantType) throw invalidRequest("grant_type is required");

    const { client } = await clients.authenticate({ headers, body });

    if (grantType === "authorization_code") {
      clients.assertGrantAllowed(client, "authorization_code");
      return exchangeAuthorizationCode({ client, body });
    }
    if (grantType === "refresh_token") {
      clients.assertGrantAllowed(client, "refresh_token");
      return exchangeRefreshToken({ client, body });
    }
    throw unsupportedGrantType(`Unsupported grant_type "${grantType}"`);
  }

  /**
   * The authorization code grant (RFC 6749 section 4.1.3).
   *
   * A code is single-use. Redemption is a conditional update scoped to
   * `usedAt: null`, so two concurrent requests cannot both succeed — the check
   * and the claim are one atomic operation rather than a read followed by a
   * write.
   */
  async function exchangeAuthorizationCode({ client, body }) {
    const code = String(body.code || "").trim();
    if (!code) throw invalidRequest("code is required");

    const record = await prisma.authorizationCode.findUnique({ where: { codeHash: hashToken(code) } });
    // A code that does not exist, belongs to another client, or has expired is
    // one error: `invalid_grant`. Distinguishing them would tell an attacker
    // which codes were real.
    if (!record) throw invalidGrant("The authorization code is not valid");

    if (!safeEqual(record.clientId, client.clientId)) {
      // A code issued to one client being redeemed by another is a serious
      // signal, so the code is burned rather than merely refused.
      await prisma.authorizationCode.updateMany({
        where: { id: record.id, usedAt: null },
        data: { usedAt: now() }
      });
      await auditLog?.record({
        action: "oauth.code.wrong_client",
        targetType: "client",
        targetId: client.clientId,
        metadata: { issuedTo: record.clientId }
      });
      throw invalidGrant("The authorization code is not valid");
    }

    // A code is discovered spent in two places, and both mean the same thing.
    //
    // This one is the pre-read: the row already had `usedAt` before we touched
    // it. The other is the conditional update further down, which is what
    // actually makes redemption single-use. Only this branch used to revoke and
    // audit, and the two are reached by different callers: a client redeeming a
    // code twice in sequence arrives here, while an attacker racing the real
    // client with a stolen code arrives at the other one — both requests read
    // `usedAt: null`, one update wins, and the loser used to get a bare
    // `invalid_grant`. Racing is the natural way to use a stolen code, so the
    // detection was absent from exactly the case it exists for.
    //
    // The cost of treating a client's own duplicate submission as theft is
    // accepted here for the same reason it is accepted for refresh-token
    // families: a code presented twice cannot be told apart from a code that
    // leaked, and guessing wrong in the other direction leaves the attacker
    // holding live tokens.
    const refuseAsReplay = async () => {
      // The code is gone, but a token issued from its first use may still be
      // live, so every token descended from it is revoked.
      await revokeTokensForSession({
        sessionId: record.sessionId,
        clientId: client.clientId,
        userId: record.userId,
        reason: "code_replay"
      });
      await auditLog?.record({
        action: "oauth.code.replayed",
        actorUserId: record.userId,
        targetType: "client",
        targetId: client.clientId
      });
      return invalidGrant("The authorization code has already been used");
    };

    if (record.usedAt) {
      throw await refuseAsReplay();
    }

    if (record.expiresAt <= now()) throw invalidGrant("The authorization code has expired");

    // RFC 6749 section 4.1.3: redirect_uri must be present and identical to the
    // one from the authorization request.
    const presentedRedirect = String(body.redirect_uri || "").trim();
    if (!presentedRedirect || !safeEqual(presentedRedirect, record.redirectUri)) {
      throw invalidGrant("redirect_uri does not match the authorization request");
    }

    verifyPkce({ record, body, client });

    // Resolve the key before opening the database transaction. A generated key
    // may itself need the database on first boot, and nested work through the
    // root client would defeat the atomic state transition below.
    await keys.ensureKeyRing();

    const issuedAt = now();
    const accessTokenId = randomId();
    const scopes = decodeScopes(record.scopes);
    let account;
    let issuedClient;
    let response;
    try {
      response = await prisma.$transaction(async (database) => {
        issuedClient = await lockClient(database, client.clientId);
        assertTokenClientEligible(issuedClient, scopes, "authorization_code", record.redirectUri);
        verifyPkce({ record, body, client: issuedClient });

        account = await lockUser(database, record.userId);
        assertTokenAccountEligible(account, scopes);

        const grant = await lockGrant(database, {
          userId: record.userId,
          clientId: issuedClient.clientId
        });
        if (!grant || grant.revokedAt || !scopeRegistry.covers(decodeScopes(grant.scopes), scopes)) {
          throw invalidGrant("Access for this application has been revoked");
        }

        // Claiming the code and storing every token derived from it are one
        // transition. A database error therefore leaves the code retryable.
        const claimed = await database.authorizationCode.updateMany({
          where: { id: record.id, usedAt: null, expiresAt: { gt: issuedAt } },
          data: { usedAt: issuedAt }
        });
        if (!claimed.count) {
          const current = await database.authorizationCode.findUnique({ where: { id: record.id } });
          if (current?.usedAt) throw new CodeReplayDetected();
          throw invalidGrant("The authorization code has expired");
        }

        const session = await database.oidcSession.findUnique({
          where: {
            sessionId_clientId: { sessionId: record.sessionId, clientId: issuedClient.clientId }
          }
        });
        if (!session || session.revokedAt) throw invalidGrant("That session has been ended");

        return issueTokens({
          client: issuedClient,
          account,
          scopes,
          sessionId: record.sessionId,
          sid: session.id,
          authTime: record.authTime,
          nonce: record.nonce,
          database,
          issuedAt,
          accessTokenId,
          recordAudit: false
        });
      });
    } catch (error) {
      if (!(error instanceof CodeReplayDetected)) throw error;
      throw await refuseAsReplay();
    }

    await recordTokenIssued({
      client: issuedClient,
      account,
      scopes,
      refreshed: false,
      accessTokenId
    });
    return response;
  }

  /**
   * Verifies the PKCE code_verifier (RFC 7636 section 4.6).
   *
   * The verifier is compared by recomputing the challenge, so the verifier itself
   * was never stored. A code issued with a challenge must be redeemed with a
   * verifier — omitting it cannot be allowed to bypass the check, which is the
   * PKCE downgrade attack.
   */
  function verifyPkce({ record, body, client }) {
    const verifier = String(body.code_verifier || "").trim();

    if (!record.codeChallenge) {
      if (verifier) throw invalidGrant("This authorization code was not issued with PKCE");
      if (client.requiresPkce) throw invalidGrant("PKCE is required for this client");
      return;
    }
    if (!verifier) throw invalidGrant("code_verifier is required");
    // RFC 7636 section 4.1 fixes the length at 43–128 characters.
    if (verifier.length < 43 || verifier.length > 128) {
      throw invalidGrant("code_verifier must be between 43 and 128 characters");
    }
    if (!/^[A-Za-z0-9\-._~]+$/.test(verifier)) {
      throw invalidGrant("code_verifier contains an invalid character");
    }
    if (!safeEqual(s256Challenge(verifier), record.codeChallenge)) {
      throw invalidGrant("code_verifier does not match the code_challenge");
    }
  }

  /**
   * The refresh token grant (RFC 6749 section 6).
   *
   * With rotation on — the default — each use issues a new token and retires the
   * old one. Presenting an already-rotated token means either a leak or a race;
   * the whole family is revoked, per OAuth 2.0 Security BCP guidance. That does
   * log out a client that genuinely raced, and detecting theft is worth it.
   */
  async function exchangeRefreshToken({ client, body }) {
    const presented = String(body.refresh_token || "").trim();
    if (!presented) throw invalidRequest("refresh_token is required");

    const record = await prisma.refreshToken.findUnique({ where: { tokenHash: hashToken(presented) } });
    if (!record) throw invalidGrant("The refresh token is not valid");

    if (!safeEqual(record.clientId, client.clientId)) {
      await revokeFamily(record.familyId, "wrong_client");
      throw invalidGrant("The refresh token is not valid");
    }

    if (record.revokedAt || (rotateRefreshTokens && record.usedAt)) {
      await revokeFamily(record.familyId, "refresh_replay");
      await auditLog?.record({
        action: "oauth.refresh.replayed",
        actorUserId: record.userId,
        targetType: "client",
        targetId: client.clientId,
        metadata: { familyId: record.familyId }
      });
      throw invalidGrant("The refresh token has been revoked");
    }

    if (record.expiresAt <= now()) throw invalidGrant("The refresh token has expired");

    let scopes = decodeScopes(record.scopes);
    // RFC 6749 section 6: the requested scope must not exceed what was granted.
    if (body.scope) {
      const requested = scopeRegistry.parse(body.scope, { strict: true }).granted;
      if (!scopeRegistry.covers(scopes, requested)) {
        throw invalidScope("The requested scope exceeds the scope of the original grant");
      }
      scopes = requested;
    }

    const tokenArgs = {
      scopes,
      sessionId: record.sessionId,
      authTime: record.authTime,
      // No `nonce` on a refresh: OIDC Core section 12.2 says an ID token issued
      // from a refresh must not carry the original nonce.
      nonce: null,
      familyId: record.familyId,
      parentTokenId: record.id
    };

    if (!rotateRefreshTokens) {
      // RFC 6749 makes a replacement refresh token optional. Reuse the
      // presented token in this compatibility mode instead of minting an
      // unbounded tree of live siblings on every exchange.
      //
      // The original row still has to participate in the transaction. Without
      // the conditional update below, RFC 7009 revocation can commit after the
      // pre-read above but before token issuance, and this request would return
      // a new access token from an already-revoked refresh token. Writing the
      // unchanged expiry acquires the row lock without rotating or extending
      // the credential.
      await keys.ensureKeyRing();
      const issuedAt = now();
      const accessTokenId = randomId();
      let issuedAccount;
      let issuedClient;
      let response;
      try {
        response = await prisma.$transaction(async (database) => {
          issuedClient = await lockClient(database, client.clientId);
          try {
            assertTokenClientEligible(issuedClient, scopes, "refresh_token");
          } catch (error) {
            throw new RefreshStateRejected("client_changed", error);
          }

          issuedAccount = await lockUser(database, record.userId);
          try {
            assertTokenAccountEligible(issuedAccount, scopes);
          } catch (error) {
            throw new RefreshStateRejected("account_unavailable", error);
          }

          const currentGrant = await lockGrant(database, {
            userId: record.userId,
            clientId: issuedClient.clientId
          });
          if (
            !currentGrant ||
            currentGrant.revokedAt ||
            !scopeRegistry.covers(decodeScopes(currentGrant.scopes), scopes)
          ) {
            throw new RefreshStateRejected(
              "grant_revoked",
              invalidGrant("Access for this application has been revoked")
            );
          }

          const locked = await database.refreshToken.updateMany({
            where: {
              id: record.id,
              usedAt: null,
              revokedAt: null,
              expiresAt: { gt: issuedAt }
            },
            data: { expiresAt: record.expiresAt }
          });
          if (!locked.count) {
            throw new RefreshStateRejected(
              "refresh_revoked",
              invalidGrant("The refresh token has been revoked")
            );
          }

          const currentSession = await database.oidcSession.findUnique({
            where: {
              sessionId_clientId: { sessionId: record.sessionId, clientId: issuedClient.clientId }
            }
          });
          if (!currentSession || currentSession.revokedAt) {
            throw new RefreshStateRejected("session_ended", invalidGrant("That session has been ended"));
          }

          return issueTokens({
            ...tokenArgs,
            client: issuedClient,
            account: issuedAccount,
            sid: currentSession.id,
            database,
            issuedAt,
            accessTokenId,
            recordAudit: false,
            issueRefreshToken: false
          });
        });
      } catch (error) {
        if (!(error instanceof RefreshStateRejected)) throw error;
        if (error.reason !== "refresh_revoked") {
          await revokeFamily(record.familyId, error.reason);
        }
        throw error.protocolError;
      }

      await recordTokenIssued({
        client: issuedClient,
        account: issuedAccount,
        scopes,
        refreshed: true,
        accessTokenId
      });
      return response;
    }

    // Retiring the presented token and storing its replacement are one state
    // transition. Otherwise a database error between the two writes makes a
    // legitimate retry look like theft and revokes the whole token family.
    await keys.ensureKeyRing();
    const issuedAt = now();
    const accessTokenId = randomId();
    let issuedAccount;
    let issuedClient;
    let response;
    try {
      response = await prisma.$transaction(async (database) => {
        issuedClient = await lockClient(database, client.clientId);
        try {
          assertTokenClientEligible(issuedClient, scopes, "refresh_token");
        } catch (error) {
          throw new RefreshStateRejected("client_changed", error);
        }

        issuedAccount = await lockUser(database, record.userId);
        try {
          assertTokenAccountEligible(issuedAccount, scopes);
        } catch (error) {
          throw new RefreshStateRejected("account_unavailable", error);
        }

        const currentGrant = await lockGrant(database, {
          userId: record.userId,
          clientId: issuedClient.clientId
        });
        if (
          !currentGrant ||
          currentGrant.revokedAt ||
          !scopeRegistry.covers(decodeScopes(currentGrant.scopes), scopes)
        ) {
          throw new RefreshStateRejected(
            "grant_revoked",
            invalidGrant("Access for this application has been revoked")
          );
        }

        const claimed = await database.refreshToken.updateMany({
          where: { id: record.id, usedAt: null, revokedAt: null, expiresAt: { gt: issuedAt } },
          data: { usedAt: issuedAt }
        });
        if (!claimed.count) throw new RefreshReplayDetected();

        const currentSession = await database.oidcSession.findUnique({
          where: {
            sessionId_clientId: { sessionId: record.sessionId, clientId: issuedClient.clientId }
          }
        });
        if (!currentSession || currentSession.revokedAt) {
          throw new RefreshStateRejected("session_ended", invalidGrant("That session has been ended"));
        }

        return issueTokens({
          ...tokenArgs,
          client: issuedClient,
          account: issuedAccount,
          sid: currentSession.id,
          database,
          issuedAt,
          accessTokenId,
          recordAudit: false
        });
      });
    } catch (error) {
      if (error instanceof RefreshStateRejected) {
        await revokeFamily(record.familyId, error.reason);
        throw error.protocolError;
      }
      if (!(error instanceof RefreshReplayDetected)) throw error;
      await revokeFamily(record.familyId, "refresh_replay");
      await auditLog?.record({
        action: "oauth.refresh.replayed",
        actorUserId: record.userId,
        targetType: "client",
        targetId: client.clientId,
        metadata: { familyId: record.familyId }
      });
      throw invalidGrant("The refresh token has been revoked");
    }

    await recordTokenIssued({
      client: issuedClient,
      account: issuedAccount,
      scopes,
      refreshed: true,
      accessTokenId
    });
    return response;
  }

  async function recordTokenIssued({ client, account, scopes, refreshed, accessTokenId }) {
    await auditLog?.record({
      action: "oauth.token.issued",
      actorUserId: account.id,
      targetType: "client",
      targetId: client.clientId,
      metadata: { scopes, refreshed, jti: accessTokenId }
    });
  }

  /**
   * Mints the token response.
   *
   * The access token is a JWT so a resource server can validate it offline
   * against JWKS. It carries `token_use: "access"` and the ID token
   * `token_use: "id"`, so neither can be presented where the other is expected —
   * a confusion that has caused real vulnerabilities.
   */
  async function issueTokens({
    client,
    account,
    scopes,
    sessionId,
    sid,
    authTime,
    nonce,
    familyId = null,
    parentTokenId = null,
    database = prisma,
    issuedAt = now(),
    accessTokenId = randomId(),
    recordAudit = true,
    issueRefreshToken = true
  }) {
    const keyRing = await keys.ensureKeyRing();
    const issuedAtSeconds = epoch(issuedAt);

    const accessToken = signJwt({
      key: keyRing.activeKey,
      claims: {
        iss: issuer,
        sub: account.id,
        // The audience of an access token is the resource server. With no
        // resource indicators (RFC 8707) configured, the issuer is the audience
        // and `client_id` identifies the presenter.
        aud: issuer,
        client_id: client.clientId,
        iat: issuedAtSeconds,
        exp: issuedAtSeconds + ttl.accessTokenSeconds,
        jti: accessTokenId,
        scope: scopes.join(" "),
        sid,
        token_use: "access"
      }
    });

    const response = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ttl.accessTokenSeconds,
      // Always reported, because it may differ from what was requested. RFC 6749
      // section 5.1 requires it in that case, and sending it always means a
      // client never has to guess.
      scope: scopes.join(" ")
    };

    if (scopes.includes("openid")) {
      response.id_token = await buildIdToken({
        client,
        account,
        scopes,
        sid,
        authTime,
        nonce,
        accessToken,
        issuedAt
      });
    }

    // OIDC Core section 11: a refresh token is issued when the user granted
    // `offline_access`. A first-party client may be configured to receive one
    // without it, which is a deployment's choice about its own applications.
    const wantsRefresh =
      client.allowedGrantTypes.includes("refresh_token") &&
      (scopes.includes("offline_access") || (client.isFirstParty && !scopes.includes("openid")));

    if (wantsRefresh && issueRefreshToken) {
      const refreshToken = randomToken();
      const family = familyId || randomId();
      await database.refreshToken.create({
        data: {
          id: randomId(),
          tokenHash: hashToken(refreshToken),
          familyId: family,
          parentTokenId,
          clientId: client.clientId,
          userId: account.id,
          sessionId,
          scopes: encodeScopes(scopes),
          authTime,
          expiresAt: new Date(issuedAt.getTime() + ttl.refreshTokenSeconds * 1000)
        }
      });
      response.refresh_token = refreshToken;
    }

    const touchedSession = await database.oidcSession.updateMany({
      where: { id: sid, sessionId, clientId: client.clientId, revokedAt: null },
      data: { lastSeenAt: issuedAt }
    });
    if (touchedSession.count !== 1) throw invalidGrant("That session has been ended");

    if (recordAudit) {
      await recordTokenIssued({
        client,
        account,
        scopes,
        refreshed: Boolean(parentTokenId),
        accessTokenId
      });
    }

    return response;
  }

  /**
   * Builds the ID token (OIDC Core section 2).
   *
   * `at_hash` binds the ID token to the access token issued with it, per section
   * 3.1.3.6; `azp` is included when the audience could be read as more than the
   * client, per 3.1.3.7.
   */
  async function buildIdToken({ client, account, scopes, sid, authTime, nonce, accessToken, issuedAt }) {
    const keyRing = await keys.ensureKeyRing();
    const issuedAtSeconds = epoch(issuedAt);
    const claims = {
      iss: issuer,
      sub: account.id,
      aud: client.clientId,
      azp: client.clientId,
      iat: issuedAtSeconds,
      exp: issuedAtSeconds + ttl.idTokenSeconds,
      auth_time: epoch(authTime),
      sid,
      token_use: "id",
      at_hash: leftHalfHash(accessToken, keyRing.activeKey.alg),
      ...(nonce ? { nonce } : {}),
      ...buildUserClaims({ account, scopes })
    };
    return signJwt({ key: keyRing.activeKey, claims });
  }

  /**
   * Resolves the standard OIDC claims for an account, then lets the registry add
   * whatever a deployment's custom scopes define. The standard set is fixed here;
   * everything deployment-specific arrives through configuration.
   */
  function buildUserClaims({ account, scopes }) {
    const baseClaims = {
      name: account.name,
      // OIDC calls this value "preferred", not unique. An externally linked
      // account can therefore preserve its upstream display username without
      // using that value as the local account-binding key.
      preferred_username: account.username || account.attributes?.external_preferred_username || null,
      picture: account.picture,
      email: account.email,
      email_verified: account.emailVerified,
      updated_at: account.updatedAt ? epoch(account.updatedAt) : undefined
    };
    // A synthesized placeholder address must not be presented as the user's
    // email. RFC 2606 reserves `.invalid` precisely so it can never resolve.
    if (baseClaims.email && baseClaims.email.endsWith("@external.invalid")) {
      baseClaims.email = null;
      baseClaims.email_verified = false;
    }
    return scopeRegistry.claimsFor({ user: account, scopes, baseClaims });
  }

  // --- UserInfo ------------------------------------------------------------

  /**
   * The UserInfo endpoint (OIDC Core section 5.3).
   *
   * `sub` is always present. Section 5.3.2 requires it, and a client library is
   * told to verify that it matches the ID token's `sub` — so omitting it, as the
   * previous implementation did, breaks conformant clients outright.
   */
  async function userinfo({ accessToken }) {
    const verified = await verifyAccessToken(accessToken);
    const scopes = decodeScopes(verified.claims.scope);
    if (!verified.claims.scope || !scopes.includes("openid")) {
      // Section 5.3.1: UserInfo requires an access token issued with `openid`.
      throw invalidToken("This access token was not issued with the openid scope");
    }

    const currentClient = await clients.findByClientId(verified.claims.client_id);
    const account = await accounts.findById(verified.claims.sub);
    const grant = currentClient
      ? await prisma.grant.findUnique({
          where: {
            userId_clientId: { userId: verified.claims.sub, clientId: currentClient.clientId }
          }
        })
      : null;
    if (!scopesRemainAllowed(account, currentClient, grant, scopes)) {
      throw invalidToken("This access token is no longer authorized");
    }

    // The same three lines introspection already had.
    //
    // An access token is a self-contained JWT, so a resource server validating
    // it offline cannot know it was revoked — that is an honest trade-off and
    // the README says so. This endpoint is not that: it belongs to the issuer,
    // it is already reading the database for the account, and `sid` is sitting
    // in the claims it just verified. Without the check, a user who ends a
    // session from /account is told the device is signed out while the token
    // taken from it keeps returning their email, name, and picture for the rest
    // of its lifetime — up to 24 hours, configurable. Worse, the same token
    // handed to /oauth2/introspect correctly came back `{active: false}`, so
    // the issuer contradicted itself about whether it was still valid.
    const session = verified.claims.sid
      ? await prisma.oidcSession.findUnique({ where: { id: verified.claims.sid } })
      : null;
    if (
      !session ||
      session.revokedAt ||
      session.userId !== account.id ||
      session.clientId !== currentClient.clientId
    ) {
      throw invalidToken("That session has ended or is no longer available");
    }

    return {
      sub: account.id,
      ...buildUserClaims({ account, scopes })
    };
  }

  /**
   * Verifies a bearer access token.
   *
   * The signing algorithm comes from the key the `kid` resolves to, never from
   * the token header — see lib/jwt. `token_use` is checked so an ID token cannot
   * be presented as an access token.
   */
  async function verifyAccessToken(rawToken) {
    const token = String(rawToken || "").trim();
    if (!token) throw invalidToken("An access token is required");

    let claims;
    try {
      claims = await verifyIssuedJwt(token);
    } catch (error) {
      throw invalidToken(error.message);
    }
    if (claims.token_use !== "access") {
      throw invalidToken("That token is not an access token");
    }
    return { claims };
  }

  /**
   * Verifies a token this issuer signed and returns its claims. `alg` comes from
   * the key the `kid` resolves to, never the token header — see lib/jwt.
   */
  async function verifyIssuedJwt(token, { allowExpired = false } = {}) {
    const keyRing = await keys.ensureKeyRing();
    const { payload } = verifyJwt(token, {
      keyRing,
      issuer,
      allowExpired,
      clockToleranceSeconds
    });
    return payload;
  }

  // --- Introspection and revocation ---------------------------------------

  /**
   * RFC 7662 token introspection.
   *
   * A token that is unknown, expired, revoked, or belongs to someone else gets
   * `{ active: false }` and nothing more — section 2.2 is explicit that the
   * response must not reveal anything about a token the caller is not entitled
   * to.
   */
  async function introspect({ headers, body }) {
    const { client } = await clients.authenticate({ headers, body });
    const token = String(body?.token || "").trim();
    if (!token) throw invalidRequest("token is required");

    const hint = String(body?.token_type_hint || "").trim();

    // A refresh token is opaque and looked up by hash; an access token is a JWT.
    // The hint is honoured but not trusted, so a wrong hint still works.
    const order = hint === "refresh_token" ? ["refresh", "access"] : ["access", "refresh"];
    for (const kind of order) {
      const result =
        kind === "access"
          ? await introspectAccessToken({ token, client })
          : await introspectRefreshToken({ token, client });
      if (result) return result;
    }
    return { active: false };
  }

  async function introspectAccessToken({ token, client }) {
    let claims;
    try {
      claims = await verifyIssuedJwt(token);
    } catch {
      return null;
    }
    if (claims.token_use !== "access") return null;
    // Only the client the token was issued to may introspect it.
    if (!safeEqual(claims.client_id || "", client.clientId)) return { active: false };

    const scopes = decodeScopes(claims.scope);
    const currentClient = await clients.findByClientId(client.clientId);
    const account = await accounts.findById(claims.sub);
    const grant = currentClient
      ? await prisma.grant.findUnique({
          where: { userId_clientId: { userId: claims.sub, clientId: currentClient.clientId } }
        })
      : null;
    if (!scopesRemainAllowed(account, currentClient, grant, scopes)) return { active: false };

    const session = claims.sid ? await prisma.oidcSession.findUnique({ where: { id: claims.sid } }) : null;
    if (
      !session ||
      session.revokedAt ||
      session.userId !== account.id ||
      session.clientId !== currentClient.clientId
    ) {
      return { active: false };
    }

    return {
      active: true,
      scope: claims.scope,
      client_id: claims.client_id,
      // RFC 7662 section 2.2 lists `username` as a human-readable identifier.
      username: account.username || account.attributes?.external_preferred_username || account.email,
      token_type: "Bearer",
      exp: claims.exp,
      iat: claims.iat,
      sub: claims.sub,
      aud: claims.aud,
      iss: issuer,
      jti: claims.jti,
      sid: claims.sid,
      token_use: "access"
    };
  }

  async function introspectRefreshToken({ token, client }) {
    const record = await prisma.refreshToken.findUnique({ where: { tokenHash: hashToken(token) } });
    if (!record) return null;
    if (!safeEqual(record.clientId, client.clientId)) return { active: false };
    if (record.revokedAt || record.usedAt || record.expiresAt <= now()) return { active: false };

    const scopes = decodeScopes(record.scopes);
    const currentClient = await clients.findByClientId(client.clientId);
    const account = await accounts.findById(record.userId);
    const grant = currentClient
      ? await prisma.grant.findUnique({
          where: { userId_clientId: { userId: record.userId, clientId: currentClient.clientId } }
        })
      : null;
    if (
      !currentClient?.allowedGrantTypes.includes("refresh_token") ||
      !scopesRemainAllowed(account, currentClient, grant, scopes)
    ) {
      return { active: false };
    }

    const session = await prisma.oidcSession.findUnique({
      where: {
        sessionId_clientId: { sessionId: record.sessionId, clientId: currentClient.clientId }
      }
    });
    if (!session || session.revokedAt || session.userId !== account.id) return { active: false };

    return {
      active: true,
      scope: scopes.join(" "),
      client_id: record.clientId,
      username: account.username || account.attributes?.external_preferred_username || account.email,
      token_type: "Bearer",
      exp: epoch(record.expiresAt),
      iat: epoch(record.createdAt),
      sub: record.userId,
      iss: issuer,
      token_use: "refresh"
    };
  }

  /**
   * RFC 7009 token revocation.
   *
   * Always answers 200, even for an unknown token: section 2.2 requires it, so
   * the endpoint cannot be used to test whether a token is valid. Revoking a
   * refresh token takes its whole family, since a rotated descendant is the same
   * authorization.
   */
  async function revoke({ headers, body }) {
    const { client } = await clients.authenticate({ headers, body });
    const token = String(body?.token || "").trim();
    if (!token) throw invalidRequest("token is required");

    const refresh = await prisma.refreshToken.findUnique({ where: { tokenHash: hashToken(token) } });
    if (refresh && safeEqual(refresh.clientId, client.clientId)) {
      await revokeFamily(refresh.familyId, "client_revoked");
      await auditLog?.record({
        action: "oauth.token.revoked",
        actorUserId: refresh.userId,
        targetType: "client",
        targetId: client.clientId,
        metadata: { token_use: "refresh" }
      });
      return { revoked: true };
    }

    // A resource server validating a JWT offline cannot observe revocation until
    // expiry. This issuer can: UserInfo and introspection both consult the OIDC
    // session, so ending that session makes the presented token inactive here
    // and also retires refresh tokens descended from the same browser session.
    let claims;
    try {
      claims = await verifyIssuedJwt(token);
    } catch {
      // An unknown or malformed token is not an error here, per RFC 7009.
      return { revoked: true };
    }
    if (claims.token_use === "access" && safeEqual(claims.client_id || "", client.clientId)) {
      const session = claims.sid
        ? await prisma.oidcSession.findUnique({ where: { id: String(claims.sid) } })
        : null;
      if (
        session &&
        session.clientId === client.clientId &&
        session.userId === claims.sub
      ) {
        await revokeTokensForSession({
          sessionId: session.sessionId,
          clientId: client.clientId,
          userId: claims.sub,
          reason: "client_revoked"
        });
      }
      await auditLog?.record({
        action: "oauth.token.revoked",
        actorUserId: claims.sub,
        targetType: "client",
        targetId: client.clientId,
        metadata: { token_use: "access" }
      });
    }
    return { revoked: true };
  }

  async function revokeFamily(familyId, reason) {
    const family = await prisma.refreshToken.findFirst({
      where: { familyId: String(familyId) },
      select: { clientId: true, userId: true }
    });
    if (!family) return { revoked: 0 };

    const timestamp = now();
    const revoked = await prisma.$transaction(async (database) => {
      // Refresh issuance takes these locks in the same order. Whichever side
      // obtains the Grant lock first completes its whole state transition before
      // the other can inspect or change the family, so a replacement token
      // cannot be inserted just after this update and escape revocation.
      const client = await lockClient(database, family.clientId);
      if (!client) return 0;
      const user = await lockUser(database, family.userId);
      if (!user) return 0;
      await lockGrant(database, { userId: family.userId, clientId: family.clientId });

      const result = await database.refreshToken.updateMany({
        where: { familyId: String(familyId), revokedAt: null },
        data: { revokedAt: timestamp }
      });
      return result.count;
    });

    await auditLog?.record({
      action: "oauth.refresh.family_revoked",
      targetType: "refresh_family",
      targetId: familyId,
      metadata: { reason }
    });
    return { revoked };
  }

  async function revokeTokensForSession({ sessionId, clientId, userId, reason }) {
    const timestamp = now();
    await prisma.$transaction(async (database) => {
      // Code-replay containment is one transition. If either write fails, a
      // caller may retry the replay response without leaving a live refresh
      // family behind a revoked OIDC session, or the inverse.
      const client = await lockClient(database, clientId);
      if (!client) return;
      const user = await lockUser(database, userId);
      if (!user) return;
      await lockGrant(database, { userId, clientId });
      await lockBrowserSession(database, { sessionId, userId, validAt: null });

      await database.refreshToken.updateMany({
        where: { sessionId, clientId, revokedAt: null },
        data: { revokedAt: timestamp }
      });
      await database.oidcSession.updateMany({
        where: { sessionId, clientId, revokedAt: null },
        data: { revokedAt: timestamp, revocationReason: reason }
      });
    });
  }

  // --- Grants the user manages --------------------------------------------

  /**
   * The applications a user has authorized. This is what makes consent
   * reversible; the previous implementation had the query but mounted no route,
   * so a user could grant access and never withdraw it.
   */
  async function listGrantsForUser(userId) {
    const grants = await prisma.grant.findMany({
      where: { userId: String(userId || ""), revokedAt: null },
      orderBy: { grantedAt: "desc" }
    });

    const results = [];
    for (const grant of grants) {
      const client = await clients.findByClientId(grant.clientId);
      if (!client) continue;
      const scopes = decodeScopes(grant.scopes);
      const activeTokens = await prisma.refreshToken.count({
        where: { userId: grant.userId, clientId: grant.clientId, revokedAt: null, expiresAt: { gt: now() } }
      });
      results.push({
        clientId: client.clientId,
        clientName: client.name,
        logoUri: client.logoUri,
        clientUri: client.clientUri,
        scopes,
        permissions: scopeRegistry.describeForConsent(scopes),
        grantedAt: grant.grantedAt,
        updatedAt: grant.updatedAt,
        hasOfflineAccess: activeTokens > 0
      });
    }
    return results;
  }

  /**
   * Withdraws a grant: the grant row, every refresh token, unused codes, and the
   * per-client sessions, plus a back-channel logout so the client learns of it
   * rather than discovering it on its next refresh.
   */
  async function revokeGrant({ userId, clientId, reason = "user_revoked", actorUserId = null }) {
    const ownerId = String(userId);
    const relyingPartyId = String(clientId);
    const timestamp = now();
    const revoked = await prisma.$transaction(async (database) => {
      // Match authorization and refresh issuance's stable lock order. A grant
      // that is being withdrawn cannot be widened, used for a new code, or used
      // for a replacement refresh token after this transaction has observed it.
      const client = await lockClient(database, relyingPartyId);
      if (!client) return null;
      const user = await lockUser(database, ownerId);
      if (!user) return null;
      const grant = await lockGrant(database, { userId: ownerId, clientId: relyingPartyId });
      if (!grant || grant.revokedAt) return null;

      // The row lock serializes concurrent withdrawal requests; the conditional
      // update keeps the operation idempotent if a different path already
      // completed the transition before this transaction obtained its locks.
      const claimed = await database.grant.updateMany({
        where: { id: grant.id, revokedAt: null },
        data: { revokedAt: timestamp, version: { increment: 1 } }
      });
      if (!claimed.count) return null;

      await database.refreshToken.updateMany({
        where: { userId: grant.userId, clientId: grant.clientId, revokedAt: null },
        data: { revokedAt: timestamp }
      });
      await database.authorizationCode.updateMany({
        where: { userId: grant.userId, clientId: grant.clientId, usedAt: null },
        data: { usedAt: timestamp }
      });

      const oidcSessions = await database.oidcSession.findMany({
        where: { userId: grant.userId, clientId: grant.clientId, revokedAt: null }
      });
      await database.oidcSession.updateMany({
        where: { userId: grant.userId, clientId: grant.clientId, revokedAt: null },
        data: { revokedAt: timestamp, revocationReason: reason }
      });

      // The outbox rows are part of the withdrawal commit. A database failure
      // while recording delivery intent rolls the Grant, tokens, codes, and OIDC
      // sessions back as well, so a committed logout can never be silently lost.
      for (const session of oidcSessions) {
        await backchannel?.enqueue(
          {
            clientId: grant.clientId,
            // `session.id`, not `session.sessionId`: the ID token published the
            // former as `sid`, and that is what the relying party indexed by.
            sid: session.id,
            userId: grant.userId,
            subject: grant.userId,
            reason
          },
          database
        );
      }
      return { grant };
    });
    if (!revoked) return { revoked: false };
    const { grant } = revoked;

    await auditLog?.record({
      action: "oauth.grant.revoked",
      actorUserId: actorUserId || grant.userId,
      targetUserId: grant.userId,
      targetType: "client",
      targetId: grant.clientId,
      metadata: { reason }
    });
    return { revoked: true };
  }

  // --- Logout --------------------------------------------------------------

  /**
   * RP-initiated logout (OIDC RP-Initiated Logout 1.0).
   *
   * `post_logout_redirect_uri` is honoured only when registered by the client
   * that `id_token_hint` or `client_id` identifies. Redirecting to an
   * unregistered URI would make this an open redirect on the logout endpoint.
   */
  async function resolveLogoutRedirect({ clientId, postLogoutRedirectUri, state }) {
    const requested = String(postLogoutRedirectUri || "").trim();
    if (!requested) return null;
    if (!clientId) return null;

    const client = await clients.findByClientId(clientId);
    if (!client) return null;
    if (!client.postLogoutRedirectUris.includes(requested)) return null;

    const target = new URL(requested);
    if (state) target.searchParams.set("state", String(state));
    return target.toString();
  }

  /**
   * Reads `id_token_hint` to identify who is logging out.
   *
   * Verified as a signature but accepted when expired: the whole point of the
   * hint is that the session is ending, and an expired ID token is the normal
   * case at logout.
   */
  async function readIdTokenHint(idTokenHint) {
    const raw = String(idTokenHint || "").trim();
    if (!raw) return null;
    try {
      const claims = await verifyIssuedJwt(raw, { allowExpired: true });
      if (claims.token_use !== "id") return null;
      return {
        clientId: Array.isArray(claims.aud) ? claims.aud[0] : claims.aud,
        sub: claims.sub,
        sid: claims.sid
      };
    } catch {
      return null;
    }
  }

  /** Ends every per-client session for a browser session and notifies each client. */
  async function endSessions({ sessionId, userId, reason = "user_logout" }) {
    // `userId` is the authorization check, not decoration for the audit entry.
    //
    // It arrived as a parameter and was used only in the audit record below,
    // while both queries matched on `sessionId` alone — and `sessionId` reaches
    // here from `req.body.session_id`. Any signed-in user could therefore end
    // another user's OIDC sessions across every client, and fire a logout
    // notification to each one, by submitting an identifier that was not
    // theirs. The caller's own comment said this was scoped; it was not.
    //
    // Required rather than optional: an omitted scope is the whole defect, and
    // a default of "match everything" is what it silently did before.
    if (!userId) {
      throw new TypeError("endSessions requires a userId: it is what scopes the revocation to its owner");
    }

    const ownerId = String(userId);
    const browserSessionId = String(sessionId);
    const timestamp = now();
    const ended = await prisma.$transaction(async (database) => {
      // User -> Browser Session is the shared lock order used by account-wide
      // revocation. `validAt: null` deliberately allows an operator-requested
      // logout to clean up an expired row as well as an active one.
      const user = await lockUser(database, ownerId);
      if (!user) return null;
      const browserSession = await lockBrowserSession(database, {
        sessionId: browserSessionId,
        userId: ownerId,
        validAt: null
      });
      if (!browserSession) return null;

      const where = { sessionId: browserSession.id, userId: ownerId, revokedAt: null };
      const oidcSessions = await database.oidcSession.findMany({ where });

      // Delete the browser credential in the same commit as the client-facing
      // revocation state. Even a session with no OIDC rows is still a real
      // browser credential and must report revoked=true once removed.
      const removed = await database.session.deleteMany({
        where: { id: browserSession.id, userId: ownerId }
      });
      if (!removed.count) return null;

      await database.oidcSession.updateMany({
        where,
        data: { revokedAt: timestamp, revocationReason: reason }
      });

      let notified = 0;
      for (const session of oidcSessions) {
        const queued = await backchannel?.enqueue(
          {
            clientId: session.clientId,
            // `session.id`, not `session.sessionId`: see the note on enqueue. The
            // rows here were selected by browser session, so `sessionId` is the
            // same value for every one of them — which is what made the mistake
            // look plausible.
            sid: session.id,
            userId: session.userId,
            subject: session.userId,
            reason
          },
          database
        );
        if (queued) notified += 1;
      }
      return { browserSession, oidcSessions, notified };
    });

    if (!ended) return { revoked: false, notified: 0 };
    const { browserSession, oidcSessions, notified } = ended;

    await auditLog?.record({
      action: "oauth.session.ended",
      actorUserId: userId,
      targetType: "session",
      targetId: browserSession.id,
      metadata: { reason, clients: oidcSessions.length }
    });
    return { revoked: true, notified };
  }

  // --- Housekeeping --------------------------------------------------------

  async function pruneStaleOidcSessions(cutoff) {
    const staleBefore = new Date(
      cutoff.getTime() - Math.max(ttl.accessTokenSeconds, ttl.refreshTokenSeconds) * 1000
    );
    const batchSize = 500;
    let afterId = null;
    let count = 0;

    for (;;) {
      const candidates = await prisma.oidcSession.findMany({
        where: {
          lastSeenAt: { lt: staleBefore },
          ...(afterId ? { id: { gt: afterId } } : {})
        },
        orderBy: { id: "asc" },
        take: batchSize,
        select: { id: true, sessionId: true }
      });
      if (!candidates.length) break;
      afterId = candidates[candidates.length - 1].id;

      // A remembered browser session can outlive every token it previously
      // issued. Keep its per-client row so a later logout can still fan out a
      // back-channel notification. There is intentionally no foreign key: a
      // revoked OIDC row must outlive the deleted browser session until all
      // signed tokens that name it have expired.
      const activeBrowserSessions = await prisma.session.findMany({
        where: {
          id: { in: [...new Set(candidates.map((candidate) => candidate.sessionId))] },
          expiresAt: { gt: cutoff }
        },
        select: { id: true }
      });
      const activeIds = new Set(activeBrowserSessions.map((session) => session.id));
      const removable = candidates
        .filter((candidate) => !activeIds.has(candidate.sessionId))
        .map((candidate) => candidate.id);
      if (removable.length) {
        // A token exchange can refresh lastSeenAt after the candidate read.
        // Re-check the cutoff in the delete so a newly active session cannot be
        // removed from underneath the access token that just refreshed it.
        const deleted = await prisma.oidcSession.deleteMany({
          where: { id: { in: removable }, lastSeenAt: { lt: staleBefore } }
        });
        count += deleted.count;
      }
      if (candidates.length < batchSize) break;
    }

    return { count };
  }

  /**
   * Deletes spent and expired protocol records. Not scheduled automatically: a
   * deployment decides when to run it, and the reads that matter all check expiry
   * themselves, so a delayed sweep is a storage question rather than a security
   * one.
   */
  async function pruneExpired() {
    const cutoff = now();
    // A used code is the replay detector for every credential descended from
    // its first exchange. Keep it until the longest possible access/refresh
    // credential can no longer be alive; deleting it immediately turns a replay
    // into an ordinary invalid_grant and skips containment of those descendants.
    const codeReplayBefore = new Date(
      cutoff.getTime() - Math.max(ttl.accessTokenSeconds, ttl.refreshTokenSeconds) * 1000
    );
    const [requests, codes, tokens, sessions] = await Promise.all([
      prisma.authorizationRequest.deleteMany({
        where: { OR: [{ expiresAt: { lt: cutoff } }, { consumedAt: { not: null } }] }
      }),
      prisma.authorizationCode.deleteMany({
        where: {
          OR: [
            { usedAt: null, expiresAt: { lt: cutoff } },
            { usedAt: { lt: codeReplayBefore } }
          ]
        }
      }),
      prisma.refreshToken.deleteMany({ where: { expiresAt: { lt: cutoff } } }),
      pruneStaleOidcSessions(cutoff)
    ]);
    return {
      authorizationRequests: requests.count,
      codes: codes.count,
      refreshTokens: tokens.count,
      oidcSessions: sessions.count
    };
  }

  return {
    authorizationServerMetadata,
    buildUserClaims,
    completeAuthorization,
    denyAuthorization,
    discoveryDocument,
    /**
     * One indexed read, for the health check.
     *
     * Against a real table rather than `SELECT 1`, and the difference is not
     * pedantic: Prisma reconnects on the next query after a disconnect, and
     * `SELECT 1` needs no schema — so against a SQLite file that had been
     * removed it opened a fresh empty one and answered successfully. It proved
     * a connection, which was never the question either.
     *
     * `signingKey` is the table to ask for. It is small, it is read once at
     * boot and rarely after, and an issuer that cannot reach it cannot sign
     * anything — so "this row is unreachable" and "this process is useless" are
     * the same statement. LIMIT 1 on the primary key, so the cost does not grow
     * with the data.
     */
    ping: () => prisma.signingKey.findFirst({ select: { id: true } }),
    endSessions,
    findActiveGrant,
    introspect,
    issueTokens,
    jwks,
    listGrantsForUser,
    loadAuthorizationRequest,
    parseAuthorizationRequest,
    persistAuthorizationRequest,
    pruneExpired,
    readIdTokenHint,
    resolveAuthorization,
    resolveLogoutRedirect,
    revoke,
    revokeGrant,
    token,
    upsertGrant,
    userinfo,
    verifyAccessToken,
    verifyIssuedJwt
  };
}

module.exports = { createProviderService, epoch, optionalOpaque, parsePrompt };

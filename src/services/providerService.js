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

  function endpoint(pathname) {
    return `${issuer}${pathname}`;
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
      expiresAt: record.expiresAt
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

    // prompt=login forces re-authentication even for an active session.
    if (prompts.includes("login")) {
      return { action: "login", reason: "prompt_login" };
    }

    // max_age caps how long ago authentication may have happened.
    if (request.maxAge !== null && request.maxAge !== undefined) {
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

  /** Records or widens the user's decision to trust a client. */
  async function upsertGrant({ userId, clientId, scopes }) {
    const existing = await prisma.grant.findUnique({
      where: { userId_clientId: { userId, clientId } }
    });
    const merged = scopeRegistry.sort([...(existing && !existing.revokedAt ? decodeScopes(existing.scopes) : []), ...scopes]);

    if (existing) {
      return prisma.grant.update({
        where: { id: existing.id },
        data: {
          scopes: encodeScopes(merged),
          revokedAt: null,
          // The version increments on every change, so a stored grant can be
          // told apart from the one a token was issued under.
          version: existing.version + 1
        }
      });
    }
    return prisma.grant.create({
      data: {
        id: randomId(),
        userId,
        clientId,
        scopes: encodeScopes(merged)
      }
    });
  }

  /**
   * Issues an authorization code and marks the request consumed, so one
   * authorization request can never yield two codes.
   */
  async function issueCode({ request, account, session, scopes }) {
    const code = randomToken();
    const consumedAt = now();

    const consumed = await prisma.authorizationRequest.updateMany({
      where: { id: request.id, consumedAt: null },
      data: { consumedAt }
    });
    if (!consumed.count) throw invalidRequest("This authorization request has already been completed");

    // The per-client session view backs `sid`, session status, and back-channel
    // logout fan-out.
    const oidcSession = await prisma.oidcSession.upsert({
      where: { sessionId_clientId: { sessionId: session.id, clientId: request.client.clientId } },
      create: {
        id: randomId(),
        sessionId: session.id,
        clientId: request.client.clientId,
        userId: account.id,
        authTime: session.authTime,
        lastSeenAt: consumedAt
      },
      update: { lastSeenAt: consumedAt, revokedAt: null, revocationReason: null }
    });

    await prisma.authorizationCode.create({
      data: {
        id: randomId(),
        codeHash: hashToken(code),
        clientId: request.client.clientId,
        redirectUri: request.redirectUri,
        nonce: request.nonce,
        codeChallenge: request.codeChallenge,
        codeChallengeMethod: request.codeChallengeMethod,
        scopes: encodeScopes(scopes),
        userId: account.id,
        sessionId: session.id,
        authTime: session.authTime,
        expiresAt: new Date(consumedAt.getTime() + ttl.authorizationCodeSeconds * 1000)
      }
    });

    await auditLog?.record({
      action: "oauth.code.issued",
      actorUserId: account.id,
      targetType: "client",
      targetId: request.client.clientId,
      metadata: { scopes, sid: oidcSession.id }
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

    const scopes = approvedScopes
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
          state: request.state
        })
      };
    }

    scopeRegistry.assertAllowedForUser(account, scopes);
    await upsertGrant({ userId: account.id, clientId: request.client.clientId, scopes });
    return issueCode({ request, account, session, scopes });
  }

  /** Records the user's refusal as an `access_denied` redirect (RFC 6749 4.1.2.1). */
  async function denyAuthorization({ requestToken }) {
    const request = await loadAuthorizationRequest(requestToken);
    if (!request) throw invalidRequest("This sign-in request has expired");
    await prisma.authorizationRequest.updateMany({
      where: { id: request.id, consumedAt: null },
      data: { consumedAt: now() }
    });
    return {
      redirectUrl: buildErrorRedirect(request.redirectUri, {
        error: "access_denied",
        errorDescription: "The user declined the request",
        state: request.state
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

    if (record.usedAt) {
      // Replay. The code is gone, but a token issued from its first use may still
      // be live, so every token descended from it is revoked.
      await revokeTokensForSession({ sessionId: record.sessionId, clientId: client.clientId, reason: "code_replay" });
      await auditLog?.record({
        action: "oauth.code.replayed",
        actorUserId: record.userId,
        targetType: "client",
        targetId: client.clientId
      });
      throw invalidGrant("The authorization code has already been used");
    }

    if (record.expiresAt <= now()) throw invalidGrant("The authorization code has expired");

    // RFC 6749 section 4.1.3: redirect_uri must be present and identical to the
    // one from the authorization request.
    const presentedRedirect = String(body.redirect_uri || "").trim();
    if (!presentedRedirect || !safeEqual(presentedRedirect, record.redirectUri)) {
      throw invalidGrant("redirect_uri does not match the authorization request");
    }

    verifyPkce({ record, body, client });

    const claimed = await prisma.authorizationCode.updateMany({
      where: { id: record.id, usedAt: null },
      data: { usedAt: now() }
    });
    if (!claimed.count) throw invalidGrant("The authorization code has already been used");

    const account = await accounts.findById(record.userId);
    if (!account || account.status === accounts.STATUS.DISABLED) {
      throw invalidGrant("That account is no longer available");
    }

    const oidcSession = await prisma.oidcSession.findUnique({
      where: { sessionId_clientId: { sessionId: record.sessionId, clientId: client.clientId } }
    });
    if (oidcSession?.revokedAt) throw invalidGrant("That session has been ended");

    return issueTokens({
      client,
      account,
      scopes: decodeScopes(record.scopes),
      sessionId: record.sessionId,
      sid: oidcSession?.id || record.sessionId,
      authTime: record.authTime,
      nonce: record.nonce
    });
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

    const account = await accounts.findById(record.userId);
    if (!account || account.status === accounts.STATUS.DISABLED) {
      await revokeFamily(record.familyId, "account_unavailable");
      throw invalidGrant("That account is no longer available");
    }

    // A grant the user has since revoked must stop working, or "revoke access"
    // means nothing until the refresh token expires on its own.
    const grant = await findActiveGrant({ userId: account.id, clientId: client.clientId });
    if (!grant) {
      await revokeFamily(record.familyId, "grant_revoked");
      throw invalidGrant("Access for this application has been revoked");
    }

    const oidcSession = await prisma.oidcSession.findUnique({
      where: { sessionId_clientId: { sessionId: record.sessionId, clientId: client.clientId } }
    });
    if (oidcSession?.revokedAt) {
      await revokeFamily(record.familyId, "session_ended");
      throw invalidGrant("That session has been ended");
    }

    let scopes = decodeScopes(record.scopes);
    // RFC 6749 section 6: the requested scope must not exceed what was granted.
    if (body.scope) {
      const requested = scopeRegistry.parse(body.scope, { strict: true }).granted;
      if (!scopeRegistry.covers(scopes, requested)) {
        throw invalidScope("The requested scope exceeds the scope of the original grant");
      }
      scopes = requested;
    }
    // Narrow to what the grant still covers, in case it was reduced.
    scopes = scopeRegistry.sort(scopes.filter((scope) => decodeScopes(grant.scopes).includes(scope)));
    if (!scopes.length) throw invalidGrant("Access for this application has been revoked");

    if (rotateRefreshTokens) {
      const claimed = await prisma.refreshToken.updateMany({
        where: { id: record.id, usedAt: null, revokedAt: null },
        data: { usedAt: now() }
      });
      if (!claimed.count) {
        await revokeFamily(record.familyId, "refresh_replay");
        throw invalidGrant("The refresh token has been revoked");
      }
    }

    return issueTokens({
      client,
      account,
      scopes,
      sessionId: record.sessionId,
      sid: oidcSession?.id || record.sessionId,
      authTime: record.authTime,
      // No `nonce` on a refresh: OIDC Core section 12.2 says an ID token issued
      // from a refresh must not carry the original nonce.
      nonce: null,
      familyId: record.familyId,
      parentTokenId: record.id
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
    parentTokenId = null
  }) {
    const keyRing = await keys.ensureKeyRing();
    const issuedAt = now();
    const issuedAtSeconds = epoch(issuedAt);
    const accessTokenId = randomId();

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

    if (wantsRefresh) {
      const refreshToken = randomToken();
      const family = familyId || randomId();
      await prisma.refreshToken.create({
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

    await prisma.oidcSession.updateMany({
      where: { sessionId, clientId: client.clientId },
      data: { lastSeenAt: issuedAt }
    });

    await auditLog?.record({
      action: "oauth.token.issued",
      actorUserId: account.id,
      targetType: "client",
      targetId: client.clientId,
      metadata: { scopes, refreshed: Boolean(parentTokenId), jti: accessTokenId }
    });

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
      preferred_username: account.username || null,
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
    if (!verified.claims.scope || !decodeScopes(verified.claims.scope).includes("openid")) {
      // Section 5.3.1: UserInfo requires an access token issued with `openid`.
      throw invalidToken("This access token was not issued with the openid scope");
    }

    const account = await accounts.findById(verified.claims.sub);
    if (!account || account.status === accounts.STATUS.DISABLED) {
      throw invalidToken("That account is no longer available");
    }

    const scopes = decodeScopes(verified.claims.scope);
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

    const session = claims.sid ? await prisma.oidcSession.findUnique({ where: { id: claims.sid } }) : null;
    if (session?.revokedAt) return { active: false };

    const account = await accounts.findById(claims.sub);
    if (!account || account.status === accounts.STATUS.DISABLED) return { active: false };

    return {
      active: true,
      scope: claims.scope,
      client_id: claims.client_id,
      // RFC 7662 section 2.2 lists `username` as a human-readable identifier.
      username: account.username || account.email,
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

    const account = await accounts.findById(record.userId);
    if (!account || account.status === accounts.STATUS.DISABLED) return { active: false };

    return {
      active: true,
      scope: decodeScopes(record.scopes).join(" "),
      client_id: record.clientId,
      username: account.username || account.email,
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

    // An access token is a self-contained JWT and cannot be withdrawn before it
    // expires. Revoking the family behind it is the honest interpretation of the
    // request, and its short lifetime is what bounds the exposure.
    try {
      const claims = await verifyIssuedJwt(token);
      if (claims.token_use === "access" && safeEqual(claims.client_id || "", client.clientId)) {
        await prisma.refreshToken.updateMany({
          where: { userId: claims.sub, clientId: client.clientId, revokedAt: null },
          data: { revokedAt: now() }
        });
        await auditLog?.record({
          action: "oauth.token.revoked",
          actorUserId: claims.sub,
          targetType: "client",
          targetId: client.clientId,
          metadata: { token_use: "access" }
        });
      }
    } catch {
      // An unknown or malformed token is not an error here, per RFC 7009.
    }
    return { revoked: true };
  }

  async function revokeFamily(familyId, reason) {
    await prisma.refreshToken.updateMany({
      where: { familyId, revokedAt: null },
      data: { revokedAt: now() }
    });
    await auditLog?.record({
      action: "oauth.refresh.family_revoked",
      targetType: "refresh_family",
      targetId: familyId,
      metadata: { reason }
    });
  }

  async function revokeTokensForSession({ sessionId, clientId, reason }) {
    await prisma.refreshToken.updateMany({
      where: { sessionId, clientId, revokedAt: null },
      data: { revokedAt: now() }
    });
    await prisma.oidcSession.updateMany({
      where: { sessionId, clientId, revokedAt: null },
      data: { revokedAt: now(), revocationReason: reason }
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
    const grant = await prisma.grant.findUnique({
      where: { userId_clientId: { userId: String(userId), clientId: String(clientId) } }
    });
    if (!grant || grant.revokedAt) return { revoked: false };

    const timestamp = now();
    await prisma.grant.update({
      where: { id: grant.id },
      data: { revokedAt: timestamp, version: grant.version + 1 }
    });
    await prisma.refreshToken.updateMany({
      where: { userId: grant.userId, clientId: grant.clientId, revokedAt: null },
      data: { revokedAt: timestamp }
    });
    await prisma.authorizationCode.updateMany({
      where: { userId: grant.userId, clientId: grant.clientId, usedAt: null },
      data: { usedAt: timestamp }
    });

    const oidcSessions = await prisma.oidcSession.findMany({
      where: { userId: grant.userId, clientId: grant.clientId, revokedAt: null }
    });
    await prisma.oidcSession.updateMany({
      where: { userId: grant.userId, clientId: grant.clientId, revokedAt: null },
      data: { revokedAt: timestamp, revocationReason: reason }
    });

    for (const session of oidcSessions) {
      await backchannel?.enqueue({
        clientId: grant.clientId,
        sessionId: session.sessionId,
        userId: grant.userId,
        subject: grant.userId,
        reason
      });
    }

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
    const oidcSessions = await prisma.oidcSession.findMany({
      where: { sessionId: String(sessionId), revokedAt: null }
    });
    if (!oidcSessions.length) return { notified: 0 };

    await prisma.oidcSession.updateMany({
      where: { sessionId: String(sessionId), revokedAt: null },
      data: { revokedAt: now(), revocationReason: reason }
    });

    let notified = 0;
    for (const session of oidcSessions) {
      const queued = await backchannel?.enqueue({
        clientId: session.clientId,
        sessionId: session.sessionId,
        userId: session.userId,
        subject: session.userId,
        reason
      });
      if (queued) notified += 1;
    }

    await auditLog?.record({
      action: "oauth.session.ended",
      actorUserId: userId,
      targetType: "session",
      targetId: String(sessionId),
      metadata: { reason, clients: oidcSessions.length }
    });
    return { notified };
  }

  // --- Housekeeping --------------------------------------------------------

  /**
   * Deletes spent and expired protocol records. Not scheduled automatically: a
   * deployment decides when to run it, and the reads that matter all check expiry
   * themselves, so a delayed sweep is a storage question rather than a security
   * one.
   */
  async function pruneExpired() {
    const cutoff = now();
    const [requests, codes, tokens] = await Promise.all([
      prisma.authorizationRequest.deleteMany({
        where: { OR: [{ expiresAt: { lt: cutoff } }, { consumedAt: { not: null } }] }
      }),
      prisma.authorizationCode.deleteMany({
        where: { OR: [{ expiresAt: { lt: cutoff } }, { usedAt: { not: null } }] }
      }),
      prisma.refreshToken.deleteMany({ where: { expiresAt: { lt: cutoff } } })
    ]);
    return { authorizationRequests: requests.count, codes: codes.count, refreshTokens: tokens.count };
  }

  return {
    authorizationServerMetadata,
    buildUserClaims,
    completeAuthorization,
    denyAuthorization,
    discoveryDocument,
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

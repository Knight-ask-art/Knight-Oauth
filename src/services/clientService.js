"use strict";

const { hashToken, randomId, randomToken, verifyTokenHash } = require("../lib/crypto");
const { decodeScopes, decodeUris, encodeScopes, encodeUris } = require("../lib/lists");
const { appError, invalidClient, invalidRequest, invalidToken, unauthorizedClient } = require("../lib/errors");
const { findMatchingRedirectUri, parseHttpsUrl, parseRedirectUri } = require("../lib/uri");

// Registered relying parties.
//
// One model covers all three ways a client gets here — a static entry in the
// environment, a submission through the web UI, and RFC 7591 dynamic
// registration — because they differ only in who creates the record and whether
// it needs approval. The protocol code downstream should not be able to tell
// them apart.
//
// Client authentication supports the three methods a relying party is likely to
// use, from RFC 6749 section 2.3 and OIDC Core section 9:
//
//   client_secret_basic   HTTP Basic. Required of an OAuth server by RFC 6749
//                         section 2.3.1, and the default.
//   client_secret_post    credentials in the form body. Optional per the RFC,
//                         but a real share of client libraries only do this, and
//                         refusing it is a compatibility failure rather than a
//                         security measure.
//   none                  public clients — a mobile or single-page app that
//                         cannot hold a secret. Authenticated by PKCE instead
//                         (RFC 7636), which is why PKCE is mandatory for them.
//
// The previous Knight-internal issuer accepted only Basic. That is the single
// change most likely to decide whether a stock library works here at all.

const AUTH_METHODS = new Set(["client_secret_basic", "client_secret_post", "none"]);
const CLIENT_TYPES = new Set(["confidential", "public"]);
const STATUS = { PENDING: "PENDING", APPROVED: "APPROVED", REJECTED: "REJECTED", DISABLED: "DISABLED" };
const GRANT_TYPES = new Set(["authorization_code", "refresh_token", "client_credentials"]);
const RESPONSE_TYPES = new Set(["code"]);

const MAX_REDIRECT_URIS = 20;
const MAX_NAME_LENGTH = 120;

function text(value, maximum, name, { required = false } = {}) {
  const raw = String(value ?? "").trim();
  if (required && !raw) throw invalidRequest(`${name} is required`);
  if (raw.length > maximum) throw invalidRequest(`${name} is too long`);
  return raw;
}

function createClientService({ prisma, config, scopeRegistry, auditLog, now = () => new Date() } = {}) {
  const allowInsecureHttp = Boolean(config?.allowInsecureHttp);
  const requireApproval = config?.clients?.requireApproval !== false;
  const dynamicRegistrationEnabled = Boolean(config?.clients?.dynamicRegistrationEnabled);
  const registrationAccessToken = config?.clients?.registrationAccessToken || "";
  const requirePkceForConfidential = config?.security?.requirePkce !== false;

  /**
   * The in-memory view of a client. Delimited columns are decoded exactly once,
   * here, so no caller has to know the storage format.
   */
  function toClient(record) {
    if (!record) return null;
    return {
      id: record.id,
      clientId: record.clientId,
      clientType: record.clientType,
      name: record.name,
      description: record.description || null,
      logoUri: record.logoUri || null,
      clientUri: record.clientUri || null,
      tosUri: record.tosUri || null,
      policyUri: record.policyUri || null,
      contacts: decodeUris(record.contacts),
      redirectUris: decodeUris(record.redirectUris),
      postLogoutRedirectUris: decodeUris(record.postLogoutRedirectUris),
      backchannelLogoutUri: record.backchannelLogoutUri || null,
      allowedScopes: decodeScopes(record.allowedScopes),
      allowedGrantTypes: decodeScopes(record.allowedGrantTypes),
      tokenEndpointAuthMethod: record.tokenEndpointAuthMethod,
      status: record.status,
      isFirstParty: record.isFirstParty,
      requireConsent: record.requireConsent,
      isPublic: record.clientType === "public",
      hasSecret: Boolean(record.clientSecretHash),
      ownerUserId: record.ownerUserId || null,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      /** True when this client must present a PKCE challenge. */
      get requiresPkce() {
        return record.clientType === "public" || requirePkceForConfidential;
      }
    };
  }

  // --- Validation ----------------------------------------------------------

  function normalizeRedirectUris(value, { name = "redirect_uris", required = true } = {}) {
    const raw = Array.isArray(value) ? value : decodeUris(String(value || "").replaceAll("\r\n", "\n"));
    const entries = [...new Set(raw.map((entry) => String(entry || "").trim()).filter(Boolean))];
    if (required && !entries.length) throw invalidRequest(`${name} is required`);
    if (entries.length > MAX_REDIRECT_URIS) throw invalidRequest(`${name} has too many entries`);
    // parseRedirectUri is what allows loopback http and private-use schemes, so a
    // native or desktop app can register here at all.
    return entries.map((entry) => parseRedirectUri(entry, { allowInsecureHttp, name }));
  }

  /**
   * Validates requested scopes against the registry.
   *
   * `openid` is NOT required. A plain OAuth 2.0 client that wants an access token
   * and no identity token is a legitimate client, and rejecting it — as the
   * previous implementation did — makes this an OIDC-only server rather than the
   * OAuth 2.0 server it advertises.
   */
  function normalizeScopes(value, { fallback = ["openid", "profile", "email"] } = {}) {
    const raw = Array.isArray(value) ? value : String(value || "").split(/[\s,]+/);
    const entries = [...new Set(raw.map((scope) => String(scope || "").trim()).filter(Boolean))];
    const selected = entries.length ? entries : fallback;
    const unknown = selected.filter((scope) => !scopeRegistry.has(scope));
    if (unknown.length) {
      throw invalidRequest(`Unknown scope: ${unknown.join(", ")}`);
    }
    return scopeRegistry.sort(selected);
  }

  function normalizeGrantTypes(value, { clientType }) {
    const raw = Array.isArray(value) ? value : String(value || "").split(/[\s,]+/);
    const entries = [...new Set(raw.map((entry) => String(entry || "").trim()).filter(Boolean))];
    const selected = entries.length ? entries : ["authorization_code", "refresh_token"];
    for (const grant of selected) {
      if (!GRANT_TYPES.has(grant)) {
        throw invalidRequest(`Unsupported grant type: ${grant}`);
      }
      // client_credentials authenticates the client itself, which a client with
      // no secret cannot do.
      if (grant === "client_credentials" && clientType === "public") {
        throw invalidRequest("A public client cannot use the client_credentials grant");
      }
    }
    return selected;
  }

  function normalizeAuthMethod(value, { clientType }) {
    const method = String(value || "").trim() || (clientType === "public" ? "none" : "client_secret_basic");
    if (!AUTH_METHODS.has(method)) {
      throw invalidRequest(`Unsupported token_endpoint_auth_method: ${method}`);
    }
    if (clientType === "public" && method !== "none") {
      throw invalidRequest("A public client must use token_endpoint_auth_method=none");
    }
    if (clientType === "confidential" && method === "none") {
      throw invalidRequest("A confidential client must authenticate at the token endpoint");
    }
    return method;
  }

  /** Builds the row for a create or update, validating every field. */
  function buildClientData(input, { existing = null } = {}) {
    const clientType = String(input.clientType || existing?.clientType || "confidential").trim();
    if (!CLIENT_TYPES.has(clientType)) throw invalidRequest("client_type must be confidential or public");

    const responseTypes = Array.isArray(input.responseTypes) ? input.responseTypes : [];
    for (const responseType of responseTypes) {
      if (!RESPONSE_TYPES.has(String(responseType).trim())) {
        // The implicit and hybrid flows return tokens through the browser's URL,
        // where they land in history and referrers. Current OAuth 2.0 Security
        // BCP guidance is not to use them, so only `code` is implemented.
        throw invalidRequest(`Unsupported response type: ${responseType}. Only "code" is supported.`);
      }
    }

    return {
      clientType,
      name: text(input.name ?? existing?.name, MAX_NAME_LENGTH, "Client name", { required: true }),
      description: text(input.description ?? existing?.description, 500, "Description") || null,
      logoUri: parseHttpsUrl(input.logoUri ?? existing?.logoUri, "logo_uri", { allowHttp: allowInsecureHttp }) || null,
      clientUri: parseHttpsUrl(input.clientUri ?? existing?.clientUri, "client_uri", { allowHttp: allowInsecureHttp }) || null,
      tosUri: parseHttpsUrl(input.tosUri ?? existing?.tosUri, "tos_uri", { allowHttp: allowInsecureHttp }) || null,
      policyUri: parseHttpsUrl(input.policyUri ?? existing?.policyUri, "policy_uri", { allowHttp: allowInsecureHttp }) || null,
      contacts: encodeUris(
        (Array.isArray(input.contacts) ? input.contacts : decodeUris(existing?.contacts)).slice(0, 10)
      ),
      redirectUris: encodeUris(
        normalizeRedirectUris(input.redirectUris ?? decodeUris(existing?.redirectUris))
      ),
      postLogoutRedirectUris: encodeUris(
        normalizeRedirectUris(input.postLogoutRedirectUris ?? decodeUris(existing?.postLogoutRedirectUris), {
          name: "post_logout_redirect_uris",
          required: false
        })
      ),
      // Back-channel logout is a server-to-server POST, so there is no
      // native-app carve-out to make: it must be a real HTTPS endpoint.
      backchannelLogoutUri:
        parseHttpsUrl(input.backchannelLogoutUri ?? existing?.backchannelLogoutUri, "backchannel_logout_uri", {
          allowHttp: allowInsecureHttp
        }) || null,
      allowedScopes: encodeScopes(
        normalizeScopes(input.scopes ?? decodeScopes(existing?.allowedScopes))
      ),
      allowedGrantTypes: encodeScopes(
        normalizeGrantTypes(input.grantTypes ?? decodeScopes(existing?.allowedGrantTypes), { clientType })
      ),
      tokenEndpointAuthMethod: normalizeAuthMethod(
        input.tokenEndpointAuthMethod ?? existing?.tokenEndpointAuthMethod,
        { clientType }
      )
    };
  }

  // --- Lookup --------------------------------------------------------------

  async function findByClientId(clientId) {
    const raw = String(clientId || "").trim();
    if (!raw) return null;
    return toClient(await prisma.oAuthClient.findUnique({ where: { clientId: raw } }));
  }

  /**
   * Loads a client for use in a protocol flow. An unknown or unapproved client is
   * `invalid_client`, not `access_denied`: whether a client id exists is not a
   * secret, but the two cases must not be distinguishable by status code either.
   */
  async function requireActiveClient(clientId) {
    const client = await findByClientId(clientId);
    if (!client) throw invalidClient("Unknown client");
    if (client.status !== STATUS.APPROVED) {
      throw invalidClient(
        client.status === STATUS.PENDING
          ? "This client is awaiting approval"
          : "This client is not permitted to request tokens"
      );
    }
    return client;
  }

  // --- Client authentication ----------------------------------------------

  /**
   * Parses the Authorization header for HTTP Basic client credentials.
   *
   * RFC 6749 section 2.3.1 requires the client id and secret to be
   * form-urlencoded before base64. Skipping the decode breaks any client whose
   * secret contains `+`, `/`, or `%`, which is a real and hard-to-diagnose
   * failure, so it is done properly here.
   */
  function parseBasicAuth(header) {
    const raw = String(header || "");
    if (!raw) return null;
    if (!/^Basic\s/i.test(raw)) return null;

    const decoded = Buffer.from(raw.replace(/^Basic\s+/i, ""), "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator < 0) throw invalidClient("Malformed Basic credentials");

    let clientId;
    let clientSecret;
    try {
      clientId = decodeURIComponent(decoded.slice(0, separator));
      clientSecret = decodeURIComponent(decoded.slice(separator + 1));
    } catch {
      // A client that base64'd raw bytes without form-encoding first is not
      // following the RFC, but the credentials are still usable as sent.
      clientId = decoded.slice(0, separator);
      clientSecret = decoded.slice(separator + 1);
    }
    return { clientId, clientSecret };
  }

  /**
   * Authenticates the client on a token, introspection, or revocation request.
   *
   * Presenting credentials two ways at once is rejected outright, per RFC 6749
   * section 2.3.1: it is otherwise ambiguous which one the server checked, and
   * that ambiguity has been the basis of real confusion attacks.
   */
  async function authenticate({ headers = {}, body = {} } = {}) {
    const basic = parseBasicAuth(headers.authorization || headers.Authorization);
    const postId = String(body.client_id || "").trim();
    const postSecret = String(body.client_secret || "").trim();

    if (basic && postSecret) {
      throw invalidClient("Present client credentials once, not in both the header and the body");
    }

    const clientId = basic ? basic.clientId : postId;
    if (!clientId) throw invalidClient("Client authentication is required");

    const client = await requireActiveClient(clientId);
    const record = await prisma.oAuthClient.findUnique({ where: { clientId: client.clientId } });

    if (client.tokenEndpointAuthMethod === "none") {
      // A public client must not send a secret; accepting one would make the
      // method ambiguous. Its authentication is PKCE, checked at the token
      // endpoint against the challenge recorded with the authorization code.
      if (basic?.clientSecret || postSecret) {
        throw invalidClient("This client is registered as public and must not send a client secret");
      }
      return { client, method: "none" };
    }

    const presented = basic ? basic.clientSecret : postSecret;
    if (!presented) throw invalidClient("Client authentication is required");

    const expectedMethod = client.tokenEndpointAuthMethod;
    const usedMethod = basic ? "client_secret_basic" : "client_secret_post";
    if (usedMethod !== expectedMethod) {
      throw invalidClient(`This client must authenticate with ${expectedMethod}`);
    }

    if (!verifyTokenHash(presented, record.clientSecretHash)) {
      throw invalidClient("Client authentication failed");
    }
    return { client, method: usedMethod };
  }

  /** Resolves the redirect URI for an authorization request. */
  function resolveRedirectUri(client, requested) {
    const raw = String(requested || "").trim();
    if (!raw) {
      // OIDC Core section 3.1.2.1 makes redirect_uri REQUIRED, and defaulting to
      // the sole registered URI when a client omits it hides a client bug. But a
      // missing redirect_uri cannot be reported by redirecting, so this must
      // surface as a direct error.
      throw invalidRequest("redirect_uri is required");
    }
    const matched = findMatchingRedirectUri(client.redirectUris, raw);
    if (!matched) {
      // Never redirect to an unregistered URI to report this, or the check is
      // pointless: that is the open-redirect the exact-match rule prevents.
      throw invalidRequest("redirect_uri does not match a registered redirect URI for this client");
    }
    // The requested form is returned, not the registered one: RFC 6749 section
    // 4.1.3 requires the token request's redirect_uri to equal what was sent to
    // the authorization endpoint, and a loopback port would otherwise differ.
    return raw;
  }

  function assertGrantAllowed(client, grantType) {
    if (!client.allowedGrantTypes.includes(grantType)) {
      throw unauthorizedClient(`This client is not permitted to use the ${grantType} grant`);
    }
  }

  /** Narrows requested scopes to what the client registered. */
  function filterScopes(client, requested) {
    const allowed = new Set(client.allowedScopes);
    return scopeRegistry.sort(requested.filter((scope) => allowed.has(scope)));
  }

  // --- Creation ------------------------------------------------------------

  /**
   * Creates a client. A secret is generated for a confidential client and
   * returned once — only its hash is stored, so it cannot be shown again.
   */
  async function create(input, { status, ownerUserId = null, actorUserId = null } = {}) {
    const data = buildClientData(input);
    const clientId = String(input.clientId || "").trim() || `c_${randomToken(18)}`;
    const secret = data.clientType === "confidential" ? randomToken(32) : null;

    let record;
    try {
      record = await prisma.oAuthClient.create({
        data: {
          id: randomId(),
          clientId,
          clientSecretHash: secret ? hashToken(secret) : null,
          status: status || (requireApproval ? STATUS.PENDING : STATUS.APPROVED),
          isFirstParty: Boolean(input.isFirstParty),
          requireConsent: input.requireConsent === undefined ? true : Boolean(input.requireConsent),
          ownerUserId,
          ...data
        }
      });
    } catch (error) {
      if (error?.code === "P2002") throw invalidRequest("That client_id is already registered");
      throw error;
    }

    await auditLog?.record({
      action: "client.created",
      actorUserId,
      targetType: "client",
      targetId: record.clientId,
      metadata: {
        status: record.status,
        client_type: record.clientType,
        grant_types: decodeScopes(record.allowedGrantTypes)
      }
    });
    return { client: toClient(record), clientSecret: secret };
  }

  /** A user submitting a client through the UI. Approval follows policy. */
  async function submit({ ownerUserId, ...input }) {
    if (config?.clients?.allowUserRegistration === false) {
      throw appError("Only an administrator can register a client on this server", 403);
    }
    return create(input, { ownerUserId, actorUserId: ownerUserId });
  }

  async function update({ clientId, input, actorUserId }) {
    const existing = await prisma.oAuthClient.findUnique({ where: { clientId: String(clientId) } });
    if (!existing) throw invalidRequest("Unknown client");
    const data = buildClientData(input, { existing });
    const record = await prisma.oAuthClient.update({
      where: { id: existing.id },
      data: {
        ...data,
        requireConsent: input.requireConsent === undefined ? existing.requireConsent : Boolean(input.requireConsent)
      }
    });
    await auditLog?.record({
      action: "client.updated",
      actorUserId,
      targetType: "client",
      targetId: record.clientId
    });
    return toClient(record);
  }

  /**
   * Issues a new secret and invalidates the old one immediately. There is no
   * overlap window: a client whose secret is being rotated because it leaked
   * needs the old one dead now, and a client doing planned rotation can be
   * updated in the same maintenance window.
   */
  async function rotateSecret({ clientId, actorUserId }) {
    const existing = await prisma.oAuthClient.findUnique({ where: { clientId: String(clientId) } });
    if (!existing) throw invalidRequest("Unknown client");
    if (existing.clientType !== "confidential") {
      throw invalidRequest("A public client has no secret to rotate");
    }
    const secret = randomToken(32);
    await prisma.oAuthClient.update({
      where: { id: existing.id },
      data: { clientSecretHash: hashToken(secret) }
    });
    await auditLog?.record({
      action: "client.secret.rotated",
      actorUserId,
      targetType: "client",
      targetId: existing.clientId
    });
    return { clientSecret: secret };
  }

  async function setStatus({ clientId, status, actorUserId }) {
    if (!Object.values(STATUS).includes(status)) throw invalidRequest("Unknown client status");
    const existing = await prisma.oAuthClient.findUnique({ where: { clientId: String(clientId) } });
    if (!existing) throw invalidRequest("Unknown client");

    const record = await prisma.oAuthClient.update({
      where: { id: existing.id },
      data: { status, reviewedByUserId: actorUserId || null, reviewedAt: now() }
    });

    // Disabling or rejecting a client must stop tokens it already holds from
    // being refreshed; otherwise a revoked client keeps working for the life of
    // its refresh token.
    if (status === STATUS.DISABLED || status === STATUS.REJECTED) {
      await prisma.refreshToken.updateMany({
        where: { clientId: record.clientId, revokedAt: null },
        data: { revokedAt: now() }
      });
      await prisma.oidcSession.updateMany({
        where: { clientId: record.clientId, revokedAt: null },
        data: { revokedAt: now(), revocationReason: "client_disabled" }
      });
    }

    await auditLog?.record({
      action: "client.status.changed",
      actorUserId,
      targetType: "client",
      targetId: record.clientId,
      metadata: { status }
    });
    return toClient(record);
  }

  /**
   * Approves a pending client and issues its secret. Kept separate from
   * setStatus because the secret can only be shown at this one moment.
   */
  async function approve({ clientId, actorUserId }) {
    const existing = await prisma.oAuthClient.findUnique({ where: { clientId: String(clientId) } });
    if (!existing) throw invalidRequest("Unknown client");
    if (existing.status !== STATUS.PENDING) {
      throw appError("Only a pending client can be approved", 409);
    }

    const secret = existing.clientType === "confidential" ? randomToken(32) : null;
    const record = await prisma.oAuthClient.update({
      where: { id: existing.id },
      data: {
        status: STATUS.APPROVED,
        clientSecretHash: secret ? hashToken(secret) : existing.clientSecretHash,
        reviewedByUserId: actorUserId || null,
        reviewedAt: now()
      }
    });
    await auditLog?.record({
      action: "client.approved",
      actorUserId,
      targetType: "client",
      targetId: record.clientId
    });
    return { client: toClient(record), clientSecret: secret };
  }

  async function remove({ clientId, actorUserId }) {
    const existing = await prisma.oAuthClient.findUnique({ where: { clientId: String(clientId) } });
    if (!existing) return { deleted: false };
    // Cascades take the codes, tokens, grants, and OIDC sessions with it.
    await prisma.oAuthClient.delete({ where: { id: existing.id } });
    await auditLog?.record({
      action: "client.deleted",
      actorUserId,
      targetType: "client",
      targetId: existing.clientId
    });
    return { deleted: true };
  }

  // --- RFC 7591 dynamic registration ---------------------------------------

  /**
   * Checks the initial access token for the registration endpoint.
   *
   * Off by default. When on without a token in production, `loadEnv` refuses to
   * start: an open registration endpoint lets anyone create a client on your
   * issuer, and while that is legal per RFC 7591 section 1.2, it should be a
   * decision rather than a default.
   */
  function assertRegistrationAllowed(authorizationHeader) {
    if (!dynamicRegistrationEnabled) {
      throw appError("Dynamic client registration is not enabled on this server", 404);
    }
    if (!registrationAccessToken) return;

    const raw = String(authorizationHeader || "");
    const presented = /^Bearer\s+(.+)$/i.exec(raw)?.[1]?.trim();
    if (!presented || !verifyTokenHash(presented, hashToken(registrationAccessToken))) {
      // A bearer token that is missing or wrong is 401 with a challenge, not 400
      // (RFC 6750 section 3, which RFC 7591 section 3.1 defers to for the initial
      // access token). The distinction is not cosmetic: a client library reads 400
      // as "my request was malformed" and gives up, and 401 as "my credential was
      // refused", which is the thing the operator has to fix.
      throw invalidToken("A valid initial access token is required to register a client");
    }
  }

  /**
   * RFC 7591 registration. Maps the wire field names onto the internal shape and
   * returns the RFC 7591 section 3.2.1 response.
   *
   * A dynamically registered client is APPROVED on creation: requiring manual
   * approval would make the endpoint useless for its purpose, and the gate is the
   * initial access token instead.
   */
  async function registerDynamic({ metadata = {}, authorizationHeader } = {}) {
    assertRegistrationAllowed(authorizationHeader);

    const requestedAuthMethod = String(metadata.token_endpoint_auth_method || "").trim();
    const clientType = requestedAuthMethod === "none" ? "public" : "confidential";

    const { client, clientSecret } = await create(
      {
        clientType,
        name: metadata.client_name || "Dynamically registered client",
        redirectUris: metadata.redirect_uris,
        postLogoutRedirectUris: metadata.post_logout_redirect_uris,
        backchannelLogoutUri: metadata.backchannel_logout_uri,
        logoUri: metadata.logo_uri,
        clientUri: metadata.client_uri,
        tosUri: metadata.tos_uri,
        policyUri: metadata.policy_uri,
        contacts: metadata.contacts,
        scopes: metadata.scope,
        grantTypes: metadata.grant_types,
        responseTypes: metadata.response_types,
        tokenEndpointAuthMethod: requestedAuthMethod || undefined,
        // Consent is always shown for a client nobody vetted.
        requireConsent: true,
        isFirstParty: false
      },
      { status: STATUS.APPROVED }
    );

    // RFC 7592: the token that lets the client read and update its own
    // registration. Stored hashed, returned once.
    const accessToken = randomToken(32);
    await prisma.oAuthClient.update({
      where: { clientId: client.clientId },
      data: { registrationAccessTokenHash: hashToken(accessToken) }
    });

    return {
      client,
      registration: {
        client_id: client.clientId,
        ...(clientSecret ? { client_secret: clientSecret } : {}),
        client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
        // 0 means "does not expire", per RFC 7591 section 3.2.1.
        ...(clientSecret ? { client_secret_expires_at: 0 } : {}),
        registration_access_token: accessToken,
        registration_client_uri: `${config.issuer}/oauth2/register/${encodeURIComponent(client.clientId)}`,
        client_name: client.name,
        redirect_uris: client.redirectUris,
        grant_types: client.allowedGrantTypes,
        response_types: ["code"],
        token_endpoint_auth_method: client.tokenEndpointAuthMethod,
        scope: client.allowedScopes.join(" ")
      }
    };
  }

  /**
   * The RFC 7592 client information response.
   *
   * No secret and no registration access token: those are returned once, at
   * registration, and cannot be re-read. A client that lost its secret rotates
   * it rather than fetching it again, which is what keeps a stolen registration
   * token from also yielding the client secret.
   */
  function toRegistrationResponse(client) {
    return {
      client_id: client.clientId,
      client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
      registration_client_uri: `${config.issuer}/oauth2/register/${encodeURIComponent(client.clientId)}`,
      client_name: client.name,
      redirect_uris: client.redirectUris,
      ...(client.postLogoutRedirectUris.length
        ? { post_logout_redirect_uris: client.postLogoutRedirectUris }
        : {}),
      ...(client.backchannelLogoutUri ? { backchannel_logout_uri: client.backchannelLogoutUri } : {}),
      ...(client.logoUri ? { logo_uri: client.logoUri } : {}),
      ...(client.clientUri ? { client_uri: client.clientUri } : {}),
      ...(client.tosUri ? { tos_uri: client.tosUri } : {}),
      ...(client.policyUri ? { policy_uri: client.policyUri } : {}),
      ...(client.contacts.length ? { contacts: client.contacts } : {}),
      grant_types: client.allowedGrantTypes,
      response_types: ["code"],
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      scope: client.allowedScopes.join(" ")
    };
  }

  /**
   * RFC 7592 section 2.2 update. The client sends its full metadata and the
   * result replaces what was registered.
   *
   * `client_id` is immutable, and a request naming a different one is rejected
   * rather than ignored — section 2.2 requires that, and silently accepting it
   * would let a client believe it had re-identified itself.
   */
  async function updateRegistration({ clientId, metadata = {} }) {
    const target = String(clientId);
    if (metadata.client_id !== undefined && String(metadata.client_id) !== target) {
      throw invalidRequest("client_id cannot be changed");
    }
    // Section 2.2: a client secret may not be set by the client.
    if (metadata.client_secret !== undefined) {
      throw invalidRequest("client_secret cannot be set through the registration endpoint");
    }

    const existing = await prisma.oAuthClient.findUnique({ where: { clientId: target } });
    if (!existing) throw invalidRequest("Unknown client");

    const requestedAuthMethod = String(metadata.token_endpoint_auth_method || "").trim();
    // A confidential client cannot become public through an update: its existing
    // secret would keep working while the server stopped requiring it.
    if (requestedAuthMethod && (requestedAuthMethod === "none") !== (existing.clientType === "public")) {
      throw invalidRequest("token_endpoint_auth_method cannot change the client type; register a new client instead");
    }

    return update({
      clientId: target,
      input: {
        name: metadata.client_name,
        redirectUris: metadata.redirect_uris,
        postLogoutRedirectUris: metadata.post_logout_redirect_uris,
        backchannelLogoutUri: metadata.backchannel_logout_uri,
        logoUri: metadata.logo_uri,
        clientUri: metadata.client_uri,
        tosUri: metadata.tos_uri,
        policyUri: metadata.policy_uri,
        contacts: metadata.contacts,
        scopes: metadata.scope,
        grantTypes: metadata.grant_types,
        responseTypes: metadata.response_types,
        tokenEndpointAuthMethod: requestedAuthMethod || undefined
      },
      actorUserId: null
    });
  }

  /** RFC 7592 configuration access: authenticates with the registration token. */
  async function authenticateRegistrationToken({ clientId, authorizationHeader }) {
    const record = await prisma.oAuthClient.findUnique({ where: { clientId: String(clientId || "") } });
    const presented = /^Bearer\s+(.+)$/i.exec(String(authorizationHeader || ""))?.[1]?.trim();
    // A missing client and a wrong token get the same answer, so the endpoint
    // does not confirm which client ids exist. RFC 7592 section 2.1 asks for 401
    // in both cases, which is also what keeps the two indistinguishable.
    if (!record || !presented || !verifyTokenHash(presented, record.registrationAccessTokenHash)) {
      throw invalidToken("Invalid registration access token");
    }
    return toClient(record);
  }

  // --- Listing and bootstrap ----------------------------------------------

  async function listForOwner(ownerUserId) {
    const records = await prisma.oAuthClient.findMany({
      where: { ownerUserId: String(ownerUserId || "") },
      orderBy: { createdAt: "desc" }
    });
    return records.map(toClient);
  }

  async function listAll({ status = "", take = 100, skip = 0 } = {}) {
    const where = status ? { status: String(status) } : {};
    const [records, total] = await Promise.all([
      prisma.oAuthClient.findMany({
        where,
        orderBy: [{ status: "asc" }, { createdAt: "desc" }],
        take: Math.min(Math.max(Number(take) || 100, 1), 500),
        skip: Math.max(Number(skip) || 0, 0)
      }),
      prisma.oAuthClient.count({ where })
    ]);
    return { clients: records.map(toClient), total };
  }

  /**
   * Imports OAUTH_STATIC_CLIENTS at boot, so a first-party relying party exists
   * before anyone logs in. Idempotent on client_id: re-running updates rather
   * than duplicating.
   *
   * A secret must be supplied in the configuration. Generating one here would
   * print it to a log or lose it entirely, and the operator needs it in the
   * relying party's own configuration anyway.
   */
  async function syncStaticClients(rawJson) {
    const raw = String(rawJson || "").trim();
    if (!raw) return { imported: 0, updated: 0 };

    let entries;
    try {
      entries = JSON.parse(raw);
    } catch {
      throw new Error("OAUTH_STATIC_CLIENTS must be valid JSON");
    }
    if (!Array.isArray(entries)) throw new Error("OAUTH_STATIC_CLIENTS must be a JSON array");

    let imported = 0;
    let updated = 0;

    for (const entry of entries) {
      const clientId = String(entry?.clientId || "").trim();
      if (!clientId) throw new Error("Each OAUTH_STATIC_CLIENTS entry requires a clientId");

      const clientType = String(entry.clientType || "confidential").trim();
      const secret = String(entry.clientSecret || "").trim();
      if (clientType === "confidential" && !secret) {
        throw new Error(`Static client "${clientId}" requires a clientSecret`);
      }

      // `clientName` as well as `name`: every other key in this JSON is the
      // camelCase of an RFC 7591 metadata field, `client_name` included, so
      // `clientName` is what an operator writes next to `clientId` and
      // `clientSecret`. Accepting only `name` failed the boot with "Client name
      // is required" while the configuration plainly carried one.
      const name = entry.name ?? entry.clientName;
      const data = buildClientData({ ...entry, clientType, name });
      const existing = await prisma.oAuthClient.findUnique({ where: { clientId } });

      if (existing) {
        await prisma.oAuthClient.update({
          where: { id: existing.id },
          data: {
            ...data,
            clientSecretHash: secret ? hashToken(secret) : existing.clientSecretHash,
            status: STATUS.APPROVED,
            isFirstParty: Boolean(entry.isFirstParty),
            requireConsent: entry.requireConsent === undefined ? existing.requireConsent : Boolean(entry.requireConsent)
          }
        });
        updated += 1;
        continue;
      }

      await prisma.oAuthClient.create({
        data: {
          id: randomId(),
          clientId,
          clientSecretHash: secret ? hashToken(secret) : null,
          status: STATUS.APPROVED,
          isFirstParty: Boolean(entry.isFirstParty),
          // A first-party client may skip consent, but only if the operator says
          // so explicitly — being first-party is not on its own a reason to stop
          // asking the user.
          requireConsent: entry.requireConsent === undefined ? !entry.isFirstParty : Boolean(entry.requireConsent),
          ...data
        }
      });
      imported += 1;
    }

    return { imported, updated };
  }

  return {
    AUTH_METHODS,
    STATUS,
    approve,
    assertGrantAllowed,
    authenticate,
    authenticateRegistrationToken,
    create,
    filterScopes,
    findByClientId,
    listAll,
    listForOwner,
    normalizeRedirectUris,
    normalizeScopes,
    parseBasicAuth,
    registerDynamic,
    remove,
    requireActiveClient,
    resolveRedirectUri,
    rotateSecret,
    setStatus,
    submit,
    syncStaticClients,
    toClient,
    toRegistrationResponse,
    update,
    updateRegistration,
    get dynamicRegistrationEnabled() {
      return dynamicRegistrationEnabled;
    },
    get supportedAuthMethods() {
      return [...AUTH_METHODS];
    }
  };
}

module.exports = { AUTH_METHODS, STATUS, createClientService };

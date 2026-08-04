"use strict";

const crypto = require("node:crypto");

const { randomId, safeEqual } = require("../lib/crypto");
const { encodeJson } = require("../lib/lists");
const { invalidRequest, loginRequired } = require("../lib/errors");

// External identity providers — the pluggable half of the identity story.
//
// Local accounts (accountService) are the default and need nothing configured.
// This module is for the deployment that already has a user directory and does
// not want a second one: an upstream site authenticates the user however it
// likes and hands them over.
//
// The adapter contract is small on purpose. An adapter provides:
//
//   name                        stable identifier, stored on ExternalIdentity
//   displayName                 shown on the login page
//   buildStartUrl({ ... })      where to send the browser
//   verify({ ... }) -> claims   turn the upstream's response into
//                               { subject, email?, name?, picture?, attributes? }
//
// Everything after `verify` — matching or creating the local account, issuing a
// session — is shared, so a new upstream kind means writing `verify` and nothing
// else.
//
// The `handoff` kind ships today. It differs from the coupled design it replaces
// in one way that matters: the upstream no longer writes into this service's
// database. It signs a short-lived JWT with a shared secret, which any HMAC
// library can do in a few lines, so the upstream needs no access to this
// service's storage and the two can be deployed independently.

const TICKET_ALG = "HS256";
const MAX_TICKET_LENGTH = 4096;
const MAX_EXTERNAL_USERNAME_LENGTH = 64;
const EXTERNAL_USERNAME_ATTRIBUTE = "external_preferred_username";
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function base64UrlDecode(part) {
  return Buffer.from(String(part), "base64url").toString("utf8");
}

/**
 * Verifies a compact HMAC-signed JWT.
 *
 * `alg` is fixed to HS256 rather than read from the header. A verifier that
 * trusts the header's `alg` accepts `{"alg":"none"}` and, when it also holds
 * asymmetric keys, is open to algorithm confusion. The header is checked to
 * match, never consulted to decide.
 */
function verifyTicketSignature(ticket, secret) {
  const parts = String(ticket || "").split(".");
  if (parts.length !== 3) throw invalidRequest("The sign-in ticket is malformed");
  const [headerPart, payloadPart, signaturePart] = parts;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${headerPart}.${payloadPart}`)
    .digest("base64url");
  if (!safeEqual(signaturePart, expected)) {
    throw invalidRequest("The sign-in ticket signature is not valid");
  }

  let header;
  let payload;
  try {
    header = JSON.parse(base64UrlDecode(headerPart));
    payload = JSON.parse(base64UrlDecode(payloadPart));
  } catch {
    throw invalidRequest("The sign-in ticket is malformed");
  }
  if (header?.alg !== TICKET_ALG) {
    throw invalidRequest(`The sign-in ticket must be signed with ${TICKET_ALG}`);
  }
  if (!payload || typeof payload !== "object") {
    throw invalidRequest("The sign-in ticket payload is malformed");
  }
  return payload;
}

/**
 * The `handoff` adapter.
 *
 * Flow:
 *   1. This issuer redirects to `startUrl` with `state` (an opaque value tying
 *      the return to the pending authorization request) and `return_to`.
 *   2. The upstream authenticates the user and redirects back to
 *      /login/external/<name>/callback?ticket=<jwt>&state=<state>
 *   3. The ticket is verified here.
 *
 * Required claims: `iss` (must equal the provider name), `aud` (this issuer),
 * `sub` (the upstream user), `exp`, `iat`, `jti`, and `state`. `state` inside
 * the signed payload is what binds the ticket to the request that started it —
 * without it, a ticket captured from one login could be replayed into another
 * user's pending authorization.
 */
function createHandoffAdapter(provider, { issuer }) {
  const secret = provider.sharedSecret;
  if (!secret) {
    throw new Error(`External identity provider "${provider.name}" requires a sharedSecret`);
  }

  return {
    name: provider.name,
    kind: "handoff",
    displayName: provider.displayName || provider.name,
    autoCreateUsers: provider.autoCreateUsers !== false,
    useSubjectAsUserId: provider.useSubjectAsUserId === true,
    syncAdminFromAttribute: provider.syncAdminFromAttribute || null,

    buildStartUrl({ state, returnTo }) {
      const url = new URL(provider.startUrl);
      url.searchParams.set("state", state);
      url.searchParams.set("return_to", returnTo);
      // The upstream needs to know who is asking so it can look up the right
      // shared secret and audience.
      url.searchParams.set("client", issuer);
      return url.toString();
    },

    async verify({ ticket, state, now }) {
      const raw = String(ticket || "").trim();
      if (!raw) throw invalidRequest("The sign-in ticket is missing");
      if (raw.length > MAX_TICKET_LENGTH) throw invalidRequest("The sign-in ticket is too large");

      const payload = verifyTicketSignature(raw, secret);

      if (payload.iss !== provider.name) {
        throw invalidRequest("The sign-in ticket was issued by an unexpected party");
      }
      // `aud` may be a string or an array, per RFC 7519 section 4.1.3.
      const audience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!audience.includes(issuer)) {
        throw invalidRequest("The sign-in ticket is not addressed to this issuer");
      }

      const subject = String(payload.sub || "").trim();
      if (!subject) throw invalidRequest("The sign-in ticket does not identify a user");
      if (provider.useSubjectAsUserId && !CANONICAL_UUID.test(subject)) {
        throw invalidRequest("The sign-in ticket subject is not a canonical account identifier");
      }

      if (payload.username !== undefined && payload.username !== null && typeof payload.username !== "string") {
        throw invalidRequest("The sign-in ticket username is not valid");
      }
      const username = String(payload.username || "").trim() || null;
      if (
        username &&
        (username.length > MAX_EXTERNAL_USERNAME_LENGTH || /[\u0000-\u001f\u007f]/.test(username))
      ) {
        throw invalidRequest("The sign-in ticket username is not valid");
      }

      const seconds = Math.floor(now.getTime() / 1000);
      if (!Number.isFinite(payload.exp) || payload.exp <= seconds) {
        throw invalidRequest("The sign-in ticket has expired");
      }
      if (!Number.isFinite(payload.iat)) {
        throw invalidRequest("The sign-in ticket has no valid issued-at time");
      }
      // A ticket dated in the future is either a clock problem or a forgery
      // attempt; both are worth refusing. The 60s allowance is for ordinary skew.
      if (payload.iat > seconds + 60) {
        throw invalidRequest("The sign-in ticket is not valid yet");
      }
      // A long-lived ticket defeats the point of a short-lived handoff, so the
      // configured TTL is a ceiling the upstream cannot exceed.
      if (payload.exp - payload.iat > provider.ticketTtlSeconds) {
        throw invalidRequest("The sign-in ticket is valid for too long");
      }

      const jti = String(payload.jti || "").trim();
      if (!jti) throw invalidRequest("The sign-in ticket has no identifier");

      if (!payload.state || !safeEqual(payload.state, String(state || ""))) {
        throw invalidRequest("The sign-in ticket does not match this sign-in attempt");
      }

      return {
        subject,
        jti,
        expiresAt: new Date(payload.exp * 1000),
        username,
        email: String(payload.email || "").trim().toLowerCase() || null,
        emailVerified: payload.email_verified === true,
        name: String(payload.name || "").trim() || null,
        picture: String(payload.picture || "").trim() || null,
        // Anything else the upstream sends becomes an account attribute, which
        // is how a deployment's custom scopes get something to release. The core
        // does not interpret it.
        attributes:
          payload.attributes && typeof payload.attributes === "object" && !Array.isArray(payload.attributes)
            ? payload.attributes
            : {}
      };
    }
  };
}

const ADAPTERS = { handoff: createHandoffAdapter };

function createExternalIdentityService({ prisma, config, accounts, auditLog, now = () => new Date() } = {}) {
  const issuer = config?.issuer;
  const adapters = new Map();

  for (const provider of config?.externalProviders || []) {
    const factory = ADAPTERS[provider.kind];
    if (!factory) throw new Error(`Unsupported external identity provider kind "${provider.kind}"`);
    adapters.set(provider.name, factory(provider, { issuer }));
  }

  function get(name) {
    return adapters.get(String(name || "")) || null;
  }

  function require_(name) {
    const adapter = get(name);
    if (!adapter) throw invalidRequest("Unknown sign-in provider");
    return adapter;
  }

  function externalRoleFor(adapter, claims) {
    const attribute = adapter.syncAdminFromAttribute;
    if (!attribute) return accounts.ROLE.USER;
    return claims.attributes?.[attribute] === true ? accounts.ROLE.ADMIN : accounts.ROLE.USER;
  }

  function hasBooleanAuthorityAssertion(adapter, claims) {
    const attribute = adapter.syncAdminFromAttribute;
    return Boolean(attribute) && typeof claims.attributes?.[attribute] === "boolean";
  }

  /** For the login page. Empty when no provider is configured, which is the default. */
  function list() {
    return [...adapters.values()].map((adapter) => ({
      name: adapter.name,
      displayName: adapter.displayName,
      kind: adapter.kind
    }));
  }

  /**
   * Records a ticket as spent. The unique constraint does the work: a replay
   * loses the insert race and is rejected, even if two arrive at once.
   */
  async function consumeTicket({ provider, jti, expiresAt }) {
    try {
      await prisma.consumedTicket.create({
        data: {
          id: randomId(),
          provider,
          jti,
          expiresAt
        }
      });
    } catch (error) {
      if (error?.code === "P2002") {
        throw invalidRequest("This sign-in ticket has already been used");
      }
      throw error;
    }
  }

  /**
   * Resolves upstream claims to a local account.
   *
   * The link is (provider, subject) and nothing else. Matching on email instead
   * would let an upstream take over a local account by asserting an address it
   * does not control; an explicit link is the only safe join. An account that
   * already has a local password keeps it — this adds a way in, it does not
   * replace one.
   */
  async function resolveAccount(adapter, claims, { ipAddress, userAgent } = {}) {
    const existing = await prisma.externalIdentity.findUnique({
      where: { provider_subject: { provider: adapter.name, subject: claims.subject } }
    });

    if (existing) {
      const account = await accounts.findById(existing.userId);
      if (!account) {
        // The identity outlived its account. Cascade delete should prevent this;
        // if it happens, refuse rather than silently creating a new account for
        // a subject that was deliberately removed.
        throw loginRequired("That account is no longer available");
      }
      if (account.status === accounts.STATUS.DISABLED) {
        throw loginRequired("That account has been disabled");
      }

      // Refresh the non-authoritative profile hints and attributes on each login
      // so a change upstream propagates.
      await prisma.externalIdentity.update({
        where: { id: existing.id },
        data: {
          profileJson: encodeJson({
            email: claims.email,
            username: claims.username,
            name: claims.name,
            picture: claims.picture
          })
        }
      });
      const attributes = {
        ...(claims.attributes || {}),
        [EXTERNAL_USERNAME_ATTRIBUTE]: claims.username || null
      };
      if (Object.keys(claims.attributes || {}).length || claims.username || account.attributes?.[EXTERNAL_USERNAME_ATTRIBUTE]) {
        await accounts.setAttributes({ userId: account.id, attributes });
      }
      let refreshed = await accounts.findById(account.id);
      if (hasBooleanAuthorityAssertion(adapter, claims)) {
        refreshed = await accounts.syncExternalAuthority({
          userId: account.id,
          role: externalRoleFor(adapter, claims),
          provider: adapter.name,
          ipAddress,
          userAgent
        });
      }
      return { account: refreshed, created: false };
    }

    if (!adapter.autoCreateUsers) {
      throw loginRequired(
        "This account is not linked yet. Sign in with your local account first, then link it."
      );
    }

    // A brand-new upstream subject. If the asserted address already belongs to a
    // local account, the two are NOT merged automatically: that decision belongs
    // to whoever can prove control of the local account, and making it here
    // would be an account-takeover path.
    if (claims.email) {
      const collision = await accounts.findByEmail(claims.email);
      if (collision) {
        throw loginRequired(
          "An account already uses that email address. Sign in with your password, then link this provider from your account settings."
        );
      }
    }

    if (adapter.useSubjectAsUserId && await accounts.findById(claims.subject)) {
      // A canonical subject already used by another local record must not be
      // silently adopted by this provider. Linking it is an explicit operator or
      // authenticated-user action, not an automatic handoff side effect.
      throw loginRequired("That account identifier is already in use");
    }

    const account = await createLinkedAccount(adapter, claims);
    await auditLog?.record({
      action: "account.external.created",
      actorUserId: account.id,
      targetType: "user",
      targetId: account.id,
      metadata: { provider: adapter.name },
      ipAddress,
      userAgent
    });
    return { account, created: true };
  }

  /**
   * Creates a local account with no password, linked to the upstream subject.
   *
   * The email is synthesized when the upstream sends none, because the column is
   * required and unique. A `.invalid` host is used, which RFC 2606 reserves
   * precisely so it can never resolve — the address is a placeholder and mail to
   * it must not go anywhere. Such an account is never marked email-verified.
   */
  async function createLinkedAccount(adapter, claims) {
    const timestamp = now();
    const email = claims.email || `${adapter.name}-${claims.subject}@external.invalid`;
    const userId = adapter.useSubjectAsUserId ? claims.subject : randomId();
    const attributes = {
      ...(claims.attributes || {}),
      ...(claims.username ? { [EXTERNAL_USERNAME_ATTRIBUTE]: claims.username } : {})
    };

    const record = await prisma.user.create({
      data: {
        id: userId,
        email: email.toLowerCase(),
        // Trusting the upstream's `email_verified` is a deployment-level
        // decision: the shared secret means the assertion is authentic, and the
        // operator configured this provider precisely because they trust it.
        emailVerifiedAt: claims.email && claims.emailVerified ? timestamp : null,
        passwordHash: null,
        name: claims.name,
        picture: claims.picture,
        role: externalRoleFor(adapter, claims),
        status: accounts.STATUS.ACTIVE,
        attributesJson: Object.keys(attributes).length ? encodeJson(attributes) : null,
        externalIdentities: {
          create: {
            id: randomId(),
            provider: adapter.name,
            subject: claims.subject,
            profileJson: encodeJson({
              email: claims.email,
              username: claims.username,
              name: claims.name,
              picture: claims.picture
            })
          }
        }
      }
    });
    return accounts.toAccount(record);
  }

  /**
   * Completes a callback: verify the ticket, spend it, resolve the account.
   */
  async function completeCallback({ provider, ticket, state, ipAddress, userAgent } = {}) {
    const adapter = require_(provider);
    const claims = await adapter.verify({ ticket, state, now: now() });
    await consumeTicket({ provider: adapter.name, jti: claims.jti, expiresAt: claims.expiresAt });
    const { account, created } = await resolveAccount(adapter, claims, { ipAddress, userAgent });
    await auditLog?.record({
      action: "account.external.login",
      actorUserId: account.id,
      targetType: "user",
      targetId: account.id,
      metadata: { provider: adapter.name, created },
      ipAddress,
      userAgent
    });
    return { account, created, provider: adapter.name };
  }

  /**
   * Links a provider to the account already signed in — the safe counterpart to
   * the automatic merge that resolveAccount refuses.
   */
  async function link({ provider, ticket, state, userId, ipAddress, userAgent } = {}) {
    const adapter = require_(provider);
    const claims = await adapter.verify({ ticket, state, now: now() });
    await consumeTicket({ provider: adapter.name, jti: claims.jti, expiresAt: claims.expiresAt });

    const existing = await prisma.externalIdentity.findUnique({
      where: { provider_subject: { provider: adapter.name, subject: claims.subject } }
    });
    if (existing && existing.userId !== userId) {
      throw invalidRequest("That provider account is already linked to a different account");
    }
    if (existing) return { linked: false, alreadyLinked: true };

    await prisma.externalIdentity.create({
      data: {
        id: randomId(),
        userId,
        provider: adapter.name,
        subject: claims.subject,
        profileJson: encodeJson({ email: claims.email, name: claims.name, picture: claims.picture })
      }
    });
    await auditLog?.record({
      action: "account.external.linked",
      actorUserId: userId,
      targetType: "user",
      targetId: userId,
      metadata: { provider: adapter.name },
      ipAddress,
      userAgent
    });
    return { linked: true, alreadyLinked: false };
  }

  /**
   * Unlinks a provider. Refused when it would leave the account with no way to
   * sign in — no password and no other linked identity.
   */
  async function unlink({ provider, userId, ipAddress, userAgent } = {}) {
    const account = await accounts.findById(userId);
    if (!account) throw invalidRequest("Unknown account");

    const identities = await prisma.externalIdentity.findMany({ where: { userId } });
    const target = identities.find((identity) => identity.provider === String(provider));
    if (!target) return { unlinked: false };

    if (!account.hasPassword && identities.length === 1) {
      throw invalidRequest("Set a password before unlinking your only sign-in method");
    }

    await prisma.externalIdentity.delete({ where: { id: target.id } });
    await auditLog?.record({
      action: "account.external.unlinked",
      actorUserId: userId,
      targetType: "user",
      targetId: userId,
      metadata: { provider: target.provider },
      ipAddress,
      userAgent
    });
    return { unlinked: true };
  }

  async function listForUser(userId) {
    const identities = await prisma.externalIdentity.findMany({
      where: { userId: String(userId || "") },
      orderBy: { createdAt: "asc" }
    });
    return identities.map((identity) => ({
      provider: identity.provider,
      displayName: get(identity.provider)?.displayName || identity.provider,
      subject: identity.subject,
      createdAt: identity.createdAt
    }));
  }

  /** Drops spent ticket records whose expiry has passed. Safe to schedule. */
  async function pruneConsumedTickets() {
    return prisma.consumedTicket.deleteMany({ where: { expiresAt: { lt: now() } } });
  }

  return {
    completeCallback,
    get,
    link,
    list,
    listForUser,
    pruneConsumedTickets,
    unlink,
    get enabled() {
      return adapters.size > 0;
    }
  };
}

module.exports = {
  createExternalIdentityService,
  createHandoffAdapter,
  verifyTicketSignature
};

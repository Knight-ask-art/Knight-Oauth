"use strict";

const { invalidScope } = require("./errors");
const { decodeScopes } = require("./lists");

// The scope and claim registry.
//
// The core ships only what OIDC Core 1.0 section 5.4 defines, plus
// `offline_access` from section 11. Anything deployment-specific — Knight's
// `knight_uid` and `credits.*`, or any other operator's resource scopes — is
// injected as a custom scope through configuration and is absent unless
// configured. That separation is what lets a stock client library work against
// this issuer without knowing anything about the deployment.

/** Standard scopes and the UserInfo/ID Token claims each releases. */
const STANDARD_SCOPES = {
  openid: {
    description: "Verify your identity",
    claims: ["sub"]
  },
  profile: {
    description: "See your basic profile: name, username, and picture",
    claims: [
      "name",
      "family_name",
      "given_name",
      "middle_name",
      "nickname",
      "preferred_username",
      "profile",
      "picture",
      "website",
      "gender",
      "birthdate",
      "zoneinfo",
      "locale",
      "updated_at"
    ]
  },
  email: {
    description: "See your email address",
    claims: ["email", "email_verified"]
  },
  address: {
    description: "See your postal address",
    claims: ["address"]
  },
  phone: {
    description: "See your phone number",
    claims: ["phone_number", "phone_number_verified"]
  },
  offline_access: {
    description: "Stay signed in when you are not using the app",
    claims: []
  }
};

// Reserved claims are set by the issuer from verified state. A custom scope may
// not overwrite one: a deployment must not be able to forge `sub` or move `exp`.
const RESERVED_CLAIMS = new Set([
  "iss",
  "sub",
  "aud",
  "exp",
  "iat",
  "nbf",
  "jti",
  "auth_time",
  "nonce",
  "acr",
  "amr",
  "azp",
  "sid",
  "at_hash",
  "c_hash",
  "client_id",
  "scope",
  "token_use"
]);

// Claims the issuer asserts from the account record, as opposed to the ones it
// asserts about the token itself.
//
// These are deliberately NOT in RESERVED_CLAIMS, and the difference is
// load-bearing: claimsFor skips a reserved claim in both of its loops, so
// reserving `email` would stop the standard `email` scope from releasing one at
// all — the standard scopes are exactly the mechanism for handing these out.
// What must not happen is a *deployment-defined* scope asserting them, because
// a custom scope's values come from the account's `attributes` map, which an
// upstream identity provider rewrites on every login.
//
// The concrete failure: a custom scope declaring `email_verified` reads it from
// `attributes`, and claimsFor applies claimsFrom after the standard claims, so
// the upstream value wins. An upstream sending
// `{ email_verified: true, email: "ceo@corp.com" }` would put a verified email
// nobody verified into every relying party's ID token — including past
// providerService's explicit defence that a synthesised `@external.invalid`
// address must always report `email_verified: false`.
// Every entry here is one the issuer already resolves from the account record,
// so refusing it to a custom scope removes no capability — the standard scope
// that releases it still does.
//
// `phone_number` is deliberately absent, and the difference is the point.
// Nothing populates it: buildUserClaims has no phone field, so the standard
// `phone` scope declares the claim and produces nothing, and a custom scope
// reading it from `attributes` is the only way a deployment can supply one.
// Refusing it would take that away and give nothing back. `phone_number_verified`
// is a different kind of statement — it asserts the issuer checked something —
// and that is exactly what an upstream-controlled attribute must not be able to
// say. A deployment may supply the number; it may not certify it.
const ACCOUNT_CLAIMS = new Set([
  "email",
  "email_verified",
  "name",
  "preferred_username",
  "picture",
  "updated_at",
  "phone_number_verified"
]);

// RFC 7662 defines these fields as issuer-controlled introspection metadata.
// A deployment-specific live-authority boolean must never overwrite one of
// them, even if a custom scope is misconfigured.
const INTROSPECTION_RESPONSE_FIELDS = new Set([
  ...RESERVED_CLAIMS,
  "active",
  "username",
  "token_type",
  "__proto__",
  "prototype",
  "constructor"
]);

// Keep private introspection field names deliberately boring. They are emitted
// as JSON object keys and consumed as security decisions, so whitespace,
// control characters, and look-alike punctuation have no useful role here.
const INTROSPECTION_CLAIM_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;

const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]+$/; // RFC 6749 appendix A.4
const MAX_SCOPE_LENGTH = 1024;

function validateScopeToken(scope) {
  if (!SCOPE_TOKEN.test(scope)) {
    throw invalidScope(`Scope token contains an illegal character: ${scope}`);
  }
}

function assertIntrospectionClaimName(claim) {
  if (!INTROSPECTION_CLAIM_NAME.test(claim)) {
    throw new Error(`Invalid introspection claim name "${claim}"`);
  }
  if (INTROSPECTION_RESPONSE_FIELDS.has(claim)) {
    throw new Error(`Introspection claim "${claim}" collides with a standard response field`);
  }
}

/**
 * Builds the registry the issuer runs against.
 *
 * @param {Array} customScopes  entries of
 *   `{ name, description, claims?, claimsFrom? }`. `claimsFrom` is
 *   `(user, context) => object`, letting a deployment map its own data into
 *   claims without the core knowing the shape.
 */
function createScopeRegistry({ customScopes = [] } = {}) {
  const scopes = new Map();
  const introspectionClaims = new Set();

  for (const [name, definition] of Object.entries(STANDARD_SCOPES)) {
    scopes.set(name, { name, standard: true, claimsFrom: null, ...definition });
  }

  for (const entry of customScopes) {
    const name = String(entry?.name || "").trim();
    if (!name) throw new Error("A custom scope requires a name");
    validateScopeToken(name);
    if (STANDARD_SCOPES[name]) {
      throw new Error(`Custom scope "${name}" collides with a standard OIDC scope`);
    }
    const claims = (entry.claims || []).map((claim) => String(claim).trim()).filter(Boolean);
    for (const claim of claims) {
      if (RESERVED_CLAIMS.has(claim)) {
        throw new Error(`Custom scope "${name}" may not define the reserved claim "${claim}"`);
      }
    }
    if (entry.claimsFrom && typeof entry.claimsFrom !== "function") {
      throw new Error(`Custom scope "${name}" claimsFrom must be a function`);
    }
    const introspectionClaim = String(entry.introspectionClaim || "").trim() || null;
    if (introspectionClaim) {
      assertIntrospectionClaimName(introspectionClaim);
      if (typeof entry.allowFor !== "function") {
        throw new Error(`Custom scope "${name}" requires allowFor when introspectionClaim is configured`);
      }
      if (introspectionClaims.has(introspectionClaim)) {
        throw new Error(`Duplicate introspection claim "${introspectionClaim}"`);
      }
      introspectionClaims.add(introspectionClaim);
    }
    scopes.set(name, {
      name,
      standard: false,
      description: String(entry.description || name),
      claims,
      claimsFrom: entry.claimsFrom || null,
      introspectionClaim,
      /** Restrict a scope to accounts satisfying a predicate, e.g. admin-only. */
      allowFor: typeof entry.allowFor === "function" ? entry.allowFor : null
    });
  }

  const supported = [...scopes.keys()];
  const claimsSupported = [
    ...new Set([
      "iss",
      "sub",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      "sid",
      "scope",
      "client_id",
      ...supported.flatMap((name) => scopes.get(name).claims)
    ])
  ];

  function has(scope) {
    return scopes.has(scope);
  }

  function get(scope) {
    return scopes.get(scope) || null;
  }

  /**
   * Parses a raw `scope` parameter.
   *
   * Two deliberate departures from the previous Knight-internal behaviour:
   *   * `openid` is not required. A plain OAuth 2.0 client that wants an access
   *     token and no ID token is a legitimate client (RFC 6749); demanding
   *     `openid` locked those out.
   *   * an unknown scope is dropped rather than fatal when `strict` is false,
   *     which is what OIDC Core section 3.1.2.1 permits and what keeps a client
   *     that requests a scope this deployment does not define from breaking
   *     outright. The granted set is always reported back in the token response,
   *     so the client is never misled about what it received.
   */
  function parse(value, { strict = false } = {}) {
    const raw = String(value || "");
    if (raw.length > MAX_SCOPE_LENGTH) throw invalidScope("scope is too long");

    const requested = decodeScopes(raw);
    for (const scope of requested) validateScopeToken(scope);

    const known = requested.filter((scope) => scopes.has(scope));
    const unknown = requested.filter((scope) => !scopes.has(scope));
    if (strict && unknown.length) {
      throw invalidScope(`Unsupported scope: ${unknown.join(" ")}`);
    }
    return { requested, granted: sort(known), unknown };
  }

  /** Sorts for stable storage and comparison; `openid` leads, per convention. */
  function sort(list) {
    const order = new Map(supported.map((name, index) => [name, index]));
    return [...new Set(list)].sort((left, right) => {
      const leftIndex = order.has(left) ? order.get(left) : Number.MAX_SAFE_INTEGER;
      const rightIndex = order.has(right) ? order.get(right) : Number.MAX_SAFE_INTEGER;
      if (leftIndex !== rightIndex) return leftIndex - rightIndex;
      return left.localeCompare(right);
    });
  }

  /** Scopes in `candidate` that `granted` does not already cover. */
  function beyond(granted, candidate) {
    const held = new Set(granted || []);
    return (candidate || []).filter((scope) => !held.has(scope));
  }

  function covers(granted, requested) {
    const held = new Set(granted || []);
    return (requested || []).every((scope) => held.has(scope));
  }

  /**
   * Rejects scopes the account may not authorize. A deployment expresses that
   * with `allowFor`, e.g. an admin-only resource scope.
   */
  function assertAllowedForUser(user, requestedScopes) {
    for (const scope of requestedScopes || []) {
      const definition = scopes.get(scope);
      if (definition?.allowFor && !definition.allowFor(user)) {
        throw invalidScope(`This account cannot authorize the scope ${scope}`);
      }
    }
  }

  /**
   * Assembles claims for the granted scopes.
   *
   * @param {object} args
   * @param {object} args.user     the account record
   * @param {string[]} args.scopes granted scopes
   * @param {object} args.baseClaims  standard claims the issuer already resolved
   * @param {object} args.context  passed through to a custom `claimsFrom`
   */
  function claimsFor({ user, scopes: granted, baseClaims = {}, context = {} }) {
    const result = {};
    for (const scope of granted || []) {
      const definition = scopes.get(scope);
      if (!definition) continue;

      for (const claim of definition.claims) {
        if (RESERVED_CLAIMS.has(claim)) continue;
        const value = baseClaims[claim];
        if (value !== undefined && value !== null && value !== "") {
          result[claim] = value;
        }
      }

      if (definition.claimsFrom) {
        const produced = definition.claimsFrom(user, context) || {};
        for (const [claim, value] of Object.entries(produced)) {
          // A deployment cannot overwrite an issuer-controlled claim, even by
          // mistake in its own configuration — nor one the issuer asserts from
          // the account record, which this loop runs after and would otherwise
          // silently win against.
          if (RESERVED_CLAIMS.has(claim) || ACCOUNT_CLAIMS.has(claim)) continue;
          if (value !== undefined && value !== null) result[claim] = value;
        }
      }
    }
    return result;
  }

  /**
   * Computes deployment-defined live-authority booleans for access-token
   * introspection. A value is true only when the token was granted the owning
   * scope and the account still satisfies that scope's current allowFor rule.
   * Values never come from account attributes or from JWT claims.
   *
   * A restricted scope without such a boolean remains fail-closed: if its
   * allowFor rule stops passing, the token cannot be reported active because a
   * relying party would otherwise see the stale scope with no live correction.
   */
  function introspectionAuthorityFor({ user, scopes: granted }) {
    const held = new Set(granted || []);
    const claims = {};
    let canRemainActive = true;
    for (const definition of scopes.values()) {
      const claim = definition.introspectionClaim;
      const wasGranted = held.has(definition.name);
      let allowed = wasGranted;
      if (wasGranted && definition.allowFor) {
        try {
          allowed = Boolean(definition.allowFor(user));
        } catch {
          allowed = false;
        }
      }
      if (wasGranted && definition.allowFor && !allowed && !claim) {
        canRemainActive = false;
      }
      if (claim) claims[claim] = Boolean(allowed);
    }
    return { canRemainActive, claims };
  }

  /** Scopes shown on the consent screen; `openid` carries no user-visible grant. */
  function describeForConsent(granted) {
    return sort(granted || [])
      .filter((scope) => scope !== "openid")
      .map((scope) => ({
        name: scope,
        description: scopes.get(scope)?.description || scope
      }));
  }

  return {
    assertAllowedForUser,
    beyond,
    claimsFor,
    claimsSupported,
    covers,
    describeForConsent,
    get,
    has,
    introspectionAuthorityFor,
    parse,
    sort,
    supported
  };
}

module.exports = {
  ACCOUNT_CLAIMS,
  INTROSPECTION_RESPONSE_FIELDS,
  RESERVED_CLAIMS,
  STANDARD_SCOPES,
  assertIntrospectionClaimName,
  createScopeRegistry
};

"use strict";

const path = require("node:path");

const { SUPPORTED_ALGORITHMS, DEFAULT_ALGORITHM } = require("../lib/jwt");
const {
  ACCOUNT_CLAIMS,
  RESERVED_CLAIMS,
  STANDARD_SCOPES,
  assertIntrospectionClaimName
} = require("../lib/scopes");
const { normalizeIssuer, parseHttpsUrl } = require("../lib/uri");
const { ROOT: PROJECT_ROOT } = require("./dotenv");

// Configuration is validated once, at boot, and a bad value stops the process.
// A misconfigured issuer that starts anyway is worse than one that refuses:
// silent misconfiguration in an authorization server is how tokens end up
// trusted by the wrong party.

function bool(value, fallback = false) {
  if (value === undefined || value === "") return fallback;
  const text = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(text)) return true;
  if (["0", "false", "no", "off"].includes(text)) return false;
  throw new Error(`Expected a boolean value, received "${value}"`);
}

function integer(value, fallback, name, { min, max }) {
  const result = value === undefined || value === "" ? fallback : Number(value);
  if (!Number.isInteger(result) || result < min || result > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return result;
}

function text(value, fallback = "") {
  return String(value ?? fallback).trim();
}

function list(value) {
  return [...new Set(String(value || "").split(/[\s,]+/).filter(Boolean))];
}

/**
 * Parses TRUST_PROXY into what Express's `trust proxy` setting accepts.
 *
 * The value decides what `req.ip` is, and `req.ip` is now what the rate limiter
 * counts against and what the audit log records as the address a sign-in came
 * from. Express reads the *left-most* X-Forwarded-For entry as the client, and
 * `true` tells it to trust every hop — including the entries the client wrote
 * itself. nginx's usual recipe is
 * `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`, which appends
 * rather than replaces, so "the proxy is mine" does not close it: a caller
 * sending its own X-Forwarded-For gets that value back out as `req.ip`, rotates
 * it per request, and never meets a limit.
 *
 * A hop count does close it. Express counts back from the socket, so with `1`
 * the address is the one the nearest proxy observed and anything the client
 * prepended is out of reach.
 *
 * `TRUST_PROXY=true` therefore now means one hop rather than all of them. That
 * is a change in meaning, and it is the safe direction: a single reverse proxy
 * is what almost every deployment has, it is what `true` was reached for, and a
 * deployment behind two says `2`. Anything that is not a boolean or an integer
 * is handed to Express as-is, which accepts a comma-separated list of addresses,
 * CIDR ranges, and the presets `loopback`, `linklocal`, and `uniquelocal`.
 */
function parseTrustProxy(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return false;

  const lowered = raw.toLowerCase();
  if (["0", "false", "no", "off"].includes(lowered)) return false;
  // Not `true`: see above. One hop is what a boolean was asking for.
  if (["true", "yes", "on"].includes(lowered)) return 1;

  if (/^\d+$/.test(raw)) {
    const hops = Number(raw);
    if (hops < 0 || hops > 32) {
      throw new Error("TRUST_PROXY must be between 0 and 32 when it is a hop count");
    }
    return hops === 0 ? false : hops;
  }

  // An address list or a preset. Express validates it when it is applied, and a
  // bad entry there fails the boot rather than silently trusting nothing.
  return raw;
}

/**
 * Parses OAUTH_CUSTOM_SCOPES: deployment-specific scopes the core knows nothing
 * about. Shape:
 *
 *   [
 *     {
 *       "name": "credits.read",
 *       "description": "Read your credit balance",
 *       "claims": ["knight_uid"],
 *       "adminOnly": false,
 *       "introspectionClaim": null
 *     }
 *   ]
 *
 * `claims` names claims sourced from the account's extra attributes. A scope
 * marked `adminOnly` can only be authorized by an account with the ADMIN role,
 * which is how a privileged resource scope is expressed without the core
 * hardcoding one.
 */
function parseCustomScopes(value) {
  const raw = text(value);
  if (!raw) return [];

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("OAUTH_CUSTOM_SCOPES must be valid JSON");
  }
  if (!Array.isArray(parsed)) {
    throw new Error("OAUTH_CUSTOM_SCOPES must be a JSON array");
  }

  return parsed.map((entry) => {
    const name = text(entry?.name);
    if (!name) throw new Error("Each OAUTH_CUSTOM_SCOPES entry requires a name");
    const claims = Array.isArray(entry.claims) ? entry.claims.map((claim) => text(claim)).filter(Boolean) : [];
    const adminOnly = bool(entry.adminOnly, false);
    const introspectionClaim = text(entry.introspectionClaim) || null;
    if (introspectionClaim && !adminOnly) {
      throw new Error(
        `OAUTH_CUSTOM_SCOPES entry "${name}" requires adminOnly=true when introspectionClaim is configured`
      );
    }
    return {
      name,
      description: text(entry.description) || name,
      claims,
      adminOnly,
      introspectionClaim,
      allowFor: adminOnly ? (user) => user?.role === "ADMIN" : null,
      // Claims are read from the account's `attributes` map, so a deployment
      // populates them through its identity adapter rather than through code.
      claimsFrom: claims.length
        ? (user) => {
            const attributes = user?.attributes || {};
            const result = {};
            for (const claim of claims) {
              if (attributes[claim] !== undefined && attributes[claim] !== null) {
                result[claim] = attributes[claim];
              }
            }
            return result;
          }
        : null
    };
  });
}

/**
 * Parses OAUTH_EXTERNAL_IDENTITY_PROVIDERS. Each entry configures one upstream
 * the issuer will accept an authenticated user from. Only the `handoff` kind
 * ships today — a signed short-lived ticket from a site that already owns the
 * login UI, which is how an existing user directory is reused without copying
 * passwords.
 *
 *   [
 *     {
 *       "name": "knight",
 *       "kind": "handoff",
 *       "displayName": "Knight",
 *       "startUrl": "https://www.example.com/oauth2/handoff/start",
 *       "sharedSecret": "...",
 *       "useSubjectAsUserId": true,
 *       "syncAdminFromAttribute": "knight_admin"
 *     }
 *   ]
 */
function parseExternalProviders(value, { allowInsecureHttp }) {
  const raw = text(value);
  if (!raw) return [];

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("OAUTH_EXTERNAL_IDENTITY_PROVIDERS must be valid JSON");
  }
  if (!Array.isArray(parsed)) {
    throw new Error("OAUTH_EXTERNAL_IDENTITY_PROVIDERS must be a JSON array");
  }

  return parsed.map((entry) => {
    const name = text(entry?.name);
    const kind = text(entry?.kind) || "handoff";
    if (!name) throw new Error("Each external identity provider requires a name");
    if (kind !== "handoff") {
      throw new Error(`Unsupported external identity provider kind "${kind}"`);
    }
    // A handoff ticket is only worth anything if it can be verified, so the
    // secret is required rather than optional. Without it the issuer would be
    // trusting whatever identity an unauthenticated caller claimed.
    const sharedSecret = text(entry?.sharedSecret);
    if (!sharedSecret) {
      throw new Error(`External identity provider "${name}" requires a sharedSecret to verify handoff tickets`);
    }
    if (sharedSecret.length < 32) {
      throw new Error(`External identity provider "${name}" sharedSecret must be at least 32 characters`);
    }
    const syncAdminFromAttribute = text(entry?.syncAdminFromAttribute) || null;
    if (syncAdminFromAttribute && !/^[a-z][a-z0-9_.-]{0,63}$/.test(syncAdminFromAttribute)) {
      throw new Error(
        `External provider ${name} syncAdminFromAttribute must be a lowercase attribute name`
      );
    }
    return {
      name,
      kind,
      displayName: text(entry?.displayName) || name,
      startUrl: parseHttpsUrl(entry?.startUrl, `External provider ${name} startUrl`, {
        required: true,
        allowHttp: allowInsecureHttp
      }),
      sharedSecret,
      // When enabled, the upstream subject is the canonical local account id.
      // This is useful only for a provider whose subject namespace is explicitly
      // trusted; it is never inferred from a request or from an email address.
      useSubjectAsUserId: bool(entry?.useSubjectAsUserId, false),
      // Role synchronization is opt-in and scoped to this provider. A missing or
      // non-boolean value is deliberately handled as "no change" by the adapter.
      syncAdminFromAttribute,
      // A brand-new upstream subject may create a local account. Off by default:
      // auto-provisioning from an unauthenticated upstream would be an open door.
      autoCreateUsers: bool(entry?.autoCreateUsers, true),
      ticketTtlSeconds: integer(entry?.ticketTtlSeconds, 60, `External provider ${name} ticketTtlSeconds`, {
        min: 15,
        max: 600
      })
    };
  });
}

/**
 * Turns a SQLite `file:` URL into an absolute path, and passes anything else
 * through.
 *
 * This is not tidying. Prisma resolves a relative `file:` URL against the
 * directory holding the schema, and the schemas live in `prisma/<provider>/`, so
 * `file:./data/knight-oauth.db` means `prisma/sqlite/data/` to the CLI and to the
 * client — not the `data/` directory the setup script creates, the Dockerfile
 * chowns, and a compose volume mounts. The consequence in a container is that the
 * database and the signing key it holds sit outside the volume, so every token
 * ever issued stops verifying the next time the container is replaced.
 *
 * Resolving it here means one absolute answer that the app, the Prisma CLI and
 * the operator's `ls` all agree on.
 */
function resolveDatabaseUrl({ provider, url }) {
  if (provider === "postgresql") {
    if (!url) throw new Error("DATABASE_URL is required when DATABASE_PROVIDER=postgresql");
    return url;
  }

  const target = url || "file:./data/knight-oauth.db";
  if (!target.startsWith("file:")) {
    throw new Error('DATABASE_URL must start with "file:" when DATABASE_PROVIDER=sqlite');
  }

  // `file:` with no slashes is Prisma's own spelling of a path, not a URL with a
  // host, so the path is whatever follows the scheme.
  const filePath = target.slice("file:".length);
  // A file: URL that is already absolute, or an in-memory database, is left as
  // it is; `:memory:` has no path to resolve.
  if (filePath === ":memory:" || path.isAbsolute(filePath)) return target;

  return `file:${path.resolve(PROJECT_ROOT, filePath).replaceAll("\\", "/")}`;
}

function loadEnv(source = process.env) {
  const nodeEnv = text(source.NODE_ENV, "development");
  const isProduction = nodeEnv === "production";

  // http is tolerated outside production so a first run needs no TLS setup.
  const allowInsecureHttp = bool(source.OAUTH_ALLOW_INSECURE_HTTP, !isProduction);

  const publicBaseUrl = normalizeIssuer(
    parseHttpsUrl(source.PUBLIC_BASE_URL || "http://127.0.0.1:3010", "PUBLIC_BASE_URL", {
      required: true,
      allowHttp: allowInsecureHttp
    })
  );
  // The issuer identifier is compared byte-for-byte by every relying party, so
  // it defaults to the public base URL rather than being independently guessed.
  const issuer = normalizeIssuer(
    parseHttpsUrl(source.OAUTH_ISSUER || publicBaseUrl, "OAUTH_ISSUER", {
      required: true,
      allowHttp: allowInsecureHttp
    })
  );

  const databaseProvider = text(source.DATABASE_PROVIDER, "sqlite").toLowerCase();
  if (!["sqlite", "postgresql"].includes(databaseProvider)) {
    throw new Error("DATABASE_PROVIDER must be sqlite or postgresql");
  }
  const databaseUrl = resolveDatabaseUrl({
    provider: databaseProvider,
    url: text(source.DATABASE_URL)
  });

  const signingAlgorithm = text(source.OAUTH_SIGNING_ALGORITHM, DEFAULT_ALGORITHM);
  if (!SUPPORTED_ALGORITHMS.includes(signingAlgorithm)) {
    throw new Error(`OAUTH_SIGNING_ALGORITHM must be one of ${SUPPORTED_ALGORITHMS.join(", ")}`);
  }

  const env = {
    nodeEnv,
    isProduction,
    port: integer(source.PORT, 3010, "PORT", { min: 1, max: 65535 }),
    trustProxy: parseTrustProxy(source.TRUST_PROXY),
    allowInsecureHttp,

    database: {
      provider: databaseProvider,
      url: databaseUrl
    },

    issuer,
    publicBaseUrl,

    branding: {
      // Deliberately generic: this is a standalone product, not a Knight-only
      // deployment, and the operator names their own installation.
      serviceName: text(source.OAUTH_SERVICE_NAME, "Knight OAuth"),
      logoUrl: text(source.OAUTH_LOGO_URL),
      supportUrl: text(source.OAUTH_SUPPORT_URL),
      primaryColor: text(source.OAUTH_PRIMARY_COLOR, "#2b6cb0")
    },

    signing: {
      algorithm: signingAlgorithm,
      signingKeysJson: text(source.OAUTH_SIGNING_KEYS_JSON),
      activeKid: text(source.OAUTH_ACTIVE_KID),
      // On in development so a clone boots; must be an explicit decision in
      // production, where a key belongs in a secret manager.
      allowGeneratedKeys: bool(source.OAUTH_ALLOW_GENERATED_KEYS, !isProduction)
    },

    ttl: {
      authorizationRequestSeconds: integer(
        source.OAUTH_AUTHORIZATION_REQUEST_TTL,
        600,
        "OAUTH_AUTHORIZATION_REQUEST_TTL",
        { min: 60, max: 3600 }
      ),
      authorizationCodeSeconds: integer(
        source.OAUTH_AUTHORIZATION_CODE_TTL,
        60,
        "OAUTH_AUTHORIZATION_CODE_TTL",
        // OIDC Core section 3.1.2.5 recommends at most 10 minutes; 60s is ample
        // for a redirect round trip.
        { min: 30, max: 600 }
      ),
      accessTokenSeconds: integer(source.OAUTH_ACCESS_TOKEN_TTL, 3600, "OAUTH_ACCESS_TOKEN_TTL", {
        min: 60,
        max: 86400
      }),
      idTokenSeconds: integer(source.OAUTH_ID_TOKEN_TTL, 3600, "OAUTH_ID_TOKEN_TTL", {
        min: 60,
        max: 86400
      }),
      refreshTokenSeconds: integer(
        source.OAUTH_REFRESH_TOKEN_TTL,
        30 * 24 * 60 * 60,
        "OAUTH_REFRESH_TOKEN_TTL",
        { min: 3600, max: 365 * 24 * 60 * 60 }
      ),
      sessionSeconds: integer(source.OAUTH_SESSION_TTL, 24 * 60 * 60, "OAUTH_SESSION_TTL", {
        min: 300,
        max: 90 * 24 * 60 * 60
      }),
      rememberMeSeconds: integer(
        source.OAUTH_REMEMBER_ME_TTL,
        30 * 24 * 60 * 60,
        "OAUTH_REMEMBER_ME_TTL",
        { min: 3600, max: 365 * 24 * 60 * 60 }
      ),
      clockToleranceSeconds: integer(
        source.OAUTH_CLOCK_TOLERANCE,
        0,
        "OAUTH_CLOCK_TOLERANCE",
        { min: 0, max: 300 }
      )
    },

    accounts: {
      // Open registration is the default for a self-hosted install; an operator
      // running a closed directory turns it off.
      registrationEnabled: bool(source.OAUTH_REGISTRATION_ENABLED, true),
      // A closed-directory deployment may still need the authorization and
      // consent pages while delegating every user authentication to an
      // upstream account provider. This is deliberately separate from
      // registrationEnabled: turning off sign-up must not turn off OAuth
      // authorization, and it must not leave a second password directory
      // reachable by accident.
      localLoginEnabled: bool(source.OAUTH_LOCAL_LOGIN_ENABLED, true),
      // Requiring a verified address before login needs working mail. Defaulting
      // it on would make a fresh install appear broken, so it is opt-in and the
      // README says to enable it in production.
      requireEmailVerification: bool(source.OAUTH_REQUIRE_EMAIL_VERIFICATION, false),
      minPasswordLength: integer(source.OAUTH_MIN_PASSWORD_LENGTH, 12, "OAUTH_MIN_PASSWORD_LENGTH", {
        min: 8,
        max: 256
      }),
      // First account to register becomes ADMIN, so a fresh install has an
      // administrator without a seeding step.
      firstUserIsAdmin: bool(source.OAUTH_FIRST_USER_IS_ADMIN, true)
    },

    clients: {
      // RFC 7591. Off by default: an open registration endpoint lets anyone
      // create a client on your issuer.
      dynamicRegistrationEnabled: bool(source.OAUTH_DYNAMIC_REGISTRATION_ENABLED, false),
      // When dynamic registration is on, an initial access token can gate it.
      registrationAccessToken: text(source.OAUTH_REGISTRATION_ACCESS_TOKEN),
      // Whether a client submitted through the UI needs an administrator's
      // approval before it can be used.
      requireApproval: bool(source.OAUTH_CLIENT_REQUIRE_APPROVAL, true),
      allowUserRegistration: bool(source.OAUTH_CLIENT_ALLOW_USER_REGISTRATION, true)
    },

    security: {
      // RFC 7636. Required for public clients regardless; this setting governs
      // whether a confidential client may also skip it.
      requirePkce: bool(source.OAUTH_REQUIRE_PKCE, true),
      // `plain` exists in RFC 7636 and is not worth supporting: it offers no
      // protection against an interception attack. S256 only.
      requireNonceForIdToken: bool(source.OAUTH_REQUIRE_NONCE, false),
      rotateRefreshTokens: bool(source.OAUTH_ROTATE_REFRESH_TOKENS, true),
      loginRateLimitPerMinute: integer(
        source.OAUTH_LOGIN_RATE_LIMIT_PER_MINUTE,
        10,
        "OAUTH_LOGIN_RATE_LIMIT_PER_MINUTE",
        { min: 1, max: 1000 }
      ),
      tokenRateLimitPerMinute: integer(
        source.OAUTH_TOKEN_RATE_LIMIT_PER_MINUTE,
        120,
        "OAUTH_TOKEN_RATE_LIMIT_PER_MINUTE",
        { min: 1, max: 10000 }
      )
    },

    audit: {
      // How long an audit record is kept. 0 keeps everything.
      //
      // This table had no cleanup path at all — auditService.prune existed with
      // no caller, there is no admin page and no CLI — so it grew for the life
      // of the deployment at one row per sign-in, token, consent, and
      // revocation, and the volume filling is the point at which this issuer
      // stops being able to sign anything. A year is the default the prune
      // function itself already carried; a deployment that must retain longer,
      // or forever, says so.
      retentionDays: integer(source.OAUTH_AUDIT_LOG_RETENTION_DAYS, 365, "OAUTH_AUDIT_LOG_RETENTION_DAYS", {
        min: 0,
        max: 3650
      })
    },

    backchannel: {
      retrySeconds: integer(source.OAUTH_BACKCHANNEL_RETRY_SECONDS, 60, "OAUTH_BACKCHANNEL_RETRY_SECONDS", {
        min: 15,
        max: 3600
      }),
      maxAttempts: integer(source.OAUTH_BACKCHANNEL_MAX_ATTEMPTS, 10, "OAUTH_BACKCHANNEL_MAX_ATTEMPTS", {
        min: 1,
        max: 100
      }),
      // `backchannel_logout_uri` is the only URL on a client that this server
      // requests itself, so it is the only one where a registered value decides
      // what the process connects to. Off by default; a deployment whose
      // relying parties really are on the same private network says so.
      allowPrivateNetwork: bool(source.OAUTH_BACKCHANNEL_ALLOW_PRIVATE_NETWORK, false),
      timeoutMs: integer(source.OAUTH_BACKCHANNEL_TIMEOUT_MS, 5000, "OAUTH_BACKCHANNEL_TIMEOUT_MS", {
        min: 500,
        max: 30000
      })
    },

    mail: {
      // Without SMTP the issuer logs the verification link instead of sending
      // it. That is honest behaviour for a local install and is refused in
      // production when verification is required.
      enabled: bool(source.SMTP_ENABLED, false),
      host: text(source.SMTP_HOST),
      port: integer(source.SMTP_PORT, 587, "SMTP_PORT", { min: 1, max: 65535 }),
      secure: bool(source.SMTP_SECURE, false),
      user: text(source.SMTP_USER),
      password: text(source.SMTP_PASSWORD),
      from: text(source.SMTP_FROM)
    },

    customScopes: parseCustomScopes(source.OAUTH_CUSTOM_SCOPES),
    externalProviders: parseExternalProviders(source.OAUTH_EXTERNAL_IDENTITY_PROVIDERS, {
      allowInsecureHttp
    }),

    // Statically configured clients, for a first-party relying party that should
    // exist before anyone logs in. Same shape as the UI form.
    staticClients: text(source.OAUTH_STATIC_CLIENTS)
  };

  // --- Cross-field checks, all of which must fail the boot ------------------

  if (isProduction) {
    if (new URL(env.publicBaseUrl).protocol !== "https:" && !allowInsecureHttp) {
      throw new Error("PUBLIC_BASE_URL must use HTTPS in production");
    }
    if (new URL(env.issuer).protocol !== "https:" && !allowInsecureHttp) {
      throw new Error("OAUTH_ISSUER must use HTTPS in production");
    }
    if (env.accounts.requireEmailVerification && !env.mail.enabled) {
      throw new Error(
        "OAUTH_REQUIRE_EMAIL_VERIFICATION=true needs SMTP_ENABLED=true, otherwise no user can complete verification"
      );
    }
    if (env.clients.dynamicRegistrationEnabled && !env.clients.registrationAccessToken) {
      throw new Error(
        "OAUTH_DYNAMIC_REGISTRATION_ENABLED=true in production requires OAUTH_REGISTRATION_ACCESS_TOKEN, or anyone can register a client"
      );
    }
  }

  if (env.mail.enabled && (!env.mail.host || !env.mail.from)) {
    throw new Error("SMTP_ENABLED=true requires SMTP_HOST and SMTP_FROM");
  }

  const scopeNames = env.customScopes.map((scope) => scope.name);
  if (new Set(scopeNames).size !== scopeNames.length) {
    throw new Error("OAUTH_CUSTOM_SCOPES contains a duplicate scope name");
  }
  const introspectionClaims = env.customScopes
    .map((scope) => scope.introspectionClaim)
    .filter(Boolean);
  if (new Set(introspectionClaims).size !== introspectionClaims.length) {
    throw new Error("OAUTH_CUSTOM_SCOPES contains a duplicate introspection claim");
  }

  // The scope registry rejects these too, but it is built after the first
  // request rather than at boot. Failing here means a deployment that would
  // silently shadow `email` or forge `sub` never starts.
  for (const scope of env.customScopes) {
    if (STANDARD_SCOPES[scope.name]) {
      throw new Error(
        `OAUTH_CUSTOM_SCOPES entry "${scope.name}" collides with a standard OIDC scope`
      );
    }
    if (scope.introspectionClaim) {
      assertIntrospectionClaimName(scope.introspectionClaim);
    }
    for (const claim of scope.claims) {
      if (RESERVED_CLAIMS.has(claim)) {
        throw new Error(
          `OAUTH_CUSTOM_SCOPES entry "${scope.name}" may not define the reserved claim "${claim}"`
        );
      }
      // A custom scope's values are read from the account's `attributes` map,
      // which an external identity provider rewrites on every login. Letting one
      // declare `email_verified` would hand every relying party a verified
      // address that nobody verified. The standard `email` and `profile` scopes
      // are how these are released, and they read the account record instead.
      if (ACCOUNT_CLAIMS.has(claim)) {
        throw new Error(
          `OAUTH_CUSTOM_SCOPES entry "${scope.name}" may not define "${claim}": it is asserted from the account record. ` +
            "Use the standard scope that releases it."
        );
      }
    }
  }

  const providerNames = env.externalProviders.map((provider) => provider.name);
  if (new Set(providerNames).size !== providerNames.length) {
    throw new Error("OAUTH_EXTERNAL_IDENTITY_PROVIDERS contains a duplicate name");
  }

  if (isProduction && !env.accounts.localLoginEnabled && env.externalProviders.length === 0) {
    throw new Error(
      "OAUTH_LOCAL_LOGIN_ENABLED=false in production requires at least one OAUTH_EXTERNAL_IDENTITY_PROVIDERS handoff provider"
    );
  }

  return env;
}

module.exports = { loadEnv, parseCustomScopes, parseExternalProviders };

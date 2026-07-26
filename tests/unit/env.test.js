"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { loadEnv } = require("../../src/config/env");

// Configuration is the one part of this server that cannot be fixed by a retry:
// a bad value either stops the boot or is trusted for the process's lifetime.
// These tests cover the second case — the settings where an accepted-but-wrong
// value would quietly weaken the issuer rather than break it visibly.
//
// `loadEnv` takes its source as an argument precisely so this can be tested
// without touching `process.env`.

const SECRET = "0123456789abcdef0123456789abcdef"; // 32 chars, the documented minimum

test("a bare development environment boots with safe defaults", () => {
  const env = loadEnv({});

  // No PUBLIC_BASE_URL: a first clone gets loopback rather than a failed boot.
  assert.equal(env.publicBaseUrl, "http://127.0.0.1:3010");
  // The issuer defaults to the public base URL. Relying parties compare the
  // issuer byte-for-byte, so guessing it independently is how a deployment ends
  // up advertising one value and signing another.
  assert.equal(env.issuer, env.publicBaseUrl);
  assert.equal(env.database.provider, "sqlite");

  // The defaults that matter for security, asserted so a change to any of them
  // has to be deliberate.
  assert.equal(env.security.requirePkce, true);
  assert.equal(env.security.rotateRefreshTokens, true);
  assert.equal(env.clients.dynamicRegistrationEnabled, false, "an open registration endpoint must be opt-in");
  assert.equal(env.clients.requireApproval, true);
  assert.equal(env.trustProxy, false, "trusting a forwarded address by default lets a caller spoof it");
  assert.equal(env.externalProviders.length, 0);
  assert.equal(env.customScopes.length, 0);
});

test("the issuer identifier is normalized so it compares byte-for-byte", () => {
  const env = loadEnv({
    PUBLIC_BASE_URL: "https://id.example.com/",
    OAUTH_ISSUER: "https://id.example.com///"
  });
  assert.equal(env.issuer, "https://id.example.com");
  assert.equal(env.publicBaseUrl, "https://id.example.com");
});

test("production refuses a plaintext issuer", () => {
  assert.throws(
    () =>
      loadEnv({
        NODE_ENV: "production",
        PUBLIC_BASE_URL: "http://id.example.com"
      }),
    /must use HTTPS/
  );

  // ...and the escape hatch is explicit, for a deployment terminating TLS at a
  // proxy. It has to be asked for by name.
  const env = loadEnv({
    NODE_ENV: "production",
    OAUTH_ALLOW_INSECURE_HTTP: "true",
    PUBLIC_BASE_URL: "http://id.internal",
    OAUTH_SIGNING_KEYS_JSON: "[]"
  });
  assert.equal(env.publicBaseUrl, "http://id.internal");
});

test("production will not enable dynamic registration without a gate on it", () => {
  const base = {
    NODE_ENV: "production",
    PUBLIC_BASE_URL: "https://id.example.com",
    OAUTH_DYNAMIC_REGISTRATION_ENABLED: "true"
  };
  assert.throws(() => loadEnv(base), /OAUTH_REGISTRATION_ACCESS_TOKEN/);

  const env = loadEnv({ ...base, OAUTH_REGISTRATION_ACCESS_TOKEN: SECRET });
  assert.equal(env.clients.dynamicRegistrationEnabled, true);
});

test("production will not require email verification it cannot deliver", () => {
  // Requiring a confirmed address with no way to send the message locks every
  // new account out permanently, which is a worse failure than not booting.
  assert.throws(
    () =>
      loadEnv({
        NODE_ENV: "production",
        PUBLIC_BASE_URL: "https://id.example.com",
        OAUTH_REQUIRE_EMAIL_VERIFICATION: "true"
      }),
    /SMTP_ENABLED/
  );
});

test("SMTP needs enough configuration to actually send", () => {
  assert.throws(() => loadEnv({ SMTP_ENABLED: "true", SMTP_HOST: "smtp.example.com" }), /SMTP_FROM/);
  const env = loadEnv({ SMTP_ENABLED: "true", SMTP_HOST: "smtp.example.com", SMTP_FROM: "id@example.com" });
  assert.equal(env.mail.enabled, true);
});

test("a lifetime outside its range stops the boot", () => {
  // OIDC Core section 3.1.2.5: an authorization code should live no longer than
  // ten minutes. The bound is in the config so a deployment cannot widen it.
  assert.throws(() => loadEnv({ OAUTH_AUTHORIZATION_CODE_TTL: "3600" }), /OAUTH_AUTHORIZATION_CODE_TTL/);
  assert.throws(() => loadEnv({ OAUTH_ACCESS_TOKEN_TTL: "10" }), /OAUTH_ACCESS_TOKEN_TTL/);
  assert.throws(() => loadEnv({ PORT: "0" }), /PORT/);
  assert.throws(() => loadEnv({ OAUTH_MIN_PASSWORD_LENGTH: "4" }), /OAUTH_MIN_PASSWORD_LENGTH/);
});

test("a boolean setting rejects a value it cannot interpret", () => {
  // Silently reading "maybe" as false is how a setting an operator believes is
  // on turns out to be off.
  assert.throws(() => loadEnv({ OAUTH_REQUIRE_PKCE: "maybe" }), /boolean/);
  assert.equal(loadEnv({ OAUTH_REQUIRE_PKCE: "off" }).security.requirePkce, false);
  assert.equal(loadEnv({ OAUTH_REQUIRE_PKCE: "yes" }).security.requirePkce, true);
});

test("postgresql requires a connection string; sqlite has a default", () => {
  assert.throws(() => loadEnv({ DATABASE_PROVIDER: "postgresql" }), /DATABASE_URL is required/);
  assert.throws(() => loadEnv({ DATABASE_PROVIDER: "mysql" }), /sqlite or postgresql/);

  const pg = loadEnv({ DATABASE_PROVIDER: "postgresql", DATABASE_URL: "postgresql://localhost/oauth" });
  assert.equal(pg.database.url, "postgresql://localhost/oauth");
  assert.match(loadEnv({}).database.url, /^file:/);
});

test("a sqlite path is resolved against the project root, not the schema's directory", () => {
  // Prisma resolves a relative `file:` URL against the directory holding the
  // schema, and the schemas live in prisma/<provider>/. Left relative, the CLI
  // and the app open two different files: `prisma/sqlite/data/` for one and
  // `data/` for the other. In a container that means the database — and the
  // signing key stored in it — sits outside the mounted volume, so every token
  // ever issued stops verifying when the container is replaced.
  const root = path.resolve(__dirname, "..", "..").replaceAll("\\", "/");

  const url = loadEnv({}).database.url;
  assert.equal(url, `file:${root}/data/knight-oauth.db`);
  assert.ok(!url.includes("prisma/sqlite"), "the default must not resolve inside the schema directory");

  // A configured relative path gets the same treatment.
  assert.equal(
    loadEnv({ DATABASE_URL: "file:./var/oauth.db" }).database.url,
    `file:${root}/var/oauth.db`
  );

  // An absolute path is the operator's decision and is left exactly as written,
  // as is an in-memory database, which has no path to resolve.
  const absolute = process.platform === "win32" ? "file:C:/tmp/oauth.db" : "file:/tmp/oauth.db";
  assert.equal(loadEnv({ DATABASE_URL: absolute }).database.url, absolute);
  assert.equal(loadEnv({ DATABASE_URL: "file::memory:" }).database.url, "file::memory:");

  // sqlite with something that is not a file URL is a mistake worth failing on:
  // a postgres URL left behind after switching the provider back would otherwise
  // be handed to a sqlite client.
  assert.throws(
    () => loadEnv({ DATABASE_URL: "postgresql://localhost/oauth" }),
    /must start with "file:"/
  );
});

test("only a supported signing algorithm is accepted", () => {
  assert.throws(() => loadEnv({ OAUTH_SIGNING_ALGORITHM: "HS256" }), /OAUTH_SIGNING_ALGORITHM/);
  assert.throws(() => loadEnv({ OAUTH_SIGNING_ALGORITHM: "none" }), /OAUTH_SIGNING_ALGORITHM/);
  for (const algorithm of ["EdDSA", "RS256", "ES256"]) {
    assert.equal(loadEnv({ OAUTH_SIGNING_ALGORITHM: algorithm }).signing.algorithm, algorithm);
  }
});

test("a custom scope may not shadow a standard one or forge a reserved claim", () => {
  const custom = (entries) => ({ OAUTH_CUSTOM_SCOPES: JSON.stringify(entries) });

  // A deployment redefining `email` would change what a relying party thinks it
  // asked for, and one defining `sub` could name any account it liked.
  assert.throws(() => loadEnv(custom([{ name: "email", claims: [] }])), /collides with a standard OIDC scope/);
  assert.throws(
    () => loadEnv(custom([{ name: "billing", claims: ["sub"] }])),
    /reserved claim/
  );
  assert.throws(
    () => loadEnv(custom([{ name: "billing" }, { name: "billing" }])),
    /duplicate scope name/
  );
  assert.throws(() => loadEnv({ OAUTH_CUSTOM_SCOPES: "{" }), /valid JSON/);
  assert.throws(() => loadEnv({ OAUTH_CUSTOM_SCOPES: "{}" }), /JSON array/);
  assert.throws(() => loadEnv(custom([{ description: "no name" }])), /requires a name/);
});

test("a custom scope may not assert a claim the issuer makes from the account", () => {
  const custom = (entries) => ({ OAUTH_CUSTOM_SCOPES: JSON.stringify(entries) });

  // A custom scope's values are read from the account's `attributes` map, which
  // an external identity provider rewrites on every sign-in — and claimsFor
  // applies them after the standard claims, so the upstream value won. An
  // upstream sending `{ email_verified: true, email: "ceo@corp.com" }` would put
  // a verified address nobody verified into every relying party's ID token,
  // straight past the issuer's own rule that a synthesised `@external.invalid`
  // address must always report `email_verified: false`.
  for (const claim of ["email", "email_verified", "name", "preferred_username", "picture", "phone_number_verified"]) {
    assert.throws(
      () => loadEnv(custom([{ name: "billing", claims: [claim] }])),
      /asserted from the account record/,
      `a custom scope was allowed to define ${claim}`
    );
  }

  // The distinction that makes this safe to enforce: these are refused to
  // *custom* scopes, not reserved outright. Reserving them would stop the
  // standard `email` and `profile` scopes releasing them at all, which is the
  // mechanism they exist to be.
  const env = loadEnv(custom([{ name: "billing", claims: ["billing_tier"] }]));
  assert.equal(env.customScopes[0].claims[0], "billing_tier");
});

test("a custom scope reads its claims from the account's attributes", () => {
  // This is the whole of the private-extension mechanism: the core has no
  // knowledge of `credits.read` or `knight_uid`, and a deployment that wants
  // them configures them rather than patching code.
  const env = loadEnv({
    OAUTH_CUSTOM_SCOPES: JSON.stringify([
      { name: "credits.read", description: "Read your balance", claims: ["knight_uid"] },
      { name: "credits.admin", claims: [], adminOnly: true }
    ])
  });

  const [read, admin] = env.customScopes;
  assert.equal(read.description, "Read your balance");
  assert.deepEqual(read.claimsFrom({ attributes: { knight_uid: 42, other: "x" } }), { knight_uid: 42 });
  // An absent attribute is omitted rather than emitted as null, so a claim the
  // account has no value for simply is not in the token.
  assert.deepEqual(read.claimsFrom({ attributes: {} }), {});
  assert.equal(read.allowFor, null);

  assert.equal(admin.adminOnly, true);
  assert.equal(admin.allowFor({ role: "ADMIN" }), true);
  assert.equal(admin.allowFor({ role: "USER" }), false);
  // A scope with no claims gets no claim source at all, rather than one that
  // returns an empty object on every token.
  assert.equal(admin.claimsFrom, null);
});

test("an external identity provider must be verifiable", () => {
  const provider = (entry) => ({ OAUTH_EXTERNAL_IDENTITY_PROVIDERS: JSON.stringify([entry]) });
  const valid = {
    name: "upstream",
    kind: "handoff",
    startUrl: "https://www.example.com/handoff/start",
    sharedSecret: SECRET
  };

  // Without a secret the issuer would be believing whatever identity an
  // unauthenticated caller asserted.
  assert.throws(() => loadEnv(provider({ ...valid, sharedSecret: "" })), /requires a sharedSecret/);
  assert.throws(() => loadEnv(provider({ ...valid, sharedSecret: "short" })), /at least 32 characters/);
  assert.throws(() => loadEnv(provider({ ...valid, name: "" })), /requires a name/);
  assert.throws(() => loadEnv(provider({ ...valid, kind: "saml" })), /Unsupported external identity provider kind/);
  // A handoff start URL is a server-chosen destination a user is sent to, so it
  // gets no plaintext carve-out outside development.
  assert.throws(
    () =>
      loadEnv({
        NODE_ENV: "production",
        PUBLIC_BASE_URL: "https://id.example.com",
        ...provider({ ...valid, startUrl: "http://www.example.com/handoff/start" })
      }),
    /must use HTTPS/
  );

  const env = loadEnv(provider(valid));
  assert.equal(env.externalProviders.length, 1);
  assert.equal(env.externalProviders[0].displayName, "upstream");
  assert.equal(env.externalProviders[0].ticketTtlSeconds, 60);
  assert.throws(
    () => loadEnv({ OAUTH_EXTERNAL_IDENTITY_PROVIDERS: JSON.stringify([valid, valid]) }),
    /duplicate name/
  );
});

test("nothing in a loaded config carries a Knight-specific default", () => {
  // This project was extracted from a larger site. The point of the extraction
  // is that a fresh install belongs to whoever runs it, so no hostname, brand,
  // or scope from that origin may survive as a default.
  const env = loadEnv({});
  const serialized = JSON.stringify(env);
  assert.doesNotMatch(serialized, /knightx/i);
  assert.equal(env.branding.logoUrl, "");
  assert.equal(env.branding.supportUrl, "");
});

test("the environment compose.yml sets actually boots", () => {
  // compose.yml promises that `docker compose up --build` works with no .env at
  // all. It also sets NODE_ENV=production, which turns off two defaults that a
  // zero-config boot depends on: http is rejected, and the issuer refuses to
  // generate a signing key. Both had to be re-enabled explicitly in compose.yml,
  // and this is what catches it if either is dropped — otherwise the failure
  // appears only as a container that will not start, which nobody sees until
  // they try the documented command.
  //
  // Keep in sync with the `environment:` block in compose.yml.
  const compose = {
    NODE_ENV: "production",
    DATABASE_URL: "file:/app/data/knight-oauth.db",
    PUBLIC_BASE_URL: "http://127.0.0.1:3010",
    OAUTH_ALLOW_INSECURE_HTTP: "true",
    OAUTH_ALLOW_GENERATED_KEYS: "true",
    TRUST_PROXY: "false"
  };

  const env = loadEnv(compose);
  assert.equal(env.isProduction, true);
  assert.equal(env.issuer, "http://127.0.0.1:3010");
  assert.equal(
    env.signing.allowGeneratedKeys,
    true,
    "the container has no key configured, so it must be allowed to generate one or it cannot serve a single token"
  );

  // The other half of the guarantee: the permissiveness above must come from
  // compose.yml, never from the defaults. A production deployment that does not
  // go through that file still has to opt in.
  assert.throws(
    () => loadEnv({ NODE_ENV: "production", PUBLIC_BASE_URL: "http://id.example.com" }),
    /must use HTTPS/,
    "plaintext http must not become acceptable in production by default"
  );
  assert.equal(
    loadEnv({ NODE_ENV: "production", PUBLIC_BASE_URL: "https://id.example.com" }).signing
      .allowGeneratedKeys,
    false,
    "a real production deployment must supply its own key rather than generate one"
  );
});

"use strict";

const assert = require("node:assert/strict");
const { after, before, describe, it } = require("node:test");

const { withDatabase } = require("../helpers/database");
const { loadEnv } = require("../../src/config/env");
const { start } = require("../../src/server");

// The entry point.
//
// The other suites build the app with supertest, which never opens a port and
// never runs any of what `src/server.js` adds: the boot-time checks, the static
// client import, the maintenance timers, and the drain. Those are the parts that
// only fail in a real deployment, so they get a real listening server on port 0.
//
// This is also the regression test for a boot that used to fail outright. The
// runtime read no `.env` and let Prisma resolve DATABASE_URL itself, so a fresh
// clone died with a schema validation error before it reached this file.

const CONFIG = {
  PUBLIC_BASE_URL: "http://127.0.0.1:3010",
  OAUTH_ALLOW_GENERATED_KEYS: "true"
};

const quiet = { error() {}, warn() {}, info() {} };

describe("the entry point", () => {
  let db;

  before(async () => {
    db = await withDatabase();
  });

  after(async () => {
    await db.close();
  });

  /**
   * `start` disconnects the shared Prisma client on close, and this suite's one
   * is shared across tests, so each handle is closed with the server rather than
   * by tearing the client down. The prisma double below forwards everything to
   * the real client except `$disconnect`.
   */
  function prismaForTest() {
    return new Proxy(db.prisma, {
      get(target, property) {
        if (property === "$disconnect") return async () => {};
        const value = target[property];
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
  }

  async function boot(extra = {}) {
    return start({
      env: loadEnv({ ...CONFIG, ...extra }),
      // The OS picks a free port, so the suite cannot collide with a server the
      // developer already has running. It is an argument rather than PORT=0
      // because the configuration rightly refuses port 0: an issuer whose port
      // nobody can predict is a misconfiguration.
      port: 0,
      prisma: prismaForTest(),
      logger: quiet
    });
  }

  it("listens, serves discovery, and reports healthy", async () => {
    const handle = await boot();
    try {
      assert.ok(handle.port > 0, "the server did not report a bound port");

      const base = `http://127.0.0.1:${handle.port}`;
      const health = await fetch(`${base}/healthz`);
      assert.equal(health.status, 200);
      assert.equal((await health.json()).status, "ok");

      // Reaching this over a real socket, rather than through supertest, is what
      // proves the process is actually serving.
      const discovery = await fetch(`${base}/.well-known/openid-configuration`);
      assert.equal(discovery.status, 200);
      const metadata = await discovery.json();
      assert.equal(metadata.issuer, "http://127.0.0.1:3010");
    } finally {
      await handle.close();
    }
  });

  it("has a signing key before the port opens", async () => {
    // The key is generated during boot verification, not lazily on the first
    // request, so JWKS is populated on the very first call. A deployment where
    // the key was missing would otherwise fail at the first token exchange.
    const handle = await boot();
    try {
      const jwks = await (await fetch(`http://127.0.0.1:${handle.port}/oauth2/jwks`)).json();
      assert.equal(jwks.keys.length, 1);
      assert.equal(jwks.keys[0].alg, "RS256");
      // A public JWKS must never carry private parameters. `d` is the RSA private
      // exponent; its presence would publish the signing key.
      assert.equal(jwks.keys[0].d, undefined);
    } finally {
      await handle.close();
    }
  });

  it("imports OAUTH_STATIC_CLIENTS, and accepts clientName for the client name", async () => {
    const handle = await boot({
      OAUTH_STATIC_CLIENTS: JSON.stringify([
        {
          clientId: "static-rp",
          // Not `name`: every neighbouring key is the camelCase of an RFC 7591
          // field, so this is the spelling an operator writes, and the one
          // .env.example documents.
          clientName: "Statically Configured RP",
          clientSecret: "a-static-client-secret-for-the-test-suite",
          redirectUris: ["https://rp.example/callback"],
          grantTypes: ["authorization_code", "refresh_token"],
          scopes: ["openid", "profile"],
          isFirstParty: true
        }
      ])
    });
    try {
      const client = await handle.services.clients.findByClientId("static-rp");
      assert.ok(client, "the static client was not imported");
      assert.equal(client.name, "Statically Configured RP");
      assert.equal(client.status, "APPROVED");

      // The secret is stored as a hash and the record must not carry it back.
      assert.equal(client.clientSecret, undefined);
      assert.equal(client.clientSecretHash, undefined);
    } finally {
      await handle.close();
    }
  });

  it("refuses to start on a configuration error rather than serving a broken issuer", async () => {
    // A confidential client with no secret could never authenticate, so importing
    // it and starting anyway would produce an issuer that fails at the token
    // endpoint with no explanation.
    await assert.rejects(
      () =>
        boot({
          OAUTH_STATIC_CLIENTS: JSON.stringify([
            { clientId: "no-secret", clientName: "No Secret", redirectUris: ["https://rp.example/cb"] }
          ])
        }),
      /OAUTH_STATIC_CLIENTS could not be imported.*clientSecret/s
    );
  });

  it("stops accepting connections after close", async () => {
    const handle = await boot();
    const port = handle.port;
    await handle.close();

    await assert.rejects(
      () => fetch(`http://127.0.0.1:${port}/healthz`),
      // The rejection is a connection failure; which errno depends on the
      // platform, so the assertion is only that nothing answered.
      (error) => error instanceof Error
    );
  });

  it("closes idempotently", async () => {
    // The signal handler can be entered twice, and a shutdown that threw the
    // second time would turn a clean drain into a non-zero exit.
    const handle = await boot();
    await handle.close();
    await handle.close();
  });
});

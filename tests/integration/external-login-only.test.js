"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { after, before, describe, it } = require("node:test");
const request = require("supertest");

const { withDatabase } = require("../helpers/database");
const { loadEnv } = require("../../src/config/env");
const { createApp } = require("../../src/app");

const HANDOFF_SECRET = "external-login-only-test-secret-with-more-than-32-chars";

describe("external-login-only browser routing", () => {
  let db;
  let app;
  let config;

  before(async () => {
    db = await withDatabase();
    config = loadEnv({
      PUBLIC_BASE_URL: "https://oauth.example.test",
      DATABASE_PROVIDER: db.provider,
      DATABASE_URL: db.url,
      OAUTH_ALLOW_GENERATED_KEYS: "true",
      OAUTH_LOCAL_LOGIN_ENABLED: "false",
      OAUTH_EXTERNAL_IDENTITY_PROVIDERS: JSON.stringify([
        {
          name: "knight",
          kind: "handoff",
          displayName: "Knight",
          startUrl: "https://www.knightx.asia/oauth2/handoff/start",
          sharedSecret: HANDOFF_SECRET,
          useSubjectAsUserId: true
        }
      ])
    });
    app = createApp({ env: config, prisma: db.prisma, logger: { error() {}, warn() {}, info() {} } });
  });

  after(async () => {
    await db?.close();
  });

  it("never renders the issuer's own login form in handoff-only mode", async () => {
    const response = await request(app).get("/login?next=%2Faccount").expect(302);
    assert.equal(response.headers.location, "/login/external/knight?next=%2Faccount");
    assert.doesNotMatch(response.text, /Sign in|Email or username/);
  });

  it("sends the external login route directly to the configured main-site handoff", async () => {
    const agent = request.agent(app);
    const response = await agent.get("/login/external/knight?next=%2Faccount").expect(302);
    const handoff = new URL(response.headers.location);

    assert.equal(handoff.origin, "https://www.knightx.asia");
    assert.equal(handoff.pathname, "/oauth2/handoff/start");
    assert.match(handoff.searchParams.get("state") || "", /^[A-Za-z0-9_-]{32,}$/);
    assert.equal(handoff.searchParams.get("return_to"), "https://oauth.example.test/login/external/knight/callback");
    assert.equal(handoff.searchParams.get("client"), "https://oauth.example.test");
    assert.match(response.headers["set-cookie"].join(";"), /__Host-koauth_session=/);
  });

  it("uses the main-site handoff for an anonymous authorization request", async () => {
    const client = await app.locals.services.clients.create(
      {
        name: "Credit Portal",
        description: "A first-party client",
        clientType: "public",
        redirectUris: ["https://credit.example.test/callback"],
        scopes: ["openid"],
        grantTypes: ["authorization_code"],
        tokenEndpointAuthMethod: "none",
        requireConsent: true
      },
      { status: "APPROVED" }
    );
    const challenge = crypto.createHash("sha256").update("test-verifier", "ascii").digest("base64url");
    const query = new URLSearchParams({
      client_id: client.client.clientId,
      redirect_uri: client.client.redirectUris[0],
      response_type: "code",
      scope: "openid",
      state: "external-login-state",
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    const response = await request(app).get(`/oauth2/authorize?${query}`).expect(302);
    const login = new URL(response.headers.location, config.publicBaseUrl);
    assert.equal(login.pathname, "/login/external/knight");
    const next = login.searchParams.get("next");
    assert.match(next || "", /^\/oauth2\/authorize\/continue\?request=/);
  });
});

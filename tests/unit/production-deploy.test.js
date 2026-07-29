"use strict";

const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");
const request = require("supertest");

const { createRateLimitMiddleware } = require("../../src/middleware/rateLimit");

const root = path.resolve(__dirname, "..", "..");
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), "utf8");

test("the production overlay binds an immutable image and an explicit proxy identity", () => {
  const compose = read("deploy/server/compose.production.override.yml");

  assert.match(compose, /^\s{4}image:\s*\$\{OAUTH_IMAGE:\?/m);
  assert.match(compose, /^\s{6}TRUST_PROXY:\s*\$\{OAUTH_TRUSTED_PROXY:\?/m);
  assert.match(compose, /^\s{6}oauth_proxy:$/m);
  assert.match(compose, /^\s{8}ipv4_address:\s*\$\{OAUTH_CONTAINER_IP:\?/m);
  assert.match(compose, /^\s{4}name:\s*\$\{OAUTH_PROXY_NETWORK_NAME:\?/m);
  assert.doesNotMatch(compose, /^\s{6}- stack_proxy$/m);
  assert.doesNotMatch(compose, /^\s{4}image:\s*knight-oauth:[0-9a-f]+$/m);
});

test("the production overlay replaces development environment files with explicit trust-root allowlists", () => {
  const compose = read("deploy/server/compose.production.override.yml");
  const environment = read("deploy/server/.env.production.example");

  assert.match(compose, /^\s{4}env_file:\s*!override\s*\[\]\s*$/m);
  assert.match(compose, /^\s{6}OAUTH_STATIC_CLIENTS:\s*\$\{OAUTH_STATIC_CLIENTS:-\[\]\}$/m);
  assert.match(
    compose,
    /^\s{6}OAUTH_EXTERNAL_IDENTITY_PROVIDERS:\s*\$\{OAUTH_EXTERNAL_IDENTITY_PROVIDERS:-\[\]\}$/m
  );
  assert.match(environment, /^OAUTH_STATIC_CLIENTS=\[\]$/m);
  assert.match(environment, /^OAUTH_EXTERNAL_IDENTITY_PROVIDERS=\[\]$/m);
});

test("the production environment template starts with bootstrap authority disabled", () => {
  const environment = read("deploy/server/.env.production.example");

  assert.match(environment, /^OAUTH_REGISTRATION_ENABLED=false$/m);
  assert.match(environment, /^OAUTH_FIRST_USER_IS_ADMIN=false$/m);
  assert.doesNotMatch(environment, /^OAUTH_REGISTRATION_ENABLED=true$/m);
  assert.doesNotMatch(environment, /^OAUTH_FIRST_USER_IS_ADMIN=true$/m);
});

async function exerciseTokenLimit(trustProxy) {
  const app = express();
  app.set("trust proxy", trustProxy);
  app.use(express.urlencoded({ extended: false }));
  app.use(
    createRateLimitMiddleware({
      config: {
        security: {
          loginRateLimitPerMinute: 1,
          tokenRateLimitPerMinute: 1
        }
      },
      logger: { warn() {} },
      now: () => 1_000
    })
  );
  app.post("/oauth2/token", (req, res) => res.json({ ip: req.ip }));

  const send = (forwardedFor) =>
    request(app).post("/oauth2/token").set("X-Forwarded-For", forwardedFor).type("form").send({});

  const first = await send("198.51.100.10");
  const repeated = await send("198.51.100.10");
  const rotated = await send("198.51.100.11");
  return { first, repeated, rotated };
}

test("a direct non-Caddy peer cannot rotate the production IP limit", async () => {
  const result = await exerciseTokenLimit("172.31.255.2");

  assert.equal(result.first.status, 200);
  assert.notEqual(result.first.body.ip, "198.51.100.10");
  assert.equal(result.repeated.status, 429);
  assert.equal(result.rotated.status, 429);
});

test("an explicitly trusted proxy still preserves its observed client address", async () => {
  // Supertest connects over loopback, so `loopback` models the same explicit
  // address trust that production assigns to Caddy without requiring a Docker
  // interface in the unit-test process.
  const result = await exerciseTokenLimit("loopback");

  assert.equal(result.first.status, 200);
  assert.equal(result.first.body.ip, "198.51.100.10");
  assert.equal(result.repeated.status, 429);
  assert.equal(result.rotated.status, 200);
  assert.equal(result.rotated.body.ip, "198.51.100.11");
});

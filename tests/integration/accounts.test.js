"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { after, before, describe, it } = require("node:test");

const { withDatabase } = require("../helpers/database");
const { loadEnv } = require("../../src/config/env");
const { hashToken, verifyPassword } = require("../../src/lib/crypto");
const { createAccountService } = require("../../src/services/accountService");
const { createAuditService } = require("../../src/services/auditService");
const { createSessionService } = require("../../src/services/sessionService");
const { createExternalIdentityService } = require("../../src/services/externalIdentityService");

const SHARED_SECRET = "test-shared-secret-at-least-32-characters-long";

/** Mints a handoff ticket the way an upstream site would. */
function signTicket(payload, secret = SHARED_SECRET) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${signature}`;
}

function ticketPayload(overrides = {}) {
  const seconds = Math.floor(Date.now() / 1000);
  return {
    iss: "upstream",
    aud: "http://127.0.0.1:3010",
    sub: "upstream-user-1",
    iat: seconds,
    exp: seconds + 60,
    jti: crypto.randomUUID(),
    state: "handoff-state-value",
    ...overrides
  };
}

/**
 * Wraps Prisma so one selected write fails inside an interactive transaction.
 * The real database still performs every earlier write, which makes rollback
 * behavior observable instead of replacing it with a hand-written database
 * double.
 */
function failOnceInTransaction(prisma, { model, method }) {
  let failed = false;

  function wrap(client) {
    return new Proxy(client, {
      get(target, property) {
        if (property === "$transaction") {
          return (operation, options) => {
            if (typeof operation !== "function") {
              return target.$transaction(operation, options);
            }
            return target.$transaction((transaction) => operation(wrap(transaction)), options);
          };
        }

        const value = target[property];
        if (property !== model || !value) {
          return typeof value === "function" ? value.bind(target) : value;
        }

        return new Proxy(value, {
          get(delegate, delegateMethod) {
            const delegateValue = delegate[delegateMethod];
            if (delegateMethod !== method || typeof delegateValue !== "function") {
              return typeof delegateValue === "function" ? delegateValue.bind(delegate) : delegateValue;
            }
            return async (...args) => {
              if (!failed) {
                failed = true;
                throw new Error("injected transaction failure");
              }
              return delegateValue.apply(delegate, args);
            };
          }
        });
      }
    });
  }

  return { prisma: wrap(prisma), didFail: () => failed };
}

/** Records database writes made through an interactive transaction. */
function observeTransactionWrites(prisma) {
  const writes = [];
  const writeMethods = new Set(["create", "createMany", "update", "updateMany", "delete", "deleteMany"]);

  function wrapTransaction(client) {
    return new Proxy(client, {
      get(target, model) {
        const delegate = target[model];
        if (!delegate || typeof delegate !== "object") {
          return typeof delegate === "function" ? delegate.bind(target) : delegate;
        }
        return new Proxy(delegate, {
          get(modelDelegate, method) {
            const operation = modelDelegate[method];
            if (typeof operation !== "function") return operation;
            return async (...args) => {
              if (writeMethods.has(method)) writes.push(`${String(model)}.${String(method)}`);
              return operation.apply(modelDelegate, args);
            };
          }
        });
      }
    });
  }

  const observed = new Proxy(prisma, {
    get(target, property) {
      if (property === "$transaction") {
        return (operation, options) => {
          if (typeof operation !== "function") return target.$transaction(operation, options);
          return target.$transaction((transaction) => operation(wrapTransaction(transaction)), options);
        };
      }
      const value = target[property];
      return typeof value === "function" ? value.bind(target) : value;
    }
  });
  return { prisma: observed, writes };
}

function deferred() {
  let resolve;
  const promise = new Promise((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

/** Pauses the first selected read after the database returned its snapshot. */
function pauseOnceAfterRead(prisma, { model, method }) {
  const reached = deferred();
  const resume = deferred();
  let paused = false;
  const delegate = prisma[model];
  const wrappedDelegate = new Proxy(delegate, {
    get(target, property) {
      const value = target[property];
      if (property !== method || typeof value !== "function") {
        return typeof value === "function" ? value.bind(target) : value;
      }
      return async (...args) => {
        const result = await value.apply(target, args);
        if (!paused) {
          paused = true;
          reached.resolve();
          await resume.promise;
        }
        return result;
      };
    }
  });
  const wrappedPrisma = new Proxy(prisma, {
    get(target, property) {
      if (property === model) return wrappedDelegate;
      const value = target[property];
      return typeof value === "function" ? value.bind(target) : value;
    }
  });
  return { prisma: wrappedPrisma, reached: reached.promise, resume: resume.resolve };
}

/** Makes every participant receive its database snapshot before any proceeds. */
function synchronizeReads(prisma, { model, method, participants }) {
  const release = deferred();
  let arrived = 0;
  const delegate = prisma[model];
  const wrappedDelegate = new Proxy(delegate, {
    get(target, property) {
      const value = target[property];
      if (property !== method || typeof value !== "function") {
        return typeof value === "function" ? value.bind(target) : value;
      }
      return async (...args) => {
        const result = await value.apply(target, args);
        arrived += 1;
        if (arrived === participants) release.resolve();
        await release.promise;
        return result;
      };
    }
  });
  return new Proxy(prisma, {
    get(target, property) {
      if (property === model) return wrappedDelegate;
      const value = target[property];
      return typeof value === "function" ? value.bind(target) : value;
    }
  });
}

async function seedRevocableCredentials({ prisma, sessions, userId }) {
  const { sid, session } = await sessions.create({ userId });
  const suffix = crypto.randomUUID();
  const clientId = `transaction-client-${suffix}`;
  await prisma.oAuthClient.create({
    data: {
      id: crypto.randomUUID(),
      clientId,
      name: "Transaction regression client",
      redirectUris: "https://client.test/callback",
      allowedScopes: "openid",
      status: "APPROVED"
    }
  });
  const refreshToken = await prisma.refreshToken.create({
    data: {
      id: crypto.randomUUID(),
      tokenHash: crypto.createHash("sha256").update(crypto.randomUUID()).digest("hex"),
      familyId: crypto.randomUUID(),
      clientId,
      userId,
      sessionId: session.id,
      scopes: "openid",
      authTime: new Date(),
      expiresAt: new Date(Date.now() + 60_000)
    }
  });
  const oidcSession = await prisma.oidcSession.create({
    data: {
      id: crypto.randomUUID(),
      sessionId: session.id,
      clientId,
      userId,
      authTime: session.authTime,
      lastSeenAt: new Date()
    }
  });
  return {
    sid,
    sessionId: session.id,
    refreshTokenId: refreshToken.id,
    oidcSessionId: oidcSession.id
  };
}

describe("local accounts and external identity", () => {
  let db;
  let prisma;
  let config;
  let accounts;
  let sessions;
  let external;
  let sentMail;

  before(async () => {
    db = await withDatabase();
    prisma = db.prisma;

    config = loadEnv({
      OAUTH_EXTERNAL_IDENTITY_PROVIDERS: JSON.stringify([
        {
          name: "upstream",
          kind: "handoff",
          displayName: "Upstream Site",
          startUrl: "https://upstream.test/oauth2/handoff/start",
          sharedSecret: SHARED_SECRET,
          subjectMode: "upstream"
        }
      ])
    });

    sentMail = [];
    const mailer = {
      sendEmailVerification: async (message) => sentMail.push({ kind: "verify", ...message }),
      sendPasswordReset: async (message) => sentMail.push({ kind: "reset", ...message }),
      sendExistingAccountNotice: async (message) => sentMail.push({ kind: "exists", ...message })
    };
    const auditLog = createAuditService({ prisma, logger: { error() {} } });

    accounts = createAccountService({ prisma, config, mailer, auditLog });
    sessions = createSessionService({ prisma, config, auditLog });
    external = createExternalIdentityService({ prisma, config, accounts, auditLog });
  });

  after(async () => {
    await db?.close();
  });

  it("registers the first account as an administrator", async () => {
    const { account } = await accounts.register({
      email: "First@Example.com",
      password: "correct-horse-battery-staple",
      username: "first"
    });
    assert.equal(account.role, "ADMIN");
    // The address is stored folded, so a login with different case still matches.
    assert.equal(account.email, "first@example.com");
    assert.equal(account.status, "ACTIVE");
    // `sub` must be opaque: not the email, not the username.
    assert.match(account.id, /^[0-9a-f-]{36}$/);
    assert.notEqual(account.id, account.email);
  });

  it("registers a second account as an ordinary user", async () => {
    const { account } = await accounts.register({
      email: "second@example.com",
      password: "another-long-enough-password"
    });
    assert.equal(account.role, "USER");
  });

  it("does not disclose that an email is already registered", async () => {
    const result = await accounts.register({
      email: "second@example.com",
      password: "yet-another-long-password"
    });
    // No account, no error the caller could distinguish from success, and the
    // existing holder is notified instead.
    assert.equal(result.duplicateEmail, true);
    assert.equal(result.account, null);
    assert.ok(sentMail.some((mail) => mail.kind === "exists" && mail.email === "second@example.com"));
  });

  it("rejects a password below the configured minimum", async () => {
    await assert.rejects(
      accounts.register({ email: "short@example.com", password: "short" }),
      /at least 12 characters/
    );
  });

  it("rejects a duplicate username with a distinct message", async () => {
    await assert.rejects(
      accounts.register({
        email: "third@example.com",
        password: "a-perfectly-fine-password",
        username: "first"
      }),
      /username is taken/
    );
  });

  it("authenticates with an email or a username", async () => {
    const byEmail = await accounts.authenticate({
      identifier: "FIRST@example.com",
      password: "correct-horse-battery-staple"
    });
    assert.equal(byEmail.ok, true);

    const byUsername = await accounts.authenticate({
      identifier: "first",
      password: "correct-horse-battery-staple"
    });
    assert.equal(byUsername.ok, true);
    assert.equal(byUsername.account.id, byEmail.account.id);
  });

  it("blocks every local-password entry point in handoff-only mode", async () => {
    const handoffOnly = createAccountService({
      prisma,
      config: {
        ...config,
        accounts: { ...config.accounts, localLoginEnabled: false }
      },
      auditLog: createAuditService({ prisma, logger: { error() {} } })
    });

    assert.deepEqual(
      await handoffOnly.authenticate({ identifier: "first@example.com", password: "correct-horse-battery-staple" }),
      { ok: false, reason: "local_login_disabled", account: null }
    );
    assert.deepEqual(await handoffOnly.requestPasswordReset({ email: "first@example.com" }), { sent: false });
    assert.deepEqual(
      await handoffOnly.resetPassword({ token: "still-not-usable", password: "replacement-password" }),
      { ok: false, reason: "local_login_disabled", account: null }
    );
    assert.deepEqual(
      await handoffOnly.changePassword({
        userId: (await accounts.findByEmail("first@example.com")).id,
        currentPassword: "correct-horse-battery-staple",
        newPassword: "replacement-password"
      }),
      { ok: false, reason: "local_login_disabled" }
    );
  });

  it("refuses a wrong password and an unknown account identically", async () => {
    const wrong = await accounts.authenticate({ identifier: "first", password: "not-the-password" });
    const unknown = await accounts.authenticate({ identifier: "nobody@example.com", password: "whatever" });
    assert.equal(wrong.ok, false);
    assert.equal(unknown.ok, false);
    // Neither returns an account, so a caller cannot tell the two apart.
    assert.equal(wrong.account, null);
    assert.equal(unknown.account, null);
  });

  it("reports scrypt saturation identically and rebuilds a failed dummy hash", async () => {
    await accounts.register({
      email: "saturation-known@example.com",
      password: "saturation-known-password",
      username: "saturation-known"
    });

    const original = crypto.scrypt;
    let firstCallback = null;
    let calls = 0;

    crypto.scrypt = (password, salt, keylen, options, callback) => {
      calls += 1;
      if (calls === 1) {
        firstCallback = callback;
        return;
      }
      setImmediate(() => callback(null, Buffer.alloc(keylen, 7)));
    };

    try {
      const salt = Buffer.from("bounded-scrypt-salt").toString("base64url");
      const expected = Buffer.alloc(16, 7).toString("base64url");
      const stored = `scrypt$16384$8$1$${salt}$${expected}`;
      const accepted = Array.from({ length: 65 }, () => verifyPassword("password", stored));

      // A fresh service has not built its dummy hash yet. Both a real account
      // and an unknown one arrive while the shared KDF queue is full and must
      // surface the same temporary failure.
      const isolated = createAccountService({
        prisma,
        config,
        mailer: null,
        auditLog: { record: async () => {} }
      });
      const knownBusy = assert.rejects(
        isolated.authenticate({ identifier: "saturation-known", password: "not-the-password" }),
        (error) => error?.statusCode === 503
      );
      const unknownBusy = assert.rejects(
        isolated.authenticate({ identifier: "nobody@example.com", password: "not-the-password" }),
        (error) => error?.statusCode === 503
      );
      await Promise.all([knownBusy, unknownBusy]);

      while (!firstCallback) await new Promise((resolve) => setImmediate(resolve));
      firstCallback(null, Buffer.alloc(16, 7));
      await Promise.all(accepted);

      // The failed dummy-hash promise must have been discarded. Otherwise this
      // would either stay rejected forever or skip the KDF and return
      // immediately, restoring an account-enumeration timing difference.
      const recovered = await isolated.authenticate({
        identifier: "nobody@example.com",
        password: "not-the-password"
      });
      assert.equal(recovered.ok, false);
      assert.equal(recovered.reason, "unknown_identifier");
      assert.ok(calls >= 3, "the unknown-account path did not rebuild and verify its dummy hash");
    } finally {
      crypto.scrypt = original;
    }
  });

  it("resets a password and invalidates the link afterwards", async () => {
    sentMail.length = 0;
    const requested = await accounts.requestPasswordReset({ email: "second@example.com" });
    assert.equal(requested.sent, true);

    const mail = sentMail.find((entry) => entry.kind === "reset");
    assert.ok(mail?.token);

    const reset = await accounts.resetPassword({ token: mail.token, password: "brand-new-long-password" });
    assert.equal(reset.ok, true);

    const login = await accounts.authenticate({
      identifier: "second@example.com",
      password: "brand-new-long-password"
    });
    assert.equal(login.ok, true);

    // Single use.
    const replay = await accounts.resetPassword({ token: mail.token, password: "another-new-password-1" });
    assert.equal(replay.ok, false);
    assert.equal(replay.reason, "invalid_token");
  });

  it("reports nothing when a reset is requested for an unknown address", async () => {
    const result = await accounts.requestPasswordReset({ email: "ghost@example.com" });
    // Same shape as a real request from the caller's perspective; no mail sent.
    assert.equal(result.sent, false);
  });

  it("revokes sessions and refresh tokens when a password changes", async () => {
    const account = await accounts.findByEmail("second@example.com");
    const { sid } = await sessions.create({ userId: account.id });
    assert.ok(await sessions.find(sid));

    await accounts.changePassword({
      userId: account.id,
      currentPassword: "brand-new-long-password",
      newPassword: "changed-once-again-password"
    });

    // A password change must not leave a live session behind.
    assert.equal(await sessions.find(sid), null);
  });

  it("rolls back a password reset when credential revocation fails", async () => {
    sentMail.length = 0;
    const { account } = await accounts.register({
      email: "reset-transaction@example.com",
      password: "original-reset-password"
    });
    await accounts.requestPasswordReset({ email: account.email });
    const resetMail = sentMail.find((entry) => entry.kind === "reset");
    assert.ok(resetMail?.token);

    const credentials = await seedRevocableCredentials({ prisma, sessions, userId: account.id });
    const fault = failOnceInTransaction(prisma, { model: "session", method: "deleteMany" });
    const failingAccounts = createAccountService({ prisma: fault.prisma, config });

    await assert.rejects(
      failingAccounts.resetPassword({ token: resetMail.token, password: "replacement-reset-password" }),
      /injected transaction failure/
    );
    assert.equal(fault.didFail(), true);
    assert.ok(await sessions.find(credentials.sid), "the old browser session was partially revoked");
    assert.equal(
      (await prisma.refreshToken.findUnique({ where: { id: credentials.refreshTokenId } })).revokedAt,
      null,
      "the refresh token was partially revoked"
    );
    assert.equal(
      (await accounts.authenticate({ identifier: account.email, password: "original-reset-password" })).ok,
      true,
      "the password changed despite the failed revocation"
    );
    assert.equal(
      (await accounts.authenticate({ identifier: account.email, password: "replacement-reset-password" })).ok,
      false
    );

    const retry = await accounts.resetPassword({
      token: resetMail.token,
      password: "replacement-reset-password"
    });
    assert.equal(retry.ok, true, "the reset link was consumed by a rolled-back reset");
  });

  it("rolls back a signed-in password change when credential revocation fails", async () => {
    const { account } = await accounts.register({
      email: "change-transaction@example.com",
      password: "original-change-password"
    });
    const credentials = await seedRevocableCredentials({ prisma, sessions, userId: account.id });
    const fault = failOnceInTransaction(prisma, { model: "session", method: "deleteMany" });
    const failingAccounts = createAccountService({ prisma: fault.prisma, config });

    await assert.rejects(
      failingAccounts.changePassword({
        userId: account.id,
        currentPassword: "original-change-password",
        newPassword: "replacement-change-password"
      }),
      /injected transaction failure/
    );
    assert.equal(fault.didFail(), true);
    assert.ok(await sessions.find(credentials.sid), "the old browser session was partially revoked");
    assert.equal(
      (await prisma.refreshToken.findUnique({ where: { id: credentials.refreshTokenId } })).revokedAt,
      null,
      "the refresh token was partially revoked"
    );
    assert.equal(
      (await accounts.authenticate({ identifier: account.email, password: "original-change-password" })).ok,
      true,
      "the password changed despite the failed revocation"
    );
    assert.equal(
      (await accounts.authenticate({ identifier: account.email, password: "replacement-change-password" })).ok,
      false
    );
  });

  it("rolls back every credential class when revokeAllCredentials fails", async () => {
    const { account } = await accounts.register({
      email: "revoke-transaction@example.com",
      password: "revoke-transaction-password"
    });
    const credentials = await seedRevocableCredentials({ prisma, sessions, userId: account.id });
    const fault = failOnceInTransaction(prisma, { model: "session", method: "deleteMany" });
    const failingAccounts = createAccountService({ prisma: fault.prisma, config });

    await assert.rejects(
      failingAccounts.revokeAllCredentials(account.id, "transaction_regression"),
      /injected transaction failure/
    );
    assert.equal(fault.didFail(), true);
    assert.ok(await sessions.find(credentials.sid), "the browser session was partially revoked");
    assert.equal(
      (await prisma.refreshToken.findUnique({ where: { id: credentials.refreshTokenId } })).revokedAt,
      null,
      "the refresh token was partially revoked"
    );
  });

  it("locks account credentials in user-session-refresh-code-oidc-token order", async () => {
    const { account } = await accounts.register({
      email: "credential-lock-order@example.com",
      password: "credential-lock-order-password"
    });
    await seedRevocableCredentials({ prisma, sessions, userId: account.id });
    const beforeOwner = await prisma.user.findUnique({
      where: { id: account.id },
      select: { updatedAt: true }
    });
    const observed = observeTransactionWrites(prisma);
    const orderedAccounts = createAccountService({ prisma: observed.prisma, config });

    await orderedAccounts.revokeAllCredentials(account.id, "lock_order_regression");

    assert.deepEqual(observed.writes, [
      "user.updateMany",
      "session.deleteMany",
      "refreshToken.updateMany",
      "authorizationCode.updateMany",
      "oidcSession.updateMany",
      "passwordResetToken.updateMany",
      "emailVerificationToken.updateMany"
    ]);
    const afterOwner = await prisma.user.findUnique({
      where: { id: account.id },
      select: { updatedAt: true }
    });
    assert.equal(
      afterOwner.updatedAt.getTime(),
      beforeOwner.updatedAt.getTime(),
      "the write lock changed the account update timestamp"
    );
  });

  it("does not overwrite an administrative disable from a stale reset snapshot", async () => {
    sentMail.length = 0;
    const { account } = await accounts.register({
      email: "reset-disable-race@example.com",
      password: "original-race-password"
    });
    await accounts.requestPasswordReset({ email: account.email });
    const resetMail = sentMail.find((entry) => entry.kind === "reset");
    assert.ok(resetMail?.token);

    const before = await prisma.user.findUnique({ where: { id: account.id } });
    const paused = pauseOnceAfterRead(prisma, { model: "user", method: "findUnique" });
    const racingAccounts = createAccountService({ prisma: paused.prisma, config });
    const reset = racingAccounts.resetPassword({
      token: resetMail.token,
      password: "replacement-race-password"
    });

    await paused.reached;
    await prisma.user.update({
      where: { id: account.id },
      data: { status: "DISABLED", disabledAt: new Date(), disabledReason: "concurrent_admin_action" }
    });
    paused.resume();

    const result = await reset;
    assert.equal(result.ok, false);
    assert.equal(result.reason, "disabled");
    const after = await prisma.user.findUnique({ where: { id: account.id } });
    assert.equal(after.status, "DISABLED", "the reset undid the administrative disable");
    assert.equal(after.passwordHash, before.passwordHash, "the reset changed the password after disable");
    const resetRecord = await prisma.passwordResetToken.findUnique({
      where: { tokenHash: hashToken(resetMail.token) }
    });
    assert.equal(resetRecord.usedAt, null, "the rejected reset consumed its one-time link");
  });

  it("allows only one concurrent password change to consume the old password", async () => {
    const { account } = await accounts.register({
      email: "change-password-race@example.com",
      password: "shared-old-password"
    });
    const synchronizedPrisma = synchronizeReads(prisma, {
      model: "user",
      method: "findUnique",
      participants: 2
    });
    const racingAccounts = createAccountService({ prisma: synchronizedPrisma, config });

    const results = await Promise.all([
      racingAccounts.changePassword({
        userId: account.id,
        currentPassword: "shared-old-password",
        newPassword: "first-concurrent-password"
      }),
      racingAccounts.changePassword({
        userId: account.id,
        currentPassword: "shared-old-password",
        newPassword: "second-concurrent-password"
      })
    ]);

    assert.equal(results.filter((result) => result.ok).length, 1, "both stale password changes succeeded");
    const rejected = results.find((result) => !result.ok);
    assert.equal(rejected?.reason, "bad_password");
    assert.equal(
      (await accounts.authenticate({ identifier: account.email, password: "shared-old-password" })).ok,
      false,
      "the consumed old password still worked"
    );
    const winningPasswords = await Promise.all(
      ["first-concurrent-password", "second-concurrent-password"].map((password) =>
        accounts.authenticate({ identifier: account.email, password })
      )
    );
    assert.equal(
      winningPasswords.filter((result) => result.ok).length,
      1,
      "the stored password did not match exactly one successful request"
    );
  });

  it("rolls back DISABLED status when credential revocation fails", async () => {
    const { account } = await accounts.register({
      email: "disable-transaction@example.com",
      password: "disable-transaction-password"
    });
    const credentials = await seedRevocableCredentials({ prisma, sessions, userId: account.id });
    const fault = failOnceInTransaction(prisma, { model: "session", method: "deleteMany" });
    const failingAccounts = createAccountService({ prisma: fault.prisma, config });

    await assert.rejects(
      failingAccounts.setStatus({ userId: account.id, status: "DISABLED", reason: "transaction_regression" }),
      /injected transaction failure/
    );
    assert.equal(fault.didFail(), true);
    const after = await prisma.user.findUnique({ where: { id: account.id } });
    assert.equal(after.status, "ACTIVE", "the status committed without credential revocation");
    assert.equal(after.disabledAt, null);
    assert.equal(after.disabledReason, null);
    assert.ok(await sessions.find(credentials.sid), "the browser session was partially revoked");
    assert.equal(
      (await prisma.refreshToken.findUnique({ where: { id: credentials.refreshTokenId } })).revokedAt,
      null,
      "the refresh token was partially revoked"
    );
  });

  it("stores a session cookie only as a hash", async () => {
    const account = await accounts.findByEmail("first@example.com");
    const { sid, session } = await sessions.create({ userId: account.id });
    const row = await prisma.session.findUnique({ where: { id: session.id } });
    assert.notEqual(row.sidHash, sid);
    assert.equal(row.sidHash.length, 64);
    assert.ok(!JSON.stringify(row).includes(sid));
  });

  it("issues a new session identifier on login", async () => {
    const account = await accounts.findByEmail("first@example.com");
    const cookies = [];
    const res = { cookie: (name, value) => cookies.push(value), clearCookie() {} };

    const first = await sessions.login({ res, userId: account.id });
    const second = await sessions.login({ res, currentSid: first.sid, userId: account.id });

    assert.notEqual(first.sid, second.sid);
    // The pre-login identifier stops working, which is what closes fixation.
    assert.equal(await sessions.find(first.sid), null);
    assert.ok(await sessions.find(second.sid));
  });

  it("rolls back logout when either the Session or OIDC write fails", async () => {
    const { account } = await accounts.register({
      email: "logout-transaction@example.com",
      password: "logout-transaction-password"
    });

    for (const model of ["session", "oidcSession"]) {
      const credentials = await seedRevocableCredentials({ prisma, sessions, userId: account.id });
      const fault = failOnceInTransaction(prisma, { model, method: model === "session" ? "deleteMany" : "updateMany" });
      const failingSessions = createSessionService({ prisma: fault.prisma, config });

      await assert.rejects(
        failingSessions.logout({ sid: credentials.sid, reason: "transaction_regression" }),
        /injected transaction failure/
      );
      assert.equal(fault.didFail(), true);
      assert.ok(await sessions.find(credentials.sid), `${model} failure deleted the browser session`);
      assert.equal(
        (await prisma.oidcSession.findUnique({ where: { id: credentials.oidcSessionId } })).revokedAt,
        null,
        `${model} failure partially revoked the OIDC session`
      );
    }
  });

  it("rolls back remote session revocation when either Session or OIDC write fails", async () => {
    const { account } = await accounts.register({
      email: "remote-revoke-transaction@example.com",
      password: "remote-revoke-transaction-password"
    });

    for (const model of ["session", "oidcSession"]) {
      const credentials = await seedRevocableCredentials({ prisma, sessions, userId: account.id });
      const fault = failOnceInTransaction(prisma, { model, method: model === "session" ? "deleteMany" : "updateMany" });
      const failingSessions = createSessionService({ prisma: fault.prisma, config });

      await assert.rejects(
        failingSessions.revoke({
          sessionId: credentials.sessionId,
          userId: account.id,
          reason: "transaction_regression"
        }),
        /injected transaction failure/
      );
      assert.equal(fault.didFail(), true);
      assert.ok(
        await prisma.session.findUnique({ where: { id: credentials.sessionId } }),
        `${model} failure deleted the browser session`
      );
      assert.equal(
        (await prisma.oidcSession.findUnique({ where: { id: credentials.oidcSessionId } })).revokedAt,
        null,
        `${model} failure partially revoked the OIDC session`
      );
    }
  });

  it("uses a verified upstream subject for a new handoff account", async () => {
    const payload = ticketPayload({
        sub: crypto.randomUUID(),
        email: "upstream@example.com",
        username: "upstream-user",
        name: "Upstream User",
        attributes: { knight_uid: 4242 }
      });
    const ticket = signTicket(payload);
    const result = await external.completeCallback({
      provider: "upstream",
      ticket,
      state: "handoff-state-value"
    });
    assert.equal(result.created, true);
    assert.equal(result.migrated, false);
    assert.equal(result.account.id, payload.sub);
    assert.equal(result.account.email, "upstream@example.com");
    assert.equal(result.account.hasPassword, false);
    // Attributes are what a custom scope releases as a claim.
    assert.equal(result.account.attributes.knight_uid, 4242);
    assert.equal(result.account.attributes.external_preferred_username, "upstream-user");
  });

  it("rejects a malformed subject when a handoff provider requires UUID subjects", async () => {
    const strictConfig = loadEnv({
      OAUTH_EXTERNAL_IDENTITY_PROVIDERS: JSON.stringify([
        {
          name: "uuid-upstream",
          kind: "handoff",
          displayName: "UUID Upstream",
          startUrl: "https://upstream.test/oauth2/handoff/start",
          sharedSecret: SHARED_SECRET,
          subjectMode: "upstream",
          subjectFormat: "uuid"
        }
      ])
    });
    const strictExternal = createExternalIdentityService({ prisma, config: strictConfig, accounts });
    for (const sub of ["not-a-uuid", crypto.randomUUID().toUpperCase(), ` ${crypto.randomUUID()}`]) {
      const payload = ticketPayload({ iss: "uuid-upstream", sub });
      await assert.rejects(
        strictExternal.completeCallback({
          provider: "uuid-upstream",
          ticket: signTicket(payload),
          state: payload.state
        }),
        /subject must be a UUID/
      );
    }
  });

  it("rejects a replayed handoff ticket", async () => {
    const payload = ticketPayload({ sub: "upstream-user-2" });
    const ticket = signTicket(payload);
    await external.completeCallback({ provider: "upstream", ticket, state: payload.state });
    await assert.rejects(
      external.completeCallback({ provider: "upstream", ticket, state: payload.state }),
      /already been used/
    );
  });

  it("rejects a ticket signed with the wrong secret", async () => {
    const payload = ticketPayload({ sub: "upstream-user-3" });
    await assert.rejects(
      external.completeCallback({
        provider: "upstream",
        ticket: signTicket(payload, "a-different-secret-of-sufficient-length"),
        state: payload.state
      }),
      /signature is not valid/
    );
  });

  it("rejects an unsigned ticket claiming alg none", async () => {
    const payload = ticketPayload({ sub: "upstream-user-4" });
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    await assert.rejects(
      external.completeCallback({
        provider: "upstream",
        ticket: `${header}.${body}.`,
        state: payload.state
      }),
      /signature is not valid/
    );
  });

  it("rejects a ticket whose state does not match the request", async () => {
    const payload = ticketPayload({ sub: "upstream-user-5", state: "some-other-state" });
    await assert.rejects(
      external.completeCallback({
        provider: "upstream",
        ticket: signTicket(payload),
        state: "handoff-state-value"
      }),
      /does not match this sign-in attempt/
    );
  });

  it("rejects an expired ticket", async () => {
    const seconds = Math.floor(Date.now() / 1000);
    const payload = ticketPayload({ sub: "upstream-user-6", iat: seconds - 300, exp: seconds - 60 });
    await assert.rejects(
      external.completeCallback({ provider: "upstream", ticket: signTicket(payload), state: payload.state }),
      /has expired/
    );
  });

  it("requires a numeric issued-at time on a handoff ticket", async () => {
    for (const iat of [undefined, "not-a-time"]) {
      const payload = ticketPayload({ sub: `upstream-user-iat-${String(iat)}`, iat });
      await assert.rejects(
        external.completeCallback({ provider: "upstream", ticket: signTicket(payload), state: payload.state }),
        /no valid issued-at time/
      );
    }
  });

  it("rejects a ticket addressed to a different issuer", async () => {
    const payload = ticketPayload({ sub: "upstream-user-7", aud: "https://somewhere-else.test" });
    await assert.rejects(
      external.completeCallback({ provider: "upstream", ticket: signTicket(payload), state: payload.state }),
      /not addressed to this issuer/
    );
  });

  it("refuses to merge an upstream subject into an existing local account", async () => {
    const payload = ticketPayload({ sub: "upstream-user-8", email: "first@example.com" });
    // Automatic merging on a matching email would be an account-takeover path.
    await assert.rejects(
      external.completeCallback({ provider: "upstream", ticket: signTicket(payload), state: payload.state }),
      /already uses that email address/
    );
  });

  it("returns the same account on a second sign-in from the same subject", async () => {
    const first = await external.completeCallback({
      provider: "upstream",
      ticket: signTicket(ticketPayload({ sub: "returning-user", email: "returning@example.com" })),
      state: "handoff-state-value"
    });
    const second = await external.completeCallback({
      provider: "upstream",
      ticket: signTicket(ticketPayload({ sub: "returning-user", email: "returning@example.com" })),
      state: "handoff-state-value"
    });
    assert.equal(second.created, false);
    assert.equal(second.account.id, first.account.id);
  });

  it("migrates a legacy random linked user ID to its verified upstream subject", async () => {
    const legacyID = crypto.randomUUID();
    const subject = crypto.randomUUID();
    await prisma.user.create({
      data: {
        id: legacyID,
        email: "legacy-linked-subject@example.com",
        passwordHash: null,
        status: accounts.STATUS.ACTIVE,
        externalIdentities: {
          create: {
            id: crypto.randomUUID(),
            provider: "upstream",
            subject
          }
        }
      }
    });
    const credentials = await seedRevocableCredentials({ prisma, sessions, userId: legacyID });
    const payload = ticketPayload({ subject, sub: subject });
    const result = await external.completeCallback({
      provider: "upstream",
      ticket: signTicket(payload),
      state: payload.state
    });

    assert.equal(result.created, false);
    assert.equal(result.migrated, true);
    assert.equal(result.account.id, subject);
    assert.equal(await accounts.findById(legacyID), null);
    assert.equal(
      (await prisma.externalIdentity.findUnique({ where: { provider_subject: { provider: "upstream", subject } } })).userId,
      subject
    );
    assert.equal(await prisma.session.findUnique({ where: { id: credentials.sessionId } }), null);
    assert.ok((await prisma.refreshToken.findUnique({ where: { id: credentials.refreshTokenId } })).revokedAt);
    assert.ok((await prisma.oidcSession.findUnique({ where: { id: credentials.oidcSessionId } })).revokedAt);
  });

  it("migrates an account in the same transaction that creates its canonical provider link", async () => {
    const legacyID = crypto.randomUUID();
    const subject = crypto.randomUUID();
    await prisma.user.create({
      data: {
        id: legacyID,
        email: "legacy-link-migration@example.com",
        passwordHash: null,
        status: accounts.STATUS.ACTIVE
      }
    });
    const credentials = await seedRevocableCredentials({ prisma, sessions, userId: legacyID });
    const payload = ticketPayload({ sub: subject });
    const result = await external.link({
      provider: "upstream",
      ticket: signTicket(payload),
      state: payload.state,
      userId: legacyID
    });

    assert.deepEqual(result, { linked: true, alreadyLinked: false, migrated: true });
    assert.equal(await accounts.findById(legacyID), null);
    assert.ok(await accounts.findById(subject));
    assert.equal(
      (await prisma.externalIdentity.findUnique({ where: { provider_subject: { provider: "upstream", subject } } })).userId,
      subject
    );
    assert.equal(await prisma.session.findUnique({ where: { id: credentials.sessionId } }), null);
    assert.ok((await prisma.refreshToken.findUnique({ where: { id: credentials.refreshTokenId } })).revokedAt);
    assert.ok((await prisma.oidcSession.findUnique({ where: { id: credentials.oidcSessionId } })).revokedAt);
  });

  it("rolls a subject migration back when the durable logout queue cannot be written", async () => {
    const legacyID = crypto.randomUUID();
    const subject = crypto.randomUUID();
    await prisma.user.create({
      data: {
        id: legacyID,
        email: "legacy-migration-outbox-failure@example.com",
        passwordHash: null,
        status: accounts.STATUS.ACTIVE,
        externalIdentities: {
          create: {
            id: crypto.randomUUID(),
            provider: "upstream",
            subject
          }
        }
      }
    });
    const credentials = await seedRevocableCredentials({ prisma, sessions, userId: legacyID });
    const failingExternal = createExternalIdentityService({
      prisma,
      config,
      accounts,
      backchannel: {
        async enqueue() {
          throw new Error("injected backchannel outbox failure");
        }
      }
    });
    const payload = ticketPayload({ sub: subject });

    await assert.rejects(
      failingExternal.completeCallback({
        provider: "upstream",
        ticket: signTicket(payload),
        state: payload.state
      }),
      /injected backchannel outbox failure/
    );
    assert.ok(await accounts.findById(legacyID));
    assert.equal(await accounts.findById(subject), null);
    assert.equal(
      (await prisma.externalIdentity.findUnique({ where: { provider_subject: { provider: "upstream", subject } } })).userId,
      legacyID
    );
    assert.ok(await prisma.session.findUnique({ where: { id: credentials.sessionId } }));
    assert.equal((await prisma.refreshToken.findUnique({ where: { id: credentials.refreshTokenId } })).revokedAt, null);
    assert.equal((await prisma.oidcSession.findUnique({ where: { id: credentials.oidcSessionId } })).revokedAt, null);
  });

  it("fails closed when a legacy linked account conflicts with another account's canonical subject", async () => {
    const legacyID = crypto.randomUUID();
    const subject = crypto.randomUUID();
    await prisma.user.create({
      data: { id: subject, email: "canonical-subject-owner@example.com", passwordHash: null, status: accounts.STATUS.ACTIVE }
    });
    await prisma.user.create({
      data: {
        id: legacyID,
        email: "legacy-subject-conflict@example.com",
        passwordHash: null,
        status: accounts.STATUS.ACTIVE,
        externalIdentities: {
          create: {
            id: crypto.randomUUID(),
            provider: "upstream",
            subject
          }
        }
      }
    });
    const payload = ticketPayload({ subject, sub: subject });
    await assert.rejects(
      external.completeCallback({ provider: "upstream", ticket: signTicket(payload), state: payload.state }),
      /conflicts with an existing account/
    );
    assert.equal(
      (await prisma.externalIdentity.findUnique({ where: { provider_subject: { provider: "upstream", subject } } })).userId,
      legacyID
    );
    assert.equal(await prisma.consumedTicket.count({ where: { provider: "upstream", jti: payload.jti } }), 1);
  });

  it("refuses to unlink the only way into an account", async () => {
    const account = await external
      .listForUser((await accounts.findByEmail("returning@example.com")).id)
      .then(() => accounts.findByEmail("returning@example.com"));
    await assert.rejects(
      external.unlink({ provider: "upstream", userId: account.id }),
      /Set a password before unlinking/
    );
  });

  it("keeps credentials out of the audit log", async () => {
    const audit = createAuditService({ prisma, logger: { error() {} } });
    await audit.record({
      action: "test.event",
      targetType: "test",
      metadata: {
        client_secret: "super-secret",
        refresh_token: "a-token",
        code_verifier: "a-verifier",
        nested: { password: "hunter2" },
        token_endpoint_auth_method: "client_secret_basic",
        safe: "kept"
      }
    });
    const { entries } = await audit.list({ action: "test.event" });
    const metadata = JSON.parse(entries[0].metadataJson);
    assert.equal(metadata.client_secret, "[redacted]");
    assert.equal(metadata.refresh_token, "[redacted]");
    assert.equal(metadata.code_verifier, "[redacted]");
    assert.equal(metadata.nested.password, "[redacted]");
    // A mechanism name is not a secret and stays readable.
    assert.equal(metadata.token_endpoint_auth_method, "client_secret_basic");
    assert.equal(metadata.safe, "kept");
  });

  it("verifies an email address once", async () => {
    const verifying = loadEnv({ OAUTH_REQUIRE_EMAIL_VERIFICATION: "true" });
    const mail = [];
    const service = createAccountService({
      prisma,
      config: verifying,
      mailer: {
        sendEmailVerification: async (message) => mail.push(message),
        sendPasswordReset: async () => {},
        sendExistingAccountNotice: async () => {}
      }
    });

    const { account, verificationRequired } = await service.register({
      email: "pending@example.com",
      password: "a-long-enough-password-here"
    });
    assert.equal(verificationRequired, true);
    assert.equal(account.status, "PENDING");

    // A pending account cannot sign in while verification is required.
    const blocked = await service.authenticate({
      identifier: "pending@example.com",
      password: "a-long-enough-password-here"
    });
    assert.equal(blocked.ok, false);
    assert.equal(blocked.reason, "unverified");

    const verified = await service.verifyEmail(mail[0].token);
    assert.equal(verified.ok, true);
    assert.equal(verified.account.status, "ACTIVE");
    assert.equal(verified.account.emailVerified, true);

    const replay = await service.verifyEmail(mail[0].token);
    assert.equal(replay.ok, false);

    const allowed = await service.authenticate({
      identifier: "pending@example.com",
      password: "a-long-enough-password-here"
    });
    assert.equal(allowed.ok, true);
  });

  it("runs against the database the environment selected", async () => {
    // Asked of the engine, not of the configuration.
    //
    // The suite passing is not evidence of which database it passed on: a run
    // that silently fell back to SQLite would report the same counts, and this
    // whole helper exists because "it was green" had been standing in for "it
    // was checked on both". So the engine is asked what it is.
    if (db.provider === "postgresql") {
      const rows = await prisma.$queryRawUnsafe("SELECT version() AS version");
      assert.match(String(rows[0].version), /PostgreSQL/, "DATABASE_PROVIDER said postgresql; the engine disagreed");
    } else {
      const rows = await prisma.$queryRawUnsafe("SELECT sqlite_version() AS version");
      assert.match(String(rows[0].version), /^\d+\./, "the engine did not answer as SQLite");
    }
  });

  it("revokes credentials when an account is disabled", async () => {
    const account = await accounts.findByEmail("upstream@example.com");
    const { sid } = await sessions.create({ userId: account.id });
    await accounts.setStatus({ userId: account.id, status: "DISABLED", reason: "testing" });
    assert.equal(await sessions.find(sid), null);
    const reloaded = await accounts.findById(account.id);
    assert.equal(reloaded.status, "DISABLED");
  });

  it("burns an outstanding reset link when the password changes another way", async () => {
    // The sequence this closes: someone with brief access to the mailbox
    // requests a reset, takes the link, and deletes the mail. The account holder
    // notices and does the textbook thing — signs in and changes their password.
    // That killed every session and refresh token and left the attacker's link
    // untouched, still unused and valid for the rest of its hour. Using it then
    // locks the holder back out, from a remedy they had already applied.
    sentMail.length = 0;
    const account = await accounts.register({
      email: "outstanding@example.com",
      password: "a-long-enough-password-here"
    });
    await accounts.requestPasswordReset({ email: "outstanding@example.com" });
    const link = sentMail.find((entry) => entry.kind === "reset");
    assert.ok(link?.token, "no reset link was issued");

    await accounts.changePassword({
      userId: account.account.id,
      currentPassword: "a-long-enough-password-here",
      newPassword: "a-different-long-password"
    });

    const used = await accounts.resetPassword({ token: link.token, password: "attacker-chosen-password" });
    assert.equal(used.ok, false, "the reset link outlived the password change it should have been ended by");
    assert.equal(
      (await accounts.authenticate({
        identifier: "outstanding@example.com",
        password: "a-different-long-password"
      })).ok,
      true,
      "the password the holder actually chose must still be the one that works"
    );
  });

  it("will not let a disabled account re-enable itself with a link from before", async () => {
    // Both writes used to set `status: ACTIVE` unconditionally, so a reset or
    // verification link issued while the account was usable was also a way back
    // in after an administrator disabled it — and the reset controller signs the
    // caller in immediately afterwards.
    sentMail.length = 0;
    const created = await accounts.register({
      email: "disabled-later@example.com",
      password: "a-long-enough-password-here"
    });
    await accounts.requestPasswordReset({ email: "disabled-later@example.com" });
    const reset = sentMail.find((entry) => entry.kind === "reset");
    const verify = sentMail.find((entry) => entry.kind === "verify");
    assert.ok(reset?.token && verify?.token, "both kinds of link are needed for this");

    // Disabled by writing the row, not through setStatus — that revokes
    // credentials, which now burns both links, and the point here is the guard
    // that refuses a link which *did* survive. A row disabled by an older
    // build, or by an operator reaching for SQL, is exactly that case.
    await prisma.user.update({ where: { id: created.account.id }, data: { status: "DISABLED" } });

    const viaReset = await accounts.resetPassword({ token: reset.token, password: "a-brand-new-password-x" });
    assert.equal(viaReset.ok, false);
    assert.equal(viaReset.reason, "disabled");

    const viaVerify = await accounts.verifyEmail(verify.token);
    assert.equal(viaVerify.ok, false);
    assert.equal(viaVerify.reason, "disabled");

    assert.equal((await accounts.findById(created.account.id)).status, "DISABLED", "the account let itself back in");
  });
});

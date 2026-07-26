"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { after, before, describe, it } = require("node:test");

const { withDatabase } = require("../helpers/database");
const { loadEnv } = require("../../src/config/env");
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
          sharedSecret: SHARED_SECRET
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

  it("refuses a wrong password and an unknown account identically", async () => {
    const wrong = await accounts.authenticate({ identifier: "first", password: "not-the-password" });
    const unknown = await accounts.authenticate({ identifier: "nobody@example.com", password: "whatever" });
    assert.equal(wrong.ok, false);
    assert.equal(unknown.ok, false);
    // Neither returns an account, so a caller cannot tell the two apart.
    assert.equal(wrong.account, null);
    assert.equal(unknown.account, null);
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

  it("creates a local account from a valid handoff ticket", async () => {
    const ticket = signTicket(
      ticketPayload({ email: "upstream@example.com", name: "Upstream User", attributes: { knight_uid: 4242 } })
    );
    const result = await external.completeCallback({
      provider: "upstream",
      ticket,
      state: "handoff-state-value"
    });
    assert.equal(result.created, true);
    assert.equal(result.account.email, "upstream@example.com");
    assert.equal(result.account.hasPassword, false);
    // Attributes are what a custom scope releases as a claim.
    assert.equal(result.account.attributes.knight_uid, 4242);
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

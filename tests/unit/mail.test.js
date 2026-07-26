"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createMailService } = require("../../src/services/mailService");

// What a disabled mailer is allowed to write down.
//
// With SMTP off, the link is the only way to continue, so outside production it
// goes to the console on purpose. In production that is an account takeover
// waiting for anyone who can read the process log — a set that includes every
// log shipper, aggregator, APM agent, and support engineer, and is far larger
// than the set who can read the database. The guard that was supposed to
// prevent it only covered email verification, and only when verification was
// required; password reset was never covered at all, and both
// OAUTH_REQUIRE_EMAIL_VERIFICATION and SMTP_ENABLED default to false while
// compose.yml sets NODE_ENV=production.
//
// Asserted against the recorded log lines rather than the return value, because
// the return value was never the problem.

function collectingLogger() {
  const lines = [];
  const record = (...args) => lines.push(args.map(String).join(" "));
  return { lines, info: record, warn: record, error: record };
}

function mailerFor({ isProduction }) {
  const logger = collectingLogger();
  const service = createMailService({
    config: {
      isProduction,
      publicBaseUrl: "https://issuer.example",
      mail: { enabled: false },
      branding: { serviceName: "Knight OAuth" }
    },
    logger
  });
  return { service, logger };
}

const TOKEN = "a-single-use-token-nobody-should-read";
const expiresAt = new Date(Date.now() + 3_600_000);

test("in production a disabled mailer logs neither the link nor the token", async () => {
  const { service, logger } = mailerFor({ isProduction: true });

  await service.sendPasswordReset({ email: "ada@example.com", name: "Ada", token: TOKEN, expiresAt });
  await service.sendEmailVerification({ email: "ada@example.com", name: "Ada", token: TOKEN, expiresAt });

  const written = logger.lines.join("\n");
  assert.ok(written.length > 0, "something should be recorded, or an operator cannot tell mail is off");
  assert.ok(!written.includes(TOKEN), "the single-use token reached the log");
  assert.ok(!written.includes("reset-password?token="), "a working reset link reached the log");
  assert.ok(!written.includes("verify-email?token="), "a working verification link reached the log");
  // The address identifies the account, so it is masked rather than dropped:
  // an operator still has enough to correlate a report with a line.
  assert.ok(!written.includes("ada@example.com"), "the full address reached the log");
  assert.ok(written.includes("a***@example.com"), "nothing identifiable enough to act on was recorded");
});

test("outside production the link is still printed, because it is the only way to continue", async () => {
  const { service, logger } = mailerFor({ isProduction: false });

  await service.sendPasswordReset({ email: "ada@example.com", name: "Ada", token: TOKEN, expiresAt });

  const written = logger.lines.join("\n");
  assert.ok(written.includes(TOKEN), "a local install with SMTP off has no other way to finish a reset");
  assert.ok(written.includes("reset-password?token="));
});

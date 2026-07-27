"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const { verifyPassword } = require("../../src/lib/crypto");

test("password verification shares the bounded scrypt gate", async () => {
  const original = crypto.scrypt;
  let active = 0;
  let peak = 0;

  crypto.scrypt = (password, salt, keylen, options, callback) => {
    active += 1;
    peak = Math.max(peak, active);
    setImmediate(() => {
      active -= 1;
      callback(null, Buffer.alloc(keylen, 7));
    });
  };

  try {
    const salt = Buffer.from("bounded-scrypt-salt").toString("base64url");
    const expected = Buffer.alloc(16, 7).toString("base64url");
    const stored = `scrypt$16384$8$1$${salt}$${expected}`;
    const results = await Promise.all(
      Array.from({ length: 6 }, () => verifyPassword("password", stored))
    );

    assert.deepEqual(results, [true, true, true, true, true, true]);
    assert.equal(peak, 1, "verification bypassed the single-operation scrypt gate");
  } finally {
    crypto.scrypt = original;
  }
});

test("password verification reports saturation and recovers after the queue drains", async () => {
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

    // One active operation plus the 64-entry queue is accepted. The next
    // request must be told the server is busy rather than that its password is
    // wrong.
    const accepted = Array.from({ length: 65 }, () => verifyPassword("password", stored));
    const overflow = assert.rejects(
      verifyPassword("password", stored),
      (error) => error?.statusCode === 503
    );
    await overflow;

    while (!firstCallback) await new Promise((resolve) => setImmediate(resolve));
    firstCallback(null, Buffer.alloc(16, 7));
    assert.deepEqual(await Promise.all(accepted), Array(65).fill(true));

    assert.equal(await verifyPassword("password", stored), true, "the scrypt gate did not recover");
  } finally {
    crypto.scrypt = original;
  }
});

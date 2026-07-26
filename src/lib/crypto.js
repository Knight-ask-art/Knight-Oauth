"use strict";

const crypto = require("node:crypto");

// Every value in this file is either a credential or derived from one. Two rules
// hold throughout:
//   1. A credential is stored only as a SHA-256 hash. Tokens are high-entropy
//      random values, so a password KDF buys nothing against a brute-force
//      search of a 256-bit space; passwords are the exception and use scrypt.
//   2. A comparison against a stored value is constant-time, so a timing signal
//      cannot be used to recover the value.

const TOKEN_BYTES = 32;

/** URL-safe random token with 256 bits of entropy. */
function randomToken(bytes = TOKEN_BYTES) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function randomId() {
  return crypto.randomUUID();
}

/** Lowercase hex SHA-256. Used for every token-at-rest column. */
function hashToken(token) {
  return crypto.createHash("sha256").update(String(token), "utf8").digest("hex");
}

/**
 * Constant-time equality for arbitrary-length strings. Both sides are hashed
 * first so that a length difference does not leak through timingSafeEqual's
 * length precondition.
 */
function safeEqual(left, right) {
  const leftHash = crypto.createHash("sha256").update(String(left ?? ""), "utf8").digest();
  const rightHash = crypto.createHash("sha256").update(String(right ?? ""), "utf8").digest();
  return crypto.timingSafeEqual(leftHash, rightHash);
}

/** Constant-time check of a token against its stored hash. */
function verifyTokenHash(token, expectedHash) {
  if (!token || !expectedHash) return false;
  return safeEqual(hashToken(token), String(expectedHash));
}

// --- Passwords -------------------------------------------------------------
//
// scrypt from Node's standard library, so a self-hosted deployment needs no
// native build toolchain. Parameters follow the OWASP recommendation of
// N = 2^17, r = 8, p = 1; `maxmem` must be raised explicitly because Node's
// default 32 MiB ceiling is below what those parameters need.

const SCRYPT = { N: 131072, r: 8, p: 1, keylen: 64, maxmem: 256 * 1024 * 1024 };
const SALT_BYTES = 16;

function scryptHash(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, SCRYPT.keylen, SCRYPT, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });
}

/**
 * Returns a self-describing string: the parameters travel with the hash so a
 * future parameter change can be rolled out without invalidating stored
 * passwords.
 *
 *   scrypt$N$r$p$<salt-base64url>$<hash-base64url>
 */
async function hashPassword(password) {
  const raw = String(password ?? "");
  if (!raw) throw new Error("password must not be empty");
  const salt = crypto.randomBytes(SALT_BYTES);
  const derived = await scryptHash(raw, salt);
  return [
    "scrypt",
    SCRYPT.N,
    SCRYPT.r,
    SCRYPT.p,
    salt.toString("base64url"),
    derived.toString("base64url")
  ].join("$");
}

/**
 * Verifies a password against a stored hash. Returns false for a null hash: an
 * account that authenticates only through an external provider has no password,
 * and "no password set" must never mean "any password works".
 */
async function verifyPassword(password, storedHash) {
  const raw = String(password ?? "");
  const stored = String(storedHash ?? "");
  if (!raw || !stored) return false;

  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, n, r, p, saltPart, hashPart] = parts;
  const params = { N: Number(n), r: Number(r), p: Number(p) };
  if (!Number.isInteger(params.N) || !Number.isInteger(params.r) || !Number.isInteger(params.p)) return false;

  let salt;
  let expected;
  try {
    salt = Buffer.from(saltPart, "base64url");
    expected = Buffer.from(hashPart, "base64url");
  } catch {
    return false;
  }
  if (!salt.length || !expected.length) return false;

  const derived = await new Promise((resolve) => {
    crypto.scrypt(
      raw,
      salt,
      expected.length,
      { ...params, maxmem: SCRYPT.maxmem },
      (error, key) => resolve(error ? null : key)
    );
  });
  if (!derived) return false;
  return crypto.timingSafeEqual(derived, expected);
}

/** True when a stored hash was produced with parameters weaker than current. */
function passwordNeedsRehash(storedHash) {
  const parts = String(storedHash ?? "").split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return true;
  return Number(parts[1]) < SCRYPT.N || Number(parts[2]) < SCRYPT.r || Number(parts[3]) < SCRYPT.p;
}

// --- PKCE ------------------------------------------------------------------

/** base64url(SHA-256(verifier)), the S256 transform of RFC 7636. */
function s256Challenge(verifier) {
  return crypto.createHash("sha256").update(String(verifier), "utf8").digest("base64url");
}

module.exports = {
  hashPassword,
  hashToken,
  passwordNeedsRehash,
  randomId,
  randomToken,
  s256Challenge,
  safeEqual,
  verifyPassword,
  verifyTokenHash
};

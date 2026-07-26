"use strict";

const { createKeyRing, generateKey, normalizeKey, DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS } = require("../lib/jwt");
const { randomId } = require("../lib/crypto");

// Where signing keys come from, in precedence order:
//
//   1. OAUTH_SIGNING_KEYS_JSON — an explicit key set in the environment. A
//      deployment that manages keys externally (a secret manager, a shared key
//      across replicas) always wins, and nothing is written to the database.
//
//   2. The signing_keys table — generated on first boot when no key set was
//      supplied. This is what makes `git clone && npm start` produce a working
//      issuer: without it, a fresh deployment either refuses to start or signs
//      with an ephemeral key that invalidates every token on restart.
//
// Case 2 has a caveat that belongs in the open, not in a footnote: it stores a
// private key in the application database. That is the right trade for a
// single-node self-hosted install and the wrong one for a fleet, so the
// production guidance is to supply case 1.

function parseEnvKeys(signingKeysJson) {
  const raw = String(signingKeysJson || "").trim();
  if (!raw) return [];

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("OAUTH_SIGNING_KEYS_JSON must be valid JSON");
  }
  const entries = Array.isArray(parsed) ? parsed : parsed?.keys;
  if (!Array.isArray(entries) || !entries.length) {
    throw new Error("OAUTH_SIGNING_KEYS_JSON must contain a non-empty keys array");
  }
  // normalizeKey validates the key material and throws with a specific reason.
  return entries.map((entry) => normalizeKey(entry));
}

/**
 * @param {object} args
 * @param {object} args.config the `signing` block from the environment:
 *   `{ algorithm, signingKeysJson, activeKid, allowGeneratedKeys }`.
 */
function createKeyService({ prisma, config, now = () => new Date() } = {}) {
  const algorithm = String(config?.algorithm || DEFAULT_ALGORITHM).trim();
  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw new Error(
      `OAUTH_SIGNING_ALGORITHM must be one of ${SUPPORTED_ALGORITHMS.join(", ")}`
    );
  }

  let keyRing = null;
  let source = "none";

  function toKeyEntry(record) {
    return {
      kid: record.kid,
      alg: record.alg,
      privateJwk: JSON.parse(record.privateJwkJson)
    };
  }

  /** Keys still needed for verification: the active one plus any not yet expired. */
  async function loadStoredKeys() {
    if (!prisma?.signingKey?.findMany) return [];
    const records = await prisma.signingKey.findMany({ orderBy: { createdAt: "desc" } });
    const current = now();
    return records.filter((record) => record.isActive || !record.expiresAt || record.expiresAt > current);
  }

  async function persistGeneratedKey() {
    const key = generateKey({ alg: algorithm });
    const privateJwk = key.privateKey.export({ format: "jwk" });
    await prisma.signingKey.create({
      data: {
        id: randomId(),
        kid: key.kid,
        alg: key.alg,
        privateJwkJson: JSON.stringify(privateJwk),
        publicJwkJson: JSON.stringify(key.publicJwk),
        isActive: true
      }
    });
    return { kid: key.kid, alg: key.alg, privateJwk };
  }

  /**
   * Resolves the key ring. Safe to call repeatedly; the ring is cached after the
   * first successful load.
   */
  async function ensureKeyRing() {
    if (keyRing) return keyRing;

    const envKeys = parseEnvKeys(config?.signingKeysJson);
    if (envKeys.length) {
      keyRing = createKeyRing({
        keys: envKeys.map((key) => ({
          kid: key.kid,
          alg: key.alg,
          privateJwk: key.privateKey.export({ format: "jwk" })
        })),
        activeKid: config?.activeKid
      });
      source = "environment";
      return keyRing;
    }

    if (!config?.allowGeneratedKeys) {
      throw new Error(
        "No signing key is configured. Set OAUTH_SIGNING_KEYS_JSON, or set OAUTH_ALLOW_GENERATED_KEYS=true to let the issuer generate and store one."
      );
    }

    const stored = await loadStoredKeys();
    if (stored.length) {
      const active = stored.find((record) => record.isActive) || stored[0];
      keyRing = createKeyRing({
        keys: stored.map(toKeyEntry),
        activeKid: active.kid
      });
      source = "database";
      return keyRing;
    }

    // Two replicas booting into an empty table can both generate. The unique
    // constraint on `kid` will not catch it, since the kids differ, so re-read
    // and let whichever row is active win rather than trusting the local write.
    const generated = await persistGeneratedKey();
    const settled = await loadStoredKeys();
    const keys = settled.length ? settled.map(toKeyEntry) : [generated];
    const active = settled.find((record) => record.isActive);
    keyRing = createKeyRing({ keys, activeKid: active?.kid || generated.kid });
    source = "database";
    return keyRing;
  }

  /**
   * Adds a new active key and retires the previous one, keeping it in JWKS for
   * `overlapSeconds` so tokens signed a moment ago still verify. Relying parties
   * are expected to re-fetch JWKS on an unknown `kid`.
   */
  async function rotate({ overlapSeconds = 24 * 60 * 60 } = {}) {
    if (source === "environment") {
      throw new Error("Signing keys come from OAUTH_SIGNING_KEYS_JSON; rotate them where they are managed");
    }
    if (!prisma?.signingKey?.updateMany) {
      throw new Error("Key rotation requires a database-backed key store");
    }
    const retireAt = new Date(now().getTime() + overlapSeconds * 1000);
    await prisma.signingKey.updateMany({
      where: { isActive: true },
      data: { isActive: false, rotatedAt: now(), expiresAt: retireAt }
    });
    await persistGeneratedKey();
    keyRing = null;
    return ensureKeyRing();
  }

  /** Drops retired keys whose overlap window has closed. */
  async function pruneExpired() {
    if (!prisma?.signingKey?.deleteMany) return { count: 0 };
    return prisma.signingKey.deleteMany({
      where: { isActive: false, expiresAt: { lt: now() } }
    });
  }

  return {
    ensureKeyRing,
    pruneExpired,
    rotate,
    get algorithm() {
      return algorithm;
    },
    get source() {
      return source;
    }
  };
}

module.exports = { createKeyService, parseEnvKeys };

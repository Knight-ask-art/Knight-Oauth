"use strict";

const { createKeyRing, generateKey, normalizeKey, DEFAULT_ALGORITHM, SUPPORTED_ALGORITHMS } = require("../lib/jwt");
const { randomId } = require("../lib/crypto");

// A deterministic primary key turns first-boot key creation into a database
// singleton. `kid` cannot do that because each process generates a different
// key before it writes. This id is only used for the initial generated key;
// rotated keys keep random ids.
const BOOTSTRAP_KEY_ID = "oauth-signing-key-bootstrap";

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
    const records = await prisma.signingKey.findMany({
      orderBy: [{ createdAt: "desc" }, { id: "desc" }]
    });
    const current = now();
    return records.filter((record) => record.isActive || !record.expiresAt || record.expiresAt > current);
  }

  function generatedKeyData(id = randomId()) {
    const key = generateKey({ alg: algorithm });
    const privateJwk = key.privateKey.export({ format: "jwk" });
    return {
      id,
      kid: key.kid,
      alg: key.alg,
      privateJwkJson: JSON.stringify(privateJwk),
      publicJwkJson: JSON.stringify(key.publicJwk),
      isActive: true
    };
  }

  async function persistGeneratedKey() {
    const record = await prisma.signingKey.create({ data: generatedKeyData() });
    return toKeyEntry(record);
  }

  async function persistBootstrapKey() {
    if (!prisma?.signingKey?.upsert) {
      throw new Error("Generated signing keys require a database-backed key store with upsert support");
    }
    const record = await prisma.signingKey.upsert({
      where: { id: BOOTSTRAP_KEY_ID },
      // A non-empty no-op update keeps this eligible for Prisma's native
      // INSERT ... ON CONFLICT path on both SQLite and PostgreSQL.
      update: { id: BOOTSTRAP_KEY_ID },
      create: generatedKeyData(BOOTSTRAP_KEY_ID)
    });
    return toKeyEntry(record);
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

    // Two replicas can both observe an empty table. The fixed bootstrap id and
    // atomic upsert make the database choose one row; every caller uses the row
    // returned by that upsert rather than its locally generated candidate.
    const generated = await persistBootstrapKey();
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

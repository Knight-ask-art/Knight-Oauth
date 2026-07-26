"use strict";

const crypto = require("node:crypto");

// JWS signing and verification for the algorithms an OIDC provider actually
// needs to be interoperable.
//
// The previous Knight-internal issuer signed only EdDSA. That is a fine
// algorithm and a poor default: RFC 7518 lists RS256 as the only *required*
// algorithm, OIDC Core section 15.1 mandates RS256 support for an OP, and a long
// tail of relying-party libraries (Grafana, Nextcloud, Discourse, Spring
// Security, most PHP and Java clients) implement RS256 and nothing else. So
// RS256 is the default here, with ES256 and EdDSA available for deployments
// whose clients support them.

const ALGORITHMS = {
  RS256: {
    kty: "RSA",
    // Node needs the digest named explicitly for RSASSA-PKCS1-v1_5.
    sign: (data, privateKey) => crypto.sign("sha256", data, privateKey),
    verify: (data, signature, publicKey) => crypto.verify("sha256", data, publicKey, signature),
    generate: () => crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }),
    matchesKey: (key) => key.asymmetricKeyType === "rsa"
  },
  ES256: {
    kty: "EC",
    // JWS requires the fixed-width R||S form, not the ASN.1 DER sequence
    // OpenSSL emits by default.
    sign: (data, privateKey) =>
      crypto.sign("sha256", data, { key: privateKey, dsaEncoding: "ieee-p1363" }),
    verify: (data, signature, publicKey) =>
      crypto.verify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature),
    generate: () => crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }),
    matchesKey: (key) => key.asymmetricKeyType === "ec"
  },
  EdDSA: {
    kty: "OKP",
    // Ed25519 hashes internally; passing a digest name is an error.
    sign: (data, privateKey) => crypto.sign(null, data, privateKey),
    verify: (data, signature, publicKey) => crypto.verify(null, data, publicKey, signature),
    generate: () => crypto.generateKeyPairSync("ed25519"),
    matchesKey: (key) => key.asymmetricKeyType === "ed25519"
  }
};

const SUPPORTED_ALGORITHMS = Object.keys(ALGORITHMS);
const DEFAULT_ALGORITHM = "RS256";

function jwtError(message, code = "INVALID_JWT") {
  const error = new Error(message);
  error.code = code;
  return error;
}

function encodeSegment(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decodeSegment(value, name) {
  try {
    const json = Buffer.from(String(value || ""), "base64url").toString("utf8");
    const parsed = JSON.parse(json);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed;
  } catch {
    throw jwtError(`Invalid ${name}`);
  }
}

/**
 * Splits a compact JWS without verifying it. Used only to read the `kid` and the
 * unverified `client_id`/`aud` needed to pick a key and an audience — never to
 * make an authorization decision.
 */
function decodeJwt(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw jwtError("Malformed JWT");
  }
  return {
    encodedHeader: parts[0],
    encodedPayload: parts[1],
    encodedSignature: parts[2],
    header: decodeSegment(parts[0], "JWT header"),
    payload: decodeSegment(parts[1], "JWT payload")
  };
}

/** RFC 7638 JWK thumbprint, so a `kid` is derived from the key rather than named by hand. */
function jwkThumbprint(publicJwk) {
  const members = {
    RSA: ["e", "kty", "n"],
    EC: ["crv", "kty", "x", "y"],
    OKP: ["crv", "kty", "x"]
  }[publicJwk.kty];
  if (!members) throw jwtError(`Unsupported key type ${publicJwk.kty}`, "INVALID_KEYSET");
  const canonical = {};
  for (const member of members) canonical[member] = publicJwk[member];
  return crypto.createHash("sha256").update(JSON.stringify(canonical), "utf8").digest("base64url");
}

function algorithmForKey(keyObject) {
  return SUPPORTED_ALGORITHMS.find((alg) => ALGORITHMS[alg].matchesKey(keyObject)) || null;
}

/**
 * Normalizes one key into the internal form: a Node KeyObject pair, the public
 * JWK to publish, and the algorithm it signs with.
 *
 * @param {object} entry `{ kid?, alg?, privateJwk | private_jwk | privateKeyPem }`
 */
function normalizeKey(entry) {
  if (!entry || typeof entry !== "object") {
    throw jwtError("A signing key entry must be an object", "INVALID_KEYSET");
  }

  const jwk = entry.privateJwk || entry.private_jwk || entry.jwk;
  const pem = entry.privateKeyPem || entry.private_key_pem;
  if (!jwk && !pem) {
    throw jwtError("A signing key entry requires privateJwk or privateKeyPem", "INVALID_KEYSET");
  }

  let privateKey;
  try {
    privateKey = pem
      ? crypto.createPrivateKey(String(pem))
      : crypto.createPrivateKey({ key: jwk, format: "jwk" });
  } catch {
    throw jwtError("A signing key is not a valid private key", "INVALID_KEYSET");
  }

  const detected = algorithmForKey(privateKey);
  if (!detected) {
    throw jwtError(
      `Unsupported key type ${privateKey.asymmetricKeyType}; use RSA, P-256 EC, or Ed25519`,
      "INVALID_KEYSET"
    );
  }

  const alg = String(entry.alg || detected).trim();
  if (!ALGORITHMS[alg]) {
    throw jwtError(`Unsupported signing algorithm ${alg}`, "INVALID_KEYSET");
  }
  if (!ALGORITHMS[alg].matchesKey(privateKey)) {
    throw jwtError(`Signing algorithm ${alg} does not match the supplied key type`, "INVALID_KEYSET");
  }
  if (alg === "RS256") {
    const bits = privateKey.asymmetricKeyDetails?.modulusLength ?? 0;
    if (bits && bits < 2048) {
      throw jwtError("An RSA signing key must be at least 2048 bits", "INVALID_KEYSET");
    }
  }
  if (alg === "ES256") {
    const curve = privateKey.asymmetricKeyDetails?.namedCurve;
    if (curve && curve !== "prime256v1") {
      throw jwtError("ES256 requires the P-256 curve", "INVALID_KEYSET");
    }
  }

  const publicKey = crypto.createPublicKey(privateKey);
  const exported = publicKey.export({ format: "jwk" });
  const kid = String(entry.kid || "").trim() || jwkThumbprint(exported);

  return {
    kid,
    alg,
    privateKey,
    publicKey,
    publicJwk: { ...exported, kid, use: "sig", alg }
  };
}

/** Generates a fresh key, for first-boot bootstrap and for rotation. */
function generateKey({ alg = DEFAULT_ALGORITHM, kid } = {}) {
  const definition = ALGORITHMS[alg];
  if (!definition) throw jwtError(`Unsupported signing algorithm ${alg}`, "INVALID_KEYSET");
  const { privateKey } = definition.generate();
  return normalizeKey({ alg, kid, privateJwk: privateKey.export({ format: "jwk" }) });
}

/**
 * A key ring holds every key whose tokens must still verify, and designates one
 * as active for signing. Retired keys stay in JWKS so tokens issued before a
 * rotation keep verifying until they expire.
 */
function createKeyRing({ keys = [], activeKid } = {}) {
  const normalized = keys.map(normalizeKey);
  if (!normalized.length) return null;

  if (new Set(normalized.map((key) => key.kid)).size !== normalized.length) {
    throw jwtError("Signing key ids must be unique", "INVALID_KEYSET");
  }

  const selected = String(activeKid || "").trim();
  const activeKey = selected
    ? normalized.find((key) => key.kid === selected)
    : normalized[0];
  if (!activeKey) {
    throw jwtError(`The active key id ${selected} is not present in the key set`, "INVALID_KEYSET");
  }

  return {
    activeKey,
    keys: normalized,
    keysByKid: new Map(normalized.map((key) => [key.kid, key])),
    algorithms: [...new Set(normalized.map((key) => key.alg))],
    jwks: { keys: normalized.map((key) => key.publicJwk) }
  };
}

/** Signs a compact JWS with the given key. */
function signJwt({ key, claims, header = {} }) {
  if (!key?.privateKey || !key?.kid || !key?.alg) {
    throw jwtError("A signing key is unavailable", "SIGNING_UNAVAILABLE");
  }
  const encodedHeader = encodeSegment({ alg: key.alg, kid: key.kid, typ: "JWT", ...header });
  const encodedPayload = encodeSegment(claims);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = ALGORITHMS[key.alg]
    .sign(Buffer.from(signingInput, "utf8"), key.privateKey)
    .toString("base64url");
  return `${signingInput}.${signature}`;
}

/**
 * Verifies signature and claims.
 *
 * `alg` is taken from the key the `kid` resolves to, never from the token
 * header, so a token cannot nominate its own algorithm — the substitution that
 * `alg: none` and RSA/HMAC confusion attacks rely on.
 */
function verifyJwt(
  token,
  {
    keyRing,
    issuer,
    audience,
    nowSeconds = () => Math.floor(Date.now() / 1000),
    allowExpired = false,
    clockToleranceSeconds = 0
  } = {}
) {
  if (!keyRing) throw jwtError("Signing keys are unavailable", "SIGNING_UNAVAILABLE");

  const parsed = decodeJwt(token);
  const kid = String(parsed.header?.kid || "").trim();
  if (!kid) throw jwtError("JWT header is missing kid");

  const key = keyRing.keysByKid.get(kid);
  if (!key) throw jwtError("Unknown JWT key id");

  // The header must agree with the key's algorithm; it does not get to choose it.
  if (parsed.header.alg !== key.alg) throw jwtError("JWT algorithm mismatch");

  const signingInput = Buffer.from(`${parsed.encodedHeader}.${parsed.encodedPayload}`, "utf8");
  let signature;
  try {
    signature = Buffer.from(parsed.encodedSignature, "base64url");
  } catch {
    throw jwtError("Malformed JWT signature");
  }

  let valid = false;
  try {
    valid = ALGORITHMS[key.alg].verify(signingInput, signature, key.publicKey);
  } catch {
    valid = false;
  }
  if (!valid) throw jwtError("Invalid JWT signature");

  const payload = parsed.payload;
  if (issuer && payload.iss !== issuer) throw jwtError("JWT issuer mismatch");

  if (audience) {
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audiences.includes(audience)) throw jwtError("JWT audience mismatch");
    // OIDC Core section 3.1.3.7: with multiple audiences, `azp` must name the
    // party the token was issued to.
    if (audiences.length > 1 && payload.azp && payload.azp !== audience) {
      throw jwtError("JWT azp mismatch");
    }
  }

  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)) {
    throw jwtError("JWT timing claims are invalid");
  }
  if (payload.exp <= payload.iat) throw jwtError("JWT expires before it was issued");

  const now = Number(nowSeconds());
  if (!allowExpired && payload.exp + clockToleranceSeconds <= now) {
    throw jwtError("JWT has expired", "JWT_EXPIRED");
  }
  if (Number.isInteger(payload.nbf) && payload.nbf - clockToleranceSeconds > now) {
    throw jwtError("JWT is not yet valid");
  }

  return { header: parsed.header, payload };
}

/**
 * `at_hash` / `c_hash` per OIDC Core section 3.1.3.6: base64url of the left half
 * of the hash of the ASCII value, using the digest paired with the signing
 * algorithm.
 */
function leftHalfHash(value, alg) {
  const digest = { RS256: "sha256", ES256: "sha256", EdDSA: "sha512" }[alg] || "sha256";
  const hash = crypto.createHash(digest).update(String(value), "ascii").digest();
  return hash.subarray(0, hash.length / 2).toString("base64url");
}

module.exports = {
  ALGORITHMS,
  DEFAULT_ALGORITHM,
  SUPPORTED_ALGORITHMS,
  createKeyRing,
  decodeJwt,
  generateKey,
  jwkThumbprint,
  leftHalfHash,
  normalizeKey,
  signJwt,
  verifyJwt
};

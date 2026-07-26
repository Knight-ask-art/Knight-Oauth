#!/usr/bin/env node
// Generates a signing key set for OAUTH_SIGNING_KEYS_JSON.
//
//   npm run keys:generate               one RS256 key
//   npm run keys:generate -- ES256      one ES256 key
//   npm run keys:generate -- RS256 2    two RS256 keys (for a staged rotation)
//
// The output contains a PRIVATE key. Put it in a secret manager or in .env,
// never in the repository. Printing to stdout is deliberate: it keeps the secret
// out of a file this script chose, and lets you pipe it where it belongs.

const { generateKey, SUPPORTED_ALGORITHMS, DEFAULT_ALGORITHM } = require("../src/lib/jwt");

function main() {
  const [algArg, countArg] = process.argv.slice(2);
  const alg = (algArg || DEFAULT_ALGORITHM).trim();
  if (!SUPPORTED_ALGORITHMS.includes(alg)) {
    process.stderr.write(`Algorithm must be one of ${SUPPORTED_ALGORITHMS.join(", ")}\n`);
    process.exit(1);
  }
  const count = Number(countArg || 1);
  if (!Number.isInteger(count) || count < 1 || count > 10) {
    process.stderr.write("Count must be an integer between 1 and 10\n");
    process.exit(1);
  }

  const keys = [];
  for (let index = 0; index < count; index += 1) {
    const key = generateKey({ alg });
    keys.push({
      kid: key.kid,
      alg: key.alg,
      privateJwk: key.privateKey.export({ format: "jwk" })
    });
  }

  // Single-line, because this is pasted into an environment variable.
  process.stdout.write(`${JSON.stringify({ keys })}\n`);
  process.stderr.write(
    `\nGenerated ${count} ${alg} key(s). Set this as OAUTH_SIGNING_KEYS_JSON and\n` +
      `set OAUTH_ALLOW_GENERATED_KEYS=false so the issuer uses only this key set.\n` +
      `The first key is the active signer; the rest stay published in JWKS.\n` +
      `This output is a private key — treat it as a secret.\n`
  );
}

main();

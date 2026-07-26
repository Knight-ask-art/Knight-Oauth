#!/usr/bin/env node
// One command to get from a fresh clone to a running issuer.
//
//   npm run setup
//
// It does the four things that must happen in order and nothing else:
//
//   1. render the Prisma schema for the configured provider
//   2. generate the Prisma client from it
//   3. apply the migrations
//   4. report what the next command is
//
// Nothing here writes a secret. A signing key is generated on first boot and
// stored in the database, which is the right default for a single-node install;
// `npm run keys:generate` is for the deployment that wants to hold the key
// itself. A `.env` is optional and is only created from the example on request,
// because a file this script invented is a file nobody knows to look at.

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const PROVIDERS = ["postgresql", "sqlite"];

function say(message) {
  process.stdout.write(`${message}\n`);
}

/**
 * Reads DATABASE_PROVIDER the same way scripts/prisma.js does, so setup and
 * every later command agree on which schema they are operating on.
 */
function resolveProvider() {
  if (!process.env.DATABASE_PROVIDER && fs.existsSync(path.join(ROOT, ".env"))) {
    try {
      process.loadEnvFile(path.join(ROOT, ".env"));
    } catch {
      // A malformed .env is reported by the step that actually needs it.
    }
  }
  const provider = String(process.env.DATABASE_PROVIDER || "sqlite").trim().toLowerCase();
  if (!PROVIDERS.includes(provider)) {
    process.stderr.write(`DATABASE_PROVIDER must be one of ${PROVIDERS.join(", ")}\n`);
    process.exit(1);
  }
  return provider;
}

/**
 * Runs a step as a child of this process.
 *
 * No shell. Each step is `node <script>`, and `process.execPath` on Windows is
 * `C:\Program Files\nodejs\node.exe` — through a shell that space splits the
 * command and the step fails with "'C:\Program' is not recognized" instead of
 * running. Nothing here needs shell features, so the argv is passed directly.
 */
function run(label, args) {
  say(`\n→ ${label}`);
  const result = spawnSync(process.execPath, args, { cwd: ROOT, stdio: "inherit" });
  if (result.error) {
    process.stderr.write(`\n${label} could not start: ${result.error.message}\n`);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.stderr.write(`\n${label} failed. Fix the error above and run npm run setup again.\n`);
    process.exit(result.status === null ? 1 : result.status);
  }
}

function main() {
  const provider = resolveProvider();
  const wantsEnv = process.argv.includes("--env");

  say(`Knight OAuth setup — database provider: ${provider}`);

  if (wantsEnv) {
    const target = path.join(ROOT, ".env");
    if (fs.existsSync(target)) {
      say("\n→ .env already exists, leaving it alone");
    } else {
      fs.copyFileSync(path.join(ROOT, ".env.example"), target);
      say("\n→ wrote .env from .env.example");
    }
  }

  // PostgreSQL needs a reachable database before step 3, and saying so here is
  // more useful than a connection error from the migration.
  if (provider === "postgresql" && !process.env.DATABASE_URL) {
    process.stderr.write(
      "\nDATABASE_PROVIDER is postgresql but DATABASE_URL is not set.\n" +
        "Set it in .env or in the environment, then run npm run setup again.\n"
    );
    process.exit(1);
  }

  run("rendering the Prisma schema", [path.join(ROOT, "scripts", "build-schema.js")]);
  run("generating the Prisma client", [path.join(ROOT, "scripts", "prisma.js"), "generate"]);
  run("applying migrations", [path.join(ROOT, "scripts", "prisma.js"), "migrate", "deploy"]);

  say(
    [
      "",
      "Done. Start the server with:",
      "",
      "    npm start",
      "",
      "Then open http://127.0.0.1:3010 and register. The first account becomes an",
      "administrator, so register yours before anyone else can reach the service.",
      "",
      "Discovery, for pointing a client library at it:",
      "",
      "    http://127.0.0.1:3010/.well-known/openid-configuration",
      ""
    ].join("\n")
  );
}

main();

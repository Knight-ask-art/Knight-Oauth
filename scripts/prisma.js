#!/usr/bin/env node
// Runs the Prisma CLI against the schema for the configured provider.
//
// There is one data model (prisma/schema.template.prisma) rendered into one
// schema per provider, so every Prisma command needs to be told which one it is
// operating on. Rather than making every caller remember `--schema`, this
// wrapper reads DATABASE_PROVIDER and inserts it.
//
//   node scripts/prisma.js migrate deploy
//   node scripts/prisma.js generate
//
// Migrations live beside their schema (prisma/<provider>/migrations), which is
// where Prisma looks by default. That separation is required, not cosmetic: the
// SQL that creates these tables is not identical on both databases.

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const PROVIDERS = ["postgresql", "sqlite"];

/** Reads DATABASE_PROVIDER from .env if the environment does not already set it. */
function resolveProvider() {
  if (!process.env.DATABASE_PROVIDER) {
    const envFile = path.join(ROOT, ".env");
    if (fs.existsSync(envFile)) {
      try {
        process.loadEnvFile(envFile);
      } catch {
        // A malformed .env is the Prisma CLI's problem to report, not ours.
      }
    }
  }
  const provider = String(process.env.DATABASE_PROVIDER || "sqlite").trim().toLowerCase();
  if (!PROVIDERS.includes(provider)) {
    process.stderr.write(`DATABASE_PROVIDER must be one of ${PROVIDERS.join(", ")}\n`);
    process.exit(1);
  }
  return provider;
}

function main() {
  const provider = resolveProvider();
  const schema = path.join("prisma", provider, "schema.prisma");

  if (!fs.existsSync(path.join(ROOT, schema))) {
    process.stderr.write(`${schema} is missing. Run: npm run db:schema\n`);
    process.exit(1);
  }

  // The URL is made absolute, not left relative.
  //
  // Prisma resolves a relative `file:` URL against the directory holding the
  // schema, and the schema is `prisma/sqlite/schema.prisma`, so a relative
  // default would migrate `prisma/sqlite/data/knight-oauth.db` while the running
  // app opened `data/knight-oauth.db`: two databases, and a service that starts
  // against an empty one. src/config/env.js resolves it the same way for the
  // runtime, so both land on the same file.
  if (provider === "sqlite") {
    const target = process.env.DATABASE_URL || "file:./data/knight-oauth.db";
    if (target.startsWith("file:")) {
      const filePath = target.slice("file:".length);
      const absolute =
        filePath === ":memory:" ? filePath : path.resolve(ROOT, filePath).replaceAll("\\", "/");
      if (filePath !== ":memory:") fs.mkdirSync(path.dirname(absolute), { recursive: true });
      process.env.DATABASE_URL = `file:${absolute}`;
    }
  }

  const args = process.argv.slice(2);
  if (!args.length) {
    process.stderr.write("Usage: node scripts/prisma.js <prisma-command> [...args]\n");
    process.exit(1);
  }

  // The CLI is invoked as a local file rather than through `npx`, and with no
  // shell. `npx` wants a writable cache directory, which a container running
  // read-only with a non-root user does not have, so `migrate deploy` inside the
  // image would fail on something unrelated to the migration. Resolving the
  // installed package also means the version in package.json is the one that
  // runs, with no chance of npx fetching a different one.
  let cli;
  try {
    cli = require.resolve("prisma/build/index.js");
  } catch {
    process.stderr.write("The Prisma CLI is not installed. Run: npm install\n");
    process.exit(1);
  }

  const result = spawnSync(process.execPath, [cli, ...args, "--schema", schema], {
    cwd: ROOT,
    stdio: "inherit"
  });
  if (result.error) {
    process.stderr.write(`Could not run the Prisma CLI: ${result.error.message}\n`);
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

main();

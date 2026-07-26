#!/usr/bin/env node
// Container entrypoint.
//
// Applies migrations, then hands off to the server. `migrate deploy` is
// idempotent — it applies what is pending and reports "No pending migrations"
// otherwise — so a restart costs one query.
//
// This is on by default for SQLite and off by default for PostgreSQL, and the
// asymmetry is deliberate. A SQLite deployment is one container with one file,
// and asking someone to run a migration by hand before the service will start is
// a bad first experience. A PostgreSQL deployment usually has more than one
// replica, and several replicas racing to migrate the same database is a real way
// to corrupt one. There, the migration is a step an operator runs once:
//
//   docker compose run --rm knight-oauth node scripts/prisma.js migrate deploy
//
// Override either way with OAUTH_MIGRATE_ON_START=true|false.
//
// The handoff is a require of `runAsMain`, not a second process. The server is
// therefore the same PID the container runtime is watching, so a SIGTERM from
// `docker stop` reaches the process that knows how to drain rather than a
// wrapper that would not forward it.

const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");

// Load `.env` before deciding anything about the database. The migration step
// and the server must see the same DATABASE_URL, and a compose file that mounts
// one into /app/.env would otherwise be ignored until the server started.
const { loadDotEnv } = require(path.join(ROOT, "src", "config", "dotenv"));
loadDotEnv();

function bool(value) {
  if (value === undefined || value === "") return undefined;
  const text = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(text)) return true;
  if (["0", "false", "no", "off"].includes(text)) return false;
  process.stderr.write(`OAUTH_MIGRATE_ON_START must be true or false, received "${value}"\n`);
  process.exit(1);
}

function main() {
  const provider = String(process.env.DATABASE_PROVIDER || "sqlite").trim().toLowerCase();
  const configured = bool(process.env.OAUTH_MIGRATE_ON_START);
  const migrate = configured === undefined ? provider === "sqlite" : configured;

  if (migrate) {
    process.stdout.write("applying migrations\n");
    const result = spawnSync(
      process.execPath,
      [path.join(ROOT, "scripts", "prisma.js"), "migrate", "deploy"],
      { cwd: ROOT, stdio: "inherit" }
    );
    if (result.status !== 0) {
      // Deliberately fatal. Starting against a database whose schema does not
      // match the client produces a service that answers discovery and then fails
      // every request that touches a table, which is harder to diagnose than a
      // container that refuses to start.
      process.stderr.write("\nMigrations failed; not starting the server.\n");
      process.exit(result.status === null ? 1 : result.status);
    }
  } else {
    process.stdout.write(
      `skipping migrations (DATABASE_PROVIDER=${provider}); run: node scripts/prisma.js migrate deploy\n`
    );
  }

  // Same PID, same process. The signal handlers registered by runAsMain are the
  // ones the container runtime will reach.
  require(path.join(ROOT, "src", "server.js")).runAsMain();
}

main();

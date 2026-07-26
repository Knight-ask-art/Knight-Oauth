"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

// Integration tests run against a real database rather than a hand-rolled Prisma
// double.
//
// A double proves the code calls the methods the author expected. It cannot prove
// a unique constraint fires, that a scoped `updateMany` actually makes a
// single-use token single-use, or that the generated schema applies at all. Those
// are exactly the properties this service depends on, so they are tested against
// the real engine.
//
// *Which* real engine is the point of this file.
//
// It used to be SQLite and only SQLite: the sqlite migration was replayed
// directly, so every integration test ran on one of the two databases this
// project claims to support, and the CI job that has a live PostgreSQL never ran
// `npm test` against it. That is not a gap in coverage so much as a gap in the
// shape of it — the failures it hides are the ones where the two engines
// disagree, and SQLite is the forgiving one. Prisma opens a single connection to
// SQLite and the whole application is one writer, so a check-then-act that races
// on PostgreSQL is serialised into correctness here and passes.
//
// DATABASE_PROVIDER selects. Each suite still gets its own isolated database:
// a file on SQLite, a schema on PostgreSQL. Both are needed, because
// `node --test` runs test files concurrently and three of them use a database.

const ROOT = path.resolve(__dirname, "..", "..");
const TEST_DIR = path.join(ROOT, "data", "test");

const PROVIDER = String(process.env.DATABASE_PROVIDER || "sqlite")
  .trim()
  .toLowerCase();

/** The single generated migration for a provider, found rather than hardcoded. */
function migrationFor(provider) {
  const dir = path.join(ROOT, "prisma", provider, "migrations");
  if (!fs.existsSync(dir)) {
    throw new Error(`prisma/${provider}/migrations is missing. Run: npm run db:schema && npm run db:migrate`);
  }
  const entries = fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(dir, entry.name, "migration.sql"))
    .filter((file) => fs.existsSync(file))
    .sort();
  if (!entries.length) {
    throw new Error(`no migration.sql under prisma/${provider}/migrations`);
  }
  return entries;
}

/**
 * Splits a migration into statements. The generated SQL contains no string
 * literals with semicolons and no triggers or procedures, so splitting on `;` is
 * sound here — it would not be for arbitrary SQL.
 *
 * Each statement is preceded by a `-- CreateTable` comment, so comment lines are
 * stripped from within a chunk rather than the chunk being discarded.
 */
function statements(sql) {
  return sql
    .split(";")
    .map((chunk) =>
      chunk
        .split("\n")
        .filter((line) => !line.trim().startsWith("--"))
        .join("\n")
        .trim()
    )
    .filter(Boolean);
}

function loadPrisma() {
  // The generated client matches whichever provider `db:generate` last ran for,
  // so a mismatch here is a configuration error rather than something to paper
  // over.
  // eslint-disable-next-line global-require
  return require("@prisma/client").PrismaClient;
}

async function applyMigrations(prisma, files) {
  for (const file of files) {
    for (const statement of statements(fs.readFileSync(file, "utf8"))) {
      await prisma.$executeRawUnsafe(statement);
    }
  }
}

async function withSqlite() {
  const files = migrationFor("sqlite");
  fs.mkdirSync(TEST_DIR, { recursive: true });

  const file = path.join(TEST_DIR, `${crypto.randomUUID()}.db`);
  const url = `file:${file.replaceAll("\\", "/")}`;

  process.env.DATABASE_URL = url;
  const PrismaClient = loadPrisma();
  // Logging is off: several tests assert that a unique constraint fires, and
  // Prisma prints those expected violations, which buries a real failure.
  const prisma = new PrismaClient({ datasources: { db: { url } }, log: [] });

  await applyMigrations(prisma, files);

  async function close() {
    await prisma.$disconnect();
    for (const suffix of ["", "-journal", "-wal", "-shm"]) {
      try {
        fs.rmSync(`${file}${suffix}`, { force: true });
      } catch {
        // A Windows file lock can outlive disconnect; a leftover file in
        // data/test is harmless and gitignored.
      }
    }
  }

  return { prisma, close, url, file, provider: "sqlite" };
}

async function withPostgres() {
  const files = migrationFor("postgresql");
  const base = String(process.env.DATABASE_URL || "").trim();
  if (!base) {
    throw new Error("DATABASE_URL is required when DATABASE_PROVIDER=postgresql");
  }

  // A schema per suite, because `node --test` runs the files concurrently and
  // they would otherwise create the same tables in the same place.
  const schema = `test_${crypto.randomUUID().replaceAll("-", "")}`;
  const scoped = new URL(base);
  scoped.searchParams.set("schema", schema);
  const url = scoped.toString();

  const PrismaClient = loadPrisma();

  // Created over a separate connection, before the scoped one is opened.
  // Prisma turns `?schema=` into a search_path, and an unqualified CREATE TABLE
  // against a search_path naming a schema that does not exist yet fails with
  // "no schema has been selected to create in" — so the schema has to be there
  // first.
  const bootstrap = new PrismaClient({ datasources: { db: { url: base } }, log: [] });
  await bootstrap.$executeRawUnsafe(`CREATE SCHEMA IF NOT EXISTS "${schema}"`);
  await bootstrap.$disconnect();

  process.env.DATABASE_URL = url;
  const prisma = new PrismaClient({ datasources: { db: { url } }, log: [] });
  await applyMigrations(prisma, files);

  async function close() {
    await prisma.$disconnect();
    const cleanup = new PrismaClient({ datasources: { db: { url: base } }, log: [] });
    try {
      await cleanup.$executeRawUnsafe(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    } finally {
      await cleanup.$disconnect();
    }
  }

  return { prisma, close, url, schema, provider: "postgresql" };
}

async function withDatabase() {
  return PROVIDER === "postgresql" ? withPostgres() : withSqlite();
}

module.exports = { withDatabase, statements, execFileSync, PROVIDER };

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

// Integration tests run against a real SQLite database rather than a hand-rolled
// Prisma double.
//
// A double proves the code calls the methods the author expected. It cannot prove
// a unique constraint fires, that a scoped `updateMany` actually makes a
// single-use token single-use, or that the generated schema applies at all. Those
// are exactly the properties this service depends on, so they are tested against
// the real engine.
//
// Each suite gets its own file, deleted afterwards, so tests do not share state.

const ROOT = path.resolve(__dirname, "..", "..");
const TEST_DIR = path.join(ROOT, "data", "test");
const MIGRATION = path.join(ROOT, "prisma", "sqlite", "migrations", "0000000000000_init", "migration.sql");

/**
 * Splits the migration into statements. The generated SQL contains no string
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

async function withDatabase() {
  if (!fs.existsSync(MIGRATION)) {
    throw new Error("prisma/sqlite migrations are missing. Run: npm run db:schema && npm run db:migrate");
  }
  fs.mkdirSync(TEST_DIR, { recursive: true });

  const file = path.join(TEST_DIR, `${crypto.randomUUID()}.db`);
  const url = `file:${file.replaceAll("\\", "/")}`;

  // The client is generated from the sqlite schema; `db:generate` must have run.
  process.env.DATABASE_URL = url;
  // eslint-disable-next-line global-require
  const { PrismaClient } = require("@prisma/client");
  // Logging is off: several tests assert that a unique constraint fires, and
  // Prisma prints those expected violations, which buries a real failure.
  const prisma = new PrismaClient({
    datasources: { db: { url } },
    log: []
  });

  const sql = fs.readFileSync(MIGRATION, "utf8");
  for (const statement of statements(sql)) {
    await prisma.$executeRawUnsafe(statement);
  }

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

  return { prisma, close, url, file };
}

module.exports = { withDatabase, statements, execFileSync };

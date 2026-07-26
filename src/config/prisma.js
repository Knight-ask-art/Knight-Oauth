"use strict";

const fs = require("node:fs");
const path = require("node:path");

const { loadDotEnv } = require("./dotenv");
const { loadEnv } = require("./env");

// The shared Prisma client, built on first use.
//
// Lazily, and that is not an optimisation. This module is reached by importing
// `src/app.js`, and the test suite imports it hundreds of times while supplying
// its own client. Building eagerly would mean every one of those runs opened a
// connection nothing used, and — worse — validated the developer's local `.env`,
// so a `.env` written for a production deployment would fail the test suite.
//
// The URL comes from the validated configuration rather than being left for
// Prisma to read out of the environment. Two reasons, both of which were real
// bugs:
//
//   * Prisma resolves a relative `file:` URL against the schema's directory, so
//     the default landed in `prisma/sqlite/data/` rather than `data/` — a
//     different database from the one the migrations were applied to. The
//     configuration resolves it to an absolute path first.
//
//   * With no DATABASE_URL in the environment at all, which is the state of a
//     fresh clone, Prisma refuses to construct a client. `npm start` failed with
//     a schema validation error instead of using the documented SQLite default.

let client = null;

function build() {
  loadDotEnv();
  const config = loadEnv();

  // SQLite will not create a missing directory, and the first thing the server
  // does is connect. The URL is absolute by this point, so this creates the
  // directory the client is actually going to open.
  if (config.database.provider === "sqlite") {
    const file = config.database.url.slice("file:".length);
    if (file !== ":memory:") fs.mkdirSync(path.dirname(file), { recursive: true });
  }

  // Required here rather than at the top of the file: on a clone where
  // `prisma generate` has not run, `@prisma/client` throws on import. Deferring
  // it means the error arrives from the code path that needs a database, and the
  // message below says what to run.
  let PrismaClient;
  try {
    ({ PrismaClient } = require("@prisma/client"));
  } catch (error) {
    throw new Error(
      `The Prisma client is not generated. Run: npm run setup\n(${error?.message})`
    );
  }

  return new PrismaClient({
    datasources: { db: { url: config.database.url } },
    // Query logging stays off in every environment: these queries carry token
    // hashes and session identifiers, and a log is not a place those belong.
    log: config.isProduction ? ["error"] : ["warn", "error"]
  });
}

module.exports = {
  get prisma() {
    if (!client) client = build();
    return client;
  }
};

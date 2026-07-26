"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createAccountService } = require("../../src/services/accountService");

// The administrator user search, tested at the query it builds rather than the
// rows it returns.
//
// This is deliberate. The behaviour under test is a disagreement *between* the
// two databases — Prisma compiles `contains` to LIKE, SQLite folds case for
// ASCII and PostgreSQL does not — and tests/helpers/database.js runs on SQLite
// only, so a row-level test passes on the database that was never broken. The
// bug it is guarding against shipped exactly that way: searching "smith" found
// "Alice Smith" on SQLite and nothing on PostgreSQL.
//
// A stub client makes the assertion the one that matters: given a provider,
// which filter is sent. No database is involved, so it runs on both.

/** Records the `where` handed to Prisma and returns nothing. */
function stubPrisma() {
  const seen = [];
  return {
    seen,
    user: {
      findMany: async ({ where }) => {
        seen.push(where);
        return [];
      },
      count: async () => 0
    }
  };
}

function serviceFor(provider) {
  const prisma = stubPrisma();
  const accounts = createAccountService({
    prisma,
    config: { database: { provider } }
  });
  return { prisma, accounts };
}

test("the search is case-insensitive on postgresql", async () => {
  const { prisma, accounts } = serviceFor("postgresql");
  await accounts.list({ query: "Smith" });

  const [where] = prisma.seen;
  for (const clause of where.OR) {
    const [field, filter] = Object.entries(clause)[0];
    assert.equal(
      filter.mode,
      "insensitive",
      `${field} is filtered case-sensitively, so an administrator searching "smith" would not find "Smith"`
    );
  }
});

test("the search sends no mode on sqlite, which would reject it", async () => {
  const { prisma, accounts } = serviceFor("sqlite");
  await accounts.list({ query: "Smith" });

  const [where] = prisma.seen;
  for (const clause of where.OR) {
    const [field, filter] = Object.entries(clause)[0];
    assert.equal(
      "mode" in filter,
      false,
      `${field} sends mode to SQLite, where Prisma rejects it as an unknown argument`
    );
  }
});

test("an unset provider is treated as sqlite rather than sending mode", async () => {
  const { prisma, accounts } = serviceFor(undefined);
  await accounts.list({ query: "Smith" });

  for (const clause of prisma.seen[0].OR) {
    assert.equal("mode" in Object.values(clause)[0], false);
  }
});

test("the email term is folded regardless of provider", async () => {
  for (const provider of ["postgresql", "sqlite"]) {
    const { prisma, accounts } = serviceFor(provider);
    await accounts.list({ query: "Alice@Example.COM" });

    const email = prisma.seen[0].OR.find((clause) => "email" in clause).email;
    // Addresses are stored normalized by normalizeEmail, so folding the term is
    // what makes this an exact match rather than merely a case-insensitive one.
    assert.equal(email.contains, "alice@example.com", `provider ${provider}`);
  }
});

test("an empty query filters nothing rather than matching everything by accident", async () => {
  const { prisma, accounts } = serviceFor("postgresql");
  await accounts.list({ query: "   " });

  assert.deepEqual(prisma.seen[0], {});
});

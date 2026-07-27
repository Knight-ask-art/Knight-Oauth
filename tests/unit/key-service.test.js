"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { createKeyService } = require("../../src/services/keyService");

/**
 * Models two processes that both observe an empty signing-key table. With a
 * check-then-create implementation, the second insert is held until the first
 * process has re-read and cached its own key. An atomic upsert never reaches
 * that second-insert path: both processes receive the same persisted row.
 */
function createRacingStore() {
  const rows = [];
  const initialReads = [];
  let createCalls = 0;
  let pendingSecondCreate = null;

  function copyRows() {
    return rows
      .slice()
      .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime());
  }

  function persist(data) {
    const record = {
      ...data,
      createdAt: new Date(Date.UTC(2026, 0, 1, 0, 0, rows.length)),
      rotatedAt: null,
      expiresAt: null
    };
    rows.push(record);
    return record;
  }

  const signingKey = {
    async findMany() {
      if (initialReads.length < 2) {
        return new Promise((resolve) => {
          initialReads.push(resolve);
          if (initialReads.length === 2) {
            for (const settle of initialReads) settle([]);
          }
        });
      }

      const snapshot = copyRows();
      if (pendingSecondCreate) {
        const pending = pendingSecondCreate;
        pendingSecondCreate = null;
        queueMicrotask(() => pending.resolve(persist(pending.data)));
      }
      return snapshot;
    },

    async create({ data }) {
      createCalls += 1;
      if (createCalls === 1) return persist(data);
      return new Promise((resolve) => {
        pendingSecondCreate = { data, resolve };
      });
    },

    async upsert({ where, create }) {
      const existing = rows.find((row) => row.id === where.id);
      return existing || persist(create);
    }
  };

  return { prisma: { signingKey }, rows };
}

test("concurrent first boots converge on one database signing key", async () => {
  const store = createRacingStore();
  const config = { algorithm: "EdDSA", allowGeneratedKeys: true };
  const first = createKeyService({ prisma: store.prisma, config });
  const second = createKeyService({ prisma: store.prisma, config });

  const [firstRing, secondRing] = await Promise.all([
    first.ensureKeyRing(),
    second.ensureKeyRing()
  ]);

  assert.equal(store.rows.length, 1, "bootstrap must persist exactly one active key");
  assert.equal(firstRing.activeKey.kid, secondRing.activeKey.kid);
  assert.equal(firstRing.activeKey.kid, store.rows[0].kid);
});

test("the PostgreSQL production compose fails closed without managed signing keys", () => {
  const compose = fs.readFileSync(
    path.resolve(__dirname, "..", "..", "compose.postgres.yml"),
    "utf8"
  );

  assert.match(
    compose,
    /OAUTH_ALLOW_GENERATED_KEYS:\s*\$\{OAUTH_ALLOW_GENERATED_KEYS:-false\}/
  );
  assert.doesNotMatch(
    compose,
    /OAUTH_ALLOW_GENERATED_KEYS:\s*\$\{OAUTH_ALLOW_GENERATED_KEYS:-true\}/
  );
});

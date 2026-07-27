"use strict";

const assert = require("node:assert/strict");
const { after, before, describe, it } = require("node:test");
const { PrismaClient } = require("@prisma/client");

const { withDatabase } = require("../helpers/database");
const { createKeyService } = require("../../src/services/keyService");

describe("database signing-key bootstrap", () => {
  let db;

  before(async () => {
    db = await withDatabase();
  });

  after(async () => {
    await db.close();
  });

  it("converges concurrent first boots on one persisted key", async () => {
    const config = { algorithm: "EdDSA", allowGeneratedKeys: true };
    // One PrismaClient per service models separate issuer processes and separate
    // connection pools. Sharing db.prisma only proves concurrency inside one
    // client; it does not exercise PostgreSQL's cross-connection conflict path.
    const isolatedClients = Array.from(
      { length: 8 },
      () => new PrismaClient({ datasources: { db: { url: db.url } }, log: [] })
    );

    try {
      const services = isolatedClients.map((prisma) => createKeyService({ prisma, config }));
      const rings = await Promise.all(services.map((service) => service.ensureKeyRing()));
      const records = await db.prisma.signingKey.findMany({ where: { isActive: true } });

      assert.equal(records.length, 1, "concurrent bootstrap persisted more than one active key");
      assert.equal(new Set(rings.map((ring) => ring.activeKey.kid)).size, 1);
      assert.equal(rings[0].activeKey.kid, records[0].kid);
    } finally {
      await Promise.all(isolatedClients.map((client) => client.$disconnect()));
    }
  });
});

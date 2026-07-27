"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { createBackchannelService } = require("../../src/services/backchannelService");

function clientRecord(backchannelLogoutUri) {
  return {
    clientId: "client-under-test",
    backchannelLogoutUri
  };
}

function clientFacade() {
  return {
    async findByClientId() {
      throw new Error("enqueue escaped the supplied transaction");
    },
    toClient(record) {
      return record;
    }
  };
}

test("back-channel enqueue reads the client and writes the outbox in one transaction", async () => {
  const writes = [];
  const transaction = {
    oAuthClient: {
      async findUnique() {
        return clientRecord("https://client.example/logout");
      }
    },
    backchannelLogout: {
      async create({ data }) {
        writes.push(data);
      }
    }
  };
  const service = createBackchannelService({
    prisma: {},
    config: { issuer: "https://issuer.example" },
    clients: clientFacade()
  });

  const queued = await service.enqueue(
    {
      clientId: "client-under-test",
      sid: "session-id",
      userId: "user-id",
      subject: "user-id"
    },
    transaction
  );

  assert.equal(queued, true);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].clientId, "client-under-test");
});

test("back-channel enqueue observes an endpoint removed in the current transaction", async () => {
  let writes = 0;
  const transaction = {
    oAuthClient: {
      async findUnique() {
        return clientRecord(null);
      }
    },
    backchannelLogout: {
      async create() {
        writes += 1;
      }
    }
  };
  const service = createBackchannelService({
    prisma: {},
    config: { issuer: "https://issuer.example" },
    clients: clientFacade()
  });

  const queued = await service.enqueue(
    {
      clientId: "client-under-test",
      sid: "session-id",
      userId: "user-id",
      subject: "user-id"
    },
    transaction
  );

  assert.equal(queued, false);
  assert.equal(writes, 0);
});

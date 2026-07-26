"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { createCounter, createRateLimitMiddleware } = require("../../src/middleware/rateLimit");

// The rate limiter, tested at the two things the integration test cannot reach
// cheaply: what happens when a window elapses, and whether the two halves of
// the key are independent budgets.
//
// tests/integration/http.test.js covers the half that matters most — that the
// middleware is mounted in the real app and reads the configured value — since
// the defect being fixed was a setting with no consumer at all, which every
// unit test in the world would have passed. This file covers the arithmetic.

/** A clock that only moves when told to. */
function fakeClock(start = 1_000_000) {
  let value = start;
  return {
    now: () => value,
    advance: (ms) => {
      value += ms;
    }
  };
}

function fakeRes() {
  const res = {
    statusCode: null,
    headers: {},
    body: null,
    rendered: null,
    set(name, value) {
      res.headers[name.toLowerCase()] = value;
      return res;
    },
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      return res;
    },
    render(template, locals) {
      res.rendered = { template, locals };
      return res;
    }
  };
  return res;
}

function runMiddleware(middleware, { path, method = "POST", ip, body = {} }) {
  const res = fakeRes();
  let passed = false;
  middleware({ path, method, ip, body }, res, () => {
    passed = true;
  });
  return { res, passed };
}

const config = (overrides = {}) => ({
  security: { loginRateLimitPerMinute: 3, tokenRateLimitPerMinute: 5, ...overrides }
});

test("a window allows exactly the limit, then refuses", () => {
  const clock = fakeClock();
  const counter = createCounter({ now: clock.now });

  for (let i = 0; i < 4; i += 1) {
    assert.equal(counter.hit("k", 4).allowed, true, `hit ${i + 1} of 4 should be allowed`);
  }
  assert.equal(counter.hit("k", 4).allowed, false, "the fifth is over a limit of four");
});

test("the window resets once it has elapsed, rather than blocking forever", () => {
  const clock = fakeClock();
  const counter = createCounter({ now: clock.now });

  counter.hit("k", 1);
  assert.equal(counter.hit("k", 1).allowed, false);

  // A locked-out caller has to become un-locked-out, or the limiter is an
  // outage with a timer on it.
  clock.advance(60_000);
  assert.equal(counter.hit("k", 1).allowed, true, "the window never reopened");
});

test("retry-after counts down within the window rather than restating it", () => {
  const clock = fakeClock();
  const counter = createCounter({ now: clock.now });

  counter.hit("k", 1);
  clock.advance(45_000);
  const blocked = counter.hit("k", 1);
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.retryAfterSeconds, 15);
});

test("one address cannot spend another account's budget, and vice versa", () => {
  const middleware = createRateLimitMiddleware({ config: config(), logger: { warn() {} } });
  const attempt = (ip, identifier) =>
    runMiddleware(middleware, { path: "/login", ip, body: { identifier } });

  // Three from one address against one account: at the limit.
  for (let i = 0; i < 3; i += 1) assert.equal(attempt("10.0.0.1", "ada@example.com").passed, true);
  assert.equal(attempt("10.0.0.1", "ada@example.com").passed, false);

  // A different address, same account. The account's own budget is spent, so
  // this is still refused — otherwise a botnet walks straight past the limit.
  assert.equal(attempt("10.0.0.2", "ada@example.com").passed, false);

  // A different account from a fresh address: unaffected.
  assert.equal(attempt("10.0.0.3", "grace@example.com").passed, true);
});

test("an address is metered even when no identifier is submitted", () => {
  const middleware = createRateLimitMiddleware({ config: config(), logger: { warn() {} } });
  const attempt = () => runMiddleware(middleware, { path: "/login", ip: "10.0.0.9", body: {} });

  for (let i = 0; i < 3; i += 1) assert.equal(attempt().passed, true);
  assert.equal(attempt().passed, false, "omitting the identifier must not opt out of the limit");
});

test("a refused sign-in renders a page; a refused token request answers JSON", () => {
  const middleware = createRateLimitMiddleware({ config: config(), logger: { warn() {} } });

  let last;
  for (let i = 0; i < 4; i += 1) {
    last = runMiddleware(middleware, { path: "/login", ip: "10.0.1.1", body: {} });
  }
  assert.equal(last.res.statusCode, 429);
  assert.equal(last.res.rendered?.template, "error");
  assert.ok(last.res.headers["retry-after"], "a 429 must say when to retry");

  for (let i = 0; i < 6; i += 1) {
    last = runMiddleware(middleware, { path: "/oauth2/token", ip: "10.0.1.1", body: {} });
  }
  assert.equal(last.res.statusCode, 429);
  // A client library parses this; an HTML error page would be an unreadable
  // failure at the one endpoint that is never opened by a browser.
  assert.equal(last.res.body?.error, "slow_down");
  assert.equal(last.res.rendered, null);
});

test("the two limits are separate settings, and each is read", () => {
  // The token endpoint is not scrypt-bound, so it carries a much higher ceiling.
  // Reading one setting for both would be invisible in any test that used the
  // same number for each.
  const middleware = createRateLimitMiddleware({
    config: { security: { loginRateLimitPerMinute: 1, tokenRateLimitPerMinute: 4 } },
    logger: { warn() {} }
  });

  assert.equal(runMiddleware(middleware, { path: "/login", ip: "10.0.2.1", body: {} }).passed, true);
  assert.equal(runMiddleware(middleware, { path: "/login", ip: "10.0.2.1", body: {} }).passed, false);

  for (let i = 0; i < 4; i += 1) {
    assert.equal(runMiddleware(middleware, { path: "/oauth2/token", ip: "10.0.2.1", body: {} }).passed, true);
  }
  assert.equal(runMiddleware(middleware, { path: "/oauth2/token", ip: "10.0.2.1", body: {} }).passed, false);
});

test("an unmetered path and a non-matching method pass straight through", () => {
  const middleware = createRateLimitMiddleware({ config: config(), logger: { warn() {} } });

  for (let i = 0; i < 20; i += 1) {
    assert.equal(runMiddleware(middleware, { path: "/account", ip: "10.0.3.1", body: {} }).passed, true);
    // The login page itself is a GET, and rendering it costs nothing.
    assert.equal(
      runMiddleware(middleware, { path: "/login", method: "GET", ip: "10.0.3.1", body: {} }).passed,
      true
    );
  }
});

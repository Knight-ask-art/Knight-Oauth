"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { findMatchingRedirectUri, parseRedirectUri } = require("../../src/lib/uri");

// Redirect URI matching, which is the comparison that decides where an
// authorization code is delivered. Getting it wrong is redirect-based account
// takeover, so the negative cases below matter more than the positive ones and
// are the larger half of this file on purpose.
//
// What changed: a registered URI has always been stored in the form
// parseRedirectUri produces, while the requested one was compared as the raw
// string the client sent. That is not stricter than exact matching, only
// inconsistent — it refused requests that denoted the registered endpoint
// exactly. Both sides are now normalised the same way.

/** How a URI is stored once registered. */
const registered = (uri) => parseRedirectUri(uri);

const matches = (registeredUris, requested) =>
  findMatchingRedirectUri(registeredUris.map(registered), requested) !== null;

test("a registration is stored in normalised form", () => {
  // The premise of everything below. If this stops holding, the comparison is
  // being asked to reconcile two arbitrary strings again.
  assert.equal(registered("https://rp.example"), "https://rp.example/");
  assert.equal(registered("https://RP.Example/cb"), "https://rp.example/cb");
  assert.equal(registered("https://rp.example:443/cb"), "https://rp.example/cb");
});

test("forms that denote the registered endpoint are accepted", () => {
  const uris = ["https://rp.example/cb"];

  assert.ok(matches(uris, "https://rp.example/cb"), "the literal form");
  assert.ok(matches(uris, "https://rp.example:443/cb"), "the default port stated explicitly");
  assert.ok(matches(uris, "https://RP.example/cb"), "the host in another case");
  assert.ok(matches(uris, "HTTPS://rp.example/cb"), "the scheme in another case");

  // A registration written without a trailing slash is stored with one, so the
  // request that omits it has to match.
  assert.ok(matches(["https://rp.example"], "https://rp.example"), "no path either side");
  assert.ok(matches(["https://rp.example"], "https://rp.example/"), "path added by the client");
});

test("a different destination is refused, however it is dressed up", () => {
  const uris = ["https://rp.example/cb"];

  assert.ok(!matches(uris, "https://evil.example/cb"), "another host");
  assert.ok(!matches(uris, "https://rp.example.evil.example/cb"), "the host as a prefix of another");
  assert.ok(!matches(uris, "https://sub.rp.example/cb"), "a subdomain");
  assert.ok(!matches(uris, "http://rp.example/cb"), "the scheme downgraded");
  assert.ok(!matches(uris, "https://rp.example:8443/cb"), "a non-default port");
  assert.ok(!matches(uris, "https://rp.example/cbx"), "the path as a prefix of another");
  assert.ok(!matches(uris, "https://rp.example/cb/more"), "a longer path");
  assert.ok(!matches(uris, "https://rp.example/"), "the registered path dropped");
  assert.ok(!matches(uris, "https://rp.example/cb?x=1"), "a query the registration does not have");

  // The classic one: everything up to the `@` is userinfo, so this is a request
  // for evil.example that reads as rp.example.
  assert.ok(!matches(uris, "https://rp.example@evil.example/cb"), "the registered host as userinfo");
  assert.ok(!matches(uris, "https://rp.example:x@evil.example/cb"), "userinfo with a password");

  // Normalising resolves dot-segments, so this is a request for /evil.
  assert.ok(!matches(uris, "https://rp.example/cb/../evil"), "dot-segments leading elsewhere");

  // RFC 6749 section 3.1.2: the endpoint URI must not include a fragment. A
  // registration cannot carry one, so a request that does cannot match.
  assert.ok(!matches(uris, "https://rp.example/cb#x"), "a fragment");

  assert.ok(!matches(uris, ""), "nothing at all");
  assert.ok(!matches(uris, "not-a-url"), "not a URI");
  assert.ok(!matches(uris, "/cb"), "a relative reference");
});

test("normalising a dot-segment path does not let it reach a different registration", () => {
  // Both are registered, so the question is which one the request resolves to
  // rather than whether it is accepted at all. It has to be the one it denotes.
  const uris = ["https://rp.example/cb", "https://rp.example/evil"].map(registered);
  assert.equal(findMatchingRedirectUri(uris, "https://rp.example/cb/../evil"), "https://rp.example/evil");
});

test("a loopback registration still matches on any port, and only on port", () => {
  // RFC 8252 section 7.3: a native app cannot predict the port the OS hands it.
  const uris = ["http://127.0.0.1:1234/cb"];

  assert.ok(matches(uris, "http://127.0.0.1:49152/cb"), "another port");
  assert.ok(matches(uris, "http://127.0.0.1/cb"), "no port");

  assert.ok(!matches(uris, "http://localhost:1234/cb"), "localhost is a different host from 127.0.0.1");
  assert.ok(!matches(uris, "http://127.0.0.1:1234/other"), "a different path");
  assert.ok(!matches(uris, "http://127.0.0.2:1234/cb"), "a different address");
  assert.ok(!matches(uris, "https://127.0.0.1:1234/cb"), "a different scheme");
  // The carve-out is for loopback only; it must not float the port anywhere else.
  assert.ok(!matches(["https://rp.example:8443/cb"], "https://rp.example:9999/cb"), "a public host");
});

test("a private-use scheme matches exactly, with no normalisation to hide behind", () => {
  const uris = ["com.example.app:/oauth2redirect"];

  assert.ok(matches(uris, "com.example.app:/oauth2redirect"));
  assert.ok(!matches(uris, "com.example.evil:/oauth2redirect"));
  assert.ok(!matches(uris, "com.example.app:/other"));
});

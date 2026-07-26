"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { isPrivateNetworkHost, parseHttpsUrl } = require("../../src/lib/uri");

// The address check behind `backchannel_logout_uri`.
//
// That URL is the only one on a registered client that the issuer requests
// itself, which makes it the only one where what a client registers decides
// what the server connects to. Everything else parseHttpsUrl validates — a
// logo, a terms page, an external provider's start URL — is loaded or opened by
// the user's browser, on the user's own networks, so the check is opt-in rather
// than the default.
//
// The delivery is POST-only with `redirect: "manual"`, a signed JWT for a body,
// and a response that is never read. What leaks is the status code, and it is
// written back to `lastError` for an operator to read: enough to tell an open
// port from a closed one, from inside the network, with a results page.

test("addresses on the machine's own networks are recognised", () => {
  for (const host of [
    "127.0.0.1",
    "127.1.2.3",
    "0.0.0.0",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.1.1",
    "100.64.0.1",
    // Where a cloud instance's credentials answer.
    "169.254.169.254",
    "localhost",
    "anything.localhost",
    "::1",
    "[::1]",
    "fd00::1",
    "fc00::1",
    "fe80::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1"
  ]) {
    assert.equal(isPrivateNetworkHost(host), true, `${host} should be private`);
  }
});

test("ordinary public addresses and names are not", () => {
  for (const host of [
    "rp.example",
    "example.com",
    "8.8.8.8",
    "1.1.1.1",
    // Adjacent to a private range on either side, which is where an off-by-one
    // in the masks would show.
    "9.255.255.255",
    "11.0.0.0",
    "172.15.255.255",
    "172.32.0.0",
    "192.167.255.255",
    "192.169.0.0",
    "169.253.255.255",
    "169.255.0.0",
    "100.63.255.255",
    "100.128.0.0",
    "2001:4860:4860::8888",
    // A name that merely contains one, rather than being one.
    "localhost.evil.example",
    "127.0.0.1.evil.example"
  ]) {
    assert.equal(isPrivateNetworkHost(host), false, `${host} should not be private`);
  }
});

test("a backchannel URL is refused for a private address and accepted for a public one", () => {
  const backchannel = (value) =>
    parseHttpsUrl(value, "backchannel_logout_uri", { blockPrivateNetwork: true });

  assert.equal(backchannel("https://rp.example/backchannel-logout"), "https://rp.example/backchannel-logout");

  for (const value of [
    // The loopback carve-out in parseHttpsUrl used to accept this even in
    // production with allowInsecureHttp off, which is the whole finding.
    "http://127.0.0.1:9200/_cluster/settings",
    "https://169.254.169.254/latest/meta-data/",
    "https://10.0.0.5/internal",
    "https://[::1]/logout",
    "https://localhost/logout"
  ]) {
    assert.throws(() => backchannel(value), /must not point at a loopback, link-local, or private address/, value);
  }
});

test("the check is opt-in, so the URLs a browser fetches are unaffected", () => {
  // A logo on loopback is a developer's own machine rendering their own image.
  // Refusing it here would break local development for no gain: the request is
  // made by the browser, not by this process.
  assert.equal(
    parseHttpsUrl("http://127.0.0.1:8080/logo.png", "logo_uri"),
    "http://127.0.0.1:8080/logo.png"
  );
});

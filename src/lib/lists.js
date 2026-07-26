"use strict";

// SQLite has no array column, so scalar lists are stored as delimited TEXT. The
// delimiters are chosen so that no legal member can contain one:
//   * scope tokens cannot contain a space (RFC 6749 section 3.3)
//   * URIs cannot contain a raw newline (RFC 3986 section 2)
// This module is the only place that encodes or decodes those columns, so the
// invariant is checked in exactly one spot.

function assertNoDelimiter(value, delimiter, name) {
  if (value.includes(delimiter)) {
    throw new Error(`${name} must not contain the list delimiter`);
  }
}

/** "openid profile" -> ["openid", "profile"] */
function decodeScopes(value) {
  return String(value || "")
    .split(" ")
    .map((scope) => scope.trim())
    .filter(Boolean);
}

/** ["openid", "profile"] -> "openid profile" */
function encodeScopes(scopes) {
  const list = [...new Set((scopes || []).map((scope) => String(scope || "").trim()).filter(Boolean))];
  for (const scope of list) assertNoDelimiter(scope, " ", "scope");
  return list.join(" ");
}

/** "a\nb" -> ["a", "b"] */
function decodeUris(value) {
  return String(value || "")
    .split("\n")
    .map((uri) => uri.trim())
    .filter(Boolean);
}

/** ["a", "b"] -> "a\nb" */
function encodeUris(uris) {
  const list = [...new Set((uris || []).map((uri) => String(uri || "").trim()).filter(Boolean))];
  for (const uri of list) assertNoDelimiter(uri, "\n", "URI");
  return list.join("\n");
}

/**
 * Parses a TEXT column holding JSON. A malformed or absent value yields the
 * fallback rather than throwing, because a damaged metadata blob must never take
 * down a protocol endpoint.
 */
function decodeJson(value, fallback = null) {
  if (value === null || value === undefined || value === "") return fallback;
  try {
    const parsed = JSON.parse(String(value));
    return parsed === null ? fallback : parsed;
  } catch {
    return fallback;
  }
}

function encodeJson(value) {
  if (value === null || value === undefined) return null;
  return JSON.stringify(value);
}

module.exports = {
  decodeJson,
  decodeScopes,
  decodeUris,
  encodeJson,
  encodeScopes,
  encodeUris
};

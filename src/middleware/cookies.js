"use strict";

// Cookie parsing.
//
// Express does not parse cookies itself, and this server needs exactly two of
// them: the session identifier and the CSRF token. Both are opaque tokens
// this server minted, so there is nothing to sign, decrypt, or JSON-decode —
// a dependency would buy features none of the code below wants.
//
// The parser is deliberately strict about size. A request carrying megabytes of
// cookies is not a browser, and parsing it before rejecting it is work an
// attacker gets for free.

const MAX_HEADER_LENGTH = 8192;

/** Parses a `Cookie` header into a plain object. Later duplicates lose. */
function parseCookieHeader(header) {
  const jar = Object.create(null);
  const raw = String(header || "");
  if (!raw || raw.length > MAX_HEADER_LENGTH) return jar;

  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    if (!name || name in jar) continue;
    let value = part.slice(index + 1).trim();
    // A quoted-string value is legal (RFC 6265 section 4.1.1).
    if (value.length > 1 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    try {
      jar[name] = decodeURIComponent(value);
    } catch {
      // A value that is not valid percent-encoding is taken literally rather
      // than dropped: it will simply fail to match anything this server issued.
      jar[name] = value;
    }
  }
  return jar;
}

function cookieMiddleware(req, res, next) {
  req.cookies = parseCookieHeader(req.headers?.cookie);
  next();
}

module.exports = { cookieMiddleware, parseCookieHeader };

# Knight Authentication Handoff Contract

This document is the normative integration contract between the independent
Knight OAuth service and `knight-app`. It covers only upstream authentication
handoff. It does not grant credit access, issue OAuth tokens from `knight-app`,
or permit either service to read the other's database.

The two services share one high-entropy HMAC secret through their production
secret stores. Never put that value, a handoff ticket, OAuth state, a session
cookie, or a callback query string in Git, chat, logs, screenshots, or release
receipts.

## Ownership

| Component | Owns | Must not own |
| --- | --- | --- |
| Knight OAuth | OAuth browser session, `state`, safe post-login path, callback validation, replay ledger, local account link, OAuth authorization and tokens | Knight credentials or `knight-app` sessions |
| `knight-app` | Existing Knight login, upstream user lookup, ticket signing, exact callback/client allowlists | OAuth session, OAuth grants, authorization codes, access tokens, or refresh tokens |

## Browser flow

1. OAuth begins the handoff at `GET /login/external/:provider`.
2. OAuth creates a cryptographically random `state`. It stores that value and a
   safe local post-login path in its server-side session.
3. OAuth redirects the browser to the configured Knight `startUrl` with these
   exact query parameters:

   | Parameter | Value |
   | --- | --- |
   | `state` | `<opaque-state-from-oauth>` |
   | `return_to` | The exact OAuth callback URL for this provider |
   | `client` | The exact configured OAuth issuer |

4. `knight-app` validates `return_to` and `client` against exact HTTPS
   allowlists, then authenticates the existing Knight user. A signed-out user
   signs in on Knight and resumes the same handoff.
5. `knight-app` signs one short-lived compact JWT with HS256.
6. The browser returns to the validated `return_to` URL with exactly these
   handoff values:

   | Parameter | Value |
   | --- | --- |
   | `ticket` | `<signed-ticket>` |
   | `state` | The unchanged `<opaque-state-from-oauth>` value |

7. OAuth compares the callback `state` with its server-side session, consumes
   that state before account resolution, verifies and consumes the ticket, then
   creates a fresh authenticated OAuth session. The original safe local path is
   the only permitted post-login destination.

The OAuth callback path is
`/login/external/<provider>/callback`. Provider names and configured URLs are
case-sensitive contract values; neither side may infer or rewrite them.

## Ticket claims

The JOSE header must declare `alg` as `HS256`. OAuth fixes verification to
HS256 and rejects `none`, any other algorithm, and algorithm selection driven
by an untrusted header.

### Required claims

| Claim | Contract |
| --- | --- |
| `iss` | Exact configured provider name |
| `aud` | Exact OAuth issuer string, or an array containing that exact string |
| `sub` | Stable, opaque Knight user identifier; never an email address |
| `iat` | JWT NumericDate for ticket issuance |
| `exp` | JWT NumericDate for ticket expiry |
| `jti` | Unique, high-entropy ticket identifier |
| `state` | Exact state received from OAuth for this browser flow |

### Optional claims

| Claim | Contract |
| --- | --- |
| `username` | Current Knight username; treated as non-unique profile data, never as an account-linking key |
| `email` | Current Knight email address, when release is intended |
| `email_verified` | Boolean `true` only when Knight has actually verified `email` |
| `name` | Current display name |
| `picture` | Current avatar URL |
| `attributes` | JSON object containing explicitly approved deployment attributes |

Do not place passwords, session identifiers, access tokens, refresh tokens,
authorization codes, secrets, roles, or unrestricted database records in a
ticket. The `sub` claim is the account-linking authority. Matching email never
causes an automatic account merge.

## Time and replay rules

- The default ticket lifetime is 60 seconds. The configured lifetime must be
  between 15 and 600 seconds.
- `exp - iat` must not exceed the configured ticket lifetime.
- OAuth allows at most 60 seconds of future clock skew for `iat`.
- A ticket is single-use. OAuth stores `(provider, jti)` under a unique database
  constraint, so sequential and concurrent replay attempts are rejected.
- OAuth links accounts by unique `(provider, subject)`, not by email.
- Keep both hosts synchronized to a trusted time source.

## Redirect validation and failure behavior

`knight-app` must compare both `return_to` and `client` with exact, configured,
HTTPS allowlist entries. Prefix matching, suffix matching, wildcards, derived
subdomains, user-supplied fallbacks, and arbitrary redirects are forbidden.

If authentication or ticket creation fails, remain on Knight or show a fixed
safe Knight error page. Never redirect to an unvalidated callback. OAuth must
reject missing or wrong state, malformed or oversized tickets, bad signatures,
wrong issuer or audience, invalid ticket times, replay, unknown providers,
email collisions, and disabled accounts without creating an authenticated
session.

Logs and error reports may include only safe metadata such as timestamp,
provider name, outcome class, and a server-generated correlation identifier.
They must not include a ticket, state value, callback query, session cookie,
shared secret, or identity payload.

## Shared-secret lifecycle

The current OAuth implementation accepts one shared secret per provider and has
no dual-key overlap. Rotation therefore requires a coordinated maintenance
window:

1. Stop new handoff starts and allow the configured ticket lifetime plus clock
   skew to elapse.
2. Update both services through their secret stores without printing the value.
3. Restart or reload both services as required.
4. Run the sanitized acceptance matrix below before reopening handoffs.

Do not rotate one side independently and do not preserve the old value in Git,
receipts, shell history, or temporary files.

## Production acceptance matrix

All rows are release gates. Evidence records only case identifier, UTC time,
status/outcome class, release identifier, and pass/fail. It never records a
ticket, state, cookie, secret, token, code, nonce, or PKCE verifier.

| Case | Required result |
| --- | --- |
| Existing linked user | Knight authentication resumes and OAuth signs in the expected linked account |
| Signed-out user | Knight login completes, the original handoff resumes, and OAuth signs in |
| Wrong or missing state | OAuth rejects the callback and creates no authenticated session |
| Missing required claim | OAuth rejects the ticket |
| Tampered signature or wrong algorithm | OAuth rejects the ticket |
| Wrong issuer or audience | OAuth rejects the ticket |
| Expired, overlong, or future-dated ticket | OAuth rejects the ticket |
| Sequential replay | Second use is rejected |
| Concurrent replay | Exactly one request may consume the ticket |
| Callback/client allowlist attack | Knight does not redirect or sign a ticket for the supplied destination |
| Email collision | OAuth refuses automatic merge and requires an explicit authenticated link |
| Disabled account | OAuth refuses sign-in |
| Log inspection | No sensitive handoff or OAuth values appear in either service's logs |

Production enablement requires the complete matrix against the deployed release
and a verified rollback path. Local unit tests or a successful login alone are
not production acceptance.

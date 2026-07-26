# Security policy

## Reporting a vulnerability

Report privately through **GitHub Security Advisories** on this repository
(*Security → Report a vulnerability*), not through a public issue. A public issue
for an authentication bug tells everyone running the software about it before
there is a fix.

Please include what you need to reproduce it: the request, the configuration that
matters, and what you expected instead. **Do not include real tokens, cookies,
`state`, `nonce`, PKCE verifiers, client secrets, or private keys** — a
description or a redacted value is enough, and a live credential in a report is
one more place it exists.

## What is in scope

Anything that lets a party obtain or use an authorization it was not granted:

- issuing a token for a scope, client, or account that did not authorize it
- accepting a token, code, or assertion that should have been refused
- bypassing PKCE, redirect URI matching, client authentication, or consent
- cross-site request forgery on a state-changing endpoint
- reading another account's data through any surface
- escalating from a user account to an administrator one
- a private key, client secret, or password hash reaching a response, a log, or
  the audit trail

## What is not

- A finding that depends on `OAUTH_ALLOW_INSECURE_HTTP=true`, on
  `TRUST_PROXY=true` with no proxy in front, or on a signing key you published
  yourself. These are documented as things not to do.
- Missing rate limits on an endpoint that has no credential to guess.
- Anything requiring an administrator account you were legitimately given — an
  administrator can already manage clients and accounts by design.

## Deploying safely

The two that matter most, both covered in the README:

1. **Serve over HTTPS.** OAuth over plaintext exposes tokens in transit.
2. **Hold your own signing key** (`OAUTH_SIGNING_KEYS_JSON`, with
   `OAUTH_ALLOW_GENERATED_KEYS=false`) if you run more than one replica.

## Supported versions

The latest release on the default branch. There is no long-term support branch.

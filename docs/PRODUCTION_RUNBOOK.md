# Knight OAuth Production Runbook

This is the release procedure for a lightweight, single-instance deployment at
`https://oauth.knightx.asia`. It is intentionally separate from Credit, Core,
Main, and Canvas. Do not change those services while following this runbook.

The service implements the authorization-code and refresh-token grants. It does
not implement the client-credentials grant.

## Recommended initial topology: single-instance SQLite

The recommended initial Knight production topology is the repository's
`compose.yml`: exactly one Node application container and one local persistent
Docker volume containing SQLite. This is the lowest-resource supported option
and needs no PostgreSQL sidecar, Redis, queue, or worker.

Its operating limits are part of the design, not optional tuning:

- Run exactly one application instance. SQLite is not the horizontal-scaling
  topology for this service.
- Keep the volume on local storage. SQLite relies on local filesystem locking;
  do not use a shared or network filesystem for the database file.
- There is no application high availability or shared-write capability. Plan a
  maintenance window and accept that a host outage makes OAuth unavailable.
- Keep protected, consistent backups and complete an isolated restore drill
  before a schema-changing release.
- Inject the signing key from an operator-controlled secret source and apply
  the production overrides below. The repository's zero-config defaults are
  only for loopback evaluation.

Unless a section explicitly says otherwise, every image build, migration,
Compose, deployment, and rollback command in this runbook is for this
single-instance SQLite topology.

## PostgreSQL alternative

PostgreSQL is the scale and operational-resilience alternative, not Knight's
lightweight initial default. A PostgreSQL release needs all of the following:

- `compose.postgres.yml`, with an image built specifically for
  `DATABASE_PROVIDER=postgresql`; do not reuse a SQLite-targeted image.
- A manual `migrate deploy` step owned by one release process before the
  application starts. Do not let multiple replicas race migrations.
- Database-native protected backups, a tested restore procedure, and a rollback
  plan that accounts for migration compatibility as well as the application
  image.
- Additional CPU, memory, storage, monitoring, and maintenance budget for the
  PostgreSQL service.

The exact SQLite commands below do not apply to PostgreSQL. Follow the
`compose.postgres.yml` workflow in the README and produce equivalent sanitized
readiness, protocol, backup, and rollback evidence.

## Non-negotiable boundaries

- Run one Knight OAuth application instance. The shipped SQLite deployment is
  the lowest-resource supported topology: one Node process, one named volume,
  no Redis, queue, worker, or database sidecar.
- Bind Node to `127.0.0.1:3010`; expose only the TLS reverse proxy.
- Keep the issuer exactly `https://oauth.knightx.asia`.
- Use `NODE_ENV=production`, `OAUTH_ALLOW_INSECURE_HTTP=false`, and an exact
  `TRUST_PROXY` hop count matching the deployed proxy chain.
- Inject signing keys and credentials from an operator-controlled, root-readable
  secret source. Never put them in Git, commands, terminal output, receipts, or
  chat. Do not use `docker compose config`, an unscoped `docker inspect`, `env`,
  or `printenv` as evidence because they can disclose environment values. A
  narrowly formatted image-ID lookup is safe and is used below.
- Never expose an empty database while both `OAUTH_REGISTRATION_ENABLED=true`
  and `OAUTH_FIRST_USER_IS_ADMIN=true`. Keep the public route restricted to the
  operator until the intended administrator has been created and verified.
- Edge and origin access logs must omit URL query strings and request bodies.
  Authorization and handoff callback queries contain short-lived security
  values that must not enter Cloudflare, proxy, or application log storage.
- Do not scale above one application replica while using the in-process rate
  limiter or instance-local key cache.
- Never use `docker compose down -v` during deploy or rollback. It deletes the
  SQLite database and stored signing material.

## Expected cache boundary

| Endpoint class | Cache policy | Browser cookie allowed |
| --- | --- | --- |
| Discovery and JWKS | `public, max-age=300` | No |
| `/healthz` | `no-store` | No |
| Authorization, login, consent, account, admin | `no-store`, `Vary: Cookie` | Yes |
| Token, UserInfo, introspection, revocation, registration | `no-store` | No CSRF cookie |

Cloudflare may cache only Discovery and JWKS. It must bypass cache for every
other OAuth, account, admin, and health endpoint.

## 1. Prepare the SQLite candidate

Start from a clean checkout. These commands emit only a commit identifier and
test results; they do not read runtime credentials.

```bash
git status --short
RELEASE_ID="$(git rev-parse --verify HEAD)"
npm ci
npm run db:schema:check
npm test
docker build --build-arg DATABASE_PROVIDER=sqlite \
  --tag "knight-oauth:${RELEASE_ID}" .
docker image inspect "knight-oauth:${RELEASE_ID}" \
  --format 'image_id={{.Id}} created={{.Created}}'
```

Do not proceed if the worktree has unexplained changes, schema validation
fails, tests fail, or the image build fails. Store only the commit identifier,
image ID, timestamps, and pass/fail counts in the release receipt.

Before changing the running container, capture the immutable image ID actually
used by that container. Do not derive rollback from a mutable local tag:

```bash
RUNNING_CONTAINER_ID="$(docker compose ps -q knight-oauth)"
if [ -n "$RUNNING_CONTAINER_ID" ]; then
  ROLLBACK_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$RUNNING_CONTAINER_ID")"
  test -n "$ROLLBACK_IMAGE_ID"
  printf 'rollback_image_id=%s\n' "$ROLLBACK_IMAGE_ID"
else
  ROLLBACK_IMAGE_ID=""
  printf 'rollback_image_id=none first_deployment=true\n'
fi
```

Keep these variables in the same protected operator shell through deployment.
Do not stop the current application yet: TLS, proxy, and Cloudflare checks in
the next two sections must run while the known-good release is still available.

## 2. Validate origin TLS and SNI

Cloudflare `525` means Cloudflare could not complete TLS with the origin. Fix
that before deploying the application. The origin must present a currently
valid certificate for `oauth.knightx.asia` when that hostname is sent as SNI.

Run these from a trusted operator host. `ORIGIN_IP` is an operator-local shell
variable, not evidence to commit.

```bash
validate_origin_preflight() {
  if ! openssl s_client \
    -connect "${ORIGIN_IP}:443" \
    -servername oauth.knightx.asia \
    -verify_hostname oauth.knightx.asia \
    -verify_return_error </dev/null; then
    printf 'origin_tls_check=failed\n' >&2
    return 1
  fi

  ORIGIN_HEALTH_STATUS="$(curl --silent --show-error \
    --resolve "oauth.knightx.asia:443:${ORIGIN_IP}" \
    --output /dev/null \
    --write-out '%{http_code}' \
    https://oauth.knightx.asia/healthz || true)"
  printf 'origin_health_status=%s\n' "$ORIGIN_HEALTH_STATUS"

  if [ -n "${ROLLBACK_IMAGE_ID:-}" ]; then
    test "$ORIGIN_HEALTH_STATUS" = 200
  else
    printf 'origin_health_gate=pending first_deployment=true\n'
  fi
}

validate_origin_preflight
```

Required result: certificate verification succeeds and its SAN covers the exact
hostname. On an upgrade, origin health must also return `200` from the still
running known-good release. On a first deployment with no previous application,
record that health is pending rather than treating the expected proxy `502` or
`503` as success; it must become `200` after section 4. Confirm the reverse proxy
forwards to `127.0.0.1:3010`, preserves the original host, and does not rewrite
OAuth paths.
When the origin uses Cloudflare Origin CA rather than a publicly trusted CA,
pass its operator-controlled CA bundle to `openssl` and `curl`; do not disable
certificate or hostname verification.

Set Cloudflare SSL/TLS mode to **Full (strict)**. Do not use Flexible mode and do
not disable origin certificate validation to hide a `525`.

Configure the origin proxy to log the URL path without its query string, and
configure Cloudflare Logpush, WAF event export, or equivalent edge logs to omit
query-bearing URI fields. Do not log request bodies or authorization headers.
Validate this with a synthetic, non-secret query marker on `/healthz`; inspect
edge and origin logs and retain only a pass/fail result proving that the marker
was absent. Never use a real ticket, state, code, nonce, or verifier for this
check.

## 3. Configure Cloudflare for protocol traffic

OAuth libraries cannot solve an interstitial challenge. Add a narrowly scoped
WAF/Bot rule for host `oauth.knightx.asia` that skips interactive challenge
actions on these machine endpoints:

- `/.well-known/openid-configuration`
- `/.well-known/oauth-authorization-server`
- `/.well-known/jwks.json`
- `/oauth2/jwks`
- `/oauth2/token`
- `/oauth2/userinfo`
- `/oauth2/introspect`
- `/oauth2/revoke`
- `/oauth2/register` and `/oauth2/register/*`
- `/healthz`

Keep Cloudflare network-level DDoS protection enabled. Keep application client
authentication, bearer-token validation, registration-token validation, and
the repository's rate limits enabled. This rule bypasses only browser
challenges; it does not make an endpoint anonymous.

For a fresh database, add a temporary default-deny or operator-IP allowlist for
the entire `oauth.knightx.asia` host before starting the candidate. The trusted
operator must still be able to run the TLS and protocol checks in this runbook,
but general public traffic must remain blocked until the administrator bootstrap
and all acceptance gates have passed.

Allow the four Discovery/JWKS paths to follow their origin `Cache-Control`
header for at most five minutes. Add a higher-priority bypass-cache rule for
`/healthz`, `/oauth2/authorize*`, `/oauth2/consent*`, all token-adjacent
endpoints, and all login, account, and admin paths.

On an upgrade, require `200` from Discovery, JWKS, and health from outside the
origin network before changing the application. On a first deployment, validate
the Cloudflare rules while the operator-only hold is active and defer the `200`
application checks until section 5. A `403` HTML challenge, `525`, redirect to
another host, or HTML body on a JSON endpoint blocks public opening.

## 4. Deploy the SQLite single instance

Provision production configuration out of band. Confirm required variable names
are present without printing values. Production must override the
development-friendly Compose defaults for insecure HTTP and generated keys.

If a previous SQLite instance is running, stop only that application now and
take a consistent protected snapshot of its volume. Store it outside the
repository with owner-only permissions and prove it can be restored in an
isolated location. Do not inspect or attach snapshot contents to evidence. The
TLS and Cloudflare preflight has already completed, so this stop begins the
bounded application deployment window rather than an open-ended preflight.

Tag the tested SQLite image for the repository-native `compose.yml` file and
recreate only the OAuth application:

```bash
if [ -n "${ROLLBACK_IMAGE_ID:-}" ]; then
  docker image tag "$ROLLBACK_IMAGE_ID" knight-oauth:rollback
fi
docker image tag "knight-oauth:${RELEASE_ID}" knight-oauth:local
docker compose up --detach --no-build --force-recreate knight-oauth
```

Do not start a second application replica during handover. The SQLite entrypoint
applies pending migrations before Node starts. A migration failure blocks the
rollout; never force the server to start against an unverified schema.

On a fresh database, keep the edge operator-only while bootstrapping. If local
registration is used to create the administrator, only the intended operator
may reach the real HTTPS registration flow while
`OAUTH_FIRST_USER_IS_ADMIN=true`. Verify that the intended account can reach the
admin surface, then set `OAUTH_FIRST_USER_IS_ADMIN=false`. For a Knight
handoff-only deployment, also set `OAUTH_REGISTRATION_ENABLED=false`. Recreate
the single application container after these changes and repeat readiness; do
not open general public traffic merely because the first login succeeded.

Before any public opening, verify that the database contains exactly one
administrator. This check prints only the count and a fixed failure marker; it
does not print account identity or configuration:

```bash
docker compose exec -T knight-oauth node <<'NODE'
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

(async () => {
  const count = await prisma.user.count({ where: { role: "ADMIN" } });
  console.log(`admin_count=${count}`);
  if (count !== 1) process.exitCode = 1;
})()
  .catch(() => {
    console.error("admin_count_check=failed");
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
NODE
```

Required result: `admin_count=1` and exit status `0`. Retain only the count and
pass/fail in the receipt. Any other count keeps the public hold in place.

## 5. Poll readiness for at most 90 seconds

Poll loopback first. This records only timestamp and status, never a response
body, header value, cookie, or credential.

```bash
deadline=$((SECONDS + 90))
ready=0
while [ "$SECONDS" -lt "$deadline" ]; do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    http://127.0.0.1:3010/healthz || true)"
  printf 'readiness time=%s status=%s\n' "$(date -u +%FT%TZ)" "$status"
  if [ "$status" = 200 ]; then
    ready=1
    break
  fi
  sleep 2
done
test "$ready" -eq 1
```

After loopback readiness passes, repeat the bounded poll against origin TLS
using `--resolve`, then against the public Cloudflare URL. Any failure moves
directly to rollback.

## 6. Run sanitized protocol probes

This probe reports only status, media type, cache policy, and whether a
`Set-Cookie` header exists. It never prints a cookie or follows redirects.

```bash
node <<'NODE'
const base = "https://oauth.knightx.asia";
const checks = [
  "/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server",
  "/.well-known/jwks.json",
  "/oauth2/jwks",
  "/healthz"
];

(async () => {
  let failed = false;
  for (const path of checks) {
    const response = await fetch(base + path, { redirect: "manual" });
    const receipt = {
      path,
      status: response.status,
      contentType: response.headers.get("content-type"),
      cacheControl: response.headers.get("cache-control"),
      hasSetCookie: response.headers.has("set-cookie")
    };
    console.log(JSON.stringify(receipt));
    if (response.status !== 200 || receipt.hasSetCookie) failed = true;
  }
  process.exitCode = failed ? 1 : 0;
})().catch(() => {
  console.error(JSON.stringify({ probe: "failed" }));
  process.exitCode = 1;
});
NODE
```

Then run the repository's unauthenticated compatibility probe:

```bash
node .github/scripts/probe.js https://oauth.knightx.asia
```

The compatibility probe sends no credentials. In addition to Discovery, JWKS,
token, and UserInfo, it exercises unauthenticated requests to introspection,
revocation, dynamic registration, and registration management. Those requests
must return the expected JSON 4xx boundary with `no-store` and no `Set-Cookie`;
an HTML challenge, redirect, cacheable response, or cookie blocks the release.

An authenticated acceptance flow is a mandatory release gate, but run it only
after a designated test client and temporary test account are available through
an approved secret channel. The operator-controlled runner must verify all of
the following without printing credential values:

- authorization-code redirect with exact `state` and issuer validation, plus
  ID-token `nonce` validation when OpenID Connect is requested
- PKCE S256 exchange and an access-token lifetime of one hour
- consent approval followed by UserInfo claims for the granted scopes
- refresh-token rotation, with the replaced refresh token refused on replay
- refresh-token revocation followed by inactive introspection of that refresh
  token
- consent denial returning `access_denied` and no authorization code

Never pass a client secret on the command line and never retain access tokens,
refresh tokens, authorization codes, cookies, `state`, `nonce`, or PKCE
verifiers in a receipt or terminal transcript. Record only case identifiers,
status codes, expected/actual booleans, timestamps, and pass/fail counts. If the
controlled flow cannot be run or any case fails, keep the public hold in place
and roll back the candidate.

For a fresh database, remove the temporary public-traffic hold only after every
gate above passes. Immediately repeat public readiness and both sanitized probes
after opening the route. Any different result moves directly to rollback.

## 7. Roll back SQLite on any failed gate

Rollback is mandatory for readiness failure, non-JSON Discovery/JWKS, a
Cloudflare challenge, TLS failure, unexpected redirect, a public endpoint
setting a cookie, or any authentication-flow regression.

Stop the candidate first, regardless of whether this is an upgrade or a first
deployment:

```bash
docker compose stop knight-oauth
```

If the candidate applied a migration that is not backward compatible with the
rollback image, restore the protected pre-deploy snapshot now, while no
application container is writing to the database. Complete and verify that
restore before continuing. Never start the rollback image against an
incompatible candidate schema.

After the database is compatible with the rollback image, restore the previous
immutable image. A first deployment has no previous image and remains stopped:

```bash
if [ -n "${ROLLBACK_IMAGE_ID:-}" ]; then
  docker image tag "$ROLLBACK_IMAGE_ID" knight-oauth:local
  docker compose up --detach --no-build --force-recreate knight-oauth
else
  printf 'rollback_state=stopped first_deployment=true\n'
fi
```

When a previous image was restored, poll loopback, origin TLS, and public
readiness again with the same 90-second procedure, then re-run the sanitized
probe. Keep the public hold in place when a first deployment is left stopped.

Keep the candidate image, previous image, and snapshot until the acceptance
window closes.

## 8. Release receipt

The receipt may contain only:

- UTC deployment window
- commit/release identifier and image ID
- database provider and replica count
- migration exit status, never database output containing values
- local, origin, and public readiness status codes with timestamps
- TLS verification result and certificate expiry date
- each sanitized probe's path, status, media type, cache policy, and
  `hasSetCookie` boolean
- test suite pass/fail counts
- rollback image ID, snapshot identifier, and rollback drill result
- administrator bootstrap/public-hold result, without account identity
- edge and origin query-log redaction result

The receipt must not contain passwords, private keys, client secrets, access or
refresh tokens, authorization codes, cookies, handoff tickets, registration
access tokens, `state`, `nonce`, PKCE verifiers, request bodies, database rows,
or raw environment/configuration dumps.

# Knight OAuth

[![CI](https://github.com/Knight-ask-art/Knight-Oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/Knight-ask-art/Knight-Oauth/actions/workflows/ci.yml)

A standalone, self-hostable **OAuth 2.0 authorization server and OpenID Connect
provider**. One Node process, one database, no Redis, no queue, no sidecar.

It is built to be driven by **off-the-shelf client libraries**. You point a
library at the discovery document and it configures itself — there is nothing
about this server a relying party has to special-case.

[中文说明见下 / Chinese documentation below](#knight-oauth-中文说明)

```bash
git clone https://github.com/Knight-ask-art/Knight-Oauth.git
cd Knight-Oauth
npm install
npm run setup
npm start
```

That is the whole install. It runs on SQLite, generates a signing key on first
boot, and serves a working issuer at <http://127.0.0.1:3010>. Register an
account — the first one becomes the administrator — and the issuer is ready for
a client.

---

## Contents

- [What it implements](#what-it-implements)
- [Quick start](#quick-start)
- [Connecting a client](#connecting-a-client)
- [Configuration](#configuration)
- [Custom scopes and claims](#custom-scopes-and-claims)
- [External identity providers](#external-identity-providers)
- [Production notes](#production-notes)
- [Docker](#docker)
- [Project layout](#project-layout)
- [Development](#development)
- [Security](#security)
- [License](#license)

---

## What it implements

| Specification | Status |
| --- | --- |
| OAuth 2.0 Authorization Framework (RFC 6749) | Authorization code grant, refresh token grant, client credentials |
| PKCE (RFC 7636) | **S256 only.** Mandatory for public clients, on by default for confidential ones |
| OpenID Connect Core 1.0 | ID tokens, UserInfo, `nonce`, `auth_time`, `max_age`, `prompt`, `login_hint`, `sid` |
| OpenID Connect Discovery 1.0 | `/.well-known/openid-configuration` |
| Authorization Server Metadata (RFC 8414) | `/.well-known/oauth-authorization-server` |
| Token Introspection (RFC 7662) | `/oauth2/introspect` |
| Token Revocation (RFC 7009) | `/oauth2/revoke` |
| Bearer Token Usage (RFC 6750) | `WWW-Authenticate` challenges on 401 |
| Dynamic Client Registration (RFC 7591) | Opt-in, gated by an initial access token |
| Client Management (RFC 7592) | Read, update, and delete your own registration |
| Issuer Identification (RFC 9207) | `iss` in the authorization response |
| Native Apps (RFC 8252) | Private-use URI schemes, loopback redirects with a floating port |
| RP-Initiated Logout 1.0 | `/oauth2/logout` with `id_token_hint` and `post_logout_redirect_uri` |
| Back-Channel Logout 1.0 | Signed logout tokens, retried with backoff |

`plain` PKCE is deliberately **not** implemented: it offers no protection
against an interception attack, so accepting it would only let a client think it
was protected.

### Both discovery paths are served

An OpenID Connect library looks for `/.well-known/openid-configuration`; a plain
OAuth 2.0 library looks for `/.well-known/oauth-authorization-server`. Serving
one and not the other turns a supported configuration into a support ticket, so
both are answered.

### Three client authentication methods

- `client_secret_basic` — HTTP Basic, the RFC 6749 default
- `client_secret_post` — credentials in the form body, which a real share of
  libraries do exclusively
- `none` — public clients, authenticated by PKCE instead

### Signing algorithms

`RS256` (default), `ES256`, `EdDSA`. RS256 is the default because OpenID Connect
Core §15.1 requires every provider to support it, which is what makes an
unconfigured client library work. `HS256` and `none` are rejected.

### What comes with it

- Local accounts: registration, sign-in, password reset, email verification,
  scrypt password hashing
- A consent screen where each scope is a checkbox the user can clear
- A self-service page listing every application with access, and every signed-in
  device, both revocable
- An administrator surface for approving, disabling, and deleting clients, and
  for managing accounts
- An audit log of security-relevant events
- CSRF protection on every browser form, and a Content Security Policy with no
  `unsafe-inline`

### Endpoints

| Path | Purpose |
| --- | --- |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `/oauth2/jwks` | Public signing keys (also at `/.well-known/jwks.json`) |
| `/oauth2/authorize` | Authorization request (GET and POST) |
| `/oauth2/consent` | Consent screen and decision |
| `/oauth2/token` | Code and refresh-token exchange |
| `/oauth2/userinfo` | UserInfo (GET and POST) |
| `/oauth2/introspect` | Token introspection |
| `/oauth2/revoke` | Token revocation |
| `/oauth2/register` | Dynamic registration, and `/{client_id}` for management |
| `/oauth2/logout` | RP-initiated logout |
| `/healthz` | Liveness |

---

## Quick start

Requires **Node 22 or newer**.

```bash
npm install
npm run setup     # renders the schema, generates the client, applies migrations
npm start
```

Open <http://127.0.0.1:3010>, register, and you have an issuer. No `.env` is
needed to get this far; `npm run setup -- --env` writes one from the example if
you want somewhere to start editing.

Check the discovery document:

```bash
curl http://127.0.0.1:3010/.well-known/openid-configuration
```

### Registering a client

Two ways, and they produce the same kind of client:

1. **Through the UI.** Sign in, go to *Applications*, and submit one. With
   `OAUTH_CLIENT_REQUIRE_APPROVAL=true` (the default) an administrator approves
   it first. The client secret is displayed exactly once.
2. **Dynamically (RFC 7591).** Set `OAUTH_DYNAMIC_REGISTRATION_ENABLED=true` and
   an `OAUTH_REGISTRATION_ACCESS_TOKEN`, then:

```bash
curl -X POST http://127.0.0.1:3010/oauth2/register \
  -H "Authorization: Bearer $OAUTH_REGISTRATION_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://app.example.com/auth/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email offline_access"
  }'
```

The response carries `client_id`, `client_secret`, and a
`registration_access_token` for reading and updating the registration later.
That is the only time either secret is returned.

---

## Connecting a client

Anything that speaks OpenID Connect works. Give it the issuer and it discovers
the rest.

### Node — `openid-client`

```js
import * as client from "openid-client";

const config = await client.discovery(
  new URL("https://oauth.example.com"),
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET
);
```

### Python — `authlib`

```python
oauth.register(
    name="knight",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url="https://oauth.example.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
)
```

### Next.js — Auth.js / NextAuth

```js
providers: [
  {
    id: "knight",
    name: "Knight OAuth",
    type: "oidc",
    issuer: "https://oauth.example.com",
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    checks: ["pkce", "state"]
  }
]
```

### Spring Security

```yaml
spring:
  security:
    oauth2:
      client:
        provider:
          knight:
            issuer-uri: https://oauth.example.com
        registration:
          knight:
            client-id: ${CLIENT_ID}
            client-secret: ${CLIENT_SECRET}
            scope: openid,profile,email
```

### By hand

```
GET /oauth2/authorize
  ?client_id=...
  &redirect_uri=https://app.example.com/auth/callback
  &response_type=code
  &scope=openid%20profile%20email%20offline_access
  &state=<random>
  &nonce=<random>
  &code_challenge=<base64url(sha256(verifier))>
  &code_challenge_method=S256
```

```bash
curl -X POST https://oauth.example.com/oauth2/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=authorization_code \
  -d code=... \
  -d redirect_uri=https://app.example.com/auth/callback \
  -d code_verifier=...
```

Redirect URIs are matched **exactly**, per RFC 6749 §3.1.2.3 — no prefix
matching, no wildcards. The two exceptions are the ones RFC 8252 requires for
native apps: a private-use scheme (`com.example.app:/callback`) and a loopback
redirect, where the port may differ from the registered one because the app
cannot reserve a port in advance.

---

## Configuration

Every setting is optional. See [`.env.example`](.env.example) for the annotated
list; these are the ones that matter most.

| Variable | Default | Notes |
| --- | --- | --- |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:3010` | Where clients and browsers reach this service |
| `OAUTH_ISSUER` | `PUBLIC_BASE_URL` | The `iss` value. Changing it on a live deployment invalidates every issued token |
| `DATABASE_PROVIDER` | `sqlite` | Or `postgresql` |
| `DATABASE_URL` | `file:./data/knight-oauth.db` | Required for `postgresql` |
| `OAUTH_SIGNING_ALGORITHM` | `RS256` | Or `ES256`, `EdDSA` |
| `OAUTH_SIGNING_KEYS_JSON` | — | Supply your own key set instead of generating one |
| `OAUTH_ALLOW_GENERATED_KEYS` | `true` | Set false when you supply the keys |
| `OAUTH_REQUIRE_PKCE` | `true` | Governs confidential clients; public clients always require it |
| `OAUTH_ROTATE_REFRESH_TOKENS` | `true` | Reusing a rotated token revokes the whole family |
| `OAUTH_REGISTRATION_ENABLED` | `true` | Local account sign-up |
| `OAUTH_FIRST_USER_IS_ADMIN` | `true` | So a fresh install has an administrator without seeding |
| `OAUTH_CLIENT_REQUIRE_APPROVAL` | `true` | UI-submitted clients wait for an administrator |
| `OAUTH_DYNAMIC_REGISTRATION_ENABLED` | `false` | An open registration endpoint should be a decision |
| `TRUST_PROXY` | `false` | Only enable behind a proxy you control |

The server refuses to start rather than run in a state that looks secure and is
not: a plaintext issuer in production, dynamic registration in production with
no initial access token, email verification required with no SMTP, a custom
scope that shadows a standard one or forges `sub`, `HS256`, or a database
provider it does not support.

### Switching to PostgreSQL

```bash
DATABASE_PROVIDER=postgresql
DATABASE_URL=postgresql://knight_oauth:secret@127.0.0.1:5432/knight_oauth
```

```bash
npm run db:schema     # render prisma/postgresql/schema.prisma
npm run db:generate
npm run db:migrate
```

Prisma cannot take `datasource provider` from an environment variable, so one
schema per provider is generated from `prisma/schema.template.prisma`. That is
why the schemas are committed and why there is a `db:schema:check`.

---

## Custom scopes and claims

The core implements only the standard OIDC scopes and the standard claims from
OIDC Core §5.4. That is what makes a stock client library work here without
knowing anything about your deployment.

Anything of your own — a resource scope for your API, an internal user id — is
configuration:

```jsonc
OAUTH_CUSTOM_SCOPES=[
  {
    "name": "billing.read",
    "description": "Read your invoices",   // shown on the consent screen
    "claims": ["tenant_id"]                // released from the account's attributes
  },
  { "name": "billing.admin", "description": "Administer billing", "adminOnly": true }
]
```

Write the description the way the user reads it — *"Read your invoices"*, not
`billing.read`. A custom scope may not shadow a standard scope and may not
declare a reserved claim (`sub`, `iss`, `aud`, `exp`, …), so it can never forge
an identity; the server refuses to start if one tries.

---

## External identity providers

If you already have a site with a login screen and a user table, you do not have
to copy a password database here. Configure a **handoff** provider and this
server delegates authentication:

```jsonc
OAUTH_EXTERNAL_IDENTITY_PROVIDERS=[{
  "name": "main-site",
  "kind": "handoff",
  "displayName": "Main Site",
  "startUrl": "https://www.example.com/oauth2/handoff/start",
  "sharedSecret": "at-least-32-characters-of-random-secret",
  "autoCreateUsers": true,
  "ticketTtlSeconds": 60
}]
```

This server sends the user to `startUrl`, the upstream authenticates them
however it likes, and returns a short-lived ticket signed with `sharedSecret`.
The secret is mandatory and must be at least 32 characters: an unsigned ticket
would mean trusting whatever identity an anonymous caller claimed.

Local accounts and external providers coexist — configuring one does not turn
off the other.

---

## Production notes

- **Use HTTPS.** The server refuses a plaintext issuer in production unless you
  explicitly set `OAUTH_ALLOW_INSECURE_HTTP=true`, which you should not.
- **Hold your own signing key** if you run more than one replica. Generate it
  with `npm run keys:generate`, put it in `OAUTH_SIGNING_KEYS_JSON`, and set
  `OAUTH_ALLOW_GENERATED_KEYS=false`. Otherwise each replica generates its own
  and tokens signed by one are rejected by the next.
- **`TRUST_PROXY=true` only behind a proxy you control.** It makes the app trust
  `X-Forwarded-*`, and a directly exposed process would let a caller spoof its
  own address past the rate limiter and into the audit log.
- **Never change `OAUTH_ISSUER` on a live deployment.** Clients compare `iss`
  byte for byte; changing it invalidates every token already issued.
- **Back up the database.** It holds the accounts, the grants, and — unless you
  supplied one — the signing key.
- **Access tokens are self-contained JWTs and cannot be withdrawn early.**
  Revoking one, or a refresh-token replay that revokes its whole family, ends the
  grant — but an access token already issued stays verifiable until it expires,
  so introspection keeps reporting `active: true` for it. What bounds that window
  is `OAUTH_ACCESS_TOKEN_TTL` (one hour by default); shorten it if your threat
  model needs revocation to bite sooner, at the cost of more refresh traffic.

---

## Docker

```bash
docker compose up --build -d
```

No `.env` is required. The container applies pending SQLite migrations on start,
generates a signing key on first boot, and serves a working issuer on
`http://127.0.0.1:3010`. The SQLite file — and the signing key stored in it —
lives on a named Docker volume, so tokens survive a rebuild. `docker compose down`
keeps it; `docker compose down -v` deletes it, and every token issued so far stops
verifying. To keep the database at a path you can see, follow the comment on the
`volumes:` entry in `compose.yml` — a bind mount needs its directory to exist and
be owned by uid 1000 first, because the container does not run as root.

The image runs as a non-root user with a read-only root filesystem, all
capabilities dropped, and `no-new-privileges`. The compose file binds to
`127.0.0.1` on purpose: put a TLS-terminating reverse proxy in front of it rather
than exposing the process.

Two settings in `compose.yml` are what make that zero-config boot work, and both
have to change for a real deployment. `NODE_ENV=production` normally refuses a
plaintext `http` issuer and refuses to generate a signing key; `compose.yml` sets
`OAUTH_ALLOW_INSECURE_HTTP=true` and `OAUTH_ALLOW_GENERATED_KEYS=true` to override
that for a loopback-only container. Once the service has a domain, serve HTTPS and
set `PUBLIC_BASE_URL` to the `https` address, supply a key through
`OAUTH_SIGNING_KEYS_JSON` from a secret manager, and set both back to `false`.

For PostgreSQL, uncomment the marked lines in `compose.yml`, set
`POSTGRES_PASSWORD`, rebuild with `--build-arg DATABASE_PROVIDER=postgresql`, and
run the migration once by hand before starting the service:

```bash
docker compose build --build-arg DATABASE_PROVIDER=postgresql
docker compose run --rm knight-oauth node scripts/prisma.js migrate deploy
docker compose up -d
```

Migrations are not applied automatically for PostgreSQL: several replicas racing
to migrate the same database is a real way to corrupt one. Override either way
with `OAUTH_MIGRATE_ON_START=true|false`.

---

## Project layout

```text
src/
  app.js              composition root — every service is built here
  server.js           process entry point
  config/env.js       configuration: parsed, validated, refuses bad values
  lib/                jwt, scopes, crypto, uri matching — no I/O
  services/           accounts, clients, provider, sessions, keys, mail, audit
  controllers/        HTTP handling, one per surface
  routes/             URL to controller, in the order discovery advertises them
  middleware/         session, CSRF, cookies
  views/              EJS templates for login, consent, account, admin
prisma/
  schema.template.prisma      one data model
  postgresql/ sqlite/         one generated schema and migration set each
scripts/
  setup.js              npm run setup
  build-schema.js       renders the template per provider
  prisma.js             Prisma CLI wrapper that knows the provider
  docker-entrypoint.js  container entry: migrate, then boot
  generate-keys.js      npm run keys:generate
tests/
  unit/                 configuration and pure logic
  integration/          real SQLite database, real HTTP, real templates
```

---

## Development

```bash
npm run dev            # node --watch
npm test               # unit + integration
npm run test:unit
npm run test:integration
npm run db:schema:check
```

The integration suite runs against a real temporary SQLite database rather than a
Prisma double, and drives the app over HTTP with real session cookies and real
CSRF tokens. A double can prove the code called the method the author expected;
it cannot prove that a unique constraint fires, that a scoped `updateMany`
actually makes a single-use token single-use, or that a template renders at all.

CI covers what a single machine does not: the suite on Linux and Windows across
Node 22 and 24, the PostgreSQL migration applied to a real server with the issuer
booted against it, and a `docker compose up` that asserts the signing key survives
the container being destroyed and recreated. `.github/scripts/probe.js` is the
piece that runs against a live server over real HTTP — point it at any running
instance to check it the way a client library would:

```bash
node .github/scripts/probe.js http://127.0.0.1:3010
```

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

Report a vulnerability privately through GitHub's security advisories rather than
a public issue. See [SECURITY.md](SECURITY.md).

If you deploy this: HTTPS, your own signing key for multi-replica deployments,
and `OAUTH_DYNAMIC_REGISTRATION_ENABLED` left off unless you need it and have set
an initial access token.

---

## License

MIT. See [LICENSE](LICENSE).

---
---

# Knight OAuth（中文说明）

一个**独立、可自托管的 OAuth 2.0 授权服务器与 OpenID Connect 提供方**。单个
Node 进程、单个数据库，不需要 Redis、消息队列或任何附加组件。

它的设计目标是**能被现成的第三方客户端库直接驱动**：把库指向发现文档，它自己
就能完成配置——本服务没有任何需要客户端特殊处理的地方。

```bash
git clone https://github.com/Knight-ask-art/Knight-Oauth.git
cd Knight-Oauth
npm install
npm run setup
npm start
```

这就是全部安装步骤。默认使用 SQLite，首次启动自动生成签名密钥，在
<http://127.0.0.1:3010> 提供一个可用的 issuer。注册一个账号（第一个注册的账号
自动成为管理员），然后就可以接入客户端了。

## 实现了哪些规范

| 规范 | 说明 |
| --- | --- |
| OAuth 2.0（RFC 6749） | 授权码模式、刷新令牌、客户端凭据 |
| PKCE（RFC 7636） | **仅支持 S256**。公开客户端强制要求，机密客户端默认开启 |
| OpenID Connect Core 1.0 | ID Token、UserInfo、`nonce`、`auth_time`、`max_age`、`prompt`、`sid` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` |
| 授权服务器元数据（RFC 8414） | `/.well-known/oauth-authorization-server` |
| 令牌内省（RFC 7662）／吊销（RFC 7009） | `/oauth2/introspect`、`/oauth2/revoke` |
| Bearer 令牌（RFC 6750） | 401 时返回 `WWW-Authenticate` 挑战 |
| 动态客户端注册（RFC 7591／7592） | 可选开启，需初始访问令牌 |
| Issuer 标识（RFC 9207） | 授权响应中返回 `iss` |
| 原生应用（RFC 8252） | 私有 URI scheme、环回地址端口浮动 |
| RP 发起的登出 1.0 ／ 后台通道登出 1.0 | `/oauth2/logout`、签名登出令牌 |

**两个发现路径都提供**：OIDC 客户端库找 `/.well-known/openid-configuration`，
纯 OAuth 2.0 客户端库找 `/.well-known/oauth-authorization-server`。只提供一个
会把「本来支持的配置」变成一张支持工单。

**三种客户端认证方式**：`client_secret_basic`、`client_secret_post`、`none`。
第二种在规范里是可选的，但相当一部分客户端库只会用它——不支持它属于兼容性缺
陷，而不是安全措施。

**签名算法**：`RS256`（默认）、`ES256`、`EdDSA`。默认选 RS256 是因为 OIDC Core
§15.1 要求每个 OP 都必须支持它，这才让未经配置的客户端库能直接工作。`HS256`
和 `none` 一律拒绝。

`plain` 模式的 PKCE **故意不实现**：它对拦截攻击没有任何防护作用，接受它只会
让客户端误以为自己受到了保护。

## 自带的功能

- 本地账号体系：注册、登录、密码重置、邮箱验证，密码用 scrypt 哈希
- 授权确认页：每个 scope 都是可取消勾选的复选框，取消即缩小授权范围
- 用户自助页面：列出所有已授权的应用和所有已登录设备，都可以随时撤销
- 管理界面：审批／禁用／删除客户端，管理账号
- 安全事件审计日志
- 所有浏览器表单都有 CSRF 保护，CSP 不含 `unsafe-inline`

## 接入客户端

任何支持 OpenID Connect 的库都可以，把 issuer 给它即可。上文英文部分给出了
`openid-client`（Node）、`authlib`（Python）、Auth.js／NextAuth、Spring
Security 的配置示例，以及手写请求的写法。

重定向 URI 按 RFC 6749 §3.1.2.3 **精确匹配**，不做前缀匹配、不支持通配符。只有
RFC 8252 要求的两种原生应用情形例外：私有 scheme（`com.example.app:/callback`）
和环回地址——后者允许端口与注册时不同，因为应用无法提前占用一个端口。

## 配置

所有配置项都是可选的，完整带注释的清单见 [`.env.example`](.env.example)。最常用
的几项见上文英文部分的表格。

服务器**宁可拒绝启动，也不会运行在「看起来安全但实际不安全」的状态**：生产环境
下的明文 issuer、生产环境下开启动态注册却没有初始访问令牌、要求邮箱验证却没有
配置 SMTP、自定义 scope 覆盖标准 scope 或伪造 `sub`、`HS256`、不支持的数据库
provider——这些都会在启动时直接报错。

### 切换到 PostgreSQL

```bash
DATABASE_PROVIDER=postgresql
DATABASE_URL=postgresql://knight_oauth:secret@127.0.0.1:5432/knight_oauth
npm run db:schema && npm run db:generate && npm run db:migrate
```

Prisma 无法从环境变量读取 `datasource provider`，所以由
`prisma/schema.template.prisma` 为每个数据库各生成一份 schema 并提交进仓库。

## 私有扩展：自定义 scope 与 claim

核心只实现标准 OIDC scope 和 OIDC Core §5.4 的标准 claim。这正是让第三方客户端
库无需了解你的部署细节就能工作的原因。

属于你自己的东西——给你 API 用的资源 scope、内部用户 id——都通过配置声明：

```jsonc
OAUTH_CUSTOM_SCOPES=[
  { "name": "billing.read", "description": "查看你的账单", "claims": ["tenant_id"] },
  { "name": "billing.admin", "description": "管理所有账单", "adminOnly": true }
]
```

`description` 要按用户读到的方式写（「查看你的账单」而不是 `billing.read`）。
自定义 scope 不能覆盖标准 scope，也不能声明保留 claim（`sub`、`iss`、`aud`、
`exp` 等），因此它永远无法伪造身份；一旦尝试，服务器拒绝启动。

## 复用已有站点的登录体系

如果你已经有一个带登录页和用户表的站点，不需要把密码库复制过来。配置一个
**handoff** 外部身份源，本服务会把认证委托出去：本服务把用户重定向到
`startUrl`，上游用它自己的方式完成认证，再返回一张用 `sharedSecret` 签名的短
时效票据。共享密钥是必需的，且至少 32 个字符——未签名的票据意味着相信任何匿名
调用方声称的身份。

本地账号和外部身份源可以共存，配置其中一个不会关闭另一个。

## 生产部署要点

- **用 HTTPS。** 生产环境下明文 issuer 会被拒绝，除非显式设置
  `OAUTH_ALLOW_INSECURE_HTTP=true`——不要这么做。
- **多副本部署必须自己持有签名密钥。** 用 `npm run keys:generate` 生成，放进
  `OAUTH_SIGNING_KEYS_JSON`，并设置 `OAUTH_ALLOW_GENERATED_KEYS=false`。否则每
  个副本各自生成一份密钥，一个副本签发的令牌会被另一个拒绝。
- **只有在你自己掌控的反向代理后面才开 `TRUST_PROXY=true`。** 它会让应用信任
  `X-Forwarded-*`；直接暴露的进程开了它，调用方就能伪造自己的来源 IP，绕过限流
  并污染审计日志。
- **不要修改已上线部署的 `OAUTH_ISSUER`。** 客户端会逐字节比对 `iss`，改了会让
  所有已签发的令牌失效。
- **备份数据库。** 里面有账号、授权记录，以及（如果你没自己提供）签名密钥。
- **访问令牌是自包含 JWT，无法提前撤销。** 撤销令牌、或刷新令牌被重放导致整个
  family 被吊销，都会终止这次授权；但已经签发出去的访问令牌在过期前仍然可以验签
  通过，内省也会继续返回 `active: true`。真正限制这个窗口的是
  `OAUTH_ACCESS_TOKEN_TTL`（默认 1 小时）——如果你的威胁模型要求撤销立刻生效，就
  把它调短，代价是刷新请求变多。

## Docker

```bash
docker compose up --build -d
```

不需要 `.env`。容器启动时会应用待执行的 SQLite 迁移，首次启动自动生成签名密钥，
并在 `http://127.0.0.1:3010` 提供可用的 issuer。SQLite 文件（以及其中的签名密钥）
存放在一个具名 Docker 卷上，因此重建镜像不会让已签发的令牌失效。`docker compose down`
会保留它；`docker compose down -v` 会删除它，此前签发的所有令牌都将无法验证。如果希望
数据库落在宿主机上可见的路径，请参考 `compose.yml` 中 `volumes:` 条目上的注释：容器不以
root 运行，所以 bind mount 的目录必须先存在、并且属主为 uid 1000。

镜像以非 root 用户运行，根文件系统只读，丢弃所有 capability，并设置
`no-new-privileges`。compose 文件故意只绑定 `127.0.0.1`：请在前面放一个负责 TLS
终止的反向代理，而不是直接把进程暴露出去。

上面这种"零配置即可启动"依赖 `compose.yml` 里的两个设置，正式部署时两者都必须修改。
`NODE_ENV=production` 默认会拒绝明文 `http` 的 issuer，也拒绝自动生成签名密钥；
`compose.yml` 通过 `OAUTH_ALLOW_INSECURE_HTTP=true` 和
`OAUTH_ALLOW_GENERATED_KEYS=true` 为仅监听回环地址的容器放开这两项。一旦服务有了正式
域名，请启用 HTTPS 并把 `PUBLIC_BASE_URL` 改为 `https` 地址，通过
`OAUTH_SIGNING_KEYS_JSON` 从密钥管理服务注入密钥，然后把这两项改回 `false`。

切换到 PostgreSQL 时，取消 `compose.yml` 中标注行的注释，设置
`POSTGRES_PASSWORD`，用 `--build-arg DATABASE_PROVIDER=postgresql` 重新构建，并在
启动服务前手动执行一次迁移：

```bash
docker compose build --build-arg DATABASE_PROVIDER=postgresql
docker compose run --rm knight-oauth node scripts/prisma.js migrate deploy
docker compose up -d
```

PostgreSQL 默认不会在启动时自动迁移：多副本同时迁移同一数据库是真实的损坏路径。
可用 `OAUTH_MIGRATE_ON_START=true|false` 覆盖任一方向的默认行为。

## 开发

```bash
npm run dev            # node --watch
npm test               # 单元 + 集成测试
```

集成测试跑在真实的临时 SQLite 数据库上，并通过真实 HTTP 请求、真实会话 cookie
和真实 CSRF 令牌驱动整个应用，而不是用 Prisma 替身。替身只能证明代码调用了作者
预期的方法，无法证明唯一约束真的生效、带条件的 `updateMany` 真的让一次性令牌只
能用一次，或者模板真的能渲染出来。

CI 覆盖单台机器覆盖不到的部分：Linux 与 Windows 上分别跑 Node 22 和 24 的测试；把
PostgreSQL 迁移应用到真实数据库并在其上启动 issuer；以及执行一次
`docker compose up`，验证容器被销毁重建后签名密钥依然有效。其中
`.github/scripts/probe.js` 是通过真实 HTTP 探测运行中服务的部分，可以指向任意实例，
用第三方客户端库的视角检查它：

```bash
node .github/scripts/probe.js http://127.0.0.1:3010
```

欢迎贡献代码，见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可

MIT，见 [LICENSE](LICENSE)。

# Contributing

Thanks for looking. This is an authorization server, so the bar for a change is a
little different from most projects: a bug here is someone else's account.

## Getting set up

```bash
npm install
npm run setup
npm test
```

Node 22 or newer. No database server is needed — the default is SQLite and the
tests create their own temporary file per suite.

## Before you open a pull request

```bash
npm test                  # unit + integration, all of it
npm run db:schema:check    # the committed schemas match the template
```

Both must pass. If you changed `prisma/schema.template.prisma`, run
`npm run db:schema` and commit the two generated schemas along with a migration
for each provider — the SQL is not identical on PostgreSQL and SQLite, which is
why they are separate.

## What a good change looks like

**Cite the specification.** If the change is about protocol behaviour, say which
document and section. `RFC 6749 §3.1.2.3` in a comment is worth more than a
paragraph of prose, because the next person can go read it.

**Explain why, not what.** The code already says what it does. Comments in this
repository explain the decision — why PKCE `plain` is absent, why the token
endpoint is exempt from CSRF, why a status code is 401 and not 400. If a reviewer
would ask "why is it like this?", answer it in the comment.

**Test the property, not the call.** The integration suite uses a real database
and real HTTP for a reason: a mock proves the code called what the author
expected, which is not the same as proving a unique constraint fires or a
single-use token is single use. If your change is security-relevant, the test
should fail if the protection is removed.

**Do not widen what is accepted to make something work.** If a client library
does not work against this server, that is usually worth fixing — but the fix is
to support a method the specification allows, not to relax a check. Accepting
`plain` PKCE or prefix-matching a redirect URI would make some integrations
easier and would be the wrong trade.

## Things that will be turned down

- A signing key, client secret, or `.env` in a commit. Check before you push.
- Logging a token, cookie, `state`, `nonce`, PKCE verifier, client secret, or
  private key — including into the audit log.
- A new runtime dependency for something the standard library does. The
  dependency list is short deliberately: every package here is in the path of an
  authentication decision.
- Storing a credential as anything other than a hash.
- An inline `<script>` or `<style>` in a template. The Content Security Policy has
  no `unsafe-inline`, so a browser drops it silently and the page quietly
  half-works.

## A note on the templates

EJS tokenizes the whole file with a regular expression before it parses any
JavaScript, so an opening tag written literally inside a `<% %>` block — even in
a comment — ends the block early and breaks the template. Describe a tag in
prose; do not spell one out.

EJS also copies a fixed list of names (`client`, `scope`, `context`, `debug`,
`cache`, `strict`, `async`, and a few more) out of the render data and treats them
as compiler options. This app registers its own engine function in `src/app.js` to
keep locals and options apart, which is what makes a local named `client` safe.
Do not replace that with `app.set("view engine", "ejs")`.

## Reporting a security issue

Not here — see [SECURITY.md](SECURITY.md). Use a private advisory rather than a
public issue or pull request.

## License

By contributing you agree your contribution is licensed under the MIT License,
the same as the rest of the project.

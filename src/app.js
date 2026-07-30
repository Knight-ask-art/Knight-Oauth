"use strict";

const path = require("node:path");
const ejs = require("ejs");
const express = require("express");
const helmet = require("helmet");

const { loadEnv } = require("./config/env");
const { prisma: defaultPrisma } = require("./config/prisma");

const { createScopeRegistry } = require("./lib/scopes");
const { createAccountService } = require("./services/accountService");
const { createAuditService } = require("./services/auditService");
const { createBackchannelService } = require("./services/backchannelService");
const { createClientService } = require("./services/clientService");
const { createExternalIdentityService } = require("./services/externalIdentityService");
const { createKeyService } = require("./services/keyService");
const { createMailService } = require("./services/mailService");
const { createProviderService } = require("./services/providerService");
const { createSessionService } = require("./services/sessionService");

const { cookieMiddleware } = require("./middleware/cookies");
const { createCsrfMiddleware, isStatelessProtocolEndpoint } = require("./middleware/csrf");
const { createRateLimitMiddleware } = require("./middleware/rateLimit");
const { createSessionMiddleware, requireAdmin, requireAuth } = require("./middleware/session");

const { createAccountController } = require("./controllers/accountController");
const { createAdminController } = require("./controllers/adminController");
const { createExternalController } = require("./controllers/externalController");
const { createOAuthController } = require("./controllers/oauthController");

const { createAccountRoutes } = require("./routes/accountRoutes");
const { createAdminRoutes } = require("./routes/adminRoutes");
const { createOAuthRoutes } = require("./routes/oauthRoutes");

// Composition root.
//
// Every service is constructed here and passed its collaborators explicitly, so
// there is one place that describes what this server is made of and no module
// reaches for a global. It is also what makes the test suite able to build the
// same graph against a temporary database.
//
// Middleware order is load-bearing:
//
//   1. helmet          — headers, before anything can respond
//   2. body parsers    — the protocol endpoints are form-encoded
//   3. public routes   — machine responses never enter browser state middleware
//   4. cookies         — the session middleware reads them
//   5. session         — attaches req.currentUser, which CSRF rendering uses
//   6. csrf            — must see req.body, so it follows the parsers
//   7. stateful routes — authorization, account, and administration
//   8. error handler   — last, and it decides JSON or HTML by path
//
// Putting CSRF before the body parser is a classic way to make it silently pass
// every request, so the order above is not incidental.

function createApp(options = {}) {
  const config = options.env || loadEnv();
  const prisma = options.prisma || defaultPrisma;
  const logger = options.logger || console;

  // --- Services -------------------------------------------------------------
  const auditLog = options.auditLog || createAuditService({ prisma, logger });
  const scopeRegistry = options.scopeRegistry || createScopeRegistry({ customScopes: config.customScopes });
  const mailer = options.mailer || createMailService({ config, logger });
  const accounts = options.accounts || createAccountService({ prisma, config, mailer, auditLog });
  const sessions = options.sessions || createSessionService({ prisma, config, auditLog });
  const clients = options.clients || createClientService({ prisma, config, scopeRegistry, auditLog });
  const keys = options.keys || createKeyService({ prisma, config: config.signing });

  const backchannel =
    options.backchannel ||
    createBackchannelService({
      prisma,
      config,
      clients,
      keys,
      auditLog,
      fetchImpl: options.fetchImpl
    });

  const provider =
    options.provider ||
    createProviderService({
      prisma,
      config,
      scopeRegistry,
      clients,
      accounts,
      sessions,
      keys,
      auditLog,
      backchannel
    });

  // Only built when a provider is configured. An unconfigured deployment gets no
  // external sign-in routes at all rather than routes that always fail.
  const external =
    options.external ||
    (config.externalProviders.length
      ? createExternalIdentityService({ prisma, config, accounts, auditLog, backchannel })
      : null);

  // --- Controllers ----------------------------------------------------------
  const oauthController = createOAuthController({
    config,
    provider,
    clients,
    scopeRegistry,
    accounts,
    logger
  });
  const accountController = createAccountController({
    config,
    accounts,
    sessions,
    provider,
    clients,
    external,
    logger
  });
  const adminController = createAdminController({ config, accounts, clients, logger });
  const externalController = external
    ? createExternalController({ config, external, sessions, accounts, logger })
    : null;

  // --- The application ------------------------------------------------------
  const app = express();

  app.locals.config = config;
  app.locals.isProduction = config.isProduction;
  app.locals.branding = config.branding;
  // Reachable for a scheduled prune or a graceful shutdown without rebuilding
  // the graph.
  app.locals.services = {
    accounts,
    auditLog,
    backchannel,
    clients,
    external,
    keys,
    prisma,
    provider,
    scopeRegistry,
    sessions
  };

  app.set("views", path.join(__dirname, "views"));
  app.set("view engine", "ejs");
  // EJS's Express adapter copies a fixed list of names — `client`, `scope`,
  // `context`, `debug`, `cache`, `strict`, `async` and a few more — straight out
  // of the render data and treats them as compiler options. The consent screen
  // renders with a local called `client`, which EJS read as `client: true` and
  // compiled the template in client mode, where `include` does not exist: every
  // consent request was a 500. Registering the engine ourselves keeps locals and
  // options apart, so a view local can be named after the thing it describes.
  app.engine("ejs", (file, locals, callback) => {
    ejs.renderFile(file, locals, { filename: file, cache: config.isProduction }, callback);
  });
  // Off, so an issuer behind a load balancer does not advertise what it runs.
  app.disable("x-powered-by");
  // `req.ip` is only trustworthy behind a proxy that sets the header, and
  // trusting it otherwise lets a caller spoof the address in the audit log and
  // in every rate-limit bucket. The value is passed through rather than
  // collapsed to `true`: a hop count is what makes the address the nearest
  // proxy observed rather than the left-most entry the client may have written.
  // See parseTrustProxy in config/env.js.
  if (config.trustProxy !== false) app.set("trust proxy", config.trustProxy);

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          // No inline script anywhere in the views, so this needs no unsafe-inline
          // and an injected <script> cannot run.
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          // A client's logo is a URL it registered, so images may come from
          // anywhere; nothing is executed as a result.
          imgSrc: ["'self'", "data:", "https:"],
          // The consent form posts to this issuer and nowhere else, which is what
          // stops an injected form from retargeting a submission.
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          ...(config.allowInsecureHttp ? {} : { upgradeInsecureRequests: [] })
        }
      },
      // A cross-origin relying party legitimately fetches discovery metadata and
      // JWKS, so the default same-origin policy would break exactly the clients
      // this server exists for. Those two are read-only public documents.
      crossOriginResourcePolicy: { policy: "cross-origin" },
      // The authorization endpoint is reached by a cross-site top-level redirect,
      // which COEP/COOP isolation would interfere with for embedded flows.
      crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
      // HSTS only where the issuer actually serves https; setting it over http is
      // meaningless and, on a shared hostname, harmful.
      hsts: config.allowInsecureHttp ? false : { maxAge: 31536000, includeSubDomains: true }
    })
  );

  // Body limits are small on purpose. Nothing on this server legitimately posts
  // more than a few kilobytes, and a large body is either a mistake or an
  // attempt to make the process do allocation work.
  app.use(express.json({ limit: "64kb" }));
  app.use(express.urlencoded({ extended: false, limit: "64kb" }));

  // The one operator-configurable value that has to reach CSS, served as a real
  // stylesheet rather than an inline <style> block. That is what lets `styleSrc`
  // above stay `'self'` with no `unsafe-inline`: a browser drops an inline style
  // under that policy silently, so the brand colour would simply not apply and
  // nothing would say why.
  //
  // Registered ahead of the static mount so it wins on that path. It is written
  // into a custom property, and the value is escaped, so a stray character in
  // configuration cannot close the rule and open another.
  app.get("/static/css/brand.css", (req, res) => {
    const color = String(config.branding.primaryColor || "#2b6cb0").replace(/[^#a-zA-Z0-9(),.%\s-]/g, "");
    res.type("text/css");
    res.set("Cache-Control", "public, max-age=300");
    return res.send(`:root { --brand: ${color}; }\n`);
  });
  app.use("/static", express.static(path.join(__dirname, "public"), { index: false, maxAge: "1h" }));

  // --- CORS, for the endpoints a browser-based client reads -----------------
  //
  // A single-page application fetches discovery, JWKS, and the token endpoint
  // from the browser, so those must answer a cross-origin request. `*` is right
  // here and safe: none of them authenticates with a cookie, so there is no
  // ambient authority for another origin to borrow. Credentials are never
  // allowed, which is what keeps that true.
  const CORS_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/oauth2/jwks",
    "/oauth2/token",
    "/oauth2/userinfo",
    "/oauth2/revoke"
  ];
  app.use((req, res, next) => {
    if (!CORS_PATHS.includes(req.path)) return next();
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Max-Age", "600");
    if (req.method === "OPTIONS") return res.status(204).end();
    return next();
  });

  // Public machine endpoints must stay independent of browser state. Mounting
  // them before the cookie, session, and CSRF middleware means a health probe
  // or client fetching metadata never receives a session/CSRF cookie, even if
  // the request happens to carry a browser cookie of its own.
  app.get("/healthz", oauthController.health);
  app.get("/.well-known/openid-configuration", oauthController.openidConfiguration);
  app.get("/.well-known/oauth-authorization-server", oauthController.authorizationServerMetadata);
  app.get("/oauth2/jwks", oauthController.jwks);
  app.get("/.well-known/jwks.json", oauthController.jwks);

  app.use(cookieMiddleware);
  const sessionMiddleware = createSessionMiddleware({ sessions, accounts, provider });
  app.use((req, res, next) => {
    if (isStatelessProtocolEndpoint(req.path)) return next();
    return sessionMiddleware(req, res, next);
  });
  app.use(createCsrfMiddleware({ secureCookies: String(config.publicBaseUrl).startsWith("https:") }));

  // --- Rate limiting --------------------------------------------------------
  //
  // After CSRF, so a request that fails there is never counted — it cost
  // nothing to refuse, and the endpoints being metered are expensive only past
  // that point. After the body parsers, because the second half of each key is
  // the identifier the caller submitted.
  //
  // Mounted here rather than on each route so that rateLimit.js holds the whole
  // policy in one readable table. Which endpoints are metered, and at what, is
  // the kind of thing that should be answerable by opening one file.
  app.use(createRateLimitMiddleware({ config, logger }));

  // --- Routes ---------------------------------------------------------------
  app.use(createOAuthRoutes({ controller: oauthController }));
  app.use(createAccountRoutes({ controller: accountController, external: externalController, requireAuth }));
  app.use(createAdminRoutes({ controller: adminController, requireAdmin }));

  // --- Not found ------------------------------------------------------------
  app.use((req, res) => {
    if (wantsJson(req)) {
      return res.status(404).json({ error: "not_found", error_description: "No such endpoint" });
    }
    return res.status(404).render("error", {
      branding: config.branding,
      title: "Not found",
      heading: "There is nothing here",
      message: "The page you asked for does not exist on this server.",
      status: 404
    });
  });

  /** A protocol endpoint answers in JSON; a browser page answers in HTML. */
  function wantsJson(req) {
    return (
      req.path.startsWith("/oauth2/") ||
      req.path.startsWith("/.well-known/") ||
      req.path === "/healthz" ||
      req.accepts(["html", "json"]) === "json"
    );
  }

  // --- Errors ---------------------------------------------------------------
  //
  // A protocol error carries a code a client branches on, so it is passed
  // through verbatim. Anything else is reported as `server_error` with a fixed
  // message: an internal error's text can name a table, a path, or a value, and
  // an authorization server should not narrate its internals to a caller.
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);

    const isProtocol = Boolean(error?.isProtocolError);
    const status = Number.isInteger(error?.statusCode) ? error.statusCode : 500;

    if (status >= 500) {
      logger.error?.("unhandled error", {
        method: req.method,
        path: req.path,
        message: error?.message,
        stack: error?.stack
      });
    }

    if (wantsJson(req)) {
      if (isProtocol && status === 401 && !res.get("WWW-Authenticate")) {
        // RFC 6750 section 3 / RFC 6749 section 5.2: a 401 needs a challenge, and
        // some client libraries will not retry without one.
        const scheme = error.code === "invalid_client" ? "Basic" : "Bearer";
        res.set("WWW-Authenticate", `${scheme} realm="${config.issuer}", error="${error.code}"`);
      }
      res.set("Cache-Control", "no-store");
      return res.status(status).json({
        error: isProtocol ? error.code : "server_error",
        error_description: isProtocol ? error.message : "The server could not complete this request"
      });
    }

    return res.status(status).render("error", {
      branding: config.branding,
      title: status >= 500 ? "Server error" : "Something went wrong",
      heading: status >= 500 ? "This server hit an error" : "That request could not be completed",
      message:
        status >= 500
          ? "Something went wrong on this server. Try again, and tell the operator if it keeps happening."
          : error?.message || "The request was not valid.",
      code: isProtocol ? error.code : null,
      status
    });
  });

  return app;
}

module.exports = { createApp };

"use strict";

// Before anything reads configuration, including the module that builds the
// Prisma client.
const { loadDotEnv } = require("./config/dotenv");
if (require.main === module) loadDotEnv();

const { createApp } = require("./app");
const { loadEnv } = require("./config/env");

// Entry point.
//
// Three things happen here that do not belong in `createApp`, because the test
// suite builds the app hundreds of times and must not do any of them:
//
//   1. Boot-time verification. The database connection, the signing key and the
//      statically configured clients are all resolved before the port opens, so
//      a misconfigured deployment fails at start with one clear message instead
//      of serving 500s at the first token request.
//
//   2. Maintenance. Expired codes, used tokens, dead sessions and delivered
//      logout notifications accumulate forever otherwise, and a queued
//      back-channel logout is only delivered by something calling `flush`.
//
//   3. Graceful shutdown. A SIGTERM in the middle of a token exchange should
//      finish the exchange, not drop it.
//
// `start` does all three and returns a handle. The signal handlers and the
// `process.exit` calls live in the self-run block at the bottom, not in `start`,
// so the drain can be exercised by a caller that intends to keep running.

// How often the queue is drained and the expired rows are dropped. Delivery is
// checked at the back-channel retry interval, because a client waiting on a
// logout notification is waiting on this; pruning is hourly because nothing
// depends on its timeliness.
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;
// Requests still in flight when a shutdown signal arrives get this long to
// finish before the process gives up on them. Longer than a typical proxy's own
// drain timeout would just make the proxy give up first.
const SHUTDOWN_GRACE_MS = 10_000;

/**
 * Resolves everything that can be wrong about the configuration before the port
 * opens. Each step throws with its own message, which is the whole point: "no
 * signing key is configured" is actionable, and a 500 from /oauth2/token an hour
 * later is not.
 */
async function verifyBoot({ services, config, logger }) {
  await services.prisma.$connect();

  // Fails when OAUTH_SIGNING_KEYS_JSON is malformed, and when no key exists and
  // generation is disallowed. Also the point at which a first boot writes its
  // generated key, so the first request is not the one paying for it.
  await services.keys.ensureKeyRing();

  // Idempotent on client_id. Throws on malformed JSON or a confidential client
  // with no secret, both of which are configuration errors worth failing on.
  try {
    const staticClients = await services.clients.syncStaticClients(config.staticClients);
    if (staticClients.imported || staticClients.updated) {
      logger.info?.(
        `static clients: ${staticClients.imported} imported, ${staticClients.updated} updated`
      );
    }
  } catch (error) {
    // Named, because the underlying validators talk about a field ("Client name
    // is required") without saying which of several entries carried it.
    throw new Error(`OAUTH_STATIC_CLIENTS could not be imported: ${error?.message}`);
  }
}

/**
 * Drops rows nothing needs any more.
 *
 * Every step is independent and each failure is logged rather than thrown: this
 * runs on a timer with no caller, and a transient database error during a prune
 * must not take down an otherwise healthy issuer. `signing_keys` is pruned too,
 * but only rows already retired past their overlap window — the active key is
 * matched by `isActive: false`, never by age.
 */
async function prune({ services, logger }) {
  const steps = [
    ["authorization state", () => services.provider.pruneExpired()],
    ["sessions", () => services.sessions.pruneExpired()],
    ["account tokens", () => services.accounts.pruneExpiredTokens()],
    ["retired signing keys", () => services.keys.pruneExpired()],
    ["delivered logouts", () => services.backchannel.pruneDelivered()],
    ...(services.external ? [["consumed tickets", () => services.external.pruneConsumedTickets()]] : [])
  ];

  for (const [what, run] of steps) {
    try {
      await run();
    } catch (error) {
      logger.warn?.(`prune failed for ${what}: ${error?.message}`);
    }
  }
}

/** Delivers queued back-channel logout notifications. */
async function flushLogouts({ services, logger }) {
  try {
    await services.backchannel.flush();
  } catch (error) {
    logger.warn?.(`back-channel logout flush failed: ${error?.message}`);
  }
}

/**
 * setInterval with a re-entrancy guard. A prune that takes longer than its
 * interval would otherwise start again on top of itself, and two concurrent
 * `deleteMany` sweeps over the same rows is a lock fight on a busy database.
 */
function repeat(intervalMs, task) {
  let running = false;
  const timer = setInterval(async () => {
    if (running) return;
    running = true;
    try {
      await task();
    } finally {
      running = false;
    }
  }, intervalMs);
  // The listening server keeps the process alive; these must not be what does
  // it, or closing the server would leave a process that never exits.
  timer.unref();
  return timer;
}

/** What is safe to print at startup: no URL with a password in it, no key material. */
function describe({ config, keys, port }) {
  const lines = [
    `${config.branding.serviceName} — ${config.nodeEnv}`,
    `listening   ${port}`,
    `issuer      ${config.issuer}`,
    `database    ${config.database.provider}`,
    // The source is the thing that usually surprises an operator: a key held in
    // the database means restarting is fine but a second replica is not.
    `signing     ${keys.algorithm} (key source: ${keys.source})`,
    `discovery   ${config.issuer}/.well-known/openid-configuration`
  ];
  if (config.externalProviders.length) {
    lines.push(`external    ${config.externalProviders.map((provider) => provider.name).join(", ")}`);
  }
  if (config.clients.dynamicRegistrationEnabled && !config.clients.registrationAccessToken) {
    lines.push("WARNING     dynamic registration is open — anyone can register a client");
  }
  // Outside production a disabled mailer prints the link, so the operator finds
  // out by using it. In production the link is suppressed, which is correct but
  // silent: password reset and email verification simply stop working, and the
  // first report of it comes from a locked-out user. Say so at boot instead.
  if (config.isProduction && !config.mail.enabled) {
    lines.push(
      "WARNING     SMTP is off in production — password reset and email verification cannot be delivered; set SMTP_ENABLED=true"
    );
  }
  // Every URL a client is told to use comes from the issuer, so an issuer whose
  // port is not the one being listened on produces a discovery document that
  // points at nothing. Easy to do with PORT set and PUBLIC_BASE_URL left alone,
  // and the symptom otherwise appears in the client, not here.
  const issuerPort = new URL(config.issuer).port || (config.issuer.startsWith("https:") ? "443" : "80");
  if (String(port) !== issuerPort) {
    lines.push(
      `WARNING     listening on ${port} but the issuer says ${issuerPort}; set PUBLIC_BASE_URL to match, or clients will be sent to the wrong port`
    );
  }
  return lines.join("\n");
}

/**
 * Boots the service and returns a handle.
 *
 * @param {object} [options] passed through to `createApp`, so a caller can
 *   supply its own database or logger.
 * @param {number} [options.port] overrides the configured port. Only a caller
 *   that already holds the process uses this — 0 asks the OS for a free port,
 *   which the configuration itself rejects, because an issuer on a port nobody
 *   can predict is a misconfiguration rather than a feature.
 * @returns {Promise<{server: import("node:http").Server, config: object,
 *   services: object, port: number, close: () => Promise<void>}>}
 */
async function start(options = {}) {
  const config = options.env || loadEnv();
  const logger = options.logger || console;
  const requestedPort = options.port ?? config.port;
  const app = createApp({ ...options, env: config, logger });
  const services = app.locals.services;

  await verifyBoot({ services, config, logger });

  const server = await new Promise((resolve, reject) => {
    const listener = app.listen(requestedPort);
    listener.once("listening", () => resolve(listener));
    // Without this, EADDRINUSE surfaces as an unhandled 'error' event that
    // crashes with a stack instead of the one line that says the port is taken.
    listener.once("error", reject);
  });

  // Slow-loris style: a connection that sends nothing still holds a socket. The
  // defaults are generous for a browser and far too generous for endpoints whose
  // largest legitimate body is a few kilobytes.
  server.headersTimeout = 20_000;
  server.requestTimeout = 30_000;

  const port = server.address()?.port ?? requestedPort;
  logger.info?.(describe({ config, keys: services.keys, port }));

  const timers = [
    repeat(PRUNE_INTERVAL_MS, () => prune({ services, logger })),
    repeat(config.backchannel.retrySeconds * 1000, () => flushLogouts({ services, logger }))
  ];

  let closing = null;
  /** Stops accepting connections, waits for in-flight requests, releases the database. */
  function close() {
    if (closing) return closing;
    closing = (async () => {
      for (const timer of timers) clearInterval(timer);

      const closed = new Promise((resolve) => server.close(resolve));
      // Idle keep-alive sockets hold the server open for their full timeout with
      // no request to wait for, so they are closed rather than waited on. Active
      // ones are left alone: that is the request being allowed to finish.
      server.closeIdleConnections?.();

      let timedOut = false;
      const grace = new Promise((resolve) => {
        const timer = setTimeout(() => {
          timedOut = true;
          resolve();
        }, SHUTDOWN_GRACE_MS);
        timer.unref();
      });

      await Promise.race([closed, grace]);
      if (timedOut) logger.warn?.(`still draining after ${SHUTDOWN_GRACE_MS}ms, giving up on open connections`);
      await services.prisma.$disconnect().catch(() => {});
    })();
    return closing;
  }

  return { server, config, services, port, close };
}

/**
 * Boots the service and wires signal handlers. Called by this module when it is
 * the process entry point, and by the Docker entrypoint after migrations.
 *
 * Exported separately from `start` so a wrapper that has already done setup
 * work — applying migrations, for instance — can take over as the process
 * without being blocked by `require.main === module`. A plain `require` of this
 * file does nothing, which is what the test suite needs.
 */
function runAsMain() {
  // The entrypoint may have already loaded `.env`; doing it again is free.
  loadDotEnv();

  return start()
    .then((handle) => {
      let shuttingDown = false;
      const onSignal = async (signal) => {
        // A second signal during the drain means whoever sent it wants out now.
        if (shuttingDown) process.exit(1);
        shuttingDown = true;
        console.info(`${signal} received, draining`);
        await handle.close();
        process.exit(0);
      };
      // SIGTERM is what a container runtime and systemd send. SIGINT is Ctrl+C.
      // Node cannot receive a real SIGTERM on Windows, which is why the drain
      // lives in `close()` rather than inside the handler.
      process.on("SIGTERM", () => onSignal("SIGTERM"));
      process.on("SIGINT", () => onSignal("SIGINT"));
    })
    .catch((error) => {
      // The message, not the stack: a configuration error's stack is noise, and
      // this is the line an operator reads out of `docker logs`. Anything that is
      // not an Error still prints everything it has, because then the location is
      // the useful part.
      process.stderr.write(`Knight OAuth failed to start: ${error?.message || error}\n`);
      if (!(error instanceof Error) || !error.message) process.stderr.write(`${error?.stack || error}\n`);
      process.exit(1);
    });
}

module.exports = { start, runAsMain };

if (require.main === module) {
  runAsMain();
}

"use strict";

const { randomToken, safeEqual } = require("../lib/crypto");

// Sign-in through an external identity provider.
//
// Two values have to survive the round trip to the upstream and back: the
// `state` that binds the returning ticket to the request that started it, and
// where to send the user afterwards. Both are held server-side, in the session,
// rather than echoed through the URL — a `return_to` the upstream can rewrite is
// an open redirect, and a `state` the upstream can choose is not a binding at
// all.
//
// A visitor starting an external login has no session yet, so an anonymous one
// is created to hold that state. It carries no privileges. When the user is
// actually signed in, `req.signIn` destroys it and issues a fresh identifier, so
// nothing planted before authentication survives it.

const STATE_KEY = "externalState";
const RETURN_KEY = "externalReturnTo";

/** Restricts a post-login destination to a path on this server. */
function safeNext(value, fallback = "/account") {
  const raw = String(value || "");
  if (!raw.startsWith("/") || raw.startsWith("//")) return fallback;
  return raw;
}

function createExternalController({ config, external, sessions, accounts, logger = console }) {
  const branding = config.branding;

  function unavailable(res, message) {
    return res.status(404).render("error", {
      branding,
      title: "Not available",
      heading: "That sign-in method is not available",
      message,
      status: 404
    });
  }

  /** Ensures there is a session to park the state in, anonymous if need be. */
  async function sessionForState(req, res) {
    if (req.session) return req.session;
    const { sid, session, maxAgeMs } = await sessions.create({
      ipAddress: req.ip,
      userAgent: req.get("user-agent")
    });
    // `sessions.cookieName`, not the bare constant: an https issuer uses the
    // `__Host-` prefixed spelling, and writing the unprefixed one here would set
    // a cookie the session middleware does not read — so the state parked in it
    // would be gone by the time the upstream handed the browser back, and no
    // external sign-in would ever complete.
    res.cookie(sessions.cookieName, sid, sessions.cookieOptions(maxAgeMs));
    req.sid = sid;
    req.session = session;
    return session;
  }

  /**
   * GET /login/external/:provider — hands the browser to the upstream.
   *
   * A GET is right here: nothing has changed yet, and this is a navigation the
   * user asked for by following a link on the sign-in page.
   */
  async function start(req, res, next) {
    try {
      const adapter = external?.get?.(req.params.provider);
      if (!adapter) return unavailable(res, "This server is not configured to use that provider.");

      const session = await sessionForState(req, res);
      const state = randomToken();
      await sessions.update({
        sessionId: session.id,
        data: {
          [STATE_KEY]: state,
          [RETURN_KEY]: safeNext(req.query.next, "/account")
        }
      });

      const returnTo = new URL(
        `/login/external/${encodeURIComponent(adapter.name)}/callback`,
        config.publicBaseUrl
      ).toString();

      return res.redirect(adapter.buildStartUrl({ state, returnTo }));
    } catch (error) {
      return next(error);
    }
  }

  /**
   * GET /login/external/:provider/callback — verifies the ticket and signs in.
   *
   * The state comparison happens here rather than inside the adapter's `verify`,
   * because only this layer knows which request the browser started. `verify`
   * checks that the signed ticket carries the same value, so the two together
   * bind ticket to browser to request.
   */
  async function callback(req, res, next) {
    try {
      const adapter = external?.get?.(req.params.provider);
      if (!adapter) return unavailable(res, "This server is not configured to use that provider.");

      const expected = String(req.session?.data?.[STATE_KEY] || "");
      const presented = String(req.query.state || "");
      if (!expected || !presented || !safeEqual(presented, expected)) {
        return res.status(400).render("error", {
          branding,
          title: "Sign-in failed",
          heading: "That sign-in could not be completed",
          message:
            "The sign-in attempt did not match this browser. It may have expired, or been started somewhere else. Try again from the sign-in page.",
          status: 400
        });
      }

      const target = safeNext(req.session?.data?.[RETURN_KEY], "/account");
      // Spent whether or not what follows succeeds, so a state cannot be reused.
      await sessions.update({
        sessionId: req.session.id,
        data: { [STATE_KEY]: null, [RETURN_KEY]: null }
      });

      const { account } = await external.completeCallback({
        provider: adapter.name,
        ticket: req.query.ticket,
        state: presented,
        ipAddress: req.ip,
        userAgent: req.get("user-agent")
      });

      if (account.status === accounts.STATUS.DISABLED) {
        return res.status(403).render("error", {
          branding,
          title: "Account unavailable",
          heading: "That account has been disabled",
          message: "Contact the operator of this server.",
          status: 403
        });
      }

      await req.signIn({ userId: account.id });
      return res.redirect(target);
    } catch (error) {
      if (error?.isProtocolError || (error?.statusCode && error.statusCode < 500)) {
        logger.warn?.("external sign-in refused", error.message);
        return res.status(error.statusCode || 400).render("error", {
          branding,
          title: "Sign-in failed",
          heading: "That sign-in could not be completed",
          message: error.message,
          status: error.statusCode || 400
        });
      }
      return next(error);
    }
  }

  /** POST /account/external/unlink — drops a linked provider. */
  async function unlink(req, res, next) {
    try {
      await external.unlink({
        provider: req.body.provider,
        userId: req.currentUser.id,
        ipAddress: req.ip,
        userAgent: req.get("user-agent")
      });
      return res.redirect("/account?notice=provider-unlinked");
    } catch (error) {
      if (error?.isProtocolError || (error?.statusCode && error.statusCode < 500)) {
        return res.status(400).render("notice", {
          branding,
          title: "Not unlinked",
          heading: "That provider was not unlinked",
          message: error.message,
          actionUrl: "/account",
          actionLabel: "Back to your account"
        });
      }
      return next(error);
    }
  }

  return { callback, start, unlink };
}

module.exports = { createExternalController };

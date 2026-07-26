"use strict";

const { SESSION_COOKIE } = require("../services/sessionService");

// Session middleware.
//
// The session identifier is a bearer credential for the whole account, so it is
// looked up through sessionService, which stores only its hash. This middleware
// never sees a raw value except the one the browser presented and never writes
// one anywhere but the cookie.

/**
 * Attaches `req.session`, `req.currentUser`, and the two transitions a request
 * can make: signing in and signing out.
 */
function createSessionMiddleware({ sessions, accounts, provider }) {
  return async (req, res, next) => {
    try {
      // The name comes from the service, because it depends on the scheme: an
      // https issuer uses the `__Host-` prefixed spelling. Deliberately no
      // fallback to the unprefixed one — see the note on the constants.
      req.sid = req.cookies?.[sessions.cookieName] || null;
      req.session = req.sid ? await sessions.find(req.sid) : null;
      req.currentUser = null;

      if (req.session?.userId) {
        const account = await accounts.findById(req.session.userId);
        // A disabled account must lose its session immediately, not at expiry.
        if (account && account.status !== accounts.STATUS.DISABLED) {
          req.currentUser = account;
          // Extends an active session so a user is not signed out mid-task.
          req.session = (await sessions.touch({ res, sid: req.sid, session: req.session })) || req.session;
        } else {
          await sessions.logout({ res, sid: req.sid, reason: "account_unavailable" });
          req.session = null;
          req.sid = null;
        }
      }

      req.signIn = async ({ userId, remember = false } = {}) => {
        const result = await sessions.login({
          res,
          currentSid: req.sid,
          userId,
          remember,
          ipAddress: req.ip,
          userAgent: req.get?.("user-agent")
        });
        req.sid = result.sid;
        req.session = result.session;
        req.currentUser = await accounts.findById(userId);
        return result.session;
      };

      req.signOut = async ({ reason = "user_logout" } = {}) => {
        // An anonymous session — one holding only external-login state — has no
        // OIDC sessions to end, because those are created at authorization and
        // that requires an account. Skipping it here rather than inside
        // `endSessions` keeps `userId` a hard requirement there, where it is
        // the check that scopes the revocation to its owner.
        if (req.session?.userId) {
          // Notifying each client by back channel is what makes this a real
          // logout rather than one only this issuer knows about.
          await provider?.endSessions({ sessionId: req.session.id, userId: req.session.userId, reason });
        }
        await sessions.logout({ res, sid: req.sid, reason });
        req.session = null;
        req.currentUser = null;
        req.sid = null;
      };

      res.locals.currentUser = req.currentUser;
      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Requires a signed-in user for a browser page.
 *
 * An unauthenticated request is redirected to the sign-in page carrying where it
 * was going, so a user who follows a bookmark to a management page lands back
 * there after signing in. The return target is restricted to a path on this
 * issuer — accepting an absolute URL would make the sign-in page an open
 * redirect.
 */
function requireAuth(req, res, next) {
  if (req.currentUser) return next();
  const target = req.originalUrl.startsWith("/") && !req.originalUrl.startsWith("//") ? req.originalUrl : "/";
  return res.redirect(`/login?next=${encodeURIComponent(target)}`);
}

function requireAdmin(req, res, next) {
  if (!req.currentUser) return requireAuth(req, res, next);
  if (req.currentUser.role !== "ADMIN") {
    return res.status(403).render("error", {
      title: "Forbidden",
      heading: "You do not have access to this page",
      message: "This page is for administrators of this server.",
      status: 403
    });
  }
  return next();
}

/** Requires a verified email address, when the deployment demands one. */
function createRequireVerifiedEmail({ accounts }) {
  return (req, res, next) => {
    if (!accounts.requireEmailVerification) return next();
    if (!req.currentUser) return requireAuth(req, res, next);
    if (req.currentUser.emailVerified) return next();
    return res.redirect("/verify-email");
  };
}

module.exports = {
  SESSION_COOKIE,
  createRequireVerifiedEmail,
  createSessionMiddleware,
  requireAdmin,
  requireAuth
};

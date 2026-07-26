"use strict";

const { appError } = require("../lib/errors");

// The account surface: register, sign in, recover a password, verify an email,
// and manage which applications have access.
//
// Two rules run through all of it:
//
//   * A response never reveals whether an address is registered. Registration,
//     password reset, and sign-in all answer identically whether or not the
//     account exists, because the difference is an account-enumeration oracle
//     and an authorization server is a high-value place to have one.
//
//   * Where a page redirects to after signing in is restricted to a path on this
//     issuer. Echoing an arbitrary `next` back as a redirect would make the
//     sign-in page an open redirect, which is how a phishing flow borrows a
//     trusted domain.

/** Restricts a post-login destination to a path on this server. */
function safeNext(value, fallback = "/account") {
  const raw = String(value || "");
  // A protocol-relative `//host` is a redirect off-site that looks like a path.
  if (!raw.startsWith("/") || raw.startsWith("//")) return fallback;
  return raw;
}

function createAccountController({ config, accounts, sessions, provider, clients, external, logger = console }) {
  const branding = config.branding;

  function view(res, template, locals = {}) {
    return res.render(template, { branding, ...locals });
  }

  // --- Registration --------------------------------------------------------

  function registerPage(req, res) {
    if (req.currentUser) return res.redirect("/account");
    if (!accounts.registrationEnabled) {
      return res.status(403).render("error", {
        branding,
        title: "Registration closed",
        heading: "This server is not accepting new accounts",
        message: "Ask the operator of this server for an account.",
        status: 403
      });
    }
    return view(res, "register", {
      title: "Create an account",
      values: {},
      error: null,
      next: safeNext(req.query.next, "/account"),
      providers: external?.list?.() || [],
      minPasswordLength: accounts.minPasswordLength
    });
  }

  async function submitRegister(req, res, next) {
    const values = {
      email: String(req.body.email || ""),
      username: String(req.body.username || ""),
      name: String(req.body.name || "")
    };
    try {
      const result = await accounts.register({
        email: values.email,
        password: req.body.password,
        username: values.username,
        name: values.name,
        ipAddress: req.ip,
        userAgent: req.get("user-agent")
      });

      // One answer for every outcome: same status, same heading, same message,
      // and no Set-Cookie in any of them.
      //
      // Every other layer already treats this as the invariant. `register`
      // swallows P2002 and returns `{account: null}` rather than an error;
      // it notifies the existing holder inside a try/catch so a mail failure
      // cannot change the reply; check-email.ejs says in its own comment that
      // its wording is conditional precisely because this page is what a caller
      // sees when the address was already taken. This function was the one
      // place that gave it away, and it did not need the page to be read: a
      // duplicate rendered 200 HTML, while a free address answered 302 with a
      // session cookie. Status line alone, one request, no guessing.
      //
      // Signing in is therefore a separate, explicit step. There is no way to
      // establish a session here and still have the two answers be identical —
      // the cookie is the tell. The link below carries `next`, so a
      // registration that began inside an authorization request still lands
      // back in it after signing in.
      return view(res, "check-email", {
        title: "Check your email",
        heading: "Check your email",
        message: `If ${values.email} can be registered, a message is on its way with what to do next.`,
        next: safeNext(req.body.next, "")
      });
    } catch (error) {
      if (error?.statusCode && error.statusCode < 500) {
        return res.status(error.statusCode).render("register", {
          branding,
          title: "Create an account",
          values,
          error: error.message,
          next: safeNext(req.body.next, "/account"),
          providers: external?.list?.() || [],
          minPasswordLength: accounts.minPasswordLength
        });
      }
      return next(error);
    }
  }

  // --- Sign in -------------------------------------------------------------

  function loginPage(req, res) {
    const target = safeNext(req.query.next, "/account");
    // `reauthenticate` comes from prompt=login or max_age: a session exists but
    // the client asked for a fresh authentication.
    const reauthenticate = req.query.reauthenticate === "1";
    if (req.currentUser && !reauthenticate) return res.redirect(target);

    return view(res, "login", {
      title: "Sign in",
      identifier: String(req.query.login_hint || ""),
      error: null,
      next: target,
      reauthenticate,
      registrationEnabled: accounts.registrationEnabled,
      providers: external?.list?.() || [],
      minPasswordLength: accounts.minPasswordLength
    });
  }

  async function submitLogin(req, res, next) {
    const identifier = String(req.body.identifier || "");
    const target = safeNext(req.body.next, "/account");
    try {
      const result = await accounts.authenticate({
        identifier,
        password: req.body.password,
        ipAddress: req.ip,
        userAgent: req.get("user-agent")
      });

      if (!result.ok) {
        if (result.reason === "unverified") {
          return view(res, "check-email", {
            title: "Confirm your email",
            heading: "Confirm your email address to sign in",
            message: "Open the link in the message we sent you. Ask for a new one below if it has expired.",
            resend: true,
            identifier
          });
        }
        // Every other failure gets one message. "No such account" and "wrong
        // password" must be indistinguishable.
        const message =
          result.reason === "disabled"
            ? "That account has been disabled. Contact the operator of this server."
            : "That email or username and password do not match.";
        return res.status(401).render("login", {
          branding,
          title: "Sign in",
          identifier,
          error: message,
          next: target,
          reauthenticate: false,
          registrationEnabled: accounts.registrationEnabled,
          providers: external?.list?.() || [],
          minPasswordLength: accounts.minPasswordLength
        });
      }

      await req.signIn({ userId: result.account.id, remember: req.body.remember === "on" });
      return res.redirect(target);
    } catch (error) {
      return next(error);
    }
  }

  async function logout(req, res, next) {
    try {
      if (req.currentUser) await req.signOut({ reason: "user_logout" });
      return res.redirect("/");
    } catch (error) {
      return next(error);
    }
  }

  // --- Password recovery ---------------------------------------------------

  function forgotPasswordPage(req, res) {
    return view(res, "forgot-password", { title: "Reset your password", error: null, sent: false });
  }

  async function submitForgotPassword(req, res, next) {
    try {
      await accounts.requestPasswordReset({
        email: req.body.email,
        ipAddress: req.ip,
        userAgent: req.get("user-agent")
      });
      // Always the same answer. `sent` is not the service's result, deliberately:
      // reporting whether a message went out would confirm the address.
      return view(res, "forgot-password", { title: "Reset your password", error: null, sent: true });
    } catch (error) {
      return next(error);
    }
  }

  function resetPasswordPage(req, res) {
    return view(res, "reset-password", {
      title: "Choose a new password",
      token: String(req.query.token || ""),
      minPasswordLength: accounts.minPasswordLength,
      error: null
    });
  }

  async function submitResetPassword(req, res, next) {
    const token = String(req.body.token || "");
    try {
      const result = await accounts.resetPassword({
        token,
        password: req.body.password,
        ipAddress: req.ip,
        userAgent: req.get("user-agent")
      });

      if (!result.ok) {
        const message =
          result.reason === "expired_token"
            ? "That link has expired. Ask for a new one."
            : "That link is not valid. It may already have been used.";
        return res.status(400).render("reset-password", {
          branding,
          title: "Choose a new password",
          token,
          minPasswordLength: accounts.minPasswordLength,
          error: message
        });
      }

      // The reset revoked every session, including this browser's, so signing in
      // again here is a new session rather than a resumed one.
      await req.signIn({ userId: result.account.id });
      return view(res, "notice", {
        title: "Password changed",
        heading: "Your password has been changed",
        message: "You have been signed out everywhere else.",
        actionUrl: "/account",
        actionLabel: "Go to your account"
      });
    } catch (error) {
      if (error?.statusCode && error.statusCode < 500) {
        return res.status(error.statusCode).render("reset-password", {
          branding,
          title: "Choose a new password",
          token,
          minPasswordLength: accounts.minPasswordLength,
          error: error.message
        });
      }
      return next(error);
    }
  }

  // --- Email verification --------------------------------------------------

  async function verifyEmail(req, res, next) {
    try {
      const result = await accounts.verifyEmail(req.query.token, {
        ipAddress: req.ip,
        userAgent: req.get("user-agent")
      });
      if (!result.ok) {
        return res.status(400).render("notice", {
          branding,
          title: "Link not valid",
          heading: "That confirmation link did not work",
          message:
            result.reason === "expired_token"
              ? "The link has expired. Sign in to ask for a new one."
              : "The link is not valid, or it has already been used.",
          actionUrl: "/login",
          actionLabel: "Sign in"
        });
      }
      return view(res, "notice", {
        title: "Email confirmed",
        heading: "Your email address is confirmed",
        message: "You can sign in now.",
        actionUrl: "/login",
        actionLabel: "Sign in"
      });
    } catch (error) {
      return next(error);
    }
  }

  async function resendVerification(req, res, next) {
    try {
      // Resolved from the session when there is one, and otherwise from what was
      // typed — but the answer is the same either way, so this cannot be used to
      // probe for accounts.
      const account = req.currentUser || (await accounts.findByIdentifier(req.body.identifier));
      if (account && !account.emailVerified) {
        await accounts.issueEmailVerification(account);
      }
      return view(res, "check-email", {
        title: "Check your email",
        heading: "Check your email",
        message: "If that account needs confirming, a new link is on its way."
      });
    } catch (error) {
      return next(error);
    }
  }

  // --- The account page ----------------------------------------------------

  /**
   * The locals the account page needs, built in one place.
   *
   * Both the page and every failed form submission render the same template, and
   * assembling this twice is how the two drift — the session list in particular
   * has to carry which session is the current one, or the page offers to sign the
   * user out of the browser they are looking at it in.
   */
  async function accountLocals(req, { error = null, notice = null } = {}) {
    const [grants, browserSessions] = await Promise.all([
      provider.listGrantsForUser(req.currentUser.id),
      sessions.listForUser(req.currentUser.id)
    ]);
    return {
      title: "Your account",
      account: req.currentUser,
      grants,
      sessions: browserSessions.map((session) => ({
        ...session,
        current: session.id === req.session?.id
      })),
      minPasswordLength: accounts.minPasswordLength,
      error,
      notice
    };
  }

  async function accountPage(req, res, next) {
    try {
      return view(res, "account", await accountLocals(req, { notice: req.query.notice || null }));
    } catch (error) {
      return next(error);
    }
  }

  async function updateProfile(req, res, next) {
    try {
      await accounts.updateProfile({
        userId: req.currentUser.id,
        name: req.body.name,
        username: req.body.username
      });
      return res.redirect("/account?notice=profile-updated");
    } catch (error) {
      if (error?.statusCode && error.statusCode < 500) {
        return res
          .status(error.statusCode)
          .render("account", { branding, ...(await accountLocals(req, { error: error.message })) });
      }
      return next(error);
    }
  }

  async function changePassword(req, res, next) {
    try {
      const result = await accounts.changePassword({
        userId: req.currentUser.id,
        currentPassword: req.body.current_password,
        newPassword: req.body.new_password,
        ipAddress: req.ip,
        userAgent: req.get("user-agent")
      });
      if (!result.ok) {
        return res.status(400).render("notice", {
          branding,
          title: "Password not changed",
          heading: "Your password was not changed",
          message:
            result.reason === "bad_password"
              ? "The current password you entered is not correct."
              : "That password could not be used.",
          actionUrl: "/account",
          actionLabel: "Back to your account"
        });
      }
      // The change revoked every session. Signing in again keeps this browser
      // usable without weakening that.
      await req.signIn({ userId: req.currentUser.id });
      return res.redirect("/account?notice=password-changed");
    } catch (error) {
      if (error?.statusCode && error.statusCode < 500) {
        return res.status(error.statusCode).render("notice", {
          branding,
          title: "Password not changed",
          heading: "Your password was not changed",
          message: error.message,
          actionUrl: "/account",
          actionLabel: "Back to your account"
        });
      }
      return next(error);
    }
  }

  /**
   * Withdraws an application's access.
   *
   * This is the route the previous implementation never mounted, which meant a
   * user could grant access and had no way to take it back. Revoking here drops
   * the grant, every token, and the client's session, and notifies it.
   */
  async function revokeGrant(req, res, next) {
    try {
      await provider.revokeGrant({
        userId: req.currentUser.id,
        clientId: req.body.client_id,
        reason: "user_revoked",
        actorUserId: req.currentUser.id
      });
      return res.redirect("/account?notice=access-revoked");
    } catch (error) {
      return next(error);
    }
  }

  /** Ends one other browser session, or all of them. */
  async function revokeSession(req, res, next) {
    try {
      const sessionId = String(req.body.session_id || "");
      if (sessionId === "all") {
        const all = await sessions.listForUser(req.currentUser.id);
        for (const session of all) {
          if (session.id === req.session?.id) continue;
          await provider.endSessions({ sessionId: session.id, userId: req.currentUser.id, reason: "user_revoked" });
          await sessions.revoke({ sessionId: session.id, userId: req.currentUser.id });
        }
        return res.redirect("/account?notice=sessions-ended");
      }

      // Scoped to the caller's own id, so one user cannot end another's session
      // by guessing an identifier.
      await provider.endSessions({ sessionId, userId: req.currentUser.id, reason: "user_revoked" });
      const result = await sessions.revoke({ sessionId, userId: req.currentUser.id });
      if (result.revoked && sessionId === req.session?.id) return res.redirect("/");
      return res.redirect("/account?notice=sessions-ended");
    } catch (error) {
      return next(error);
    }
  }

  // --- The applications a user registered -----------------------------------

  async function clientsPage(req, res, next) {
    try {
      const owned = await clients.listForOwner(req.currentUser.id);
      return view(res, "clients", {
        title: "Your applications",
        clients: owned,
        scopes: config.customScopes,
        allowUserRegistration: config.clients.allowUserRegistration !== false,
        requireApproval: config.clients.requireApproval !== false,
        error: null,
        notice: req.query.notice || null,
        created: null
      });
    } catch (error) {
      return next(error);
    }
  }

  async function submitClient(req, res, next) {
    try {
      const result = await clients.submit({
        ownerUserId: req.currentUser.id,
        name: req.body.name,
        description: req.body.description,
        clientType: req.body.client_type,
        redirectUris: String(req.body.redirect_uris || "").split(/[\s,]+/).filter(Boolean),
        postLogoutRedirectUris: String(req.body.post_logout_redirect_uris || "")
          .split(/[\s,]+/)
          .filter(Boolean),
        clientUri: req.body.client_uri,
        scopes: req.body.scope,
        grantTypes: String(req.body.grant_types || "authorization_code").split(/[\s,]+/).filter(Boolean),
        tokenEndpointAuthMethod: req.body.token_endpoint_auth_method
      });

      const owned = await clients.listForOwner(req.currentUser.id);
      // The secret is shown exactly once, here. Only its hash is stored, so this
      // page cannot be revisited to read it again.
      return view(res, "clients", {
        title: "Your applications",
        clients: owned,
        scopes: config.customScopes,
        allowUserRegistration: config.clients.allowUserRegistration !== false,
        requireApproval: config.clients.requireApproval !== false,
        error: null,
        notice: null,
        created: { client: result.client, clientSecret: result.clientSecret }
      });
    } catch (error) {
      if (error?.statusCode && error.statusCode < 500) {
        const owned = await clients.listForOwner(req.currentUser.id);
        return res.status(error.statusCode).render("clients", {
          branding,
          title: "Your applications",
          clients: owned,
          scopes: config.customScopes,
          allowUserRegistration: config.clients.allowUserRegistration !== false,
          requireApproval: config.clients.requireApproval !== false,
          error: error.message,
          notice: null,
          created: null
        });
      }
      return next(error);
    }
  }

  async function rotateClientSecret(req, res, next) {
    try {
      const clientId = String(req.body.client_id || "");
      const owned = await clients.listForOwner(req.currentUser.id);
      // Ownership is checked here rather than trusted from the form.
      if (!owned.some((client) => client.clientId === clientId)) {
        throw appError("That application is not yours", 403);
      }
      const result = await clients.rotateSecret({ clientId, actorUserId: req.currentUser.id });
      return view(res, "clients", {
        title: "Your applications",
        clients: await clients.listForOwner(req.currentUser.id),
        scopes: config.customScopes,
        allowUserRegistration: config.clients.allowUserRegistration !== false,
        requireApproval: config.clients.requireApproval !== false,
        error: null,
        notice: null,
        created: { client: result.client, clientSecret: result.clientSecret }
      });
    } catch (error) {
      return next(error);
    }
  }

  async function deleteClient(req, res, next) {
    try {
      const clientId = String(req.body.client_id || "");
      const owned = await clients.listForOwner(req.currentUser.id);
      if (!owned.some((client) => client.clientId === clientId)) {
        throw appError("That application is not yours", 403);
      }
      await clients.remove({ clientId, actorUserId: req.currentUser.id });
      return res.redirect("/account/applications?notice=application-deleted");
    } catch (error) {
      return next(error);
    }
  }

  /** The landing page: what this server is and where to go. */
  function homePage(req, res) {
    return view(res, "home", {
      title: branding.serviceName,
      issuer: config.issuer,
      account: req.currentUser,
      registrationEnabled: accounts.registrationEnabled
    });
  }

  return {
    accountPage,
    changePassword,
    clientsPage,
    deleteClient,
    forgotPasswordPage,
    homePage,
    loginPage,
    logout,
    registerPage,
    resendVerification,
    resetPasswordPage,
    revokeGrant,
    revokeSession,
    rotateClientSecret,
    submitClient,
    submitForgotPassword,
    submitLogin,
    submitRegister,
    submitResetPassword,
    updateProfile,
    verifyEmail
  };
}

module.exports = { createAccountController, safeNext };

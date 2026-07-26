"use strict";

// The operator's surface.
//
// This exists because `OAUTH_CLIENT_REQUIRE_APPROVAL` defaults to on: a client
// submitted through the account pages starts PENDING and cannot be used until
// someone approves it. Without this page that default would be a dead end, and
// the alternative — defaulting approval off — would let any account with a login
// register a working client on the issuer.
//
// Approving a confidential client mints its secret, and that secret is shown
// exactly once, here. Only its hash is stored, so this page cannot be revisited
// to read it: an operator who loses it rotates the secret instead.

function createAdminController({ config, accounts, clients, logger = console }) {
  const branding = config.branding;

  async function clientsPage(req, res, next) {
    try {
      const status = String(req.query.status || "");
      const { clients: list, total } = await clients.listAll({ status });
      return res.render("admin-clients", {
        branding,
        title: "Applications",
        clients: list,
        total,
        status,
        statuses: Object.values(clients.STATUS),
        notice: req.query.notice || null,
        created: null
      });
    } catch (error) {
      return next(error);
    }
  }

  async function approveClient(req, res, next) {
    try {
      const result = await clients.approve({
        clientId: req.body.client_id,
        actorUserId: req.currentUser.id
      });
      const { clients: list, total } = await clients.listAll({ status: "" });
      return res.render("admin-clients", {
        branding,
        title: "Applications",
        clients: list,
        total,
        status: "",
        statuses: Object.values(clients.STATUS),
        notice: null,
        // Shown once. A public client has no secret, so this is null for one.
        created: result.clientSecret ? { client: result.client, clientSecret: result.clientSecret } : null
      });
    } catch (error) {
      if (error?.statusCode && error.statusCode < 500) {
        return res.status(error.statusCode).render("notice", {
          branding,
          title: "Not approved",
          heading: "That application was not approved",
          message: error.message,
          actionUrl: "/admin/applications",
          actionLabel: "Back to applications"
        });
      }
      return next(error);
    }
  }

  /**
   * Rejects or disables a client. Both stop it working immediately — the service
   * revokes its refresh tokens and per-client sessions — which is the point: a
   * client left able to refresh for a month is not disabled.
   */
  async function setClientStatus(req, res, next) {
    try {
      await clients.setStatus({
        clientId: req.body.client_id,
        status: req.body.status,
        actorUserId: req.currentUser.id
      });
      return res.redirect("/admin/applications?notice=status-changed");
    } catch (error) {
      if (error?.statusCode && error.statusCode < 500) {
        return res.status(error.statusCode).render("notice", {
          branding,
          title: "Not changed",
          heading: "That application was not changed",
          message: error.message,
          actionUrl: "/admin/applications",
          actionLabel: "Back to applications"
        });
      }
      return next(error);
    }
  }

  async function deleteClient(req, res, next) {
    try {
      await clients.remove({ clientId: req.body.client_id, actorUserId: req.currentUser.id });
      return res.redirect("/admin/applications?notice=application-deleted");
    } catch (error) {
      return next(error);
    }
  }

  async function usersPage(req, res, next) {
    try {
      const query = String(req.query.q || "");
      const { accounts: users, total } = await accounts.list({ query });
      return res.render("admin-users", {
        branding,
        title: "Accounts",
        users,
        total,
        query,
        roles: Object.values(accounts.ROLE),
        statuses: Object.values(accounts.STATUS),
        notice: req.query.notice || null
      });
    } catch (error) {
      return next(error);
    }
  }

  /**
   * Disables or re-enables an account.
   *
   * Refused on the operator's own account: locking yourself out of the only
   * administrative surface is not recoverable through the UI.
   */
  async function setUserStatus(req, res, next) {
    try {
      const userId = String(req.body.user_id || "");
      if (userId === req.currentUser.id) {
        return res.status(400).render("notice", {
          branding,
          title: "Not changed",
          heading: "You cannot change your own account here",
          message: "Ask another administrator, so nobody locks themselves out.",
          actionUrl: "/admin/users",
          actionLabel: "Back to accounts"
        });
      }
      await accounts.setStatus({
        userId,
        status: req.body.status,
        reason: req.body.reason,
        actorUserId: req.currentUser.id
      });
      return res.redirect("/admin/users?notice=status-changed");
    } catch (error) {
      if (error?.statusCode && error.statusCode < 500) {
        return res.status(error.statusCode).render("notice", {
          branding,
          title: "Not changed",
          heading: "That account was not changed",
          message: error.message,
          actionUrl: "/admin/users",
          actionLabel: "Back to accounts"
        });
      }
      return next(error);
    }
  }

  async function setUserRole(req, res, next) {
    try {
      const userId = String(req.body.user_id || "");
      if (userId === req.currentUser.id) {
        return res.status(400).render("notice", {
          branding,
          title: "Not changed",
          heading: "You cannot change your own role",
          message: "Ask another administrator, so the server is never left without one.",
          actionUrl: "/admin/users",
          actionLabel: "Back to accounts"
        });
      }
      await accounts.setRole({ userId, role: req.body.role, actorUserId: req.currentUser.id });
      return res.redirect("/admin/users?notice=role-changed");
    } catch (error) {
      if (error?.statusCode && error.statusCode < 500) {
        return res.status(error.statusCode).render("notice", {
          branding,
          title: "Not changed",
          heading: "That account was not changed",
          message: error.message,
          actionUrl: "/admin/users",
          actionLabel: "Back to accounts"
        });
      }
      return next(error);
    }
  }

  return {
    approveClient,
    clientsPage,
    deleteClient,
    setClientStatus,
    setUserRole,
    setUserStatus,
    usersPage
  };
}

module.exports = { createAdminController };

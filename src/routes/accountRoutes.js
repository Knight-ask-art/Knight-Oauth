"use strict";

const express = require("express");

// The browser surface: signing up, signing in, and managing what has access.
//
// Every route that changes something is a POST, and every POST goes through the
// CSRF middleware mounted in app.js. That matters most for the two routes that
// take access away — revoking a grant and ending a session — because a working
// cross-site GET there would let any page sign a user out of their applications.
//
// `requireAuth` is applied per route rather than to the whole router: the
// sign-in, registration, and recovery pages must stay reachable to someone with
// no session, and mounting the guard broadly and then punching holes in it is
// how a page ends up unprotected by accident.

function createAccountRoutes({ controller, external, requireAuth }) {
  const router = express.Router();

  router.get("/", controller.homePage);

  // --- Registration, sign-in, sign-out --------------------------------------
  router.get("/register", controller.registerPage);
  router.post("/register", controller.submitRegister);
  router.get("/login", controller.loginPage);
  router.post("/login", controller.submitLogin);
  router.post("/logout", controller.logout);

  // --- Recovery and verification --------------------------------------------
  router.get("/forgot-password", controller.forgotPasswordPage);
  router.post("/forgot-password", controller.submitForgotPassword);
  router.get("/reset-password", controller.resetPasswordPage);
  router.post("/reset-password", controller.submitResetPassword);
  // A GET, because it is a link in an email. The token is single-use and short
  // lived, which is what makes that acceptable.
  router.get("/verify-email", controller.verifyEmail);
  router.post("/verify-email/resend", controller.resendVerification);

  // --- External identity providers ------------------------------------------
  // Mounted only when a provider is configured, so an unconfigured deployment
  // has no such route rather than a route that always fails.
  if (external) {
    router.get("/login/external/:provider", external.start);
    router.get("/login/external/:provider/callback", external.callback);
    router.post("/account/external/unlink", requireAuth, external.unlink);
  }

  // --- The account page ------------------------------------------------------
  router.get("/account", requireAuth, controller.accountPage);
  router.post("/account/profile", requireAuth, controller.updateProfile);
  router.post("/account/password", requireAuth, controller.changePassword);
  // Withdrawing an application's access, and ending a session on another device.
  router.post("/account/grants/revoke", requireAuth, controller.revokeGrant);
  router.post("/account/sessions/revoke", requireAuth, controller.revokeSession);

  // --- Applications the user registered --------------------------------------
  router.get("/account/applications", requireAuth, controller.clientsPage);
  router.post("/account/applications", requireAuth, controller.submitClient);
  router.post("/account/applications/rotate-secret", requireAuth, controller.rotateClientSecret);
  router.post("/account/applications/delete", requireAuth, controller.deleteClient);

  return router;
}

module.exports = { createAccountRoutes };

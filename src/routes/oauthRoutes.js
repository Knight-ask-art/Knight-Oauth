"use strict";

const express = require("express");

// The protocol surface.
//
// The paths here are the ones published in discovery metadata, so they are part
// of this server's contract with every client that ever configures itself
// against it: changing one breaks deployed relying parties that cached the
// document. They are listed in the same order as the metadata that advertises
// them, so the two can be read side by side.
//
// Method choices follow the specifications rather than convention:
//
//   * /authorize accepts GET and POST (OIDC Core section 3.1.2.1).
//   * /token, /introspect, /revoke are POST only. A GET would put credentials in
//     a URL, and RFC 6749 section 3.2 requires POST regardless.
//   * /userinfo accepts GET and POST (OIDC Core section 5.3.1).
//   * OPTIONS on the endpoints a browser-based client reaches is answered so a
//     CORS preflight does not fail before the real request is made.

function createOAuthRoutes({ controller }) {
  const router = express.Router();

  // --- Authorization -------------------------------------------------------
  router.get("/oauth2/authorize", controller.authorize);
  router.post("/oauth2/authorize", controller.authorize);
  // Where the login and consent pages return to. Not advertised: it is internal
  // to this server's own flow, and the request is re-evaluated on arrival.
  router.get("/oauth2/authorize/continue", controller.continueAuthorization);

  router.get("/oauth2/consent", controller.consentPage);
  router.post("/oauth2/consent", controller.submitConsent);

  // --- Token and token-adjacent endpoints ----------------------------------
  router.post("/oauth2/token", controller.token);
  router.get("/oauth2/userinfo", controller.userinfo);
  router.post("/oauth2/userinfo", controller.userinfo);
  router.post("/oauth2/introspect", controller.introspect);
  router.post("/oauth2/revoke", controller.revoke);

  // --- Dynamic client registration (RFC 7591) and management (RFC 7592) -----
  router.post("/oauth2/register", controller.register);
  router.get("/oauth2/register/:clientId", controller.readRegistration);
  router.put("/oauth2/register/:clientId", controller.updateRegistration);
  router.delete("/oauth2/register/:clientId", controller.deleteRegistration);

  // --- RP-initiated logout -------------------------------------------------
  router.get("/oauth2/logout", controller.logoutPage);
  router.post("/oauth2/logout", controller.submitLogout);

  return router;
}

module.exports = { createOAuthRoutes };

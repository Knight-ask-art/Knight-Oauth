"use strict";

const express = require("express");

// The operator's routes.
//
// `requireAdmin` is applied to the router rather than per route, which is the
// opposite of accountRoutes and deliberately so: there is no page here that
// should ever be reachable without the ADMIN role, so the guard belongs where a
// route added later inherits it automatically.

function createAdminRoutes({ controller, requireAdmin }) {
  const router = express.Router();

  router.use("/admin", requireAdmin);

  router.get("/admin", (req, res) => res.redirect("/admin/applications"));

  router.get("/admin/applications", controller.clientsPage);
  router.post("/admin/applications/approve", controller.approveClient);
  router.post("/admin/applications/status", controller.setClientStatus);
  router.post("/admin/applications/delete", controller.deleteClient);

  router.get("/admin/users", controller.usersPage);
  router.post("/admin/users/status", controller.setUserStatus);
  router.post("/admin/users/role", controller.setUserRole);

  return router;
}

module.exports = { createAdminRoutes };

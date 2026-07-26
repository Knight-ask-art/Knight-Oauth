"use strict";

const { buildErrorRedirect } = require("../lib/uri");
const { invalidRequest, invalidToken } = require("../lib/errors");

// The protocol endpoints.
//
// Two conventions here exist for interoperability rather than tidiness:
//
//   * Every JSON response carries `Cache-Control: no-store`. RFC 6749 section
//     5.1 requires it on the token endpoint, and a cached token response is a
//     token handed to the next user of a shared cache.
//
//   * An authorization error is delivered by redirect only when the client and
//     its redirect_uri both validated. Otherwise it is rendered here. Getting
//     that backwards turns the authorization endpoint into an open redirect,
//     so the decision is read from the error rather than guessed.

const REQUEST_PARAM = "request";

function noStore(res) {
  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");
  return res;
}

/** Reads a bearer token from the header, or the body/query per OIDC Core 5.3.1. */
function bearerToken(req) {
  const header = String(req.get("authorization") || "");
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (match) return match[1].trim();
  // Section 5.3.1 permits the form-encoded body; a GET with the token in the
  // query string is not accepted, because it lands in server logs and history.
  if (req.method === "POST" && req.body?.access_token) return String(req.body.access_token).trim();
  return "";
}

function createOAuthController({ config, provider, clients, scopeRegistry, accounts, logger = console }) {
  const branding = config.branding;

  function renderProtocolError(res, error, status = 400) {
    return res.status(status).render("error", {
      title: "Authorization error",
      heading: "This request could not be completed",
      message: error?.message || "The request was not valid.",
      code: error?.code || null,
      status
    });
  }

  // --- Discovery -----------------------------------------------------------

  async function openidConfiguration(req, res, next) {
    try {
      // Cacheable, unlike everything token-bearing: this is public metadata a
      // client is expected to fetch often, and letting it be cached briefly is
      // what keeps that cheap.
      res.set("Cache-Control", "public, max-age=300");
      res.json(await provider.discoveryDocument());
    } catch (error) {
      next(error);
    }
  }

  async function authorizationServerMetadata(req, res, next) {
    try {
      res.set("Cache-Control", "public, max-age=300");
      res.json(await provider.authorizationServerMetadata());
    } catch (error) {
      next(error);
    }
  }

  async function jwks(req, res, next) {
    try {
      res.set("Cache-Control", "public, max-age=300");
      // The registered media type for a JWK Set (RFC 7517 section 8.5). Some
      // libraries check it.
      res.type("application/jwk-set+json");
      res.json(await provider.jwks());
    } catch (error) {
      next(error);
    }
  }

  // --- Authorization endpoint ---------------------------------------------

  /**
   * GET and POST /oauth2/authorize.
   *
   * POST is supported because OIDC Core section 3.1.2.1 allows it, and a client
   * with a long request sends it that way.
   */
  async function authorize(req, res, next) {
    const params = req.method === "POST" ? req.body : req.query;
    let request;
    try {
      request = await provider.parseAuthorizationRequest(params);
    } catch (error) {
      // Only redirect when the redirect_uri itself was validated.
      if (error?.redirectValidated && error.redirectUri) {
        return res.redirect(
          buildErrorRedirect(error.redirectUri, {
            error: error.code || "invalid_request",
            errorDescription: error.message,
            state: error.state,
            issuer: config.issuer
          })
        );
      }
      if (error?.isProtocolError) return renderProtocolError(res, error, error.statusCode || 400);
      return next(error);
    }

    try {
      const decision = await provider.resolveAuthorization({
        request,
        account: req.currentUser,
        session: req.session
      });

      const requestToken = await provider.persistAuthorizationRequest(request);

      if (decision.action === "login") {
        // The parked request travels as an opaque token in the URL, so nothing
        // about the client or the scopes can be tampered with between here and
        // consent.
        const next = `/oauth2/authorize/continue?${REQUEST_PARAM}=${encodeURIComponent(requestToken)}`;
        const loginUrl = new URL("/login", config.publicBaseUrl);
        loginUrl.searchParams.set("next", next);
        if (request.loginHint) loginUrl.searchParams.set("login_hint", request.loginHint);
        // prompt=login means re-authenticate even though a session exists.
        if (decision.reason === "prompt_login" || decision.reason === "max_age") {
          loginUrl.searchParams.set("reauthenticate", "1");
        }
        return res.redirect(loginUrl.pathname + loginUrl.search);
      }

      if (decision.action === "consent") {
        return res.redirect(`/oauth2/consent?${REQUEST_PARAM}=${encodeURIComponent(requestToken)}`);
      }

      const { redirectUrl } = await provider.completeAuthorization({
        requestToken,
        account: req.currentUser,
        session: req.session
      });
      return res.redirect(redirectUrl);
    } catch (error) {
      // Past validation, an error is the client's to receive.
      if (error?.isProtocolError) {
        return res.redirect(
          buildErrorRedirect(request.redirectUri, {
            error: error.code,
            errorDescription: error.message,
            state: request.state,
            issuer: config.issuer
          })
        );
      }
      return next(error);
    }
  }

  /**
   * Where login returns to. The parked request is re-evaluated rather than
   * trusted: the user who signed in may not be the one the request was parked
   * for, and the session may still fail `max_age`.
   */
  async function continueAuthorization(req, res, next) {
    try {
      const requestToken = String(req.query[REQUEST_PARAM] || "");
      const request = await provider.loadAuthorizationRequest(requestToken);
      if (!request) {
        return renderProtocolError(
          res,
          invalidRequest("This sign-in request has expired. Start again from the application."),
          400
        );
      }

      const decision = await provider.resolveAuthorization({
        request,
        account: req.currentUser,
        session: req.session
      });

      if (decision.action === "login") {
        const next = `/oauth2/authorize/continue?${REQUEST_PARAM}=${encodeURIComponent(requestToken)}`;
        return res.redirect(`/login?next=${encodeURIComponent(next)}`);
      }
      if (decision.action === "consent") {
        return res.redirect(`/oauth2/consent?${REQUEST_PARAM}=${encodeURIComponent(requestToken)}`);
      }

      const { redirectUrl } = await provider.completeAuthorization({
        requestToken,
        account: req.currentUser,
        session: req.session
      });
      return res.redirect(redirectUrl);
    } catch (error) {
      if (error?.isProtocolError) return renderProtocolError(res, error, error.statusCode || 400);
      return next(error);
    }
  }

  // --- Consent -------------------------------------------------------------

  async function consentPage(req, res, next) {
    try {
      const requestToken = String(req.query[REQUEST_PARAM] || "");
      const request = await provider.loadAuthorizationRequest(requestToken);
      if (!request) {
        return renderProtocolError(res, invalidRequest("This sign-in request has expired"), 400);
      }
      if (!req.currentUser) {
        const next = `/oauth2/consent?${REQUEST_PARAM}=${encodeURIComponent(requestToken)}`;
        return res.redirect(`/login?next=${encodeURIComponent(next)}`);
      }

      const grant = await provider.findActiveGrant({
        userId: req.currentUser.id,
        clientId: request.client.clientId
      });

      return res.render("consent", {
        title: `Authorize ${request.client.name}`,
        branding,
        requestToken,
        client: request.client,
        // Human-readable descriptions come from the scope registry, so a
        // deployment's own scopes get a real description rather than a raw name.
        permissions: scopeRegistry.describeForConsent(request.scopes),
        scopes: request.scopes,
        account: req.currentUser,
        previouslyGranted: Boolean(grant),
        // Shown so the user can see where the result is going. This is the
        // registered, validated URI, not raw input.
        redirectOrigin: new URL(request.redirectUri).origin
      });
    } catch (error) {
      if (error?.isProtocolError) return renderProtocolError(res, error, error.statusCode || 400);
      return next(error);
    }
  }

  async function submitConsent(req, res, next) {
    try {
      const requestToken = String(req.body[REQUEST_PARAM] || "");
      if (!req.currentUser) return res.redirect("/login");

      if (String(req.body.decision || "") !== "allow") {
        const { redirectUrl } = await provider.denyAuthorization({ requestToken });
        return res.redirect(redirectUrl);
      }

      // Checkbox names arrive as a string when one is ticked and an array when
      // several are. Normalizing here keeps the service from having to know it.
      //
      // An unticked checkbox is absent from the submission entirely, so a user
      // who cleared every box sends no `scope` at all — indistinguishable from a
      // form that offered no choices, which would be read as "approve everything
      // requested". `scope_selection` is the form saying the choice was made
      // here, which turns an empty selection into an empty approval.
      const raw = req.body.scope;
      const chose = Boolean(req.body.scope_selection);
      const approvedScopes =
        raw === undefined ? (chose ? [] : null) : (Array.isArray(raw) ? raw : [raw]).map(String);

      const { redirectUrl } = await provider.completeAuthorization({
        requestToken,
        account: req.currentUser,
        session: req.session,
        approvedScopes
      });
      return res.redirect(redirectUrl);
    } catch (error) {
      if (error?.isProtocolError) return renderProtocolError(res, error, error.statusCode || 400);
      return next(error);
    }
  }

  // --- Token, UserInfo, introspection, revocation --------------------------

  async function token(req, res, next) {
    try {
      const result = await provider.token({ headers: req.headers, body: req.body || {} });
      return noStore(res).json(result);
    } catch (error) {
      return next(error);
    }
  }

  async function userinfo(req, res, next) {
    try {
      const accessToken = bearerToken(req);
      if (!accessToken) {
        // RFC 6750 section 3: a request without credentials gets a bare challenge.
        res.set("WWW-Authenticate", `Bearer realm="${config.issuer}"`);
        throw invalidToken("An access token is required");
      }
      const claims = await provider.userinfo({ accessToken });
      return noStore(res).json(claims);
    } catch (error) {
      return next(error);
    }
  }

  async function introspect(req, res, next) {
    try {
      const result = await provider.introspect({ headers: req.headers, body: req.body || {} });
      return noStore(res).json(result);
    } catch (error) {
      return next(error);
    }
  }

  async function revoke(req, res, next) {
    try {
      await provider.revoke({ headers: req.headers, body: req.body || {} });
      // RFC 7009 section 2.2: an empty 200, whether or not anything was revoked.
      return noStore(res).status(200).end();
    } catch (error) {
      return next(error);
    }
  }

  // --- Dynamic client registration (RFC 7591 / 7592) -----------------------

  async function register(req, res, next) {
    try {
      const { registration } = await clients.registerDynamic({
        metadata: req.body || {},
        authorizationHeader: req.get("authorization")
      });
      // Section 3.2.1: 201 with the client information response. This is the one
      // and only time the secret and the registration access token are returned.
      return noStore(res).status(201).json(registration);
    } catch (error) {
      return next(error);
    }
  }

  async function readRegistration(req, res, next) {
    try {
      const client = await clients.authenticateRegistrationToken({
        clientId: req.params.clientId,
        authorizationHeader: req.get("authorization")
      });
      return noStore(res).json(clients.toRegistrationResponse(client));
    } catch (error) {
      return next(error);
    }
  }

  async function updateRegistration(req, res, next) {
    try {
      const existing = await clients.authenticateRegistrationToken({
        clientId: req.params.clientId,
        authorizationHeader: req.get("authorization")
      });
      const updated = await clients.updateRegistration({
        clientId: existing.clientId,
        metadata: req.body || {}
      });
      return noStore(res).json(clients.toRegistrationResponse(updated));
    } catch (error) {
      return next(error);
    }
  }

  async function deleteRegistration(req, res, next) {
    try {
      const existing = await clients.authenticateRegistrationToken({
        clientId: req.params.clientId,
        authorizationHeader: req.get("authorization")
      });
      await clients.remove({ clientId: existing.clientId, actorUserId: null });
      // RFC 7592 section 2.3: 204 with no body.
      return noStore(res).status(204).end();
    } catch (error) {
      return next(error);
    }
  }

  // --- RP-initiated logout -------------------------------------------------

  /**
   * GET /oauth2/logout (OIDC RP-Initiated Logout 1.0).
   *
   * A GET that ends a session is a CSRF risk, which is why the spec allows an
   * interstitial. Confirmation is shown unless the request carries a valid
   * `id_token_hint`, which proves the client had a real session and is the
   * spec's own basis for skipping the prompt.
   */
  async function logoutPage(req, res, next) {
    try {
      const hint = await provider.readIdTokenHint(req.query.id_token_hint);
      const clientId = hint?.clientId || String(req.query.client_id || "") || null;
      const state = req.query.state ? String(req.query.state) : null;
      const postLogoutRedirectUri = req.query.post_logout_redirect_uri
        ? String(req.query.post_logout_redirect_uri)
        : null;

      const target = await provider.resolveLogoutRedirect({ clientId, postLogoutRedirectUri, state });

      if (!req.currentUser) {
        // Nothing to end; honour the redirect so a client's sign-out flow still
        // completes rather than dead-ending on this page.
        return res.redirect(target || "/");
      }

      // The hint proves the request came from a client the user really had a
      // session with, so no interstitial is needed.
      if (hint && hint.sub === req.currentUser.id) {
        await req.signOut({ reason: "rp_initiated_logout" });
        return res.redirect(target || "/");
      }

      const client = clientId ? await clients.findByClientId(clientId) : null;
      return res.render("logout", {
        title: "Sign out",
        branding,
        clientName: client?.name || null,
        redirectTarget: target,
        // Carried through the form so the POST resolves the same destination.
        // It is re-validated there against what the client registered rather
        // than trusted because this page echoed it.
        clientId,
        postLogoutRedirectUri,
        state,
        account: req.currentUser
      });
    } catch (error) {
      return next(error);
    }
  }

  async function submitLogout(req, res, next) {
    try {
      const target = await provider.resolveLogoutRedirect({
        clientId: req.body.client_id ? String(req.body.client_id) : null,
        postLogoutRedirectUri: req.body.post_logout_redirect_uri
          ? String(req.body.post_logout_redirect_uri)
          : null,
        state: req.body.state ? String(req.body.state) : null
      });
      if (req.currentUser) await req.signOut({ reason: "rp_initiated_logout" });
      return res.redirect(target || "/");
    } catch (error) {
      return next(error);
    }
  }

  /** Health check. Reports the signing key source, which is what usually breaks. */
  async function health(req, res) {
    try {
      const jwksDocument = await provider.jwks();
      return res.json({
        status: "ok",
        issuer: config.issuer,
        keys: jwksDocument.keys.length
      });
    } catch (error) {
      logger.error?.("health check failed", error?.message);
      return res.status(503).json({ status: "unavailable" });
    }
  }

  return {
    authorizationServerMetadata,
    authorize,
    consentPage,
    continueAuthorization,
    deleteRegistration,
    health,
    introspect,
    jwks,
    logoutPage,
    openidConfiguration,
    readRegistration,
    register,
    revoke,
    submitConsent,
    submitLogout,
    token,
    updateRegistration,
    userinfo
  };
}

module.exports = { REQUEST_PARAM, bearerToken, createOAuthController };

"use strict";

// OAuth 2.0 and OpenID Connect error codes are part of the wire protocol, not
// prose. A client branches on `error`, so the code and the HTTP status must be
// deliberate rather than incidental.

/**
 * @param {string} code    an RFC 6749 / OIDC Core error code
 * @param {string} message developer-facing description; safe to show a client
 * @param {number} status  HTTP status
 */
function protocolError(code, message, status = 400) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = status;
  error.isProtocolError = true;
  return error;
}

const invalidRequest = (message) => protocolError("invalid_request", message, 400);
const invalidClient = (message) => protocolError("invalid_client", message, 401);
const invalidGrant = (message) => protocolError("invalid_grant", message, 400);
const invalidScope = (message) => protocolError("invalid_scope", message, 400);
const unauthorizedClient = (message) => protocolError("unauthorized_client", message, 400);
const unsupportedGrantType = (message) => protocolError("unsupported_grant_type", message, 400);
const unsupportedResponseType = (message) => protocolError("unsupported_response_type", message, 400);
const accessDenied = (message, status = 403) => protocolError("access_denied", message, status);
const loginRequired = (message) => protocolError("login_required", message, 401);
const consentRequired = (message) => protocolError("consent_required", message, 400);
const invalidToken = (message) => protocolError("invalid_token", message, 401);
const insufficientScope = (message) => protocolError("insufficient_scope", message, 403);
const serverError = (message) => protocolError("server_error", message, 500);
const temporarilyUnavailable = (message) => protocolError("temporarily_unavailable", message, 503);

// RFC 7591 section 3.2.2 defines its own codes for dynamic client registration,
// and a registration client branches on them the same way a token client
// branches on `invalid_grant`. Answering everything with `invalid_request` tells
// a caller only that something was wrong somewhere in a metadata document that
// may carry twenty fields; these say which kind of thing, which is the whole
// reason the registry has entries for them. Both are 400.
const invalidRedirectUri = (message) => protocolError("invalid_redirect_uri", message, 400);
const invalidClientMetadata = (message) => protocolError("invalid_client_metadata", message, 400);

/**
 * A non-protocol application error, for the account and management surfaces
 * where a rendered page rather than a JSON error body is the right answer.
 */
function appError(message, status = 400) {
  const error = new Error(message);
  error.statusCode = status;
  return error;
}

module.exports = {
  accessDenied,
  appError,
  consentRequired,
  insufficientScope,
  invalidClient,
  invalidClientMetadata,
  invalidGrant,
  invalidRedirectUri,
  invalidRequest,
  invalidScope,
  invalidToken,
  loginRequired,
  protocolError,
  serverError,
  temporarilyUnavailable,
  unauthorizedClient,
  unsupportedGrantType,
  unsupportedResponseType
};

"use strict";
/**
 * auth-header — construct HTTP Authorization headers for the framework's
 * outbound consumers.
 *
 * The previous shape was `_authHeaders(config)` reimplemented in three
 * places (log-stream-webhook, object-store-http-put, object-store-gcs).
 * Each handled the same { auth, token, username, password } shape with
 * subtly different argument names and case semantics. This module
 * collapses the construction.
 *
 * Public API:
 *
 *   bearer(token)                      → { Authorization: "Bearer <token>" }
 *   basic(username, password)          → { Authorization: "Basic <b64>" }
 *   fromConfig({ auth, token, ... })   → headers object for the named auth method
 *
 * fromConfig accepts:
 *
 *   { auth: "none" }                                → {}
 *   { auth: "bearer", token }                       → bearer(token)
 *   { auth: "basic",  username, password }          → basic(username, password)
 *
 * Anything else throws AuthHeaderError. The "header" pass-through mode
 * that consumers used to wedge into _authHeaders is NOT auth-header's job
 * — that's just header merging. Consumers do `Object.assign({}, config.headers)`
 * themselves and combine the two layers at the call site.
 *
 * Why this is a separate primitive vs. a helper inside http-client:
 *   - Some callers (log-stream-local) might emit auth headers without
 *     going through http-client (e.g. signed-URL inputs to a token).
 *   - Keeping it pure-string-construction with no I/O makes it test-only
 *     in 0ms and reusable from non-network contexts.
 */

var { FrameworkError } = require("./framework-error");

class AuthHeaderError extends FrameworkError {
  constructor(message, code) {
    super(message, code || "auth-header/invalid");
    this.name = "AuthHeaderError";
    this.isAuthHeaderError = true;
  }
}

function bearer(token) {
  if (typeof token !== "string" || token.length === 0) {
    throw new AuthHeaderError("bearer: token must be a non-empty string");
  }
  return { Authorization: "Bearer " + token };
}

function basic(username, password) {
  // Accepting empty username + empty password reflects RFC 7617's
  // tolerance — some legacy endpoints want literally "Basic <b64('::')>".
  // We accept the cast to string but reject undefined-as-username
  // (which would silently produce "Basic <b64('undefined:...')>").
  if (username == null) {
    throw new AuthHeaderError("basic: username is required (pass empty string for credential-less basic)");
  }
  var pwd = password == null ? "" : password;
  var b64 = Buffer.from(String(username) + ":" + String(pwd), "utf8").toString("base64");
  return { Authorization: "Basic " + b64 };
}

function fromConfig(config) {
  if (!config || !config.auth || config.auth === "none") return {};
  if (config.auth === "bearer") return bearer(config.token);
  if (config.auth === "basic")  return basic(config.username, config.password);
  throw new AuthHeaderError(
    "unknown auth method '" + config.auth + "' (expected 'none' | 'bearer' | 'basic')",
    "auth-header/unknown-method"
  );
}

module.exports = {
  bearer:           bearer,
  basic:            basic,
  fromConfig:       fromConfig,
  AuthHeaderError:  AuthHeaderError,
};

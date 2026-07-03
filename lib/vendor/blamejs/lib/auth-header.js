// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.authHeader
 * @nav    HTTP
 * @title  Auth Headers
 *
 * @intro
 *   RFC 7235 / RFC 7617 outbound Authorization header construction —
 *   the small, security-aware primitive every framework consumer that
 *   talks to a credentialed HTTP endpoint composes (log-stream-webhook,
 *   object-store-http-put, object-store-gcs, custom outbound clients).
 *
 *   Previously each consumer re-implemented `_authHeaders(config)` with
 *   subtly different argument names and case semantics. This module
 *   collapses the construction so token / credential rules live in one
 *   place: never produce `Basic <b64('undefined:...')>`, always pass
 *   bearer tokens through unmodified, refuse unknown auth methods at
 *   call time rather than silently emitting no header.
 *
 *   Three forms:
 *     - `bearer(token)`               -> { Authorization: "Bearer <token>" }
 *     - `basic(username, password)`   -> { Authorization: "Basic <b64>" }
 *     - `fromConfig({ auth, ... })`   -> dispatch by `auth` field
 *
 *   `fromConfig` accepts `{ auth: "none" }` (returns `{}`),
 *   `{ auth: "bearer", token }`, and `{ auth: "basic", username,
 *   password }`. Anything else throws `AuthHeaderError`. The "raw
 *   header pass-through" mode some consumers wanted is intentionally
 *   NOT this module's job — that's plain header merging at the call
 *   site, kept separate so the auth-header primitive stays pure
 *   string construction with no I/O.
 *
 *   Validation tier: config-time / entry-point. Bad opts throw
 *   synchronously so an operator catches the typo at boot rather than
 *   on the first outbound request.
 *
 * @card
 *   RFC 7235 / RFC 7617 outbound Authorization header construction — the small, security-aware primitive every framework consumer that talks to a credentialed HTTP endpoint composes (log-stream-webhook, object-store-http-put, object-store-gcs, custom outbound clients).
 */

var { FrameworkError } = require("./framework-error");

class AuthHeaderError extends FrameworkError {
  constructor(message, code) {
    super(message, code || "auth-header/invalid");
    this.name = "AuthHeaderError";
    this.isAuthHeaderError = true;
  }
}

/**
 * @primitive b.authHeader.bearer
 * @signature b.authHeader.bearer(token)
 * @since     0.5.0
 * @related   b.authHeader.basic, b.authHeader.fromConfig
 *
 * Build an `{ Authorization: "Bearer <token>" }` header object from a
 * non-empty string token. The token is passed through verbatim — no
 * encoding, no whitespace trimming — because RFC 6750 b64token tokens
 * are already in the legal Authorization-value alphabet. Empty / null /
 * non-string input throws `AuthHeaderError`.
 *
 * @example
 *   var headers = b.authHeader.bearer("eyJhbGciOiJIUzI1NiJ9.payload.sig");
 *   // → { Authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" }
 */
function bearer(token) {
  if (typeof token !== "string" || token.length === 0) {
    throw new AuthHeaderError("bearer: token must be a non-empty string");
  }
  return { Authorization: "Bearer " + token };
}

/**
 * @primitive b.authHeader.basic
 * @signature b.authHeader.basic(username, password)
 * @since     0.5.0
 * @related   b.authHeader.bearer, b.authHeader.fromConfig
 *
 * Build an `{ Authorization: "Basic <base64(user:pass)>" }` header per
 * RFC 7617. Empty username + empty password is accepted (some legacy
 * endpoints want literal `Basic <b64('::')>`), but `null` / `undefined`
 * username throws `AuthHeaderError` to refuse the silent-bug shape
 * `Basic <b64('undefined:...')>`. `password === null` is normalized to
 * an empty string.
 *
 * @example
 *   var headers = b.authHeader.basic("svc-account", "s3cr3t");
 *   // → { Authorization: "Basic c3ZjLWFjY291bnQ6czNjcjN0" }
 */
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

/**
 * @primitive b.authHeader.fromConfig
 * @signature b.authHeader.fromConfig(config)
 * @since     0.5.0
 * @related   b.authHeader.bearer, b.authHeader.basic
 *
 * Dispatch by the `auth` field on a consumer config object — the
 * shared shape every framework outbound consumer accepts. Returns an
 * empty object for `auth: "none"` (or a missing config), routes to
 * `bearer(token)` for `auth: "bearer"`, and to `basic(username,
 * password)` for `auth: "basic"`. Any other `auth` value throws
 * `AuthHeaderError` with the `auth-header/unknown-method` code so a
 * typo doesn't silently produce an unauthenticated request.
 *
 * @opts
 *   {
 *     auth?:     "none" | "bearer" | "basic",  // default: "none"
 *     token?:    string,                       // required when auth === "bearer"
 *     username?: string,                       // required when auth === "basic"
 *     password?: string,                       // optional when auth === "basic"
 *   }
 *
 * @example
 *   var headers = b.authHeader.fromConfig({
 *     auth:  "bearer",
 *     token: "eyJhbGciOiJIUzI1NiJ9.payload.sig",
 *   });
 *   // → { Authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" }
 */
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

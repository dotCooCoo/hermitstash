// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.auth.ciba
 * @nav        Identity
 * @title      CIBA (decoupled auth)
 * @order      330
 * @card       OpenID Connect Client-Initiated Backchannel Authentication
 *             1.0 — the "decoupled" auth flow where the relying party
 *             authenticates the user out-of-band (push notification to a
 *             phone, kiosk-driven sign-in on a separate channel) and
 *             tokens are delivered via poll / ping / push.
 *
 * @intro
 *   CIBA is the OpenID Connect spec for flows where the device that
 *   initiates the authentication isn't the device that completes it.
 *   Canonical use cases: a call-center agent confirming a customer
 *   identity by pushing a prompt to the customer's phone; a TPM-less
 *   POS terminal asking the user's wallet to authorize a purchase; an
 *   IVR step-up that requires the customer's mobile-app fingerprint.
 *
 *   The relying party (RP):
 *     1. POSTs `auth_req_id` request to the IdP's
 *        `backchannel_authentication_endpoint` with login_hint /
 *        login_hint_token / id_token_hint identifying the user, plus
 *        scope / acr_values / requested_expiry / binding_message.
 *     2. Receives `{ auth_req_id, expires_in, interval }`.
 *     3. Waits for token delivery via the operator-chosen mode:
 *
 *        - **poll**: RP polls /token with grant_type=
 *          urn:openid:params:grant-type:ciba + auth_req_id every
 *          `interval` seconds; gets `authorization_pending`,
 *          `slow_down`, or the tokens.
 *        - **ping**: IdP POSTs `{ auth_req_id }` to the RP's
 *          `client_notification_endpoint`; the RP's handler then
 *          calls /token to fetch.
 *        - **push**: IdP POSTs `{ auth_req_id, access_token,
 *          id_token, refresh_token, ... }` directly. The
 *          `client_notification_token` registered with the IdP
 *          authenticates each callback.
 *
 *   This module provides:
 *
 *     b.auth.ciba.client.create({ ... })
 *       .startAuthentication({ loginHint, scope, bindingMessage, ... })
 *       .pollToken({ authReqId })
 *       .receivePingNotification(req)        // ping mode handler
 *       .receivePushNotification(req)        // push mode handler
 *
 *   Composes b.auth.oauth for client_assertion / token-endpoint
 *   plumbing (so JWT-bearer client auth, mTLS client auth, and PAR
 *   alongside CIBA all share one set of audited credentials).
 */

var C            = require("../constants");
var lazyRequire  = require("../lazy-require");
var validateOpts = require("../validate-opts");
var safeJson     = require("../safe-json");
var safeUrl      = require("../safe-url");
var { generateToken, sha3Hash, timingSafeEqual } = require("../crypto");
var { AuthError } = require("../framework-error");

var httpClient    = lazyRequire(function () { return require("../http-client"); });
var oauth         = lazyRequire(function () { return require("./oauth"); });
var audit         = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var emit = validateOpts.makeNamespacedEmitters("auth.ciba", { audit: audit, observability: observability });

var DEFAULT_INTERVAL_SEC = 5;
var DEFAULT_EXPIRES_SEC  = 600;
var MAX_BINDING_MSG_LEN  = 200;
var MAX_RESPONSE_BYTES   = 64 * 1024;
var MIN_INTERVAL_SEC     = 1;
var MAX_INTERVAL_SEC     = 300;                                                                  // allow:raw-time-literal — 300s polling-interval ceiling; time-derived literal, C.TIME.seconds(300) applies, retained pending migration

var _emitAudit  = emit.audit;
var _emitMetric = emit.metric;

/**
 * @primitive b.auth.ciba.client.create
 * @signature b.auth.ciba.client.create(opts)
 * @since     0.8.62
 * @status    stable
 * @related   b.auth.oid4vci.issuer.create
 *
 * Build a CIBA-aware OIDC RP. Operators wire the resulting object's
 * methods onto routes that drive the decoupled-auth flow.
 *
 * @opts
 *   {
 *     issuer:                     string,        // OIDC issuer URL — required
 *     clientId:                   string,        // RP client_id — required
 *     clientAuth:                 "secret"|"jwt"|"mtls",   // token-endpoint auth
 *     clientSecret?:              string,        // when clientAuth = "secret"
 *     clientAssertionSigner?:     fn(payload)→jwt, // when clientAuth = "jwt"
 *     backchannelAuthenticationEndpoint?: string, // optional — discovered when omitted
 *     tokenEndpoint?:             string,        // optional — discovered
 *     scope?:                     string|string[],
 *     deliveryMode:               "poll"|"ping"|"push",
 *     clientNotificationToken?:   string,        // fixed token RP mints once + registers with IdP
 *     httpClientOpts?:            object,        // options merged INTO each request
 *     http?:                      { client?: object, allowedHosts?: string[] },  // the client each request is made THROUGH, and its host pin
 *     allowHttp?:                 boolean,
 *   }
 *
 * @example
 *   var ciba = b.auth.ciba.client.create({
 *     issuer:       "https://idp.example.com",
 *     clientId:     "rp-1",
 *     clientAuth:   "secret",
 *     clientSecret: process.env.CIBA_CLIENT_SECRET,
 *     scope:        ["openid", "profile"],
 *     deliveryMode: "poll",
 *   });
 *   var ticket = await ciba.startAuthentication({
 *     loginHint:      "alice@example.com",
 *     bindingMessage: "Authorize wire transfer of $4,200",
 *     acrValues:      ["urn:mace:incommon:iap:silver"],
 *   });
 *   // → { authReqId, expiresIn, interval }
 *   var tokens = await ciba.pollToken({ authReqId: ticket.authReqId });
 *   // → { accessToken, idToken, ... } once user approves
 */
function create(opts) {
  validateOpts.requireObject(opts, "auth.ciba.client.create", AuthError);
  validateOpts.requireNonEmptyString(opts.issuer, "auth.ciba.client.create: issuer", AuthError, "auth-ciba/no-issuer");
  validateOpts.requireNonEmptyString(opts.clientId, "auth.ciba.client.create: clientId", AuthError, "auth-ciba/no-client-id");

  var clientAuth = opts.clientAuth || "secret";
  if (["secret", "jwt", "mtls"].indexOf(clientAuth) === -1) {
    throw new AuthError("auth-ciba/bad-client-auth",
      "auth.ciba.client.create: clientAuth must be 'secret' | 'jwt' | 'mtls'");
  }
  if (clientAuth === "secret" && !opts.clientSecret) {
    throw new AuthError("auth-ciba/no-client-secret",
      "auth.ciba.client.create: clientSecret required for clientAuth='secret'");
  }
  if (clientAuth === "jwt" && typeof opts.clientAssertionSigner !== "function") {
    throw new AuthError("auth-ciba/no-assertion-signer",
      "auth.ciba.client.create: clientAssertionSigner required for clientAuth='jwt'");
  }

  var httpOpts = validateOpts.outboundHttpOpts(opts.http, "auth.ciba.client.create",
                                               AuthError, "auth-ciba");

  var deliveryMode = opts.deliveryMode || "poll";
  if (["poll", "ping", "push"].indexOf(deliveryMode) === -1) {
    throw new AuthError("auth-ciba/bad-delivery-mode",
      "auth.ciba.client.create: deliveryMode must be 'poll' | 'ping' | 'push'");
  }

  var inner = oauth().create({
    issuer:                            opts.issuer,
    clientId:                          opts.clientId,
    clientSecret:                      opts.clientSecret,
    redirectUri:                       opts.redirectUri || (opts.issuer + "/__ciba_no_redirect__"),
    scope:                             opts.scope,
    backchannelAuthenticationEndpoint: opts.backchannelAuthenticationEndpoint,
    tokenEndpoint:                     opts.tokenEndpoint,
    httpClient:                        opts.httpClientOpts,
    http:                              opts.http,
    allowHttp:                         opts.allowHttp === true,
    allowInternal:                     opts.allowInternal,
    isOidc:                            true,
  });

  var clientNotificationToken = opts.clientNotificationToken || null;
  if ((deliveryMode === "ping" || deliveryMode === "push") && !clientNotificationToken) {
    throw new AuthError("auth-ciba/no-notification-token",
      "auth.ciba.client.create: clientNotificationToken required for ping/push delivery modes");
  }
  if (clientNotificationToken !== null && clientNotificationToken.length < 32) {
    throw new AuthError("auth-ciba/notification-token-too-short",
      "auth.ciba.client.create: clientNotificationToken must be >= 32 chars " +
      "(generate via b.crypto.generateToken(32) or stronger; CIBA §7.1.2 " +
      "requires opaque hard-to-guess token).");
  }

  function _basicAuthHeader() {
    if (clientAuth !== "secret") return null;
    var pair = encodeURIComponent(opts.clientId) + ":" + encodeURIComponent(opts.clientSecret);
    return "Basic " + Buffer.from(pair, "utf8").toString("base64");
  }

  async function _resolveBackchannelEndpoint() {
    if (opts.backchannelAuthenticationEndpoint) return opts.backchannelAuthenticationEndpoint;
    var disc = await inner.discover();
    if (!disc || typeof disc.backchannel_authentication_endpoint !== "string") {
      throw new AuthError("auth-ciba/no-backchannel-endpoint",
        "ciba: IdP discovery doc has no backchannel_authentication_endpoint " +
        "(set opts.backchannelAuthenticationEndpoint on create() if the IdP doesn't publish it)");
    }
    return disc.backchannel_authentication_endpoint;
  }

  async function _resolveTokenEndpoint() {
    if (opts.tokenEndpoint) return opts.tokenEndpoint;
    var disc = await inner.discover();
    if (!disc || typeof disc.token_endpoint !== "string") {
      throw new AuthError("auth-ciba/no-token-endpoint",
        "ciba: IdP discovery doc has no token_endpoint");
    }
    return disc.token_endpoint;
  }

  function _validateBindingMessage(msg) {
    if (msg === undefined || msg === null) return null;
    if (typeof msg !== "string") {
      throw new AuthError("auth-ciba/bad-binding-message",
        "ciba: bindingMessage must be a string");
    }
    if (msg.length > MAX_BINDING_MSG_LEN) {
      throw new AuthError("auth-ciba/binding-message-too-long",
        "ciba: bindingMessage exceeds " + MAX_BINDING_MSG_LEN + " chars (CIBA §7.1)");
    }
    for (var ci = 0; ci < msg.length; ci += 1) {
      var cc = msg.charCodeAt(ci);
      if (cc <= 0x001f ||
          (cc >= 0x007f && cc <= 0x009f) ||
          (cc >= 0x200b && cc <= 0x200f) ||
          (cc >= 0x202a && cc <= 0x202e) ||
          (cc >= 0x2066 && cc <= 0x2069) ||
          cc === 0xfeff) {
        throw new AuthError("auth-ciba/binding-message-control-chars",
          "ciba: bindingMessage contains control / bidi / zero-width characters");
      }
    }
    return msg;
  }

  async function _postForm(url, body, headers) {
    safeUrl.parse(url, {
      allowedProtocols: opts.allowHttp === true ? safeUrl.ALLOW_HTTP_ALL : safeUrl.ALLOW_HTTP_TLS,
    });
    var hc = httpOpts.client
      ? httpClient().pinnedClient(httpOpts.client, httpOpts.allowedHosts)
      : httpClient();
    var basic = _basicAuthHeader();
    var hdrs = Object.assign({
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept":       "application/json",
    }, headers || {});
    if (basic) hdrs["Authorization"] = basic;
    var req = {
      url:          url,
      method:       "POST",
      headers:      hdrs,
      body:         body.toString(),
      responseMode: "always-resolve",
    };
    Object.assign(req, opts.httpClientOpts || {});
    if (httpOpts.allowedHosts) req.allowedHosts = httpOpts.allowedHosts.slice();
    safeUrl.parse(req.url, {
      allowedProtocols: opts.allowHttp === true ? safeUrl.ALLOW_HTTP_ALL : safeUrl.ALLOW_HTTP_TLS,
    });
    if (opts.allowHttp === true) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    if (opts.allowInternal != null) req.allowInternal = opts.allowInternal;
    var res = await hc.request(req);
    if (res.statusCode < 200 || res.statusCode >= 300) {
      var bodyText = res.body ? res.body.toString("utf8") : "";
      var err;
      try { err = safeJson.parse(bodyText, { maxBytes: MAX_RESPONSE_BYTES }); } catch (_e) { /* silent-catch: non-JSON IdP error body falls through to the bodyText snippet path below */ }
      var code = (err && err.error) || ("http-" + res.statusCode);
      var msg = (err && (err.error_description || err.error)) || bodyText.slice(0, 200);
      var aerr = new AuthError("auth-ciba/" + code, "ciba: " + msg);
      aerr.cibaError = err || null;
      aerr.statusCode = res.statusCode;
      throw aerr;
    }
    if (!res.body) return null;
    try { return safeJson.parse(res.body.toString("utf8"), { maxBytes: MAX_RESPONSE_BYTES }); }
    catch (e) {
      throw new AuthError("auth-ciba/bad-json",
        "ciba: response not JSON: " + ((e && e.message) || String(e)));
    }
  }

  /**
   * @primitive b.auth.ciba.client.startAuthentication
   * @signature b.auth.ciba.client.startAuthentication(opts)
   * @since     0.8.62
   *
   * POST to the IdP's backchannel_authentication_endpoint and return
   * a ticket with `authReqId` + `expiresIn` + `interval`. At least
   * one of `loginHint` / `loginHintToken` / `idTokenHint` must be
   * supplied to identify the user.
   *
   * @opts
   *   {
   *     loginHint?:        string,
   *     loginHintToken?:   string,
   *     idTokenHint?:      string,
   *     scope?:            string|string[],
   *     bindingMessage?:   string,
   *     acrValues?:        string|string[],
   *     requestedExpiry?:  number,
   *     userCode?:         string,
   *   }
   *
   * @example
   *   var ticket = await ciba.startAuthentication({
   *     loginHint:      "alice@example.com",
   *     bindingMessage: "Authorize wire transfer of $4,200",
   *   });
   *   // → { authReqId, expiresIn, interval }
   */
  async function startAuthentication(sopts) {
    sopts = sopts || {};
    if (!sopts.loginHint && !sopts.loginHintToken && !sopts.idTokenHint) {
      throw new AuthError("auth-ciba/no-user-hint",
        "ciba.startAuthentication: one of loginHint / loginHintToken / idTokenHint required");
    }
    var endpoint = await _resolveBackchannelEndpoint();
    var body = new URLSearchParams();
    if (sopts.loginHint)      body.set("login_hint", sopts.loginHint);
    if (sopts.loginHintToken) body.set("login_hint_token", sopts.loginHintToken);
    if (sopts.idTokenHint)    body.set("id_token_hint", sopts.idTokenHint);

    var scope = sopts.scope || opts.scope || ["openid"];
    if (Array.isArray(scope)) scope = scope.join(" ");
    body.set("scope", scope);

    if (sopts.bindingMessage !== undefined) {
      var msg = _validateBindingMessage(sopts.bindingMessage);
      if (msg) body.set("binding_message", msg);
    }
    if (Array.isArray(sopts.acrValues) && sopts.acrValues.length > 0) {
      body.set("acr_values", sopts.acrValues.join(" "));
    } else if (typeof sopts.acrValues === "string" && sopts.acrValues.length > 0) {
      body.set("acr_values", sopts.acrValues);
    }
    if (typeof sopts.requestedExpiry === "number" &&
        Number.isInteger(sopts.requestedExpiry) && sopts.requestedExpiry > 0) {
      body.set("requested_expiry", String(sopts.requestedExpiry));
    }
    if (typeof sopts.userCode === "string") body.set("user_code", sopts.userCode);

    if (clientAuth === "jwt") {
      var assertion = await opts.clientAssertionSigner({
        iss: opts.clientId, sub: opts.clientId, aud: endpoint,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + C.TIME.minutes(5) / 1000,
        jti: generateToken(16),
      });
      body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      body.set("client_assertion", assertion);
      body.set("client_id", opts.clientId);
    }
    if (clientAuth === "mtls") {
      body.set("client_id", opts.clientId);
    }
    if (clientNotificationToken && (deliveryMode === "ping" || deliveryMode === "push")) {
      body.set("client_notification_token", clientNotificationToken);
    }

    var rv = await _postForm(endpoint, body);
    if (!rv || typeof rv.auth_req_id !== "string") {
      throw new AuthError("auth-ciba/bad-response",
        "ciba.startAuthentication: response missing auth_req_id");
    }
    var interval = typeof rv.interval === "number" && rv.interval >= MIN_INTERVAL_SEC && rv.interval <= MAX_INTERVAL_SEC
      ? rv.interval : DEFAULT_INTERVAL_SEC;
    var expiresIn = typeof rv.expires_in === "number" && rv.expires_in > 0
      ? rv.expires_in : DEFAULT_EXPIRES_SEC;
    _registerInitialInterval(rv.auth_req_id, interval, expiresIn);

    _emitAudit("start", "success", {
      authReqIdHash: sha3Hash("auth-ciba:" + rv.auth_req_id),
      deliveryMode:  deliveryMode,
      hasBindingMessage: !!sopts.bindingMessage,
    });
    _emitMetric("started");
    return {
      authReqId: rv.auth_req_id,
      expiresIn: expiresIn,
      interval:  interval,
    };
  }

  /**
   * @primitive b.auth.ciba.client.pollToken
   * @signature b.auth.ciba.client.pollToken(opts)
   * @since     0.8.62
   *
   * Poll the IdP's /token endpoint with grant_type=ciba. Returns the
   * tokens once the user approves; throws AuthError with code
   * "auth-ciba/authorization_pending" or "auth-ciba/slow_down" while
   * waiting. Operators wrap with their preferred backoff.
   *
   * @opts
   *   { authReqId: string }
   *
   * @example
   *   var tokens = await ciba.pollToken({ authReqId: ticket.authReqId });
   *   // → { accessToken, idToken, refreshToken, tokenType, scope, expiresIn, raw }
   */
  var _intervalState = new Map();

  function _purgeExpiredIntervals(nowMs) {
    var iter = _intervalState.entries();
    var step = iter.next();
    while (!step.done) {
      var pair = step.value;
      if (pair[1].expireAtMs <= nowMs) _intervalState.delete(pair[0]);
      step = iter.next();
    }
  }

  function _registerInitialInterval(authReqId, intervalSec, expiresInSec) {
    var nowMs = Date.now();
    _purgeExpiredIntervals(nowMs);
    _intervalState.set(authReqId, {
      interval:   intervalSec,
      expireAtMs: nowMs + C.TIME.seconds(expiresInSec),
    });
  }

  async function _verifyIdTokenIfPresent(idToken, auditKey, op, expectedAuthReqId) {
    if (!idToken) return null;
    var verified;
    try {
      verified = await inner.verifyIdToken(idToken);
    } catch (e) {
      _emitAudit("id_token_verify_fail", "failure",
        auditKey ? { authReqIdHash: sha3Hash(auditKey) } : {});
      throw new AuthError("auth-ciba/id-token-invalid",
        "ciba." + op + ": id_token failed verification: " +
        ((e && e.code) || (e && e.message) || String(e)));
    }
    var payload = verified && verified.claims;
    var boundId = payload && payload["urn:openid:params:jwt:claim:auth_req_id"];
    if (typeof boundId !== "string" || !timingSafeEqual(boundId, expectedAuthReqId)) {
      _emitAudit("id_token_authreqid_mismatch", "failure",
        auditKey ? { authReqIdHash: sha3Hash(auditKey) } : {});
      throw new AuthError("auth-ciba/id-token-authreqid-mismatch",
        "ciba." + op + ": id_token urn:openid:params:jwt:claim:auth_req_id does not " +
        "match the expected auth_req_id (cross-user token-substitution defense)");
    }
    return verified;
  }

  async function pollToken(popts) {
    popts = popts || {};
    if (typeof popts.authReqId !== "string" || popts.authReqId.length === 0) {
      throw new AuthError("auth-ciba/no-auth-req-id",
        "ciba.pollToken: authReqId required");
    }
    var endpoint = await _resolveTokenEndpoint();
    var body = new URLSearchParams();
    body.set("grant_type", "urn:openid:params:grant-type:ciba");
    body.set("auth_req_id", popts.authReqId);
    if (clientAuth === "jwt") {
      var assertion = await opts.clientAssertionSigner({
        iss: opts.clientId, sub: opts.clientId, aud: endpoint,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + C.TIME.minutes(5) / 1000,
        jti: generateToken(16),
      });
      body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      body.set("client_assertion", assertion);
      body.set("client_id", opts.clientId);
    }
    if (clientAuth === "mtls") body.set("client_id", opts.clientId);
    var rv;
    try {
      rv = await _postForm(endpoint, body);
    } catch (err) {
      if (err && err.code === "auth-ciba/slow_down") {
        var entry = _intervalState.get(popts.authReqId);
        var current = entry ? entry.interval : DEFAULT_INTERVAL_SEC;
        var idpSuggested = err.cibaError && typeof err.cibaError.interval === "number"
          ? err.cibaError.interval : null;
        var next = current + 5;
        if (idpSuggested !== null && idpSuggested > next && idpSuggested <= MAX_INTERVAL_SEC) {
          next = idpSuggested;
        }
        if (next > MAX_INTERVAL_SEC) next = MAX_INTERVAL_SEC;
        if (entry) {
          _intervalState.set(popts.authReqId, { interval: next, expireAtMs: entry.expireAtMs });
        }
        err.nextIntervalSec = next;
      } else if (err && (
        err.code === "auth-ciba/expired_token" ||
        err.code === "auth-ciba/access_denied" ||
        err.code === "auth-ciba/invalid_grant" ||
        err.code === "auth-ciba/transaction_failed")) {
        _intervalState.delete(popts.authReqId);
      }
      throw err;
    }
    _intervalState.delete(popts.authReqId);
    var pollClaims = await _verifyIdTokenIfPresent(rv.id_token,
      "auth-ciba:" + popts.authReqId, "pollToken", popts.authReqId);
    _emitAudit("token_received", "success", {
      authReqIdHash: sha3Hash("auth-ciba:" + popts.authReqId),
    });
    _emitMetric("token-received");
    return {
      accessToken:  rv.access_token   || null,
      idToken:      rv.id_token       || null,
      claims:       pollClaims,
      refreshToken: rv.refresh_token  || null,
      tokenType:    rv.token_type     || null,
      scope:        rv.scope          || null,
      expiresIn:    typeof rv.expires_in === "number" ? rv.expires_in : null,
      raw:          rv,
    };
  }

  /**
   * @primitive b.auth.ciba.client.parseNotification
   * @signature b.auth.ciba.client.parseNotification(req, opts)
   * @since     0.8.62
   *
   * Parse + authenticate an IdP-initiated callback to the RP's
   * `client_notification_endpoint`. Validates the bearer
   * `client_notification_token` (timing-safe equality) before
   * surfacing the body. Use the returned `authReqId` to drive the
   * RP-side flow:
   *
   *   - In **ping** mode the body is `{ auth_req_id }`. Call
   *     `pollToken({ authReqId })` afterwards.
   *   - In **push** mode the body carries the full token-response
   *     object; no follow-up call needed.
   *
   * Async because a pushed `id_token` is verified (signature + iss/aud/exp)
   * via the composed inner OAuth client before it is returned — the
   * verified claims are surfaced as `claims`. A present-but-invalid
   * id_token throws `auth-ciba/id-token-invalid` (the notification-token
   * bearer authenticates the caller, never the token itself).
   *
   * @opts
   *   { body?: object }   // pre-parsed body; defaults to req.body
   *
   * @example
   *   app.post("/ciba/notify", async function (req, res) {
   *     var info = await ciba.parseNotification(req, { body: req.body });
   *     // → { authReqId, accessToken, idToken, claims, ... }
   *     res.statusCode = 204; res.end();
   *   });
   */
  async function parseNotification(req, popts) {
    popts = popts || {};
    if (!req || !req.headers) {
      throw new AuthError("auth-ciba/bad-notification-req",
        "ciba.parseNotification: req with headers required");
    }
    var authzHeader = req.headers["authorization"];
    var BEARER_PREFIX = "bearer ";
    if (!authzHeader || authzHeader.slice(0, BEARER_PREFIX.length).toLowerCase() !== BEARER_PREFIX) {
      throw new AuthError("auth-ciba/missing-bearer",
        "ciba.parseNotification: Authorization: Bearer header missing");
    }
    var presented = authzHeader.slice(BEARER_PREFIX.length).trim();
    if (presented.length === 0 || !clientNotificationToken) {
      throw new AuthError("auth-ciba/bad-bearer",
        "ciba.parseNotification: empty bearer or no expected token configured");
    }
    var presentedHash = sha3Hash(presented);
    var expectedHash  = sha3Hash(clientNotificationToken);
    if (!timingSafeEqual(presentedHash, expectedHash)) {
      _emitAudit("notification_token_mismatch", "failure", {});
      throw new AuthError("auth-ciba/wrong-bearer",
        "ciba.parseNotification: client_notification_token does not match");
    }
    var body = popts.body !== undefined ? popts.body : req.body;
    if (typeof body === "string") {
      try { body = safeJson.parse(body, { maxBytes: MAX_RESPONSE_BYTES }); }
      catch (e) {
        throw new AuthError("auth-ciba/bad-notification-body",
          "ciba.parseNotification: body is not JSON: " + ((e && e.message) || String(e)));
      }
    }
    if (!body || typeof body !== "object") {
      throw new AuthError("auth-ciba/no-notification-body",
        "ciba.parseNotification: body required (Buffer/string parsed by middleware)");
    }
    validateOpts.requireNonEmptyString(body.auth_req_id,
      "ciba.parseNotification: auth_req_id", AuthError, "auth-ciba/no-auth-req-id-in-body");
    var pushClaims = await _verifyIdTokenIfPresent(body.id_token,
      "auth-ciba:" + body.auth_req_id, "parseNotification", body.auth_req_id);
    _emitAudit("notification_received", "success", {
      authReqIdHash: sha3Hash("auth-ciba:" + body.auth_req_id),
      mode:          deliveryMode,
    });
    _emitMetric("notification-received");
    return {
      authReqId:    body.auth_req_id,
      accessToken:  body.access_token  || null,
      idToken:      body.id_token      || null,
      claims:       pushClaims,
      refreshToken: body.refresh_token || null,
      tokenType:    body.token_type    || null,
      scope:        body.scope         || null,
      expiresIn:    typeof body.expires_in === "number" ? body.expires_in : null,
      raw:          body,
    };
  }

  return {
    startAuthentication: startAuthentication,
    pollToken:           pollToken,
    parseNotification:   parseNotification,
    issuer:              opts.issuer,
    clientId:            opts.clientId,
    deliveryMode:        deliveryMode,
  };
}

module.exports = {
  client: { create: create },
};

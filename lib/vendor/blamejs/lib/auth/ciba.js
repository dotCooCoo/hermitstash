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

var lazyRequire  = require("../lazy-require");
var validateOpts = require("../validate-opts");
var safeJson     = require("../safe-json");
var safeUrl      = require("../safe-url");
var { generateToken, sha3Hash } = require("../crypto");
var { AuthError } = require("../framework-error");

var httpClient    = lazyRequire(function () { return require("../http-client"); });
var oauth         = lazyRequire(function () { return require("./oauth"); });
var audit         = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var emit = validateOpts.makeNamespacedEmitters("auth.ciba", { audit: audit, observability: observability });

var DEFAULT_INTERVAL_SEC = 5;
var DEFAULT_EXPIRES_SEC  = 600;
var MAX_BINDING_MSG_LEN  = 200;
var MAX_RESPONSE_BYTES   = 64 * 1024;                                                            // allow:raw-byte-literal — JSON token-response cap
var MIN_INTERVAL_SEC     = 1;
var MAX_INTERVAL_SEC     = 300;                                                                  // allow:raw-time-literal — interval ceiling

// _emitAudit emits under the "auth.ciba.<action>" namespace; _emitMetric
// fires the matching observability counter. Implementations live in
// validateOpts.makeNamespacedEmitters; the locals are aliases so the
// existing call sites read identically.
var _emitAudit  = emit.audit;
var _emitMetric = emit.metric;

/**
 * @primitive b.auth.ciba.client.create
 * @signature b.auth.ciba.client.create(opts)
 * @since     0.8.62
 * @status    stable
 * @related   b.auth.oauth.create, b.auth.jwt
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
 *     httpClientOpts?:            object,
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

  var deliveryMode = opts.deliveryMode || "poll";
  if (["poll", "ping", "push"].indexOf(deliveryMode) === -1) {
    throw new AuthError("auth-ciba/bad-delivery-mode",
      "auth.ciba.client.create: deliveryMode must be 'poll' | 'ping' | 'push'");
  }

  // Inner OAuth client — composes discovery, JWKS fetch, ID-token
  // verification. CIBA's token endpoint, JWKS, and discovery are all
  // shared with the RP's other OIDC flows so we reuse the existing
  // primitive's caching + audit + clock-skew tolerance.
  var inner = oauth().create({
    issuer:                            opts.issuer,
    clientId:                          opts.clientId,
    clientSecret:                      opts.clientSecret,
    redirectUri:                       opts.redirectUri || (opts.issuer + "/__ciba_no_redirect__"),
    scope:                             opts.scope,
    backchannelAuthenticationEndpoint: opts.backchannelAuthenticationEndpoint,
    tokenEndpoint:                     opts.tokenEndpoint,
    httpClientOpts:                    opts.httpClientOpts,
    allowHttp:                         opts.allowHttp === true,
    isOidc:                            true,
  });

  var clientNotificationToken = opts.clientNotificationToken || null;
  if ((deliveryMode === "ping" || deliveryMode === "push") && !clientNotificationToken) {
    throw new AuthError("auth-ciba/no-notification-token",
      "auth.ciba.client.create: clientNotificationToken required for ping/push delivery modes");
  }

  // Each backchannel-authentication request mints a fresh
  // `client_notification_token` per the spec? No — the RP registers
  // ONE long-lived token with the IdP at registration time. Operator
  // rotates by re-registering. Per CIBA §7.1.1.

  function _basicAuthHeader() {
    if (clientAuth !== "secret") return null;
    var pair = opts.clientId + ":" + opts.clientSecret;
    return "Basic " + Buffer.from(pair, "utf8").toString("base64");
  }

  async function _resolveBackchannelEndpoint() {
    // Hit discovery if not pre-configured. The inner OAuth client
    // already has discovery cache; we ride it via the public discover()
    // shape.
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
    // Per §7.1, binding_message MUST be plain text + restricted to
    // characters most user-agents render legibly. Refuse control /
    // bidi / zero-width.
    // Codepoint scan instead of a regex character class - eslint's
    // no-control-regex rule refuses control-char ranges in regex
    // literals regardless of how they're spelled.
    for (var ci = 0; ci < msg.length; ci += 1) {
      var cc = msg.charCodeAt(ci);
      if (cc <= 0x001f ||
          (cc >= 0x007f && cc <= 0x009f) ||
          (cc >= 0x200b && cc <= 0x200f) ||
          (cc >= 0x202a && cc <= 0x202e) ||
          (cc >= 0x2066 && cc <= 0x2069) ||
          cc === 0xfeff) {                                                                      // allow:raw-byte-literal — codepoint constants for control / bidi / zero-width / BOM
        throw new AuthError("auth-ciba/binding-message-control-chars",
          "ciba: bindingMessage contains control / bidi / zero-width characters");
      }
    }
    return msg;
  }

  async function _postForm(url, body, headers) {
    safeUrl.assertHttpUrl(url, opts.allowHttp === true);
    var hc = httpClient();
    var basic = _basicAuthHeader();
    var hdrs = Object.assign({
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept":       "application/json",
    }, headers || {});
    if (basic) hdrs["Authorization"] = basic;
    var req = {
      url:    url,
      method: "POST",
      headers: hdrs,
      body:    body.toString(),
    };
    Object.assign(req, opts.httpClientOpts || {});
    if (opts.allowHttp === true) req.allowedProtocols = safeUrl.ALLOW_HTTP_ALL;
    var res = await hc.request(req);
    if (res.statusCode < 200 || res.statusCode >= 300) {
      var bodyText = res.body ? res.body.toString("utf8") : "";
      var err;
      try { err = safeJson.parse(bodyText, { maxBytes: MAX_RESPONSE_BYTES }); } catch (_e) { /* silent-catch: non-JSON IdP error body falls through to the bodyText snippet path below */ }
      var code = (err && err.error) || ("http-" + res.statusCode);
      var msg = (err && (err.error_description || err.error)) || bodyText.slice(0, 200);   // allow:raw-byte-literal — error-message snippet length
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
   * @signature client.startAuthentication(opts)
   * @since     0.8.62
   *
   * POST to the IdP's backchannel_authentication_endpoint and return
   * a ticket with `authReqId` + `expiresIn` + `interval`. At least
   * one of `loginHint` / `loginHintToken` / `idTokenHint` must be
   * supplied to identify the user.
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
        iat: Math.floor(Date.now() / 1000),                                                     // allow:raw-byte-literal — ms→s
        exp: Math.floor(Date.now() / 1000) + 300,                                               // allow:raw-byte-literal — assertion 5m TTL
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
   * @signature client.pollToken({ authReqId })
   * @since     0.8.62
   *
   * Poll the IdP's /token endpoint with grant_type=ciba. Returns the
   * tokens once the user approves; throws AuthError with code
   * "auth-ciba/authorization_pending" or "auth-ciba/slow_down" while
   * waiting. Operators wrap with their preferred backoff.
   */
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
        iat: Math.floor(Date.now() / 1000),                                                     // allow:raw-byte-literal — ms→s
        exp: Math.floor(Date.now() / 1000) + 300,                                               // allow:raw-byte-literal — assertion 5m TTL
        jti: generateToken(16),
      });
      body.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
      body.set("client_assertion", assertion);
      body.set("client_id", opts.clientId);
    }
    if (clientAuth === "mtls") body.set("client_id", opts.clientId);
    var rv = await _postForm(endpoint, body);
    _emitAudit("token_received", "success", {
      authReqIdHash: sha3Hash("auth-ciba:" + popts.authReqId),
    });
    _emitMetric("token-received");
    return {
      accessToken:  rv.access_token   || null,
      idToken:      rv.id_token       || null,
      refreshToken: rv.refresh_token  || null,
      tokenType:    rv.token_type     || null,
      scope:        rv.scope          || null,
      expiresIn:    typeof rv.expires_in === "number" ? rv.expires_in : null,
      raw:          rv,
    };
  }

  /**
   * @primitive b.auth.ciba.client.parseNotification
   * @signature client.parseNotification(req, opts?)
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
   */
  function parseNotification(req, popts) {
    popts = popts || {};
    if (!req || !req.headers) {
      throw new AuthError("auth-ciba/bad-notification-req",
        "ciba.parseNotification: req with headers required");
    }
    var authzHeader = req.headers["authorization"] || req.headers["Authorization"];
    if (!authzHeader || authzHeader.indexOf("Bearer ") !== 0) {
      throw new AuthError("auth-ciba/missing-bearer",
        "ciba.parseNotification: Authorization: Bearer header missing");
    }
    var presented = authzHeader.substring("Bearer ".length).trim();
    if (presented.length === 0 || !clientNotificationToken) {
      throw new AuthError("auth-ciba/bad-bearer",
        "ciba.parseNotification: empty bearer or no expected token configured");
    }
    // Constant-time compare via the framework's primitive shape —
    // sha3-of-each + ===-of-hash is constant-time over equal-length
    // hashes regardless of presented length, so a length-side-channel
    // probe can't enumerate the prefix.
    var presentedHash = sha3Hash(presented);
    var expectedHash  = sha3Hash(clientNotificationToken);
    if (presentedHash !== expectedHash) {
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
    if (typeof body.auth_req_id !== "string") {
      throw new AuthError("auth-ciba/no-auth-req-id-in-body",
        "ciba.parseNotification: body missing auth_req_id");
    }
    _emitAudit("notification_received", "success", {
      authReqIdHash: sha3Hash("auth-ciba:" + body.auth_req_id),
      mode:          deliveryMode,
    });
    _emitMetric("notification-received");
    return {
      authReqId:    body.auth_req_id,
      accessToken:  body.access_token  || null,
      idToken:      body.id_token      || null,
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

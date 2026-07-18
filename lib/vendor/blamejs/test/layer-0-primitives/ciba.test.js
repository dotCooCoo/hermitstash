// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.ciba.client — canonical per-primitive coverage for the CIBA
 * (OpenID Connect Client-Initiated Backchannel Authentication) RP client:
 * create()-time option validation, startAuthentication's backchannel POST +
 * body assembly, pollToken's grant_type=ciba loop (authorization_pending /
 * slow_down back-off / terminal errors), and parseNotification's ping/push
 * callback authentication.
 *
 * Every flow drives the REAL consumer path against a localhost OIDC stub
 * (discovery + JWKS + scriptable /bc-auth + /token) — never the network, no
 * NODE_ENV bypass. The stub's key pair signs ES256 id_tokens so the composed
 * inner OAuth client's id_token verification runs end-to-end.
 *
 * The auth_req_id-binding substitution defense (id_token bound to the flow's
 * auth_req_id) has its own file (ciba-authreqid-binding.test.js); this file
 * targets the error / adversarial / option-default / fail-closed branches.
 */

var http       = require("http");
var nodeCrypto = require("crypto");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var CLIENT_ID     = "rp-ciba-cov";
var KID           = "cov-es256";
// >= 32 chars — clears the CIBA §7.1.2 client_notification_token min-entropy guard.
var CNT           = "client-notification-token-opaque-and-long-enough-for-ciba-min-entropy-guard";
var CLIENT_SECRET = "ciba-cov-client-secret-opaque-and-long-enough-for-basic-auth-padding-xxxxxxxx";

// The trusted signing key — its public JWK is served at /jwks so the inner
// OAuth client's verifyIdToken accepts tokens minted with `_signer`.
var _signer = _makeKeyPair(KID);
// A rogue key never published to /jwks — id_tokens it signs fail verification
// (drives the fail-closed auth-ciba/id-token-invalid branch).
var _rogue  = _makeKeyPair("rogue-" + KID);

function _makeKeyPair(kid) {
  var kp  = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  var jwk = kp.publicKey.export({ format: "jwk" });
  jwk.kid = kid; jwk.alg = "ES256"; jwk.use = "sig";
  return { kp: kp, jwk: jwk };
}

function _b64url(x) { return Buffer.from(x).toString("base64url"); }

// Mint an ES256 id_token. `authReqIdClaim` (when defined) is written as the
// urn:openid:params:jwt:claim:auth_req_id binding claim. `signer` defaults to
// the trusted key; pass `_rogue` for a signature the JWKS can't verify.
function _mintIdToken(issuer, authReqIdClaim, signer) {
  signer = signer || _signer;
  var header  = { alg: "ES256", kid: signer.jwk.kid, typ: "JWT" };
  var now     = Math.floor(Date.now() / 1000);
  var payload = { iss: issuer, aud: CLIENT_ID, sub: "user-cov", iat: now, exp: now + 3600 };
  if (authReqIdClaim !== undefined) payload["urn:openid:params:jwt:claim:auth_req_id"] = authReqIdClaim;
  var input = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
  var sig   = nodeCrypto.sign("sha256", Buffer.from(input),
    { key: signer.kp.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + _b64url(sig);
}

// Localhost OIDC stub. `holder` scripts the per-request behavior:
//   holder.discoveryOmit  — "backchannel" | "token" drops that field from the
//                           discovery doc (drives ciba's no-*-endpoint refusals).
//   holder.onBcAuth(body, res) / holder.onToken(body, res) — script /bc-auth
//                           and /token responses. Unset → sensible defaults.
//   holder.bcAuthBodies / holder.tokenBodies — captured request bodies.
async function _withIdp(fn) {
  var holder = {
    issuer:        null,
    discoveryOmit: null,
    onBcAuth:      null,
    onToken:       null,
    bcAuthBodies:  [],
    tokenBodies:   [],
  };
  function _json(res, status, obj) {
    var s = JSON.stringify(obj);
    res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
    res.end(s);
  }
  function _readBody(req, cb) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () { cb(Buffer.concat(chunks).toString("utf8")); });
  }
  var server = http.createServer(function (req, res) {
    var u = new URL(req.url, "http://localhost");
    if (u.pathname === "/.well-known/openid-configuration") {
      var doc = {
        issuer:                              holder.issuer,
        authorization_endpoint:              holder.issuer + "/auth",
        token_endpoint:                      holder.issuer + "/token",
        backchannel_authentication_endpoint: holder.issuer + "/bc-auth",
        jwks_uri:                            holder.issuer + "/jwks",
      };
      if (holder.discoveryOmit === "backchannel") delete doc.backchannel_authentication_endpoint;
      if (holder.discoveryOmit === "token")       delete doc.token_endpoint;
      _json(res, 200, doc); return;
    }
    if (u.pathname === "/jwks") { _json(res, 200, { keys: [_signer.jwk] }); return; }
    if (u.pathname === "/bc-auth") {
      _readBody(req, function (body) {
        holder.bcAuthBodies.push(body);
        if (holder.onBcAuth) { holder.onBcAuth(body, res); return; }
        _json(res, 200, { auth_req_id: "bc-default-req", expires_in: 300, interval: 5 });
      });
      return;
    }
    if (u.pathname === "/token") {
      _readBody(req, function (body) {
        holder.tokenBodies.push(body);
        if (holder.onToken) { holder.onToken(body, res); return; }
        res.writeHead(404); res.end();
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  holder.issuer = "http://127.0.0.1:" + server.address().port;
  try { return await fn(holder.issuer, holder); }
  finally { await new Promise(function (r) { server.close(function () { r(); }); }); }
}

// Standard poll-mode client with explicit endpoints (no discovery).
function _pollClient(issuer, extra) {
  return b.auth.ciba.client.create(Object.assign({
    issuer:                            issuer,
    clientId:                          CLIENT_ID,
    clientSecret:                      CLIENT_SECRET,
    tokenEndpoint:                     issuer + "/token",
    backchannelAuthenticationEndpoint: issuer + "/bc-auth",
    deliveryMode:                      "poll",
    allowHttp:                         true,
    allowInternal:                     true,
  }, extra || {}));
}

// The CIBA client's discovery + JWKS + POST traffic rides the shared
// b.httpClient keep-alive agent; its cached sockets (and the stub server)
// would otherwise hold the forked worker's event loop open past run(). Tear
// the pool down and poll until the TCP handles have actually closed.
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "ciba: TCP handle drain after _resetForTest" });
}

// ---- startAuthentication (happy path + body assembly) -----------------

async function _runStartAuthenticationHappy() {
  await _withIdp(async function (issuer, holder) {
    var ciba = _pollClient(issuer, { scope: ["openid", "profile"] });
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-happy-1", expires_in: 120, interval: 3 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var ticket = await ciba.startAuthentication({
      loginHint:       "alice@example.com",
      bindingMessage:  "Authorize wire transfer of $4,200",
      acrValues:       ["urn:mace:incommon:iap:silver"],
      requestedExpiry: 90,
    });
    check("b.auth.ciba.client.startAuthentication: returns ticket with authReqId/expiresIn/interval",
          ticket && ticket.authReqId === "req-happy-1" && ticket.expiresIn === 120 && ticket.interval === 3);
    var sent = new URLSearchParams(holder.bcAuthBodies[0]);
    check("startAuthentication: login_hint forwarded", sent.get("login_hint") === "alice@example.com");
    check("startAuthentication: scope array joined",   sent.get("scope") === "openid profile");
    check("startAuthentication: binding_message forwarded",
          sent.get("binding_message") === "Authorize wire transfer of $4,200");
    check("startAuthentication: acr_values joined",    sent.get("acr_values") === "urn:mace:incommon:iap:silver");
    check("startAuthentication: requested_expiry forwarded", sent.get("requested_expiry") === "90");
  });
}

// ---- pollToken (happy path) -------------------------------------------

async function _runPollTokenHappy() {
  await _withIdp(async function (issuer, holder) {
    var ciba = _pollClient(issuer);
    var AUTH_REQ_ID = "req-poll-happy";
    var polls = 0;
    holder.onToken = function (body, res) {
      polls += 1;
      if (polls === 1) {
        var pend = JSON.stringify({ error: "authorization_pending" });
        res.writeHead(400, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(pend) });
        res.end(pend); return;
      }
      var tok = JSON.stringify({
        access_token: "poll-at", token_type: "Bearer", expires_in: 3600, scope: "openid",
        id_token: _mintIdToken(issuer, AUTH_REQ_ID),
      });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(tok) });
      res.end(tok);
    };
    var pending = null;
    try { await ciba.pollToken({ authReqId: AUTH_REQ_ID }); }
    catch (e) { pending = e; }
    check("b.auth.ciba.client.pollToken: authorization_pending surfaced as typed AuthError",
          pending && pending.code === "auth-ciba/authorization_pending");
    var tokens = await ciba.pollToken({ authReqId: AUTH_REQ_ID });
    check("pollToken: tokens returned once approved",
          tokens && tokens.accessToken === "poll-at" && tokens.expiresIn === 3600 &&
          tokens.claims && tokens.claims.claims["urn:openid:params:jwt:claim:auth_req_id"] === AUTH_REQ_ID);
  });
}

// ---- parseNotification (push happy path) ------------------------------

async function _runParseNotificationHappy() {
  await _withIdp(async function (issuer) {
    var ciba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
      tokenEndpoint: issuer + "/token", backchannelAuthenticationEndpoint: issuer + "/bc-auth",
      deliveryMode: "push", clientNotificationToken: CNT, allowHttp: true, allowInternal: true,
    });
    var info = await ciba.parseNotification(
      { headers: { authorization: "Bearer " + CNT } },
      { body: { auth_req_id: "req-push-1", access_token: "push-at",
                id_token: _mintIdToken(issuer, "req-push-1") } });
    check("b.auth.ciba.client.parseNotification: push callback surfaces bound tokens",
          info && info.authReqId === "req-push-1" && info.accessToken === "push-at" &&
          info.claims && info.claims.claims["urn:openid:params:jwt:claim:auth_req_id"] === "req-push-1");
  });
}

// ---- create() option validation (entry-point THROW tier) -------------

// create() rejects malformed configuration at the entry point (config-time
// tier — throw so the operator catches the typo at boot). None of these hit
// the network: the inner OAuth client is built lazily.
function _runCreateValidation() {
  function _throws(label, opts, code) {
    var err = null;
    try { b.auth.ciba.client.create(opts); } catch (e) { err = e; }
    check(label, err && err.code === code);
  }
  var base = { issuer: "https://idp.example.com", clientId: CLIENT_ID };
  _throws("create: unknown clientAuth refused",
          Object.assign({ clientAuth: "kerberos" }, base), "auth-ciba/bad-client-auth");
  _throws("create: clientAuth=secret without clientSecret refused",
          Object.assign({ clientAuth: "secret" }, base), "auth-ciba/no-client-secret");
  _throws("create: clientAuth=jwt without clientAssertionSigner refused",
          Object.assign({ clientAuth: "jwt" }, base), "auth-ciba/no-assertion-signer");
  _throws("create: unknown deliveryMode refused",
          Object.assign({ clientAuth: "secret", clientSecret: CLIENT_SECRET, deliveryMode: "carrier-pigeon" }, base),
          "auth-ciba/bad-delivery-mode");
  _throws("create: ping/push without clientNotificationToken refused",
          Object.assign({ clientAuth: "secret", clientSecret: CLIENT_SECRET, deliveryMode: "ping" }, base),
          "auth-ciba/no-notification-token");
  _throws("create: sub-32-char clientNotificationToken refused (CIBA §7.1.2 min entropy)",
          Object.assign({ clientAuth: "secret", clientSecret: CLIENT_SECRET, deliveryMode: "push",
                          clientNotificationToken: "short" }, base),
          "auth-ciba/notification-token-too-short");
  // Non-object opts + missing issuer / clientId also refuse at the top.
  var e1 = null; try { b.auth.ciba.client.create(null); } catch (e) { e1 = e; }
  check("create: non-object opts refused", e1 !== null);
  var e2 = null; try { b.auth.ciba.client.create({ clientId: CLIENT_ID }); } catch (e) { e2 = e; }
  check("create: missing issuer refused", e2 && e2.code === "auth-ciba/no-issuer");
  var e3 = null; try { b.auth.ciba.client.create({ issuer: "https://idp.example.com" }); } catch (e) { e3 = e; }
  check("create: missing clientId refused", e3 && e3.code === "auth-ciba/no-client-id");
}

// ---- startAuthentication branch coverage ------------------------------

async function _runStartAuthenticationBranches() {
  await _withIdp(async function (issuer, holder) {
    // no user hint → refused before any network call.
    var pollCiba = _pollClient(issuer);
    var noHint = null;
    try { await pollCiba.startAuthentication({ scope: "openid" }); }
    catch (e) { noHint = e; }
    check("startAuthentication: no login_hint/login_hint_token/id_token_hint refused",
          noHint && noHint.code === "auth-ciba/no-user-hint");

    // login_hint_token + id_token_hint + acr string + user_code + interval
    // clamp (out-of-range interval falls back to the 5s default) +
    // expires_in default (non-positive → 600s).
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-variants", expires_in: 0, interval: 9999 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var t = await pollCiba.startAuthentication({
      loginHintToken: "lht-abc", idTokenHint: "idth-xyz",
      acrValues: "urn:acr:single", userCode: "1234",
    });
    check("startAuthentication: out-of-range interval clamps to 5s default", t.interval === 5);
    check("startAuthentication: non-positive expires_in clamps to 600s default", t.expiresIn === 600);
    var sent = new URLSearchParams(holder.bcAuthBodies[holder.bcAuthBodies.length - 1]);
    check("startAuthentication: login_hint_token + id_token_hint + acr string + user_code forwarded",
          sent.get("login_hint_token") === "lht-abc" && sent.get("id_token_hint") === "idth-xyz" &&
          sent.get("acr_values") === "urn:acr:single" && sent.get("user_code") === "1234");

    // A 200 response whose JSON lacks auth_req_id → bad-response.
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ expires_in: 120, interval: 5 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var badResp = null;
    try { await pollCiba.startAuthentication({ loginHint: "a@b.co" }); }
    catch (e) { badResp = e; }
    check("startAuthentication: response without auth_req_id refused",
          badResp && badResp.code === "auth-ciba/bad-response");
  });
}

// clientAuth=jwt (assertion signer wired) and clientAuth=mtls both drive
// distinct request-body assembly in startAuthentication + pollToken.
async function _runClientAuthModes() {
  await _withIdp(async function (issuer, holder) {
    var assertions = [];
    var jwtCiba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientAuth: "jwt",
      clientAssertionSigner: async function (payload) {
        assertions.push(payload); return "header.body.sig";
      },
      tokenEndpoint: issuer + "/token", backchannelAuthenticationEndpoint: issuer + "/bc-auth",
      deliveryMode: "poll", allowHttp: true, allowInternal: true,
    });
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-jwt", expires_in: 120, interval: 5 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    await jwtCiba.startAuthentication({ loginHint: "jwt@example.com" });
    var jwtBody = new URLSearchParams(holder.bcAuthBodies[holder.bcAuthBodies.length - 1]);
    check("startAuthentication(jwt): client_assertion + assertion_type set",
          jwtBody.get("client_assertion") === "header.body.sig" &&
          jwtBody.get("client_assertion_type") === "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" &&
          jwtBody.get("client_id") === CLIENT_ID);

    holder.onToken = function (body, res) {
      var s = JSON.stringify({ access_token: "jwt-at", token_type: "Bearer" });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var jwtTok = await jwtCiba.pollToken({ authReqId: "req-jwt" });
    var jwtPollBody = new URLSearchParams(holder.tokenBodies[holder.tokenBodies.length - 1]);
    check("pollToken(jwt): client_assertion set + minimal token response nulls absent fields",
          jwtPollBody.get("client_assertion") === "header.body.sig" &&
          jwtTok.accessToken === "jwt-at" && jwtTok.refreshToken === null &&
          jwtTok.scope === null && jwtTok.expiresIn === null && jwtTok.idToken === null);
    check("startAuthentication(jwt): assertion payload carries iss/sub/aud/jti",
          assertions.length >= 1 && assertions[0].iss === CLIENT_ID &&
          assertions[0].sub === CLIENT_ID && typeof assertions[0].jti === "string");

    // mtls — no secret, no signer; client_id set on both requests.
    var mtlsCiba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientAuth: "mtls",
      tokenEndpoint: issuer + "/token", backchannelAuthenticationEndpoint: issuer + "/bc-auth",
      deliveryMode: "poll", allowHttp: true, allowInternal: true,
    });
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-mtls", expires_in: 120 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    await mtlsCiba.startAuthentication({ loginHint: "mtls@example.com" });
    var mtlsBody = new URLSearchParams(holder.bcAuthBodies[holder.bcAuthBodies.length - 1]);
    check("startAuthentication(mtls): client_id set, no client_assertion",
          mtlsBody.get("client_id") === CLIENT_ID && mtlsBody.get("client_assertion") === null);
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ access_token: "mtls-at" });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    await mtlsCiba.pollToken({ authReqId: "req-mtls" });
    var mtlsPoll = new URLSearchParams(holder.tokenBodies[holder.tokenBodies.length - 1]);
    check("pollToken(mtls): client_id set on token request", mtlsPoll.get("client_id") === CLIENT_ID);
  });
}

// ping/push modes forward the client_notification_token on the backchannel
// request so the IdP can authenticate its later callback.
async function _runNotificationTokenForwarding() {
  await _withIdp(async function (issuer, holder) {
    var pingCiba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
      backchannelAuthenticationEndpoint: issuer + "/bc-auth", tokenEndpoint: issuer + "/token",
      deliveryMode: "ping", clientNotificationToken: CNT, allowHttp: true, allowInternal: true,
    });
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-ping", expires_in: 120 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    await pingCiba.startAuthentication({ loginHint: "ping@example.com" });
    var sent = new URLSearchParams(holder.bcAuthBodies[holder.bcAuthBodies.length - 1]);
    check("startAuthentication(ping): client_notification_token forwarded", sent.get("client_notification_token") === CNT);

    // push mode drives the OTHER arm of the deliveryMode ping/push guard.
    var pushCiba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
      backchannelAuthenticationEndpoint: issuer + "/bc-auth", tokenEndpoint: issuer + "/token",
      deliveryMode: "push", clientNotificationToken: CNT, allowHttp: true, allowInternal: true,
    });
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-push-start", expires_in: 120 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    await pushCiba.startAuthentication({ loginHint: "push@example.com" });
    var sentPush = new URLSearchParams(holder.bcAuthBodies[holder.bcAuthBodies.length - 1]);
    check("startAuthentication(push): client_notification_token forwarded", sentPush.get("client_notification_token") === CNT);
  });
}

// ---- binding-message validation (§7.1 legibility rules) ---------------

async function _runBindingMessageValidation() {
  await _withIdp(async function (issuer) {
    var ciba = _pollClient(issuer);
    async function _rejects(label, msg, code) {
      var err = null;
      try { await ciba.startAuthentication({ loginHint: "a@b.co", bindingMessage: msg }); }
      catch (e) { err = e; }
      check(label, err && err.code === code);
    }
    await _rejects("bindingMessage: non-string refused", 12345, "auth-ciba/bad-binding-message");
    await _rejects("bindingMessage: over-length refused", "x".repeat(201), "auth-ciba/binding-message-too-long");
    await _rejects("bindingMessage: control character refused", "approve" + String.fromCharCode(0x07) + "now", "auth-ciba/binding-message-control-chars");
    await _rejects("bindingMessage: bidi override refused", "approve" + String.fromCharCode(0x202e) + "en", "auth-ciba/binding-message-control-chars");
    await _rejects("bindingMessage: bidi isolate refused", "approve" + String.fromCharCode(0x2066) + "en", "auth-ciba/binding-message-control-chars");
    await _rejects("bindingMessage: zero-width space refused", "approve" + String.fromCharCode(0x200b) + "now", "auth-ciba/binding-message-control-chars");
    await _rejects("bindingMessage: DEL/C1 control refused", "approve" + String.fromCharCode(0x007f) + "now", "auth-ciba/binding-message-control-chars");
    await _rejects("bindingMessage: BOM refused", "approve" + String.fromCharCode(0xfeff) + "now", "auth-ciba/binding-message-control-chars");
    // A null bindingMessage is treated as "not supplied" (validator returns
    // null; the field is simply omitted from the backchannel request).
    var okNull = false;
    try { okNull = !!(await ciba.startAuthentication({ loginHint: "a@b.co", bindingMessage: null })); }
    catch (_e) { okNull = false; }
    check("bindingMessage: null is accepted as 'not supplied'", okNull === true);
  });
}

// ---- _postForm IdP-error surfacing ------------------------------------

async function _runPostFormErrors() {
  await _withIdp(async function (issuer, holder) {
    var ciba = _pollClient(issuer);
    // 4xx with structured OAuth error JSON → typed auth-ciba/<error>.
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ error: "invalid_request", error_description: "malformed auth_req_id" });
      res.writeHead(400, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var typed = null;
    try { await ciba.pollToken({ authReqId: "req-err" }); }
    catch (e) { typed = e; }
    check("_postForm: structured OAuth error JSON surfaced as typed AuthError",
          typed && typed.code === "auth-ciba/invalid_request" &&
          typed.statusCode === 400 && typed.cibaError && typed.cibaError.error === "invalid_request");

    // 5xx with a NON-JSON body → falls back to http-<status> code.
    holder.onToken = function (body, res) {
      var s = "upstream unavailable";
      res.writeHead(503, { "Content-Type": "text/plain", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var nonJson = null;
    try { await ciba.pollToken({ authReqId: "req-503" }); }
    catch (e) { nonJson = e; }
    check("_postForm: non-JSON error body falls back to http-<status> code",
          nonJson && nonJson.code === "auth-ciba/http-503" && nonJson.statusCode === 503);

    // 200 with a non-JSON body → auth-ciba/bad-json.
    holder.onToken = function (body, res) {
      var s = "<html>not json</html>";
      res.writeHead(200, { "Content-Type": "text/html", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var badJson = null;
    try { await ciba.pollToken({ authReqId: "req-badjson" }); }
    catch (e) { badJson = e; }
    check("_postForm: non-JSON 200 body refused as bad-json",
          badJson && badJson.code === "auth-ciba/bad-json");
  });
}

// ---- discovery-driven endpoint resolution -----------------------------

async function _runDiscovery() {
  // backchannel + token endpoints resolved from the discovery document
  // (no explicit endpoints configured).
  await _withIdp(async function (issuer, holder) {
    var ciba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
      deliveryMode: "poll", allowHttp: true, allowInternal: true,
    });
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-disc", expires_in: 120 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var t = await ciba.startAuthentication({ loginHint: "disc@example.com" });
    check("startAuthentication: backchannel endpoint resolved via discovery", t.authReqId === "req-disc");
    check("startAuthentication: discovery hit the well-known backchannel path",
          holder.bcAuthBodies.length === 1);
    // pollToken on the same client resolves the token endpoint via discovery.
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ access_token: "disc-at", token_type: "Bearer" });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var dt = await ciba.pollToken({ authReqId: "req-disc" });
    check("pollToken: token endpoint resolved via discovery", dt && dt.accessToken === "disc-at");
  });

  // discovery doc without backchannel_authentication_endpoint → refused.
  await _withIdp(async function (issuer, holder) {
    holder.discoveryOmit = "backchannel";
    var ciba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
      deliveryMode: "poll", allowHttp: true, allowInternal: true,
    });
    var err = null;
    try { await ciba.startAuthentication({ loginHint: "a@b.co" }); }
    catch (e) { err = e; }
    check("startAuthentication: discovery lacking backchannel endpoint refused",
          err && err.code === "auth-ciba/no-backchannel-endpoint");
  });

  // discovery doc without token_endpoint → pollToken refused.
  await _withIdp(async function (issuer, holder) {
    holder.discoveryOmit = "token";
    var ciba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
      backchannelAuthenticationEndpoint: issuer + "/bc-auth",
      deliveryMode: "poll", allowHttp: true, allowInternal: true,
    });
    var err = null;
    try { await ciba.pollToken({ authReqId: "req-x" }); }
    catch (e) { err = e; }
    check("pollToken: discovery lacking token endpoint refused",
          err && err.code === "auth-ciba/no-token-endpoint");
  });
}

// ---- pollToken adversarial + id_token verification --------------------

async function _runPollTokenAdversarial() {
  await _withIdp(async function (issuer, holder) {
    var ciba = _pollClient(issuer);

    // missing authReqId refused at the entry (defensive-reader tier).
    var noId = null;
    try { await ciba.pollToken({}); } catch (e) { noId = e; }
    check("pollToken: missing authReqId refused", noId && noId.code === "auth-ciba/no-auth-req-id");
    var emptyId = null;
    try { await ciba.pollToken({ authReqId: "" }); } catch (e) { emptyId = e; }
    check("pollToken: empty authReqId refused", emptyId && emptyId.code === "auth-ciba/no-auth-req-id");

    // id_token signed by an unpublished key → verification fails closed.
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ access_token: "at", id_token: _mintIdToken(issuer, "req-forge", _rogue) });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var forged = null;
    try { await ciba.pollToken({ authReqId: "req-forge" }); }
    catch (e) { forged = e; }
    check("pollToken: id_token with unverifiable signature refused (fail-closed)",
          forged && forged.code === "auth-ciba/id-token-invalid");

    // id_token bound to a DIFFERENT auth_req_id → substitution refused.
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ access_token: "at", id_token: _mintIdToken(issuer, "req-OTHER") });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var mismatch = null;
    try { await ciba.pollToken({ authReqId: "req-mine" }); }
    catch (e) { mismatch = e; }
    check("pollToken: id_token bound to another auth_req_id refused (substitution)",
          mismatch && mismatch.code === "auth-ciba/id-token-authreqid-mismatch");
  });
}

// ---- slow_down back-off + terminal-error interval cleanup -------------

async function _runSlowDownAndTerminal() {
  // entry seeded via startAuthentication → slow_down honors an IdP-suggested
  // interval when it exceeds the minimum 5s bump.
  await _withIdp(async function (issuer, holder) {
    var ciba = _pollClient(issuer);
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-slow", expires_in: 300, interval: 5 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    await ciba.startAuthentication({ loginHint: "slow@example.com" });
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ error: "slow_down", interval: 20 });
      res.writeHead(400, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var slow = null;
    try { await ciba.pollToken({ authReqId: "req-slow" }); }
    catch (e) { slow = e; }
    check("pollToken: slow_down honors IdP-suggested interval over the 5s minimum bump",
          slow && slow.code === "auth-ciba/slow_down" && slow.nextIntervalSec === 20);
  });

  // entry seeded at the 300s ceiling → next bump is clamped to the max.
  await _withIdp(async function (issuer, holder) {
    var ciba = _pollClient(issuer);
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-cap", expires_in: 300, interval: 300 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    await ciba.startAuthentication({ loginHint: "cap@example.com" });
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ error: "slow_down" });
      res.writeHead(400, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var capped = null;
    try { await ciba.pollToken({ authReqId: "req-cap" }); }
    catch (e) { capped = e; }
    check("pollToken: slow_down bump clamped to the 300s ceiling",
          capped && capped.nextIntervalSec === 300);
  });

  // slow_down for an unseeded authReqId → bumps from the 5s default.
  await _withIdp(async function (issuer, holder) {
    var ciba = _pollClient(issuer);
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ error: "slow_down" });
      res.writeHead(400, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var unseeded = null;
    try { await ciba.pollToken({ authReqId: "never-started" }); }
    catch (e) { unseeded = e; }
    check("pollToken: slow_down on an unseeded authReqId bumps from the 5s default",
          unseeded && unseeded.nextIntervalSec === 10);
  });

  // terminal error clears the per-authReqId interval tracking.
  await _withIdp(async function (issuer, holder) {
    var ciba = _pollClient(issuer);
    holder.onBcAuth = function (body, res) {
      var s = JSON.stringify({ auth_req_id: "req-term", expires_in: 300, interval: 5 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    await ciba.startAuthentication({ loginHint: "term@example.com" });
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ error: "access_denied", error_description: "user rejected" });
      res.writeHead(400, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var terminal = null;
    try { await ciba.pollToken({ authReqId: "req-term" }); }
    catch (e) { terminal = e; }
    check("pollToken: terminal access_denied surfaced (interval entry cleared)",
          terminal && terminal.code === "auth-ciba/access_denied");
  });
}

// A tiny expires_in makes the auth_req_id's interval entry lapse before the
// next startAuthentication runs, driving _purgeExpiredIntervals' delete arm.
async function _runIntervalPurge() {
  await _withIdp(async function (issuer, holder) {
    var ciba = _pollClient(issuer);
    var n = 0;
    holder.onBcAuth = function (body, res) {
      n += 1;
      // First request registers an entry that has already lapsed by the time
      // the second request's opportunistic sweep runs (a full localhost
      // round-trip easily exceeds a sub-millisecond expiry).
      var expiresIn = n === 1 ? 0.0001 : 300;
      var s = JSON.stringify({ auth_req_id: "req-purge-" + n, expires_in: expiresIn, interval: 5 });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var first = await ciba.startAuthentication({ loginHint: "purge1@example.com" });
    var second = await ciba.startAuthentication({ loginHint: "purge2@example.com" });
    // A third register sees the (still-valid, 300s) req-purge-2 entry and
    // leaves it in place — the sweep's non-expired arm.
    var third = await ciba.startAuthentication({ loginHint: "purge3@example.com" });
    check("startAuthentication: expired entries purged, live entries retained across registers",
          first.authReqId === "req-purge-1" && second.authReqId === "req-purge-2" &&
          third.authReqId === "req-purge-3");
  });
}

// ---- parseNotification authentication + shape defenses ----------------

function _pushClient(issuer) {
  return b.auth.ciba.client.create({
    issuer: issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
    tokenEndpoint: issuer + "/token", backchannelAuthenticationEndpoint: issuer + "/bc-auth",
    deliveryMode: "push", clientNotificationToken: CNT, allowHttp: true, allowInternal: true,
  });
}

async function _runParseNotificationErrors() {
  await _withIdp(async function (issuer) {
    var ciba = _pushClient(issuer);
    async function _rejects(label, req, opts, code) {
      var err = null;
      try { await ciba.parseNotification(req, opts); } catch (e) { err = e; }
      check(label, err && err.code === code);
    }
    await _rejects("parseNotification: req without headers refused",
                   {}, {}, "auth-ciba/bad-notification-req");
    await _rejects("parseNotification: null req refused",
                   null, {}, "auth-ciba/bad-notification-req");
    await _rejects("parseNotification: missing Authorization header refused",
                   { headers: {} }, {}, "auth-ciba/missing-bearer");
    await _rejects("parseNotification: non-Bearer scheme refused",
                   { headers: { authorization: "Basic abc" } }, {}, "auth-ciba/missing-bearer");
    await _rejects("parseNotification: empty bearer token refused",
                   { headers: { authorization: "Bearer    " } }, {}, "auth-ciba/bad-bearer");
    await _rejects("parseNotification: wrong client_notification_token refused (timing-safe compare)",
                   { headers: { authorization: "Bearer " + CNT + "-tampered" } },
                   { body: { auth_req_id: "x" } }, "auth-ciba/wrong-bearer");
    // Authenticated but malformed body shapes.
    await _rejects("parseNotification: non-JSON string body refused",
                   { headers: { authorization: "Bearer " + CNT } },
                   { body: "<<not json>>" }, "auth-ciba/bad-notification-body");
    await _rejects("parseNotification: null body refused",
                   { headers: { authorization: "Bearer " + CNT } },
                   { body: null }, "auth-ciba/no-notification-body");
    await _rejects("parseNotification: body without auth_req_id refused",
                   { headers: { authorization: "Bearer " + CNT } },
                   { body: { access_token: "at" } }, "auth-ciba/no-auth-req-id-in-body");

    // A JSON *string* body is parsed then surfaced (middleware-parsed shape).
    var info = await ciba.parseNotification(
      { headers: { authorization: "Bearer " + CNT } },
      { body: JSON.stringify({ auth_req_id: "req-strbody", access_token: "str-at" }) });
    check("parseNotification: JSON string body parsed + surfaced",
          info && info.authReqId === "req-strbody" && info.accessToken === "str-at");

    // RFC 7235 §2.1 — the auth-scheme token is ASCII case-insensitive. A
    // spec-compliant sender using a lowercase or mixed-case "bearer" scheme
    // with the correct token must authenticate, not be refused as missing.
    var lowerScheme = await ciba.parseNotification(
      { headers: { authorization: "bearer " + CNT } },
      { body: { auth_req_id: "req-lower" } });
    check("parseNotification: lowercase 'bearer' scheme authenticates (RFC 7235 case-insensitive)",
          lowerScheme && lowerScheme.authReqId === "req-lower");
    var mixedScheme = await ciba.parseNotification(
      { headers: { authorization: "BeArEr " + CNT } },
      { body: { auth_req_id: "req-mixed" } });
    check("parseNotification: mixed-case 'BeArEr' scheme authenticates",
          mixedScheme && mixedScheme.authReqId === "req-mixed");

    // Push body carrying a forged (unverifiable) id_token → fail-closed.
    var forged = null;
    try {
      await ciba.parseNotification(
        { headers: { authorization: "Bearer " + CNT } },
        { body: { auth_req_id: "req-p", id_token: _mintIdToken(issuer, "req-p", _rogue) } });
    } catch (e) { forged = e; }
    check("parseNotification: forged pushed id_token refused (bearer authenticates caller, not token)",
          forged && forged.code === "auth-ciba/id-token-invalid");
  });
}

// ping mode: the callback body is just { auth_req_id } — no id_token, so the
// verified-claims field is null and the token fields default to null.
async function _runParseNotificationPing() {
  await _withIdp(async function (issuer) {
    var ciba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
      tokenEndpoint: issuer + "/token", backchannelAuthenticationEndpoint: issuer + "/bc-auth",
      deliveryMode: "ping", clientNotificationToken: CNT, allowHttp: true, allowInternal: true,
    });
    // No opts arg → the handler reads req.body directly (popts defaults to {}).
    var info = await ciba.parseNotification(
      { headers: { authorization: "Bearer " + CNT }, body: { auth_req_id: "req-ping-only" } });
    check("parseNotification(ping): bare { auth_req_id } surfaces authReqId, null tokens/claims",
          info && info.authReqId === "req-ping-only" && info.claims === null &&
          info.accessToken === null && info.idToken === null && info.expiresIn === null);

    // A numeric expires_in in a token-bearing body surfaces verbatim.
    var withExp = await ciba.parseNotification(
      { headers: { authorization: "Bearer " + CNT } },
      { body: { auth_req_id: "req-ping-exp", access_token: "at", expires_in: 1800 } });
    check("parseNotification: numeric expires_in surfaced", withExp.expiresIn === 1800);
  });
}

// Option defaults + no-argument entry points (defensive-reader tier: the
// handlers coerce a missing opts object to {} then reject on the real gap).
async function _runOptionDefaults() {
  await _withIdp(async function (issuer, holder) {
    // deliveryMode defaults to "poll" when omitted.
    var defCiba = b.auth.ciba.client.create({
      issuer: issuer, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
      tokenEndpoint: issuer + "/token", backchannelAuthenticationEndpoint: issuer + "/bc-auth",
      allowHttp: true, allowInternal: true,
    });
    check("create: deliveryMode defaults to poll", defCiba.deliveryMode === "poll");

    // startAuthentication() with no args → sopts coerced to {} → no-user-hint.
    var noArgsStart = null;
    try { await defCiba.startAuthentication(); } catch (e) { noArgsStart = e; }
    check("startAuthentication: no-argument call refused (no user hint)",
          noArgsStart && noArgsStart.code === "auth-ciba/no-user-hint");

    // pollToken() with no args → popts coerced to {} → no-auth-req-id.
    var noArgsPoll = null;
    try { await defCiba.pollToken(); } catch (e) { noArgsPoll = e; }
    check("pollToken: no-argument call refused (no authReqId)",
          noArgsPoll && noArgsPoll.code === "auth-ciba/no-auth-req-id");

    // A token response with NO access_token → accessToken defaults to null.
    holder.onToken = function (body, res) {
      var s = JSON.stringify({ refresh_token: "rt-only" });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(s) });
      res.end(s);
    };
    var noAt = await defCiba.pollToken({ authReqId: "req-noat" });
    check("pollToken: absent access_token defaults to null (refresh_token surfaced)",
          noAt.accessToken === null && noAt.refreshToken === "rt-only");
  });
}

async function _runTests() {
  await _runStartAuthenticationHappy();
  await _runPollTokenHappy();
  await _runParseNotificationHappy();
  _runCreateValidation();
  await _runStartAuthenticationBranches();
  await _runClientAuthModes();
  await _runNotificationTokenForwarding();
  await _runBindingMessageValidation();
  await _runPostFormErrors();
  await _runDiscovery();
  await _runPollTokenAdversarial();
  await _runSlowDownAndTerminal();
  await _runIntervalPurge();
  await _runParseNotificationErrors();
  await _runParseNotificationPing();
  await _runOptionDefaults();
}

async function run() {
  try { await _runTests(); }
  finally { await _drainTcpHandles(); }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK ciba — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); });
}

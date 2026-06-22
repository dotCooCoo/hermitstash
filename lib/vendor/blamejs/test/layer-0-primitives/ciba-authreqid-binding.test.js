"use strict";
/**
 * b.auth.ciba.client — the ID Token returned by a CIBA token response /
 * push notification MUST carry urn:openid:params:jwt:claim:auth_req_id, and the
 * RP MUST verify it equals the auth_req_id this flow used (OpenID CIBA Core
 * §7.3 / §10.1). Without it, an id_token minted for a DIFFERENT auth_req_id
 * (another user's CIBA flow at the same RP) can be substituted.
 *
 * Drives the real parseNotification (push) consumer path against a local OIDC
 * discovery + JWKS server, with an ES256-signed id_token.
 */

var http       = require("http");
var nodeCrypto = require("crypto");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var CLIENT_ID = "rp-ciba";
var KID       = "test-es256";
var CNT       = "client-notification-token-very-long-and-opaque-enough-for-ciba-min-entropy-padding";

var _kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
var _pubJwk = _kp.publicKey.export({ format: "jwk" });
_pubJwk.kid = KID; _pubJwk.alg = "ES256"; _pubJwk.use = "sig";

function _b64url(x) { return Buffer.from(x).toString("base64url"); }

function _mintIdToken(issuer, authReqIdClaim) {
  var header  = { alg: "ES256", kid: KID, typ: "JWT" };
  var now     = Math.floor(Date.now() / 1000);
  var payload = {
    iss: issuer, aud: CLIENT_ID, sub: "user-1", iat: now, exp: now + 3600,
  };
  if (authReqIdClaim !== undefined) payload["urn:openid:params:jwt:claim:auth_req_id"] = authReqIdClaim;
  var input = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
  var sig   = nodeCrypto.sign("sha256", Buffer.from(input), { key: _kp.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + _b64url(sig);
}

async function _withIdp(fn) {
  var holder = { issuer: null };
  var server = http.createServer(function (req, res) {
    var u = new URL(req.url, "http://localhost");
    if (u.pathname === "/.well-known/openid-configuration") {
      var doc = JSON.stringify({
        issuer: holder.issuer, authorization_endpoint: holder.issuer + "/auth",
        token_endpoint: holder.issuer + "/token", jwks_uri: holder.issuer + "/jwks",
      });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(doc) });
      res.end(doc); return;
    }
    if (u.pathname === "/jwks") {
      var jwks = JSON.stringify({ keys: [_pubJwk] });
      res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(jwks) });
      res.end(jwks); return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  holder.issuer = "http://127.0.0.1:" + server.address().port;
  try { return await fn(holder.issuer); }
  finally { await new Promise(function (r) { server.close(function () { r(); }); }); }
}

function _cibaClient(issuer) {
  return b.auth.ciba.client.create({
    issuer: issuer, clientId: CLIENT_ID,
    clientSecret: "ciba-client-secret-very-long-and-opaque-enough-for-min-entropy-guard-padding-xx",
    tokenEndpoint: issuer + "/token",
    backchannelAuthenticationEndpoint: issuer + "/bc-auth",
    deliveryMode: "push", clientNotificationToken: CNT,
    allowHttp: true, allowInternal: true,
  });
}

function _push(idToken, bodyAuthReqId) {
  return {
    req:  { headers: { authorization: "Bearer " + CNT } },
    opts: { body: { auth_req_id: bodyAuthReqId, access_token: "at", id_token: idToken } },
  };
}

async function run() {
  await _withIdp(async function (issuer) {
    var ciba = _cibaClient(issuer);

    // Matching auth_req_id claim → accepted.
    var okPush = _push(_mintIdToken(issuer, "req-AAA"), "req-AAA");
    var okInfo = await ciba.parseNotification(okPush.req, okPush.opts);
    check("parseNotification: id_token bound to the notification's auth_req_id is accepted",
          okInfo && okInfo.authReqId === "req-AAA" && okInfo.claims && okInfo.claims.claims &&
          okInfo.claims.claims["urn:openid:params:jwt:claim:auth_req_id"] === "req-AAA");

    // id_token minted for a DIFFERENT auth_req_id → refused (substitution).
    var badPush = _push(_mintIdToken(issuer, "req-BBB"), "req-AAA");
    var threwMismatch = null;
    try { await ciba.parseNotification(badPush.req, badPush.opts); }
    catch (e) { threwMismatch = e; }
    check("parseNotification: id_token for a different auth_req_id refused",
          threwMismatch && threwMismatch.code === "auth-ciba/id-token-authreqid-mismatch");

    // id_token with no auth_req_id claim → refused (MUST be present).
    var noClaimPush = _push(_mintIdToken(issuer, undefined), "req-AAA");
    var threwAbsent = null;
    try { await ciba.parseNotification(noClaimPush.req, noClaimPush.opts); }
    catch (e) { threwAbsent = e; }
    check("parseNotification: id_token missing the auth_req_id claim refused",
          threwAbsent && threwAbsent.code === "auth-ciba/id-token-authreqid-mismatch");

    // An EMPTY auth_req_id in the notification body must be refused outright —
    // otherwise it reaches the binding helper as a falsy expected value and the
    // substitution defense is skipped, so an id_token minted for ANOTHER flow
    // would be returned as trusted.
    var emptyPush = _push(_mintIdToken(issuer, "req-attacker"), "");
    var threwEmpty = null;
    try { await ciba.parseNotification(emptyPush.req, emptyPush.opts); }
    catch (e) { threwEmpty = e; }
    check("parseNotification: empty auth_req_id in the body is refused",
          threwEmpty && threwEmpty.code === "auth-ciba/no-auth-req-id-in-body");
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK ciba-authreqid-binding — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}

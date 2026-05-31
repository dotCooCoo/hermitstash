"use strict";
/**
 * Layer 0 — b.auth.jar.parse: RFC 9101 JWT-Secured Authorization
 * Request (server side). Verifies the client-signed request object
 * via verifyExternal (mandatory alg allowlist), pins iss + client_id
 * + aud, refuses nested request / request_uri, and returns the
 * authorization parameters. Request objects are signed inline with a
 * classical key (RS256) to mirror a real OAuth client.
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var nodeCrypto = require("node:crypto");

function _b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function _signRs256(privateKey, header, payload) {
  var input = _b64url(JSON.stringify(header)) + "." + _b64url(JSON.stringify(payload));
  var sig = nodeCrypto.sign("sha256", Buffer.from(input, "ascii"),
    { key: privateKey, padding: nodeCrypto.constants.RSA_PKCS1_PADDING });
  return input + "." + _b64url(sig);
}
function _rsaPair() {
  return nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength:      2048,
    publicKeyEncoding:  { type: "spki",  format: "jwk" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}
function _nowSec() { return Math.floor(Date.now() / 1000); }

var KEYS = _rsaPair();
var JWK = Object.assign({}, KEYS.publicKey, { kid: "c1", use: "sig", alg: "RS256" });
var AS = "https://as.example.com";
var CLIENT = "s6BhdRkqt3";

function _requestObject(extraClaims) {
  var payload = Object.assign({
    iss:           CLIENT,
    aud:           AS,
    client_id:     CLIENT,
    response_type: "code",
    redirect_uri:  "https://app.example.com/cb",
    scope:         "openid profile",
    state:         "xyz-state",
    nonce:         "n-0S6_WzA2Mj",
    iat:           _nowSec(),
    exp:           _nowSec() + 120,
  }, extraClaims || {});
  return _signRs256(KEYS.privateKey, { alg: "RS256", typ: "oauth-authz-req+jwt", kid: "c1" }, payload);
}

function _parseOpts(over) {
  var o = { clientId: CLIENT, audience: AS, algorithms: ["RS256"], jwks: [JWK] };
  if (over) { var k = Object.keys(over); for (var i = 0; i < k.length; i++) o[k[i]] = over[k[i]]; }
  return o;
}

async function testRoundTrip() {
  var jar = _requestObject();
  var out = await b.auth.jar.parse(jar, _parseOpts());
  check("parse: returns authorization params", out.params.response_type === "code" && out.params.redirect_uri === "https://app.example.com/cb");
  check("parse: preserves state + nonce + scope", out.params.state === "xyz-state" && out.params.nonce === "n-0S6_WzA2Mj" && out.params.scope === "openid profile");
  check("parse: strips JWT envelope claims from params", out.params.iss === undefined && out.params.aud === undefined && out.params.exp === undefined && out.params.iat === undefined);
  check("parse: full claims still available", out.claims.iss === CLIENT && out.claims.aud === AS);
}

async function testAntiNesting() {
  var withUri = _requestObject({ request_uri: "https://evil.example.com/ro" });
  var e1 = null;
  try { await b.auth.jar.parse(withUri, _parseOpts()); } catch (e) { e1 = e; }
  check("parse: nested request_uri refused (RFC 9101 §6.3)", e1 && e1.code === "auth-jar/nested-request");
  var withReq = _requestObject({ request: "ey.another.jwt" });
  var e2 = null;
  try { await b.auth.jar.parse(withReq, _parseOpts()); } catch (e) { e2 = e; }
  check("parse: nested request refused", e2 && e2.code === "auth-jar/nested-request");
}

async function testClientIdBinding() {
  // iss matches clientId, but the client_id claim differs → mismatch.
  var mismatched = _requestObject({ client_id: "different-client" });
  var e1 = null;
  try { await b.auth.jar.parse(mismatched, _parseOpts()); } catch (e) { e1 = e; }
  check("parse: client_id claim mismatch refused", e1 && e1.code === "auth-jar/client-id-mismatch");

  // iss itself differs from expected clientId → verifyExternal issuer pin throws.
  var wrongIss = _signRs256(KEYS.privateKey, { alg: "RS256", typ: "oauth-authz-req+jwt", kid: "c1" },
    { iss: "attacker-client", aud: AS, client_id: "attacker-client", response_type: "code",
      iat: _nowSec(), exp: _nowSec() + 120 });
  var e2 = null;
  try { await b.auth.jar.parse(wrongIss, _parseOpts()); } catch (e) { e2 = e; }
  check("parse: iss not matching expected client refused (verifyExternal issuer pin)", e2 !== null);

  // Codex P2 on PR #182 — a request object that OMITS client_id must
  // be refused (RFC 9101 §5.2 requires it in the signed object), not
  // waved through on the strength of an outer query-param client_id.
  var noClientId = _signRs256(KEYS.privateKey, { alg: "RS256", typ: "oauth-authz-req+jwt", kid: "c1" },
    { iss: CLIENT, aud: AS, response_type: "code", redirect_uri: "https://app/cb",
      iat: _nowSec(), exp: _nowSec() + 120 });
  var e3 = null;
  try { await b.auth.jar.parse(noClientId, _parseOpts()); } catch (e) { e3 = e; }
  check("parse: missing client_id claim refused (RFC 9101 §5.2)", e3 && e3.code === "auth-jar/missing-client-id");
}

async function testAlgConfusionDelegated() {
  var jar = _requestObject();
  // Valid RS256 JAR, but the AS only accepts HS256 → verifyExternal refuses the HMAC alg.
  var e1 = null;
  try { await b.auth.jar.parse(jar, _parseOpts({ algorithms: ["HS256"] })); } catch (e) { e1 = e; }
  check("parse: HMAC in the allowlist refused (alg-confusion defense delegated)", e1 && /refused-alg/.test(e1.code || ""));
  // Audience mismatch → verifyExternal aud pin throws.
  var e2 = null;
  try { await b.auth.jar.parse(jar, _parseOpts({ audience: "https://other-as.example.com" })); } catch (e) { e2 = e; }
  check("parse: audience mismatch refused", e2 !== null);
}

async function testValidation() {
  var bads = [
    [function () { return b.auth.jar.parse("", _parseOpts()); }, "auth-jar/no-jar"],
    [function () { return b.auth.jar.parse(_requestObject(), { audience: AS, algorithms: ["RS256"], jwks: [JWK] }); }, "auth-jar/bad-client-id"],
    [function () { return b.auth.jar.parse(_requestObject(), { clientId: CLIENT, algorithms: ["RS256"], jwks: [JWK] }); }, "auth-jar/bad-audience"],
  ];
  var ok = true;
  for (var i = 0; i < bads.length; i++) {
    var caught = null;
    try { await bads[i][0](); } catch (e) { caught = e; }
    if (!caught || caught.code !== bads[i][1]) { ok = false; check("validation case " + i + " expected " + bads[i][1] + " got " + (caught && caught.code), false); }
  }
  check("parse: malformed args throw the right codes", ok);
  // Missing algorithms → verifyExternal requires it (no defaults).
  var noAlg = null;
  try { await b.auth.jar.parse(_requestObject(), { clientId: CLIENT, audience: AS, jwks: [JWK] }); } catch (e) { noAlg = e; }
  check("parse: missing algorithms refused (verifyExternal — no alg defaults)", noAlg !== null);
}

// RFC 9101 §10.8 — the request object MUST be typed so a same-client JWT
// minted for another purpose can't be replayed as a request object.
async function testTypEnforcement() {
  function _withTyp(typ) {
    var payload = {
      iss: CLIENT, aud: AS, client_id: CLIENT, response_type: "code",
      redirect_uri: "https://app.example.com/cb",
      iat: _nowSec(), exp: _nowSec() + 120,
    };
    var header = { alg: "RS256", kid: "c1" };
    if (typ !== undefined) header.typ = typ;
    return _signRs256(KEYS.privateKey, header, payload);
  }
  var okBare = await b.auth.jar.parse(_withTyp("oauth-authz-req+jwt"), _parseOpts());
  check("parse: typ 'oauth-authz-req+jwt' accepted", okBare.params.response_type === "code");
  var okPrefixed = await b.auth.jar.parse(_withTyp("application/oauth-authz-req+jwt"), _parseOpts());
  check("parse: typ 'application/oauth-authz-req+jwt' accepted", okPrefixed.params.response_type === "code");

  var eWrong = null;
  try { await b.auth.jar.parse(_withTyp("JWT"), _parseOpts()); } catch (e) { eWrong = e; }
  check("parse: wrong typ refused (cross-JWT confusion, RFC 9101 §10.8)",
    eWrong && eWrong.code === "auth-jar/bad-typ");

  var eAbsent = null;
  try { await b.auth.jar.parse(_withTyp(undefined), _parseOpts()); } catch (e) { eAbsent = e; }
  check("parse: absent typ refused (strict)", eAbsent && eAbsent.code === "auth-jar/bad-typ");
}

async function run() {
  await testRoundTrip();
  await testAntiNesting();
  await testClientIdBinding();
  await testAlgConfusionDelegated();
  await testValidation();
  await testTypEnforcement();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[auth-jar] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

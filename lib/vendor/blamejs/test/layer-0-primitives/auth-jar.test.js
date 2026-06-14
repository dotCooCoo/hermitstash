"use strict";
/**
 * Layer 0 — b.auth.jar: RFC 9101 JWT-Secured Authorization Request.
 *
 * parse (server side) verifies the client-signed request object via
 * verifyExternal (mandatory alg allowlist), pins iss + client_id + aud,
 * refuses nested request / request_uri, and returns the authorization
 * parameters. Request objects are signed inline with a classical key
 * (RS256) to mirror a real OAuth client.
 *
 * build (client side) mints the request object via b.auth.jws.sign and
 * round-trips through parse as the verifying oracle across RS256 / PS256 /
 * ES256 / EdDSA; the anti-nesting, reserved-claim, required-param,
 * alg-key-mismatch, none-refusal, and exp-window paths are asserted.
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

// ---- b.auth.jar.build (RFC 9101 client side) ----

// Per-alg keypair generators. Public half as a JWK (kid c1) so jar.parse
// verifies the build output against it; private half as a KeyObject for the
// signer.
function _ecPair(curve, alg) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: curve });
  var jwk = Object.assign(kp.publicKey.export({ format: "jwk" }), { kid: "c1", use: "sig", alg: alg });
  return { privateKey: kp.privateKey, jwk: jwk };
}
function _rsaSigPair(alg) {
  var kp = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var jwk = Object.assign(kp.publicKey.export({ format: "jwk" }), { kid: "c1", use: "sig", alg: alg });
  return { privateKey: kp.privateKey, jwk: jwk };
}
function _edPair() {
  var kp = nodeCrypto.generateKeyPairSync("ed25519");
  var jwk = Object.assign(kp.publicKey.export({ format: "jwk" }), { kid: "c1", use: "sig", alg: "EdDSA" });
  return { privateKey: kp.privateKey, jwk: jwk };
}

function _buildParams(over) {
  var p = {
    response_type: "code",
    client_id:     CLIENT,
    redirect_uri:  "https://app.example.com/cb",
    scope:         "openid profile",
    state:         "xyz-state",
    nonce:         "n-0S6_WzA2Mj",
  };
  if (over) { var k = Object.keys(over); for (var i = 0; i < k.length; i++) p[k[i]] = over[k[i]]; }
  return p;
}

// build → parse round-trip across every classical alg family, using the
// in-repo jar.parse as the verifying oracle.
async function testBuildRoundTrip() {
  var cases = [
    { name: "RS256", pair: _rsaSigPair("RS256"), alg: "RS256" },
    { name: "PS256", pair: _rsaSigPair("PS256"), alg: "PS256" },
    { name: "ES256", pair: _ecPair("P-256", "ES256"), alg: "ES256" },
    { name: "EdDSA", pair: _edPair(), alg: "EdDSA" },
  ];
  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var ro = b.auth.jar.build(_buildParams(), {
      clientId: CLIENT, audience: AS, key: c.pair.privateKey, alg: c.alg, kid: "c1",
    });
    var hdr = JSON.parse(Buffer.from(ro.split(".")[0], "base64url").toString("utf8"));
    check("build[" + c.name + "]: header typ is oauth-authz-req+jwt", hdr.typ === "oauth-authz-req+jwt");
    check("build[" + c.name + "]: header alg matches the key", hdr.alg === c.alg);
    check("build[" + c.name + "]: header carries kid", hdr.kid === "c1");
    var out = await b.auth.jar.parse(ro, _parseOpts({ algorithms: [c.alg], jwks: [c.pair.jwk] }));
    check("build[" + c.name + "]: round-trips through parse — params preserved",
      out.params.response_type === "code" && out.params.redirect_uri === "https://app.example.com/cb" &&
      out.params.scope === "openid profile" && out.params.state === "xyz-state");
    check("build[" + c.name + "]: parse sees iss=clientId + aud=AS",
      out.claims.iss === CLIENT && out.claims.aud === AS);
    check("build[" + c.name + "]: builder minted jti + nbf + iat + exp",
      typeof out.claims.jti === "string" && typeof out.claims.nbf === "number" &&
      typeof out.claims.iat === "number" && typeof out.claims.exp === "number");
  }
}

// alg inferred from the key when no explicit alg is supplied.
async function testBuildAlgInference() {
  var ed = _edPair();
  var ro = b.auth.jar.build(_buildParams(), { clientId: CLIENT, audience: AS, key: ed.privateKey, kid: "c1" });
  var hdr = JSON.parse(Buffer.from(ro.split(".")[0], "base64url").toString("utf8"));
  check("build: Ed25519 key infers EdDSA alg (no explicit alg)", hdr.alg === "EdDSA");
  var out = await b.auth.jar.parse(ro, _parseOpts({ algorithms: ["EdDSA"], jwks: [ed.jwk] }));
  check("build: inferred-alg object verifies", out.params.response_type === "code");
}

// anti-nesting — params carrying request / request_uri refused at build.
async function testBuildAntiNesting() {
  var ec = _ecPair("P-256", "ES256");
  var e1 = null;
  try { b.auth.jar.build(_buildParams({ request: "ey.x.y" }), { clientId: CLIENT, audience: AS, key: ec.privateKey }); }
  catch (e) { e1 = e; }
  check("build: nested request refused (RFC 9101 §4)", e1 && e1.code === "auth-jar/nested-request");
  var e2 = null;
  try { b.auth.jar.build(_buildParams({ request_uri: "https://evil/ro" }), { clientId: CLIENT, audience: AS, key: ec.privateKey }); }
  catch (e) { e2 = e; }
  check("build: nested request_uri refused", e2 && e2.code === "auth-jar/nested-request");
}

// reserved-collision + required-param + client_id agreement refusals.
async function testBuildClaimRules() {
  var ec = _ecPair("P-256", "ES256");
  var opts = { clientId: CLIENT, audience: AS, key: ec.privateKey };
  var e1 = null;
  try { b.auth.jar.build(_buildParams({ iss: "evil" }), opts); } catch (e) { e1 = e; }
  check("build: params.iss collision refused (builder owns iss)", e1 && e1.code === "auth-jar/reserved-claim");
  var e2 = null;
  try { b.auth.jar.build(_buildParams({ exp: 123 }), opts); } catch (e) { e2 = e; }
  check("build: params.exp collision refused (builder mints exp)", e2 && e2.code === "auth-jar/reserved-claim");
  var e3 = null;
  var noRt = _buildParams(); delete noRt.response_type;
  try { b.auth.jar.build(noRt, opts); } catch (e) { e3 = e; }
  check("build: missing response_type refused (RFC 9101 §4)", e3 && e3.code === "auth-jar/missing-required-param");
  var e4 = null;
  try { b.auth.jar.build(_buildParams({ client_id: "different" }), opts); } catch (e) { e4 = e; }
  check("build: params.client_id != opts.clientId refused", e4 && e4.code === "auth-jar/client-id-mismatch");
}

// alg-key mismatch + `none` refusal (delegated to the jws signer).
async function testBuildAlgRefusals() {
  var ec = _ecPair("P-256", "ES256");
  var e1 = null;
  // a P-256 key cannot produce an RS256 signature.
  try { b.auth.jar.build(_buildParams(), { clientId: CLIENT, audience: AS, key: ec.privateKey, alg: "RS256" }); }
  catch (e) { e1 = e; }
  check("build: alg incompatible with key refused (ES key + RS256)",
    e1 && e1.code === "auth-jwt-external/sign-alg-key-mismatch");
  var e2 = null;
  try { b.auth.jar.build(_buildParams(), { clientId: CLIENT, audience: AS, key: ec.privateKey, alg: "none" }); }
  catch (e) { e2 = e; }
  check("build: alg 'none' refused", e2 && e2.code === "auth-jwt-external/sign-alg-refused");
  var e3 = null;
  try { b.auth.jar.build(_buildParams(), { clientId: CLIENT, audience: AS, key: ec.privateKey, alg: "HS256" }); }
  catch (e) { e3 = e; }
  check("build: HMAC alg refused", e3 && e3.code === "auth-jwt-external/sign-alg-refused");
}

// exp window honored — default 5m, operator override respected, and an
// already-expired window is refused by parse.
async function testBuildExpWindow() {
  var ec = _ecPair("P-256", "ES256");
  var defaultRo = b.auth.jar.build(_buildParams(), { clientId: CLIENT, audience: AS, key: ec.privateKey });
  var defaultClaims = JSON.parse(Buffer.from(defaultRo.split(".")[1], "base64url").toString("utf8"));
  var defaultTtl = defaultClaims.exp - defaultClaims.iat;
  check("build: default exp window is 5 minutes", defaultTtl === 300);

  var shortRo = b.auth.jar.build(_buildParams(), {
    clientId: CLIENT, audience: AS, key: ec.privateKey, kid: "c1", expiresInMs: 60 * 1000 });
  var shortClaims = JSON.parse(Buffer.from(shortRo.split(".")[1], "base64url").toString("utf8"));
  check("build: expiresInMs override honored (60s)", shortClaims.exp - shortClaims.iat === 60);

  // The minted window is a live exp parse enforces: a fresh object inside
  // the window verifies, and the same object handed to parse with a NEGATIVE
  // skew that pushes "now" past the exp is refused on the expired path —
  // proves the builder's exp reaches the verifier and is checked, not cosmetic.
  var liveRo = b.auth.jar.build(_buildParams(), {
    clientId: CLIENT, audience: AS, key: ec.privateKey, kid: "c1", expiresInMs: 60 * 1000 });
  var liveOut = await b.auth.jar.parse(liveRo, _parseOpts({ algorithms: ["ES256"], jwks: [ec.jwk], clockSkewMs: 0 }));
  check("build: object inside its exp window verifies", liveOut.params.response_type === "code");
  var eExp = null;
  try {
    await b.auth.jar.parse(liveRo, _parseOpts({ algorithms: ["ES256"], jwks: [ec.jwk], clockSkewMs: -120 * 1000 }));
  } catch (e) { eExp = e; }
  check("build: exp is enforced by parse (skew past exp refuses)", eExp && /expired/.test(eExp.code || ""));
}

// config-time opt validation.
async function testBuildValidation() {
  var ec = _ecPair("P-256", "ES256");
  var bads = [
    [function () { return b.auth.jar.build(null, { clientId: CLIENT, audience: AS, key: ec.privateKey }); }, "auth-jar/bad-params"],
    [function () { return b.auth.jar.build(_buildParams(), { audience: AS, key: ec.privateKey }); }, "auth-jar/bad-client-id"],
    [function () { return b.auth.jar.build(_buildParams(), { clientId: CLIENT, key: ec.privateKey }); }, "auth-jar/bad-audience"],
    [function () { return b.auth.jar.build(_buildParams(), { clientId: CLIENT, audience: AS }); }, "auth-jar/no-key"],
    [function () { return b.auth.jar.build(_buildParams(), { clientId: CLIENT, audience: AS, key: ec.privateKey, bogus: 1 }); }, null],
    [function () { return b.auth.jar.build(_buildParams(), { clientId: CLIENT, audience: AS, key: ec.privateKey, expiresInMs: -5 }); }, "auth-jar/bad-expiry"],
  ];
  var ok = true;
  for (var i = 0; i < bads.length; i++) {
    var caught = null;
    try { bads[i][0](); } catch (e) { caught = e; }
    var expected = bads[i][1];
    var pass = expected === null ? (caught !== null) : (caught && caught.code === expected);
    if (!pass) { ok = false; check("build validation case " + i + " expected " + expected + " got " + (caught && caught.code), false); }
  }
  check("build: malformed args throw the right codes", ok);
}

// A verified-but-hostile request object carrying a `__proto__` claim
// (JSON.parse materializes it as an own key; JSON.stringify round-trips
// it) must not graft onto the returned params object's prototype chain
// (CWE-1321). The signature is the client's own — signing hostile claim
// names is exactly what a malicious-but-registered client would do.
async function testProtoPollutionClaimInert() {
  var payload = JSON.parse(JSON.stringify({
    iss:           CLIENT,
    aud:           AS,
    client_id:     CLIENT,
    response_type: "code",
    iat:           _nowSec(),
    exp:           _nowSec() + 120,
  }).replace("\"response_type\"", "\"__proto__\":{\"polluted\":true},\"response_type\""));
  check("fixture: payload carries __proto__ as an own key",
        Object.prototype.hasOwnProperty.call(payload, "__proto__"));
  var jar = _signRs256(KEYS.privateKey,
    { alg: "RS256", typ: "oauth-authz-req+jwt", kid: "c1" }, payload);
  var out = await b.auth.jar.parse(jar, _parseOpts());
  check("parse: __proto__ claim does not graft onto params' prototype",
        Object.getPrototypeOf(out.params) === Object.prototype &&
        out.params.polluted === undefined);
  check("parse: __proto__ not copied as an own params key",
        !Object.prototype.hasOwnProperty.call(out.params, "__proto__"));
  check("parse: Object.prototype untouched",
        Object.prototype.polluted === undefined);
  check("parse: legitimate params still returned",
        out.params.response_type === "code");
}

async function run() {
  await testRoundTrip();
  await testAntiNesting();
  await testClientIdBinding();
  await testAlgConfusionDelegated();
  await testValidation();
  await testTypEnforcement();
  await testBuildRoundTrip();
  await testBuildAlgInference();
  await testBuildAntiNesting();
  await testBuildClaimRules();
  await testBuildAlgRefusals();
  await testBuildExpWindow();
  await testBuildValidation();
  await testProtoPollutionClaimInert();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[auth-jar] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

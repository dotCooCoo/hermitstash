"use strict";
/**
 * b.auth.oauth callback / JARM / refresh-rotation primitives (v0.8.70):
 *   - parseCallback   (RFC 9207 AS Issuer Identifier validation)
 *   - parseJarmResponse (OAuth 2.0 JARM signed authorization response)
 *   - refreshAccessToken seen() callback (RFC 9700 §4.13 / OAuth 2.1 §6.1)
 *   - authorizationUrl PKCE-downgrade refusal (RFC 9700 §4.13 / RFC 7636)
 */

var http    = require("node:http");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Minimal OIDC discovery server: serves /.well-known/openid-configuration
// with operator-chosen code_challenge_methods_supported so the PKCE
// downgrade gate runs against a real discovery round-trip.
function _spawnDiscoveryServer(methods) {
  var issuerHolder = { value: null };
  var server = http.createServer(function (req, res) {
    var u = new URL(req.url, "http://localhost");
    if (u.pathname !== "/.well-known/openid-configuration") { res.writeHead(404); res.end(); return; }
    var doc = {
      issuer:                 issuerHolder.value,
      authorization_endpoint: issuerHolder.value + "/auth",
      token_endpoint:         issuerHolder.value + "/token",
      jwks_uri:               issuerHolder.value + "/jwks",
    };
    if (methods !== undefined) doc.code_challenge_methods_supported = methods;
    var body = JSON.stringify(doc);
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
    res.end(body);
  });
  server._issuerHolder = issuerHolder;
  return server;
}

async function _pkceDowngradeCase(methods, expectRefusal, label) {
  var server = _spawnDiscoveryServer(methods);
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var issuer = "http://127.0.0.1:" + server.address().port;
  server._issuerHolder.value = issuer;
  try {
    var oa = b.auth.oauth.create({
      issuer:        issuer,
      clientId:      "rp-dl",
      redirectUri:   "https://rp.example/cb",
      isOidc:        true,
      allowHttp:     true,
      allowInternal: true,
    });
    var err = null;
    try { await oa.authorizationUrl(); } catch (e) { err = e; }
    if (expectRefusal) {
      check(label, err !== null && err.code === "auth-oauth/pkce-downgrade");
    } else {
      check(label, err === null);
    }
  } finally { server.close(); }
}

async function run() {
  var oauth = b.auth.oauth.create({
    issuer:        "https://idp.example",
    clientId:      "rp-1",
    clientSecret:  "test-secret",
    redirectUri:   "https://rp.example/cb",
    scope:         ["openid"],
    isOidc:        true,
    allowHttp:     true,
    allowInternal: true,
  });

  var rv = await oauth.parseCallback({ code: "abc123", state: "s1", iss: "https://idp.example" }, { expectedState: "s1" });
  check("oauth.parseCallback: happy path returns code+state",     rv.code === "abc123" && rv.state === "s1");

  var threw = false;
  try { await oauth.parseCallback({ code: "abc", iss: "https://attacker.example" }); }
  catch (e) { threw = /iss-mismatch-callback/.test(e.code) && /RFC 9207/.test(e.message); }
  check("oauth.parseCallback: iss mismatch refused (RFC 9207)",   threw);

  threw = false;
  try { await oauth.parseCallback({ error: "access_denied", error_description: "user said no" }); }
  catch (e) { threw = /op-error/.test(e.code); }
  check("oauth.parseCallback: OP error param refused",            threw);

  threw = false;
  try { await oauth.parseCallback({ code: "abc", state: "wrong" }, { expectedState: "expected" }); }
  catch (e) { threw = /state-mismatch/.test(e.code); }
  check("oauth.parseCallback: state mismatch refused (CSRF)",     threw);

  threw = false;
  try { await oauth.parseCallback({ code: "abc" }, { requireIssParam: true }); }
  catch (e) { threw = /missing-iss-callback/.test(e.code); }
  check("oauth.parseCallback: requireIssParam refuses missing iss", threw);

  threw = false;
  try { await oauth.parseJarmResponse(""); }
  catch (e) { threw = /no-jarm-response/.test(e.code); }
  check("oauth.parseJarmResponse: empty refused",                 threw);

  threw = false;
  try { await oauth.parseJarmResponse("not-a-jws"); }
  catch (e) { threw = /malformed-jarm-response/.test(e.code); }
  check("oauth.parseJarmResponse: non-3-segment refused",         threw);

  threw = false;
  try {
    await oauth.refreshAccessToken("rt-1", { seen: async function () { return true; } });
  } catch (e) { threw = /refresh-token-replay/.test(e.code); }
  check("oauth.refreshAccessToken: seen()=true refuses replay",   threw);

  // PKCE downgrade defense (RFC 9700 §4.13 / RFC 7636). An OP whose
  // discovery metadata advertises code_challenge_methods_supported
  // without "S256" is refused at authorizationUrl; S256-capable or
  // field-absent OPs keep working (back-compat).
  await _pkceDowngradeCase(["plain"], true,
    "oauth.authorizationUrl: plain-only OP refused (PKCE downgrade)");
  await _pkceDowngradeCase([], true,
    "oauth.authorizationUrl: empty methods list refused (no S256)");
  await _pkceDowngradeCase(["S256"], false,
    "oauth.authorizationUrl: S256-only OP accepted");
  await _pkceDowngradeCase(["S256", "plain"], false,
    "oauth.authorizationUrl: S256+plain OP accepted");
  await _pkceDowngradeCase(undefined, false,
    "oauth.authorizationUrl: field-absent OP accepted (back-compat)");

  // Static-endpoint client with no discovery must never gain a network
  // fetch or a downgrade refusal — the gate only inspects already-
  // resolved discovery metadata.
  var oaStatic = b.auth.oauth.create({
    issuer:                "https://static.example",
    clientId:              "rp-static",
    redirectUri:           "https://rp.example/cb",
    isOidc:                true,
    authorizationEndpoint: "https://static.example/auth",
    tokenEndpoint:         "https://static.example/token",
  });
  var staticErr = null;
  try { await oaStatic.authorizationUrl(); } catch (e) { staticErr = e; }
  check("oauth.authorizationUrl: static endpoints skip discovery (no fetch, no refusal)",
        staticErr === null);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

"use strict";
// b.csp — CSP3 header builder + nonce/hash helpers.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var DEFAULT_CSP = require("../../lib/middleware/security-headers").DEFAULT_CSP;

// Every directive the framework's own DEFAULT_CSP emits must be a
// directive b.csp.build recognizes — otherwise the default policy can't
// round-trip through the builder (regression: fenced-frame-src shipped in
// DEFAULT_CSP but was missing from ALL_DIRECTIVES).
function testDefaultCspRoundTrips() {
  var directives = {};
  DEFAULT_CSP.split(";").forEach(function (part) {
    var tokens = part.trim().split(/\s+/);
    if (!tokens[0]) return;
    directives[tokens[0]] = tokens.slice(1);
  });
  check("DEFAULT_CSP names fenced-frame-src", Object.prototype.hasOwnProperty.call(directives, "fenced-frame-src"));
  var threw = null;
  try { b.csp.build(directives, { acknowledgeUnsafe: true, allowDataImages: true, trustedTypesPolicies: ["default"] }); }
  catch (e) { threw = e.code + ": " + e.message; }
  check("DEFAULT_CSP round-trips through b.csp.build", threw === null);
}

function testWebrtcDirective() {
  var policy = b.csp.build({ "default-src": ["'self'"], "webrtc": ["'block'"] });
  check("csp.build accepts webrtc directive", policy.indexOf("webrtc 'block'") !== -1);
}

function testBuild() {
  var policy = b.csp.build({
    "default-src":     ["'self'"],
    "script-src":      ["'self'"],
    "img-src":         ["'self'"],
    "object-src":      ["'none'"],
    "base-uri":        ["'self'"],
    "frame-ancestors": ["'none'"],
  });
  check("csp.build returns a string",          typeof policy === "string");
  check("csp.build emits default-src",         policy.indexOf("default-src 'self'") !== -1);
  check("csp.build auto-adds Trusted Types",   policy.indexOf("require-trusted-types-for 'script'") !== -1);
}

function testRefusesUnsafeKeywords() {
  var threw = null;
  try { b.csp.build({ "script-src": ["'self'", "'unsafe-inline'"] }); }
  catch (e) { threw = e.code; }
  check("csp.build refuses 'unsafe-inline'", threw === "csp/unsafe-keyword");
}

function testRefusesCatchAll() {
  var threw = null;
  try { b.csp.build({ "default-src": ["*"] }); }
  catch (e) { threw = e.code; }
  check("csp.build refuses '*' source", threw === "csp/catch-all-source");
}

function testRefusesDataInImg() {
  var threw = null;
  try { b.csp.build({ "img-src": ["'self'", "data:"] }); }
  catch (e) { threw = e.code; }
  check("csp.build refuses data: in img-src", threw === "csp/data-source");
  // allowDataImages opt unblocks
  var policy = b.csp.build({ "img-src": ["'self'", "data:"] }, { allowDataImages: true });
  check("csp.build accepts data: with allowDataImages",
    policy.indexOf("img-src 'self' data:") !== -1);
}

function testRefusesUnknownDirective() {
  var threw = null;
  try { b.csp.build({ "not-a-real-directive": ["'self'"] }); }
  catch (e) { threw = e.code; }
  check("csp.build refuses unknown directive", threw === "csp/unknown-directive");
}

function testNonce() {
  var n = b.csp.nonce();
  check("csp.nonce returns a string",          typeof n === "string");
  check("csp.nonce is base64url-shaped",       /^[A-Za-z0-9_-]+$/.test(n));
  check("csp.nonce is >= 22 chars (128 bits)", n.length >= 22);                                  // allow:raw-byte-literal — 128/6 rounded up
  var threw = null;
  try { b.csp.nonce(8); } catch (e) { threw = e.code; }
  check("csp.nonce refuses < 16-byte length", threw === "csp/bad-nonce-len");
}

function testHash() {
  var src = b.csp.hash("console.log('boot');");
  check("csp.hash returns sha384 by default",
    src.indexOf("'sha384-") === 0 && src.charAt(src.length - 1) === "'");
  var sha256 = b.csp.hash("console.log('boot');", "sha256");
  check("csp.hash supports sha256", sha256.indexOf("'sha256-") === 0);
  var threw = null;
  try { b.csp.hash("x", "md5"); } catch (e) { threw = e.code; }
  check("csp.hash refuses md5", threw === "csp/bad-hash-alg");
}

function testCspErrorClass() {
  check("CspError exported", typeof b.csp.CspError === "function");
  var e = new b.csp.CspError("csp/test", "synthetic");
  check("CspError carries code", e.code === "csp/test");
}

function run() {
  testDefaultCspRoundTrips();
  testWebrtcDirective();
  testBuild();
  testRefusesUnsafeKeywords();
  testRefusesCatchAll();
  testRefusesDataInImg();
  testRefusesUnknownDirective();
  testNonce();
  testHash();
  testCspErrorClass();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };

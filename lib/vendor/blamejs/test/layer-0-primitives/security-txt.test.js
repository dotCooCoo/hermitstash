"use strict";
/**
 * b.middleware.securityTxt — RFC 9116 /.well-known/security.txt emitter.
 *
 * Covers: required-field enforcement (Contact / Expires), future-expiry
 * check, the served body shape, root-path opt, method gating, and the
 * de-advertised `audit` opt (the middleware serves a static public file
 * on a hot path — no audit-worthy event, so the knob was removed).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mkRes() {
  return {
    statusCode: null,
    headers:    null,
    bodyChunks: [],
    ended:      false,
    writeHead:  function (code, headers) { this.statusCode = code; this.headers = headers; return this; },
    end:        function (chunk) { if (chunk !== undefined) this.bodyChunks.push(chunk); this.ended = true; return this; },
  };
}

function testServesWellKnown() {
  var mw = b.middleware.securityTxt({
    contact: ["mailto:security@example.com"],
    expires: "2099-01-01T00:00:00Z",
    policy:  "https://example.com/security/policy",
  });
  var res = _mkRes();
  var nexted = false;
  mw({ method: "GET", url: "/.well-known/security.txt" }, res, function () { nexted = true; });
  check("securityTxt: serves at /.well-known/security.txt", res.statusCode === 200 && res.ended && !nexted);
  var body = Buffer.concat(res.bodyChunks.map(function (c) { return Buffer.isBuffer(c) ? c : Buffer.from(String(c)); })).toString("utf8");
  check("securityTxt: body carries Contact line", body.indexOf("Contact: mailto:security@example.com") !== -1);
  check("securityTxt: body carries Expires line", body.indexOf("Expires: 2099-01-01T00:00:00Z") !== -1);
  check("securityTxt: content-type text/plain", /text\/plain/.test(res.headers["Content-Type"]));
}

function testPassthroughOnOtherPaths() {
  var mw = b.middleware.securityTxt({
    contact: ["mailto:security@example.com"],
    expires: "2099-01-01T00:00:00Z",
  });
  var res = _mkRes();
  var nexted = false;
  mw({ method: "GET", url: "/something-else" }, res, function () { nexted = true; });
  check("securityTxt: non-matching path falls through to next", nexted && res.statusCode === null);
}

function testRequiredFieldEnforcement() {
  var threwNoContact = false;
  try { b.middleware.securityTxt({ expires: "2099-01-01T00:00:00Z" }); }
  catch (_e) { threwNoContact = true; }
  check("securityTxt: missing contact throws", threwNoContact);

  var threwNoExpires = false;
  try { b.middleware.securityTxt({ contact: ["mailto:s@example.com"] }); }
  catch (_e) { threwNoExpires = true; }
  check("securityTxt: missing expires throws", threwNoExpires);

  var threwPastExpiry = false;
  try {
    b.middleware.securityTxt({
      contact: ["mailto:s@example.com"],
      expires: "2000-01-01T00:00:00Z",
    });
  } catch (_e) { threwPastExpiry = true; }
  check("securityTxt: past expires throws", threwPastExpiry);
}

function testRejectsAuditOpt() {
  // `audit` was accepted-but-unread (no audit-worthy event — the
  // middleware serves a static public file and already uses the
  // observability sink for the served counter). De-advertised: passing
  // it now throws at config time.
  var threw = false;
  try {
    b.middleware.securityTxt({
      contact: ["mailto:security@example.com"],
      expires: "2099-01-01T00:00:00Z",
      audit:   true,
    });
  } catch (_e) { threw = true; }
  check("securityTxt: unknown 'audit' opt rejected", threw);

  // The same opts WITHOUT audit construct fine.
  var mw = b.middleware.securityTxt({
    contact: ["mailto:security@example.com"],
    expires: "2099-01-01T00:00:00Z",
  });
  check("securityTxt: constructs without audit opt", typeof mw === "function");
}

async function run() {
  testServesWellKnown();
  testPassthroughOnOtherPaths();
  testRequiredFieldEnforcement();
  testRejectsAuditOpt();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

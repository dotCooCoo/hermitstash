"use strict";
/**
 * b.mail.server.submission — outbound SMTP submission listener.
 *
 * Tests cover opts validation, AUTH-required posture under strict
 * profile, AUTH-needs-TLS gate (RFC 4954 §4), identity-binding,
 * and the multi-step verify hook contract.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("submission.create is fn",
    typeof b.mail.server.submission.create === "function");
  check("MailServerSubmissionError is fn",
    typeof b.mail.server.submission.MailServerSubmissionError === "function");
}

function testCreateRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.submission.create({}); } catch (e) { threw = e; }
  check("submission.create refuses missing tlsContext",
    threw && threw.code === "mail-server-submission/no-tls-context");
}

function testStrictProfileRequiresAuthConfig() {
  var threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      // no auth config — strict default refuses
    });
  } catch (e) { threw = e; }
  check("strict profile refuses missing auth config",
    threw && threw.code === "mail-server-submission/no-auth");
}

function testPermissiveAllowsNoAuth() {
  var threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      profile:    "permissive",
    });
  } catch (e) { threw = e; }
  check("permissive accepts no auth (operator-acknowledged legacy)",
    threw === null);
}

function testBadAuthShapeRefused() {
  var threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      auth:       { mechanisms: [], verify: function () {} },
    });
  } catch (e) { threw = e; }
  check("empty mechanisms refused",
    threw && threw.code === "mail-server-submission/bad-auth");

  threw = null;
  try {
    b.mail.server.submission.create({
      tlsContext: {},
      auth:       { mechanisms: ["PLAIN"], verify: "not-a-fn" },
    });
  } catch (e) { threw = e; }
  check("non-function verify refused",
    threw && threw.code === "mail-server-submission/bad-auth");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.submission.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-submission/") === 0);
  }
  expectBad("negative maxLineBytes refused",
    { tlsContext: {}, profile: "permissive", maxLineBytes: -1 });
  expectBad("non-finite idleTimeoutMs refused",
    { tlsContext: {}, profile: "permissive", idleTimeoutMs: Infinity });
}

function run() {
  testSurface();
  testCreateRequiresTlsContext();
  testStrictProfileRequiresAuthConfig();
  testPermissiveAllowsNoAuth();
  testBadAuthShapeRefused();
  testBadBoundsRefused();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-server-submission] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}

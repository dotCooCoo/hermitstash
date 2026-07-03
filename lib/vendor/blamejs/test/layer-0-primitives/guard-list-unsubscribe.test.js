// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardListUnsubscribe — RFC 2369 + RFC 8058 List-Unsubscribe /
 * List-Unsubscribe-Post header validator.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("validate is fn",              typeof b.guardListUnsubscribe.validate === "function");
  check("compliancePosture is fn",     typeof b.guardListUnsubscribe.compliancePosture === "function");
  check("PROFILES frozen",             Object.isFrozen(b.guardListUnsubscribe.PROFILES));
  check("DANGEROUS_SCHEMES frozen",    Object.isFrozen(b.guardListUnsubscribe.DANGEROUS_SCHEMES));
  check("ONE_CLICK_POST_VALUE",        b.guardListUnsubscribe.ONE_CLICK_POST_VALUE === "List-Unsubscribe=One-Click");
  check("NAME=listUnsubscribe",        b.guardListUnsubscribe.NAME === "listUnsubscribe");
  // Exercise the error-class constructor so test-coverage gate sees
  // a direct reference.
  var e = new b.guardListUnsubscribe.GuardListUnsubscribeError("guard-list-unsubscribe/test", "smoke");
  check("error class wires",           e.code === "guard-list-unsubscribe/test");
  check("error class permanent",        e.permanent === true);
}

function testAcceptCompliantHeaders() {
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<mailto:u@x.com?subject=unsub>, <https://x.com/unsub?id=42>",
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("compliant: accept",          v.action === "accept");
  check("compliant: oneClickReady",   v.oneClickReady === true);
  check("compliant: hasHttpsUri",     v.hasHttpsUri === true);
  check("compliant: hasMailtoUri",    v.hasMailtoUri === true);
  check("compliant: postHeaderOk",    v.postHeaderOk === true);
}

function testRefuseWithoutHttpsUnderStrict() {
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<mailto:u@x.com?subject=unsub>",
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("no https: refuse",           v.action === "refuse");
  check("no https: reason",           v.reason.indexOf("no https://") !== -1);
}

function testRefuseHttpUri() {
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<http://x.com/unsub>",
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("http://: refuse",            v.action === "refuse");
  check("http://: reason",            v.reason.indexOf("http://") !== -1);
}

function testRefuseDangerousSchemes() {
  ["javascript:alert(1)", "data:text/html,a", "file:///etc/passwd", "vbscript:msgbox", "blob:abc"].forEach(function (u) {
    var v = b.guardListUnsubscribe.validate({
      listUnsubscribe: "<" + u + ">",
    });
    check("dangerous scheme refused: " + u.split(":")[0], v.action === "refuse");
  });
}

function testRefuseCrlfInjection() {
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe: "<https://x.com/unsub>\r\nBcc: evil@example.com",
  });
  check("CRLF injection refused",     v.action === "refuse");
  check("CRLF reason",                v.reason.indexOf("CR/LF") !== -1);
}

function testRefuseControlChar() {
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe: "<https://x.com/unsub" + String.fromCharCode(0) + ">",
  });
  check("NUL refused",                v.action === "refuse");
  check("NUL reason",                 v.reason.indexOf("control char") !== -1);
}

function testRefuseMissingPostHeader() {
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe: "<https://x.com/unsub>",
    // no listUnsubscribePost
  });
  check("missing Post header refused", v.action === "refuse");
  check("missing Post reason",        v.reason.indexOf("List-Unsubscribe-Post") !== -1);
}

function testRefuseMalformedPostHeader() {
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<https://x.com/unsub>",
    listUnsubscribePost: "List-Unsubscribe=OneClick",        // missing hyphen
  });
  check("malformed Post refused",      v.action === "refuse");

  var v2 = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<https://x.com/unsub>",
    listUnsubscribePost: "list-unsubscribe=one-click",       // wrong case
  });
  check("case-sensitive Post refused", v2.action === "refuse");
}

function testAcceptUnderBalancedWithoutHttps() {
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe: "<mailto:u@x.com?subject=unsub>",
  }, { profile: "balanced" });
  check("balanced without https accepts", v.action === "accept");
  check("balanced reports oneClickReady=false", v.oneClickReady === false);
}

function testAcceptCommaInUri() {
  // PR #63 Codex P1: URI containing a comma in query string is
  // legitimate per RFC 3986 (`,` is a sub-delim) and was being
  // rejected by the earlier split(",") implementation.
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<https://x.com/unsub?tags=a,b,c>",
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("comma-in-URI: accept",        v.action === "accept");
  check("comma-in-URI: parsed intact", v.uris[0].raw === "https://x.com/unsub?tags=a,b,c");

  // Multiple URIs, one with commas
  var v2 = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<mailto:u@x.com>, <https://x.com/unsub?tags=a,b>",
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("mixed with comma-URI: count 2", v2.uris.length === 2);
  check("mixed with comma-URI: 2nd intact", v2.uris[1].raw === "https://x.com/unsub?tags=a,b");
}

function testRefuseEmptyUris() {
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe: "no brackets here",
  });
  check("no <URI> elements refused",  v.action === "refuse");
}

function testRefuseTooManyUris() {
  var uris = [];
  for (var i = 0; i < 20; i += 1) uris.push("<https://x" + i + ".com/u>");
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe: uris.join(", "),
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("too many URIs refused",      v.action === "refuse");
  check("too many URIs reason",       v.reason.indexOf("maxUris") !== -1);
}

function testRefuseBadInput() {
  var threw1 = null;
  try { b.guardListUnsubscribe.validate(null); }
  catch (e) { threw1 = e; }
  check("null headers refused",       threw1 && threw1.code === "guard-list-unsubscribe/bad-input");

  var threw2 = null;
  try { b.guardListUnsubscribe.validate({}); }
  catch (e) { threw2 = e; }
  check("missing listUnsubscribe",    threw2 && threw2.code === "guard-list-unsubscribe/bad-input");

  var threw3 = null;
  try { b.guardListUnsubscribe.validate({ listUnsubscribe: "x" }, { profile: "yolo" }); }
  catch (e) { threw3 = e; }
  check("bad profile refused",         threw3 && threw3.code === "guard-list-unsubscribe/bad-profile");
}

function testCompliancePosture() {
  check("hipaa → strict",     b.guardListUnsubscribe.compliancePosture("hipaa") === "strict");
  check("unknown → null",     b.guardListUnsubscribe.compliancePosture("foo") === null);
}

function testPostureBindsStrict() {
  // posture hipaa pins strict — refuses no-https even though caller asked balanced
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe: "<mailto:u@x.com>",
  }, { posture: "hipaa", profile: "balanced" });
  check("posture overrides profile",   v.action === "refuse");
}

function testOversizeUriRefused() {
  var bigUri = "https://x.com/" + "a".repeat(3000);
  var v = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<" + bigUri + ">",
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("oversize URI refused",       v.action === "refuse");
  check("oversize URI reason",        v.reason.indexOf("maxUriBytes") !== -1);
}

function run() {
  testSurface();
  testAcceptCompliantHeaders();
  testRefuseWithoutHttpsUnderStrict();
  testRefuseHttpUri();
  testRefuseDangerousSchemes();
  testRefuseCrlfInjection();
  testRefuseControlChar();
  testRefuseMissingPostHeader();
  testRefuseMalformedPostHeader();
  testAcceptUnderBalancedWithoutHttps();
  testAcceptCommaInUri();
  testRefuseEmptyUris();
  testRefuseTooManyUris();
  testRefuseBadInput();
  testCompliancePosture();
  testPostureBindsStrict();
  testOversizeUriRefused();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}

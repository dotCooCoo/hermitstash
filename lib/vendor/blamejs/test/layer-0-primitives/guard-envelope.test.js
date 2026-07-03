// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardEnvelope — RFC 7489 §3.1 DMARC Identifier Alignment.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("check is fn",                typeof b.guardEnvelope.check === "function");
  check("compliancePosture is fn",    typeof b.guardEnvelope.compliancePosture === "function");
  check("PROFILES frozen",            Object.isFrozen(b.guardEnvelope.PROFILES));
  check("GuardEnvelopeError is fn",   typeof b.guardEnvelope.GuardEnvelopeError === "function");
  check("NAME=envelope",              b.guardEnvelope.NAME === "envelope");
}

function testStrictAlignmentExactMatch() {
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "example.com",
    spfResult:        { result: "pass", domain: "example.com" },
    dkimResults:      [{ result: "pass", signingDomain: "example.com" }],
  }, { spfMode: "strict", dkimMode: "strict" });
  check("strict-exact spf aligned",   v.spf.aligned === true);
  check("strict-exact dkim aligned",  v.dkim[0].aligned === true);
  check("strict-exact action accept", v.action === "accept");
}

function testStrictAlignmentSubdomainRefused() {
  // Strict mode: bounces.example.com vs example.com → refused.
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "example.com",
    spfResult:        { result: "pass", domain: "bounces.example.com" },
    dkimResults:      [],
  }, { spfMode: "strict", profile: "strict" });
  check("strict-subdomain SPF NOT aligned", v.spf.aligned === false);
  check("strict-subdomain action refuse",    v.action === "refuse");
}

function testRelaxedAlignmentSubdomainAccepted() {
  // Relaxed mode (default): same organizational domain.
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "alerts.news.example.com",
    spfResult:        { result: "pass", domain: "bounces.example.com" },
    dkimResults:      [],
  });
  check("relaxed-subdomain SPF aligned", v.spf.aligned === true);
  check("relaxed action accept",         v.action === "accept");
}

function testCrossOrgDomainRefused() {
  // example.com vs example.org — different orgs → fail.
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "example.com",
    spfResult:        { result: "pass", domain: "evil.example.org" },
    dkimResults:      [],
  });
  check("cross-org SPF not aligned",  v.spf.aligned === false);
  check("cross-org action refuse",    v.action === "refuse");
}

function testSpfFailDoesNotAlign() {
  // SPF result not "pass" → not aligned regardless of domain match.
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "example.com",
    spfResult:        { result: "fail", domain: "example.com" },
    dkimResults:      [],
  });
  check("spf-fail not aligned",       v.spf.aligned === false);
  check("spf-fail spfPass=false",     v.spf.spfPass === false);
  check("spf-fail action refuse",     v.action === "refuse");
}

function testDkimAlignmentOneSignerSufficient() {
  // One of multiple DKIM signers aligned → overall aligned.
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "example.com",
    spfResult:        { result: "fail", domain: "example.com" },
    dkimResults:      [
      { result: "fail", signingDomain: "evil.org" },
      { result: "pass", signingDomain: "example.com" },
    ],
  });
  check("dkim one aligned → overall aligned", v.aligned === true);
  check("action accept",              v.action === "accept");
  check("dkim[0] not aligned",        v.dkim[0].aligned === false);
  check("dkim[1] aligned",            v.dkim[1].aligned === true);
}

function testPublicSuffixConfusionRefused() {
  // Attacker can't claim "co.uk" as their org domain — PSL says co.uk
  // IS a public suffix, so the org-domain lookup returns null.
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "victim.co.uk",
    spfResult:        { result: "pass", domain: "attacker.co.uk" },
    dkimResults:      [],
  });
  // victim.co.uk and attacker.co.uk DO have the same effective TLD+1
  // structure, but their org domains are 'victim.co.uk' vs
  // 'attacker.co.uk' — DIFFERENT orgs.
  check("psl-confusion victim vs attacker not aligned", v.spf.aligned === false);
}

function testEmptyDkimList() {
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "example.com",
    spfResult:        { result: "pass", domain: "example.com" },
  });
  check("no dkim list defaults to empty",   v.dkim.length === 0);
  check("spf alone can align",              v.aligned === true);
}

function testPermissiveAlwaysAccepts() {
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "example.com",
    spfResult:        { result: "fail", domain: "evil.org" },
    dkimResults:      [],
  }, { profile: "permissive" });
  check("permissive: aligned=false",        v.aligned === false);
  check("permissive: action=accept anyway", v.action === "accept");
}

function testPostureBindsStrict() {
  // hipaa posture pins strict (gateOnFailure=true).
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "example.com",
    spfResult:        { result: "fail", domain: "evil.org" },
    dkimResults:      [],
  }, { posture: "hipaa" });
  check("hipaa posture refuses misalignment", v.action === "refuse");
}

function testBadInputRefused() {
  var threw1 = null;
  try { b.guardEnvelope.check(null); }
  catch (e) { threw1 = e; }
  check("null ctx refused",           threw1 && threw1.code === "guard-envelope/bad-input");

  var threw2 = null;
  try { b.guardEnvelope.check({ fromHeaderDomain: "" }); }
  catch (e) { threw2 = e; }
  check("empty fromHeaderDomain refused", threw2 && threw2.code === "guard-envelope/bad-input");

  var threw3 = null;
  try { b.guardEnvelope.check({ fromHeaderDomain: "x.com" }, { spfMode: "yolo" }); }
  catch (e) { threw3 = e; }
  check("bad spfMode refused",        threw3 && threw3.code === "guard-envelope/bad-mode");

  var threw4 = null;
  try { b.guardEnvelope.check({ fromHeaderDomain: "x.com" }, { profile: "yolo" }); }
  catch (e) { threw4 = e; }
  check("bad profile refused",        threw4 && threw4.code === "guard-envelope/bad-profile");
}

function testCompliancePosture() {
  check("hipaa → strict",     b.guardEnvelope.compliancePosture("hipaa") === "strict");
  check("unknown → null",     b.guardEnvelope.compliancePosture("foo") === null);
}

function testCaseInsensitive() {
  // RFC 7489 §3.1 — domain comparison is case-insensitive.
  var v = b.guardEnvelope.check({
    fromHeaderDomain: "EXAMPLE.COM",
    spfResult:        { result: "pass", domain: "Example.Com" },
    dkimResults:      [],
  }, { spfMode: "strict" });
  check("case-insensitive strict match",  v.spf.aligned === true);
}

function run() {
  testSurface();
  testStrictAlignmentExactMatch();
  testStrictAlignmentSubdomainRefused();
  testRelaxedAlignmentSubdomainAccepted();
  testCrossOrgDomainRefused();
  testSpfFailDoesNotAlign();
  testDkimAlignmentOneSignerSufficient();
  testPublicSuffixConfusionRefused();
  testEmptyDkimList();
  testPermissiveAlwaysAccepts();
  testPostureBindsStrict();
  testBadInputRefused();
  testCompliancePosture();
  testCaseInsensitive();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}

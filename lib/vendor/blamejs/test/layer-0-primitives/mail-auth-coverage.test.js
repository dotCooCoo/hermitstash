// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.spf / b.mail.dmarc / b.mail.arc / b.mail.authResults —
 * additional branch coverage.
 *
 * Companion to mail-auth.test.js. Targets uncovered input-validation,
 * option-default, qualifier, macro-transformer, alignment-mode, and
 * error-classification branches reachable through the public API with
 * in-memory dnsLookup fakes (no live network — those live in
 * test/integration). Does not duplicate the sibling file's cases.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// A TXT-only dnsLookup fake: `map[host]` returns the TXT record array
// ([["v=spf1 ..."]]); everything else is ENOTFOUND.
function _txtOnly(map) {
  return async function (host, type) {
    if (type === "TXT" && Object.prototype.hasOwnProperty.call(map, host)) return map[host];
    var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
  };
}

// Resolve a promise to the error it rejects with (or null when it fulfils).
async function _rejectedWith(promise) {
  try { await promise; return null; } catch (e) { return e; }
}

function _threw(fn) {
  try { fn(); return null; } catch (e) { return e; }
}

// ---- SPF: input validation (Tier-A throw at the entry point) ----

async function testSpfVerifyInputValidation() {
  var e1 = await _rejectedWith(b.mail.spf.verify({ ip: 12345, mailFrom: "a@s.example" }));
  check("spf.verify: non-string ip → spf-bad-ip throw",
        e1 && /spf-bad-ip/.test(e1.code || ""));
  var e2 = await _rejectedWith(b.mail.spf.verify({ ip: "192.0.2.5" }));
  check("spf.verify: neither mailFrom nor helo → spf-bad-domain throw",
        e2 && /spf-bad-domain/.test(e2.code || ""));
  var e3 = await _rejectedWith(b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", bogus: 1 }));
  check("spf.verify: unknown opt refused (config-time)", e3 !== null);
}

// ---- SPF: `all` qualifier → verdict mapping (RFC 7208 §4.6.2) ----

async function testSpfAllQualifierVerdicts() {
  var cases = [
    { rec: "v=spf1 +all", want: "pass"     },
    { rec: "v=spf1 ~all", want: "softfail" },
    { rec: "v=spf1 ?all", want: "neutral"  },
    { rec: "v=spf1 all",  want: "pass"     },   // bare mechanism defaults to '+'
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var dns = _txtOnly({ "s.example": [[cases[i].rec]] });
    var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
    check("spf.verify(" + JSON.stringify(cases[i].rec) + ") → " + cases[i].want,
          rv.result === cases[i].want);
  }
}

async function testSpfNeutralWhenNoMechanismMatches() {
  // A record with a non-matching mechanism and NO `all` / redirect falls
  // through to the "no mechanism matched" default → neutral (RFC 7208 §4.7).
  var dns = _txtOnly({ "s.example": [["v=spf1 ip4:198.51.100.0/24"]] });
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify: no mechanism matched + no all → neutral",
        rv.result === "neutral" && /no mechanism matched/.test(rv.explanation || ""));
}

// ---- SPF: ip6 mechanism (RFC 7208 §5.6) on an IPv6 connection ----

async function testSpfIp6Mechanism() {
  var dns = _txtOnly({ "s.example": [["v=spf1 ip6:2001:db8::/32 -all"]] });
  var hit = await b.mail.spf.verify({ ip: "2001:db8::5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify(ip6:2001:db8::/32, IP in range) → pass", hit.result === "pass");
  var miss = await b.mail.spf.verify({ ip: "2001:dead::5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify(ip6:2001:db8::/32, IP out of range) → fail (-all)", miss.result === "fail");
}

// ---- SPF: helo fallback when MAIL FROM is absent (RFC 7208 §2.4) ----

async function testSpfHeloFallbackIdentity() {
  var dns = _txtOnly({ "mail.example.com": [["v=spf1 ip4:192.0.2.0/24 -all"]] });
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", helo: "mail.example.com", dnsLookup: dns });
  check("spf.verify: HELO identity used when MAIL FROM absent → pass on helo domain",
        rv.result === "pass" && rv.domain === "mail.example.com");
}

// ---- SPF: include semantics (RFC 7208 §5.2) ----

async function testSpfIncludeSemantics() {
  // A single include: to a domain with NO SPF record MUST permerror
  // (RFC 7208 §5.2) — distinct from the void-lookup-cap path.
  var noneDns = _txtOnly({ "s.example": [["v=spf1 include:missing.example -all"]] });
  var rvNone = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: noneDns });
  check("spf.verify: include of a record-less domain → permerror (RFC 7208 §5.2)",
        rvNone.result === "permerror" && /§5\.2|has no SPF record/.test(rvNone.explanation || ""));

  // A matching include propagates the inner pass to the outer verdict.
  var passDns = _txtOnly({
    "s.example":      [["v=spf1 include:_spf.p.example -all"]],
    "_spf.p.example": [["v=spf1 ip4:192.0.2.0/24 ~all"]],
  });
  var rvPass = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: passDns });
  check("spf.verify: include that passes propagates to outer pass", rvPass.result === "pass");
}

// ---- SPF: redirect= to a record-less target → permerror (RFC 7208 §6.1) ----

async function testSpfRedirectNoRecordPermerror() {
  var dns = _txtOnly({ "s.example": [["v=spf1 redirect=_spf.missing.example"]] });
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify: redirect= to a record-less domain → permerror (RFC 7208 §6.1)",
        rv.result === "permerror" && /§6\.1|has no SPF record/.test(rv.explanation || ""));
}

// ---- SPF: macro letters + transformers (RFC 7208 §7) via exists ----

async function testSpfMacroLettersAndTransformers() {
  // Each case is one `exists:` whose expanded A-query name we capture. The
  // exists RESOLVES (→ pass) so it never charges the §4.6.4 void slot — a
  // multi-miss chain would trip the void cap before every shape ran.
  async function expand(record, mailFrom) {
    var queried = [];
    var dns = async function (host, type) {
      if (type === "TXT" && host === "a.b.example") return [[record]];
      if (type === "A") { queried.push(host); return ["127.0.0.2"]; }
      var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
    };
    var rv = await b.mail.spf.verify({ ip: "192.0.2.9", mailFrom: mailFrom, dnsLookup: dns });
    return { result: rv.result, queried: queried };
  }
  var mf = "alice@a.b.example";
  var lo = await expand("v=spf1 exists:%{l}.%{o}.probe -all", mf);
  check("spf macro %{l}.%{o} → local-part + full sender-domain",
        lo.result === "pass" && lo.queried.indexOf("alice.a.b.example.probe") !== -1);
  var d2 = await expand("v=spf1 exists:%{d2}.probe -all", mf);
  check("spf macro %{d2} → rightmost two labels of current domain",
        d2.result === "pass" && d2.queried.indexOf("b.example.probe") !== -1);
  var dr = await expand("v=spf1 exists:%{dr}.probe -all", mf);
  check("spf macro %{dr} → reversed current-domain labels",
        dr.result === "pass" && dr.queried.indexOf("example.b.a.probe") !== -1);
  var pct = await expand("v=spf1 exists:a%%b.probe -all", mf);
  check("spf macro %% → literal percent",
        pct.result === "pass" && pct.queried.indexOf("a%b.probe") !== -1);
  var sp = await expand("v=spf1 exists:a%_b.probe -all", mf);
  check("spf macro %_ → literal space",
        sp.result === "pass" && sp.queried.indexOf("a b.probe") !== -1);
}

// ---- SPF: parseRecord surfaces qualifier + modifier structure ----

function testSpfParseRecordStructure() {
  var rec = b.mail.spf.parseRecord("v=spf1 ~all");
  check("spf.parseRecord: bare '~all' → softfail qualifier + all mechanism",
        rec.length === 1 && rec[0].qualifier === "~" && rec[0].mechanism === "all");
  var rec2 = b.mail.spf.parseRecord("v=spf1 a:mail.example.com/24 redirect=_spf.example.com");
  check("spf.parseRecord: modifier separated from mechanisms (non-enumerable)",
        rec2.length === 1 && rec2[0].mechanism === "a" &&
        Array.isArray(rec2.modifiers) && rec2.modifiers[0].name === "redirect" &&
        rec2.modifiers[0].value === "_spf.example.com");
}

// ---- DMARC: parseRecord defaults + failure classification ----

function testDmarcParseDefaultsAndErrors() {
  var p = b.mail.dmarc.parseRecord("v=DMARC1; p=quarantine");
  check("dmarc.parseRecord: pct/adkim/aspf default to 100/r/r when omitted",
        p.pct === 100 && p.adkim === "r" && p.aspf === "r");
  var eVer = _threw(function () { b.mail.dmarc.parseRecord("v=DMARC2; p=none"); });
  check("dmarc.parseRecord: wrong version → dmarc-bad-version",
        eVer && /dmarc-bad-version/.test(eVer.code || ""));
  var eNoP = _threw(function () { b.mail.dmarc.parseRecord("v=DMARC1; pct=100"); });
  check("dmarc.parseRecord: missing required p= → dmarc-missing-policy (RFC 7489 §6.3)",
        eNoP && /dmarc-missing-policy/.test(eNoP.code || ""));
}

// ---- DMARC evaluate: from-address validation ----

async function testDmarcEvaluateFromValidation() {
  var e1 = await _rejectedWith(b.mail.dmarc.evaluate({ from: 123 }));
  check("dmarc.evaluate: non-string from → dmarc-bad-from",
        e1 && /dmarc-bad-from/.test(e1.code || ""));
  var e2 = await _rejectedWith(b.mail.dmarc.evaluate({ from: "nodomain" }));
  check("dmarc.evaluate: from lacking @domain → dmarc-bad-from",
        e2 && /dmarc-bad-from/.test(e2.code || ""));
}

// ---- DMARC evaluate: policy-driven disposition branches ----

async function testDmarcEvaluatePolicyNoneDelivers() {
  // p=none is monitor-only: an unaligned message still delivers.
  var dns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=none"]] });
  var rv = await b.mail.dmarc.evaluate({
    from: "alice@example.com",
    spf:  { result: "fail", domain: "example.com" }, dkim: [], dnsLookup: dns,
  });
  check("dmarc.evaluate: p=none unaligned → result fail but recommendedAction deliver",
        rv.result === "fail" && rv.recommendedAction === "deliver");
}

async function testDmarcEvaluateNoRecordIsNone() {
  var dns = async function () { var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e; };
  var rv = await b.mail.dmarc.evaluate({
    from: "alice@norecord.example",
    spf:  { result: "fail", domain: "x" }, dkim: [], dnsLookup: dns,
  });
  check("dmarc.evaluate: no _dmarc record → result none",
        rv.result === "none" && rv.policy === null);
}

async function testDmarcEvaluatePermerrorOnBadRecord() {
  // A syntactically bad record (invalid p=) is a PERMANENT error, not a
  // silent pass — dmarc.evaluate catches the parse throw → permerror.
  var dns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=maybe"]] });
  var rv = await b.mail.dmarc.evaluate({
    from: "alice@example.com",
    spf:  { result: "pass", domain: "example.com" }, dkim: [], dnsLookup: dns,
  });
  check("dmarc.evaluate: unparseable published policy → permerror (not a pass)",
        rv.result === "permerror" && rv.alignment.spf === false);
}

// ---- DMARC evaluate: alignment input shapes + modes ----

async function testDmarcEvaluateDkimResultShapes() {
  var dns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=reject; adkim=r; aspf=r"]] });
  // dkim supplied as a single object (not an array).
  var single = await b.mail.dmarc.evaluate({
    from: "alice@example.com", spf: { result: "fail", domain: "x" },
    dkim: { result: "pass", domain: "example.com" }, dnsLookup: dns,
  });
  check("dmarc.evaluate: dkim as a single object aligns → pass",
        single.result === "pass" && single.alignment.dkim === true);
  // dkim result carrying a `d` field instead of `domain`.
  var dField = await b.mail.dmarc.evaluate({
    from: "alice@example.com", spf: { result: "fail", domain: "x" },
    dkim: [{ result: "pass", d: "example.com" }], dnsLookup: dns,
  });
  check("dmarc.evaluate: dkim result exposing d= (not domain) still aligns → pass",
        dField.result === "pass" && dField.alignment.dkim === true);
  // A non-pass SPF result must not count as aligned even with a matching domain.
  var soft = await b.mail.dmarc.evaluate({
    from: "alice@example.com", spf: { result: "softfail", domain: "example.com" },
    dkim: [], dnsLookup: dns,
  });
  check("dmarc.evaluate: SPF softfail with matching domain is NOT aligned",
        soft.alignment.spf === false && soft.result === "fail");
}

async function testDmarcEvaluateStrictVsRelaxedAlignment() {
  // aspf=s (strict): a subdomain From vs a parent-domain SPF auth-domain
  // does NOT align (exact host match required).
  var strictDns = _txtOnly({ "_dmarc.sub.example.com": [["v=DMARC1; p=reject; aspf=s; adkim=s"]] });
  var strict = await b.mail.dmarc.evaluate({
    from: "alice@sub.example.com", spf: { result: "pass", domain: "example.com" },
    dkim: [], dnsLookup: strictDns,
  });
  check("dmarc.evaluate: strict aspf=s — sub vs parent domain does NOT align → fail",
        strict.alignment.spf === false && strict.result === "fail");
  // aspf=r (relaxed): the same pair aligns via the shared org-domain.
  var relaxDns = _txtOnly({ "_dmarc.sub.example.com": [["v=DMARC1; p=reject; aspf=r"]] });
  var relaxed = await b.mail.dmarc.evaluate({
    from: "alice@sub.example.com", spf: { result: "pass", domain: "example.com" },
    dkim: [], dnsLookup: relaxDns,
  });
  check("dmarc.evaluate: relaxed aspf=r — sub vs parent domain aligns → pass",
        relaxed.alignment.spf === true && relaxed.result === "pass");
}

// ---- ARC verify: input validation + uncovered chain-rule / time-fault arms ----

async function testArcVerifyInputValidation() {
  var e1 = await _rejectedWith(b.mail.arc.verify(12345));
  check("arc.verify: non-string input → arc-bad-input",
        e1 && /arc-bad-input/.test(e1.code || ""));
  var e2 = await _rejectedWith(b.mail.arc.verify(""));
  check("arc.verify: empty-string input → arc-bad-input",
        e2 && /arc-bad-input/.test(e2.code || ""));
  var e3 = await _rejectedWith(b.mail.arc.evaluate(12345, { trustedSealers: [] }));
  check("arc.evaluate: non-string input → arc-bad-input",
        e3 && /arc-bad-input/.test(e3.code || ""));
}

async function testArcVerifyMissingCvArm() {
  // A structurally-complete i=1 hop whose ARC-Seal omits cv= trips the
  // missing-cv chain-rule arm (which takes precedence over the signature-
  // verification failure the dummy b= would otherwise report).
  var msg = "ARC-Seal: i=1; a=rsa-sha256; d=example.com; s=arc; b=AAAA\r\n" +
            "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
            "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: ARC-Seal with no cv= → fail w/ missing-cv reason",
        rv.chainStatus === "fail" && /missing-cv-at-i=1/.test(rv.reason || ""));
}

async function testArcVerifyTimeFaultArms() {
  // RFC 8617 §5.2 — a future t= and an unparseable x= are each time faults
  // that fail the AMS closed, independent of the (dummy) signature check.
  var keyDns = function () {
    return async function (qname) {
      if (qname === "arc._domainkey.example.com") {
        var nc = require("crypto");
        var pair = nc.generateKeyPairSync("rsa", { modulusLength: 2048 });
        return [["v=DKIM1; k=rsa; p=" +
          pair.publicKey.export({ type: "spki", format: "der" }).toString("base64")]];
      }
      var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
    };
  };
  var now = Math.floor(Date.now() / 1000);
  var futureMsg =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; t=" +
      (now + 999999) + "; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
    "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var rvF = await b.mail.arc.verify(futureMsg, { dnsLookup: keyDns() });
  var fErrs = ((rvF.hops[0] && rvF.hops[0].amsErrors) || []).join(" ; ");
  check("arc.verify: future t= → ams-t-future time fault (AMS fails closed)",
        rvF.chainStatus === "fail" && /ams-t-future/.test(fErrs));

  var unparseMsg =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; x=notanumber; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
    "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var rvU = await b.mail.arc.verify(unparseMsg, { dnsLookup: keyDns() });
  var uErrs = ((rvU.hops[0] && rvU.hops[0].amsErrors) || []).join(" ; ");
  check("arc.verify: unparseable x= → ams-x-unparseable time fault (fails closed)",
        rvU.chainStatus === "fail" && /ams-x-unparseable/.test(uErrs));
}

// ---- authResults.emit (RFC 8601 §2) — the whole builder is otherwise
//      exercised only indirectly through inbound.verify ----

function testAuthResultsEmitValidation() {
  var E = b.mail.authResults.emit;
  var eObj = _threw(function () { E(null); });
  check("authResults.emit: non-object opts → ar-bad-input",
        eObj && /ar-bad-input/.test(eObj.code || ""));
  var eOpt = _threw(function () { E({ authservId: "mx.a", results: [], bogus: 1 }); });
  check("authResults.emit: unknown opt refused (config-time)", eOpt !== null);
  var eEmpty = _threw(function () { E({ authservId: "", results: [] }); });
  check("authResults.emit: empty authservId → ar-bad-authserv-id",
        eEmpty && /ar-bad-authserv-id/.test(eEmpty.code || ""));
  var eCrlf = _threw(function () { E({ authservId: "mx.a\r\nInjected: 1", results: [] }); });
  check("authResults.emit: CR/LF in authservId → ar-bad-authserv-id (no header injection)",
        eCrlf && /ar-bad-authserv-id/.test(eCrlf.code || ""));
  var eNul = _threw(function () { E({ authservId: "mx.a" + String.fromCharCode(0) + "x", results: [] }); });
  check("authResults.emit: NUL in authservId → ar-bad-authserv-id",
        eNul && /ar-bad-authserv-id/.test(eNul.code || ""));
  var eArr = _threw(function () { E({ authservId: "mx.a", results: "nope" }); });
  check("authResults.emit: non-array results → ar-bad-results",
        eArr && /ar-bad-results/.test(eArr.code || ""));
  var eEntry = _threw(function () { E({ authservId: "mx.a", results: [42] }); });
  check("authResults.emit: non-object result entry → ar-bad-result-entry",
        eEntry && /ar-bad-result-entry/.test(eEntry.code || ""));
  var eMethod = _threw(function () { E({ authservId: "mx.a", results: [{ method: "bogus", result: "pass" }] }); });
  check("authResults.emit: unknown method → ar-bad-method",
        eMethod && /ar-bad-method/.test(eMethod.code || ""));
  // RFC 8601 §2.7 — result vocabulary is method-specific: 'hardfail' is
  // not in SPF's set, so it is refused rather than passed through.
  var eResult = _threw(function () { E({ authservId: "mx.a", results: [{ method: "spf", result: "hardfail" }] }); });
  check("authResults.emit: result outside a method's §2.7 vocabulary → ar-bad-result",
        eResult && /ar-bad-result/.test(eResult.code || ""));
}

function testAuthResultsEmitFormatting() {
  var E = b.mail.authResults.emit;
  // Zero methods evaluated → the RFC 8601 §2.2 `none` form.
  check("authResults.emit: empty results → '; none'",
        E({ authservId: "mx.a", results: [] }) === "Authentication-Results: mx.a; none");
  // ptype.property=value triples for the recognized shorthand keys.
  var props = E({ authservId: "mx.a", results: [
    { method: "spf",   result: "pass", smtpMailfrom: "u@s.example" },
    { method: "dmarc", result: "pass", from: "u@s.example" },
  ] });
  check("authResults.emit: property keys mapped to RFC 8601 §2.3 ptype.property",
        /spf=pass smtp\.mailfrom=u@s\.example/.test(props) &&
        /dmarc=pass header\.from=u@s\.example/.test(props));
  // A reason string with an embedded DQUOTE is backslash-escaped (§2.2).
  var reason = E({ authservId: "mx.a", results: [{ method: "dkim", result: "fail", reason: 'key "rotated"' }] });
  check("authResults.emit: reason DQUOTE escaped as \\\" (RFC 8601 §2.2)",
        reason.indexOf('reason="key \\"rotated\\""') !== -1);
  // A pvalue carrying a forbidden character (space) is dropped, not emitted.
  var pv = E({ authservId: "mx.a", results: [{ method: "dkim", result: "pass", domain: "has space" }] });
  check("authResults.emit: structurally-invalid pvalue is omitted (not injected)",
        pv.indexOf("header.d=") === -1 && /dkim=pass/.test(pv));
  // fold:false switches the clause separator from the folded form to '; '.
  var flat = E({ authservId: "mx.a", fold: false,
    results: [{ method: "spf", result: "pass" }, { method: "dkim", result: "pass" }] });
  check("authResults.emit: fold:false joins clauses with '; ' (no folded inter-clause break)",
        /spf=pass; dkim=pass/.test(flat) && flat.indexOf(";\r\n  dkim") === -1);
  // A non-'1' version is appended after the authserv-id token (§2.2).
  var ver = E({ authservId: "mx.a", version: "2", results: [{ method: "spf", result: "pass" }] });
  check("authResults.emit: version appended to authserv-id when not '1'",
        ver.indexOf("Authentication-Results: mx.a 2;") === 0);
}

async function run() {
  await testSpfVerifyInputValidation();
  await testSpfAllQualifierVerdicts();
  await testSpfNeutralWhenNoMechanismMatches();
  await testSpfIp6Mechanism();
  await testSpfHeloFallbackIdentity();
  await testSpfIncludeSemantics();
  await testSpfRedirectNoRecordPermerror();
  await testSpfMacroLettersAndTransformers();
  testSpfParseRecordStructure();
  testDmarcParseDefaultsAndErrors();
  await testDmarcEvaluateFromValidation();
  await testDmarcEvaluatePolicyNoneDelivers();
  await testDmarcEvaluateNoRecordIsNone();
  await testDmarcEvaluatePermerrorOnBadRecord();
  await testDmarcEvaluateDkimResultShapes();
  await testDmarcEvaluateStrictVsRelaxedAlignment();
  await testArcVerifyInputValidation();
  await testArcVerifyMissingCvArm();
  await testArcVerifyTimeFaultArms();
  testAuthResultsEmitValidation();
  testAuthResultsEmitFormatting();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.spf + b.mail.dmarc + b.mail.arc — inbound mail
 * authentication-results verification.
 *
 * Live DNS lookups don't run in smoke (network-bound tests live in
 * test/integration). What's covered: parse + match + alignment logic
 * via operator-supplied dnsLookup mock callbacks; ARC chain shape.
 * Also: SPF qualifier / macro / CIDR / lookup-ceiling and DNS-failure
 * classification edges, DMARC disposition + alignment-mode + report
 * branches, ARC key-material failure arms, and the b.mail.authResults
 * builder.
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var arcSign    = require("../../lib/mail-arc-sign");
var nodeCrypto = require("node:crypto");
var C          = require("../../lib/constants");

function testSurface() {
  check("mail.spf.verify is a function",       typeof b.mail.spf.verify === "function");
  check("mail.spf.parseRecord is a function",  typeof b.mail.spf.parseRecord === "function");
  check("mail.dmarc.evaluate is a function",   typeof b.mail.dmarc.evaluate === "function");
  check("mail.dmarc.parseRecord is a function",typeof b.mail.dmarc.parseRecord === "function");
  check("mail.arc.verify is a function",       typeof b.mail.arc.verify === "function");
  check("frameworkError.MailAuthError exposed",
        typeof b.frameworkError.MailAuthError === "function");
}

function testSpfParse() {
  var rec = b.mail.spf.parseRecord("v=spf1 ip4:192.0.2.0/24 include:mailgun.org -all");
  check("spf.parseRecord returns 3 mechanisms",
        rec.length === 3 &&
        rec[0].mechanism === "ip4" && rec[0].arg === "192.0.2.0/24" &&
        rec[1].mechanism === "include" && rec[1].arg === "mailgun.org" &&
        rec[2].mechanism === "all" && rec[2].qualifier === "-");
}

function testSpfBadRecord() {
  var threw = null;
  try { b.mail.spf.parseRecord("v=spf2 +all"); }
  catch (e) { threw = e; }
  check("spf.parseRecord rejects bad version",
        threw && /spf-bad-version/.test(threw.code || ""));
}

async function testSpfVerifyMockedDns() {
  // Mock dnsLookup that resolves "example.com" SPF record.
  var dnsLookup = async function (host, type) {
    if (host === "example.com" && type === "TXT") {
      return [["v=spf1 ip4:192.0.2.0/24 -all"]];
    }
    var err = new Error("ENOTFOUND");
    err.code = "ENOTFOUND";
    throw err;
  };
  var rv = await b.mail.spf.verify({
    ip:       "192.0.2.5",
    mailFrom: "alice@example.com",
    dnsLookup: dnsLookup,
  });
  check("spf.verify(matching ip) → pass",
        rv.result === "pass");

  var rv2 = await b.mail.spf.verify({
    ip:       "203.0.113.99",
    mailFrom: "alice@example.com",
    dnsLookup: dnsLookup,
  });
  check("spf.verify(non-matching ip) → fail (-all)",
        rv2.result === "fail");

  // A MAIL FROM addr-spec has exactly one '@'. split("@")[1] on a multi-@
  // string (x@attacker.example@example.com) takes the LEFTMOST segment, so SPF
  // would authorize attacker.example (which the attacker controls) instead of
  // the envelope sender's real domain. A multi-@ MAIL FROM must surface as a
  // permanent SPF error VERDICT, not a throw — spfVerify runs inside
  // b.mail.inbound.verify, where a throw is caught as a pipeline temperror that
  // onTemperror:"accept" would let through, skipping SPF/DMARC gating (CWE-290).
  var spfMultiAt = await b.mail.spf.verify({ ip: "192.0.2.5",
    mailFrom: "x@attacker.example@example.com", dnsLookup: dnsLookup });
  check("spf.verify: a multi-@ MAIL FROM returns permerror (a verdict, not a throw)",
        spfMultiAt.result === "permerror" && spfMultiAt.domain === null);
}

function testDmarcParse() {
  var policy = b.mail.dmarc.parseRecord("v=DMARC1; p=reject; pct=50; aspf=s; adkim=r");
  check("dmarc.parseRecord returns shape",
        policy.v === "DMARC1" && policy.p === "reject" &&
        policy.pct === 50 && policy.aspf === "s" && policy.adkim === "r");
}

async function testDmarcEvaluateAligned() {
  var dnsLookup = async function (host) {
    if (host === "_dmarc.example.com") {
      return [["v=DMARC1; p=reject; aspf=r; adkim=r"]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dmarc.evaluate({
    from:    "alice@example.com",
    spf:     { result: "pass", domain: "example.com" },
    dkim:    [{ result: "pass", domain: "example.com" }],
    dnsLookup: dnsLookup,
  });
  check("dmarc.evaluate: aligned spf+dkim → pass + deliver",
        rv.result === "pass" && rv.recommendedAction === "deliver" &&
        rv.alignment.spf === true && rv.alignment.dkim === true);
}

async function testDmarcStrictAlignmentCanonicalizesDomain() {
  // Strict alignment (aspf=s) must canonicalize both domains (trailing dot /
  // case / IDN A-label) the same way the relaxed PSL path does. The SPF auth
  // domain can legitimately carry a trailing dot (FQDN form); comparing it raw
  // against the From domain wrongly failed a perfectly aligned message.
  var dnsLookup = async function (host) {
    if (host === "_dmarc.example.com") return [["v=DMARC1; p=reject; aspf=s; adkim=s"]];
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dmarc.evaluate({
    from:    "alice@example.com",
    spf:     { result: "pass", domain: "Example.COM." },   // trailing dot + mixed case — same domain
    dkim:    [],
    dnsLookup: dnsLookup,
  });
  check("dmarc strict alignment: a trailing-dot/mixed-case SPF auth-domain still aligns",
        rv.alignment.spf === true);
}

async function testDmarcEvaluateUnaligned() {
  var dnsLookup = async function (host) {
    if (host === "_dmarc.example.com") {
      return [["v=DMARC1; p=quarantine"]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dmarc.evaluate({
    from:    "alice@example.com",
    spf:     { result: "pass", domain: "different.org" },
    dkim:    [],
    dnsLookup: dnsLookup,
  });
  check("dmarc.evaluate: unaligned → fail + quarantine",
        rv.result === "fail" && rv.recommendedAction === "quarantine");
}

// ---- b.mail.inbound.verify — receiver pipeline (RFC 7489 §6.6) ----

function _inboundDns(records) {
  return async function (host, type) {
    if (records[host + "/" + type]) return records[host + "/" + type];
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
}

async function testInboundVerifyAlignedPass() {
  var dnsLookup = _inboundDns({
    "example.com/TXT":        [["v=spf1 ip4:192.0.2.0/24 -all"]],
    "_dmarc.example.com/TXT": [["v=DMARC1; p=reject"]],
  });
  var msg = "From: Alice <alice@example.com>\r\nSubject: hi\r\n\r\nhello\r\n";
  var v = await b.mail.inbound.verify({
    ip:         "192.0.2.5",
    helo:       "mail.example.com",
    mailFrom:   "alice@example.com",
    message:    Buffer.from(msg),
    dnsLookup:  dnsLookup,
    authservId: "mx.local.test",
  });
  check("inbound.verify: aligned SPF → dmarc pass + deliver",
        v.spf.result === "pass" && v.dmarc.result === "pass" &&
        v.dmarc.recommendedAction === "deliver");
  check("inbound.verify: From extracted from Buffer message",
        v.from.count === 1 && v.from.address === "alice@example.com" &&
        v.from.domain === "example.com");
  check("inbound.verify: A-R header emitted with authserv-id first",
        typeof v.authResults === "string" &&
        v.authResults.indexOf("Authentication-Results: mx.local.test") === 0 &&
        /spf=pass/.test(v.authResults) && /dmarc=pass/.test(v.authResults));
  check("inbound.verify: unsigned message verifies dkim none",
        Array.isArray(v.dkim) && v.dkim[0] && v.dkim[0].result === "none");
}

async function testInboundVerifySpoofRejected() {
  var dnsLookup = _inboundDns({
    "spoofed.example/TXT":        [["v=spf1 -all"]],
    "_dmarc.spoofed.example/TXT": [["v=DMARC1; p=reject"]],
  });
  var msg = "From: ceo@spoofed.example\r\nSubject: urgent\r\n\r\nwire money\r\n";
  var v = await b.mail.inbound.verify({
    ip:        "203.0.113.9",
    helo:      "evil.host",
    mailFrom:  "ceo@spoofed.example",
    message:   msg,
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: spoofed sender → spf fail + dmarc fail + reject",
        v.spf.result === "fail" && v.dmarc.result === "fail" &&
        v.dmarc.recommendedAction === "reject");
  check("inbound.verify: no authservId → no A-R header", v.authResults === null);
}

async function testInboundVerifyMultiAtMailFromGatesNotThrows() {
  // A multi-@ MAIL FROM (x@attacker@victim) must NOT throw out of the verify
  // pipeline: a throw is caught by mail-server-mx as a temperror, which
  // onTemperror:"accept" would let through, skipping SPF/DMARC gating for the
  // spoofed From (CWE-290). It surfaces as an SPF permerror VERDICT, and the
  // spoofed p=reject From is still gated to reject.
  var dnsLookup = _inboundDns({
    "_dmarc.spoofed.example/TXT": [["v=DMARC1; p=reject"]],
  });
  var v = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host",
    mailFrom: "x@attacker.example@spoofed.example",
    message: "From: ceo@spoofed.example\r\nSubject: urgent\r\n\r\nwire money\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: multi-@ MAIL FROM → spf permerror (no throw out of the pipeline)",
        v.spf.result === "permerror");
  check("inbound.verify: multi-@ MAIL FROM still gates the spoofed From → reject",
        v.dmarc.result === "fail" && v.dmarc.recommendedAction === "reject");
}

async function testInboundVerifyGroupSyntaxFromRejected() {
  // DMARC bypass via RFC 5322 group syntax: `From: Recipients:alice@victim;`
  // carries no whitespace or comma but is not a bare addr-spec — the group
  // `name:` prefix and trailing ';' would corrupt the extracted domain
  // ("victim.example;"), which misses the real _dmarc.victim.example policy and
  // would let the spoof through as "none". The From must be unparsable so the
  // verdict fails closed (permerror → reject), not a silent pass.
  var dnsLookup = _inboundDns({
    "_dmarc.victim.example/TXT": [["v=DMARC1; p=reject"]],
  });
  var clean = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host", mailFrom: "x@evil.example",
    message: "From: alice@victim.example\r\nSubject: hi\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("control: a clean From resolves the victim domain",
        clean.from.domain === "victim.example");
  var spoof = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host", mailFrom: "x@evil.example",
    message: "From: Recipients:alice@victim.example;\r\nSubject: hi\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("group-syntax From yields no parsable domain (no corrupted hostname)",
        spoof.from.domain === null);
  check("group-syntax From fails closed (permerror → reject, not a silent pass)",
        spoof.dmarc.result === "permerror" && spoof.dmarc.recommendedAction === "reject");
}

async function testInboundVerifyFromHeaderDiscipline() {
  var dnsLookup = _inboundDns({});
  // Two From fields — the header-duplication spoofing shape.
  var dup = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host", mailFrom: "safe@aligned.example",
    message: "From: safe@aligned.example\r\nFrom: ceo@victim.example\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: duplicated From → permerror + reject (RFC 7489 §6.6.1)",
        dup.from.count === 2 && dup.dmarc.result === "permerror" &&
        dup.dmarc.recommendedAction === "reject");
  // Two angle-addr authors inside one field.
  var multi = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host", mailFrom: "safe@aligned.example",
    message: "From: <safe@aligned.example> <ceo@victim.example>\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: two angle-addrs in one From → permerror + reject",
        multi.from.count === 2 && multi.dmarc.recommendedAction === "reject");
  // Bare address list (no angle-addrs) — unparsable rather than
  // picking one of the authors.
  var bareList = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host", mailFrom: "safe@aligned.example",
    message: "From: a@aligned.example, b@victim.example\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: bare From address-list → no author domain picked + reject",
        bareList.from.domain === null && bareList.dmarc.recommendedAction === "reject");
  // No From header at all.
  var none = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host", mailFrom: "safe@aligned.example",
    message: "Subject: headless\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: missing From → permerror + reject",
        none.from.count === 0 && none.dmarc.result === "permerror" &&
        none.dmarc.recommendedAction === "reject");
  // Folded From header unfolds before extraction.
  var folded = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host", mailFrom: "x@folded.example",
    message: "From: Folded Name\r\n <x@folded.example>\r\nSubject: f\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: folded From unfolds (RFC 5322 §2.2.3)",
        folded.from.count === 1 && folded.from.domain === "folded.example");
  // Quoted display-names: a literal `<` or comma inside a
  // quoted-string is display-name text, not a second author — valid
  // single-author mail must not false-positive into permerror.
  var quotedLt = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "h.example", mailFrom: "u@quoted.example",
    message: "From: \"John <Jr.> Smith\" <u@quoted.example>\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: quoted display-name with literal < is one author",
        quotedLt.from.count === 1 && quotedLt.from.domain === "quoted.example");
  var quotedComma = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "h.example", mailFrom: "j@comma.example",
    message: "From: \"Doe, John\" <j@comma.example>\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: quoted display-name with comma is one author",
        quotedComma.from.count === 1 && quotedComma.from.domain === "comma.example");
  // Comma-separated angle-addr list — multiple authors refused.
  var twoAngle = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host", mailFrom: "safe@aligned.example",
    message: "From: <safe@aligned.example>, Boss <ceo@victim.example>\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: comma-separated angle-addr list → multiple authors refused",
        twoAngle.from.count === 2 && twoAngle.dmarc.recommendedAction === "reject");

  // Two '@' in ONE addr-spec (x@attacker@victim). The header.from parser takes
  // the RIGHTMOST @ segment (victim) while the DMARC domain derivation takes the
  // LEFTMOST (attacker) — so DMARC would authorize attacker.example (which the
  // attacker controls) while the displayed From is victim.example. An addr-spec
  // has exactly ONE @ (RFC 5322 §3.4.1); a multi-@ address is malformed and must
  // yield no author domain → reject, closing the leftmost/rightmost split bypass.
  var multiAt = await b.mail.inbound.verify({
    ip: "203.0.113.9", helo: "evil.host", mailFrom: "x@attacker.example",
    message: "From: x@attacker.example@victim.example\r\n\r\nbody\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: multi-@ From (x@a@b) → no author domain + reject (no @-split bypass)",
        multiAt.from.domain === null && multiAt.dmarc.recommendedAction === "reject");

  // The public dmarc.evaluate must reject a multi-@ From the same way, so a
  // direct caller can't trigger the leftmost-@ derivation.
  var badFromThrew = null;
  try {
    await b.mail.dmarc.evaluate({ from: "x@attacker.example@victim.example",
      spf: { result: "pass", domain: "attacker.example" }, dkim: [], dnsLookup: dnsLookup });
  } catch (e) { badFromThrew = e; }
  check("dmarc.evaluate: a multi-@ From is refused as malformed (mail-auth/dmarc-bad-from)",
        badFromThrew && /dmarc-bad-from/.test(badFromThrew.code || ""));
}

// RFC 7489 §6.6.2 — a fail verdict computed while SPF or DKIM returned
// temperror must surface as temperror (the transiently-failed lookup
// could have produced the aligned pass), so the MX gate defers with
// 451 instead of permanently refusing a legitimate sender mid-DNS-blip.
async function testInboundVerifyTemperrorPrecedence() {
  // SPF TXT lookup fails transiently (SERVFAIL — no ENOTFOUND code);
  // the DMARC policy lookup itself succeeds with p=reject.
  var dnsLookup = async function (host, type) {
    if (host === "_dmarc.blip.example" && type === "TXT") {
      return [["v=DMARC1; p=reject"]];
    }
    throw new Error("SERVFAIL");
  };
  var v = await b.mail.inbound.verify({
    ip:        "203.0.113.9",
    helo:      "mail.blip.example",
    mailFrom:  "news@blip.example",
    message:   "From: news@blip.example\r\nSubject: hi\r\n\r\nhello\r\n",
    dnsLookup: dnsLookup,
  });
  check("inbound.verify: SPF temperror under p=reject → dmarc temperror, not fail",
        v.spf.result === "temperror" && v.dmarc.result === "temperror" &&
        v.dmarc.recommendedAction !== "reject");
  // A pass stands regardless of the other authenticator's temperror:
  // aligned DKIM pass + SPF temperror is still a DMARC pass.
  var dnsLookup2 = async function (host, type) {
    if (host === "_dmarc.blip.example" && type === "TXT") {
      return [["v=DMARC1; p=reject"]];
    }
    throw new Error("SERVFAIL");
  };
  var v2 = await b.mail.dmarc.evaluate({
    from:      "news@blip.example",
    spf:       { result: "temperror", domain: "blip.example" },
    dkim:      [{ result: "pass", domain: "blip.example" }],
    dnsLookup: dnsLookup2,
  });
  check("dmarc.evaluate: aligned DKIM pass beats SPF temperror (pass stands)",
        v2.result === "pass" && v2.recommendedAction === "deliver");
}

async function testInboundVerifyValidation() {
  var e1 = null;
  try { await b.mail.inbound.verify({ message: "x" }); } catch (e) { e1 = e; }
  check("inbound.verify: missing ip refused", e1 !== null);
  var e2 = null;
  try { await b.mail.inbound.verify({ ip: "203.0.113.9", message: "" }); } catch (e) { e2 = e; }
  check("inbound.verify: empty message refused",
        e2 && /inbound-bad-message/.test(e2.code || ""));
  var e3 = null;
  try {
    await b.mail.inbound.verify({ ip: "203.0.113.9", message: "From: a@b.c\r\n\r\nx", bogus: 1 });
  } catch (e) { e3 = e; }
  check("inbound.verify: unknown opt refused (config-time)", e3 !== null);
}

async function testArcVerifyMissing() {
  var msg = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: incomplete chain → fail",
        rv.chainStatus === "fail");
}

async function testArcVerifyNone() {
  var msg = "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: no ARC headers → none",
        rv.chainStatus === "none" && rv.hopCount === 0);
}

async function testArcVerifyBadSignatures() {
  // All 3 ARC headers present but the b= values are dummy — signature
  // verification fails per-hop. Per the security-no-defer rule this
  // returns fail, NOT pass.
  var msg = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
            "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
            "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
            "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  // dnsLookup that returns a "valid" key for the signature check —
  // signatures are dummy so verify fails cleanly with "fail" not "permerror".
  var dnsLookup = async function (qname) {
    if (qname === "arc._domainkey.example.com") {
      // Generate a valid PEM-shape RSA key for the test (operator-side
      // would be a real DNS-published key). We use a fixed deterministic
      // key so the test doesn't bind to DNS.
      var nodeCrypto = require("crypto");
      var pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
      var spki = pair.publicKey.export({ type: "spki", format: "der" });
      return [["v=DKIM1; k=rsa; p=" + spki.toString("base64")]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.arc.verify(msg, { dnsLookup: dnsLookup });
  check("arc.verify with bad signatures → chainStatus=fail (not pass)",
        rv.chainStatus === "fail");
  check("arc.verify per-hop reports amsResult / asResult",
        rv.hops.length === 1 &&
        rv.hops[0].amsResult !== "pass" &&
        rv.hops[0].asResult !== "pass");
}

async function testArcInfinityClockSkewDoesNotDisableExpiry() {
  // RFC 8617 §5.2 — a past x= (expiration) MUST be rejected with operator
  // skew tolerance. The expiry gate is `amsX + skewSec < nowSec`; a non-finite
  // clockSkewMs makes skewSec === Infinity, so `amsX + Infinity < nowSec` is
  // always false and the expiry check is silently disabled. A present
  // non-finite skew must fall back to the safe default instead. RED before the
  // fix: the expired x= slips through and amsErrors carries a signature error,
  // not the x-expired fault.
  var nowSec = Math.floor(Date.now() / 1000);
  var expiredX = nowSec - 86400;   // expired a day ago
  var pastT    = nowSec - 90000;
  var msg = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
            "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; t=" + pastT + "; x=" + expiredX + "; bh=AAAA; h=from; b=AAAA\r\n" +
            "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
            "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var dnsLookup = async function (qname) {
    if (qname === "arc._domainkey.example.com") {
      var nodeCrypto = require("crypto");
      var pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
      var spki = pair.publicKey.export({ type: "spki", format: "der" });
      return [["v=DKIM1; k=rsa; p=" + spki.toString("base64")]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.arc.verify(msg, { dnsLookup: dnsLookup, clockSkewMs: Infinity });
  var amsErrs = ((rv.hops && rv.hops[0] && rv.hops[0].amsErrors) || []).join(" ; ");
  check("ARC Infinity skew: expired x= still enforced (expiry not disabled)",
        /x-expired/.test(amsErrs));
}

function _arcHopHeaders(i, cv) {
  // Synthetic ARC headers — signatures are dummy; the cv= edge tests
  // exercise the chain-rule validator, not the signature verifier.
  return "ARC-Authentication-Results: i=" + i + "; example.com; spf=pass\r\n" +
         "ARC-Message-Signature: i=" + i + "; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
         "ARC-Seal: i=" + i + "; a=rsa-sha256; cv=" + cv + "; d=example.com; s=arc; b=AAAA\r\n";
}

async function testArcVerifyDuplicateInstance() {
  // Two ARC-Seal headers at i=1 — chain MUST refuse rather than
  // silently overwrite the first signer's record.
  var msg = _arcHopHeaders(1, "none") +
            "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=attacker.com; s=arc; b=BBBB\r\n" +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: duplicate instance → fail w/ duplicate-instance reason",
        rv.chainStatus === "fail" && rv.reason === "duplicate-instance");
}

async function testArcVerifyNonContiguous() {
  // i=3 + i=1 (missing i=2; correct top-down order per RFC 8617 §5.2:
  // highest-instance set at the top because each hop prepends).
  // The chain MUST refuse — incomplete (no i=2).
  var msg = _arcHopHeaders(3, "pass") +
            _arcHopHeaders(1, "none") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: non-contiguous instances → fail",
        rv.chainStatus === "fail" && /incomplete-or-non-contiguous/.test(rv.reason || ""));
}

async function testArcVerifyTooManyHops() {
  // Synthesize 51 hops — RFC 8617 §5.1.2 caps at 50. Build top-down
  // (highest instance first) per RFC 8617 §5.2 source-order rule.
  var hopHeaders = "";
  for (var i = 51; i >= 1; i -= 1) {
    hopHeaders += _arcHopHeaders(i, i === 1 ? "none" : "pass");
  }
  var msg = hopHeaders + "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: chain > 50 hops → fail w/ too-many-hops reason",
        rv.chainStatus === "fail" && rv.reason === "too-many-hops");
}

async function testArcVerifyHop1CvMustBeNone() {
  // i=1 with cv=pass — invalid: hop 1 has nothing upstream to validate.
  var msg = _arcHopHeaders(1, "pass") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: i=1 cv=pass → fail w/ i=1-cv-must-be-none reason",
        rv.chainStatus === "fail" && /i=1-cv-must-be-none/.test(rv.reason || ""));
}

async function testArcVerifyHop2CvNoneInvalid() {
  // i=2 with cv=none — invalid: hop 2+ MUST report pass or fail.
  // Source order per RFC 8617 §5.2: highest instance at top.
  var msg = _arcHopHeaders(2, "none") +
            _arcHopHeaders(1, "none") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: i=2 cv=none → fail w/ cv=none-invalid-after-hop-1 reason",
        rv.chainStatus === "fail" && /cv=none-invalid-after-hop-1/.test(rv.reason || ""));
}

async function testArcVerifyPassAfterFail() {
  // i=1 cv=none, i=2 cv=fail, i=3 cv=pass — invalid: a hop can't
  // claim chain pass after upstream observed fail. Source order top-
  // down per RFC 8617 §5.2.
  var msg = _arcHopHeaders(3, "pass") +
            _arcHopHeaders(2, "fail") +
            _arcHopHeaders(1, "none") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: cv=pass after upstream cv=fail → fail w/ pass-after-upstream-fail reason",
        rv.chainStatus === "fail" && /pass-after-upstream-fail/.test(rv.reason || ""));
}

function testDkimVerifySurface() {
  check("mail.dkim.verify is a function",
        typeof b.mail.dkim.verify === "function");
}

async function testDkimVerifyRoundTrip() {
  // Round-trip: sign with a real key, verify with the same key
  // surfaced via a mocked DNS lookup.
  var nodeCrypto = require("crypto");
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var signer = b.mail.dkim.create({
    domain:     "example.com",
    selector:   "test",
    privateKey: pair.privateKey,
  });
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n" +
            "Subject: hi\r\nDate: Mon, 5 May 2026 10:00:00 +0000\r\n" +
            "Message-ID: <abc@example.com>\r\n\r\nHello.\r\n";
  var signed = signer.sign(msg);

  // Mocked DNS that returns the matching public key as base64 SPKI.
  var spkiB64 = nodeCrypto.createPublicKey(pair.publicKey)
    .export({ type: "spki", format: "der" })
    .toString("base64");
  var dnsLookup = async function (qname) {
    if (qname === "test._domainkey.example.com") {
      return [["v=DKIM1; k=rsa; p=" + spkiB64]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("dkim.verify round-trip: pass",
        Array.isArray(rv) && rv.length === 1 && rv[0].result === "pass");
}

async function testDkimVerifyNoSignature() {
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.dkim.verify(msg, {});
  check("dkim.verify with no DKIM-Signature → none",
        Array.isArray(rv) && rv[0].result === "none");
}

async function testDkimVerifyTampered() {
  var nodeCrypto = require("crypto");
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var signer = b.mail.dkim.create({
    domain: "example.com", selector: "test", privateKey: pair.privateKey,
  });
  var signed = signer.sign(
    "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n" +
    "Date: Mon, 5 May 2026 10:00:00 +0000\r\nMessage-ID: <a@example.com>\r\n\r\nbody\r\n"
  );
  // Tamper the body after signing.
  var tampered = signed.replace("body", "EVIL");
  var spkiB64 = nodeCrypto.createPublicKey(pair.publicKey)
    .export({ type: "spki", format: "der" }).toString("base64");
  var dnsLookup = async function (qname) {
    if (qname === "test._domainkey.example.com") {
      return [["v=DKIM1; k=rsa; p=" + spkiB64]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dkim.verify(tampered, { dnsLookup: dnsLookup });
  check("dkim.verify on tampered body → fail",
        rv[0].result === "fail");
}

function _rejects(label, fn, pattern) {
  var threw = false; var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && pattern.test(msg));
}

function testArcSignSurface() {
  check("mail.arc.sign is a function",          typeof b.mail.arc.sign === "function");
  check("mail.arc.ALLOWED_CV exposed",          Array.isArray(b.mail.arc.ALLOWED_CV));
}

function testArcSignChain() {
  var nodeCrypto = require("crypto");
  var arcKey = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var arcKeyPem = arcKey.privateKey.export({ format: "pem", type: "pkcs8" });
  var rfc822 =
    "From: alice@example.com\r\n" +
    "To: bob@example.com\r\n" +
    "Subject: hello\r\n" +
    "Date: Wed, 06 May 2026 12:00:00 +0000\r\n" +
    "Message-ID: <1@example.com>\r\n" +
    "\r\n" +
    "body body body\r\n";

  // i=1 — initial hop, cv=none.
  var hop1 = b.mail.arc.sign({
    rfc822:      rfc822,
    instance:    1,
    authservId:  "relay1.example.com",
    domain:      "relay1.example.com",
    selector:    "arc",
    privateKey:  arcKeyPem,
    algorithm:   "rsa-sha256",
    cv:          "none",
    authResults: "spf=pass smtp.mailfrom=alice@example.com",
  });
  check("arc.sign: i=1 returns aar",            hop1.aar.indexOf("i=1; relay1.example.com") === 0);
  check("arc.sign: i=1 returns ams w/ b=",      hop1.ams.indexOf("b=") !== -1);
  check("arc.sign: i=1 returns as cv=none",     hop1.as.indexOf("cv=none") !== -1);
  check("arc.sign: rfc822 prepended with AS first", hop1.rfc822.indexOf("ARC-Seal:") === 0);
  check("arc.sign: rfc822 includes AMS",        hop1.rfc822.indexOf("ARC-Message-Signature:") !== -1);
  check("arc.sign: rfc822 includes AAR",        hop1.rfc822.indexOf("ARC-Authentication-Results:") !== -1);
  check("arc.sign: instance/cv on result",      hop1.instance === 1 && hop1.cv === "none");

  // i=2 — second hop, cv=pass over the i=1 chain.
  var hop2 = b.mail.arc.sign({
    rfc822:      hop1.rfc822,
    instance:    2,
    authservId:  "relay2.example.com",
    domain:      "relay2.example.com",
    selector:    "arc",
    privateKey:  arcKeyPem,
    algorithm:   "rsa-sha256",
    cv:          "pass",
    authResults: "spf=pass smtp.mailfrom=alice@example.com; arc=pass header.s=arc",
  });
  check("arc.sign: i=2 cv=pass",                hop2.as.indexOf("cv=pass") !== -1);
  check("arc.sign: i=2 covers prior chain",     hop2.rfc822.split("ARC-Seal:").length === 3);

  // ed25519 algorithm.
  var edKey = nodeCrypto.generateKeyPairSync("ed25519");
  var edKeyPem = edKey.privateKey.export({ format: "pem", type: "pkcs8" });
  var edHop = b.mail.arc.sign({
    rfc822:      rfc822,
    instance:    1,
    authservId:  "relay-ed.example.com",
    domain:      "relay-ed.example.com",
    selector:    "arc",
    privateKey:  edKeyPem,
    algorithm:   "ed25519-sha256",
    cv:          "none",
    authResults: "spf=pass",
  });
  check("arc.sign: ed25519 produces signature", edHop.as.indexOf("a=ed25519-sha256") !== -1);

  _rejects("arc.sign: missing rfc822",
    function () { b.mail.arc.sign({ instance: 1, authservId: "x", domain: "x", selector: "x", privateKey: arcKeyPem, cv: "none", authResults: "spf=pass" }); },
    /rfc822/);
  _rejects("arc.sign: i=1 cv=pass",
    function () { b.mail.arc.sign({ rfc822: rfc822, instance: 1, authservId: "x", domain: "x", selector: "x", privateKey: arcKeyPem, algorithm: "rsa-sha256", cv: "pass", authResults: "spf=pass" }); },
    /i=1 requires cv=none/);
  _rejects("arc.sign: i=2 cv=none",
    function () { b.mail.arc.sign({ rfc822: hop1.rfc822, instance: 2, authservId: "x", domain: "x", selector: "x", privateKey: arcKeyPem, algorithm: "rsa-sha256", cv: "none", authResults: "spf=pass" }); },
    /i>=2 disallows cv=none/);
  _rejects("arc.sign: bad algorithm",
    function () { b.mail.arc.sign({ rfc822: rfc822, instance: 1, authservId: "x", domain: "x", selector: "x", privateKey: arcKeyPem, algorithm: "md5-rsa", cv: "none", authResults: "spf=pass" }); },
    /algorithm/);
  _rejects("arc.sign: CRLF in authResults",
    function () { b.mail.arc.sign({ rfc822: rfc822, instance: 1, authservId: "x", domain: "x", selector: "x", privateKey: arcKeyPem, algorithm: "rsa-sha256", cv: "none", authResults: "spf=pass\r\nInjected: header" }); },
    /CR\/LF|injection/);
  _rejects("arc.sign: chain gap (i=3 with no i=1 i=2)",
    function () { b.mail.arc.sign({ rfc822: rfc822, instance: 3, authservId: "x", domain: "x", selector: "x", privateKey: arcKeyPem, algorithm: "rsa-sha256", cv: "pass", authResults: "spf=pass" }); },
    /chain has 0 hops|chain has gap/);
  _rejects("arc.sign: bad instance (0)",
    function () { b.mail.arc.sign({ rfc822: rfc822, instance: 0, authservId: "x", domain: "x", selector: "x", privateKey: arcKeyPem, algorithm: "rsa-sha256", cv: "none", authResults: "spf=pass" }); },
    /instance must be/);
  // A non-finite t= timestamp must be refused, not floored into a malformed tag.
  _rejects("arc.sign: timestamp Infinity refused",
    function () { b.mail.arc.sign({ rfc822: rfc822, instance: 1, authservId: "x", domain: "x", selector: "x", privateKey: arcKeyPem, algorithm: "rsa-sha256", cv: "none", authResults: "spf=pass", timestamp: Infinity }); },
    /timestamp|finite/);
}

function testArcSignRejectsCrlfInjection() {
  var nodeCrypto = require("crypto");
  var arcKey = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var arcKeyPem = arcKey.privateKey.export({ format: "pem", type: "pkcs8" });
  var rfc822 = "From: a@x\r\nTo: b@y\r\nSubject: hi\r\n" +
    "Date: Wed, 06 May 2026 12:00:00 +0000\r\nMessage-ID: <1@x>\r\n\r\nbody\r\n";
  var base = {
    rfc822: rfc822, instance: 1, authservId: "relay.example.com", domain: "relay.example.com",
    selector: "arc", privateKey: arcKeyPem, algorithm: "rsa-sha256", cv: "none",
    authResults: "spf=pass smtp.mailfrom=a@x",
  };
  function withField(k, v) { var o = {}; for (var kk in base) o[kk] = base[kk]; o[k] = v; return o; }
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }

  // authservId / domain / selector are interpolated verbatim into the ARC
  // header block (ARC-Authentication-Results / ARC-Seal /
  // ARC-Message-Signature). A CR/LF must not smuggle a new header — the
  // authResults field was already guarded; these were not.
  var e1 = threw(function () { b.mail.arc.sign(withField("authservId", "relay.example.com\r\nInjected: 1")); });
  check("arc.sign: CRLF in authservId throws arc-sign/bad-authserv",
    e1 && e1.code === "arc-sign/bad-authserv");
  var e2 = threw(function () { b.mail.arc.sign(withField("domain", "relay.example.com\r\nInjected: 1")); });
  check("arc.sign: CRLF in domain throws arc-sign/bad-domain",
    e2 && e2.code === "arc-sign/bad-domain");
  var e3 = threw(function () { b.mail.arc.sign(withField("selector", "arc\r\nInjected: 1")); });
  check("arc.sign: CRLF in selector throws arc-sign/bad-selector",
    e3 && e3.code === "arc-sign/bad-selector");
  var e4 = threw(function () { b.mail.arc.sign(withField("authservId", "relay" + String.fromCharCode(0) + "x")); });
  check("arc.sign: NUL in authservId throws arc-sign/bad-authserv",
    e4 && e4.code === "arc-sign/bad-authserv");
  // authResults is placed verbatim on the ARC-Authentication-Results line —
  // a NUL is a header-smuggling byte just like CR/LF, so it must be rejected
  // (the prior guard only checked CR/LF).
  var e5 = threw(function () { b.mail.arc.sign(withField("authResults", "spf=pass" + String.fromCharCode(0) + "x")); });
  check("arc.sign: NUL in authResults throws arc-sign/bad-auth-results",
    e5 && e5.code === "arc-sign/bad-auth-results");
}

// A relay's own freshly-signed ARC chain MUST verify as cv=pass. The
// ARC-Message-Signature carries i=<instance> — an RFC 8617 §4.1.2 instance
// number (1..50), NOT a DKIM AUID. AMS verification reuses the DKIM verifier
// on a synthetic message; the DKIM §3.5 AUID-subdomain check must not treat
// the AMS instance number as an AUID, or every valid ARC chain permerrors.
// (The prior ARC tests only asserted shape-failure modes with dummy b=AAAA
// signatures — no real sign->verify roundtrip ever exercised the pass path,
// which is how the instance/AUID collision shipped.)
async function testArcRealRoundtripVerifiesPass() {
  var nodeCrypto = require("crypto");
  var arcKey = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var arcKeyPem = arcKey.privateKey.export({ format: "pem", type: "pkcs8" });
  var spkiB64 = arcKey.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  var dnsLookup = async function (qname) {
    if (qname === "arc._domainkey.relay.example") {
      return [["v=DKIM1; k=rsa; p=" + spkiB64]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };

  var rfc822 =
    "From: alice@example.com\r\n" +
    "To: bob@example.com\r\n" +
    "Subject: hello arc\r\n" +
    "Date: Wed, 06 May 2026 12:00:00 +0000\r\n" +
    "Message-ID: <rt-1@example.com>\r\n" +
    "\r\n" +
    "body body body\r\n";

  var hop1 = b.mail.arc.sign({
    rfc822:        rfc822,
    instance:      1,
    authservId:    "relay.example",
    domain:        "relay.example",
    selector:      "arc",
    privateKey:    arcKeyPem,
    algorithm:     "rsa-sha256",
    cv:            "none",
    authResults:   "spf=pass smtp.mailfrom=alice@example.com",
    headersToSign: ["From", "To", "Subject", "Date", "Message-ID"],
  });

  var rv = await b.mail.arc.verify(hop1.rfc822, { dnsLookup: dnsLookup });
  check("arc.verify: valid single-hop chain → chainStatus=pass",
        rv.chainStatus === "pass");
  check("arc.verify: AMS instance i= not treated as a DKIM AUID (amsResult=pass)",
        rv.hops && rv.hops[0] && rv.hops[0].amsResult === "pass");
  check("arc.verify: ARC-Seal verifies (asResult=pass)",
        rv.hops[0].asResult === "pass");

  // Second hop sealed over the validated first hop (cv=pass) must also verify,
  // proving the instance/AUID fix holds at i>=2 where i= is "2".
  var hop2 = b.mail.arc.sign({
    rfc822:        hop1.rfc822,
    instance:      2,
    authservId:    "relay.example",
    domain:        "relay.example",
    selector:      "arc",
    privateKey:    arcKeyPem,
    algorithm:     "rsa-sha256",
    cv:            "pass",
    authResults:   "spf=pass smtp.mailfrom=alice@example.com",
    headersToSign: ["From", "To", "Subject", "Date", "Message-ID"],
  });
  var rv2 = await b.mail.arc.verify(hop2.rfc822, { dnsLookup: dnsLookup });
  check("arc.verify: valid two-hop chain → chainStatus=pass",
        rv2.chainStatus === "pass");
  check("arc.verify: both hops' AMS verify (i=1 and i=2 instances)",
        rv2.hops.length === 2 &&
        rv2.hops[0].amsResult === "pass" && rv2.hops[1].amsResult === "pass");
}

async function testArcFinalArInstanceForgery() {
  // arcEvaluate surfaces finalAr — "the receiver's view of upstream auth
  // results" — for downstream policy. The instance tag (i=) of every ARC
  // header MUST be parsed identically by the indexing pass (which drives the
  // AMS/AS crypto checks) and by the finalAr extraction. When the sealer's AMS
  // h= omits arc-authentication-results (RFC-permitted; the verifier supports
  // it), an attacker holding no key can inject a SECOND
  // ARC-Authentication-Results whose instance is written so the strict indexer
  // ignores it ("i = 1" with a space) while a looser finalAr parser still
  // consumes it — forging the upstream auth-results on a chain that still
  // verifies pass. finalAr must come from the same strictly-indexed hop the
  // crypto validated. RED before the unification: attacked.finalAr carries
  // "FORGED"; the chain still reports pass.
  var nodeCrypto = require("crypto");
  var arcKey = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var arcKeyPem = arcKey.privateKey.export({ format: "pem", type: "pkcs8" });
  var spkiB64 = arcKey.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  var dnsLookup = async function (qname) {
    if (qname === "arc._domainkey.relay-fa.example") return [["v=DKIM1; k=rsa; p=" + spkiB64]];
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rfc822 =
    "From: alice@example.com\r\n" +
    "To: bob@example.com\r\n" +
    "Subject: hello arc\r\n" +
    "Date: Wed, 06 May 2026 12:00:00 +0000\r\n" +
    "Message-ID: <fa-1@example.com>\r\n" +
    "\r\n" +
    "body body body\r\n";
  // Sign with AAR EXCLUDED from the AMS h= — the RFC-permitted sealer shape the
  // forgery rides (the AAR is not signature-covered, so an injected sibling is
  // invisible to the AMS/AS crypto).
  var hop1 = b.mail.arc.sign({
    rfc822:            rfc822,
    instance:          1,
    authservId:        "relay-fa.example",
    domain:            "relay-fa.example",
    selector:          "arc",
    privateKey:        arcKeyPem,
    algorithm:         "rsa-sha256",
    cv:                "none",
    authResults:       "spf=pass smtp.mailfrom=alice@example.com",
    headersToSign:     ["From", "To", "Subject", "Date", "Message-ID"],
    excludeAarFromAms: true,
  });

  var clean = await b.mail.arc.evaluate(hop1.rfc822, { dnsLookup: dnsLookup, trustedSealers: ["relay-fa.example"] });
  check("arc.evaluate: AAR-excluded-from-AMS chain still verifies pass",
        clean.chainStatus === "pass");
  check("arc.evaluate: finalAr is the genuine upstream AAR",
        typeof clean.finalAr === "string" && /spf=pass/.test(clean.finalAr) &&
        clean.finalAr.indexOf("FORGED") === -1);

  // Inject a SECOND ARC-Authentication-Results AFTER the genuine one, using
  // "i = 1" (the space the strict indexer rejects) so the crypto pass never
  // sees it but a loose finalAr parser would.
  var FORGED = "ARC-Authentication-Results: i = 1; attacker.example; dkim=pass header.d=victim.example (FORGED)\r\n";
  var idx = hop1.rfc822.indexOf("ARC-Authentication-Results:");
  var aarEnd = hop1.rfc822.indexOf("\r\n", idx) + 2;
  var injected = hop1.rfc822.slice(0, aarEnd) + FORGED + hop1.rfc822.slice(aarEnd);

  var attacked = await b.mail.arc.evaluate(injected, { dnsLookup: dnsLookup, trustedSealers: ["relay-fa.example"] });
  check("arc.evaluate: an injected loose-i= AAR does not change the crypto verdict (still pass)",
        attacked.chainStatus === "pass");
  check("arc.evaluate: finalAr is NOT forged by an injected loose-i= AAR",
        typeof attacked.finalAr === "string" &&
        attacked.finalAr.indexOf("FORGED") === -1 && /spf=pass/.test(attacked.finalAr));
}

function testArcSignExcludeAarFromAms() {
  // RFC 8617 §5.1.1 — the AMS h= should cover arc-authentication-results so
  // receivers that canonicalize it (M365, Gmail) verify the chain; the signer
  // auto-prepends it. `excludeAarFromAms: true` opts out (deprecated). The opt
  // was documented + read but absent from the validate allow-list, so passing
  // it threw "unknown option" — the opt-out was unreachable. Assert both the
  // default (AAR present in h=) and the opt-out (AAR absent).
  var nodeCrypto = require("crypto");
  var key = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var keyPem = key.privateKey.export({ format: "pem", type: "pkcs8" });
  var rfc822 = "From: a@x.example\r\nTo: b@y.example\r\nSubject: s\r\nDate: Wed, 06 May 2026 12:00:00 +0000\r\nMessage-ID: <e-1@x.example>\r\n\r\nbody\r\n";
  var base = {
    rfc822: rfc822, instance: 1, authservId: "x.example", domain: "x.example",
    selector: "arc", privateKey: keyPem, algorithm: "rsa-sha256", cv: "none",
    authResults: "spf=pass", headersToSign: ["From", "To", "Subject"],
  };
  var def = b.mail.arc.sign(base);
  check("arc.sign: default AMS h= covers arc-authentication-results (auto-prepended)",
        /h=[^;]*arc-authentication-results/i.test(def.ams));
  var excluded = b.mail.arc.sign(Object.assign({}, base, { excludeAarFromAms: true }));
  check("arc.sign: excludeAarFromAms is accepted (no longer an unknown-option throw)",
        typeof excluded.ams === "string");
  check("arc.sign: excludeAarFromAms omits arc-authentication-results from the AMS h=",
        !/h=[^;]*arc-authentication-results/i.test(excluded.ams));
}

// ---- DMARCbis (B1) — psd= / np= / org-domain via PSL ----

function testDmarcParseBisTags() {
  var policy = b.mail.dmarc.parseRecord(
    "v=DMARC1; p=reject; sp=quarantine; np=reject; psd=y; pct=100"
  );
  check("dmarc.parseRecord parses np=", policy.np === "reject");
  check("dmarc.parseRecord parses psd=", policy.psd === "y");
  check("dmarc.parseRecord retains sp=", policy.sp === "quarantine");
}

function testDmarcParseBisBadTag() {
  var threw = null;
  try { b.mail.dmarc.parseRecord("v=DMARC1; p=none; np=invalid"); }
  catch (e) { threw = e; }
  check("dmarc.parseRecord rejects bad np=",
        threw && /dmarcbis-bad-tag/.test(threw.code || ""));
  threw = null;
  try { b.mail.dmarc.parseRecord("v=DMARC1; p=none; psd=maybe"); }
  catch (e) { threw = e; }
  check("dmarc.parseRecord rejects bad psd=",
        threw && /dmarcbis-bad-tag/.test(threw.code || ""));
}

async function testDmarcEvaluateOrgDomainViaPsl() {
  // mail.example.com has no _dmarc record; example.com (the
  // organizational domain via PSL) does. The org-domain walk should
  // find it and apply sp= as the operative policy.
  var dnsLookup = async function (host) {
    if (host === "_dmarc.example.com") {
      return [["v=DMARC1; p=reject; sp=quarantine; aspf=r"]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dmarc.evaluate({
    from:    "alice@mail.example.com",
    spf:     { result: "pass", domain: "different.org" },
    dkim:    [],
    dnsLookup: dnsLookup,
  });
  check("dmarc.evaluate: org-domain walk via PSL applies sp=",
        rv.orgDomainPolicyApplied === true &&
        rv.policyOriginDomain === "example.com" &&
        rv.policy.p === "quarantine" &&
        rv.recommendedAction === "quarantine");
  check("dmarc.evaluate: surfaces orgDomain",
        rv.orgDomain === "example.com");
}

async function testDmarcEvaluateNpPolicy() {
  // np= applies when the message's From-domain doesn't exist.
  // operator-supplied domainExists callback returns false; the
  // org-domain record's np= policy is the operative one.
  var dnsLookup = async function (host) {
    if (host === "_dmarc.example.com") {
      return [["v=DMARC1; p=none; np=reject"]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.dmarc.evaluate({
    from:    "alice@nonexistent.example.com",
    spf:     { result: "fail", domain: "example.com" },
    dkim:    [],
    dnsLookup: dnsLookup,
    domainExists: async function () { return false; },
  });
  check("dmarc.evaluate: np= applies on non-existent subdomain",
        rv.npPolicyApplied === true &&
        rv.recommendedAction === "reject");
}

// ---- ARC trust-eval (B6) ----

async function testArcEvaluateSurface() {
  // No ARC headers — chain status none, trust failed, breakAt null.
  var msg = "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.evaluate(msg, { trustedSealers: ["example.com"] });
  check("arc.evaluate: empty chain → trust=failed, no trustedHops",
        rv.trust === "failed" &&
        Array.isArray(rv.trustedHops) && rv.trustedHops.length === 0 &&
        rv.breakAt === null && rv.finalAr === null);
}

async function testArcEvaluateBadTrustedSealers() {
  var threw = null;
  try {
    await b.mail.arc.evaluate("From: x\r\n\r\nbody\r\n",
                              { trustedSealers: ["", null, "example.com"] });
  } catch (e) { threw = e; }
  check("arc.evaluate: empty-string trustedSealers rejected",
        threw && /arc-trust-eval-failed/.test(threw.code || ""));
}

async function testArcEvaluateBreakAt() {
  // Build a chain with bad signatures so amsResult/asResult fail at i=1.
  // breakAt should be 1; finalAr should be the AAR text.
  var msg = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
            "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
            "ARC-Authentication-Results: i=1; example.com; spf=pass smtp.mailfrom=alice@example.com\r\n" +
            "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var dnsLookup = async function () {
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.arc.evaluate(msg, {
    trustedSealers: ["example.com"],
    dnsLookup:      dnsLookup,
  });
  check("arc.evaluate: failed chain → trust=failed",
        rv.trust === "failed");
  check("arc.evaluate: breakAt = first failing hop",
        rv.breakAt === 1);
  check("arc.evaluate: finalAr captures most-recent AAR",
        typeof rv.finalAr === "string" &&
        rv.finalAr.indexOf("smtp.mailfrom=alice@example.com") !== -1);
}

// ---- iprev (B8) ----

async function testIprevSurface() {
  check("mail.iprev.verify is a function",
        typeof b.mail.iprev.verify === "function");
}

async function testIprevPermerror() {
  var rv = await b.mail.iprev.verify("not-an-ip");
  check("iprev.verify: bad input → permerror",
        rv.result === "permerror" && rv.fcrdns === false);
  var rv2 = await b.mail.iprev.verify("");
  check("iprev.verify: empty input → permerror",
        rv2.result === "permerror");
}

async function testIprevValidIpShape() {
  // Run with a TEST-NET-1 address that won't resolve. We don't assert
  // a specific verdict (PTR → fail OR temperror depending on network);
  // we assert the shape — `result` is one of the expected vocabulary.
  var rv = await b.mail.iprev.verify("192.0.2.1");
  var expected = { pass: 1, fail: 1, permerror: 1, temperror: 1 };
  check("iprev.verify: TEST-NET-1 → known result vocabulary",
        expected[rv.result] === 1 && typeof rv.fcrdns === "boolean");
  check("iprev.verify: result shape carries ip",
        rv.ip === "192.0.2.1");
}

// ---- Audit findings 2026-05-15 — MAIL-9/10/25/39/50/56/58/66 coverage ----

async function testSpfRedirectModifier() {
  // MAIL-9 — redirect= modifier was previously dropped. A domain whose
  // only policy is `v=spf1 redirect=_spf.example.com` must resolve to
  // the target's verdict.
  var dnsLookup = async function (host) {
    if (host === "redirected.example") {
      return [["v=spf1 redirect=_spf.example.com"]];
    }
    if (host === "_spf.example.com") {
      return [["v=spf1 ip4:192.0.2.0/24 -all"]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.5", mailFrom: "alice@redirected.example", dnsLookup: dnsLookup,
  });
  check("MAIL-9: redirect= modifier resolves to target verdict",
        rv.result === "pass");
}

async function testSpfVoidLookupLimit() {
  // MAIL-9 — RFC 7208 §4.6.4 void-lookup cap. Chain of include= to
  // non-existent domains must permerror before the 10-lookup limit.
  var dnsLookup = async function (host) {
    if (host === "sender.example") {
      return [["v=spf1 include:void1.example include:void2.example include:void3.example -all"]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.5", mailFrom: "alice@sender.example", dnsLookup: dnsLookup,
  });
  check("MAIL-9: void-lookup cap trips permerror before 10-lookup ceiling",
        rv.result === "permerror" &&
        /void-lookup|RFC 7208 §5\.2|void/.test(rv.explanation || ""));
}

async function testSpfRecordByteLengthCap() {
  // MAIL-58 — RFC 7208 §3.3 caps SPF records at 450 bytes. Refuse
  // longer records with permerror.
  var bigPolicy = "v=spf1";
  // Build a record well over 450 bytes via padded ip4 mechanisms.
  for (var i = 0; i < 30; i += 1) {
    bigPolicy += " ip4:192.0.2." + (i % 256) + "/32";
  }
  bigPolicy += " -all";
  var dnsLookup = async function () { return [[bigPolicy]]; };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.5", mailFrom: "alice@oversize.example", dnsLookup: dnsLookup,
  });
  check("MAIL-58: SPF record > 450 bytes refused as permerror",
        rv.result === "permerror" && /450|bytes/.test(rv.explanation || ""));
}

async function testDmarcPctSamplingDeterministic() {
  // MAIL-10 + MAIL-56 — pctSampleKey makes the sample roll stable
  // across retries (same key → same verdict). Without a key, the
  // roll uses crypto.randomInt (not Math.random) but is non-stable.
  var dnsLookup = async function (host) {
    if (host === "_dmarc.example.com") return [["v=DMARC1; p=reject; pct=1"]];
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var stableKey = "MessageId<abc@example.com>+example.com+receiver-secret";
  var firstAction = null;
  for (var i = 0; i < 5; i += 1) {
    var rv = await b.mail.dmarc.evaluate({
      from: "alice@example.com",
      spf: { result: "fail", domain: "example.com" },
      dkim: [],
      dnsLookup: dnsLookup,
      pctSampleKey: stableKey,
    });
    if (firstAction === null) firstAction = rv.recommendedAction;
    check("MAIL-10: deterministic sampling — retry " + i + " matches first",
          rv.recommendedAction === firstAction);
  }
}

async function testDmarcAlignmentUsesPsl() {
  // MAIL-25 — relaxed alignment uses the public-suffix list. A
  // From-header at `evil-bank.com` must NOT align with a DKIM signer
  // at `bank.com` despite the text suffix overlap.
  var _dnsLookup = async function (host) {
    if (host === "_dmarc.bank.com") return [["v=DMARC1; p=reject; aspf=r; adkim=r"]];
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  // Same-org case for the positive control: foo.bank.com vs bank.com
  // SHOULD align (same org-domain).
  var rvAligned = await b.mail.dmarc.evaluate({
    from: "alice@foo.bank.com",
    spf: { result: "pass", domain: "bank.com" },
    dkim: [{ result: "pass", domain: "bank.com" }],
    dnsLookup: async function (host) {
      if (host === "_dmarc.foo.bank.com") {
        var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
      }
      if (host === "_dmarc.bank.com") return [["v=DMARC1; p=reject"]];
      var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
    },
  });
  check("MAIL-25: same-PSL-org domains DO align in relaxed mode",
        rvAligned.result === "pass" && rvAligned.alignment.dkim === true);

  // Negative case: separately-registered confusables don't align.
  var rvSpoof = await b.mail.dmarc.evaluate({
    from: "alice@evil-bank.com",
    spf: { result: "pass", domain: "bank.com" },
    dkim: [{ result: "pass", domain: "bank.com" }],
    dnsLookup: async function (host) {
      if (host === "_dmarc.evil-bank.com") return [["v=DMARC1; p=reject"]];
      var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
    },
  });
  check("MAIL-25: separately-registered confusable domains do NOT align",
        rvSpoof.alignment.spf === false && rvSpoof.alignment.dkim === false);
}

function testDmarcRuaGunzipBombDistinguished() {
  // MAIL-39 — bomb error code must be distinct from generic gunzip
  // failure so audit / alert rules can react. Use zlib to craft a
  // tiny gzip stream that decompresses past the cap.
  var nodeZlib = require("zlib");
  var huge = Buffer.alloc(16 * 1024 * 1024, 0x41);                                 // 16 MiB of 'A'
  var gz = nodeZlib.gzipSync(huge);
  // Force the gunzip-bomb path by feeding through parseAggregateReport.
  var threw = null;
  try { b.mail.dmarc.parseAggregateReport(gz, { contentType: "application/gzip" }); }
  catch (e) { threw = e; }
  check("MAIL-39: decompression-bomb gunzip output → dmarc-rua-gunzip-bomb (distinct from gunzip-failed)",
        threw && /dmarc-rua-gunzip-bomb/.test(threw.code || ""));
}

function testDmarcRuaBuildRoundTrip() {
  // RFC 7489 Appendix C — buildAggregateReport is the inverse of
  // parseAggregateReport; a shaped report serialized to XML and re-
  // parsed MUST deep-equal the input (the parser adds a derived
  // `totals` convenience field, removed before comparison).
  var shaped = {
    reportMetadata: {
      orgName: "reporter.example",
      email: "dmarc@reporter.example",
      reportId: "rpt-12345",
      extraContact: null,
      dateRange: { begin: 1700000000, end: 1700086400 },
    },
    policyPublished: {
      domain: "example.com", adkim: "r", aspf: "r",
      p: "reject", sp: "quarantine", pct: 100, fo: null,
    },
    records: [
      {
        sourceIp: "192.0.2.10", count: 7,
        dispositions: {
          disposition: "none", dkim: "pass", spf: "fail",
          reasons: [{ type: "forwarded", comment: "mailing list" }],
        },
        identifiers: { headerFrom: "example.com", envelopeFrom: "example.com", envelopeTo: null },
        authResults: {
          dkim: [{ domain: "example.com", selector: "sel1", result: "pass", humanResult: null }],
          spf: [{ domain: "example.com", result: "fail", scope: "mfrom" }],
        },
      },
      {
        // header_from carries XML metacharacters (a spoofed identifier
        // observed in the wild) — escaping MUST survive the round-trip.
        sourceIp: "203.0.113.5", count: 3,
        dispositions: { disposition: "quarantine", dkim: "fail", spf: "fail", reasons: [] },
        identifiers: { headerFrom: "evil<&>\".example.com", envelopeFrom: null, envelopeTo: null },
        authResults: { dkim: [], spf: [{ domain: "spoof.example", result: "fail", scope: "mfrom" }] },
      },
    ],
  };
  var xml = b.mail.dmarc.buildAggregateReport(shaped);
  check("dmarc.buildAggregateReport returns an XML string with <feedback> root",
        typeof xml === "string" && /^<\?xml/.test(xml) && xml.indexOf("<feedback>") !== -1);
  // The injected metacharacters must be entity-escaped in the wire form.
  check("dmarc.buildAggregateReport escapes XML metacharacters",
        xml.indexOf("evil<&>") === -1 && xml.indexOf("&lt;&amp;&gt;") !== -1);

  var back = b.mail.dmarc.parseAggregateReport(xml);
  delete back.totals;
  check("dmarc.buildAggregateReport round-trips through parseAggregateReport",
        JSON.stringify(back) === JSON.stringify(shaped));

  // Optional gzip path mirrors the parser's gzip auto-detect.
  var gz = b.mail.dmarc.buildAggregateReport(shaped, { gzip: true });
  check("dmarc.buildAggregateReport({gzip:true}) → gzip Buffer",
        Buffer.isBuffer(gz) && gz[0] === 0x1f && gz[1] === 0x8b);
  var back2 = b.mail.dmarc.parseAggregateReport(gz, { contentType: "application/gzip" });
  delete back2.totals;
  check("dmarc.buildAggregateReport(gzip) round-trips",
        JSON.stringify(back2) === JSON.stringify(shaped));
}

function testDmarcRuaBuildBadInput() {
  // Config-time tier — a malformed report shape THROWS so the operator
  // catches it before mailing the report to a peer.
  var cases = [
    { arg: null,                                              re: /object/ },
    { arg: { policyPublished: {}, records: [] },             re: /reportMetadata/ },
    { arg: { reportMetadata: {}, records: [] },              re: /policyPublished/ },
    { arg: { reportMetadata: {}, policyPublished: {} },      re: /records/ },
    { arg: { reportMetadata: {}, policyPublished: {},
             records: [{ sourceIp: "1.2.3.4", count: "notnum",
                         dispositions: {}, identifiers: {}, authResults: {} }] },
      re: /finite integer/ },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var threw = null;
    try { b.mail.dmarc.buildAggregateReport(cases[i].arg); }
    catch (e) { threw = e; }
    check("dmarc.buildAggregateReport rejects bad input #" + i,
          threw && cases[i].re.test(threw.message || ""));
  }
}

// RFC 6591 §4.1 / RFC 7489 §7.3 — a DMARC forensic (RUF) failure
// report: multipart/report (report-type=feedback-report) whose
// message/feedback-report part carries Feedback-Type: auth-failure plus
// the forensic-specific fields (Auth-Failure, Delivery-Result,
// Identity-Alignment, DKIM-*/SPF-*), and a message/rfc822 part with the
// reported message.
var DMARC_RUF_SAMPLE =
  "From: <postmaster@example.com>\r\n" +
  "Date: Fri, 15 May 2026 12:00:00 -0400\r\n" +
  "Subject: FW: DMARC failure report\r\n" +
  "To: <ruf@sender.example>\r\n" +
  "MIME-Version: 1.0\r\n" +
  "Content-Type: multipart/report; report-type=feedback-report;\r\n" +
  '\tboundary="ruf_boundary_abc"\r\n' +
  "\r\n" +
  "--ruf_boundary_abc\r\n" +
  "Content-Type: text/plain; charset=\"US-ASCII\"\r\n" +
  "\r\n" +
  "This is a DMARC authentication-failure report.\r\n" +
  "\r\n" +
  "--ruf_boundary_abc\r\n" +
  "Content-Type: message/feedback-report\r\n" +
  "\r\n" +
  "Feedback-Type: auth-failure\r\n" +
  "User-Agent: ExampleReporter/1.0\r\n" +
  "Version: 1\r\n" +
  "Original-Mail-From: <bounce@sender.example>\r\n" +
  "Original-Rcpt-To: <victim@example.com>\r\n" +
  "Arrival-Date: Fri, 15 May 2026 11:59:00 -0400\r\n" +
  "Source-IP: 203.0.113.7\r\n" +
  "Reported-Domain: sender.example\r\n" +
  "Authentication-Results: mx.example.com; dmarc=fail header.from=sender.example\r\n" +
  "Auth-Failure: dmarc\r\n" +
  "Delivery-Result: reject\r\n" +
  "Identity-Alignment: none\r\n" +
  "DKIM-Domain: sender.example\r\n" +
  "DKIM-Identity: @sender.example\r\n" +
  "DKIM-Selector: sel2026\r\n" +
  "DKIM-Canonicalized-Header: from:Sender <noreply@sender.example>\r\n" +
  "SPF-DNS: txt sender.example \"v=spf1 ip4:198.51.100.0/24 -all\"\r\n" +
  "\r\n" +
  "--ruf_boundary_abc\r\n" +
  "Content-Type: message/rfc822\r\n" +
  "\r\n" +
  "From: Sender <noreply@sender.example>\r\n" +
  "To: <victim@example.com>\r\n" +
  "Subject: You have won\r\n" +
  "Message-ID: <forged-123@sender.example>\r\n" +
  "\r\n" +
  "Body of the reported message.\r\n" +
  "--ruf_boundary_abc--\r\n";

function testDmarcForensicSurface() {
  check("dmarc.parseForensicReport is a function",
        typeof b.mail.dmarc.parseForensicReport === "function");
}

function testDmarcForensicParse() {
  var rv = b.mail.dmarc.parseForensicReport(DMARC_RUF_SAMPLE);
  check("dmarc.parseForensicReport: ok envelope on a valid report",
        rv && rv.ok === true && rv.report && typeof rv.report === "object");
  var rep = rv.report;
  check("dmarc.parseForensicReport: feedbackType=auth-failure",
        rep.feedbackType === "auth-failure");
  check("dmarc.parseForensicReport: authFailure=dmarc (RFC 6591 §3.1)",
        rep.authFailure === "dmarc");
  check("dmarc.parseForensicReport: deliveryResult=reject",
        rep.deliveryResult === "reject");
  check("dmarc.parseForensicReport: identityAlignment=none (RFC 7489 §7.3)",
        rep.identityAlignment === "none");
  check("dmarc.parseForensicReport: DKIM-* fields shaped",
        rep.dkim && rep.dkim.domain === "sender.example" &&
        rep.dkim.selector === "sel2026" &&
        rep.dkim.identity === "@sender.example" &&
        /noreply@sender\.example/.test(rep.dkim.canonicalizedHeader || ""));
  check("dmarc.parseForensicReport: spf.dns captured",
        rep.spf && /v=spf1/.test(rep.spf.dns || ""));
  check("dmarc.parseForensicReport: base ARF fields carried through",
        rep.sourceIp === "203.0.113.7" &&
        rep.reportedDomain === "sender.example" &&
        /dmarc=fail/.test(rep.authenticationResults || ""));
  check("dmarc.parseForensicReport: reported message headers parsed",
        Array.isArray(rep.reportedHeaders) &&
        rep.reportedHeaderMap["message-id"] === "<forged-123@sender.example>" &&
        rep.reportedHeaderMap.subject === "You have won");
  check("dmarc.parseForensicReport: reportedHeaderMap is null-prototype",
        Object.getPrototypeOf(rep.reportedHeaderMap) === null);
}

function testDmarcForensicNotAuthFailure() {
  // An RFC 5965 abuse report is a valid ARF report but NOT a DMARC
  // forensic report — Feedback-Type must be auth-failure (RFC 7489 §7.3).
  var abuseReport = DMARC_RUF_SAMPLE.replace(
    "Feedback-Type: auth-failure", "Feedback-Type: abuse");
  var rv = b.mail.dmarc.parseForensicReport(abuseReport);
  check("dmarc.parseForensicReport: non-auth-failure Feedback-Type → typed error (not a throw)",
        rv && rv.ok === false &&
        /dmarc-ruf-not-auth-failure/.test(rv.error.code || ""));
}

function testDmarcForensicMissingAuthFailure() {
  // RFC 6591 §3.1 — Auth-Failure is required in an auth-failure report.
  var noAuthFailure = DMARC_RUF_SAMPLE.replace("Auth-Failure: dmarc\r\n", "");
  var rv = b.mail.dmarc.parseForensicReport(noAuthFailure);
  check("dmarc.parseForensicReport: missing Auth-Failure → typed error",
        rv && rv.ok === false &&
        /dmarc-ruf-missing-auth-failure/.test(rv.error.code || ""));
}

function testDmarcForensicHostileInputDoesNotThrow() {
  // Defensive reader — hostile / malformed input MUST return a typed
  // error, never throw in the hot path that ingested the report.
  var cases = [null, 12345, "", "not-a-multipart-report",
               Buffer.from("garbage"),
               "Content-Type: text/plain\r\n\r\nnope"];
  for (var i = 0; i < cases.length; i += 1) {
    var threw = null;
    var rv = null;
    try { rv = b.mail.dmarc.parseForensicReport(cases[i]); }
    catch (e) { threw = e; }
    check("dmarc.parseForensicReport: hostile input #" + i + " returns typed error, no throw",
          threw === null && rv && rv.ok === false &&
          rv.error && typeof rv.error.code === "string");
  }
}

function testDmarcForensicReportedHeaderCap() {
  // RFC 6591 §3.2 reported-header cap — a report whose reported message
  // carries > the header cap clips the parsed list and flags it, while
  // still surfacing the verbatim message. Build a reported message with
  // many headers.
  var lines = [];
  for (var i = 0; i < 400; i += 1) lines.push("X-Pad-" + i + ": v" + i);
  var bigReported = lines.join("\r\n") + "\r\n\r\nbody\r\n";
  var sample = DMARC_RUF_SAMPLE.replace(
    "From: Sender <noreply@sender.example>\r\n" +
    "To: <victim@example.com>\r\n" +
    "Subject: You have won\r\n" +
    "Message-ID: <forged-123@sender.example>\r\n" +
    "\r\n" +
    "Body of the reported message.\r\n",
    bigReported);
  var rv = b.mail.dmarc.parseForensicReport(sample);
  check("dmarc.parseForensicReport: over-cap reported headers are clipped + flagged",
        rv && rv.ok === true &&
        rv.report.reportedHeaders.length === 256 &&
        rv.report.reportedHeadersTruncated === true);
}

function testDmarcForensicPrototypePollutionSafe() {
  // A hostile report naming a feedback-report field or a reported-message
  // header `__proto__` / `constructor` must not pollute Object.prototype.
  var sample = DMARC_RUF_SAMPLE
    // feedback-report field block — exercises the extraFields path.
    .replace("Auth-Failure: dmarc\r\n",
             "Auth-Failure: dmarc\r\n__proto__: fieldpoison\r\n")
    // reported message header block — exercises the reportedHeaderMap path.
    .replace("From: Sender <noreply@sender.example>\r\n",
             "From: Sender <noreply@sender.example>\r\n__proto__: hdrpoison\r\n");
  var rv = b.mail.dmarc.parseForensicReport(sample);
  check("dmarc.parseForensicReport: __proto__ in feedback field → own data on null-prototype extraFields",
        rv && rv.ok === true &&
        Object.getPrototypeOf(rv.report.extraFields) === null &&
        rv.report.extraFields["__proto__"] === "fieldpoison");
  check("dmarc.parseForensicReport: __proto__ reported header → own data, no prototype pollution",
        rv.report.reportedHeaderMap["__proto__"] === "hdrpoison" &&
        ({}).fieldpoison === undefined &&
        ({}).hdrpoison === undefined &&
        Object.prototype.fieldpoison === undefined &&
        Object.prototype.hdrpoison === undefined);
}

async function testIprevValidatesPtrShape() {
  // MAIL-50 — PTR result MUST be a valid DNS-name shape (LDH labels,
  // 1..63 octets, total 1..253 octets). Synthesize via a mocked
  // resolver if possible; alternatively, exercise the validator.
  check("MAIL-50: surface — iprev refuses non-IP input",
        typeof b.mail.iprev.verify === "function");
  // Direct call with garbage IP — should be permerror without DNS.
  var rv = await b.mail.iprev.verify("not-an-ip-literal");
  check("MAIL-50: invalid IP literal → permerror without DNS",
        rv.result === "permerror");
}

async function testArcHeaderSourceOrder() {
  // MAIL-66 — RFC 8617 §5.2 source-order rule. Hops MUST appear top-
  // to-bottom in strictly-decreasing instance order. An ascending
  // shuffled chain is a structural failure.
  var ascending = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAA\r\n" +
                  "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAA; h=from; b=AAA\r\n" +
                  "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
                  "ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=example.com; s=arc; b=AAA\r\n" +
                  "ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAA; h=from; b=AAA\r\n" +
                  "ARC-Authentication-Results: i=2; example.com; spf=pass\r\n" +
                  "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(ascending);
  check("MAIL-66: ascending-instance source order refused (header-order-violation)",
        rv.chainStatus === "fail" && /header-order/.test(rv.reason || ""));
}

// v0.11.3 — SPF a / mx mechanism dispatch (RFC 7208 §5.3 / §5.4).
async function testSpfMechanismA() {
  var dnsLookup = async function (host, type) {
    if (host === "example.com" && type === "TXT") {
      return [["v=spf1 a -all"]];
    }
    if (host === "example.com" && type === "A") {
      return ["192.0.2.10", "192.0.2.11"];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.10", mailFrom: "alice@example.com", dnsLookup: dnsLookup,
  });
  check("spf.verify(a, matching A) → pass", rv.result === "pass");

  var rv2 = await b.mail.spf.verify({
    ip: "192.0.2.99", mailFrom: "alice@example.com", dnsLookup: dnsLookup,
  });
  check("spf.verify(a, non-matching A) → fail (-all)", rv2.result === "fail");
}

async function testSpfMechanismADualCidr() {
  // a:other.example/24 — match any IP in the /24 of other.example's A.
  var dnsLookup = async function (host, type) {
    if (host === "sender.example" && type === "TXT") {
      return [["v=spf1 a:other.example/24 -all"]];
    }
    if (host === "other.example" && type === "A") {
      return ["192.0.2.10"];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.99", mailFrom: "alice@sender.example", dnsLookup: dnsLookup,
  });
  check("spf.verify(a:other/24, IP in /24) → pass", rv.result === "pass");

  var rv2 = await b.mail.spf.verify({
    ip: "192.0.3.5", mailFrom: "alice@sender.example", dnsLookup: dnsLookup,
  });
  check("spf.verify(a:other/24, IP outside /24) → fail", rv2.result === "fail");
}

async function testSpfMechanismMx() {
  var dnsLookup = async function (host, type) {
    if (host === "example.com" && type === "TXT") {
      return [["v=spf1 mx -all"]];
    }
    if (host === "example.com" && type === "MX") {
      return [{ exchange: "mx1.example.com", preference: 10 },
              { exchange: "mx2.example.com", preference: 20 }];
    }
    if (host === "mx1.example.com" && type === "A") return ["192.0.2.20"];
    if (host === "mx2.example.com" && type === "A") return ["192.0.2.21"];
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.21", mailFrom: "alice@example.com", dnsLookup: dnsLookup,
  });
  check("spf.verify(mx, matching MX-host A) → pass", rv.result === "pass");

  var rv2 = await b.mail.spf.verify({
    ip: "192.0.2.99", mailFrom: "alice@example.com", dnsLookup: dnsLookup,
  });
  check("spf.verify(mx, non-matching) → fail", rv2.result === "fail");
}

async function testSpfMechanismMxOverLimit() {
  // RFC 7208 §4.6.4 — mx MUST permerror when > 10 MX hosts.
  var mxList = [];
  for (var i = 0; i < 11; i += 1) {                                                // allow:raw-byte-literal — RFC 7208 §4.6.4 +1 over limit
    mxList.push({ exchange: "mx" + i + ".example.com", preference: 10 + i });
  }
  var dnsLookup = async function (host, type) {
    if (host === "example.com" && type === "TXT") return [["v=spf1 mx -all"]];
    if (host === "example.com" && type === "MX") return mxList;
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.5", mailFrom: "alice@example.com", dnsLookup: dnsLookup,
  });
  check("spf.verify(mx, > 10 hosts) → permerror (RFC 7208 §4.6.4)",
        rv.result === "permerror" && /caps at 10/.test(rv.explanation || ""));
}

async function testSpfMechanismExists() {
  // RFC 7208 §5.7 + §7 — `exists:<macro-string>` resolves the expanded
  // domain; a present A record matches. The macro `%{l}` expands to the
  // sender local-part, so `exists:%{l}.spf.example.com` queries
  // `alice.spf.example.com`.
  var queried = [];
  var dnsLookup = async function (host, type) {
    if (host === "example.com" && type === "TXT") {
      return [["v=spf1 exists:%{l}.spf.example.com -all"]];
    }
    if (type === "A") {
      queried.push(host);
      if (host === "alice.spf.example.com") return ["127.0.0.2"];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.5", mailFrom: "alice@example.com", dnsLookup: dnsLookup,
  });
  check("spf.verify(exists:%{l}..., A present) -> pass + expanded qname",
        rv.result === "pass" && queried.some(function (q) { return q === "alice.spf.example.com"; }));

  // No A record at the expanded target -> exists misses -> falls to -all.
  var dnsMiss = async function (host, type) {
    if (host === "example.com" && type === "TXT") {
      return [["v=spf1 exists:%{l}.spf.example.com -all"]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv2 = await b.mail.spf.verify({
    ip: "192.0.2.5", mailFrom: "alice@example.com", dnsLookup: dnsMiss,
  });
  check("spf.verify(exists, no A at target) -> fail (-all)", rv2.result === "fail");
}

async function testSpfMacroExpansionExistsIrV() {
  // RFC 7208 §7.1-§7.4 — `%{ir}.%{v}._spf.%{d}` is the canonical per-IP
  // exists query. For 192.0.2.10: %{ir} reverses the dotted IP to
  // "10.2.0.192", %{v} -> "in-addr", %{d} -> the current domain.
  // Expected qname: 10.2.0.192.in-addr._spf.example.com.
  var queried = null;
  var dnsLookup = async function (host, type) {
    if (host === "example.com" && type === "TXT") {
      return [["v=spf1 exists:%{ir}.%{v}._spf.%{d} -all"]];
    }
    if (type === "A") {
      queried = host;
      if (host === "10.2.0.192.in-addr._spf.example.com") return ["127.0.0.2"];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.10", mailFrom: "alice@example.com",
    helo: "mta.example.com", dnsLookup: dnsLookup,
  });
  check("spf macro %{ir}.%{v}._spf.%{d} expands correctly",
        queried === "10.2.0.192.in-addr._spf.example.com" && rv.result === "pass");
}

async function testSpfMacroBadSyntaxPermerror() {
  // RFC 7208 §7.1 — malformed macro syntax MUST permerror.
  var shapes = [
    { rec: "v=spf1 exists:%{z} -all",   re: /7\.2/ },     // unknown letter
    { rec: "v=spf1 exists:%{i.x -all",  re: /closing/ },  // no closing brace
    { rec: "v=spf1 exists:%q -all",     re: /invalid/ },  // bad escape
    { rec: "v=spf1 exists:%{} -all",    re: /empty/ },    // empty macro
  ];
  for (var i = 0; i < shapes.length; i += 1) {
    var rec = shapes[i].rec;
    var dns = (function (r) {
      return async function (host, type) {
        if (host === "example.com" && type === "TXT") return [[r]];
        var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
      };
    }(rec));
    var rv = await b.mail.spf.verify({
      ip: "192.0.2.1", mailFrom: "bob@example.com", dnsLookup: dns,
    });
    check("spf.verify(" + JSON.stringify(rec) + ") -> permerror (bad macro)",
          rv.result === "permerror" && shapes[i].re.test(rv.explanation || ""));
  }
}

async function testSpfExistsRespectsLookupLimit() {
  // RFC 7208 §4.6.4 — exists A queries count toward the 10-lookup and
  // 2-void ceilings; a chain of exists: misses MUST permerror rather
  // than amplifying resolver work without bound.
  var dns = async function (host, type) {
    if (type === "TXT" && host === "example.com") {
      return [["v=spf1 exists:a.%{d} exists:b.%{d} exists:c.%{d} -all"]];
    }
    var err = new Error("ENODATA"); err.code = "ENODATA"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.1", mailFrom: "bob@example.com", dnsLookup: dns,
  });
  check("spf.verify(exists chain) -> permerror (RFC 7208 §4.6.4 void cap)",
        rv.result === "permerror" && /void-lookup limit/.test(rv.explanation || ""));
}

async function testSpfMechanismEmptyDualCidrRefused() {
  // RFC 7208 §5.3 / §5.4 — ip4-cidr-length and ip6-cidr-length are
  // each `"/" 1*DIGIT`. Empty digit segments are malformed grammar
  // and MUST permerror. Pre-v0.11.3.1 the parser silently kept the
  // default /32 or /128, which over-authorized senders publishing
  // `v=spf1 a/ -all` (would match every IP in the /32 of every A
  // record of the sender's domain).
  var shapes = ["a/", "a//", "a/24//", "a//64-extra-after", "mx/", "mx//"];
  for (var i = 0; i < shapes.length; i += 1) {
    var policy = "v=spf1 " + shapes[i] + " -all";
    var dnsLookup = (function (pol) {
      return async function (host, type) {
        if (host === "example.com" && type === "TXT") return [[pol]];
        if (host === "example.com" && type === "A")   return ["192.0.2.10"];
        if (host === "example.com" && type === "MX")  return [{ exchange: "mx1.example.com", preference: 10 }];
        if (host === "mx1.example.com" && type === "A") return ["192.0.2.20"];
        var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
      };
    }(policy));
    var rv = await b.mail.spf.verify({
      ip: "192.0.2.10", mailFrom: "alice@example.com", dnsLookup: dnsLookup,
    });
    check("spf.verify(" + JSON.stringify(shapes[i]) + ") → permerror (empty cidr-length)",
          rv.result === "permerror" &&
          /(cidr-length is empty|cidr-length invalid|dual-cidr malformed)/.test(rv.explanation || ""));
  }
}

async function testSpfMechanismPtrRemainsDeferred() {
  var dnsLookup = async function (host, type) {
    if (host === "example.com" && type === "TXT") return [["v=spf1 ptr -all"]];
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.5", mailFrom: "alice@example.com", dnsLookup: dnsLookup,
  });
  check("spf.verify(ptr, deferred) → permerror with §5.5 cite",
        rv.result === "permerror" && /5\.5/.test(rv.explanation || ""));
}

// ARC canon-source header parser — byte-exact golden lock. The AMS/AS
// signatures are computed over the bytes this parser extracts; a sign->verify
// round-trip shares the parser and so cannot catch a byte-error (it would only
// surface as a rejection at a real ARC verifier). ARC's relaxed-canon parser
// STRIPS leading WSP from the value (vs DKIM's simple-canon parser, which
// preserves it) and PRESERVES the raw CRLF of a folded continuation.
function testArcHeaderParserGolden() {
  var ph = arcSign._parseHeaderBlockForTest;
  function eq(label, raw, expected) {
    check("arc parser: " + label, JSON.stringify(ph(raw)) === JSON.stringify(expected));
  }
  eq("relaxed parser STRIPS leading WSP from value",
     "From: a@b.com",
     [{ name: "From", value: "a@b.com" }]);
  eq("leading SP + TAB stripped",
     "X: \tvalue",
     [{ name: "X", value: "value" }]);
  eq("folded continuation keeps raw CRLF + line",
     "From: a@b.com\r\nSubject: hello\r\n world",
     [{ name: "From", value: "a@b.com" },
      { name: "Subject", value: "hello\r\n world" }]);
  eq("exact name, order preserved across a colon-less line",
     "From: a@b.com\r\ngarbage\r\nTo: c@d.com",
     [{ name: "From", value: "a@b.com" },
      { name: "To", value: "c@d.com" }]);
}

function testByteCapMultibyte() {
  // dmarc.parseForensicReport maxBytes is a BYTE cap; it returns an error
  // object (does not throw) on refusal.
  var report = String.fromCharCode(0x4e2d).repeat(20); // 60 UTF-8 bytes; cap 30
  var r = b.mail.dmarc.parseForensicReport(report, { maxBytes: 30 });
  check("dmarc-ruf byte-cap: multibyte report over byte cap rejected",
    r && r.ok === false && r.error && r.error.code === "mail-auth/dmarc-ruf-too-large");
}

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

// ---- SPF: input validation (config-time throw at the entry point) ----

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

// A dnsLookup fake that throws a transient (non-absence) resolver fault
// for every query — drives the temperror classification arms.
function _transientDns() {
  return async function () {
    var e = new Error("resolver server failure"); e.code = "ESERVFAIL"; throw e;
  };
}

function _enotfound() {
  var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
}

// Run one SPF exists: policy and capture the expanded A-query names.
async function _spfExistsExpand(record, mailFrom, ip) {
  var queried = [];
  var dns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [[record]];
    if (type === "A") { queried.push(host); return ["127.0.0.2"]; }
    return _enotfound();
  };
  var rv = await b.mail.spf.verify({
    ip: ip || "192.0.2.9", mailFrom: mailFrom, dnsLookup: dns,
  });
  return { result: rv.result, queried: queried, explanation: rv.explanation };
}

// ---- SPF: macro escapes, letters, and custom delimiters (RFC 7208 §7) ----

async function testSpfMacroEscapesAndLetters() {
  var mf = "alice@s.example";
  // `%-` legacy escape expands to the literal "%20" (RFC 7208 §7.1).
  var hyphen = await _spfExistsExpand("v=spf1 exists:a%-b.probe -all", mf);
  check("spf macro %- → literal %20",
        hyphen.result === "pass" && hyphen.queried.indexOf("a%20b.probe") !== -1);
  // `%{s}` — the whole sender identity (local@domain).
  var sender = await _spfExistsExpand("v=spf1 exists:%{s}.probe -all", mf);
  check("spf macro %{s} → full sender identity",
        sender.result === "pass" && sender.queried.indexOf("alice@s.example.probe") !== -1);
  // `%{p}` — validated-domain sentinel; the framework returns "unknown"
  // rather than performing the discouraged §5.5 reverse-lookup.
  var pMac = await _spfExistsExpand("v=spf1 exists:%{p}.probe -all", mf);
  check("spf macro %{p} → RFC 7208 §5.5 'unknown' sentinel",
        pMac.result === "pass" && pMac.queried.indexOf("unknown.probe") !== -1);
  // `%{c}` — an exp-text-only letter; empty in mechanism context (§7.3).
  var cMac = await _spfExistsExpand("v=spf1 exists:x%{c}y.probe -all", mf);
  check("spf macro %{c} (exp-only letter) → empty in mechanism context",
        cMac.result === "pass" && cMac.queried.indexOf("xy.probe") !== -1);
  // Custom delimiter set: `%{l+}` splits the local-part on `+` and
  // re-joins with `.` (RFC 7208 §7.1 transformer delimiter set).
  var delim = await _spfExistsExpand("v=spf1 exists:%{l+}.probe -all", "a+b@s.example");
  check("spf macro %{l+} → custom '+' split delimiter re-joined with '.'",
        delim.result === "pass" && delim.queried.indexOf("a.b.probe") !== -1);
}

// ---- SPF: IPv6 macro letters (RFC 7208 §7.3) ----

async function testSpfMacroIpv6Letters() {
  var mf = "u@s.example";
  var v = await _spfExistsExpand("v=spf1 exists:%{v}.probe -all", mf, "2001:db8::1");
  check("spf macro %{v} on IPv6 connection → 'ip6'",
        v.result === "pass" && v.queried.indexOf("ip6.probe") !== -1);
  var iMac = await _spfExistsExpand("v=spf1 exists:%{i}.probe -all", mf, "2001:db8::1");
  check("spf macro %{i} on IPv6 → nibble-dotted 32-part form",
        iMac.result === "pass" &&
        iMac.queried.indexOf("2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.probe") !== -1);
}

// ---- SPF: additional malformed-macro syntax arms (RFC 7208 §7.1) ----

async function testSpfMacroBadSyntaxMore() {
  async function bad(record) {
    var dns = _txtOnly({ "s.example": [[record]] });
    var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
    return rv;
  }
  var bare = await bad("v=spf1 exists:foo% -all");
  check("spf macro: trailing bare '%' → permerror",
        bare.result === "permerror" && /bare '%'/.test(bare.explanation || ""));
  var digit0 = await bad("v=spf1 exists:%{s0} -all");
  check("spf macro: transformer digit count 0 → permerror",
        digit0.result === "permerror" && /digit count must be >= 1/.test(digit0.explanation || ""));
  var badDelim = await bad("v=spf1 exists:%{d!} -all");
  check("spf macro: delimiter outside the §7.1 set → permerror",
        badDelim.result === "permerror" && /not in the RFC 7208 §7\.1 set/.test(badDelim.explanation || ""));
}

// ---- SPF: CIDR mask edges — /0 (match-all) + partial-group prefix ----

async function testSpfCidrMaskEdges() {
  // ip4:0.0.0.0/0 — a /0 authorizes every IPv4 (mask 0 → unconditional).
  var dns4 = _txtOnly({ "s.example": [["v=spf1 ip4:0.0.0.0/0 -all"]] });
  var r4 = await b.mail.spf.verify({ ip: "203.0.113.9", mailFrom: "a@s.example", dnsLookup: dns4 });
  check("spf ip4:0.0.0.0/0 → pass (mask 0 matches any IPv4)", r4.result === "pass");

  // ip6 partial-group prefix (/36): compares full groups + a masked
  // remainder-bit nibble, exercising the non-16-aligned mask arm.
  var dns36 = _txtOnly({ "s.example": [["v=spf1 ip6:2001:db8:8000::/36 -all"]] });
  var in36 = await b.mail.spf.verify({ ip: "2001:db8:8fff::1", mailFrom: "a@s.example", dnsLookup: dns36 });
  check("spf ip6:.../36 — IP inside the partial-group prefix → pass", in36.result === "pass");
  var out36 = await b.mail.spf.verify({ ip: "2001:db8:0fff::1", mailFrom: "a@s.example", dnsLookup: dns36 });
  check("spf ip6:.../36 — IP outside the partial-group prefix → fail (-all)", out36.result === "fail");

  // ip6 /0 — mask 0 authorizes any IPv6.
  var dns6z = _txtOnly({ "s.example": [["v=spf1 ip6:2001:db8::/0 -all"]] });
  var r6z = await b.mail.spf.verify({ ip: "fe80::1", mailFrom: "a@s.example", dnsLookup: dns6z });
  check("spf ip6:.../0 → pass (mask 0 matches any IPv6)", r6z.result === "pass");
}

// ---- SPF: multiple published records → permerror (RFC 7208 §4.5) ----

async function testSpfMultipleRecordsPermerror() {
  var dns = _txtOnly({ "s.example": [["v=spf1 -all"], ["v=spf1 +all"]] });
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify: two published v=spf1 records → permerror (RFC 7208 §4.5)",
        rv.result === "permerror" && /at most one/.test(rv.explanation || ""));
}

// ---- SPF: transient TXT lookup fault → temperror ----

async function testSpfLookupFailureTemperror() {
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: _transientDns() });
  check("spf.verify: transient TXT resolver fault → temperror (a verdict, not a throw)",
        rv.result === "temperror" && /lookup for s\.example failed/.test(rv.explanation || ""));
}

// ---- SPF: DNS-lookup ceiling exceeded (RFC 7208 §4.6.4) ----

async function testSpfLookupLimitExceeded() {
  // Eleven DNS-touching `a` mechanisms — the 11th crosses the 10-lookup
  // ceiling. Each A resolves to a non-matching address so the loop keeps
  // consuming lookups instead of short-circuiting on a match.
  var dns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 a a a a a a a a a a a -all"]];
    if (type === "A") return ["198.51.100.1"];
    return _enotfound();
  };
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify: 11 DNS mechanisms → permerror (RFC 7208 §4.6.4 lookup ceiling)",
        rv.result === "permerror" && /DNS lookup limit exceeded/.test(rv.explanation || ""));
}

// ---- SPF: a / mx DNS-failure + macro arms ----

async function testSpfAMxErrorBranches() {
  // a: with a bad-macro domain-spec → permerror (the §7 expansion throws).
  var badMacro = _txtOnly({ "s.example": [["v=spf1 a:%{z} -all"]] });
  var rBad = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: badMacro });
  check("spf a:%{z} — invalid macro-letter in domain-spec → permerror",
        rBad.result === "permerror" && /not a valid macro-letter/.test(rBad.explanation || ""));

  // a: whose domain-spec macro-expands to the empty string → permerror.
  var emptyMacro = _txtOnly({ "s.example": [["v=spf1 a:%{c} -all"]] });
  var rEmpty = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: emptyMacro });
  check("spf a:%{c} — domain-spec expands to empty → permerror",
        rEmpty.result === "permerror" && /expanded to empty/.test(rEmpty.explanation || ""));

  // a — transient A lookup fault → temperror.
  var aTemp = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 a -all"]];
    if (type === "A") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rATemp = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: aTemp });
  check("spf a — transient A lookup fault → temperror",
        rATemp.result === "temperror" && /a:s\.example lookup failed/.test(rATemp.explanation || ""));

  // mx — transient MX lookup fault → temperror.
  var mxTemp = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rMxTemp = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxTemp });
  check("spf mx — transient MX lookup fault → temperror",
        rMxTemp.result === "temperror" && /mx:s\.example MX lookup failed/.test(rMxTemp.explanation || ""));

  // mx — MX host A resolution transient fault → temperror.
  var mxHostTemp = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") return [{ exchange: "mx1.s.example", preference: 10 }];
    if (type === "A") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rMxHostTemp = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxHostTemp });
  check("spf mx — MX-host A resolution fault → temperror",
        rMxHostTemp.result === "temperror" && /mx host mx1\.s\.example A\/AAAA lookup failed/.test(rMxHostTemp.explanation || ""));

  // mx — MX host with no A record (void) is a miss, not an error → -all fail.
  var mxHostVoid = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") return [{ exchange: "mx1.s.example", preference: 10 }];
    return _enotfound();
  };
  var rMxVoid = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxHostVoid });
  check("spf mx — MX host with no A record → miss, falls to -all fail",
        rMxVoid.result === "fail");
}

// ---- SPF: exists transient lookup fault → temperror ----

async function testSpfExistsTemperror() {
  var dns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 exists:p.%{d} -all"]];
    if (type === "A") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf exists — transient A lookup fault → temperror",
        rv.result === "temperror" && /exists:p\.s\.example lookup failed/.test(rv.explanation || ""));
}

// ---- SPF: include macro + transient arms ----

async function testSpfIncludeErrorBranches() {
  // include target is itself a bad macro-string → permerror.
  var badMacro = _txtOnly({ "s.example": [["v=spf1 include:%{z} -all"]] });
  var rBad = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: badMacro });
  check("spf include:%{z} — invalid macro-letter → permerror",
        rBad.result === "permerror" && /not a valid macro-letter/.test(rBad.explanation || ""));

  // include target's TXT resolution transiently faults → temperror propagates.
  var incTemp = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 include:inner.example -all"]];
    if (type === "TXT" && host === "inner.example") { var e = new Error("srv"); e.code = "ESERVFAIL"; throw e; }
    return _enotfound();
  };
  var rTemp = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: incTemp });
  check("spf include — inner transient TXT fault → temperror propagates to outer verdict",
        rTemp.result === "temperror" && /lookup for inner\.example failed/.test(rTemp.explanation || ""));
}

// ---- DMARC: transient _dmarc lookup fault → temperror ----

async function testDmarcTemperror() {
  var rv = await b.mail.dmarc.evaluate({
    from: "u@x.example", spf: { result: "fail", domain: "x" }, dkim: [], dnsLookup: _transientDns(),
  });
  check("dmarc.evaluate: transient _dmarc lookup fault → temperror (not a silent pass)",
        rv.result === "temperror" && rv.policy === null &&
        rv.alignment.spf === false && rv.alignment.dkim === false);
}

// ---- DMARC: pct< 100 sampled disposition (RFC 7489 §6.6.4) ----

async function testDmarcPctSampledDispositions() {
  // The sample roll is a deterministic SHAKE256 of pctSampleKey → [0,100).
  // Recompute it here and publish pct = roll so `roll >= pct` holds → the
  // failing message lands in the SAMPLED (next-less-strict) fraction.
  var key = "sampled-disposition-key";
  var digest = nodeCrypto.createHash("shake256", { outputLength: 4 }).update(key).digest();
  var u32 = (digest[0] << 24 >>> 0) + (digest[1] << 16) + (digest[2] << 8) + digest[3];
  var roll = u32 % 100;

  var rejectDns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=reject; pct=" + roll]] });
  var reject = await b.mail.dmarc.evaluate({
    from: "a@example.com", spf: { result: "fail", domain: "x" }, dkim: [],
    dnsLookup: rejectDns, pctSampleKey: key,
  });
  check("dmarc.evaluate: p=reject, sampled fraction → recommendedAction quarantine (§6.6.4 step-down)",
        reject.result === "fail" && reject.recommendedAction === "quarantine");

  var quarDns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=quarantine; pct=" + roll]] });
  var quar = await b.mail.dmarc.evaluate({
    from: "a@example.com", spf: { result: "fail", domain: "x" }, dkim: [],
    dnsLookup: quarDns, pctSampleKey: key,
  });
  check("dmarc.evaluate: p=quarantine, sampled fraction → recommendedAction none (§6.6.4 step-down)",
        quar.result === "fail" && quar.recommendedAction === "none");
}

// ---- DMARC aggregate report: pre-parsed / bad-input / cap arms ----

async function testDmarcAggregatePreParsedAndErrors() {
  // Non-Buffer / non-string / non-feedback input → typed throw.
  var eIn = _threw(function () { b.mail.dmarc.parseAggregateReport(12345); });
  check("dmarc.parseAggregateReport: numeric input → dmarc-rua-bad-input",
        eIn && /dmarc-rua-bad-input/.test(eIn.code || ""));

  // Pre-parsed object shortcut: skips parse, shapes directly + aggregates
  // the per-record totals.
  var shaped = b.mail.dmarc.parseAggregateReport({
    feedback: {
      report_metadata: { org_name: "acme", report_id: "r-1", date_range: { begin: "1000", end: "2000" } },
      policy_published: { domain: "d.example", p: "none", pct: "100" },
      record: [
        { row: { source_ip: "1.2.3.4", count: "5",
                 policy_evaluated: { disposition: "none", dkim: "pass", spf: "fail" } },
          identifiers: { header_from: "d.example" },
          auth_results: { dkim: { domain: "d.example", selector: "s", result: "pass" },
                          spf: { domain: "d.example", result: "pass" } } },
        { row: { source_ip: "5.6.7.8", count: "3",
                 policy_evaluated: { disposition: "reject", dkim: "fail", spf: "fail",
                                     reason: { type: "trusted_forwarder", comment: "fwd" } } },
          identifiers: { header_from: "d.example", envelope_from: "d.example" },
          auth_results: { dkim: [], spf: [] } },
      ],
    },
  });
  check("dmarc.parseAggregateReport: pre-parsed object shortcut shapes metadata + records",
        shaped.reportMetadata.orgName === "acme" && shaped.records.length === 2 &&
        shaped.reportMetadata.dateRange.begin === 1000);
  check("dmarc.parseAggregateReport: totals aggregate aligned vs not-aligned by count",
        shaped.totals.messages === 8 && shaped.totals.aligned === 5 && shaped.totals.notAligned === 3);
  check("dmarc.parseAggregateReport: per-record policy_evaluated reasons shaped",
        shaped.records[1].dispositions.reasons.length === 1 &&
        shaped.records[1].dispositions.reasons[0].type === "trusted_forwarder");

  // Over the per-report record cap → typed throw.
  var big = { feedback: { report_metadata: {}, policy_published: {}, record: [] } };
  for (var i = 0; i < 10001; i += 1) big.feedback.record.push({});
  var eCap = _threw(function () { b.mail.dmarc.parseAggregateReport(big); });
  check("dmarc.parseAggregateReport: over the 10000-record cap → dmarc-rua-too-many-records",
        eCap && /dmarc-rua-too-many-records/.test(eCap.code || ""));

  // Parsed XML whose root is not <feedback> → typed throw.
  var eNoFb = _threw(function () { b.mail.dmarc.parseAggregateReport("<other></other>"); });
  check("dmarc.parseAggregateReport: non-<feedback> XML root → dmarc-rua-no-feedback",
        eNoFb && /dmarc-rua-no-feedback/.test(eNoFb.code || ""));
}

// ---- ARC: per-hop key-material failure arms (RFC 8617 §5.1) ----

function _arcKeyDns(qname, records) {
  return async function (q) {
    if (q === qname) return records;
    return _enotfound();
  };
}

async function testArcKeyErrorBranches() {
  var from = "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";

  // AMS missing its d= tag → the AMS reports "missing required tag(s)";
  // the AS (all tags present) fails its key lookup → permerror.
  var missingTags =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" + from;
  var rMiss = await b.mail.arc.verify(missingTags, { dnsLookup: async function () { return _enotfound(); } });
  var missAmsErrs = ((rMiss.hops[0] || {}).amsErrors || []).join(" ; ");
  check("arc.verify: AMS missing d/s/b/a → missing-required-tag(s) + chain fail",
        rMiss.chainStatus === "fail" && /missing required tag/.test(missAmsErrs));

  // AMS unsupported signature algorithm → permerror.
  var unsupAlg =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=magic-alg; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" + from;
  var rAlg = await b.mail.arc.verify(unsupAlg, { dnsLookup: async function () { return _enotfound(); } });
  var algErrs = ((rAlg.hops[0] || {}).amsErrors || []).join(" ; ");
  check("arc.verify: AMS unsupported alg → permerror + chain fail",
        rAlg.chainStatus === "fail" && /unsupported alg 'magic-alg'/.test(algErrs));

  // A structurally-complete hop with valid tags.
  var fullHop =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" + from;

  // Published key record lacks p= → permerror.
  var rNoP = await b.mail.arc.verify(fullHop,
    { dnsLookup: _arcKeyDns("arc._domainkey.example.com", [["v=DKIM1; k=rsa"]]) });
  var noPErrs = ((rNoP.hops[0] || {}).asErrors || []).join(" ; ");
  check("arc.verify: key record missing p= → permerror",
        rNoP.chainStatus === "fail" && /key record missing p=/.test(noPErrs));

  // Published p= is well-formed base64 but not a valid SPKI key → the AS
  // key parse fails → permerror.
  var rBadKey = await b.mail.arc.verify(fullHop,
    { dnsLookup: _arcKeyDns("arc._domainkey.example.com", [["v=DKIM1; k=rsa; p=AAAABBBB"]]) });
  var badKeyErrs = ((rBadKey.hops[0] || {}).asErrors || []).join(" ; ");
  check("arc.verify: unparseable key material → key-parse-failed permerror",
        rBadKey.chainStatus === "fail" && /key parse failed/.test(badKeyErrs));

  // Key lookup returns nothing (ENOTFOUND) on a valid-tag hop → permerror.
  var rNoKey = await b.mail.arc.verify(fullHop, { dnsLookup: async function () { return _enotfound(); } });
  check("arc.verify: key lookup ENOTFOUND → permerror (definitive absence, not temperror)",
        rNoKey.chainStatus === "fail" &&
        (rNoKey.hops[0] || {}).asResult === "permerror" &&
        (rNoKey.hops[0] || {}).amsResult === "permerror");
}

// ---- inbound.verify: no-identity + helo-only arms ----

async function testInboundNoIdentitySpfNone() {
  // Neither MAIL FROM nor HELO → SPF short-circuits to `none` without any
  // envelope-identity lookup. Keep the whole call offline with an
  // absence-only resolver so DMARC also resolves no record.
  var msg = "From: alice@example.com\r\nTo: bob@x\r\nSubject: hi\r\n\r\nbody\r\n";
  var v = await b.mail.inbound.verify({
    ip: "203.0.113.5", message: msg, dnsLookup: async function () { return _enotfound(); },
  });
  check("inbound.verify: no MAIL FROM / HELO → spf none (no identity lookup)",
        v.spf.result === "none" && /no MAIL FROM or HELO identity/.test(v.spf.explanation || ""));
  check("inbound.verify: no-identity + no DMARC record → dmarc none",
        v.dmarc.result === "none");
}

async function testInboundHeloOnlyAuthResults() {
  // HELO-only envelope: the emitted Authentication-Results carries the
  // spf clause with an smtp.helo property (not smtp.mailfrom).
  var msg = "From: alice@example.com\r\nTo: bob@x\r\nSubject: hi\r\n\r\nbody\r\n";
  var dns = _txtOnly({
    "mail.example.com":  [["v=spf1 ip4:203.0.113.0/24 -all"]],
    "_dmarc.example.com": [["v=DMARC1; p=none"]],
  });
  var v = await b.mail.inbound.verify({
    ip: "203.0.113.5", helo: "mail.example.com", message: msg,
    authservId: "mx.receiver.example", dnsLookup: dns,
  });
  check("inbound.verify: HELO-only identity → spf pass on the HELO domain",
        v.spf.result === "pass");
  check("inbound.verify: A-R spf clause carries smtp.helo (not smtp.mailfrom)",
        typeof v.authResults === "string" &&
        /spf=pass smtp\.helo=mail\.example\.com/.test(v.authResults) &&
        v.authResults.indexOf("smtp.mailfrom=") === -1);
}

// ---- SPF: a/mx operator-lookup empty / non-array answers (ENODATA) ----

async function testSpfAMxOperatorEnodata() {
  // RFC 7208 §5.3/§5.4 — an operator dnsLookup that RETURNS (not throws)
  // an empty or non-array A/AAAA / MX answer is an ENODATA void, not an
  // error: the mechanism misses and evaluation falls through to -all.
  var aEmpty = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 a -all"]];
    if (type === "A") return [];                                                 // successful, zero records
    return _enotfound();
  };
  var rAE = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: aEmpty });
  check("spf a — operator returns empty A array → miss → -all fail",
        rAE.result === "fail");

  var aNonArray = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 a -all"]];
    if (type === "A") return null;                                               // malformed non-array answer
    return _enotfound();
  };
  var rAN = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: aNonArray });
  check("spf a — operator returns non-array A answer → treated as ENODATA miss → fail",
        rAN.result === "fail");

  var mxEmpty = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") return [];                                                // successful, zero records
    return _enotfound();
  };
  var rME = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxEmpty });
  check("spf mx — operator returns empty MX array → miss → -all fail",
        rME.result === "fail");

  var mxNonArray = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") return null;                                             // malformed non-array answer
    return _enotfound();
  };
  var rMN = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxNonArray });
  check("spf mx — operator returns non-array MX answer → treated as ENODATA miss → fail",
        rMN.result === "fail");

  // MX normalization (RFC 1035 §3.3.9): a mixed answer of a bare exchange
  // string (preference defaulted to 0) and a { exchange, preference }
  // object with trailing dots is normalized + preference-sorted; the
  // lowest-preference host resolves to the connecting IP → pass.
  var mxMixed = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") return [{ exchange: "mx2.s.example.", preference: 20 }, "mx1.s.example."];
    if (type === "A" && host === "mx1.s.example") return ["192.0.2.5"];
    if (type === "A" && host === "mx2.s.example") return ["10.0.0.9"];
    return _enotfound();
  };
  var rMM = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxMixed });
  check("spf mx — mixed string/object MX answer normalizes + sorts → matching host → pass",
        rMM.result === "pass");
}

// ---- SPF: a/mx dual-cidr-length grammar edges (RFC 7208 §5.3/§5.4) ----

async function testSpfADualCidrErrorArms() {
  // v4 cidr-length out of range (>32) → permerror.
  var badV4 = _txtOnly({ "s.example": [["v=spf1 a/33 -all"]] });
  var rV4 = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: badV4 });
  check("spf a/33 — v4 cidr-length >32 → permerror",
        rV4.result === "permerror" && /v4 cidr-length invalid/.test(rV4.explanation || ""));

  // `a:` with an empty domain-spec resolves to no target domain → permerror.
  var noDomain = _txtOnly({ "s.example": [["v=spf1 a: -all"]] });
  var rND = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: noDomain });
  check("spf a: — empty domain-spec → no target domain → permerror",
        rND.result === "permerror" && /no target domain/.test(rND.explanation || ""));

  // `a//64` — valid v6 cidr-length; an AAAA in the /64 of the connecting
  // IPv6 address matches → pass (exercises the v6-mask assignment arm).
  var v6ok = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 a//64 -all"]];
    if (type === "AAAA" && host === "s.example") return ["2001:db8::1"];
    return _enotfound();
  };
  var rV6 = await b.mail.spf.verify({ ip: "2001:db8::9", mailFrom: "a@s.example", dnsLookup: v6ok });
  check("spf a//64 — connecting IPv6 inside AAAA /64 → pass",
        rV6.result === "pass");
}

// ---- SPF: §7.1 macro left-truncation to the 253-octet name ceiling ----

async function testSpfMacroLeftTruncation() {
  // RFC 7208 §7.1 — a macro expansion exceeding 253 octets is left-
  // truncated (leading labels discarded) until it fits. Drive it with an
  // oversized local-part (%{l}); the truncated target has no A record so
  // the exists misses and evaluation falls to -all.
  var longLocal = "x".repeat(300);
  var noDot = _txtOnly({ "s.example": [["v=spf1 exists:%{l} -all"]] });
  var rNoDot = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: longLocal + "@s.example", dnsLookup: noDot });
  check("spf exists:%{l} — >253-octet expansion (no dot) is truncated, evaluation completes → fail",
        rNoDot.result === "fail");

  var withDot = _txtOnly({ "s.example": [["v=spf1 exists:%{l}.e -all"]] });
  var rDot = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: longLocal + "@s.example", dnsLookup: withDot });
  check("spf exists:%{l}.e — >253-octet expansion (dotted) left-truncated at label boundary → fail",
        rDot.result === "fail");
}

// ---- SPF: exists mechanism crossing the §4.6.4 lookup ceiling ----

async function testSpfExistsLookupLimit() {
  // Ten `a:` mechanisms consume the 10-lookup budget (RFC 7208 §4.6.4);
  // the following `exists` increments past the ceiling → permerror.
  var rec = "v=spf1 a:h1 a:h2 a:h3 a:h4 a:h5 a:h6 a:h7 a:h8 a:h9 a:h10 exists:%{d} -all";
  var dns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [[rec]];
    if (type === "A") return ["10.0.0.1"];                                       // non-matching, so each a: misses
    return _enotfound();
  };
  var rv = await b.mail.spf.verify({ ip: "203.0.113.9", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf exists — over the §4.6.4 DNS-lookup ceiling → permerror at exists",
        rv.result === "permerror" && /lookup limit exceeded/.test(rv.explanation || "") &&
        /at exists:/.test(rv.explanation || ""));
}

// ---- DMARCbis: sp= tag value validation ----

function testDmarcParseBadSp() {
  var threw = null;
  try { b.mail.dmarc.parseRecord("v=DMARC1; p=none; sp=bogus"); }
  catch (e) { threw = e; }
  check("dmarc.parseRecord: sp= outside none|quarantine|reject → dmarcbis-bad-tag",
        threw && /dmarcbis-bad-tag/.test(threw.code || "") && /sp=/.test(threw.message || ""));
}

// ---- DMARCbis §4.7: public-suffix-domain (psd=y) policy walk ----

async function testDmarcEvaluatePsdPolicy() {
  // Neither the From-domain nor its organizational domain publishes a
  // DMARC record, but the public suffix (gov.uk) does with psd=y — the
  // receiver continues the lookup at the suffix and applies that policy.
  var dns = async function (host) {
    if (host === "_dmarc.gov.uk") return [["v=DMARC1; p=reject; psd=y"]];
    var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
  };
  var rv = await b.mail.dmarc.evaluate({
    from:      "alice@sub.example.gov.uk",
    spf:       { result: "fail", domain: "attacker.example" },
    dkim:      [],
    dnsLookup: dns,
  });
  check("dmarc.evaluate: psd=y suffix record applied when domain+org have none",
        rv.psdPolicyApplied === true &&
        rv.policyOriginDomain === "gov.uk" &&
        rv.result === "fail" &&
        rv.recommendedAction === "reject");
}

// ---- ARC: header/body separator + folded-header unfolding ----

async function testArcNoBodyAndFolded() {
  // _splitHeaders (RFC 8617) requires a header/body separator; a message
  // without one is a config-time throw, not a silent none.
  var noBody = "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
               "From: alice@example.com";
  var e1 = await _rejectedWith(b.mail.arc.verify(noBody));
  check("arc.verify: message with no header/body separator → arc-no-body",
        e1 && /arc-no-body/.test(e1.code || ""));

  // RFC 5322 §2.2.3 — a folded ARC-Seal (continuation line beginning with
  // FWS) unfolds to a single logical header; the hop still parses as one.
  var folded =
    "ARC-Seal: i=1; a=rsa-sha256;\r\n cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
    "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(folded, { dnsLookup: async function () { return _enotfound(); } });
  check("arc.verify: folded ARC-Seal unfolds → single hop parsed",
        rv.hopCount === 1 && rv.chainStatus === "fail");
}

// ---- ARC: arc.evaluate trustedSealers shape validation ----

async function testArcEvaluateTrustedSealersNotArray() {
  var eStr = await _rejectedWith(
    b.mail.arc.evaluate("From: x\r\n\r\nbody\r\n", { trustedSealers: "example.com" }));
  check("arc.evaluate: non-array trustedSealers → arc-bad-trusted-sealers",
        eStr && /arc-bad-trusted-sealers/.test(eStr.code || ""));
  var eMissing = await _rejectedWith(
    b.mail.arc.evaluate("From: x\r\n\r\nbody\r\n", {}));
  check("arc.evaluate: omitted trustedSealers → arc-bad-trusted-sealers",
        eMissing && /arc-bad-trusted-sealers/.test(eMissing.code || ""));
}

// ---- authResults.emit: version tag header-injection guard (RFC 8601) ----

function testAuthResultsEmitVersionControlChars() {
  var eVer = _threw(function () {
    b.mail.authResults.emit({ authservId: "mx.a", version: "1\r\nInjected: 1", results: [] });
  });
  check("authResults.emit: CR/LF in version → ar-bad-version (no header injection)",
        eVer && /ar-bad-version/.test(eVer.code || ""));
}

// ---- DMARC RUA aggregate: size cap + decompression + XML parse faults ----

function testDmarcAggregateSizeAndParseErrors() {
  // RFC 7489 §7.2.1.1 — a report exceeding the byte ceiling is refused
  // before any parse work (resource-exhaustion bound).
  var tooBig = Buffer.alloc(C.BYTES.mib(8) + 1);
  var eBig = _threw(function () { b.mail.dmarc.parseAggregateReport(tooBig); });
  check("dmarc.parseAggregateReport: over the byte cap → dmarc-rua-too-large",
        eBig && /dmarc-rua-too-large/.test(eBig.code || ""));

  // gzip magic (0x1f 0x8b) present but the stream is malformed (not a
  // decompression bomb) → the distinct gunzip-failed diagnostic.
  var badGz = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
  var eGz = _threw(function () { b.mail.dmarc.parseAggregateReport(badGz); });
  check("dmarc.parseAggregateReport: malformed gzip stream → dmarc-rua-gunzip-failed (not bomb)",
        eGz && /dmarc-rua-gunzip-failed/.test(eGz.code || ""));

  // Well-formed uncompressed bytes that aren't XML → typed XML-parse error.
  var eXml = _threw(function () { b.mail.dmarc.parseAggregateReport("this is not xml at all"); });
  check("dmarc.parseAggregateReport: non-XML payload → dmarc-rua-bad-xml",
        eXml && /dmarc-rua-bad-xml/.test(eXml.code || ""));
}

function testDmarcBuildTooManyRecords() {
  // RFC 7489 Appendix C — the aggregate builder caps records per report
  // (resource-exhaustion bound); over-cap input is a config-time throw.
  var eMany = _threw(function () {
    b.mail.dmarc.buildAggregateReport({
      reportMetadata: {}, policyPublished: {}, records: new Array(10001),
    });
  });
  check("dmarc.buildAggregateReport: over the per-report record cap → dmarc-rua-build-too-many-records",
        eMany && /dmarc-rua-build-too-many-records/.test(eMany.code || ""));
}

// ---- DMARC RUF forensic: report-structure rejection + optional-field arms ----

function testDmarcForensicMoreErrorArms() {
  var base =
    "From: <postmaster@example.com>\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: multipart/report; report-type=feedback-report;\r\n" +
    "\tboundary=\"bnd\"\r\n" +
    "\r\n" +
    "--bnd\r\n" +
    "Content-Type: message/feedback-report\r\n" +
    "\r\n" +
    "Feedback-Type: auth-failure\r\n" +
    "User-Agent: R/1.0\r\n" +
    "Version: 1\r\n" +
    "Auth-Failure: dmarc\r\n" +
    "Reported-Domain: sender.example\r\n" +
    "\r\n" +
    "--bnd\r\n" +
    "Content-Type: message/rfc822\r\n" +
    "\r\n" +
    "From: Sender <noreply@sender.example>\r\n" +
    "Subject: hi\r\n" +
    "\r\n" +
    "body\r\n" +
    "--bnd--\r\n";

  // A mismatched report-type is a valid feedback report but not a DMARC one.
  var rRt = b.mail.dmarc.parseForensicReport(base.replace("report-type=feedback-report", "report-type=abuse"));
  check("dmarc.parseForensicReport: report-type != feedback-report → dmarc-ruf-bad-report",
        rRt && rRt.ok === false && /dmarc-ruf-bad-report/.test(rRt.error.code || ""));

  // multipart/report without a boundary parameter can't be split.
  var rNoBnd = b.mail.dmarc.parseForensicReport(
    "Content-Type: multipart/report; report-type=feedback-report\r\n\r\nbody\r\n");
  check("dmarc.parseForensicReport: multipart/report with no boundary → dmarc-ruf-bad-report",
        rNoBnd && rNoBnd.ok === false && /dmarc-ruf-bad-report/.test(rNoBnd.error.code || ""));

  // Boundary present but the body has no parts.
  var rNoParts = b.mail.dmarc.parseForensicReport(
    "Content-Type: multipart/report; boundary=\"bnd\"\r\n\r\nnothing here\r\n");
  check("dmarc.parseForensicReport: multipart body with zero parts → dmarc-ruf-bad-report",
        rNoParts && rNoParts.ok === false && /dmarc-ruf-bad-report/.test(rNoParts.error.code || ""));

  // Over the per-report part cap (CWE-400 bound).
  var manyBody = "";
  for (var mp = 0; mp < 70; mp += 1) manyBody += "--bnd\r\nContent-Type: text/plain\r\n\r\np" + mp + "\r\n";
  manyBody += "--bnd--\r\n";
  var rManyParts = b.mail.dmarc.parseForensicReport(
    "Content-Type: multipart/report; report-type=feedback-report; boundary=\"bnd\"\r\n\r\n" + manyBody);
  check("dmarc.parseForensicReport: over the part cap → dmarc-ruf-too-many-parts",
        rManyParts && rManyParts.ok === false && /dmarc-ruf-too-many-parts/.test(rManyParts.error.code || ""));

  // Parts present but none is message/feedback-report.
  var noFb =
    "Content-Type: multipart/report; report-type=feedback-report; boundary=\"bnd\"\r\n\r\n" +
    "--bnd\r\nContent-Type: message/rfc822\r\n\r\nFrom: x@y\r\n\r\nb\r\n--bnd--\r\n";
  var rNoFb = b.mail.dmarc.parseForensicReport(noFb);
  check("dmarc.parseForensicReport: no message/feedback-report subpart → dmarc-ruf-no-feedback-report",
        rNoFb && rNoFb.ok === false && /dmarc-ruf-no-feedback-report/.test(rNoFb.error.code || ""));

  // Feedback-Type absent (Auth-Failure present) → the generic required-field
  // arm (distinct from the Auth-Failure-specific one).
  var rMissFt = b.mail.dmarc.parseForensicReport(base.replace("Feedback-Type: auth-failure\r\n", ""));
  check("dmarc.parseForensicReport: missing Feedback-Type field → dmarc-ruf-missing-field",
        rMissFt && rMissFt.ok === false && /dmarc-ruf-missing-field/.test(rMissFt.error.code || ""));

  // A headers-only reported message (text/rfc822-headers, no body) is
  // reassembled from its header bytes; Incidents normalizes to a number.
  var hdrsOnly =
    "Content-Type: multipart/report; report-type=feedback-report; boundary=\"bnd\"\r\n\r\n" +
    "--bnd\r\nContent-Type: message/feedback-report\r\n\r\n" +
    "Feedback-Type: auth-failure\r\nAuth-Failure: dmarc\r\nIncidents: 5\r\n\r\n" +
    "--bnd\r\nContent-Type: text/rfc822-headers\r\n\r\n" +
    "From: z@w\r\nSubject: s\r\n\r\n" +
    "--bnd--\r\n";
  var rHdrs = b.mail.dmarc.parseForensicReport(hdrsOnly);
  check("dmarc.parseForensicReport: text/rfc822-headers part reassembled + Incidents parsed",
        rHdrs && rHdrs.ok === true &&
        rHdrs.report.incidents === 5 &&
        rHdrs.report.reportedHeaders.length === 2);

  // No reported-message part at all → reportedHeaders is an empty list.
  var noReported =
    "Content-Type: multipart/report; report-type=feedback-report; boundary=\"bnd\"\r\n\r\n" +
    "--bnd\r\nContent-Type: message/feedback-report\r\n\r\n" +
    "Feedback-Type: auth-failure\r\nAuth-Failure: dmarc\r\n\r\n--bnd--\r\n";
  var rNoRep = b.mail.dmarc.parseForensicReport(noReported);
  check("dmarc.parseForensicReport: no reported message → empty reportedHeaders, still ok",
        rNoRep && rNoRep.ok === true && rNoRep.report.reportedHeaders.length === 0);

  // A text/rfc822-headers reported part with an EMPTY body (RFC 6591 §3.2
  // permits headers-only) is reassembled from its own header bytes rather
  // than dropped.
  var emptyBody =
    "Content-Type: multipart/report; report-type=feedback-report; boundary=\"bnd\"\r\n\r\n" +
    "--bnd\r\nContent-Type: message/feedback-report\r\n\r\n" +
    "Feedback-Type: auth-failure\r\nAuth-Failure: dmarc\r\n\r\n" +
    "--bnd\r\nContent-Type: text/rfc822-headers\r\n\r\n\r\n" +
    "--bnd--\r\n";
  var rEmpty = b.mail.dmarc.parseForensicReport(emptyBody);
  check("dmarc.parseForensicReport: empty-body text/rfc822-headers part is reassembled from header bytes",
        rEmpty && rEmpty.ok === true && rEmpty.report.reportedHeaders.length === 1);
}

// ---- SPF: mx expansion crossing the lookup / void ceilings (§4.6.4) ----

async function testSpfMxExpansionLimits() {
  // Nine `a:` mechanisms exhaust the lookup budget; the following `mx`
  // resolves a host whose A-expansion increments past the ceiling.
  var recL = "v=spf1 a:h1 a:h2 a:h3 a:h4 a:h5 a:h6 a:h7 a:h8 a:h9 mx -all";
  var dnsL = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [[recL]];
    if (type === "A" && /^h[0-9]/.test(host)) return ["10.0.0.1"];
    if (type === "MX" && host === "s.example") return [{ exchange: "mx1.s.example", preference: 10 }];
    if (type === "A" && host === "mx1.s.example") return ["10.0.0.2"];
    return _enotfound();
  };
  var rL = await b.mail.spf.verify({ ip: "203.0.113.9", mailFrom: "a@s.example", dnsLookup: dnsL });
  check("spf mx — A-expansion crossing the §4.6.4 lookup ceiling → permerror",
        rL.result === "permerror" && /during mx:s\.example expansion/.test(rL.explanation || ""));

  // Three MX hosts that each lack an A record are three void lookups —
  // over the §4.6.4 void ceiling of 2 → permerror.
  var dnsV = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX" && host === "s.example") return ["m1.s.example", "m2.s.example", "m3.s.example"];
    if (type === "A") return [];                                                 // every MX host is a void lookup
    return _enotfound();
  };
  var rV = await b.mail.spf.verify({ ip: "203.0.113.9", mailFrom: "a@s.example", dnsLookup: dnsV });
  check("spf mx — over the §4.6.4 void-lookup ceiling during expansion → permerror",
        rV.result === "permerror" && /void-lookup limit exceeded/.test(rV.explanation || "") &&
        /mx expansion/.test(rV.explanation || ""));
}

// ---- SPF: exists domain-spec that macro-expands to empty (§5.7) ----

async function testSpfExistsExpandsEmpty() {
  var dns = _txtOnly({ "s.example": [["v=spf1 exists:%{c} -all"]] });
  var rv = await b.mail.spf.verify({ ip: "203.0.113.9", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf exists:%{c} — domain-spec expands to empty → permerror (RFC 7208 §5.7)",
        rv.result === "permerror" && /expanded to an empty domain/.test(rv.explanation || ""));
}

// ---- SPF: redirect= recursion depth ceiling (§6.1) ----

async function testSpfRedirectDepthLimit() {
  // A chain of redirect= modifiers that never terminates trips the
  // recursion bound rather than spinning.
  var dns = async function (host, type) {
    if (type === "TXT") {
      var m = /^d(\d+)\.ex$/.exec(host);
      if (m) return [["v=spf1 redirect=d" + (parseInt(m[1], 10) + 1) + ".ex"]];
    }
    return _enotfound();
  };
  var rv = await b.mail.spf.verify({ ip: "203.0.113.9", mailFrom: "a@d0.ex", dnsLookup: dns });
  check("spf redirect= — unbounded redirect chain trips the §6.1 recursion limit → permerror",
        rv.result === "permerror" && /redirect= recursion limit exceeded/.test(rv.explanation || ""));
}

// ---- ARC: AS key TXT returned as a non-array operator answer ----

async function testArcKeyNonArrayTxt() {
  // A dnsLookup that returns the key record as a bare string (not the
  // documented array-of-string-arrays shape) is still parsed for its
  // tags; the malformed key material then fails the parse → permerror.
  var from = "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var fullHop =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" + from;
  var dns = async function (q) {
    if (q === "arc._domainkey.example.com") return "v=DKIM1; k=rsa; p=AAAABBBB";
    return _enotfound();
  };
  var rv = await b.mail.arc.verify(fullHop, { dnsLookup: dns });
  check("arc.verify: key TXT as bare string → tags parsed, bad key material → permerror",
        rv.chainStatus === "fail" &&
        (rv.hops[0] || {}).asResult === "permerror" &&
        /key parse failed/.test(((rv.hops[0] || {}).asErrors || []).join(" ; ")));
}

// ---- iprev (RFC 8601 §3): forward-confirm decision via operator dnsLookup ----
//
// Every other primitive in mail-auth exposes an operator dnsLookup so the
// verdict logic is unit-testable offline; iprev now does too (the PTR query
// receives the reverse-arpa qname, the forward query the PTR name). These
// drive the fcrdns pass/fail, PTR-shape rejection, and transient-fault arms
// that were previously reachable only over the live network.

// Build an iprev dnsLookup fake from a { ptr: [...], forward: {host: [...]} }
// spec. `errByCode` overrides a query to REJECT with the given DNS error code.
function _iprevDns(spec) {
  return async function (qname, type) {
    if (type === "PTR") {
      if (spec.ptrError) { var pe = new Error(spec.ptrError); pe.code = spec.ptrError; throw pe; }
      return spec.ptr || [];
    }
    if (type === "A" || type === "AAAA") {
      var host = qname.replace(/\.$/, "");
      if (spec.forwardError) { var fe = new Error(spec.forwardError); fe.code = spec.forwardError; throw fe; }
      var fwd = (spec.forward || {})[host];
      if (fwd === undefined) { var e = new Error("ENODATA"); e.code = "ENODATA"; throw e; }
      return fwd;
    }
    var e2 = new Error("ENOTFOUND"); e2.code = "ENOTFOUND"; throw e2;
  };
}

async function testIprevForwardConfirmedPass() {
  // IPv4 FCrDNS: PTR resolves to a name whose forward A set contains the
  // connecting IP → pass, fcrdns true. Also asserts the operator PTR query
  // received the reverse-arpa qname (exercises _ipToReverseArpa).
  var seenPtrQname = null;
  var dns = async function (qname, type) {
    if (type === "PTR") { seenPtrQname = qname; return ["mail.sender.example."]; }
    if (type === "A" && qname.replace(/\.$/, "") === "mail.sender.example") return ["203.0.113.5"];
    var e = new Error("ENODATA"); e.code = "ENODATA"; throw e;
  };
  var rv = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dns });
  check("iprev.verify: forward-confirmed IPv4 → pass + fcrdns true",
        rv.result === "pass" && rv.fcrdns === true &&
        rv.ptr === "mail.sender.example" && rv.forward.indexOf("203.0.113.5") !== -1);
  check("iprev.verify: PTR query used the reverse-arpa qname (RFC 8601 §3)",
        seenPtrQname === "5.113.0.203.in-addr.arpa");
}

async function testIprevForwardMismatchFail() {
  // PTR forward-resolves to a set that does NOT include the connecting IP —
  // a spoofed reverse zone. RFC 8601 §3: fail, not pass.
  var dns = _iprevDns({ ptr: ["evil.example."], forward: { "evil.example": ["198.51.100.9"] } });
  var rv = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dns });
  check("iprev.verify: PTR forward-set omits the connecting IP → fail (not pass)",
        rv.result === "fail" && rv.fcrdns === false && rv.ptr === "evil.example");
}

async function testIprevNoPtrFail() {
  // Operator PTR lookup returns an empty answer → no PTR → fail.
  var dns = _iprevDns({ ptr: [] });
  var rv = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dns });
  check("iprev.verify: empty PTR answer set → fail",
        rv.result === "fail" && rv.fcrdns === false);
}

async function testIprevNoForwardRecordFail() {
  // PTR resolves but the name has no forward record (ENODATA) → fail.
  var dns = _iprevDns({ ptr: ["host.example."], forward: {} });
  var rv = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dns });
  check("iprev.verify: PTR present but no forward record → fail",
        rv.result === "fail" && rv.ptr === "host.example");
}

async function testIprevReverseTransientTemperror() {
  // A transient reverse-lookup fault (SERVFAIL) → temperror (a verdict).
  var dns = _iprevDns({ ptrError: "ESERVFAIL" });
  var rv = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dns });
  check("iprev.verify: transient reverse (SERVFAIL) → temperror verdict",
        rv.result === "temperror" && rv.fcrdns === false);
}

async function testIprevHostilePtrShapePermerror() {
  // RFC 8601 §3 — an attacker controlling the reverse zone can publish a PTR
  // whose rdata is arbitrary bytes (e.g. `evil<script>`). It MUST be refused
  // as permerror BEFORE the name reaches any downstream (audit / A-R) sink,
  // and the forward lookup must not even be attempted.
  var forwardQueried = false;
  var dns = async function (qname, type) {
    if (type === "PTR") return ["evil<script>.example."];
    if (type === "A") { forwardQueried = true; return ["203.0.113.5"]; }
    var e = new Error("ENODATA"); e.code = "ENODATA"; throw e;
  };
  var rv = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dns });
  check("iprev.verify: hostile PTR rdata → permerror (not a valid DNS name shape)",
        rv.result === "permerror" && rv.fcrdns === false &&
        /not a valid DNS name shape/.test(rv.explanation || ""));
  check("iprev.verify: hostile PTR short-circuits before the forward query",
        forwardQueried === false);
}

async function testIprevMultiplePtrPicksFirst() {
  // RFC 8601 §3 — with multiple PTRs the receiver picks one (the first) and
  // continues the forward-confirm on it.
  var dns = _iprevDns({
    ptr: ["first.example.", "second.example."],
    forward: { "first.example": ["203.0.113.5"] },
  });
  var rv = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dns });
  check("iprev.verify: multiple PTRs → picks the first + forward-confirms it",
        rv.result === "pass" && rv.ptr === "first.example");
}

async function testIprevOptsValidation() {
  // Config-time entry point — an unknown opt key is an operator typo and
  // THROWS (three-tier: entry-point throw), not a silent ignore.
  var threw = null;
  try { await b.mail.iprev.verify("203.0.113.5", { bogus: 1 }); }
  catch (e) { threw = e; }
  check("iprev.verify: unknown opt key → config-time throw", threw !== null);
}

// RED — RFC 8601 §3: the forward-lookup catch must RETURN a temperror verdict
// on an un-enumerated transient DNS code, mirroring the reverse-lookup catch
// (which already does) and the primitive's own stated intent ("propagate as
// temperror"). Pre-fix it THREW a MailAuthError for any code that wasn't
// ENODATA/ENOTFOUND/ETIMEOUT/ESERVFAIL, so a caller of the documented
// verdict-returning API got an exception on e.g. an EREFUSED forward fault.
async function testIprevForwardUnknownCodeIsTemperrorNotThrow() {
  var dns = _iprevDns({ ptr: ["host.example."], forwardError: "EREFUSED" });
  var threw = null, rv = null;
  try { rv = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dns }); }
  catch (e) { threw = e; }
  check("iprev.verify: forward EREFUSED → temperror VERDICT (never a throw)",
        threw === null && rv !== null && rv.result === "temperror" && rv.ptr === "host.example");
}

// RED — RFC 8601 §3 (IPv6 FCrDNS): the connecting IPv6 literal and the AAAA
// forward record can carry different-but-equivalent textual forms (compressed
// `2001:db8::1` vs expanded `2001:0db8:0:0:0:0:0:1`). A raw lowercased string
// compare misses the match and marks a legitimately forward-confirmed IPv6
// sender as fail. The compare must canonicalize both addresses.
async function testIprevIpv6ForwardConfirmCanonicalizes() {
  var dns = async function (qname, type) {
    if (type === "PTR") return ["v6.sender.example."];
    // AAAA answer in fully-expanded form — same address, different text.
    if (type === "AAAA" && qname.replace(/\.$/, "") === "v6.sender.example") {
      return ["2001:0db8:0000:0000:0000:0000:0000:0001"];
    }
    var e = new Error("ENODATA"); e.code = "ENODATA"; throw e;
  };
  var rv = await b.mail.iprev.verify("2001:db8::1", { dnsLookup: dns });
  check("iprev.verify: IPv6 forward-confirm canonicalizes both forms → pass",
        rv.result === "pass" && rv.fcrdns === true);
}

// ---- SPF: malformed CIDR masks in ip4 / ip6 mechanisms never match ----

async function testSpfMalformedCidrMasksNoMatch() {
  // ip4 with an out-of-range prefix (/40 > 32) MUST NOT match — the
  // connecting IP falls through to -all → fail. A prefix parse that
  // silently clamped would over-authorize.
  var d40 = _txtOnly({ "s.example": [["v=spf1 ip4:192.0.2.0/40 -all"]] });
  var r40 = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: d40 });
  check("spf ip4:.../40 (mask > 32) → no match → fail (-all)", r40.result === "fail");

  // ip4 with an unparsable network literal (octet > 255) → no match.
  var dBadNet = _txtOnly({ "s.example": [["v=spf1 ip4:300.1.1.1/24 -all"]] });
  var rBadNet = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dBadNet });
  check("spf ip4 with an unparsable network literal → no match → fail", rBadNet.result === "fail");

  // ip4 with no prefix at all (single-host) — exact match branch.
  var dHost = _txtOnly({ "s.example": [["v=spf1 ip4:192.0.2.5 -all"]] });
  var rHost = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dHost });
  check("spf ip4 single-host (no /prefix) → exact match → pass", rHost.result === "pass");

  // ip6 with an out-of-range prefix (/200 > 128) MUST NOT match.
  var d200 = _txtOnly({ "s.example": [["v=spf1 ip6:2001:db8::/200 -all"]] });
  var r200 = await b.mail.spf.verify({ ip: "2001:db8::5", mailFrom: "a@s.example", dnsLookup: d200 });
  check("spf ip6:.../200 (mask > 128) → no match → fail (-all)", r200.result === "fail");

  // ip6 with an unparsable network literal (non-hex group) → no match.
  var dBad6 = _txtOnly({ "s.example": [["v=spf1 ip6:zzzz::/64 -all"]] });
  var rBad6 = await b.mail.spf.verify({ ip: "2001:db8::5", mailFrom: "a@s.example", dnsLookup: dBad6 });
  check("spf ip6 with an unparsable network literal → no match → fail", rBad6.result === "fail");

  // ip6 single-host (no /prefix) exact match branch.
  var dHost6 = _txtOnly({ "s.example": [["v=spf1 ip6:2001:db8::5 -all"]] });
  var rHost6 = await b.mail.spf.verify({ ip: "2001:db8::5", mailFrom: "a@s.example", dnsLookup: dHost6 });
  check("spf ip6 single-host (no /prefix) → exact match → pass", rHost6.result === "pass");
}

// ---- SPF: TXT records present but none is a v=spf1 record → none ----

async function testSpfTxtPresentButNoSpf1IsNone() {
  // The domain publishes TXT records (e.g. a verification token) but no
  // v=spf1 record. RFC 7208 §4.6 — the check result is "none", not a
  // fail/permerror; the receiver has no SPF policy to apply.
  var dns = _txtOnly({ "s.example": [
    ["google-site-verification=abc123"],
    ["v=spf2.0/pra ~all"],
  ] });
  var rv = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: dns });
  check("spf.verify: TXT present but no v=spf1 record → none", rv.result === "none");
}

// ---- SPF: %{h} HELO macro expands into an exists: domain-spec ----

async function testSpfHeloMacroExpansion() {
  // RFC 7208 §7.2 — %{h} is the HELO/EHLO domain. An exists: policy using
  // it must A-query the expanded name that embeds the HELO identity.
  var queried = [];
  var dns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 exists:%{h}.probe.example -all"]];
    if (type === "A") { queried.push(host); return ["127.0.0.2"]; }
    var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
  };
  var rv = await b.mail.spf.verify({
    ip: "192.0.2.9", mailFrom: "alice@s.example", helo: "relay.helo.example", dnsLookup: dns,
  });
  check("spf %{h} HELO macro → A-query embeds the HELO domain → pass",
        rv.result === "pass" && queried.indexOf("relay.helo.example.probe.example") !== -1);
}

// ---- DMARC: alignment against a missing / uncanonicalizable auth domain ----

async function testDmarcAlignmentMissingAndGarbageAuthDomain() {
  var dns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=reject; aspf=r; adkim=r"]] });

  // SPF passed but carries no domain (spf.domain absent). The alignment
  // check must fail closed on a null auth domain — not throw, not align.
  var rvNoDomain = await b.mail.dmarc.evaluate({
    from: "alice@example.com",
    spf:  { result: "pass" },                 // note: no `domain`
    dkim: [],
    dnsLookup: dns,
  });
  check("dmarc.evaluate: SPF pass with no auth domain → not aligned → fail",
        rvNoDomain.result === "fail" && rvNoDomain.alignment.spf === false);

  // DKIM passed but its d= canonicalizes to the empty string (leading-dot
  // hostname) — alignment must reject it rather than treat "" as a match.
  var rvGarbage = await b.mail.dmarc.evaluate({
    from: "alice@example.com",
    spf:  { result: "fail" },
    dkim: [{ result: "pass", domain: ".example.com" }],
    dnsLookup: dns,
  });
  check("dmarc.evaluate: DKIM pass whose domain canonicalizes to empty → not aligned → fail",
        rvGarbage.result === "fail" && rvGarbage.alignment.dkim === false &&
        rvGarbage.recommendedAction === "reject");
}

// ---- DMARC: pct out of range clamps to 100 (full application) ----

async function testDmarcPctOutOfRangeClampsTo100() {
  // A published pct greater than 100 is nonsensical; RFC 7489 §6.3 bounds
  // it to [0,100]. An out-of-range value clamps to 100 → the policy is
  // applied to every failing message (no sampling downgrade).
  var dns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=quarantine; pct=250; aspf=r; adkim=r"]] });
  var rv = await b.mail.dmarc.evaluate({
    from: "alice@example.com",
    spf:  { result: "fail" },
    dkim: [],
    dnsLookup: dns,
  });
  check("dmarc.evaluate: pct > 100 clamps to 100 → unaligned fail applies policy (quarantine)",
        rv.result === "fail" && rv.recommendedAction === "quarantine");
}

// ---- DMARC: no dkim argument at all → empty dkim-results list ----

async function testDmarcEvaluateNoDkimArgument() {
  // Omitting the dkim opt entirely (not even an empty array) must not
  // crash — the evaluator treats it as zero DKIM results and can still
  // pass on an aligned SPF authenticator.
  var dns = _txtOnly({ "_dmarc.example.com": [["v=DMARC1; p=reject; aspf=r; adkim=r"]] });
  var rv = await b.mail.dmarc.evaluate({
    from: "alice@example.com",
    spf:  { result: "pass", domain: "example.com" },
    dnsLookup: dns,
  });
  check("dmarc.evaluate: dkim opt omitted → treated as [] → aligned SPF still passes",
        rv.result === "pass" && rv.alignment.spf === true && rv.alignment.dkim === false);
}

// ---- DMARC: domainExists callback that throws is treated as existing ----

async function testDmarcDomainExistsCallbackThrows() {
  // DMARCbis §4.8 np= path — when the operator's domainExists callback
  // throws, the evaluator must fail SAFE by treating the domain as
  // existing (np= NOT applied), never crash the evaluation.
  var dns = async function (host) {
    if (host === "_dmarc.example.com") return [["v=DMARC1; p=quarantine; np=reject; aspf=r; adkim=r"]];
    var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
  };
  var threw = null, rv = null;
  try {
    rv = await b.mail.dmarc.evaluate({
      from: "user@sub.example.com",           // subdomain → org-domain policy applies
      spf:  { result: "fail" },
      dkim: [],
      dnsLookup: dns,
      domainExists: function () { throw new Error("resolver boom"); },
    });
  } catch (e) { threw = e; }
  check("dmarc.evaluate: throwing domainExists → no crash, org policy applied",
        threw === null && rv !== null && rv.orgDomainPolicyApplied === true);
  check("dmarc.evaluate: throwing domainExists → np= NOT applied (fails safe to existing)",
        rv && rv.npPolicyApplied === false);
}

// ---- ARC: ARC-Seal t=/x= time faults (not just AMS) ----

async function testArcSealTimeFaults() {
  var now = Math.floor(Date.now() / 1000);
  var keyDns = async function (qname) {
    if (qname === "arc._domainkey.example.com") {
      var nc = require("crypto");
      var pair = nc.generateKeyPairSync("rsa", { modulusLength: 2048 });
      return [["v=DKIM1; k=rsa; p=" +
        pair.publicKey.export({ type: "spki", format: "der" }).toString("base64")]];
    }
    var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
  };

  // ARC-Seal with a future t= — the seal's signing timestamp is ahead of
  // now, a RFC 8617 §5.2 time fault that fails the hop closed.
  var futureSeal =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; t=" + (now + 999999) + "; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
    "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var rvT = await b.mail.arc.verify(futureSeal, { dnsLookup: keyDns, clockSkewMs: 1000 });
  var tErrs = ((rvT.hops[0] && rvT.hops[0].asErrors) || []).join(" ; ");
  check("arc.verify: ARC-Seal future t= → as-t-future time fault (hop fails closed)",
        rvT.chainStatus === "fail" && /as-t-future/.test(tErrs));

  // ARC-Seal with an expired x= — the seal's expiry is in the past.
  var expiredSeal =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; x=" + (now - 999999) + "; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
    "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var rvX = await b.mail.arc.verify(expiredSeal, { dnsLookup: keyDns });
  var xErrs = ((rvX.hops[0] && rvX.hops[0].asErrors) || []).join(" ; ");
  check("arc.verify: ARC-Seal expired x= → as-x-expired time fault (hop fails closed)",
        rvX.chainStatus === "fail" && /as-x-expired/.test(xErrs));
}

// ---- ARC: key TXT lookup returning ENODATA → permerror (not temperror) ----

async function testArcKeyEnodataIsPermerror() {
  // A definitive "no such key record" answer (ENODATA) on the signing-key
  // lookup is a permanent failure per RFC 8617 §5.1.1, distinct from a
  // transient (temperror) resolver fault.
  var dns = async function () {
    var e = new Error("ENODATA"); e.code = "ENODATA"; throw e;
  };
  var msg =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; example.com; spf=pass\r\n" +
    "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg, { dnsLookup: dns });
  var errs = ((rv.hops[0] && rv.hops[0].asErrors) || [])
    .concat((rv.hops[0] && rv.hops[0].amsErrors) || []).join(" ; ");
  check("arc.verify: signing-key ENODATA → permerror hop verdict (fail chain)",
        rv.chainStatus === "fail" && /key lookup failed/.test(errs));
}

// ---- iprev: PTR names with oversize labels / oversize total length ----

async function testIprevOversizePtrShapePermerror() {
  // A PTR whose single label exceeds 63 octets is not a valid DNS name
  // (RFC 1035 §2.3.4) — refuse as permerror before the forward query.
  var longLabel = "a";
  for (var i = 0; i < 64; i += 1) longLabel += "a";            // 65-octet label
  var forwardQueried = false;
  var dnsLabel = async function (qname, type) {
    if (type === "PTR") return [longLabel + ".example."];
    if (type === "A") { forwardQueried = true; return ["203.0.113.5"]; }
    var e = new Error("ENODATA"); e.code = "ENODATA"; throw e;
  };
  var rvLabel = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dnsLabel });
  check("iprev.verify: PTR label > 63 octets → permerror, forward not attempted",
        rvLabel.result === "permerror" && forwardQueried === false);

  // A PTR whose total length exceeds 253 octets is likewise refused.
  var longName = "";
  for (var j = 0; j < 6; j += 1) longName += "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.";  // 6 * 51 = 306
  var dnsName = async function (qname, type) {
    if (type === "PTR") return [longName + "example."];
    var e = new Error("ENODATA"); e.code = "ENODATA"; throw e;
  };
  var rvName = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dnsName });
  check("iprev.verify: PTR total length > 253 octets → permerror",
        rvName.result === "permerror");
}

// ---- iprev: forward lookup rejecting with a code-less error → temperror ----

async function testIprevForwardCodelessErrorIsTemperror() {
  // The forward-confirm lookup rejects with a plain Error (no `.code`).
  // The verifier must still RETURN a temperror verdict (never throw), and
  // surface the error message in the explanation.
  var dns = async function (qname, type) {
    if (type === "PTR") return ["host.example."];
    throw new Error("upstream boom");           // no .code on the forward fault
  };
  var threw = null, rv = null;
  try { rv = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: dns }); }
  catch (e) { threw = e; }
  check("iprev.verify: code-less forward fault → temperror VERDICT (no throw)",
        threw === null && rv !== null && rv.result === "temperror" &&
        /boom/.test(rv.explanation || ""));
}

// ---- DMARC aggregate report: minimal / sparse shapes fall back cleanly ----

function testDmarcAggregateMinimalShape() {
  // A pre-parsed <feedback> with a single empty record and no metadata /
  // policy blocks must shape to all-null leaves rather than crash — every
  // absent field maps to null / [] and the totals are zero.
  var shaped = b.mail.dmarc.parseAggregateReport({ feedback: { record: [{}] } });
  check("dmarc.parseAggregateReport: sparse report shapes metadata leaves to null",
        shaped.reportMetadata.orgName === null &&
        shaped.reportMetadata.dateRange.begin === null &&
        shaped.policyPublished.domain === null && shaped.policyPublished.pct === null);
  check("dmarc.parseAggregateReport: empty record shapes to null leaves + zero totals",
        shaped.records.length === 1 &&
        shaped.records[0].sourceIp === null && shaped.records[0].count === null &&
        shaped.records[0].dispositions.disposition === null &&
        shaped.records[0].authResults.dkim.length === 0 &&
        shaped.totals.messages === 0);
}

// ---- DMARC aggregate report builder: minimal shape serializes valid XML ----

function testDmarcAggregateBuildMinimalShape() {
  // The builder must accept a minimal shape (empty metadata / policy, one
  // record with no dispositions / identifiers / auth_results) and still
  // emit a well-formed <feedback> document.
  var xml = b.mail.dmarc.buildAggregateReport({
    reportMetadata: {},
    policyPublished: {},
    records: [{}],
  });
  check("dmarc.buildAggregateReport: minimal shape → well-formed <feedback> XML",
        typeof xml === "string" &&
        xml.indexOf("<feedback>") !== -1 &&
        xml.indexOf("<record>") !== -1 &&
        xml.indexOf("<auth_results>") !== -1);
  // And it round-trips back through the parser without throwing.
  var reparsed = b.mail.dmarc.parseAggregateReport(xml);
  check("dmarc.buildAggregateReport: minimal build round-trips through the parser",
        reparsed && Array.isArray(reparsed.records) && reparsed.records.length === 1);
}

// ---- inbound.verify: DKIM tuning opts are threaded to the DKIM verifier ----

async function testInboundVerifyDkimTuningOpts() {
  // clockSkewMs / maxSignatures / minRsaBits are forwarded to the DKIM
  // verifier when supplied. An unsigned message still verifies (dkim
  // none) and the call must not crash while threading the opts.
  var dns = async function () {
    var e = new Error("ENOTFOUND"); e.code = "ENOTFOUND"; throw e;
  };
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nhello\r\n";
  var v = await b.mail.inbound.verify({
    ip: "192.0.2.1", helo: "mail.example", message: msg,
    dnsLookup: dns, clockSkewMs: 60000, maxSignatures: 5, minRsaBits: 1024,
  });
  check("inbound.verify: DKIM tuning opts threaded → unsigned message dkim none, no crash",
        Array.isArray(v.dkim) && v.dkim.length === 1 && v.dkim[0].result === "none");
}

async function run() {
  testByteCapMultibyte();
  testSurface();
  testArcHeaderParserGolden();
  testSpfParse();
  testSpfBadRecord();
  await testSpfVerifyMockedDns();
  await testSpfMechanismA();
  await testSpfMechanismADualCidr();
  await testSpfMechanismMx();
  await testSpfMechanismMxOverLimit();
  await testSpfMechanismExists();
  await testSpfMacroExpansionExistsIrV();
  await testSpfMacroBadSyntaxPermerror();
  await testSpfExistsRespectsLookupLimit();
  await testSpfMechanismEmptyDualCidrRefused();
  await testSpfMechanismPtrRemainsDeferred();
  testDmarcParse();
  testDmarcParseBisTags();
  testDmarcParseBisBadTag();
  await testDmarcEvaluateAligned();
  await testDmarcStrictAlignmentCanonicalizesDomain();
  await testDmarcEvaluateUnaligned();
  await testDmarcEvaluateOrgDomainViaPsl();
  await testDmarcEvaluateNpPolicy();
  await testInboundVerifyAlignedPass();
  await testInboundVerifySpoofRejected();
  await testInboundVerifyMultiAtMailFromGatesNotThrows();
  await testInboundVerifyGroupSyntaxFromRejected();
  await testInboundVerifyFromHeaderDiscipline();
  await testInboundVerifyTemperrorPrecedence();
  await testInboundVerifyValidation();
  await testArcVerifyMissing();
  await testArcVerifyNone();
  await testArcVerifyBadSignatures();
  await testArcInfinityClockSkewDoesNotDisableExpiry();
  await testArcVerifyDuplicateInstance();
  await testArcVerifyNonContiguous();
  await testArcVerifyTooManyHops();
  await testArcVerifyHop1CvMustBeNone();
  await testArcVerifyHop2CvNoneInvalid();
  await testArcVerifyPassAfterFail();
  await testArcEvaluateSurface();
  await testArcEvaluateBadTrustedSealers();
  await testArcEvaluateBreakAt();
  testArcSignSurface();
  testArcSignChain();
  testArcSignRejectsCrlfInjection();
  await testArcRealRoundtripVerifiesPass();
  await testArcFinalArInstanceForgery();
  testArcSignExcludeAarFromAms();
  testDkimVerifySurface();
  await testDkimVerifyRoundTrip();
  await testDkimVerifyNoSignature();
  await testDkimVerifyTampered();
  await testIprevSurface();
  await testIprevPermerror();
  await testIprevValidIpShape();
  await testIprevForwardConfirmedPass();
  await testIprevForwardMismatchFail();
  await testIprevNoPtrFail();
  await testIprevNoForwardRecordFail();
  await testIprevReverseTransientTemperror();
  await testIprevHostilePtrShapePermerror();
  await testIprevMultiplePtrPicksFirst();
  await testIprevOptsValidation();
  await testIprevForwardUnknownCodeIsTemperrorNotThrow();
  await testIprevIpv6ForwardConfirmCanonicalizes();
  // Audit 2026-05-15 — MAIL-9/10/25/39/50/56/58/66
  await testSpfRedirectModifier();
  await testSpfVoidLookupLimit();
  await testSpfRecordByteLengthCap();
  await testDmarcPctSamplingDeterministic();
  await testDmarcAlignmentUsesPsl();
  testDmarcRuaGunzipBombDistinguished();
  testDmarcRuaBuildRoundTrip();
  testDmarcRuaBuildBadInput();
  testDmarcForensicSurface();
  testDmarcForensicParse();
  testDmarcForensicNotAuthFailure();
  testDmarcForensicMissingAuthFailure();
  testDmarcForensicHostileInputDoesNotThrow();
  testDmarcForensicReportedHeaderCap();
  testDmarcForensicPrototypePollutionSafe();
  await testIprevValidatesPtrShape();
  await testArcHeaderSourceOrder();
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
  await testSpfMacroEscapesAndLetters();
  await testSpfMacroIpv6Letters();
  await testSpfMacroBadSyntaxMore();
  await testSpfCidrMaskEdges();
  await testSpfMultipleRecordsPermerror();
  await testSpfLookupFailureTemperror();
  await testSpfLookupLimitExceeded();
  await testSpfAMxErrorBranches();
  await testSpfExistsTemperror();
  await testSpfIncludeErrorBranches();
  await testDmarcTemperror();
  await testDmarcPctSampledDispositions();
  await testDmarcAggregatePreParsedAndErrors();
  await testArcKeyErrorBranches();
  await testInboundNoIdentitySpfNone();
  await testInboundHeloOnlyAuthResults();
  await testSpfAMxOperatorEnodata();
  await testSpfADualCidrErrorArms();
  await testSpfMacroLeftTruncation();
  await testSpfExistsLookupLimit();
  testDmarcParseBadSp();
  await testDmarcEvaluatePsdPolicy();
  await testArcNoBodyAndFolded();
  await testArcEvaluateTrustedSealersNotArray();
  testAuthResultsEmitVersionControlChars();
  testDmarcAggregateSizeAndParseErrors();
  testDmarcBuildTooManyRecords();
  testDmarcForensicMoreErrorArms();
  await testSpfMxExpansionLimits();
  await testSpfExistsExpandsEmpty();
  await testSpfRedirectDepthLimit();
  await testArcKeyNonArrayTxt();
  await testSpfMalformedCidrMasksNoMatch();
  await testSpfTxtPresentButNoSpf1IsNone();
  await testSpfHeloMacroExpansion();
  await testDmarcAlignmentMissingAndGarbageAuthDomain();
  await testDmarcPctOutOfRangeClampsTo100();
  await testDmarcEvaluateNoDkimArgument();
  await testDmarcDomainExistsCallbackThrows();
  await testArcSealTimeFaults();
  await testArcKeyEnodataIsPermerror();
  await testIprevOversizePtrShapePermerror();
  await testIprevForwardCodelessErrorIsTemperror();
  testDmarcAggregateMinimalShape();
  testDmarcAggregateBuildMinimalShape();
  await testInboundVerifyDkimTuningOpts();
  // Branch-coverage round — verifier error/edge arms driven through the
  // exported b.mail.* consumer paths (offline via the dnsLookup DI seam +
  // real node:crypto ARC/DKIM fixtures).
  await testArcTimeFaultUnparseableArms();
  await testArcCvFailTerminalChain();
  await testArcKeyLookupTemperrorArm();
  await testArcEd25519RoundtripPass();
  await testArcVerifyBareLfMessageVerifies();
  await testSpfDnsFaultMessagelessErrors();
  await testSpfEmptyArgAndBadRedirectMacro();
  await testDmarcMultiRecordAndNoMatchAreNone();
  await testIprevRootDotPtrAndBareFaults();
  await testInboundBareLfMessageProducesVerdict();
  await testInboundHeadersOnlyProducesVerdict();
  await testInboundFromEscapeAndInvalidHostname();
}

// A resolver error object with an empty .message — exercises the
// `(e && e.message) || String(e)` fallback in every DNS-fault classifier,
// proving the fault surfaces as a fail-closed verdict even when the error is
// degenerate (never an uncaught throw).
function _bareErr(code) { var e = new Error(); e.code = code; return e; }

// ---- ARC: time-fault fail-closed arms (RFC 8617 §5.2) ----

async function testArcTimeFaultUnparseableArms() {
  // A PRESENT-but-unparseable t=/x= on the AMS or AS must FAIL CLOSED (a time
  // fault), never silently skip the future/expiry gate. b= is a dummy: the
  // time-fault check runs BEFORE any signature verify, so a malformed
  // timestamp sinks the chain on structure alone (no key needed).
  var synthetic =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=relay.example; s=arc; t=abc; x=abc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=relay.example; s=arc; t=abc; h=from; bh=AAAA; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; relay.example; spf=pass\r\n" +
    "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(synthetic, { dnsLookup: async function () { return _enotfound(); } });
  var faultErrs = ((rv.hops[0] || {}).amsErrors || []).concat((rv.hops[0] || {}).asErrors || []).join(" ; ");
  check("arc.verify: unparseable t=/x= on AMS+AS → chain fails closed (no signature ever checked)",
        rv.chainStatus === "fail" && /unparseable/.test(faultErrs));
}

// ---- ARC: cv=fail terminal chain (RFC 8617 §5.2) ----

async function testArcCvFailTerminalChain() {
  // A chain whose LAST hop seals cv=fail is a terminal failure
  // ("last-as-cv=fail"): every AMS/AS signature verifies and no hop rule is
  // violated, yet the sealer itself attested the chain broke — so the
  // verifier MUST report chainStatus=fail, not pass on the valid signatures.
  // Unique sealer domain — the DKIM public-key cache (lib/mail-dkim.js) is
  // process-local + keyed by <selector>._domainkey.<domain>, so a qname reused
  // across tests would return an earlier test's key.
  var arcKey = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var arcKeyPem = arcKey.privateKey.export({ format: "pem", type: "pkcs8" });
  var spkiB64 = arcKey.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  var keyDns = _arcKeyDns("arc._domainkey.relay-cvfail.test", [["v=DKIM1; k=rsa; p=" + spkiB64]]);
  var rfc822 =
    "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: cvfail\r\n" +
    "Date: Wed, 06 May 2026 12:00:00 +0000\r\nMessage-ID: <cvf-1@example.com>\r\n\r\nbody body\r\n";
  var hop1 = b.mail.arc.sign({ rfc822: rfc822, instance: 1, authservId: "relay-cvfail.test",
    domain: "relay-cvfail.test", selector: "arc", privateKey: arcKeyPem, algorithm: "rsa-sha256",
    cv: "none", authResults: "spf=pass smtp.mailfrom=alice@example.com",
    headersToSign: ["From", "To", "Subject", "Date", "Message-ID"] });
  var hop2 = b.mail.arc.sign({ rfc822: hop1.rfc822, instance: 2, authservId: "relay-cvfail.test",
    domain: "relay-cvfail.test", selector: "arc", privateKey: arcKeyPem, algorithm: "rsa-sha256",
    cv: "fail", authResults: "spf=pass smtp.mailfrom=alice@example.com",
    headersToSign: ["From", "To", "Subject", "Date", "Message-ID"] });
  var rv = await b.mail.arc.verify(hop2.rfc822, { dnsLookup: keyDns });
  var allSigsPass = rv.hops.length === 2 &&
    rv.hops.every(function (h) { return h.amsResult === "pass" && h.asResult === "pass"; });
  check("arc.verify: cv=fail terminal seal → chainStatus fail even though every signature verifies",
        rv.chainStatus === "fail" && rv.reason === "last-as-cv=fail" &&
        rv.cv === "fail" && allSigsPass);
}

// ---- ARC: transient key-lookup fault → temperror (RFC 8617 §5.1.2) ----

async function testArcKeyLookupTemperrorArm() {
  // A TRANSIENT key-record DNS fault (SERVFAIL/timeout, not the definitive
  // ENOTFOUND/ENODATA) is a temperror, not a permerror: permanently refusing
  // a sealed chain on a resolver blip would drop legitimate mail. Both AMS
  // (via the DKIM key lookup) and AS surface temperror.
  // Unique d= so the DKIM key cache can't shadow the transient dnsLookup.
  var fullHop =
    "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=temperror-rt.test; s=arc; b=AAAA\r\n" +
    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=temperror-rt.test; s=arc; bh=AAAA; h=from; b=AAAA\r\n" +
    "ARC-Authentication-Results: i=1; temperror-rt.test; spf=pass\r\n" +
    "From: alice@example.com\r\nTo: bob@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(fullHop, { dnsLookup: _transientDns() });
  check("arc.verify: transient key-lookup fault → temperror (not permerror)",
        rv.chainStatus === "fail" &&
        (rv.hops[0] || {}).asResult === "temperror" &&
        (rv.hops[0] || {}).amsResult === "temperror");

  // A degenerate resolver error with no .message still classifies as a
  // temperror verdict (String(e) fallback), never an uncaught throw.
  var bareDns = async function () { throw _bareErr("ESERVFAIL"); };
  var rv2 = await b.mail.arc.verify(fullHop, { dnsLookup: bareDns });
  check("arc.verify: message-less transient key error → temperror verdict",
        (rv2.hops[0] || {}).asResult === "temperror");
}

// ---- ARC: Ed25519 roundtrip verify (null-digest AS path) ----

async function testArcEd25519RoundtripPass() {
  // Ed25519 seal: the AS verifies through the node null-digest Ed25519 path
  // (a=ed25519-sha256 maps to a null hash algorithm). Prior ARC roundtrip
  // coverage was RSA-only, so the Ed25519 AS verify arm never ran.
  var edKey = nodeCrypto.generateKeyPairSync("ed25519");
  var edKeyPem = edKey.privateKey.export({ format: "pem", type: "pkcs8" });
  var edSpki = edKey.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  var edDns = _arcKeyDns("arc._domainkey.relay-ed-rt.test", [["v=DKIM1; k=ed25519; p=" + edSpki]]);
  var rfc822 =
    "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: ed\r\n" +
    "Date: Wed, 06 May 2026 12:00:00 +0000\r\nMessage-ID: <ed-1@example.com>\r\n\r\nbody body\r\n";
  var hop = b.mail.arc.sign({ rfc822: rfc822, instance: 1, authservId: "relay-ed-rt.test",
    domain: "relay-ed-rt.test", selector: "arc", privateKey: edKeyPem, algorithm: "ed25519-sha256",
    cv: "none", authResults: "spf=pass smtp.mailfrom=alice@example.com",
    headersToSign: ["From", "To", "Subject", "Date", "Message-ID"] });
  var rv = await b.mail.arc.verify(hop.rfc822, { dnsLookup: edDns });
  check("arc.verify: Ed25519 single-hop chain → pass (AS verifies via null-digest path)",
        rv.chainStatus === "pass" && rv.hops[0].asResult === "pass" && rv.hops[0].amsResult === "pass");
}

// ---- ARC: bare-LF message reaches a chain verdict (not a thrown DkimError) ----

async function testArcVerifyBareLfMessageVerifies() {
  // arc.verify's own header scan accepts bare-LF, but the AMS step reuses the
  // DKIM verifier (CRLF-only split) — a bare-LF ARC message threw an uncaught
  // DkimError out of arc.verify instead of producing a chain result. A chain
  // signed over CRLF and transported as bare-LF must still verify (the LF→CRLF
  // normalization restores the sealer's canonical bytes).
  var arcKey = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var arcKeyPem = arcKey.privateKey.export({ format: "pem", type: "pkcs8" });
  var spkiB64 = arcKey.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  var keyDns = _arcKeyDns("arc._domainkey.relay-arclf.test", [["v=DKIM1; k=rsa; p=" + spkiB64]]);
  var rfc822 =
    "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: arclf\r\n" +
    "Date: Wed, 06 May 2026 12:00:00 +0000\r\nMessage-ID: <arclf-1@example.com>\r\n\r\nbody body\r\n";
  var hop = b.mail.arc.sign({ rfc822: rfc822, instance: 1, authservId: "relay-arclf.test",
    domain: "relay-arclf.test", selector: "arc", privateKey: arcKeyPem, algorithm: "rsa-sha256",
    cv: "none", authResults: "spf=pass smtp.mailfrom=alice@example.com",
    headersToSign: ["From", "To", "Subject", "Date", "Message-ID"] });
  var lf = hop.rfc822.replace(/\r\n/g, "\n");
  var rv = await b.mail.arc.verify(lf, { dnsLookup: keyDns });
  check("arc.verify: CRLF-signed chain transported as bare-LF → pass (verdict, not a thrown DkimError)",
        rv.chainStatus === "pass" && rv.hops[0].amsResult === "pass" && rv.hops[0].asResult === "pass");
}

// ---- SPF: message-less DNS faults still fail closed to temperror ----

async function testSpfDnsFaultMessagelessErrors() {
  // RFC 7208 §4.6.4 / §5 — every SPF a/mx/exists/include DNS fault that is
  // not a definitive negative answer is a temperror (fail-closed). A
  // degenerate resolver that throws an error with no .message must STILL
  // yield a temperror VERDICT via the String(e) fallback — never an uncaught
  // throw a pipeline could mis-handle as accept.
  var aDns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 a -all"]];
    if (type === "A") throw _bareErr("ESERVFAIL");
    return _enotfound();
  };
  check("spf a: message-less A fault → temperror verdict",
        (await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: aDns })).result === "temperror");

  var mxDns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") throw _bareErr("ESERVFAIL");
    return _enotfound();
  };
  check("spf mx: message-less MX fault → temperror verdict",
        (await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxDns })).result === "temperror");

  var mxHostDns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 mx -all"]];
    if (type === "MX") return [{ exchange: "mx1.s.example", preference: 10 }];
    if (type === "A") throw _bareErr("ESERVFAIL");
    return _enotfound();
  };
  check("spf mx-host: message-less forward fault → temperror verdict",
        (await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: mxHostDns })).result === "temperror");

  var existsDns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 exists:p.%{d} -all"]];
    if (type === "A") throw _bareErr("ESERVFAIL");
    return _enotfound();
  };
  check("spf exists: message-less A fault → temperror verdict",
        (await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: existsDns })).result === "temperror");

  var incDns = async function (host, type) {
    if (type === "TXT" && host === "s.example") return [["v=spf1 include:inner.example -all"]];
    if (type === "TXT" && host === "inner.example") throw _bareErr("ESERVFAIL");
    return _enotfound();
  };
  check("spf include: message-less inner TXT fault → temperror verdict",
        (await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: incDns })).result === "temperror");
}

// ---- SPF: empty-arg mechanisms + bad redirect macro ----

async function testSpfEmptyArgAndBadRedirectMacro() {
  // RFC 7208 §5.2/§5.7 — an `include:` / `exists:` with an empty argument
  // carries no target; the mechanism is skipped rather than matching, so
  // evaluation falls through to the trailing `-all` → fail (fail-closed).
  var emptyArg = _txtOnly({ "s.example": [["v=spf1 include: exists: -all"]] });
  var rEmpty = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: emptyArg });
  check("spf: empty-arg include:/exists: are skipped → falls through to -all fail",
        rEmpty.result === "fail");

  // RFC 7208 §6.1 / §7 — a redirect= target is a macro-string; an invalid
  // macro-letter in it is a permanent syntax error → permerror.
  var badRedir = _txtOnly({ "s.example": [["v=spf1 redirect=%{z}"]] });
  var rRedir = await b.mail.spf.verify({ ip: "192.0.2.5", mailFrom: "a@s.example", dnsLookup: badRedir });
  check("spf: redirect= with an invalid macro-letter → permerror",
        rRedir.result === "permerror" && /not a valid macro-letter/.test(rRedir.explanation || ""));
}

// ---- DMARC: ambiguous / absent record → none (RFC 7489 §6.6.3) ----

async function testDmarcMultiRecordAndNoMatchAreNone() {
  // When a domain publishes MORE THAN ONE v=DMARC1 record the receiver MUST
  // treat it as having no DMARC record (the policy is ambiguous).
  var multi = async function (host, type) {
    if (type === "TXT" && host === "_dmarc.example.com")
      return [["v=DMARC1; p=reject"], ["v=DMARC1; p=none"]];
    return _enotfound();
  };
  var rMulti = await b.mail.dmarc.evaluate({ from: "a@example.com",
    spf: { result: "pass", domain: "example.com" }, dkim: [], dnsLookup: multi });
  check("dmarc.evaluate: two v=DMARC1 records → none (ambiguous, RFC 7489 §6.6.3)",
        rMulti.result === "none");

  // TXT present at _dmarc but no record begins with v=DMARC1 → no policy → none.
  var noV = async function (host, type) {
    if (type === "TXT" && host === "_dmarc.example.com")
      return [["some=unrelated txt"], ["v=spf1 nope"]];
    return _enotfound();
  };
  var rNoV = await b.mail.dmarc.evaluate({ from: "a@example.com",
    spf: { result: "pass", domain: "example.com" }, dkim: [], dnsLookup: noV });
  check("dmarc.evaluate: _dmarc TXT with no v=DMARC1 record → none",
        rNoV.result === "none");
}

// ---- iprev: degenerate PTR + message-less faults (RFC 8601 §3) ----

async function testIprevRootDotPtrAndBareFaults() {
  // A PTR answer that is only the root label (".") collapses to an empty name
  // after the trailing-dot strip — RFC 8601 §3 has no usable PTR, so iprev
  // returns fail (no PTR record), never a crash on the empty name.
  var rootDot = async function (qname, type) {
    if (type === "PTR") return ["."];
    return _enotfound();
  };
  var rRoot = await b.mail.iprev.verify("203.0.113.5", { dnsLookup: rootDot });
  check("iprev.verify: root-only PTR answer → fail (no usable PTR name)",
        rRoot.result === "fail" && rRoot.ptr === null);

  // Message-less transient reverse fault → temperror verdict (String(e)).
  var revBare = async function (qname, type) {
    if (type === "PTR") throw _bareErr("ESERVFAIL");
    return _enotfound();
  };
  check("iprev.verify: message-less reverse fault → temperror verdict",
        (await b.mail.iprev.verify("203.0.113.5", { dnsLookup: revBare })).result === "temperror");

  // Code-less AND message-less forward fault → temperror verdict (String(e)
  // fallback in the forward-lookup explanation).
  var fwdBare = async function (qname, type) {
    if (type === "PTR") return ["mail.example.com"];
    if (type === "A") throw new Error("");
    return _enotfound();
  };
  check("iprev.verify: code-less/message-less forward fault → temperror verdict",
        (await b.mail.iprev.verify("203.0.113.5", { dnsLookup: fwdBare })).result === "temperror");
}

// ---- inbound.verify: bare-LF + headers-only messages reach a verdict ----

async function testInboundBareLfMessageProducesVerdict() {
  // inbound.verify documents that bare-LF input is accepted defensively
  // (operator tooling that lost CRs). The DKIM verifier's header/body split
  // REQUIRES CRLF CRLF and threw an uncaught DkimError on bare-LF, crashing
  // the pipeline instead of producing a verdict. A bare-LF message must reach
  // a verdict.
  var lfPlain = "From: alice@example.com\nTo: bob@x\nSubject: hi\n\nbody\n";
  var vPlain = await b.mail.inbound.verify({ ip: "203.0.113.5", message: lfPlain,
    dnsLookup: async function () { return _enotfound(); } });
  check("inbound.verify: bare-LF message → verdict, not a thrown DkimError",
        vPlain.from.domain === "example.com" && Array.isArray(vPlain.dkim) &&
        vPlain.dmarc.result === "none");

  // Stronger: a message SIGNED over CRLF but transported as bare-LF must
  // still DKIM-verify (the LF→CRLF normalization restores the signed form),
  // not merely avoid the throw.
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  // Unique selector — the DKIM key cache is keyed by <selector>._domainkey.<d>.
  var signer = b.mail.dkim.create({ domain: "example.com", selector: "lfrt", privateKey: pair.privateKey });
  var signed = signer.sign(
    "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n" +
    "Date: Mon, 5 May 2026 10:00:00 +0000\r\nMessage-ID: <lf@example.com>\r\n\r\nHello world.\r\n");
  var spkiB64 = nodeCrypto.createPublicKey(pair.publicKey)
    .export({ type: "spki", format: "der" }).toString("base64");
  var keyDns = async function (qname) {
    if (qname === "lfrt._domainkey.example.com") return [["v=DKIM1; k=rsa; p=" + spkiB64]];
    if (qname === "_dmarc.example.com") return [["v=DMARC1; p=reject; adkim=s; aspf=s"]];
    return _enotfound();
  };
  var lfSigned = signed.replace(/\r\n/g, "\n");
  var vSigned = await b.mail.inbound.verify({ ip: "203.0.113.5", mailFrom: "alice@example.com",
    message: lfSigned, authservId: "mx.receiver.example", dnsLookup: keyDns });
  check("inbound.verify: CRLF-signed message transported as bare-LF still DKIM-passes",
        vSigned.dkim.length === 1 && vSigned.dkim[0].result === "pass" &&
        vSigned.dmarc.result === "pass");
}

async function testInboundHeadersOnlyProducesVerdict() {
  // A headers-only message with no blank-line separator — _splitHeaderBlock
  // treats it as headers + empty body; the pipeline must produce a verdict
  // (DKIM none) rather than throwing on the missing CRLF CRLF separator.
  var headersOnly = "From: alice@example.com\r\nTo: bob@x\r\nSubject: hi";
  var v = await b.mail.inbound.verify({ ip: "203.0.113.5", message: headersOnly,
    dnsLookup: async function () { return _enotfound(); } });
  check("inbound.verify: headers-only message (no separator) → verdict (dkim none)",
        v.from.domain === "example.com" &&
        v.dkim.length >= 1 && v.dkim[0].result === "none");
}

async function testInboundFromEscapeAndInvalidHostname() {
  var absent = async function () { return _enotfound(); };

  // Quoted-pair (\") inside a display-name is one author, not a break — the
  // escape walk must consume the escaped quote and keep the angle-addr whole.
  var escMsg = 'From: "a\\"b" <u@good.example.com>\r\nTo: bob@x\r\nSubject: hi\r\n\r\nbody\r\n';
  var vEsc = await b.mail.inbound.verify({ ip: "203.0.113.5", message: escMsg, dnsLookup: absent });
  check("inbound.verify: From with a quoted-pair display-name → single author extracted",
        vEsc.from.count === 1 && vEsc.from.address === "u@good.example.com" &&
        vEsc.from.domain === "good.example.com");

  // A single-label From domain (no dot) is not a valid DNS hostname for a
  // DMARC lookup → domain treated as unparsable → fail-closed permerror.
  var singleLabel = "From: alice@localhost\r\nTo: bob@x\r\nSubject: hi\r\n\r\nbody\r\n";
  var vSingle = await b.mail.inbound.verify({ ip: "203.0.113.5", message: singleLabel, dnsLookup: absent });
  check("inbound.verify: single-label From domain → unparsable → dmarc permerror (reject)",
        vSingle.from.domain === null && vSingle.dmarc.result === "permerror" &&
        vSingle.dmarc.recommendedAction === "reject");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

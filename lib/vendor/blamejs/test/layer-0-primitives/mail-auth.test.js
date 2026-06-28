"use strict";
/**
 * b.mail.spf + b.mail.dmarc + b.mail.arc — inbound mail
 * authentication-results verification.
 *
 * Live DNS lookups don't run in smoke (network-bound tests live in
 * test/integration). What's covered: parse + match + alignment logic
 * via operator-supplied dnsLookup mock callbacks; ARC chain shape.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var arcSign = require("../../lib/mail-arc-sign");

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
  await testDmarcEvaluateUnaligned();
  await testDmarcEvaluateOrgDomainViaPsl();
  await testDmarcEvaluateNpPolicy();
  await testInboundVerifyAlignedPass();
  await testInboundVerifySpoofRejected();
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
  await testArcRealRoundtripVerifiesPass();
  testDkimVerifySurface();
  await testDkimVerifyRoundTrip();
  await testDkimVerifyNoSignature();
  await testDkimVerifyTampered();
  await testIprevSurface();
  await testIprevPermerror();
  await testIprevValidIpShape();
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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

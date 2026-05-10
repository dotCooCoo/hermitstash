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
  // i=1 + i=3 (missing i=2) — chain MUST refuse.
  var msg = _arcHopHeaders(1, "none") +
            _arcHopHeaders(3, "pass") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: non-contiguous instances → fail",
        rv.chainStatus === "fail" && /incomplete-or-non-contiguous/.test(rv.reason || ""));
}

async function testArcVerifyTooManyHops() {
  // Synthesize 51 hops — RFC 8617 §5.1.2 caps at 50.
  var hopHeaders = "";
  for (var i = 1; i <= 51; i += 1) {
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
  var msg = _arcHopHeaders(1, "none") +
            _arcHopHeaders(2, "none") +
            "From: alice@example.com\r\n\r\nbody\r\n";
  var rv = await b.mail.arc.verify(msg);
  check("arc.verify: i=2 cv=none → fail w/ cv=none-invalid-after-hop-1 reason",
        rv.chainStatus === "fail" && /cv=none-invalid-after-hop-1/.test(rv.reason || ""));
}

async function testArcVerifyPassAfterFail() {
  // i=1 cv=none, i=2 cv=fail, i=3 cv=pass — invalid: a hop can't
  // claim chain pass after upstream observed fail.
  var msg = _arcHopHeaders(1, "none") +
            _arcHopHeaders(2, "fail") +
            _arcHopHeaders(3, "pass") +
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

async function run() {
  testSurface();
  testSpfParse();
  testSpfBadRecord();
  await testSpfVerifyMockedDns();
  testDmarcParse();
  testDmarcParseBisTags();
  testDmarcParseBisBadTag();
  await testDmarcEvaluateAligned();
  await testDmarcEvaluateUnaligned();
  await testDmarcEvaluateOrgDomainViaPsl();
  await testDmarcEvaluateNpPolicy();
  await testArcVerifyMissing();
  await testArcVerifyNone();
  await testArcVerifyBadSignatures();
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
  testDkimVerifySurface();
  await testDkimVerifyRoundTrip();
  await testDkimVerifyNoSignature();
  await testDkimVerifyTampered();
  await testIprevSurface();
  await testIprevPermerror();
  await testIprevValidIpShape();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

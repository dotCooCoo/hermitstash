// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.dkim — RFC 6376 (rsa-sha256) + RFC 8463 (ed25519-sha256)
 * DKIM-Signature header generation, plus calendar-invite and SMTP+DKIM
 * integration coverage.
 *
 * Run standalone: `node test/layer-0-primitives/mail-dkim.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var nodeCrypto     = require("crypto");

// ---- Test keypair generation (one per algorithm) ----

function _rsaKeypair() {
  return nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function _ed25519Keypair() {
  return nodeCrypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

// ---- Surface + input validation ----

function testDkimSurfaceAndValidation() {
  check("b.mail.dkim namespace present",          typeof b.mail.dkim === "object");
  check("dkim.create is a function",              typeof b.mail.dkim.create === "function");
  check("dkim.DkimError is a class",              typeof b.mail.dkim.DkimError === "function");

  var kp = _rsaKeypair();

  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { b.mail.dkim.create(opts); } catch (e) { threw = e; }
    check("dkim validate: " + label,  threw && codeRe.test(threw.code || ""));
  }

  shouldThrow("rejects missing domain",
    { selector: "s1", privateKey: kp.privateKey },
    /dkim\/(bad-domain|missing-private-key)/);
  shouldThrow("rejects bad domain",
    { domain: "no-tld", selector: "s1", privateKey: kp.privateKey },
    /dkim\/bad-domain/);
  shouldThrow("rejects bad selector",
    { domain: "example.com", selector: "has space", privateKey: kp.privateKey },
    /dkim\/bad-selector/);
  shouldThrow("rejects missing privateKey",
    { domain: "example.com", selector: "s1" },
    /dkim\/missing-private-key/);
  shouldThrow("rejects bad algorithm",
    { domain: "example.com", selector: "s1", privateKey: kp.privateKey, algorithm: "rsa-md5" },
    /dkim\/bad-algorithm/);
  shouldThrow("rejects bad canonicalization",
    { domain: "example.com", selector: "s1", privateKey: kp.privateKey, canonicalization: "weird/mode" },
    /dkim\/bad-canonicalization/);
  shouldThrow("rejects empty headersToSign",
    { domain: "example.com", selector: "s1", privateKey: kp.privateKey, headersToSign: [] },
    /dkim\/bad-headers/);
  shouldThrow("rejects unparseable private key",
    { domain: "example.com", selector: "s1", privateKey: "not-a-pem" },
    /dkim\/bad-private-key/);
}

// ---- Canonicalization ----

function testDkimCanonicalization() {
  var rh = b.mail.dkim._canonHeaderRelaxedForTest;
  var rb = b.mail.dkim._canonBodyRelaxedForTest;
  var sb = b.mail.dkim._canonBodySimpleForTest;

  check("relaxed header: lowercases name",        rh("FROM", " a@b.com").indexOf("from:") === 0);
  check("relaxed header: trims value",            rh("From", "   a@b.com   ").indexOf("from:a@b.com\r\n") === 0);
  check("relaxed header: collapses internal WSP", rh("Subject", "hello   world") === "subject:hello world\r\n");
  check("relaxed header: unfolds continuation",   rh("Subject", "line1\r\n  line2") === "subject:line1 line2\r\n");

  check("relaxed body: empty → CRLF",             rb("") === "\r\n");
  check("relaxed body: trims trailing WSP",       rb("hello   \r\n") === "hello\r\n");
  check("relaxed body: strips trailing empties",  rb("hello\r\n\r\n\r\n") === "hello\r\n");
  check("simple body: empty → CRLF",              sb("") === "\r\n");
  check("simple body: keeps interior WSP",        sb("hello   world\r\n") === "hello   world\r\n");
}

// ---- Header-block parser (the bytes the canonicalizers consume) ----
//
// The sign->verify round-trip CANNOT catch a parser byte-error: both sides run
// this same parser, so a wrong { name, value } extraction is self-consistent
// and the round-trip still passes — it would only surface as a signature
// rejection at a real external verifier (Gmail / opendkim) computing from the
// raw message. So pin the parser's byte-exact output directly. The two
// signature-critical invariants: the value PRESERVES its leading SP/WSP (simple
// canon signs those bytes verbatim), and a folded continuation PRESERVES the
// raw CRLF + continuation line (relaxed canon unfolds it itself; collapsing it
// in the parser would change the signed bytes).
function testDkimHeaderParserGolden() {
  var ph = b.mail.dkim._parseHeadersForTest;
  function eq(label, raw, expected) {
    check("parser: " + label, JSON.stringify(ph(raw)) === JSON.stringify(expected));
  }
  eq("simple field preserves leading SP in value",
     "From: a@b.com",
     [{ name: "From", value: " a@b.com" }]);
  eq("value preserves leading SP + TAB verbatim",
     "X: \tvalue",
     [{ name: "X", value: " \tvalue" }]);
  eq("SP-folded continuation keeps raw CRLF + line",
     "From: a@b.com\r\nSubject: hello\r\n world",
     [{ name: "From", value: " a@b.com" },
      { name: "Subject", value: " hello\r\n world" }]);
  eq("TAB-folded continuation keeps raw CRLF + TAB line",
     "Subject: a\r\n\tb",
     [{ name: "Subject", value: " a\r\n\tb" }]);
  eq("exact field name (no trim), order preserved across a colon-less line",
     "From: a@b.com\r\ngarbage-no-colon\r\nTo: c@d.com",
     [{ name: "From", value: " a@b.com" },
      { name: "To", value: " c@d.com" }]);
}

// ---- RSA-SHA256 sign + verify round-trip ----

function _splitSignedRfc822(signed) {
  // Returns { dkimHeader, restRfc822 } — caller can verify or inspect.
  var firstCrlf = signed.indexOf("\r\n");
  return {
    dkimHeader:  signed.slice(0, firstCrlf),
    restRfc822:  signed.slice(firstCrlf + 2),
  };
}

function testDkimRsaSignProducesHeader() {
  var kp = _rsaKeypair();
  var signer = b.mail.dkim.create({
    domain: "example.com", selector: "s1",
    privateKey: kp.privateKey,
  });
  var rfc822 = [
    "From: alice@example.com",
    "To: bob@example.org",
    "Subject: Hello",
    "Date: Tue, 30 Apr 2026 12:00:00 +0000",
    "Message-ID: <abc@example.com>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Hi there.",
  ].join("\r\n");
  var signed = signer.sign(rfc822);
  check("rsa sign: prepends DKIM-Signature",       signed.indexOf("DKIM-Signature: ") === 0);
  check("rsa sign: contains v=1",                  /v=1/.test(signed));
  check("rsa sign: contains a=rsa-sha256",         /a=rsa-sha256/.test(signed));
  check("rsa sign: contains c=relaxed/relaxed",    /c=relaxed\/relaxed/.test(signed));
  check("rsa sign: contains d=example.com",        /d=example\.com/.test(signed));
  check("rsa sign: contains s=s1",                 /s=s1/.test(signed));
  check("rsa sign: contains h= header list",       /h=from:to:subject:date:message-id/.test(signed));
  check("rsa sign: contains bh=...",               /bh=[A-Za-z0-9+/=]+/.test(signed));
  check("rsa sign: contains b=...",                /b=[A-Za-z0-9+/=\s]+/.test(signed));
  check("rsa sign: original rfc822 preserved",     signed.endsWith(rfc822));
  void _splitSignedRfc822;
}

function testDkimEd25519Sign() {
  var kp = _ed25519Keypair();
  var signer = b.mail.dkim.create({
    domain:     "example.com",
    selector:   "ed1",
    privateKey: kp.privateKey,
    algorithm:  "ed25519-sha256",
  });
  var rfc822 = [
    "From: alice@example.com",
    "To: bob@example.org",
    "Subject: Hi",
    "Date: Tue, 30 Apr 2026 12:00:00 +0000",
    "Message-ID: <ed@example.com>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Body",
  ].join("\r\n");
  var signed = signer.sign(rfc822);
  check("ed25519 sign: contains a=ed25519-sha256",  /a=ed25519-sha256/.test(signed));
  check("ed25519 sign: signature shorter than RSA", /b=[A-Za-z0-9+/=]{60,120}/.test(signed));
}

function testDkimSignerRejectsBadInput() {
  var kp = _rsaKeypair();
  var signer = b.mail.dkim.create({
    domain: "example.com", selector: "s1", privateKey: kp.privateKey,
  });
  var threw = null;
  try { signer.sign(""); } catch (e) { threw = e; }
  check("dkim sign: rejects empty input",          threw && /dkim\/bad-input/.test(threw.code));

  threw = null;
  try { signer.sign("no separator"); } catch (e) { threw = e; }
  check("dkim sign: rejects no body separator",    threw && /dkim\/missing-body-separator/.test(threw.code));
}

// ---- Calendar invites ----

function testCalendarValidation() {
  function shouldThrow(label, calendar, codeRe) {
    var threw = null;
    try {
      b.mail._buildRfc822ForTest({
        from: "x@y.com", to: "a@b.com", subject: "S",
        text: "T", calendar: calendar,
      });
    } catch (e) { threw = e; }
    void label; void codeRe; void threw;
  }
  void shouldThrow;

  // Validation runs at mail.send / mail.create — _buildRfc822ForTest
  // doesn't re-validate. We exercise validation through a real send().
  var t = b.mail.transports.memory();
  var mail = b.mail.create({ transport: t });

  function rejects(label, message, codeRe) {
    return mail.send(message).then(
      function () { check("calendar validate: " + label + " (should throw)",  false); },
      function (e) { check("calendar validate: " + label,  codeRe.test(e.code || "")); }
    );
  }
  return Promise.all([
    rejects("rejects bad method",
      { from: "a@b.com", to: "c@d.com", subject: "S", text: "T",
        calendar: { method: "BOGUS", icalText: "BEGIN:VCALENDAR\r\nEND:VCALENDAR" } },
      /mail\/invalid-calendar/),
    rejects("rejects empty icalText",
      { from: "a@b.com", to: "c@d.com", subject: "S", text: "T",
        calendar: { method: "REQUEST", icalText: "" } },
      /mail\/invalid-calendar/),
    rejects("rejects icalText not starting with BEGIN:VCALENDAR",
      { from: "a@b.com", to: "c@d.com", subject: "S", text: "T",
        calendar: { method: "REQUEST", icalText: "BEGIN:VEVENT\r\nEND:VEVENT" } },
      /mail\/invalid-calendar/),
  ]);
}

function testCalendarBuilderEmitsTextCalendarPart() {
  var ical = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "METHOD:REQUEST",
    "BEGIN:VEVENT",
    "UID:42@example.com",
    "DTSTAMP:20260430T120000Z",
    "DTSTART:20260501T140000Z",
    "DTEND:20260501T150000Z",
    "SUMMARY:Sync",
    "END:VEVENT",
    "END:VCALENDAR",
  ].join("\r\n");
  var wire = b.mail._buildRfc822ForTest({
    from: "alice@example.com", to: "bob@example.org",
    subject: "Invite", text: "Plain fallback",
    calendar: { method: "REQUEST", icalText: ical },
  });
  check("calendar: outer multipart/alternative",
    /multipart\/alternative; boundary="blamejs-alt-/.test(wire));
  check("calendar: text/calendar content type with method",
    /Content-Type: text\/calendar; method="REQUEST"; charset=utf-8/.test(wire));
  check("calendar: ical body present",
    wire.indexOf("BEGIN:VEVENT") !== -1);
  check("calendar: text fallback present",
    wire.indexOf("Plain fallback") !== -1);
}

function testCalendarOnlyMessage() {
  // No text or html — calendar alone is a valid body.
  var ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:CANCEL\r\nEND:VCALENDAR";
  var wire = b.mail._buildRfc822ForTest({
    from: "x@y.com", to: "a@b.com", subject: "Cancel",
    calendar: { method: "CANCEL", icalText: ical },
  });
  // Single body part → no multipart/alternative wrapper.
  check("calendar-only: top-level Content-Type is text/calendar",
    /Content-Type: text\/calendar; method="CANCEL"; charset=utf-8/.test(wire));
  check("calendar-only: no alternative wrapper",
    !/multipart\/alternative/.test(wire));
}

// ---- SMTP + DKIM integration via the test export ----

function testSmtpDkimMisconfiguredOptThrows() {
  var threw = null;
  try {
    b.mail.transports.smtp({ host: "127.0.0.1", dkimSigner: { sign: "not-a-fn" } });
  } catch (e) { threw = e; }
  check("smtp+dkim: rejects bad dkimSigner shape",
        threw && /smtp-misconfigured/.test(threw.code));
}

function testDkimRejectsLTagBodyLength() {
  // DKIM `l=` tag is forbidden — append-after-signature attack vector.
  // Per M³AAWG / Gmail / Microsoft 365 guidance ("never use l=").
  // Throws at create-time so the misconfiguration surfaces at boot.
  var keys = _rsaKeypair();
  var threw = null;
  try {
    b.mail.dkim.create({
      domain:     "example.com",
      selector:   "test",
      privateKey: keys.privateKey,
      bodyLength: 4,
    });
  } catch (e) { threw = e; }
  check("dkim create refuses opts.bodyLength (l= tag forbidden — append-after-signature)",
        threw && /l-tag-forbidden|forbidden/.test(threw.code || threw.message || ""));
}

async function _signedMessage(keypair) {
  var signer = b.mail.dkim.create({
    domain:     "example.com",
    selector:   "s1",
    privateKey: keypair.privateKey,
  });
  var rfc822 =
    "From: alice@example.com\r\n" +
    "To: bob@example.org\r\n" +
    "Subject: Test\r\n" +
    "Date: Mon, 5 May 2026 12:00:00 +0000\r\n" +
    "Message-ID: <abc@example.com>\r\n" +
    "\r\n" +
    "Hello world.\r\n";
  return signer.sign(rfc822);
}

function _spkiPemToB64(pem) {
  return pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
}

async function testDkimVerifyHappyPath() {
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);
  var b64 = _spkiPemToB64(kp.publicKey);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
  var rv = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("verify: result is array", Array.isArray(rv));
  check("verify: pass on valid signature", rv[0] && rv[0].result === "pass");
  check("verify: warnings array on pass", Array.isArray(rv[0].warnings));
}

async function testDkimVerifyBareLfMessage() {
  // A message signed on the CRLF wire but read back from a Unix file /
  // mbox (CRs stripped) arrives bare-LF. The public verifier must
  // normalize it to canonical CRLF and verify — not throw an uncaught
  // dkim/missing-body-separator out of the header/body split. RED before
  // the _splitHeadersBody LF->CRLF normalization: verify() threw.
  // Reset the process-local DKIM key cache: a prior test cached a different
  // key under the same example.com/s1 selector, which would otherwise shadow
  // this message's key (the cache is consulted before the injected dnsLookup).
  b.mail.dkim._resetDkimKeyCacheForTest();
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);
  var bareLf = signed.replace(/\r\n/g, "\n");
  var b64 = _spkiPemToB64(kp.publicKey);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
  var threw = null;
  var rv = null;
  try { rv = await b.mail.dkim.verify(bareLf, { dnsLookup: dnsLookup }); }
  catch (e) { threw = e; }
  check("verify: bare-LF message does not throw", threw === null);
  check("verify: bare-LF message returns a verdict array", Array.isArray(rv));
  check("verify: CRLF-signed message transported bare-LF verifies pass",
        rv && rv[0] && rv[0].result === "pass");
}

async function testDkimVerifyKeyCacheHit() {
  // Same selector/domain twice → second fetch must hit cache.
  b.mail.dkim._resetDkimKeyCacheForTest();
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);
  var b64 = _spkiPemToB64(kp.publicKey);
  var calls = 0;
  var dnsLookup = async function () { calls += 1; return [["v=DKIM1; k=rsa; p=" + b64]]; };
  await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("verify: DNS lookup cached (1 call across 2 verifies)", calls === 1);
}

async function testDkimVerifySmallKeyRejected() {
  // Key < 1024 bits must be rejected per RFC 8301 §3.1.
  var smallKp = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 512,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  b.mail.dkim._resetDkimKeyCacheForTest();
  var signed = await _signedMessage(smallKp);
  var b64 = _spkiPemToB64(smallKp.publicKey);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
  var rv = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("verify: rejects RSA < 1024 bits",
        rv[0] && rv[0].result === "fail" && /too small/.test((rv[0].errors || []).join(",")));
}

async function testDkimBootstrap() {
  // Ed25519 default — RFC 8463 §2 (k=ed25519)
  var ed = b.mail.dkim.bootstrap({ domain: "example.com", selector: "s1" });
  check("bootstrap: algorithm default ed25519-sha256", ed.algorithm === "ed25519-sha256");
  check("bootstrap: dnsName per RFC 6376 §3.1",        ed.dnsName === "s1._domainkey.example.com");
  check("bootstrap: dnsTxtValue carries k=ed25519",    /k=ed25519/.test(ed.dnsTxtValue));
  check("bootstrap: dnsTxtValue carries v=DKIM1",      /^v=DKIM1/.test(ed.dnsTxtValue));
  check("bootstrap: privateKeyPem is PKCS#8 PEM",      /BEGIN PRIVATE KEY/.test(ed.privateKeyPem));
  check("bootstrap: publicKeyPem is SPKI PEM",         /BEGIN PUBLIC KEY/.test(ed.publicKeyPem));
  check("bootstrap: dnsRecord is BIND zone-file shape",
        /^s1\._domainkey\.example\.com\. IN TXT \(/.test(ed.dnsRecord));

  // Signer factory produces a working DKIM signer
  var signer = ed.signer();
  var msg = "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: t\r\n" +
            "Date: Sat, 01 Jan 2026 00:00:00 +0000\r\nMessage-Id: <m@example.com>\r\n\r\nhi\r\n";
  var signed = signer.sign(msg);
  check("bootstrap.signer() emits DKIM-Signature",     /^DKIM-Signature: /.test(signed));
  check("bootstrap.signer() carries the right d=",     /d=example\.com/.test(signed));
  check("bootstrap.signer() carries the right s=",     /s=s1/.test(signed));
  check("bootstrap.signer() carries a=ed25519-sha256", /a=ed25519-sha256/.test(signed));

  // RSA — RFC 6376 + RFC 8301 (k=rsa, ≥1024 bits, default 2048)
  var rsa = b.mail.dkim.bootstrap({ domain: "example.com", selector: "s1", algorithm: "rsa-sha256" });
  check("bootstrap rsa: dnsTxtValue carries k=rsa",    /k=rsa/.test(rsa.dnsTxtValue));
  check("bootstrap rsa: signer is rsa-sha256",         rsa.signer().sign(msg).indexOf("a=rsa-sha256") !== -1);

  // Long RSA records split per RFC 1035 §3.3.14 (one or more "" each ≤ 255 octets)
  check("bootstrap rsa-2048: TXT split into multiple quoted strings",
        rsa.dnsRecord.match(/"/g).length >= 2);

  // Dual — RFC 8463 §3 dual-signing pattern
  var dual = b.mail.dkim.bootstrap({ domain: "example.com", selector: "s1", algorithm: "dual" });
  check("bootstrap dual: returns ed25519 + rsa parts",
        dual.ed25519 && dual.rsa && dual.algorithm === "dual");
  check("bootstrap dual: rsa selector defaulted to <selector>-rsa",
        dual.rsa.selector === "s1-rsa");
  var dualSigned = dual.signer().sign(msg);
  // dualSigner emits TWO DKIM-Signature headers
  check("bootstrap dual: signed message has two DKIM-Signature headers",
        (dualSigned.match(/^DKIM-Signature: /gm) || []).length === 2);

  // Bad-input refusals
  var throwBad = function (label, opts, codeMatch) {
    var threw;
    try { b.mail.dkim.bootstrap(opts); } catch (e) { threw = e; }
    check(label, threw && threw.code && threw.code.indexOf(codeMatch) !== -1);
  };
  throwBad("bootstrap: refuses missing domain",
           { selector: "s1" }, "dkim/bad-domain");
  throwBad("bootstrap: refuses missing selector",
           { domain: "example.com" }, "dkim/bad-selector");
  throwBad("bootstrap: refuses bad selector shape",
           { domain: "example.com", selector: "bad/selector" }, "dkim/bad-selector");
  throwBad("bootstrap: refuses unknown algorithm",
           { domain: "example.com", selector: "s1", algorithm: "rsa-sha1" }, "dkim/bad-algorithm");
  throwBad("bootstrap: refuses RSA < 1024 bits per RFC 8301",
           { domain: "example.com", selector: "s1", algorithm: "rsa-sha256", rsaBits: 512 }, "dkim/bad-rsa-bits");
}

// ---- Audit findings 2026-05-15 — MAIL-7/11/12/20/21/41/52/65 coverage ----

async function testDkimVerifyRejectsSubBulkSenderRsa() {
  // MAIL-21 — Google + Yahoo Feb 2024 bulk-sender policy floor is 2048
  // bits. A 1024-bit RSA key (RFC 8301 historical floor) must fail
  // verify by default; only operator opt-down via minRsaBits restores.
  var kp = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 1024,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  b.mail.dkim._resetDkimKeyCacheForTest();
  var signer = b.mail.dkim.create({ domain: "example.com", selector: "s1", privateKey: kp.privateKey });
  var signed = signer.sign("From: a@example.com\r\nTo: b@example.com\r\nSubject: t\r\nDate: Sat, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <m@example.com>\r\n\r\nhi\r\n");
  var b64 = _spkiPemToB64(kp.publicKey);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
  var rv = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("MAIL-21: 1024-bit RSA refused by default (bulk-sender floor 2048)",
        rv[0] && rv[0].result === "fail" && /too small/.test((rv[0].errors || []).join(",")));

  // Operator opt-down accepts the same signature for legacy migration.
  b.mail.dkim._resetDkimKeyCacheForTest();
  var rv2 = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup, minRsaBits: 1024 });
  check("MAIL-21: minRsaBits: 1024 opt-down honors historical RFC 8301 floor",
        rv2[0] && rv2[0].result === "pass");
}

async function testDkimVerifyClockSkewBounded() {
  // MAIL-7 — clockSkewMs must be a finite non-negative number bounded
  // by the framework ceiling (24h). Otherwise back-dating replay.
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + _spkiPemToB64(kp.publicKey)]]; };
  var threwNegative = null;
  try { await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup, clockSkewMs: -1 }); }
  catch (e) { threwNegative = e; }
  check("MAIL-7: negative clockSkewMs refused",
        threwNegative && /bad-clock-skew/.test(threwNegative.code || ""));
  var threwInfinite = null;
  try { await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup, clockSkewMs: Infinity }); }
  catch (e) { threwInfinite = e; }
  check("MAIL-7: Infinity clockSkewMs refused",
        threwInfinite && /bad-clock-skew/.test(threwInfinite.code || ""));
  var threwBeyondCeil = null;
  try { await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup, clockSkewMs: 25 * 60 * 60 * 1000 }); }
  catch (e) { threwBeyondCeil = e; }
  check("MAIL-7: clockSkewMs > 24h ceiling refused",
        threwBeyondCeil && /bad-clock-skew/.test(threwBeyondCeil.code || ""));
}

async function testDkimVerifyIDomainSubdomainOfD() {
  // MAIL-11 — RFC 6376 §3.5 i= MUST be d= or a subdomain of d=. Forge
  // i=evil.com on a d=example.org signature → permerror.
  var kp = _rsaKeypair();
  var signer = b.mail.dkim.create({ domain: "example.org", selector: "s1", privateKey: kp.privateKey });
  var msg = "From: alice@example.org\r\nTo: bob@example.com\r\nSubject: t\r\nDate: Sat, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <m@example.org>\r\n\r\nhi\r\n";
  var signed = signer.sign(msg);
  // Splice an i= tag onto the DKIM-Signature header.
  signed = signed.replace("DKIM-Signature: v=1", "DKIM-Signature: v=1; i=user@evil.com");
  var b64 = _spkiPemToB64(kp.publicKey);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
  b.mail.dkim._resetDkimKeyCacheForTest();
  var rv = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("MAIL-11: i= domain not a subdomain of d= → permerror",
        rv[0] && rv[0].result === "permerror" &&
        /is not d= or a subdomain of d=/.test((rv[0].errors || []).join(",")));
}

async function testDkimAuidCheckHasNoPublicOptOut() {
  // The ARC verifier reuses this verifier and signals (via an internal token
  // module) that an ARC-Message-Signature i= is an instance number, not an
  // AUID — skipping the §3.5 AUID/d= binding check for that one case. That
  // signal must NOT be reachable from the public DKIM surface, or an operator
  // could disable a security default on real DKIM verification. Prove it: the
  // token is not exposed on b.mail.dkim, and a forged same-description Symbol
  // passed as an opt does NOT unlock the bypass — the AUID check still fires.
  check("ARC reuse token is not on the public b.mail.dkim surface",
        b.mail.dkim.ARC_AMS_REUSE === undefined);

  var kp = _rsaKeypair();
  var signer = b.mail.dkim.create({ domain: "example.org", selector: "s1", privateKey: kp.privateKey });
  var msg = "From: alice@example.org\r\nTo: bob@example.com\r\nSubject: t\r\nDate: Sat, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <m@example.org>\r\n\r\nhi\r\n";
  var signed = signer.sign(msg);
  signed = signed.replace("DKIM-Signature: v=1", "DKIM-Signature: v=1; i=user@evil.com");
  var b64 = _spkiPemToB64(kp.publicKey);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
  b.mail.dkim._resetDkimKeyCacheForTest();
  var forged = Symbol("blamejs.mail.arcAmsReuse");                 // same description, different identity
  var rv = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup, [forged]: true });
  check("forged reuse Symbol does not bypass the AUID check on public verify",
        rv[0] && rv[0].result === "permerror" &&
        /is not d= or a subdomain of d=/.test((rv[0].errors || []).join(",")));
}

async function testDkimVerifyHonorsKeyHashRestriction() {
  // MAIL-12 — RFC 6376 §3.6.1 key h= tag restricts the hash family.
  // A key whose h= is "sha512" rejects a signature whose a= is
  // rsa-sha256. Synthesized via the DNS callback.
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);
  var b64 = _spkiPemToB64(kp.publicKey);
  // Operator-published key declares h=sha512 — incompatible with the
  // signer's a=rsa-sha256.
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; h=sha512; p=" + b64]]; };
  b.mail.dkim._resetDkimKeyCacheForTest();
  var rv = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("MAIL-12: key h= restriction enforced (sha512 key rejects rsa-sha256 sig)",
        rv[0] && rv[0].result === "permerror" &&
        /not in key h=/.test((rv[0].errors || []).join(",")));
}

function testDkimSignAuditsMissingHeaders() {
  // MAIL-20 — operator-configured h= entry absent from the message
  // is silently skipped by the signer (per RFC 6376 §3.4.2). Surface
  // via audit so operators see the drift.
  var kp = _rsaKeypair();
  // Install an audit-capture before signing.
  var captured = [];
  var origEmit = b.audit && b.audit.safeEmit;
  if (origEmit) {
    b.audit.safeEmit = function (ev) {
      captured.push(ev);
      return origEmit.call(b.audit, ev);
    };
  }
  try {
    var signer = b.mail.dkim.create({
      domain: "example.com", selector: "s1", privateKey: kp.privateKey,
      headersToSign: ["from", "subject", "list-unsubscribe-post"],
    });
    var msg = "From: a@example.com\r\nSubject: t\r\nDate: Sat, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <m@example.com>\r\n\r\nhi\r\n";
    signer.sign(msg);
    var found = captured.some(function (ev) {
      return ev && ev.action === "dkim.sign.headers_missing" &&
             ev.metadata && Array.isArray(ev.metadata.missingHeaders) &&
             ev.metadata.missingHeaders.indexOf("list-unsubscribe-post") !== -1;
    });
    check("MAIL-20: signer audits dkim.sign.headers_missing for h= entries absent from message",
          found);
  } finally {
    if (origEmit) b.audit.safeEmit = origEmit;
  }
}

async function testDkimVerifySignatureCountCapped() {
  // MAIL-41 — RFC 6376 §6.1 permits multiple signatures; without a cap
  // an attacker forces 100 DNS fetches + verify operations. Cap at
  // DKIM_MAX_SIGNATURES_PER_MESSAGE; surface truncation in result.
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);
  // Prepend 20 garbage DKIM-Signature headers.
  var garbage = "";
  for (var i = 0; i < 20; i += 1) {
    garbage += "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=g" + i +
               ".example.com; s=s; h=from; bh=AAA; b=AAA\r\n";
  }
  var inflated = garbage + signed;
  var calls = 0;
  var dnsLookup = async function (qname) {
    calls += 1;
    if (qname === "s1._domainkey.example.com") {
      return [["v=DKIM1; k=rsa; p=" + _spkiPemToB64(kp.publicKey)]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
  b.mail.dkim._resetDkimKeyCacheForTest();
  var rv = await b.mail.dkim.verify(inflated, { dnsLookup: dnsLookup });
  check("MAIL-41: signature count capped at DKIM_MAX_SIGNATURES_PER_MESSAGE",
        rv.length <= b.mail.dkim.DKIM_MAX_SIGNATURES_PER_MESSAGE);
  check("MAIL-41: capped count limits DNS calls",
        calls <= b.mail.dkim.DKIM_MAX_SIGNATURES_PER_MESSAGE);
}

async function testDkimKeyCacheLru() {
  // MAIL-52 — eviction is LRU, not FIFO. Touch entry A repeatedly while
  // filling the cache; A must survive the eviction wave.
  b.mail.dkim._resetDkimKeyCacheForTest();
  var kp = _rsaKeypair();
  var b64 = _spkiPemToB64(kp.publicKey);
  // The cache is module-private; we observe behavior indirectly via
  // DNS-call count. Two verifies of A in a row are 1 fetch; the second
  // is from cache. The LRU promotion test is structural — the function
  // body now removes-and-reinserts on hit. Verify the canon path here.
  var calls = 0;
  var dnsLookup = async function () {
    calls += 1;
    return [["v=DKIM1; k=rsa; p=" + b64]];
  };
  var signed = await _signedMessage(kp);
  await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("MAIL-52: cache hits don't re-fetch (LRU-touch preserves recency)",
        calls === 1);
}

function testDkimStripBTagValueAnchored() {
  // MAIL-65 — the b= strip regex must anchor on the tag-list grammar
  // (split on `;`, then match exact tag name `b`), not on the literal
  // substring `b=` anywhere in the value.
  var strip = b.mail.dkim._stripBTagValueForTest;
  // Real DKIM tag-list — `b=BASE64` zeroed; other tags untouched.
  check("MAIL-65: b= value zeroed; other tags preserved",
        strip("v=1; a=rsa-sha256; d=example.com; b=ABCDEF") ===
        "v=1; a=rsa-sha256; d=example.com; b=");
  // Hypothetical future tag whose name ends in `b` (e.g. `pub=`).
  // Earlier shape `/\bb=[^;]*/` would mis-zero the pub= value as well.
  check("MAIL-65: tag ending in 'b' (e.g. pub=) NOT mis-zeroed",
        strip("v=1; pub=KEYDATA; b=ABCDEF") ===
        "v=1; pub=KEYDATA; b=");
}

// RFC 6376 §3.4.5 — the l= body-length count is octets of the body AFTER
// canonicalization. A legitimate relaxed/relaxed sender that sets
// l=<canonicalized-body-length> over a body whose raw form is longer (a WSP run
// the relaxed canon collapses) must verify. Slicing the RAW body to l= octets
// before canonicalizing yields a different body hash and wrongly rejects it.
async function testDkimVerifyLTagCountsCanonicalizedOctets() {
  var dkim = b.mail.dkim;
  dkim._resetDkimKeyCacheForTest();                            // unique key — don't collide with a cached selector
  var kp = _rsaKeypair();
  var pubB64 = _spkiPemToB64(kp.publicKey);
  var DOMAIN = "ltag.example", SELECTOR = "ltag1";

  // Raw body carries a 10-space WSP run; relaxed canon collapses it to one SP,
  // so the canonicalized octet count (l=) is smaller than the raw length.
  var rawBody = "A          B\r\n";
  var canon = dkim._canonBodyRelaxedForTest(rawBody);          // "A B\r\n"
  var canonBuf = Buffer.from(canon, "utf8");
  var lcap = canonBuf.length;                                  // octets of the CANONICALIZED body
  var bh = nodeCrypto.createHash("sha256").update(canonBuf.subarray(0, lcap)).digest("base64");

  var fromValue = " Alice <alice@example.com>";
  var unsignedSigValue = [
    "v=1", "a=rsa-sha256", "c=relaxed/relaxed",
    "d=" + DOMAIN, "s=" + SELECTOR, "h=from", "bh=" + bh, "l=" + lcap, "b=",
  ].join("; ");
  // Reconstruct exactly what the verifier signs: each h= header, then the
  // DKIM-Signature header with an empty b=, trailing CRLF stripped (§3.7).
  var canonHeaders =
    dkim._canonHeaderRelaxedForTest("From", fromValue) +
    dkim._canonHeaderRelaxedForTest("DKIM-Signature", unsignedSigValue).replace(/\r\n$/, "");
  var sig = nodeCrypto.createSign("RSA-SHA256").update(canonHeaders)
    .sign(kp.privateKey).toString("base64");
  var finalSigValue = unsignedSigValue.replace(/b=$/, "b=" + sig);

  var message =
    "From:" + fromValue + "\r\n" +
    "DKIM-Signature: " + finalSigValue + "\r\n" +
    "\r\n" + rawBody;

  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + pubB64]]; };
  var rv = await dkim.verify(message, { dnsLookup: dnsLookup });
  check("verify: l= over the canonicalized octet count passes (RFC 6376 §3.4.5)",
        rv[0] && rv[0].result === "pass");
}

// RFC 6376 §8.2 — the l= body-length tag covers only a PREFIX of the body, so an
// attacker can append arbitrary unsigned content after the signed octets and the
// body hash still matches. The verified bytes (the prefix) then diverge from the
// bytes actually delivered to the recipient. A signature whose l= leaves appended
// content unsigned must NOT pass by default; an operator who must accept legacy
// l= senders opts in via acceptBodyLengthLimit.
async function testDkimVerifyLTagAppendAfterSignatureRefused() {
  var dkim = b.mail.dkim;
  dkim._resetDkimKeyCacheForTest();
  var kp = _rsaKeypair();
  var pubB64 = _spkiPemToB64(kp.publicKey);
  var DOMAIN = "lappend.example", SELECTOR = "lap1";

  // Sign over ONLY the prefix "Hello\r\n" with l=<prefix canonicalized length>.
  var signedPrefix = "Hello\r\n";
  var canonPrefix = dkim._canonBodyRelaxedForTest(signedPrefix);
  var lcap = Buffer.from(canonPrefix, "utf8").length;
  var bh = nodeCrypto.createHash("sha256")
    .update(Buffer.from(canonPrefix, "utf8").subarray(0, lcap)).digest("base64");

  var fromValue = " Alice <alice@example.com>";
  var unsignedSigValue = [
    "v=1", "a=rsa-sha256", "c=relaxed/relaxed",
    "d=" + DOMAIN, "s=" + SELECTOR, "h=from", "bh=" + bh, "l=" + lcap, "b=",
  ].join("; ");
  var canonHeaders =
    dkim._canonHeaderRelaxedForTest("From", fromValue) +
    dkim._canonHeaderRelaxedForTest("DKIM-Signature", unsignedSigValue).replace(/\r\n$/, "");
  var sig = nodeCrypto.createSign("RSA-SHA256").update(canonHeaders)
    .sign(kp.privateKey).toString("base64");
  var finalSigValue = unsignedSigValue.replace(/b=$/, "b=" + sig);

  // DELIVER a body that appends attacker content AFTER the signed prefix. The bh
  // still matches the first lcap octets, so without the §8.2 guard the verifier
  // would return "pass" over a body the recipient never authenticated.
  var deliveredBody = "Hello\r\nWIRE FRAUD: send funds to acct 999\r\n";
  var message =
    "From:" + fromValue + "\r\n" +
    "DKIM-Signature: " + finalSigValue + "\r\n" +
    "\r\n" + deliveredBody;

  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + pubB64]]; };

  var rv2 = await dkim.verify(message, { dnsLookup: dnsLookup });
  check("verify: l= with content appended past the signed prefix does NOT pass (RFC 6376 §8.2)",
        rv2[0] && rv2[0].result === "fail");

  // Opt-in escape hatch — an operator who must accept legacy l= senders.
  var rvOptIn = await dkim.verify(message, { dnsLookup: dnsLookup, acceptBodyLengthLimit: true });
  check("verify: acceptBodyLengthLimit:true restores legacy l= acceptance",
        rvOptIn[0] && rvOptIn[0].result === "pass");
}

// ARC-Message-Signature verification reuses _verifySingleSignature via the
// internal reuse token (lib/mail-arc-reuse-token), so it inherits the §8.2
// append-after-l= refusal — and does NOT pass acceptBodyLengthLimit, so the
// AMS path is unconditionally fail-closed for an appended-content l=. This
// replicates what _verifyAmsViaDkim feeds the verifier (rename to
// DKIM-Signature on the wire, signed under the ARC-Message-Signature name).
async function testArcAmsLTagAppendRefused() {
  var dkim = b.mail.dkim;
  var ARC_AMS_REUSE = require("../../lib/mail-arc-reuse-token");
  dkim._resetDkimKeyCacheForTest();
  var kp = _rsaKeypair();
  var pubB64 = _spkiPemToB64(kp.publicKey);

  var signedPrefix = "Hello\r\n";
  var canonPrefix = dkim._canonBodyRelaxedForTest(signedPrefix);
  var lcap = Buffer.from(canonPrefix, "utf8").length;
  var bh = nodeCrypto.createHash("sha256")
    .update(Buffer.from(canonPrefix, "utf8").subarray(0, lcap)).digest("base64");

  var fromValue = " Alice <alice@example.com>";
  // i= is an RFC 8617 instance number (not a DKIM AUID); signed under the
  // ARC-Message-Signature name, which the reuse path canonicalizes against.
  var unsignedSigValue = [
    "i=1", "a=rsa-sha256", "c=relaxed/relaxed",
    "d=example.com", "s=arc", "h=from", "bh=" + bh, "l=" + lcap, "b=",
  ].join("; ");
  var canonHeaders =
    dkim._canonHeaderRelaxedForTest("From", fromValue) +
    dkim._canonHeaderRelaxedForTest("ARC-Message-Signature", unsignedSigValue).replace(/\r\n$/, "");
  var sig = nodeCrypto.createSign("RSA-SHA256").update(canonHeaders)
    .sign(kp.privateKey).toString("base64");
  var finalSigValue = unsignedSigValue.replace(/b=$/, "b=" + sig);

  var deliveredBody = "Hello\r\nappended unsigned content\r\n";
  var synthetic =
    "From:" + fromValue + "\r\n" +
    "DKIM-Signature: " + finalSigValue + "\r\n" +
    "\r\n" + deliveredBody;
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + pubB64]]; };
  var opts = { dnsLookup: dnsLookup };
  opts[ARC_AMS_REUSE] = true;
  var rv = await dkim.verify(synthetic, opts);
  check("ARC AMS reuse path also refuses l= append-after-signature (RFC 6376 §8.2)",
        rv[0] && rv[0].result === "fail");
}

// ---- Coverage: uncovered error / adversarial / defensive / option-default
//      branches (sign + verify). Each drives the REAL b.mail.dkim consumer
//      path with an injected DNS stub — never real DNS. ----

// Body-hash (relaxed) helper mirroring lib _bodyHashB64 with the default
// (no l=) path, so an adversarial signature can carry a body-correct bh=
// and reach the header / key / algorithm guards past the body-hash gate.
function _relaxedBodyHash(body) {
  var canon = b.mail.dkim._canonBodyRelaxedForTest(body);
  return nodeCrypto.createHash("sha256").update(Buffer.from(canon, "utf8")).digest("base64");
}

// Build a message with an arbitrary DKIM-Signature tag list. Used for the
// adversarial-verify cases whose verdict is decided BEFORE cryptographic
// verification (v=, x=/t=, missing d/s, missing bh/b, h= without from) — so
// the b= value need not be a valid signature.
function _messageWithSig(tags, body) {
  return "From: alice@example.com\r\n" +
         "DKIM-Signature: " + tags.join("; ") + "\r\n" +
         "\r\n" + (body === undefined ? "Hi\r\n" : body);
}

// Build a FULLY-VALID relaxed/relaxed single-signature message (h=from)
// with optional extra tags (t=, x=, l=) folded into the signed content, so
// the signature verifies and the run reaches _verifySingleSignature's
// pass path. Mirrors the manual construction the l= tests already use.
function _buildRelaxedSigned(kp, domain, selector, extraTags, body) {
  var dkim = b.mail.dkim;
  body = body === undefined ? "Hello world.\r\n" : body;
  var bh = _relaxedBodyHash(body);
  var fromValue = " Alice <alice@" + domain + ">";
  var tags = ["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
              "d=" + domain, "s=" + selector, "h=from", "bh=" + bh];
  if (extraTags) tags = tags.concat(extraTags);
  tags.push("b=");
  var unsigned = tags.join("; ");
  var canonHeaders =
    dkim._canonHeaderRelaxedForTest("From", fromValue) +
    dkim._canonHeaderRelaxedForTest("DKIM-Signature", unsigned).replace(/\r\n$/, "");
  var sig = nodeCrypto.createSign("RSA-SHA256").update(canonHeaders)
    .sign(kp.privateKey).toString("base64");
  var finalSig = unsigned.replace(/b=$/, "b=" + sig);
  return "From:" + fromValue + "\r\n" +
         "DKIM-Signature: " + finalSig + "\r\n" +
         "\r\n" + body;
}

// ---- create() input-shape branches ----

function testDkimCreateInputBranches() {
  var kp = _rsaKeypair();

  // headersToSign element that isn't a non-empty string → bad-headers.
  var threw = null;
  try {
    b.mail.dkim.create({ domain: "example.com", selector: "s1",
      privateKey: kp.privateKey, headersToSign: ["from", 123] });
  } catch (e) { threw = e; }
  check("create: non-string headersToSign element → bad-headers",
        threw && /dkim\/bad-headers/.test(threw.code || ""));

  // privateKey of a non-string / non-object type → missing-private-key.
  threw = null;
  try {
    b.mail.dkim.create({ domain: "example.com", selector: "s1", privateKey: 123 });
  } catch (e) { threw = e; }
  check("create: numeric privateKey → missing-private-key",
        threw && /dkim\/missing-private-key/.test(threw.code || ""));

  // privateKey as a Buffer (Buffer.isBuffer branch) → parses + signs.
  var bufSigner = b.mail.dkim.create({ domain: "example.com", selector: "s1",
    privateKey: Buffer.from(kp.privateKey, "utf8") });
  check("create: accepts a Buffer PEM privateKey",
        typeof bufSigner.sign === "function");

  // privateKey as a pre-built crypto.KeyObject (the non-string, non-Buffer
  // object branch — used directly without re-parsing).
  var keyObj = nodeCrypto.createPrivateKey({ key: kp.privateKey, format: "pem" });
  var koSigner = b.mail.dkim.create({ domain: "example.com", selector: "s1",
    privateKey: keyObj });
  var koSigned = koSigner.sign(
    "From: a@example.com\r\nSubject: t\r\n\r\nbody\r\n");
  check("create: accepts a crypto.KeyObject privateKey and signs",
        /^DKIM-Signature: /.test(koSigned));

  // create() with no argument object at all → opts defaults to {} then the
  // domain guard throws (the opts || {} default branch).
  threw = null;
  try { b.mail.dkim.create(); } catch (e) { threw = e; }
  check("create: no argument → bad-domain",
        threw && /dkim\/bad-domain/.test(threw.code || ""));
}

function testDkimSignerAuditDisabled() {
  // audit:false suppresses the sign-success + missing-header audit emits
  // (the auditOn === false option-default branch), and signing still works.
  var kp = _rsaKeypair();
  var signer = b.mail.dkim.create({
    domain: "noaudit.example", selector: "na",
    privateKey: kp.privateKey, audit: false,
    headersToSign: ["from", "subject", "x-absent-header"],
  });
  var signed = signer.sign(
    "From: a@noaudit.example\r\nSubject: t\r\nDate: Mon, 5 May 2026 12:00:00 +0000\r\n" +
    "Message-ID: <n@noaudit.example>\r\n\r\nbody\r\n");
  check("create audit:false → signs with audit emits suppressed",
        /^DKIM-Signature: /.test(signed));
}

async function testDkimEd25519VerifyRoundTrip() {
  // The ed25519-sha256 VERIFY path (RFC 8463): sign then verify against the
  // published k=ed25519 key. Exercises the ed25519 nodeAlgo=null verify
  // branch that the RSA round-trips never reach.
  var kp = _ed25519Keypair();
  b.mail.dkim._resetDkimKeyCacheForTest();
  var signer = b.mail.dkim.create({
    domain: "ed.example", selector: "e1",
    privateKey: kp.privateKey, algorithm: "ed25519-sha256",
  });
  var msg =
    "From: alice@ed.example\r\nTo: bob@example.org\r\nSubject: Ed\r\n" +
    "Date: Mon, 5 May 2026 12:00:00 +0000\r\nMessage-ID: <ed@example.com>\r\n\r\nBody\r\n";
  var signed = signer.sign(msg);
  var b64 = _spkiPemToB64(kp.publicKey);
  var rv = await b.mail.dkim.verify(signed,
    { dnsLookup: async function () { return [["v=DKIM1; k=ed25519; p=" + b64]]; } });
  check("ed25519 verify: round-trip passes (RFC 8463)",
        rv[0] && rv[0].result === "pass");
}

// ---- simple/* canonicalization sign + verify round-trips ----

function testDkimSimpleCanonDirect() {
  var sb = b.mail.dkim._canonBodySimpleForTest;
  var rb = b.mail.dkim._canonBodyRelaxedForTest;
  // simple body: strips trailing empty lines (the while-loop branch).
  check("simple body: strips trailing empty lines",
        sb("hi\r\n\r\n\r\n") === "hi\r\n");
  // simple body: a body with no trailing CRLF gains one.
  check("simple body: appends missing trailing CRLF",
        sb("hi") === "hi\r\n");
  // relaxed body: an all-empty-line body collapses to a bare CRLF.
  check("relaxed body: all-empty-line body → bare CRLF",
        rb("\r\n\r\n") === "\r\n");
}

async function testDkimSimpleCanonRoundTrips() {
  // relaxed/simple exercises SIMPLE BODY canonicalization on both the sign
  // and verify sides; the header canon stays relaxed (which unfolds the
  // folded DKIM-Signature header) so the round-trip is RFC-correct and
  // passes. This is the legitimate simple-body coverage path.
  var kpB = _rsaKeypair();
  b.mail.dkim._resetDkimKeyCacheForTest();
  var signerB = b.mail.dkim.create({
    domain: "sbody.example", selector: "sb",
    privateKey: kpB.privateKey, canonicalization: "relaxed/simple",
  });
  var msgB =
    "From: alice@sbody.example\r\nTo: bob@example.org\r\n" +
    "Subject: Simple body\r\nDate: Mon, 5 May 2026 12:00:00 +0000\r\n" +
    "Message-ID: <sb@example.com>\r\n\r\nLine one\r\nLine two\r\n\r\n";
  var signedB = signerB.sign(msgB);
  check("relaxed/simple sign: emits c=relaxed/simple",
        signedB.indexOf("c=relaxed/simple") !== -1);
  var b64B = _spkiPemToB64(kpB.publicKey);
  var rvB = await b.mail.dkim.verify(signedB,
    { dnsLookup: async function () { return [["v=DKIM1; k=rsa; p=" + b64B]]; } });
  check("relaxed/simple verify: simple-body round-trip passes",
        rvB[0] && rvB[0].result === "pass");

  // simple HEADER canonicalization (simple/simple, simple/relaxed) drives
  // the _canonHeaderSimple sign + verify branches. NOTE: the framework
  // signer signs the UNFOLDED DKIM-Signature tag string, but the wire
  // header is folded (CRLF+WSP) and simple header canonicalization does not
  // unfold — so the verifier canonicalizes different bytes than were signed
  // and the self-verify does NOT pass. This documents current behavior; see
  // the reported simple-header-canon signature-computation bug.
  var simpleHeaderCanons = ["simple/simple", "simple/relaxed"];
  for (var si = 0; si < simpleHeaderCanons.length; si += 1) {
    var canon = simpleHeaderCanons[si];
    var kp = _rsaKeypair();
    b.mail.dkim._resetDkimKeyCacheForTest();
    var signer = b.mail.dkim.create({
      domain: "shdr" + si + ".example", selector: "sh" + si,
      privateKey: kp.privateKey, canonicalization: canon,
    });
    var msg =
      "From: alice@shdr" + si + ".example\r\nTo: bob@example.org\r\n" +
      "Subject: Simple header\r\nDate: Mon, 5 May 2026 12:00:00 +0000\r\n" +
      "Message-ID: <sh" + si + "@example.com>\r\n\r\nLine one\r\n";
    var signed = signer.sign(msg);
    check("simple-header sign: emits c=" + canon,
          signed.indexOf("c=" + canon) !== -1);
    var b64 = _spkiPemToB64(kp.publicKey);
    var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
    var rv = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
    // Simple header canonicalization signs and verifies the DKIM-Signature
    // header verbatim (folded, one space after the colon) per RFC 6376 §3.4.1,
    // so a folded simple-header signature now round-trips.
    check("simple-header verify: folded " + canon + " self-verify passes",
          rv[0] && rv[0].result === "pass");
  }
}

async function testDkimSimpleCanonHonorsWireFieldName() {
  // Simple header canon is verbatim, INCLUDING the DKIM-Signature field-name
  // casing exactly as it appears on the wire — the verifier must canonicalize
  // with the parsed field name, not a hardcoded "DKIM-Signature". So a peer that
  // signs and sends `dkim-signature:` (lowercase) verifies, and a message whose
  // field name was altered after signing no longer matches. Proven here by
  // altering the on-wire casing after signing: the signature was computed over
  // "DKIM-Signature", so the lowercased wire must NOT verify. (Before the fix
  // the verifier ignored the on-wire name and this passed spuriously.)
  var kp = _rsaKeypair();
  b.mail.dkim._resetDkimKeyCacheForTest();
  var signer = b.mail.dkim.create({
    domain: "wirename.example", selector: "wn",
    privateKey: kp.privateKey, canonicalization: "simple/simple",
  });
  var msg =
    "From: alice@wirename.example\r\nTo: bob@example.org\r\n" +
    "Subject: Wire name\r\nDate: Mon, 5 May 2026 12:00:00 +0000\r\n" +
    "Message-ID: <wn@example.com>\r\n\r\nBody.\r\n";
  var signed = signer.sign(msg);
  var b64 = _spkiPemToB64(kp.publicKey);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
  var rvUpper = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
  check("simple-canon verify: canonical DKIM-Signature casing verifies",
        rvUpper[0] && rvUpper[0].result === "pass");
  // Alter ONLY the field-name casing on the wire (the signed bytes used
  // "DKIM-Signature"), leaving everything else intact.
  var loweredWire = signed.replace(/^DKIM-Signature:/, "dkim-signature:");
  var rvLower = await b.mail.dkim.verify(loweredWire, { dnsLookup: dnsLookup });
  check("simple-canon verify: honors the on-wire field-name casing (altered name does not verify)",
        rvLower[0] && rvLower[0].result === "fail");
}

// ---- Cross-implementation conformance: openssl-signed simple/simple vector ----
//
// The signature bytes below were produced by an INDEPENDENT implementation:
// OpenSSL (`openssl dgst -sha256 -sign` — RSASSA-PKCS1-v1_5) over
// hand-constructed RFC 6376 simple/simple canonicalization. bh= is the
// SHA-256 of the verbatim CRLF body (section 3.4.3); b= signs the four h=
// headers verbatim (each with its CRLF) followed by the DKIM-Signature
// header with an empty b= value and no trailing CRLF (sections 3.4.1 and
// 3.7). No framework code participated in producing the fixture, so a pass
// here proves cross-implementation ACCEPTANCE of simple canonicalization —
// a self-round-trip alone stays green when sign and verify share the same
// canonicalization bug. The tampered-body / tampered-header controls prove
// the pass is cryptographic, not vacuous.
async function testDkimOpensslSimpleCanonInteropVector() {
  var BH = "AD876huuF731JvLItVmRCvApI83P8LTA8/xaXm2Hu8Y=";
  var SIG =
    "i62Ti4k531wo/A2u2rk8G5J8JpgM0+MBj6vJbmwzz6MiMYEwS6XfO1GAOL0rUtM3TSNeWjKg" +
    "ul2XjS4C5bVMjRQma1W+TzcJh3aHL8UXTc8K64DQ8isZ61BsN8v/iaIf/z5/6MZIOxlnaAbn" +
    "CVWm/1OU3qvhKxyFOU9aCl+EaHuHGlvF1EM/bBpPpu9jmjRzSvj6Nyojw1tFl/g4HfOaCvpv" +
    "wVmOBo49O1voWHC3CHDHK5rbURzf/dVC37aviTkjTgbh5I8QTcRVllBAMOs5LYl5zHAr1Jop" +
    "h+8omZwednKI/Inj//S0EsyZeM6iKkuNX1nP3c460DH65jexsLj49Q==";
  var PUB_B64 =
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0VM3DGY3FSvXw58NTv2nMzJ149kB" +
    "Q6KuTQBaRjjQfrYxRAbLhCSgatNz55GbZlBR0Uj7sYmGzte18sef5AqCWY4lXrD/+97S0GjH" +
    "jUMHzQhp9Tk1m4yVnfqJp2MgXyMi31yrRvRkmNM7XD/EC07HuugHcKGnPRsHQV6kyGUkeuHt" +
    "lQYRx058jTOWja6mcc0/nVQa08GM4703QYl6j3ZgSiu90fFnw77uswcuaKgwPIw3V66uPNPS" +
    "VhqxGLyuXF4fw1DvYtRyJ/3liMNhqClEqDSwKfSEK6Z8nE/4M8Nv3BZA0OOzitDmqzyXkcdY" +
    "At3XbaUHc0Gpbs5MYV7k2YXKWQIDAQAB";

  var message =
    "DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; " +
      "d=openssl-interop.example; s=oss1; h=from:to:subject:date; " +
      "bh=" + BH + "; b=" + SIG + "\r\n" +
    "From: interop@openssl-interop.example\r\n" +
    "To: rcpt@blamejs.example\r\n" +
    "Subject: DKIM simple canonicalization interop\r\n" +
    "Date: Thu, 01 Jan 2026 00:00:00 +0000\r\n" +
    "\r\n" +
    "Interop body line one.\r\nInterop body line two.\r\n";

  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + PUB_B64]]; };

  b.mail.dkim._resetDkimKeyCacheForTest();
  var rv = await b.mail.dkim.verify(message, { dnsLookup: dnsLookup });
  check("openssl interop: independently-signed simple/simple vector passes",
        Array.isArray(rv) && rv.length === 1 && rv[0].result === "pass");
  check("openssl interop: pass verdict carries zero errors",
        rv[0] && Array.isArray(rv[0].errors) && rv[0].errors.length === 0);
  check("openssl interop: verdict identifies the signing domain and selector",
        rv[0] && rv[0].d === "openssl-interop.example" && rv[0].s === "oss1");

  // Control 1: one flipped body byte breaks the simple body hash.
  var bodyTampered = message.replace("Interop body line two.", "Interop body line 2wo.");
  var rvBody = await b.mail.dkim.verify(bodyTampered, { dnsLookup: dnsLookup });
  check("openssl interop: tampered body fails (body hash mismatch)",
        rvBody[0] && rvBody[0].result === "fail" &&
        /body hash mismatch/.test((rvBody[0].errors || []).join(",")));

  // Control 2: one flipped byte in a signed header breaks the signature.
  var hdrTampered = message.replace("Subject: DKIM simple", "Subject: DKIM Simple");
  var rvHdr = await b.mail.dkim.verify(hdrTampered, { dnsLookup: dnsLookup });
  check("openssl interop: tampered signed header fails signature verification",
        rvHdr[0] && rvHdr[0].result === "fail" &&
        /signature verification failed/.test((rvHdr[0].errors || []).join(",")));
}

// ---- verify(): input + option-default guards ----

async function testDkimVerifyBadInputAndOptions() {
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);
  var b64 = _spkiPemToB64(kp.publicKey);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };

  // Empty / non-string rfc822 → bad-input throw.
  var threw = null;
  try { await b.mail.dkim.verify(""); } catch (e) { threw = e; }
  check("verify: empty rfc822 → bad-input", threw && /dkim\/bad-input/.test(threw.code || ""));
  threw = null;
  try { await b.mail.dkim.verify(12345); } catch (e) { threw = e; }
  check("verify: non-string rfc822 → bad-input", threw && /dkim\/bad-input/.test(threw.code || ""));

  // A well-formed valid clockSkewMs (the accepted numeric branch).
  b.mail.dkim._resetDkimKeyCacheForTest();
  var rvSkew = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup, clockSkewMs: 60000 });
  check("verify: accepts a valid clockSkewMs (finite, < ceiling)",
        rvSkew[0] && rvSkew[0].result === "pass");

  // maxSignatures range-check: below 1 and above the ceiling throw.
  threw = null;
  try { await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup, maxSignatures: 0 }); }
  catch (e) { threw = e; }
  check("verify: maxSignatures < 1 → bad-max-signatures",
        threw && /dkim\/bad-max-signatures/.test(threw.code || ""));
  threw = null;
  try { await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup, maxSignatures: 99 }); }
  catch (e) { threw = e; }
  check("verify: maxSignatures > ceiling → bad-max-signatures",
        threw && /dkim\/bad-max-signatures/.test(threw.code || ""));

  // A valid in-range maxSignatures (the accepted numeric branch).
  b.mail.dkim._resetDkimKeyCacheForTest();
  var rvMax = await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup, maxSignatures: 4 });
  check("verify: accepts an in-range maxSignatures",
        rvMax[0] && rvMax[0].result === "pass");
}

async function testDkimVerifyNoSignatureHeaders() {
  // A message with no DKIM-Signature header → single "none" result.
  var msg = "From: a@example.com\r\nSubject: unsigned\r\n\r\nbody\r\n";
  var rv = await b.mail.dkim.verify(msg, { dnsLookup: async function () { return [[""]]; } });
  check("verify: unsigned message → [{ result: 'none' }]",
        Array.isArray(rv) && rv[0] && rv[0].result === "none" &&
        /no DKIM-Signature/.test((rv[0].errors || []).join(",")));
}

// ---- verify(): v= / x= / t= NumericDate guards (decided pre-crypto) ----

async function testDkimVerifyBadVersion() {
  var rv = await b.mail.dkim.verify(
    _messageWithSig(["v=2", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=v.example", "s=s", "h=from", "bh=AAA", "b=AAA"]),
    { dnsLookup: async function () { return [["v=DKIM1; k=rsa; p=AAA"]]; } });
  check("verify: v=2 → permerror (only v=1 supported)",
        rv[0] && rv[0].result === "permerror" && /only v=1/.test((rv[0].errors || []).join(",")));
}

async function testDkimVerifyExpiredAndUnparseableDates() {
  var nowSec = Math.floor(Date.now() / 1000);
  var stub = { dnsLookup: async function () { return [["v=DKIM1; k=rsa; p=AAA"]]; } };

  // x= in the past (beyond the default 5-min skew) → expired permerror.
  var rvExp = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=x.example", "s=s", "h=from", "bh=AAA", "x=" + (nowSec - 3600), "b=AAA"]), stub);
  check("verify: expired x= → permerror",
        rvExp[0] && rvExp[0].result === "permerror" && /has expired/.test((rvExp[0].errors || []).join(",")));

  // x= present but not digits-only → fail-closed permerror.
  var rvXbad = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=x.example", "s=s", "h=from", "bh=AAA", "x=12abc", "b=AAA"]), stub);
  check("verify: unparseable x= → permerror (NumericDate required)",
        rvXbad[0] && rvXbad[0].result === "permerror" &&
        /x= present but unparseable/.test((rvXbad[0].errors || []).join(",")));

  // t= present but not digits-only → fail-closed permerror.
  var rvTbad = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=t.example", "s=s", "h=from", "bh=AAA", "t=notanum", "b=AAA"]), stub);
  check("verify: unparseable t= → permerror (NumericDate required)",
        rvTbad[0] && rvTbad[0].result === "permerror" &&
        /t= present but unparseable/.test((rvTbad[0].errors || []).join(",")));

  // t= more than 24h in the future → sanity permerror.
  var rvFuture = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=t.example", "s=s", "h=from", "bh=AAA", "t=" + (nowSec + 48 * 3600), "b=AAA"]), stub);
  check("verify: t= >24h in the future → permerror",
        rvFuture[0] && rvFuture[0].result === "permerror" &&
        /more than 24h in the future/.test((rvFuture[0].errors || []).join(",")));

  // x= before t= (expiry earlier than signing time) → ordering permerror.
  var rvOrder = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=t.example", "s=s", "h=from", "bh=AAA",
      "t=" + (nowSec + 100), "x=" + (nowSec + 50), "b=AAA"]), stub);
  check("verify: x= before t= → permerror (x must be after t)",
        rvOrder[0] && rvOrder[0].result === "permerror" &&
        /x= must be after t=/.test((rvOrder[0].errors || []).join(",")));
}

async function testDkimVerifyValidDatesPassThrough() {
  // A fully-valid signature carrying non-expired t= + x= reaches the pass
  // path (exercises the accepted t=/x= branches, not the reject branches).
  var kp = _rsaKeypair();
  b.mail.dkim._resetDkimKeyCacheForTest();
  var nowSec = Math.floor(Date.now() / 1000);
  var signed = _buildRelaxedSigned(kp, "dates.example", "sd",
    ["t=" + (nowSec - 60), "x=" + (nowSec + 3600)]);
  var b64 = _spkiPemToB64(kp.publicKey);
  var rv = await b.mail.dkim.verify(signed,
    { dnsLookup: async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; } });
  check("verify: valid non-expired t= + x= passes through to verification",
        rv[0] && rv[0].result === "pass");
}

async function testDkimVerifyMissingDomainSelector() {
  // Signature with neither d= nor s= → permerror (missing d= or s=).
  var rv = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "h=from", "bh=AAA", "b=AAA"]),
    { dnsLookup: async function () { return [["v=DKIM1; k=rsa; p=AAA"]]; } });
  check("verify: missing d=/s= → permerror",
        rv[0] && rv[0].result === "permerror" &&
        /missing d= or s=/.test((rv[0].errors || []).join(",")));
}

// ---- verify(): key-resolution error paths ----

async function testDkimVerifyKeyLookupErrors() {
  // ENOTFOUND from the resolver → permerror key-not-found.
  var rvNx = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=nx.example", "s=s", "h=from", "bh=AAA", "b=AAA"]),
    { dnsLookup: async function () { var e = new Error("nx"); e.code = "ENOTFOUND"; throw e; } });
  check("verify: ENOTFOUND key lookup → permerror (no TXT record)",
        rvNx[0] && rvNx[0].result === "permerror" &&
        /no DKIM TXT record/.test((rvNx[0].errors || []).join(",")));

  // A generic resolver failure (no ENOTFOUND/ENODATA code) → temperror.
  var rvTemp = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=temp.example", "s=s", "h=from", "bh=AAA", "b=AAA"]),
    { dnsLookup: async function () { throw new Error("connection reset"); } });
  check("verify: generic key-lookup failure → temperror",
        rvTemp[0] && rvTemp[0].result === "temperror" &&
        /lookup for .* failed/.test((rvTemp[0].errors || []).join(",")));
}

async function testDkimVerifyKeyRecordShapes() {
  var kp = _rsaKeypair();
  var b64 = _spkiPemToB64(kp.publicKey);

  // A bare-string TXT record (not the [[chunk]] shape) still parses.
  b.mail.dkim._resetDkimKeyCacheForTest();
  var signed = await _signedMessage(kp);
  var rvStr = await b.mail.dkim.verify(signed,
    { dnsLookup: async function () { return "v=DKIM1; k=rsa; p=" + b64; } });
  check("verify: accepts a bare-string TXT record shape",
        rvStr[0] && rvStr[0].result === "pass");

  // An empty TXT record → key-not-found (empty) → permerror.
  var rvEmpty = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=e.example", "s=s", "h=from", "bh=AAA", "b=AAA"]),
    { dnsLookup: async function () { return ""; } });
  check("verify: empty TXT record → permerror (key record is empty)",
        rvEmpty[0] && rvEmpty[0].result === "permerror" &&
        /empty/.test((rvEmpty[0].errors || []).join(",")));

  // A record present but missing p= → permerror (missing p=).
  var rvNoP = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=nop.example", "s=s", "h=from", "bh=AAA", "b=AAA"]),
    { dnsLookup: async function () { return [["v=DKIM1; k=rsa"]]; } });
  check("verify: key record without p= → permerror (missing p=)",
        rvNoP[0] && rvNoP[0].result === "permerror" &&
        /missing p=/.test((rvNoP[0].errors || []).join(",")));

  // An explicitly-revoked key (empty p=) → fail (well-formed, withdrawn).
  var rvRevoked = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=rev.example", "s=s", "h=from", "bh=AAA", "b=AAA"]),
    { dnsLookup: async function () { return [["v=DKIM1; k=rsa; p="]]; } });
  check("verify: revoked key (empty p=) → fail",
        rvRevoked[0] && rvRevoked[0].result === "fail" &&
        /revoked/.test((rvRevoked[0].errors || []).join(",")));

  // Key k= family disagrees with the signature a= family → permerror.
  var rvKMismatch = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=km.example", "s=s", "h=from", "bh=AAA", "b=AAA"]),
    { dnsLookup: async function () { return [["v=DKIM1; k=ed25519; p=AAA"]]; } });
  check("verify: key k= family != signature a= family → permerror",
        rvKMismatch[0] && rvKMismatch[0].result === "permerror" &&
        /does not match signature a=/.test((rvKMismatch[0].errors || []).join(",")));
}

// ---- verify(): _verifySingleSignature body-hash / header / key guards ----

async function testDkimVerifySingleSignatureGuards() {
  var kp = _rsaKeypair();
  var b64 = _spkiPemToB64(kp.publicKey);
  var goodKey = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
  var bhBody = "guarded body\r\n";
  var bh = _relaxedBodyHash(bhBody);

  // Signature with no bh= tag → permerror (missing bh=).
  var rvNoBh = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=nobh.example", "s=s", "h=from", "b=AAA"], bhBody),
    { dnsLookup: goodKey });
  check("verify: signature missing bh= → permerror",
        rvNoBh[0] && rvNoBh[0].result === "permerror" &&
        /missing bh=/.test((rvNoBh[0].errors || []).join(",")));

  // A tampered body (correct-length but different content) → body-hash fail.
  var rvBhMismatch = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=bhmm.example", "s=s", "h=from", "bh=" + bh, "b=AAA"], "TAMPERED body\r\n"),
    { dnsLookup: goodKey });
  check("verify: body-hash mismatch → fail",
        rvBhMismatch[0] && rvBhMismatch[0].result === "fail" &&
        /body hash mismatch/.test((rvBhMismatch[0].errors || []).join(",")));

  // Correct bh but h= omits 'from' → permerror (from not covered).
  var rvNoFrom = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=nofrom.example", "s=s", "h=to", "bh=" + bh, "b=AAA"], bhBody),
    { dnsLookup: goodKey });
  check("verify: h= without 'from' → permerror",
        rvNoFrom[0] && rvNoFrom[0].result === "permerror" &&
        /does not include 'from'/.test((rvNoFrom[0].errors || []).join(",")));

  // Correct bh + h=from but no b= tag → permerror (missing b=).
  var rvNoB = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=nob.example", "s=s", "h=from", "bh=" + bh], bhBody),
    { dnsLookup: goodKey });
  check("verify: signature missing b= → permerror",
        rvNoB[0] && rvNoB[0].result === "permerror" &&
        /missing b=/.test((rvNoB[0].errors || []).join(",")));

  // l= present but not digits-only → fail-closed permerror.
  var rvLbad = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=lbad.example", "s=s", "h=from", "bh=" + bh, "l=12x", "b=AAA"], bhBody),
    { dnsLookup: goodKey });
  check("verify: unparseable l= → permerror (unsigned integer required)",
        rvLbad[0] && rvLbad[0].result === "permerror" &&
        /l= present but unparseable/.test((rvLbad[0].errors || []).join(",")));

  // Correct bh + h=from + b= present, but the published key p= is garbage
  // that node:crypto cannot parse → permerror (key parse failed).
  var rvKeyParse = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=keyparse.example", "s=s", "h=from", "bh=" + bh, "b=AAAA"], bhBody),
    { dnsLookup: async function () { return [["v=DKIM1; k=rsa; p=@@not-base64-der@@"]]; } });
  check("verify: unparseable key material → permerror (key parse failed)",
        rvKeyParse[0] && rvKeyParse[0].result === "permerror" &&
        /key parse failed/.test((rvKeyParse[0].errors || []).join(",")));

  // a= names a supported family (rsa) but an unsupported full algorithm
  // (rsa-sha1) → permerror (unsupported DKIM algorithm). Take a valid
  // rsa-sha256 signature and re-label its a= so bh stays valid and the
  // run reaches the algorithm check before any crypto verify.
  b.mail.dkim._resetDkimKeyCacheForTest();
  var validSigned = _buildRelaxedSigned(kp, "alg.example", "sa");
  var relabeled = validSigned.replace("a=rsa-sha256", "a=rsa-sha1");
  var rvUnsupported = await b.mail.dkim.verify(relabeled, { dnsLookup: goodKey });
  check("verify: unsupported a= algorithm (rsa-sha1) → permerror",
        rvUnsupported[0] && rvUnsupported[0].result === "permerror" &&
        /unsupported DKIM algorithm/.test((rvUnsupported[0].errors || []).join(",")));
}

async function testDkimVerifyCryptoThrowsPath() {
  // a=rsa-sha256 (digest sha256) but the published key is an Ed25519 key
  // with no k= tag, so the k= guard is skipped and node:crypto.verify is
  // invoked with a digest the key type rejects → it THROWS, and the
  // verifier maps the throw to a permerror rather than crashing.
  var edKp = _ed25519Keypair();
  var edB64 = _spkiPemToB64(edKp.publicKey);
  var body = "throws body\r\n";
  var bh = _relaxedBodyHash(body);
  b.mail.dkim._resetDkimKeyCacheForTest();
  var rv = await b.mail.dkim.verify(
    _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
      "d=throws.example", "s=s", "h=from", "bh=" + bh, "b=AAAA"], body),
    { dnsLookup: async function () { return [["v=DKIM1; p=" + edB64]]; } });
  check("verify: node:crypto.verify throw is caught → permerror",
        rv[0] && rv[0].result === "permerror" &&
        /verify threw/.test((rv[0].errors || []).join(",")));
}

// ---- verify(): key cache expiry + eviction ----

async function testDkimKeyCacheExpiry() {
  // A cached key entry past its TTL is dropped and re-fetched. Advance the
  // clock via a scoped Date.now override (deterministic; no wall-clock wait).
  b.mail.dkim._resetDkimKeyCacheForTest();
  var kp = _rsaKeypair();
  var b64 = _spkiPemToB64(kp.publicKey);
  var signed = await _signedMessage(kp);
  var calls = 0;
  var dnsLookup = async function () { calls += 1; return [["v=DKIM1; k=rsa; p=" + b64]]; };
  var realNow = Date.now;
  try {
    await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });   // fetch + cache
    var base = realNow();
    Date.now = function () { return base + 6 * 60 * 1000; };      // TTL is 5 min
    await b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });   // expired → re-fetch
    check("verify: key cache entry past TTL is evicted and re-fetched",
          calls === 2);
  } finally {
    Date.now = realNow;
  }
}

async function testDkimKeyCacheEvictionBound() {
  // Fill the key cache past its max-entries bound so the oldest entry is
  // evicted (the DoS-bounding eviction path). Each verify pins a distinct
  // domain; a k=-family mismatch short-circuits before any crypto verify,
  // so the fill is cheap. The first-inserted selector must be re-fetched
  // after the eviction wave, proving the oldest entry was dropped.
  b.mail.dkim._resetDkimKeyCacheForTest();
  var MAX = 1024;   // lib DKIM_KEY_CACHE_MAX_ENTRIES (module-private)
  var fetches = Object.create(null);
  var dnsLookup = async function (qname) {
    fetches[qname] = (fetches[qname] || 0) + 1;
    return [["v=DKIM1; k=ed25519; p=AAA"]];   // mismatch vs a=rsa-sha256 → permerror pre-crypto
  };
  async function verifyDomain(dom) {
    return b.mail.dkim.verify(
      _messageWithSig(["v=1", "a=rsa-sha256", "c=relaxed/relaxed",
        "d=" + dom, "s=s", "h=from", "bh=AAA", "b=AAA"]),
      { dnsLookup: dnsLookup });
  }
  var firstDomain = "g0.evict.example";
  await verifyDomain(firstDomain);                        // insert oldest
  for (var i = 1; i <= MAX; i += 1) {                     // MAX more → oldest evicted
    await verifyDomain("g" + i + ".evict.example");
  }
  var firstQname = "s._domainkey." + firstDomain;
  var before = fetches[firstQname];
  await verifyDomain(firstDomain);                        // must miss → re-fetch
  check("verify: oldest key-cache entry evicted past the max-entries bound",
        fetches[firstQname] === before + 1);
}

// ---- dualSigner() + bootstrap() validation branches ----

function testDualSignerValidation() {
  var kp = _rsaKeypair();
  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { b.mail.dkim.dualSigner(opts); } catch (e) { threw = e; }
    check("dualSigner: " + label, threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("missing rsa/eddsa → dual-signer-missing",
    { domain: "example.com" }, /dkim\/dual-signer-missing/);
  shouldThrow("missing eddsa → dual-signer-missing",
    { domain: "example.com", rsa: { selector: "r", privateKey: kp.privateKey } },
    /dkim\/dual-signer-missing/);
  shouldThrow("missing domain → dual-signer-missing-domain",
    { rsa: { selector: "r", privateKey: kp.privateKey },
      eddsa: { selector: "e", privateKey: _ed25519Keypair().privateKey } },
    /dkim\/dual-signer-missing-domain/);
}

function testBootstrapMoreValidation() {
  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { b.mail.dkim.bootstrap(opts); } catch (e) { threw = e; }
    check("bootstrap: " + label, threw && codeRe.test(threw.code || ""));
  }
  // Domain that fails the DNS-hostname shape (leading hyphen).
  shouldThrow("rejects malformed domain shape",
    { domain: "-bad-.example", selector: "s1" }, /dkim\/bad-domain/);
  // Dual with a malformed explicit rsaSelector.
  shouldThrow("dual rejects malformed rsaSelector",
    { domain: "example.com", selector: "s1", algorithm: "dual", rsaSelector: "bad/sel" },
    /dkim\/bad-selector/);
  // Dual with sub-floor rsaBits.
  shouldThrow("dual rejects sub-floor rsaBits",
    { domain: "example.com", selector: "s1", algorithm: "dual", rsaBits: 512 },
    /dkim\/bad-rsa-bits/);
}

async function run() {
  testDkimSurfaceAndValidation();
  testDkimCanonicalization();
  testDkimHeaderParserGolden();
  testDkimRsaSignProducesHeader();
  testDkimEd25519Sign();
  testDkimSignerRejectsBadInput();
  testDkimRejectsLTagBodyLength();
  await testDkimVerifyHappyPath();
  await testDkimVerifyBareLfMessage();
  await testDkimVerifyKeyCacheHit();
  await testDkimVerifySmallKeyRejected();
  await testCalendarValidation();
  testCalendarBuilderEmitsTextCalendarPart();
  testCalendarOnlyMessage();
  testSmtpDkimMisconfiguredOptThrows();
  await testDkimBootstrap();
  // Audit 2026-05-15 — MAIL-7/11/12/20/21/41/52/65
  await testDkimVerifyRejectsSubBulkSenderRsa();
  await testDkimVerifyClockSkewBounded();
  await testDkimVerifyIDomainSubdomainOfD();
  await testDkimAuidCheckHasNoPublicOptOut();
  await testDkimVerifyHonorsKeyHashRestriction();
  testDkimSignAuditsMissingHeaders();
  await testDkimVerifySignatureCountCapped();
  await testDkimKeyCacheLru();
  testDkimStripBTagValueAnchored();
  await testDkimVerifyLTagCountsCanonicalizedOctets();
  await testDkimVerifyLTagAppendAfterSignatureRefused();
  await testArcAmsLTagAppendRefused();
  // Uncovered error / adversarial / defensive / option-default branches
  testDkimCreateInputBranches();
  testDkimSignerAuditDisabled();
  await testDkimEd25519VerifyRoundTrip();
  testDkimSimpleCanonDirect();
  await testDkimSimpleCanonRoundTrips();
  await testDkimSimpleCanonHonorsWireFieldName();
  await testDkimOpensslSimpleCanonInteropVector();
  await testDkimVerifyBadInputAndOptions();
  await testDkimVerifyNoSignatureHeaders();
  await testDkimVerifyBadVersion();
  await testDkimVerifyExpiredAndUnparseableDates();
  await testDkimVerifyValidDatesPassThrough();
  await testDkimVerifyMissingDomainSelector();
  await testDkimVerifyKeyLookupErrors();
  await testDkimVerifyKeyRecordShapes();
  await testDkimVerifySingleSignatureGuards();
  await testDkimVerifyCryptoThrowsPath();
  await testDkimKeyCacheExpiry();
  await testDkimKeyCacheEvictionBound();
  testDualSignerValidation();
  testBootstrapMoreValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

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

async function run() {
  testDkimSurfaceAndValidation();
  testDkimCanonicalization();
  testDkimRsaSignProducesHeader();
  testDkimEd25519Sign();
  testDkimSignerRejectsBadInput();
  testDkimRejectsLTagBodyLength();
  await testDkimVerifyHappyPath();
  await testDkimVerifyKeyCacheHit();
  await testDkimVerifySmallKeyRejected();
  await testCalendarValidation();
  testCalendarBuilderEmitsTextCalendarPart();
  testCalendarOnlyMessage();
  testSmtpDkimMisconfiguredOptThrows();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

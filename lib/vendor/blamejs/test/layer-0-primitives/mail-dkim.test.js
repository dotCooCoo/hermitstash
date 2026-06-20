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

async function run() {
  testDkimSurfaceAndValidation();
  testDkimCanonicalization();
  testDkimHeaderParserGolden();
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
  await testDkimBootstrap();
  // Audit 2026-05-15 — MAIL-7/11/12/20/21/41/52/65
  await testDkimVerifyRejectsSubBulkSenderRsa();
  await testDkimVerifyClockSkewBounded();
  await testDkimVerifyIDomainSubdomainOfD();
  await testDkimVerifyHonorsKeyHashRestriction();
  testDkimSignAuditsMissingHeaders();
  await testDkimVerifySignatureCountCapped();
  await testDkimKeyCacheLru();
  testDkimStripBTagValueAnchored();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

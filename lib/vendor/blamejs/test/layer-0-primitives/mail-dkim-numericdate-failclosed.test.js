"use strict";
/**
 * b.mail.dkim.verify — x= / t= present-but-unparseable must FAIL CLOSED.
 *
 * RFC 6376 §3.5 — x= (expiration) and t= (timestamp) are NumericDate
 * (digits-only seconds-since-epoch). The prior code parsed each with
 * parseInt() guarded by isFinite(): a present-but-unparseable value
 * (x=abc, x=, t=oops) yielded NaN, isFinite() was false, and the WHOLE
 * expiry / future-date / ordering check SILENTLY SKIPPED — verification
 * then proceeded to result:"pass" with no expiry enforced. An attacker
 * replaying a message could neuter x= expiry by corrupting the tag.
 *
 * Mirrors the SAML Conditions present-but-unparseable fail-closed fix:
 * when x= / t= is PRESENT it MUST parse as a finite NumericDate, else
 * verify() returns result:"permerror".
 *
 * Drives the real consumer path b.mail.dkim.verify (not an internal
 * helper). The x=/t= checks run BEFORE the DNS key fetch + signature
 * verify, so a spliced tag over an otherwise-valid signature reaches
 * them regardless of the (mocked) key.
 *
 * Run standalone: `node test/layer-0-primitives/mail-dkim-numericdate-failclosed.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("crypto");

function _rsaKeypair() {
  return nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function _spkiPemToB64(pem) {
  return pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
}

function _signedMessage(keypair) {
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

// Splice a tag (e.g. "x=abc") into the DKIM-Signature header value, right
// after the "v=1" prefix, leaving the rest of the (valid) signature intact.
function _spliceTag(signed, tag) {
  return signed.replace("DKIM-Signature: v=1", "DKIM-Signature: v=1; " + tag);
}

async function _verify(signed, kp) {
  b.mail.dkim._resetDkimKeyCacheForTest();
  var b64 = _spkiPemToB64(kp.publicKey);
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + b64]]; };
  return b.mail.dkim.verify(signed, { dnsLookup: dnsLookup });
}

async function testDkimXTagUnparseableFailsClosed() {
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);

  var rvAbc = await _verify(_spliceTag(signed, "x=abc"), kp);
  check("verify: x=abc → permerror (not pass)",
        rvAbc[0] && rvAbc[0].result === "permerror");
  check("verify: x=abc error names present-but-unparseable",
        rvAbc[0] && /x=.*unparseable/i.test((rvAbc[0].errors || []).join(" ")));

  var rvEmpty = await _verify(_spliceTag(signed, "x="), kp);
  check("verify: x= (empty) → permerror (not pass)",
        rvEmpty[0] && rvEmpty[0].result === "permerror");

  var rvLenient = await _verify(_spliceTag(signed, "x=12abc"), kp);
  check("verify: x=12abc (parseInt-lenient) → permerror (not pass)",
        rvLenient[0] && rvLenient[0].result === "permerror");
}

async function testDkimLTagUnparseableFailsClosed() {
  // Sibling of the same root: l= (body-length cap, §3.5 unsigned integer).
  // A present-but-unparseable l= previously fell through to lcap=undefined,
  // silently hashing the WHOLE body instead of refusing the malformed tag.
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);

  var rv = await _verify(_spliceTag(signed, "l=abc"), kp);
  check("verify: l=abc → permerror (not fall-through)",
        rv[0] && rv[0].result === "permerror");
  check("verify: l=abc error names present-but-unparseable",
        rv[0] && /l=.*unparseable/i.test((rv[0].errors || []).join(" ")));
}

async function testDkimTTagUnparseableFailsClosed() {
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);

  var rv = await _verify(_spliceTag(signed, "t=oops"), kp);
  check("verify: t=oops → permerror (not pass)",
        rv[0] && rv[0].result === "permerror");
  check("verify: t=oops error names present-but-unparseable",
        rv[0] && /t=.*unparseable/i.test((rv[0].errors || []).join(" ")));
}

// Guard against over-correction: a well-formed x= far in the future + a
// well-formed t= still verify to "pass" (the fix must not reject valid
// NumericDate values).
async function testDkimWellFormedNumericDateStillPasses() {
  var kp = _rsaKeypair();
  var signed = await _signedMessage(kp);

  // x= 1 year out, t= now — both well-formed, ordering valid.
  var nowSec = Math.floor(Date.now() / 1000);
  var future = nowSec + (365 * 24 * 60 * 60);
  // Note: splicing x=/t= changes the signed header value, so the body-hash
  // / signature won't match — but the verdict must be a CRYPTO failure
  // ("fail"/"permerror" from sig mismatch), NEVER skip the well-formed
  // time checks. The point of THIS case: well-formed values are PARSED
  // (don't trip the present-but-unparseable refusal). Assert the error,
  // if any, is not the unparseable refusal.
  var rv = await _verify(_spliceTag(signed, "t=" + nowSec + "; x=" + future), kp);
  var joined = (rv[0].errors || []).join(" ");
  check("verify: well-formed x=/t= not refused as unparseable",
        !/unparseable/i.test(joined));
}

async function run() {
  await testDkimXTagUnparseableFailsClosed();
  await testDkimLTagUnparseableFailsClosed();
  await testDkimTTagUnparseableFailsClosed();
  await testDkimWellFormedNumericDateStillPasses();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () {
    console.log("mail-dkim-numericdate-failclosed: OK");
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : e);
    process.exit(1);
  });
}

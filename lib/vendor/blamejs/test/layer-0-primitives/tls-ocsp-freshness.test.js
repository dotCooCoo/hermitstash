"use strict";
/**
 * b.network.tls.ocsp.evaluate — OCSP response FRESHNESS enforcement
 * (RFC 6960 §4.2.2.1). Regression coverage for the dead staleness gate:
 * evaluateOcspResponse called Date.parse() on thisUpdate/nextUpdate, but
 * those fields are already unix-ms NUMBERS (parseOcspResponse → _parseTime
 * returns Date.UTC(...)). Date.parse(<number>) coerces to a bare-integer
 * string → NaN, so the !isFinite guard rejected EVERY signature-valid
 * response (fresh or stale) with a misleading "missing thisUpdate", leaving
 * the real future-thisUpdate / past-nextUpdate window checks as unreachable
 * dead code (the past-nextUpdate branch latently fail-open).
 *
 * No existing test built a full SIGNED `successful` BasicOCSPResponse — every
 * prior OCSP test short-circuited before the freshness gate — which is why
 * the dead check shipped. This builds a real ECDSA-SHA256-signed response and
 * drives the consumer path, asserting:
 *   - a STALE response (past nextUpdate) is REJECTED for the stale reason
 *     (RED before the fix: rejected, but with "missing thisUpdate");
 *   - a FRESH response is ACCEPTED (RED before the fix: rejected as "missing
 *     thisUpdate" — the bug cannot tell fresh from stale);
 *   - a FUTURE-thisUpdate response is rejected for the future reason.
 *
 * Run standalone: node test/layer-0-primitives/tls-ocsp-freshness.test.js
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var asn1    = require("../../lib/asn1-der");

// A fixed reference time so the test is wall-clock independent (passed to
// evaluate as opts.now). All thisUpdate/nextUpdate are offsets from this.
var FIXED_NOW = 1750000000000;   // 2025-06-15T...Z, a stable ms value

function _pad(n, width) {
  var s = String(n);
  while (s.length < width) s = "0" + s;
  return s;
}

// unix-ms → GeneralizedTime "YYYYMMDDhhmmssZ" (the on-the-wire shape
// _parseTime accepts; it truncates to whole seconds, which is fine — the
// offsets here are minutes/days, far from the second boundary).
function _genTime(ms) {
  var d = new Date(ms);
  return asn1.writeNode(0x18, Buffer.from(
    _pad(d.getUTCFullYear(), 4) + _pad(d.getUTCMonth() + 1, 2) + _pad(d.getUTCDate(), 2) +
    _pad(d.getUTCHours(), 2) + _pad(d.getUTCMinutes(), 2) + _pad(d.getUTCSeconds(), 2) + "Z",
    "ascii"));
}

// Build a complete, validly-signed OCSP "successful" response (certStatus
// good) for a given serial, with the supplied thisUpdate/nextUpdate ms.
// Returns { der, issuerPem, serialHex }.
function _buildSignedOcsp(opts) {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var issuerPem = kp.publicKey.export({ type: "spki", format: "pem" });

  var serial = Buffer.from([0x12, 0x34, 0x56, 0x78]);
  var serialHex = serial.toString("hex");

  // certID = SEQ { AlgId{sha1,NULL}, issuerNameHash OCTET(20), issuerKeyHash OCTET(20), serial INT }
  // (the evaluator only reads the serial from certID; the two hashes are not
  // checked, so fixed 20-byte fillers are fine.)
  var hashAlg = asn1.writeSequence([asn1.writeOid("1.3.14.3.2.26"), asn1.writeNull()]);  // sha1
  var nameHash = asn1.writeOctetString(Buffer.alloc(20, 0xaa));
  var keyHash  = asn1.writeOctetString(Buffer.alloc(20, 0xbb));
  var certId = asn1.writeSequence([hashAlg, nameHash, keyHash, asn1.writeInteger(serial)]);

  // certStatus good = [0] IMPLICIT NULL (empty primitive context tag).
  var certStatusGood = asn1.writeContextImplicit(0, Buffer.alloc(0));

  // SingleResponse = SEQ { certID, certStatus, thisUpdate, [0] EXPLICIT nextUpdate }
  var singleResponseChildren = [
    certId,
    certStatusGood,
    _genTime(opts.thisUpdateMs),
  ];
  if (typeof opts.nextUpdateMs === "number") {
    singleResponseChildren.push(asn1.writeContextExplicit(0, _genTime(opts.nextUpdateMs)));
  }
  var singleResponse = asn1.writeSequence(singleResponseChildren);

  // ResponseData (tbs) = SEQ { responderID [2] EXPLICIT KeyHash, producedAt, responses SEQ-OF }
  var responderId = asn1.writeContextExplicit(2, asn1.writeOctetString(Buffer.alloc(20, 0xcc)));
  var producedAt  = _genTime(FIXED_NOW);
  var responses   = asn1.writeSequence([singleResponse]);
  var tbs = asn1.writeSequence([responderId, producedAt, responses]);

  // Sign the tbsResponseData DER (header + value) — exactly the bytes the
  // verifier slices and checks. node emits a DER ECDSA-Sig-Value, which the
  // verifier accepts for OID 1.2.840.10045.4.3.2.
  var sig = nodeCrypto.sign("sha256", tbs, kp.privateKey);

  var sigAlg = asn1.writeSequence([asn1.writeOid("1.2.840.10045.4.3.2")]);  // ecdsa-with-SHA256
  var basic = asn1.writeSequence([tbs, sigAlg, asn1.writeBitString(sig)]);

  // responseBytes [0] EXPLICIT SEQ { id-pkix-ocsp-basic, OCTET(basic) }
  var responseBytesInner = asn1.writeSequence([
    asn1.writeOid("1.3.6.1.5.5.7.48.1.1"),
    asn1.writeOctetString(basic),
  ]);
  var responseBytes = asn1.writeContextExplicit(0, responseBytesInner);

  // OCSPResponse = SEQ { responseStatus ENUMERATED(0 successful), responseBytes }
  var responseStatus = asn1.writeNode(0x0a, Buffer.from([0]));
  var der = asn1.writeSequence([responseStatus, responseBytes]);

  return { der: der, issuerPem: issuerPem, serialHex: serialHex };
}

// A STALE response (nextUpdate well in the past) MUST be rejected — and for
// the STALE reason, not the misleading "missing thisUpdate" the dead gate
// produced. RED before the fix: ok:false but errors=["...missing thisUpdate..."].
function testRejectsStaleResponse() {
  var fx = _buildSignedOcsp({
    thisUpdateMs: FIXED_NOW - 3 * 86400000,   // 3 days ago
    nextUpdateMs: FIXED_NOW - 2 * 86400000,   // 2 days ago → STALE
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("stale: rejected (ok=false)", rv.ok === false);
  check("stale: signature still verified (proves we reached the freshness gate)",
        rv.signatureValid === true);
  var errs = (rv.errors || []).join(" ; ");
  check("stale: rejected for the STALE reason, not 'missing thisUpdate'",
        /nextUpdate|stale/i.test(errs) && !/missing thisUpdate/i.test(errs));
}

// A FRESH response (thisUpdate just past, nextUpdate in the future) MUST be
// accepted. RED before the fix: rejected as "missing thisUpdate" (the bug
// cannot distinguish fresh from stale — both wrongly ok:false).
function testAcceptsFreshResponse() {
  var fx = _buildSignedOcsp({
    thisUpdateMs: FIXED_NOW - 3600000,        // 1 hour ago
    nextUpdateMs: FIXED_NOW + 86400000,       // +1 day → FRESH
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("fresh: accepted (ok=true)", rv.ok === true);
  check("fresh: certStatus good", rv.certStatus === "good");
  check("fresh: signature verified", rv.signatureValid === true);
  check("fresh: no errors", Array.isArray(rv.errors) && rv.errors.length === 0);
}

// A FUTURE-dated thisUpdate (clock skew / replay) MUST be rejected for the
// future reason — proves the future-window check is live, not dead.
function testRejectsFutureThisUpdate() {
  var fx = _buildSignedOcsp({
    thisUpdateMs: FIXED_NOW + 2 * 86400000,   // 2 days in the future
    nextUpdateMs: FIXED_NOW + 3 * 86400000,
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("future: rejected (ok=false)", rv.ok === false);
  check("future: rejected for the FUTURE reason",
        /future/i.test((rv.errors || []).join(" ; ")));
}

// A fresh response with NO nextUpdate (optional field absent) MUST be
// accepted — guards the typeof-guard's null→NaN handling of the optional
// nextUpdate branch.
function testAcceptsFreshNoNextUpdate() {
  var fx = _buildSignedOcsp({
    thisUpdateMs: FIXED_NOW - 3600000,        // 1 hour ago, no nextUpdate
  });
  var rv = b.network.tls.ocsp.evaluate(fx.der, {
    issuerPem: fx.issuerPem, serialHex: fx.serialHex, now: FIXED_NOW,
  });
  check("no-nextUpdate fresh: accepted (ok=true)", rv.ok === true);
  check("no-nextUpdate fresh: certStatus good", rv.certStatus === "good");
}

async function run() {
  testRejectsStaleResponse();
  testAcceptsFreshResponse();
  testRejectsFutureThisUpdate();
  testAcceptsFreshNoNextUpdate();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

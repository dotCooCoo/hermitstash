// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.httpSig — RFC 9421 HTTP Message Signatures.
 *
 * sign + verify round-trip across both supported algorithms (ed25519
 * + ml-dsa-65), content-digest auto-emission + tamper-rejection,
 * derived-component coverage, expired/future skew refusal,
 * unknown-keyid + unsupported-alg refusal.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var nodeCrypto = require("crypto");

function _genEd25519() {
  return nodeCrypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function _genMlDsa65() {
  return nodeCrypto.generateKeyPairSync("ml-dsa-65", {
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

function testSurface() {
  check("crypto.httpSig namespace exposed",
        b.crypto.httpSig && typeof b.crypto.httpSig === "object");
  check("crypto.httpSig.sign is a function",
        typeof b.crypto.httpSig.sign === "function");
  check("crypto.httpSig.verify is a function",
        typeof b.crypto.httpSig.verify === "function");
  check("crypto.httpSig.contentDigest is a function",
        typeof b.crypto.httpSig.contentDigest === "function");
  check("SUPPORTED_ALGS includes ed25519 + ml-dsa-65",
        b.crypto.httpSig.SUPPORTED_ALGS.indexOf("ed25519") !== -1 &&
        b.crypto.httpSig.SUPPORTED_ALGS.indexOf("ml-dsa-65") !== -1);
  check("RSA / ECDSA / HMAC are NOT exposed",
        b.crypto.httpSig.SUPPORTED_ALGS.indexOf("rsa-pss-sha512") === -1 &&
        b.crypto.httpSig.SUPPORTED_ALGS.indexOf("ecdsa-p256-sha256") === -1 &&
        b.crypto.httpSig.SUPPORTED_ALGS.indexOf("hmac-sha256") === -1);
}

function testRoundTripEd25519() {
  var keys = _genEd25519();
  var msg = {
    method:  "POST",
    url:     "https://api.example.com/orders?ref=abc",
    headers: { host: "api.example.com", "content-type": "application/json" },
    body:    '{"amount":100}',
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid:      "k1",
    alg:        "ed25519",
    privateKey: keys.privateKey,
    covered:    ["@method", "@target-uri", "@authority", "content-digest"],
  });
  check("sign emits Signature-Input + Signature + Content-Digest",
        signed.headers["Signature-Input"] && signed.headers["Signature"] &&
        signed.headers["Content-Digest"]);

  var verified = b.crypto.httpSig.verify(
    Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) }),
    { keyResolver: function () { return keys.publicKey; } }
  );
  check("ed25519 round-trip verifies", verified.valid === true);
  check("verify reports correct keyid + alg",
        verified.keyid === "k1" && verified.alg === "ed25519");
}

function testRoundTripMlDsa65() {
  var keys = _genMlDsa65();
  var msg = {
    method:  "GET",
    url:     "https://api.example.com/profile",
    headers: { host: "api.example.com" },
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid:      "k-pqc",
    alg:        "ml-dsa-65",
    privateKey: keys.privateKey,
    covered:    ["@method", "@target-uri", "@authority"],
  });
  var verified = b.crypto.httpSig.verify(
    Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) }),
    { keyResolver: function () { return keys.publicKey; } }
  );
  check("ml-dsa-65 round-trip verifies", verified.valid === true);
  check("verify reports ml-dsa-65 alg",  verified.alg === "ml-dsa-65");
}

function testContentDigestTamper() {
  var keys = _genEd25519();
  var msg = {
    method:  "POST",
    url:     "https://api.example.com/x",
    headers: { host: "api.example.com" },
    body:    "original-body",
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid:      "k1",
    alg:        "ed25519",
    privateKey: keys.privateKey,
    covered:    ["@method", "@target-uri", "content-digest"],
  });
  var tamperedMsg = Object.assign({}, msg, {
    body:    "tampered-body",
    headers: Object.assign({}, msg.headers, signed.headers),
  });
  var verified = b.crypto.httpSig.verify(tamperedMsg, {
    keyResolver: function () { return keys.publicKey; },
  });
  check("tampered body refuses content-digest verify",
        verified.valid === false &&
        verified.reason === "content-digest-mismatch");
}

// v0.15.12 (#178) — the content-digest check was rewritten from an unanchored
// substring `indexOf` (+ dead identity-replace) to a top-level-member parse
// with a constant-time compare. The signature already binds the Content-Digest
// header (covered component), so the substring case is not reachable via the
// consumer path — this guards that the refactor still ACCEPTS a valid sha3-512
// member (no over-tightening) while testContentDigestTamper guards the reject.
function testContentDigestMemberAnchored() {
  var keys = _genEd25519();
  var msg = {
    method:  "POST",
    url:     "https://api.example.com/x",
    headers: { host: "api.example.com" },
    body:    "member-anchored-body",
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid:      "k1",
    alg:        "ed25519",
    privateKey: keys.privateKey,
    covered:    ["@method", "@target-uri", "content-digest"],
  });
  check("#178 a valid sha3-512 content-digest member parses + matches",
        /^sha3-512=:/.test(signed.headers["Content-Digest"]));
  var verifyMsg = Object.assign({}, msg, {
    headers: Object.assign({}, msg.headers, signed.headers),
  });
  var verified = b.crypto.httpSig.verify(verifyMsg, {
    keyResolver: function () { return keys.publicKey; },
  });
  check("#178 member-anchored content-digest verify still accepts the valid member",
        verified.valid === true);
}

function testExpired() {
  var keys = _genEd25519();
  var msg = {
    method:  "GET",
    url:     "https://api.example.com/x",
    headers: { host: "api.example.com" },
  };
  var oldTs = Math.floor(Date.now() / 1000) - 60 * 60;     // 1 hour ago
  var signed = b.crypto.httpSig.sign(msg, {
    keyid:      "k1",
    alg:        "ed25519",
    privateKey: keys.privateKey,
    covered:    ["@method", "@target-uri"],
    created:    oldTs,
  });
  var verified = b.crypto.httpSig.verify(
    Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) }),
    {
      keyResolver: function () { return keys.publicKey; },
      toleranceMs: b.constants.TIME.minutes(5),
    }
  );
  check("expired signature refuses verify",
        verified.valid === false && verified.reason === "expired");
}

function testNonFiniteToleranceDoesNotDisableFreshness() {
  // A non-finite toleranceMs (Infinity / NaN) must not disable the freshness
  // window: `ageMs > Infinity` is always false, so a stale (replayed) signature
  // would verify. A malformed tolerance falls back to the default instead. RED
  // before the guard: the hour-old signature verifies.
  var keys = _genEd25519();
  var msg = { method: "GET", url: "https://api.example.com/x", headers: { host: "api.example.com" } };
  var oldTs = Math.floor(Date.now() / 1000) - 60 * 60;     // 1 hour ago
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri"], created: oldTs,
  });
  var vmsg = Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) });
  var bad = [Infinity, NaN, -1];
  for (var i = 0; i < bad.length; i++) {
    var v = b.crypto.httpSig.verify(vmsg, {
      keyResolver: function () { return keys.publicKey; },
      toleranceMs: bad[i],
    });
    check("httpSig: non-finite/negative toleranceMs (" + String(bad[i]) + ") falls back, stale signature still 'expired'",
          v.valid === false && v.reason === "expired");
  }
}

function testUnknownKeyid() {
  var keys = _genEd25519();
  var msg = {
    method:  "GET",
    url:     "https://api.example.com/x",
    headers: { host: "api.example.com" },
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid:      "k1", alg: "ed25519",
    privateKey: keys.privateKey,
    covered:    ["@method", "@target-uri"],
  });
  var verified = b.crypto.httpSig.verify(
    Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) }),
    { keyResolver: function () { return null; } }
  );
  check("unknown keyid refuses verify",
        verified.valid === false && verified.reason === "unknown-keyid");
}

function testValidation() {
  var keys = _genEd25519();
  var msg = { method: "GET", url: "https://x", headers: {} };
  var t1 = null;
  try {
    b.crypto.httpSig.sign(msg, { keyid: "k", alg: "rsa-pss-sha512", privateKey: keys.privateKey, covered: ["@method"] });
  } catch (e) { t1 = e; }
  check("unsupported alg throws", t1 && t1.code === "BAD_OPT");

  var t2 = null;
  try {
    b.crypto.httpSig.sign(msg, { alg: "ed25519", privateKey: keys.privateKey, covered: ["@method"] });
  } catch (e) { t2 = e; }
  check("missing keyid throws", t2 && t2.code === "BAD_OPT");

  var t3 = null;
  try {
    b.crypto.httpSig.sign(msg, { keyid: "k", alg: "ed25519", privateKey: keys.privateKey, covered: [] });
  } catch (e) { t3 = e; }
  check("empty covered throws", t3 && t3.code === "BAD_OPT");
}

function testQueryParam() {
  var keys = _genEd25519();
  var msg = {
    method:  "GET",
    url:     "https://api.example.com/x?ref=alpha&id=42",
    headers: { host: "api.example.com" },
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@query-param;name=\"ref\""],
  });
  var verified = b.crypto.httpSig.verify(
    Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) }),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] }
  );
  check("query-param coverage round-trips",
        verified.valid === true);
}

// Helper: pull the raw base64 signature out of a `label=:base64:` Signature header.
function _sigBytes(sigHeader) {
  var m = /:([A-Za-z0-9+/=]+):/.exec(sigHeader);
  return Buffer.from(m[1], "base64");
}

// RFC 9421 §2.2.8 — a @query-param name/value is canonicalized by decoding
// (application/x-www-form-urlencoded parse: "+"->space, %XX->byte) then
// re-encoding, so a "+"-encoded space on the wire becomes %20 in the signature
// base (the RFC's own worked example: bar=with+plus+whitespace ->
// with%20plus%20whitespace). The framework must SIGN that canonical value, or
// its signatures do not interoperate with a conformant peer. We rebuild the
// canonical base from the framework's OWN emitted Signature-Input terminator
// (so param order / label are exact) and assert the emitted signature verifies
// over it. Pre-fix the framework signed the raw value "with+plus+whitespace",
// so this canonical base fails to verify (RED).
function testQueryParamValueCanonicalizedToPercent20() {
  var keys = _genEd25519();
  var created = Math.floor(Date.now() / 1000);
  var msg = {
    method:  "GET",
    url:     "https://api.example.com/p?bar=with+plus+whitespace",
    headers: { host: "api.example.com" },
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@query-param;name=\"bar\""], created: created,
  });
  // Terminator = the Signature-Input value after the label (RFC 9421 §2.5).
  var sigInput = signed.headers["Signature-Input"];
  var afterLabel = sigInput.slice(sigInput.indexOf("=") + 1);
  var canonicalBase =
    "\"@method\": GET\n" +
    "\"@query-param\";name=\"bar\": with%20plus%20whitespace\n" +
    "\"@signature-params\": " + afterLabel;
  var ok = nodeCrypto.verify(null, Buffer.from(canonicalBase, "utf8"),
    keys.publicKey, _sigBytes(signed.headers["Signature"]));
  check("sign covers the %20-canonical @query-param value (not the raw + form)", ok === true);

  // And the self-round-trip still verifies (sign + verify share the resolver).
  var verified = b.crypto.httpSig.verify(
    Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) }),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("the +-encoded @query-param message round-trips", verified.valid === true);
}

// The emitted component identifier name must be the canonical percent-encoded
// form (RFC 9421 §2.2.8), so it is deterministic across peers and never carries
// a literal space. An operator passing the decoded name "my key" must yield
// ;name="my%20key" in Signature-Input. Pre-fix it emitted ;name="my key"
// (a literal space the verifier then could not parse).
function testQueryParamEmittedNameCanonicalized() {
  var keys = _genEd25519();
  var msg = {
    method:  "GET",
    url:     "https://api.example.com/p?my%20key=value",
    headers: { host: "api.example.com" },
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@query-param;name=\"my key\""],
  });
  check("emitted Signature-Input carries the canonical ;name=\"my%20key\"",
        /;name="my%20key"/.test(signed.headers["Signature-Input"]) &&
        !/;name="my key"/.test(signed.headers["Signature-Input"]));
  var verified = b.crypto.httpSig.verify(
    Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) }),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("a whitespace query-param name round-trips after canonicalization",
        verified.valid === true);
}

// A conformant external peer signs the RFC-canonical base; the framework's
// verify must rebuild the identical base and accept it. This is the true
// interop check (a self-round-trip cannot catch a shared sign/verify bug).
// Covers hex-case normalization (%2f -> %2F) and an encoded "&" surviving.
function testQueryParamVerifiesConformantPeer() {
  var keys = _genEd25519();
  var created = Math.floor(Date.now() / 1000);
  var msg = {
    method:  "POST",
    url:     "https://api.example.com/p?path=a%2fb&amp=x%26y",
    headers: { host: "api.example.com" },
  };
  var params = ";created=" + created + ";alg=\"ed25519\";keyid=\"k1\"";
  var covered = "(\"@query-param\";name=\"path\" \"@query-param\";name=\"amp\")";
  var canonicalBase =
    "\"@query-param\";name=\"path\": a%2Fb\n" +              // %2f -> %2F
    "\"@query-param\";name=\"amp\": x%26y\n" +               // encoded & survives
    "\"@signature-params\": " + covered + params;
  var sig = nodeCrypto.sign(null, Buffer.from(canonicalBase, "utf8"), keys.privateKey);
  var full = Object.assign({}, msg, { headers: Object.assign({}, msg.headers, {
    "Signature-Input": "sig1=" + covered + params,
    "Signature":       "sig1=:" + sig.toString("base64") + ":",
  }) });
  var verified = b.crypto.httpSig.verify(full, { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("verify accepts a conformant peer's canonical @query-param base (hex-case + encoded &)",
        verified.valid === true);
}

// The RFC 9421 §2.2.8 published worked example (request 2) — the authoritative
// interop vectors. The framework's signature base for these three @query-param
// components must equal the RFC's "resulting values" byte-for-byte: a
// "+"-encoded space -> %20, multi-space/newline values stay %-encoded, and a
// name with UTF-8 + reserved chars round-trips through its percent-encoded form.
function testQueryParamRfc9421PublishedVectors() {
  var keys = _genEd25519();
  var created = Math.floor(Date.now() / 1000);
  var msg = {
    method: "GET",
    url: "https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value" +
         "&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something",
    headers: { host: "example.com" },
  };
  var covered = [
    "@query-param;name=\"var\"",
    "@query-param;name=\"bar\"",
    "@query-param;name=\"fa%C3%A7ade%22%3A%20\"",
  ];
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey, covered: covered, created: created,
  });
  var sigInput = signed.headers["Signature-Input"];
  var afterLabel = sigInput.slice(sigInput.indexOf("=") + 1);
  var canonicalBase =
    "\"@query-param\";name=\"var\": this%20is%20a%20big%0Amultiline%20value\n" +
    "\"@query-param\";name=\"bar\": with%20plus%20whitespace\n" +
    "\"@query-param\";name=\"fa%C3%A7ade%22%3A%20\": something\n" +
    "\"@signature-params\": " + afterLabel;
  var ok = nodeCrypto.verify(null, Buffer.from(canonicalBase, "utf8"),
    keys.publicKey, _sigBytes(signed.headers["Signature"]));
  check("sign matches the RFC 9421 §2.2.8 published @query-param base vectors", ok === true);
}

// A decoded @query-param name containing a literal form delimiter ('&' or a
// '+') must canonicalize to its percent-encoded form, NOT be split by the
// form parser. With a colliding bare 'a' parameter present, mis-splitting
// "a&b" to "a" would sign the WRONG parameter's value. The canonical name for
// a param on the wire as a%26b is name="a%26b".
function testQueryParamDecodedNameWithDelimiter() {
  var keys = _genEd25519();
  var msg = {
    method:  "GET",
    url:     "https://api.example.com/p?a%26b=right&a=wrong",
    headers: { host: "api.example.com" },
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@query-param;name=\"a&b\""],   // decoded name with a literal &
  });
  check("decoded name with '&' canonicalizes to %26 (not split to \"a\")",
        /;name="a%26b"/.test(signed.headers["Signature-Input"]) &&
        !/;name="a"/.test(signed.headers["Signature-Input"]));
  var verified = b.crypto.httpSig.verify(
    Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) }),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("decoded-name-with-& message round-trips (covers a%26b, not a)",
        verified.valid === true);
}

// RFC 9421 §3.2 — the verifier MUST refuse a signature that does not cover the
// components the application requires. Pre-fix, verify() built the signature
// base solely from the attacker-supplied Signature-Input covered set and never
// checked coverage, so an @authority-only signature was accepted after the
// method / target-uri / body were changed (the verifier acts on a request whose
// security-relevant parts were never signed). This pins both the explicit
// requiredComponents refusal AND the body-aware secure default.
function testRequiredComponentsCoverage() {
  var keys = _genEd25519();

  // (a) Under-covered signature: covers ONLY @authority.
  var underMsg = {
    method:  "GET",
    url:     "https://api.example.com/x?ref=abc",
    headers: { host: "api.example.com" },
  };
  var underSigned = b.crypto.httpSig.sign(underMsg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@authority"],
  });
  var underHeaders = Object.assign({}, underMsg.headers, underSigned.headers);

  // Explicit requiredComponents → REFUSED (the signature is cryptographically
  // valid, but @method / @target-uri are not covered). RED on the pre-fix tree:
  // requiredComponents was ignored, so this returned { valid: true }.
  var refusedExplicit = b.crypto.httpSig.verify(
    Object.assign({}, underMsg, { headers: underHeaders }),
    { keyResolver: function () { return keys.publicKey; },
      requiredComponents: ["@method", "@target-uri"] });
  check("under-covered signature refused when requiredComponents demands @method/@target-uri",
        refusedExplicit.valid === false && refusedExplicit.reason === "missing-required-component");

  // The secure DEFAULT (no requiredComponents passed) also refuses it —
  // coverage enforcement is on by default, not opt-in.
  var refusedDefault = b.crypto.httpSig.verify(
    Object.assign({}, underMsg, { headers: underHeaders }),
    { keyResolver: function () { return keys.publicKey; } });
  check("under-covered signature refused by the secure default (@method/@target-uri required)",
        refusedDefault.valid === false && refusedDefault.reason === "missing-required-component");

  // The captured @authority-only signature replayed across a DIFFERENT method +
  // path is refused (the concrete attack the finding pins).
  var replay = b.crypto.httpSig.verify(
    { method: "DELETE", url: "https://api.example.com/admin/delete-all",
      headers: Object.assign({ host: "api.example.com" }, underSigned.headers) },
    { keyResolver: function () { return keys.publicKey; } });
  check("replay of @authority-only signature across method+path is refused",
        replay.valid === false && replay.reason === "missing-required-component");

  // (b) Positive control — a fully-covered signature still verifies, both under
  // the explicit required set and under the secure default (no over-tightening).
  var fullMsg = {
    method:  "POST",
    url:     "https://api.example.com/orders",
    headers: { host: "api.example.com" },
    body:    '{"amount":1}',
  };
  var fullSigned = b.crypto.httpSig.sign(fullMsg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri", "@authority", "content-digest"],
  });
  var fullHeaders = Object.assign({}, fullMsg.headers, fullSigned.headers);
  var okExplicit = b.crypto.httpSig.verify(
    Object.assign({}, fullMsg, { headers: fullHeaders }),
    { keyResolver: function () { return keys.publicKey; },
      requiredComponents: ["@method", "@target-uri"] });
  check("fully-covered signature verifies under explicit requiredComponents", okExplicit.valid === true);
  var okDefault = b.crypto.httpSig.verify(
    Object.assign({}, fullMsg, { headers: fullHeaders }),
    { keyResolver: function () { return keys.publicKey; } });
  check("fully-covered bodied signature verifies under the secure default (incl. content-digest)",
        okDefault.valid === true);

  // (c) Body-aware rule: a bodied request whose signer omitted content-digest is
  // refused by the default; requiredComponents:[] waives the floor (audited
  // escape hatch — the signature itself is still verified).
  var noDigest = b.crypto.httpSig.sign(fullMsg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri", "@authority"],   // content-digest omitted
  });
  var noDigestHeaders = Object.assign({}, fullMsg.headers, noDigest.headers);
  var refusedNoDigest = b.crypto.httpSig.verify(
    Object.assign({}, fullMsg, { headers: noDigestHeaders }),
    { keyResolver: function () { return keys.publicKey; } });
  check("bodied request without content-digest coverage refused by default",
        refusedNoDigest.valid === false && refusedNoDigest.reason === "missing-required-component");
  var waived = b.crypto.httpSig.verify(
    Object.assign({}, fullMsg, { headers: noDigestHeaders }),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("requiredComponents:[] waives the coverage floor (signature itself still verifies)",
        waived.valid === true);

  // (d) Parameterized components match WITH their parameters: a required
  // @query-param;name="tenant" is NOT satisfied by a covered ;name="other"
  // (the required-coverage check must not truncate the parameter suffix).
  var paramMsg = {
    method:  "GET",
    url:     "https://api.example.com/x?tenant=acme&other=z",
    headers: { host: "api.example.com" },
  };
  var paramSigned = b.crypto.httpSig.sign(paramMsg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri", "@query-param;name=\"other\""],
  });
  var paramHeaders = Object.assign({}, paramMsg.headers, paramSigned.headers);
  var wrongParam = b.crypto.httpSig.verify(
    Object.assign({}, paramMsg, { headers: paramHeaders }),
    { keyResolver: function () { return keys.publicKey; },
      requiredComponents: ["@method", "@target-uri", "@query-param;name=\"tenant\""] });
  check("a required @query-param;name=\"tenant\" is NOT satisfied by a covered ;name=\"other\"",
        wrongParam.valid === false && wrongParam.reason === "missing-required-component");
  var rightParam = b.crypto.httpSig.verify(
    Object.assign({}, paramMsg, { headers: paramHeaders }),
    { keyResolver: function () { return keys.publicKey; },
      requiredComponents: ["@method", "@target-uri", "@query-param;name=\"other\""] });
  check("a required @query-param is satisfied when the covered param matches exactly",
        rightParam.valid === true);
}

async function run() {
  testSurface();
  testRoundTripEd25519();
  testRoundTripMlDsa65();
  testContentDigestTamper();
  testContentDigestMemberAnchored();
  testExpired();
  testNonFiniteToleranceDoesNotDisableFreshness();
  testUnknownKeyid();
  testValidation();
  testQueryParam();
  testQueryParamValueCanonicalizedToPercent20();
  testQueryParamEmittedNameCanonicalized();
  testQueryParamVerifiesConformantPeer();
  testQueryParamRfc9421PublishedVectors();
  testQueryParamDecodedNameWithDelimiter();
  testRequiredComponentsCoverage();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

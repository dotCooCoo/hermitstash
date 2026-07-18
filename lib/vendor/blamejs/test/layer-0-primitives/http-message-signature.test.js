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

// Shared fixtures for the branch-coverage suite below. Every test drives the
// exported b.crypto.httpSig.{sign,verify,contentDigest} consumer path; nothing
// reaches for a private function.
function _reqBase(extra) {
  return Object.assign({
    method:  "GET",
    url:     "https://api.example.com/x",
    headers: { host: "api.example.com" },
  }, extra || {});
}
function _withSig(msg, signed) {
  return Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) });
}

// _sfQuotedString refuses any parameter byte outside printable-ASCII
// (RFC 8941 §3.3.3): a control byte in a signature parameter (here `nonce`)
// makes sign() throw BAD_PARAM rather than emit a header that would mis-parse
// on the wire. Constructed via fromCharCode so no literal control byte lands
// in the test source.
function testNonPrintableParamRejected() {
  var keys = _genEd25519();
  var ctl = String.fromCharCode(1);
  var err = null;
  try {
    b.crypto.httpSig.sign(_reqBase(), {
      keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
      covered: ["@method", "@target-uri"], nonce: "bad" + ctl + "nonce",
    });
  } catch (e) { err = e; }
  check("sign refuses a control byte in a signature parameter (BAD_PARAM)",
        err && err.code === "BAD_PARAM");
}

// RFC 9421 §2.2 derived components — @scheme / @request-target / @path /
// @query / @authority all resolve into the signature base and round-trip.
// @status (a response component) resolves from a numeric status; covering it
// with no status throws MISSING_STATUS; an unknown @-component throws
// UNKNOWN_DERIVED.
function testDerivedComponents() {
  var keys = _genEd25519();
  var msg = {
    method:  "GET",
    url:     "https://api.example.com/a/b?q=1",
    headers: { host: "api.example.com" },
  };
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@scheme", "@authority", "@request-target", "@path", "@query"],
  });
  var verified = b.crypto.httpSig.verify(_withSig(msg, signed),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("all §2.2 derived components (@scheme/@authority/@request-target/@path/@query) round-trip",
        verified.valid === true);

  // @status resolves from a numeric status (response-style message).
  var respMsg = {
    method:  "GET",
    url:     "https://api.example.com/a",
    headers: { host: "api.example.com" },
    status:  200,
  };
  var respSigned = b.crypto.httpSig.sign(respMsg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri", "@status"],
  });
  var respVerified = b.crypto.httpSig.verify(_withSig(respMsg, respSigned),
    { keyResolver: function () { return keys.publicKey; } });
  check("@status resolves from a numeric status and round-trips", respVerified.valid === true);

  // A URL with NO query exercises the empty-query branches: @request-target
  // omits the (absent) query, and @query defaults to "?".
  var noQueryMsg = _reqBase({ url: "https://api.example.com/x" });
  var noQuerySigned = b.crypto.httpSig.sign(noQueryMsg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@request-target", "@query"],
  });
  var noQueryVerified = b.crypto.httpSig.verify(_withSig(noQueryMsg, noQuerySigned),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("@request-target/@query on a query-less URL round-trip (@query → '?')",
        noQueryVerified.valid === true);

  // @status covered but message carries no status → MISSING_STATUS.
  var statusErr = null;
  try {
    b.crypto.httpSig.sign(_reqBase(), {
      keyid: "k1", alg: "ed25519", privateKey: keys.privateKey, covered: ["@status"],
    });
  } catch (e) { statusErr = e; }
  check("@status without a numeric status throws MISSING_STATUS",
        statusErr && statusErr.code === "MISSING_STATUS");

  // Unknown @-component → UNKNOWN_DERIVED.
  var derivedErr = null;
  try {
    b.crypto.httpSig.sign(_reqBase(), {
      keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
      covered: ["@method", "@bogus-derived"],
    });
  } catch (e) { derivedErr = e; }
  check("an unknown @-derived component throws UNKNOWN_DERIVED",
        derivedErr && derivedErr.code === "UNKNOWN_DERIVED");
}

// RFC 9421 §2.3 signature parameters — nonce / tag / expires / explicit label
// all serialize into Signature-Input, and an explicit `now` feeds `created`.
// verify surfaces created / expires / nonce on the valid result.
function testSignatureParameters() {
  var keys = _genEd25519();
  var nowMs = Date.now();
  var nowSec = Math.floor(nowMs / 1000);
  var msg = _reqBase();
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri"],
    label:   "custom-label",
    nonce:   "n-0123",
    tag:     "app-a",
    expires: nowSec + 300,
    now:     function () { return nowMs; },
  });
  var si = signed.headers["Signature-Input"];
  check("Signature-Input carries the custom label", si.indexOf("custom-label=") === 0);
  check("Signature-Input serializes nonce + tag + expires + created",
        /;created=/.test(si) && /;expires=/.test(si) &&
        /;nonce="n-0123"/.test(si) && /;tag="app-a"/.test(si));
  var verified = b.crypto.httpSig.verify(_withSig(msg, signed),
    { keyResolver: function () { return keys.publicKey; },
      now: function () { return nowMs; } });
  check("parameterized signature round-trips + surfaces nonce/expires/created",
        verified.valid === true && verified.label === "custom-label" &&
        verified.nonce === "n-0123" && verified.expires === nowSec + 300 &&
        verified.created === nowSec);
}

// @query-param sign-time failure modes (defensive resolution throws at base
// build): no query string at all, the named param absent, and a bare
// @query-param with no ;name parameter.
function testQueryParamSignFailures() {
  var keys = _genEd25519();
  var noQueryErr = null;
  try {
    b.crypto.httpSig.sign(_reqBase(), {
      keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
      covered: ["@query-param;name=\"x\""],
    });
  } catch (e) { noQueryErr = e; }
  check("@query-param on a URL with no query throws MISSING_QUERY",
        noQueryErr && noQueryErr.code === "MISSING_QUERY");

  var absentErr = null;
  try {
    b.crypto.httpSig.sign(_reqBase({ url: "https://api.example.com/x?present=1" }), {
      keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
      covered: ["@query-param;name=\"absent\""],
    });
  } catch (e) { absentErr = e; }
  check("@query-param naming an absent param throws MISSING_QUERY_PARAM",
        absentErr && absentErr.code === "MISSING_QUERY_PARAM");

  var bareErr = null;
  try {
    b.crypto.httpSig.sign(_reqBase({ url: "https://api.example.com/x?present=1" }), {
      keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
      covered: ["@query-param"],
    });
  } catch (e) { bareErr = e; }
  check("a bare @query-param with no ;name parameter throws BAD_QUERY_PARAM",
        bareErr && bareErr.code === "BAD_QUERY_PARAM");
}

// RFC 9421 §2.2.8 — a valueless query member (`?flag&ref=1`) resolves to the
// empty string for its value, matching on the name only (the `eq === -1`
// branches for both the wire name and the returned value).
function testQueryParamValuelessFlag() {
  var keys = _genEd25519();
  var msg = _reqBase({ url: "https://api.example.com/x?flag&ref=1" });
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@query-param;name=\"flag\""],
  });
  var verified = b.crypto.httpSig.verify(_withSig(msg, signed),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("a valueless @query-param flag (name only, empty value) round-trips",
        verified.valid === true);
}

// A covered header that is not present in the message throws MISSING_HEADER at
// base build (sign side).
function testMissingCoveredHeader() {
  var keys = _genEd25519();
  var err = null;
  try {
    b.crypto.httpSig.sign(_reqBase(), {
      keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
      covered: ["@method", "x-absent-header"],
    });
  } catch (e) { err = e; }
  check("covering a header absent from the message throws MISSING_HEADER",
        err && err.code === "MISSING_HEADER");
}

// RFC 9421 §2.1 — a multi-valued header (array) is obs-folded into one
// ", "-joined value in the base, and round-trips on both sides.
function testArrayHeaderValue() {
  var keys = _genEd25519();
  var msg = _reqBase({ headers: { host: "api.example.com", "x-multi": ["a", "b"] } });
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "x-multi"],
  });
  var verified = b.crypto.httpSig.verify(_withSig(msg, signed),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("a multi-valued (array) header obs-folds and round-trips", verified.valid === true);
}

// contentDigest accepts a string or Buffer and refuses any other body type.
function testContentDigestFunction() {
  check("contentDigest(string) returns the sha3-512 structured field",
        /^sha3-512=:.+:$/.test(b.crypto.httpSig.contentDigest("abc")));
  check("contentDigest(Buffer) returns the sha3-512 structured field",
        /^sha3-512=:.+:$/.test(b.crypto.httpSig.contentDigest(Buffer.from("abc"))));
  check("contentDigest of a Buffer equals contentDigest of the equivalent string",
        b.crypto.httpSig.contentDigest(Buffer.from("abc")) ===
        b.crypto.httpSig.contentDigest("abc"));
  var err = null;
  try { b.crypto.httpSig.contentDigest(12345); } catch (e) { err = e; }
  check("contentDigest of a non-string/Buffer body throws BAD_BODY",
        err && err.code === "BAD_BODY");
}

// sign()-side option / message failures: a message with no headers, a covered
// content-digest with no body, and an unparseable private key (SIGN_FAILED).
function testSignFailures() {
  var keys = _genEd25519();
  var headersErr = null;
  try {
    b.crypto.httpSig.sign({ method: "GET", url: "https://api.example.com/x" }, {
      keyid: "k1", alg: "ed25519", privateKey: keys.privateKey, covered: ["@method"],
    });
  } catch (e) { headersErr = e; }
  check("a message with no headers throws BAD_OPT", headersErr && headersErr.code === "BAD_OPT");

  var bodyErr = null;
  try {
    b.crypto.httpSig.sign(_reqBase({ method: "POST", url: "https://api.example.com/o" }), {
      keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
      covered: ["@method", "content-digest"],
    });
  } catch (e) { bodyErr = e; }
  check("covering content-digest with no body throws BAD_OPT",
        bodyErr && bodyErr.code === "BAD_OPT");

  var signErr = null;
  try {
    b.crypto.httpSig.sign(_reqBase(), {
      keyid: "k1", alg: "ed25519", privateKey: "-----BEGIN PRIVATE KEY-----\nnot-real\n-----END PRIVATE KEY-----\n",
      covered: ["@method", "@target-uri"],
    });
  } catch (e) { signErr = e; }
  check("an unparseable private key throws SIGN_FAILED", signErr && signErr.code === "SIGN_FAILED");
}

// verify()-side option / presence gates that return a verdict (never throw,
// except the keyResolver contract): no keyResolver, no Signature-Input, no
// Signature.
function testVerifyPresenceGates() {
  var keys = _genEd25519();
  var signed = b.crypto.httpSig.sign(_reqBase(), {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey, covered: ["@method", "@target-uri"],
  });
  var resolverErr = null;
  try { b.crypto.httpSig.verify(_reqBase(), {}); } catch (e) { resolverErr = e; }
  check("verify without a keyResolver throws BAD_OPT", resolverErr && resolverErr.code === "BAD_OPT");

  // verify with no opts argument at all defaults opts to {} then hits the same
  // keyResolver contract.
  var noOptsErr = null;
  try { b.crypto.httpSig.verify(_reqBase()); } catch (e) { noOptsErr = e; }
  check("verify with no opts argument throws BAD_OPT (opts defaults to {})",
        noOptsErr && noOptsErr.code === "BAD_OPT");

  var noInput = b.crypto.httpSig.verify(_reqBase(),
    { keyResolver: function () { return keys.publicKey; } });
  check("verify with no Signature-Input returns missing-signature-input",
        noInput.valid === false && noInput.reason === "missing-signature-input");

  var onlyInput = b.crypto.httpSig.verify(
    _reqBase({ headers: { host: "api.example.com", "Signature-Input": signed.headers["Signature-Input"] } }),
    { keyResolver: function () { return keys.publicKey; } });
  check("verify with Signature-Input but no Signature returns missing-signature",
        onlyInput.valid === false && onlyInput.reason === "missing-signature");
}

// Malformed Signature-Input header shapes all return the bad-signature-input
// verdict (the _parseSignatureInput throw is caught): missing '=', a covered
// list not starting with '(', a covered list missing ')', and an unterminated
// quoted token.
function testMalformedSignatureInput() {
  var keys = _genEd25519();
  var cases = [
    ["missing '='",            "no-equals-here"],
    ["covered not '('",        "sig1=notparen"],
    ["covered missing ')'",    "sig1=(no-close"],
    ["unterminated quote",     "sig1=(\"@method);alg=\"ed25519\""],
  ];
  for (var i = 0; i < cases.length; i++) {
    var v = b.crypto.httpSig.verify(
      _reqBase({ headers: {
        host: "api.example.com",
        "Signature-Input": cases[i][1],
        "Signature": "sig1=:AAAA:",
      } }),
      { keyResolver: function () { return keys.publicKey; } });
    check("malformed Signature-Input (" + cases[i][0] + ") → bad-signature-input",
          v.valid === false && v.reason === "bad-signature-input");
  }
}

// A forward-compat peer MAY transmit bare (unquoted) covered tokens; the parser
// tolerates them and — because the base re-quotes each bare name — the
// signature still verifies.
function testBareUnquotedCoveredTokens() {
  var keys = _genEd25519();
  var msg = _reqBase();
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey, covered: ["@method", "@target-uri"],
  });
  var bareInput = signed.headers["Signature-Input"]
    .replace("(\"@method\" \"@target-uri\")", "(@method @target-uri)");
  check("the rewrite produced bare unquoted covered tokens",
        /\(@method @target-uri\)/.test(bareInput));
  var verified = b.crypto.httpSig.verify(
    _withSig(msg, { headers: Object.assign({}, signed.headers, { "Signature-Input": bareInput }) }),
    { keyResolver: function () { return keys.publicKey; } });
  check("bare (unquoted) covered tokens still verify (base re-quotes them)",
        verified.valid === true);
}

// parsed-parameter gates: an unsupported alg and a missing/empty keyid each
// return a verdict before any crypto runs.
function testParsedParamGates() {
  var keys = _genEd25519();
  var badAlg = b.crypto.httpSig.verify(
    _reqBase({ headers: {
      host: "api.example.com",
      "Signature-Input": "sig1=(\"@method\");created=1;keyid=\"k1\";alg=\"rsa-pss-sha512\"",
      "Signature": "sig1=:AAAA:",
    } }),
    { keyResolver: function () { return keys.publicKey; } });
  check("an unsupported alg in Signature-Input → unsupported-alg",
        badAlg.valid === false && badAlg.reason === "unsupported-alg");

  var noKeyid = b.crypto.httpSig.verify(
    _reqBase({ headers: {
      host: "api.example.com",
      "Signature-Input": "sig1=(\"@method\");created=1;alg=\"ed25519\"",
      "Signature": "sig1=:AAAA:",
    } }),
    { keyResolver: function () { return keys.publicKey; } });
  check("a Signature-Input with no keyid → missing-keyid",
        noKeyid.valid === false && noKeyid.reason === "missing-keyid");
}

// RFC 9421 §3.2.4 — a future-dated `created` beyond the clock-skew window is
// refused (`future`), and an already-passed `expires` is refused
// (`expires-passed`); a malformed clockSkewMs falls back to the default window.
function testTimeGates() {
  var keys = _genEd25519();
  var nowSec = Math.floor(Date.now() / 1000);

  var futureSigned = b.crypto.httpSig.sign(_reqBase(), {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri"], created: nowSec + 3600,
  });
  var future = b.crypto.httpSig.verify(_withSig(_reqBase(), futureSigned),
    { keyResolver: function () { return keys.publicKey; } });
  check("a far-future created is refused (future)",
        future.valid === false && future.reason === "future");

  var expiredSigned = b.crypto.httpSig.sign(_reqBase(), {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri"], created: nowSec, expires: nowSec - 10,
  });
  var expires = b.crypto.httpSig.verify(_withSig(_reqBase(), expiredSigned),
    { keyResolver: function () { return keys.publicKey; } });
  check("an already-passed expires is refused (expires-passed)",
        expires.valid === false && expires.reason === "expires-passed");

  // A near-future created (within the default skew) verifies even when a
  // malformed clockSkewMs is supplied (it falls back to the default window).
  var nearSigned = b.crypto.httpSig.sign(_reqBase(), {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri"], created: nowSec + 2,
  });
  var near = b.crypto.httpSig.verify(_withSig(_reqBase(), nearSigned),
    { keyResolver: function () { return keys.publicKey; }, clockSkewMs: NaN });
  check("a malformed clockSkewMs falls back to the default skew (near-future accepted)",
        near.valid === true);

  // An explicit, valid clockSkewMs is honored: a signature ~5 minutes in the
  // future is refused under a tight 1-minute skew but accepted under a 10-minute
  // skew.
  var aheadSigned = b.crypto.httpSig.sign(_reqBase(), {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri"], created: nowSec + 300,
  });
  var tightSkew = b.crypto.httpSig.verify(_withSig(_reqBase(), aheadSigned),
    { keyResolver: function () { return keys.publicKey; },
      clockSkewMs: b.constants.TIME.minutes(1) });
  check("a 5-min-future signature is refused under a tight explicit clockSkewMs",
        tightSkew.valid === false && tightSkew.reason === "future");
  var wideSkew = b.crypto.httpSig.verify(_withSig(_reqBase(), aheadSigned),
    { keyResolver: function () { return keys.publicKey; },
      clockSkewMs: b.constants.TIME.minutes(10) });
  check("the same 5-min-future signature is accepted under a wide explicit clockSkewMs",
        wideSkew.valid === true);
}

// A keyResolver that throws is caught and reported (key-resolver-threw), never
// propagated out of verify.
function testKeyResolverThrows() {
  var keys = _genEd25519();
  var signed = b.crypto.httpSig.sign(_reqBase(), {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey, covered: ["@method", "@target-uri"],
  });
  var v = b.crypto.httpSig.verify(_withSig(_reqBase(), signed),
    { keyResolver: function () { throw new Error("resolver down"); } });
  check("a throwing keyResolver is caught and reported (key-resolver-threw)",
        v.valid === false && v.reason === "key-resolver-threw");
}

// verify-side content-digest branches: covered but no body
// (content-digest-no-body), covered with body but the header stripped
// (content-digest-header-missing), and a multi-member Content-Digest whose
// sha3-512 member matches after skipping a malformed and a non-sha3-512 member.
function testContentDigestVerifyBranches() {
  var keys = _genEd25519();
  var wb = {
    method: "POST", url: "https://api.example.com/o",
    headers: { host: "api.example.com" }, body: "B",
  };
  var cdSigned = b.crypto.httpSig.sign(wb, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri", "content-digest"],
  });

  // Body dropped at verify → content-digest-no-body (covered set still names it).
  var noBody = b.crypto.httpSig.verify(
    { method: "POST", url: "https://api.example.com/o",
      headers: Object.assign({}, wb.headers, cdSigned.headers) },
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("content-digest covered but the verified message has no body → content-digest-no-body",
        noBody.valid === false && noBody.reason === "content-digest-no-body");

  // Body present but the Content-Digest header stripped → header-missing.
  var strippedHeaders = Object.assign({}, wb.headers, cdSigned.headers);
  delete strippedHeaders["Content-Digest"];
  var headerMissing = b.crypto.httpSig.verify(
    { method: "POST", url: "https://api.example.com/o", headers: strippedHeaders, body: "B" },
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("content-digest covered, body present, header stripped → content-digest-header-missing",
        headerMissing.valid === false && headerMissing.reason === "content-digest-header-missing");

  // A multi-member Content-Digest (malformed member + a non-sha3-512 member +
  // the real sha3-512 member) supplied at BOTH sign and verify verifies: the
  // parser skips the first two members and matches the sha3-512 one.
  var realDigest = b.crypto.httpSig.contentDigest("B");
  var multiHeader = "malformedmember, sha-256=:AAAA:, " + realDigest;
  var multiMsg = {
    method: "POST", url: "https://api.example.com/o",
    headers: { host: "api.example.com", "content-digest": multiHeader }, body: "B",
  };
  var multiSigned = b.crypto.httpSig.sign(multiMsg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri", "content-digest"],
  });
  var multi = b.crypto.httpSig.verify(_withSig(multiMsg, multiSigned),
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("a multi-member Content-Digest matches its sha3-512 member (skipping malformed + non-sha3-512)",
        multi.valid === true);
}

// The Signature header may carry multiple comma-separated labels; verify picks
// the one named by Signature-Input's label. A decoy-prefixed header still
// verifies; a header with no matching label returns bad-signature-header.
function testMultiLabelSignature() {
  var keys = _genEd25519();
  var msg = _reqBase();
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey, covered: ["@method", "@target-uri"],
  });
  var decoyHeaders = Object.assign({}, signed.headers,
    { "Signature": "decoy=:AAAA:, " + signed.headers["Signature"] });
  var found = b.crypto.httpSig.verify(_withSig(msg, { headers: decoyHeaders }),
    { keyResolver: function () { return keys.publicKey; } });
  check("verify finds the correct label among comma-separated Signature entries",
        found.valid === true);

  var wrongHeaders = Object.assign({}, signed.headers, { "Signature": "other=:AAAA:" });
  var missing = b.crypto.httpSig.verify(_withSig(msg, { headers: wrongHeaders }),
    { keyResolver: function () { return keys.publicKey; } });
  check("a Signature header with no entry for the label → bad-signature-header",
        missing.valid === false && missing.reason === "bad-signature-header");
}

// The final crypto verdict: a cryptographically-wrong signature (valid key,
// wrong signer) returns bad-signature; a resolver returning a non-key string
// makes node's verify throw, caught as verify-threw.
function testCryptoVerdicts() {
  var keys = _genEd25519();
  var other = _genEd25519();
  var msg = _reqBase();
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey, covered: ["@method", "@target-uri"],
  });
  var wrongKey = b.crypto.httpSig.verify(_withSig(msg, signed),
    { keyResolver: function () { return other.publicKey; } });
  check("a signature checked against the wrong (valid) public key → bad-signature",
        wrongKey.valid === false && wrongKey.reason === "bad-signature");

  var garbageKey = b.crypto.httpSig.verify(_withSig(msg, signed),
    { keyResolver: function () { return "not-a-real-key-pem"; } });
  check("a resolver returning a non-key string makes node's verify throw → verify-threw",
        garbageKey.valid === false && garbageKey.reason === "verify-threw");
}

// If base construction fails at verify (a covered header present at sign but
// stripped before verify), verify returns build-base-failed rather than
// throwing.
function testBuildBaseFailed() {
  var keys = _genEd25519();
  var msg = _reqBase({ headers: { host: "api.example.com", "x-custom": "v" } });
  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey,
    covered: ["@method", "@target-uri", "x-custom"],
  });
  var strippedHeaders = Object.assign({}, msg.headers, signed.headers);
  delete strippedHeaders["x-custom"];
  var v = b.crypto.httpSig.verify(
    { method: "GET", url: "https://api.example.com/x", headers: strippedHeaders },
    { keyResolver: function () { return keys.publicKey; }, requiredComponents: [] });
  check("a covered header stripped before verify → build-base-failed",
        v.valid === false && v.reason === "build-base-failed");
}

// RFC 8941 §3.1.2 parameter parsing tolerance: verify rebuilds the canonical
// @signature-params terminator from the parsed values, so a transmitted
// Signature-Input with a trailing ';' (empty parameter) or an unquoted string
// parameter (a conformant peer's serialization variant) still verifies.
function testSignatureInputParamTolerance() {
  var keys = _genEd25519();
  var msg = _reqBase();

  var signed = b.crypto.httpSig.sign(msg, {
    keyid: "k1", alg: "ed25519", privateKey: keys.privateKey, covered: ["@method", "@target-uri"],
  });
  var trailingInput = signed.headers["Signature-Input"] + ";";
  var trailing = b.crypto.httpSig.verify(
    _withSig(msg, { headers: Object.assign({}, signed.headers, { "Signature-Input": trailingInput }) }),
    { keyResolver: function () { return keys.publicKey; } });
  check("a trailing ';' (empty parameter) in Signature-Input is tolerated and still verifies",
        trailing.valid === true);

  // A conformant peer signs the canonical base (quoted tag) but transmits the
  // tag parameter unquoted — verify parses it as a plain string, rebuilds the
  // canonical (quoted) terminator, and the signature matches.
  var created = Math.floor(Date.now() / 1000);
  var coveredSf = "(\"@method\" \"@target-uri\")";
  var canonicalBase =
    "\"@method\": GET\n" +
    "\"@target-uri\": https://api.example.com/x\n" +
    "\"@signature-params\": " + coveredSf +
    ";created=" + created + ";alg=\"ed25519\";keyid=\"k1\";tag=\"mytag\"";
  var sig = nodeCrypto.sign(null, Buffer.from(canonicalBase, "utf8"), keys.privateKey);
  var unquotedInput = "sig1=" + coveredSf +
    ";created=" + created + ";alg=\"ed25519\";keyid=\"k1\";tag=mytag";   // tag unquoted
  var unquoted = b.crypto.httpSig.verify(
    _withSig(msg, { headers: {
      "Signature-Input": unquotedInput,
      "Signature": "sig1=:" + sig.toString("base64") + ":",
    } }),
    { keyResolver: function () { return keys.publicKey; } });
  check("an unquoted string parameter (tag=mytag) parses as a string and verifies",
        unquoted.valid === true);
}

function testAlgKeyBinding() {
  // Alg-confusion (CWE-347): the declared alg is only an authenticated label
  // unless it is bound to the key's real type. SUPPORTED_ALGS names ARE the
  // node asymmetricKeyType values, so sign() must refuse to emit a mislabeled
  // token and verify() must refuse a key whose type differs from the declared
  // alg -- a classical ed25519 key must never pass under a declared PQC alg.
  var e = _genEd25519();
  var m = _genMlDsa65();
  var msg = {
    method:  "POST",
    url:     "https://api.example.com/x",
    headers: { host: "api.example.com" },
    body:    "{}",
  };
  var cov = ["@method", "@target-uri", "@authority", "content-digest"];

  var signThrew = false;
  try {
    b.crypto.httpSig.sign(msg, { keyid: "k", alg: "ml-dsa-65", privateKey: e.privateKey, covered: cov });
  } catch (err) { signThrew = (err && err.code === "BAD_OPT"); }
  check("httpSig.sign: ed25519 key declared alg=ml-dsa-65 refused (BAD_OPT)", signThrew);

  var signed = b.crypto.httpSig.sign(msg, { keyid: "k", alg: "ed25519", privateKey: e.privateKey, covered: cov });
  var full = Object.assign({}, msg, { headers: Object.assign({}, msg.headers, signed.headers) });
  var mismatch = b.crypto.httpSig.verify(full, { keyResolver: function () { return m.publicKey; } });
  check("httpSig.verify: declared alg != resolved key type refused (alg-key-mismatch)",
        mismatch.valid === false && mismatch.reason === "alg-key-mismatch");

  var okEd = b.crypto.httpSig.verify(full, { keyResolver: function () { return e.publicKey; } });
  check("httpSig: legit ed25519 round-trip still verifies", okEd.valid === true);
  var s2 = b.crypto.httpSig.sign(msg, { keyid: "k2", alg: "ml-dsa-65", privateKey: m.privateKey, covered: cov });
  var f2 = Object.assign({}, msg, { headers: Object.assign({}, msg.headers, s2.headers) });
  var okMl = b.crypto.httpSig.verify(f2, { keyResolver: function () { return m.publicKey; } });
  check("httpSig: legit ml-dsa-65 round-trip still verifies", okMl.valid === true);
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
  testNonPrintableParamRejected();
  testDerivedComponents();
  testSignatureParameters();
  testQueryParamSignFailures();
  testQueryParamValuelessFlag();
  testMissingCoveredHeader();
  testArrayHeaderValue();
  testContentDigestFunction();
  testSignFailures();
  testVerifyPresenceGates();
  testMalformedSignatureInput();
  testBareUnquotedCoveredTokens();
  testParsedParamGates();
  testTimeGates();
  testKeyResolverThrows();
  testAlgKeyBinding();
  testContentDigestVerifyBranches();
  testMultiLabelSignature();
  testCryptoVerdicts();
  testBuildBaseFailed();
  testSignatureInputParamTolerance();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

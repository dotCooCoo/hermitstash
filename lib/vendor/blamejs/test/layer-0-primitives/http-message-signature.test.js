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
    covered:    ["@method", "content-digest"],
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
    covered:    ["@method", "content-digest"],
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
    { keyResolver: function () { return keys.publicKey; } }
  );
  check("query-param coverage round-trips",
        verified.valid === true);
}

async function run() {
  testSurface();
  testRoundTripEd25519();
  testRoundTripMlDsa65();
  testContentDigestTamper();
  testContentDigestMemberAnchored();
  testExpired();
  testUnknownKeyid();
  testValidation();
  testQueryParam();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

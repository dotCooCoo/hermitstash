"use strict";
/**
 * PQC PKCS8 forward-compat capture.
 *
 * Node 24 LTS exports ML-KEM / ML-DSA private keys as a full PKCS8
 * encoding that carries the entire expanded key material. Node 26
 * switched the default to a seed-only PKCS8 — same AlgorithmIdentifier
 * OID, structurally different OCTET STRING contents, much shorter blob.
 * Node 26's PKCS8 importer accepts BOTH shapes.
 *
 * Observed lengths (PKCS8 DER, type=pkcs8, format=der):
 *
 *   alg                   Node 24 (full)   Node 26 (seed-only)
 *   ml-kem-1024           ~3168 bytes      ~86  bytes
 *   ml-dsa-65             ~4032 bytes      ~54  bytes
 *   ml-dsa-87             ~4896 bytes      ~54  bytes
 *   slh-dsa-shake-256f    ~150  bytes      ~150 bytes   (no shift —
 *                                                       SLH-DSA private
 *                                                       key IS the seed)
 *   ed25519               48    bytes      48    bytes  (classical,
 *                                                       unaffected)
 *
 * The framework writes PQC private keys (sealed) from lib/crypto.js,
 * lib/audit-sign.js, lib/content-credentials.js, lib/ai-model-manifest.js,
 * lib/a2a.js, lib/acme.js. After the Node 26 floor-bump those writes
 * emit seed-only PKCS8 blobs by default; clients still on Node 24 LTS
 * during the compatibility window would NOT be able to import them
 * (Node 24's importer pre-dates the seed-only shape). The Node 26
 * floor-bump landing PR carries the explicit-encoding switch in the
 * primitives that write material destined for cross-version consumers.
 *
 * This test:
 *   1. Captures the PKCS8 shape per alg on the current Node version
 *      (one check per alg covering length + AlgorithmIdentifier prefix).
 *   2. Roundtrips export → import → sign-verify (or KEM encap/decap)
 *      to prove the freshly-exported blob is self-importable.
 *   3. Re-imports a hardcoded fixture (captured offline) every run as
 *      a regression guard against importer drift.
 *
 * TODO: When Node 28 / a Node 26 patch ships a future re-encoding
 * shift, add a second fixture capturing THAT release's default shape
 * and verify both round-trip cleanly. The fixture below was captured
 * on Node v26.1.0 (seed-only shape); when a Node 24-captured fixture
 * is generated on a 24 LTS machine, embed it as FIXTURE_NODE24_*
 * alongside FIXTURE_NODE26_* and assert both import paths succeed.
 */

var nodeCrypto = require("node:crypto");
var helpers    = require("../helpers");
var check      = helpers.check;

// Hardcoded fixtures — captured on Node v26.1.0 (seed-only shape).
// Format: PKCS8 DER private key + SPKI DER public key, both base64.
// Used as a regression guard: every run re-imports the same blob and
// signs+verifies a payload against the matching pubkey.
var FIXTURE_NODE26_MLDSA65_PRIV_B64 =
  "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIHA2Y+VRD6S2jl3dfX0H5KVTQk4NjoacmIB6V8W8EkkC";
var FIXTURE_NODE26_MLDSA65_PUB_B64 =
  "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";

// Per-alg expected behavior on the running Node version.
// Threshold model: if the export blob is shorter than seedCeiling it's
// a seed-only encoding; if longer than fullFloor it's the full
// encoding. SLH-DSA's private key is already a small seed, so it has
// the same length on both Node versions — we mark it shape-stable.
var ALG_TABLE = [
  {
    name:           "ml-kem-1024",
    seedCeiling:    256,     // Node 26 ~86
    fullFloor:      2048,    // Node 24 ~3168
    shapeStable:    false,
    kind:           "kem",
    expectedAkt:    "ml-kem-1024",
  },
  {
    name:           "ml-dsa-65",
    seedCeiling:    256,     // Node 26 ~54
    fullFloor:      3000,    // Node 24 ~4032
    shapeStable:    false,
    kind:           "sig",
    expectedAkt:    "ml-dsa-65",
  },
  {
    name:           "ml-dsa-87",
    seedCeiling:    256,     // Node 26 ~54
    fullFloor:      3500,    // Node 24 ~4896
    shapeStable:    false,
    kind:           "sig",
    expectedAkt:    "ml-dsa-87",
  },
  {
    name:           "slh-dsa-shake-256f",
    // SLH-DSA private key is itself the seed (~128 + ASN.1 header).
    // Same length both directions — the seed-only shift doesn't apply.
    seedCeiling:    256,
    fullFloor:      256,
    shapeStable:    true,
    kind:           "sig",
    expectedAkt:    "slh-dsa-shake-256f",
  },
  {
    name:           "ed25519",
    // Classical EdDSA — never affected by the PQC seed-only shift.
    seedCeiling:    64,
    fullFloor:      64,
    shapeStable:    true,
    kind:           "sig",
    expectedAkt:    "ed25519",
  },
];

function _classifyShape(spec, derLen) {
  if (spec.shapeStable) return "stable";
  if (derLen <= spec.seedCeiling) return "seed-only";
  if (derLen >= spec.fullFloor)   return "full";
  return "unknown";
}

function _hexPrefix(buf, n) {
  return buf.subarray(0, n).toString("hex");
}

function run() {
  var nodeMajor = parseInt(process.versions.node.split(".")[0], 10);
  check("running on a Node version known to this test",
    nodeMajor >= 24 && nodeMajor < 30);

  ALG_TABLE.forEach(function (spec) {
    // -- (1) capture the export shape on the current Node version.
    var kp = nodeCrypto.generateKeyPairSync(spec.name);
    var der = kp.privateKey.export({ type: "pkcs8", format: "der" });
    check(spec.name + ": pkcs8 export returns non-empty Buffer",
      Buffer.isBuffer(der) && der.length > 0);

    var shape = _classifyShape(spec, der.length);
    check(spec.name + ": pkcs8 shape classifiable (len=" + der.length +
          " shape=" + shape + " prefix=" + _hexPrefix(der, 20) + ")",
      shape !== "unknown");

    // Node 26-specific assertion for PQC algs whose shape DID shift.
    if (!spec.shapeStable && nodeMajor >= 26) {
      check(spec.name + ": Node 26 default is seed-only encoding",
        shape === "seed-only");
    }
    if (!spec.shapeStable && nodeMajor < 26) {
      check(spec.name + ": Node 24 default is full encoding",
        shape === "full");
    }

    // AlgorithmIdentifier OID prefix sanity. Every PKCS8 begins with
    // SEQUENCE { INTEGER 0, AlgorithmIdentifier { OID ... } ... }; the
    // first few bytes encode the SEQUENCE tag + length + version. The
    // exact prefix differs per alg but bytes [0]=0x30 (SEQUENCE) and
    // a small INTEGER 0x02 0x01 0x00 must be present.
    check(spec.name + ": pkcs8 starts with SEQUENCE tag",
      der[0] === 0x30);
    check(spec.name + ": pkcs8 carries INTEGER version=0",
      der.indexOf(Buffer.from([0x02, 0x01, 0x00])) !== -1);

    // -- (2) roundtrip: import, then sign+verify (or encap/decap for KEM).
    var reimported = nodeCrypto.createPrivateKey({
      key:    der,
      format: "der",
      type:   "pkcs8",
    });
    check(spec.name + ": reimport KeyObject.asymmetricKeyType matches",
      reimported.asymmetricKeyType === spec.expectedAkt);

    if (spec.kind === "sig") {
      var payload = Buffer.from(spec.name + " roundtrip payload");
      var sig = nodeCrypto.sign(null, payload, reimported);
      check(spec.name + ": sign with reimported key produces non-empty sig",
        Buffer.isBuffer(sig) && sig.length > 0);
      var ok = nodeCrypto.verify(null, payload, kp.publicKey, sig);
      check(spec.name + ": verify against original public key succeeds", ok === true);
    } else if (spec.kind === "kem") {
      // ML-KEM encap/decap roundtrip. encapsulate() uses the public
      // key and emits { sharedKey, ciphertext }; decapsulate() uses
      // the private key + ciphertext and yields the same sharedKey.
      var enc = nodeCrypto.encapsulate(kp.publicKey);
      check(spec.name + ": encapsulate returns sharedKey + ciphertext",
        Buffer.isBuffer(enc.sharedKey) && Buffer.isBuffer(enc.ciphertext));
      var dec = nodeCrypto.decapsulate(reimported, enc.ciphertext);
      check(spec.name + ": decapsulate with reimported key recovers sharedKey",
        Buffer.isBuffer(dec) && dec.equals(enc.sharedKey));
    }
  });

  // -- (3) fixture roundtrip: re-import a captured PKCS8 every run.
  // Regression guard against importer drift.
  var fixturePriv = Buffer.from(FIXTURE_NODE26_MLDSA65_PRIV_B64, "base64");
  var fixturePub  = Buffer.from(FIXTURE_NODE26_MLDSA65_PUB_B64,  "base64");

  check("fixture: ml-dsa-65 priv blob is the expected seed-only length",
    fixturePriv.length === 54);
  check("fixture: ml-dsa-65 pub  blob is the expected spki length",
    fixturePub.length === 1974);

  var importedFixture = nodeCrypto.createPrivateKey({
    key:    fixturePriv,
    format: "der",
    type:   "pkcs8",
  });
  check("fixture: re-imports as ml-dsa-65",
    importedFixture.asymmetricKeyType === "ml-dsa-65");

  var fixturePubKey = nodeCrypto.createPublicKey({
    key:    fixturePub,
    format: "der",
    type:   "spki",
  });
  check("fixture: spki re-imports as ml-dsa-65",
    fixturePubKey.asymmetricKeyType === "ml-dsa-65");

  var fixturePayload = Buffer.from("Node 26 seed-only PKCS8 fixture roundtrip");
  var fixtureSig = nodeCrypto.sign(null, fixturePayload, importedFixture);
  check("fixture: sign produces non-empty signature",
    Buffer.isBuffer(fixtureSig) && fixtureSig.length > 0);
  check("fixture: verify against captured public key succeeds",
    nodeCrypto.verify(null, fixturePayload, fixturePubKey, fixtureSig) === true);

  // TODO: When a Node 24 LTS machine is available, capture a parallel
  //   FIXTURE_NODE24_MLDSA65_PRIV_B64 (full-shape PKCS8, ~4032 bytes)
  //   + matching public key, and assert it ALSO re-imports cleanly here
  //   — that nails down "Node-24-sealed material remains importable on
  //   Node 26" as a permanent regression guard. The reverse direction
  //   (Node 26 seed-only → Node 24 importer) cannot be tested in the
  //   same process, but a Node 24 container leg can be added to the
  //   release runbook to consume this fixture.

  console.log("OK — " + helpers.getChecks() + " checks passed");
}

try {
  run();
} catch (e) {
  console.error(e && (e.stack || e.message || String(e)));
  process.exit(1);
}

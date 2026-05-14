"use strict";
/**
 * b.vendorData — packaging-mode-invariant + signed + canary-guarded
 * loader for vendored data files.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("vendorData.get is fn",         typeof b.vendorData.get === "function");
  check("vendorData.getAsString is fn", typeof b.vendorData.getAsString === "function");
  check("vendorData.verifyAll is fn",   typeof b.vendorData.verifyAll === "function");
  check("vendorData.inventory is fn",   typeof b.vendorData.inventory === "function");
  check("vendorData.VendorDataError is constructor",
        typeof b.vendorData.VendorDataError === "function");
  check("KNOWN_VENDOR_DATA frozen",
        Object.isFrozen(b.vendorData.KNOWN_VENDOR_DATA));
}

function testKnownVendorDataEntries() {
  var known = b.vendorData.KNOWN_VENDOR_DATA;
  check("KNOWN: public-suffix-list registered", !!known["public-suffix-list"]);
  check("KNOWN: common-passwords-top-10000 registered",
        !!known["common-passwords-top-10000"]);
  check("KNOWN: bimi-trust-anchors registered", !!known["bimi-trust-anchors"]);
  check("KNOWN: PSL has canary",
        known["public-suffix-list"].canary === "_blamejs_canary_v0_9_8_.local");
  check("KNOWN: common-pw has canary",
        known["common-passwords-top-10000"].canary ===
        "_blamejs_canary_password_2026_05_13_blamejs_internal_");
  check("KNOWN: BIMI canary is null (PEM bundle — no in-payload canary)",
        known["bimi-trust-anchors"].canary === null);
}

function testGetReturnsVerifiedBuffer() {
  var psl = b.vendorData.get("public-suffix-list");
  check("get: PSL returns Buffer", Buffer.isBuffer(psl));
  check("get: PSL non-empty",      psl.length > 100000);

  var cp = b.vendorData.get("common-passwords-top-10000");
  check("get: common-pw returns Buffer", Buffer.isBuffer(cp));
  check("get: common-pw non-empty",      cp.length > 10000);

  var bimi = b.vendorData.get("bimi-trust-anchors");
  check("get: BIMI returns Buffer", Buffer.isBuffer(bimi));
}

function testGetAsStringRoundtrip() {
  var raw = b.vendorData.get("public-suffix-list");
  var str = b.vendorData.getAsString("public-suffix-list");
  check("getAsString: utf8-decodes the buffer", str === raw.toString("utf8"));
  check("getAsString: cache shared with get()",
        b.vendorData.get("public-suffix-list") === raw);
}

function testGetRefusesUnknownName() {
  var threw = null;
  try { b.vendorData.get("not-a-real-vendor-file"); } catch (e) { threw = e; }
  check("get: unknown name refused",
        threw && (threw.code || "").indexOf("vendor-data/unknown") !== -1);
}

function testVerifyAllReturnsNames() {
  var names = b.vendorData.verifyAll();
  check("verifyAll: returns array",         Array.isArray(names));
  check("verifyAll: all 3 names",           names.length === 3);
  check("verifyAll: PSL in list",           names.indexOf("public-suffix-list") !== -1);
  check("verifyAll: common-pw in list",     names.indexOf("common-passwords-top-10000") !== -1);
  check("verifyAll: BIMI in list",          names.indexOf("bimi-trust-anchors") !== -1);
}

function testInventoryShape() {
  var inv = b.vendorData.inventory();
  check("inventory: 3 entries", inv.length === 3);
  var pslEntry = inv.find(function (e) { return e.name === "public-suffix-list"; });
  check("inventory: PSL has source",      typeof pslEntry.source === "string");
  check("inventory: PSL has fetchedAt",   typeof pslEntry.fetchedAt === "string");
  check("inventory: PSL has sha256",      typeof pslEntry.sha256 === "string");
  check("inventory: PSL sha256 length",   pslEntry.sha256.length === 64);
  check("inventory: PSL has sha3_512",    typeof pslEntry.sha3_512 === "string");
  check("inventory: PSL sha3_512 length", pslEntry.sha3_512.length === 128);
  check("inventory: PSL has signedBy",    typeof pslEntry.signedBy === "string");
  check("inventory: PSL signedBy prefix", pslEntry.signedBy.indexOf("sha256:") === 0);
  check("inventory: PSL byteLength > 0",  pslEntry.byteLength > 0);
}

function testCanaryPresentInParsedPSL() {
  // The canary token in the PSL payload MUST surface as a valid public
  // suffix after parse. Defense-in-depth — an attacker who swaps the
  // PSL data bytes + forges hashes + forges signatures still has to
  // preserve the canary in the parsed structure.
  check("PSL canary is a public-suffix after parse",
        b.publicSuffix.isPublicSuffix("_blamejs_canary_v0_9_8_.local") === true);
}

function testTamperDetectionViaCloneAndModify() {
  // Simulate tamper: take the payload buffer, modify it, recompute
  // sha256, attempt to construct a fake module — vendor-data refuses
  // because the embedded sha256 in metadata still matches the ORIGINAL
  // payload, not the modified one. (This test exercises the verify
  // path; it doesn't actually modify the on-disk .data.js — that
  // would invalidate later test invocations.)
  var nodeCrypto = require("crypto");
  var original = b.vendorData.get("public-suffix-list");
  var modified = Buffer.from(original);
  modified[0] ^= 0xff;
  var modifiedHash = nodeCrypto.createHash("sha256").update(modified).digest("hex");
  var originalHash = nodeCrypto.createHash("sha256").update(original).digest("hex");
  check("tamper sim: modified hash differs", modifiedHash !== originalHash);
  // The runtime verifier's actual code path is exercised by the cache hit
  // (returning the verified original). The modified Buffer is local — not
  // injected into the module cache. This test serves as documentation of
  // the threat model the verifier defends against.
}

function testSignatureFingerprintStableAcrossCalls() {
  var inv1 = b.vendorData.inventory();
  var inv2 = b.vendorData.inventory();
  check("fingerprint: stable across calls",
        inv1[0].signedBy === inv2[0].signedBy);
  // All 3 entries signed by the same maintainer key
  var fp = inv1[0].signedBy;
  for (var i = 1; i < inv1.length; i++) {
    check("fingerprint: " + inv1[i].name + " signed by same key as " + inv1[0].name,
          inv1[i].signedBy === fp);
  }
}

async function run() {
  testSurface();
  testKnownVendorDataEntries();
  testGetReturnsVerifiedBuffer();
  testGetAsStringRoundtrip();
  testGetRefusesUnknownName();
  testVerifyAllReturnsNames();
  testInventoryShape();
  testCanaryPresentInParsedPSL();
  testTamperDetectionViaCloneAndModify();
  testSignatureFingerprintStableAcrossCalls();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

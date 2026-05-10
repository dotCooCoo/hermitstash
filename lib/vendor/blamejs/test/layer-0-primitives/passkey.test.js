"use strict";
/**
 * b.auth.passkey — WebAuthn (FIDO2) primitives.
 *
 * Covers the v0.8.53 surface added on top of the earlier per-file
 * primitive checks in test/00-primitives.js:
 *
 *   - WebAuthn L3 §6.1.3 BE/BS flag surfacing on verifyRegistration
 *     and verifyAuthentication results (backupEligible / backupState).
 *   - WebAuthn L3 §10.1.2 / §10.3 / §10.5 extension helpers
 *     (extensions.prf / largeBlob / credBlob): config-time validation
 *     and shape correctness.
 *   - Conditional UI / autofill helper (conditionalAuthOptions) and
 *     mediation passthrough on startAuthentication.
 *
 * The shape-of-result tests stub the vendored verify* functions via a
 * test-local require-cache override; standing up real WebAuthn
 * fixtures is out of scope for a primitive-layer suite.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// ---- BE/BS surfacing ----

async function testRegistrationBackupFlagsMultiDevice() {
  var path = require.resolve("../../lib/vendor/simplewebauthn-server.cjs");
  var orig = require.cache[path].exports;
  require.cache[path].exports = Object.assign({}, orig, {
    verifyRegistrationResponse: async function () {
      return {
        verified: true,
        registrationInfo: {
          credentialDeviceType: "multiDevice",
          credentialBackedUp:   true,
        },
      };
    },
  });
  // Force passkey.js to re-resolve the vendor binding via _vendor() —
  // the wrapper is direct require, so we override the cache before the
  // call and restore after. The test only exercises the post-vendor
  // mapping logic.
  delete require.cache[require.resolve("../../lib/auth/passkey")];
  var passkey = require("../../lib/auth/passkey");
  try {
    var rv = await passkey.verifyRegistration({
      response:          { id: "x" },
      expectedChallenge: "c",
      expectedOrigin:    "https://x.test",
      expectedRPID:      "x.test",
    });
    check("verifyRegistration backupEligible=true on multiDevice",
          rv.backupEligible === true);
    check("verifyRegistration backupState=true on credentialBackedUp=true",
          rv.backupState === true);
    check("verifyRegistration registrationInfo passes through",
          rv.registrationInfo && rv.registrationInfo.credentialDeviceType === "multiDevice");
  } finally {
    require.cache[path].exports = orig;
    delete require.cache[require.resolve("../../lib/auth/passkey")];
  }
}

async function testRegistrationBackupFlagsSingleDevice() {
  var path = require.resolve("../../lib/vendor/simplewebauthn-server.cjs");
  var orig = require.cache[path].exports;
  require.cache[path].exports = Object.assign({}, orig, {
    verifyRegistrationResponse: async function () {
      return {
        verified: true,
        registrationInfo: {
          credentialDeviceType: "singleDevice",
          credentialBackedUp:   false,
        },
      };
    },
  });
  delete require.cache[require.resolve("../../lib/auth/passkey")];
  var passkey = require("../../lib/auth/passkey");
  try {
    var rv = await passkey.verifyRegistration({
      response:          { id: "x" },
      expectedChallenge: "c",
      expectedOrigin:    "https://x.test",
      expectedRPID:      "x.test",
    });
    check("verifyRegistration backupEligible=false on singleDevice",
          rv.backupEligible === false);
    check("verifyRegistration backupState=false on credentialBackedUp=false",
          rv.backupState === false);
  } finally {
    require.cache[path].exports = orig;
    delete require.cache[require.resolve("../../lib/auth/passkey")];
  }
}

async function testAuthenticationBackupFlags() {
  var path = require.resolve("../../lib/vendor/simplewebauthn-server.cjs");
  var orig = require.cache[path].exports;
  require.cache[path].exports = Object.assign({}, orig, {
    verifyAuthenticationResponse: async function () {
      return {
        verified: true,
        authenticationInfo: {
          newCounter: 5,
          credentialDeviceType: "multiDevice",
          credentialBackedUp:   true,
        },
      };
    },
  });
  delete require.cache[require.resolve("../../lib/auth/passkey")];
  var passkey = require("../../lib/auth/passkey");
  try {
    var rv = await passkey.verifyAuthentication({
      response:          { id: "x" },
      expectedChallenge: "c",
      expectedOrigin:    "https://x.test",
      expectedRPID:      "x.test",
      credential:        { id: "abc", publicKey: Buffer.from("00", "hex"), counter: 0 },
    });
    check("verifyAuthentication backupEligible=true on multiDevice",
          rv.backupEligible === true);
    check("verifyAuthentication backupState=true on credentialBackedUp=true",
          rv.backupState === true);
  } finally {
    require.cache[path].exports = orig;
    delete require.cache[require.resolve("../../lib/auth/passkey")];
  }
}

// ---- Extension helpers ----

function testPrfExt() {
  var p = b.auth.passkey;
  var first = Buffer.from(new Array(32).fill(1));                                  // allow:raw-byte-literal — PRF salt size
  var ext = p.extensions.prf({ eval: { first: first } });
  check("prf returns { prf: { eval: { first } } }",
        ext && ext.prf && ext.prf.eval &&
        typeof ext.prf.eval.first === "string" &&
        ext.prf.eval.first.length > 0);

  var ext2 = p.extensions.prf({ eval: { first: first, second: first } });
  check("prf passes second through",
        ext2.prf.eval.second === ext2.prf.eval.first);

  // String input
  var ext3 = p.extensions.prf({ eval: { first: "AAAA" } });
  check("prf accepts base64url string",
        ext3.prf.eval.first === "AAAA");

  var threw = null;
  try { p.extensions.prf({}); } catch (e) { threw = e; }
  check("prf({}) throws missing-eval",
        threw && /missing-eval/.test(threw.code || ""));

  threw = null;
  try { p.extensions.prf({ eval: {} }); } catch (e) { threw = e; }
  check("prf({ eval: {} }) throws missing-prf-first",
        threw && /missing-prf-first/.test(threw.code || ""));

  threw = null;
  try { p.extensions.prf({ eval: { first: "not base64url!" } }); } catch (e) { threw = e; }
  check("prf rejects non-base64url string",
        threw && /bad-extension-input/.test(threw.code || ""));

  threw = null;
  try { p.extensions.prf({ eval: { first: 123 } }); } catch (e) { threw = e; }
  check("prf rejects non-Buffer non-string",
        threw && /bad-extension-input/.test(threw.code || ""));
}

function testLargeBlobExt() {
  var p = b.auth.passkey;
  var ext = p.extensions.largeBlob({ support: "preferred" });
  check("largeBlob support='preferred' shape",
        ext && ext.largeBlob && ext.largeBlob.support === "preferred");

  ext = p.extensions.largeBlob({ support: "required" });
  check("largeBlob support='required' shape", ext.largeBlob.support === "required");

  ext = p.extensions.largeBlob({ read: true });
  check("largeBlob read=true shape", ext.largeBlob.read === true);

  var blob = Buffer.from(new Array(64).fill(0xab));                                // allow:raw-byte-literal — fixture blob length
  ext = p.extensions.largeBlob({ write: blob });
  check("largeBlob write Buffer encodes to base64url",
        typeof ext.largeBlob.write === "string" && ext.largeBlob.write.length > 0);

  var threw = null;
  try { p.extensions.largeBlob(); } catch (e) { threw = e; }
  check("largeBlob() throws missing-largeblob",
        threw && /missing-largeblob/.test(threw.code || ""));

  threw = null;
  try { p.extensions.largeBlob({}); } catch (e) { threw = e; }
  check("largeBlob({}) throws empty-largeblob",
        threw && /empty-largeblob/.test(threw.code || ""));

  threw = null;
  try { p.extensions.largeBlob({ support: "x" }); } catch (e) { threw = e; }
  check("largeBlob bad support throws",
        threw && /bad-largeblob-support/.test(threw.code || ""));

  threw = null;
  try { p.extensions.largeBlob({ read: "yes" }); } catch (e) { threw = e; }
  check("largeBlob read non-boolean throws",
        threw && /bad-largeblob-read/.test(threw.code || ""));

  threw = null;
  try { p.extensions.largeBlob({ read: true, write: blob }); } catch (e) { threw = e; }
  check("largeBlob read+write conflict throws",
        threw && /conflicting-largeblob/.test(threw.code || ""));

  threw = null;
  try { p.extensions.largeBlob({ write: "not a buffer" }); } catch (e) { threw = e; }
  check("largeBlob write non-Buffer throws",
        threw && /bad-largeblob-write/.test(threw.code || ""));
}

function testCredBlobExt() {
  var p = b.auth.passkey;
  var blob = Buffer.from(new Array(16).fill(0xa0));                                // allow:raw-byte-literal — fixture blob length
  var ext = p.extensions.credBlob({ blob: blob });
  check("credBlob shape",
        ext && typeof ext.credBlob === "string" && ext.credBlob.length > 0);

  ext = p.extensions.credBlob({ blob: new Uint8Array([1, 2, 3]) });                // allow:raw-byte-literal — fixture bytes
  check("credBlob accepts Uint8Array",
        ext.credBlob && ext.credBlob.length > 0);

  var threw = null;
  try { p.extensions.credBlob(); } catch (e) { threw = e; }
  check("credBlob() throws missing-credblob",
        threw && /missing-credblob/.test(threw.code || ""));

  threw = null;
  try { p.extensions.credBlob({}); } catch (e) { threw = e; }
  check("credBlob({}) throws missing-credblob",
        threw && /missing-credblob/.test(threw.code || ""));

  threw = null;
  try { p.extensions.credBlob({ blob: "not a buffer" }); } catch (e) { threw = e; }
  check("credBlob non-Buffer throws",
        threw && /bad-credblob/.test(threw.code || ""));

  // Empty blob — must throw (1-32 bytes range).
  threw = null;
  try { p.extensions.credBlob({ blob: Buffer.alloc(0) }); } catch (e) { threw = e; }
  check("credBlob empty blob throws credblob-bad-length",
        threw && /credblob-bad-length/.test(threw.code || ""));

  // Over-32-byte blob — must throw.
  threw = null;
  try { p.extensions.credBlob({ blob: Buffer.alloc(33) }); } catch (e) { threw = e; }    // allow:raw-byte-literal — CTAP2.1 limit + 1
  check("credBlob 33-byte blob throws credblob-bad-length",
        threw && /credblob-bad-length/.test(threw.code || ""));
}

// ---- Conditional UI / mediation ----

async function testConditionalAuthOptions() {
  var p = b.auth.passkey;
  var opts = await p.conditionalAuthOptions({ rpId: "example.com" });
  check("conditionalAuthOptions has challenge",
        typeof opts.challenge === "string" && opts.challenge.length > 0);
  check("conditionalAuthOptions has rpId",
        opts.rpId === "example.com");
  check("conditionalAuthOptions sets mediation='conditional'",
        opts.mediation === "conditional");
  check("conditionalAuthOptions allowCredentials is empty",
        Array.isArray(opts.allowCredentials) && opts.allowCredentials.length === 0);
  check("conditionalAuthOptions sets default hints",
        Array.isArray(opts.hints) && opts.hints.indexOf("client-device") !== -1);

  var threw = null;
  try { await p.conditionalAuthOptions(); } catch (e) { threw = e; }
  check("conditionalAuthOptions() throws missing-opts",
        threw && /missing-opts/.test(threw.code || ""));

  threw = null;
  try { await p.conditionalAuthOptions({}); } catch (e) { threw = e; }
  check("conditionalAuthOptions({}) throws missing-rpId",
        threw && /missing-rpId/.test(threw.code || ""));
}

async function testStartAuthMediationPassthrough() {
  var p = b.auth.passkey;
  var opts = await p.startAuthentication({ rpId: "example.com", mediation: "optional" });
  check("startAuthentication echoes mediation when set",
        opts.mediation === "optional");

  var noMed = await p.startAuthentication({ rpId: "example.com" });
  check("startAuthentication omits mediation when not set",
        noMed.mediation === undefined);

  var threw = null;
  try { await p.startAuthentication({ rpId: "example.com", mediation: "BOGUS" }); }
  catch (e) { threw = e; }
  check("startAuthentication rejects bad mediation",
        threw && /bad-mediation/.test(threw.code || ""));
}

// ---- run ----

async function run() {
  await testRegistrationBackupFlagsMultiDevice();
  await testRegistrationBackupFlagsSingleDevice();
  await testAuthenticationBackupFlags();
  testPrfExt();
  testLargeBlobExt();
  testCredBlobExt();
  await testConditionalAuthOptions();
  await testStartAuthMediationPassthrough();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

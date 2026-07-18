// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

// ---- startRegistration: required-input guards + option defaults ----

async function testStartRegistrationGuards() {
  var threw = null;
  try { await b.auth.passkey.startRegistration(); } catch (e) { threw = e; }
  check("startRegistration() throws missing-opts",
        threw && /missing-opts/.test(threw.code || ""));

  threw = null;
  try { await b.auth.passkey.startRegistration({}); } catch (e) { threw = e; }
  check("startRegistration({}) throws missing-rpName",
        threw && /missing-rpName/.test(threw.code || ""));

  threw = null;
  try { await b.auth.passkey.startRegistration({ rpName: "X" }); } catch (e) { threw = e; }
  check("startRegistration without rpId throws missing-rpId",
        threw && /missing-rpId/.test(threw.code || ""));

  threw = null;
  try { await b.auth.passkey.startRegistration({ rpName: "X", rpId: "x.test" }); }
  catch (e) { threw = e; }
  check("startRegistration without userName throws missing-userName",
        threw && /missing-userName/.test(threw.code || ""));
}

async function testStartRegistrationDefaultsAndOptions() {
  var opts = await b.auth.passkey.startRegistration({
    rpName: "Example", rpId: "example.com", userName: "alice",
  });
  check("startRegistration returns a base64url challenge",
        typeof opts.challenge === "string" && opts.challenge.length > 0);
  check("startRegistration applies default hints (client-device + hybrid)",
        Array.isArray(opts.hints) &&
        opts.hints.indexOf("client-device") !== -1 &&
        opts.hints.indexOf("hybrid") !== -1);
  check("startRegistration defaults residentKey='preferred'",
        opts.authenticatorSelection &&
        opts.authenticatorSelection.residentKey === "preferred");
  check("startRegistration defaults userVerification='preferred'",
        opts.authenticatorSelection.userVerification === "preferred");
  check("startRegistration defaults userDisplayName to userName",
        opts.user && opts.user.displayName === "alice");
  check("startRegistration defaults attestation='none'",
        opts.attestation === "none");

  // Every non-default option threaded: custom hints, authenticatorSelection,
  // attestationType, timeout, excludeCredentials.
  var custom = await b.auth.passkey.startRegistration({
    rpName: "Example", rpId: "example.com", userName: "bob",
    userDisplayName: "Bob B", attestationType: "direct", timeout: 60000,
    hints: ["security-key"],
    authenticatorSelection: {
      residentKey: "required", userVerification: "required",
      authenticatorAttachment: "platform", requireResidentKey: true,
    },
    excludeCredentials: [{ id: "AAAA", type: "public-key" }],
  });
  check("startRegistration echoes custom hints verbatim",
        Array.isArray(custom.hints) && custom.hints.length === 1 &&
        custom.hints[0] === "security-key");
  check("startRegistration threads custom authenticatorSelection",
        custom.authenticatorSelection.residentKey === "required" &&
        custom.authenticatorSelection.userVerification === "required" &&
        custom.authenticatorSelection.authenticatorAttachment === "platform");
  check("startRegistration honors custom userDisplayName",
        custom.user.displayName === "Bob B");
  check("startRegistration honors attestationType='direct'",
        custom.attestation === "direct");
}

// ---- Extension allowlist enforced through the real startRegistration path ----

async function testStartRegistrationExtensionAllowlist() {
  // Recognised keys route through their builder and reach the vendor options.
  var routed = await b.auth.passkey.startRegistration({
    rpName: "Example", rpId: "example.com", userName: "alice",
    extensions: {
      prf:       { eval: { first: "AAAA" } },
      largeBlob: { support: "preferred" },
      credBlob:  { blob: Buffer.from(new Array(8).fill(0x11)) },              // allow:raw-byte-literal — fixture blob
    },
  });
  check("startRegistration routes prf extension to spec shape",
        routed.extensions && routed.extensions.prf &&
        routed.extensions.prf.eval && routed.extensions.prf.eval.first === "AAAA");
  check("startRegistration routes largeBlob extension",
        routed.extensions.largeBlob && routed.extensions.largeBlob.support === "preferred");
  check("startRegistration routes credBlob to base64url",
        typeof routed.extensions.credBlob === "string" && routed.extensions.credBlob.length > 0);

  // Non-object extensions → bad-extensions.
  var threw = null;
  try {
    await b.auth.passkey.startRegistration({
      rpName: "Example", rpId: "example.com", userName: "a", extensions: "nope",
    });
  } catch (e) { threw = e; }
  check("startRegistration rejects non-object extensions",
        threw && /bad-extensions/.test(threw.code || ""));

  // Array extensions → bad-extensions (Array.isArray guard).
  threw = null;
  try {
    await b.auth.passkey.startRegistration({
      rpName: "Example", rpId: "example.com", userName: "a", extensions: ["prf"],
    });
  } catch (e) { threw = e; }
  check("startRegistration rejects array extensions",
        threw && /bad-extensions/.test(threw.code || ""));

  // Unknown key → refused unless opted out.
  threw = null;
  try {
    await b.auth.passkey.startRegistration({
      rpName: "Example", rpId: "example.com", userName: "a",
      extensions: { unknownExt: { some: "thing" } },
    });
  } catch (e) { threw = e; }
  check("startRegistration refuses an unknown extension key",
        threw && /unknown-extension/.test(threw.code || ""));

  // allowUnknownExtensions:true → the key passes through verbatim.
  var passthrough = await b.auth.passkey.startRegistration({
    rpName: "Example", rpId: "example.com", userName: "a",
    extensions: { unknownExt: { some: "thing" } },
    allowUnknownExtensions: true,
  });
  check("startRegistration passes unknown extension through when opted out",
        passthrough.extensions && passthrough.extensions.unknownExt &&
        passthrough.extensions.unknownExt.some === "thing");
}

// ---- startAuthentication / conditionalAuthOptions custom-hints branch ----

async function testStartAuthenticationHintsAndExtensions() {
  var custom = await b.auth.passkey.startAuthentication({
    rpId: "example.com", hints: ["security-key"],
    userVerification: "required",
    extensions: { prf: { eval: { first: "AAAA" } } },
  });
  check("startAuthentication echoes custom hints",
        Array.isArray(custom.hints) && custom.hints[0] === "security-key");
  check("startAuthentication routes extensions through the allowlist",
        custom.extensions && custom.extensions.prf &&
        custom.extensions.prf.eval.first === "AAAA");
  check("startAuthentication threads custom userVerification",
        custom.userVerification === "required");

  var threw = null;
  try {
    await b.auth.passkey.startAuthentication({
      rpId: "example.com", extensions: { bogus: 1 },
    });
  } catch (e) { threw = e; }
  check("startAuthentication refuses unknown extension key",
        threw && /unknown-extension/.test(threw.code || ""));

  threw = null;
  try { await b.auth.passkey.startAuthentication(); } catch (e) { threw = e; }
  check("startAuthentication() throws missing-opts",
        threw && /missing-opts/.test(threw.code || ""));
}

async function testConditionalAuthCustomHints() {
  var opts = await b.auth.passkey.conditionalAuthOptions({
    rpId: "example.com", hints: ["hybrid"],
    userVerification: "required",
    extensions: { prf: { eval: { first: "AAAA" } } },
  });
  check("conditionalAuthOptions echoes custom hints",
        Array.isArray(opts.hints) && opts.hints.length === 1 && opts.hints[0] === "hybrid");
  check("conditionalAuthOptions still forces mediation='conditional'",
        opts.mediation === "conditional");
  check("conditionalAuthOptions routes extensions",
        opts.extensions && opts.extensions.prf && opts.extensions.prf.eval.first === "AAAA");
}

// ---- _b64urlExtInput byte-cap + Uint8Array normalization ----

function testExtensionInputBounds() {
  // Uint8Array at the 32-byte cap normalizes to base64url.
  var ok = b.auth.passkey.extensions.prf({ eval: { first: new Uint8Array(32) } });
  check("prf accepts a 32-byte Uint8Array and encodes base64url",
        ok.prf.eval.first && typeof ok.prf.eval.first === "string");

  // A base64url STRING that decodes to > 32 bytes is refused (44 b64url
  // chars → 33 decoded bytes), per CTAP2.1 PRF salt cap.
  var threw = null;
  try { b.auth.passkey.extensions.prf({ eval: { first: "A".repeat(44) } }); }
  catch (e) { threw = e; }
  check("prf refuses an over-cap base64url string",
        threw && /extension-input-too-large/.test(threw.code || ""));

  // Over-cap Buffer refused.
  threw = null;
  try { b.auth.passkey.extensions.prf({ eval: { first: Buffer.alloc(33) } }); }          // allow:raw-byte-literal — cap + 1
  catch (e) { threw = e; }
  check("prf refuses an over-cap Buffer",
        threw && /extension-input-too-large/.test(threw.code || ""));

  // Over-cap Uint8Array refused.
  threw = null;
  try { b.auth.passkey.extensions.prf({ eval: { first: new Uint8Array(33) } }); }         // allow:raw-byte-literal — cap + 1
  catch (e) { threw = e; }
  check("prf refuses an over-cap Uint8Array",
        threw && /extension-input-too-large/.test(threw.code || ""));

  // second salt travels through the same normalizer + cap.
  threw = null;
  try {
    b.auth.passkey.extensions.prf({ eval: { first: "AAAA", second: Buffer.alloc(33) } }); // allow:raw-byte-literal — cap + 1
  } catch (e) { threw = e; }
  check("prf caps eval.second the same way",
        threw && /extension-input-too-large/.test(threw.code || ""));
}

// ---- verifyRegistration: expectedOrigin validation + required-input guards ----

async function testVerifyRegistrationOriginValidation() {
  var base = { response: { id: "x" }, expectedChallenge: "c", expectedRPID: "x.test" };

  var threw = null;
  try { await b.auth.passkey.verifyRegistration(); } catch (e) { threw = e; }
  check("verifyRegistration() throws missing-opts",
        threw && /missing-opts/.test(threw.code || ""));

  threw = null;
  try { await b.auth.passkey.verifyRegistration({ expectedChallenge: "c" }); }
  catch (e) { threw = e; }
  check("verifyRegistration without response throws missing-response",
        threw && /missing-response/.test(threw.code || ""));

  // Empty-string origin.
  threw = null;
  try { await b.auth.passkey.verifyRegistration(Object.assign({}, base, { expectedOrigin: "" })); }
  catch (e) { threw = e; }
  check("verifyRegistration rejects empty-string expectedOrigin",
        threw && /missing-expectedOrigin/.test(threw.code || ""));

  // Empty array.
  threw = null;
  try { await b.auth.passkey.verifyRegistration(Object.assign({}, base, { expectedOrigin: [] })); }
  catch (e) { threw = e; }
  check("verifyRegistration rejects empty expectedOrigin array",
        threw && /missing-expectedOrigin/.test(threw.code || ""));

  // Array with a non-string element.
  threw = null;
  try {
    await b.auth.passkey.verifyRegistration(
      Object.assign({}, base, { expectedOrigin: ["https://a.test", 123] }));
  } catch (e) { threw = e; }
  check("verifyRegistration rejects a non-string element in expectedOrigin array",
        threw && /missing-expectedOrigin/.test(threw.code || ""));

  // Array with an empty-string element.
  threw = null;
  try {
    await b.auth.passkey.verifyRegistration(
      Object.assign({}, base, { expectedOrigin: [""] }));
  } catch (e) { threw = e; }
  check("verifyRegistration rejects an empty-string element in expectedOrigin array",
        threw && /missing-expectedOrigin/.test(threw.code || ""));

  // Neither string nor array (number).
  threw = null;
  try { await b.auth.passkey.verifyRegistration(Object.assign({}, base, { expectedOrigin: 123 })); }
  catch (e) { threw = e; }
  check("verifyRegistration rejects a numeric expectedOrigin",
        threw && /missing-expectedOrigin/.test(threw.code || ""));

  // A well-formed multi-origin array PASSES validation and reaches the
  // vendor (which then rejects the bogus response for an unrelated reason —
  // proving the origin-array validation itself did not reject).
  threw = null;
  try {
    await b.auth.passkey.verifyRegistration(
      Object.assign({}, base, { expectedOrigin: ["https://a.test", "https://b.test"] }));
  } catch (e) { threw = e; }
  check("verifyRegistration accepts a valid multi-origin array (fails later, not on origin)",
        threw && !/missing-expectedOrigin/.test(threw.code || ""));
}

// ---- verifyRegistration BE/BS fallback when the vendor returns no info ----

async function testVerifyRegistrationNoRegistrationInfoFallback() {
  var path = require.resolve("../../lib/vendor/simplewebauthn-server.cjs");
  var orig = require.cache[path].exports;
  var vendorReturn = { verified: false };                                            // no registrationInfo
  require.cache[path].exports = Object.assign({}, orig, {
    verifyRegistrationResponse: async function () { return vendorReturn; },
  });
  delete require.cache[require.resolve("../../lib/auth/passkey")];
  var passkey = require("../../lib/auth/passkey");
  var input = {
    response:          { id: "x" },
    expectedChallenge: "c",
    expectedOrigin:    "https://x.test",
    expectedRPID:      "x.test",
  };
  try {
    // (a) vendor returns a result object with no registrationInfo — the
    //     BE/BS fields default to false and verified:false is preserved.
    var rv = await passkey.verifyRegistration(input);
    check("verifyRegistration defaults backupEligible=false without registrationInfo",
          rv.backupEligible === false);
    check("verifyRegistration defaults backupState=false without registrationInfo",
          rv.backupState === false);
    check("verifyRegistration preserves verified:false in the fallback",
          rv.verified === false);

    // (b) vendor returns nullish — the defensive `rv = rv || {}` fallback
    //     synthesizes a result rather than throwing on a missing return.
    vendorReturn = null;
    var rv2 = await passkey.verifyRegistration(input);
    check("verifyRegistration synthesizes a result when the vendor returns nullish",
          rv2 && rv2.backupEligible === false && rv2.backupState === false);
  } finally {
    require.cache[path].exports = orig;
    delete require.cache[require.resolve("../../lib/auth/passkey")];
  }
}

// ---- verifyAuthentication: response / credential / counter guards ----

async function testVerifyAuthenticationGuards() {
  var base = {
    response: { id: "x" }, expectedChallenge: "c",
    expectedOrigin: "https://x.test", expectedRPID: "x.test",
  };
  var pub = Buffer.from("00", "hex");

  var threw = null;
  try { await b.auth.passkey.verifyAuthentication(); } catch (e) { threw = e; }
  check("verifyAuthentication() throws missing-opts",
        threw && /missing-opts/.test(threw.code || ""));

  threw = null;
  try { await b.auth.passkey.verifyAuthentication({ expectedChallenge: "c" }); }
  catch (e) { threw = e; }
  check("verifyAuthentication without response throws missing-response",
        threw && /missing-response/.test(threw.code || ""));

  // Credential missing entirely / missing publicKey / missing id.
  threw = null;
  try { await b.auth.passkey.verifyAuthentication(base); } catch (e) { threw = e; }
  check("verifyAuthentication without credential throws missing-credential",
        threw && /missing-credential/.test(threw.code || ""));

  threw = null;
  try {
    await b.auth.passkey.verifyAuthentication(
      Object.assign({}, base, { credential: { id: "a" } }));
  } catch (e) { threw = e; }
  check("verifyAuthentication credential without publicKey throws missing-credential",
        threw && /missing-credential/.test(threw.code || ""));

  // counter undefined/null — refused to prevent clone-detection bypass.
  threw = null;
  try {
    await b.auth.passkey.verifyAuthentication(
      Object.assign({}, base, { credential: { id: "a", publicKey: pub } }));
  } catch (e) { threw = e; }
  check("verifyAuthentication with missing counter throws missing-counter",
        threw && /missing-counter/.test(threw.code || ""));

  threw = null;
  try {
    await b.auth.passkey.verifyAuthentication(
      Object.assign({}, base, { credential: { id: "a", publicKey: pub, counter: null } }));
  } catch (e) { threw = e; }
  check("verifyAuthentication with null counter throws missing-counter",
        threw && /missing-counter/.test(threw.code || ""));

  // Non-integer / out-of-range counters — each disjunct of the guard.
  var badCounters = [
    ["5", "string counter"],
    [-1, "negative counter"],
    [1.5, "fractional counter"],
    [Infinity, "non-finite counter"],
    [NaN, "NaN counter"],
  ];
  for (var i = 0; i < badCounters.length; i++) {
    threw = null;
    try {
      await b.auth.passkey.verifyAuthentication(Object.assign({}, base, {
        credential: { id: "a", publicKey: pub, counter: badCounters[i][0] },
      }));
    } catch (e) { threw = e; }
    check("verifyAuthentication rejects " + badCounters[i][1] + " with bad-counter",
          threw && /bad-counter/.test(threw.code || ""));
  }
}

// ---- verifyAuthentication BE/BS fallback when the vendor returns no info ----

async function testVerifyAuthenticationNoAuthInfoFallback() {
  var path = require.resolve("../../lib/vendor/simplewebauthn-server.cjs");
  var orig = require.cache[path].exports;
  var vendorReturn = { verified: false };                                            // no authenticationInfo
  require.cache[path].exports = Object.assign({}, orig, {
    verifyAuthenticationResponse: async function () { return vendorReturn; },
  });
  delete require.cache[require.resolve("../../lib/auth/passkey")];
  var passkey = require("../../lib/auth/passkey");
  var input = {
    response:          { id: "x" },
    expectedChallenge: "c",
    expectedOrigin:    "https://x.test",
    expectedRPID:      "x.test",
    credential:        { id: "abc", publicKey: Buffer.from("00", "hex"), counter: 0 },
  };
  try {
    var rv = await passkey.verifyAuthentication(input);
    check("verifyAuthentication defaults backupEligible=false without authenticationInfo",
          rv.backupEligible === false);
    check("verifyAuthentication defaults backupState=false without authenticationInfo",
          rv.backupState === false);
    check("verifyAuthentication preserves verified:false in the fallback",
          rv.verified === false);

    // vendor returns nullish — defensive `rv = rv || {}` synthesizes a result.
    vendorReturn = null;
    var rv2 = await passkey.verifyAuthentication(input);
    check("verifyAuthentication synthesizes a result when the vendor returns nullish",
          rv2 && rv2.backupEligible === false && rv2.backupState === false);
  } finally {
    require.cache[path].exports = orig;
    delete require.cache[require.resolve("../../lib/auth/passkey")];
  }
}

// ---- compareBackupState — all verdicts + input guards ----

function testCompareBackupState() {
  var okDiff = b.auth.passkey.compareBackupState(
    { backupEligible: true, backupState: true },
    { backupEligible: true, backupState: true });
  check("compareBackupState verdict 'ok' when flags unchanged", okDiff.verdict === "ok");
  check("compareBackupState surfaces prev/current fields",
        okDiff.prevBackupEligible === true && okDiff.currentBackupState === true);

  check("compareBackupState detects be-flipped-on",
        b.auth.passkey.compareBackupState({ backupEligible: false }, { backupEligible: true })
          .verdict === "be-flipped-on");
  check("compareBackupState detects be-flipped-off",
        b.auth.passkey.compareBackupState({ backupEligible: true }, { backupEligible: false })
          .verdict === "be-flipped-off");
  check("compareBackupState detects bs-flipped-on",
        b.auth.passkey.compareBackupState(
          { backupEligible: true, backupState: false },
          { backupEligible: true, backupState: true }).verdict === "bs-flipped-on");
  check("compareBackupState detects bs-flipped-off",
        b.auth.passkey.compareBackupState(
          { backupEligible: true, backupState: true },
          { backupEligible: true, backupState: false }).verdict === "bs-flipped-off");

  var threw = null;
  try { b.auth.passkey.compareBackupState(null, {}); } catch (e) { threw = e; }
  check("compareBackupState rejects a non-object prev",
        threw && /bad-compare-backup/.test(threw.code || ""));

  threw = null;
  try { b.auth.passkey.compareBackupState({}, "nope"); } catch (e) { threw = e; }
  check("compareBackupState rejects a non-object current",
        threw && /bad-compare-backup/.test(threw.code || ""));
}

// ---- Signal API builders (W3C draft) ----

function testSignalUnknownCredential() {
  var out = b.auth.passkey.signalUnknownCredential({ rpId: "x.test", credentialId: "AAAA" });
  check("signalUnknownCredential returns { rpId, credentialId }",
        out.rpId === "x.test" && out.credentialId === "AAAA");

  var threw = null;
  try { b.auth.passkey.signalUnknownCredential(); } catch (e) { threw = e; }
  check("signalUnknownCredential() throws missing-opts",
        threw && /missing-opts/.test(threw.code || ""));

  threw = null;
  try { b.auth.passkey.signalUnknownCredential({ credentialId: "AAAA" }); } catch (e) { threw = e; }
  check("signalUnknownCredential without rpId throws missing-rpId",
        threw && /missing-rpId/.test(threw.code || ""));

  threw = null;
  try { b.auth.passkey.signalUnknownCredential({ rpId: "x.test" }); } catch (e) { threw = e; }
  check("signalUnknownCredential without credentialId throws missing-credentialId",
        threw && /missing-credentialId/.test(threw.code || ""));

  threw = null;
  try { b.auth.passkey.signalUnknownCredential({ rpId: "x.test", credentialId: "not base64!" }); }
  catch (e) { threw = e; }
  check("signalUnknownCredential rejects a non-base64url credentialId",
        threw && /bad-credential-id/.test(threw.code || ""));
}

function testSignalAllAcceptedCredentials() {
  var out = b.auth.passkey.signalAllAcceptedCredentials({
    rpId: "x.test", userId: "AAAA", allAcceptedCredentialIds: ["BBBB", "CCCC"],
  });
  check("signalAllAcceptedCredentials returns a defensive copy of the id list",
        Array.isArray(out.allAcceptedCredentialIds) &&
        out.allAcceptedCredentialIds.length === 2 &&
        out.allAcceptedCredentialIds[0] === "BBBB");

  var threw = null;
  try { b.auth.passkey.signalAllAcceptedCredentials(); } catch (e) { threw = e; }
  check("signalAllAcceptedCredentials() throws missing-opts",
        threw && /missing-opts/.test(threw.code || ""));

  threw = null;
  try { b.auth.passkey.signalAllAcceptedCredentials({ userId: "AAAA", allAcceptedCredentialIds: [] }); }
  catch (e) { threw = e; }
  check("signalAllAcceptedCredentials without rpId throws missing-rpId",
        threw && /missing-rpId/.test(threw.code || ""));

  threw = null;
  try { b.auth.passkey.signalAllAcceptedCredentials({ rpId: "x.test", allAcceptedCredentialIds: [] }); }
  catch (e) { threw = e; }
  check("signalAllAcceptedCredentials without userId throws missing-userId",
        threw && /missing-userId/.test(threw.code || ""));

  threw = null;
  try {
    b.auth.passkey.signalAllAcceptedCredentials({
      rpId: "x.test", userId: "not base64!", allAcceptedCredentialIds: [],
    });
  } catch (e) { threw = e; }
  check("signalAllAcceptedCredentials rejects a non-base64url userId",
        threw && /bad-user-id/.test(threw.code || ""));

  threw = null;
  try {
    b.auth.passkey.signalAllAcceptedCredentials({
      rpId: "x.test", userId: "AAAA", allAcceptedCredentialIds: "not-an-array",
    });
  } catch (e) { threw = e; }
  check("signalAllAcceptedCredentials rejects a non-array id list",
        threw && /bad-accepted-list/.test(threw.code || ""));

  threw = null;
  try {
    b.auth.passkey.signalAllAcceptedCredentials({
      rpId: "x.test", userId: "AAAA", allAcceptedCredentialIds: ["OK1", "bad element!"],
    });
  } catch (e) { threw = e; }
  check("signalAllAcceptedCredentials rejects a non-base64url list element",
        threw && /bad-accepted-list/.test(threw.code || ""));
}

function testSignalCurrentUserDetails() {
  var out = b.auth.passkey.signalCurrentUserDetails({
    rpId: "x.test", userId: "AAAA", name: "alice", displayName: "Alice A",
  });
  check("signalCurrentUserDetails returns the descriptor",
        out.rpId === "x.test" && out.userId === "AAAA" &&
        out.name === "alice" && out.displayName === "Alice A");

  var threw = null;
  try { b.auth.passkey.signalCurrentUserDetails(); } catch (e) { threw = e; }
  check("signalCurrentUserDetails() throws missing-opts",
        threw && /missing-opts/.test(threw.code || ""));

  threw = null;
  try {
    b.auth.passkey.signalCurrentUserDetails({ userId: "AAAA", name: "a", displayName: "b" });
  } catch (e) { threw = e; }
  check("signalCurrentUserDetails without rpId throws missing-rpId",
        threw && /missing-rpId/.test(threw.code || ""));

  threw = null;
  try {
    b.auth.passkey.signalCurrentUserDetails({ rpId: "x.test", name: "a", displayName: "b" });
  } catch (e) { threw = e; }
  check("signalCurrentUserDetails without userId throws missing-userId",
        threw && /missing-userId/.test(threw.code || ""));

  threw = null;
  try {
    b.auth.passkey.signalCurrentUserDetails({
      rpId: "x.test", userId: "not base64!", name: "a", displayName: "b",
    });
  } catch (e) { threw = e; }
  check("signalCurrentUserDetails rejects a non-base64url userId",
        threw && /bad-user-id/.test(threw.code || ""));

  threw = null;
  try {
    b.auth.passkey.signalCurrentUserDetails({
      rpId: "x.test", userId: "AAAA", displayName: "b",
    });
  } catch (e) { threw = e; }
  check("signalCurrentUserDetails without name throws missing-name",
        threw && /missing-name/.test(threw.code || ""));

  threw = null;
  try {
    b.auth.passkey.signalCurrentUserDetails({
      rpId: "x.test", userId: "AAAA", name: "a",
    });
  } catch (e) { threw = e; }
  check("signalCurrentUserDetails without displayName throws missing-displayName",
        threw && /missing-displayName/.test(threw.code || ""));

  var longName = "n".repeat(257);
  threw = null;
  try {
    b.auth.passkey.signalCurrentUserDetails({
      rpId: "x.test", userId: "AAAA", name: longName, displayName: "b",
    });
  } catch (e) { threw = e; }
  check("signalCurrentUserDetails rejects an over-long name",
        threw && /name-too-long/.test(threw.code || ""));

  threw = null;
  try {
    b.auth.passkey.signalCurrentUserDetails({
      rpId: "x.test", userId: "AAAA", name: "a", displayName: longName,
    });
  } catch (e) { threw = e; }
  check("signalCurrentUserDetails rejects an over-long displayName",
        threw && /displayname-too-long/.test(threw.code || ""));
}

function testExportedAllowedExtensionKeys() {
  check("ALLOWED_EXTENSION_KEYS lists prf/largeBlob/credBlob",
        b.auth.passkey.ALLOWED_EXTENSION_KEYS.prf === 1 &&
        b.auth.passkey.ALLOWED_EXTENSION_KEYS.largeBlob === 1 &&
        b.auth.passkey.ALLOWED_EXTENSION_KEYS.credBlob === 1);
  check("ALLOWED_EXTENSION_KEYS is frozen",
        Object.isFrozen(b.auth.passkey.ALLOWED_EXTENSION_KEYS));
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
  await testStartRegistrationGuards();
  await testStartRegistrationDefaultsAndOptions();
  await testStartRegistrationExtensionAllowlist();
  await testStartAuthenticationHintsAndExtensions();
  await testConditionalAuthCustomHints();
  testExtensionInputBounds();
  await testVerifyRegistrationOriginValidation();
  await testVerifyRegistrationNoRegistrationInfoFallback();
  await testVerifyAuthenticationGuards();
  await testVerifyAuthenticationNoAuthInfoFallback();
  testCompareBackupState();
  testSignalUnknownCredential();
  testSignalAllAcceptedCredentials();
  testSignalCurrentUserDetails();
  testExportedAllowedExtensionKeys();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

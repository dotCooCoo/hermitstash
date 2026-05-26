"use strict";
/**
 * @module b.eat
 * @nav    Crypto
 * @title  Entity Attestation Token (EAT)
 *
 * @intro
 *   RFC 9711 Entity Attestation Token — a CWT (or JWT) profile that
 *   carries attestation claims describing the state of a device or
 *   software entity: a freshness nonce, a Universal Entity ID, OEM /
 *   hardware identifiers, debug status, software measurements, and
 *   nested submodule attestations. EAT is the token a Relying Party
 *   asks a device to produce to prove what it is and what state it is
 *   in. This module is the EAT profile over <code>b.cwt</code> — it
 *   maps the RFC 9711 claim names to their CWT claim-key integer
 *   labels and adds the attestation-specific verification.
 *
 *   <code>b.eat.sign(claims, opts)</code> takes a friendly claims
 *   object (<code>nonce</code>, <code>ueid</code>, <code>oemid</code>,
 *   <code>dbgstat</code>, <code>eat_profile</code>,
 *   <code>measurements</code>, <code>submods</code>, … plus the
 *   standard CWT claims) and signs it as a CWT.
 *
 *   <code>b.eat.verify(eat, opts)</code> verifies the CWT (signature +
 *   alg allowlist + time claims, via <code>b.cwt</code>) and then
 *   enforces the attestation contract:
 *
 *   - <strong>Nonce binding</strong> — when the Relying Party supplied
 *     a fresh <code>expectedNonce</code>, the token's
 *     <code>eat_nonce</code> (claim 10) MUST match it (constant-time
 *     compare). This is the freshness / anti-replay defense: without
 *     it a captured attestation can be replayed indefinitely.
 *   - <strong>Debug status</strong> — <code>requireDebugDisabled</code>
 *     refuses a token whose <code>dbgstat</code> is
 *     <code>enabled</code> (0) or absent; only the disabled states
 *     (1–4) pass.
 *   - <strong>Profile</strong> — <code>expectedProfile</code> pins the
 *     <code>eat_profile</code> claim.
 *
 *   Signing algorithms follow <code>b.cwt</code> / <code>b.cose</code>:
 *   ES256/384/512 + EdDSA (interoperable today) and ML-DSA-87.
 *
 * @card
 *   RFC 9711 Entity Attestation Token over b.cwt — sign / verify
 *   device + software attestation claims with verifier-nonce binding,
 *   debug-status policy, and profile pinning.
 */

var cwt = require("./cwt");
var bCrypto = require("./crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var EatError = defineClass("EatError", { alwaysPermanent: true });

// RFC 9711 / IANA CWT Claims registry claim keys.
var EAT = {                                                                            // allow:raw-byte-literal — RFC 9711 / IANA CWT claim-key labels, not byte sizes
  nonce: 10, ueid: 256, sueids: 257, oemid: 258, hwmodel: 259, hwversion: 260,         // allow:raw-byte-literal — CWT claim keys
  uptime: 261, oemboot: 262, dbgstat: 263, location: 264, eat_profile: 265,            // allow:raw-byte-literal — CWT claim keys
  submods: 266, swname: 270, swversion: 271, manifests: 272, measurements: 273,        // allow:raw-byte-literal — CWT claim keys
};
var EAT_BY_LABEL = {};
Object.keys(EAT).forEach(function (k) { EAT_BY_LABEL[EAT[k]] = k; });

// RFC 9711 §4.3.1 debug-status enumeration.
var DBGSTAT = {
  "enabled": 0, "disabled": 1, "disabled-since-boot": 2,
  "disabled-permanently": 3, "disabled-fully-and-permanently": 4,
};
var DBGSTAT_BY_VALUE = {};
Object.keys(DBGSTAT).forEach(function (k) { DBGSTAT_BY_VALUE[DBGSTAT[k]] = k; });

// Standard CWT claim labels → names (RFC 8392 §3.1.1) so EAT's
// friendly output names the standard claims alongside the EAT ones.
var STD_NAME = { 1: "iss", 2: "sub", 3: "aud", 4: "exp", 5: "nbf", 6: "iat", 7: "cti" };

function _toBuf(x) {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  if (typeof x === "string") return Buffer.from(x, "utf8");
  return null;
}

function _nonceMatches(claimValue, expected) {
  var exp = _toBuf(expected);
  if (!exp) return false;
  // eat_nonce may be a single byte string or an array of them (one per
  // verifier). Constant-time compare against each candidate.
  var candidates = Array.isArray(claimValue) ? claimValue : [claimValue];
  for (var i = 0; i < candidates.length; i++) {
    var c = _toBuf(candidates[i]);
    if (c && c.length === exp.length && bCrypto.timingSafeEqual(c, exp)) return true;
  }
  return false;
}

/**
 * @primitive b.eat.sign
 * @signature b.eat.sign(claims, opts)
 * @since     0.12.35
 * @status    stable
 * @related   b.eat.verify, b.cwt.sign
 *
 * Sign EAT attestation claims into a CWT. EAT claim names map to their
 * RFC 9711 integer labels; <code>dbgstat</code> accepts the enum name
 * (<code>"disabled-since-boot"</code>) or its integer. Standard CWT
 * claims (<code>iss</code> / <code>exp</code> / …) pass through to
 * <code>b.cwt.sign</code>.
 *
 * @opts
 *   {
 *     alg:        string,   // COSE signing alg (ES256 / EdDSA / ML-DSA-87 / …)
 *     privateKey: object,   // signing key
 *     kid?:       string,
 *     tagged?:    boolean,  // CWT tag 61
 *   }
 *
 * @example
 *   var eat = await b.eat.sign(
 *     { nonce: rpNonce, ueid: deviceUeid, oemid: oem, dbgstat: "disabled-permanently",
 *       eat_profile: "https://example.com/eat/profile-1", iat: Math.floor(Date.now()/1000) },
 *     { alg: "ES256", privateKey: deviceKey });
 */
async function sign(claims, opts) {
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    throw new EatError("eat/bad-claims", "eat.sign: claims must be a plain object");
  }
  validateOpts.requireObject(opts, "eat.sign", EatError);
  // Translate EAT claim names to their integer labels into a Map (so
  // the integer keys survive — a plain object would stringify them).
  // Standard CWT names (iss/sub/aud/exp/nbf/iat/cti) + custom keys are
  // left for b.cwt.sign to handle.
  var mapped = new Map();
  var keys = Object.keys(claims);
  for (var i = 0; i < keys.length; i++) {
    var name = keys[i];
    var value = claims[name];
    if (name === "dbgstat" && typeof value === "string") {
      if (!Object.prototype.hasOwnProperty.call(DBGSTAT, value)) {
        throw new EatError("eat/bad-dbgstat",
          "eat.sign: dbgstat must be one of " + Object.keys(DBGSTAT).join(" / ") + " (or an integer 0-4)");
      }
      value = DBGSTAT[value];
    }
    mapped.set(Object.prototype.hasOwnProperty.call(EAT, name) ? EAT[name] : name, value);
  }
  return cwt.sign(mapped, opts);
}

/**
 * @primitive b.eat.verify
 * @signature b.eat.verify(eat, opts)
 * @since     0.12.35
 * @status    stable
 * @related   b.eat.sign, b.cwt.verify
 *
 * Verify an EAT and return its attestation claims. Delegates the CWT
 * signature + algorithm-allowlist + time-claim checks to
 * <code>b.cwt.verify</code>, then enforces the attestation contract:
 * the <code>eat_nonce</code> must match <code>expectedNonce</code>
 * (when supplied — the freshness/anti-replay binding),
 * <code>requireDebugDisabled</code> refuses a non-disabled
 * <code>dbgstat</code>, and <code>expectedProfile</code> pins
 * <code>eat_profile</code>.
 *
 * @opts
 *   {
 *     algorithms:        string[],  // required — accepted COSE algs
 *     publicKey?:        object,
 *     keyResolver?:      function,
 *     expectedNonce?:    Buffer,    // require eat_nonce to match (freshness)
 *     requireDebugDisabled?: boolean,  // refuse dbgstat enabled / absent
 *     expectedProfile?:  string,    // pin eat_profile
 *     expectedIssuer?:   string,    // forwarded to b.cwt.verify
 *     expectedAudience?: string,
 *     clockSkewSec?:     number,
 *     now?:              number,
 *     externalAad?:      Buffer,
 *   }
 *
 * @example
 *   var att = await b.eat.verify(eat, { algorithms: ["ES256"], publicKey: devicePub, expectedNonce: rpNonce, requireDebugDisabled: true });
 *   // → { claims: { nonce, ueid, dbgstat: "disabled-permanently", ... }, raw: Map, alg }
 */
async function verify(eat, opts) {
  validateOpts.requireObject(opts, "eat.verify", EatError);
  var out = await cwt.verify(eat, {
    algorithms: opts.algorithms, publicKey: opts.publicKey, keyResolver: opts.keyResolver,
    expectedIssuer: opts.expectedIssuer, expectedAudience: opts.expectedAudience,
    clockSkewSec: opts.clockSkewSec, now: opts.now, externalAad: opts.externalAad,
  });
  var raw = out.raw;

  // Nonce binding — the freshness / anti-replay defense. When the RP
  // supplied a nonce, the token MUST carry a matching eat_nonce.
  if (opts.expectedNonce != null) {
    if (!raw.has(EAT.nonce)) {
      throw new EatError("eat/nonce-missing", "eat.verify: expectedNonce supplied but token has no eat_nonce claim");
    }
    if (!_nonceMatches(raw.get(EAT.nonce), opts.expectedNonce)) {
      throw new EatError("eat/nonce-mismatch", "eat.verify: eat_nonce does not match expectedNonce (stale / replayed attestation)");
    }
  }

  // Debug status — refuse a token that can't prove debug is disabled.
  if (opts.requireDebugDisabled === true) {
    var ds = raw.get(EAT.dbgstat);
    if (typeof ds !== "number" || ds < DBGSTAT.disabled) {
      throw new EatError("eat/debug-not-disabled",
        "eat.verify: requireDebugDisabled — dbgstat is " +
        (ds === undefined ? "absent" : (DBGSTAT_BY_VALUE[ds] || ds)) + ", not a disabled state");
    }
  }

  if (opts.expectedProfile != null && raw.get(EAT.eat_profile) !== opts.expectedProfile) {
    throw new EatError("eat/profile-mismatch", "eat.verify: eat_profile does not match expectedProfile");
  }

  // Build friendly claims: EAT + standard labels → names; decode the
  // dbgstat enum to its name.
  var claims = {};
  raw.forEach(function (v, k) {
    var name = Object.prototype.hasOwnProperty.call(EAT_BY_LABEL, k) ? EAT_BY_LABEL[k]
      : (Object.prototype.hasOwnProperty.call(STD_NAME, k) ? STD_NAME[k] : k);
    if (name === "dbgstat" && typeof v === "number" && Object.prototype.hasOwnProperty.call(DBGSTAT_BY_VALUE, v)) {
      v = DBGSTAT_BY_VALUE[v];
    }
    claims[name] = v;
  });

  return { claims: claims, raw: raw, alg: out.alg, protectedHeaders: out.protectedHeaders };
}

module.exports = {
  sign:        sign,
  verify:      verify,
  CLAIM_LABELS: EAT,
  DBGSTAT:     DBGSTAT,
  EatError:    EatError,
};

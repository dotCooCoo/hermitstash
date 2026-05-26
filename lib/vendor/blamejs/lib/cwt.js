"use strict";
/**
 * @module b.cwt
 * @nav    Crypto
 * @title  CBOR Web Token (CWT)
 *
 * @intro
 *   RFC 8392 CBOR Web Token — the CBOR-native counterpart to JWT, a
 *   signed claims set for constrained / IoT, FIDO attestation, and
 *   verifiable-credential contexts. A CWT is a COSE_Sign1
 *   (<code>b.cose</code>) whose payload is a deterministically-encoded
 *   CBOR claims map (<code>b.cbor</code>) — this module composes both
 *   and layers the standard-claim handling on top.
 *
 *   <code>b.cwt.sign(claims, opts)</code> accepts a friendly claims
 *   object; the standard claims are mapped to their RFC 8392 §3.1.1
 *   integer labels (<code>iss</code>=1, <code>sub</code>=2,
 *   <code>aud</code>=3, <code>exp</code>=4, <code>nbf</code>=5,
 *   <code>iat</code>=6, <code>cti</code>=7) and any other key is kept
 *   verbatim. <code>b.cwt.verify(cwt, opts)</code> verifies the COSE
 *   signature (delegating the mandatory algorithm allowlist to
 *   <code>b.cose.verify</code>), decodes the claims, and enforces the
 *   time + identity claims: a passed <code>exp</code>, a future
 *   <code>nbf</code>, an <code>iss</code> / <code>aud</code> mismatch
 *   against the expected values are each refused.
 *
 *   Signing algorithms follow <code>b.cose</code>: the classical
 *   ES256/384/512 + EdDSA (final COSE ids, interoperable today) and
 *   ML-DSA-87 (PQC-forward). The optional CWT CBOR tag (61, RFC 8392
 *   §6) wraps the COSE_Sign1 when <code>opts.tagged</code> is set;
 *   <code>verify</code> accepts tagged and untagged input.
 *
 * @card
 *   RFC 8392 CBOR Web Token — sign / verify a CBOR claims set as a
 *   COSE_Sign1, with standard-claim mapping + exp / nbf / iss / aud
 *   enforcement. Composes b.cose + b.cbor.
 */

var cose = require("./cose");
var cbor = require("./cbor");
var C = require("./constants");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var CwtError = defineClass("CwtError", { alwaysPermanent: true });

// RFC 8392 §3.1.1 standard claim labels.
var STD = { iss: 1, sub: 2, aud: 3, exp: 4, nbf: 5, iat: 6, cti: 7 };
var STD_BY_LABEL = {};
Object.keys(STD).forEach(function (k) { STD_BY_LABEL[STD[k]] = k; });

var NUMERIC_DATE_CLAIMS = { exp: true, nbf: true, iat: true };

// CWT CBOR tag (RFC 8392 §6) — 61, encoded as the 2-byte head 0xd8 0x3d.
var CWT_TAG_PREFIX = Buffer.from([0xd8, 0x3d]);                                        // allow:raw-byte-literal — CBOR tag-61 head (0xd8=tag 1-byte arg, 0x3d=61)

function _nowSec(opts) {
  var ms = (opts && typeof opts.now === "number") ? opts.now : Date.now();
  return Math.floor(ms / C.TIME.seconds(1));
}

// Read a leading CBOR tag head (major type 6) in any of its encodings;
// returns { tag, len } or null if the buffer doesn't start with a tag.
function _readTagHead(buf) {
  if (buf.length < 1 || (buf[0] >> 5) !== 6) return null;                               // allow:raw-byte-literal — CBOR major-type 6 (tag) shift
  var ai = buf[0] & 0x1f;
  if (ai < 24) return { tag: ai, len: 1 };
  if (ai === 24) return buf.length >= 2 ? { tag: buf[1], len: 2 } : null;               // allow:raw-byte-literal — CBOR additional-info threshold (RFC 8949 §3), not a size
  if (ai === 25) return buf.length >= 3 ? { tag: buf.readUInt16BE(1), len: 3 } : null;
  if (ai === 26) return buf.length >= 5 ? { tag: buf.readUInt32BE(1), len: 5 } : null;
  if (ai === 27) return buf.length >= 9 ? { tag: Number(buf.readBigUInt64BE(1)), len: 9 } : null;
  return null;                                                                          // reserved / indefinite — not a tag head we accept
}

/**
 * @primitive b.cwt.sign
 * @signature b.cwt.sign(claims, opts)
 * @since     0.12.34
 * @status    stable
 * @related   b.cwt.verify, b.cose.sign
 *
 * Sign a claims set into a CWT (a COSE_Sign1 over the CBOR-encoded
 * claims). Standard claims are mapped to their integer labels; custom
 * claims (string or integer keys) are kept as given. <code>exp</code>
 * / <code>nbf</code> / <code>iat</code> must be integer NumericDates
 * (seconds since the epoch).
 *
 * @opts
 *   {
 *     alg:        string,   // COSE signing alg (ES256 / EdDSA / ML-DSA-87 / …)
 *     privateKey: object,   // signing key (per b.cose.sign)
 *     kid?:       string,   // COSE kid header
 *     tagged?:    boolean,  // wrap in CWT CBOR tag 61 (default false)
 *     externalAad?: Buffer, // bound into the COSE signature
 *   }
 *
 * @example
 *   var cwt = await b.cwt.sign(
 *     { iss: "issuer.example", sub: "device-42", exp: Math.floor(Date.now()/1000) + 3600, scope: "telemetry" },
 *     { alg: "ES256", privateKey: ecKey, kid: "k1" });
 */
async function sign(claims, opts) {
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    throw new CwtError("cwt/bad-claims", "cwt.sign: claims must be a plain object or a Map");
  }
  validateOpts.requireObject(opts, "cwt.sign", CwtError);
  validateOpts(opts, ["alg", "privateKey", "kid", "tagged", "externalAad"], "cwt.sign");

  // Accept a plain object (string keys) OR a Map. A Map preserves
  // INTEGER claim keys verbatim — profiles like b.eat pass their
  // already-resolved integer labels through and must not have them
  // stringified.
  var source = (claims instanceof Map)
    ? claims
    : new Map(Object.keys(claims).map(function (k) { return [k, claims[k]]; }));

  var map = new Map();
  source.forEach(function (value, name) {
    if (typeof name === "string" && NUMERIC_DATE_CLAIMS[name] &&
        (typeof value !== "number" || !Number.isInteger(value) || value < 0)) {
      throw new CwtError("cwt/bad-numeric-date",
        "cwt.sign: claim '" + name + "' must be a non-negative integer NumericDate (seconds)");
    }
    map.set((typeof name === "string" && Object.prototype.hasOwnProperty.call(STD, name)) ? STD[name] : name, value);
  });

  var claimsCbor = cbor.encode(map);
  var coseSign1 = await cose.sign(claimsCbor, {
    alg: opts.alg, privateKey: opts.privateKey, kid: opts.kid, externalAad: opts.externalAad,
  });
  return opts.tagged === true ? Buffer.concat([CWT_TAG_PREFIX, coseSign1]) : coseSign1;
}

/**
 * @primitive b.cwt.verify
 * @signature b.cwt.verify(cwt, opts)
 * @since     0.12.34
 * @status    stable
 * @related   b.cwt.sign, b.cose.verify
 *
 * Verify a CWT and return its claims. The COSE signature is checked
 * via <code>b.cose.verify</code> (mandatory <code>algorithms</code>
 * allowlist), then the standard time / identity claims are enforced:
 * a passed <code>exp</code> (with <code>clockSkewSec</code> tolerance),
 * a not-yet-valid <code>nbf</code>, and — when requested — an
 * <code>iss</code> / <code>aud</code> mismatch are refused. Accepts a
 * CWT-tag-61-wrapped or bare COSE_Sign1.
 *
 * @opts
 *   {
 *     algorithms:       string[],  // required — accepted COSE algs (allowlist)
 *     publicKey?:       object,    // verification key (per b.cose.verify)
 *     keyResolver?:     function,
 *     expectedIssuer?:  string,    // require iss === this
 *     expectedAudience?: string,   // require aud to include this
 *     clockSkewSec?:    number,    // default 60
 *     now?:             number,    // override clock (ms) for testing
 *     externalAad?:     Buffer,
 *   }
 *
 * @example
 *   var out = await b.cwt.verify(cwt, { algorithms: ["ES256"], publicKey: pub, expectedIssuer: "issuer.example" });
 *   // → { claims: { iss, sub, exp, scope }, raw: Map, protectedHeaders: Map }
 */
async function verify(cwt, opts) {
  if (!Buffer.isBuffer(cwt) && !(cwt instanceof Uint8Array)) {
    throw new CwtError("cwt/bad-input", "cwt.verify: cwt must be a Buffer / Uint8Array");
  }
  validateOpts.requireObject(opts, "cwt.verify", CwtError);
  validateOpts(opts, [
    "algorithms", "publicKey", "keyResolver", "expectedIssuer",
    "expectedAudience", "clockSkewSec", "now", "externalAad",
  ], "cwt.verify");

  // Strip the optional CWT tag-61 wrapper to recover the COSE_Sign1.
  // Read the tag head generically (1 / 2 / 3 / 5 / 9-byte argument
  // forms) rather than matching only the minimal 0xd8 0x3d encoding —
  // an external CBOR encoder may emit a non-minimal but valid tag 61.
  var coseBytes = Buffer.from(cwt);
  var head = _readTagHead(coseBytes);
  if (head && head.tag === 61) coseBytes = coseBytes.subarray(head.len);                // allow:raw-byte-literal — CWT CBOR tag number (RFC 8392 §6)

  var verified = await cose.verify(coseBytes, {
    algorithms: opts.algorithms, publicKey: opts.publicKey,
    keyResolver: opts.keyResolver, externalAad: opts.externalAad,
  });

  var raw = cbor.decode(verified.payload);
  if (!(raw instanceof Map)) {
    throw new CwtError("cwt/bad-claims", "cwt.verify: claims payload is not a CBOR map");
  }

  // Time claims (NumericDate, seconds). Skew tolerance both directions.
  var skew = (typeof opts.clockSkewSec === "number" && opts.clockSkewSec >= 0) ? opts.clockSkewSec : 60;   // allow:numeric-opt-Infinity — clamped non-negative, else default / allow:raw-time-literal — clock-skew in seconds (NumericDate units), not a ms duration
  var now = _nowSec(opts);
  // A present exp / nbf MUST be a well-formed NumericDate — a non-numeric
  // value would otherwise bypass the time check entirely (a token could
  // carry exp: "whenever" and never expire). Refuse the malformed claim.
  if (raw.has(STD.exp)) {
    var exp = raw.get(STD.exp);
    if (typeof exp !== "number" || !isFinite(exp)) {
      throw new CwtError("cwt/malformed-claim", "cwt.verify: exp claim is present but not a numeric NumericDate");
    }
    if (now > exp + skew) {
      throw new CwtError("cwt/expired", "cwt.verify: token expired (exp " + exp + " < now " + now + ")");
    }
  }
  if (raw.has(STD.nbf)) {
    var nbf = raw.get(STD.nbf);
    if (typeof nbf !== "number" || !isFinite(nbf)) {
      throw new CwtError("cwt/malformed-claim", "cwt.verify: nbf claim is present but not a numeric NumericDate");
    }
    if (now < nbf - skew) {
      throw new CwtError("cwt/not-yet-valid", "cwt.verify: token not yet valid (nbf " + nbf + " > now " + now + ")");
    }
  }
  if (opts.expectedIssuer != null) {
    if (raw.get(STD.iss) !== opts.expectedIssuer) {
      throw new CwtError("cwt/issuer-mismatch", "cwt.verify: iss does not match expectedIssuer");
    }
  }
  if (opts.expectedAudience != null) {
    var aud = raw.get(STD.aud);
    var audOk = Array.isArray(aud) ? aud.indexOf(opts.expectedAudience) !== -1 : aud === opts.expectedAudience;
    if (!audOk) {
      throw new CwtError("cwt/audience-mismatch", "cwt.verify: aud does not include expectedAudience");
    }
  }

  // Build a friendly claims object (standard labels → names).
  var claims = {};
  raw.forEach(function (v, k) {
    claims[Object.prototype.hasOwnProperty.call(STD_BY_LABEL, k) ? STD_BY_LABEL[k] : k] = v;
  });

  return { claims: claims, raw: raw, alg: verified.alg, protectedHeaders: verified.protectedHeaders };
}

module.exports = {
  sign:        sign,
  verify:      verify,
  CLAIM_LABELS: STD,
  CwtError:    CwtError,
};

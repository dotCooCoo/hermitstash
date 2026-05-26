"use strict";
/**
 * @module b.cose
 * @nav    Crypto
 * @title  COSE signing (RFC 9052)
 *
 * @intro
 *   COSE_Sign1 signing and verification (RFC 9052 / 9053), composing
 *   the in-tree <code>b.cbor</code> codec for the deterministic
 *   Sig_structure encoding. COSE is the signed-statement substrate
 *   under SCITT, CWT, and C2PA — a CBOR-native counterpart to JWS.
 *
 *   <strong>Signing</strong> supports the classical COSE signature
 *   algorithms that are interoperable today — ES256 / ES384 / ES512
 *   (ECDSA) and EdDSA (Ed25519), all with final IANA algorithm ids
 *   (RFC 9053) — alongside ML-DSA-87 (FIPS 204) for PQC-forward
 *   deployments. There is no classical <em>default</em>: the caller
 *   names the algorithm and supplies the key. <strong>Verification</strong>
 *   accepts the same set, so the framework both produces COSE other
 *   implementations can read today and consumes third-party COSE.
 *
 *   <strong>Standards-maturity caveat on the PQC algorithm:</strong>
 *   the COSE algorithm identifier for ML-DSA-87 is <code>-50</code>, a
 *   <em>requested</em> (non-final) IANA assignment from
 *   draft-ietf-cose-dilithium; it may change before that draft is
 *   published, so an ML-DSA-87 COSE_Sign1 is not yet broadly
 *   interoperable — pin the identifier deliberately, re-open on IANA
 *   finalization. SLH-DSA-SHAKE-256f (the framework's default PQC
 *   signature elsewhere) has <strong>no</strong> COSE algorithm
 *   identifier registered at all (the COSE SPHINCS+ draft registers
 *   only the Category-1 'small' sets), so it cannot be represented in
 *   COSE and is not offered here. The COSE_Sign1 mechanism itself, and
 *   the classical algorithms, are stable; ML-DSA-87 is the forward-
 *   looking opt-in.
 *
 *   <strong>Verify is bounded.</strong> The COSE_Sign1 bytes and the
 *   protected-header bstr are decoded through <code>b.cbor.decode</code>
 *   (depth + size caps, indefinite-length / tag / duplicate-key
 *   refusal). The protected header is the integrity-protected one;
 *   <code>alg</code> (label 1) lives there. A <code>crit</code> (label
 *   2) listing a header label the verifier does not understand is
 *   refused (RFC 9052 §3.1) — a crit-bypass defense.
 *
 *   v1 ships COSE_Sign1 (single-signer) with an attached payload.
 *   Detached payload, COSE_Sign (multi-signer), COSE_Mac0, and
 *   COSE_Encrypt are deferred-with-condition (operator demand).
 *
 * @card
 *   COSE_Sign1 sign / verify (RFC 9052) over the in-tree CBOR codec —
 *   ML-DSA-87 signing (experimental, draft alg id) + classical verify,
 *   bounded + crit-checked. The substrate under SCITT / CWT / C2PA.
 */

var nodeCrypto = require("node:crypto");
var cbor = require("./cbor");
var bCrypto = require("./crypto");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var CoseError = defineClass("CoseError", { alwaysPermanent: true });

var COSE_SIGN1_TAG = 18;                                                               // allow:raw-byte-literal — RFC 9052 COSE_Sign1 CBOR tag
var HDR_ALG = 1;                                                                       // RFC 9052 §3.1 header label: alg
var HDR_CRIT = 2;                                                                      // header label: crit
var HDR_CONTENT_TYPE = 3;                                                              // header label: content type
var HDR_KID = 4;                                                                       // header label: kid
var HDR_CWT_CLAIMS = 15;                                                               // allow:raw-byte-literal — RFC 9597 CWT Claims header label (carries SCITT iss/sub)

// COSE algorithm identifiers. ML-DSA-87 is a NON-FINAL requested
// assignment (draft-ietf-cose-dilithium) — pinned deliberately, re-open
// on IANA finalization. The classical ECDSA / EdDSA ids are final
// (RFC 9053). SLH-DSA is intentionally absent (no registered COSE id).
var ALG_NAME_TO_ID = {
  "ML-DSA-87": -50,
  "ES256": -7, "ES384": -35, "ES512": -36, "EdDSA": -8,                                // allow:raw-byte-literal — COSE algorithm identifiers (RFC 9053), not byte sizes
};
var ALG_ID_TO_NAME = {};
Object.keys(ALG_NAME_TO_ID).forEach(function (k) { ALG_ID_TO_NAME[ALG_NAME_TO_ID[k]] = k; });

// Signable algorithms: the classical ECDSA / EdDSA set (final COSE
// ids, interoperable today) plus ML-DSA-87 (draft id, PQC-forward).
// All are accepted for VERIFY as well. There is no classical default —
// the caller names the algorithm explicitly.
var SIGNABLE = ["ML-DSA-87", "ES256", "ES384", "ES512", "EdDSA"];

// Header labels this verifier understands — a `crit` entry naming any
// other label is refused (RFC 9052 §3.1 crit-bypass defense).
var UNDERSTOOD_LABELS = [HDR_ALG, HDR_CRIT, HDR_CONTENT_TYPE, HDR_KID, HDR_CWT_CLAIMS];

function _toKeyObject(key, kind) {
  if (key && typeof key === "object" && typeof key.asymmetricKeyType === "string") return key;
  try {
    return kind === "private" ? nodeCrypto.createPrivateKey(key) : nodeCrypto.createPublicKey(key);
  } catch (e) {
    throw new CoseError("cose/bad-key", "cose: could not load " + kind + " key: " + e.message);
  }
}

function _algParamsFor(algId) {
  switch (algId) {
    case -50: return { nodeAlg: null };                                                // ML-DSA-87 (KeyObject specifies the hash)
    case -8:  return { nodeAlg: null };                                                // allow:raw-byte-literal — EdDSA COSE alg id (RFC 9053), not a size
    case -7:  return { nodeAlg: "sha256", dsaEncoding: "ieee-p1363" };                 // ES256
    case -35: return { nodeAlg: "sha384", dsaEncoding: "ieee-p1363" };                 // ES384
    case -36: return { nodeAlg: "sha512", dsaEncoding: "ieee-p1363" };                 // ES512
    default:
      throw new CoseError("cose/unknown-alg", "cose: unrecognized COSE algorithm id " + algId);
  }
}

function _bstr(x) {
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  if (typeof x === "string") return Buffer.from(x, "utf8");
  throw new CoseError("cose/bad-bytes", "cose: expected bytes (Buffer / Uint8Array / string)");
}

// Sig_structure (RFC 9052 §4.4) for COSE_Sign1:
//   [ "Signature1", body_protected (bstr), external_aad (bstr), payload (bstr) ]
// deterministically CBOR-encoded — the bytes that are signed / verified.
function _toBeSigned(protectedBstr, externalAad, payload) {
  return cbor.encode(["Signature1", protectedBstr, externalAad, payload]);
}

/**
 * @primitive b.cose.sign
 * @signature b.cose.sign(payload, opts)
 * @since     0.12.33
 * @status    stable
 * @related   b.cose.verify, b.cbor.encode
 *
 * Produce a tagged COSE_Sign1 (RFC 9052) over <code>payload</code>
 * (bytes). <code>alg</code> is one of the classical ECDSA / EdDSA
 * algorithms (final COSE ids, interoperable today) or
 * <code>"ML-DSA-87"</code> (draft id <code>-50</code>, PQC-forward).
 * <code>alg</code> is placed in the integrity-protected header.
 *
 * @opts
 *   {
 *     alg:                 string,    // "ES256" | "ES384" | "ES512" | "EdDSA" | "ML-DSA-87"
 *     privateKey:          object,    // matching KeyObject or PEM
 *     kid?:                string,    // → unprotected header label 4
 *     contentType?:        number|string, // → protected header label 3 (CoAP Content-Format uint or media-type string)
 *     externalAad?:        Buffer,    // default empty — bound into the signature
 *     unprotectedHeaders?: object,    // extra unprotected map entries (numeric keys)
 *     protectedHeaders?:   object,    // extra INTEGRITY-PROTECTED map entries (numeric keys); label 1 (alg) is reserved
 *     detached?:           boolean,   // emit a nil payload (RFC 9052 §4.1) — signature still covers it; caller transmits the payload separately
 *   }
 *
 * @example
 *   var coseSign1 = await b.cose.sign(Buffer.from("statement"), {
 *     alg: "ES256", privateKey: ecKey, kid: "key-1",
 *   });
 */
async function sign(payload, opts) {
  validateOpts.requireObject(opts, "cose.sign", CoseError);
  validateOpts(opts, ["alg", "privateKey", "kid", "contentType", "externalAad", "unprotectedHeaders", "protectedHeaders", "detached"], "cose.sign");
  if (SIGNABLE.indexOf(opts.alg) === -1) {
    throw new CoseError("cose/unsignable-alg",
      "cose.sign: alg must be one of " + SIGNABLE.join(" / ") +
      " (SLH-DSA has no COSE algorithm id and is not offered)");
  }
  if (!opts.privateKey) {
    throw new CoseError("cose/no-key", "cose.sign: opts.privateKey is required");
  }
  var algId = ALG_NAME_TO_ID[opts.alg];
  var params = _algParamsFor(algId);
  var key = _toKeyObject(opts.privateKey, "private");

  var protMap = new Map();
  protMap.set(HDR_ALG, algId);
  // Content type (RFC 9052 §3.1): a uint (CoAP Content-Format) or a
  // media-type string (tstr) — a SCITT signed statement declares its
  // payload media type as a string here.
  if (typeof opts.contentType === "number" || typeof opts.contentType === "string") {
    protMap.set(HDR_CONTENT_TYPE, opts.contentType);
  }
  // Extra integrity-protected headers (e.g. CWT_Claims label 15 for a
  // SCITT signed statement). alg (label 1) is managed via opts.alg and
  // cannot be overridden here — a caller that needs a different alg
  // names it in opts.alg.
  if (opts.protectedHeaders && typeof opts.protectedHeaders === "object") {
    var pk = opts.protectedHeaders instanceof Map
      ? Array.from(opts.protectedHeaders.keys())
      : Object.keys(opts.protectedHeaders);
    for (var pi = 0; pi < pk.length; pi++) {
      var plabel = Number(pk[pi]);
      if (plabel === HDR_ALG) {
        throw new CoseError("cose/reserved-header",
          "cose.sign: protectedHeaders must not set label 1 (alg) — pass opts.alg instead");
      }
      var pval = opts.protectedHeaders instanceof Map
        ? opts.protectedHeaders.get(pk[pi]) : opts.protectedHeaders[pk[pi]];
      protMap.set(plabel, pval);
    }
  }
  var protectedBstr = cbor.encode(protMap);

  var unprot = new Map();
  if (typeof opts.kid === "string") unprot.set(HDR_KID, Buffer.from(opts.kid, "utf8"));
  if (opts.unprotectedHeaders && typeof opts.unprotectedHeaders === "object") {
    var uk = Object.keys(opts.unprotectedHeaders);
    for (var i = 0; i < uk.length; i++) unprot.set(Number(uk[i]), opts.unprotectedHeaders[uk[i]]);
  }

  var payloadBytes = _bstr(payload);
  var externalAad = opts.externalAad == null ? Buffer.alloc(0) : _bstr(opts.externalAad);
  var toBeSigned = _toBeSigned(protectedBstr, externalAad, payloadBytes);

  // ML-DSA-87 + EdDSA: the KeyObject specifies the algorithm, so a
  // null digest name is correct. ECDSA: a digest + the IEEE-P1363
  // fixed-width signature encoding COSE mandates (RFC 9053 §2.1, not
  // ASN.1 DER).
  var signature = (params.nodeAlg === null)
    ? nodeCrypto.sign(null, toBeSigned, key)
    : nodeCrypto.sign(params.nodeAlg, toBeSigned, { key: key, dsaEncoding: params.dsaEncoding });

  // Detached payload (RFC 9052 §4.1): the COSE_Sign1 carries nil in the
  // payload slot; the signature still covers the payload (above), and the
  // caller transmits / re-supplies it out of band as externalPayload.
  var sign1 = [protectedBstr, unprot, opts.detached ? null : payloadBytes, signature];
  return cbor.encode(new cbor.Tag(COSE_SIGN1_TAG, sign1));
}

/**
 * @primitive b.cose.verify
 * @signature b.cose.verify(coseSign1, opts)
 * @since     0.12.33
 * @status    experimental
 * @related   b.cose.sign, b.cbor.decode
 *
 * Verify a COSE_Sign1 (RFC 9052) and return its payload + headers.
 * The bytes are decoded through the bounded <code>b.cbor</code> codec;
 * <code>alg</code> is read from the integrity-protected header and must
 * be in <code>opts.algorithms</code>; a <code>crit</code> header naming
 * a label the verifier does not understand is refused. Accepts ML-DSA-87
 * plus the classical ECDSA / EdDSA COSE algorithms.
 *
 * @opts
 *   {
 *     algorithms:   string[],  // required — accepted alg names (allowlist)
 *     publicKey?:   object,    // the verification key (KeyObject / PEM)
 *     keyResolver?: function,  // (protectedHeaders, unprotectedHeaders) → key
 *     externalAad?: Buffer,    // must match what was signed
 *     externalPayload?: Buffer, // required when the COSE_Sign1 payload is detached (nil); bound into the Sig_structure
 *     maxBytes?:    number,    // forwarded to b.cbor.decode
 *     maxDepth?:    number,
 *   }
 *
 * @example
 *   var out = await b.cose.verify(coseSign1, { algorithms: ["ML-DSA-87"], publicKey: pub });
 *   // → { payload: <Buffer>, alg: "ML-DSA-87", protectedHeaders: Map, unprotectedHeaders: Map }
 */
async function verify(coseSign1, opts) {
  validateOpts.requireObject(opts, "cose.verify", CoseError);
  validateOpts(opts, ["algorithms", "publicKey", "keyResolver", "externalAad", "externalPayload", "maxBytes", "maxDepth"], "cose.verify");
  if (!Array.isArray(opts.algorithms) || opts.algorithms.length === 0) {
    throw new CoseError("cose/algorithms-required",
      "cose.verify: opts.algorithms is required (no defaults — name the accepted algorithms)");
  }
  for (var ai = 0; ai < opts.algorithms.length; ai++) {
    if (!(opts.algorithms[ai] in ALG_NAME_TO_ID)) {
      throw new CoseError("cose/unknown-alg", "cose.verify: unknown algorithm '" + opts.algorithms[ai] + "'");
    }
  }
  if (!opts.publicKey && typeof opts.keyResolver !== "function") {
    throw new CoseError("cose/no-key", "cose.verify: pass publicKey or keyResolver");
  }

  var decoded = cbor.decode(_bstr(coseSign1), {
    allowedTags: [COSE_SIGN1_TAG],
    maxBytes:    opts.maxBytes,
    maxDepth:    opts.maxDepth,
  });
  // Accept tagged (18) or bare COSE_Sign1 array.
  var arr = (decoded instanceof cbor.Tag && decoded.tag === COSE_SIGN1_TAG) ? decoded.value : decoded;
  if (!Array.isArray(arr) || arr.length !== 4) {
    throw new CoseError("cose/malformed", "cose.verify: not a COSE_Sign1 (expected a 4-element array)");
  }
  var protectedBstr = arr[0];
  var unprotected = arr[1];
  var payload = arr[2];
  var signature = arr[3];
  if (!Buffer.isBuffer(protectedBstr) || !Buffer.isBuffer(signature)) {
    throw new CoseError("cose/malformed", "cose.verify: protected header and signature must be byte strings");
  }
  // Detached payload (RFC 9052 §4.1): a nil payload slot means the caller
  // must supply the payload out of band via opts.externalPayload, which
  // is then bound into the Sig_structure. Supplying externalPayload for
  // an attached (non-nil) token is ambiguous and refused.
  if (payload === null || payload === undefined) {
    if (opts.externalPayload == null) {
      throw new CoseError("cose/detached-no-payload",
        "cose.verify: COSE_Sign1 has a detached (nil) payload — pass opts.externalPayload to verify it");
    }
    payload = _bstr(opts.externalPayload);
  } else if (opts.externalPayload != null) {
    throw new CoseError("cose/payload-ambiguous",
      "cose.verify: opts.externalPayload was supplied but the COSE_Sign1 carries an attached payload");
  } else if (!Buffer.isBuffer(payload)) {
    // COSE_Sign1 payload is a bstr (RFC 9052 §4.2) — refuse a non-byte
    // payload rather than return a value that violates the documented
    // { payload: Buffer } shape.
    throw new CoseError("cose/malformed", "cose.verify: payload must be a byte string (bstr)");
  }
  // The unprotected header is a CBOR map — refuse a non-map rather
  // than silently coerce it to empty (callers read kid etc. from it).
  if (!(unprotected instanceof Map)) {
    throw new CoseError("cose/malformed", "cose.verify: unprotected header must be a CBOR map");
  }

  // Decode the protected header (bounded) — empty bstr means no protected headers.
  var protMap = protectedBstr.length === 0 ? new Map()
    : cbor.decode(protectedBstr, { maxBytes: opts.maxBytes, maxDepth: opts.maxDepth });
  if (!(protMap instanceof Map)) {
    throw new CoseError("cose/malformed", "cose.verify: protected header is not a CBOR map");
  }

  // crit-bypass defense: every label in a crit array must be one the
  // verifier understands AND must be present in the protected header.
  if (protMap.has(HDR_CRIT)) {
    var crit = protMap.get(HDR_CRIT);
    if (!Array.isArray(crit)) {
      throw new CoseError("cose/bad-crit", "cose.verify: crit (label 2) must be an array");
    }
    for (var ci = 0; ci < crit.length; ci++) {
      if (UNDERSTOOD_LABELS.indexOf(crit[ci]) === -1) {
        throw new CoseError("cose/crit-unknown",
          "cose.verify: crit lists header label " + crit[ci] + " which is not understood (RFC 9052 §3.1)");
      }
      if (!protMap.has(crit[ci])) {
        throw new CoseError("cose/crit-absent",
          "cose.verify: crit lists label " + crit[ci] + " not present in the protected header");
      }
    }
  }

  var algId = protMap.get(HDR_ALG);
  var algName = ALG_ID_TO_NAME[algId];
  if (algName === undefined) {
    throw new CoseError("cose/unknown-alg", "cose.verify: unrecognized protected alg id " + algId);
  }
  if (opts.algorithms.indexOf(algName) === -1) {
    throw new CoseError("cose/alg-not-allowed",
      "cose.verify: alg '" + algName + "' is not in the allowlist");
  }
  var params = _algParamsFor(algId);                                                    // throws cose/unknown-alg on an unrecognized id

  var key = opts.publicKey
    ? _toKeyObject(opts.publicKey, "public")
    : _toKeyObject(opts.keyResolver(protMap, unprotected), "public");

  var externalAad = opts.externalAad == null ? Buffer.alloc(0) : _bstr(opts.externalAad);
  var toBeSigned = _toBeSigned(protectedBstr, externalAad, payload);

  var ok;
  if (params.nodeAlg === null) {
    ok = nodeCrypto.verify(null, toBeSigned, key, signature);
  } else {
    ok = nodeCrypto.verify(params.nodeAlg, toBeSigned,
      { key: key, dsaEncoding: params.dsaEncoding }, signature);
  }
  if (!ok) {
    throw new CoseError("cose/bad-signature", "cose.verify: signature verification failed");
  }
  return {
    payload:             payload,
    alg:                 algName,
    protectedHeaders:    protMap,
    unprotectedHeaders:  unprotected,
  };
}

// ---- COSE_Encrypt0 (RFC 9052 §5.2) — single-recipient AEAD ----

var COSE_ENCRYPT0_TAG = 16;                                                            // allow:raw-byte-literal — RFC 9052 COSE_Encrypt0 CBOR tag
var HDR_IV = 5;                                                                        // RFC 9052 §3.1 unprotected header label: IV
var AEAD_TAG_LEN = 16;                                                                 // allow:raw-byte-literal — AEAD authentication tag length (bytes)

// AEAD algorithm: COSE id → node cipher + key / IV sizes. ChaCha20/
// Poly1305 (24) is the default; AES-GCM is opt-in (project hard-rule
// #2 forbids AES-GCM as a default).
var AEAD_NAME_TO_ID = { "ChaCha20-Poly1305": 24, "A256GCM": 3, "A128GCM": 1 };         // allow:raw-byte-literal — COSE AEAD algorithm identifiers (RFC 9053), not sizes
var AEAD_ID_TO_NAME = {};
Object.keys(AEAD_NAME_TO_ID).forEach(function (k) { AEAD_ID_TO_NAME[AEAD_NAME_TO_ID[k]] = k; });

function _aeadParams(algId) {
  switch (algId) {
    case 24: return { cipher: "chacha20-poly1305", keyLen: 32, ivLen: 12 };            // allow:raw-byte-literal — ChaCha20/Poly1305 key+IV sizes
    case 3:  return { cipher: "aes-256-gcm",      keyLen: 32, ivLen: 12 };             // allow:raw-byte-literal — AES-256-GCM key+IV sizes
    case 1:  return { cipher: "aes-128-gcm",      keyLen: 16, ivLen: 12 };             // allow:raw-byte-literal — AES-128-GCM key+IV sizes
    default:
      throw new CoseError("cose/unknown-alg", "cose: unrecognized AEAD COSE alg id " + algId);
  }
}

// Enc_structure (§5.3) = [ "Encrypt0", body_protected (bstr), external_aad (bstr) ]
// — deterministically CBOR-encoded, used as the AEAD associated data.
function _encStructure(protectedBstr, externalAad) {
  return cbor.encode(["Encrypt0", protectedBstr, externalAad]);
}

/**
 * @primitive b.cose.encrypt0
 * @signature b.cose.encrypt0(plaintext, opts)
 * @since     0.12.36
 * @status    stable
 * @related   b.cose.decrypt0, b.cose.sign
 *
 * Encrypt bytes into a tagged COSE_Encrypt0 (RFC 9052 §5.2), a
 * single-recipient AEAD container where the recipient already holds
 * the symmetric key (direct mode). Default algorithm is
 * <code>ChaCha20-Poly1305</code>; <code>A256GCM</code> / <code>A128GCM</code>
 * are opt-in. The Enc_structure is bound as the AEAD associated data,
 * and the authentication tag is appended to the ciphertext per COSE.
 *
 * @opts
 *   {
 *     alg:        string,   // "ChaCha20-Poly1305" (default) | "A256GCM" | "A128GCM"
 *     key:        Buffer,   // symmetric key (32 bytes for ChaCha/A256GCM, 16 for A128GCM)
 *     iv?:        Buffer,   // 12-byte IV (random if omitted)
 *     externalAad?: Buffer, // bound into the AEAD tag
 *     unprotectedHeaders?: object,
 *   }
 *
 * @example
 *   var enc = b.cose.encrypt0(Buffer.from("secret"), { alg: "ChaCha20-Poly1305", key: k });
 */
function encrypt0(plaintext, opts) {
  validateOpts.requireObject(opts, "cose.encrypt0", CoseError);
  validateOpts(opts, ["alg", "key", "iv", "externalAad", "unprotectedHeaders"], "cose.encrypt0");
  var alg = opts.alg || "ChaCha20-Poly1305";
  if (!(alg in AEAD_NAME_TO_ID)) {
    throw new CoseError("cose/unknown-alg", "cose.encrypt0: alg must be one of " + Object.keys(AEAD_NAME_TO_ID).join(" / "));
  }
  var algId = AEAD_NAME_TO_ID[alg];
  var p = _aeadParams(algId);
  var key = _bstr(opts.key);
  if (key.length !== p.keyLen) throw new CoseError("cose/bad-key", "cose.encrypt0: " + alg + " requires a " + p.keyLen + "-byte key");
  var iv = opts.iv != null ? _bstr(opts.iv) : nodeCrypto.randomBytes(p.ivLen);
  if (iv.length !== p.ivLen) throw new CoseError("cose/bad-iv", "cose.encrypt0: " + alg + " requires a " + p.ivLen + "-byte IV");

  var protMap = new Map(); protMap.set(HDR_ALG, algId);
  var protectedBstr = cbor.encode(protMap);
  var aad = _encStructure(protectedBstr, opts.externalAad == null ? Buffer.alloc(0) : _bstr(opts.externalAad));

  var cipher = nodeCrypto.createCipheriv(p.cipher, key, iv, { authTagLength: AEAD_TAG_LEN });
  cipher.setAAD(aad);
  var ct = Buffer.concat([cipher.update(_bstr(plaintext)), cipher.final()]);
  var ciphertext = Buffer.concat([ct, cipher.getAuthTag()]);                            // COSE appends the auth tag to the ciphertext

  var unprot = new Map(); unprot.set(HDR_IV, iv);
  if (opts.unprotectedHeaders && typeof opts.unprotectedHeaders === "object") {
    var uk = Object.keys(opts.unprotectedHeaders);
    for (var i = 0; i < uk.length; i++) {
      var label = Number(uk[i]);
      // The IV (label 5) is managed via opts.iv and must match the IV
      // the AEAD used — refuse an override that would emit a token whose
      // stored IV disagrees with the one it was encrypted under.
      if (label === HDR_IV) {
        throw new CoseError("cose/reserved-header",
          "cose.encrypt0: unprotectedHeaders must not set label 5 (IV) — pass opts.iv instead");
      }
      unprot.set(label, opts.unprotectedHeaders[uk[i]]);
    }
  }
  return cbor.encode(new cbor.Tag(COSE_ENCRYPT0_TAG, [protectedBstr, unprot, ciphertext]));
}

/**
 * @primitive b.cose.decrypt0
 * @signature b.cose.decrypt0(coseEncrypt0, opts)
 * @since     0.12.36
 * @status    stable
 * @related   b.cose.encrypt0
 *
 * Decrypt a COSE_Encrypt0 and return the plaintext. The algorithm is
 * read from the protected header and must be in
 * <code>opts.algorithms</code>; the Enc_structure is reconstructed as
 * the AEAD associated data and authentication failure (wrong key /
 * tampered ciphertext or AAD) is refused.
 *
 * @opts
 *   {
 *     key:        Buffer,    // symmetric key
 *     algorithms: string[],  // required — accepted AEAD algs (allowlist)
 *     externalAad?: Buffer,  // must match what was encrypted
 *     maxBytes?:  number,
 *     maxDepth?:  number,
 *   }
 *
 * @example
 *   var pt = b.cose.decrypt0(enc, { key: k, algorithms: ["ChaCha20-Poly1305"] }).plaintext;
 */
function decrypt0(coseEncrypt0, opts) {
  validateOpts.requireObject(opts, "cose.decrypt0", CoseError);
  validateOpts(opts, ["key", "algorithms", "externalAad", "maxBytes", "maxDepth"], "cose.decrypt0");
  if (!Array.isArray(opts.algorithms) || opts.algorithms.length === 0) {
    throw new CoseError("cose/algorithms-required", "cose.decrypt0: opts.algorithms is required (no defaults — name the accepted algorithms)");
  }
  var decoded = cbor.decode(_bstr(coseEncrypt0), { allowedTags: [COSE_ENCRYPT0_TAG], maxBytes: opts.maxBytes, maxDepth: opts.maxDepth });
  var arr = (decoded instanceof cbor.Tag && decoded.tag === COSE_ENCRYPT0_TAG) ? decoded.value : decoded;
  if (!Array.isArray(arr) || arr.length !== 3) {
    throw new CoseError("cose/malformed", "cose.decrypt0: not a COSE_Encrypt0 (expected a 3-element array)");
  }
  var protectedBstr = arr[0], unprotected = arr[1], ciphertext = arr[2];
  if (!Buffer.isBuffer(protectedBstr) || !Buffer.isBuffer(ciphertext)) {
    throw new CoseError("cose/malformed", "cose.decrypt0: protected header and ciphertext must be byte strings");
  }
  if (!(unprotected instanceof Map)) {
    throw new CoseError("cose/malformed", "cose.decrypt0: unprotected header must be a CBOR map");
  }
  var protMap = protectedBstr.length === 0 ? new Map()
    : cbor.decode(protectedBstr, { maxBytes: opts.maxBytes, maxDepth: opts.maxDepth });
  if (!(protMap instanceof Map)) {
    throw new CoseError("cose/malformed", "cose.decrypt0: protected header is not a CBOR map");
  }
  var algId = protMap.get(HDR_ALG);
  var algName = AEAD_ID_TO_NAME[algId];
  if (algName === undefined) {
    throw new CoseError("cose/unknown-alg", "cose.decrypt0: unrecognized AEAD alg id " + algId);
  }
  if (opts.algorithms.indexOf(algName) === -1) {
    throw new CoseError("cose/alg-not-allowed", "cose.decrypt0: alg '" + algName + "' is not in the allowlist");
  }
  var p = _aeadParams(algId);
  var key = _bstr(opts.key);
  if (key.length !== p.keyLen) throw new CoseError("cose/bad-key", "cose.decrypt0: " + algName + " requires a " + p.keyLen + "-byte key");
  var iv = unprotected.get(HDR_IV);
  if (!Buffer.isBuffer(iv) || iv.length !== p.ivLen) {
    throw new CoseError("cose/bad-iv", "cose.decrypt0: missing or wrong-length IV (unprotected label 5)");
  }
  if (ciphertext.length < AEAD_TAG_LEN) {
    throw new CoseError("cose/malformed", "cose.decrypt0: ciphertext shorter than the AEAD tag");
  }
  var tag = ciphertext.subarray(ciphertext.length - AEAD_TAG_LEN);
  var ct = ciphertext.subarray(0, ciphertext.length - AEAD_TAG_LEN);
  var aad = _encStructure(protectedBstr, opts.externalAad == null ? Buffer.alloc(0) : _bstr(opts.externalAad));

  var decipher = nodeCrypto.createDecipheriv(p.cipher, key, iv, { authTagLength: AEAD_TAG_LEN });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  var pt;
  try {
    pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch (_e) {
    throw new CoseError("cose/decrypt-failed", "cose.decrypt0: AEAD authentication failed (wrong key, tampered ciphertext, or AAD mismatch)");
  }
  return { plaintext: pt, alg: algName, protectedHeaders: protMap, unprotectedHeaders: unprotected };
}

// ---- COSE_Mac0 (RFC 9052 §6.2) — single shared-key MAC ----

var COSE_MAC0_TAG = 17;                                                       // allow:raw-byte-literal — RFC 9052 COSE_Mac0 CBOR tag
// HMAC algorithms (RFC 9053 §3.1). Only the full-length tags are offered —
// the truncated HMAC 256/64 (id 4) is omitted. HMAC is symmetric, so its
// post-quantum strength is fine; these are the COSE-standard MAC algs.
var HMAC_NAME_TO_ID = { "HMAC-256/256": 5, "HMAC-384/384": 6, "HMAC-512/512": 7 };   // allow:raw-byte-literal — COSE HMAC algorithm ids (RFC 9053)
var HMAC_ID_TO_NAME = {};
Object.keys(HMAC_NAME_TO_ID).forEach(function (k) { HMAC_ID_TO_NAME[HMAC_NAME_TO_ID[k]] = k; });
function _hmacHash(algId) {
  switch (algId) {
    case 5: return "sha256";
    case 6: return "sha384";
    case 7: return "sha512";
    default: throw new CoseError("cose/unknown-alg", "cose: unrecognized HMAC COSE alg id " + algId);
  }
}

// MAC_structure (§6.3) = [ "MAC0", body_protected (bstr), external_aad (bstr), payload (bstr) ].
function _macStructure(protectedBstr, externalAad, payload) {
  return cbor.encode(["MAC0", protectedBstr, externalAad, payload]);
}

/**
 * @primitive b.cose.mac0
 * @signature b.cose.mac0(payload, opts)
 * @since     0.12.47
 * @status    stable
 * @related   b.cose.macVerify0, b.cose.sign
 *
 * Produce a tagged COSE_Mac0 (RFC 9052 §6.2) — a single shared-key MAC
 * over <code>payload</code>. The MAC is HMAC-SHA-256 / 384 / 512 (the
 * COSE-standard MAC algorithms; HMAC is symmetric, so post-quantum
 * strength is preserved). Use when both parties hold a shared key (e.g.
 * an ECDH-derived key) and a non-repudiable signature is not wanted.
 * <code>detached: true</code> emits a nil payload, verified later with
 * <code>opts.externalPayload</code>.
 *
 * @opts
 *   {
 *     alg:        string,   // "HMAC-256/256" | "HMAC-384/384" | "HMAC-512/512"
 *     key:        Buffer,   // shared symmetric key
 *     externalAad?: Buffer, // bound into the MAC
 *     detached?:  boolean,  // emit a nil payload (caller re-supplies it on verify)
 *     unprotectedHeaders?: object,
 *   }
 *
 * @example
 *   var mac = b.cose.mac0(Buffer.from("data"), { alg: "HMAC-256/256", key: sharedKey });
 */
function mac0(payload, opts) {
  validateOpts.requireObject(opts, "cose.mac0", CoseError);
  validateOpts(opts, ["alg", "key", "externalAad", "detached", "unprotectedHeaders"], "cose.mac0");
  if (!(opts.alg in HMAC_NAME_TO_ID)) {
    throw new CoseError("cose/unsignable-alg", "cose.mac0: alg must be one of " + Object.keys(HMAC_NAME_TO_ID).join(" / "));
  }
  var key = _bstr(opts.key);
  var algId = HMAC_NAME_TO_ID[opts.alg];
  var protMap = new Map();
  protMap.set(HDR_ALG, algId);
  var protectedBstr = cbor.encode(protMap);

  var unprot = new Map();
  if (opts.unprotectedHeaders && typeof opts.unprotectedHeaders === "object") {
    var uk = Object.keys(opts.unprotectedHeaders);
    for (var i = 0; i < uk.length; i++) unprot.set(Number(uk[i]), opts.unprotectedHeaders[uk[i]]);
  }

  var payloadBytes = _bstr(payload);
  var externalAad = opts.externalAad == null ? Buffer.alloc(0) : _bstr(opts.externalAad);
  var tag = nodeCrypto.createHmac(_hmacHash(algId), key).update(_macStructure(protectedBstr, externalAad, payloadBytes)).digest();

  var mac0arr = [protectedBstr, unprot, opts.detached ? null : payloadBytes, tag];
  return cbor.encode(new cbor.Tag(COSE_MAC0_TAG, mac0arr));
}

/**
 * @primitive b.cose.macVerify0
 * @signature b.cose.macVerify0(coseMac0, opts)
 * @since     0.12.47
 * @status    stable
 * @related   b.cose.mac0
 *
 * Verify a COSE_Mac0 (RFC 9052 §6.2) and return its payload. The HMAC
 * tag is recomputed over the MAC_structure and compared in constant
 * time; the <code>alg</code> from the protected header must be in
 * <code>opts.algorithms</code>. A detached (nil) payload is supplied via
 * <code>opts.externalPayload</code>.
 *
 * @opts
 *   {
 *     algorithms:  string[],  // required — accepted HMAC alg names (allowlist)
 *     key:         Buffer,    // the shared symmetric key
 *     externalAad?: Buffer,
 *     externalPayload?: Buffer, // required for a detached payload
 *     maxBytes?:   number,
 *     maxDepth?:   number,
 *   }
 *
 * @example
 *   var out = b.cose.macVerify0(mac, { algorithms: ["HMAC-256/256"], key: sharedKey });
 *   // → { payload: <Buffer>, alg: "HMAC-256/256", protectedHeaders: Map, unprotectedHeaders: Map }
 */
function macVerify0(coseMac0, opts) {
  validateOpts.requireObject(opts, "cose.macVerify0", CoseError);
  validateOpts(opts, ["algorithms", "key", "externalAad", "externalPayload", "maxBytes", "maxDepth"], "cose.macVerify0");
  if (!Array.isArray(opts.algorithms) || opts.algorithms.length === 0) {
    throw new CoseError("cose/algorithms-required", "cose.macVerify0: opts.algorithms is required");
  }
  for (var ai = 0; ai < opts.algorithms.length; ai++) {
    if (!(opts.algorithms[ai] in HMAC_NAME_TO_ID)) {
      throw new CoseError("cose/unknown-alg", "cose.macVerify0: unknown algorithm '" + opts.algorithms[ai] + "'");
    }
  }
  if (opts.key == null) throw new CoseError("cose/no-key", "cose.macVerify0: opts.key is required");
  var key = _bstr(opts.key);

  var decoded = cbor.decode(_bstr(coseMac0), { allowedTags: [COSE_MAC0_TAG], maxBytes: opts.maxBytes, maxDepth: opts.maxDepth });
  var arr = (decoded instanceof cbor.Tag && decoded.tag === COSE_MAC0_TAG) ? decoded.value : decoded;
  if (!Array.isArray(arr) || arr.length !== 4) {
    throw new CoseError("cose/malformed", "cose.macVerify0: not a COSE_Mac0 (expected a 4-element array)");
  }
  var protectedBstr = arr[0];
  var unprotected = arr[1];
  var payload = arr[2];
  var tag = arr[3];
  if (!Buffer.isBuffer(protectedBstr) || !Buffer.isBuffer(tag)) {
    throw new CoseError("cose/malformed", "cose.macVerify0: protected header and tag must be byte strings");
  }
  if (!(unprotected instanceof Map)) {
    throw new CoseError("cose/malformed", "cose.macVerify0: unprotected header must be a CBOR map");
  }
  if (payload === null || payload === undefined) {
    if (opts.externalPayload == null) {
      throw new CoseError("cose/detached-no-payload", "cose.macVerify0: detached (nil) payload — pass opts.externalPayload");
    }
    payload = _bstr(opts.externalPayload);
  } else if (opts.externalPayload != null) {
    throw new CoseError("cose/payload-ambiguous", "cose.macVerify0: externalPayload supplied but the COSE_Mac0 carries an attached payload");
  } else if (!Buffer.isBuffer(payload)) {
    throw new CoseError("cose/malformed", "cose.macVerify0: payload must be a byte string (bstr)");
  }

  var protMap = protectedBstr.length === 0 ? new Map()
    : cbor.decode(protectedBstr, { maxBytes: opts.maxBytes, maxDepth: opts.maxDepth });
  if (!(protMap instanceof Map)) {
    throw new CoseError("cose/malformed", "cose.macVerify0: protected header is not a CBOR map");
  }
  // crit-bypass defense (RFC 9052 §3.1) — same as b.cose.verify: every
  // label a crit array names must be one this verifier understands AND
  // be present in the protected header.
  if (protMap.has(HDR_CRIT)) {
    var crit = protMap.get(HDR_CRIT);
    if (!Array.isArray(crit)) {
      throw new CoseError("cose/bad-crit", "cose.macVerify0: crit (label 2) must be an array");
    }
    for (var ci = 0; ci < crit.length; ci++) {
      if (UNDERSTOOD_LABELS.indexOf(crit[ci]) === -1) {
        throw new CoseError("cose/crit-unknown",
          "cose.macVerify0: crit lists header label " + crit[ci] + " which is not understood (RFC 9052 §3.1)");
      }
      if (!protMap.has(crit[ci])) {
        throw new CoseError("cose/crit-absent",
          "cose.macVerify0: crit lists label " + crit[ci] + " not present in the protected header");
      }
    }
  }
  var algId = protMap.get(HDR_ALG);
  var algName = HMAC_ID_TO_NAME[algId];
  if (algName === undefined) {
    throw new CoseError("cose/unknown-alg", "cose.macVerify0: unrecognized protected MAC alg id " + algId);
  }
  if (opts.algorithms.indexOf(algName) === -1) {
    throw new CoseError("cose/alg-not-allowed", "cose.macVerify0: alg '" + algName + "' is not in the allowlist");
  }

  var externalAad = opts.externalAad == null ? Buffer.alloc(0) : _bstr(opts.externalAad);
  var expected = nodeCrypto.createHmac(_hmacHash(algId), key).update(_macStructure(protectedBstr, externalAad, payload)).digest();
  if (!bCrypto.timingSafeEqual(expected, tag)) {
    throw new CoseError("cose/bad-tag", "cose.macVerify0: MAC tag verification failed");
  }
  return { payload: payload, alg: algName, protectedHeaders: protMap, unprotectedHeaders: unprotected };
}

// ---- COSE_Key (RFC 9052 §7 / RFC 9053 §7) → KeyObject ----

// COSE_Key EC2 curve identifiers (RFC 9053 §7.1) → JWK crv names. Only
// the curves b.cose.verify has an algorithm for are accepted: P-256
// (ES256), P-384 (ES384), P-521 (ES512). secp256k1 is intentionally
// absent — there is no ES256K path here, so importing one would let a
// secp256k1 key be verified under ES256, breaking the COSE alg/curve
// binding (RFC 9053). Re-add with an explicit ES256K algorithm.
var COSE_EC2_CRV = { 1: "P-256", 2: "P-384", 3: "P-521" };
var COSE_KTY_OKP = 1;
var COSE_KTY_EC2 = 2;
var COSE_OKP_ED25519 = 6;                                                    // allow:raw-byte-literal — COSE OKP Ed25519 crv id (RFC 9053)

function _coseKeyBytes(v, what) {
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v);
  throw new CoseError("cose/bad-cose-key", "cose.importKey: COSE_Key " + what + " must be a byte string");
}

/**
 * @primitive b.cose.importKey
 * @signature b.cose.importKey(coseKey)
 * @since     0.12.45
 * @status    stable
 * @related   b.cose.verify, b.cbor.decode
 *
 * Import a COSE_Key (RFC 9052 §7) — a CBOR map keyed by integer labels —
 * as a <code>node:crypto</code> public KeyObject for
 * <code>b.cose.verify</code>. Accepts the EC2 (<code>kty</code> 2:
 * P-256 / P-384 / P-521) and OKP (<code>kty</code> 1: Ed25519) key
 * types — the curves <code>b.cose.verify</code> has an algorithm for;
 * the curve is allowlisted, so an unexpected key type (including
 * secp256k1, which has no ES256K path here) is refused rather than
 * imported. The verification key embedded in an mdoc MSO or a COSE_Key
 * header is consumed this way.
 *
 * @example
 *   var key = b.cose.importKey(coseKeyMap);            // → public KeyObject
 *   var out = await b.cose.verify(sign1, { algorithms: ["ES256"], publicKey: key });
 */
function importKey(coseKey) {
  if (!(coseKey instanceof Map)) {
    if (coseKey && typeof coseKey === "object" && !Array.isArray(coseKey)) {
      var m = new Map();
      Object.keys(coseKey).forEach(function (k) { m.set(Number(k), coseKey[k]); });
      coseKey = m;
    } else {
      throw new CoseError("cose/bad-cose-key", "cose.importKey: expected a COSE_Key map");
    }
  }
  var kty = coseKey.get(1);
  var x = _coseKeyBytes(coseKey.get(-2), "x");
  var jwk;
  if (kty === COSE_KTY_OKP) {
    if (coseKey.get(-1) !== COSE_OKP_ED25519) {
      throw new CoseError("cose/unsupported-key", "cose.importKey: only OKP curve Ed25519 is supported");
    }
    jwk = { kty: "OKP", crv: "Ed25519", x: x.toString("base64url") };
  } else if (kty === COSE_KTY_EC2) {
    var crvName = COSE_EC2_CRV[coseKey.get(-1)];
    if (!crvName) throw new CoseError("cose/unsupported-key", "cose.importKey: unsupported EC2 curve id " + coseKey.get(-1));
    var y = _coseKeyBytes(coseKey.get(-3), "y");
    jwk = { kty: "EC", crv: crvName, x: x.toString("base64url"), y: y.toString("base64url") };
  } else {
    throw new CoseError("cose/unsupported-key", "cose.importKey: kty must be OKP (1) or EC2 (2), got " + kty);
  }
  try { return nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }); }
  catch (e) { throw new CoseError("cose/bad-cose-key", "cose.importKey: could not import COSE_Key: " + ((e && e.message) || e)); }
}

module.exports = {
  sign:        sign,
  verify:      verify,
  encrypt0:    encrypt0,
  decrypt0:    decrypt0,
  mac0:        mac0,
  macVerify0:  macVerify0,
  importKey:   importKey,
  ALGORITHMS:  ALG_NAME_TO_ID,
  MAC_ALGORITHMS: HMAC_NAME_TO_ID,
  COSE_MAC0_TAG: COSE_MAC0_TAG,
  AEAD_ALGORITHMS: AEAD_NAME_TO_ID,
  COSE_SIGN1_TAG: COSE_SIGN1_TAG,
  COSE_ENCRYPT0_TAG: COSE_ENCRYPT0_TAG,
  CoseError:   CoseError,
};

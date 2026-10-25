// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.crypto.hpke.pq
 * @nav        Crypto
 * @title      HPKE-PQ (experimental)
 * @slug       crypto-hpke-pq
 *
 * @intro
 *   RFC 9180 HPKE with ML-KEM-1024, under the registered HPKE codepoints of
 *   the two post-quantum HPKE drafts. Envelopes interoperate with any
 *   implementation of the same draft and suite: the key schedule is the
 *   RFC 9180 one (LabeledExtract / LabeledExpand over
 *   `suite_id = "HPKE" || kem_id || kdf_id || aead_id`, or the
 *   single-stage LabeledDerive for SHAKE256), the KEM is FIPS 203
 *   ML-KEM-1024, and the AEAD nonce is `base_nonce` XOR the sequence number.
 *
 *   - **`b.crypto.hpke.pq.connolly`**: draft-connolly-cfrg-hpke-mlkem-04.
 *     KEM `ML-KEM-1024` (0x0042) with the RFC 9180 two-stage KDFs. Default
 *     suite: ML-KEM-1024, HKDF-SHA512 (0x0003), ChaCha20Poly1305 (0x0003).
 *   - **`b.crypto.hpke.pq.wg`**: draft-ietf-hpke-pq-05. KEM `ML-KEM-1024`
 *     (0x0042) or `MLKEM1024-P384` (0x0051), with the RFC 9180 two-stage
 *     KDFs or the single-stage `SHAKE256` (0x0011). Default suite:
 *     ML-KEM-1024, SHAKE256, ChaCha20Poly1305.
 *
 *   The identifiers are those of the IANA HPKE registry,
 *   https://www.iana.org/assignments/hpke/hpke.xhtml. Both namespaces
 *   accept KDFs `HKDF-SHA384` and `HKDF-SHA512` and AEADs
 *   `AES-256-GCM`, `ChaCha20Poly1305` and `Export-only` (the last for the
 *   secret-export interface only). `HKDF-SHA256`, `SHAKE128`, `AES-128-GCM`,
 *   ML-KEM-512 / ML-KEM-768 and the other registered suites are refused with
 *   `crypto-hpke-pq/unsupported-suite`. `TurboSHAKE128` and `TurboSHAKE256`
 *   are refused the same way: `node:crypto` offers them only through the
 *   asynchronous, experimental Web Crypto `subtle.digest`, and `seal` /
 *   `open` are synchronous.
 *
 *   Under one explicit suite the two drafts specify the same construction,
 *   so an envelope sealed by `connolly` with `kdf: "HKDF-SHA512"` opens
 *   under `wg` with `kdf: "HKDF-SHA512"`. Under their defaults the KDFs
 *   differ, so the `suite_id` differs and an envelope does not open under
 *   the other namespace's default.
 *
 *   Keys are the HPKE serialized forms: an ML-KEM-1024 public key is the
 *   1568-byte encapsulation key and its private key is the 64-byte seed
 *   `(d, z)`; an MLKEM1024-P384 public key is 1665 bytes and its private
 *   key is a 32-byte seed. An ML-KEM-1024 key may also be passed as a PEM
 *   string or a `KeyObject`, which includes the pair from
 *   `b.crypto.hpke.generateKeyPair`.
 *
 *   The single-shot `seal` / `open` run one message per encapsulation.
 *   `setupSender` / `setupRecipient` return the RFC 9180 context for a
 *   sequence of messages and for `export`. The KEMs define no
 *   AuthEncap, so the auth and auth-psk modes are not offered; the psk mode
 *   is, through `psk` and `pskId`. An empty `psk` and `pskId` select base
 *   mode, the same as omitting them, and only one of the two non-empty is
 *   refused with `crypto-hpke-pq/inconsistent-psk`. A `psk` shorter than 32
 *   bytes (counted after UTF-8 encoding for a string) is refused with
 *   `crypto-hpke-pq/weak-psk`, following the RFC 9180 sec. 5.1.2 floor of
 *   32 bytes of entropy.
 *
 *   An error surfaces as an `HpkeError` with a `crypto-hpke-pq/` code:
 *   `bad-key`, `bad-opt`, `unsupported-suite`, `open-failed`,
 *   `inconsistent-psk`, `weak-psk`, `input-length`, `export-length`,
 *   `message-limit` or `export-only`, and `failed` for any other error from
 *   the vendored implementation. `input-length` applies only to the
 *   single-stage SHAKE256 KDF, which caps `info`, `psk` and `pskId` at
 *   65,535 bytes. The single-shot `seal` and `open` overwrite the context
 *   key material and the KEM shared secret with zeros before they return,
 *   and the setups overwrite the KEM shared secret once the key schedule has
 *   run. Each single-shot call and each setup emits a
 *   `system.hpke.pq.seal`, `system.hpke.pq.open` or `system.hpke.pq.setup`
 *   audit row naming the draft and suite; a tag failure emits
 *   `system.hpke.pq.open` with outcome `failure`.
 *
 *   Both drafts are Internet-Drafts, so the namespace is experimental and
 *   the draft revisions in `connolly.label` and `wg.label` name the text
 *   this code follows. The construction runs on the vendored
 *   `@blamejs/pki` HPKE implementation, which the draft-ietf-hpke-pq-05
 *   test vectors pin.
 *
 * @card
 *   RFC 9180 HPKE with ML-KEM-1024 under the IANA HPKE registry codepoints, following draft-connolly-cfrg-hpke-mlkem-04 and draft-ietf-hpke-pq-05, pinned by the published test vectors.
 */

var nodeCrypto   = require("node:crypto");
var C            = require("./constants");
var lazyRequire  = require("./lazy-require");
var validateOpts = require("./validate-opts");
var pki          = require("./vendor/blamejs-pki.cjs");
var { HpkeError } = require("./framework-error");

var _err = HpkeError.factory;

var observability = lazyRequire(function () { return require("./observability"); });
var audit         = lazyRequire(function () { return require("./audit"); });

var CONNOLLY_LABEL = "draft-connolly-cfrg-hpke-mlkem-04";
var WG_LABEL       = "draft-ietf-hpke-pq-05";

var MIN_PSK_BYTES  = C.BYTES.bytes(32);

// registry: https://www.iana.org/assignments/hpke/hpke.xhtml
var KEM_IDS = Object.freeze({
  "ML-KEM-1024":    0x0042,
  "MLKEM1024-P384": 0x0051,
});
// registry: https://www.iana.org/assignments/hpke/hpke.xhtml
var KDF_IDS = Object.freeze({
  "HKDF-SHA384": 0x0002,
  "HKDF-SHA512": 0x0003,
  "SHAKE256":    0x0011,
});
// registry: https://www.iana.org/assignments/hpke/hpke.xhtml
var AEAD_IDS = Object.freeze({
  "AES-256-GCM":      0x0002,
  "ChaCha20Poly1305": 0x0003,
  "Export-only":      0xFFFF,
});

var CONNOLLY = Object.freeze({
  name:  "connolly",
  label: CONNOLLY_LABEL,
  supported: Object.freeze({
    kem:  Object.freeze(["ML-KEM-1024"]),
    kdf:  Object.freeze(["HKDF-SHA384", "HKDF-SHA512"]),
    aead: Object.freeze(["AES-256-GCM", "ChaCha20Poly1305", "Export-only"]),
  }),
  defaults: Object.freeze({ kem: "ML-KEM-1024", kdf: "HKDF-SHA512", aead: "ChaCha20Poly1305" }),
  takesKem: false,
});

var WG = Object.freeze({
  name:  "wg",
  label: WG_LABEL,
  supported: Object.freeze({
    kem:  Object.freeze(["ML-KEM-1024", "MLKEM1024-P384"]),
    kdf:  Object.freeze(["HKDF-SHA384", "HKDF-SHA512", "SHAKE256"]),
    aead: Object.freeze(["AES-256-GCM", "ChaCha20Poly1305", "Export-only"]),
  }),
  defaults: Object.freeze({ kem: "ML-KEM-1024", kdf: "SHAKE256", aead: "ChaCha20Poly1305" }),
  takesKem: true,
});

var SUITE_KEYS     = ["kdf", "aead", "psk", "pskId", "info"];
var SEAL_KEYS      = ["recipientPubKey", "plaintext", "aad"].concat(SUITE_KEYS);
var OPEN_KEYS      = ["privateKey", "enc", "ciphertext", "aad"].concat(SUITE_KEYS);
var SENDER_KEYS    = ["recipientPubKey"].concat(SUITE_KEYS);
var RECIPIENT_KEYS = ["privateKey", "enc"].concat(SUITE_KEYS);

var PKI_CODES = Object.freeze({
  "hpke/bad-key":          "crypto-hpke-pq/bad-key",
  "hpke/bad-input":        "crypto-hpke-pq/bad-opt",
  "hpke/unknown-suite":    "crypto-hpke-pq/unsupported-suite",
  "hpke/open-failed":      "crypto-hpke-pq/open-failed",
  "hpke/inconsistent-psk": "crypto-hpke-pq/inconsistent-psk",
  "hpke/input-length":     "crypto-hpke-pq/input-length",
  "hpke/export-length":    "crypto-hpke-pq/export-length",
  "hpke/message-limit":    "crypto-hpke-pq/message-limit",
  "hpke/export-only":      "crypto-hpke-pq/export-only",
});

function _translate(e) {
  if (e instanceof HpkeError) return e;
  if (e && e.name === "HpkeError" && typeof e.code === "string") {
    var mapped = PKI_CODES[e.code] || "crypto-hpke-pq/failed";
    return _err(mapped, e.message);
  }
  return e;
}

function _call(fn) {
  try { return fn(); }
  catch (e) { throw _translate(e); }
}

function _keysFor(draft, keys) {
  return draft.takesKem ? keys.concat(["kem"]) : keys;
}

function _checkOpts(draft, opts, keys, where) {
  validateOpts.requireObject(opts, where, HpkeError, "crypto-hpke-pq/bad-opt");
  validateOpts.checkOrThrow(opts, _keysFor(draft, keys), where, HpkeError, "crypto-hpke-pq/bad-opt");
}

function _pick(draft, kind, value, where) {
  if (value === undefined || value === null) return draft.defaults[kind];
  if (typeof value !== "string" || value.length === 0) {
    throw _err("crypto-hpke-pq/bad-opt", where + ": " + kind + " must be a suite name string");
  }
  if (draft.supported[kind].indexOf(value) === -1) {
    throw _err("crypto-hpke-pq/unsupported-suite", where + ": " + kind + " " + JSON.stringify(value) +
      " is not offered under " + draft.label + "; supported: " + draft.supported[kind].join(", "));
  }
  return value;
}

function _suite(draft, opts, where) {
  var names = {
    kem:  _pick(draft, "kem", draft.takesKem ? opts.kem : undefined, where),
    kdf:  _pick(draft, "kdf", opts.kdf, where),
    aead: _pick(draft, "aead", opts.aead, where),
  };
  return { names: names, ids: { kem: KEM_IDS[names.kem], kdf: KDF_IDS[names.kdf], aead: AEAD_IDS[names.aead] } };
}

function _bytes(value, label, where) {
  if (value === undefined || value === null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === "string") return Buffer.from(value, "utf8");
  throw _err("crypto-hpke-pq/bad-opt", where + ": " + label + " must be a Buffer or a string, got " + typeof value);
}

function _setupOpts(opts, where) {
  var psk = _bytes(opts.psk, "psk", where);
  var pskId = _bytes(opts.pskId, "pskId", where);
  if (psk.length > 0 && psk.length < MIN_PSK_BYTES) {
    throw _err("crypto-hpke-pq/weak-psk", where + ": psk must be at least " + MIN_PSK_BYTES +
      " bytes (RFC 9180 sec. 5.1.2), got " + psk.length);
  }
  return {
    info:  _bytes(opts.info, "info", where),
    psk:   psk,
    pskId: pskId,
    mode:  (psk.length === 0 && pskId.length === 0) ? pki.hpke.suites.MODE.BASE : pki.hpke.suites.MODE.PSK,
  };
}

function _publicKey(value, where) {
  if (Buffer.isBuffer(value) || value instanceof nodeCrypto.KeyObject) return value;
  if (typeof value === "string" && value.length > 0) {
    try { return nodeCrypto.createPublicKey(value); }
    catch (e) { throw _err("crypto-hpke-pq/bad-key", where + ": recipientPubKey is not a readable public key: " + e.message); }
  }
  throw _err("crypto-hpke-pq/bad-opt", where + ": recipientPubKey must be a Buffer, a PEM string or a KeyObject");
}

function _privateKey(value, where) {
  if (Buffer.isBuffer(value)) return { skm: value };
  if (value instanceof nodeCrypto.KeyObject) return value;
  if (typeof value === "string" && value.length > 0) {
    try { return nodeCrypto.createPrivateKey(value); }
    catch (e) { throw _err("crypto-hpke-pq/bad-key", where + ": privateKey is not a readable private key: " + e.message); }
  }
  throw _err("crypto-hpke-pq/bad-opt", where + ": privateKey must be a Buffer seed, a PEM string or a KeyObject");
}

function _requireBuffer(value, label, where) {
  if (!Buffer.isBuffer(value)) {
    throw _err("crypto-hpke-pq/bad-opt", where + ": " + label + " must be a Buffer");
  }
  return value;
}

function _emit(action, outcome, draft, suite, metadata, reason) {
  observability().namespaced("hpke.pq")(action, 1, { outcome: outcome, draft: draft.name });
  audit().namespaced("system.hpke.pq")(action, outcome,
    Object.assign({ draft: draft.label, suite: suite.names }, metadata),
    reason ? { reason: reason } : null);
}

function _openFailed(draft, suite, e, ctBytes) {
  var t = _translate(e);
  if (t && t.code === "crypto-hpke-pq/open-failed") {
    _emit("open", "failure", draft, suite, { ctBytes: ctBytes }, "aead-tag");
  }
  return t;
}

function _senderContext(draft, opts, where) {
  var suite = _suite(draft, opts, where);
  var pk = _publicKey(opts.recipientPubKey, where);
  var setup = _setupOpts(opts, where);
  var s = _call(function () { return pki.hpke.setupS(suite.ids, pk, setup); });
  s.sharedSecret.fill(0);
  return { suite: suite, enc: Buffer.from(s.enc), context: s.context };
}

function _recipientContext(draft, opts, where) {
  var suite = _suite(draft, opts, where);
  var enc = _requireBuffer(opts.enc, "enc", where);
  var sk = _privateKey(opts.privateKey, where);
  var setup = _setupOpts(opts, where);
  var ctx = _call(function () { return pki.hpke.setupR(suite.ids, enc, sk, setup); });
  return { suite: suite, context: ctx };
}

function _seal(draft, opts) {
  var where = "hpke.pq." + draft.name + ".seal";
  _checkOpts(draft, opts, SEAL_KEYS, where);
  if (opts.plaintext === undefined || opts.plaintext === null) {
    throw _err("crypto-hpke-pq/bad-opt", where + ": plaintext required");
  }
  var plaintext = _bytes(opts.plaintext, "plaintext", where);
  var aad = _bytes(opts.aad, "aad", where);
  var s = _senderContext(draft, opts, where);
  var ct;
  try { ct = _call(function () { return s.context.seal(aad, plaintext); }); }
  finally { s.context._dispose(); }
  _emit("seal", "success", draft, s.suite, { encBytes: s.enc.length, ctBytes: ct.length });
  return { enc: s.enc, ciphertext: Buffer.from(ct) };
}

function _open(draft, opts) {
  var where = "hpke.pq." + draft.name + ".open";
  _checkOpts(draft, opts, OPEN_KEYS, where);
  var ciphertext = _requireBuffer(opts.ciphertext, "ciphertext", where);
  var aad = _bytes(opts.aad, "aad", where);
  var r = _recipientContext(draft, opts, where);
  var pt;
  try { pt = r.context.open(aad, ciphertext); }
  catch (e) { throw _openFailed(draft, r.suite, e, ciphertext.length); }
  finally { r.context._dispose(); }
  _emit("open", "success", draft, r.suite, { ctBytes: ciphertext.length });
  return Buffer.from(pt);
}

function _exportFn(context, where) {
  return function exportSecret(exporterContext, length) {
    var ctxBytes = _bytes(exporterContext, "exporterContext", where);
    if (typeof length !== "number" || !Number.isInteger(length) || length < 0) {
      throw _err("crypto-hpke-pq/export-length", where + ": length must be a non-negative integer");
    }
    return Buffer.from(_call(function () { return context.export(ctxBytes, length); }));
  };
}

function _setupSender(draft, opts) {
  var where = "hpke.pq." + draft.name + ".setupSender";
  _checkOpts(draft, opts, SENDER_KEYS, where);
  var s = _senderContext(draft, opts, where);
  _emit("setup", "success", draft, s.suite, { role: "sender", encBytes: s.enc.length });
  return {
    enc:    s.enc,
    seal:   function contextSeal(plaintext, aad) {
      if (plaintext === undefined || plaintext === null) {
        throw _err("crypto-hpke-pq/bad-opt", where + ".seal: plaintext required");
      }
      var pt = _bytes(plaintext, "plaintext", where + ".seal");
      var ad = _bytes(aad, "aad", where + ".seal");
      return Buffer.from(_call(function () { return s.context.seal(ad, pt); }));
    },
    export: _exportFn(s.context, where + ".export"),
  };
}

function _setupRecipient(draft, opts) {
  var where = "hpke.pq." + draft.name + ".setupRecipient";
  _checkOpts(draft, opts, RECIPIENT_KEYS, where);
  var r = _recipientContext(draft, opts, where);
  _emit("setup", "success", draft, r.suite, { role: "recipient" });
  return {
    open:   function contextOpen(ciphertext, aad) {
      var ct = _requireBuffer(ciphertext, "ciphertext", where + ".open");
      var ad = _bytes(aad, "aad", where + ".open");
      try { return Buffer.from(r.context.open(ad, ct)); }
      catch (e) { throw _openFailed(draft, r.suite, e, ct.length); }
    },
    export: _exportFn(r.context, where + ".export"),
  };
}

function _generateKeyPair(draft, opts) {
  var where = "hpke.pq." + draft.name + ".generateKeyPair";
  validateOpts.checkOrThrow(opts, ["kem"], where, HpkeError, "crypto-hpke-pq/bad-opt");
  return _rawKeyPair(_pick(draft, "kem", opts ? opts.kem : undefined, where));
}

function _rawKeyPair(kem) {
  var kp = _call(function () { return pki.hpke.generateKeyPair(KEM_IDS[kem]); });
  return { publicKey: Buffer.from(kp.publicKey), privateKey: Buffer.from(kp.privateKey) };
}

/**
 * @primitive b.crypto.hpke.pq.connolly.seal
 * @signature b.crypto.hpke.pq.connolly.seal(opts)
 * @since     0.10.10
 * @status    experimental
 * @related   b.crypto.hpke.pq.connolly.open, b.crypto.hpke.pq.connolly.setupSender
 *
 * Encrypt one message to an ML-KEM-1024 public key under RFC 9180 base
 * mode (psk mode when `psk` and `pskId` are given) with KEM 0x0042, as
 * draft-connolly-cfrg-hpke-mlkem-04 specifies. Returns `{ enc, ciphertext }`:
 * `enc` is the 1568-byte ML-KEM-1024 ciphertext and `ciphertext` is the AEAD
 * output for sequence number 0. The suite defaults to HKDF-SHA512 and
 * ChaCha20Poly1305.
 *
 * Throws `crypto-hpke-pq/bad-opt` for a missing or malformed option,
 * `crypto-hpke-pq/unsupported-suite` for a KDF or AEAD outside the list in
 * the module notes, `crypto-hpke-pq/bad-key` for a public key that is not
 * an ML-KEM-1024 key, `crypto-hpke-pq/inconsistent-psk` when only one of
 * `psk` and `pskId` is given, `crypto-hpke-pq/weak-psk` for a `psk` shorter
 * than 32 bytes, and `crypto-hpke-pq/export-only` for the export-only AEAD.
 *
 * @opts
 *   recipientPubKey: Buffer|string|KeyObject, // 1568-byte key, PEM or KeyObject
 *   plaintext:       Buffer|string,
 *   info:            Buffer|string,           // application context
 *   aad:             Buffer|string,           // additional authenticated data
 *   kdf:             string,                  // "HKDF-SHA512" (default) | "HKDF-SHA384"
 *   aead:            string,                  // "ChaCha20Poly1305" (default) | "AES-256-GCM"
 *   psk:             Buffer|string,           // pre-shared key, at least 32 bytes, with pskId
 *   pskId:           Buffer|string,           // pre-shared key identifier, with psk
 *
 * @example
 *   var pair   = b.crypto.hpke.pq.connolly.generateKeyPair();
 *   var sealed = b.crypto.hpke.pq.connolly.seal({
 *     recipientPubKey: pair.publicKey,
 *     plaintext:       "hello",
 *     info:            "app/topic",
 *   });
 *   sealed.enc.length;   // → 1568
 */
function connollySeal(opts) { return _seal(CONNOLLY, opts); }

/**
 * @primitive b.crypto.hpke.pq.connolly.open
 * @signature b.crypto.hpke.pq.connolly.open(opts)
 * @since     0.10.10
 * @status    experimental
 * @related   b.crypto.hpke.pq.connolly.seal, b.crypto.hpke.pq.connolly.setupRecipient
 *
 * Decrypt one RFC 9180 message sealed to an ML-KEM-1024 key under KEM
 * 0x0042, from `connolly.seal` or from any implementation of the same
 * suite. `kdf`, `aead`, `info`, `aad`, `psk` and `pskId` must match the
 * sender's. Returns the plaintext as a Buffer.
 *
 * Throws `crypto-hpke-pq/open-failed` when the AEAD tag does not verify,
 * `crypto-hpke-pq/bad-opt` for a missing or malformed option,
 * `crypto-hpke-pq/unsupported-suite` for a KDF or AEAD outside the list in
 * the module notes, `crypto-hpke-pq/bad-key` for a private key or `enc`
 * that is not ML-KEM-1024, `crypto-hpke-pq/inconsistent-psk` when only one
 * of `psk` and `pskId` is given, `crypto-hpke-pq/weak-psk` for a `psk`
 * shorter than 32 bytes, and `crypto-hpke-pq/export-only` for the
 * export-only AEAD.
 *
 * @opts
 *   privateKey:  Buffer|string|KeyObject,   // 64-byte seed, PKCS#8 PEM or KeyObject
 *   enc:         Buffer,                    // 1568-byte ML-KEM-1024 ciphertext
 *   ciphertext:  Buffer,
 *   info:        Buffer|string,
 *   aad:         Buffer|string,
 *   kdf:         string,                    // as sealed; default "HKDF-SHA512"
 *   aead:        string,                    // as sealed; default "ChaCha20Poly1305"
 *   psk:         Buffer|string,             // at least 32 bytes, as sealed
 *   pskId:       Buffer|string,
 *
 * @example
 *   var pair   = b.crypto.hpke.pq.connolly.generateKeyPair();
 *   var sealed = b.crypto.hpke.pq.connolly.seal({
 *     recipientPubKey: pair.publicKey, plaintext: "hello", info: "app/topic",
 *   });
 *   var pt = b.crypto.hpke.pq.connolly.open({
 *     privateKey: pair.privateKey, enc: sealed.enc,
 *     ciphertext: sealed.ciphertext, info: "app/topic",
 *   });
 *   pt.toString("utf8");   // → "hello"
 */
function connollyOpen(opts) { return _open(CONNOLLY, opts); }

/**
 * @primitive b.crypto.hpke.pq.connolly.setupSender
 * @signature b.crypto.hpke.pq.connolly.setupSender(opts)
 * @since     0.21.3
 * @status    experimental
 * @related   b.crypto.hpke.pq.connolly.setupRecipient, b.crypto.hpke.pq.connolly.seal
 *
 * Run the RFC 9180 sender setup once and return the context for a
 * sequence of messages: `{ enc, seal(plaintext, aad?), export(exporterContext, length) }`.
 * Each `seal` uses the next sequence number, so the recipient opens the
 * messages in the order they were sealed. `export` returns `length` bytes
 * of the RFC 9180 exporter secret for `exporterContext`.
 *
 * Throws `crypto-hpke-pq/bad-opt`, `crypto-hpke-pq/unsupported-suite`,
 * `crypto-hpke-pq/bad-key`, `crypto-hpke-pq/inconsistent-psk` and
 * `crypto-hpke-pq/weak-psk` as `connolly.seal` does. The context's `seal`
 * throws `crypto-hpke-pq/bad-opt` for a missing plaintext (pass `""` for an
 * empty message), `crypto-hpke-pq/export-only` under the export-only AEAD
 * and `crypto-hpke-pq/message-limit` when the sequence number would
 * overflow; its `export` throws `crypto-hpke-pq/export-length` for a
 * length above 255 times the KDF output size.
 *
 * @opts
 *   recipientPubKey: Buffer|string|KeyObject,
 *   info:            Buffer|string,
 *   kdf:             string,
 *   aead:            string,          // "Export-only" for a context used only to export
 *   psk:             Buffer|string,   // at least 32 bytes, with pskId
 *   pskId:           Buffer|string,
 *
 * @example
 *   var pair   = b.crypto.hpke.pq.connolly.generateKeyPair();
 *   var sender = b.crypto.hpke.pq.connolly.setupSender({
 *     recipientPubKey: pair.publicKey, info: "stream",
 *   });
 *   var c0 = sender.seal("first", "aad-0");
 *   var c1 = sender.seal("second", "aad-1");
 *   sender.enc.length;   // → 1568
 */
function connollySetupSender(opts) { return _setupSender(CONNOLLY, opts); }

/**
 * @primitive b.crypto.hpke.pq.connolly.setupRecipient
 * @signature b.crypto.hpke.pq.connolly.setupRecipient(opts)
 * @since     0.21.3
 * @status    experimental
 * @related   b.crypto.hpke.pq.connolly.setupSender, b.crypto.hpke.pq.connolly.open
 *
 * Run the RFC 9180 recipient setup for `enc` and return
 * `{ open(ciphertext, aad?), export(exporterContext, length) }`. Each
 * `open` uses the next sequence number, so the messages are opened in the
 * order they were sealed; a message opened out of order fails its tag, and
 * a failed `open` does not advance the sequence number.
 *
 * Throws `crypto-hpke-pq/bad-opt`, `crypto-hpke-pq/unsupported-suite`,
 * `crypto-hpke-pq/bad-key`, `crypto-hpke-pq/inconsistent-psk` and
 * `crypto-hpke-pq/weak-psk` as `connolly.open` does. The context's
 * `open` throws `crypto-hpke-pq/open-failed`, `crypto-hpke-pq/export-only`
 * and `crypto-hpke-pq/message-limit`; its `export` throws
 * `crypto-hpke-pq/export-length`.
 *
 * @opts
 *   privateKey:  Buffer|string|KeyObject,
 *   enc:         Buffer,
 *   info:        Buffer|string,
 *   kdf:         string,
 *   aead:        string,
 *   psk:         Buffer|string,   // at least 32 bytes, as given to setupSender
 *   pskId:       Buffer|string,
 *
 * @example
 *   var pair   = b.crypto.hpke.pq.connolly.generateKeyPair();
 *   var sender = b.crypto.hpke.pq.connolly.setupSender({ recipientPubKey: pair.publicKey });
 *   var c0     = sender.seal("first");
 *   var recip  = b.crypto.hpke.pq.connolly.setupRecipient({
 *     privateKey: pair.privateKey, enc: sender.enc,
 *   });
 *   recip.open(c0).toString("utf8");   // → "first"
 */
function connollySetupRecipient(opts) { return _setupRecipient(CONNOLLY, opts); }

/**
 * @primitive b.crypto.hpke.pq.connolly.generateKeyPair
 * @signature b.crypto.hpke.pq.connolly.generateKeyPair()
 * @since     0.21.3
 * @status    experimental
 * @related   b.crypto.hpke.pq.connolly.seal, b.crypto.hpke.pq.wg.generateKeyPair
 *
 * Generate an ML-KEM-1024 key pair in the HPKE serialized forms:
 * `{ publicKey, privateKey }`, where `publicKey` is the 1568-byte
 * encapsulation key and `privateKey` is the 64-byte seed `(d, z)` from a
 * fresh random source. These are the forms a peer implementation exchanges.
 * Throws `crypto-hpke-pq/bad-opt` when given any argument, since connolly
 * defines no KEM other than ML-KEM-1024.
 *
 * @example
 *   var pair = b.crypto.hpke.pq.connolly.generateKeyPair();
 *   pair.publicKey.length;    // → 1568
 *   pair.privateKey.length;   // → 64
 */
function connollyGenerateKeyPair() {
  if (arguments.length > 0 && arguments[0] !== undefined) {
    throw _err("crypto-hpke-pq/bad-opt",
      "hpke.pq.connolly.generateKeyPair: takes no options; connolly offers only ML-KEM-1024");
  }
  return _rawKeyPair(CONNOLLY.defaults.kem);
}

/**
 * @primitive b.crypto.hpke.pq.wg.seal
 * @signature b.crypto.hpke.pq.wg.seal(opts)
 * @since     0.10.10
 * @status    experimental
 * @related   b.crypto.hpke.pq.wg.open, b.crypto.hpke.pq.wg.setupSender, b.crypto.hpke.pq.connolly.seal
 *
 * Encrypt one message under draft-ietf-hpke-pq-05: RFC 9180 base mode (psk
 * mode when `psk` and `pskId` are given) with KEM `ML-KEM-1024` (0x0042)
 * or `MLKEM1024-P384` (0x0051). Returns `{ enc, ciphertext }`. The suite
 * defaults to ML-KEM-1024, the single-stage SHAKE256 KDF and
 * ChaCha20Poly1305.
 *
 * Throws `crypto-hpke-pq/bad-opt` for a missing or malformed option,
 * `crypto-hpke-pq/unsupported-suite` for a KEM, KDF or AEAD outside the
 * list in the module notes, `crypto-hpke-pq/bad-key` for a public key that
 * does not match the KEM, `crypto-hpke-pq/inconsistent-psk` when only one
 * of `psk` and `pskId` is given, `crypto-hpke-pq/weak-psk` for a `psk`
 * shorter than 32 bytes, `crypto-hpke-pq/export-only` for the export-only
 * AEAD, and `crypto-hpke-pq/input-length` for an `info`, `psk` or `pskId`
 * over 65,535 bytes under SHAKE256.
 *
 * @opts
 *   recipientPubKey: Buffer|string|KeyObject, // 1568 bytes (ML-KEM-1024) or 1665 (MLKEM1024-P384)
 *   plaintext:       Buffer|string,
 *   info:            Buffer|string,
 *   aad:             Buffer|string,
 *   kem:             string,                  // "ML-KEM-1024" (default) | "MLKEM1024-P384"
 *   kdf:             string,                  // "SHAKE256" (default) | "HKDF-SHA384" | "HKDF-SHA512"
 *   aead:            string,                  // "ChaCha20Poly1305" (default) | "AES-256-GCM"
 *   psk:             Buffer|string,           // pre-shared key, at least 32 bytes, with pskId
 *   pskId:           Buffer|string,           // pre-shared key identifier, with psk
 *
 * @example
 *   var pair   = b.crypto.hpke.pq.wg.generateKeyPair();
 *   var sealed = b.crypto.hpke.pq.wg.seal({
 *     recipientPubKey: pair.publicKey,
 *     plaintext:       "hello",
 *   });
 *   sealed.enc.length;   // → 1568
 */
function wgSeal(opts) { return _seal(WG, opts); }

/**
 * @primitive b.crypto.hpke.pq.wg.open
 * @signature b.crypto.hpke.pq.wg.open(opts)
 * @since     0.10.10
 * @status    experimental
 * @related   b.crypto.hpke.pq.wg.seal, b.crypto.hpke.pq.wg.setupRecipient
 *
 * Decrypt one draft-ietf-hpke-pq-05 message, from `wg.seal` or from any
 * implementation of the same suite. `kem`, `kdf`, `aead`, `info`, `aad`,
 * `psk` and `pskId` must match the sender's. Returns the plaintext as a
 * Buffer.
 *
 * Throws `crypto-hpke-pq/open-failed` when the AEAD tag does not verify,
 * `crypto-hpke-pq/bad-opt` for a missing or malformed option,
 * `crypto-hpke-pq/unsupported-suite` for a KEM, KDF or AEAD outside the
 * list in the module notes, `crypto-hpke-pq/bad-key` for a private key or
 * `enc` that does not match the KEM, `crypto-hpke-pq/inconsistent-psk`
 * when only one of `psk` and `pskId` is given, `crypto-hpke-pq/weak-psk`
 * for a `psk` shorter than 32 bytes, `crypto-hpke-pq/export-only` for the
 * export-only AEAD, and `crypto-hpke-pq/input-length` for an `info`, `psk`
 * or `pskId` over 65,535 bytes under SHAKE256.
 *
 * @opts
 *   privateKey:  Buffer|string|KeyObject,   // 64-byte (ML-KEM-1024) or 32-byte (MLKEM1024-P384) seed
 *   enc:         Buffer,
 *   ciphertext:  Buffer,
 *   info:        Buffer|string,
 *   aad:         Buffer|string,
 *   kem:         string,
 *   kdf:         string,
 *   aead:        string,
 *   psk:         Buffer|string,             // at least 32 bytes, as sealed
 *   pskId:       Buffer|string,
 *
 * @example
 *   var pair   = b.crypto.hpke.pq.wg.generateKeyPair();
 *   var sealed = b.crypto.hpke.pq.wg.seal({ recipientPubKey: pair.publicKey, plaintext: "hello" });
 *   var pt = b.crypto.hpke.pq.wg.open({
 *     privateKey: pair.privateKey, enc: sealed.enc,
 *     ciphertext: sealed.ciphertext,
 *   });
 *   pt.toString("utf8");   // → "hello"
 */
function wgOpen(opts) { return _open(WG, opts); }

/**
 * @primitive b.crypto.hpke.pq.wg.setupSender
 * @signature b.crypto.hpke.pq.wg.setupSender(opts)
 * @since     0.21.3
 * @status    experimental
 * @related   b.crypto.hpke.pq.wg.setupRecipient, b.crypto.hpke.pq.wg.seal
 *
 * Run the draft-ietf-hpke-pq-05 sender setup once and return
 * `{ enc, seal(plaintext, aad?), export(exporterContext, length) }`, the
 * RFC 9180 context for a sequence of messages. Each `seal` uses the next
 * sequence number.
 *
 * Throws `crypto-hpke-pq/bad-opt`, `crypto-hpke-pq/unsupported-suite`,
 * `crypto-hpke-pq/bad-key`, `crypto-hpke-pq/inconsistent-psk` and
 * `crypto-hpke-pq/weak-psk` and `crypto-hpke-pq/input-length` as `wg.seal`
 * does. The context's `seal` throws `crypto-hpke-pq/bad-opt` for a missing
 * plaintext (pass `""` for an empty message), `crypto-hpke-pq/export-only`
 * under the export-only AEAD and `crypto-hpke-pq/message-limit` when the
 * sequence number would overflow; its `export` throws
 * `crypto-hpke-pq/export-length` for a length above 65,535 under SHAKE256
 * or above 255 times the HKDF output size.
 *
 * @opts
 *   recipientPubKey: Buffer|string|KeyObject,
 *   info:            Buffer|string,
 *   kem:             string,
 *   kdf:             string,
 *   aead:            string,          // "Export-only" for a context used only to export
 *   psk:             Buffer|string,   // at least 32 bytes, with pskId
 *   pskId:           Buffer|string,
 *
 * @example
 *   var pair   = b.crypto.hpke.pq.wg.generateKeyPair();
 *   var sender = b.crypto.hpke.pq.wg.setupSender({ recipientPubKey: pair.publicKey });
 *   var key    = sender.export("session key", 32);
 *   key.length;   // → 32
 */
function wgSetupSender(opts) { return _setupSender(WG, opts); }

/**
 * @primitive b.crypto.hpke.pq.wg.setupRecipient
 * @signature b.crypto.hpke.pq.wg.setupRecipient(opts)
 * @since     0.21.3
 * @status    experimental
 * @related   b.crypto.hpke.pq.wg.setupSender, b.crypto.hpke.pq.wg.open
 *
 * Run the draft-ietf-hpke-pq-05 recipient setup for `enc` and return
 * `{ open(ciphertext, aad?), export(exporterContext, length) }`. Each
 * `open` uses the next sequence number; a failed `open` does not advance
 * it.
 *
 * Throws `crypto-hpke-pq/bad-opt`, `crypto-hpke-pq/unsupported-suite`,
 * `crypto-hpke-pq/bad-key`, `crypto-hpke-pq/inconsistent-psk` and
 * `crypto-hpke-pq/weak-psk` and `crypto-hpke-pq/input-length` as `wg.open`
 * does. The context's `open` throws `crypto-hpke-pq/open-failed`,
 * `crypto-hpke-pq/export-only` and `crypto-hpke-pq/message-limit`; its
 * `export` throws `crypto-hpke-pq/export-length`.
 *
 * @opts
 *   privateKey:  Buffer|string|KeyObject,
 *   enc:         Buffer,
 *   info:        Buffer|string,
 *   kem:         string,
 *   kdf:         string,
 *   aead:        string,
 *   psk:         Buffer|string,   // at least 32 bytes, as given to setupSender
 *   pskId:       Buffer|string,
 *
 * @example
 *   var pair   = b.crypto.hpke.pq.wg.generateKeyPair();
 *   var sender = b.crypto.hpke.pq.wg.setupSender({ recipientPubKey: pair.publicKey });
 *   var recip  = b.crypto.hpke.pq.wg.setupRecipient({
 *     privateKey: pair.privateKey, enc: sender.enc,
 *   });
 *   recip.export("session key", 32).equals(sender.export("session key", 32));   // → true
 */
function wgSetupRecipient(opts) { return _setupRecipient(WG, opts); }

/**
 * @primitive b.crypto.hpke.pq.wg.generateKeyPair
 * @signature b.crypto.hpke.pq.wg.generateKeyPair(opts?)
 * @since     0.21.3
 * @status    experimental
 * @related   b.crypto.hpke.pq.wg.seal, b.crypto.hpke.pq.connolly.generateKeyPair
 *
 * Generate a key pair for `kem` in the HPKE serialized forms:
 * `{ publicKey, privateKey }`. For `ML-KEM-1024` (the default) the public
 * key is 1568 bytes and the private key is the 64-byte seed; for
 * `MLKEM1024-P384` the public key is 1665 bytes and the private key is a
 * 32-byte seed. Throws `crypto-hpke-pq/bad-opt` for an unknown option and
 * `crypto-hpke-pq/unsupported-suite` for another KEM.
 *
 * @opts
 *   kem: string,   // "ML-KEM-1024" (default) | "MLKEM1024-P384"
 *
 * @example
 *   var pair = b.crypto.hpke.pq.wg.generateKeyPair({ kem: "MLKEM1024-P384" });
 *   pair.publicKey.length;    // → 1665
 *   pair.privateKey.length;   // → 32
 */
function wgGenerateKeyPair(opts) { return _generateKeyPair(WG, opts); }

module.exports = {
  connolly: {
    seal:            connollySeal,
    open:            connollyOpen,
    setupSender:     connollySetupSender,
    setupRecipient:  connollySetupRecipient,
    generateKeyPair: connollyGenerateKeyPair,
    label:           CONNOLLY_LABEL,
    DEFAULT_SUITE:   CONNOLLY.defaults,
    SUPPORTED_SUITES: CONNOLLY.supported,
  },
  wg: {
    seal:            wgSeal,
    open:            wgOpen,
    setupSender:     wgSetupSender,
    setupRecipient:  wgSetupRecipient,
    generateKeyPair: wgGenerateKeyPair,
    label:           WG_LABEL,
    DEFAULT_SUITE:   WG.defaults,
    SUPPORTED_SUITES: WG.supported,
  },
};

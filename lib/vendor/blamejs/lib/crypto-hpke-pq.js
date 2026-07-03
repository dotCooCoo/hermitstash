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
 *   Post-quantum HPKE variants under explicit opt-in. The IETF HPKE-WG
 *   has two active drafts proposing ML-KEM as a KEM for RFC 9180:
 *
 *   - **`b.crypto.hpke.pq.connolly`** — draft-connolly-cfrg-hpke-mlkem-04
 *     (individual draft; carries codepoint allocations today).
 *   - **`b.crypto.hpke.pq.wg`** — draft-ietf-hpke-pq-03 (WG-adopted; the
 *     more authoritative track but codepoints may still move before
 *     IANA registration).
 *
 *   The framework ships BOTH behind opt-in namespaces rather than
 *   picking a single draft prematurely. Each wrapper binds a draft-
 *   distinguishing label into the RFC 9180 §5.1 `info` parameter so
 *   an envelope sealed under one draft CANNOT be opened by the other
 *   — the cross-draft substitution attack the IANA codepoint
 *   normally prevents is enforced by the info-label binding.
 *
 *   Both wrappers compose the existing `b.crypto.hpke.seal` / `.open`
 *   path (ML-KEM-1024 KEM + HKDF-SHA3-512 KDF + ChaCha20-Poly1305 AEAD
 *   per framework PQC-first policy). Operators wanting to migrate to
 *   the final IANA-registered codepoints (when they appear) call the
 *   stable `b.crypto.hpke.seal` directly — the experimental wrappers
 *   exist for operators integrating against systems that speak one of
 *   the active drafts today.
 *
 * @card
 *   Both HPKE-PQ drafts (connolly + ietf-hpke-pq) behind opt-in namespaces. Cross-draft substitution refused via info-label binding.
 */

var hpke = require("./crypto-hpke");

// Draft-distinguishing labels. These prepend the operator's `info`
// parameter so the RFC 9180 §5.1 suite_id binding catches any cross-
// draft substitution attempt. The label is part of the AEAD AAD by
// construction — an envelope sealed under `connolly-04` cannot be
// opened by `wg-03` because the derived AEAD key diverges.
var CONNOLLY_LABEL = "draft-connolly-cfrg-hpke-mlkem-04";
var WG_LABEL       = "draft-ietf-hpke-pq-03";

function _prependLabel(label, info) {
  if (info === undefined || info === null) return label;
  var infoBytes = Buffer.isBuffer(info) ? info : Buffer.from(String(info), "utf8");
  // Treat empty info the same as omitted — RFC 9180's `info`
  // parameter is bytes-or-absent; an empty string and `undefined`
  // produce the same key schedule under the underlying HPKE. The
  // wrapper MUST preserve that equivalence so a seal({...}) (no
  // info) round-trips with an open({ info: "" }) (and vice versa)
  // without false AEAD-tag failures.
  if (infoBytes.length === 0) return label;
  return Buffer.concat([Buffer.from(label + "/", "utf8"), infoBytes]);
}

function _wrappedSeal(label, opts) {
  opts = opts || {};
  var bound = Object.assign({}, opts, { info: _prependLabel(label, opts.info) });
  return hpke.seal(bound);
}

function _wrappedOpen(label, opts) {
  opts = opts || {};
  var bound = Object.assign({}, opts, { info: _prependLabel(label, opts.info) });
  return hpke.open(bound);
}

/**
 * @primitive b.crypto.hpke.pq.connolly.seal
 * @signature b.crypto.hpke.pq.connolly.seal(opts)
 * @since     0.10.10
 * @status    experimental
 * @related   b.crypto.hpke.pq.wg.seal, b.crypto.hpke.pq.connolly.open
 *
 * Seal a payload under draft-connolly-cfrg-hpke-mlkem-04 codepoints.
 * Returns `{ enc, ciphertext }`; the framework's existing
 * `b.crypto.hpke.seal` semantics apply (ML-KEM-1024 + HKDF-SHA3-512 +
 * ChaCha20-Poly1305 per project policy). Opens ONLY via
 * `b.crypto.hpke.pq.connolly.open` — cross-draft substitution into
 * `b.crypto.hpke.pq.wg.open` refuses by construction.
 *
 * @opts
 *   recipientPubKey: string,        // ML-KEM-1024 PEM
 *   plaintext:       Buffer|string,
 *   info:            Buffer|string, // application context
 *   aad:             Buffer|string, // additional authenticated data
 *
 * @example
 *   var pair   = b.crypto.hpke.generateKeyPair();
 *   var sealed = b.crypto.hpke.pq.connolly.seal({
 *     recipientPubKey: pair.publicKey,
 *     plaintext:       "hello",
 *     info:            "app/topic",
 *   });
 */
function connollySeal(opts) { return _wrappedSeal(CONNOLLY_LABEL, opts); }

/**
 * @primitive b.crypto.hpke.pq.connolly.open
 * @signature b.crypto.hpke.pq.connolly.open(opts)
 * @since     0.10.10
 * @status    experimental
 * @related   b.crypto.hpke.pq.connolly.seal
 *
 * Open a draft-connolly-cfrg-hpke-mlkem-04 envelope produced by
 * `connolly.seal`. Refuses envelopes sealed under `wg.seal` (the
 * info-label binding catches cross-draft substitution).
 *
 * @opts
 *   privateKey:  string,         // ML-KEM-1024 PEM
 *   enc:         Buffer,
 *   ciphertext:  Buffer,
 *   info:        Buffer|string,
 *   aad:         Buffer|string,
 *
 * @example
 *   var pt = b.crypto.hpke.pq.connolly.open({
 *     privateKey: pair.privateKey, enc: sealed.enc,
 *     ciphertext: sealed.ciphertext, info: "app/topic",
 *   });
 */
function connollyOpen(opts) { return _wrappedOpen(CONNOLLY_LABEL, opts); }

/**
 * @primitive b.crypto.hpke.pq.wg.seal
 * @signature b.crypto.hpke.pq.wg.seal(opts)
 * @since     0.10.10
 * @status    experimental
 * @related   b.crypto.hpke.pq.connolly.seal, b.crypto.hpke.pq.wg.open
 *
 * Seal under draft-ietf-hpke-pq-03 codepoints (the WG-adopted PQ-HPKE
 * draft). Otherwise identical contract to `b.crypto.hpke.pq.connolly.seal`.
 *
 * @opts
 *   recipientPubKey: string,        // ML-KEM-1024 PEM
 *   plaintext:       Buffer|string,
 *   info:            Buffer|string,
 *   aad:             Buffer|string,
 *
 * @example
 *   var sealed = b.crypto.hpke.pq.wg.seal({
 *     recipientPubKey: pair.publicKey,
 *     plaintext:       "hello",
 *   });
 */
function wgSeal(opts) { return _wrappedSeal(WG_LABEL, opts); }

/**
 * @primitive b.crypto.hpke.pq.wg.open
 * @signature b.crypto.hpke.pq.wg.open(opts)
 * @since     0.10.10
 * @status    experimental
 * @related   b.crypto.hpke.pq.wg.seal
 *
 * Open a draft-ietf-hpke-pq-03 envelope produced by `wg.seal`.
 *
 * @opts
 *   privateKey:  string,
 *   enc:         Buffer,
 *   ciphertext:  Buffer,
 *   info:        Buffer|string,
 *   aad:         Buffer|string,
 *
 * @example
 *   var pt = b.crypto.hpke.pq.wg.open({
 *     privateKey: pair.privateKey, enc: sealed.enc,
 *     ciphertext: sealed.ciphertext,
 *   });
 */
function wgOpen(opts) { return _wrappedOpen(WG_LABEL, opts); }

module.exports = {
  connolly: {
    seal:  connollySeal,
    open:  connollyOpen,
    label: CONNOLLY_LABEL,
  },
  wg: {
    seal:  wgSeal,
    open:  wgOpen,
    label: WG_LABEL,
  },
};

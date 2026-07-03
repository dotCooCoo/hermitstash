// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.crypto.oprf
 * @nav    Crypto
 * @title  OPRF
 *
 * @intro
 *   Oblivious Pseudorandom Functions per <a
 *   href="https://www.rfc-editor.org/rfc/rfc9497">RFC 9497</a>. An OPRF lets
 *   a client learn <code>F(serverKey, input)</code> — a keyed pseudorandom
 *   value — <em>without</em> the server learning the input and without the
 *   client learning the key. It is the primitive behind Privacy Pass
 *   tokens, password-breach checks and password hardening (the server can
 *   pepper a password without ever seeing it), and private set
 *   intersection.
 *
 *   Two modes are provided per RFC 9497: <code>oprf</code> (base) and
 *   <code>voprf</code> (verifiable — the client can prove the server used
 *   the committed key, via a DLEQ proof carried in the evaluation). The
 *   partially-oblivious <code>poprf</code> mode is not yet exposed: the
 *   vendored <code>@noble/curves</code> does not implement it, so it will
 *   be added when upstream ships it rather than stubbed here.
 *   The base protocol is: the client <code>blind</code>s its input to a
 *   group element, the server <code>blindEvaluate</code>s it with its
 *   secret key, and the client <code>finalize</code>s by un-blinding and
 *   hashing. Because un-blinding cancels the blind, the output depends only
 *   on the key and the input — a server-side <code>evaluate</code> produces
 *   the same value directly.
 *
 *   <code>suite(name)</code> returns the suite for one of the RFC 9497
 *   ciphersuites — <code>ristretto255-sha512</code> (the Privacy Pass
 *   default), <code>p256-sha256</code>, <code>p384-sha384</code>, or
 *   <code>p521-sha512</code> — each exposing both shipped modes. Group and
 *   hash-to-curve operations come from the vendored <code>@noble/curves</code>.
 *   Byte arguments are <code>Uint8Array</code> / <code>Buffer</code>;
 *   returned elements and outputs are <code>Uint8Array</code>.
 *
 * @card
 *   RFC 9497 Oblivious PRFs — learn <code>F(key, input)</code> without the
 *   server seeing the input (oprf / voprf modes; ristretto255 / P-256
 *   / P-384 / P-521 suites). The primitive behind Privacy Pass, password
 *   hardening, and private set intersection.
 */

var nobleCurves = require("./vendor/noble-curves.cjs");
var { defineClass } = require("./framework-error");

var OprfError = defineClass("OprfError", { alwaysPermanent: true });

// RFC 9497 ciphersuite name → vendored @noble/curves OPRF implementation.
var SUITE_IMPL = {
  "ristretto255-sha512": nobleCurves.ristretto255_oprf,
  "p256-sha256":         nobleCurves.p256_oprf,
  "p384-sha384":         nobleCurves.p384_oprf,
  "p521-sha512":         nobleCurves.p521_oprf,
};
var SUITES = Object.keys(SUITE_IMPL);

/**
 * @primitive  b.crypto.oprf.suite
 * @signature  b.crypto.oprf.suite(name)
 * @since      0.13.0
 * @status     stable
 *
 * Return the RFC 9497 OPRF suite for <code>name</code> — one of
 * <code>"ristretto255-sha512"</code>, <code>"p256-sha256"</code>,
 * <code>"p384-sha384"</code>, or <code>"p521-sha512"</code> (case
 * insensitive). The result is <code>{ name, oprf, voprf }</code>; each mode
 * object has the protocol functions:
 *
 * <ul>
 *   <li><code>deriveKeyPair(seed, info)</code> / <code>generateKeyPair()</code>
 *       → <code>{ secretKey, publicKey }</code></li>
 *   <li><code>blind(input)</code> → <code>{ blind, blinded }</code> (client)</li>
 *   <li><code>oprf.blindEvaluate(secretKey, blinded)</code> → evaluation
 *       element; <code>voprf.blindEvaluate(secretKey, publicKey, blinded)</code>
 *       → <code>{ evaluated, proof }</code> (server)</li>
 *   <li><code>oprf.finalize(input, blind, evaluation)</code> /
 *       <code>voprf.finalize(input, blind, evaluated, blinded, publicKey, proof)</code>
 *       → output bytes (client; <code>voprf</code> verifies the proof and
 *       throws if it does not match <code>publicKey</code>)</li>
 *   <li><code>evaluate(secretKey, input)</code> → output bytes (server-side,
 *       non-oblivious — equals the client's <code>finalize</code> output)</li>
 * </ul>
 *
 * The partially-oblivious <code>poprf</code> mode is intentionally absent
 * (not implemented by the vendored <code>@noble/curves</code>). Throws
 * <code>OprfError</code> for an unknown suite name.
 *
 * @example
 *   var s = b.crypto.oprf.suite("ristretto255-sha512");
 *   var kp = s.oprf.deriveKeyPair(seed, Buffer.from("my-app"));
 *   var c  = s.oprf.blind(Buffer.from("user@example.com"));   // client
 *   var ev = s.oprf.blindEvaluate(kp.secretKey, c.blinded);   // server
 *   var out = s.oprf.finalize(Buffer.from("user@example.com"), c.blind, ev);
 *   // out === s.oprf.evaluate(kp.secretKey, Buffer.from("user@example.com"))
 */
function suite(name) {
  var impl = SUITE_IMPL[String(name).toLowerCase()];
  if (!impl) throw new OprfError("oprf/bad-suite", "crypto.oprf.suite: unknown suite '" + name + "'; expected one of " + SUITES.join(", "));
  // Expose only the modes the vendored @noble/curves implements (base +
  // verifiable). poprf is omitted rather than surfaced as an empty stub.
  return { name: impl.name, oprf: impl.oprf, voprf: impl.voprf };
}

module.exports = {
  suite:    suite,
  SUITES:   SUITES,
  OprfError: OprfError,
};

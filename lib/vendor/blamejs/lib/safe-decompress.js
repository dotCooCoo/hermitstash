// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.safeDecompress
 * @nav        Primitives
 * @title      Safe Decompress
 * @order      130
 * @slug       safe-decompress
 *
 * @card
 *   Bomb-resistant decompression: bounded output bytes, bounded
 *   expansion ratio, algorithm allowlist, audit on bomb-class refusal.
 *
 * @intro
 *   Operator-facing decompression primitive for `gzip` / `deflate` /
 *   `deflate-raw` (RFC 1951) / `brotli` / Z_NO_COMPRESSION-wrapped
 *   variants. Replaces ad-hoc `zlib.gunzipSync(buf)` / `zlib.
 *   inflateRawSync(buf)` calls in operator code with a single
 *   primitive that bounds OUTPUT BYTES + EXPANSION RATIO at the
 *   refuse boundary so a malicious peer can't ship a kilobyte of
 *   compressed input that explodes into gigabytes before the size
 *   check fires.
 *
 *   Algorithms accepted (allowlist — adding to the list is an
 *   operator-explicit opt-in to a new bomb-class surface):
 *
 *     - `"gzip"`        — `zlib.gunzipSync` (RFC 1952)
 *     - `"deflate"`     — `zlib.inflateSync` (RFC 1950 zlib wrapper)
 *     - `"deflate-raw"` — `zlib.inflateRawSync` (RFC 1951 deflate bytes
 *                         without the zlib wrapper; SAML / WebSocket
 *                         permessage-deflate / status-list)
 *     - `"brotli"`      — `zlib.brotliDecompressSync` (RFC 7932)
 *
 *   Refused with `safe-decompress/unsupported-algorithm`:
 *     - `"zstd"` — Node's zlib doesn't expose zstd in v24 LTS; operators
 *                  pin to a Node version when it lands AND wire
 *                  through the framework's algorithm allowlist.
 *     - Any algorithm not in the allowlist (including operator-typo'd).
 *
 *   Refusal posture:
 *     - `safe-decompress/decompress-failed`    — bomb-by-absolute-size
 *       (zlib's own `maxOutputLength` refuses before alloc; the throw is
 *       caught and surfaced under this code)
 *     - `safe-decompress/ratio-exceeded`       — expansion > `maxRatio`
 *       (zlib accepted the bytes; our post-decompress ratio check
 *       refuses, freeing the bytes immediately)
 *     - `safe-decompress/decompress-failed`    — malformed input;
 *       zlib's own RFC-grammar refusal surfaces here
 *     - `safe-decompress/empty-input`          — zero-byte input
 *     - `safe-decompress/oversized-input`      — pre-decompression
 *       compressed-input cap exceeded
 *
 *   Each refusal can emit a `safe-decompress.refused` audit event
 *   when operators wire `opts.audit`. The event metadata names the
 *   algorithm, compressedBytes, refusal reason — no decompressed
 *   bytes ever cross the audit boundary on the bomb-class path.
 *
 *   Threat model:
 *     - **Decompression bomb** (CWE-409 — improper handling of highly
 *       compressed data; the classic 42.zip nested-bomb expands to
 *       petabytes from kilobytes) across gzip / deflate / brotli —
 *       the bounded-output cap + expansion-ratio cap refuse before the
 *       allocation, so no decompressed bytes are ever materialized past
 *       the cap.
 *     - **Efail-class** (CVE-2017-17688 / 17689) — operators decrypting
 *       MIME parts compose `b.safeDecompress` on the inner deflate
 *       streams; the bounded-output posture defeats the unbounded-
 *       allocation arm of the attack.
 *
 *   Composes:
 *     - `b.audit.safeEmit` — bomb-refusal audit event (drop-silent per
 *       rule §5)
 *     - `b.constants.BYTES.*` — operator-facing byte-size constants
 *
 * RFC / CVE citations:
 *   - [RFC 1950](https://www.rfc-editor.org/rfc/rfc1950) zlib
 *   - [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951) deflate
 *   - [RFC 1952](https://www.rfc-editor.org/rfc/rfc1952) gzip
 *   - [RFC 7932](https://www.rfc-editor.org/rfc/rfc7932) brotli
 *   - [CWE-409](https://cwe.mitre.org/data/definitions/409.html) improper
 *     handling of highly compressed data (decompression bomb)
 */

var zlib = require("node:zlib");
var safeBuffer = require("./safe-buffer");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var C = require("./constants");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var SafeDecompressError = defineClass("SafeDecompressError", { alwaysPermanent: true });

// Algorithm allowlist (RFC-cited; any addition is an explicit
// operator-side risk acknowledgement). The map's value is the
// Node `node:zlib` sync function that performs the decompression.
var _algorithms = {
  "gzip":        function (buf, opts) { return zlib.gunzipSync(buf, opts); },
  "deflate":     function (buf, opts) { return zlib.inflateSync(buf, opts); },
  "deflate-raw": function (buf, opts) { return zlib.inflateRawSync(buf, opts); },
  "brotli":      function (buf, opts) { return zlib.brotliDecompressSync(buf, opts); },
};

// Default ratio cap (output / input). Aggressive enough to refuse
// classic bomb shapes (1000:1) while leaving headroom for legitimate
// text / JSON / XML payloads (which compress 20-50:1 commonly). Per
// RFC 8460 §5.2 community guidance for TLS-RPT report decompression.
var DEFAULT_MAX_RATIO = 50;

// Default input cap when operator omits opts.maxCompressedBytes —
// 4 MiB matches the TLS-RPT receive surface and is a reasonable
// upper bound for inbound compressed bodies on framework-mediated
// paths. Operators with bulk-data pipelines pass an explicit higher
// cap with documented rationale.
var DEFAULT_MAX_COMPRESSED_BYTES = C.BYTES.mib(4);

/**
 * @primitive b.safeDecompress
 * @signature b.safeDecompress(input, opts)
 * @since     0.11.5
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.safeBuffer.toBuffer, b.audit.safeEmit, b.guardArchive
 *
 * Decompress `input` (Buffer / Uint8Array) under `opts.algorithm` with
 * bounded output bytes and bounded expansion ratio. Refuses bomb-class
 * input BEFORE allocating the expanded buffer via zlib's own
 * `maxOutputLength`; refuses ratio-bomb shapes AFTER decompression by
 * checking `out.length / input.length` against `opts.maxRatio` and
 * dropping the buffer if the ratio is exceeded.
 *
 * @opts
 *   algorithm:           "gzip" | "deflate" | "deflate-raw" | "brotli",
 *   maxOutputBytes:      number,        // required; zlib refuses pre-alloc
 *   maxCompressedBytes:  number,        // optional; default 4 MiB input cap
 *   maxRatio:            number,        // optional; default 50:1 expansion
 *   windowBits:          number,        // optional; per-algorithm zlib opt
 *   audit:               object,        // optional b.audit handle for refusal events
 *   ctx:                 string,        // optional caller identifier (logged on refusal)
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var compressed = Buffer.from("...", "base64");
 *   try {
 *     var bytes = b.safeDecompress(compressed, {
 *       algorithm:       "gzip",
 *       maxOutputBytes:  b.constants.BYTES.mib(32),
 *       maxRatio:        100,
 *     });
 *   } catch (e) {
 *     if (e.code === "safe-decompress/ratio-exceeded") {
 *       // bomb-class shape; audit + refuse upstream
 *     } else {
 *       throw e;
 *     }
 *   }
 */
function safeDecompress(input, opts) {
  opts = opts || {};
  validateOpts(opts,
    ["algorithm", "maxOutputBytes", "maxCompressedBytes", "maxRatio",
     "windowBits", "audit", "ctx"],
    "safeDecompress");

  // Algorithm — required, must be in allowlist. Use an own-property check,
  // not `!_algorithms[algo]`: a bare truthiness/`in` lookup inherits
  // Object.prototype members, so a non-own key ("constructor", "toString",
  // …) would resolve to a prototype function and get invoked below —
  // `Object(buf)` returns the raw input, silently bypassing the allowlist
  // and returning un-decompressed bytes (fail-open).
  if (typeof opts.algorithm !== "string" ||
      !Object.prototype.hasOwnProperty.call(_algorithms, opts.algorithm)) {
    throw new SafeDecompressError(
      "safe-decompress/unsupported-algorithm",
      "safeDecompress: algorithm must be one of " +
        Object.keys(_algorithms).join(" | ") + "; got " +
        JSON.stringify(opts.algorithm));
  }

  // maxOutputBytes — required, positive finite integer.
  numericBounds.requirePositiveFiniteInt(opts.maxOutputBytes,
    "safeDecompress: maxOutputBytes", SafeDecompressError, "safe-decompress/bad-arg");

  // Input shape
  var buf;
  if (Buffer.isBuffer(input))           buf = input;
  else if (input instanceof Uint8Array) buf = Buffer.from(input);
  else {
    throw new SafeDecompressError(
      "safe-decompress/bad-input",
      "safeDecompress: input must be a Buffer or Uint8Array; got " +
        numericBounds.shape(input));
  }

  if (buf.length === 0) {
    throw new SafeDecompressError(
      "safe-decompress/empty-input",
      "safeDecompress: input is empty");
  }

  // Pre-decompression input cap (defense against very-large compressed
  // payloads whose zlib parse alone is expensive even if maxOutputLength
  // would refuse the expansion).
  var maxCompressedBytes = DEFAULT_MAX_COMPRESSED_BYTES;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxCompressedBytes,
    "safeDecompress: opts.maxCompressedBytes",
    SafeDecompressError, "safe-decompress/bad-arg");
  if (opts.maxCompressedBytes !== undefined && opts.maxCompressedBytes !== null) {
    maxCompressedBytes = opts.maxCompressedBytes;
  }
  if (safeBuffer.byteLengthOf(buf) > maxCompressedBytes) {
    _refuse(opts, "safe-decompress/oversized-input",
      "compressed input " + buf.length + " bytes exceeds maxCompressedBytes " +
      maxCompressedBytes);
  }

  // Ratio cap (output / input). 0 = unlimited (operators with
  // legitimately high-compressing payloads opt in explicitly).
  var maxRatio = DEFAULT_MAX_RATIO;
  // maxRatio has a special sentinel value: 0 (unlimited expansion).
  // The standard requireNonNegativeFiniteIntIfPresent helper covers
  // the 0-or-positive shape exactly.
  numericBounds.requireNonNegativeFiniteIntIfPresent(opts.maxRatio,
    "safeDecompress: opts.maxRatio (0 = unlimited expansion)",
    SafeDecompressError, "safe-decompress/bad-arg");
  if (opts.maxRatio !== undefined && opts.maxRatio !== null) {
    maxRatio = opts.maxRatio;
  }

  var zlibOpts = { maxOutputLength: opts.maxOutputBytes };
  if (typeof opts.windowBits === "number") zlibOpts.windowBits = opts.windowBits;

  var out;
  try {
    out = _algorithms[opts.algorithm](buf, zlibOpts);
  } catch (e) {
    // zlib refuses bombs by throwing; surface as a typed error and
    // refuse-emit. The original zlib error message is preserved on
    // .cause for operator debugging.
    var err = new SafeDecompressError(
      "safe-decompress/decompress-failed",
      "safeDecompress: decompression refused (" + opts.algorithm + "): " +
        ((e && e.message) || String(e)));
    err.cause = e;
    _refuse(opts, err.code, err.message, err);
  }

  // Ratio cap — runs AFTER decompression but BEFORE returning. zlib
  // already enforced maxOutputBytes; the ratio cap catches "bomb that
  // fit under the absolute cap but expanded 1000x." We immediately
  // drop the buffer if the ratio is exceeded so the operator-facing
  // path never sees the bomb bytes.
  if (maxRatio > 0) {
    var ratio = Math.ceil(out.length / buf.length);
    if (ratio > maxRatio) {
      // Zero the buffer before drop — defends against side-channel
      // peek + bug-induced leak. zlib already heap-allocated it; we
      // overwrite + release.
      out.fill(0);
      _refuse(opts, "safe-decompress/ratio-exceeded",
        "expansion ratio " + ratio + ":1 exceeds maxRatio " + maxRatio +
        ":1 (compressed=" + buf.length + " decompressed=" + out.length + ")");
    }
  }

  return out;
}

// Drop-silent audit emission — refuse-emit is best-effort,
// failures here don't crash the operator's path. Then throw the typed
// error so the caller's catch block decides downstream.
function _refuse(opts, code, message, originalError) {
  var auditImpl = opts.audit || (audit() && audit().safeEmit ? audit() : null);
  if (auditImpl && typeof auditImpl.safeEmit === "function") {
    try {
      auditImpl.safeEmit({
        action:   "system.safe_decompress.refused",
        outcome:  "denied",
        metadata: {
          code:      code,
          algorithm: opts.algorithm,
          ctx:       opts.ctx || null,
          reason:    message,
        },
      });
    } catch (_e) { /* drop-silent — observability is itself hot-path */ }
  }
  var err = new SafeDecompressError(code, message);
  if (originalError) err.cause = originalError;
  throw err;
}

module.exports = {
  safeDecompress:        safeDecompress,
  DEFAULT_MAX_RATIO:     DEFAULT_MAX_RATIO,
  SafeDecompressError:   SafeDecompressError,
};

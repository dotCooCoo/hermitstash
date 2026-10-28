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
 *     - `safe-decompress/output-cap-exceeded`  — bomb-by-absolute-size
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
 *     - `safe-decompress/trailing-input`: with `requireFullInput: true`,
 *       the compressed stream ends before the last input byte
 *     - `safe-decompress/unsafe-runtime`: `"brotli"` on a Node release
 *       whose bundled Brotli decoder writes out of bounds on a crafted
 *       stream (CVE-2026-111497). The supported releases with the fix
 *       are 24.22.1 and later on the 24 line and 26.12.1 and later. A
 *       prerelease build at one of those releases (`24.22.1-pre`) and
 *       every 23.x and 25.x release are refused. The input does not
 *       reach the decoder.
 *
 *   The `output-cap-exceeded`, `ratio-exceeded`, `decompress-failed`,
 *   `oversized-input`, `trailing-input` and `unsafe-runtime` refusals emit a
 *   `system.safe_decompress.refused` audit event, through `opts.audit`
 *   when it is wired and through `b.audit` otherwise. The argument
 *   refusals (`unsupported-algorithm`, `bad-arg`, `bad-input`,
 *   `empty-input`) throw without an audit event. The event metadata
 *   carries the refusal code, the algorithm, `opts.ctx` and the refusal
 *   message. No decompressed bytes are written to the audit event.
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
var nodeTypes = require("node:util").types;
var safeBuffer = require("./safe-buffer");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var C = require("./constants");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var SafeDecompressError = defineClass("SafeDecompressError", { alwaysPermanent: true });

var _algorithms = {
  "gzip":        function (buf, opts) { return zlib.gunzipSync(buf, opts); },
  "deflate":     function (buf, opts) { return zlib.inflateSync(buf, opts); },
  "deflate-raw": function (buf, opts) { return zlib.inflateRawSync(buf, opts); },
  "brotli":      function (buf, opts) { return zlib.brotliDecompressSync(buf, opts); },
};

var DEFAULT_MAX_RATIO = 50;

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
 * On a Node release whose bundled Brotli decoder writes past an internal
 * buffer on a crafted stream (CVE-2026-111497), `algorithm: "brotli"`
 * throws `safe-decompress/unsafe-runtime` before any input reaches the
 * decoder, and emits the refusal audit event. Neither `maxOutputBytes`
 * nor `maxRatio` prevents that write. The supported releases with the
 * fix are 24.22.1 and later on the 24 line and 26.12.1 and later. A
 * prerelease build at one of those releases (`24.22.1-pre`), every 23.x
 * and 25.x release, and a version string that does not parse are
 * refused. The other algorithms are unaffected.
 *
 * By default the decoder stops at the end of the compressed stream and
 * ignores any input bytes after it. With `requireFullInput: true`, input
 * bytes left over after the stream ends throw
 * `safe-decompress/trailing-input` and emit the refusal audit event.
 * Concatenated gzip members are read as one stream.
 *
 * Other refusals: `safe-decompress/unsupported-algorithm`,
 * `safe-decompress/bad-arg`, `safe-decompress/bad-input`,
 * `safe-decompress/empty-input`, `safe-decompress/oversized-input`,
 * `safe-decompress/output-cap-exceeded`,
 * `safe-decompress/decompress-failed` and
 * `safe-decompress/ratio-exceeded`.
 *
 * @opts
 *   algorithm:           "gzip" | "deflate" | "deflate-raw" | "brotli",
 *   maxOutputBytes:      number,        // required; zlib refuses pre-alloc
 *   maxCompressedBytes:  number,        // optional; default 4 MiB input cap
 *   maxRatio:            number,        // optional; default 50:1 expansion
 *   requireFullInput:    boolean,       // optional; default false
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
     "requireFullInput", "windowBits", "audit", "ctx"],
    "safeDecompress");
  validateOpts.optionalBoolean(opts.requireFullInput, "safeDecompress: opts.requireFullInput",
    SafeDecompressError, "safe-decompress/bad-arg");

  if (typeof opts.algorithm !== "string" ||
      !Object.prototype.hasOwnProperty.call(_algorithms, opts.algorithm)) {
    throw new SafeDecompressError(
      "safe-decompress/unsupported-algorithm",
      "safeDecompress: algorithm must be one of " +
        Object.keys(_algorithms).join(" | ") + "; got " +
        JSON.stringify(opts.algorithm));
  }

  if (opts.algorithm === "brotli" && !C._brotliDecoderPatched(process.versions.node)) {
    _refuse(opts, "safe-decompress/unsafe-runtime",
      "safeDecompress: algorithm \"brotli\" is refused on Node " +
        process.versions.node + ", whose Brotli decoder writes out of bounds on a " +
        "crafted stream (CVE-2026-111497); upgrade to Node 24.22.1 or later on the " +
        "24 line, or 26.12.1 or later");
  }

  numericBounds.requirePositiveFiniteInt(opts.maxOutputBytes,
    "safeDecompress: maxOutputBytes", SafeDecompressError, "safe-decompress/bad-arg");

  var buf;
  if (Buffer.isBuffer(input))           buf = input;
  else if (nodeTypes.isUint8Array(input)) buf = Buffer.from(input);
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

  var maxRatio = DEFAULT_MAX_RATIO;
  numericBounds.requireNonNegativeFiniteIntIfPresent(opts.maxRatio,
    "safeDecompress: opts.maxRatio (0 = unlimited expansion)",
    SafeDecompressError, "safe-decompress/bad-arg");
  if (opts.maxRatio !== undefined && opts.maxRatio !== null) {
    maxRatio = opts.maxRatio;
  }

  var zlibOpts = { maxOutputLength: opts.maxOutputBytes };
  if (typeof opts.windowBits === "number") zlibOpts.windowBits = opts.windowBits;
  if (opts.requireFullInput === true) zlibOpts.info = true;

  var out;
  var consumed = buf.length;
  try {
    out = _algorithms[opts.algorithm](buf, zlibOpts);
    if (zlibOpts.info) {
      consumed = out.engine.bytesWritten;
      out = out.buffer;
    }
  } catch (e) {
    var overCap = e && (e.code === "ERR_BUFFER_TOO_LARGE" ||
                        e.code === "ERR_OUT_OF_RANGE");
    var code = overCap ? "safe-decompress/output-cap-exceeded"
                       : "safe-decompress/decompress-failed";
    var err = new SafeDecompressError(code,
      "safeDecompress: decompression refused (" + opts.algorithm + "): " +
        ((e && e.message) || String(e)));
    err.cause = e;
    _refuse(opts, err.code, err.message, err);
  }

  if (consumed !== buf.length) {
    out.fill(0);
    _refuse(opts, "safe-decompress/trailing-input",
      "safeDecompress: the " + opts.algorithm + " stream ends after " + consumed +
        " of " + buf.length + " input bytes");
  }

  if (maxRatio > 0) {
    var ratio = Math.ceil(out.length / buf.length);
    if (ratio > maxRatio) {
      out.fill(0);
      _refuse(opts, "safe-decompress/ratio-exceeded",
        "expansion ratio " + ratio + ":1 exceeds maxRatio " + maxRatio +
        ":1 (compressed=" + buf.length + " decompressed=" + out.length + ")");
    }
  }

  return out;
}

// The refusal audit emission is drop-silent; the typed error is thrown either way.
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

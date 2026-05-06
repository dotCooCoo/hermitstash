"use strict";
/**
 * Buffer-safety primitives — centralizes the input-normalize, capped
 * chunk collection, and secure-zero patterns that were scattered across
 * lib/parsers/*, lib/atomic-file.js, lib/object-store-*.js, and
 * lib/log-stream-*.js.
 *
 * Public API:
 *   safeBuffer.normalizeText(input, { maxBytes, stripBom, errorClass })
 *     Accept string | Buffer | Uint8Array → returns string. Strips a
 *     leading UTF-8 BOM (U+FEFF) by default. Throws errorClass(message,
 *     code) if input is the wrong type or exceeds maxBytes.
 *
 *   safeBuffer.toBuffer(data, { maxBytes, errorClass })
 *     Accept Buffer | Uint8Array | string → returns Buffer. Throws
 *     errorClass on type mismatch or oversize.
 *
 *   safeBuffer.boundedChunkCollector({ maxBytes, errorClass })
 *     Returns { push(chunk), result(), bytesCollected() }. Each push()
 *     enforces the cap on every chunk — the OOM defense for unbounded
 *     HTTP response bodies replacing the previous `chunks.push(c)` +
 *     `Buffer.concat(chunks)` pattern that accumulated arbitrary bytes
 *     before checking size.
 *
 *   safeBuffer.secureZero(buf)
 *     Best-effort zero of buf contents (`buf.fill(0)`). JavaScript can't
 *     truly zero memory — V8 may have copies — but `fill(0)` removes the
 *     in-Buffer reference so a heap-dump won't show the secret in this
 *     particular Buffer. No-op on non-Buffers.
 *
 * Why a default error class:
 *   Each caller (xml-safe, json-safe, atomic-file, ...) wants to throw
 *   its own format-specific error class with a particular `code`. The
 *   helpers accept `{ errorClass }` so the byte-handling lives here but
 *   the error type stays format-aware (existing tests check
 *   e.code === "xml/too-large" etc.). A default SafeBufferError is used
 *   if the caller doesn't pass one.
 */

var numericBounds = require("./numeric-bounds");
var { FrameworkError } = require("./framework-error");

class SafeBufferError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "SafeBufferError";
    this.code = code || "buffer/invalid";
    this.isSafeBufferError = true;
  }
}

function _throw(errorClass, message, code) {
  var Cls = errorClass || SafeBufferError;
  throw new Cls(message, code);
}

// ---- normalizeText ----

function normalizeText(input, opts) {
  opts = opts || {};
  // maxBytes optional; positive finite int when set — Infinity / NaN
  // bypass the cap.
  var maxBytes = null;
  if (opts.maxBytes !== undefined && opts.maxBytes !== null) {
    if (!numericBounds.isPositiveFiniteInt(opts.maxBytes)) {
      throw new SafeBufferError(
        "normalizeText: maxBytes must be a positive finite integer; got " +
          numericBounds.shape(opts.maxBytes),
        "buffer/bad-arg");
    }
    maxBytes = opts.maxBytes;
  }
  var stripBom  = opts.stripBom !== false;  // default true
  var errClass  = opts.errorClass;
  var typeCode  = opts.typeCode  || "buffer/wrong-input-type";
  var sizeCode  = opts.sizeCode  || "buffer/too-large";
  var typeMsg   = opts.typeMessage || "input must be string, Buffer, or Uint8Array";
  var sizeMsg   = opts.sizeMessage || "input exceeds maxBytes";

  var text;
  if (typeof input === "string")            text = input;
  else if (Buffer.isBuffer(input))          text = input.toString("utf8");
  else if (input instanceof Uint8Array)     text = Buffer.from(input).toString("utf8");
  else _throw(errClass, typeMsg, typeCode);

  if (stripBom && text.charCodeAt(0) === 0xFEFF) text = text.slice(1);

  if (maxBytes !== null && Buffer.byteLength(text, "utf8") > maxBytes) {
    _throw(errClass, sizeMsg, sizeCode);
  }
  return text;
}

// ---- toBuffer ----

function toBuffer(data, opts) {
  opts = opts || {};
  // maxBytes optional; positive finite int when provided.
  var maxBytes = null;
  if (opts.maxBytes !== undefined && opts.maxBytes !== null) {
    if (!numericBounds.isPositiveFiniteInt(opts.maxBytes)) {
      throw new SafeBufferError(
        "toBuffer: maxBytes must be a positive finite integer; got " +
          numericBounds.shape(opts.maxBytes),
        "buffer/bad-arg");
    }
    maxBytes = opts.maxBytes;
  }
  var errClass = opts.errorClass;
  var typeCode = opts.typeCode  || "buffer/wrong-input-type";
  var sizeCode = opts.sizeCode  || "buffer/too-large";
  var typeMsg  = opts.typeMessage || "data must be Buffer, Uint8Array, or string";
  var sizeMsg  = opts.sizeMessage || "data exceeds maxBytes";

  var buf;
  if (Buffer.isBuffer(data))             buf = data;
  else if (typeof data === "string")     buf = Buffer.from(data, "utf8");
  else if (data instanceof Uint8Array)   buf = Buffer.from(data);
  else _throw(errClass, typeMsg, typeCode);

  if (maxBytes !== null && buf.length > maxBytes) {
    _throw(errClass, sizeMsg, sizeCode);
  }
  return buf;
}

// ---- boundedChunkCollector ----
//
// Replaces the unbounded `chunks.push(c); ... Buffer.concat(chunks)`
// pattern in HTTP response handlers. The cap is enforced at push() time
// so a 10-GB response from a hostile/misbehaving upstream rejects on the
// chunk that overflows — without first accumulating the whole 10 GB in
// the chunks array.

function boundedChunkCollector(opts) {
  opts = opts || {};
  // maxBytes required, positive finite integer. Accepting Infinity
  // defeats the entire point of the bounded collector (a hostile 10-GB
  // upstream would accumulate fully).
  if (!numericBounds.isPositiveFiniteInt(opts.maxBytes)) {
    throw new SafeBufferError(
      "boundedChunkCollector requires maxBytes (positive finite integer); got " +
        numericBounds.shape(opts.maxBytes),
      "buffer/bad-arg");
  }
  var maxBytes = opts.maxBytes;
  var errClass = opts.errorClass;
  var sizeCode = opts.sizeCode  || "buffer/too-large";
  var sizeMsg  = opts.sizeMessage || "stream body exceeds maxBytes";

  var chunks = [];
  var total = 0;

  return {
    push: function (chunk) {
      // Accept Buffer or Uint8Array (Node's res.on('data') yields Buffer
      // by default but consumers may have set encoding to get strings).
      if (typeof chunk === "string") chunk = Buffer.from(chunk, "utf8");
      else if (!Buffer.isBuffer(chunk) && chunk instanceof Uint8Array) chunk = Buffer.from(chunk);
      if (!Buffer.isBuffer(chunk)) {
        _throw(errClass, "chunk must be Buffer, Uint8Array, or string", "buffer/wrong-input-type");
      }
      if (total + chunk.length > maxBytes) {
        _throw(errClass, sizeMsg, sizeCode);
      }
      chunks.push(chunk);
      total += chunk.length;
    },
    result: function () {
      return Buffer.concat(chunks, total);
    },
    bytesCollected: function () { return total; },
  };
}

// ---- secureZero ----

function secureZero(buf) {
  if (Buffer.isBuffer(buf) || buf instanceof Uint8Array) {
    try { buf.fill(0); } catch (_e) { /* best effort — locked memory etc. */ }
  }
}

// ---- Shared regexes for byte-shape predicates ----
//
// HEX_RE matches a non-empty all-hex string of any length (used by
// digest comparisons, manifest checksums, X.509 serials). Length is
// caller-bounded: pass the expected length explicitly when the protocol
// fixes it (SHA3-512 → 128 hex chars, SHA-256 → 64, etc.). The regex
// itself does NOT bound length — that's the caller's contract.
var HEX_RE = /^[0-9a-fA-F]+$/;

// BASE64URL_RE matches a non-empty base64url-encoded string (RFC 4648
// §5) with NO padding. Used by JOSE primitives (JWT/JWS/JWE compact
// serialisations), DPoP jti, WebAuthn credential IDs, etc. The regex
// is length-agnostic — callers cap length per protocol contract.
var BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

// Fixed-length hex predicates used by trace-context primitives (W3C
// trace-id is 16 bytes = 32 hex chars; span-id / parent-id is 8
// bytes = 16 hex chars). Extracted to keep callers length-bounded
// without duplicating the literal in every file.
var TRACE_ID_HEX_RE = /^[0-9a-f]{32}$/;                                            // allow:regex-no-length-cap — fixed 32 hex chars (W3C §3.2.2.3)
var SPAN_ID_HEX_RE  = /^[0-9a-f]{16}$/;                                            // allow:regex-no-length-cap — fixed 16 hex chars (W3C §3.2.2.4)

// RFC 7230 §3.2.6 / RFC 9110 §5.1 `tchar` grammar — used by HTTP
// header tokens, MIME parameter names, W3C Baggage keys, etc.
// Length-agnostic; callers cap per protocol.
var RFC7230_TCHAR_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;                           // allow:regex-no-length-cap — caller bounds length

// CRLF_RE matches any control character used in HTTP-header / SMTP-
// envelope injection attacks. Header values that contain CR or LF must
// be rejected before serialization.
var CRLF_RE = /[\r\n]/;
var CRLF_RE_GLOBAL = /[\r\n]/g;   // for `.replace` strip use

// Trailing horizontal-whitespace strip — used by DKIM canonicalization
// (RFC 6376), .env / YAML scalar parsers, and any text-processing
// site that needs the "rstrip" semantic. Spaces and tabs only;
// callers that want CR/LF stripped use stripCrlf.
var TRAILING_HSPACE_RE = /[ \t]+$/;
function stripTrailingHspace(s) {
  if (typeof s !== "string") return s;
  return s.replace(TRAILING_HSPACE_RE, "");
}

function isHex(s, expectedLength) {
  if (typeof s !== "string") return false;
  if (typeof expectedLength === "number" && s.length !== expectedLength) return false;
  return HEX_RE.test(s);
}

function hasCrlf(s) {
  return typeof s === "string" && CRLF_RE.test(s);
}

function stripCrlf(s, replacement) {
  if (typeof s !== "string") return s;
  return s.replace(CRLF_RE_GLOBAL, replacement === undefined ? "" : replacement);
}

module.exports = {
  normalizeText:         normalizeText,
  toBuffer:              toBuffer,
  boundedChunkCollector: boundedChunkCollector,
  secureZero:            secureZero,
  isHex:                 isHex,
  hasCrlf:               hasCrlf,
  stripCrlf:             stripCrlf,
  stripTrailingHspace:   stripTrailingHspace,
  HEX_RE:                HEX_RE,
  BASE64URL_RE:          BASE64URL_RE,
  TRACE_ID_HEX_RE:       TRACE_ID_HEX_RE,
  SPAN_ID_HEX_RE:        SPAN_ID_HEX_RE,
  RFC7230_TCHAR_RE:      RFC7230_TCHAR_RE,
  CRLF_RE:               CRLF_RE,
  TRAILING_HSPACE_RE:    TRAILING_HSPACE_RE,
  SafeBufferError:       SafeBufferError,
};

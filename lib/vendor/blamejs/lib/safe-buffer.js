"use strict";
/**
 * @module b.safeBuffer
 * @nav    Validation
 * @title  Safe Buffer
 *
 * @intro
 *   Buffer-safety primitives that centralize the input-normalize,
 *   capped-collection, and secure-zero patterns previously scattered
 *   across parsers, atomic-file, object-store, and log-stream
 *   modules.
 *
 *   The safety guarantees the family enforces:
 *
 *   1. Type-discriminated input — every helper accepts the exact set
 *      of byte-shaped inputs it documents (Buffer / Uint8Array /
 *      string) and throws on anything else, instead of silently
 *      coercing `undefined` to `"undefined"` or letting an Object
 *      slip through `Buffer.from`.
 *
 *   2. Caller-supplied byte cap enforced BEFORE allocation. Numeric
 *      `maxBytes` opts are validated as positive finite integers —
 *      `Infinity`, `NaN`, and negative values throw at config time
 *      rather than disabling the cap. The bounded-chunk collector
 *      checks the running total on every push so a hostile 10-GB
 *      upstream rejects on the chunk that overflows, not after
 *      accumulating the full payload in memory.
 *
 *   3. UTF-8 BOM (U+FEFF) stripped by default in normalizeText so
 *      Windows-authored config files don't break downstream parsers
 *      that don't expect a leading BOM.
 *
 *   4. Best-effort secret hygiene via secureZero — `buf.fill(0)`
 *      clears the visible Buffer so a heap-dump won't show the
 *      secret in that allocation. JavaScript can't guarantee zeroing
 *      across V8 copies, but the in-buffer reference is gone.
 *
 *   5. Format-aware error classes. Each call site (xml-safe,
 *      json-safe, atomic-file, …) passes its own `errorClass` so the
 *      byte-handling lives here but the thrown error matches the
 *      caller's contract (`e.code === "xml/too-large"` etc.).
 *      A default SafeBufferError is used when no class is supplied.
 *
 *   The byte-shape predicates (HEX_RE, BASE64URL_RE, TRACE_ID_HEX_RE,
 *   SPAN_ID_HEX_RE, RFC7230_TCHAR_RE, CRLF_RE, TRAILING_HSPACE_RE)
 *   plus their helper functions (isHex, hasCrlf, stripCrlf,
 *   stripTrailingHspace) live alongside the buffer helpers because
 *   every caller that bounds bytes also tends to validate the textual
 *   shape of those bytes (header tokens, hex digests, JOSE compact
 *   serialisations, DKIM canonicalization).
 *
 * @card
 *   Buffer-safety primitives that centralize the input-normalize, capped-collection, and secure-zero patterns previously scattered across parsers, atomic-file, object-store, and log-stream modules.
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

/**
 * @primitive b.safeBuffer.normalizeText
 * @signature b.safeBuffer.normalizeText(input, opts?)
 * @since     0.4.9
 * @related   b.safeBuffer.toBuffer, b.safeBuffer.boundedChunkCollector
 *
 * Normalize a byte-shaped input (string / Buffer / Uint8Array) to a
 * UTF-8 string with the byte cap enforced BEFORE the result is handed
 * back. Anything outside the documented input set throws — `null`,
 * `undefined`, plain objects, numbers all reject instead of being
 * coerced via `Buffer.from`. The leading UTF-8 BOM (U+FEFF) is
 * stripped by default so Windows-authored config files don't break
 * downstream parsers.
 *
 * Numeric `maxBytes` is validated as a positive finite integer at
 * call-time — `Infinity` / `NaN` / negative throw rather than
 * silently disabling the cap.
 *
 * @opts
 *   maxBytes: number,        // optional positive finite int; UTF-8 byte cap
 *   stripBom: boolean,       // default true; remove leading U+FEFF
 *   errorClass: Function,    // caller-supplied Error subclass for thrown errors
 *   typeCode: string,        // default "buffer/wrong-input-type"
 *   sizeCode: string,        // default "buffer/too-large"
 *   typeMessage: string,     // override the wrong-input-type message
 *   sizeMessage: string,     // override the too-large message
 *
 * @example
 *   var b = require("blamejs");
 *   var s = b.safeBuffer.normalizeText(Buffer.from("hello"));
 *   // → "hello"
 *
 *   // BOM stripped by default.
 *   var bom = Buffer.from([0xEF, 0xBB, 0xBF, 0x68, 0x69]);
 *   b.safeBuffer.normalizeText(bom);
 *   // → "hi"
 *
 *   // Non-byte input throws instead of coercing to "undefined".
 *   try { b.safeBuffer.normalizeText(undefined); }
 *   catch (e) { e.code; }
 *   // → "buffer/wrong-input-type"
 *
 *   // maxBytes enforced; Infinity rejected at config time.
 *   try { b.safeBuffer.normalizeText("xxx", { maxBytes: Infinity }); }
 *   catch (e) { e.code; }
 *   // → "buffer/bad-arg"
 */
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

/**
 * @primitive b.safeBuffer.toBuffer
 * @signature b.safeBuffer.toBuffer(data, opts?)
 * @since     0.4.9
 * @related   b.safeBuffer.normalizeText, b.safeBuffer.boundedChunkCollector
 *
 * Coerce a byte-shaped input (Buffer / Uint8Array / string) to a
 * Buffer with the byte cap enforced before return. Unlike raw
 * `Buffer.from`, an Object / number / `undefined` does NOT slip
 * through — every non-byte input throws with a documented code.
 * `Buffer.isBuffer(data)` returns the input unchanged (zero copy);
 * Uint8Array is wrapped, string is encoded as UTF-8.
 *
 * @opts
 *   maxBytes: number,        // optional positive finite int; byte cap
 *   errorClass: Function,    // caller-supplied Error subclass
 *   typeCode: string,        // default "buffer/wrong-input-type"
 *   sizeCode: string,        // default "buffer/too-large"
 *   typeMessage: string,     // override the wrong-input-type message
 *   sizeMessage: string,     // override the too-large message
 *
 * @example
 *   var b = require("blamejs");
 *   var buf = b.safeBuffer.toBuffer("hello");
 *   buf.length;
 *   // → 5
 *
 *   // Buffer passes through unchanged (zero copy).
 *   var input = Buffer.from([1, 2, 3]);
 *   b.safeBuffer.toBuffer(input) === input;
 *   // → true
 *
 *   // Object input throws instead of coercing.
 *   try { b.safeBuffer.toBuffer({ not: "bytes" }); }
 *   catch (e) { e.code; }
 *   // → "buffer/wrong-input-type"
 *
 *   // maxBytes cap.
 *   try { b.safeBuffer.toBuffer("abcdef", { maxBytes: 3 }); }
 *   catch (e) { e.code; }
 *   // → "buffer/too-large"
 */
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

/**
 * @primitive b.safeBuffer.boundedChunkCollector
 * @signature b.safeBuffer.boundedChunkCollector(opts)
 * @since     0.4.9
 * @related   b.safeBuffer.toBuffer, b.safeBuffer.normalizeText
 *
 * Streaming-body collector that enforces `maxBytes` at every `push()`
 * — never after. A hostile upstream sending a 10-GB response rejects
 * on the chunk that overflows the cap, instead of accumulating the
 * full 10 GB in memory before the framework discovers the problem.
 *
 * `maxBytes` is REQUIRED (positive finite integer). `Infinity` is
 * rejected at construction because it defeats the entire purpose of
 * the bounded collector. Each `push()` accepts Buffer / Uint8Array /
 * string; non-byte chunks throw.
 *
 * Returns `{ push, result, bytesCollected }`. Call `result()` when the
 * stream ends to get the concatenated Buffer.
 *
 * @opts
 *   maxBytes: number,        // REQUIRED positive finite int; total byte cap
 *   errorClass: Function,    // caller-supplied Error subclass
 *   sizeCode: string,        // default "buffer/too-large"
 *   sizeMessage: string,     // override the too-large message
 *
 * @example
 *   var b = require("blamejs");
 *   var c = b.safeBuffer.boundedChunkCollector({ maxBytes: 1024 });
 *   c.push(Buffer.from("hello "));
 *   c.push(Buffer.from("world"));
 *   c.bytesCollected();
 *   // → 11
 *   c.result().toString("utf8");
 *   // → "hello world"
 *
 *   // Cap enforced at push, not at result().
 *   var c2 = b.safeBuffer.boundedChunkCollector({ maxBytes: 4 });
 *   c2.push(Buffer.from("abc"));
 *   try { c2.push(Buffer.from("defgh")); }
 *   catch (e) { e.code; }
 *   // → "buffer/too-large"
 *
 *   // Infinity rejected at construction.
 *   try { b.safeBuffer.boundedChunkCollector({ maxBytes: Infinity }); }
 *   catch (e) { e.code; }
 *   // → "buffer/bad-arg"
 */
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

/**
 * @primitive b.safeBuffer.secureZero
 * @signature b.safeBuffer.secureZero(buf)
 * @since     0.4.9
 * @related   b.safeBuffer.toBuffer, b.crypto.generateBytes
 *
 * Best-effort secret hygiene. `buf.fill(0)` clears the visible Buffer
 * / Uint8Array so a heap-dump won't show the secret in that
 * allocation. JavaScript can't guarantee zeroing across V8 internal
 * copies (string interning, JIT-spilled registers), but the in-buffer
 * reference is gone and that's the only handle the framework can
 * reliably wipe.
 *
 * Silently no-ops on non-byte inputs and on locked / shared buffers
 * that throw on `.fill` — the caller's contract is "I'm done with
 * this", not "guarantee zeroing succeeded." Pair with `Buffer`
 * allocations whose lifetime is short and well-scoped.
 *
 * @example
 *   var b = require("blamejs");
 *   var key = Buffer.from("super-secret-key");
 *   // ... use key ...
 *   b.safeBuffer.secureZero(key);
 *   key[0];
 *   // → 0
 *
 *   // No-op on non-byte input.
 *   b.safeBuffer.secureZero("a string");
 *   // → undefined
 */
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

// IPv6 hextet predicate — 1..4 hex characters (case-insensitive).
// Used by every IPv6 string-to-bytes parser that splits on `:` and
// validates each group. Extracted from guard-cidr / safe-json /
// network-tls so the shape lives in one place.
var IPV6_HEXTET_RE = /^[0-9a-fA-F]{1,4}$/;                                         // allow:regex-no-length-cap — RFC 4291 §2.2 hextet width

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
/**
 * @primitive b.safeBuffer.stripTrailingHspace
 * @signature b.safeBuffer.stripTrailingHspace(s)
 * @since     0.7.0
 * @related   b.safeBuffer.stripCrlf, b.safeBuffer.hasCrlf
 *
 * Strip trailing horizontal whitespace (spaces and tabs only) from a
 * string — the "rstrip" semantic used by DKIM canonicalization
 * (RFC 6376 §3.4.4 relaxed body), `.env` parsers, and YAML scalar
 * readers. Does NOT touch CR / LF — pair with `stripCrlf` when you
 * need full whitespace stripping. Non-string input passes through
 * unchanged so the helper is safe in mixed pipelines.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeBuffer.stripTrailingHspace("hello   ");
 *   // → "hello"
 *
 *   // Tabs stripped too; internal whitespace preserved.
 *   b.safeBuffer.stripTrailingHspace("a b\t\t");
 *   // → "a b"
 *
 *   // CR / LF intentionally preserved.
 *   b.safeBuffer.stripTrailingHspace("hello \n");
 *   // → "hello \n"
 *
 *   // Non-string passthrough.
 *   b.safeBuffer.stripTrailingHspace(42);
 *   // → 42
 */
function stripTrailingHspace(s) {
  if (typeof s !== "string") return s;
  return s.replace(TRAILING_HSPACE_RE, "");
}

/**
 * @primitive b.safeBuffer.isHex
 * @signature b.safeBuffer.isHex(s, expectedLength?)
 * @since     0.7.0
 * @related   b.safeBuffer.hasCrlf, b.crypto.timingSafeEqual
 *
 * Predicate for non-empty all-hex strings (case-insensitive). Pass
 * `expectedLength` to bound the protocol-fixed digests — SHA3-512 is
 * 128 hex chars, SHA-256 is 64, etc. Without `expectedLength` the
 * predicate is length-agnostic and the caller is responsible for
 * bounding length per protocol (X.509 serial, DKIM hash, audit-chain
 * digest).
 *
 * Non-string input returns `false` so the helper is safe in defensive
 * request-shape readers.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeBuffer.isHex("deadbeef");
 *   // → true
 *
 *   // Length-bounded check (SHA-256 = 64 hex chars).
 *   b.safeBuffer.isHex("deadbeef", 64);
 *   // → false
 *
 *   // Mixed case accepted.
 *   b.safeBuffer.isHex("DeadBeef");
 *   // → true
 *
 *   // Non-string returns false.
 *   b.safeBuffer.isHex(null);
 *   // → false
 */
function isHex(s, expectedLength) {
  if (typeof s !== "string") return false;
  if (typeof expectedLength === "number" && s.length !== expectedLength) return false;
  return HEX_RE.test(s);
}

/**
 * @primitive b.safeBuffer.hasCrlf
 * @signature b.safeBuffer.hasCrlf(s)
 * @since     0.7.0
 * @related   b.safeBuffer.stripCrlf, b.safeBuffer.stripTrailingHspace
 *
 * Detect CR or LF in a string — the canonical injection vector for
 * HTTP-header / SMTP-envelope smuggling. Header values containing CR
 * or LF must be rejected before serialization or stripped via
 * `stripCrlf`. Non-string input returns `false` so callers can chain
 * the predicate without pre-typechecking.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeBuffer.hasCrlf("X-Custom-Header: ok");
 *   // → false
 *
 *   // Injection attempt.
 *   b.safeBuffer.hasCrlf("ok\r\nX-Injected: bad");
 *   // → true
 *
 *   // Bare LF also detected.
 *   b.safeBuffer.hasCrlf("ok\nbad");
 *   // → true
 *
 *   // Non-string returns false.
 *   b.safeBuffer.hasCrlf(undefined);
 *   // → false
 */
function hasCrlf(s) {
  return typeof s === "string" && CRLF_RE.test(s);
}

/**
 * @primitive b.safeBuffer.stripCrlf
 * @signature b.safeBuffer.stripCrlf(s, replacement?)
 * @since     0.7.0
 * @related   b.safeBuffer.hasCrlf, b.safeBuffer.stripTrailingHspace
 *
 * Remove every CR and LF from a string, replacing each with the
 * `replacement` argument (default `""`). Use this when the framework
 * must serialize an operator-supplied string into a CRLF-delimited
 * protocol (HTTP header value, SMTP envelope field) and prefers
 * silent stripping over rejecting the request — most security-
 * critical sites should use `hasCrlf` + reject instead.
 *
 * Non-string input passes through unchanged.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeBuffer.stripCrlf("ok\r\nbad");
 *   // → "okbad"
 *
 *   // Custom replacement (e.g. space).
 *   b.safeBuffer.stripCrlf("a\nb\nc", " ");
 *   // → "a b c"
 *
 *   // Non-string passthrough.
 *   b.safeBuffer.stripCrlf(42);
 *   // → 42
 */
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
  IPV6_HEXTET_RE:        IPV6_HEXTET_RE,
  TRACE_ID_HEX_RE:       TRACE_ID_HEX_RE,
  SPAN_ID_HEX_RE:        SPAN_ID_HEX_RE,
  RFC7230_TCHAR_RE:      RFC7230_TCHAR_RE,
  CRLF_RE:               CRLF_RE,
  TRAILING_HSPACE_RE:    TRAILING_HSPACE_RE,
  SafeBufferError:       SafeBufferError,
};

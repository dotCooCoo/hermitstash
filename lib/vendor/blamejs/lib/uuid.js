// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.uuid
 * @featured true
 * @nav    Tools
 * @title  UUID
 *
 * @intro
 *   RFC 9562 v4 (random) + v7 (time-ordered).
 *
 *   v4 is fully random — the standard portable choice when ordering
 *   doesn't matter. v7 prefixes a 48-bit Unix-millisecond timestamp,
 *   then 74 random bits — IDs sort by creation time even
 *   lexicographically, ideal as a database PK because B-tree inserts
 *   stay near the right edge.
 *
 *   All entropy comes from `b.crypto.generateBytes`, which routes
 *   through Node's `crypto.randomBytes` — same source as
 *   `crypto.randomUUID()`.
 *
 *   Why ship v7 ourselves? Native `crypto.randomUUID()` only emits
 *   v4. v7 is the modern recommendation for any UUID landing in a
 *   sortable column (job queues, audit chain extensions, anything
 *   where insertion order matters for index locality).
 *
 * @card
 *   RFC 9562 v4 (random) + v7 (time-ordered).
 */
var C = require("./constants");
var { generateBytes } = require("./crypto");

var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
var UUID_LOOSE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

var UUID_BYTE_LEN          = C.BYTES.bytes(16);
var UUID_STR_MAX_LEN       = 36;
var HEX_TIME_LOW_END       = C.BYTES.bytes(8);
var HEX_TIME_MID_END       = C.BYTES.bytes(12);
var HEX_TIME_HI_VER_END    = C.BYTES.bytes(16);
var HEX_CLOCK_SEQ_END      = C.BYTES.bytes(20);
var HEX_NODE_END           = C.BYTES.bytes(32);
var BYTE_VERSION_IDX       = 6;
var BYTE_VARIANT_IDX       = C.BYTES.bytes(8);

function _bytesToString(bytes) {
  var hex = bytes.toString("hex");
  return hex.slice(0, HEX_TIME_LOW_END) + "-" +
         hex.slice(HEX_TIME_LOW_END, HEX_TIME_MID_END) + "-" +
         hex.slice(HEX_TIME_MID_END, HEX_TIME_HI_VER_END) + "-" +
         hex.slice(HEX_TIME_HI_VER_END, HEX_CLOCK_SEQ_END) + "-" +
         hex.slice(HEX_CLOCK_SEQ_END, HEX_NODE_END);
}

/**
 * @primitive b.uuid.v4
 * @signature b.uuid.v4()
 * @since     0.1.0
 * @related   b.uuid.v7, b.uuid.parse
 *
 * Fully random 128-bit UUID. Standard, portable; the default choice
 * when ordering doesn't matter. Returns the canonical 8-4-4-4-12
 * hex form.
 *
 * @example
 *   var id = b.uuid.v4();
 *   // → "f47ac10b-58cc-4372-a567-0e02b2c3d479"
 */
function v4() {
  var b = generateBytes(UUID_BYTE_LEN);
  b[BYTE_VERSION_IDX] = (b[BYTE_VERSION_IDX] & 0x0f) | 0x40;
  b[BYTE_VARIANT_IDX] = (b[BYTE_VARIANT_IDX] & 0x3f) | 0x80;
  return _bytesToString(b);
}

/**
 * @primitive b.uuid.v7
 * @signature b.uuid.v7(opts?)
 * @since     0.4.0
 * @related   b.uuid.v4, b.uuid.parse
 *
 * RFC 9562 §5.7 time-ordered UUID. The first 48 bits encode a Unix
 * millisecond timestamp (big-endian); the next 4 bits are version (7);
 * the remaining 74 bits are random. IDs generated within the same
 * millisecond sort by their random suffix; across milliseconds they
 * sort by time. B-tree index locality is dramatically better than v4
 * for INSERT-heavy tables.
 *
 * @opts
 *   now: number,   // override the timestamp (testing / fixtures)
 *
 * @example
 *   var id = b.uuid.v7();
 *   // → "01941bf3-9c4a-7d8e-9c11-3a4b5c6d7e8f"
 *
 *   // Deterministic fixture: same ms produces the same time prefix.
 *   var fixed = b.uuid.v7({ now: Date.UTC(2026, 0, 1) });
 *
 *   // v7 sorts by time even as plain strings:
 *   var earlier = b.uuid.v7({ now: 1700000000000 });
 *   var later   = b.uuid.v7({ now: 1700000001000 });
 *   earlier < later;   // → true
 */
function v7(opts) {
  var ms = (opts && typeof opts.now === "number") ? opts.now : Date.now();
  var b = generateBytes(UUID_BYTE_LEN);
  var msHi = Math.floor(ms / 0x100000000);
  var msLo = ms >>> 0;
  b[0] = (msHi >> 8) & 0xff;
  b[1] = msHi & 0xff;
  b[2] = (msLo >>> 24) & 0xff;
  b[3] = (msLo >>> 16) & 0xff;
  b[4] = (msLo >>>  8) & 0xff;
  b[5] = msLo & 0xff;
  b[BYTE_VERSION_IDX] = (b[BYTE_VERSION_IDX] & 0x0f) | 0x70;
  b[BYTE_VARIANT_IDX] = (b[BYTE_VARIANT_IDX] & 0x3f) | 0x80;
  return _bytesToString(b);
}

/**
 * @primitive b.uuid.parse
 * @signature b.uuid.parse(str)
 * @since     0.1.0
 * @related   b.uuid.isValid
 *
 * Strict parse: validates canonical form AND version (1-7) AND
 * RFC 9562 §4.1 variant. Returns `{ ok: true, version, bytes }` on success;
 * `{ ok: false, reason }` on failure. Never throws — operators who
 * want a thrown error layer one on top.
 *
 * @example
 *   var parsed = b.uuid.parse("f47ac10b-58cc-4372-a567-0e02b2c3d479");
 *   if (parsed.ok) {
 *     console.log(parsed.version);   // → 4
 *     console.log(parsed.bytes);     // → <Buffer f4 7a c1 0b ...>
 *   }
 *
 *   b.uuid.parse("not-a-uuid").ok;       // → false
 *   b.uuid.parse("not-a-uuid").reason;   // → "malformed"
 */
function parse(str) {
  if (typeof str !== "string") return { ok: false, reason: "not-a-string" };
  if (str.length > UUID_STR_MAX_LEN) return { ok: false, reason: "malformed" };
  if (!UUID_RE.test(str))            return { ok: false, reason: "malformed" };
  var hex = str.replace(/-/g, "");
  var bytes = Buffer.from(hex, "hex");
  var version = (bytes[BYTE_VERSION_IDX] >> 4) & 0x0f;
  var variant = (bytes[BYTE_VARIANT_IDX] >> 6) & 0x03;
  if (variant !== 0b10) return { ok: false, reason: "bad-variant" };
  return { ok: true, version: version, bytes: bytes };
}

/**
 * @primitive b.uuid.isValid
 * @signature b.uuid.isValid(str)
 * @since     0.1.0
 * @related   b.uuid.parse
 *
 * Loose shape-only check — returns `true` for any 8-4-4-4-12 hex
 * string regardless of version or variant bits. Cheap. Use `parse()`
 * when version/variant matter (most operator code does).
 *
 * @example
 *   b.uuid.isValid("f47ac10b-58cc-4372-a567-0e02b2c3d479");   // → true
 *   b.uuid.isValid("not-a-uuid");                             // → false
 */
function isValid(str) {
  if (typeof str !== "string") return false;
  if (str.length > UUID_STR_MAX_LEN) return false;
  return UUID_LOOSE_RE.test(str);
}

module.exports = {
  v4:      v4,
  v7:      v7,
  parse:   parse,
  isValid: isValid,
};

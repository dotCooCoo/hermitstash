// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.fileType
 * @nav    Validation
 * @title  File Type
 *
 * @intro
 *   Magic-byte content-type detection independent of the declared
 *   MIME. The Content-Type header on a multipart upload is supplied
 *   by the client; a hostile uploader can label a polyglot HTML
 *   payload as `image/png` and the header alone won't catch it.
 *   This primitive inspects the leading bytes against a hardcoded
 *   signature registry (PNG / JPEG / GIF / WEBP / AVIF / HEIC / PDF /
 *   OOXML / CFB / ZIP / RAR / 7Z / TAR / GZIP / BZ2 / XZ / MP3 / MP4
 *   / WEBM / PE / ELF / Mach-O) and returns the actual format.
 *
 *   `detect(buf)` returns `null` rather than throwing on bad input
 *   (saved-for-later analysis often runs against partial reads);
 *   `assertOneOf(buf, allowlist)` throws `FileTypeError` when the
 *   detected format is not in the operator-supplied allowlist.
 *   Allowlist entries match against `mime` ("image/png"), short
 *   `name` ("png"), or `category` ("image") — operators pin the
 *   tightest level the use case allows.
 *
 *   Out of scope: content disarm (CDR), polyglot detection, and
 *   filename-extension validation. Operators with disarm requirements
 *   reach for a sandbox like dangerzone or vmray; filename extensions
 *   live behind `b.guardFilename`. Operators extending the registry
 *   pass `opts.extra` to `detect` — extras come first, letting an
 *   operator override a built-in entry without forking.
 *
 * @card
 *   Magic-byte content-type detection independent of the declared MIME.
 */
/**
 * file-type — magic-byte content detection.
 *
 * MIME on a multipart upload comes from the CLIENT — a malicious
 * uploader can label a polyglot HTML payload as "image/png" and the
 * Content-Type header alone won't catch it. This primitive inspects
 * the leading bytes of a buffer against a hardcoded magic-byte
 * registry and returns the actual format independently of the
 * advertised MIME.
 *
 *   var detected = b.fileType.detect(buffer);
 *   // → { mime: "image/png", extension: "png", category: "image" }
 *   //   OR null when no signature matches
 *
 *   var ok = b.fileType.assertOneOf(buffer, ["image/png", "image/jpeg", "application/pdf"]);
 *   // → throws FileTypeError if the actual format isn't in the allowlist
 *
 * Coverage targets the formats most likely to flow through a typical
 * web app's upload boundary: images (PNG/JPEG/GIF/WEBP/AVIF/HEIC),
 * documents (PDF/DOCX/XLSX/PPTX), archives (ZIP/RAR/7Z/TAR/GZ),
 * audio/video (MP3/MP4/WEBM), and a small set of executable formats
 * to deny on upload (PE/ELF/Mach-O). Operators with format coverage
 * outside this list either pass an `extra` registry to extend, or
 * fall back to libmagic via an external sandbox process.
 *
 * Validation policy:
 *   - detect(buffer) → returns null on bad input rather than throwing
 *     (saved-for-later analysis often runs against partial reads)
 *   - assertOneOf(buffer, allowlist[, opts]) throws on mismatch.
 *     Operator opt: `allowEmpty: true` to permit zero-length buffers
 *     (default false — empty multipart parts are usually a mistake).
 *
 * Out of scope (operator brings their own):
 *   - Content disarm (CDR — strip Office macros, PDF JS, etc.).
 *     CDR is genuinely hard and format-specific; operators with that
 *     requirement reach for a sandbox like dangerzone or vmray.
 *   - Polyglot file detection (a single file that is BOTH valid PDF
 *     AND valid HTML). detect() returns the first signature match;
 *     true polyglot defense needs structural validation per format.
 *   - Filename-extension validation. The framework's view is:
 *     extensions are operator-controlled metadata, magic bytes are
 *     the wire truth.
 */
var C = require("./constants");
var { defineClass } = require("./framework-error");

var FileTypeError = defineClass("FileTypeError", { alwaysPermanent: true });
var _err = FileTypeError.factory;

// Cap on bytes inspected for OOXML / WEBP shape-check probes. Set well
// above any legitimate Office central-directory prefix and any RIFF
// header — operators don't tune this, the magic-byte registry is fixed.
var SNIFF_HEAD_BYTES = C.BYTES.kib(4);

// Signature registry. Each entry: { name, mime, extension, category,
// offset, magic: Buffer | [Buffer, ...], extra?: function(buffer)→bool }.
// Order matters — earlier entries win on ambiguous matches (e.g. ZIP
// shape catches OOXML, so OOXML-specific entries come FIRST).
var SIGNATURES = [
  // ---- Office Open XML (DOCX/XLSX/PPTX) ----
  // OOXML files are ZIP archives whose central directory contains
  // [Content_Types].xml. The cheap shape-check is the ZIP local-file
  // header (0x50 0x4B 0x03 0x04) PLUS the filename "[Content_Types].xml"
  // appearing within the first 256 bytes — present for every
  // well-formed OOXML produced by Office / LibreOffice / etc.
  { name: "docx", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    extension: "docx", category: "document",
    offset: 0, magic: Buffer.from([0x50, 0x4B, 0x03, 0x04]),
    extra: function (buf) {
      var head = buf.subarray(0, Math.min(buf.length, SNIFF_HEAD_BYTES)).toString("binary");
      return head.indexOf("word/") !== -1 || head.indexOf("[Content_Types].xml") !== -1 && head.indexOf("word") !== -1;
    } },
  { name: "xlsx", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    extension: "xlsx", category: "document",
    offset: 0, magic: Buffer.from([0x50, 0x4B, 0x03, 0x04]),
    extra: function (buf) {
      var head = buf.subarray(0, Math.min(buf.length, SNIFF_HEAD_BYTES)).toString("binary");
      return head.indexOf("xl/") !== -1;
    } },
  { name: "pptx", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    extension: "pptx", category: "document",
    offset: 0, magic: Buffer.from([0x50, 0x4B, 0x03, 0x04]),
    extra: function (buf) {
      var head = buf.subarray(0, Math.min(buf.length, SNIFF_HEAD_BYTES)).toString("binary");
      return head.indexOf("ppt/") !== -1;
    } },
  // ---- Plain ZIP (after OOXML so OOXML wins) ----
  { name: "zip", mime: "application/zip", extension: "zip", category: "archive",
    offset: 0, magic: [
      Buffer.from([0x50, 0x4B, 0x03, 0x04]),     // standard local file header
      Buffer.from([0x50, 0x4B, 0x05, 0x06]),     // empty archive
      Buffer.from([0x50, 0x4B, 0x07, 0x08]),     // spanned archive
    ] },

  // ---- Images ----
  { name: "png",  mime: "image/png",  extension: "png", category: "image",
    offset: 0, magic: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) },
  { name: "jpeg", mime: "image/jpeg", extension: "jpg", category: "image",
    offset: 0, magic: Buffer.from([0xFF, 0xD8, 0xFF]) },
  { name: "gif",  mime: "image/gif",  extension: "gif", category: "image",
    offset: 0, magic: [Buffer.from("GIF87a", "ascii"), Buffer.from("GIF89a", "ascii")] },
  { name: "webp", mime: "image/webp", extension: "webp", category: "image",
    offset: 0, magic: Buffer.from("RIFF", "ascii"),
    extra: function (buf) {
      // RIFF header: "RIFF" (0..3), file size (4..7), format tag at offset 8..11.
      return buf.length >= C.BYTES.bytes(12) &&
             buf.subarray(C.BYTES.bytes(0x08), C.BYTES.bytes(12)).toString("ascii") === "WEBP";
    } },
  { name: "bmp",  mime: "image/bmp",  extension: "bmp", category: "image",
    offset: 0, magic: Buffer.from([0x42, 0x4D]) },
  { name: "tiff", mime: "image/tiff", extension: "tiff", category: "image",
    offset: 0, magic: [
      Buffer.from([0x49, 0x49, 0x2A, 0x00]),     // little-endian
      Buffer.from([0x4D, 0x4D, 0x00, 0x2A]),     // big-endian
    ] },
  { name: "avif", mime: "image/avif", extension: "avif", category: "image",
    offset: 4, magic: Buffer.from("ftypavif", "ascii") },
  { name: "heic", mime: "image/heic", extension: "heic", category: "image",
    offset: 4, magic: [
      Buffer.from("ftypheic", "ascii"),
      Buffer.from("ftypheix", "ascii"),
      Buffer.from("ftypmif1", "ascii"),
      Buffer.from("ftypmsf1", "ascii"),
    ] },

  // ---- Documents (non-OOXML) ----
  { name: "pdf",  mime: "application/pdf", extension: "pdf", category: "document",
    offset: 0, magic: Buffer.from("%PDF-", "ascii") },
  { name: "rtf",  mime: "application/rtf", extension: "rtf", category: "document",
    offset: 0, magic: Buffer.from("{\\rtf", "ascii") },
  // CFB (Compound File Binary) — old Office (.doc/.xls/.ppt before 2007),
  // also MSI installers.
  { name: "cfb",  mime: "application/x-cfb", extension: "doc", category: "document",
    offset: 0, magic: Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) },

  // ---- Archives ----
  { name: "rar",  mime: "application/vnd.rar", extension: "rar", category: "archive",
    offset: 0, magic: [
      Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),       // RAR 1.5
      Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]), // RAR 5
    ] },
  { name: "7z",   mime: "application/x-7z-compressed", extension: "7z", category: "archive",
    offset: 0, magic: Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) },
  { name: "gz",   mime: "application/gzip", extension: "gz", category: "archive",
    offset: 0, magic: Buffer.from([0x1F, 0x8B]) },
  { name: "bz2",  mime: "application/x-bzip2", extension: "bz2", category: "archive",
    offset: 0, magic: Buffer.from("BZh", "ascii") },
  { name: "xz",   mime: "application/x-xz", extension: "xz", category: "archive",
    offset: 0, magic: Buffer.from([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) },
  { name: "tar",  mime: "application/x-tar", extension: "tar", category: "archive",
    offset: 257, magic: Buffer.from("ustar", "ascii") },

  // ---- Audio / video ----
  { name: "mp3",  mime: "audio/mpeg", extension: "mp3", category: "audio",
    offset: 0, magic: [
      Buffer.from([0x49, 0x44, 0x33]),  // ID3v2 tag
      Buffer.from([0xFF, 0xFB]),        // MPEG audio frame (no ID3)
      Buffer.from([0xFF, 0xF3]),
      Buffer.from([0xFF, 0xF2]),
    ] },
  { name: "mp4",  mime: "video/mp4", extension: "mp4", category: "video",
    offset: 4, magic: [
      Buffer.from("ftypisom", "ascii"),
      Buffer.from("ftypiso2", "ascii"),
      Buffer.from("ftypmp42", "ascii"),
      Buffer.from("ftypM4V ", "ascii"),
    ] },
  { name: "webm", mime: "video/webm", extension: "webm", category: "video",
    offset: 0, magic: Buffer.from([0x1A, 0x45, 0xDF, 0xA3]) },

  // ---- Executables (operators usually DENY these on upload) ----
  { name: "pe",     mime: "application/x-msdownload", extension: "exe", category: "executable",
    offset: 0, magic: Buffer.from([0x4D, 0x5A]) },
  { name: "elf",    mime: "application/x-executable", extension: "elf", category: "executable",
    offset: 0, magic: Buffer.from([0x7F, 0x45, 0x4C, 0x46]) },
  { name: "macho",  mime: "application/x-mach-binary", extension: "macho", category: "executable",
    offset: 0, magic: [
      Buffer.from([0xFE, 0xED, 0xFA, 0xCE]),     // big-endian, narrow word
      Buffer.from([0xFE, 0xED, 0xFA, 0xCF]),     // big-endian, wide word
      Buffer.from([0xCE, 0xFA, 0xED, 0xFE]),     // little-endian, narrow word
      Buffer.from([0xCF, 0xFA, 0xED, 0xFE]),     // little-endian, wide word
      Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]),     // universal binary (also Java .class)
    ] },
];

function _matchesAt(buf, offset, magic) {
  if (buf.length < offset + magic.length) return false;
  for (var i = 0; i < magic.length; i++) {
    if (buf[offset + i] !== magic[i]) return false;
  }
  return true;
}

function _entryMatches(entry, buf) {
  var magics = Array.isArray(entry.magic) ? entry.magic : [entry.magic];
  var matched = false;
  for (var i = 0; i < magics.length; i++) {
    if (_matchesAt(buf, entry.offset || 0, magics[i])) { matched = true; break; }
  }
  if (!matched) return false;
  if (typeof entry.extra === "function") {
    try { return !!entry.extra(buf); }
    catch (_e) { return false; }
  }
  return true;
}

/**
 * @primitive b.fileType.detect
 * @signature b.fileType.detect(buf, opts?)
 * @since     0.1.0
 * @related   b.fileType.assertOneOf, b.fileUpload.create
 *
 * Inspects the leading bytes of `buf` against the signature registry
 * and returns `{ mime, extension, category, name }` for the first
 * matching entry, or `null` when no signature matches (or `buf` is
 * empty, or not a Buffer/Uint8Array). OOXML entries (`docx`/`xlsx`/
 * `pptx`) sit before generic ZIP so well-formed Office files win
 * before the bare ZIP shape; operators extending the registry via
 * `opts.extra` get their entries scanned first so they can override
 * built-ins without forking.
 *
 * @opts
 *   extra: Array<{ name, mime, extension, category, offset, magic, extra? }>,
 *
 * @example
 *   var fs = require("node:fs");
 *   var buf = fs.readFileSync("photo.png");
 *   b.fileType.detect(buf);
 *   // → { mime: "image/png", extension: "png", category: "image", name: "png" }
 *
 *   b.fileType.detect(Buffer.from(""));   // → null
 */
function detect(buf, opts) {
  if (!Buffer.isBuffer(buf)) {
    if (buf instanceof Uint8Array) buf = Buffer.from(buf);
    else return null;
  }
  if (buf.length === 0) return null;
  var registry = SIGNATURES;
  if (opts && Array.isArray(opts.extra) && opts.extra.length > 0) {
    // Operator-extended registry: extras come FIRST so an operator can
    // override a built-in (e.g. tighten OOXML check) without forking.
    registry = opts.extra.concat(SIGNATURES);
  }
  for (var i = 0; i < registry.length; i++) {
    var entry = registry[i];
    if (_entryMatches(entry, buf)) {
      return { mime: entry.mime, extension: entry.extension, category: entry.category, name: entry.name };
    }
  }
  return null;
}

/**
 * @primitive b.fileType.assertOneOf
 * @signature b.fileType.assertOneOf(buf, allowlist, opts?)
 * @since     0.1.0
 * @related   b.fileType.detect, b.fileUpload.create
 *
 * Detects the format of `buf` and throws `FileTypeError` when the
 * result is not in `allowlist`. Allowlist entries match by `mime`
 * ("image/png"), short `name` ("png"), or `category` ("image") so
 * operators pin the tightest level the use case allows. Empty
 * buffers throw `EMPTY` unless `opts.allowEmpty: true`. Unrecognized
 * magic bytes throw `UNKNOWN_TYPE` — the framework refuses to fall
 * back to the advertised header MIME because the entire purpose of
 * this primitive is mistrusting that header.
 *
 * @opts
 *   allowEmpty: boolean,                                                // default false
 *   extra:      Array<{ name, mime, extension, category, offset, magic, extra? }>,
 *
 * @example
 *   var fs = require("node:fs");
 *   var buf = fs.readFileSync("photo.png");
 *   var detected = b.fileType.assertOneOf(buf, ["image/png", "image/jpeg"]);
 *   // → { mime: "image/png", extension: "png", category: "image", name: "png" }
 *
 *   // Category-level allowlist (any image format)
 *   b.fileType.assertOneOf(buf, ["image"]);
 */
function assertOneOf(buf, allowlist, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(buf) && !(buf instanceof Uint8Array)) {
    throw _err("BAD_INPUT", "fileType.assertOneOf: input must be a Buffer or Uint8Array, got " + typeof buf);
  }
  if (Buffer.isBuffer(buf) === false) buf = Buffer.from(buf);
  if (buf.length === 0) {
    if (opts.allowEmpty === true) return null;
    throw _err("EMPTY", "fileType.assertOneOf: input is zero bytes");
  }
  if (!Array.isArray(allowlist) || allowlist.length === 0) {
    throw _err("BAD_OPT", "fileType.assertOneOf: allowlist must be a non-empty array");
  }
  var detected = detect(buf, opts);
  if (!detected) {
    throw _err("UNKNOWN_TYPE",
      "fileType.assertOneOf: no signature matched the leading bytes (advertised MIME cannot be trusted alone)");
  }
  // allowlist entries match against `mime` OR `name` OR `category` —
  // operators can pin "image/png" specifically OR "image" for the
  // whole image bucket.
  var allowed = false;
  for (var i = 0; i < allowlist.length; i++) {
    if (allowlist[i] === detected.mime ||
        allowlist[i] === detected.name ||
        allowlist[i] === detected.category) {
      allowed = true; break;
    }
  }
  if (!allowed) {
    throw _err("DISALLOWED_TYPE",
      "fileType.assertOneOf: detected '" + detected.mime + "' (" + detected.name +
      ", category=" + detected.category + ") not in allowlist " + JSON.stringify(allowlist));
  }
  return detected;
}

module.exports = {
  detect:        detect,
  assertOneOf:   assertOneOf,
  FileTypeError: FileTypeError,
  // Internal — exposed so tests can introspect the registry shape.
  _SIGNATURES:   SIGNATURES,
};

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
var C = require("./constants");
var { defineClass } = require("./framework-error");

var FileTypeError = defineClass("FileTypeError", { alwaysPermanent: true });
var _err = FileTypeError.factory;

var SNIFF_HEAD_BYTES = C.BYTES.kib(4);

var SIGNATURES = [
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
  { name: "zip", mime: "application/zip", extension: "zip", category: "archive",
    offset: 0, magic: [
      Buffer.from([0x50, 0x4B, 0x03, 0x04]),
      Buffer.from([0x50, 0x4B, 0x05, 0x06]),
      Buffer.from([0x50, 0x4B, 0x07, 0x08]),
    ] },

  { name: "png",  mime: "image/png",  extension: "png", category: "image",
    offset: 0, magic: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) },
  { name: "jpeg", mime: "image/jpeg", extension: "jpg", extensionAliases: ["jpeg"],
    category: "image",
    offset: 0, magic: Buffer.from([0xFF, 0xD8, 0xFF]) },
  { name: "gif",  mime: "image/gif",  extension: "gif", category: "image",
    offset: 0, magic: [Buffer.from("GIF87a", "ascii"), Buffer.from("GIF89a", "ascii")] },
  { name: "webp", mime: "image/webp", extension: "webp", category: "image",
    offset: 0, magic: Buffer.from("RIFF", "ascii"),
    extra: function (buf) {
      return buf.length >= C.BYTES.bytes(12) &&
             buf.subarray(C.BYTES.bytes(0x08), C.BYTES.bytes(12)).toString("ascii") === "WEBP";
    } },
  { name: "bmp",  mime: "image/bmp",  extension: "bmp", category: "image",
    offset: 0, magic: Buffer.from([0x42, 0x4D]) },
  { name: "tiff", mime: "image/tiff", extension: "tiff", extensionAliases: ["tif"],
    category: "image",
    offset: 0, magic: [
      Buffer.from([0x49, 0x49, 0x2A, 0x00]),
      Buffer.from([0x4D, 0x4D, 0x00, 0x2A]),
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

  { name: "pdf",  mime: "application/pdf", extension: "pdf", category: "document",
    offset: 0, magic: Buffer.from("%PDF-", "ascii") },
  { name: "rtf",  mime: "application/rtf", extension: "rtf", category: "document",
    offset: 0, magic: Buffer.from("{\\rtf", "ascii") },
  { name: "cfb",  mime: "application/x-cfb", extension: "doc", category: "document",
    offset: 0, magic: Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) },

  { name: "rar",  mime: "application/vnd.rar", extension: "rar", category: "archive",
    offset: 0, magic: [
      Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
      Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]),
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

  { name: "mp3",  mime: "audio/mpeg", extension: "mp3", category: "audio",
    offset: 0, magic: [
      Buffer.from([0x49, 0x44, 0x33]),
      Buffer.from([0xFF, 0xFB]),
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

  { name: "pe",     mime: "application/x-msdownload", extension: "exe", category: "executable",
    offset: 0, magic: Buffer.from([0x4D, 0x5A]) },
  { name: "elf",    mime: "application/x-executable", extension: "elf", category: "executable",
    offset: 0, magic: Buffer.from([0x7F, 0x45, 0x4C, 0x46]) },
  { name: "macho",  mime: "application/x-mach-binary", extension: "macho", category: "executable",
    offset: 0, magic: [
      Buffer.from([0xFE, 0xED, 0xFA, 0xCE]),
      Buffer.from([0xFE, 0xED, 0xFA, 0xCF]),
      Buffer.from([0xCE, 0xFA, 0xED, 0xFE]),
      Buffer.from([0xCF, 0xFA, 0xED, 0xFE]),
      Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]),
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
 * magic bytes throw `file-type/unknown-type` — the framework refuses to fall
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
    throw _err("file-type/bad-input", "fileType.assertOneOf: input must be a Buffer or Uint8Array, got " + typeof buf);
  }
  if (Buffer.isBuffer(buf) === false) buf = Buffer.from(buf);
  if (buf.length === 0) {
    if (opts.allowEmpty === true) return null;
    throw _err("file-type/empty", "fileType.assertOneOf: input is zero bytes");
  }
  if (!Array.isArray(allowlist) || allowlist.length === 0) {
    throw _err("file-type/bad-opt", "fileType.assertOneOf: allowlist must be a non-empty array");
  }
  var detected = detect(buf, opts);
  if (!detected) {
    throw _err("file-type/unknown-type",
      "fileType.assertOneOf: no signature matched the leading bytes (advertised MIME cannot be trusted alone)");
  }
  var allowed = false;
  for (var i = 0; i < allowlist.length; i++) {
    if (allowlist[i] === detected.mime ||
        allowlist[i] === detected.name ||
        allowlist[i] === detected.category) {
      allowed = true; break;
    }
  }
  if (!allowed) {
    throw _err("file-type/disallowed-type",
      "fileType.assertOneOf: detected '" + detected.mime + "' (" + detected.name +
      ", category=" + detected.category + ") not in allowlist " + JSON.stringify(allowlist));
  }
  return detected;
}

var _MIME_TO_EXT = Object.create(null);
var _EXT_TO_MIME = Object.create(null);
SIGNATURES.forEach(function (row) {
  if (row.mime && !(row.mime.toLowerCase() in _MIME_TO_EXT)) {
    _MIME_TO_EXT[row.mime.toLowerCase()] = row.extension;
  }
  if (row.extension && !(row.extension.toLowerCase() in _EXT_TO_MIME)) {
    _EXT_TO_MIME[row.extension.toLowerCase()] = row.mime;
  }
  if (Array.isArray(row.extensionAliases)) {
    row.extensionAliases.forEach(function (alias) {
      if (alias && !(alias.toLowerCase() in _EXT_TO_MIME)) {
        _EXT_TO_MIME[alias.toLowerCase()] = row.mime;
      }
    });
  }
});

/**
 * @primitive b.fileType.extensionFor
 * @signature b.fileType.extensionFor(mime)
 * @since     0.18.43
 * @status    stable
 * @related   b.fileType.detect, b.fileType.mimeFor
 *
 * The canonical file extension for a MIME type, with no leading dot, or `null`
 * when the framework does not recognize the type. Never a guess: a caller
 * minting an object-store key or a `Content-Disposition` filename needs to
 * know when the answer is unknown rather than receive a plausible-looking one.
 *
 * `detect` answers "what is this"; the next question is usually "what should I
 * call it", and the table that answers it is the same one. Reading it here
 * rather than keeping a private copy is what stops the two drifting when a
 * signature is added.
 *
 * The lookup is case-insensitive and ignores content-type parameters, so the
 * `Content-Type` header value a request arrived with can be passed straight in.
 *
 * @example
 *   b.fileType.extensionFor("image/png");
 *   // → "png"
 */
function extensionFor(mime) {
  if (typeof mime !== "string" || mime.length === 0) return null;
  var bare = mime.split(";")[0].trim().toLowerCase();
  if (bare.length === 0) return null;
  return Object.prototype.hasOwnProperty.call(_MIME_TO_EXT, bare) ? _MIME_TO_EXT[bare] : null;
}

/**
 * @primitive b.fileType.mimeFor
 * @signature b.fileType.mimeFor(extension)
 * @since     0.18.43
 * @status    stable
 * @related   b.fileType.detect, b.fileType.extensionFor
 *
 * The MIME type for a file extension, or `null` when the framework does not
 * recognize it. The inverse of `b.fileType.extensionFor`, over the same table.
 *
 * A leading dot is accepted, because that is the form `path.extname` returns
 * and therefore the form a caller usually has in hand. The lookup is
 * case-insensitive.
 *
 * This answers a naming question, not a trust question. It reports what an
 * extension claims; it does not establish what a file IS. Only
 * `b.fileType.detect` does that, by reading the bytes — an attacker controls
 * the name, never the magic.
 *
 * @example
 *   b.fileType.mimeFor(".png");
 *   // → "image/png"
 */
function mimeFor(extension) {
  if (typeof extension !== "string" || extension.length === 0) return null;
  var ext = extension.charAt(0) === "." ? extension.slice(1) : extension;
  ext = ext.trim().toLowerCase();
  if (ext.length === 0) return null;
  return Object.prototype.hasOwnProperty.call(_EXT_TO_MIME, ext) ? _EXT_TO_MIME[ext] : null;
}

module.exports = {
  detect:        detect,
  assertOneOf:   assertOneOf,
  extensionFor:  extensionFor,
  mimeFor:       mimeFor,
  FileTypeError: FileTypeError,
  _SIGNATURES:   SIGNATURES,
};

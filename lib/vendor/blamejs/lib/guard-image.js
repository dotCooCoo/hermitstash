// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.guardImage
 * @nav    Guards
 * @title  Guard Image
 *
 * @intro
 *   Image content-safety guard — closes the magic-byte / declared-MIME
 *   mismatch class and the polyglot-file class without vendoring a
 *   raster decoder. Operators bring their own decoder (sharp, jimp,
 *   libvips bindings) and feed structural metadata to the guard.
 *   `KIND="metadata"` — consumes `ctx.metadata` shape `{ bytes?,
 *   declaredMime?, width?, height?, frames?, colorDepth?, hasAlpha? }`.
 *
 *   Magic-byte dispatch: `inspectMagic(bytes)` walks a signature table
 *   covering PNG (`89 50 4E 47 0D 0A 1A 0A`), JPEG (`FF D8 FF`),
 *   GIF87a / GIF89a, WebP (RIFF + WEBP at offset 8), BMP, ICO, TIFF
 *   (II / MM), AVIF / HEIC (`ftyp` boxes at offset 4), and SVG (`<?xml`
 *   / `<svg`). Returns the list of distinct MIMEs that match. Multiple
 *   matches signals a polyglot file (PHP-in-JPEG / JS-in-PNG class) —
 *   refused under every profile.
 *
 *   Dimension caps: oversized width / height refused against
 *   `maxWidth` / `maxHeight` (strict 8 192 px, balanced 16 384 px,
 *   permissive 65 536 px). Frame caps for animated GIF / WebP / APNG /
 *   AVIF image sequences refused against `maxFrames` (strict 60,
 *   balanced 200, permissive 1000). Operator-supplied — the guard
 *   does not decode bytes itself; the operator's decoder reports the
 *   metadata before passing it to the gate.
 *
 *   Polyglot rejection: when `_detectMagicMimes` returns more than one
 *   distinct format, the buffer carries multiple magic-byte signatures
 *   (e.g. JPEG marker followed by an embedded ZIP central directory) —
 *   refused at every profile.
 *
 *   EXIF / XMP / IPTC metadata strip: `sanitize` removes the metadata
 *   segments in-framework by walking the container framing (JPEG APPn/COM
 *   markers, PNG ancillary text chunks, GIF comment/application extensions,
 *   WebP EXIF/XMP RIFF chunks) — the privacy-leak and metadata-stego surface,
 *   stripped without a vendored decoder. Pixel transcoding / dimension
 *   downscale still belong to the operator's decoder (sharp's
 *   `withMetadata: false`, libvips `metadata-strip`); formats whose metadata
 *   lives in an offset-based structure (TIFF / HEIC / AVIF) are refused rather
 *   than passed through.
 *
 *   SVG routing: bytes that match the SVG magic are refused under every
 *   profile — operators must route SVG explicitly to `b.guardSvg`
 *   because the SVG threat catalog (XXE, billion-laughs, animation
 *   href injection, foreignObject namespace shift) is distinct from
 *   raster threats.
 *
 *   Operator-feeds-metadata pattern: the gate trusts the metadata
 *   object the operator supplies. The operator's decoder is the
 *   ground truth for `width` / `height` / `frames`; the guard refuses
 *   based on those values. This keeps the framework's no-deps stance
 *   intact while still closing the policy gaps.
 *
 *   Profiles `strict` / `balanced` / `permissive` and compliance
 *   postures `hipaa` / `pci-dss` / `gdpr` / `soc2` overlay on the
 *   profile baseline.
 *
 * @card
 *   Image content-safety guard — closes the magic-byte / declared-MIME mismatch class and the polyglot-file class without vendoring a raster decoder.
 */

var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var gateContract = require("./gate-contract");
var C = require("./constants");
var { GuardImageError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardImageError.factory;

var MAGIC_BYTES = Object.freeze([
  { mime: "image/png", bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
  { mime: "image/jpeg", bytes: [0xFF, 0xD8, 0xFF] },
  { mime: "image/gif", bytes: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61] },
  { mime: "image/gif", bytes: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61] },
  { mime: "image/webp", bytes: [0x52, 0x49, 0x46, 0x46], tail: [0x57, 0x45, 0x42, 0x50], tailOffset: 8 },
  { mime: "image/bmp", bytes: [0x42, 0x4D] },
  { mime: "image/x-icon", bytes: [0x00, 0x00, 0x01, 0x00] },
  { mime: "image/tiff", bytes: [0x49, 0x49, 0x2A, 0x00] },
  { mime: "image/tiff", bytes: [0x4D, 0x4D, 0x00, 0x2A] },
  { mime: "image/heic", bytes: [0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63], offset: 4 },
  { mime: "image/heic", bytes: [0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x78], offset: 4 },
  { mime: "image/avif", bytes: [0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66], offset: 4 },
  { mime: "image/svg+xml", bytes: [0x3C, 0x3F, 0x78, 0x6D, 0x6C], textFamily: true },
  { mime: "image/svg+xml", bytes: [0x3C, 0x73, 0x76, 0x67], textFamily: true },
]);

var PROFILES = Object.freeze({
  "strict": {
    mismatchPolicy:           "reject",
    polyglotPolicy:            "reject",
    unknownMagicPolicy:        "reject",
    svgRoutingPolicy:          "reject",
    dimensionsPolicy:          "reject",
    framesPolicy:              "reject",
    maxWidth:                  C.BYTES.bytes(8192),
    maxHeight:                 C.BYTES.bytes(8192),
    maxFrames:                 60,                                               // allow:raw-time-literal — max-frame count 60; coincidental multiple-of-60, not a duration, C.TIME N/A
    maxBytes:                  C.BYTES.mib(32),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
  "balanced": {
    mismatchPolicy:           "reject",
    polyglotPolicy:            "reject",
    unknownMagicPolicy:        "audit",
    svgRoutingPolicy:          "reject",
    dimensionsPolicy:          "audit",
    framesPolicy:              "audit",
    maxWidth:                  C.BYTES.bytes(16384),
    maxHeight:                 C.BYTES.bytes(16384),
    maxFrames:                 200,
    maxBytes:                  C.BYTES.mib(64),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
  "permissive": {
    mismatchPolicy:           "reject",
    polyglotPolicy:            "reject",
    unknownMagicPolicy:        "audit",
    svgRoutingPolicy:          "reject",
    dimensionsPolicy:          "audit",
    framesPolicy:              "audit",
    maxWidth:                  C.BYTES.bytes(65536),
    maxHeight:                 C.BYTES.bytes(65536),
    maxFrames:                 1000,
    maxBytes:                  C.BYTES.mib(256),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var INT_OPTS = ["maxBytes", "maxWidth", "maxHeight", "maxFrames"];

var POLICY_ENUM = gateContract.policyVocabulary([
  "magicPolicy", "mismatchPolicy", "polyglotPolicy", "svgRoutingPolicy",
  "dimensionsPolicy", "framesPolicy", "unknownMagicPolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

function _bytesAt(buf, offset, sig) {
  if (buf.length < offset + sig.length) return false;
  for (var i = 0; i < sig.length; i += 1) {
    if (buf[offset + i] !== sig[i]) return false;
  }
  return true;
}

function _detectMagicMimes(buf) {
  if (!buf || typeof buf.length !== "number") return [];
  var bom = (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) ? 3 : 0;
  var hits = [];
  for (var i = 0; i < MAGIC_BYTES.length; i += 1) {
    var entry = MAGIC_BYTES[i];
    var shift = entry.textFamily ? bom : 0;
    var offset = (entry.offset || 0) + shift;
    if (!_bytesAt(buf, offset, entry.bytes)) continue;
    if (entry.tail && !_bytesAt(buf, entry.tailOffset + shift, entry.tail)) continue;
    hits.push(entry.mime);
  }
  return hits;
}

function _detectIssues(metadata, opts) {
  var issues = [];
  if (!metadata || typeof metadata !== "object") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "image.bad-input",
              snippet: "image metadata is not an object" }];
  }

  var bytes = metadata.bytes;
  var byteCount = safeBuffer.byteLengthOfIfMeasurable(bytes);
  if (byteCount !== null && byteCount > opts.maxBytes) {
    return [{ kind: "image-cap", severity: "high",
              ruleId: "image.image-cap",
              snippet: "image bytes exceed maxBytes " + opts.maxBytes }];
  }

  var hits = bytes ? _detectMagicMimes(bytes) : [];
  var unique = {};
  for (var hi = 0; hi < hits.length; hi += 1) unique[hits[hi]] = true;
  var uniqueHits = Object.keys(unique);

  if (uniqueHits.length > 1 && opts.polyglotPolicy !== "allow") {
    issues.push({
      kind: "polyglot", severity: "critical",
      ruleId: "image.polyglot",
      snippet: "buffer matches multiple image-format magic bytes (" +
               uniqueHits.join(", ") + ") — polyglot file class " +
               "(PHP-in-JPEG / JS-in-PNG)",
    });
  }

  if (uniqueHits.indexOf("image/svg+xml") !== -1 &&
      opts.svgRoutingPolicy !== "allow") {
    issues.push({
      kind: "svg-routing", severity: "high",
      ruleId: "image.svg-routing",
      snippet: "buffer is SVG — route explicitly to b.guardSvg " +
               "(SVG threat catalog is distinct from raster images)",
    });
  }

  if (typeof metadata.declaredMime === "string" && bytes &&
      uniqueHits.length > 0 &&
      uniqueHits.indexOf(metadata.declaredMime.toLowerCase()) === -1 &&
      opts.mismatchPolicy !== "allow") {
    issues.push({
      kind: "mime-mismatch", severity: "high",
      ruleId: "image.mime-mismatch",
      snippet: "declared MIME `" + metadata.declaredMime + "` does not " +
               "match magic-byte detection (got " + uniqueHits.join(", ") +
               ")",
    });
  }

  if (bytes && uniqueHits.length === 0 &&
      opts.unknownMagicPolicy !== "allow") {
    issues.push({
      kind: "unknown-magic",
      severity: opts.unknownMagicPolicy === "reject" ? "high" : "warn",
      ruleId: "image.unknown-magic",
      snippet: "buffer does not match any known image-format magic " +
               "bytes (PNG / JPEG / GIF / WebP / BMP / ICO / TIFF / " +
               "AVIF / HEIC)",
    });
  }

  if (opts.dimensionsPolicy !== "allow") {
    if (typeof metadata.width === "number" && metadata.width > opts.maxWidth) {
      issues.push({
        kind: "width-cap",
        severity: opts.dimensionsPolicy === "reject" ? "high" : "warn",
        ruleId: "image.width-cap",
        snippet: "width " + metadata.width + " exceeds maxWidth " +
                 opts.maxWidth,
      });
    }
    if (typeof metadata.height === "number" && metadata.height > opts.maxHeight) {
      issues.push({
        kind: "height-cap",
        severity: opts.dimensionsPolicy === "reject" ? "high" : "warn",
        ruleId: "image.height-cap",
        snippet: "height " + metadata.height + " exceeds maxHeight " +
                 opts.maxHeight,
      });
    }
  }

  if (typeof metadata.frames === "number" &&
      opts.framesPolicy !== "allow" &&
      metadata.frames > opts.maxFrames) {
    issues.push({
      kind: "frames-cap",
      severity: opts.framesPolicy === "reject" ? "high" : "warn",
      ruleId: "image.frames-cap",
      snippet: "frames " + metadata.frames + " exceeds maxFrames " +
               opts.maxFrames,
    });
  }

  return issues;
}

/**
 * @primitive  b.guardImage.validate
 * @signature  b.guardImage.validate(input, opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardImage.sanitize, b.guardImage.gate, b.guardImage.inspectMagic
 *
 * Inspect an image-metadata bag `{ bytes?, declaredMime?, width?,
 * height?, frames? }` and return `{ ok, issues }`. Issues carry
 * `{ kind, severity, ruleId, snippet }`. Detected: magic-byte / MIME
 * mismatch (`mime-mismatch`), polyglot file (`polyglot`, refused
 * under every profile), SVG bytes routed through guardImage
 * (`svg-routing`, must go to `b.guardSvg`), unknown magic
 * (`unknown-magic`), oversized width / height (`width-cap` /
 * `height-cap`), excessive frame count (`frames-cap`), oversized
 * byte length (`image-cap`). Pure inspection — never mutates input
 * or throws on hostile metadata.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   mismatchPolicy:     "reject"|"audit"|"allow",
 *   polyglotPolicy:     "reject"|"audit"|"allow",
 *   unknownMagicPolicy: "reject"|"audit"|"allow",
 *   svgRoutingPolicy:   "reject"|"audit"|"allow",
 *   dimensionsPolicy:   "reject"|"audit"|"allow",
 *   framesPolicy:       "reject"|"audit"|"allow",
 *   maxWidth:           number,    // strict 8192, balanced 16384, permissive 65536
 *   maxHeight:          number,    // strict 8192, balanced 16384, permissive 65536
 *   maxFrames:          number,    // strict 60, balanced 200, permissive 1000
 *   maxBytes:           number,    // strict 32 MiB, balanced 64 MiB, permissive 256 MiB
 *
 * @example
 *   // Mismatch — declared image/png but bytes are JPEG.
 *   var rv = b.guardImage.validate({
 *     bytes: Buffer.from([0xFF, 0xD8, 0xFF]),
 *     declaredMime: "image/png",
 *   }, { profile: "strict" });
 *   rv.ok;                                               // → false
 *   rv.issues[0].kind;                                   // → "mime-mismatch"
 *
 *   // Oversized width refused under strict (8192 px cap).
 *   var big = b.guardImage.validate({
 *     bytes: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
 *     declaredMime: "image/png",
 *     width: 16384, height: 16384,
 *   }, { profile: "strict" });
 *   big.issues.some(function (i) { return i.kind === "width-cap"; });
 *   //                                                   → true
 */

/**
 * @primitive b.guardImage.sanitize
 * @signature b.guardImage.sanitize(input, opts)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardImage.validate, b.guardImage.gate
 *
 * Strip the container's metadata segments from `input.bytes` — EXIF/GPS,
 * XMP/IPTC, and comment payloads (the privacy-leak and metadata-stego
 * surface) — and return the bag with the cleaned bytes. Stripping walks the
 * linear container framing (JPEG APPn/COM markers, PNG ancillary text chunks,
 * GIF comment/application extensions, WebP EXIF/XMP RIFF chunks); pixel
 * transcoding and dimension downscale still need a vendored decoder and stay
 * the operator's job.
 *
 * `sanitize` first runs the validate chain and re-throws `GuardImageError`
 * when any issue is `critical` or `high` (a polyglot or MIME-mismatch is
 * refused, never stripped). A format whose metadata lives in an offset-based
 * structure that cannot be rewritten without a decoder (TIFF / HEIC / AVIF) is
 * refused with `image.sanitize-unsupported-format`; a structurally malformed
 * container is refused with `image.sanitize-malformed` rather than returned
 * half-stripped. BMP / ICO carry no metadata container and pass through.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *
 * @example
 *   // EXIF-laden JPEG → the APP1 (EXIF/XMP) segment is removed.
 *   var clean = b.guardImage.sanitize({
 *     bytes: jpegWithExif,
 *     declaredMime: "image/jpeg",
 *   }, { profile: "strict" });
 *   clean.bytes.length < jpegWithExif.length;            // → true
 *
 *   // A MIME-mismatch is refused, not stripped.
 *   try {
 *     b.guardImage.sanitize({
 *       bytes: Buffer.from([0xFF, 0xD8, 0xFF]),
 *       declaredMime: "image/png",
 *     }, { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                            // → "image.mime-mismatch"
 *   }
 */

function _stripMalformed(detail) {
  return _err("image.sanitize-malformed",
    "cannot strip image metadata — malformed container framing: " + detail);
}

function _stripJpegMetadata(buf) {
  if (buf.length < 2 || buf[0] !== 0xFF || buf[1] !== 0xD8) {
    throw _stripMalformed("missing SOI");
  }
  var parts = [buf.slice(0, 2)];
  var i = 2;
  while (i < buf.length) {
    if (buf[i] !== 0xFF) throw _stripMalformed("expected marker at " + i);
    var mi = i + 1;
    while (mi < buf.length && buf[mi] === 0xFF) mi += 1;
    if (mi >= buf.length) throw _stripMalformed("truncated marker");
    var marker = buf[mi];
    if (marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
      parts.push(buf.slice(i, mi + 1)); i = mi + 1; continue;
    }
    if (marker === 0xD9) { parts.push(buf.slice(i, mi + 1)); i = mi + 1; break; }
    if (marker === 0xDA) { parts.push(buf.slice(i)); i = buf.length; break; }
    if (mi + 3 > buf.length) throw _stripMalformed("truncated segment length");
    var segLen = (buf[mi + 1] << 8) | buf[mi + 2];
    if (segLen < 2) throw _stripMalformed("bad segment length");
    var segEnd = mi + 1 + segLen;
    if (segEnd > buf.length) throw _stripMalformed("segment overruns buffer");
    var drop = marker === 0xE1 || marker === 0xED || marker === 0xFE ||
               (marker >= 0xE3 && marker <= 0xEC) || marker === 0xEF;
    if (!drop) parts.push(buf.slice(i, segEnd));
    i = segEnd;
  }
  return Buffer.concat(parts);
}

var _PNG_DROP = Object.freeze({ tEXt: 1, zTXt: 1, iTXt: 1, eXIf: 1, tIME: 1, dSIG: 1 });
function _stripPngMetadata(buf) {
  if (buf.length < 8) throw _stripMalformed("truncated signature");
  var parts = [buf.slice(0, 8)];
  var i = 8;
  while (i + 8 <= buf.length) {
    var len = buf.readUInt32BE(i);
    if (len > 0x7FFFFFFF) throw _stripMalformed("chunk length exceeds PNG max");
    var type = buf.toString("latin1", i + 4, i + 8);
    var end = i + 12 + len;
    if (end > buf.length) throw _stripMalformed("chunk overruns buffer");
    if (!_PNG_DROP[type]) parts.push(buf.slice(i, end));
    i = end;
    if (type === "IEND") break;
  }
  return Buffer.concat(parts);
}

function _gifSkipSubBlocks(buf, i) {
  while (i < buf.length) {
    var size = buf[i];
    i += 1;
    if (size === 0) return i;
    i += size;
  }
  throw _stripMalformed("unterminated sub-block stream");
}
function _stripGifMetadata(buf) {
  if (buf.length < 13) throw _stripMalformed("truncated header");
  var i = 13;
  var packed = buf[10];
  if (packed & 0x80) i += 3 * (1 << ((packed & 0x07) + 1));
  if (i > buf.length) throw _stripMalformed("global color table overruns buffer");
  var parts = [buf.slice(0, i)];
  while (i < buf.length) {
    var b = buf[i];
    if (b === 0x3B) { parts.push(buf.slice(i, i + 1)); i += 1; break; }
    if (b === 0x2C) {
      var start = i;
      if (i + 10 > buf.length) throw _stripMalformed("truncated image descriptor");
      var lc = buf[i + 9];
      i += 10;
      if (lc & 0x80) i += 3 * (1 << ((lc & 0x07) + 1));
      if (i + 1 > buf.length) throw _stripMalformed("truncated LZW code size");
      i += 1;
      i = _gifSkipSubBlocks(buf, i);
      parts.push(buf.slice(start, i));
      continue;
    }
    if (b === 0x21) {
      if (i + 2 > buf.length) throw _stripMalformed("truncated extension");
      var label = buf[i + 1];
      var start2 = i;
      var j = i + 2;
      if (label === 0xF9) {
        var k = _gifSkipSubBlocks(buf, j);
        parts.push(buf.slice(start2, k));
        i = k;
        continue;
      }
      if (label === 0xFF) {
        if (j >= buf.length) throw _stripMalformed("truncated app extension");
        var blockSize = buf[j];
        var idEnd = j + 1 + blockSize;
        if (idEnd > buf.length) throw _stripMalformed("app-id overruns buffer");
        var appId = buf.toString("latin1", j + 1, idEnd);
        var k2 = _gifSkipSubBlocks(buf, idEnd);
        if (appId.indexOf("NETSCAPE2.0") === 0 || appId.indexOf("ANIMEXTS1.0") === 0) {
          parts.push(buf.slice(start2, k2));
        }
        i = k2;
        continue;
      }
      var k3 = j;
      if (label === 0x01) {
        if (k3 >= buf.length) throw _stripMalformed("truncated plain-text header");
        k3 += 1 + buf[k3];
        if (k3 > buf.length) throw _stripMalformed("plain-text header overruns buffer");
      }
      k3 = _gifSkipSubBlocks(buf, k3);
      i = k3;
      continue;
    }
    throw _stripMalformed("unknown block 0x" + b.toString(16) + " at " + i);
  }
  return Buffer.concat(parts);
}

function _stripWebpMetadata(buf) {
  if (buf.length < 12 ||
      buf.toString("latin1", 0, 4) !== "RIFF" ||
      buf.toString("latin1", 8, 12) !== "WEBP") {
    throw _stripMalformed("not a RIFF/WEBP container");
  }
  var body = [];
  var i = 12;
  while (i + 8 <= buf.length) {
    var fourcc = buf.toString("latin1", i, i + 4);
    var size = buf.readUInt32LE(i + 4);
    var dataEnd = i + 8 + size;
    if (dataEnd > buf.length) throw _stripMalformed("chunk overruns buffer");
    var padded = dataEnd + (size & 1);
    if (padded > buf.length) padded = buf.length;
    if (fourcc === "EXIF" || fourcc === "XMP ") { i = padded; continue; }
    var chunk = buf.slice(i, padded);
    if (fourcc === "VP8X" && size >= 1) {
      chunk = Buffer.from(chunk);
      chunk[8] = chunk[8] & ~0x08 & ~0x04;
    }
    body.push(chunk);
    i = padded;
  }
  var bodyBuf = Buffer.concat(body);
  var out = Buffer.concat([buf.slice(0, 12), bodyBuf]);
  out.writeUInt32LE(4 + bodyBuf.length, 4);
  return out;
}

function _stripImageMetadata(bytes) {
  var mimes = _detectMagicMimes(bytes);
  if (mimes.indexOf("image/jpeg") !== -1) return _stripJpegMetadata(bytes);
  if (mimes.indexOf("image/png")  !== -1) return _stripPngMetadata(bytes);
  if (mimes.indexOf("image/gif")  !== -1) return _stripGifMetadata(bytes);
  if (mimes.indexOf("image/webp") !== -1) return _stripWebpMetadata(bytes);
  if (mimes.indexOf("image/bmp") !== -1 || mimes.indexOf("image/x-icon") !== -1) return bytes;
  throw _err("image.sanitize-unsupported-format",
    "in-framework metadata strip covers jpeg/png/gif/webp (linear container " +
    "framing); this format needs a vendored decoder — refuse and run an " +
    "external sanitizer");
}

function _sanitizeTransform(metadata) {
  if (!metadata || typeof metadata !== "object" || !Buffer.isBuffer(metadata.bytes)) {
    return metadata;
  }
  var cleaned = _stripImageMetadata(metadata.bytes);
  if (cleaned === metadata.bytes) return metadata;
  return Object.assign({}, metadata, { bytes: cleaned });
}

/**
 * @primitive  b.guardImage.gate
 * @signature  b.guardImage.gate(opts)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardImage.validate, b.guardImage.sanitize, b.fileUpload, b.staticServe
 *
 * Build a `b.gateContract` gate suitable for `b.fileUpload({ contentSafety:
 * { "image/png": gate, "image/jpeg": gate } })` or `b.staticServe`.
 * Operators pass `ctx.metadata` (the decoder's reported shape) plus
 * the original `bytes`. Action chain: `serve` (no issues) →
 * `audit-only` (warn-only) → `refuse` (any critical / high). The gate
 * does not auto-strip; an operator who wants metadata removed before
 * serving calls `b.guardImage.sanitize(bag)` explicitly (it walks the
 * container framing — EXIF/XMP/IPTC out of JPEG/PNG/GIF/WebP).
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,
 *   ...:        any validate opt
 *
 * @example
 *   var imgGate = b.guardImage.gate({ profile: "strict" });
 *
 *   var verdict = await imgGate.check({
 *     metadata: {
 *       bytes: Buffer.from([0xFF, 0xD8, 0xFF]),
 *       declaredMime: "image/png",
 *       width: 1024, height: 768, frames: 1,
 *     },
 *   });
 *   verdict.action;                                      // → "refuse"
 *   verdict.issues[0].kind;                              // → "mime-mismatch"
 */
function gate(opts) {
  opts = gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardImageError,
    errCodePrefix:      "image",
    intOpts:            INT_OPTS,
    nonNegativeOpts:    gateContract.capKeysOf(DEFAULTS),
    enumOpts:           POLICY_ENUM,
  });
  return gateContract.buildGuardGate(
    opts.name || "guardImage:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var meta = ctx && (ctx.metadata || ctx.imageMetadata);
      if (!meta) return { ok: true, action: "serve" };
      var rv = module.exports.validate(meta, opts);
      return gateContract.severityDisposition(rv.issues);
    });
}

/**
 * @primitive b.guardImage.inspectMagic
 * @signature b.guardImage.inspectMagic(bytes)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardImage.validate, b.guardImage.gate
 *
 * Read the leading bytes of `bytes` and return an array of distinct
 * MIMEs that match a known image-format magic-byte signature. Empty
 * array on no match; multiple entries signals a polyglot file. Pure
 * inspection — never mutates input or throws.
 *
 * @example
 *   var pngBytes = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
 *   b.guardImage.inspectMagic(pngBytes);                 // → ["image/png"]
 *
 *   b.guardImage.inspectMagic(Buffer.from([0xFF, 0xD8, 0xFF]));
 *   //                                                   → ["image/jpeg"]
 */
function inspectMagic(bytes) {
  return _detectMagicMimes(bytes);
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind:              "metadata",
  benignBytes:       Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
  hostileBytes:      Buffer.from([0xFF, 0xD8, 0xFF]),
  benignMetadata: {
    bytes: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    declaredMime: "image/png",
    width: 100, height: 100, frames: 1,
  },
  hostileMetadata: {
    bytes: Buffer.from([0xFF, 0xD8, 0xFF]),
    declaredMime: "image/png",
  },
});

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "image",
  kind:        "metadata",
  errorClass:  GuardImageError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:            _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:           INT_OPTS,
  gate:        gate,
  extra: {
    inspectMagic: inspectMagic,
  },
});

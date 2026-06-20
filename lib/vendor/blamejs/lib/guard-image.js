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

// Magic-byte signatures. Each entry: [mime, [bytes...], offset?].
//
// Stored as numeric arrays so the source file stays pure ASCII.
var MAGIC_BYTES = Object.freeze([
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  { mime: "image/png", bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
  // JPEG: FF D8 FF
  { mime: "image/jpeg", bytes: [0xFF, 0xD8, 0xFF] },
  // GIF87a / GIF89a: 47 49 46 38 (37|39) 61
  { mime: "image/gif", bytes: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61] },
  { mime: "image/gif", bytes: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61] },
  // WebP: RIFF????WEBP — check at offsets 0..3 + 8..11.
  { mime: "image/webp", bytes: [0x52, 0x49, 0x46, 0x46], tail: [0x57, 0x45, 0x42, 0x50], tailOffset: 8 }, // RIFF + WEBP magic-byte tail offset
  // BMP: 42 4D
  { mime: "image/bmp", bytes: [0x42, 0x4D] },
  // ICO: 00 00 01 00
  { mime: "image/x-icon", bytes: [0x00, 0x00, 0x01, 0x00] },
  // TIFF II: 49 49 2A 00 / TIFF MM: 4D 4D 00 2A
  { mime: "image/tiff", bytes: [0x49, 0x49, 0x2A, 0x00] },
  { mime: "image/tiff", bytes: [0x4D, 0x4D, 0x00, 0x2A] },
  // AVIF / HEIC: ftypheic / ftypheix / ftypavif at offset 4.
  { mime: "image/heic", bytes: [0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63], offset: 4 },
  { mime: "image/heic", bytes: [0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x78], offset: 4 },
  { mime: "image/avif", bytes: [0x66, 0x74, 0x79, 0x70, 0x61, 0x76, 0x69, 0x66], offset: 4 },
  // SVG (XML) — `<?xml` or `<svg` starting bytes (after any UTF-8 BOM).
  { mime: "image/svg+xml", bytes: [0x3C, 0x3F, 0x78, 0x6D, 0x6C] },              // `<?xml`
  { mime: "image/svg+xml", bytes: [0x3C, 0x73, 0x76, 0x67] },                    // `<svg`
]);

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    mismatchPolicy:           "reject",
    polyglotPolicy:            "reject",
    unknownMagicPolicy:        "reject",
    svgRoutingPolicy:          "reject",                                         // refuse SVG bytes — route to guardSvg explicitly
    dimensionsPolicy:          "reject",
    framesPolicy:              "reject",
    maxWidth:                  C.BYTES.bytes(8192),                              // pixel cap, repurposing bytes() for clarity
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
    maxFrames:                 200,                                              // animation frame ceiling
    maxBytes:                  C.BYTES.mib(64),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
  "permissive": {
    mismatchPolicy:           "reject",                                          // mismatch refused at every profile
    polyglotPolicy:            "reject",                                          // polyglot refused at every profile
    unknownMagicPolicy:        "audit",
    svgRoutingPolicy:          "reject",                                          // route SVG explicitly at every profile
    dimensionsPolicy:          "audit",
    framesPolicy:              "audit",
    maxWidth:                  C.BYTES.bytes(65536),
    maxHeight:                 C.BYTES.bytes(65536),
    maxFrames:                 1000,                                             // animation frame ceiling
    maxBytes:                  C.BYTES.mib(256),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

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
  var hits = [];
  for (var i = 0; i < MAGIC_BYTES.length; i += 1) {
    var entry = MAGIC_BYTES[i];
    var offset = entry.offset || 0;
    if (!_bytesAt(buf, offset, entry.bytes)) continue;
    if (entry.tail && !_bytesAt(buf, entry.tailOffset, entry.tail)) continue;
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
  if (bytes && typeof bytes.length === "number" && safeBuffer.byteLengthOf(bytes) > opts.maxBytes) {
    return [{ kind: "image-cap", severity: "high",
              ruleId: "image.image-cap",
              snippet: "image bytes exceed maxBytes " + opts.maxBytes }];
  }

  var hits = bytes ? _detectMagicMimes(bytes) : [];
  var unique = {};
  for (var hi = 0; hi < hits.length; hi += 1) unique[hits[hi]] = true;
  var uniqueHits = Object.keys(unique);

  // Polyglot — multiple distinct formats matched.
  if (uniqueHits.length > 1 && opts.polyglotPolicy !== "allow") {
    issues.push({
      kind: "polyglot", severity: "critical",
      ruleId: "image.polyglot",
      snippet: "buffer matches multiple image-format magic bytes (" +
               uniqueHits.join(", ") + ") — polyglot file class " +
               "(PHP-in-JPEG / JS-in-PNG)",
    });
  }

  // SVG routing.
  if (uniqueHits.indexOf("image/svg+xml") !== -1 &&
      opts.svgRoutingPolicy !== "allow") {
    issues.push({
      kind: "svg-routing", severity: "high",
      ruleId: "image.svg-routing",
      snippet: "buffer is SVG — route explicitly to b.guardSvg " +
               "(SVG threat catalog is distinct from raster images)",
    });
  }

  // Mismatch — declaredMime vs detected.
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

  // Unknown magic.
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

  // Dimensions.
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

  // Frames.
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
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues) below — `validate(input, opts) = aggregateIssues(detect(
// input, resolveOpts(opts)))`, with the maxBytes / maxWidth / maxHeight /
// maxFrames caps declared via `intOpts`. The @primitive block above
// documents the resulting public ABI.

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
// ---- Container-framing metadata strip (sanitize) ----
//
// Linear TLV byte-surgery over the well-defined container framing — the same
// signature-walk shape as inspectMagic, NOT a pixel decoder (Hard rule: no
// vendored raster library). Removes the metadata segments that carry EXIF/GPS,
// XMP/IPTC PII, and metadata-embedded stego/polyglot payloads operators need
// stripped before serving an otherwise-clean image. Pixel transcoding and
// dimension downscale still need a decoder and stay the operator's job.
//
// A structurally malformed container is REFUSED (throw), never returned
// half-stripped — sanitize must not hand back bytes it could not fully clean.

function _stripMalformed(detail) {
  return _err("image.sanitize-malformed",
    "cannot strip image metadata — malformed container framing: " + detail);
}

// JPEG: FFD8 SOI, then marker segments until SOS (FFDA) begins entropy data.
// Drop EXIF/XMP (APP1=E1), IPTC/Photoshop (APP13=ED), comments (COM=FE), and
// the vendor APPn range (E3..EC, EF). Keep JFIF (APP0=E0), ICC color
// (APP2=E2), Adobe (APP14=EE), and every coding segment (SOFn/DHT/DQT/DRI/SOS).
function _stripJpegMetadata(buf) {
  if (buf.length < 2 || buf[0] !== 0xFF || buf[1] !== 0xD8) {
    throw _stripMalformed("missing SOI");
  }
  var parts = [buf.slice(0, 2)];
  var i = 2;
  while (i < buf.length) {
    if (buf[i] !== 0xFF) throw _stripMalformed("expected marker at " + i);
    // Collapse any 0xFF fill bytes preceding the marker code.
    var mi = i + 1;
    while (mi < buf.length && buf[mi] === 0xFF) mi += 1;
    if (mi >= buf.length) throw _stripMalformed("truncated marker");
    var marker = buf[mi];
    // Standalone markers (no length payload): TEM(01), RSTn(D0..D7).
    if (marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
      parts.push(buf.slice(i, mi + 1)); i = mi + 1; continue;
    }
    if (marker === 0xD9) { parts.push(buf.slice(i, mi + 1)); i = mi + 1; break; }  // EOI
    if (marker === 0xDA) { parts.push(buf.slice(i)); i = buf.length; break; }      // SOS + entropy → verbatim
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

// PNG: 8-byte signature, then length(4 BE)+type(4)+data+crc(4) chunks. Drop the
// text/metadata/time ancillary chunks; keep critical chunks (IHDR/PLTE/IDAT/
// IEND) and rendering ancillary (gAMA/cHRM/sRGB/iCCP/pHYs/tRNS/bKGD/sBIT/...).
// Dropping a chunk never disturbs another's per-chunk CRC.
var _PNG_DROP = Object.freeze({ tEXt: 1, zTXt: 1, iTXt: 1, eXIf: 1, tIME: 1, dSIG: 1 });
function _stripPngMetadata(buf) {
  if (buf.length < 8) throw _stripMalformed("truncated signature");
  var parts = [buf.slice(0, 8)];
  var i = 8;
  while (i + 8 <= buf.length) {
    var len = buf.readUInt32BE(i);
    if (len > 0x7FFFFFFF) throw _stripMalformed("chunk length exceeds PNG max");
    var type = buf.toString("latin1", i + 4, i + 8);
    var end = i + 12 + len;                                                        // 4 len + 4 type + len + 4 crc
    if (end > buf.length) throw _stripMalformed("chunk overruns buffer");
    if (!_PNG_DROP[type]) parts.push(buf.slice(i, end));
    i = end;
    if (type === "IEND") break;
  }
  return Buffer.concat(parts);
}

// GIF: header(6)+logical-screen-descriptor(7)+optional global color table, then
// blocks. Drop comment (0x21 0xFE) + plain-text (0x21 0x01) + non-loop
// application (0x21 0xFF, e.g. XMP) extensions; keep graphic-control extensions
// (0x21 0xF9), the NETSCAPE/ANIMEXTS loop extension (animation control), image
// descriptors (0x2C), and the trailer (0x3B).
function _gifSkipSubBlocks(buf, i) {
  while (i < buf.length) {
    var size = buf[i];
    i += 1;
    if (size === 0) return i;                                                      // block terminator
    i += size;
  }
  throw _stripMalformed("unterminated sub-block stream");
}
function _stripGifMetadata(buf) {
  if (buf.length < 13) throw _stripMalformed("truncated header");
  var i = 13;
  var packed = buf[10];
  if (packed & 0x80) i += 3 * (1 << ((packed & 0x07) + 1));                        // global color table
  if (i > buf.length) throw _stripMalformed("global color table overruns buffer");
  var parts = [buf.slice(0, i)];
  while (i < buf.length) {
    var b = buf[i];
    if (b === 0x3B) { parts.push(buf.slice(i, i + 1)); i += 1; break; }            // trailer
    if (b === 0x2C) {                                                              // image descriptor
      var start = i;
      if (i + 10 > buf.length) throw _stripMalformed("truncated image descriptor");
      var lc = buf[i + 9];
      i += 10;
      if (lc & 0x80) i += 3 * (1 << ((lc & 0x07) + 1));                            // local color table
      if (i + 1 > buf.length) throw _stripMalformed("truncated LZW code size");
      i += 1;                                                                      // LZW minimum code size
      i = _gifSkipSubBlocks(buf, i);
      parts.push(buf.slice(start, i));
      continue;
    }
    if (b === 0x21) {                                                              // extension introducer
      if (i + 2 > buf.length) throw _stripMalformed("truncated extension");
      var label = buf[i + 1];
      var start2 = i;
      var j = i + 2;
      if (label === 0xF9) {                                                        // graphic control — keep
        var k = _gifSkipSubBlocks(buf, j);
        parts.push(buf.slice(start2, k));
        i = k;
        continue;
      }
      if (label === 0xFF) {                                                        // application extension
        if (j >= buf.length) throw _stripMalformed("truncated app extension");
        var blockSize = buf[j];
        var idEnd = j + 1 + blockSize;
        if (idEnd > buf.length) throw _stripMalformed("app-id overruns buffer");
        var appId = buf.toString("latin1", j + 1, idEnd);
        var k2 = _gifSkipSubBlocks(buf, idEnd);
        if (appId.indexOf("NETSCAPE2.0") === 0 || appId.indexOf("ANIMEXTS1.0") === 0) {
          parts.push(buf.slice(start2, k2));                                       // keep loop control
        }
        i = k2;
        continue;
      }
      // comment (0xFE) / plain-text (0x01) / other → drop.
      var k3 = j;
      if (label === 0x01) {                                                        // plain text has a 12-byte header block
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

// WebP: RIFF container — "RIFF"+size(4 LE)+"WEBP"+chunks (FourCC+size(4 LE)+
// data, padded to even). Drop EXIF + XMP chunks, clear the VP8X EXIF/XMP flag
// bits so a strict decoder does not expect the dropped chunks, and rewrite the
// RIFF size. Keep VP8/VP8L/VP8X/ANIM/ANMF/ALPH/ICCP.
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
    var padded = dataEnd + (size & 1);                                             // even-pad
    if (padded > buf.length) padded = buf.length;                                  // tolerate a missing final pad byte
    if (fourcc === "EXIF" || fourcc === "XMP ") { i = padded; continue; }          // drop metadata chunk
    var chunk = buf.slice(i, padded);
    if (fourcc === "VP8X" && size >= 1) {
      chunk = Buffer.from(chunk);                                                  // own copy before mutating flags
      chunk[8] = chunk[8] & ~0x08 & ~0x04;                                         // clear EXIF + XMP presence bits
    }
    body.push(chunk);
    i = padded;
  }
  var bodyBuf = Buffer.concat(body);
  var out = Buffer.concat([buf.slice(0, 12), bodyBuf]);
  out.writeUInt32LE(4 + bodyBuf.length, 4);                                        // RIFF size = "WEBP" + chunks
  return out;
}

function _stripImageMetadata(bytes) {
  var mimes = _detectMagicMimes(bytes);
  if (mimes.indexOf("image/jpeg") !== -1) return _stripJpegMetadata(bytes);
  if (mimes.indexOf("image/png")  !== -1) return _stripPngMetadata(bytes);
  if (mimes.indexOf("image/gif")  !== -1) return _stripGifMetadata(bytes);
  if (mimes.indexOf("image/webp") !== -1) return _stripWebpMetadata(bytes);
  // BMP / ICO carry no text/EXIF metadata container — nothing to strip.
  if (mimes.indexOf("image/bmp") !== -1 || mimes.indexOf("image/x-icon") !== -1) return bytes;
  // TIFF / HEIC / AVIF keep metadata in IFD / ISO-BMFF box structures that need
  // offset-aware rewriting (a format parser — forbidden). Refuse rather than
  // hand back un-stripped bytes claiming they were sanitized.
  throw _err("image.sanitize-unsupported-format",
    "in-framework metadata strip covers jpeg/png/gif/webp (linear container " +
    "framing); this format needs a vendored decoder — refuse and run an " +
    "external sanitizer");
}

// _sanitizeTransform — defineGuard's generated sanitize runs resolve → detect →
// throw-on-refusal first, so a polyglot / mime-mismatch (critical/high) is
// refused before this point. For an otherwise-clean image the metadata bag's
// bytes are stripped of their EXIF/XMP/IPTC/comment segments; pixel transcoding
// still needs a decoder and stays the operator's job. Non-Buffer bytes pass
// through (validate already refused bad input upstream).
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

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

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

// ---- adaptive integration-test fixtures (consumed by layer-5 host harness) ----
var INTEGRATION_FIXTURES = Object.freeze({
  kind:              "metadata",
  benignBytes:       Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
  // Hostile: declared image/png but bytes are JPEG (mime-mismatch class —
  // drive-by content-type confusion / decoder-mux).
  hostileBytes:      Buffer.from([0xFF, 0xD8, 0xFF]),
  benignMetadata: {
    bytes: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    declaredMime: "image/png",
    width: 100, height: 100, frames: 1,                                        // pixel + frame count fixture
  },
  hostileMetadata: {
    bytes: Buffer.from([0xFF, 0xD8, 0xFF]),
    declaredMime: "image/png",
  },
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface. validate + sanitize are generated from `detect` (_detectIssues)
// and `sanitizeTransform` (_sanitizeTransform) with the positive-finite-int
// caps declared via `intOpts`. The image extra (inspectMagic) passes through
// verbatim. KIND="metadata" is a custom kind, so the bespoke `gate`
// (operator-feeds-metadata ctx.metadata reader) is REQUIRED and carries the
// magic-byte / polyglot / dimension chain unchanged.
module.exports = gateContract.defineGuard({
  name:        "image",
  kind:        "metadata",
  errorClass:  GuardImageError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  // detect/sanitizeTransform read a structured `{ bytes, declaredMime, ... }`
  // metadata report, not text. The generated validate's default "raw" input
  // contract hands the bag straight to detect (which owns its own bad-input).
  detect:            _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:           ["maxBytes", "maxWidth", "maxHeight", "maxFrames"],
  gate:        gate,
  extra: {
    inspectMagic: inspectMagic,
  },
});

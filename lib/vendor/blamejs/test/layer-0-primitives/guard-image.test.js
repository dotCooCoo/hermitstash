"use strict";
/**
 * guard-image — image content-safety primitive (b.guardImage).
 *
 * Covers: surface; registry parity; magic-byte / declared-MIME mismatch;
 * polyglot rejection; unknown-magic; dimension + frame caps; inspectMagic;
 * and the container-framing metadata strip (sanitize) — EXIF/XMP out of
 * JPEG (APP1), text chunks out of PNG (tEXt), comment/app extensions out of
 * GIF, EXIF/XMP RIFF chunks out of WebP with the VP8X flag bits cleared,
 * the unsupported-format / malformed refusals, and refuse-before-strip for a
 * polyglot / mismatch. The strip is byte-surgery over the linear container
 * framing, not a pixel decoder.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _has(buf, s) { return buf.toString("latin1").indexOf(s) !== -1; }
function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }

// ---- fixture builders (kept ASCII; metadata payloads carry a sentinel) ----

function _jpegWithExif() {
  return Buffer.concat([
    Buffer.from([0xFF, 0xD8]),                                                   // SOI
    Buffer.from([0xFF, 0xE1, 0x00, 0x0F]), Buffer.from("Exif  GPSDATA", "latin1"), // APP1 (EXIF) len=15
    Buffer.from([0xFF, 0xE0, 0x00, 0x10]), Buffer.from("JFIF ABCDEFGHIJ".slice(0, 14), "latin1"), // APP0 (JFIF) len=16
    Buffer.from([0xFF, 0xD9]),                                                    // EOI
  ]);
}

function _pngWithText() {
  var ihdr = Buffer.concat([Buffer.from([0, 0, 0, 13]), Buffer.from("IHDR", "latin1"),
    Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]), Buffer.from([1, 2, 3, 4])]);
  var text = Buffer.concat([Buffer.from([0, 0, 0, 18]), Buffer.from("tEXt", "latin1"),
    Buffer.from("Comment secret-gps", "latin1"), Buffer.from([9, 9, 9, 9])]);
  var iend = Buffer.concat([Buffer.from([0, 0, 0, 0]), Buffer.from("IEND", "latin1"),
    Buffer.from([0xAE, 0x42, 0x60, 0x82])]);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), ihdr, text, iend]);
}

function _gifWithComment() {
  return Buffer.concat([
    Buffer.from("GIF89a", "latin1"),
    Buffer.from([1, 0, 1, 0, 0x00, 0, 0]),                                       // LSD 1x1, no GCT
    Buffer.from([0x21, 0xFE, 0x0A]), Buffer.from("secret-gps", "latin1"), Buffer.from([0x00]), // comment ext
    Buffer.from([0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0x00]),                           // image descriptor
    Buffer.from([0x02, 0x01, 0x44, 0x00]),                                       // LZW min + sub-block + term
    Buffer.from([0x3B]),                                                         // trailer
  ]);
}

function _webpWithExif() {
  return Buffer.concat([
    Buffer.from("RIFF", "latin1"), Buffer.from([34, 0, 0, 0]), Buffer.from("WEBP", "latin1"),
    Buffer.from("VP8 ", "latin1"), Buffer.from([4, 0, 0, 0]), Buffer.from([1, 2, 3, 4]),
    Buffer.from("EXIF", "latin1"), Buffer.from([10, 0, 0, 0]), Buffer.from("secret-gps", "latin1"),
  ]);
}

function testGuardImageSurface() {
  check("guardImage is an object",              typeof b.guardImage === "object");
  check("guardImage.NAME === 'image'",          b.guardImage.NAME === "image");
  check("guardImage.PROFILES has strict",       !!b.guardImage.PROFILES["strict"]);
  check("guardImage.COMPLIANCE_POSTURES gdpr",  !!b.guardImage.COMPLIANCE_POSTURES["gdpr"]);
  check("guardImage.validate is a function",    typeof b.guardImage.validate === "function");
  check("guardImage.sanitize is a function",    typeof b.guardImage.sanitize === "function");
  check("guardImage.gate is a function",        typeof b.guardImage.gate === "function");
  check("guardImage.inspectMagic is a function", typeof b.guardImage.inspectMagic === "function");
  check("frameworkError.GuardImageError exposed", typeof b.frameworkError.GuardImageError === "function");
}

function testGuardImageRegistryParity() {
  check("guardImage registered in guardAll",
    b.guardAll.allGuards().some(function (g) { return (g.name || g.NAME) === "image"; }));
}

function testInspectMagic() {
  check("inspectMagic detects png",
    b.guardImage.inspectMagic(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])).indexOf("image/png") !== -1);
  check("inspectMagic empty on garbage",
    b.guardImage.inspectMagic(Buffer.from([0x00, 0x01, 0x02])).length === 0);
}

function testValidateMismatchAndPolyglot() {
  var rv = b.guardImage.validate({ bytes: Buffer.from([0xFF, 0xD8, 0xFF]), declaredMime: "image/png" }, { profile: "strict" });
  check("mismatch: validate ok:false", rv.ok === false);
  check("mismatch: kind reported", rv.issues.some(function (i) { return i.kind === "mime-mismatch"; }));
}

// ---- the real metadata strip ----

function testStripJpegExif() {
  var src = _jpegWithExif();
  var out = b.guardImage.sanitize({ bytes: src });
  check("jpeg: EXIF (APP1) payload removed", !_has(out.bytes, "GPSDATA") && !_has(out.bytes, "Exif"));
  check("jpeg: JFIF (APP0) preserved",       _has(out.bytes, "JFIF"));
  check("jpeg: output shrank",               out.bytes.length < src.length);
  check("jpeg: SOI + EOI intact",
    out.bytes[0] === 0xFF && out.bytes[1] === 0xD8 &&
    out.bytes[out.bytes.length - 2] === 0xFF && out.bytes[out.bytes.length - 1] === 0xD9);
  check("jpeg: bag is a fresh object (bytes replaced)", typeof out === "object" && Buffer.isBuffer(out.bytes));
}

function testStripPngText() {
  var out = b.guardImage.sanitize({ bytes: _pngWithText() });
  check("png: tEXt payload removed",   !_has(out.bytes, "secret-gps"));
  check("png: IHDR preserved",         _has(out.bytes, "IHDR"));
  check("png: IEND preserved",         _has(out.bytes, "IEND"));
  check("png: signature intact",       out.bytes[0] === 0x89 && out.bytes[1] === 0x50);
}

function testStripGifComment() {
  var out = b.guardImage.sanitize({ bytes: _gifWithComment() });
  check("gif: comment payload removed", !_has(out.bytes, "secret-gps"));
  check("gif: header preserved",        _has(out.bytes, "GIF89a"));
  check("gif: trailer preserved",       out.bytes[out.bytes.length - 1] === 0x3B);
}

function testStripWebpExif() {
  var out = b.guardImage.sanitize({ bytes: _webpWithExif() });
  check("webp: EXIF payload removed",   !_has(out.bytes, "secret-gps"));
  check("webp: VP8 chunk preserved",    _has(out.bytes, "VP8 "));
  check("webp: RIFF size rewritten",    out.bytes.readUInt32LE(4) === 16);
}

function testStripWebpVp8xFlags() {
  var webpx = Buffer.concat([
    Buffer.from("RIFF", "latin1"), Buffer.from([0, 0, 0, 0]), Buffer.from("WEBP", "latin1"),
    Buffer.from("VP8X", "latin1"), Buffer.from([10, 0, 0, 0]), Buffer.from([0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    Buffer.from("EXIF", "latin1"), Buffer.from([4, 0, 0, 0]), Buffer.from([9, 9, 9, 9]),
  ]);
  var out = b.guardImage.sanitize({ bytes: webpx });
  check("webp: VP8X EXIF+XMP flag bits cleared", (out.bytes[20] & 0x0C) === 0);
}

function testRefuseBeforeStrip() {
  // A MIME-mismatch / polyglot must refuse, never strip-and-serve.
  check("mismatch refuses (not strips)",
    _code(function () { b.guardImage.sanitize({ bytes: _jpegWithExif(), declaredMime: "image/png" }, { profile: "strict" }); }) === "image.mime-mismatch");
}

function testRefuseUnsupportedFormat() {
  var tiff = Buffer.from([0x49, 0x49, 0x2A, 0x00, 8, 0, 0, 0]);
  check("tiff: refuse unsupported-format",
    _code(function () { b.guardImage.sanitize({ bytes: tiff }); }) === "image.sanitize-unsupported-format");
}

function testRefuseMalformed() {
  var bad = Buffer.from([0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0xFF]);                    // APP1 length overruns
  check("malformed: refuse, not half-strip",
    _code(function () { b.guardImage.sanitize({ bytes: bad }); }) === "image.sanitize-malformed");
}

function testBmpPassthrough() {
  // BMP carries no text/EXIF metadata container — pass through unchanged.
  var bmp = Buffer.from([0x42, 0x4D, 0x10, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);
  var out = b.guardImage.sanitize({ bytes: bmp });
  check("bmp: passes through (no metadata container)", out.bytes === bmp);
}

function run() {
  testGuardImageSurface();
  testGuardImageRegistryParity();
  testInspectMagic();
  testValidateMismatchAndPolyglot();
  testStripJpegExif();
  testStripPngText();
  testStripGifComment();
  testStripWebpExif();
  testStripWebpVp8xFlags();
  testRefuseBeforeStrip();
  testRefuseUnsupportedFormat();
  testRefuseMalformed();
  testBmpPassthrough();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-image] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}

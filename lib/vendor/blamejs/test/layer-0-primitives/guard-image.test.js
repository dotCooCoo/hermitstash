// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-image — image content-safety primitive (b.guardImage).
 *
 * Covers: surface; registry parity; magic-byte detection across every format
 * (PNG / JPEG / GIF87a-89a / WebP / BMP / ICO / TIFF II-MM / HEIC / AVIF /
 * SVG), incl. truncated / ambiguous / RIFF-not-WEBP headers; declared-vs-actual
 * MIME mismatch; multi-signature polyglot refusal; unknown-magic severity by
 * profile; oversized / dimension / frame caps across strict/balanced/permissive
 * and the hipaa/pci-dss/gdpr/soc2 postures; the operator-feeds-metadata gate
 * (serve / audit-only / refuse by KIND); and the container-framing metadata
 * strip (sanitize) over JPEG APPn/COM (incl. standalone RST, fill-FF collapse,
 * SOS verbatim), PNG text/eXIf/tIME chunks, GIF comment/plain-text/app
 * extensions (loop kept), WebP EXIF/XMP RIFF chunks + VP8X flag clear, plus the
 * unsupported-format / malformed refusals and refuse-before-strip. The strip is
 * byte-surgery over the linear container framing, not a pixel decoder.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _has(buf, s) { return buf.toString("latin1").indexOf(s) !== -1; }
function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }
function _throws(fn) { try { fn(); return false; } catch (e) { void e; return true; } }
function _hasKind(issues, kind) {
  return issues.some(function (it) { return it.kind === kind; });
}
function _hasKindSev(issues, kind, sev) {
  return issues.some(function (it) { return it.kind === kind && it.severity === sev; });
}

// ---- magic-byte fixtures (built from hex/latin1 so the source stays ASCII) ----

var PNG_MAGIC  = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
var JPEG_MAGIC = Buffer.from([0xFF, 0xD8, 0xFF]);
var GIF87      = Buffer.from("GIF87a", "latin1");
var GIF89      = Buffer.from("GIF89a", "latin1");
var BMP_MAGIC  = Buffer.from([0x42, 0x4D]);
var ICO_MAGIC  = Buffer.from([0x00, 0x00, 0x01, 0x00]);
var TIFF_II    = Buffer.from([0x49, 0x49, 0x2A, 0x00]);
var TIFF_MM    = Buffer.from([0x4D, 0x4D, 0x00, 0x2A]);
var WEBP       = Buffer.concat([Buffer.from("RIFF", "latin1"), Buffer.from([4, 0, 0, 0]), Buffer.from("WEBP", "latin1")]);
var RIFF_WAVE  = Buffer.concat([Buffer.from("RIFF", "latin1"), Buffer.from([4, 0, 0, 0]), Buffer.from("WAVE", "latin1")]);
var HEIC       = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftypheic", "latin1")]);
var HEIX       = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftypheix", "latin1")]);
var AVIF       = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftypavif", "latin1")]);
var SVG_XML    = Buffer.from("<?xml?>", "latin1");
var SVG_TAG    = Buffer.from("<svg/>", "latin1");

// UTF-8 BOM (EF BB BF) precedes text-family images (SVG/XML) in the wild.
var BOM        = Buffer.from([0xEF, 0xBB, 0xBF]);
var BOM_XML    = Buffer.concat([BOM, SVG_XML]);
var BOM_SVG    = Buffer.concat([BOM, SVG_TAG]);

// A single buffer matching BOTH JPEG (offset 0) and HEIC (ftyp at offset 4) —
// a synthetic but genuine multi-signature polyglot.
var POLYGLOT   = Buffer.concat([Buffer.from([0xFF, 0xD8, 0xFF, 0x00]), Buffer.from("ftypheic", "latin1")]);

function testGuardImageSurface() {
  check("guardImage is an object",              typeof b.guardImage === "object");
  check("guardImage.NAME === 'image'",          b.guardImage.NAME === "image");
  check("guardImage.PROFILES has strict",       !!b.guardImage.PROFILES["strict"]);
  check("guardImage.PROFILES has balanced",     !!b.guardImage.PROFILES["balanced"]);
  check("guardImage.PROFILES has permissive",   !!b.guardImage.PROFILES["permissive"]);
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
    b.guardImage.inspectMagic(PNG_MAGIC).indexOf("image/png") !== -1);
  check("inspectMagic empty on garbage",
    b.guardImage.inspectMagic(Buffer.from([0x00, 0x01, 0x02])).length === 0);
}

function testInspectMagicAllFormats() {
  check("inspectMagic: jpeg",     b.guardImage.inspectMagic(JPEG_MAGIC).indexOf("image/jpeg") !== -1);
  check("inspectMagic: gif87a",   b.guardImage.inspectMagic(GIF87).indexOf("image/gif") !== -1);
  check("inspectMagic: gif89a",   b.guardImage.inspectMagic(GIF89).indexOf("image/gif") !== -1);
  check("inspectMagic: webp (RIFF+WEBP)", b.guardImage.inspectMagic(WEBP).indexOf("image/webp") !== -1);
  check("inspectMagic: bmp",      b.guardImage.inspectMagic(BMP_MAGIC).indexOf("image/bmp") !== -1);
  check("inspectMagic: ico",      b.guardImage.inspectMagic(ICO_MAGIC).indexOf("image/x-icon") !== -1);
  check("inspectMagic: tiff-II",  b.guardImage.inspectMagic(TIFF_II).indexOf("image/tiff") !== -1);
  check("inspectMagic: tiff-MM",  b.guardImage.inspectMagic(TIFF_MM).indexOf("image/tiff") !== -1);
  check("inspectMagic: heic",     b.guardImage.inspectMagic(HEIC).indexOf("image/heic") !== -1);
  check("inspectMagic: heix (heic alias)", b.guardImage.inspectMagic(HEIX).indexOf("image/heic") !== -1);
  check("inspectMagic: avif",     b.guardImage.inspectMagic(AVIF).indexOf("image/avif") !== -1);
  check("inspectMagic: svg (<?xml)", b.guardImage.inspectMagic(SVG_XML).indexOf("image/svg+xml") !== -1);
  check("inspectMagic: svg (<svg)",  b.guardImage.inspectMagic(SVG_TAG).indexOf("image/svg+xml") !== -1);

  // RIFF but not WEBP (a WAV) — the tail-mismatch continue branch: no webp hit.
  check("inspectMagic: RIFF/WAVE is not webp", b.guardImage.inspectMagic(RIFF_WAVE).length === 0);
  // Sub-magic-length buffer can match nothing.
  check("inspectMagic: 2-byte buffer (< jpeg magic) → []",
    b.guardImage.inspectMagic(Buffer.from([0xFF, 0xD8])).length === 0);
  // Pure inspection — never throws on non-Buffer / no-length input.
  check("inspectMagic: null → []",       b.guardImage.inspectMagic(null).length === 0);
  check("inspectMagic: undefined → []",  b.guardImage.inspectMagic(undefined).length === 0);
  check("inspectMagic: no-length obj → []", b.guardImage.inspectMagic({}).length === 0);
}

// ---- BUG A (RED-first): a UTF-8-BOM-prefixed SVG must still route to guardSvg ----
//
// The @module block documents SVG detection "after any UTF-8 BOM", and the
// svgRoutingPolicy is "reject" at EVERY profile. But a BOM-prefixed SVG matched
// no signature, so it fell through to unknown-magic — audit-only (SERVED) under
// balanced/permissive — a fail-open of the "route SVG at every profile"
// invariant, and a mis-classification (unknown-magic, not svg-routing) even
// under strict.
function testInspectMagicBomSvg() {
  check("inspectMagic: BOM + <?xml detected as svg",
    b.guardImage.inspectMagic(BOM_XML).indexOf("image/svg+xml") !== -1);
  check("inspectMagic: BOM + <svg detected as svg",
    b.guardImage.inspectMagic(BOM_SVG).indexOf("image/svg+xml") !== -1);
}

function testValidateSvgRoutedEveryProfile() {
  var profiles = ["strict", "balanced", "permissive"];
  for (var pi = 0; pi < profiles.length; pi += 1) {
    var p = profiles[pi];
    // Plain (no-BOM) SVG — the existing baseline.
    var rvPlain = b.guardImage.validate({ bytes: SVG_XML }, { profile: p });
    check("svg (<?xml) routed under " + p, _hasKind(rvPlain.issues, "svg-routing"));
    check("svg (<?xml) refused under " + p, rvPlain.ok === false);
    // BOM-prefixed SVG — the fail-open case.
    var rvBom = b.guardImage.validate({ bytes: BOM_XML }, { profile: p });
    check("BOM-svg routed under " + p, _hasKind(rvBom.issues, "svg-routing"));
    check("BOM-svg refused under " + p, rvBom.ok === false);
  }
}

// ---- BUG A follow-up (RED-first): the BOM skip must NOT extend to binary
// rasters. A UTF-8 BOM is legal only before XML/SVG text; a PNG/JPEG/etc.
// signature must sit at its real offset. Shifting every signature by the BOM
// width let a `EF BB BF`-prefixed PNG masquerade as a valid raster (ok:true
// under strict), bypassing strict magic validation. The shift is now gated on
// the text-family SVG/XML entries only. ----
function testBomDoesNotBypassRasterMagic() {
  var pngMagic = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  var bomPng = Buffer.concat([BOM, pngMagic]);
  // BOM-prefixed PNG is NOT a valid PNG (signature not at offset 0) — it must
  // NOT be detected as image/png, and strict validate must refuse it.
  check("inspectMagic: BOM + PNG magic NOT detected as image/png",
    b.guardImage.inspectMagic(bomPng).indexOf("image/png") === -1);
  var rv = b.guardImage.validate({ bytes: bomPng, declaredMime: "image/png" }, { profile: "strict" });
  check("strict: BOM-prefixed PNG refused (not accepted as a raster)", rv.ok === false);
  check("strict: BOM-prefixed PNG raises unknown-magic (signature not at offset 0)",
    _hasKind(rv.issues, "unknown-magic"));
  // Control: a genuine PNG (no BOM) still validates as a raster.
  var rvReal = b.guardImage.validate({ bytes: pngMagic }, { profile: "strict" });
  check("strict: real PNG magic detected as image/png",
    b.guardImage.inspectMagic(pngMagic).indexOf("image/png") !== -1 && !_hasKind(rvReal.issues, "unknown-magic"));
}

// ---- BUG B (RED-first): validate must never throw on hostile metadata ----
//
// The @primitive block promises validate is "pure inspection — never mutates
// input or throws on hostile metadata". A bag whose `bytes` is a plain Array or
// an array-like object (numeric `.length`, not a Buffer/string/Uint8Array) hit
// safeBuffer.byteLengthOf, which throws TypeError — crashing a direct caller.
function testValidateNeverThrowsHostileMetadata() {
  check("validate does not throw on Array-typed bytes",
    _throws(function () { b.guardImage.validate({ bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] }, { profile: "strict" }); }) === false);
  check("validate does not throw on array-like-object bytes",
    _throws(function () { b.guardImage.validate({ bytes: { length: 5 } }, { profile: "strict" }); }) === false);
  // And it still refuses the unrecognized array-like content rather than crash.
  var rv = b.guardImage.validate({ bytes: { length: 5 } }, { profile: "strict" });
  check("array-like bytes → unknown-magic refuse (not a crash)",
    rv.ok === false && _hasKind(rv.issues, "unknown-magic"));
}

function testValidateMismatchAndPolyglot() {
  var rv = b.guardImage.validate({ bytes: JPEG_MAGIC, declaredMime: "image/png" }, { profile: "strict" });
  check("mismatch: validate ok:false", rv.ok === false);
  check("mismatch: kind reported", _hasKind(rv.issues, "mime-mismatch"));
}

function testValidatePolyglot() {
  var mimes = b.guardImage.inspectMagic(POLYGLOT);
  check("polyglot: inspectMagic returns two formats",
    mimes.indexOf("image/jpeg") !== -1 && mimes.indexOf("image/heic") !== -1);
  // Refused even under permissive (polyglotPolicy is "reject" at every profile).
  var rv = b.guardImage.validate({ bytes: POLYGLOT }, { profile: "permissive" });
  check("polyglot refused under permissive", rv.ok === false);
  check("polyglot: critical severity", _hasKindSev(rv.issues, "polyglot", "critical"));
}

function testValidateUnknownMagicSeverity() {
  var garbage = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04]);
  var rvS = b.guardImage.validate({ bytes: garbage }, { profile: "strict" });
  check("unknown-magic high under strict (reject policy)",
    rvS.ok === false && _hasKindSev(rvS.issues, "unknown-magic", "high"));
  var rvB = b.guardImage.validate({ bytes: garbage }, { profile: "balanced" });
  check("unknown-magic warn under balanced (audit policy)",
    rvB.ok === true && _hasKindSev(rvB.issues, "unknown-magic", "warn"));
}

function testValidateOversizedBytes() {
  var over = Buffer.alloc(10, 0x89);
  var rv = b.guardImage.validate({ bytes: over }, { profile: "strict", maxBytes: 4 });
  check("oversized bytes → image-cap refuse",
    rv.ok === false && _hasKind(rv.issues, "image-cap"));
}

function testValidateDimensionAndFrameCaps() {
  // Width over the strict 8192 cap (reject) → high.
  var rvW = b.guardImage.validate(
    { bytes: PNG_MAGIC, declaredMime: "image/png", width: 9000, height: 100 }, { profile: "strict" });
  check("width over strict cap → width-cap high refuse",
    rvW.ok === false && _hasKindSev(rvW.issues, "width-cap", "high"));
  // Height over the strict cap → high.
  var rvH = b.guardImage.validate(
    { bytes: PNG_MAGIC, declaredMime: "image/png", width: 100, height: 9000 }, { profile: "strict" });
  check("height over strict cap → height-cap high refuse",
    rvH.ok === false && _hasKindSev(rvH.issues, "height-cap", "high"));
  // Width over the balanced 16384 cap (audit) → warn, ok stays true.
  var rvWB = b.guardImage.validate(
    { bytes: PNG_MAGIC, declaredMime: "image/png", width: 20000 }, { profile: "balanced" });
  check("width over balanced cap → warn (ok true)",
    rvWB.ok === true && _hasKindSev(rvWB.issues, "width-cap", "warn"));
  // Frames over the strict 60 cap (reject) → high.
  var rvF = b.guardImage.validate(
    { bytes: GIF89, declaredMime: "image/gif", frames: 100 }, { profile: "strict" });
  check("frames over strict cap → frames-cap high refuse",
    rvF.ok === false && _hasKindSev(rvF.issues, "frames-cap", "high"));
  // Frames over the balanced 200 cap (audit) → warn.
  var rvFB = b.guardImage.validate(
    { bytes: GIF89, declaredMime: "image/gif", frames: 300 }, { profile: "balanced" });
  check("frames over balanced cap → warn (ok true)",
    rvFB.ok === true && _hasKindSev(rvFB.issues, "frames-cap", "warn"));
}

function testValidateBadInput() {
  var rvNull = b.guardImage.validate(null, { profile: "strict" });
  check("validate(null) → bad-input refuse",
    rvNull.ok === false && _hasKind(rvNull.issues, "bad-input"));
  var rvNum = b.guardImage.validate(42, { profile: "strict" });
  check("validate(non-object) → bad-input refuse",
    rvNum.ok === false && _hasKind(rvNum.issues, "bad-input"));
}

function testValidateBadOpt() {
  check("maxWidth: -1 → bad-opt throw",
    _code(function () { b.guardImage.validate({ bytes: PNG_MAGIC }, { maxWidth: -1 }); }) === "image.bad-opt");
  check("maxFrames: Infinity → bad-opt throw",
    _code(function () { b.guardImage.validate({ bytes: PNG_MAGIC }, { maxFrames: Infinity }); }) === "image.bad-opt");
}

function testCompliancePostures() {
  // hipaa / pci-dss / soc2 map to the strict tier (dimensionsPolicy reject);
  // gdpr maps to balanced (dimensionsPolicy audit). Width 20000 exceeds both
  // the strict (8192) and balanced (16384) caps, so the posture's tier shows.
  var strictPostures = ["hipaa", "pci-dss", "soc2"];
  for (var ci = 0; ci < strictPostures.length; ci += 1) {
    var name = strictPostures[ci];
    var rv = b.guardImage.validate(
      { bytes: PNG_MAGIC, declaredMime: "image/png", width: 20000 },
      { compliancePosture: name });
    check(name + " posture → strict tier refuses oversized width",
      rv.ok === false && _hasKindSev(rv.issues, "width-cap", "high"));
  }
  var rvGdpr = b.guardImage.validate(
    { bytes: PNG_MAGIC, declaredMime: "image/png", width: 20000 },
    { compliancePosture: "gdpr" });
  check("gdpr posture → balanced tier audits oversized width (ok true)",
    rvGdpr.ok === true && _hasKindSev(rvGdpr.issues, "width-cap", "warn"));
}

// ---- the bespoke operator-feeds-metadata gate ----

async function testGate() {
  var g = b.guardImage.gate({ profile: "strict" });
  check("gate() returns a gate object", g && typeof g.check === "function");

  // No metadata → serve (nothing for the operator's decoder to report).
  var rvNone = await g.check({});
  check("gate: no metadata → serve", rvNone.action === "serve");

  // Clean PNG metadata → serve.
  var rvClean = await g.check({ metadata: {
    bytes: PNG_MAGIC, declaredMime: "image/png", width: 100, height: 100, frames: 1 } });
  check("gate: clean image → serve", rvClean.action === "serve");

  // MIME-mismatch → refuse.
  var rvMis = await g.check({ metadata: { bytes: JPEG_MAGIC, declaredMime: "image/png" } });
  check("gate: mime-mismatch → refuse", rvMis.action === "refuse");
  check("gate: mismatch issue reported", _hasKind(rvMis.issues, "mime-mismatch"));

  // Alternative ctx field ctx.imageMetadata.
  var rvAlt = await g.check({ imageMetadata: { bytes: JPEG_MAGIC, declaredMime: "image/png" } });
  check("gate: reads ctx.imageMetadata alias → refuse", rvAlt.action === "refuse");

  // Warn-level finding (balanced oversized dimension) → audit-only.
  var gBal = b.guardImage.gate({ profile: "balanced" });
  var rvAudit = await gBal.check({ metadata: { bytes: PNG_MAGIC, declaredMime: "image/png", width: 20000 } });
  check("gate: balanced oversized dimension → audit-only", rvAudit.action === "audit-only");

  // Polyglot → refuse.
  var rvPoly = await g.check({ metadata: { bytes: POLYGLOT } });
  check("gate: polyglot → refuse", rvPoly.action === "refuse");

  // BOM-SVG through the gate → refuse (route to guardSvg), not a silent serve.
  var rvBomSvg = await g.check({ metadata: { bytes: BOM_XML } });
  check("gate: BOM-svg → refuse (routed, not served)", rvBomSvg.action === "refuse");
}

// ---- the real metadata strip (sanitize) ----

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
  return Buffer.concat([PNG_MAGIC, ihdr, text, iend]);
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

// JPEG framing edge cases: standalone RST marker, a 0xFF fill byte before a
// marker code, kept ICC (APP2), dropped IPTC (APP13) + COM, and SOS entropy
// preserved verbatim.
function _jpegRich() {
  return Buffer.concat([
    Buffer.from([0xFF, 0xD8]),                                           // SOI
    Buffer.from([0xFF, 0xE1, 0x00, 0x05]), Buffer.from("px1", "latin1"), // APP1 EXIF — drop
    Buffer.from([0xFF, 0xE2, 0x00, 0x05]), Buffer.from("px2", "latin1"), // APP2 ICC  — keep
    Buffer.from([0xFF, 0xED, 0x00, 0x05]), Buffer.from("px3", "latin1"), // APP13 IPTC — drop
    Buffer.from([0xFF, 0xFE, 0x00, 0x05]), Buffer.from("px4", "latin1"), // COM — drop
    Buffer.from([0xFF, 0xD0]),                                           // RST0 standalone — keep
    Buffer.from([0xFF, 0xFF, 0xDB, 0x00, 0x04]), Buffer.from([1, 2]),    // fill-FF + DQT — keep
    Buffer.from([0xFF, 0xDA, 0x00, 0x03, 0x01]), Buffer.from("px5entropy", "latin1"), // SOS + entropy — keep verbatim
    Buffer.from([0xFF, 0xD9]),                                           // EOI (inside entropy verbatim)
  ]);
}

function testStripJpegRichFraming() {
  var src = _jpegRich();
  var out = b.guardImage.sanitize({ bytes: src });
  check("jpeg-rich: EXIF (APP1) dropped",  !_has(out.bytes, "px1"));
  check("jpeg-rich: IPTC (APP13) dropped", !_has(out.bytes, "px3"));
  check("jpeg-rich: COM dropped",          !_has(out.bytes, "px4"));
  check("jpeg-rich: ICC (APP2) preserved", _has(out.bytes, "px2"));
  check("jpeg-rich: SOS entropy preserved verbatim", _has(out.bytes, "px5entropy"));
  check("jpeg-rich: output shrank",        out.bytes.length < src.length);
  check("jpeg-rich: SOI intact",           out.bytes[0] === 0xFF && out.bytes[1] === 0xD8);
}

function testStripJpegMalformed() {
  // Each input detects as JPEG (FF D8 FF...) + passes validate, then trips a
  // distinct framing check inside the strip.
  check("jpeg: expected-marker malformed",
    _code(function () { b.guardImage.sanitize({ bytes: Buffer.from([0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x04, 0xAA, 0xBB, 0x00]) }); }) === "image.sanitize-malformed");
  check("jpeg: truncated-marker malformed",
    _code(function () { b.guardImage.sanitize({ bytes: Buffer.from([0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x04, 0xAA, 0xBB, 0xFF, 0xFF]) }); }) === "image.sanitize-malformed");
  check("jpeg: truncated-segment-length malformed",
    _code(function () { b.guardImage.sanitize({ bytes: Buffer.from([0xFF, 0xD8, 0xFF, 0xE2]) }); }) === "image.sanitize-malformed");
  check("jpeg: bad-segment-length malformed",
    _code(function () { b.guardImage.sanitize({ bytes: Buffer.from([0xFF, 0xD8, 0xFF, 0xE2, 0x00, 0x01]) }); }) === "image.sanitize-malformed");
  // Existing baseline: APP1 length overruns the buffer.
  check("jpeg: segment-overrun malformed",
    _code(function () { b.guardImage.sanitize({ bytes: Buffer.from([0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0xFF]) }); }) === "image.sanitize-malformed");
}

function testStripPngText() {
  var out = b.guardImage.sanitize({ bytes: _pngWithText() });
  check("png: tEXt payload removed",   !_has(out.bytes, "secret-gps"));
  check("png: IHDR preserved",         _has(out.bytes, "IHDR"));
  check("png: IEND preserved",         _has(out.bytes, "IEND"));
  check("png: signature intact",       out.bytes[0] === 0x89 && out.bytes[1] === 0x50);
}

function _pngChunk(type, data) {
  var len = Buffer.from([(data.length >>> 24) & 0xFF, (data.length >>> 16) & 0xFF,
    (data.length >>> 8) & 0xFF, data.length & 0xFF]);
  return Buffer.concat([len, Buffer.from(type, "latin1"), data, Buffer.from([0, 0, 0, 0])]); // crc placeholder
}

function _pngRich() {
  return Buffer.concat([
    PNG_MAGIC,
    _pngChunk("IHDR", Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0])),
    _pngChunk("zTXt", Buffer.from("zpayload", "latin1")),
    _pngChunk("eXIf", Buffer.from("epayload", "latin1")),
    _pngChunk("tIME", Buffer.from("tpayload", "latin1")),
    _pngChunk("iTXt", Buffer.from("ipayload", "latin1")),
    _pngChunk("IDAT", Buffer.from([1, 2, 3, 4])),
    _pngChunk("IEND", Buffer.from([])),
  ]);
}

function testStripPngRichChunks() {
  var out = b.guardImage.sanitize({ bytes: _pngRich() });
  check("png: zTXt dropped", !_has(out.bytes, "zpayload"));
  check("png: eXIf dropped", !_has(out.bytes, "epayload"));
  check("png: tIME dropped", !_has(out.bytes, "tpayload"));
  check("png: iTXt dropped", !_has(out.bytes, "ipayload"));
  check("png: IHDR preserved", _has(out.bytes, "IHDR"));
  check("png: IDAT preserved", _has(out.bytes, "IDAT"));
  check("png: IEND preserved", _has(out.bytes, "IEND"));
}

function testStripPngMalformed() {
  check("png: chunk-overrun malformed",
    _code(function () {
      b.guardImage.sanitize({ bytes: Buffer.concat([PNG_MAGIC, Buffer.from([0, 0, 0, 0xFF]), Buffer.from("IDAT", "latin1")]) });
    }) === "image.sanitize-malformed");
  check("png: chunk-length-exceeds-max malformed",
    _code(function () {
      b.guardImage.sanitize({ bytes: Buffer.concat([PNG_MAGIC, Buffer.from([0xFF, 0xFF, 0xFF, 0xFF]), Buffer.from("IDAT", "latin1")]) });
    }) === "image.sanitize-malformed");
}

function testStripGifComment() {
  var out = b.guardImage.sanitize({ bytes: _gifWithComment() });
  check("gif: comment payload removed", !_has(out.bytes, "secret-gps"));
  check("gif: header preserved",        _has(out.bytes, "GIF89a"));
  check("gif: trailer preserved",       out.bytes[out.bytes.length - 1] === 0x3B);
}

// Build a GIF extension block: 0x21 <label> <sub-block>* 0x00. For app / plain-
// text extensions the first sub-block is the fixed leading block (app-id / the
// 12-byte plain-text header).
function _gifExt(label, subBlocks) {
  var parts = [Buffer.from([0x21, label])];
  for (var i = 0; i < subBlocks.length; i += 1) {
    parts.push(Buffer.from([subBlocks[i].length]));
    parts.push(subBlocks[i]);
  }
  parts.push(Buffer.from([0x00]));                                                // block terminator
  return Buffer.concat(parts);
}

function _gifRich() {
  var headerGct = Buffer.concat([
    Buffer.from("GIF89a", "latin1"),
    Buffer.from([1, 0, 1, 0, 0x80, 0, 0]),                                       // LSD, packed=0x80 (GCT, 2 entries)
    Buffer.from([0, 0, 0, 0, 0, 0]),                                             // 6-byte global color table
  ]);
  var imgDesc = Buffer.concat([
    Buffer.from([0x2C, 0, 0, 0, 0, 1, 0, 1, 0, 0x80]),                           // image descriptor + LCT flag
    Buffer.from([0, 0, 0, 0, 0, 0]),                                             // 6-byte local color table
    Buffer.from([0x02]),                                                         // LZW min code size
    Buffer.from([0x01, 0x44, 0x00]),                                             // sub-block + terminator
  ]);
  return Buffer.concat([
    headerGct,
    _gifExt(0xF9, [Buffer.from([0x00, 0x00, 0x00, 0x00])]),                       // graphic control — keep
    _gifExt(0xFE, [Buffer.from("gifcmt", "latin1")]),                            // comment — drop
    _gifExt(0x01, [Buffer.alloc(12, 0), Buffer.from("gifptx", "latin1")]),       // plain-text — drop
    _gifExt(0xFF, [Buffer.from("NETSCAPE2.0", "latin1"), Buffer.from([0x01, 0x00, 0x00])]), // loop — keep
    _gifExt(0xFF, [Buffer.from("DROPMEAPPZZ", "latin1"), Buffer.from("gifxmp", "latin1")]), // non-loop app — drop
    imgDesc,
    Buffer.from([0x3B]),                                                         // trailer
  ]);
}

function testStripGifRichBlocks() {
  var out = b.guardImage.sanitize({ bytes: _gifRich() });
  check("gif-rich: comment dropped",       !_has(out.bytes, "gifcmt"));
  check("gif-rich: plain-text dropped",    !_has(out.bytes, "gifptx"));
  check("gif-rich: non-loop app dropped",  !_has(out.bytes, "gifxmp") && !_has(out.bytes, "DROPMEAPP"));
  check("gif-rich: NETSCAPE loop preserved", _has(out.bytes, "NETSCAPE2.0"));
  check("gif-rich: header preserved",      _has(out.bytes, "GIF89a"));
  check("gif-rich: trailer preserved",     out.bytes[out.bytes.length - 1] === 0x3B);
}

function testStripGifMalformed() {
  check("gif: truncated-header malformed",
    _code(function () { b.guardImage.sanitize({ bytes: Buffer.from("GIF89a", "latin1") }); }) === "image.sanitize-malformed");
  check("gif: unknown-block malformed",
    _code(function () {
      b.guardImage.sanitize({ bytes: Buffer.concat([Buffer.from("GIF89a", "latin1"), Buffer.from([1, 0, 1, 0, 0x00, 0, 0]), Buffer.from([0x99])]) });
    }) === "image.sanitize-malformed");
}

function testStripWebpExif() {
  var out = b.guardImage.sanitize({ bytes: _webpWithExif() });
  check("webp: EXIF payload removed",   !_has(out.bytes, "secret-gps"));
  check("webp: VP8 chunk preserved",    _has(out.bytes, "VP8 "));
  check("webp: RIFF size rewritten",    out.bytes.readUInt32LE(4) === 16);
}

function testStripWebpXmpAndPad() {
  var xmp = Buffer.concat([
    Buffer.from("RIFF", "latin1"), Buffer.from([0, 0, 0, 0]), Buffer.from("WEBP", "latin1"),
    Buffer.from("VP8 ", "latin1"), Buffer.from([4, 0, 0, 0]), Buffer.from([1, 2, 3, 4]),
    Buffer.from("XMP ", "latin1"), Buffer.from([6, 0, 0, 0]), Buffer.from("wxmpz0", "latin1"),
  ]);
  var outXmp = b.guardImage.sanitize({ bytes: xmp });
  check("webp: XMP chunk dropped", !_has(outXmp.bytes, "wxmpz0"));
  check("webp: VP8 preserved past XMP drop", _has(outXmp.bytes, "VP8 "));

  // Final chunk with an odd size and no trailing pad byte — tolerated.
  var oddNoPad = Buffer.concat([
    Buffer.from("RIFF", "latin1"), Buffer.from([0, 0, 0, 0]), Buffer.from("WEBP", "latin1"),
    Buffer.from("VP8 ", "latin1"), Buffer.from([3, 0, 0, 0]), Buffer.from([1, 2, 3]),
  ]);
  var outOdd = b.guardImage.sanitize({ bytes: oddNoPad });
  check("webp: odd-size final chunk without pad tolerated", _has(outOdd.bytes, "VP8 "));
}

function testStripWebpMalformed() {
  check("webp: chunk-overrun malformed",
    _code(function () {
      b.guardImage.sanitize({ bytes: Buffer.concat([
        Buffer.from("RIFF", "latin1"), Buffer.from([0, 0, 0, 0]), Buffer.from("WEBP", "latin1"),
        Buffer.from("VP8 ", "latin1"), Buffer.from([0xFF, 0, 0, 0]),
      ]) });
    }) === "image.sanitize-malformed");
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

function testSanitizePassthroughShapes() {
  // ICO carries no metadata container — same-reference passthrough.
  var icoBag = { bytes: Buffer.from([0x00, 0x00, 0x01, 0x00, 0, 0, 0, 0]) };
  check("ico: passes through unchanged", b.guardImage.sanitize(icoBag) === icoBag);
  // Non-Buffer bytes (Array) are not utf8-decoded — the bag returns unchanged.
  var arrBag = { bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] };
  check("sanitize: non-Buffer bytes pass through (same bag)", b.guardImage.sanitize(arrBag) === arrBag);
  // No bytes at all → bag returned unchanged.
  var emptyBag = {};
  check("sanitize: no bytes → bag unchanged", b.guardImage.sanitize(emptyBag) === emptyBag);
}

function testSanitizeBadInput() {
  check("sanitize(null) → bad-input refuse",
    _code(function () { b.guardImage.sanitize(null); }) === "image.bad-input");
}

async function run() {
  testGuardImageSurface();
  testGuardImageRegistryParity();
  testInspectMagic();
  testInspectMagicAllFormats();
  testInspectMagicBomSvg();
  testValidateSvgRoutedEveryProfile();
  testBomDoesNotBypassRasterMagic();
  testValidateNeverThrowsHostileMetadata();
  testValidateMismatchAndPolyglot();
  testValidatePolyglot();
  testValidateUnknownMagicSeverity();
  testValidateOversizedBytes();
  testValidateDimensionAndFrameCaps();
  testValidateBadInput();
  testValidateBadOpt();
  testCompliancePostures();
  await testGate();
  testStripJpegExif();
  testStripJpegRichFraming();
  testStripJpegMalformed();
  testStripPngText();
  testStripPngRichChunks();
  testStripPngMalformed();
  testStripGifComment();
  testStripGifRichBlocks();
  testStripGifMalformed();
  testStripWebpExif();
  testStripWebpXmpAndPad();
  testStripWebpMalformed();
  testStripWebpVp8xFlags();
  testRefuseBeforeStrip();
  testRefuseUnsupportedFormat();
  testRefuseMalformed();
  testBmpPassthrough();
  testSanitizePassthroughShapes();
  testSanitizeBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[guard-image] OK — " + helpers.getChecks() + " checks passed"); })
       .catch(function (e) { console.error("FAIL:", helpers.formatErr(e)); process.exit(1); });
}

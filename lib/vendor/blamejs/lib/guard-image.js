"use strict";
/**
 * guard-image — Image identifier-safety primitive (b.guardImage).
 *
 * Validates image-format inputs without vendoring a full decoder.
 * The framework's stance: operators bring their own decoder (sharp,
 * jimp, libvips wrappers, etc.). guardImage closes the magic-byte
 * vs declared-Content-Type mismatch class, the polyglot file class,
 * and operator-supplied metadata bounds (oversized dimensions, frame
 * count, color depth). KIND="metadata" — consumes
 * `ctx.metadata` shape: `{ bytes?, declaredMime?, width?, height?,
 * frames?, colorDepth?, hasAlpha? }`.
 *
 * Threat catalog:
 *   - Magic-byte vs declared-MIME mismatch — `Content-Type:
 *     image/png` with JPEG bytes (drive-by content-type confusion;
 *     downstream decoder picks wrong path).
 *   - Polyglot file — multiple format magic bytes detected in the
 *     same buffer (PHP-in-JPEG, JS-in-PNG class).
 *   - Oversized dimensions — operator passes width / height; the
 *     guard refuses against maxWidth / maxHeight.
 *   - Excessive frame count (animated GIF / WebP / APNG / AVIF
 *     image sequences) — operator passes frames; refused against
 *     maxFrames.
 *   - SVG content — delegates to b.guardSvg (this guard refuses
 *     SVG bytes directly so operators don't bypass the SVG guard
 *     by routing through guardImage).
 *   - Unknown / no magic-byte match.
 *
 *   var rv = b.guardImage.validate({ bytes, declaredMime: "image/png",
 *                                   width: 1024, height: 768 },
 *                                  { profile: "strict" });
 *   var g  = b.guardImage.gate({ profile: "strict" });
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
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
  { mime: "image/webp", bytes: [0x52, 0x49, 0x46, 0x46], tail: [0x57, 0x45, 0x42, 0x50], tailOffset: 8 }, // allow:raw-byte-literal — RIFF + WEBP magic-byte tail offset
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
    maxFrames:                 60,                                               // allow:raw-time-literal — animation frame count, not seconds
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
    maxFrames:                 200,                                              // allow:raw-byte-literal — animation frame ceiling
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
    maxFrames:                 1000,                                             // allow:raw-byte-literal — animation frame ceiling
    maxBytes:                  C.BYTES.mib(256),
    maxRuntimeMs:              C.TIME.seconds(5),
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardImageError,
    errCodePrefix:      "image",
  });
}

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
  if (bytes && typeof bytes.length === "number" && bytes.length > opts.maxBytes) {
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

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxWidth", "maxHeight", "maxFrames"],
    "guardImage.validate", GuardImageError, "image.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (!input || typeof input !== "object") {
    throw _err("image.bad-input", "sanitize requires metadata object");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "image.refused",
        "guardImage.sanitize: " + issues[i].snippet);
    }
  }
  return input;
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardImage:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var meta = ctx && (ctx.metadata || ctx.imageMetadata);
      if (!meta) return { ok: true, action: "serve" };
      var rv = validate(meta, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical";
      });
      var hasHigh = rv.issues.some(function (i) {
        return i.severity === "high";
      });
      if (!hasCritical && !hasHigh) {
        return { ok: true, action: "audit-only", issues: rv.issues };
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "image");
}

var _imgRulePacks = gateContract.makeRulePackLoader(GuardImageError, "image");
var loadRulePack = _imgRulePacks.load;

// Operator helper: surface the magic-byte detection result so callers
// can run their own dispatch without re-implementing the table.
function inspectMagic(bytes) {
  return _detectMagicMimes(bytes);
}

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "image",
  KIND:                "metadata",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "metadata",
    benignBytes:       Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    // Hostile: declared image/png but bytes are JPEG (mime-mismatch class —
    // drive-by content-type confusion / decoder-mux).
    hostileBytes:      Buffer.from([0xFF, 0xD8, 0xFF]),
    benignMetadata: {
      bytes: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
      declaredMime: "image/png",
      width: 100, height: 100, frames: 1,                                        // allow:raw-byte-literal — pixel + frame count fixture
    },
    hostileMetadata: {
      bytes: Buffer.from([0xFF, 0xD8, 0xFF]),
      declaredMime: "image/png",
    },
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  inspectMagic:        inspectMagic,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardImageError:     GuardImageError,
};

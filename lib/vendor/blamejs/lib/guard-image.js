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
 *   EXIF / XMP metadata strip: handled by the operator's decoder
 *   (sharp's `withMetadata: false`, libvips `metadata-strip`). The
 *   guard does not parse byte streams; it enforces the policy boundary
 *   and refuses the upload when the decoder's reported metadata
 *   violates a cap.
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
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxWidth", "maxHeight", "maxFrames"],
    "guardImage.validate", GuardImageError, "image.bad-opt");
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

/**
 * @primitive b.guardImage.sanitize
 * @signature b.guardImage.sanitize(input, opts)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardImage.validate, b.guardImage.gate
 *
 * Best-effort metadata pass-through. Image-byte sanitization
 * (transcoding, EXIF strip, dimension downscale) is the operator
 * decoder's responsibility — the guard cannot rewrite raster bytes
 * without a vendored decoder. `sanitize` validates the metadata
 * against the active profile and re-throws `GuardImageError` when
 * any issue is `critical` or `high`. Returns the input unchanged
 * when every issue is `warn` or below.
 *
 * @opts
 *   profile:           "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *
 * @example
 *   try {
 *     b.guardImage.sanitize({
 *       bytes: Buffer.from([0xFF, 0xD8, 0xFF]),
 *       declaredMime: "image/png",
 *     }, { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                            // → "image.mime-mismatch"
 *   }
 */
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
 * `audit-only` (warn-only) → `refuse` (any critical / high). No
 * `sanitize` action — image bytes can't be transcoded without a
 * vendored decoder.
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

/**
 * @primitive b.guardImage.buildProfile
 * @signature b.guardImage.buildProfile(opts)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardImage.compliancePosture, b.guardImage.gate
 *
 * Resolve a named profile against the guard's PROFILES catalog and
 * return the merged options bag. Throws
 * `GuardImageError("image.bad-profile")` on unknown name.
 *
 * @opts
 *   profile: "strict"|"balanced"|"permissive",
 *
 * @example
 *   var resolved = b.guardImage.buildProfile({ profile: "strict" });
 *   resolved.maxWidth;                                   // → 8192
 *   resolved.polyglotPolicy;                             // → "reject"
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardImage.compliancePosture
 * @signature  b.guardImage.compliancePosture(name)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardImage.gate, b.guardImage.buildProfile
 *
 * Return the option overlay for a named compliance posture
 * (`"hipaa"` / `"pci-dss"` / `"gdpr"` / `"soc2"`). Throws
 * `GuardImageError("image.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardImage.compliancePosture("hipaa");
 *   posture.mismatchPolicy;                              // → "reject"
 *   posture.forensicSnippetBytes;                        // → 256
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "image");
}

var _imgRulePacks = gateContract.makeRulePackLoader(GuardImageError, "image");
/**
 * @primitive b.guardImage.loadRulePack
 * @signature b.guardImage.loadRulePack(pack)
 * @since     0.7.13
 * @status    stable
 * @related   b.guardImage.gate
 *
 * Register an operator-supplied rule pack (extra MIME / dimension /
 * polyglot overrides) into the guard's private store. Throws
 * `GuardImageError("image.bad-opt")` when `pack` is missing or
 * `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardImage.loadRulePack({
 *     id: "kb-2026-image",
 *     extraMaxFrames: 30,
 *   });
 *   pack.id;                                             // → "kb-2026-image"
 */
var loadRulePack = _imgRulePacks.load;

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
      width: 100, height: 100, frames: 1,                                        // pixel + frame count fixture
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

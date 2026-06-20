"use strict";
/**
 * @module b.guardUuid
 * @nav    Guards
 * @title  Guard Uuid
 *
 * @intro
 *   UUID identifier-safety guard. Validates user-supplied UUID
 *   strings per RFC 9562 (May 2024 — obsoletes RFC 4122) and
 *   refuses non-RFC shapes that downstream parsers routinely
 *   misinterpret. KIND="identifier" — the gate consumes
 *   `ctx.identifier` (or `ctx.uuid`).
 *
 *   Threat catalog: wrong length / shape (canonical 36-char
 *   hyphenated, 32-char hyphenless, 38-char braced, or
 *   `urn:uuid:` prefixed — anything else is malformed); wrong
 *   character class (non-hex anywhere); invalid version field
 *   (RFC 9562 §4.2 defines 1-8; 0 and 9-F are reserved /
 *   unassigned and indicate hand-rolled or attacker-shaped IDs);
 *   variant bits (RFC 9562 §4.1 — only 10xx is the canonical
 *   variant; NCS-reserved 0xxx, Microsoft 110x, future 111x often
 *   indicate non-UUID payloads coerced into the slot); nil UUID
 *   (§5.9 all zeros — usually "no UUID set", masks missing-key
 *   bugs when passed through); max UUID (§5.10 all FF — sentinel
 *   with the same semantic risk as nil); `urn:uuid:` prefix
 *   smuggling; Microsoft GUID braces `{...}` smuggling;
 *   BIDI / zero-width / C0-control / null-byte universal-refuse.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`.
 *
 * @card
 *   UUID identifier-safety guard.
 */

var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var { GuardUuidError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardUuidError.factory;

// ---- Static patterns ----

// Canonical RFC 9562 form: 8-4-4-4-12 hex chars with dashes.
var UUID_HYPHENATED_RE = /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/i;

// Hyphenless 32-hex form (some serializers strip the hyphens).
var UUID_HYPHENLESS_RE = /^[0-9a-f]{32}$/i;

// Microsoft GUID-with-braces form.
var UUID_BRACED_RE = /^\{([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\}$/i;

// urn:uuid: prefix form.
var UUID_URN_RE = /^urn:uuid:([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/i;

var NIL_HEX = "00000000000000000000000000000000";
var MAX_HEX = "ffffffffffffffffffffffffffffffff";

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    formatPolicy:      "hyphenated-only",   // hyphenated | hyphenless | braced | urn | hyphenated-only | any
    versionPolicy:     "reject-unassigned", // reject-unassigned | audit | allow
    variantPolicy:     "reject-non-rfc",    // reject-non-rfc | audit | allow
    nilPolicy:         "reject",
    maxPolicy:         "reject",
    urnPolicy:         "reject",
    bracedPolicy:      "reject",
    allowedVersions:   [1, 2, 3, 4, 5, 6, 7, 8],                                 // UUID version digits
    maxBytes:          C.BYTES.bytes(64),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
  "balanced": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    formatPolicy:      "any",
    versionPolicy:     "reject-unassigned",
    variantPolicy:     "audit",
    nilPolicy:         "audit",
    maxPolicy:         "audit",
    urnPolicy:         "audit",
    bracedPolicy:      "audit",
    allowedVersions:   [1, 2, 3, 4, 5, 6, 7, 8],                                 // UUID version digits
    maxBytes:          C.BYTES.bytes(64),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
  "permissive": {
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    formatPolicy:      "any",
    versionPolicy:     "audit",
    variantPolicy:     "allow",
    nilPolicy:         "allow",
    maxPolicy:         "allow",
    urnPolicy:         "allow",
    bracedPolicy:      "allow",
    allowedVersions:   null,                                                     // any version
    maxBytes:          C.BYTES.bytes(64),
    maxRuntimeMs:      C.TIME.seconds(2),
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES);

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 128 });

function _classifyForm(input) {
  if (UUID_URN_RE.test(input)) return "urn";                                     // allow:regex-no-length-cap — input bounded by maxBytes
  if (UUID_BRACED_RE.test(input)) return "braced";                               // allow:regex-no-length-cap — input bounded by maxBytes
  if (UUID_HYPHENATED_RE.test(input)) return "hyphenated";                       // allow:regex-no-length-cap — input bounded by maxBytes
  if (UUID_HYPHENLESS_RE.test(input)) return "hyphenless";                       // allow:regex-no-length-cap — input bounded by maxBytes
  return null;
}

function _toCanonicalHex(input, form) {
  // Strips dashes / braces / urn prefix, returns 32-char lowercase hex.
  var s = input.toLowerCase();
  if (form === "urn")     s = s.slice("urn:uuid:".length);                       // string-length offset
  if (form === "braced")  s = s.slice(1, -1);                                    // string-length offset
  return s.replace(/-/g, "");
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "uuid", cap: { bytes: opts.maxBytes } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  // Format classification.
  var form = _classifyForm(input);
  if (form === null) {
    issues.push({
      kind: "uuid-shape", severity: "high",
      ruleId: "uuid.uuid-shape",
      snippet: "input does not match any RFC 9562 UUID form " +
               "(hyphenated / hyphenless / braced / urn:uuid:)",
    });
    return issues;
  }

  // Format-policy enforcement.
  var formatPolicy = opts.formatPolicy;
  var formAllowed = (
    formatPolicy === "any" ||
    formatPolicy === form ||
    (formatPolicy === "hyphenated-only" && form === "hyphenated")
  );
  if (!formAllowed) {
    issues.push({
      kind: "uuid-form-disallowed",
      severity: "high",
      ruleId: "uuid.uuid-form-disallowed",
      snippet: "uuid form `" + form + "` not permitted by formatPolicy `" +
               formatPolicy + "`",
    });
  }
  if (form === "urn" && opts.urnPolicy !== "allow") {
    issues.push({
      kind: "urn-prefix",
      severity: opts.urnPolicy === "reject" ? "high" : "warn",
      ruleId: "uuid.urn-prefix",
      snippet: "uuid carries `urn:uuid:` prefix — would be processed " +
               "by URN-shape parsers downstream",
    });
  }
  if (form === "braced" && opts.bracedPolicy !== "allow") {
    issues.push({
      kind: "braced",
      severity: opts.bracedPolicy === "reject" ? "high" : "warn",
      ruleId: "uuid.braced",
      snippet: "uuid uses Microsoft GUID braces `{...}` — non-canonical",
    });
  }

  var hex = _toCanonicalHex(input, form);

  // Nil / Max sentinel checks.
  if (hex === NIL_HEX && opts.nilPolicy !== "allow") {
    issues.push({
      kind: "nil-uuid",
      severity: opts.nilPolicy === "reject" ? "high" : "warn",
      ruleId: "uuid.nil-uuid",
      snippet: "uuid is the nil UUID (RFC 9562 §5.9) — sentinel often " +
               "indicates missing-key bug",
    });
  }
  if (hex === MAX_HEX && opts.maxPolicy !== "allow") {
    issues.push({
      kind: "max-uuid",
      severity: opts.maxPolicy === "reject" ? "high" : "warn",
      ruleId: "uuid.max-uuid",
      snippet: "uuid is the max UUID (RFC 9562 §5.10) — sentinel often " +
               "indicates missing-key bug",
    });
  }

  // Version + variant inspection (skip for nil / max — those bypass the
  // version-bits check by definition).
  if (hex !== NIL_HEX && hex !== MAX_HEX) {
    var versionDigit = parseInt(hex.charAt(12), 16);                             // hex digit position 12
    var variantNibble = parseInt(hex.charAt(16), 16);                            // hex digit position 16

    if (opts.versionPolicy !== "allow") {
      var allowed = opts.allowedVersions;
      var versionOk = !allowed || allowed.indexOf(versionDigit) !== -1;
      if (!versionOk) {
        issues.push({
          kind: "version-unassigned",
          severity: opts.versionPolicy === "reject-unassigned" ? "high" : "warn",
          ruleId: "uuid.version-unassigned",
          snippet: "uuid version digit " + versionDigit + " not in " +
                   "allowedVersions " + JSON.stringify(allowed) +
                   " (RFC 9562 §4.2 defines 1-8)",
        });
      }
    }

    if (opts.variantPolicy !== "allow") {
      // RFC 4122 / 9562 variant: high two bits of the variant nibble are
      // 10xx (i.e. nibble in 8/9/a/b).
      var isRfcVariant = (variantNibble & 0xC) === 0x8;                          // variant-bit mask
      if (!isRfcVariant) {
        issues.push({
          kind: "variant-non-rfc",
          severity: opts.variantPolicy === "reject-non-rfc" ? "high" : "warn",
          ruleId: "uuid.variant-non-rfc",
          snippet: "uuid variant nibble `" + hex.charAt(16) + "` is not " +    // hex digit position 16
                   "the RFC 4122 / 9562 variant (10xx — nibble 8-b)",
        });
      }
    }
  }

  return issues;
}

/**
 * @primitive  b.guardUuid.validate
 * @signature  b.guardUuid.validate(input, opts?)
 * @since      0.7.44
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardUuid.sanitize, b.guardUuid.gate, b.uuid.v4, b.uuid.v7
 *
 * Inspect a UUID string against the resolved profile and return
 * `{ ok, issues }`. Each issue carries `kind` / `severity`
 * (`critical` | `high` | `medium` | `low`) / `ruleId` / `snippet`.
 * Non-string input returns a single `uuid.bad-input` issue rather
 * than throwing — callers that prefer an exception use
 * `b.guardUuid.sanitize`.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   bidiPolicy:             "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:          "reject"|"strip"|"allow",
 *   nullBytePolicy:         "reject"|"strip"|"allow",
 *   zeroWidthPolicy:        "reject"|"strip"|"allow",
 *   formatPolicy:           "hyphenated"|"hyphenless"|"braced"|"urn"|"hyphenated-only"|"any",
 *   versionPolicy:          "reject-unassigned"|"audit"|"allow",
 *   variantPolicy:          "reject-non-rfc"|"audit"|"allow",
 *   nilPolicy:              "reject"|"audit"|"allow",
 *   maxPolicy:              "reject"|"audit"|"allow",
 *   urnPolicy:              "reject"|"audit"|"allow",
 *   maxBytes:               number,
 *
 * @example
 *   var rv = b.guardUuid.validate("550e8400-e29b-41d4-a716-446655440000",
 *                                 { profile: "strict" });
 *   rv.ok;                                             // → true
 *
 *   var bad = b.guardUuid.validate("00000000-0000-0000-0000-000000000000",
 *                                  { profile: "strict" });
 *   bad.ok;                                            // → false
 *   bad.issues[0].ruleId;                              // → "uuid.nil"
 */
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues) below — `validate(input, opts) = aggregateIssues(detect(
// input, resolveOpts(opts)))`, with the maxBytes cap declared via `intOpts`.
// The @primitive block above documents the resulting public ABI.

/**
 * @primitive  b.guardUuid.sanitize
 * @signature  b.guardUuid.sanitize(input, opts?)
 * @since      0.7.44
 * @status     stable
 * @related    b.guardUuid.validate, b.guardUuid.gate
 *
 * Normalize a UUID to canonical hyphenated lowercase form. Strips
 * Microsoft GUID braces `{...}` and the `urn:uuid:` prefix. Throws
 * `GuardUuidError` when any `critical` or `high` issue fires
 * (nil / max sentinel under reject, unassigned version, non-RFC
 * variant). Use `validate` to inspect issues without throwing.
 *
 * @opts
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:                    same shape as b.guardUuid.validate opts,
 *
 * @example
 *   var safe = b.guardUuid.sanitize("urn:uuid:550E8400-E29B-41D4-A716-446655440000",
 *                                   { profile: "balanced" });
 *   safe;                                              // → "550e8400-e29b-41d4-a716-446655440000"
 *
 *   try {
 *     b.guardUuid.sanitize("ffffffff-ffff-ffff-ffff-ffffffffffff",
 *                          { profile: "strict" });
 *   } catch (e) {
 *     e.code;                                          // → "uuid.max"
 *   }
 */
// _sanitizeTransform — the guard-specific normalize applied by defineGuard's
// generated sanitize AFTER resolve → detect → throw-on-refusal. Input is an
// already-validated string at this point (a non-string refuses upstream).
function _sanitizeTransform(input) {
  // Safe transforms: lowercase + strip braces / urn prefix → canonical
  // hyphenated form.
  var form = _classifyForm(input);
  if (!form) return input;
  var hex = _toCanonicalHex(input, form);
  return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" +                        // UUID hex slice positions
         hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" +                     // UUID hex slice positions
         hex.slice(20);                                                          // UUID hex slice positions
}

// gate / buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below; their wiki sections render from the
// single-sourced @abiTemplate (defineGuard) blocks in gate-contract.js,
// instantiated per guard by the page generator.

// Hostile: nil UUID — refused at strict (sentinel-leak class).
var INTEGRATION_FIXTURES = gateContract.identifierFixtures("550e8400-e29b-41d4-a716-446655440000", "00000000-0000-0000-0000-000000000000");

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / INTEGRATION_FIXTURES), buildProfile /
// compliancePosture / loadRulePack wiring, plus the per-guard inspection
// surface (validate / sanitize). The gate is the factory default — the
// standard serve -> audit-only -> refuse chain — reading ctx.identifier ||
// ctx.uuid via ctxFields.
module.exports = gateContract.defineGuard({
  name:        "uuid",
  kind:        "identifier",
  errorClass:  GuardUuidError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:            _detectIssues,
  sanitizeTransform: _sanitizeTransform,
  intOpts:           ["maxBytes"],
  ctxFields:   ["identifier", "uuid"],
});

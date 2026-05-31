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

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
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
    bidiPolicy:        "reject",
    controlPolicy:     "reject",
    nullBytePolicy:    "reject",
    zeroWidthPolicy:   "reject",
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
    bidiPolicy:        "reject",
    controlPolicy:     "reject",
    nullBytePolicy:    "reject",
    zeroWidthPolicy:   "reject",
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
    bidiPolicy:        "reject",                                                 // BIDI refused at every profile
    controlPolicy:     "reject",                                                 // controls refused at every profile
    nullBytePolicy:    "reject",                                                 // null refused at every profile
    zeroWidthPolicy:   "reject",                                                 // zero-width refused at every profile
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

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode: "enforce",
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa":   Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "gdpr":    Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(64),
  }),
  "soc2":    Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
});

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardUuidError,
    errCodePrefix:      "uuid",
  });
}

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
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              ruleId: "uuid.bad-input",
              snippet: "uuid is not a string" }];
  }
  if (input.length === 0) {
    return [{ kind: "empty", severity: "high",
              ruleId: "uuid.empty",
              snippet: "uuid is empty" }];
  }
  if (Buffer.byteLength(input, "utf8") > opts.maxBytes) {
    return [{ kind: "uuid-cap", severity: "high",
              ruleId: "uuid.uuid-cap",
              snippet: "uuid input exceeds maxBytes " + opts.maxBytes }];
  }

  // Codepoint-class threats (universal refuse — runs first).
  var charThreats = codepointClass.detectCharThreats(input, opts, "uuid");
  for (var ci = 0; ci < charThreats.length; ci += 1) issues.push(charThreats[ci]);

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
function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes"],
    "guardUuid.validate", GuardUuidError, "uuid.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 ruleId: "uuid.bad-input",
                 snippet: "uuid is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

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
function sanitize(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("uuid.bad-input", "sanitize requires string input");
  }
  var issues = _detectIssues(input, opts);
  for (var i = 0; i < issues.length; i += 1) {
    if (issues[i].severity === "critical" || issues[i].severity === "high") {
      throw _err(issues[i].ruleId || "uuid.refused",
        "guardUuid.sanitize: " + issues[i].snippet);
    }
  }
  // Safe transforms: lowercase + strip braces / urn prefix → canonical
  // hyphenated form.
  var form = _classifyForm(input);
  if (!form) return input;
  var hex = _toCanonicalHex(input, form);
  return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" +                        // UUID hex slice positions
         hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" +                     // UUID hex slice positions
         hex.slice(20);                                                          // UUID hex slice positions
}

/**
 * @primitive  b.guardUuid.gate
 * @signature  b.guardUuid.gate(opts?)
 * @since      0.7.44
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardUuid.validate, b.guardUuid.sanitize, b.guardAll.gate
 *
 * Build a guard gate whose async `check(ctx)` returns `{ ok, action, issues }`, consumable
 * by `b.guardAll`, ID validators, and any host that handles
 * UUID-shaped tokens. The gate reads `ctx.identifier` (or
 * `ctx.uuid`), runs `validate`, and maps severity to action: zero
 * issues `serve`; only low/medium `audit-only`; any high/critical
 * `refuse`.
 *
 * @opts
 *   name:                   string,    // gate label for audit / observability
 *   profile:                "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   ...:                    same shape as b.guardUuid.validate opts,
 *
 * @example
 *   var g = b.guardUuid.gate({ profile: "strict" });
 *   var rv = await g.check({ identifier: "550e8400-e29b-41d4-a716-446655440000" });
 *   rv.action;                                         // → "serve"
 *
 *   var bad = await g.check({ identifier: "{550e8400-e29b-41d4-a716-446655440000}" });
 *   bad.action;                                        // → "refuse"
 */
function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardUuid:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var identifier = ctx && (ctx.identifier || ctx.uuid || "");
      if (!identifier) return { ok: true, action: "serve" };
      var rv = validate(identifier, opts);
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
 * @primitive  b.guardUuid.buildProfile
 * @signature  b.guardUuid.buildProfile(opts)
 * @since      0.7.44
 * @status     stable
 * @related    b.guardUuid.gate, b.guardUuid.compliancePosture
 *
 * Compose a derived profile from one or more named bases plus
 * inline overrides. `opts.extends` is a profile name or array of
 * names (later entries shadow earlier ones); inline keys win last.
 *
 * @opts
 *   extends: string|string[],   // base profile name(s) to compose
 *   ...:     any guard-uuid key, // inline override of resolved keys
 *
 * @example
 *   var custom = b.guardUuid.buildProfile({
 *     extends: "balanced",
 *     formatPolicy: "hyphenated-only",
 *     nilPolicy: "audit",
 *   });
 *   custom.formatPolicy;                               // → "hyphenated-only"
 *   custom.nilPolicy;                                  // → "audit"
 */
var buildProfile = gateContract.makeProfileBuilder(PROFILES);

/**
 * @primitive  b.guardUuid.compliancePosture
 * @signature  b.guardUuid.compliancePosture(name)
 * @since      0.7.44
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardUuid.gate, b.guardUuid.buildProfile
 *
 * Look up a compliance-posture overlay by name (`"hipaa"` /
 * `"pci-dss"` / `"gdpr"` / `"soc2"`). Returns a shallow clone of
 * the posture object — the caller may mutate freely. Throws
 * `GuardUuidError("uuid.bad-posture")` on unknown name.
 *
 * @example
 *   var posture = b.guardUuid.compliancePosture("hipaa");
 *   posture.nilPolicy;                                 // → "reject"
 */
function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES,
    _err, "uuid");
}

var _uuidRulePacks = gateContract.makeRulePackLoader(GuardUuidError, "uuid");
/**
 * @primitive  b.guardUuid.loadRulePack
 * @signature  b.guardUuid.loadRulePack(pack)
 * @since      0.7.44
 * @status     stable
 * @related    b.guardUuid.gate
 *
 * Register an operator-supplied rule pack with the guard-uuid
 * registry. The pack is identified by `pack.id` (non-empty
 * string) and stored for later inspection / dispatch by gates
 * that opt in via `opts.rulePackId`. Throws
 * `GuardUuidError("uuid.bad-opt")` when `pack` is missing or
 * `pack.id` is not a non-empty string.
 *
 * @example
 *   var pack = b.guardUuid.loadRulePack({
 *     id: "v7-only",
 *     allowedVersions: [7],
 *   });
 *   pack.id;                                           // → "v7-only"
 */
var loadRulePack = _uuidRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "uuid",
  KIND:                "identifier",
  INTEGRATION_FIXTURES: Object.freeze({
    kind:              "identifier",
    benignBytes:       Buffer.from("550e8400-e29b-41d4-a716-446655440000", "utf8"),
    hostileBytes:      Buffer.from("00000000-0000-0000-0000-000000000000", "utf8"),
    benignIdentifier:  "550e8400-e29b-41d4-a716-446655440000",
    // Hostile: nil UUID — refused at strict (sentinel-leak class).
    hostileIdentifier: "00000000-0000-0000-0000-000000000000",
  }),
  // ---- primitive surface ----
  validate:            validate,
  sanitize:            sanitize,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardUuidError:      GuardUuidError,
};

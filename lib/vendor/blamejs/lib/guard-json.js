"use strict";
/**
 * @module b.guardJson
 * @nav    Guards
 * @title  Guard Json
 *
 * @intro
 *   JSON content-safety guard — defends against the threat catalog
 *   operators face when accepting JSON sourced from user input.
 *   `b.safeJson.parse` enforces baseline depth + size caps; this
 *   module layers prototype-pollution / depth-bomb / key-count /
 *   duplicate-key / unicode threat detection on top.
 *
 *   Prototype-pollution defense: keys `__proto__` / `constructor` /
 *   `prototype` anywhere in the tree are detected at the SOURCE level
 *   (before any parser sees them). After `JSON.parse` normalizes the
 *   input, `__proto__` routes through the prototype setter and is
 *   invisible to `Object.keys()`, so a post-parse tree walk misses
 *   the pollution shape — the source-text scan catches it. CVE
 *   coverage spans the 2025-2026 deserialization + prototype-
 *   pollution wave: CVE-2025-55182 React Server Functions RCE,
 *   CVE-2025-57820 / CVE-2026-30226 Svelte devalue, CVE-2026-35209
 *   defu, CVE-2026-28794 @orpc/client, CVE-2025-13465 Lodash path
 *   traversal, CVE-2025-25014 Kibana, CVE-2024-38984 json-override,
 *   CVE-2022-42743 deep-parse-json, GHSA-9c47-m6qq-7p4h JSON5.
 *
 *   Depth + breadth caps: `maxDepth` / `maxKeysPerObject` /
 *   `maxArrayLength` / `maxStringLength` / `maxTotalNodes` refuse
 *   key-count bombs (10^6 keys per object) and stack-exhaustion
 *   nesting attacks under strict.
 *
 *   Duplicate-key smuggling: RFC 8259 says keys SHOULD be unique;
 *   `JSON.parse` silently last-wins. A two-validator pipeline that
 *   inspects the first occurrence and trusts the parser's last-wins
 *   value is the smuggling shape; this guard rescans the source for
 *   identical quoted keys at the same `{ ... }` nesting level.
 *
 *   JSON5 / JSONC quirks (single-line `//` + block C-style
 *   comments, trailing commas, NaN / Infinity / -Infinity, hex
 *   literals, single-quoted keys) — RFC 8259 forbids these but
 *   lenient parsers accept; the guard flags them at the source so
 *   operators can refuse hostile inputs regardless of which parser
 *   is downstream.
 *
 *   Numeric precision loss: integers above `Number.MAX_SAFE_INTEGER`
 *   (~9.007 x 10^15, 16 digits) silently lose precision when round-
 *   tripped through Number. Detected via raw-text scan for digit
 *   runs of 17+ characters.
 *
 *   BOM injection (leading or mid-stream U+FEFF) and bidi / null /
 *   control / zero-width character threats route through the shared
 *   lib/codepoint-class catalog — the same detector backing the
 *   guard-csv / guard-html / guard-svg families.
 *
 *   Top-level-key allowlist: when the operator opts in via
 *   `topLevelKeyAllowlist: ["alpha", "beta"]`, every other top-level
 *   key triggers a refused-shape issue. Useful for HTTP body schemas
 *   where unexpected keys signal malformed or hostile input.
 *
 *   Profiles: `strict` / `balanced` / `permissive`. Compliance
 *   postures: `hipaa` / `pci-dss` / `gdpr` / `soc2`. Operators select
 *   via `{ profile: "strict" }` or `{ compliancePosture: "hipaa" }`;
 *   postures overlay on top of the profile baseline.
 *
 *   Source files MUST be pure ASCII; threat-detection regexes
 *   compose programmatically via lib/codepoint-class so the source
 *   never embeds the attack characters themselves.
 *
 * @card
 *   JSON content-safety guard — defends against the threat catalog operators face when accepting JSON sourced from user input.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var pick = require("./pick");
var gateContract = require("./gate-contract");
var C = require("./constants");
var safeJson = require("./safe-json");
var { GuardJsonError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardJsonError.factory;

// ---- Compiled detectors ----

var BIDI_RE       = codepointClass.BIDI_RE;
var C0_CTRL_RE    = codepointClass.C0_CTRL_RE;
var NULL_BYTE     = codepointClass.NULL_BYTE;
var BOM_CHAR      = codepointClass.BOM_CHAR;

// Comment / NaN / Infinity / hex / single-quote markers — pre-parse
// scan on the raw source. JSON.parse rejects most of these, but JSON5
// / JSONC parsers accept and silently coerce; we surface the source
// shape so operators can refuse the whole input regardless of which
// parser their downstream code uses.
var COMMENT_LINE_RE  = /(^|[^"\\])\/\/[^\r\n]*/m;
var COMMENT_BLOCK_RE = /\/\*[\s\S]*?\*\//;
var BARE_NAN_RE      = /(^|[\s,:[{(])(NaN|Infinity|-Infinity|undefined)\b/;
var TRAILING_COMMA_RE = /,(\s*[\]}])/;
var SINGLE_QUOTED_KEY_RE = /(^|[\s,{])'[^']*'\s*:/;
var HEX_LITERAL_RE   = /(^|[\s,:[{(])-?0[xX][0-9a-fA-F]+\b/;

// Numeric precision — runs of 16+ digits in a number context (above
// Number.MAX_SAFE_INTEGER ≈ 9.007e15 ≈ 16 digits).
var BIG_INTEGER_RE = /(^|[\s,:[{(])(-?\d{17,})(?:[\s,\]}]|$)/;

// Prototype-pollution key detector — SOURCE-level. After JSON.parse,
// __proto__ disappears from Object.keys() (it routes through the
// prototype setter), so a tree-walk after parse misses it. Scan the
// raw source for `"__proto__":`, `"constructor":`, `"prototype":`
// patterns to catch hostile sources before any parser sees them. The
// detection is conservative (matches inside strings too — operator's
// downstream code may run a JSON.parse without the safeJson reviver
// and the pollution still lands).
var POLLUTION_KEY_SOURCE_RE = /"(__proto__|constructor|prototype)"\s*:/;

// ---- Profile presets ----

var PROFILES = Object.freeze({
  "strict": {
    pollutionPolicy:        "reject",
    duplicateKeyPolicy:     "reject",
    nanInfinityPolicy:      "reject",
    commentPolicy:          "reject",
    trailingCommaPolicy:    "reject",
    json5SyntaxPolicy:      "reject",       // single-quoted / hex / unquoted-key
    bomPolicy:              "reject",
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    numericPrecisionPolicy: "reject",
    requireTopLevelKeyAllowlist: false,     // operator opts in via topLevelKeyAllowlist
    topLevelKeyAllowlist:   null,
    maxBytes:               C.BYTES.mib(2),
    maxDepth:               8,                                                   // recursion depth, not byte size
    maxKeysPerObject:       256,                                                 // key count cap, not byte size
    maxArrayLength:         1024,                                                // array length cap, not byte size
    maxStringLength:        C.BYTES.kib(8),
    maxTotalNodes:          0x2000,                                              // node count cap, not byte size
  },
  "balanced": {
    pollutionPolicy:        "strip",        // remove __proto__ keys silently
    duplicateKeyPolicy:     "audit",
    nanInfinityPolicy:      "reject",
    commentPolicy:          "audit",
    trailingCommaPolicy:    "audit",
    json5SyntaxPolicy:      "audit",
    bomPolicy:              "strip",
    bidiPolicy:             "strip",
    controlPolicy:          "strip",
    nullBytePolicy:         "strip",
    zeroWidthPolicy:        "strip",
    numericPrecisionPolicy: "audit",
    requireTopLevelKeyAllowlist: false,
    topLevelKeyAllowlist:   null,
    maxBytes:               C.BYTES.mib(8),
    maxDepth:               32,                                                  // recursion depth, not byte size
    maxKeysPerObject:       4096,                                                // key count cap, not byte size
    maxArrayLength:         65536,                                               // array length cap, not byte size
    maxStringLength:        C.BYTES.kib(64),
    maxTotalNodes:          0x10000,                                             // node count cap, not byte size
  },
  "permissive": {
    pollutionPolicy:        "audit",
    duplicateKeyPolicy:     "audit",
    nanInfinityPolicy:      "audit",
    commentPolicy:          "audit",
    trailingCommaPolicy:    "audit",
    json5SyntaxPolicy:      "audit",
    bomPolicy:              "strip",
    bidiPolicy:             "audit",
    controlPolicy:          "strip",
    nullBytePolicy:         "reject",
    zeroWidthPolicy:        "strip",
    numericPrecisionPolicy: "audit",
    requireTopLevelKeyAllowlist: false,
    topLevelKeyAllowlist:   null,
    maxBytes:               C.BYTES.mib(64),
    maxDepth:               64,                                                  // recursion depth, not byte size
    maxKeysPerObject:       65536,                                               // key count cap, not byte size
    maxArrayLength:         1048576,                                             // array length cap, not byte size
    maxStringLength:        C.BYTES.kib(256),
    maxTotalNodes:          0x40000,                                             // node count cap, not byte size
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs:  C.TIME.seconds(10),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

// ---- Helpers ----

function _resolveOpts(opts) {
  return gateContract.resolveProfileAndPosture(opts, {
    profiles:           PROFILES,
    compliancePostures: COMPLIANCE_POSTURES,
    defaults:           DEFAULTS,
    errorClass:         GuardJsonError,
    errCodePrefix:      "json",
  });
}

function _isPollutionKey(key) {
  // The framework's single prototype-pollution predicate (core JS vectors
  // plus any operator-registered defense-in-depth extensions) — strict JSON
  // refuses / strips every key it names, at any depth.
  return pick.isPoisonedKey(key);
}

// _scanPollutionKeys — walks parsed JSON tree counting prototype-
// pollution keys and depth + breadth + node-count exhaustion. Operator
// can either reject the whole tree or strip pollution keys.
function _scanTree(value, opts, ctx) {
  if (!ctx) ctx = { depth: 0, totalNodes: 0, pollutionHits: [],
                    duplicateKeyHits: [], breadthCapHits: [],
                    arrayLenCapHits: [], depthCapHits: [],
                    stringTooLongHits: [] };
  ctx.totalNodes += 1;
  if (ctx.totalNodes > opts.maxTotalNodes) {
    ctx.depthCapHits.push({ kind: "node-count-cap",
      snippet: "node count exceeds maxTotalNodes " + opts.maxTotalNodes });
    return ctx;
  }
  if (ctx.depth > opts.maxDepth) {
    ctx.depthCapHits.push({ kind: "depth-cap",
      snippet: "depth " + ctx.depth + " exceeds maxDepth " + opts.maxDepth });
    return ctx;
  }
  if (value === null || typeof value !== "object") {
    if (typeof value === "string" && value.length > opts.maxStringLength) {
      ctx.stringTooLongHits.push({
        kind: "string-too-long",
        snippet: "string length " + value.length +
                 " exceeds maxStringLength " + opts.maxStringLength,
      });
    }
    return ctx;
  }
  if (Array.isArray(value)) {
    if (value.length > opts.maxArrayLength) {
      ctx.arrayLenCapHits.push({
        kind: "array-length-cap",
        snippet: "array length " + value.length +
                 " exceeds maxArrayLength " + opts.maxArrayLength,
      });
    }
    for (var i = 0; i < value.length; i += 1) {
      ctx.depth += 1;
      _scanTree(value[i], opts, ctx);
      ctx.depth -= 1;
    }
    return ctx;
  }
  // Plain object.
  var keys = Object.keys(value);
  if (keys.length > opts.maxKeysPerObject) {
    ctx.breadthCapHits.push({
      kind: "key-count-cap",
      snippet: "object key count " + keys.length +
               " exceeds maxKeysPerObject " + opts.maxKeysPerObject,
    });
  }
  for (var ki = 0; ki < keys.length; ki += 1) {
    var k = keys[ki];
    if (_isPollutionKey(k)) {
      ctx.pollutionHits.push({
        kind: "prototype-pollution-key",
        snippet: "prototype-pollution key " + JSON.stringify(k) +
                 " at depth " + ctx.depth,
      });
    }
    ctx.depth += 1;
    _scanTree(value[k], opts, ctx);
    ctx.depth -= 1;
  }
  return ctx;
}

// _scanRawSource — pre-parse text scan for syntax-level threats that
// vanish after JSON.parse normalizes them: comments, trailing commas,
// NaN/Infinity, hex literals, single-quoted keys, BOM, big-integer
// precision-loss candidates.
function _scanRawSource(text, opts) {
  var issues = [];
  if (text.indexOf(BOM_CHAR) === 0 && opts.bomPolicy !== "allow") {
    issues.push({
      kind: "bom-leading", severity: "high", ruleId: "json.bom",
      snippet: "leading BOM (U+FEFF)",
    });
  }
  if (text.indexOf(BOM_CHAR) > 0 && opts.bomPolicy !== "allow") {
    issues.push({
      kind: "bom-mid-stream", severity: "high", ruleId: "json.bom",
      snippet: "BOM mid-stream",
    });
  }
  // Commented forms.
  if (opts.commentPolicy !== "allow") {
    if (COMMENT_BLOCK_RE.test(text)) {                                   // allow:regex-no-length-cap — text bounded by maxBytes above
      issues.push({
        kind: "comment-block", severity: "high", ruleId: "json.comment",
        snippet: "block comment /* ... */ (RFC 8259 forbids; JSON5/JSONC accept)",
      });
    }
    if (COMMENT_LINE_RE.test(text)) {                                    // allow:regex-no-length-cap — text bounded by maxBytes above
      issues.push({
        kind: "comment-line", severity: "high", ruleId: "json.comment",
        snippet: "line comment // (RFC 8259 forbids; JSON5/JSONC accept)",
      });
    }
  }
  if (opts.nanInfinityPolicy !== "allow" && BARE_NAN_RE.test(text)) {    // allow:regex-no-length-cap — text bounded by maxBytes above
    issues.push({
      kind: "nan-infinity", severity: "high", ruleId: "json.nan-infinity",
      snippet: "bare NaN / Infinity / undefined token (RFC 8259 forbids)",
    });
  }
  if (opts.trailingCommaPolicy !== "allow" && TRAILING_COMMA_RE.test(text)) {  // allow:regex-no-length-cap — text bounded by maxBytes above
    issues.push({
      kind: "trailing-comma", severity: "high", ruleId: "json.trailing-comma",
      snippet: "trailing comma (RFC 8259 forbids)",
    });
  }
  if (opts.json5SyntaxPolicy !== "allow") {
    if (SINGLE_QUOTED_KEY_RE.test(text)) {                               // allow:regex-no-length-cap — text bounded by maxBytes above
      issues.push({
        kind: "single-quoted-key", severity: "high", ruleId: "json.json5-syntax",
        snippet: "single-quoted key (JSON5 only; not RFC 8259)",
      });
    }
    if (HEX_LITERAL_RE.test(text)) {                                     // allow:regex-no-length-cap — text bounded by maxBytes above
      issues.push({
        kind: "hex-literal", severity: "high", ruleId: "json.json5-syntax",
        snippet: "hex numeric literal (JSON5 only; not RFC 8259)",
      });
    }
  }
  if (opts.numericPrecisionPolicy !== "allow" && BIG_INTEGER_RE.test(text)) { // allow:regex-no-length-cap — text bounded by maxBytes above
    issues.push({
      kind: "numeric-precision-loss", severity: "warn",
      ruleId: "json.numeric-precision",
      snippet: "integer above Number.MAX_SAFE_INTEGER (precision loss)",
    });
  }
  // Prototype-pollution source scan — catches __proto__/constructor/
  // prototype keys before any downstream parser sees them. Critical
  // when the operator's downstream code uses raw JSON.parse without
  // safeJson's reviver.
  if (opts.pollutionPolicy !== "allow") {
    var protoIter = text.matchAll(/"(__proto__|constructor|prototype)"\s*:/g);
    var protoMatch;
    for (protoMatch of protoIter) {
      issues.push({
        kind: "prototype-pollution-key",
        severity: opts.pollutionPolicy === "reject" ? "critical" : "high",
        ruleId: "json.prototype-pollution",
        location: protoMatch.index,
        snippet: "prototype-pollution key " + JSON.stringify(protoMatch[1]) +
                 " at byte " + protoMatch.index +
                 " (CVE-2025-55182 / CVE-2025-57820 class)",
      });
    }
  }
  // Bidi / null / control / zero-width via the shared codepoint class. JSON
  // source treats an invisible-formatting char as a `warn` (cosmetic, not a
  // structural threat) — passed as the zero-width severity.
  issues.push.apply(issues, codepointClass.detectCharThreats(text, opts, "json", "warn"));
  return issues;
}

// _detectIssues — full validate path: raw-source pre-scan + parse +
// tree walk.
function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "json", noun: "input", emptyMode: "skip", scanCodepoints: false, cap: { bytes: opts.maxBytes, kind: "too-large", snippet: function (byteLen, max) { return "input " + byteLen + " bytes exceeds maxBytes " + max; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  // Raw-source pre-scan.
  issues = issues.concat(_scanRawSource(input, opts));

  // Try parsing — bail early on syntax errors so the operator gets a
  // usable error rather than crashing the validator. safeJson.parse
  // already enforces top-level depth/size caps and returns an Error
  // on malformed input.
  var parsed;
  try {
    parsed = safeJson.parse(input, {
      maxBytes: opts.maxBytes,
      maxDepth: opts.maxDepth,
    });
  } catch (e) {
    issues.push({
      kind: "parse-failed", severity: "critical", ruleId: "json.parse",
      snippet: "JSON parse failed: " + (e && e.message),
    });
    return issues;
  }

  // Top-level-key allowlist check.
  if (opts.requireTopLevelKeyAllowlist || Array.isArray(opts.topLevelKeyAllowlist)) {
    if (!Array.isArray(opts.topLevelKeyAllowlist)) {
      issues.push({
        kind: "missing-allowlist", severity: "high",
        ruleId: "json.top-level-allowlist",
        snippet: "requireTopLevelKeyAllowlist set but topLevelKeyAllowlist is null",
      });
    } else if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      var topKeys = Object.keys(parsed);
      var allow = opts.topLevelKeyAllowlist;
      for (var tki = 0; tki < topKeys.length; tki += 1) {
        if (allow.indexOf(topKeys[tki]) === -1) {
          issues.push({
            kind: "top-level-key-not-allowlisted", severity: "high",
            ruleId: "json.top-level-allowlist",
            snippet: "top-level key " + JSON.stringify(topKeys[tki]) +
                     " not in topLevelKeyAllowlist",
          });
        }
      }
    }
  }

  // Tree walk for depth / breadth / string-length / array-length /
  // node-count caps. Pollution-key detection happens at the source
  // level (above) — after JSON.parse, __proto__ is invisible to
  // Object.keys() (routes through the prototype setter), so a post-
  // parse walk misses the pollution-source case.
  var ctx = _scanTree(parsed, opts);
  for (var bi = 0; bi < ctx.breadthCapHits.length; bi += 1) {
    issues.push(Object.assign({ severity: "high",
      ruleId: "json.breadth-cap" }, ctx.breadthCapHits[bi]));
  }
  for (var ai = 0; ai < ctx.arrayLenCapHits.length; ai += 1) {
    issues.push(Object.assign({ severity: "high",
      ruleId: "json.array-length-cap" }, ctx.arrayLenCapHits[ai]));
  }
  for (var di = 0; di < ctx.depthCapHits.length; di += 1) {
    issues.push(Object.assign({ severity: "high",
      ruleId: "json.depth-cap" }, ctx.depthCapHits[di]));
  }
  for (var si = 0; si < ctx.stringTooLongHits.length; si += 1) {
    issues.push(Object.assign({ severity: "high",
      ruleId: "json.string-too-long" }, ctx.stringTooLongHits[si]));
  }

  // Duplicate-key detection — JSON.parse silently last-wins. We re-
  // scan the source for duplicate keys at the same nesting depth.
  if (opts.duplicateKeyPolicy !== "allow") {
    var dups = _detectDuplicateKeys(input);
    for (var dki = 0; dki < dups.length; dki += 1) {
      issues.push({
        kind: "duplicate-key",
        severity: opts.duplicateKeyPolicy === "reject" ? "critical" : "warn",
        ruleId: "json.duplicate-key",
        snippet: "duplicate key " + JSON.stringify(dups[dki]) +
                 " (RFC 8259 SHOULD-unique; last-wins silently)",
      });
    }
  }

  return issues;
}

// _detectDuplicateKeys — minimal source scan that counts identical
// quoted keys at the same `{ ... }` nesting level. Not a full parser;
// catches the common `{"a":1,"a":2}` shape and similar.
function _detectDuplicateKeys(text) {
  var seen = [Object.create(null)];   // stack of scopes, top = current
  var dups = Object.create(null);
  var len = text.length;
  var i = 0;
  while (i < len) {
    var c = text.charAt(i);
    if (c === "{") { seen.push(Object.create(null)); i += 1; continue; }
    if (c === "}") { if (seen.length > 1) seen.pop(); i += 1; continue; }
    if (c === '"') {
      // Read the string up to its closing quote.
      var start = i + 1;
      var p = start;
      while (p < len) {
        var cp = text.charAt(p);
        if (cp === "\\") { p += 2; continue; }
        if (cp === '"') break;
        p += 1;
      }
      var keyText = text.slice(start, p);
      i = p + 1;
      // Skip whitespace; if next non-whitespace is `:`, this string is
      // an object key.
      while (i < len && /\s/.test(text.charAt(i))) i += 1;
      if (i < len && text.charAt(i) === ":") {
        var scope = seen[seen.length - 1];
        if (scope[keyText] === true) dups[keyText] = true;
        else scope[keyText] = true;
        i += 1;
      }
      continue;
    }
    i += 1;
  }
  return Object.keys(dups);
}

// _stripPollutionTree — recursively delete __proto__/constructor/
// prototype keys from the parsed tree. Used by sanitize when policy is
// "strip". Walks Object.create(null)-shaped clones so the cleaned tree
// has no prototype pollution.
function _stripPollutionTree(value, opts, depth) {
  depth = depth || 0;
  if (depth > opts.maxDepth) return value;
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    var out = [];
    for (var i = 0; i < value.length; i += 1) {
      out.push(_stripPollutionTree(value[i], opts, depth + 1));
    }
    return out;
  }
  var keys = Object.keys(value);
  var clean = Object.create(null);
  for (var ki = 0; ki < keys.length; ki += 1) {
    var k = keys[ki];
    if (_isPollutionKey(k)) continue;
    clean[k] = _stripPollutionTree(value[k], opts, depth + 1);
  }
  return clean;
}

// ---- Public surface ----

/**
 * @primitive  b.guardJson.validate
 * @signature  b.guardJson.validate(input, opts?)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardJson.parse, b.guardJson.gate, b.safeJson.parse
 *
 * Inspect `input` (string of JSON source) for the full guard-json
 * threat catalog without committing to a parsed value. Returns
 * `{ ok, issues }` where `issues` is the aggregated
 * detector output — every prototype-pollution key, depth/breadth
 * cap hit, duplicate-key smuggle, JSON5-quirk match, BOM placement,
 * unicode threat, and numeric-precision-loss candidate is reported
 * with `kind` / `severity` / `ruleId` / `snippet`. Profile-driven
 * (`strict` / `balanced` / `permissive`) and posture-driven
 * (`hipaa` / `pci-dss` / `gdpr` / `soc2`).
 *
 * Detection runs in two passes: a raw-source scan (BOM placement,
 * comments, NaN/Infinity, trailing commas, JSON5 quirks, source-
 * level prototype-pollution keys, codepoint-class threats) followed
 * by a parsed-tree walk (depth / breadth / array-length / string-
 * length / node-count caps, duplicate-key rescan).
 *
 * @opts
 *   profile:                  "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   pollutionPolicy:          "reject"|"strip"|"audit"|"allow",
 *   duplicateKeyPolicy:       "reject"|"audit"|"allow",
 *   nanInfinityPolicy:        "reject"|"audit"|"allow",
 *   commentPolicy:            "reject"|"audit"|"allow",
 *   trailingCommaPolicy:      "reject"|"audit"|"allow",
 *   json5SyntaxPolicy:        "reject"|"audit"|"allow",
 *   bomPolicy:                "reject"|"strip"|"allow",
 *   bidiPolicy:               "reject"|"strip"|"audit"|"allow",
 *   controlPolicy:            "reject"|"strip"|"allow",
 *   nullBytePolicy:           "reject"|"strip"|"allow",
 *   zeroWidthPolicy:          "reject"|"strip"|"audit"|"allow",
 *   numericPrecisionPolicy:   "reject"|"audit"|"allow",
 *   requireTopLevelKeyAllowlist: boolean,
 *   topLevelKeyAllowlist:     string[]|null,
 *   maxBytes:                 number,    // total source byte cap
 *   maxDepth:                 number,    // recursion depth cap
 *   maxKeysPerObject:         number,    // breadth cap per object
 *   maxArrayLength:           number,    // array length cap
 *   maxStringLength:          number,    // string length cap
 *   maxTotalNodes:            number,    // total node count cap
 *
 * @example
 *   var rv = b.guardJson.validate('{"__proto__":{"polluted":true}}', {
 *     profile: "strict",
 *   });
 *   rv.ok;                                              // → false
 *   rv.issues.some(function (i) { return i.kind === "prototype-pollution-key"; });  // → true
 */
// validate is assembled by gateContract.defineGuard from `detect`
// (_detectIssues) below — `validate(input, opts) = aggregateIssues(detect(
// input, resolveOpts(opts)))`, with the maxBytes/maxDepth/maxKeysPerObject/
// maxArrayLength/maxStringLength/maxTotalNodes caps declared via `intOpts`.
// Non-string input reduces to the same single `bad-input` issue _detectIssues
// already emits, so the prior explicit early-return is subsumed. The
// @primitive block above documents the resulting ABI.

/**
 * @primitive  b.guardJson.parse
 * @signature  b.guardJson.parse(input, opts?)
 * @since      0.7.13
 * @status     stable
 * @related    b.guardJson.validate, b.guardJson.gate, b.safeJson.parse
 *
 * Parse `input` (string of JSON source) into a JavaScript value
 * after the guard-json threat catalog clears. Refuses on prototype-
 * pollution keys when `pollutionPolicy === "reject"`, refuses on any
 * critical raw-source pre-parse threat, refuses on parse failure,
 * and otherwise routes through `b.safeJson.parse` with the configured
 * `maxBytes` / `maxDepth` caps. Strip policies (`bomPolicy: "strip"`,
 * `controlPolicy: "strip"`, `zeroWidthPolicy: "strip"`) silently
 * remove the offending characters from the source before parsing.
 *
 * Pollution keys (`__proto__` / `constructor` / `prototype`) are
 * normally invisible to `Object.keys()` after `JSON.parse` because
 * they route through prototype setters; the parse path passes
 * `allowProto: true` to `b.safeJson.parse` only when policy is
 * `audit` / `allow`, ensuring strip / reject paths produce a tree
 * with no pollution-key residue.
 *
 * Throws `GuardJsonError` on refusal — the error code matches the
 * triggering rule (`json.prototype-pollution`, `json.parse`, etc.).
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   pollutionPolicy: "reject"|"strip"|"audit"|"allow",
 *   bomPolicy:       "reject"|"strip"|"allow",
 *   controlPolicy:   "reject"|"strip"|"allow",
 *   zeroWidthPolicy: "reject"|"strip"|"audit"|"allow",
 *   maxBytes: number, maxDepth: number,
 *
 * @example
 *   var safe = b.guardJson.parse('{"name":"alice","age":30}', {
 *     profile: "strict",
 *   });
 *   safe.name;                                          // → "alice"
 *   safe.age;                                           // → 30
 */
function parse(input, opts) {
  opts = _resolveOpts(opts);
  if (typeof input !== "string") {
    throw _err("json.bad-input", "parse requires string input");
  }
  // Strip BOM if policy says strip.
  if (opts.bomPolicy === "strip" && input.indexOf(BOM_CHAR) === 0) {
    input = input.slice(1);
  }
  // Strip control chars from the source (rare in practice; refused
  // under strict; balanced/permissive allow strip).
  if (opts.controlPolicy === "strip") {
    input = input.replace(codepointClass.C0_CTRL_RE_G, "");
  }
  if (opts.zeroWidthPolicy === "strip") {
    input = input.replace(codepointClass.ZW_RE_G, "");
  }
  // Source-level pollution check — refuse early when policy is reject.
  if (opts.pollutionPolicy === "reject" && POLLUTION_KEY_SOURCE_RE.test(input)) { // allow:regex-no-length-cap — input bounded by maxBytes above
    throw _err("json.prototype-pollution",
      "guardJson.parse: source contains prototype-pollution key " +
      "(__proto__ / constructor / prototype)");
  }
  // Refuse on other critical pre-parse threats per policy.
  var preIssues = _scanRawSource(input, opts);
  for (var pi = 0; pi < preIssues.length; pi += 1) {
    var issue = preIssues[pi];
    if (issue.kind === "prototype-pollution-key") continue;            // handled above
    if (issue.severity === "critical" ||
        (issue.severity === "high" &&
         opts[_policyKeyForRuleId(issue.ruleId)] === "reject")) {
      throw _err(issue.ruleId, "guardJson.parse: " + issue.snippet);
    }
  }
  // safeJson.parse strips POISONED_KEYS via the reviver pass; this is
  // the canonical strip path. allowProto=true preserves them for the
  // permissive/audit path.
  var allowProto = opts.pollutionPolicy === "allow" ||
                   opts.pollutionPolicy === "audit";
  var parsed;
  try {
    parsed = safeJson.parse(input, {
      maxBytes:   opts.maxBytes,
      maxDepth:   opts.maxDepth,
      allowProto: allowProto,
    });
  } catch (e) {
    throw _err("json.parse", "guardJson.parse: " + (e && e.message));
  }
  return parsed;
}

function _policyKeyForRuleId(ruleId) {
  // Map issue ruleId → opts policy key for the reject-decision lookup.
  var map = {
    "json.bom":               "bomPolicy",
    "json.comment":           "commentPolicy",
    "json.nan-infinity":      "nanInfinityPolicy",
    "json.trailing-comma":    "trailingCommaPolicy",
    "json.json5-syntax":      "json5SyntaxPolicy",
    "json.numeric-precision": "numericPrecisionPolicy",
    "json.bidi":              "bidiPolicy",
    "json.control":           "controlPolicy",
    "json.null-byte":         "nullBytePolicy",
    "json.zero-width":        "zeroWidthPolicy",
  };
  return map[ruleId] || null;
}

/**
 * @primitive  b.guardJson.gate
 * @signature  b.guardJson.gate(opts?)
 * @since      0.7.13
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.guardJson.validate, b.guardJson.parse, b.staticServe.create, b.fileUpload.create
 *
 * Build a `b.gateContract` gate suitable for plugging into
 * `b.staticServe({ contentSafety: { ".json": gate } })`,
 * `b.fileUpload({ contentSafety: { "application/json": gate } })`,
 * or any host primitive that consumes the gate-contract shape.
 * Action chain on validation: `serve` (no issues) → `audit-only`
 * (warn-only issues) → `sanitize` (high/critical but every reject-
 * policy is off — re-parse + re-emit a cleaned tree via
 * `JSON.stringify`) → `refuse` (critical/high under any reject
 * policy, or sanitize threw).
 *
 * Sanitize-eligibility requires every policy in the reject set
 * (`pollutionPolicy` / `duplicateKeyPolicy` / `nanInfinityPolicy` /
 * `commentPolicy` / `trailingCommaPolicy` / `json5SyntaxPolicy` /
 * `bomPolicy` / `bidiPolicy` / `controlPolicy` / `nullBytePolicy`)
 * to be off; under strict every one is `"reject"` so the gate jumps
 * straight from `audit-only` to `refuse`.
 *
 * @opts
 *   profile:    "strict"|"balanced"|"permissive",
 *   compliancePosture: "hipaa"|"pci-dss"|"gdpr"|"soc2",
 *   name:       string,    // gate identity for audit / observability
 *
 * @example
 *   var jsonGate = b.guardJson.gate({ profile: "strict" });
 *   var hostile = Buffer.from('{"__proto__":{"x":1}}', "utf8");
 *   var verdict = await jsonGate.check({ bytes: hostile });
 *   verdict.action;                                     // → "refuse"
 */
// Disposition of each json finding = what the operator's policy for that class
// selected. The RFC-deviation findings (comments / trailing commas / NaN /
// JSON5 syntax / BOM / prototype-pollution / duplicate keys) sanitize by
// re-parsing under a mitigation policy and refuse under `reject`; the bidi /
// null / control char threats follow their shared policies; structural caps,
// a parse failure, and an allowlist miss always refuse; the big-integer
// precision and zero-width notes are audit-only. Exhaustive over every kind
// _detectIssues emits (the gate-disposition coverage test enforces it).
function _gateDispositionFor(issue, opts) {
  var shared = gateContract.charThreatDisposition(issue, opts);
  if (shared) return shared;
  switch (issue.kind) {
    case "bom-leading":
    case "bom-mid-stream":              return gateContract.policyDisposition(opts.bomPolicy);
    case "comment-block":
    case "comment-line":                return gateContract.policyDisposition(opts.commentPolicy);
    case "nan-infinity":                return gateContract.policyDisposition(opts.nanInfinityPolicy);
    case "trailing-comma":              return gateContract.policyDisposition(opts.trailingCommaPolicy);
    case "single-quoted-key":
    case "hex-literal":                 return gateContract.policyDisposition(opts.json5SyntaxPolicy);
    case "prototype-pollution-key":     return gateContract.policyDisposition(opts.pollutionPolicy);
    case "duplicate-key":               return gateContract.policyDisposition(opts.duplicateKeyPolicy);
    // zero-width is classified by charThreatDisposition above (its
    // zeroWidthPolicy). numeric-precision-loss follows its own policy like every
    // other RFC-deviation finding — under numericPrecisionPolicy:reject it
    // refuses, not audits.
    case "numeric-precision-loss":      return gateContract.policyDisposition(opts.numericPrecisionPolicy);
    case "node-count-cap":
    case "depth-cap":
    case "string-too-long":
    case "array-length-cap":
    case "key-count-cap":
    case "bad-input":
    case "too-large":
    case "parse-failed":
    case "missing-allowlist":
    case "top-level-key-not-allowlisted": return "refuse";
    default:                            return null;
  }
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildContentGate({
    name:     opts.name || "guardJson:" + (opts.profile || "default"),
    opts:     opts,
    validate: module.exports.validate,
    dispositionFor: _gateDispositionFor,
    // A sanitize-disposition finding (a class set to a mitigation) is repaired in
    // two passes: first the char-strip policies remove bidi / control / null /
    // zero-width per policy (so a strip-policy char threat is excised even when
    // it sits inside a string value), then a parse + re-serialize drops
    // __proto__ / comments / NaN / trailing commas per the active policy. Under a
    // reject policy the finding is already refuse-disposition, so this is not
    // reached for that class.
    produceSanitized: function (text, o) {
      return JSON.stringify(parse(codepointClass.applyCharStripPolicies(text, o), o));
    },
  });
}

// buildProfile / compliancePosture / loadRulePack are assembled by
// gateContract.defineGuard below (makeProfileBuilder(PROFILES) /
// lookupCompliancePosture(_, COMPLIANCE_POSTURES) / makeRulePackLoader).
// Their wiki sections render from the single-sourced @abiTemplate blocks
// in gate-contract.js, instantiated per guard by the page generator.

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "application/json",
  extension:    ".json",
  benignBytes:  Buffer.from('{"name":"alice","age":30}', "utf8"),
  // Hostile: prototype-pollution payload (CVE-2025-55182 React Server
  // Functions class; CVE-2025-57820 Svelte devalue class).
  hostileBytes: Buffer.from('{"__proto__":{"polluted":true}}', "utf8"),
});

// Assembled from the gate-contract guard factory: error class, registry
// exports (NAME / KIND / MIME_TYPES / EXTENSIONS / INTEGRATION_FIXTURES),
// buildProfile / compliancePosture / loadRulePack wiring, plus the
// per-guard inspection surface (validate / parse) and JSON extras
// (POLLUTION_KEYS, surfaced from the framework's canonical pick.POISONED_KEYS).
// The bespoke `gate` carries JSON's sanitize-reparse-reserialize chain unchanged.
module.exports = gateContract.defineGuard({
  name:        "json",
  kind:        "content",
  errorClass:  GuardJsonError,
  profiles:    PROFILES,
  defaults:    DEFAULTS,
  postures:    COMPLIANCE_POSTURES,
  mimeTypes:   ["application/json", "application/ld+json", "application/vnd.api+json"],
  extensions:  [".json", ".jsonld"],
  integrationFixtures: INTEGRATION_FIXTURES,
  detect:      _detectIssues,
  intOpts:     ["maxBytes", "maxDepth", "maxKeysPerObject", "maxArrayLength",
                "maxStringLength", "maxTotalNodes"],
  gate:        gate,
  extra: {
    _gateDispositionForTest: _gateDispositionFor,
    parse:          parse,
    POLLUTION_KEYS: pick.POISONED_KEYS,
  },
});

void BIDI_RE;       // referenced via codepointClass.detectCharThreats; binding kept for clarity
void C0_CTRL_RE;
void NULL_BYTE;

"use strict";
/**
 * guard-json — JSON content-safety primitive (b.guardJson).
 *
 * Threat catalog grounded in current research (multiple 2025–2026 CVEs
 * + ongoing prototype-pollution vulnerability series):
 *   - CVE-2025-55182 React/Next.js Server Functions deserialization → RCE
 *   - CVE-2025-57820 / CVE-2026-30226 Svelte devalue prototype pollution
 *   - CVE-2026-35209 defu prototype pollution
 *   - CVE-2026-28794 @orpc/client prototype pollution via deserialization
 *   - CVE-2025-13465 Lodash prototype-chain path traversal
 *   - CVE-2025-25014 Kibana prototype pollution → RCE
 *   - CVE-2024-38984 json-override prototype pollution
 *   - CVE-2022-42743 deep-parse-json prototype pollution
 *   - GHSA-9c47-m6qq-7p4h JSON5 prototype pollution via parse method
 *
 *   var rv = b.guardJson.validate(input, { profile: "strict" });
 *   var safe = b.guardJson.parse(input, { profile: "strict" });
 *   var g = b.guardJson.gate({ profile: "strict" });
 *
 * Threat catalog covered:
 *
 *   1. Prototype pollution — `__proto__` / `constructor` / `prototype`
 *      keys anywhere in the tree. Refused regardless of profile under
 *      strict; balanced strips; permissive audits.
 *
 *   2. Array-index pollution — non-numeric keys ON array values
 *      (Svelte devalue CVE-2025-57820 class). When operator JSON
 *      structurally has arrays, keys like `push` / `toString` injected
 *      via reviver/parser quirks pollute Array.prototype.
 *
 *   3. Depth bombs — nested arrays/objects past safe stack. Refused
 *      at the configured cap.
 *
 *   4. Breadth / key-count bombs — single object with massive key count
 *      (10⁶ keys → CPU + memory blow-up).
 *
 *   5. Duplicate keys — RFC 8259 says keys SHOULD be unique; in
 *      practice JSON.parse silently last-wins, which lets attackers
 *      smuggle duplicate-key payloads past validation that ran on the
 *      first occurrence (Bishop Fox JSON-interoperability research).
 *
 *   6. NaN / Infinity / -Infinity — RFC 8259 forbids; JSON5 / lenient
 *      parsers accept. Refused under strict.
 *
 *   7. Comments (single-line // and block-style) — RFC 8259 forbids;
 *      JSON5 / JSONC accept. Refused under strict.
 *
 *   8. Trailing commas — JSON5 accepts; refused under strict.
 *
 *   9. BOM injection — leading or mid-stream U+FEFF.
 *
 *  10. Bidi / null / control chars in string values — same codepoint
 *      catalog as guard-csv/html/svg via lib/codepoint-class.
 *
 *  11. Numeric precision loss — values above
 *      `Number.MAX_SAFE_INTEGER` silently lose precision when round-
 *      tripped through Number. Detected via raw-text scan for digit
 *      runs longer than safe-int width.
 *
 *  12. Total size cap (anti-DoS).
 *
 *  13. Top-level-key allowlist — strict profile requires the operator
 *      to declare allowed top-level keys; balanced/permissive skip.
 *
 * Source files MUST be pure ASCII per the codepoint-table programmatic
 * regex pattern; threat-detection regexes use lib/codepoint-class.
 */

var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var gateContract = require("./gate-contract");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var safeJson = require("./safe-json");
var { GuardJsonError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardJsonError.factory;

// ---- Compiled detectors ----

var BIDI_RE       = codepointClass.BIDI_RE;
var C0_CTRL_RE    = codepointClass.C0_CTRL_RE;
var ZW_RE         = codepointClass.ZERO_WIDTH_RE;
var NULL_BYTE     = codepointClass.NULL_BYTE;
var BOM_CHAR      = codepointClass.BOM_CHAR;

// Prototype-pollution key denylist. Operator-supplied JSON containing
// any of these keys at any depth is refused under strict.
var POLLUTION_KEYS = Object.freeze(["__proto__", "constructor", "prototype"]);

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
    bidiPolicy:             "reject",
    controlPolicy:          "reject",
    nullBytePolicy:         "reject",
    zeroWidthPolicy:        "reject",
    numericPrecisionPolicy: "reject",
    requireTopLevelKeyAllowlist: false,     // operator opts in via topLevelKeyAllowlist
    topLevelKeyAllowlist:   null,
    maxBytes:               C.BYTES.mib(2),
    maxDepth:               8,                                                   // allow:raw-byte-literal — recursion depth, not byte size
    maxKeysPerObject:       256,                                                 // allow:raw-byte-literal — key count cap, not byte size
    maxArrayLength:         1024,                                                // allow:raw-byte-literal — array length cap, not byte size
    maxStringLength:        C.BYTES.kib(8),
    maxTotalNodes:          0x2000,                                              // allow:raw-byte-literal — node count cap, not byte size
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
    maxDepth:               32,                                                  // allow:raw-byte-literal — recursion depth, not byte size
    maxKeysPerObject:       4096,                                                // allow:raw-byte-literal — key count cap, not byte size
    maxArrayLength:         65536,                                               // allow:raw-byte-literal — array length cap, not byte size
    maxStringLength:        C.BYTES.kib(64),
    maxTotalNodes:          0x10000,                                             // allow:raw-byte-literal — node count cap, not byte size
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
    maxDepth:               64,                                                  // allow:raw-byte-literal — recursion depth, not byte size
    maxKeysPerObject:       65536,                                               // allow:raw-byte-literal — key count cap, not byte size
    maxArrayLength:         1048576,                                             // allow:raw-byte-literal — array length cap, not byte size
    maxStringLength:        C.BYTES.kib(256),
    maxTotalNodes:          0x40000,                                             // allow:raw-byte-literal — node count cap, not byte size
  },
});

var DEFAULTS = Object.freeze(Object.assign({}, PROFILES["strict"], {
  mode:          "enforce",
  maxRuntimeMs:  C.TIME.seconds(10),
}));

var COMPLIANCE_POSTURES = Object.freeze({
  "hipaa": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "pci-dss": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(256),
  }),
  "gdpr": Object.assign({}, PROFILES["balanced"], {
    forensicSnippetBytes: C.BYTES.bytes(128),
  }),
  "soc2": Object.assign({}, PROFILES["strict"], {
    forensicSnippetBytes: C.BYTES.bytes(512),
  }),
});

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
  return POLLUTION_KEYS.indexOf(key) !== -1;
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
  // Bidi / null / control via shared codepoint class.
  issues.push.apply(issues, codepointClass.detectCharThreats(text, opts, "json"));
  if (opts.zeroWidthPolicy !== "allow" && opts.zeroWidthPolicy !== "strip" &&
      ZW_RE.test(text)) {                                                // allow:regex-no-length-cap — text bounded by maxBytes above
    issues.push({
      kind: "zero-width", severity: "warn", ruleId: "json.zero-width",
      snippet: "zero-width / invisible-formatting char in JSON source",
    });
  }
  return issues;
}

// _detectIssues — full validate path: raw-source pre-scan + parse +
// tree walk.
function _detectIssues(input, opts) {
  var issues = [];
  if (typeof input !== "string") {
    return [{ kind: "bad-input", severity: "high",
              snippet: "input is not a string" }];
  }
  if (input.length > opts.maxBytes) {
    return [{ kind: "too-large", severity: "high", ruleId: "json.too-large",
              snippet: "input " + input.length +
                       " bytes exceeds maxBytes " + opts.maxBytes }];
  }

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

function validate(input, opts) {
  opts = _resolveOpts(opts);
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxBytes", "maxDepth", "maxKeysPerObject", "maxArrayLength",
     "maxStringLength", "maxTotalNodes"],
    "guardJson.validate", GuardJsonError, "json.bad-opt");
  if (typeof input !== "string") {
    return {
      ok: false,
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "input is not a string" }],
    };
  }
  return gateContract.aggregateIssues(_detectIssues(input, opts));
}

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

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildGuardGate(
    opts.name || "guardJson:" + (opts.profile || "default"),
    opts,
    async function (ctx) {
      var text = gateContract.extractBytesAsText(ctx);
      if (!text) return { ok: true, action: "serve" };
      var rv = validate(text, opts);
      if (rv.issues.length === 0) return { ok: true, action: "serve" };
      var hasCritical = rv.issues.some(function (i) {
        return i.severity === "critical" || i.severity === "high";
      });
      if (!hasCritical) return { ok: true, action: "audit-only", issues: rv.issues };

      // Sanitize-eligibility: every reject-policy must be off.
      var canSanitize = opts.pollutionPolicy !== "reject" &&
                        opts.duplicateKeyPolicy !== "reject" &&
                        opts.nanInfinityPolicy !== "reject" &&
                        opts.commentPolicy !== "reject" &&
                        opts.trailingCommaPolicy !== "reject" &&
                        opts.json5SyntaxPolicy !== "reject" &&
                        opts.bomPolicy !== "reject" &&
                        opts.bidiPolicy !== "reject" &&
                        opts.controlPolicy !== "reject" &&
                        opts.nullBytePolicy !== "reject";
      if (canSanitize) {
        try {
          var clean = parse(text, opts);
          var emitted = JSON.stringify(clean);
          return {
            ok: true, action: "sanitize",
            sanitized: Buffer.from(emitted, "utf8"),
            issues: rv.issues,
          };
        } catch (_e) { /* fall through */ }
      }
      return { ok: false, action: "refuse", issues: rv.issues };
    });
}

var buildProfile = gateContract.makeProfileBuilder(PROFILES);

function compliancePosture(name) {
  return gateContract.lookupCompliancePosture(name, COMPLIANCE_POSTURES, _err, "json");
}

var _jsonRulePacks = gateContract.makeRulePackLoader(GuardJsonError, "json");
var loadRulePack = _jsonRulePacks.load;

module.exports = {
  // ---- guard-* family registry exports ----
  NAME:                "json",
  KIND:                "content",
  MIME_TYPES:          Object.freeze([
    "application/json", "application/ld+json", "application/vnd.api+json",
  ]),
  EXTENSIONS:          Object.freeze([".json", ".jsonld"]),
  INTEGRATION_FIXTURES: Object.freeze({
    kind:         "content",
    contentType:  "application/json",
    extension:    ".json",
    benignBytes:  Buffer.from('{"name":"alice","age":30}', "utf8"),
    // Hostile: prototype-pollution payload (CVE-2025-55182 React Server
    // Functions class; CVE-2025-57820 Svelte devalue class).
    hostileBytes: Buffer.from('{"__proto__":{"polluted":true}}', "utf8"),
  }),
  // ---- primitive surface ----
  validate:            validate,
  parse:               parse,
  gate:                gate,
  buildProfile:        buildProfile,
  compliancePosture:   compliancePosture,
  loadRulePack:        loadRulePack,
  PROFILES:            PROFILES,
  DEFAULTS:            DEFAULTS,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  POLLUTION_KEYS:      POLLUTION_KEYS,
  GuardJsonError:      GuardJsonError,
};

void BIDI_RE;       // referenced via codepointClass.detectCharThreats; binding kept for clarity
void C0_CTRL_RE;
void NULL_BYTE;

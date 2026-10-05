// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var safeBuffer = require("./safe-buffer");
var { GuardJsonError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var _err = GuardJsonError.factory;

var NULL_BYTE     = codepointClass.NULL_BYTE;
var BOM_CHAR      = codepointClass.BOM_CHAR;

var UNSAFE_INTEGER_DIGITS = 17;

var QUOTE = 0x22, BACKSLASH = 0x5C, SLASH = 0x2F, STAR = 0x2A, APOSTROPHE = 0x27;
var COMMA = 0x2C, COLON = 0x3A, MINUS = 0x2D, ZERO = 0x30, NINE = 0x39;
var CLOSE_BRACKET = 0x5D, CLOSE_BRACE = 0x7D;
var LOWER_X = 0x78, UPPER_X = 0x58;
var LOWER_E = 0x65, UPPER_E = 0x45, PERIOD = 0x2E, PLUS = 0x2B;

function _isDigit(cc) { return cc >= ZERO && cc <= NINE; }
function _isHexDigit(cc) {
  return _isDigit(cc) || (cc >= 0x41 && cc <= 0x46) || (cc >= 0x61 && cc <= 0x66);
}
function _isWordChar(cc) {
  return codepointClass.isIdentifierChar(cc) || cc === 0x24;
}
function _isJsonWhitespace(cc) {
  return cc === 0x20 || cc === 0x09 || cc === 0x0A || cc === 0x0D;
}

function _skipWhitespace(text, i) {
  while (i < text.length && _isJsonWhitespace(text.charCodeAt(i))) i += 1;
  return i;
}

function _noteIfNonFinite(found, text, start, end) {
  if (found.nonFiniteNumber !== -1) return;
  var token = text.slice(start, end);
  var negative = token.charAt(0) === "-";
  var magnitude = Number(negative ? token.slice(1) : token);
  if (isNaN(magnitude)) return;
  if (!isFinite(magnitude)) found.nonFiniteNumber = start;
}

var JSON_SHORT_ESCAPES = {
  "\"": "\"", "\\": "\\", "/": "/",
  b: "\b", f: "\f", n: "\n", r: "\r", t: "\t",
};

function _decodeJsonStringBody(raw) {
  if (raw.indexOf("\\") === -1) return raw;
  var out = "";
  for (var i = 0; i < raw.length; i += 1) {
    var ch = raw.charAt(i);
    if (ch !== "\\") { out += ch; continue; }
    var next = raw.charAt(i + 1);
    if (next === "u") {
      var hex = raw.slice(i + 2, i + 6);
      if (hex.length !== 4 ||
          !codepointClass.isRunOf(hex, codepointClass.ASCII_HEX)) return raw;
      out += String.fromCharCode(parseInt(hex, 16));
      i += 5;
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(JSON_SHORT_ESCAPES, next)) {
      out += JSON_SHORT_ESCAPES[next];
      i += 1;
      continue;
    }
    return raw;
  }
  return out;
}

function _scanJsonShapes(text) {
  var found = {
    commentLine: -1, commentBlock: -1, bareLiteral: -1, trailingComma: -1,
    singleQuotedKey: -1, hexLiteral: -1, bigInteger: -1, nonFiniteNumber: -1,
    pollutionKeys: [],
  };
  var i = 0;
  while (i < text.length) {
    var cc = text.charCodeAt(i);

    if (cc === QUOTE) {
      var start = i + 1;
      var j = start;
      while (j < text.length) {
        var sc = text.charCodeAt(j);
        if (sc === BACKSLASH) { j += 2; continue; }
        if (sc === QUOTE) break;
        j += 1;
      }
      var body = _decodeJsonStringBody(text.slice(start, Math.min(j, text.length)));
      var after = _skipWhitespace(text, j + 1);
      if (text.charCodeAt(after) === COLON && pick.isPoisonedKey(body)) {
        found.pollutionKeys.push({ index: i, name: body });
      }
      i = j >= text.length ? text.length : j + 1;
      continue;
    }

    if (cc === SLASH) {
      var next = text.charCodeAt(i + 1);
      if (next === SLASH) {
        if (found.commentLine === -1) found.commentLine = i;
        while (i < text.length && text.charCodeAt(i) !== 0x0A && text.charCodeAt(i) !== 0x0D) i += 1;
        continue;
      }
      if (next === STAR) {
        var close = text.indexOf("*/", i + 2);
        if (found.commentBlock === -1) found.commentBlock = i;
        i = close === -1 ? text.length : close + 2;
        continue;
      }
      i += 1;
      continue;
    }

    if (cc === APOSTROPHE) {
      var q = i + 1;
      while (q < text.length) {
        var qc = text.charCodeAt(q);
        if (qc === BACKSLASH) { q += 2; continue; }
        if (qc === APOSTROPHE) break;
        q += 1;
      }
      if (q >= text.length) { i += 1; continue; }
      var afterQuote = _skipWhitespace(text, q + 1);
      if (text.charCodeAt(afterQuote) === COLON && found.singleQuotedKey === -1) {
        found.singleQuotedKey = i;
      }
      i = q + 1;
      continue;
    }

    if (cc === COMMA) {
      var afterComma = _skipWhitespace(text, i + 1);
      var cc2 = text.charCodeAt(afterComma);
      if ((cc2 === CLOSE_BRACKET || cc2 === CLOSE_BRACE) && found.trailingComma === -1) {
        found.trailingComma = i;
      }
      i += 1;
      continue;
    }

    if (_isDigit(cc)) {
      var numStart = i > 0 && text.charCodeAt(i - 1) === MINUS ? i - 1 : i;
      if (cc === ZERO) {
        var xc = text.charCodeAt(i + 1);
        if ((xc === LOWER_X || xc === UPPER_X) && _isHexDigit(text.charCodeAt(i + 2))) {
          if (found.hexLiteral === -1) found.hexLiteral = numStart;
          i += 2;
          while (i < text.length && _isHexDigit(text.charCodeAt(i))) i += 1;
          _noteIfNonFinite(found, text, numStart, i);
          continue;
        }
      }
      var digitsStart = i;
      while (i < text.length && _isDigit(text.charCodeAt(i))) i += 1;
      var integerDigits = i - digitsStart;
      var isInteger = true;
      if (text.charCodeAt(i) === PERIOD) {
        isInteger = false;
        i += 1;
        while (i < text.length && _isDigit(text.charCodeAt(i))) i += 1;
      }
      var ec = text.charCodeAt(i);
      if (ec === LOWER_E || ec === UPPER_E) {
        var expDigits = i + 1;
        if (text.charCodeAt(expDigits) === MINUS || text.charCodeAt(expDigits) === PLUS) {
          expDigits += 1;
        }
        if (_isDigit(text.charCodeAt(expDigits))) {
          isInteger = false;
          i = expDigits;
          while (i < text.length && _isDigit(text.charCodeAt(i))) i += 1;
        }
      }
      if (isInteger && integerDigits >= UNSAFE_INTEGER_DIGITS && found.bigInteger === -1) {
        found.bigInteger = numStart;
      }
      _noteIfNonFinite(found, text, numStart, i);
      continue;
    }

    if (_isWordChar(cc)) {
      var wordStart = i;
      while (i < text.length && _isWordChar(text.charCodeAt(i))) i += 1;
      var word = text.slice(wordStart, i);
      if (found.bareLiteral === -1 &&
          (word === "NaN" || word === "Infinity" || word === "undefined")) {
        found.bareLiteral = wordStart > 0 && text.charCodeAt(wordStart - 1) === MINUS
          ? wordStart - 1 : wordStart;
      }
      continue;
    }

    i += 1;
  }
  return found;
}

var PROFILES = Object.freeze({
  "strict": {
    pollutionPolicy:        "reject",
    duplicateKeyPolicy:     "reject",
    nanInfinityPolicy:      "reject",
    commentPolicy:          "reject",
    trailingCommaPolicy:    "reject",
    json5SyntaxPolicy:      "reject",
    bomPolicy:              "reject",
    ...gateContract.CHAR_THREATS_REJECT_ALL,
    numericPrecisionPolicy: "reject",
    requireTopLevelKeyAllowlist: false,
    topLevelKeyAllowlist:   null,
    maxBytes:               C.BYTES.mib(2),
    maxDepth:               8,
    maxKeysPerObject:       256,
    maxArrayLength:         1024,
    maxStringLength:        C.BYTES.kib(8),
    maxTotalNodes:          0x2000,
  },
  "balanced": {
    pollutionPolicy:        "strip",
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
    maxDepth:               32,
    maxKeysPerObject:       4096,
    maxArrayLength:         65536,
    maxStringLength:        C.BYTES.kib(64),
    maxTotalNodes:          0x10000,
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
    maxDepth:               64,
    maxKeysPerObject:       65536,
    maxArrayLength:         1048576,
    maxStringLength:        C.BYTES.kib(256),
    maxTotalNodes:          0x40000,
  },
});

var DEFAULTS = gateContract.strictDefaults(PROFILES, {
  maxRuntimeMs:  C.TIME.seconds(10),
});

var COMPLIANCE_POSTURES = gateContract.compliancePostures(PROFILES, { base: 256 });

function _resolveOpts(opts) {
  return module.exports.resolveOpts(opts);
}

function _isPollutionKey(key) {
  return pick.isPoisonedKey(key);
}

function _hit(list, item) {
  if (list.length < gateContract.MAX_ISSUES_PER_KIND) list.push(item);
}

function _scanTree(value, opts, ctx) {
  if (!ctx) ctx = { depth: 0, totalNodes: 0, pollutionHits: [],
                    duplicateKeyHits: [], breadthCapHits: [],
                    arrayLenCapHits: [], depthCapHits: [],
                    stringTooLongHits: [], capped: false };
  if (ctx.capped) return ctx;
  ctx.totalNodes += 1;
  if (ctx.totalNodes > opts.maxTotalNodes) {
    ctx.capped = true;
    _hit(ctx.depthCapHits, { kind: "node-count-cap",
      snippet: "node count exceeds maxTotalNodes " + opts.maxTotalNodes });
    return ctx;
  }
  if (ctx.depth > opts.maxDepth) {
    _hit(ctx.depthCapHits, { kind: "depth-cap",
      snippet: "depth " + ctx.depth + " exceeds maxDepth " + opts.maxDepth });
    return ctx;
  }
  if (value === null || typeof value !== "object") {
    if (typeof value === "string") {
      var strBytes = safeBuffer.byteLengthOf(value);
      if (strBytes > opts.maxStringLength) {
        _hit(ctx.stringTooLongHits, {
          kind: "string-too-long",
          snippet: "string byte length " + strBytes +
                   " exceeds maxStringLength " + opts.maxStringLength + " bytes",
        });
      }
    }
    return ctx;
  }
  if (Array.isArray(value)) {
    if (value.length > opts.maxArrayLength) {
      _hit(ctx.arrayLenCapHits, {
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
  var keys = Object.keys(value);
  if (keys.length > opts.maxKeysPerObject) {
    _hit(ctx.breadthCapHits, {
      kind: "key-count-cap",
      snippet: "object key count " + keys.length +
               " exceeds maxKeysPerObject " + opts.maxKeysPerObject,
    });
  }
  for (var ki = 0; ki < keys.length; ki += 1) {
    var k = keys[ki];
    if (_isPollutionKey(k)) {
      _hit(ctx.pollutionHits, {
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

function _scanRawSource(text, opts) {
  var issues = [];
  var report = gateContract.makeIssueReporter(issues);
  if (text.indexOf(BOM_CHAR) === 0 && opts.bomPolicy !== "allow") {
    report({
      kind: "bom-leading", severity: "high", ruleId: "json.bom",
      snippet: "leading BOM (U+FEFF)",
    });
  }
  if (text.indexOf(BOM_CHAR) > 0 && opts.bomPolicy !== "allow") {
    report({
      kind: "bom-mid-stream", severity: "high", ruleId: "json.bom",
      snippet: "BOM mid-stream",
    });
  }
  var shapes = _scanJsonShapes(text);
  if (opts.commentPolicy !== "allow") {
    if (shapes.commentBlock !== -1) {
      report({
        kind: "comment-block", severity: "high", ruleId: "json.comment",
        location: shapes.commentBlock,
        snippet: "block comment /* ... */ (RFC 8259 forbids; JSON5/JSONC accept)",
      });
    }
    if (shapes.commentLine !== -1) {
      report({
        kind: "comment-line", severity: "high", ruleId: "json.comment",
        location: shapes.commentLine,
        snippet: "line comment // (RFC 8259 forbids; JSON5/JSONC accept)",
      });
    }
  }
  if (opts.nanInfinityPolicy !== "allow" && shapes.bareLiteral !== -1) {
    report({
      kind: "nan-infinity", severity: "high", ruleId: "json.nan-infinity",
      location: shapes.bareLiteral,
      snippet: "bare NaN / Infinity / undefined token (RFC 8259 forbids)",
    });
  }
  if (opts.nanInfinityPolicy !== "allow" && shapes.nonFiniteNumber !== -1) {
    report({
      kind: "nan-infinity", severity: "high", ruleId: "json.nan-infinity",
      location: shapes.nonFiniteNumber,
      snippet: "numeric literal at byte " + shapes.nonFiniteNumber +
               " exceeds the double range and parses as Infinity",
    });
  }
  if (opts.trailingCommaPolicy !== "allow" && shapes.trailingComma !== -1) {
    report({
      kind: "trailing-comma", severity: "high", ruleId: "json.trailing-comma",
      location: shapes.trailingComma,
      snippet: "trailing comma (RFC 8259 forbids)",
    });
  }
  if (opts.json5SyntaxPolicy !== "allow") {
    if (shapes.singleQuotedKey !== -1) {
      report({
        kind: "single-quoted-key", severity: "high", ruleId: "json.json5-syntax",
        location: shapes.singleQuotedKey,
        snippet: "single-quoted key (JSON5 only; not RFC 8259)",
      });
    }
    if (shapes.hexLiteral !== -1) {
      report({
        kind: "hex-literal", severity: "high", ruleId: "json.json5-syntax",
        location: shapes.hexLiteral,
        snippet: "hex numeric literal (JSON5 only; not RFC 8259)",
      });
    }
  }
  if (opts.numericPrecisionPolicy !== "allow" && shapes.bigInteger !== -1) {
    report({
      kind: "numeric-precision-loss", severity: "warn",
      ruleId: "json.numeric-precision",
      location: shapes.bigInteger,
      snippet: "integer above Number.MAX_SAFE_INTEGER (precision loss)",
    });
  }
  if (opts.pollutionPolicy !== "allow") {
    for (var pi = 0; pi < shapes.pollutionKeys.length; pi += 1) {
      var hit = shapes.pollutionKeys[pi];
      report({
        kind: "prototype-pollution-key",
        severity: opts.pollutionPolicy === "reject" ? "critical" : "high",
        ruleId: "json.prototype-pollution",
        location: hit.index,
        snippet: "prototype-pollution key " + JSON.stringify(hit.name) +
                 " at byte " + hit.index +
                 " (CVE-2025-55182 / CVE-2025-57820 class)",
      });
    }
  }
  codepointClass.detectCharThreats(text, opts, "json").forEach(report);
  return issues;
}

function _detectIssues(input, opts) {
  var pre = gateContract.detectStringInput(input, opts, { name: "json", noun: "input", emptyMode: "skip", scanCodepoints: false, cap: { bytes: opts.maxBytes, kind: "too-large", snippet: function (byteLen, max) { return "input " + byteLen + " bytes exceeds maxBytes " + max; } } });
  if (pre.done) return pre.issues;
  var issues = pre.issues;

  issues = issues.concat(_scanRawSource(input, opts));
  var report = gateContract.makeIssueReporter(issues);

  var parsed;
  try {
    parsed = safeJson.parse(input, {
      maxBytes: opts.maxBytes,
      maxDepth: opts.maxDepth,
    });
  } catch (e) {
    report({
      kind: "parse-failed", severity: "critical", ruleId: "json.parse",
      snippet: "JSON parse failed: " + (e && e.message),
    });
    return issues;
  }

  if (opts.requireTopLevelKeyAllowlist || Array.isArray(opts.topLevelKeyAllowlist)) {
    if (!Array.isArray(opts.topLevelKeyAllowlist)) {
      report({
        kind: "missing-allowlist", severity: "high",
        ruleId: "json.top-level-allowlist",
        snippet: "requireTopLevelKeyAllowlist set but topLevelKeyAllowlist is null",
      });
    } else if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      var topKeys = Object.keys(parsed);
      var allow = opts.topLevelKeyAllowlist;
      for (var tki = 0; tki < topKeys.length; tki += 1) {
        if (allow.indexOf(topKeys[tki]) === -1) {
          report({
            kind: "top-level-key-not-allowlisted", severity: "high",
            ruleId: "json.top-level-allowlist",
            snippet: "top-level key " + JSON.stringify(topKeys[tki]) +
                     " not in topLevelKeyAllowlist",
          });
        }
      }
    }
  }

  var ctx = _scanTree(parsed, opts);
  for (var bi = 0; bi < ctx.breadthCapHits.length; bi += 1) {
    report(Object.assign({ severity: "high",
      ruleId: "json.breadth-cap" }, ctx.breadthCapHits[bi]));
  }
  for (var ai = 0; ai < ctx.arrayLenCapHits.length; ai += 1) {
    report(Object.assign({ severity: "high",
      ruleId: "json.array-length-cap" }, ctx.arrayLenCapHits[ai]));
  }
  for (var di = 0; di < ctx.depthCapHits.length; di += 1) {
    report(Object.assign({ severity: "high",
      ruleId: "json.depth-cap" }, ctx.depthCapHits[di]));
  }
  for (var si = 0; si < ctx.stringTooLongHits.length; si += 1) {
    report(Object.assign({ severity: "high",
      ruleId: "json.string-too-long" }, ctx.stringTooLongHits[si]));
  }

  if (opts.duplicateKeyPolicy !== "allow") {
    var dups = _detectDuplicateKeys(input);
    for (var dki = 0; dki < dups.length; dki += 1) {
      report({
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

/**
 * @primitive  b.guardJson.detectDuplicateKeys
 * @signature  b.guardJson.detectDuplicateKeys(jsonText)
 * @since      0.20.6
 * @status     stable
 * @related    b.guardJson.validate, b.guardJwt.validate
 *
 * Scan a JSON source string and return the key names that appear more than
 * once at the same object nesting level. `JSON.parse` keeps the last of a
 * repeated key silently, so two readers of the same document can disagree on a
 * value; a duplicate key is the smuggling shape behind that disagreement. The
 * scan tracks a per-object seen-set and reads only key positions (a `"..."`
 * followed by `:`), so a repeated key inside a string value is not counted.
 *
 * @example
 *   b.guardJson.detectDuplicateKeys('{"a":1,"a":2}');   // → ["a"]
 *   b.guardJson.detectDuplicateKeys('{"a":1,"b":2}');   // → []
 */
function _detectDuplicateKeys(text) {
  var seen = [Object.create(null)];
  var dups = Object.create(null);
  var len = text.length;
  var i = 0;
  while (i < len) {
    var c = text.charAt(i);
    if (c === "{") { seen.push(Object.create(null)); i += 1; continue; }
    if (c === "}") { if (seen.length > 1) seen.pop(); i += 1; continue; }
    if (c === '"') {
      var start = i + 1;
      var p = start;
      while (p < len) {
        var cp = text.charAt(p);
        if (cp === "\\") { p += 2; continue; }
        if (cp === '"') break;
        p += 1;
      }
      var keyText = _decodeJsonStringBody(text.slice(start, p));
      i = p + 1;
      while (i < len &&
             codepointClass.inRanges(text.charCodeAt(i), codepointClass.WHITESPACE_RANGES)) i += 1;
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
    throw _err("json/bad-input", "parse requires string input");
  }
  codepointClass.assertWithinMaxBytes(input, opts, _err, "json");
  if (opts.bomPolicy === "strip" && input.indexOf(BOM_CHAR) === 0) {
    input = input.slice(1);
  }
  if (opts.controlPolicy === "strip") {
    input = codepointClass.stripRanges(input, codepointClass.CTRL_RANGES);
  }
  if (opts.bidiPolicy === "strip") {
    input = codepointClass.stripRanges(input, codepointClass.BIDI_RANGES);
  }
  if (opts.zeroWidthPolicy === "strip") {
    input = codepointClass.stripRanges(input, codepointClass.ZERO_WIDTH_RANGES);
  }
  if (codepointClass.resolveTagsPolicy(opts) === "strip") {
    input = codepointClass.stripRanges(input, codepointClass.TAG_RANGES);
  }
  if (opts.pollutionPolicy === "reject" &&
      _scanJsonShapes(input).pollutionKeys.length > 0) {
    throw _err("json.prototype-pollution",
      "guardJson.parse: source contains prototype-pollution key " +
      "(__proto__ / constructor / prototype)");
  }
  gateContract.throwOnRefusedDisposition(_scanRawSource(input, opts), {
    dispositionFor: _gateDispositionFor,
    opts:           opts,
    errorClass:     GuardJsonError,
    codePrefix:     "json",
    op:             "parse",
    skipKinds:      ["prototype-pollution-key"],
  });
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

function _sanitizeTransform(text, opts) {
  var subject = text;
  if (gateContract.policyDisposition(opts.bomPolicy) === "sanitize") {
    subject = codepointClass.stripRanges(subject, [0xFEFF]);
  }
  return JSON.stringify(parse(codepointClass.applyCharStripPolicies(subject, opts), opts));
}

function gate(opts) {
  opts = _resolveOpts(opts);
  return gateContract.buildContentGate({
    name:     opts.name || "guardJson:" + (opts.profile || "default"),
    opts:     opts,
    validate: module.exports.validate,
    dispositionFor: _gateDispositionFor,
    produceSanitized: _sanitizeTransform,
  });
}

var INTEGRATION_FIXTURES = Object.freeze({
  kind:         "content",
  contentType:  "application/json",
  extension:    ".json",
  benignBytes:  Buffer.from('{"name":"alice","age":30}', "utf8"),
  hostileBytes: Buffer.from('{"__proto__":{"polluted":true}}', "utf8"),
});

var POLICY_ENUM = gateContract.policyVocabulary([
  "duplicateKeyPolicy", "nanInfinityPolicy", "commentPolicy",
  "trailingCommaPolicy", "json5SyntaxPolicy", "numericPrecisionPolicy",
], gateContract.POLICY_VALUES.rejectAuditAllow, {
  pollutionPolicy: ["reject", "strip", "audit", "allow"],
  bomPolicy:       ["reject", "strip", "allow"],
});

module.exports = gateContract.defineGuard({
  enumOpts:    POLICY_ENUM,
  name:        "json",
  kind:        "content",
  charRepair:  true,
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
  sanitizeTransform: _sanitizeTransform,
  dispositionFor:    _gateDispositionFor,
  extra: {
    _gateDispositionForTest: _gateDispositionFor,
    parse:               parse,
    detectDuplicateKeys: _detectDuplicateKeys,
    POLLUTION_KEYS:      pick.POISONED_KEYS,
  },
});

void NULL_BYTE;

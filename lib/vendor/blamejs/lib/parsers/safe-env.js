// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Security-focused .env loader.
 *
 * Parses dotenv-style files with the framework's standard guards plus
 * change tracking and typo detection — env-var changes are
 * operationally significant and the framework records them through the
 * audit chain.
 *
 * The dotenv ecosystem has a long history of subtle footguns: implicit
 * `$VAR` expansion that surprises consumers reading process.env later,
 * silent overwrite of operator-set values, ambiguous quote handling
 * across libraries, comment-vs-value confusion. This loader rejects or
 * makes explicit each of those.
 *
 * Public API:
 *   env.parse(input, opts?)            object | throws SafeEnvError
 *   env.load(filepath, opts?)          { values, diff } | throws
 *   env.SafeEnvError                   error class
 *
 * env.parse returns the bare key/value object — pure, no I/O, no
 * audit, no schema. Use it when you have the file content already in
 * memory or when you want to compose `.env` parsing into a larger flow.
 *
 * env.load reads the file via atomicFile.readSync, applies schema
 * validation, computes a diff against the previous snapshot, optionally
 * applies values to process.env, and writes a system.config.changed
 * audit row when the diff is non-empty. Followers in cluster mode see
 * their own config; the audit write is leader-gated and is silently
 * skipped on followers (their own audit row would have nothing to
 * anchor to anyway since they don't write the chain).
 *
 * What is REJECTED:
 *   - Tabs at start of value (real spaces are fine; tabs in unquoted
 *     values are almost always a copy-paste accident)
 *   - $VAR / ${VAR} expansion (consumers reading process.env later
 *     would not know whether the value was literal or expanded —
 *     consistency over convenience). Operators who want expansion
 *     can do it themselves before passing values to the framework.
 *   - Multiline unquoted values (you must double-quote a value
 *     containing newlines). Common dotenv libraries auto-join lines;
 *     the heuristic regularly produces wrong results.
 *   - Keys outside `^[A-Z_][A-Z0-9_]*$` by default (POSIX env-var
 *     shape). Operators can override via `{ keyShape: /…/ }`.
 *   - Empty key (`=value` with no key)
 *
 * Defaults:
 *   maxBytes:        64 KiB        (.env files are config; cap is small)
 *   maxKeys:         1000
 *   keyShape:        /^[A-Z_][A-Z0-9_]*$/
 *   applyToProcess:  false         (return values; do not mutate process.env)
 *   allowOverwrite:  false         (only relevant when applyToProcess: true)
 *   rejectUnknown:   false         (warn on unregistered keys; do not refuse)
 *   audit:           true          (record diff in audit chain)
 */

var C = require("../constants");
var pick = require("../pick");
var boundedMap = require("../bounded-map");
var atomicFile = require("../atomic-file");
var lazyRequire = require("../lazy-require");
var numericBounds = require("../numeric-bounds");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var codepointClass = require("../codepoint-class");
var { FrameworkError } = require("../framework-error");
var { boot } = require("../log");

// Lazy require for audit — eager-loading audit at top of file forms a
// load cycle: vault.init → passphrase-source → safe-env → audit →
// (transitively) vault, which leaves safe-env's module.exports
// half-built when vault first reaches readVar. Defer audit resolution
// until the first emit-driven call.
var audit = lazyRequire(function () { return require("../audit"); });

var log = boot("env");

// parseInt radix — named so the call site doesn't carry a bare 16
// integer literal that reads as a byte count.
var RADIX_HEX = 0x10;

class SafeEnvError extends FrameworkError {
  constructor(message, code, line) {
    super(line != null ? message + " at line " + line : message);
    this.name = "SafeEnvError";
    this.code = code || "env/invalid";
    this.line = line == null ? null : line;
    this.isSafeEnvError = true;
  }
}

// Split an unquoted value at an inline `# comment`, returning the text BEFORE
// the comment, or null when there is no comment to strip. Replaces
// `/^([^\s#]*(?:[ \t]+[^#\s]+)*)\s+#.*$/`.
//
// That pattern was NOT catastrophic, and it is worth saying so rather than
// implying the family rule only ever removes live bugs. `[ \t]+` and `[^#\s]+`
// are disjoint, so the partition of a line into separators and tokens is unique
// and there is nothing for the engine to backtrack through — measured flat to
// 40k characters across every shape that defeats the match. It goes because the
// rule is uniform: a screen in this family costs the length of its input, and
// that holds by construction instead of by someone re-deriving the ambiguity of
// each pattern correctly, every time one is edited. The neighbouring
// trailing-whitespace strip is already a walk, for a reason that WAS measured —
// `.replace(/[ \t]+$/)` is quadratic in V8 and the parser caps total bytes, not
// bytes per line.
//
// Reading the pattern back gives a rule with no search in it. Group 1 admits no
// `#` at all, so the `#` the pattern finds is always the FIRST one; it must be
// preceded by whitespace; and everything before that whitespace run may only be
// separated by spaces and tabs (a `\v`, `\f` or U+00A0 is whitespace to `\s` but
// not to `[ \t]`, so the pattern would not match and neither does this).
function _splitInlineComment(rest) {
  var hash = rest.indexOf("#");
  if (hash <= 0) return null;                       // absent, or nothing before it
  if (!codepointClass.inRanges(rest.charCodeAt(hash - 1), codepointClass.WHITESPACE_RANGES)) {
    return null;                                    // `color#red` keeps its `#`
  }
  // Walk back over the whitespace run that `\s+` consumed.
  var end = hash - 1;
  while (end >= 0 && codepointClass.inRanges(rest.charCodeAt(end), codepointClass.WHITESPACE_RANGES)) {
    end -= 1;
  }
  var head = rest.slice(0, end + 1);
  // The separators inside group 1 are `[ \t]` only.
  for (var i = 0; i < head.length; i += 1) {
    var cc = head.charCodeAt(i);
    if (!codepointClass.inRanges(cc, codepointClass.WHITESPACE_RANGES)) continue;
    if (cc !== 0x20 && cc !== 0x09) return null;
  }
  // `#.*$` cannot cross a line terminator, and `$` without `m` is end-of-string.
  // Lines arrive split on LF and CR already, but U+2028 and U+2029 survive that
  // and are terminators to the grammar, so a comment containing one meant the
  // pattern did not match and the whole value was kept.
  for (var t = hash; t < rest.length; t += 1) {
    var tc = rest.charCodeAt(t);
    if (tc === 0x0A || tc === 0x0D || tc === 0x2028 || tc === 0x2029) return null;
  }
  return head;
}

// `export FOO=bar` — the POSIX shell convention. Replaces a `/^export\s+/` test
// paired with an identical `.replace`, which walked the prefix twice.
// The default key shape, `^[A-Z_][A-Z0-9_]*$`, as a walk. The label is what the
// refusal message quotes, so an operator still sees the shape they violated
// rather than the word "function".
var _ASCII_UPPER      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
var _KEY_HEAD_CHARS   = _ASCII_UPPER + "_";
var _KEY_TAIL_CHARS   = _ASCII_UPPER + codepointClass.ASCII_DIGITS + "_";
var DEFAULT_KEY_SHAPE = "^[A-Z_][A-Z0-9_]*$";

function _matchesDefaultKeyShape(key) {
  if (typeof key !== "string" || key.length === 0) return false;
  if (_KEY_HEAD_CHARS.indexOf(key.charAt(0)) === -1) return false;
  if (key.length === 1) return true;                 // isRunOf("") is false
  return codepointClass.isRunOf(key.slice(1), _KEY_TAIL_CHARS);
}

var _EXPORT = "export";

function _stripExportPrefix(line) {
  if (line.slice(0, _EXPORT.length) !== _EXPORT) return line;
  var i = _EXPORT.length;
  var afterWord = i;
  while (i < line.length &&
         codepointClass.inRanges(line.charCodeAt(i), codepointClass.WHITESPACE_RANGES)) i += 1;
  if (i === afterWord) return line;              // `exported=1` is a key, not a prefix
  return line.slice(i);
}

// `$VAR` and `${VAR}` references, which this parser refuses rather than expands.
// Replaces `/\$(\{[A-Za-z_]|[A-Za-z_])/` — a `$` followed either by a brace and
// an identifier head, or by an identifier head directly. A trailing `$`, `$1` or
// `$ ` is a literal dollar and stays one.
function _isIdentifierHead(ch) {
  // The length guard is load-bearing: `charAt` past the end returns "", and
  // `indexOf("")` is 0 on every string, so without it a trailing `$` reads as a
  // reference and a literal dollar at end-of-value is refused.
  if (ch.length !== 1) return false;
  return ch === "_" || codepointClass.ASCII_ALPHA.indexOf(ch) !== -1;
}

function _hasVariableReference(text) {
  for (var i = 0; i < text.length; i += 1) {
    if (text.charAt(i) !== "$") continue;
    var next = text.charAt(i + 1);
    if (next === "{") {
      if (_isIdentifierHead(text.charAt(i + 2))) return true;
      continue;
    }
    if (_isIdentifierHead(next)) return true;
  }
  return false;
}

var DEFAULTS = {
  maxBytes:       C.BYTES.kib(64),
  maxKeys:        1_000,
  // The DEFAULT shape is a walk, not a pattern. An operator may still pass a
  // RegExp — there the pattern is the INPUT, which is the one case this family
  // allows — and that override is honoured unchanged below.
  keyShape:       null,
  applyToProcess: false,
  allowOverwrite: false,
  rejectUnknown:  false,
  audit:          true,
};


// ---- parse ----

function parse(input, opts) {
  opts = opts || {};
  // Validate operator-supplied numeric opts via lib/numeric-bounds —
  // Infinity / NaN / negative / non-integer all bypass the `> 0` shape
  // and silently lift the DoS cap they were meant to enforce.
  if (opts.maxBytes !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxBytes)) {
    throw new SafeEnvError("env.parse: maxBytes must be a positive finite integer; got " +
      numericBounds.shape(opts.maxBytes), "env/bad-opt");
  }
  if (opts.maxKeys !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxKeys)) {
    throw new SafeEnvError("env.parse: maxKeys must be a positive finite integer; got " +
      numericBounds.shape(opts.maxKeys), "env/bad-opt");
  }
  var maxBytes = opts.maxBytes !== undefined
    ? Math.min(opts.maxBytes, C.BYTES.mib(1)) : DEFAULTS.maxBytes;
  var maxKeys = opts.maxKeys !== undefined
    ? Math.min(opts.maxKeys, 100_000) : DEFAULTS.maxKeys;
  var operatorKeyShape = opts.keyShape instanceof RegExp ? opts.keyShape : null;
  var keyShapeLabel = operatorKeyShape ? String(operatorKeyShape) : DEFAULT_KEY_SHAPE;
  function keyShapeAccepts(key) {
    return operatorKeyShape ? operatorKeyShape.test(key) : _matchesDefaultKeyShape(key);
  }

  input = safeBuffer.normalizeText(input, {
    maxBytes:   maxBytes,
    errorClass: SafeEnvError,
    typeCode:   "env/wrong-input-type",
    sizeCode:   "env/too-large",
  });

  // splitLinesAny breaks on LF, CR and CRLF-as-one — the same three the
  // `/\r\n|\r|\n/` alternation covered, in the same order of preference.
  var rawLines = codepointClass.splitLinesAny(input);
  var values = Object.create(null);
  var seen = new Set();

  for (var i = 0; i < rawLines.length; i++) {
    var line = rawLines[i];
    var lineNumber = i + 1;
    // Trim leading whitespace (operators sometimes indent for readability)
    var trimmed = codepointClass.trimChars(line, " \t", { trailing: false });
    if (trimmed.length === 0) continue;
    if (trimmed.charAt(0) === "#") continue;

    // Optional `export ` prefix (POSIX shell convention)
    trimmed = _stripExportPrefix(trimmed);

    var eqIdx = trimmed.indexOf("=");
    if (eqIdx < 0) {
      throw new SafeEnvError("missing '=' separator", "env/bad-line", lineNumber);
    }
    var key = safeBuffer.stripTrailingHspace(trimmed.substring(0, eqIdx));
    var rest = trimmed.substring(eqIdx + 1);

    if (key.length === 0) {
      throw new SafeEnvError("empty key", "env/empty-key", lineNumber);
    }
    if (pick.isPoisonedKey(key)) {
      throw new SafeEnvError("forbidden key '" + key + "'", "env/poisoned-key", lineNumber);
    }
    if (!keyShapeAccepts(key)) {
      throw new SafeEnvError(
        "key '" + key + "' does not match keyShape " + keyShapeLabel,
        "env/bad-key-shape", lineNumber
      );
    }
    boundedMap.requireAbsentMember(seen, key, function () {
      throw new SafeEnvError("duplicate key '" + key + "'", "env/duplicate-key", lineNumber);
    });

    // Tab at start of value is almost always a paste accident
    if (rest.charAt(0) === "\t") {
      throw new SafeEnvError(
        "tab at start of value (use spaces or quote the value)",
        "env/tab-in-value", lineNumber
      );
    }
    // Strip ONE leading space (operator-friendly: `KEY = value` → "value")
    if (rest.charAt(0) === " ") rest = rest.substring(1);

    var value;
    if (rest.charAt(0) === '"') {
      value = _decodeDoubleQuoted(rest, lineNumber);
    } else if (rest.charAt(0) === "'") {
      value = _decodeSingleQuoted(rest, lineNumber);
    } else {
      // Unquoted value: strip trailing whitespace + inline `# comment`.
      // The comment marker MUST be preceded by whitespace to count
      // (so a value like `KEY=color#red` keeps the literal `#`).
      var beforeComment = _splitInlineComment(rest);
      // stripTrailingHspace is a linear char-scan; .replace(/[ \t]+$/) is O(n^2)
      // in V8 and the env parser only caps TOTAL bytes, not per-line, so a
      // single huge-whitespace value line would otherwise hang the parser.
      value = safeBuffer.stripTrailingHspace(beforeComment === null ? rest : beforeComment);
      // Reject `$VAR` style references — explicit error so operators
      // see the policy rather than silently getting unexpanded text.
      if (_hasVariableReference(value)) {
        throw new SafeEnvError(
          "$VAR / ${VAR} expansion not supported (escape with \\$ if literal, or quote and expand yourself)",
          "env/expansion-banned", lineNumber
        );
      }
    }

    seen.add(key);
    values[key] = value;
    if (seen.size > maxKeys) {
      throw new SafeEnvError("input exceeds maxKeys", "env/too-many-keys", lineNumber);
    }
  }

  // Convert null-prototype to plain {} so JSON.stringify and for-in work.
  var out = {};
  for (var k in values) {
    if (Object.prototype.hasOwnProperty.call(values, k)) out[k] = values[k];
  }
  return out;
}

function _decodeDoubleQuoted(rest, lineNumber) {
  // Find closing quote, handling \\ + \"
  var i = 1;
  var out = "";
  while (i < rest.length) {
    var ch = rest.charAt(i);
    if (ch === "\\") {
      var esc = rest.charAt(i + 1);
      switch (esc) {
        case '"':  out += '"';  i += 2; continue;
        case "\\": out += "\\"; i += 2; continue;
        case "n":  out += "\n"; i += 2; continue;
        case "r":  out += "\r"; i += 2; continue;
        case "t":  out += "\t"; i += 2; continue;
        case "$":  out += "$";  i += 2; continue;  // literal $ escape
        case "u": {
          var hex = rest.substring(i + 2, i + 6);
          if (!safeBuffer.isHex(hex, 4)) {
            throw new SafeEnvError("bad \\u escape", "env/bad-escape", lineNumber);
          }
          out += String.fromCharCode(parseInt(hex, RADIX_HEX));
          i += 6;
          continue;
        }
        default:
          throw new SafeEnvError("unknown escape '\\" + esc + "'", "env/bad-escape", lineNumber);
      }
    }
    if (ch === '"') {
      // Optional inline comment after closing quote — ignore.
      return out;
    }
    var afterDollar = rest.charAt(i + 1);
    if (ch === "$" && (afterDollar === "{" || _isIdentifierHead(afterDollar))) {
      throw new SafeEnvError(
        "$VAR / ${VAR} expansion not supported in double-quoted value (use \\$ for literal $)",
        "env/expansion-banned", lineNumber
      );
    }
    out += ch;
    i += 1;
  }
  throw new SafeEnvError("unterminated double-quoted value", "env/unterminated-string", lineNumber);
}

function _decodeSingleQuoted(rest, lineNumber) {
  // Single-quoted is fully literal: no escapes, no expansion. Closing
  // quote is the first un-escaped `'` — but since there are no escapes,
  // it's literally the next `'`.
  var end = rest.indexOf("'", 1);
  if (end < 0) {
    throw new SafeEnvError("unterminated single-quoted value", "env/unterminated-string", lineNumber);
  }
  return rest.substring(1, end);
}

// ---- Schema validation + type coercion ----
//
// expected = { KEY: { type, sensitivity, default? } }
//   type: "string" (default) | "number" | "boolean" | "json"
//   sensitivity: "boot-only" | "runtime" | "breaking" (informational; used by diff)
//   default: optional value to use when key is absent

function _coerceType(rawValue, type, key) {
  if (type === "string" || type == null) return rawValue;
  if (type === "number") {
    if (rawValue === "") return null;
    var n = Number(rawValue);
    if (Number.isNaN(n)) {
      throw new SafeEnvError("'" + rawValue + "' is not a number for key '" + key + "'",
        "env/bad-type");
    }
    return n;
  }
  if (type === "boolean") {
    // Only accept the unambiguous spellings — no yes/no/on/off
    // (consistent with our YAML "Norway problem" stance).
    if (rawValue === "true") return true;
    if (rawValue === "false") return false;
    throw new SafeEnvError(
      "boolean key '" + key + "' must be 'true' or 'false' (got '" + rawValue + "')",
      "env/bad-type"
    );
  }
  if (type === "json") {
    try { return safeJson.parse(rawValue); }
    catch (e) {
      throw new SafeEnvError("invalid JSON for key '" + key + "': " + e.message,
        "env/bad-type");
    }
  }
  throw new SafeEnvError("unknown type '" + type + "' for key '" + key + "'",
    "env/bad-schema");
}

// ---- Levenshtein distance for typo detection ----

function _levenshtein(a, b) {
  var m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return 4;  // early-exit: anything > 2 we don't care about
  var prev = new Array(n + 1);
  var curr = new Array(n + 1);
  for (var j = 0; j <= n; j++) prev[j] = j;
  for (var i = 1; i <= m; i++) {
    curr[0] = i;
    for (var k = 1; k <= n; k++) {
      var cost = a.charAt(i - 1) === b.charAt(k - 1) ? 0 : 1;
      curr[k] = Math.min(
        prev[k] + 1,         // deletion
        curr[k - 1] + 1,     // insertion
        prev[k - 1] + cost   // substitution
      );
    }
    var tmp = prev; prev = curr; curr = tmp;
  }
  return prev[n];
}

function _detectSuspicious(values, expected) {
  if (!expected) return [];
  var expectedKeys = Object.keys(expected);
  var expectedUpper = expectedKeys.map(function (k) { return k.toUpperCase(); });
  var suspicious = [];
  for (var key in values) {
    if (Object.prototype.hasOwnProperty.call(expected, key)) continue;  // registered

    // Case-mismatch: an exact match exists if you upper-case
    var upper = key.toUpperCase();
    var caseIdx = expectedUpper.indexOf(upper);
    if (caseIdx !== -1 && expectedKeys[caseIdx] !== key) {
      suspicious.push({
        key:        key,
        suggestion: expectedKeys[caseIdx],
        reason:     "case-mismatch",
      });
      continue;
    }

    // Levenshtein distance ≤ 2
    var bestDist = Infinity;
    var bestKey = null;
    for (var j = 0; j < expectedKeys.length; j++) {
      var d = _levenshtein(key, expectedKeys[j]);
      if (d < bestDist) { bestDist = d; bestKey = expectedKeys[j]; }
    }
    if (bestDist <= 2 && bestKey) {
      suspicious.push({
        key:        key,
        suggestion: bestKey,
        reason:     "single-char-typo",
      });
    } else {
      suspicious.push({ key: key, suggestion: null, reason: "unknown" });
    }
  }
  return suspicious;
}

// ---- Diff computation ----

function _diff(prevValues, nextValues, expected) {
  var added = [];
  var removed = [];
  var changed = [];
  function _sensitivityOf(k) {
    if (expected && expected[k] && expected[k].sensitivity) return expected[k].sensitivity;
    return null;
  }
  for (var k in nextValues) {
    if (!Object.prototype.hasOwnProperty.call(prevValues, k)) {
      added.push(k);
    } else if (prevValues[k] !== nextValues[k]) {
      changed.push({ key: k, sensitivity: _sensitivityOf(k) });
    }
  }
  for (var k2 in prevValues) {
    if (!Object.prototype.hasOwnProperty.call(nextValues, k2)) {
      removed.push(k2);
    }
  }
  return { added: added, removed: removed, changed: changed };
}

// ---- load() ----

function load(filepath, opts) {
  if (typeof filepath !== "string") {
    throw new SafeEnvError("load requires a file path", "env/bad-arg");
  }
  opts = opts || {};
  var applyToProcess = opts.applyToProcess === true;
  var allowOverwrite = opts.allowOverwrite === true;
  var rejectUnknown = opts.rejectUnknown === true;
  var auditEnabled = opts.audit !== false;
  var expected = opts.expected || null;
  var allowChange = new Set((opts.allow || []).map(String));

  var bytes = atomicFile.readSync(filepath, {
    maxBytes: opts.maxBytes != null ? opts.maxBytes : DEFAULTS.maxBytes,
  });
  var rawValues = parse(bytes.toString("utf8"), {
    maxBytes: opts.maxBytes,
    maxKeys:  opts.maxKeys,
    keyShape: opts.keyShape,
  });

  // Schema-driven coercion + missing-required detection
  var values = {};
  if (expected) {
    for (var k in expected) {
      if (Object.prototype.hasOwnProperty.call(rawValues, k)) {
        values[k] = _coerceType(rawValues[k], expected[k].type, k);
      } else if ("default" in expected[k]) {
        values[k] = expected[k].default;
      } else if (expected[k].required === true) {
        throw new SafeEnvError("required key '" + k + "' missing from " + filepath,
          "env/missing-required");
      }
    }
    // Also include unregistered keys in values so the operator's app can
    // still read them; they just don't get coercion.
    for (var k2 in rawValues) {
      if (!Object.prototype.hasOwnProperty.call(values, k2)) {
        values[k2] = rawValues[k2];
      }
    }
  } else {
    values = rawValues;
  }

  // Suspicious-key detection
  var suspicious = _detectSuspicious(rawValues, expected);
  if (rejectUnknown && suspicious.length > 0) {
    var keys = suspicious.map(function (s) { return s.key; }).join(", ");
    throw new SafeEnvError(
      "rejectUnknown: unregistered keys present: " + keys,
      "env/unknown-keys"
    );
  }

  // Snapshot diff
  var snapshotPath = opts.snapshotPath || null;
  var prevValues = {};
  if (snapshotPath && atomicFile.exists(snapshotPath)) {
    try {
      var snapBuf = atomicFile.readSync(snapshotPath);
      prevValues = safeJson.parse(snapBuf) || {};
    } catch (_e) { /* missing/corrupt snapshot → treat as empty */ }
  }
  var diff = _diff(prevValues, rawValues, expected);
  diff.suspicious = suspicious;

  // Refuse breaking changes unless explicitly allowed
  if (expected) {
    for (var i = 0; i < diff.changed.length; i++) {
      var entry = diff.changed[i];
      if (entry.sensitivity === "breaking" && !allowChange.has(entry.key)) {
        throw new SafeEnvError(
          "key '" + entry.key + "' is sensitivity:'breaking' — pass " +
          "{ allow: ['" + entry.key + "'] } to acknowledge the change",
          "env/breaking-change"
        );
      }
    }
  }

  // Optionally apply to process.env
  if (applyToProcess) {
    for (var k3 in rawValues) {
      if (Object.prototype.hasOwnProperty.call(process.env, k3) && !allowOverwrite) {
        // Existing env var — leave untouched
        continue;
      }
      process.env[k3] = rawValues[k3];
    }
  }

  // Persist new snapshot (best-effort; failure to write doesn't crash
  // the load — operators just lose change-tracking until next successful
  // write).
  if (snapshotPath) {
    try {
      atomicFile.writeSync(snapshotPath, JSON.stringify(rawValues), { fileMode: 0o600 });
    } catch (_e) { /* best-effort */ }
  }

  // Audit hooks
  if (auditEnabled && _hasNonEmptyDiff(diff)) {
    _writeAuditRows(filepath, diff);
  }

  return { values: values, diff: diff };
}

function _hasNonEmptyDiff(d) {
  return d.added.length > 0 || d.removed.length > 0 ||
         d.changed.length > 0 || d.suspicious.length > 0;
}

function _writeAuditRows(filepath, diff) {
  // Both audit.record and cluster.requireLeader sit downstream — if
  // we're a follower, audit.record will throw NotLeaderError. Catch
  // explicitly: a follower's local config-load shouldn't crash because
  // the cluster's audit chain belongs to the leader.
  var auditInst = audit();   // resolve the lazy-required audit module

  function _safeRecord(action, metadata) {
    try {
      auditInst.emit({
        actor:    { kind: "system", id: "config-loader" },
        action:   action,
        outcome:  "success",
        target:   { kind: "config-file", id: filepath },
        metadata: metadata,
      });
    } catch (e) {
      if (e && e.code === "NOT_LEADER") return;  // follower; expected
      // Unexpected — but config-loading should not fail on audit failure
      // (the audit chain is observability, not the loaded values).
      // Surface via stderr so operators notice without crashing.
      log.error("audit.record failed: " + e.message);
    }
  }

  if (diff.added.length > 0 || diff.removed.length > 0 || diff.changed.length > 0) {
    _safeRecord("system.config.changed", {
      file:    filepath,
      added:   diff.added,
      removed: diff.removed,
      changed: diff.changed,
    });
  }
  if (diff.suspicious.length > 0) {
    _safeRecord("system.config.suspicious", {
      file:        filepath,
      suspicious:  diff.suspicious,
    });
  }
}

// ---- readVar() — single process.env reader with schema validation ----
//
// Centralizes "read one process.env var, with size cap + type coercion +
// optional default + optional strip-after-read for secrets". Replaces
// scattered `process.env.BLAMEJS_*` reads across lib/* — every call site
// that previously did its own missing/empty/coerce handling now goes
// through this primitive.
//
// schema:
//   type:     "string" (default) | "number" | "boolean" | "json" | "buffer"
//   required: bool — throw if missing/empty (default: false)
//   default:  fallback value when var is missing/empty (overrides required)
//   maxBytes: cap on byte length (default 64 KiB; pass 4096 for secrets)
//   strip:    bool — `delete process.env[name]` after read (for secrets)
//   enum:     optional array of allowed raw string values (string type only)

var READVAR_DEFAULT_MAX_BYTES = C.BYTES.kib(64);

function readVar(name, schema) {
  if (typeof name !== "string" || name.length === 0) {
    throw new SafeEnvError("readVar requires a non-empty name", "env/bad-arg");
  }
  schema = schema || {};
  var type     = schema.type || "string";
  var required = schema.required === true;
  var hasDefault = "default" in schema;
  if (schema.maxBytes !== undefined && !numericBounds.isPositiveFiniteInt(schema.maxBytes)) {
    throw new SafeEnvError(
      "readVar: maxBytes must be a positive finite integer; got " +
        numericBounds.shape(schema.maxBytes),
      "env/bad-opt"
    );
  }
  var maxBytes = (schema.maxBytes !== undefined)
    ? schema.maxBytes : READVAR_DEFAULT_MAX_BYTES;
  var strip    = schema.strip === true;

  var raw = process.env[name];
  var present = raw !== undefined && raw !== null && raw !== "";

  if (!present) {
    if (hasDefault) return schema.default;
    if (required) {
      throw new SafeEnvError(name + " env var is not set or is empty", "env/missing-required");
    }
    return undefined;
  }

  // Size cap. Apply BEFORE strip so an oversized value still triggers
  // the diagnostic (operator gets a clear error, not a silent truncation).
  if (Buffer.byteLength(raw, "utf8") > maxBytes) {
    throw new SafeEnvError(
      name + " exceeds " + maxBytes + " byte limit",
      "env/too-large"
    );
  }

  // enum constraint (string type only, applied to RAW value before coercion)
  if (Array.isArray(schema.enum) && schema.enum.indexOf(raw) === -1) {
    throw new SafeEnvError(
      name + "='" + raw + "' is not one of: " + schema.enum.join(", "),
      "env/bad-value"
    );
  }

  var value;
  if (type === "buffer") {
    value = Buffer.from(raw, "utf8");
  } else {
    value = _coerceType(raw, type, name);
  }

  if (strip) {
    delete process.env[name];
  }

  return value;
}

module.exports = {
  parse:         parse,
  load:          load,
  readVar:       readVar,
  SafeEnvError:  SafeEnvError,
};

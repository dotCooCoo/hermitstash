// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.safeEnv
 * @nav    Validation
 * @title  Safe Env
 * @slug   safe-env
 *
 * @intro
 *   Reads <code>.env</code> files and environment variables as data with a
 *   declared shape, rather than as whatever the shell happened to export.
 *
 *   The parser is bounded in bytes and in key count, and it does not expand
 *   or interpolate. It does not quietly pass an expansion through either: an
 *   unquoted <code>$OTHER</code> or <code>${OTHER}</code> is refused, because
 *   a value a shell would expand and this parser would not is a difference
 *   that surfaces in production. A literal dollar sign is written by
 *   single-quoting the value, or by escaping it as <code>\$</code> inside a
 *   double-quoted one; an unquoted value has no escape and refuses either
 *   way. An operator-supplied key pattern
 *   is checked for catastrophic backtracking before it is used, since a
 *   pattern applied to every key in a file is a denial of service if it can
 *   be made to backtrack.
 *
 *   Reading one variable goes through a schema that says the type, whether it
 *   is required, and what the default is. A variable holding a secret is read
 *   with <code>strip</code>, which removes it from the environment as it is
 *   read so no child process started afterwards inherits it. That is the
 *   limit of what stripping does: the environment the process was started
 *   with is still readable through <code>/proc/&lt;pid&gt;/environ</code> on
 *   Linux. A non-boolean where a boolean was expected is refused rather than
 *   read as false, because that is how a process starts without a variable
 *   its own schema calls required.
 *
 * @card
 *   Parse .env files and read environment variables against a declared schema:
 *   bounded, no interpolation, and secrets strippable as they are read.
 */

var C = require("../constants");
var pick = require("../pick");
var boundedMap = require("../bounded-map");
var atomicFile = require("../atomic-file");
var lazyRequire = require("../lazy-require");
var numericBounds = require("../numeric-bounds");
var validateOpts = require("../validate-opts");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");
var codepointClass = require("../codepoint-class");
var guardRegex = require("../guard-regex");
var { FrameworkError } = require("../framework-error");
var frameworkError = require("../framework-error");
var { boot } = require("../log");

// Lazy require for audit — eager-loading audit at top of file forms a
// load cycle: vault.init → passphrase-source → safe-env → audit →
// (transitively) vault, which leaves safe-env's module.exports
// half-built when vault first reaches readVar. Defer audit resolution
// until the first emit-driven call.
var audit = lazyRequire(function () { return require("../audit"); });

var log = boot("env");

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

frameworkError.messageFirstFactory(SafeEnvError);

function _duplicateKeyThrower(lineNumber) {
  return function (key) {
    throw new SafeEnvError("duplicate key '" + key + "'", "env/duplicate-key", lineNumber);
  };
}

function _splitInlineComment(rest) {
  var hash = rest.indexOf("#");
  if (hash <= 0) return null;
  if (!codepointClass.inRanges(rest.charCodeAt(hash - 1), codepointClass.WHITESPACE_RANGES)) {
    return null;
  }
  var end = hash - 1;
  while (end >= 0 && codepointClass.inRanges(rest.charCodeAt(end), codepointClass.WHITESPACE_RANGES)) {
    end -= 1;
  }
  var head = rest.slice(0, end + 1);
  for (var i = 0; i < head.length; i += 1) {
    var cc = head.charCodeAt(i);
    if (!codepointClass.inRanges(cc, codepointClass.WHITESPACE_RANGES)) continue;
    if (cc !== 0x20 && cc !== 0x09) return null;
  }
  for (var t = hash; t < rest.length; t += 1) {
    var tc = rest.charCodeAt(t);
    if (tc === 0x0A || tc === 0x0D || tc === 0x2028 || tc === 0x2029) return null;
  }
  return head;
}

var _ASCII_UPPER      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
var _KEY_HEAD_CHARS   = _ASCII_UPPER + "_";
var _KEY_TAIL_CHARS   = _ASCII_UPPER + codepointClass.ASCII_DIGITS + "_";
var DEFAULT_KEY_SHAPE = "^[A-Z_][A-Z0-9_]*$";

function _matchesDefaultKeyShape(key) {
  if (typeof key !== "string" || key.length === 0) return false;
  if (_KEY_HEAD_CHARS.indexOf(key.charAt(0)) === -1) return false;
  if (key.length === 1) return true;
  return codepointClass.isRunOf(key.slice(1), _KEY_TAIL_CHARS);
}

var _EXPORT = "export";

function _stripExportPrefix(line) {
  if (line.slice(0, _EXPORT.length) !== _EXPORT) return line;
  var i = _EXPORT.length;
  var afterWord = i;
  while (i < line.length &&
         codepointClass.inRanges(line.charCodeAt(i), codepointClass.WHITESPACE_RANGES)) i += 1;
  if (i === afterWord) return line;
  return line.slice(i);
}

function _isIdentifierHead(ch) {
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
  keyShape:       null,
  applyToProcess: false,
  allowOverwrite: false,
  rejectUnknown:  false,
  audit:          true,
};

function _optionalKeyShape(value, label) {
  if (value === undefined || value === null) return value;
  if (!(value instanceof RegExp)) {
    throw new SafeEnvError(label + " must be a RegExp; got " + typeof value, "env/bad-opt");
  }
  return value;
}

var LOAD_OPT_RULES = Object.freeze([
  ["applyToProcess", validateOpts.optionalBoolean],
  ["allowOverwrite", validateOpts.optionalBoolean],
  ["audit",          validateOpts.optionalBoolean],
  ["allow",          validateOpts.optionalNonEmptyStringArray],
  ["snapshotPath",   validateOpts.optionalNonEmptyString],
  ["expected",       validateOpts.optionalPlainObject],
  ["maxBytes",       validateOpts.optionalPositiveInt],
  ["maxKeys",        validateOpts.optionalPositiveInt],
  ["keyShape",       _optionalKeyShape],
]);

var VALID_EXPECTED_TYPES = Object.freeze({
  string: 1, number: 1, boolean: 1, json: 1,
});

function _assertExpectedSchema(expected) {
  if (expected === undefined || expected === null) return;
  var keys = Object.keys(expected);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var entry = expected[k];
    validateOpts.optionalPlainObject(entry, "safeEnv.load: expected['" + k + "']",
      SafeEnvError, "env/bad-schema", "must be an object describing the key");
    if (entry === undefined || entry === null) {
      throw new SafeEnvError(
        "safeEnv.load: expected['" + k + "'] must be an object describing the key",
        "env/bad-schema");
    }
    if (entry.type !== undefined && entry.type !== null &&
        !Object.prototype.hasOwnProperty.call(VALID_EXPECTED_TYPES, entry.type)) {
      throw new SafeEnvError(
        "safeEnv.load: expected['" + k + "'].type must be one of " +
        Object.keys(VALID_EXPECTED_TYPES).join(", ") + "; got " +
        numericBounds.shape(entry.type), "env/bad-schema");
    }
    validateOpts.optionalBoolean(entry.required,
      "safeEnv.load: expected['" + k + "'].required (anything other than a " +
      "boolean was read as false, so a key the schema calls required would be " +
      "treated as optional)", SafeEnvError, "env/bad-opt");
    validateOpts.optionalNonEmptyString(entry.sensitivity,
      "safeEnv.load: expected['" + k + "'].sensitivity",
      SafeEnvError, "env/bad-schema");
  }
}

function _assertLoadOpts(opts) {
  for (var i = 0; i < LOAD_OPT_RULES.length; i++) {
    var rule = LOAD_OPT_RULES[i];
    rule[1](opts[rule[0]], "safeEnv.load: opts." + rule[0],
      SafeEnvError, "env/bad-opt");
  }
  _assertExpectedSchema(opts.expected);
}


/**
 * @primitive b.safeEnv.parse
 * @signature b.safeEnv.parse(input, opts?)
 * @since     0.0.16
 * @status    stable
 * @related   b.safeEnv.load, b.safeEnv.readVar
 *
 * Parse `.env` text and return a plain object of key to string value.
 *
 * Nothing is expanded, and nothing that looks like an expansion is quietly
 * passed through either. A `$VAR` or `${VAR}` raises `env/expansion-banned`
 * naming the line, unquoted or double-quoted alike, because a value that a
 * shell would have expanded and this parser would not is the kind of
 * difference that is found in production.
 *
 * Two forms keep a literal dollar sign. A single-quoted value is returned
 * exactly as written, and a double-quoted value may escape it as `\$`. An
 * unquoted value has neither: `$USER`, `${USER}` and `\$USER` are all refused
 * there, because a bare backslash is not an escape outside quotes.
 *
 * The input is bounded at 64 KiB and 1,000 keys by default, and `maxBytes` and
 * `maxKeys` are clamped to 1 MiB and 100,000 whatever is passed, so a caller
 * cannot raise the limit past what the parser is prepared to walk.
 *
 * `keyShape` constrains which key names are accepted. It must be a `RegExp`,
 * and it is checked before being used: one that can backtrack catastrophically
 * raises `env/unsafe-pattern` and a stateful one `env/stateful-pattern`, since
 * the pattern runs against every key in the file. A key it does not match
 * raises `env/bad-key-shape`.
 *
 * The input itself raises `env/wrong-input-type` when it is neither a string
 * nor a Buffer, `env/too-large` over `maxBytes` and `env/too-many-keys` over
 * `maxKeys`. A `maxBytes` or `maxKeys` that is not a positive integer raises
 * `env/bad-opt`.
 *
 * Each line is parsed strictly, and each refusal names the line:
 * `env/bad-line` for a line with no `=`, `env/empty-key` for a name that is
 * blank, `env/duplicate-key` for a name already set in the same file,
 * `env/poisoned-key` for one of the prototype-polluting names,
 * `env/tab-in-value` for a raw tab, `env/unterminated-string` for a quote that
 * never closes, and `env/bad-escape` for an escape sequence this parser does
 * not define.
 *
 * @opts
 *   maxBytes: number,   // default 65536; clamped to 1 MiB
 *   maxKeys:  number,   // default 1000; clamped to 100000
 *   keyShape: object,   // RegExp every key must match
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.safeEnv.parse("PORT=8080\nGREETING='hi $USER'\n");
 *   // → { PORT: "8080", GREETING: "hi $USER" }
 *
 *   // Unquoted, the same value is refused rather than guessed at:
 *   try { b.safeEnv.parse("GREETING=hi $USER\n"); }
 *   catch (e) { e.code; }        // → "env/expansion-banned"
 */
function parse(input, opts) {
  opts = opts || {};
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
  var operatorKeyShape = null;
  if (opts.keyShape !== undefined && opts.keyShape !== null) {
    if (!(opts.keyShape instanceof RegExp)) {
      throw new SafeEnvError("env.parse: keyShape must be a RegExp; got " + typeof opts.keyShape, "env/bad-opt");
    }
    try { guardRegex.assertSafe(opts.keyShape, "env.parse: keyShape"); }
    catch (unsafe) { throw new SafeEnvError(unsafe.message, "env/unsafe-pattern"); }
    try { guardRegex.assertStateless(opts.keyShape, "env.parse: keyShape"); }
    catch (stateful) { throw new SafeEnvError(stateful.message, "env/stateful-pattern"); }
    operatorKeyShape = opts.keyShape;
  }
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

  var rawLines = codepointClass.splitLinesAny(input);
  var values = Object.create(null);
  var seen = new Set();

  for (var i = 0; i < rawLines.length; i++) {
    var line = rawLines[i];
    var lineNumber = i + 1;
    var trimmed = codepointClass.trimChars(line, " \t", { trailing: false });
    if (trimmed.length === 0) continue;
    if (trimmed.charAt(0) === "#") continue;

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
    boundedMap.requireAbsentMember(seen, key, _duplicateKeyThrower(lineNumber));

    if (rest.charAt(0) === "\t") {
      throw new SafeEnvError(
        "tab at start of value (use spaces or quote the value)",
        "env/tab-in-value", lineNumber
      );
    }
    if (rest.charAt(0) === " ") rest = rest.substring(1);

    var value;
    if (rest.charAt(0) === '"') {
      value = _decodeDoubleQuoted(rest, lineNumber);
    } else if (rest.charAt(0) === "'") {
      value = _decodeSingleQuoted(rest, lineNumber);
    } else {
      var beforeComment = _splitInlineComment(rest);
      value = safeBuffer.stripTrailingHspace(beforeComment === null ? rest : beforeComment);
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

  var out = {};
  for (var k in values) {
    if (Object.prototype.hasOwnProperty.call(values, k)) out[k] = values[k];
  }
  return out;
}

function _decodeDoubleQuoted(rest, lineNumber) {
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
        case "$":  out += "$";  i += 2; continue;
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
  var end = rest.indexOf("'", 1);
  if (end < 0) {
    throw new SafeEnvError("unterminated single-quoted value", "env/unterminated-string", lineNumber);
  }
  return rest.substring(1, end);
}

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

function _levenshtein(a, b) {
  var m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return 4;
  var prev = new Array(n + 1);
  var curr = new Array(n + 1);
  for (var j = 0; j <= n; j++) prev[j] = j;
  for (var i = 1; i <= m; i++) {
    curr[0] = i;
    for (var k = 1; k <= n; k++) {
      var cost = a.charAt(i - 1) === b.charAt(k - 1) ? 0 : 1;
      curr[k] = Math.min(
        prev[k] + 1,
        curr[k - 1] + 1,
        prev[k - 1] + cost
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
    if (Object.prototype.hasOwnProperty.call(expected, key)) continue;

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

/**
 * @primitive b.safeEnv.load
 * @signature b.safeEnv.load(filepath, opts?)
 * @since     0.1.5
 * @status    stable
 * @related   b.safeEnv.parse, b.safeEnv.readVar
 *
 * Read and parse a `.env` file, and optionally apply it to `process.env`.
 *
 * Nothing reaches the process environment unless `applyToProcess` is true, and
 * even then an existing variable is not replaced unless `allowOverwrite` is
 * true. A file cannot silently change a variable the deployment already set.
 *
 * `snapshotPath` names the file holding the previous load's keys and values.
 * Give it and the load compares the file against that snapshot, then rewrites
 * the snapshot at mode `0600` with what it just read. Leave it out and there
 * is nothing to compare against, so every key is reported as added, no key is
 * reported as changed, and the two gates below that act on a change never
 * fire. A snapshot that is missing or will not parse is treated as empty, and
 * a snapshot that cannot be written back is skipped; neither stops the load.
 *
 * `allow` is a different gate: it names the keys whose change the caller
 * acknowledges when the comparison against the snapshot marks them
 * `sensitivity: "breaking"`, which otherwise raises `env/breaking-change`
 * naming the key. It does not permit an overwrite, so a name listed there and
 * already present in the environment is still skipped.
 *
 * `expected` is a schema for the keys the file should carry, and
 * `rejectUnknown` refuses a file carrying keys the schema does not name. The
 * boolean is validated rather than coerced: anything non-boolean used to be
 * read as false, which loaded the file instead of refusing it.
 *
 * Every `expected` entry is checked before the file is opened. An entry is an
 * object; its `type` is `string`, `number`, `boolean` or `json`; its
 * `required` is a boolean; and its `sensitivity` is a non-empty string. A
 * malformed entry raises `env/bad-schema`, except a non-boolean `required`,
 * which raises `env/bad-opt`. Checking it up front is what turns
 * `expected: { PORT: null }` into a named refusal instead of a `TypeError`
 * raised while reading the entry, and it catches an unknown `type` on a key
 * the file happens not to carry, which the per-key coercion never reaches.
 *
 * It returns `{ values, diff }`. `values` is the parsed map after the schema
 * is applied. `diff` compares the file against the snapshot and is computed
 * before anything is written to `process.env`, so it reports a key as added or
 * changed whether or not the value reached the environment: with
 * `applyToProcess` false nothing is applied at all, and with `allowOverwrite`
 * false a key already set in the environment is skipped while still appearing
 * in the diff. Read it as what the file says relative to the last snapshot,
 * not as what is now live. The audit rows are written from it.
 *
 * The load is recorded in the audit chain unless `audit` is false, with the
 * key names and not their values.
 *
 * The call's own requirements raise `env/bad-arg` for a path that is not a
 * string, and `env/bad-opt` for an option of the wrong shape: a non-boolean
 * `applyToProcess`, `allowOverwrite`, `rejectUnknown` or `audit`, an `allow`
 * that is not an array of names, a `snapshotPath` that is not a non-empty
 * string, or an `expected` that is not a plain object. They are checked before
 * the file is opened, since a typo in one of them otherwise reads as the
 * default and the load looks like it worked. The `expected`
 * schema raises `env/bad-schema` for a type it does not define, `env/bad-type`
 * for a value that will not coerce to the type named, `env/missing-required`
 * for a `required` key the file omits, and `env/unknown-keys` under
 * `rejectUnknown` for keys the schema does not name.
 *
 * Reading the file goes through `b.safeEnv.parse`, so every refusal it makes
 * reaches this caller: `env/wrong-input-type`, `env/too-large`,
 * `env/too-many-keys`, `env/bad-line`, `env/empty-key`, `env/duplicate-key`,
 * `env/poisoned-key`, `env/bad-key-shape`, `env/tab-in-value`,
 * `env/bad-escape`, `env/unterminated-string`, `env/expansion-banned`,
 * `env/unsafe-pattern` and `env/stateful-pattern`, each described there.
 *
 * @opts
 *   applyToProcess: boolean,  // default false; write into process.env
 *   allowOverwrite: boolean,  // default false; replace existing variables
 *   snapshotPath:   string,   // previous load's keys; compared then rewritten
 *   allow:          array,    // names whose "breaking" change is acknowledged
 *   expected:       object,   // schema for the keys the file should carry
 *   rejectUnknown:  boolean,  // default false; refuse unnamed keys
 *   maxBytes:       number,   // read and parse ceiling; default 65536
 *   maxKeys:        number,   // forwarded to parse; default 1000
 *   keyShape:       object,   // forwarded to parse; RegExp every key must match
 *   audit:          boolean,  // false silences the audit event
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var loaded = b.safeEnv.load(".env", {
 *     applyToProcess: true,
 *     snapshotPath:   "./.env.snapshot.json",
 *   });
 *   loaded.values.PORT;
 *   loaded.diff;                 // → the file against the last snapshot
 */
function load(filepath, opts) {
  if (typeof filepath !== "string") {
    throw new SafeEnvError("load requires a file path", "env/bad-arg");
  }
  opts = opts || {};
  _assertLoadOpts(opts);
  var applyToProcess = opts.applyToProcess === true;
  var allowOverwrite = opts.allowOverwrite === true;
  validateOpts.optionalBoolean(opts.rejectUnknown,
    "safeEnv.load: opts.rejectUnknown (anything other than a boolean was read as false, so a " +
    "file carrying keys the schema does not name was loaded rather than refused)",
    SafeEnvError, "env/bad-opt");
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

  var values = {};
  if (expected) {
    for (var k in expected) {
      if (expected[k].required !== undefined && expected[k].required !== null &&
          typeof expected[k].required !== "boolean") {
        throw new SafeEnvError(
          "key '" + k + "': required must be a boolean; anything else was read as false, so a " +
            "key the schema calls required would be treated as optional; got " +
            numericBounds.shape(expected[k].required),
          "env/bad-opt");
      }
      if (Object.prototype.hasOwnProperty.call(rawValues, k)) {
        values[k] = _coerceType(rawValues[k], expected[k].type, k);
      } else if ("default" in expected[k]) {
        values[k] = expected[k].default;
      } else if (expected[k].required === true) {
        throw new SafeEnvError("required key '" + k + "' missing from " + filepath,
          "env/missing-required");
      }
    }
    for (var k2 in rawValues) {
      if (!Object.prototype.hasOwnProperty.call(values, k2)) {
        values[k2] = rawValues[k2];
      }
    }
  } else {
    values = rawValues;
  }

  var suspicious = _detectSuspicious(rawValues, expected);
  if (rejectUnknown && suspicious.length > 0) {
    var keys = suspicious.map(function (s) { return s.key; }).join(", ");
    throw new SafeEnvError(
      "rejectUnknown: unregistered keys present: " + keys,
      "env/unknown-keys"
    );
  }

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

  if (applyToProcess) {
    for (var k3 in rawValues) {
      if (Object.prototype.hasOwnProperty.call(process.env, k3) && !allowOverwrite) {
        continue;
      }
      process.env[k3] = rawValues[k3];
    }
  }

  if (snapshotPath) {
    try {
      atomicFile.writeSync(snapshotPath, JSON.stringify(rawValues), { fileMode: 0o600 });
    } catch (_e) { /* best-effort */ }
  }

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
  var auditInst = audit();

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
      if (e && e.code === "cluster/not-leader") return;
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

var READVAR_DEFAULT_MAX_BYTES = C.BYTES.kib(64);

/**
 * @primitive b.safeEnv.readVar
 * @signature b.safeEnv.readVar(name, schema?)
 * @since     0.1.5
 * @status    stable
 * @related   b.safeEnv.load, b.vaultPassphraseSource.fromEnv
 *
 * Read one environment variable against a schema and return it in the declared
 * type.
 *
 * An empty string counts as absent, since that is what an unset variable looks
 * like once it has passed through a shell or an orchestrator. Absent takes the
 * `default` when the schema has one, raises when `required` is true, and is
 * otherwise `undefined`.
 *
 * `strip: true` removes the variable from `process.env` as it is read, which is
 * how a secret is read: nothing the process starts afterwards inherits it.
 * `type: "buffer"` returns the value as a Buffer so it can be zeroed.
 *
 * The strip does not reach the environment block the process started with. On
 * Linux a variable present at exec time stays readable through
 * `/proc/<pid>/environ` for the life of the process, so a secret that must be
 * kept from a local reader belongs in a file rather than the environment.
 *
 * `required` must be a boolean. Anything else is refused rather than read as
 * false, because that is exactly how a process starts up missing a variable its
 * own schema calls required.
 *
 * @opts
 *   type:     string,   // string | number | boolean | buffer; default "string"
 *   required: boolean,  // raise when absent
 *   default:  string,   // value used when absent
 *   maxBytes: number,   // value ceiling
 *   strip:    boolean,  // remove from process.env as it is read
 *
 * @example
 *   // requires: API_TOKEN set in the environment
 *   var b = require("@blamejs/core");
 *   var port = b.safeEnv.readVar("PORT", { type: "number", default: 8080 });
 *   var token = b.safeEnv.readVar("API_TOKEN", { type: "buffer", strip: true });
 *   token.fill(0);
 */
function readVar(name, schema) {
  if (typeof name !== "string" || name.length === 0) {
    throw new SafeEnvError("readVar requires a non-empty name", "env/bad-arg");
  }
  schema = schema || {};
  var type     = schema.type || "string";
  if (schema.required !== undefined && schema.required !== null &&
      typeof schema.required !== "boolean") {
    throw new SafeEnvError(
      "readVar: required must be a boolean; anything else was read as false, so the process " +
        "would start without a variable its own schema calls required; got " +
        numericBounds.shape(schema.required),
      "env/bad-opt");
  }
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
  validateOpts.optionalBoolean(schema.strip,
    "readVar: strip (anything other than a boolean was read as false, so the " +
    "variable stayed in process.env and was inherited by every child the " +
    "process starts)",
    SafeEnvError, "env/bad-opt");
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

  if (Buffer.byteLength(raw, "utf8") > maxBytes) {
    throw new SafeEnvError(
      name + " exceeds " + maxBytes + " byte limit",
      "env/too-large"
    );
  }

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

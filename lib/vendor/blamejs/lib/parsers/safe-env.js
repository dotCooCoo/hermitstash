// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
    boundedMap.requireAbsentMember(seen, key, function () {
      throw new SafeEnvError("duplicate key '" + key + "'", "env/duplicate-key", lineNumber);
    });

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

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * INI parser — same security defaults as the framework's other parsers.
 *
 * INI is the Windows config-file format (also used by systemd unit
 * files, .gitconfig, php.ini, tox.ini, and a long tail of operator
 * tooling). The format has no formal spec — we implement the
 * widely-compatible subset:
 *
 *   - Sections:        [section-name]                     -> object key
 *   - Subsections:     [parent.child] / [parent "child"]  -> nested object
 *   - Key-value:       key = value  /  key: value
 *   - Comments:        ; or # at the start of a line, or after a value
 *   - Quoted values:   "double" / 'single' (escapes: \\ \" \' \n \t)
 *   - Booleans:        true/false/yes/no/on/off (case-insensitive)
 *   - Numbers:         decimal integers + floats; hex (0xABCD)
 *
 * Security defaults:
 *   - maxBytes:        1 MiB (operator override via opts.maxBytes)
 *   - maxSections:     500 (depth + breadth limit)
 *   - maxKeysPerSection: 1000
 *   - maxValueBytes:   64 KiB
 *   - prototype-pollution: keys named __proto__, constructor, prototype
 *     are rejected (would otherwise let an attacker poison Object.prototype
 *     when a downstream consumer uses bracket access)
 *   - Duplicate-key policy: opts.onDuplicate = "throw" (default) | "first" | "last".
 *     Silent overwrite (the bare-INI default) is OFF — operators almost
 *     never want a config error to silently shadow earlier values.
 *
 * Public API:
 *   parsers.ini.parse(input, opts?)   -> object
 *   parsers.ini.IniSafeError          (with .code matching ini/...)
 *
 * Input validation throws at parse time — every malformed input
 * surfaces immediately, never silently coerces to a usable shape.
 */

var C = require("../constants");
var pick = require("../pick");
var numericBounds = require("../numeric-bounds");
var safeBuffer = require("../safe-buffer");
var { defineClass } = require("../framework-error");

var IniSafeError = defineClass("IniSafeError", { alwaysPermanent: true });

// parseInt radix — named so the call site doesn't carry a bare 16
// integer literal that reads as a byte count.
var RADIX_HEX = 0x10;

var DEFAULT_MAX_BYTES         = C.BYTES.mib(1);
var DEFAULT_MAX_SECTIONS      = 500;
var DEFAULT_MAX_KEYS_SECTION  = 1_000;
var DEFAULT_MAX_VALUE_BYTES   = C.BYTES.kib(64);


var TRUE_VALUES  = new Set(["true", "yes", "on"]);
var FALSE_VALUES = new Set(["false", "no", "off"]);

function _err(code, message) { return new IniSafeError(code, message); }

function _stripComment(line) {
  var inSingle = false, inDouble = false, escape = false;
  for (var i = 0; i < line.length; i++) {
    var c = line.charAt(i);
    if (escape) { escape = false; continue; }
    if (c === "\\" && (inSingle || inDouble)) { escape = true; continue; }
    if (c === "\"" && !inSingle) { inDouble = !inDouble; continue; }
    if (c === "'"  && !inDouble) { inSingle = !inSingle; continue; }
    if (!inSingle && !inDouble && (c === ";" || c === "#")) {
      if (i === 0 || /\s/.test(line.charAt(i - 1))) {
        return line.slice(0, i);
      }
    }
  }
  return line;
}

function _unquote(raw) {
  var s = raw.trim();
  if (s.length === 0) return s;
  var first = s.charAt(0), last = s.charAt(s.length - 1);
  if ((first === "\"" && last === "\"") || (first === "'" && last === "'")) {
    if (s.length < 2) {
      throw _err("ini/bad-quote", "unbalanced quote in value: " + JSON.stringify(s));
    }
    var inner = s.slice(1, -1);
    var out = "";
    var i = 0;
    while (i < inner.length) {
      var c = inner.charAt(i);
      if (c === "\\" && i + 1 < inner.length) {
        var next = inner.charAt(i + 1);
        if (next === "\\")      out += "\\";
        else if (next === "n")  out += "\n";
        else if (next === "t")  out += "\t";
        else if (next === "r")  out += "\r";
        else if (next === "\"") out += "\"";
        else if (next === "'")  out += "'";
        else throw _err("ini/bad-escape", "unknown escape sequence \\" + next);
        i += 2;
      } else {
        out += c;
        i += 1;
      }
    }
    return out;
  }
  return s;
}

function _coerceValue(raw) {
  if (raw.length === 0) return raw;
  var first = raw.charAt(0);
  if (first === "\"" || first === "'") return _unquote(raw);
  var lower = raw.toLowerCase();
  if (TRUE_VALUES.has(lower))  return true;
  if (FALSE_VALUES.has(lower)) return false;
  if (/^0x[0-9a-f]+$/i.test(raw)) {
    var hex = parseInt(raw, RADIX_HEX);
    if (!Number.isSafeInteger(hex)) {
      throw _err("ini/value-out-of-range", "hex integer exceeds safe-integer range: " + raw);
    }
    return hex;
  }
  if (/^-?\d+$/.test(raw)) {
    var n = Number(raw);
    if (!Number.isSafeInteger(n)) {
      throw _err("ini/value-out-of-range", "integer exceeds safe-integer range: " + raw);
    }
    return n;
  }
  if (/^-?\d+\.\d+([eE][+-]?\d+)?$/.test(raw) || /^-?\d+[eE][+-]?\d+$/.test(raw)) {
    return Number(raw);
  }
  return _unquote(raw);
}

function _validateKey(name) {
  if (pick.isPoisonedKey(name)) {
    throw _err("ini/forbidden-key", "key '" + name + "' is reserved (prototype pollution defense)");
  }
}

function _ensureSection(root, sectionPath) {
  if (sectionPath.length === 0) return root;
  var node = root;
  for (var i = 0; i < sectionPath.length; i++) {
    var seg = sectionPath[i];
    _validateKey(seg);
    if (Object.prototype.hasOwnProperty.call(node, seg)) {
      var existing = node[seg];
      if (typeof existing !== "object" || existing === null || Array.isArray(existing)) {
        throw _err("ini/section-conflict",
          "section path [" + sectionPath.join(".") + "] collides with existing scalar at '" + seg + "'");
      }
      node = existing;
    } else {
      var child = Object.create(null);   // null-proto: see root (pollution-safe)
      node[seg] = child;
      node = child;
    }
  }
  return node;
}

function _parseSectionHeader(line) {
  var inner = line.slice(1, line.lastIndexOf("]")).trim();
  if (inner.length === 0) {
    throw _err("ini/empty-section", "section header [] has no name");
  }
  var quotedMatch = /^([A-Za-z0-9._-]+)\s+"([^"\\]*(?:\\.[^"\\]*)*)"$/.exec(inner);
  if (quotedMatch) {
    return [quotedMatch[1], quotedMatch[2]];
  }
  var parts = inner.split(".");
  for (var i = 0; i < parts.length; i++) {
    if (parts[i].length === 0) {
      throw _err("ini/bad-section", "section name has empty segment: " + JSON.stringify(inner));
    }
    if (!safeBuffer.BASE64URL_RE.test(parts[i])) {
      throw _err("ini/bad-section",
        "section segment must match [A-Za-z0-9_-]+ (got " + JSON.stringify(parts[i]) + ")");
    }
  }
  return parts;
}

function parse(input, opts) {
  opts = opts || {};
  // Validate operator-supplied numeric opts via lib/numeric-bounds —
  // Infinity / NaN / negative / non-integer all bypass `|| DEFAULT_*`
  // (Infinity is truthy) and silently lift the DoS cap they were meant
  // to enforce.
  var _numericOpts = ["maxBytes", "maxSections", "maxKeysPerSection", "maxValueBytes"];
  for (var _ni = 0; _ni < _numericOpts.length; _ni++) {
    var _name = _numericOpts[_ni];
    if (opts[_name] !== undefined && !numericBounds.isPositiveFiniteInt(opts[_name])) {
      throw _err("ini/bad-opt",
        "ini.parse: " + _name + " must be a positive finite integer; got " +
          numericBounds.shape(opts[_name]));
    }
  }
  var maxBytes        = opts.maxBytes        !== undefined ? opts.maxBytes        : DEFAULT_MAX_BYTES;
  var maxSections     = opts.maxSections     !== undefined ? opts.maxSections     : DEFAULT_MAX_SECTIONS;
  var maxKeysPerSect  = opts.maxKeysPerSection !== undefined ? opts.maxKeysPerSection : DEFAULT_MAX_KEYS_SECTION;
  var maxValueBytes   = opts.maxValueBytes   !== undefined ? opts.maxValueBytes   : DEFAULT_MAX_VALUE_BYTES;
  var onDuplicate     = opts.onDuplicate     || "throw";

  if (typeof input !== "string") {
    throw _err("ini/bad-input", "ini.parse: input must be a string, got " + typeof input);
  }
  if (Buffer.byteLength(input, "utf8") > maxBytes) {
    throw _err("ini/too-large",
      "ini.parse: input exceeds " + maxBytes + " bytes");
  }
  if (onDuplicate !== "throw" && onDuplicate !== "first" && onDuplicate !== "last") {
    throw _err("ini/bad-opt",
      "ini.parse: onDuplicate must be 'throw' | 'first' | 'last', got " + JSON.stringify(onDuplicate));
  }

  // Defense-in-depth against prototype pollution: every parsed node is a
  // null-prototype object, so a key like __proto__ / constructor / prototype
  // (already REFUSED by _validateKey → pick.isPoisonedKey before any write)
  // could only ever land as an own property here, never reach Object.prototype.
  // safe-ini's own reads use Object.prototype.hasOwnProperty.call(node, ...),
  // so a null-proto tree is fully compatible.
  var root = Object.create(null);
  var currentSectionPath = [];
  var currentSection = root;
  var sectionCount = 0;
  var keysInCurrentSection = 0;

  var lines = input.split(/\r?\n/);
  for (var li = 0; li < lines.length; li++) {
    var raw = lines[li];
    var stripped = _stripComment(raw).trim();
    if (stripped.length === 0) continue;

    if (stripped.charAt(0) === "[") {
      if (stripped.charAt(stripped.length - 1) !== "]") {
        throw _err("ini/bad-section", "section header at line " + (li + 1) + " missing closing ']'");
      }
      sectionCount += 1;
      if (sectionCount > maxSections) {
        throw _err("ini/too-many-sections",
          "ini.parse: section count exceeds " + maxSections);
      }
      currentSectionPath = _parseSectionHeader(stripped);
      currentSection = _ensureSection(root, currentSectionPath);
      keysInCurrentSection = 0;
      continue;
    }

    var eqIdx = stripped.indexOf("=");
    var coIdx = stripped.indexOf(":");
    var sepIdx;
    if (eqIdx === -1) sepIdx = coIdx;
    else if (coIdx === -1) sepIdx = eqIdx;
    else sepIdx = Math.min(eqIdx, coIdx);
    if (sepIdx === -1) {
      throw _err("ini/bad-line",
        "line " + (li + 1) + " is neither blank nor key=value: " + JSON.stringify(stripped));
    }

    var key = stripped.slice(0, sepIdx).trim();
    var valueRaw = stripped.slice(sepIdx + 1).trim();
    if (key.length === 0) {
      throw _err("ini/empty-key", "line " + (li + 1) + " has empty key");
    }
    _validateKey(key);
    if (Buffer.byteLength(valueRaw, "utf8") > maxValueBytes) {
      throw _err("ini/value-too-large",
        "line " + (li + 1) + " value exceeds " + maxValueBytes + " bytes");
    }
    keysInCurrentSection += 1;
    if (keysInCurrentSection > maxKeysPerSect) {
      throw _err("ini/too-many-keys",
        "section [" + currentSectionPath.join(".") + "] exceeds " + maxKeysPerSect + " keys");
    }
    var value = _coerceValue(valueRaw);

    if (Object.prototype.hasOwnProperty.call(currentSection, key)) {
      if (onDuplicate === "throw") {
        throw _err("ini/duplicate-key",
          "section [" + currentSectionPath.join(".") + "] redefines key '" + key + "' " +
          "(opt onDuplicate:'first' or 'last' to allow)");
      }
      if (onDuplicate === "first") continue;
    }
    currentSection[key] = value;
  }

  return root;
}

module.exports = {
  parse:        parse,
  IniSafeError: IniSafeError,
};

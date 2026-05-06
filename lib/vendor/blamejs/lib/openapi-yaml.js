"use strict";
/**
 * OpenAPI 3.1 — minimal YAML 1.2 emitter for the document JSON.
 *
 * Why a hand-rolled emitter: the framework is zero-runtime-dep and the
 * vendored yaml-min already handles most cases. This module bridges
 * the OpenAPI document into a YAML rendering operators can paste into
 * Swagger-UI / docs-as-code pipelines that want yaml.
 *
 * Output is pure ASCII, uses 2-space indentation, quotes strings that
 * could be parsed as numbers / booleans / null / yaml-tags / contain
 * special characters. Operators with strict yaml-emitter requirements
 * pipe the document JSON through their own yaml stack instead.
 */

var { defineClass } = require("./framework-error");
var OpenApiError = defineClass("OpenApiError", { alwaysPermanent: true });

var SPECIAL_KEYS = ["true", "false", "null", "True", "False", "Null",
                    "TRUE", "FALSE", "NULL", "yes", "no", "on", "off",
                    "Yes", "No", "On", "Off", "YES", "NO", "ON", "OFF",
                    "~"];

var QUOTE_PATTERN = /[:#&*!|>'"%@`{}[\],?]|^\s|\s$|^-\s|\t/;
var NUMBER_PATTERN = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;
var INT_PATTERN    = /^-?\d+$/;
var DATE_PATTERN   = /^\d{4}-\d{2}-\d{2}/;

function _needsQuoting(str) {
  if (str.length === 0) return true;
  if (SPECIAL_KEYS.indexOf(str) !== -1) return true;
  if (NUMBER_PATTERN.test(str)) return true;
  if (INT_PATTERN.test(str))    return true;
  if (DATE_PATTERN.test(str))   return true;
  if (QUOTE_PATTERN.test(str))  return true;
  return false;
}

function _quoteString(str) {
  // Use double quotes; escape backslashes + quotes + control chars.
  var out = '"';
  for (var i = 0; i < str.length; i += 1) {
    var ch = str.charAt(i);
    var code = str.charCodeAt(i);
    if (ch === "\\")      out += "\\\\";
    else if (ch === '"')  out += '\\"';
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0d) out += "\\r";
    else if (code === 0x09) out += "\\t";
    else if (code < 0x20)   out += "\\u" + code.toString(16).padStart(4, "0");        // allow:raw-byte-literal — codepoint hex padding
    else                    out += ch;
  }
  out += '"';
  return out;
}

function _encodeScalar(value) {
  if (value === null)              return "null";
  if (value === undefined)         return "null";
  if (typeof value === "boolean")  return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value))          return "null";
    return String(value);
  }
  if (typeof value === "string") {
    if (_needsQuoting(value))      return _quoteString(value);
    return value;
  }
  if (typeof value === "bigint")   return String(value);
  return _quoteString(String(value));
}

function _encodeKey(key) {
  if (typeof key !== "string") return _quoteString(String(key));
  if (_needsQuoting(key))      return _quoteString(key);
  return key;
}

function _isScalar(v) {
  return v === null || v === undefined ||
         typeof v === "boolean" || typeof v === "number" ||
         typeof v === "string"  || typeof v === "bigint";
}

function _isPlainObject(v) {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function emit(value, indent) {
  indent = indent || 0;
  var pad = _pad(indent);

  if (_isScalar(value)) {
    return _encodeScalar(value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    var arrLines = [];
    for (var i = 0; i < value.length; i += 1) {
      var entry = value[i];
      if (_isScalar(entry)) {
        arrLines.push(pad + "- " + _encodeScalar(entry));
      } else if (Array.isArray(entry)) {
        arrLines.push(pad + "- " + emit(entry, indent + 1).replace(/^\s+/, ""));
      } else {
        arrLines.push(pad + "-");
        arrLines.push(emit(entry, indent + 1));
      }
    }
    return arrLines.join("\n");
  }
  if (_isPlainObject(value)) {
    var keys = Object.keys(value);
    if (keys.length === 0) return "{}";
    var objLines = [];
    for (var k = 0; k < keys.length; k += 1) {
      var keyStr = keys[k];
      var v = value[keyStr];
      var encodedKey = _encodeKey(keyStr);
      if (_isScalar(v)) {
        objLines.push(pad + encodedKey + ": " + _encodeScalar(v));
      } else if (Array.isArray(v) && v.length === 0) {
        objLines.push(pad + encodedKey + ": []");
      } else if (_isPlainObject(v) && Object.keys(v).length === 0) {
        objLines.push(pad + encodedKey + ": {}");
      } else {
        objLines.push(pad + encodedKey + ":");
        objLines.push(emit(v, indent + 1));
      }
    }
    return objLines.join("\n");
  }
  return _encodeScalar(value);
}

function _pad(indent) {
  var s = "";
  for (var i = 0; i < indent; i += 1) s += "  ";
  return s;
}

function toYaml(doc) {
  if (doc == null || typeof doc !== "object") {
    throw new OpenApiError("openapi/bad-yaml-input",
      "openapi.toYaml: input must be a non-null object");
  }
  return emit(doc, 0) + "\n";
}

module.exports = {
  toYaml:        toYaml,
  emit:          emit,
  OpenApiError:  OpenApiError,
};

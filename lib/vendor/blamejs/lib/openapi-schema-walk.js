"use strict";
/**
 * OpenAPI 3.1 — converts a b.safeSchema description into the JSON
 * Schema dialect that OpenAPI 3.1 uses (which IS JSON Schema 2020-12
 * proper, not the OpenAPI 3.0 fork). Operators pass either:
 *
 *   - A b.safeSchema object (with the framework's `.parse / .optional /
 *     ...` interface) — we walk the spec to produce JSON Schema.
 *
 *   - A plain JSON Schema object — passes through unchanged (just
 *     validated for shape so a typo in the operator's hand-written
 *     schema fails at build-time, not at consumer-time).
 *
 *   - A primitive type name like "string" / "integer" / "boolean" —
 *     translated to the corresponding JSON Schema scalar.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var OpenApiError = defineClass("OpenApiError", { alwaysPermanent: true });

var TYPE_KEYWORDS = ["type", "properties", "items", "enum", "const",
                     "format", "pattern", "anyOf", "oneOf", "allOf",
                     "not", "$ref", "$id"];

function _isPlainObject(v) {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function _isJsonSchemaShape(v) {
  if (!_isPlainObject(v)) return false;
  for (var i = 0; i < TYPE_KEYWORDS.length; i += 1) {
    if (Object.prototype.hasOwnProperty.call(v, TYPE_KEYWORDS[i])) return true;
  }
  return false;
}

function _isSafeSchema(v) {
  return !!v && typeof v === "object" &&
         typeof v.parse === "function" && typeof v._kind === "string";
}

function _safeSchemaToJsonSchema(schema) {
  var out  = {};
  switch (schema._kind) {
    case "string":
      out.type = "string";
      if (typeof schema._minLength === "number") out.minLength = schema._minLength;
      if (typeof schema._maxLength === "number") out.maxLength = schema._maxLength;
      if (schema._format)  out.format = schema._format;
      if (schema._regex && schema._regex.source) out.pattern = schema._regex.source;
      break;
    case "number":
    case "integer":
      out.type = (schema._kind === "integer") ? "integer" : "number";
      if (typeof schema._min === "number") out.minimum = schema._min;
      if (typeof schema._max === "number") out.maximum = schema._max;
      if (schema._isInt === true) out.type = "integer";
      break;
    case "boolean":
      out.type = "boolean";
      break;
    case "literal":
      out.const = schema._value;
      break;
    case "enum":
      out.enum = (schema._values || []).slice();
      break;
    case "null":
      out.type = "null";
      break;
    case "array":
      out.type = "array";
      if (schema._element != null) out.items = walk(schema._element);
      if (typeof schema._minItems === "number") out.minItems = schema._minItems;
      if (typeof schema._maxItems === "number") out.maxItems = schema._maxItems;
      break;
    case "object":
      out.type = "object";
      out.properties = {};
      var requiredList = [];
      var shape = schema.shape || schema._shape || {};
      for (var key in shape) {
        if (Object.prototype.hasOwnProperty.call(shape, key)) {
          var childSchema = shape[key];
          out.properties[key] = walk(childSchema);
          if (!childSchema._isOptional) {
            requiredList.push(key);
          }
        }
      }
      if (requiredList.length > 0) out.required = requiredList;
      out.additionalProperties = (schema._mode === "passthrough") ? true : false;
      break;
    case "record":
      out.type = "object";
      if (schema._valueSchema) out.additionalProperties = walk(schema._valueSchema);
      break;
    case "union":
      out.oneOf = (schema._options || []).map(walk);
      break;
    case "any":
    case "unknown":
      break;
    default:
      break;
  }
  if (schema._description) out.description = schema._description;
  if (schema._example != null) out.example = schema._example;
  if (schema._isNullable === true && typeof out.type === "string") {
    out.type = [out.type, "null"];
  }
  return out;
}

function walk(input) {
  if (input == null) return {};
  if (typeof input === "string") {
    return { type: input };
  }
  if (_isSafeSchema(input)) {
    return _safeSchemaToJsonSchema(input);
  }
  if (_isJsonSchemaShape(input)) {
    return _cloneJsonSchema(input);
  }
  if (_isPlainObject(input)) {
    // Hand-shaped object — operator passed a JSON-Schema-like object
    // without a recognised keyword; clone as-is and let the spec
    // validation in build() flag it.
    return _cloneJsonSchema(input);
  }
  throw new OpenApiError("openapi/bad-schema",
    "schema-walk: unsupported schema input — got " + typeof input);
}

function _cloneJsonSchema(obj) {
  if (obj == null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) {
    var arrOut = [];
    for (var i = 0; i < obj.length; i += 1) {
      arrOut.push(_cloneJsonSchema(obj[i]));
    }
    return arrOut;
  }
  var out = {};
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      out[key] = _cloneJsonSchema(obj[key]);
    }
  }
  return out;
}

// Validates a JSON Schema document for the most common authoring
// errors. Used at build-time so a typo doesn't reach the spec
// consumer. Not a full JSON-Schema-vocabulary validator — that's
// outside scope; operators with strict needs run a downstream
// validator like ajv against the emitted document.
function validateJsonSchema(schema, label) {
  validateOpts.requireNonEmptyString(label || "schema", "validateJsonSchema: label",
    OpenApiError, "openapi/bad-schema");
  if (!_isPlainObject(schema)) {
    throw new OpenApiError("openapi/bad-schema",
      label + ": schema must be a plain object");
  }
  if (typeof schema.type === "string") {
    var validTypes = ["string", "number", "integer", "boolean",
                      "object", "array", "null"];
    if (validTypes.indexOf(schema.type) === -1) {
      throw new OpenApiError("openapi/bad-schema",
        label + ": invalid type " + JSON.stringify(schema.type));
    }
  }
  if (Array.isArray(schema.type)) {
    for (var i = 0; i < schema.type.length; i += 1) {
      if (typeof schema.type[i] !== "string") {
        throw new OpenApiError("openapi/bad-schema",
          label + ": type[" + i + "] must be a string");
      }
    }
  }
  return true;
}

module.exports = {
  walk:                walk,
  validateJsonSchema:  validateJsonSchema,
  _isSafeSchema:       _isSafeSchema,
  _isJsonSchemaShape:  _isJsonSchemaShape,
  OpenApiError:        OpenApiError,
};

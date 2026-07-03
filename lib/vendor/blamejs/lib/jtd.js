// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.jtd
 * @nav    Data
 * @title  JSON Type Definition
 *
 * @intro
 *   Validate a JSON value against a JSON Type Definition schema (RFC
 *   8927) — a small, portable, cross-implementation schema language.
 *   Unlike the framework's fluent <code>b.safeSchema</code> builder, a
 *   JTD schema is plain JSON you can share with any JTD implementation
 *   (and generate code from), which makes it the right choice for
 *   interop contracts.
 *
 *   <code>validate(schema, instance)</code> returns an array of errors,
 *   each a <code>{ instancePath, schemaPath }</code> pair pointing at the
 *   offending value and the schema rule it broke (an empty array means
 *   valid). All eight schema forms are supported — empty, <code>type</code>,
 *   <code>enum</code>, <code>elements</code>, <code>properties</code>,
 *   <code>values</code>, <code>discriminator</code>, and <code>ref</code>
 *   (with <code>definitions</code>) — and a malformed schema is rejected
 *   at compile time rather than mis-validating.
 *
 * @card
 *   JSON Type Definition (RFC 8927) — validate JSON against a portable,
 *   standardized schema (all eight forms), returning instancePath /
 *   schemaPath errors. The interop-friendly companion to the fluent
 *   <code>b.safeSchema</code> builder.
 */

var { defineClass } = require("./framework-error");
var rfc3339 = require("./rfc3339");

var JtdError = defineClass("JtdError", { alwaysPermanent: true });

var MAX_DEPTH = 10000;

var TYPES = {
  boolean: 1, string: 1, timestamp: 1, float32: 1, float64: 1,
  int8: 1, uint8: 1, int16: 1, uint16: 1, int32: 1, uint32: 1,
};
var INT_RANGES = {
  int8: [-128, 127], uint8: [0, 255], int16: [-32768, 32767],                              // RFC 8927 integer type bounds
  uint16: [0, 65535], int32: [-2147483648, 2147483647], uint32: [0, 4294967295],            // RFC 8927 integer type bounds
};
var FORM_KEYWORDS = ["ref", "type", "enum", "elements", "properties", "optionalProperties", "values", "discriminator"];
var SHARED_KEYWORDS = { definitions: 1, nullable: 1, metadata: 1 };

function _isPlainObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
function _isInteger(v) { return typeof v === "number" && isFinite(v) && Math.floor(v) === v; }

// RFC 3339 date-time (the JTD "timestamp" type) — strict form shared with
// the other spec-driven consumers via lib/rfc3339.js.
var _validTimestamp = rfc3339.isValidDateTime;

// --- compile-time well-formedness (RFC 8927 section 2.2) ---
function _checkSchema(schema, root, isRoot) {
  if (!_isPlainObject(schema)) throw new JtdError("jtd/bad-schema", "jtd: schema must be an object");
  if (!isRoot && Object.prototype.hasOwnProperty.call(schema, "definitions")) throw new JtdError("jtd/bad-schema", "jtd: 'definitions' is allowed only at the root");
  Object.keys(schema).forEach(function (k) {
    if (FORM_KEYWORDS.indexOf(k) === -1 && !Object.prototype.hasOwnProperty.call(SHARED_KEYWORDS, k) && k !== "additionalProperties" && k !== "mapping") throw new JtdError("jtd/bad-schema", "jtd: unknown keyword '" + k + "'");
  });
  if (Object.prototype.hasOwnProperty.call(schema, "nullable") && typeof schema.nullable !== "boolean") throw new JtdError("jtd/bad-schema", "jtd: 'nullable' must be a boolean");
  if (Object.prototype.hasOwnProperty.call(schema, "metadata") && !_isPlainObject(schema.metadata)) throw new JtdError("jtd/bad-schema", "jtd: 'metadata' must be an object");
  if (Object.prototype.hasOwnProperty.call(schema, "definitions")) {
    if (!_isPlainObject(schema.definitions)) throw new JtdError("jtd/bad-schema", "jtd: 'definitions' must be an object");
    Object.keys(schema.definitions).forEach(function (k) { _checkSchema(schema.definitions[k], root, false); });
  }
  if (Object.prototype.hasOwnProperty.call(schema, "mapping") && !Object.prototype.hasOwnProperty.call(schema, "discriminator")) throw new JtdError("jtd/bad-schema", "jtd: 'mapping' is only valid with 'discriminator'");
  var formSet = {};
  FORM_KEYWORDS.forEach(function (k) { if (Object.prototype.hasOwnProperty.call(schema, k)) formSet[(k === "optionalProperties") ? "properties" : k] = 1; });
  var formNames = Object.keys(formSet);
  if (formNames.length > 1) throw new JtdError("jtd/bad-schema", "jtd: a schema may use only one form (got " + formNames.join(", ") + ")");

  if ("ref" in schema) {
    if (typeof schema.ref !== "string" || !root.definitions || !Object.prototype.hasOwnProperty.call(root.definitions, schema.ref)) throw new JtdError("jtd/bad-schema", "jtd: 'ref' must name a key in the root definitions");
  }
  if ("type" in schema && !Object.prototype.hasOwnProperty.call(TYPES, schema.type)) throw new JtdError("jtd/bad-schema", "jtd: unknown type '" + schema.type + "'");
  if ("enum" in schema) {
    if (!Array.isArray(schema.enum) || schema.enum.length === 0) throw new JtdError("jtd/bad-schema", "jtd: 'enum' must be a non-empty array");
    var seen = Object.create(null);
    schema.enum.forEach(function (e) { if (typeof e !== "string") throw new JtdError("jtd/bad-schema", "jtd: 'enum' values must be strings"); if (seen[e]) throw new JtdError("jtd/bad-schema", "jtd: duplicate enum value"); seen[e] = 1; });
  }
  if ("elements" in schema) _checkSchema(schema.elements, root, false);
  if ("values" in schema) _checkSchema(schema.values, root, false);
  if ("properties" in schema || "optionalProperties" in schema) {
    var props = schema.properties || {}, opt = schema.optionalProperties || {};
    if (!_isPlainObject(props) || !_isPlainObject(opt)) throw new JtdError("jtd/bad-schema", "jtd: properties / optionalProperties must be objects");
    Object.keys(props).forEach(function (k) { if (Object.prototype.hasOwnProperty.call(opt, k)) throw new JtdError("jtd/bad-schema", "jtd: '" + k + "' in both properties and optionalProperties"); _checkSchema(props[k], root, false); });
    Object.keys(opt).forEach(function (k) { _checkSchema(opt[k], root, false); });
    if ("additionalProperties" in schema && typeof schema.additionalProperties !== "boolean") throw new JtdError("jtd/bad-schema", "jtd: 'additionalProperties' must be a boolean");
  }
  if ("discriminator" in schema) {
    if (typeof schema.discriminator !== "string") throw new JtdError("jtd/bad-schema", "jtd: 'discriminator' must be a string");
    if (!_isPlainObject(schema.mapping)) throw new JtdError("jtd/bad-schema", "jtd: 'discriminator' requires a 'mapping' object");
    Object.keys(schema.mapping).forEach(function (k) {
      var sub = schema.mapping[k];
      _checkSchema(sub, root, false);
      if (!_isPlainObject(sub) || (!("properties" in sub) && !("optionalProperties" in sub))) throw new JtdError("jtd/bad-schema", "jtd: discriminator mapping schemas must use the properties form");
      if (sub.nullable === true) throw new JtdError("jtd/bad-schema", "jtd: discriminator mapping schemas must not be nullable");
      var p = sub.properties || {}, o = sub.optionalProperties || {};
      if (Object.prototype.hasOwnProperty.call(p, schema.discriminator) || Object.prototype.hasOwnProperty.call(o, schema.discriminator)) throw new JtdError("jtd/bad-schema", "jtd: discriminator tag must not appear in a mapping schema's properties");
    });
  }
  if ("additionalProperties" in schema && !("properties" in schema) && !("optionalProperties" in schema)) throw new JtdError("jtd/bad-schema", "jtd: 'additionalProperties' requires a properties form");
}

// --- validation (RFC 8927 section 3.3) ---
function _typeOk(type, v) {
  if (type === "boolean") return typeof v === "boolean";
  if (type === "string") return typeof v === "string";
  if (type === "timestamp") return typeof v === "string" && _validTimestamp(v);
  if (type === "float32" || type === "float64") return typeof v === "number" && isFinite(v);
  var range = INT_RANGES[type];
  return _isInteger(v) && v >= range[0] && v <= range[1];
}

function _val(schema, inst, ip, sp, root, depth, errors, discrimTag) {
  if (depth > MAX_DEPTH) throw new JtdError("jtd/too-deep", "jtd: schema recursion exceeded the depth cap");
  if (schema.nullable === true && inst === null) return;

  if ("ref" in schema) { _val(root.definitions[schema.ref], inst, ip, ["definitions", schema.ref], root, depth + 1, errors, undefined); return; }

  if ("type" in schema) {
    if (!_typeOk(schema.type, inst)) errors.push({ instancePath: ip.slice(), schemaPath: sp.concat("type") });
    return;
  }
  if ("enum" in schema) {
    if (typeof inst !== "string" || schema.enum.indexOf(inst) === -1) errors.push({ instancePath: ip.slice(), schemaPath: sp.concat("enum") });
    return;
  }
  if ("elements" in schema) {
    if (!Array.isArray(inst)) { errors.push({ instancePath: ip.slice(), schemaPath: sp.concat("elements") }); return; }
    for (var i = 0; i < inst.length; i++) _val(schema.elements, inst[i], ip.concat(String(i)), sp.concat("elements"), root, depth + 1, errors, undefined);
    return;
  }
  if ("properties" in schema || "optionalProperties" in schema) {
    if (!_isPlainObject(inst)) {
      errors.push({ instancePath: ip.slice(), schemaPath: sp.concat("properties" in schema ? "properties" : "optionalProperties") });
      return;
    }
    var props = schema.properties || {}, opt = schema.optionalProperties || {};
    Object.keys(props).forEach(function (k) {
      if (Object.prototype.hasOwnProperty.call(inst, k)) _val(props[k], inst[k], ip.concat(k), sp.concat("properties", k), root, depth + 1, errors, undefined);
      else errors.push({ instancePath: ip.slice(), schemaPath: sp.concat("properties", k) });
    });
    Object.keys(opt).forEach(function (k) {
      if (Object.prototype.hasOwnProperty.call(inst, k)) _val(opt[k], inst[k], ip.concat(k), sp.concat("optionalProperties", k), root, depth + 1, errors, undefined);
    });
    if (schema.additionalProperties !== true) {
      Object.keys(inst).forEach(function (k) {
        if (!Object.prototype.hasOwnProperty.call(props, k) && !Object.prototype.hasOwnProperty.call(opt, k) && k !== discrimTag) {
          errors.push({ instancePath: ip.concat(k), schemaPath: sp.slice() });
        }
      });
    }
    return;
  }
  if ("values" in schema) {
    if (!_isPlainObject(inst)) { errors.push({ instancePath: ip.slice(), schemaPath: sp.concat("values") }); return; }
    Object.keys(inst).forEach(function (k) { _val(schema.values, inst[k], ip.concat(k), sp.concat("values"), root, depth + 1, errors, undefined); });
    return;
  }
  if ("discriminator" in schema) {
    if (!_isPlainObject(inst)) { errors.push({ instancePath: ip.slice(), schemaPath: sp.concat("discriminator") }); return; }
    var tag = schema.discriminator;
    if (!Object.prototype.hasOwnProperty.call(inst, tag)) { errors.push({ instancePath: ip.slice(), schemaPath: sp.concat("discriminator") }); return; }
    if (typeof inst[tag] !== "string") { errors.push({ instancePath: ip.concat(tag), schemaPath: sp.concat("discriminator") }); return; }
    if (!Object.prototype.hasOwnProperty.call(schema.mapping, inst[tag])) { errors.push({ instancePath: ip.concat(tag), schemaPath: sp.concat("mapping") }); return; }
    _val(schema.mapping[inst[tag]], inst, ip, sp.concat("mapping", inst[tag]), root, depth + 1, errors, tag);
    return;
  }
  // empty form: accepts anything
}

/**
 * @primitive b.jtd.validate
 * @signature b.jtd.validate(schema, instance)
 * @since     0.12.62
 * @status    stable
 * @compliance soc2
 * @related   b.safeSchema, b.jsonPointer.get
 *
 * Validate a JSON value against a JSON Type Definition schema (RFC 8927)
 * and return the array of validation errors — each a
 * <code>{ instancePath, schemaPath }</code> pair of token arrays naming
 * the offending value and the schema rule it broke. An empty array means
 * the instance is valid. All eight schema forms are supported. The schema
 * itself is checked for well-formedness first; a malformed schema throws
 * <code>jtd/bad-schema</code> rather than silently mis-validating.
 *
 * @example
 *   b.jtd.validate({ properties: { id: { type: "uint32" } } }, { id: -1 });
 *   // -> [ { instancePath: ["id"], schemaPath: ["properties", "id", "type"] } ]
 */
function validate(schema, instance) {
  _checkSchema(schema, schema, true);
  var errors = [];
  _val(schema, instance, [], [], schema, 0, errors, undefined);
  return errors;
}

/**
 * @primitive b.jtd.isValid
 * @signature b.jtd.isValid(schema, instance)
 * @since     0.12.62
 * @status    stable
 * @related   b.jtd.validate
 *
 * Convenience boolean form of <code>validate</code> — <code>true</code>
 * when the instance conforms to the JTD schema (no errors). Throws
 * <code>jtd/bad-schema</code> on a malformed schema.
 *
 * @example
 *   b.jtd.isValid({ type: "string" }, "hello");   // -> true
 */
function isValid(schema, instance) { return validate(schema, instance).length === 0; }

module.exports = {
  validate: validate,
  isValid:  isValid,
  JtdError: JtdError,
};

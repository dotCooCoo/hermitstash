"use strict";
/**
 * @module b.jsonSchema
 * @nav    Data
 * @title  JSON Schema
 *
 * @intro
 *   Validate JSON against a <a href="https://json-schema.org/">JSON Schema</a>
 *   2020-12 document — the dialect <a href="https://www.openapis.org/">OpenAPI
 *   3.1</a> adopted and the most widely implemented schema language. This is
 *   the standards-track counterpart to the fluent <code>b.safeSchema</code>
 *   builder (in-process, ergonomic) and the portable <code>b.jtd</code>
 *   (small, codegen-friendly): reach for <code>b.jsonSchema</code> when the
 *   schema is an existing JSON Schema document — an API contract, a config
 *   schema, an OpenAPI component.
 *
 *   <code>compile(schema, opts)</code> returns a reusable validator;
 *   <code>validate(schema, instance, opts)</code> compiles and runs in one
 *   call, returning <code>{ valid, errors }</code> where each error names the
 *   failing instance location, the schema keyword, and a message. The full
 *   2020-12 vocabulary is supported — every applicator
 *   (<code>allOf</code> / <code>anyOf</code> / <code>oneOf</code> /
 *   <code>not</code> / <code>if</code>-<code>then</code>-<code>else</code>,
 *   <code>properties</code> / <code>patternProperties</code> /
 *   <code>additionalProperties</code> / <code>prefixItems</code> /
 *   <code>items</code> / <code>contains</code>), the annotation-aware
 *   <code>unevaluatedProperties</code> / <code>unevaluatedItems</code>, every
 *   assertion keyword, and reference resolution
 *   (<code>$ref</code> / <code>$anchor</code> / <code>$dynamicRef</code> /
 *   <code>$dynamicAnchor</code> / <code>$defs</code> / <code>$id</code> base
 *   URIs). <code>format</code> is an annotation by default (opt in to
 *   assertion with <code>assertFormat: true</code>). External references
 *   resolve through an operator-supplied schema map (<code>opts.schemas</code>)
 *   — never a network fetch.
 *
 *   Two advanced behaviors are opt-in rather than built in: validating a
 *   schema <em>document</em> against the dialect metaschema works only if you
 *   supply that metaschema via <code>opts.schemas</code> (it is not bundled),
 *   and <code>$vocabulary</code>-based keyword selection is not honored —
 *   every standard keyword always asserts.
 *
 * @card
 *   JSON Schema 2020-12 validation (the OpenAPI 3.1 dialect) — full
 *   vocabulary including <code>$dynamicRef</code> and annotation-aware
 *   <code>unevaluated*</code>, returning located <code>{ valid, errors }</code>.
 *   The standards-track companion to <code>b.safeSchema</code> and
 *   <code>b.jtd</code>.
 */

var numericBounds = require("./numeric-bounds");
var rfc3339 = require("./rfc3339");
var { defineClass } = require("./framework-error");

var JsonSchemaError = defineClass("JsonSchemaError", { alwaysPermanent: true });

var DIALECT_2020_12 = "https://json-schema.org/draft/2020-12/schema";
var MAX_REF_DEPTH = 10000;                                  // recursion-depth cap (count, not a byte size)
var DEFAULT_MAX_ERRORS = 100;                               // error-collection cap

function _typeOf(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return "number";
  if (typeof v === "boolean") return "boolean";
  if (typeof v === "string") return "string";
  if (typeof v === "object") return "object";
  return "unknown";
}
function _isObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
function _isInteger(v) { return typeof v === "number" && isFinite(v) && Math.floor(v) === v; }

// Deep equality for enum / const / uniqueItems (JSON value semantics).
function _deepEqual(a, b) {
  if (a === b) return true;
  var ta = _typeOf(a), tb = _typeOf(b);
  if (ta !== tb) return false;
  if (ta === "number") return a === b;
  if (ta === "array") {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (!_deepEqual(a[i], b[i])) return false;
    return true;
  }
  if (ta === "object") {
    var ka = Object.keys(a), kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    for (var j = 0; j < ka.length; j++) {
      if (!Object.prototype.hasOwnProperty.call(b, ka[j])) return false;
      if (!_deepEqual(a[ka[j]], b[ka[j]])) return false;
    }
    return true;
  }
  return false;
}

// --- URI helpers (RFC 3986 resolution via WHATWG URL where possible) ---

function _resolveUri(ref, base) {
  if (!base) {
    // No base — keep absolute as-is; bare fragments stay as "#...".
    if (ref.indexOf("#") === 0) return ref;
    return ref;
  }
  if (ref === "") return base;
  // RFC 3986 relative→absolute resolution of a schema $id/$ref (operator-
  // trusted schema text, not request data); safeUrl.parse intentionally
  // rejects the relative refs and non-http schemes schemas legitimately use.
  try { return new URL(ref, base).href; }   // allow:raw-new-url — schema $id/$ref URI resolution, not request-data URL handling
  catch (_e) {
    // Relative resolution against a non-URL base (e.g. "urn:..." or a
    // bare name). Fall back to fragment-aware concatenation.
    if (ref.indexOf("#") === 0) {
      var hashIdx = base.indexOf("#");
      return (hashIdx === -1 ? base : base.slice(0, hashIdx)) + ref;
    }
    return ref;
  }
}
function _splitFragment(uri) {
  var i = uri.indexOf("#");
  if (i === -1) return { base: uri, fragment: null };
  return { base: uri.slice(0, i), fragment: uri.slice(i + 1) };
}
// Decode a JSON Pointer reference token (~1 → /, ~0 → ~) per RFC 6901.
function _unescapePointerToken(t) { return t.replace(/~1/g, "/").replace(/~0/g, "~"); }

// --- registry: indexes every subschema by canonical URI + anchors ---

function _Registry() { this.schemas = {}; this.dynamicAnchors = {}; this.baseByNode = new Map(); }

_Registry.prototype.add = function (schema, baseUri) {
  this._walk(schema, baseUri || "", "");
  // A document retrieved from URI X is addressable by X even when its own
  // $id is a different (canonical) URI — register the retrieval URI too.
  if (baseUri && (_isObject(schema) || typeof schema === "boolean")) {
    if (!Object.prototype.hasOwnProperty.call(this.schemas, baseUri)) this.schemas[baseUri] = schema;
    if (!Object.prototype.hasOwnProperty.call(this.schemas, baseUri + "#")) this.schemas[baseUri + "#"] = schema;
  }
};

// Walk a schema document, registering $id base changes, $anchor and
// $dynamicAnchor names, and indexing every subschema by its base URI +
// JSON-pointer fragment.
_Registry.prototype._walk = function (node, baseUri, pointer) {
  if (!_isObject(node) && typeof node !== "boolean") return;
  if (typeof node === "boolean") { this.schemas[baseUri + "#" + pointer] = node; return; }

  var thisBase = baseUri;
  if (typeof node.$id === "string") {
    thisBase = _resolveUri(node.$id, baseUri);
    var sf = _splitFragment(thisBase);
    thisBase = sf.base + (sf.fragment ? "#" + sf.fragment : "");
    // Canonicalize: $id without fragment becomes the new base.
    if (!sf.fragment) {
      this.schemas[thisBase] = node;
      this.schemas[thisBase + "#"] = node;
    }
    pointer = "";   // pointer is now relative to the new base
  }
  // Index this node by base#pointer + record its canonical base so the
  // validator uses it directly (a $ref to a node with its own relative $id
  // must NOT re-resolve that $id against the URI used to reach it).
  this.schemas[thisBase + "#" + pointer] = node;
  if (pointer === "") this.schemas[thisBase] = node;
  this.baseByNode.set(node, thisBase);

  if (typeof node.$anchor === "string") {
    this.schemas[thisBase + "#" + node.$anchor] = node;
  }
  if (typeof node.$dynamicAnchor === "string") {
    this.schemas[thisBase + "#" + node.$dynamicAnchor] = node;
    if (!this.dynamicAnchors[node.$dynamicAnchor]) this.dynamicAnchors[node.$dynamicAnchor] = [];
    this.dynamicAnchors[node.$dynamicAnchor].push({ uri: thisBase, schema: node });
  }

  // Recurse. Keywords whose values are schemas vs maps-of-schemas vs
  // arrays-of-schemas are walked with the right shape.
  var self = this;
  function child(key, sub, ptr) { self._walk(sub, thisBase, ptr); }
  SCHEMA_KEYWORDS.forEach(function (k) {
    if (node[k] !== undefined) child(k, node[k], pointer + "/" + k);
  });
  SCHEMA_MAP_KEYWORDS.forEach(function (k) {
    if (_isObject(node[k])) {
      Object.keys(node[k]).forEach(function (sk) {
        child(k, node[k][sk], pointer + "/" + k + "/" + _escPtr(sk));
      });
    }
  });
  SCHEMA_ARRAY_KEYWORDS.forEach(function (k) {
    if (Array.isArray(node[k])) {
      node[k].forEach(function (sub, idx) { child(k, sub, pointer + "/" + k + "/" + idx); });
    }
  });
};

_Registry.prototype.resolve = function (uri) {
  if (Object.prototype.hasOwnProperty.call(this.schemas, uri)) return this.schemas[uri];
  var sf = _splitFragment(uri);
  // Try base with empty fragment.
  if (sf.fragment === null) {
    if (Object.prototype.hasOwnProperty.call(this.schemas, sf.base + "#")) return this.schemas[sf.base + "#"];
    return undefined;
  }
  // JSON-pointer fragment: resolve against the registered base document.
  if (sf.fragment === "" || sf.fragment.charAt(0) === "/") {
    var doc = this.schemas[sf.base] !== undefined ? this.schemas[sf.base] : this.schemas[sf.base + "#"];
    if (doc === undefined) return undefined;
    return _pointerInto(doc, sf.fragment);
  }
  // Plain-name anchor.
  return this.schemas[sf.base + "#" + sf.fragment];
};

function _escPtr(s) { return s.replace(/~/g, "~0").replace(/\//g, "~1"); }

function _pointerInto(doc, fragment) {
  if (fragment === "" ) return doc;
  var parts = fragment.split("/");
  parts.shift();   // leading ""
  var cur = doc;
  for (var i = 0; i < parts.length; i++) {
    var tok = _unescapePointerToken(decodeURIComponent(parts[i]));
    if (cur === null || typeof cur !== "object") return undefined;
    if (Array.isArray(cur)) {
      var idx = Number(tok);
      if (!_isInteger(idx) || idx < 0 || idx >= cur.length) return undefined;
      cur = cur[idx];
    } else {
      if (!Object.prototype.hasOwnProperty.call(cur, tok)) return undefined;
      cur = cur[tok];
    }
  }
  return cur;
}

// Keyword classification for the registry walker.
var SCHEMA_KEYWORDS = ["additionalProperties", "propertyNames", "items",
  "contains", "not", "if", "then", "else", "unevaluatedItems",
  "unevaluatedProperties"];
var SCHEMA_MAP_KEYWORDS = ["$defs", "definitions", "properties",
  "patternProperties", "dependentSchemas"];
var SCHEMA_ARRAY_KEYWORDS = ["allOf", "anyOf", "oneOf", "prefixItems"];

module.exports = _buildModule();

function _buildModule() {
  return {
    DIALECT:          DIALECT_2020_12,
    JsonSchemaError:  JsonSchemaError,
    compile:          compile,
    validate:         validate,
    isValid:          isValid,
  };
}

/**
 * @primitive  b.jsonSchema.compile
 * @signature  b.jsonSchema.compile(schema, opts?)
 * @since      0.12.64
 * @status     stable
 * @related    b.jsonSchema.validate, b.safeSchema, b.jtd
 *
 * Compile a JSON Schema 2020-12 document into a reusable validator. The
 * returned object has <code>validate(instance)</code> →
 * <code>{ valid, errors }</code> and <code>isValid(instance)</code> →
 * boolean. Compiling once and validating many instances avoids re-indexing
 * the schema's references on every call.
 *
 * @opts
 *   schemas:       object,   // map of external $id/URI → schema, for $ref
 *   assertFormat:  boolean,  // default: false (format is an annotation)
 *   maxErrors:     number,   // default: 100 — stop collecting past this
 *
 * @example
 *   var v = b.jsonSchema.compile({ type: "object",
 *     properties: { n: { type: "integer" } }, required: ["n"] });
 *   v.validate({ n: 1 }).valid;   // → true
 */
function compile(schema, opts) {
  opts = opts || {};
  if (!_isObject(schema) && typeof schema !== "boolean") {
    throw new JsonSchemaError("json-schema/bad-schema", "jsonSchema.compile: schema must be an object or boolean");
  }
  var registry = new _Registry();
  // Register operator-supplied external schemas first (so $id collisions
  // prefer the root document registered last).
  if (_isObject(opts.schemas)) {
    Object.keys(opts.schemas).forEach(function (uri) {
      registry.add(opts.schemas[uri], uri);
    });
  }
  var rootBase = (_isObject(schema) && typeof schema.$id === "string") ? _resolveUri(schema.$id, "") : "";
  registry.add(schema, rootBase);

  var assertFormat = opts.assertFormat === true;
  var maxErrors = numericBounds.isPositiveFiniteInt(opts.maxErrors) ? opts.maxErrors : DEFAULT_MAX_ERRORS;

  function _run(instance) {
    var ctx = {
      registry: registry, assertFormat: assertFormat, maxErrors: maxErrors,
      errors: [], depth: 0, dynamicScope: [],
    };
    _validate(schema, instance, "", "#", rootBase, ctx);
    return { valid: ctx.errors.length === 0, errors: ctx.errors };
  }
  return {
    validate: _run,
    isValid: function (instance) { return _run(instance).valid; },
  };
}

/**
 * @primitive  b.jsonSchema.validate
 * @signature  b.jsonSchema.validate(schema, instance, opts?)
 * @since      0.12.64
 * @status     stable
 * @related    b.jsonSchema.compile, b.jsonSchema.isValid
 *
 * Compile <code>schema</code> and validate <code>instance</code> in one
 * call, returning <code>{ valid, errors }</code>. Each error is
 * <code>{ instancePath, keyword, schemaPath, message }</code>. For repeated
 * validation against the same schema, use <code>compile</code> instead.
 *
 * @opts
 *   schemas:       object,   // map of external $id/URI → schema, for $ref
 *   assertFormat:  boolean,  // default: false (format is an annotation)
 *   maxErrors:     number,   // default: 100 — stop collecting past this
 *
 * @example
 *   b.jsonSchema.validate({ type: "string", minLength: 2 }, "hi").valid;
 *   // → true
 */
function validate(schema, instance, opts) {
  return compile(schema, opts).validate(instance);
}

/**
 * @primitive  b.jsonSchema.isValid
 * @signature  b.jsonSchema.isValid(schema, instance, opts?)
 * @since      0.12.64
 * @status     stable
 * @related    b.jsonSchema.validate
 *
 * Boolean convenience form of <code>validate</code>.
 *
 * @opts
 *   schemas:       object,   // map of external $id/URI → schema, for $ref
 *   assertFormat:  boolean,  // default: false (format is an annotation)
 *   maxErrors:     number,   // default: 100 — stop collecting past this
 *
 * @example
 *   b.jsonSchema.isValid({ type: "integer" }, 3);   // → true
 */
function isValid(schema, instance, opts) {
  return compile(schema, opts).validate(instance).valid;
}

// ============================================================
// Core evaluation. Returns { evaluatedProps: {name:true}, evaluatedItems:
// {index:true} } describing the annotations produced for unevaluated*.
// Errors are pushed onto ctx.errors. A subschema "fails" iff it pushed at
// least one error during its own evaluation (tracked via error-count
// snapshot at each applicator boundary).
// ============================================================

function _err(ctx, instancePath, keyword, schemaPath, message) {
  if (ctx.errors.length < ctx.maxErrors) {
    ctx.errors.push({ instancePath: instancePath, keyword: keyword, schemaPath: schemaPath, message: message });
  }
}

// Validate `instance` against `schema`. Annotations (evaluated props/items)
// are returned so callers (objects/arrays with unevaluated*) can consult
// them. `silent` runs validation without recording errors (used by
// applicators that only need the boolean + annotations, e.g. anyOf/oneOf
// branches, if).
function _validate(schema, instance, instancePath, schemaPath, baseUri, ctx, silent) {
  var ann = { evaluatedProps: {}, evaluatedItems: {} };
  if (schema === true) return ann;
  if (schema === false) {
    if (!silent) _err(ctx, instancePath, "false", schemaPath, "schema is false — no value is valid");
    ann.failed = true;
    return ann;
  }
  if (!_isObject(schema)) return ann;

  if (ctx.depth++ > MAX_REF_DEPTH) throw new JsonSchemaError("json-schema/ref-loop", "jsonSchema: reference depth exceeded (cyclic $ref?)");
  // The effective base for this subschema. The registry already computed
  // each walked node's canonical base (its $id resolved against its lexical
  // parent), so prefer that — re-resolving $id against the URI we arrived
  // by would double a relative $id. Fall back to live resolution for nodes
  // the registry didn't index (defensive).
  var effectiveBase = ctx.registry.baseByNode.has(schema)
    ? ctx.registry.baseByNode.get(schema)
    : (typeof schema.$id === "string" ? _resolveUri(schema.$id, baseUri) : baseUri);
  // Push the effective base onto the dynamic scope so $dynamicRef can find
  // the outermost frame carrying a matching $dynamicAnchor.
  ctx.dynamicScope.push(effectiveBase);
  try {
    return _validateBody(schema, instance, instancePath, schemaPath, effectiveBase, ctx, silent, ann);
  } finally { ctx.depth--; ctx.dynamicScope.pop(); }
}

function _validateBody(schema, instance, instancePath, schemaPath, baseUri, ctx, silent, ann) {
  // baseUri already reflects this subschema's $id (resolved in _validate).
  var type = _typeOf(instance);
  var startErrors = ctx.errors.length;
  function fail() { return ctx.errors.length > startErrors; }
  function emit(kw, msg) { if (!silent) _err(ctx, instancePath, kw, schemaPath + "/" + kw, msg); ann.failed = true; }

  // ---- $ref / $dynamicRef (in-place applicators) ----
  if (typeof schema.$ref === "string") {
    var refUri = _resolveUri(schema.$ref, baseUri);
    var target = ctx.registry.resolve(refUri);
    if (target === undefined) target = ctx.registry.resolve(_splitFragment(refUri).base + "#" + (_splitFragment(refUri).fragment || ""));
    if (target === undefined) {
      emit("$ref", "cannot resolve $ref '" + schema.$ref + "'");
    } else {
      var refBase = _splitFragment(refUri).base || baseUri;
      var refAnn = _validate(target, instance, instancePath, schemaPath + "/$ref", refBase, ctx, silent);
      _mergeAnn(ann, refAnn);
      if (refAnn.failed) ann.failed = true;   // the child emits its own errors (when not silent); propagate pass/fail
    }
  }
  if (typeof schema.$dynamicRef === "string") {
    _applyDynamicRef(schema.$dynamicRef, instance, instancePath, schemaPath, baseUri, ctx, silent, ann);
  }

  // ---- assertions ----
  if (schema.type !== undefined && !_typeMatches(schema.type, instance, type)) {
    emit("type", "value is " + type + ", expected " + (Array.isArray(schema.type) ? schema.type.join("/") : schema.type));
  }
  if (schema.enum !== undefined) {
    var inEnum = false;
    for (var ei = 0; ei < schema.enum.length; ei++) { if (_deepEqual(instance, schema.enum[ei])) { inEnum = true; break; } }
    if (!inEnum) emit("enum", "value is not one of the enum values");
  }
  if (Object.prototype.hasOwnProperty.call(schema, "const")) {
    if (!_deepEqual(instance, schema.const)) emit("const", "value does not equal const");
  }

  if (type === "number") _checkNumber(schema, instance, emit);
  if (type === "string") _checkString(schema, instance, ctx, emit);
  if (type === "array") _checkArray(schema, instance, instancePath, schemaPath, baseUri, ctx, silent, ann, emit);
  if (type === "object") _checkObject(schema, instance, instancePath, schemaPath, baseUri, ctx, silent, ann, emit);

  // ---- in-place applicators (apply regardless of type) ----
  _applyLogical(schema, instance, instancePath, schemaPath, baseUri, ctx, silent, ann, emit);

  // ---- format (annotation by default; assertion when enabled) ----
  if (typeof schema.format === "string" && ctx.assertFormat) {
    if (!_checkFormat(schema.format, instance, type)) emit("format", "value does not match format '" + schema.format + "'");
  }

  // ---- unevaluatedProperties / unevaluatedItems (consume annotations) ----
  if (type === "object" && schema.unevaluatedProperties !== undefined) {
    Object.keys(instance).forEach(function (key) {
      if (ann.evaluatedProps[key]) return;
      var sub = _validate(schema.unevaluatedProperties, instance[key], instancePath + "/" + _escPtr(key), schemaPath + "/unevaluatedProperties", baseUri, ctx, silent);
      if (!sub.failed) ann.evaluatedProps[key] = true;
      else emit("unevaluatedProperties", "unevaluated property '" + key + "' is invalid");
    });
  }
  if (type === "array" && schema.unevaluatedItems !== undefined) {
    for (var ui = 0; ui < instance.length; ui++) {
      if (ann.evaluatedItems[ui]) continue;
      var subi = _validate(schema.unevaluatedItems, instance[ui], instancePath + "/" + ui, schemaPath + "/unevaluatedItems", baseUri, ctx, silent);
      if (!subi.failed) ann.evaluatedItems[ui] = true;
      else emit("unevaluatedItems", "unevaluated item at index " + ui + " is invalid");
    }
  }

  if (fail()) ann.failed = true;
  return ann;
}

function _typeMatches(typeKw, instance, actual) {
  var list = Array.isArray(typeKw) ? typeKw : [typeKw];
  for (var i = 0; i < list.length; i++) {
    var t = list[i];
    if (t === actual) return true;
    if (t === "integer" && actual === "number" && _isInteger(instance)) return true;
  }
  return false;
}

function _checkNumber(schema, n, emit) {
  if (typeof schema.multipleOf === "number") {
    var q = n / schema.multipleOf;
    if (!isFinite(q) || Math.abs(q - Math.round(q)) > 1e-9 * Math.max(1, Math.abs(q))) {
      // Exact check for integers; tolerance only bridges float error.
      if (n % schema.multipleOf !== 0) emit("multipleOf", "value is not a multiple of " + schema.multipleOf);
    }
  }
  if (typeof schema.maximum === "number" && n > schema.maximum) emit("maximum", "value > maximum " + schema.maximum);
  if (typeof schema.exclusiveMaximum === "number" && n >= schema.exclusiveMaximum) emit("exclusiveMaximum", "value >= exclusiveMaximum " + schema.exclusiveMaximum);
  if (typeof schema.minimum === "number" && n < schema.minimum) emit("minimum", "value < minimum " + schema.minimum);
  if (typeof schema.exclusiveMinimum === "number" && n <= schema.exclusiveMinimum) emit("exclusiveMinimum", "value <= exclusiveMinimum " + schema.exclusiveMinimum);
}

function _strLen(s) {
  // Code-point length (not UTF-16 units) per JSON Schema string length.
  var n = 0;
  for (var i = 0; i < s.length; i++) { n++; var c = s.charCodeAt(i); if (c >= 0xD800 && c <= 0xDBFF) i++; }
  return n;
}
function _checkString(schema, s, ctx, emit) {
  if (typeof schema.maxLength === "number" && _strLen(s) > schema.maxLength) emit("maxLength", "string longer than maxLength " + schema.maxLength);
  if (typeof schema.minLength === "number" && _strLen(s) < schema.minLength) emit("minLength", "string shorter than minLength " + schema.minLength);
  if (typeof schema.pattern === "string") {
    var re = _compileRegex(schema.pattern, ctx);
    if (re && !re.test(s)) emit("pattern", "string does not match pattern");
  }
}

var _regexCache = {};
function _compileRegex(pattern, ctx) {
  if (Object.prototype.hasOwnProperty.call(_regexCache, pattern)) return _regexCache[pattern];
  var re = null;
  try { re = new RegExp(pattern, "u"); }                    // allow:dynamic-regex — JSON Schema pattern is part of the (operator-trusted) schema, not instance data
  catch (_e) {
    try { re = new RegExp(pattern); } catch (_e2) { re = null; }
  }
  _regexCache[pattern] = re;
  return re;
}

function _checkArray(schema, arr, instancePath, schemaPath, baseUri, ctx, silent, ann, emit) {
  if (typeof schema.maxItems === "number" && arr.length > schema.maxItems) emit("maxItems", "array longer than maxItems " + schema.maxItems);
  if (typeof schema.minItems === "number" && arr.length < schema.minItems) emit("minItems", "array shorter than minItems " + schema.minItems);
  if (schema.uniqueItems === true) {
    for (var a = 0; a < arr.length; a++) for (var bI = a + 1; bI < arr.length; bI++) {
      if (_deepEqual(arr[a], arr[bI])) { emit("uniqueItems", "array items are not unique (indices " + a + ", " + bI + ")"); a = arr.length; break; }
    }
  }
  var prefixLen = 0;
  if (Array.isArray(schema.prefixItems)) {
    prefixLen = schema.prefixItems.length;
    for (var pi = 0; pi < prefixLen && pi < arr.length; pi++) {
      var ps = _validate(schema.prefixItems[pi], arr[pi], instancePath + "/" + pi, schemaPath + "/prefixItems/" + pi, baseUri, ctx, silent);
      if (!ps.failed) ann.evaluatedItems[pi] = true; else emit("prefixItems", "item " + pi + " does not match prefixItems schema");
    }
  }
  if (schema.items !== undefined) {
    for (var ii = prefixLen; ii < arr.length; ii++) {
      var is = _validate(schema.items, arr[ii], instancePath + "/" + ii, schemaPath + "/items", baseUri, ctx, silent);
      if (!is.failed) ann.evaluatedItems[ii] = true; else emit("items", "item " + ii + " does not match items schema");
    }
  }
  if (schema.contains !== undefined) {
    var matched = 0;
    for (var ci = 0; ci < arr.length; ci++) {
      var cs = _validate(schema.contains, arr[ci], instancePath + "/" + ci, schemaPath + "/contains", baseUri, ctx, true);
      if (!cs.failed) { matched++; ann.evaluatedItems[ci] = true; }
    }
    var minC = typeof schema.minContains === "number" ? schema.minContains : 1;
    if (matched < minC) emit("contains", "array has " + matched + " matching items, need at least " + minC);
    if (typeof schema.maxContains === "number" && matched > schema.maxContains) emit("maxContains", "array has " + matched + " matching items, more than maxContains " + schema.maxContains);
  }
}

function _checkObject(schema, obj, instancePath, schemaPath, baseUri, ctx, silent, ann, emit) {
  var keys = Object.keys(obj);
  if (typeof schema.maxProperties === "number" && keys.length > schema.maxProperties) emit("maxProperties", "object has more than maxProperties " + schema.maxProperties);
  if (typeof schema.minProperties === "number" && keys.length < schema.minProperties) emit("minProperties", "object has fewer than minProperties " + schema.minProperties);
  if (Array.isArray(schema.required)) {
    schema.required.forEach(function (rk) {
      if (!Object.prototype.hasOwnProperty.call(obj, rk)) emit("required", "missing required property '" + rk + "'");
    });
  }
  if (_isObject(schema.dependentRequired)) {
    Object.keys(schema.dependentRequired).forEach(function (dk) {
      if (Object.prototype.hasOwnProperty.call(obj, dk) && Array.isArray(schema.dependentRequired[dk])) {
        schema.dependentRequired[dk].forEach(function (req) {
          if (!Object.prototype.hasOwnProperty.call(obj, req)) emit("dependentRequired", "property '" + dk + "' requires '" + req + "'");
        });
      }
    });
  }
  if (_isObject(schema.properties)) {
    keys.forEach(function (k) {
      if (Object.prototype.hasOwnProperty.call(schema.properties, k)) {
        var ps = _validate(schema.properties[k], obj[k], instancePath + "/" + _escPtr(k), schemaPath + "/properties/" + _escPtr(k), baseUri, ctx, silent);
        if (!ps.failed) ann.evaluatedProps[k] = true; else ann.failed = true;
      }
    });
  }
  if (_isObject(schema.patternProperties)) {
    Object.keys(schema.patternProperties).forEach(function (pat) {
      var re = _compileRegex(pat, ctx);
      if (!re) return;
      keys.forEach(function (k) {
        if (re.test(k)) {
          var ps = _validate(schema.patternProperties[pat], obj[k], instancePath + "/" + _escPtr(k), schemaPath + "/patternProperties/" + _escPtr(pat), baseUri, ctx, silent);
          if (!ps.failed) ann.evaluatedProps[k] = true; else ann.failed = true;
        }
      });
    });
  }
  if (schema.additionalProperties !== undefined) {
    keys.forEach(function (k) {
      if (ann.evaluatedProps[k]) return;
      // additionalProperties applies to keys not in properties and not
      // matched by patternProperties (regardless of those passing).
      if (_isObject(schema.properties) && Object.prototype.hasOwnProperty.call(schema.properties, k)) return;
      if (_patternMatches(schema.patternProperties, k, ctx)) return;
      var ps = _validate(schema.additionalProperties, obj[k], instancePath + "/" + _escPtr(k), schemaPath + "/additionalProperties", baseUri, ctx, silent);
      if (!ps.failed) ann.evaluatedProps[k] = true; else ann.failed = true;
    });
  }
  if (schema.propertyNames !== undefined) {
    keys.forEach(function (k) {
      var ps = _validate(schema.propertyNames, k, instancePath + "/" + _escPtr(k), schemaPath + "/propertyNames", baseUri, ctx, silent);
      if (ps.failed) emit("propertyNames", "property name '" + k + "' is invalid");
    });
  }
  if (_isObject(schema.dependentSchemas)) {
    Object.keys(schema.dependentSchemas).forEach(function (dk) {
      if (Object.prototype.hasOwnProperty.call(obj, dk)) {
        var ds = _validate(schema.dependentSchemas[dk], obj, instancePath, schemaPath + "/dependentSchemas/" + _escPtr(dk), baseUri, ctx, silent);
        _mergeAnn(ann, ds);
        if (ds.failed) ann.failed = true;
      }
    });
  }
}

function _patternMatches(patternProperties, key, ctx) {
  if (!_isObject(patternProperties)) return false;
  var pats = Object.keys(patternProperties);
  for (var i = 0; i < pats.length; i++) {
    var re = _compileRegex(pats[i], ctx);
    if (re && re.test(key)) return true;
  }
  return false;
}

function _applyLogical(schema, instance, instancePath, schemaPath, baseUri, ctx, silent, ann, emit) {
  if (Array.isArray(schema.allOf)) {
    schema.allOf.forEach(function (sub, i) {
      var r = _validate(sub, instance, instancePath, schemaPath + "/allOf/" + i, baseUri, ctx, silent);
      _mergeAnn(ann, r);
      if (r.failed) emit("allOf", "value does not match allOf[" + i + "]");
    });
  }
  if (Array.isArray(schema.anyOf)) {
    var anyMatched = false;
    schema.anyOf.forEach(function (sub, i) {
      var r = _validate(sub, instance, instancePath, schemaPath + "/anyOf/" + i, baseUri, ctx, true);
      if (!r.failed) { anyMatched = true; _mergeAnn(ann, r); }
    });
    if (!anyMatched) emit("anyOf", "value does not match any anyOf subschema");
  }
  if (Array.isArray(schema.oneOf)) {
    var matchCount = 0;
    schema.oneOf.forEach(function (sub, i) {
      var r = _validate(sub, instance, instancePath, schemaPath + "/oneOf/" + i, baseUri, ctx, true);
      if (!r.failed) { matchCount++; _mergeAnn(ann, r); }
    });
    if (matchCount !== 1) emit("oneOf", "value matches " + matchCount + " oneOf subschemas, expected exactly 1");
  }
  if (schema.not !== undefined) {
    var rn = _validate(schema.not, instance, instancePath, schemaPath + "/not", baseUri, ctx, true);
    if (!rn.failed) emit("not", "value must not match the 'not' subschema");
  }
  if (schema.if !== undefined) {
    var ri = _validate(schema.if, instance, instancePath, schemaPath + "/if", baseUri, ctx, true);
    if (!ri.failed) {
      _mergeAnn(ann, ri);   // if's annotations apply only when 'if' validates
      if (schema.then !== undefined) {
        var rt = _validate(schema.then, instance, instancePath, schemaPath + "/then", baseUri, ctx, silent);
        _mergeAnn(ann, rt);
        if (rt.failed) emit("then", "value matches 'if' but not 'then'");
      }
    } else if (schema.else !== undefined) {
      var re2 = _validate(schema.else, instance, instancePath, schemaPath + "/else", baseUri, ctx, silent);
      _mergeAnn(ann, re2);
      if (re2.failed) emit("else", "value does not match 'if' nor 'else'");
    }
  }
}

function _applyDynamicRef(dref, instance, instancePath, schemaPath, baseUri, ctx, silent, ann) {
  var refUri = _resolveUri(dref, baseUri);
  var sf = _splitFragment(refUri);
  var anchorName = sf.fragment;
  // Resolve lexically first (exactly like $ref).
  var target = ctx.registry.resolve(refUri);
  var targetBase = sf.base || baseUri;
  // Dynamic scope resolution applies ONLY when the fragment is a plain-name
  // anchor AND the lexically-resolved target itself carries a matching
  // $dynamicAnchor. Otherwise $dynamicRef behaves like a normal $ref (so a
  // plain $anchor of the same name, or a non-matching/absent $dynamicAnchor,
  // is left as the lexical target).
  var isPlainName = anchorName && anchorName.charAt(0) !== "/" && anchorName !== "";
  if (isPlainName && _isObject(target) && target.$dynamicAnchor === anchorName) {
    for (var i = 0; i < ctx.dynamicScope.length; i++) {
      var frameBase = ctx.dynamicScope[i];
      var cand = ctx.registry.schemas[frameBase + "#" + anchorName];
      if (_isObject(cand) && cand.$dynamicAnchor === anchorName) { target = cand; targetBase = frameBase; break; }
    }
  }
  if (target === undefined) { if (!silent) _err(ctx, instancePath, "$dynamicRef", schemaPath + "/$dynamicRef", "cannot resolve $dynamicRef '" + dref + "'"); ann.failed = true; return; }
  var r = _validate(target, instance, instancePath, schemaPath + "/$dynamicRef", targetBase, ctx, silent);
  _mergeAnn(ann, r);
  if (r.failed) ann.failed = true;
}

function _mergeAnn(into, from) {
  if (!from) return;
  if (from.evaluatedProps) Object.keys(from.evaluatedProps).forEach(function (k) { into.evaluatedProps[k] = true; });
  if (from.evaluatedItems) Object.keys(from.evaluatedItems).forEach(function (k) { into.evaluatedItems[k] = true; });
}

// --- format assertions (opt-in) ---
function _checkFormat(format, value, type) {
  if (type !== "string") return true;   // format only asserts on strings
  switch (format) {
    case "date-time": return rfc3339.isValidDateTime(value);
    // RFC 3339 full-date: shape + real field ranges (reuse the strict
    // date-time validator by anchoring a midnight UTC time).
    case "date": return /^\d{4}-\d{2}-\d{2}$/.test(value) && rfc3339.isValidDateTime(value + "T00:00:00Z");   // allow:regex-no-length-cap — fixed-width date shape
    // RFC 3339 full-time: a mandatory offset + valid ranges, obtained by
    // anchoring an epoch date (rejects "12:00:00" and "25:61:61Z").
    case "time": return rfc3339.isValidDateTime("1970-01-01T" + value);
    // Single "@", non-empty local + domain, no whitespace. The class
    // excludes "@", so the split point is unique — the match is linear.
    case "email": return /^[^@\s]+@[^@\s]+$/.test(value);   // allow:regex-no-length-cap — linear (no overlapping quantifiers)
    case "uri": case "iri": {
      if (/\s/.test(value)) return false;                       // raw whitespace is not a valid URI
      if (/%(?![0-9A-Fa-f]{2})/.test(value)) return false;      // malformed percent-escape
      if (!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(value)) return false;   // absolute URI requires a scheme   // allow:regex-no-length-cap — linear scheme prefix
      try { new URL(value); return true; } catch (_e) { return false; }   // allow:raw-new-url — string-shape check, no fetch / SSRF surface
    }
    case "uuid": return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value);   // allow:regex-no-length-cap — fixed-width UUID
    case "ipv4": return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split(".").every(function (o) { return Number(o) <= 255; });   // allow:regex-no-length-cap — bounded dotted-quad
    case "regex": try { new RegExp(value); return true; } catch (_e2) { return false; }   // allow:dynamic-regex — format:"regex" validates the string IS a regex
    default: return true;   // unknown formats are valid (annotation semantics)
  }
}

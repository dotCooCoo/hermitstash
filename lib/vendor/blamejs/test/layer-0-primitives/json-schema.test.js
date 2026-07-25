// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.jsonSchema (JSON Schema 2020-12).
 * Oracle: the official json-schema-org/JSON-Schema-Test-Suite draft2020-12
 * (1292 of 1295 cases pass during development; the 3 skipped require the
 * bundled dialect metaschema or $vocabulary selection — both opt-in). This
 * file embeds a representative slice across the vocabulary plus the surface
 * + reference-resolution + annotation cases that exercise the tricky paths.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testSurface() {
  check("b.jsonSchema.validate is a function", typeof b.jsonSchema.validate === "function");
  check("b.jsonSchema.compile is a function", typeof b.jsonSchema.compile === "function");
  check("b.jsonSchema.isValid is a function", typeof b.jsonSchema.isValid === "function");
  check("b.jsonSchema.DIALECT is 2020-12", b.jsonSchema.DIALECT === "https://json-schema.org/draft/2020-12/schema");
  check("b.jsonSchema.JsonSchemaError is a class", typeof b.jsonSchema.JsonSchemaError === "function");
  check("compile rejects non-schema", code(function () { b.jsonSchema.compile(42); }) === "json-schema/bad-schema");
  var v = b.jsonSchema.compile({ type: "integer" });
  check("compiled validator has validate + isValid", typeof v.validate === "function" && typeof v.isValid === "function");
}

function testAssertions() {
  check("type integer accepts int", b.jsonSchema.isValid({ type: "integer" }, 3));
  check("type integer rejects float", !b.jsonSchema.isValid({ type: "integer" }, 3.5));
  check("type rejects wrong type", !b.jsonSchema.isValid({ type: "string" }, 1));
  check("enum", b.jsonSchema.isValid({ enum: ["a", "b"] }, "b") && !b.jsonSchema.isValid({ enum: ["a"] }, "z"));
  check("const deep-equal", b.jsonSchema.isValid({ const: { a: [1, 2] } }, { a: [1, 2] }) && !b.jsonSchema.isValid({ const: { a: [1] } }, { a: [2] }));
  check("multipleOf", b.jsonSchema.isValid({ multipleOf: 3 }, 9) && !b.jsonSchema.isValid({ multipleOf: 3 }, 10));
  check("maximum/exclusiveMaximum", b.jsonSchema.isValid({ maximum: 5 }, 5) && !b.jsonSchema.isValid({ exclusiveMaximum: 5 }, 5));
  check("minLength counts code points", !b.jsonSchema.isValid({ minLength: 2 }, "😀") && b.jsonSchema.isValid({ maxLength: 1 }, "😀"));
  check("pattern", b.jsonSchema.isValid({ pattern: "^a+$" }, "aaa") && !b.jsonSchema.isValid({ pattern: "^a+$" }, "b"));
}

function testArrays() {
  check("prefixItems + items", b.jsonSchema.isValid({ prefixItems: [{ type: "number" }], items: { type: "string" } }, [1, "a", "b"]));
  check("items rejects bad tail", !b.jsonSchema.isValid({ prefixItems: [{ type: "number" }], items: { type: "string" } }, [1, 2]));
  check("uniqueItems", b.jsonSchema.isValid({ uniqueItems: true }, [1, 2, 3]) && !b.jsonSchema.isValid({ uniqueItems: true }, [1, 1]));
  check("contains + minContains", b.jsonSchema.isValid({ contains: { const: 2 }, minContains: 2 }, [2, 2, 3]) && !b.jsonSchema.isValid({ contains: { const: 2 }, minContains: 2 }, [2, 3]));
  check("maxItems/minItems", !b.jsonSchema.isValid({ maxItems: 1 }, [1, 2]) && !b.jsonSchema.isValid({ minItems: 2 }, [1]));
}

function testObjects() {
  var s = { type: "object", properties: { n: { type: "integer" } }, required: ["n"], additionalProperties: false };
  check("properties + required pass", b.jsonSchema.isValid(s, { n: 1 }));
  check("required missing fails", !b.jsonSchema.isValid(s, {}));
  check("additionalProperties:false rejects extra", !b.jsonSchema.isValid(s, { n: 1, x: 2 }));
  check("patternProperties", b.jsonSchema.isValid({ patternProperties: { "^x": { type: "number" } } }, { x1: 1 }) && !b.jsonSchema.isValid({ patternProperties: { "^x": { type: "number" } } }, { x1: "a" }));
  check("propertyNames", !b.jsonSchema.isValid({ propertyNames: { pattern: "^a" } }, { b: 1 }));
  check("dependentRequired", !b.jsonSchema.isValid({ dependentRequired: { a: ["b"] } }, { a: 1 }));
  check("dependentSchemas", !b.jsonSchema.isValid({ dependentSchemas: { a: { required: ["b"] } } }, { a: 1 }));
}

function testApplicators() {
  check("allOf", b.jsonSchema.isValid({ allOf: [{ type: "number" }, { minimum: 0 }] }, 5) && !b.jsonSchema.isValid({ allOf: [{ type: "number" }, { minimum: 0 }] }, -1));
  check("anyOf", b.jsonSchema.isValid({ anyOf: [{ type: "string" }, { type: "number" }] }, 1) && !b.jsonSchema.isValid({ anyOf: [{ type: "string" }] }, 1));
  check("oneOf exactly one", b.jsonSchema.isValid({ oneOf: [{ multipleOf: 2 }, { multipleOf: 3 }] }, 4) && !b.jsonSchema.isValid({ oneOf: [{ multipleOf: 2 }, { multipleOf: 3 }] }, 6));
  check("not", b.jsonSchema.isValid({ not: { type: "string" } }, 1) && !b.jsonSchema.isValid({ not: { type: "string" } }, "x"));
  check("if/then/else", b.jsonSchema.isValid({ if: { type: "number" }, then: { minimum: 0 }, else: { type: "string" } }, 5) && b.jsonSchema.isValid({ if: { type: "number" }, then: { minimum: 0 }, else: { type: "string" } }, "x") && !b.jsonSchema.isValid({ if: { type: "number" }, then: { minimum: 0 } }, -1));
  check("boolean schema true/false", b.jsonSchema.isValid(true, 42) && !b.jsonSchema.isValid(false, 42));
}

function testUnevaluated() {
  // unevaluatedProperties sees annotations from $ref inside allOf.
  var s = {
    $defs: { one: { properties: { a: true } } },
    allOf: [{ $ref: "#/$defs/one" }, { properties: { b: true } }],
    unevaluatedProperties: false,
  };
  check("unevaluatedProperties + ref-in-allOf accepts evaluated", b.jsonSchema.isValid(s, { a: 1, b: 2 }));
  check("unevaluatedProperties + ref-in-allOf rejects unevaluated", !b.jsonSchema.isValid(s, { a: 1, c: 3 }));
  check("unevaluatedItems", b.jsonSchema.isValid({ prefixItems: [{ type: "number" }], unevaluatedItems: false }, [1]) && !b.jsonSchema.isValid({ prefixItems: [{ type: "number" }], unevaluatedItems: false }, [1, 2]));
}

function testRefs() {
  // $ref to $defs + $anchor.
  check("$ref to $defs", b.jsonSchema.isValid({ $defs: { pos: { minimum: 0 } }, $ref: "#/$defs/pos" }, 5));
  check("$anchor ref", b.jsonSchema.isValid({ $defs: { p: { $anchor: "pos", minimum: 0 } }, $ref: "#pos" }, 5));
  // External schema via opts.schemas (no network).
  var ext = { "https://example.com/int": { type: "integer" } };
  check("external $ref via opts.schemas", b.jsonSchema.isValid({ $ref: "https://example.com/int" }, 3, { schemas: ext }));
  check("external $ref rejects", !b.jsonSchema.isValid({ $ref: "https://example.com/int" }, "x", { schemas: ext }));
  // $dynamicRef / $dynamicAnchor (the recursive bookend pattern).
  var dyn = {
    $id: "https://example.com/tree",
    $dynamicAnchor: "node",
    type: "object",
    properties: { data: true, children: { type: "array", items: { $dynamicRef: "#node" } } },
  };
  check("$dynamicRef recursion validates", b.jsonSchema.isValid(dyn, { data: 1, children: [{ data: 2, children: [] }] }));
}

function testErrorsShape() {
  var r = b.jsonSchema.validate({ type: "object", properties: { n: { type: "integer" } } }, { n: "bad" });
  check("validate returns {valid, errors}", r.valid === false && Array.isArray(r.errors) && r.errors.length >= 1);
  check("error names instancePath + keyword", r.errors[0].instancePath === "/n" && r.errors[0].keyword === "type");
}

function testFormat() {
  // format is an annotation by default (does not assert).
  check("format annotation by default", b.jsonSchema.isValid({ type: "string", format: "email" }, "not-an-email"));
  // assertFormat:true turns it into an assertion.
  check("assertFormat rejects bad email", !b.jsonSchema.isValid({ type: "string", format: "email" }, "nope", { assertFormat: true }));
  check("assertFormat accepts good date-time", b.jsonSchema.isValid({ type: "string", format: "date-time" }, "2020-01-01T00:00:00Z", { assertFormat: true }));
  // time requires an offset and valid ranges (RFC 3339 full-time).
  check("time rejects missing offset", !b.jsonSchema.isValid({ format: "time" }, "12:00:00", { assertFormat: true }));
  check("time rejects out-of-range", !b.jsonSchema.isValid({ format: "time" }, "25:61:61Z", { assertFormat: true }));
  check("time accepts offset form", b.jsonSchema.isValid({ format: "time" }, "12:00:00+05:30", { assertFormat: true }));
  // date enforces real field ranges.
  check("date rejects month 13", !b.jsonSchema.isValid({ format: "date" }, "2020-13-01", { assertFormat: true }));
  check("date accepts valid", b.jsonSchema.isValid({ format: "date" }, "2020-02-29", { assertFormat: true }));
  // uri rejects raw spaces and relative refs.
  check("uri rejects raw space", !b.jsonSchema.isValid({ format: "uri" }, "http://e xample.com", { assertFormat: true }));
  check("uri rejects relative", !b.jsonSchema.isValid({ format: "uri" }, "/relative/path", { assertFormat: true }));
  check("uri accepts absolute", b.jsonSchema.isValid({ format: "uri" }, "https://example.com/x", { assertFormat: true }));
}

function testDepthCap() {
  // validate(schema, instance) recurses one level per nested subschema
  // application. A recursive schema (items:{$ref:"#"}) against a deeply
  // nested instance — both attacker-controlled when validating a request
  // body — would overflow the V8 stack with an uncaught RangeError before
  // the depth guard fired (its cap was set above native overflow). The cap
  // is now well under overflow so the typed json-schema/ref-loop error
  // surfaces instead of a crash, while legitimate nesting (deep or wide)
  // still validates.
  var recursive = { $schema: b.jsonSchema.DIALECT, type: "array", items: { $ref: "#" } };
  function deepArr(n) { var a = [], c = a; for (var i = 0; i < n; i++) { var n2 = []; c.push(n2); c = n2; } return a; }
  check("validate: deeply nested instance throws typed ref-loop (not RangeError)",
    code(function () { b.jsonSchema.validate(recursive, deepArr(1500)); }) === "json-schema/ref-loop");
  // Legit shallow nesting validates clean.
  check("validate: shallow nesting still validates", b.jsonSchema.validate(recursive, deepArr(40)).valid === true);
  // Breadth must not trip the nesting cap (sibling properties do not
  // accumulate depth).
  var wide = { type: "object", properties: {} }; var obj = {};
  for (var k = 0; k < 400; k++) { wide.properties["p" + k] = { type: "integer" }; obj["p" + k] = k; }
  check("validate: wide-but-shallow object does not trip the depth cap",
    b.jsonSchema.validate(wide, obj).valid === true);
}

function testInstanceTypes() {
  // _typeOf across every JSON type + the "unknown" fallback (undefined).
  check("null instance matches type:null", b.jsonSchema.isValid({ type: "null" }, null));
  check("null rejected by type:string", !b.jsonSchema.isValid({ type: "string" }, null));
  check("boolean instance matches type:boolean", b.jsonSchema.isValid({ type: "boolean" }, true));
  check("array instance matches type:array", b.jsonSchema.isValid({ type: "array" }, [1, 2]));
  check("object instance matches type:object", b.jsonSchema.isValid({ type: "object" }, { a: 1 }));
  // undefined has no JSON type ("unknown"); an empty schema accepts it but a
  // typed schema rejects it (the type never matches "unknown").
  check("undefined accepted by empty schema", b.jsonSchema.isValid({}, undefined));
  check("undefined rejected by type:string", !b.jsonSchema.isValid({ type: "string" }, undefined));
  // type as an array — a match plus the joined mismatch message.
  check("type array matches a member", b.jsonSchema.isValid({ type: ["string", "number"] }, 5));
  var r = b.jsonSchema.validate({ type: ["string", "number"] }, true);
  check("type array mismatch names both", !r.valid && r.errors[0].keyword === "type" && r.errors[0].message.indexOf("string/number") >= 0);
}

function testDeepEqualEdges() {
  // const uses JSON deep-equality — exercise each early-out branch.
  check("const type-mismatch fails", !b.jsonSchema.isValid({ const: 5 }, "5"));
  check("const array length-mismatch fails", !b.jsonSchema.isValid({ const: [1, 2] }, [1, 2, 3]));
  check("const object key-count mismatch fails", !b.jsonSchema.isValid({ const: { a: 1 } }, { a: 1, b: 2 }));
  check("const object same-count different-keys fails", !b.jsonSchema.isValid({ const: { a: 1 } }, { b: 1 }));
  check("const deep-equal object passes", b.jsonSchema.isValid({ const: { a: 1 } }, { a: 1 }));
}

function testNumericBounds() {
  check("maximum rejects over", !b.jsonSchema.isValid({ maximum: 5 }, 6));
  check("maximum accepts at bound", b.jsonSchema.isValid({ maximum: 5 }, 5));
  check("exclusiveMaximum rejects at bound", !b.jsonSchema.isValid({ exclusiveMaximum: 5 }, 5));
  check("exclusiveMaximum accepts under", b.jsonSchema.isValid({ exclusiveMaximum: 5 }, 4));
  check("minimum rejects under", !b.jsonSchema.isValid({ minimum: 5 }, 4));
  check("minimum accepts at bound", b.jsonSchema.isValid({ minimum: 5 }, 5));
  check("exclusiveMinimum rejects at bound", !b.jsonSchema.isValid({ exclusiveMinimum: 5 }, 5));
  check("exclusiveMinimum accepts over", b.jsonSchema.isValid({ exclusiveMinimum: 5 }, 6));
}

function testStringBounds() {
  check("maxLength rejects longer", !b.jsonSchema.isValid({ maxLength: 2 }, "abc"));
  check("maxLength accepts equal", b.jsonSchema.isValid({ maxLength: 3 }, "abc"));
  // A surrogate-pair emoji counts as one code point, not two UTF-16 units.
  check("maxLength counts astral code points once", b.jsonSchema.isValid({ maxLength: 1 }, String.fromCodePoint(0x1F600)));
}

function testRegexFallback() {
  // A pattern valid without the /u flag but invalid with it — the compiler
  // falls back to a non-unicode RegExp rather than dropping the constraint.
  check("pattern retries without /u flag", b.jsonSchema.isValid({ pattern: "a\\-z" }, "a-z") && !b.jsonSchema.isValid({ pattern: "a\\-z" }, "qqq"));
  // A pattern invalid under both flags compiles to null → constraint skipped.
  check("uncompilable pattern is skipped", b.jsonSchema.isValid({ pattern: "[" }, "anything"));
  check("uncompilable patternProperties key is skipped", b.jsonSchema.isValid({ patternProperties: { "[": { type: "number" } } }, { x: "str" }));
}

function testArrayApplicatorEdges() {
  check("prefixItems mismatch fails", !b.jsonSchema.isValid({ prefixItems: [{ type: "string" }] }, [5]));
  check("minContains not met fails", !b.jsonSchema.isValid({ contains: { type: "number" }, minContains: 2 }, [1, "a"]));
  check("minContains met passes", b.jsonSchema.isValid({ contains: { type: "number" }, minContains: 2 }, [1, 2, "a"]));
  check("maxContains exceeded fails", !b.jsonSchema.isValid({ contains: { type: "number" }, maxContains: 1 }, [1, 2, 3]));
}

function testObjectApplicatorEdges() {
  check("maxProperties exceeded fails", !b.jsonSchema.isValid({ maxProperties: 1 }, { a: 1, b: 2 }));
  check("minProperties not met fails", !b.jsonSchema.isValid({ minProperties: 2 }, { a: 1 }));
  // additionalProperties skips keys owned by properties even when that
  // property's own schema failed — no double-count as an additional prop.
  var r1 = b.jsonSchema.validate({ properties: { a: { type: "string" } }, additionalProperties: false }, { a: 123 });
  check("addlProps ignores properties-owned key", !r1.valid && r1.errors.length === 1 && r1.errors[0].keyword === "type");
  // ...and keys matched by patternProperties, even when that pattern failed.
  var r2 = b.jsonSchema.validate({ patternProperties: { "^x": { type: "string" } }, additionalProperties: false }, { xa: 123 });
  check("addlProps ignores pattern-matched key", !r2.valid && r2.errors.length === 1 && r2.errors[0].keyword === "type");
  // An additionalProperties schema that passes marks the key evaluated.
  check("addlProps success accepts", b.jsonSchema.isValid({ additionalProperties: { type: "number" } }, { x: 5 }));
  check("addlProps failure rejects", !b.jsonSchema.isValid({ additionalProperties: { type: "number" } }, { x: "no" }));
  // A key matching NO patternProperties pattern falls through to
  // additionalProperties (here false → rejected).
  var r3 = b.jsonSchema.validate({ patternProperties: { "^x": { type: "number" } }, additionalProperties: false }, { y: 1 });
  check("addlProps applies to non-pattern-matched key", !r3.valid && r3.errors[0].keyword === "false");
}

function testUnevaluatedSuccess() {
  // An unevaluated property/item that VALIDATES against the unevaluated*
  // schema is accepted (and recorded as evaluated).
  var so = { properties: { a: true }, unevaluatedProperties: { type: "string" } };
  check("unevaluatedProperties accepts matching extra", b.jsonSchema.isValid(so, { a: 1, b: "ok" }));
  check("unevaluatedProperties rejects non-matching extra", !b.jsonSchema.isValid(so, { a: 1, b: 2 }));
  var sa = { prefixItems: [{ type: "number" }], unevaluatedItems: { type: "number" } };
  check("unevaluatedItems accepts matching tail", b.jsonSchema.isValid(sa, [1, 2]));
  check("unevaluatedItems rejects non-matching tail", !b.jsonSchema.isValid(sa, [1, "x"]));
}

function testConditionalElse() {
  var s = { if: { type: "string" }, else: { type: "number" } };
  check("if-fails-else-fails rejects", !b.jsonSchema.isValid(s, true));
  check("if-fails-else-passes accepts", b.jsonSchema.isValid(s, 5));
  check("if-passes accepts", b.jsonSchema.isValid(s, "hi"));
}

function testRefResolution() {
  // Empty $ref points at the current schema; a root that is only {$ref:""}
  // is an infinite self-reference caught fail-closed by the depth cap —
  // both with no base and with a resolved $id base.
  check("empty self-$ref caught by depth cap", code(function () { b.jsonSchema.validate({ $ref: "" }, 1); }) === "json-schema/ref-loop");
  check("empty $ref under a base still self-loops", code(function () { b.jsonSchema.validate({ $id: "https://ex/x", allOf: [{ $ref: "" }] }, 5); }) === "json-schema/ref-loop");
  // A $id that is a bare name carrying a fragment: relative fragment refs
  // resolve against the fragment-stripped base (an unusual, discouraged
  // shape — child refs do not cleanly resolve, reported fail-closed).
  var r125 = b.jsonSchema.validate({ $id: "mybase#sec", $defs: { foo: { type: "string" } }, $ref: "#/$defs/foo" }, "hi");
  check("bare-name $id with fragment reports unresolved child ref", !r125.valid && r125.errors[0].keyword === "$ref");
  // A boolean schema is registerable and referenceable by an external URI.
  check("boolean schema addressable by URI", b.jsonSchema.isValid({ $ref: "https://ex/bool" }, 42, { schemas: { "https://ex/bool": true } }) && !b.jsonSchema.isValid({ $ref: "https://ex/bool" }, 42, { schemas: { "https://ex/bool": false } }));
  // A $id that is a bare name (not a URL): a fragment $ref resolves by
  // fragment-aware concatenation against that base.
  var bare = { $id: "mybase", $defs: { foo: { type: "string" } }, $ref: "#/$defs/foo" };
  check("bare-name base fragment $ref resolves", b.jsonSchema.isValid(bare, "hi") && !b.jsonSchema.isValid(bare, 5));
  // A relative nested $id under a urn: base (URL resolution throws → falls
  // back to keeping the relative name).
  check("urn base + relative nested $id validates", b.jsonSchema.isValid({ $id: "urn:ex:root", $defs: { leaf: { $id: "leaf", type: "string" } }, $ref: "#/$defs/leaf" }, "hi"));
  // A document is addressable by its retrieval URI even when its own $id is
  // a different canonical URI.
  var ext = { "https://retrieval.example/x": { $id: "https://canonical.example/y", type: "integer" } };
  check("retrieval URI addressable", b.jsonSchema.isValid({ $ref: "https://retrieval.example/x" }, 3, { schemas: ext }) && !b.jsonSchema.isValid({ $ref: "https://retrieval.example/x" }, "no", { schemas: ext }));
  check("canonical $id addressable", b.jsonSchema.isValid({ $ref: "https://canonical.example/y" }, 3, { schemas: ext }));
  // A schema keyed by "base#" is reachable by a $ref written without the #.
  var hk = { "https://ex/x#": { type: "string" } };
  check("base#-keyed schema reachable without fragment", b.jsonSchema.isValid({ $ref: "https://ex/x" }, "hi", { schemas: hk }) && !b.jsonSchema.isValid({ $ref: "https://ex/x" }, 5, { schemas: hk }));
}

function testRefUnresolvable() {
  function err(schema, inst, opts) {
    var r = b.jsonSchema.validate(schema, inst, opts);
    return !r.valid && r.errors.length === 1 && r.errors[0].keyword === "$ref";
  }
  check("fragment-less unknown $ref reports unresolved", err({ $ref: "https://nowhere.example/x" }, 1));
  check("pointer past a primitive reports unresolved", err({ xdata: [10, 20, 30], $ref: "#/xdata/0/toodeep" }, "x"));
  check("pointer array-index OOB reports unresolved", err({ xdata: [10, 20, 30], $ref: "#/xdata/9" }, "x"));
  check("pointer missing object key reports unresolved", err({ xmap: { a: 1 }, $ref: "#/nope" }, "x"));
  check("unknown plain-name anchor reports unresolved", err({ $defs: { p: { $anchor: "pos" } }, $ref: "#nonexistent" }, 1));
}

function testRefIntoNonSchema() {
  // A JSON Pointer into non-schema data (arrays, maps, escaped tokens)
  // resolves the raw value; a non-object value imposes no constraint.
  check("$ref into a data array index imposes no constraint", b.jsonSchema.isValid({ xdata: [10, 20, 30], $ref: "#/xdata/1" }, "anything"));
  check("$ref into a data map is an empty schema", b.jsonSchema.isValid({ xmap: { a: 1 }, $ref: "#/xmap" }, "anything"));
  var esc = { xmap: { "a/b": { type: "string" } }, $ref: "#/xmap/a~1b" };
  check("$ref pointer with ~1 escape resolves", b.jsonSchema.isValid(esc, "hi") && !b.jsonSchema.isValid(esc, 5));
  // A pointed-to object carrying a $id exercises the base-resolution
  // fallback for a node the registry did not index as a schema.
  check("$ref into a data object carrying $id", b.jsonSchema.isValid({ xmap: { $id: "http://x/y", a: 1 }, $ref: "#/xmap" }, "anything"));
}

function testWalkNonSchemaValues() {
  // A schema keyword whose value is not a schema (a bare number) imposes no
  // constraint rather than crashing the walker/validator.
  check("items:<number> imposes no constraint", b.jsonSchema.isValid({ items: 5 }, [1, 2, 3]));
  // not:<non-schema> — the non-schema is treated as always-pass, so 'not'
  // always fails.
  check("not:<number> always fails (non-schema is always-pass)", !b.jsonSchema.isValid({ not: 5 }, "x"));
  // A $id carrying a fragment still validates.
  check("$id with fragment validates", b.jsonSchema.isValid({ $id: "https://ex.example/a#sec", type: "string" }, "hi"));
}

function testDynamicRefEdges() {
  // Unresolvable $dynamicRef reports a located error (fail-closed).
  var r = b.jsonSchema.validate({ $dynamicRef: "#nope" }, 1);
  check("unresolvable $dynamicRef reports error", !r.valid && r.errors[0].keyword === "$dynamicRef");
  // $dynamicRef to a plain $anchor (no $dynamicAnchor) behaves like $ref,
  // resolving with an empty base.
  var s = { $defs: { x: { $anchor: "a", type: "string" } }, properties: { p: { $dynamicRef: "#a" } } };
  check("$dynamicRef to plain $anchor validates", b.jsonSchema.isValid(s, { p: "hi" }) && !b.jsonSchema.isValid(s, { p: 5 }));
  // A resolved $dynamicRef target that rejects the instance propagates fail.
  var tree = { $id: "https://ex/tree", $dynamicAnchor: "node", type: "object", properties: { children: { type: "array", items: { $dynamicRef: "#node" } } } };
  check("$dynamicRef recursion rejects bad child", !b.jsonSchema.isValid(tree, { children: ["notobject"] }));
}

function testMaxErrorsOpt() {
  // A valid maxErrors caps error collection; the option is honored.
  var v = b.jsonSchema.compile({ type: "object", properties: {}, additionalProperties: false }, { maxErrors: 2 });
  check("maxErrors caps collected errors", v.validate({ a: 1, b: 2, c: 3, d: 4 }).errors.length === 2);
  // An out-of-range maxErrors falls back to the default (does not throw).
  check("invalid maxErrors falls back to default", b.jsonSchema.validate({ type: "string" }, "x", { maxErrors: -1 }).valid === true);
}

function testFormatAssertions() {
  var af = { assertFormat: true };
  // format only asserts on strings — a non-string instance passes.
  check("format assertion skips non-string", b.jsonSchema.isValid({ format: "email" }, 123, af));
  check("uri rejects malformed percent-escape", !b.jsonSchema.isValid({ format: "uri" }, "http://x/%zz", af));
  check("uri rejects scheme-valid-but-unparseable", !b.jsonSchema.isValid({ format: "uri" }, "http://[", af));
  check("uuid accepts canonical", b.jsonSchema.isValid({ format: "uuid" }, "12345678-1234-1234-1234-123456789abc", af));
  check("uuid rejects non-uuid", !b.jsonSchema.isValid({ format: "uuid" }, "not-a-uuid", af));
  check("ipv4 accepts dotted-quad", b.jsonSchema.isValid({ format: "ipv4" }, "1.2.3.4", af));
  check("ipv4 rejects out-of-range octet", !b.jsonSchema.isValid({ format: "ipv4" }, "999.1.1.1", af));
  check("regex accepts valid pattern", b.jsonSchema.isValid({ format: "regex" }, "[a-z]+", af));
  check("regex rejects invalid pattern", !b.jsonSchema.isValid({ format: "regex" }, "[", af));
  check("unknown format is annotation-valid", b.jsonSchema.isValid({ format: "totally-unknown" }, "x", af));
}

async function run() {
  testSurface();
  testAssertions();
  testArrays();
  testObjects();
  testApplicators();
  testUnevaluated();
  testRefs();
  testErrorsShape();
  testFormat();
  testDepthCap();
  testInstanceTypes();
  testDeepEqualEdges();
  testNumericBounds();
  testStringBounds();
  testRegexFallback();
  testArrayApplicatorEdges();
  testObjectApplicatorEdges();
  testUnevaluatedSuccess();
  testConditionalElse();
  testRefResolution();
  testRefUnresolvable();
  testRefIntoNonSchema();
  testWalkNonSchemaValues();
  testDynamicRefEdges();
  testMaxErrorsOpt();
  testFormatAssertions();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[json-schema] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }

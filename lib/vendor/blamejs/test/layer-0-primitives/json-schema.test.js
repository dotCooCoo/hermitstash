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
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[json-schema] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }

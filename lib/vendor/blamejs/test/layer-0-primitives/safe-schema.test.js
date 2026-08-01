// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeSchema.SafeSchemaError + b.safeSchema.undefined_ — the schema
 * error class and the undefined-only leaf schema.
 *
 * SafeSchemaError is thrown by every construction-time misuse (bad
 * union, poisoned shape key) AND by schema.parse() on validation
 * failure, carrying the full per-field .issues array so one 400 can
 * report every failing field. It is marked alwaysPermanent so a
 * validation failure never round-trips through retry / transient-error
 * logic. undefined_() is the leaf schema that accepts only `undefined`
 * (implicitly optional) and rejects everything else with an issue code
 * of "type".
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function run() {
  var s = b.safeSchema;

  // ---- SafeSchemaError: thrown by parse() on validation failure ----
  var threw = false;
  var caught = null;
  try { s.string().min(3).parse("ab"); }
  catch (e) { threw = true; caught = e; }
  check("b.safeSchema.SafeSchemaError: parse() of an invalid value throws", threw);
  check("SafeSchemaError: instanceof the exported class",
    caught instanceof b.safeSchema.SafeSchemaError);
  check("SafeSchemaError: name is SafeSchemaError", caught && caught.name === "SafeSchemaError");
  check("SafeSchemaError: carries an .issues array", Array.isArray(caught.issues));
  check("SafeSchemaError: issue[0] has the { path, code, message } shape",
    caught.issues.length === 1 &&
    Array.isArray(caught.issues[0].path) &&
    typeof caught.issues[0].code === "string" &&
    typeof caught.issues[0].message === "string");
  check("SafeSchemaError: issue code reflects the failed check (string/too-short)",
    caught.issues[0].code === "string/too-short");

  // alwaysPermanent — a validation failure must never be retried as if
  // it were a transient fault. defineClass({ alwaysPermanent: true })
  // stamps `.permanent = true` on every instance.
  check("SafeSchemaError: marked permanent so it never round-trips retry",
    caught.permanent === true);

  // The advertised aggregation guarantee: one throw surfaces EVERY
  // failing field so HTTP middleware can answer with a single 400.
  var multiThrew = null;
  try { s.object({ a: s.string().min(3), b: s.number() }).parse({ a: "x", b: "nope" }); }
  catch (e) { multiThrew = e; }
  check("SafeSchemaError: aggregates all failing fields into one .issues array",
    multiThrew instanceof b.safeSchema.SafeSchemaError && multiThrew.issues.length === 2);
  check("SafeSchemaError: each aggregated issue carries its field path",
    multiThrew.issues[0].path[0] === "a" && multiThrew.issues[1].path[0] === "b");

  // ---- SafeSchemaError: also thrown on construction-time misuse ----
  var badUnion = null;
  try { s.union([]); }
  catch (e) { badUnion = e; }
  check("SafeSchemaError: construction-time misuse (empty union) throws it",
    badUnion instanceof b.safeSchema.SafeSchemaError && badUnion.code === "safe-schema/bad-union");

  // A prototype-pollution shape key is rejected at construction, not at
  // parse, so an operator schema can never define one.
  var poisoned = null;
  try { s.object({ "constructor": s.string() }); }
  catch (e) { poisoned = e; }
  check("SafeSchemaError: a poisoned shape key ('constructor') is refused at construction",
    poisoned instanceof b.safeSchema.SafeSchemaError && poisoned.code === "safe-schema/poisoned-shape-key");

  // ---- undefined_(): accepts only undefined; implicitly optional ----
  check("b.safeSchema.undefined_: parse(undefined) returns undefined",
    b.safeSchema.undefined_().parse(undefined) === undefined);

  var nullThrew = null;
  try { s.undefined_().parse(null); }
  catch (e) { nullThrew = e; }
  check("undefined_: parse(null) throws SafeSchemaError with a type issue",
    nullThrew instanceof b.safeSchema.SafeSchemaError && nullThrew.issues[0].code === "type");

  var valThrew = null;
  try { s.undefined_().parse(0); }
  catch (e) { valThrew = e; }
  check("undefined_: parse(0) rejects a defined value with a type issue",
    valThrew instanceof b.safeSchema.SafeSchemaError && valThrew.issues[0].code === "type");

  // safeParse mirrors parse without throwing — the non-throwing consumer
  // path an operator uses to fold errors into a response body.
  check("undefined_: safeParse(undefined) is ok:true",
    s.undefined_().safeParse(undefined).ok === true);
  var spBad = s.undefined_().safeParse(1);
  check("undefined_: safeParse(1) is ok:false with the type error code",
    spBad.ok === false && spBad.errors[0].code === "type");

  testSafeSchemaBranches(s);
}

// Construction-time misuse throws, validation _fail arms, and the
// success/boundary paths across the builder API — driven only through the
// public `b.safeSchema.*` surface (`.parse` / `.safeParse`).
function testSafeSchemaBranches(s) {
  function ctorCode(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
  function issue(schema, value) { var r = schema.safeParse(value); return r.ok ? "OK" : r.errors[0].code; }

  // ---- construction-time misuse ----
  check("pipe: non-schema arg → bad-pipe", ctorCode(function () { s.string().pipe("x"); }) === "safe-schema/bad-pipe");
  check("enum_: empty array → bad-enum", ctorCode(function () { s.enum_([]); }) === "safe-schema/bad-enum");
  check("object: non-object shape → bad-shape", ctorCode(function () { s.object("x"); }) === "safe-schema/bad-shape");
  check("object: non-schema shape value → bad-shape", ctorCode(function () { s.object({ a: "x" }); }) === "safe-schema/bad-shape");
  check("extend: non-object arg → bad-extend", ctorCode(function () { s.object({ a: s.string() }).extend("x"); }) === "safe-schema/bad-extend");
  check("array: non-schema item → bad-item", ctorCode(function () { s.array("x"); }) === "safe-schema/bad-item");
  check("tuple: empty array → bad-tuple", ctorCode(function () { s.tuple([]); }) === "safe-schema/bad-tuple");
  check("tuple: non-schema item → bad-tuple", ctorCode(function () { s.tuple(["x"]); }) === "safe-schema/bad-tuple");
  check("tuple.rest: non-schema arg → bad-tuple-rest", ctorCode(function () { s.tuple([s.string()]).rest("x"); }) === "safe-schema/bad-tuple-rest");
  check("union: non-array arg → bad-union", ctorCode(function () { s.union("x"); }) === "safe-schema/bad-union");
  check("union: non-schema option → bad-union", ctorCode(function () { s.union([s.string(), "x"]); }) === "safe-schema/bad-union");
  check("record: non-schema value → bad-value-schema", ctorCode(function () { s.record("x"); }) === "safe-schema/bad-value-schema");
  check("record: non-schema key → bad-key-schema", ctorCode(function () { s.record("x", s.string()); }) === "safe-schema/bad-key-schema");
  check("discriminatedUnion: empty options → bad-union", ctorCode(function () { s.discriminatedUnion("kind", []); }) === "safe-schema/bad-union");
  check("discriminatedUnion: non-schema option → bad-discriminated-option", ctorCode(function () { s.discriminatedUnion("kind", ["x"]); }) === "safe-schema/bad-discriminated-option");
  check("preprocess: non-fn first arg → bad-preprocess", ctorCode(function () { s.preprocess("x", s.string()); }) === "safe-schema/bad-preprocess");
  check("preprocess: non-schema second arg → bad-preprocess", ctorCode(function () { s.preprocess(function (v) { return v; }, "x"); }) === "safe-schema/bad-preprocess");
  check("lazy: non-fn arg → bad-lazy", ctorCode(function () { s.lazy("x"); }) === "safe-schema/bad-lazy");

  // ---- validation failure arms ----
  check("string.max: too long → string/too-long", issue(s.string().max(3), "toolong") === "string/too-long");
  check("string.email: overlong → string/email-too-long", issue(s.string().email(), "a".repeat(255) + "@x.io") === "string/email-too-long");
  check("string.ip: bad → string/ip", issue(s.string().ip(), "not-an-ip") === "string/ip");
  check("string.ulid: bad → string/ulid", issue(s.string().ulid(), "not-a-ulid") === "string/ulid");
  check("string.base64: bad → string/base64", issue(s.string().base64(), "!!not base64!!") === "string/base64");
  check("number.finite: Infinity → number/not-finite", issue(s.number().finite(), Infinity) === "number/not-finite");
  check("object: non-object value → type", issue(s.object({ a: s.string() }), "x") === "type");
  check("array.max: too long → array/too-long", issue(s.array(s.string()).max(2), ["a", "b", "c"]) === "array/too-long");
  check("array.length: wrong count → array/wrong-length", issue(s.array(s.string()).length(2), ["a"]) === "array/wrong-length");
  check("tuple: non-array value → type", issue(s.tuple([s.string()]), "x") === "type");
  check("record: non-object value → type", issue(s.record(s.string()), "x") === "type");
  check("discriminatedUnion: non-object value → type",
        issue(s.discriminatedUnion("kind", [s.object({ kind: s.literal("a") })]), "x") === "type");
  check("lazy: fn returning a non-schema → lazy issue", issue(s.lazy(function () { return "x"; }), "y") === "lazy");

  // ---- success / boundary arms ----
  check("string.max: within limit passes", s.string().max(5).parse("ok") === "ok");
  check("number.finite: a finite number passes", s.number().finite().parse(5) === 5);
  check("array.max: within limit passes", s.array(s.string()).max(3).parse(["a"]).length === 1);
  check("union: matches one of the options", s.union([s.string(), s.number()]).parse(42) === 42);

  // ---- catch: static default + function default ----
  check("catch: static default on failure", s.string().catch("D").parse(123) === "D");
  check("catch: function default on failure", s.string().catch(function () { return "F"; }).parse(123) === "F");

  // ---- transform: success + thrown error ----
  check("transform: maps a valid value", s.string().transform(function (v) { return v.toUpperCase(); }).parse("hi") === "HI");
  check("transform: a thrown error becomes a transform issue",
        issue(s.string().transform(function () { throw new Error("boom"); }), "x") === "transform");

  // ---- strict object rejects unknown keys ----
  check("object.strict: an unknown key is rejected",
        s.object({ a: s.string() }).strict().safeParse({ a: "x", extra: 1 }).ok === false);
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}

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
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}

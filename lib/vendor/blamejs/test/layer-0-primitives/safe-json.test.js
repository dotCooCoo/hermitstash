// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeJson parse caps — the six documented limit constants and the fact
 * that b.safeJson.parse actually enforces them.
 *
 * These are not typeof assertions: each test drives the real parse consumer
 * path so the constant's advertised value is proven to be the boundary the
 * primitive honors. The DEFAULT_* trio is exercised end-to-end (a payload one
 * step past the cap refuses with the documented .code; a payload at/under it
 * parses). The ABSOLUTE_* trio is the ceiling opts.max* clamps down to — the
 * depth ceiling is exercised via a real clamp (a huge maxDepth request is
 * pinned back to 1000), and the byte / key ceilings are exercised as the higher
 * working cap that changes a parse outcome the default refuses. Fixtures are
 * sized from the constants themselves so a value drift breaks the test.
 */

var { check, b } = require("../helpers");

function _nest(n) {
  return "[".repeat(n) + "1" + "]".repeat(n);
}

function _objectWithKeys(n) {
  var pairs = [];
  for (var i = 0; i < n; i += 1) pairs.push('"k' + i + '":0');
  return "{" + pairs.join(",") + "}";
}

function _code(fn) {
  try { fn(); return "OK"; }
  catch (e) { return e && e.code; }
}

// ---- DEFAULT_MAX_BYTES ----

function testDefaultMaxBytes() {
  check("b.safeJson.DEFAULT_MAX_BYTES is the advertised 1 MiB",
        b.safeJson.DEFAULT_MAX_BYTES === 1048576);

  // A JSON string body just past the default cap refuses BEFORE the parser
  // sees it — the whole point of the byte cap is DoS-avoidance on the parse
  // thread. Sizing the payload off the constant means a value drift flips it.
  var overDefault = '"' + "x".repeat(b.safeJson.DEFAULT_MAX_BYTES + 100) + '"';
  check("parse refuses a body larger than DEFAULT_MAX_BYTES with json/too-large",
        _code(function () { b.safeJson.parse(overDefault); }) === "json/too-large");

  // A small body sails through under the same default cap.
  var underDefault = '"' + "x".repeat(64) + '"';
  check("parse accepts a body well under DEFAULT_MAX_BYTES",
        b.safeJson.parse(underDefault) === "x".repeat(64));

  // Proof the DEFAULT is what applied above: raising maxBytes past the body
  // size accepts the same over-default payload the default rejected.
  check("raising opts.maxBytes above the body accepts what the default refused",
        typeof b.safeJson.parse(overDefault, {
          maxBytes: b.safeJson.DEFAULT_MAX_BYTES + 200,
        }) === "string");
}

// ---- DEFAULT_MAX_DEPTH ----

function testDefaultMaxDepth() {
  check("b.safeJson.DEFAULT_MAX_DEPTH is the advertised 100",
        b.safeJson.DEFAULT_MAX_DEPTH === 100);

  // Nesting one level past the default bound refuses; nesting exactly at the
  // bound parses. Bounds stack-overflow risk for downstream clone/merge walks.
  var tooDeep = _nest(b.safeJson.DEFAULT_MAX_DEPTH + 1);
  check("parse refuses nesting past DEFAULT_MAX_DEPTH with json/too-deep",
        _code(function () { b.safeJson.parse(tooDeep); }) === "json/too-deep");

  var atDepth = _nest(b.safeJson.DEFAULT_MAX_DEPTH);
  check("parse accepts nesting at DEFAULT_MAX_DEPTH",
        Array.isArray(b.safeJson.parse(atDepth)));
}

// ---- DEFAULT_MAX_KEYS ----

function testDefaultMaxKeys() {
  check("b.safeJson.DEFAULT_MAX_KEYS is the advertised 10 000",
        b.safeJson.DEFAULT_MAX_KEYS === 10000);

  // One key past the default per-object cap refuses (CVE-2026-21717 HashDoS
  // guard); exactly at the cap parses.
  var tooMany = _objectWithKeys(b.safeJson.DEFAULT_MAX_KEYS + 1);
  check("parse refuses an object past DEFAULT_MAX_KEYS with json/too-many-keys",
        _code(function () { b.safeJson.parse(tooMany); }) === "json/too-many-keys");

  var atKeys = _objectWithKeys(b.safeJson.DEFAULT_MAX_KEYS);
  check("parse accepts an object at DEFAULT_MAX_KEYS",
        Object.keys(b.safeJson.parse(atKeys)).length === b.safeJson.DEFAULT_MAX_KEYS);
}

// ---- ABSOLUTE_MAX_BYTES ----

function testAbsoluteMaxBytes() {
  check("b.safeJson.ABSOLUTE_MAX_BYTES is the advertised 64 MiB",
        b.safeJson.ABSOLUTE_MAX_BYTES === 67108864);
  check("ABSOLUTE_MAX_BYTES sits above the default (real headroom ceiling)",
        b.safeJson.ABSOLUTE_MAX_BYTES > b.safeJson.DEFAULT_MAX_BYTES);

  // Exercised as the higher working cap: a body the default refuses is
  // accepted when maxBytes is raised to the absolute ceiling. The full clamp
  // at 64 MiB is asserted by value only — allocating a 64 MiB body per process
  // is unsuitable for the parallel smoke harness.
  var overDefault = '"' + "x".repeat(b.safeJson.DEFAULT_MAX_BYTES + 100) + '"';
  check("default cap refuses the over-default body",
        _code(function () { b.safeJson.parse(overDefault); }) === "json/too-large");
  check("maxBytes = ABSOLUTE_MAX_BYTES accepts the over-default body",
        typeof b.safeJson.parse(overDefault, {
          maxBytes: b.safeJson.ABSOLUTE_MAX_BYTES,
        }) === "string");
}

// ---- ABSOLUTE_MAX_DEPTH ----

function testAbsoluteMaxDepth() {
  check("b.safeJson.ABSOLUTE_MAX_DEPTH is the advertised 1000",
        b.safeJson.ABSOLUTE_MAX_DEPTH === 1000);
  check("ABSOLUTE_MAX_DEPTH sits above the default",
        b.safeJson.ABSOLUTE_MAX_DEPTH > b.safeJson.DEFAULT_MAX_DEPTH);

  // A caller asking for a maxDepth far above the ceiling is silently clamped
  // to ABSOLUTE_MAX_DEPTH — so nesting one past the ceiling still refuses even
  // with the inflated request, and nesting at the ceiling still parses.
  var hugeRequest = b.safeJson.ABSOLUTE_MAX_DEPTH * 100;
  var pastCeiling = _nest(b.safeJson.ABSOLUTE_MAX_DEPTH + 1);
  check("an inflated maxDepth is clamped to ABSOLUTE_MAX_DEPTH (refuses past it)",
        _code(function () {
          b.safeJson.parse(pastCeiling, { maxDepth: hugeRequest });
        }) === "json/too-deep");

  var atCeiling = _nest(b.safeJson.ABSOLUTE_MAX_DEPTH);
  check("nesting at ABSOLUTE_MAX_DEPTH parses under the clamped cap",
        Array.isArray(b.safeJson.parse(atCeiling, { maxDepth: hugeRequest })));
}

// ---- ABSOLUTE_MAX_KEYS ----

function testAbsoluteMaxKeys() {
  check("b.safeJson.ABSOLUTE_MAX_KEYS is the advertised 1 000 000",
        b.safeJson.ABSOLUTE_MAX_KEYS === 1000000);
  check("ABSOLUTE_MAX_KEYS sits above the default (real headroom ceiling)",
        b.safeJson.ABSOLUTE_MAX_KEYS > b.safeJson.DEFAULT_MAX_KEYS);

  // Exercised as the higher working cap: an object the default refuses is
  // accepted when maxKeys is raised to the absolute ceiling. The full clamp at
  // 1 000 000 keys is asserted by value only — allocating a million-key object
  // per process is unsuitable for the parallel smoke harness.
  var overDefault = _objectWithKeys(b.safeJson.DEFAULT_MAX_KEYS + 1);
  check("default cap refuses the over-default object",
        _code(function () { b.safeJson.parse(overDefault); }) === "json/too-many-keys");
  check("maxKeys = ABSOLUTE_MAX_KEYS accepts the over-default object",
        Object.keys(b.safeJson.parse(overDefault, {
          maxKeys: b.safeJson.ABSOLUTE_MAX_KEYS,
        })).length === b.safeJson.DEFAULT_MAX_KEYS + 1);
}

// ---- json/syntax must not echo the parsed input (CWE-532) ----

function _thrown(fn) {
  try { fn(); return null; }
  catch (e) { return e; }
}

function testSyntaxErrorDoesNotLeakInputBytes() {
  // A syntax error on secret-bearing input must NOT reflect a window of the
  // parsed bytes back in the thrown message. `parse` sits at a trust boundary;
  // a consumer that logs the error (directly, or via an unhandled rejection
  // stack) would otherwise re-emit the secret (CWE-532). b.redact does not
  // mitigate this: it deliberately excludes the high-entropy detector, so a
  // raw key-byte snippet passes through unredacted.
  var secret = "MIIJSECRETBYTES1234567890";
  var caught = _thrown(function () { b.safeJson.parse('{"k": ' + secret + '}'); });

  check("parse throws on the malformed secret-bearing body",
        caught !== null);
  check("the syntax error keeps the stable json/syntax code",
        caught && caught.code === "json/syntax");
  // V8 echoes a leading window of the offending input (here "MIIJSECRET…");
  // the sanitized message must contain none of it.
  check("the thrown message does NOT echo a window of the parsed input",
        caught && typeof caught.message === "string" &&
        caught.message.indexOf(secret) === -1 &&
        caught.message.indexOf("MIIJSECRET") === -1);

  // A position-bearing V8 error keeps the (non-secret) numeric offset while
  // still hiding the input snippet.
  var posSecret = "TOPSECRETVALUE";
  var posCaught = _thrown(function () {
    b.safeJson.parse('{"a":1 "' + posSecret + '":2}');
  });
  check("a position-bearing syntax error still hides the input snippet",
        posCaught && posCaught.code === "json/syntax" &&
        typeof posCaught.message === "string" &&
        posCaught.message.indexOf(posSecret) === -1);
}

// ---- SafeJsonError constructor defaults ----

function testSafeJsonErrorDefaults() {
  // Constructed directly (a public export) with no code / path — the
  // `code || "json/invalid"` and `path || null` fallbacks only fire here,
  // since every internal throw passes an explicit code.
  var e1 = new b.safeJson.SafeJsonError("boom");
  check("SafeJsonError with no code defaults to json/invalid", e1.code === "json/invalid");
  check("SafeJsonError with no path defaults to null", e1.path === null);
  check("SafeJsonError carries its identity flags",
        e1.isSafeJsonError === true && e1.name === "SafeJsonError");

  var e2 = new b.safeJson.SafeJsonError("boom", "json/x", "$.a");
  check("SafeJsonError honors an explicit code and path",
        e2.code === "json/x" && e2.path === "$.a");
}

// ---- parse: allowProto ternary + reviver proto-strip ----

function testParseAllowProtoAndProtoStrip() {
  // Reviver strips poisoned keys during JSON.parse (the `? undefined :
  // _stripProtoKeys` false arm + the isPoisonedKey true arm).
  var stripped = b.safeJson.parse('{"constructor":{"x":1},"prototype":9,"id":5}');
  check("parse strips a constructor key via the reviver",
        !Object.prototype.hasOwnProperty.call(stripped, "constructor"));
  check("parse strips a prototype key via the reviver",
        !Object.prototype.hasOwnProperty.call(stripped, "prototype"));
  check("parse keeps the benign key alongside stripped ones", stripped.id === 5);

  // allowProto:true selects the `? undefined` reviver arm (no stripping) and
  // skips the walk-time strip, so the poisoned own key survives.
  var kept = b.safeJson.parse('{"constructor":7,"id":5}', { allowProto: true });
  check("parse allowProto:true keeps the constructor own key",
        Object.prototype.hasOwnProperty.call(kept, "constructor") && kept.constructor === 7);
}

// ---- parse: schema (throw + collectErrors) ----

function testParseWithSchema() {
  var schema = { type: "object", required: ["a"], properties: { a: { type: "integer" } } };

  var ok = b.safeJson.parse('{"a":3}', { schema: schema });
  check("parse with schema returns the parsed value on success", ok.a === 3);

  check("parse with schema throws json/validation on mismatch",
        _code(function () { b.safeJson.parse('{"a":"nope"}', { schema: schema }); }) === "json/validation");

  var report = b.safeJson.parse('{"a":"nope"}', { schema: schema, collectErrors: true });
  check("parse with schema + collectErrors returns an error report instead of throwing",
        report && report.ok === false && Array.isArray(report.errors) && report.errors.length >= 1);

  var goodReport = b.safeJson.parse('{"a":3}', { schema: schema, collectErrors: true });
  check("parse with schema + collectErrors returns an ok report on valid input",
        goodReport.ok === true && goodReport.errors.length === 0);
}

// ---- parse: legacy expectType + requiredKeys ----

function testParseExpectTypeAndRequiredKeys() {
  check("parse expectType matching returns the value",
        b.safeJson.parse("[1,2]", { expectType: "array" }).length === 2);
  check("parse expectType mismatch throws json/type-mismatch",
        _code(function () { b.safeJson.parse('{"a":1}', { expectType: "array" }); }) === "json/type-mismatch");

  // requiredKeys on an object drives all four operands of the guard true and
  // enters the missing-key loop.
  check("parse requiredKeys all-present returns the value",
        b.safeJson.parse('{"a":1,"b":2}', { requiredKeys: ["a", "b"] }).b === 2);
  check("parse requiredKeys with a missing key throws json/missing-key",
        _code(function () { b.safeJson.parse('{"a":1}', { requiredKeys: ["a", "zzz"] }); }) === "json/missing-key");
  // A non-object root short-circuits the `!Array.isArray(parsed)` operand.
  check("parse requiredKeys is ignored when the root is an array",
        Array.isArray(b.safeJson.parse("[1,2]", { requiredKeys: ["a"] })));
}

// ---- parseOrDefault ----

function testParseOrDefault() {
  check("parseOrDefault returns the parsed value on success",
        b.safeJson.parseOrDefault('{"x":1}', {}).x === 1);
  check("parseOrDefault returns the fallback on a syntax error",
        b.safeJson.parseOrDefault("{not json", { fb: 1 }).fb === 1);
  check("parseOrDefault returns the fallback on a non-string input",
        Array.isArray(b.safeJson.parseOrDefault(null, [])));
}

// ---- parseStringOrObject ----

function _makeCustomErr() {
  // An operator-supplied error class as parseStringOrObject documents it:
  // `new errorClass(code, message)`.
  function CustomErr(code, message) {
    var e = new Error(message);
    e.name = "CustomErr";
    e.code = code;
    return e;
  }
  return CustomErr;
}

function testParseStringOrObject() {
  var CustomErr = _makeCustomErr();

  // JSON string routes through parse (poisoned key stripped, caps applied).
  var v = b.safeJson.parseStringOrObject('{"__proto__":{"x":1},"a":1}');
  check("parseStringOrObject parses a JSON string and strips poisoned keys",
        v.a === 1 && !Object.prototype.hasOwnProperty.call(v, "__proto__"));

  // An already-decoded plain object is returned by identity.
  var obj = { a: 1 };
  check("parseStringOrObject returns a plain object unchanged (identity)",
        b.safeJson.parseStringOrObject(obj) === obj);

  // Invalid JSON, no errorClass → rethrows the underlying SafeJsonError.
  var e1 = _thrown(function () { b.safeJson.parseStringOrObject("{not json"); });
  check("parseStringOrObject rethrows SafeJsonError on bad JSON without an errorClass",
        e1 && e1.isSafeJsonError === true);

  // Invalid JSON, with errorClass → wraps in that class with jsonCode.
  var e2 = _thrown(function () {
    b.safeJson.parseStringOrObject("{not json", {
      errorClass: CustomErr, jsonCode: "x/bad-json", label: "x.parse",
    });
  });
  check("parseStringOrObject wraps bad JSON in the operator errorClass with jsonCode",
        e2 && e2.name === "CustomErr" && e2.code === "x/bad-json");

  // Non-string / non-object (number), no errorClass → SafeJsonError.
  var e3 = _thrown(function () { b.safeJson.parseStringOrObject(42); });
  check("parseStringOrObject rejects a number with json/wrong-input-type",
        e3 && e3.code === "json/wrong-input-type");

  // Buffer input (own object-but-binary branch), with errorClass → inputCode.
  var e4 = _thrown(function () {
    b.safeJson.parseStringOrObject(Buffer.from("x"), {
      errorClass: CustomErr, inputCode: "x/bad-input",
    });
  });
  check("parseStringOrObject rejects a Buffer via the operator errorClass with inputCode",
        e4 && e4.name === "CustomErr" && e4.code === "x/bad-input");

  // A non-Buffer Uint8Array also fails the plain-object gate.
  var e5 = _thrown(function () { b.safeJson.parseStringOrObject(new Uint8Array([1, 2])); });
  check("parseStringOrObject rejects a Uint8Array with json/wrong-input-type",
        e5 && e5.code === "json/wrong-input-type");

  // null is neither a string nor a plain object.
  var e6 = _thrown(function () { b.safeJson.parseStringOrObject(null); });
  check("parseStringOrObject rejects null with json/wrong-input-type",
        e6 && e6.code === "json/wrong-input-type");
}

// ---- stringify ----

function testStringify() {
  check("stringify encodes a plain object",
        b.safeJson.stringify({ a: 1, b: 2 }) === '{"a":1,"b":2}');

  var cyclic = { name: "root" };
  cyclic.self = cyclic;
  check("stringify throws json/circular on a cycle by default",
        _code(function () { b.safeJson.stringify(cyclic); }) === "json/circular");

  var c2 = { name: "root" };
  c2.self = c2;
  check("stringify onCircular:replace substitutes the default placeholder",
        b.safeJson.stringify(c2, { onCircular: "replace" }) === '{"name":"root","self":"[Circular]"}');

  var c3 = { name: "x" };
  c3.self = c3;
  check("stringify honors a custom circularReplacement",
        b.safeJson.stringify(c3, { onCircular: "replace", circularReplacement: "CYC" }) === '{"name":"x","self":"CYC"}');

  // Poisoned own keys are dropped by the replacer on the way out.
  check("stringify suppresses poisoned keys on output",
        b.safeJson.stringify({ a: 1, constructor: 9, prototype: 8 }) === '{"a":1}');

  // allowProto keeps them.
  check("stringify allowProto:true keeps poisoned keys",
        b.safeJson.stringify({ a: 1, constructor: 9 }, { allowProto: true }).indexOf('"constructor":9') !== -1);

  // indent forwarded to JSON.stringify.
  check("stringify forwards a numeric indent",
        b.safeJson.stringify({ a: 1 }, { indent: 2 }) === '{\n  "a": 1\n}');

  // A SafeJsonError raised during serialization is rethrown unchanged.
  var boom = { toJSON: function () { throw new b.safeJson.SafeJsonError("nope", "json/custom"); } };
  check("stringify rethrows a SafeJsonError raised during serialization",
        _code(function () { b.safeJson.stringify(boom); }) === "json/custom");

  // A non-circular serialization failure maps to json/stringify.
  check("stringify wraps a non-circular serialization failure as json/stringify",
        _code(function () { b.safeJson.stringify({ n: BigInt(10) }); }) === "json/stringify");
}

// ---- stringify replace-mode cycle cleaning ----

function testStringifyReplaceCleaning() {
  // Self-referential array.
  var arr = [1];
  arr.push(arr);
  check("stringify replace-mode handles a self-referential array",
        b.safeJson.stringify(arr, { onCircular: "replace" }) === '[1,"[Circular]"]');

  // Shared non-cyclic subtree preserved (stack-discipline, not falsely flagged).
  var shared = { x: 1 };
  check("stringify replace-mode preserves a shared non-cyclic subtree",
        b.safeJson.stringify({ a: shared, b: shared }, { onCircular: "replace" }) ===
        '{"a":{"x":1},"b":{"x":1}}');

  // Poisoned keys stripped during the cleaning walk.
  var cp = { a: 1, constructor: 9 };
  cp.self = cp;
  check("stringify replace-mode strips poisoned keys while cleaning cycles",
        b.safeJson.stringify(cp, { onCircular: "replace" }) === '{"a":1,"self":"[Circular]"}');

  // allowProto keeps poisoned keys through the cleaning walk.
  check("stringify replace-mode + allowProto keeps poisoned keys",
        b.safeJson.stringify({ a: 1, constructor: 9 }, { onCircular: "replace", allowProto: true })
          .indexOf('"constructor":9') !== -1);

  // Scalar / null roots pass straight through the cleaning walk.
  check("stringify replace-mode passes through a scalar root",
        b.safeJson.stringify(5, { onCircular: "replace" }) === "5");
  check("stringify replace-mode passes through a null root",
        b.safeJson.stringify(null, { onCircular: "replace" }) === "null");

  // An inherited enumerable key is skipped by the own-property gate in the walk.
  var proto = { inherited: 1 };
  var withChain = Object.create(proto);
  withChain.own = 2;
  withChain.self = withChain;
  check("stringify replace-mode copies only own keys (skips inherited enumerable)",
        b.safeJson.stringify(withChain, { onCircular: "replace" }) === '{"own":2,"self":"[Circular]"}');
}

// ---- stringifyForScript ----

function testStringifyForScript() {
  var BS = String.fromCharCode(92); // single backslash, matching the escapes emitted
  var out = b.safeJson.stringifyForScript({ html: "</script><!--&" });
  check("stringifyForScript escapes < to \\u003c", out.indexOf(BS + "u003c") !== -1);
  check("stringifyForScript escapes > to \\u003e", out.indexOf(BS + "u003e") !== -1);
  check("stringifyForScript escapes & to \\u0026", out.indexOf(BS + "u0026") !== -1);
  check("stringifyForScript leaves no raw </script> substring", out.indexOf("</script>") === -1);
  check("stringifyForScript round-trips to the original value",
        JSON.parse(out).html === "</script><!--&");

  var sepInput = "a" + String.fromCharCode(0x2028) + "b" + String.fromCharCode(0x2029) + "c";
  var sep = b.safeJson.stringifyForScript({ s: sepInput });
  check("stringifyForScript escapes U+2028", sep.indexOf(BS + "u2028") !== -1);
  check("stringifyForScript escapes U+2029", sep.indexOf(BS + "u2029") !== -1);
}

// ---- canonical ----

function testCanonical() {
  check("canonical undefined root serializes to null", b.safeJson.canonical(undefined) === "null");
  check("canonical null", b.safeJson.canonical(null) === "null");
  check("canonical boolean", b.safeJson.canonical(true) === "true");
  check("canonical finite number", b.safeJson.canonical(3.5) === "3.5");
  check("canonical string", b.safeJson.canonical("hi") === '"hi"');
  check("canonical sorts object keys at every depth",
        b.safeJson.canonical({ b: 2, a: { d: 4, c: 3 } }) === '{"a":{"c":3,"d":4},"b":2}');
  check("canonical serializes arrays in order", b.safeJson.canonical([3, 1, 2]) === "[3,1,2]");
  check("canonical strips poisoned keys",
        b.safeJson.canonical({ constructor: 9, a: 1 }) === '{"a":1}');
  check("canonical refuses a non-finite number nested in an object",
        _code(function () { b.safeJson.canonical({ r: Infinity }); }) === "json/non-finite");
  check("canonical refuses a NaN root",
        _code(function () { b.safeJson.canonical(NaN); }) === "json/non-finite");
  check("canonical refuses an uncanonicalizable type (function)",
        _code(function () { b.safeJson.canonical({ f: function () {} }); }) === "json/uncanonical");
}

// ---- validate: modes + bad schema ----

function testValidateModes() {
  check("validate throws json/bad-schema when the schema is not an object",
        _code(function () { b.safeJson.validate({}, null); }) === "json/bad-schema");
  check("validate throw-mode returns the value on success",
        b.safeJson.validate({ a: 1 }, { type: "object" }).a === 1);

  var okReport = b.safeJson.validate(5, { type: "integer" }, { collectErrors: true });
  check("validate collectErrors returns an ok report on success",
        okReport.ok === true && okReport.errors.length === 0);

  var badReport = b.safeJson.validate("x", { type: "integer" }, { collectErrors: true });
  check("validate collectErrors returns an error report on failure",
        badReport.ok === false && badReport.errors.length >= 1);

  check("validate throw-mode throws json/validation on the first failure",
        _code(function () { b.safeJson.validate("x", { type: "integer" }); }) === "json/validation");
}

// ---- _validateNode: type keyword ----

function testValidateTypes() {
  check("validate integer accepts an integer",
        b.safeJson.validate(5, { type: "integer" }) === 5);
  check("validate integer rejects a non-number",
        _code(function () { b.safeJson.validate("x", { type: "integer" }); }) === "json/validation");
  check("validate integer rejects a non-integer number",
        _code(function () { b.safeJson.validate(1.5, { type: "integer" }); }) === "json/validation");
  check("validate string accepts a string",
        b.safeJson.validate("s", { type: "string" }) === "s");
  check("validate non-integer type mismatch reports json/validation",
        _code(function () { b.safeJson.validate(5, { type: "string" }); }) === "json/validation");
  // A null value against a string type drives _typeName(null) -> "null".
  check("validate names a null value as 'null' on a type mismatch",
        _code(function () { b.safeJson.validate(null, { type: "string" }); }) === "json/validation");
}

// ---- _validateNode: enum ----

function testValidateEnum() {
  check("validate enum accepts an in-set value",
        b.safeJson.validate("a", { enum: ["a", "b"] }) === "a");
  check("validate enum rejects an out-of-set value",
        _code(function () { b.safeJson.validate("z", { enum: ["a", "b"] }); }) === "json/validation");
}

// ---- _validateNode: string constraints ----

function testValidateStringConstraints() {
  check("validate minLength failure",
        _code(function () { b.safeJson.validate("a", { type: "string", minLength: 3 }); }) === "json/validation");
  check("validate minLength pass",
        b.safeJson.validate("abc", { type: "string", minLength: 3 }) === "abc");
  check("validate maxLength failure",
        _code(function () { b.safeJson.validate("abcd", { type: "string", maxLength: 2 }); }) === "json/validation");
  check("validate pattern (RegExp) failure",
        _code(function () { b.safeJson.validate("xyz", { type: "string", pattern: /^a/ }); }) === "json/validation");
  check("validate pattern (RegExp) pass",
        b.safeJson.validate("abc", { type: "string", pattern: /^a/ }) === "abc");
  check("validate pattern (string) compiles and matches",
        b.safeJson.validate("abc", { type: "string", pattern: "^a" }) === "abc");
  check("validate format known + matching",
        b.safeJson.validate("a@b.com", { type: "string", format: "email" }) === "a@b.com");
  check("validate format known + failing",
        _code(function () { b.safeJson.validate("nope", { type: "string", format: "email" }); }) === "json/validation");
  check("validate format unknown reports json/unknown-format",
        _code(function () { b.safeJson.validate("x", { type: "string", format: "does-not-exist" }); }) === "json/unknown-format");
}

// ---- _validateNode: number constraints ----

function testValidateNumberConstraints() {
  check("validate minimum failure",
        _code(function () { b.safeJson.validate(1, { minimum: 5 }); }) === "json/validation");
  check("validate exclusiveMinimum failure (equal)",
        _code(function () { b.safeJson.validate(5, { exclusiveMinimum: 5 }); }) === "json/validation");
  check("validate maximum failure",
        _code(function () { b.safeJson.validate(10, { maximum: 5 }); }) === "json/validation");
  check("validate exclusiveMaximum failure (equal)",
        _code(function () { b.safeJson.validate(5, { exclusiveMaximum: 5 }); }) === "json/validation");
  check("validate number within all bounds passes",
        b.safeJson.validate(5, { minimum: 0, maximum: 10, exclusiveMinimum: 0, exclusiveMaximum: 10 }) === 5);
}

// ---- _validateNode: array constraints ----

function testValidateArrayConstraints() {
  check("validate minItems failure",
        _code(function () { b.safeJson.validate([1], { minItems: 3 }); }) === "json/validation");
  check("validate maxItems failure",
        _code(function () { b.safeJson.validate([1, 2, 3], { maxItems: 2 }); }) === "json/validation");
  check("validate items recurses into elements",
        _code(function () { b.safeJson.validate([1, "x"], { items: { type: "integer" } }); }) === "json/validation");
  check("validate items pass",
        Array.isArray(b.safeJson.validate([1, 2], { items: { type: "integer" } })));
}

// ---- _validateNode: object constraints ----

function testValidateObjectConstraints() {
  check("validate required-key missing",
        _code(function () { b.safeJson.validate({}, { required: ["a"] }); }) === "json/validation");
  check("validate properties recurses into a known key",
        _code(function () {
          b.safeJson.validate({ a: "x" }, { properties: { a: { type: "integer" } } });
        }) === "json/validation");
  check("validate additionalProperties:false rejects an unknown key",
        _code(function () {
          b.safeJson.validate({ a: 1, b: 2 }, { properties: { a: {} }, additionalProperties: false });
        }) === "json/validation");
  // Default additionalProperties (allowed) leaves an extra key alone.
  check("validate allows extra keys when additionalProperties is not false",
        b.safeJson.validate({ a: 1, b: 2 }, { properties: { a: { type: "integer" } } }).b === 2);

  // An inherited enumerable property is skipped by the own-property gate.
  var vproto = { inh: 1 };
  var vval = Object.create(vproto);
  vval.a = 5;
  check("validate iterates only own properties (skips inherited enumerable)",
        b.safeJson.validate(vval, { properties: { a: { type: "integer" } } }).a === 5);

  // Collect mode surfaces multiple errors from one object.
  var schema = {
    type: "object",
    required: ["email", "age"],
    properties: {
      email: { type: "string", format: "email" },
      age:   { type: "integer", minimum: 0 },
    },
    additionalProperties: false,
  };
  var report = b.safeJson.validate({ email: "nope", age: -1, extra: 1 }, schema, { collectErrors: true });
  check("validate collect mode surfaces every failure at once",
        report.ok === false && report.errors.length >= 3);
}

// ---- formats registry ----

function testFormats() {
  var f = b.safeJson.formats;

  check("email valid", f.email("a@b.com") === true);
  check("email non-string", f.email(5) === false);
  check("email over 254 chars", f.email("a".repeat(250) + "@b.com") === false);
  check("email bad shape", f.email("nope") === false);

  check("url valid https", f.url("https://example.com") === true);
  check("url non-string", f.url(5) === false);
  check("url disallowed protocol", f.url("file:///etc/passwd") === false);

  check("uuid valid", f.uuid("f47ac10b-58cc-4372-a567-0e02b2c3d479") === true);
  check("uuid invalid", f.uuid("not-a-uuid") === false);
  check("uuid non-string", f.uuid(5) === false);

  check("ulid valid", f.ulid("01ARZ3NDEKTSV4RRFFQ69G5FAV") === true);
  check("ulid invalid", f.ulid("zzz") === false);

  check("iso8601-date valid", f["iso8601-date"]("2020-01-15") === true);
  check("iso8601-date bad shape", f["iso8601-date"]("2020/01/15") === false);
  check("iso8601-date impossible date", f["iso8601-date"]("2020-13-45") === false);
  check("iso8601-date non-string", f["iso8601-date"](5) === false);

  check("iso8601-datetime valid", f["iso8601-datetime"]("2020-01-15T00:00:00.000Z") === true);
  check("iso8601-datetime non-string", f["iso8601-datetime"](5) === false);
  check("iso8601-datetime mismatch", f["iso8601-datetime"]("not-a-date") === false);

  check("ipv4 valid", f.ipv4("192.168.1.1") === true);
  check("ipv4 non-string", f.ipv4(5) === false);
  check("ipv4 wrong part count", f.ipv4("1.2.3") === false);
  check("ipv4 non-numeric part", f.ipv4("1.2.3.x") === false);
  check("ipv4 out of range", f.ipv4("256.0.0.1") === false);
  check("ipv4 leading zero", f.ipv4("01.2.3.4") === false);

  check("ipv6 full 8 groups", f.ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") === true);
  check("ipv6 compressed", f.ipv6("2001:db8::1") === true);
  check("ipv6 loopback", f.ipv6("::1") === true);
  check("ipv6 all-zero ::", f.ipv6("::") === true);
  check("ipv6 ipv4-mapped", f.ipv6("::ffff:192.168.1.1") === true);
  check("ipv6 non-string", f.ipv6(5) === false);
  check("ipv6 empty", f.ipv6("") === false);
  check("ipv6 too long", f.ipv6("a".repeat(46)) === false);
  check("ipv6 zone id rejected", f.ipv6("fe80::1%eth0") === false);
  check("ipv6 triple colon rejected", f.ipv6("2001:::1") === false);
  check("ipv6 multiple :: rejected", f.ipv6("2001::db8::1") === false);
  check("ipv6 too many groups rejected", f.ipv6("1:2:3:4:5:6:7:8:9") === false);
  check("ipv6 redundant :: (8 groups) rejected", f.ipv6("1:2:3:4:5:6:7:8::") === false);
  check("ipv6 bad hextet rejected", f.ipv6("2001:db8::zzzz") === false);
  check("ipv6 bad ipv4 tail rejected", f.ipv6("::ffff:999.1.1.1") === false);

  check("ip accepts an ipv4", f.ip("10.0.0.1") === true);
  check("ip accepts an ipv6", f.ip("::1") === true);
  check("ip rejects garbage", f.ip("nope") === false);

  check("hex valid", f.hex("deadbeef") === true);
  check("hex invalid", f.hex("xyz") === false);

  check("slug valid", f.slug("my-slug-1") === true);
  check("slug invalid (spaces)", f.slug("Not Slug") === false);
  check("slug non-string", f.slug(5) === false);
}

// ---- registerFormat + isJsonObject ----

function testRegisterFormatAndIsJsonObject() {
  b.safeJson.registerFormat("test-region", function (v) {
    return typeof v === "string" && /^[a-z]{2}-\d$/.test(v);
  });
  check("registerFormat installs a working validator",
        b.safeJson.formats["test-region"]("us-1") === true &&
        b.safeJson.formats["test-region"]("nope") === false);
  check("registerFormat rejects a non-string name",
        _code(function () { b.safeJson.registerFormat(5, function () {}); }) === "json/bad-format-name");
  check("registerFormat rejects an uppercase name",
        _code(function () { b.safeJson.registerFormat("BadName", function () {}); }) === "json/bad-format-name");
  check("registerFormat rejects a non-function validator",
        _code(function () { b.safeJson.registerFormat("ok-name", "not-fn"); }) === "json/bad-format-validator");

  check("isJsonObject true for a plain object", b.safeJson.isJsonObject({ a: 1 }) === true);
  check("isJsonObject false for null", b.safeJson.isJsonObject(null) === false);
  check("isJsonObject false for an array", b.safeJson.isJsonObject([1]) === false);
  check("isJsonObject false for a scalar", b.safeJson.isJsonObject(5) === false);
}

async function run() {
  testDefaultMaxBytes();
  testDefaultMaxDepth();
  testDefaultMaxKeys();
  testAbsoluteMaxBytes();
  testAbsoluteMaxDepth();
  testAbsoluteMaxKeys();
  testSyntaxErrorDoesNotLeakInputBytes();
  testSafeJsonErrorDefaults();
  testParseAllowProtoAndProtoStrip();
  testParseWithSchema();
  testParseExpectTypeAndRequiredKeys();
  testParseOrDefault();
  testParseStringOrObject();
  testStringify();
  testStringifyReplaceCleaning();
  testStringifyForScript();
  testCanonical();
  testValidateModes();
  testValidateTypes();
  testValidateEnum();
  testValidateStringConstraints();
  testValidateNumberConstraints();
  testValidateArrayConstraints();
  testValidateObjectConstraints();
  testFormats();
  testRegisterFormatAndIsJsonObject();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

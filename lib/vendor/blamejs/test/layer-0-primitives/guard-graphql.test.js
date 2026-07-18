// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var BENIGN_REQ = { query: "query GetMe { me { id name } }", operationName: "GetMe" };

// Introspection leak — `__schema` in production posture. Strict refuses.
var INTROSPECT_REQ = {
  query: "query Inspect { __schema { types { name } } }",
  operationName: "Inspect",
};

// Alias-amplification — 9 aliases in one selection-set exceeds strict's
// maxAliasesPerSelection (8); the breadth-DoS class.
var ALIAS_BOMB_REQ = {
  query: "{ a:me { id } b:me { id } c:me { id } d:me { id } e:me { id } " +
         "f:me { id } g:me { id } h:me { id } i:me { id } }",
};

// A complete GraphQL string literal whose backslash is itself escaped:
// double-quote, backslash, backslash, double-quote. `'\\\\'` is a two-char
// backslash run in JS source, so this is exactly the 4 characters `"\\"`.
var ESC_BS_STRING = '"' + "\\\\" + '"';

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, !!threw && (threw.code || "") === codeMatch);
  return threw;
}

function hasRule(rv, ruleId) {
  return rv.issues.some(function (i) { return i.ruleId === ruleId; });
}

// Build a query whose real selection-set depth is `levels + 2`, with an early
// GraphQL string literal ending in an escaped backslash. A scanner that
// mis-tracks the escaped closing quote stays stuck in-string and ignores every
// following brace, under-measuring the depth to 1.
function deepQueryAfterEscapedString(levels) {
  var open = "";
  var close = "";
  for (var i = 0; i < levels; i += 1) { open += "n" + i + " { "; close = " }" + close; }
  return "{ f(a: " + ESC_BS_STRING + ") { " + open + "id" + close + " } }";
}

async function testGate() {
  var gqlGate = b.guardGraphql.gate({ profile: "strict" });

  // Introspection query → refuse before any schema-resolution work.
  var introspect = await gqlGate.check({ graphqlRequest: INTROSPECT_REQ });
  check("guardGraphql.gate introspection action=refuse", introspect.action === "refuse");
  check("guardGraphql.gate introspection ok=false",      introspect.ok === false);
  check("guardGraphql.gate introspection ruleId",
    introspect.issues.some(function (i) { return i.ruleId === "graphql.introspection"; }));

  // Benign named query → serve.
  var serve = await gqlGate.check({ graphqlRequest: BENIGN_REQ });
  check("guardGraphql.gate benign action=serve",         serve.action === "serve");
  check("guardGraphql.gate benign ok=true",              serve.ok === true);

  // Alias bomb → refuse (breadth-amplification DoS).
  var bomb = await gqlGate.check({ graphqlRequest: ALIAS_BOMB_REQ });
  check("guardGraphql.gate alias-bomb action=refuse",    bomb.action === "refuse");
  check("guardGraphql.gate alias-bomb ruleId",
    bomb.issues.some(function (i) { return i.ruleId === "graphql.alias-bomb"; }));

  // No request on ctx → serve (nothing to gate).
  var none = await gqlGate.check({});
  check("guardGraphql.gate no-request action=serve",     none.action === "serve");

  // Gate also reads ctx.gql (alias field) — deep query blinded by an escaped
  // string must still refuse via the gate consumer path, not just validate.
  var viaGql = await gqlGate.check({ gql: { query: deepQueryAfterEscapedString(15) } });
  check("guardGraphql.gate ctx.gql depth-after-string refuse", viaGql.action === "refuse");
  check("guardGraphql.gate ctx.gql depth-after-string ruleId",
    viaGql.issues.some(function (i) { return i.ruleId === "graphql.depth-exceeded"; }));
}

function testSanitize() {
  // Benign request passes through unchanged (bundles aren't repairable, so
  // sanitize is pass-through-or-throw); the returned bundle re-validates clean.
  var clean = b.guardGraphql.sanitize(BENIGN_REQ, { profile: "strict" });
  check("guardGraphql.sanitize benign returns bundle",   clean === BENIGN_REQ);
  check("guardGraphql.sanitize benign revalidates ok",
    b.guardGraphql.validate(clean, { profile: "strict" }).ok === true);

  // Hostile: introspection query REFUSED (thrown), never returned — the leak
  // shape is a refuse-class outcome, not something sanitize patches up.
  var err = expectThrows("guardGraphql.sanitize introspection throws",
    function () { b.guardGraphql.sanitize(INTROSPECT_REQ, { profile: "strict" }); },
    "graphql.introspection");
  check("guardGraphql.sanitize introspection GuardGraphqlError",
    err instanceof b.guardGraphql.GuardGraphqlError);

  // Hostile: prototype-pollution gadget in a query alias (CVE-2026-32621) —
  // critical, refused at every profile.
  expectThrows("guardGraphql.sanitize proto-poison throws",
    function () {
      b.guardGraphql.sanitize({ query: "query { a:__proto__ { id } }" }, { profile: "strict" });
    },
    "graphql.query-prototype-poison");
}

// ---- RED: escaped-backslash string desync blinds the DoS shape walker ----
//
// A complete GraphQL string literal ending in an escaped backslash (`"\\"`)
// must not blind the depth / alias walker. A scanner that reads the closing
// quote as escaped stays stuck in-string, ignores every following brace and
// colon, and under-measures depth to 1 / aliases to 0 — a depth-bomb or
// alias-bomb then rides through strict validation as shape-clean (fail-open
// DoS-measurement bypass on VALID GraphQL). These drive the shipped
// b.guardGraphql.validate consumer path.
function testStringEvasionDepthBomb() {
  var req = { query: deepQueryAfterEscapedString(15) };            // real depth 17 > strict cap 8
  var rv = b.guardGraphql.validate(req, { profile: "strict" });
  check("depth-after-escaped-string refuses (ok=false)", rv.ok === false);
  check("depth-after-escaped-string fires depth-exceeded",
    hasRule(rv, "graphql.depth-exceeded"));

  // The benign control: an escaped double-quote INSIDE a string must NOT be
  // mistaken for the terminator, and braces inside the string content must stay
  // ignored. Query text: `{ f(a: "x\"{{{{{{{{{{{{" ) { id } }` — the 12 braces
  // live inside the string, so real depth is 2 (well under the strict cap).
  var benign = { query: '{ f(a: "x\\"' + "{{{{{{{{{{{{" + '" ) { id } }' };
  var rvB = b.guardGraphql.validate(benign, { profile: "strict" });
  check("escaped quote + in-string braces stay shape-clean", rvB.ok === true);
}

function testStringEvasionAliasBomb() {
  // 12 aliases (> strict cap 8) in a selection-set that follows an escaped
  // string literal. Must be measured and refused.
  var aliases = "";
  for (var i = 0; i < 12; i += 1) {
    aliases += String.fromCharCode(97 + i) + ":me { id } ";
  }
  var req = { query: "{ f(a: " + ESC_BS_STRING + ") { " + aliases + " } }" };
  var rv = b.guardGraphql.validate(req, { profile: "strict" });
  check("alias-after-escaped-string refuses (ok=false)", rv.ok === false);
  check("alias-after-escaped-string fires alias-bomb",
    hasRule(rv, "graphql.alias-bomb"));
}

// ---- RED: unbalanced-brace stack desync must not blind the alias walker ----
//
// A malformed query with a leading `}` must not desync the per-selection-set
// alias stack from brace depth. A `depth`-indexed counter that lands on an
// absent slot (`undefined + 1 === NaN`) poisons every later comparison so an
// alias-bomb reads as clean. The walker must remain robust on adversarial /
// syntactically-invalid input.
function testUnbalancedBraceAliasBomb() {
  var req = { query: "}{ a:m b:m c:m d:m e:m f:m g:m h:m i:m j:m k:m }" };  // 11 aliases > 8
  var rv = b.guardGraphql.validate(req, { profile: "strict" });
  check("unbalanced-brace alias walker stays measured (ok=false)", rv.ok === false);
  check("unbalanced-brace alias-bomb still fires",
    hasRule(rv, "graphql.alias-bomb"));
}

// ---- bad-input / query-missing defensive branches ----
function testBadInput() {
  var rvNull = b.guardGraphql.validate(null, { profile: "strict" });
  check("bad-input null refuses",   rvNull.ok === false);
  check("bad-input null ruleId",    hasRule(rvNull, "graphql.bad-input"));

  var rvNum = b.guardGraphql.validate(5, { profile: "strict" });
  check("bad-input number refuses", rvNum.ok === false);
  check("bad-input number ruleId",  hasRule(rvNum, "graphql.bad-input"));

  var rvEmpty = b.guardGraphql.validate({ query: "" }, { profile: "strict" });
  check("query-missing empty refuses",     rvEmpty.ok === false);
  check("query-missing empty ruleId",      hasRule(rvEmpty, "graphql.query-missing"));

  var rvNonStr = b.guardGraphql.validate({ query: 123 }, { profile: "strict" });
  check("query-missing non-string refuses", rvNonStr.ok === false);
  check("query-missing non-string ruleId",  hasRule(rvNonStr, "graphql.query-missing"));
}

// ---- byte caps: request / query / variables ----
function testCaps() {
  // request-cap — total serialized bytes over strict maxBytes (32 KiB).
  var big = {};
  for (var i = 0; i < 5000; i += 1) { big["k" + i] = "v" + i; }
  var rvReq = b.guardGraphql.validate({ query: "{ me { id } }", variables: big },
    { profile: "strict" });
  check("request-cap refuses",  rvReq.ok === false);
  check("request-cap ruleId",   hasRule(rvReq, "graphql.request-cap"));

  // query-cap — query bytes over an explicit tiny maxQueryBytes override.
  var rvQ = b.guardGraphql.validate({ query: "{ me { id name } }" },
    { profile: "strict", maxQueryBytes: 4 });
  check("query-cap refuses",    rvQ.ok === false);
  check("query-cap ruleId",     hasRule(rvQ, "graphql.query-cap"));

  // variables-cap — variables bytes over an explicit tiny maxVariableBytes.
  var rvV = b.guardGraphql.validate({ query: "{ me { id } }", variables: { a: "xxxxxxxxxx" } },
    { profile: "strict", maxVariableBytes: 4 });
  check("variables-cap refuses", rvV.ok === false);
  check("variables-cap ruleId",  hasRule(rvV, "graphql.variables-cap"));
}

// ---- prototype-pollution: variable-key form (CVE-2026-32621) ----
function testVariableProtoPoison() {
  // JSON.parse installs `__proto__` as an OWN enumerable key (not the
  // prototype slot), the exact deep-merge gadget shape.
  var req = { query: "{ me { id } }", variables: JSON.parse('{"__proto__": {"x": 1}}') };
  var rv = b.guardGraphql.validate(req, { profile: "strict" });
  check("variable-proto-poison refuses",  rv.ok === false);
  check("variable-proto-poison critical",
    rv.issues.some(function (i) {
      return i.ruleId === "graphql.variable-prototype-poison" && i.severity === "critical";
    }));

  // sanitize surfaces the critical ruleId as the thrown error code.
  expectThrows("variable-proto-poison sanitize throws",
    function () { b.guardGraphql.sanitize(req, { profile: "strict" }); },
    "graphql.variable-prototype-poison");
}

// ---- introspection policy matrix: reject (strict) / audit (balanced) ----
function testIntrospectionPolicies() {
  // balanced audits: warn-only, still ok=true (audit-only disposition).
  var rvAudit = b.guardGraphql.validate({ query: '{ __type(name:"X"){ name } }' },
    { profile: "balanced" });
  check("introspection balanced audit ok=true", rvAudit.ok === true);
  check("introspection balanced warn severity",
    rvAudit.issues.some(function (i) {
      return i.ruleId === "graphql.introspection" && i.severity === "warn";
    }));

  // permissive allows outright — no introspection issue at all.
  var rvAllow = b.guardGraphql.validate({ query: "{ __schema { types { name } } }" },
    { profile: "permissive" });
  check("introspection permissive no issue", !hasRule(rvAllow, "graphql.introspection"));
}

// ---- persisted-query allowlist (require) ----
function testPersistedQuery() {
  var rvMissing = b.guardGraphql.validate({ query: "{ me { id } }" },
    { profile: "strict", persistedQueryPolicy: "require" });
  check("persisted-query missing refuses", rvMissing.ok === false);
  check("persisted-query missing ruleId",  hasRule(rvMissing, "graphql.persisted-query-missing"));

  var rvPresent = b.guardGraphql.validate(
    { query: "{ me { id } }", extensions: { persistedQuery: { sha256Hash: "abc" } } },
    { profile: "strict", persistedQueryPolicy: "require" });
  check("persisted-query present ok=true", rvPresent.ok === true);
}

// ---- operation-name allowlist ----
function testOperationAllowlist() {
  var rvDenied = b.guardGraphql.validate(
    { query: "{ me { id } }", operationName: "Evil" },
    { profile: "strict", allowedOperations: ["GetMe"], operationNamePolicy: "reject" });
  check("operation-not-allowed refuses", rvDenied.ok === false);
  check("operation-not-allowed ruleId",  hasRule(rvDenied, "graphql.operation-not-allowed"));

  var rvAllowed = b.guardGraphql.validate(
    { query: "{ me { id } }", operationName: "GetMe" },
    { profile: "strict", allowedOperations: ["GetMe"], operationNamePolicy: "reject" });
  check("operation allowed ok=true", rvAllowed.ok === true);

  // audit disposition: a denied op under `audit` warns but does not refuse.
  var rvAudit = b.guardGraphql.validate(
    { query: "{ me { id } }", operationName: "Evil" },
    { profile: "strict", allowedOperations: ["GetMe"], operationNamePolicy: "audit" });
  check("operation-not-allowed audit ok=true", rvAudit.ok === true);
  check("operation-not-allowed audit warn",
    rvAudit.issues.some(function (i) {
      return i.ruleId === "graphql.operation-not-allowed" && i.severity === "warn";
    }));
}

// ---- variable-shape type-confusion ----
function testVariableTypeConfusion() {
  var rvReject = b.guardGraphql.validate(
    { query: "{ me { id } }", variables: { id: "5" } },
    { profile: "strict", variableShapes: { id: "number" }, variableShapePolicy: "reject" });
  check("variable-type-confusion refuses", rvReject.ok === false);
  check("variable-type-confusion ruleId",  hasRule(rvReject, "graphql.variable-type-confusion"));

  // Matching type → clean; an undefined declared var is skipped (no false hit).
  var rvOk = b.guardGraphql.validate(
    { query: "{ me { id } }", variables: { id: 5 } },
    { profile: "strict", variableShapes: { id: "number", other: "string" },
      variableShapePolicy: "reject" });
  check("variable-shape matching type ok=true", rvOk.ok === true);
}

// ---- batch defense: reject / audit-over-limit / per-entry recursion ----
function testBatch() {
  // strict refuses any batch outright and short-circuits.
  var rvReject = b.guardGraphql.validate(
    [ { query: "{ me { id } }" }, { query: "{ me { id } }" } ], { profile: "strict" });
  check("batch reject strict refuses", rvReject.ok === false);
  check("batch reject strict ruleId",  hasRule(rvReject, "graphql.batch-size"));

  // balanced audits an over-limit batch (12 > cap 10): warn-only, ok=true.
  var batch = [];
  for (var i = 0; i < 12; i += 1) { batch.push({ query: "{ me { id } }" }); }
  var rvAudit = b.guardGraphql.validate(batch, { profile: "balanced" });
  check("batch over-limit balanced ok=true", rvAudit.ok === true);
  check("batch over-limit balanced warn",
    rvAudit.issues.some(function (i) {
      return i.ruleId === "graphql.batch-size" && i.severity === "warn";
    }));

  // per-entry recursion prefixes the sub-issue snippet with the batch index.
  var rvSub = b.guardGraphql.validate(
    [ { query: "query Inspect { __schema { types { name } } }" } ], { profile: "balanced" });
  check("batch per-entry recursion surfaces sub-issue",
    hasRule(rvSub, "graphql.introspection"));
  check("batch per-entry snippet is index-prefixed",
    rvSub.issues.some(function (i) { return /^\[batch\[0\]\]/.test(i.snippet); }));
}

async function run() {
  await testGate();
  testSanitize();
  testStringEvasionDepthBomb();
  testStringEvasionAliasBomb();
  testUnbalancedBraceAliasBomb();
  testBadInput();
  testCaps();
  testVariableProtoPoison();
  testIntrospectionPolicies();
  testPersistedQuery();
  testOperationAllowlist();
  testVariableTypeConfusion();
  testBatch();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

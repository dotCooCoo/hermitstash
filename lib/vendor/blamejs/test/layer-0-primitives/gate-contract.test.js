// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.gateContract shared guard substrate.
 *
 * Exercises the profile-and-posture composition surface, the gate
 * lifecycle, the dispatch/wrapper gates, and the guard-module factories
 * through their real consumer paths:
 *
 *   - Profile composition — buildProfile (baseProfile / extends string +
 *     array / overrides / removes / array-union / nested-merge / cycle /
 *     unknown), makeProfileBuilder, makeProfileResolver, resolveProfileName.
 *   - Posture resolution — resolveProfileAndPosture (profile + posture
 *     overlay, bad-profile / bad-posture throws, the b.compliance.set()
 *     global-posture fallback, and the one-time unmapped-posture warning),
 *     lookupCompliancePosture (unknown / prototype-key rejection / clone),
 *     makePostureAccessor, compliancePostures, strictDefaults.
 *   - Gate lifecycle — defineGate / buildGuardGate error branches plus the
 *     full check() path: hooks (beforeCheck skip/transform/throw, afterCheck,
 *     onIssue suppress/promote/replace, onSanitize, onRefuse, onAudit), the
 *     runtime cap, decision cache (hit + best-effort failure), forensic
 *     snapshot + evidence store, mode-posture translation, and the
 *     check-threw refusal.
 *   - Dispatch + wrapper gates — composeGates / multiplexGates /
 *     contentTypeMux / byActorTier / byRoute / byDirection / shadowMode /
 *     canaryGate / cachingGate / workerThreadGate.
 *   - Issue vocabulary — ISSUE_SEVERITIES, aggregateIssues, summarizeIssues,
 *     severityDisposition, policyDisposition, charThreatDisposition.
 *   - Validate substrate — runIssueValidator + INPUT_CONTRACTS,
 *     detectStringInput, badInputResultIfNotStringOrBuffer, composeHooks,
 *     throwOnRefusalSeverity, extractBytesAsText, identifierFixtures,
 *     makeRulePackLoader, buildContentGate, and the defineGuard /
 *     defineParser assemblers.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;

var GC  = b.gateContract;
var GCE = GC.GateContractError;

// ---- small operator-supplied handle collectors (defineGate's real
//      opts.audit / opts.observability / forensicEvidenceStore surface;
//      no shared helper provides a gate-contract audit/obs collector). ----
function makeAuditCollector() {
  return { rows: [], safeEmit: function (entry) { this.rows.push(entry); } };
}
function makeObsCollector() {
  return {
    events: [],
    safeEvent: function (name, value, labels) {
      this.events.push({ name: name, value: value, labels: labels });
    },
    has: function (name) { return this.events.some(function (e) { return e.name === name; }); },
  };
}
function makeForensicStore() {
  return { writes: [], write: async function (rec) { this.writes.push(rec); } };
}

function serveCheck() { return { ok: true, action: "serve" }; }
function refuseCheck() {
  return { ok: false, action: "refuse",
    issues: [{ kind: "x.bad", severity: "high", snippet: "bad" }] };
}

// ------------------------------------------------------------------
// Issue-severity vocabulary + audit projection (advertised semantics).
// ------------------------------------------------------------------

function testIssueSeverities() {
  var sevs = b.gateContract.ISSUE_SEVERITIES;
  check("ISSUE_SEVERITIES: exact ladder",
    JSON.stringify(sevs) === JSON.stringify(["info", "warn", "high", "critical"]));
  check("ISSUE_SEVERITIES: frozen", Object.isFrozen(sevs) === true);
  check("ISSUE_SEVERITIES: critical highest", sevs.indexOf("critical") === 3);
  check("ISSUE_SEVERITIES: info lowest", sevs.indexOf("info") === 0);

  sevs.forEach(function (sev) {
    var result = GC.aggregateIssues([{ kind: "k." + sev, severity: sev }]);
    var expectOk = (sev === "info" || sev === "warn");
    check("aggregateIssues(" + sev + ") ok=" + expectOk, result.ok === expectOk);
  });

  var mixed = GC.aggregateIssues([
    { kind: "a", severity: "info" },
    { kind: "b", severity: "high" },
    { kind: "c", severity: "warn" },
  ]);
  check("aggregateIssues: mixed with high → ok false", mixed.ok === false);
  check("aggregateIssues: mixed keeps all issues", mixed.issues.length === 3);
  check("aggregateIssues: empty → ok true", GC.aggregateIssues([]).ok === true);
}

function testSummarizeIssues() {
  var summary = GC.summarizeIssues([
    { kind: "csv.bidi", severity: "high", ruleId: "BIDI-OVERRIDE",
      snippet: "U+202E raw bytes that must never reach the audit log" },
    { kind: "csv.trailing-whitespace", severity: "info", ruleId: "TRIM" },
  ]);
  check("summarizeIssues: length preserved", summary.length === 2);
  check("summarizeIssues: kind preserved", summary[0].kind === "csv.bidi");
  check("summarizeIssues: severity preserved", summary[0].severity === "high");
  check("summarizeIssues: ruleId preserved", summary[0].ruleId === "BIDI-OVERRIDE");
  check("summarizeIssues: snippet stripped", summary[0].snippet === undefined);
  check("summarizeIssues: exactly 3 keys",
    Object.keys(summary[0]).sort().join(",") === "kind,ruleId,severity");
  check("summarizeIssues: second snippet absent",
    Object.prototype.hasOwnProperty.call(summary[1], "snippet") === false);

  var noRule = GC.summarizeIssues([{ kind: "x", severity: "warn" }]);
  check("summarizeIssues: absent ruleId → undefined", noRule[0].ruleId === undefined);
  check("summarizeIssues: non-array → []",
    Array.isArray(GC.summarizeIssues("nope")) && GC.summarizeIssues("nope").length === 0);
  check("summarizeIssues: undefined → []", GC.summarizeIssues(undefined).length === 0);
}

function testSeverityAndPolicyDispositions() {
  check("severityDisposition: [] → serve",
    GC.severityDisposition([]).action === "serve");
  var lo = GC.severityDisposition([{ kind: "k", severity: "low" }]);
  check("severityDisposition: low → audit-only", lo.action === "audit-only" && lo.ok === true);
  var hi = GC.severityDisposition([{ kind: "k", severity: "high" }]);
  check("severityDisposition: high → refuse", hi.action === "refuse" && hi.ok === false);
  var crit = GC.severityDisposition([{ kind: "k", severity: "critical" }]);
  check("severityDisposition: critical → refuse", crit.action === "refuse");

  check("policyDisposition: reject → refuse", GC.policyDisposition("reject") === "refuse");
  check("policyDisposition: audit → audit", GC.policyDisposition("audit") === "audit");
  check("policyDisposition: audit-only → audit", GC.policyDisposition("audit-only") === "audit");
  check("policyDisposition: strip → sanitize", GC.policyDisposition("strip") === "sanitize");
  check("policyDisposition: redact → sanitize", GC.policyDisposition("redact") === "sanitize");
  check("policyDisposition: prefix-tab → sanitize", GC.policyDisposition("prefix-tab") === "sanitize");
  check("policyDisposition: typo → refuse (fail closed)", GC.policyDisposition("rejet") === "refuse");
  check("policyDisposition: undefined → refuse (fail closed)",
    GC.policyDisposition(undefined) === "refuse");

  check("charThreatDisposition: bidi-override honors bidiPolicy",
    GC.charThreatDisposition({ kind: "bidi-override" }, { bidiPolicy: "reject" }) === "refuse");
  check("charThreatDisposition: null-byte honors nullBytePolicy",
    GC.charThreatDisposition({ kind: "null-byte" }, { nullBytePolicy: "strip" }) === "sanitize");
  check("charThreatDisposition: control-char honors controlPolicy",
    GC.charThreatDisposition({ kind: "control-char" }, { controlPolicy: "audit" }) === "audit");
  check("charThreatDisposition: zero-width honors zeroWidthPolicy (unknown → refuse)",
    GC.charThreatDisposition({ kind: "zero-width" }, { zeroWidthPolicy: "allow" }) === "refuse");
  check("charThreatDisposition: unknown kind → null",
    GC.charThreatDisposition({ kind: "other" }, {}) === null);
}

// ------------------------------------------------------------------
// buildProfile / makeProfileBuilder — composition, merge, remove, cycle.
// ------------------------------------------------------------------

var PROFILES = {
  base:    { tags: ["p", "a"], attrs: { a: ["href", "target"] }, mode: "keep" },
  withImg: { extends: ["base"], tags: ["img"] },
  cycA:    { extends: ["cycB"] },
  cycB:    { extends: ["cycA"] },
};
function resolveProfile(name) { return PROFILES[name] || null; }

function testBuildProfileComposition() {
  // requireObject + resolveProfile-required error branches.
  var threw = false;
  try { GC.buildProfile("not-an-object"); } catch (e) { threw = e instanceof GCE; }
  check("buildProfile: non-object opts throws GateContractError", threw);

  threw = false;
  try { GC.buildProfile({ baseProfile: "base" }); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("buildProfile: missing resolveProfile → bad-opt", threw);

  // baseProfile walk pulls its nested `extends` in; arrays union.
  var withImg = GC.buildProfile({ baseProfile: "withImg", resolveProfile: resolveProfile });
  check("buildProfile: baseProfile walk unions extended tags",
    JSON.stringify(withImg.tags) === JSON.stringify(["p", "a", "img"]));
  check("buildProfile: nested object carried from extended base",
    JSON.stringify(withImg.attrs.a) === JSON.stringify(["href", "target"]));

  // extends as a bare string normalizes to a one-element list.
  var strExtend = GC.buildProfile({ extends: "base", resolveProfile: resolveProfile });
  check("buildProfile: extends string composes",
    JSON.stringify(strExtend.tags) === JSON.stringify(["p", "a"]));

  // extends as an array.
  var arrExtend = GC.buildProfile({ extends: ["base"], resolveProfile: resolveProfile });
  check("buildProfile: extends array composes", arrExtend.mode === "keep");

  // overrides merge after extends (array union + new scalar key).
  var overridden = GC.buildProfile({
    baseProfile: "base", overrides: { tags: ["em"], added: 1 }, resolveProfile: resolveProfile,
  });
  check("buildProfile: overrides union onto array",
    JSON.stringify(overridden.tags) === JSON.stringify(["p", "a", "em"]));
  check("buildProfile: overrides add scalar key", overridden.added === 1);

  // removes: array-entry filter, nested-object removal, whole-key delete.
  var removed = GC.buildProfile({
    baseProfile: "base",
    removes: { tags: ["a"], attrs: { a: ["target"] }, mode: true },
    resolveProfile: resolveProfile,
  });
  check("buildProfile: removes filters array entry",
    JSON.stringify(removed.tags) === JSON.stringify(["p"]));
  check("buildProfile: removes nested array entry",
    JSON.stringify(removed.attrs.a) === JSON.stringify(["href"]));
  check("buildProfile: removes deletes whole key",
    Object.prototype.hasOwnProperty.call(removed, "mode") === false);

  // Scalar override through _mergeProfile (later source wins).
  var scalar = GC.buildProfile({
    baseProfile: "base", overrides: { mode: "swap" }, resolveProfile: resolveProfile,
  });
  check("buildProfile: scalar override replaces", scalar.mode === "swap");

  // Nested-object recursion in _mergeProfile: both base and override carry a
  // nested object under the same key → recursive merge (array union + new key).
  var nested = GC.buildProfile({
    baseProfile: "base",
    overrides: { attrs: { a: ["extra"], img: ["src"] } },
    resolveProfile: resolveProfile,
  });
  check("buildProfile: nested object merges recursively (array union)",
    JSON.stringify(nested.attrs.a) === JSON.stringify(["href", "target", "extra"]));
  check("buildProfile: nested object merges recursively (new sub-key)",
    JSON.stringify(nested.attrs.img) === JSON.stringify(["src"]));

  // Cycle detection.
  threw = false;
  try { GC.buildProfile({ baseProfile: "cycA", resolveProfile: resolveProfile }); }
  catch (e) { threw = e.code === "gate-contract/profile-cycle"; }
  check("buildProfile: cycle throws profile-cycle", threw);

  // Unknown profile name.
  threw = false;
  try { GC.buildProfile({ baseProfile: "ghost", resolveProfile: resolveProfile }); }
  catch (e) { threw = e.code === "gate-contract/unknown-profile"; }
  check("buildProfile: unknown baseProfile throws unknown-profile", threw);

  threw = false;
  try { GC.buildProfile({ extends: ["ghost"], resolveProfile: resolveProfile }); }
  catch (e) { threw = e.code === "gate-contract/unknown-profile"; }
  check("buildProfile: unknown extends throws unknown-profile", threw);

  // Empty opts → empty base object.
  var empty = GC.buildProfile({ resolveProfile: resolveProfile });
  check("buildProfile: no baseProfile/extends → {}", Object.keys(empty).length === 0);
}

function testMakeProfileBuilder() {
  var build = GC.makeProfileBuilder(PROFILES);
  var custom = build({ baseProfile: "withImg", overrides: { tags: ["em"] } });
  check("makeProfileBuilder: resolves through closed-over table",
    custom.tags.indexOf("img") !== -1 && custom.tags.indexOf("em") !== -1);
  var threw = false;
  try { build({ baseProfile: "ghost" }); }
  catch (e) { threw = e.code === "gate-contract/unknown-profile"; }
  check("makeProfileBuilder: unknown name throws unknown-profile", threw);
}

function testMakeProfileResolverAndName() {
  var resolver = GC.makeProfileResolver({
    profiles: { strict: { a: 1 }, balanced: { a: 2 } },
    postures: { hipaa: "strict" }, defaults: "strict",
    errorClass: GCE, codePrefix: "csv",
  });
  check("makeProfileResolver: posture-first", resolver({ posture: "hipaa" }) === "strict");
  check("makeProfileResolver: explicit profile", resolver({ profile: "balanced" }) === "balanced");
  check("makeProfileResolver: default fallback", resolver({}) === "strict");
  check("makeProfileResolver: unmapped posture falls to default",
    resolver({ posture: "nope" }) === "strict");
  var threw = false;
  try { resolver({ profile: "ghost" }); }
  catch (e) { threw = e.code === "csv/bad-profile"; }
  check("makeProfileResolver: unknown profile throws bad-profile", threw);

  var byObject = GC.makeProfileResolver({
    profiles: { strict: { a: 1 } }, postures: { hipaa: "strict" },
    defaults: "strict", errorClass: GCE, codePrefix: "csv", byObject: true,
  });
  check("makeProfileResolver: byObject returns config object",
    byObject({ profile: "strict" }).a === 1);
  check("makeProfileResolver: byObject posture returns object",
    byObject({ posture: "hipaa" }).a === 1);

  var POSTURES = { hipaa: "strict" };
  check("resolveProfileName: explicit profile wins",
    GC.resolveProfileName({ profile: "balanced" }, POSTURES, "strict") === "balanced");
  check("resolveProfileName: posture mapped",
    GC.resolveProfileName({ posture: "hipaa" }, POSTURES, "strict") === "strict");
  check("resolveProfileName: default when neither",
    GC.resolveProfileName({}, POSTURES, "strict") === "strict");
  check("resolveProfileName: prototype-key posture → default (proto-shadow safe)",
    GC.resolveProfileName({ posture: "constructor" }, {}, "strict") === "strict");
  check("resolveProfileName: null opts → default",
    GC.resolveProfileName(null, POSTURES, "strict") === "strict");
}

// ------------------------------------------------------------------
// resolveProfileAndPosture — overlays, throws, global-posture fallback,
// unmapped-posture warning.
// ------------------------------------------------------------------

function testResolveProfileAndPosture() {
  var RP = { strict: { a: 1, x: "s" }, balanced: { a: 2, x: "b" } };
  var RPOST = { hipaa: { p: "redact" }, "pci-dss": { p: "redact" } };
  var cfg = {
    profiles: RP, compliancePostures: RPOST, defaults: { a: 0, d: 9 },
    errorClass: GCE, errCodePrefix: "csv",
  };

  // requireObject(cfg).
  var threw = false;
  try { GC.resolveProfileAndPosture({}, null); }
  catch (e) { threw = e instanceof GCE; }
  check("resolveProfileAndPosture: non-object cfg throws", threw);

  // Profile overlay + defaults + inline-opts-last precedence.
  var byProfile = GC.resolveProfileAndPosture({ profile: "balanced" }, cfg);
  check("resolveProfileAndPosture: profile overlay applied", byProfile.x === "b");
  check("resolveProfileAndPosture: defaults kept when not overlaid", byProfile.d === 9);

  var inlineWins = GC.resolveProfileAndPosture({ profile: "balanced", a: 42 }, cfg);
  check("resolveProfileAndPosture: inline opt wins over overlay", inlineWins.a === 42);

  // bad-profile.
  threw = false;
  try { GC.resolveProfileAndPosture({ profile: "ghost" }, cfg); }
  catch (e) { threw = e.code === "csv.bad-profile"; }
  check("resolveProfileAndPosture: unknown profile → bad-profile", threw);

  // Posture overlay.
  var byPosture = GC.resolveProfileAndPosture({ compliancePosture: "hipaa" }, cfg);
  check("resolveProfileAndPosture: posture overlay applied", byPosture.p === "redact");

  // bad-posture.
  threw = false;
  try { GC.resolveProfileAndPosture({ compliancePosture: "ghost" }, cfg); }
  catch (e) { threw = e.code === "csv.bad-posture"; }
  check("resolveProfileAndPosture: unknown posture → bad-posture", threw);

  // Default errorClass + prefix branch (cfg without errorClass/errCodePrefix).
  threw = false;
  try { GC.resolveProfileAndPosture({ profile: "ghost" }, { profiles: RP }); }
  catch (e) { threw = e instanceof GCE && e.code === "guard.bad-profile"; }
  check("resolveProfileAndPosture: default errorClass/prefix on bad-profile", threw);
}

function testGlobalPostureFallback() {
  var RP = { strict: { a: 1 }, balanced: { a: 2 } };
  var RPOST = { hipaa: { p: "redact" } };
  var cfg = {
    profiles: RP, compliancePostures: RPOST, defaults: { a: 0 },
    errorClass: GCE, errCodePrefix: "csv",
  };
  try {
    b.compliance.set("hipaa");
    var resolved = GC.resolveProfileAndPosture({}, cfg);
    check("global posture: b.compliance.set('hipaa') picked up as fallback overlay",
      resolved.p === "redact");
  } finally {
    if (typeof b.compliance._resetForTest === "function") b.compliance._resetForTest();
    GC._resetForTest();
  }
}

function testUnmappedPostureWarning() {
  var RP = { strict: { a: 1 } };
  // No compliancePostures overlay for the pinned posture → safe-default
  // fall-through + a one-time grep-able warning (dedupe on second call).
  var cfg = {
    profiles: RP, compliancePostures: { hipaa: { p: "redact" } },
    defaults: { a: 0, d: 7 }, errorClass: GCE, errCodePrefix: "csv",
  };
  try {
    GC._resetForTest();
    b.compliance.set("fedramp-rev5-moderate");
    var r1 = GC.resolveProfileAndPosture({}, cfg);
    check("unmapped posture: safe-default fall-through (no overlay applied)",
      r1.p === undefined && r1.d === 7);
    // Second call hits the dedupe early-return in _warnUnmappedPosture.
    var r2 = GC.resolveProfileAndPosture({}, cfg);
    check("unmapped posture: dedupe keeps safe default on repeat", r2.d === 7);
  } finally {
    if (typeof b.compliance._resetForTest === "function") b.compliance._resetForTest();
    GC._resetForTest();
  }
}

// ------------------------------------------------------------------
// Compliance-posture lookups + posture/defaults factories.
// ------------------------------------------------------------------

function testLookupCompliancePosture() {
  var POST = { hipaa: { p: "redact", n: 1 } };
  var got = GC.lookupCompliancePosture("hipaa", POST, GCE.factory, "csv");
  check("lookupCompliancePosture: returns posture values", got.p === "redact");
  got.p = "MUTATED";
  check("lookupCompliancePosture: returns a clone (source untouched)",
    POST.hipaa.p === "redact");

  var threw = false;
  try { GC.lookupCompliancePosture("ghost", POST, GCE.factory, "csv"); }
  catch (e) { threw = e.code === "csv.bad-posture"; }
  check("lookupCompliancePosture: unknown name throws bad-posture", threw);

  // Prototype-key must not resolve to an inherited value.
  threw = false;
  try { GC.lookupCompliancePosture("constructor", POST, GCE.factory, "csv"); }
  catch (e) { threw = e.code === "csv.bad-posture"; }
  check("lookupCompliancePosture: prototype key rejected", threw);
}

function testMakePostureAccessor() {
  var acc = GC.makePostureAccessor({ hipaa: "strict" });
  check("makePostureAccessor: known posture → mapped name", acc("hipaa") === "strict");
  check("makePostureAccessor: unknown → null default", acc("nope") === null);
  check("makePostureAccessor: prototype key → fallback (proto-shadow safe)",
    acc("constructor") === null);
  var accF = GC.makePostureAccessor({ hipaa: "strict" }, { fallback: "none" });
  check("makePostureAccessor: custom fallback", accF("nope") === "none");
}

function testCompliancePosturesFactory() {
  var built = GC.compliancePostures({ strict: { s: 1 }, balanced: { z: 2 } }, { base: 64 });
  check("compliancePostures: hipaa is strict tier + budget",
    built.hipaa.s === 1 && built.hipaa.forensicSnippetBytes === 64);
  check("compliancePostures: gdpr is balanced tier + half budget",
    built.gdpr.z === 2 && built.gdpr.forensicSnippetBytes === 32);
  check("compliancePostures: soc2 keeps double budget",
    built.soc2.forensicSnippetBytes === 128);
  check("compliancePostures: postures frozen", Object.isFrozen(built.hipaa));

  var overlaid = GC.compliancePostures({ strict: {}, balanced: {} },
    { base: 64, overlays: { gdpr: { extra: true } } });
  check("compliancePostures: per-posture overlay merged", overlaid.gdpr.extra === true);

  var threw = false;
  try { GC.compliancePostures({ strict: {} }, { base: 64 }); }
  catch (e) { threw = e.code === "gate-contract/bad-profiles"; }
  check("compliancePostures: missing balanced → bad-profiles", threw);

  threw = false;
  try { GC.compliancePostures({ strict: {}, balanced: {} }, { base: 63 }); }
  catch (e) { threw = e.code === "gate-contract/bad-base"; }
  check("compliancePostures: odd base → bad-base", threw);

  threw = false;
  try { GC.compliancePostures({ strict: {}, balanced: {} }, { base: 0 }); }
  catch (e) { threw = e.code === "gate-contract/bad-base"; }
  check("compliancePostures: zero base → bad-base", threw);

  threw = false;
  try { GC.compliancePostures(null, { base: 64 }); }
  catch (e) { threw = e instanceof GCE; }
  check("compliancePostures: non-object profiles throws", threw);
}

function testStrictDefaults() {
  var d = GC.strictDefaults({ strict: { a: 1 } });
  check("strictDefaults: strict profile + enforce mode", d.a === 1 && d.mode === "enforce");
  check("strictDefaults: frozen", Object.isFrozen(d));
  var overlaid = GC.strictDefaults({ strict: { a: 1 } }, { maxRuntimeMs: 10 });
  check("strictDefaults: overlay merged last", overlaid.maxRuntimeMs === 10);

  var threw = false;
  try { GC.strictDefaults({}); }
  catch (e) { threw = e.code === "gate-contract/bad-profiles"; }
  check("strictDefaults: missing strict → bad-profiles", threw);

  threw = false;
  try { GC.strictDefaults(null); }
  catch (e) { threw = e instanceof GCE; }
  check("strictDefaults: non-object profiles throws", threw);
}

// ------------------------------------------------------------------
// Validate substrate — contracts, detectStringInput, composeHooks,
// throwOnRefusalSeverity, extractBytesAsText, fixtures, rule packs.
// ------------------------------------------------------------------

function detectFormula(text) {
  if (/^[=+@]/.test(String(text))) {
    return [{ kind: "csv.formula-injection", severity: "high", snippet: String(text).slice(0, 8) }];
  }
  return [];
}

function testRunIssueValidatorContracts() {
  var bad = GC.runIssueValidator("=cmd|x", {}, detectFormula);
  check("runIssueValidator: text contract flags high issue", bad.ok === false);
  var ok = GC.runIssueValidator("ada,36", {}, detectFormula);
  check("runIssueValidator: text contract clean → ok", ok.ok === true);

  var fromBuf = GC.runIssueValidator(Buffer.from("=x"), {}, detectFormula);
  check("runIssueValidator: text contract coerces Buffer", fromBuf.ok === false);

  var badInput = GC.runIssueValidator(42, {}, detectFormula);
  check("runIssueValidator: text contract non-string → bad-input",
    badInput.ok === false && badInput.issues[0].kind === "bad-input");

  // raw contract: object passes through to the detector untouched.
  var rawOk = GC.runIssueValidator({ meta: 1 }, {}, function () { return []; }, "raw");
  check("runIssueValidator: raw contract passes object through", rawOk.ok === true);

  // bytes contract rejects non-string/Buffer.
  var bytesBad = GC.runIssueValidator(42, {}, detectFormula, "bytes");
  check("runIssueValidator: bytes contract non-string → bad-input", bytesBad.ok === false);
  var bytesOk = GC.runIssueValidator(Buffer.from("ada"), {}, detectFormula, "bytes");
  check("runIssueValidator: bytes contract Buffer passes", bytesOk.ok === true);

  // Custom function contract.
  var custom = function (input) {
    return input === "bad" ? { badInput: "custom rejects" } : { subject: input };
  };
  var cBad = GC.runIssueValidator("bad", {}, detectFormula, custom);
  check("runIssueValidator: custom contract badInput", cBad.ok === false);
  var cOk = GC.runIssueValidator("good", {}, function () { return []; }, custom);
  check("runIssueValidator: custom contract subject", cOk.ok === true);

  // Unknown contract name falls back to text.
  var unknown = GC.runIssueValidator(42, {}, detectFormula, "no-such-contract");
  check("runIssueValidator: unknown contract name → text (rejects non-string)",
    unknown.ok === false);
}

function testBadInputResult() {
  check("badInputResultIfNotStringOrBuffer: string → null",
    GC.badInputResultIfNotStringOrBuffer("hi") === null);
  check("badInputResultIfNotStringOrBuffer: Buffer → null",
    GC.badInputResultIfNotStringOrBuffer(Buffer.from("x")) === null);
  var bad = GC.badInputResultIfNotStringOrBuffer(42);
  check("badInputResultIfNotStringOrBuffer: number → bad-input result",
    bad.ok === false && bad.issues[0].kind === "bad-input");
  check("badInputResultIfNotStringOrBuffer: null → bad-input result",
    GC.badInputResultIfNotStringOrBuffer(null).ok === false);
}

function testDetectStringInput() {
  var threw = false;
  try { GC.detectStringInput("x", {}, null); } catch (e) { threw = e instanceof GCE; }
  check("detectStringInput: non-object cfg throws", threw);

  threw = false;
  try { GC.detectStringInput("x", {}, {}); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("detectStringInput: missing cfg.name throws bad-opt", threw);

  var nonStr = GC.detectStringInput(42, {}, { name: "cidr" });
  check("detectStringInput: non-string → done bad-input",
    nonStr.done === true && nonStr.issues[0].ruleId === "cidr.bad-input");

  var emptyIssue = GC.detectStringInput("", {}, { name: "cidr" });
  check("detectStringInput: empty (default) → done empty issue",
    emptyIssue.done === true && emptyIssue.issues[0].kind === "empty");

  var emptyOk = GC.detectStringInput("", {}, { name: "cidr", emptyMode: "ok" });
  check("detectStringInput: emptyMode ok → done with []",
    emptyOk.done === true && emptyOk.issues.length === 0);

  var emptySkip = GC.detectStringInput("", {}, {
    name: "cidr", emptyMode: "skip", scanCodepoints: false,
  });
  check("detectStringInput: emptyMode skip + no scan → not done, []",
    emptySkip.done === false && emptySkip.issues.length === 0);

  var capped = GC.detectStringInput("abcdef", {}, { name: "cidr", cap: { bytes: 3 } });
  check("detectStringInput: over cap → default cap issue",
    capped.done === true && capped.issues[0].kind === "cidr-cap" &&
    capped.issues[0].ruleId === "cidr.cidr-cap");

  var capFn = GC.detectStringInput("abcdef", {}, {
    name: "cidr", cap: { bytes: 3, kind: "too-big", snippet: function (len) { return "len=" + len; } },
  });
  check("detectStringInput: cap function snippet + custom kind",
    capFn.issues[0].kind === "too-big" && capFn.issues[0].snippet === "len=6");

  var scanned = GC.detectStringInput("clean", {}, { name: "cidr" });
  check("detectStringInput: clean input → not done, codepoint list",
    scanned.done === false && Array.isArray(scanned.issues));
}

async function testComposeHooks() {
  check("composeHooks: empty → null", GC.composeHooks([]) === null);
  check("composeHooks: single → identity", typeof GC.composeHooks([serveCheck]) === "function");

  var redact = function (issue) { return Object.assign({}, issue, { snippet: "<redacted>" }); };
  var dropInfo = function (issue) { return issue.severity === "info" ? { suppress: true } : null; };
  var chain = GC.composeHooks([dropInfo, redact]);
  var infoHit = await chain({ kind: "trim", severity: "info" });
  check("composeHooks: suppress short-circuits chain", infoHit.suppress === true);
  var bidi = await chain({ kind: "bidi", severity: "high", snippet: "U+202E" });
  check("composeHooks: last non-null result wins", bidi.snippet === "<redacted>");

  var skipHook = function () { return { skip: true }; };
  var neverRuns = function () { throw new Error("should not run"); };
  var skipChain = GC.composeHooks([skipHook, neverRuns]);
  var skipRv = await skipChain({});
  check("composeHooks: skip short-circuits chain", skipRv.skip === true);

  var nullFirst = GC.composeHooks([function () { return null; }, function () { return { x: 1 }; }]);
  check("composeHooks: null then value → value", (await nullFirst({})).x === 1);
}

function testThrowOnRefusalSeverity() {
  var threw = null;
  try {
    GC.throwOnRefusalSeverity([{ severity: "high", ruleId: "R1", snippet: "boom" }],
      { errorClass: GCE, codePrefix: "csv" });
  } catch (e) { threw = e; }
  check("throwOnRefusalSeverity: high throws with ruleId code",
    threw && threw.code === "R1" && /boom/.test(threw.message));

  threw = null;
  try {
    GC.throwOnRefusalSeverity([{ severity: "critical", snippet: "x" }],
      { errorClass: GCE, codePrefix: "csv" });
  } catch (e) { threw = e; }
  check("throwOnRefusalSeverity: fallback code = <prefix>.refused",
    threw && threw.code === "csv.refused");

  // Custom severities: high is NOT a refusal severity → no throw.
  var noThrow = true;
  try {
    GC.throwOnRefusalSeverity([{ severity: "high", snippet: "x" }],
      { errorClass: GCE, codePrefix: "csv", severities: ["critical"] });
  } catch (_e) { noThrow = false; }
  check("throwOnRefusalSeverity: narrowed severities skip high", noThrow);

  // Below-refusal severities → no throw.
  noThrow = true;
  try {
    GC.throwOnRefusalSeverity([{ severity: "info", snippet: "x" }],
      { errorClass: GCE, codePrefix: "csv" });
  } catch (_e) { noThrow = false; }
  check("throwOnRefusalSeverity: info does not throw", noThrow);
}

function testExtractBytesAsText() {
  check("extractBytesAsText: null ctx → ''", GC.extractBytesAsText(null) === "");
  check("extractBytesAsText: no bytes → ''", GC.extractBytesAsText({}) === "");
  check("extractBytesAsText: string bytes → identity",
    GC.extractBytesAsText({ bytes: "x,y" }) === "x,y");
  check("extractBytesAsText: Buffer → utf8",
    GC.extractBytesAsText({ bytes: Buffer.from("abc") }) === "abc");
}

function testIdentifierFixtures() {
  var fx = GC.identifierFixtures("example.com", "192.168.1.1");
  check("identifierFixtures: benignIdentifier", fx.benignIdentifier === "example.com");
  check("identifierFixtures: benignBytes derived",
    Buffer.isBuffer(fx.benignBytes) && fx.benignBytes.toString() === "example.com");
  check("identifierFixtures: kind identifier + frozen",
    fx.kind === "identifier" && Object.isFrozen(fx));
  var asciiFx = GC.identifierFixtures("x", "y", "ascii");
  check("identifierFixtures: ascii encoding accepted", asciiFx.hostileBytes.toString() === "y");

  var threw = false;
  try { GC.identifierFixtures("", "x"); } catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("identifierFixtures: empty benign throws bad-opt", threw);
  threw = false;
  try { GC.identifierFixtures("x", ""); } catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("identifierFixtures: empty hostile throws bad-opt", threw);
  threw = false;
  try { GC.identifierFixtures("x", "y", "not-an-encoding"); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("identifierFixtures: invalid encoding throws bad-opt", threw);
}

function testMakeRulePackLoader() {
  var packs = GC.makeRulePackLoader(GCE, "csv");
  packs.load({ id: "p1", rules: [{ id: "ssn" }] });
  check("makeRulePackLoader: get returns stored pack", packs.get("p1").rules.length === 1);
  check("makeRulePackLoader: list returns packs", packs.list().length === 1);
  check("makeRulePackLoader: get missing → null", packs.get("nope") === null);

  var threw = false;
  try { packs.load(null); } catch (e) { threw = e instanceof GCE; }
  check("makeRulePackLoader: non-object pack throws", threw);
  threw = false;
  try { packs.load({ rules: [] }); } catch (e) { threw = e.code === "csv.bad-opt"; }
  check("makeRulePackLoader: missing pack.id throws bad-opt", threw);
}

// ------------------------------------------------------------------
// validateGateShape / runGate.
// ------------------------------------------------------------------

async function testValidateGateShapeAndRunGate() {
  var goodGate = GC.defineGate({ name: "vgs", check: async function () { return serveCheck(); } });
  check("validateGateShape: valid gate returned unchanged",
    GC.validateGateShape(goodGate, "uploads") === goodGate);

  var cases = [
    [null, "non-object"],
    [{}, "check-not-fn"],
    [{ check: function () {}, mode: "yolo" }, "bad-mode"],
    [{ check: function () {}, metrics: 5 }, "metrics-not-fn"],
    [{ check: function () {}, close: 5 }, "close-not-fn"],
  ];
  cases.forEach(function (c) {
    var threw = false;
    try { GC.validateGateShape(c[0], "lbl"); }
    catch (e) { threw = e.code === "gate-contract/bad-shape"; }
    check("validateGateShape: " + c[1] + " → bad-shape", threw);
  });

  check("runGate: null gate → serve",
    (await GC.runGate(null, {})).action === "serve");
  check("runGate: gate without check → serve",
    (await GC.runGate({}, {})).action === "serve");
  var d = await GC.runGate(goodGate, { bytes: Buffer.from("x") });
  check("runGate: real gate returns its decision", d.action === "serve");
}

// ------------------------------------------------------------------
// defineGate / buildGuardGate — construction errors + full lifecycle.
// ------------------------------------------------------------------

function testDefineGateBadOpts() {
  var threw = false;
  try { GC.defineGate("nope"); } catch (e) { threw = e instanceof GCE; }
  check("defineGate: non-object opts throws", threw);

  threw = false;
  try { GC.defineGate({}); } catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("defineGate: missing name throws bad-opt", threw);

  threw = false;
  try { GC.defineGate({ name: "g" }); } catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("defineGate: missing check throws bad-opt", threw);

  threw = false;
  try { GC.defineGate({ name: "g", check: function () {}, mode: "yolo" }); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("defineGate: invalid mode throws bad-opt", threw);
}

async function testDefineGateLifecycle() {
  var obs = makeObsCollector();
  var audit = makeAuditCollector();
  var gate = GC.defineGate({
    name: "lc", audit: audit, observability: obs,
    check: async function (ctx) {
      return GC.extractBytesAsText(ctx) === "REFUSE" ? refuseCheck() : serveCheck();
    },
  });

  var served = await gate.check({ bytes: Buffer.from("hello") });
  check("defineGate: serve decision ok", served.ok === true && served.action === "serve");
  check("defineGate: forensicHash computed from bytes", typeof served.forensicHash === "string");
  check("defineGate: cacheKey present when bytes present", typeof served.cacheKey === "string");
  check("defineGate: runtimeMs numeric", typeof served.runtimeMs === "number");
  check("defineGate: audit handle received serve entry",
    audit.rows.some(function (r) { return r.action === "lc.serve"; }));
  check("defineGate: observability handle received serve counter", obs.has("lc.serve"));

  var refused = await gate.check({ bytes: Buffer.from("REFUSE") });
  check("defineGate: refuse decision", refused.action === "refuse" && refused.ok === false);
  check("defineGate: refuse audit outcome denied",
    audit.rows.some(function (r) { return r.action === "lc.refuse" && r.outcome === "denied"; }));

  var m = gate.metrics();
  check("defineGate: metrics passed counted", m.passed === 1);
  check("defineGate: metrics refused counted", m.refused === 1);
  check("defineGate: metrics p50 numeric", typeof m.p50RuntimeMs === "number");

  // String bytes also hash; no-bytes → null hash/cacheKey.
  var strServed = await gate.check({ bytes: "plainstring" });
  check("defineGate: string bytes hashed", typeof strServed.forensicHash === "string");
  var noBytes = await gate.check({});
  check("defineGate: no bytes → null forensicHash", noBytes.forensicHash === null);
  check("defineGate: no bytes → null cacheKey", noBytes.cacheKey === null);

  // reset zeroes counters.
  gate.reset();
  check("defineGate: reset zeroes counters", gate.metrics().passed === 0 && gate.metrics().refused === 0);

  // dryRun runs the check; policyDiff surfaces both rule hashes.
  var dry = await gate.dryRun({ bytes: Buffer.from("x") });
  check("defineGate: dryRun returns a decision", dry.action === "serve");
  var other = GC.defineGate({ name: "other", check: async function () { return serveCheck(); } });
  var diff = gate.policyDiff(other);
  check("defineGate: policyDiff carries self + other ruleHash",
    diff.selfRuleHash === gate.ruleHash && diff.otherRuleHash === other.ruleHash);
  check("defineGate: exposes name/version/ruleHash/mode",
    gate.name === "lc" && gate.version === "1.0.0" &&
    typeof gate.ruleHash === "string" && gate.mode === "enforce");
}

async function testDefineGateCheckThrows() {
  var obs = makeObsCollector();
  var refuseFlag = false;
  var gate = GC.defineGate({
    name: "boom", observability: obs,
    onRefuse: function () { refuseFlag = true; },
    check: async function () { throw new Error("detector blew up"); },
  });
  var d = await gate.check({ bytes: Buffer.from("x") });
  check("defineGate: thrown check → refuse", d.action === "refuse" && d.ok === false);
  check("defineGate: thrown check → check-threw issue", d.issues[0].kind === "check-threw");
  check("defineGate: thrown check counted as refused", gate.metrics().refused === 1);
  check("defineGate: thrown check emits check_threw obs", obs.has("boom.check_threw"));
  await helpers.waitUntil(function () { return refuseFlag; },
    { timeoutMs: 3000, label: "defineGate check-threw: onRefuse fired" });
  check("defineGate: onRefuse hook fired on thrown check", refuseFlag === true);
}

async function testDefineGateTimeout() {
  var pending = [];
  var gate = GC.defineGate({
    name: "slow", maxRuntimeMs: 1,
    check: function () {
      return new Promise(function (resolve) {
        // Latency simulator, not a condition-wait: the check must run
        // longer than the gate's maxRuntimeMs:1 so the timeout fires
        // first. The setTimeout IS the simulated latency (file is
        // allowlisted for test-promise-settimeout-sleep like
        // audit-use-store.test.js's slow-callback simulator).
        var t = setTimeout(function () { resolve(serveCheck()); }, 5000);
        if (t.unref) t.unref();
        pending.push(t);
      });
    },
  });
  try {
    var d = await gate.check({ bytes: Buffer.from("x") });
    check("defineGate: runtime cap exceeded → refuse", d.action === "refuse");
    check("defineGate: runtime-cap refusal is a check-threw", d.issues[0].kind === "check-threw");
  } finally {
    pending.forEach(function (t) { clearTimeout(t); });
  }
}

async function testDefineGateBeforeCheckHooks() {
  // skip → early serve, check never runs.
  var checkRan = false;
  var skipGate = GC.defineGate({
    name: "skip",
    beforeCheck: function () { return { skip: true }; },
    check: async function () { checkRan = true; return refuseCheck(); },
  });
  var skipped = await skipGate.check({ bytes: Buffer.from("x") });
  check("defineGate: beforeCheck skip → serve", skipped.action === "serve");
  check("defineGate: beforeCheck skip bypasses check", checkRan === false);

  // transform → mutated ctx reaches the check.
  var seen = null;
  var xformGate = GC.defineGate({
    name: "xform",
    beforeCheck: function () { return { transform: { bytes: Buffer.from("XFORM") } }; },
    check: async function (ctx) { seen = GC.extractBytesAsText(ctx); return serveCheck(); },
  });
  await xformGate.check({ bytes: Buffer.from("original") });
  check("defineGate: beforeCheck transform mutates ctx", seen === "XFORM");

  // throwing hook → hook_threw, treated as null, proceeds normally.
  var obs = makeObsCollector();
  var throwGate = GC.defineGate({
    name: "hookthrow", observability: obs,
    beforeCheck: function () { throw new Error("hook boom"); },
    check: async function () { return serveCheck(); },
  });
  var afterThrow = await throwGate.check({ bytes: Buffer.from("x") });
  check("defineGate: throwing beforeCheck still serves", afterThrow.action === "serve");
  check("defineGate: throwing hook emits hook_threw obs", obs.has("hookthrow.hook_threw"));
}

async function testDefineGateAfterAndIssueHooks() {
  // afterCheck amends the decision.
  var amendGate = GC.defineGate({
    name: "amend",
    afterCheck: function () {
      return { ok: false, action: "refuse", issues: [{ kind: "amended", severity: "high" }] };
    },
    check: async function () { return serveCheck(); },
  });
  var amended = await amendGate.check({ bytes: Buffer.from("x") });
  check("defineGate: afterCheck amends decision", amended.action === "refuse");

  // onIssue suppress + promote.
  var suppressPromoteGate = GC.defineGate({
    name: "issues1",
    onIssue: function (issue) {
      if (issue.severity === "info") return { suppress: true };
      if (issue.severity === "high") return { promote: "critical" };
      return null;
    },
    check: async function () {
      return { ok: false, action: "refuse", issues: [
        { kind: "a", severity: "info" }, { kind: "b", severity: "high" },
      ] };
    },
  });
  var sp = await suppressPromoteGate.check({ bytes: Buffer.from("x") });
  check("defineGate: onIssue suppress drops the info issue", sp.issues.length === 1);
  check("defineGate: onIssue promote raises severity", sp.issues[0].severity === "critical");

  // onIssue replace (returns a new issue object) + passthrough (null).
  var replaceGate = GC.defineGate({
    name: "issues2",
    onIssue: function (issue) {
      return issue.kind === "replace-me"
        ? { kind: "replaced", severity: "warn" } : null;
    },
    check: async function () {
      return { ok: false, action: "refuse", issues: [
        { kind: "replace-me", severity: "high" }, { kind: "keep", severity: "warn" },
      ] };
    },
  });
  var rp = await replaceGate.check({ bytes: Buffer.from("x") });
  check("defineGate: onIssue replace substitutes the issue",
    rp.issues[0].kind === "replaced");
  check("defineGate: onIssue null passes issue through", rp.issues[1].kind === "keep");

  // onSanitize final transform on a sanitize decision.
  var sanitizeGate = GC.defineGate({
    name: "san",
    onSanitize: function () { return Buffer.from("scrubbed"); },
    check: async function () {
      return { ok: true, action: "sanitize", sanitized: Buffer.from("raw") };
    },
  });
  var san = await sanitizeGate.check({ bytes: Buffer.from("dirty") });
  check("defineGate: onSanitize replaces sanitized bytes",
    Buffer.isBuffer(san.sanitized) && san.sanitized.toString() === "scrubbed");
  check("defineGate: sanitize counted", sanitizeGate.metrics().sanitized === 1);
}

async function testDefineGateAuditHooks() {
  // onAudit returning false suppresses emission.
  var suppressAudit = makeAuditCollector();
  var suppressGate = GC.defineGate({
    name: "auditsup", audit: suppressAudit,
    onAudit: function () { return false; },
    check: async function () { return serveCheck(); },
  });
  await suppressGate.check({ bytes: Buffer.from("x") });
  check("defineGate: onAudit false suppresses emission", suppressAudit.rows.length === 0);

  // onAudit returning an object replaces the default entry.
  var replaceAudit = makeAuditCollector();
  var replaceGate = GC.defineGate({
    name: "auditrep", audit: replaceAudit,
    onAudit: function () { return { action: "custom.audit", outcome: "success", tag: "replaced" }; },
    check: async function () { return serveCheck(); },
  });
  await replaceGate.check({ bytes: Buffer.from("x") });
  check("defineGate: onAudit object replaces entry",
    replaceAudit.rows.some(function (r) { return r.tag === "replaced"; }));

  // No onAudit hook → default entry emitted.
  var defaultAudit = makeAuditCollector();
  var defaultGate = GC.defineGate({
    name: "auditdef", audit: defaultAudit,
    check: async function () { return serveCheck(); },
  });
  await defaultGate.check({ bytes: Buffer.from("x") });
  check("defineGate: no onAudit → default entry emitted",
    defaultAudit.rows.some(function (r) { return r.action === "auditdef.serve"; }));
}

async function testDefineGateModes() {
  var warnGate = GC.defineGate({
    name: "warnmode", mode: "warn-only",
    check: async function () { return refuseCheck(); },
  });
  var warned = await warnGate.check({ bytes: Buffer.from("x") });
  check("defineGate: warn-only translates refuse → warn",
    warned.action === "warn" && warned.ok === true);
  check("defineGate: warn-only counts warned", warnGate.metrics().warned === 1);

  var auditOnlyGate = GC.defineGate({
    name: "auditmode", mode: "audit-only",
    check: async function () { return refuseCheck(); },
  });
  var auditOnly = await auditOnlyGate.check({ bytes: Buffer.from("x") });
  check("defineGate: audit-only mode → audit-only action",
    auditOnly.action === "audit-only" && auditOnly.ok === true);

  var logOnlyGate = GC.defineGate({
    name: "logmode", mode: "log-only",
    check: async function () { return refuseCheck(); },
  });
  check("defineGate: log-only mode → audit-only action",
    (await logOnlyGate.check({ bytes: Buffer.from("x") })).action === "audit-only");

  var shadowGate = GC.defineGate({
    name: "shadowmode", mode: "shadow",
    check: async function () { return refuseCheck(); },
  });
  var shadowed = await shadowGate.check({ bytes: Buffer.from("x") });
  check("defineGate: shadow mode never refuses",
    shadowed.action === "audit-only" && shadowed.ok === true);
}

async function testDefineGateForensicAndCache() {
  // Forensic snapshot on a refusal + operator evidence store write.
  var store = makeForensicStore();
  var forensicGate = GC.defineGate({
    name: "forensic", forensicSnippetBytes: 8, forensicEvidenceStore: store,
    check: async function () { return refuseCheck(); },
  });
  var fd = await forensicGate.check({ bytes: Buffer.from("hostile-payload-bytes"), actor: "u1", route: "/x" });
  check("defineGate: forensic snapshot captured on refuse",
    Buffer.isBuffer(fd.forensicSnapshot) && fd.forensicSnapshot.length === 8);
  await helpers.waitUntil(function () { return store.writes.length >= 1; },
    { timeoutMs: 3000, label: "defineGate forensic: evidence store write" });
  check("defineGate: evidence store received the snippet",
    store.writes[0].gate === "forensic" && Buffer.isBuffer(store.writes[0].snippet));

  // Evidence-store write throwing is best-effort (decision still refuses).
  var throwingStore = { write: async function () { throw new Error("store down"); } };
  var bestEffortGate = GC.defineGate({
    name: "forensic2", forensicSnippetBytes: 4, forensicEvidenceStore: throwingStore,
    check: async function () { return refuseCheck(); },
  });
  var be = await bestEffortGate.check({ bytes: Buffer.from("payload") });
  check("defineGate: forensic store failure is best-effort", be.action === "refuse");

  // Real per-gate decision cache: second identical input hits the cache.
  var cache = b.cache.create({ namespace: "gc-cov-cache", backend: "memory", maxEntries: 50 });
  try {
    var callCount = 0;
    var cachedGate = GC.defineGate({
      name: "cachedgate", cache: cache, cacheTtlMs: 60000,
      check: async function () { callCount += 1; return serveCheck(); },
    });
    var c1 = await cachedGate.check({ bytes: Buffer.from("identical") });
    var c2 = await cachedGate.check({ bytes: Buffer.from("identical") });
    check("defineGate: cache first miss runs check", callCount === 1);
    check("defineGate: cache hit skips check re-run", c1.action === "serve" && c2.action === "serve");
  } finally {
    await cache.close();
  }

  // Cache backend throwing on get/set is best-effort.
  var badCache = {
    get: async function () { throw new Error("get boom"); },
    set: async function () { throw new Error("set boom"); },
  };
  var badCacheGate = GC.defineGate({
    name: "badcache", cache: badCache, cacheTtlMs: 1000,
    check: async function () { return serveCheck(); },
  });
  var bc = await badCacheGate.check({ bytes: Buffer.from("x") });
  check("defineGate: cache get/set failures are best-effort", bc.action === "serve");
}

async function testBuildGuardGate() {
  var obs = makeObsCollector();
  var audit = makeAuditCollector();
  // Full opts bag forwarded to defineGate.
  var gate = GC.buildGuardGate("myGuard:strict", {
    mode: "enforce", audit: audit, observability: obs,
    forensicSnippetBytes: 0, cacheTtlMs: 0, maxRuntimeMs: 0,
    beforeCheck: null, afterCheck: null, onIssue: null,
    onSanitize: null, onRefuse: null, onAudit: null,
  }, async function (ctx) {
    var text = GC.extractBytesAsText(ctx);
    if (text.length === 0) return { ok: true, action: "serve" };
    if (/\s/.test(text)) {
      return { ok: false, action: "refuse", issues: [{ kind: "whitespace", severity: "high" }] };
    }
    return { ok: true, action: "serve" };
  });
  check("buildGuardGate: result satisfies validateGateShape",
    GC.validateGateShape(gate, "gg") === gate);
  check("buildGuardGate: clean input serves",
    (await gate.check({ bytes: Buffer.from("hello") })).action === "serve");
  check("buildGuardGate: whitespace refuses",
    (await gate.check({ bytes: Buffer.from("a b") })).action === "refuse");

  // Error branches inherited from defineGate.
  var threw = false;
  try { GC.buildGuardGate("bad", {}, 5); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("buildGuardGate: non-function check throws bad-opt", threw);
  threw = false;
  try { GC.buildGuardGate("bad", { mode: "yolo" }, async function () {}); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("buildGuardGate: invalid mode throws bad-opt", threw);
}

// ------------------------------------------------------------------
// Dispatch + wrapper gates.
// ------------------------------------------------------------------

function serveGate(name) {
  return GC.defineGate({ name: name || "serve", check: async function () { return serveCheck(); } });
}
function refuseGate(name) {
  return GC.defineGate({ name: name || "refuse", check: async function () { return refuseCheck(); } });
}
function sanitizeGate(name) {
  return GC.defineGate({
    name: name || "san",
    check: async function () {
      return { ok: true, action: "sanitize", sanitized: Buffer.from("clean") };
    },
  });
}

async function testComposeGates() {
  var refuseFirst = GC.composeGates([serveGate("a"), refuseGate("b")], { name: "chain" });
  check("composeGates: first refusal wins",
    (await refuseFirst.check({ bytes: Buffer.from("x") })).action === "refuse");

  var allServe = GC.composeGates([serveGate("a"), serveGate("b")]);
  check("composeGates: all-serve → serve",
    (await allServe.check({ bytes: Buffer.from("x") })).action === "serve");

  // sanitize feeds the scrubbed bytes forward when firstRefusalWins (default).
  var seenBytes = null;
  var sink = GC.defineGate({
    name: "sink",
    check: async function (ctx) { seenBytes = GC.extractBytesAsText(ctx); return serveCheck(); },
  });
  var feedChain = GC.composeGates([sanitizeGate("s"), sink]);
  await feedChain.check({ bytes: Buffer.from("dirty") });
  check("composeGates: sanitize output feeds next gate", seenBytes === "clean");

  // firstRefusalWins:false does not feed forward.
  seenBytes = null;
  var noFeed = GC.composeGates([sanitizeGate("s2"), GC.defineGate({
    name: "sink2",
    check: async function (ctx) { seenBytes = GC.extractBytesAsText(ctx); return serveCheck(); },
  })], { firstRefusalWins: false });
  var nf = await noFeed.check({ bytes: Buffer.from("dirty") });
  check("composeGates: firstRefusalWins false skips feed", seenBytes === "dirty" && nf.action === "serve");
}

async function testMultiplexAndContentTypeMux() {
  var mux = GC.multiplexGates({
    ".csv": serveGate("csv"), "default": refuseGate("def"),
  });
  check("multiplexGates: extension match dispatches",
    (await mux.check({ bytes: Buffer.from("x"), filename: "a.CSV" })).action === "serve");
  check("multiplexGates: unmatched → default fallback",
    (await mux.check({ bytes: Buffer.from("x"), filename: "a.txt" })).action === "refuse");

  var noFallback = GC.multiplexGates({ ".csv": serveGate("csv") });
  check("multiplexGates: no match + no fallback → serve",
    (await noFallback.check({ bytes: Buffer.from("x"), filename: "a.bin" })).action === "serve");
  check("multiplexGates: no filename → serve",
    (await noFallback.check({ bytes: Buffer.from("x") })).action === "serve");

  var ctMux = GC.contentTypeMux({
    "text/csv": serveGate("csv"), "default": refuseGate("def"),
  });
  check("contentTypeMux: strips params + matches",
    (await ctMux.check({ bytes: Buffer.from("x"), contentType: "text/CSV; charset=utf-8" })).action === "serve");
  check("contentTypeMux: unknown → default",
    (await ctMux.check({ bytes: Buffer.from("x"), contentType: "application/json" })).action === "refuse");

  var ctNoFallback = GC.contentTypeMux({ "text/csv": serveGate("csv") });
  check("contentTypeMux: no match + no fallback → serve",
    (await ctNoFallback.check({ bytes: Buffer.from("x"), contentType: "image/png" })).action === "serve");
}

async function testTierRouteDirectionDispatch() {
  var byTier = GC.byActorTier({ free: refuseGate("free"), paid: serveGate("paid"), default: refuseGate("d") });
  check("byActorTier: tier match dispatches",
    (await byTier.check({ bytes: Buffer.from("x"), actor: { tier: "paid" } })).action === "serve");
  check("byActorTier: missing tier → default",
    (await byTier.check({ bytes: Buffer.from("x") })).action === "refuse");
  var byTierNoDefault = GC.byActorTier({ paid: serveGate("paid") });
  check("byActorTier: unmapped + no default → serve",
    (await byTierNoDefault.check({ bytes: Buffer.from("x"), actor: { tier: "free" } })).action === "serve");

  var byPath = GC.byRoute({ "/admin/*": serveGate("admin"), "*": refuseGate("pub") });
  check("byRoute: prefix glob matches",
    (await byPath.check({ bytes: Buffer.from("x"), route: "/admin/imports" })).action === "serve");
  check("byRoute: fallback star matches",
    (await byPath.check({ bytes: Buffer.from("x"), route: "/public/x" })).action === "refuse");
  var exactRoute = GC.byRoute({ "/exact": serveGate("exact") });
  check("byRoute: exact pattern matches",
    (await exactRoute.check({ bytes: Buffer.from("x"), route: "/exact" })).action === "serve");
  check("byRoute: no match + no fallback → serve",
    (await exactRoute.check({ bytes: Buffer.from("x"), route: "/nope" })).action === "serve");

  var byDir = GC.byDirection({ inbound: refuseGate("in"), outbound: serveGate("out") });
  check("byDirection: inbound dispatch",
    (await byDir.check({ bytes: Buffer.from("x"), direction: "inbound" })).action === "refuse");
  check("byDirection: default outbound",
    (await byDir.check({ bytes: Buffer.from("x") })).action === "serve");
  var byDirEmpty = GC.byDirection({ inbound: refuseGate("in") });
  check("byDirection: unmapped direction → serve",
    (await byDirEmpty.check({ bytes: Buffer.from("x"), direction: "sideways" })).action === "serve");
}

async function testShadowCanaryCachingWorkerGates() {
  // shadowMode: primary decision honored; divergent candidate runs async.
  var candidateRan = false;
  var candidate = GC.defineGate({
    name: "cand",
    check: async function () { candidateRan = true; return refuseCheck(); },
  });
  var staged = GC.shadowMode(serveGate("prim"), candidate, { name: "staged" });
  var sd = await staged.check({ bytes: Buffer.from("x") });
  check("shadowMode: primary decision honored", sd.action === "serve");
  await helpers.waitUntil(function () { return candidateRan; },
    { timeoutMs: 3000, label: "shadowMode: candidate ran (divergence branch)" });
  check("shadowMode: candidate executed", candidateRan === true);

  // canaryGate: rate 0 downgrades refuse → warn; rate 1 keeps refuse.
  var canaryDowngrade = GC.canaryGate(refuseGate("c1"), { rate: 0 });
  check("canaryGate: rate 0 downgrades refuse to warn",
    (await canaryDowngrade.check({ bytes: Buffer.from("x") })).action === "warn");
  var canaryEnforce = GC.canaryGate(refuseGate("c2"), { rate: 1 });
  check("canaryGate: rate 1 enforces refuse",
    (await canaryEnforce.check({ bytes: Buffer.from("x") })).action === "refuse");
  var canaryServe = GC.canaryGate(serveGate("c3"));
  check("canaryGate: non-refuse passes through (default rate)",
    (await canaryServe.check({ bytes: Buffer.from("x") })).action === "serve");

  // cachingGate: bad backend throws; good backend wraps + delegates.
  var threw = false;
  try { GC.cachingGate(serveGate("cg"), { backend: { get: function () {} } }); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("cachingGate: backend missing set → bad-opt", threw);

  var cache = b.cache.create({ namespace: "gc-cov-wrap", backend: "memory", maxEntries: 10 });
  try {
    var cached = GC.cachingGate(serveGate("wrapped"), { backend: cache, ttlMs: 60000 });
    check("cachingGate: wraps and delegates",
      (await cached.check({ bytes: Buffer.from("x") })).action === "serve");
    check("cachingGate: default name derives from wrapped gate", cached.name === "wrapped:cached");
  } finally {
    await cache.close();
  }

  // workerThreadGate: missing worker throws; worker stub delegates.
  threw = false;
  try { GC.workerThreadGate(serveGate("w"), {}); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("workerThreadGate: missing worker → bad-opt", threw);
  var worker = { run: async function () { return { ok: true, action: "serve" }; } };
  var offloaded = GC.workerThreadGate(serveGate("wg"), { worker: worker });
  check("workerThreadGate: delegates to worker.run",
    (await offloaded.check({ bytes: Buffer.from("x") })).action === "serve");
}

// ------------------------------------------------------------------
// buildContentGate — serve / refuse / sanitize / audit dispositions.
// ------------------------------------------------------------------

async function testBuildContentGate() {
  // Clean serve + empty subject serve.
  var cleanGate = GC.buildContentGate({
    name: "cg-clean", opts: {},
    validate: function () { return { ok: true, issues: [] }; },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: clean input serves",
    (await cleanGate.check({ bytes: Buffer.from("ok") })).action === "serve");
  check("buildContentGate: empty subject serves",
    (await cleanGate.check({})).action === "serve");

  // Refuse via issue.disposition.
  var refuseGate2 = GC.buildContentGate({
    name: "cg-refuse", opts: {},
    validate: function () {
      return { ok: false, issues: [{ kind: "k", severity: "high", disposition: "refuse" }] };
    },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: refuse disposition refuses",
    (await refuseGate2.check({ bytes: Buffer.from("x") })).action === "refuse");

  // Sanitize via disposition, verified producer output.
  var sanGate = GC.buildContentGate({
    name: "cg-san", opts: {},
    validate: function () {
      return { ok: false, issues: [{ kind: "k", severity: "high", disposition: "sanitize" }] };
    },
    produceSanitized: function () { return "scrubbed"; },
  });
  var sanD = await sanGate.check({ bytes: Buffer.from("x") });
  check("buildContentGate: sanitize disposition sanitizes",
    sanD.action === "sanitize" && sanD.sanitized.toString() === "scrubbed");

  // Sanitize blocked by sanitizeBlockingKinds → refuse.
  var blockedGate = GC.buildContentGate({
    name: "cg-block", opts: {}, sanitizeBlockingKinds: ["svgz"],
    validate: function () {
      return { ok: false, issues: [{ kind: "svgz", severity: "high", disposition: "sanitize" }] };
    },
    produceSanitized: function () { return "x"; },
  });
  check("buildContentGate: sanitizeBlockingKinds forces refuse",
    (await blockedGate.check({ bytes: Buffer.from("x") })).action === "refuse");

  // Producer throws → refuse.
  var throwProducer = GC.buildContentGate({
    name: "cg-throw", opts: {},
    validate: function () {
      return { ok: false, issues: [{ kind: "k", severity: "high", disposition: "sanitize" }] };
    },
    produceSanitized: function () { throw new Error("cannot repair"); },
  });
  check("buildContentGate: producer throw → refuse",
    (await throwProducer.check({ bytes: Buffer.from("x") })).action === "refuse");

  // Audit-only disposition.
  var auditGate = GC.buildContentGate({
    name: "cg-audit", opts: {},
    validate: function () {
      return { ok: true, issues: [{ kind: "k", severity: "low", disposition: "audit" }] };
    },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: audit disposition → audit-only",
    (await auditGate.check({ bytes: Buffer.from("x") })).action === "audit-only");

  // dispositionFor from the guard overrides.
  var dispForGate = GC.buildContentGate({
    name: "cg-dispfor", opts: {},
    validate: function () { return { ok: false, issues: [{ kind: "k", severity: "high" }] }; },
    dispositionFor: function () { return "audit"; },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: dispositionFor downgrades to audit-only",
    (await dispForGate.check({ bytes: Buffer.from("x") })).action === "audit-only");

  // Severity fallback (no disposition, no dispositionFor) → refuse on high.
  var sevFallback = GC.buildContentGate({
    name: "cg-sev", opts: {},
    validate: function () { return { ok: false, issues: [{ kind: "k", severity: "high" }] }; },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: severity fallback refuses on high",
    (await sevFallback.check({ bytes: Buffer.from("x") })).action === "refuse");

  // extraIssues (operator detect-only) + ctxField "bytes".
  var extraGate = GC.buildContentGate({
    name: "cg-extra", opts: {}, ctxField: "bytes",
    validate: function () { return { ok: true, issues: [] }; },
    extraIssues: function () { return [{ kind: "op", severity: "high" }]; },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: extraIssues high refuses (ctxField bytes)",
    (await extraGate.check({ bytes: Buffer.from("x") })).action === "refuse");
}

// ------------------------------------------------------------------
// defineGuard / defineParser — the full guard-module assemblers, driven
// through their real consumer surface.
// ------------------------------------------------------------------

var GUARD_PROFILES = {
  strict:     { maxBytes: 256, bidiPolicy: "reject" },
  balanced:   { maxBytes: 512, bidiPolicy: "strip" },
  permissive: { maxBytes: 1024, bidiPolicy: "allow" },
};

function guardDetect(input) {
  if (String(input).indexOf("BAD") === 0) {
    return [{ kind: "content.bad", severity: "high", ruleId: "gccov.bad", snippet: "BAD" }];
  }
  return [];
}

async function testDefineGuard() {
  var guard = GC.defineGuard({
    name: "gccov", kind: "content", errorName: "GcCoverageContentError",
    profiles: GUARD_PROFILES, base: 64,
    mimeTypes: ["text/gccov"], extensions: [".gccov"],
    integrationFixtures: { kind: "content", benignBytes: Buffer.from("ok") },
    detect: guardDetect, inputContract: "text", intOpts: ["maxBytes"],
    sanitizeTransform: function (subject) { return String(subject).replace("BAD", ""); },
    extra: { helperConst: 7 },
  });

  check("defineGuard: NAME/KIND exported", guard.NAME === "gccov" && guard.KIND === "content");
  check("defineGuard: content kind exports MIME/EXTENSIONS",
    guard.MIME_TYPES[0] === "text/gccov" && guard.EXTENSIONS[0] === ".gccov");
  check("defineGuard: INTEGRATION_FIXTURES surfaced",
    guard.INTEGRATION_FIXTURES.kind === "content");
  check("defineGuard: base derives COMPLIANCE_POSTURES (strict tier + budget)",
    guard.COMPLIANCE_POSTURES.hipaa.forensicSnippetBytes === 64);
  check("defineGuard: base derives DEFAULTS via strictDefaults",
    guard.DEFAULTS.mode === "enforce" && guard.DEFAULTS.maxBytes === 256);
  check("defineGuard: extra merged verbatim", guard.helperConst === 7);
  check("defineGuard: error class exported under its name",
    typeof guard.GcCoverageContentError === "function");

  // Generated validate (runIssueValidator + detect).
  check("defineGuard: validate clean → ok", guard.validate("hello", {}).ok === true);
  check("defineGuard: validate hostile → not ok", guard.validate("BADxyz", {}).ok === false);
  check("defineGuard: validate non-text → bad-input (text contract)",
    guard.validate(42, {}).ok === false);

  // Generated sanitize (resolve → detect → throwOnRefusalSeverity → transform).
  check("defineGuard: sanitize clean returns transform output",
    guard.sanitize("okvalue", {}) === "okvalue");
  var threw = false;
  try { guard.sanitize("BADxyz", {}); }
  catch (e) { threw = e instanceof guard.GcCoverageContentError; }
  check("defineGuard: sanitize refuses on high finding", threw);

  // resolveOpts (and the no-argument default path in validate / resolveOpts).
  check("defineGuard: resolveOpts applies profile",
    guard.resolveOpts({ profile: "balanced" }).maxBytes === 512);
  check("defineGuard: validate with no opts arg resolves defaults",
    guard.validate("hello").ok === true);
  check("defineGuard: resolveOpts with no opts arg → defaults",
    guard.resolveOpts().maxBytes === 256);

  // buildProfile (makeProfileBuilder-backed).
  var custom = guard.buildProfile({ extends: "strict", overrides: { maxBytes: 99 } });
  check("defineGuard: buildProfile composes strict + override",
    custom.maxBytes === 99 && custom.bidiPolicy === "reject");

  // compliancePosture (lookupCompliancePosture-backed clone).
  check("defineGuard: compliancePosture returns overlay clone",
    guard.compliancePosture("hipaa").forensicSnippetBytes === 64);
  threw = false;
  try { guard.compliancePosture("nope"); }
  catch (e) { threw = e.code === "gccov.bad-posture"; }
  check("defineGuard: compliancePosture unknown throws bad-posture", threw);

  // loadRulePack.
  guard.loadRulePack({ id: "pk", rules: [] });
  check("defineGuard: loadRulePack accepts a pack", true);

  // Default gate (content KIND → extractBytesAsText dispatch); gate() with no
  // opts exercises the defaultGate resolve-with-{} default.
  var gate = guard.gate({});
  var gateNoOpts = guard.gate();
  check("defineGuard: gate() with no opts serves clean bytes",
    (await gateNoOpts.check({ bytes: Buffer.from("hello") })).action === "serve");
  check("defineGuard: default gate serves clean bytes",
    (await gate.check({ bytes: Buffer.from("hello") })).action === "serve");
  check("defineGuard: default gate refuses hostile bytes",
    (await gate.check({ bytes: Buffer.from("BADxyz") })).action === "refuse");
  check("defineGuard: default gate serves when no ctx value",
    (await gate.check({})).action === "serve");

  // Construction error branches.
  threw = false;
  try {
    GC.defineGuard({ name: "gccov2", kind: "weird-kind",
      profiles: GUARD_PROFILES, errorClass: GCE, validate: function () { return { ok: true, issues: [] }; } });
  } catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("defineGuard: custom kind without gate throws bad-opt", threw);

  threw = false;
  try {
    GC.defineGuard({ name: "gccov3", kind: "content", profiles: GUARD_PROFILES,
      errorClass: GCE, errorName: "Dup" });
  } catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("defineGuard: errorClass + errorName both → bad-opt", threw);

  threw = false;
  try {
    GC.defineGuard({ name: "gccov4", kind: "content", profiles: GUARD_PROFILES, errorClass: GCE });
  } catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("defineGuard: missing validate/detect → bad-opt", threw);

  threw = false;
  try { GC.defineGuard({ kind: "content" }); }
  catch (e) { threw = e instanceof GCE; }
  check("defineGuard: missing name throws", threw);
}

async function testDefineGuardIdentifierKind() {
  // Identifier KIND with explicit defaults + postures (non-base branch) —
  // covers the ctx-field dispatch loop in _ctxValueForKind.
  var guard = GC.defineGuard({
    name: "gcid", kind: "identifier", errorName: "GcCoverageIdentError",
    profiles: { strict: { maxBytes: 64 }, balanced: { maxBytes: 128 }, permissive: { maxBytes: 256 } },
    defaults: { maxBytes: 64, mode: "enforce" },
    postures: { hipaa: "strict", "pci-dss": "strict", gdpr: "strict", soc2: "strict" },
    validate: function (value) {
      if (String(value).indexOf(" ") !== -1) {
        return { ok: false, issues: [{ kind: "id.space", severity: "high", snippet: "space" }] };
      }
      // No `issues` field on the clean path exercises the default gate's
      // `rv.issues || []` fallback.
      return { ok: true };
    },
  });
  check("defineGuard(identifier): explicit DEFAULTS kept", guard.DEFAULTS.maxBytes === 64);
  check("defineGuard(identifier): explicit COMPLIANCE_POSTURES kept",
    guard.COMPLIANCE_POSTURES.hipaa === "strict");
  var gate = guard.gate({});
  check("defineGuard(identifier): reads ctx.identifier field",
    (await gate.check({ identifier: "cleanid" })).action === "serve");
  check("defineGuard(identifier): reads ctx.token fallback field",
    (await gate.check({ token: "has space" })).action === "refuse");
  check("defineGuard(identifier): no ctx value → serve",
    (await gate.check({})).action === "serve");
}

async function testDefineGuardDerivedDefaults() {
  // Neither `base` nor explicit `defaults` / `postures`, and a `detect`
  // without `inputContract` — exercises the profiles.strict default, the
  // ALL_STRICT_POSTURES default, and the "raw" input-contract default.
  var guard = GC.defineGuard({
    name: "gcraw", kind: "content", errorName: "GcCoverageRawError",
    profiles: GUARD_PROFILES,
    detect: function (input) {
      return String(input).indexOf("NO") === 0
        ? [{ kind: "raw.bad", severity: "high", snippet: "no" }] : [];
    },
  });
  check("defineGuard(raw): DEFAULTS falls back to profiles.strict",
    guard.DEFAULTS.maxBytes === 256 && guard.DEFAULTS.bidiPolicy === "reject");
  check("defineGuard(raw): postures default to ALL_STRICT_POSTURES",
    guard.COMPLIANCE_POSTURES.hipaa === "strict");
  check("defineGuard(raw): generated validate (raw contract) clean → ok",
    guard.validate("fine", {}).ok === true);
  check("defineGuard(raw): generated validate (raw contract) hostile → not ok",
    guard.validate("NOxyz", {}).ok === false);
}

async function testResidualBranches() {
  // validateGateShape with an explicit custom errorClass argument.
  var threw = false;
  try { GC.validateGateShape(null, "lbl", GCE); }
  catch (e) { threw = e instanceof GCE && e.code === "gate-contract/bad-shape"; }
  check("validateGateShape: explicit errorClass argument used", threw);

  // check() with no ctx + a check returning undefined → default serve decision.
  var noCtxGate = GC.defineGate({ name: "noctx", check: async function () { return undefined; } });
  var noCtx = await noCtxGate.check();
  check("defineGate: no ctx + undefined decision → default serve", noCtx.action === "serve");

  // onAudit returning null emits the framework's default entry.
  var audit = makeAuditCollector();
  var nullAuditGate = GC.defineGate({
    name: "auditnull", audit: audit,
    onAudit: function () { return null; },
    check: async function () { return serveCheck(); },
  });
  await nullAuditGate.check({ bytes: Buffer.from("x") });
  check("defineGate: onAudit null → default entry emitted",
    audit.rows.some(function (r) { return r.action === "auditnull.serve"; }));

  // contentTypeMux with no contentType → "" → default fallback.
  var ctMux = GC.contentTypeMux({ "text/csv": serveGate("c"), "default": refuseGate("d") });
  check("contentTypeMux: missing contentType → default",
    (await ctMux.check({ bytes: Buffer.from("x") })).action === "refuse");

  // byRoute with no route + a "default" fallback key.
  var byRouteDefault = GC.byRoute({ "/admin/*": serveGate("a"), "default": refuseGate("d") });
  check("byRoute: missing route + default-key fallback",
    (await byRouteDefault.check({ bytes: Buffer.from("x") })).action === "refuse");

  // buildContentGate severity fallback on a critical finding (no disposition).
  var critGate = GC.buildContentGate({
    name: "cg-crit", opts: {},
    validate: function () { return { ok: false, issues: [{ kind: "k", severity: "critical" }] }; },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: critical severity fallback refuses",
    (await critGate.check({ bytes: Buffer.from("x") })).action === "refuse");

  // buildContentGate extraIssues returning undefined → treated as no issues.
  var extraNone = GC.buildContentGate({
    name: "cg-extranone", opts: {},
    validate: function () { return { ok: true, issues: [] }; },
    extraIssues: function () { return undefined; },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: extraIssues undefined → serve",
    (await extraNone.check({ bytes: Buffer.from("x") })).action === "serve");

  // buildContentGate producer returning a Buffer passes through unchanged.
  var bufSan = GC.buildContentGate({
    name: "cg-buf", opts: {},
    validate: function () {
      return { ok: false, issues: [{ kind: "k", severity: "high", disposition: "sanitize" }] };
    },
    produceSanitized: function () { return Buffer.from("bufclean"); },
  });
  var bufD = await bufSan.check({ bytes: Buffer.from("x") });
  check("buildContentGate: Buffer producer output preserved",
    bufD.action === "sanitize" && bufD.sanitized.toString() === "bufclean");

  // resolveProfileAndPosture with a cfg that omits `defaults`.
  var noDefaults = GC.resolveProfileAndPosture({ profile: "strict" },
    { profiles: { strict: { a: 1 } }, compliancePostures: {}, errorClass: GCE, errCodePrefix: "csv" });
  check("resolveProfileAndPosture: cfg without defaults still resolves", noDefaults.a === 1);

  // resolveProfileAndPosture with omitted opts → default {}.
  var noOpts = GC.resolveProfileAndPosture(undefined,
    { profiles: { strict: { a: 1 } }, compliancePostures: {}, defaults: { d: 1 },
      errorClass: GCE, errCodePrefix: "csv" });
  check("resolveProfileAndPosture: omitted opts defaults to {}", noOpts.d === 1);

  // validateGateShape with no label uses the default "gate" label.
  var vg = serveGate("vg-nolabel");
  check("validateGateShape: default label path returns gate", GC.validateGateShape(vg) === vg);

  // Forensic snapshot on STRING bytes + a refusal carrying no issues array.
  var store = makeForensicStore();
  var strForensic = GC.defineGate({
    name: "strforensic", forensicSnippetBytes: 4, forensicEvidenceStore: store,
    check: async function () { return { ok: false, action: "refuse" }; },
  });
  var sf = await strForensic.check({ bytes: "hostile-string-payload" });
  check("defineGate: forensic snapshot from string bytes",
    Buffer.isBuffer(sf.forensicSnapshot) && sf.forensicSnapshot.length === 4);
  await helpers.waitUntil(function () { return store.writes.length >= 1; },
    { timeoutMs: 3000, label: "residual: string-bytes forensic write" });
  check("defineGate: forensic write defaults issues to []",
    Array.isArray(store.writes[0].issues) && store.writes[0].issues.length === 0);

  // shadowMode with no opts → default "shadow" name.
  var candRan = false;
  var stagedDefault = GC.shadowMode(serveGate("prim2"),
    GC.defineGate({ name: "cand2", check: async function () { candRan = true; return serveCheck(); } }));
  check("shadowMode: default name", stagedDefault.name === "shadow");
  await stagedDefault.check({ bytes: Buffer.from("x") });
  await helpers.waitUntil(function () { return candRan; },
    { timeoutMs: 3000, label: "residual: shadow default-opts candidate ran" });

  // cachingGate / workerThreadGate with no opts argument.
  threw = false;
  try { GC.cachingGate(serveGate("cg2")); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("cachingGate: no opts → bad-opt (missing backend)", threw);
  threw = false;
  try { GC.workerThreadGate(serveGate("w2")); }
  catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("workerThreadGate: no opts → bad-opt (missing worker)", threw);

  // makeProfileResolver's returned function with no opts → default profile.
  var resolver = GC.makeProfileResolver({
    profiles: { strict: { a: 1 } }, postures: {}, defaults: "strict",
    errorClass: GCE, codePrefix: "csv",
  });
  check("makeProfileResolver: no opts → default profile", resolver() === "strict");

  // compliancePostures with no spec → bad-base (spec.base undefined).
  threw = false;
  try { GC.compliancePostures({ strict: {}, balanced: {} }); }
  catch (e) { threw = e.code === "gate-contract/bad-base"; }
  check("compliancePostures: omitted spec → bad-base", threw);

  // buildGuardGate with undefined opts.
  var bgg = GC.buildGuardGate("bgg-noopts", undefined, async function () { return serveCheck(); });
  check("buildGuardGate: undefined opts still builds",
    (await bgg.check({ bytes: Buffer.from("x") })).action === "serve");

  // buildContentGate with no opts on the spec.
  var cgNoOpts = GC.buildContentGate({
    name: "cg-noopts",
    validate: function () { return { ok: true, issues: [] }; },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: spec without opts serves clean",
    (await cgNoOpts.check({ bytes: Buffer.from("x") })).action === "serve");

  // buildContentGate low-severity fallback → audit-only (ternary audit arm).
  var lowGate = GC.buildContentGate({
    name: "cg-low", opts: {},
    validate: function () { return { ok: true, issues: [{ kind: "k", severity: "low" }] }; },
    produceSanitized: function (s) { return s; },
  });
  check("buildContentGate: low-severity fallback → audit-only",
    (await lowGate.check({ bytes: Buffer.from("x") })).action === "audit-only");

  // composeHooks with no argument → null.
  check("composeHooks: no argument → null", GC.composeHooks() === null);

  // defineGuard / defineParser with no errorName + no errorClass mint a
  // default-named error class.
  var autoGuard = GC.defineGuard({
    name: "gccovauto", kind: "content", profiles: GUARD_PROFILES,
    validate: function () { return { ok: true, issues: [] }; },
  });
  check("defineGuard: default error class minted",
    Object.keys(autoGuard).some(function (k) { return /Error$/.test(k) && typeof autoGuard[k] === "function"; }));
  var autoParser = GC.defineParser({
    name: "gccovautoparse", entry: function () { return true; }, profiles: { strict: {} },
  });
  check("defineParser: default error class minted",
    Object.keys(autoParser).some(function (k) { return /Error$/.test(k) && typeof autoParser[k] === "function"; }));
}

async function testDefineGuardSanitizeAmplification() {
  // The text-scrubber shape: sanitizeAmplificationCap opts into the
  // "sanitize must shrink, never grow" post-condition, and sanitizeSeverities
  // narrows the refusal set. Drives the generated-sanitize bad-input +
  // amplification-cap branches.
  var guard = GC.defineGuard({
    name: "gcamp", kind: "content", errorName: "GcCoverageAmpError",
    profiles: {
      strict:     { maxGrowth: 2 },
      balanced:   { maxGrowth: 2 },
      permissive: { maxGrowth: 2 },
    },
    base: 64,
    detect: function (input) {
      var s = String(input);
      if (s.indexOf("NOSNIP") === 0) {
        // bad-input finding with no snippet → the default-message fallback.
        return [{ kind: "bad-input", severity: "high" }];
      }
      if (s.indexOf("BADIN") === 0) {
        return [{ kind: "bad-input", severity: "high", snippet: "unprocessable shape" }];
      }
      if (s.indexOf("HI") === 0) {
        return [{ kind: "content.high", severity: "high", ruleId: "gcamp.high", snippet: "hi" }];
      }
      return [];
    },
    inputContract: "text",
    sanitizeSeverities: ["critical", "high"],
    sanitizeAmplificationCap: "maxGrowth",
    sanitizeTransform: function (subject) {
      return subject.indexOf("GROW") === 0 ? subject + "x".repeat(1000) : subject;
    },
  });

  // Non-string input rejected by the ampCapField text contract.
  var threw = false;
  try { guard.sanitize(42, {}); }
  catch (e) { threw = e.code === "gcamp.bad-input"; }
  check("defineGuard(amp): non-string sanitize input → bad-input", threw);

  // A bad-input FINDING (on a string subject) refuses always.
  threw = false;
  try { guard.sanitize("BADINxyz", {}); }
  catch (e) { threw = e.code === "gcamp.bad-input"; }
  check("defineGuard(amp): bad-input finding refuses", threw);

  // A bad-input finding with no snippet uses the default message.
  var noSnipMsg = null;
  try { guard.sanitize("NOSNIPxyz", {}); }
  catch (e) { noSnipMsg = e.message; }
  check("defineGuard(amp): bad-input without snippet → default message",
    /not processable/.test(noSnipMsg || ""));

  // A high finding refuses via throwOnRefusalSeverity (narrowed severities set).
  threw = false;
  try { guard.sanitize("HIxyz", {}); }
  catch (e) { threw = e instanceof guard.GcCoverageAmpError; }
  check("defineGuard(amp): high finding refuses", threw);

  // Amplifying transform trips the growth cap.
  threw = false;
  try { guard.sanitize("GROWvalue", {}); }
  catch (e) { threw = e.code === "gcamp.sanitize-amplified"; }
  check("defineGuard(amp): output over growth cap → sanitize-amplified", threw);

  // Clean, non-amplifying input returns the transform output.
  check("defineGuard(amp): clean input returns transform output",
    guard.sanitize("okvalue", {}) === "okvalue");
}

function testDefineParser() {
  var parser = GC.defineParser({
    name: "gcparser", entry: function (line) { return { ok: line.length > 0 }; },
    errorName: "GcCoverageParserError",
    profiles: { strict: { maxLine: 512 } },
    extra: { KNOWN_VERBS: ["USER", "PASS"] },
  });
  check("defineParser: entry exported under default 'validate'",
    typeof parser.validate === "function" && parser.validate("USER x").ok === true);
  check("defineParser: PROFILES surfaced", parser.PROFILES.strict.maxLine === 512);
  check("defineParser: COMPLIANCE_POSTURES defaults to ALL_STRICT",
    parser.COMPLIANCE_POSTURES.hipaa === "strict");
  check("defineParser: compliancePosture returns profile name",
    parser.compliancePosture("hipaa") === "strict");
  check("defineParser: compliancePosture unknown → null",
    parser.compliancePosture("not-a-regime") === null);
  check("defineParser: extra merged", parser.KNOWN_VERBS.length === 2);
  check("defineParser: error class exported",
    typeof parser.GcCoverageParserError === "function");

  // entryName override.
  var custom = GC.defineParser({
    name: "gcparser2", entry: function () { return true; }, entryName: "parse",
    errorClass: GCE, profiles: { strict: {} },
  });
  check("defineParser: entryName override", typeof custom.parse === "function");

  var threw = false;
  try {
    GC.defineParser({ name: "gcp3", entry: 5, profiles: { strict: {} }, errorClass: GCE });
  } catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("defineParser: non-function entry → bad-opt", threw);

  threw = false;
  try {
    GC.defineParser({ name: "gcp4", entry: function () {}, profiles: { strict: {} },
      errorClass: GCE, errorName: "Dup" });
  } catch (e) { threw = e.code === "gate-contract/bad-opt"; }
  check("defineParser: errorClass + errorName both → bad-opt", threw);

  threw = false;
  try { GC.defineParser({ entry: function () {}, profiles: {} }); }
  catch (e) { threw = e instanceof GCE; }
  check("defineParser: missing name throws", threw);
}

async function run() {
  testIssueSeverities();
  testSummarizeIssues();
  testSeverityAndPolicyDispositions();
  testBuildProfileComposition();
  testMakeProfileBuilder();
  testMakeProfileResolverAndName();
  testResolveProfileAndPosture();
  testGlobalPostureFallback();
  testUnmappedPostureWarning();
  testLookupCompliancePosture();
  testMakePostureAccessor();
  testCompliancePosturesFactory();
  testStrictDefaults();
  testRunIssueValidatorContracts();
  testBadInputResult();
  testDetectStringInput();
  await testComposeHooks();
  testThrowOnRefusalSeverity();
  testExtractBytesAsText();
  testIdentifierFixtures();
  testMakeRulePackLoader();
  await testValidateGateShapeAndRunGate();
  testDefineGateBadOpts();
  await testDefineGateLifecycle();
  await testDefineGateCheckThrows();
  await testDefineGateTimeout();
  await testDefineGateBeforeCheckHooks();
  await testDefineGateAfterAndIssueHooks();
  await testDefineGateAuditHooks();
  await testDefineGateModes();
  await testDefineGateForensicAndCache();
  await testBuildGuardGate();
  await testComposeGates();
  await testMultiplexAndContentTypeMux();
  await testTierRouteDirectionDispatch();
  await testShadowCanaryCachingWorkerGates();
  await testBuildContentGate();
  await testDefineGuard();
  await testDefineGuardIdentifierKind();
  await testDefineGuardDerivedDefaults();
  await testDefineGuardSanitizeAmplification();
  await testResidualBranches();
  testDefineParser();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

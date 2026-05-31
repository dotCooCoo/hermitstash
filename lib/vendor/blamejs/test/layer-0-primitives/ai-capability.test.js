"use strict";
/**
 * Layer 0 — b.ai.capability registry + cheapest-satisfying-model
 * router. NIST AI RMF MAP 2.x capability documentation + Model Cards
 * descriptor; routing to the cheapest sufficient model defends
 * over-provisioning spend and catches capability mismatch before the
 * inference call.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

function _fleet() {
  return b.ai.capability.create({
    audit: false,
    models: {
      haiku:  { maxContextTokens: 200000, maxOutputTokens: 8192, reasoningTier: "basic",
                costPer1kInputTokens: 0.001, costPer1kOutputTokens: 0.005, promptCachingMaxTokens: 200000 },
      sonnet: { maxContextTokens: 200000, reasoningTier: "standard", toolUse: true, structuredOutput: true,
                costPer1kInputTokens: 0.003, costPer1kOutputTokens: 0.015 },
      opus:   { maxContextTokens: 200000, reasoningTier: "advanced", toolUse: true, structuredOutput: true,
                modalitiesIn: ["text", "image"], citationSupport: true,
                costPer1kInputTokens: 0.015, costPer1kOutputTokens: 0.075 },
    },
  });
}

async function testDescribeListRegister() {
  var f = _fleet();
  check("list: all registered models", f.list().sort().join(",") === "haiku,opus,sonnet");
  var d = f.describe("opus");
  check("describe: returns descriptor", d.modelId === "opus" && d.reasoningTier === "advanced");
  check("describe: defaults applied (modalitiesOut → text)", d.modalitiesOut.length === 1 && d.modalitiesOut[0] === "text");
  check("describe: maxOutputTokens defaults to maxContextTokens", f.describe("sonnet").maxOutputTokens === 200000);
  var unknown = null;
  try { f.describe("gpt"); } catch (e) { unknown = e; }
  check("describe: unknown model throws", unknown && unknown.code === "ai-capability/unknown-model");
  f.register("nano", { maxContextTokens: 32000, costPer1kInputTokens: 0.0005, costPer1kOutputTokens: 0.001 });
  check("register: new model is routable", f.describe("nano").maxContextTokens === 32000);
}

async function testRouteCheapestSatisfying() {
  var f = _fleet();
  var p = f.route({ requirements: { toolUse: true }, costBasis: { inputTokens: 4000, outputTokens: 500 } });
  // sonnet: 4*0.003 + 0.5*0.015 = 0.0195 ; opus: 4*0.015 + 0.5*0.075 = 0.0975 → sonnet cheaper
  check("route: cheapest tool-using model is sonnet", p.modelId === "sonnet");
  check("route: estimatedCost reflects costBasis", Math.abs(p.estimatedCost - 0.0195) < 1e-9);
  check("route: reason names candidate count", p.reason === "cheapest-of-2");
}

async function testRouteRankingWithoutCostBasis() {
  var f = _fleet();
  // No costBasis → rank by sum of per-1k rates. haiku 0.006 < sonnet 0.018 < opus 0.090.
  var p = f.route({ requirements: {} });
  check("route: no requirements + no costBasis picks cheapest overall (haiku)", p.modelId === "haiku");
}

async function testRouteModalityAndReasoning() {
  var f = _fleet();
  var img = f.route({ requirements: { modalitiesIn: ["image"] } });
  check("route: image-in requirement selects opus (only match)", img.modelId === "opus");
  var adv = f.route({ requirements: { minReasoningTier: "advanced" } });
  check("route: advanced reasoning selects opus", adv.modelId === "opus");
  var std = f.route({ requirements: { minReasoningTier: "standard" }, costBasis: { inputTokens: 1000, outputTokens: 0 } });
  check("route: standard tier admits sonnet (cheaper than opus)", std.modelId === "sonnet");
}

async function testTieBreakDeterministic() {
  var f = b.ai.capability.create({
    audit: false,
    models: {
      zebra: { maxContextTokens: 1000, costPer1kInputTokens: 0.002, costPer1kOutputTokens: 0 },
      alpha: { maxContextTokens: 1000, costPer1kInputTokens: 0.002, costPer1kOutputTokens: 0 },
    },
  });
  var p = f.route({ requirements: {} });
  check("tie-break: equal cost resolves to lexicographically-first model id", p.modelId === "alpha");
}

async function testSatisfiesPreciseFailures() {
  var f = _fleet();
  var r = f.satisfies("haiku", { toolUse: true, minReasoningTier: "advanced", minContextTokens: 300000 });
  check("satisfies: ok=false when unmet", r.ok === false);
  var reqs = r.failures.map(function (x) { return x.requirement; }).sort();
  check("satisfies: every unmet requirement listed", reqs.join(",") === "minContextTokens,minReasoningTier,toolUse");
  var hit = r.failures.filter(function (x) { return x.requirement === "minContextTokens"; })[0];
  check("satisfies: failure names need + have", hit.need === 300000 && hit.have === 200000);
  check("satisfies: ok=true when met", f.satisfies("opus", { toolUse: true, citationSupport: true }).ok === true);
}

async function testFallbackAndNoCandidate() {
  var f = _fleet();
  var refused = null;
  try { f.route({ requirements: { minContextTokens: 999999 } }); } catch (e) { refused = e; }
  check("route: no match + no fallback throws", refused && refused.code === "ai-capability/no-candidate");
  var fb = f.route({ requirements: { minContextTokens: 999999 }, fallback: "opus" });
  check("route: fallback returned when no match", fb.modelId === "opus" && fb.reason === "fallback");
  var badFb = null;
  try { f.route({ requirements: { minContextTokens: 999999 }, fallback: "ghost" }); } catch (e) { badFb = e; }
  check("route: unknown fallback throws", badFb && badFb.code === "ai-capability/unknown-model");
}

async function testDescriptorFrozenImmutable() {
  var f = _fleet();
  var d = f.describe("opus");
  var threw = false;
  try { d.maxContextTokens = 1; } catch (_e) { threw = true; }   // strict mode → throws
  check("descriptor: frozen (mutation rejected / ignored)", threw === true || f.describe("opus").maxContextTokens === 200000);
  var threw2 = false;
  try { d.modalitiesIn.push("audio"); } catch (_e) { threw2 = true; }
  check("descriptor: modalities array frozen", threw2 === true || f.describe("opus").modalitiesIn.indexOf("audio") === -1);
}

async function testConfigValidation() {
  var cases = [
    [{ models: {} }, "ai-capability/bad-models"],
    [{ models: [] }, "ai-capability/bad-models"],
    [{ models: { m: { maxContextTokens: 0 } } }, "ai-capability/bad-descriptor"],
    [{ models: { m: { maxContextTokens: 1.5 } } }, "ai-capability/bad-descriptor"],
    [{ models: { m: { maxContextTokens: 100, reasoningTier: "genius" } } }, "ai-capability/bad-descriptor"],
    [{ models: { m: { maxContextTokens: 100, modalitiesIn: "text" } } }, "ai-capability/bad-descriptor"],
    [{ models: { m: { maxContextTokens: 100, costPer1kInputTokens: -1 } } }, "ai-capability/bad-descriptor"],
    [{ models: { m: { maxContextTokens: 100, bogusField: true } } }, null],   // unknown descriptor key → validateOpts throws (any error)
  ];
  var ok = true;
  for (var i = 0; i < cases.length; i++) {
    var caught = null;
    try { b.ai.capability.create(cases[i][0]); } catch (e) { caught = e; }
    if (!caught) { ok = false; check("config: case " + i + " should have thrown", false); continue; }
    if (cases[i][1] && caught.code !== cases[i][1]) { ok = false; check("config: case " + i + " expected " + cases[i][1] + " got " + caught.code, false); }
  }
  check("config: every malformed create() throws", ok);
}

async function testRequirementsValidation() {
  var f = _fleet();
  var bads = [
    [function () { f.route({ requirements: { minReasoningTier: "genius" } }); }, "ai-capability/bad-requirements"],
    [function () { f.route({ requirements: { modalitiesIn: "image" } }); }, "ai-capability/bad-requirements"],
    [function () { f.route({ requirements: [] }); }, "ai-capability/bad-requirements"],
    [function () { f.route({ requirements: {}, costBasis: [] }); }, "ai-capability/bad-requirements"],
  ];
  var ok = true;
  for (var i = 0; i < bads.length; i++) {
    var caught = null;
    try { bads[i][0](); } catch (e) { caught = e; }
    if (!caught || caught.code !== bads[i][1]) ok = false;
  }
  check("requirements: malformed requirements / costBasis throw", ok);
  var unknownKey = null;
  try { f.route({ requirements: { bogusReq: 1 } }); } catch (e) { unknownKey = e; }
  check("requirements: unknown requirement key rejected", unknownKey !== null);
}

async function testNonNumericRequirementFailsClosed() {
  // Codex P1 on PR #179 — a non-numeric numeric-minimum (NaN, "128k",
  // a bad parse) used to make the `<` comparison false and SILENTLY
  // satisfy the requirement, so an undersized model could be picked.
  // It must now fail fast at the validation boundary, not fail open.
  var f = _fleet();
  var bads = [
    function () { f.route({ requirements: { minContextTokens: "300000" } }); },   // string
    function () { f.route({ requirements: { minContextTokens: NaN } }); },
    function () { f.route({ requirements: { minOutputTokens: Infinity } }); },
    function () { f.route({ requirements: { minPromptCachingTokens: -1 } }); },
    function () { f.satisfies("opus", { minContextTokens: "lots" }); },           // same boundary on satisfies()
    function () { f.route({ requirements: { toolUse: 1 } }); },                   // non-boolean opt-in
    function () { f.route({ requirements: { citationSupport: "yes" } }); },
  ];
  var ok = true;
  for (var i = 0; i < bads.length; i++) {
    var caught = null;
    try { bads[i](); } catch (e) { caught = e; }
    if (!caught || caught.code !== "ai-capability/bad-requirements") { ok = false; }
  }
  check("requirements: non-numeric / non-boolean values fail closed (no silent satisfy)", ok);
  // A valid numeric minimum still routes.
  check("requirements: valid numeric minimum still routes",
    f.route({ requirements: { minContextTokens: 100000 } }).modelId === "haiku");
}

async function testMalformedCostBasisFailsFast() {
  // Codex P2 on PR #179 — a malformed costBasis field used to coerce
  // to 0 and underprice a candidate, deterministically biasing the
  // "cheapest" choice. Present-but-non-numeric fields now throw.
  var f = _fleet();
  var bads = [
    function () { f.route({ requirements: {}, costBasis: { inputTokens: "lots" } }); },
    function () { f.route({ requirements: {}, costBasis: { outputTokens: NaN } }); },
    function () { f.route({ requirements: {}, costBasis: { inputTokens: -5 } }); },
    function () { f.route({ requirements: {}, costBasis: { bogus: 1 } }); },        // unknown key
  ];
  var ok = true;
  for (var i = 0; i < bads.length; i++) {
    var caught = null;
    try { bads[i](); } catch (e) { caught = e; }
    if (!caught) ok = false;
  }
  check("costBasis: malformed fields fail fast (no silent zero-coercion)", ok);
  // An absent field is still fine (treated as 0 tokens on that side).
  check("costBasis: absent field defaults cleanly",
    f.route({ requirements: {}, costBasis: { inputTokens: 1000 } }).modelId === "haiku");
}

async function run() {
  await testDescribeListRegister();
  await testRouteCheapestSatisfying();
  await testRouteRankingWithoutCostBasis();
  await testRouteModalityAndReasoning();
  await testTieBreakDeterministic();
  await testSatisfiesPreciseFailures();
  await testFallbackAndNoCandidate();
  await testDescriptorFrozenImmutable();
  await testConfigValidation();
  await testRequirementsValidation();
  await testNonNumericRequirementFailsClosed();
  await testMalformedCostBasisFailsFast();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[ai-capability] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

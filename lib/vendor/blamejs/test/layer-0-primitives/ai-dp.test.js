// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.ai.dp float-safe differential privacy. Snapping-
 * mechanism Laplace (Mironov 2012) + discrete Gaussian (CKS20) with
 * CSPRNG noise; per-scope ε/δ budgets with basic + Rényi-DP
 * accounting. Statistical checks validate the noise distributions;
 * the budget tests validate composition + exhaustion.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

// A budget large enough that the statistical loops never exhaust it.
function _bigBudget() {
  return b.ai.dp.budget({ scope: "stat", epsilon: 1e12, delta: 0.9, accounting: "basic", audit: false });
}
function _mean(xs) { var s = 0; for (var i = 0; i < xs.length; i++) s += xs[i]; return s / xs.length; }
function _variance(xs, mean) { var s = 0; for (var i = 0; i < xs.length; i++) s += (xs[i] - mean) * (xs[i] - mean); return s / xs.length; }

async function testMechanismValidation() {
  var cases = [
    [{ type: "exponential", sensitivity: 1, epsilon: 1 }, "ai-dp/bad-mechanism"],
    [{ type: "laplace", sensitivity: 0, epsilon: 1, bound: 10 }, "ai-dp/bad-sensitivity"],
    [{ type: "laplace", sensitivity: 1, epsilon: 0, bound: 10 }, "ai-dp/bad-epsilon"],
    [{ type: "laplace", sensitivity: 1, epsilon: 1 }, "ai-dp/bad-bound"],
    [{ type: "gaussian", sensitivity: 1, epsilon: 0.5 }, "ai-dp/bad-delta"],
    [{ type: "gaussian", sensitivity: 1, epsilon: 0.5, delta: 1 }, "ai-dp/bad-delta"],
    [{ type: "gaussian", sensitivity: 1, epsilon: 2, delta: 1e-6 }, "ai-dp/epsilon-too-large"],
  ];
  var ok = true;
  for (var i = 0; i < cases.length; i++) {
    var caught = null;
    try { b.ai.dp.mechanism(cases[i][0]); } catch (e) { caught = e; }
    if (!caught || caught.code !== cases[i][1]) { ok = false; check("mechanism case " + i + " expected " + cases[i][1] + " got " + (caught && caught.code), false); }
  }
  check("mechanism: malformed configs throw the right codes", ok);
  var lap = b.ai.dp.mechanism({ type: "laplace", sensitivity: 1, epsilon: 0.5, bound: 1000 });
  check("mechanism: laplace scale = sensitivity/epsilon", lap.scale === 2 && lap.delta === 0);
  var gss = b.ai.dp.mechanism({ type: "gaussian", sensitivity: 1, epsilon: 0.5, delta: 1e-6 });
  check("mechanism: gaussian computes sigma", gss.sigma > 0 && gss.sigma2 > 0);
}

async function testSnappingLaplaceDistribution() {
  var bud = _bigBudget();
  var m = b.ai.dp.mechanism({ type: "laplace", sensitivity: 1, epsilon: 0.5, bound: 1e6 });   // scale 2 → Λ 2
  var N = 40000, xs = [], onGrid = true;
  for (var i = 0; i < N; i++) {
    var v = bud.consume(m, 100).value;
    xs.push(v);
    if (v % 2 !== 0) onGrid = false;                       // snapping grid Λ = 2
  }
  check("laplace: every output lands on the power-of-two snapping grid", onGrid);
  var mean = _mean(xs);
  check("laplace: mean ≈ true value (100)", Math.abs(mean - 100) < 0.3);
  var variance = _variance(xs, mean);
  check("laplace: variance ≈ 2·scale² (8)", variance > 6.5 && variance < 9.5);
}

async function testLaplaceClamping() {
  var bud = _bigBudget();
  var m = b.ai.dp.mechanism({ type: "laplace", sensitivity: 1, epsilon: 1, bound: 10 });
  var withinBound = true;
  for (var i = 0; i < 5000; i++) {
    var v = bud.consume(m, 1000000).value;                 // true value far outside the bound
    if (v < -10 || v > 10) withinBound = false;
  }
  check("laplace: output is clamped to ±bound", withinBound);
}

async function testDiscreteGaussianDistribution() {
  var bud = _bigBudget();
  var m = b.ai.dp.mechanism({ type: "gaussian", sensitivity: 1, epsilon: 0.5, delta: 1e-6 });
  var N = 40000, xs = [], allInt = true;
  for (var i = 0; i < N; i++) {
    var v = bud.consume(m, 0).value;
    xs.push(v);
    if (!Number.isInteger(v)) allInt = false;
  }
  check("gaussian: discrete — every output is an integer", allInt);
  var mean = _mean(xs);
  check("gaussian: mean ≈ 0", Math.abs(mean) < 0.5);
  var variance = _variance(xs, mean);
  // Discrete Gaussian variance ≈ σ² for σ not tiny.
  check("gaussian: variance ≈ σ²", variance > m.sigma2 * 0.85 && variance < m.sigma2 * 1.15);
}

async function testBudgetBasicComposition() {
  var bud = b.ai.dp.budget({ scope: "t", epsilon: 1.0, delta: 1e-5, accounting: "basic", audit: false });
  var m = b.ai.dp.mechanism({ type: "laplace", sensitivity: 1, epsilon: 0.3, bound: 100 });
  var r1 = bud.consume(m, 5);
  check("budget: consume returns { value, cost, remaining }",
    typeof r1.value === "number" && r1.cost.epsilon === 0.3 && Math.abs(r1.remaining.epsilon - 0.7) < 1e-9);
  bud.consume(m, 5);
  bud.consume(m, 5);                                        // spent 0.9
  var refused = null;
  try { bud.consume(m, 5); } catch (e) { refused = e; }    // 0.9 + 0.3 > 1.0
  check("budget: basic composition refuses over-ε release", refused && refused.code === "ai-dp/budget-exhausted");
  check("budget: spent reflects three releases", Math.abs(bud.spent().epsilon - 0.9) < 1e-9);
  bud.reset();
  check("budget: reset clears spend", bud.spent().epsilon === 0);
}

async function testBudgetDeltaExhaustion() {
  var bud = b.ai.dp.budget({ scope: "t", epsilon: 1e6, delta: 2.5e-6, accounting: "basic", audit: false });
  var m = b.ai.dp.mechanism({ type: "gaussian", sensitivity: 1, epsilon: 0.1, delta: 1e-6 });
  bud.consume(m, 0); bud.consume(m, 0);                    // δ spent 2e-6
  var refused = null;
  try { bud.consume(m, 0); } catch (e) { refused = e; }    // 2e-6 + 1e-6 > 2.5e-6
  check("budget: δ budget exhaustion refuses (not just ε)", refused && refused.code === "ai-dp/budget-exhausted");
}

async function testRdpTighterThanBasic() {
  function spend(acc) {
    var bud = b.ai.dp.budget({ scope: "s", epsilon: 1e9, delta: 1e-3, accounting: acc, audit: false });
    var m = b.ai.dp.mechanism({ type: "gaussian", sensitivity: 1, epsilon: 0.3, delta: 1e-6 });
    for (var k = 0; k < 12; k++) bud.consume(m, 0);
    return bud.spent().epsilon;
  }
  var basicEps = spend("basic");
  var rdpEps = spend("rdp");
  check("rdp: 12× Gaussian basic sums to 3.6", Math.abs(basicEps - 3.6) < 1e-9);
  check("rdp: Rényi accounting is strictly tighter than basic", rdpEps < basicEps);
}

async function testBudgetValidation() {
  var cases = [
    [{ scope: "", epsilon: 1 }, "ai-dp/bad-scope"],
    [{ scope: "s", epsilon: 0 }, "ai-dp/bad-epsilon"],
    [{ scope: "s", epsilon: 1, delta: 1 }, "ai-dp/bad-delta"],
    [{ scope: "s", epsilon: 1, delta: -1 }, "ai-dp/bad-delta"],
    [{ scope: "s", epsilon: 1, accounting: "zcdp" }, "ai-dp/bad-accounting"],
    [{ scope: "s", epsilon: 1, delta: 0, accounting: "rdp" }, "ai-dp/bad-accounting"],
  ];
  var ok = true;
  for (var i = 0; i < cases.length; i++) {
    var caught = null;
    try { b.ai.dp.budget(cases[i][0]); } catch (e) { caught = e; }
    if (!caught || caught.code !== cases[i][1]) { ok = false; check("budget case " + i + " expected " + cases[i][1] + " got " + (caught && caught.code), false); }
  }
  check("budget: malformed configs throw the right codes", ok);
  // A gaussian mechanism needs a scope delta > 0.
  var bud = b.ai.dp.budget({ scope: "s", epsilon: 1, accounting: "basic", audit: false });
  var refused = null;
  try { bud.consume(b.ai.dp.mechanism({ type: "gaussian", sensitivity: 1, epsilon: 0.5, delta: 1e-6 }), 0); } catch (e) { refused = e; }
  check("budget: gaussian into a δ=0 scope refused", refused && refused.code === "ai-dp/bad-delta");
}

async function run() {
  await testMechanismValidation();
  await testSnappingLaplaceDistribution();
  await testLaplaceClamping();
  await testDiscreteGaussianDistribution();
  await testBudgetBasicComposition();
  await testBudgetDeltaExhaustion();
  await testRdpTighterThanBasic();
  await testBudgetValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[ai-dp] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

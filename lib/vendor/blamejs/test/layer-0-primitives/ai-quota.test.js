// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.ai.quota per-tenant AI usage budgets. Defends OWASP
 * LLM10:2025 unbounded consumption / denial-of-wallet: atomic
 * consume-and-check across tokens / requests / cost-usd /
 * compute-hours dimensions with hard / soft / warn enforcement.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

function _q(over) {
  var base = { dimension: "requests", period: "hour", limit: 3, audit: false };
  if (over) { var k = Object.keys(over); for (var i = 0; i < k.length; i++) base[k[i]] = over[k[i]]; }
  return b.ai.quota.create(base);
}

async function testAccumulatesWithinWindow() {
  var q = _q();
  var r1 = q.consume("t", "m", 1);
  check("consume: first charge counts", r1.used === 1 && r1.allowed === true && r1.exceeded === false);
  check("consume: remaining tracks limit", r1.remaining === 2 && r1.limit === 3);
  var r2 = q.consume("t", "m", 1);
  check("consume: second charge accumulates", r2.used === 2 && r2.remaining === 1);
  check("consume: dimension + period echoed", r2.dimension === "requests" && r2.period === "hour");
  check("consume: effective enforcement echoed", r2.enforcement === "hard");
  check("consume: resetsAt is after windowStart", r2.resetsAt > r2.windowStart);
}

async function testHardConditionalReserve() {
  var q = _q();
  q.consume("t", "m", 3);                                 // exactly at limit — allowed
  check("hard: at-limit charge allowed", q.check("t", "m").used === 3);
  var refused = null;
  try { q.consume("t", "m", 1); } catch (e) { refused = e; }
  check("hard: over-limit consume throws", refused && refused.code === "ai-quota/exceeded");
  check("hard: rejected consume never charges (counter unchanged)", q.check("t", "m").used === 3);
}

async function testHardReserveNoTransientOvercount() {
  // Codex P1 on PR #178 — hard mode must reserve via an atomic
  // conditional test-and-charge, never charge-then-refund. A rejected
  // over-budget call must leave the counter exactly unchanged so a
  // concurrent / subsequent smaller call that fits is not falsely
  // denied by a transient over-count.
  var q = _q({ limit: 10 });
  q.consume("t", "m", 8);
  var refused = null;
  try { q.consume("t", "m", 3); } catch (e) { refused = e; }   // 8+3=11 > 10 → refused
  check("reserve: over-budget call refused", refused && refused.code === "ai-quota/exceeded");
  check("reserve: refused call left counter at 8 (no transient charge)", q.check("t", "m").used === 8);
  var fits = q.consume("t", "m", 1);                            // 8+1=9 ≤ 10 → allowed
  check("reserve: smaller call that fits is not falsely denied", fits.allowed === true && fits.used === 9);
}

async function testSoftAdmitsButReports() {
  var q = _q({ enforcement: "soft" });
  q.consume("t", "m", 3);
  var over = q.consume("t", "m", 2);
  check("soft: over-budget charge stands", over.used === 5);
  check("soft: reported not-allowed for caller to honor", over.allowed === false && over.exceeded === true);
}

async function testWarnAdmitsAdvisory() {
  var q = _q({ enforcement: "warn" });
  q.consume("t", "m", 3);
  var over = q.consume("t", "m", 5);
  check("warn: over-budget charge stands", over.used === 8);
  check("warn: still allowed (advisory only) but flagged exceeded", over.allowed === true && over.exceeded === true);
}

async function testPerCallEnforcementOverride() {
  var q = _q();                                           // default hard
  q.consume("t", "m", 3);
  var over = q.consume("t", "m", 1, { enforcement: "warn" });
  check("override: per-call warn admits over a hard default", over.allowed === true && over.exceeded === true);
  check("override: result reports the effective (overridden) enforcement", over.enforcement === "warn");
  var bad = null;
  try { q.consume("t", "m", 1, { enforcement: "nope" }); } catch (e) { bad = e; }
  check("override: bad per-call enforcement refused", bad && bad.code === "ai-quota/bad-enforcement");
}

async function testLimitResolutionMostSpecificWins() {
  var q = b.ai.quota.create({
    dimension: "tokens", period: "day", limit: 100, audit: false,
    perModel:       { "opus": 200 },
    perTenant:      { "vip": 500 },
    perTenantModel: { "vip|opus": 1000 },
  });
  check("limit: default applies", q.check("anon", "haiku").limit === 100);
  check("limit: perModel overrides default", q.check("anon", "opus").limit === 200);
  check("limit: perTenant overrides perModel", q.check("vip", "haiku").limit === 500);
  check("limit: perTenantModel is most specific", q.check("vip", "opus").limit === 1000);
}

async function testFloatCostDimension() {
  var q = b.ai.quota.create({ dimension: "cost-usd", period: "month", limit: 1.0, audit: false });
  var r = q.consume("t", "m", 0.4);
  check("cost-usd: fractional amount accepted", Math.abs(r.used - 0.4) < 1e-9);
  q.consume("t", "m", 0.4);
  var refused = null;
  try { q.consume("t", "m", 0.4); } catch (e) { refused = e; }
  check("cost-usd: fractional overage refused under hard", refused && refused.code === "ai-quota/exceeded");
  check("cost-usd: refund keeps fractional total", Math.abs(q.check("t", "m").used - 0.8) < 1e-9);
}

async function testKeyCollisionSafety() {
  // A hostile tenant name containing the ":" key separator must not
  // bleed into another (tenant, model) pair's budget. Percent-
  // encoding of tenant + model keeps the namespaces disjoint.
  var q = _q({ limit: 5 });
  q.consume("a:b", "c", 4);
  var other = q.check("a", "b:c");
  check("key-safety: 'a:b'/'c' does not collide with 'a'/'b:c'", other.used === 0);
}

async function testSharedStoreAggregatesAcrossEnforcers() {
  // Two enforcers sharing one store model a two-node cluster: the
  // ceiling is enforced on the AGGREGATE, not per-process.
  var counters = new Map();
  function slot(k, win) {
    var e = counters.get(k);
    if (!e || e.expiresAt <= Date.now()) { e = { v: 0, expiresAt: Date.now() + win }; counters.set(k, e); }
    return e;
  }
  var store = {
    reserve: function (k, amt, limit, win) {
      var e = slot(k, win);
      if (e.v + amt > limit) return { allowed: false, used: e.v };
      e.v += amt; return { allowed: true, used: e.v };
    },
    add: function (k, amt, win) { var e = slot(k, win); e.v += amt; return e.v; },
    get: function (k) { var e = counters.get(k); return (e && e.expiresAt > Date.now()) ? e.v : 0; },
    reset: function (k) { if (k === undefined) counters.clear(); else counters.delete(k); },
  };
  var nodeA = b.ai.quota.create({ dimension: "requests", period: "hour", limit: 10, store: store, audit: false });
  var nodeB = b.ai.quota.create({ dimension: "requests", period: "hour", limit: 10, store: store, audit: false });
  nodeA.consume("t", "m", 6);
  var bView = nodeB.consume("t", "m", 3);
  check("shared-store: node B sees node A's charges", bView.used === 9);
  var refused = null;
  try { nodeB.consume("t", "m", 2); } catch (e) { refused = e; }
  check("shared-store: aggregate ceiling enforced across nodes", refused && refused.code === "ai-quota/exceeded");
}

async function testResetSemantics() {
  var q = _q({ limit: 10 });
  q.consume("t", "m1", 2);
  q.consume("t", "m2", 3);
  q.reset("t", "m1");
  check("reset: per-(tenant,model) clears one key", q.check("t", "m1").used === 0 && q.check("t", "m2").used === 3);
  q.reset("t");
  check("reset: tenant-wide clears remaining models", q.check("t", "m2").used === 0);
  q.consume("t", "m1", 1);
  q.reset();
  check("reset: no-arg clears all", q.check("t", "m1").used === 0);
}

async function testResetTenantWideUnsupportedWithExternalStore() {
  var noop = function () {};
  var store = { reserve: function () { return { allowed: true, used: 0 }; }, add: function () { return 0; }, get: function () { return 0; }, reset: noop };
  var q = b.ai.quota.create({ dimension: "requests", period: "hour", limit: 5, store: store, audit: false });
  var refused = null;
  try { q.reset("t"); } catch (e) { refused = e; }
  check("reset: tenant-wide without model refused on external store", refused && refused.code === "ai-quota/reset-unsupported");
}

async function testConfigValidation() {
  var cases = [
    [{ dimension: "bogus", period: "hour", limit: 1 }, "ai-quota/bad-dimension"],
    [{ dimension: "tokens", period: "fortnight", limit: 1 }, "ai-quota/bad-period"],
    [{ dimension: "tokens", period: "hour", limit: 0 }, "ai-quota/bad-limit"],
    [{ dimension: "tokens", period: "hour", limit: -1 }, "ai-quota/bad-limit"],
    [{ dimension: "tokens", period: "hour", limit: 1, enforcement: "nope" }, "ai-quota/bad-enforcement"],
    [{ dimension: "tokens", period: "hour", limit: 1, perTenant: { x: -3 } }, "ai-quota/bad-override"],
    [{ dimension: "tokens", period: "hour", limit: 1, perModel: [] }, "ai-quota/bad-override"],
    [{ dimension: "tokens", period: "hour", limit: 1, store: { reserve: function () {} } }, "ai-quota/bad-store"],
  ];
  var allCorrect = true;
  for (var i = 0; i < cases.length; i++) {
    var caught = null;
    try { b.ai.quota.create(cases[i][0]); } catch (e) { caught = e; }
    if (!caught || caught.code !== cases[i][1]) {
      allCorrect = false;
      check("config: case " + i + " expected " + cases[i][1] + " got " + (caught && caught.code), false);
    }
  }
  check("config: every malformed create() throws the right code", allCorrect);
  // unknown key rejected by validateOpts
  var unknown = null;
  try { b.ai.quota.create({ dimension: "tokens", period: "hour", limit: 1, bogusKey: 1 }); } catch (e) { unknown = e; }
  check("config: unknown opts key rejected", unknown !== null);
}

async function testConsumeArgValidation() {
  var q = _q();
  var bads = [
    [function () { q.consume("", "m", 1); }, "ai-quota/bad-tenant"],
    [function () { q.consume("t", "", 1); }, "ai-quota/bad-model"],
    [function () { q.consume("t", "m", -1); }, "ai-quota/bad-amount"],
    [function () { q.consume("t", "m", NaN); }, "ai-quota/bad-amount"],
    [function () { q.consume("t", "m", Infinity); }, "ai-quota/bad-amount"],
  ];
  var ok = true;
  for (var i = 0; i < bads.length; i++) {
    var caught = null;
    try { bads[i][0](); } catch (e) { caught = e; }
    if (!caught || caught.code !== bads[i][1]) ok = false;
  }
  check("consume: arg validation throws the right codes", ok);
  check("consume: zero amount is a valid no-op charge", q.consume("t", "m", 0).used === 0);
}

async function testAuditPathDoesNotThrow() {
  // Default audit:true routes through the framework audit module
  // (drop-silent). It must never throw on the request hot path even
  // when audit is uninitialised in layer 0.
  var q = b.ai.quota.create({ dimension: "requests", period: "hour", limit: 1 });
  var threw = false;
  try { q.consume("t", "m", 1); try { q.consume("t", "m", 1); } catch (_e) { /* expected exceeded */ } }
  catch (_e) { threw = true; }
  check("audit: default audit:true path is drop-silent on hot path", threw === false);
}

async function testSecondWindowRollover() {
  // Real wall-clock rollover for the shortest period. passiveObserve
  // lets >1s elapse so the next consume lands in a fresh window —
  // the documented tool for a TTL/elapse assertion (no fixed sleep).
  var q = b.ai.quota.create({ dimension: "requests", period: "second", limit: 2, audit: false });
  q.consume("t", "m", 2);
  check("rollover: window full before boundary", q.check("t", "m").used === 2);
  await helpers.passiveObserve(1100, "ai.quota: per-second window rolls to a fresh budget");
  var fresh = q.consume("t", "m", 1);
  check("rollover: fresh window resets the counter", fresh.used === 1 && fresh.allowed === true);
}

async function run() {
  await testAccumulatesWithinWindow();
  await testHardConditionalReserve();
  await testHardReserveNoTransientOvercount();
  await testSoftAdmitsButReports();
  await testWarnAdmitsAdvisory();
  await testPerCallEnforcementOverride();
  await testLimitResolutionMostSpecificWins();
  await testFloatCostDimension();
  await testKeyCollisionSafety();
  await testSharedStoreAggregatesAcrossEnforcers();
  await testResetSemantics();
  await testResetTenantWideUnsupportedWithExternalStore();
  await testConfigValidation();
  await testConsumeArgValidation();
  await testAuditPathDoesNotThrow();
  await testSecondWindowRollover();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[ai-quota] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

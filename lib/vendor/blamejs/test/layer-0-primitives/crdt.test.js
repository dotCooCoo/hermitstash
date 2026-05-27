"use strict";
/**
 * Layer 0 — b.crdt (state-based CvRDTs).
 *
 * Oracle: the CRDT correctness laws themselves. A state-based CvRDT's merge is
 * a join over a semilattice, so for every type merge must be commutative,
 * associative, and idempotent, and two replicas that apply concurrent ops then
 * merge must converge to the same value. Those laws ARE the specification
 * (Shapiro et al.); each is asserted below alongside worked examples.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var crdt = b.crdt;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
function val(c) { return JSON.stringify(c.value()); }

// Assert the three merge laws for a type, given three instances carrying
// concurrent (disjoint-replica) ops.
function laws(label, a, c, d) {
  check(label + ": commutative", val(a.merge(c)) === val(c.merge(a)));
  check(label + ": associative", val(a.merge(c).merge(d)) === val(a.merge(c.merge(d))));
  check(label + ": idempotent",  val(a.merge(a)) === val(a));
  // Convergence: cross-merge of two replicas lands on one value both ways.
  check(label + ": converges",   val(a.merge(c)) === val(c.merge(a)));
}

function testSurface() {
  // Reference each primitive by its full b.crdt.* path (coverage gate).
  check("b.crdt.gCounter is a factory",    typeof b.crdt.gCounter === "function" && typeof b.crdt.gCounter.fromState === "function");
  check("b.crdt.pnCounter is a factory",   typeof b.crdt.pnCounter === "function" && typeof b.crdt.pnCounter.fromState === "function");
  check("b.crdt.gSet is a factory",        typeof b.crdt.gSet === "function" && typeof b.crdt.gSet.fromState === "function");
  check("b.crdt.twoPSet is a factory",     typeof b.crdt.twoPSet === "function" && typeof b.crdt.twoPSet.fromState === "function");
  check("b.crdt.orSet is a factory",       typeof b.crdt.orSet === "function" && typeof b.crdt.orSet.fromState === "function");
  check("b.crdt.lwwRegister is a factory", typeof b.crdt.lwwRegister === "function" && typeof b.crdt.lwwRegister.fromState === "function");
  check("b.crdt.orMap is a factory",       typeof b.crdt.orMap === "function" && typeof b.crdt.orMap.fromState === "function");
  check("b.crdt.CrdtError is a class",     typeof b.crdt.CrdtError === "function");
}

function testGCounter() {
  var a = crdt.gCounter({ replicaId: "a" }).inc(3);
  var c = crdt.gCounter({ replicaId: "c" }).inc(5);
  var d = crdt.gCounter({ replicaId: "d" }).inc(1);
  check("gCounter sum across replicas", a.merge(c).value() === 8);
  laws("gCounter", a, c, d);
  check("gCounter inc default is 1", crdt.gCounter({ replicaId: "a" }).inc().value() === 1);
  check("gCounter rejects negative inc", code(function () { crdt.gCounter().inc(-1); }) === "crdt/bad-value");
}

function testPNCounter() {
  var a = crdt.pnCounter({ replicaId: "a" }).inc(5).dec(2);
  var c = crdt.pnCounter({ replicaId: "c" }).inc(1);
  var d = crdt.pnCounter({ replicaId: "d" }).dec(3);
  check("pnCounter value", a.value() === 3);
  check("pnCounter merged value", a.merge(c).merge(d).value() === 1);
  laws("pnCounter", a, c, d);
}

function testGSet() {
  var a = crdt.gSet({ replicaId: "a" }).add("x").add("y");
  var c = crdt.gSet({ replicaId: "c" }).add("z");
  var d = crdt.gSet({ replicaId: "d" }).add("x");
  check("gSet union", val(a.merge(c)) === JSON.stringify(["x", "y", "z"]));
  check("gSet has", a.has("x") && !a.has("q"));
  check("gSet supports structured elements", crdt.gSet().add({ k: 1 }).has({ k: 1 }));
  laws("gSet", a, c, d);
  // value() order must converge for structured elements regardless of merge
  // order (sorted by the encoded key, not the decoded value).
  var s1 = crdt.gSet().add({ id: 2 }).add({ id: 1 });
  var s2 = crdt.gSet().add({ id: 3 });
  check("gSet structured-element value order converges", JSON.stringify(s1.merge(s2).value()) === JSON.stringify(s2.merge(s1).value()));
}

function testTwoPSet() {
  var s = crdt.twoPSet().add("a").add("b").remove("a");
  check("twoPSet remove", val(s) === JSON.stringify(["b"]));
  check("twoPSet remove-wins (no re-add)", !s.add("a").has("a"));
  var a = crdt.twoPSet({ replicaId: "a" }).add("x").remove("x");
  var c = crdt.twoPSet({ replicaId: "c" }).add("y");
  var d = crdt.twoPSet({ replicaId: "d" }).add("z");
  laws("twoPSet", a, c, d);
}

function testORSet() {
  // Concurrent re-add survives a remove that did not observe it.
  var a = crdt.orSet({ replicaId: "a" }).add("x").add("y");
  var c = crdt.orSet.fromState(a.state(), { replicaId: "c" });
  a.remove("x");
  c.add("x");
  check("orSet concurrent re-add survives remove", a.merge(c).value().indexOf("x") !== -1);
  // A remove that observed the add wins.
  var s = crdt.orSet().add("z");
  check("orSet observed remove drops element", s.remove("z").value().indexOf("z") === -1);
  laws("orSet", crdt.orSet({ replicaId: "a" }).add("p"), crdt.orSet({ replicaId: "c" }).add("q"), crdt.orSet({ replicaId: "d" }).add("r"));
  // tombstoneRetention cap is accepted and bounds the tombstone set.
  var capped = crdt.orSet({ replicaId: "a", tombstoneRetention: 2 });
  capped.add("1").add("2").add("3").remove("1").remove("2").remove("3");
  check("orSet tombstoneRetention bounds the set", capped.state().tombstones.length <= 2);
  check("orSet rejects bad tombstoneRetention", code(function () { crdt.orSet({ tombstoneRetention: -1 }); }) === "crdt/bad-value");
}

function testLWWRegister() {
  var a = crdt.lwwRegister({ replicaId: "a" }).set("first", 1);
  var c = crdt.lwwRegister({ replicaId: "c" }).set("second", 2);
  check("lwwRegister higher ts wins", a.merge(c).value() === "second");
  // Tie-break by replicaId (deterministic).
  var r1 = crdt.lwwRegister({ replicaId: "a" }).set("a", 100);
  var r2 = crdt.lwwRegister({ replicaId: "c" }).set("c", 100);
  check("lwwRegister tie-break by replicaId", r1.merge(r2).value() === "c" && r2.merge(r1).value() === "c");
  laws("lwwRegister",
    crdt.lwwRegister({ replicaId: "a" }).set("x", 5),
    crdt.lwwRegister({ replicaId: "c" }).set("y", 9),
    crdt.lwwRegister({ replicaId: "d" }).set("z", 3));
}

function testORMap() {
  var a = crdt.orMap({ replicaId: "a" }).set("k1", "v1", 10);
  var c = crdt.orMap({ replicaId: "c" }).set("k1", "v2", 20).set("k2", "x", 5);
  var merged = a.merge(c);
  check("orMap concurrent key write resolves LWW", merged.get("k1") === "v2");
  check("orMap disjoint keys both present", merged.has("k2") && val(merged) === JSON.stringify({ k1: "v2", k2: "x" }));
  check("orMap commutative", val(a.merge(c)) === val(c.merge(a)));
  // Remove a key, then converge.
  var p = crdt.orMap.fromState(merged.state(), { replicaId: "a" }).remove("k2");
  check("orMap remove converges", val(p.merge(merged)) === JSON.stringify({ k1: "v2" }));
  check("orMap rejects non-string key", code(function () { crdt.orMap().set(5, "v"); }) === "crdt/bad-key");
  // Removing a key clears its register, so a re-add starts clean — a later set
  // with a lower timestamp than the pre-remove value still wins on this replica.
  var rr = crdt.orMap({ replicaId: "a" }).set("k", "old", 100);
  rr.remove("k");
  rr.set("k", "new", 50);   // lower ts than the removed "old"@100
  check("orMap remove clears register so re-add wins", rr.get("k") === "new");
  check("orMap re-add appears in value", JSON.stringify(rr.value()) === JSON.stringify({ k: "new" }));
}

function testStateRoundTrip() {
  ["gCounter", "pnCounter", "gSet", "twoPSet", "orSet", "lwwRegister", "orMap"].forEach(function (t) {
    var inst = crdt[t]({ replicaId: "a" });
    var s = inst.state();
    check(t + ": fromState round-trips", JSON.stringify(crdt[t].fromState(s, { replicaId: "a" }).state()) === JSON.stringify(s));
    check(t + ": fromState rejects a mismatched type", code(function () { crdt[t].fromState({ type: "WRONG" }); }) === "crdt/type-mismatch");
  });
}

async function run() {
  testSurface();
  testGCounter();
  testPNCounter();
  testGSet();
  testTwoPSet();
  testORSet();
  testLWWRegister();
  testORMap();
  testStateRoundTrip();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[crdt] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }

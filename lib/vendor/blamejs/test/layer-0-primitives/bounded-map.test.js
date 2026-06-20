"use strict";
/**
 * bounded-map — entry-count-capped Map facade.
 *
 * Run standalone: `node test/layer-0-primitives/bounded-map.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var check   = helpers.check;
var { boundedMap, BoundedMapError } = require("../../lib/bounded-map");

function testEvictOldest() {
  var evicted = [];
  var m = boundedMap({ maxEntries: 3, onEvict: function (k, v) { evicted.push(k + "=" + v); } });
  m.set("a", 1); m.set("b", 2); m.set("c", 3);
  check("evict-oldest: at capacity, all present", m.size === 3 && m.has("a") && m.has("c"));
  m.set("d", 4);
  check("evict-oldest: size stays at cap",        m.size === 3);
  check("evict-oldest: oldest (a) evicted",       !m.has("a") && m.has("d"));
  m.set("e", 5);
  check("evict-oldest: next oldest (b) evicted",  !m.has("b") && m.has("e"));
  check("evict-oldest: onEvict fired for a,b",    evicted.join(",") === "a=1,b=2");
}

function testUpdateDoesNotGrowOrEvict() {
  var evicted = [];
  var m = boundedMap({ maxEntries: 2, onEvict: function (k) { evicted.push(k); } });
  m.set("x", 1); m.set("y", 1);
  var r = m.set("x", 99);   // update existing — must not evict y
  check("update returns true",            r === true);
  check("update keeps size at 2",         m.size === 2);
  check("update did not evict",            m.has("y") && evicted.length === 0);
  check("update changed the value",        m.get("x") === 99);
}

function testRejectPolicy() {
  var m = boundedMap({ maxEntries: 2, policy: "reject" });
  check("reject: first two stored",       m.set("a", 1) === true && m.set("b", 1) === true);
  check("reject: third refused",          m.set("c", 1) === false);
  check("reject: new key NOT stored",     !m.has("c") && m.size === 2);
  check("reject: live entries untouched", m.has("a") && m.has("b"));
  // Updating an existing key is still allowed at capacity (no growth).
  check("reject: update existing allowed", m.set("a", 2) === true && m.get("a") === 2);
}

function testMapFacade() {
  var m = boundedMap({ maxEntries: 10 });
  m.set("k1", "v1"); m.set("k2", "v2");
  check("get",    m.get("k1") === "v1");
  check("has",    m.has("k2") && !m.has("nope"));
  check("delete", m.delete("k1") === true && !m.has("k1") && m.size === 1);
  var iter = [];
  for (var e of m) iter.push(e[0] + "=" + e[1]);
  check("iterable yields entries", iter.join(",") === "k2=v2");
  var keys = []; var it = m.keys(); var n; while (!(n = it.next()).done) keys.push(n.value);
  check("keys()", keys.join(",") === "k2");
  var fe = []; m.forEach(function (v, k) { fe.push(k + "=" + v); });
  check("forEach", fe.join(",") === "k2=v2");
  m.clear();
  check("clear", m.size === 0);
}

function testValidation() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("maxEntries 0 → throws",     threw(function () { boundedMap({ maxEntries: 0 }); }) instanceof BoundedMapError);
  check("maxEntries -1 → throws",    threw(function () { boundedMap({ maxEntries: -1 }); }));
  check("maxEntries 1.5 → throws",   threw(function () { boundedMap({ maxEntries: 1.5 }); }));
  check("maxEntries missing → throws", threw(function () { boundedMap({}); }));
  var e = threw(function () { boundedMap({ maxEntries: 5, policy: "nope" }); });
  check("bad policy → throws bad-policy", e && e.code === "bounded-map/bad-policy");
}

var getOrInsert = require("../../lib/bounded-map").getOrInsert;
function _threw(fn) { try { fn(); return null; } catch (e) { return e; } }

function testGetOrInsert() {
  // get-or-insert: factory runs once, second call returns the cached value.
  var m = new Map();
  var calls = 0;
  var v1 = getOrInsert(m, "a", function () { calls++; return [1]; });
  var v2 = getOrInsert(m, "a", function () { calls++; return [2]; });
  check("getOrInsert: returns cached value on 2nd call", v1 === v2);
  check("getOrInsert: factory ran exactly once",         calls === 1);
  check("getOrInsert: stored the value",                 m.get("a") === v1);

  // cap path — at maxSize with an absent key, do NOT store; fire onFull.
  var capped = new Map(); capped.set("x", 1); capped.set("y", 2);
  var full = false;
  var r = getOrInsert(capped, "z", function () { return 9; },
    { maxSize: 2, onFull: function () { full = true; return "DROPPED"; } });
  check("getOrInsert cap: absent key not stored at cap", !capped.has("z"));
  check("getOrInsert cap: onFull fired",                 full === true);
  check("getOrInsert cap: returns onFull result",        r === "DROPPED");
  check("getOrInsert cap: existing key still returned",
    getOrInsert(capped, "x", function () { return 99; }, { maxSize: 2 }) === 1);
  // cap with no onFull → undefined.
  check("getOrInsert cap: no onFull → undefined",
    getOrInsert(capped, "w", function () { return 1; }, { maxSize: 2 }) === undefined);

  // validation — every input checked, throws typed BoundedMapError.
  check("getOrInsert: non-Map map throws bad-map",
    (_threw(function () { getOrInsert({}, "k", function () { return 1; }); }) || {}).code === "bounded-map/bad-map");
  check("getOrInsert: non-function factory throws bad-factory",
    (_threw(function () { getOrInsert(new Map(), "k", 42); }) || {}).code === "bounded-map/bad-factory");
  ["__NaN__", "__Infinity__", -1, 0, 1.5, "5"].forEach(function (bad) {
    var v = bad === "__NaN__" ? NaN : (bad === "__Infinity__" ? Infinity : bad);
    check("getOrInsert: maxSize " + String(bad) + " throws bad-max-size",
      (_threw(function () { getOrInsert(new Map(), "k", function () { return 1; }, { maxSize: v }); }) || {}).code
        === "bounded-map/bad-max-size");
  });
  check("getOrInsert: non-function onFull throws bad-on-full",
    (_threw(function () { getOrInsert(new Map(), "k", function () { return 1; }, { maxSize: 1, onFull: 7 }); }) || {}).code
      === "bounded-map/bad-on-full");
}

var requireAbsent  = require("../../lib/bounded-map").requireAbsent;
var requirePresent = require("../../lib/bounded-map").requirePresent;

function testRequireAbsent() {
  // uniqueness guard: absent key → returns undefined, onConflict NOT called.
  var m = new Map();
  var conflicts = 0;
  var r = requireAbsent(m, "k", function () { conflicts++; });
  check("requireAbsent: absent → undefined",        r === undefined);
  check("requireAbsent: absent → onConflict silent", conflicts === 0);
  // present key → onConflict(key, existing) called, its result returned.
  m.set("k", 42);
  var seen = null;
  var r2 = requireAbsent(m, "k", function (key, existing) { seen = key + "=" + existing; return "DUP"; });
  check("requireAbsent: present → onConflict fired", seen === "k=42");
  check("requireAbsent: present → returns onConflict result", r2 === "DUP");
  // the canonical caller throws a typed error from onConflict.
  check("requireAbsent: onConflict can throw",
    (_threw(function () {
      requireAbsent(m, "k", function () { throw new BoundedMapError("x/dup", "duplicate"); });
    }) || {}).code === "x/dup");
  // validation
  check("requireAbsent: non-Map throws bad-map",
    (_threw(function () { requireAbsent({}, "k", function () {}); }) || {}).code === "bounded-map/bad-map");
  check("requireAbsent: non-function onConflict throws bad-on-conflict",
    (_threw(function () { requireAbsent(new Map(), "k", 7); }) || {}).code === "bounded-map/bad-on-conflict");
}

function testRequirePresent() {
  // existence guard: present key → returns the existing value, onMissing NOT called.
  var m = new Map(); m.set("k", 99);
  var missing = 0;
  var v = requirePresent(m, "k", function () { missing++; });
  check("requirePresent: present → returns value", v === 99);
  check("requirePresent: present → onMissing silent", missing === 0);
  // absent key → onMissing(key) called, its result returned.
  var seen = null;
  var r = requirePresent(m, "nope", function (key) { seen = key; return "MISS"; });
  check("requirePresent: absent → onMissing fired", seen === "nope");
  check("requirePresent: absent → returns onMissing result", r === "MISS");
  check("requirePresent: onMissing can throw",
    (_threw(function () {
      requirePresent(m, "nope", function () { throw new BoundedMapError("x/nf", "not found"); });
    }) || {}).code === "x/nf");
  // validation
  check("requirePresent: non-Map throws bad-map",
    (_threw(function () { requirePresent({}, "k", function () {}); }) || {}).code === "bounded-map/bad-map");
  check("requirePresent: non-function onMissing throws bad-on-missing",
    (_threw(function () { requirePresent(new Map(), "k", 7); }) || {}).code === "bounded-map/bad-on-missing");
}

var requireAbsentMember = require("../../lib/bounded-map").requireAbsentMember;

function testRequireAbsentMember() {
  // Set-uniqueness guard: absent member → undefined, onConflict NOT called.
  var s = new Set();
  var conflicts = 0;
  var r = requireAbsentMember(s, "k", function () { conflicts++; });
  check("requireAbsentMember: absent → undefined",        r === undefined);
  check("requireAbsentMember: absent → onConflict silent", conflicts === 0);
  // present member → onConflict(key) called, its result returned.
  s.add("k");
  var seen = null;
  var r2 = requireAbsentMember(s, "k", function (key) { seen = key; return "DUP"; });
  check("requireAbsentMember: present → onConflict fired", seen === "k");
  check("requireAbsentMember: present → returns onConflict result", r2 === "DUP");
  // the canonical caller throws a typed duplicate/cycle error.
  check("requireAbsentMember: onConflict can throw",
    (_threw(function () {
      requireAbsentMember(s, "k", function () { throw new BoundedMapError("x/dup", "duplicate"); });
    }) || {}).code === "x/dup");
  // works on any { has } view, including object identity in a Set.
  var nodeA = {}, visited = new Set([nodeA]);
  check("requireAbsentMember: object-identity membership (cycle use)",
    requireAbsentMember(visited, nodeA, function () { return "CYCLE"; }) === "CYCLE");
  // validation
  check("requireAbsentMember: non-Set throws bad-set",
    (_threw(function () { requireAbsentMember({}, "k", function () {}); }) || {}).code === "bounded-map/bad-set");
  check("requireAbsentMember: non-function onConflict throws bad-on-conflict",
    (_threw(function () { requireAbsentMember(new Set(), "k", 7); }) || {}).code === "bounded-map/bad-on-conflict");
}

function run() {
  testEvictOldest();
  testUpdateDoesNotGrowOrEvict();
  testRejectPolicy();
  testMapFacade();
  testValidation();
  testGetOrInsert();
  testRequireAbsent();
  testRequirePresent();
  testRequireAbsentMember();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[bounded-map] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}

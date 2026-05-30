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

function run() {
  testEvictOldest();
  testUpdateDoesNotGrowOrEvict();
  testRejectPolicy();
  testMapFacade();
  testValidation();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[bounded-map] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}

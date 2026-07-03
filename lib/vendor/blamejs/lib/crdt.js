// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.crdt
 * @nav    Data
 * @title  CRDTs
 *
 * @intro
 *   Conflict-free Replicated Data Types — data structures that several
 *   replicas can update independently, with no coordination, and still
 *   converge to the same value once they have all seen each other's state.
 *   These are the state-based CvRDTs: each type's <code>merge</code> is a
 *   join over a semilattice, so it is commutative, associative, and
 *   idempotent — replicas can merge in any order, any number of times, and
 *   land on the same result. That makes them the substrate for eventually-
 *   consistent state across an active/active cluster, offline-first clients
 *   that reconcile on reconnect, or any "last writer need not win, but
 *   everyone agrees" counter / set / register / map.
 *
 *   Every type exposes the same contract: local mutators (e.g.
 *   <code>inc</code>, <code>add</code>, <code>set</code>),
 *   <code>merge(other)</code> which returns a new converged instance without
 *   mutating either operand, <code>value()</code> for the materialized value,
 *   and <code>state()</code> / <code>fromState()</code> for a JSON-
 *   serializable form to snapshot (via <code>b.archive</code> /
 *   <code>b.backup</code>) or ship to a peer. Each replica carries a
 *   <code>replicaId</code> so per-replica contributions stay distinct.
 *
 *   This release covers the state-based family — grow-only and PN counters,
 *   grow-only / two-phase / observed-remove sets, a last-write-wins register,
 *   and an observed-remove map. Operation-based sequence CRDTs (RGA), delta-
 *   state mutators, and a live event-bus replicator are not included; the
 *   state-based types merge correctly without a causal channel, which is the
 *   whole point.
 *
 * @card
 *   Conflict-free Replicated Data Types (`b.crdt`) — state-based CvRDT
 *   counters, sets, a last-write-wins register, and an observed-remove map
 *   whose `merge` is commutative, associative, and idempotent, so replicas
 *   converge with no coordination.
 */

var bCrypto = require("./crypto");
var safeJson = require("./safe-json");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");

var CrdtError = defineClass("CrdtError", { alwaysPermanent: true });

function _replicaId(opts) {
  var id = opts && opts.replicaId;
  if (id == null) return bCrypto.generateToken(8);   // random replica-id token length
  if (typeof id !== "string" || id.length === 0) throw new CrdtError("crdt/bad-replica-id", "crdt: replicaId must be a non-empty string");
  return id;
}
function _posInt(n, label) {
  if (!numericBounds.isNonNegativeFiniteInt(n)) throw new CrdtError("crdt/bad-value", "crdt: " + label + " must be a non-negative integer");
  return n;
}
function _maxMerge(a, b) {
  var out = {};
  var k;
  for (k in a) if (Object.prototype.hasOwnProperty.call(a, k)) out[k] = a[k];
  for (k in b) if (Object.prototype.hasOwnProperty.call(b, k)) out[k] = (out[k] === undefined || b[k] > out[k]) ? b[k] : out[k];
  return out;
}

/**
 * @primitive  b.crdt.gCounter
 * @signature  b.crdt.gCounter(opts?)
 * @since      0.13.4
 * @status     stable
 * @compliance soc2
 * @related    b.crdt.pnCounter, b.crdt.gSet
 *
 * A grow-only counter: each replica tracks its own increment-only tally, and
 * the value is their sum. <code>merge</code> takes the per-replica maximum, so
 * it converges no matter the order. Increments only — use
 * <code>pnCounter</code> when you also need to decrement.
 *
 * @opts
 *   replicaId: string,   // this replica's id (default: random)
 *
 * @example
 *   var a = b.crdt.gCounter({ replicaId: "a" }).inc(3);
 *   var c = b.crdt.gCounter({ replicaId: "c" }).inc(5);
 *   a.merge(c).value();   // → 8
 */
function gCounter(opts) {
  opts = opts || {};
  var replicaId = _replicaId(opts);
  var counts = {};
  if (opts._counts) { for (var k in opts._counts) if (Object.prototype.hasOwnProperty.call(opts._counts, k)) counts[k] = opts._counts[k]; }

  return {
    type: "gCounter",
    replicaId: replicaId,
    inc: function (n) { n = n == null ? 1 : _posInt(n, "inc"); counts[replicaId] = (counts[replicaId] || 0) + n; return this; },
    value: function () { var s = 0; for (var k in counts) if (Object.prototype.hasOwnProperty.call(counts, k)) s += counts[k]; return s; },
    state: function () { return { type: "gCounter", counts: Object.assign({}, counts) }; },
    merge: function (other) { return gCounter({ replicaId: replicaId, _counts: _maxMerge(counts, _otherState(other, "gCounter").counts) }); },
  };
}
gCounter.fromState = function (s, opts) { _assertState(s, "gCounter"); return gCounter(Object.assign({}, opts, { _counts: s.counts })); };

/**
 * @primitive  b.crdt.pnCounter
 * @signature  b.crdt.pnCounter(opts?)
 * @since      0.13.4
 * @status     stable
 * @compliance soc2
 * @related    b.crdt.gCounter, b.crdt.lwwRegister
 *
 * A positive-negative counter: two grow-only counters (increments and
 * decrements) whose difference is the value, so it supports both
 * <code>inc</code> and <code>dec</code> and still converges.
 *
 * @opts
 *   replicaId: string,   // this replica's id (default: random)
 *
 * @example
 *   var a = b.crdt.pnCounter({ replicaId: "a" }).inc(5).dec(2);
 *   var c = b.crdt.pnCounter({ replicaId: "c" }).inc(1);
 *   a.merge(c).value();   // → 4
 */
function pnCounter(opts) {
  opts = opts || {};
  var replicaId = _replicaId(opts);
  var p = gCounter({ replicaId: replicaId, _counts: opts._p });
  var n = gCounter({ replicaId: replicaId, _counts: opts._n });

  return {
    type: "pnCounter",
    replicaId: replicaId,
    inc: function (by) { p.inc(by); return this; },
    dec: function (by) { n.inc(by); return this; },
    value: function () { return p.value() - n.value(); },
    state: function () { return { type: "pnCounter", p: p.state().counts, n: n.state().counts }; },
    merge: function (other) {
      var o = _otherState(other, "pnCounter");
      return pnCounter({ replicaId: replicaId, _p: _maxMerge(p.state().counts, o.p), _n: _maxMerge(n.state().counts, o.n) });
    },
  };
}
pnCounter.fromState = function (s, opts) { _assertState(s, "pnCounter"); return pnCounter(Object.assign({}, opts, { _p: s.p, _n: s.n })); };

/**
 * @primitive  b.crdt.gSet
 * @signature  b.crdt.gSet(opts?)
 * @since      0.13.4
 * @status     stable
 * @compliance soc2
 * @related    b.crdt.twoPSet, b.crdt.orSet
 *
 * A grow-only set: elements can be added but never removed; <code>merge</code>
 * is set union. The simplest convergent set — reach for <code>orSet</code>
 * when removal is needed. Elements may be strings or JSON-serializable values.
 *
 * @opts
 *   replicaId: string,   // this replica's id (default: random)
 *
 * @example
 *   var a = b.crdt.gSet().add("x");
 *   var c = b.crdt.gSet().add("y");
 *   a.merge(c).value();   // → ["x", "y"]
 */
function gSet(opts) {
  opts = opts || {};
  var replicaId = _replicaId(opts);
  var els = new Set(opts._els || []);

  return {
    type: "gSet",
    replicaId: replicaId,
    add: function (x) { els.add(_key(x)); return this; },
    has: function (x) { return els.has(_key(x)); },
    value: function () { return _decodeKeys(els); },
    state: function () { return { type: "gSet", els: Array.from(els) }; },
    merge: function (other) { var o = _otherState(other, "gSet"); var u = new Set(els); o.els.forEach(function (e) { u.add(e); }); return gSet({ replicaId: replicaId, _els: u }); },
  };
}
gSet.fromState = function (s, opts) { _assertState(s, "gSet"); return gSet(Object.assign({}, opts, { _els: s.els })); };

/**
 * @primitive  b.crdt.twoPSet
 * @signature  b.crdt.twoPSet(opts?)
 * @since      0.13.4
 * @status     stable
 * @compliance soc2
 * @related    b.crdt.gSet, b.crdt.orSet
 *
 * A two-phase set: an add-set and a remove-set (tombstones). An element can be
 * added and removed, but once removed it can never be re-added — remove wins
 * permanently. When re-adding must work, use <code>orSet</code>.
 *
 * @opts
 *   replicaId: string,   // this replica's id (default: random)
 *
 * @example
 *   var s = b.crdt.twoPSet().add("a").add("b").remove("a");
 *   s.value();   // → ["b"]
 */
function twoPSet(opts) {
  opts = opts || {};
  var replicaId = _replicaId(opts);
  var adds = new Set(opts._adds || []);
  var removes = new Set(opts._removes || []);

  return {
    type: "twoPSet",
    replicaId: replicaId,
    add: function (x) { adds.add(_key(x)); return this; },
    remove: function (x) { var k = _key(x); if (adds.has(k)) removes.add(k); return this; },
    has: function (x) { var k = _key(x); return adds.has(k) && !removes.has(k); },
    value: function () { var live = new Set(); adds.forEach(function (k) { if (!removes.has(k)) live.add(k); }); return _decodeKeys(live); },
    state: function () { return { type: "twoPSet", adds: Array.from(adds), removes: Array.from(removes) }; },
    merge: function (other) {
      var o = _otherState(other, "twoPSet");
      var a = new Set(adds), r = new Set(removes);
      o.adds.forEach(function (e) { a.add(e); });
      o.removes.forEach(function (e) { r.add(e); });
      return twoPSet({ replicaId: replicaId, _adds: a, _removes: r });
    },
  };
}
twoPSet.fromState = function (s, opts) { _assertState(s, "twoPSet"); return twoPSet(Object.assign({}, opts, { _adds: s.adds, _removes: s.removes })); };

/**
 * @primitive  b.crdt.orSet
 * @signature  b.crdt.orSet(opts?)
 * @since      0.13.4
 * @status     stable
 * @compliance soc2
 * @related    b.crdt.gSet, b.crdt.twoPSet, b.crdt.orMap
 *
 * An observed-remove set: each add stamps a unique tag, and remove tombstones
 * the tags it has observed for that element, so an element survives if any
 * concurrent add was not seen by the remove — re-adding works, and a
 * concurrent add-vs-remove resolves add-wins. <code>tombstoneRetention</code>
 * optionally caps the tombstone set to bound memory against a remove flood; it
 * drops the oldest tombstones, which can resurrect a concurrently-removed
 * element, so leave it unset unless that trade-off is acceptable.
 *
 * Each add stamps a unique tag; remove tombstones the tags currently observed
 * for that element. An element is present if it has a live (un-tombstoned) tag.
 *
 * @opts
 *   replicaId:          string,   // this replica's id (default: random)
 *   tombstoneRetention: number,   // optional cap on retained tombstones (default: unbounded)
 *
 * @example
 *   var a = b.crdt.orSet().add("x");
 *   var c = b.crdt.orSet.fromState(a.state()).add("x");  // re-add elsewhere
 *   a.remove("x");
 *   a.merge(c).value();   // → ["x"]  (concurrent re-add survives)
 */
function orSet(opts) {
  opts = opts || {};
  var replicaId = _replicaId(opts);
  var tombstoneRetention = opts.tombstoneRetention;
  if (tombstoneRetention != null) _posInt(tombstoneRetention, "tombstoneRetention");
  // elems: key -> array of tags ; tombstones: Set of removed tags
  var elems = {};
  if (opts._elems) { for (var k in opts._elems) if (Object.prototype.hasOwnProperty.call(opts._elems, k)) elems[k] = opts._elems[k].slice(); }
  var tombstones = new Set(opts._tombstones || []);
  var seq = 0;

  function _tag() { return replicaId + ":" + (++seq) + ":" + bCrypto.generateToken(4); }
  function _liveTags(key) { return (elems[key] || []).filter(function (t) { return !tombstones.has(t); }); }
  function _gcTombstones() {
    if (tombstoneRetention == null || tombstones.size <= tombstoneRetention) return;
    // Bounded-memory tradeoff (opt-in): drop oldest tombstones. Documented to
    // possibly resurrect a concurrently-removed element — full causal GC ships
    // with the replicator slice.
    var arr = Array.from(tombstones);
    tombstones = new Set(arr.slice(arr.length - tombstoneRetention));
  }

  return {
    type: "orSet",
    replicaId: replicaId,
    add: function (x) { var key = _key(x); (elems[key] = elems[key] || []).push(_tag()); return this; },
    remove: function (x) { var key = _key(x); _liveTags(key).forEach(function (t) { tombstones.add(t); }); _gcTombstones(); return this; },
    has: function (x) { return _liveTags(_key(x)).length > 0; },
    value: function () { var live = []; for (var key in elems) if (Object.prototype.hasOwnProperty.call(elems, key) && _liveTags(key).length > 0) live.push(key); return _decodeKeys(new Set(live)); },
    state: function () { var e = {}; for (var key in elems) if (Object.prototype.hasOwnProperty.call(elems, key)) e[key] = elems[key].slice(); return { type: "orSet", elems: e, tombstones: Array.from(tombstones) }; },
    merge: function (other) {
      var o = _otherState(other, "orSet");
      var e = {};
      var key;
      for (key in elems) if (Object.prototype.hasOwnProperty.call(elems, key)) e[key] = elems[key].slice();
      for (key in o.elems) if (Object.prototype.hasOwnProperty.call(o.elems, key)) {
        var merged = (e[key] || []).concat(o.elems[key]);
        e[key] = Array.from(new Set(merged));   // union of tags, dedup
      }
      var ts = new Set(tombstones);
      o.tombstones.forEach(function (t) { ts.add(t); });
      return orSet({ replicaId: replicaId, tombstoneRetention: tombstoneRetention, _elems: e, _tombstones: ts });
    },
  };
}
orSet.fromState = function (s, opts) { _assertState(s, "orSet"); return orSet(Object.assign({}, opts, { _elems: s.elems, _tombstones: s.tombstones })); };

/**
 * @primitive  b.crdt.lwwRegister
 * @signature  b.crdt.lwwRegister(opts?)
 * @since      0.13.4
 * @status     stable
 * @compliance soc2
 * @related    b.crdt.pnCounter, b.crdt.orMap
 *
 * A last-write-wins register: holds a single value with a timestamp;
 * <code>merge</code> keeps the higher-timestamped write, breaking ties by the
 * higher <code>replicaId</code> so the outcome is deterministic. Pass an
 * explicit timestamp to <code>set</code> for a logical clock, or omit it to
 * use wall-clock milliseconds.
 *
 * @opts
 *   replicaId: string,   // this replica's id (default: random)
 *
 * @example
 *   var a = b.crdt.lwwRegister({ replicaId: "a" }).set("first", 1);
 *   var c = b.crdt.lwwRegister({ replicaId: "c" }).set("second", 2);
 *   a.merge(c).value();   // → "second"
 */
function lwwRegister(opts) {
  opts = opts || {};
  var replicaId = _replicaId(opts);
  var current = opts._current || { value: null, ts: -1, replicaId: "" };

  function _beats(a, b) { return a.ts > b.ts || (a.ts === b.ts && a.replicaId > b.replicaId); }
  return {
    type: "lwwRegister",
    replicaId: replicaId,
    set: function (v, ts) { ts = ts == null ? Date.now() : _posInt(ts, "ts"); var cand = { value: v, ts: ts, replicaId: replicaId }; if (_beats(cand, current)) current = cand; return this; },
    value: function () { return current.value; },
    timestamp: function () { return current.ts; },
    state: function () { return { type: "lwwRegister", current: { value: current.value, ts: current.ts, replicaId: current.replicaId } }; },
    merge: function (other) { var o = _otherState(other, "lwwRegister"); var win = _beats(o.current, current) ? o.current : current; return lwwRegister({ replicaId: replicaId, _current: { value: win.value, ts: win.ts, replicaId: win.replicaId } }); },
  };
}
lwwRegister.fromState = function (s, opts) { _assertState(s, "lwwRegister"); return lwwRegister(Object.assign({}, opts, { _current: s.current })); };

/**
 * @primitive  b.crdt.orMap
 * @signature  b.crdt.orMap(opts?)
 * @since      0.13.4
 * @status     stable
 * @compliance soc2
 * @related    b.crdt.orSet, b.crdt.lwwRegister
 *
 * An observed-remove map: key presence follows observed-remove-set semantics
 * (a key can be set, removed, and set again), and each key's value is a
 * last-write-wins register, so concurrent writes to a live key converge by
 * timestamp (higher wins, ties by replicaId). Removing a key clears its value
 * register locally, so a re-add on the same replica starts clean; across
 * replicas the value is strictly last-write-wins by timestamp — supply
 * monotonic timestamps (the default wall-clock does) for re-add to win. Keys
 * are non-empty strings.
 *
 * Keys follow OR-Set add/remove semantics; each key's value is an LWW register,
 * so concurrent writes to the same key converge by last-write-wins.
 *
 * @opts
 *   replicaId: string,   // this replica's id (default: random)
 *
 * @example
 *   var a = b.crdt.orMap({ replicaId: "a" }).set("k", "v1", 1);
 *   var c = b.crdt.orMap({ replicaId: "c" }).set("k", "v2", 2);
 *   a.merge(c).value();   // → { k: "v2" }
 */
function orMap(opts) {
  opts = opts || {};
  var replicaId = _replicaId(opts);
  var keys = orSet({ replicaId: replicaId, _elems: opts._keyElems, _tombstones: opts._keyTombstones });
  var vals = {};   // key -> lwwRegister state
  if (opts._vals) { for (var k in opts._vals) if (Object.prototype.hasOwnProperty.call(opts._vals, k)) vals[k] = opts._vals[k]; }

  function _reg(key) { return lwwRegister.fromState(vals[key] || { type: "lwwRegister", current: { value: null, ts: -1, replicaId: "" } }, { replicaId: replicaId }); }
  // Keys pass to the OR-Set raw (it encodes internally) and index `vals`
  // directly, so the materialized value is keyed by the plain string.
  return {
    type: "orMap",
    replicaId: replicaId,
    set: function (key, v, ts) { key = _mapKey(key); keys.add(key); vals[key] = _reg(key).set(v, ts).state(); return this; },
    // Removing a key clears its value register, so re-adding the key on this
    // replica starts from a clean last-write-wins state rather than reusing the
    // pre-remove value. (Across replicas the value still follows last-write-wins
    // by timestamp — a concurrent, un-removed higher-timestamped write wins;
    // making a re-add causally supersede needs vector clocks, which ship with
    // the replicator slice.)
    remove: function (key) { key = _mapKey(key); keys.remove(key); delete vals[key]; return this; },
    has: function (key) { return keys.has(_mapKey(key)); },
    get: function (key) { key = _mapKey(key); return keys.has(key) ? _reg(key).value() : undefined; },
    value: function () { var out = {}; keys.value().forEach(function (key) { out[key] = _reg(key).value(); }); return out; },
    state: function () { var ks = keys.state(); return { type: "orMap", keyElems: ks.elems, keyTombstones: ks.tombstones, vals: Object.assign({}, vals) }; },
    merge: function (other) {
      var o = _otherState(other, "orMap");
      var mergedKeys = keys.merge({ state: function () { return { type: "orSet", elems: o.keyElems, tombstones: o.keyTombstones }; } }).state();
      var v = {};
      var key;
      for (key in vals) if (Object.prototype.hasOwnProperty.call(vals, key)) v[key] = vals[key];
      for (key in o.vals) if (Object.prototype.hasOwnProperty.call(o.vals, key)) {
        if (!v[key]) { v[key] = o.vals[key]; }
        else {
          var merged = lwwRegister.fromState(v[key], { replicaId: replicaId }).merge({ state: function () { return o.vals[key]; } });
          v[key] = merged.state();
        }
      }
      return orMap({ replicaId: replicaId, _keyElems: mergedKeys.elems, _keyTombstones: mergedKeys.tombstones, _vals: v });
    },
  };
}
orMap.fromState = function (s, opts) { _assertState(s, "orMap"); return orMap(Object.assign({}, opts, { _keyElems: s.keyElems, _keyTombstones: s.keyTombstones, _vals: s.vals })); };

// ---- shared helpers --------------------------------------------------------

// Set/map elements are keyed by a reversible string so structured values work.
function _key(x) {
  if (typeof x === "string") return "s:" + x;
  return "j:" + JSON.stringify(x);
}
function _mapKey(k) {
  if (typeof k !== "string" || k.length === 0) throw new CrdtError("crdt/bad-key", "crdt.orMap: keys must be non-empty strings");
  return k;
}
function _decodeKeys(set) {
  // Sort by the encoded key (a deterministic, unique string for every element,
  // including structured ones) BEFORE decoding, so the materialized array order
  // is identical regardless of merge order — structured elements would all
  // collapse to "[object Object]" if sorted by their decoded value.
  return Array.from(set).sort().map(function (k) {
    return k.charAt(0) === "s" ? k.slice(2) : safeJson.parse(k.slice(2));
  });
}
function _otherState(other, expected) {
  var s = other && typeof other.state === "function" ? other.state() : other;
  _assertState(s, expected);
  return s;
}
function _assertState(s, expected) {
  if (!s || typeof s !== "object") throw new CrdtError("crdt/bad-state", "crdt: expected a " + expected + " state object");
  if (s.type !== expected) throw new CrdtError("crdt/type-mismatch", "crdt: expected a " + expected + " state, got '" + s.type + "'");
}

module.exports = {
  gCounter:    gCounter,
  pnCounter:   pnCounter,
  gSet:        gSet,
  twoPSet:     twoPSet,
  orSet:       orSet,
  lwwRegister: lwwRegister,
  orMap:       orMap,
  CrdtError:   CrdtError,
};

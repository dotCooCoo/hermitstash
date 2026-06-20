"use strict";
/**
 * @module b.worm
 * @nav    Compliance
 * @title  WORM Retention
 *
 * @intro
 *   Write-once-read-many records with retention-until immutability — the
 *   storage discipline regulators require for records that must not be
 *   altered or deleted before a retention period elapses (SEC 17a-4(f),
 *   CFTC 1.31, FINRA 4511, and the "immutable storage" controls in many
 *   sectoral postures). A WORM store enforces, on every mutating call, that
 *   a stored record cannot be overwritten or deleted while it is within its
 *   retention window or under a legal hold.
 *
 *   Two modes mirror the cloud Object-Lock model: in <code>compliance</code>
 *   mode (the default) a record cannot be deleted before its
 *   <code>retainUntil</code> time by anyone, including the operator; in
 *   <code>governance</code> mode a privileged caller may override with an
 *   explicit reason, which is audited. Retention can only be
 *   <em>extended</em>, never shortened. Every record carries a SHA3-512
 *   content digest, so <code>get</code> detects tampering of the underlying
 *   bytes. Every allow/refuse decision is audited.
 *
 *   Storage is pluggable: <code>create</code> takes a synchronous
 *   <code>store</code> adapter (<code>get</code> / <code>set</code> /
 *   <code>delete</code> / <code>has</code> / <code>keys</code>) so the WORM
 *   policy layer sits over an operator's durable backend (a sealed DB
 *   table, an S3 Object-Lock bucket, a filesystem); the default in-memory
 *   adapter is for tests and ephemeral use.
 *
 * @card
 *   Write-once-read-many retention (`b.worm.create`) — SEC 17a-4 / CFTC-style
 *   immutable records with compliance / governance Object-Lock modes,
 *   extend-only retention, legal holds, and a tamper-evident SHA3-512 digest
 *   over any pluggable store.
 */

var nodeCrypto = require("node:crypto");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var { timingSafeEqual } = require("./crypto");
var { defineClass } = require("./framework-error");
var audit = lazyRequire(function () { return require("./audit"); });

var WormError = defineClass("WormError", { alwaysPermanent: true });

var MODES = { compliance: 1, governance: 1 };

function _now(clock) { return typeof clock === "function" ? clock() : Date.now(); }
function _toBytes(data) {
  // Always return a fresh copy — the WORM record owns its bytes. If we kept
  // the caller's Buffer, a later mutation of their reference would silently
  // change stored bytes and break the digest, defeating immutability.
  if (Buffer.isBuffer(data)) return Buffer.from(data);
  if (data instanceof Uint8Array) return Buffer.from(data);
  if (typeof data === "string") return Buffer.from(data, "utf8");
  return Buffer.from(JSON.stringify(data), "utf8");   // structured value → canonical-ish JSON
}
function _digest(bytes) { return nodeCrypto.createHash("sha3-512").update(bytes).digest(); }

// Default in-memory store adapter (tests / ephemeral). Operators pass a
// durable adapter with the same five synchronous methods.
function _memStore() {
  var m = new Map();
  return {
    get: function (id) { return m.get(id); },
    set: function (id, rec) { m.set(id, rec); },
    delete: function (id) { m.delete(id); },
    has: function (id) { return m.has(id); },
    keys: function () { return Array.from(m.keys()); },
  };
}

/**
 * @primitive  b.worm.create
 * @signature  b.worm.create(opts?)
 * @since      0.13.0
 * @status     stable
 * @compliance sox-404, soc2
 * @related    b.retention.create, b.legalHold, b.retention.complianceFloor
 *
 * Create a WORM store that enforces write-once-read-many retention over a
 * backing store. The returned instance has <code>put</code>,
 * <code>get</code>, <code>delete</code>, <code>extendRetention</code>,
 * <code>placeLegalHold</code>, <code>releaseLegalHold</code>, and
 * <code>list</code>. Throws <code>WormError</code> on policy violations.
 *
 * @opts
 *   store:             object,   // adapter: get/set/delete/has/keys (default: in-memory)
 *   mode:              string,   // "compliance" (default) | "governance"
 *   defaultRetentionMs: number,  // applied when put() gives no retain time
 *   clock:             function, // () => epoch ms (default Date.now; for tests)
 *
 * @example
 *   var w = b.worm.create({ mode: "compliance" });
 *   w.put("invoice-42", pdfBytes, { retentionMs: b.C.TIME.days(2555) }); // 7y
 *   w.get("invoice-42").data;            // → pdfBytes (digest verified)
 *   w.delete("invoice-42");              // throws worm/retained until 2033
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["store", "mode", "defaultRetentionMs", "clock"], "worm.create");
  var mode = opts.mode || "compliance";
  if (!MODES[mode]) throw new WormError("worm/bad-mode", "worm.create: mode must be 'compliance' or 'governance'");
  var store = opts.store || _memStore();
  ["get", "set", "delete", "has", "keys"].forEach(function (m) {
    if (typeof store[m] !== "function") throw new WormError("worm/bad-store", "worm.create: store adapter must implement " + m + "()");
  });
  var clock = opts.clock;
  var defaultRetentionMs = opts.defaultRetentionMs;
  if (defaultRetentionMs != null && (typeof defaultRetentionMs !== "number" || !isFinite(defaultRetentionMs) || defaultRetentionMs < 0)) {
    throw new WormError("worm/bad-opt", "worm.create: defaultRetentionMs must be a non-negative finite number");
  }

  var _baseAudit = audit().namespaced("worm");
  function _emit(action, outcome, id, metadata) {
    _baseAudit(action, outcome, Object.assign({ id: id, mode: mode }, metadata || {}), { actor: { type: "system" } });
  }

  function _resolveRetainUntil(now, putOpts) {
    if (putOpts.retainUntil != null) {
      if (typeof putOpts.retainUntil !== "number" || !isFinite(putOpts.retainUntil)) throw new WormError("worm/bad-opt", "worm.put: retainUntil must be an epoch-ms number");
      return putOpts.retainUntil;
    }
    var ms = putOpts.retentionMs != null ? putOpts.retentionMs : defaultRetentionMs;
    if (ms == null) throw new WormError("worm/no-retention", "worm.put: a retention is required — pass retainUntil, retentionMs, or set defaultRetentionMs at create()");
    if (typeof ms !== "number" || !isFinite(ms) || ms < 0) throw new WormError("worm/bad-opt", "worm.put: retentionMs must be a non-negative finite number");
    return now + ms;
  }

  function put(id, data, putOpts) {
    putOpts = putOpts || {};
    if (typeof id !== "string" || id.length === 0) throw new WormError("worm/bad-id", "worm.put: id must be a non-empty string");
    var now = _now(clock);
    var existing = store.get(id);
    if (existing) {
      // Write-once: an existing record may not be overwritten while it is
      // still retained or held — that is the whole guarantee.
      if (existing.legalHolds.length > 0 || now < existing.retainUntil) {
        _emit("put-refused", "denied", id, { reason: "write-once" });
        throw new WormError("worm/already-exists", "worm.put: '" + id + "' exists and is still retained/held — WORM records are write-once");
      }
    }
    var bytes = _toBytes(data);
    var retainUntil = _resolveRetainUntil(now, putOpts);
    var holds = [];
    if (putOpts.legalHold != null) holds.push(String(putOpts.legalHold));
    var rec = {
      bytes: bytes,
      digest: _digest(bytes),
      createdAt: now,
      retainUntil: retainUntil,
      legalHolds: holds,
      mode: mode,
    };
    store.set(id, rec);
    _emit("put", "allowed", id, { retainUntil: retainUntil, bytes: bytes.length });
    return { id: id, digest: rec.digest.toString("hex"), createdAt: now, retainUntil: retainUntil };
  }

  function _require(id) {
    var rec = store.get(id);
    if (!rec) throw new WormError("worm/not-found", "worm: no record '" + id + "'");
    return rec;
  }

  function get(id) {
    var rec = _require(id);
    // Tamper-evidence: the stored digest must still match the stored bytes.
    if (!timingSafeEqual(rec.digest, _digest(rec.bytes))) {
      _emit("tamper-detected", "denied", id, {});
      throw new WormError("worm/tampered", "worm.get: stored bytes for '" + id + "' do not match their digest");
    }
    // Hand back a copy so a consumer cannot mutate the stored bytes through
    // the read API and corrupt the record behind the policy checks.
    return { id: id, data: Buffer.from(rec.bytes), digest: rec.digest.toString("hex"), createdAt: rec.createdAt, retainUntil: rec.retainUntil, legalHolds: rec.legalHolds.slice(), mode: rec.mode };
  }

  function del(id, delOpts) {
    delOpts = delOpts || {};
    var rec = _require(id);
    var now = _now(clock);
    if (rec.legalHolds.length > 0) {
      _emit("delete-refused", "denied", id, { reason: "legal-hold", holds: rec.legalHolds.length });
      throw new WormError("worm/legal-hold", "worm.delete: '" + id + "' is under " + rec.legalHolds.length + " legal hold(s)");
    }
    if (now < rec.retainUntil) {
      if (mode === "governance" && delOpts.override === true) {
        if (typeof delOpts.reason !== "string" || delOpts.reason.length === 0) throw new WormError("worm/override-reason", "worm.delete: a governance override requires a non-empty reason");
        store.delete(id);
        _emit("delete-override", "allowed", id, { retainUntil: rec.retainUntil, reason: delOpts.reason });
        return true;
      }
      _emit("delete-refused", "denied", id, { reason: "retained", retainUntil: rec.retainUntil });
      throw new WormError("worm/retained", "worm.delete: '" + id + "' is retained until " + new Date(rec.retainUntil).toISOString() + (mode === "compliance" ? " (compliance mode — no override)" : " (pass { override: true, reason } in governance mode)"));
    }
    store.delete(id);
    _emit("delete", "allowed", id, {});
    return true;
  }

  function extendRetention(id, newRetainUntil) {
    var rec = _require(id);
    if (typeof newRetainUntil !== "number" || !isFinite(newRetainUntil)) throw new WormError("worm/bad-opt", "worm.extendRetention: newRetainUntil must be an epoch-ms number");
    if (newRetainUntil < rec.retainUntil) {
      _emit("extend-refused", "denied", id, { current: rec.retainUntil, requested: newRetainUntil });
      throw new WormError("worm/retention-shorten", "worm.extendRetention: retention can only be extended, never shortened");
    }
    rec.retainUntil = newRetainUntil;
    store.set(id, rec);
    _emit("extend", "allowed", id, { retainUntil: newRetainUntil });
    return newRetainUntil;
  }

  function placeLegalHold(id, holdId) {
    var rec = _require(id);
    if (typeof holdId !== "string" || holdId.length === 0) throw new WormError("worm/bad-opt", "worm.placeLegalHold: holdId must be a non-empty string");
    if (rec.legalHolds.indexOf(holdId) === -1) { rec.legalHolds.push(holdId); store.set(id, rec); }
    _emit("legal-hold-placed", "allowed", id, { holdId: holdId });
    return rec.legalHolds.slice();
  }

  function releaseLegalHold(id, holdId) {
    var rec = _require(id);
    var i = rec.legalHolds.indexOf(String(holdId));
    if (i !== -1) { rec.legalHolds.splice(i, 1); store.set(id, rec); }
    _emit("legal-hold-released", "allowed", id, { holdId: holdId });
    return rec.legalHolds.slice();
  }

  function list() { return store.keys(); }

  return {
    put: put, get: get, delete: del, extendRetention: extendRetention,
    placeLegalHold: placeLegalHold, releaseLegalHold: releaseLegalHold,
    list: list, mode: mode,
  };
}

module.exports = {
  create:    create,
  MODES:     Object.keys(MODES),
  WormError: WormError,
};

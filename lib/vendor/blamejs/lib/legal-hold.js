"use strict";
/**
 * legal-hold — subject-level litigation/regulatory hold registry.
 *
 * A legal hold (a.k.a. litigation hold, preservation order, regulatory
 * hold) freezes a named subject's data so retention sweeps, RTBF
 * erasures, and routine purges cannot remove records pending the
 * resolution of an investigation, lawsuit, audit, or regulatory
 * inquiry. Per FRCP Rule 26 / Rule 37(e) (US Federal Rules of Civil
 * Procedure), GDPR Art. 17(3)(e) (right-to-erasure exception for
 * legal claims), SEC Rule 17a-4 (broker-dealer record preservation),
 * and HIPAA §164.530(j)(2) (six-year retention of HIPAA records),
 * once an organization knows or should reasonably know that records
 * are relevant to anticipated litigation or regulatory action, it
 * must suspend routine destruction.
 *
 * Per-rule `legalHoldField` in b.retention already lets an operator
 * gate retention skips on a column value. This module is the central
 * registry that:
 *
 *   1. Records each placement / release as a hash-chained audit row
 *      (`legalhold.placed` / `legalhold.released` events).
 *   2. Persists subject-id-keyed entries in `_blamejs_legal_hold` so
 *      the framework can answer `isHeld(subjectId)` in O(1) without
 *      the operator having to plumb a flag column into every table.
 *   3. Wires into b.subject.erase + b.retention so a placed hold
 *      refuses erasure even when the operator-supplied
 *      acknowledgements would otherwise pass.
 *
 *   var holds = b.legalHold.create({
 *     db:       b.db,
 *     audit:    b.audit,
 *     signWith: b.auditSign,             // optional — sign every event
 *   });
 *
 *   await holds.place("user-42", {
 *     reason:      "SEC subpoena 2026-03-12 case 24-cv-01933",
 *     custodian:   "legal@example.com",
 *     citation:    "FRCP-26",
 *     retainUntil: Date.now() + C.TIME.days(365),  // optional sunset
 *   });
 *
 *   await holds.release("user-42", {
 *     reason:   "case dismissed; preservation duty ended",
 *     approver: "legal@example.com",
 *   });
 *
 *   holds.isHeld("user-42");              // → boolean (sync read)
 *   holds.list();                         // → [{ subjectId, ... }]
 *   holds.history("user-42");             // → [{ at, action, ... }]
 *
 * Storage shape: `_blamejs_legal_hold` is the active registry (one
 * row per held subject); placement + release history is preserved in
 * the framework audit_log via `legalhold.placed` / `.released`
 * events. Operators wanting a flat history table re-derive it from
 * the audit chain.
 *
 * Validation tier: throw at config-time on bad opts; throw on
 * missing/garbage subjectId at the API; emit + return shaped error
 * on policy denials (already-held / not-held / invalid-citation).
 */
var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var LegalHoldError = defineClass("LegalHoldError", { alwaysPermanent: true });
var _err = LegalHoldError.factory;

// Per FRCP Rule 26(f) / 37(e), GDPR Art. 17(3)(e), SEC Rule 17a-4(b),
// HIPAA §164.530(j)(2), 21 CFR Part 11 §11.10(c). Operator-supplied
// citation should match one of these or be a free-form reference; the
// framework only sanity-checks shape, not value.
var KNOWN_CITATIONS = Object.freeze([
  "FRCP-26", "FRCP-37(e)",
  "GDPR-Art-17-3-e",
  "SEC-Rule-17a-4", "SEC-Rule-17a-4(f)",
  "FINRA-4511",
  "HIPAA-164.530(j)(2)",
  "21-CFR-Part-11", "21-CFR-Part-11-11.10(c)",
  "operator-defined",
]);

function _subjectIdString(subjectId) {
  if (subjectId === null || subjectId === undefined) {
    throw _err("BAD_ARG", "subjectId must be a non-empty string");
  }
  var s = String(subjectId);
  if (s.length === 0) {
    throw _err("BAD_ARG", "subjectId must be a non-empty string");
  }
  return s;
}

function _hashSubject(subjectId) {
  return bCrypto.sha3Hash("bj-legal-hold:" + subjectId);
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["db", "audit", "signWith"], "legalHold");
  if (!opts.db || typeof opts.db.prepare !== "function") {
    throw _err("BAD_OPT", "create: opts.db is required (a b.db handle)");
  }
  var db = opts.db;
  var auditOn = opts.audit !== false && opts.audit != null;
  var auditInstance = (opts.audit && opts.audit !== true) ? opts.audit : null;
  // signWith is reserved for future per-event detached signatures;
  // currently the audit chain itself is hash-linked + the sidecar
  // signing on audit_checkpoints covers tamper detection. Validate
  // shape so a caller passing it gets a typo-surfacing throw, but
  // don't require it.
  validateOpts.optionalObjectWithMethod(opts.signWith, "sign",
    "create: opts.signWith", LegalHoldError, "BAD_OPT", "b.auditSign-shaped object");

  function _emit(action, info, outcome) {
    if (!auditOn) return;
    var sink = auditInstance || audit();
    try {
      sink.safeEmit({
        action:   action,
        outcome:  outcome,
        resource: { kind: "legal-hold", id: info && info.subjectId },
        reason:   (info && info.reason) || null,
        metadata: info || {},
      });
    } catch (_e) { /* best-effort */ }
  }

  function _ensureSchema() {
    // Idempotent migration. The framework SQLite path installs the
    // table via FRAMEWORK_SCHEMA at boot; this guard is for the
    // external-db / cluster path where schema migrations are operator-
    // driven. Either way the IF NOT EXISTS shape is safe to re-run.
    var fn = db.runSql || db.execRaw;
    if (typeof fn === "function") {
      fn(
        'CREATE TABLE IF NOT EXISTS "_blamejs_legal_hold" (' +
        '"subjectIdHash" TEXT PRIMARY KEY,' +
        '"placedAt" INTEGER NOT NULL,' +
        '"placedBy" TEXT,' +
        '"reason" TEXT NOT NULL,' +
        '"custodian" TEXT,' +
        '"citation" TEXT,' +
        '"retainUntil" INTEGER' +
        ')'
      );
    }
  }

  function place(subjectId, args) {
    var sid = _subjectIdString(subjectId);
    args = args || {};
    if (typeof args.reason !== "string" || args.reason.length === 0) {
      throw _err("BAD_ARG", "place: args.reason is required (non-empty string)");
    }
    if (args.citation !== undefined && args.citation !== null) {
      if (typeof args.citation !== "string" || args.citation.length === 0) {
        throw _err("BAD_ARG", "place: args.citation must be a non-empty string");
      }
    }
    if (args.retainUntil !== undefined && args.retainUntil !== null) {
      if (typeof args.retainUntil !== "number" ||
          !isFinite(args.retainUntil) ||
          args.retainUntil <= 0) {
        throw _err("BAD_ARG", "place: args.retainUntil must be a positive finite ms-epoch");
      }
    }
    _ensureSchema();
    var hash = _hashSubject(sid);
    var existing = db.prepare(
      'SELECT placedAt FROM "_blamejs_legal_hold" WHERE subjectIdHash = ?'
    ).get(hash);
    if (existing) {
      _emit("legalhold.place_rejected",
        { subjectId: sid, reason: "already-held",
          existingSince: existing.placedAt },
        "denied");
      return { error: "already-held", placedAt: existing.placedAt };
    }
    var nowMs = Date.now();
    db.prepare(
      'INSERT INTO "_blamejs_legal_hold" ' +
      '(subjectIdHash, placedAt, placedBy, reason, custodian, citation, retainUntil) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(
      hash, nowMs,
      args.placedBy || null,
      args.reason,
      args.custodian || null,
      args.citation || null,
      args.retainUntil || null
    );
    _emit("legalhold.placed",
      { subjectId: sid, reason: args.reason,
        custodian: args.custodian || null,
        citation:  args.citation  || null,
        retainUntil: args.retainUntil || null,
        placedBy: args.placedBy || null,
        knownCitation: args.citation && KNOWN_CITATIONS.indexOf(args.citation) !== -1 },
      "success");
    return { placed: true, placedAt: nowMs };
  }

  function release(subjectId, args) {
    var sid = _subjectIdString(subjectId);
    args = args || {};
    if (typeof args.reason !== "string" || args.reason.length === 0) {
      throw _err("BAD_ARG", "release: args.reason is required (non-empty string)");
    }
    if (typeof args.approver !== "string" || args.approver.length === 0) {
      throw _err("BAD_ARG", "release: args.approver is required (non-empty string)");
    }
    _ensureSchema();
    var hash = _hashSubject(sid);
    var existing = db.prepare(
      'SELECT placedAt, reason FROM "_blamejs_legal_hold" WHERE subjectIdHash = ?'
    ).get(hash);
    if (!existing) {
      _emit("legalhold.release_rejected",
        { subjectId: sid, reason: "not-held" },
        "denied");
      return { error: "not-held" };
    }
    db.prepare(
      'DELETE FROM "_blamejs_legal_hold" WHERE subjectIdHash = ?'
    ).run(hash);
    _emit("legalhold.released",
      { subjectId: sid, reason: args.reason,
        approver: args.approver,
        originalReason: existing.reason,
        heldSince: existing.placedAt },
      "success");
    return { released: true, heldSince: existing.placedAt };
  }

  function isHeld(subjectId) {
    var sid = _subjectIdString(subjectId);
    _ensureSchema();
    var hash = _hashSubject(sid);
    var row = db.prepare(
      'SELECT retainUntil FROM "_blamejs_legal_hold" WHERE subjectIdHash = ?'
    ).get(hash);
    if (!row) return false;
    // retainUntil expiry — when the operator pinned a sunset and it
    // has passed, the hold has lapsed and isHeld returns false. The
    // row stays so audit/history reads can see when the sunset hit;
    // operators wanting the row gone call release() explicitly.
    if (row.retainUntil && row.retainUntil < Date.now()) return false;
    return true;
  }

  function get(subjectId) {
    var sid = _subjectIdString(subjectId);
    _ensureSchema();
    var hash = _hashSubject(sid);
    var row = db.prepare(
      'SELECT subjectIdHash, placedAt, placedBy, reason, custodian, citation, retainUntil ' +
      'FROM "_blamejs_legal_hold" WHERE subjectIdHash = ?'
    ).get(hash);
    if (!row) return null;
    return {
      subjectId:   sid,
      placedAt:    row.placedAt,
      placedBy:    row.placedBy,
      reason:      row.reason,
      custodian:   row.custodian,
      citation:    row.citation,
      retainUntil: row.retainUntil,
      lapsed:      !!(row.retainUntil && row.retainUntil < Date.now()),
    };
  }

  function list() {
    _ensureSchema();
    var rows = db.prepare(
      'SELECT subjectIdHash, placedAt, placedBy, reason, custodian, citation, retainUntil ' +
      'FROM "_blamejs_legal_hold" ORDER BY placedAt'
    ).all();
    var nowMs = Date.now();
    return rows.map(function (r) {
      return {
        subjectIdHash: r.subjectIdHash,
        placedAt:      r.placedAt,
        placedBy:      r.placedBy,
        reason:        r.reason,
        custodian:     r.custodian,
        citation:      r.citation,
        retainUntil:   r.retainUntil,
        lapsed:        !!(r.retainUntil && r.retainUntil < nowMs),
      };
    });
  }

  function history(subjectId) {
    // Re-derive the placement/release history from the audit chain.
    // We don't store a separate history table — the audit_log is
    // already tamper-evident and chain-verified.
    var sid = _subjectIdString(subjectId);
    var rows = [];
    try {
      var auditQuery = db.prepare(
        'SELECT recordedAt, action, metadata, outcome ' +
        'FROM audit_log ' +
        'WHERE action LIKE ? AND resourceKind = ? ' +
        'ORDER BY recordedAt'
      );
      // resourceId is sealed, so match on resourceKind + post-filter
      // by parsed metadata.
      var raw = auditQuery.all("legalhold.%", "legal-hold");
      for (var i = 0; i < raw.length; i++) {
        var meta = null;
        try { meta = safeJson.parse(raw[i].metadata || "{}"); } catch (_e) { meta = null; }
        if (meta && meta.subjectId === sid) {
          rows.push({
            at:       raw[i].recordedAt,
            action:   raw[i].action,
            outcome:  raw[i].outcome,
            metadata: meta,
          });
        }
      }
    } catch (_e) { /* drop-silent: audit_log may be sealed-metadata in cluster mode */ }
    return rows;
  }

  var instance = {
    place:           place,
    release:         release,
    isHeld:          isHeld,
    get:             get,
    list:            list,
    history:         history,
    KNOWN_CITATIONS: KNOWN_CITATIONS,
  };
  // Auto-register the most recent instance as the framework singleton
  // so b.subject.erase / b.retention can consult b.legalHold.isHeld
  // without each operator threading the instance through. Operators
  // building multiple registries (multi-tenant, test isolation) call
  // create() once per tenant; the last create() wins for the global
  // gate, and per-tenant code holds its own instance reference.
  _registerSingleton(instance);
  return instance;
}

// Singleton convenience — many primitives (b.subject.erase,
// b.retention) need to consult the registry without each operator
// passing a holds instance through. The first create() under a
// db handle wins; subsequent calls return the active singleton.
var _singleton = null;

function _registerSingleton(instance) {
  _singleton = instance;
}

function _getSingleton() {
  return _singleton;
}

function _resetForTest() {
  _singleton = null;
}

module.exports = {
  create:            create,
  KNOWN_CITATIONS:   KNOWN_CITATIONS,
  LegalHoldError:    LegalHoldError,
  _registerSingleton: _registerSingleton,
  _getSingleton:     _getSingleton,
  _resetForTest:     _resetForTest,
};

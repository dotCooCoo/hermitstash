// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var bCrypto = require("./crypto");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var sql = require("./sql");
var cryptoField = require("./crypto-field");
var { defineClass } = require("./framework-error");

var HOLD_TABLE = "_blamejs_legal_hold";   // allow:hand-rolled-sql — canonical local table-name; passed to b.sql with quoteName
var AUDIT_TABLE = "audit_log";

var auditEmit = require("./audit-emit");

var LegalHoldError = defineClass("LegalHoldError", { alwaysPermanent: true });
var _err = LegalHoldError.factory;

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
    throw _err("legal-hold/bad-arg", "subjectId must be a non-empty string");
  }
  var s = String(subjectId);
  if (s.length === 0) {
    throw _err("legal-hold/bad-arg", "subjectId must be a non-empty string");
  }
  return s;
}

function _hashSubject(subjectId) {
  return bCrypto.sha3Hash("bj-legal-hold:" + subjectId);
}

function _handleDialect(db) {
  if (db && typeof db.dialect === "function") {
    try { var d = db.dialect(); return typeof d === "string" ? d : "sqlite"; }
    catch (_e) { return "sqlite"; }
  }
  if (db && typeof db.dialect === "string") return db.dialect;
  return "sqlite";
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["db", "audit", "signWith"], "legalHold");
  if (!opts.db || typeof opts.db.prepare !== "function") {
    throw _err("legal-hold/bad-opt", "create: opts.db is required (a b.db handle)");
  }
  var db = opts.db;
  var SQL_OPTS = { dialect: _handleDialect(db), quoteName: true };
  var auditOn = opts.audit !== false && opts.audit != null;
  var auditInstance = (opts.audit && opts.audit !== true) ? opts.audit : null;
  validateOpts.optionalObjectWithMethod(opts.signWith, "sign",
    "create: opts.signWith", LegalHoldError, "legal-hold/bad-opt", "b.auditSign-shaped object");

  var _emit = auditEmit.gatedReasonEmitter({
    audit: auditOn,
    sink:  auditInstance,
    extra: function (info) { return { resource: { kind: "legal-hold", id: info && info.subjectId } }; },
  });

  function _ensureSchema() {
    var fn = db.runSql || db.execRaw;
    if (typeof fn === "function") {
      var ddl = sql.createTable(HOLD_TABLE, [
        { name: "subjectIdHash", type: "text", primaryKey: true },
        { name: "placedAt",      type: "int",  notNull: true },
        { name: "placedBy",      type: "text" },
        { name: "reason",        type: "text", notNull: true },
        { name: "custodian",     type: "text" },
        { name: "citation",      type: "text" },
        { name: "retainUntil",   type: "int" },
      ], SQL_OPTS);
      fn(ddl.sql);
    }
    if (!cryptoField.getSchema(HOLD_TABLE)) {
      cryptoField.registerTable(HOLD_TABLE, {
        sealedFields: ["reason", "placedBy", "custodian", "citation"],
      });
    }
  }

  function place(subjectId, args) {
    var sid = _subjectIdString(subjectId);
    args = args || {};
    if (typeof args.reason !== "string" || args.reason.length === 0) {
      throw _err("legal-hold/bad-arg", "place: args.reason is required (non-empty string)");
    }
    if (args.citation !== undefined && args.citation !== null) {
      if (typeof args.citation !== "string" || args.citation.length === 0) {
        throw _err("legal-hold/bad-arg", "place: args.citation must be a non-empty string");
      }
    }
    if (args.retainUntil !== undefined && args.retainUntil !== null) {
      if (typeof args.retainUntil !== "number" ||
          !isFinite(args.retainUntil) ||
          args.retainUntil <= 0) {
        throw _err("legal-hold/bad-arg", "place: args.retainUntil must be a positive finite ms-epoch");
      }
    }
    _ensureSchema();
    var hash = _hashSubject(sid);
    var placeSelBuilt = sql.select(HOLD_TABLE, SQL_OPTS)
      .columns(["placedAt", "retainUntil"])
      .where("subjectIdHash", hash)
      .toSql();
    var placeSelStmt = db.prepare(placeSelBuilt.sql);
    var existing = placeSelStmt.get.apply(placeSelStmt, placeSelBuilt.params);
    var nowMs = Date.now();
    var renewedFromLapsed = false;
    if (existing) {
      var existingLapsed = existing.retainUntil && existing.retainUntil < nowMs;
      if (!existingLapsed) {
        _emit("legalhold.place_rejected",
          { subjectId: sid, reason: "already-held",
            existingSince: existing.placedAt },
          "denied");
        return { error: "already-held", placedAt: existing.placedAt };
      }
      renewedFromLapsed = true;
      var lapseDelBuilt = sql.delete(HOLD_TABLE, SQL_OPTS)
        .where("subjectIdHash", hash)
        .toSql();
      var lapseDelStmt = db.prepare(lapseDelBuilt.sql);
      lapseDelStmt.run.apply(lapseDelStmt, lapseDelBuilt.params);
    }
    var placeInsBuilt = sql.insert(HOLD_TABLE, SQL_OPTS)
      .values(cryptoField.sealRow(HOLD_TABLE, {
        subjectIdHash: hash,
        placedAt:      nowMs,
        placedBy:      args.placedBy || null,
        reason:        args.reason,
        custodian:     args.custodian || null,
        citation:      args.citation || null,
        retainUntil:   args.retainUntil || null,
      }))
      .toSql();
    var placeInsStmt = db.prepare(placeInsBuilt.sql);
    placeInsStmt.run.apply(placeInsStmt, placeInsBuilt.params);
    _emit("legalhold.placed",
      { subjectId: sid, reason: args.reason,
        custodian: args.custodian || null,
        citation:  args.citation  || null,
        retainUntil: args.retainUntil || null,
        placedBy: args.placedBy || null,
        renewedFromLapsed: renewedFromLapsed,
        knownCitation: args.citation && KNOWN_CITATIONS.indexOf(args.citation) !== -1 },
      "success");
    return { placed: true, placedAt: nowMs, renewedFromLapsed: renewedFromLapsed };
  }

  function release(subjectId, args) {
    var sid = _subjectIdString(subjectId);
    args = args || {};
    if (typeof args.reason !== "string" || args.reason.length === 0) {
      throw _err("legal-hold/bad-arg", "release: args.reason is required (non-empty string)");
    }
    if (typeof args.approver !== "string" || args.approver.length === 0) {
      throw _err("legal-hold/bad-arg", "release: args.approver is required (non-empty string)");
    }
    _ensureSchema();
    var hash = _hashSubject(sid);
    var relSelBuilt = sql.select(HOLD_TABLE, SQL_OPTS)
      .columns(["placedAt", "reason"])
      .where("subjectIdHash", hash)
      .toSql();
    var relSelStmt = db.prepare(relSelBuilt.sql);
    var existing = relSelStmt.get.apply(relSelStmt, relSelBuilt.params);
    if (!existing) {
      _emit("legalhold.release_rejected",
        { subjectId: sid, reason: "not-held" },
        "denied");
      return { error: "not-held" };
    }
    existing = cryptoField.unsealRow(HOLD_TABLE, existing);
    var relDelBuilt = sql.delete(HOLD_TABLE, SQL_OPTS)
      .where("subjectIdHash", hash)
      .toSql();
    var relDelStmt = db.prepare(relDelBuilt.sql);
    relDelStmt.run.apply(relDelStmt, relDelBuilt.params);
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
    var heldBuilt = sql.select(HOLD_TABLE, SQL_OPTS)
      .columns(["retainUntil"])
      .where("subjectIdHash", hash)
      .toSql();
    var heldStmt = db.prepare(heldBuilt.sql);
    var row = heldStmt.get.apply(heldStmt, heldBuilt.params);
    if (!row) return false;
    if (row.retainUntil && row.retainUntil < Date.now()) return false;
    return true;
  }

  function get(subjectId) {
    var sid = _subjectIdString(subjectId);
    _ensureSchema();
    var hash = _hashSubject(sid);
    var getBuilt = sql.select(HOLD_TABLE, SQL_OPTS)
      .columns(["subjectIdHash", "placedAt", "placedBy", "reason", "custodian", "citation", "retainUntil"])
      .where("subjectIdHash", hash)
      .toSql();
    var getStmt = db.prepare(getBuilt.sql);
    var row = getStmt.get.apply(getStmt, getBuilt.params);
    if (!row) return null;
    row = cryptoField.unsealRow(HOLD_TABLE, row);
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
    var listBuilt = sql.select(HOLD_TABLE, SQL_OPTS)
      .columns(["subjectIdHash", "placedAt", "placedBy", "reason", "custodian", "citation", "retainUntil"])
      .orderBy("placedAt", "asc")
      .toSql();
    var listStmt = db.prepare(listBuilt.sql);
    var rows = listStmt.all.apply(listStmt, listBuilt.params);
    var nowMs = Date.now();
    return rows.map(function (r) {
      r = cryptoField.unsealRow(HOLD_TABLE, r);
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
    var sid = _subjectIdString(subjectId);
    var rows = [];
    try {
      var histBuilt = sql.select(AUDIT_TABLE, SQL_OPTS)
        .columns(["recordedAt", "action", "metadata", "outcome"])
        .whereLike("action", "legalhold.", "prefix")
        .where("resourceKind", "legal-hold")
        .orderBy("recordedAt", "asc")
        .toSql();
      var auditQuery = db.prepare(histBuilt.sql);
      var raw = auditQuery.all.apply(auditQuery, histBuilt.params);
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
  _registerSingleton(instance);
  return instance;
}

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

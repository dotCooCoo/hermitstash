"use strict";
/**
 * @module b.subject
 * @nav    Identity
 * @title  Subject
 *
 * @intro
 *   Data subject (user) lifecycle + DSR (Data Subject Rights) helpers —
 *   register / lookup / export / erase. Tied to GDPR (Articles 15-22)
 *   and CCPA workflows; also covers AU Privacy Act review (right to
 *   erasure) and HIPAA §164.524 access requests.
 *
 *   App schema declares per-table `subjectField` (the column that points
 *   to the subject) and `personalDataCategories` (semantic tag for the
 *   Record of Processing Activities). This module then walks every
 *   table that knows about a given subject without the app having to
 *   plumb subject IDs through repository code.
 *
 *   Erasure model: physical row deletion with the audit chain preserved
 *   (the subject's data rows are gone; the audit_log entries about them
 *   remain hash-linked). `b.subject.erase` satisfies GDPR Art. 17 in
 *   the strict sense (subject data is erased). `b.subject.eraseHard`
 *   layers cryptographic erasure on top — destroys per-row K_row keys
 *   for tables that opted into per-row keying, leaving any residual
 *   ciphertext in WAL / replica / backup storage undecryptable even if
 *   the operator's vault key is later recovered.
 *
 *   Every mutating call routes through `cluster.requireLeader` and
 *   writes a structured audit event (`subject.export` / `subject.rectify`
 *   / `subject.erase` / `subject.erase_hard` / `subject.restrict` /
 *   `subject.objection`). Erasure is additionally gated by the central
 *   legal-hold registry (FRCP Rule 26/37(e), GDPR Art 17(3)(e), SEC
 *   Rule 17a-4, HIPAA §164.530(j)(2)) — a stale operator attestation
 *   cannot override an active hold.
 *
 * @card
 *   Data subject (user) lifecycle + DSR (Data Subject Rights) helpers — register / lookup / export / erase.
 */
var { sha3Hash } = require("./crypto");
var cryptoField = require("./crypto-field");
var audit = require("./audit");
var cluster = require("./cluster");
var lazyRequire = require("./lazy-require");

var db = lazyRequire(function () { return require("./db"); });
var legalHold = lazyRequire(function () { return require("./legal-hold"); });

// Required acknowledgements before subject.erase will run. Operator must
// explicitly attest each one to confirm no statutory retention or active
// litigation hold blocks the deletion.
var REQUIRED_ERASE_ACKS = ["no-litigation-hold", "no-statutory-retention-required"];

// ---- Export (Art. 15, Art. 20) ----

/**
 * @primitive  b.subject.export
 * @signature  b.subject.export(subjectId, opts?)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr, ccpa, hipaa
 * @related    b.subject.exportData, b.subject.rectify, b.subject.erase
 *
 * GDPR Art. 15 (right of access) + Art. 20 (data portability) +
 * HIPAA §164.524 access request. Walks every table whose schema
 * declared a `subjectField` pointing at the subject identifier and
 * returns `{ tableName: [unsealedRows] }`. Sealed columns are
 * unsealed in-memory for the export; derived-hash columns are used
 * for predicate lookup so plaintext subject IDs never need to land
 * in a query string. Writes a `subject.export` audit event listing
 * the tables touched.
 *
 * @opts
 *   include: "all" | string[],   // table allowlist; "all" exports every subjectField-tagged table
 *   reason:  string,             // ticket reference recorded in the audit event
 *
 * @example
 *   var dump = b.subject.export("user-4471", {
 *     include: "all",
 *     reason:  "GDPR Art. 15 access request 2026-05-08 ticket #4471",
 *   });
 *   Object.keys(dump);
 *   // → ["users", "orders", "audit_log"]
 *
 *   var ordersOnly = b.subject.export("user-4471", {
 *     include: ["orders"],
 *     reason:  "GDPR Art. 20 portability subset",
 *   });
 */

/**
 * @primitive  b.subject.exportData
 * @signature  b.subject.exportData(subjectId, opts?)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr, ccpa, hipaa
 * @related    b.subject.export
 *
 * Identical behaviour to `b.subject.export`. Shipped as a non-reserved
 * alias because some downstream toolchains (older bundlers, TypeScript
 * `import { export }` parsing, JSON-serialised method lists) trip on
 * the `export` keyword. New code should prefer `b.subject.export`;
 * `exportData` is kept for tool-friendliness.
 *
 * @opts
 *   include: "all" | string[],   // table allowlist
 *   reason:  string,             // ticket reference recorded in the audit event
 *
 * @example
 *   var dump = b.subject.exportData("user-4471", {
 *     include: "all",
 *     reason:  "GDPR Art. 15 access request",
 *   });
 *   Array.isArray(dump.users || []);
 *   // → true
 */
function exportData(subjectId, opts) {
  if (!subjectId) throw new Error("subject.export requires a subjectId");
  opts = opts || {};
  var include = opts.include || "all";

  var tables = db()._getSubjectTables();
  if (tables.length === 0) {
    return _writeAudit("subject.export", subjectId, "success", { reason: opts.reason || null }, {});
  }

  var dump = {};
  for (var i = 0; i < tables.length; i++) {
    var t = tables[i];
    if (include !== "all" && include.indexOf(t.name) === -1) continue;

    // Look up via derivedHash if the subjectField is sealed; otherwise raw equality.
    var rows = _findRowsForSubject(t.name, t.subjectField, subjectId);
    if (rows.length > 0) dump[t.name] = rows;
  }

  _writeAudit("subject.export", subjectId, "success", { reason: opts.reason || null, tables: Object.keys(dump) });
  return dump;
}

function _findRowsForSubject(tableName, subjectField, subjectId) {
  var hash = db().hashFor(tableName, subjectField, subjectId);
  if (hash) {
    // The schema has a derived hash for the subjectField — look up via that
    var derivedFieldName = _getDerivedFieldName(tableName, subjectField);
    if (derivedFieldName) {
      var pred = {};
      pred[derivedFieldName] = hash;
      return db().from(tableName).where(pred).all();
    }
  }
  // No derived hash — assume subjectField is raw, do direct equality
  var rawPred = {};
  rawPred[subjectField] = subjectId;
  return db().from(tableName).where(rawPred).all();
}

function _getDerivedFieldName(tableName, sourceField) {
  var schema = cryptoField.getSchema(tableName);
  if (!schema || !schema.derivedHashes) return null;
  for (var derivedField in schema.derivedHashes) {
    if (schema.derivedHashes[derivedField].from === sourceField) return derivedField;
  }
  return null;
}

// ---- Rectify (Art. 16) ----

/**
 * @primitive  b.subject.rectify
 * @signature  b.subject.rectify(subjectId, opts)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr, ccpa, hipaa
 * @related    b.subject.export, b.subject.erase
 *
 * GDPR Art. 16 (right to rectification). Updates a single row in a
 * single table on behalf of the subject and emits an audit event
 * carrying the before/after values for the changed fields. Leader-only
 * in cluster mode (`cluster.requireLeader`). Throws when the row
 * cannot be located or `opts` is missing required keys.
 *
 * @opts
 *   table:   string,         // table name (must declare subjectField in schema)
 *   id:      string,         // _id of the row to update
 *   changes: object,         // { fieldName: newValue, ... }
 *   reason:  string,         // ticket reference recorded in the audit event
 *
 * @example
 *   var ok = b.subject.rectify("user-4471", {
 *     table:   "users",
 *     id:      "row-9912",
 *     changes: { email: "new@example.com", displayName: "Jane Roe" },
 *     reason:  "GDPR Art. 16 rectification ticket #5512",
 *   });
 *   ok;
 *   // → true
 */
function rectify(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.rectify requires a subjectId");
  if (!opts || !opts.table || !opts.id || !opts.changes) {
    throw new Error("subject.rectify requires { table, id, changes }");
  }

  // Read current values for audit metadata
  var before = db().from(opts.table).where({ _id: opts.id }).first();
  if (!before) {
    _writeAudit("subject.rectify", subjectId, "failure", {
      reason:     "row not found",
      table:      opts.table,
      rowId:      opts.id,
      requestReason: opts.reason,
    });
    throw new Error("subject.rectify: row not found in '" + opts.table + "' with _id '" + opts.id + "'");
  }

  var changedKeys = Object.keys(opts.changes);
  var beforeValues = {};
  for (var i = 0; i < changedKeys.length; i++) beforeValues[changedKeys[i]] = before[changedKeys[i]];

  var ok = db().from(opts.table).where({ _id: opts.id }).updateOne(opts.changes);

  _writeAudit("subject.rectify", subjectId, ok ? "success" : "failure", {
    table:         opts.table,
    rowId:         opts.id,
    fieldsChanged: changedKeys,
    requestReason: opts.reason,
    // before/after values are sealed in the audit metadata too (sealing
    // happens at the audit_log boundary because metadata is in the seal list)
    before:        beforeValues,
    after:         opts.changes,
  });

  return ok;
}

// ---- Erase (Art. 17 right to be forgotten) ----

/**
 * @primitive  b.subject.erase
 * @signature  b.subject.erase(subjectId, opts)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr, ccpa, hipaa
 * @related    b.subject.eraseHard, b.subject.export, b.subject.restrict
 *
 * GDPR Art. 17 (right to be forgotten). Physical row deletion across
 * every subjectField-tagged table; the audit chain remains intact
 * (entries about the subject stay hash-linked even after the subject's
 * data rows are gone). Leader-only.
 *
 * Two gates layer in front of the deletion: every operator-supplied
 * acknowledgement in `REQUIRED_ERASE_ACKS` must be present
 * (`no-litigation-hold`, `no-statutory-retention-required`), AND the
 * central legal-hold registry must report no active hold for the
 * subject. The registry is authoritative — a stale attestation cannot
 * override an active hold (FRCP Rule 26/37(e), GDPR Art 17(3)(e),
 * SEC Rule 17a-4, HIPAA §164.530(j)(2)).
 *
 * Returns `{ rowsDeleted, perTable }`. Use `b.subject.eraseHard` when
 * residual ciphertext in WAL / replicas / backups must also be made
 * undecryptable.
 *
 * @opts
 *   reason:           string,    // ticket reference recorded in the audit event
 *   acknowledgements: string[],  // must include every entry in REQUIRED_ERASE_ACKS
 *   legalHold:        object,    // optional override for testing; defaults to the framework registry
 *
 * @example
 *   var result = b.subject.erase("user-4471", {
 *     reason:           "GDPR Art. 17 request 2026-05-08 ticket #4471",
 *     acknowledgements: [
 *       "no-litigation-hold",
 *       "no-statutory-retention-required",
 *     ],
 *   });
 *   result.rowsDeleted;
 *   // → 12
 *   Object.keys(result.perTable);
 *   // → ["users", "orders", "preferences"]
 */
function erase(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.erase requires a subjectId");
  if (!opts || !opts.reason) {
    throw new Error("subject.erase requires { reason } — e.g. 'GDPR Art. 17 request 2026-04-25 ticket #4471'");
  }
  if (!Array.isArray(opts.acknowledgements)) {
    throw new Error("subject.erase requires { acknowledgements: [...] } — see REQUIRED_ERASE_ACKS");
  }
  for (var i = 0; i < REQUIRED_ERASE_ACKS.length; i++) {
    if (opts.acknowledgements.indexOf(REQUIRED_ERASE_ACKS[i]) === -1) {
      throw new Error(
        "subject.erase: missing required acknowledgement '" + REQUIRED_ERASE_ACKS[i] + "'. " +
        "Operator must attest no litigation hold and no statutory retention before erasure."
      );
    }
  }

  // Authoritative legal-hold gate. Even when the operator passed the
  // "no-litigation-hold" attestation, the central registry is the
  // source of truth — a stale attestation cannot override an active
  // hold. Per FRCP Rule 26/37(e), GDPR Art 17(3)(e), SEC Rule 17a-4,
  // HIPAA §164.530(j)(2).
  var holds = (opts && opts.legalHold) || legalHold()._getSingleton();
  if (holds && holds.isHeld(subjectId)) {
    var holdInfo = holds.get(subjectId) || {};
    _writeAudit("subject.erase", subjectId, "denied", {
      requestReason: opts.reason,
      reason:        "legal-hold-active",
      heldSince:     holdInfo.placedAt,
      citation:      holdInfo.citation,
    });
    throw new Error(
      "subject.erase: subject '" + subjectId + "' is on legal hold (" +
      (holdInfo.citation || "operator-defined") + "; placed " +
      new Date(holdInfo.placedAt).toISOString() +
      "). Release the hold before erasure."
    );
  }

  var tables = db()._getSubjectTables();
  var totalDeleted = 0;
  var perTable = {};

  for (var t = 0; t < tables.length; t++) {
    var spec = tables[t];
    var hash = db().hashFor(spec.name, spec.subjectField, subjectId);
    var pred;
    if (hash) {
      var derivedField = _getDerivedFieldName(spec.name, spec.subjectField);
      if (derivedField) {
        pred = {}; pred[derivedField] = hash;
      } else {
        pred = {}; pred[spec.subjectField] = subjectId;
      }
    } else {
      pred = {}; pred[spec.subjectField] = subjectId;
    }
    var deleted = db().from(spec.name).where(pred).deleteMany();
    totalDeleted += deleted;
    perTable[spec.name] = deleted;
  }

  // Mark subject as erased (so future writes refuse to mention them)
  _markErased(subjectId);

  _writeAudit("subject.erase", subjectId, "success", {
    requestReason:  opts.reason,
    rowsDeleted:    totalDeleted,
    perTable:       perTable,
    acknowledgements: opts.acknowledgements,
  });

  return { rowsDeleted: totalDeleted, perTable: perTable };
}

// ---- Crypto-shred erase (Art. 17 + WAL/replica residual closure) ----
//
// F-RTBF-3 — when a table opts into per-row keying via
// b.cryptoField.declarePerRowKey, this primitive deletes the
// per-row K_row entries from _blamejs_per_row_keys, leaving any
// residual ciphertext in WAL / replica / backup storage
// undecryptable even if the operator's vault key is later
// recovered. Combined with a row DELETE + REINDEX, this is the
// strongest GDPR Art. 17 erasure shape the framework offers.

/**
 * @primitive  b.subject.eraseHard
 * @signature  b.subject.eraseHard(subjectId, opts)
 * @since      0.8.44
 * @status     stable
 * @compliance gdpr, ccpa, hipaa
 * @related    b.subject.erase, b.cryptoField.declarePerRowKey
 *
 * Cryptographic erasure on top of `b.subject.erase`. For tables that
 * opted into per-row keying via `b.cryptoField.declarePerRowKey`, the
 * call destroys each row's K_row entry from `_blamejs_per_row_keys`
 * before the row DELETE, then runs `REINDEX` on the table so B-tree
 * pages holding the deleted index entries are rebuilt. Residual
 * ciphertext in WAL / replicas / backup archives stays undecryptable
 * even if the operator's vault key is later recovered — the strongest
 * Art. 17 erasure shape the framework offers.
 *
 * Same legal-hold + acknowledgement gates as `b.subject.erase`.
 * Leader-only. Returns `{ rowsDeleted, perRowKeysDestroyed, perTable }`.
 *
 * @opts
 *   reason:           string,    // ticket reference recorded in the audit event
 *   acknowledgements: string[],  // must include every entry in REQUIRED_ERASE_ACKS
 *   legalHold:        object,    // optional override for testing
 *
 * @example
 *   var result = b.subject.eraseHard("user-4471", {
 *     reason:           "GDPR Art. 17 cryptographic erasure ticket #4471",
 *     acknowledgements: [
 *       "no-litigation-hold",
 *       "no-statutory-retention-required",
 *     ],
 *   });
 *   result.rowsDeleted;
 *   // → 12
 *   result.perRowKeysDestroyed;
 *   // → 8
 */
function eraseHard(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.eraseHard requires a subjectId");
  opts = opts || {};
  if (!opts.reason) {
    throw new Error("subject.eraseHard requires { reason } — e.g. 'GDPR Art. 17 ticket #4471'");
  }
  if (!Array.isArray(opts.acknowledgements)) {
    throw new Error("subject.eraseHard requires { acknowledgements: [...] } — see REQUIRED_ERASE_ACKS");
  }
  for (var i = 0; i < REQUIRED_ERASE_ACKS.length; i++) {
    if (opts.acknowledgements.indexOf(REQUIRED_ERASE_ACKS[i]) === -1) {
      throw new Error(
        "subject.eraseHard: missing required acknowledgement '" +
        REQUIRED_ERASE_ACKS[i] + "'");
    }
  }
  // Authoritative legal-hold gate.
  var holds = (opts && opts.legalHold) || legalHold()._getSingleton();
  if (holds && holds.isHeld(subjectId)) {
    var holdInfo = holds.get(subjectId) || {};
    _writeAudit("subject.erase_hard", subjectId, "denied", {
      requestReason: opts.reason,
      reason:        "legal-hold-active",
      heldSince:     holdInfo.placedAt,
      citation:      holdInfo.citation,
    });
    throw new Error(
      "subject.eraseHard: subject '" + subjectId + "' is on legal hold (" +
      (holdInfo.citation || "operator-defined") + "). Release the hold first.");
  }

  var tables = db()._getSubjectTables();
  var perTable = {};
  var perRowKeysDestroyed = 0;
  var totalDeleted = 0;

  db().transaction(function () {
    for (var t = 0; t < tables.length; t++) {
      var spec = tables[t];
      var hash = db().hashFor(spec.name, spec.subjectField, subjectId);
      var pred;
      if (hash) {
        var derivedField = _getDerivedFieldName(spec.name, spec.subjectField);
        if (derivedField) {
          pred = {}; pred[derivedField] = hash;
        } else {
          pred = {}; pred[spec.subjectField] = subjectId;
        }
      } else {
        pred = {}; pred[spec.subjectField] = subjectId;
      }
      // Find rows so we can destroy their per-row keys before delete.
      var rows = db().from(spec.name).where(pred).all();
      if (cryptoField.hasPerRowKey(spec.name)) {
        for (var r = 0; r < rows.length; r++) {
          var rowId = rows[r]._id;
          if (rowId) {
            var dr = cryptoField.destroyPerRowKey(spec.name, rowId, db());
            perRowKeysDestroyed += (dr && dr.destroyed) || 0;
          }
        }
      }
      var deleted = db().from(spec.name).where(pred).deleteMany();
      totalDeleted += deleted;
      perTable[spec.name] = deleted;
      // REINDEX the table so B-tree pages holding the deleted row's
      // index entries are rebuilt — closes the F-RTBF-2 residual class.
      try { db().runSql('REINDEX "' + spec.name + '"'); }                                        // allow:identifier-from-schema — table name comes from FRAMEWORK_SCHEMA
      catch (_e) { /* cluster mode / unsupported dialect */ }
    }
    _markErased(subjectId);
  });

  _writeAudit("subject.erase_hard", subjectId, "success", {
    requestReason:       opts.reason,
    rowsDeleted:         totalDeleted,
    perRowKeysDestroyed: perRowKeysDestroyed,
    perTable:            perTable,
    acknowledgements:    opts.acknowledgements,
  });
  return {
    rowsDeleted:         totalDeleted,
    perRowKeysDestroyed: perRowKeysDestroyed,
    perTable:            perTable,
  };
}

// ---- Restrict (Art. 18) ----

/**
 * @primitive  b.subject.restrict
 * @signature  b.subject.restrict(subjectId, opts)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr
 * @related    b.subject.isRestricted, b.subject.recordObjection
 *
 * GDPR Art. 18 (right to restriction of processing). Toggles a flag in
 * `_blamejs_subject_restrictions` keyed by the subject-id hash;
 * downstream code consults `b.subject.isRestricted` before processing.
 * Leader-only. The subject ID is hashed before storage so the table
 * carries no plaintext subject identifiers.
 *
 * @opts
 *   on:     boolean,   // true to apply restriction, false to lift
 *   reason: string,    // ticket reference recorded in the audit event
 *
 * @example
 *   b.subject.restrict("user-4471", {
 *     on:     true,
 *     reason: "GDPR Art. 18 contested-accuracy hold ticket #6612",
 *   });
 *   b.subject.isRestricted("user-4471");
 *   // → true
 *
 *   b.subject.restrict("user-4471", { on: false, reason: "dispute resolved" });
 *   b.subject.isRestricted("user-4471");
 *   // → false
 */
function restrict(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.restrict requires a subjectId");
  if (!opts || typeof opts.on !== "boolean") {
    throw new Error("subject.restrict requires { on: true|false }");
  }
  var existing = db().prepare(
    "SELECT subjectIdHash FROM _blamejs_subject_restrictions WHERE subjectIdHash = ?"
  ).get(_subjectHash(subjectId));

  if (opts.on) {
    if (!existing) {
      db().prepare(
        "INSERT INTO _blamejs_subject_restrictions (subjectIdHash, since, reason) VALUES (?, ?, ?)"
      ).run(_subjectHash(subjectId), Date.now(), opts.reason || null);
    }
  } else if (existing) {
    db().prepare(
      "DELETE FROM _blamejs_subject_restrictions WHERE subjectIdHash = ?"
    ).run(_subjectHash(subjectId));
  }

  _writeAudit("subject.restrict", subjectId, "success", {
    on:     opts.on,
    reason: opts.reason || null,
  });
  return true;
}

/**
 * @primitive  b.subject.isRestricted
 * @signature  b.subject.isRestricted(subjectId)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr
 * @related    b.subject.restrict
 *
 * Cheap read-side check — returns `true` when the subject currently
 * has an active GDPR Art. 18 restriction. Safe to call on any node
 * (no leader gate); reads from `_blamejs_subject_restrictions` via
 * the indexed subject-id hash.
 *
 * @example
 *   if (b.subject.isRestricted("user-4471")) {
 *     throw new Error("processing paused under GDPR Art. 18");
 *   }
 *   b.subject.isRestricted("user-9999");
 *   // → false
 */
function isRestricted(subjectId) {
  if (!subjectId) return false;
  var row = db().prepare(
    "SELECT 1 FROM _blamejs_subject_restrictions WHERE subjectIdHash = ?"
  ).get(_subjectHash(subjectId));
  return !!row;
}

// ---- Object (Art. 21) ----

/**
 * @primitive  b.subject.recordObjection
 * @signature  b.subject.recordObjection(subjectId, opts)
 * @since      0.1.0
 * @status     stable
 * @compliance gdpr
 * @related    b.subject.restrict
 *
 * GDPR Art. 21 (right to object). Records a structured audit event
 * (`subject.objection`) naming the processing purpose the subject is
 * objecting to plus an optional free-form reason. The framework does
 * not enforce the objection automatically — operators wire the
 * downstream consequence (suppress marketing send, exclude from
 * profiling, etc.) into their own pipeline. Leader-only.
 *
 * @opts
 *   purpose: string,   // e.g. "marketing", "profiling", "automated-decisioning"
 *   reason:  string,   // optional free-form ticket reference
 *
 * @example
 *   b.subject.recordObjection("user-4471", {
 *     purpose: "marketing",
 *     reason:  "GDPR Art. 21 opt-out ticket #7780",
 *   });
 *   // → true
 */
function recordObjection(subjectId, opts) {
  cluster.requireLeader();
  if (!subjectId) throw new Error("subject.recordObjection requires a subjectId");
  if (!opts || !opts.purpose) throw new Error("subject.recordObjection requires { purpose }");
  _writeAudit("subject.objection", subjectId, "success", {
    purpose: opts.purpose,
    reason:  opts.reason || null,
  });
  return true;
}

// ---- Internal helpers ----

function _markErased(subjectId) {
  db().prepare(
    "INSERT OR REPLACE INTO _blamejs_subject_erasures (subjectIdHash, erasedAt) VALUES (?, ?)"
  ).run(_subjectHash(subjectId), Date.now());
}

function _subjectHash(subjectId) {
  // Use the framework's email-style namespace; the consistent thing matters,
  // not which prefix. Subject IDs are typically opaque already.
  return sha3Hash("bj-subject:" + String(subjectId));
}

function _writeAudit(action, subjectId, outcome, metadata) {
  // recordSafe — audit failure must not roll back the subject
  // mutation that already touched the database. Hot-path audit
  // sinks are drop-silent: swallow any throw from audit.emit so a
  // misconfigured sink doesn't crash a partially-committed subject
  // mutation. Errors surface via the audit sink's own logger.
  try {
    audit.emit({
      actor:    {},
      action:   action,
      resource: { kind: "subject", id: subjectId },
      outcome:  outcome,
      reason:   metadata && metadata.requestReason ? metadata.requestReason : null,
      metadata: metadata || null,
    });
  } catch (_e) { /* drop-silent — audit emit failure must not block subject mutation */ }
}

function _resetForTest() { db.reset(); }

module.exports = {
  export:               exportData,
  exportData:           exportData,  // alias — `export` is a reserved word in some toolchains
  rectify:              rectify,
  erase:                erase,
  eraseHard:            eraseHard,
  restrict:             restrict,
  isRestricted:         isRestricted,
  recordObjection:      recordObjection,
  REQUIRED_ERASE_ACKS:  REQUIRED_ERASE_ACKS,
  _resetForTest:        _resetForTest,
};

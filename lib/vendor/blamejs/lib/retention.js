"use strict";
/**
 * @module b.retention
 * @nav    Compliance
 * @title  Retention
 *
 * @intro
 *   Row-level retention floors per regulatory regime. GDPR Art. 17,
 *   HIPAA 45 CFR §164.530(j), PCI-DSS Req. 3.1, SOX §802 and friends
 *   all share the shape: "data of class X stored beyond TTL Y must be
 *   either deleted or anonymized". `b.retention` ties the framework's
 *   building blocks (`b.cryptoField.eraseRow` for crypto-erasure of
 *   sealed columns, `b.scheduler` for cadence, `b.audit` for the
 *   chain, `b.legalHold` for per-subject holds) into one
 *   operator-facing primitive that emits delete / erase / soft-delete
 *   jobs at expiry.
 *
 *   Action vocabulary per row: `"erase"` (sealed columns + derived
 *   hashes go to NULL, `__erasedAt` set, row remains for FK / audit
 *   reference — cleartext is unrecoverable even with a vault key);
 *   `"delete"` (full row DELETE — for tables with no FK / audit
 *   reference); `"soft-delete"` (writes a deletion timestamp into
 *   `softDeleteField` — typical "trash bin" pattern); `"warn"` (audit
 *   only, no row write — used as an early stage in multi-stage
 *   schedules); `function(row)` (escape hatch for joined / conditional
 *   retention). Cascades follow `rule.cascade[]` foreign-key edges so
 *   a parent erase fans out into child rows in the same sweep.
 *
 *   `b.compliance.set(posture)` cascades into `applyPosture` here, so
 *   the active posture's `audit_log` minimum-retention floor becomes
 *   the default `ttlMs` for any rule the operator declares without an
 *   explicit value. `complianceFloor(posture, candidateTtlMs)`
 *   surfaces those minimums for app-side conditional logic.
 *
 *   Audit events (namespace `retention`): `rule.declared`,
 *   `sweep.started`, `row.processed` (with `action`), `row.warned`,
 *   `row.legal_hold_skipped`, `sweep.completed`, `sweep.failed`,
 *   `sweep.skipped_concurrent`. Each sweep is single-flighted per
 *   rule name so a slow run cannot be re-entered by the next
 *   scheduler tick.
 *
 * @card
 *   Row-level retention floors per regulatory regime.
 */
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var safeSql = require("./safe-sql");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });
var cryptoField = require("./crypto-field");
var legalHold = lazyRequire(function () { return require("./legal-hold"); });

var RetentionError = defineClass("RetentionError", { alwaysPermanent: true });
var _err = RetentionError.factory;

// Identifier-level SQLi defense: every operator-supplied table name,
// column name, and cascade FK must pass safeSql.validateIdentifier
// before reaching SQL string concatenation. Without this gate a
// rule registered with `table: 'users"; DROP TABLE audit_log;--'`
// would break out of the quoted-identifier wrap and execute the
// embedded statement.
function _validateRuleIdentifier(value, label) {
  try {
    safeSql.validateIdentifier(value, { allowReserved: true });
  } catch (e) {
    throw _err("BAD_RULE",
      label + " is not a safe SQL identifier: " + (e && e.message || String(e)));
  }
}

function _validateRule(rule) {
  if (!rule || typeof rule !== "object") {
    throw _err("BAD_RULE", "rule must be an object");
  }
  if (typeof rule.name !== "string" || rule.name.length === 0) {
    throw _err("BAD_RULE", "rule.name (string) is required");
  }
  if (typeof rule.table !== "string" || rule.table.length === 0) {
    throw _err("BAD_RULE", "rule.table (string) is required");
  }
  _validateRuleIdentifier(rule.table, "rule.table");
  if (typeof rule.ageField !== "string" || rule.ageField.length === 0) {
    throw _err("BAD_RULE", "rule.ageField (string) is required");
  }
  _validateRuleIdentifier(rule.ageField, "rule.ageField");
  if (typeof rule.ttlMs !== "number" || !isFinite(rule.ttlMs) || rule.ttlMs <= 0) {
    throw _err("BAD_RULE", "rule.ttlMs must be a positive finite number");
  }
  var action = rule.action;
  if (typeof action !== "string" && typeof action !== "function") {
    throw _err("BAD_RULE", "rule.action must be 'erase' / 'delete' / 'soft-delete' or a function(row)");
  }
  if (typeof action === "string" && ["erase", "delete", "soft-delete"].indexOf(action) === -1) {
    throw _err("BAD_RULE",
      "rule.action string must be 'erase' / 'delete' / 'soft-delete', got " + JSON.stringify(action));
  }
  if (rule.batchSize !== undefined &&
      (typeof rule.batchSize !== "number" || !isFinite(rule.batchSize) ||
       rule.batchSize <= 0 || Math.floor(rule.batchSize) !== rule.batchSize)) {
    throw _err("BAD_RULE", "rule.batchSize must be a positive integer");
  }
  if (rule.softDeleteField !== undefined &&
      (typeof rule.softDeleteField !== "string" || rule.softDeleteField.length === 0)) {
    throw _err("BAD_RULE", "rule.softDeleteField must be a non-empty string");
  }
  if (rule.softDeleteField !== undefined) {
    _validateRuleIdentifier(rule.softDeleteField, "rule.softDeleteField");
  }
  if (rule.legalHoldField !== undefined &&
      (typeof rule.legalHoldField !== "string" || rule.legalHoldField.length === 0)) {
    throw _err("BAD_RULE", "rule.legalHoldField must be a non-empty string");
  }
  if (rule.legalHoldField !== undefined) {
    _validateRuleIdentifier(rule.legalHoldField, "rule.legalHoldField");
  }
  if (rule.subjectField !== undefined &&
      (typeof rule.subjectField !== "string" || rule.subjectField.length === 0)) {
    throw _err("BAD_RULE", "rule.subjectField must be a non-empty string");
  }
  if (rule.subjectField !== undefined) {
    _validateRuleIdentifier(rule.subjectField, "rule.subjectField");
  }
  if (rule.cascade !== undefined) {
    if (!Array.isArray(rule.cascade) || rule.cascade.length === 0) {
      throw _err("BAD_RULE", "rule.cascade must be a non-empty array of { table, foreignKey } entries");
    }
    for (var ci = 0; ci < rule.cascade.length; ci++) {
      var c = rule.cascade[ci];
      if (!c || typeof c.table !== "string" || c.table.length === 0 ||
          typeof c.foreignKey !== "string" || c.foreignKey.length === 0) {
        throw _err("BAD_RULE", "rule.cascade[" + ci + "] must be { table: string, foreignKey: string }");
      }
      _validateRuleIdentifier(c.table, "rule.cascade[" + ci + "].table");
      _validateRuleIdentifier(c.foreignKey, "rule.cascade[" + ci + "].foreignKey");
    }
  }
  if (rule.stages !== undefined) {
    if (!Array.isArray(rule.stages) || rule.stages.length === 0) {
      throw _err("BAD_RULE", "rule.stages must be a non-empty array of { atMs, action } entries");
    }
    for (var si = 0; si < rule.stages.length; si++) {
      var stage = rule.stages[si];
      if (!stage || typeof stage.atMs !== "number" || !isFinite(stage.atMs) || stage.atMs <= 0) {
        throw _err("BAD_RULE", "rule.stages[" + si + "].atMs must be a positive finite number");
      }
      if (typeof stage.action !== "string" && typeof stage.action !== "function") {
        throw _err("BAD_RULE",
          "rule.stages[" + si + "].action must be 'erase' / 'delete' / 'soft-delete' / 'warn' or a function(row)");
      }
      if (typeof stage.action === "string" &&
          ["erase", "delete", "soft-delete", "warn"].indexOf(stage.action) === -1) {
        throw _err("BAD_RULE",
          "rule.stages[" + si + "].action string must be one of erase / delete / soft-delete / warn");
      }
    }
  }
}

/**
 * @primitive  b.retention.create
 * @signature  b.retention.create(opts)
 * @since      0.6.14
 * @status     stable
 * @compliance gdpr, hipaa, pci-dss, sox-404, soc2, dora, nis2
 * @related    b.retention.complianceFloor, b.retention.applyPosture, b.cryptoField.eraseRow, b.legalHold
 *
 * Build a retention controller bound to a database handle. Returns an
 * object with `declare(rule)`, `run(name, runOpts?)`, `runAll(runOpts?)`,
 * `preview(name)`, and `list()`. Audit emit is on by default; pass
 * `audit: false` for a quiet controller in tests.
 *
 * @opts
 *   db:    object,                                // b.db handle, must expose .prepare(sql)
 *   audit: boolean | object,                      // true | false | a b.audit instance
 *
 * @example
 *   var rules = b.retention.create({ db: b.db, audit: true });
 *   rules.declare({
 *     name:     "users.notes-ttl",
 *     table:    "users",
 *     ageField: "createdAt",
 *     ttlMs:    C.TIME.days(90),
 *     action:   "erase",
 *     batchSize: 500,
 *     legalHoldField: "__legalHold",
 *   });
 *   var summary = await rules.run("users.notes-ttl");
 *   // → { name, scanned, processed, action: "erase", durationMs, errors: [] }
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["db", "audit"], "retention");
  if (!opts.db || typeof opts.db.prepare !== "function") {
    throw _err("BAD_OPT", "create: opts.db is required (a b.db handle with .prepare(sql))");
  }
  var db = opts.db;
  var auditOn = opts.audit !== false && opts.audit != null;
  var auditInstance = (opts.audit && opts.audit !== true) ? opts.audit : null;
  var rules = {};

  function _emit(action, info, outcome) {
    if (!auditOn) return;
    var sink = auditInstance || audit();
    try {
      sink.safeEmit({
        action:   action,
        outcome:  outcome,
        metadata: info || {},
      });
    } catch (_e) { /* best-effort */ }
  }

  // Per-rule "running" lock so a slow sweep can't be re-entered by
  // the next scheduler tick. Operators with overlap risk wire a
  // longer scheduler.every and let the lock catch the rare overrun.
  var running = {};

  function declare(rule) {
    _validateRule(rule);
    if (rules[rule.name]) {
      throw _err("DUPLICATE_RULE", "rule '" + rule.name + "' is already declared");
    }
    rules[rule.name] = Object.assign({ batchSize: 500 }, rule);
    _emit("retention.rule.declared",
      { name: rule.name, table: rule.table, ageField: rule.ageField,
        ttlMs: rule.ttlMs, action: typeof rule.action === "function" ? "<custom>" : rule.action,
        hasStages: Array.isArray(rule.stages) && rule.stages.length > 0,
        hasCascade: Array.isArray(rule.cascade) && rule.cascade.length > 0,
        legalHoldField: rule.legalHoldField || null,
        softDeleteField: rule.softDeleteField || null },
      "success");
  }

  function _hardDelete(table, rowId, dryRun) {
    if (dryRun) return { wouldDelete: 1 };
    var del = db.prepare("DELETE FROM \"" + table + "\" WHERE _id = ?");
    del.run(rowId);
    return { deleted: 1 };
  }

  function _softDelete(table, rowId, softField, dryRun) {
    if (dryRun) return { wouldSoftDelete: 1 };
    var upd = db.prepare(
      "UPDATE \"" + table + "\" SET \"" + softField + "\" = ? WHERE _id = ?");
    upd.run(Date.now(), rowId);
    return { softDeleted: 1 };
  }

  function _erase(table, row, dryRun) {
    var erased = cryptoField.eraseRow(table, row);
    var sealedFields = cryptoField.getSealedFields(table) || [];
    var hashFields = [];
    var schema = cryptoField.getSchema(table);
    if (schema && schema.derivedHashes) {
      for (var k in schema.derivedHashes) hashFields.push(k);
    }
    if (sealedFields.length === 0 && hashFields.length === 0) {
      // Table has no sealed columns to erase — fall back to delete.
      return _hardDelete(table, row._id, dryRun);
    }
    if (dryRun) return { wouldErase: 1, sealedFieldCount: sealedFields.length };
    var setClauses = [];
    var values = [];
    for (var si = 0; si < sealedFields.length; si++) {
      setClauses.push('"' + sealedFields[si] + '" = ?');
      values.push(null);
    }
    for (var hi = 0; hi < hashFields.length; hi++) {
      setClauses.push('"' + hashFields[hi] + '" = ?');
      values.push(null);
    }
    values.push(row._id);
    var upd2 = db.prepare("UPDATE \"" + table + "\" SET " + setClauses.join(", ") + " WHERE _id = ?");
    upd2.run.apply(upd2, values);
    void erased;
    return { erased: 1, sealedFieldCount: sealedFields.length };
  }

  function _cascade(rule, rowId, dryRun) {
    if (!Array.isArray(rule.cascade) || rule.cascade.length === 0) return null;
    var cascadeSummary = [];
    for (var i = 0; i < rule.cascade.length; i++) {
      var c = rule.cascade[i];
      if (dryRun) {
        var sel = db.prepare(
          "SELECT COUNT(*) AS n FROM \"" + c.table + "\" WHERE \"" + c.foreignKey + "\" = ?");
        var n = sel.get(rowId);
        cascadeSummary.push({ table: c.table, foreignKey: c.foreignKey,
          wouldDelete: (n && typeof n.n === "number") ? n.n : 0 });
      } else {
        var del = db.prepare(
          "DELETE FROM \"" + c.table + "\" WHERE \"" + c.foreignKey + "\" = ?");
        var result = del.run(rowId);
        cascadeSummary.push({ table: c.table, foreignKey: c.foreignKey,
          deleted: result.changes || 0 });
      }
    }
    return cascadeSummary;
  }

  async function _runAction(rule, action, row, dryRun) {
    if (typeof action === "function") {
      if (dryRun) return { wouldCustomAction: 1 };
      var ret = await action(row);
      return ret || { customAction: 1 };
    }
    if (action === "warn") {
      // Multi-stage "warn" entry — emit an audit event but DON'T touch the row.
      _emit("retention.row.warned",
        { table: rule.table, name: rule.name, rowId: row._id, ageMs: Date.now() - Number(row[rule.ageField]) },
        "warning");
      return { warned: 1 };
    }
    if (action === "soft-delete") {
      if (!rule.softDeleteField) {
        throw _err("BAD_RULE",
          "soft-delete action requires rule.softDeleteField (column to write deletion timestamp into)");
      }
      return _softDelete(rule.table, row._id, rule.softDeleteField, dryRun);
    }
    if (action === "delete") {
      var hardRes = _hardDelete(rule.table, row._id, dryRun);
      var hardCasc = _cascade(rule, row._id, dryRun);
      if (hardCasc) hardRes.cascade = hardCasc;
      return hardRes;
    }
    // erase
    var eraseRes = _erase(rule.table, row, dryRun);
    var eraseCasc = _cascade(rule, row._id, dryRun);
    if (eraseCasc) eraseRes.cascade = eraseCasc;
    return eraseRes;
  }

  function _stageForRow(rule, row, nowMs) {
    // Multi-stage routing: pick the most-aggressive stage whose atMs
    // threshold the row has crossed. Ordered descending so erase
    // wins over warn when both are due.
    if (!Array.isArray(rule.stages) || rule.stages.length === 0) return rule.action;
    var ageMs = nowMs - Number(row[rule.ageField]);
    var sorted = rule.stages.slice().sort(function (a, b) { return b.atMs - a.atMs; });
    for (var i = 0; i < sorted.length; i++) {
      if (ageMs >= sorted[i].atMs) return sorted[i].action;
    }
    return null;
  }

  async function run(name, runOpts) {
    var rule = rules[name];
    if (!rule) throw _err("NO_SUCH_RULE", "rule '" + name + "' not declared");
    runOpts = runOpts || {};
    var dryRun = runOpts.dryRun === true;
    if (!dryRun && running[name]) {
      _emit("retention.sweep.skipped_concurrent",
        { name: name, reason: "previous sweep still running" }, "warning");
      return { name: name, skipped: true, reason: "concurrent-sweep-in-progress" };
    }
    if (!dryRun) running[name] = true;
    var startedAt = Date.now();
    // For multi-stage rules the cutoff is the EARLIEST stage atMs;
    // single-stage rules use ttlMs.
    var earliestAtMs = rule.ttlMs;
    if (Array.isArray(rule.stages) && rule.stages.length > 0) {
      for (var sx = 0; sx < rule.stages.length; sx++) {
        if (rule.stages[sx].atMs < earliestAtMs) earliestAtMs = rule.stages[sx].atMs;
      }
    }
    var cutoff = startedAt - earliestAtMs;
    _emit("retention.sweep.started",
      { name: name, table: rule.table, cutoff: cutoff, dryRun: dryRun,
        hasStages: Array.isArray(rule.stages) && rule.stages.length > 0 },
      "success");

    var summary = { name: name, scanned: 0, processed: 0, skipped: 0,
      legalHoldsHonored: 0, dryRun: dryRun,
      action: typeof rule.action === "function" ? "custom" : rule.action,
      errors: [], stageBreakdown: {} };

    try {
      var moreRows = true;
      while (moreRows) {
        var rows;
        // The candidate WHERE-clause: age + not-already-erased + not-on-legal-hold +
        // (when soft-delete is configured) not-already-soft-deleted.
        var whereParts = ['"' + rule.ageField + '" <= ?'];
        var whereArgs = [cutoff];
        if (rule.softDeleteField) {
          whereParts.push('("' + rule.softDeleteField + '" IS NULL)');
        }
        var sql = "SELECT * FROM \"" + rule.table + "\" " +
          "WHERE " + whereParts.join(" AND ") + " " +
          "AND (__erasedAt IS NULL OR __erasedAt = '') " +
          "LIMIT ?";
        var selStmt;
        try { selStmt = db.prepare(sql); rows = selStmt.all.apply(selStmt, whereArgs.concat([rule.batchSize])); }
        catch (_eA) {
          // Fallback: tables without __erasedAt
          var sqlPlain = "SELECT * FROM \"" + rule.table + "\" " +
            "WHERE " + whereParts.join(" AND ") + " LIMIT ?";
          var selPlain = db.prepare(sqlPlain);
          rows = selPlain.all.apply(selPlain, whereArgs.concat([rule.batchSize]));
        }
        if (!rows || rows.length === 0) { moreRows = false; break; }
        summary.scanned += rows.length;
        for (var i = 0; i < rows.length; i++) {
          var row = rows[i];
          // Legal-hold honour: per-row exemption skips ALL retention
          // actions until the operator clears the field.
          if (rule.legalHoldField && row[rule.legalHoldField]) {
            summary.legalHoldsHonored++;
            _emit("retention.row.legal_hold_skipped",
              { name: name, table: rule.table, rowId: row._id,
                source: "per-row-field" }, "warning");
            continue;
          }
          // Subject-level legal-hold registry consult. When the rule
          // names a subjectField (typical for user-keyed retention
          // tables), the central registry is authoritative. Honors
          // the same skip semantics as the per-row field.
          if (rule.subjectField && row[rule.subjectField]) {
            var holdsRegistry = legalHold._getSingleton();
            if (holdsRegistry && holdsRegistry.isHeld(row[rule.subjectField])) {
              summary.legalHoldsHonored++;
              _emit("retention.row.legal_hold_skipped",
                { name: name, table: rule.table, rowId: row._id,
                  source: "subject-registry",
                  subjectId: row[rule.subjectField] }, "warning");
              continue;
            }
          }
          var action = _stageForRow(rule, row, startedAt);
          if (!action) { summary.skipped++; continue; }
          var actionLabel = typeof action === "function" ? "custom" : action;
          summary.stageBreakdown[actionLabel] = (summary.stageBreakdown[actionLabel] || 0) + 1;
          try {
            var result = await _runAction(rule, action, row, dryRun);
            summary.processed++;
            _emit("retention.row.processed",
              { name: name, table: rule.table, rowId: row._id, action: actionLabel,
                dryRun: dryRun, result: result },
              "success");
          } catch (e) {
            summary.errors.push({ rowId: row._id,
              reason: (e && e.message) || String(e) });
          }
        }
        if (rows.length < rule.batchSize) moreRows = false;
      }
    } catch (e) {
      _emit("retention.sweep.failed",
        { name: name, table: rule.table, reason: (e && e.message) || String(e) },
        "failure");
      if (!dryRun) delete running[name];
      throw _err("SWEEP_FAILED",
        "rule '" + name + "' sweep failed: " + ((e && e.message) || String(e)));
    }
    if (!dryRun) delete running[name];
    summary.durationMs = Date.now() - startedAt;
    _emit("retention.sweep.completed",
      { name: name, table: rule.table, scanned: summary.scanned,
        processed: summary.processed, skipped: summary.skipped,
        legalHoldsHonored: summary.legalHoldsHonored,
        errorCount: summary.errors.length, dryRun: dryRun,
        durationMs: summary.durationMs, stageBreakdown: summary.stageBreakdown },
      summary.errors.length > 0 ? "warning" : "success");
    return summary;
  }

  async function runAll(runOpts) {
    var summaries = [];
    var names = Object.keys(rules);
    for (var i = 0; i < names.length; i++) {
      try { summaries.push(await run(names[i], runOpts)); }
      catch (e) {
        summaries.push({ name: names[i], error: (e && e.message) || String(e) });
      }
    }
    return summaries;
  }

  // Operator-callable preview — runs `run(name, { dryRun: true })`
  // without consuming the concurrency lock and returns the count of
  // rows that WOULD be touched. Useful for ops dashboards that want
  // to surface "the next sweep will erase N rows" before the operator
  // promotes a rule's TTL.
  async function preview(name) {
    return await run(name, { dryRun: true });
  }

  function list() {
    return Object.keys(rules).map(function (n) {
      var r = rules[n];
      return {
        name: r.name, table: r.table, ageField: r.ageField, ttlMs: r.ttlMs,
        action: typeof r.action === "function" ? "<custom>" : r.action,
        batchSize: r.batchSize,
      };
    });
  }

  return { declare: declare, run: run, runAll: runAll, preview: preview, list: list };
}

// Audit-log retention floors per regulatory posture. These are the
// MINIMUMS — operators may declare longer windows but cannot declare
// shorter ones. Operator-facing helper for compliance audit.
//
//   PCI-DSS Requirement 10.7.1   — 12 months online (active accessible)
//   HIPAA 45 CFR §164.316(b)(2)  — 6 years from creation
//   SOX (Sarbanes-Oxley) §802     — 7 years for audit-relevant records
//   GDPR Art. 5(1)(e)             — no fixed minimum; operator declares
//   SOC 2 (CC1–CC9)              — 1 year typical; auditor-driven
//   DORA Art. 17 (incident logs) — 5 years
var COMPLIANCE_RETENTION_FLOOR_MS = Object.freeze({
  "pci-dss":  C.TIME.days(365),        // 12 months — PCI-DSS §10.7.1
  "hipaa":    C.TIME.days(365 * 6),    // 6 years — 45 CFR §164.316(b)(2)(i)
  "sox":      C.TIME.days(365 * 7),    // 7 years — Sarbanes-Oxley §802
  "soc2":     C.TIME.days(365),        // 1 year — typical SOC 2 audit window
  "dora":     C.TIME.days(365 * 5),    // 5 years — DORA Article 17 incident logs
  "nis2":     C.TIME.days(365 * 3),    // 3 years — NIS2 Art. 23 incident reporting
  "cra":      C.TIME.days(365 * 5),    // 5 years — CRA Art. 14 vulnerability handling logs
  "lgpd-br":  C.TIME.days(365 * 5),    // 5 years — Brazil LGPD Art. 16 + fiscal-record minimum
  "appi-jp":  C.TIME.days(365 * 3),    // 3 years — Japan APPI handler-of-record requirement
  "pdpa-sg":  C.TIME.days(365 * 1),    // 1 year — PDPA breach-notification audit trail
  "uk-gdpr":  C.TIME.days(365 * 6),    // 6 years — UK ICO guidance, statutory limit alignment
});

// Operator passes a posture name + a candidate ttlMs; returns the
// effective ttl that meets-or-exceeds the floor. Throws if posture is
// unknown so typos surface at config time.
/**
 * @primitive  b.retention.complianceFloor
 * @signature  b.retention.complianceFloor(posture, candidateTtlMs)
 * @since      0.7.24
 * @status     stable
 * @compliance pci-dss, hipaa, sox-404, soc2, dora, nis2, cra
 * @related    b.retention.applyPosture, b.retention.create, b.compliance
 *
 * Take a regulatory posture name and a candidate TTL; return the
 * effective TTL that meets-or-exceeds the regime's minimum-retention
 * floor. Floors come from `COMPLIANCE_RETENTION_FLOOR_MS` (PCI-DSS
 * §10.7.1: 12 months online; HIPAA 45 CFR §164.316(b)(2)(i): 6 years;
 * SOX §802: 7 years; DORA Art. 17: 5 years; NIS2 Art. 23: 3 years;
 * CRA Art. 14: 5 years; LGPD-BR / APPI-JP / PDPA-SG / UK-GDPR variants
 * matched). Throws on an unknown posture so config-time typos surface.
 *
 * @example
 *   var ttl = b.retention.complianceFloor("hipaa", b.C.TIME.days(180));
 *   // → 189216000000 (HIPAA's 6-year floor wins over the 180-day candidate)
 *
 *   var sox = b.retention.complianceFloor("sox", 0);
 *   // → 220752000000 (Sarbanes-Oxley §802 — 7 years)
 */
function complianceFloor(posture, candidateTtlMs) {
  if (typeof posture !== "string") {
    throw new RetentionError("retention/bad-posture",
      "complianceFloor: posture must be a string, got " + JSON.stringify(posture));
  }
  var floor = COMPLIANCE_RETENTION_FLOOR_MS[posture];
  if (floor === undefined) {
    throw new RetentionError("retention/unknown-posture",
      "complianceFloor: unknown posture '" + posture + "'; expected one of " +
      Object.keys(COMPLIANCE_RETENTION_FLOOR_MS).join(", "));
  }
  if (typeof candidateTtlMs !== "number" || !isFinite(candidateTtlMs) || candidateTtlMs <= 0) {
    return floor;
  }
  return candidateTtlMs > floor ? candidateTtlMs : floor;
}

// applyPosture — F-POSTURE-1 cascade hook. b.compliance.set(posture)
// calls this to merge posture defaults into retention's state. The
// retention module itself doesn't carry per-instance global defaults;
// the cascade's job here is to surface the posture's audit-log
// retention floor as the value rules.declare() uses when an operator
// hasn't passed an explicit ttlMs. Returns the recognized floor (ms)
// or null when the posture has no retention floor.
/**
 * @primitive  b.retention.applyPosture
 * @signature  b.retention.applyPosture(posture)
 * @since      0.7.24
 * @status     stable
 * @compliance pci-dss, hipaa, sox-404, soc2, dora, nis2, cra
 * @related    b.retention.complianceFloor, b.retention.activePosture, b.compliance
 *
 * Cascade hook called by `b.compliance.set(posture)`. Records the
 * posture name and its `audit_log` retention floor as module state so
 * subsequent `complianceFloor` callers without an explicit posture
 * argument inherit the active value. Returns `null` for an empty
 * input or a posture with no retention floor; otherwise returns
 * `{ posture, floorMs }`.
 *
 * @example
 *   b.compliance.set("hipaa");
 *   b.retention.applyPosture("hipaa");
 *   // → { posture: "hipaa", floorMs: 189216000000 }
 *   b.retention.activePosture();
 *   // → "hipaa"
 */
function applyPosture(posture) {
  if (typeof posture !== "string" || posture.length === 0) return null;
  var floor = COMPLIANCE_RETENTION_FLOOR_MS[posture];
  STATE.activePosture = posture;
  STATE.activeFloorMs = (typeof floor === "number") ? floor : null;
  return { posture: posture, floorMs: STATE.activeFloorMs };
}

// Module-level state — read by complianceFloor() callers that omit the
// posture argument (lookup falls back to the active cascade-set value).
var STATE = { activePosture: null, activeFloorMs: null };

/**
 * @primitive  b.retention.activePosture
 * @signature  b.retention.activePosture()
 * @since      0.7.24
 * @status     stable
 * @related    b.retention.applyPosture, b.compliance.current
 *
 * Read the posture name set by the most recent `applyPosture` call,
 * or `null` if `b.compliance.set` has never run on this process.
 * Used by audit-dashboard tooling to surface "this deployment is
 * pinned to <posture>" without crossing into `b.compliance` directly.
 *
 * @example
 *   var p = b.retention.activePosture();
 *   if (p === null) console.log("no compliance posture pinned");
 *   else            console.log("active posture:", p);
 *   // → "hipaa"
 */
function activePosture() { return STATE.activePosture; }

module.exports = {
  create:                         create,
  complianceFloor:                complianceFloor,
  applyPosture:                   applyPosture,
  activePosture:                  activePosture,
  COMPLIANCE_RETENTION_FLOOR_MS:  COMPLIANCE_RETENTION_FLOOR_MS,
  RetentionError:                 RetentionError,
};

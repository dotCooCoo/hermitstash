// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var { Readable } = require("node:stream");
var C = require("./constants");
var codepointClass = require("./codepoint-class");
var cryptoField = require("./crypto-field");
var { generateToken } = require("./crypto");
var safeJson = require("./safe-json");
var safeJsonPath = require("./safe-jsonpath");
var safeSql = require("./safe-sql");
var sql = require("./sql");
var audit = require("./audit");
var lazyRequire = require("./lazy-require");
var { DbQueryError } = require("./framework-error");
var numericBounds = require("./numeric-bounds");

// Circular load — db.js requires db-query at module scope, so the
// residency gate reaches back for getDataResidency() lazily.
var db = lazyRequire(function () { return require("./db"); });

function _postureState() {
  try {
    var compliance = require("./compliance");                                     // allow:inline-require — defensive against optional load
    var posture = compliance.current();
    return { posture: posture, regulated: compliance.isCrossBorderRegulated(posture) };
  } catch (_e) { return { posture: null, regulated: false }; }
}

// Unregulated postures audit (drop-silent) and pass; tables with no
function _ciColumn(row, col) {
  if (Object.prototype.hasOwnProperty.call(row, col)) return { present: true, value: row[col] };
  var lc = String(col).toLowerCase();
  var keys = Object.keys(row);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === lc) return { present: true, value: row[keys[i]] };
  }
  return { present: false, value: undefined };
}

function _assertLocalResidency(table, plaintextRow, op) {
  var spec = cryptoField.getPerRowResidency(table);
  var colMap = cryptoField.getColumnResidency(table);
  if (!spec && !colMap) return;

  var residency = null;
  try { residency = db().getDataResidency(); } catch (_e) { residency = null; }
  var region = residency && residency.region ? residency.region : null;
  var allowedRegions = region
    ? [region].concat(Array.isArray(residency.allowedStorageRegions)
        ? residency.allowedStorageRegions : [])
    : null;
  var state = _postureState();
  var posture = state.posture;
  var regulated = state.regulated;

  if (spec) {
    var resolved = _ciColumn(plaintextRow, spec.residencyColumn);
    var tag = resolved.value;
    var tagPresent = tag !== undefined && tag !== null;
    var colInChangeSet = resolved.present;
    if (op === "insert" && !tagPresent) {
      throw new DbQueryError("db-query/row-residency-tag-missing",
        op + ": table '" + table + "' declares per-row residency on column '" +
        spec.residencyColumn + "' — every inserted row must carry a tag from [" +
        spec.allowedTags.join(", ") + "]", true);
    }
    if (op === "update" && colInChangeSet && !tagPresent) {
      throw new DbQueryError("db-query/row-residency-tag-missing",
        op + ": table '" + table + "' residency column '" + spec.residencyColumn +
        "' cannot be cleared — set a tag from [" + spec.allowedTags.join(", ") + "]", true);
    }
    if (tagPresent) {
      if (typeof tag !== "string" || spec.allowedTags.indexOf(tag) === -1) {
        throw new DbQueryError("db-query/row-residency-tag-invalid",
          op + ": table '" + table + "' residency tag '" + tag +
          "' is not in allowedTags [" + spec.allowedTags.join(", ") + "]", true);
      }
      if (tag !== "global" && tag !== "unrestricted" && allowedRegions &&
          allowedRegions.indexOf(tag) === -1) {
        if (regulated) {
          audit.safeEmit({ action: "db.residency.gate.rejected", outcome: "denied",
            metadata: { table: table, rowTag: tag, region: region, posture: posture,
                        operation: op, scope: "local" } });
          throw new DbQueryError("db-query/row-residency-local-mismatch",
            op + ": row residency tag '" + tag + "' is outside this deployment's " +
            "region set [" + allowedRegions.join(", ") + "] under '" + posture +
            "' posture (cross-border transfer refused)", true);
        }
        audit.safeEmit({ action: "db.residency.gate.advisory", outcome: "info",
          metadata: { table: table, rowTag: tag, region: region, posture: posture || null,
                      operation: op, scope: "local" } });
      }
    }
  }

  if (colMap && region) {
    var refusal = cryptoField.assertColumnResidency(table, plaintextRow, { backendTag: region });
    if (refusal) {
      if (regulated) {
        audit.safeEmit({ action: "db.column_residency.gate.rejected", outcome: "denied",
          metadata: { table: refusal.table, column: refusal.column, want: refusal.want,
                      got: refusal.got, posture: posture, operation: op, scope: "local" } });
        throw new DbQueryError("db-query/column-residency-mismatch",
          op + ": column '" + refusal.column + "' on table '" + refusal.table +
          "' is bound to residency '" + refusal.want + "' but this deployment's " +
          "region is '" + refusal.got + "' under '" + posture + "' posture", true);
      }
      audit.safeEmit({ action: "db.residency.gate.advisory", outcome: "info",
        metadata: { table: refusal.table, column: refusal.column, want: refusal.want,
                    got: refusal.got, posture: posture || null, operation: op, scope: "local" } });
    }
  }
}

var ALLOWED_OPS = new Set([
  "=", "!=", "<>", "<", "<=", ">", ">=", "IS", "IS NOT", "LIKE", "IN",
  "@>", "?", "?|", "?&",
]);
var JSONB_CONTAINMENT_OPS = new Set(["@>"]);
var JSONB_KEY_OPS         = new Set(["?", "?|", "?&"]);

class Query {
  constructor(database, tableName, opts) {
    if (typeof tableName !== "string") {
      throw new TypeError("Query: tableName must be a string, got " + typeof tableName);
    }
    var schema = null;
    var table  = tableName;
    if (tableName.indexOf(".") !== -1) {
      var parts = tableName.split(".");
      if (parts.length !== 2 || parts[0].length === 0 || parts[1].length === 0) {
        throw new Error("Query: schema-qualified tableName must be exactly " +
          "'schema.table' (got '" + tableName + "'). Three-part identifiers " +
          "(catalog.schema.table) and empty parts are not supported.");
      }
      schema = parts[0];
      table  = parts[1];
      safeSql.validateIdentifier(schema, { allowReserved: true });
    }
    safeSql.validateIdentifier(table, { allowReserved: true });

    this._db            = database;
    this._schema        = schema;
    this._table         = table;
    this._qualifiedKey  = schema ? schema + "." + table : table;
    this._conditions    = [];
    this._select        = null;
    this._orderBy       = null;
    this._limit         = null;
    this._offset        = null;

    opts = opts || {};
    this._declaredColumns = (opts.declaredColumns instanceof Set) ? opts.declaredColumns
      : (Array.isArray(opts.declaredColumns) ? new Set(opts.declaredColumns) : null);
    this._columnGateMode  = opts.columnGateMode || "reject";
    this._allowedColumns  = null;
    if (opts.primaryKey !== undefined && opts.primaryKey !== null) {
      safeSql.validateIdentifier(opts.primaryKey, { allowReserved: true });
      this._primaryKey = opts.primaryKey;
    } else {
      this._primaryKey = null;
    }
  }

  allowedColumns(cols) {
    if (!Array.isArray(cols) || cols.length === 0) {
      throw new TypeError("allowedColumns(cols): expected a non-empty array of column names");
    }
    cols.forEach(_validateField);
    this._allowedColumns = new Set(cols);
    return this;
  }

  // throws | "warn" drop-silent audits + allows | "off" / no declared
  _assertColumnMember(field, where) {
    if (this._allowedColumns && !this._allowedColumns.has(field)) {
      throw new Error("column '" + field + "' is not in the allowedColumns() set" +
        (where ? " (" + where + ")" : ""));
    }
    if (this._declaredColumns === null || this._columnGateMode === "off") return;
    if (this._declaredColumns.has(field)) return;
    if (this._columnGateMode === "warn") {
      try {
        audit.safeEmit({
          action:   "db.query.unknown_column",
          outcome:  "failure",
          metadata: { table: this._qualifiedKey, column: field, where: where || null },
        });
      } catch (_e) { /* drop-silent — observability sink, by design */ }
      return;
    }
    throw new Error("column '" + field + "' is not a declared column of '" +
      this._qualifiedKey + "'" + (where ? " (" + where + ")" : "") +
      ". Declared columns: " + Array.from(this._declaredColumns).join(", ") +
      ". Use .allowedColumns([...]) or db.init({ columnGate: 'off' }) to bypass.");
  }

  _dialect() {
    var d = this._db && this._db.dialect;
    if (d === "postgres" || d === "mysql" || d === "sqlite") return d;
    return "sqlite";
  }

  _sqlOpts() {
    return this._schema
      ? { dialect: this._dialect(), schema: this._schema, quoteName: true }
      : { dialect: this._dialect(), quoteName: true };
  }

  _hasConditions() {
    return this._conditions.length > 0;
  }

  _applyConditions(builder) {
    if (this._conditions.length === 0) return builder;
    var conds = this._conditions;
    builder.whereGroup(function (pred) {
      for (var i = 0; i < conds.length; i++) {
        conds[i].apply(pred);
      }
    });
    return builder;
  }

  where(fieldOrObj, op, value) {
    if (fieldOrObj && typeof fieldOrObj === "object") {
      for (var k in fieldOrObj) {
        this._addCondition(k, "=", fieldOrObj[k]);
      }
      return this;
    }
    if (arguments.length === 2) {
      return this._addCondition(fieldOrObj, "=", op);
    }
    return this._addCondition(fieldOrObj, op, value);
  }

  whereIn(field, values) {
    return this.where(field, "IN", values);
  }

  whereNull(field) {
    return this.where(field, "IS", null);
  }
  whereNotNull(field) {
    return this.where(field, "IS NOT", null);
  }

  _resolvePredicate(field, op, value) {
    if (!ALLOWED_OPS.has(op)) {
      throw new Error("invalid where operator: " + op);
    }
    if (JSONB_CONTAINMENT_OPS.has(op)) {
      if (typeof value === "string") {
        var parsed;
        try { parsed = safeJson.parse(value); }
        catch (e) {
          throw new Error("where '" + op + "' value: invalid JSON string: " +
            ((e && e.message) || String(e)));
        }
        safeJsonPath.validateContainment(parsed);
      } else {
        safeJsonPath.validateContainment(value);
        value = JSON.stringify(value);
      }
    }
    if (JSONB_KEY_OPS.has(op)) {
      if (op === "?") {
        if (typeof value !== "string") {
          throw new Error("where '?' requires a string key (got " + (typeof value) + ")");
        }
        safeJsonPath.validateKey(value);
      } else {
        if (!Array.isArray(value) || value.length === 0) {
          throw new Error("where '" + op + "' requires a non-empty array of string keys");
        }
        for (var ki = 0; ki < value.length; ki++) {
          safeJsonPath.validateKey(value[ki]);
        }
      }
    }
    if (this._isSealedField(field)) {
      var missingHashMsg =
        "cannot query sealed column '" + this._cryptoFieldKey() + "." + field +
        "' without a derived hash. Declare derivedHashes: { <name>: { from: '" + field + "' } } " +
        "in the table's schema config.";
      if (op === "IN") {
        if (!Array.isArray(value) || value.length === 0) {
          throw new Error("where IN on sealed column '" + this._cryptoFieldKey() +
            "." + field + "' requires a non-empty array of values");
        }
        var sealedField = null;
        var hashedValues = [];
        for (var inI = 0; inI < value.length; inI++) {
          var elemLookup = cryptoField.lookupHash(this._cryptoFieldKey(), field, value[inI]);
          if (!elemLookup) throw new Error(missingHashMsg);
          sealedField = elemLookup.field;
          hashedValues.push(elemLookup.value);
          if (elemLookup.legacyValue != null && elemLookup.legacyValue !== elemLookup.value) {
            hashedValues.push(elemLookup.legacyValue);
          }
        }
        field = sealedField;
        value = hashedValues;
      } else {
        var lookup = cryptoField.lookupHash(this._cryptoFieldKey(), field, value);
        if (!lookup) throw new Error(missingHashMsg);
        field = lookup.field;
        if (op === "=" && lookup.legacyValue != null && lookup.legacyValue !== lookup.value) {
          op = "IN";
          value = [lookup.value, lookup.legacyValue];
        } else {
          value = lookup.value;
        }
      }
    }
    _validateField(field);
    this._assertColumnMember(field, "where");
    if (op === "IN") {
      if (!Array.isArray(value) || value.length === 0) {
        throw new Error("where IN requires a non-empty array of values");
      }
    }
    return { field: field, op: op, value: value };
  }

  _emitPredicate(pred, joiner, field, op, value) {
    if (op === "IN") {
      if (joiner === "OR") pred.orWhereIn(field, value);
      else pred.whereIn(field, value);
      return;
    }
    if (joiner === "OR") pred.orWhereOp(field, op, value);
    else pred.whereOp(field, op, value);
  }

  _addCondition(field, op, value) {
    var resolved = this._resolvePredicate(field, op, value);
    var self = this;
    this._pushLeaf("AND", function (pred) {
      self._emitPredicate(pred, "AND", resolved.field, resolved.op, resolved.value);
    });
    return this;
  }

  _pushLeaf(joiner, apply) {
    this._conditions.push({ joiner: joiner, apply: apply });
  }

  _isSealedField(field) {
    var sealed = cryptoField.getSealedFields(this._cryptoFieldKey());
    return sealed.indexOf(field) !== -1;
  }

  _cryptoFieldKey() {
    if (!this._schema) return this._table;
    if (cryptoField.getSealedFields(this._qualifiedKey).length > 0) {
      return this._qualifiedKey;
    }
    return this._table;
  }

  whereRaw(sql_, params, opts) {
    if (typeof sql_ !== "string" || sql_.length === 0) {
      throw new Error("whereRaw: sql must be a non-empty string");
    }
    var p = Array.isArray(params) ? params.slice() : (params == null ? [] : [params]);
    if (!(opts && opts.allowLiterals === true)) _assertRawNoStringLiteral(sql_, "whereRaw");
    var holders = safeSql.countPlaceholders(sql_);
    if (holders !== p.length) {
      throw new Error("whereRaw: " + holders + " placeholder(s) in sql but " +
        p.length + " param(s) supplied");
    }
    this._pushLeaf("AND", function (pred) {
      pred.whereRaw(sql_, p, opts);
    });
    return this;
  }

  select(columns) {
    if (!Array.isArray(columns)) {
      throw new Error("select() expects an array of column names");
    }
    columns.forEach(_validateField);
    var self = this;
    columns.forEach(function (c) { self._assertColumnMember(c, "select"); });
    this._select = columns.slice();
    return this;
  }

  orderBy(field, direction) {
    _validateField(field);
    this._assertColumnMember(field, "orderBy");
    direction = (direction || "asc").toLowerCase();
    if (direction !== "asc" && direction !== "desc") {
      throw new Error("orderBy direction must be 'asc' or 'desc'");
    }
    var entry = { field: field, direction: direction.toUpperCase() };
    if (this._orderBy === null) {
      this._orderBy = entry;
      return this;
    }
    if (Array.isArray(this._orderBy)) {
      this._orderBy.push(entry);
    } else {
      this._orderBy = [this._orderBy, entry];
    }
    return this;
  }

  limit(n) {
    if (!Number.isInteger(n) || n < 0) throw new Error("limit must be a non-negative integer");
    this._limit = n;
    return this;
  }

  offset(n) {
    if (!Number.isInteger(n) || n < 0) throw new Error("offset must be a non-negative integer");
    this._offset = n;
    return this;
  }

  _applySelectClauses(qb) {
    if (this._select) qb.columns(this._select);
    if (this._orderBy) {
      var entries = Array.isArray(this._orderBy) ? this._orderBy : [this._orderBy];
      for (var i = 0; i < entries.length; i++) {
        qb.orderBy(entries[i].field, entries[i].direction === "DESC" ? "desc" : "asc");
      }
    }
    if (this._limit !== null)  qb.limit(this._limit);
    if (this._offset !== null) qb.offset(this._offset);
    return qb;
  }

  first() {
    var qb = sql.select(this._table, this._sqlOpts());
    this._applyConditions(qb);
    this._applySelectClauses(qb);
    qb.limit(1);
    var built = qb.toSql();
    var stmt = this._db.prepare(built.sql);
    var row = stmt.get.apply(stmt, built.params);
    return row ? cryptoField.unsealRow(this._cryptoFieldKey(), row, undefined, this._db) : null;
  }

  all() {
    var qb = sql.select(this._table, this._sqlOpts());
    this._applyConditions(qb);
    this._applySelectClauses(qb);
    var built = qb.toSql();
    var stmt = this._db.prepare(built.sql);
    var rows = stmt.all.apply(stmt, built.params);
    var out = new Array(rows.length);
    var key = this._cryptoFieldKey();
    var dbHandle = this._db;
    for (var i = 0; i < rows.length; i++) {
      out[i] = cryptoField.unsealRow(key, rows[i], undefined, dbHandle);
    }
    return out;
  }

  stream(opts) {
    var qb = sql.select(this._table, this._sqlOpts());
    this._applyConditions(qb);
    this._applySelectClauses(qb);
    var built = qb.toSql();
    var perCallLimit;
    var dbModule = require("./db");                                                                    // allow:inline-require — circular-load defense (db imports db-query)
    perCallLimit = dbModule.getStreamLimit();
    if (opts && opts.streamLimit !== undefined) {
      numericBounds.requirePositiveFiniteIntIfPresent(opts.streamLimit,
        "Query.stream: opts.streamLimit", DbQueryError, "db-query/bad-stream-limit");
      perCallLimit = opts.streamLimit;
    }
    var stmt = this._db.prepare(built.sql);
    var key = this._cryptoFieldKey();
    var dbHandle = this._db;
    var iter;
    try { iter = stmt.iterate.apply(stmt, built.params); }
    catch (e) {
      var r = new Readable({ objectMode: true, read: function () {} });
      setImmediate(function () { r.destroy(e); });
      return r;
    }
    var emitted = 0;
    return new Readable({
      objectMode: true,
      read: function () {
        try {
          if (emitted >= perCallLimit) {
            this.destroy(new Error("Query.stream: emitted " + emitted +
              " rows, exceeding streamLimit " + perCallLimit +
              ". Pass opts.streamLimit higher OR raise via db.init({ streamLimit })."));
            return;
          }
          var step = iter.next();
          if (step.done) { this.push(null); return; }
          emitted += 1;
          this.push(cryptoField.unsealRow(key, step.value, undefined, dbHandle));
        } catch (e) {
          this.destroy(e);
        }
      },
    });
  }

  count() {
    var qb = sql.select(this._table, this._sqlOpts()).count("*", "n");
    this._applyConditions(qb);
    var built = qb.toSql();
    var stmt = this._db.prepare(built.sql);
    var row = stmt.get.apply(stmt, built.params);
    return row ? row.n : 0;
  }

  insertOne(row) {
    if (!row || typeof row !== "object") {
      throw new Error("insertOne requires a row object");
    }
    var withId = Object.assign({}, row);
    if (withId._id === undefined || withId._id === null) {
      withId._id = generateToken(C.BYTES.bytes(16));
    }
    _assertLocalResidency(this._cryptoFieldKey(), withId, "insert");
    var sealOpts;
    var cfKey = this._cryptoFieldKey();
    if (cryptoField.hasPerRowKey(cfKey)) {
      var kRow = cryptoField.materializePerRowKey(cfKey, withId._id, this._db);
      sealOpts = { kRow: kRow, rowId: withId._id };
    }
    var sealed = cryptoField.sealRow(cfKey, withId, sealOpts);
    var built = sql.insert(this._table, this._sqlOpts()).values(sealed).toSql();
    var insertStmt = this._db.prepare(built.sql);
    insertStmt.run.apply(insertStmt, built.params);
    return Object.assign({}, withId);
  }

  insertMany(rows) {
    if (!Array.isArray(rows)) throw new Error("insertMany expects an array");
    var out = new Array(rows.length);
    for (var i = 0; i < rows.length; i++) {
      out[i] = this.insertOne(rows[i]);
    }
    return out;
  }

  updateOne(changes) {
    var n = this._update(changes, true);
    return n > 0;
  }

  updateMany(changes) {
    return this._update(changes, false);
  }

  _update(changes, single) {
    if (!changes || typeof changes !== "object") {
      throw new Error("update requires a changes object");
    }
    if (!this._hasConditions()) {
      throw new Error("refusing unconditional update — call where(...) first");
    }
    _assertLocalResidency(this._cryptoFieldKey(), changes, "update");
    var cfKey = this._cryptoFieldKey();
    if (cryptoField.hasPerRowKey(cfKey)) {
      return this._updatePerRowKey(cfKey, changes, single);
    }
    var sealed = cryptoField.sealRow(cfKey, changes);
    var setKeys = Object.keys(sealed);
    if (setKeys.length === 0) {
      throw new Error("update changes object is empty");
    }
    setKeys.forEach(_validateField);
    var selfUpd = this;
    setKeys.forEach(function (k) { selfUpd._assertColumnMember(k, "update"); });

    var built;
    if (single) {
      built = this._buildSingleRowWrite(sealed);
      if (built === null) return 0;
    } else {
      var qb = sql.update(this._table, this._sqlOpts()).set(sealed);
      this._applyConditions(qb);
      built = qb.toSql();
    }
    var updStmt = this._db.prepare(built.sql);
    var info = updStmt.run.apply(updStmt, built.params);
    return info.changes;
  }

  _rowLocatorColumn(dialect) {
    return dialect === "sqlite" ? "rowid" : this._pkColumn();
  }

  _pkColumn() {
    return this._primaryKey || "_id";
  }

  _buildSingleRowWrite(sealed) {
    if (this._dialect() === "mysql") {
      var pkVal = this._resolveSinglePk();
      if (pkVal === null) return null;
      return sql.update(this._table, this._sqlOpts())
        .set(sealed)
        .where(this._pkColumn(), pkVal)
        .toSql();
    }
    var col = this._rowLocatorColumn(this._dialect());
    var inner = sql.select(this._table, this._sqlOpts()).columns([col]);
    this._applyConditions(inner);
    inner.limit(1);
    return sql.update(this._table, this._sqlOpts())
      .set(sealed)
      .whereSub(col, "=", inner)
      .toSql();
  }

  _resolveSinglePk() {
    var pk = this._pkColumn();
    var pick = sql.select(this._table, this._sqlOpts()).columns([pk]);
    this._applyConditions(pick);
    pick.limit(1);
    var built = pick.toSql();
    var stmt = this._db.prepare(built.sql);
    var row = stmt.get.apply(stmt, built.params);
    if (!row) return null;
    var v = row[pk];
    return (v === undefined || v === null) ? null : v;
  }

  _updatePerRowKey(cfKey, changes, single) {
    var idSelect = sql.select(this._table, this._sqlOpts()).columns(["_id"]);
    this._applyConditions(idSelect);
    if (single) idSelect.limit(1);
    var idBuilt = idSelect.toSql();
    var idStmt = this._db.prepare(idBuilt.sql);
    var idRows = idStmt.all.apply(idStmt, idBuilt.params);
    var changed = 0;
    for (var r = 0; r < idRows.length; r++) {
      var rowId = idRows[r]._id;
      if (rowId === undefined || rowId === null) continue;
      var kRow = cryptoField.materializePerRowKey(cfKey, rowId, this._db);
      var sealed = cryptoField.sealRow(cfKey, changes, { kRow: kRow, rowId: rowId });
      var setKeys = Object.keys(sealed);
      if (setKeys.length === 0) {
        throw new Error("update changes object is empty");
      }
      setKeys.forEach(_validateField);
      var selfUpd = this;
      setKeys.forEach(function (k) { selfUpd._assertColumnMember(k, "update"); });
      var built = sql.update(this._table, this._sqlOpts())
        .set(sealed).where("_id", rowId).toSql();
      var updStmt = this._db.prepare(built.sql);
      var info = updStmt.run.apply(updStmt, built.params);
      changed += (info && info.changes) || 0;
    }
    return changed;
  }

  deleteOne() {
    return this._delete(true) > 0;
  }

  deleteMany() {
    return this._delete(false);
  }

  increment(column, delta) {
    if (typeof column !== "string" || column.length === 0) {
      throw new Error("increment(column, delta): column must be a non-empty string");
    }
    _validateField(column);
    this._assertColumnMember(column, "increment");
    if (delta === undefined) delta = 1;
    if (typeof delta !== "number" || !Number.isFinite(delta) || !Number.isInteger(delta)) {
      throw new Error("increment(column, delta): delta must be a finite integer (default 1)");
    }
    if (!this._hasConditions()) {
      throw new Error("refusing unconditional increment — call where(...) first");
    }
    var qc = safeSql.quoteIdentifier(column, this._dialect(), { allowReserved: true });
    var qb = sql.update(this._table, this._sqlOpts())
      .setRaw(column, "COALESCE(" + qc + ", 0) + ?", [delta]);
    this._applyConditions(qb);
    var built = qb.toSql();
    var stmt = this._db.prepare(built.sql);
    var info = stmt.run.apply(stmt, built.params);
    return info.changes;
  }

  whereGroup(closure) {
    if (typeof closure !== "function") {
      throw new Error("whereGroup(closure): expected function (qb) => ...");
    }
    var sub = new WhereBuilder(this);
    closure(sub);
    if (sub._parts.length === 0) return this;
    this._pushLeaf("AND", function (pred) {
      pred.whereGroup(function (g) { sub.replay(g); });
    });
    return this;
  }

  orWhere(fieldOrObjOrFn, op, value) {
    if (this._conditions.length === 0) {
      throw new Error("orWhere(...): no prior where(...) — start the chain with where(...)");
    }
    var argc = arguments.length;
    var prevLeaf = this._conditions.pop();
    var orApply;
    if (typeof fieldOrObjOrFn === "function") {
      var sub = new WhereBuilder(this);
      fieldOrObjOrFn(sub);
      if (sub._parts.length === 0) {
        this._conditions.push(prevLeaf);
        return this;
      }
      orApply = function (pred) {
        pred.orWhereGroup(function (g) { sub.replay(g); });
      };
    } else if (fieldOrObjOrFn !== null && typeof fieldOrObjOrFn === "object" &&
               !Array.isArray(fieldOrObjOrFn)) {
      var self = this;
      var resolvedList = Object.keys(fieldOrObjOrFn).map(function (k) {
        return self._resolvePredicate(k, "=", fieldOrObjOrFn[k]);
      });
      orApply = function (pred) {
        pred.orWhereGroup(function (g) {
          for (var i = 0; i < resolvedList.length; i++) {
            self._emitPredicate(g, "AND", resolvedList[i].field, resolvedList[i].op,
              resolvedList[i].value);
          }
        });
      };
    } else {
      var resolved = (argc === 2)
        ? this._resolvePredicate(fieldOrObjOrFn, "=", op)
        : this._resolvePredicate(fieldOrObjOrFn, op, value);
      var selfP = this;
      orApply = function (pred) {
        selfP._emitPredicate(pred, "OR", resolved.field, resolved.op, resolved.value);
      };
    }
    this._pushLeaf("AND", function (pred) {
      pred.whereGroup(function (g) {
        prevLeaf.apply(g);
        orApply(g);
      });
    });
    return this;
  }

  search(fields, term, opts) {
    if (!Array.isArray(fields) || fields.length === 0) {
      throw new Error("search(fields, term): fields must be a non-empty array of column names");
    }
    fields.forEach(_validateField);
    var selfS = this;
    fields.forEach(function (f) { selfS._assertColumnMember(f, "search"); });
    if (term === undefined || term === null) return this;
    if (typeof term !== "string") {
      throw new Error("search(fields, term): term must be a string");
    }
    if (term.length === 0) return this;
    var match = (opts && opts.match) || "substring";
    if (match !== "exact" && match !== "prefix" && match !== "substring") {
      throw new Error("search: opts.match must be 'substring' | 'prefix' | 'exact'");
    }
    var fieldList = fields.slice();
    this._pushLeaf("AND", function (pred) {
      pred.whereGroup(function (g) {
        for (var i = 0; i < fieldList.length; i++) {
          if (i === 0) g.whereLike(fieldList[i], term, match);
          else g.orWhereLike(fieldList[i], term, match);
        }
      });
    });
    return this;
  }

  paginate(opts) {
    opts = opts || {};
    var limit = opts.limit === undefined ? 25 : opts.limit;
    var offset = opts.offset === undefined ? 0 : opts.offset;
    if (!Number.isInteger(limit) || limit <= 0 || limit > 1000) {
      throw new Error("paginate: limit must be a positive integer ≤ 1000 (default 25)");
    }
    if (!Number.isInteger(offset) || offset < 0) {
      throw new Error("paginate: offset must be a non-negative integer");
    }
    if (opts.orderBy) {
      var dir = opts.orderDir || (opts.orderDirection || "asc");
      this.orderBy(opts.orderBy, dir);
    }
    var total = this.count();
    var items = this.limit(limit).offset(offset).all();
    var totalPages = Math.max(1, Math.ceil(total / limit));
    var page = Math.floor(offset / limit) + 1;
    return {
      items:      items,
      total:      total,
      limit:      limit,
      offset:     offset,
      page:       page,
      totalPages: totalPages,
    };
  }

  _delete(single) {
    if (!this._hasConditions()) {
      throw new Error("refusing unconditional delete — call where(...) first");
    }
    var built;
    if (single) {
      if (this._dialect() === "mysql") {
        var pkVal = this._resolveSinglePk();
        if (pkVal === null) return 0;
        built = sql.delete(this._table, this._sqlOpts())
          .where(this._pkColumn(), pkVal)
          .toSql();
      } else {
        var col = this._rowLocatorColumn(this._dialect());
        var inner = sql.select(this._table, this._sqlOpts()).columns([col]);
        this._applyConditions(inner);
        inner.limit(1);
        built = sql.delete(this._table, this._sqlOpts())
          .whereSub(col, "=", inner)
          .toSql();
      }
    } else {
      var dqb = sql.delete(this._table, this._sqlOpts());
      this._applyConditions(dqb);
      built = dqb.toSql();
    }
    var delStmt = this._db.prepare(built.sql);
    var info = delStmt.run.apply(delStmt, built.params);
    return info.changes;
  }
}

class WhereBuilder {
  constructor(gate) {
    this._parts = [];
    this._gate = gate || null;
  }
  _push(joiner, field, op, value) {
    if (typeof field !== "string" || field.length === 0) {
      throw new Error("WhereBuilder: field must be a non-empty string");
    }
    _validateField(field);
    if (this._gate) this._gate._assertColumnMember(field, "whereGroup");
    if (op === "IN" || op === "NOT IN") {
      if (!Array.isArray(value) || value.length === 0) {
        throw new Error("WhereBuilder: " + op + " requires a non-empty array of values");
      }
      this._parts.push({ joiner: joiner, kind: "cmp", field: field, op: op, value: value.slice() });
      return this;
    }
    if (!ALLOWED_OPS.has(op) && op !== "NOT IN") {
      throw new Error("WhereBuilder: invalid operator '" + op + "'");
    }
    this._parts.push({ joiner: joiner, kind: "cmp", field: field, op: op, value: value });
    return this;
  }
  eq(f, v)   { return this._push("AND", f, "=",  v); }
  neq(f, v)  { return this._push("AND", f, "!=", v); }
  gt(f, v)   { return this._push("AND", f, ">",  v); }
  gte(f, v)  { return this._push("AND", f, ">=", v); }
  lt(f, v)   { return this._push("AND", f, "<",  v); }
  lte(f, v)  { return this._push("AND", f, "<=", v); }
  in(f, vs)  { return this._push("AND", f, "IN", vs); }
  like(f, v) { return this._push("AND", f, "LIKE", v); }
  orEq(f, v)   { return this._push("OR", f, "=",  v); }
  orNeq(f, v)  { return this._push("OR", f, "!=", v); }
  orGt(f, v)   { return this._push("OR", f, ">",  v); }
  orGte(f, v)  { return this._push("OR", f, ">=", v); }
  orLt(f, v)   { return this._push("OR", f, "<",  v); }
  orLte(f, v)  { return this._push("OR", f, "<=", v); }
  orIn(f, vs)  { return this._push("OR", f, "IN", vs); }
  orLike(f, v) { return this._push("OR", f, "LIKE", v); }
  raw(sql_, params, opts) {
    if (typeof sql_ !== "string" || sql_.length === 0) {
      throw new Error("WhereBuilder.raw: sql must be a non-empty string");
    }
    var p = Array.isArray(params) ? params.slice() : (params == null ? [] : [params]);
    if (!(opts && opts.allowLiterals === true)) _assertRawNoStringLiteral(sql_, "WhereBuilder.raw");
    if (safeSql.countPlaceholders(sql_) !== p.length) {
      throw new Error("WhereBuilder.raw: placeholder count mismatch");
    }
    this._parts.push({ joiner: "AND", kind: "raw", sql: sql_, params: p, opts: opts });
    return this;
  }
  replay(pred) {
    for (var i = 0; i < this._parts.length; i++) {
      _replayPart(pred, this._parts[i], this._parts[i].joiner === "OR" && i > 0);
    }
  }
  build() {
    if (this._parts.length === 0) return { sql: "", params: [] };
    var self = this;
    var built = sql.select("t", { dialect: "sqlite" })
      .whereGroup(function (g) { self.replay(g); })
      .toSql();
    var m = /WHERE \((.*)\)$/.exec(built.sql);
    return { sql: m ? m[1] : "", params: built.params };
  }
}

function _assertRawNoStringLiteral(rawSql, where) {
  safeSql.assertNoRawStringLiteral(rawSql, where);
}

function _replayPart(pred, part, or) {
  if (part.kind === "raw") {
    if (or) pred.orWhereRaw(part.sql, part.params, part.opts);
    else pred.whereRaw(part.sql, part.params, part.opts);
    return;
  }
  if (part.op === "LIKE") {
    var likeDialect = (pred && typeof pred._dialect === "function") ? pred._dialect() : "sqlite";
    var likeSql = safeSql.quoteIdentifier(part.field, likeDialect, { allowReserved: true }) + " LIKE ?";
    if (or) pred.orWhereRaw(likeSql, [part.value]);
    else pred.whereRaw(likeSql, [part.value]);
    return;
  }
  if (part.op === "IN") {
    if (or) pred.orWhereIn(part.field, part.value);
    else pred.whereIn(part.field, part.value);
    return;
  }
  if (part.op === "NOT IN") {
    if (or) pred.orWhereGroup(function (g) { g.whereNotIn(part.field, part.value); });
    else pred.whereNotIn(part.field, part.value);
    return;
  }
  if (or) pred.orWhereOp(part.field, part.op, part.value);
  else pred.whereOp(part.field, part.op, part.value);
}

function _validateField(field) {
  if (typeof field !== "string" ||
      field.length === 0 ||
      field.length > safeSql.MAX_IDENTIFIER_LENGTH ||
      !safeSql.isDefaultIdentifier(field)) {
    throw new Error("invalid field name: '" + field +
      "' (must be " + safeSql.DEFAULT_IDENTIFIER_SHAPE + ", length 1.." +
      safeSql.MAX_IDENTIFIER_LENGTH + ")");
  }
}

var _RAW_WRITE_KEYWORD_RE = /^\s*(?:INSERT|REPLACE|UPDATE)\b/i;
var _RAW_INSERT_RE = /^\s*(?:INSERT|REPLACE)\s+(?:OR\s+[A-Za-z]+\s+)?INTO\s+(?:[\x22\x27\x60]?[A-Za-z_]\w*[\x22\x27\x60]?\s*\.\s*){0,3}[\x22\x27\x60]?([A-Za-z_]\w*)[\x22\x27\x60]?\s*\(([^)]+)\)\s*VALUES\s*\(([\s\S]+)\)$/i;
var _RAW_UPDATE_RE = /^\s*UPDATE\s+(?:[\x22\x27\x60]?[A-Za-z_]\w*[\x22\x27\x60]?\s*\.\s*){0,3}[\x22\x27\x60]?([A-Za-z_]\w*)[\x22\x27\x60]?\s+SET\s+([\s\S]+)$/i;

function _stripStatementTail(s) {
  var ws = codepointClass.WHITESPACE_RANGES;
  var end = s.length;
  while (end > 0 && codepointClass.inRanges(s.charCodeAt(end - 1), ws)) end -= 1;
  if (end > 0 && s.charCodeAt(end - 1) === 0x3B ) {
    end -= 1;
    while (end > 0 && codepointClass.inRanges(s.charCodeAt(end - 1), ws)) end -= 1;
  }
  return end === s.length ? s : s.slice(0, end);
}
var _RAW_TABLE_RE = /^\s*(?:INSERT|REPLACE)\s+(?:OR\s+[A-Za-z]+\s+)?INTO\s+(?:[\x22\x27\x60]?[A-Za-z_]\w*[\x22\x27\x60]?\s*\.\s*){0,3}[\x22\x27\x60]?([A-Za-z_]\w*)[\x22\x27\x60]?|^\s*UPDATE\s+(?:[\x22\x27\x60]?[A-Za-z_]\w*[\x22\x27\x60]?\s*\.\s*){0,3}[\x22\x27\x60]?([A-Za-z_]\w*)[\x22\x27\x60]?/i;

function _unquoteIdent(s) {
  s = String(s).trim();
  if (s.length >= 2 &&
      (s.charAt(0) === '"' || s.charAt(0) === "'" || s.charAt(0) === "`") &&
      s.charAt(s.length - 1) === s.charAt(0)) {
    return s.slice(1, -1);
  }
  return s;
}

function _stripLeadingSqlComments(sql) {
  var s = String(sql), prev;
  do {
    prev = s;
    s = s.replace(/^\s+/, "");                 // allow:regex-no-length-cap — anchored, single leading run
    s = s.replace(/^--[^\n]*\r?\n?/, "");      // allow:regex-no-length-cap — anchored leading line comment
    s = s.replace(/^\/\*[\s\S]*?\*\//, "");    // allow:regex-no-length-cap — anchored leading block comment (lazy, single scan)
  } while (s !== prev);
  return s;
}

function _normalizeForWriteParse(sql) {
  return _stripLeadingSqlComments(safeSql.normalizeForScan(sql));
}

var _CTE_WRITE_TARGET_RE = /(?:\b(?:INSERT|REPLACE)\s+(?:OR\s+[A-Za-z]+\s+)?INTO|\bMERGE\s+INTO)\s+(?:[\x22\x27\x60]?[A-Za-z_]\w*[\x22\x27\x60]?\s*\.\s*){0,3}[\x22\x27\x60]?([A-Za-z_]\w*)[\x22\x27\x60]?|\bUPDATE\s+(?:[\x22\x27\x60]?[A-Za-z_]\w*[\x22\x27\x60]?\s*\.\s*){0,3}[\x22\x27\x60]?([A-Za-z_]\w*)[\x22\x27\x60]?\s+SET\b/ig;  // allow:regex-no-length-cap — alternation, no nested quantifiers; linear
function _firstResidencyWriteTarget(s) {
  _CTE_WRITE_TARGET_RE.lastIndex = 0;
  var m;
  while ((m = _CTE_WRITE_TARGET_RE.exec(s)) !== null) {  // allow:regex-no-length-cap
    var t = _unquoteIdent(m[1] || m[2]);
    if (t && (cryptoField.getPerRowResidency(t) || cryptoField.getColumnResidency(t))) return t;
  }
  return null;
}

function _rawWriteTable(sql) {
  if (typeof sql !== "string") return null;
  var s = _normalizeForWriteParse(sql);
  if (_RAW_WRITE_KEYWORD_RE.test(s)) {  // allow:regex-no-length-cap
    var m = _RAW_TABLE_RE.exec(s);  // allow:regex-no-length-cap
    return m ? _unquoteIdent(m[1] || m[2]) : null;
  }
  if (/^\s*(?:WITH|EXPLAIN)\b/i.test(s)) {  // allow:regex-no-length-cap
    return _firstResidencyWriteTarget(s);
  }
  return null;
}

function _isRawWriteToResidencyTable(sql) {
  var table = _rawWriteTable(sql);
  if (!table) return false;
  return !!(cryptoField.getPerRowResidency(table) || cryptoField.getColumnResidency(table));
}

function _splitTopLevelCommas(s) {
  var out = [], depth = 0, cur = "", q = null;
  for (var i = 0; i < s.length; i++) {
    var c = s.charAt(i);
    if (q) {
      cur += c;
      if (c === q) { if (s.charAt(i + 1) === q) { cur += s.charAt(++i); } else { q = null; } }
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { q = c; cur += c; continue; }
    if (c === "(") { depth += 1; cur += c; continue; }
    if (c === ")") { depth -= 1; cur += c; continue; }
    if (c === "," && depth === 0) { out.push(cur); cur = ""; continue; }
    cur += c;
  }
  if (cur.trim() !== "") out.push(cur);
  return out.map(function (x) { return x.trim(); });
}

function _setClauseBeforeWhere(s) {
  var depth = 0, q = null, n = s.length;
  for (var i = 0; i < n; i++) {
    var c = s.charAt(i);
    if (q) {
      if (c === q) { if (s.charAt(i + 1) === q) { i++; } else { q = null; } }
      continue;
    }
    if (c === "'" || c === '"' || c === "\x60") { q = c; continue; }
    if (c === "(") { depth += 1; continue; }
    if (c === ")") { depth -= 1; continue; }
    if (depth === 0 && (c === " " || c === "\t" || c === "\n" || c === "\r")) {
      var j = i;
      while (j < n && /\s/.test(s.charAt(j))) j += 1;
      if (s.substr(j, 5).toLowerCase() === "where" && !/\w/.test(s.charAt(j + 5) || "")) {
        return s.slice(0, i);
      }
    }
  }
  return s;
}

function _rawValue(tok, boundParams, pc) {
  tok = tok.trim();
  if (tok === "?") { return boundParams[pc.i++]; }
  if (tok.length >= 2 && (tok.charAt(0) === "'" || tok.charAt(0) === '"')) {
    var qc = tok.charAt(0);
    return tok.slice(1, -1).split(qc + qc).join(qc);
  }
  if (/^null$/i.test(tok)) return null;
  if (/^-?\d+(?:\.\d+)?$/.test(tok)) return Number(tok);
  return tok;
}

function _flattenRunParams(argsLike) {
  var a = Array.prototype.slice.call(argsLike || []);
  if (a.length === 1 && Array.isArray(a[0])) return a[0];
  return a;
}

function _assertRawWriteResidency(sql, boundParams) {
  var table = _rawWriteTable(sql);
  if (!table) return;
  if (!cryptoField.getPerRowResidency(table) && !cryptoField.getColumnResidency(table)) return;
  boundParams = _flattenRunParams(boundParams);

  var norm = _normalizeForWriteParse(sql);

  if (norm.length > 100000) {
    throw new DbQueryError("db-query/row-residency-raw-unparseable",
      "raw write to residency table '" + table + "' exceeds the parse limit (" +
      norm.length + " chars) - use b.db.from(\"" + table + "\") so residency is validated", true);
  }

  var body = _stripStatementTail(norm);
  var mi = _RAW_INSERT_RE.exec(body);  // allow:regex-no-length-cap — input length-capped above
  var mu = mi ? null : _RAW_UPDATE_RE.exec(body);  // allow:regex-no-length-cap — input length-capped above
  if (!mi && !mu) {
    throw new DbQueryError("db-query/row-residency-raw-unparseable",
      "raw write to residency table '" + table + "' cannot be parsed to validate its " +
      "residency tag - use b.db.from(\"" + table + "\").insertOne / .updateOne so the tag is checked", true);
  }

  var plaintextRow = {};
  var pc = { i: 0 };
  if (mi) {
    var cols = _splitTopLevelCommas(mi[2]).map(_unquoteIdent);
    var vals = _splitTopLevelCommas(mi[3]);
    if (cols.length !== vals.length) {
      throw new DbQueryError("db-query/row-residency-raw-unparseable",
        "raw insert to residency table '" + table + "' has an unmodelled VALUES shape " +
        "(multi-row / expression) - use the structured builder so residency is validated", true);
    }
    for (var ci = 0; ci < cols.length; ci++) {
      plaintextRow[cols[ci]] = _rawValue(vals[ci], boundParams, pc);
    }
    _assertLocalResidency(table, plaintextRow, "insert");
  } else {
    var assigns = _splitTopLevelCommas(_setClauseBeforeWhere(mu[2]));
    for (var ai = 0; ai < assigns.length; ai++) {
      var eq = assigns[ai].indexOf("=");
      if (eq === -1) continue;
      plaintextRow[_unquoteIdent(assigns[ai].slice(0, eq))] = _rawValue(assigns[ai].slice(eq + 1), boundParams, pc);
    }
    _assertLocalResidency(table, plaintextRow, "update");
  }
}

module.exports = {
  Query: Query,
  _isRawWriteToResidencyTable: _isRawWriteToResidencyTable,
  _assertRawWriteResidency:    _assertRawWriteResidency,
  _stripLeadingSqlComments:    _stripLeadingSqlComments,
};

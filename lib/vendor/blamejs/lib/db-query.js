"use strict";
/**
 * Chainable Query builder.
 *
 * Public surface (all methods sync — node:sqlite is sync):
 *
 *   db.from('users')                          // → Query
 *     .where({ status: 'active' })            // object form: AND of equalities
 *     .where('createdAt', '>', '2026-01-01')  // operator form: AND condition
 *     .select(['_id', 'email'])               // optional projection
 *     .orderBy('createdAt', 'desc')
 *     .limit(10).offset(20)
 *     .all();                                 // → array of decrypted rows
 *
 * Terminal methods: first(), all(), count(),
 *                   insertOne(row), insertMany(rows),
 *                   updateOne(changes), updateMany(changes),
 *                   deleteOne(), deleteMany().
 *
 * Sealed-field semantics:
 *   - On insert/update, sealed columns are vault.seal()'d and their derived
 *     hashes computed automatically.
 *   - On read, sealed columns are vault.unseal()'d before the row is returned.
 *   - where() on a sealed column with a registered derived hash silently
 *     translates to the derived hash column. Querying a sealed column WITHOUT
 *     a derived hash throws (every encryption uses a fresh nonce — the lookup
 *     would always return zero rows; failing loudly is safer).
 */
var { Readable } = require("node:stream");
var C = require("./constants");
var cryptoField = require("./crypto-field");
var { generateToken } = require("./crypto");
var safeSql = require("./safe-sql");

var ALLOWED_OPS = new Set(["=", "!=", "<>", "<", "<=", ">", ">=", "IS", "IS NOT", "LIKE", "IN"]);

class Query {
  constructor(database, tableName) {
    // Identifier safety: tableName flows into SQL via interpolation
    // (parameter placeholders only bind values, not names). Validate at
    // construction so an attacker-controlled name with embedded `"` or
    // SQL keywords can't break out of the wrapping quotes downstream.
    if (typeof tableName !== "string") {
      throw new TypeError("Query: tableName must be a string, got " + typeof tableName);
    }
    // Cross-schema syntax: "schema.table". Two-part identifier only —
    // three-part (catalog.schema.table) is rejected. Both parts must
    // be valid SQL identifiers and contain no further dots.
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
      // Validate the schema identifier separately. allowReserved:true
      // because we always wrap in `"..."`.
      safeSql.validateIdentifier(schema, { allowReserved: true });
    }
    safeSql.validateIdentifier(table, { allowReserved: true });

    this._db            = database;
    this._schema        = schema;
    this._table         = table;
    this._qualifiedKey  = schema ? schema + "." + table : table;
    this._where         = [];
    this._whereParams   = [];
    this._select        = null;
    this._orderBy       = null;
    this._limit         = null;
    this._offset        = null;
  }

  // Quoted SQL form: `"schema"."table"` if schema-qualified, else `"table"`.
  _quotedTable() {
    return this._schema
      ? '"' + this._schema + '"."' + this._table + '"'
      : '"' + this._table + '"';
  }

  // ---- Chainable filters ----

  where(fieldOrObj, op, value) {
    if (fieldOrObj && typeof fieldOrObj === "object") {
      // Object form: { field: value, ... } — all AND'd as equalities
      for (var k in fieldOrObj) {
        this._addCondition(k, "=", fieldOrObj[k]);
      }
      return this;
    }
    if (arguments.length === 2) {
      // where('field', value) shorthand
      return this._addCondition(fieldOrObj, "=", op);
    }
    return this._addCondition(fieldOrObj, op, value);
  }

  _addCondition(field, op, value) {
    if (!ALLOWED_OPS.has(op)) {
      throw new Error("invalid where operator: " + op);
    }
    // Sealed-field translation: rewrite predicate to use derived hash if available
    if (this._isSealedField(field)) {
      var lookup = cryptoField.lookupHash(this._cryptoFieldKey(), field, value);
      if (!lookup) {
        throw new Error(
          "cannot query sealed column '" + this._cryptoFieldKey() + "." + field +
          "' without a derived hash. Declare derivedHashes: { <name>: { from: '" + field + "' } } " +
          "in the table's schema config."
        );
      }
      field = lookup.field;
      value = lookup.value;
    }
    cryptoField && _validateField(field);
    this._where.push('"' + field + '" ' + op + " ?");
    this._whereParams.push(value);
    return this;
  }

  _isSealedField(field) {
    var sealed = cryptoField.getSealedFields(this._cryptoFieldKey());
    return sealed.indexOf(field) !== -1;
  }

  // Sealed-field registry lookup key. Schema-qualified queries first
  // try the qualified name (`audit.users`) so an operator can register
  // per-schema sealed columns; falls back to the bare table when no
  // qualified registration exists. The fall-back lets the existing
  // table-name-only registrations keep working unchanged.
  _cryptoFieldKey() {
    if (!this._schema) return this._table;
    if (cryptoField.getSealedFields(this._qualifiedKey).length > 0) {
      return this._qualifiedKey;
    }
    return this._table;
  }

  // whereRaw — append a parenthesized raw SQL fragment with positional
  // placeholders and the parameter values that fill them. Composes with
  // .where() (AND-joined via the same `_where` array). The fragment
  // must NOT contain operator-supplied SQL — it's caller-controlled
  // text used to build expressions the chainable .where() can't express
  // (compound OR, row-value comparison for cursor pagination, etc.).
  // Placeholder count must match params.length.
  whereRaw(sql, params) {
    if (typeof sql !== "string" || sql.length === 0) {
      throw new Error("whereRaw: sql must be a non-empty string");
    }
    var p = Array.isArray(params) ? params : (params == null ? [] : [params]);
    var holders = (sql.match(/\?/g) || []).length;
    if (holders !== p.length) {
      throw new Error("whereRaw: " + holders + " placeholder(s) in sql but " +
        p.length + " param(s) supplied");
    }
    this._where.push("(" + sql + ")");
    for (var i = 0; i < p.length; i++) this._whereParams.push(p[i]);
    return this;
  }

  select(columns) {
    if (!Array.isArray(columns)) {
      throw new Error("select() expects an array of column names");
    }
    columns.forEach(_validateField);
    this._select = columns.slice();
    return this;
  }

  orderBy(field, direction) {
    _validateField(field);
    direction = (direction || "asc").toLowerCase();
    if (direction !== "asc" && direction !== "desc") {
      throw new Error("orderBy direction must be 'asc' or 'desc'");
    }
    var entry = { field: field, direction: direction.toUpperCase() };
    if (this._orderBy === null) {
      // First call — keep the back-compat single-object shape so any
      // legacy reader that does `query._orderBy.field` keeps working.
      this._orderBy = entry;
      return this;
    }
    // Second-or-later call — promote to an array. Multi-column ORDER BY
    // is the keyset-pagination tiebreaker pattern: ORDER BY createdAt
    // DESC, _id DESC means same-second rows still have a total order.
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

  // ---- Build SELECT components ----

  _whereClause() {
    return this._where.length === 0 ? "" : " WHERE " + this._where.join(" AND ");
  }

  _orderLimitOffset() {
    var s = "";
    if (this._orderBy) {
      var entries = Array.isArray(this._orderBy) ? this._orderBy : [this._orderBy];
      var fragments = [];
      for (var i = 0; i < entries.length; i++) {
        fragments.push('"' + entries[i].field + '" ' + entries[i].direction);
      }
      s += " ORDER BY " + fragments.join(", ");
    }
    if (this._limit !== null)  s += " LIMIT "  + this._limit;
    if (this._offset !== null) s += " OFFSET " + this._offset;
    return s;
  }

  _projection() {
    if (!this._select) return "*";
    return this._select.map(function (c) { return '"' + c + '"'; }).join(", ");
  }

  // ---- Terminal methods (sync) ----

  first() {
    var sql = "SELECT " + this._projection() + " FROM " + this._quotedTable() +
              this._whereClause() + this._orderLimitOffset() + " LIMIT 1";
    var stmt = this._db.prepare(sql);
    var row = stmt.get.apply(stmt, this._whereParams);
    return row ? cryptoField.unsealRow(this._cryptoFieldKey(), row) : null;
  }

  all() {
    var sql = "SELECT " + this._projection() + " FROM " + this._quotedTable() +
              this._whereClause() + this._orderLimitOffset();
    var stmt = this._db.prepare(sql);
    var rows = stmt.all.apply(stmt, this._whereParams);
    var out = new Array(rows.length);
    var key = this._cryptoFieldKey();
    for (var i = 0; i < rows.length; i++) {
      out[i] = cryptoField.unsealRow(key, rows[i]);
    }
    return out;
  }

  // Streaming counterpart to all(). Each row is auto-unsealed against
  // the bound table's sealedFields registration before it lands in the
  // operator's pipeline. For large result sets (audit exports, backup
  // table dumps) this avoids materializing the full rowset in memory.
  stream() {
    var sql = "SELECT " + this._projection() + " FROM " + this._quotedTable() +
              this._whereClause() + this._orderLimitOffset();
    var stmt = this._db.prepare(sql);
    var key = this._cryptoFieldKey();
    var iter;
    try { iter = stmt.iterate.apply(stmt, this._whereParams); }
    catch (e) {
      var r = new Readable({ objectMode: true, read: function () {} });
      setImmediate(function () { r.destroy(e); });
      return r;
    }
    return new Readable({
      objectMode: true,
      read: function () {
        try {
          var step = iter.next();
          if (step.done) { this.push(null); return; }
          this.push(cryptoField.unsealRow(key, step.value));
        } catch (e) {
          this.destroy(e);
        }
      },
    });
  }

  count() {
    var sql = "SELECT COUNT(*) AS n FROM " + this._quotedTable() + this._whereClause();
    var stmt = this._db.prepare(sql);
    var row = stmt.get.apply(stmt, this._whereParams);
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
    var sealed = cryptoField.sealRow(this._cryptoFieldKey(), withId);
    var cols = Object.keys(sealed);
    var placeholders = cols.map(function () { return "?"; }).join(", ");
    var quotedCols = cols.map(function (c) { return '"' + c + '"'; }).join(", ");
    var values = cols.map(function (c) { return sealed[c]; });
    var sql = "INSERT INTO " + this._quotedTable() + " (" + quotedCols + ") VALUES (" + placeholders + ")";
    var insertStmt = this._db.prepare(sql);
    insertStmt.run.apply(insertStmt, values);
    // Return the original row with _id filled in (plaintext, never sealed)
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
    if (this._where.length === 0) {
      throw new Error("refusing unconditional update — call where(...) first");
    }
    var sealed = cryptoField.sealRow(this._cryptoFieldKey(), changes);
    var setKeys = Object.keys(sealed);
    if (setKeys.length === 0) {
      throw new Error("update changes object is empty");
    }
    setKeys.forEach(_validateField);
    var setClause = setKeys.map(function (k) { return '"' + k + '" = ?'; }).join(", ");
    var setValues = setKeys.map(function (k) { return sealed[k]; });

    var whereSql = this._where.join(" AND ");
    var limit = single ? " LIMIT 1" : "";
    // SQLite supports LIMIT on UPDATE only when compiled with SQLITE_ENABLE_UPDATE_DELETE_LIMIT.
    // node:sqlite ships without that flag — emulate single-row with a sub-select on rowid.
    var sql;
    var qt = this._quotedTable();
    if (single) {
      sql = "UPDATE " + qt + " SET " + setClause +
            " WHERE rowid = (SELECT rowid FROM " + qt + " WHERE " + whereSql + " LIMIT 1)";
    } else {
      sql = "UPDATE " + qt + " SET " + setClause + " WHERE " + whereSql + limit;
    }
    var allParams = setValues.concat(this._whereParams);
    var updStmt = this._db.prepare(sql);
    var info = updStmt.run.apply(updStmt, allParams);
    return info.changes;
  }

  deleteOne() {
    return this._delete(true) > 0;
  }

  deleteMany() {
    return this._delete(false);
  }

  _delete(single) {
    if (this._where.length === 0) {
      throw new Error("refusing unconditional delete — call where(...) first");
    }
    var whereSql = this._where.join(" AND ");
    var sql;
    var qt = this._quotedTable();
    if (single) {
      sql = "DELETE FROM " + qt +
            " WHERE rowid = (SELECT rowid FROM " + qt + " WHERE " + whereSql + " LIMIT 1)";
    } else {
      sql = "DELETE FROM " + qt + " WHERE " + whereSql;
    }
    var delStmt = this._db.prepare(sql);
    var info = delStmt.run.apply(delStmt, this._whereParams);
    return info.changes;
  }
}

function _validateField(field) {
  if (typeof field !== "string" ||
      field.length === 0 ||
      field.length > safeSql.MAX_IDENTIFIER_LENGTH ||
      !safeSql.DEFAULT_IDENTIFIER_RE.test(field)) {
    throw new Error("invalid field name: '" + field +
      "' (must match " + safeSql.DEFAULT_IDENTIFIER_RE + ", length 1.." +
      safeSql.MAX_IDENTIFIER_LENGTH + ")");
  }
}

module.exports = { Query: Query };

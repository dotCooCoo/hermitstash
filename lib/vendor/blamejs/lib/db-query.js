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
var safeJson = require("./safe-json");
var safeJsonPath = require("./safe-jsonpath");
var safeSql = require("./safe-sql");

// "@>" / "?" / "?|" / "?&" are JSONB containment + key-existence
// operators. Routed through safeJsonPath validation before binding so
// operator-supplied values can't smuggle NUL / control / bidi
// characters into the JSON-shape comparison.
var ALLOWED_OPS = new Set([
  "=", "!=", "<>", "<", "<=", ">", ">=", "IS", "IS NOT", "LIKE", "IN",
  "@>", "?", "?|", "?&",
]);
var JSONB_CONTAINMENT_OPS = new Set(["@>"]);
var JSONB_KEY_OPS         = new Set(["?", "?|", "?&"]);

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
    // D-M4 — JSONB / JSON-path injection guard. Routes operator-
    // supplied JSONB containment + key-existence values through
    // safe-jsonpath before they reach the engine. Bound via `?`
    // placeholder so the value still doesn't interpolate; this is
    // the second line of defense — refuses NUL / control / bidi /
    // zero-width that some drivers silently strip out of JSON
    // round-trip but the engine processes verbatim.
    if (JSONB_CONTAINMENT_OPS.has(op)) {
      if (typeof value === "string") {
        // Operator passed pre-stringified JSON; parse + validate the
        // shape, refuse on bad shape / control chars / depth bomb.
        var parsed;
        try { parsed = safeJson.parse(value); }
        catch (e) {
          throw new Error("where '" + op + "' value: invalid JSON string: " +
            ((e && e.message) || String(e)));
        }
        safeJsonPath.validateContainment(parsed);
      } else {
        safeJsonPath.validateContainment(value);
        // Bind the canonical-shape JSON so the driver sees the same
        // bytes we validated. JSON.stringify here is safe — the
        // shape was just walked end-to-end.
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
        // ?| / ?& take a Postgres text[] of keys. Caller passes a JS
        // array; each element validated as a single key.
        if (!Array.isArray(value) || value.length === 0) {
          throw new Error("where '" + op + "' requires a non-empty array of string keys");
        }
        for (var ki = 0; ki < value.length; ki++) {
          safeJsonPath.validateKey(value[ki]);
        }
      }
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
    if (op === "IN") {
      // node:sqlite ? does not support array-binding. Pre-v0.8.18
      // `where(field, "IN", [1,2,3])` silently bound the entire
      // array to a single placeholder and matched zero rows.
      // Expand to (?, ?, ?) and push each value separately.
      if (!Array.isArray(value) || value.length === 0) {
        throw new Error("where IN requires a non-empty array of values");
      }
      var placeholders = value.map(function () { return "?"; }).join(", ");
      this._where.push('"' + field + '" IN (' + placeholders + ")");
      for (var i = 0; i < value.length; i += 1) this._whereParams.push(value[i]);
      return this;
    }
    if (op === "LIKE" && typeof value === "string") {
      // Escape SQL LIKE metacharacters %  and _ in operator-supplied
      // input. Without this, a single `%` in untrusted input becomes
      // a wildcard that matches everything — a column-disclosure
      // class (`q=%@%` enumerates entire table). Use a backslash as
      // the escape character (uniform across SQLite + Postgres) and
      // emit the corresponding ESCAPE clause so the engine treats it
      // as the escape token. Operators who deliberately want LIKE
      // wildcards in their value bypass via whereRaw().
      var escaped = value.replace(/[\\%_]/g, "\\$&");
      this._where.push('"' + field + '" LIKE ? ESCAPE ' + "'\\\\'");
      this._whereParams.push(escaped);
      return this;
    }
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
    // Count `?` placeholders, but skip occurrences inside string
    // literals ('...'  or "..."), line comments (-- to EOL), and
    // block comments (/* ... */). Pre-v0.8.18 the naive regex
    // counted `?` inside literals (e.g. `WHERE name = 'a?b' AND id
    // = ?`) which caused mismatched-count errors OR — worse — let
    // through fragments where the literal-`?` placebo masked a
    // missed real placeholder.
    var holders = _countPlaceholders(sql);
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
  // D-M5 — streamLimit ceiling enforced from the module-level db
  // config; per-call opts.streamLimit overrides for one-off bumps.
  stream(opts) {
    var sql = "SELECT " + this._projection() + " FROM " + this._quotedTable() +
              this._whereClause() + this._orderLimitOffset();
    var perCallLimit;
    // db.js exports getStreamLimit so this module reads the live
    // ceiling without bouncing through the lib's circular load.
    var dbModule = require("./db");                                                                    // allow:inline-require — circular-load defense (db imports db-query)
    perCallLimit = dbModule.getStreamLimit();
    if (opts && opts.streamLimit !== undefined) {
      if (typeof opts.streamLimit !== "number" || !isFinite(opts.streamLimit) ||
          opts.streamLimit <= 0 || Math.floor(opts.streamLimit) !== opts.streamLimit) {
        throw new Error("Query.stream: opts.streamLimit must be a positive finite integer; got " +
          JSON.stringify(opts.streamLimit));
      }
      perCallLimit = opts.streamLimit;
    }
    var stmt = this._db.prepare(sql);
    var key = this._cryptoFieldKey();
    var iter;
    try { iter = stmt.iterate.apply(stmt, this._whereParams); }
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

  // Atomic counter increment.
  //
  // `from(table).where(filter).increment("col", 1)` emits
  // `UPDATE table SET col = col + ? WHERE ...` so concurrent writers
  // can't collide on a fetch/mutate/store sequence (which would lose
  // increments under racing transactions). Pass a negative delta to
  // decrement.
  //
  // Returns the number of rows changed (matches updateMany shape).
  increment(column, delta) {
    if (typeof column !== "string" || column.length === 0) {
      throw new Error("increment(column, delta): column must be a non-empty string");
    }
    _validateField(column);
    if (delta === undefined) delta = 1;
    if (typeof delta !== "number" || !Number.isFinite(delta) || !Number.isInteger(delta)) {
      throw new Error("increment(column, delta): delta must be a finite integer (default 1)");
    }
    if (this._where.length === 0) {
      throw new Error("refusing unconditional increment — call where(...) first");
    }
    var whereSql = this._where.join(" AND ");
    var qt = this._quotedTable();
    var qc = '"' + column + '"';
    // Use COALESCE so a NULL counter starts at 0 instead of producing
    // NULL + delta = NULL silently (which would silently drop the
    // operation under SQLite's NULL-arithmetic rules).
    var sql = "UPDATE " + qt + " SET " + qc + " = COALESCE(" + qc + ", 0) + ? WHERE " + whereSql;
    var allParams = [delta].concat(this._whereParams);
    var stmt = this._db.prepare(sql);
    var info = stmt.run.apply(stmt, allParams);
    return info.changes;
  }

  // `.where(closure)` for grouped expressions, including OR
  // composition. Pass a function `(qb) => qb.eq(col, val).orEq(...)`;
  // the inner closure builds an expression that becomes a single
  // parenthesised AND-leaf in the outer where chain.
  //
  // The closure receives a `WhereBuilder` exposing `.eq` / `.neq` /
  // `.gt` / `.gte` / `.lt` / `.lte` / `.in` / `.like` plus `.orEq`,
  // `.orNeq`, `.orGt`, `.orGte`, `.orLt`, `.orLte`, `.orIn`,
  // `.orLike`, and `.raw(sql, params)`. Each non-`or` call ANDs the
  // expression; each `or*` call ORs it.
  whereGroup(closure) {
    if (typeof closure !== "function") {
      throw new Error("whereGroup(closure): expected function (qb) => ...");
    }
    var sub = new WhereBuilder();
    closure(sub);
    var built = sub.build();
    if (!built.sql) return this;
    this._where.push("(" + built.sql + ")");
    for (var i = 0; i < built.params.length; i++) this._whereParams.push(built.params[i]);
    return this;
  }

  // Top-level OR — extends the existing where-chain so
  // `.where(a).orWhere(b)` produces `WHERE (a) OR (b)` rather than
  // `WHERE (a) AND (b)`. Accepts the same arg shapes as `.where`:
  // object-literal map, `(field, value)`, `(field, op, value)`, or a
  // `(qb) => ...` closure.
  orWhere(fieldOrObjOrFn, op, value) {
    if (this._where.length === 0) {
      throw new Error("orWhere(...): no prior where(...) — start the chain with where(...)");
    }
    if (typeof fieldOrObjOrFn === "function") {
      var sub = new WhereBuilder();
      fieldOrObjOrFn(sub);
      var built = sub.build();
      if (!built.sql) return this;
      var prev = this._where.pop();
      this._where.push("(" + prev + " OR (" + built.sql + "))");
      for (var i = 0; i < built.params.length; i++) this._whereParams.push(built.params[i]);
      return this;
    }
    // For non-closure shapes, build a transient single-leaf Query and
    // splice it. We compile to a `WhereBuilder` for symmetry.
    var sub2 = new WhereBuilder();
    if (fieldOrObjOrFn !== null && typeof fieldOrObjOrFn === "object" && !Array.isArray(fieldOrObjOrFn)) {
      Object.keys(fieldOrObjOrFn).forEach(function (k) { sub2.eq(k, fieldOrObjOrFn[k]); });
    } else if (op === undefined) {
      sub2.eq(fieldOrObjOrFn, /* value */ arguments[1]);
    } else {
      sub2._push("AND", fieldOrObjOrFn, op, value);
    }
    var built2 = sub2.build();
    if (!built2.sql) return this;
    var prev2 = this._where.pop();
    this._where.push("(" + prev2 + " OR (" + built2.sql + "))");
    for (var j = 0; j < built2.params.length; j++) this._whereParams.push(built2.params[j]);
    return this;
  }

  // `.search(fields, term)` — chainable LIKE-OR helper. Adds
  // `(field1 LIKE ? OR field2 LIKE ? ...)` ANDed onto the existing
  // where-chain. Empty term is a no-op (so `?search=` from a query-
  // string flows through cleanly).
  //
  // `term` is wrapped with `%` on both sides for substring match by
  // default; pass `{ match: "prefix" }` for `term%` only or
  // `{ match: "exact" }` to LIKE the term verbatim (for operators
  // who need to keep `%`/`_` in the user-supplied query).
  search(fields, term, opts) {
    if (!Array.isArray(fields) || fields.length === 0) {
      throw new Error("search(fields, term): fields must be a non-empty array of column names");
    }
    fields.forEach(_validateField);
    if (term === undefined || term === null) return this;
    if (typeof term !== "string") {
      throw new Error("search(fields, term): term must be a string");
    }
    if (term.length === 0) return this;
    var match = (opts && opts.match) || "substring";
    // Escape the operator's term so SQL LIKE wildcards in user input
    // don't widen the match. Use `~` as the ESCAPE char (SQLite's
    // ESCAPE clause requires a single character — picking `~` rather
    // than `\` avoids JS-string-literal escaping headaches; `~` rarely
    // appears in user-supplied search terms).
    var escaped = String(term).replace(/[~%_]/g, function (c) { return "~" + c; });
    var pattern;
    if (match === "exact")        pattern = escaped;
    else if (match === "prefix")  pattern = escaped + "%";
    else if (match === "substring") pattern = "%" + escaped + "%";
    else throw new Error("search: opts.match must be 'substring' | 'prefix' | 'exact'");
    var clauses = fields.map(function (f) { return '"' + f + '" LIKE ? ESCAPE \'~\''; });
    var sql = "(" + clauses.join(" OR ") + ")";
    var params = fields.map(function () { return pattern; });
    this._where.push(sql);
    for (var i = 0; i < params.length; i++) this._whereParams.push(params[i]);
    return this;
  }

  // `.paginate(opts)` — page envelope. Composes the existing
  // `.orderBy().limit().offset().all()` + a separate `.count()` so
  // operators get `{ items, total, limit, offset, page, totalPages }`
  // in one call.
  //
  // Defaults: `limit = 25`, `offset = 0`. `orderBy` is required when
  // the underlying query has no order — otherwise SQLite returns
  // rows in storage order (not stable across page calls).
  paginate(opts) {
    opts = opts || {};
    var limit = opts.limit === undefined ? 25 : opts.limit;
    var offset = opts.offset === undefined ? 0 : opts.offset;
    if (!Number.isInteger(limit) || limit <= 0 || limit > 1000) {                          // allow:raw-byte-literal — paginate page-size cap, not bytes
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

// WhereBuilder — sub-expression builder used by Query.whereGroup() and
// Query.orWhere((qb) => ...) to compose grouped AND/OR predicates that
// the bare .where() chain (which only ANDs) can't express.
//
// Each `.eq` / `.neq` / `.gt` / `.gte` / `.lt` / `.lte` / `.in` /
// `.like` call ANDs an expression; `.orEq` / `.orNeq` / `.orGt` /
// `.orGte` / `.orLt` / `.orLte` / `.orIn` / `.orLike` ORs an
// expression. `.raw(sql, params)` AND's an arbitrary fragment.
//
// `.build()` returns `{ sql, params }`. Empty builder → `{ sql: "",
// params: [] }`.
class WhereBuilder {
  constructor() {
    this._parts = [];   // [{ joiner: "AND"|"OR", sql: "...", params: [...] }]
  }
  _push(joiner, field, op, value) {
    if (typeof field !== "string" || field.length === 0) {
      throw new Error("WhereBuilder: field must be a non-empty string");
    }
    _validateField(field);
    var qf = '"' + field + '"';
    if (op === "IN" || op === "NOT IN") {
      if (!Array.isArray(value) || value.length === 0) {
        throw new Error("WhereBuilder: " + op + " requires a non-empty array of values");
      }
      var placeholders = value.map(function () { return "?"; }).join(", ");
      this._parts.push({ joiner: joiner, sql: qf + " " + op + " (" + placeholders + ")", params: value.slice() });
      return this;
    }
    if (!ALLOWED_OPS.has(op)) {
      throw new Error("WhereBuilder: invalid operator '" + op + "'");
    }
    this._parts.push({ joiner: joiner, sql: qf + " " + op + " ?", params: [value] });
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
  raw(sql, params) {
    if (typeof sql !== "string" || sql.length === 0) {
      throw new Error("WhereBuilder.raw: sql must be a non-empty string");
    }
    var p = Array.isArray(params) ? params : (params == null ? [] : [params]);
    if (_countPlaceholders(sql) !== p.length) {
      throw new Error("WhereBuilder.raw: placeholder count mismatch");
    }
    this._parts.push({ joiner: "AND", sql: "(" + sql + ")", params: p });
    return this;
  }
  build() {
    if (this._parts.length === 0) return { sql: "", params: [] };
    var sql = this._parts[0].sql;
    var params = this._parts[0].params.slice();
    for (var i = 1; i < this._parts.length; i += 1) {
      sql = sql + " " + this._parts[i].joiner + " " + this._parts[i].sql;
      for (var j = 0; j < this._parts[i].params.length; j += 1) {
        params.push(this._parts[i].params[j]);
      }
    }
    return { sql: sql, params: params };
  }
}

// Count `?` placeholders outside string literals + comments.
// Tracks SQL single-quoted, double-quoted, line-comment, and block-
// comment state to avoid counting `?` characters that are part of
// literal text the SQL engine never interprets as a binding marker.
function _countPlaceholders(sql) {
  var count = 0;
  var i = 0;
  var len = sql.length;
  while (i < len) {
    var ch = sql.charAt(i);
    var next = i + 1 < len ? sql.charAt(i + 1) : "";
    if (ch === "'" || ch === '"') {
      var quote = ch;
      i += 1;
      while (i < len) {
        if (sql.charAt(i) === quote) {
          // SQL doubles the quote char to escape it within a literal.
          if (sql.charAt(i + 1) === quote) { i += 2; continue; }
          i += 1; break;
        }
        i += 1;
      }
      continue;
    }
    if (ch === "-" && next === "-") {
      while (i < len && sql.charAt(i) !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < len && !(sql.charAt(i) === "*" && sql.charAt(i + 1) === "/")) i += 1;
      i += 2;
      continue;
    }
    if (ch === "?") count += 1;
    i += 1;
  }
  return count;
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

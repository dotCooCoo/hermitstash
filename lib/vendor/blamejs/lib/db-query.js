// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 * SQL construction composes b.sql (lib/sql.js): every terminal builds a
 * b.sql verb builder ({ dialect: "sqlite" }, the local node:sqlite
 * backend), replays the recorded structured WHERE conditions onto it, and
 * calls .toSql() for the { sql, params } pair — which db-query then
 * prepares + runs on the local sqlite handle. b.sql owns identifier
 * quoting (through b.safeSql), value binding (every value a `?`
 * placeholder), IN-list expansion, LIKE auto-escape, and the output
 * validator (_assertEmittable). db-query keeps everything b.sql cannot
 * know about: the residency write-gate, sealed-row seal/unseal, _id
 * auto-generation, per-row-key materialization, the column-membership
 * gate, sealed-field → derived-hash translation, and the JSONB/JSON-path
 * value guard — all applied at condition-record / row-build time, before
 * the structured shape reaches b.sql.
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
var sql = require("./sql");
var audit = require("./audit");
var lazyRequire = require("./lazy-require");
var { DbQueryError } = require("./framework-error");
var numericBounds = require("./numeric-bounds");

// Circular load — db.js requires db-query at module scope, so the
// residency gate reaches back for getDataResidency() lazily.
var db = lazyRequire(function () { return require("./db"); });

// Cross-border regulated postures live on b.compliance
// (CROSS_BORDER_REGULATED_POSTURES — one vocabulary shared with
// external-db's gate): under these, a residency mismatch REFUSES the
// write; under anything else the gates emit an advisory audit and
// pass (backward-compatible).
function _postureState() {
  try {
    var compliance = require("./compliance");                                     // allow:inline-require — defensive against optional load
    var posture = compliance.current();
    return { posture: posture, regulated: compliance.isCrossBorderRegulated(posture) };
  } catch (_e) { return { posture: null, regulated: false }; }
}

// Local-SQLite write-residency gate (GDPR Art 44-46 / PIPL Art 38 /
// DPDP §16 cross-border transfer restrictions). Runs on the PLAINTEXT
// row before sealRow so the tag column is readable even when other
// columns seal. Two layers:
//
//   1. Per-ROW tag (declarePerRowResidency): on INSERT the declared
//      column must be present and within allowedTags; under a
//      regulated posture a tag outside the deployment's region set
//      ({ region } + allowedStorageRegions from db.init's
//      dataResidency) refuses the write. UPDATEs gate only when the
//      change set touches the residency column (an update that does
//      not move residency is not a transfer).
//   2. Per-COLUMN tags (declareColumnResidency): the long-advertised
//      assertColumnResidency gate, enforced here against the
//      deployment region. Operators tag columns with the region
//      value their dataResidency declares.
//
// Unregulated postures audit (drop-silent) and pass; tables with no
// declaration are untouched.
// Resolve a column in a raw-SQL-parsed row case-insensitively (SQL unquoted
// identifiers fold case; the parser preserves the token). Exact match wins
// first so a structured-builder row (keys already canonical) is unaffected.
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
    // SQL unquoted identifiers are case-insensitive, and the raw-SQL parser
    // preserves the column token's case — so resolve the residency column
    // case-insensitively. A case-sensitive lookup let `UPDATE t SET REGION=...`
    // miss a `residencyColumn: "region"` declaration, skipping the gate and
    // admitting a cross-border write (CWE-178 / CWE-863). Fail-safe: any
    // spelling that could be the residency column engages the gate.
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
    // An UPDATE that explicitly sets the residency column to null /
    // undefined would clear the row's region binding (INSERT refuses a
    // missing tag; the same row must not be nullable into an untagged
    // state on update). UPDATEs that don't touch the column pass.
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
  constructor(database, tableName, opts) {
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
    // Recorded WHERE chain — an ordered list of leaves. Each leaf is
    // { joiner, apply(predicate) } where apply() replays the leaf onto a
    // b.sql Predicate (or builder) using its where-family methods. The
    // sealed-field translation, JSONB value guard, and column-membership
    // gate run at record time (in _addCondition / whereRaw / search /
    // whereGroup / orWhere), so the recorded shape is already safe; the
    // terminal just replays it through b.sql, which owns quoting +
    // binding + the output validator.
    this._conditions    = [];
    this._select        = null;
    this._orderBy       = null;
    this._limit         = null;
    this._offset        = null;

    // Column-membership gate. `db.from()` passes the table's
    // declared columns + the configured gate mode so an operator-
    // supplied column name that isn't a real column of the table is
    // refused before it interpolates into SQL as an identifier
    // (ORDER-BY / sealed-column-disclosure injection — CWE-89 /
    // CWE-1336). A bare `new Query(db, name)` with no opts leaves the
    // gate disabled (declaredColumns null), so direct/internal
    // construction is unaffected.
    opts = opts || {};
    this._declaredColumns = (opts.declaredColumns instanceof Set) ? opts.declaredColumns
      : (Array.isArray(opts.declaredColumns) ? new Set(opts.declaredColumns) : null);
    this._columnGateMode  = opts.columnGateMode || "reject";
    this._allowedColumns  = null;
    // PRIMARY KEY column for the dialect-aware single-row write idiom on
    // non-sqlite handles (sqlite uses the implicit rowid). db.from() tables
    // key on `_id`; a table with a different PK declares it here. Validated
    // as an identifier so it can splice into SQL as a quoted column.
    if (opts.primaryKey !== undefined && opts.primaryKey !== null) {
      safeSql.validateIdentifier(opts.primaryKey, { allowReserved: true });
      this._primaryKey = opts.primaryKey;
    } else {
      this._primaryKey = null;
    }
  }

  // Restrict the operator-allowable columns to an explicit subset
  // (tighter than the schema-declared set). Use when a query is built
  // from request input and must only ever touch a known-safe list.
  // Throws on a non-array or an invalid identifier.
  allowedColumns(cols) {
    if (!Array.isArray(cols) || cols.length === 0) {
      throw new TypeError("allowedColumns(cols): expected a non-empty array of column names");
    }
    cols.forEach(_validateField);
    this._allowedColumns = new Set(cols);
    return this;
  }

  // Assert `field` is a member of the allowed/declared column set
  // before it is interpolated into SQL as an identifier. The operator
  // `allowedColumns()` set (when present) is ALWAYS enforced; the
  // schema gate respects the configured mode ("reject" default
  // throws | "warn" drop-silent audits + allows | "off" / no declared
  // set skips).
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

  // Resolve the SQL dialect for the handle this Query runs against.
  // db.from() drives the framework's local node:sqlite handle (dialect
  // "sqlite", the default). An operator who constructs `new Query(handle,
  // table)` over their OWN Postgres / MySQL handle declares the dialect on
  // the handle via `handle.dialect` ("postgres" | "mysql"), so b.sql emits
  // the matching identifier quoting + single-row-write idiom. An unknown /
  // absent value falls back to "sqlite" — the historical default — so every
  // existing caller is byte-identical.
  _dialect() {
    var d = this._db && this._db.dialect;
    if (d === "postgres" || d === "mysql" || d === "sqlite") return d;
    return "sqlite";
  }

  // The b.sql opts for every terminal's verb builder. The dialect is
  // resolved from the handle (sqlite by default; the operator's external
  // handle can declare postgres / mysql). quoteName forces b.sql to QUOTE
  // the resolved table name: db-query does NO clusterStorage prefix rewrite,
  // so it never needs the bare-unquoted form — and quoting preserves
  // db-query's reserved-word / case-sensitive table-name support (`"name"`
  // is the safe identifier form). The schema qualifier (when present) makes
  // b.sql emit the quoted `"schema"."table"` form. db-query owns the column
  // gate (sealed-field rewrite happens before b.sql sees a column), so the
  // builder's own gate stays off.
  _sqlOpts() {
    return this._schema
      ? { dialect: this._dialect(), schema: this._schema, quoteName: true }
      : { dialect: this._dialect(), quoteName: true };
  }

  // Whether any WHERE condition has been recorded — drives the
  // unconditional-update / -delete / -increment refusals.
  _hasConditions() {
    return this._conditions.length > 0;
  }

  // Replay the recorded WHERE chain onto a b.sql verb builder. The whole
  // chain is wrapped in one b.sql whereGroup so the leaves' AND/OR
  // joiners compose at a single precedence level (and a no-condition
  // chain leaves the builder's where untouched). Returns the builder.
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

  // whereIn(field, values) — AND an `IN (...)` membership predicate. Facade
  // over where(field, "IN", values) symmetric with b.sql's whereIn, so a
  // caller can match a column against a value list (e.g. the dual-read
  // derived-hash candidate set) without spelling the "IN" operator.
  whereIn(field, values) {
    return this.where(field, "IN", values);
  }

  // whereNull / whereNotNull — explicit NULL predicates (IS NULL / IS NOT
  // NULL). `where({ field: null })` / `where(field, "=", null)` is refused
  // because `col = NULL` is UNKNOWN in SQL (never true); these are the
  // intended way to test a column for NULL.
  whereNull(field) {
    return this.where(field, "IS", null);
  }
  whereNotNull(field) {
    return this.where(field, "IS NOT", null);
  }

  // Resolve a (field, op, value) predicate through the framework gates
  // (JSONB value guard, sealed-field → derived-hash rewrite, column
  // membership) and return the post-rewrite { field, op, value } that
  // b.sql will emit. Shared by _addCondition and the WhereBuilder so the
  // gates run identically whether the leaf is top-level or grouped.
  _resolvePredicate(field, op, value) {
    if (!ALLOWED_OPS.has(op)) {
      throw new Error("invalid where operator: " + op);
    }
    // JSONB / JSON-path injection guard. Routes operator-
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
      var missingHashMsg =
        "cannot query sealed column '" + this._cryptoFieldKey() + "." + field +
        "' without a derived hash. Declare derivedHashes: { <name>: { from: '" + field + "' } } " +
        "in the table's schema config.";
      if (op === "IN") {
        // Membership query on a sealed column: each candidate plaintext maps
        // to its own derived hash. Hashing the whole array as one value (the
        // scalar path below) never matches — whereIn/$in on a sealed column
        // would throw or silently miss. Expand to the per-element hash set,
        // and for each element ALSO include the legacy salted-sha3 digest so
        // membership dual-reads across the v0.15.0 keyed-MAC flip exactly as
        // the "=" path does (un-migrated rows must still be found).
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
          // Dual-read across the v0.15.0 keyed-MAC default flip: a row written
          // before the flip carries the legacy salted-sha3 digest, so an
          // equality lookup on a sealed field must match BOTH the active
          // keyed-MAC digest and the legacy one — otherwise the flip silently
          // drops every un-migrated row from the result. b.sql expands the
          // IN-list to (?, ?) and binds each digest.
          op = "IN";
          value = [lookup.value, lookup.legacyValue];
        } else {
          value = lookup.value;
        }
      }
    }
    _validateField(field);
    // Gate the post-sealed-rewrite physical column (derived-hash
    // columns are declared physical columns, so the rewrite target
    // passes membership).
    this._assertColumnMember(field, "where");
    if (op === "IN") {
      // node:sqlite ? does not support array-binding; b.sql expands the
      // IN-list to (?, ?, ?) and binds each element. Validate the shape
      // here so the failure is db-query's clear message, not a builder
      // error deeper in the stack.
      if (!Array.isArray(value) || value.length === 0) {
        throw new Error("where IN requires a non-empty array of values");
      }
    }
    return { field: field, op: op, value: value };
  }

  // Apply a resolved predicate onto a b.sql Predicate using the given
  // joiner ("AND" via where* / "OR" via orWhere*). LIKE auto-escape,
  // IN-list expansion, IS NULL, and JSONB emission are all owned by
  // b.sql's _cmp from here.
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

  // Append a WHERE leaf. `apply(pred)` replays it onto a b.sql Predicate
  // (AND-joined at the chain level — the leaf's own apply decides AND vs
  // OR internally). orWhere() rewrites the last leaf rather than
  // appending, to preserve `(prev OR new)` grouping precedence.
  _pushLeaf(joiner, apply) {
    this._conditions.push({ joiner: joiner, apply: apply });
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
  // .where() (AND-joined). The fragment must NOT contain operator-
  // supplied SQL — it's caller-controlled text used to build expressions
  // the chainable .where() can't express (compound OR, row-value
  // comparison for cursor pagination, etc.). b.sql's whereRaw guards the
  // fragment (b.guardSql + embedded-literal + placeholder-count); the
  // count + literal validation that db-query historically did inline now
  // lives in that one choke-point.
  whereRaw(sql_, params, opts) {
    if (typeof sql_ !== "string" || sql_.length === 0) {
      throw new Error("whereRaw: sql must be a non-empty string");
    }
    var p = Array.isArray(params) ? params.slice() : (params == null ? [] : [params]);
    // Fail-fast at the chain-build boundary (matching the pre-b.sql
    // contract — the operator catches a bad fragment at the whereRaw call,
    // not deep inside a terminal). The embedded-literal + placeholder-count
    // refusals keep db-query's stable SafeSqlError `sql/raw-literal` /
    // explicit count-mismatch contract; b.sql's whereRaw (applied at the
    // terminal) is the additional emission-time guard (b.guardSql, stacked-
    // statement, encoding). allowLiterals opts the operator out of the
    // literal refusal for a static, operator-controlled literal.
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

  // ---- Build SELECT components on a b.sql builder ----

  // Apply the recorded projection / order / limit / offset onto a b.sql
  // SELECT builder. Projection columns + orderBy fields already passed
  // _validateField + the column gate at record time.
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

  // ---- Terminal methods (sync) ----

  first() {
    var qb = sql.select(this._table, this._sqlOpts());
    this._applyConditions(qb);
    this._applySelectClauses(qb);
    qb.limit(1);
    var built = qb.toSql();
    var stmt = this._db.prepare(built.sql);
    var row = stmt.get.apply(stmt, built.params);
    // 4th arg (dbHandle) lets unsealRow fetch + unwrap the row-scoped
    // K_row for vault.row: cells (declarePerRowKey tables).
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

  // Streaming counterpart to all(). Each row is auto-unsealed against
  // the bound table's sealedFields registration before it lands in the
  // operator's pipeline. For large result sets (audit exports, backup
  // table dumps) this avoids materializing the full rowset in memory.
  // StreamLimit ceiling enforced from the module-level db
  // config; per-call opts.streamLimit overrides for one-off bumps.
  stream(opts) {
    var qb = sql.select(this._table, this._sqlOpts());
    this._applyConditions(qb);
    this._applySelectClauses(qb);
    var built = qb.toSql();
    var perCallLimit;
    // db.js exports getStreamLimit so this module reads the live
    // ceiling without bouncing through the lib's circular load.
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
    // Residency gates read the PLAINTEXT row (the tag column must be
    // inspectable even when sibling columns seal below).
    _assertLocalResidency(this._cryptoFieldKey(), withId, "insert");
    // Per-row-key tables (declarePerRowKey): materialize a fresh K_row
    // BEFORE sealRow so sealed columns encrypt under the row-scoped key
    // (vault.row: cells). rowId MUST be withId._id — the same value
    // b.subject.eraseHard / b.retention destroy on, so a later shred
    // makes these cells undecryptable. Materialize stores the random
    // row-secret AAD-sealed in the per-row-key store.
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
    if (!this._hasConditions()) {
      throw new Error("refusing unconditional update — call where(...) first");
    }
    // Residency gates on the plaintext change set — an UPDATE that
    // touches the residency tag (or a region-bound column) is a
    // transfer and goes through the same refusal matrix as INSERT.
    _assertLocalResidency(this._cryptoFieldKey(), changes, "update");
    var cfKey = this._cryptoFieldKey();
    // Per-row-key tables: sealed columns must re-encrypt under EACH
    // affected row's own K_row, so a single set-based UPDATE can't seal
    // one value across rows. Resolve the affected _id set, then seal +
    // write each row under its row-scoped key. Idempotent materialize
    // re-derives the existing K_row (created on INSERT).
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

    // No engine ships a portable UPDATE ... LIMIT, so a single-row update
    // resolves exactly one row then writes it. The shape is dialect-aware
    // (sqlite rowid sub-select / postgres PK sub-select / mysql
    // resolve-then-write — _buildSingleRowWrite). A null result means the
    // WHERE matched no row, so there is nothing to update (0 changes).
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

  // The single-row-write row locator, by dialect. No engine ships
  // UPDATE ... LIMIT portably (node:sqlite is built without
  // SQLITE_ENABLE_UPDATE_DELETE_LIMIT), so the single-row idiom is a
  // sub-SELECT that resolves exactly one row then matches it:
  //
  //   sqlite   — the implicit `rowid` system column (every non-WITHOUT-
  //              ROWID table has one); `WHERE "rowid" = (SELECT "rowid"
  //              FROM t WHERE ... LIMIT 1)`.
  //   postgres — the table's PRIMARY KEY (`_id`, the db.from() convention).
  //              Postgres accepts LIMIT in a scalar subquery, so the same
  //              `= (SELECT "_id" ... LIMIT 1)` shape works — and using the
  //              real, UNIQUE `_id` column keeps b.sql's quote-by-
  //              construction intact (ctid is an unquotable system column
  //              that would force a raw-identifier escape and is unstable
  //              across VACUUM).
  //   mysql    — also the PRIMARY KEY, but MySQL refuses LIMIT in a
  //              subquery that directly references the same table in an
  //              `IN`/`=` predicate; wrapping the inner SELECT in a derived
  //              table (`... IN (SELECT "_id" FROM (SELECT "_id" ... LIMIT
  //              1) AS _s)`) is the standard work-around.
  //
  // The inner SELECT is composed through b.sql (same table + conditions)
  // and spliced via whereSub — passing the inner BUILDER (not concatenated
  // SQL) so b.sql concatenates the sub-query's sql + params itself and the
  // final statement still runs through b.sql's output validator.
  _rowLocatorColumn(dialect) {
    return dialect === "sqlite" ? "rowid" : this._pkColumn();
  }

  // The PRIMARY KEY column for single-row writes on non-sqlite dialects.
  // db.from() tables key on `_id` (auto-generated when absent on insert);
  // an operator running a table with a different PK overrides it via the
  // `primaryKey` construction opt.
  _pkColumn() {
    return this._primaryKey || "_id";
  }

  _buildSingleRowWrite(sealed) {
    if (this._dialect() === "mysql") {
      // MySQL forbids referencing the UPDATE/DELETE target table in a
      // subquery (error 1093), so the single-statement sub-SELECT idiom
      // the other dialects use is unavailable. Resolve the one row's PK in
      // a prior SELECT, then write `WHERE pk = ?` with the resolved value
      // bound — every value still binds, the identifier still quotes by
      // construction, and the write is a single validated statement with no
      // self-referential subquery. Returns null when no row matched.
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

  // Resolve the PK of exactly one row matching the recorded WHERE (LIMIT
  // 1). Used by the MySQL single-row write path, where a self-referential
  // subquery is rejected by the engine. The SELECT is a clean, fully-bound
  // b.sql statement; returns the PK value, or null when nothing matched.
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

  // Per-row-key UPDATE. Sealed columns on a declarePerRowKey table are
  // K_row cells (vault.row:), so each affected row must be re-sealed
  // under its OWN K_row — a single set-based UPDATE can't carry per-row
  // ciphertext. Resolve the affected _id set via the WHERE, then for
  // each row: materialize (idempotent) its K_row, seal the change set
  // under it (derived hashes computed from plaintext as usual), and
  // UPDATE that single row by _id. `single` stops after the first row.
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

  // Atomic counter increment.
  //
  // `from(table).where(filter).increment("col", 1)` emits
  // `UPDATE table SET col = COALESCE(col, 0) + ? WHERE ...` so concurrent
  // writers can't collide on a fetch/mutate/store sequence (which would
  // lose increments under racing transactions). Pass a negative delta to
  // decrement.
  //
  // Returns the number of rows changed (matches updateMany shape).
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
    // Use COALESCE so a NULL counter starts at 0 instead of producing
    // NULL + delta = NULL silently (which would silently drop the
    // operation under SQLite's NULL-arithmetic rules). The quoted column
    // expression is built by b.safeSql under the active dialect so the
    // increment RHS references the same quoted identifier b.sql's set
    // target uses (double-quote on sqlite/postgres, backtick on mysql).
    var qc = safeSql.quoteIdentifier(column, this._dialect(), { allowReserved: true });
    var qb = sql.update(this._table, this._sqlOpts())
      .setRaw(column, "COALESCE(" + qc + ", 0) + ?", [delta]);
    this._applyConditions(qb);
    var built = qb.toSql();
    var stmt = this._db.prepare(built.sql);
    var info = stmt.run.apply(stmt, built.params);
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
    var sub = new WhereBuilder(this);
    closure(sub);
    if (sub._parts.length === 0) return this;
    this._pushLeaf("AND", function (pred) {
      pred.whereGroup(function (g) { sub.replay(g); });
    });
    return this;
  }

  // Top-level OR — extends the existing where-chain so
  // `.where(a).orWhere(b)` produces `WHERE (a) OR (b)` rather than
  // `WHERE (a) AND (b)`. Accepts the same arg shapes as `.where`:
  // object-literal map, `(field, value)`, `(field, op, value)`, or a
  // `(qb) => ...` closure. Replays as `(prevLeaf OR newLeaf)` so the
  // grouping precedence matches the pre-b.sql `( prev OR ( new ) )` form.
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
        // Empty OR closure — restore the prior leaf untouched.
        this._conditions.push(prevLeaf);
        return this;
      }
      orApply = function (pred) {
        pred.orWhereGroup(function (g) { sub.replay(g); });
      };
    } else if (fieldOrObjOrFn !== null && typeof fieldOrObjOrFn === "object" &&
               !Array.isArray(fieldOrObjOrFn)) {
      // Object map — all equalities OR'd as one group leaf.
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
      // 2-arg orWhere(field, value) is the equality shorthand; 3-arg
      // orWhere(field, op, value) carries an explicit operator. Mirror
      // .where()'s arguments.length discrimination so a 2-arg value of
      // (e.g.) the number 5 is never mistaken for an operator.
      var resolved = (argc === 2)
        ? this._resolvePredicate(fieldOrObjOrFn, "=", op)
        : this._resolvePredicate(fieldOrObjOrFn, op, value);
      var selfP = this;
      orApply = function (pred) {
        selfP._emitPredicate(pred, "OR", resolved.field, resolved.op, resolved.value);
      };
    }
    // Re-push a single leaf that emits ( prevLeaf OR newLeaf ).
    this._pushLeaf("AND", function (pred) {
      pred.whereGroup(function (g) {
        prevLeaf.apply(g);
        orApply(g);
      });
    });
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
    // b.sql's whereLike owns the wildcard handling end-to-end: it escapes
    // the user's `%` / `_` metacharacters with `~`, adds the LIVE wrapping
    // wildcard per mode, and emits `"field" LIKE ? ESCAPE '~'` (a
    // builder-emitted ESCAPE clause, so no raw-fragment guard refusal). An
    // OR group across every search field; the first leaf leads, the rest
    // OR-join.
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
    if (!Number.isInteger(limit) || limit <= 0 || limit > 1000) {                          // paginate page-size cap, not bytes
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
      // No engine ships a portable DELETE ... LIMIT, so single-row delete
      // mirrors the single-row update idiom: sqlite splices a rowid
      // sub-select, postgres a PK sub-select (both via b.sql whereSub, the
      // inner builder object — b.sql concatenates the sub-query's sql +
      // params, no hand-rolled string), and mysql resolves the one PK in a
      // prior SELECT then deletes `WHERE pk = ?` (the engine forbids a
      // subquery referencing the DELETE target table). A null PK means the
      // WHERE matched nothing — 0 rows deleted.
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

// WhereBuilder — sub-expression builder used by Query.whereGroup() and
// Query.orWhere((qb) => ...) to compose grouped AND/OR predicates that
// the bare .where() chain (which only ANDs) can't express.
//
// Each `.eq` / `.neq` / `.gt` / `.gte` / `.lt` / `.lte` / `.in` /
// `.like` call ANDs an expression; `.orEq` / `.orNeq` / `.orGt` /
// `.orGte` / `.orLt` / `.orLte` / `.orIn` / `.orLike` ORs an
// expression. `.raw(sql, params)` AND's an arbitrary fragment.
//
// Each part is recorded structurally ({ joiner, kind, ... }) and replayed
// onto a b.sql Predicate via replay(pred) — b.sql owns the quoting +
// binding + LIKE escape + IN-list expansion. The owning Query runs the
// column-membership gate as each part is recorded.
class WhereBuilder {
  constructor(gate) {
    this._parts = [];   // [{ joiner, kind: "cmp"|"raw", ... }]
    // The owning Query, so grouped/OR sub-expressions enforce the
    // same column-membership gate as the top-level chain.
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
    // Same fail-fast literal + placeholder-count contract as Query.whereRaw
    // (stable SafeSqlError code); b.sql re-guards at the terminal.
    if (!(opts && opts.allowLiterals === true)) _assertRawNoStringLiteral(sql_, "WhereBuilder.raw");
    if (safeSql.countPlaceholders(sql_) !== p.length) {
      throw new Error("WhereBuilder.raw: placeholder count mismatch");
    }
    this._parts.push({ joiner: "AND", kind: "raw", sql: sql_, params: p, opts: opts });
    return this;
  }
  // Replay the recorded parts onto a b.sql Predicate. The first part
  // leads the group (its joiner is the group's first leaf); each later
  // part AND/OR-joins per its recorded joiner. b.sql performs identifier
  // quoting, value binding, and IN-list expansion.
  replay(pred) {
    for (var i = 0; i < this._parts.length; i++) {
      _replayPart(pred, this._parts[i], this._parts[i].joiner === "OR" && i > 0);
    }
  }
  build() {
    // Back-compat shim for any external reader that called build() to get
    // a { sql, params } pair. Replay onto a transient b.sql SELECT's
    // predicate and extract. Returns { sql: "", params: [] } when empty.
    if (this._parts.length === 0) return { sql: "", params: [] };
    var self = this;
    var built = sql.select("t", { dialect: "sqlite" })
      .whereGroup(function (g) { self.replay(g); })
      .toSql();
    // Strip the "SELECT * FROM t WHERE (" prefix + trailing ")".
    var m = /WHERE \((.*)\)$/.exec(built.sql);
    return { sql: m ? m[1] : "", params: built.params };
  }
}

// Refuse a raw SQL fragment that embeds a single-quoted string literal.
// A whereRaw / WhereBuilder.raw fragment is a STATIC template whose every
// value binds through a `?` placeholder; an embedded `'...'` literal is
// the signature of operator input concatenated into the query builder
// (CWE-89 / CWE-564). Double-quoted identifiers (`"col"`), line comments,
// and block comments are skipped. Operators with a deliberate static
// literal pass `{ allowLiterals: true }`. db-query runs this eagerly at
// the chain-build boundary so the operator-facing `sql/raw-literal`
// SafeSqlError contract is stable; b.sql's whereRaw re-guards the same
// fragment at the terminal (b.guardSql + the emission-time validator).
// Single linear pass, no backtracking regex; shares the scan shape with
// b.safeSql.countPlaceholders.
function _assertRawNoStringLiteral(rawSql, where) {
  // Routes through the shared safeSql scanner; the default error reproduces
  // this module's exact SafeSqlError("sql/raw-literal") message.
  safeSql.assertNoRawStringLiteral(rawSql, where);
}

// Apply one recorded WhereBuilder part onto a b.sql Predicate. `or`
// selects the OR-joining method (after the first leaf in a group); the
// first leaf ignores its joiner (it leads the group). NOT IN and LIKE
// are the two ops with a behavior the bare structured Predicate does not
// expose 1:1: NOT IN has no orWhere* form, and the WhereBuilder LIKE is a
// caller-controlled-wildcard LIKE (the value binds verbatim — no
// auto-escape, matching the pre-b.sql WhereBuilder semantics, distinct
// from .search() which escapes). Both compose through the guarded raw /
// group surface without weakening anything.
function _replayPart(pred, part, or) {
  if (part.kind === "raw") {
    if (or) pred.orWhereRaw(part.sql, part.params, part.opts);
    else pred.whereRaw(part.sql, part.params, part.opts);
    return;
  }
  if (part.op === "LIKE") {
    // Verbatim LIKE — caller controls the wildcards (no escape clause),
    // exactly as the pre-migration WhereBuilder emitted `"f" LIKE ?`. The
    // identifier quoting follows the predicate's OWN dialect (the builder
    // it replays onto), so the LIKE column matches the surrounding query's
    // quoting on mysql (backtick) as well as sqlite/postgres (double-quote).
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
    // b.sql exposes no orWhereNotIn; emit an OR NOT-IN leaf as a
    // single-member OR group so the join precedence is preserved.
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
      !safeSql.DEFAULT_IDENTIFIER_RE.test(field)) {
    throw new Error("invalid field name: '" + field +
      "' (must match " + safeSql.DEFAULT_IDENTIFIER_RE + ", length 1.." +
      safeSql.MAX_IDENTIFIER_LENGTH + ")");
  }
}

// ---- raw-write residency gate (execRaw / prepared-statement execution) ----
// The structured builder runs every insert/update through _assertLocalResidency.
// The raw paths (b.db.runSql / execRaw, b.db.prepare(sql).run(...)) bypass it, so
// a cross-border row could land straight on disk under a regulated posture. These
// helpers extract the residency-column value from a raw INSERT / UPDATE / REPLACE
// and run it through the SAME gate; a write to a residency table the framework
// cannot parse fails CLOSED (refused) - a raw write never skips the check.
var _RAW_WRITE_KEYWORD_RE = /^\s*(?:INSERT|REPLACE|UPDATE)\b/i;
var _RAW_INSERT_RE = /^\s*(?:INSERT|REPLACE)\s+(?:OR\s+[A-Za-z]+\s+)?INTO\s+(?:[\x22\x27\x60]?[A-Za-z_]\w*[\x22\x27\x60]?\s*\.\s*){0,3}[\x22\x27\x60]?([A-Za-z_]\w*)[\x22\x27\x60]?\s*\(([^)]+)\)\s*VALUES\s*\(([\s\S]+)\)\s*;?\s*$/i;
var _RAW_UPDATE_RE = /^\s*UPDATE\s+(?:[\x22\x27\x60]?[A-Za-z_]\w*[\x22\x27\x60]?\s*\.\s*){0,3}[\x22\x27\x60]?([A-Za-z_]\w*)[\x22\x27\x60]?\s+SET\s+([\s\S]+?)\s*;?\s*$/i;
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

// Strip LEADING SQL comments + whitespace so the ^-anchored write-detection
// regexes see the real statement head. Without this, a residency write smuggled
// behind a leading "/* x */" or "-- x\n" comment is NOT recognized as a write →
// the residency gate is skipped entirely (a cross-border-write BYPASS). The
// executed SQL is unchanged; this normalized copy is only for the gate's parse.
// Each replace is ^-anchored single-pass; the loop terminates when nothing more
// is stripped (an unterminated /* leaves the head intact → write still detected
// or fails closed downstream).
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

// Non-anchored write-target scan for the writable-CTE / EXPLAIN-prefixed case.
// A SQLite `WITH c AS (...) INSERT INTO residents ...` / `WITH ... UPDATE residents
// SET ...` is a real write, but its effective verb is hidden behind the prefix so
// the ^-anchored _RAW_WRITE_KEYWORD_RE misses it. This matches every INSERT/REPLACE
// INTO, MERGE INTO, and UPDATE ... SET target token anywhere in the statement and
// returns the first that names a residency table — so such a write still ENGAGES
// the residency gate (_assertRawWriteResidency then fails CLOSED: the ^-anchored
// body parsers can't read a CTE body, so it throws row-residency-raw-unparseable
// directing the operator to b.db.from().insertOne/.updateOne). DELETE moves no
// residency value across a border, so it is not a residency write. Linear scan.
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
  // The ^-anchored regexes scan only the statement head (constant-time). Strip
  // leading comments first so a commented-out head can't hide the write.
  if (typeof sql !== "string") return null;
  var s = _stripLeadingSqlComments(sql);
  if (_RAW_WRITE_KEYWORD_RE.test(s)) {  // allow:regex-no-length-cap
    var m = _RAW_TABLE_RE.exec(s);  // allow:regex-no-length-cap
    return m ? _unquoteIdent(m[1] || m[2]) : null;
  }
  // Writable-CTE / EXPLAIN-prefixed write: the effective write verb is hidden
  // behind the prefix the ^-anchored test misses. If it writes a residency table,
  // return it so the gate engages and then fails closed on the unparseable body.
  if (/^\s*(?:WITH|EXPLAIN)\b/i.test(s)) {  // allow:regex-no-length-cap
    return _firstResidencyWriteTarget(s);
  }
  return null;
}

// Cheap prepare-time pre-check so only writes to a residency table get wrapped.
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

// Quote/paren-aware: return the SET-clause text up to the first top-level
// WHERE keyword that is NOT inside a string literal or parenthesised
// subexpression. A WHERE embedded in a quoted value (SET note='x WHERE
// y', ...) is skipped, so a residency-column assignment after it is still
// parsed and gated. Linear scan; fixed 5-char keyword peek, no per-char slice.
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
  return tok;  // bare expression / named param: opaque -> fails the allowedTags check -> refused
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

  // Parse the comment-stripped head: a leading "/* x */" / "-- x" comment must
  // not hide the INSERT/UPDATE body from the ^-anchored regexes below (that would
  // let a residency-restricted write through the gate). The executed SQL is
  // unchanged; this normalized copy is only for residency parsing.
  var norm = _stripLeadingSqlComments(sql);

  // The INSERT/UPDATE body regexes below scan with [\s\S]+; bound the input
  // first and fail CLOSED on an over-long statement - a residency write the
  // framework cannot safely parse must be refused, never let past the gate.
  if (norm.length > 100000) {
    throw new DbQueryError("db-query/row-residency-raw-unparseable",
      "raw write to residency table '" + table + "' exceeds the parse limit (" +
      norm.length + " chars) - use b.db.from(\"" + table + "\") so residency is validated", true);
  }

  var mi = _RAW_INSERT_RE.exec(norm);  // allow:regex-no-length-cap — input length-capped above
  var mu = mi ? null : _RAW_UPDATE_RE.exec(norm);  // allow:regex-no-length-cap — input length-capped above
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
  // Shared leading-comment stripper so db.js's storage-low write-gate sees the
  // real statement head (a `/* x */ INSERT` / WITH-prefixed write must not slip
  // the ENOSPC gate the way it slipped the residency gate).
  _stripLeadingSqlComments:    _stripLeadingSqlComments,
};

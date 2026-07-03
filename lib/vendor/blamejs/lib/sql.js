// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.sql
 * @nav        Validation
 * @title      SQL Builder
 * @order      90
 * @featured   true
 *
 * @intro
 *   Chainable SQL builder that makes hand-rolled SQL impossible. Every
 *   table and column name is quoted by construction through
 *   `b.safeSql`; every value is a bound `?` placeholder, never
 *   string-interpolated. The builder emits BARE logical table names and
 *   `?` placeholders - `b.clusterStorage` rewrites bare framework tables
 *   to their cluster-prefixed names and translates `?` to `$N` for
 *   Postgres at execute time - so one query text runs unchanged against
 *   the local SQLite single-node backend and the operator-supplied
 *   external Postgres / MySQL in cluster mode.
 *
 *   The terminal call is `.toSql()` returning `{ sql, params }`. Pass
 *   that straight to `b.clusterStorage.execute(sql, params)`. The
 *   builder never touches the database itself - it is a pure SQL-string
 *   composer, which keeps it free of the residency / sealed-column
 *   write-path concerns that `db.from(...)` (the executing query
 *   builder, `lib/db-query.js`) owns.
 *
 *   Only `upsert` emits dialect-final syntax (Postgres / SQLite
 *   `ON CONFLICT ... DO UPDATE`, MySQL `ON DUPLICATE KEY UPDATE`); every
 *   other verb stays `?`-placeholder + double-quote and defers the
 *   dialect rewrite to `b.clusterStorage`. Joins, common-table
 *   expressions, scalar and `IN`/`EXISTS` subqueries, grouping,
 *   aggregates, and `RETURNING` are all composable. DDL builders
 *   (`createTable` / `createIndex` / `alterTable` / `dropTable`) reuse
 *   the framework's own type map so operator app-schema tables get the
 *   same quote-by-construction guarantee the framework tables get.
 *
 *   Safety defaults are not opt-in: `update` and `delete` THROW without a
 *   `where()` unless `allowNoWhere` is set; a column-membership gate
 *   refuses unknown columns; `LIKE` auto-escapes `%` / `_` / `\` and
 *   emits the matching `ESCAPE`; raw fragments pass through `b.guardSql`
 *   (strict by default on the request path) plus the placeholder-count
 *   and embedded-literal scanners.
 *
 * @card
 *   Chainable SQL builder - every identifier quoted by construction, every value a bound placeholder, dialect-aware upsert.
 */

var safeSql = require("./safe-sql");
var frameworkSchema = require("./framework-schema");
var safeJson = require("./safe-json");
var safeJsonPath = require("./safe-jsonpath");
var lazyRequire = require("./lazy-require");
var C = require("./constants");
var { FrameworkError } = require("./framework-error");

// Output-validation bounds (enforced by _assertEmittable on every build).
// Two scopes: statement-level (the whole emitted text + total bind count)
// and column-level (each individual bound value).
//
// MAX_SQL_BYTES: a runaway/DoS ceiling on the emitted statement text - a
// build this large is a bug (an unbatched bulk insert, a pathological
// IN-list), never a legitimate single statement. MAX_BIND_PARAMS: the
// wire-protocol bind-parameter ceiling - Postgres + MySQL cap a statement
// at 65535 parameters (exceeding it is a hard driver error), and SQLite's
// default SQLITE_MAX_VARIABLE_NUMBER is 32766 since 3.32; catching it at
// build surfaces a clear builder error instead of a cryptic driver crash.
//
// MAX_PARAM_BYTES: the per-value (column-level) ceiling. A single bound
// value can be pathologically large WITHOUT tripping MAX_SQL_BYTES, because
// bound values ride the wire separately - they are not interpolated into
// the statement text. 64 MiB is MySQL's default max_allowed_packet, the
// tightest per-value wire boundary across the supported drivers; a value
// larger than this is a buffer-overflow-class mistake (an unintended whole-
// file / whole-buffer bind), never a legitimate single column.
var MAX_SQL_BYTES = C.BYTES.mib(4);
var MAX_BIND_PARAMS = 65535;
var MAX_PARAM_BYTES = C.BYTES.mib(64);

// b.guardSql is the residual-raw-surface guard (whereRaw / setRaw /
// having-raw / join-raw / on-raw). It is lazy-required so b.sql does not
// hard-depend on the guard at module load (the guard module composes
// gate-contract + db-query helpers and is loaded on first raw use), and
// so a circular load between the two never wedges boot. The guard is
// applied by DEFAULT on every raw fragment - strict on the request path
// - never behind a config flag (security defaults are wired in, not
// opt-in). Operators with a deliberately benign single-statement read
// fragment relax via `{ guardProfile: "balanced" }`; the structurally
// unambiguous refusals (stacked statements, invalid encoding) never
// relax regardless of profile.
var guardSql = lazyRequire(function () { return require("./guard-sql"); });

/**
 * @primitive  b.sql.SqlBuilderError
 * @signature  b.sql.SqlBuilderError
 * @since      0.14.29
 * @status     stable
 * @related    b.safeSql.SafeSqlError, b.sql.select, b.sql.upsert
 *
 * Error thrown by every `b.sql` builder on a bad call shape - an unknown
 * dialect, an invalid identifier, an unconditional `update`/`delete`, a
 * placeholder-count mismatch, an empty value set, a conflicting upsert
 * action, and so on. Extends `FrameworkError` and is always permanent:
 * these are programming / config errors caught at SQL-composition time,
 * well before the query reaches a driver, so retrying never makes them
 * valid. The throw IS the security signal.
 *
 * Carries a stable `.code` with a `sql-builder/` prefix
 * (`sql-builder/bad-dialect`, `sql-builder/no-where`,
 * `sql-builder/placeholder-mismatch`, `sql-builder/empty-values`,
 * `sql-builder/conflict-action`, `sql-builder/unknown-column`, ...) - the
 * slash style mirrors `SafeSqlError`'s codes and stays distinct from the
 * dot-style codes `b.guardSql` raises.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   try {
 *     b.sql.update("users").set({ active: false }).toSql();
 *   } catch (e) {
 *     e instanceof b.sql.SqlBuilderError;   // -> true
 *     e.code;                               // -> "sql-builder/no-where"
 *   }
 */
// Mirrors the in-file error-class convention used by sibling composition
// modules that subclass FrameworkError directly (safe-sql.js
// SafeSqlError, cluster-storage.js ClusterStorageError) rather than
// routing through framework-error.defineClass. An integrator who would
// rather register it centrally adds
// `defineClass("SqlBuilderError", { alwaysPermanent: true })` to
// framework-error.js and re-points this require; the public shape
// (name / code / permanent / isSqlBuilderError) is identical either way.
class SqlBuilderError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "SqlBuilderError";
    this.code = code || "sql-builder/invalid";
    this.permanent = true;
    this.isSqlBuilderError = true;
  }
}

function _err(message, code) {
  return new SqlBuilderError(message, code);
}

// ---- Dialects -------------------------------------------------------

var DIALECTS = Object.freeze({ postgres: true, sqlite: true, mysql: true });

function _normDialect(dialect) {
  if (dialect === undefined || dialect === null) return "sqlite";
  if (typeof dialect !== "string" || DIALECTS[dialect] !== true) {
    throw _err("dialect must be one of postgres | sqlite | mysql (got " +
      JSON.stringify(dialect) + ")", "sql-builder/bad-dialect");
  }
  return dialect;
}

// MySQL quotes identifiers with backticks; Postgres + SQLite share the
// SQL-standard double-quote. The quoting below agrees with the framework
// DDL builder (framework-schema.js), which double-quotes on both backend
// dialects for the same casing-preservation reason.
//
// Validate then wrap an identifier in dialect quotes. The builder accepts
// reserved-word identifiers BY DESIGN: quoting a name is exactly what
// makes `from` / `select` / `count` / `key` usable as a real column or
// table, which is the framework's stated rationale for quote-by-
// construction (framework-schema.js DDL builder makes the same point).
// Every identifier the builder emits is quoted through the framework's
// single identifier primitive - b.safeSql.quoteIdentifier - with
// allowReserved on: quoting is exactly what makes a SQL-keyword column
// (e.g. `from`) safe in identifier position, and the builder admits
// reserved names by design. quoteIdentifier still enforces shape /
// length / null-byte / sqlite_-prefix rules, so nothing is weakened and
// the builder composes the primitive rather than reinventing quoting.
function _quoteId(name, dialect) {
  return safeSql.quoteIdentifier(name, dialect, { allowReserved: true });
}

// ---- DDL logical-type map -------------------------------------------
//
// The framework's own DDL builder (framework-schema.js `_types`) is the
// single source of truth for the two column types that diverge across
// dialects - the integer and binary tokens. b.sql consumes that map for
// operator app-schema parity rather than forking it: postgres BIGINT /
// BYTEA, sqlite INTEGER / BLOB. _types covers postgres + sqlite only
// (the framework's two backend dialects); MySQL is a b.sql-only DDL
// target, so its divergent tokens are mapped here. JSON diverges three
// ways (postgres JSONB / mysql JSON / sqlite TEXT) and is handled in
// _ddlType; the remaining tokens (TEXT / BOOLEAN / REAL / NUMERIC /
// TIMESTAMP) resolve uniformly. If framework-schema later exports `_types`, this
// reads it directly; until then the postgres/sqlite INT/BLOB values are
// kept byte-identical to framework-schema._types so there is exactly one
// definition of each token in the shipped tree.
var _schemaTypes = (typeof frameworkSchema._types === "function")
  ? frameworkSchema._types
  : function (dialect) {
      if (dialect === "postgres") return { INT: "BIGINT", BLOB: "BYTEA" };
      if (dialect === "sqlite") return { INT: "INTEGER", BLOB: "BLOB" };
      throw _err("framework type map has no entry for dialect '" + dialect + "'",
        "sql-builder/bad-dialect");
    };

// Logical type vocabulary -> dialect-final SQL type token. INT/BLOB
// delegate to the framework map (or its MySQL extension); the rest are
// dialect-invariant. Callers pass a logical name (case-insensitive) OR a
// verbatim type string - a string the vocabulary does not recognise is
// emitted as-is so operators can declare a dialect-specific type the map
// does not enumerate (it is still placed after a quoted column name, so
// no identifier injection is possible).
function _ddlType(logical, dialect) {
  if (typeof logical !== "string" || logical.length === 0) {
    throw _err("column type must be a non-empty string", "sql-builder/bad-type");
  }
  var key = logical.toUpperCase();
  var divergent;
  if (key === "INT" || key === "INTEGER" || key === "BIGINT") {
    divergent = (dialect === "mysql") ? { INT: "BIGINT" } : _schemaTypes(dialect);
    return divergent.INT;
  }
  if (key === "BLOB" || key === "BYTEA" || key === "BINARY") {
    divergent = (dialect === "mysql") ? { BLOB: "LONGBLOB" } : _schemaTypes(dialect);
    return divergent.BLOB;
  }
  if (key === "TEXT" || key === "STRING") return "TEXT";
  if (key === "BOOLEAN" || key === "BOOL") return "BOOLEAN";
  if (key === "REAL" || key === "FLOAT" || key === "DOUBLE") return "REAL";
  if (key === "NUMERIC" || key === "DECIMAL") return "NUMERIC";
  if (key === "TIMESTAMP") return "TIMESTAMP";
  if (key === "JSON") {
    return dialect === "postgres" ? "JSONB" : (dialect === "mysql" ? "JSON" : "TEXT");
  }
  // Unrecognised: a verbatim dialect-specific type (VARCHAR(255), GEOGRAPHY,
  // NUMERIC(10,2), DOUBLE PRECISION, TIMESTAMP WITH TIME ZONE, MySQL
  // ENUM('a','b') / SET(...), ...). It follows a quoted identifier so it is in
  // type position, never identifier position. Injection safety for the type
  // token is enforced at the statement level: createTable / alterTable route
  // the finished DDL through _assertCatalogEmittable, whose quote-aware
  // single-statement scan refuses a top-level ';', a comment marker, an
  // unbalanced quote, an unbalanced paren, and a NUL - while CORRECTLY allowing
  // those same characters when they sit inside a balanced quoted label (e.g.
  // ENUM('needs;review')). A non-quote-aware pre-scan here would over-reject
  // such valid labels, so the one quote-aware gate is the right place to check.
  return logical;
}

// ---- Operators ------------------------------------------------------
//
// Shared with the executing query builder (lib/db-query.js ALLOWED_OPS):
// comparison, IS/IS NOT, LIKE/NOT LIKE, IN/NOT IN, BETWEEN, and the
// Postgres JSONB containment + key-existence operators. Operator-supplied
// op strings are validated against this allowlist so no operator token
// reaches the SQL except one of these exact strings.
var ALLOWED_OPS = Object.freeze({
  "=": true, "!=": true, "<>": true, "<": true, "<=": true, ">": true, ">=": true,
  "IS": true, "IS NOT": true, "LIKE": true, "NOT LIKE": true,
  "IN": true, "NOT IN": true, "BETWEEN": true,
  "@>": true, "?": true, "?|": true, "?&": true,
  // sqlite FTS5 full-text match - `<fts-table-or-column> MATCH ?`. The
  // operand (the FTS5 query expression) ALWAYS binds as a single `?`;
  // build-gated to the sqlite dialect in _cmp (no Postgres / MySQL form).
  "MATCH": true,
});

var JOIN_KINDS = Object.freeze({
  INNER: "INNER JOIN", LEFT: "LEFT JOIN", RIGHT: "RIGHT JOIN",
  FULL: "FULL JOIN", CROSS: "CROSS JOIN",
});

// ---- Identifier helpers ---------------------------------------------

function _validateColumn(col) {
  if (typeof col !== "string" || col.length === 0) {
    throw _err("column name must be a non-empty string", "sql-builder/bad-column");
  }
  // Routes through safeSql so the shape / length / reserved-word /
  // null-byte rules are the framework's single identifier policy.
  safeSql.validateIdentifier(col, { allowReserved: true });
  return col;
}

// ---- Table reference ------------------------------------------------
//
// Bare DEFAULT logical names stay UNQUOTED so clusterStorage.resolveTables
// can rewrite them to the cluster-prefixed form (a quoted name would not
// match its bare-identifier scan). A custom prefix or a schema qualifier
// is validated + quoted at build time - an invalid identifier throws
// here, at config time, where the operator catches the typo at boot.
// Two-segment qualified names (schema.table) are the maximum.
function _normTableRef(name, opts) {
  opts = opts || {};
  if (name instanceof TableRef) return name;
  if (typeof name !== "string" || name.length === 0) {
    throw _err("table name must be a non-empty string", "sql-builder/bad-table");
  }
  var schema = opts.schema || null;
  var table = name;
  if (schema === null && name.indexOf(".") !== -1) {
    var dotParts = name.split(".");
    if (dotParts.length !== 2 || dotParts[0].length === 0 || dotParts[1].length === 0) {
      throw _err("schema-qualified table must be exactly 'schema.table' (got '" +
        name + "')", "sql-builder/bad-table");
    }
    schema = dotParts[0];
    table = dotParts[1];
  }
  return new TableRef(table, {
    schema: schema,
    prefix: opts.prefix !== undefined ? opts.prefix : (opts.tablePrefix || null),
    alias: opts.alias || null,
    quoteName: opts.quoteName === true,
  });
}

/**
 * @primitive  b.sql.table
 * @signature  b.sql.table(name, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.select, b.clusterStorage.resolveTables
 *
 * Build a table reference. A bare default logical name
 * (`b.sql.table("audit_log")`) stays UNQUOTED in the emitted SQL so
 * `b.clusterStorage` can rewrite it to the cluster-prefixed name. A
 * schema qualifier (`{ schema: "public" }` or the dotted form
 * `"public.users"`) or an operator app-table `prefix` is validated and
 * quoted at build time - a bad identifier throws immediately. The
 * `prefix` here is operator app-table namespacing, distinct from the
 * framework's internal `_blamejs_` prefix; it is prepended to the table
 * name and the whole result is quoted as one identifier. At most two
 * segments (schema.table). An `alias` is quoted and appended for joins.
 *
 * @opts
 *   schema:  string,   // schema qualifier, quoted at build time
 *   prefix:  string,   // operator app-table namespace, prepended then quoted
 *   alias:   string,   // table alias, used to disambiguate joins
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.table("audit_log").toString("sqlite");
 *   // -> "audit_log"               (bare default - clusterStorage rewrites)
 *
 *   b.sql.table("users", { schema: "public" }).toString("postgres");
 *   // -> '"public"."users"'
 *
 *   b.sql.table("orders", { prefix: "shopX_" }).toString("sqlite");
 *   // -> '"shopX_orders"'
 */
function table(name, opts) {
  return _normTableRef(name, opts);
}

class TableRef {
  constructor(name, opts) {
    opts = opts || {};
    if (typeof name !== "string" || name.length === 0) {
      throw _err("table name must be a non-empty string", "sql-builder/bad-table");
    }
    this._schema = opts.schema || null;
    this._prefix = opts.prefix || null;
    this._alias = opts.alias || null;
    // quoteName forces a bare default name to be quoted. The bare-default
    // name normally stays UNQUOTED so b.clusterStorage's resolveTables can
    // rewrite it to the cluster-prefixed form (a quoted name would not
    // match its bare-identifier scan). A LOCAL-only consumer that does NO
    // cluster rewrite (the executing query builder's single-node sqlite
    // path) opts into quoting so a reserved-word / case-sensitive table
    // name still emits a valid `"name"` identifier - quoting is exactly
    // what makes a SQL-keyword table name safe in identifier position.
    this._quoteName = opts.quoteName === true;
    // A custom prefix is validated as an identifier and prepended; the
    // combined name is then a single quoted identifier. The bare default
    // (no prefix, no schema) stays unquoted for clusterStorage.
    if (this._prefix !== null) {
      _validateColumn(this._prefix);
      this._name = this._prefix + name;
      this._bare = false;
    } else {
      this._name = name;
      this._bare = this._schema === null && !this._quoteName;
    }
    if (this._schema !== null) safeSql.validateIdentifier(this._schema, { allowReserved: true });
    if (this._alias !== null) safeSql.validateIdentifier(this._alias, { allowReserved: true });
    // Validate the base name shape even for the bare default - an
    // attacker-influenced logical name still must be a real identifier.
    safeSql.validateIdentifier(this._name, { allowReserved: true });
  }

  // The reference as it appears in FROM / INTO / UPDATE / JOIN. Bare
  // default names stay unquoted (clusterStorage rewrite target); custom
  // / schema-qualified names are quoted. Alias is never part of the
  // resolution target - added separately where an alias is legal.
  ref(dialect) {
    if (this._schema !== null) {
      return _quoteId(this._schema, dialect) + "." + _quoteId(this._name, dialect);
    }
    if (this._bare) return this._name;
    return _quoteId(this._name, dialect);
  }

  // ref() plus a quoted alias, for FROM / JOIN where an alias is legal.
  refWithAlias(dialect) {
    var base = this.ref(dialect);
    return this._alias !== null ? base + " " + _quoteId(this._alias, dialect) : base;
  }

  // The identifier columns are qualified against - the alias when set,
  // else the resolution target.
  qualifier(dialect) {
    if (this._alias !== null) return _quoteId(this._alias, dialect);
    return this.ref(dialect);
  }

  toString(dialect) {
    return this.refWithAlias(_normDialect(dialect));
  }
}

// ---- Allowlisted SQL function literals ------------------------------
//
// A small set of nullary, side-effect-free SQL function tokens an operator
// commonly wants in INSERT VALUES / SET RHS (a server-side timestamp) but
// which CANNOT be a bound `?` parameter (a `?` binds a value; these emit a
// keyword the engine evaluates). Rather than open a raw-fragment hole on
// the values path, b.sql.fn(name) wraps EXACTLY one of these allowlisted
// tokens - an unknown name throws, so no arbitrary expression reaches a
// VALUES / SET position. The token is dialect-checked at emit (NOW() is
// Postgres / MySQL; CURRENT_TIMESTAMP is portable). It is NOT a value -
// it consumes no `?` and contributes no param.
var SQL_FUNCTIONS = Object.freeze({
  "NOW":               { sql: "NOW()",             dialects: { postgres: true, mysql: true } },
  "CURRENT_TIMESTAMP": { sql: "CURRENT_TIMESTAMP", dialects: { postgres: true, sqlite: true, mysql: true } },
  "CURRENT_DATE":      { sql: "CURRENT_DATE",      dialects: { postgres: true, sqlite: true, mysql: true } },
  "CURRENT_TIME":      { sql: "CURRENT_TIME",      dialects: { postgres: true, sqlite: true, mysql: true } },
});

class SqlFunction {
  constructor(name) {
    if (typeof name !== "string") {
      throw _err("b.sql.fn(name): name must be a string", "sql-builder/bad-fn");
    }
    var key = name.toUpperCase();
    if (!Object.prototype.hasOwnProperty.call(SQL_FUNCTIONS, key)) {
      throw _err("b.sql.fn(name): '" + name + "' is not an allowlisted SQL function " +
        "(NOW / CURRENT_TIMESTAMP / CURRENT_DATE / CURRENT_TIME); a bound value uses a ? " +
        "placeholder, an arbitrary expression uses a guarded raw fragment", "sql-builder/bad-fn");
    }
    this._key = key;
    this.isSqlFunction = true;
  }
  // The SQL token for the builder's dialect; throws when the function is
  // not available on that backend (NOW() on sqlite has no portable form).
  toSqlToken(dialect) {
    var def = SQL_FUNCTIONS[this._key];
    if (def.dialects[dialect] !== true) {
      throw _err("b.sql.fn('" + this._key + "') is not available on " + dialect +
        " (use CURRENT_TIMESTAMP for a portable server timestamp)", "sql-builder/fn-unsupported");
    }
    return def.sql;
  }
}

/**
 * @primitive  b.sql.fn
 * @signature  b.sql.fn(name)
 * @since      0.15.0
 * @status     stable
 * @related    b.sql.insert, b.sql.update, b.sql.cast
 *
 * Wrap an allowlisted, nullary, side-effect-free SQL function token for use
 * as an INSERT `values()` / UPDATE `set()` right-hand side - a value
 * position that must emit a keyword the engine evaluates server-side (a
 * `NOW()` timestamp) rather than a bound `?` parameter. The allowlist is
 * exactly `NOW` / `CURRENT_TIMESTAMP` / `CURRENT_DATE` / `CURRENT_TIME`; an
 * unknown name throws, so no arbitrary expression reaches a VALUES / SET
 * position. The token is dialect-checked at emit (`NOW()` is Postgres /
 * MySQL; `CURRENT_TIMESTAMP` is portable). The wrapped function consumes
 * no `?` and contributes no param.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.insert("events")
 *     .values({ topic: "x", at: b.sql.fn("CURRENT_TIMESTAMP") })
 *     .toSql();
 *   // -> { sql: 'INSERT INTO events ("topic", "at") VALUES (?, CURRENT_TIMESTAMP)',
 *   //     params: ["x"] }
 */
function fn(name) { return new SqlFunction(name); }

// ---- Allowlisted column casts ---------------------------------------
//
// A `col::type` / `?::type` cast applies an allowlisted target type to a
// quoted column or a bound `?` placeholder. The cast TYPE is matched
// against a fixed vocabulary (no operator-supplied type token reaches the
// SQL), and the LHS is either a quoted identifier or a single bound
// placeholder - never raw text. Postgres `::` is the canonical form; the
// same vocabulary maps to a portable form where one exists (jsonb -> json
// on a non-Postgres backend that has it; interval has no portable cast and
// is Postgres-only).
var CAST_TYPES = Object.freeze({
  "jsonb":     { postgres: "jsonb",     mysql: "json",   sqlite: null },
  "json":      { postgres: "json",      mysql: "json",   sqlite: null },
  "interval":  { postgres: "interval",  mysql: null,     sqlite: null },
  "uuid":      { postgres: "uuid",      mysql: null,     sqlite: null },
  "text":      { postgres: "text",      mysql: "char",   sqlite: "text" },
  "int":       { postgres: "integer",   mysql: "signed", sqlite: "integer" },
  "bigint":    { postgres: "bigint",    mysql: "signed", sqlite: "integer" },
  "timestamptz": { postgres: "timestamptz", mysql: null, sqlite: null },
  "boolean":   { postgres: "boolean",   mysql: null,     sqlite: null },
});

function _castType(type, dialect) {
  if (typeof type !== "string" || type.length === 0) {
    throw _err("cast type must be a non-empty string", "sql-builder/bad-cast");
  }
  var key = type.toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(CAST_TYPES, key)) {
    throw _err("cast type '" + type + "' is not on the allowlist (jsonb / json / " +
      "interval / uuid / text / int / bigint / timestamptz / boolean)", "sql-builder/bad-cast");
  }
  var target = CAST_TYPES[key][dialect];
  if (target === null || target === undefined) {
    throw _err("cast to '" + type + "' has no portable form on " + dialect +
      " (it is Postgres-only)", "sql-builder/cast-unsupported");
  }
  return target;
}

// Render the dialect-correct cast suffix for a bound `?` placeholder or a
// quoted column. Postgres uses the `::type` operator; MySQL has no `::`,
// so a cast there wraps in CAST(<lhs> AS <type>). SQLite is weakly typed -
// the small set of casts portable to sqlite (text / int) emit
// CAST(<lhs> AS <type>) too; a sqlite-unsupported cast already threw in
// _castType.
function _renderCast(lhs, type, dialect) {
  var target = _castType(type, dialect);
  if (dialect === "postgres") return lhs + "::" + target;
  return "CAST(" + lhs + " AS " + target + ")";
}

// A value wrapped for binding-with-cast: the value binds as a single `?`
// and the placeholder carries the dialect cast (`?::jsonb` on Postgres).
class CastValue {
  constructor(value, type) {
    // Eager allowlist-membership check so a typo'd type token fails at the
    // call site (the entry-point THROW tier), not deep inside a later
    // toSql(). The dialect-portability check (interval / uuid are
    // Postgres-only) stays at render time, where the target dialect is known.
    if (typeof type !== "string" || type.length === 0) {
      throw _err("cast type must be a non-empty string", "sql-builder/bad-cast");
    }
    if (CAST_TYPES[type.toLowerCase()] === undefined) {
      throw _err("cast type '" + type + "' is not on the allowlist (jsonb / json / " +
        "interval / uuid / text / int / bigint / timestamptz / boolean)", "sql-builder/bad-cast");
    }
    this.value = value;
    this.type = type;
    this.isCastValue = true;
  }
}

/**
 * @primitive  b.sql.cast
 * @signature  b.sql.cast(value, type)
 * @since      0.15.0
 * @status     stable
 * @related    b.sql.insert, b.sql.update, b.sql.fn
 *
 * Wrap a value so it binds as a single `?` placeholder carrying a
 * dialect-correct cast - `?::jsonb` on Postgres, `CAST(? AS json)` on
 * MySQL. The cast TYPE is matched against a fixed allowlist (`jsonb` /
 * `json` / `interval` / `uuid` / `text` / `int` / `bigint` / `timestamptz`
 * / `boolean`); an unknown type, or one with no portable form on the
 * target dialect (`interval` / `uuid` are Postgres-only), throws at build.
 * Use it for an INSERT `values()` / UPDATE `set()` cell that must coerce a
 * bound string into a typed column (a JSON string into a `jsonb` column, a
 * duration string into an `interval`).
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.insert("docs", { dialect: "postgres" })
 *     .values({ id: 1, meta: b.sql.cast('{"a":1}', "jsonb") })
 *     .toSql();
 *   // -> { sql: 'INSERT INTO docs ("id", "meta") VALUES (?, ?::jsonb)',
 *   //     params: [1, '{"a":1}'] }
 */
function cast(value, type) { return new CastValue(value, type); }

// Render a single value cell for an INSERT VALUES / UPDATE SET RHS.
// Returns { sql, params } where sql is `?` for a bound value, `?::type`
// for a CastValue, or the dialect function token for a SqlFunction (no
// param). The single choke-point both insert and update value paths use,
// so the allowlisted-function / cast handling lives in one place.
function _renderValueCell(value, dialect) {
  if (value instanceof SqlFunction) {
    return { sql: value.toSqlToken(dialect), params: [] };
  }
  if (value instanceof CastValue) {
    return { sql: _renderCast("?", value.type, dialect), params: [value.value] };
  }
  return { sql: "?", params: [value] };
}

// ---- Value-binding helpers ------------------------------------------
//
// Every value is pushed to a params array and represented in the SQL by
// a `?`. A b.sql builder used as a subquery contributes its placeholders
// in left-to-right order, so a params array concatenation is always
// correct as long as fragments are appended in emission order.

// A column reference qualified column expression. Accepts "col" or
// "alias.col" / "table.col" - both segments validated + quoted.
function _qualifiedColumn(expr, dialect) {
  if (typeof expr !== "string" || expr.length === 0) {
    throw _err("column expression must be a non-empty string", "sql-builder/bad-column");
  }
  if (expr.indexOf(".") !== -1) {
    var parts = expr.split(".");
    if (parts.length !== 2 || parts[0].length === 0 || parts[1].length === 0) {
      throw _err("qualified column must be 'qualifier.column' (got '" + expr + "')",
        "sql-builder/bad-column");
    }
    safeSql.validateIdentifier(parts[0], { allowReserved: true });
    safeSql.validateIdentifier(parts[1], { allowReserved: true });
    return _quoteId(parts[0], dialect) + "." + _quoteId(parts[1], dialect);
  }
  _validateColumn(expr);
  return _quoteId(expr, dialect);
}

// LIKE auto-escape. Escapes %, _, and the escape char itself in an
// operator-supplied LIKE value so a stray % can't widen the match into a
// full-table disclosure. The escape char is `~`, NOT backslash: MySQL with
// the default sql_mode treats backslash as a string-literal escape, so
// `ESCAPE '\'` reads as an unterminated literal and parse-errors - `~` is
// parser-mode-independent across SQLite / Postgres / MySQL. Mirrors
// db-query.js's LIKE handling.
function _escapeLike(value) {
  return String(value).replace(/[~%_]/g, "~$&");
}

// Compose a sub-builder into a parent statement. The builder quotes
// identifiers eagerly (at the columns() / where() call), so a sub built with
// a different dialect than the parent has already baked in the wrong quote
// char - splicing it would emit mixed quoting the wrong backend mis-reads
// (a default-sqlite sub's "id" inside a mysql parent, or a mysql sub's `id`
// inside a postgres parent). Refuse the mismatch loudly at build rather than
// ship a corrupt statement; the operator builds the sub with the matching
// { dialect } so the whole statement is one dialect. A sub left at the
// default (sqlite) composes cleanly into a default (sqlite) parent.
function _composeSub(subBuilder, parentDialect) {
  if (subBuilder._dialect !== parentDialect) {
    throw _err("sub-query dialect '" + subBuilder._dialect + "' does not match the " +
      "parent statement's dialect '" + parentDialect + "' - build the composed " +
      "sub-query with { dialect: '" + parentDialect + "' } so the whole statement " +
      "is one dialect", "sql-builder/dialect-mismatch");
  }
  return subBuilder.toSql();
}

// The Postgres JSONB operators. Two shared dialect-design gates compose
// over this set so every emission site (the value-comparison _cmp path,
// scalar-subquery comparison, join-ON) enforces the same rule.
var JSONB_OPS = Object.freeze({ "@>": true, "?": true, "?|": true, "?&": true });

// Build-time refusal: a JSONB operator on a non-Postgres builder would emit
// jsonb_exists* / @> to a backend that has neither (downstream regression).
function _assertJsonbDialect(op, dialect) {
  if (JSONB_OPS[op] === true && dialect !== "postgres") {
    throw _err("the '" + op + "' JSONB operator is Postgres-only (no portable " +
      "SQLite / MySQL equivalent); build this query with { dialect: 'postgres' }",
      "sql-builder/jsonb-postgres-only");
  }
}

// Build-time refusal: a JSONB operator in a position that has no
// jsonb_exists* rewrite (scalar-subquery comparison, join-ON) - the bare
// operator would splice in and the wrong backend mis-reads it (and a bare
// `?` collides with the placeholder marker even on Postgres).
function _refuseJsonbOp(op, position) {
  if (JSONB_OPS[op] === true) {
    throw _err("the '" + op + "' JSONB operator is not supported in " + position +
      "; use where(col, '" + op + "', value) on a Postgres builder",
      "sql-builder/jsonb-bad-position");
  }
}

// ---- Condition tree (WHERE / HAVING / JOIN-ON) ----------------------
//
// A predicate group is an ordered list of leaves joined by AND / OR.
// Each leaf carries its own SQL fragment + params; nesting is a leaf
// whose fragment is a parenthesised sub-group. This is the structure
// every where/having/on clause and every whereGroup closure builds.

class Predicate {
  constructor(owner, joinerDefault) {
    this._owner = owner;            // the builder, for the column gate
    this._joiner = joinerDefault || "AND";
    this._parts = [];               // [{ joiner, sql, params }]
  }

  _gate(col) {
    if (this._owner && typeof this._owner._assertColumnMember === "function") {
      this._owner._assertColumnMember(col, "where");
    }
  }

  _dialect() {
    return this._owner ? this._owner._dialect : "sqlite";
  }

  _add(joiner, sql, params) {
    this._parts.push({ joiner: joiner, sql: sql, params: params || [] });
    return this;
  }

  // Core comparison. op validated against ALLOWED_OPS; the JSONB key-
  // existence operators emit the jsonb_exists* function family (see below).
  _cmp(joiner, col, op, value) {
    if (ALLOWED_OPS[op] !== true) {
      throw _err("invalid where operator '" + op + "'", "sql-builder/bad-operator");
    }
    this._gate(col);
    var dialect = this._dialect();
    var qc = _qualifiedColumn(col, dialect);

    // Dialect-design gate: the JSONB containment (@>) + key-existence (?, ?|,
    // ?&) operators are Postgres-only - the JSONB type, the jsonb_exists*
    // functions, and @> containment have no portable SQLite / MySQL form.
    // Emitting them for a non-Postgres backend silently regresses downstream
    // (no such function / unknown operator at execute), so refuse at build.
    _assertJsonbDialect(op, dialect);

    // JSONB / JSON-path injection guard + placeholder-safe emission
    // (inherited + hardened from the executing query builder). The Postgres
    // JSONB containment (@>) and key-existence (?, ?|, ?&) operators take an
    // operator-supplied operand the engine compares verbatim; route it
    // through safeJsonPath so NUL / control / bidi / zero-width characters a
    // driver might silently strip can't smuggle into the JSON-shape compare.
    //
    // The key-existence operators are emitted as the jsonb_exists* FUNCTION
    // family, not the literal `?` / `?|` / `?&` operator: a literal `?`
    // collides with the `?` bind-placeholder marker, so placeholderize would
    // rewrite the operator itself to `$N` and corrupt the query. The operand
    // always binds via a single `?` placeholder.
    if (op === "@>") {
      if (typeof value === "string") {
        var parsedContainment;
        try { parsedContainment = safeJson.parse(value); }
        catch (e) {
          throw _err("where '@>' value: invalid JSON string: " + ((e && e.message) || String(e)),
            "sql-builder/bad-jsonb-value");
        }
        safeJsonPath.validateContainment(parsedContainment);
      } else {
        safeJsonPath.validateContainment(value);
        // Bind the canonical-shape JSON so the driver sees the bytes we
        // just walked end-to-end.
        value = JSON.stringify(value);
      }
    } else if (op === "?") {
      if (typeof value !== "string") {
        throw _err("where '?' requires a string key (got " + (typeof value) + ")",
          "sql-builder/bad-jsonb-key");
      }
      safeJsonPath.validateKey(value);
      return this._add(joiner, "jsonb_exists(" + qc + ", ?)", [value]);
    } else if (op === "?|" || op === "?&") {
      if (!Array.isArray(value) || value.length === 0) {
        throw _err("'" + op + "' requires a non-empty array of keys", "sql-builder/bad-jsonb-keys");
      }
      for (var ki = 0; ki < value.length; ki += 1) safeJsonPath.validateKey(value[ki]);
      var jsonbExistsFn = op === "?|" ? "jsonb_exists_any" : "jsonb_exists_all";
      return this._add(joiner, jsonbExistsFn + "(" + qc + ", ?)", [value.slice()]);
    }

    if (op === "IN" || op === "NOT IN") {
      if (value instanceof Builder) {
        var sub = _composeSub(value, this._dialect());
        return this._add(joiner, qc + " " + op + " (" + sub.sql + ")", sub.params);
      }
      if (!Array.isArray(value) || value.length === 0) {
        throw _err(op + " requires a non-empty array of values (or a subquery builder)",
          "sql-builder/empty-in");
      }
      var holders = value.map(function () { return "?"; }).join(", ");
      return this._add(joiner, qc + " " + op + " (" + holders + ")", value.slice());
    }

    if (op === "BETWEEN") {
      if (!Array.isArray(value) || value.length !== 2) {
        throw _err("BETWEEN requires a [low, high] pair", "sql-builder/bad-between");
      }
      return this._add(joiner, qc + " BETWEEN ? AND ?", [value[0], value[1]]);
    }

    if ((op === "IS" || op === "IS NOT") && value === null) {
      // IS NULL / IS NOT NULL - no placeholder, no param.
      return this._add(joiner, qc + " " + op + " NULL", []);
    }

    // `col = NULL` / `col != NULL` is UNKNOWN in SQL — never true. Emitting it
    // (e.g. from where({ col: null })) silently matches zero rows; worse, a null
    // accidentally passed where a real value was expected (where({ ownerId }))
    // would, if rewritten to `IS NULL`, return orphan rows — an authorization
    // footgun. Refuse it and direct the caller to the explicit NULL predicates.
    if (value === null && (op === "=" || op === "!=" || op === "<>")) {
      throw _err("where(" + JSON.stringify(col) + ", '" + op + "', null) is never true in SQL " +
        "(col " + op + " NULL is UNKNOWN); use whereNull(col) / whereNotNull(col) to test for NULL",
        "sql-builder/null-equality");
    }

    if ((op === "LIKE" || op === "NOT LIKE") && typeof value === "string") {
      return this._add(joiner, qc + " " + op + " ? ESCAPE '~'", [_escapeLike(value)]);
    }

    // sqlite FTS5 `<fts-table-or-column> MATCH ?`. The full-text query
    // expression ALWAYS binds as a single `?` - never interpolated - so an
    // operator-supplied search term cannot reshape the statement. MATCH has
    // no portable Postgres / MySQL form (Postgres uses to_tsvector @@
    // to_tsquery; MySQL uses MATCH ... AGAINST with different grammar), so
    // refuse a non-sqlite dialect at build, the config-time tier.
    if (op === "MATCH") {
      if (dialect !== "sqlite") {
        throw _err("the MATCH full-text operator is sqlite-FTS5-only (no portable " +
          "Postgres / MySQL form); build this query with { dialect: 'sqlite' }",
          "sql-builder/match-sqlite-only");
      }
      if (typeof value !== "string" || value.length === 0) {
        throw _err("MATCH requires a non-empty FTS5 query string", "sql-builder/bad-match");
      }
      return this._add(joiner, qc + " MATCH ?", [value]);
    }

    return this._add(joiner, qc + " " + op + " ?", [value]);
  }

  // where(field, val) / where(field, op, val) / where({ ... }).
  where(fieldOrObj, op, value) {
    if (fieldOrObj && typeof fieldOrObj === "object" && !(fieldOrObj instanceof Builder)) {
      var self = this;
      Object.keys(fieldOrObj).forEach(function (k) { self._cmp("AND", k, "=", fieldOrObj[k]); });
      return this;
    }
    if (arguments.length === 2) return this._cmp("AND", fieldOrObj, "=", op);
    return this._cmp("AND", fieldOrObj, op, value);
  }
  andWhere(fieldOrObj, op, value) { return this.where(fieldOrObj, op, value); }
  orWhere(fieldOrObj, op, value) {
    if (fieldOrObj && typeof fieldOrObj === "object" && !(fieldOrObj instanceof Builder)) {
      var self = this;
      Object.keys(fieldOrObj).forEach(function (k) { self._cmp("OR", k, "=", fieldOrObj[k]); });
      return this;
    }
    if (arguments.length === 2) return this._cmp("OR", fieldOrObj, "=", op);
    return this._cmp("OR", fieldOrObj, op, value);
  }

  whereOp(col, op, value) { return this._cmp("AND", col, op, value); }
  orWhereOp(col, op, value) { return this._cmp("OR", col, op, value); }

  // LIKE with caller-controlled match mode. The structured LIKE in _cmp
  // escapes the WHOLE bound value (so a `%` in the value is a literal
  // percent, never a wildcard) - correct for an exact compare but it
  // can't express a "contains" / "starts-with" search where the wrapping
  // `%` MUST stay a live wildcard while the user's own `%` / `_` stay
  // escaped. This helper bridges that: it escapes the user term's
  // metacharacters with `~` (matching _cmp's escape char) and then adds
  // the LIVE wrapping wildcard per mode, binding the assembled pattern.
  // It emits the SAME `col LIKE ? ESCAPE '~'` form _cmp does - the ESCAPE
  // literal is builder-emitted (not a raw fragment), so it is not subject
  // to the raw-fragment guard's embedded-literal refusal. Mode is
  // "substring" (default, `%term%`), "prefix" (`term%`), or "exact"
  // (`term`, equivalent to a structured LIKE but spelled as a search).
  whereLike(col, term, mode) { return this._like("AND", col, term, mode); }
  orWhereLike(col, term, mode) { return this._like("OR", col, term, mode); }
  _like(joiner, col, term, mode) {
    if (typeof term !== "string") {
      throw _err("whereLike requires a string term (got " + (typeof term) + ")",
        "sql-builder/bad-like-term");
    }
    this._gate(col);
    var qc = _qualifiedColumn(col, this._dialect());
    var escaped = _escapeLike(term);
    var pattern;
    var m = mode || "substring";
    if (m === "exact") pattern = escaped;
    else if (m === "prefix") pattern = escaped + "%";
    else if (m === "substring") pattern = "%" + escaped + "%";
    else throw _err("whereLike mode must be 'substring' | 'prefix' | 'exact'",
      "sql-builder/bad-like-mode");
    return this._add(joiner, qc + " LIKE ? ESCAPE '~'", [pattern]);
  }

  // sqlite FTS5 full-text MATCH. The target is the FTS virtual-table name
  // (the recommended shape - `<fts> MATCH ?` inside an IN-subquery - since
  // FTS5 MATCH binds to the virtual table, and an aliased / joined column
  // ref is parsed as an ordinary column and fails) or a single FTS column.
  // The query expression binds as one `?`. sqlite-only (enforced in _cmp);
  // the column gate is bypassed because the target is a table identifier,
  // not a member of the builder's declared column set.
  whereMatch(target, expr) {
    if (this._dialect() !== "sqlite") {
      throw _err("whereMatch (FTS5 MATCH) is sqlite-only; build with { dialect: 'sqlite' }",
        "sql-builder/match-sqlite-only");
    }
    if (typeof expr !== "string" || expr.length === 0) {
      throw _err("whereMatch requires a non-empty FTS5 query string", "sql-builder/bad-match");
    }
    return this._add("AND", _qualifiedColumn(target, "sqlite") + " MATCH ?", [expr]);
  }
  orWhereMatch(target, expr) {
    if (this._dialect() !== "sqlite") {
      throw _err("orWhereMatch (FTS5 MATCH) is sqlite-only; build with { dialect: 'sqlite' }",
        "sql-builder/match-sqlite-only");
    }
    if (typeof expr !== "string" || expr.length === 0) {
      throw _err("orWhereMatch requires a non-empty FTS5 query string", "sql-builder/bad-match");
    }
    return this._add("OR", _qualifiedColumn(target, "sqlite") + " MATCH ?", [expr]);
  }

  // sqlite `<col> IN (SELECT value FROM json_each(?))`. The JSON-array
  // STRING binds as one `?` and sqlite's table-valued json_each unrolls it
  // to a one-column row set - the placeholder-safe way to test membership
  // in a variable-length set without expanding to one `?` per element (and
  // without the Postgres-only `= ANY(?)` array bind). The bound value MUST
  // be a JSON array string (json_each errors at execute on a non-array).
  // sqlite-only (json_each is a sqlite extension); the column is gated +
  // quoted by construction.
  whereInJsonEach(col, jsonArrayString) {
    if (this._dialect() !== "sqlite") {
      throw _err("whereInJsonEach (json_each table-valued function) is sqlite-only; " +
        "use whereInArray on Postgres", "sql-builder/json-each-sqlite-only");
    }
    if (typeof jsonArrayString !== "string" || jsonArrayString.length === 0) {
      throw _err("whereInJsonEach requires a JSON-array string", "sql-builder/bad-json-each");
    }
    this._gate(col);
    var qc = _qualifiedColumn(col, "sqlite");
    return this._add("AND", qc + " IN (SELECT value FROM json_each(?))", [jsonArrayString]);
  }

  whereIn(col, values) { return this._cmp("AND", col, "IN", values); }
  whereNotIn(col, values) { return this._cmp("AND", col, "NOT IN", values); }
  orWhereIn(col, values) { return this._cmp("OR", col, "IN", values); }

  // Postgres `col = ANY(?)` - the whole array binds as ONE parameter
  // (a single `?`), in contrast to `whereIn` which expands to one `?`
  // per element. This is the form a Postgres driver wants for a
  // variable-length id set without a placeholder explosion (and it
  // stays a single bind under the 65535-param wire ceiling). On a
  // non-Postgres dialect there is no `= ANY(array)` value form, so it
  // degrades to the portable expanded `IN (?, ?, ...)` automatically -
  // every element still binds, the contract is identical. The array is
  // bound, never interpolated.
  whereInArray(col, values) { return this._inArray("AND", col, values); }
  orWhereInArray(col, values) { return this._inArray("OR", col, values); }
  _inArray(joiner, col, values) {
    if (!Array.isArray(values) || values.length === 0) {
      throw _err("whereInArray requires a non-empty array of values", "sql-builder/empty-in");
    }
    // Validate each element is a bindable parameter. On the non-Postgres IN-list
    // path every element is its own `?`, so the driver rejects an undefined at
    // execute; the Postgres `= ANY(?)` path binds the WHOLE array as one param,
    // where an undefined is silently coerced to NULL — diverging per dialect.
    // Reject undefined here so every backend fails the same way, at build.
    for (var vi = 0; vi < values.length; vi += 1) {
      if (values[vi] === undefined) {
        throw _err("whereInArray value[" + vi + "] is undefined (not a bindable parameter)",
          "sql-builder/bad-in-value");
      }
    }
    this._gate(col);
    var qc = _qualifiedColumn(col, this._dialect());
    if (this._dialect() === "postgres") {
      // The whole array is one bound value (one `?`); the driver expands
      // it to a Postgres array operand at execute.
      return this._add(joiner, qc + " = ANY(?)", [values.slice()]);
    }
    var holders = values.map(function () { return "?"; }).join(", ");
    return this._add(joiner, qc + " IN (" + holders + ")", values.slice());
  }

  whereNull(col) { return this._cmp("AND", col, "IS", null); }
  whereNotNull(col) { return this._cmp("AND", col, "IS NOT", null); }
  orWhereNull(col) { return this._cmp("OR", col, "IS", null); }

  whereBetween(col, low, high) { return this._cmp("AND", col, "BETWEEN", [low, high]); }

  // Nested group: where(qb => qb.where(...).orWhere(...)) -> "( ... )".
  whereGroup(closure) { return this._group("AND", closure); }
  orWhereGroup(closure) { return this._group("OR", closure); }
  _group(joiner, closure) {
    if (typeof closure !== "function") {
      throw _err("whereGroup(closure): expected a function", "sql-builder/bad-closure");
    }
    var sub = new Predicate(this._owner, "AND");
    closure(sub);
    var built = sub.build();
    if (!built.sql) return this;
    return this._add(joiner, "(" + built.sql + ")", built.params);
  }

  // Subquery EXISTS / NOT EXISTS.
  whereExists(subBuilder) { return this._exists("AND", "EXISTS", subBuilder); }
  whereNotExists(subBuilder) { return this._exists("AND", "NOT EXISTS", subBuilder); }
  orWhereExists(subBuilder) { return this._exists("OR", "EXISTS", subBuilder); }
  _exists(joiner, kw, subBuilder) {
    if (!(subBuilder instanceof Builder)) {
      throw _err(kw + " requires a b.sql subquery builder", "sql-builder/bad-subquery");
    }
    var sub = _composeSub(subBuilder, this._dialect());
    return this._add(joiner, kw + " (" + sub.sql + ")", sub.params);
  }

  // Scalar-subquery comparison: whereSub("col", "=", subBuilder).
  whereSub(col, op, subBuilder) {
    if (ALLOWED_OPS[op] !== true) {
      throw _err("invalid where operator '" + op + "'", "sql-builder/bad-operator");
    }
    // JSONB operators have no jsonb_exists* rewrite in scalar-subquery
    // position (only the value-comparison where() path emits it), so refuse
    // them here rather than splice a bare ?/?|/?&/@> a backend mis-reads.
    _refuseJsonbOp(op, "a scalar-subquery comparison");
    if (!(subBuilder instanceof Builder)) {
      throw _err("whereSub requires a b.sql subquery builder", "sql-builder/bad-subquery");
    }
    this._gate(col);
    var sub = _composeSub(subBuilder, this._dialect());
    return this._add("AND", _qualifiedColumn(col, this._dialect()) + " " + op +
      " (" + sub.sql + ")", sub.params);
  }

  // Raw fragment, guarded by b.guardSql + the embedded-literal +
  // placeholder-count scanners. The fragment must be a value expression
  // (no statement terminator, no verb, no string literal) and every
  // value must be a `?` bound through params.
  whereRaw(sql, params, opts) { return this._raw("AND", sql, params, opts); }
  orWhereRaw(sql, params, opts) { return this._raw("OR", sql, params, opts); }
  _raw(joiner, sql, params, opts) {
    var checked = _checkRawFragment(sql, params, opts, "whereRaw");
    return this._add(joiner, "(" + checked.sql + ")", checked.params);
  }

  build() {
    if (this._parts.length === 0) return { sql: "", params: [] };
    var sql = this._parts[0].sql;
    var params = this._parts[0].params.slice();
    for (var i = 1; i < this._parts.length; i++) {
      sql += " " + this._parts[i].joiner + " " + this._parts[i].sql;
      for (var j = 0; j < this._parts[i].params.length; j++) params.push(this._parts[i].params[j]);
    }
    return { sql: sql, params: params };
  }

  get length() { return this._parts.length; }
}

// ---- Raw-fragment guard ---------------------------------------------
//
// The single choke-point every raw escape hatch (whereRaw / setRaw /
// havingRaw / joinRaw / on-raw / conflictWhere) passes through. Three
// layers, all on by default:
//   1. b.guardSql.validate - RFC/CVE defense for hostile raw SQL
//      (stacked statements, comment-smuggling, file/exec/exfil
//      primitives, invalid encoding). Strict profile on the request
//      path; { ok:false } refuses the fragment.
//   2. embedded-literal refusal - a '...' literal is the signature of
//      operator input concatenated into the fragment; refuse unless the
//      caller explicitly opts in for a static operator-controlled
//      literal.
//   3. placeholder-count - the number of `?` must equal params.length,
//      so no value is silently unbound or over-supplied.
function _checkRawFragment(sql, params, opts, where) {
  opts = opts || {};
  if (typeof sql !== "string" || sql.length === 0) {
    throw _err(where + ": sql must be a non-empty string", "sql-builder/bad-raw");
  }
  var p = Array.isArray(params) ? params.slice() : (params == null ? [] : [params]);

  // Guard against hostile raw SQL via b.guardSql.validate - the direct
  // content checker that returns { ok, issues }. Default strict (request
  // path); a benign single-statement read fragment can relax via
  // guardProfile, but the structurally unambiguous classes (stacked
  // statements, invalid encoding) refuse under every profile. The
  // fragment context requires the fragment to be a value expression
  // (any statement terminator / verb / dangerous token refuses).
  // allowLiterals propagates to b.guardSql too: its own embedded-string-
  // literal rule honours the same opt (a static operator-controlled
  // literal the caller deliberately allows), so a fragment opted in here
  // must not be refused by the guard's literal rule while the local
  // _assertRawNoStringLiteral pass is skipped - the two literal checks
  // stay consistent. The structurally unambiguous classes (stacked
  // statements, invalid encoding, dangerous primitives) refuse regardless.
  var profile = opts.guardProfile || "strict";
  var g = guardSql();
  if (g && typeof g.validate === "function") {
    var result = g.validate(sql, {
      profile: profile, context: "fragment", allowLiterals: opts.allowLiterals === true,
    });
    if (result && result.ok === false) {
      var first = (result.issues && result.issues[0]) || {};
      throw _err(where + ": raw fragment refused by b.guardSql (" +
        (first.code || "policy") + (first.snippet ? ": " + first.snippet : "") + ")",
        "sql-builder/guard-refused");
    }
  }

  // Embedded-literal + placeholder-count scan (single linear pass over
  // the fragment, comment / quoted-identifier aware).
  if (opts.allowLiterals !== true) _assertRawNoStringLiteral(sql, where);
  // A bare Postgres JSONB key-existence operator (?| / ?&) in a raw fragment
  // is corrupted by clusterStorage.placeholderize (the ? is rewritten to $N
  // -> "tags $1| keys"); _countPlaceholders also miscounts the ? as a bind.
  // Refuse it - the structured where(col, '?|', keys) path emits the
  // placeholder-safe jsonb_exists_any() form instead.
  _assertNoRawJsonbKeyOp(sql, where);
  var holders = _countPlaceholders(sql);
  if (holders !== p.length) {
    throw _err(where + ": " + holders + " placeholder(s) in sql but " + p.length +
      " param(s) supplied", "sql-builder/placeholder-mismatch");
  }
  return { sql: sql, params: p };
}

// Refuse a raw fragment that embeds a single-quoted string literal. A
// '...' literal is the signature of operator input concatenated into the
// builder (CWE-89). Double-quoted identifiers, line comments, and block
// comments are skipped. Single linear pass, no backtracking regex. Same
// shape as db-query.js's scanner.
function _assertRawNoStringLiteral(sql, where) {
  safeSql.assertNoRawStringLiteral(sql, where, function (w) {
    return _err(w + ": raw SQL must not contain a string literal ('...') - bind " +
      "every value with a ? placeholder, or pass { allowLiterals: true } when the " +
      "literal is static and operator-controlled", "sql-builder/raw-literal");
  });
}

// Refuse the two-char Postgres JSONB key-existence tokens (?| / ?&) in a raw
// fragment. They are unambiguous (a `?` placeholder is never immediately
// followed by `|` / `&`), can't be expressed safely under the ?->$N
// placeholderize rewrite, and have a placeholder-safe structured form
// (where(col, '?|', keys) -> jsonb_exists_any). Quote/comment-aware so a
// `?|` inside an allowLiterals fragment's literal or comment is ignored.
function _assertNoRawJsonbKeyOp(sql, where) {
  var i = 0;
  var len = sql.length;
  while (i < len) {
    var ch = sql.charAt(i);
    var next = i + 1 < len ? sql.charAt(i + 1) : "";
    if (ch === "'" || ch === '"' || ch === "`") {
      var q = ch;
      i += 1;
      while (i < len) {
        if (sql.charAt(i) === q) {
          if (sql.charAt(i + 1) === q) { i += 2; continue; }
          i += 1; break;
        }
        i += 1;
      }
      continue;
    }
    if (ch === "-" && next === "-") { while (i < len && sql.charAt(i) !== "\n") i += 1; continue; }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < len && !(sql.charAt(i) === "*" && sql.charAt(i + 1) === "/")) i += 1;
      i += 2;
      continue;
    }
    if (ch === "?" && (next === "|" || next === "&")) {
      throw _err(where + ": raw SQL must not contain the Postgres JSONB key-existence " +
        "operator '?" + next + "' (it collides with the ? bind placeholder) - use the " +
        "structured where(col, '?" + next + "', keys) form", "sql-builder/raw-jsonb-op");
    }
    i += 1;
  }
}

// Placeholder counting (quote/comment-aware) is the scanner shared with the
// residency write-gate; composed from safe-sql so the skip rules live in one
// place. The output validator below uses it for placeholder/param parity.
var _countPlaceholders = safeSql.countPlaceholders;

// Translate the builder's `?` placeholders to a dialect's positional form
// (Postgres `$1..$N`; SQLite / MySQL keep `?`); composed from safe-sql so the
// quote / comment / backtick skip rules live in one place. The toExternalSql
// terminal for code that hands the SQL to an operator-supplied driver directly.
var _toPositional = safeSql.toPositional;

/**
 * @primitive  b.sql.toExternalSql
 * @signature  b.sql.toExternalSql(builtOrBuilder, dialect)
 * @since      0.15.0
 * @status     stable
 * @related    b.sql.select, b.sql.createTable, b.clusterStorage.placeholderize
 *
 * Translate a built statement to a driver's positional placeholder form for
 * code that hands the SQL to an operator-supplied driver DIRECTLY (no
 * `b.clusterStorage` in the path to rewrite). Accepts either a chainable
 * builder (any `b.sql.select` / `insert` / `update` / `delete` / `upsert`,
 * via its own `.toExternalSql()` method) OR a plain `{ sql, params }` result
 * from a DDL builder (`createTable` / `createIndex` / `alterTable` /
 * `dropTable` / the RLS + catalog builders). Postgres gets `$1..$N`; SQLite
 * and MySQL keep `?`. The `?`-by-construction invariant is unchanged - only
 * the emitted text differs at the last step.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var ddl = b.sql.toExternalSql(
 *     b.sql.createIndex("idx_pending", "outbox", ["next_attempt_at"],
 *       { dialect: "postgres", where: "status = 'pending'" }),
 *     "postgres");
 *   // -> { sql: 'CREATE INDEX IF NOT EXISTS "idx_pending" ON outbox ' +
 *   //          '("next_attempt_at") WHERE status = \'pending\'', params: [] }
 */
function toExternalSql(builtOrBuilder, dialect) {
  if (builtOrBuilder instanceof Builder) return builtOrBuilder.toExternalSql(dialect);
  if (builtOrBuilder && typeof builtOrBuilder.sql === "string" &&
      Array.isArray(builtOrBuilder.params)) {
    var d = _normDialect(dialect);
    return { sql: _toPositional(builtOrBuilder.sql, d), params: builtOrBuilder.params };
  }
  throw _err("b.sql.toExternalSql expects a b.sql builder or a { sql, params } result",
    "sql-builder/bad-external-input");
}

// Final output gate - every verb's toSql() routes through _emit() before
// returning, so a builder bug or a tainted identifier can never reach the
// driver. Three invariants over the assembled statement, reusing the same
// quote/comment-aware scan:
//   1. placeholder <-> param parity - a `?` without its bound param (or a
//      param without its `?`) silently shifts values into the wrong
//      columns, the highest-severity builder bug.
//   2. exactly one statement - no top-level `;` outside literals/comments
//      (a stacked statement has no place in a single built statement).
//   3. balanced parentheses at the top level (structural well-formedness).
// String literals only legitimately appear via whereRaw { allowLiterals }
// (already gated at fragment time), so the literal check stays there.
function _assertEmittable(sql, params) {
  // ---- shape ----
  // A builder bug must never emit a non-string / empty statement, and
  // params must be an array - a misshapen output hides a real defect
  // rather than failing loudly at the driver.
  if (typeof sql !== "string" || sql.length === 0) {
    throw _err("toSql: emitted SQL must be a non-empty string (builder bug)",
      "sql-builder/empty-sql");
  }
  if (!Array.isArray(params)) {
    throw _err("toSql: params must be an array (builder bug)",
      "sql-builder/bad-params-shape");
  }
  // ---- size ----
  // Runaway / DoS ceiling on the statement text. A statement this large
  // is a bug (an unbatched bulk write, a pathological IN-list), never a
  // legitimate single query.
  if (sql.length > MAX_SQL_BYTES) {
    throw _err("toSql: emitted SQL is " + sql.length + " bytes, over the " +
      MAX_SQL_BYTES + "-byte cap - batch the operation rather than building " +
      "one oversized statement", "sql-builder/sql-too-large");
  }
  // ---- text validity (boundary-escape) ----
  // A NUL byte truncates the statement at C-string-based drivers and can't
  // be stored in Postgres text; lone UTF-16 surrogates encode to invalid
  // UTF-8 on the wire (the CVE-2025-1094 encoding-escape class). Neither
  // can legitimately appear in builder-emitted SQL.
  if (sql.indexOf("\u0000") !== -1) {
    throw _err("toSql: emitted SQL contains a NUL byte - rejected " +
      "(statement-truncation / boundary-escape risk)", "sql-builder/null-byte-sql");
  }
  if (typeof sql.isWellFormed === "function" && !sql.isWellFormed()) {
    throw _err("toSql: emitted SQL contains invalid Unicode (lone " +
      "surrogates) - rejected (would encode to invalid UTF-8 on the wire)",
      "sql-builder/invalid-encoding-sql");
  }
  var n = params.length;
  // ---- bind-parameter ceiling ----
  // The wire-protocol limit (Postgres/MySQL 65535; SQLite 32766). Past it
  // is a hard driver error; catch it here with a clear message. The usual
  // cause is an unbounded IN-list / bulk insert that should be chunked.
  if (n > MAX_BIND_PARAMS) {
    throw _err("toSql: " + n + " bind parameters exceeds the " + MAX_BIND_PARAMS +
      "-parameter wire limit - chunk the values (batch the IN-list / rows)",
      "sql-builder/too-many-params");
  }
  // ---- param-element shape ----
  // A param that is `undefined` / a function / a symbol is a caller
  // mistake (a typo'd variable, a method reference passed by accident);
  // drivers coerce these ambiguously (undefined -> NULL, function ->
  // "[Function]"), silently storing the wrong value. Bind a concrete
  // value (string / number / boolean / null / bigint / Buffer / Date /
  // a JSON-serializable object). null is valid SQL NULL.
  for (var pi = 0; pi < n; pi += 1) {
    var pv = params[pi];
    var pt = typeof pv;
    if (pv === undefined || pt === "function" || pt === "symbol") {
      throw _err("toSql: param[" + pi + "] is " +
        (pv === undefined ? "undefined" : pt) + " - bind a concrete value " +
        "(string / number / boolean / null / bigint / Buffer / Date / object); " +
        "use null for SQL NULL", "sql-builder/bad-param-value");
    }
    // ---- column-level (per-value) size boundary ----
    // Only strings / Buffers can carry an unbounded payload; everything
    // else (number / boolean / bigint / Date / null) is fixed-small. A
    // single value over the per-value ceiling is a buffer-overflow-class
    // mistake (a whole file / whole buffer bound by accident), distinct
    // from the total-statement and total-param caps above.
    if (pt === "string" || Buffer.isBuffer(pv)) {
      var vbytes = pt === "string" ? Buffer.byteLength(pv, "utf8") : pv.length;
      if (vbytes > MAX_PARAM_BYTES) {
        throw _err("toSql: param[" + pi + "] is " + vbytes + " bytes, over the " +
          MAX_PARAM_BYTES + "-byte per-value ceiling - stream large blobs " +
          "through chunked storage rather than binding one oversized column",
          "sql-builder/param-too-large");
      }
    }
    if (pt === "string") {
      // A bound string still rides the wire. A NUL byte cannot be stored
      // in a Postgres text column and truncates C-string-based drivers; a
      // lone UTF-16 surrogate encodes to invalid UTF-8 on the wire (the
      // text values that "jump out of boundaries"). Reject both here so a
      // malformed value fails loudly at build time, not as a corrupt store.
      if (pv.indexOf("\u0000") !== -1) {
        throw _err("toSql: param[" + pi + "] contains a NUL byte - rejected " +
          "(text-column / driver truncation, boundary-escape risk)",
          "sql-builder/null-byte-param");
      }
      if (typeof pv.isWellFormed === "function" && !pv.isWellFormed()) {
        throw _err("toSql: param[" + pi + "] contains invalid Unicode (lone " +
          "surrogates) - rejected (would encode to invalid UTF-8 on the wire)",
          "sql-builder/invalid-encoding-param");
      }
    }
  }
  // ---- placeholder <-> param parity ----
  var holders = _countPlaceholders(sql);
  if (holders !== n) {
    throw _err("toSql: placeholder/param count mismatch - " + holders +
      " '?' placeholder(s) but " + n + " param(s); emitting this would " +
      "misalign bound values across columns", "sql-builder/param-mismatch");
  }
  safeSql.assertSingleStatement(sql, {
    label: "toSql",
    makeError: function (m, suffix) { return _err(m, "sql-builder/" + suffix); },
  });
}

// Terminal wrapper: validate then return the { sql, params } shape every
// verb's toSql() emits.
function _emit(sql, params) {
  _assertEmittable(sql, params);
  return { sql: sql, params: params };
}

// ---- WITH (CTE) -----------------------------------------------------
//
// A CTE is a name + a subquery (a b.sql Builder whose toSql() composes,
// params concatenated in CTE order before the main statement's params)
// OR a guarded raw fragment. A statement carries an ordered list of
// CTEs; withRecursive marks the WITH clause RECURSIVE.

function _cteFragment(cte, dialect) {
  var name = _quoteId(cte.name, dialect);
  if (cte.builder instanceof Builder) {
    // Render the CTE body under the OUTER statement's dialect, not the
    // sub-builder's own (default sqlite), so the name + body quote
    // consistently in one statement.
    var sub = _composeSub(cte.builder, dialect);
    return { sql: name + " AS (" + sub.sql + ")", params: sub.params };
  }
  // Raw CTE body - guarded like any raw fragment but allowed to be a
  // full SELECT/INSERT/UPDATE/DELETE statement (migration context).
  var checked = _checkRawFragment(cte.sql, cte.params, { guardProfile: cte.guardProfile || "balanced" },
    "with");
  return { sql: name + " AS (" + checked.sql + ")", params: checked.params };
}

function _renderWith(ctes, recursive, dialect) {
  if (!ctes || ctes.length === 0) return { sql: "", params: [] };
  var fragments = [];
  var params = [];
  for (var i = 0; i < ctes.length; i++) {
    var f = _cteFragment(ctes[i], dialect);
    fragments.push(f.sql);
    for (var j = 0; j < f.params.length; j++) params.push(f.params[j]);
  }
  return {
    sql: "WITH " + (recursive ? "RECURSIVE " : "") + fragments.join(", ") + " ",
    params: params,
  };
}

// ---- Base Builder ---------------------------------------------------
//
// Holds the shared dialect, table, CTE list, and column-membership gate.
// Each verb is a subclass with its own clause set + toSql().

class Builder {
  constructor(verb, tableNameOrRef, opts) {
    opts = opts || {};
    this._verb = verb;
    this._dialect = _normDialect(opts.dialect);
    this._table = _normTableRef(tableNameOrRef, opts);
    this._ctes = [];
    this._cteRecursive = false;

    // Column-membership gate. When the operator declares allowedColumns
    // (or a schema-declared set), an unknown column is refused before it
    // interpolates as an identifier (ORDER-BY / disclosure injection).
    this._allowedColumns = null;
    if (opts.allowedColumns) {
      if (!Array.isArray(opts.allowedColumns) || opts.allowedColumns.length === 0) {
        throw _err("allowedColumns must be a non-empty array", "sql-builder/bad-allowed-columns");
      }
      opts.allowedColumns.forEach(_validateColumn);
      this._allowedColumns = new Set(opts.allowedColumns);
    }
    this._columnGateMode = opts.columnGateMode || (this._allowedColumns ? "reject" : "off");
  }

  // Restrict columns to an explicit subset (chainable form of the opt).
  allowedColumns(cols) {
    if (!Array.isArray(cols) || cols.length === 0) {
      throw _err("allowedColumns(cols): expected a non-empty array", "sql-builder/bad-allowed-columns");
    }
    cols.forEach(_validateColumn);
    this._allowedColumns = new Set(cols);
    if (this._columnGateMode === "off") this._columnGateMode = "reject";
    return this;
  }

  columnGate(mode) {
    if (mode !== "reject" && mode !== "warn" && mode !== "off") {
      throw _err("columnGate mode must be 'reject' | 'warn' | 'off'", "sql-builder/bad-gate-mode");
    }
    this._columnGateMode = mode;
    return this;
  }

  // Assert a column is a member of the gate set before it is quoted into
  // SQL. Always enforces an explicit allowedColumns set; "warn" mode
  // permits unknown columns (no audit sink here - this is a pure string
  // builder), "off" / no set skips. A qualified "alias.col" gates on the
  // bare column segment.
  _assertColumnMember(col, where) {
    if (this._columnGateMode === "off" || this._allowedColumns === null) return;
    var bare = col.indexOf(".") !== -1 ? col.split(".").pop() : col;
    if (this._allowedColumns.has(bare)) return;
    if (this._columnGateMode === "warn") return;
    throw _err("column '" + col + "' is not in the allowedColumns set" +
      (where ? " (" + where + ")" : ""), "sql-builder/unknown-column");
  }

  // ---- WITH (shared by every verb) ----
  with(name, subqueryOrRaw, params, opts) {
    return this._pushCte(false, name, subqueryOrRaw, params, opts);
  }
  withRecursive(name, subqueryOrRaw, params, opts) {
    return this._pushCte(true, name, subqueryOrRaw, params, opts);
  }
  _pushCte(recursive, name, subqueryOrRaw, params, opts) {
    _validateColumn(name);
    if (recursive) this._cteRecursive = true;
    if (subqueryOrRaw instanceof Builder) {
      this._ctes.push({ name: name, builder: subqueryOrRaw });
    } else if (typeof subqueryOrRaw === "string") {
      this._ctes.push({
        name: name, sql: subqueryOrRaw, params: params,
        guardProfile: (opts && opts.guardProfile) || "balanced",
      });
    } else {
      throw _err("with(name, ...): second arg must be a b.sql builder or a raw SQL string",
        "sql-builder/bad-cte");
    }
    return this;
  }

  // Subclasses implement _render() -> { sql, params } WITHOUT the WITH
  // prefix; toSql() prepends the rendered CTE clause.
  toSql() {
    var body = this._render();
    if (this._ctes.length === 0) return body;
    var withClause = _renderWith(this._ctes, this._cteRecursive, this._dialect);
    return {
      sql: withClause.sql + body.sql,
      params: withClause.params.concat(body.params),
    };
  }

  // Driver-final form for code that targets an operator-supplied driver
  // DIRECTLY (b.externalDb.query / a transaction client), with no
  // b.clusterStorage in the path to rewrite placeholders. The builder
  // always composes `?` placeholders by construction; this terminal
  // translates them to the dialect's positional form at the boundary:
  // `$1..$N` for Postgres, left as `?` for SQLite / MySQL. The translation
  // is the SAME quote/comment-aware single pass clusterStorage uses, so a
  // `?` inside a string literal / quoted identifier / comment is never
  // rewritten. The `?`-by-construction invariant is unchanged - only the
  // emitted text differs at the very last step.
  toExternalSql(dialect) {
    var built = this.toSql();
    var d = _normDialect(dialect || this._dialect);
    return { sql: _toPositional(built.sql, d), params: built.params };
  }
}

// ---- SELECT ---------------------------------------------------------

class SelectBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("select", tableNameOrRef, opts);
    this._projection = [];        // [{ sql, params }] - column / aggregate / scalar-subquery
    this._distinct = false;
    this._joins = [];             // [{ sql, params }]
    this._where = new Predicate(this, "AND");
    this._groupBy = [];
    this._having = new Predicate(this, "AND");
    this._orderBy = [];
    this._limit = null;
    this._offset = null;
    this._lockMode = null;        // null | "UPDATE" | "SHARE"
    this._lockSkipLocked = false;
    this._lockNoWait = false;
  }

  distinct() { this._distinct = true; return this; }

  // Projection: array of column names (or "alias.col"); each quoted.
  // Empty / unset -> "*".
  columns(cols) {
    if (!Array.isArray(cols)) throw _err("columns() expects an array", "sql-builder/bad-columns");
    var self = this;
    cols.forEach(function (c) {
      self._assertColumnMember(c, "select");
      self._projection.push({ sql: _qualifiedColumn(c, self._dialect), params: [] });
    });
    return this;
  }
  select(cols) { return this.columns(cols); }

  // A guarded raw projection expression - a constant `1` presence sentinel
  // (`SELECT 1 ... WHERE ...` for an existence probe), a function-call
  // projection, or any value expression the structured column / aggregate
  // helpers don't cover. It rides the same b.guardSql raw-fragment gate as
  // whereRaw (no statement terminator, no embedded string literal unless
  // allowLiterals); any value binds via a `?` carried in params.
  selectRaw(expr, params, opts) {
    var checked = _checkRawFragment(expr, params, opts, "selectRaw");
    this._projection.push({ sql: checked.sql, params: checked.params });
    return this;
  }

  // Aggregate helpers. alias is quoted; the aggregated column is quoted
  // (or "*" for count()).
  count(col, alias) { return this._agg("COUNT", col || "*", alias, false); }
  countDistinct(col, alias) { return this._agg("COUNT", col, alias, true); }
  max(col, alias) { return this._agg("MAX", col, alias, false); }
  min(col, alias) { return this._agg("MIN", col, alias, false); }
  sum(col, alias) { return this._agg("SUM", col, alias, false); }
  avg(col, alias) { return this._agg("AVG", col, alias, false); }
  _agg(fn, col, alias, distinct) {
    var inner;
    if (col === "*") {
      inner = "*";
    } else {
      this._assertColumnMember(col, fn.toLowerCase());
      inner = (distinct ? "DISTINCT " : "") + _qualifiedColumn(col, this._dialect);
    }
    var sql = fn + "(" + inner + ")";
    if (alias) { _validateColumn(alias); sql += " AS " + _quoteId(alias, this._dialect); }
    this._projection.push({ sql: sql, params: [] });
    return this;
  }

  // Scalar subquery in the projection: selectSub(subBuilder, "alias").
  selectSub(subBuilder, alias) {
    if (!(subBuilder instanceof Builder)) {
      throw _err("selectSub requires a b.sql subquery builder", "sql-builder/bad-subquery");
    }
    _validateColumn(alias);
    var sub = _composeSub(subBuilder, this._dialect);
    this._projection.push({
      sql: "(" + sub.sql + ") AS " + _quoteId(alias, this._dialect),
      params: sub.params,
    });
    return this;
  }

  // ---- JOINs ----
  join(tbl, onLeft, op, onRight) { return this._join("INNER", tbl, onLeft, op, onRight); }
  innerJoin(tbl, onLeft, op, onRight) { return this._join("INNER", tbl, onLeft, op, onRight); }
  leftJoin(tbl, onLeft, op, onRight) { return this._join("LEFT", tbl, onLeft, op, onRight); }
  rightJoin(tbl, onLeft, op, onRight) { return this._join("RIGHT", tbl, onLeft, op, onRight); }
  fullJoin(tbl, onLeft, op, onRight) { return this._join("FULL", tbl, onLeft, op, onRight); }
  crossJoin(tbl) { return this._join("CROSS", tbl, null, null, null); }
  _join(kind, tbl, onLeft, op, onRight) {
    var ref = _normTableRef(tbl, {});
    var clause = JOIN_KINDS[kind] + " " + ref.refWithAlias(this._dialect);
    if (kind !== "CROSS") {
      if (typeof onLeft !== "string" || typeof onRight !== "string") {
        throw _err(kind + " join requires onLeft + onRight column expressions",
          "sql-builder/bad-join-on");
      }
      var joinOp = op || "=";
      // The ON operator is a comparison; validate against the same
      // allowlist. Both operands are column expressions (quoted), never
      // bound values - a join condition compares columns, not literals.
      if (ALLOWED_OPS[joinOp] !== true) {
        throw _err("invalid join ON operator '" + joinOp + "'", "sql-builder/bad-operator");
      }
      // A JSONB operator in a join ON has no jsonb_exists* rewrite and a bare
      // `?` collides with the placeholder marker; refuse it here.
      _refuseJsonbOp(joinOp, "a join ON clause");
      clause += " ON " + _qualifiedColumn(onLeft, this._dialect) + " " + joinOp + " " +
        _qualifiedColumn(onRight, this._dialect);
    }
    this._joins.push({ sql: clause, params: [] });
    return this;
  }

  // Raw join (guarded) - the full "<KIND> JOIN <tbl> ON <raw>" escape
  // hatch for join conditions the column-pair form can't express.
  joinRaw(sql, params, opts) {
    var checked = _checkRawFragment(sql, params, opts, "joinRaw");
    this._joins.push({ sql: checked.sql, params: checked.params });
    return this;
  }

  // ---- WHERE (delegated to the Predicate) ----
  // where / andWhere / orWhere forward `arguments` rather than fixed
  // positional params: the Predicate distinguishes the 2-arg
  // where(field, value) shorthand from the 3-arg where(field, op, value)
  // form by arguments.length, so a fixed (a, b, c) signature here would
  // make a 2-arg call look like 3 (binding the value as the operator).
  where() { this._where.where.apply(this._where, arguments); return this; }
  andWhere() { this._where.andWhere.apply(this._where, arguments); return this; }
  orWhere() { this._where.orWhere.apply(this._where, arguments); return this; }
  whereOp(col, op, value) { this._where.whereOp(col, op, value); return this; }
  orWhereOp(col, op, value) { this._where.orWhereOp(col, op, value); return this; }
  whereIn(col, values) { this._where.whereIn(col, values); return this; }
  whereNotIn(col, values) { this._where.whereNotIn(col, values); return this; }
  orWhereIn(col, values) { this._where.orWhereIn(col, values); return this; }
  whereInArray(col, values) { this._where.whereInArray(col, values); return this; }
  orWhereInArray(col, values) { this._where.orWhereInArray(col, values); return this; }
  whereInJsonEach(col, jsonArrayString) { this._where.whereInJsonEach(col, jsonArrayString); return this; }
  whereMatch(target, expr) { this._where.whereMatch(target, expr); return this; }
  orWhereMatch(target, expr) { this._where.orWhereMatch(target, expr); return this; }
  whereNull(col) { this._where.whereNull(col); return this; }
  whereNotNull(col) { this._where.whereNotNull(col); return this; }
  orWhereNull(col) { this._where.orWhereNull(col); return this; }
  whereLike(col, term, mode) { this._where.whereLike(col, term, mode); return this; }
  orWhereLike(col, term, mode) { this._where.orWhereLike(col, term, mode); return this; }
  whereBetween(col, low, high) { this._where.whereBetween(col, low, high); return this; }
  whereGroup(closure) { this._where.whereGroup(closure); return this; }
  orWhereGroup(closure) { this._where.orWhereGroup(closure); return this; }
  whereExists(sub) { this._where.whereExists(sub); return this; }
  whereNotExists(sub) { this._where.whereNotExists(sub); return this; }
  whereSub(col, op, sub) { this._where.whereSub(col, op, sub); return this; }
  whereRaw(sql, params, opts) { this._where.whereRaw(sql, params, opts); return this; }
  orWhereRaw(sql, params, opts) { this._where.orWhereRaw(sql, params, opts); return this; }

  // ---- Row locking (Postgres / MySQL 8+) ----
  // FOR UPDATE [SKIP LOCKED] - the competing-consumer claim idiom. SKIP
  // LOCKED lets parallel workers each grab a disjoint row set without
  // blocking on each other's locks (the at-least-once outbox / job-queue
  // claim). It is Postgres / MySQL-only; SQLite is a single writer and
  // has no row lock, so the builder REFUSES forUpdate on a sqlite dialect
  // at build (emitting unsupported syntax would be a silent driver error)
  // - the caller branches on dialect and uses a plain transaction-scoped
  // SELECT for sqlite, exactly as the publisher does.
  forUpdate(opts) { return this._lock("UPDATE", opts); }
  forShare(opts) { return this._lock("SHARE", opts); }
  _lock(mode, opts) {
    opts = opts || {};
    if (this._dialect === "sqlite") {
      throw _err("forUpdate / forShare row locking is Postgres / MySQL-only " +
        "(SQLite is a single writer with no row lock); branch on dialect and use a " +
        "transaction-scoped SELECT for sqlite", "sql-builder/lock-unsupported");
    }
    this._lockMode = mode;
    this._lockSkipLocked = opts.skipLocked === true;
    this._lockNoWait = opts.noWait === true;
    if (this._lockSkipLocked && this._lockNoWait) {
      throw _err("forUpdate: skipLocked and noWait are mutually exclusive", "sql-builder/bad-lock");
    }
    return this;
  }

  // ---- GROUP BY / HAVING ----
  groupBy(cols) {
    var arr = Array.isArray(cols) ? cols : [cols];
    var self = this;
    arr.forEach(function (c) {
      self._assertColumnMember(c, "groupBy");
      self._groupBy.push(_qualifiedColumn(c, self._dialect));
    });
    return this;
  }
  having() { this._having.where.apply(this._having, arguments); return this; }
  orHaving() { this._having.orWhere.apply(this._having, arguments); return this; }
  havingRaw(sql, params, opts) { this._having.whereRaw(sql, params, opts); return this; }

  // ---- ORDER BY / LIMIT / OFFSET ----
  orderBy(col, direction) {
    this._assertColumnMember(col, "orderBy");
    var dir = (direction || "asc").toLowerCase();
    if (dir !== "asc" && dir !== "desc") {
      throw _err("orderBy direction must be 'asc' or 'desc'", "sql-builder/bad-direction");
    }
    this._orderBy.push(_qualifiedColumn(col, this._dialect) + " " + dir.toUpperCase());
    return this;
  }
  limit(n) {
    if (!Number.isInteger(n) || n < 0) {
      throw _err("limit must be a non-negative integer", "sql-builder/bad-limit");
    }
    this._limit = n;
    return this;
  }
  offset(n) {
    if (!Number.isInteger(n) || n < 0) {
      throw _err("offset must be a non-negative integer", "sql-builder/bad-offset");
    }
    this._offset = n;
    return this;
  }

  _render() {
    var dialect = this._dialect;
    var params = [];
    var projSql;
    if (this._projection.length === 0) {
      projSql = "*";
    } else {
      var pieces = [];
      for (var p = 0; p < this._projection.length; p++) {
        pieces.push(this._projection[p].sql);
        for (var pp = 0; pp < this._projection[p].params.length; pp++) {
          params.push(this._projection[p].params[pp]);
        }
      }
      projSql = pieces.join(", ");
    }

    var sql = "SELECT " + (this._distinct ? "DISTINCT " : "") + projSql +
      " FROM " + this._table.refWithAlias(dialect);

    for (var j = 0; j < this._joins.length; j++) {
      sql += " " + this._joins[j].sql;
      for (var jp = 0; jp < this._joins[j].params.length; jp++) params.push(this._joins[j].params[jp]);
    }

    var w = this._where.build();
    if (w.sql) { sql += " WHERE " + w.sql; for (var wi = 0; wi < w.params.length; wi++) params.push(w.params[wi]); }

    if (this._groupBy.length > 0) sql += " GROUP BY " + this._groupBy.join(", ");

    var h = this._having.build();
    if (h.sql) { sql += " HAVING " + h.sql; for (var hi = 0; hi < h.params.length; hi++) params.push(h.params[hi]); }

    if (this._orderBy.length > 0) sql += " ORDER BY " + this._orderBy.join(", ");
    if (this._limit !== null) sql += " LIMIT " + this._limit;
    if (this._offset !== null) sql += " OFFSET " + this._offset;

    if (this._lockMode !== null) {
      sql += " FOR " + this._lockMode;
      if (this._lockSkipLocked) sql += " SKIP LOCKED";
      else if (this._lockNoWait) sql += " NOWAIT";
    }

    return _emit(sql, params);
  }
}

// ---- INSERT ---------------------------------------------------------

class InsertBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("insert", tableNameOrRef, opts);
    this._columns = null;
    this._rows = [];              // array of value arrays, aligned to _columns
    this._returning = null;
  }

  columns(cols) {
    if (!Array.isArray(cols) || cols.length === 0) {
      throw _err("columns() expects a non-empty array", "sql-builder/bad-columns");
    }
    var self = this;
    cols.forEach(function (c) { self._assertColumnMember(c, "insert"); _validateColumn(c); });
    this._columns = cols.slice();
    return this;
  }

  // values(obj) - one row from a column->value map (sets _columns from
  // the keys if not already set). values([obj, obj]) - multiple rows.
  // values(array) - one row aligned to a prior columns() call.
  values(rowOrRows) {
    if (Array.isArray(rowOrRows) && rowOrRows.length > 0 && typeof rowOrRows[0] === "object" &&
        rowOrRows[0] !== null && !Array.isArray(rowOrRows[0])) {
      // Array of row objects.
      var self = this;
      rowOrRows.forEach(function (r) { self._addRowObject(r); });
      return this;
    }
    if (Array.isArray(rowOrRows)) {
      // A single positional row aligned to columns().
      if (this._columns === null) {
        throw _err("values(array) requires a prior columns([...]) call", "sql-builder/no-columns");
      }
      if (rowOrRows.length !== this._columns.length) {
        throw _err("values(array): " + rowOrRows.length + " values but " +
          this._columns.length + " columns", "sql-builder/value-count");
      }
      this._rows.push(rowOrRows.slice());
      return this;
    }
    if (rowOrRows && typeof rowOrRows === "object") {
      this._addRowObject(rowOrRows);
      return this;
    }
    throw _err("values() requires a row object, an array of row objects, or a value array",
      "sql-builder/bad-values");
  }

  _addRowObject(obj) {
    var keys = Object.keys(obj);
    if (keys.length === 0) throw _err("insert row object is empty", "sql-builder/empty-values");
    if (this._columns === null) {
      this.columns(keys);
    }
    var self = this;
    var row = this._columns.map(function (c) {
      if (!Object.prototype.hasOwnProperty.call(obj, c)) {
        throw _err("insert row is missing column '" + c + "'", "sql-builder/missing-column");
      }
      return obj[c];
    });
    // Reject extra keys not in the column set (silent-drop would lose data).
    keys.forEach(function (k) {
      if (self._columns.indexOf(k) === -1) {
        throw _err("insert row has column '" + k + "' not in the column set", "sql-builder/extra-column");
      }
    });
    this._rows.push(row);
  }

  returning(cols) { this._returning = _normReturning(cols); return this; }

  _render() {
    if (this._columns === null || this._rows.length === 0) {
      throw _err("insert requires columns + at least one values() row", "sql-builder/empty-values");
    }
    var dialect = this._dialect;
    var quotedCols = this._columns.map(function (c) { return _quoteId(c, dialect); }).join(", ");
    var holders = [];
    var params = [];
    // Each cell renders to `?` (bound), `?::type` (cast), or an allowlisted
    // SQL function token (NOW() / CURRENT_TIMESTAMP - no param). A
    // SqlFunction / CastValue cell is identical across rows for a given
    // column, but the cell is resolved per-row so a multi-row insert can
    // mix a literal in one row and a function in another.
    for (var r = 0; r < this._rows.length; r++) {
      var cells = [];
      for (var v = 0; v < this._rows[r].length; v++) {
        var rendered = _renderValueCell(this._rows[r][v], dialect);
        cells.push(rendered.sql);
        for (var rp = 0; rp < rendered.params.length; rp++) params.push(rendered.params[rp]);
      }
      holders.push("(" + cells.join(", ") + ")");
    }
    var sql = "INSERT INTO " + this._table.ref(dialect) + " (" + quotedCols + ") VALUES " +
      holders.join(", ");
    sql += _renderReturning(this._returning, dialect);
    return _emit(sql, params);
  }
}

// ---- INSERT ... SELECT ... WHERE (conditional / append-only) --------
//
// A conditional INSERT that materialises its row from a value-less SELECT
// guarded by a WHERE - INSERT INTO t (cols) SELECT <cells> WHERE <guard>.
// The append-only-ledger debit idiom: the new row is written ONLY when a
// guard derived from the table itself holds (a store-credit / gift-card /
// points / metered-quota balance that lives on the latest row, with no
// mutable counter row to increment()). The SELECT has no FROM - it is a
// single computed row that the WHERE either admits (one row inserted) or
// rejects (zero rows), evaluated atomically inside the INSERT against the
// table the guard's correlated subquery / EXISTS references, so two racing
// debits cannot both pass the balance check.
//
// Standard-SQL across sqlite / Postgres / MySQL - the only dialect-divergent
// clause is RETURNING (Postgres / SQLite; refused on MySQL by the shared
// _renderReturning, which the MySQL caller replaces with an explicit read).
// Every SELECT cell routes through the SAME _renderValueCell choke-point
// INSERT VALUES uses (so a cell is a bound ?, a b.sql.cast(...) ?::type, or a
// b.sql.fn(...) allowlisted server function - no param), and the guard is a
// full Predicate (the whole where-family: whereExists / whereSub / whereOp /
// whereRaw / whereGroup compose, which is how a balance fence is expressed).
//
// Safety default: an INSERT...SELECT with no WHERE is just an INSERT...VALUES
// and shipping it un-guarded is almost always a bug, so the verb THROWS
// without a where() unless allowNoWhere() opts in - the same discipline
// update / delete apply.
class InsertSelectWhereBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("insert-select-where", tableNameOrRef, opts);
    this._columns = null;
    this._values = null;          // single row, aligned to _columns
    this._where = new Predicate(this, "AND");
    this._returning = null;
    this._allowNoWhere = false;
  }

  // Declare the target column list (validated + gated). values() infers it
  // from a row object's keys when omitted, exactly like INSERT.
  columns(cols) {
    if (!Array.isArray(cols) || cols.length === 0) {
      throw _err("columns() expects a non-empty array", "sql-builder/bad-columns");
    }
    var self = this;
    cols.forEach(function (c) { self._assertColumnMember(c, "insertSelectWhere"); _validateColumn(c); });
    this._columns = cols.slice();
    return this;
  }

  // values(obj) - one row from a column->value map (sets _columns from the
  // keys when not already declared). values(array) - one positional row
  // aligned to a prior columns() call. A single row only: the SELECT
  // materialises exactly one candidate row gated by the WHERE.
  values(rowOrArray) {
    if (Array.isArray(rowOrArray)) {
      if (this._columns === null) {
        throw _err("values(array) requires a prior columns([...]) call", "sql-builder/no-columns");
      }
      if (rowOrArray.length !== this._columns.length) {
        throw _err("values(array): " + rowOrArray.length + " values but " +
          this._columns.length + " columns", "sql-builder/value-count");
      }
      this._values = rowOrArray.slice();
      return this;
    }
    if (rowOrArray && typeof rowOrArray === "object") {
      var keys = Object.keys(rowOrArray);
      if (keys.length === 0) throw _err("insertSelectWhere row object is empty", "sql-builder/empty-values");
      if (this._columns === null) this.columns(keys);
      var self = this;
      this._values = this._columns.map(function (c) {
        if (!Object.prototype.hasOwnProperty.call(rowOrArray, c)) {
          throw _err("insertSelectWhere row is missing column '" + c + "'", "sql-builder/missing-column");
        }
        return rowOrArray[c];
      });
      keys.forEach(function (k) {
        if (self._columns.indexOf(k) === -1) {
          throw _err("insertSelectWhere row has column '" + k + "' not in the column set",
            "sql-builder/extra-column");
        }
      });
      return this;
    }
    throw _err("insertSelectWhere values() requires a row object or a value array aligned to columns()",
      "sql-builder/bad-values");
  }

  // A deliberate un-guarded conditional insert opts in here - same shape as
  // update / delete. Without it the verb refuses an empty WHERE.
  allowNoWhere() { this._allowNoWhere = true; return this; }

  where() { this._where.where.apply(this._where, arguments); return this; }
  andWhere() { this._where.andWhere.apply(this._where, arguments); return this; }
  orWhere() { this._where.orWhere.apply(this._where, arguments); return this; }
  whereOp(col, op, value) { this._where.whereOp(col, op, value); return this; }
  orWhereOp(col, op, value) { this._where.orWhereOp(col, op, value); return this; }
  whereIn(col, values) { this._where.whereIn(col, values); return this; }
  whereNotIn(col, values) { this._where.whereNotIn(col, values); return this; }
  orWhereIn(col, values) { this._where.orWhereIn(col, values); return this; }
  whereInArray(col, values) { this._where.whereInArray(col, values); return this; }
  orWhereInArray(col, values) { this._where.orWhereInArray(col, values); return this; }
  whereInJsonEach(col, jsonArrayString) { this._where.whereInJsonEach(col, jsonArrayString); return this; }
  whereMatch(target, expr) { this._where.whereMatch(target, expr); return this; }
  whereNull(col) { this._where.whereNull(col); return this; }
  whereNotNull(col) { this._where.whereNotNull(col); return this; }
  orWhereNull(col) { this._where.orWhereNull(col); return this; }
  whereLike(col, term, mode) { this._where.whereLike(col, term, mode); return this; }
  orWhereLike(col, term, mode) { this._where.orWhereLike(col, term, mode); return this; }
  whereBetween(col, low, high) { this._where.whereBetween(col, low, high); return this; }
  whereSub(col, op, sub) { this._where.whereSub(col, op, sub); return this; }
  whereExists(sub) { this._where.whereExists(sub); return this; }
  whereNotExists(sub) { this._where.whereNotExists(sub); return this; }
  orWhereExists(sub) { this._where.orWhereExists(sub); return this; }
  whereGroup(closure) { this._where.whereGroup(closure); return this; }
  orWhereGroup(closure) { this._where.orWhereGroup(closure); return this; }
  whereRaw(sql, params, opts) { this._where.whereRaw(sql, params, opts); return this; }
  orWhereRaw(sql, params, opts) { this._where.orWhereRaw(sql, params, opts); return this; }

  returning(cols) { this._returning = _normReturning(cols); return this; }

  _render() {
    if (this._columns === null || this._values === null) {
      throw _err("insertSelectWhere requires columns + a values() row", "sql-builder/empty-values");
    }
    if (this._where.length === 0 && !this._allowNoWhere) {
      throw _err("refusing unconditional insertSelectWhere - call where(...) first or " +
        "allowNoWhere() (an un-guarded INSERT...SELECT is just INSERT...VALUES)",
        "sql-builder/no-where");
    }
    var dialect = this._dialect;
    var params = [];
    var quotedCols = this._columns.map(function (c) { return _quoteId(c, dialect); }).join(", ");

    // Each SELECT cell renders through the same choke-point INSERT VALUES
    // uses: `?` (bound), `?::type` (cast), or an allowlisted server-function
    // token (NOW() / CURRENT_TIMESTAMP - no param).
    var cells = [];
    for (var v = 0; v < this._values.length; v += 1) {
      var rendered = _renderValueCell(this._values[v], dialect);
      cells.push(rendered.sql);
      for (var rp = 0; rp < rendered.params.length; rp += 1) params.push(rendered.params[rp]);
    }

    var sql = "INSERT INTO " + this._table.ref(dialect) + " (" + quotedCols + ") SELECT " +
      cells.join(", ");

    var w = this._where.build();
    if (w.sql) {
      sql += " WHERE " + w.sql;
      for (var wi = 0; wi < w.params.length; wi += 1) params.push(w.params[wi]);
    }

    sql += _renderReturning(this._returning, dialect);
    return _emit(sql, params);
  }
}

// ---- UPDATE ---------------------------------------------------------

class UpdateBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("update", tableNameOrRef, opts);
    this._set = [];               // [{ sql, params }]
    this._where = new Predicate(this, "AND");
    this._returning = null;
    this._allowNoWhere = false;
    // guardedUpdate() flips _requireGuard so _render refuses to emit a CAS
    // statement that has no compare-and-swap fence (which would silently be a
    // plain unconditional-on-state update). _guardCount tracks guardWhere calls.
    this._requireGuard = false;
    this._guardCount = 0;
  }

  // guardWhere(col, expected) - the compare-and-swap fence. ANDs
  // `col = <expected>` (a bound ?) into the WHERE so the UPDATE lands ONLY if
  // the row is STILL in the expected value - the cross-instance atomic claim
  // (the transaction substitute on autocommit-only substrates: D1 over an HTTP
  // bridge, any adapter without interactive transactions). An EXPLICIT
  // `null` becomes `col IS NULL` (since `col = NULL` is never true) so a
  // null-state fence works; `undefined` is REFUSED rather than silently
  // collapsing to `IS NULL`, because an omitted/unset expected value would turn
  // a CAS into "match the NULL-state rows" and update the wrong rows. The
  // won/lost result is read from rowCount via b.sql.casWon.
  guardWhere(col, expected) {
    if (expected === undefined) {
      throw _err("guardWhere expected value is undefined - pass an explicit null for an " +
        "IS NULL fence, or a value; refusing to silently match NULL-state rows",
        "sql-builder/bad-guard-value");
    }
    if (expected === null) {
      this._where.whereNull(col);
    } else {
      this._where.whereOp(col, "=", expected);
    }
    this._guardCount += 1;
    return this;
  }

  // guardWhereOp(col, op, expected) - a non-equality CAS fence (e.g. an
  // optimistic-version `>=`, or a balance `>= amount` debit guard). Routes the
  // operator through the same whereOp allowlist every other predicate uses.
  guardWhereOp(col, op, expected) {
    this._where.whereOp(col, op, expected);
    this._guardCount += 1;
    return this;
  }

  // set(obj) - column->value assignments. set(col, value) - single
  // assignment. A value may be a bound literal, a b.sql.cast(...) (binds
  // `?::type`), or a b.sql.fn(...) allowlisted SQL function (emits the
  // token, no param) - all routed through the single _renderValueCell
  // choke-point. A SqlFunction / CastValue is itself an object, so the
  // object-form detection excludes them explicitly.
  set(colOrObj, value) {
    var self = this;
    if (colOrObj && typeof colOrObj === "object" &&
        !(colOrObj instanceof SqlFunction) && !(colOrObj instanceof CastValue)) {
      var keys = Object.keys(colOrObj);
      if (keys.length === 0) throw _err("set object is empty", "sql-builder/empty-set");
      keys.forEach(function (k) {
        self._assertColumnMember(k, "update");
        var cell = _renderValueCell(colOrObj[k], self._dialect);
        self._set.push({ sql: _quoteId(k, self._dialect) + " = " + cell.sql, params: cell.params });
      });
      return this;
    }
    this._assertColumnMember(colOrObj, "update");
    var cell1 = _renderValueCell(value, this._dialect);
    this._set.push({ sql: _quoteId(colOrObj, this._dialect) + " = " + cell1.sql, params: cell1.params });
    return this;
  }

  // setRaw(col, rawExpr, params) - assign a guarded raw expression
  // (e.g. "count" = "count" + ?). The column is quoted; the expression
  // is guarded + placeholder-checked.
  setRaw(col, expr, params, opts) {
    this._assertColumnMember(col, "update");
    var checked = _checkRawFragment(expr, params, opts, "setRaw");
    this._set.push({
      sql: _quoteId(col, this._dialect) + " = " + checked.sql,
      params: checked.params,
    });
    return this;
  }

  allowNoWhere() { this._allowNoWhere = true; return this; }

  where() { this._where.where.apply(this._where, arguments); return this; }
  andWhere() { this._where.andWhere.apply(this._where, arguments); return this; }
  orWhere() { this._where.orWhere.apply(this._where, arguments); return this; }
  whereOp(col, op, value) { this._where.whereOp(col, op, value); return this; }
  orWhereOp(col, op, value) { this._where.orWhereOp(col, op, value); return this; }
  whereIn(col, values) { this._where.whereIn(col, values); return this; }
  whereNotIn(col, values) { this._where.whereNotIn(col, values); return this; }
  orWhereIn(col, values) { this._where.orWhereIn(col, values); return this; }
  whereInArray(col, values) { this._where.whereInArray(col, values); return this; }
  orWhereInArray(col, values) { this._where.orWhereInArray(col, values); return this; }
  whereInJsonEach(col, jsonArrayString) { this._where.whereInJsonEach(col, jsonArrayString); return this; }
  whereMatch(target, expr) { this._where.whereMatch(target, expr); return this; }
  whereNull(col) { this._where.whereNull(col); return this; }
  whereNotNull(col) { this._where.whereNotNull(col); return this; }
  orWhereNull(col) { this._where.orWhereNull(col); return this; }
  whereLike(col, term, mode) { this._where.whereLike(col, term, mode); return this; }
  orWhereLike(col, term, mode) { this._where.orWhereLike(col, term, mode); return this; }
  whereSub(col, op, sub) { this._where.whereSub(col, op, sub); return this; }
  whereExists(sub) { this._where.whereExists(sub); return this; }
  whereNotExists(sub) { this._where.whereNotExists(sub); return this; }
  whereGroup(closure) { this._where.whereGroup(closure); return this; }
  orWhereGroup(closure) { this._where.orWhereGroup(closure); return this; }
  whereRaw(sql, params, opts) { this._where.whereRaw(sql, params, opts); return this; }
  orWhereRaw(sql, params, opts) { this._where.orWhereRaw(sql, params, opts); return this; }

  returning(cols) { this._returning = _normReturning(cols); return this; }

  _render() {
    if (this._set.length === 0) throw _err("update requires a set(...) call", "sql-builder/empty-set");
    if (this._requireGuard && this._guardCount === 0) {
      throw _err("guardedUpdate requires at least one guardWhere(...) / guardWhereOp(...) " +
        "compare-and-swap fence - without it this is a plain update; use b.sql.update for that",
        "sql-builder/no-guard");
    }
    if (this._where.length === 0 && !this._allowNoWhere) {
      throw _err("refusing unconditional update - call where(...) first or allowNoWhere()",
        "sql-builder/no-where");
    }
    var dialect = this._dialect;
    var params = [];
    var setPieces = [];
    for (var s = 0; s < this._set.length; s++) {
      setPieces.push(this._set[s].sql);
      for (var sp = 0; sp < this._set[s].params.length; sp++) params.push(this._set[s].params[sp]);
    }
    var sql = "UPDATE " + this._table.ref(dialect) + " SET " + setPieces.join(", ");
    var w = this._where.build();
    if (w.sql) { sql += " WHERE " + w.sql; for (var wi = 0; wi < w.params.length; wi++) params.push(w.params[wi]); }
    sql += _renderReturning(this._returning, dialect);
    return _emit(sql, params);
  }
}

// ---- DELETE ---------------------------------------------------------

class DeleteBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("delete", tableNameOrRef, opts);
    this._where = new Predicate(this, "AND");
    this._returning = null;
    this._allowNoWhere = false;
  }

  allowNoWhere() { this._allowNoWhere = true; return this; }

  where() { this._where.where.apply(this._where, arguments); return this; }
  andWhere() { this._where.andWhere.apply(this._where, arguments); return this; }
  orWhere() { this._where.orWhere.apply(this._where, arguments); return this; }
  whereOp(col, op, value) { this._where.whereOp(col, op, value); return this; }
  orWhereOp(col, op, value) { this._where.orWhereOp(col, op, value); return this; }
  whereIn(col, values) { this._where.whereIn(col, values); return this; }
  whereNotIn(col, values) { this._where.whereNotIn(col, values); return this; }
  orWhereIn(col, values) { this._where.orWhereIn(col, values); return this; }
  whereInArray(col, values) { this._where.whereInArray(col, values); return this; }
  orWhereInArray(col, values) { this._where.orWhereInArray(col, values); return this; }
  whereInJsonEach(col, jsonArrayString) { this._where.whereInJsonEach(col, jsonArrayString); return this; }
  whereMatch(target, expr) { this._where.whereMatch(target, expr); return this; }
  whereNull(col) { this._where.whereNull(col); return this; }
  whereNotNull(col) { this._where.whereNotNull(col); return this; }
  orWhereNull(col) { this._where.orWhereNull(col); return this; }
  whereLike(col, term, mode) { this._where.whereLike(col, term, mode); return this; }
  orWhereLike(col, term, mode) { this._where.orWhereLike(col, term, mode); return this; }
  whereSub(col, op, sub) { this._where.whereSub(col, op, sub); return this; }
  whereExists(sub) { this._where.whereExists(sub); return this; }
  whereNotExists(sub) { this._where.whereNotExists(sub); return this; }
  whereGroup(closure) { this._where.whereGroup(closure); return this; }
  orWhereGroup(closure) { this._where.orWhereGroup(closure); return this; }
  whereRaw(sql, params, opts) { this._where.whereRaw(sql, params, opts); return this; }
  orWhereRaw(sql, params, opts) { this._where.orWhereRaw(sql, params, opts); return this; }

  returning(cols) { this._returning = _normReturning(cols); return this; }

  _render() {
    if (this._where.length === 0 && !this._allowNoWhere) {
      throw _err("refusing unconditional delete - call where(...) first or allowNoWhere()",
        "sql-builder/no-where");
    }
    var dialect = this._dialect;
    var params = [];
    var sql = "DELETE FROM " + this._table.ref(dialect);
    var w = this._where.build();
    if (w.sql) { sql += " WHERE " + w.sql; for (var wi = 0; wi < w.params.length; wi++) params.push(w.params[wi]); }
    sql += _renderReturning(this._returning, dialect);
    return _emit(sql, params);
  }
}

// ---- UPSERT (the dialect-divergence centrepiece) --------------------
//
// The one verb that must emit dialect-final syntax - placeholderize +
// resolveTables cannot synthesise a conflict clause.
//
//   Postgres / SQLite:
//     INSERT INTO t (cols) VALUES (?...) ON CONFLICT (keys)
//       DO UPDATE SET col = EXCLUDED.col [WHERE <guard>] [RETURNING ...]
//     | DO NOTHING
//
//   MySQL:
//     INSERT INTO t (cols) VALUES (?...) ON DUPLICATE KEY UPDATE
//       col = VALUES(col)              (or IF(<guard>, VALUES(col), col)
//                                       when conflictWhere is present -
//                                       MySQL has no per-statement WHERE
//                                       on the conflict action)
//     No WHERE, no RETURNING. A readbackSql SELECT is auto-emitted so the
//     caller can fetch the upserted row the way RETURNING would have
//     surfaced it.
//
// All three conflict actions are required: doUpdate (re-bind specific
// columns, optionally to an expression), doUpdateFromExcluded (set the
// listed columns to the proposed row's values), and doNothing.
class UpsertBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("upsert", tableNameOrRef, opts);
    this._columns = null;
    this._values = null;          // single row, aligned to _columns
    this._conflictKeys = null;
    this._action = null;          // "update" | "update-excluded" | "nothing"
    this._updateCols = null;      // for update-excluded: [col, ...]
    this._updateExprs = null;     // for update: { col: "?" | rawExpr } map, ordered
    this._updateParams = null;    // params for the update expressions
    this._conflictWhere = null;   // { sql, params } guarded fragment
    this._returning = null;
  }

  columns(cols) {
    if (!Array.isArray(cols) || cols.length === 0) {
      throw _err("columns() expects a non-empty array", "sql-builder/bad-columns");
    }
    var self = this;
    cols.forEach(function (c) { self._assertColumnMember(c, "upsert"); _validateColumn(c); });
    this._columns = cols.slice();
    return this;
  }

  values(obj) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      throw _err("upsert values() requires a single row object", "sql-builder/bad-values");
    }
    var keys = Object.keys(obj);
    if (keys.length === 0) throw _err("upsert row object is empty", "sql-builder/empty-values");
    if (this._columns === null) this.columns(keys);
    var self = this;
    this._values = this._columns.map(function (c) {
      if (!Object.prototype.hasOwnProperty.call(obj, c)) {
        throw _err("upsert row is missing column '" + c + "'", "sql-builder/missing-column");
      }
      return obj[c];
    });
    keys.forEach(function (k) {
      if (self._columns.indexOf(k) === -1) {
        throw _err("upsert row has column '" + k + "' not in the column set", "sql-builder/extra-column");
      }
    });
    return this;
  }

  onConflict(keyCols) {
    var arr = Array.isArray(keyCols) ? keyCols : [keyCols];
    if (arr.length === 0) throw _err("onConflict requires at least one key column", "sql-builder/bad-conflict");
    arr.forEach(_validateColumn);
    this._conflictKeys = arr.slice();
    return this;
  }

  // DO UPDATE SET col = EXCLUDED.col for each listed column.
  doUpdateFromExcluded(cols) {
    if (!Array.isArray(cols) || cols.length === 0) {
      throw _err("doUpdateFromExcluded requires a non-empty column array", "sql-builder/conflict-action");
    }
    var self = this;
    cols.forEach(function (c) { self._assertColumnMember(c, "upsert"); _validateColumn(c); });
    this._action = "update-excluded";
    this._updateCols = cols.slice();
    return this;
  }

  // DO UPDATE SET col = <value-or-expr>. An array of columns sets each
  // to EXCLUDED.col (Postgres/SQLite) / VALUES(col) (MySQL). An object
  // { col: "?" } re-binds the column to a supplied param; { col: rawExpr }
  // sets it to a guarded raw expression. Pass exprParams for any `?` in
  // the object's expressions, in column order.
  doUpdate(colsOrMap, exprParams) {
    if (Array.isArray(colsOrMap)) return this.doUpdateFromExcluded(colsOrMap);
    if (!colsOrMap || typeof colsOrMap !== "object") {
      throw _err("doUpdate requires a column array or a { col: expr } map", "sql-builder/conflict-action");
    }
    var keys = Object.keys(colsOrMap);
    if (keys.length === 0) throw _err("doUpdate map is empty", "sql-builder/conflict-action");
    var self = this;
    keys.forEach(function (c) { self._assertColumnMember(c, "upsert"); _validateColumn(c); });
    this._action = "update";
    this._updateExprs = colsOrMap;
    this._updateParams = Array.isArray(exprParams) ? exprParams.slice()
      : (exprParams == null ? [] : [exprParams]);
    return this;
  }

  doNothing() { this._action = "nothing"; return this; }

  // The fenced WHERE on the conflict action (Postgres/SQLite); on MySQL
  // it folds into IF(<guard>, VALUES(col), col). Guarded raw fragment.
  //
  // opts.guardColumn names the column the fence protects - the column the
  // guard expression compares against (e.g. a monotonic fencing token).
  // On MySQL it is emitted LAST in the SET list so the IF on every other
  // column evaluates the guard against this column's PRE-UPDATE value
  // (MySQL evaluates the SET list left to right and a later assignment in
  // the same statement sees earlier columns' already-updated values - the
  // IF-eval-order hazard). Ignored on Postgres / SQLite, which apply the
  // WHERE atomically. When omitted the SET list keeps its declared order
  // (correct whenever the guard does not also appear as a SET target).
  conflictWhere(sql, params, opts) {
    var checked = _checkRawFragment(sql, params, opts, "conflictWhere");
    var guardColumn = opts && opts.guardColumn;
    if (guardColumn !== undefined && guardColumn !== null) {
      _validateColumn(guardColumn);
      checked.guardColumn = guardColumn;
    }
    this._conflictWhere = checked;
    return this;
  }

  returning(cols) { this._returning = _normReturning(cols); return this; }

  // Render the VALUES tuple through the same _renderValueCell choke-point
  // INSERT uses, so an upsert VALUES cell may be a bound literal, a
  // b.sql.cast(...) (`?::type`), or a b.sql.fn(...) allowlisted function
  // (`NOW()` / `CURRENT_TIMESTAMP`, no param). Without this the wrapper
  // objects would leak straight into params (a SqlFunction / CastValue is
  // an object, not a scalar) and the driver would mis-bind them.
  _renderValuesTuple(dialect) {
    var cells = [];
    var params = [];
    for (var i = 0; i < this._values.length; i += 1) {
      var rendered = _renderValueCell(this._values[i], dialect);
      cells.push(rendered.sql);
      for (var p = 0; p < rendered.params.length; p += 1) params.push(rendered.params[p]);
    }
    return { sql: cells.join(", "), params: params };
  }

  _render() {
    if (this._columns === null || this._values === null) {
      throw _err("upsert requires columns + values()", "sql-builder/empty-values");
    }
    if (this._action === null) {
      throw _err("upsert requires a conflict action - doUpdate(...) / " +
        "doUpdateFromExcluded(...) / doNothing()", "sql-builder/conflict-action");
    }
    if (this._action !== "nothing" && this._conflictKeys === null && this._dialect !== "mysql") {
      throw _err("upsert doUpdate requires onConflict(keys) on " + this._dialect,
        "sql-builder/bad-conflict");
    }
    return this._dialect === "mysql" ? this._renderMysql() : this._renderStandard();
  }

  // Postgres + SQLite: ON CONFLICT (keys) DO UPDATE ... [WHERE] [RETURNING].
  _renderStandard() {
    var dialect = this._dialect;
    var quotedCols = this._columns.map(function (c) { return _quoteId(c, dialect); }).join(", ");
    var tuple = this._renderValuesTuple(dialect);
    var params = tuple.params;

    var sql = "INSERT INTO " + this._table.ref(dialect) + " (" + quotedCols + ") VALUES (" +
      tuple.sql + ")";

    if (this._action === "nothing") {
      sql += " ON CONFLICT" + this._conflictTarget(dialect) + " DO NOTHING";
    } else {
      var setClause = this._buildStandardSet(dialect);
      sql += " ON CONFLICT" + this._conflictTarget(dialect) + " DO UPDATE SET " + setClause.sql;
      for (var i = 0; i < setClause.params.length; i++) params.push(setClause.params[i]);
      if (this._conflictWhere) {
        sql += " WHERE " + this._conflictWhere.sql;
        for (var w = 0; w < this._conflictWhere.params.length; w++) params.push(this._conflictWhere.params[w]);
      }
    }
    sql += _renderReturning(this._returning, dialect);
    return _emit(sql, params);
  }

  _conflictTarget(dialect) {
    if (this._conflictKeys === null) return "";
    var keys = this._conflictKeys.map(function (k) { return _quoteId(k, dialect); }).join(", ");
    return " (" + keys + ")";
  }

  _buildStandardSet(dialect) {
    var pieces = [];
    var params = [];
    if (this._action === "update-excluded") {
      for (var i = 0; i < this._updateCols.length; i++) {
        var c = this._updateCols[i];
        pieces.push(_quoteId(c, dialect) + " = EXCLUDED." + _quoteId(c, dialect));
      }
    } else {
      // action === "update": { col: expr } map. "?" re-binds to a param;
      // any other string is a guarded raw expression.
      var keys = Object.keys(this._updateExprs);
      var paramCursor = 0;
      for (var k = 0; k < keys.length; k++) {
        var col = keys[k];
        var expr = this._updateExprs[col];
        if (expr === "?") {
          pieces.push(_quoteId(col, dialect) + " = ?");
          params.push(this._updateParams[paramCursor]);
          paramCursor += 1;
        } else if (typeof expr === "string") {
          // Guarded raw expression (e.g. "EXCLUDED.\"count\" + 1"). Its
          // own `?` placeholders draw from _updateParams in order.
          var remaining = this._updateParams.slice(paramCursor);
          var needed = _countPlaceholders(expr);
          var exprParams = remaining.slice(0, needed);
          var checked = _checkRawFragment(expr, exprParams, { allowLiterals: false }, "doUpdate");
          pieces.push(_quoteId(col, dialect) + " = " + checked.sql);
          for (var ep = 0; ep < checked.params.length; ep++) params.push(checked.params[ep]);
          paramCursor += needed;
        } else {
          throw _err("doUpdate expression for '" + col + "' must be '?' or a raw SQL string",
            "sql-builder/conflict-action");
        }
      }
    }
    return { sql: pieces.join(", "), params: params };
  }

  // MySQL: ON DUPLICATE KEY UPDATE col = VALUES(col). No WHERE, no
  // RETURNING. conflictWhere folds into IF(<guard>, VALUES(col), col).
  // The guard column is emitted LAST so MySQL's left-to-right evaluation
  // of the SET list sees the other columns' pre-guard values when the
  // guard references them (the IF-eval-order hazard). A readbackSql
  // SELECT is returned alongside so the caller can fetch the row that
  // RETURNING would have surfaced.
  _renderMysql() {
    var dialect = "mysql";
    var quotedCols = this._columns.map(function (c) { return _quoteId(c, dialect); }).join(", ");
    var tuple = this._renderValuesTuple(dialect);
    var params = tuple.params;

    var sql = "INSERT INTO " + this._table.ref(dialect) + " (" + quotedCols + ") VALUES (" +
      tuple.sql + ")";

    if (this._action === "nothing") {
      // MySQL has no DO NOTHING; the idiom is to no-op a key column.
      // Assign the first conflict / first column to itself so the row is
      // left unchanged on duplicate.
      var noopCol = (this._conflictKeys && this._conflictKeys[0]) || this._columns[0];
      sql += " ON DUPLICATE KEY UPDATE " + _quoteId(noopCol, dialect) + " = " +
        _quoteId(noopCol, dialect);
    } else {
      var setBuild = this._buildMysqlSet(dialect);
      sql += " ON DUPLICATE KEY UPDATE " + setBuild.sql;
      for (var i = 0; i < setBuild.params.length; i++) params.push(setBuild.params[i]);
    }

    var out = _emit(sql, params);
    // RETURNING is unavailable on MySQL upsert - emit a readback SELECT
    // keyed on the conflict columns so the caller fetches the row. Validate
    // it through the same output gate.
    if (this._returning !== null) {
      var rb = this._buildReadback(dialect);
      _assertEmittable(rb.sql, rb.params);
      out.readbackSql = rb;
    }
    return out;
  }

  _buildMysqlSet(dialect) {
    var guardSqlText = this._conflictWhere ? this._conflictWhere.sql : null;
    var guardParams = this._conflictWhere ? this._conflictWhere.params : [];

    // Resolve the ordered (col, assignment-RHS) list WITHOUT the guard
    // wrap first; then, when a guard is present, wrap each RHS in
    // IF(<guard>, <rhs>, col) and order the guard column (a column the
    // guard references, if it is itself a set target) LAST.
    var assignments = [];   // [{ col, rhs, rhsParams }]
    if (this._action === "update-excluded") {
      for (var i = 0; i < this._updateCols.length; i++) {
        var c = this._updateCols[i];
        assignments.push({ col: c, rhs: "VALUES(" + _quoteId(c, dialect) + ")", rhsParams: [] });
      }
    } else {
      var keys = Object.keys(this._updateExprs);
      var paramCursor = 0;
      for (var k = 0; k < keys.length; k++) {
        var col = keys[k];
        var expr = this._updateExprs[col];
        if (expr === "?") {
          assignments.push({ col: col, rhs: "?", rhsParams: [this._updateParams[paramCursor]] });
          paramCursor += 1;
        } else if (typeof expr === "string") {
          var needed = _countPlaceholders(expr);
          var exprParams = this._updateParams.slice(paramCursor, paramCursor + needed);
          var checked = _checkRawFragment(expr, exprParams, { allowLiterals: false }, "doUpdate");
          assignments.push({ col: col, rhs: checked.sql, rhsParams: checked.params });
          paramCursor += needed;
        } else {
          throw _err("doUpdate expression for '" + col + "' must be '?' or a raw SQL string",
            "sql-builder/conflict-action");
        }
      }
    }

    var pieces = [];
    var params = [];
    if (guardSqlText === null) {
      for (var a = 0; a < assignments.length; a++) {
        pieces.push(_quoteId(assignments[a].col, dialect) + " = " + assignments[a].rhs);
        for (var ap = 0; ap < assignments[a].rhsParams.length; ap++) params.push(assignments[a].rhsParams[ap]);
      }
      return { sql: pieces.join(", "), params: params };
    }

    // Guarded: col = IF(<guard>, <rhs>, col). The guard's own params are
    // bound once per assignment (the guard expression repeats per SET
    // target in MySQL's UPDATE list). The guard column - the column the
    // fenced comparison protects - is emitted last so the IF on the
    // other columns evaluates against this column's pre-update value.
    var guardColName = this._conflictWhere && this._conflictWhere.guardColumn
      ? this._conflictWhere.guardColumn : null;
    var ordered = assignments.slice();
    if (guardColName) {
      ordered.sort(function (x, y) {
        var xg = x.col === guardColName ? 1 : 0;
        var yg = y.col === guardColName ? 1 : 0;
        return xg - yg;
      });
    }
    for (var o = 0; o < ordered.length; o++) {
      var qc = _quoteId(ordered[o].col, dialect);
      pieces.push(qc + " = IF(" + guardSqlText + ", " + ordered[o].rhs + ", " + qc + ")");
      for (var gp = 0; gp < guardParams.length; gp++) params.push(guardParams[gp]);
      for (var rp = 0; rp < ordered[o].rhsParams.length; rp++) params.push(ordered[o].rhsParams[rp]);
    }
    return { sql: pieces.join(", "), params: params };
  }

  // Readback SELECT for the MySQL upsert path - fetch the upserted row by
  // its conflict key(s) bound to the proposed values, projecting the
  // RETURNING column list (or "*").
  _buildReadback(dialect) {
    var keys = this._conflictKeys || [];
    if (keys.length === 0) {
      // No declared conflict key - read back by the full proposed row's
      // first column as a best-effort key.
      keys = [this._columns[0]];
    }
    var proj = (this._returning === "*" || this._returning === null)
      ? "*"
      : this._returning.map(function (c) { return _quoteId(c, dialect); }).join(", ");
    var sql = "SELECT " + proj + " FROM " + this._table.ref(dialect);
    var params = [];
    var conds = [];
    for (var i = 0; i < keys.length; i++) {
      var idx = this._columns.indexOf(keys[i]);
      if (idx === -1) {
        throw _err("upsert readback: conflict key '" + keys[i] + "' is not in the value set",
          "sql-builder/bad-conflict");
      }
      var keyVal = this._values[idx];
      if (keyVal instanceof SqlFunction) {
        // A server-evaluated function (NOW() / CURRENT_TIMESTAMP / ...) as a
        // conflict key has no stable readback identity: the row holds the value
        // the server computed at INSERT time, which a fresh evaluation in this
        // WHERE would never equal, so the readback would silently match zero
        // rows. Refuse rather than return a wrong (empty) result.
        throw _err("upsert readback: conflict key '" + keys[i] + "' is a " +
          "server-evaluated function (b.sql.fn) with no stable readback identity " +
          "- use a literal/cast conflict key or read the row back explicitly",
          "sql-builder/bad-conflict");
      }
      // Resolve the key value through the same cell renderer the VALUES tuple
      // uses, so a b.sql.cast(...) conflict key emits `col = CAST(? AS type)`
      // (Postgres `col = ?::type`) binding the inner value, and a plain scalar
      // still emits `col = ?` binding the value unchanged.
      var cell = _renderValueCell(keyVal, dialect);
      conds.push(_quoteId(keys[i], dialect) + " = " + cell.sql);
      for (var cp = 0; cp < cell.params.length; cp++) params.push(cell.params[cp]);
    }
    sql += " WHERE " + conds.join(" AND ");
    return { sql: sql, params: params };
  }
}

// RETURNING normalization - "*" or an array of validated columns.
function _normReturning(cols) {
  if (cols === "*" || cols === undefined || cols === null) return "*";
  var arr = Array.isArray(cols) ? cols : [cols];
  arr.forEach(_validateColumn);
  return arr.slice();
}

function _renderReturning(returning, dialect) {
  if (returning === null) return "";
  // MySQL / MariaDB do not support RETURNING on INSERT / UPDATE / DELETE.
  // Emitting it would parse-error at the driver; refuse at build with a
  // clear message so the operator runs an explicit read-back SELECT.
  // (The upsert verb's MySQL path already auto-emits a readback instead of
  // reaching here.)
  if (dialect === "mysql") {
    throw _err("RETURNING is not supported on MySQL for this verb - run a " +
      "read-back SELECT on the affected key instead", "sql-builder/returning-unsupported");
  }
  if (returning === "*") return " RETURNING *";
  return " RETURNING " + returning.map(function (c) { return _quoteId(c, dialect); }).join(", ");
}

// ---- DDL builders ---------------------------------------------------
//
// Operator app-schema parity: createTable / createIndex / alterTable /
// dropTable, dialect-aware and quote-by-construction, reusing the
// framework's own type vocabulary (no fork of the type map). DDL is
// declarative - these return { sql } (no params) since DDL binds no
// values.

/**
 * @primitive  b.sql.createTable
 * @signature  b.sql.createTable(name, columns, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.createIndex, b.sql.alterTable, b.sql.dropTable
 *
 * Build a `CREATE TABLE` statement with every identifier quoted by
 * construction and every column type drawn from the framework's own
 * type map (so an operator app-schema table is portable across the same
 * dialects the framework tables are). `columns` is an array of column
 * specs; each `{ name, type, constraints?, primaryKey?, notNull?,
 * unique?, default? }`. The `type` is a logical name (`int` / `text` /
 * `blob` / `boolean` / `real` / `numeric` / `timestamp` / `json`) mapped
 * to the dialect token, or a verbatim dialect type string. Emits
 * `IF NOT EXISTS` by default so re-running is idempotent.
 *
 * @opts
 *   dialect:       string,   // postgres | sqlite | mysql (default sqlite)
 *   ifNotExists:   boolean,  // default true
 *   primaryKey:    array,    // composite PK column list (table-level)
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.createTable("widget", [
 *     { name: "id",   type: "int",  primaryKey: true },
 *     { name: "name", type: "text", notNull: true },
 *   ], { dialect: "postgres" }).sql;
 *   // -> 'CREATE TABLE IF NOT EXISTS widget ("id" BIGINT PRIMARY KEY, "name" TEXT NOT NULL)'
 *   //   (the bare default table name is the clusterStorage rewrite
 *   //    target; pass a prefix or schema to quote it)
 */
function createTable(name, columns, opts) {
  opts = opts || {};
  var dialect = _normDialect(opts.dialect);
  var ref = _normTableRef(name, opts);
  if (!Array.isArray(columns) || columns.length === 0) {
    throw _err("createTable requires a non-empty columns array", "sql-builder/bad-columns");
  }
  var pieces = columns.map(function (c) {
    if (typeof c !== "object" || c === null || typeof c.name !== "string") {
      throw _err("createTable column must be { name, type, ... }", "sql-builder/bad-column");
    }
    _validateColumn(c.name);
    var qn = _quoteId(c.name, dialect);
    // Auto-increment / identity PK. This MUST diverge by dialect or an app
    // developed on the default sqlite dialect (where INTEGER PRIMARY KEY is
    // a rowid alias that auto-increments implicitly) breaks on the
    // postgres / mysql backend the builder advertises portability to (a
    // plain BIGINT PRIMARY KEY there does NOT default a value). postgres ->
    // BIGSERIAL (implies the int type + sequence default); sqlite -> INTEGER
    // PRIMARY KEY AUTOINCREMENT (MUST be INTEGER, not BIGINT); mysql ->
    // BIGINT AUTO_INCREMENT. An identity column is the primary key and takes
    // no DEFAULT.
    if (c.autoIncrement || c.serial) {
      if (c.default !== undefined) {
        throw _err("createTable: auto-increment column '" + c.name +
          "' cannot also declare a default", "sql-builder/bad-column");
      }
      var idDef;
      if (dialect === "postgres") idDef = qn + " BIGSERIAL PRIMARY KEY";
      else if (dialect === "mysql") idDef = qn + " BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY";
      else idDef = qn + " INTEGER PRIMARY KEY AUTOINCREMENT";
      if (typeof c.constraints === "string" && c.constraints.length > 0) {
        var idCk = _checkRawFragment(c.constraints, [], { allowLiterals: true }, "createTable.constraints");
        idDef += " " + idCk.sql;
      }
      return idDef;
    }
    var def = qn + " " + _ddlType(c.type, dialect);
    if (c.primaryKey) def += " PRIMARY KEY";
    if (c.notNull) def += " NOT NULL";
    if (c.unique) def += " UNIQUE";
    if (c.default !== undefined) def += " DEFAULT " + _ddlDefault(c.default);
    // Foreign key: a quote-by-construction REFERENCES clause (string table
    // name or { table, column?, onDelete?, onUpdate? }). Identifiers are
    // validated + quoted; the referential actions are allowlisted.
    if (c.references !== undefined && c.references !== false) {
      def += _ddlReferences(c.references, dialect, opts);
    }
    if (typeof c.constraints === "string" && c.constraints.length > 0) {
      // Verbatim constraint clause (CHECK / REFERENCES). Guarded so an
      // operator-influenced constraint can't smuggle a statement.
      var checked = _checkRawFragment(c.constraints, [], { allowLiterals: true }, "createTable.constraints");
      def += " " + checked.sql;
    }
    return def;
  });
  if (Array.isArray(opts.primaryKey) && opts.primaryKey.length > 0) {
    // A column-level primary key (primaryKey / autoIncrement / serial) and a
    // composite opts.primaryKey are mutually exclusive: emitting both produces
    // two PRIMARY KEY clauses, which sqlite / Postgres / MySQL all reject at the
    // driver. Catch the contradiction at build time with a clear error rather
    // than a cryptic "multiple primary keys" failure mid-migration. Lives in the
    // shared composer so defineTable is covered too.
    var colHasPk = columns.some(function (c) {
      return c && (c.primaryKey || c.autoIncrement || c.serial);
    });
    if (colHasPk) {
      throw _err("createTable: a column-level primary key (primaryKey / " +
        "autoIncrement / serial) and a composite opts.primaryKey are mutually " +
        "exclusive", "sql-builder/bad-column");
    }
    opts.primaryKey.forEach(_validateColumn);
    pieces.push("PRIMARY KEY (" + opts.primaryKey.map(function (k) {
      return _quoteId(k, dialect);
    }).join(", ") + ")");
  }
  var ifNot = opts.ifNotExists === false ? "" : "IF NOT EXISTS ";
  var sql = "CREATE TABLE " + ifNot + ref.ref(dialect) + " (" + pieces.join(", ") + ")";
  // Route the finished DDL through the same emittable gate every SELECT /
  // INSERT / UPDATE / DELETE verb uses: it refuses a stacked top-level ';', a
  // NUL, an unterminated quote, and unbalanced parens - a defence-in-depth
  // backstop behind the per-column type / constraint guards.
  return _assertCatalogEmittable(sql, []);
}

// DDL DEFAULT renderer - numeric / boolean / null inline; a string
// default is emitted as a single-quoted SQL literal with the quote
// doubled to escape it (DDL defaults are static, operator-controlled,
// and never bound).
function _ddlDefault(value) {
  if (value === null) return "NULL";
  if (typeof value === "number" && isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "string") return "'" + value.replace(/'/g, "''") + "'";
  throw _err("createTable column default must be a string, number, boolean, or null",
    "sql-builder/bad-default");
}

// Referential actions allowed on a foreign key (ON DELETE / ON UPDATE).
var FK_ACTIONS = Object.freeze({
  "CASCADE": true, "SET NULL": true, "SET DEFAULT": true, "RESTRICT": true, "NO ACTION": true,
});

// Quote-by-construction REFERENCES clause. `references` is a table-name
// string (referenced column defaults to "id") or { table, column?, onDelete?,
// onUpdate? }. The referenced table inherits the parent table's prefix /
// schema so a prefixed deployment's FK target resolves to the same namespace.
function _ddlReferences(references, dialect, opts) {
  var spec = typeof references === "string" ? { table: references } : references;
  if (!spec || typeof spec.table !== "string" || spec.table.length === 0) {
    throw _err("column 'references' must be a table name or { table, column?, onDelete?, onUpdate? }",
      "sql-builder/bad-references");
  }
  var refTable = _normTableRef(spec.table, opts || {});
  var refCol = spec.column || "id";
  _validateColumn(refCol);
  var out = " REFERENCES " + refTable.ref(dialect) + " (" + _quoteId(refCol, dialect) + ")";
  ["onDelete", "onUpdate"].forEach(function (k) {
    if (spec[k] === undefined || spec[k] === null) return;
    var action = String(spec[k]).toUpperCase();
    if (FK_ACTIONS[action] !== true) {
      throw _err("invalid " + k + " referential action '" + spec[k] +
        "' (CASCADE / SET NULL / SET DEFAULT / RESTRICT / NO ACTION)", "sql-builder/bad-fk-action");
    }
    out += (k === "onDelete" ? " ON DELETE " : " ON UPDATE ") + action;
  });
  return out;
}

/**
 * @primitive  b.sql.createIndex
 * @signature  b.sql.createIndex(name, tableName, columns, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.createTable, b.sql.dropTable
 *
 * Build a `CREATE INDEX` statement, identifiers quoted by construction,
 * `IF NOT EXISTS` by default. `columns` is the indexed column list (each
 * quoted); `opts.unique` emits a `UNIQUE INDEX`.
 *
 * @opts
 *   dialect:      string,   // postgres | sqlite | mysql (default sqlite)
 *   unique:       boolean,  // default false
 *   ifNotExists:  boolean,  // default true
 *   where:        string,   // partial-index predicate (guarded raw fragment)
 *   whereParams:  Array,    // bound params for the partial-index predicate
 *
 * A partial index (`opts.where`) narrows the index to rows matching a
 * boolean predicate - the publisher's pending-row index
 * (`WHERE status = 'pending'`) is the canonical case. The predicate rides
 * the same `b.guardSql`-gated raw-fragment path as `whereRaw` (a static
 * operator-controlled literal opts in via `allowLiterals`); MySQL has no
 * partial index, so it throws there.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.createIndex("idx_widget_name", "widget", ["name"],
 *     { dialect: "sqlite", unique: true }).sql;
 *   // -> 'CREATE UNIQUE INDEX IF NOT EXISTS "idx_widget_name" ON widget ("name")'
 *   //   (the index name is quoted; the bare default table stays the
 *   //    clusterStorage rewrite target)
 */
function createIndex(name, tableName, columns, opts) {
  opts = opts || {};
  var dialect = _normDialect(opts.dialect);
  _validateColumn(name);
  var ref = _normTableRef(tableName, opts);
  if (!Array.isArray(columns) || columns.length === 0) {
    throw _err("createIndex requires a non-empty columns array", "sql-builder/bad-columns");
  }
  columns.forEach(_validateColumn);
  var ifNot = opts.ifNotExists === false ? "" : "IF NOT EXISTS ";
  var cols = columns.map(function (c) { return _quoteId(c, dialect); }).join(", ");
  var sql = "CREATE " + (opts.unique ? "UNIQUE " : "") + "INDEX " + ifNot +
    _quoteId(name, dialect) + " ON " + ref.ref(dialect) + " (" + cols + ")";
  var params = [];
  if (opts.where !== undefined && opts.where !== null) {
    if (dialect === "mysql") {
      throw _err("createIndex: partial index (where) is Postgres / SQLite-only " +
        "(MySQL has no partial index)", "sql-builder/partial-index-unsupported");
    }
    var checked = _checkRawFragment(opts.where, opts.whereParams,
      { allowLiterals: opts.allowLiterals !== false }, "createIndex.where");
    sql += " WHERE " + checked.sql;
    params = checked.params;
  }
  return { sql: sql, params: params };
}

/**
 * @primitive  b.sql.alterTable
 * @signature  b.sql.alterTable(name, change, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.createTable, b.sql.dropTable
 *
 * Build an `ALTER TABLE` statement. `change` is one of
 * `{ addColumn: { name, type, ... } }`,
 * `{ dropColumn: "name" }`, or
 * `{ renameColumn: { from, to } }` - each identifier quoted, the
 * add-column type drawn from the framework type map.
 *
 * @opts
 *   dialect:  string,   // postgres | sqlite | mysql (default sqlite)
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.alterTable("widget", { addColumn: { name: "active", type: "boolean" } },
 *     { dialect: "postgres" }).sql;
 *   // -> 'ALTER TABLE widget ADD COLUMN "active" BOOLEAN'
 *   //   (bare default table name; the added column is quoted)
 */
function alterTable(name, change, opts) {
  opts = opts || {};
  var dialect = _normDialect(opts.dialect);
  var ref = _normTableRef(name, opts);
  if (!change || typeof change !== "object") {
    throw _err("alterTable requires a change descriptor", "sql-builder/bad-alter");
  }
  var head = "ALTER TABLE " + ref.ref(dialect) + " ";
  if (change.addColumn) {
    var col = change.addColumn;
    if (typeof col.name !== "string") throw _err("addColumn requires a name", "sql-builder/bad-column");
    _validateColumn(col.name);
    var def = _quoteId(col.name, dialect) + " " + _ddlType(col.type, dialect);
    if (col.notNull) def += " NOT NULL";
    if (col.unique) def += " UNIQUE";
    if (col.default !== undefined) def += " DEFAULT " + _ddlDefault(col.default);
    return _assertCatalogEmittable(head + "ADD COLUMN " + def, []);
  }
  if (change.dropColumn) {
    _validateColumn(change.dropColumn);
    return _assertCatalogEmittable(head + "DROP COLUMN " + _quoteId(change.dropColumn, dialect), []);
  }
  if (change.renameColumn) {
    var rc = change.renameColumn;
    if (typeof rc.from !== "string" || typeof rc.to !== "string") {
      throw _err("renameColumn requires { from, to }", "sql-builder/bad-alter");
    }
    _validateColumn(rc.from);
    _validateColumn(rc.to);
    return _assertCatalogEmittable(
      head + "RENAME COLUMN " + _quoteId(rc.from, dialect) + " TO " + _quoteId(rc.to, dialect), []);
  }
  throw _err("alterTable change must be addColumn / dropColumn / renameColumn",
    "sql-builder/bad-alter");
}

/**
 * @primitive  b.sql.dropTable
 * @signature  b.sql.dropTable(name, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.createTable, b.sql.alterTable
 *
 * Build a `DROP TABLE` statement, identifier quoted, `IF EXISTS` by
 * default so dropping a missing table is a no-op.
 *
 * @opts
 *   dialect:   string,   // postgres | sqlite | mysql (default sqlite)
 *   ifExists:  boolean,  // default true
 *   cascade:   boolean,  // default false (Postgres CASCADE)
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.dropTable("widget", { dialect: "postgres", cascade: true }).sql;
 *   // -> 'DROP TABLE IF EXISTS widget CASCADE'
 *   //   (bare default table name; the clusterStorage rewrite target)
 */
function dropTable(name, opts) {
  opts = opts || {};
  var dialect = _normDialect(opts.dialect);
  var ref = _normTableRef(name, opts);
  var ifExists = opts.ifExists === false ? "" : "IF EXISTS ";
  var sql = "DROP TABLE " + ifExists + ref.ref(dialect);
  if (opts.cascade && dialect === "postgres") sql += " CASCADE";
  return { sql: sql, params: [] };
}

// ---- sqlite virtual table (FTS5) ------------------------------------
//
// The sqlite-only virtual-table DDL b.sql's general createTable has no
// form for - the FTS5 full-text index the mail store's sealed-token
// search runs MATCH against. The supported module is `fts5` (the only one
// a framework primitive ships against); the column list + tokenizer
// option are quoted / allowlisted by construction so no operator-supplied
// token reaches the DDL raw.

// The tokenizers an operator may name - the fixed FTS5 built-in set. A
// custom tokenizer (a loadable extension) is outside the framework's
// supported surface and refused, so no arbitrary token reaches the
// `tokenize = '...'` option.
var FTS5_TOKENIZERS = Object.freeze({
  "unicode61": true, "ascii": true, "porter": true, "trigram": true,
});
// The tokenizer ARGUMENT tokens FTS5 accepts after the tokenizer name
// (e.g. `unicode61 remove_diacritics 2`). A fixed allowlist so the whole
// `tokenize` option is builder-controlled end to end.
var FTS5_TOKENIZER_ARGS = Object.freeze({
  "remove_diacritics": true, "0": true, "1": true, "2": true,
  "categories": true, "tokenchars": true, "separators": true, "case_sensitive": true,
});

/**
 * @primitive  b.sql.createVirtualTable
 * @signature  b.sql.createVirtualTable(name, opts)
 * @since      0.15.0
 * @status     stable
 * @related    b.sql.createTable, b.sql.select, b.sql.createIndex
 *
 * Build a sqlite `CREATE VIRTUAL TABLE ... USING fts5(...)` statement for
 * a full-text index - the construct `b.sql.createTable` has no form for.
 * `opts.columns` is the FTS5 column list; each entry is a column name (a
 * searched column) or `{ name, unindexed: true }` (a stored-but-not-
 * searched column, the join key). `opts.tokenize` names a built-in FTS5
 * tokenizer (`unicode61` / `ascii` / `porter` / `trigram`) and optional
 * allowlisted arguments (`remove_diacritics 2`); a custom / loadable
 * tokenizer is refused. Every column name is quoted by construction and
 * every tokenizer token is allowlisted, so no operator-supplied token
 * reaches the DDL raw. `IF NOT EXISTS` by default. sqlite-only (FTS5 is a
 * sqlite extension); a non-sqlite dialect throws at build.
 *
 * @opts
 *   columns:      Array,    // FTS5 columns: "name" | { name, unindexed }
 *   tokenize:     string,   // "unicode61 remove_diacritics 2" (built-in + allowlisted args)
 *   ifNotExists:  boolean,  // default true
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.createVirtualTable("mail_fts", {
 *     columns:  [{ name: "objectid", unindexed: true }, "subject_toks", "body_toks"],
 *     tokenize: "unicode61 remove_diacritics 2",
 *   }).sql;
 *   // -> 'CREATE VIRTUAL TABLE IF NOT EXISTS "mail_fts" USING fts5(' +
 *   //    '"objectid" UNINDEXED, "subject_toks", "body_toks", ' +
 *   //    "tokenize = 'unicode61 remove_diacritics 2')"
 */
function createVirtualTable(name, opts) {
  opts = opts || {};
  var dialect = _normDialect(opts.dialect || "sqlite");
  if (dialect !== "sqlite") {
    throw _err("createVirtualTable (USING fts5) is sqlite-only (FTS5 is a sqlite " +
      "extension); build it with { dialect: 'sqlite' }", "sql-builder/vtable-sqlite-only");
  }
  // The table identifier is QUOTED (this DDL targets a concrete sqlite
  // handle, not a clusterStorage-rewritten bare name).
  var ref = _normTableRef(name, Object.assign({}, opts, { quoteName: true }));
  if (!Array.isArray(opts.columns) || opts.columns.length === 0) {
    throw _err("createVirtualTable requires a non-empty columns array", "sql-builder/bad-columns");
  }
  var cols = opts.columns.map(function (c) {
    var colName = typeof c === "string" ? c : (c && c.name);
    _validateColumn(colName);
    var piece = _quoteId(colName, "sqlite");
    if (c && typeof c === "object" && c.unindexed === true) piece += " UNINDEXED";
    // Reject any other per-column option token (an arbitrary string would
    // splice into the DDL); only UNINDEXED is supported.
    if (c && typeof c === "object") {
      for (var k in c) {
        if (!Object.prototype.hasOwnProperty.call(c, k)) continue;
        if (k === "name" || k === "unindexed") continue;
        throw _err("createVirtualTable column option '" + k + "' is not supported " +
          "(only { name, unindexed } )", "sql-builder/bad-vtable-column");
      }
    }
    return piece;
  });
  var tokenizeClause = "";
  if (opts.tokenize !== undefined && opts.tokenize !== null) {
    tokenizeClause = ", tokenize = '" + _ftsTokenize(opts.tokenize) + "'";
  }
  var ifNot = opts.ifNotExists === false ? "" : "IF NOT EXISTS ";
  var sql = "CREATE VIRTUAL TABLE " + ifNot + ref.ref("sqlite") + " USING fts5(" +
    cols.join(", ") + tokenizeClause + ")";
  return { sql: sql, params: [] };
}

// Validate + re-render an FTS5 tokenize spec from its allowlisted tokens.
// The first token is the tokenizer name (built-in only); the rest are
// allowlisted argument tokens. Returns the canonical space-joined string -
// every token came off the allowlist, so the emitted `'...'` literal is
// fully builder-controlled (no operator token reaches the DDL raw).
function _ftsTokenize(spec) {
  if (typeof spec !== "string" || spec.length === 0) {
    throw _err("createVirtualTable tokenize must be a non-empty string", "sql-builder/bad-tokenize");
  }
  var tokens = spec.trim().split(/\s+/);
  if (FTS5_TOKENIZERS[tokens[0]] !== true) {
    throw _err("createVirtualTable tokenizer '" + tokens[0] + "' is not a built-in FTS5 " +
      "tokenizer (unicode61 / ascii / porter / trigram); a loadable tokenizer is refused",
      "sql-builder/bad-tokenize");
  }
  for (var i = 1; i < tokens.length; i += 1) {
    if (FTS5_TOKENIZER_ARGS[tokens[i]] !== true) {
      throw _err("createVirtualTable tokenize argument '" + tokens[i] + "' is not on the " +
        "allowlist", "sql-builder/bad-tokenize");
    }
  }
  return tokens.join(" ");
}

// ---- Row-Level Security (Postgres RLS) ------------------------------
//
// Postgres-only: ENABLE ROW LEVEL SECURITY + CREATE POLICY + DROP POLICY.
// Identifiers (schema / table / policy / role) are quoted by construction
// through the framework's single identifier primitive; the USING /
// WITH CHECK boolean predicates ride the EXISTING guardSql-gated raw-
// fragment path (the same choke-point whereRaw / setRaw use), so an
// operator-influenced predicate can't smuggle a stacked statement, a
// string literal, or a dangerous primitive. SQLite + MySQL have no
// portable RLS grammar, so every RLS builder refuses a non-Postgres
// dialect at build time (config-time tier - the operator catches the
// typo at boot, not at apply).

var RLS_COMMANDS = Object.freeze({
  ALL: true, SELECT: true, INSERT: true, UPDATE: true, DELETE: true,
});

function _assertPostgresRls(dialect, what) {
  if (dialect !== "postgres") {
    throw _err(what + " is Postgres-only (SQLite / MySQL have no portable " +
      "row-level-security grammar); build it with { dialect: 'postgres' }",
      "sql-builder/rls-postgres-only");
  }
}

// A USING / WITH CHECK predicate is a boolean value expression, routed
// through the SAME raw-fragment guard whereRaw uses (b.guardSql strict +
// the embedded-literal + placeholder-count scanners). It binds no params
// by default - an RLS predicate references session GUCs / row columns, not
// per-request bound values - but accepts a params array for the rare
// parameterized predicate. Returns the checked { sql, params }.
function _rlsPredicate(label, expr, params, opts) {
  return _checkRawFragment(expr, params, opts || {}, label);
}

/**
 * @primitive  b.sql.enableRowLevelSecurity
 * @signature  b.sql.enableRowLevelSecurity(table, opts?)
 * @since      0.15.0
 * @status     stable
 * @related    b.sql.createPolicy, b.sql.dropPolicy, b.db.declareRowPolicy
 *
 * Build a Postgres `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` statement,
 * the table identifier quoted by construction (schema-qualified via
 * `{ schema }` or the dotted `"schema.table"` form). Postgres has no
 * `IF NOT EXISTS` for this verb; the declarative migration in
 * `b.db.declareRowPolicy` checks `pg_class.relrowsecurity` and skips the
 * ALTER when already enabled, so re-running a partially-applied migration
 * set does not fail. Refuses a non-Postgres dialect at build time.
 *
 * @opts
 *   schema:  string,   // schema qualifier, quoted at build time
 *   force:   boolean,  // default false - emit FORCE ROW LEVEL SECURITY
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.enableRowLevelSecurity("sessions",
 *     { schema: "public" }).sql;
 *   // -> 'ALTER TABLE "public"."sessions" ENABLE ROW LEVEL SECURITY'
 */
function enableRowLevelSecurity(name, opts) {
  opts = opts || {};
  var dialect = _normDialect(opts.dialect || "postgres");
  _assertPostgresRls(dialect, "enableRowLevelSecurity");
  // RLS targets a concrete table, so it is quoted (quoteName) rather than
  // emitted bare - there is no clusterStorage rewrite for a Postgres RLS
  // migration, which runs against the operator's external backend directly.
  var ref = _normTableRef(name, Object.assign({}, opts, { quoteName: true }));
  var sql = "ALTER TABLE " + ref.ref(dialect) + " " +
    (opts.force === true ? "FORCE" : "ENABLE") + " ROW LEVEL SECURITY";
  return { sql: sql, params: [] };
}

/**
 * @primitive  b.sql.disableRowLevelSecurity
 * @signature  b.sql.disableRowLevelSecurity(table, opts?)
 * @since      0.15.0
 * @status     stable
 * @related    b.sql.enableRowLevelSecurity, b.sql.dropPolicy
 *
 * Build a Postgres `ALTER TABLE ... DISABLE ROW LEVEL SECURITY` statement
 * (the inverse of `enableRowLevelSecurity`), the table identifier quoted
 * by construction. Refuses a non-Postgres dialect at build time.
 *
 * @opts
 *   schema:  string,   // schema qualifier, quoted at build time
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.disableRowLevelSecurity("sessions", { schema: "public" }).sql;
 *   // -> 'ALTER TABLE "public"."sessions" DISABLE ROW LEVEL SECURITY'
 */
function disableRowLevelSecurity(name, opts) {
  opts = opts || {};
  var dialect = _normDialect(opts.dialect || "postgres");
  _assertPostgresRls(dialect, "disableRowLevelSecurity");
  var ref = _normTableRef(name, Object.assign({}, opts, { quoteName: true }));
  return { sql: "ALTER TABLE " + ref.ref(dialect) + " DISABLE ROW LEVEL SECURITY", params: [] };
}

/**
 * @primitive  b.sql.createPolicy
 * @signature  b.sql.createPolicy(name, table, spec, opts?)
 * @since      0.15.0
 * @status     stable
 * @related    b.sql.enableRowLevelSecurity, b.sql.dropPolicy, b.db.declareRowPolicy
 *
 * Build a Postgres `CREATE POLICY` statement in canonical clause order:
 * `name -> table -> AS PERMISSIVE|RESTRICTIVE -> FOR <command> ->
 * TO <role> -> USING (<pred>) -> WITH CHECK (<pred>)`. The policy / table /
 * role identifiers are quoted by construction; the `using` and `withCheck`
 * boolean predicates ride the SAME `b.guardSql`-gated raw-fragment path as
 * `whereRaw` (strict profile by default, embedded-literal + placeholder-
 * count scanners), so an operator-influenced predicate cannot smuggle a
 * stacked statement or a dangerous primitive. Refuses a non-Postgres
 * dialect at build time.
 *
 * `spec.command` is one of `ALL` (default) / `SELECT` / `INSERT` /
 * `UPDATE` / `DELETE`; `spec.permissive` defaults `true` (a `PERMISSIVE`
 * policy OR-combines with peers; `false` emits `RESTRICTIVE`, which
 * AND-combines). `spec.role` is optional (omitted -> the policy applies to
 * every role). The predicates default to binding no params - an RLS
 * predicate references session GUCs / row columns - but a `usingParams` /
 * `withCheckParams` array binds values for a parameterized predicate.
 *
 * @opts
 *   schema:        string,   // schema qualifier for the table
 *   guardProfile:  string,   // raw-fragment guard profile (default "strict")
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.createPolicy("tenant_isolation", "sessions", {
 *     role:      "app_user",
 *     command:   "ALL",
 *     using:     "tenant_id = current_setting('app.tenant_id')::uuid",
 *     withCheck: "tenant_id = current_setting('app.tenant_id')::uuid",
 *   }, { schema: "public" }).sql;
 *   // -> 'CREATE POLICY "tenant_isolation" ON "public"."sessions" ' +
 *   //    'AS PERMISSIVE FOR ALL TO "app_user" ' +
 *   //    "USING (tenant_id = current_setting('app.tenant_id')::uuid) " +
 *   //    "WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid)"
 *   //   (the static current_setting literal opts in via allowLiterals)
 */
function createPolicy(name, table, spec, opts) {
  opts = opts || {};
  spec = spec || {};
  var dialect = _normDialect(opts.dialect || "postgres");
  _assertPostgresRls(dialect, "createPolicy");
  _validateColumn(name);
  var ref = _normTableRef(table, Object.assign({}, opts, { quoteName: true }));

  var command = "ALL";
  if (spec.command !== undefined && spec.command !== null) {
    if (typeof spec.command !== "string" || RLS_COMMANDS[spec.command.toUpperCase()] !== true) {
      throw _err("createPolicy command must be ALL / SELECT / INSERT / UPDATE / DELETE (got " +
        JSON.stringify(spec.command) + ")", "sql-builder/bad-rls-command");
    }
    command = spec.command.toUpperCase();
  }
  var permissive = spec.permissive !== false;

  if (spec.using === undefined || spec.using === null) {
    throw _err("createPolicy requires a 'using' boolean predicate", "sql-builder/bad-rls-predicate");
  }
  // The USING / WITH CHECK predicates are guarded raw fragments. RLS
  // predicates routinely carry a static, operator-controlled string
  // literal (current_setting('app.tenant_id')), so allowLiterals defaults
  // ON here - the literal is the policy author's, never per-request input;
  // every value-bearing operand still binds via a ? placeholder + params.
  var rawOpts = {
    guardProfile: opts.guardProfile || "strict",
    allowLiterals: spec.allowLiterals !== false,
  };
  var using = _rlsPredicate("createPolicy.using", spec.using, spec.usingParams, rawOpts);
  var withCheck = null;
  if (spec.withCheck !== undefined && spec.withCheck !== null) {
    withCheck = _rlsPredicate("createPolicy.withCheck", spec.withCheck, spec.withCheckParams, rawOpts);
  }

  var sql = "CREATE POLICY " + _quoteId(name, dialect) + " ON " + ref.ref(dialect);
  sql += " AS " + (permissive ? "PERMISSIVE" : "RESTRICTIVE");
  sql += " FOR " + command;
  if (spec.role !== undefined && spec.role !== null) {
    _validateColumn(spec.role);
    sql += " TO " + _quoteId(spec.role, dialect);
  }
  var params = [];
  sql += " USING (" + using.sql + ")";
  for (var ui = 0; ui < using.params.length; ui += 1) params.push(using.params[ui]);
  if (withCheck) {
    sql += " WITH CHECK (" + withCheck.sql + ")";
    for (var wi = 0; wi < withCheck.params.length; wi += 1) params.push(withCheck.params[wi]);
  }
  return _emit(sql, params);
}

/**
 * @primitive  b.sql.dropPolicy
 * @signature  b.sql.dropPolicy(name, table, opts?)
 * @since      0.15.0
 * @status     stable
 * @related    b.sql.createPolicy, b.sql.enableRowLevelSecurity
 *
 * Build a Postgres `DROP POLICY` statement, the policy + table identifiers
 * quoted by construction, `IF EXISTS` by default so dropping a missing
 * policy is a no-op (the migration down-path is idempotent). Refuses a
 * non-Postgres dialect at build time.
 *
 * @opts
 *   schema:    string,   // schema qualifier for the table
 *   ifExists:  boolean,  // default true
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.dropPolicy("tenant_isolation", "sessions", { schema: "public" }).sql;
 *   // -> 'DROP POLICY IF EXISTS "tenant_isolation" ON "public"."sessions"'
 */
function dropPolicy(name, table, opts) {
  opts = opts || {};
  var dialect = _normDialect(opts.dialect || "postgres");
  _assertPostgresRls(dialect, "dropPolicy");
  _validateColumn(name);
  var ref = _normTableRef(table, Object.assign({}, opts, { quoteName: true }));
  var ifExists = opts.ifExists === false ? "" : "IF EXISTS ";
  return { sql: "DROP POLICY " + ifExists + _quoteId(name, dialect) + " ON " + ref.ref(dialect), params: [] };
}

// ---- Catalog / PRAGMA (narrow audited sqlite-internal sub-API) ------
//
// b.safeSql.quoteIdentifier refuses an `sqlite_`-prefixed identifier BY
// DESIGN (sql/internal-prefix) and _assertEmittable refuses a multi-verb
// statement - both stay intact for every general caller. The vault key-
// rotation pipeline (lib/vault/rotate.js) legitimately needs to read the
// sqlite catalog (sqlite_master), introspect a table (PRAGMA table_info),
// set journal mode + synchronous, checkpoint the WAL, and sample rows in
// random order. None of those compose through the general builder. This
// narrow sub-API allowlists EXACTLY those statements + verbs and nothing
// else: every other sqlite_-prefixed identifier and every other PRAGMA
// verb still refuses through the general quoteIdentifier / builder gate.
//
// Every emitter here returns the SAME { sql, params } shape the verbs do,
// validated through a CATALOG-scoped output gate (_assertCatalogEmittable)
// that allows the sqlite_master / PRAGMA / RANDOM() forms the general
// _assertEmittable refuses while keeping NUL / surrogate / stacked-
// statement / unterminated-quote refusals fully intact.

// The exact PRAGMA verbs this sub-API will emit. A verb not on this list
// throws - the allowlist is the audit boundary, not a suggestion.
var CATALOG_PRAGMA_VERBS = Object.freeze({
  "table_info":      { kind: "introspect" },   // PRAGMA table_info("<table>")
  "journal_mode":    { kind: "set-or-read" },  // PRAGMA journal_mode=WAL | PRAGMA journal_mode
  "synchronous":     { kind: "set-or-read" },  // PRAGMA synchronous=NORMAL
  "wal_checkpoint":  { kind: "checkpoint" },   // PRAGMA wal_checkpoint(TRUNCATE)
});
// Allowlisted argument tokens per set-or-read / checkpoint PRAGMA - a
// fixed, operator-uninfluenced vocabulary so no arbitrary token reaches
// the PRAGMA argument position.
var PRAGMA_JOURNAL_MODES = Object.freeze({
  DELETE: true, TRUNCATE: true, PERSIST: true, MEMORY: true, WAL: true, OFF: true,
});
var PRAGMA_SYNC_LEVELS = Object.freeze({ OFF: true, NORMAL: true, FULL: true, EXTRA: true });
var PRAGMA_CHECKPOINT_MODES = Object.freeze({ PASSIVE: true, FULL: true, RESTART: true, TRUNCATE: true });

// Quote an sqlite identifier WITH allowReserved (an internal table walk
// can encounter any name). The sqlite_-prefix rule stays in force for the
// general quoteIdentifier path; catalog identifiers that are themselves a
// real user table go through the normal allowReserved quote (a user table
// is never sqlite_-prefixed). The ONLY sqlite_-prefixed token this sub-API
// emits is the fixed `sqlite_master` / `sqlite_schema` literal below -
// never an operator-supplied name.
function _catalogQuoteTable(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw _err("catalog: table name must be a non-empty string", "sql-builder/bad-table");
  }
  // A catalog walk reads a name OUT of sqlite_master, so the live table
  // name is already a validated existing identifier; still route it through
  // the framework quote primitive (shape / length / NUL rules) with
  // allowReserved on. An sqlite_-prefixed user table cannot exist (sqlite
  // reserves the prefix), so the general internal-prefix refusal correctly
  // rejects it if one is ever passed - the catalog sub-API never relaxes
  // that for an operator-supplied name.
  return safeSql.quoteIdentifier(name, "sqlite", { allowReserved: true });
}

// Output gate for the catalog sub-API. Keeps every boundary-escape
// refusal _assertEmittable has (NUL, lone surrogate, stacked top-level ';',
// unterminated quote, param/placeholder parity) but does NOT run the
// single-verb / identifier-shape assumptions the general gate makes about
// the builder verbs - a PRAGMA / catalog statement is its own shape.
function _assertCatalogEmittable(sql, params) {
  if (typeof sql !== "string" || sql.length === 0) {
    throw _err("catalog: emitted SQL must be a non-empty string (builder bug)",
      "sql-builder/empty-sql");
  }
  if (!Array.isArray(params)) {
    throw _err("catalog: params must be an array (builder bug)", "sql-builder/bad-params-shape");
  }
  if (sql.indexOf("\u0000") !== -1) {
    throw _err("catalog: emitted SQL contains a NUL byte - rejected",
      "sql-builder/null-byte-sql");
  }
  if (typeof sql.isWellFormed === "function" && !sql.isWellFormed()) {
    throw _err("catalog: emitted SQL contains invalid Unicode (lone surrogates) - rejected",
      "sql-builder/invalid-encoding-sql");
  }
  var holders = _countPlaceholders(sql);
  if (holders !== params.length) {
    throw _err("catalog: placeholder/param count mismatch - " + holders + " '?' but " +
      params.length + " param(s)", "sql-builder/param-mismatch");
  }
  // Quote/comment-aware single-statement + balanced-paren scan, identical
  // to _assertEmittable's tail. A stacked top-level ';' / unterminated
  // quote is refused here too.
  safeSql.assertSingleStatement(sql, {
    label: "catalog",
    makeError: function (m, suffix) { return _err(m, "sql-builder/" + suffix); },
  });
  return { sql: sql, params: params };
}

// The audited catalog/PRAGMA sub-API. Every method returns { sql, params }.
var catalog = Object.freeze({
  /**
   * @primitive  b.sql.catalog.listTables
   * @signature  b.sql.catalog.listTables()
   * @since      0.15.0
   * @status     stable
   * @related    b.sql.catalog.tableInfo, b.sql.catalog.tableExists
   *
   * Build the sqlite catalog query that lists every user table -
   * `SELECT name FROM sqlite_master WHERE type='table' AND
   * name NOT LIKE 'sqlite_%'`. This is the ONLY general path that emits an
   * `sqlite_master` reference; the framework's `b.safeSql.quoteIdentifier`
   * refuses an `sqlite_`-prefixed identifier for every other caller, so a
   * `sqlite_master` scan cannot be hand-built through the normal builder.
   * The `sqlite_%` LIKE pattern is a builder-emitted static literal (not
   * operator input). sqlite-internal; no dialect option.
   *
   * @example
   *   var b = require("@blamejs/core");
   *   var q = b.sql.catalog.listTables();
   *   // -> { sql: "SELECT name FROM sqlite_master WHERE type = 'table' " +
   *   //          "AND name NOT LIKE 'sqlite_%'", params: [] }
   */
  listTables: function () {
    var sql = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'";
    return _assertCatalogEmittable(sql, []);
  },

  /**
   * @primitive  b.sql.catalog.tableExists
   * @signature  b.sql.catalog.tableExists(name)
   * @since      0.15.0
   * @status     stable
   * @related    b.sql.catalog.listTables, b.sql.catalog.tableInfo
   *
   * Build the sqlite catalog existence probe for one table -
   * `SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, the
   * table name BOUND as a `?` parameter (never interpolated). Returns one
   * row when the table exists, none otherwise.
   *
   * @example
   *   var b = require("@blamejs/core");
   *   b.sql.catalog.tableExists("audit_log");
   *   // -> { sql: "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
   *   //     params: ["audit_log"] }
   */
  tableExists: function (name) {
    if (typeof name !== "string" || name.length === 0) {
      throw _err("catalog.tableExists: name must be a non-empty string", "sql-builder/bad-table");
    }
    var sql = "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?";
    return _assertCatalogEmittable(sql, [name]);
  },

  /**
   * @primitive  b.sql.catalog.tableInfo
   * @signature  b.sql.catalog.tableInfo(name)
   * @since      0.15.0
   * @status     stable
   * @related    b.sql.catalog.listTables, b.sql.pragma
   *
   * Build a `PRAGMA table_info("<table>")` statement, the table name
   * quoted by construction through `b.safeSql`. PRAGMA does not bind a
   * parameter in its argument position, so the name is quoted (shape /
   * length / NUL-validated), never string-interpolated raw. sqlite-only.
   *
   * @example
   *   var b = require("@blamejs/core");
   *   b.sql.catalog.tableInfo("audit_log").sql;
   *   // -> 'PRAGMA table_info("audit_log")'
   */
  tableInfo: function (name) {
    var sql = "PRAGMA table_info(" + _catalogQuoteTable(name) + ")";
    return _assertCatalogEmittable(sql, []);
  },

  /**
   * @primitive  b.sql.catalog.sampleRandom
   * @signature  b.sql.catalog.sampleRandom(table, columns?, opts?)
   * @since      0.15.0
   * @status     stable
   * @related    b.sql.select, b.sql.catalog.tableInfo
   *
   * Build a `SELECT <cols> FROM "<table>" ORDER BY RANDOM() LIMIT ?`
   * row-sampler, identifiers quoted by construction and the limit BOUND as
   * a `?` parameter. `RANDOM()` ordering is the audited sqlite sampler form
   * the general `b.sql.select` builder has no clause for (it is used to
   * pick representative rows for verification, not cryptographic
   * randomness). `columns` defaults to `*`. sqlite-only.
   *
   * @opts
   *   limit:  number,   // bound LIMIT (required > 0)
   *
   * @example
   *   var b = require("@blamejs/core");
   *   b.sql.catalog.sampleRandom("sessions", ["_id", "email"], { limit: 50 });
   *   // -> { sql: 'SELECT "_id", "email" FROM "sessions" ORDER BY RANDOM() LIMIT ?',
   *   //     params: [50] }
   */
  /**
   * @primitive  b.sql.catalog.changes
   * @signature  b.sql.catalog.changes()
   * @since      0.15.0
   * @status     stable
   * @related    b.sql.catalog.listTables, b.sql.delete
   *
   * Build `SELECT changes() AS c` - the sqlite scalar that reports the row
   * count of the most recent INSERT / UPDATE / DELETE on the current
   * connection. `changes()` is a sqlite-internal function with no table to
   * select from, so the general builder (which requires a FROM table) has
   * no form for it; this audited builder emits the exact zero-parameter
   * probe the inbox sweep uses to learn how many rows a preceding DELETE
   * removed. sqlite-only; the column alias is `c`.
   *
   * @example
   *   var b = require("@blamejs/core");
   *   b.sql.catalog.changes().sql;   // -> "SELECT changes() AS c"
   */
  changes: function () {
    return _assertCatalogEmittable("SELECT changes() AS c", []);
  },

  sampleRandom: function (table, columns, opts) {
    opts = opts || {};
    var qt = _catalogQuoteTable(table);
    var proj = "*";
    if (columns !== undefined && columns !== null) {
      if (!Array.isArray(columns) || columns.length === 0) {
        throw _err("catalog.sampleRandom: columns must be a non-empty array (or omit for *)",
          "sql-builder/bad-columns");
      }
      proj = columns.map(function (c) {
        _validateColumn(c);
        return _quoteId(c, "sqlite");
      }).join(", ");
    }
    var limit = opts.limit;
    if (!Number.isInteger(limit) || limit <= 0) {
      throw _err("catalog.sampleRandom: opts.limit must be a positive integer", "sql-builder/bad-limit");
    }
    var sql = "SELECT " + proj + " FROM " + qt + " ORDER BY RANDOM() LIMIT ?";
    return _assertCatalogEmittable(sql, [limit]);
  },
});

/**
 * @primitive  b.sql.pragma
 * @signature  b.sql.pragma(verb, arg?)
 * @since      0.15.0
 * @status     stable
 * @related    b.sql.catalog.tableInfo, b.sql.catalog.listTables
 *
 * Build a sqlite `PRAGMA` statement from a NARROW allowlist of verbs:
 * `journal_mode` (set `PRAGMA journal_mode=WAL` or read `PRAGMA
 * journal_mode`), `synchronous` (`PRAGMA synchronous=NORMAL`), and
 * `wal_checkpoint` (`PRAGMA wal_checkpoint(TRUNCATE)`). The argument is
 * matched against a fixed per-verb vocabulary - a journal mode / sync
 * level / checkpoint mode - so no operator-influenced token reaches the
 * PRAGMA argument position. A verb not on the allowlist throws; this is
 * the audit boundary the at-rest key-rotation pipeline routes its PRAGMA
 * statements through. Pass no `arg` to a set-or-read verb to read the
 * current value. sqlite-only.
 *
 * @opts
 *   (none - the second positional is the allowlisted argument token)
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.pragma("journal_mode", "WAL").sql;      // -> 'PRAGMA journal_mode=WAL'
 *   b.sql.pragma("synchronous", "NORMAL").sql;    // -> 'PRAGMA synchronous=NORMAL'
 *   b.sql.pragma("wal_checkpoint", "TRUNCATE").sql; // -> 'PRAGMA wal_checkpoint(TRUNCATE)'
 *   b.sql.pragma("journal_mode").sql;             // -> 'PRAGMA journal_mode'  (read)
 */
function pragma(verb, arg) {
  if (typeof verb !== "string" || !Object.prototype.hasOwnProperty.call(CATALOG_PRAGMA_VERBS, verb)) {
    throw _err("pragma: verb '" + verb + "' is not on the allowlist (journal_mode / " +
      "synchronous / wal_checkpoint); a PRAGMA outside this set is refused by design",
      "sql-builder/bad-pragma");
  }
  var def = CATALOG_PRAGMA_VERBS[verb];
  if (def.kind === "introspect") {
    // table_info is reached via catalog.tableInfo (needs a quoted name).
    throw _err("pragma: use b.sql.catalog.tableInfo(name) for PRAGMA table_info",
      "sql-builder/bad-pragma");
  }
  if (def.kind === "checkpoint") {
    var ckMode = (arg === undefined || arg === null) ? "PASSIVE" : String(arg).toUpperCase();
    if (PRAGMA_CHECKPOINT_MODES[ckMode] !== true) {
      throw _err("pragma wal_checkpoint mode must be PASSIVE / FULL / RESTART / TRUNCATE (got " +
        JSON.stringify(arg) + ")", "sql-builder/bad-pragma-arg");
    }
    return _assertCatalogEmittable("PRAGMA wal_checkpoint(" + ckMode + ")", []);
  }
  // set-or-read: journal_mode / synchronous.
  if (arg === undefined || arg === null) {
    return _assertCatalogEmittable("PRAGMA " + verb, []);
  }
  var token = String(arg).toUpperCase();
  var vocab = verb === "journal_mode" ? PRAGMA_JOURNAL_MODES : PRAGMA_SYNC_LEVELS;
  if (vocab[token] !== true) {
    throw _err("pragma " + verb + " argument '" + arg + "' is not in the allowed vocabulary",
      "sql-builder/bad-pragma-arg");
  }
  return _assertCatalogEmittable("PRAGMA " + verb + "=" + token, []);
}

// ---- Schema optimization (defineTable) ------------------------------
//
// PK / FK / index automation over createTable + createIndex. Each layer is
// on by default and individually disablable.

// Naive pluralizer for FK table inference (entity -> table). Covers the
// common English cases; an unusual plural is overridden with an explicit
// `references`. consonant+y -> ies, sibilant -> es, else -> s.
function _pluralize(s) {
  if (/[^aeiou]y$/i.test(s)) return s.slice(0, -1) + "ies";
  if (/(?:s|x|z|ch|sh)$/i.test(s)) return s + "es";
  return s + "s";
}

// Infer a foreign-key reference from a column name by convention: a column
// named `<entity>Id` / `<entity>_id` references `<pluralize(entity)>(<pkCol>)`.
// Returns null when the name does not match (or the entity part is empty,
// e.g. a bare `id` / `_id`).
function _inferFkRef(colName, pkCol) {
  var m = /^(.+?)(?:Id|_id)$/.exec(colName);
  if (!m || m[1].length === 0) return null;
  return { table: _pluralize(m[1]), column: pkCol };
}

// Deterministic index name `idx_<table>_<cols>`, sanitized to an identifier
// and capped at the dialect identifier limit (Postgres NAMEDATALEN 63) the
// same way the query builder bounds every identifier. An over-long name is
// truncated with a short stable checksum suffix so two long names can't
// collide after truncation.
function _indexName(table, cols) {
  var base = ("idx_" + table + "_" + cols.join("_")).replace(/[^A-Za-z0-9_]/g, "_");
  if (base.length > safeSql.MAX_IDENTIFIER_LENGTH) {
    var h = 0;
    for (var i = 0; i < base.length; i += 1) h = (h * 31 + base.charCodeAt(i)) >>> 0;
    base = base.slice(0, safeSql.MAX_IDENTIFIER_LENGTH - 9) + "_" + h.toString(36);
  }
  return base;
}

/**
 * @primitive  b.sql.defineTable
 * @signature  b.sql.defineTable(name, spec, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.createTable, b.sql.createIndex, b.sql.select
 *
 * Declarative schema with built-in PK / FK / index optimization. Returns an
 * ordered `{ statements: [{ sql, params }, ...] }` bundle (the `CREATE TABLE`
 * first, then each `CREATE INDEX`) to run in sequence. Three automation
 * layers, each on by default and individually disablable:
 *
 * - **Primary key** - if no column declares `primaryKey` / `autoIncrement`
 *   and `opts.primaryKey` is unset, an identity PK column (`opts.primaryKeyColumn`,
 *   default `id`) is auto-added in the dialect-correct form (BIGSERIAL /
 *   INTEGER AUTOINCREMENT / BIGINT AUTO_INCREMENT). Disable: `autoPrimaryKey: false`.
 * - **Foreign keys** - a column named `<entity>Id` / `<entity>_id` infers a
 *   `REFERENCES <pluralize(entity)>(<pk>)` constraint. Override one column with
 *   an explicit `references` (`"table"` or `{ table, column?, onDelete?,
 *   onUpdate? }`) or opt it out with `references: false`. Disable all
 *   inference: `autoForeignKeys: false`.
 * - **Indexes** - every FK column is auto-indexed (databases do not index
 *   FK columns for you), as is any column flagged `index: true`
 *   (`unique: true` is enforced inline). Add composite / custom indexes via
 *   `opts.indexes`. Disable auto-indexing: `autoIndex: false`.
 *
 * Every index / FK column is gated against the table's declared column set -
 * the same column-namespace discipline the query builder applies with
 * `allowedColumns` - and every generated index name is bounded to the dialect
 * identifier limit.
 *
 * @opts
 *   dialect:           string,   // postgres | sqlite | mysql (default sqlite)
 *   prefix:            string,   // operator app-table namespace prefix
 *   schema:            string,   // schema qualifier
 *   autoPrimaryKey:    boolean,  // default true
 *   primaryKeyColumn:  string,   // default "id"
 *   autoForeignKeys:   boolean,  // default true (naming-convention inference)
 *   autoIndex:         boolean,  // default true
 *   indexes:           array,    // [{ columns: [...], unique?, name? }]
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var ddl = b.sql.defineTable("orders", [
 *     { name: "userId", type: "int" },         // -> FK users(id) + index
 *     { name: "total",  type: "numeric" },
 *     { name: "email",  type: "text", index: true },
 *   ], { dialect: "postgres" });
 *   ddl.statements.length;
 *   // -> 3  (CREATE TABLE orders; CREATE INDEX on userId; CREATE INDEX on email)
 */
function defineTable(name, spec, opts) {
  opts = opts || {};
  var dialect = _normDialect(opts.dialect);
  if (!Array.isArray(spec) || spec.length === 0) {
    throw _err("defineTable requires a non-empty columns spec array", "sql-builder/bad-columns");
  }
  var autoPk  = opts.autoPrimaryKey  !== false;
  var autoFk  = opts.autoForeignKeys !== false;
  var autoIdx = opts.autoIndex       !== false;
  var pkCol   = opts.primaryKeyColumn || "id";

  // Shallow-copy each spec so FK inference never mutates the caller's object.
  var cols = spec.map(function (c) {
    if (!c || typeof c !== "object" || typeof c.name !== "string") {
      throw _err("defineTable column must be { name, type, ... }", "sql-builder/bad-column");
    }
    return Object.assign({}, c);
  });

  // PK automation.
  var declaredPk = cols.some(function (c) { return c.primaryKey || c.autoIncrement; }) ||
    (Array.isArray(opts.primaryKey) && opts.primaryKey.length > 0);
  if (autoPk && !declaredPk) cols.unshift({ name: pkCol, autoIncrement: true });

  // Column namespace - index / FK columns must be members, the same gate the
  // query builder enforces with allowedColumns / _assertColumnMember.
  var declared = {};
  cols.forEach(function (c) { declared[c.name] = true; });
  function _assertMember(col, where) {
    if (declared[col] !== true) {
      throw _err("defineTable: " + where + " references column '" + col +
        "' which is not a declared column of '" + name + "'", "sql-builder/unknown-column");
    }
  }

  // FK automation (convention-by-default + per-column override).
  var fkColumns = [];
  cols.forEach(function (c) {
    if (c.references === false) return;                              // opt-out
    if (c.references !== undefined) { fkColumns.push(c.name); return; }  // explicit
    if (c.primaryKey || c.autoIncrement) return;                    // PK is not an FK
    if (autoFk) {
      var inferred = _inferFkRef(c.name, pkCol);
      if (inferred) { c.references = inferred; fkColumns.push(c.name); }
    }
  });

  var statements = [createTable(name, cols, opts)];

  // Index automation. Generated index names are bounded by _indexName.
  var indexed = {};
  function _pushIndex(indexCols, unique, explicitName) {
    indexCols.forEach(function (col) { _assertMember(col, "index"); });
    statements.push(createIndex(explicitName || _indexName(name, indexCols), name, indexCols,
      { dialect: dialect, unique: unique === true, prefix: opts.prefix, schema: opts.schema }));
  }
  if (autoIdx) {
    fkColumns.forEach(function (cn) {
      if (!indexed[cn]) { indexed[cn] = true; _pushIndex([cn], false, null); }
    });
    cols.forEach(function (c) {
      if (c.index === true && !c.unique && !c.primaryKey && !c.autoIncrement && !indexed[c.name]) {
        indexed[c.name] = true; _pushIndex([c.name], false, null);
      }
    });
  }
  // Explicit indexes are always honored (even with autoIndex off).
  if (Array.isArray(opts.indexes)) {
    opts.indexes.forEach(function (ix) {
      if (!ix || !Array.isArray(ix.columns) || ix.columns.length === 0) {
        throw _err("defineTable opts.indexes entry needs a non-empty columns array",
          "sql-builder/bad-index");
      }
      _pushIndex(ix.columns, ix.unique, ix.name);
    });
  }

  return { statements: statements };
}

// ---- Verb entry points ----------------------------------------------

/**
 * @primitive  b.sql.select
 * @signature  b.sql.select(table, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.insert, b.sql.update, b.sql.delete, b.sql.upsert
 *
 * Start a `SELECT` builder over `table` (a name, a `"schema.table"`, or a
 * `b.sql.table(...)` reference). Chain `columns` / aggregates /
 * `join` family / `where` family / `groupBy` / `having` / `orderBy` /
 * `limit` / `offset`, then call `toSql()` for `{ sql, params }`. Emits
 * bare default table names + `?` placeholders so `b.clusterStorage`
 * applies the cluster prefix + Postgres `$N` translation at execute time.
 *
 * @opts
 *   dialect:         string,   // postgres | sqlite | mysql (default sqlite)
 *   schema:          string,   // schema qualifier for the table
 *   prefix:          string,   // operator app-table namespace prefix
 *   alias:           string,   // table alias (for joins)
 *   allowedColumns:  array,    // column-membership gate set
 *   columnGateMode:  string,   // reject | warn | off
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.select("users")
 *     .columns(["id", "email"])
 *     .where("status", "active")
 *     .orderBy("createdAt", "desc")
 *     .limit(10)
 *     .toSql();
 *   // -> { sql: 'SELECT "id", "email" FROM users WHERE "status" = ? ORDER BY "createdAt" DESC LIMIT 10',
 *   //     params: ["active"] }
 */
function select(tableNameOrRef, opts) { return new SelectBuilder(tableNameOrRef, opts); }

/**
 * @primitive  b.sql.insert
 * @signature  b.sql.insert(table, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.select, b.sql.upsert, b.sql.update
 *
 * Start an `INSERT` builder. Provide rows via `columns([...])` +
 * `values([...])` (positional), `values({ ... })` (one row object), or
 * `values([{...}, {...}])` (multi-row). Optional `returning(cols)`. The
 * value set is fully bound - every value becomes a `?` placeholder.
 *
 * @opts
 *   dialect:         string,   // postgres | sqlite | mysql (default sqlite)
 *   schema:          string,   // schema qualifier
 *   prefix:          string,   // operator app-table namespace prefix
 *   allowedColumns:  array,    // column-membership gate set
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.insert("users")
 *     .values({ id: 1, email: "a@b.c" })
 *     .returning(["id"])
 *     .toSql();
 *   // -> { sql: 'INSERT INTO users ("id", "email") VALUES (?, ?) RETURNING "id"',
 *   //     params: [1, "a@b.c"] }
 */
function insert(tableNameOrRef, opts) { return new InsertBuilder(tableNameOrRef, opts); }

/**
 * @primitive  b.sql.insertSelectWhere
 * @signature  b.sql.insertSelectWhere(table, opts?)
 * @since      0.15.13
 * @status     stable
 * @related    b.sql.insert, b.sql.upsert, b.sql.update
 *
 * Start a conditional `INSERT ... SELECT ... WHERE` builder - a row written
 * ONLY when a guard derived from the table itself holds. Emits
 * `INSERT INTO t (cols) SELECT <cells> WHERE <guard>`: the value-less SELECT
 * is a single computed candidate row the WHERE either admits (one row
 * inserted) or rejects (zero rows). It is the race-free append-only-ledger
 * debit - a store-credit / gift-card / wallet / points / metered-quota /
 * seat-counter balance that lives only on the latest row, with no mutable
 * counter row to `increment()`. The guard's correlated subquery / `EXISTS`
 * is evaluated atomically inside the INSERT, so two concurrent debits cannot
 * both pass the same balance check.
 *
 * Supply the row via `columns([...])` + `values([...])` (positional),
 * `values({ ... })` (one row object, inferring the column list from its
 * keys), then the guard via the full `where` family (`whereExists` /
 * `whereSub` / `whereOp` / `whereGroup` / `whereRaw` all compose - the
 * balance fence is typically an `EXISTS` against the same table). Each SELECT
 * cell routes through the same choke-point INSERT `values()` uses, so a cell
 * may be a bound `?`, a `b.sql.cast(...)` (`?::type`), or a `b.sql.fn(...)`
 * allowlisted server function (`NOW()`, no param). Standard SQL across sqlite
 * / Postgres / MySQL; only `RETURNING` diverges (Postgres / SQLite - refused
 * on MySQL, run an explicit read).
 *
 * Safety default: an INSERT...SELECT with no WHERE is just an
 * INSERT...VALUES, so the verb THROWS without a `where()` unless
 * `allowNoWhere()` opts in - the same discipline `update` / `delete` apply.
 *
 * @opts
 *   dialect:         string,   // postgres | sqlite | mysql (default sqlite)
 *   schema:          string,   // schema qualifier
 *   prefix:          string,   // operator app-table namespace prefix
 *   allowedColumns:  array,    // column-membership gate set
 *
 * @example
 *   // Append a -25 debit ONLY if the wallet's balance row still covers it -
 *   // a race-free conditional insert with no read-modify-write. The guard is
 *   // an EXISTS over a same-dialect sub-builder (no raw statement verb).
 *   var covered = b.sql.select("wallet", { dialect: "postgres" })
 *     .selectRaw("1")
 *     .whereRaw('"id" = ? AND "balance" >= ?', ["w-1", 25]);
 *   b.sql.insertSelectWhere("wallet_ledger", { dialect: "postgres" })
 *     .values({ wallet_id: "w-1", amount: -25, at: b.sql.fn("NOW") })
 *     .whereExists(covered)
 *     .returning(["id"])
 *     .toSql();
 *   // -> { sql: 'INSERT INTO wallet_ledger ("wallet_id", "amount", "at") ' +
 *   //          'SELECT ?, ?, NOW() WHERE EXISTS (SELECT 1 FROM wallet ' +
 *   //          'WHERE ("id" = ? AND "balance" >= ?)) RETURNING "id"',
 *   //     params: ["w-1", -25, "w-1", 25] }
 */
function insertSelectWhere(tableNameOrRef, opts) { return new InsertSelectWhereBuilder(tableNameOrRef, opts); }

/**
 * @primitive  b.sql.update
 * @signature  b.sql.update(table, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.select, b.sql.insert, b.sql.delete
 *
 * Start an `UPDATE` builder. Set assignments via `set({ ... })` /
 * `set(col, val)` / `setRaw(col, expr, params)`; filter via the `where`
 * family. An update with no `where()` THROWS unless `allowNoWhere()` is
 * called - a deliberate full-table write must opt in. Optional
 * `returning(cols)`.
 *
 * @opts
 *   dialect:         string,   // postgres | sqlite | mysql (default sqlite)
 *   schema:          string,   // schema qualifier
 *   prefix:          string,   // operator app-table namespace prefix
 *   allowedColumns:  array,    // column-membership gate set
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.update("users")
 *     .set({ status: "inactive" })
 *     .where("id", 1)
 *     .toSql();
 *   // -> { sql: 'UPDATE users SET "status" = ? WHERE "id" = ?', params: ["inactive", 1] }
 */
function update(tableNameOrRef, opts) { return new UpdateBuilder(tableNameOrRef, opts); }

/**
 * @primitive  b.sql.guardedUpdate
 * @signature  b.sql.guardedUpdate(table, opts?)
 * @since      0.15.21
 * @status     stable
 * @related    b.sql.update, b.sql.insertSelectWhere, b.sql.casWon
 *
 * Start a compare-and-swap `UPDATE` builder - the cross-instance-safe way to
 * advance a status / version on a single-statement-per-request backend (D1
 * over an HTTP bridge, or any autocommit-only adapter without interactive
 * transactions). It is `b.sql.update` plus a required `guardWhere(col,
 * expected)` fence: the statement lands ONLY when the row is STILL in the
 * expected value, so two racing transitions cannot both win. Refuses to
 * render without at least one `guardWhere(...)` / `guardWhereOp(...)` - an
 * unfenced one would just be a plain update.
 *
 * Read the winner from the result's `rowCount` with `b.sql.casWon(result)`:
 * exactly one row matched (`won: true`) means this caller made the
 * transition; zero (`won: false`) means it lost the race and must no-op /
 * refuse. The sibling of `b.sql.insertSelectWhere` (the conditional-INSERT
 * debit) for the conditional-UPDATE case, and the b.fsm composition partner
 * (resolve the destination side-effect-free with `instance.target(event)`,
 * then guard on the from-state here).
 *
 * @opts
 *   dialect:         string,   // postgres | sqlite | mysql (default sqlite)
 *   schema:          string,   // schema qualifier
 *   prefix:          string,   // operator app-table namespace prefix
 *   allowedColumns:  array,    // column-membership gate set
 *
 * @example
 *   var b = require("@blamejs/core");
 *   // advance order id=7 from "paid" -> "shipped" iff still "paid"
 *   var q = b.sql.guardedUpdate("orders")
 *     .set({ status: "shipped" })
 *     .where("id", 7)
 *     .guardWhere("status", "paid")
 *     .toSql();
 *   // -> { sql: 'UPDATE orders SET "status" = ? WHERE "id" = ? AND "status" = ?',
 *   //      params: ["shipped", 7, "paid"] }
 *   // var res = await b.db.raw(q.sql, q.params);
 *   // if (!b.sql.casWon(res).won) { return refuse(); }   // lost the race
 */
function guardedUpdate(tableNameOrRef, opts) {
  var builder = new UpdateBuilder(tableNameOrRef, opts);
  builder._requireGuard = true;
  return builder;
}

/**
 * @primitive  b.sql.casWon
 * @signature  b.sql.casWon(result)
 * @since      0.15.21
 * @status     stable
 * @related    b.sql.guardedUpdate, b.sql.insertSelectWhere
 *
 * Interpret a compare-and-swap result's affected-row count into a won/lost
 * verdict, owning the `Number(rowCount) === 1` check and the cross-adapter
 * field-name divergence (`b.db` / `b.externalDb` normalize to `rowCount`; raw
 * sqlite reports `changes`, raw mysql `affectedRows` / `rowsAffected`).
 * Returns `{ won, rowCount }` where `won` is true only when exactly one row
 * was affected. Throws when the result carries no recognizable numeric
 * row-count field - an indeterminate result must surface, never be silently
 * read as a win (a phantom win on a CAS is a double-spend).
 *
 * @example
 *   var v = b.sql.casWon(await b.db.raw(q.sql, q.params));
 *   if (v.won) { applyTransition(); } else { refuseLostRace(v.rowCount); }
 */
function casWon(result) {
  if (!result || typeof result !== "object") {
    throw _err("casWon: result must be the object returned by the query runner",
      "sql-builder/bad-cas-result");
  }
  var count = null;
  var fields = ["rowCount", "changes", "affectedRows", "rowsAffected"];
  for (var i = 0; i < fields.length; i += 1) {
    var v = result[fields[i]];
    if (typeof v === "number" && isFinite(v)) { count = v; break; }
  }
  if (count === null) {
    throw _err("casWon: result has no numeric rowCount / changes / affectedRows field - " +
      "cannot determine the compare-and-swap outcome", "sql-builder/no-row-count");
  }
  return { won: count === 1, rowCount: count };
}

/**
 * @primitive  b.sql.delete
 * @signature  b.sql.delete(table, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.select, b.sql.update, b.sql.insert
 *
 * Start a `DELETE` builder. Filter via the `where` family. A delete with
 * no `where()` THROWS unless `allowNoWhere()` is called. Optional
 * `returning(cols)`.
 *
 * @opts
 *   dialect:         string,   // postgres | sqlite | mysql (default sqlite)
 *   schema:          string,   // schema qualifier
 *   prefix:          string,   // operator app-table namespace prefix
 *   allowedColumns:  array,    // column-membership gate set
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.delete("sessions")
 *     .where("expiresAt", "<", 1700000000)
 *     .toSql();
 *   // -> { sql: 'DELETE FROM sessions WHERE "expiresAt" < ?', params: [1700000000] }
 */
function del(tableNameOrRef, opts) { return new DeleteBuilder(tableNameOrRef, opts); }

/**
 * @primitive  b.sql.upsert
 * @signature  b.sql.upsert(table, opts?)
 * @since      0.14.29
 * @status     stable
 * @related    b.sql.insert, b.sql.update, b.sql.select
 *
 * Start an `UPSERT` builder - the one verb that emits dialect-final
 * conflict syntax. Supply the row via `columns` + `values({...})`, the
 * conflict key via `onConflict(keys)`, and one conflict action:
 * `doUpdate(cols | { col: expr })`, `doUpdateFromExcluded(cols)`, or
 * `doNothing()`. Optional `conflictWhere(rawGuard, params, opts?)` fences
 * the update - pass `{ guardColumn: "<col>" }` to name the column the
 * fence protects so the MySQL fold emits it last (see below); optional
 * `returning(cols)`.
 *
 * On Postgres / SQLite `toSql()` returns
 * `{ sql, params }` emitting `ON CONFLICT (keys) DO UPDATE SET
 * col = EXCLUDED.col [WHERE ...] [RETURNING ...]`. On MySQL it returns
 * `{ sql, params, readbackSql }` emitting `ON DUPLICATE KEY UPDATE
 * col = VALUES(col)` (or `IF(guard, VALUES(col), col)` when
 * `conflictWhere` is set); MySQL evaluates the SET list left to right, so
 * when the fenced guard column is itself a SET target it must be assigned
 * last (each IF must see the guard column's pre-update value) - name it
 * via `conflictWhere(..., { guardColumn })` and the fold reorders it to
 * the end. MySQL has no per-statement WHERE / RETURNING on the conflict
 * action, so a readback `SELECT` keyed on the conflict columns is
 * returned for the caller to fetch the upserted row.
 *
 * @opts
 *   dialect:         string,   // postgres | sqlite | mysql (default sqlite)
 *   schema:          string,   // schema qualifier
 *   prefix:          string,   // operator app-table namespace prefix
 *   allowedColumns:  array,    // column-membership gate set
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.sql.upsert("audit_tip", { dialect: "postgres" })
 *     .values({ id: 1, counter: 42 })
 *     .onConflict(["id"])
 *     .doUpdateFromExcluded(["counter"])
 *     .toSql();
 *   // -> { sql: 'INSERT INTO audit_tip ("id", "counter") VALUES (?, ?) ' +
 *   //          'ON CONFLICT ("id") DO UPDATE SET "counter" = EXCLUDED."counter"',
 *   //     params: [1, 42] }
 */
function upsert(tableNameOrRef, opts) { return new UpsertBuilder(tableNameOrRef, opts); }

module.exports = {
  // Verbs
  select:        select,
  insert:        insert,
  insertSelectWhere: insertSelectWhere,
  update:        update,
  guardedUpdate: guardedUpdate,
  casWon:        casWon,
  delete:        del,
  upsert:        upsert,
  // Table reference
  table:         table,
  // Value-position helpers (INSERT values() / UPDATE set() right-hand side)
  fn:            fn,
  cast:          cast,
  // Driver-final positional translation (for direct-driver callers: a DDL
  // { sql, params } result or a chainable builder -> $1..$N on postgres).
  toExternalSql: toExternalSql,
  // DDL
  createTable:   createTable,
  createIndex:   createIndex,
  alterTable:    alterTable,
  dropTable:     dropTable,
  createVirtualTable: createVirtualTable,
  defineTable:   defineTable,
  // Row-Level Security (Postgres)
  enableRowLevelSecurity:  enableRowLevelSecurity,
  disableRowLevelSecurity: disableRowLevelSecurity,
  createPolicy:            createPolicy,
  dropPolicy:              dropPolicy,
  // Catalog / PRAGMA (narrow audited sqlite-internal sub-API)
  catalog:       catalog,
  pragma:        pragma,
  // Error class
  SqlBuilderError: SqlBuilderError,
  // Exposed for the integrator: the operator-facing builder bases +
  // operator allowlist, so wiki harvesters + adjacent lib code can
  // instanceof-check a builder and the must-compose detector can scope.
  Builder:       Builder,
  ALLOWED_OPS:   ALLOWED_OPS,
};

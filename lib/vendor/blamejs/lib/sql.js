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

var DIALECTS = Object.freeze({ postgres: true, sqlite: true, mysql: true });

function _normDialect(dialect) {
  if (dialect === undefined || dialect === null) return "sqlite";
  if (typeof dialect !== "string" || DIALECTS[dialect] !== true) {
    throw _err("dialect must be one of postgres | sqlite | mysql (got " +
      JSON.stringify(dialect) + ")", "sql-builder/bad-dialect");
  }
  return dialect;
}

function _quoteId(name, dialect) {
  return safeSql.quoteIdentifier(name, dialect, { allowReserved: true });
}

var _schemaTypes = (typeof frameworkSchema._types === "function")
  ? frameworkSchema._types
  : function (dialect) {
      if (dialect === "postgres") return { INT: "BIGINT", BLOB: "BYTEA" };
      if (dialect === "sqlite") return { INT: "INTEGER", BLOB: "BLOB" };
      throw _err("framework type map has no entry for dialect '" + dialect + "'",
        "sql-builder/bad-dialect");
    };

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
  return logical;
}

var ALLOWED_OPS = Object.freeze({
  "=": true, "!=": true, "<>": true, "<": true, "<=": true, ">": true, ">=": true,
  "IS": true, "IS NOT": true, "LIKE": true, "NOT LIKE": true,
  "IN": true, "NOT IN": true, "BETWEEN": true,
  "@>": true, "?": true, "?|": true, "?&": true,
  "MATCH": true,
});

var JOIN_KINDS = Object.freeze({
  INNER: "INNER JOIN", LEFT: "LEFT JOIN", RIGHT: "RIGHT JOIN",
  FULL: "FULL JOIN", CROSS: "CROSS JOIN",
});

function _validateColumn(col) {
  if (typeof col !== "string" || col.length === 0) {
    throw _err("column name must be a non-empty string", "sql-builder/bad-column");
  }
  safeSql.validateIdentifier(col, { allowReserved: true });
  return col;
}

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
    this._quoteName = opts.quoteName === true;
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
    safeSql.validateIdentifier(this._name, { allowReserved: true });
  }

  ref(dialect) {
    if (this._schema !== null) {
      return _quoteId(this._schema, dialect) + "." + _quoteId(this._name, dialect);
    }
    if (this._bare) return this._name;
    return _quoteId(this._name, dialect);
  }

  refWithAlias(dialect) {
    var base = this.ref(dialect);
    return this._alias !== null ? base + " " + _quoteId(this._alias, dialect) : base;
  }

  qualifier(dialect) {
    if (this._alias !== null) return _quoteId(this._alias, dialect);
    return this.ref(dialect);
  }

  toString(dialect) {
    return this.refWithAlias(_normDialect(dialect));
  }
}

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

function _renderCast(lhs, type, dialect) {
  var target = _castType(type, dialect);
  if (dialect === "postgres") return lhs + "::" + target;
  return "CAST(" + lhs + " AS " + target + ")";
}

class CastValue {
  constructor(value, type) {
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

function _renderValueCell(value, dialect) {
  if (value instanceof SqlFunction) {
    return { sql: value.toSqlToken(dialect), params: [] };
  }
  if (value instanceof CastValue) {
    return { sql: _renderCast("?", value.type, dialect), params: [value.value] };
  }
  return { sql: "?", params: [value] };
}

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

function _escapeLike(value) {
  return String(value).replace(/[~%_]/g, "~$&");
}

function _composeSub(subBuilder, parentDialect) {
  if (subBuilder._dialect !== parentDialect) {
    throw _err("sub-query dialect '" + subBuilder._dialect + "' does not match the " +
      "parent statement's dialect '" + parentDialect + "' - build the composed " +
      "sub-query with { dialect: '" + parentDialect + "' } so the whole statement " +
      "is one dialect", "sql-builder/dialect-mismatch");
  }
  return subBuilder.toSql();
}

var JSONB_OPS = Object.freeze({ "@>": true, "?": true, "?|": true, "?&": true });

function _assertJsonbDialect(op, dialect) {
  if (JSONB_OPS[op] === true && dialect !== "postgres") {
    throw _err("the '" + op + "' JSONB operator is Postgres-only (no portable " +
      "SQLite / MySQL equivalent); build this query with { dialect: 'postgres' }",
      "sql-builder/jsonb-postgres-only");
  }
}

function _refuseJsonbOp(op, position) {
  if (JSONB_OPS[op] === true) {
    throw _err("the '" + op + "' JSONB operator is not supported in " + position +
      "; use where(col, '" + op + "', value) on a Postgres builder",
      "sql-builder/jsonb-bad-position");
  }
}

class Predicate {
  constructor(owner, joinerDefault) {
    this._owner = owner;
    this._joiner = joinerDefault || "AND";
    this._parts = [];
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

  _cmp(joiner, col, op, value) {
    if (ALLOWED_OPS[op] !== true) {
      throw _err("invalid where operator '" + op + "'", "sql-builder/bad-operator");
    }
    this._gate(col);
    var dialect = this._dialect();
    var qc = _qualifiedColumn(col, dialect);

    _assertJsonbDialect(op, dialect);

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
      return this._add(joiner, qc + " " + op + " NULL", []);
    }

    if (value === null && (op === "=" || op === "!=" || op === "<>")) {
      throw _err("where(" + JSON.stringify(col) + ", '" + op + "', null) is never true in SQL " +
        "(col " + op + " NULL is UNKNOWN); use whereNull(col) / whereNotNull(col) to test for NULL",
        "sql-builder/null-equality");
    }

    if ((op === "LIKE" || op === "NOT LIKE") && typeof value === "string") {
      return this._add(joiner, qc + " " + op + " ? ESCAPE '~'", [_escapeLike(value)]);
    }

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

  where(fieldOrObj, op, value) {
    if (fieldOrObj && typeof fieldOrObj === "object" && !(fieldOrObj instanceof Builder)) {
      var self = this;
      Object.keys(fieldOrObj).forEach(function (k) { self._cmp("AND", k, "=", fieldOrObj[k]); });
      return this;
    }
    if (arguments.length === 2) return this._cmp("AND", fieldOrObj, "=", op);
    return this._cmp("AND", fieldOrObj, op, value);
  }
  andWhere() { return this.where.apply(this, arguments); }
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

  whereInArray(col, values) { return this._inArray("AND", col, values); }
  orWhereInArray(col, values) { return this._inArray("OR", col, values); }
  _inArray(joiner, col, values) {
    if (!Array.isArray(values) || values.length === 0) {
      throw _err("whereInArray requires a non-empty array of values", "sql-builder/empty-in");
    }
    for (var vi = 0; vi < values.length; vi += 1) {
      if (values[vi] === undefined) {
        throw _err("whereInArray value[" + vi + "] is undefined (not a bindable parameter)",
          "sql-builder/bad-in-value");
      }
    }
    this._gate(col);
    var qc = _qualifiedColumn(col, this._dialect());
    if (this._dialect() === "postgres") {
      return this._add(joiner, qc + " = ANY(?)", [values.slice()]);
    }
    var holders = values.map(function () { return "?"; }).join(", ");
    return this._add(joiner, qc + " IN (" + holders + ")", values.slice());
  }

  whereNull(col) { return this._cmp("AND", col, "IS", null); }
  whereNotNull(col) { return this._cmp("AND", col, "IS NOT", null); }
  orWhereNull(col) { return this._cmp("OR", col, "IS", null); }

  whereBetween(col, low, high) { return this._cmp("AND", col, "BETWEEN", [low, high]); }

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

  whereSub(col, op, subBuilder) {
    if (ALLOWED_OPS[op] !== true) {
      throw _err("invalid where operator '" + op + "'", "sql-builder/bad-operator");
    }
    _refuseJsonbOp(op, "a scalar-subquery comparison");
    if (!(subBuilder instanceof Builder)) {
      throw _err("whereSub requires a b.sql subquery builder", "sql-builder/bad-subquery");
    }
    this._gate(col);
    var sub = _composeSub(subBuilder, this._dialect());
    return this._add("AND", _qualifiedColumn(col, this._dialect()) + " " + op +
      " (" + sub.sql + ")", sub.params);
  }

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

function _checkRawFragment(sql, params, opts, where) {
  opts = opts || {};
  if (typeof sql !== "string" || sql.length === 0) {
    throw _err(where + ": sql must be a non-empty string", "sql-builder/bad-raw");
  }
  var p = Array.isArray(params) ? params.slice() : (params == null ? [] : [params]);

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

  if (opts.allowLiterals !== true) _assertRawNoStringLiteral(sql, where);
  _assertNoRawJsonbKeyOp(sql, where);
  var holders = _countPlaceholders(sql);
  if (holders !== p.length) {
    throw _err(where + ": " + holders + " placeholder(s) in sql but " + p.length +
      " param(s) supplied", "sql-builder/placeholder-mismatch");
  }
  return { sql: sql, params: p };
}

function _assertRawNoStringLiteral(sql, where) {
  safeSql.assertNoRawStringLiteral(sql, where, function (w) {
    return _err(w + ": raw SQL must not contain a string literal ('...') - bind " +
      "every value with a ? placeholder, or pass { allowLiterals: true } when the " +
      "literal is static and operator-controlled", "sql-builder/raw-literal");
  });
}

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

var _countPlaceholders = safeSql.countPlaceholders;

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

function _assertEmittable(sql, params) {
  if (typeof sql !== "string" || sql.length === 0) {
    throw _err("toSql: emitted SQL must be a non-empty string (builder bug)",
      "sql-builder/empty-sql");
  }
  if (!Array.isArray(params)) {
    throw _err("toSql: params must be an array (builder bug)",
      "sql-builder/bad-params-shape");
  }
  if (sql.length > MAX_SQL_BYTES) {
    throw _err("toSql: emitted SQL is " + sql.length + " bytes, over the " +
      MAX_SQL_BYTES + "-byte cap - batch the operation rather than building " +
      "one oversized statement", "sql-builder/sql-too-large");
  }
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
  if (n > MAX_BIND_PARAMS) {
    throw _err("toSql: " + n + " bind parameters exceeds the " + MAX_BIND_PARAMS +
      "-parameter wire limit - chunk the values (batch the IN-list / rows)",
      "sql-builder/too-many-params");
  }
  for (var pi = 0; pi < n; pi += 1) {
    var pv = params[pi];
    var pt = typeof pv;
    if (pv === undefined || pt === "function" || pt === "symbol") {
      throw _err("toSql: param[" + pi + "] is " +
        (pv === undefined ? "undefined" : pt) + " - bind a concrete value " +
        "(string / number / boolean / null / bigint / Buffer / Date / object); " +
        "use null for SQL NULL", "sql-builder/bad-param-value");
    }
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

function _emit(sql, params) {
  _assertEmittable(sql, params);
  return { sql: sql, params: params };
}

function _cteFragment(cte, dialect) {
  var name = _quoteId(cte.name, dialect);
  if (cte.builder instanceof Builder) {
    var sub = _composeSub(cte.builder, dialect);
    return { sql: name + " AS (" + sub.sql + ")", params: sub.params };
  }
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

class Builder {
  constructor(verb, tableNameOrRef, opts) {
    opts = opts || {};
    this._verb = verb;
    this._dialect = _normDialect(opts.dialect);
    this._table = _normTableRef(tableNameOrRef, opts);
    this._ctes = [];
    this._cteRecursive = false;

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

  _assertColumnMember(col, where) {
    if (this._columnGateMode === "off" || this._allowedColumns === null) return;
    var bare = col.indexOf(".") !== -1 ? col.split(".").pop() : col;
    if (this._allowedColumns.has(bare)) return;
    if (this._columnGateMode === "warn") return;
    throw _err("column '" + col + "' is not in the allowedColumns set" +
      (where ? " (" + where + ")" : ""), "sql-builder/unknown-column");
  }

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

  toSql() {
    var body = this._render();
    if (this._ctes.length === 0) return body;
    var withClause = _renderWith(this._ctes, this._cteRecursive, this._dialect);
    return {
      sql: withClause.sql + body.sql,
      params: withClause.params.concat(body.params),
    };
  }

  toExternalSql(dialect) {
    var built = this.toSql();
    var d = _normDialect(dialect || this._dialect);
    return { sql: _toPositional(built.sql, d), params: built.params };
  }
}

class SelectBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("select", tableNameOrRef, opts);
    this._projection = [];
    this._distinct = false;
    this._joins = [];
    this._where = new Predicate(this, "AND");
    this._groupBy = [];
    this._having = new Predicate(this, "AND");
    this._orderBy = [];
    this._limit = null;
    this._offset = null;
    this._lockMode = null;
    this._lockSkipLocked = false;
    this._lockNoWait = false;
  }

  distinct() { this._distinct = true; return this; }

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

  selectRaw(expr, params, opts) {
    var checked = _checkRawFragment(expr, params, opts, "selectRaw");
    this._projection.push({ sql: checked.sql, params: checked.params });
    return this;
  }

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
      if (ALLOWED_OPS[joinOp] !== true) {
        throw _err("invalid join ON operator '" + joinOp + "'", "sql-builder/bad-operator");
      }
      _refuseJsonbOp(joinOp, "a join ON clause");
      clause += " ON " + _qualifiedColumn(onLeft, this._dialect) + " " + joinOp + " " +
        _qualifiedColumn(onRight, this._dialect);
    }
    this._joins.push({ sql: clause, params: [] });
    return this;
  }

  joinRaw(sql, params, opts) {
    var checked = _checkRawFragment(sql, params, opts, "joinRaw");
    this._joins.push({ sql: checked.sql, params: checked.params });
    return this;
  }

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
    var limitToken = null;
    if (this._limit !== null) {
      limitToken = String(this._limit);
    } else if (this._offset !== null) {
      limitToken = dialect === "sqlite" ? "-1"
        : (dialect === "mysql" ? "18446744073709551615" : "ALL");
    }
    if (limitToken !== null) sql += " LIMIT " + limitToken;
    if (this._offset !== null) sql += " OFFSET " + this._offset;

    if (this._lockMode !== null) {
      sql += " FOR " + this._lockMode;
      if (this._lockSkipLocked) sql += " SKIP LOCKED";
      else if (this._lockNoWait) sql += " NOWAIT";
    }

    return _emit(sql, params);
  }
}

class InsertBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("insert", tableNameOrRef, opts);
    this._columns = null;
    this._rows = [];
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

  values(rowOrRows) {
    if (Array.isArray(rowOrRows) && rowOrRows.length > 0 && typeof rowOrRows[0] === "object" &&
        rowOrRows[0] !== null && !Array.isArray(rowOrRows[0])) {
      var self = this;
      rowOrRows.forEach(function (r) { self._addRowObject(r); });
      return this;
    }
    if (Array.isArray(rowOrRows)) {
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

class InsertSelectWhereBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("insert-select-where", tableNameOrRef, opts);
    this._columns = null;
    this._values = null;
    this._where = new Predicate(this, "AND");
    this._returning = null;
    this._allowNoWhere = false;
  }

  columns(cols) {
    if (!Array.isArray(cols) || cols.length === 0) {
      throw _err("columns() expects a non-empty array", "sql-builder/bad-columns");
    }
    var self = this;
    cols.forEach(function (c) { self._assertColumnMember(c, "insertSelectWhere"); _validateColumn(c); });
    this._columns = cols.slice();
    return this;
  }

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

class UpdateBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("update", tableNameOrRef, opts);
    this._set = [];
    this._where = new Predicate(this, "AND");
    this._returning = null;
    this._allowNoWhere = false;
    this._requireGuard = false;
    this._guardCount = 0;
  }

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

  guardWhereOp(col, op, expected) {
    this._where.whereOp(col, op, expected);
    this._guardCount += 1;
    return this;
  }

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

class UpsertBuilder extends Builder {
  constructor(tableNameOrRef, opts) {
    super("upsert", tableNameOrRef, opts);
    this._columns = null;
    this._values = null;
    this._conflictKeys = null;
    this._action = null;
    this._updateCols = null;
    this._updateExprs = null;
    this._updateParams = null;
    this._conflictWhere = null;
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

  _renderMysql() {
    var dialect = "mysql";
    var quotedCols = this._columns.map(function (c) { return _quoteId(c, dialect); }).join(", ");
    var tuple = this._renderValuesTuple(dialect);
    var params = tuple.params;

    var sql = "INSERT INTO " + this._table.ref(dialect) + " (" + quotedCols + ") VALUES (" +
      tuple.sql + ")";

    if (this._action === "nothing") {
      var noopCol = (this._conflictKeys && this._conflictKeys[0]) || this._columns[0];
      sql += " ON DUPLICATE KEY UPDATE " + _quoteId(noopCol, dialect) + " = " +
        _quoteId(noopCol, dialect);
    } else {
      var setBuild = this._buildMysqlSet(dialect);
      sql += " ON DUPLICATE KEY UPDATE " + setBuild.sql;
      for (var i = 0; i < setBuild.params.length; i++) params.push(setBuild.params[i]);
    }

    var out = _emit(sql, params);
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

    var assignments = [];
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

  _buildReadback(dialect) {
    var keys = this._conflictKeys || [];
    if (keys.length === 0) {
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
        throw _err("upsert readback: conflict key '" + keys[i] + "' is a " +
          "server-evaluated function (b.sql.fn) with no stable readback identity " +
          "- use a literal/cast conflict key or read the row back explicitly",
          "sql-builder/bad-conflict");
      }
      var cell = _renderValueCell(keyVal, dialect);
      conds.push(_quoteId(keys[i], dialect) + " = " + cell.sql);
      for (var cp = 0; cp < cell.params.length; cp++) params.push(cell.params[cp]);
    }
    sql += " WHERE " + conds.join(" AND ");
    return { sql: sql, params: params };
  }
}

function _normReturning(cols) {
  if (cols === "*" || cols === undefined || cols === null) return "*";
  var arr = Array.isArray(cols) ? cols : [cols];
  arr.forEach(_validateColumn);
  return arr.slice();
}

function _renderReturning(returning, dialect) {
  if (returning === null) return "";
  if (dialect === "mysql") {
    throw _err("RETURNING is not supported on MySQL for this verb - run a " +
      "read-back SELECT on the affected key instead", "sql-builder/returning-unsupported");
  }
  if (returning === "*") return " RETURNING *";
  return " RETURNING " + returning.map(function (c) { return _quoteId(c, dialect); }).join(", ");
}

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
    if (c.references !== undefined && c.references !== false) {
      def += _ddlReferences(c.references, dialect, opts);
    }
    if (typeof c.constraints === "string" && c.constraints.length > 0) {
      var checked = _checkRawFragment(c.constraints, [], { allowLiterals: true }, "createTable.constraints");
      def += " " + checked.sql;
    }
    return def;
  });
  if (Array.isArray(opts.primaryKey) && opts.primaryKey.length > 0) {
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
  return _assertCatalogEmittable(sql, []);
}

function _ddlDefault(value) {
  if (value === null) return "NULL";
  if (typeof value === "number" && isFinite(value)) return String(value);
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "string") return "'" + value.replace(/'/g, "''") + "'";
  throw _err("createTable column default must be a string, number, boolean, or null",
    "sql-builder/bad-default");
}

var FK_ACTIONS = Object.freeze({
  "CASCADE": true, "SET NULL": true, "SET DEFAULT": true, "RESTRICT": true, "NO ACTION": true,
});

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

var FTS5_TOKENIZERS = Object.freeze({
  "unicode61": true, "ascii": true, "porter": true, "trigram": true,
});
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
  var ref = _normTableRef(name, Object.assign({}, opts, { quoteName: true }));
  if (!Array.isArray(opts.columns) || opts.columns.length === 0) {
    throw _err("createVirtualTable requires a non-empty columns array", "sql-builder/bad-columns");
  }
  var cols = opts.columns.map(function (c) {
    var colName = typeof c === "string" ? c : (c && c.name);
    _validateColumn(colName);
    var piece = _quoteId(colName, "sqlite");
    if (c && typeof c === "object" && c.unindexed === true) piece += " UNINDEXED";
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

var CATALOG_PRAGMA_VERBS = Object.freeze({
  "table_info":      { kind: "introspect" },
  "journal_mode":    { kind: "set-or-read" },
  "synchronous":     { kind: "set-or-read" },
  "wal_checkpoint":  { kind: "checkpoint" },
});
var PRAGMA_JOURNAL_MODES = Object.freeze({
  DELETE: true, TRUNCATE: true, PERSIST: true, MEMORY: true, WAL: true, OFF: true,
});
var PRAGMA_SYNC_LEVELS = Object.freeze({ OFF: true, NORMAL: true, FULL: true, EXTRA: true });
var PRAGMA_CHECKPOINT_MODES = Object.freeze({ PASSIVE: true, FULL: true, RESTART: true, TRUNCATE: true });

function _catalogQuoteTable(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw _err("catalog: table name must be a non-empty string", "sql-builder/bad-table");
  }
  return safeSql.quoteIdentifier(name, "sqlite", { allowReserved: true });
}

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
  safeSql.assertSingleStatement(sql, {
    label: "catalog",
    makeError: function (m, suffix) { return _err(m, "sql-builder/" + suffix); },
  });
  return { sql: sql, params: params };
}

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

function _pluralize(s) {
  if (/[^aeiou]y$/i.test(s)) return s.slice(0, -1) + "ies";
  if (/(?:s|x|z|ch|sh)$/i.test(s)) return s + "es";
  return s + "s";
}

function _inferFkRef(colName, pkCol) {
  var m = /^(.+?)(?:Id|_id)$/.exec(colName);
  if (!m || m[1].length === 0) return null;
  return { table: _pluralize(m[1]), column: pkCol };
}

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

  var cols = spec.map(function (c) {
    if (!c || typeof c !== "object" || typeof c.name !== "string") {
      throw _err("defineTable column must be { name, type, ... }", "sql-builder/bad-column");
    }
    return Object.assign({}, c);
  });

  var declaredPk = cols.some(function (c) { return c.primaryKey || c.autoIncrement; }) ||
    (Array.isArray(opts.primaryKey) && opts.primaryKey.length > 0);
  if (autoPk && !declaredPk) cols.unshift({ name: pkCol, autoIncrement: true });

  var declared = {};
  cols.forEach(function (c) { declared[c.name] = true; });
  function _assertMember(col, where) {
    if (declared[col] !== true) {
      throw _err("defineTable: " + where + " references column '" + col +
        "' which is not a declared column of '" + name + "'", "sql-builder/unknown-column");
    }
  }

  var fkColumns = [];
  cols.forEach(function (c) {
    if (c.references === false) return;
    if (c.references !== undefined) { fkColumns.push(c.name); return; }
    if (c.primaryKey || c.autoIncrement) return;
    if (autoFk) {
      var inferred = _inferFkRef(c.name, pkCol);
      if (inferred) { c.references = inferred; fkColumns.push(c.name); }
    }
  });

  var statements = [createTable(name, cols, opts)];

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
 *   // var stmt = b.db.prepare(q.sql);
 *   // var res  = stmt.run.apply(stmt, q.params);
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
 *   // requires: an open database and a `q` built by b.sql.guardedUpdate
 *   var stmt = b.db.prepare(q.sql);
 *   var v = b.sql.casWon(stmt.run.apply(stmt, q.params));
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
  select:        select,
  insert:        insert,
  insertSelectWhere: insertSelectWhere,
  update:        update,
  guardedUpdate: guardedUpdate,
  casWon:        casWon,
  delete:        del,
  upsert:        upsert,
  table:         table,
  fn:            fn,
  cast:          cast,
  toExternalSql: toExternalSql,
  createTable:   createTable,
  createIndex:   createIndex,
  alterTable:    alterTable,
  dropTable:     dropTable,
  createVirtualTable: createVirtualTable,
  defineTable:   defineTable,
  enableRowLevelSecurity:  enableRowLevelSecurity,
  disableRowLevelSecurity: disableRowLevelSecurity,
  createPolicy:            createPolicy,
  dropPolicy:              dropPolicy,
  catalog:       catalog,
  pragma:        pragma,
  SqlBuilderError: SqlBuilderError,
  Builder:       Builder,
  ALLOWED_OPS:   ALLOWED_OPS,
};

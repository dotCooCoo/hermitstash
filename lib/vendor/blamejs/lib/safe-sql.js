"use strict";
/**
 * SQL safety primitive — identifier validation and parameterized query
 * helpers.
 *
 * The framework's own SQL is parameterized everywhere — values bind
 * through node:sqlite or external-db drivers, never string-concatenated.
 * That covers value injection. The remaining attack surface is
 * IDENTIFIER injection: when a TABLE name or COLUMN name is interpolated
 * into a SQL string, a malicious or misconfigured caller can break out
 * of the intended structure. This is rare in framework-internal code
 * (we control the names) but easy to get wrong if operator-supplied
 * config flows in unchecked.
 *
 * This module provides the thin validator that any code interpolating
 * identifiers should call first. It does NOT execute SQL; it just
 * validates the inputs that get composed into SQL elsewhere.
 *
 * Public API:
 *   safeSql.validateIdentifier(name, opts?)        throws on bad shape
 *   safeSql.quoteIdentifier(name, dialect?)        returns "name" / `name`
 *   safeSql.assertOneOf(name, allowlist)           throws unless in list
 *   safeSql.SafeSqlError                           error class
 *
 * Identifier rule (default): `^[A-Za-z_][A-Za-z0-9_]*$` with length
 *   1–63 chars (Postgres NAMEDATALEN default; SQLite has no hard
 *   limit but matching the strictest dialect is the safe bound).
 *
 * Forbidden in identifiers regardless of regex:
 *   - SQL reserved words (a small allowlist, not exhaustive — operators
 *     who need reserved-word identifiers should quote them and accept
 *     the dialect-specific quoting)
 *   - Leading underscore prefixed `sqlite_` (SQLite-internal)
 *   - Embedded null byte
 *
 * Quoting:
 *   sqlite     "name"      (double-quote per SQL standard; SQLite
 *                          accepts double quotes for identifiers
 *                          per its quirks settings)
 *   postgres   "name"
 *   mysql      `name`      (MySQL's backtick convention)
 *
 * Allowlist usage (recommended):
 *   var ALLOWED_TABLES = new Set(["audit_log", "consent_log", …]);
 *   safeSql.assertOneOf(operatorTableName, ALLOWED_TABLES);
 *   var sql = "INSERT INTO " + safeSql.quoteIdentifier(operatorTableName) + " …";
 *
 *   The allowlist is the strongest guarantee. Operators with dynamic
 *   identifier needs (rare) use validateIdentifier alone, accepting
 *   that any string passing the regex is allowed.
 */

// Reserved-word block list — the most dangerous to accept as a bare
// identifier. Not exhaustive; the allowlist pattern below is preferred.
var BANNED_IDENTIFIERS = new Set([
  "select", "insert", "update", "delete", "drop", "create", "alter",
  "truncate", "grant", "revoke", "union", "exec", "execute",
  "where", "from", "join", "into", "values", "table", "database",
  "schema", "index", "view", "trigger", "procedure", "function",
  "begin", "commit", "rollback", "savepoint",
  // SQLite-specific commands that escape the parameterized-query
  // model. attach/detach mount external databases; pragma changes
  // PRAGMAs (foreign_keys / cell_size_check / trusted_schema /
  // journal_mode etc.) which can disable security-relevant
  // protections; analyze / vacuum drop or rewrite indexes.
  "pragma", "attach", "detach", "analyze", "vacuum", "reindex",
]);

// Default identifier shape — Postgres NAMEDATALEN (63 chars) is the
// strictest of the dialects we support, so use it as the bound.
var DEFAULT_IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
var MAX_IDENTIFIER_LENGTH = 63;

var { FrameworkError } = require("./framework-error");

class SafeSqlError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "SafeSqlError";
    this.code = code || "sql/invalid";
    this.isSafeSqlError = true;
  }
}

function validateIdentifier(name, opts) {
  opts = opts || {};
  if (typeof name !== "string") {
    throw new SafeSqlError("identifier must be a string (got " + typeof name + ")",
      "sql/bad-type");
  }
  if (name.length === 0) {
    throw new SafeSqlError("identifier must not be empty", "sql/empty");
  }
  if (name.length > MAX_IDENTIFIER_LENGTH) {
    throw new SafeSqlError(
      "identifier '" + name + "' exceeds maxLength " + MAX_IDENTIFIER_LENGTH,
      "sql/too-long"
    );
  }
  if (name.indexOf("\0") >= 0) {
    throw new SafeSqlError("identifier contains null byte", "sql/null-byte");
  }
  var pattern = opts.pattern || DEFAULT_IDENTIFIER_RE;
  if (!pattern.test(name)) {
    throw new SafeSqlError(
      "identifier '" + name + "' does not match required pattern " + pattern,
      "sql/bad-shape"
    );
  }
  if (!opts.allowReserved && BANNED_IDENTIFIERS.has(name.toLowerCase())) {
    throw new SafeSqlError(
      "identifier '" + name + "' is a SQL reserved word",
      "sql/reserved-word"
    );
  }
  if (!opts.allowSqliteInternal && /^sqlite_/i.test(name)) {
    throw new SafeSqlError(
      "identifier '" + name + "' uses the SQLite-internal 'sqlite_' prefix",
      "sql/internal-prefix"
    );
  }
  return name;
}

function quoteIdentifier(name, dialect) {
  validateIdentifier(name);
  dialect = (dialect || "sqlite").toLowerCase();
  if (dialect === "mysql") return "`" + name + "`";
  // sqlite + postgres both use double-quote per SQL standard
  return '"' + name + '"';
}

// Quote a multi-part qualified name like `schema.table` or
// `database.schema.table`. Each segment is validated + quoted
// independently so the dotted form `"schema"."table"` resolves
// correctly. Replaces the wrong shape `"schema.table"` (one literal
// identifier with a dot in it). Accepts an array of parts OR a string
// with `.` as the separator.
//
//   quoteQualified(["public", "users"])     → '"public"."users"'
//   quoteQualified("public.users")          → '"public"."users"'
//   quoteQualified(["public", "Order"], "postgres")
//                                          → '"public"."Order"'   (case preserved)
//   quoteQualified("dbA.public.users")      → '"dbA"."public"."users"'
function quoteQualified(parts, dialect) {
  var arr;
  if (typeof parts === "string") {
    if (parts.length === 0) {
      throw new SafeSqlError("qualified name must not be empty", "sql/empty");
    }
    arr = parts.split(".");
  } else if (Array.isArray(parts)) {
    arr = parts.slice();
  } else {
    throw new SafeSqlError(
      "qualified name must be a string or array, got " + typeof parts,
      "sql/bad-type"
    );
  }
  if (arr.length === 0) {
    throw new SafeSqlError("qualified name must have at least one segment", "sql/empty");
  }
  var quoted = [];
  for (var i = 0; i < arr.length; i++) {
    quoted.push(quoteIdentifier(arr[i], dialect));
  }
  return quoted.join(".");
}

function assertOneOf(name, allowlist) {
  if (typeof name !== "string") {
    throw new SafeSqlError("name must be a string", "sql/bad-type");
  }
  // Accept either Set or array
  var ok = false;
  if (allowlist && typeof allowlist.has === "function") {
    ok = allowlist.has(name);
  } else if (Array.isArray(allowlist)) {
    ok = allowlist.indexOf(name) !== -1;
  } else {
    throw new SafeSqlError("allowlist must be a Set or array", "sql/bad-allowlist");
  }
  if (!ok) {
    throw new SafeSqlError(
      "identifier '" + name + "' not in allowlist",
      "sql/not-allowed"
    );
  }
  return name;
}

module.exports = {
  validateIdentifier:  validateIdentifier,
  quoteIdentifier:     quoteIdentifier,
  quoteQualified:      quoteQualified,
  assertOneOf:         assertOneOf,
  SafeSqlError:        SafeSqlError,
  // Exposed so consumers can compose their own validators
  DEFAULT_IDENTIFIER_RE: DEFAULT_IDENTIFIER_RE,
  MAX_IDENTIFIER_LENGTH: MAX_IDENTIFIER_LENGTH,
};

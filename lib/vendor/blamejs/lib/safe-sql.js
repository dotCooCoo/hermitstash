"use strict";
/**
 * @module b.safeSql
 * @nav    Validation
 * @title  Safe Sql
 *
 * @intro
 *   SQL identifier validation + dialect-aware quoting + allowlist
 *   gating. Defends against IDENTIFIER injection — the residual attack
 *   surface left over when a TABLE name or COLUMN name flows from
 *   operator-supplied config into a SQL string. Values bind through
 *   parameterized queries everywhere in the framework, but parameters
 *   can't carry identifiers; that interpolation is what this module
 *   guards.
 *
 *   Default identifier shape: `^[A-Za-z_][A-Za-z0-9_]*$`, length 1–63
 *   (Postgres NAMEDATALEN — the strictest of the supported dialects).
 *   Reserved words (SELECT / DROP / PRAGMA / ATTACH / …) and the
 *   SQLite-internal `sqlite_` prefix are refused unless the caller
 *   explicitly opts in. Quoting follows dialect convention: SQLite +
 *   Postgres double-quote, MySQL backtick. Multi-segment names
 *   (`schema.table`) validate + quote each segment independently so
 *   the dotted form `"schema"."table"` resolves correctly instead of
 *   collapsing into one literal identifier with a dot in it.
 *
 *   Recommended pattern is the closed allowlist:
 *
 *     var ALLOWED = new Set(["audit_log", "consent_log"]);
 *     b.safeSql.assertOneOf(name, ALLOWED);
 *     var sql = "INSERT INTO " + b.safeSql.quoteIdentifier(name) + " ...";
 *
 *   The allowlist is the strongest guarantee. Operators with genuinely
 *   dynamic identifier needs use `validateIdentifier` alone, accepting
 *   that any string passing the regex is allowed.
 *
 *   Validation policy: every primitive throws `SafeSqlError` on bad
 *   input — these run at SQL-composition time, well before the query
 *   reaches the database. The throw IS the security signal.
 *
 * @card
 *   SQL identifier validation + dialect-aware quoting + allowlist gating.
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

/**
 * @primitive b.safeSql.SafeSqlError
 * @signature b.safeSql.SafeSqlError
 * @since     0.1.0
 * @status    stable
 * @related   b.safeSql.validateIdentifier, b.safeSql.quoteIdentifier, b.safeSql.assertOneOf
 *
 * Error class thrown by every `b.safeSql` primitive on bad input.
 * Extends `FrameworkError`. Carries a stable `.code` —
 * `sql/bad-type` / `sql/empty` / `sql/too-long` / `sql/null-byte` /
 * `sql/bad-shape` / `sql/reserved-word` / `sql/internal-prefix` /
 * `sql/not-allowed` / `sql/bad-allowlist`. Operators catch these at
 * SQL-composition boundaries; the throw fires before the query
 * reaches the database driver.
 *
 * @example
 *   var b = require("blamejs");
 *   try {
 *     b.safeSql.validateIdentifier("drop");
 *   } catch (e) {
 *     e instanceof b.safeSql.SafeSqlError;   // → true
 *     e.code;                                // → "sql/reserved-word"
 *   }
 */
class SafeSqlError extends FrameworkError {
  constructor(message, code) {
    super(message);
    this.name = "SafeSqlError";
    this.code = code || "sql/invalid";
    this.isSafeSqlError = true;
  }
}

/**
 * @primitive b.safeSql.validateIdentifier
 * @signature b.safeSql.validateIdentifier(name, opts?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeSql.quoteIdentifier, b.safeSql.assertOneOf, b.safeSql.SafeSqlError
 *
 * Throw-on-bad-shape validator for SQL table / column / index names.
 * Enforces the default identifier regex (`[A-Za-z_][A-Za-z0-9_]*`),
 * a 63-character cap (Postgres NAMEDATALEN — strictest supported
 * dialect), no embedded null byte, no SQL reserved word, no
 * SQLite-internal `sqlite_` prefix. Returns `name` on success so the
 * call composes inside a SQL fragment without an extra temporary.
 *
 * @opts
 *   pattern:              RegExp,  // override the default shape regex
 *   allowReserved:        boolean, // default false; permit reserved words like "select"/"drop"
 *   allowSqliteInternal:  boolean, // default false; permit "sqlite_..." identifiers
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.validateIdentifier("audit_log");
 *   // → "audit_log"
 *
 *   try { b.safeSql.validateIdentifier("drop"); }
 *   catch (e) { e.code; }
 *   // → "sql/reserved-word"
 *
 *   try { b.safeSql.validateIdentifier("evil; DROP"); }
 *   catch (e) { e.code; }
 *   // → "sql/bad-shape"
 *
 *   // Operator opts in to a custom shape (still ASCII-only, still capped).
 *   b.safeSql.validateIdentifier("col-1", { pattern: /^[A-Za-z][A-Za-z0-9_-]*$/ });
 *   // → "col-1"
 */
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

/**
 * @primitive b.safeSql.quoteIdentifier
 * @signature b.safeSql.quoteIdentifier(name, dialect?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeSql.validateIdentifier, b.safeSql.quoteQualified
 *
 * Validate `name` then wrap it in dialect-appropriate quotes —
 * double-quote for SQLite + Postgres (per SQL standard), backtick for
 * MySQL. Default dialect is `"sqlite"`. Throws `SafeSqlError` if the
 * identifier fails `validateIdentifier`.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.quoteIdentifier("users");
 *   // → '"users"'
 *
 *   b.safeSql.quoteIdentifier("Order", "postgres");
 *   // → '"Order"'
 *
 *   b.safeSql.quoteIdentifier("users", "mysql");
 *   // → "`users`"
 */
function quoteIdentifier(name, dialect) {
  validateIdentifier(name);
  dialect = (dialect || "sqlite").toLowerCase();
  if (dialect === "mysql") return "`" + name + "`";
  // sqlite + postgres both use double-quote per SQL standard
  return '"' + name + '"';
}

/**
 * @primitive b.safeSql.quoteQualified
 * @signature b.safeSql.quoteQualified(parts, dialect?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeSql.quoteIdentifier, b.safeSql.validateIdentifier
 *
 * Quote a multi-part qualified name like `schema.table` or
 * `database.schema.table`. Each segment is validated and quoted
 * independently so the resulting SQL is `"schema"."table"` (three
 * lookups against the catalog) instead of `"schema.table"` (one
 * literal identifier with a dot in its name — a different and
 * usually-nonexistent object). Accepts an array of parts OR a
 * dot-separated string.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.quoteQualified(["public", "users"]);
 *   // → '"public"."users"'
 *
 *   b.safeSql.quoteQualified("public.users");
 *   // → '"public"."users"'
 *
 *   b.safeSql.quoteQualified("dbA.public.users");
 *   // → '"dbA"."public"."users"'
 *
 *   b.safeSql.quoteQualified(["app", "orders"], "mysql");
 *   // → "`app`.`orders`"
 */
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

/**
 * @primitive b.safeSql.assertOneOf
 * @signature b.safeSql.assertOneOf(name, allowlist)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeSql.validateIdentifier, b.safeSql.quoteIdentifier
 *
 * Closed-allowlist gate — the strongest guarantee against identifier
 * injection. `allowlist` is a `Set` or `Array` of permitted names;
 * anything outside throws `SafeSqlError` with `.code = "sql/not-allowed"`.
 * Returns `name` on success so the call composes inline with
 * `quoteIdentifier`. Use this whenever the operator-supplied identifier
 * is drawn from a known finite set (which is most cases — table names
 * are config, not user input).
 *
 * @example
 *   var b = require("blamejs");
 *   var ALLOWED = new Set(["audit_log", "consent_log", "session"]);
 *
 *   b.safeSql.assertOneOf("audit_log", ALLOWED);
 *   // → "audit_log"
 *
 *   try { b.safeSql.assertOneOf("users", ALLOWED); }
 *   catch (e) { e.code; }
 *   // → "sql/not-allowed"
 *
 *   // Array form works too.
 *   b.safeSql.assertOneOf("audit_log", ["audit_log", "consent_log"]);
 *   // → "audit_log"
 */
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

/**
 * @primitive b.safeSql.DEFAULT_IDENTIFIER_RE
 * @signature b.safeSql.DEFAULT_IDENTIFIER_RE
 * @since     0.1.0
 * @status    stable
 * @related   b.safeSql.validateIdentifier, b.safeSql.MAX_IDENTIFIER_LENGTH
 *
 * The default identifier shape regex — `/^[A-Za-z_][A-Za-z0-9_]*$/`.
 * Exposed so operator code that needs a slightly-wider or
 * slightly-narrower shape can compose against it instead of
 * re-deriving the pattern. ASCII-only by design — Unicode
 * identifiers are dialect-specific and surface in mismatched-encoding
 * footguns we don't want to default into.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.DEFAULT_IDENTIFIER_RE.test("audit_log");
 *   // → true
 *
 *   b.safeSql.DEFAULT_IDENTIFIER_RE.test("1starts_with_digit");
 *   // → false
 */

/**
 * @primitive b.safeSql.MAX_IDENTIFIER_LENGTH
 * @signature b.safeSql.MAX_IDENTIFIER_LENGTH
 * @since     0.1.0
 * @status    stable
 * @related   b.safeSql.validateIdentifier, b.safeSql.DEFAULT_IDENTIFIER_RE
 *
 * Hard cap on identifier length — 63 characters. Matches Postgres'
 * NAMEDATALEN default; SQLite and MySQL accept longer names but
 * defaulting to the strictest dialect keeps cross-dialect SQL
 * portable.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.MAX_IDENTIFIER_LENGTH;
 *   // → 63
 */

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

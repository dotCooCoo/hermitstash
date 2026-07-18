// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 * @signature b.safeSql.quoteIdentifier(name, dialect?, opts?)
 * @since     0.1.0
 * @status    stable
 * @related   b.safeSql.validateIdentifier, b.safeSql.quoteQualified
 *
 * Validate `name` then wrap it in dialect-appropriate quotes —
 * double-quote for SQLite + Postgres (per SQL standard), backtick for
 * MySQL. Default dialect is `"sqlite"`. Throws `SafeSqlError` if the
 * identifier fails `validateIdentifier`.
 *
 * `opts` is forwarded to `validateIdentifier` — pass
 * `{ allowReserved: true }` to quote a name that collides with a SQL
 * keyword (a column literally named `from` / `select`). Quoting is
 * exactly what makes a reserved word safe in identifier position, so the
 * query builder (`b.sql`) routes every identifier through here with
 * `allowReserved` on; the default still rejects reserved words so a bare
 * caller catches the likely typo.
 *
 * @opts
 *   allowReserved:  boolean,   // default: false — permit SQL-keyword names (safe once quoted)
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.quoteIdentifier("users");
 *   // → '"users"'
 *
 *   b.safeSql.quoteIdentifier("Order", "postgres");
 *   // → '"Order"'
 *
 *   b.safeSql.quoteIdentifier("from", "postgres", { allowReserved: true });
 *   // → '"from"'
 *
 *   b.safeSql.quoteIdentifier("users", "mysql");
 *   // → "`users`"
 */
function quoteIdentifier(name, dialect, opts) {
  validateIdentifier(name, opts);
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
 * @primitive b.safeSql.quoteList
 * @signature b.safeSql.quoteList(names, dialect?, opts?)
 * @since     0.15.0
 * @status    stable
 * @related   b.safeSql.quoteIdentifier, b.safeSql.quoteQualified, b.sql
 *
 * Quote a list of identifiers into a comma-joined fragment — each name
 * validated + quoted via `quoteIdentifier`. The "many" companion to
 * `quoteIdentifier` (one) and `quoteQualified` (a dotted name): use it for
 * SELECT projections and INSERT column lists so the recurring
 * `cols.map(quoteIdentifier).join(", ")` shape is composed, not hand-rolled.
 *
 * There is deliberately NO value/string-literal quoter in this module:
 * values flow as bound placeholders (`?` / `$N`), never interpolated, which
 * is what makes the injection class structurally impossible. Quoting a
 * literal would reopen it — use the query builder's parameter binding.
 *
 * `opts` is forwarded to each `quoteIdentifier` (e.g.
 * `{ allowReserved: true }` for column lists that may contain SQL-keyword
 * names, as `b.sql` does).
 *
 * Throws `SafeSqlError` (`sql/empty`) on an empty array and (per
 * `quoteIdentifier`) on any invalid identifier.
 *
 * @opts
 *   allowReserved:  boolean,   // default: false — forwarded to quoteIdentifier
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.quoteList(["id", "createdAt"], "postgres");
 *   // → '"id", "createdAt"'
 *
 *   b.safeSql.quoteList(["queueName", "status"], "mysql");
 *   // → "`queueName`, `status`"
 */
function quoteList(names, dialect, opts) {
  if (!Array.isArray(names) || names.length === 0) {
    throw new SafeSqlError("quoteList requires a non-empty array of identifiers", "sql/empty");
  }
  var out = [];
  for (var i = 0; i < names.length; i++) {
    out.push(quoteIdentifier(names[i], dialect, opts));
  }
  return out.join(", ");
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
 * @primitive b.safeSql.countPlaceholders
 * @signature b.safeSql.countPlaceholders(sql)
 * @since     0.14.29
 * @status    stable
 * @related   b.safeSql.quoteIdentifier, b.safeSql.validateIdentifier
 *
 * Count the bound `?` placeholders in a SQL string, skipping any `?`
 * that appears inside a string literal (`'...'` / `"..."`, doubled-quote
 * escape aware) or inside a line or block comment. The canonical quote-
 * and comment-aware scanner the query builder uses to check placeholder /
 * param parity and the residency write-gate uses to align bound values;
 * both compose this so the skip rules live in one place.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.countPlaceholders("a = ? AND b = ?");
 *   // → 2
 *
 *   b.safeSql.countPlaceholders("note = 'is ? literal' AND id = ?");
 *   // → 1
 */
function countPlaceholders(sql) {
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

/**
 * @primitive b.safeSql.toPositional
 * @signature b.safeSql.toPositional(sql, dialect)
 * @since     0.15.13
 * @status    stable
 * @related   b.safeSql.countPlaceholders, b.sql
 *
 * Rewrite bound `?` placeholders to Postgres `$N` positional form,
 * skipping any `?` inside a string literal (`'...'` / `"..."` /
 * `` `...` ``, doubled-quote escape aware) or a line / block comment. For
 * any non-Postgres dialect the SQL is returned unchanged (`?` is already
 * the wire form). This is the same quote- and comment-aware scan as
 * `countPlaceholders`, extended to emit the rewritten string and to skip
 * MySQL backtick-quoted identifiers; the query builder and the cluster
 * store both compose it so the rewrite lives in one place.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.toPositional("a = ? AND b = ?", "postgres");
 *   // → "a = $1 AND b = $2"
 *
 *   b.safeSql.toPositional("note = 'is ? literal' AND id = ?", "postgres");
 *   // → "note = 'is ? literal' AND id = $1"
 */
function toPositional(sql, dialect) {
  if (dialect !== "postgres") return sql;
  var out = "";
  var n = 0;
  var i = 0;
  var len = sql.length;
  while (i < len) {
    var c = sql.charAt(i);
    var nx = i + 1 < len ? sql.charAt(i + 1) : "";
    if (c === "'" || c === '"' || c === "`") {
      out += c;
      i += 1;
      while (i < len) {
        var q = sql.charAt(i);
        if (q === c) {
          if (sql.charAt(i + 1) === c) { out += c + c; i += 2; continue; }
          out += c; i += 1; break;
        }
        out += q; i += 1;
      }
      continue;
    }
    if (c === "-" && nx === "-") {
      while (i < len && sql.charAt(i) !== "\n") { out += sql.charAt(i); i += 1; }
      continue;
    }
    if (c === "/" && nx === "*") {
      out += "/*"; i += 2;
      while (i < len && !(sql.charAt(i) === "*" && sql.charAt(i + 1) === "/")) { out += sql.charAt(i); i += 1; }
      if (i < len) { out += "*/"; i += 2; }
      continue;
    }
    if (c === "?") { n += 1; out += "$" + n; i += 1; continue; }
    out += c;
    i += 1;
  }
  return out;
}

/**
 * @primitive b.safeSql.normalizeForScan
 * @signature b.safeSql.normalizeForScan(sql)
 * @since     0.17.4
 * @status    stable
 * @related   b.safeSql.countPlaceholders, b.safeSql.toPositional, b.safeSql.assertSingleStatement
 *
 * Produce a parse-only copy of `sql` whose token boundaries are real
 * whitespace, so a regex tokenizer that assumes whitespace-separated tokens
 * cannot be evaded. SQL lets two tokens abut with NO whitespace whenever a
 * comment OR a quoted-identifier boundary separates them (an `INSERT` whose
 * quoted table name abuts `INTO`, or a slash-star comment wedged between a
 * keyword and the table); a keyword/table detector hand-rolled with `\s+`
 * boundaries silently misses those forms even though the engine executes them.
 * This scan replaces every line (`--`) and slash-star block comment with a
 * single space and inserts a separating space wherever a quoted string /
 * identifier (`'...'` / `"..."` / a backtick-quoted name) abuts a word
 * character on either side — a word char directly before the opening quote OR
 * directly after the closing quote. The same quote- and comment-aware single
 * pass as `countPlaceholders` / `toPositional` (doubled-quote escapes
 * respected), so a comment marker inside a string literal is copied verbatim,
 * never collapsed. The executed SQL is unchanged — this copy only feeds a
 * scanner.
 *
 * @example
 *   var b = require("blamejs");
 *   b.safeSql.normalizeForScan('INSERT INTO"t"(a) VALUES(?)');
 *   // → 'INSERT INTO "t"(a) VALUES(?)'
 *
 *   b.safeSql.normalizeForScan('UPDATE"residents"SET x=1');
 *   // → 'UPDATE "residents" SET x=1'
 *
 *   b.safeSql.normalizeForScan("SELECT 1-- note");
 *   // → "SELECT 1 "
 */
function normalizeForScan(sql) {
  var s = String(sql);
  var out = "";
  var i = 0;
  var len = s.length;
  while (i < len) {
    var c = s.charAt(i);
    var nx = i + 1 < len ? s.charAt(i + 1) : "";
    if (c === "'" || c === '"' || c === "`") {
      // A quoted token abutting a word character gets a separating space so the
      // downstream whitespace-anchored tokenizer sees the boundary — on BOTH
      // sides: before the opening quote when a word char precedes it
      // (`INTO"t"`), and after the closing quote when a word char follows it
      // (`"t"SET` / `UPDATE"residents"SET`). A quoted identifier separates
      // tokens with no whitespace in either direction, so a one-sided boundary
      // still lets a write hide from the scan. Between, copy the whole quoted
      // run verbatim (doubled-quote escapes preserved) so a comment marker
      // inside the literal is never collapsed.
      if (out.length > 0 && /\w/.test(out.charAt(out.length - 1))) out += " ";
      out += c;
      i += 1;
      while (i < len) {
        var q = s.charAt(i);
        out += q;
        if (q === c) {
          if (s.charAt(i + 1) === c) { out += c; i += 2; continue; }
          i += 1; break;
        }
        i += 1;
      }
      if (i < len && /\w/.test(s.charAt(i))) out += " ";
      continue;
    }
    if (c === "-" && nx === "-") {          // line comment → one space
      i += 2;
      while (i < len && s.charAt(i) !== "\n") i += 1;
      out += " ";
      continue;
    }
    if (c === "/" && nx === "*") {          // block comment → one space
      i += 2;
      while (i < len && !(s.charAt(i) === "*" && s.charAt(i + 1) === "/")) i += 1;
      i += 2;
      out += " ";
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
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

/**
 * @primitive b.safeSql.assertSingleStatement
 * @signature b.safeSql.assertSingleStatement(sql, opts?)
 * @since     0.15.4
 * @status    stable
 * @related   b.safeSql.quoteIdentifier, b.safeSql.countPlaceholders, b.sql
 *
 * The one quote/comment-aware single-statement gate for any FINISHED SQL
 * string that reaches a driver. Refuses a NUL, a lone surrogate, a
 * top-level ';' (stacked statement), an unterminated quote, and unbalanced
 * parentheses - while CORRECTLY allowing those characters inside a balanced
 * quoted label (e.g. a MySQL ENUM('a;b')). Hand-rolled DDL (schema
 * reconcile, the DSR store, migrations) and the b.sql builder's own output
 * gates route through this single scan so the injection backstop cannot
 * drift between the structured builder and the raw-DDL paths. Returns the
 * input string so a caller can wrap inline:
 *   runSql(db, safeSql.assertSingleStatement(ddl, { label: "schema" }));
 *
 * @opts
 *   label:     string,    // message prefix (default: "sql")
 *   makeError: function,  // (message, codeSuffix) => Error  (default: SafeSqlError "sql/<suffix>")
 *
 * @example
 *   var ddl = b.safeSql.assertSingleStatement("CREATE TABLE t (id INTEGER)", { label: "schema" });
 *   // returns the input string; throws sql/stacked-statement on a stacked DDL
 */
function assertSingleStatement(sql, opts) {
  opts = opts || {};
  var label = typeof opts.label === "string" ? opts.label : "sql";
  var mkErr = typeof opts.makeError === "function"
    ? opts.makeError
    : function (msg, suffix) { return new SafeSqlError(msg, "sql/" + suffix); };
  // Backtick written via its code point so no NUL byte can reach this source.
  var BACKTICK = String.fromCharCode(96);
  if (typeof sql !== "string" || sql.length === 0) {
    throw mkErr(label + ": SQL must be a non-empty string", "empty-sql");
  }
  if (sql.indexOf(String.fromCharCode(0)) !== -1) {
    throw mkErr(label + ": SQL contains a NUL byte - rejected", "null-byte-sql");
  }
  if (typeof sql.isWellFormed === "function" && !sql.isWellFormed()) {
    throw mkErr(label + ": SQL contains invalid Unicode (lone surrogates) - rejected",
      "invalid-encoding-sql");
  }
  var i = 0;
  var len = sql.length;
  var depth = 0;
  while (i < len) {
    var ch = sql.charAt(i);
    var next = i + 1 < len ? sql.charAt(i + 1) : "";
    if (ch === "'" || ch === '"' || ch === BACKTICK) {
      var qch = ch;
      var closed = false;
      i += 1;
      while (i < len) {
        if (sql.charAt(i) === qch) {
          if (sql.charAt(i + 1) === qch) { i += 2; continue; }  // doubled quote = escaped literal
          i += 1; closed = true; break;
        }
        i += 1;
      }
      if (!closed) {
        throw mkErr(label + ": unterminated quote in SQL (quote-jump / breakout risk)",
          "unterminated-quote");
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
    if (ch === "(") { depth += 1; }
    else if (ch === ")") { depth -= 1; }
    else if (ch === ";") {
      throw mkErr(label + ": emitted a top-level ';' - exactly one statement", "stacked-statement");
    }
    i += 1;
  }
  if (depth !== 0) {
    throw mkErr(label + ": unbalanced parentheses in SQL", "unbalanced");
  }
  return sql;
}

/**
 * @primitive b.safeSql.assertNoRawStringLiteral
 * @signature b.safeSql.assertNoRawStringLiteral(sql, where, makeError?)
 * @since     0.15.13
 * @status    stable
 * @related   b.safeSql.assertSingleStatement, b.safeSql.countPlaceholders, b.sql
 *
 * The one quote/comment-aware scan that refuses a `'...'` STRING LITERAL in
 * raw SQL — the injection backstop for the b.sql builder's raw fragments and
 * the external-db raw-query path, which must bind every value with a `?`
 * placeholder rather than splice a literal. Walks the SQL skipping `"..."`
 * quoted identifiers (doubled-quote escapes handled), `-- line` comments, and
 * slash-star block comments; on the first top-level `'` it throws the caller's
 * error (`makeError(where)` returns the Error to throw). Both b.sql and the
 * external-db raw gate route through this single scan so a fix to the scanner
 * cannot drift between them.
 *
 * @example
 *   b.safeSql.assertNoRawStringLiteral("WHERE id = ?", "where");   // ok (no literal)
 *   try { b.safeSql.assertNoRawStringLiteral("WHERE name = 'x'", "where"); }
 *   catch (e) { e.code; }                                          // → "sql/raw-literal"
 */
function assertNoRawStringLiteral(sql, where, makeError) {
  var mkErr = typeof makeError === "function" ? makeError : function (w) {
    return new SafeSqlError(w + ": raw SQL must not contain a string literal ('...') — bind every " +
      "value with a ? placeholder, or pass { allowLiterals: true } when the literal " +
      "is static and operator-controlled.", "sql/raw-literal");
  };
  var i = 0;
  var len = sql.length;
  while (i < len) {
    var ch = sql.charAt(i);
    var next = i + 1 < len ? sql.charAt(i + 1) : "";
    if (ch === '"') {
      i += 1;
      while (i < len) {
        if (sql.charAt(i) === '"') {
          if (sql.charAt(i + 1) === '"') { i += 2; continue; }
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
    if (ch === "'") {
      throw mkErr(where);
    }
    i += 1;
  }
}

module.exports = {
  assertNoRawStringLiteral: assertNoRawStringLiteral,
  validateIdentifier:  validateIdentifier,
  assertSingleStatement: assertSingleStatement,
  quoteIdentifier:     quoteIdentifier,
  quoteQualified:      quoteQualified,
  quoteList:           quoteList,
  assertOneOf:         assertOneOf,
  countPlaceholders:   countPlaceholders,
  toPositional:        toPositional,
  normalizeForScan:    normalizeForScan,
  SafeSqlError:        SafeSqlError,
  // Exposed so consumers can compose their own validators
  DEFAULT_IDENTIFIER_RE: DEFAULT_IDENTIFIER_RE,
  MAX_IDENTIFIER_LENGTH: MAX_IDENTIFIER_LENGTH,
};

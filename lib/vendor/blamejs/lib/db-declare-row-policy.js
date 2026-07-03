// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.db.declareRowPolicy — declarative Postgres ROW LEVEL SECURITY policy
 * migration spec.
 *
 * Returns a migration-shape object that b.externalDb.migrate(...) applies
 * against a Postgres backend. Generates:
 *
 *   ALTER TABLE <schema>.<table> ENABLE ROW LEVEL SECURITY;     -- idempotent
 *   CREATE POLICY <name> ON <schema>.<table>
 *     [AS PERMISSIVE | RESTRICTIVE]
 *     FOR <command>
 *     [TO <role>]
 *     USING (<expr>)
 *     [WITH CHECK (<expr>)];
 *
 * Pairs with b.externalDb.transaction({ sessionGucs: { 'app.tenant_id': uuid } })
 * for the per-request `SET LOCAL` plumbing. The recommended tenant-per-row
 * shape:
 *
 *   b.db.declareRowPolicy({
 *     schema:    "public",
 *     table:     "sessions",
 *     name:      "tenant_isolation",
 *     role:      "app_user",
 *     using:     "tenant_id = current_setting('app.tenant_id')::uuid",
 *     withCheck: "tenant_id = current_setting('app.tenant_id')::uuid",
 *     command:   "ALL",
 *   });
 *
 *   await b.externalDb.transaction(async function (tx) {
 *     return await tx.query("SELECT * FROM sessions WHERE _id = $1", [sid]);
 *   }, { sessionGucs: { "app.tenant_id": req.user.tenantId } });
 *
 * Postgres-only: SQLite + MySQL have no equivalent grammar. Apply throws
 * NOT_SUPPORTED at migration-apply time when the targeted backend's
 * dialect isn't "postgres".
 *
 * Validation at declareRowPolicy() call time — bad shape throws here, not
 * at apply time:
 *   - schema, table, name, role → safeSql.validateIdentifier
 *   - command ∈ {ALL, SELECT, INSERT, UPDATE, DELETE}
 *   - permissive boolean
 *   - using / withCheck operator-supplied SQL strings; semicolons rejected
 *
 * Audit metadata emitted on apply:
 *   {
 *     policy:    "schema.table.name",
 *     table:     "schema.table",
 *     role:      "...",
 *     command:   "ALL"|...,
 *     permissive: true|false,
 *     hasWithCheck: bool,
 *   }
 */
var safeSql = require("./safe-sql");
var sql = require("./sql");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var DeclareRowPolicyError = defineClass("DeclareRowPolicyError", { alwaysPermanent: true });

var ALLOWED_OPTS = [
  "schema", "table", "name", "role",
  "using", "withCheck", "command", "permissive", "backend",
];

// allow:hand-rolled-sql — RLS FOR-<command> keyword allowlist, not SQL text;
// the policy itself is composed through b.sql.createPolicy.
var ALLOWED_COMMANDS = ["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"];

function _err(code, message) {
  return new DeclareRowPolicyError(code, message);
}

// _isRlsEnabled — fail-closed coercion of pg_class.relrowsecurity. Native pg
// drivers return a JS boolean; a proxy / ORM / non-native driver may return
// "t"/"f", "true"/"false", or 1/0. RLS counts as enabled ONLY on a value that
// unambiguously means true; every other shape (including the truthy string
// "f") reads as not-enabled, so ENABLE is (re-)issued rather than silently
// skipped — a skipped ENABLE would leave the table's rows unprotected.
function _isRlsEnabled(v) {
  if (v === true || v === 1) return true;
  if (typeof v === "string") return /^(t|true|1|on|yes)$/i.test(v.trim());
  return false;
}

function _validateIdent(where, value) {
  try {
    safeSql.validateIdentifier(value, { allowReserved: true });
  } catch (e) {
    throw _err("declare-row-policy/bad-identifier",
      where + ": invalid identifier '" + value + "': " + ((e && e.message) || String(e)));
  }
}

function _validateExpression(where, value) {
  if (typeof value !== "string") {
    throw _err("declare-row-policy/bad-type", where + " must be a string");
  }
  if (value.length === 0) {
    throw _err("declare-row-policy/empty-expression", where + " must be a non-empty boolean expression");
  }
  if (value.indexOf(";") !== -1) {
    throw _err("declare-row-policy/bad-expression",
      where + " must not contain ';' — use a single boolean expression");
  }
  return value;
}

function _validateOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("declare-row-policy/bad-opts", "declareRowPolicy requires an opts object");
  }
  for (var k in opts) {
    if (Object.prototype.hasOwnProperty.call(opts, k) && ALLOWED_OPTS.indexOf(k) === -1) {
      throw _err("declare-row-policy/unknown-opt",
        "unknown opt '" + k + "'. Allowed: " + ALLOWED_OPTS.join(", "));
    }
  }

  validateOpts.requireNonEmptyString(opts.schema, "schema", DeclareRowPolicyError, "declare-row-policy/missing-opt");
  _validateIdent("schema", opts.schema);

  validateOpts.requireNonEmptyString(opts.table, "table", DeclareRowPolicyError, "declare-row-policy/missing-opt");
  _validateIdent("table", opts.table);

  validateOpts.requireNonEmptyString(opts.name, "name", DeclareRowPolicyError, "declare-row-policy/missing-opt");
  _validateIdent("name", opts.name);

  var role = null;
  if (opts.role !== undefined && opts.role !== null) {
    if (typeof opts.role !== "string" || opts.role.length === 0) {
      throw _err("declare-row-policy/bad-type", "role must be a non-empty string");
    }
    _validateIdent("role", opts.role);
    role = opts.role;
  }

  if (opts.using === undefined || opts.using === null) {
    throw _err("declare-row-policy/missing-opt", "using is required (USING expression)");
  }
  var using = _validateExpression("using", opts.using);

  var withCheck = null;
  if (opts.withCheck !== undefined && opts.withCheck !== null) {
    withCheck = _validateExpression("withCheck", opts.withCheck);
  }

  var command = "ALL";
  if (opts.command !== undefined && opts.command !== null) {
    if (typeof opts.command !== "string") {
      throw _err("declare-row-policy/bad-type", "command must be a string");
    }
    var upper = opts.command.toUpperCase();
    if (ALLOWED_COMMANDS.indexOf(upper) === -1) {
      throw _err("declare-row-policy/bad-command",
        "command must be one of " + ALLOWED_COMMANDS.join(", ") + ", got '" + opts.command + "'");
    }
    command = upper;
  }

  var permissive = true;
  if (opts.permissive !== undefined && opts.permissive !== null) {
    if (typeof opts.permissive !== "boolean") {
      throw _err("declare-row-policy/bad-type", "permissive must be a boolean");
    }
    permissive = opts.permissive;
  }

  if (opts.backend !== undefined && opts.backend !== null) {
    if (typeof opts.backend !== "string" || opts.backend.length === 0) {
      throw _err("declare-row-policy/bad-type", "backend must be a non-empty string");
    }
  }

  return {
    schema:     opts.schema,
    table:      opts.table,
    name:       opts.name,
    role:       role,
    using:      using,
    withCheck:  withCheck,
    command:    command,
    permissive: permissive,
    backend:    opts.backend || null,
  };
}

function _ensureBackendIsPostgres(externalDb, backendName) {
  var list = externalDb.listBackends();
  var found = null;
  for (var i = 0; i < list.length; i++) {
    if (list[i].name === backendName) { found = list[i]; break; }
  }
  if (!found) {
    throw _err("declare-row-policy/unknown-backend",
      "no externalDb backend named '" + backendName + "' — declared backends: " +
      list.map(function (b) { return b.name; }).join(", "));
  }
  if (found.dialect !== "postgres") {
    throw _err("declare-row-policy/not-supported",
      "declareRowPolicy is Postgres-only; backend '" + backendName + "' has dialect='" +
      found.dialect + "'. Write the policy as a hand-rolled migration for this dialect.");
  }
}

function declareRowPolicy(opts) {
  var spec = _validateOpts(opts);
  // The dotted "schema.table" form b.sql's RLS builders accept (each
  // segment validated + quoted by construction inside b.sql).
  var tableRef = spec.schema + "." + spec.table;

  var description = "declareRowPolicy " + spec.schema + "." + spec.table + "." + spec.name;

  async function up(xdb, ctx) {
    if (ctx && ctx.externalDb && ctx.backendName) {
      _ensureBackendIsPostgres(ctx.externalDb, ctx.backendName);
    }

    // Idempotent ENABLE — Postgres has no IF NOT EXISTS for this. Read
    // the current setting from pg_class and skip the ALTER when already
    // on, so re-running a migration set in a partially-applied state
    // doesn't fail with a no-op error from the lock acquisition. The
    // pg_class / pg_namespace catalog join is composed through b.sql with
    // a guarded raw join (system-catalog columns are outside any operator
    // schema, so a column gate has no set to check); the schema + table
    // names bind as parameters, never interpolate.
    var rlsQuery = sql.select("pg_class", { dialect: "postgres", alias: "c" })
      .columns(["c.relrowsecurity"])
      .joinRaw("JOIN pg_namespace n ON n.oid = c.relnamespace")
      .whereRaw("n.nspname = ?", [spec.schema])
      .whereRaw("c.relname = ?", [spec.table])
      .toExternalSql("postgres");
    var rlsCheck = await xdb.query(rlsQuery.sql, rlsQuery.params);
    var rows = (rlsCheck && rlsCheck.rows) || [];
    if (rows.length === 0) {
      throw _err("declare-row-policy/table-not-found",
        "source table '" + spec.schema + "." + spec.table +
        "' not found (does it exist? does the migration role have visibility?)");
    }
    // relrowsecurity is a Postgres boolean. Native pg drivers return true/false,
    // but a proxy / ORM / non-native driver may hand back "t"/"f", "true"/"false",
    // or 1/0. The string "f" is TRUTHY, so a bare `!rows[0].relrowsecurity` would
    // read "f" as "already enabled" and silently SKIP ENABLE — leaving the table's
    // rows unprotected while the migration reports success. Treat RLS as enabled
    // ONLY on a value that unambiguously means true; anything else fails closed and
    // (re-)issues ENABLE, which is a harmless no-op on an already-enabled table.
    if (!_isRlsEnabled(rows[0].relrowsecurity)) {
      var enableStmt = sql.enableRowLevelSecurity(tableRef, { dialect: "postgres" });
      await xdb.query(enableStmt.sql, enableStmt.params);
    }

    // CREATE POLICY assembled in canonical order by b.sql.createPolicy:
    // name → table → AS PERMISSIVE/RESTRICTIVE → FOR command → TO role →
    // USING → WITH CHECK. The using / withCheck boolean predicates ride
    // b.sql's guarded raw-fragment path (the same b.guardSql gate the
    // operator-facing whereRaw uses).
    var policyStmt = sql.createPolicy(spec.name, tableRef, {
      command:    spec.command,
      permissive: spec.permissive,
      role:       spec.role || undefined,
      using:      spec.using,
      withCheck:  spec.withCheck || undefined,
    }, { dialect: "postgres" });
    await xdb.query(policyStmt.sql, policyStmt.params);

    return {
      policy:       spec.schema + "." + spec.table + "." + spec.name,
      table:        spec.schema + "." + spec.table,
      role:         spec.role,
      command:      spec.command,
      permissive:   spec.permissive,
      hasWithCheck: !!spec.withCheck,
    };
  }

  async function down(xdb, ctx) {
    if (ctx && ctx.externalDb && ctx.backendName) {
      _ensureBackendIsPostgres(ctx.externalDb, ctx.backendName);
    }
    var dropStmt = sql.dropPolicy(spec.name, tableRef, { dialect: "postgres", ifExists: true });
    await xdb.query(dropStmt.sql, dropStmt.params);
  }

  return {
    description: description,
    target:      "externalDb",
    backend:     spec.backend,
    up:          up,
    down:        down,
    _spec:       spec,
  };
}

module.exports = {
  declareRowPolicy:        declareRowPolicy,
  DeclareRowPolicyError:   DeclareRowPolicyError,
};

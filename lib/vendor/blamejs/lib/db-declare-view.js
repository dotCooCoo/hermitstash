// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.db.declareView — declarative view + GRANT migration spec.
 *
 * Returns a migration-shape object that b.externalDb.migrate(...) applies
 * against a Postgres backend. The view exposes a deliberately-narrowed
 * column projection of the source table — sensitive columns are dropped
 * (redactColumns), sealed columns are auto-omitted (operator declares
 * via sealedColumns; a future externalDb sealed-fields registry will
 * make this automatic), and existing derived hash columns can be
 * exposed in place of their plaintext source via hashColumns.
 *
 * Postgres-only: SQLite has no GRANT semantics; MySQL's CREATE VIEW
 * grammar differs and isn't covered. Apply throws NOT_SUPPORTED at
 * migration-apply time when the targeted backend's dialect isn't
 * "postgres" so operators see the failure cause clearly.
 *
 * Public API (b.db.declareView):
 *
 *   var mig = b.db.declareView({
 *     schema:         "analytics",          // target schema
 *     name:           "sessions",           // view name
 *     source:         "public.sessions",    // schema.table OR ["public","sessions"]
 *     redactColumns:  ["ssn", "diagnosis"], // dropped from view
 *     sealedColumns:  ["secrets_jsonb"],    // operator-declared sealed cols (auto-omit)
 *     hashColumns:    { emailHash: "email" },// hide source plaintext, keep hash
 *     whereClause:    "deleted_at IS NULL", // optional filter
 *     grantTo:        ["analytics_user"],   // roles that get SELECT
 *     backend:        "main",               // optional — defaults to default backend
 *   });
 *
 *   // mig is a migration-shape object: { description, target, backend, up, down }
 *   // Place it in a migration file:
 *   //   module.exports = mig;
 *   // and run b.externalDb.migrate.create({ dir }).up();
 *
 * Validation runs at migration apply (not declare) time so source-column
 * existence and role existence checks query the live database. Operator
 * typos surface as clear errors at the migrate command, not as silent
 * empty views or grant-to-nonexistent-role footguns.
 *
 * Throw at declareView() call time on:
 *   - schema, name, source segments → safeSql.validateIdentifier
 *   - column names in redactColumns / sealedColumns / hashColumns →
 *     safeSql.validateIdentifier
 *   - role names in grantTo → safeSql.validateIdentifier
 *   - whereClause stays operator-supplied SQL (the framework cannot
 *     validate arbitrary expressions); it interpolates as-is into the
 *     migration text. Operators wrap any literal values inside
 *     whereClause via standard SQL quoting.
 *
 * Audit metadata emitted on apply:
 *   {
 *     view:                "schema.name",
 *     source:              "schema.table",
 *     selectedColumns:     [string],
 *     redactedColumns:     [string],   // intersection of redactColumns & source
 *     autoExcludedSealed:  [string],   // sealedColumns members found in source
 *     hashedColumns:       { aliasOrHashCol: srcCol },
 *     grantedTo:           [string],
 *   }
 */
var safeSql = require("./safe-sql");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var DeclareViewError = defineClass("DeclareViewError", { alwaysPermanent: true });

var ALLOWED_OPTS = [
  "schema", "name", "source",
  "redactColumns", "sealedColumns", "hashColumns",
  "whereClause", "grantTo", "backend",
];

function _err(code, message) {
  return new DeclareViewError(code, message);
}

function _validateIdent(where, value) {
  try {
    safeSql.validateIdentifier(value, { allowReserved: true });
  } catch (e) {
    throw _err("declare-view/bad-identifier",
      where + ": invalid identifier '" + value + "': " + ((e && e.message) || String(e)));
  }
}

function _validateStringArray(where, arr, optional) {
  if (arr === undefined || arr === null) {
    if (optional) return [];
    throw _err("declare-view/missing-opt", where + " is required");
  }
  if (!Array.isArray(arr)) {
    throw _err("declare-view/bad-type", where + " must be an array of strings");
  }
  for (var i = 0; i < arr.length; i++) {
    if (typeof arr[i] !== "string" || arr[i].length === 0) {
      throw _err("declare-view/bad-entry",
        where + "[" + i + "] must be a non-empty string");
    }
  }
  return arr.slice();
}

function _parseSource(source) {
  // Accepts "schema.table" or ["schema", "table"] or "table" (defaults to public).
  var parts;
  if (typeof source === "string") {
    if (source.length === 0) {
      throw _err("declare-view/bad-source", "source must be a non-empty string or array");
    }
    parts = source.split(".");
  } else if (Array.isArray(source)) {
    parts = source.slice();
  } else {
    throw _err("declare-view/bad-source",
      "source must be a string ('schema.table') or array (['schema','table']), got " + typeof source);
  }
  if (parts.length === 1) parts = ["public", parts[0]];
  if (parts.length !== 2) {
    throw _err("declare-view/bad-source",
      "source must resolve to two segments [schema, table]; got " + parts.length + " segment(s)");
  }
  for (var i = 0; i < parts.length; i++) _validateIdent("source[" + i + "]", parts[i]);
  return { schema: parts[0], name: parts[1] };
}

function _validateOpts(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("declare-view/bad-opts", "declareView requires an opts object");
  }
  for (var k in opts) {
    if (Object.prototype.hasOwnProperty.call(opts, k) && ALLOWED_OPTS.indexOf(k) === -1) {
      throw _err("declare-view/unknown-opt",
        "unknown opt '" + k + "'. Allowed: " + ALLOWED_OPTS.join(", "));
    }
  }

  validateOpts.requireNonEmptyString(opts.schema, "schema", DeclareViewError, "declare-view/missing-opt");
  _validateIdent("schema", opts.schema);

  validateOpts.requireNonEmptyString(opts.name, "name", DeclareViewError, "declare-view/missing-opt");
  _validateIdent("name", opts.name);

  if (opts.source === undefined) {
    throw _err("declare-view/missing-opt", "source is required");
  }
  var src = _parseSource(opts.source);

  var redactColumns = _validateStringArray("redactColumns", opts.redactColumns, true);
  for (var i = 0; i < redactColumns.length; i++) {
    _validateIdent("redactColumns[" + i + "]", redactColumns[i]);
  }

  var sealedColumns = _validateStringArray("sealedColumns", opts.sealedColumns, true);
  for (var j = 0; j < sealedColumns.length; j++) {
    _validateIdent("sealedColumns[" + j + "]", sealedColumns[j]);
  }

  var hashColumns = {};
  validateOpts.optionalPlainObject(opts.hashColumns, "hashColumns",
    DeclareViewError, "declare-view/bad-type",
    "must be an object { aliasOrHashCol: srcCol }");
  if (opts.hashColumns !== undefined && opts.hashColumns !== null) {
    for (var hc in opts.hashColumns) {
      if (!Object.prototype.hasOwnProperty.call(opts.hashColumns, hc)) continue;
      _validateIdent("hashColumns key '" + hc + "'", hc);
      var v = opts.hashColumns[hc];
      if (typeof v !== "string" || v.length === 0) {
        throw _err("declare-view/bad-entry",
          "hashColumns['" + hc + "'] must be a non-empty string (the source plaintext column)");
      }
      _validateIdent("hashColumns['" + hc + "']", v);
      hashColumns[hc] = v;
    }
  }

  var whereClause = null;
  if (opts.whereClause !== undefined && opts.whereClause !== null) {
    if (typeof opts.whereClause !== "string") {
      throw _err("declare-view/bad-type", "whereClause must be a string");
    }
    if (opts.whereClause.indexOf(";") !== -1) {
      throw _err("declare-view/bad-where",
        "whereClause must not contain ';' — use a single boolean expression");
    }
    whereClause = opts.whereClause;
  }

  var grantTo = _validateStringArray("grantTo", opts.grantTo, true);
  for (var g = 0; g < grantTo.length; g++) {
    _validateIdent("grantTo[" + g + "]", grantTo[g]);
  }

  if (opts.backend !== undefined && opts.backend !== null) {
    if (typeof opts.backend !== "string" || opts.backend.length === 0) {
      throw _err("declare-view/bad-type", "backend must be a non-empty string");
    }
  }

  return {
    schema:         opts.schema,
    name:           opts.name,
    source:         src,
    redactColumns:  redactColumns,
    sealedColumns:  sealedColumns,
    hashColumns:    hashColumns,
    whereClause:    whereClause,
    grantTo:        grantTo,
    backend:        opts.backend || null,
  };
}

// ---- Apply-time helpers (run inside up()) ----

async function _fetchSourceColumns(xdb, schema, table) {
  var res = await xdb.query(
    "SELECT column_name FROM information_schema.columns " +
    "WHERE table_schema = $1 AND table_name = $2 " +
    "ORDER BY ordinal_position ASC",
    [schema, table]
  );
  var rows = (res && res.rows) || [];
  return rows.map(function (r) { return r.column_name; });
}

async function _fetchExistingRoles(xdb, names) {
  if (names.length === 0) return new Set();
  var placeholders = names.map(function (_, i) { return "$" + (i + 1); }).join(", ");
  var res = await xdb.query(
    "SELECT rolname FROM pg_roles WHERE rolname IN (" + placeholders + ")",
    names
  );
  var rows = (res && res.rows) || [];
  return new Set(rows.map(function (r) { return r.rolname; }));
}

function _missing(required, available) {
  var miss = [];
  for (var i = 0; i < required.length; i++) {
    if (available.indexOf(required[i]) === -1) miss.push(required[i]);
  }
  return miss;
}

function _buildSelectColumnList(sourceCols, spec) {
  // Drop set: redactColumns ∩ source, sealedColumns ∩ source, hashColumns.values ∩ source.
  var dropSet = Object.create(null);
  for (var i = 0; i < spec.redactColumns.length; i++) dropSet[spec.redactColumns[i]] = true;
  for (var j = 0; j < spec.sealedColumns.length; j++) dropSet[spec.sealedColumns[j]] = true;
  for (var hc in spec.hashColumns) dropSet[spec.hashColumns[hc]] = true;

  var kept = [];
  for (var k = 0; k < sourceCols.length; k++) {
    if (!dropSet[sourceCols[k]]) kept.push(sourceCols[k]);
  }
  return kept;
}

function _intersectInSource(list, sourceCols) {
  var srcSet = Object.create(null);
  for (var i = 0; i < sourceCols.length; i++) srcSet[sourceCols[i]] = true;
  var out = [];
  for (var j = 0; j < list.length; j++) {
    if (srcSet[list[j]]) out.push(list[j]);
  }
  return out;
}

function _ensureBackendIsPostgres(externalDb, backendName) {
  // externalDb.listBackends() returns { name, dialect, ... } per backend.
  var list = externalDb.listBackends();
  var found = null;
  for (var i = 0; i < list.length; i++) {
    if (list[i].name === backendName) { found = list[i]; break; }
  }
  if (!found) {
    throw _err("declare-view/unknown-backend",
      "no externalDb backend named '" + backendName + "' — declared backends: " +
      list.map(function (b) { return b.name; }).join(", "));
  }
  if (found.dialect !== "postgres") {
    throw _err("declare-view/not-supported",
      "declareView is Postgres-only; backend '" + backendName + "' has dialect='" +
      found.dialect + "'. Write the view as a hand-rolled migration for this dialect.");
  }
}

// ---- The factory ----

function declareView(opts) {
  var spec = _validateOpts(opts);

  // The migration shape consumed by b.externalDb.migrate. The runner
  // resolves the backend at apply time (operator may set spec.backend
  // explicitly OR rely on the migrate runner's default backend).
  var description = "declareView " + spec.schema + "." + spec.name;
  var qView   = safeSql.quoteQualified([spec.schema, spec.name], "postgres");
  var qSource = safeSql.quoteQualified([spec.source.schema, spec.source.name], "postgres");

  async function up(xdb, ctx) {
    // Boundary throw: confirm we're on Postgres before any DDL leaves the process.
    if (ctx && ctx.externalDb && ctx.backendName) {
      _ensureBackendIsPostgres(ctx.externalDb, ctx.backendName);
    }

    // Live validation — source columns + roles must exist.
    var sourceCols = await _fetchSourceColumns(xdb, spec.source.schema, spec.source.name);
    if (sourceCols.length === 0) {
      throw _err("declare-view/source-not-found",
        "source table '" + spec.source.schema + "." + spec.source.name +
        "' has no columns visible (does it exist? does the migration role have SELECT on information_schema.columns?)");
    }

    var missingRedact = _missing(spec.redactColumns, sourceCols);
    if (missingRedact.length > 0) {
      throw _err("declare-view/redact-not-in-source",
        "redactColumns [" + missingRedact.join(", ") + "] not present on source '" +
        spec.source.schema + "." + spec.source.name + "'");
    }

    var missingHashKeys = _missing(Object.keys(spec.hashColumns), sourceCols);
    if (missingHashKeys.length > 0) {
      throw _err("declare-view/hash-key-not-in-source",
        "hashColumns keys [" + missingHashKeys.join(", ") + "] not present on source '" +
        spec.source.schema + "." + spec.source.name +
        "' — declare them as derivedHashes on the source schema first");
    }

    var missingHashSrc = _missing(_objValues(spec.hashColumns), sourceCols);
    if (missingHashSrc.length > 0) {
      throw _err("declare-view/hash-source-not-in-source",
        "hashColumns values [" + missingHashSrc.join(", ") + "] not present on source '" +
        spec.source.schema + "." + spec.source.name + "'");
    }

    if (spec.grantTo.length > 0) {
      var existing = await _fetchExistingRoles(xdb, spec.grantTo);
      var missingRoles = [];
      for (var i = 0; i < spec.grantTo.length; i++) {
        if (!existing.has(spec.grantTo[i])) missingRoles.push(spec.grantTo[i]);
      }
      if (missingRoles.length > 0) {
        throw _err("declare-view/role-not-found",
          "grantTo roles [" + missingRoles.join(", ") +
          "] not present in pg_roles — CREATE ROLE them in an earlier migration");
      }
    }

    var selectedColumns = _buildSelectColumnList(sourceCols, spec);
    if (selectedColumns.length === 0) {
      throw _err("declare-view/empty-select",
        "view '" + spec.schema + "." + spec.name +
        "' would have zero columns after redact/sealed/hash exclusions — adjust the spec");
    }

    // Build CREATE VIEW. Each column is independently quoted so a
    // reserved-word column name (e.g. "user", "order") resolves correctly.
    var quotedCols = selectedColumns.map(function (c) {
      return safeSql.quoteIdentifier(c, "postgres");
    }).join(", ");
    var createSql = "CREATE VIEW " + qView + " AS SELECT " + quotedCols +
                    " FROM " + qSource;
    if (spec.whereClause) createSql += " WHERE " + spec.whereClause;

    await xdb.query(createSql, []);

    // GRANT SELECT — one statement covers all roles.
    if (spec.grantTo.length > 0) {
      var quotedRoles = spec.grantTo.map(function (r) {
        return safeSql.quoteIdentifier(r, "postgres");
      }).join(", ");
      await xdb.query(
        "GRANT SELECT ON " + qView + " TO " + quotedRoles,
        []
      );
    }

    return {
      view:                spec.schema + "." + spec.name,
      source:              spec.source.schema + "." + spec.source.name,
      selectedColumns:     selectedColumns,
      redactedColumns:     _intersectInSource(spec.redactColumns, sourceCols),
      autoExcludedSealed:  _intersectInSource(spec.sealedColumns, sourceCols),
      hashedColumns:       Object.assign({}, spec.hashColumns),
      grantedTo:           spec.grantTo.slice(),
    };
  }

  async function down(xdb, ctx) {
    if (ctx && ctx.externalDb && ctx.backendName) {
      _ensureBackendIsPostgres(ctx.externalDb, ctx.backendName);
    }
    await xdb.query("DROP VIEW IF EXISTS " + qView, []);
  }

  return {
    description: description,
    target:      "externalDb",
    backend:     spec.backend,
    up:          up,
    down:        down,
    // Expose the validated spec for testability — declareView callers
    // can introspect what the migration will emit without running it.
    _spec:       spec,
  };
}

function _objValues(obj) {
  var out = [];
  for (var k in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) out.push(obj[k]);
  }
  return out;
}

module.exports = {
  declareView:        declareView,
  DeclareViewError:   DeclareViewError,
};

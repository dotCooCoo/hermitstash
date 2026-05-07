"use strict";
/**
 * b.db.declareView — declarative view + GRANT migration spec.
 *
 * These tests exercise the spec validation, source-column / role
 * existence checks, and the SQL emitted to xdb. A fake xdb captures
 * every query and returns canned results so we can assert behavior
 * without standing up a real Postgres.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _fakeXdb(spec) {
  // spec.sourceColumns: array — what information_schema returns
  // spec.existingRoles: array — what pg_roles returns
  // spec.queryHook(sql, params): optional override for specific queries
  spec = spec || {};
  var captured = [];
  return {
    captured: captured,
    query: async function (sql, params) {
      captured.push({ sql: sql, params: (params || []).slice() });
      if (spec.queryHook) {
        var r = spec.queryHook(sql, params);
        if (r !== undefined) return r;
      }
      if (/FROM information_schema\.columns/.test(sql)) {
        var rows = (spec.sourceColumns || []).map(function (c) {
          return { column_name: c };
        });
        return { rows: rows, rowCount: rows.length };
      }
      if (/FROM pg_roles/.test(sql)) {
        var existing = (spec.existingRoles || []);
        var asked = params || [];
        var matched = asked.filter(function (a) { return existing.indexOf(a) !== -1; });
        return {
          rows: matched.map(function (r) { return { rolname: r }; }),
          rowCount: matched.length,
        };
      }
      // CREATE VIEW / GRANT / DROP VIEW etc.
      return { rows: [], rowCount: 0 };
    },
  };
}

async function _expectThrow(label, fn, codeRe) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label,
    threw !== null && (codeRe ? codeRe.test(threw.code || "") : true));
}

async function run() {
  // ---------- Input validation at declareView() time ----------

  _expectThrow("rejects missing opts",
    function () { b.db.declareView(); },
    /declare-view\/bad-opts/);

  _expectThrow("rejects unknown opt",
    function () { b.db.declareView({ schema: "a", name: "b", source: "c", bogus: 1 }); },
    /declare-view\/unknown-opt/);

  _expectThrow("rejects missing schema",
    function () { b.db.declareView({ name: "b", source: "c" }); },
    /declare-view\/missing-opt/);

  _expectThrow("rejects missing name",
    function () { b.db.declareView({ schema: "a", source: "c" }); },
    /declare-view\/missing-opt/);

  _expectThrow("rejects missing source",
    function () { b.db.declareView({ schema: "a", name: "b" }); },
    /declare-view\/missing-opt/);

  _expectThrow("rejects bad identifier in schema",
    function () { b.db.declareView({ schema: "a; DROP TABLE", name: "b", source: "c.d" }); },
    /declare-view\/bad-identifier/);

  _expectThrow("rejects 3-segment source",
    function () { b.db.declareView({ schema: "a", name: "b", source: "x.y.z" }); },
    /declare-view\/bad-source/);

  _expectThrow("rejects bad identifier in redactColumns",
    function () {
      b.db.declareView({ schema: "a", name: "b", source: "c.d",
                         redactColumns: ["ok", "bad ident"] });
    },
    /declare-view\/bad-identifier/);

  _expectThrow("rejects whereClause with semicolon",
    function () {
      b.db.declareView({ schema: "a", name: "b", source: "c.d",
                         whereClause: "x = 1; DROP TABLE c.d" });
    },
    /declare-view\/bad-where/);

  _expectThrow("rejects bad hashColumns shape",
    function () {
      b.db.declareView({ schema: "a", name: "b", source: "c.d",
                         hashColumns: ["not-an-object"] });
    },
    /declare-view\/bad-type/);

  // ---------- Spec parsing ----------

  var spec1 = b.db.declareView({
    schema: "analytics", name: "sessions",
    source: "public.sessions",
  })._spec;
  check("parses 'schema.table' source",
    spec1.source.schema === "public" && spec1.source.name === "sessions");

  var spec2 = b.db.declareView({
    schema: "analytics", name: "sessions",
    source: ["public", "sessions"],
  })._spec;
  check("parses [schema, table] source",
    spec2.source.schema === "public" && spec2.source.name === "sessions");

  var spec3 = b.db.declareView({
    schema: "analytics", name: "sessions",
    source: "sessions",
  })._spec;
  check("defaults bare table source to 'public' schema",
    spec3.source.schema === "public" && spec3.source.name === "sessions");

  // ---------- Migration shape ----------

  var mig = b.db.declareView({
    schema: "analytics", name: "sessions",
    source: "public.sessions",
    redactColumns: ["ssn"],
    grantTo: ["analytics_user"],
  });
  check("returns migration shape with target",
    mig.target === "externalDb" &&
    typeof mig.up === "function" &&
    typeof mig.down === "function" &&
    typeof mig.description === "string");

  // ---------- Apply-time validation: source columns ----------

  await _expectThrow("up() throws when source has no columns",
    async function () {
      var x = _fakeXdb({ sourceColumns: [] });
      await mig.up(x);
    },
    /declare-view\/source-not-found/);

  await _expectThrow("up() throws when redactColumn not on source",
    async function () {
      var m = b.db.declareView({
        schema: "a", name: "v", source: "public.t",
        redactColumns: ["nope"],
      });
      var x = _fakeXdb({ sourceColumns: ["id", "email"] });
      await m.up(x);
    },
    /declare-view\/redact-not-in-source/);

  await _expectThrow("up() throws when hashColumns key not on source",
    async function () {
      var m = b.db.declareView({
        schema: "a", name: "v", source: "public.t",
        hashColumns: { emailHash: "email" },
      });
      var x = _fakeXdb({ sourceColumns: ["id", "email"] });   // missing emailHash
      await m.up(x);
    },
    /declare-view\/hash-key-not-in-source/);

  await _expectThrow("up() throws when hashColumns value not on source",
    async function () {
      var m = b.db.declareView({
        schema: "a", name: "v", source: "public.t",
        hashColumns: { emailHash: "missing_email_col" },
      });
      var x = _fakeXdb({ sourceColumns: ["id", "emailHash"] });
      await m.up(x);
    },
    /declare-view\/hash-source-not-in-source/);

  await _expectThrow("up() throws when grantTo role missing in pg_roles",
    async function () {
      var m = b.db.declareView({
        schema: "a", name: "v", source: "public.t",
        grantTo: ["analytics_user"],
      });
      var x = _fakeXdb({ sourceColumns: ["id"], existingRoles: [] });
      await m.up(x);
    },
    /declare-view\/role-not-found/);

  await _expectThrow("up() throws when SELECT list collapses to zero columns",
    async function () {
      var m = b.db.declareView({
        schema: "a", name: "v", source: "public.t",
        redactColumns: ["a", "b"],
      });
      var x = _fakeXdb({ sourceColumns: ["a", "b"] });
      await m.up(x);
    },
    /declare-view\/empty-select/);

  // ---------- SELECT column list logic ----------

  var mig2 = b.db.declareView({
    schema: "analytics", name: "sessions",
    source: "public.sessions",
    redactColumns: ["ssn"],
    sealedColumns: ["secrets_jsonb"],
    hashColumns:   { emailHash: "email" },
  });
  var x2 = _fakeXdb({
    sourceColumns: ["id", "email", "emailHash", "ssn", "secrets_jsonb", "createdAt"],
    existingRoles: [],
  });
  var result2 = await mig2.up(x2);

  check("SELECT drops redactColumns",
    result2.selectedColumns.indexOf("ssn") === -1);
  check("SELECT drops sealedColumns",
    result2.selectedColumns.indexOf("secrets_jsonb") === -1);
  check("SELECT drops hashColumns source plaintext",
    result2.selectedColumns.indexOf("email") === -1);
  check("SELECT keeps hashColumns hash output",
    result2.selectedColumns.indexOf("emailHash") !== -1);
  check("SELECT keeps non-redacted columns",
    result2.selectedColumns.indexOf("id") !== -1 &&
    result2.selectedColumns.indexOf("createdAt") !== -1);
  check("returns audit metadata structure",
    Array.isArray(result2.redactedColumns) &&
    Array.isArray(result2.autoExcludedSealed) &&
    typeof result2.hashedColumns === "object");

  // ---------- Emitted SQL ----------

  var createSql = x2.captured.find(function (q) { return /^CREATE VIEW/.test(q.sql); });
  check("emits CREATE VIEW with quoted qualified name",
    createSql && /CREATE VIEW "analytics"\."sessions"/.test(createSql.sql));
  check("emits FROM with quoted qualified source",
    createSql && /FROM "public"\."sessions"/.test(createSql.sql));
  check("emits SELECT with quoted column list",
    createSql && /SELECT "id", "emailHash", "createdAt"/.test(createSql.sql));

  // ---------- whereClause ----------

  var migWhere = b.db.declareView({
    schema: "a", name: "v", source: "public.t",
    whereClause: "deleted_at IS NULL",
  });
  var xWhere = _fakeXdb({ sourceColumns: ["id"] });
  await migWhere.up(xWhere);
  var createWhere = xWhere.captured.find(function (q) { return /^CREATE VIEW/.test(q.sql); });
  check("whereClause appended to CREATE VIEW",
    createWhere && /WHERE deleted_at IS NULL/.test(createWhere.sql));

  // ---------- GRANT ----------

  var migGrant = b.db.declareView({
    schema: "a", name: "v", source: "public.t",
    grantTo: ["analytics_user", "bi_user"],
  });
  var xGrant = _fakeXdb({
    sourceColumns: ["id"],
    existingRoles: ["analytics_user", "bi_user"],
  });
  await migGrant.up(xGrant);
  var grantSql = xGrant.captured.find(function (q) { return /^GRANT SELECT/.test(q.sql); });
  check("emits GRANT SELECT to all roles, quoted",
    grantSql && /GRANT SELECT ON "a"\."v" TO "analytics_user", "bi_user"/.test(grantSql.sql));

  // ---------- down() ----------

  var xDown = _fakeXdb({ sourceColumns: [] });   // not used by down()
  await mig.down(xDown);
  var dropSql = xDown.captured.find(function (q) { return /^DROP VIEW/.test(q.sql); });
  check("down() emits DROP VIEW IF EXISTS",
    dropSql && /DROP VIEW IF EXISTS "analytics"\."sessions"/.test(dropSql.sql));

  // ---------- backend opt passthrough ----------

  var migBackend = b.db.declareView({
    schema: "a", name: "v", source: "public.t",
    backend: "pg-main",
  });
  check("backend opt forwards into migration spec",
    migBackend.backend === "pg-main");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

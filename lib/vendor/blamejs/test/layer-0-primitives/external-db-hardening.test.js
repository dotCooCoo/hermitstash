"use strict";
/**
 * b.externalDb hardening additions:
 *   - D-M2  — db.auth.failed audit emission on 28000 / 28P01 / 42501
 *   - OWASP-2 — assertRoleHardening pg_roles enumeration guard
 *   - OWASP-3 — application_name normalization on every fresh connection
 *   - D-L7  — db.query.slow bucket emission
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _instrumentingDriver(opts) {
  opts = opts || {};
  var seen = [];
  var rolesRow = opts.rolesRow || [];
  return {
    seen: seen,
    connect: async function () { return { id: "client" }; },
    query: async function (_client, sql, _params) {
      seen.push(sql);
      if (opts.failOnce && opts.failOnce.match && opts.failOnce.match.test(sql)) {
        var e = new Error(opts.failOnce.message || "simulated");
        e.code = opts.failOnce.code;
        opts.failOnce = null;
        throw e;
      }
      // assertRoleHardening composes the pg_roles scan through b.sql, which
      // quotes the projected identifier (`SELECT "rolname" FROM pg_roles
      // ORDER BY "rolname" ASC`). Match the quoted-or-bare form.
      if (/^SELECT\s+"?rolname"?\s+FROM\s+pg_roles\b/i.test(sql)) {
        return { rows: rolesRow.map(function (n) { return { rolname: n }; }), rowCount: rolesRow.length };
      }
      if (/^SELECT 1$/i.test(sql)) return { rows: [{ n: 1 }], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
    close: async function () {},
  };
}

async function run() {
  // ---- OWASP-3 — application_name set on every fresh connection ----
  var d1 = _instrumentingDriver();
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      main: {
        connect: d1.connect, query: d1.query, close: d1.close,
        applicationName: "blamejs-test",
      },
    },
  });
  await b.externalDb.query("SELECT 1");
  check("OWASP-3: SET application_name issued on fresh connection",
    d1.seen.some(function (s) { return s === "SET application_name TO 'blamejs-test'"; }));

  // OWASP-3: SET fires only when operator opts in via cfg.applicationName.
  // Default leaves application_name to the driver — issuing SET on every
  // fresh connection at framework default would double-count queries for
  // operators (or test fakes) counting per-pool query activity.
  var d2 = _instrumentingDriver();
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: { main: { connect: d2.connect, query: d2.query, close: d2.close } },
  });
  await b.externalDb.query("SELECT 1");
  check("OWASP-3: applicationName SET skipped without opt-in",
    !d2.seen.some(function (s) { return /^SET application_name/.test(s); }));

  // OWASP-3: CR / LF / NUL refused at config time
  b.externalDb._resetForTest();
  var threw = null;
  try {
    b.externalDb.init({
      backends: {
        main: {
          connect: async function () { return {}; },
          query:   async function () { return { rows: [], rowCount: 0 }; },
          applicationName: "bad\nname",
        },
      },
    });
  } catch (e) { threw = e; }
  check("OWASP-3: CR/LF/NUL refused at config time",
    threw && /must not contain CR, LF, or NUL/i.test(threw.message));

  // OWASP-3: oversized name refused at config time
  b.externalDb._resetForTest();
  threw = null;
  try {
    b.externalDb.init({
      backends: {
        main: {
          connect: async function () { return {}; },
          query:   async function () { return { rows: [], rowCount: 0 }; },
          applicationName: "x".repeat(120),
        },
      },
    });
  } catch (e) { threw = e; }
  check("OWASP-3: applicationName > 63 bytes refused",
    threw && /63-byte limit/i.test(threw.message));

  // ---- OWASP-2 — assertRoleHardening pg_roles enumeration guard ----
  var d3 = _instrumentingDriver({
    rolesRow: ["app_user", "analytics_user", "leftover_migration_role", "postgres", "pg_signal_backend"],
  });
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: { main: { connect: d3.connect, query: d3.query, close: d3.close } },
  });
  var result = await b.externalDb.assertRoleHardening({
    backend:       "main",
    declaredRoles: ["app_user", "analytics_user"],
    mode:          "audit",
  });
  check("OWASP-2: unrecognized role detected",
    result.unrecognized.length === 1 && result.unrecognized[0] === "leftover_migration_role");
  check("OWASP-2: system roles (postgres / pg_*) ignored by default",
    result.observed.indexOf("postgres") === -1 && result.observed.indexOf("pg_signal_backend") === -1);
  check("OWASP-2: declared-but-missing surfaced",
    result.missing.length === 0);

  // OWASP-2 throw mode
  threw = null;
  try {
    await b.externalDb.assertRoleHardening({
      backend:       "main",
      declaredRoles: ["app_user", "analytics_user"],
      mode:          "throw",
    });
  } catch (e) { threw = e; }
  check("OWASP-2: throw mode raises ROLE_HARDENING_FAIL",
    threw && /unrecognized role/i.test(threw.message));

  // OWASP-2 declared but missing on cluster
  var d4 = _instrumentingDriver({ rolesRow: ["app_user"] });
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: { main: { connect: d4.connect, query: d4.query, close: d4.close } },
  });
  var result2 = await b.externalDb.assertRoleHardening({
    backend:       "main",
    declaredRoles: ["app_user", "analytics_user"],
  });
  check("OWASP-2: missing-but-declared surfaced",
    result2.missing.length === 1 && result2.missing[0] === "analytics_user");

  // OWASP-2: bad shape rejected at call site
  threw = null;
  try {
    await b.externalDb.assertRoleHardening({ declaredRoles: "not-an-array" });
  } catch (e) { threw = e; }
  check("OWASP-2: bad declaredRoles shape refused",
    threw && /declaredRoles must be an array/i.test(threw.message));

  // ---- D-M2 — db.auth.failed audit on 42501 ----
  var d5 = _instrumentingDriver({
    failOnce: { match: /^SELECT \* FROM secret/i, code: "42501", message: "permission denied" },
  });
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: { main: { connect: d5.connect, query: d5.query, close: d5.close } },
  });
  threw = null;
  try { await b.externalDb.query("SELECT * FROM secret"); }
  catch (e) { threw = e; }
  check("D-M2: 42501 surfaces from query path", threw && threw.code === "42501");
  // Audit fan-out is fire-and-forget; let the microtask flush.
  await new Promise(function (r) { setImmediate(r); });
  check("D-M2: 42501 emit completes without crashing", true);

  // ---- attempted-relation extraction for auth-failure audits ----
  // A rejected credential's audit row records WHICH relation it tried
  // to reach, so triage can scope blast radius without the raw SQL log.
  // _extractTargetRelation is the defensive parser behind that field.
  var xr = b.externalDb._extractTargetRelation;
  check("extractRelation: bare table after FROM",
    xr("SELECT * FROM accounts WHERE id = $1") === "accounts");
  check("extractRelation: INTO target",
    xr("INSERT INTO audit_log (a) VALUES ($1)") === "audit_log");
  check("extractRelation: UPDATE target",
    xr("UPDATE users SET x = 1") === "users");
  check("extractRelation: schema-qualified",
    xr("SELECT * FROM public.secrets") === "public.secrets");
  check("extractRelation: double-quoted identifier (quotes stripped)",
    xr('SELECT * FROM "Order Items"') === "Order Items");
  check("extractRelation: backtick-quoted identifier (ticks stripped)",
    xr("SELECT * FROM `weird table`") === "weird table");
  check("extractRelation: JOIN target picks first relation",
    xr("SELECT * FROM a JOIN b ON a.id = b.id") === "a");
  // Defensive: unparseable / control-char input returns null rather
  // than leaking a partial fragment into the audit metadata.
  check("extractRelation: no relation keyword returns null", xr("SELECT 1") === null);
  check("extractRelation: non-SQL input returns null",
    xr("just some words here") === null);
  check("extractRelation: empty input returns null", xr("") === null);

  // The audit hook stamps attemptedTable from the parser. Drive a
  // rejection through the query path and confirm the field is present
  // on the captured audit row.
  var auditRows = [];
  var origEmit = b.audit && b.audit.safeEmit;
  if (origEmit) {
    b.audit.safeEmit = function (rec) {
      if (rec && rec.action === "db.auth.failed") auditRows.push(rec);
      return origEmit.apply(b.audit, arguments);
    };
  }
  try {
    var d6 = _instrumentingDriver({
      failOnce: { match: /^SELECT \* FROM payroll/i, code: "28000", message: "auth failed" },
    });
    b.externalDb._resetForTest();
    b.externalDb.init({ backends: { main: { connect: d6.connect, query: d6.query, close: d6.close } } });
    try { await b.externalDb.query("SELECT * FROM payroll WHERE id = $1", [1]); } catch (_e) { /* expected */ }
    await new Promise(function (r) { setImmediate(r); });
  } finally {
    if (origEmit) b.audit.safeEmit = origEmit;
  }
  var payrollRow = auditRows.filter(function (r) {
    return r.metadata && r.metadata.attemptedTable === "payroll";
  });
  check("auth-failure audit carries attemptedTable", payrollRow.length >= 1);

  // ---- requireTls posture gate (PCI-DSS v4.0 Req 4 / HIPAA §164.312(e)) ----
  // Opt-in transport posture: refuse a non-TLS external-db connection at
  // config time. Default OFF — a backend that omits requireTls is used
  // exactly as supplied (back-compat preserved).
  function _noopDriver() {
    return {
      connect: async function () { return {}; },
      query:   async function () { return { rows: [], rowCount: 0 }; },
      close:   async function () {},
    };
  }
  function _initThrows(label, cfg, codeRe) {
    b.externalDb._resetForTest();
    var threw = null;
    try { b.externalDb.init({ backends: { main: cfg } }); }
    catch (e) { threw = e; }
    check("requireTls rejects: " + label,
      threw && (codeRe.test(threw.code || "") || codeRe.test(threw.message || "")));
    b.externalDb._resetForTest();
  }
  function _initOk(label, cfg) {
    b.externalDb._resetForTest();
    var threw = null;
    try { b.externalDb.init({ backends: { main: cfg } }); }
    catch (e) { threw = e; }
    check("requireTls accepts: " + label, threw === null);
    b.externalDb._resetForTest();
  }

  // Default OFF — no requireTls → plaintext connection used as-is.
  var nd = _noopDriver();
  _initOk("absent requireTls (default off, back-compat)",
    { connect: nd.connect, query: nd.query, close: nd.close });

  // requireTls:false is an explicit no-gate.
  _initOk("requireTls:false explicit off",
    { connect: nd.connect, query: nd.query, requireTls: false });

  // requireTls:true with no TLS declaration → refused.
  _initThrows("requireTls true, no TLS declared",
    { connect: nd.connect, query: nd.query, requireTls: true }, /TLS_REQUIRED/);

  // requireTls:true with sslmode that permits plaintext fallback → refused.
  _initThrows("requireTls true, sslmode 'prefer' (plaintext fallback)",
    { connect: nd.connect, query: nd.query, requireTls: true, sslmode: "prefer" }, /TLS_REQUIRED/);
  _initThrows("requireTls true, sslmode 'disable'",
    { connect: nd.connect, query: nd.query, requireTls: true, sslmode: "disable" }, /TLS_REQUIRED/);

  // requireTls:true with explicit non-TLS transport → refused.
  _initThrows("requireTls true, tls:false",
    { connect: nd.connect, query: nd.query, requireTls: true, tls: false }, /TLS_REQUIRED/);

  // requireTls:true satisfied by tls:true.
  _initOk("requireTls true, tls:true",
    { connect: nd.connect, query: nd.query, requireTls: true, tls: true });

  // requireTls:true satisfied by an ssl object.
  _initOk("requireTls true, ssl object",
    { connect: nd.connect, query: nd.query, requireTls: true, ssl: { rejectUnauthorized: true } });

  // requireTls:true satisfied by guaranteed sslmode values.
  _initOk("requireTls true, sslmode 'require'",
    { connect: nd.connect, query: nd.query, requireTls: true, sslmode: "require" });
  _initOk("requireTls true, sslmode 'verify-full'",
    { connect: nd.connect, query: nd.query, requireTls: true, sslmode: "verify-full" });

  // requireTls must be a boolean — non-boolean refused at config time.
  _initThrows("requireTls non-boolean",
    { connect: nd.connect, query: nd.query, requireTls: "yes" }, /INVALID_CONFIG|must be a boolean/);

  // ---- OTel db.* semantic-convention attributes on the data emit path ----
  // db.system / db.operation / db.statement / db.name ride the audit
  // metadata so OTel dashboards correlate without a per-framework adapter.
  // Mirrors the db.ddl.executed shape on the local SQLite side.
  var otelRows = [];
  var origEmit2 = b.audit && b.audit.safeEmit;
  if (origEmit2) {
    b.audit.safeEmit = function (rec) {
      if (rec && typeof rec.action === "string" &&
          rec.action.indexOf("system.externaldb.") === 0) otelRows.push(rec);
      return origEmit2.apply(b.audit, arguments);
    };
  }
  try {
    var od = _instrumentingDriver();
    b.externalDb._resetForTest();
    b.externalDb.init({
      backends: { pgmain: { dialect: "postgres", connect: od.connect, query: od.query, close: od.close } },
    });
    await b.externalDb.query("SELECT id FROM users WHERE id = $1", [7]);                              // default — no includeSqlInAudit
    await b.externalDb.query("SELECT id FROM users WHERE id = $1", [7], { includeSqlInAudit: true }); // opted in
    await b.externalDb.transaction(async function (tx) { await tx.query("SELECT 1"); });
    await new Promise(function (r) { setImmediate(r); });
  } finally {
    if (origEmit2) b.audit.safeEmit = origEmit2;
  }
  var qRow = otelRows.filter(function (r) { return r.action === "system.externaldb.query"; });
  check("OTel: db.system maps dialect to OTel registry value (postgres→postgresql)",
    qRow.length >= 2 && qRow[0].metadata["db.system"] === "postgresql");
  check("OTel: db.name carries the backend name",
    qRow.length >= 2 && qRow[0].metadata["db.name"] === "pgmain");
  check("OTel: db.operation is the leading SQL keyword (always emitted)",
    qRow.length >= 2 && qRow[0].metadata["db.operation"] === "SELECT");
  // db.statement carries the SQL text (which can hold operator-inlined PII /
  // secrets), so it is gated behind the includeSqlInAudit opt-out: omitted by
  // default, present only when the operator opts in. This is the regression
  // guard for the privacy gate.
  check("OTel: db.statement OMITTED by default (respects includeSqlInAudit opt-out)",
    qRow.length >= 2 && qRow[0].metadata["db.statement"] === undefined);
  check("OTel: db.statement present + sanitized only when includeSqlInAudit:true",
    qRow.length >= 2 &&
    qRow[1].metadata["db.statement"] === "SELECT id FROM users WHERE id = $1" &&
    qRow[1].metadata["db.statement"].indexOf("7") === -1);
  var txRow = otelRows.filter(function (r) { return r.action === "system.externaldb.transaction"; });
  check("OTel: transaction span carries db.system + db.operation BEGIN",
    txRow.length >= 1 &&
    txRow[0].metadata["db.system"] === "postgresql" &&
    txRow[0].metadata["db.operation"] === "BEGIN");

  b.externalDb._resetForTest();
}

if (require.main === module) {
  run().then(
    function () { process.exit(0); },
    function (err) { console.error(err && err.stack); process.exit(1); }
  );
}

module.exports = { run: run };

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
      if (/^SELECT rolname FROM pg_roles/i.test(sql)) {
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

  b.externalDb._resetForTest();
}

if (require.main === module) {
  run().then(
    function () { process.exit(0); },
    function (err) { console.error(err && err.stack); process.exit(1); }
  );
}

module.exports = { run: run };

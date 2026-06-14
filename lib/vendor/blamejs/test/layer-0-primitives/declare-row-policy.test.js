"use strict";
/**
 * b.db.declareRowPolicy — declarative Postgres ROW LEVEL SECURITY
 * migration spec.
 *
 * Tests cover input validation at declare() time, idempotent ENABLE-RLS guard,
 * CREATE POLICY emission for each command + permissive shape, the
 * Postgres-only fail-fast, and DROP POLICY on down().
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function _fakeXdb(spec) {
  spec = spec || {};
  var captured = [];
  return {
    captured: captured,
    query: async function (sql, params) {
      captured.push({ sql: sql, params: (params || []).slice() });
      if (/FROM pg_class/.test(sql)) {
        if (spec.tableExists === false) return { rows: [], rowCount: 0 };
        // A native pg driver hands back a JS boolean for relrowsecurity.
        // `relrowsecurityRaw` lets a test inject exactly what a proxy /
        // ORM / non-native driver returns instead (the string "t"/"f",
        // "true"/"false", or 1/0) without the !! coercion masking it.
        var rel = Object.prototype.hasOwnProperty.call(spec, "relrowsecurityRaw")
          ? spec.relrowsecurityRaw
          : !!spec.rlsAlreadyOn;
        return {
          rows: [{ relrowsecurity: rel }],
          rowCount: 1,
        };
      }
      return { rows: [], rowCount: 0 };
    },
  };
}

function _fakeExternalDb(backendName, dialect) {
  return {
    listBackends: function () {
      return [{ name: backendName, dialect: dialect || "postgres" }];
    },
  };
}

async function _expectThrow(label, fn, re) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  check(label, threw !== null && (re ? re.test(threw.code || "") : true));
}

async function run() {
  // ---- input validation at declareRowPolicy() ----
  await _expectThrow("rejects missing opts",
    function () { b.db.declareRowPolicy(); },
    /declare-row-policy\/bad-opts/);

  await _expectThrow("rejects unknown opt",
    function () { b.db.declareRowPolicy({ schema: "a", table: "b", name: "c", using: "1=1", bogus: 1 }); },
    /declare-row-policy\/unknown-opt/);

  await _expectThrow("rejects missing schema",
    function () { b.db.declareRowPolicy({ table: "b", name: "c", using: "1=1" }); },
    /declare-row-policy\/missing-opt/);

  await _expectThrow("rejects missing table",
    function () { b.db.declareRowPolicy({ schema: "a", name: "c", using: "1=1" }); },
    /declare-row-policy\/missing-opt/);

  await _expectThrow("rejects missing name",
    function () { b.db.declareRowPolicy({ schema: "a", table: "b", using: "1=1" }); },
    /declare-row-policy\/missing-opt/);

  await _expectThrow("rejects missing using",
    function () { b.db.declareRowPolicy({ schema: "a", table: "b", name: "c" }); },
    /declare-row-policy\/missing-opt/);

  await _expectThrow("rejects bad identifier in schema",
    function () { b.db.declareRowPolicy({ schema: "bad name", table: "b", name: "c", using: "1=1" }); },
    /declare-row-policy\/bad-identifier/);

  await _expectThrow("rejects bad role identifier",
    function () { b.db.declareRowPolicy({ schema: "a", table: "b", name: "c", role: "bad name", using: "1=1" }); },
    /declare-row-policy\/bad-identifier/);

  await _expectThrow("rejects unknown command",
    function () { b.db.declareRowPolicy({ schema: "a", table: "b", name: "c", using: "1=1", command: "TRUNCATE" }); },
    /declare-row-policy\/bad-command/);

  await _expectThrow("rejects semicolon in using",
    function () { b.db.declareRowPolicy({ schema: "a", table: "b", name: "c", using: "1=1; DROP TABLE x" }); },
    /declare-row-policy\/bad-expression/);

  await _expectThrow("rejects semicolon in withCheck",
    function () { b.db.declareRowPolicy({ schema: "a", table: "b", name: "c", using: "1=1", withCheck: "1=1; DROP" }); },
    /declare-row-policy\/bad-expression/);

  await _expectThrow("rejects empty using",
    function () { b.db.declareRowPolicy({ schema: "a", table: "b", name: "c", using: "" }); },
    /declare-row-policy\/(missing-opt|empty-expression)/);

  await _expectThrow("rejects non-boolean permissive",
    function () { b.db.declareRowPolicy({ schema: "a", table: "b", name: "c", using: "1=1", permissive: "yes" }); },
    /declare-row-policy\/bad-type/);

  // ---- Migration shape ----
  var mig = b.db.declareRowPolicy({
    schema:    "public",
    table:     "sessions",
    name:      "tenant_isolation",
    role:      "app_user",
    using:     "tenant_id = current_setting('app.tenant_id')::uuid",
    withCheck: "tenant_id = current_setting('app.tenant_id')::uuid",
    command:   "ALL",
  });
  check("migration shape: target=externalDb",  mig.target === "externalDb");
  check("migration shape: has up()",            typeof mig.up === "function");
  check("migration shape: has down()",          typeof mig.down === "function");
  check("migration shape: description includes policy id",
    /declareRowPolicy public\.sessions\.tenant_isolation/.test(mig.description));

  // ---- up() emits ENABLE RLS + CREATE POLICY when RLS not yet on ----
  var xdb = _fakeXdb({ rlsAlreadyOn: false });
  var ctx = { externalDb: _fakeExternalDb("main", "postgres"), backendName: "main" };
  var result = await mig.up(xdb, ctx);
  var sqls = xdb.captured.map(function (c) { return c.sql; });
  check("up: ALTER TABLE ... ENABLE ROW LEVEL SECURITY emitted",
    sqls.some(function (s) { return /ALTER TABLE "public"\."sessions" ENABLE ROW LEVEL SECURITY/.test(s); }));
  check("up: CREATE POLICY emitted with quoted identifiers",
    sqls.some(function (s) { return /CREATE POLICY "tenant_isolation" ON "public"\."sessions"/.test(s); }));
  check("up: AS PERMISSIVE present (default)",
    sqls.some(function (s) { return /AS PERMISSIVE/.test(s); }));
  check("up: FOR ALL emitted",
    sqls.some(function (s) { return /FOR ALL/.test(s); }));
  check("up: TO \"app_user\" emitted",
    sqls.some(function (s) { return /TO "app_user"/.test(s); }));
  check("up: USING expression interpolated",
    sqls.some(function (s) { return /USING \(tenant_id = current_setting/.test(s); }));
  check("up: WITH CHECK emitted",
    sqls.some(function (s) { return /WITH CHECK \(tenant_id/.test(s); }));
  check("up: returns audit metadata",
    result && result.policy === "public.sessions.tenant_isolation" && result.command === "ALL");

  // ---- up() skips ALTER when RLS already on (idempotent) ----
  var xdb2 = _fakeXdb({ rlsAlreadyOn: true });
  var mig2 = b.db.declareRowPolicy({
    schema: "public", table: "sessions", name: "p2",
    using: "user_id = current_setting('app.user_id')::uuid",
    command: "SELECT", permissive: false,
  });
  await mig2.up(xdb2, ctx);
  var sqls2 = xdb2.captured.map(function (c) { return c.sql; });
  check("idempotent: ALTER TABLE skipped when RLS already on",
    !sqls2.some(function (s) { return /ALTER TABLE/.test(s); }));
  check("RESTRICTIVE rendered when permissive=false",
    sqls2.some(function (s) { return /AS RESTRICTIVE/.test(s); }));
  check("FOR SELECT emitted",
    sqls2.some(function (s) { return /FOR SELECT/.test(s); }));
  check("no role omitted: no TO clause",
    !sqls2.some(function (s) { return /^CREATE POLICY.* TO /.test(s); }));
  check("no withCheck: clause omitted",
    !sqls2.some(function (s) { return /WITH CHECK/.test(s); }));

  // ---- non-native-boolean driver: the string "f" means RLS-DISABLED ----
  // A proxy / ORM / non-native pg driver returns relrowsecurity as the
  // string "f" (false) rather than a JS boolean. "f" is TRUTHY, so a bare
  // `!relrowsecurity` would read it as "already enabled" and SILENTLY SKIP
  // the ENABLE ROW LEVEL SECURITY — leaving every row in the table
  // unprotected while the migration reports success. ENABLE must still be
  // emitted for "f"/"false"/0/"no"; it must be skipped only for a value
  // that unambiguously means true.
  async function _runMig(relRaw) {
    var x = _fakeXdb({ relrowsecurityRaw: relRaw });
    var m = b.db.declareRowPolicy({
      schema: "public", table: "sessions", name: "rls_coerce",
      using: "user_id = current_setting('app.user_id')::uuid", command: "ALL",
    });
    await m.up(x, ctx);
    return x.captured.map(function (c) { return c.sql; });
  }
  function _hasEnable(sqls) {
    return sqls.some(function (s) { return /ENABLE ROW LEVEL SECURITY/.test(s); });
  }
  check('non-native driver: ENABLE emitted when relrowsecurity is the string "f"',
    _hasEnable(await _runMig("f")));
  check('non-native driver: ENABLE emitted when relrowsecurity is "false"',
    _hasEnable(await _runMig("false")));
  check("non-native driver: ENABLE emitted when relrowsecurity is the number 0",
    _hasEnable(await _runMig(0)));
  check('non-native driver: ENABLE emitted when relrowsecurity is "no"',
    _hasEnable(await _runMig("no")));
  check('enabled-state respected: ENABLE skipped when relrowsecurity is the string "t"',
    !_hasEnable(await _runMig("t")));
  check('enabled-state respected: ENABLE skipped when relrowsecurity is "true"',
    !_hasEnable(await _runMig("true")));
  check("enabled-state respected: ENABLE skipped when relrowsecurity is the number 1",
    !_hasEnable(await _runMig(1)));

  // ---- table not found → throws ----
  var xdb3 = _fakeXdb({ tableExists: false });
  var threw3 = null;
  try { await mig.up(xdb3, ctx); } catch (e) { threw3 = e; }
  check("table-not-found: clear error",
    threw3 && /declare-row-policy\/table-not-found/.test(threw3.code || ""));

  // ---- down() drops policy ----
  var xdb4 = _fakeXdb();
  await mig.down(xdb4, ctx);
  var sqls4 = xdb4.captured.map(function (c) { return c.sql; });
  check("down: DROP POLICY IF EXISTS emitted",
    sqls4.some(function (s) {
      return /DROP POLICY IF EXISTS "tenant_isolation" ON "public"\."sessions"/.test(s);
    }));

  // ---- Postgres-only fail-fast ----
  var ctxSqlite = { externalDb: _fakeExternalDb("main", "sqlite"), backendName: "main" };
  var threwSqlite = null;
  try { await mig.up(_fakeXdb(), ctxSqlite); } catch (e) { threwSqlite = e; }
  check("non-postgres dialect: NOT_SUPPORTED on up",
    threwSqlite && /declare-row-policy\/not-supported/.test(threwSqlite.code || ""));

  var threwSqliteDown = null;
  try { await mig.down(_fakeXdb(), ctxSqlite); } catch (e) { threwSqliteDown = e; }
  check("non-postgres dialect: NOT_SUPPORTED on down",
    threwSqliteDown && /declare-row-policy\/not-supported/.test(threwSqliteDown.code || ""));

  // Unknown backend
  var ctxUnknown = { externalDb: _fakeExternalDb("other", "postgres"), backendName: "missing" };
  var threwUnknown = null;
  try { await mig.up(_fakeXdb(), ctxUnknown); } catch (e) { threwUnknown = e; }
  check("unknown backend: clear error",
    threwUnknown && /declare-row-policy\/unknown-backend/.test(threwUnknown.code || ""));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

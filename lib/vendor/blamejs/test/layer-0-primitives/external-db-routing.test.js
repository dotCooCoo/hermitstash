"use strict";
/**
 * b.externalDb v0.6.3 additions:
 *   - configurePool(name, opts) — runtime pool resize
 *   - adapters.connectAs(connect, opts) — Postgres role-aware connect wrapper
 *   - read/write namespace + replica routing
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var _makeFakeDriver = helpers._makeFakeDriver;

function _initWithSingle(driver) {
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      main: { connect: driver.connect, query: driver.query, close: driver.close, ping: driver.ping },
    },
  });
}

async function run() {
  // ---- configurePool ----
  var d = _makeFakeDriver();
  _initWithSingle(d);
  b.externalDb.configurePool("main", { min: 2, max: 50, idleTimeoutMs: 60000 });
  // No throw — happy path. The new bounds take effect on next acquire.
  check("configurePool: happy path",  true);

  // configurePool rejects bad opts at the call site.
  function rejects(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("configurePool rejects: " + label,
          threw && codeRe.test(threw.code || ""));
  }
  rejects("unknown backend",      function () { b.externalDb.configurePool("nope", { max: 10 }); }, /UNKNOWN_BACKEND/);
  rejects("unknown opt",          function () { b.externalDb.configurePool("main", { bogus: 1 }); }, /INVALID_CONFIG/);
  rejects("non-positive max",     function () { b.externalDb.configurePool("main", { max: 0 }); },  /INVALID_CONFIG/);
  rejects("non-integer max",      function () { b.externalDb.configurePool("main", { max: 1.5 }); }, /INVALID_CONFIG/);
  rejects("min > max",            function () { b.externalDb.configurePool("main", { min: 50, max: 10 }); }, /INVALID_CONFIG/);
  rejects("Infinity max",         function () { b.externalDb.configurePool("main", { max: Infinity }); }, /INVALID_CONFIG/);
  rejects("non-string name",      function () { b.externalDb.configurePool(42, {}); }, /INVALID_CONFIG/);

  // ---- adapters.connectAs ----
  // Track every SQL the driver sees so we can assert SET statements.
  function _instrumentingDriver() {
    var seen = [];
    return {
      seen: seen,
      connect: async function () { return { id: "client" }; },
      query:   async function (_client, sql, _params) {
        seen.push(sql);
        return { rows: [], rowCount: 0 };
      },
      close:   async function () {},
    };
  }
  var d2 = _instrumentingDriver();
  var wrappedConnect = b.externalDb.adapters.connectAs(d2.connect, {
    query:              d2.query,
    role:               "analytics_user",
    searchPath:         ["analytics", "public"],
    applicationName:    "wiki:analytics",
    statementTimeoutMs: 30000,
    gucs: { idle_in_transaction_session_timeout: "60s" },
  });
  await wrappedConnect();
  check("connectAs: SET ROLE issued",
        d2.seen.some(function (s) { return s === 'SET ROLE "analytics_user"'; }));
  check("connectAs: SET search_path issued",
        d2.seen.some(function (s) { return s === 'SET search_path TO "analytics", "public"'; }));
  check("connectAs: SET application_name issued",
        d2.seen.some(function (s) { return s === "SET application_name TO 'wiki:analytics'"; }));
  check("connectAs: SET statement_timeout issued",
        d2.seen.some(function (s) { return s === "SET statement_timeout TO 30000"; }));
  check("connectAs: SET custom GUC issued",
        d2.seen.some(function (s) { return s === 'SET "idle_in_transaction_session_timeout" TO \'60s\''; }));

  // Identifier validation rejects bad shape at config time.
  function rejectsCa(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("connectAs rejects: " + label,
          threw && (codeRe.test(threw.code || "") || codeRe.test(threw.message || "")));
  }
  var rawConnect = function () {};
  var rawQuery   = function () {};
  rejectsCa("bad role identifier",
    function () { b.externalDb.adapters.connectAs(rawConnect,
      { query: rawQuery, role: "bad name with spaces" }); }, /sql\/bad-shape|INVALID/);
  rejectsCa("bad searchPath segment",
    function () { b.externalDb.adapters.connectAs(rawConnect,
      { query: rawQuery, searchPath: ["1bad"] }); }, /sql\/bad-shape|INVALID/);
  rejectsCa("non-positive statementTimeoutMs",
    function () { b.externalDb.adapters.connectAs(rawConnect,
      { query: rawQuery, statementTimeoutMs: 0 }); }, /INVALID_CONFIG/);
  rejectsCa("missing query fn",
    function () { b.externalDb.adapters.connectAs(rawConnect, { role: "x" }); }, /INVALID_CONFIG/);
  // SQL-standard single-quote escaping for application_name string literal.
  d2.seen.length = 0;
  var wcEsc = b.externalDb.adapters.connectAs(d2.connect, {
    query: d2.query, applicationName: "wiki'with'quotes",
  });
  await wcEsc();
  check("connectAs: applicationName single-quotes escaped per SQL standard",
        d2.seen.some(function (s) { return s === "SET application_name TO 'wiki''with''quotes'"; }));

  // ---- Read-replica routing ----
  // Two replicas + primary. read.query must round-robin across replicas.
  b.externalDb._resetForTest();
  function _trackingDriver(label) {
    var seen = [];
    return {
      label: label,
      seen:  seen,
      connect: async function () { return { id: label + "-client" }; },
      query:   async function (_c, sql, _p) {
        seen.push(sql);
        if (/^SELECT 1$/i.test(sql)) return { rows: [], rowCount: 0 };
        return { rows: [{ from: label }], rowCount: 1 };
      },
      close:   async function () {},
      ping:    async function () { return true; },
    };
  }
  var primary  = _trackingDriver("primary");
  var replica1 = _trackingDriver("replica1");
  var replica2 = _trackingDriver("replica2");
  b.externalDb.init({
    backends: {
      main: {
        connect: primary.connect, query: primary.query, close: primary.close, ping: primary.ping,
        replicas: [
          { connect: replica1.connect, query: replica1.query, close: replica1.close, weight: 1 },
          { connect: replica2.connect, query: replica2.query, close: replica2.close, weight: 1 },
        ],
      },
    },
  });

  // 2 reads should hit both replicas at least once (weights are equal).
  await b.externalDb.read.query("SELECT 1");
  await b.externalDb.read.query("SELECT 1");
  await b.externalDb.read.query("SELECT 1");
  await b.externalDb.read.query("SELECT 1");
  check("read.query: hit replica1",
        replica1.seen.length > 0);
  check("read.query: hit replica2",
        replica2.seen.length > 0);
  check("read.query: did NOT hit primary on healthy replicas",
        primary.seen.length === 0);

  // write.query goes to primary.
  await b.externalDb.write.query("INSERT INTO x (a) VALUES (1)");
  check("write.query: routes to primary",
        primary.seen.some(function (s) { return /INSERT INTO x/.test(s); }));

  // legacy externalDb.query() unchanged — primary.
  await b.externalDb.query("INSERT INTO y (b) VALUES (2)");
  check("externalDb.query: primary unchanged",
        primary.seen.some(function (s) { return /INSERT INTO y/.test(s); }));

  // Read on a backend with NO replicas falls back to primary.
  b.externalDb._resetForTest();
  var solo = _trackingDriver("solo");
  b.externalDb.init({
    backends: {
      single: { connect: solo.connect, query: solo.query, close: solo.close, ping: solo.ping },
    },
  });
  await b.externalDb.read.query("SELECT 1");
  check("read.query: no replicas configured → primary",
        solo.seen.some(function (s) { return /SELECT 1/.test(s); }));

  // ---- replicas config validation rejects bad shapes at init ----
  b.externalDb._resetForTest();
  function rejectsReplicas(label, replicasCfg, codeRe) {
    var threw = null;
    try {
      b.externalDb.init({
        backends: {
          x: {
            connect: primary.connect, query: primary.query, close: primary.close,
            replicas: replicasCfg,
          },
        },
      });
    } catch (e) { threw = e; }
    check("replicas rejects: " + label,
          threw && codeRe.test(threw.code || ""));
    b.externalDb._resetForTest();
  }
  rejectsReplicas("empty array", [], /INVALID_CONFIG/);
  rejectsReplicas("missing connect",
    [{ query: replica1.query }], /INVALID_CONFIG/);
  rejectsReplicas("missing query",
    [{ connect: replica1.connect }], /INVALID_CONFIG/);
  rejectsReplicas("non-positive weight",
    [{ connect: replica1.connect, query: replica1.query, weight: 0 }], /INVALID_CONFIG/);
  rejectsReplicas("non-integer weight",
    [{ connect: replica1.connect, query: replica1.query, weight: 1.5 }], /INVALID_CONFIG/);

  // ---- dbRoleBackends + ALS-routed backend pick (v0.6.6) ----
  b.externalDb._resetForTest();
  var appDriver       = _trackingDriver("app");
  var analyticsDriver = _trackingDriver("analytics");
  b.externalDb.init({
    backends: {
      appMain:       {
        connect: appDriver.connect,       query: appDriver.query,
        close:   appDriver.close,         ping:  appDriver.ping,
      },
      analyticsMain: {
        connect: analyticsDriver.connect, query: analyticsDriver.query,
        close:   analyticsDriver.close,   ping:  analyticsDriver.ping,
      },
    },
    defaultBackend:  "appMain",
    dbRoleBackends:  {
      app_user:       "appMain",
      analytics_user: "analyticsMain",
    },
  });

  // Default: no ALS role → defaultBackend.
  await b.externalDb.query("SELECT 1");
  check("dbRoleBackends: no role → defaultBackend",
    appDriver.seen.length > 0 && analyticsDriver.seen.length === 0);

  // runAs("analytics_user") routes read.query to analyticsMain.
  appDriver.seen.length = 0;
  analyticsDriver.seen.length = 0;
  await b.externalDb.runAs("analytics_user", async function () {
    await b.externalDb.read.query("SELECT 1");
    check("runAs: currentRole inside scope",
      b.externalDb.currentRole() === "analytics_user");
  });
  check("runAs: read.query routed by ALS role",
    analyticsDriver.seen.length > 0 && appDriver.seen.length === 0);
  check("runAs: ALS clears outside scope",
    b.externalDb.currentRole() === null);

  // Explicit { backend: ... } always wins over ALS role.
  appDriver.seen.length = 0;
  analyticsDriver.seen.length = 0;
  await b.externalDb.runAs("analytics_user", async function () {
    await b.externalDb.query("SELECT 1", [], { backend: "appMain" });
  });
  check("dbRoleBackends: explicit backend overrides ALS role",
    appDriver.seen.length > 0 && analyticsDriver.seen.length === 0);

  // Unmapped role → defaultBackend.
  appDriver.seen.length = 0;
  analyticsDriver.seen.length = 0;
  await b.externalDb.runAs("admin_user", async function () {
    await b.externalDb.query("SELECT 1");
  });
  check("dbRoleBackends: unmapped role → defaultBackend",
    appDriver.seen.length > 0 && analyticsDriver.seen.length === 0);

  // bad role identifier shape rejected at init.
  function rejectsInit(label, opts, codeRe) {
    b.externalDb._resetForTest();
    var threw = null;
    try { b.externalDb.init(opts); } catch (e) { threw = e; }
    check("dbRoleBackends rejects: " + label,
      threw && (codeRe.test(threw.code || "") || codeRe.test(threw.message || "")));
    b.externalDb._resetForTest();
  }
  rejectsInit("non-object map",
    { backends: { x: { connect: appDriver.connect, query: appDriver.query } },
      dbRoleBackends: ["a"] },
    /INVALID_CONFIG/);
  rejectsInit("malformed role identifier",
    { backends: { x: { connect: appDriver.connect, query: appDriver.query } },
      dbRoleBackends: { "bad name": "x" } },
    /INVALID_CONFIG/);
  rejectsInit("backend reference does not exist",
    { backends: { x: { connect: appDriver.connect, query: appDriver.query } },
      dbRoleBackends: { app_user: "missing" } },
    /INVALID_CONFIG/);

  // ---- runAs input validation ----
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      x: { connect: appDriver.connect, query: appDriver.query },
    },
  });
  function rejectsRunAs(label, fn, re) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("runAs rejects: " + label, threw && re.test(threw.code || "") || re.test((threw && threw.message) || ""));
  }
  rejectsRunAs("non-fn body",
    function () { b.externalDb.runAs("x", "not a fn"); },
    /INVALID_FN/);
  rejectsRunAs("malformed role identifier",
    function () { b.externalDb.runAs("bad name", function () {}); },
    /sql\/bad-shape|INVALID/);

  // ---- transaction sessionGucs (v0.6.6 D4b) ----
  b.externalDb._resetForTest();
  var txDriver = _trackingDriver("tx");
  b.externalDb.init({
    backends: {
      main: { connect: txDriver.connect, query: txDriver.query, close: txDriver.close },
    },
  });

  txDriver.seen.length = 0;
  await b.externalDb.transaction(async function (tx) {
    await tx.query("SELECT 1");
  }, {
    sessionGucs: {
      "app.tenant_id":  "abc-123",
      "app.scale":      42,
      "app.dryRun":     false,
    },
  });
  check("sessionGucs: SET LOCAL string literal escaped",
    txDriver.seen.indexOf("SET LOCAL \"app\".\"tenant_id\" = 'abc-123'") !== -1);
  check("sessionGucs: SET LOCAL numeric value emitted raw",
    txDriver.seen.indexOf('SET LOCAL "app"."scale" = 42') !== -1);
  check("sessionGucs: SET LOCAL boolean rendered as true/false",
    txDriver.seen.indexOf('SET LOCAL "app"."dryRun" = false') !== -1);
  check("sessionGucs: SET LOCAL emitted AFTER BEGIN",
    txDriver.seen.indexOf("BEGIN") < txDriver.seen.indexOf("SET LOCAL \"app\".\"tenant_id\" = 'abc-123'"));

  // SQL-string escaping for embedded quotes.
  txDriver.seen.length = 0;
  await b.externalDb.transaction(async function (tx) {
    await tx.query("SELECT 1");
  }, {
    sessionGucs: { "app.note": "alice's tenant" },
  });
  check("sessionGucs: embedded single quote doubled per SQL standard",
    txDriver.seen.indexOf("SET LOCAL \"app\".\"note\" = 'alice''s tenant'") !== -1);

  // bad sessionGucs shapes throw at the call site.
  async function rejectsTx(label, gucs, re) {
    var threw = null;
    try {
      await b.externalDb.transaction(async function () {}, { sessionGucs: gucs });
    } catch (e) { threw = e; }
    check("sessionGucs rejects: " + label,
      threw && (re.test(threw.code || "") || re.test(threw.message || "")));
  }
  await rejectsTx("array shape",        ["a"],                    /INVALID_SESSION_GUCS/);
  await rejectsTx("bad name",           { "bad name": "x" },      /INVALID_SESSION_GUCS|sql\//);
  await rejectsTx("null value",         { "app.x": null },        /INVALID_SESSION_GUCS/);
  await rejectsTx("Infinity number",    { "app.x": Infinity },    /INVALID_SESSION_GUCS/);
  await rejectsTx("object value",       { "app.x": { y: 1 } },    /INVALID_SESSION_GUCS/);

  // ---- v0.6.7: role-tagged metrics + 42501 denied detection ----
  b.externalDb._resetForTest();
  var obs = b.testing.captureObservability();

  // Replace observability for the duration; restore at the end.
  var obsModule = require("../../lib/observability");
  var origEvent = obsModule.event;
  obsModule.event = obs.event;

  function _metricDriver(label) {
    var seen = [];
    return {
      label: label,
      seen:  seen,
      connect: async function () { return { id: label + "-c" }; },
      query:   async function (_c, sql, _p) {
        seen.push(sql);
        if (/PERMISSION_DENIED/i.test(sql)) {
          var e = new Error("permission denied for table sessions");
          e.code = "42501";
          throw e;
        }
        if (/^SELECT 1$/i.test(sql)) return { rows: [], rowCount: 0 };
        if (/^BEGIN/i.test(sql) || /^COMMIT/i.test(sql) || /^ROLLBACK/i.test(sql)) {
          return { rows: [], rowCount: 0 };
        }
        return { rows: [{ from: label }], rowCount: 1 };
      },
      close: async function () {},
      ping:  async function () { return true; },
    };
  }

  var driverApp = _metricDriver("app");
  var driverAna = _metricDriver("ana");
  b.externalDb.init({
    backends: {
      appMain:       { connect: driverApp.connect, query: driverApp.query, close: driverApp.close },
      analyticsMain: { connect: driverAna.connect, query: driverAna.query, close: driverAna.close },
    },
    defaultBackend: "appMain",
    dbRoleBackends: { app_user: "appMain", analytics_user: "analyticsMain" },
  });

  obs.clear();
  await b.externalDb.runAs("analytics_user", async function () {
    await b.externalDb.query("SELECT 1");
  });
  var successEvents = obs.byName("externaldb.query.success");
  check("metrics: query.success tagged with role label",
    successEvents.length === 1 && successEvents[0].labels.role === "analytics_user");
  var durationEvents = obs.byName("externaldb.query.duration_ms");
  check("metrics: query.duration_ms tagged with role label",
    durationEvents.length === 1 && durationEvents[0].labels.role === "analytics_user" &&
    typeof durationEvents[0].value === "number");

  // 42501 → db.role.denied
  obs.clear();
  var threwDenied = null;
  try {
    await b.externalDb.runAs("app_user", async function () {
      await b.externalDb.query("PERMISSION_DENIED test");
    });
  } catch (e) { threwDenied = e; }
  check("42501 propagates as caller error",  threwDenied && threwDenied.code === "42501");
  var deniedEvents = obs.byName("db.role.denied");
  check("42501: db.role.denied counter emitted with role label",
    deniedEvents.length === 1 && deniedEvents[0].labels.role === "app_user");

  // No role → "(none)" label fallback
  obs.clear();
  await b.externalDb.query("SELECT 1");
  var noRoleEvents = obs.byName("externaldb.query.success");
  check("metrics: no role bound → labels.role=(none)",
    noRoleEvents.length === 1 && noRoleEvents[0].labels.role === "(none)");

  // ---- v0.6.7: pool acquire-wait emitted under contention ----
  // Force a wait by holding all connections + queueing a second request.
  obs.clear();
  b.externalDb._resetForTest();
  var slowDriver = _metricDriver("slow");
  b.externalDb.init({
    backends: {
      x: {
        connect: slowDriver.connect, query: slowDriver.query, close: slowDriver.close,
        pool:    { min: 1, max: 1, idleTimeoutMs: 60000 },
      },
    },
  });
  // Hold the only client, then start a second query in parallel.
  // The second has to wait — emits acquire_wait.
  var holdResolve;
  var holdingDriver = {
    connect: async function () { return { id: "held" }; },
    query:   async function (_c, sql) {
      if (sql === "HOLD") return new Promise(function (r) { holdResolve = r; });
      return { rows: [], rowCount: 0 };
    },
    close:   async function () {},
  };
  b.externalDb._resetForTest();
  b.externalDb.init({
    backends: {
      x: {
        connect: holdingDriver.connect, query: holdingDriver.query, close: holdingDriver.close,
        pool:    { min: 1, max: 1, idleTimeoutMs: 60000 },
      },
    },
  });
  obs.clear();
  // First call acquires the only slot.
  var first = b.externalDb.query("HOLD");
  // Wait a tick so the first acquire definitely landed.
  await new Promise(function (r) { setImmediate(r); });
  // Second call waits.
  var second = b.externalDb.query("SELECT 1");
  // Brief real-time gap so the second query's promise enters the
  // pool's wait queue before we release the first. acquire_wait is
  // emitted on release (when the waiter unblocks), not on wait-start,
  // so we can't poll for it pre-release.
  await helpers.passiveObserve(5, "externaldb: enter pool wait queue before release");
  // Release the held call.
  holdResolve({ rows: [], rowCount: 0 });
  await first;
  await second;
  var acquireWaitEvents = obs.byName("externaldb.pool.acquire_wait");
  check("acquire_wait: emitted when waiter blocks at max capacity",
    acquireWaitEvents.length >= 1 &&
    typeof acquireWaitEvents[0].value === "number" &&
    acquireWaitEvents[0].labels.backend === "x");

  // ---- v0.6.7: runAs emits db.role.switched audit ----
  // Swap audit module's safeEmit for capture; restore after.
  b.externalDb._resetForTest();
  var auditModule = require("../../lib/audit");
  var origSafeEmit = auditModule.safeEmit;
  var captured = [];
  auditModule.safeEmit = function (e) { captured.push(e); };
  try {
    b.externalDb.init({
      backends: {
        x: { connect: holdingDriver.connect, query: async function () { return { rows: [], rowCount: 0 }; } },
      },
    });
    await b.externalDb.runAs("analytics_user", async function () { /* no-op */ });
    var runAsAudit = captured.filter(function (e) { return e && e.action === "db.role.switched"; });
    check("runAs: db.role.switched audit emitted",
      runAsAudit.length === 1 &&
      runAsAudit[0].metadata.newRole === "analytics_user" &&
      runAsAudit[0].metadata.source === "runAs");

    // No-op transition (same role) → no emission.
    captured.length = 0;
    await b.externalDb.runAs(null, async function () { /* no role -> still no role */ });
    check("runAs: same-role transition does NOT emit",
      captured.filter(function (e) { return e && e.action === "db.role.switched"; }).length === 0);
  } finally {
    auditModule.safeEmit = origSafeEmit;
  }

  // Restore observability
  obsModule.event = origEvent;

  // ---- Final clean ----
  b.externalDb._resetForTest();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

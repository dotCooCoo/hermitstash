"use strict";
/**
 * queue — bring-your-own database for the local backend.
 *
 * The local protocol defaults to the framework DB + "_blamejs_jobs"
 * table, but accepts { db, table, schema } so an operator can point the
 * queue rows at their own store / table / schema. Identifiers are
 * validated + quoted through b.safeSql (SQL identifier injection, CWE-89)
 * and refused at config time when unsafe; sealed columns (payload,
 * lastError) stay sealed regardless of which physical table the rows
 * land in.
 *
 * Run standalone: `node test/layer-0-primitives/queue-byo-db.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-q-byo-")); }

// A jobs-shaped table with the same columns as _blamejs_jobs so the
// local backend can write to it when pointed there via { table }.
// payload + lastError are TEXT to hold the vault-sealed blobs.
function _createCustomJobsTable(name) {
  b.db.exec(
    "CREATE TABLE IF NOT EXISTS " + name + " (" +
    "  _id              TEXT PRIMARY KEY," +
    "  queueName        TEXT NOT NULL," +
    "  payload          TEXT," +
    "  status           TEXT NOT NULL," +
    "  enqueuedAt       INTEGER NOT NULL," +
    "  availableAt      INTEGER NOT NULL," +
    "  leasedAt         INTEGER," +
    "  leaseExpiresAt   INTEGER," +
    "  attempts         INTEGER NOT NULL DEFAULT 0," +
    "  maxAttempts      INTEGER NOT NULL DEFAULT 5," +
    "  lastError        TEXT," +
    "  finishedAt       INTEGER," +
    "  traceId          TEXT," +
    "  classification   TEXT," +
    "  priority         INTEGER NOT NULL DEFAULT 0," +
    "  repeatCron       TEXT," +
    "  repeatTimezone   TEXT," +
    "  flowId           TEXT," +
    "  flowChildName    TEXT," +
    "  dependsOn        TEXT" +
    ")"
  );
}

// ---- Default config unchanged ----

async function testDefaultConfigUsesFrameworkJobsTable() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    await b.queue.enqueue("default-q", { tag: "default" });

    var rows = await b.db.from("_blamejs_jobs")
      .where({ queueName: "default-q", status: "pending" }).all();
    check("default: row lands in _blamejs_jobs", rows.length === 1);
    check("default: size reads the default table",
          (await b.queue.size("default-q")) === 1);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// ---- Custom table ----

async function testCustomTableRoutesRowsThere() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    _createCustomJobsTable("app_jobs");
    b.queue.init({ backends: { byo: { protocol: "local", table: "app_jobs" } } });

    await b.queue.enqueue("byo-q", { tag: "custom" }, { traceId: "t-1" });

    var inCustom = await b.db.from("app_jobs")
      .where({ queueName: "byo-q" }).all();
    check("custom table: enqueued row lands in app_jobs", inCustom.length === 1);

    var inDefault = await b.db.from("_blamejs_jobs")
      .where({ queueName: "byo-q" }).all();
    check("custom table: nothing written to _blamejs_jobs", inDefault.length === 0);

    check("custom table: size reads from the custom table",
          (await b.queue.size("byo-q")) === 1);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testCustomTableFullLifecycleAndSealing() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    _createCustomJobsTable("app_jobs");
    b.queue.init({ backends: { byo: { protocol: "local", table: "app_jobs" } } });

    var seen = null;
    var consumer = b.queue.consume("byo-life", async function (job) {
      seen = job.payload;
    }, { backend: "byo", concurrency: 1, pollIntervalMs: 25, fastPollMs: 5 });

    await b.queue.enqueue("byo-life", { secret: "social-9999" }, { backend: "byo" });
    await helpers.waitUntil(function () { return seen !== null; }, {
      timeoutMs: 4000, label: "queue byo-db: consumer leased + ran the job from the custom table",
    });
    check("custom table: payload round-trips through lease/unseal",
          seen && seen.secret === "social-9999");

    // The stored payload column is sealed — raw bytes must NOT contain the
    // plaintext. Sealing keys off the _blamejs_jobs column map even though
    // the physical row lives in app_jobs.
    var raw = await b.db.from("app_jobs").where({ queueName: "byo-life" }).all();
    check("custom table: a row exists in app_jobs", raw.length === 1);
    var storedPayload = String(raw[0].payload || "");
    check("custom table: stored payload is sealed (no plaintext)",
          storedPayload.indexOf("social-9999") === -1 && storedPayload.length > 0);

    consumer.cancel();
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// ---- Bring-your-own store handle ----

async function testCustomDbHandleReceivesCalls() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    _createCustomJobsTable("handle_jobs");
    // A spy handle that delegates to the framework store but records the
    // SQL it was handed, so we can confirm the backend dispatches through
    // the operator-supplied handle (not cluster-storage directly) and
    // targets the configured table.
    var sqls = [];
    var spy = {
      execute: function (sql, params) {
        sqls.push(sql);
        return b.clusterStorage.execute(sql, params);
      },
      executeOne: function (sql, params) {
        sqls.push(sql);
        return b.clusterStorage.executeOne(sql, params);
      },
      executeAll: function (sql, params) {
        sqls.push(sql);
        return b.clusterStorage.executeAll(sql, params);
      },
    };
    b.queue.init({ backends: { byo: { protocol: "local", db: spy, table: "handle_jobs" } } });

    await b.queue.enqueue("handle-q", { tag: "via-handle" }, { backend: "byo" });
    await b.queue.size("handle-q", { backend: "byo" });

    check("byo handle: enqueue dispatched through the supplied handle",
          sqls.some(function (s) { return /INSERT INTO "handle_jobs"/.test(s); }));
    check("byo handle: size dispatched through the supplied handle",
          sqls.some(function (s) { return /FROM "handle_jobs"/.test(s); }));
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// ---- Schema qualifier ----

async function testSchemaQualifierIsQuoted() {
  // Verifies the schema.table qualifier is composed via safeSql quoting.
  // No physical schema needed — we capture the SQL through a spy handle
  // and assert the quoted dotted form, which is the injection-safe shape.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var sqls = [];
    var spy = {
      execute:    function (sql) { sqls.push(sql); return Promise.resolve({ rows: [], rowCount: 0 }); },
      executeOne: function (sql) { sqls.push(sql); return Promise.resolve(null); },
      executeAll: function (sql) { sqls.push(sql); return Promise.resolve([]); },
    };
    b.queue.init({ backends: { byo: { protocol: "local", db: spy, schema: "work", table: "jobs_t" } } });
    await b.queue.enqueue("sch-q", { tag: "x" }, { backend: "byo" });
    check("schema qualifier: composed as quoted \"work\".\"jobs_t\"",
          sqls.some(function (s) { return s.indexOf('"work"."jobs_t"') !== -1; }));
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// ---- Config-time validation (the security boundary) ----

async function testRejectsUnsafeTableAndSchemaAndHandle() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    function initThrew(cfg) {
      var threw = false;
      try {
        b.queue.init({ backends: { byo: Object.assign({ protocol: "local" }, cfg) } });
      } catch (_e) { threw = true; }
      try { b.queue._resetForTest(); } catch (_e2) {}
      return threw;
    }

    check("rejects an injection-shaped table name",
          initThrew({ table: "jobs; DROP TABLE users" }));
    check("rejects a quote-bearing table name",
          initThrew({ table: 'jobs" --' }));
    check("rejects a SQL reserved word as table",
          initThrew({ table: "select" }));
    check("rejects a non-string table",
          initThrew({ table: 123 }));
    check("rejects an injection-shaped schema name",
          initThrew({ table: "jobs_t", schema: "public; DROP" }));
    check("rejects a non-string schema",
          initThrew({ table: "jobs_t", schema: {} }));
    check("rejects a db handle that is not an object",
          initThrew({ db: "not-a-handle" }));
    check("rejects a db handle missing required methods",
          initThrew({ db: { execute: function () {} } }));

    // The default (no custom table/schema/db) must still init cleanly.
    var ok = true;
    try {
      b.queue.init({ backends: { plain: { protocol: "local" } } });
    } catch (_e) { ok = false; }
    check("default config still inits cleanly", ok);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// ---- Flow routing under a custom table ----

async function testFlowSecondPassTargetsCustomTable() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    _createCustomJobsTable("flow_jobs");
    b.queue.init({
      backends: { byo: { protocol: "local", table: "flow_jobs" } },
      defaultBackend: "byo",
    });

    var ord = [];
    var consumer = b.queue.consume("byo-flow", async function (job) {
      ord.push(job.payload.tag);
    }, { backend: "byo", concurrency: 4, pollIntervalMs: 25, fastPollMs: 5 });

    await b.queue.enqueueFlow({
      queueName: "byo-flow",
      children: [
        { name: "fetch",     payload: { tag: "fetch" } },
        { name: "transform", payload: { tag: "transform" }, dependsOn: ["fetch"] },
      ],
    });

    // The flow children — including the dependsOn second pass — must all
    // land in flow_jobs, not _blamejs_jobs.
    var inCustom = await b.db.from("flow_jobs").where({ queueName: "byo-flow" }).all();
    check("flow byo: both children written to the custom table", inCustom.length === 2);
    var inDefault = await b.db.from("_blamejs_jobs").where({ queueName: "byo-flow" }).all();
    check("flow byo: nothing leaked to _blamejs_jobs", inDefault.length === 0);

    await helpers.waitUntil(function () { return ord.length === 2; }, {
      timeoutMs: 5000, label: "queue byo-flow: both flow jobs processed in order",
    });
    check("flow byo: dependency order preserved through the custom table",
          ord[0] === "fetch" && ord[1] === "transform");

    consumer.cancel();
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

// ---- Self-registration: seal at rest without db.init ----

// A standalone redis/sqs queue node may never run db.init in-process, so
// the _blamejs_jobs sealed-column declaration would be absent and
// cryptoField.sealRow would silently pass the payload through in cleartext.
// queue.init must self-register the seal table so payloads seal regardless.
async function testSealRegistersWithoutDbInit() {
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    // Simulate a process where db.init never registered _blamejs_jobs with
    // cryptoField — clear the registry, then confirm it is genuinely gone.
    b.cryptoField.clearForTest();
    check("self-register precondition: _blamejs_jobs schema cleared",
          b.cryptoField.getSchema("_blamejs_jobs") === null);

    // queue.init must self-register the seal table.
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    check("self-register: queue.init re-registered _blamejs_jobs seal map",
          b.cryptoField.getSchema("_blamejs_jobs") !== null);

    await b.queue.enqueue("seal-q", { secret: "ssn-7777", token: "bearer-abc" });

    // Read the RAW payload column. b.db.from("_blamejs_jobs") would auto-
    // UNSEAL (it's a registered table), masking the at-rest state — so use
    // a raw prepared SELECT to inspect the bytes actually on disk.
    var raw = b.db.prepare("SELECT payload FROM _blamejs_jobs WHERE queueName = ?").all("seal-q");
    check("self-register: a row exists", raw.length === 1);
    var stored = String(raw[0].payload || "");
    check("self-register: payload sealed at rest (no plaintext secret)",
          stored.length > 0 && stored.indexOf("ssn-7777") === -1 && stored.indexOf("bearer-abc") === -1);
    check("self-register: payload carries the vault seal prefix",
          stored.indexOf("vault:") === 0);
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 500 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testDefaultConfigUsesFrameworkJobsTable();
  await testCustomTableRoutesRowsThere();
  await testCustomTableFullLifecycleAndSealing();
  await testCustomDbHandleReceivesCalls();
  await testSchemaQualifierIsQuoted();
  await testRejectsUnsafeTableAndSchemaAndHandle();
  await testFlowSecondPassTargetsCustomTable();
  await testSealRegistersWithoutDbInit();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { process.exitCode = 1; throw e; }
  );
}

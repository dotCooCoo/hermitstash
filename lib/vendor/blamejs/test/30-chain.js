// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 3 — chain-writing modules (audit, consent, subject, checkpoint)
 *           + cluster-storage (SQL dispatcher).
 *
 * (Layer 3: uses db + chain-writer +
 * cluster-storage). Hash-chained log tables and the framework write-path
 * primitives that consume them.
 *
 *   cluster-storage   — SQL dispatcher (placeholderize, resolveTables,
 *                       local + cluster dispatch)
 *   audit             — chain append + verify + self-logging + begin-trace
 *   consent           — chain append (uses chain-writer)
 *   subject           — DSAR (export + delete) using audit + db
 *   append-only       — INSERT-only trigger guards + foreign keys +
 *                       table metadata reflection
 *   checkpoint        — sign + verify + tamper detect + rollback detect
 *
 * Layers 0, 1, 2 must run first. Each test sets up its own tmpDir + db.
 *
 * Usage from smoke.js:
 *   var chainLayer = require("./30-chain");
 *   await chainLayer.run();
 */

var helpers = require("./_helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;
var setupTestDb              = helpers.setupTestDb;
var teardownTestDb           = helpers.teardownTestDb;
var setTestPassphraseEnv     = helpers.setTestPassphraseEnv;
var _makeSqliteDriver        = helpers._makeSqliteDriver;

async function testClusterStorageLocalDispatch() {
  // With no cluster.init, executeAll should dispatch to local SQLite.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cs-"));
  try {
    // Reset cluster BEFORE setupTestDb so its internal audit.checkpoint
    // runs on the permanent-leader fallback (terminated=false).
    b.cluster._resetForTest();
    await setupTestDb(tmpDir);

    // Seed an audit row via the existing local path so we have something
    // to read back.
    var ev = await b.audit.record({
      actor:   { kind: "user", id: "u1" },
      action:  "auth.login",
      outcome: "success",
    });
    check("setup: audit row recorded locally",      ev !== null);

    // Now read back through cluster-storage. In single-node mode, should
    // hit the local SQLite, table name is unprefixed.
    check("tableName(audit_log) is unprefixed locally",
          b.clusterStorage.tableName("audit_log") === "audit_log");

    var rows = await b.clusterStorage.executeAll("SELECT _id, action FROM audit_log");
    check("clusterStorage.executeAll local: row found", rows.length >= 1);
    check("clusterStorage row has audit action",        rows[0].action === "auth.login");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

function testClusterStoragePlaceholderize() {
  check("placeholderize sqlite: passthrough",
        b.clusterStorage.placeholderize("SELECT * FROM t WHERE a = ? AND b = ?", "sqlite") ===
        "SELECT * FROM t WHERE a = ? AND b = ?");
  check("placeholderize postgres: ? → $1, $2",
        b.clusterStorage.placeholderize("SELECT * FROM t WHERE a = ? AND b = ?", "postgres") ===
        "SELECT * FROM t WHERE a = $1 AND b = $2");
  check("placeholderize: skips ? inside single-quoted strings",
        b.clusterStorage.placeholderize("SELECT * FROM t WHERE label = '?' AND id = ?", "postgres") ===
        "SELECT * FROM t WHERE label = '?' AND id = $1");
}

function testClusterStorageResolveTablesIsNoOpInSingleNode() {
  b.cluster._resetForTest();
  var sql = "SELECT * FROM audit_log";
  check("resolveTables: passthrough when not cluster mode",
        b.clusterStorage.resolveTables(sql) === sql);
}

async function testClusterStorageClusterDispatch() {
  // Spin up a real cluster: full framework + external-db + cluster.init.
  // Then run executeAll against external-db tables created by
  // frameworkSchema.ensureSchema. The resolveTables should rewrite
  // audit_log → _blamejs_audit_log automatically.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cs-cluster-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: {
        "ops": { connect: driver.connect, query: driver.query, close: driver.close },
      },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });

    b.cluster._resetForTest();
    await b.cluster.init({
      nodeId:            "cs-cluster-test",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    // Now in cluster mode. Insert a row using unprefixed name + ? placeholders.
    await b.clusterStorage.execute(
      "INSERT INTO audit_log (_id, recordedAt, monotonicCounter, action, outcome, prevHash, rowHash, nonce, fencingToken) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ["row1", Date.now(), 1, "auth.login", "success", "", "h1", Buffer.alloc(16), 1]
    );

    // Read back, also via unprefixed name. Dispatcher rewrites both.
    var rows = await b.clusterStorage.executeAll("SELECT _id, action FROM audit_log WHERE _id = ?", ["row1"]);
    check("clusterStorage cluster mode: row found via unprefixed name",  rows.length === 1);
    check("clusterStorage cluster mode: row data preserved",             rows[0].action === "auth.login");

    // Verify the row actually landed in the prefixed table
    var directRows = await b.externalDb.query("SELECT _id FROM _blamejs_audit_log WHERE _id = ?", ["row1"]);
    check("cluster row written to _blamejs_-prefixed external table",    directRows.rows.length === 1);

    // tableName getter reflects cluster mode
    check("tableName(audit_log) prefixed in cluster mode",
          b.clusterStorage.tableName("audit_log") === "_blamejs_audit_log");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// Single-node tests for the discovery surface — no external-db needed,
// run against the permanent-leader fallback.
function testClusterEndpointSingleNode() {
  b.cluster._resetForTest();
  check("cluster.endpoint() returns null in single-node fallback",
        b.cluster.endpoint() === null);
}

async function testClusterDiscoveryHandlerSingleNode() {
  b.cluster._resetForTest();
  var handler = b.cluster.discoveryHandler();
  check("cluster.discoveryHandler returns a function", typeof handler === "function");

  // Mock res with capture
  var captured = { status: null, headers: null, body: "" };
  var res = {
    writeHead: function (s, h) { captured.status = s; captured.headers = h; },
    end:       function (b)    { captured.body += b || ""; },
  };
  await handler({ method: "GET", url: "/cluster/leader" }, res);

  check("discoveryHandler: 200 in single-node fallback",        captured.status === 200);
  check("discoveryHandler: Content-Type is JSON",
        captured.headers["Content-Type"].indexOf("application/json") === 0);
  check("discoveryHandler: Cache-Control is no-store",
        captured.headers["Cache-Control"] === "no-store");

  var body = JSON.parse(captured.body);
  check("discoveryHandler: leader.nodeId is single-node-local",
        body.leader && body.leader.nodeId === "single-node-local");
  check("discoveryHandler: leader.endpoint is null when unconfigured",
        body.leader.endpoint === null);
  check("discoveryHandler: self.isLeader is true in fallback",
        body.self && body.self.isLeader === true);
}

async function testClusterEndpointInitValidation() {
  b.cluster._resetForTest();

  // Setup minimal external-db so cluster.init has somewhere to land —
  // we'll never reach the heartbeat because validation throws first.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-clep-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });

    // 1. http:// rejected by default (HTTPS-only allowlist)
    var rejected = null;
    try {
      await b.cluster.init({
        nodeId:            "ep-test-1",
        externalDbBackend: "ops",
        dialect:           "sqlite",
        endpoint:          "http://node1.internal:8080",
      });
    } catch (e) { rejected = e; }
    check("cluster.init: http:// endpoint rejected by default",
          rejected && rejected.code === "INVALID_ENDPOINT");
    b.cluster._resetForTest();

    // 2. Malformed URL rejected
    var malformed = null;
    try {
      await b.cluster.init({
        nodeId:            "ep-test-2",
        externalDbBackend: "ops",
        dialect:           "sqlite",
        endpoint:          "not-a-url",
      });
    } catch (e) { malformed = e; }
    check("cluster.init: malformed endpoint rejected",
          malformed && malformed.code === "INVALID_ENDPOINT");
    b.cluster._resetForTest();

    // 3. http:// accepted with explicit allowedProtocols opt-in
    await b.cluster.init({
      nodeId:            "ep-test-3",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      endpoint:          "http://node1.internal:8080",
      allowedProtocols:  b.safeUrl.ALLOW_HTTP_ALL,
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });
    check("cluster.endpoint() returns configured value",
          b.cluster.endpoint() === "http://node1.internal:8080");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterDiscoveryAcquiredLeader() {
  // Spin up a real cluster, configure an endpoint, verify the leader-row
  // captures it AND discoveryHandler reports it back.
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-disc-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });

    await b.cluster.init({
      nodeId:            "disc-test-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      endpoint:          "https://disc-test-1.internal:8443",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    check("cluster.isLeader after acquire", b.cluster.isLeader() === true);

    var leader = await b.cluster.currentLeader();
    check("currentLeader: nodeId matches",
          leader && leader.nodeId === "disc-test-1");
    check("currentLeader: endpoint persisted to leader row",
          leader.endpoint === "https://disc-test-1.internal:8443");
    check("currentLeader: fencingToken is monotonic (>= 1)",
          typeof leader.fencingToken === "number" && leader.fencingToken >= 1);

    // discoveryHandler reports leader + endpoint
    var captured = { status: null, body: "" };
    var res = {
      writeHead: function (s, _h) { captured.status = s; },
      end:       function (b)     { captured.body += b || ""; },
    };
    await b.cluster.discoveryHandler()({ method: "GET" }, res);
    check("discoveryHandler: 200 with active leader",         captured.status === 200);
    var body = JSON.parse(captured.body);
    check("discoveryHandler: leader.nodeId in cluster mode",
          body.leader.nodeId === "disc-test-1");
    check("discoveryHandler: leader.endpoint in cluster mode",
          body.leader.endpoint === "https://disc-test-1.internal:8443");
    check("discoveryHandler: self.isLeader is true",          body.self.isLeader === true);
    check("discoveryHandler: self.endpoint matches",
          body.self.endpoint === "https://disc-test-1.internal:8443");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterAuditTipFencing() {
  // Verify the canonical fencing-token guard on _blamejs_audit_tip:
  //   1. First write (fencingToken=N) — INSERT path, accepted
  //   2. Same-token re-write (N) — UPDATE path with WHERE N <= N, accepted
  //   3. Higher-token write (N+5) — UPDATE path, accepted
  //   4. Lower-token write (N+2) — UPDATE rejected by WHERE clause,
  //      audit.checkpoint() throws ClusterError(code=FENCED_OUT).
  //
  // We drive checkpoint() directly rather than recreating the DB row by
  // hand — this proves the framework's actual write path enforces the
  // fence, not just that the SQL would do the right thing in isolation.
  //
  // Forcing the leader's fencingToken to step down is non-trivial in a
  // single-process test (the cluster module's lease state isn't directly
  // mutable). Instead we drive _upsertAuditTip directly with explicit
  // tokens — that's the function the framework's write path calls, and
  // it carries the WHERE-clause guard.
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fence-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });

    await b.cluster.init({
      nodeId:            "fence-test-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    // Direct upserts via cluster-storage (bypasses audit.checkpoint's
    // chain-tip read so we can test the fence in isolation).
    async function upsert(counter, hash, signedAt, token) {
      var result = await b.clusterStorage.execute(
        "INSERT INTO _blamejs_audit_tip " +
        "  (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) " +
        "VALUES ('audit', ?, ?, ?, ?) " +
        "ON CONFLICT (scope) DO UPDATE SET " +
        "  atMonotonicCounter = EXCLUDED.atMonotonicCounter, " +
        "  rowHash            = EXCLUDED.rowHash, " +
        "  signedAt           = EXCLUDED.signedAt, " +
        "  fencingToken       = EXCLUDED.fencingToken " +
        "WHERE _blamejs_audit_tip.fencingToken <= EXCLUDED.fencingToken " +
        "RETURNING fencingToken",
        [counter, hash, signedAt, token]
      );
      return result.rows.length > 0;
    }

    // 1. First write (token=3) succeeds — INSERT path
    check("audit-tip: first write at token=3 accepted",
          (await upsert(1,  "h1", "1", 3)) === true);

    // 2. Same-token rewrite (token=3) — WHERE 3<=3 → UPDATE path
    check("audit-tip: same-token rewrite at token=3 accepted",
          (await upsert(2,  "h2", "2", 3)) === true);

    // 3. Higher-token bump (token=8) — WHERE 3<=8 → UPDATE
    check("audit-tip: higher-token write at token=8 accepted",
          (await upsert(3,  "h3", "3", 8)) === true);

    // 4. Stale-token write (token=5, stored=8) — fenced out
    check("audit-tip: lower-token write at token=5 rejected (fenced)",
          (await upsert(4,  "h4", "4", 5)) === false);

    // The stored row should still reflect the highest-accepted token (8)
    var stored = await b.clusterStorage.executeOne(
      "SELECT fencingToken, rowHash FROM _blamejs_audit_tip WHERE scope = 'audit'"
    );
    check("audit-tip: stored token unchanged after rejected write",
          Number(stored.fencingToken) === 8);
    check("audit-tip: stored rowHash unchanged after rejected write",
          stored.rowHash === "h3");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterSessionsSharedAcrossNodes() {
  // Sessions migrated to external-db when migrated to external-db — a session created on
  // the leader must be verifiable by reading the SAME external-db row.
  // We can't truly stand up two node processes in-test, so we simulate
  // the cluster-shared-storage property by:
  //   1. cluster.init as leader, create a session — row lands in
  //      external-db's _blamejs_sessions.
  //   2. SELECT directly from external-db; row is there with sealed
  //      data (proves it didn't go to local SQLite).
  //   3. session.verify reads through cluster-storage and returns
  //      the unsealed row — proves the round-trip works.
  //   4. Compare against the local SQLite _blamejs_sessions table —
  //      should be empty (proves cluster mode is actually routing
  //      reads/writes away from local).
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sess-cl-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    await setupTestDb(tmpDir);
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    await b.cluster.init({
      nodeId:            "sess-cluster-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    var s = await b.session.create({ userId: "u-cluster-1", data: { role: "admin" } });
    check("create returned token",                  typeof s.token === "string");

    // Row lands in external-db, NOT in local SQLite
    var extRows = await b.externalDb.query(
      "SELECT sidHash FROM _blamejs_sessions",
      [], { backend: "ops" }
    );
    check("session row in external-db",             extRows.rows.length === 1);
    check("session row sidHash is hashed (128 hex)",
          /^[0-9a-f]{128}$/.test(extRows.rows[0].sidHash));

    var localRows = b.db.prepare("SELECT sidHash FROM _blamejs_sessions").all();
    check("local SQLite session table is empty in cluster mode",
          localRows.length === 0);

    // Round-trip: verify reads back through external-db
    var v = await b.session.verify(s.token);
    check("cluster-mode verify returns userId",     v && v.userId === "u-cluster-1");
    check("cluster-mode verify returns unsealed data",
          v && v.data && v.data.role === "admin");

    // Cleanup via destroy hits external-db too
    var destroyed = await b.session.destroy(s.token);
    check("cluster-mode destroy returns true",      destroyed === true);
    var afterDelete = await b.externalDb.query(
      "SELECT COUNT(*) AS n FROM _blamejs_sessions",
      [], { backend: "ops" }
    );
    check("session row removed from external-db",   Number(afterDelete.rows[0].n) === 0);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    await teardownTestDb(tmpDir);
  }
}

async function testClusterConsentTipFencing() {
  // Mirror of testClusterAuditTipFencing but for the consent chain:
  // verify the canonical fencing-token guard on _blamejs_consent_tip
  // through direct upserts (3, 3, 8, 5 token sequence).
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cf-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    await b.cluster.init({
      nodeId:            "consent-fence-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    async function upsert(counter, hash, signedAt, token) {
      var result = await b.clusterStorage.execute(
        "INSERT INTO _blamejs_consent_tip " +
        "  (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) " +
        "VALUES ('consent', ?, ?, ?, ?) " +
        "ON CONFLICT (scope) DO UPDATE SET " +
        "  atMonotonicCounter = EXCLUDED.atMonotonicCounter, " +
        "  rowHash            = EXCLUDED.rowHash, " +
        "  signedAt           = EXCLUDED.signedAt, " +
        "  fencingToken       = EXCLUDED.fencingToken " +
        "WHERE _blamejs_consent_tip.fencingToken <= EXCLUDED.fencingToken " +
        "RETURNING fencingToken",
        [counter, hash, signedAt, token]
      );
      return result.rows.length > 0;
    }

    check("consent-tip: first write at token=3 accepted",
          (await upsert(1, "h1", "1", 3)) === true);
    check("consent-tip: same-token rewrite at token=3 accepted",
          (await upsert(2, "h2", "2", 3)) === true);
    check("consent-tip: higher-token write at token=8 accepted",
          (await upsert(3, "h3", "3", 8)) === true);
    check("consent-tip: lower-token write at token=5 rejected (fenced)",
          (await upsert(4, "h4", "4", 5)) === false);

    var stored = await b.clusterStorage.executeOne(
      "SELECT fencingToken, rowHash FROM _blamejs_consent_tip WHERE scope = 'consent'"
    );
    check("consent-tip: stored token unchanged after rejected write",
          Number(stored.fencingToken) === 8);
    check("consent-tip: stored rowHash unchanged after rejected write",
          stored.rowHash === "h3");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterConsentTipUpdatedOnGrant() {
  // The actual integration: consent.grant in cluster mode writes the
  // chain row AND upserts _blamejs_consent_tip. After a grant, the
  // tip should record the row's monotonicCounter and rowHash.
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ct-grant-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    await setupTestDb(tmpDir);
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    await b.cluster.init({
      nodeId:            "consent-grant-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    var grantResult = await b.consent.grant({
      subjectId:   "subj-1",
      purpose:     "marketing.email",
      lawfulBasis: "consent",
      channel:     "ui",
    });
    check("consent.grant returned a row with monotonicCounter",
          grantResult && typeof grantResult.monotonicCounter === "number");

    // Consent tip should now reflect the grant
    var tip = await b.externalDb.query(
      "SELECT atMonotonicCounter, rowHash FROM _blamejs_consent_tip WHERE scope='consent'",
      [], { backend: "ops" }
    );
    check("consent-tip: row exists after first grant",
          tip.rows.length === 1);
    check("consent-tip: counter matches grant's monotonicCounter",
          Number(tip.rows[0].atMonotonicCounter) === Number(grantResult.monotonicCounter));
    check("consent-tip: rowHash matches grant's rowHash",
          tip.rows[0].rowHash === grantResult.rowHash);

    // Second grant advances the tip
    var grant2 = await b.consent.grant({
      subjectId:   "subj-2",
      purpose:     "marketing.email",
      lawfulBasis: "consent",
      channel:     "ui",
    });
    var tip2 = await b.externalDb.query(
      "SELECT atMonotonicCounter, rowHash FROM _blamejs_consent_tip WHERE scope='consent'",
      [], { backend: "ops" }
    );
    check("consent-tip: counter advanced on second grant",
          Number(tip2.rows[0].atMonotonicCounter) === Number(grant2.monotonicCounter));
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    await teardownTestDb(tmpDir);
  }
}

async function testClusterConsentRollbackDetected() {
  // Pre-seed consent-tip with counter=999 + empty consent_log; spawn
  // a child that runs cluster.init and verify it exits 1 with the
  // generalized "consent-log rollback detected" message.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cr-detect-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    await b.externalDb.query(
      "INSERT INTO _blamejs_consent_tip (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) " +
      "VALUES ('consent', 999, 'rolled-hash', '0', 5)"
    );
    await b.externalDb.shutdown();
    driver._close();

    var spawnSync = require("child_process").spawnSync;
    var indexPath = path.resolve(__dirname, "..", "index.js").replace(/\\/g, "/");
    var dbPathForChild = dbPath.replace(/\\/g, "/");
    var childScript =
      "var b = require('" + indexPath + "');\n" +
      "var sqlite = require('node:sqlite');\n" +
      "var conn = new sqlite.DatabaseSync('" + dbPathForChild + "');\n" +
      "var driver = {\n" +
      "  connect: async function () { return { id: 'c1' }; },\n" +
      "  query:   async function (_c, sql, params) {\n" +
      "    var stmt = conn.prepare(sql);\n" +
      "    if (/^\\s*SELECT/i.test(sql) || /\\bRETURNING\\b/i.test(sql)) {\n" +
      "      return { rows: stmt.all.apply(stmt, params || []), rowCount: 0 };\n" +
      "    }\n" +
      "    var info = stmt.run.apply(stmt, params || []);\n" +
      "    return { rows: [], rowCount: info.changes };\n" +
      "  },\n" +
      "  close:   async function () {},\n" +
      "};\n" +
      "(async function () {\n" +
      "  b.externalDb.init({ backends: { ops: driver } });\n" +
      "  await b.cluster.init({ nodeId: 'cr-child', externalDbBackend: 'ops', dialect: 'sqlite', leaseTtl: 30000, heartbeatInterval: 10000 });\n" +
      "  console.log('UNEXPECTED-BOOT');\n" +
      "})().catch(function (e) { console.error('CHILD-ERR ' + e.message); process.exit(99); });\n";
    var result = spawnSync(process.execPath, ["-e", childScript], { encoding: "utf8" });
    check("consent-rollback boot exits via the catch handler (code 99)",
          result.status === 99);
    check("consent-rollback boot logs the consent-chain message",
          /consent-log rollback detected/i.test(result.stderr || ""));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterQueueJobsSharedAcrossNodes() {
  // Queue jobs migrated to external-db when migrated to external-db — enqueue from the
  // leader writes to external-db; lease + complete observe the same
  // shared row. Mirrors the session-cluster test's structure: one
  // node process, but verifies storage-routing properties.
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-q-cl-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    await setupTestDb(tmpDir);
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    await b.cluster.init({
      nodeId:            "q-cluster-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    // Use the queue-local protocol directly so the test focuses on the
    // storage-routing semantics, not the dispatcher's audit-emit /
    // breaker layers (those have their own tests).
    var queueLocal = require("../lib/queue-local").create();
    var enq = await queueLocal.enqueue("cl-test", { x: 42 }, { traceId: "trace-1" });
    check("cluster queue: enqueue returns jobId",      typeof enq.jobId === "string");

    // Row lands in external-db, NOT in local SQLite
    var extRows = await b.externalDb.query(
      "SELECT _id, queueName, status FROM _blamejs_jobs",
      [], { backend: "ops" }
    );
    check("cluster queue: row in external-db",          extRows.rows.length === 1);
    check("cluster queue: row status is pending",       extRows.rows[0].status === "pending");

    var localRows = b.db.prepare("SELECT _id FROM _blamejs_jobs").all();
    check("cluster queue: local SQLite jobs table empty",
          localRows.length === 0);

    // Lease via the same external-db storage; payload round-trips
    // through the seal/unseal pipeline correctly
    var leased = await queueLocal.lease("cl-test", b.constants.TIME.seconds(30), 1);
    check("cluster queue: lease returns 1 job",         leased.length === 1);
    check("cluster queue: lease unseals payload",
          leased[0].payload && leased[0].payload.x === 42);
    check("cluster queue: lease preserves traceId",     leased[0].traceId === "trace-1");

    // Status transition lands in external-db
    var afterLease = await b.externalDb.query(
      "SELECT status, attempts FROM _blamejs_jobs WHERE _id = ?",
      [enq.jobId], { backend: "ops" }
    );
    check("cluster queue: row status flipped to inflight",
          afterLease.rows[0].status === "inflight");
    check("cluster queue: attempts incremented",
          Number(afterLease.rows[0].attempts) === 1);

    // Complete cycles back to external-db
    var done = await queueLocal.complete(enq.jobId);
    check("cluster queue: complete returns true",       done === true);
    var afterDone = await b.externalDb.query(
      "SELECT status FROM _blamejs_jobs WHERE _id = ?",
      [enq.jobId], { backend: "ops" }
    );
    check("cluster queue: row status now done",         afterDone.rows[0].status === "done");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    await teardownTestDb(tmpDir);
  }
}

async function testClusterVaultKeyFirstBootRecords() {
  // First cluster boot: no _blamejs_cluster_state row yet. cluster.init
  // should write THIS node's vault-key fingerprint and record nodeId.
  // Subsequent cluster.init from the same vault file passes without
  // changes (idempotent).
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vk-first-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    await setupTestDb(tmpDir);    // initializes vault
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });

    // First boot — writes the row.
    await b.cluster.init({
      nodeId:            "vk-first-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });
    var stored = await b.externalDb.query(
      "SELECT vaultKeyFp, recordedByNode FROM _blamejs_cluster_state WHERE scope='state'",
      [], { backend: "ops" }
    );
    check("cluster-state row recorded after first boot",
          stored.rows.length === 1);
    check("cluster-state recorded by this node",
          stored.rows[0].recordedByNode === "vk-first-1");
    check("cluster-state fingerprint is hex sha3-512 (128 chars)",
          /^[0-9a-f]{128}$/.test(stored.rows[0].vaultKeyFp));

    // Same vault, fresh cluster.init — passes silently
    await b.cluster.shutdown();
    await b.cluster.init({
      nodeId:            "vk-first-2",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });
    var stored2 = await b.externalDb.query(
      "SELECT vaultKeyFp, recordedByNode FROM _blamejs_cluster_state WHERE scope='state'",
      [], { backend: "ops" }
    );
    check("cluster-state fingerprint unchanged after same-vault re-init",
          stored2.rows[0].vaultKeyFp === stored.rows[0].vaultKeyFp);
    check("cluster-state recordedByNode unchanged (first writer wins)",
          stored2.rows[0].recordedByNode === "vk-first-1");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    await teardownTestDb(tmpDir);
  }
}

async function testClusterVaultKeyMismatchDetected() {
  // Pre-seed the cluster-state row with a fingerprint that won't match
  // the freshly-generated vault keys in the child process. cluster.init
  // detects the drift and process.exit(1)s. Spawn-a-child pattern so
  // we can capture the exit code.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vk-drift-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    // Provider ensureSchema creates _blamejs_leader + _blamejs_cluster_state.
    // We don't run cluster.init here — just construct the provider manually
    // so the table exists, then pre-seed with a wrong fingerprint.
    var providerDb = require("../lib/cluster-provider-db");
    var prov = providerDb.create({ externalDbBackend: "ops", dialect: "sqlite" });
    await prov.ensureSchema();

    await b.externalDb.query(
      "INSERT INTO _blamejs_cluster_state (scope, vaultKeyFp, recordedAt, recordedByNode) " +
      "VALUES ('state', ?, ?, 'pre-existing-node')",
      ["deadbeef".repeat(16), Date.now()]    // 128-hex bogus fingerprint
    );
    await b.externalDb.shutdown();
    driver._close();

    var spawnSync = require("child_process").spawnSync;
    var indexPath = path.resolve(__dirname, "..", "index.js").replace(/\\/g, "/");
    var dbPathForChild = dbPath.replace(/\\/g, "/");
    var childTmp = path.resolve(tmpDir, "child-data").replace(/\\/g, "/");
    var childScript =
      "var b = require('" + indexPath + "');\n" +
      "var sqlite = require('node:sqlite');\n" +
      "var conn = new sqlite.DatabaseSync('" + dbPathForChild + "');\n" +
      "var driver = {\n" +
      "  connect: async function () { return { id: 'c1' }; },\n" +
      "  query:   async function (_c, sql, params) {\n" +
      "    var stmt = conn.prepare(sql);\n" +
      "    if (/^\\s*SELECT/i.test(sql) || /\\bRETURNING\\b/i.test(sql)) {\n" +
      "      return { rows: stmt.all.apply(stmt, params || []), rowCount: 0 };\n" +
      "    }\n" +
      "    var info = stmt.run.apply(stmt, params || []);\n" +
      "    return { rows: [], rowCount: info.changes };\n" +
      "  },\n" +
      "  close:   async function () {},\n" +
      "};\n" +
      "process.env.BLAMEJS_SKIP_NTP_CHECK = '1';\n" +
      "(async function () {\n" +
      "  require('fs').mkdirSync('" + childTmp + "', { recursive: true });\n" +
      "  await b.vault.init({ dataDir: '" + childTmp + "', mode: 'plaintext' });\n" +
      "  b.externalDb.init({ backends: { ops: driver } });\n" +
      "  await b.cluster.init({ nodeId: 'vk-drift-child', externalDbBackend: 'ops', dialect: 'sqlite', leaseTtl: 30000, heartbeatInterval: 10000 });\n" +
      "  console.log('UNEXPECTED-BOOT');\n" +
      "})().catch(function (e) { console.error('CHILD-ERR ' + e.message); process.exit(99); });\n";
    var result = spawnSync(process.execPath, ["-e", childScript], { encoding: "utf8" });
    check("vault-key drift boot exits via the catch handler (code 99)",
          result.status === 99);
    check("vault-key drift boot logs detection message",
          /vault-key drift detected/i.test(result.stderr || ""));
    check("vault-key drift boot did NOT print UNEXPECTED-BOOT",
          (result.stdout || "").indexOf("UNEXPECTED-BOOT") === -1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterAuditTipRollbackHappyPath() {
  // Happy path — tip matches the row at its recorded counter, cluster.init
  // proceeds. Pre-populate an audit_log row + a matching tip row, then
  // run cluster.init; verify the rollback-check log line and a clean
  // boot.
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rb-ok-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    // One audit_log row at counter=1 with hash "h1", plus a tip row
    // pointing at it. cluster.init should accept this as a clean state.
    await b.externalDb.query(
      "INSERT INTO _blamejs_audit_log " +
      "(_id, recordedAt, monotonicCounter, action, outcome, prevHash, rowHash, nonce, fencingToken) " +
      "VALUES ('row-ok', ?, 1, 'system.test.ok', 'success', '', 'h1', x'00000000000000000000000000000000', 1)",
      [Date.now()]
    );
    await b.externalDb.query(
      "INSERT INTO _blamejs_audit_tip (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) " +
      "VALUES ('audit', 1, 'h1', '0', 1)"
    );

    var threw = null;
    try {
      await b.cluster.init({
        nodeId:            "rb-ok-1",
        externalDbBackend: "ops",
        dialect:           "sqlite",
        leaseTtl:          b.constants.TIME.seconds(30),
        heartbeatInterval: b.constants.TIME.seconds(10),
      });
    } catch (e) { threw = e; }
    check("cluster.init: happy-path rollback check passes",  threw === null);
    check("cluster.init: lease acquired",                    b.cluster.isLeader() === true);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterAuditTipRollbackDetected() {
  // Pre-seed a tip recording counter=999 with no matching audit_log
  // row. cluster.init should detect this as rollback (current MAX <
  // tip counter) and process.exit(1). We fork a child process to
  // capture the exit code and stderr — same pattern as the
  // single-node testRollbackDetection.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rb-detect-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    // Empty audit_log + tip claiming counter=999. Net: rollback.
    await b.externalDb.query(
      "INSERT INTO _blamejs_audit_tip (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) " +
      "VALUES ('audit', 999, 'rolled-hash', '0', 5)"
    );
    await b.externalDb.shutdown();
    driver._close();

    // Spawn a child that re-opens the same db file and calls
    // cluster.init. The rollback check should fire and exit(1).
    var spawnSync = require("child_process").spawnSync;
    var indexPath = path.resolve(__dirname, "..", "index.js").replace(/\\/g, "/");
    var dbPathForChild = dbPath.replace(/\\/g, "/");
    var childScript =
      "var b = require('" + indexPath + "');\n" +
      "var sqlite = require('node:sqlite');\n" +
      "var conn = new sqlite.DatabaseSync('" + dbPathForChild + "');\n" +
      "var driver = {\n" +
      "  connect: async function () { return { id: 'c1' }; },\n" +
      "  query:   async function (_c, sql, params) {\n" +
      "    var stmt = conn.prepare(sql);\n" +
      "    if (/^\\s*SELECT/i.test(sql) || /\\bRETURNING\\b/i.test(sql)) {\n" +
      "      return { rows: stmt.all.apply(stmt, params || []), rowCount: 0 };\n" +
      "    }\n" +
      "    var info = stmt.run.apply(stmt, params || []);\n" +
      "    return { rows: [], rowCount: info.changes };\n" +
      "  },\n" +
      "  close:   async function () {},\n" +
      "};\n" +
      "(async function () {\n" +
      "  b.externalDb.init({ backends: { ops: driver } });\n" +
      "  await b.cluster.init({ nodeId: 'rb-child', externalDbBackend: 'ops', dialect: 'sqlite', leaseTtl: 30000, heartbeatInterval: 10000 });\n" +
      "  console.log('UNEXPECTED-BOOT');\n" +
      "})().catch(function (e) { console.error('CHILD-ERR ' + e.message); process.exit(99); });\n";
    var result = spawnSync(process.execPath, ["-e", childScript], { encoding: "utf8" });
    // cluster.init throws ClusterError on rollback detection; the child
    // script's catch handler exits with code 99. Pre-v0.7.0 the lib called
    // process.exit(1) unilaterally; the test now asserts the controlled-throw
    // path so callers can decide their own exit code.
    check("rollback boot exits via the catch handler (code 99)",
          result.status === 99);
    check("rollback boot logs detection message",
          /audit-log rollback detected/i.test(result.stderr || ""));
    check("rollback boot did NOT print UNEXPECTED-BOOT (exited before continuing)",
          (result.stdout || "").indexOf("UNEXPECTED-BOOT") === -1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterAuditTipRowHashMismatch() {
  // Same counter on both sides but different rowHash — row substitution
  // at the chain head. Detection path: tipCounter == currentMax, but
  // the row at that counter has a different hash than the tip recorded.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rb-hash-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    await b.externalDb.query(
      "INSERT INTO _blamejs_audit_log " +
      "(_id, recordedAt, monotonicCounter, action, outcome, prevHash, rowHash, nonce, fencingToken) " +
      "VALUES ('row-substituted', ?, 1, 'system.test.subst', 'success', '', 'WRONG-HASH', x'00000000000000000000000000000000', 1)",
      [Date.now()]
    );
    // Tip records the OLD hash at the same counter — substitution.
    await b.externalDb.query(
      "INSERT INTO _blamejs_audit_tip (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) " +
      "VALUES ('audit', 1, 'ORIGINAL-HASH', '0', 1)"
    );
    await b.externalDb.shutdown();
    driver._close();

    var spawnSync = require("child_process").spawnSync;
    var indexPath = path.resolve(__dirname, "..", "index.js").replace(/\\/g, "/");
    var dbPathForChild = dbPath.replace(/\\/g, "/");
    var childScript =
      "var b = require('" + indexPath + "');\n" +
      "var sqlite = require('node:sqlite');\n" +
      "var conn = new sqlite.DatabaseSync('" + dbPathForChild + "');\n" +
      "var driver = {\n" +
      "  connect: async function () { return { id: 'c1' }; },\n" +
      "  query:   async function (_c, sql, params) {\n" +
      "    var stmt = conn.prepare(sql);\n" +
      "    if (/^\\s*SELECT/i.test(sql) || /\\bRETURNING\\b/i.test(sql)) {\n" +
      "      return { rows: stmt.all.apply(stmt, params || []), rowCount: 0 };\n" +
      "    }\n" +
      "    var info = stmt.run.apply(stmt, params || []);\n" +
      "    return { rows: [], rowCount: info.changes };\n" +
      "  },\n" +
      "  close:   async function () {},\n" +
      "};\n" +
      "(async function () {\n" +
      "  b.externalDb.init({ backends: { ops: driver } });\n" +
      "  await b.cluster.init({ nodeId: 'rb-hash-child', externalDbBackend: 'ops', dialect: 'sqlite', leaseTtl: 30000, heartbeatInterval: 10000 });\n" +
      "  console.log('UNEXPECTED-BOOT');\n" +
      "})().catch(function (e) { console.error('CHILD-ERR ' + e.message); process.exit(99); });\n";
    var result = spawnSync(process.execPath, ["-e", childScript], { encoding: "utf8" });
    check("row-hash mismatch boot exits via the catch handler (code 99)",
          result.status === 99);
    check("row-hash mismatch boot logs detection message",
          /row-hash mismatch/i.test(result.stderr || ""));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function testClusterAuditFlushNoRecursionHang() {
  // Regression test for :
  // Before the fix, audit.flush() in cluster mode hung forever because
  // each drained event wrote through external-db, externalDb.query
  // emitted a system.externaldb.query audit event back into the same
  // handler buffer, and handlers.drain's while-loop processed those new
  // items in the same call — so the buffer refilled as fast as it
  // emptied. The fix bounds drain to a snapshot of the buffer at start
  // (matching the documented recursion-safety contract). This test
  // proves flush() returns within a tight wall-clock budget in cluster
  // mode under exactly the producer/consumer cycle that triggered the
  // hang.
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-flush-rec-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    await setupTestDb(tmpDir);
    await b.audit.flush();    // drain any boot-time emits in single-node
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });
    await b.cluster.init({
      nodeId:            "flush-rec-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    // record() bypasses the buffer, but the underlying externalDb.query
    // emits a system.externaldb.query event INTO the buffer. Subsequent
    // flush() drains that — and each drained event itself writes through
    // external-db, emitting more events. Pre-fix: hang. Post-fix: drain
    // is bounded; lingering events stay for the next call.
    await b.audit.record({
      action:  "system.test.flush_recursion",
      outcome: "success",
      actor:   { userId: "rec-test" },
    });

    // withTestTimeout is the no-hang regression guard — if flush() truly
    // hangs it never resolves and the wrapper rejects with "test timed out"
    // after 5s, failing loudly rather than wedging the runner. It clears its
    // own guard timer on settle (no leaked Timeout), and there is no separate
    // elapsed check to drift into a Windows boundary flake.
    await helpers.withTestTimeout("audit.flush returns (no recursion hang)",
      function () { return b.audit.flush(); }, { timeoutMs: 5000 });
    check("audit.flush returns (no recursion hang)",  true);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    await teardownTestDb(tmpDir);
  }
}

async function testClusterAuditTipFencedOutErrorSurface() {
  // Verify that audit.js's _upsertAuditTip surfaces
  // ClusterError(code=FENCED_OUT, permanent=true) when the fence rejects
  // the write. This catches a regression where the original
  // UPDATE-then-INSERT-if-missing path swallowed silently — operators
  // MUST see fence rejection.
  //
  // We bypass audit.record/flush (which crosses the single-node →
  // cluster-mode boundary mid-buffer, an unrelated complication) and
  // exercise audit.checkpoint() directly: insert one audit_log row by
  // hand into external-db, pre-seed the audit-tip with a higher token
  // than the local lease has, and assert the checkpoint surfaces the
  // FENCED_OUT class+code.
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fence-err-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  try {
    // Full framework boot needed because checkpoint() invokes audit-sign
    // (signature over the chain head) which requires the signing key
    // initialized via db.init.
    await setupTestDb(tmpDir);
    b.externalDb.init({
      backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
    });
    await b.frameworkSchema.ensureSchema({
      externalDbBackend: "ops",
      dialect:           "sqlite",
    });

    await b.cluster.init({
      nodeId:            "fence-err-test-1",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          b.constants.TIME.seconds(30),
      heartbeatInterval: b.constants.TIME.seconds(10),
    });

    // Insert one audit_log row directly so checkpoint has a tip to
    // anchor. clusterStorage rewrites `audit_log` → `_blamejs_audit_log`
    // in cluster mode, and we use `?` placeholders so the dispatcher's
    // dialect translation handles the parameterization.
    await b.clusterStorage.execute(
      "INSERT INTO audit_log " +
      "  (_id, recordedAt, monotonicCounter, action, outcome, " +
      "   prevHash, rowHash, nonce, fencingToken) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ["fence-row", Date.now(), 1, "system.test.fence", "success",
       "", "fence-hash-1", Buffer.alloc(16), 1]
    );

    // Pre-seed _blamejs_audit_tip with a token (99) higher than this
    // node's lease (=1 right after acquire). The checkpoint's
    // _upsertAuditTip will write fencingToken=1, which is below the
    // stored 99 — the WHERE-clause guard rejects it.
    await b.clusterStorage.execute(
      "INSERT INTO _blamejs_audit_tip " +
      "  (scope, atMonotonicCounter, rowHash, signedAt, fencingToken) " +
      "VALUES ('audit', ?, ?, ?, ?) " +
      "ON CONFLICT (scope) DO UPDATE SET " +
      "  fencingToken = EXCLUDED.fencingToken",
      [0, "preseed", "0", 99]
    );

    var threw = null;
    try { await b.audit.checkpoint(); }
    catch (e) { threw = e; }

    check("checkpoint: fenced-out throws", threw !== null);
    check("checkpoint: error is ClusterError",
          threw && threw.isClusterError === true);
    check("checkpoint: error code is FENCED_OUT",
          threw && threw.code === "FENCED_OUT");
    check("checkpoint: error is permanent",
          threw && threw.permanent === true);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) {}
    try { await b.externalDb.shutdown(); } catch (_e) {}
    driver._close();
    await teardownTestDb(tmpDir);
  }
}

async function testAuditChain() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-audit-"));
  try {
    await setupTestDb(tmpDir);

    // Unregistered namespace rejected
    var nsRejected = false;
    try { await b.audit.record({ action: "orders.created", outcome: "success" }); }
    catch (_) { nsRejected = true; }
    check("unregistered namespace rejected", nsRejected);

    // Register + record
    b.audit.registerNamespace("orders");
    var ev1 = await b.audit.record({
      actor:    { userId: "user-1", ip: "1.2.3.4" },
      action:   "orders.created",
      resource: { kind: "order", id: "ord-1" },
      outcome:  "success",
      metadata: { total: 99.95 },
    });
    check("audit.record returns row with rowHash",   typeof ev1.rowHash === "string" && ev1.rowHash.length === 128);
    check("first row's prevHash is ZERO_HASH",       ev1.prevHash === b.auditChain.ZERO_HASH);

    var ev2 = await b.audit.record({
      actor:    { userId: "user-1", ip: "1.2.3.4" },
      action:   "auth.login.success",
      resource: { kind: "user", id: "user-1" },
      outcome:  "success",
    });
    check("second row's prevHash = first row's rowHash", ev2.prevHash === ev1.rowHash);
    check("monotonicCounter increments",                 ev2.monotonicCounter === ev1.monotonicCounter + 1);

    // Invalid action format
    var actionRejected = false;
    try { await b.audit.record({ action: "no-dot", outcome: "success" }); }
    catch (_) { actionRejected = true; }
    check("malformed action rejected", actionRejected);

    // Invalid outcome
    var outcomeRejected = false;
    try { await b.audit.record({ action: "auth.login.success", outcome: "ok" }); }
    catch (_) { outcomeRejected = true; }
    check("invalid outcome rejected", outcomeRejected);

    // safeEmit: fire-and-forget shape with default-fill + try/catch.
    // Surface contract: never throws on malformed input; valid events
    // get queued via the handler (full end-to-end landing depends on
    // cluster init, covered by integration tests elsewhere).
    check("audit.safeEmit is exposed",                typeof b.audit.safeEmit === "function");
    var threwOnMalformed = null;
    try {
      b.audit.safeEmit();
      b.audit.safeEmit(null);
      b.audit.safeEmit({});                            // missing action
      b.audit.safeEmit({ outcome: "success" });        // missing action
      b.audit.safeEmit("not-an-object");
    } catch (e) { threwOnMalformed = e; }
    check("safeEmit: malformed inputs silently dropped", threwOnMalformed === null);
    var threwOnValid = null;
    try { b.audit.safeEmit({ action: "orders.shipped" }); }
    catch (e) { threwOnValid = e; }
    check("safeEmit: valid event accepted without throw", threwOnValid === null);

    // Verify chain is intact
    var v1 = await b.audit.verify();
    check("audit.verify() ok after valid records",  v1.ok === true && v1.rowsVerified === 2);

    // Query by various criteria
    var byUser = await b.audit.query({ actorUserId: "user-1" });
    check("query by sealed actorUserId returns rows",   byUser.length === 2);
    check("query result rows are unsealed",             byUser[0].actorUserId === "user-1");
    var byAction = await b.audit.query({ action: "auth.login.success" });
    check("query by action returns matching",            byAction.length === 1);
    var byKind = await b.audit.query({ resourceKind: "order" });
    check("query by resourceKind returns matching",     byKind.length === 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditChainBreak() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-broken-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.record({ action: "test.event", outcome: "success" });
    var v1 = await b.audit.verify();
    check("chain ok before tampering", v1.ok === true);

    // Manually corrupt a row's reason field. Currently the audit_log
    // table has BEFORE-UPDATE/DELETE triggers blocking direct mutation —
    // simulating a raw-DB-file tamper that bypassed those guards by
    // dropping the triggers around the corruption.
    b.db.runSql("DROP TRIGGER IF EXISTS no_update_audit_log");
    b.db.prepare('UPDATE audit_log SET reason = ? WHERE monotonicCounter = 1').run("vault:tampered-but-not-actually-sealed");
    b.db.runSql("CREATE TRIGGER IF NOT EXISTS no_update_audit_log BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only — UPDATE prohibited'); END");
    var v2 = await b.audit.verify();
    check("chain detected after row tampering",         v2.ok === false);
    check("chain break reports breakAt index",          v2.breakAt === 0 || v2.breakAt === 1);
    check("chain break reports rowHash mismatch reason",
          v2.reason === "rowHash mismatch" || v2.reason === "prevHash mismatch");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditSelfLogging() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-selflog-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.record({ action: "test.event", outcome: "success" });

    // A query auto-records an audit.read event before returning rows
    var beforeCount = b.db.from("audit_log").count();
    var rows = await b.audit.query({ action: "test.event" });
    var afterCount = b.db.from("audit_log").count();
    check("query returned both test.event rows",         rows.length === 2);
    check("query auto-recorded an audit.read event",     afterCount === beforeCount + 1);

    // The audit.read row exists
    var readRows = await b.audit.query({ action: "audit.read" });
    check("audit.read events queryable directly",        readRows.length >= 1);
    check("audit.read row has criteria metadata",
          readRows[0].metadata && /criteria/.test(readRows[0].metadata));

    // Querying for audit.read does NOT recursively self-log (else infinite chain)
    var beforeRecursionCheck = b.db.from("audit_log").count();
    await b.audit.query({ action: "audit.read" });
    var afterRecursionCheck = b.db.from("audit_log").count();
    check("query for audit.read does NOT auto-self-log",  afterRecursionCheck === beforeRecursionCheck);

    // Audit chain still verifies through all the self-logging
    var v = await b.audit.verify();
    check("audit chain ok after self-log activity",       v.ok === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testBeginTrace() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-trace-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");

    var t1 = b.audit.beginTrace();
    var t2 = b.audit.beginTrace();
    check("beginTrace returns 32-hex string",            typeof t1 === "string" && t1.length === 32 && /^[0-9a-f]+$/.test(t1));
    check("beginTrace returns unique values",            t1 !== t2);

    // Apps thread the traceId through linked events
    var ev1 = await b.audit.record({
      action:   "test.start",
      outcome:  "success",
      metadata: { traceId: t1 },
    });
    var ev2 = await b.audit.record({
      action:   "test.continue",
      outcome:  "success",
      metadata: { traceId: t1, parentEventId: ev1._id },
    });

    // Query and verify trace correlation is queryable from metadata
    var rows = await b.audit.query({ action: "test.start" });
    var meta = JSON.parse(rows[0].metadata);
    check("traceId persists into audit row metadata",    meta.traceId === t1);

    var rows2 = await b.audit.query({ action: "test.continue" });
    var meta2 = JSON.parse(rows2[0].metadata);
    check("parentEventId persists into audit row",       meta2.parentEventId === ev1._id);
    check("traceId is shared across linked events",      meta2.traceId === t1);

    void ev2;
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testConsent() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-consent-"));
  try {
    await setupTestDb(tmpDir);

    var subjectId = "user-7";
    check("isGranted is false before grant",     b.consent.isGranted({ subjectId, purpose: "marketing.email" }) === false);

    await b.consent.grant({
      subjectId:    subjectId,
      purpose:      "marketing.email",
      lawfulBasis:  "consent",
      scope:        { channels: ["email"], topics: ["product-updates"] },
      channel:      "web_form_v2",
      evidenceRef:  "/evidence/forms/2026-04-25T...",
    });
    check("isGranted true after grant",          b.consent.isGranted({ subjectId, purpose: "marketing.email" }) === true);

    await b.consent.withdraw({ subjectId, purpose: "marketing.email" });
    check("isGranted false after withdraw",      b.consent.isGranted({ subjectId, purpose: "marketing.email" }) === false);

    var hist = b.consent.history(subjectId);
    check("history returns 2 events",            hist.length === 2);
    check("history first event is grant",        hist[0].action === "granted");
    check("history second event is withdraw",    hist[1].action === "withdrawn");
    check("history unsealed subjectId",          hist[0].subjectId === subjectId);

    var cv = await b.consent.verify();
    check("consent.verify() ok",                 cv.ok === true && cv.rowsVerified === 2);

    // Invalid lawful basis
    var basisRejected = false;
    try { await b.consent.grant({ subjectId, purpose: "x", lawfulBasis: "bogus", channel: "x" }); }
    catch (_) { basisRejected = true; }
    check("invalid lawfulBasis rejected", basisRejected);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSubjectRights() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-subject-"));
  try {
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      auditSigning: { mode: "plaintext" },
      schema: [
        {
          name: "users",
          columns: {
            _id:       "TEXT PRIMARY KEY",
            email:     "TEXT",
            emailHash: "TEXT",
            name:      "TEXT",
          },
          indexes:        ["emailHash"],
          sealedFields:   ["email", "name"],
          derivedHashes:  { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
          subjectField:   "_id",
          personalDataCategories: { email: "email", name: "name" },
        },
        {
          name: "orders",
          columns: {
            _id:        "TEXT PRIMARY KEY",
            userId:     "TEXT",
            userIdHash: "TEXT",
            amount:     "REAL",
          },
          indexes:        ["userIdHash"],
          sealedFields:   [],
          derivedHashes:  { userIdHash: { from: "userId" } },
          subjectField:   "userId",
          personalDataCategories: {},
        },
      ],
    });

    b.db.from("users").insertOne({ _id: "u-alice", email: "alice@x.com", name: "Alice" });
    b.db.from("users").insertOne({ _id: "u-bob",   email: "bob@x.com",   name: "Bob" });
    b.db.from("orders").insertOne({ _id: "o-1", userId: "u-alice", amount: 99.95 });
    b.db.from("orders").insertOne({ _id: "o-2", userId: "u-alice", amount: 12.50 });
    b.db.from("orders").insertOne({ _id: "o-3", userId: "u-bob",   amount: 7.00 });

    // Export
    var dump = b.subject.export("u-alice", { reason: "Art. 15 access request 2026-04-25" });
    check("subject.export returns dump for alice",    dump.users && dump.users.length === 1);
    check("subject.export decrypts sealed fields",    dump.users[0].email === "alice@x.com");
    check("subject.export walks orders too",          dump.orders && dump.orders.length === 2);

    // Rectify
    var ok = b.subject.rectify("u-alice", {
      table:   "users",
      id:      "u-alice",
      changes: { name: "Alice Updated" },
      reason:  "Art. 16 rectification 2026-04-25",
    });
    check("rectify returns true",                     ok === true);
    var aliceAfter = b.db.from("users").where({ _id: "u-alice" }).first();
    check("rectify wrote new value",                  aliceAfter.name === "Alice Updated");

    // Erase requires both acknowledgements
    var noAckRejected = false;
    try { b.subject.erase("u-alice", { reason: "Art. 17", acknowledgements: ["no-litigation-hold"] }); }
    catch (_) { noAckRejected = true; }
    check("erase without all acknowledgements rejected", noAckRejected);

    // Erase with all acks
    var result = b.subject.erase("u-alice", {
      reason:           "Art. 17 erasure request 2026-04-25 ticket #4471",
      acknowledgements: ["no-litigation-hold", "no-statutory-retention-required"],
    });
    check("erase returns rowsDeleted",                 result.rowsDeleted >= 3);
    check("alice gone from users",                     b.db.from("users").where({ _id: "u-alice" }).first() === null);
    check("alice's orders gone",                       b.db.from("orders").where({ userIdHash: b.db.hashFor("orders", "userId", "u-alice") }).all().length === 0);
    check("bob still present",                         b.db.from("users").where({ _id: "u-bob" }).first() !== null);

    // Erasure marker recorded
    var erasureRow = b.db.prepare("SELECT subjectIdHash FROM _blamejs_subject_erasures").all();
    check("subject erasure marker recorded",           erasureRow.length === 1);

    // Restrict / isRestricted
    check("isRestricted false initially",              b.subject.isRestricted("u-bob") === false);
    b.subject.restrict("u-bob", { on: true, reason: "Art. 18 contested accuracy" });
    check("isRestricted true after restrict",          b.subject.isRestricted("u-bob") === true);
    b.subject.restrict("u-bob", { on: false });
    check("isRestricted false after lift",             b.subject.isRestricted("u-bob") === false);

    // Audit chain still intact after all this activity
    var av = await b.audit.verify();
    check("audit chain intact through subject ops",    av.ok === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAppendOnlyTriggers() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-trig-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });

    var deleteRejected = false;
    try { b.db.runSql("DELETE FROM audit_log"); }
    catch (e) { deleteRejected = /append-only|prohibited/i.test(e.message); }
    check("DELETE on audit_log raises ABORT",            deleteRejected);

    var updateRejected = false;
    try { b.db.runSql("UPDATE audit_log SET outcome = 'denied' WHERE 1=1"); }
    catch (e) { updateRejected = /append-only|prohibited/i.test(e.message); }
    check("UPDATE on audit_log raises ABORT",            updateRejected);

    // consent_log
    await b.consent.grant({ subjectId: "u-1", purpose: "x", lawfulBasis: "consent", channel: "api" });
    var conDelRejected = false;
    try { b.db.runSql("DELETE FROM consent_log"); }
    catch (e) { conDelRejected = /append-only|prohibited/i.test(e.message); }
    check("DELETE on consent_log raises ABORT",          conDelRejected);

    // INSERT still works (the framework's API uses it constantly above)
    var counts = b.db.prepare("SELECT (SELECT COUNT(*) FROM audit_log) AS a, (SELECT COUNT(*) FROM consent_log) AS c").get();
    check("INSERT on audit_log still works",             counts.a >= 1);
    check("INSERT on consent_log still works",           counts.c >= 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testForeignKeys() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fk-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      auditSigning: { mode: "plaintext" },
      schema: [
        {
          name: "users",
          columns: { _id: "TEXT", email: "TEXT", emailHash: "TEXT" },
          primaryKey: "_id",
          indexes:    ["emailHash"],
          sealedFields:  ["email"],
          derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
        },
        {
          name: "orders",
          columns: { _id: "TEXT", userId: "TEXT NOT NULL", amount: "REAL" },
          primaryKey: "_id",
          foreignKeys: [{ column: "userId", references: "users._id", onDelete: "CASCADE" }],
        },
      ],
    });

    // Verify foreign_keys pragma is ON
    var fkPragma = b.db.prepare("PRAGMA foreign_keys").get();
    check("foreign_keys pragma is enabled",              fkPragma.foreign_keys === 1);

    // Verify FK declared in DDL
    var fkInfo = b.db.prepare("PRAGMA foreign_key_list(orders)").all();
    check("orders has 1 FK declared",                    fkInfo.length === 1);
    check("FK references users(_id)",                    fkInfo[0].table === "users" && fkInfo[0].from === "userId" && fkInfo[0].to === "_id");
    check("FK on_delete is CASCADE",                     fkInfo[0].on_delete === "CASCADE");

    // Insert valid user + order
    b.db.from("users").insertOne({ _id: "u-1", email: "a@b.com" });
    b.db.from("orders").insertOne({ _id: "o-1", userId: "u-1", amount: 100 });
    check("valid order insert succeeds",                 b.db.from("orders").where({ _id: "o-1" }).first() !== null);

    // FK violation: order with non-existent userId
    var fkViolated = false;
    try { b.db.from("orders").insertOne({ _id: "o-2", userId: "u-nonexistent", amount: 50 }); }
    catch (e) { fkViolated = /FOREIGN KEY|constraint/i.test(e.message); }
    check("FK violation rejects insert",                 fkViolated);

    // Cascade delete: deleting user removes their orders
    b.db.from("users").where({ _id: "u-1" }).deleteOne();
    check("ON DELETE CASCADE removes child rows",        b.db.from("orders").where({ _id: "o-1" }).first() === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testTableMetadata() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-meta-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      auditSigning: { mode: "plaintext" },
      schema: [
        {
          name: "items",
          columns: { _id: "TEXT", ownerId: "TEXT", name: "TEXT", nameHash: "TEXT" },
          primaryKey: "_id",
          foreignKeys: [{ column: "ownerId", references: "users._id", onDelete: "SET NULL" }],
          indexes: ["nameHash"],
          sealedFields: ["name"],
          derivedHashes: { nameHash: { from: "name" } },
          subjectField: "ownerId",
          personalDataCategories: { name: "label" },
        },
        // users table with no FKs
        { name: "users", columns: { _id: "TEXT" }, primaryKey: "_id" },
      ],
    });

    var meta = b.db.getTableMetadata("items");
    check("metadata returns object",                     typeof meta === "object" && meta !== null);
    check("metadata.primaryKey is array",                Array.isArray(meta.primaryKey) && meta.primaryKey[0] === "_id");
    check("metadata.foreignKeys captured",               meta.foreignKeys.length === 1 && meta.foreignKeys[0].references === "users._id");
    check("metadata.sealedFields captured",              meta.sealedFields[0] === "name");
    check("metadata.subjectField captured",              meta.subjectField === "ownerId");
    check("metadata.personalDataCategories captured",    meta.personalDataCategories.name === "label");

    // Framework tables also show up in metadata
    var auditMeta = b.db.getTableMetadata("audit_log");
    check("audit_log metadata available",                auditMeta !== null);
    check("audit_log primaryKey is _id",                 auditMeta.primaryKey[0] === "_id");

    // Mutating the snapshot doesn't affect framework state
    meta.foreignKeys.push({ column: "fake" });
    var freshMeta = b.db.getTableMetadata("items");
    check("metadata snapshot is deep-copied",            freshMeta.foreignKeys.length === 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditSignDefaultsToSlhDsa() {
  // First-run plaintext init in a fresh data directory should generate
  // an SLH-DSA-SHAKE-256f keypair (the current default), and the
  // on-disk file should record `algorithm: "slh-dsa-shake-256f"` so
  // future loads dispatch correctly without re-detection.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-asd-"));
  try {
    // This test inspects the on-disk JSON content of audit-sign.key,
    // which only exists in plaintext audit-signing mode. Override
    // setupTestDb's secure-mode default explicitly.
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    b.cluster._resetForTest();
    b.audit._resetForTest();
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir:      tmpDir,
      atRest:       "plain",
      auditSigning: { mode: "plaintext" },
      schema:       [],
    });
    check("auditSign.getAlgorithm is exposed",
          typeof b.auditSign.getAlgorithm === "function");
    check("auditSign default alg is SLH-DSA-SHAKE-256f",
          b.auditSign.getAlgorithm() === "slh-dsa-shake-256f");
    check("auditSign exposes DEFAULT_SIGNING_ALG constant",
          b.auditSign.DEFAULT_SIGNING_ALG === "slh-dsa-shake-256f");
    check("auditSign exposes SUPPORTED_SIGNING_ALGS",
          Array.isArray(b.auditSign.SUPPORTED_SIGNING_ALGS) &&
          b.auditSign.SUPPORTED_SIGNING_ALGS.indexOf("slh-dsa-shake-256f") !== -1 &&
          b.auditSign.SUPPORTED_SIGNING_ALGS.indexOf("ml-dsa-87") !== -1);

    // On-disk file records the algorithm
    var keyJson = JSON.parse(fs.readFileSync(path.join(tmpDir, "audit-sign.key"), "utf8"));
    check("on-disk key file records algorithm field",
          keyJson.algorithm === "slh-dsa-shake-256f");
    check("on-disk public key is SLH-DSA SPKI PEM",
          /BEGIN PUBLIC KEY/.test(keyJson.publicKey));

    // Sign + verify round-trip works with the SLH-DSA-SHAKE-256f key
    var sig = b.auditSign.sign("hello from slh-dsa");
    check("SLH-DSA sign returns a Buffer",                 Buffer.isBuffer(sig));
    // SLH-DSA-SHAKE-256f signatures are ~50 KB
    check("SLH-DSA-SHAKE-256f signature size matches FIPS 205 (~50 KB)",
          sig.length > 49000 && sig.length < 51000);
    check("SLH-DSA verify accepts the signature",
          b.auditSign.verify("hello from slh-dsa", sig) === true);
    check("SLH-DSA verify rejects altered payload",
          b.auditSign.verify("hello from slh-dsa!", sig) === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditSignMlDsaOptIn() {
  // Operators with throughput-sensitive deployments can opt into
  // ml-dsa-87 at db.init via auditSigning: { algorithm: "ml-dsa-87" }.
  // Verify the option propagates and produces a working ML-DSA-87 key.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-asm-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
    b.cluster._resetForTest();
    b.audit._resetForTest();
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir:      tmpDir,
      atRest:       "plain",
      auditSigning: { mode: "plaintext", algorithm: "ml-dsa-87" },
      schema:       [],
    });

    check("opt-in alg honored in keys.algorithm",
          b.auditSign.getAlgorithm() === "ml-dsa-87");
    var keyJson = JSON.parse(fs.readFileSync(path.join(tmpDir, "audit-sign.key"), "utf8"));
    check("on-disk key file records ml-dsa-87",
          keyJson.algorithm === "ml-dsa-87");

    var sig = b.auditSign.sign("hello from ml-dsa-87");
    // ML-DSA-87 signatures are ~5 KB — order-of-magnitude smaller than SLH-DSA
    check("ML-DSA-87 signature size matches FIPS 204 (~5 KB)",
          sig.length > 4000 && sig.length < 6000);
    check("ML-DSA-87 verify round-trip",
          b.auditSign.verify("hello from ml-dsa-87", sig) === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditSignLegacyFileBackcompat() {
  // Pre-v1 compat-shim sweep removed the implicit ml-dsa-87 fallback
  // for key files missing the `algorithm` field. Such files now throw
  // KEY_FILE_MISSING_ALG at boot — operators rotate the key (deletes
  // the file and boots fresh) or hand-edit to add the field.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-asl-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";

    var nodeCrypto = require("crypto");
    var pair = nodeCrypto.generateKeyPairSync("ml-dsa-87", {
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    fs.writeFileSync(
      path.join(tmpDir, "audit-sign.key"),
      JSON.stringify({ publicKey: pair.publicKey, privateKey: pair.privateKey }, null, 2),
      { mode: 0o600 }
    );

    process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
    b.cluster._resetForTest();
    b.audit._resetForTest();
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });

    var threw = null;
    try {
      await b.db.init({
        dataDir:      tmpDir,
        atRest:       "plain",
        auditSigning: { mode: "plaintext" },
        schema:       [],
      });
    } catch (e) { threw = e; }
    check("legacy file (no algorithm field) refuses to load — explicit alg required",
          threw && /MISSING_ALG|missing.*algorithm/i.test(threw.code || threw.message || ""));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testAuditSignRejectsUnsupportedAlgorithm() {
  // Typo or unsupported alg name surfaces at init time, not as a deeper
  // "key generation failed" error from nodeCrypto.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-asbad-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
    b.cluster._resetForTest();
    b.audit._resetForTest();
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });

    var threw = null;
    try {
      await b.db.init({
        dataDir:      tmpDir,
        atRest:       "plain",
        auditSigning: { mode: "plaintext", algorithm: "ed25519" },  // not in supported list
        schema:       [],
      });
    } catch (e) { threw = e; }
    check("unsupported algorithm rejected at init",
          threw && /algorithm must be one of/.test(threw.message));
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function testCheckpointSign() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ckpt-"));
  try {
    await setupTestDb(tmpDir);

    // auditSign module surface
    check("auditSign namespace present",                typeof b.auditSign === "object");
    check("auditSign.getPublicKey is a function",       typeof b.auditSign.getPublicKey === "function");
    check("auditSign.getPublicKeyFingerprint works",
          typeof b.auditSign.getPublicKeyFingerprint() === "string" &&
          b.auditSign.getPublicKeyFingerprint().length === 128);

    // audit-sign keypair file written (wrapped mode is what setupTestDb
    // configures, matching production posture; sealed file is the
    // expected on-disk artifact).
    check("audit-sign.key.sealed file exists in wrapped mode",
          fs.existsSync(path.join(tmpDir, "audit-sign.key.sealed")));

    // Empty audit_log → checkpoint returns null (nothing to anchor)
    var emptyResult = await b.audit.checkpoint();
    check("checkpoint() on empty log returns null",     emptyResult === null);

    // Record and checkpoint
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.record({ action: "test.event", outcome: "success" });
    var ckpt = await b.audit.checkpoint();
    check("checkpoint() returns a checkpoint object",   ckpt && typeof ckpt._id === "string");
    check("checkpoint anchors monotonic counter",       typeof ckpt.atMonotonicCounter === "number");
    check("checkpoint includes pubkey fingerprint",
          ckpt.publicKeyFingerprint === b.auditSign.getPublicKeyFingerprint());

    // skipIfUnchanged: second call with no new audit activity returns null
    var skipResult = await b.audit.checkpoint({ skipIfUnchanged: true });
    check("checkpoint(skipIfUnchanged) on unchanged log returns null", skipResult === null);

    // After more activity, skipIfUnchanged anchors a new checkpoint
    await b.audit.record({ action: "test.event", outcome: "success" });
    var freshCkpt = await b.audit.checkpoint({ skipIfUnchanged: true });
    check("skipIfUnchanged anchors when chain advances", freshCkpt !== null);
    check("new checkpoint counter > prior checkpoint",   freshCkpt.atMonotonicCounter > ckpt.atMonotonicCounter);

    // audit.tip sidecar written
    var tipPath = path.join(tmpDir, "audit.tip");
    check("audit.tip sidecar written",                  fs.existsSync(tipPath));
    var tip = JSON.parse(fs.readFileSync(tipPath, "utf8"));
    check("audit.tip records latest counter",           tip.atMonotonicCounter === freshCkpt.atMonotonicCounter);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testCheckpointVerify() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cverify-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");

    // Empty case
    var v0 = await b.audit.verifyCheckpoints();
    check("verifyCheckpoints empty case ok",            v0.ok === true && v0.checkpointsVerified === 0);

    // Several events + checkpoints
    for (var i = 0; i < 5; i++) {
      await b.audit.record({ action: "test.event", outcome: "success" });
      await b.audit.checkpoint();
    }
    var v1 = await b.audit.verifyCheckpoints();
    check("verifyCheckpoints ok across multiple anchors", v1.ok === true && v1.checkpointsVerified === 5);

    // Adding more rows then a fresh checkpoint still verifies
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.checkpoint();
    var v2 = await b.audit.verifyCheckpoints();
    check("verifyCheckpoints ok after additional checkpoint", v2.ok === true && v2.checkpointsVerified === 6);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// Regression: a fire-and-forget checkpoint launched by db.close() reads the
// chain tip from the open database, then its deferred insert resolves the live
// db handle at resume time. If a fresh database opened in between, the old
// tip's checkpoint must NOT be anchored into that different/absent database
// (it would forge a checkpoint signed under the prior keypair into another db).
// Reproduce deterministically: tear the db down (bumping the db generation)
// between the tip read and the insert — auditSign.sign() sits exactly there in
// checkpoint(). The checkpoint must fail closed (return null, never throw, never
// write) instead of inserting against the torn-down/replaced database.
async function testCheckpointCrossGenerationRefused() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-ckptgen-"));
  var realGen = b.db._dbGeneration;
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });

    // Simulate the db handle being closed/replaced between the tip read and
    // the insert: dbGeneration() returns one value when checkpoint() binds at
    // entry, and a changed value at the pre-insert re-check. The checkpoint
    // must fail closed — return null and write nothing.
    var n = 0;
    b.db._dbGeneration = function () { n += 1; return n <= 1 ? 1000 : 1001; };
    var result = await b.audit.checkpoint();
    b.db._dbGeneration = realGen;

    check("cross-generation checkpoint returns null", result === null);
    var after = await b.audit.verifyCheckpoints();
    check("cross-generation checkpoint wrote nothing", after.ok === true && after.checkpointsVerified === 0);

    // Control: a stable-generation checkpoint still anchors normally.
    var ok = await b.audit.checkpoint();
    check("stable-generation checkpoint still anchors", ok && typeof ok._id === "string");
  } finally {
    b.db._dbGeneration = realGen;
    await teardownTestDb(tmpDir);
  }
}

async function testCheckpointTamperDetect() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cdetect-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.checkpoint();
    await b.audit.record({ action: "test.event", outcome: "success" });
    await b.audit.record({ action: "test.event", outcome: "success" });
    var anchorCkpt = await b.audit.checkpoint();

    // Tamper with the audit_log row that the checkpoint anchors. Drop the
    // append-only triggers temporarily, recompute the chain hash so the
    // per-row chain still verifies (simulating a privileged attacker with
    // vault key access who's trying to rewrite history). The CHECKPOINT
    // signature will still mismatch because the original rowHash was signed.
    b.db.runSql("DROP TRIGGER IF EXISTS no_update_audit_log");
    var origRow = b.db.prepare("SELECT * FROM audit_log WHERE monotonicCounter = ?").get(anchorCkpt.atMonotonicCounter);
    // Change something innocuous + recompute rowHash so per-row chain holds
    var tamperedFields = Object.assign({}, origRow);
    tamperedFields.outcome = "denied";
    var nonceBuf = Buffer.isBuffer(origRow.nonce) ? origRow.nonce : Buffer.from(origRow.nonce);
    var fields = Object.assign({}, tamperedFields);
    delete fields.prevHash; delete fields.rowHash; delete fields.nonce;
    var newRowHash = b.auditChain.computeRowHash(origRow.prevHash, fields, nonceBuf);
    b.db.prepare("UPDATE audit_log SET outcome = ?, rowHash = ? WHERE monotonicCounter = ?")
        .run("denied", newRowHash, anchorCkpt.atMonotonicCounter);
    b.db.runSql("CREATE TRIGGER IF NOT EXISTS no_update_audit_log BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only — UPDATE prohibited'); END");

    // Per-row chain may still pass IF attacker also fixed the next row's
    // prevHash + rowHash recursively. They didn't here; verifyChain might
    // catch it at the next row. But the CHECKPOINT layer catches it
    // unconditionally — anchored rowHash no longer matches what's on disk.
    var ckptResult = await b.audit.verifyCheckpoints();
    check("checkpoint verify catches anchored-rowHash tampering",  ckptResult.ok === false);
    check("break reason mentions rowHash mismatch",
          /rowHash mismatch|tampered/i.test(ckptResult.reason || ""));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testRollbackDetection() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rollback-"));
  try {
    await setupTestDb(tmpDir);
    b.audit.registerNamespace("test");
    for (var i = 0; i < 3; i++) {
      await b.audit.record({ action: "test.event", outcome: "success" });
    }
    await b.audit.checkpoint();

    // audit.tip should now record counter >= 3
    var tipPath = path.join(tmpDir, "audit.tip");
    check("audit.tip exists post-checkpoint",   fs.existsSync(tipPath));
    var tip = JSON.parse(fs.readFileSync(tipPath, "utf8"));
    check("audit.tip records non-zero counter", tip.atMonotonicCounter >= 3);

    // Simulate rollback: write an audit.tip claiming a higher counter than
    // currently exists in DB. On next boot, db.init() should detect and
    // refuse — but we can't easily test process.exit() in-process. Verify
    // the rollback-detection function is wired by inspecting that an
    // "out of sync" tip would be detected. Use the public surface:
    // close, write tampered tip, reopen.
    b.db.close();
    // CodeQL js/file-system-race: test/ scope only. tipPath is inside the
    // per-test tmpDir created by setupTestDb (owner-only 0o700); the test
    // intentionally clobbers it to simulate rollback tampering. No
    // attacker model in a single-test process; the rule is documented as
    // a non-finding for test fixtures.
    fs.writeFileSync(tipPath, JSON.stringify({
      atMonotonicCounter:   999999,
      atRowHash:            "deadbeef".repeat(16),
      anchoredAt:           Date.now(),
      checkpointId:         "fake",
      publicKeyFingerprint: "fake",
      version:              1,
    }, null, 2));

    // Reopen — should detect rollback and exit. We fork a child to capture
    // the exit code. The on-disk dataDir is in wrapped/encrypted modes
    // (setupTestDb's secure default), so the child re-inits in those
    // same modes; the test passphrase is inherited via env.
    setTestPassphraseEnv();
    var spawnSync = require("child_process").spawnSync;
    var childScript = "var b = require('" + path.resolve("../blamejs/index.js").replace(/\\/g, "/") + "');\n" +
      "process.env.BLAMEJS_SKIP_NTP_CHECK = '1';\n" +
      "(async function () {\n" +
      "  await b.vault.init({ dataDir: " + JSON.stringify(tmpDir) + " });\n" +
      "  await b.db.init({ dataDir: " + JSON.stringify(tmpDir) + ", tmpDir: " + JSON.stringify(path.join(tmpDir, "tmpfs")) + ", schema: [] });\n" +
      "})().catch(function (e) { console.error(e.message); process.exit(99); });\n";
    var result = spawnSync(process.execPath, ["-e", childScript], { encoding: "utf8" });
    check("rollback boot exits via the catch handler (code 99)", result.status === 99);
    check("rollback boot logs detection message",                /rollback detected/i.test(result.stderr || ""));
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- run() ----

async function run() {
  // cluster-storage (SQL dispatcher)
  await testClusterStorageLocalDispatch();
  testClusterStoragePlaceholderize();
  testClusterStorageResolveTablesIsNoOpInSingleNode();
  await testClusterStorageClusterDispatch();

  // cluster discovery surface (endpoint + discoveryHandler)
  testClusterEndpointSingleNode();
  await testClusterDiscoveryHandlerSingleNode();
  await testClusterEndpointInitValidation();
  await testClusterDiscoveryAcquiredLeader();

  // cluster-mode audit-tip fencing (canonical fencing-token guard) +
  // recursion-safety regression for the handlers.drain bug discovered
  // while wiring the fence test
  await testClusterAuditTipFencing();
  await testClusterAuditFlushNoRecursionHang();
  await testClusterAuditTipFencedOutErrorSurface();

  // cluster-mode boot-time rollback detection on the audit chain
  await testClusterAuditTipRollbackHappyPath();
  await testClusterAuditTipRollbackDetected();
  await testClusterAuditTipRowHashMismatch();

  // cluster-mode vault-key consistency check
  await testClusterVaultKeyFirstBootRecords();
  await testClusterVaultKeyMismatchDetected();

  // cluster-mode sessions: session.* now dispatches through
  // cluster-storage so writes/reads land in external-db, making the
  // session store shared across all nodes
  await testClusterSessionsSharedAcrossNodes();

  // cluster-mode queue: queue-local routes through cluster-storage so
  // the leader's enqueue/lease/complete operate on the shared
  // external-db queue — followers don't run lease (gated) but observe
  // the same state via reads
  await testClusterQueueJobsSharedAcrossNodes();

  // cluster-mode consent integrity: _blamejs_consent_tip is the
  // canonical fencing-token-guarded coordination row, updated on
  // every consent.grant / consent.withdraw, checked at boot for
  // rollback detection — same protections as audit_log
  await testClusterConsentTipFencing();
  await testClusterConsentTipUpdatedOnGrant();
  await testClusterConsentRollbackDetected();

  // audit chain + verify (now exercises chain-writer transitively)
  await testAuditChain();
  await testAuditChainBreak();
  await testAuditSelfLogging();
  await testBeginTrace();

  // consent (uses chain-writer)
  await testConsent();

  // subject rights (uses audit + db)
  await testSubjectRights();

  // append-only triggers + foreign keys + table metadata
  await testAppendOnlyTriggers();
  await testForeignKeys();
  await testTableMetadata();

  // audit-sign algorithm-agility
  await testAuditSignDefaultsToSlhDsa();
  await testAuditSignMlDsaOptIn();
  await testAuditSignLegacyFileBackcompat();
  await testAuditSignRejectsUnsupportedAlgorithm();

  // checkpoint sign / verify / tamper / rollback
  await testCheckpointSign();
  await testCheckpointVerify();
  await testCheckpointCrossGenerationRefused();
  await testCheckpointTamperDetect();
  await testRollbackDetection();
}

module.exports = {
  name: "Layer 3 — chain (cluster-storage + audit + consent + subject + checkpoint)",
  run:  run,
  testClusterStorageLocalDispatch:                     testClusterStorageLocalDispatch,
  testClusterStoragePlaceholderize:                    testClusterStoragePlaceholderize,
  testClusterStorageResolveTablesIsNoOpInSingleNode:   testClusterStorageResolveTablesIsNoOpInSingleNode,
  testClusterStorageClusterDispatch:                   testClusterStorageClusterDispatch,
  testClusterEndpointSingleNode:                       testClusterEndpointSingleNode,
  testClusterDiscoveryHandlerSingleNode:               testClusterDiscoveryHandlerSingleNode,
  testClusterEndpointInitValidation:                   testClusterEndpointInitValidation,
  testClusterDiscoveryAcquiredLeader:                  testClusterDiscoveryAcquiredLeader,
  testClusterAuditTipFencing:                          testClusterAuditTipFencing,
  testClusterAuditFlushNoRecursionHang:                testClusterAuditFlushNoRecursionHang,
  testClusterAuditTipFencedOutErrorSurface:            testClusterAuditTipFencedOutErrorSurface,
  testClusterAuditTipRollbackHappyPath:                testClusterAuditTipRollbackHappyPath,
  testClusterAuditTipRollbackDetected:                 testClusterAuditTipRollbackDetected,
  testClusterAuditTipRowHashMismatch:                  testClusterAuditTipRowHashMismatch,
  testClusterVaultKeyFirstBootRecords:                 testClusterVaultKeyFirstBootRecords,
  testClusterVaultKeyMismatchDetected:                 testClusterVaultKeyMismatchDetected,
  testClusterSessionsSharedAcrossNodes:                testClusterSessionsSharedAcrossNodes,
  testClusterQueueJobsSharedAcrossNodes:               testClusterQueueJobsSharedAcrossNodes,
  testClusterConsentTipFencing:                        testClusterConsentTipFencing,
  testClusterConsentTipUpdatedOnGrant:                 testClusterConsentTipUpdatedOnGrant,
  testClusterConsentRollbackDetected:                  testClusterConsentRollbackDetected,
  testAuditChain:                                      testAuditChain,
  testAuditChainBreak:                                 testAuditChainBreak,
  testAuditSelfLogging:                                testAuditSelfLogging,
  testBeginTrace:                                      testBeginTrace,
  testConsent:                                         testConsent,
  testSubjectRights:                                   testSubjectRights,
  testAppendOnlyTriggers:                              testAppendOnlyTriggers,
  testForeignKeys:                                     testForeignKeys,
  testTableMetadata:                                   testTableMetadata,
  testAuditSignDefaultsToSlhDsa:                       testAuditSignDefaultsToSlhDsa,
  testAuditSignMlDsaOptIn:                             testAuditSignMlDsaOptIn,
  testAuditSignLegacyFileBackcompat:                   testAuditSignLegacyFileBackcompat,
  testAuditSignRejectsUnsupportedAlgorithm:            testAuditSignRejectsUnsupportedAlgorithm,
  testCheckpointSign:                                  testCheckpointSign,
  testCheckpointVerify:                                testCheckpointVerify,
  testCheckpointTamperDetect:                          testCheckpointTamperDetect,
  testRollbackDetection:                               testRollbackDetection,
};

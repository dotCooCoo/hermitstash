"use strict";
/**
 * scheduler — exactly-once-globally tick-claim.
 *
 * When opts.cluster is wired, every fire must INSERT a row into
 * _blamejs_scheduler_ticks keyed on (taskName, scheduledAtUnix). The
 * row-winner runs the task; the loser increments task.tickClaimLost
 * and skips silently. Single-node (no opts.cluster) skips the
 * tick-claim path entirely and fires unconditionally.
 *
 * Run standalone: `node test/layer-0-primitives/scheduler-exactly-once.test.js`
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

async function testSingleNodeNoTickClaim() {
  // No opts.cluster wired → tick-claim path skipped entirely. fires
  // increments normally, tickClaimLost stays 0, no rows in the ticks
  // table.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sched-eo-"));
  try {
    await setupTestDb(tmpDir);
    var fired = 0;
    var sched = b.scheduler.create({ audit: false });
    sched.schedule({ name: "single", every: 60000, run: async function () { fired++; } });
    sched._fireOnce("single");
    await helpers.waitUntil(function () {
      var t = sched.list()[0];
      return t && t.fires === 1;
    }, { timeoutMs: 5000, label: "scheduler single-node: fire callback completed" });
    var listed = sched.list()[0];
    check("single-node: fires increments",         listed.fires === 1);
    check("single-node: tickClaimLost stays 0",    listed.tickClaimLost === 0);
    check("single-node: run callback executed",    fired === 1);

    var rows = b.db.prepare("SELECT * FROM _blamejs_scheduler_ticks").all();
    check("single-node: no tick rows inserted",    rows.length === 0);

    await sched.stop();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClusterWinnerInsertsTickRow() {
  // opts.cluster wired + isLeader=true + no competing row → INSERT
  // succeeds (rowCount=1), task fires, tick row landed in DB.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sched-eo-"));
  try {
    await setupTestDb(tmpDir);
    var fired = 0;
    var fakeCluster = {
      isLeader:      function () { return true; },
      currentNodeId: function () { return "node-A"; },
    };
    var sched = b.scheduler.create({ cluster: fakeCluster, audit: false });
    var task = sched.schedule({ name: "winner", every: 60000, run: async function () { fired++; } });
    var nominalRun = task.nextRun;

    sched._fireOnce("winner");
    await helpers.waitUntil(function () {
      var t = sched.list()[0];
      return t && t.fires === 1;
    }, { timeoutMs: 5000, label: "scheduler winner: tick-claim won + fire completed" });

    var listed = sched.list()[0];
    check("winner: fires increments",              listed.fires === 1);
    check("winner: tickClaimLost stays 0",         listed.tickClaimLost === 0);
    check("winner: run callback executed",         fired === 1);

    var rows = b.db.prepare(
      "SELECT * FROM _blamejs_scheduler_ticks WHERE name = 'winner'"
    ).all();
    check("winner: tick row inserted",             rows.length === 1);
    check("winner: tickKey matches name:nominalRun",
                                                    rows[0].tickKey === "winner:" + nominalRun);
    check("winner: claimedBy carries nodeId",      rows[0].claimedBy === "node-A");

    await sched.stop();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClusterLoserSkipsAndCounts() {
  // Pre-insert a competing tick row before the scheduler fires. The
  // scheduler's INSERT...ON CONFLICT DO NOTHING returns rowCount=0 →
  // tickClaimLost increments, run does NOT execute, scheduler.tick.lost
  // event emitted.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sched-eo-"));
  try {
    await setupTestDb(tmpDir);
    var fired = 0;
    var fakeCluster = {
      isLeader:      function () { return true; },
      currentNodeId: function () { return "node-B"; },
    };
    var sched = b.scheduler.create({ cluster: fakeCluster, audit: true });
    var task = sched.schedule({ name: "loser", every: 60000, run: async function () { fired++; } });
    var nominalRun = task.nextRun;

    // Simulate "another node already claimed this tick"
    await b.clusterStorage.execute(
      "INSERT INTO _blamejs_scheduler_ticks " +
      "(tickKey, name, scheduledAtUnix, claimedAtUnix, claimedBy) " +
      "VALUES (?, ?, ?, ?, ?)",
      ["loser:" + nominalRun, "loser", nominalRun, Date.now() - 100, "other-node"]
    );

    sched._fireOnce("loser");
    // The lost tick-claim is observable as tickClaimLost incrementing —
    // poll on that rather than a fixed tick budget. Once it lands, the
    // skipped run (fires stays 0) is guaranteed.
    await helpers.waitUntil(function () {
      var t = sched.list()[0];
      return t && t.tickClaimLost === 1;
    }, { timeoutMs: 5000, label: "scheduler loser: tick-claim lost recorded" });

    var listed = sched.list()[0];
    check("loser: fires stays 0",                  listed.fires === 0);
    check("loser: tickClaimLost === 1",            listed.tickClaimLost === 1);
    check("loser: run callback NOT executed",      fired === 0);

    var rows = b.db.prepare(
      "SELECT claimedBy FROM _blamejs_scheduler_ticks WHERE name = 'loser'"
    ).all();
    check("loser: only the competing row remains", rows.length === 1);
    check("loser: competing claimedBy preserved",  rows[0].claimedBy === "other-node");

    await b.audit.flush();
    var lostRows = await b.audit.query({ action: "system.scheduler.tick.lost" });
    check("loser: system.scheduler.tick.lost audit emitted", lostRows.length === 1);

    await sched.stop();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testPruneRemovesOldRows() {
  // Operator-callable pruneTickClaims must remove rows older than the
  // retention threshold and emit system.scheduler.tick.pruned.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sched-eo-"));
  try {
    await setupTestDb(tmpDir);
    var fakeCluster = {
      isLeader:      function () { return true; },
      currentNodeId: function () { return "pruner" ; },
    };
    var sched = b.scheduler.create({
      cluster:         fakeCluster,
      audit:           true,
      tickRetentionMs: 1000,           // 1 second
      pruneIntervalMs: 60 * 60 * 1000, // never auto-prune in this test
    });

    var now = Date.now();
    // Old rows (> retention) should be pruned.
    await b.clusterStorage.execute(
      "INSERT INTO _blamejs_scheduler_ticks (tickKey, name, scheduledAtUnix, claimedAtUnix, claimedBy) VALUES (?, ?, ?, ?, ?)",
      ["old:1", "old", now - 5000, now - 5000, "n1"]
    );
    await b.clusterStorage.execute(
      "INSERT INTO _blamejs_scheduler_ticks (tickKey, name, scheduledAtUnix, claimedAtUnix, claimedBy) VALUES (?, ?, ?, ?, ?)",
      ["old:2", "old", now - 4000, now - 4000, "n1"]
    );
    // Recent row should stay.
    await b.clusterStorage.execute(
      "INSERT INTO _blamejs_scheduler_ticks (tickKey, name, scheduledAtUnix, claimedAtUnix, claimedBy) VALUES (?, ?, ?, ?, ?)",
      ["new:1", "new", now - 100, now - 100, "n1"]
    );

    var removed = await sched.pruneTickClaims();
    check("pruneTickClaims removed 2 old rows",      removed === 2);
    var remaining = b.db.prepare("SELECT COUNT(*) AS n FROM _blamejs_scheduler_ticks").get();
    check("recent row remains after prune",          remaining.n === 1);

    await b.audit.flush();
    var prunedRows = await b.audit.query({ action: "system.scheduler.tick.pruned" });
    check("system.scheduler.tick.pruned emitted",    prunedRows.length === 1);
    var meta = typeof prunedRows[0].metadata === "string"
      ? JSON.parse(prunedRows[0].metadata) : prunedRows[0].metadata;
    check("audit metadata carries rowsDeleted = 2",  meta && meta.rowsDeleted === 2);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testPruneNoOpWithoutCluster() {
  // Single-node scheduler (no cluster) writes no tick rows, so prune is
  // a no-op returning 0.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sched-eo-"));
  try {
    await setupTestDb(tmpDir);
    var sched = b.scheduler.create({ audit: false });
    var removed = await sched.pruneTickClaims();
    check("single-node prune is a no-op",            removed === 0);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testListExposesTickClaimLost() {
  // The list() projection must surface tickClaimLost so operators can
  // observe contention without needing to read the table directly.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-sched-eo-"));
  try {
    await setupTestDb(tmpDir);
    var sched = b.scheduler.create({ audit: false });
    sched.schedule({ name: "shape", every: 60000, run: function () {} });
    var entry = sched.list()[0];
    check("list(): tickClaimLost present",         "tickClaimLost" in entry);
    check("list(): tickClaimLost initial value 0", entry.tickClaimLost === 0);
    await sched.stop();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testSingleNodeNoTickClaim();
  await testClusterWinnerInsertsTickRow();
  await testClusterLoserSkipsAndCounts();
  await testPruneRemovesOldRows();
  await testPruneNoOpWithoutCluster();
  await testListExposesTickClaimLost();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}

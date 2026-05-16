"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeOrch(health) {
  return {
    health: function () { return Promise.resolve(health || { agents: [], elections: [], consumers: [], streams: 0, draining: false, overall: "ok" }); },
  };
}

function _fakeBackend() {
  var map = new Map();
  return {
    put:    function (k, v) { map.set(k, v); return Promise.resolve(); },
    get:    function (k)    { return Promise.resolve(map.get(k) || null); },
    delete: function (k)    { map.delete(k); return Promise.resolve(); },
    list:   function ()     {
      var out = [];
      map.forEach(function (v) { out.push(v); });
      return Promise.resolve(out);
    },
    _size: function () { return map.size; },
  };
}

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function testSurface() {
  check("create is fn",         typeof b.agent.snapshot.create === "function");
  check("SCHEMA_VERSION = 1",   b.agent.snapshot.SCHEMA_VERSION === 1);
  check("AgentSnapshotError",   typeof b.agent.snapshot.AgentSnapshotError === "function");
  var e = new b.agent.snapshot.AgentSnapshotError("agent-snapshot/test", "t");
  check("error carries code",   e.code === "agent-snapshot/test");
}

async function testCreateRequiresOrchestrator() {
  var threw = null;
  try { b.agent.snapshot.create({ backend: _fakeBackend() }); } catch (e) { threw = e; }
  check("create refuses missing orchestrator",
    threw && (threw.code || "").indexOf("agent-snapshot/bad-orchestrator") !== -1);
}

async function testCreateRequiresBackend() {
  var threw = null;
  try { b.agent.snapshot.create({ orchestrator: _fakeOrch() }); } catch (e) { threw = e; }
  check("create refuses missing backend",
    threw && (threw.code || "").indexOf("agent-snapshot/bad-backend") !== -1);
}

async function testTakeAndPersist() {
  var snapshot = b.agent.snapshot.create({
    orchestrator: _fakeOrch(),
    backend:      _fakeBackend(),
  });
  var snap = await snapshot.takeSnapshot({});
  check("takeSnapshot: snapshotId present",
    typeof snap.snapshotId === "string" && snap.snapshotId.indexOf("snap-") === 0);
  check("takeSnapshot: schemaVersion = 1", snap.schemaVersion === 1);
  check("takeSnapshot: takenAt is number", typeof snap.takenAt === "number");
  var r = await snapshot.persist(snap);
  check("persist: returns snapshotId", r.snapshotId === snap.snapshotId);
}

async function testLoadLatest() {
  var snapshot = b.agent.snapshot.create({
    orchestrator: _fakeOrch(),
    backend:      _fakeBackend(),
  });
  var miss = await snapshot.loadLatest();
  check("loadLatest: empty backend returns null", miss === null);
  var s1 = await snapshot.takeSnapshot({});
  await snapshot.persist(s1);
  await new Promise(function (r) { setTimeout(r, 10); });
  var s2 = await snapshot.takeSnapshot({});
  await snapshot.persist(s2);
  var loaded = await snapshot.loadLatest();
  check("loadLatest: returns most recent",
    loaded && loaded.snapshotId === s2.snapshotId && loaded.takenAt >= s1.takenAt);
}

async function testLoadById() {
  var snapshot = b.agent.snapshot.create({
    orchestrator: _fakeOrch(),
    backend:      _fakeBackend(),
  });
  var s = await snapshot.takeSnapshot({});
  await snapshot.persist(s);
  var hit = await snapshot.loadById(s.snapshotId);
  check("loadById: returns snapshot", hit.snapshotId === s.snapshotId);
  var miss = await snapshot.loadById("nope");
  check("loadById: miss returns null", miss === null);
}

async function testRestoreTopologyChange() {
  // Snapshot from a 3-consumer cluster; restore into a 5-consumer cluster.
  var snapHealth = { agents: [], elections: [], consumers: [{ topic: "t.0" }, { topic: "t.1" }, { topic: "t.2" }], streams: 0, draining: false, overall: "ok" };
  var restoreHealth = { agents: [], elections: [], consumers: [{ topic: "t.0" }, { topic: "t.1" }, { topic: "t.2" }, { topic: "t.3" }, { topic: "t.4" }], streams: 0, draining: false, overall: "ok" };

  // Take snapshot using the 3-consumer orchestrator.
  var snap1 = b.agent.snapshot.create({
    orchestrator: _fakeOrch(snapHealth),
    backend:      _fakeBackend(),
  });
  var snap = await snap1.takeSnapshot({});

  // Restore using the 5-consumer orchestrator.
  var snap2 = b.agent.snapshot.create({
    orchestrator: _fakeOrch(restoreHealth),
    backend:      _fakeBackend(),
  });
  var r = await snap2.restore(snap, {});
  check("restore: topologyChanged detected",  r.topologyChanged === true);
  check("restore: snapshotId echoed",          r.snapshotId === snap.snapshotId);
}

async function testRefuseOnTopologyChange() {
  var snapHealth = { agents: [], elections: [], consumers: [{ topic: "t.0" }, { topic: "t.1" }], streams: 0, draining: false, overall: "ok" };
  var restoreHealth = { agents: [], elections: [], consumers: [{ topic: "t.0" }], streams: 0, draining: false, overall: "ok" };
  var s1 = b.agent.snapshot.create({ orchestrator: _fakeOrch(snapHealth), backend: _fakeBackend() });
  var snap = await s1.takeSnapshot({});
  var s2 = b.agent.snapshot.create({ orchestrator: _fakeOrch(restoreHealth), backend: _fakeBackend() });
  await expectRejection("refuseOnTopologyChange refuses",
    s2.restore(snap, { refuseOnTopologyChange: true }),
    "agent-snapshot/topology-changed");
}

async function testSchemaVersionMismatch() {
  var snapshot = b.agent.snapshot.create({
    orchestrator: _fakeOrch(),
    backend:      _fakeBackend(),
  });
  var snap = await snapshot.takeSnapshot({});
  snap.schemaVersion = 999;
  await expectRejection("refuses schema-version mismatch",
    snapshot.restore(snap, {}),
    "agent-snapshot/schema-version-mismatch");
  // Operator opt-in works
  var r = await snapshot.restore(snap, { allowSchemaVersionMismatch: true });
  check("schema-version opt-in OK", r.snapshotId === snap.snapshotId);
}

async function testList() {
  var snapshot = b.agent.snapshot.create({
    orchestrator: _fakeOrch(),
    backend:      _fakeBackend(),
  });
  await snapshot.persist(await snapshot.takeSnapshot({}));
  await snapshot.persist(await snapshot.takeSnapshot({}));
  var list = await snapshot.list({});
  check("list: 2 entries", list.length === 2);
}

async function testGc() {
  var backend = _fakeBackend();
  var snapshot = b.agent.snapshot.create({
    orchestrator: _fakeOrch(),
    backend:      backend,
  });
  await snapshot.persist(await snapshot.takeSnapshot({}));
  await new Promise(function (r) { setTimeout(r, 30); });
  var r = await snapshot.gc({ olderThanMs: 0 });
  check("gc: 1 purged", r.purged === 1);
  check("gc: backend empty", backend._size() === 0);
}

async function run() {
  testSurface();
  await testCreateRequiresOrchestrator();
  await testCreateRequiresBackend();
  await testTakeAndPersist();
  await testLoadLatest();
  await testLoadById();
  await testRestoreTopologyChange();
  await testRefuseOnTopologyChange();
  await testSchemaVersionMismatch();
  await testList();
  await testGc();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

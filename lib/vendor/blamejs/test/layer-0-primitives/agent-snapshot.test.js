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

// Deterministic fake signer + sealer for the per-test snapshot path.
// Production wires b.audit-sign + b.vault.aad; tests use the fakes so
// they don't need the full audit-sign passphrase boot.
function _fakeSigner() {
  var nodeCrypto = require("node:crypto");
  var key = Buffer.alloc(32, 0x42);                                                                     // allow:raw-byte-literal — test fake key fill byte
  return {
    sign: function (bytes) { return nodeCrypto.createHmac("sha3-512", key).update(bytes).digest(); },
    verify: function (bytes, sig) {
      var expected = nodeCrypto.createHmac("sha3-512", key).update(bytes).digest();
      if (expected.length !== sig.length) return false;
      try { return nodeCrypto.timingSafeEqual(expected, sig); } catch (_e) { return false; }
    },
    getPublicKey: function () { return null; },
  };
}

function _fakeSealer() {
  var nodeCrypto = require("node:crypto");
  var key = Buffer.alloc(32, 0x55);                                                                     // allow:raw-byte-literal — test fake key fill byte
  function _aadStr(aad) {
    var keys = Object.keys(aad).sort();
    return keys.map(function (k) { return k + "=" + aad[k]; }).join("|");
  }
  return {
    seal: function (plaintext, aad) {
      var aadBuf = Buffer.from(_aadStr(aad), "utf8");
      var iv = Buffer.alloc(16, 0);                                                                     // allow:raw-byte-literal — deterministic test IV
      var c = nodeCrypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });                 // allow:raw-byte-literal — test-only AES-GCM (production uses ML-KEM + XChaCha20)
      c.setAAD(aadBuf);
      var ct = Buffer.concat([c.update(Buffer.from(plaintext, "utf8")), c.final()]);
      var tag = c.getAuthTag();
      return Buffer.concat([tag, ct]).toString("base64");
    },
    unseal: function (value, aad) {
      var aadBuf = Buffer.from(_aadStr(aad), "utf8");
      var raw = Buffer.from(value, "base64");
      var tag = raw.subarray(0, 16);                                                                    // allow:raw-byte-literal — AES-GCM tag length
      var ct  = raw.subarray(16);                                                                       // allow:raw-byte-literal — AES-GCM tag length offset
      var iv = Buffer.alloc(16, 0);                                                                     // allow:raw-byte-literal — deterministic test IV
      var d = nodeCrypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });               // allow:raw-byte-literal — test-only AES-GCM
      d.setAAD(aadBuf);
      d.setAuthTag(tag);
      return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
    },
  };
}

function _signedSnapshot(opts) {
  opts = opts || {};
  return b.agent.snapshot.create({
    orchestrator:    opts.orchestrator || _fakeOrch(),
    backend:         opts.backend || _fakeBackend(),
    signer:          opts.signer || _fakeSigner(),
    sealer:          opts.sealer || _fakeSealer(),
    allowPlaintext:  opts.allowPlaintext === true,
    restoreHandlers: opts.restoreHandlers || null,
  });
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
  var snapshot = _signedSnapshot();
  var snap = await snapshot.takeSnapshot({});
  check("takeSnapshot: snapshotId present",
    typeof snap.snapshotId === "string" && snap.snapshotId.indexOf("snap-") === 0);
  check("takeSnapshot: schemaVersion = 1", snap.schemaVersion === 1);
  check("takeSnapshot: takenAt is number", typeof snap.takenAt === "number");
  var r = await snapshot.persist(snap);
  check("persist: returns snapshotId", r.snapshotId === snap.snapshotId);
  check("persist: sig populated", typeof snap.sig === "string" && snap.sig.length > 0);
}

async function testLoadLatest() {
  var snapshot = _signedSnapshot();
  var miss = await snapshot.loadLatest();
  check("loadLatest: empty backend returns null", miss === null);
  var s1 = await snapshot.takeSnapshot({});
  await snapshot.persist(s1);
  // s2.takenAt must differ from s1.takenAt for loadLatest's most-recent
  // ordering; wait until the wall clock has advanced past s1.takenAt.
  await helpers.waitUntil(function () {
    return Date.now() > s1.takenAt;
  }, { label: "agent-snapshot: clock advanced past s1.takenAt before s2" });
  var s2 = await snapshot.takeSnapshot({});
  await snapshot.persist(s2);
  var loaded = await snapshot.loadLatest();
  check("loadLatest: returns most recent",
    loaded && loaded.snapshotId === s2.snapshotId && loaded.takenAt >= s1.takenAt);
}

async function testLoadById() {
  var snapshot = _signedSnapshot();
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
  var snap1 = _signedSnapshot({ orchestrator: _fakeOrch(snapHealth) });
  var snap = await snap1.takeSnapshot({});

  // Restore using the 5-consumer orchestrator.
  var snap2 = _signedSnapshot({ orchestrator: _fakeOrch(restoreHealth) });
  var r = await snap2.restore(snap, {});
  check("restore: topologyChanged detected",  r.topologyChanged === true);
  check("restore: snapshotId echoed",          r.snapshotId === snap.snapshotId);
}

async function testRefuseOnTopologyChange() {
  var snapHealth = { agents: [], elections: [], consumers: [{ topic: "t.0" }, { topic: "t.1" }], streams: 0, draining: false, overall: "ok" };
  var restoreHealth = { agents: [], elections: [], consumers: [{ topic: "t.0" }], streams: 0, draining: false, overall: "ok" };
  var s1 = _signedSnapshot({ orchestrator: _fakeOrch(snapHealth) });
  var snap = await s1.takeSnapshot({});
  var s2 = _signedSnapshot({ orchestrator: _fakeOrch(restoreHealth) });
  await expectRejection("refuseOnTopologyChange refuses",
    s2.restore(snap, { refuseOnTopologyChange: true }),
    "agent-snapshot/topology-changed");
}

async function testSchemaVersionMismatch() {
  var snapshot = _signedSnapshot();
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
  var snapshot = _signedSnapshot();
  await snapshot.persist(await snapshot.takeSnapshot({}));
  await snapshot.persist(await snapshot.takeSnapshot({}));
  var list = await snapshot.list({});
  check("list: 2 entries", list.length === 2);
}

async function testGc() {
  var backend = _fakeBackend();
  var snapshot = _signedSnapshot({ backend: backend });
  var snap = await snapshot.takeSnapshot({});
  await snapshot.persist(snap);
  // gc({olderThanMs: 0}) considers anything strictly older than `now`
  // as fair game; wait until the clock has surpassed the snapshot's
  // takenAt before invoking gc.
  await helpers.waitUntil(function () {
    return Date.now() > snap.takenAt;
  }, { label: "agent-snapshot.gc: clock past snap.takenAt for olderThan filter" });
  var r = await snapshot.gc({ olderThanMs: 0 });
  check("gc: 1 purged", r.purged === 1);
  check("gc: backend empty", backend._size() === 0);
}

async function testSignerNotWiredRefused() {
  // SUBSTRATE-1 — persist without signer/sealer wired refuses by default.
  // (vault is not initialized here; auditSign also not initialized.)
  var snapshot = b.agent.snapshot.create({
    orchestrator: _fakeOrch(),
    backend:      _fakeBackend(),
  });
  var snap = await snapshot.takeSnapshot({});
  await expectRejection("persist without signer refuses",
    snapshot.persist(snap),
    "agent-snapshot/signer-not-wired");
}

async function testTamperedEnvelopeRefused() {
  // SUBSTRATE-1 — sealed+signed envelope rejects on signature tamper.
  var backend = _fakeBackend();
  var snap1 = _signedSnapshot({ backend: backend });
  var s = await snap1.takeSnapshot({});
  await snap1.persist(s);
  // Tamper: re-write the wrapper's sealed value to a different
  // envelope's bytes. We swap two snapshotIds' sealed payloads.
  var s2 = await snap1.takeSnapshot({});
  await snap1.persist(s2);
  var raw1 = await backend.get(s.snapshotId);
  var raw2 = await backend.get(s2.snapshotId);
  // Cross-paste s2's sealed body into s1's wrapper. AAD pins
  // snapshotId so unseal MUST fail.
  var tampered = Object.assign({}, raw1, { sealed: raw2.sealed });
  await backend.put(s.snapshotId, tampered);
  await expectRejection("loadById refuses tampered envelope",
    snap1.loadById(s.snapshotId),
    "agent-snapshot/unseal-failed");
}

async function testUnsignedEnvelopeRefused() {
  // SUBSTRATE-1 — envelope with sig stripped is refused.
  var backend = _fakeBackend();
  var snap1 = _signedSnapshot({ backend: backend });
  var s = await snap1.takeSnapshot({});
  await snap1.persist(s);
  // Replace stored row with a plaintext envelope missing sig — simulates
  // an attacker who wrote bytes directly to the backend.
  await backend.put(s.snapshotId, Object.assign({}, s, { sig: null }));
  await expectRejection("loadById refuses unsigned envelope",
    snap1.loadById(s.snapshotId),
    "agent-snapshot/unsigned");
}

async function testRestoreHandlersInvoked() {
  // SUBSTRATE-18 — restoreHandlers run end-to-end with audited counts.
  var invocations = [];
  var handlers = {
    orchestratorState: function (payload) { invocations.push("orchestratorState"); return 1; },
    idempotencyCache:  function (payload) { invocations.push("idempotencyCache");  return 2; },
    sagas:             function (payload) { invocations.push("sagas");             return payload.length; },
    streams:           function (payload) { invocations.push("streams");           return payload.length; },
  };
  var snapshot = _signedSnapshot({ restoreHandlers: handlers });
  var snap = await snapshot.takeSnapshot({
    sagas:   [{ id: "s1" }, { id: "s2" }],
    streams: [{ id: "st1" }],
    idempotencyCache: { hot: 1 },
  });
  var r = await snapshot.restore(snap, {});
  check("restore invoked orchestratorState handler", invocations.indexOf("orchestratorState") !== -1);
  check("restore invoked sagas handler", invocations.indexOf("sagas") !== -1);
  check("restore returned sagas count", r.restored.sagas === 2);
  check("restore returned streams count", r.restored.streams === 1);
}

async function testRestoreRequireHandlersRefuses() {
  // SUBSTRATE-18 — requireHandlers refuses silent no-op.
  var snapshot = _signedSnapshot();
  var snap = await snapshot.takeSnapshot({ sagas: [{ id: "s1" }] });
  await expectRejection("restore requires handlers when in-flight",
    snapshot.restore(snap, { requireHandlers: true }),
    "agent-snapshot/no-restore-handlers");
}

async function run() {
  testSurface();
  await testCreateRequiresOrchestrator();
  await testCreateRequiresBackend();
  await testSignerNotWiredRefused();
  await testTakeAndPersist();
  await testLoadLatest();
  await testLoadById();
  await testTamperedEnvelopeRefused();
  await testUnsignedEnvelopeRefused();
  await testRestoreTopologyChange();
  await testRefuseOnTopologyChange();
  await testSchemaVersionMismatch();
  await testList();
  await testGc();
  await testRestoreHandlersInvoked();
  await testRestoreRequireHandlersRefuses();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

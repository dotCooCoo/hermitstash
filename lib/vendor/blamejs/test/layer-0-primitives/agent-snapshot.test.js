// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var fs      = require("fs");
var os      = require("os");
var path    = require("path");
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

// ---- reseal (vault-key rotation) -----------------------------------------
//
// reseal composes b.vault.aad.resealRoot, which only re-keys a real
// `vault.aad:` blob — so these cases use the live b.vault.aad sealer
// (omit the `sealer` opt so _resolveSealer picks up vault().aad) under a
// setupVaultOnly fixture. The signer stays a fake so the test doesn't
// need the full audit-sign passphrase boot.

function _vaultBackedSnapshot(backend) {
  return b.agent.snapshot.create({
    orchestrator: _fakeOrch(),
    backend:      backend,
    signer:       _fakeSigner(),
    // sealer omitted on purpose → live b.vault.aad.
  });
}

function testResealRotationSurface() {
  var desc = b.agent.snapshot.AAD_ROTATION;
  check("AAD_ROTATION exported",            desc && typeof desc === "object");
  check("AAD_ROTATION.table",               desc.table === "agent.snapshot");
  check("AAD_ROTATION.rowIdField",          desc.rowIdField === "snapshotId");
  check("AAD_ROTATION.schemaVersion",       desc.schemaVersion === String(b.agent.snapshot.SCHEMA_VERSION));
  check("AAD_ROTATION.backend external",    desc.backend === "external");
  check("AAD_ROTATION.reseal is fn",        typeof desc.reseal === "function");
  check("reseal exported on module",        typeof b.agent.snapshot.reseal === "function");
}

async function testResealBadInputRefused() {
  await expectRejection("reseal refuses missing backend",
    b.agent.snapshot.reseal({ oldRootJson: "a", newRootJson: "b" }),
    "agent-snapshot/bad-backend");
  await expectRejection("reseal refuses missing oldRootJson",
    b.agent.snapshot.reseal({ backend: _fakeBackend(), newRootJson: "b" }),
    "agent-snapshot/bad-root");
  await expectRejection("reseal refuses missing newRootJson",
    b.agent.snapshot.reseal({ backend: _fakeBackend(), oldRootJson: "a" }),
    "agent-snapshot/bad-root");
}

async function testResealRekeysUnderNewRoot() {
  var backend = _fakeBackend();
  var snapshot = _vaultBackedSnapshot(backend);
  var snap = await snapshot.takeSnapshot({ sagas: [{ id: "s1" }] });
  await snapshot.persist(snap);

  var oldRootJson = b.vault.getKeysJson();
  // A distinct, keys-shaped root: resealRoot hashes the whole serialized
  // form, so any byte-distinct JSON is a different vault root.
  var newRootJson = JSON.stringify(
    Object.assign(JSON.parse(oldRootJson), { _rotationTestRoot: "v2" }));

  var before = await backend.get(snap.snapshotId);
  var beforeSealed = before.sealed;
  var prefix = b.agent.snapshot.SEALED_PREFIX;
  check("pre-reseal: wrapper carries the prefix", beforeSealed.indexOf(prefix) === 0);
  var innerBefore = beforeSealed.slice(prefix.length);
  check("pre-reseal: inner blob is a vault.aad: value",
    b.vault.aad.isAadSealed(innerBefore));

  var result = await b.agent.snapshot.reseal({
    backend:     backend,
    oldRootJson: oldRootJson,
    newRootJson: newRootJson,
  });
  check("reseal: table echoed", result.table === "agent.snapshot");
  check("reseal: 1 row re-keyed", result.resealed === 1);

  var after = await backend.get(snap.snapshotId);
  check("post-reseal: prefix preserved", after.sealed.indexOf(prefix) === 0);
  check("post-reseal: ciphertext changed", after.sealed !== beforeSealed);
  check("post-reseal: decorative wrapper preserved",
    after.snapshotId === snap.snapshotId && after.takenAt === before.takenAt);

  // The AAD the cell was sealed under — rebuilt the SAME way the module
  // does, via the column-shaped tuple.
  var aad = {
    table:         "agent.snapshot",
    rowId:         snap.snapshotId,
    column:        "envelope",
    schemaVersion: String(b.agent.snapshot.SCHEMA_VERSION),
  };
  var innerAfter = after.sealed.slice(prefix.length);
  // Re-keyed blob opens under the NEW root + the SAME AAD, yielding the
  // original signed envelope JSON.
  var reopened = b.vault.aad.unsealRoot(innerAfter, aad, newRootJson);
  var env = JSON.parse(reopened);
  check("post-reseal: envelope decrypts under new root",
    env.snapshotId === snap.snapshotId);

  // ...and is now undecryptable under the OLD root (the AEAD tag is
  // keyed off the new root).
  var oldRootFails = false;
  try { b.vault.aad.unsealRoot(innerAfter, aad, oldRootJson); }
  catch (_e) { oldRootFails = true; }
  check("post-reseal: old root no longer opens the cell", oldRootFails);
}

async function testResealSkipsPlaintextRows() {
  // A bare-envelope row (no `sealed` wrapper) — what the allowPlaintext
  // path writes, and what a legacy plaintext snapshot looks like — has no
  // AAD-sealed blob to re-key, so reseal skips it and re-keys only the
  // sealed rows. Inject the plaintext row directly so the skip branch is
  // exercised regardless of whether the live vault would otherwise seal.
  var backend = _fakeBackend();
  var sealedSnap = _vaultBackedSnapshot(backend);
  var ss = await sealedSnap.takeSnapshot({});
  await sealedSnap.persist(ss);

  // Plaintext row: the bare envelope, snapshotId-keyed, no `sealed`.
  var plainSnap = await sealedSnap.takeSnapshot({});
  await backend.put(plainSnap.snapshotId, plainSnap);

  var oldRootJson = b.vault.getKeysJson();
  var newRootJson = JSON.stringify(
    Object.assign(JSON.parse(oldRootJson), { _rotationTestRoot: "v3" }));
  var result = await b.agent.snapshot.reseal({
    backend:     backend,
    oldRootJson: oldRootJson,
    newRootJson: newRootJson,
  });
  check("reseal: only the sealed row counted (plaintext skipped)",
    result.resealed === 1);
}

async function testResealRefusesNonVaultSealer() {
  // A row sealed by a custom KMS sealer carries a non-vault.aad: inner
  // blob; reseal can't re-key it via resealRoot, so it refuses rather
  // than silently no-op (the operator must re-key through their KMS).
  var backend = _fakeBackend();
  var kms = b.agent.snapshot.create({
    orchestrator: _fakeOrch(),
    backend:      backend,
    signer:       _fakeSigner(),
    sealer:       _fakeSealer(),   // AES-GCM fake → not a vault.aad: blob
  });
  var snap = await kms.takeSnapshot({});
  await kms.persist(snap);
  var oldRootJson = b.vault.getKeysJson();
  var newRootJson = JSON.stringify(
    Object.assign(JSON.parse(oldRootJson), { _rotationTestRoot: "v5" }));
  await expectRejection("reseal refuses a non-vault-sealed row",
    b.agent.snapshot.reseal({
      backend:     backend,
      oldRootJson: oldRootJson,
      newRootJson: newRootJson,
    }),
    "agent-snapshot/not-vault-sealed");
}

async function testResealDescriptorMapsStore() {
  // The AAD_ROTATION.reseal adapter maps the pipeline's generic `store`
  // term onto this module's backend.
  var backend = _fakeBackend();
  var snapshot = _vaultBackedSnapshot(backend);
  await snapshot.persist(await snapshot.takeSnapshot({}));
  var oldRootJson = b.vault.getKeysJson();
  var newRootJson = JSON.stringify(
    Object.assign(JSON.parse(oldRootJson), { _rotationTestRoot: "v4" }));
  var result = await b.agent.snapshot.AAD_ROTATION.reseal({
    store:       backend,
    oldRootJson: oldRootJson,
    newRootJson: newRootJson,
  });
  check("AAD_ROTATION.reseal: re-keyed via store alias", result.resealed === 1);
}

async function runReseal() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-snapshot-reseal-"));
  await helpers.setupVaultOnly(tmpDir);
  try {
    testResealRotationSurface();
    await testResealBadInputRefused();
    await testResealRekeysUnderNewRoot();
    await testResealSkipsPlaintextRows();
    await testResealRefusesNonVaultSealer();
    await testResealDescriptorMapsStore();
    await testResealDescriptorBackendKey();
    await testResealRekeyFailure();
  } finally {
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function testAllowPlaintextRefusedUnderRegulatedPosture() {
  // #112 — allowPlaintext claimed to be "refused under hipaa/pci-dss/gdpr/soc2"
  // but had NO posture check: persist wrote a plaintext body and load waived
  // signature verification (CWE-347) under a regulated posture. The dev escape
  // hatch must actually refuse under a regulated posture, at BOTH boundaries.
  var backend = _fakeBackend();
  try {
    b.compliance.clear();
    b.compliance.set("hipaa");

    // (A) persist must refuse the no-sealer plaintext path under hipaa.
    var plain = b.agent.snapshot.create({
      orchestrator:   _fakeOrch(),
      backend:        backend,
      signer:         _fakeSigner(),   // signer wired; sealer omitted -> plaintext body
      allowPlaintext: true,
    });
    var sA = await plain.takeSnapshot({});
    await expectRejection("persist allowPlaintext refused under hipaa",
      plain.persist(sA), "agent-snapshot/plaintext-refused-under-posture");

    // (B) load must NOT waive verify for an attacker-written unsigned snapshot
    // under hipaa (the CWE-347 path).
    var signed = _signedSnapshot({ backend: backend });
    var sB = await signed.takeSnapshot({});
    await backend.put(sB.snapshotId, Object.assign({}, sB, { sig: null }));
    var plainLoader = b.agent.snapshot.create({
      orchestrator: _fakeOrch(), backend: backend, signer: _fakeSigner(), allowPlaintext: true,
    });
    await expectRejection("load unsigned NOT waived under hipaa",
      plainLoader.loadById(sB.snapshotId), "agent-snapshot/plaintext-refused-under-posture");
  } finally {
    b.compliance.clear();
  }

  // (C) control — with no regulated posture (dev), the escape hatch still works.
  var devBackend = _fakeBackend();
  var dev = b.agent.snapshot.create({
    orchestrator: _fakeOrch(), backend: devBackend, signer: _fakeSigner(), allowPlaintext: true,
  });
  var sC = await dev.takeSnapshot({});
  var persisted = await dev.persist(sC);
  check("dev allowPlaintext persists without a regulated posture",
    persisted && typeof persisted.snapshotId === "string");
}

// ---- Load-gate: wrapper-vs-body cross-checks + signature refusals -------

async function testTenantMismatchRefused() {
  // A hostile backend relabels a SEALED row's decorative wrapper tenantId.
  // The seal's AAD binds table + snapshotId + schemaVersion but NOT
  // tenantId, so the Poly1305 tag still verifies after the relabel — yet
  // the wrapper tenantId is exactly what loadLatest({ tenantId }) filters
  // on. Without a wrapper-vs-body cross-check, loadLatest({ tenantId:"b" })
  // returns tenant-a's AUTHENTIC snapshot (cross-tenant restore). The load
  // gate must refuse the relabel.
  var backend = _fakeBackend();
  var snapshot = _signedSnapshot({ backend: backend });
  var s = await snapshot.takeSnapshot({ tenantId: "tenant-a" });
  await snapshot.persist(s);
  var raw = await backend.get(s.snapshotId);
  await backend.put(s.snapshotId, Object.assign({}, raw, { tenantId: "tenant-b" }));
  await expectRejection("loadLatest refuses relabelled cross-tenant wrapper",
    snapshot.loadLatest({ tenantId: "tenant-b" }),
    "agent-snapshot/tenant-id-mismatch");

  // Control — an untouched tenant still round-trips.
  var backend2 = _fakeBackend();
  var snap2 = _signedSnapshot({ backend: backend2 });
  var s2 = await snap2.takeSnapshot({ tenantId: "tenant-c" });
  await snap2.persist(s2);
  var ok = await snap2.loadLatest({ tenantId: "tenant-c" });
  check("loadLatest returns matching-tenant snapshot",
    ok && ok.snapshotId === s2.snapshotId && ok.tenantId === "tenant-c");
}

async function testTakenAtMismatchRefused() {
  // Same class as the tenant relabel: loadLatest sorts candidates on the
  // untrusted wrapper takenAt to pick "latest", but takenAt is not AAD-bound,
  // so a hostile backend can relabel a returned row's age. takenAt is a signed
  // body field, so the load gate cross-checks the wrapper against the body and
  // refuses a divergence (audit-integrity / rollback defense).
  var backend = _fakeBackend();
  var snapshot = _signedSnapshot({ backend: backend });
  var s = await snapshot.takeSnapshot({ tenantId: "tenant-a" });
  await snapshot.persist(s);
  var raw = await backend.get(s.snapshotId);
  await backend.put(s.snapshotId, Object.assign({}, raw, { takenAt: (raw.takenAt || 0) + 1000000 }));
  await expectRejection("loadById refuses a relabelled wrapper takenAt",
    snapshot.loadById(s.snapshotId),
    "agent-snapshot/taken-at-mismatch");

  // Control — an untouched row still round-trips.
  var backend2 = _fakeBackend();
  var snap2 = _signedSnapshot({ backend: backend2 });
  var s2 = await snap2.takeSnapshot({ tenantId: "tenant-c" });
  await snap2.persist(s2);
  var ok = await snap2.loadLatest({ tenantId: "tenant-c" });
  check("loadLatest returns row with un-relabelled takenAt",
    ok && ok.snapshotId === s2.snapshotId);
}

// A backend whose list() can be forged independently of get() — the deeper
// threat model where list() and get() are separately tamperable.
function _listForgingBackend() {
  var map = new Map();
  var forge = null;   // when set: { field, value } applied to list() entries only
  return {
    put:    function (k, v) { map.set(k, v); return Promise.resolve(); },
    get:    function (k)    { return Promise.resolve(map.get(k) || null); },
    delete: function (k)    { map.delete(k); return Promise.resolve(); },
    list:   function () {
      var out = [];
      map.forEach(function (v) {
        if (forge) { var c = Object.assign({}, v); c[forge.field] = forge.value; out.push(c); }
        else out.push(v);
      });
      return Promise.resolve(out);
    },
    forgeList: function (field, value) { forge = { field: field, value: value }; },
  };
}

async function testListOnlyTenantForgeryRefused() {
  // Deeper than a get() wrapper relabel: list() and get() are independently
  // tamperable. A backend that relabels tenant A's LIST entry as tenant B while
  // leaving A's get() row honest passes the wrapper/body cross-check in
  // _unwrapAndVerify (the honest row agrees with its own body), yet
  // loadLatest({ tenantId:'tenant-b' }) selects it via the forged list filter
  // and would return A's authentic snapshot for a tenant-B query. The requested
  // tenantId must be bound to the loaded snapshot's authenticated tenantId.
  var backend = _listForgingBackend();
  var snapshot = _signedSnapshot({ backend: backend });
  var s = await snapshot.takeSnapshot({ tenantId: "tenant-a" });
  await snapshot.persist(s);
  backend.forgeList("tenantId", "tenant-b");   // list() now claims tenant-b; get() stays tenant-a
  await expectRejection("loadLatest refuses a list()-only tenant forgery (requested vs authenticated)",
    snapshot.loadLatest({ tenantId: "tenant-b" }),
    "agent-snapshot/tenant-id-mismatch");
}

async function testListOnlyTakenAtForgeryRefused() {
  // list() sort metadata is likewise untrusted: a backend that inflates a row's
  // list() takenAt to win the "latest" sort, while get() returns the honest
  // (older) body, is caught by binding the selection sort key to the loaded
  // snapshot's authenticated takenAt.
  var backend = _listForgingBackend();
  var snapshot = _signedSnapshot({ backend: backend });
  var s = await snapshot.takeSnapshot({ tenantId: "tenant-a" });
  await snapshot.persist(s);
  backend.forgeList("takenAt", 99999999999999);   // list() claims a far-future age; get() stays honest
  await expectRejection("loadLatest refuses a list()-only takenAt sort-key forgery",
    snapshot.loadLatest({ tenantId: "tenant-a" }),
    "agent-snapshot/taken-at-mismatch");
}

async function testTenantMismatchTamperDirections() {
  // Both directions of a wrapper/body tenant divergence are refused: a
  // hostile backend that ADDS a tenant to a no-tenant body, and one that
  // STRIPS the tenant from a tenant body.
  var backend = _fakeBackend();
  var snapshot = _signedSnapshot({ backend: backend });

  var s0 = await snapshot.takeSnapshot({});
  await snapshot.persist(s0);
  var raw0 = await backend.get(s0.snapshotId);
  await backend.put(s0.snapshotId, Object.assign({}, raw0, { tenantId: "ghost" }));
  await expectRejection("wrapper adds a tenant to a no-tenant body → refused",
    snapshot.loadById(s0.snapshotId), "agent-snapshot/tenant-id-mismatch");

  var s1 = await snapshot.takeSnapshot({ tenantId: "real" });
  await snapshot.persist(s1);
  var raw1 = await backend.get(s1.snapshotId);
  await backend.put(s1.snapshotId, Object.assign({}, raw1, { tenantId: null }));
  await expectRejection("wrapper strips the tenant from a tenant body → refused",
    snapshot.loadById(s1.snapshotId), "agent-snapshot/tenant-id-mismatch");
}

async function testTopologySameCountRemap() {
  // Same consumer COUNT but a different topic SET is a real topology
  // change — a count-only comparison would miss it and defeat
  // refuseOnTopologyChange. [a,b] -> [a,c].
  var snapHealth = { agents: [], elections: [], consumers: [{ topic: "a" }, { topic: "b" }], streams: 0, draining: false, overall: "ok" };
  var restoreHealth = { agents: [], elections: [], consumers: [{ topic: "a" }, { topic: "c" }], streams: 0, draining: false, overall: "ok" };
  var s1 = _signedSnapshot({ orchestrator: _fakeOrch(snapHealth) });
  var snap = await s1.takeSnapshot({ sagas: [{ id: "x" }] });
  var r = await _signedSnapshot({ orchestrator: _fakeOrch(restoreHealth) }).restore(snap, {});
  check("same-count topic remap detected as topology change", r.topologyChanged === true);
  await expectRejection("same-count remap honored by refuseOnTopologyChange",
    _signedSnapshot({ orchestrator: _fakeOrch(restoreHealth) })
      .restore(snap, { refuseOnTopologyChange: true }),
    "agent-snapshot/topology-changed");
}

async function testSnapshotIdMismatchRefused() {
  // A hostile backend returns a different snapshot's body for the
  // requested id. The wrapper/body snapshotId cross-check refuses it
  // before any signature is even consulted.
  var backend = _fakeBackend();
  var writer = _signedSnapshot({ backend: backend });
  var s = await writer.takeSnapshot({});
  await writer.persist(s);
  await backend.put("different-key", s);
  await expectRejection("loadById refuses wrapper/body snapshotId mismatch",
    writer.loadById("different-key"), "agent-snapshot/snapshot-id-mismatch");
}

async function testPlaintextForgedSignatureRefused() {
  // Plaintext-downgrade + forgery: an attacker writes a bare (unsealed)
  // envelope with a tampered signed field, so the stored signature no
  // longer covers the bytes. Load must refuse with bad-signature.
  var backend = _fakeBackend();
  var writer = _signedSnapshot({ backend: backend });
  var s = await writer.takeSnapshot({});
  await writer.persist(s);
  var forged = Object.assign({}, s, { takenAt: s.takenAt + 1 });
  await backend.put(forged.snapshotId, forged);
  await expectRejection("loadById refuses forged plaintext (bad signature)",
    writer.loadById(forged.snapshotId), "agent-snapshot/bad-signature");
}

async function testVerifyThrowsRefused() {
  // A verifier that THROWS (e.g. malformed key material) must fail closed
  // to bad-signature, never accept the snapshot.
  var base = _fakeSigner();
  var throwingVerify = {
    sign:         base.sign,
    verify:       function () { throw new Error("verify boom"); },
    getPublicKey: function () { return null; },
  };
  var backend = _fakeBackend();
  var snapshot = b.agent.snapshot.create({
    orchestrator: _fakeOrch(), backend: backend, signer: throwingVerify, sealer: _fakeSealer(),
  });
  var s = await snapshot.takeSnapshot({});
  await snapshot.persist(s);
  await expectRejection("load refuses when verify throws",
    snapshot.loadById(s.snapshotId), "agent-snapshot/bad-signature");
}

async function testSealedLoadWithoutSealerRefused() {
  // An allowPlaintext-mode loader (no sealer wired, vault not initialized)
  // encountering a SEALED row must refuse — it cannot silently skip the
  // seal and treat the ciphertext as plaintext.
  var backend = _fakeBackend();
  var writer = _signedSnapshot({ backend: backend });
  var s = await writer.takeSnapshot({});
  await writer.persist(s);
  var loader = b.agent.snapshot.create({
    orchestrator: _fakeOrch(), backend: backend, signer: _fakeSigner(), allowPlaintext: true,
  });
  await expectRejection("sealed row + no sealer on load refuses",
    loader.loadById(s.snapshotId), "agent-snapshot/sealer-not-wired");
}

async function testPersistSealerNotWiredRefused() {
  // Signer wired, no sealer, vault not initialized, allowPlaintext not set
  // — persist must refuse rather than write cleartext (secure-by-default).
  var snapshot = b.agent.snapshot.create({
    orchestrator: _fakeOrch(), backend: _fakeBackend(), signer: _fakeSigner(),
  });
  var s = await snapshot.takeSnapshot({});
  await expectRejection("persist without sealer refuses (sealer-not-wired)",
    snapshot.persist(s), "agent-snapshot/sealer-not-wired");
}

// ---- Size caps + defensive take-snapshot shape -------------------------

async function testTakeSnapshotOversizeRefused() {
  var tiny = b.agent.snapshot.create({
    orchestrator: _fakeOrch(), backend: _fakeBackend(),
    signer: _fakeSigner(), sealer: _fakeSealer(),
    policy: { maxSnapshotBytes: 10, drainTimeoutMs: 1000, snapshotIntervalMs: 2000 },
  });
  await expectRejection("takeSnapshot oversize refuses",
    tiny.takeSnapshot({}), "agent-snapshot/oversize");
}

async function testPersistOversizeRefused() {
  // takeSnapshot on a generous facade, persist on a tiny-cap facade: the
  // signed envelope exceeds the persist-time cap.
  var big = _signedSnapshot();
  var s = await big.takeSnapshot({});
  var tiny = b.agent.snapshot.create({
    orchestrator: _fakeOrch(), backend: _fakeBackend(),
    signer: _fakeSigner(), sealer: _fakeSealer(),
    policy: { maxSnapshotBytes: 10 },
  });
  await expectRejection("persist oversize refuses",
    tiny.persist(s), "agent-snapshot/oversize");
}

async function testTakeSnapshotHealthNonArray() {
  // health() that omits the agents/elections/consumers arrays coerces to
  // empty arrays rather than throwing. takeSnapshot() with no opts also
  // exercises the snapshotOpts default.
  var snapshot = _signedSnapshot({ orchestrator: _fakeOrch({ overall: "ok" }) });
  var s = await snapshot.takeSnapshot();
  check("health non-array → empty agents",
    Array.isArray(s.orchestratorState.agents) && s.orchestratorState.agents.length === 0);
  check("health non-array → empty elections", s.orchestratorState.elections.length === 0);
  check("health non-array → empty consumers", s.orchestratorState.consumers.length === 0);
}

// ---- Restore-handler dispatch edges ------------------------------------

async function testRestoreNoHandlersAcknowledgedDrop() {
  // In-flight items, no handlers, requireHandlers NOT set → the drop is
  // acknowledged: restore returns a zero-count result (no throw), the
  // audited skip is the operator's grep signal.
  var snapshot = _signedSnapshot();
  var snap = await snapshot.takeSnapshot({ sagas: [{ id: "s1" }] });
  var r = await snapshot.restore(snap);
  check("restore acknowledged-drop echoes snapshotId", r.snapshotId === snap.snapshotId);
  check("restore acknowledged-drop counts zero", r.restored.sagas === 0);
}

async function testRestoreHandlerThrows() {
  var handlers = { sagas: function () { throw new Error("handler boom"); } };
  var snapshot = _signedSnapshot({ restoreHandlers: handlers });
  var snap = await snapshot.takeSnapshot({ sagas: [{ id: "s1" }] });
  await expectRejection("restore handler throw surfaces as restore-handler-failed",
    snapshot.restore(snap, {}), "agent-snapshot/restore-handler-failed");
}

async function testRestoreVoidHandlerAndNullPayload() {
  // Void (return-undefined) handlers: array payloads count their length,
  // object payloads count 1; a null payload segment is a 0-count no-op.
  var handlers = {
    sagas:            function () { /* void, array payload */ },
    idempotencyCache: function () { /* void, object payload */ },
    streams:          function () { /* payload forced null below */ },
  };
  var snapshot = _signedSnapshot({ restoreHandlers: handlers });
  var snap = await snapshot.takeSnapshot({
    sagas: [{ id: "s1" }, { id: "s2" }], idempotencyCache: { hot: 1 },
  });
  snap.inFlight.streams = null;
  var r = await snapshot.restore(snap, {});
  check("void array-handler returns payload length", r.restored.sagas === 2);
  check("void object-handler returns 1", r.restored.idempotencyCache === 1);
  check("null-payload handler returns 0", r.restored.streams === 0);
}

// ---- Load/list/gc filtering + defensive backends -----------------------

async function testLoadLatestTenantFilter() {
  var snapshot = _signedSnapshot();
  var sa = await snapshot.takeSnapshot({ tenantId: "t-alpha" });
  await snapshot.persist(sa);
  var missByTenant = await snapshot.loadLatest({ tenantId: "t-nope" });
  check("loadLatest tenant filter: no match → null", missByTenant === null);
  var hit = await snapshot.loadLatest({ tenantId: "t-alpha" });
  check("loadLatest tenant filter: match returns snap",
    hit && hit.snapshotId === sa.snapshotId);
}

async function testListFilters() {
  var snapshot = _signedSnapshot();
  var sa = await snapshot.takeSnapshot({ tenantId: "l-alpha" });
  await snapshot.persist(sa);
  var only = await snapshot.list({ tenantId: "l-alpha", sinceMs: 1 });
  check("list tenant+since filter keeps match",
    only.length === 1 && only[0].tenantId === "l-alpha");
  var none = await snapshot.list({ tenantId: "l-beta" });
  check("list tenant filter excludes non-match", none.length === 0);
  var future = await snapshot.list({ sinceMs: Date.now() + 100000 });
  check("list sinceMs filter excludes older", future.length === 0);
  var all = await snapshot.list();
  check("list() no opts returns entries", all.length === 1);
}

async function testGcNoDeleteBackend() {
  var noDel = {
    put:  function () { return Promise.resolve(); },
    get:  function () { return Promise.resolve(null); },
    list: function () { return Promise.resolve([]); },
  };
  var snapshot = _signedSnapshot({ backend: noDel });
  var r = await snapshot.gc();
  check("gc without backend.delete → purged 0", r.purged === 0);
}

async function testGcDeleteThrows() {
  var map = new Map();
  var throwingDel = {
    put:    function (k, v) { map.set(k, v); return Promise.resolve(); },
    get:    function (k)    { return Promise.resolve(map.get(k) || null); },
    list:   function ()     { var o = []; map.forEach(function (v) { o.push(v); }); return Promise.resolve(o); },
    delete: function ()     { return Promise.reject(new Error("delete boom")); },
  };
  var snapshot = _signedSnapshot({ backend: throwingDel });
  var s = await snapshot.takeSnapshot({});
  await snapshot.persist(s);
  await helpers.waitUntil(function () { return Date.now() > s.takenAt; },
    { label: "agent-snapshot.gc: clock past takenAt before delete-throw gc" });
  var r = await snapshot.gc({ olderThanMs: 0 });
  check("gc swallows delete rejection, purged 0", r.purged === 0);
}

// ---- create() + reseal() input-shape edges -----------------------------

async function testCreateNoArgs() {
  var threw = null;
  try { b.agent.snapshot.create(); } catch (e) { threw = e; }
  check("create() no args → bad-orchestrator",
    threw && (threw.code || "").indexOf("agent-snapshot/bad-orchestrator") !== -1);
}

async function testResealBackendListNonArray() {
  var backend = {
    put:  function () { return Promise.resolve(); },
    get:  function () { return Promise.resolve(null); },
    list: function () { return Promise.resolve(null); },
  };
  var r = await b.agent.snapshot.reseal({ backend: backend, oldRootJson: "x", newRootJson: "y" });
  check("reseal list non-array → resealed 0",
    r.resealed === 0 && r.table === "agent.snapshot");
}

async function testResealSkipsBadEntries() {
  var backend = {
    put:  function () { return Promise.resolve(); },
    get:  function (k) { return Promise.resolve(k === "present-null" ? null : null); },
    list: function () {
      return Promise.resolve([{}, { snapshotId: "" }, { snapshotId: "present-null" }]);
    },
  };
  var r = await b.agent.snapshot.reseal({ backend: backend, oldRootJson: "x", newRootJson: "y" });
  check("reseal skips no/empty snapshotId + missing raw", r.resealed === 0);
}

async function testResealNoArgsAndDescriptorNoArgs() {
  await expectRejection("reseal() no args → bad-backend",
    b.agent.snapshot.reseal(), "agent-snapshot/bad-backend");
  await expectRejection("AAD_ROTATION.reseal() no args → bad-backend",
    b.agent.snapshot.AAD_ROTATION.reseal(), "agent-snapshot/bad-backend");
}

async function testLoadByIdBadId() {
  var snapshot = _signedSnapshot();
  await expectRejection("loadById empty id refuses",
    snapshot.loadById(""), "agent-snapshot/bad-snapshot-id");
  await expectRejection("loadById non-string id refuses",
    snapshot.loadById(null), "agent-snapshot/bad-snapshot-id");
}

async function testListAndLoadLatestBackendNonArray() {
  var backend = {
    put:  function () { return Promise.resolve(); },
    get:  function () { return Promise.resolve(null); },
    list: function () { return Promise.resolve(null); },
  };
  var snapshot = _signedSnapshot({ backend: backend });
  var l = await snapshot.list({});
  check("list non-array backend → []", Array.isArray(l) && l.length === 0);
  var latest = await snapshot.loadLatest({});
  check("loadLatest non-array backend → null", latest === null);
}

async function testGcDefaultOlderThan() {
  var backend = _fakeBackend();
  var snapshot = _signedSnapshot({ backend: backend });
  var s = await snapshot.takeSnapshot({});
  await snapshot.persist(s);
  await helpers.waitUntil(function () { return Date.now() > s.takenAt; },
    { label: "agent-snapshot.gc: clock past takenAt for default-olderThan gc" });
  var r = await snapshot.gc({});
  check("gc default olderThanMs purges old entry",
    r.purged === 1 && backend._size() === 0);
}

async function testRealAuditSignerRoundTrip() {
  // No opts.signer → _resolveSigner falls back to the framework's real
  // b.auditSign, exercising the signer wrapper (sign / verify /
  // getPublicKey) and persist's getPublicKey-bound sigPubKey path.
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-snapshot-auditsign-"));
  b.auditSign._resetForTest();
  await b.auditSign.init({ dataDir: dir, mode: "plaintext", algorithm: "ml-dsa-65" });
  try {
    var backend = _fakeBackend();
    var snapshot = b.agent.snapshot.create({
      orchestrator: _fakeOrch(), backend: backend, sealer: _fakeSealer(),
    });
    var s = await snapshot.takeSnapshot({});
    await snapshot.persist(s);
    check("real auditSign: sig populated",
      typeof s.sig === "string" && s.sig.length > 0);
    check("real auditSign: sigPubKey bound off getPublicKey",
      typeof s.sigPubKey === "string" && s.sigPubKey.length > 0);
    var loaded = await snapshot.loadById(s.snapshotId);
    check("real auditSign: verified round-trip",
      loaded && loaded.snapshotId === s.snapshotId);
  } finally {
    b.auditSign._resetForTest();
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

// ---- reseal rekey-failure + descriptor backend-key (vault-backed) ------

async function testResealRekeyFailure() {
  var backend = _fakeBackend();
  var snapshot = _vaultBackedSnapshot(backend);
  var snap = await snapshot.takeSnapshot({});
  await snapshot.persist(snap);
  var raw = await backend.get(snap.snapshotId);
  var prefix = b.agent.snapshot.SEALED_PREFIX;
  var inner = raw.sealed.slice(prefix.length);
  // Corrupt the inner vault.aad ciphertext (keep the prefix so it still
  // looks vault-sealed) so resealRoot's unseal fails. Stamp an explicit
  // wrapper schemaVersion so the != null AAD reconstruction branch runs.
  var corrupted = inner.slice(0, inner.length - 6) + "AAAAAA";
  await backend.put(snap.snapshotId,
    Object.assign({}, raw, { sealed: prefix + corrupted, schemaVersion: 1 }));
  var oldRootJson = b.vault.getKeysJson();
  var newRootJson = JSON.stringify(
    Object.assign(JSON.parse(oldRootJson), { _rotationTestRoot: "v6" }));
  await expectRejection("reseal refuses a row it cannot re-key",
    b.agent.snapshot.reseal({
      backend: backend, oldRootJson: oldRootJson, newRootJson: newRootJson,
    }),
    "agent-snapshot/reseal-failed");
}

async function testResealDescriptorBackendKey() {
  // AAD_ROTATION.reseal maps `backend` when the pipeline passes no `store`.
  var backend = _fakeBackend();
  var snapshot = _vaultBackedSnapshot(backend);
  await snapshot.persist(await snapshot.takeSnapshot({}));
  var oldRootJson = b.vault.getKeysJson();
  var newRootJson = JSON.stringify(
    Object.assign(JSON.parse(oldRootJson), { _rotationTestRoot: "v7" }));
  var result = await b.agent.snapshot.AAD_ROTATION.reseal({
    backend: backend, oldRootJson: oldRootJson, newRootJson: newRootJson,
  });
  check("AAD_ROTATION.reseal via backend key re-keyed", result.resealed === 1);
}

async function run() {
  testSurface();
  await testCreateRequiresOrchestrator();
  await testCreateRequiresBackend();
  await testCreateNoArgs();
  await testSignerNotWiredRefused();
  await testPersistSealerNotWiredRefused();
  await testTakeAndPersist();
  await testTakeSnapshotHealthNonArray();
  await testTakeSnapshotOversizeRefused();
  await testPersistOversizeRefused();
  await testLoadLatest();
  await testLoadLatestTenantFilter();
  await testLoadById();
  await testSnapshotIdMismatchRefused();
  await testTenantMismatchRefused();
  await testTakenAtMismatchRefused();
  await testListOnlyTenantForgeryRefused();
  await testListOnlyTakenAtForgeryRefused();
  await testTenantMismatchTamperDirections();
  await testTopologySameCountRemap();
  await testPlaintextForgedSignatureRefused();
  await testVerifyThrowsRefused();
  await testSealedLoadWithoutSealerRefused();
  await testTamperedEnvelopeRefused();
  await testUnsignedEnvelopeRefused();
  await testAllowPlaintextRefusedUnderRegulatedPosture();
  await testRestoreTopologyChange();
  await testRefuseOnTopologyChange();
  await testSchemaVersionMismatch();
  await testList();
  await testListFilters();
  await testGc();
  await testGcNoDeleteBackend();
  await testGcDeleteThrows();
  await testRestoreHandlersInvoked();
  await testRestoreRequireHandlersRefuses();
  await testRestoreNoHandlersAcknowledgedDrop();
  await testRestoreHandlerThrows();
  await testRestoreVoidHandlerAndNullPayload();
  await testLoadByIdBadId();
  await testListAndLoadLatestBackendNonArray();
  await testGcDefaultOlderThan();
  await testResealBackendListNonArray();
  await testResealSkipsBadEntries();
  await testResealNoArgsAndDescriptorNoArgs();
  await testRealAuditSignerRoundTrip();
  await runReseal();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

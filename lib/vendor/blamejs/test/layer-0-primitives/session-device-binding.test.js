// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.sessionDeviceBinding — bind sessions to a device fingerprint and
 * refuse on drift.
 *
 * Run standalone: `node test/layer-0-primitives/session-device-binding.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var fs   = require("fs");
var os   = require("os");
var path = require("path");

function _captureAudit() {
  var captured = [];
  return {
    safeEmit: function (e) { captured.push(e); },
    captured: captured,
    byAction: function (action) {
      return captured.filter(function (e) { return e.action === action; });
    },
  };
}

function _memoryStore() {
  var data = new Map();
  return {
    data: data,
    get:  function (k) { return Promise.resolve(data.get(k)); },
    set:  function (k, v) { data.set(k, v); return Promise.resolve(); },
    del:  function (k) { data.delete(k); return Promise.resolve(); },
  };
}

function _mockReq(overrides) {
  var base = {
    url: "/x",
    method: "GET",
    headers: {
      "user-agent":      "Mozilla/5.0 (Macintosh; Intel)",
      "accept-language": "en-US,en;q=0.9",
      "accept-encoding": "gzip, br",
    },
    socket: { remoteAddress: "192.0.2.7" },
  };
  if (overrides && overrides.headers) {
    overrides.headers = Object.assign({}, base.headers, overrides.headers);
  }
  return Object.assign({}, base, overrides || {});
}

function testSurface() {
  check("b.sessionDeviceBinding namespace", typeof b.sessionDeviceBinding === "object");
  check("b.sessionDeviceBinding.create is fn", typeof b.sessionDeviceBinding.create === "function");
  check("DEFAULTS frozen", Object.isFrozen(b.sessionDeviceBinding.DEFAULTS));
  check("DEFAULTS.ipV4Prefix 24", b.sessionDeviceBinding.DEFAULTS.ipV4Prefix === 24);
  check("DEFAULTS.fingerprintBytes 32", b.sessionDeviceBinding.DEFAULTS.fingerprintBytes === 32);
  check("sessionDeviceBinding.SessionDeviceBindingError is fn",
        typeof b.sessionDeviceBinding.SessionDeviceBindingError === "function");
}

async function testCreateRejectsBadOpts() {
  var threw;

  // #330 — a no-store create() (no opts, or {} with neither bindingStore nor
  // storeInSession) now returns an INSTANCE whose stateless fingerprint() works
  // (the soft device-binding building block for self-validating tokens), while
  // the persisted bind()/verify()/unbind() lifecycle throws a clear
  // "no store configured" — instead of refusing to construct at all.
  var noStore = b.sessionDeviceBinding.create();
  check("create() with no opts returns a no-store instance", noStore && typeof noStore.fingerprint === "function");
  var noStoreFp = noStore.fingerprint(_mockReq());
  check("no-store instance fingerprint(req) returns a digest", Buffer.isBuffer(noStoreFp) && noStoreFp.length > 0);
  var noStore2 = b.sessionDeviceBinding.create({});
  check("create({}) returns a no-store instance", noStore2 && typeof noStore2.fingerprint === "function");
  // bind() is async, so the no-store guard surfaces as a rejection.
  var bindErr = null;
  try { await noStore2.bind("tok_x", _mockReq()); } catch (e) { bindErr = e; }
  check("no-store bind() fails closed with session-device-binding/no-store",
        bindErr && bindErr.code === "session-device-binding/no-store");

  threw = false;
  try {
    b.sessionDeviceBinding.create({
      bindingStore:    _memoryStore(),
      requireBoundKey: true,
      // missing boundKeyResolver
    });
  } catch (_e) { threw = true; }
  check("create() rejects requireBoundKey without boundKeyResolver", threw);

  threw = false;
  try {
    b.sessionDeviceBinding.create({
      bindingStore: { get: function () {} },  // missing set/del
    });
  } catch (_e) { threw = true; }
  check("create() rejects bad bindingStore shape", threw);

  threw = false;
  try {
    b.sessionDeviceBinding.create({
      bindingStore: _memoryStore(),
      ttlMs:        -1,
    });
  } catch (_e) { threw = true; }
  check("create() rejects negative ttlMs", threw);
}

async function testBindAndVerifyHappyPath() {
  var auditMock = _captureAudit();
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
    audit:        auditMock,
  });
  var token = "tok_" + Date.now();
  var req = _mockReq();
  var fp = await binding.bind(token, req);
  check("bind returns 32-byte fingerprint", Buffer.isBuffer(fp) && fp.length === 32);
  check("audit emitted device.bound",
    auditMock.byAction("session.device.bound").length === 1);

  var verdict = await binding.verify(token, req);
  check("verify returns ok on same fingerprint", verdict.ok === true);
}

async function testVerifyDriftRefuses() {
  var auditMock = _captureAudit();
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
    audit:        auditMock,
  });
  var token = "tok_drift";
  var req1 = _mockReq();
  await binding.bind(token, req1);

  // Different UA → fingerprint drifts.
  var req2 = _mockReq({ headers: { "user-agent": "curl/8" } });
  var verdict = await binding.verify(token, req2);
  check("verify returns ok=false on drift", verdict.ok === false);
  check("verify reason is drift", verdict.reason === "drift");
  check("audit emitted device.drift",
    auditMock.byAction("session.device.drift").length === 1);
  check("audit emitted device.refused",
    auditMock.byAction("session.device.refused").length >= 1);
}

async function testVerifyMissingBindRefuses() {
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
  });
  var verdict = await binding.verify("never-bound", _mockReq());
  check("verify refuses unbound token", verdict.ok === false);
  check("reason missing-bind", verdict.reason === "missing-bind");
}

async function testIpToleranceAcrossSubnet() {
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
  });
  var token = "tok_ip";
  await binding.bind(token, _mockReq({ socket: { remoteAddress: "192.0.2.10" } }));
  // Same /24 → still ok.
  var same24 = await binding.verify(token,
    _mockReq({ socket: { remoteAddress: "192.0.2.99" } }));
  check("verify ok on same /24", same24.ok === true);
  // Different /24 → drift.
  var diff = await binding.verify(token,
    _mockReq({ socket: { remoteAddress: "203.0.113.5" } }));
  check("verify drift on different /24", diff.ok === false);
}

async function testRequireBoundKeyEnforces() {
  var auditMock = _captureAudit();
  var key = Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  var binding = b.sessionDeviceBinding.create({
    bindingStore:     _memoryStore(),
    requireBoundKey:  true,
    boundKeyResolver: function (req) { return req.boundKey || null; },
    audit:            auditMock,
  });
  var token = "tok_bk";
  var req = _mockReq({ boundKey: key });
  await binding.bind(token, req);

  // Verify with same key → ok.
  var ok = await binding.verify(token, _mockReq({ boundKey: key }));
  check("verify ok with same bound key", ok.ok === true);

  // Verify without key → refuse.
  var noKey = await binding.verify(token, _mockReq({ boundKey: null }));
  check("verify refuses missing bound key", noKey.ok === false);
  check("reason missing-bound-key", noKey.reason === "missing-bound-key");

  // Verify with different key → drift.
  var differentKey = Buffer.from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  var diff = await binding.verify(token, _mockReq({ boundKey: differentKey }));
  check("verify drift on different bound key", diff.ok === false);
  check("reason drift on key change", diff.reason === "drift");
}

async function testBindRefusesWithoutBoundKey() {
  var binding = b.sessionDeviceBinding.create({
    bindingStore:     _memoryStore(),
    requireBoundKey:  true,
    boundKeyResolver: function () { return null; },
  });
  var threw = false;
  try { await binding.bind("tok_nokey", _mockReq()); }
  catch (_e) { threw = true; }
  check("bind throws when requireBoundKey but no key", threw);
}

async function testFingerprintIsStable() {
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
  });
  var fp1 = binding.fingerprint(_mockReq());
  var fp2 = binding.fingerprint(_mockReq());
  check("fingerprint stable across identical requests",
    Buffer.isBuffer(fp1) && Buffer.isBuffer(fp2) && fp1.equals(fp2));
}

async function testUnbind() {
  var store = _memoryStore();
  var binding = b.sessionDeviceBinding.create({ bindingStore: store });
  var token = "tok_u";
  await binding.bind(token, _mockReq());
  check("store has token", store.data.has(token));
  await binding.unbind(token);
  check("store cleared after unbind", !store.data.has(token));
}

function testNamespaceFingerprint() {
  // The namespace-level b.sessionDeviceBinding.fingerprint(req, opts?) is the
  // stateless device-hash helper (distinct from an instance's bound method):
  // deterministic for identical request shape, divergent when a bound
  // component changes.
  check("b.sessionDeviceBinding.fingerprint is a function",
    typeof b.sessionDeviceBinding.fingerprint === "function");
  var fp1 = b.sessionDeviceBinding.fingerprint(_mockReq());
  var fp2 = b.sessionDeviceBinding.fingerprint(_mockReq());
  check("namespace fingerprint: returns a Buffer", Buffer.isBuffer(fp1));
  check("namespace fingerprint: deterministic for identical requests", fp1.equals(fp2));
  var other = _mockReq();
  other.headers = Object.assign({}, other.headers, { "user-agent": "Totally-Different/9.9" });
  var fp3 = b.sessionDeviceBinding.fingerprint(other);
  check("namespace fingerprint: diverges when a bound component changes", !fp1.equals(fp3));
}

// ---------------------------------------------------------------------------
// b.session device-binding (lib/session.js) — the persisted, sid-keyed
// fingerprint binding on b.session.create / verify / rotate. Distinct from the
// stateless b.sessionDeviceBinding helper above; these drive the real
// b.session.<method>() consumer path against a live test DB.
// ---------------------------------------------------------------------------

// A request whose client-IP + UA drive the b.session fingerprint. The bare
// socket peer (no trustedProxies) is what b.session hashes by default, so a
// different remoteAddress / user-agent is a genuine device drift.
function _dev(remoteAddress, ua) {
  return {
    headers: { "user-agent": ua || "deviceA", "accept-language": "en-US,en;q=0.9" },
    socket:  { remoteAddress: remoteAddress || "203.0.113.10" },
  };
}

// The strict "maxAnomalyScore" binding policy must FAIL CLOSED when a real
// drift occurs but no decisive anomaly score can be produced (operator set the
// threshold but supplied no scorer, or the scorer can't return a number). The
// pre-fix path left fingerprintAnomalyScore = null and skipped the refusal, so
// a session bound to device A was accepted from device B under a declared
// strict threshold — the exact "binding check that fails open accepts a
// relocated session" this suite guards. Mirrors the existing bindingUnreadable
// fail-closed rule, extended to the uncomputable-score branch.
async function testSessionMaxAnomalyScoreFailsClosedWithoutScore() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-maxscore-"));
  try {
    await setupTestDb(tmpDir);
    var devA = _dev("203.0.113.10", "deviceA");
    var s = await b.session.create({ userId: "u-score", req: devA });

    // Bound device under the same strict policy still verifies (no drift).
    var same = await b.session.verify(s.token, { req: devA, maxAnomalyScore: 0.5 });
    check("maxAnomalyScore: bound device still verifies", same && same.userId === "u-score");

    // Drift from a different device under maxAnomalyScore with NO scorer: the
    // score is uncomputable, so a strict threshold must refuse (null).
    var devB = _dev("198.51.100.9", "deviceB");
    var verdict = await b.session.verify(s.token, { req: devB, maxAnomalyScore: 0.5 });
    check("maxAnomalyScore + drift + no scorer -> FAILS CLOSED (null)", verdict === null);

    // Same root: a scorer that returns a non-number yields no score either.
    var badScorer = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.5, scorer: function () { return "not-a-number"; },
    });
    check("maxAnomalyScore + drift + non-numeric scorer -> FAILS CLOSED (null)", badScorer === null);

    // A scorer that THROWS is swallowed (best-effort) -> score null -> refuse.
    var threwScorer = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.5, scorer: function () { throw new Error("boom"); },
    });
    check("maxAnomalyScore + drift + throwing scorer -> FAILS CLOSED (null)", threwScorer === null);

    // A scorer that returns a non-finite number (Infinity/NaN) yields no score.
    var infScorer = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.5, scorer: function () { return Infinity; },
    });
    check("maxAnomalyScore + drift + non-finite scorer -> FAILS CLOSED (null)", infScorer === null);

    // The refusals above must NOT have destroyed the row (fingerprint refusal is
    // not row cleanup) — the bound device still verifies.
    var still = await b.session.verify(s.token, { req: devA, maxAnomalyScore: 0.5 });
    check("maxAnomalyScore: strict refusal left the session row intact", still && still.userId === "u-score");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// The scorer path itself: a computed score below the threshold admits the
// (drifted) session, above the threshold refuses it, and out-of-range scores
// clamp to [0,1]. Locks the legitimate maxAnomalyScore behavior so the
// fail-closed fix above doesn't over-refuse the benign-drift case.
async function testSessionMaxAnomalyScoreScorerBands() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-scorer-"));
  try {
    await setupTestDb(tmpDir);
    var devA = _dev("203.0.113.10", "deviceA");
    var s = await b.session.create({ userId: "u-sc", req: devA });
    var devB = _dev("198.51.100.9", "deviceB");

    // Benign drift (score below threshold) -> accepted, drift + score surfaced.
    var benign = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.8, scorer: function () { return 0.2; },
    });
    check("maxAnomalyScore: score below threshold -> accepted with drift",
      benign && benign.fingerprintDrift === true && benign.fingerprintAnomalyScore === 0.2);

    // Malicious drift (score above threshold) -> refused.
    var refused = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.5, scorer: function () { return 0.9; },
    });
    check("maxAnomalyScore: score above threshold -> refused (null)", refused === null);

    // Out-of-range score clamps to 1 -> above 0.99 -> refused.
    var clamp = await b.session.verify(s.token, {
      req: devB, maxAnomalyScore: 0.99, scorer: function () { return 5; },
    });
    check("maxAnomalyScore: score clamps to 1 -> above threshold -> refused (null)", clamp === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// requireFingerprintMatch: any drift on a readable binding refuses the session
// (returns null) without destroying the row; default mode surfaces drift but
// returns the session. Covers the strict-refuse and default-drift branches of
// verify() that the unreadable-binding test does not exercise.
async function testSessionRequireFingerprintMatchDrift() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-reqfp-"));
  try {
    await setupTestDb(tmpDir);
    var devA = _dev("203.0.113.10", "deviceA");
    var s = await b.session.create({ userId: "u-strict2", req: devA });

    var ok = await b.session.verify(s.token, { req: devA, requireFingerprintMatch: true });
    check("requireFingerprintMatch: same device verifies", ok && ok.userId === "u-strict2");

    var devB = _dev("198.51.100.9", "deviceB");
    var refused = await b.session.verify(s.token, { req: devB, requireFingerprintMatch: true });
    check("requireFingerprintMatch: drift refuses (null)", refused === null);

    var stillOk = await b.session.verify(s.token, { req: devA, requireFingerprintMatch: true });
    check("requireFingerprintMatch: refusal did not destroy the row", stillOk && stillOk.userId === "u-strict2");

    // Default mode (no strict opt) surfaces the drift but still returns it.
    var lax = await b.session.verify(s.token, { req: devB });
    check("default mode: drift surfaced, session returned", lax && lax.fingerprintDrift === true);
    check("default mode: fingerprintAnomalyScore is null without a scorer", lax.fingerprintAnomalyScore === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// rotate() on a fingerprint-bound session without { req } throws (the sid-keyed
// binding cannot follow the new sid otherwise) and leaves the old session
// intact; an unbound session rotates without req. Covers the
// ROTATE_FINGERPRINT_REQ_REQUIRED guard.
async function testSessionRotateRequiresReqOnBound() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-rotreq-"));
  try {
    await setupTestDb(tmpDir);
    var devA = _dev("203.0.113.10", "deviceA");
    var s = await b.session.create({ userId: "u-rotreq", req: devA });

    var err = null;
    try { await b.session.rotate(s.token); } catch (e) { err = e; }
    check("rotate on a bound session without req throws",
      err && err.code === "ROTATE_FINGERPRINT_REQ_REQUIRED");

    // The throw happened before the UPDATE — the bound session is untouched.
    var still = await b.session.verify(s.token, { req: devA, requireFingerprintMatch: true });
    check("rotate throw left the bound session intact", still && still.userId === "u-rotreq");

    // An unbound session rotates fine without req.
    var s2 = await b.session.create({ userId: "u-unbound" });
    var r2 = await b.session.rotate(s2.token);
    check("rotate on an unbound session without req succeeds", r2 && typeof r2.token === "string");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// Anonymous session minting + isAnonymous + destroyAllForUser's anon refusal.
async function testSessionAnonymousLifecycle() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-anon-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ anonymous: true });
    check("anonymous create returns a token", s && typeof s.token === "string");

    var info = await b.session.verify(s.token);
    check("anonymous session verifies", info && typeof info.userId === "string");
    check("anonymous userId carries the anon: prefix", info.userId.indexOf(b.session.ANON_PREFIX) === 0);
    check("b.session.isAnonymous true for an anon userId", b.session.isAnonymous(info.userId) === true);
    check("b.session.isAnonymous false for a normal userId", b.session.isAnonymous("user-42") === false);

    var both = null;
    try { await b.session.create({ anonymous: true, userId: "u-x" }); } catch (e) { both = e; }
    check("create rejects anonymous:true + userId together", both && both.code === "INVALID_ARG");

    var refuseAnon = null;
    try { await b.session.destroyAllForUser(info.userId); } catch (e) { refuseAnon = e; }
    check("destroyAllForUser refuses an anon-prefix id", refuseAnon && refuseAnon.code === "INVALID_ARG");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  testSurface();
  testNamespaceFingerprint();
  await testCreateRejectsBadOpts();
  await testBindAndVerifyHappyPath();
  await testVerifyDriftRefuses();
  await testVerifyMissingBindRefuses();
  await testIpToleranceAcrossSubnet();
  await testRequireBoundKeyEnforces();
  await testBindRefusesWithoutBoundKey();
  await testFingerprintIsStable();
  await testUnbind();
  // b.session (lib/session.js) persisted device-binding paths.
  await testSessionMaxAnomalyScoreFailsClosedWithoutScore();
  await testSessionMaxAnomalyScoreScorerBands();
  await testSessionRequireFingerprintMatchDrift();
  await testSessionRotateRequiresReqOnBound();
  await testSessionAnonymousLifecycle();
}

if (require.main === module) {
  run().then(function () {
    console.log("OK session-device-binding — " + helpers.getChecks() + " checks");
  }).catch(function (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  });
}

module.exports = { run: run };

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

function testCreateRejectsBadOpts() {
  var threw;

  threw = false;
  try { b.sessionDeviceBinding.create(); } catch (_e) { threw = true; }
  check("create() rejects empty opts", threw);

  threw = false;
  try { b.sessionDeviceBinding.create({}); } catch (_e) { threw = true; }
  check("create() requires bindingStore or storeInSession", threw);

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

async function run() {
  testSurface();
  testCreateRejectsBadOpts();
  await testBindAndVerifyHappyPath();
  await testVerifyDriftRefuses();
  await testVerifyMissingBindRefuses();
  await testIpToleranceAcrossSubnet();
  await testRequireBoundKeyEnforces();
  await testBindRefusesWithoutBoundKey();
  await testFingerprintIsStable();
  await testUnbind();
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

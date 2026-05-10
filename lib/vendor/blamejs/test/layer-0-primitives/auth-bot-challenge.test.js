"use strict";
/**
 * b.authBotChallenge — adaptive bot-challenge gate for auth paths.
 *
 * Run standalone: `node test/layer-0-primitives/auth-bot-challenge.test.js`
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

// In-memory store matching the b.cache get/set/del shape.
function _memoryStore() {
  var data = new Map();
  return {
    data: data,
    get:  function (k) { return Promise.resolve(data.get(k)); },
    set:  function (k, v) { data.set(k, v); return Promise.resolve(); },
    del:  function (k) { data.delete(k); return Promise.resolve(); },
  };
}

// Minimal lockout-shaped fake matching create()'s contract.
function _fakeLockout() {
  var state = {};
  var calls = { fail: 0, success: 0, unlock: 0 };
  return {
    calls: calls,
    state: state,
    recordFailure: function (key) {
      calls.fail += 1;
      state[key] = (state[key] || 0) + 1;
      return Promise.resolve({ locked: false, attempts: state[key] });
    },
    recordSuccess: function (key) {
      calls.success += 1;
      delete state[key];
      return Promise.resolve();
    },
    check: function (key) {
      return Promise.resolve({ locked: false, attempts: state[key] || 0 });
    },
    unlock: function (key) {
      calls.unlock += 1;
      delete state[key];
      return Promise.resolve(true);
    },
  };
}

// Simple bot-guard fake: configurable verdict.
function _fakeBotGuard(behaviour) {
  return function (req, res, next) {
    if (behaviour === "tag") {
      req.suspectedBot = "missing-accept-language";
      return next();
    }
    if (behaviour === "block") {
      if (typeof res.writeHead === "function") res.writeHead(403);
      res.end("blocked");
      return;
    }
    return next();  // "pass"
  };
}

function _mockReq(overrides) {
  return Object.assign({
    url: "/login",
    method: "POST",
    headers: {
      "user-agent": "Mozilla/5.0 (test)",
      "accept-language": "en-US,en;q=0.9",
    },
    body: { email: "user@example.com" },
    socket: { remoteAddress: "192.0.2.1" },
  }, overrides || {});
}

function _mockRes() {
  var r = {
    statusCode: 0,
    body: "",
    headers: {},
    writableEnded: false,
    writeHead: function (status, headers) {
      r.statusCode = status;
      r.headers = headers || {};
    },
    end: function (body) { r.body = body || ""; r.writableEnded = true; },
  };
  return r;
}

function testSurface() {
  check("b.authBotChallenge namespace", typeof b.authBotChallenge === "object");
  check("b.authBotChallenge.create is function", typeof b.authBotChallenge.create === "function");
  check("STATES frozen", Object.isFrozen(b.authBotChallenge.STATES));
  check("DEFAULTS.threshold 3", b.authBotChallenge.DEFAULTS.threshold === 3);
  check("DEFAULTS.escalationThreshold 6", b.authBotChallenge.DEFAULTS.escalationThreshold === 6);
  check("authBotChallenge.AuthBotChallengeError is fn",
        typeof b.authBotChallenge.AuthBotChallengeError === "function");
}

function testCreateRejectsBadOpts() {
  var threw;
  threw = false;
  try { b.authBotChallenge.create(); } catch (_e) { threw = true; }
  check("create() rejects empty opts", threw);

  threw = false;
  try {
    b.authBotChallenge.create({
      botGuard: _fakeBotGuard("pass"),
      lockout:  _fakeLockout(),
      sessionStore: _memoryStore(),
      threshold: 5,
      escalationThreshold: 3,
    });
  } catch (_e) { threw = true; }
  check("create() rejects escalationThreshold <= threshold", threw);

  threw = false;
  try {
    b.authBotChallenge.create({
      botGuard: "not-a-fn",
      lockout:  _fakeLockout(),
      sessionStore: _memoryStore(),
    });
  } catch (_e) { threw = true; }
  check("create() rejects bad botGuard", threw);

  threw = false;
  try {
    b.authBotChallenge.create({
      botGuard: _fakeBotGuard("pass"),
      lockout:  {},
      sessionStore: _memoryStore(),
    });
  } catch (_e) { threw = true; }
  check("create() rejects bad lockout shape", threw);

  threw = false;
  try {
    b.authBotChallenge.create({
      botGuard: _fakeBotGuard("pass"),
      lockout:  _fakeLockout(),
      sessionStore: { get: function () {} },  // missing set/del
    });
  } catch (_e) { threw = true; }
  check("create() rejects bad sessionStore shape", threw);
}

async function testStaircaseAdvances() {
  var auditMock = _captureAudit();
  var lockout = _fakeLockout();
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    2,
    escalationThreshold: 4,
    audit:        auditMock,
  });
  var key = "user@example.com";

  var s1 = await gate.recordFailure(key);
  check("first failure stays NEW", s1.stage === "new");
  var s2 = await gate.recordFailure(key);
  check("second failure transitions to challenged", s2.stage === "challenged");
  check("audit emitted required",
    auditMock.byAction("auth.bot_challenge.required").length === 1);

  var s3 = await gate.recordFailure(key);
  check("third failure stays challenged", s3.stage === "challenged");
  var s4 = await gate.recordFailure(key);
  check("fourth failure escalates to locked", s4.stage === "locked");
  check("audit emitted escalated",
    auditMock.byAction("auth.bot_challenge.escalated").length === 1);
}

async function testMiddlewareChallengeFn() {
  var auditMock = _captureAudit();
  var lockout = _fakeLockout();
  var challengeCalls = 0;
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("tag"),  // marks suspectedBot
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    1,
    escalationThreshold: 5,
    challengeFn:  function (req) {
      challengeCalls += 1;
      return Promise.resolve(req.body && req.body.captchaToken === "good");
    },
    audit:        auditMock,
  });
  var key = "user@example.com";
  // Force the state into challenged.
  await gate.recordFailure(key);

  var mw = gate.middleware();
  var nextCalled = 0;
  // Bad captcha → middleware should not call next; it writes 401.
  var req = _mockReq({ body: { email: key, captchaToken: "wrong" } });
  var res = _mockRes();
  await mw(req, res, function () { nextCalled += 1; });
  check("middleware did not call next on bad captcha", nextCalled === 0);
  check("middleware wrote 401", res.statusCode === 401);
  check("challengeFn invoked", challengeCalls === 1);

  // Good captcha → next called, state transitions to passed.
  var req2 = _mockReq({ body: { email: key, captchaToken: "good" } });
  var res2 = _mockRes();
  await mw(req2, res2, function () { nextCalled += 1; });
  check("middleware calls next on good captcha", nextCalled === 1);
  check("audit emitted passed",
    auditMock.byAction("auth.bot_challenge.passed").length >= 1);
}

async function testMiddlewareLockedReturns423() {
  var lockout = _fakeLockout();
  var auditMock = _captureAudit();
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    1,
    escalationThreshold: 2,
    audit:        auditMock,
  });
  var key = "u@x";
  await gate.recordFailure(key);
  await gate.recordFailure(key);  // → locked

  var mw = gate.middleware();
  var req = _mockReq({ body: { email: key } });
  var res = _mockRes();
  var nextCalled = 0;
  await mw(req, res, function () { nextCalled += 1; });
  check("middleware refuses locked session with 423", res.statusCode === 423);
  check("middleware did not call next on locked", nextCalled === 0);
}

async function testRecordSuccessClears() {
  var lockout = _fakeLockout();
  var auditMock = _captureAudit();
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    2,
    escalationThreshold: 5,
    audit:        auditMock,
  });
  await gate.recordFailure("u@x");
  await gate.recordFailure("u@x");
  var pre = await gate.check("u@x");
  check("state advanced to challenged", pre.stage === "challenged");
  await gate.recordSuccess("u@x");
  var post = await gate.check("u@x");
  check("state cleared after recordSuccess", post.stage === "new");
  check("lockout.recordSuccess called", lockout.calls.success >= 1);
}

async function testReset() {
  var lockout = _fakeLockout();
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      lockout,
    sessionStore: _memoryStore(),
    threshold:    2,
    escalationThreshold: 5,
  });
  await gate.recordFailure("u@x");
  await gate.recordFailure("u@x");
  var did = await gate.reset("u@x");
  check("reset returns true when state existed", did === true);
  check("lockout.unlock called by reset", lockout.calls.unlock >= 1);
}

async function testEscalationFnInvoked() {
  var escalated = 0;
  var gate = b.authBotChallenge.create({
    botGuard:     _fakeBotGuard("pass"),
    lockout:      _fakeLockout(),
    sessionStore: _memoryStore(),
    threshold:    1,
    escalationThreshold: 2,
    escalationFn: function () { escalated += 1; return Promise.resolve(); },
  });
  await gate.recordFailure("u@x");
  await gate.recordFailure("u@x");
  // Yield so the in-flight escalationFn can settle.
  await new Promise(function (r) { setImmediate(r); });
  check("escalationFn invoked when threshold crossed", escalated === 1);
}

async function run() {
  testSurface();
  testCreateRejectsBadOpts();
  await testStaircaseAdvances();
  await testMiddlewareChallengeFn();
  await testMiddlewareLockedReturns423();
  await testRecordSuccessClears();
  await testReset();
  await testEscalationFnInvoked();
}

if (require.main === module) {
  run().then(function () {
    console.log("OK auth-bot-challenge — " + helpers.getChecks() + " checks");
  }).catch(function (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  });
}

module.exports = { run: run };

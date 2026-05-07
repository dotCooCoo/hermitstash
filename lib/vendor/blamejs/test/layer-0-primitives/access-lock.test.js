"use strict";
/**
 * b.auth.accessLock — three-mode access-lock primitive tests.
 *
 * Run standalone: `node test/layer-0-primitives/access-lock.test.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockReq(method, url, opts) {
  opts = opts || {};
  return {
    method:  method || "GET",
    url:     url || "/",
    headers: opts.headers || {},
    user:    opts.user || null,
  };
}
function _mockRes() {
  var captured = { headers: null, body: null, status: 0, ended: false };
  return {
    writableEnded: false,
    writeHead: function (status, headers) {
      captured.status = status;
      captured.headers = headers;
    },
    end: function (body) {
      captured.body = body;
      captured.ended = true;
      this.writableEnded = true;
    },
    _captured: captured,
  };
}

function testOpenModePassesEverything() {
  var lock = b.auth.accessLock.create({ startMode: "open", audit: false });
  var mw = lock.middleware();
  var calls = 0;
  mw(_mockReq("GET",    "/"), _mockRes(), function () { calls++; });
  mw(_mockReq("POST",   "/"), _mockRes(), function () { calls++; });
  mw(_mockReq("DELETE", "/"), _mockRes(), function () { calls++; });
  check("open mode passes every method", calls === 3);
  check("lock.mode() reports open", lock.mode() === "open");
}

function testReadOnlyModeRefusesWrites() {
  var lock = b.auth.accessLock.create({ startMode: "read-only", audit: false });
  var mw = lock.middleware();
  var calls = 0;
  var res1 = _mockRes(), res2 = _mockRes(), res3 = _mockRes();
  mw(_mockReq("GET",    "/"), res1, function () { calls++; });
  mw(_mockReq("HEAD",   "/"), res2, function () { calls++; });
  mw(_mockReq("POST",   "/"), res3, function () { calls++; });
  check("read-only passes GET",  calls >= 1 && res1._captured.status === 0);
  check("read-only passes HEAD", calls >= 2 && res2._captured.status === 0);
  check("read-only refuses POST 503", res3._captured.status === 503);
  check("read-only refused with Retry-After", res3._captured.headers["Retry-After"] === "60");
}

function testLockedModeRefusesEverythingExceptPassthrough() {
  var lock = b.auth.accessLock.create({
    startMode:        "locked",
    audit:            false,
    passthroughPaths: ["/healthz", "/admin/access-lock"],
  });
  var mw = lock.middleware();
  var passthroughCalls = 0;
  var refusedRes = _mockRes();
  mw(_mockReq("GET", "/healthz"),                _mockRes(), function () { passthroughCalls++; });
  mw(_mockReq("POST","/admin/access-lock/open"), _mockRes(), function () { passthroughCalls++; });
  mw(_mockReq("GET", "/api/things"),             refusedRes, function () { passthroughCalls++; });
  check("locked passes /healthz",                          passthroughCalls >= 1);
  check("locked passes /admin/access-lock subpath",        passthroughCalls >= 2);
  check("locked refuses /api/things 503",                  refusedRes._captured.status === 503);
}

function testUnlockRolesBypassEveryMode() {
  var lock = b.auth.accessLock.create({
    startMode:    "locked",
    audit:        false,
    unlockRoles:  ["sre"],
    getRole:      function (req) { return req.user && req.user.role; },
  });
  var mw = lock.middleware();
  var sreCalls = 0;
  var nonSreRes = _mockRes();
  mw(_mockReq("POST", "/anything", { user: { role: "sre" } }),     _mockRes(), function () { sreCalls++; });
  mw(_mockReq("POST", "/anything", { user: { role: "viewer" } }),  nonSreRes,  function () {});
  check("sre bypasses locked mode",   sreCalls === 1);
  check("non-sre refused in locked",  nonSreRes._captured.status === 503);
}

function testSetTransitionsAuditAndChangeMode() {
  var lock = b.auth.accessLock.create({ startMode: "open", audit: false });
  check("initial mode is open", lock.mode() === "open");
  var r1 = lock.set("locked", { actor: "sre-bot", reason: "schema migration" });
  check("transition reports changed",     r1.changed === true);
  check("transition reports from",        r1.from === "open");
  check("transition reports to",          r1.mode === "locked");
  check("lock.mode() reflects new mode",  lock.mode() === "locked");
  var r2 = lock.set("locked");
  check("no-op transition reports changed=false", r2.changed === false);
  var status = lock.status();
  check("status exposes current mode", status.mode === "locked");
  check("status exposes setBy",        status.setBy === "sre-bot");
  check("status exposes reason",       status.reason === "schema migration");
}

function testSetRefusesUnknownMode() {
  var lock = b.auth.accessLock.create({ startMode: "open", audit: false });
  var threw = false;
  try { lock.set("vacation"); }
  catch (e) { threw = e.code === "auth-access-lock/bad-mode"; }
  check("set refuses unknown mode", threw);
}

function testCreateRefusesBadStartMode() {
  var threw = false;
  try { b.auth.accessLock.create({ startMode: "WAT" }); }
  catch (e) { threw = e.code === "auth-access-lock/bad-mode"; }
  check("create refuses bad startMode", threw);
}

(function run() {
  testOpenModePassesEverything();
  testReadOnlyModeRefusesWrites();
  testLockedModeRefusesEverythingExceptPassthrough();
  testUnlockRolesBypassEveryMode();
  testSetTransitionsAuditAndChangeMode();
  testSetRefusesUnknownMode();
  testCreateRefusesBadStartMode();
  console.log("OK — access-lock tests");
})();

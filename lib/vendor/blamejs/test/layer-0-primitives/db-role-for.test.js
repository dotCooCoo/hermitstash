"use strict";
/**
 * b.middleware.dbRoleFor — request-time DB role binding.
 *
 * Covers create() opts validation, runtime resolver-output validation,
 * AsyncLocalStorage scope, fallthrough resolution order (resolve →
 * permissions → defaultRole), and the requireRole 401 path.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;
var _mockReq = helpers._mockReq;
var _mockRes = helpers._mockRes;

var dbRoleContext = require("../../lib/db-role-context");

function _runMw(mw, req, res) {
  return new Promise(function (resolve, reject) {
    mw(req, res, function (err) {
      if (err) return reject(err);
      // After next() — capture the ALS role inside the middleware's
      // continuation by reading it before the resolve.
      resolve({ role: dbRoleContext.getRole() });
    });
  });
}

async function run() {
  // ---- opts validation rejects bad shapes at create() ----

  function rejects(label, fn, re) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("dbRoleFor rejects: " + label,
      threw && (re.test(threw.code || "") || re.test(threw.message || "")));
  }

  rejects("unknown opt",
    function () { b.middleware.dbRoleFor({ bogus: 1 }); },
    /unknown option|db-role-for\/bad-opt/);

  rejects("non-fn resolve",
    function () { b.middleware.dbRoleFor({ resolve: "x" }); },
    /db-role-for\/bad-opt/);

  rejects("non-fn responder",
    function () { b.middleware.dbRoleFor({ responder: "x" }); },
    /db-role-for\/bad-opt/);

  rejects("non-perms permissions",
    function () { b.middleware.dbRoleFor({ permissions: { foo: 1 } }); },
    /db-role-for\/bad-opt/);

  rejects("empty defaultRole",
    function () { b.middleware.dbRoleFor({ defaultRole: "" }); },
    /db-role-for\/bad-opt/);

  rejects("malformed defaultRole identifier",
    function () { b.middleware.dbRoleFor({ defaultRole: "bad name" }); },
    /db-role-for\/bad-role/);

  rejects("non-boolean requireRole",
    function () { b.middleware.dbRoleFor({ requireRole: "yes" }); },
    /db-role-for\/bad-opt/);

  rejects("out-of-range missingRoleStatus",
    function () { b.middleware.dbRoleFor({ missingRoleStatus: 42 }); },
    /db-role-for\/bad-opt/);

  // ---- resolver path ----

  var mw1 = b.middleware.dbRoleFor({
    resolve: function (req) { return req.user && req.user.dbRole; },
    defaultRole: "app_user",
  });
  var req1 = _mockReq({ url: "/x" });
  req1.user = { dbRole: "analytics_user" };
  var res1 = _mockRes();
  var r1 = await _runMw(mw1, req1, res1);
  check("resolver path: req.dbRole set",        req1.dbRole === "analytics_user");
  check("resolver path: ALS role inside scope", r1.role === "analytics_user");

  // ---- defaultRole fallback when resolver returns null ----

  var req2 = _mockReq({ url: "/x" });
  req2.user = {};                                 // resolver returns undefined
  var res2 = _mockRes();
  var r2 = await _runMw(mw1, req2, res2);
  check("default fallback: req.dbRole=app_user", req2.dbRole === "app_user");
  check("default fallback: ALS role=app_user",   r2.role === "app_user");

  // ---- permissions integration ----

  var perms = b.permissions.create({
    roles: {
      analyst: { permissions: ["sessions:read"], dbRole: "analytics_user" },
      app:     { permissions: ["sessions:*"],    dbRole: "app_user" },
    },
  });
  var mw3 = b.middleware.dbRoleFor({
    permissions: perms,
    defaultRole: "app_user",
  });
  var req3 = _mockReq({ url: "/x" });
  req3.user = { roles: ["analyst"] };
  var r3 = await _runMw(mw3, req3, _mockRes());
  check("permissions integration: dbRole picked from role table",
    req3.dbRole === "analytics_user" && r3.role === "analytics_user");

  // No matching role → defaultRole
  var req4 = _mockReq({ url: "/x" });
  req4.user = { roles: ["unknown"] };
  var r4 = await _runMw(mw3, req4, _mockRes());
  check("permissions: unknown role → defaultRole",
    req4.dbRole === "app_user" && r4.role === "app_user");

  // ---- requireRole + missing actor → 401 ----

  var mw5 = b.middleware.dbRoleFor({
    permissions: perms,
    requireRole: true,                         // no defaultRole
    missingRoleStatus: 401,
  });
  var req5 = _mockReq({ url: "/x" });            // no user → no actor
  var res5 = _mockRes();
  var nextCalled5 = false;
  mw5(req5, res5, function () { nextCalled5 = true; });
  // The default responder writes synchronously, so a microtask flush
  // is enough to let the test check captured status.
  await Promise.resolve();
  var captured5 = res5._captured();
  check("requireRole: 401 when no actor", captured5.status === 401);
  check("requireRole: next() NOT called",  !nextCalled5);
  check("requireRole: ALS NOT entered",   dbRoleContext.getRole() === null);

  // ---- resolver returns malformed identifier → next(err) ----

  var badResolverErr = null;
  var mw6 = b.middleware.dbRoleFor({
    resolve: function () { return "bad name"; },
  });
  await new Promise(function (resolve) {
    mw6(_mockReq({ url: "/x" }), _mockRes(), function (err) {
      badResolverErr = err;
      resolve();
    });
  });
  check("malformed resolver return → next(err)",
    badResolverErr && /db-role-for\/bad-role/.test(badResolverErr.code || ""));

  // ---- no role + requireRole=false → next() with null binding ----

  var mw7 = b.middleware.dbRoleFor({});
  var req7 = _mockReq({ url: "/x" });
  var calledNext = false;
  await new Promise(function (resolve) {
    mw7(req7, _mockRes(), function () { calledNext = true; resolve(); });
  });
  check("no role + requireRole=false: next() called, dbRole=null",
    calledNext && req7.dbRole === null);

  // ---- ALS scope leaves cleanly after next() returns ----
  // Outside the handler the ALS role is null again.
  check("ALS scope: outside handler the role is null",
    dbRoleContext.getRole() === null);

  // ---- runWithRole: out-of-request scoping ----
  var insideRole = null;
  await dbRoleContext.runWithRole("app_user", async function () {
    insideRole = dbRoleContext.getRole();
  });
  check("runWithRole: inside scope, getRole returns the bound role",
    insideRole === "app_user");
  check("runWithRole: outside scope, getRole is null again",
    dbRoleContext.getRole() === null);

  // ---- audit: db.role.switched emitted on bind (success path) ----
  var audCap = b.testing.captureAudit();
  var mwAudit = b.middleware.dbRoleFor({
    audit:       audCap,
    defaultRole: "app_user",
  });
  await _runMw(mwAudit, _mockReq({ url: "/x" }), _mockRes());
  var switched = audCap.byAction("db.role.switched");
  check("audit: db.role.switched emitted on success",
    switched.length === 1 &&
    switched[0].metadata.newRole === "app_user" &&
    switched[0].metadata.previousRole === null &&
    switched[0].metadata.source === "middleware" &&
    switched[0].outcome === "success");

  // ---- audit: opt-out via auditSuccess: false ----
  var audCap2 = b.testing.captureAudit();
  var mwOptOut = b.middleware.dbRoleFor({
    audit:        audCap2,
    defaultRole:  "app_user",
    auditSuccess: false,
  });
  await _runMw(mwOptOut, _mockReq({ url: "/x" }), _mockRes());
  check("audit: auditSuccess=false suppresses success emission",
    audCap2.byAction("db.role.switched").length === 0);

  // ---- audit: requireRole + missing actor → failure emission ----
  var audCap3 = b.testing.captureAudit();
  var mwReq = b.middleware.dbRoleFor({
    audit:       audCap3,
    permissions: perms,
    requireRole: true,
  });
  var resReq = _mockRes();
  mwReq(_mockReq({ url: "/x" }), resReq, function () {});
  await Promise.resolve();
  var failures = audCap3.byAction("db.role.switched");
  check("audit: failure path emits with outcome=failure + reason=no-role",
    failures.length === 1 &&
    failures[0].outcome === "failure" &&
    failures[0].reason === "no-role");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

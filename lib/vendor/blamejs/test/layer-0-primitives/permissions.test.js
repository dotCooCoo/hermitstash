"use strict";
/**
 * b.permissions — RBAC primitive.
 *
 * Run standalone: `node test/layer-0-primitives/permissions.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _mockReq  = helpers._mockReq;
var _bodyRes  = helpers._bodyRes;

// ---- Surface ----

function testSurface() {
  check("b.permissions namespace present",       typeof b.permissions === "object");
  check("b.permissions.create is a function",    typeof b.permissions.create === "function");
  check("b.permissions.match is a function",     typeof b.permissions.match === "function");
  check("PermissionsError class",                typeof b.permissions.PermissionsError === "function");
  check("DEFAULTS frozen",                       Object.isFrozen(b.permissions.DEFAULTS));
  check("DEFAULTS.auditFailures true",           b.permissions.DEFAULTS.auditFailures === true);
  check("DEFAULTS.auditSuccess true (auth decision IS the audit event)",
        b.permissions.DEFAULTS.auditSuccess === true);
  check("DEFAULTS.denyStatus 403",               b.permissions.DEFAULTS.denyStatus === 403);
  check("DEFAULTS.missingActorStatus 401",       b.permissions.DEFAULTS.missingActorStatus === 401);
}

// ---- Wildcard matching (every row of the documented table) ----

function testMatchTable() {
  var m = b.permissions.match;
  check("* matches users:read",                          m("*", "users:read") === true);
  check("* matches anything:foo:bar",                    m("*", "anything:foo:bar") === true);
  check("users:* matches users:read",                    m("users:*", "users:read") === true);
  check("users:* matches users:read:detail (greedy)",    m("users:*", "users:read:detail") === true);
  check("users:read matches users:read",                 m("users:read", "users:read") === true);
  check("users:read does NOT match users:read:detail",   m("users:read", "users:read:detail") === false);
  check("*:read matches posts:read",                     m("*:read", "posts:read") === true);
  check("*:read does NOT match posts:write",             m("*:read", "posts:write") === false);
  check("users:*:read matches users:foo:read",           m("users:*:read", "users:foo:read") === true);
  check("users:*:read does NOT match users:foo:write",   m("users:*:read", "users:foo:write") === false);
  check("granted longer than required → no match",       m("users:read:detail", "users:read") === false);
  check("non-string granted → false",                    m(null, "x") === false);
  check("non-string required → false",                   m("x", null) === false);
  check("empty granted → false",                         m("", "x") === false);
  check("empty required → false",                        m("x", "") === false);
}

// ---- Role expansion ----

function testRoleExpansion() {
  var p = b.permissions.create({
    roles: {
      admin:  { extends: ["editor"], permissions: ["users:delete"] },
      editor: ["users:read", "users:write", "posts:*"],
      viewer: ["*:read"],
    },
  });
  var adminScopes = p.expand(["admin"]);
  check("admin expansion includes editor scopes",
        adminScopes.indexOf("users:read") !== -1 &&
        adminScopes.indexOf("users:write") !== -1 &&
        adminScopes.indexOf("posts:*") !== -1);
  check("admin expansion includes admin's own scopes",
        adminScopes.indexOf("users:delete") !== -1);
  check("admin expansion deduplicates",
        adminScopes.length === 4);

  // Both admin + editor → no duplicates
  var both = p.expand(["admin", "editor"]);
  check("expand([admin,editor]) deduplicates", both.length === 4);

  // Unknown role names silently ignored (operator may pass mixed)
  check("expand with unknown role ignores it",
        p.expand(["editor", "ghost"]).length === 3);

  check("expand with non-array → []",  p.expand(null).length === 0);
}

function testRoleExpansionDeepInheritance() {
  var p = b.permissions.create({
    roles: {
      a: { extends: ["b"], permissions: ["a:x"] },
      b: { extends: ["c"], permissions: ["b:x"] },
      c: ["c:x"],
    },
  });
  var scopes = p.expand(["a"]);
  check("transitive extends: a inherits c",     scopes.indexOf("c:x") !== -1);
  check("transitive extends: a inherits b",     scopes.indexOf("b:x") !== -1);
  check("transitive extends: a's own",          scopes.indexOf("a:x") !== -1);
}

function testRolesProperty() {
  var p = b.permissions.create({
    roles: { admin: ["*"], viewer: ["*:read"] },
  });
  check("roles property is array",              Array.isArray(p.roles));
  check("roles property is frozen",             Object.isFrozen(p.roles));
  check("roles contains admin",                 p.roles.indexOf("admin") !== -1);
  check("has(admin) true",                      p.has("admin") === true);
  check("has(ghost) false",                     p.has("ghost") === false);
}

// ---- check / checkAll / checkAny ----

function testCheckPureFunctions() {
  var p = b.permissions.create({
    roles: {
      editor: ["users:read", "users:write", "posts:*"],
      viewer: ["*:read"],
    },
  });
  // Direct scopes
  check("scopes: read OK",            p.check({ scopes: ["users:read"] }, "users:read") === true);
  check("scopes: write denied",       p.check({ scopes: ["users:read"] }, "users:write") === false);
  check("scopes: wildcard grants",    p.check({ scopes: ["users:*"] }, "users:write") === true);
  // Role-based
  check("role editor: posts:foo OK",  p.check({ roles: ["editor"] }, "posts:foo") === true);
  check("role viewer: posts:read OK", p.check({ roles: ["viewer"] }, "posts:read") === true);
  check("role viewer: posts:write denied", p.check({ roles: ["viewer"] }, "posts:write") === false);

  // checkAll
  check("checkAll all OK",            p.checkAll({ scopes: ["users:read", "users:write"] },
                                                 ["users:read", "users:write"]) === true);
  check("checkAll partial → false",   p.checkAll({ scopes: ["users:read"] },
                                                 ["users:read", "users:write"]) === false);
  check("checkAll empty list → false", p.checkAll({ scopes: ["users:read"] }, []) === false);

  // checkAny
  check("checkAny one OK",            p.checkAny({ scopes: ["users:read"] },
                                                 ["users:read", "users:write"]) === true);
  check("checkAny none → false",      p.checkAny({ scopes: ["billing:read"] },
                                                 ["users:read", "users:write"]) === false);
}

function testCheckTolerantOnBadActor() {
  var p = b.permissions.create({ roles: { admin: ["*"] } });
  check("check(null, x) → false",     p.check(null, "users:read") === false);
  check("check({}, x) → false",       p.check({}, "users:read") === false);
  check("check({scopes:[]}, x) → false", p.check({ scopes: [] }, "users:read") === false);
  check("check with non-string scope items skipped",
        p.check({ scopes: [42, "users:read"] }, "users:read") === true);
}

// ---- Middleware ----

function _runMiddleware(mw, req) {
  return new Promise(function (resolve) {
    var res = _bodyRes();
    var nextCalled = false;
    res.on("finish", function () { resolve({ res: res, nextCalled: nextCalled }); });
    mw(req, res, function () { nextCalled = true; resolve({ res: res, nextCalled: nextCalled }); });
  });
}

async function testMiddlewareSuccess() {
  var p = b.permissions.create({
    roles: { editor: ["users:read", "users:write"] },
  });
  var mw = p.require("users:read");
  var req = _mockReq();
  req.user = { roles: ["editor"] };
  var r = await _runMiddleware(mw, req);
  check("middleware: next() called on success", r.nextCalled === true);
  check("middleware: no status written on success", r.res._endedStatus === null);
}

async function testMiddlewareDeny() {
  var p = b.permissions.create({
    roles: { viewer: ["*:read"] },
  });
  var mw = p.require("users:write");
  var req = _mockReq();
  req.user = { roles: ["viewer"] };
  var r = await _runMiddleware(mw, req);
  check("middleware: next() not called on deny", r.nextCalled === false);
  check("middleware: 403 written on deny",        r.res._endedStatus === 403);
  check("middleware: forbidden in body",          /forbidden/.test(r.res._captured));
}

async function testMiddlewareMissingActor() {
  var p = b.permissions.create({
    roles: { admin: ["*"] },
  });
  var mw = p.require("users:read");
  var req = _mockReq();    // no user, no apiKey
  var r = await _runMiddleware(mw, req);
  check("middleware: 401 missing actor",          r.res._endedStatus === 401);
  check("middleware: missing_actor in body",      /missing_actor/.test(r.res._captured));
}

async function testMiddlewareApiKeyResolverDefault() {
  var p = b.permissions.create({
    roles: { admin: ["*"] },
  });
  var mw = p.require("users:read");
  var req = _mockReq();
  req.apiKey = { scopes: ["users:read"] };
  var r = await _runMiddleware(mw, req);
  check("middleware: apiKey.scopes resolves",     r.nextCalled === true);
}

async function testMiddlewareUserScopesResolverDefault() {
  var p = b.permissions.create({ roles: { admin: ["*"] } });
  var mw = p.require("users:read");
  var req = _mockReq();
  req.user = { scopes: ["users:read"] };
  var r = await _runMiddleware(mw, req);
  check("middleware: user.scopes resolves",       r.nextCalled === true);
}

async function testMiddlewareCustomResolver() {
  var p = b.permissions.create({
    roles: { admin: ["*"] },
    resolver: function (req) {
      // Custom shape: req.principal.permissions
      if (req.principal && Array.isArray(req.principal.permissions)) {
        return { scopes: req.principal.permissions };
      }
      return null;
    },
  });
  var mw = p.require("users:read");
  var req = _mockReq();
  req.principal = { permissions: ["users:read"] };
  var r = await _runMiddleware(mw, req);
  check("middleware: custom resolver works",      r.nextCalled === true);
}

async function testMiddlewareRequireAll() {
  var p = b.permissions.create({ roles: { admin: ["*"] } });
  var mw = p.requireAll(["users:read", "users:write"]);
  var req = _mockReq();
  req.user = { scopes: ["users:read", "users:write"] };
  var r = await _runMiddleware(mw, req);
  check("requireAll: all match → next",           r.nextCalled === true);

  var mwDeny = p.requireAll(["users:read", "users:write"]);
  var req2 = _mockReq();
  req2.user = { scopes: ["users:read"] };
  var r2 = await _runMiddleware(mwDeny, req2);
  check("requireAll: partial → 403",              r2.res._endedStatus === 403);
}

async function testMiddlewareRequireAny() {
  var p = b.permissions.create({ roles: { admin: ["*"] } });
  var mw = p.requireAny(["admin:write", "users:read"]);
  var req = _mockReq();
  req.user = { scopes: ["users:read"] };
  var r = await _runMiddleware(mw, req);
  check("requireAny: one match → next",           r.nextCalled === true);

  var mwDeny = p.requireAny(["admin:write", "billing:read"]);
  var req2 = _mockReq();
  req2.user = { scopes: ["users:read"] };
  var r2 = await _runMiddleware(mwDeny, req2);
  check("requireAny: none → 403",                 r2.res._endedStatus === 403);
}

async function testMiddlewareCustomResponder() {
  var p = b.permissions.create({
    roles: { viewer: ["*:read"] },
    responder: function (req, res, status, info) {
      res.writeHead(status, { "Content-Type": "text/plain" });
      res.end("CUSTOM " + status + " " + info.error);
    },
  });
  var mw = p.require("users:write");
  var req = _mockReq();
  req.user = { roles: ["viewer"] };
  var r = await _runMiddleware(mw, req);
  check("custom responder: 403 written",          r.res._endedStatus === 403);
  check("custom responder: body matches shape",
        /CUSTOM 403 forbidden/.test(r.res._captured));
}

// ---- Audit + observability emission ----

async function testAuditAndObservabilityEmission() {
  var cap = b.testing.captureMetricsTap();
  var audit = b.testing.captureAudit();
  try {
    var p = b.permissions.create({
      roles: { viewer: ["*:read"] },
      audit: audit,
      auditSuccess: true,        // we want to observe both branches
    });

    // Success path
    var mwOk = p.require("users:read");
    await _runMiddleware(mwOk, Object.assign(_mockReq(), { user: { roles: ["viewer"] } }));

    // Deny path
    var mwDeny = p.require("users:write");
    await _runMiddleware(mwDeny, Object.assign(_mockReq(), { user: { roles: ["viewer"] } }));

    // Missing actor path
    var mwMissing = p.require("users:read");
    await _runMiddleware(mwMissing, _mockReq());
  } finally {
    cap.restore();
  }

  check("emits permissions.check event",
        cap.byName("permissions.check").length > 0);
  check("emits permissions.missing_actor event",
        cap.byName("permissions.missing_actor").length > 0);

  var checkEvents = cap.byName("permissions.check");
  var hasSuccess = checkEvents.some(function (e) { return e.labels.outcome === "success"; });
  var hasDeny = checkEvents.some(function (e) { return e.labels.outcome === "deny"; });
  check("permissions.check emits success outcome", hasSuccess === true);
  check("permissions.check emits deny outcome",    hasDeny === true);

  check("audit emits check.deny",
        audit.byAction("permissions.check.deny").length > 0);
  check("audit emits check.success (auditSuccess=true)",
        audit.byAction("permissions.check.success").length > 0);
  check("audit emits missing_actor",
        audit.byAction("permissions.missing_actor").length > 0);
}

async function testAuditDefaults() {
  var audit = b.testing.captureAudit();
  // Defaults: both success AND failure audited (auth decision is the event)
  var p = b.permissions.create({
    roles: { admin: ["*"] },
    audit: audit,
  });
  var mwOk = p.require("users:read");
  await _runMiddleware(mwOk, Object.assign(_mockReq(), { user: { scopes: ["*"] } }));
  check("default: success IS audited (auth decision)",
        audit.byAction("permissions.check.success").length > 0);

  var mwDeny = p.require("users:write");
  await _runMiddleware(mwDeny, Object.assign(_mockReq(), { user: { scopes: ["users:read"] } }));
  check("default: deny IS audited",
        audit.byAction("permissions.check.deny").length > 0);
}

async function testAuditSuccessOptOut() {
  var audit = b.testing.captureAudit();
  // Operator opt-out for extreme volume
  var p = b.permissions.create({
    roles: { admin: ["*"] },
    audit: audit,
    auditSuccess: false,
  });
  var mwOk = p.require("users:read");
  await _runMiddleware(mwOk, Object.assign(_mockReq(), { user: { scopes: ["*"] } }));
  check("opt-out: success NOT audited when auditSuccess=false",
        audit.byAction("permissions.check.success").length === 0);
}

// ---- 5 W's audit propagation ----

async function testFiveWsAuditPropagation() {
  var audit = b.testing.captureAudit();
  var p = b.permissions.create({
    roles: { editor: ["users:read"], viewer: ["*:read"] },
    audit: audit,
  });

  var req = _mockReq();
  req.url = "/admin/users/42";
  req.method = "GET";
  req.ip = "203.0.113.99";
  req.headers["user-agent"] = "compliance-test/1.0";
  req.headers["x-request-id"] = "req-perm-001";
  req.user = { id: "admin-7", roles: ["editor"] };

  // Success path
  await _runMiddleware(p.require("users:read"), req);
  var success = audit.byAction("permissions.check.success")[0];
  check("perms 5 W's: success has WHO (userId)",     success.actor.userId === "admin-7");
  check("perms 5 W's: success has WHERE (ip)",       success.actor.ip === "203.0.113.99");
  check("perms 5 W's: success has HOW (userAgent)",  success.actor.userAgent === "compliance-test/1.0");
  check("perms 5 W's: success has HOW (route)",      success.actor.route === "/admin/users/42");
  check("perms 5 W's: success has HOW (requestId)",  success.actor.requestId === "req-perm-001");
  check("perms 5 W's: success has roles preserved",
        Array.isArray(success.actor.roles) && success.actor.roles.indexOf("editor") !== -1);

  // Deny path
  audit.clear();
  var denyReq = _mockReq();
  denyReq.url = "/admin/users/42/delete";
  denyReq.method = "DELETE";
  denyReq.ip = "203.0.113.99";
  denyReq.user = { id: "viewer-9", roles: ["viewer"] };
  await _runMiddleware(p.require("users:write"), denyReq);
  var deny = audit.byAction("permissions.check.deny")[0];
  check("perms 5 W's: deny has WHO",       deny.actor.userId === "viewer-9");
  check("perms 5 W's: deny has WHERE",     deny.actor.ip === "203.0.113.99");
  check("perms 5 W's: deny has HOW (route)", deny.actor.route === "/admin/users/42/delete");
  check("perms 5 W's: deny has HOW (method)", deny.actor.method === "DELETE");
}

// ---- Input validation (rejects bad opts at create time) ----

function testCreateRejectsBadOpts() {
  function expect(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  expect("create: missing roles",
    function () { b.permissions.create({}); }, "BAD_OPT");
  expect("create: roles not object",
    function () { b.permissions.create({ roles: ["a", "b"] }); }, "BAD_OPT");
  expect("create: empty roles",
    function () { b.permissions.create({ roles: {} }); }, "BAD_OPT");
  expect("create: bad scope format (uppercase)",
    function () { b.permissions.create({ roles: { admin: ["Users:read"] } }); }, "BAD_SCOPE");
  expect("create: bad scope format (special chars)",
    function () { b.permissions.create({ roles: { admin: ["users/read"] } }); }, "BAD_SCOPE");
  expect("create: empty scope",
    function () { b.permissions.create({ roles: { admin: [""] } }); }, "BAD_SCOPE");
  expect("create: bad role shape (number)",
    function () { b.permissions.create({ roles: { admin: 42 } }); }, "BAD_ROLE");
  expect("create: extends not array",
    function () { b.permissions.create({ roles: { a: { extends: "b", permissions: [] } } }); }, "BAD_ROLE");
  expect("create: unknown role in extends",
    function () { b.permissions.create({ roles: { a: { extends: ["ghost"], permissions: [] } } }); }, "UNKNOWN_ROLE");
  expect("create: cycle in extends",
    function () { b.permissions.create({
      roles: {
        a: { extends: ["b"], permissions: [] },
        b: { extends: ["a"], permissions: [] },
      }
    }); }, "CYCLE");

  // Middleware registration validates scope at declaration time
  var p = b.permissions.create({ roles: { admin: ["*"] } });
  expect("require: bad scope format throws at declaration",
    function () { p.require("Bad:Scope"); }, "BAD_SCOPE");
  expect("requireAll: empty array",
    function () { p.requireAll([]); }, "BAD_OPT");
  expect("requireAny: non-array",
    function () { p.requireAny("not-array"); }, "BAD_OPT");

  // Status code validation
  expect("create: bad denyStatus",
    function () { b.permissions.create({ roles: { a: ["*"] }, denyStatus: 50 }); }, "BAD_OPT");
  expect("create: bad missingActorStatus",
    function () { b.permissions.create({ roles: { a: ["*"] }, missingActorStatus: 999 }); }, "BAD_OPT");

  // Audit shape
  expect("create: bad audit shape",
    function () { b.permissions.create({ roles: { a: ["*"] }, audit: {} }); }, "BAD_OPT");
}

// ---- v0.6.6 — dbRole role-table integration ----

function testDbRoleFor() {
  var p = b.permissions.create({
    roles: {
      admin:   { extends: ["app"], permissions: ["users:delete"] },
      app:     { permissions: ["users:read", "users:write"], dbRole: "app_user" },
      analyst: { permissions: ["users:read"],                dbRole: "analytics_user" },
      viewer:  { permissions: ["users:read"] }, // no dbRole declared
    },
  });

  check("dbRoleFor: actor with single role returns its dbRole",
    p.dbRoleFor({ roles: ["analyst"] }) === "analytics_user");

  check("dbRoleFor: actor with role that has no dbRole walks extends",
    p.dbRoleFor({ roles: ["admin"] }) === "app_user");

  check("dbRoleFor: actor with multiple roles — first wins",
    p.dbRoleFor({ roles: ["analyst", "app"] }) === "analytics_user");

  check("dbRoleFor: viewer (no dbRole anywhere) → null",
    p.dbRoleFor({ roles: ["viewer"] }) === null);

  check("dbRoleFor: empty roles → null",
    p.dbRoleFor({ roles: [] }) === null);

  check("dbRoleFor: scopes-only actor → null",
    p.dbRoleFor({ scopes: ["users:read"] }) === null);

  check("dbRoleFor: null input → null",
    p.dbRoleFor(null) === null);

  // Request-shape input → resolver fires.
  var req = _mockReq({ url: "/x" });
  req.user = { roles: ["app"] };
  check("dbRoleFor: request-shape input passes through resolver",
    p.dbRoleFor(req) === "app_user");

  // dbRole validates as a SQL identifier at create() — bad shape throws here.
  function rejectsCreate(label, opts, re) {
    var threw = null;
    try { b.permissions.create(opts); } catch (e) { threw = e; }
    check("permissions.create rejects: " + label,
      threw && (re.test(threw.code || "") || re.test(threw.message || "")));
  }
  rejectsCreate("non-string dbRole",
    { roles: { x: { permissions: ["a:b"], dbRole: 42 } } },
    /BAD_ROLE/);
  rejectsCreate("empty dbRole",
    { roles: { x: { permissions: ["a:b"], dbRole: "" } } },
    /BAD_ROLE/);
  rejectsCreate("malformed dbRole identifier",
    { roles: { x: { permissions: ["a:b"], dbRole: "bad name" } } },
    /BAD_ROLE/);
}

// ---- Run ----

async function run() {
  testSurface();
  testMatchTable();
  testRoleExpansion();
  testRoleExpansionDeepInheritance();
  testRolesProperty();
  testCheckPureFunctions();
  testCheckTolerantOnBadActor();
  await testMiddlewareSuccess();
  await testMiddlewareDeny();
  await testMiddlewareMissingActor();
  await testMiddlewareApiKeyResolverDefault();
  await testMiddlewareUserScopesResolverDefault();
  await testMiddlewareCustomResolver();
  await testMiddlewareRequireAll();
  await testMiddlewareRequireAny();
  await testMiddlewareCustomResponder();
  await testAuditAndObservabilityEmission();
  await testAuditDefaults();
  await testAuditSuccessOptOut();
  await testFiveWsAuditPropagation();
  testCreateRejectsBadOpts();
  testDbRoleFor();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}

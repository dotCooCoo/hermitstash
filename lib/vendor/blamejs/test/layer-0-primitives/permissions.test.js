// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

// ---- Role-table validation: uncovered adversarial branches ----

function testRoleTableValidationEdgeCases() {
  function expect(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }

  // permissions must be an array (lib line 137-138)
  expect("create: permissions not an array → BAD_ROLE",
    function () { b.permissions.create({ roles: { admin: { permissions: "users:read" } } }); },
    "BAD_ROLE");

  // null entry short-circuits the `entry && typeof === object` guard →
  // falls to the catch-all throw (lib line 169; left-operand false branch)
  expect("create: null role entry → BAD_ROLE",
    function () { b.permissions.create({ roles: { admin: null } }); },
    "BAD_ROLE");
  expect("create: boolean role entry → BAD_ROLE",
    function () { b.permissions.create({ roles: { admin: true } }); },
    "BAD_ROLE");

  // mfaWindowMs must be a positive finite number (lib line 160-163)
  expect("create: negative role mfaWindowMs → BAD_ROLE",
    function () { b.permissions.create({ roles: { a: { permissions: ["x:y"], mfaWindowMs: -1 } } }); },
    "BAD_ROLE");
  expect("create: zero role mfaWindowMs → BAD_ROLE",
    function () { b.permissions.create({ roles: { a: { permissions: ["x:y"], mfaWindowMs: 0 } } }); },
    "BAD_ROLE");
  expect("create: NaN role mfaWindowMs → BAD_ROLE",
    function () { b.permissions.create({ roles: { a: { permissions: ["x:y"], mfaWindowMs: NaN } } }); },
    "BAD_ROLE");
  expect("create: Infinity role mfaWindowMs → BAD_ROLE",
    function () { b.permissions.create({ roles: { a: { permissions: ["x:y"], mfaWindowMs: Infinity } } }); },
    "BAD_ROLE");
  expect("create: string role mfaWindowMs → BAD_ROLE",
    function () { b.permissions.create({ roles: { a: { permissions: ["x:y"], mfaWindowMs: "600000" } } }); },
    "BAD_ROLE");

  // valid mfaWindowMs is accepted + a role with extends but NO permissions
  // key exercises the `entry.permissions || []` default (lib line 136, 164-165)
  var ok = b.permissions.create({
    roles: {
      base:  ["reports:read"],
      admin: { extends: ["base"], requireMfa: true, mfaWindowMs: 600000 },
    },
  });
  check("create: role with valid mfaWindowMs + no own permissions builds",
    ok.expand(["admin"]).indexOf("reports:read") !== -1);

  // empty-string role name (Object.keys yields "") (lib line 184-185)
  expect("create: empty-string role name → BAD_ROLE",
    function () { b.permissions.create({ roles: { "": ["a:b"] } }); },
    "BAD_ROLE");

  // extends entries must be non-empty strings (lib line 191-193)
  expect("create: empty-string extends entry → BAD_ROLE",
    function () { b.permissions.create({ roles: { a: { extends: [""], permissions: [] } } }); },
    "BAD_ROLE");
  expect("create: non-string extends entry → BAD_ROLE",
    function () { b.permissions.create({ roles: { a: { extends: [42], permissions: [] } } }); },
    "BAD_ROLE");
}

// Per-segment wildcard where required has fewer segments (lib line 99)
function testMatchPerSegmentWildcardShortRequired() {
  var m = b.permissions.match;
  check("users:*:read vs users → false (required too short at wildcard)",
    m("users:*:read", "users") === false);
  check("a:*:c vs a → false",  m("a:*:c", "a") === false);
  check("*:read vs empty-segmentless still handled",
    m("a:*:c", "a:x") === false); // required exhausted after non-wildcard match at index 2
}

// ---- Middleware registration-time opt validation (lib 465-469, 476-477) ----

function testMiddlewareOptValidation() {
  var p = b.permissions.create({ roles: { admin: ["*"] } });
  function expect(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  expect("require: negative mfaWindowMs → BAD_OPT",
    function () { p.require("users:read", { mfaWindowMs: -5 }); }, "BAD_OPT");
  expect("require: zero mfaWindowMs → BAD_OPT",
    function () { p.require("users:read", { mfaWindowMs: 0 }); }, "BAD_OPT");
  expect("require: NaN mfaWindowMs → BAD_OPT",
    function () { p.require("users:read", { mfaWindowMs: NaN }); }, "BAD_OPT");
  expect("require: Infinity mfaWindowMs → BAD_OPT",
    function () { p.require("users:read", { mfaWindowMs: Infinity }); }, "BAD_OPT");
  expect("require: string mfaWindowMs → BAD_OPT",
    function () { p.require("users:read", { mfaWindowMs: "1000" }); }, "BAD_OPT");
  expect("require: non-function context → BAD_OPT",
    function () { p.require("users:read", { context: "not-a-fn" }); }, "BAD_OPT");
  expect("require: object context → BAD_OPT",
    function () { p.require("users:read", { context: {} }); }, "BAD_OPT");

  // A valid, explicit mfaWindowMs opt is accepted at registration.
  var mw = p.require("users:read", { mfaWindowMs: 600000, context: function (req) { return req; } });
  check("require: valid mfaWindowMs + context opts accepted", typeof mw === "function");
}

// ---- policy() registration (lib 350-382) ----

function testPolicyRegistration() {
  var p = b.permissions.create({ roles: { svc: ["orders:read", "orders:write"] } });
  function expect(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }

  // Bad scope shape rejected (lib 351)
  expect("policy: bad scope shape → BAD_SCOPE",
    function () { p.policy("Bad:Scope", function (a, c) { return true; }); }, "BAD_SCOPE");
  // Non-function predicate (lib 352-353)
  expect("policy: non-function predicate → BAD_OPT",
    function () { p.policy("orders:read", "nope"); }, "BAD_OPT");

  // First registration succeeds; second on same scope is refused (lib 355-357)
  p.policy("orders:read", function (a, c) { return true; });
  expect("policy: duplicate scope → DUPLICATE_POLICY",
    function () { p.policy("orders:read", function (a, c) { return true; }); }, "DUPLICATE_POLICY");
}

function testPolicyPredicateArityWarning() {
  var audit = b.testing.captureAudit();
  var p = b.permissions.create({ roles: { svc: ["orders:write"] }, audit: audit });

  // Arity-1 predicate (forgot the context param) → one-time register-time
  // audit warning (lib 365-380).
  p.policy("orders:write", function (actor) { return true; });
  var warns = audit.byAction("permissions.policy_predicate_shape_warning");
  check("policy: arity<2 predicate emits shape warning", warns.length === 1);
  check("policy: shape warning carries the scope + arity",
    warns[0].metadata && warns[0].metadata.scope === "orders:write" && warns[0].metadata.arity === 1);

  // Arity-0 predicate also warns.
  p.policy("orders:read", function () { return true; });
  check("policy: arity-0 predicate warns too",
    audit.byAction("permissions.policy_predicate_shape_warning").length === 2);

  // A correct arity-2 predicate does NOT warn.
  audit.clear();
  var p2 = b.permissions.create({ roles: { svc: ["orders:write"] }, audit: audit });
  p2.policy("orders:write", function (actor, ctx) { return true; });
  check("policy: arity-2 predicate does not warn",
    audit.byAction("permissions.policy_predicate_shape_warning").length === 0);

  // Arity<2 with NO audit sink must not throw (drop-silent guard, lib 366-379).
  var p3 = b.permissions.create({ roles: { svc: ["orders:write"] } });
  var threw = null;
  try { p3.policy("orders:write", function (a) { return true; }); } catch (e) { threw = e; }
  check("policy: arity<2 without audit sink does not throw", threw === null);
}

// ---- MFA enforcement gate (lib 526-604) ----

function testMfaPerRouteEnforcement() {
  var minutes = b.constants.TIME.minutes;
  var p = b.permissions.create({
    roles: { editor: ["users:read", "users:write"] },
    // Default resolver drops mfaAuthenticated/mfaAt; MFA-aware operators
    // return the full user object.
    resolver: function (req) { return req.user || null; },
  });

  // Route requires MFA; actor never stepped up → mfa_required deny.
  return (async function () {
    var mw = p.require("users:write", { requireMfa: true });

    var noMfa = await _runMiddleware(mw, Object.assign(_mockReq(), { user: { roles: ["editor"] } }));
    check("mfa route: un-stepped-up actor denied", noMfa.res._endedStatus === 403);
    check("mfa route: mfa_required in body", /mfa_required/.test(noMfa.res._captured));
    check("mfa route: next() not called", noMfa.nextCalled === false);

    // Fresh MFA stamp → passes (window floor 15m, mfaAt = now).
    var fresh = await _runMiddleware(mw, Object.assign(_mockReq(), {
      user: { roles: ["editor"], mfaAuthenticated: true, mfaAt: Date.now() },
    }));
    check("mfa route: fresh step-up passes", fresh.nextCalled === true);

    // Stale MFA stamp beyond the 15m default window floor → denied (lib 578-586).
    var stale = await _runMiddleware(mw, Object.assign(_mockReq(), {
      user: { roles: ["editor"], mfaAuthenticated: true, mfaAt: Date.now() - minutes(20) },
    }));
    check("mfa route: stale step-up beyond default window denied", stale.res._endedStatus === 403);

    // Explicit larger window lets the same stale stamp through (lib 464-468 valid path).
    var wide = p.require("users:write", { requireMfa: true, mfaWindowMs: minutes(30) });
    var wideR = await _runMiddleware(wide, Object.assign(_mockReq(), {
      user: { roles: ["editor"], mfaAuthenticated: true, mfaAt: Date.now() - minutes(20) },
    }));
    check("mfa route: explicit 30m window admits a 20m-old step-up", wideR.nextCalled === true);
  })();
}

async function testMfaPerRoleEnforcement() {
  var minutes = b.constants.TIME.minutes;
  var cap = b.testing.captureMetricsTap();
  var audit = b.testing.captureAudit();
  try {
    var p = b.permissions.create({
      roles: {
        admin:   { permissions: ["users:delete"], requireMfa: true, mfaWindowMs: minutes(10) },
        billing: { permissions: ["billing:read"], requireMfa: true },
        reader:  ["users:read"],
      },
      audit:    audit,
      resolver: function (req) { return req.user || null; },
    });

    // Route has NO requireMfa; the admin role's requireMfa forces the gate
    // because admin grants the requested users:delete (lib 536-568).
    var mw = p.require("users:delete");
    var denied = await _runMiddleware(mw, Object.assign(_mockReq(), { user: { roles: ["admin"] } }));
    check("mfa role: role-level requireMfa forces gate → deny", denied.res._endedStatus === 403);
    check("mfa role: mfa.required audit emitted",
      audit.byAction("permissions.mfa.required").length > 0);
    check("mfa role: mfa_required metric emitted",
      cap.byName("permissions.mfa_required").length > 0);

    // With a fresh step-up (within the role's 10m window) → passes.
    var okr = await _runMiddleware(mw, Object.assign(_mockReq(), {
      user: { roles: ["admin"], mfaAuthenticated: true, mfaAt: Date.now() },
    }));
    check("mfa role: fresh step-up within role window passes", okr.nextCalled === true);

    // Stale beyond the role's 10m window → denied (lib 564-566 window propagation).
    var staleR = await _runMiddleware(mw, Object.assign(_mockReq(), {
      user: { roles: ["admin"], mfaAuthenticated: true, mfaAt: Date.now() - minutes(15) },
    }));
    check("mfa role: stale beyond role's own window denied", staleR.res._endedStatus === 403);

    // A requireMfa role whose scopes DON'T match the request does NOT force
    // the gate; a second non-mfa role satisfies RBAC (lib 554-555 no-match,
    // 547 non-mfa-role continue). billing.requireMfa but grants billing:read,
    // reader grants users:read — request users:read → no MFA.
    var mwRead = p.require("users:read");
    var noGate = await _runMiddleware(mwRead, Object.assign(_mockReq(), {
      user: { roles: ["billing", "reader"] },
    }));
    check("mfa role: non-matching requireMfa role does not force gate", noGate.nextCalled === true);

    // Non-string entry in actor.roles is skipped during the MFA walk (lib 544).
    var mixed = await _runMiddleware(mwRead, Object.assign(_mockReq(), {
      user: { roles: [42, "reader"] },
    }));
    check("mfa role: non-string role entry skipped in MFA walk", mixed.nextCalled === true);
  } finally {
    cap.restore();
  }
}

// ---- ABAC policy evaluation in the request lifecycle (lib 606-684) ----

async function testPolicyAbacSingleMode() {
  var audit = b.testing.captureAudit();
  var cap = b.testing.captureMetricsTap();
  try {
    // Policy passes → request proceeds (lib 615, 647-652, 668 true, 686 success).
    var pass = b.permissions.create({ roles: { svc: ["orders:write"] }, audit: audit });
    pass.policy("orders:write", function (actor, ctx) { return true; });
    var passR = await _runMiddleware(pass.require("orders:write"),
      Object.assign(_mockReq(), { user: { scopes: ["orders:write"] } }));
    check("abac single: passing policy proceeds", passR.nextCalled === true);

    // Policy returns falsy → 403 policy_denied + policy.deny audit (lib 668-682).
    var deny = b.permissions.create({ roles: { svc: ["orders:write"] }, audit: audit });
    deny.policy("orders:write", function (actor, ctx) { return false; });
    var denyR = await _runMiddleware(deny.require("orders:write"),
      Object.assign(_mockReq(), { user: { scopes: ["orders:write"] } }));
    check("abac single: failing policy → 403", denyR.res._endedStatus === 403);
    check("abac single: policy_denied in body", /policy_denied/.test(denyR.res._captured));
    check("abac single: policy.deny audit emitted",
      audit.byAction("permissions.policy.deny").length > 0);

    // Predicate throws → 403 policy_error + policy.error audit (lib 653-667).
    var thrower = b.permissions.create({ roles: { svc: ["orders:write"] }, audit: audit });
    thrower.policy("orders:write", function (actor, ctx) { throw new Error("boom-predicate"); });
    var throwR = await _runMiddleware(thrower.require("orders:write"),
      Object.assign(_mockReq(), { user: { scopes: ["orders:write"] } }));
    check("abac single: throwing predicate → 403", throwR.res._endedStatus === 403);
    check("abac single: policy_error in body", /policy_error/.test(throwR.res._captured));
    var perr = audit.byAction("permissions.policy.error");
    check("abac single: policy.error audit with predicate-threw reason",
      perr.some(function (e) { return e.reason === "predicate-threw"; }));
    check("abac single: policy_error metric emitted",
      cap.byName("permissions.policy_error").length > 0);
  } finally {
    cap.restore();
  }
}

async function testPolicyAbacContextProvider() {
  var audit = b.testing.captureAudit();
  var cap = b.testing.captureMetricsTap();
  try {
    // Context provider result is threaded into the predicate (lib 626-629).
    var p = b.permissions.create({ roles: { svc: ["orders:write"] }, audit: audit });
    p.policy("orders:write", function (actor, ctx) { return ctx && ctx.tenant === "acme"; });
    var mw = p.require("orders:write", {
      context: async function (req) { return { tenant: req.tenant }; },
    });

    var okReq = Object.assign(_mockReq(), { user: { scopes: ["orders:write"] }, tenant: "acme" });
    var okR = await _runMiddleware(mw, okReq);
    check("abac context: matching context admits request", okR.nextCalled === true);

    var badReq = Object.assign(_mockReq(), { user: { scopes: ["orders:write"] }, tenant: "evil" });
    var badR = await _runMiddleware(mw, badReq);
    check("abac context: non-matching context → 403", badR.res._endedStatus === 403);

    // Context provider throws → policy_context_error + context-provider-threw
    // audit (lib 628-645), BEFORE the predicate runs.
    var predicateRan = false;
    var p2 = b.permissions.create({ roles: { svc: ["orders:write"] }, audit: audit });
    p2.policy("orders:write", function (actor, ctx) { predicateRan = true; return true; });
    var mw2 = p2.require("orders:write", {
      context: function (req) { throw new Error("ctx-boom"); },
    });
    var ctxErr = await _runMiddleware(mw2,
      Object.assign(_mockReq(), { user: { scopes: ["orders:write"] } }));
    check("abac context: provider throw → 403", ctxErr.res._endedStatus === 403);
    check("abac context: policy_context_error in body",
      /policy_context_error/.test(ctxErr.res._captured));
    check("abac context: predicate NOT reached when provider throws", predicateRan === false);
    check("abac context: context-provider-threw audit reason",
      audit.byAction("permissions.policy.error").some(function (e) {
        return e.reason === "context-provider-threw";
      }));
    check("abac context: policy_context_error metric emitted",
      cap.byName("permissions.policy_context_error").length > 0);
  } finally {
    cap.restore();
  }
}

async function testPolicyAbacAllAndAnyModes() {
  // requireAll: every requested scope's policy must pass (lib 617-623 all branch).
  var pAll = b.permissions.create({ roles: { svc: ["orders:read", "orders:write"] } });
  pAll.policy("orders:read",  function (a, c) { return true; });
  pAll.policy("orders:write", function (a, c) { return true; });
  var allR = await _runMiddleware(
    pAll.requireAll(["orders:read", "orders:write"]),
    Object.assign(_mockReq(), { user: { scopes: ["orders:read", "orders:write"] } }));
  check("abac all: both policies pass → proceed", allR.nextCalled === true);

  // requireAll: a single failing policy short-circuits to deny.
  var pAllDeny = b.permissions.create({ roles: { svc: ["orders:read", "orders:write"] } });
  pAllDeny.policy("orders:read",  function (a, c) { return true; });
  pAllDeny.policy("orders:write", function (a, c) { return false; });
  var allDenyR = await _runMiddleware(
    pAllDeny.requireAll(["orders:read", "orders:write"]),
    Object.assign(_mockReq(), { user: { scopes: ["orders:read", "orders:write"] } }));
  check("abac all: one failing policy → 403", allDenyR.res._endedStatus === 403);

  // requireAny: a policy on a scope the actor does NOT hold is skipped so its
  // existence never leaks (lib 619-622, the `!check → continue` path). The
  // held scope's passing policy admits the request even though the unheld
  // scope carries a would-deny policy.
  var pAny = b.permissions.create({ roles: { svc: ["orders:read", "orders:write"] } });
  pAny.policy("orders:read",  function (a, c) { return true; });
  pAny.policy("orders:write", function (a, c) { return false; });
  var anyR = await _runMiddleware(
    pAny.requireAny(["orders:read", "orders:write"]),
    Object.assign(_mockReq(), { user: { scopes: ["orders:read"] } }));
  check("abac any: unheld scope's policy skipped, held scope admits", anyR.nextCalled === true);
}

// ---- Audit opt-out for failures (lib 393 failure branch) ----

async function testAuditFailuresOptOut() {
  var audit = b.testing.captureAudit();
  var p = b.permissions.create({
    roles: { viewer: ["*:read"] },
    audit: audit,
    auditFailures: false,
  });
  var mwDeny = p.require("users:write");
  await _runMiddleware(mwDeny, Object.assign(_mockReq(), { user: { roles: ["viewer"] } }));
  check("opt-out: deny NOT audited when auditFailures=false",
    audit.byAction("permissions.check.deny").length === 0);
}

// ---- dbRoleFor: non-string / unknown role names + shared-ancestor guard ----

function testDbRoleForAdversarialRoles() {
  var p = b.permissions.create({
    roles: {
      analyst: { permissions: ["users:read"], dbRole: "analytics_user" },
      // Two roles share a dbRole-less ancestor to exercise the visited guard
      // in _findDbRole (lib 752).
      shared: { permissions: ["x:y"] },
      a: { extends: ["shared"], permissions: [] },
      b: { extends: ["shared"], permissions: [] },
    },
  });

  // Non-string + unknown role names are skipped before a valid one resolves
  // (lib 728-729).
  check("dbRoleFor: non-string + unknown roles skipped, valid one wins",
    p.dbRoleFor({ roles: [123, "ghost", "analyst"] }) === "analytics_user");

  // Both top-level roles walk into the same dbRole-less ancestor; the second
  // walk re-encounters the already-visited ancestor → null overall.
  check("dbRoleFor: shared dbRole-less ancestor → null (visited guard)",
    p.dbRoleFor({ roles: ["a", "b"] }) === null);
}

// ---- Residual defensive/default branches reached through the consumer path ----

// Returns a truthy non-Error value with no `.message` — thrown to drive the
// `(e && e.message) || String(e)` fallback. Routed through a call so it isn't
// a throw-literal.
function _nonErrorValue(tag) { return { note: tag }; }

async function testBranchCleanups() {
  var minutes = b.constants.TIME.minutes;

  function expect(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }

  // denyStatus upper-bound (lib 257 `> 599` operand) + no-arg create()
  // hitting the `opts || {}` default (lib 324).
  expect("create: denyStatus above 599 → BAD_OPT",
    function () { b.permissions.create({ roles: { a: ["*"] }, denyStatus: 600 }); }, "BAD_OPT");
  expect("create: no args → roles-missing BAD_OPT (opts||{} default)",
    function () { b.permissions.create(); }, "BAD_OPT");

  // checkAll / checkAny non-array required-scopes → false (lib 425, 433).
  var p = b.permissions.create({ roles: { admin: ["*"] } });
  check("checkAll: non-array required → false", p.checkAll({ scopes: ["users:read"] }, "nope") === false);
  check("checkAny: non-array required → false", p.checkAny({ scopes: ["users:read"] }, null) === false);

  // Missing-actor hint branch when the resolver returns null despite an
  // actor being present on the request (lib 486-487 path0).
  var auditA = b.testing.captureAudit();
  var pNull = b.permissions.create({
    roles: { admin: ["*"] }, audit: auditA, resolver: function () { return null; },
  });
  var reqWithUser = _mockReq();
  reqWithUser.user = { roles: ["admin"] };
  await _runMiddleware(pNull.require("users:read"), reqWithUser);
  var ma = auditA.byAction("permissions.missing_actor")[0];
  check("missing-actor hint reflects resolver-returned-null-despite-actor",
    ma && /actor present on req but resolver returned null/.test(ma.metadata.hint));

  // Resolver-supplied userId flows into the audit actor shape (lib 778 path0).
  var auditB = b.testing.captureAudit();
  var pUid = b.permissions.create({
    roles: { admin: ["*"] }, audit: auditB,
    resolver: function () { return { userId: "svc-1", scopes: ["users:read"] }; },
  });
  await _runMiddleware(pUid.require("users:read"), _mockReq());
  var succ = auditB.byAction("permissions.check.success")[0];
  check("resolver-supplied userId appears in audit actor", succ && succ.actor.userId === "svc-1");

  // MFA gate with an actor that set mfaAuthenticated but NO numeric mfaAt →
  // mfaAt coerces to 0 → treated as ancient → denied (lib 583 `: 0`).
  var pMfa = b.permissions.create({
    roles: { editor: ["users:write"] },
    resolver: function (req) { return req.user || null; },
  });
  var noStamp = await _runMiddleware(
    pMfa.require("users:write", { requireMfa: true, mfaWindowMs: minutes(30) }),
    Object.assign(_mockReq(), { user: { roles: ["editor"], mfaAuthenticated: true } }));
  check("mfa: mfaAuthenticated without numeric mfaAt is treated as stale → 403",
    noStamp.res._endedStatus === 403);

  // Per-role requireMfa forcing the gate on a multi-scope (requireAny) route
  // exercises the non-single `requestedList` branch (lib 554 `: requested`).
  var pAnyMfa = b.permissions.create({
    roles: {
      admin:  { permissions: ["users:delete"], requireMfa: true },
      reader: ["users:read"],
    },
    resolver: function (req) { return req.user || null; },
  });
  var anyMfa = await _runMiddleware(
    pAnyMfa.requireAny(["users:delete", "posts:read"]),
    Object.assign(_mockReq(), { user: { roles: ["admin"] } }));
  check("mfa: per-role gate on requireAny route denies un-stepped-up actor",
    anyMfa.res._endedStatus === 403);

  // Non-Error throws fall through the `String(e)` audit-metadata fallback in
  // both ABAC error paths (lib 638 context, lib 660 predicate).
  // A thrown value with no `.message` (here a bare object, not an Error)
  // drives the `String(e)` fallback in the audit-metadata construction.
  var pCtxStr = b.permissions.create({ roles: { svc: ["orders:write"] } });
  pCtxStr.policy("orders:write", function (a, c) { return true; });
  var ctxStr = await _runMiddleware(
    pCtxStr.require("orders:write", { context: function () { throw _nonErrorValue("ctx"); } }),
    Object.assign(_mockReq(), { user: { scopes: ["orders:write"] } }));
  check("abac: non-Error context throw still denies (String(e) fallback)",
    ctxStr.res._endedStatus === 403);

  var pPredStr = b.permissions.create({ roles: { svc: ["orders:write"] } });
  pPredStr.policy("orders:write", function (a, c) { throw _nonErrorValue("pred"); });
  var predStr = await _runMiddleware(
    pPredStr.require("orders:write"),
    Object.assign(_mockReq(), { user: { scopes: ["orders:write"] } }));
  check("abac: non-Error predicate throw still denies (String(e) fallback)",
    predStr.res._endedStatus === 403);
}

// ---- Run ----

async function run() {
  testSurface();
  testMatchTable();
  testMatchPerSegmentWildcardShortRequired();
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
  await testAuditFailuresOptOut();
  await testFiveWsAuditPropagation();
  testCreateRejectsBadOpts();
  testRoleTableValidationEdgeCases();
  testMiddlewareOptValidation();
  testPolicyRegistration();
  testPolicyPredicateArityWarning();
  await testMfaPerRouteEnforcement();
  await testMfaPerRoleEnforcement();
  await testPolicyAbacSingleMode();
  await testPolicyAbacContextProvider();
  await testPolicyAbacAllAndAnyModes();
  testDbRoleFor();
  testDbRoleForAdversarialRoles();
  await testBranchCleanups();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}

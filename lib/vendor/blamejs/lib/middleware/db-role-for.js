// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var dbRoleContext = require("../db-role-context");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var safeSql = require("../safe-sql");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var audit        = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });

var DbRoleForError = defineClass("DbRoleForError", { alwaysPermanent: true });
var _err = function (code, message) { return new DbRoleForError(code, message); };

var ALLOWED_OPTS = [
  "resolve", "permissions", "defaultRole",
  "requireRole", "missingRoleStatus", "responder",
  "audit", "auditFailures", "auditSuccess",
];

function _emitEvent(n, v, l) { observability().safeEvent(n, v, l || {}); }

function _validateRoleIdentifier(role, where) {
  try {
    safeSql.validateIdentifier(role, { allowReserved: false });
  } catch (e) {
    throw _err("db-role-for/bad-role",
      where + ": role '" + role + "' is not a valid SQL identifier: " +
      ((e && e.message) || String(e)));
  }
}

function _defaultResponder(req, res, status, info) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(info));
}

/**
 * @primitive b.middleware.dbRoleFor
 * @signature b.middleware.dbRoleFor(opts)
 * @since     0.1.0
 * @related   b.middleware.attachUser, b.externalDb.query
 *
 * Binds a request-time database role into AsyncLocalStorage so
 * `b.externalDb.query` / `read` / `write` / `transaction` auto-route
 * to the matching backend (`app_user`, `analytics_user`, etc.) without
 * any operator threading of the role through the handler signature.
 * Resolution order: operator-supplied `resolve(req)` → permissions
 * RBAC `dbRoleFor` → `defaultRole` → null. Throws at create-time on
 * bad opts (resolver/responder shape, malformed default-role
 * identifier, out-of-range missing-role status). Runtime returns
 * are validated against `safeSql.validateIdentifier` — a garbage
 * resolver return surfaces as next(err), not silent fallthrough.
 * Emits `db.role.switched` audit + `db.role.bound` observability.
 *
 * @opts
 *   {
 *     resolve:           function(req): string|null,
 *     permissions:       object,           // b.permissions instance
 *     defaultRole:       string,
 *     requireRole:       boolean,
 *     missingRoleStatus: number,           // default 401
 *     responder:         function(req, res, status, info): void,
 *     audit:             object,
 *     auditFailures:     boolean,          // default true
 *     auditSuccess:      boolean,          // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.attachUser({ userLoader: async function () { return { id: 1 }; } }));
 *   app.use(b.middleware.dbRoleFor({
 *     defaultRole: "app_user",
 *     resolve:     function (req) { return req.user && req.user.dbRole; },
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ALLOWED_OPTS, "middleware.dbRoleFor");

  validateOpts.optionalFunction(opts.resolve, "middleware.dbRoleFor: resolve", DbRoleForError, "db-role-for/bad-opt");
  validateOpts.optionalFunction(opts.responder, "middleware.dbRoleFor: responder", DbRoleForError, "db-role-for/bad-opt");
  validateOpts.optionalObjectWithMethod(opts.permissions, "dbRoleFor",
    "middleware.dbRoleFor: permissions", DbRoleForError, "db-role-for/bad-opt",
    "must be a b.permissions instance (missing dbRoleFor method)");
  if (opts.defaultRole !== undefined && opts.defaultRole !== null) {
    if (typeof opts.defaultRole !== "string" || opts.defaultRole.length === 0) {
      throw _err("db-role-for/bad-opt",
        "middleware.dbRoleFor: defaultRole must be a non-empty string");
    }
    _validateRoleIdentifier(opts.defaultRole, "middleware.dbRoleFor: defaultRole");
  }
  validateOpts.optionalBoolean(opts.requireRole, "middleware.dbRoleFor: requireRole", DbRoleForError, "db-role-for/bad-opt");
  if (opts.missingRoleStatus !== undefined) {
    if (typeof opts.missingRoleStatus !== "number" ||
        !isFinite(opts.missingRoleStatus) ||
        opts.missingRoleStatus < 100 || opts.missingRoleStatus > 599) {
      throw _err("db-role-for/bad-opt",
        "middleware.dbRoleFor: missingRoleStatus must be an HTTP status code (100-599)");
    }
  }
  validateOpts.auditShape(opts.audit, "middleware.dbRoleFor", DbRoleForError, "db-role-for/bad-opt");
  validateOpts.optionalBoolean(opts.auditFailures, "middleware.dbRoleFor: auditFailures", DbRoleForError, "db-role-for/bad-opt");
  validateOpts.optionalBoolean(opts.auditSuccess, "middleware.dbRoleFor: auditSuccess", DbRoleForError, "db-role-for/bad-opt");

  var resolveFn         = opts.resolve || null;
  var perms             = opts.permissions || null;
  var defaultRole       = opts.defaultRole || null;
  var requireRole       = !!opts.requireRole;
  var missingRoleStatus = opts.missingRoleStatus || 401;
  var responder         = opts.responder || _defaultResponder;
  var auditSink         = opts.audit || null;
  var auditFailures     = (opts.auditFailures === undefined) ? true : opts.auditFailures;
  var auditSuccess      = (opts.auditSuccess  === undefined) ? true : opts.auditSuccess;

  return function dbRoleForMiddleware(req, res, next) {
    var role = null;
    var source = null;

    if (resolveFn) {
      var resolved;
      try { resolved = resolveFn(req); }
      catch (e) { return next(e); }
      if (resolved !== undefined && resolved !== null && resolved !== "") {
        role = resolved;
        source = "resolver";
      }
    }

    if (!role && perms) {
      var fromPerms;
      try { fromPerms = perms.dbRoleFor(req); }
      catch (e) { return next(e); }
      if (fromPerms) {
        role = fromPerms;
        source = "permissions";
      }
    }

    if (!role && defaultRole) {
      role = defaultRole;
      source = "default";
    }

    if (!role) {
      if (requireRole) {
        _emitEvent("db.role.missing", 1, {});
        if (auditFailures) {
          _auditSwitch(auditSink, req, {
            previousRole: dbRoleContext.getRole(),
            newRole:      null,
            source:       "middleware",
            outcome:      "failure",
            reason:       "no-role",
          });
        }
        return responder(req, res, missingRoleStatus, {
          error:  "missing_db_role",
          status: missingRoleStatus,
        });
      }
      req.dbRole = null;
      return next();
    }

    if (typeof role !== "string") {
      return next(_err("db-role-for/bad-resolver-return",
        "middleware.dbRoleFor: resolver returned non-string role: " + typeof role));
    }
    try {
      _validateRoleIdentifier(role, "middleware.dbRoleFor: resolver/" + source);
    } catch (e) {
      return next(e);
    }

    var previousRole = dbRoleContext.getRole();
    req.dbRole = role;
    _emitEvent("db.role.bound", 1, { role: role, source: source });
    if (auditSuccess) {
      _auditSwitch(auditSink, req, {
        previousRole: previousRole,
        newRole:      role,
        source:       "middleware",
        outcome:      "success",
      });
    }
    dbRoleContext.runWithRole(role, function () { next(); });
  };
}

function _auditSwitch(sink, req, info) {
  try {
    var emitter = sink || audit();
    emitter.safeEmit({
      action:   "db.role.switched",
      actor:    requestHelpers.extractActorContext(req),
      resource: { kind: "db.role", id: info.newRole || "(none)" },
      outcome:  info.outcome || "success",
      reason:   info.reason || null,
      metadata: {
        previousRole: info.previousRole || null,
        newRole:      info.newRole || null,
        source:       info.source,
      },
    });
  } catch (_e) { /* audit best-effort */ }
}

module.exports = {
  create:           create,
  DbRoleForError:   DbRoleForError,
};

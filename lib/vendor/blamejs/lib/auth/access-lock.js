// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var defineClass = require("../framework-error").defineClass;
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var requestHelpers = require("../request-helpers");

var audit = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });

var AccessLockError = defineClass("AccessLockError", { alwaysPermanent: true });

var VALID_MODES = Object.freeze({ open: 1, "read-only": 1, locked: 1 });
var SAFE_METHODS = Object.freeze({ GET: 1, HEAD: 1, OPTIONS: 1 });

function _normalizeMode(mode) {
  if (typeof mode !== "string") return null;
  var m = mode.toLowerCase();
  return Object.prototype.hasOwnProperty.call(VALID_MODES, m) ? m : null;
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "startMode", "unlockRoles", "passthroughPaths",
    "audit", "getRole", "errorMessage",
  ], "auth.accessLock");

  var startMode = _normalizeMode(opts.startMode || "open");
  if (!startMode) {
    throw new AccessLockError("auth-access-lock/bad-mode",
      "auth.accessLock: opts.startMode must be one of " + Object.keys(VALID_MODES).join(", "));
  }
  var unlockRoles = Array.isArray(opts.unlockRoles) ? opts.unlockRoles.slice() : [];
  for (var ri = 0; ri < unlockRoles.length; ri++) {
    if (typeof unlockRoles[ri] !== "string" || unlockRoles[ri].length === 0) {
      throw new AccessLockError("auth-access-lock/bad-role",
        "auth.accessLock: unlockRoles[" + ri + "] must be a non-empty string");
    }
  }
  var passthroughPaths = Array.isArray(opts.passthroughPaths)
    ? opts.passthroughPaths.slice() : [];
  var getRole = typeof opts.getRole === "function" ? opts.getRole : null;
  var errorMessage = typeof opts.errorMessage === "string" && opts.errorMessage.length > 0
    ? opts.errorMessage : "service in restricted access mode";

  var currentMode = startMode;
  var modeSetAt   = Date.now();
  var modeSetBy   = "boot";
  var modeReason  = "initial mode at boot";

  var _emitAudit = audit().namespaced("auth.access_lock", opts.audit);
  var _emitMetric = observability().namespaced("auth.access_lock");

  var _isPassthrough = requestHelpers.makeSkipMatcher(
    { skipPaths: passthroughPaths }, "auth.accessLock");

  function _hasUnlockRole(req) {
    if (!getRole || unlockRoles.length === 0) return false;
    var role;
    try { role = getRole(req); }
    catch (_e) { return false; }
    if (!role) return false;
    if (typeof role === "string") return unlockRoles.indexOf(role) !== -1;
    if (Array.isArray(role)) {
      for (var i = 0; i < role.length; i++) {
        if (unlockRoles.indexOf(role[i]) !== -1) return true;
      }
    }
    return false;
  }

  function set(mode, info) {
    var next = _normalizeMode(mode);
    if (!next) {
      throw new AccessLockError("auth-access-lock/bad-mode",
        "auth.accessLock.set: mode must be one of " + Object.keys(VALID_MODES).join(", "));
    }
    if (next === currentMode) return { mode: currentMode, changed: false };
    var prev = currentMode;
    info = info || {};
    currentMode = next;
    modeSetAt = Date.now();
    modeSetBy = typeof info.actor === "string" ? info.actor : "unspecified";
    modeReason = typeof info.reason === "string" ? info.reason : "";
    _emitAudit("mode_changed", "success", {
      from:   prev,
      to:     next,
      actor:  modeSetBy,
      reason: modeReason,
    });
    _emitMetric("mode_changed", 1, { from: prev, to: next });
    return { mode: currentMode, changed: true, from: prev };
  }

  function mode() { return currentMode; }
  function status() {
    return {
      mode:      currentMode,
      since:     modeSetAt,
      setBy:     modeSetBy,
      reason:    modeReason,
      passthroughPaths: passthroughPaths.slice(),
      unlockRoles:      unlockRoles.slice(),
    };
  }

  function _refuse(res, reason) {
    if (!res.writableEnded && typeof res.writeHead === "function") {
      res.writeHead(C.HTTP.STATUS.SERVICE_UNAVAILABLE, {
        "Content-Type":  "application/json; charset=utf-8",
        "Retry-After":   "60",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify({ error: errorMessage, mode: currentMode, reason: reason }));
    }
  }

  function middleware() {
    return function accessLockMiddleware(req, res, next) {
      if (currentMode === "open") return next();
      if (_isPassthrough(req)) return next();
      if (_hasUnlockRole(req)) return next();
      if (currentMode === "read-only") {
        var method = (req.method || "GET").toUpperCase();
        if (Object.prototype.hasOwnProperty.call(SAFE_METHODS, method)) return next();
        _emitAudit("refused", "denied", { mode: currentMode, method: method, path: req.url });
        _emitMetric("refused", 1, { mode: currentMode, reason: "non-safe-method" });
        return _refuse(res, "non-safe-method-in-read-only");
      }
      _emitAudit("refused", "denied", { mode: currentMode, method: req.method, path: req.url });
      _emitMetric("refused", 1, { mode: currentMode, reason: "locked" });
      return _refuse(res, "locked");
    };
  }

  _emitAudit("boot", "success", { mode: currentMode });
  _emitMetric("boot", 1, { mode: currentMode });

  return {
    middleware:       middleware,
    set:              set,
    mode:             mode,
    status:           status,
    VALID_MODES:      Object.keys(VALID_MODES),
  };
}

module.exports = {
  create:          create,
  AccessLockError: AccessLockError,
  VALID_MODES:     Object.keys(VALID_MODES),
};

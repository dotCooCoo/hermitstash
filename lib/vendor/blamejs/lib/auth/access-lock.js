"use strict";
/**
 * b.auth.accessLock — three-mode access-lock primitive for stop-the-
 * world / read-only / role-restricted operator interventions.
 *
 * Operators flip the framework's serving posture between modes during
 * incident response, schema migration windows, security investigations,
 * and break-glass review:
 *
 *   "open"      — normal operation; every request reaches its handler
 *   "read-only" — refuses non-idempotent methods (POST/PUT/PATCH/DELETE)
 *                 with 503; GET/HEAD/OPTIONS pass
 *   "locked"    — refuses every request with 503 except a small set of
 *                 operator-specified pass-through paths (status, health,
 *                 break-glass-unlock); useful during schema migrations or
 *                 a hard maintenance window
 *
 * Mode flips audit + emit a metric so dashboards see the transition.
 * The operator-supplied unlockRoles allows a privileged role
 * (configured via b.permissions) to bypass all three modes — the
 * break-glass operator can always reach the unlock endpoint to flip
 * back to "open". Without unlockRoles, "locked" is genuinely closed
 * and the operator has to redeploy with an opts.startMode override
 * to recover.
 *
 *   var lock = b.auth.accessLock.create({
 *     startMode:    "open",
 *     unlockRoles:  ["sre", "security-incident-response"],
 *     passthroughPaths: ["/healthz", "/readyz", "/admin/access-lock"],
 *     audit:        b.audit,
 *     getRole:      function (req) { return req.user && req.user.role; },
 *   });
 *
 *   router.use(lock.middleware());
 *   router.post("/admin/access-lock/:mode", function (req, res) {
 *     await lock.set(req.params.mode, { actor: req.user.id, reason: req.body.reason });
 *     res.json({ mode: lock.mode() });
 *   });
 */

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
      res.writeHead(503, {
        "Content-Type":  "application/json; charset=utf-8",
        "Retry-After":   "60",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify({ error: errorMessage, mode: currentMode, reason: reason }));
    }
  }

  function middleware() {
    return function accessLockMiddleware(req, res, next) {
      // open — fast path, no checks.
      if (currentMode === "open") return next();
      // passthrough paths bypass all modes (status / health / unlock endpoint).
      if (_isPassthrough(req)) return next();
      // unlockRoles bypass all modes.
      if (_hasUnlockRole(req)) return next();
      if (currentMode === "read-only") {
        var method = (req.method || "GET").toUpperCase();
        if (Object.prototype.hasOwnProperty.call(SAFE_METHODS, method)) return next();
        _emitAudit("refused", "denied", { mode: currentMode, method: method, path: req.url });
        _emitMetric("refused", 1, { mode: currentMode, reason: "non-safe-method" });
        return _refuse(res, "non-safe-method-in-read-only");
      }
      // locked — refuse everything that wasn't passthrough / unlockRole.
      _emitAudit("refused", "denied", { mode: currentMode, method: req.method, path: req.url });
      _emitMetric("refused", 1, { mode: currentMode, reason: "locked" });
      return _refuse(res, "locked");
    };
  }

  // Initial-mode audit fires once at create-time so operators see the
  // boot-time posture in the audit chain (confirms the deploy started
  // in the expected mode).
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

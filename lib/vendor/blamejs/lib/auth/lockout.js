// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var { LockoutError } = require("../framework-error");

var observability = lazyRequire(function () { return require("../observability"); });

var _err = LockoutError.factory;

var DEFAULT_ADMIN_LOCK_MS = C.TIME.hours(24);

var DEFAULTS = Object.freeze({
  maxAttempts:     5,
  windowMs:        C.TIME.minutes(15),
  lockoutDurations: Object.freeze([
    C.TIME.minutes(1),
    C.TIME.minutes(5),
    C.TIME.minutes(15),
    C.TIME.hours(1),
    C.TIME.hours(6),
  ]),
  auditFailures: true,
  auditEngaged:  true,
  auditUnlock:   true,
  auditSuccess:  false,
});

var ALLOWED_OPTS = [
  "namespace", "cache", "maxAttempts", "windowMs", "lockoutDurations",
  "audit", "auditFailures", "auditEngaged", "auditSuccess", "auditUnlock",
  "observability", "clock",
];

function _requireString(name, val) {
  if (typeof val !== "string" || val.length === 0) {
    throw _err("lockout/bad-opt", name + ": expected non-empty string, got " +
               typeof val + " " + JSON.stringify(val));
  }
}

function _requirePositiveInt(name, val) {
  if (!numericBounds.isPositiveFiniteInt(val)) {
    throw _err("lockout/bad-opt", name + ": expected positive integer, got " +
               typeof val + " " + JSON.stringify(val));
  }
}

function _requireNonNegFinite(name, val) {
  if (typeof val !== "number" || !isFinite(val) || val < 0) {
    throw _err("lockout/bad-opt", name + ": expected non-negative finite number, got " +
               typeof val + " " + JSON.stringify(val));
  }
}

function _requireKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("lockout/bad-key", "key must be a non-empty string, got " +
               typeof key + " " + JSON.stringify(key));
  }
}

function _resolveDuration(durations, lockNumber) {
  if (typeof durations === "function") {
    var v = durations(lockNumber);
    if (typeof v !== "number" || !isFinite(v) || v < 0) {
      throw _err("lockout/bad-lockout-duration",
        "lockoutDurations(" + lockNumber + ") must return a non-negative finite number, got " +
        typeof v + " " + JSON.stringify(v));
    }
    return v;
  }
  var idx = Math.min(lockNumber - 1, durations.length - 1);
  return durations[idx];
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ALLOWED_OPTS, "auth.lockout");

  if (!opts.cache || typeof opts.cache !== "object" ||
      typeof opts.cache.get !== "function" ||
      typeof opts.cache.del !== "function" ||
      typeof opts.cache.update !== "function") {
    throw _err("lockout/bad-opt", "auth.lockout.create: opts.cache must be a b.cache " +
               "instance (or shape with get/del/update — the failure counter needs " +
               "an atomic update). Pass b.cache.create({...}).");
  }
  _requireString("namespace", opts.namespace);

  var maxAttempts = opts.maxAttempts !== undefined ? opts.maxAttempts : DEFAULTS.maxAttempts;
  _requirePositiveInt("maxAttempts", maxAttempts);

  var windowMs = opts.windowMs !== undefined ? opts.windowMs : DEFAULTS.windowMs;
  _requirePositiveInt("windowMs", windowMs);

  var lockoutDurations = opts.lockoutDurations !== undefined
                            ? opts.lockoutDurations : DEFAULTS.lockoutDurations;
  if (typeof lockoutDurations !== "function") {
    if (!Array.isArray(lockoutDurations) || lockoutDurations.length === 0) {
      throw _err("lockout/bad-opt", "lockoutDurations must be a non-empty array of ms or a function(lockNumber)→ms");
    }
    for (var i = 0; i < lockoutDurations.length; i++) {
      _requireNonNegFinite("lockoutDurations[" + i + "]", lockoutDurations[i]);
    }
  }

  validateOpts.auditShape(opts.audit, "auth.lockout.create", LockoutError);
  validateOpts.observabilityShape(opts.observability, "auth.lockout.create", LockoutError);
  validateOpts.optionalFunction(opts.clock, "auth.lockout.create: clock", LockoutError);

  var cache         = opts.cache;
  var namespace     = opts.namespace;
  var auditInst     = opts.audit || null;
  var obsInst       = opts.observability || null;
  var clock         = opts.clock || Date.now;
  var auditFailures = opts.auditFailures !== undefined ? !!opts.auditFailures : DEFAULTS.auditFailures;
  var auditEngaged  = opts.auditEngaged  !== undefined ? !!opts.auditEngaged  : DEFAULTS.auditEngaged;
  var auditSuccess  = opts.auditSuccess  !== undefined ? !!opts.auditSuccess  : DEFAULTS.auditSuccess;
  var auditUnlock   = opts.auditUnlock   !== undefined ? !!opts.auditUnlock   : DEFAULTS.auditUnlock;

  function _scopedKey(key) { return namespace + ":" + key; }

  // framework's global registry (a no-op when none is wired), drop-silent.
  var _emitObs = observability().makeCounterEmitter(obsInst);

  var _emitAudit = requestHelpers.makeResourceAuditEmitter(auditInst, "auth.lockout", function (key) {
    return namespace + ":" + key;
  });

  function _signalCacheError(op) {
    _emitObs("auth.lockout.cache_error", { namespace: namespace, op: op });
    _emitAudit("auth.lockout.cache_error", "<system>", "failure",
      { namespace: namespace, op: op }, null);
  }

  async function _readState(key) {
    try {
      var raw = await cache.get(_scopedKey(key));
      return raw || null;
    } catch (_e) {
      _signalCacheError("get");
      return null;
    }
  }


  async function _deleteState(key) {
    try {
      await cache.del(_scopedKey(key));
    } catch (_e) {
      _signalCacheError("del");
    }
  }

  async function _atomicClear(key, onState, preserveIf) {
    try {
      await cache.update(_scopedKey(key), function (state) {
        state = state || null;
        onState(state);
        if (!state) return { abort: true };
        if (preserveIf && preserveIf(state)) return { abort: true };
        return { delete: true };
      }, { ttlMs: windowMs });
    } catch (e) {
      if (e && e.code === "cache/unsupported") {
        var st = await _readState(key);
        onState(st);
        if (st && !(preserveIf && preserveIf(st))) await _deleteState(key);
        return;
      }
      _signalCacheError("update");
      var st2 = await _readState(key);
      onState(st2);
      if (st2 && !(preserveIf && preserveIf(st2))) await _deleteState(key);
    }
  }

  function _isActiveForcedLock(state) {
    return !!(state && state.forced === true &&
              typeof state.lockedUntil === "number" && state.lockedUntil > clock());
  }

  function _verdictFromState(state, now) {
    if (!state) return { locked: false, attempts: 0 };
    if (state.lockedUntil && state.lockedUntil > now) {
      return {
        locked:      true,
        attempts:    state.attempts || 0,
        lockedUntil: state.lockedUntil,
      };
    }
    return { locked: false, attempts: state.attempts || 0 };
  }

  async function recordFailure(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var now = clock();
    var outcome = null;
    var mutatorErr = null;
    try {
      await cache.update(_scopedKey(key), function (state) {
        try {
          state = state || null;
          if (state && state.lockedUntil && state.lockedUntil > now) {
            outcome = { kind: "during-lock", attempts: state.attempts || 0,
              lockNumber: state.lockNumber || 0, lockedUntil: state.lockedUntil };
            return { abort: true };
          }
          if (state && state.lastFailureAt && (now - state.lastFailureAt) > windowMs) {
            state = { attempts: 0, lockNumber: state.lockNumber || 0,
              firstFailureAt: null, lastFailureAt: null, lockedUntil: null };
          }
          var attempts = (state && state.attempts) || 0;
          var lockNumber = (state && state.lockNumber) || 0;
          attempts += 1;
          var lockedUntil = null, newLock = false;
          if (attempts >= maxAttempts) {
            lockNumber += 1;
            lockedUntil = now + _resolveDuration(lockoutDurations, lockNumber);
            newLock = true;
            attempts = 0;
          }
          var newState = {
            attempts:       attempts,
            lockNumber:     lockNumber,
            firstFailureAt: (state && state.firstFailureAt) || now,
            lastFailureAt:  now,
            lockedUntil:    lockedUntil,
          };
          outcome = { kind: "recorded", attempts: attempts, lockNumber: lockNumber,
            lockedUntil: lockedUntil, newLock: newLock };
          return { value: newState, ttlMs: lockedUntil ? (lockedUntil - now + windowMs) : windowMs };
        } catch (me) {
          mutatorErr = me;
          throw me;
        }
      }, { ttlMs: windowMs });
    } catch (e) {
      if (mutatorErr) throw mutatorErr;
      if (e && e.code === "cache/unsupported") {
        throw _err("lockout/cache-no-atomic-update",
          "auth.lockout: the cache backend does not support atomic update() — the " +
          "failure counter cannot be enforced across nodes on a get/set-only backend; " +
          "use a cache whose backend implements update (the memory or cluster backend).");
      }
      _signalCacheError("update");
      return { locked: false, attempts: 0 };
    }

    if (outcome.kind === "during-lock") {
      _emitObs("auth.lockout.failure_during_lock", { namespace: namespace });
      if (auditFailures) {
        _emitAudit("auth.lockout.failure", key, "denied",
          { duringLock: true, attempts: outcome.attempts, lockNumber: outcome.lockNumber,
            lockedUntil: outcome.lockedUntil, reason: callOpts.reason || null },
          callOpts.req);
      }
      return { locked: true, attempts: outcome.attempts, lockedUntil: outcome.lockedUntil };
    }

    _emitObs("auth.lockout.failure", { namespace: namespace });
    if (auditFailures) {
      _emitAudit("auth.lockout.failure", key, "failure",
        { attempts: outcome.attempts, lockNumber: outcome.lockNumber,
          reason: callOpts.reason || null },
        callOpts.req);
    }

    if (outcome.newLock) {
      _emitObs("auth.lockout.engaged", {
        namespace:  namespace,
        lockNumber: String(outcome.lockNumber),
      });
      if (auditEngaged) {
        _emitAudit("auth.lockout.engaged", key, "denied",
          { lockNumber: outcome.lockNumber, lockedUntil: outcome.lockedUntil,
            durationMs: outcome.lockedUntil - now,
            reason: callOpts.reason || null },
          callOpts.req);
      }
      return { locked: true, attempts: 0, lockedUntil: outcome.lockedUntil };
    }

    return { locked: false, attempts: outcome.attempts };
  }

  async function recordSuccess(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var hadCounter = false;
    var clearedAttempts = 0;
    await _atomicClear(key, function (state) {
      hadCounter = !!(state && (state.attempts > 0 || state.lockedUntil));
      clearedAttempts = (state && state.attempts) || 0;
    }, _isActiveForcedLock);
    _emitObs("auth.lockout.success", { namespace: namespace });
    if (auditSuccess) {
      _emitAudit("auth.lockout.success", key, "success",
        { attemptsCleared: clearedAttempts,
          hadCounter:      hadCounter },
        callOpts.req);
    }
  }

  async function check(key) {
    _requireKey(key);
    var state = await _readState(key);
    return _verdictFromState(state, clock());
  }

  async function unlock(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var now = clock();
    var hadLock = false;
    var prior = { attempts: 0, lockedUntil: null, lockNumber: 0 };
    await _atomicClear(key, function (state) {
      hadLock = !!(state && (
        (state.lockedUntil && state.lockedUntil > now) ||
        (state.attempts || 0) > 0
      ));
      prior = {
        attempts:    (state && state.attempts) || 0,
        lockedUntil: (state && state.lockedUntil) || null,
        lockNumber:  (state && state.lockNumber) || 0,
      };
    });
    _emitObs("auth.lockout.unlock", { namespace: namespace });
    if (auditUnlock) {
      _emitAudit("auth.lockout.unlock", key, "success",
        { hadLock:           hadLock,
          priorAttempts:    prior.attempts,
          priorLockedUntil: prior.lockedUntil,
          priorLockNumber:  prior.lockNumber,
          reason:           callOpts.reason || null },
        callOpts.req);
    }
    return hadLock;
  }

  async function lock(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var now = clock();
    var lockedUntil;
    if (typeof callOpts.untilMs === "number" && isFinite(callOpts.untilMs)) {
      lockedUntil = callOpts.untilMs;
    } else if (typeof callOpts.durationMs === "number" && isFinite(callOpts.durationMs) && callOpts.durationMs > 0) {
      lockedUntil = now + callOpts.durationMs;
    } else {
      lockedUntil = now + DEFAULT_ADMIN_LOCK_MS;
    }
    if (lockedUntil <= now) {
      throw _err("lockout/bad-opt", "lock: resolved lockedUntil is not in the future " +
        "(untilMs/durationMs) — use unlock() to clear a lock");
    }
    var ttl = lockedUntil - now + windowMs;
    var lockNumber = 0;
    try {
      await cache.update(_scopedKey(key), function (state) {
        lockNumber = ((state && state.lockNumber) || 0) + 1;
        return {
          value: {
            attempts:       0,
            lockNumber:     lockNumber,
            firstFailureAt: (state && state.firstFailureAt) || now,
            lastFailureAt:  now,
            lockedUntil:    lockedUntil,
            forced:         true,
          },
          ttlMs: ttl,
        };
      }, { ttlMs: ttl });
    } catch (e) {
      if (e && e.code === "cache/unsupported") {
        throw _err("lockout/cache-no-atomic-update",
          "auth.lockout: the cache backend does not support atomic update() — " +
          "lock() cannot enforce the lockout across nodes on a get/set-only backend.");
      }
      throw e;
    }
    _emitObs("auth.lockout.engaged", { namespace: namespace, lockNumber: String(lockNumber) });
    if (auditEngaged) {
      _emitAudit("auth.lockout.engaged", key, "denied",
        { lockNumber: lockNumber, lockedUntil: lockedUntil, durationMs: lockedUntil - now,
          forced: true, reason: callOpts.reason || null },
        callOpts.req);
    }
    return { locked: true, lockedUntil: lockedUntil, lockNumber: lockNumber };
  }

  async function attempts(key) {
    _requireKey(key);
    var state = await _readState(key);
    return (state && state.attempts) || 0;
  }

  async function close() {
    // The cache is operator-owned; lockout doesn't close it. Provided
    // for API symmetry with other primitives (cache.close, notify.close,
    // etc.) so operator shutdown code can call close() uniformly.
  }

  return {
    recordFailure: recordFailure,
    recordSuccess: recordSuccess,
    check:         check,
    lock:          lock,
    unlock:        unlock,
    attempts:      attempts,
    close:         close,
    namespace:     namespace,
  };
}

module.exports = {
  create:       create,
  LockoutError: LockoutError,
  DEFAULTS:     DEFAULTS,
};

"use strict";
/**
 * b.auth.lockout — per-key failed-attempt tracking with exponential
 * backoff lockout windows and admin/unlock.
 *
 * Operators compose this around any "X attempts to do Y" surface where
 * online brute force is the threat — login by password, login by TOTP,
 * passkey verification, password-reset code entry, etc. Each operator-
 * named instance keeps its own counter namespace, so login attempts and
 * TOTP attempts decay and lock independently.
 *
 * State storage is a b.cache instance the operator passes in. Memory
 * backend → per-process counters. Cluster backend → shared across nodes.
 * The cache TTL keeps the state self-cleaning — no separate sweep.
 *
 *   var loginLock = b.auth.lockout.create({
 *     namespace: "login",
 *     cache:     b.cache.create({ namespace: "auth.lockout.login", backend: "cluster" }),
 *     audit:     b.audit,
 *   });
 *
 *   // Pre-check before doing argon2 verify (saves ~250ms when locked)
 *   var state = await loginLock.check(req.body.email);
 *   if (state.locked) return res.status(429).json({ lockedUntil: state.lockedUntil });
 *
 *   var ok = await b.auth.password.verify(stored, req.body.password);
 *   if (!ok) {
 *     var verdict = await loginLock.recordFailure(req.body.email, { req });
 *     return res.status(401).json({
 *       attemptsRemaining: Math.max(0, MAX - verdict.attempts),
 *       lockedUntil:       verdict.lockedUntil,
 *     });
 *   }
 *   await loginLock.recordSuccess(req.body.email, { req });
 *   // ... session.create
 *
 *   // Admin-driven unlock — emits auth.lockout.unlock with the admin
 *   // operator's 5 W's via extractActorContext({ req }).
 *   await loginLock.unlock(targetUserId, { req, reason: "support ticket #4471" });
 *
 * Default backoff ladder (each subsequent lockout in a window-of-windows
 * stays longer to make sustained attacks expensive):
 *
 *   1st lockout → C.TIME.minutes(1)
 *   2nd         → C.TIME.minutes(5)
 *   3rd         → C.TIME.minutes(15)
 *   4th         → C.TIME.hours(1)
 *   5th and later → C.TIME.hours(6)
 *
 * Failures outside `windowMs` decay (counter resets on the next failure).
 * Successful auth clears the counter and any active lockout entirely so
 * a legitimate user who finally remembers their password isn't penalised
 * for the prior streak.
 *
 * Backend-error posture: if the cache backend throws on get/set/del —
 * Redis down, cluster DB unreachable — the lockout fails OPEN, not
 * closed. The framework's job is to slow brute force, not to lock
 * operators out of their own admin account because the cache went
 * away. Backend errors emit `auth.lockout.cache_error` observability
 * so ops dashboards see the issue.
 *
 * Operator surface returned by create():
 *
 *   recordFailure(key, opts?)  → { locked, attempts, lockedUntil? }
 *   recordSuccess(key, opts?)  → void                   (clears counter)
 *   check(key)                 → { locked, attempts, lockedUntil? }
 *                                                       (read-only)
 *   unlock(key, opts?)         → boolean                (admin unlock)
 *   attempts(key)              → number
 *   close()                    → void                   (no-op; cache is
 *                                                       operator-owned)
 *
 * Audit events (when `audit: b.audit` passed):
 *
 *   auth.lockout.failure   — every recordFailure. Default ON.
 *   auth.lockout.engaged   — lockout transition. Default ON.
 *   auth.lockout.unlock    — admin unlock. Default ON.
 *   auth.lockout.success   — recordSuccess. Default OFF (opt in via
 *                            auditSuccess: true for raw request-log mode).
 */

var C = require("../constants");
var numericBounds = require("../numeric-bounds");
var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var { LockoutError } = require("../framework-error");

var observability = lazyRequire(function () { return require("../observability"); });

var _err = LockoutError.factory;

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
    throw _err("BAD_OPT", name + ": expected non-empty string, got " +
               typeof val + " " + JSON.stringify(val));
  }
}

function _requirePositiveInt(name, val) {
  if (!numericBounds.isPositiveFiniteInt(val)) {
    throw _err("BAD_OPT", name + ": expected positive integer, got " +
               typeof val + " " + JSON.stringify(val));
  }
}

function _requireNonNegFinite(name, val) {
  if (typeof val !== "number" || !isFinite(val) || val < 0) {
    throw _err("BAD_OPT", name + ": expected non-negative finite number, got " +
               typeof val + " " + JSON.stringify(val));
  }
}

function _requireKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("BAD_KEY", "key must be a non-empty string, got " +
               typeof key + " " + JSON.stringify(key));
  }
}

function _resolveDuration(durations, lockNumber) {
  if (typeof durations === "function") {
    var v = durations(lockNumber);
    if (typeof v !== "number" || !isFinite(v) || v < 0) {
      throw _err("BAD_LOCKOUT_DURATION",
        "lockoutDurations(" + lockNumber + ") must return a non-negative finite number, got " +
        typeof v + " " + JSON.stringify(v));
    }
    return v;
  }
  // Array — clamp to last entry so deeper lockouts stay at the longest.
  var idx = Math.min(lockNumber - 1, durations.length - 1);
  return durations[idx];
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ALLOWED_OPTS, "auth.lockout");

  if (!opts.cache || typeof opts.cache !== "object" ||
      typeof opts.cache.get !== "function" ||
      typeof opts.cache.set !== "function" ||
      typeof opts.cache.del !== "function") {
    throw _err("BAD_OPT", "auth.lockout.create: opts.cache must be a b.cache " +
               "instance (or shape with get/set/del). Pass b.cache.create({...}).");
  }
  _requireString("namespace", opts.namespace);

  var maxAttempts = opts.maxAttempts !== undefined ? opts.maxAttempts : DEFAULTS.maxAttempts;
  _requirePositiveInt("maxAttempts", maxAttempts);

  var windowMs = opts.windowMs !== undefined ? opts.windowMs : DEFAULTS.windowMs;
  _requireNonNegFinite("windowMs", windowMs);

  var lockoutDurations = opts.lockoutDurations !== undefined
                            ? opts.lockoutDurations : DEFAULTS.lockoutDurations;
  if (typeof lockoutDurations !== "function") {
    if (!Array.isArray(lockoutDurations) || lockoutDurations.length === 0) {
      throw _err("BAD_OPT", "lockoutDurations must be a non-empty array of ms or a function(lockNumber)→ms");
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

  // Emit to the operator's configured observability instance, else the
  // framework's global registry (a no-op when none is wired), drop-silent.
  var _emitObs = observability().makeCounterEmitter(obsInst);

  var _emitAudit = requestHelpers.makeResourceAuditEmitter(auditInst, "auth.lockout", function (key) {
    return namespace + ":" + key;
  });

  // Cache failures fail-OPEN by design (per the framework's
  // documented brute-force-lockout posture — rather than crash the
  // request, allow the attempt). The signal MUST land somewhere
  // visible regardless of operator wiring: observability picks it up
  // when wired, and audit picks it up when wired. Without the audit
  // path a deployment running with no observability + a degraded
  // cache silently gets brute-force-protection-disabled.
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

  async function _writeState(key, state, ttlMs) {
    try {
      await cache.set(_scopedKey(key), state, { ttlMs: ttlMs });
    } catch (_e) {
      _signalCacheError("set");
    }
  }

  async function _deleteState(key) {
    try {
      await cache.del(_scopedKey(key));
    } catch (_e) {
      _signalCacheError("del");
    }
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

  // ---- Public surface ----

  // Per-key serialization of the failure counter (read→increment→write on an
  // async store): concurrent recordFailure calls for the same key would lose
  // updates, letting parallel failures stay under the lockout threshold. A
  // per-key promise chain applies them sequentially in-process.
  var _recordChains = new Map();
  function recordFailure(key, callOpts) {
    var prev = _recordChains.get(key) || Promise.resolve();
    var run = prev.then(function () { return _doRecordFailure(key, callOpts); },
                        function () { return _doRecordFailure(key, callOpts); });
    var tail = run.then(function () {}, function () {});
    _recordChains.set(key, tail);
    tail.then(function () { if (_recordChains.get(key) === tail) _recordChains.delete(key); });
    return run;
  }

  async function _doRecordFailure(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var now = clock();
    var state = await _readState(key);

    // If currently locked, the lockout itself counts — don't accumulate
    // additional attempts during the cooldown. The caller saw locked=true
    // from check() OR from a prior failure; this branch handles a caller
    // that calls recordFailure() on a locked account anyway (e.g. they
    // skipped check()).
    if (state && state.lockedUntil && state.lockedUntil > now) {
      _emitObs("auth.lockout.failure_during_lock", { namespace: namespace });
      if (auditFailures) {
        _emitAudit("auth.lockout.failure", key, "denied",
          { duringLock: true, attempts: state.attempts || 0,
            lockNumber: state.lockNumber || 0,
            lockedUntil: state.lockedUntil,
            reason: callOpts.reason || null },
          callOpts.req);
      }
      return {
        locked:      true,
        attempts:    state.attempts || 0,
        lockedUntil: state.lockedUntil,
      };
    }

    // Window decay: failures older than windowMs reset the counter.
    // Lock-number persists across decay windows so an attacker who
    // sleeps off a lockout doesn't get a fresh ladder rung.
    if (state && state.lastFailureAt && (now - state.lastFailureAt) > windowMs) {
      state = {
        attempts:       0,
        lockNumber:     state.lockNumber || 0,
        firstFailureAt: null,
        lastFailureAt:  null,
        lockedUntil:    null,
      };
    }

    var attempts   = (state && state.attempts) || 0;
    var lockNumber = (state && state.lockNumber) || 0;
    attempts += 1;

    var lockedUntil = null;
    var newLock = false;
    if (attempts >= maxAttempts) {
      lockNumber += 1;
      var dur = _resolveDuration(lockoutDurations, lockNumber);
      lockedUntil = now + dur;
      newLock = true;
      attempts = 0;  // counter resets — the lockout window IS the punishment
    }

    var newState = {
      attempts:       attempts,
      lockNumber:     lockNumber,
      firstFailureAt: (state && state.firstFailureAt) || now,
      lastFailureAt:  now,
      lockedUntil:    lockedUntil,
    };

    // TTL: keep the state alive long enough that a follower-up failure
    // after the window/lockout expires still finds the lockNumber. The
    // longer of (windowMs after last failure) or (lockedUntil + windowMs).
    var ttlMs = lockedUntil ? (lockedUntil - now + windowMs) : windowMs;
    await _writeState(key, newState, ttlMs);

    _emitObs("auth.lockout.failure", { namespace: namespace });
    if (auditFailures) {
      _emitAudit("auth.lockout.failure", key, "failure",
        { attempts: newState.attempts, lockNumber: lockNumber,
          reason: callOpts.reason || null },
        callOpts.req);
    }

    if (newLock) {
      _emitObs("auth.lockout.engaged", {
        namespace:  namespace,
        lockNumber: String(lockNumber),
      });
      if (auditEngaged) {
        _emitAudit("auth.lockout.engaged", key, "denied",
          { lockNumber: lockNumber, lockedUntil: lockedUntil,
            durationMs: lockedUntil - now,
            reason: callOpts.reason || null },
          callOpts.req);
      }
      return { locked: true, attempts: 0, lockedUntil: lockedUntil };
    }

    return { locked: false, attempts: attempts };
  }

  async function recordSuccess(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var state = await _readState(key);
    var hadCounter = !!(state && (state.attempts > 0 || state.lockedUntil));
    if (state) await _deleteState(key);
    _emitObs("auth.lockout.success", { namespace: namespace });
    if (auditSuccess) {
      _emitAudit("auth.lockout.success", key, "success",
        { attemptsCleared: (state && state.attempts) || 0,
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
    var state = await _readState(key);
    var now = clock();
    var hadLock = !!(state && (
      (state.lockedUntil && state.lockedUntil > now) ||
      (state.attempts || 0) > 0
    ));
    if (state) await _deleteState(key);
    _emitObs("auth.lockout.unlock", { namespace: namespace });
    if (auditUnlock) {
      _emitAudit("auth.lockout.unlock", key, "success",
        { hadLock:           hadLock,
          priorAttempts:    (state && state.attempts) || 0,
          priorLockedUntil: (state && state.lockedUntil) || null,
          priorLockNumber:  (state && state.lockNumber) || 0,
          reason:           callOpts.reason || null },
        callOpts.req);
    }
    return hadLock;
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

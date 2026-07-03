// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

// Default duration for an operator-forced lock() (ATO kill-switch / incident
// response) when neither untilMs nor durationMs is supplied — long enough to
// require an explicit admin unlock() during an active incident.
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
      typeof opts.cache.del !== "function" ||
      typeof opts.cache.update !== "function") {
    throw _err("BAD_OPT", "auth.lockout.create: opts.cache must be a b.cache " +
               "instance (or shape with get/del/update — the failure counter needs " +
               "an atomic update). Pass b.cache.create({...}).");
  }
  _requireString("namespace", opts.namespace);

  var maxAttempts = opts.maxAttempts !== undefined ? opts.maxAttempts : DEFAULTS.maxAttempts;
  _requirePositiveInt("maxAttempts", maxAttempts);

  var windowMs = opts.windowMs !== undefined ? opts.windowMs : DEFAULTS.windowMs;
  // windowMs must be POSITIVE: a 0 window makes every failure "decay" on the
  // next request (the `now - lastFailureAt > windowMs` reset fires for any
  // elapsed time) so the counter never reaches maxAttempts, AND the cache TTL
  // of 0 makes the state non-persistent — together silently disabling lockout.
  _requirePositiveInt("windowMs", windowMs);

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


  async function _deleteState(key) {
    try {
      await cache.del(_scopedKey(key));
    } catch (_e) {
      _signalCacheError("del");
    }
  }

  // Atomically clear the lockout state under a compare-and-set, so a clear
  // (recordSuccess / unlock) cannot race a concurrent recordFailure that just
  // engaged a lock — a read-then-del would erase that fresh lock. onState is
  // invoked with the pre-clear state inside the CAS mutator (it may re-run on a
  // retry; the last invocation reflects the committed state) to capture audit
  // detail. On a backend that can't do an atomic update at runtime it falls
  // back to read-then-del (a lost clear leaves a lock in place — fail-safe).
  // preserveIf(state) → true to KEEP the state (abort the clear) rather than
  // delete it. recordSuccess passes a predicate that preserves an active forced
  // (admin / ATO kill-switch) lock, so a successful login by someone who still
  // holds the compromised password cannot clear it — only an explicit unlock()
  // releases a forced lock.
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
      if (e && e.code === "UNSUPPORTED") {
        var st = await _readState(key);
        onState(st);
        if (st && !(preserveIf && preserveIf(st))) await _deleteState(key);
        return;
      }
      _signalCacheError("update");
      // Best-effort fallback so a transient cache error doesn't leave the
      // counter un-cleared on the happy path.
      var st2 = await _readState(key);
      onState(st2);
      if (st2 && !(preserveIf && preserveIf(st2))) await _deleteState(key);
    }
  }

  // An active forced/admin lock (set by lock()) must survive recordSuccess.
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

  // ---- Public surface ----

  // The failure counter is a read-modify-write on a shared cache. A plain
  // get -> increment -> set is not atomic, so concurrent recordFailure calls
  // across nodes lose increments and a brute-force attacker spread across nodes
  // stays under the lockout threshold. cache.update runs the whole decision
  // under a compare-and-set (with retry on the cluster backend), so every
  // failure is counted. The mutator is PURE (it may re-run on a CAS retry): it
  // computes the next state, records the outcome for the post-commit audit /
  // observability emits below, and captures any error it raises so a
  // configuration fault surfaces instead of being read as a cache failure.
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
          // Currently locked: the lockout itself counts — don't accumulate during
          // the cooldown. Abort (no write); the verdict comes from the read state.
          if (state && state.lockedUntil && state.lockedUntil > now) {
            outcome = { kind: "during-lock", attempts: state.attempts || 0,
              lockNumber: state.lockNumber || 0, lockedUntil: state.lockedUntil };
            return { abort: true };
          }
          // Window decay: failures older than windowMs reset the counter.
          // Lock-number persists so an attacker who sleeps off a lockout doesn't
          // get a fresh ladder rung.
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
            attempts = 0;  // counter resets — the lockout window IS the punishment
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
          // Keep the state only as long as it is meaningful: a non-locked counter
          // expires after the decay window (so check()/attempts() read clean once
          // it has elapsed), and a lock persists until lockedUntil plus a window
          // so the lockNumber survives the cooldown — for the operator's actual
          // configured duration, however long. A DURATION (the cache resolves it
          // against its own clock) so an injectable lockout clock never desyncs
          // the cache's expiry.
          return { value: newState, ttlMs: lockedUntil ? (lockedUntil - now + windowMs) : windowMs };
        } catch (me) {
          mutatorErr = me;
          throw me;
        }
      }, { ttlMs: windowMs });
    } catch (e) {
      // A configuration fault raised by the mutator (e.g. a lockoutDurations
      // function returning an invalid value) must surface — not be swallowed as
      // a backend failure and silently disable the lockout.
      if (mutatorErr) throw mutatorErr;
      // A backend that can't actually commit an atomic update (a get/set-only
      // backend throws UNSUPPORTED at call time) must surface LOUD — failing
      // open here would silently disable lockout. Any other cache error keeps
      // the documented fail-OPEN posture (allow the attempt, signal it).
      if (e && e.code === "UNSUPPORTED") {
        throw _err("CACHE_NO_ATOMIC_UPDATE",
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
    // Preserve an active forced (admin / ATO) lock: a successful credential
    // verification must not release a kill-switch lock — the password may still
    // be the compromised one. A forced lock yields only to unlock().
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

  // Force an account into lockout immediately — the operator action behind an
  // ATO kill-switch / incident response, independent of the failure counter.
  // Sets lockedUntil to `untilMs` (absolute) or now+`durationMs`, defaulting to
  // a long admin lock; bumps lockNumber so a subsequent failure ladders from
  // here. Uses the same compare-and-set as recordFailure (atomic, retried). An
  // admin lock that cannot be committed THROWS (the caller — e.g. the kill-
  // switch — must know it did not lock), rather than the hot-path fail-open.
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
      throw _err("BAD_OPT", "lock: resolved lockedUntil is not in the future " +
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
            // Marks this as an operator-forced lock so recordSuccess won't clear
            // it — it is released only by an explicit unlock().
            forced:         true,
          },
          ttlMs: ttl,
        };
      }, { ttlMs: ttl });
    } catch (e) {
      if (e && e.code === "UNSUPPORTED") {
        throw _err("CACHE_NO_ATOMIC_UPDATE",
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

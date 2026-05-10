"use strict";
/**
 * @module b.authBotChallenge
 * @nav    Identity
 * @title  Auth Bot Challenge
 *
 * @intro
 *   Adaptive bot-challenge gate for authentication paths. Composes
 *   `b.middleware.botGuard` + `b.auth.lockout` + an operator-supplied
 *   challenge function (captcha / email confirmation / second-factor
 *   prompt) into a deterministic staircase that escalates protection
 *   as failed-auth attempts accumulate.
 *
 *   Staircase: below `threshold` failures, requests flow through
 *   unchanged. At `threshold`, bot-guard heuristics gate the session.
 *   After bot-guard passes but failures keep accumulating, the
 *   operator's `challengeFn(req, res)` runs (returning `true` clears
 *   the challenge). Past `escalationThreshold`, `escalationFn(req)`
 *   runs (typically `b.auth.atoKillSwitch.trigger`) and the middleware
 *   answers 423 Locked.
 *
 *   Session state is operator-storage — pass a `b.cache`-shaped
 *   sessionStore (any backend) and the gate persists per-key
 *   (stage, failures, challengedAt, passedAt). The lockout primitive
 *   stays the cluster-shared counter authority; this primitive layers
 *   the human-vs-bot ladder above it.
 *
 *   Audit emissions: `auth.bot_challenge.required` /
 *   `.passed` / `.failed` / `.escalated` / `.cleared`. Validation
 *   policy: `create()` throws on bad opts at boot; `middleware()`
 *   never throws (staircase failures audit and answer 401/423);
 *   `recordFailure` / `recordSuccess` / `check` / `reset` throw on
 *   bad keys.
 *
 * @card
 *   Adaptive bot-challenge gate for authentication paths.
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var { AuthBotChallengeError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });

var DEFAULT_THRESHOLD             = 3;
var DEFAULT_ESCALATION_THRESHOLD  = 6;
var DEFAULT_CHALLENGE_TTL_MS      = C.TIME.minutes(30);

var STATE_NEW        = "new";
var STATE_CHALLENGED = "challenged";
var STATE_PASSED     = "passed";
var STATE_LOCKED     = "locked";

var ALLOWED_OPTS = [
  "botGuard", "lockout", "sessionStore", "threshold", "escalationThreshold",
  "challengeFn", "escalationFn", "audit", "challengeTtlMs", "keyExtractor",
  "observability", "clock",
];

function _requireFunction(name, val) {
  if (typeof val !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      name + ": expected function, got " + typeof val);
  }
}

function _requirePositiveInt(name, val) {
  if (typeof val !== "number" || !isFinite(val) || val < 1 || Math.floor(val) !== val) {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      name + ": expected positive integer, got " + JSON.stringify(val));
  }
}

function _requireNonNegFinite(name, val) {
  if (typeof val !== "number" || !isFinite(val) || val < 0) {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      name + ": expected non-negative finite number, got " + JSON.stringify(val));
  }
}

function _requireKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-key",
      "key must be a non-empty string, got " + typeof key + " " + JSON.stringify(key));
  }
}

function _requireSessionStore(store) {
  if (!store || typeof store !== "object" ||
      typeof store.get !== "function" ||
      typeof store.set !== "function" ||
      typeof store.del !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "sessionStore must be a b.cache-shaped object (get/set/del)");
  }
}

function _requireBotGuard(bg) {
  if (typeof bg !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "botGuard must be a connect-style middleware function (got " + typeof bg + ")");
  }
}

function _requireLockout(lk) {
  if (!lk || typeof lk !== "object" ||
      typeof lk.recordFailure !== "function" ||
      typeof lk.recordSuccess !== "function" ||
      typeof lk.check !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "lockout must be a b.auth.lockout-shaped instance " +
      "(recordFailure/recordSuccess/check)");
  }
}

function _defaultKeyExtractor(req) {
  // Default key strategy: prefer user-supplied identifier (req.body.email,
  // req.body.username), fall back to client IP. Operators override via
  // opts.keyExtractor for OAuth flows / passkey ceremonies.
  if (req && req.body && typeof req.body === "object") {
    if (typeof req.body.email === "string" && req.body.email.length > 0) {
      return req.body.email.toLowerCase();
    }
    if (typeof req.body.username === "string" && req.body.username.length > 0) {
      return req.body.username.toLowerCase();
    }
  }
  try { return requestHelpers.clientIp(req); }
  catch (_e) { return "<unknown>"; }
}

/**
 * @primitive b.authBotChallenge.create
 * @signature b.authBotChallenge.create(opts)
 * @since     0.8.48
 * @status    stable
 * @related   b.middleware.botGuard
 *
 * Build an adaptive bot-challenge gate. Returns
 * `{ middleware, recordFailure, recordSuccess, check, reset }`.
 * `middleware()` is the connect-style entry point; `recordFailure(key)`
 * and `recordSuccess(key)` advance / clear the ladder from the
 * operator's post-verify code path.
 *
 * @opts
 *   botGuard:            Function,   // connect-style (req, res, next) middleware
 *   lockout:             Object,     // b.auth.lockout instance (recordFailure / recordSuccess / check)
 *   sessionStore:        Object,     // b.cache-shaped store (get / set / del)
 *   threshold:           number,     // failures before challenge stage (default 3)
 *   escalationThreshold: number,     // failures before lockout (default 6; must exceed threshold)
 *   challengeFn:         Function,   // async (req, res) → boolean | thrown
 *   escalationFn:        Function,   // async (req) → void; runs at lockout
 *   audit:               Object,     // b.audit instance (safeEmit-shaped)
 *   challengeTtlMs:      number,     // session-mark TTL (default 30 minutes)
 *   keyExtractor:        Function,   // (req) → string; default body.email / body.username / clientIp
 *   observability:       Object,     // observability sink (event-shaped)
 *   clock:               Function,   // () → number; testing override (default Date.now)
 *
 * @example
 *   var gate = b.authBotChallenge.create({
 *     botGuard:     botGuardMiddleware,
 *     lockout:      lockoutInstance,
 *     sessionStore: cacheInstance,
 *     threshold:    3,
 *     escalationThreshold: 6,
 *     challengeFn:  async function (req, res) {
 *       return req.body && req.body.captchaToken === "verified";
 *     },
 *     escalationFn: async function (req) {
 *       // Kill session, lock account, page on-call.
 *     },
 *     audit:        auditInstance,
 *   });
 *
 *   // Mount on the login route — the gate decides 200 / 401 / 423.
 *   var loginRoute = [gate.middleware(), function (req, res) { res.end("ok"); }];
 *
 *   // After verifying the credential, advance the ladder explicitly:
 *   var advanced = await gate.recordFailure("user@example.com");
 *   advanced.stage;          // → "new" | "challenged" | "locked"
 *
 *   var status = await gate.check("user@example.com");
 *   status.failures;         // → 1
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ALLOWED_OPTS, "authBotChallenge.create");

  _requireBotGuard(opts.botGuard);
  _requireLockout(opts.lockout);
  _requireSessionStore(opts.sessionStore);

  var threshold = opts.threshold !== undefined ? opts.threshold : DEFAULT_THRESHOLD;
  _requirePositiveInt("threshold", threshold);
  var escalationThreshold = opts.escalationThreshold !== undefined
    ? opts.escalationThreshold : DEFAULT_ESCALATION_THRESHOLD;
  _requirePositiveInt("escalationThreshold", escalationThreshold);
  if (escalationThreshold <= threshold) {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "escalationThreshold (" + escalationThreshold + ") must exceed threshold (" + threshold + ")");
  }

  var challengeTtlMs = opts.challengeTtlMs !== undefined
    ? opts.challengeTtlMs : DEFAULT_CHALLENGE_TTL_MS;
  _requireNonNegFinite("challengeTtlMs", challengeTtlMs);

  if (opts.challengeFn !== undefined) _requireFunction("challengeFn", opts.challengeFn);
  if (opts.escalationFn !== undefined) _requireFunction("escalationFn", opts.escalationFn);
  if (opts.keyExtractor !== undefined) _requireFunction("keyExtractor", opts.keyExtractor);

  validateOpts.auditShape(opts.audit, "authBotChallenge.create", AuthBotChallengeError);

  var botGuard      = opts.botGuard;
  var lockout       = opts.lockout;
  var sessionStore  = opts.sessionStore;
  var challengeFn   = opts.challengeFn || null;
  var escalationFn  = opts.escalationFn || null;
  var keyExtractor  = opts.keyExtractor || _defaultKeyExtractor;
  var auditInst     = opts.audit || null;
  var obsInst       = opts.observability || null;
  var clock         = opts.clock || Date.now;

  function _emitObs(name, labels) {
    var sink = obsInst || _safeGlobalObs();
    if (!sink) return;
    try { sink.event(name, 1, labels); } catch (_e) { /* drop-silent */ }
  }

  function _safeGlobalObs() {
    try { return observability(); } catch (_e) { return null; }
  }

  function _emitAudit(action, key, outcome, metadata, req) {
    if (!auditInst) return;
    try {
      var event = {
        action:   action,
        outcome:  outcome,
        resource: { kind: "auth.bot_challenge", id: key },
        metadata: metadata || {},
      };
      if (req) event.actor = requestHelpers.extractActorContext(req);
      auditInst.safeEmit(event);
    } catch (_e) { /* audit best-effort */ }
  }

  async function _readState(key) {
    try {
      var raw = await sessionStore.get(key);
      return raw || null;
    } catch (_e) { return null; }
  }

  async function _writeState(key, state, ttlMs) {
    try { await sessionStore.set(key, state, { ttlMs: ttlMs }); }
    catch (_e) { /* drop-silent: store transient */ }
  }

  async function _deleteState(key) {
    try { await sessionStore.del(key); }
    catch (_e) { /* drop-silent */ }
  }

  // Run the bot-guard middleware in a captured-response harness — bot-
  // guard is a (req, res, next) middleware shape. The challenge gate
  // does NOT block here; it only inspects whether bot-guard's
  // heuristics flagged the request.
  function _runBotGuardCheck(req) {
    return new Promise(function (resolve) {
      var capturedRes = {
        statusCode: 200, // allow:raw-byte-literal — HTTP 200 status code, not bytes
        writableEnded: false,
        writeHead: function (status) { capturedRes.statusCode = status; },
        end: function () { capturedRes.writableEnded = true; },
      };
      var settled = false;
      function done(passed, reason) {
        if (settled) return;
        settled = true;
        resolve({ passed: passed, reason: reason || null });
      }
      try {
        botGuard(req, capturedRes, function () {
          // If bot-guard tagged the request, surface that. The default
          // botGuard mode is "block"; in tag mode req.suspectedBot
          // gets set. Either way: flagged = challenge required.
          if (req.suspectedBot) return done(false, req.suspectedBot);
          return done(true, null);
        });
        // If middleware terminated by writing a response, treat as flagged.
        if (capturedRes.writableEnded) {
          done(false, "bot-guard-blocked");
          return;
        }
      } catch (_e) {
        done(false, "bot-guard-exception");
        return;
      }
    });
  }

  // ---- Internal staircase advance ----

  async function _advanceFailure(key, req) {
    var now = clock();
    var state = await _readState(key) || {
      stage: STATE_NEW, failures: 0, challengedAt: null, passedAt: null,
    };
    state.failures = (state.failures || 0) + 1;

    // Lockout subscriber — propagate the failure into the lockout
    // primitive so cluster-shared counters stay accurate.
    try { await lockout.recordFailure(key, { req: req, reason: "auth-bot-challenge" }); }
    catch (_e) { /* lockout best-effort */ }

    if (state.failures >= escalationThreshold) {
      state.stage = STATE_LOCKED;
      await _writeState(key, state, challengeTtlMs);
      _emitObs("auth.bot_challenge.escalated", { stage: STATE_LOCKED });
      _emitAudit("auth.bot_challenge.escalated", key, "denied",
        { failures: state.failures, threshold: escalationThreshold }, req);
      if (escalationFn) {
        try { await escalationFn(req); }
        catch (_e) { /* escalation best-effort */ }
      }
      return { stage: STATE_LOCKED, failures: state.failures };
    }
    if (state.failures >= threshold) {
      state.stage = STATE_CHALLENGED;
      state.challengedAt = now;
      await _writeState(key, state, challengeTtlMs);
      _emitObs("auth.bot_challenge.required", { stage: STATE_CHALLENGED });
      _emitAudit("auth.bot_challenge.required", key, "denied",
        { failures: state.failures, threshold: threshold }, req);
      return { stage: STATE_CHALLENGED, failures: state.failures };
    }
    await _writeState(key, state, challengeTtlMs);
    return { stage: STATE_NEW, failures: state.failures };
  }

  // ---- Public surface ----

  function middleware() {
    return async function authBotChallengeMiddleware(req, res, next) {
      var key;
      try { key = keyExtractor(req); }
      catch (_e) { key = "<unknown>"; }
      if (typeof key !== "string" || key.length === 0) key = "<unknown>";

      var state = await _readState(key);

      if (state && state.stage === STATE_LOCKED) {
        _emitAudit("auth.bot_challenge.escalated", key, "denied",
          { reason: "already-locked" }, req);
        return _writeLocked(res);
      }

      if (state && state.stage === STATE_CHALLENGED) {
        // Run bot-guard heuristics first — fastest path. If those don't
        // pass, defer to the operator-supplied challengeFn.
        var bgVerdict = await _runBotGuardCheck(req);
        if (bgVerdict.passed) {
          state.stage = STATE_PASSED;
          state.passedAt = clock();
          await _writeState(key, state, challengeTtlMs);
          _emitObs("auth.bot_challenge.passed", { stage: "bot-guard" });
          _emitAudit("auth.bot_challenge.passed", key, "success",
            { stage: "bot-guard" }, req);
          return next();
        }
        if (challengeFn) {
          var challengeResult;
          try { challengeResult = await challengeFn(req, res); }
          catch (e) {
            _emitAudit("auth.bot_challenge.failed", key, "denied",
              { stage: "challenge-fn", error: e && e.message }, req);
            // Challenge-fn threw — treat as a failure; advance the ladder.
            await _advanceFailure(key, req);
            return _writeLocked(res);
          }
          // The challengeFn may have responded itself (e.g. rendered a
          // captcha page on GET). Detect that.
          if (res && res.writableEnded) return;
          if (challengeResult === true) {
            state.stage = STATE_PASSED;
            state.passedAt = clock();
            await _writeState(key, state, challengeTtlMs);
            _emitObs("auth.bot_challenge.passed", { stage: "challenge-fn" });
            _emitAudit("auth.bot_challenge.passed", key, "success",
              { stage: "challenge-fn" }, req);
            return next();
          }
          _emitObs("auth.bot_challenge.failed", { stage: "challenge-fn" });
          _emitAudit("auth.bot_challenge.failed", key, "denied",
            { stage: "challenge-fn" }, req);
          await _advanceFailure(key, req);
          return _writeChallengeRequired(res);
        }
        // No challengeFn supplied and bot-guard failed → 401.
        _emitObs("auth.bot_challenge.failed", { stage: "bot-guard-only" });
        _emitAudit("auth.bot_challenge.failed", key, "denied",
          { stage: "bot-guard-only", reason: bgVerdict.reason }, req);
        return _writeChallengeRequired(res);
      }

      // STATE_NEW or STATE_PASSED — flow through. Whether the wrapped
      // handler counts the attempt as a failure is the operator's
      // responsibility (they call gate.recordFailure(key) post-verify).
      return next();
    };
  }

  function _writeChallengeRequired(res) {
    if (!res || res.writableEnded) return;
    if (typeof res.writeHead === "function") {
      res.writeHead(401, {
        "Content-Type": "text/plain",
        "WWW-Authenticate": 'Bearer error="bot_challenge_required"',
      });
    } else if (typeof res.statusCode !== "undefined") {
      res.statusCode = 401;
    }
    if (typeof res.end === "function") res.end("Bot challenge required");
  }

  function _writeLocked(res) {
    if (!res || res.writableEnded) return;
    if (typeof res.writeHead === "function") {
      res.writeHead(423, { "Content-Type": "text/plain" });
    } else if (typeof res.statusCode !== "undefined") {
      res.statusCode = 423;
    }
    if (typeof res.end === "function") res.end("Locked");
  }

  async function recordFailure(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    return await _advanceFailure(key, callOpts.req || null);
  }

  async function recordSuccess(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var state = await _readState(key);
    if (state) await _deleteState(key);
    try { await lockout.recordSuccess(key, { req: callOpts.req }); }
    catch (_e) { /* best-effort */ }
    _emitObs("auth.bot_challenge.cleared", {});
    _emitAudit("auth.bot_challenge.passed", key, "success",
      { stage: "auth-success", failuresCleared: (state && state.failures) || 0 },
      callOpts.req);
  }

  async function check(key) {
    _requireKey(key);
    var state = await _readState(key);
    if (!state) return { stage: STATE_NEW, failures: 0 };
    return {
      stage:    state.stage,
      failures: state.failures || 0,
    };
  }

  async function reset(key, callOpts) {
    _requireKey(key);
    callOpts = callOpts || {};
    var state = await _readState(key);
    if (state) await _deleteState(key);
    try { await lockout.unlock(key, { req: callOpts.req, reason: "bot-challenge:reset" }); }
    catch (_e) { /* best-effort */ }
    _emitAudit("auth.bot_challenge.passed", key, "success",
      { stage: "admin-reset", reason: callOpts.reason || null,
        priorStage: state && state.stage || null,
        priorFailures: state && state.failures || 0 },
      callOpts.req);
    return !!state;
  }

  return {
    middleware:    middleware,
    recordFailure: recordFailure,
    recordSuccess: recordSuccess,
    check:         check,
    reset:         reset,
  };
}

module.exports = {
  create:  create,
  AuthBotChallengeError: AuthBotChallengeError,
  STATES:  Object.freeze({
    NEW:        STATE_NEW,
    CHALLENGED: STATE_CHALLENGED,
    PASSED:     STATE_PASSED,
    LOCKED:     STATE_LOCKED,
  }),
  DEFAULTS: Object.freeze({
    threshold:           DEFAULT_THRESHOLD,
    escalationThreshold: DEFAULT_ESCALATION_THRESHOLD,
    challengeTtlMs:      DEFAULT_CHALLENGE_TTL_MS,
  }),
};

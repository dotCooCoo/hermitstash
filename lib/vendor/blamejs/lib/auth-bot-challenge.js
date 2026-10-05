// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var numericBounds = require("./numeric-bounds");
var safeAsync = require("./safe-async");
var { AuthBotChallengeError } = require("./framework-error");

/**
 * @primitive b.authBotChallenge.AuthBotChallengeError
 * @signature b.authBotChallenge.AuthBotChallengeError
 * @since     0.8.44
 * @status    stable
 * @related   b.authBotChallenge.create
 *
 * The error class this namespace throws. It extends `FrameworkError` and
 * carries a stable `.code`: `auth-bot-challenge/bad-opt` for an option the
 * staircase cannot be built from, and `auth-bot-challenge/bad-key` for a
 * key that does not identify a caller.
 *
 * Every one is marked `.permanent = true`, because each reports a
 * configuration the process was started with. Retrying it would call the
 * same constructor with the same arguments, so a retry layer treats it as
 * final rather than looping.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   try {
 *     b.authBotChallenge.create({ threshold: -1 });
 *   } catch (e) {
 *     e instanceof b.authBotChallenge.AuthBotChallengeError;   // → true
 *     e.permanent;                                             // → true
 *   }
 */

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
  "trustedProxies", "forwardedHeaders", "clientIpResolver",
];

function _requireFunction(name, val) {
  if (typeof val !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      name + ": expected function, got " + typeof val);
  }
}

function _requirePositiveInt(name, val) {
  if (!numericBounds.isPositiveFiniteInt(val)) {
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
  validateOpts.requireMethods(store, ["get", "set", "del"],
    "sessionStore (b.cache-shaped)", AuthBotChallengeError, "auth-bot-challenge/bad-opt");
}

function _requireBotGuard(bg) {
  if (typeof bg !== "function") {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "botGuard must be a connect-style middleware function (got " + typeof bg + ")");
  }
}

function _requireLockout(lk) {
  validateOpts.requireMethods(lk, ["recordFailure", "recordSuccess", "check"],
    "lockout (b.auth.lockout-shaped instance)", AuthBotChallengeError, "auth-bot-challenge/bad-opt");
}

function _namedCarrier(carried, opts) {
  if (carried === null || carried === undefined) return null;
  var named = null;
  try { named = requestHelpers.actorIdentityKey(carried, opts); }
  catch (_e) { named = null; }
  if (typeof named === "string" && named !== requestHelpers.ANONYMOUS_ACTOR_KEY) {
    return named;
  }
  return null;
}

function _ownerIdOf(actor) { return _readProperty(actor, "ownerId"); }

function _readProperty(obj, name) {
  if (obj === null || obj === undefined) return undefined;
  try { return obj[name]; }
  catch (_e) { return undefined; }
}

function _defaultKeyExtractor(req, ipResolver) {
  if (req && req.body && typeof req.body === "object") {
    if (typeof req.body.email === "string" && req.body.email.length > 0) {
      return "body:email:" + req.body.email.toLowerCase();
    }
    if (typeof req.body.username === "string" && req.body.username.length > 0) {
      return "body:username:" + req.body.username.toLowerCase();
    }
  }
  var carriedUser = _readProperty(req, "user");
  if (carriedUser === null || carriedUser === undefined) {
    carriedUser = _readProperty(req, "actor");
  }
  var fromUser = _namedCarrier(carriedUser, null);
  if (fromUser !== null) return "actor:" + fromUser;
  var keyCarrier = _readProperty(req, "apiKey");
  if (keyCarrier !== null && typeof keyCarrier === "object") {
    var fromKey = _namedCarrier(keyCarrier, null);
    if (fromKey !== null) return "apikey:" + fromKey;
    var fromOwner = _namedCarrier(keyCarrier, { actorKey: _ownerIdOf });
    if (fromOwner !== null) return "apikey-owner:" + fromOwner;
  }
  var addr = null;
  try { addr = ipResolver(req); }
  catch (_e) { addr = null; }
  return "addr:" + (typeof addr === "string" && addr.length > 0 ? addr : "<unknown>");
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
 * One ladder counts one caller, so the key names the caller as precisely as
 * the request allows: the credential in the body as `body:<field>:<value>`,
 * naming the field as well as the value because a username that reads like
 * someone's address is not that person, then the
 * authenticated user on `req.user` or `req.actor` as `actor:<key>`, then the API
 * key on `req.apiKey` as `apikey:<key>`, then the client address as
 * `addr:<ip>`. Every rung carries its own namespace, including the address,
 * because the resolved address is partly chosen by the caller: a request from
 * inside a declared proxy range picks which forwarded hop is read, and an
 * operator `clientIpResolver` owns resolution entirely. So a value one rung
 * reads can never spell another rung's key, and a user and an API key holding
 * the same id are two callers. A
 * route that carries no credential in
 * its body, such as a token refresh or a step-up confirmation, is therefore
 * counted per principal rather than per address, where an address is shared by
 * everyone behind one NAT or one proxy and a single caller reaching the
 * escalation threshold would lock out the rest.
 *
 * The CREDENTIAL carrier names a principal only when it is an object: a raw key
 * string such as `req.apiKey = req.headers["x-api-key"]` is the secret itself,
 * and this value is written to the session store and to audit rows. Such a
 * request is counted per address. `req.user` and `req.actor` are not credentials
 * and may be a string or a number, which the resolver names as before.
 *
 * A carrier that is present but names no principal is counted per address, and
 * a `tenantId` the resolver cannot name makes the whole carrier unnameable. That
 * is deliberate: naming such a carrier by its `id` alone would let one tenant's
 * ladder count another tenant's caller, which is worse than sharing the address. An API-key record is named by its `id`, or by its
 * `ownerId` under `apikey-owner:<key>` when it carries none, which is the shape
 * `b.middleware.requireBoundKey` stores for a resolver that returns no id. The
 * owner form keeps the record's `tenantId` binding, so one owner in two tenants
 * is two callers and a key whose `id` is another key's `ownerId` is a third.
 *
 * `middleware()` writes the key it counted on to `req.botChallengeKey`, and
 * `recordFailure(req.botChallengeKey)` is how the post-verify path advances
 * that same ladder rather than a second one derived by hand.
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
 *   keyExtractor:        Function,   // (req) → string naming the ladder. Default: body.email, then body.username, then the authenticated principal through b.requestHelpers.actorIdentityKey, then the client address
 *   trustedProxies:      string[],   // CIDRs whose forwarded headers name the client address; without one the socket address is used and a forwarded header is ignored
 *   forwardedHeaders:    string[],   // named forwarded headers to read, alongside trustedProxies
 *   clientIpResolver:    Function,   // (req) → the client address
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
 *   // After verifying the credential, advance the ladder the middleware
 *   // counted on. Pass req.botChallengeKey rather than rebuilding it: on the
 *   // login route above it reads "body:user@example.com".
 *   var advanced = await gate.recordFailure(req.botChallengeKey);
 *   advanced.stage;          // → "new" | "challenged" | "locked"
 *
 *   var status = await gate.check(req.botChallengeKey);
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
  var _ipResolver;
  try {
    _ipResolver = requestHelpers.trustedClientIp({
      trustedProxies:   opts.trustedProxies,
      forwardedHeaders: opts.forwardedHeaders,
      clientIpResolver: opts.clientIpResolver,
    });
  } catch (e) {
    throw new AuthBotChallengeError("auth-bot-challenge/bad-opt",
      "authBotChallenge.create: " + ((e && e.message) || String(e)));
  }
  var keyExtractor  = opts.keyExtractor ||
    function (req) { return _defaultKeyExtractor(req, _ipResolver.resolve); };
  var auditInst     = opts.audit || null;
  var obsInst       = opts.observability || null;
  var clock         = opts.clock || Date.now;

  var _emitObs = observability().makeCounterEmitter(obsInst);

  var _emitAudit = requestHelpers.makeResourceAuditEmitter(auditInst, "auth.bot_challenge");

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

  function _runBotGuardCheck(req) {
    return new Promise(function (resolve) {
      var capturedRes = {
        statusCode: C.HTTP.STATUS.OK,
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
          if (req.suspectedBot) return done(false, req.suspectedBot);
          return done(true, null);
        });
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

  var _advanceSerializer = safeAsync.keyedSerializer();
  function _advanceFailure(key, req) {
    return _advanceSerializer.run(key, function () { return _doAdvanceFailure(key, req); });
  }

  async function _doAdvanceFailure(key, req) {
    var now = clock();
    var state = await _readState(key) || {
      stage: STATE_NEW, failures: 0, challengedAt: null, passedAt: null,
    };
    state.failures = (state.failures || 0) + 1;

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

  function middleware() {
    return async function authBotChallengeMiddleware(req, res, next) {
      var key;
      try { key = keyExtractor(req); }
      catch (_e) { key = "<unknown>"; }
      if (typeof key !== "string" || key.length === 0) key = "<unknown>";
      if (req && typeof req === "object") {
        try { req.botChallengeKey = key; }
        catch (_e) { /* frozen request object */ }
      }

      var state = await _readState(key);

      if (state && state.stage === STATE_LOCKED) {
        _emitAudit("auth.bot_challenge.escalated", key, "denied",
          { reason: "already-locked" }, req);
        return _writeLocked(res);
      }

      if (state && state.stage === STATE_CHALLENGED) {
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
            await _advanceFailure(key, req);
            return _writeLocked(res);
          }
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
        _emitObs("auth.bot_challenge.failed", { stage: "bot-guard-only" });
        _emitAudit("auth.bot_challenge.failed", key, "denied",
          { stage: "bot-guard-only", reason: bgVerdict.reason }, req);
        return _writeChallengeRequired(res);
      }

      return next();
    };
  }

  function _writeChallengeRequired(res) {
    if (!res || res.writableEnded) return;
    if (typeof res.writeHead === "function") {
      res.writeHead(C.HTTP.STATUS.UNAUTHORIZED, {
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
      res.writeHead(C.HTTP.STATUS.LOCKED, { "Content-Type": "text/plain" });
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

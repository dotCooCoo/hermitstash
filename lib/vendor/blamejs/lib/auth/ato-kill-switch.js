"use strict";
/**
 * b.auth.atoKillSwitch — composite primitive for account-takeover
 * incident response. Composes `b.session.destroyAllForUser` +
 * `b.auth.lockout.lock` + (optionally) `b.auth.accessLock` mode flip
 * into a single operator-callable workflow.
 *
 * Trigger conditions are operator territory (SOC alert, fraud signal,
 * user self-report, IDS rule); this primitive is the deterministic
 * cleanup path once the trigger fires:
 *
 *   1. destroy every session for the user across the cluster
 *   2. lock the user out of new logins (b.auth.lockout)
 *   3. emit an audit row with reason / actor for downstream forensics
 *
 *   await b.auth.atoKillSwitch.trigger({
 *     userId:    "u_42",
 *     reason:    "fraud-signal: 14 failed MFA from new geo",
 *     actor:     { id: req.user && req.user.id, role: req.user && req.user.role },
 *     lockout:   true,                  // default true
 *     accessLock: "locked",             // optional — flip the global access-lock mode
 *   });
 *
 * Returns `{ sessionsDestroyed, lockoutApplied, accessLockMode }`.
 */

var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var session = lazyRequire(function () { return require("../session"); });
var lockout = lazyRequire(function () { return require("./lockout"); });
var accessLock = lazyRequire(function () { return require("./access-lock"); });
var audit = lazyRequire(function () { return require("../audit"); });

var AtoKillSwitchError = defineClass("AtoKillSwitchError", { alwaysPermanent: true });

async function trigger(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "userId", "reason", "actor", "lockout", "accessLock",
  ], "auth.atoKillSwitch.trigger");

  validateOpts.requireNonEmptyString(opts.userId, "userId", AtoKillSwitchError, "auth-ato-kill-switch/missing-user-id");
  validateOpts.requireNonEmptyString(opts.reason, "reason", AtoKillSwitchError, "auth-ato-kill-switch/missing-reason");
  var doLockout       = opts.lockout !== false;
  var accessLockMode  = typeof opts.accessLock === "string" ? opts.accessLock : null;

  var sessionsDestroyed = 0;
  try {
    sessionsDestroyed = await session().destroyAllForUser(opts.userId);
  } catch (e) {
    audit().safeEmit({
      action: "auth.ato_kill_switch.partial",
      outcome: "failure",
      metadata: {
        userId: opts.userId,
        step:   "destroy-sessions",
        reason: e && e.message,
      },
    });
    throw e;
  }

  var lockoutApplied = false;
  if (doLockout) {
    try {
      await lockout().lock(opts.userId, {
        reason: "ato-kill-switch:" + opts.reason,
      });
      lockoutApplied = true;
    } catch (_e) { /* lockout is best-effort; sessions already destroyed */ }
  }

  var modeApplied = null;
  if (accessLockMode !== null) {
    try {
      var lock = accessLock();
      if (lock && typeof lock.set === "function") {
        await lock.set(accessLockMode, {
          actor:  opts.actor || null,
          reason: "ato-kill-switch:" + opts.reason,
        });
        modeApplied = accessLockMode;
      }
    } catch (_e) { /* operator may not have wired global accessLock; fine */ }
  }

  audit().safeEmit({
    action: "auth.ato_kill_switch.triggered",
    outcome: "success",
    metadata: {
      userId:             opts.userId,
      reason:             opts.reason,
      actor:              opts.actor || null,
      sessionsDestroyed:  sessionsDestroyed,
      lockoutApplied:     lockoutApplied,
      accessLockMode:     modeApplied,
    },
  });

  return {
    sessionsDestroyed: sessionsDestroyed,
    lockoutApplied:    lockoutApplied,
    accessLockMode:    modeApplied,
  };
}

module.exports = {
  trigger:              trigger,
  AtoKillSwitchError:   AtoKillSwitchError,
};

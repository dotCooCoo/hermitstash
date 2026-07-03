// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   2. lock the user out of new logins via the supplied lockout instance
 *   3. emit an audit row with reason / actor for downstream forensics
 *
 *   await b.auth.atoKillSwitch.trigger({
 *     userId:    "u_42",
 *     reason:    "fraud-signal: 14 failed MFA from new geo",
 *     actor:     { id: req.user && req.user.id, role: req.user && req.user.role },
 *     lockout:   appLockout,            // a b.auth.lockout instance (or false to skip)
 *     accessLock: "locked",             // optional — flip the global access-lock mode
 *   });
 *
 * The lockout step needs the operator's configured b.auth.lockout instance
 * (there is no module-level lockout store); pass it as `opts.lockout`. When it
 * is omitted, the lockout step is skipped and the returned `lockoutApplied` is
 * false (with an audit row) — the account is NOT locked.
 *
 * Returns `{ sessionsDestroyed, lockoutApplied, accessLockMode }`.
 */

var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var session = lazyRequire(function () { return require("../session"); });
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
  // opts.lockout is the operator's configured b.auth.lockout INSTANCE to lock
  // the account in (or false to skip the lockout step). The kill-switch needs
  // that instance's store to engage the lock — there is no module-level lockout
  // singleton — so without an instance the lockout step cannot run and is
  // reported (rather than silently claiming success while never locking).
  var skipLockout    = opts.lockout === false;
  var lockoutInst    = (opts.lockout && typeof opts.lockout === "object" &&
                        typeof opts.lockout.lock === "function") ? opts.lockout : null;
  var accessLockMode = typeof opts.accessLock === "string" ? opts.accessLock : null;

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
  if (!skipLockout) {
    if (lockoutInst) {
      try {
        await lockoutInst.lock(opts.userId, {
          reason: "ato-kill-switch:" + opts.reason,
        });
        lockoutApplied = true;
      } catch (e) {
        // The lockout step failed (e.g. a cache outage) AFTER sessions were
        // destroyed. Don't fail the whole kill-switch — but surface it so the
        // operator knows the account was NOT locked, rather than swallowing.
        audit().safeEmit({
          action: "auth.ato_kill_switch.partial",
          outcome: "failure",
          metadata: { userId: opts.userId, step: "lockout", reason: e && e.message },
        });
      }
    } else {
      // No lockout instance supplied: the kill-switch cannot lock the account.
      // Report it (the result's lockoutApplied stays false) so the operator
      // doesn't believe the user was locked out of new logins.
      audit().safeEmit({
        action: "auth.ato_kill_switch.partial",
        outcome: "failure",
        metadata: {
          userId: opts.userId,
          step:   "lockout",
          reason: "no lockout instance supplied (pass opts.lockout = b.auth.lockout.create({ cache, namespace }))",
        },
      });
    }
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

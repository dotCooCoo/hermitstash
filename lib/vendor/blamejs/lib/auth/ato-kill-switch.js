// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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
        audit().safeEmit({
          action: "auth.ato_kill_switch.partial",
          outcome: "failure",
          metadata: { userId: opts.userId, step: "lockout", reason: e && e.message },
        });
      }
    } else {
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

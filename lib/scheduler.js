"use strict";
/**
 * App-wide scheduler instance.
 *
 * blamejs's `b.scheduler.create()` returns a fresh instance per call —
 * fine for libraries that scope their own jobs but wrong for HermitStash
 * which has multi-file consumers (server-main.js registers ~15 cleanup
 * jobs at boot; routes/admin.js calls getStatus() to render the admin
 * Tasks tab). Both need to reference the SAME instance, otherwise
 * getStatus() returns an empty array and the admin UI shows "no
 * scheduled jobs" while server-main's jobs run unobserved.
 *
 * This module instantiates the singleton once at first require (Node's
 * module cache holds the instance for the rest of the process). Every
 * importer gets the same object.
 *
 * Surface preserved (every existing call site keeps working):
 *   register(name, intervalMs, fn)
 *   start()
 *   getStatus()
 *
 * `getStatus()` is wrapped here to add a numeric `interval` field on
 * each task — blamejs reports the schedule as `when: "every 60000ms"`
 * (string), but HS's admin Tasks tab + sync-client tests expect a
 * numeric `interval`. The wrapper parses the `every Nms` form back
 * into a number and leaves cron-style `when` strings untouched
 * (HS doesn't register cron tasks today; if that changes, callers
 * should use `when` instead of `interval`).
 */
var instance = require("./vendor/blamejs").scheduler.create();

var _origGetStatus = instance.getStatus.bind(instance);
instance.getStatus = function () {
  var status = _origGetStatus();
  if (status && Array.isArray(status.tasks)) {
    status.tasks = status.tasks.map(function (t) {
      var interval = null;
      if (typeof t.when === "string") {
        var match = t.when.match(/^every\s+(\d+)ms$/);
        if (match) interval = parseInt(match[1], 10);
      }
      return Object.assign({}, t, { interval: interval });
    });
  }
  return status;
};

module.exports = instance;

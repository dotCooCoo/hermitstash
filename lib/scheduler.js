/**
 * Simple task scheduler for periodic cleanup operations.
 * Supports both sync and async job functions.
 * Includes a watchdog timeout to prevent hung jobs from permanently locking.
 */

var logger = require("../app/shared/logger");
var MAX_JOB_MS = 10 * 60 * 1000; // 10 minutes max per job

var tasks = [];
var timers = [];

function register(name, intervalMs, fn, opts) {
  tasks.push({ name: name, interval: intervalMs, fn: fn, lastRun: null, nextRun: Date.now() + intervalMs, running: false, skipInitial: opts && opts.skipInitial });
}

function start() {
  for (var i = 0; i < tasks.length; i++) {
    (function(task) {
      var run = function() {
        if (task.running) return; // skip if previous run still in progress
        task.running = true;
        task.lastRun = new Date().toISOString();
        task.nextRun = Date.now() + task.interval;

        // Watchdog: force-reset running flag if job hangs
        var watchdog = setTimeout(function () {
          if (task.running) {
            logger.warn("[scheduler] " + task.name + " exceeded " + (MAX_JOB_MS / 1000) + "s max run time — forcing reset");
            task.running = false;
          }
        }, MAX_JOB_MS);
        watchdog.unref();

        function done() {
          clearTimeout(watchdog);
          task.running = false;
        }

        try {
          var result = task.fn();
          if (result && typeof result.then === "function") {
            result
              .catch(function(e) { logger.error("[scheduler] " + task.name + " failed", { error: e.message }); })
              .then(done);
          } else {
            done();
          }
        } catch(e) {
          logger.error("[scheduler] " + task.name + " failed", { error: e.message });
          done();
        }
      };
      // Run once after 10s (unless skipInitial), then on interval
      if (!task.skipInitial) setTimeout(run, 10000);
      var timer = setInterval(run, task.interval);
      timer.unref();
      timers.push(timer);
    })(tasks[i]);
  }
}

function getStatus() {
  return tasks.map(function(t) {
    return { name: t.name, interval: t.interval, lastRun: t.lastRun, nextRun: t.nextRun ? new Date(t.nextRun).toISOString() : null, running: t.running };
  });
}

module.exports = { register: register, start: start, getStatus: getStatus };

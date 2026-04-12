/**
 * Simple task scheduler for periodic cleanup operations.
 * Supports both sync and async job functions.
 */

var tasks = [];
var timers = [];

function register(name, intervalMs, fn) {
  tasks.push({ name: name, interval: intervalMs, fn: fn, lastRun: null, nextRun: Date.now() + intervalMs, running: false });
}

function start() {
  for (var i = 0; i < tasks.length; i++) {
    (function(task) {
      var run = function() {
        if (task.running) return; // skip if previous run still in progress
        task.running = true;
        task.lastRun = new Date().toISOString();
        task.nextRun = Date.now() + task.interval;
        try {
          var result = task.fn();
          if (result && typeof result.then === "function") {
            result
              .catch(function(e) { console.error("[scheduler]", task.name, e.message); })
              .then(function() { task.running = false; });
          } else {
            task.running = false;
          }
        } catch(e) {
          console.error("[scheduler]", task.name, e.message);
          task.running = false;
        }
      };
      // Run once after 10s, then on interval
      setTimeout(run, 10000);
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

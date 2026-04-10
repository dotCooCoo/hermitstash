/**
 * Simple task scheduler for periodic cleanup operations.
 */

var tasks = [];
var timers = [];

function register(name, intervalMs, fn) {
  tasks.push({ name: name, interval: intervalMs, fn: fn, lastRun: null, nextRun: Date.now() + intervalMs });
}

function start() {
  for (var i = 0; i < tasks.length; i++) {
    (function(task) {
      var run = function() {
        task.lastRun = new Date().toISOString();
        task.nextRun = Date.now() + task.interval;
        try { task.fn(); } catch(e) { console.error("[scheduler]", task.name, e.message); }
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
    return { name: t.name, interval: t.interval, lastRun: t.lastRun, nextRun: t.nextRun ? new Date(t.nextRun).toISOString() : null };
  });
}

module.exports = { register: register, start: start, getStatus: getStatus };

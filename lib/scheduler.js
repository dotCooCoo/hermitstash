/**
 * Simple task scheduler for periodic cleanup operations.
 * Supports both sync and async job functions.
 * Includes a watchdog timeout to prevent hung jobs from permanently locking.
 */

var logger = require("../app/shared/logger");
var MAX_JOB_MS = 10 * 60 * 1000; // 10 minutes max per job

var tasks = [];
var timers = [];

/**
 * Compute the next wall-clock occurrence of HH:MM in a given IANA timezone.
 * Uses Intl.DateTimeFormat to get the current time in the target zone, then
 * walks minute-arithmetic forward to the target. Falls back to local server
 * time if the timezone is empty or invalid.
 *
 * Caveat: minute-based forward walk handles DST gaps/overlaps approximately —
 * during the spring-forward hour (e.g. 02:00→03:00 in US DST) a 02:30 baseline
 * doesn't exist that day; the next run lands on the equivalent UTC instant
 * which surfaces as 03:30 wall-clock. For backups this is acceptable; if
 * exact-time-every-day matters, pick a baseline outside DST transition hours.
 */
function nextWallClockTime(timeOfDay, timeZone) {
  var match = String(timeOfDay).match(/^(\d{1,2}):(\d{2})$/);
  if (!match) return null;
  var hh = parseInt(match[1], 10);
  var mm = parseInt(match[2], 10);
  if (hh < 0 || hh > 23 || mm < 0 || mm > 59) return null;

  var now = new Date();
  var tz = null;
  if (timeZone) {
    try {
      // Validate by attempting to format — throws on invalid IANA names
      new Intl.DateTimeFormat("en-US", { timeZone: timeZone }).format(now);
      tz = timeZone;
    } catch (_e) {
      tz = null; // invalid name — fall through to server-local
    }
  }

  if (!tz) {
    // Server-local time path
    var nextLocal = new Date(now);
    nextLocal.setHours(hh, mm, 0, 0);
    if (nextLocal <= now) nextLocal.setDate(nextLocal.getDate() + 1);
    return nextLocal.getTime();
  }

  // TZ-aware path: read current hour/minute in target zone, compute minutes
  // until target HH:MM.
  var parts = {};
  new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    hour: "2-digit", minute: "2-digit", hour12: false,
  }).formatToParts(now).forEach(function (p) {
    if (p.type === "hour" || p.type === "minute") parts[p.type] = p.value;
  });
  var curH = parseInt(parts.hour, 10);
  var curM = parseInt(parts.minute, 10);
  // Treat "24" as midnight (some locales emit "24:00" instead of "00:00")
  if (curH === 24) curH = 0;
  var minsUntil = (hh - curH) * 60 + (mm - curM);
  if (minsUntil <= 0) minsUntil += 24 * 60;
  return now.getTime() + minsUntil * 60 * 1000;
}

function register(name, intervalMs, fn, opts) {
  var task = { name: name, interval: intervalMs, fn: fn, lastRun: null, running: false, skipInitial: opts && opts.skipInitial };

  // baseline: HH:MM (24-hour). When set with optional timezone, the first run
  // fires at the next occurrence of that wall-clock time in the target zone,
  // then every `intervalMs` after. This anchors daily/weekly jobs to a stable
  // clock time so restarts don't drift the schedule. Falls back to
  // "now + interval" if baseline is invalid or absent.
  if (opts && opts.baseline) {
    var t = nextWallClockTime(opts.baseline, opts.timezone);
    if (t) {
      task.nextRun = t;
      task.baseline = opts.baseline;
      task.timezone = opts.timezone || null;
    }
  }
  if (!task.nextRun) task.nextRun = Date.now() + intervalMs;

  tasks.push(task);
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

      // If task has a baseline, wait until the next baseline time for the first
      // run, then start the interval timer from there. Otherwise fall back to
      // the legacy 10s-warmup-then-interval pattern.
      if (task.baseline) {
        var delay = Math.max(0, task.nextRun - Date.now());
        var timer = setTimeout(function () {
          run();
          var iv = setInterval(run, task.interval);
          iv.unref();
          timers.push(iv);
        }, delay);
        timer.unref();
        timers.push(timer);
        return;
      }

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

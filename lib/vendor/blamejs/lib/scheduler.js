"use strict";
/**
 * scheduler — cron + interval scheduler over lib/jobs (or direct fn).
 *
 * The framework's primitive for "run X at Y" — backed by jobs/queue
 * for retries, audit, and cluster-aware dispatch, with a direct-fn
 * escape hatch for the simple cases.
 *
 *   var sched = b.scheduler.create({
 *     jobs:    jobsInstance,    // optional; needed for { job: "name" }
 *     cluster: b.cluster,       // optional; gates fires to leader only
 *     audit:   true,            // default true
 *   });
 *
 *   sched.schedule({
 *     name:     "nightly-cleanup",
 *     cron:     "0 2 * * *",        // POSIX 5-field cron
 *     timezone: "America/New_York", // IANA name; default = server-local
 *     job:      "cleanup",          // dispatched via jobs.enqueue
 *     payload:  { scope: "all" },
 *   });
 *
 *   sched.schedule({
 *     name:     "stats-aggregation",
 *     every:    300000,             // ms between runs
 *     baseline: "00:00",            // HH:MM anchor (optional)
 *     timezone: "America/New_York",
 *     job:      "aggregate-stats",
 *   });
 *
 *   sched.schedule({
 *     name:  "heartbeat",
 *     every: 60000,
 *     run:   async function () { … },  // direct function (no jobs needed)
 *   });
 *
 *   await sched.start();   // arms timers
 *   await sched.stop();    // clears timers, drops pending fires
 *
 *   sched.list();          // → [{ name, when, lastRun, nextRun, running }]
 *
 * Cron grammar (5 fields, space-separated):
 *
 *   minute (0–59)  hour (0–23)  dom (1–31)  month (1–12)  dow (0–7; 0/7=Sun)
 *
 * Each field accepts:  *  N  N,M,…  A-B  *\/N  A-B/N
 *
 * Shorthands: @hourly @daily @midnight @weekly @monthly @yearly @annually
 *
 * Cluster gating: when opts.cluster is wired and the local node is not
 * the leader, schedule fires no-op. The leader still computes nextRun
 * locally so a leader transition picks up cleanly.
 *
 * Exactly-once-globally: when opts.cluster is wired, every fire first
 * INSERTs a row into _blamejs_scheduler_ticks keyed on (taskName,
 * scheduledAtUnix). The PRIMARY KEY race ensures that even if two
 * nodes briefly believe they are the leader (split-brain on lease
 * boundary), only the row-winner runs the task. The loser increments
 * task.tickClaimLost (visible via list()) and skips silently. Task
 * handlers should still be idempotent — operators may add jobs.enqueue
 * dedup keys for defense-in-depth.
 *
 * Tick-claim retention: rows older than opts.tickRetentionMs (default
 * 7 days) are pruned automatically — at most once per opts.pruneInterval
 * Ms (default 60s) — by the leader on its next successful fire. Operators
 * can also call sched.pruneTickClaims(olderThanMs?) on demand to force
 * a sweep (e.g. from a maintenance script) and observe the count via
 * the system.scheduler.tick.pruned audit event.
 *
 * Watchdog: if a fire's promise hasn't settled after MAX_JOB_MS
 * (10min default; opts.maxJobMs to override), the running flag is
 * force-cleared and a warning emitted, so a hung job doesn't lock out
 * future fires.
 */

var lazyRequire = require("./lazy-require");
var audit  = lazyRequire(function () { return require("./audit"); });
var log    = lazyRequire(function () { return require("./log").boot("scheduler"); });
var clusterStorage = require("./cluster-storage");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { SchedulerError } = require("./framework-error");

var DEFAULT_MAX_JOB_MS             = C.TIME.minutes(10);
var DEFAULT_TICK_RETENTION_MS      = C.TIME.days(7);
var DEFAULT_TICK_PRUNE_INTERVAL_MS = C.TIME.minutes(1);

// ---- Cron parsing ----

var CRON_SHORTHANDS = {
  "@yearly":   "0 0 1 1 *",
  "@annually": "0 0 1 1 *",
  "@monthly":  "0 0 1 * *",
  "@weekly":   "0 0 * * 0",
  "@daily":    "0 0 * * *",
  "@midnight": "0 0 * * *",
  "@hourly":   "0 * * * *",
};

var CRON_FIELD_RANGES = [
  { name: "minute", min: 0, max: 59 },
  { name: "hour",   min: 0, max: 23 },
  { name: "dom",    min: 1, max: 31 },
  { name: "month",  min: 1, max: 12 },
  { name: "dow",    min: 0, max: 7 }, // 0 and 7 both mean Sunday
];

function _parseCronField(text, range) {
  var parts = String(text).split(",");
  var set = new Set();
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i].trim();
    if (part.length === 0) {
      throw new SchedulerError("scheduler/invalid-cron",
        "empty term in cron field '" + range.name + "'", true);
    }
    var step = 1;
    var stepIdx = part.indexOf("/");
    if (stepIdx !== -1) {
      var stepStr = part.slice(stepIdx + 1);
      step = parseInt(stepStr, 10);
      if (!Number.isFinite(step) || step < 1) {
        throw new SchedulerError("scheduler/invalid-cron",
          "bad step '" + stepStr + "' in cron field '" + range.name + "'", true);
      }
      // Reject step > field-range, even though the for-loop below would
      // silently produce a single-value schedule (e.g. `*/99999` for
      // minutes degenerates to "minute 0 of every hour"). An operator
      // typing `*/99999` clearly meant something else; silent acceptance
      // hides the typo and produces a schedule that fires once per hour
      // when the operator probably wanted once per N minutes for small N.
      // The bound is `range.max - range.min + 1` so e.g. minutes (0-59)
      // accepts step up to 60 (inclusive — `*/60` is "minute 0 of every
      // hour" written with a redundant step).
      var rangeSize = range.max - range.min + 1;
      if (step > rangeSize) {
        throw new SchedulerError("scheduler/invalid-cron",
          "step '" + stepStr + "' exceeds field range (" + rangeSize +
          ") in cron field '" + range.name + "'", true);
      }
      part = part.slice(0, stepIdx);
    }
    var lo, hi;
    if (part === "*") {
      lo = range.min; hi = range.max;
    } else if (part.indexOf("-") !== -1) {
      var seg = part.split("-");
      if (seg.length !== 2) {
        throw new SchedulerError("scheduler/invalid-cron",
          "bad range '" + part + "' in cron field '" + range.name + "'", true);
      }
      lo = parseInt(seg[0], 10);
      hi = parseInt(seg[1], 10);
    } else {
      lo = parseInt(part, 10);
      hi = lo;
    }
    if (!Number.isFinite(lo) || !Number.isFinite(hi) || lo > hi ||
        lo < range.min || hi > range.max) {
      throw new SchedulerError("scheduler/invalid-cron",
        "value '" + part + "' out of range " + range.min + "-" + range.max +
        " in cron field '" + range.name + "'", true);
    }
    for (var v = lo; v <= hi; v += step) set.add(v);
  }
  // Normalize Sunday: dow 7 → 0 (so the matcher can use a single set)
  if (range.name === "dow" && set.has(7)) { set.add(0); set.delete(7); }
  return set;
}

function parseCron(expr) {
  if (typeof expr !== "string" || expr.length === 0) {
    throw new SchedulerError("scheduler/invalid-cron",
      "cron expression must be a non-empty string", true);
  }
  var trimmed = expr.trim();
  if (CRON_SHORTHANDS[trimmed.toLowerCase()]) {
    trimmed = CRON_SHORTHANDS[trimmed.toLowerCase()];
  }
  var fields = trimmed.split(/\s+/);
  if (fields.length !== 5) {
    throw new SchedulerError("scheduler/invalid-cron",
      "cron expression must have 5 fields (got " + fields.length + "): " + expr, true);
  }
  var sets = [];
  for (var i = 0; i < 5; i++) {
    sets.push(_parseCronField(fields[i], CRON_FIELD_RANGES[i]));
  }
  return {
    expr:   trimmed,
    minute: sets[0],
    hour:   sets[1],
    dom:    sets[2],
    month:  sets[3],
    dow:    sets[4],
    // Whether dom or dow was constrained — matters for the cron quirk
    // where day-of-month and day-of-week are OR'd when both are set.
    domRestricted: sets[2].size < (CRON_FIELD_RANGES[2].max - CRON_FIELD_RANGES[2].min + 1),
    dowRestricted: sets[4].size < 7,
  };
}

// ---- Timezone-aware wall-clock helpers ----
//
// We need "what's the wall clock in TZ for time T?" and "given wall
// clock W in TZ, what UTC instant does that correspond to?". Intl
// gives us the first cheaply. The second is approximated by walking
// minute-by-minute — accurate enough for cron schedules (DST gaps fire
// at the next valid wall-clock instant; overlaps fire once at the
// first matching instant).

function _getWallClockParts(date, timeZone) {
  if (!timeZone) {
    return {
      year:   date.getFullYear(),
      month:  date.getMonth() + 1,
      day:    date.getDate(),
      hour:   date.getHours(),
      minute: date.getMinutes(),
      dow:    date.getDay(),
    };
  }
  var fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: timeZone,
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", weekday: "short",
    hour12: false,
  });
  var parts = {};
  fmt.formatToParts(date).forEach(function (p) { parts[p.type] = p.value; });
  var dowMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  // Some locales emit "24:00" for midnight — normalize before parseInt so
  // the integer literal stays out of the source.
  var hr = (parts.hour === "24") ? 0 : parseInt(parts.hour, 10);
  return {
    year:   parseInt(parts.year, 10),
    month:  parseInt(parts.month, 10),
    day:    parseInt(parts.day, 10),
    hour:   hr,
    minute: parseInt(parts.minute, 10),
    dow:    dowMap[parts.weekday] || 0,
  };
}

function _validateTimezone(tz) {
  if (!tz) return null;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz }).format(new Date());
    return tz;
  } catch (_e) {
    throw new SchedulerError("scheduler/invalid-timezone",
      "unknown IANA timezone '" + tz + "'", true);
  }
}

function _matchesCron(cron, parts) {
  if (!cron.minute.has(parts.minute)) return false;
  if (!cron.hour.has(parts.hour))     return false;
  if (!cron.month.has(parts.month))   return false;
  // POSIX cron quirk: when both dom AND dow are restricted, the day
  // matches if EITHER matches (OR). When only one is restricted,
  // standard AND.
  var domOk = cron.dom.has(parts.day);
  var dowOk = cron.dow.has(parts.dow);
  if (cron.domRestricted && cron.dowRestricted) return domOk || dowOk;
  if (cron.domRestricted) return domOk;
  if (cron.dowRestricted) return dowOk;
  return true; // both fully wild
}

// nextCronFire — earliest UTC ms ≥ `after` whose wall-clock in `tz`
// matches the cron sets. Walks minute by minute; bounded at ~530K
// iterations (1 year of minutes) before giving up with a clear error.
function nextCronFire(cron, after, timeZone) {
  var MINUTE_MS = C.TIME.minutes(1);
  // Round up to the next whole minute boundary
  var t = new Date(after.getTime() + (MINUTE_MS - (after.getTime() % MINUTE_MS)) % MINUTE_MS);
  if (t.getTime() <= after.getTime()) t = new Date(t.getTime() + MINUTE_MS);
  // 1 year of minute-walks plus a 1-hour DST/leap cushion.
  var maxIters = (C.TIME.days(366) / MINUTE_MS) + (C.TIME.hours(1) / MINUTE_MS);
  for (var i = 0; i < maxIters; i++) {
    var parts = _getWallClockParts(t, timeZone);
    if (_matchesCron(cron, parts)) return t.getTime();
    t = new Date(t.getTime() + MINUTE_MS);
  }
  throw new SchedulerError("scheduler/cron-no-fire",
    "cron expression '" + cron.expr + "' produced no fire within 1 year " +
    "(impossible date constraint?)", true);
}

// nextBaselineFire — next UTC ms whose wall-clock in `tz` matches HH:MM.
function nextBaselineFire(timeOfDay, timeZone, after) {
  var match = String(timeOfDay).match(/^(\d{1,2}):(\d{2})$/);
  if (!match) {
    throw new SchedulerError("scheduler/invalid-baseline",
      "baseline must be HH:MM (got '" + timeOfDay + "')", true);
  }
  var hh = parseInt(match[1], 10);
  var mm = parseInt(match[2], 10);
  if (hh < 0 || hh > 23 || mm < 0 || mm > 59) {
    throw new SchedulerError("scheduler/invalid-baseline",
      "baseline '" + timeOfDay + "' is not a valid 24h time", true);
  }
  var MINUTE_MS = C.TIME.minutes(1);
  var t = new Date(after.getTime() + (MINUTE_MS - (after.getTime() % MINUTE_MS)) % MINUTE_MS);
  if (t.getTime() <= after.getTime()) t = new Date(t.getTime() + MINUTE_MS);
  // 1 day of minute-walks plus a 1-hour DST cushion.
  for (var i = 0; i < (C.TIME.hours(24) / MINUTE_MS) + (C.TIME.hours(1) / MINUTE_MS); i++) {
    var parts = _getWallClockParts(t, timeZone);
    if (parts.hour === hh && parts.minute === mm) return t.getTime();
    t = new Date(t.getTime() + MINUTE_MS);
  }
  throw new SchedulerError("scheduler/baseline-no-fire",
    "baseline '" + timeOfDay + "' produced no fire within 24h+ (timezone bug?)", true);
}

// ---- Engine ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "jobs", "cluster", "audit",
    "maxJobMs", "tickRetentionMs", "pruneIntervalMs",
  ], "scheduler");
  var jobsInstance    = opts.jobs    || null;
  var clusterInstance = opts.cluster || null;
  var auditOn         = opts.audit !== false;
  var maxJobMs        = opts.maxJobMs || DEFAULT_MAX_JOB_MS;
  var tickRetentionMs = opts.tickRetentionMs != null
    ? opts.tickRetentionMs : DEFAULT_TICK_RETENTION_MS;
  var pruneIntervalMs = opts.pruneIntervalMs != null
    ? opts.pruneIntervalMs : DEFAULT_TICK_PRUNE_INTERVAL_MS;

  // name → task
  var tasks   = new Map();
  var timers  = new Set();
  var started = false;
  var lastPruneAt = 0;

  var _err = SchedulerError.factory;

  function _emit(action, info, outcome) {
    if (!auditOn) return;
    audit().safeEmit({
      action:   action,
      outcome:  outcome,
      metadata: info || {},
      reason:   info && info.reason ? info.reason : null,
    });
  }

  function _isLeaderHere() {
    if (!clusterInstance) return true;
    try {
      if (typeof clusterInstance.isLeader === "function") return !!clusterInstance.isLeader();
    } catch (_e) { /* treat unknown leadership state as not-leader */ }
    return false;
  }

  function schedule(spec) {
    if (started) {
      throw _err("ALREADY_STARTED",
        "scheduler.schedule: cannot register '" + (spec && spec.name) +
        "' after start() — schedule all tasks before calling start()", true);
    }
    if (!spec || typeof spec !== "object") {
      throw _err("INVALID_SPEC", "scheduler.schedule requires a spec object", true);
    }
    if (typeof spec.name !== "string" || spec.name.length === 0) {
      throw _err("INVALID_NAME", "scheduler.schedule: spec.name is required", true);
    }
    if (tasks.has(spec.name)) {
      throw _err("DUPLICATE_NAME",
        "scheduler.schedule: '" + spec.name + "' is already scheduled", true);
    }

    var hasCron     = typeof spec.cron === "string";
    var hasEvery    = typeof spec.every === "number";
    if ((hasCron && hasEvery) || (!hasCron && !hasEvery)) {
      throw _err("INVALID_SPEC",
        "scheduler.schedule: spec must set exactly one of cron / every (got cron=" +
        hasCron + ", every=" + hasEvery + ")", true);
    }
    if (hasEvery && (!Number.isFinite(spec.every) || spec.every < C.TIME.seconds(1))) {
      throw _err("INVALID_SPEC",
        "scheduler.schedule: spec.every must be a number ≥ 1000 ms", true);
    }
    var hasJob = typeof spec.job === "string" && spec.job.length > 0;
    var hasRun = typeof spec.run === "function";
    if ((hasJob && hasRun) || (!hasJob && !hasRun)) {
      throw _err("INVALID_SPEC",
        "scheduler.schedule: spec must set exactly one of job / run", true);
    }
    if (hasJob && !jobsInstance) {
      throw _err("INVALID_SPEC",
        "scheduler.schedule: spec.job requires opts.jobs at scheduler.create — " +
        "use spec.run for direct-function tasks when jobs is unwired", true);
    }

    var tz = _validateTimezone(spec.timezone || null);
    var task = {
      name:      spec.name,
      timezone:  tz,
      job:       hasJob ? spec.job : null,
      payload:   spec.payload || null,
      run:       hasRun ? spec.run : null,
      enqueueOpts: spec.enqueueOpts || null,
      lastRun:   null,
      lastFinish: null,
      lastError: null,
      running:   false,
      runningSince: 0,
      fires:     0,
      misses:    0,    // skipped because previous run still in-flight
      nonLeaderSkips: 0,
      tickClaimLost:  0, // lost the tick-claim race to another leader (cluster only)
    };
    if (hasCron) {
      task.kind = "cron";
      task.cron = parseCron(spec.cron);
      task.exprDesc = "cron " + task.cron.expr + (tz ? " " + tz : "");
      task.nextRun = nextCronFire(task.cron, new Date(), tz);
    } else {
      task.kind = "every";
      task.every = spec.every;
      if (spec.baseline) {
        task.baseline = spec.baseline;
        task.nextRun = nextBaselineFire(spec.baseline, tz, new Date());
      } else {
        // Initial offset: fire one full interval after start (consistent
        // with how operators usually expect interval timers).
        task.nextRun = Date.now() + spec.every;
      }
      task.exprDesc = "every " + spec.every + "ms" +
                      (spec.baseline ? " from " + spec.baseline : "") +
                      (tz ? " " + tz : "");
    }

    tasks.set(spec.name, task);
    return task;
  }

  function _computeNextRun(task, after) {
    if (task.kind === "cron") {
      return nextCronFire(task.cron, new Date(after), task.timezone);
    }
    // every: anchor on baseline if set (so day-to-day drift stays
    // bounded), otherwise pure interval from `after`.
    if (task.baseline) {
      return nextBaselineFire(task.baseline, task.timezone, new Date(after));
    }
    return after + task.every;
  }

  function _fireOnce(task) {
    // Skip if previous run still in flight.
    if (task.running) {
      // Watchdog: if we're past MAX_JOB_MS, force-clear and let this fire.
      if (task.runningSince && (Date.now() - task.runningSince) > maxJobMs) {
        try {
          log().warn("[scheduler] '" + task.name + "' exceeded " +
            (maxJobMs / C.TIME.seconds(1)) + "s — forcing reset");
        } catch (_e) { /* logger best-effort */ }
        _emit("system.scheduler.task.watchdog", { name: task.name }, "failure");
        task.running = false;
      } else {
        task.misses++;
        _emit("system.scheduler.task.skipped",
          { name: task.name, reason: "previous-run-in-flight" }, "denied");
        return;
      }
    }

    // Cluster leader gate. Compute nextRun even when not leader so a
    // leader transition picks up cleanly without a state reload.
    if (!_isLeaderHere()) {
      task.nonLeaderSkips++;
      task.nextRun = _computeNextRun(task, Date.now());
      return;
    }

    // Capture the nominal scheduled time for this tick before we
    // recompute nextRun for the next firing.
    var nominalRun = task.nextRun;

    // Compute the next fire time forward from now (not from nominal
    // nextRun) so a long-running fire doesn't queue up backlog ticks.
    // Done before any await so _arm() reads the fresh value when it
    // re-arms after this synchronous return.
    task.nextRun = _computeNextRun(task, Date.now());

    // Cluster mode: race for the tick-claim row. Loser of the INSERT
    // skips silently. Single-node mode (no clusterInstance wired) fires
    // unconditionally — there's only one process so no contention is
    // possible.
    if (clusterInstance) {
      var tickKey = task.name + ":" + nominalRun;
      var claimedBy = (typeof clusterInstance.currentNodeId === "function")
        ? clusterInstance.currentNodeId() : "unknown";
      clusterStorage.execute(
        "INSERT INTO _blamejs_scheduler_ticks " +
        "(tickKey, name, scheduledAtUnix, claimedAtUnix, claimedBy) " +
        "VALUES (?, ?, ?, ?, ?) " +
        "ON CONFLICT (tickKey) DO NOTHING",
        [tickKey, task.name, nominalRun, Date.now(), claimedBy]
      ).then(function (result) {
        var won = (result && result.rowCount > 0);
        if (won) {
          _runFire(task);
        } else {
          task.tickClaimLost++;
          _emit("system.scheduler.tick.lost", {
            name: task.name, tickKey: tickKey, claimedBy: claimedBy,
          }, "denied");
        }
      }, function (e) {
        try {
          log().warn("[scheduler] tick-claim failed for '" + task.name + "'",
            { error: (e && e.message) || String(e) });
        } catch (_e) { /* logger best-effort */ }
        _emit("system.scheduler.tick.error", {
          name: task.name, tickKey: tickKey,
          reason: (e && e.message) || String(e),
        }, "failure");
      });
      return;
    }

    _runFire(task);
  }

  // Operator-callable prune. Deletes _blamejs_scheduler_ticks rows whose
  // scheduledAtUnix is older than `olderThanMs` (default = retention
  // window passed to scheduler.create). Returns a Promise that resolves
  // to the number of rows removed. No-op if cluster wiring is absent
  // (single-node scheduler doesn't write tick rows).
  async function pruneTickClaims(olderThanMs) {
    if (!clusterInstance) return 0;
    var threshold = Date.now() - (
      typeof olderThanMs === "number" ? olderThanMs : tickRetentionMs
    );
    var result = await clusterStorage.execute(
      "DELETE FROM _blamejs_scheduler_ticks WHERE scheduledAtUnix < ?",
      [threshold]
    );
    var removed = (result && result.rowCount) || 0;
    if (removed > 0) {
      _emit("system.scheduler.tick.pruned", {
        rowsDeleted:    removed,
        olderThanUnix:  threshold,
      });
    }
    return removed;
  }

  // Rate-limited best-effort prune called after a successful tick claim.
  // Errors are swallowed — pruning is housekeeping, not part of the fire
  // critical path.
  function _maybePruneTickClaims() {
    if (!clusterInstance) return;
    if (tickRetentionMs <= 0) return;
    var now = Date.now();
    if (now - lastPruneAt < pruneIntervalMs) return;
    lastPruneAt = now;
    pruneTickClaims().catch(function (e) {
      try {
        log().warn("[scheduler] tick-claim prune failed",
          { error: (e && e.message) || String(e) });
      } catch (_e) { /* logger best-effort */ }
    });
  }

  function _runFire(task) {
    _maybePruneTickClaims();
    task.fires++;
    task.running = true;
    task.runningSince = Date.now();
    task.lastRun = new Date().toISOString();
    var startedAt = Date.now();

    var promise;
    try {
      if (task.job) {
        promise = jobsInstance.enqueue(task.job, task.payload || {}, task.enqueueOpts || {});
      } else {
        promise = Promise.resolve(task.run());
      }
    } catch (e) {
      promise = Promise.reject(e);
    }

    Promise.resolve(promise).then(function (_v) {
      task.running = false;
      task.runningSince = 0;
      task.lastFinish = new Date().toISOString();
      task.lastError = null;
      _emit("system.scheduler.task.success", {
        name:       task.name,
        kind:       task.kind,
        durationMs: Date.now() - startedAt,
        viaJob:     !!task.job,
      });
    }, function (e) {
      task.running = false;
      task.runningSince = 0;
      task.lastFinish = new Date().toISOString();
      task.lastError = (e && e.message) || String(e);
      try {
        log().error("[scheduler] '" + task.name + "' failed", { error: task.lastError });
      } catch (_e) { /* logger best-effort */ }
      _emit("system.scheduler.task.failure", {
        name:       task.name,
        kind:       task.kind,
        durationMs: Date.now() - startedAt,
        viaJob:     !!task.job,
        reason:     task.lastError,
      }, "failure");
    });
  }

  function _arm(task) {
    var delay = Math.max(0, task.nextRun - Date.now());
    var t = setTimeout(function () {
      timers.delete(t);
      if (!started) return;
      _fireOnce(task);
      if (!started) return;
      _arm(task);
    }, delay);
    if (typeof t.unref === "function") t.unref();
    timers.add(t);
  }

  async function start() {
    if (started) return;
    started = true;
    tasks.forEach(function (task) { _arm(task); });
    _emit("scheduler.start", { count: tasks.size });
  }

  async function stop() {
    if (!started) return;
    started = false;
    timers.forEach(function (t) {
      try { clearTimeout(t); }
      catch (e) { log().debug("stop-cleanup-failed", { op: "clearTimeout", error: e.message }); }
    });
    timers.clear();
    _emit("scheduler.stop", { count: tasks.size });
  }

  function list() {
    var out = [];
    tasks.forEach(function (task) {
      out.push({
        name:           task.name,
        when:           task.exprDesc,
        kind:           task.kind,
        timezone:       task.timezone || null,
        lastRun:        task.lastRun,
        lastFinish:     task.lastFinish,
        lastError:      task.lastError,
        nextRun:        task.nextRun ? new Date(task.nextRun).toISOString() : null,
        running:        task.running,
        fires:          task.fires,
        misses:         task.misses,
        nonLeaderSkips: task.nonLeaderSkips,
        tickClaimLost:  task.tickClaimLost,
      });
    });
    return out;
  }

  function _resetForTest() {
    tasks.forEach(function (_t, _n) { /* noop — drop refs below */ });
    timers.forEach(function (t) {
      try { clearTimeout(t); }
      catch (e) { log().debug("stop-cleanup-failed", { op: "clearTimeout", error: e.message }); }
    });
    timers.clear();
    tasks.clear();
    started = false;
  }

  return {
    schedule:      schedule,
    start:         start,
    stop:          stop,
    list:          list,
    pruneTickClaims: pruneTickClaims,
    _fireOnce:     function (name) { // test hook
      var task = tasks.get(name);
      if (!task) throw _err("UNKNOWN_NAME", "no task '" + name + "'", true);
      _fireOnce(task);
    },
    _resetForTest: _resetForTest,
  };
}

module.exports = {
  create:           create,
  parseCron:        parseCron,
  nextCronFire:     nextCronFire,
  nextBaselineFire: nextBaselineFire,
  SchedulerError:   SchedulerError,
};

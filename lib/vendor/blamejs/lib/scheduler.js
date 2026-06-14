"use strict";
/**
 * @module b.scheduler
 * @featured true
 * @nav    Production
 * @title  Scheduler
 *
 * @intro
 *   Cron-style task scheduler with cluster leader gating, deduplicated
 *   ticks, drift correction, and an audit event on every tick.
 *
 *   Two registration shapes share the same engine: 5-field POSIX cron
 *   (`"0 2 * * *"`) for wall-clock schedules and `every: ms` (with an
 *   optional `baseline: "HH:MM"` anchor) for interval schedules.
 *   Timezones are IANA names; without one the schedule follows the
 *   server's local clock. Cron shorthands `@hourly`, `@daily`,
 *   `@midnight`, `@weekly`, `@monthly`, `@yearly` and `@annually` are
 *   accepted.
 *
 *   When opts.cluster is wired, fires are gated to the current leader.
 *   Every fire INSERTs a row into _blamejs_scheduler_ticks keyed on
 *   (name, scheduledAtUnix); the PRIMARY KEY race deduplicates across a
 *   split-brain window — losers increment task.tickClaimLost and skip.
 *   Tick-claim rows older than opts.tickRetentionMs (default 7 days)
 *   are pruned automatically by the leader, throttled to at most one
 *   sweep per opts.pruneIntervalMs (default 60s). Operators can force a
 *   sweep with sched.pruneTickClaims(olderThanMs?).
 *
 *   Drift correction: nextRun is computed forward from now (not from
 *   the nominal scheduled time) so a long-running fire never queues a
 *   backlog of catch-up ticks. A watchdog clears the `running` flag if
 *   a fire's promise hasn't settled after opts.maxJobMs (default 10
 *   minutes) so a hung handler can't permanently lock out future fires.
 *   Every state transition emits an audit event under
 *   `system.scheduler.*` so operators see every fire, miss, watchdog
 *   reset, and tick-claim race in their audit log.
 *
 * @card
 *   Cron-style task scheduler with cluster leader gating, deduplicated ticks, drift correction, and an audit event on every tick.
 */

var lazyRequire = require("./lazy-require");
var audit  = lazyRequire(function () { return require("./audit"); });
var log    = lazyRequire(function () { return require("./log").boot("scheduler"); });
var clusterStorage = require("./cluster-storage");
var sql = require("./sql");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { SchedulerError } = require("./framework-error");

var DEFAULT_MAX_JOB_MS             = C.TIME.minutes(10);
var DEFAULT_TICK_RETENTION_MS      = C.TIME.days(7);
var DEFAULT_TICK_PRUNE_INTERVAL_MS = C.TIME.minutes(1);

// b.sql opts for every _blamejs_scheduler_ticks statement: thread the ACTIVE
// backend dialect (clusterStorage.dialect() — "sqlite" single-node,
// "postgres" | "mysql" in cluster mode) so the emitted identifier quoting +
// dialect idioms (ON CONFLICT DO NOTHING vs the MySQL no-op fold) match the
// backend the SQL dispatches to. Defaulting to "sqlite" works on Postgres
// only by accident (both double-quote identifiers) and emits the wrong
// quoting on MySQL. clusterStorage.execute still rewrites the bare table name
// + translates `?` placeholders at dispatch; this controls only the builder-
// side quoting + idiom selection. The table name stays BARE (no quoteName)
// so clusterStorage's prefix rewrite still fires.
function _ticksSqlOpts() { return { dialect: clusterStorage.dialect() }; }

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

/**
 * @primitive b.scheduler.parseCron
 * @signature b.scheduler.parseCron(expr)
 * @since     0.5.0
 * @related   b.scheduler.create, b.scheduler.nextCronFire
 *
 * Parse a 5-field POSIX cron expression (or one of the `@hourly`,
 * `@daily`, `@midnight`, `@weekly`, `@monthly`, `@yearly`, `@annually`
 * shorthands) into a struct of populated minute / hour / dom / month /
 * dow sets plus the normalized expression text. Throws SchedulerError
 * (`scheduler/invalid-cron`) on malformed input — empty fields, bad
 * step / range syntax, or values outside each field's bounds. The
 * `dow` field accepts both 0 and 7 for Sunday and normalizes to 0.
 *
 * @example
 *   var cron = b.scheduler.parseCron("0 2 * * *");
 *   cron.expr;             // → "0 2 * * *"
 *   cron.minute.has(0);    // → true
 *   cron.hour.has(2);      // → true
 *
 *   var weekly = b.scheduler.parseCron("@weekly");
 *   weekly.expr;           // → "0 0 * * 0"
 */
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

/**
 * @primitive b.scheduler.nextCronFire
 * @signature b.scheduler.nextCronFire(cron, after, timeZone)
 * @since     0.5.0
 * @related   b.scheduler.parseCron, b.scheduler.nextBaselineFire
 *
 * Earliest UTC millisecond strictly after `after` whose wall-clock in
 * `timeZone` matches the parsed cron sets. Walks minute-by-minute; the
 * search is bounded at one year plus a one-hour DST cushion before
 * throwing SchedulerError (`scheduler/cron-no-fire`) so an impossible
 * date constraint surfaces loudly instead of looping forever. Pass
 * `null` for `timeZone` to follow the server's local clock.
 *
 * @example
 *   var cron = b.scheduler.parseCron("0 2 * * *");
 *   var when = b.scheduler.nextCronFire(cron, new Date("2026-05-09T00:00:00Z"), "UTC");
 *   new Date(when).toISOString();
 *   // → "2026-05-09T02:00:00.000Z"
 */
// Walks minute by minute; bounded at ~530K iterations (1 year of
// minutes) before giving up with a clear error.
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

/**
 * @primitive b.scheduler.nextBaselineFire
 * @signature b.scheduler.nextBaselineFire(timeOfDay, timeZone, after)
 * @since     0.5.0
 * @related   b.scheduler.nextCronFire, b.scheduler.create
 *
 * Earliest UTC millisecond strictly after `after` whose wall-clock in
 * `timeZone` matches the supplied `HH:MM` time-of-day. Used internally
 * to anchor `every`-shaped tasks to a daily baseline; exposed so
 * operators can compute the same instant for fixtures or external
 * coordination. Throws SchedulerError on malformed input
 * (`scheduler/invalid-baseline`) or on a no-fire-within-24h timezone
 * bug (`scheduler/baseline-no-fire`). Pass `null` for `timeZone` to
 * follow the server's local clock.
 *
 * @example
 *   var when = b.scheduler.nextBaselineFire(
 *     "02:30", "UTC", new Date("2026-05-09T01:00:00Z")
 *   );
 *   new Date(when).toISOString();
 *   // → "2026-05-09T02:30:00.000Z"
 */
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

/**
 * @primitive b.scheduler.create
 * @signature b.scheduler.create(opts)
 * @since     0.5.0
 * @related   b.scheduler.parseCron, b.cluster.init, b.jobs.create
 *
 * Build a scheduler instance. Returns a facade exposing `schedule`,
 * `register`, `start`, `stop`, `list`, `getStatus`, and
 * `pruneTickClaims`. Tasks are registered before `start()`; `start()`
 * arms timers, `stop()` clears them and drops pending fires. When
 * `opts.cluster` is supplied, fires are gated to the leader and a
 * tick-claim row in `_blamejs_scheduler_ticks` deduplicates split-brain
 * windows. When `opts.jobs` is supplied, tasks declared with
 * `{ job: "name" }` dispatch via the jobs queue; tasks declared with
 * `{ run: fn }` execute the function directly.
 *
 * @opts
 *   jobs:            object,    // optional jobs instance for { job: "name" } tasks
 *   cluster:         object,    // optional cluster instance — gates fires to leader
 *   audit:           boolean,   // emit system.scheduler.* audit events (default true)
 *   maxJobMs:        number,    // watchdog reset threshold (default 10 minutes)
 *   tickRetentionMs: number,    // tick-claim row retention (default 7 days)
 *   pruneIntervalMs: number,    // throttle for opportunistic prune (default 60s)
 *
 * @example
 *   var sched = b.scheduler.create({ audit: true });
 *   sched.schedule({
 *     name: "nightly-cleanup",
 *     cron: "0 2 * * *",
 *     timezone: "UTC",
 *     run: async function () { return "ok"; },
 *   });
 *   await sched.start();
 *   var snapshot = sched.list();
 *   snapshot[0].name;           // → "nightly-cleanup"
 *   await sched.stop();
 */
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
      // Monotonic run tag. The watchdog and each fire bump it, so a run the
      // watchdog abandoned can't clobber state / emit a stale settle event
      // when its slow promise finally resolves.
      runGeneration: 0,
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
                      (spec.baseline ? " anchored " + spec.baseline : "") +
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
        // Supersede the abandoned run so its late settle is ignored.
        task.runGeneration++;
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
      // BARE logical table name — clusterStorage rewrites _blamejs_scheduler_ticks
      // to the configured prefix and placeholderizes the ? markers. The
      // PRIMARY KEY race on tickKey deduplicates the split-brain window; the
      // loser's ON CONFLICT DO NOTHING reports zero rowCount and skips.
      var claimBuilt = sql.upsert("_blamejs_scheduler_ticks", _ticksSqlOpts())   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
        .columns(["tickKey", "name", "scheduledAtUnix", "claimedAtUnix", "claimedBy"])
        .values({
          tickKey:         tickKey,
          name:            task.name,
          scheduledAtUnix: nominalRun,
          claimedAtUnix:   Date.now(),
          claimedBy:       claimedBy,
        })
        .onConflict(["tickKey"])
        .doNothing()
        .toSql();
      clusterStorage.execute(claimBuilt.sql, claimBuilt.params).then(function (result) {
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
    var pruneBuilt = sql.delete("_blamejs_scheduler_ticks", _ticksSqlOpts())   // allow:hand-rolled-sql — bare logical name for clusterStorage rewrite
      .where("scheduledAtUnix", "<", threshold)
      .toSql();
    var result = await clusterStorage.execute(pruneBuilt.sql, pruneBuilt.params);
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
    // Tag this run. The settle handlers below only write back if the tag still
    // matches — so a run the watchdog reset (or a newer fire) can't clobber the
    // current run's state or emit a stale success/failure when it settles late.
    var gen = (task.runGeneration = (task.runGeneration || 0) + 1);

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
      if (task.runGeneration !== gen) return;   // watchdog/newer fire superseded this run
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
      if (task.runGeneration !== gen) return;   // watchdog/newer fire superseded this run
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

  // Shorthand for the common interval-based registration shape:
  //   register("rotate-keys", C.TIME.minutes(5), runFn)
  // is equivalent to schedule({ name, every: 300000, run: runFn }).
  // Operators wanting cron expressions or job-queue dispatch keep
  // using schedule() — register() is the every-N-ms direct-function
  // path. Returns the scheduler instance for method chaining.
  function register(name, intervalMs, fn) {
    if (typeof name !== "string" || name.length === 0) {
      throw _err("INVALID_NAME", "scheduler.register: name must be a non-empty string", true);
    }
    if (typeof intervalMs !== "number" || !Number.isFinite(intervalMs) || intervalMs < C.TIME.seconds(1)) {
      throw _err("INVALID_SPEC",
        "scheduler.register: intervalMs must be a finite number ≥ 1000", true);
    }
    if (typeof fn !== "function") {
      throw _err("INVALID_SPEC", "scheduler.register: fn must be a function", true);
    }
    schedule({ name: name, every: intervalMs, run: fn });
    return facade;
  }

  // Operator-facing health surface — every task with its lifecycle
  // counters plus an aggregate. Probes / dashboards / readiness gates
  // get a single object they can serialize. This is `list()` plus
  // started state and aggregate stats.
  function getStatus() {
    var taskList = list();
    var aggregate = {
      total:          taskList.length,
      running:        0,
      withErrors:     0,
      totalFires:     0,
      totalMisses:    0,
      nonLeaderSkips: 0,
      tickClaimLost:  0,
    };
    for (var i = 0; i < taskList.length; i++) {
      var t = taskList[i];
      if (t.running)        aggregate.running        += 1;
      if (t.lastError)      aggregate.withErrors     += 1;
      aggregate.totalFires      += t.fires || 0;
      aggregate.totalMisses     += t.misses || 0;
      aggregate.nonLeaderSkips  += t.nonLeaderSkips || 0;
      aggregate.tickClaimLost   += t.tickClaimLost || 0;
    }
    return {
      started:   started,
      isLeader:  _isLeaderHere(),
      tasks:     taskList,
      aggregate: aggregate,
    };
  }

  var facade = {
    schedule:      schedule,
    register:      register,
    getStatus:     getStatus,
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
  return facade;
}

module.exports = {
  create:           create,
  parseCron:        parseCron,
  nextCronFire:     nextCronFire,
  nextBaselineFire: nextBaselineFire,
  SchedulerError:   SchedulerError,
};

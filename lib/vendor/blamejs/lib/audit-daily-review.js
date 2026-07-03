// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.auditDailyReview
 * @nav    Compliance
 * @title  Audit Daily Review
 *
 * @intro
 *   PCI DSS 4.0 Req 10.4.1.1 daily-review primitive (mandatory
 *   effective 2025-03-31). Automated review of all security event
 *   logs, CHD/SAD components, critical system components, and security-
 *   function components — surfacing anomalies and exceptions for
 *   follow-up. The framework provides scheduling, query, severity
 *   classification, and notify wiring; the operator supplies the
 *   notify channel and any post-review workflow.
 *
 *   Adjacent regimes covered: HIPAA §164.308(a)(1)(ii)(D) (regular
 *   review of activity records), SOX §302/§404 (quarterly self-
 *   attestation), SOC 2 CC7.2 (anomaly identification and response),
 *   GDPR Art. 32 (ongoing security testing/evaluation). When `posture`
 *   is one of `pci-dss` / `hipaa` / `sox` / `sox-404` / `soc2`, a
 *   `notify` callback is mandatory at create-time — the regulators all demand
 *   a follow-up channel.
 *
 *   Severity classification: `denied` / `failure` outcomes default to
 *   `warning`; `auth.fail*` / `audit.read` / `csrf.bad_*` / `ato.*` /
 *   `honeytoken.tripped` / `breakglass.*` / `ddl.change.applied`
 *   raise to `alert`; `audit.tamper*` / `vault.aad.unseal_failed` /
 *   `config.drift.detected` / `vendor.integrity.tampered` /
 *   `ato.killSwitch.tripped` raise to `critical`. Operators with
 *   richer rules pass `opts.classify(event) → severity`.
 *
 *   Audit events: `audit.daily_review.completed` (every run),
 *   `.notified` (notify fired), `.notify_failed` (notify threw or
 *   rejected; the review itself still completed), `.scheduled`,
 *   `.stopped`.
 *
 * @card
 *   PCI DSS 4.0 Req 10.4.1.1 daily-review primitive (mandatory effective 2025-03-31).
 */

var validateOpts = require("./validate-opts");
var C = require("./constants");
var { AuditDailyReviewError } = require("./framework-error");

var SEVERITY_ORDER = ["info", "notice", "warning", "alert", "critical"];

var ALERT_PATTERNS = [
  /^auth\.(fail|failed|locked|denied|invalid)/,
  /^audit\.read$/,
  /^audit\.tamper/,
  /^csrf\.bad_/,
  /^ato\./,
  /^honeytoken\.tripped/,
  /^compliance\.posture\.set_rejected/,
  /^audit\.actor_binding\.violation/,
  /^ddl\.change\.applied/,
  /^breakglass\./,
];

var CRITICAL_PATTERNS = [
  /^audit\.tamper/,
  /^vault\.aad\.unseal_failed/,
  /^config\.drift\.detected/,
  /^vendor\.integrity\.tampered/,
  /^ato\.killSwitch\.tripped/,
];

var POSTURES_REQUIRING_NOTIFY = ["pci-dss", "hipaa", "sox", "sox-404", "soc2"];

function _defaultClassify(event) {
  if (!event || typeof event !== "object" || typeof event.action !== "string") {
    return "info";
  }
  var action = event.action;
  for (var i = 0; i < CRITICAL_PATTERNS.length; i++) {
    if (CRITICAL_PATTERNS[i].test(action)) return "critical";
  }
  for (var j = 0; j < ALERT_PATTERNS.length; j++) {
    if (ALERT_PATTERNS[j].test(action)) return "alert";
  }
  if (event.outcome === "denied" || event.outcome === "failure") return "warning";
  return "info";
}

function _severityAtLeast(severity, threshold) {
  var tIdx = SEVERITY_ORDER.indexOf(threshold);
  if (tIdx === -1) return false;   // unknown threshold (validated at config)
  var sIdx = SEVERITY_ORDER.indexOf(severity);
  // An UNKNOWN event severity — e.g. a custom classify(event) returning an
  // unexpected value — must NOT silently drop the event from the review. Fail
  // SAFE: treat it as meeting the threshold so the operator still sees the
  // event (and notices their classify mis-returned) rather than missing a
  // flagged event.
  if (sIdx === -1) return true;
  return sIdx >= tIdx;
}

function _err(code, msg) {
  return new AuditDailyReviewError(code, msg);
}

/**
 * @primitive b.auditDailyReview.create
 * @signature b.auditDailyReview.create(opts)
 * @since     0.8.48
 * @status    stable
 * @compliance pci-dss, hipaa, sox-404, soc2, gdpr
 * @related   b.audit, b.scheduler, b.compliance
 *
 * Build a daily-review scheduler. Returns
 * `{ run, list, lastRun, schedule, start, stop, classify, posture,
 * cron, severityThreshold, lookbackHours }`. `run()` executes a single
 * review window on demand; `start()` arms the scheduler so the review
 * fires on the configured cron; `list()` returns the bounded history
 * buffer of past summaries.
 *
 * @opts
 *   audit:             Object,     // b.audit instance (query / safeEmit)
 *   scheduler:         Object,     // b.scheduler instance; required for start()
 *   lookbackHours:     number,     // window size in hours (default 24)
 *   severityThreshold: string,     // info|notice|warning|alert|critical (default "warning")
 *   posture:           string,     // pci-dss | hipaa | sox-404 | soc2 | …
 *   cron:              string,     // POSIX 5-field expr (default "0 6 * * *")
 *   notify:            Function,   // async (summary) → void; required under listed postures
 *   classify:          Function,   // (event) → severity; default action-prefix table
 *   queryLimit:        number,     // max rows pulled from audit.query (default 10000)
 *   historyLimit:      number,     // bounded summary buffer (default 30)
 *   now:               Function,   // () → number; testing override
 *
 * @example
 *   var review = b.auditDailyReview.create({
 *     audit:             auditInstance,
 *     scheduler:         schedulerInstance,
 *     lookbackHours:     24,
 *     severityThreshold: "warning",
 *     posture:           "pci-dss",
 *     cron:              "0 6 * * *",
 *     notify:            async function (summary) {
 *       if (summary.hitCount > 0) {
 *         // page on-call with summary.thresholdHits
 *       }
 *     },
 *   });
 *
 *   // On-demand:
 *   var summary = await review.run();
 *   summary.totalEvents;       // → 1842
 *   summary.bySeverity;        // → { info: 1700, warning: 120, alert: 22, critical: 0, notice: 0 }
 *   summary.hitCount;          // → 142  (events at-or-above warning)
 *
 *   // Or arm the scheduler so the review fires nightly at 06:00 UTC:
 *   await review.start();
 *   review.lastRun();          // → most recent summary or null
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "scheduler", "lookbackHours", "severityThreshold",
    "posture", "cron", "notify", "classify", "queryLimit", "historyLimit",
    "now",
  ], "auditDailyReview.create");

  validateOpts.auditShape(opts.audit, "auditDailyReview",
    AuditDailyReviewError, "auditDailyReview/bad-audit");
  if (!opts.audit) {
    throw _err("auditDailyReview/audit-required",
      "auditDailyReview.create: opts.audit is required (must expose query() / safeEmit())");
  }
  if (typeof opts.audit.query !== "function") {
    throw _err("auditDailyReview/audit-query-missing",
      "auditDailyReview.create: opts.audit.query must be a function");
  }
  validateOpts.shape(opts, {
    audit:        { methods: ["query", "safeEmit"] },
    notify:       { rule: "optional-function",     code: "auditDailyReview/bad-notify" },
    classify:     { rule: "optional-function",     code: "auditDailyReview/bad-classify" },
    now:          { rule: "optional-function",     code: "auditDailyReview/bad-now" },
    posture:      { rule: "optional-string",       code: "auditDailyReview/bad-posture" },
    cron:         { rule: "optional-string",       code: "auditDailyReview/bad-cron" },
    severityThreshold: { rule: "optional-string",  code: "auditDailyReview/bad-severity" },
    queryLimit:   { rule: "optional-positive-int", code: "auditDailyReview/bad-querylimit" },
    historyLimit: { rule: "optional-positive-int", code: "auditDailyReview/bad-historylimit" },
    // lookbackHours — positive finite number (hours, not bytes). Bespoke
    // check preserves the auditDailyReview/bad-lookback code the message
    // below depends on; a positive-int token would reject fractional hours.
    lookbackHours: function (value, label) {
      if (value === undefined || value === null) return;
      if (typeof value !== "number" || !isFinite(value) || value <= 0) {
        throw _err("auditDailyReview/bad-lookback",
          "auditDailyReview.create: lookbackHours must be a positive finite number");
      }
    },
  }, "auditDailyReview", AuditDailyReviewError, "auditDailyReview/bad-opts",
     // scheduler is forwarded to the b.scheduler instance at start() and not
     // validated locally at create-time (start() requires it on its own).
     { allow: ["scheduler"] });

  // lookbackHours — default 24 per PCI DSS 4.0 daily cadence. Caller can
  // pass weekly / monthly via larger numbers.
  var lookbackHours = 24; // lookback in HOURS, not bytes
  if (opts.lookbackHours !== undefined) {
    if (typeof opts.lookbackHours !== "number" || !isFinite(opts.lookbackHours) ||
        opts.lookbackHours <= 0) {
      throw _err("auditDailyReview/bad-lookback",
        "auditDailyReview.create: lookbackHours must be a positive finite number");
    }
    lookbackHours = opts.lookbackHours;
  }

  var severityThreshold = opts.severityThreshold || "warning";
  if (SEVERITY_ORDER.indexOf(severityThreshold) === -1) {
    throw _err("auditDailyReview/bad-severity",
      "auditDailyReview.create: severityThreshold must be one of " +
      SEVERITY_ORDER.join(", "));
  }

  var posture = opts.posture || null;
  if (posture && POSTURES_REQUIRING_NOTIFY.indexOf(posture) !== -1 && !opts.notify) {
    throw _err("auditDailyReview/notify-required-under-posture",
      "auditDailyReview.create: posture '" + posture + "' requires notify callback " +
      "(PCI DSS 10.4.1.1 / HIPAA §164.308(a)(1)(ii)(D) demand a follow-up channel)");
  }

  var cron = opts.cron || "0 6 * * *";   // 06:00 UTC daily
  var queryLimit = opts.queryLimit || 10000;                                    // operator-tunable result cap, count not bytes
  var historyLimit = opts.historyLimit || 30;                                   // bounded history buffer (count, not bytes)
  var classify = typeof opts.classify === "function" ? opts.classify : _defaultClassify;
  var now = typeof opts.now === "function" ? opts.now : Date.now;
  var auditMod = opts.audit;
  var notify = typeof opts.notify === "function" ? opts.notify : null;
  var schedulerMod = opts.scheduler || null;

  var history = [];
  var taskName = "blamejs.auditDailyReview." + (posture || "default");
  var armedScheduler = null;

  function _emit(action, metadata, outcome) {
    try {
      auditMod.safeEmit({
        action:   action,
        outcome:  outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* audit best-effort */ }
  }

  async function run() {
    var startedAt = now();
    var fromMs = startedAt - C.TIME.hours(lookbackHours);
    var rows;
    try {
      rows = await auditMod.query({
        from:  fromMs,
        to:    startedAt,
        limit: queryLimit,
        // Newest-first: if the window holds more than queryLimit events, keep
        // the MOST RECENT (the actionable ones) — an ascending+limit query would
        // keep the oldest and silently drop the newest from the review.
        order: "desc",
      });
    } catch (e) {
      _emit("audit.daily_review.failed", {
        reason: (e && e.message) || String(e),
        lookbackHours: lookbackHours,
      }, "failure");
      throw _err("auditDailyReview/query-failed",
        "auditDailyReview.run: audit.query failed: " + ((e && e.message) || String(e)));
    }

    var bySeverity = { info: 0, notice: 0, warning: 0, alert: 0, critical: 0 };
    var byOutcome  = { success: 0, failure: 0, denied: 0, other: 0 };
    var byNamespace = Object.create(null);
    var thresholdHits = [];
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var sev = classify(r);
      if (bySeverity[sev] === undefined) bySeverity[sev] = 0;
      bySeverity[sev]++;

      var oc = r && r.outcome;
      if (oc === "success" || oc === "failure" || oc === "denied") byOutcome[oc]++;
      else byOutcome.other++;

      var ns = (r && typeof r.action === "string") ? r.action.split(".")[0] : "unknown";
      byNamespace[ns] = (byNamespace[ns] || 0) + 1;

      if (_severityAtLeast(sev, severityThreshold)) {
        thresholdHits.push({
          action:   r.action,
          outcome:  r.outcome,
          severity: sev,
          recordedAt: r.recordedAt,
          actorUserId: r.actorUserId || null,
          requestId: r.requestId || null,
        });
      }
    }

    var summary = {
      runAt:           new Date(startedAt).toISOString(),
      lookbackHours:   lookbackHours,
      windowFromMs:    fromMs,
      windowToMs:      startedAt,
      totalEvents:     rows.length,
      bySeverity:      bySeverity,
      byOutcome:       byOutcome,
      byNamespace:     byNamespace,
      severityThreshold: severityThreshold,
      thresholdHits:   thresholdHits,
      hitCount:        thresholdHits.length,
      durationMs:      now() - startedAt,
      posture:         posture,
    };

    history.push(summary);
    if (history.length > historyLimit) history.splice(0, history.length - historyLimit);

    _emit("audit.daily_review.completed", {
      lookbackHours: lookbackHours,
      totalEvents:   summary.totalEvents,
      hitCount:      summary.hitCount,
      durationMs:    summary.durationMs,
      posture:       posture,
    });

    if (notify && thresholdHits.length > 0) {
      try {
        await notify(summary);
        _emit("audit.daily_review.notified", {
          hitCount: thresholdHits.length, posture: posture,
        });
      } catch (e) {
        _emit("audit.daily_review.notify_failed", {
          reason: (e && e.message) || String(e),
          hitCount: thresholdHits.length, posture: posture,
        }, "failure");
        // Don't throw — the daily review completed, only notify failed.
        // Operators read audit.daily_review.notify_failed to chase down
        // their notify-channel outage.
      }
    }

    return summary;
  }

  function lastRun() {
    return history.length > 0 ? history[history.length - 1] : null;
  }

  function list() {
    return history.slice();
  }

  function schedule() {
    return cron;
  }

  async function start() {
    if (!schedulerMod) {
      throw _err("auditDailyReview/no-scheduler",
        "auditDailyReview.start: opts.scheduler is required to arm the cron firing — " +
        "operators without a scheduler call run() on their own cadence");
    }
    if (armedScheduler) return;
    armedScheduler = schedulerMod;
    armedScheduler.schedule({
      name: taskName,
      cron: cron,
      run:  run,
    });
    if (typeof armedScheduler.start === "function") {
      // Scheduler.start() is idempotent — safe to call when the scheduler
      // was already armed by other tasks.
      try { await armedScheduler.start(); } catch (_e) { /* operator-controlled */ }
    }
    _emit("audit.daily_review.scheduled", {
      cron: cron, taskName: taskName, posture: posture,
    });
  }

  async function stop() {
    if (!armedScheduler) return;
    armedScheduler = null;
    _emit("audit.daily_review.stopped", { taskName: taskName, posture: posture });
  }

  return {
    run:        run,
    list:       list,
    lastRun:    lastRun,
    schedule:   schedule,
    start:      start,
    stop:       stop,
    classify:   classify,
    posture:    posture,
    cron:       cron,
    severityThreshold: severityThreshold,
    lookbackHours:     lookbackHours,
  };
}

module.exports = {
  create: create,
  SEVERITY_ORDER:           SEVERITY_ORDER,
  ALERT_PATTERNS:           ALERT_PATTERNS,
  CRITICAL_PATTERNS:        CRITICAL_PATTERNS,
  POSTURES_REQUIRING_NOTIFY: POSTURES_REQUIRING_NOTIFY,
  AuditDailyReviewError:    AuditDailyReviewError,
};

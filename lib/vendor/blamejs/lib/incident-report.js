// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("./constants");
var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var safeAsync = require("./safe-async");
var validateOpts = require("./validate-opts");

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var IncidentReportError = defineClass("IncidentReportError", { alwaysPermanent: true });

var DEFAULT_DEADLINES = Object.freeze({
  initial:      C.TIME.hours(24),
  intermediate: C.TIME.hours(72),
  final:        C.TIME.days(30),
});

var VALID_STAGES = Object.freeze({ initial: 1, intermediate: 1, final: 1 });

var REGIME_DEADLINES = Object.freeze({
  gdpr: Object.freeze({
    initial:      C.TIME.hours(24),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(30),
  }),
  nis2: Object.freeze({
    initial:      C.TIME.hours(24),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(30),
  }),
  dora: Object.freeze({
    initial:      C.TIME.hours(4),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(30),
  }),
  cra: Object.freeze({
    initial:      C.TIME.hours(24),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(14),
  }),
  hipaa: Object.freeze({
    initial:      C.TIME.hours(24),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(60),
  }),
});

function _resolveDeadlines(regime, override) {
  var base = (typeof regime === "string" &&
              Object.prototype.hasOwnProperty.call(REGIME_DEADLINES, regime))
    ? REGIME_DEADLINES[regime] : DEFAULT_DEADLINES;
  if (!override || typeof override !== "object") return base;
  return Object.freeze({
    initial:      typeof override.initial      === "number" ? override.initial      : base.initial,
    intermediate: typeof override.intermediate === "number" ? override.intermediate : base.intermediate,
    final:        typeof override.final        === "number" ? override.final        : base.final,
  });
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "persist", "onStage", "deadlines", "now",
  ], "incident.report");

  var persist = typeof opts.persist === "function" ? opts.persist : null;
  var onStage = typeof opts.onStage === "function" ? opts.onStage : null;
  var deadlinesOverride = opts.deadlines || null;
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };

  var incidents = new Map();
  var seq = 0;

  var _emitAudit = audit().namespaced("incident.report", opts.audit);
  var _emitMetric = observability().namespaced("incident.report");

  function _genIncidentId(regime, detectedAt) {
    seq += 1;
    var ts = new Date(detectedAt).toISOString().replace(/[:.]/g, "-");
    return "incident-" + (regime || "generic") + "-" + ts + "-" + seq;
  }

  async function open(spec) {
    if (!spec || typeof spec !== "object") {
      throw new IncidentReportError("incident-report/bad-spec",
        "incident.report.open: spec must be an object with { regime, detectedAt, scope, summary, impact }");
    }
    if (typeof spec.regime !== "string" || spec.regime.length === 0) {
      throw new IncidentReportError("incident-report/bad-regime",
        "incident.report.open: spec.regime must be a non-empty string (gdpr / nis2 / dora / cra / hipaa or operator-defined)");
    }
    if (typeof spec.detectedAt !== "number" || !isFinite(spec.detectedAt)) {
      throw new IncidentReportError("incident-report/bad-detected-at",
        "incident.report.open: spec.detectedAt must be a finite Unix-ms timestamp");
    }
    var deadlines = _resolveDeadlines(spec.regime, deadlinesOverride);
    var id = _genIncidentId(spec.regime, spec.detectedAt);
    var record = {
      id:           id,
      regime:       spec.regime,
      detectedAt:   spec.detectedAt,
      scope:        spec.scope || null,
      summary:      spec.summary || null,
      impact:       spec.impact || null,
      deadlines:    deadlines,
      dueBy: {
        initial:      spec.detectedAt + deadlines.initial,
        intermediate: spec.detectedAt + deadlines.intermediate,
        final:        spec.detectedAt + deadlines.final,
      },
      stages:       {},
      openedAt:     now(),
      closedAt:     null,
    };
    incidents.set(id, record);
    _emitAudit("opened", "success", {
      incidentId: id, regime: spec.regime, detectedAt: spec.detectedAt,
      dueByInitial:      record.dueBy.initial,
      dueByIntermediate: record.dueBy.intermediate,
      dueByFinal:        record.dueBy.final,
    });
    _emitMetric("opened", 1, { regime: spec.regime });
    if (persist) {
      try { await persist(record); }
      catch (e) { _emitAudit("persist_failed", "failure", { incidentId: id, error: (e && e.message) || String(e) }); }
    }
    return record;
  }

  async function _recordStage(incidentId, stage, payload) {
    if (!Object.prototype.hasOwnProperty.call(VALID_STAGES, stage)) {
      throw new IncidentReportError("incident-report/bad-stage",
        "incident.report._recordStage: stage must be one of " + Object.keys(VALID_STAGES).join(", "));
    }
    var rec = incidents.get(incidentId);
    if (!rec) {
      throw new IncidentReportError("incident-report/unknown-incident",
        "incident.report: no incident with id '" + incidentId + "'");
    }
    if (rec.stages[stage]) {
      throw new IncidentReportError("incident-report/stage-already-filed",
        "incident.report: incident '" + incidentId + "' already has a '" + stage + "' stage filing");
    }
    var nowMs = now();
    var dueBy = rec.dueBy[stage];
    var late = nowMs > dueBy;
    var lateBy = late ? (nowMs - dueBy) : 0;
    rec.stages[stage] = {
      filedAt:  nowMs,
      dueBy:    dueBy,
      late:     late,
      lateBy:   lateBy,
      payload:  payload || {},
    };
    if (stage === "final") rec.closedAt = nowMs;

    _emitAudit("stage_recorded", late ? "late" : "success", {
      incidentId: incidentId, regime: rec.regime, stage: stage,
      dueBy: dueBy, filedAt: nowMs, late: late, lateBy: lateBy,
    });
    _emitMetric("stage_recorded", 1, { regime: rec.regime, stage: stage, late: String(late) });
    safeAsync.safeInvoke(onStage,
      { incidentId: incidentId, stage: stage, dueBy: dueBy, late: late, regime: rec.regime, fields: payload });
    if (persist) {
      try { await persist(rec); }
      catch (e) { _emitAudit("persist_failed", "failure", { incidentId: incidentId, stage: stage, error: (e && e.message) || String(e) }); }
    }
    return rec;
  }

  function recordInitial(incidentId, payload)      { return _recordStage(incidentId, "initial",      payload); }
  function recordIntermediate(incidentId, payload) { return _recordStage(incidentId, "intermediate", payload); }
  function recordFinal(incidentId, payload)        { return _recordStage(incidentId, "final",        payload); }

  function get(incidentId) { return incidents.get(incidentId) || null; }
  function list() {
    var out = [];
    incidents.forEach(function (rec) { out.push(rec); });
    return out;
  }

  function status() {
    var nowMs = now();
    var summary = {
      total:  incidents.size,
      open:   0,
      closed: 0,
      late:   { initial: 0, intermediate: 0, final: 0 },
    };
    incidents.forEach(function (rec) {
      if (rec.closedAt) summary.closed += 1; else summary.open += 1;
      ["initial", "intermediate", "final"].forEach(function (s) {
        if (!rec.stages[s] && nowMs > rec.dueBy[s]) summary.late[s] += 1;
        else if (rec.stages[s] && rec.stages[s].late) summary.late[s] += 1;
      });
    });
    return summary;
  }

  return {
    open:               open,
    recordInitial:      recordInitial,
    recordIntermediate: recordIntermediate,
    recordFinal:        recordFinal,
    get:                get,
    list:               list,
    status:             status,
    REGIME_DEADLINES:   REGIME_DEADLINES,
    DEFAULT_DEADLINES:  DEFAULT_DEADLINES,
  };
}

function createDeadlineClock(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "notify", "approachThresholds", "intervalMs", "autoStart", "now",
  ], "incident.report.createDeadlineClock");

  var auditOn = opts.audit !== false;
  var notify  = (opts.notify && typeof opts.notify.send === "function") ? opts.notify : null;
  var thresholds = Array.isArray(opts.approachThresholds) ? opts.approachThresholds.slice() : [0.5, 0.75, 0.9];
  for (var ti = 0; ti < thresholds.length; ti += 1) {
    if (typeof thresholds[ti] !== "number" || !(thresholds[ti] > 0 && thresholds[ti] < 1)) {
      throw new IncidentReportError("incident-report/bad-threshold",
        "createDeadlineClock: approachThresholds must be numbers strictly between 0 and 1");
    }
  }
  thresholds.sort(function (a, b) { return a - b; });
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };
  var intervalMs = (typeof opts.intervalMs === "number" && isFinite(opts.intervalMs) && opts.intervalMs > 0)
    ? opts.intervalMs : C.TIME.minutes(1);
  var autoStart = opts.autoStart !== false;

  var tracked = new Map();
  var timer = null;

  var _emit = audit().namespaced("incident.report.clock", auditOn);
  function _notify(payload) {
    if (!notify) return;
    // Drop-silent: escalation is best-effort and never crashes a tick.
    safeAsync.safeInvoke(function (p) { return notify.send(p); }, payload);
  }

  function track(record) {
    if (!record || typeof record !== "object" || typeof record.id !== "string" || record.id.length === 0) {
      throw new IncidentReportError("incident-report/bad-record",
        "createDeadlineClock.track: record must be an incident.report record with a string id");
    }
    if (!record.dueBy || typeof record.dueBy !== "object" ||
        typeof record.detectedAt !== "number") {
      throw new IncidentReportError("incident-report/bad-record",
        "createDeadlineClock.track: record must carry detectedAt + dueBy { initial, intermediate, final }");
    }
    tracked.set(record.id, {
      detectedAt: record.detectedAt,
      dueBy:      record.dueBy,
      regime:     record.regime || null,
      acked:      {},
      fired:      {},
    });
    return record.id;
  }

  function untrack(id) { return tracked.delete(id); }

  function acknowledgeSubmission(id, stage, info) {
    if (!Object.prototype.hasOwnProperty.call(VALID_STAGES, stage)) {
      throw new IncidentReportError("incident-report/bad-stage",
        "createDeadlineClock.acknowledgeSubmission: stage must be one of " + Object.keys(VALID_STAGES).join(", "));
    }
    var t = tracked.get(id);
    if (!t) {
      throw new IncidentReportError("incident-report/unknown-incident",
        "createDeadlineClock.acknowledgeSubmission: no tracked incident '" + id + "'");
    }
    t.acked[stage] = true;
    _emit("submission_acknowledged", "success", { incidentId: id, regime: t.regime, stage: stage, info: info || null });
    return true;
  }

  function tick(nowMsArg) {
    var nowMs = typeof nowMsArg === "number" ? nowMsArg : now();
    tracked.forEach(function (t, id) {
      var stages = ["initial", "intermediate", "final"];
      for (var si = 0; si < stages.length; si += 1) {
        var stage = stages[si];
        if (t.acked[stage]) continue;
        var due = t.dueBy[stage];
        if (typeof due !== "number") continue;
        var span = due - t.detectedAt;
        if (span <= 0) continue;
        if (nowMs >= due) {
          var pk = stage + ":passed";
          if (!t.fired[pk]) {
            t.fired[pk] = true;
            _emit("deadline_passed", "failure", { incidentId: id, regime: t.regime, stage: stage, dueBy: due });
            _notify({ kind: "deadline_passed", incidentId: id, regime: t.regime, stage: stage, dueBy: due });
          }
          continue;
        }
        var proportion = (nowMs - t.detectedAt) / span;
        for (var thi = thresholds.length - 1; thi >= 0; thi -= 1) {
          if (proportion >= thresholds[thi]) {
            var ak = stage + ":approaching:" + thresholds[thi];
            if (!t.fired[ak]) {
              t.fired[ak] = true;
              _emit("deadline_approaching", "warning",
                { incidentId: id, regime: t.regime, stage: stage, dueBy: due, threshold: thresholds[thi] });
              _notify({ kind: "deadline_approaching", incidentId: id, regime: t.regime, stage: stage, dueBy: due, threshold: thresholds[thi] });
            }
            break;
          }
        }
      }
    });
  }

  function start() {
    if (timer) return;
    timer = setInterval(function () { tick(); }, intervalMs);
    if (timer && typeof timer.unref === "function") timer.unref();
  }
  function stop() {
    if (timer) { clearInterval(timer); timer = null; }
  }
  function status() {
    return { tracked: tracked.size, running: timer !== null, intervalMs: intervalMs };
  }

  if (autoStart) start();
  return {
    track:                 track,
    untrack:               untrack,
    acknowledgeSubmission: acknowledgeSubmission,
    tick:                  tick,
    start:                 start,
    stop:                  stop,
    status:                status,
  };
}

module.exports = {
  create:                create,
  createDeadlineClock:   createDeadlineClock,
  IncidentReportError:   IncidentReportError,
  REGIME_DEADLINES:      REGIME_DEADLINES,
  DEFAULT_DEADLINES:     DEFAULT_DEADLINES,
  VALID_STAGES:          Object.keys(VALID_STAGES),
};

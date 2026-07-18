// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.incident.report — generic 3-stage incident-reporting primitive.
 *
 * The three stages mirror the deadline pattern that recurs across
 * regulatory regimes (GDPR Article 33 / NIS2 Article 23 / DORA
 * Article 19 / CRA Article 14 / HIPAA Breach Notification Rule):
 *
 *   1. Initial / early-warning notification — within 24 hours of
 *      detection. Operators report what they know: scope, suspected
 *      cause, immediate-mitigation plan.
 *   2. Intermediate / status update — within 72 hours of detection.
 *      Updated impact assessment, root-cause analysis progress,
 *      operator's response posture.
 *   3. Final report — within 30 days of detection (or per-regime
 *      deadline). Full incident narrative, affected-data-subject
 *      count, remediation, lessons learned.
 *
 *   var ir = b.incident.report.create({
 *     audit:    b.audit,
 *     persist:  async function (record) { await db.run("INSERT ..."); },
 *     onStage:  function (event) {
 *       // event = { incidentId, stage: "initial"|"intermediate"|"final",
 *       //           dueBy, regime, fields }
 *     },
 *     deadlines: {                                  // operator-overridable per regime
 *       initial:      C.TIME.hours(24),
 *       intermediate: C.TIME.hours(72),
 *       final:        C.TIME.days(30),
 *     },
 *   });
 *   var incident = await ir.open({
 *     regime:       "gdpr",                         // identifies the regulatory regime
 *     detectedAt:   Date.now(),
 *     scope:        "data-confidentiality-breach",
 *     summary:      "...",
 *     impact:       { dataSubjects: 1200, categories: ["pii", "phi"] },
 *   });
 *   await ir.recordInitial(incident.id, { ... });
 *   await ir.recordIntermediate(incident.id, { ... });
 *   await ir.recordFinal(incident.id, { ... });
 *
 * Each stage records a tamper-evident audit event with the regime,
 * incident ID, stage, due-by timestamp, and operator-supplied
 * payload. The `persist` hook writes to the operator's incident
 * registry (DB / SIEM / SOAR system); audits give regulator-friendly
 * proof-of-process when the primitive is queried later.
 *
 * Late-stage detection (filing past the due-by) is recorded with a
 * `lateBy` field on the audit metadata and `outcome: "late"`, so
 * regulator audits can distinguish "filed on time" from "filed late
 * but eventually". Refusing to record at all would lose the data;
 * the framework's posture is "always record, always flag late".
 */

var C = require("./constants");
var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
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

// Regime defaults — operators select these via opts.regime so the
// per-regime deadline shape is the framework default, not something
// the operator has to redefine each time. Operators with mixed
// regimes per incident pick the shortest deadline (the "first wall
// to hit" rule). Per-regime overrides go on opts.deadlines and
// override the regime defaults.
var REGIME_DEADLINES = Object.freeze({
  // GDPR Article 33 §1: notify within 72 hours of awareness.
  // No formal "initial" stage — the framework adds an internal
  // 24-hour initial-warning checkpoint as a practical posture.
  gdpr: Object.freeze({
    initial:      C.TIME.hours(24),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(30),
  }),
  // NIS2 Directive Article 23 §4: early warning within 24h, full
  // notification within 72h, final report within 1 month.
  nis2: Object.freeze({
    initial:      C.TIME.hours(24),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(30),
  }),
  // DORA (EU Digital Operational Resilience Act) Art. 19 + RTS (EU)
  // 2024/1772 Art. 5: initial within 4h of classifying the incident as
  // major (outer bound 24h from awareness), intermediate within 72h of the
  // initial notification, final within 1 month of the intermediate report.
  // (intermediate was 24h here, contradicting lib/dora.js's 72h — the RTS
  // value is 72h from the initial notification; aligned.)
  dora: Object.freeze({
    initial:      C.TIME.hours(4),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(30),
  }),
  // CRA (EU Cyber Resilience Act) Article 14: early warning within
  // 24h, vulnerability/incident notification within 72h, final
  // report within 14 days.
  cra: Object.freeze({
    initial:      C.TIME.hours(24),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(14),
  }),
  // HIPAA Breach Notification Rule (45 CFR §164.404 etc.): notify
  // affected individuals within 60 days; HHS within 60 days for
  // breaches affecting 500+ individuals (annually otherwise). The
  // initial / intermediate stages have no statutory deadline; we
  // adopt the EU 24/72-hour internal checkpoints as good operator
  // practice.
  hipaa: Object.freeze({
    initial:      C.TIME.hours(24),
    intermediate: C.TIME.hours(72),
    final:        C.TIME.days(60),
  }),
});

function _resolveDeadlines(regime, override) {
  // Own-key lookup only: `regime` is operator-supplied and free-form, so a
  // value colliding with an Object.prototype member ("valueOf", "toString",
  // "constructor", ...) must fall back to DEFAULT_DEADLINES, not resolve to the
  // inherited prototype function (which would make every dueBy NaN and report a
  // missed deadline as met). Unknown-but-benign regimes fall back the same way.
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

  // In-memory registry — operators wire `persist` for durable
  // storage. The in-memory map is for unit tests + small operator
  // deployments that don't yet wire a DB-backed registry.
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
      stages:       {},                                                                  // populated by recordInitial / recordIntermediate / recordFinal
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
    if (onStage) {
      try { onStage({ incidentId: incidentId, stage: stage, dueBy: dueBy, late: late, regime: rec.regime, fields: payload }); }
      catch (_e) { /* drop-silent — operator hook */ }
    }
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

  // Operator-facing summary for dashboards / regulator-prep — counts
  // open / late / closed across all tracked regimes.
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

// Breach detection -> notification running clock. The reporter
// (`create`) computes the static per-stage deadlines; this clock turns
// them into a live escalation loop: it tracks open incident records and,
// on each tick, fires "approaching" warnings as a stage's deadline nears
// and a "passed" alert when it elapses — once per (incident, stage,
// state) so a busy tick interval can't storm the operator. It re-uses
// the reporter's REGIME_DEADLINES / dueBy timestamps and re-encodes no
// jurisdiction hour-counts (GDPR Art.33 72h, NIS2 Art.23(4) 24h, DORA
// Art.19 + RTS 2024/1772 4h, CRA Art.14, HIPAA 45 CFR 164.404/408).
// `approachThresholds` are unitless proportions of detected-to-due.
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

  var tracked = new Map();   // incidentId -> { detectedAt, dueBy, regime, acked, fired }
  var timer = null;

  var _emit = audit().namespaced("incident.report.clock", auditOn);
  function _notify(payload) {
    if (!notify) return;
    try {
      var r = notify.send(payload);
      if (r && typeof r.then === "function") r.then(null, function () {});
    } catch (_e) { /* drop-silent — escalation is best-effort, never crashes a tick */ }
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

  // Pure evaluation seam — operators (and tests) can pass an explicit
  // nowMs. Each (incident, stage, state) fires AT MOST once; a stage
  // that has been acknowledged is skipped entirely.
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

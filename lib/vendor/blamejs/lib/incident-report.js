// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.incident.report
 * @nav    Compliance
 * @title  Incident Report
 * @slug   incident-report
 *
 * @intro
 *   Staged incident reporting against the clock a regime imposes. An
 *   incident is opened with the regime it falls under, and the deadlines for
 *   the initial, intermediate and final reports follow from that: four hours
 *   for a DORA initial notification, twenty-four for GDPR, NIS2, the CRA and
 *   HIPAA, seventy-two hours for every intermediate report, and a final
 *   report at fourteen, thirty or sixty days depending on the regime.
 *
 *   One incident often reports under more than one regime, which is why the
 *   deadlines belong to the incident rather than the deployment. The regime
 *   is named when the incident is opened, so an operator is not computing
 *   dates during an incident.
 *
 *   Every deadline is measured from <code>detectedAt</code>, the moment the
 *   organization became aware, and not from the moment the incident was
 *   recorded. That is what the regimes say, and it means an incident entered
 *   two hours after detection already has two hours gone.
 *
 *   The deadline clock watches the open incidents and notifies as each
 *   deadline approaches, at half, three quarters and nine tenths of the
 *   window by default. It stops tracking an incident once its submission is
 *   acknowledged, so what remains is what is still outstanding.
 *
 * @card
 *   Staged incident reporting on each regime's own clock, from DORA's
 *   four-hour initial notification to a sixty-day HIPAA final report, with a
 *   deadline watcher that notifies before each window closes.
 */

var C = require("./constants");
var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");
var nodeTypes = require("node:util").types;
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

function _snapshotPayload(payload) {
  if (!payload || typeof payload !== "object") return payload || {};
  return _frozenCopy(payload);
}

var MAX_RECORD_DEPTH = 512;

function _assertSealable(value) {
  _frozenCopy(value);
  return value;
}

function _frozenCopy(value, seen, depth) {
  if (value === null || typeof value !== "object") return value;
  depth = depth || 0;
  if (depth > MAX_RECORD_DEPTH) {
    throw new IncidentReportError("incident-report/record-too-deep",
      "a record nested deeper than " + MAX_RECORD_DEPTH + " levels cannot be " +
      "sealed; file the evidence as a flatter structure");
  }
  if (nodeTypes.isDate(value)) return new Date(value.getTime());
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (nodeTypes.isDataView(value)) {
    return new DataView(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  if (ArrayBuffer.isView(value)) return value.slice();
  if (nodeTypes.isAnyArrayBuffer(value)) return value.slice(0);
  if (nodeTypes.isRegExp(value)) {
    // allow:dynamic-regex — source and flags are read off a RegExp the caller already compiled, so this recompiles that same pattern and admits nothing new
    return new RegExp(value.source, value.flags);
  }
  seen = seen || new Map();
  if (seen.has(value)) return seen.get(value);
  var next = depth + 1;
  if (nodeTypes.isMap(value)) {
    var map = new Map();
    seen.set(value, map);
    value.forEach(function (v, k) {
      map.set(_frozenCopy(k, seen, next), _frozenCopy(v, seen, next));
    });
    return map;
  }
  if (nodeTypes.isSet(value)) {
    var set = new Set();
    seen.set(value, set);
    value.forEach(function (v) { set.add(_frozenCopy(v, seen, next)); });
    return set;
  }
  if (Array.isArray(value)) {
    var arr = [];
    seen.set(value, arr);
    for (var i = 0; i < value.length; i++) arr.push(_frozenCopy(value[i], seen, next));
    return Object.freeze(arr);
  }
  var out = {};
  seen.set(value, out);
  var keys = Object.keys(value);
  for (var k = 0; k < keys.length; k++) {
    Object.defineProperty(out, keys[k], {
      value:      _frozenCopy(value[keys[k]], seen, next),
      enumerable: true, writable: true, configurable: true,
    });
  }
  return Object.freeze(out);
}

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

/**
 * @primitive b.incident.report.create
 * @signature b.incident.report.create(opts?)
 * @since     0.8.44
 * @status    stable
 * @compliance gdpr, hipaa, soc2
 * @related   b.incident.report.createDeadlineClock, b.nis2.report.create, b.dora.create
 *
 * Open an incident register. The returned object answers `open`,
 * `recordInitial`, `recordIntermediate`, `recordFinal`, `get`, `list` and
 * `status`.
 *
 * `status()` answers across the register, not per incident: `total`, how many
 * are `open` and `closed`, and a `late` count for each of the three stages.
 * Which stage one incident owes next comes from `get(id)`.
 *
 * `open(spec)` requires two fields. `regime` decides the deadlines: `gdpr`,
 * `nis2`, `dora`, `cra` and `hipaa` are known, and any other string is
 * accepted and takes the default twenty-four hour, seventy-two hour and
 * thirty-day windows; an empty or non-string one raises
 * `incident-report/bad-regime`, because an incident with no regime has no
 * deadline. `detectedAt` must be a finite epoch-millisecond timestamp and has
 * no default (`incident-report/bad-detected-at`): every deadline is computed
 * from it, so a guessed value would produce the wrong one.
 *
 * `scope`, `summary` and `impact` are recorded when given and stored as
 * `null` otherwise. They are what the filings are written from, so an incident
 * opened without them has a deadline and nothing to report against it.
 *
 * `deadlines` overrides any of the three windows, per register.
 *
 * `persist` is an outbound sink, not storage the register reads back: it is
 * called with each record as it is written, and `create` always starts empty.
 * There is no restoration path, and `open` is not one, since it mints a new
 * id, empties `stages` and clears `closedAt`: replaying a persisted record
 * through it would turn a filed incident back into an outstanding one.
 *
 * So a restart loses `get`, `list`, `status` and the deadline clock for every
 * incident opened before it. An incident usually outlasts the process
 * handling it, so treat what `persist` receives as the record of what
 * happened, and read it with the deployment's own tooling rather than
 * expecting the register to come back.
 *
 * `onStage` is called as each stage is recorded, with one event object
 * carrying `incidentId`, `stage`, `dueBy`, `late` and `regime`, plus `fields`,
 * the payload that stage was recorded with. This is where a deployment wires
 * its own notification; `late` is the field worth routing on.
 *
 * A stage keeps a structured copy of the fields it was filed with, not the
 * object that was passed, so mutating or reusing that object afterwards does
 * not change what the record says was filed. `onStage` still receives the
 * object as given.
 *
 * The copy holds the data rather than the classes around it. Dates, Maps, Sets
 * and cycles survive; a `Buffer` comes back as a `Uint8Array` over the same
 * bytes, and a value whose `toJSON` lives on its prototype comes back as a
 * plain object, so serializing the record can differ from serializing what was
 * passed. Pass plain data for anything a filing will be rendered from.
 *
 * A payload holding something that cannot be copied at all, such as a
 * function, is kept by reference instead of being emptied, since losing the
 * filing's contents is worse than sharing the object.
 *
 * `audit` is `false` to stay silent, `true` or omitted for the framework
 * chain, or a configuration object such as `{ sink: yourAudit }` to send the
 * events somewhere else. Anything else raises `incident-report/bad-opt`: a
 * string or a number was read as "not false" and left the events on while the
 * configuration said they were off.
 *
 * @opts
 *   deadlines: object,   // initial / intermediate / final, in ms
 *   onStage:   object,   // function (event) per stage; see the prose for its fields
 *   persist:   object,   // function (record) per write; not read back
 *   now:       object,   // function returning epoch ms; for tests
 *   audit:     boolean,  // false silences the audit events
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var incidents = b.incident.report.create();
 *   var rec = await incidents.open({
 *     regime:     "dora",
 *     detectedAt: Date.now(),
 *     scope:      "payments-api",
 *     summary:    "Elevated error rate from one provider",
 *     impact:     "degraded",
 *   });
 *   await incidents.recordInitial(rec.id, { reportedTo: "BaFin" });
 *   incidents.status();            // → { total, open, closed, late: { … } }
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "persist", "onStage", "deadlines", "now",
  ], "incident.report");
  if (typeof opts.audit !== "boolean") {
    validateOpts.optionalPlainObject(opts.audit, "incident.report: opts.audit",
      IncidentReportError, "incident-report/bad-opt",
      "must be false, true, or an audit configuration object such as { sink: yourAudit }");
  }

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
      scope:        _frozenCopy(spec.scope) || null,
      summary:      _frozenCopy(spec.summary) || null,
      impact:       _frozenCopy(spec.impact) || null,
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
    incidents.set(id, _assertSealable(record));
    _emitAudit("opened", "success", {
      incidentId: id, regime: spec.regime, detectedAt: spec.detectedAt,
      dueByInitial:      record.dueBy.initial,
      dueByIntermediate: record.dueBy.intermediate,
      dueByFinal:        record.dueBy.final,
    });
    _emitMetric("opened", 1, { regime: spec.regime });
    var sealed = _frozenCopy(record);
    if (persist) {
      try { await persist(sealed); }
      catch (e) { _emitAudit("persist_failed", "failure", { incidentId: id, error: (e && e.message) || String(e) }); }
    }
    return sealed;
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
    var entry = {
      filedAt:  nowMs,
      dueBy:    dueBy,
      late:     late,
      lateBy:   lateBy,
      payload:  _snapshotPayload(payload),
    };
    var probe = { stages: {} };
    probe.stages[stage] = entry;
    rec.stages[stage] = _frozenCopy(probe).stages[stage];
    if (stage === "final") rec.closedAt = nowMs;

    _emitAudit("stage_recorded", late ? "late" : "success", {
      incidentId: incidentId, regime: rec.regime, stage: stage,
      dueBy: dueBy, filedAt: nowMs, late: late, lateBy: lateBy,
    });
    _emitMetric("stage_recorded", 1, { regime: rec.regime, stage: stage, late: String(late) });
    safeAsync.safeInvoke(onStage,
      { incidentId: incidentId, stage: stage, dueBy: dueBy, late: late, regime: rec.regime, fields: payload });
    var sealed = _frozenCopy(rec);
    if (persist) {
      try { await persist(sealed); }
      catch (e) { _emitAudit("persist_failed", "failure", { incidentId: incidentId, stage: stage, error: (e && e.message) || String(e) }); }
    }
    return sealed;
  }

  function recordInitial(incidentId, payload)      { return _recordStage(incidentId, "initial",      payload); }
  function recordIntermediate(incidentId, payload) { return _recordStage(incidentId, "intermediate", payload); }
  function recordFinal(incidentId, payload)        { return _recordStage(incidentId, "final",        payload); }

  function get(incidentId) {
    var rec = incidents.get(incidentId);
    return rec ? _frozenCopy(rec) : null;
  }
  function list() {
    var out = [];
    incidents.forEach(function (rec) { out.push(_frozenCopy(rec)); });
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

/**
 * @primitive b.incident.report.createDeadlineClock
 * @signature b.incident.report.createDeadlineClock(opts?)
 * @since     0.8.44
 * @status    stable
 * @related   b.incident.report.create
 *
 * Watch open incidents and notify before each reporting deadline. The clock
 * answers `track`, `untrack`, `acknowledgeSubmission`, `tick`, `start`, `stop`
 * and `status`.
 *
 * `track(record)` starts watching one incident. Each tick measures how much of
 * the window has elapsed and notifies for the highest threshold that has been
 * crossed and not yet fired, once per threshold per stage: half, three
 * quarters and nine tenths of the window by default. A tick that jumps past
 * more than one threshold therefore sends one alert naming the highest, not
 * one per threshold. A threshold outside the open interval between 0 and 1
 * raises `incident-report/bad-threshold`, since a threshold at 0 fires
 * immediately and one at 1 fires only once the deadline has passed.
 *
 * `acknowledgeSubmission` is how an incident stops being chased: once the
 * stage is submitted, its deadline no longer raises an alert.
 * `autoStart` is on, so the clock begins ticking every minute when it is
 * created; `tick()` drives it by hand instead, which is how it is tested.
 * `status()` answers `{ tracked, running, intervalMs }`, which is the clock's
 * own state rather than any incident's.
 *
 * `autoStart` and `audit` must be booleans, raising
 * `incident-report/bad-opt` otherwise. Anything else was read as "not false",
 * so a typo left the timer running and the audit events on while the
 * configuration said they were off.
 *
 * @opts
 *   notify:             object,   // object with send(message); receives each alert
 *   approachThresholds: array,    // fractions in (0,1); default [0.5, 0.75, 0.9]
 *   intervalMs:         number,   // default 1 minute
 *   autoStart:          boolean,  // false leaves it to tick() or start()
 *   now:                object,   // function returning epoch ms; for tests
 *   audit:              boolean,  // false silences the audit events
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var clock = b.incident.report.createDeadlineClock({
 *     autoStart: false,
 *     notify:    { send: function (m) { console.warn(m.summary); } },
 *   });
 *   clock.track(rec);
 *   clock.tick();                  // → notifies the highest threshold crossed
 *   clock.status();                // → { tracked, running, intervalMs }
 *   clock.acknowledgeSubmission(rec.id, "initial");
 *   clock.stop();
 */
function createDeadlineClock(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "notify", "approachThresholds", "intervalMs", "autoStart", "now",
  ], "incident.report.createDeadlineClock");
  validateOpts.optionalBoolean(opts.audit,
    "incident.report.createDeadlineClock: audit",
    IncidentReportError, "incident-report/bad-opt");
  validateOpts.optionalBoolean(opts.autoStart,
    "incident.report.createDeadlineClock: autoStart",
    IncidentReportError, "incident-report/bad-opt");

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
  _frozenCopy:           _frozenCopy,
  _assertSealable:       _assertSealable,
  IncidentReportError:   IncidentReportError,
  REGIME_DEADLINES:      REGIME_DEADLINES,
  DEFAULT_DEADLINES:     DEFAULT_DEADLINES,
  VALID_STAGES:          Object.keys(VALID_STAGES),
};

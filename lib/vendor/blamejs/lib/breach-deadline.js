"use strict";
/**
 * b.breach.deadline + b.breach.report — US state breach-notification
 * deadline registry + reporter.
 *
 * Every US state + territory has its own breach-notification statute
 * with a deadline (60 days, 45 days, "without unreasonable delay").
 * Operators detecting a breach affecting residents in multiple states
 * face a fan-out problem: which state(s), what deadline for each,
 * what notice content. The registry encodes the per-jurisdiction
 * deadline + statutory citation; the reporter surfaces an operator-
 * friendly "what do I owe and when" plan.
 *
 *   var deadlines = b.breach.deadline.forStates(["CA", "NY", "TX"], breachDetectedAt);
 *   // -> [{ state: "CA", dueBy: ..., statute: "Cal. Civ. Code §1798.82" }, ...]
 *
 *   var reporter = b.breach.report.create({ audit: b.audit });
 *   var rec = reporter.open({
 *     detectedAt: Date.now(),
 *     affectedStates: ["CA", "NY", "TX"],
 *     scope:    "data-confidentiality-breach",
 *     impact:   { individualsAffected: 5000 },
 *   });
 *   await reporter.fileNotice(rec.id, "CA", { ... });
 *
 * The registry is statutory data — operators don't override it
 * without legal counsel review. Updates ride into the framework via
 * patch releases when state legislatures amend their breach laws.
 */

var C = require("./constants");
var defineClass = require("./framework-error").defineClass;
var lazyRequire = require("./lazy-require");

var audit = lazyRequire(function () { return require("./audit"); });
var incidentReport = lazyRequire(function () { return require("./incident-report"); });

var BreachError = defineClass("BreachError", { alwaysPermanent: true });

// Per-state deadlines as days-from-detection. "WITHOUT_UNREASONABLE_DELAY"
// is encoded as a sentinel; operators interpret as "as soon as
// reasonably possible, never later than the longest acceptable for
// the state's tort-liability standard". Common interpretation: 60 days
// is a defensible ceiling, but operators with active forensics may
// stretch to 90 days with documented investigative justification.
var WITHOUT_UNREASONABLE_DELAY = "WITHOUT_UNREASONABLE_DELAY";

var STATE_DEADLINES = Object.freeze({
  // Each entry: { days, statute, asapCeilingDays }
  // Days = statutory hard deadline in days. asapCeilingDays = the
  // operator-defensible ceiling for "without unreasonable delay" states.
  AL: { days: 45,  statute: "Ala. Code §8-38-5" },
  AK: { days: 45,  statute: "Alaska Stat. §45.48.010" },
  AZ: { days: 45,  statute: "Ariz. Rev. Stat. §18-552" }, /* allow:raw-time-literal — statutory deadline days */
  AR: { days: 45,  statute: "Ark. Code §4-110-105" }, /* allow:raw-time-literal — statutory deadline days */
  CA: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Cal. Civ. Code §1798.82", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  CO: { days: 30,  statute: "Colo. Rev. Stat. §6-1-716" }, /* allow:raw-time-literal — statutory deadline days */
  CT: { days: 60,  statute: "Conn. Gen. Stat. §36a-701b" }, /* allow:raw-time-literal — statutory deadline days */
  DE: { days: 60,  statute: "Del. Code §12B-102" }, /* allow:raw-time-literal — statutory deadline days */
  DC: { days: 60,  statute: "D.C. Code §28-3852" }, /* allow:raw-time-literal — statutory deadline days */
  FL: { days: 30,  statute: "Fla. Stat. §501.171" }, /* allow:raw-time-literal — statutory deadline days */
  GA: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Ga. Code §10-1-911", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  HI: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Haw. Rev. Stat. §487N-2", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  ID: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Idaho Code §28-51-105", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  IL: { days: WITHOUT_UNREASONABLE_DELAY, statute: "815 ILCS 530/10", asapCeilingDays: 45 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  IN: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Ind. Code §24-4.9-3-3", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  IA: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Iowa Code §715C.2", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  KS: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Kan. Stat. §50-7a02", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  KY: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Ky. Rev. Stat. §365.732", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  LA: { days: 60,  statute: "La. Rev. Stat. §51:3074" }, /* allow:raw-time-literal — statutory deadline days */
  ME: { days: 30,  statute: "Me. Rev. Stat. tit. 10 §1348" },
  MD: { days: 45,  statute: "Md. Code Com. Law §14-3504" }, /* allow:raw-time-literal — statutory deadline days */
  MA: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Mass. Gen. Laws ch. 93H §3", asapCeilingDays: 30 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  MI: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Mich. Comp. Laws §445.72", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  MN: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Minn. Stat. §325E.61", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  MS: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Miss. Code §75-24-29", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  MO: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Mo. Rev. Stat. §407.1500", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  MT: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Mont. Code §30-14-1704", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  NE: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Neb. Rev. Stat. §87-803", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  NV: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Nev. Rev. Stat. §603A.220", asapCeilingDays: 45 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  NH: { days: WITHOUT_UNREASONABLE_DELAY, statute: "N.H. Rev. Stat. §359-C:20", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  NJ: { days: WITHOUT_UNREASONABLE_DELAY, statute: "N.J. Stat. §56:8-163", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  NM: { days: 45,  statute: "N.M. Stat. §57-12C-6" }, /* allow:raw-time-literal — statutory deadline days */
  NY: { days: WITHOUT_UNREASONABLE_DELAY, statute: "N.Y. Gen. Bus. Law §899-aa (SHIELD Act)", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  NC: { days: WITHOUT_UNREASONABLE_DELAY, statute: "N.C. Gen. Stat. §75-65", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  ND: { days: WITHOUT_UNREASONABLE_DELAY, statute: "N.D. Cent. Code §51-30-02", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  OH: { days: 45,  statute: "Ohio Rev. Code §1349.19" }, /* allow:raw-time-literal — statutory deadline days */
  OK: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Okla. Stat. tit. 24 §163", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  OR: { days: 45,  statute: "Or. Rev. Stat. §646A.604" }, /* allow:raw-time-literal — statutory deadline days */
  PA: { days: WITHOUT_UNREASONABLE_DELAY, statute: "73 Pa. Cons. Stat. §2303", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  PR: { days: 10,  statute: "P.R. Laws Ann. tit. 10 §4051 (Citizen Information Security Act)" }, /* allow:raw-time-literal — statutory deadline days */
  RI: { days: 45,  statute: "R.I. Gen. Laws §11-49.3-3" }, /* allow:raw-time-literal — statutory deadline days */
  SC: { days: WITHOUT_UNREASONABLE_DELAY, statute: "S.C. Code §39-1-90", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  SD: { days: 60,  statute: "S.D. Codified Laws §22-40-20" }, /* allow:raw-time-literal — statutory deadline days */
  TN: { days: 45,  statute: "Tenn. Code §47-18-2107" }, /* allow:raw-time-literal — statutory deadline days */
  TX: { days: 60,  statute: "Tex. Bus. & Com. Code §521.053" }, /* allow:raw-time-literal — statutory deadline days */
  UT: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Utah Code §13-44-202", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  VT: { days: 45,  statute: "Vt. Stat. tit. 9 §2435" }, /* allow:raw-time-literal — statutory deadline days */
  VA: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Va. Code §18.2-186.6", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  WA: { days: 30,  statute: "Wash. Rev. Code §19.255.010" }, /* allow:raw-time-literal — statutory deadline days */
  WV: { days: WITHOUT_UNREASONABLE_DELAY, statute: "W. Va. Code §46A-2A-102", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
  WI: { days: 45,  statute: "Wis. Stat. §134.98" }, /* allow:raw-time-literal — statutory deadline days */
  WY: { days: WITHOUT_UNREASONABLE_DELAY, statute: "Wyo. Stat. §40-12-502", asapCeilingDays: 60 }, /* allow:raw-time-literal — statutory ASAP ceiling days */
});

function _msPerDay() { return C.TIME.days(1); }

function _deadlineFor(state, detectedAtMs) {
  var rec = STATE_DEADLINES[state.toUpperCase()];
  if (!rec) {
    throw new BreachError("breach/unknown-state",
      "breach.deadline: unknown state code '" + state + "' (use US 2-letter codes)");
  }
  if (rec.days === WITHOUT_UNREASONABLE_DELAY) {
    return {
      state:    state.toUpperCase(),
      kind:     "as-soon-as-possible",
      ceilingDays: rec.asapCeilingDays,
      ceilingDueBy: detectedAtMs + (rec.asapCeilingDays * _msPerDay()),
      statute:  rec.statute,
    };
  }
  return {
    state:    state.toUpperCase(),
    kind:     "hard-deadline",
    days:     rec.days,
    dueBy:    detectedAtMs + (rec.days * _msPerDay()),
    statute:  rec.statute,
  };
}

function forStates(states, detectedAtMs) {
  if (!Array.isArray(states)) {
    throw new BreachError("breach/bad-states",
      "breach.deadline.forStates: states must be an array of US state codes");
  }
  if (typeof detectedAtMs !== "number" || !isFinite(detectedAtMs)) {
    throw new BreachError("breach/bad-detected-at",
      "breach.deadline.forStates: detectedAtMs must be a finite Unix-ms timestamp");
  }
  var out = [];
  for (var i = 0; i < states.length; i++) {
    out.push(_deadlineFor(states[i], detectedAtMs));
  }
  return out;
}

// b.breach.report — operator-side breach-tracking that wraps the
// deadline registry and tracks per-state filing status.
function createReporter(opts) {
  opts = opts || {};
  var now = typeof opts.now === "function" ? opts.now : function () { return Date.now(); };
  var seq = 0;
  var breaches = new Map();

  var _emitAudit = audit().namespaced("breach.report", opts.audit);

  function open(spec) {
    if (!spec || typeof spec !== "object") {
      throw new BreachError("breach-report/bad-spec",
        "breach.report.open: spec must be an object with { detectedAt, affectedStates, scope, impact }");
    }
    if (typeof spec.detectedAt !== "number" || !isFinite(spec.detectedAt)) {
      throw new BreachError("breach-report/bad-detected-at",
        "breach.report.open: spec.detectedAt must be a finite Unix-ms timestamp");
    }
    if (!Array.isArray(spec.affectedStates) || spec.affectedStates.length === 0) {
      throw new BreachError("breach-report/bad-states",
        "breach.report.open: spec.affectedStates must be a non-empty array of US state codes");
    }
    seq += 1;
    var id = "breach-" + new Date(spec.detectedAt).toISOString().replace(/[:.]/g, "-") + "-" + seq;
    var deadlines = forStates(spec.affectedStates, spec.detectedAt);
    var rec = {
      id:               id,
      detectedAt:       spec.detectedAt,
      affectedStates:   spec.affectedStates.map(function (s) { return s.toUpperCase(); }),
      scope:            spec.scope || null,
      impact:           spec.impact || null,
      deadlines:        deadlines,
      filings:          {},                                                              // state -> { filedAt, late }
      openedAt:         now(),
      closedAt:         null,
    };
    breaches.set(id, rec);
    _emitAudit("opened", "success", {
      breachId: id,
      states:   rec.affectedStates,
      detectedAt: spec.detectedAt,
    });
    return rec;
  }

  async function fileNotice(breachId, state, fields) {
    var rec = breaches.get(breachId);
    if (!rec) {
      throw new BreachError("breach-report/unknown-breach",
        "breach.report.fileNotice: no breach with id '" + breachId + "'");
    }
    var stateUp = state.toUpperCase();
    if (rec.affectedStates.indexOf(stateUp) === -1) {
      throw new BreachError("breach-report/state-not-tracked",
        "breach.report.fileNotice: state '" + stateUp + "' is not in this breach's affectedStates");
    }
    if (rec.filings[stateUp]) {
      throw new BreachError("breach-report/already-filed",
        "breach.report.fileNotice: filing for state '" + stateUp + "' is already recorded");
    }
    var deadline = rec.deadlines.filter(function (d) { return d.state === stateUp; })[0];
    var filedAt = now();
    var dueBy = deadline.kind === "hard-deadline" ? deadline.dueBy : deadline.ceilingDueBy;
    var late = filedAt > dueBy;
    rec.filings[stateUp] = {
      filedAt: filedAt,
      dueBy:   dueBy,
      late:    late,
      lateBy:  late ? (filedAt - dueBy) : 0,
      payload: fields || {},
    };
    if (Object.keys(rec.filings).length === rec.affectedStates.length) {
      rec.closedAt = filedAt;
    }
    _emitAudit("notice_filed", late ? "late" : "success", {
      breachId: breachId, state: stateUp, dueBy: dueBy, late: late,
      lateBy: rec.filings[stateUp].lateBy,
    });
    return rec;
  }

  function get(id) { return breaches.get(id) || null; }
  function list() { var out = []; breaches.forEach(function (rec) { out.push(rec); }); return out; }
  function pending(breachId) {
    var rec = breaches.get(breachId);
    if (!rec) return [];
    var pendingStates = [];
    for (var i = 0; i < rec.affectedStates.length; i++) {
      if (!rec.filings[rec.affectedStates[i]]) {
        pendingStates.push(rec.deadlines.filter(function (d) { return d.state === rec.affectedStates[i]; })[0]);
      }
    }
    return pendingStates;
  }

  return {
    open:         open,
    fileNotice:   fileNotice,
    get:          get,
    list:         list,
    pending:      pending,
  };
}

// Resolve a per-state breach deadline entry to its wall-clock due-by ms.
// Hard-deadline states expose `dueBy`; "without unreasonable delay"
// states expose the operator-defensible `ceilingDueBy`.
function _dueByOf(deadlineEntry) {
  return deadlineEntry.kind === "hard-deadline"
    ? deadlineEntry.dueBy
    : deadlineEntry.ceilingDueBy;
}

/**
 * @primitive  b.breach.deadline.createClock
 * @signature  b.breach.deadline.createClock(opts?)
 * @since      0.14.18
 * @status     stable
 * @compliance gdpr, soc2
 *
 * Detection-to-notification running clock for US state breach
 * deadlines. `forStates` / `report.create` compute the static
 * per-state due-by timestamps; this clock turns them into a live
 * escalation loop. It composes the regime-agnostic
 * `b.incident.report.createDeadlineClock` (one underlying clock,
 * one synthetic incident per affected state) so a breach with
 * residents in many states escalates each state's statutory wall
 * independently: an "approaching" warning fires as a state's
 * deadline nears, a "passed" alert fires when it elapses, and
 * `acknowledgeSubmission(breachId, state)` silences a state once its
 * notice is filed. Each (breach, state) escalation fires at most once
 * per phase regardless of tick cadence.
 *
 * The per-state deadline carries the same statutory data the registry
 * encodes — hard-deadline states (e.g. TX Tex. Bus. & Com. Code
 * §521.053, 60 days; CO Colo. Rev. Stat. §6-1-716, 30 days) use the
 * statutory wall; "without unreasonable delay" states (e.g. CA Cal.
 * Civ. Code §1798.82) use the operator-defensible ASAP ceiling. The
 * statutory hour/day counts are never re-encoded here — they are read
 * from STATE_DEADLINES. This mirrors the multi-regime clock in
 * `b.incident.report` (GDPR Art.33 72h, NIS2 Art.23(4) 24h, DORA
 * Art.19 4h, HIPAA 45 CFR 164.404/408 60 days) for the federal regimes
 * that run alongside the state statutes.
 *
 * @opts
 *   audit:              boolean,        // emit tamper-evident clock audits — default true
 *   notify:             object,         // { send(payload) } escalation sink — best-effort, drop-silent
 *   approachThresholds: number[],       // unitless proportions of detected-to-due — default [0.5, 0.75, 0.9]
 *   intervalMs:         number,         // auto-tick cadence — default C.TIME.minutes(1)
 *   autoStart:          boolean,        // start the auto-tick timer immediately — default true
 *   now:                function,       // injectable clock source for testing — default Date.now
 *
 * @example
 *   var reporter = b.breach.report.create({ audit: b.audit });
 *   var rec = reporter.open({
 *     detectedAt:     Date.now(),
 *     affectedStates: ["CA", "TX"],
 *     impact:         { individualsAffected: 5000 },
 *   });
 *   var clock = b.breach.deadline.createClock({
 *     notify:    { send: function (p) { alertOnCall(p); } },
 *     autoStart: false,
 *   });
 *   clock.trackReport(rec);
 *   // later, on each operator-controlled evaluation:
 *   clock.tick();
 *   await reporter.fileNotice(rec.id, "CA", { method: "email" });
 *   clock.acknowledgeSubmission(rec.id, "CA");   // silence CA escalation
 */
function createDeadlineClock(opts) {
  opts = opts || {};
  // Compose the regime-agnostic clock — it owns the tick loop,
  // once-per-phase firing, audit/notify fan-out, and timer lifecycle.
  // The breach clock only adapts per-state breach deadlines onto its
  // single-stage `final` slot and tracks the (breach, state) keying.
  var inner = incidentReport().createDeadlineClock({
    audit:              opts.audit,
    notify:             opts.notify,
    approachThresholds: opts.approachThresholds,
    intervalMs:         opts.intervalMs,
    autoStart:          opts.autoStart,
    now:                opts.now,
  });

  // breachId -> { detectedAt, states: { STATE -> innerIncidentId } }
  var tracked = new Map();

  function _innerId(breachId, state) {
    return breachId + "::" + state;
  }

  function trackReport(report) {
    if (!report || typeof report !== "object" || typeof report.id !== "string" || report.id.length === 0) {
      throw new BreachError("breach-clock/bad-report",
        "breach.deadline.createClock.trackReport: report must be a breach.report record with a string id");
    }
    if (typeof report.detectedAt !== "number" || !isFinite(report.detectedAt)) {
      throw new BreachError("breach-clock/bad-detected-at",
        "breach.deadline.createClock.trackReport: report.detectedAt must be a finite Unix-ms timestamp");
    }
    if (!Array.isArray(report.deadlines) || report.deadlines.length === 0) {
      throw new BreachError("breach-clock/bad-deadlines",
        "breach.deadline.createClock.trackReport: report.deadlines must be the non-empty per-state array from breach.report.open");
    }
    var entry = tracked.get(report.id) || { detectedAt: report.detectedAt, states: {} };
    for (var i = 0; i < report.deadlines.length; i += 1) {
      var d = report.deadlines[i];
      var state = d.state;
      if (entry.states[state]) continue;   // idempotent re-track of the same state
      var innerId = _innerId(report.id, state);
      // The statutory wall is carried on the `final` stage so the
      // approach-then-pass escalation runs against the per-state
      // deadline; initial/intermediate are left undefined (the inner
      // tick skips stages with no due-by).
      inner.track({
        id:         innerId,
        detectedAt: report.detectedAt,
        regime:     d.statute || state,
        dueBy:      { final: _dueByOf(d) },
      });
      entry.states[state] = innerId;
    }
    tracked.set(report.id, entry);
    return report.id;
  }

  function untrack(breachId) {
    var entry = tracked.get(breachId);
    if (!entry) return false;
    var states = Object.keys(entry.states);
    for (var i = 0; i < states.length; i += 1) {
      inner.untrack(entry.states[states[i]]);
    }
    return tracked.delete(breachId);
  }

  function acknowledgeSubmission(breachId, state, info) {
    var entry = tracked.get(breachId);
    var stateUp = (typeof state === "string") ? state.toUpperCase() : state;
    if (!entry || !entry.states[stateUp]) {
      throw new BreachError("breach-clock/unknown-tracked-state",
        "breach.deadline.createClock.acknowledgeSubmission: no tracked breach '" + breachId + "' for state '" + state + "'");
    }
    return inner.acknowledgeSubmission(entry.states[stateUp], "final", info);
  }

  function status() {
    var innerStatus = inner.status();
    return {
      breaches:   tracked.size,
      tracked:    innerStatus.tracked,
      running:    innerStatus.running,
      intervalMs: innerStatus.intervalMs,
    };
  }

  return {
    trackReport:           trackReport,
    untrack:               untrack,
    acknowledgeSubmission: acknowledgeSubmission,
    tick:                  inner.tick,
    start:                 inner.start,
    stop:                  inner.stop,
    status:                status,
  };
}

module.exports = {
  // b.breach.deadline.* — registry lookups + running clock
  deadline: {
    forStates:                 forStates,
    createClock:               createDeadlineClock,
    STATE_DEADLINES:           STATE_DEADLINES,
    WITHOUT_UNREASONABLE_DELAY: WITHOUT_UNREASONABLE_DELAY,
  },
  // b.breach.report.create(...) — per-incident reporter
  report:      { create: createReporter },
  BreachError: BreachError,
};

"use strict";
/**
 * @module b.ddlChangeControl
 * @nav    Compliance
 * @title  DDL Change Control
 *
 * @intro
 *   Formal DDL approval / change-control workflow. SOX 404 ICFR and
 *   PCI DSS Req 6.5 / 10.7 require a documented change-control process
 *   for any schema change touching financial reporting or cardholder-
 *   data systems. The framework's existing audit emission on DDL only
 *   logs that a change happened; this primitive enforces a multi-
 *   approver, time-windowed, hash-anchored flow BEFORE the change
 *   applies.
 *
 *   Lifecycle: `propose(sql, opts)` captures the SQL under a SHA3-512
 *   hash and optional signed payload; `approve(changeId, approver)`
 *   adds an approver signature (rejecting self-approval under SOX/PCI
 *   postures); `reject(changeId, reviewer, reason)` terminates;
 *   `applyApproved(changeId, runner)` executes the SQL via the
 *   operator-supplied runner ONLY when the change has the minimum
 *   approver count, the window is open, and the stored SQL still
 *   hashes to its captured digest (defense against in-memory
 *   tampering between propose and apply).
 *
 *   Window grammar accepts `"always"` (24/7), `"Mon-Fri 09:00-17:00
 *   UTC"`, or `"Mon,Wed,Fri 14:00-18:00 UTC"`. Postures `sox-404` /
 *   `sox` / `pci-dss` enforce minimum 2 approvers and disable self-
 *   approval. Audit emissions live in the `ddl.*` namespace:
 *   `ddl.change.proposed` / `.approved` / `.rejected` / `.applied` /
 *   `.apply_refused` (the last carrying the refusal reason —
 *   insufficient-approvals / window-closed / sql-tampered / self-
 *   approval-denied). State is in-process by default; operators pass
 *   a durable `opts.store` ({ get, put, list }) for cluster-wide
 *   visibility.
 *
 * @card
 *   Formal DDL approval / change-control workflow.
 */

var validateOpts = require("./validate-opts");
var { sha3Hash, generateToken } = require("./crypto");
var C = require("./constants");
var { DdlChangeControlError } = require("./framework-error");

var STATE_PROPOSED = "proposed";
var STATE_APPROVED = "approved";
var STATE_REJECTED = "rejected";
var STATE_APPLIED  = "applied";
var STATE_FAILED   = "failed";

var POSTURES_REQUIRING_CHANGE_CONTROL = ["sox-404", "sox", "pci-dss"];

// Window spec grammar - operator-friendly subset:
//   "Mon-Fri 09:00-17:00 UTC"
//   "Mon,Wed,Fri 14:00-18:00 UTC"
//   "always"  (24/7)
var DAY_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

function _parseWindowSpec(spec) {
  if (typeof spec !== "string" || spec.length === 0) {
    throw new DdlChangeControlError("ddl-change-control/bad-window",
      "windowSpec must be a non-empty string");
  }
  var trimmed = spec.trim();
  if (trimmed.toLowerCase() === "always") {
    return { always: true };
  }
  var parts = trimmed.split(/\s+/);
  if (parts.length !== 3) {
    throw new DdlChangeControlError("ddl-change-control/bad-window",
      "windowSpec must be 'always' or '<days> <HH:MM-HH:MM> UTC' - got " + JSON.stringify(spec));
  }
  if (parts[2].toUpperCase() !== "UTC") {
    throw new DdlChangeControlError("ddl-change-control/bad-window",
      "windowSpec timezone must be UTC - got " + parts[2]);
  }
  var days = new Set();
  var dayParts = parts[0].split(",");
  for (var i = 0; i < dayParts.length; i++) {
    var dp = dayParts[i].trim().toLowerCase();
    if (dp.indexOf("-") !== -1) {
      var range = dp.split("-");
      if (range.length !== 2) {
        throw new DdlChangeControlError("ddl-change-control/bad-window",
          "windowSpec day-range must be 'A-B' - got " + dp);
      }
      var lo = DAY_NAMES.indexOf(range[0]);
      var hi = DAY_NAMES.indexOf(range[1]);
      if (lo === -1 || hi === -1) {
        throw new DdlChangeControlError("ddl-change-control/bad-window",
          "windowSpec unknown day in range " + dp);
      }
      if (lo <= hi) {
        for (var d = lo; d <= hi; d++) days.add(d);
      } else {
        for (var d2 = lo; d2 < DAY_NAMES.length; d2++) days.add(d2);
        for (var d3 = 0; d3 <= hi; d3++) days.add(d3);
      }
    } else {
      var idx = DAY_NAMES.indexOf(dp);
      if (idx === -1) {
        throw new DdlChangeControlError("ddl-change-control/bad-window",
          "windowSpec unknown day '" + dp + "'");
      }
      days.add(idx);
    }
  }
  var hourParts = parts[1].split("-");
  if (hourParts.length !== 2) {
    throw new DdlChangeControlError("ddl-change-control/bad-window",
      "windowSpec hour-range must be 'HH:MM-HH:MM' - got " + parts[1]);
  }
  var startMin = _parseHHMM(hourParts[0]);
  var endMin   = _parseHHMM(hourParts[1]);
  if (startMin >= endMin) {
    throw new DdlChangeControlError("ddl-change-control/bad-window",
      "windowSpec start must be < end - got " + parts[1]);
  }
  return { always: false, days: days, startMin: startMin, endMin: endMin };
}

function _parseHHMM(s) {
  var m = /^(\d{2}):(\d{2})$/.exec(s);
  if (!m) {
    throw new DdlChangeControlError("ddl-change-control/bad-window",
      "windowSpec time must be HH:MM - got " + s);
  }
  var hh = parseInt(m[1], 10);
  var mm = parseInt(m[2], 10);
  if (hh < 0 || hh > 23 || mm < 0 || mm > 59) {
    throw new DdlChangeControlError("ddl-change-control/bad-window",
      "windowSpec time out of range - got " + s);
  }
  return hh * 60 + mm; // allow:raw-time-literal — HH*60+MM minute-of-day conversion; coincidental multiple-of-60 factor, not a duration, C.TIME N/A
}

function _isInWindow(window, nowMs) {
  if (!window) return true;
  if (window.always) return true;
  var d = new Date(nowMs);
  var dayIdx = d.getUTCDay();
  if (!window.days.has(dayIdx)) return false;
  var min = d.getUTCHours() * 60 + d.getUTCMinutes(); // allow:raw-time-literal — HH*60+MM minute-of-day conversion; coincidental multiple-of-60 factor, not a duration, C.TIME N/A
  return min >= window.startMin && min < window.endMin;
}

function _memoryStore() {
  var byId = new Map();
  return {
    get: function (id) { return byId.get(id) || null; },
    put: function (id, change) { byId.set(id, change); },
    list: function () { return Array.from(byId.values()); },
  };
}

/**
 * @primitive b.ddlChangeControl.create
 * @signature b.ddlChangeControl.create(opts)
 * @since     0.8.48
 * @status    stable
 * @compliance sox-404, pci-dss
 * @related   b.audit, b.compliance, b.dualControl
 *
 * Build a DDL change-control workflow. Returns
 * `{ propose, approve, reject, applyApproved, list, get, posture,
 * approvers, windowSpec }`. `propose` returns `{ changeId, sqlHash }`;
 * `approve` returns `{ changeId, signaturesCount, thresholdMet }`;
 * `applyApproved` runs the SQL through the operator-supplied runner
 * and returns `{ changeId, result, durationMs }`.
 *
 * @opts
 *   audit:        Object,    // b.audit instance (safeEmit-shaped)
 *   approvers:    number,    // minimum approvals before applyApproved (default 2; ≥2 under SOX/PCI)
 *   windowSpec:   string,    // "always" | "Mon-Fri 09:00-17:00 UTC" | "Mon,Wed 14:00-18:00 UTC"
 *   posture:      string,    // "sox-404" | "sox" | "pci-dss" (forces approvers≥2 + no self-approval)
 *   signWith:     Function,  // (bytes) → signature; signs propose+approve payloads
 *   verifyWith:   Function,  // (bytes, sig) → boolean; reserved for store-backed restoration
 *   store:        Object,    // { get(id), put(id, change), list() }; default in-memory Map
 *   now:          Function,  // () → ms; testing override
 *   selfApproval: boolean,   // allow proposer to approve own change (forced false under listed postures)
 *
 * @example
 *   var ddl = b.ddlChangeControl.create({
 *     audit:      auditInstance,
 *     approvers:  2,
 *     windowSpec: "Mon-Fri 09:00-17:00 UTC",
 *     posture:    "sox-404",
 *   });
 *
 *   var p = await ddl.propose("ALTER TABLE accounts ADD COLUMN region TEXT", {
 *     proposer: "alice",
 *     reason:   "data-residency expansion",
 *     ticket:   "JIRA-123",
 *   });
 *   p.changeId;     // → "<32-hex token>"
 *   p.sqlHash;      // → "<sha3-512 hex>"
 *
 *   await ddl.approve(p.changeId, "bob");
 *   var a2 = await ddl.approve(p.changeId, "carol");
 *   a2.thresholdMet;   // → true
 *
 *   var applied = await ddl.applyApproved(p.changeId, async function (sql) {
 *     return { rowsAffected: 0 };
 *   });
 *   applied.result.rowsAffected;   // → 0
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "approvers", "windowSpec", "posture", "signWith",
    "verifyWith", "store", "now", "selfApproval",
  ], "ddlChangeControl.create");
  validateOpts.auditShape(opts.audit, "ddlChangeControl",
    DdlChangeControlError, "ddl-change-control/bad-audit");
  validateOpts.optionalFunction(opts.signWith,
    "ddlChangeControl: signWith", DdlChangeControlError, "ddl-change-control/bad-signer");
  validateOpts.optionalFunction(opts.verifyWith,
    "ddlChangeControl: verifyWith", DdlChangeControlError, "ddl-change-control/bad-verifier");
  validateOpts.optionalFunction(opts.now,
    "ddlChangeControl: now", DdlChangeControlError, "ddl-change-control/bad-now");
  validateOpts.optionalNonEmptyString(opts.posture,
    "ddlChangeControl: posture", DdlChangeControlError, "ddl-change-control/bad-posture");

  var approvers = 2;
  if (opts.approvers !== undefined) {
    if (typeof opts.approvers !== "number" || !isFinite(opts.approvers) ||
        opts.approvers < 1) {
      throw new DdlChangeControlError("ddl-change-control/bad-approvers",
        "approvers must be a positive integer");
    }
    approvers = Math.floor(opts.approvers);
  }
  var posture = opts.posture || null;
  if (posture && POSTURES_REQUIRING_CHANGE_CONTROL.indexOf(posture) !== -1 && approvers < 2) {
    throw new DdlChangeControlError("ddl-change-control/insufficient-approvers",
      "posture '" + posture + "' requires approvers >= 2 (SOX 404 / PCI-DSS 6.5)");
  }

  var window = opts.windowSpec ? _parseWindowSpec(opts.windowSpec) : null;
  var auditMod = opts.audit && typeof opts.audit.safeEmit === "function" ? opts.audit : null;
  var signWith = typeof opts.signWith === "function" ? opts.signWith : null;
  var now = typeof opts.now === "function" ? opts.now : Date.now;
  var store = opts.store && typeof opts.store === "object" &&
    typeof opts.store.get === "function" && typeof opts.store.put === "function"
    ? opts.store : _memoryStore();
  var selfApprovalAllowed = opts.selfApproval === true;
  if (posture && POSTURES_REQUIRING_CHANGE_CONTROL.indexOf(posture) !== -1) {
    selfApprovalAllowed = false;
  }

  function _emit(action, metadata, outcome) {
    if (!auditMod) return;
    try {
      auditMod.safeEmit({
        action:   action,
        outcome:  outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* audit best-effort */ }
  }

  function _hashSql(sql) {
    return sha3Hash(Buffer.from(sql, "utf8"));
  }

  async function propose(sql, options) {
    options = options || {};
    if (typeof sql !== "string" || sql.length === 0) {
      throw new DdlChangeControlError("ddl-change-control/bad-sql",
        "propose: sql must be a non-empty string");
    }
    if (typeof options.proposer !== "string" || options.proposer.length === 0) {
      throw new DdlChangeControlError("ddl-change-control/missing-proposer",
        "propose: opts.proposer is required (non-empty string)");
    }
    var changeId = generateToken(C.BYTES.bytes(16));
    var sqlHash = _hashSql(sql);
    var proposedAt = now();
    var proposalSig = signWith ? signWith(Buffer.from(
      JSON.stringify({ changeId: changeId, sqlHash: sqlHash, proposer: options.proposer, proposedAt: proposedAt }),
      "utf8"
    )) : null;
    var change = {
      changeId:    changeId,
      sqlHash:     sqlHash,
      sql:         sql,
      proposer:    options.proposer,
      reason:      options.reason || null,
      ticket:      options.ticket || null,
      proposedAt:  proposedAt,
      proposalSignature: proposalSig
        ? (Buffer.isBuffer(proposalSig) ? proposalSig.toString("base64") : String(proposalSig))
        : null,
      state:       STATE_PROPOSED,
      approvals:   [],
      rejection:   null,
      appliedAt:   null,
      applier:     null,
      applyDurationMs: null,
      applyError:  null,
    };
    store.put(changeId, change);
    _emit("ddl.change.proposed", {
      changeId: changeId, sqlHash: sqlHash, proposer: options.proposer,
      reason: options.reason || null, ticket: options.ticket || null,
    });
    return { changeId: changeId, sqlHash: sqlHash };
  }

  async function approve(changeId, approver, options) {
    options = options || {};
    if (typeof changeId !== "string" || changeId.length === 0) {
      throw new DdlChangeControlError("ddl-change-control/bad-id",
        "approve: changeId must be a non-empty string");
    }
    if (typeof approver !== "string" || approver.length === 0) {
      throw new DdlChangeControlError("ddl-change-control/missing-approver",
        "approve: approver must be a non-empty string");
    }
    var change = store.get(changeId);
    if (!change) {
      throw new DdlChangeControlError("ddl-change-control/unknown-change",
        "approve: unknown changeId '" + changeId + "'");
    }
    if (change.state === STATE_REJECTED) {
      throw new DdlChangeControlError("ddl-change-control/already-rejected",
        "approve: change '" + changeId + "' is already rejected");
    }
    if (change.state === STATE_APPLIED) {
      throw new DdlChangeControlError("ddl-change-control/already-applied",
        "approve: change '" + changeId + "' is already applied");
    }
    if (!selfApprovalAllowed && approver === change.proposer) {
      _emit("ddl.change.apply_refused", {
        changeId: changeId, reason: "self-approval-denied", actor: approver,
      }, "denied");
      throw new DdlChangeControlError("ddl-change-control/self-approval-denied",
        "approve: proposer '" + approver + "' cannot approve their own change under posture '" +
        (posture || "default") + "'");
    }
    for (var i = 0; i < change.approvals.length; i++) {
      if (change.approvals[i].approver === approver) {
        throw new DdlChangeControlError("ddl-change-control/duplicate-approval",
          "approve: '" + approver + "' has already approved this change");
      }
    }
    var approvedAt = now();
    var approvalSig = signWith ? signWith(Buffer.from(
      JSON.stringify({ changeId: changeId, approver: approver, approvedAt: approvedAt, sqlHash: change.sqlHash }),
      "utf8"
    )) : null;
    change.approvals.push({
      approver:   approver,
      approvedAt: approvedAt,
      signature:  approvalSig
        ? (Buffer.isBuffer(approvalSig) ? approvalSig.toString("base64") : String(approvalSig))
        : null,
      reason:     options.reason || null,
    });
    if (change.approvals.length >= approvers) change.state = STATE_APPROVED;
    store.put(changeId, change);
    _emit("ddl.change.approved", {
      changeId: changeId, approver: approver, signaturesCount: change.approvals.length,
      threshold: approvers,
    });
    return {
      changeId:        changeId,
      signaturesCount: change.approvals.length,
      thresholdMet:    change.state === STATE_APPROVED,
    };
  }

  async function reject(changeId, reviewer, reason) {
    if (typeof changeId !== "string" || changeId.length === 0) {
      throw new DdlChangeControlError("ddl-change-control/bad-id",
        "reject: changeId must be a non-empty string");
    }
    if (typeof reviewer !== "string" || reviewer.length === 0) {
      throw new DdlChangeControlError("ddl-change-control/missing-reviewer",
        "reject: reviewer must be a non-empty string");
    }
    var change = store.get(changeId);
    if (!change) {
      throw new DdlChangeControlError("ddl-change-control/unknown-change",
        "reject: unknown changeId '" + changeId + "'");
    }
    if (change.state === STATE_APPLIED) {
      throw new DdlChangeControlError("ddl-change-control/already-applied",
        "reject: change '" + changeId + "' is already applied");
    }
    change.state = STATE_REJECTED;
    change.rejection = { reviewer: reviewer, reason: reason || null, rejectedAt: now() };
    store.put(changeId, change);
    _emit("ddl.change.rejected", {
      changeId: changeId, reviewer: reviewer, reason: reason || null,
    });
  }

  function list() {
    return store.list().map(function (c) {
      return {
        changeId:   c.changeId,
        sqlHash:    c.sqlHash,
        proposer:   c.proposer,
        proposedAt: c.proposedAt,
        state:      c.state,
        approvals:  c.approvals.map(function (a) {
          return { approver: a.approver, approvedAt: a.approvedAt };
        }),
        appliedAt:  c.appliedAt,
        applier:    c.applier,
      };
    });
  }

  function get(changeId) {
    var c = store.get(changeId);
    if (!c) return null;
    return structuredClone(c);
  }

  async function applyApproved(changeId, runner) {
    if (typeof runner !== "function") {
      throw new DdlChangeControlError("ddl-change-control/bad-runner",
        "applyApproved: runner must be an async function (sql) => result");
    }
    var change = store.get(changeId);
    if (!change) {
      throw new DdlChangeControlError("ddl-change-control/unknown-change",
        "applyApproved: unknown changeId '" + changeId + "'");
    }
    if (change.state === STATE_APPLIED) {
      throw new DdlChangeControlError("ddl-change-control/already-applied",
        "applyApproved: change '" + changeId + "' is already applied");
    }
    if (change.state === STATE_REJECTED) {
      throw new DdlChangeControlError("ddl-change-control/already-rejected",
        "applyApproved: change '" + changeId + "' is rejected");
    }
    if (change.approvals.length < approvers) {
      _emit("ddl.change.apply_refused", {
        changeId: changeId,
        reason: "insufficient-approvals: " + change.approvals.length + "/" + approvers,
      }, "denied");
      throw new DdlChangeControlError("ddl-change-control/insufficient-approvals",
        "applyApproved: change '" + changeId + "' has " + change.approvals.length +
        " approvals; threshold is " + approvers);
    }
    if (!_isInWindow(window, now())) {
      _emit("ddl.change.apply_refused", {
        changeId: changeId, reason: "window-closed",
      }, "denied");
      throw new DdlChangeControlError("ddl-change-control/window-closed",
        "applyApproved: change '" + changeId + "' refused - outside allowed window");
    }
    var currentHash = _hashSql(change.sql);
    if (currentHash !== change.sqlHash) {
      _emit("ddl.change.apply_refused", {
        changeId: changeId, reason: "sql-tampered",
      }, "denied");
      throw new DdlChangeControlError("ddl-change-control/sql-tampered",
        "applyApproved: stored SQL no longer matches its hash - refusing to apply");
    }
    var startedAt = now();
    var result;
    try {
      result = await runner(change.sql, {
        changeId: changeId, sqlHash: change.sqlHash,
        approvals: change.approvals.slice(),
      });
    } catch (e) {
      change.state = STATE_FAILED;
      change.applyError = (e && e.message) || String(e);
      store.put(changeId, change);
      _emit("ddl.change.applied", {
        changeId: changeId, sqlHash: change.sqlHash,
        applier: change.applier, durationMs: now() - startedAt,
        reason: change.applyError,
      }, "failure");
      throw e;
    }
    change.state = STATE_APPLIED;
    change.appliedAt = now();
    change.applyDurationMs = change.appliedAt - startedAt;
    change.applier = "runner";
    store.put(changeId, change);
    _emit("ddl.change.applied", {
      changeId: changeId, sqlHash: change.sqlHash,
      durationMs: change.applyDurationMs,
    });
    return {
      changeId:   changeId,
      result:     result,
      durationMs: change.applyDurationMs,
    };
  }

  return {
    propose:        propose,
    approve:        approve,
    reject:         reject,
    applyApproved:  applyApproved,
    list:           list,
    get:            get,
    posture:        posture,
    approvers:      approvers,
    windowSpec:     opts.windowSpec || null,
  };
}

module.exports = {
  create:                create,
  STATES: {
    PROPOSED: STATE_PROPOSED,
    APPROVED: STATE_APPROVED,
    REJECTED: STATE_REJECTED,
    APPLIED:  STATE_APPLIED,
    FAILED:   STATE_FAILED,
  },
  POSTURES_REQUIRING_CHANGE_CONTROL: POSTURES_REQUIRING_CHANGE_CONTROL,
  DdlChangeControlError: DdlChangeControlError,
};

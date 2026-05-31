"use strict";
/**
 * @module b.dsr
 * @nav    Compliance
 * @title  Dsr
 *
 * @intro
 *   Data Subject Rights workflow (GDPR Art 15-22, CCPA opt-out /
 *   right-to-know / right-to-delete) — ticket lifecycle, deadline
 *   tracking, source-by-source export.
 *
 *   Coordinates the operator's response to GDPR Articles 15-22 /
 *   CCPA / CPRA / LGPD / PIPEDA / UK-GDPR data-subject requests.
 *   The framework owns the ticket state machine, deadline
 *   computation, audit emission, and source orchestration. The
 *   operator owns the storage backend (declares a `ticketStore`
 *   that satisfies the `{ insert, get, list, update }` shape) and
 *   the per-source `query` / `erase` callbacks.
 *
 *   Ticket states: `pending` -> `in_progress` -> (`completed` |
 *   `partially_completed` | `cancelled` | `rejected` | `expired`).
 *
 *   Posture-aware deadlines: gdpr/uk-gdpr/pipeda-ca = 30 days,
 *   ccpa = 45 days, lgpd-br/pipl-cn = 15 days. Operators override
 *   per-ticket via `submit({ deadlineMs })`.
 *
 *   Verification ladder (GDPR Art 12(6) / CCPA §1798.140(y)):
 *   minimal / secondary / strong. Erasure + portability +
 *   rectification default to `secondary`; the framework refuses
 *   `process()` when the actual level is below the per-type floor.
 *
 * @card
 *   Data Subject Rights workflow (GDPR Art 15-22, CCPA opt-out / right-to-know / right-to-delete) — ticket lifecycle, deadline tracking, source-by-source export.
 */
/*
 * Original prose retained as a compact reference:
 *
 *   var dsr = b.dsr.create({
 *     ticketStore: dsrTickets,           // operator-supplied storage
 *     posture:     "gdpr",               // sets default deadline (1mo)
 *     identityResolver: async function (input) {
 *       // takes operator-form input; returns canonical subject
 *       return { subjectId, email, phone, aliases };
 *     },
 *     sources: [
 *       {
 *         name:  "users",
 *         query: async function (subj) { return rowsAboutSubj; },
 *         erase: async function (subj) { return { deletedIds: [...] }; },
 *       },
 *       {
 *         name:  "orders",
 *         query: async function (subj) { ... },
 *         erase: async function (subj) { ... },
 *         // CCPA §1798.105(d) — sale records may be retained for legal
 *         // dispute purposes; flag the source so erasure produces a
 *         // partial-success outcome.
 *         eraseExclusions: ["legal-hold"],
 *       },
 *     ],
 *     audit:           true,
 *     retentionFloorMs: C.TIME.days(30),  // export TTL
 *   });
 *
 *   // Operator route: subject submits a request
 *   var ticket = await dsr.submit({
 *     type:    "access",                  // | "erasure" | "portability" |
 *                                         //   "rectification" | "restriction" |
 *                                         //   "object" | "automated-decision"
 *     subject: { email: "alice@example.com" },
 *     reason:  "user-initiated via web form",
 *     // optional — operator-side workflow ID for cross-ref
 *     externalRef: "case-ZD-12345",
 *   });
 *
 *   // Operator route: admin processes a queued ticket
 *   var result = await dsr.process(ticket.id, {
 *     actor:   "compliance@example.com",
 *     verifyContext: { mfaVerified: true, attestation: "..." },
 *   });
 *
 *   // Cancel before processing (operator chooses; subject withdraws)
 *   await dsr.cancel(ticket.id, {
 *     actor:  "compliance@example.com",
 *     reason: "subject withdrew on phone call",
 *   });
 *
 * Ticket state machine:
 *   pending → in_progress → (completed | partially_completed | cancelled | rejected)
 *
 * Audit emissions (audit namespace `dsr`):
 *   dsr.ticket.submitted   — every submit()
 *   dsr.ticket.in_progress — every process() entry
 *   dsr.ticket.completed   — every successful process() exit
 *   dsr.ticket.partial     — process() with at least one source failure
 *   dsr.ticket.cancelled   — every cancel()
 *   dsr.ticket.rejected    — process() refuses (verify-context fail / unsupported)
 *   dsr.ticket.expired     — ticket past deadline without completion
 *   dsr.source.queried     — per-source successful query
 *   dsr.source.erased      — per-source successful erase
 *   dsr.source.failed      — per-source failure
 *
 * Posture-aware deadline (operator may override per-ticket):
 *   gdpr     — 1 month (Art. 12(3)); extendable +2 months for complexity
 *   ccpa     — 45 calendar days; extendable +45 days
 *   lgpd-br  — 15 days for data subjects' requests (LGPD Art. 19)
 *   pipeda-ca — 30 days
 *   uk-gdpr  — 1 month (mirrors GDPR)
 *   default  — 30 days
 */

var C = require("./constants");
var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var safeSql = require("./safe-sql");
var { defineClass } = require("./framework-error");

var DsrError = defineClass("DsrError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });
var observability = lazyRequire(function () { return require("./observability"); });

var VALID_REQUEST_TYPES = Object.freeze([
  "access",                 // GDPR Art. 15 / CCPA §1798.110
  "erasure",                // GDPR Art. 17 / CCPA §1798.105
  "portability",            // GDPR Art. 20 / CCPA §1798.130
  "rectification",          // GDPR Art. sixteen
  "restriction",            // GDPR Art. 18
  "object",                 // GDPR Art. 21
  "automated-decision",     // GDPR Art. 22 — review of automated decision
]);

var VALID_STATES = Object.freeze([
  "pending",
  "in_progress",
  "completed",
  "partially_completed",
  "cancelled",
  "rejected",
  "expired",
]);

var TERMINAL_STATES = Object.freeze({
  completed:           true,
  partially_completed: true,
  cancelled:           true,
  rejected:            true,
  expired:             true,
});

// Per-posture default deadline. Operators with ambiguity (multi-region
// deployments) pass an explicit `deadlineMs` to submit().
// Verification level — operator-side controls for the identity ladder
// per GDPR Art. 12(6) ("the controller may request the provision of
// additional information necessary to confirm the identity of the
// data subject").
//
//   "minimal"  — controller relies on operator's identity-resolver
//                (e.g. session-bound user lookup); no extra step.
//   "secondary" — controller requires a second factor (email-link
//                challenge, phone OTP, MFA recheck) verified at
//                request submission time.
//   "strong"    — controller requires a notarised attestation /
//                in-person verification step (typically required
//                for healthcare / minor's data).
var VALID_VERIFICATION_LEVELS = Object.freeze([
  "minimal",
  "secondary",
  "strong",
]);

// For each request type, the minimum verification level the framework
// recommends. Operators override per-ticket via opts.verificationLevel
// but cannot drop BELOW the matrix.
var TYPE_MIN_VERIFICATION = Object.freeze({
  "access":             "minimal",      // GDPR Recital sixty-four — provide info if identity confirmed
  "erasure":            "secondary",    // irreversible — second factor recommended
  "portability":        "secondary",    // mass export — second factor recommended
  "rectification":      "secondary",    // data integrity impact
  "restriction":        "minimal",
  "object":             "minimal",
  "automated-decision": "minimal",
});

var POSTURE_DEADLINE_MS = Object.freeze({
  "gdpr":      C.TIME.days(30),     // GDPR Art. 12(3) — 1 month
  "uk-gdpr":   C.TIME.days(30),     // UK ICO — mirrors GDPR
  "ccpa":      C.TIME.days(45),     // CCPA — 45 calendar days
  "lgpd-br":   C.TIME.days(15),     // LGPD Art. 19 — 15 days
  "pipeda-ca": C.TIME.days(30),     // PIPEDA — 30 days
  "appi-jp":   C.TIME.days(30),     // APPI — typical 30-day handling
  "pdpa-sg":   C.TIME.days(30),     // PDPA — 30 days
  "pipl-cn":   C.TIME.days(15),     // PIPL — 15 days
  "default":   C.TIME.days(30),
});

// Operator extends without modifying the table (exported for tests
// + extension). Read-only at module scope.
function _deadlineForPosture(posture) {
  if (typeof posture !== "string") return POSTURE_DEADLINE_MS["default"];
  return POSTURE_DEADLINE_MS[posture] || POSTURE_DEADLINE_MS["default"];
}

function _now() { return Date.now(); }

function _isTerminal(state) { return TERMINAL_STATES[state] === true; }

function _validateTicketStore(store) {
  if (!store || typeof store !== "object") return false;
  return ["insert", "get", "list", "update"].every(function (m) {
    return typeof store[m] === "function";
  });
}

function _validateSource(s) {
  if (!s || typeof s !== "object") return false;
  if (typeof s.name !== "string" || s.name.length === 0) return false;
  if (typeof s.query !== "function" && typeof s.erase !== "function") return false;
  return true;
}

/**
 * @primitive b.dsr.create
 * @signature b.dsr.create(opts)
 * @since     0.8.0
 * @status    stable
 * @compliance gdpr, ccpa
 * @related   b.dsr.memoryTicketStore, b.dsr.dbTicketStore
 *
 * Build a Data Subject Rights workflow handle. Wires the ticket
 * store, identity resolver, and per-source query/erase callbacks
 * into one coordinator that exposes `submit`, `process`, `cancel`,
 * `reject`, `expireOverdue`, `buildReceipt`, and
 * `buildPortabilityBundle`. Posture (`gdpr`, `ccpa`, `lgpd-br`,
 * `uk-gdpr`, `pipeda-ca`, etc.) sets the default deadline; the
 * framework refuses `process()` when the actual verification level
 * is below the per-type floor.
 *
 * @opts
 *   ticketStore:        { insert, get, list, update },
 *   posture:            string,           // "gdpr" | "ccpa" | "lgpd-br" | ...
 *   identityResolver:   async function (input) -> resolvedSubject,
 *   sources:            [{ name, query?, erase?, eraseExclusions? }],
 *   audit:              boolean,          // default true
 *   retentionFloorMs:   number,           // export TTL; default 30 days
 *   deadlineMs:         number,           // overrides posture default
 *   verificationLevel:  "minimal" | "secondary" | "strong",
 *   minVerificationByType: { erasure: "secondary", ... },
 *   receiptSigner:      async function (receipt) -> { issuer, algorithm, signature },
 *
 * @example
 *   var dsr = b.dsr.create({
 *     ticketStore: b.dsr.memoryTicketStore(),
 *     posture:     "gdpr",
 *     identityResolver: async function (input) {
 *       return { subjectId: "u-42", email: input.email, phone: null };
 *     },
 *     sources: [{
 *       name: "users",
 *       query: async function (subj) { return [{ email: subj.email }]; },
 *       erase: async function (subj) { return { deletedIds: [subj.subjectId] }; },
 *     }],
 *   });
 *   var ticket = await dsr.submit({
 *     type:    "access",
 *     subject: { email: "alice@example.com" },
 *     reason:  "user-initiated",
 *   });
 *   var processed = await dsr.process(ticket.id, {
 *     actor: "compliance@example.com",
 *     verificationLevel: "secondary",
 *   });
 *   processed.status;
 *   // → "completed"
 */
function create(opts) {
  validateOpts.requireObject(opts, "dsr", DsrError);
  validateOpts(opts, [
    "ticketStore", "posture", "identityResolver",
    "sources", "audit", "retentionFloorMs",
    "deadlineMs", "observability",
    "verificationLevel", "verifyContext",
    "receiptSigner", "minVerificationByType",
  ], "dsr.create");

  if (!_validateTicketStore(opts.ticketStore)) {
    throw new DsrError("dsr/bad-store",
      "dsr.create: ticketStore must implement { insert, get, list, update }");
  }
  if (typeof opts.identityResolver !== "function") {
    throw new DsrError("dsr/bad-identity",
      "dsr.create: identityResolver must be an async function");
  }
  if (!Array.isArray(opts.sources) || opts.sources.length === 0) {
    throw new DsrError("dsr/no-sources",
      "dsr.create: sources must be a non-empty array");
  }
  for (var i = 0; i < opts.sources.length; i++) {
    if (!_validateSource(opts.sources[i])) {
      throw new DsrError("dsr/bad-source",
        "dsr.create: sources[" + i + "] missing name or query/erase function");
    }
  }
  if (opts.posture !== undefined && typeof opts.posture !== "string") {
    throw new DsrError("dsr/bad-posture",
      "dsr.create: posture must be a string");
  }
  validateOpts.optionalPositiveFinite(opts.retentionFloorMs,
    "dsr.create: retentionFloorMs", DsrError, "dsr/bad-opts");
  validateOpts.optionalPositiveFinite(opts.deadlineMs,
    "dsr.create: deadlineMs", DsrError, "dsr/bad-opts");

  var store    = opts.ticketStore;
  var posture  = opts.posture || "default";
  var auditOn  = opts.audit !== false;
  var defaultDeadlineMs = opts.deadlineMs || _deadlineForPosture(posture);
  var retentionFloorMs  = opts.retentionFloorMs || C.TIME.days(30);

  var defaultVerificationLevel = opts.verificationLevel || null;
  if (defaultVerificationLevel !== null &&
      VALID_VERIFICATION_LEVELS.indexOf(defaultVerificationLevel) === -1) {
    throw new DsrError("dsr/bad-verification-level",
      "dsr.create: verificationLevel must be one of " +
      VALID_VERIFICATION_LEVELS.join(", "));
  }
  var minVerificationByType = Object.assign({}, TYPE_MIN_VERIFICATION,
                                              opts.minVerificationByType || {});
  // Validate operator override values
  var overrideKeys = Object.keys(minVerificationByType);
  for (var ki = 0; ki < overrideKeys.length; ki++) {
    if (VALID_VERIFICATION_LEVELS.indexOf(minVerificationByType[overrideKeys[ki]]) === -1) {
      throw new DsrError("dsr/bad-min-verification",
        "dsr.create: minVerificationByType[" + overrideKeys[ki] +
        "] must be one of " + VALID_VERIFICATION_LEVELS.join(", "));
    }
  }
  validateOpts.optionalFunction(opts.receiptSigner,
    "dsr.create: receiptSigner", DsrError, "dsr/bad-opts");

  function _levelOrdinal(lvl) {
    return VALID_VERIFICATION_LEVELS.indexOf(lvl);
  }
  function _isVerificationOk(actualLevel, requiredLevel) {
    return _levelOrdinal(actualLevel) >= _levelOrdinal(requiredLevel);
  }

  // Source registry — keyed by name for O(1) lookup
  var sources = Object.create(null);
  for (var s = 0; s < opts.sources.length; s++) {
    sources[opts.sources[s].name] = opts.sources[s];
  }

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   action,
        outcome:  outcome === "ok" ? "success" : outcome === "fail" ? "failure" : outcome === "warn" ? "success" : outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent — audit sink */ }
  }

  function _emitMetric(verb, n, labels) {
    try { observability().safeEvent("dsr." + verb, n || 1, labels || {}); }
    catch (_e) { /* drop-silent */ }
  }

  function _newTicketId() {
    var ts = String(Date.now()).slice(-7);                                         // last 7 chars of unix-ms timestamp; collision-resistant when paired with the random suffix
    var rnd = bCrypto.generateBytes(C.BYTES.bytes(6)).toString("hex").toUpperCase();
    return "DSR-" + ts + "-" + rnd;
  }

  async function submit(input) {
    if (!input || typeof input !== "object") {
      throw new DsrError("dsr/bad-submit", "submit: input must be an object");
    }
    if (VALID_REQUEST_TYPES.indexOf(input.type) === -1) {
      throw new DsrError("dsr/bad-type",
        "submit: type must be one of " + VALID_REQUEST_TYPES.join(", ") +
        " (got " + JSON.stringify(input.type) + ")");
    }
    if (!input.subject || typeof input.subject !== "object") {
      throw new DsrError("dsr/bad-subject",
        "submit: subject must be an object");
    }

    // Resolve canonical subject identity
    var resolved;
    try { resolved = await opts.identityResolver(input.subject); }
    catch (e) {
      _emitAudit("dsr.ticket.rejected", "fail", {
        reason: "identity-resolver-failed",
        error:  (e && e.message) || String(e),
      });
      throw new DsrError("dsr/identity-resolver-failed",
        "submit: identityResolver threw: " + ((e && e.message) || String(e)));
    }
    if (!resolved || typeof resolved !== "object") {
      throw new DsrError("dsr/identity-not-resolved",
        "submit: identityResolver returned non-object (subject not found?)");
    }

    var deadlineMs = (typeof input.deadlineMs === "number" && isFinite(input.deadlineMs))
      ? input.deadlineMs
      : defaultDeadlineMs;

    var now = _now();
    var submitVerificationLevel = input.verificationLevel || defaultVerificationLevel || null;
    if (submitVerificationLevel !== null &&
        VALID_VERIFICATION_LEVELS.indexOf(submitVerificationLevel) === -1) {
      throw new DsrError("dsr/bad-verification-level",
        "submit: verificationLevel must be one of " +
        VALID_VERIFICATION_LEVELS.join(", "));
    }
    var ticket = {
      id:           _newTicketId(),
      type:         input.type,
      subject:      resolved,
      submittedBy:  input.submittedBy || null,
      reason:       input.reason || null,
      externalRef:  input.externalRef || null,
      status:       "pending",
      submittedAt:  now,
      deadlineAt:   now + deadlineMs,
      processedAt:  null,
      result:       null,
      sourceResults: [],
      posture:      posture,
      retentionUntil: now + retentionFloorMs,
      verificationLevel: submitVerificationLevel,
      verifyContext:     null,
    };
    await store.insert(ticket);
    _emitAudit("dsr.ticket.submitted", "ok", {
      id:          ticket.id,
      type:        ticket.type,
      posture:     posture,
      deadlineAt:  ticket.deadlineAt,
    });
    _emitMetric("submitted", 1, { type: ticket.type, posture: posture });
    return ticket;
  }

  async function process(ticketId, opts2) {
    opts2 = opts2 || {};
    var ticket = await store.get(ticketId);
    if (!ticket) {
      throw new DsrError("dsr/not-found", "process: ticket " + ticketId + " not found");
    }
    if (_isTerminal(ticket.status)) {
      throw new DsrError("dsr/terminal-state",
        "process: ticket " + ticketId + " is in terminal state " + ticket.status);
    }
    if (ticket.status === "in_progress") {
      throw new DsrError("dsr/already-in-progress",
        "process: ticket " + ticketId + " is already in progress");
    }

    // Identity-verification ladder per GDPR Article 12(6) / CCPA
    // §1798.140(y). The operator passes the verification level
    // they completed at submission/process time; the framework
    // refuses processing if it's below the per-type floor.
    var requiredLevel = minVerificationByType[ticket.type] || "minimal";
    var actualLevel = (opts2 && opts2.verificationLevel) ||
                      ticket.verificationLevel ||
                      defaultVerificationLevel ||
                      "minimal";
    if (VALID_VERIFICATION_LEVELS.indexOf(actualLevel) === -1) {
      throw new DsrError("dsr/bad-verification-level",
        "process: verificationLevel must be one of " +
        VALID_VERIFICATION_LEVELS.join(", "));
    }
    if (!_isVerificationOk(actualLevel, requiredLevel)) {
      _emitAudit("dsr.ticket.rejected", "fail", {
        id: ticket.id, type: ticket.type,
        reason: "insufficient-verification",
        required: requiredLevel, actual: actualLevel,
      });
      throw new DsrError("dsr/insufficient-verification",
        "process: ticket " + ticketId + " requires verification level " +
        requiredLevel + " but actual is " + actualLevel +
        " (operator must complete the additional verification step before re-processing)");
    }
    ticket.verificationLevel = actualLevel;
    ticket.verifyContext = opts2.verifyContext || null;

    // Mark in_progress before any source dispatch — protects against
    // concurrent processors picking the same ticket.
    ticket.status = "in_progress";
    ticket.startedAt = _now();
    ticket.processor = opts2.actor || null;
    await store.update(ticket.id, ticket);
    _emitAudit("dsr.ticket.in_progress", "ok", {
      id:     ticket.id,
      type:   ticket.type,
      actor:  opts2.actor || null,
    });

    var sourceResults = [];
    var anyFailed = false;
    var totalRows = 0;
    var deletedTotal = 0;

    var sourceNames = Object.keys(sources);
    for (var i = 0; i < sourceNames.length; i++) {
      var src = sources[sourceNames[i]];
      var sourceResult = {
        name:    src.name,
        outcome: "skipped",
        rows:    null,
        deleted: null,
        error:   null,
      };
      try {
        if (ticket.type === "access" || ticket.type === "portability" ||
            ticket.type === "rectification") {
          if (typeof src.query === "function") {
            var rows = await src.query(ticket.subject);
            sourceResult.outcome = "queried";
            sourceResult.rows    = Array.isArray(rows) ? rows.length : (rows ? 1 : 0);
            sourceResult.data    = rows;       // operator-side responsibility to redact
            totalRows += sourceResult.rows;
            _emitAudit("dsr.source.queried", "ok", {
              ticketId: ticket.id, source: src.name, rows: sourceResult.rows,
            });
          }
        } else if (ticket.type === "erasure") {
          if (typeof src.erase === "function") {
            var eraseResult = await src.erase(ticket.subject);
            var deleted = (eraseResult && Array.isArray(eraseResult.deletedIds))
              ? eraseResult.deletedIds.length
              : (typeof (eraseResult && eraseResult.deleted) === "number"
                 ? eraseResult.deleted : 0);
            sourceResult.outcome = "erased";
            sourceResult.deleted = deleted;
            sourceResult.deletedIds = (eraseResult && eraseResult.deletedIds) || null;
            sourceResult.exclusions = (eraseResult && eraseResult.exclusions) ||
                                      src.eraseExclusions || null;
            deletedTotal += deleted;
            _emitAudit("dsr.source.erased", "ok", {
              ticketId: ticket.id, source: src.name, deleted: deleted,
            });
          }
        } else if (ticket.type === "restriction") {
          // Restriction is operator-side: we mark the source as "noted"
          // so the operator's downstream code skips processing for the
          // subject. The framework records the restriction; enforcement
          // is operator code that reads sourceResults.
          sourceResult.outcome = "marked-restricted";
        } else if (ticket.type === "object") {
          // Object to processing — same shape as restriction but different
          // outcome label so audits read correctly.
          sourceResult.outcome = "marked-objection";
        } else if (ticket.type === "automated-decision") {
          // Operator-side: log a review-required marker
          sourceResult.outcome = "marked-automated-decision-review";
        }
      } catch (e) {
        anyFailed = true;
        sourceResult.outcome = "failed";
        sourceResult.error   = (e && e.message) || String(e);
        _emitAudit("dsr.source.failed", "fail", {
          ticketId: ticket.id, source: src.name,
          error: sourceResult.error,
        });
      }
      sourceResults.push(sourceResult);
    }

    var finalStatus = anyFailed ? "partially_completed" : "completed";
    ticket.status        = finalStatus;
    ticket.processedAt   = _now();
    ticket.sourceResults = sourceResults;
    ticket.result = {
      type:           ticket.type,
      anyFailed:      anyFailed,
      totalRowsFound: totalRows,
      totalDeleted:   deletedTotal,
      sources:        sourceResults.map(function (r) {
        return {
          name:    r.name, outcome: r.outcome,
          rows:    r.rows, deleted: r.deleted,
          error:   r.error,
        };
      }),
    };
    await store.update(ticket.id, ticket);
    _emitAudit(anyFailed ? "dsr.ticket.partial" : "dsr.ticket.completed",
               anyFailed ? "warn" : "ok",
               { id: ticket.id, type: ticket.type, totalRows: totalRows,
                 totalDeleted: deletedTotal, anyFailed: anyFailed });
    _emitMetric(anyFailed ? "partial" : "completed", 1, { type: ticket.type });
    return ticket;
  }

  async function cancel(ticketId, opts2) {
    opts2 = opts2 || {};
    var ticket = await store.get(ticketId);
    if (!ticket) {
      throw new DsrError("dsr/not-found", "cancel: ticket " + ticketId + " not found");
    }
    if (_isTerminal(ticket.status)) {
      throw new DsrError("dsr/terminal-state",
        "cancel: ticket " + ticketId + " is in terminal state " + ticket.status);
    }
    ticket.status        = "cancelled";
    ticket.cancelledAt   = _now();
    ticket.cancelledBy   = opts2.actor || null;
    ticket.cancelReason  = opts2.reason || null;
    await store.update(ticket.id, ticket);
    _emitAudit("dsr.ticket.cancelled", "ok", {
      id: ticket.id, type: ticket.type, actor: opts2.actor || null,
      reason: opts2.reason || null,
    });
    _emitMetric("cancelled", 1, { type: ticket.type });
    return ticket;
  }

  async function reject(ticketId, opts2) {
    opts2 = opts2 || {};
    if (typeof opts2.reason !== "string" || opts2.reason.length === 0) {
      throw new DsrError("dsr/bad-reject",
        "reject: opts.reason is required (operator must record the rejection rationale)");
    }
    var ticket = await store.get(ticketId);
    if (!ticket) {
      throw new DsrError("dsr/not-found", "reject: ticket " + ticketId + " not found");
    }
    if (_isTerminal(ticket.status)) {
      throw new DsrError("dsr/terminal-state",
        "reject: ticket " + ticketId + " is in terminal state " + ticket.status);
    }
    ticket.status        = "rejected";
    ticket.rejectedAt    = _now();
    ticket.rejectedBy    = opts2.actor || null;
    ticket.rejectReason  = opts2.reason;
    await store.update(ticket.id, ticket);
    _emitAudit("dsr.ticket.rejected", "ok", {
      id: ticket.id, type: ticket.type, actor: opts2.actor || null,
      reason: opts2.reason,
    });
    _emitMetric("rejected", 1, { type: ticket.type });
    return ticket;
  }

  async function get(ticketId) {
    return await store.get(ticketId);
  }

  async function listBySubject(subject) {
    if (!subject || typeof subject !== "object") return [];
    return await store.list({ subject: subject });
  }

  async function listByStatus(status) {
    if (VALID_STATES.indexOf(status) === -1) {
      throw new DsrError("dsr/bad-status",
        "listByStatus: status must be one of " + VALID_STATES.join(", "));
    }
    return await store.list({ status: status });
  }

  async function expireOverdue() {
    // Sweep tickets whose deadline has passed without terminal state.
    // Operator runs this on a schedule (e.g. via b.scheduler).
    var now = _now();
    var pending = await store.list({ status: "pending" });
    var inFlight = await store.list({ status: "in_progress" });
    var candidates = [].concat(pending || [], inFlight || []);
    var expired = [];
    for (var i = 0; i < candidates.length; i++) {
      var t = candidates[i];
      if (typeof t.deadlineAt === "number" && t.deadlineAt < now) {
        t.status     = "expired";
        t.expiredAt  = now;
        await store.update(t.id, t);
        _emitAudit("dsr.ticket.expired", "warn", {
          id: t.id, type: t.type,
          deadlineAt: t.deadlineAt,
        });
        expired.push(t);
      }
    }
    return expired;
  }

  // Build an operator-signed receipt for a completed/cancelled/rejected
  // ticket. The receipt is the canonical "I did the thing" artifact
  // the operator gives to the subject + retains for compliance audit.
  // Receipt shape:
  //   {
  //     schema:        "blamejs.dsr.receipt/1",
  //     ticketId, type, status,
  //     subject:       { subjectId, email, phone },
  //     posture, verificationLevel,
  //     submittedAt, processedAt | cancelledAt | rejectedAt,
  //     deadlineAt,
  //     summary:       { totalRowsFound?, totalDeleted?, sources?[],
  //                      cancelReason?, rejectReason? },
  //     issuedAt, issuer (from receiptSigner.issuer),
  //     signature:     base64url-encoded operator signature when
  //                    receiptSigner is provided
  //   }
  async function buildReceipt(ticketId) {
    var ticket = await store.get(ticketId);
    if (!ticket) {
      throw new DsrError("dsr/not-found",
        "buildReceipt: ticket " + ticketId + " not found");
    }
    if (!_isTerminal(ticket.status)) {
      throw new DsrError("dsr/not-terminal",
        "buildReceipt: ticket must be in terminal state (got " +
        ticket.status + ")");
    }
    var summary = {};
    if (ticket.status === "completed" || ticket.status === "partially_completed") {
      summary.totalRowsFound = (ticket.result && ticket.result.totalRowsFound) || 0;
      summary.totalDeleted   = (ticket.result && ticket.result.totalDeleted)   || 0;
      summary.sources        = (ticket.result && ticket.result.sources)        || [];
    } else if (ticket.status === "cancelled") {
      summary.cancelReason = ticket.cancelReason || null;
    } else if (ticket.status === "rejected") {
      summary.rejectReason = ticket.rejectReason || null;
    } else if (ticket.status === "expired") {
      summary.deadlineAt = ticket.deadlineAt;
    }
    var receipt = {
      schema:            "blamejs.dsr.receipt/1",
      ticketId:          ticket.id,
      type:              ticket.type,
      status:            ticket.status,
      subject: {
        subjectId: ticket.subject.subjectId || null,
        email:     ticket.subject.email     || null,
        phone:     ticket.subject.phone     || null,
      },
      posture:           ticket.posture,
      verificationLevel: ticket.verificationLevel || "minimal",
      submittedAt:       ticket.submittedAt,
      processedAt:       ticket.processedAt   || null,
      cancelledAt:       ticket.cancelledAt   || null,
      rejectedAt:        ticket.rejectedAt    || null,
      expiredAt:         ticket.expiredAt     || null,
      deadlineAt:        ticket.deadlineAt,
      summary:           summary,
      issuedAt:          _now(),
    };
    if (typeof opts.receiptSigner === "function") {
      try {
        var sigResult = await opts.receiptSigner(receipt);
        receipt.issuer    = (sigResult && sigResult.issuer)    || null;
        receipt.algorithm = (sigResult && sigResult.algorithm) || null;
        receipt.signature = (sigResult && sigResult.signature) || null;
      } catch (e) {
        // Signer failure is operator-side; return unsigned receipt
        // with a marker so the caller can decide how to handle.
        receipt.signatureError = (e && e.message) || String(e);
      }
    }
    return receipt;
  }

  // Build a portability bundle from a completed access/portability
  // ticket. Operators wire this into their export endpoint; the
  // framework structures the output as a JSON envelope.
  function buildPortabilityBundle(ticket) {
    if (!ticket || ticket.type === undefined) {
      throw new DsrError("dsr/bad-ticket", "buildPortabilityBundle: ticket required");
    }
    if (ticket.type !== "access" && ticket.type !== "portability") {
      throw new DsrError("dsr/wrong-type",
        "buildPortabilityBundle: ticket.type must be 'access' or 'portability'");
    }
    if (!_isTerminal(ticket.status) || ticket.status === "cancelled" ||
        ticket.status === "rejected" || ticket.status === "expired") {
      throw new DsrError("dsr/not-completed",
        "buildPortabilityBundle: ticket must be in completed/partially_completed state");
    }
    var bundle = {
      schema:       "blamejs.dsr.portability/1",
      ticketId:     ticket.id,
      type:         ticket.type,
      subject: {
        subjectId: ticket.subject.subjectId || null,
        email:     ticket.subject.email     || null,
        phone:     ticket.subject.phone     || null,
      },
      generatedAt:  _now(),
      retentionUntil: ticket.retentionUntil,
      data:         {},
    };
    var results = ticket.sourceResults || [];
    for (var i = 0; i < results.length; i++) {
      var r = results[i];
      if (r.outcome === "queried" && r.data !== undefined) {
        bundle.data[r.name] = r.data;
      }
    }
    return bundle;
  }

  return {
    submit:                 submit,
    process:                process,
    cancel:                 cancel,
    reject:                 reject,
    get:                    get,
    listBySubject:          listBySubject,
    listByStatus:           listByStatus,
    expireOverdue:          expireOverdue,
    buildReceipt:           buildReceipt,
    buildPortabilityBundle: buildPortabilityBundle,
    // Test hooks
    _deadlineForPosture:    _deadlineForPosture,
    _isTerminal:            _isTerminal,
    _isVerificationOk:      _isVerificationOk,
  };
}

/**
 * @primitive b.dsr.memoryTicketStore
 * @signature b.dsr.memoryTicketStore()
 * @since     0.8.0
 * @status    stable
 * @related   b.dsr.create, b.dsr.dbTicketStore
 *
 * In-memory ticket store — operator dev / test scaffold. Production
 * operators wire `b.dsr.dbTicketStore` (or their own b.externalDb-
 * backed store). The shape is the contract: `{ insert(ticket),
 * get(id), list(filter), update(id, ticket) }`. The returned store
 * also exposes `_size()` for tests.
 *
 * @example
 *   var store = b.dsr.memoryTicketStore();
 *   await store.insert({ id: "DSR-1", status: "pending", subject: {} });
 *   var t = await store.get("DSR-1");
 *   t.status;
 *   // → "pending"
 *   var pending = await store.list({ status: "pending" });
 *   pending.length;
 *   // → 1
 */
function memoryTicketStore() {
  var byId = new Map();
  return {
    insert: async function (ticket) {
      if (byId.has(ticket.id)) {
        throw new DsrError("dsr/duplicate-ticket-id",
          "memoryTicketStore: duplicate ticket id " + ticket.id);
      }
      byId.set(ticket.id, Object.assign({}, ticket));
    },
    get: async function (id) {
      var t = byId.get(id);
      return t ? Object.assign({}, t) : null;
    },
    list: async function (filter) {
      filter = filter || {};
      var out = [];
      for (var entry of byId) {
        var t = entry[1];
        if (filter.status && t.status !== filter.status) continue;
        if (filter.subject) {
          if (filter.subject.email && t.subject.email !== filter.subject.email) continue;
          if (filter.subject.subjectId && t.subject.subjectId !== filter.subject.subjectId) continue;
        }
        out.push(Object.assign({}, t));
      }
      return out;
    },
    update: async function (id, ticket) {
      if (!byId.has(id)) {
        throw new DsrError("dsr/ticket-not-found",
          "memoryTicketStore: ticket " + id + " not found for update");
      }
      byId.set(id, Object.assign({}, ticket));
    },
    _size: function () { return byId.size; },
  };
}

/**
 * @primitive b.dsr.dbTicketStore
 * @signature b.dsr.dbTicketStore(opts)
 * @since     0.8.0
 * @status    stable
 * @compliance gdpr, ccpa
 * @related   b.dsr.create, b.dsr.memoryTicketStore
 *
 * Production-grade ticket store backed by `b.db`. Auto-provisions
 * the table on first use, indexes on `subject_email` and `status`,
 * persists the full ticket as a JSON payload column, and exposes
 * `purgeExpired(asOfMs?)` for retention-floor enforcement.
 *
 * @opts
 *   db:    b.db-shaped handle (`{ runSql, prepare }`),
 *   table: string,   // SQL identifier; defaults to "dsr_tickets"
 *
 * @example
 *   var store = b.dsr.dbTicketStore({ db: b.db.handle(), table: "dsr_tickets" });
 *   await store.insert({
 *     id:           "DSR-1234567-DEADBEEF",
 *     type:         "erasure",
 *     status:       "pending",
 *     subject:      { subjectId: "u-42", email: "alice@example.com" },
 *     submittedAt:  Date.now(),
 *     deadlineAt:   Date.now() + 30 * 86400 * 1000,
 *     retentionUntil: Date.now() + 30 * 86400 * 1000,
 *   });
 *   var purged = await store.purgeExpired();
 *   typeof purged;
 *   // → "number"
 */
// b.db-backed ticket store — production operators wire this against
// the framework's SQLite engine. The store auto-provisions a single
// table (default name `dsr_tickets`) with the canonical column set:
//
//   id            TEXT PRIMARY KEY
//   type          TEXT NOT NULL
//   status        TEXT NOT NULL
//   subject_id    TEXT
//   subject_email TEXT
//   subject_phone TEXT
//   submitted_at  INTEGER NOT NULL
//   deadline_at   INTEGER NOT NULL
//   processed_at  INTEGER
//   verification_level TEXT
//   posture       TEXT
//   payload       TEXT  -- full JSON for the ticket
//
// Indexed on subject_email and status for the common list-by-subject
// and list-by-status queries.
function dbTicketStore(opts) {
  opts = opts || {};
  var db = opts.db;
  if (!db || typeof db.runSql !== "function" || typeof db.prepare !== "function") {
    throw new DsrError("dsr/bad-db",
      "dbTicketStore: opts.db must be a b.db-shaped handle (with runSql + prepare)");
  }
  var tableRaw = opts.table || "dsr_tickets";
  var qTable, qEmailIdx, qStatusIdx;
  try {
    qTable     = safeSql.quoteIdentifier(tableRaw, "sqlite");
    qEmailIdx  = safeSql.quoteIdentifier(tableRaw + "_email_idx", "sqlite");
    qStatusIdx = safeSql.quoteIdentifier(tableRaw + "_status_idx", "sqlite");
  } catch (sqlErr) {
    throw new DsrError("dsr/bad-table",
      "dbTicketStore: table must be a valid SQL identifier: " +
      (sqlErr && sqlErr.message ? sqlErr.message : String(sqlErr)));
  }

  // Auto-provision schema if not already present. Idempotent.
  function ensureSchema() {
    db.runSql("CREATE TABLE IF NOT EXISTS " + qTable + " (" +
      "id            TEXT PRIMARY KEY, " +
      "type          TEXT NOT NULL, " +
      "status        TEXT NOT NULL, " +
      "subject_id    TEXT, " +
      "subject_email TEXT, " +
      "subject_phone TEXT, " +
      "submitted_at  INTEGER NOT NULL, " +
      "deadline_at   INTEGER NOT NULL, " +
      "processed_at  INTEGER, " +
      "verification_level TEXT, " +
      "posture       TEXT, " +
      "payload       TEXT NOT NULL" +
    ")");
    db.runSql("CREATE INDEX IF NOT EXISTS " + qEmailIdx + " ON " +
              qTable + " (subject_email)");
    db.runSql("CREATE INDEX IF NOT EXISTS " + qStatusIdx + " ON " +
              qTable + " (status)");
  }
  ensureSchema();

  return {
    insert: async function (ticket) {
      var stmt = db.prepare("INSERT INTO " + qTable +
        " (id, type, status, subject_id, subject_email, subject_phone, " +
        "  submitted_at, deadline_at, processed_at, verification_level, posture, payload) " +
        " VALUES ($id, $type, $status, $sid, $email, $phone, $submittedAt, " +
        "         $deadlineAt, $processedAt, $verLevel, $posture, $payload)");
      stmt.run({
        $id:           ticket.id,
        $type:         ticket.type,
        $status:       ticket.status,
        $sid:          (ticket.subject && ticket.subject.subjectId) || null,
        $email:        (ticket.subject && ticket.subject.email)     || null,
        $phone:        (ticket.subject && ticket.subject.phone)     || null,
        $submittedAt:  ticket.submittedAt,
        $deadlineAt:   ticket.deadlineAt,
        $processedAt:  ticket.processedAt || null,
        $verLevel:     ticket.verificationLevel || null,
        $posture:      ticket.posture || null,
        $payload:      JSON.stringify(ticket),
      });
    },
    get: async function (id) {
      var rows = db.prepare("SELECT payload FROM " + qTable + " WHERE id = $id")
                   .all({ $id: id });
      if (!rows || rows.length === 0) return null;
      return JSON.parse(rows[0].payload);                                          // allow:bare-json-parse — payload was JSON.stringify-ed by this same store, never from operator/network input
    },
    list: async function (filter) {
      filter = filter || {};
      var sql = "SELECT payload FROM " + qTable;
      var conds = [];
      var params = {};
      if (filter.status) {
        conds.push("status = $status");
        params.$status = filter.status;
      }
      if (filter.subject) {
        if (filter.subject.email) {
          conds.push("subject_email = $email");
          params.$email = filter.subject.email;
        }
        if (filter.subject.subjectId) {
          conds.push("subject_id = $sid");
          params.$sid = filter.subject.subjectId;
        }
      }
      if (conds.length > 0) sql += " WHERE " + conds.join(" AND ");
      sql += " ORDER BY submitted_at DESC";
      var rows = db.prepare(sql).all(params);
      return rows.map(function (r) { return JSON.parse(r.payload); });             // allow:bare-json-parse — payload was JSON.stringify-ed by this same store, never from operator/network input
    },
    update: async function (id, ticket) {
      var stmt = db.prepare("UPDATE " + qTable + " SET " +
        " type = $type, status = $status, subject_id = $sid, " +
        " subject_email = $email, subject_phone = $phone, " +
        " submitted_at = $submittedAt, deadline_at = $deadlineAt, " +
        " processed_at = $processedAt, verification_level = $verLevel, " +
        " posture = $posture, payload = $payload " +
        " WHERE id = $id");
      var info = stmt.run({
        $id:           id,
        $type:         ticket.type,
        $status:       ticket.status,
        $sid:          (ticket.subject && ticket.subject.subjectId) || null,
        $email:        (ticket.subject && ticket.subject.email)     || null,
        $phone:        (ticket.subject && ticket.subject.phone)     || null,
        $submittedAt:  ticket.submittedAt,
        $deadlineAt:   ticket.deadlineAt,
        $processedAt:  ticket.processedAt || null,
        $verLevel:     ticket.verificationLevel || null,
        $posture:      ticket.posture || null,
        $payload:      JSON.stringify(ticket),
      });
      if (info && info.changes === 0) {
        throw new DsrError("dsr/ticket-not-found",
          "dbTicketStore: ticket " + id + " not found for update");
      }
    },
    purgeExpired: async function (asOfMs) {
      // Bulk-delete tickets in terminal states whose retentionUntil
      // is in the past. Returns the number of rows removed.
      var asOf = (typeof asOfMs === "number" && isFinite(asOfMs)) ? asOfMs : Date.now();
      var rows = db.prepare("SELECT id, payload FROM " + qTable +
                            " WHERE status IN ('completed','partially_completed','cancelled','rejected','expired')").all({});
      var purged = 0;
      var del = db.prepare("DELETE FROM " + qTable + " WHERE id = $id");
      for (var i = 0; i < rows.length; i++) {
        try {
          var t = JSON.parse(rows[i].payload);                                      // allow:bare-json-parse — payload was JSON.stringify-ed by this same store, never from operator/network input
          if (t.retentionUntil && t.retentionUntil < asOf) {
            del.run({ $id: rows[i].id });
            purged += 1;
          }
        } catch (_e) { /* malformed payload — leave it */ }
      }
      return purged;
    },
    _table:    tableRaw,
    _ensureSchema: ensureSchema,
  };
}

// ---- v0.8.77 — US state-law DSR drift registry -------------------
//
// Each US state consumer-privacy law expresses the same DSR core
// (access / deletion / correction / portability) but with per-state
// drift on three knobs: cure-period (days between operator-receipt
// and statutory-deadline-to-respond), profiling-opt-out
// (right-to-limit-automated-decision-making variants), and minor-
// consent (age threshold + opt-in vs. opt-out vs. parental-VPC).
//
// `b.dsr.stateRules(state)` returns the metadata; operators feed it
// into their own DSR ticket-routing layer to surface "this VA
// resident's correction request must be acknowledged within 45 days
// with one 45-day extension".

// State DSR rule table — `responseDays` / `extensionDays` / `cureDays`
// are integer day-counts from per-state statutes (not durations in
// seconds/ms).
var STATE_RULES = Object.freeze({
  "vcdpa":     { posture: "vcdpa",     state: "VA", responseDays: 45, extensionDays: 45, cureDays: 30,  profilingOptOut: true,  minorOptIn: 13,  notes: "Cure right sunset 2025-01-01" },                                                                          // allow:raw-time-literal
  "co-cpa":    { posture: "co-cpa",    state: "CO", responseDays: 45, extensionDays: 45, cureDays: 60,  profilingOptOut: true,  minorOptIn: 13,  notes: "Cure right sunset 2025-01-01; UOOM (GPC) mandatory" },                                                    // allow:raw-time-literal
  "ctdpa":     { posture: "ctdpa",     state: "CT", responseDays: 45, extensionDays: 45, cureDays: 60,  profilingOptOut: true,  minorOptIn: 13,  notes: "Cure right sunset 2025-01-01; GPC mandatory" },                                                           // allow:raw-time-literal
  "ucpa":      { posture: "ucpa",      state: "UT", responseDays: 45, extensionDays: 45, cureDays: 30,  profilingOptOut: false, minorOptIn: 13,  notes: "Narrowest scope; no cure-period sunset" },                                                                // allow:raw-time-literal
  "tdpsa":     { posture: "tdpsa",     state: "TX", responseDays: 45, extensionDays: 45, cureDays: 30,  profilingOptOut: true,  minorOptIn: 13,  notes: "Small-business carve-out applies" },                                                                      // allow:raw-time-literal
  "or-cpa":    { posture: "or-cpa",    state: "OR", responseDays: 45, extensionDays: 45, cureDays: 60,  profilingOptOut: true,  minorOptIn: 13,  notes: "Specific-third-party-name DSR enhancement" },                                                             // allow:raw-time-literal
  "mt-cdpa":   { posture: "mt-cdpa",   state: "MT", responseDays: 45, extensionDays: 45, cureDays: 60,  profilingOptOut: true,  minorOptIn: 13,  notes: "Cure period sunsets 2026-04-01" },                                                                        // allow:raw-time-literal
  "ia-icdpa":  { posture: "ia-icdpa",  state: "IA", responseDays: 90, extensionDays: 45, cureDays: 90,  profilingOptOut: false, minorOptIn: null, notes: "Weakest framework — longest response, no profiling opt-out" },                                            // allow:raw-time-literal
  "in-indpa":  { posture: "in-indpa",  state: "IN", responseDays: 45, extensionDays: 45, cureDays: 30,  profilingOptOut: true,  minorOptIn: 13,  notes: "Effective 2026-01-01" },                                                                                  // allow:raw-time-literal
  "de-dpdpa":  { posture: "de-dpdpa",  state: "DE", responseDays: 45, extensionDays: 45, cureDays: 60,  profilingOptOut: true,  minorOptIn: 13,  notes: "Effective 2026-01-01" },                                                                                  // allow:raw-time-literal
  "nh-nhpa":   { posture: "nh-nhpa",   state: "NH", responseDays: 45, extensionDays: 45, cureDays: 60,  profilingOptOut: true,  minorOptIn: 13,  notes: "Effective 2026-01-01; cure right sunset 2026-01-01" },                                                    // allow:raw-time-literal
  "nj-njdpa":  { posture: "nj-njdpa",  state: "NJ", responseDays: 45, extensionDays: 45, cureDays: 30,  profilingOptOut: true,  minorOptIn: 17,  notes: "Under-17 opt-in default" },                                                                                // allow:raw-time-literal
  "ky-kcdpa":  { posture: "ky-kcdpa",  state: "KY", responseDays: 45, extensionDays: 45, cureDays: 30,  profilingOptOut: true,  minorOptIn: 13,  notes: "Effective 2026-01-01" },                                                                                  // allow:raw-time-literal
  "tn-tipa":   { posture: "tn-tipa",   state: "TN", responseDays: 45, extensionDays: 45, cureDays: 60,  profilingOptOut: true,  minorOptIn: 13,  notes: "NIST CSF safe-harbor available" },                                                                        // allow:raw-time-literal
  "mn-mncdpa": { posture: "mn-mncdpa", state: "MN", responseDays: 45, extensionDays: 45, cureDays: 30,  profilingOptOut: true,  minorOptIn: 13,  notes: "Effective 2026-07-31; profiling opt-out for consequential decisions" },
  "ri-ricpa":  { posture: "ri-ricpa",  state: "RI", responseDays: 45, extensionDays: 45, cureDays: 0,   profilingOptOut: true,  minorOptIn: 13,  notes: "Effective 2026-01-01; no cure period" },                                                                  // allow:raw-time-literal
  "ne-dpa":    { posture: "ne-dpa",    state: "NE", responseDays: 45, extensionDays: 45, cureDays: 30,  profilingOptOut: true,  minorOptIn: 13,  notes: "Effective 2025-01-01" },                                                                                  // allow:raw-time-literal
  "nv-sb370":  { posture: "nv-sb370",  state: "NV", responseDays: 60, extensionDays: 30, cureDays: 0,   profilingOptOut: false, minorOptIn: null, notes: "Consumer-health data only" },                                                                            // allow:raw-time-literal
  "ca-aadc":   { posture: "ca-aadc",   state: "CA", responseDays: 0,  extensionDays: 0,  cureDays: 90,  profilingOptOut: true,  minorOptIn: 18,  notes: "Under-18 default-high-privacy; partial preliminary injunction NetChoice v. Bonta" },                       // allow:raw-time-literal
  "ct-sb3":    { posture: "ct-sb3",    state: "CT", responseDays: 45, extensionDays: 45, cureDays: 60,  profilingOptOut: false, minorOptIn: null, notes: "Consumer-health data only" },                                                                            // allow:raw-time-literal
  "tx-cubi":   { posture: "tx-cubi",   state: "TX", responseDays: 0,  extensionDays: 0,  cureDays: 0,   profilingOptOut: false, minorOptIn: null, notes: "Biometric-only; private-right-of-action absent" },                                                       // allow:raw-time-literal
  "modpa":     { posture: "modpa",     state: "MD", responseDays: 45, extensionDays: 45, cureDays: 60,  profilingOptOut: true,  minorOptIn: 13,  notes: "Strict data-minimization; effective 2026-10-01" },                                                       // allow:raw-time-literal
  "quebec-25": { posture: "quebec-25", state: "QC", responseDays: 30, extensionDays: 30, cureDays: 0,   profilingOptOut: true,  minorOptIn: 14,  notes: "DPIA + automated-decision opt-out; FR-language obligations" },
  "fl-fdbr":   { posture: "fl-fdbr",   state: "FL", responseDays: 45, extensionDays: 15, cureDays: 30,  profilingOptOut: true,  minorOptIn: 13,  notes: "Narrow scope ($1B+ revenue threshold); effective 2024-07-01; AG-only enforcement" },
});

/**
 * @primitive b.dsr.stateRules
 * @signature b.dsr.stateRules(state)
 * @since     0.8.77
 * @related   b.compliance.describe
 *
 * Returns per-state DSR rules: response window, extension period,
 * cure period (statutory grace before enforcement attaches),
 * profiling-opt-out availability, and minor-consent age threshold.
 * `state` accepts either the posture name (`"vcdpa"`) or the
 * 2-letter state abbreviation (`"VA"`). Returns null when unknown.
 *
 * @example
 *   var rules = b.dsr.stateRules("vcdpa");
 *   // rules.responseDays    → 45
 *   // rules.cureDays        → 30
 *   // rules.profilingOptOut → true
 */
function stateRules(state) {
  if (typeof state !== "string" || state.length === 0) return null;
  // Direct posture-name lookup first
  if (STATE_RULES[state]) return Object.assign({}, STATE_RULES[state]);
  // 2-letter state abbreviation lookup (case-insensitive)
  var u = state.toUpperCase();
  var keys = Object.keys(STATE_RULES);
  for (var i = 0; i < keys.length; i++) {
    if (STATE_RULES[keys[i]].state === u) {
      return Object.assign({}, STATE_RULES[keys[i]]);
    }
  }
  return null;
}

/**
 * @primitive b.dsr.listStateRules
 * @signature b.dsr.listStateRules()
 * @since     0.8.77
 *
 * Returns every state-rule entry as an array (useful for admin UI
 * cure-period dashboards / operator-facing matrices).
 *
 * @example
 *   var all = b.dsr.listStateRules();
 *   // → [{ posture: "vcdpa", state: "VA", responseDays: 45, ... }, ...]
 */
function listStateRules() {
  return Object.keys(STATE_RULES).map(function (k) {
    return Object.assign({}, STATE_RULES[k]);
  });
}

module.exports = {
  create:                    create,
  memoryTicketStore:         memoryTicketStore,
  dbTicketStore:             dbTicketStore,
  VALID_REQUEST_TYPES:       VALID_REQUEST_TYPES,
  VALID_STATES:              VALID_STATES,
  VALID_VERIFICATION_LEVELS: VALID_VERIFICATION_LEVELS,
  TYPE_MIN_VERIFICATION:     TYPE_MIN_VERIFICATION,
  POSTURE_DEADLINE_MS:       POSTURE_DEADLINE_MS,
  stateRules:                stateRules,
  listStateRules:            listStateRules,
  DsrError:                  DsrError,
};

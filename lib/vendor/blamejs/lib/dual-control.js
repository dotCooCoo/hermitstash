"use strict";
/**
 * @module b.dualControl
 * @nav    Identity
 * @title  Dual Control
 *
 * @intro
 *   M-of-N approval workflow for destructive operations (eraseHard,
 *   key rotation, etc.). b.breakGlass gates a single-actor step-up
 *   (TOTP / passkey proof from the SAME actor performing the
 *   unseal); dual-control raises the bar to "two distinct named
 *   actors must approve before the operation runs" — the standard
 *   control for HIPAA admin actions, PCI key rotation, financial
 *   close, T+1 settlement, and similar compliance-sensitive flows.
 *
 *   Every state transition emits an audit row:
 *   `dual.grant.requested` / `dual.grant.approved` /
 *   `dual.grant.denied` / `dual.grant.consumed` /
 *   `dual.grant.expired` / `dual.grant.cancelled`. Each event
 *   carries the grant ID and the actor 5 W's so a compliance
 *   reviewer can reconstruct the chain.
 *
 *   Grants live in a b.cache instance the operator wires in (memory
 *   backend → per-process; cluster backend → shared across nodes).
 *   The cache TTL bounds grant freshness automatically. Optional
 *   cooling-off lock (`consumeLockMs`) defends against rapid-burst
 *   compromise of requester+approver. Optional `approverRoles`
 *   restricts approval to actors carrying a named role.
 *
 * @card
 *   M-of-N approval workflow for destructive operations (eraseHard, key rotation, etc.).
 */
var lazyRequire = require("./lazy-require");
var bCrypto = require("./crypto");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var DualControlError = defineClass("DualControlError", { alwaysPermanent: true });
var _err = DualControlError.factory;

var DEFAULTS = Object.freeze({
  ttlMs:              C.TIME.minutes(15),
  minApprovers:       2,
  forbidSelfApprove:  true,
  // Cooling-off lock between final approval and consume. Prevents the
  // "rushed approval" failure where an attacker compromises the
  // requester AND an approver in close succession and immediately
  // executes the destructive op. Default 0 (no lock); compliance
  // regimes typically pin 30s–2min.
  consumeLockMs:      0,
  // Minimum reason length on request() AND each approve(). Forces a
  // meaningful audit trail — empty / single-char reasons aren't
  // compliance-defensible. 0 disables.
  minReasonLength:    0,
  // Optional approver-role gate. When set, the approver actor MUST
  // carry one of these roles (actor.roles list) for approve() to
  // accept. The framework can't enforce role assignment from this
  // primitive — operator wires actor.roles upstream of approve().
  approverRoles:      null,
  // Notification hook fired on every state transition. Operator-
  // supplied function (event) → void; thrown errors are swallowed
  // (best-effort, the audit chain is the source of truth).
  notify:             null,
});

function _actorIdOf(actor) {
  if (!actor || typeof actor !== "object") return null;
  if (typeof actor.id === "string" && actor.id.length > 0) return actor.id;
  if (typeof actor._id === "string" && actor._id.length > 0) return actor._id;
  if (typeof actor.userId === "string" && actor.userId.length > 0) return actor.userId;
  if (typeof actor.email === "string" && actor.email.length > 0) return "email:" + actor.email;
  return null;
}

/**
 * @primitive b.dualControl.create
 * @signature b.dualControl.create(opts)
 * @since     0.8.41
 * @status    stable
 * @compliance hipaa, pci-dss, sox-404, dora, soc2
 * @related   b.breakGlass.policy.set, b.audit, b.cache.create
 *
 * Build a dual-control approval workflow bound to a `namespace`.
 * Returns a handle exposing async `request(args)` (open a pending
 * grant), `approve(args)` (a different actor approves; quorum
 * detection is automatic), `cancel(args)` (the requester withdraws),
 * `revoke(args)` (an admin denies), `consume(grantId, args)` (the
 * destructive code path single-uses the grant), and `status(grantId)`
 * for inspection. Every transition audits with the actor 5 W's.
 * Grant lifecycle is bounded by `ttlMs`; cluster-shared grants need
 * a cluster-backed cache.
 *
 * @opts
 *   namespace:          string,                          // grant key namespace (required, non-empty)
 *   cache:              b.cache,                         // b.cache instance — memory or cluster (required)
 *   audit:              b.audit,                         // optional audit sink (defaults to global b.audit)
 *   ttlMs:              number,                          // grant lifetime (default 15 minutes)
 *   minApprovers:       number,                          // approvals required to reach quorum (default 2, ≥2)
 *   forbidSelfApprove:  boolean,                         // requester cannot approve own grant (default true)
 *   consumeLockMs:      number,                          // cooling-off ms after final approval (default 0)
 *   minReasonLength:    number,                          // minimum chars on reason fields (default 0 → off)
 *   approverRoles:      Array<string>,                   // restrict approve() to actors with one of these roles (default null)
 *   notify:             function,                        // (event) → void; fired on every transition
 *
 * @example
 *   var approvals = b.dualControl.create({
 *     namespace:        "users.eraseHard",
 *     cache:            b.cache.create({ namespace: "dc", backend: "memory" }),
 *     audit:            b.audit,
 *     ttlMs:            b.constants.TIME.minutes(15),
 *     minApprovers:     2,
 *     consumeLockMs:    b.constants.TIME.minutes(2),
 *     minReasonLength:  12,
 *     approverRoles:    ["security:officer", "compliance:officer"],
 *   });
 *
 *   // Step 1: requester opens the grant.
 *   var opened = await approvals.request({
 *     action:      "users.eraseHard",
 *     resource:    { kind: "user", id: "user-42" },
 *     requestedBy: { id: "alice", roles: ["engineer"] },
 *     reason:      "GDPR Art. 17 erasure request, ticket SUP-4421",
 *     req:         req,
 *   });
 *   // → { grantId: "dc-<hex>", status: "pending", needs: 2, expiresAt: ... }
 *
 *   // Step 2: a different actor approves.
 *   var approved = await approvals.approve({
 *     grantId:  opened.grantId,
 *     approver: { id: "bob", roles: ["security:officer"] },
 *     reason:   "verified ticket SUP-4421 against subject identity",
 *     req:      req,
 *   });
 *   // → { grantId, status: "approved", approvedBy: ["alice"... wait, no: ["bob"], ... }
 *
 *   // Step 3: the destructive code path consumes the grant once.
 *   var grant = await approvals.consume(opened.grantId, { req: req });
 *   if (!grant.ready) throw new Error("dual-control: " + grant.reason);
 *   await b.db.eraseHard("users", { id: "user-42" });
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "namespace", "cache", "audit", "ttlMs", "minApprovers", "forbidSelfApprove",
    "consumeLockMs", "minReasonLength", "approverRoles", "notify",
  ], "dualControl");
  validateOpts.requireNonEmptyString(opts.namespace, "create: opts.namespace", DualControlError, "BAD_OPT");
  if (!opts.cache || typeof opts.cache.get !== "function" || typeof opts.cache.set !== "function") {
    throw _err("BAD_OPT", "create: opts.cache is required (a b.cache instance)");
  }
  var ttlMs = opts.ttlMs !== undefined ? opts.ttlMs : DEFAULTS.ttlMs;
  if (typeof ttlMs !== "number" || !isFinite(ttlMs) || ttlMs <= 0) {
    throw _err("BAD_OPT", "create: ttlMs must be a positive finite number");
  }
  var minApprovers = opts.minApprovers !== undefined ? opts.minApprovers : DEFAULTS.minApprovers;
  if (typeof minApprovers !== "number" || !isFinite(minApprovers) ||
      minApprovers < 2 || Math.floor(minApprovers) !== minApprovers) {
    throw _err("BAD_OPT", "create: minApprovers must be an integer >= 2 (dual-control by definition needs 2+)");
  }
  var forbidSelfApprove = opts.forbidSelfApprove !== undefined ? opts.forbidSelfApprove === true : DEFAULTS.forbidSelfApprove;
  var consumeLockMs = opts.consumeLockMs !== undefined ? opts.consumeLockMs : DEFAULTS.consumeLockMs;
  if (typeof consumeLockMs !== "number" || !isFinite(consumeLockMs) || consumeLockMs < 0) {
    throw _err("BAD_OPT", "create: consumeLockMs must be a non-negative finite number");
  }
  var minReasonLength = opts.minReasonLength !== undefined ? opts.minReasonLength : DEFAULTS.minReasonLength;
  if (typeof minReasonLength !== "number" || !isFinite(minReasonLength) || minReasonLength < 0 ||
      Math.floor(minReasonLength) !== minReasonLength) {
    throw _err("BAD_OPT", "create: minReasonLength must be a non-negative integer");
  }
  var approverRoles = opts.approverRoles !== undefined ? opts.approverRoles : DEFAULTS.approverRoles;
  if (approverRoles !== null) {
    if (!Array.isArray(approverRoles) || approverRoles.length === 0 ||
        !approverRoles.every(function (r) { return typeof r === "string" && r.length > 0; })) {
      throw _err("BAD_OPT", "create: approverRoles must be null or a non-empty array of role-name strings");
    }
  }
  var notifyFn = opts.notify;
  if (notifyFn !== undefined && notifyFn !== null && typeof notifyFn !== "function") {
    throw _err("BAD_OPT", "create: notify must be a function (event) => void or null");
  }
  var namespace = opts.namespace;
  var cache = opts.cache;
  var auditOn = opts.audit !== false && opts.audit != null;
  var auditInstance = (opts.audit && opts.audit !== true) ? opts.audit : null;

  function _emit(action, info, outcome, req) {
    if (auditOn) {
      var sink = auditInstance || audit();
      try {
        sink.safeEmit({
          action:   action,
          outcome:  outcome,
          actor:    requestHelpers.extractActorContext(req),
          resource: { kind: "dual.grant", id: info.grantId },
          reason:   info.reason || null,
          metadata: info,
        });
      } catch (_e) { /* best-effort */ }
    }
    if (notifyFn) {
      try { notifyFn({ action: action, outcome: outcome, info: info }); }
      catch (_e) { /* best-effort */ }
    }
  }

  function _checkReason(reason, where) {
    if (minReasonLength <= 0) return null;
    var s = (reason == null) ? "" : String(reason).trim();
    if (s.length < minReasonLength) {
      return { error: "reason-too-short",
        message: where + ": reason must be at least " + minReasonLength + " characters" };
    }
    return null;
  }

  function _approverRoleOk(actor) {
    if (!approverRoles) return true;
    if (!actor || !Array.isArray(actor.roles)) return false;
    for (var i = 0; i < approverRoles.length; i++) {
      var required = approverRoles[i];
      // Wildcard match — actor's "security:*" satisfies a required
      // "security:officer" (matching the b.permissions.match
      // semantics elsewhere in the framework). Without this, an
      // operator with a wildcard-shaped role can't approve dual-
      // control flows even when b.permissions would consider the
      // role assignment satisfied.
      for (var j = 0; j < actor.roles.length; j++) {
        var actorRole = actor.roles[j];
        if (actorRole === required) return true;
        if (typeof actorRole === "string" &&
            actorRole.length > 0 &&
            actorRole.charAt(actorRole.length - 1) === "*") {
          var prefix = actorRole.slice(0, -1);
          if (typeof required === "string" && required.indexOf(prefix) === 0) {
            return true;
          }
        }
      }
    }
    return false;
  }

  function _key(grantId) { return namespace + ":" + grantId; }

  async function request(args) {
    if (!args || typeof args !== "object") {
      throw _err("BAD_ARG", "request: args object required");
    }
    if (typeof args.action !== "string" || args.action.length === 0) {
      throw _err("BAD_ARG", "request: args.action (string) is required");
    }
    var requesterId = _actorIdOf(args.requestedBy);
    if (!requesterId) {
      throw _err("BAD_ARG", "request: args.requestedBy must be an actor with a stable id");
    }
    var reasonProblem = _checkReason(args.reason, "request");
    if (reasonProblem) {
      return Object.assign({ grantId: null }, reasonProblem);
    }
    var grantId = "dc-" + bCrypto.generateToken(C.BYTES.bytes(8));
    var nowMs = Date.now();
    var record = {
      grantId:        grantId,
      action:         args.action,
      resource:       args.resource || null,
      requestedBy:    requesterId,
      requestedAt:    nowMs,
      reason:         args.reason || null,
      approvedBy:     [],     // ordered list of approver IDs
      approvalsAt:    [],     // matching timestamps
      approvalReasons:[],
      approverRoleHits: [],   // recorded for audit when approverRoles is set
      consumedAt:     null,
      revokedAt:      null,
      revokedReason:  null,
      cancelledAt:    null,
      cancelledReason:null,
      quorumReachedAt:null,
      expiresAt:      nowMs + ttlMs,
      minApprovers:   minApprovers,
      consumeLockMs:  consumeLockMs,
    };
    await cache.set(_key(grantId), record, { ttlMs: ttlMs });
    _emit("dual.grant.requested",
      { grantId: grantId, action: args.action, requestedBy: requesterId, needs: minApprovers,
        reason: args.reason || null, expiresAt: record.expiresAt,
        consumeLockMs: consumeLockMs, approverRolesRequired: approverRoles },
      "success", args.req);
    return {
      grantId:    grantId,
      status:     "pending",
      needs:      minApprovers,
      approvedBy: [],
      expiresAt:  record.expiresAt,
    };
  }

  async function cancel(args) {
    if (!args || typeof args !== "object") throw _err("BAD_ARG", "cancel: args required");
    var actorId = _actorIdOf(args.cancelledBy);
    var outcome = await cache.update(_key(args.grantId), function (record) {
      if (!record) return { abort: { response: { error: "grant-not-found", grantId: args.grantId } } };
      if (record.consumedAt !== null) return { abort: { response: { error: "grant-already-consumed", grantId: record.grantId } } };
      if (record.revokedAt !== null)  return { abort: { response: { error: "grant-revoked", grantId: record.grantId } } };
      if (record.cancelledAt !== null) return { abort: { response: { error: "grant-already-cancelled", grantId: record.grantId } } };
      // Cancellation by anyone other than the requester is a revoke, not a
      // cancel — surface explicitly.
      if (actorId !== record.requestedBy) {
        return { abort: { response: { error: "only-requester-can-cancel", grantId: record.grantId, requestedBy: record.requestedBy } } };
      }
      record.cancelledAt = Date.now();
      record.cancelledReason = args.reason || null;
      return { value: record, expiresAt: record.expiresAt };
    }, { ttlMs: ttlMs });
    if (outcome.aborted) return outcome.aborted.response;
    var rec = outcome.value;
    _emit("dual.grant.cancelled",
      { grantId: rec.grantId, action: rec.action, cancelledBy: actorId, reason: args.reason || null },
      "success", args.req);
    return { grantId: rec.grantId, status: "cancelled" };
  }

  async function _load(grantId) {
    if (typeof grantId !== "string" || grantId.length === 0) {
      throw _err("BAD_ARG", "grantId (string) is required");
    }
    var record = await cache.get(_key(grantId));
    return record || null;
  }

  async function approve(args) {
    if (!args || typeof args !== "object") throw _err("BAD_ARG", "approve: args required");
    var approverId = _actorIdOf(args.approver);
    if (!approverId) throw _err("BAD_ARG", "approve: args.approver must be an actor with a stable id");
    // Pre-compute the pure, record-independent checks so the mutator stays
    // side-effect-free (it may re-run under cluster CAS contention).
    var roleOk = _approverRoleOk(args.approver);
    var reasonProblem = _checkReason(args.reason, "approve");
    var roleHits = (approverRoles && args.approver && Array.isArray(args.approver.roles))
      ? args.approver.roles.filter(function (r) { return approverRoles.indexOf(r) !== -1; })
      : null;

    // Atomic read-modify-write: the duplicate-approver guard and the
    // approvedBy append commit together, so two concurrent approvals (or a
    // retried one) cannot each read a stale snapshot and append the same
    // approver twice — the quorum-bypass the get/set version allowed.
    var outcome = await cache.update(_key(args.grantId), function (record) {
      if (!record) return { abort: { response: { error: "grant-not-found", grantId: args.grantId } } };
      if (record.consumedAt !== null) return { abort: { response: { error: "grant-already-consumed", grantId: record.grantId } } };
      if (record.revokedAt !== null) return { abort: { response: { error: "grant-revoked", grantId: record.grantId, revokedReason: record.revokedReason } } };
      if (record.cancelledAt !== null) return { abort: { response: { error: "grant-cancelled", grantId: record.grantId } } };
      if (record.expiresAt < Date.now()) {
        return { abort: { response: { error: "grant-expired", grantId: record.grantId },
          event: "dual.grant.expired", meta: { grantId: record.grantId, action: record.action }, outcome: "failure" } };
      }
      if (forbidSelfApprove && approverId === record.requestedBy) {
        return { abort: { response: { error: "self-approval-forbidden", grantId: record.grantId },
          event: "dual.grant.self_approval_denied",
          meta: { grantId: record.grantId, action: record.action, approver: approverId }, outcome: "denied" } };
      }
      if (!roleOk) {
        return { abort: { response: { error: "approver-role-required", grantId: record.grantId, requiredRoles: approverRoles },
          event: "dual.grant.role_denied",
          meta: { grantId: record.grantId, action: record.action, approver: approverId, requiredRoles: approverRoles,
            actorRoles: (args.approver && Array.isArray(args.approver.roles)) ? args.approver.roles : [] }, outcome: "denied" } };
      }
      if (record.approvedBy.indexOf(approverId) !== -1) {
        return { abort: { response: { error: "already-approved-by-this-actor", grantId: record.grantId, approvedBy: record.approvedBy.slice() } } };
      }
      if (reasonProblem) return { abort: { response: Object.assign({ grantId: record.grantId }, reasonProblem) } };
      record.approvedBy.push(approverId);
      record.approvalsAt.push(Date.now());
      record.approvalReasons.push(args.reason || null);
      // Record which required role satisfied the approval — an audit
      // reviewer can confirm the actor approved as e.g. security-officer.
      if (roleHits) record.approverRoleHits.push(roleHits);
      if (record.approvedBy.length >= record.minApprovers && record.quorumReachedAt === null) {
        record.quorumReachedAt = Date.now();
      }
      return { value: record, expiresAt: record.expiresAt };
    }, { ttlMs: ttlMs });

    if (outcome.aborted) {
      var ab = outcome.aborted;
      if (ab.event) _emit(ab.event, ab.meta, ab.outcome, args.req);
      return ab.response;
    }
    var rec = outcome.value;
    var status = (rec.approvedBy.length >= rec.minApprovers) ? "approved" : "pending";
    var consumeUnlockAt = rec.quorumReachedAt !== null ? rec.quorumReachedAt + rec.consumeLockMs : null;
    _emit("dual.grant.approved",
      { grantId: rec.grantId, action: rec.action, approver: approverId,
        approverCount: rec.approvedBy.length, needs: rec.minApprovers,
        status: status, reason: args.reason || null, consumeUnlockAt: consumeUnlockAt },
      "success", args.req);
    return {
      grantId:    rec.grantId,
      status:     status,
      approvedBy: rec.approvedBy.slice(),
      needs:      rec.minApprovers,
      expiresAt:  rec.expiresAt,
      consumeUnlockAt: consumeUnlockAt,
    };
  }

  async function revoke(args) {
    if (!args || typeof args !== "object") throw _err("BAD_ARG", "revoke: args required");
    var revokedById = _actorIdOf(args.revokedBy);
    var outcome = await cache.update(_key(args.grantId), function (record) {
      if (!record) return { abort: { response: { error: "grant-not-found", grantId: args.grantId } } };
      if (record.consumedAt !== null) return { abort: { response: { error: "grant-already-consumed", grantId: record.grantId } } };
      record.revokedAt = Date.now();
      record.revokedReason = args.reason || null;
      return { value: record, expiresAt: record.expiresAt };
    }, { ttlMs: ttlMs });
    if (outcome.aborted) return outcome.aborted.response;
    var rec = outcome.value;
    _emit("dual.grant.denied",
      { grantId: rec.grantId, action: rec.action, revokedBy: revokedById, reason: args.reason || null },
      "denied", args.req);
    return { grantId: rec.grantId, status: "revoked" };
  }

  async function consume(grantId, args) {
    args = args || {};
    // Atomic read-modify-write: the consumedAt check and the consumedAt set
    // commit together (compare-and-set), so two concurrent consumes cannot
    // both observe consumedAt === null and both proceed — exactly one wins
    // and runs the destructive operation. The get/set version let a
    // single-use grant be consumed twice.
    var outcome = await cache.update(_key(grantId), function (record) {
      if (!record) return { abort: { response: { ready: false, reason: "grant-not-found" } } };
      if (record.revokedAt !== null) return { abort: { response: { ready: false, reason: "revoked" } } };
      if (record.cancelledAt !== null) return { abort: { response: { ready: false, reason: "cancelled" } } };
      if (record.consumedAt !== null) return { abort: { response: { ready: false, reason: "already-consumed" } } };
      if (record.expiresAt < Date.now()) {
        return { abort: { response: { ready: false, reason: "expired" }, del: true,
          event: "dual.grant.expired", meta: { grantId: record.grantId, action: record.action }, outcome: "failure" } };
      }
      if (record.approvedBy.length < record.minApprovers) {
        return { abort: { response: { ready: false, reason: "not-enough-approvers",
          approvedBy: record.approvedBy.slice(), needs: record.minApprovers } } };
      }
      // Cooling-off lock: a quorum-reached grant can't consume until
      // consumeLockMs has passed since the final approval — defends against
      // rapid-burst compromise of requester + approver.
      if ((record.consumeLockMs || 0) > 0 && record.quorumReachedAt !== null) {
        var unlockAt = record.quorumReachedAt + record.consumeLockMs;
        if (Date.now() < unlockAt) {
          return { abort: { response: { ready: false, reason: "consume-locked", unlockAt: unlockAt, waitMs: unlockAt - Date.now() },
            event: "dual.grant.consume_locked",
            meta: { grantId: record.grantId, action: record.action, unlockAt: unlockAt, waitMs: unlockAt - Date.now() }, outcome: "denied" } };
        }
      }
      record.consumedAt = Date.now();
      return { value: record, expiresAt: record.expiresAt };
    }, { ttlMs: ttlMs });

    if (outcome.aborted) {
      var ab = outcome.aborted;
      if (ab.event) _emit(ab.event, ab.meta, ab.outcome, args.req);
      if (ab.del) { try { await cache.del(_key(grantId)); } catch (_e) { /* sweep handles it */ } }
      return ab.response;
    }
    var rec = outcome.value;
    // Single-use by design — drop the (now consumed) grant from the cache.
    await cache.del(_key(rec.grantId));
    _emit("dual.grant.consumed",
      { grantId: rec.grantId, action: rec.action,
        approvedBy: rec.approvedBy.slice(), approvalReasons: rec.approvalReasons.slice() },
      "success", args.req);
    return {
      ready:      true,
      grantId:    rec.grantId,
      action:     rec.action,
      resource:   rec.resource,
      approvedBy: rec.approvedBy.slice(),
      requestedBy:rec.requestedBy,
    };
  }

  async function status(grantId) {
    var record = await _load(grantId);
    if (!record) return null;
    var s = "pending";
    if (record.revokedAt !== null) s = "revoked";
    else if (record.cancelledAt !== null) s = "cancelled";
    else if (record.consumedAt !== null) s = "consumed";
    else if (record.expiresAt < Date.now()) s = "expired";
    else if (record.approvedBy.length >= record.minApprovers) s = "approved";
    return {
      grantId:         record.grantId,
      action:          record.action,
      status:          s,
      requestedBy:     record.requestedBy,
      approvedBy:      record.approvedBy.slice(),
      needs:           record.minApprovers,
      expiresAt:       record.expiresAt,
      quorumReachedAt: record.quorumReachedAt,
      consumeUnlockAt: record.quorumReachedAt !== null && record.consumeLockMs > 0
        ? record.quorumReachedAt + record.consumeLockMs : null,
    };
  }

  return {
    request:  request,
    approve:  approve,
    revoke:   revoke,
    cancel:   cancel,
    consume:  consume,
    status:   status,
  };
}

module.exports = {
  create:           create,
  DualControlError: DualControlError,
};

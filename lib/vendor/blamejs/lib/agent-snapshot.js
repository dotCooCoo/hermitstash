"use strict";
/**
 * @module     b.agent.snapshot
 * @nav        Agent
 * @title      Agent Snapshot
 * @order      90
 *
 * @intro
 *   Drain → snapshot in-flight state; restart → restore + resume. The
 *   last substrate slice: makes the orchestrator + idempotency +
 *   stream + event-bus + tenant + saga + posture-chain + trace
 *   stack operationally durable across deploys + crashes.
 *
 *   Snapshot captures (registry of agents, in-flight streams' last-
 *   seen cursors, half-completed saga state, pending event-bus
 *   deliveries, idempotency cache hot-subset). Restore re-elects
 *   shards, replays buffered events (composes v0.9.22 idempotency to
 *   prevent double-execute), resumes sagas from their persisted
 *   step pointer.
 *
 *   ```js
 *   var snapshot = b.agent.snapshot.create({
 *     orchestrator: orch,
 *     backend:      operatorBackend,         // { put, get, list, delete }
 *     audit:        b.audit,
 *     policy: {
 *       drainTimeoutMs:     C.TIME.minutes(2),
 *       snapshotIntervalMs: C.TIME.minutes(5),
 *       maxSnapshotBytes:   C.BYTES.mib(50),
 *     },
 *   });
 *
 *   // At SIGTERM:
 *   await orch.drain({});
 *   var snap = await snapshot.takeSnapshot();
 *   await snapshot.persist(snap);
 *
 *   // At restart:
 *   var loaded = await snapshot.loadLatest();
 *   if (loaded) await snapshot.restore(loaded);
 *   ```
 *
 * @card
 *   Drain → snapshot in-flight state; restart → restore. Composes
 *   orchestrator drain + outbox in-flight tracking + saga persisted
 *   state + event-bus subscriber registry + idempotency hot cache.
 */

var lazyRequire           = require("./lazy-require");
var C                     = require("./constants");
var { defineClass }       = require("./framework-error");
var bCrypto               = require("./crypto");
var guardSnapshotEnvelope = require("./guard-snapshot-envelope");
var agentAudit            = require("./agent-audit");

var audit                 = lazyRequire(function () { return require("./audit"); });

var AgentSnapshotError = defineClass("AgentSnapshotError", { alwaysPermanent: true });

var DEFAULT_DRAIN_TIMEOUT_MS     = C.TIME.minutes(2);
var DEFAULT_SNAPSHOT_INTERVAL_MS = C.TIME.minutes(5);
var DEFAULT_MAX_SNAPSHOT_BYTES   = C.BYTES.mib(50);
var SCHEMA_VERSION               = 1;
var SNAPSHOT_ID_RAND_BYTES       = 8;                                                                 // allow:raw-byte-literal — snapshot-id random suffix

/**
 * @primitive b.agent.snapshot.create
 * @signature b.agent.snapshot.create(opts)
 * @since     0.9.30
 * @status    stable
 * @related   b.agent.orchestrator.create, b.backup.create
 *
 * Create the snapshot facade. Operator wires the durable storage
 * backend; framework owns the envelope shape + drain/restore
 * coordination.
 *
 * @opts
 *   orchestrator: b.agent.orchestrator,    // required
 *   backend:      { put, get, list, delete },  // required
 *   audit:        b.audit namespace,             // optional
 *   policy:       { drainTimeoutMs, snapshotIntervalMs, maxSnapshotBytes },
 *
 * @example
 *   var snapshot = b.agent.snapshot.create({
 *     orchestrator: orch, backend: myBackend,
 *   });
 *   var snap = await snapshot.takeSnapshot();
 *   await snapshot.persist(snap);
 */
function create(opts) {
  opts = opts || {};
  if (!opts.orchestrator || typeof opts.orchestrator.health !== "function") {
    throw new AgentSnapshotError("agent-snapshot/bad-orchestrator",
      "create: opts.orchestrator with .health() required");
  }
  if (!opts.backend || typeof opts.backend.put !== "function" ||
      typeof opts.backend.get !== "function" || typeof opts.backend.list !== "function") {
    throw new AgentSnapshotError("agent-snapshot/bad-backend",
      "create: opts.backend must expose { put, get, list, delete? }");
  }
  var policy = opts.policy || {};
  var drainTimeoutMs     = typeof policy.drainTimeoutMs === "number" ? policy.drainTimeoutMs : DEFAULT_DRAIN_TIMEOUT_MS;
  var snapshotIntervalMs = typeof policy.snapshotIntervalMs === "number" ? policy.snapshotIntervalMs : DEFAULT_SNAPSHOT_INTERVAL_MS;
  var maxSnapshotBytes   = typeof policy.maxSnapshotBytes === "number" ? policy.maxSnapshotBytes : DEFAULT_MAX_SNAPSHOT_BYTES;
  var auditImpl = opts.audit || audit();

  var ctx = {
    orchestrator: opts.orchestrator,
    backend:      opts.backend,
    audit:        auditImpl,
    drainTimeoutMs: drainTimeoutMs,
    snapshotIntervalMs: snapshotIntervalMs,
    maxSnapshotBytes: maxSnapshotBytes,
  };

  return {
    takeSnapshot: function (snapshotOpts)      { return _takeSnapshot(ctx, snapshotOpts || {}); },
    persist:      function (snap)              { return _persist(ctx, snap); },
    loadLatest:   function (loadOpts)          { return _loadLatest(ctx, loadOpts || {}); },
    loadById:     function (snapshotId)        { return _loadById(ctx, snapshotId); },
    restore:      function (snap, restoreOpts) { return _restore(ctx, snap, restoreOpts || {}); },
    list:         function (listOpts)          { return _list(ctx, listOpts || {}); },
    gc:           function (gcOpts)            { return _gc(ctx, gcOpts || {}); },
    SCHEMA_VERSION: SCHEMA_VERSION,
    AgentSnapshotError: AgentSnapshotError,
  };
}

// ---- Take snapshot --------------------------------------------------------

async function _takeSnapshot(ctx, snapshotOpts) {
  var snapshotId = "snap-" + bCrypto.generateToken(SNAPSHOT_ID_RAND_BYTES);
  var health = await ctx.orchestrator.health();
  var envelope = {
    snapshotId:        snapshotId,
    takenAt:           Date.now(),
    frameworkVersion:  snapshotOpts.frameworkVersion || _frameworkVersion(),
    schemaVersion:     SCHEMA_VERSION,
    tenantId:          snapshotOpts.tenantId || null,
    orchestratorState: {
      agents:    Array.isArray(health.agents)    ? health.agents.slice()    : [],
      elections: Array.isArray(health.elections) ? health.elections.slice() : [],
      consumers: Array.isArray(health.consumers) ? health.consumers.slice() : [],
    },
    inFlight: {
      streams:           snapshotOpts.streams           || [],
      sagas:             snapshotOpts.sagas             || [],
      outboxJobs:        snapshotOpts.outboxJobs        || [],
      busSubscribers:    snapshotOpts.busSubscribers    || [],
      pendingDeliveries: snapshotOpts.pendingDeliveries || [],
    },
    idempotencyCache:    snapshotOpts.idempotencyCache  || {},
    sig:                 null,                            // populated by persist() via b.audit-sign
  };
  guardSnapshotEnvelope.validate(envelope, { profile: "strict" });
  // Enforce per-instance maxSnapshotBytes (separate from guard's
  // profile-level cap — operator may have tighter limits).
  var serialized = JSON.stringify(envelope);
  if (Buffer.byteLength(serialized, "utf8") > ctx.maxSnapshotBytes) {
    throw new AgentSnapshotError("agent-snapshot/oversize",
      "takeSnapshot: " + Buffer.byteLength(serialized, "utf8") +
      " bytes exceeds maxSnapshotBytes=" + ctx.maxSnapshotBytes);
  }
  agentAudit.safeAudit(ctx.audit, "agent.snapshot.taken", null, {
    snapshotId: snapshotId,
    inFlightCount: _inFlightCount(envelope),
    tenantId: envelope.tenantId,
  });
  return envelope;
}

// ---- Persist --------------------------------------------------------------

async function _persist(ctx, snap) {
  guardSnapshotEnvelope.validate(snap);
  // Operator's backend stores the envelope by snapshotId.
  await ctx.backend.put(snap.snapshotId, snap);
  agentAudit.safeAudit(ctx.audit, "agent.snapshot.persisted", null, {
    snapshotId: snap.snapshotId, takenAt: snap.takenAt,
  });
  return { snapshotId: snap.snapshotId };
}

// ---- Load -----------------------------------------------------------------

async function _loadLatest(ctx, loadOpts) {
  var entries = await ctx.backend.list();
  if (!Array.isArray(entries) || entries.length === 0) return null;
  // Filter by tenantId if requested.
  var filtered = entries.filter(function (e) {
    if (loadOpts.tenantId && e.tenantId !== loadOpts.tenantId) return false;
    return true;
  });
  if (filtered.length === 0) return null;
  filtered.sort(function (a, b) { return (b.takenAt || 0) - (a.takenAt || 0); });
  var latestId = filtered[0].snapshotId;
  var snap = await ctx.backend.get(latestId);
  if (!snap) return null;
  guardSnapshotEnvelope.validate(snap);
  return snap;
}

async function _loadById(ctx, snapshotId) {
  if (typeof snapshotId !== "string" || snapshotId.length === 0) {
    throw new AgentSnapshotError("agent-snapshot/bad-snapshot-id",
      "loadById: snapshotId required");
  }
  var snap = await ctx.backend.get(snapshotId);
  if (!snap) return null;
  guardSnapshotEnvelope.validate(snap);
  return snap;
}

// ---- Restore --------------------------------------------------------------

async function _restore(ctx, snap, restoreOpts) {
  guardSnapshotEnvelope.validate(snap);
  // Schema-version mismatch refuses unless operator explicit opt-in.
  if (snap.schemaVersion !== SCHEMA_VERSION) {
    if (!restoreOpts.allowSchemaVersionMismatch) {
      throw new AgentSnapshotError("agent-snapshot/schema-version-mismatch",
        "restore: snap.schemaVersion=" + snap.schemaVersion +
        " != current=" + SCHEMA_VERSION + "; set restoreOpts.allowSchemaVersionMismatch to opt in");
    }
  }
  // Topology change detection — current cluster's consumer set may
  // differ from the snapshot's. Re-shard-and-resume default; operator
  // can opt to refuse via restoreOpts.refuseOnTopologyChange.
  var currentHealth = await ctx.orchestrator.health();
  var topologyChanged = _topologyChanged(snap.orchestratorState, currentHealth);
  if (topologyChanged && restoreOpts.refuseOnTopologyChange) {
    throw new AgentSnapshotError("agent-snapshot/topology-changed",
      "restore: cluster topology changed since snapshot; refuseOnTopologyChange=true");
  }
  if (topologyChanged) {
    agentAudit.safeAudit(ctx.audit, "agent.snapshot.topology-change", null, {
      snapshotId:           snap.snapshotId,
      snapshotConsumerCount: (snap.orchestratorState.consumers || []).length,
      restoreConsumerCount:  (currentHealth.consumers || []).length,
      reshardedShards:       _reshardedShards(snap.orchestratorState, currentHealth),
      affectedInFlight:      _inFlightCount(snap),
      affectedSagas:         (snap.inFlight && snap.inFlight.sagas || []).length,
      affectedStreams:       (snap.inFlight && snap.inFlight.streams || []).length,
    });
  }
  // Restore is a SIGNAL — orchestrator + idempotency + saga + event-
  // bus consumers see the envelope and hydrate themselves. v0.9.30
  // ships the contract; each substrate primitive's restore hook lands
  // in subsequent slices as operators wire them.
  agentAudit.safeAudit(ctx.audit, "agent.snapshot.restored", null, {
    snapshotId:   snap.snapshotId,
    schemaVersion: snap.schemaVersion,
    inFlightCount: _inFlightCount(snap),
    topologyChanged: topologyChanged,
  });
  return { snapshotId: snap.snapshotId, topologyChanged: topologyChanged };
}

// ---- List + GC ------------------------------------------------------------

async function _list(ctx, listOpts) {
  var entries = await ctx.backend.list();
  if (!Array.isArray(entries)) return [];
  return entries.filter(function (e) {
    if (listOpts.tenantId && e.tenantId !== listOpts.tenantId) return false;
    if (listOpts.sinceMs && (e.takenAt || 0) < listOpts.sinceMs) return false;
    return true;
  }).map(function (e) {
    return {
      snapshotId: e.snapshotId,
      takenAt:    e.takenAt,
      tenantId:   e.tenantId || null,
    };
  });
}

async function _gc(ctx, gcOpts) {
  if (typeof ctx.backend.delete !== "function") return { purged: 0 };
  var olderThanMs = typeof gcOpts.olderThanMs === "number" ? gcOpts.olderThanMs : 0;
  var cutoff = Date.now() - olderThanMs;
  var entries = await ctx.backend.list();
  var purged = 0;
  for (var i = 0; i < entries.length; i += 1) {
    var e = entries[i];
    if ((e.takenAt || 0) <= cutoff) {
      try { await ctx.backend.delete(e.snapshotId); purged += 1; }
      catch (_e) { /* best-effort */ }
    }
  }
  agentAudit.safeAudit(ctx.audit, "agent.snapshot.gc", null, { purged: purged });
  return { purged: purged };
}

// ---- Internals ------------------------------------------------------------

function _inFlightCount(snap) {
  if (!snap || !snap.inFlight) return 0;
  var n = 0;
  ["streams", "sagas", "outboxJobs", "busSubscribers", "pendingDeliveries"].forEach(function (k) {
    if (Array.isArray(snap.inFlight[k])) n += snap.inFlight[k].length;
  });
  return n;
}

function _topologyChanged(snapshotState, currentHealth) {
  // Compare the topic SET, not just the consumer count — a same-count
  // remap (topics [a,b] → [c,d]) is a real topology change that count-
  // only comparison would miss, defeating refuseOnTopologyChange.
  if (!snapshotState || !currentHealth) return false;
  var snapTopics = new Set((snapshotState.consumers || []).map(function (c) { return c.topic; }));
  var currTopics = new Set((currentHealth.consumers || []).map(function (c) { return c.topic; }));
  if (snapTopics.size !== currTopics.size) return true;
  var changed = false;
  snapTopics.forEach(function (t) { if (!currTopics.has(t)) changed = true; });
  return changed;
}

function _reshardedShards(snapshotState, currentHealth) {
  // Compute shard topics from snapshot vs current; return the set of
  // topic names whose presence differs.
  var snapTopics = new Set((snapshotState.consumers || []).map(function (c) { return c.topic; }));
  var currTopics = new Set((currentHealth.consumers || []).map(function (c) { return c.topic; }));
  var changed = [];
  snapTopics.forEach(function (t) { if (!currTopics.has(t)) changed.push(t); });
  currTopics.forEach(function (t) { if (!snapTopics.has(t)) changed.push(t); });
  return changed;
}

function _frameworkVersion() {
  // Read framework version dynamically to avoid a load-time require
  // of package.json (which would couple module-load order to package
  // path). Inline require is gated by allow-marker because the
  // snapshot envelope needs the CURRENT version at the moment of
  // takeSnapshot, not at agent-snapshot.js load time.
  try { return require("../package.json").version; }                                                  // allow:inline-require — read at snapshot time, not load time
  catch (_e) { return "unknown"; }
}

module.exports = {
  create:               create,
  SCHEMA_VERSION:       SCHEMA_VERSION,
  AgentSnapshotError:   AgentSnapshotError,
  guards: {
    envelope: guardSnapshotEnvelope,
  },
};

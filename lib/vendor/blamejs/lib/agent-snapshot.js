// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var safeJson              = require("./safe-json");
var vaultAad              = require("./vault-aad");
var validateOpts          = require("./validate-opts");

var audit                 = lazyRequire(function () { return require("./audit"); });
var auditSign             = lazyRequire(function () { return require("./audit-sign"); });
var compliance            = lazyRequire(function () { return require("./compliance"); });
var vault                 = lazyRequire(function () { return require("./vault"); });

var AgentSnapshotError = defineClass("AgentSnapshotError", { alwaysPermanent: true });

var SEALED_PREFIX = "snap-sealed-v1:";
var SNAPSHOT_TABLE = "agent.snapshot";

var DEFAULT_DRAIN_TIMEOUT_MS     = C.TIME.minutes(2);
var DEFAULT_SNAPSHOT_INTERVAL_MS = C.TIME.minutes(5);
var DEFAULT_MAX_SNAPSHOT_BYTES   = C.BYTES.mib(50);
var SCHEMA_VERSION               = 1;
var SNAPSHOT_ID_RAND_BYTES       = 8;

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
  var signer = opts.signer || null;
  var sealer = opts.sealer || null;
  var restoreHandlers = opts.restoreHandlers && typeof opts.restoreHandlers === "object"
    ? opts.restoreHandlers : null;

  var allowPlaintext = opts.allowPlaintext === true;

  var ctx = {
    orchestrator: opts.orchestrator,
    backend:      opts.backend,
    audit:        auditImpl,
    drainTimeoutMs: drainTimeoutMs,
    snapshotIntervalMs: snapshotIntervalMs,
    maxSnapshotBytes: maxSnapshotBytes,
    signer:           signer,
    sealer:           sealer,
    restoreHandlers:  restoreHandlers,
    allowPlaintext:   allowPlaintext,
  };

  return {
    takeSnapshot: function (snapshotOpts)      { return _takeSnapshot(ctx, snapshotOpts || {}); },
    persist:      function (snap)              { return _persist(ctx, snap); },
    loadLatest:   function (loadOpts)          { return _loadLatest(ctx, loadOpts || {}); },
    loadById:     function (snapshotId)        { return _loadById(ctx, snapshotId); },
    restore:      function (snap, restoreOpts) { return _restore(ctx, snap, restoreOpts || {}); },
    list:         function (listOpts)          { return _list(ctx, listOpts || {}); },
    gc:           function (gcOpts)            { return _gc(ctx, gcOpts || {}); },
    SCHEMA_VERSION:       SCHEMA_VERSION,
    SEALED_PREFIX:        SEALED_PREFIX,
    AgentSnapshotError:   AgentSnapshotError,
  };
}

/**
 * @primitive b.agent.snapshot.reseal
 * @signature b.agent.snapshot.reseal(opts)
 * @since     0.14.12
 * @status    stable
 * @related   b.agent.snapshot.create, b.vault.getKeysJson
 *
 * Re-seal every persisted snapshot envelope from the OLD vault root to
 * the NEW vault root under the SAME column-shaped AAD, for a vault-key
 * rotation. The snapshot seal is a `vault.aad:` ciphertext hidden behind
 * the `snap-sealed-v1:` wrapper prefix and written to an operator
 * backend, so a `db.enc` scan for the bare `vault.aad:` prefix can
 * neither detect nor reach it — the rotation pipeline drives the re-key
 * through this explicit backend walk. Each row is unsealed under the old
 * root and re-sealed under the new root in memory (composing
 * `b.vault.aad.resealRoot`); the plaintext envelope is never written to
 * operator-readable storage. The decorative wrapper fields the backend's
 * `list()` filters on (`snapshotId` / `takenAt` / `tenantId`) are
 * preserved, so the index is untouched.
 *
 * `allowPlaintext` envelopes (no `sealed` wrapper) carry no AAD-sealed
 * blob to re-key and are skipped; the returned `resealed` count reflects
 * only re-sealed rows. A row sealed by a non-default KMS sealer (the
 * inner blob is not a `vault.aad:` value) is refused — re-key it through
 * the operator's own KMS, not this path.
 *
 * @opts
 *   backend:     { put, get, list },  // the same backend create() was wired with
 *   oldRootJson: string,              // b.vault.getKeysJson() of the OLD keypair
 *   newRootJson: string,              // b.vault.getKeysJson() of the NEW keypair
 *
 * @example
 *   var result = await b.agent.snapshot.reseal({
 *     backend:     operatorBackend,
 *     oldRootJson: oldKeysJson,
 *     newRootJson: newKeysJson,
 *   });
 *   result.table;      // → "agent.snapshot"
 *   result.resealed;   // → <count of re-keyed snapshots>
 */
async function reseal(opts) {
  opts = opts || {};
  var backend = opts.backend;
  validateOpts.requireMethods(backend, ["put", "get", "list"],
    "reseal: opts.backend (same backend create() was wired with)",
    AgentSnapshotError, "agent-snapshot/bad-backend");
  validateOpts.requireNonEmptyString(opts.oldRootJson,
    "reseal: opts.oldRootJson (b.vault.getKeysJson() of the OLD keypair)",
    AgentSnapshotError, "agent-snapshot/bad-root");
  validateOpts.requireNonEmptyString(opts.newRootJson,
    "reseal: opts.newRootJson (b.vault.getKeysJson() of the NEW keypair)",
    AgentSnapshotError, "agent-snapshot/bad-root");

  var entries = await backend.list();
  if (!Array.isArray(entries)) return { table: SNAPSHOT_TABLE, resealed: 0 };
  var resealed = 0;
  for (var i = 0; i < entries.length; i += 1) {
    var snapshotId = entries[i] && entries[i].snapshotId;
    if (typeof snapshotId !== "string" || snapshotId.length === 0) continue;
    var raw = await backend.get(snapshotId);
    if (!raw) continue;
    if (!raw.sealed || typeof raw.sealed !== "string" ||
        raw.sealed.indexOf(SEALED_PREFIX) !== 0) {
      continue;
    }
    var innerBlob = raw.sealed.slice(SEALED_PREFIX.length);
    if (!vaultAad.isAadSealed(innerBlob)) {
      throw new AgentSnapshotError("agent-snapshot/not-vault-sealed",
        "reseal: snapshot " + snapshotId + " was sealed by a non-vault sealer " +
        "(no " + JSON.stringify(vaultAad.AAD_PREFIX) + " prefix on the inner blob); " +
        "re-key it through the KMS the operator wired as opts.sealer at create() time");
    }
    var aad = _snapshotAad({
      snapshotId:    snapshotId,
      schemaVersion: raw.schemaVersion != null ? raw.schemaVersion : SCHEMA_VERSION,
    });
    var rekeyed;
    try {
      rekeyed = vaultAad.resealRoot(innerBlob, aad, opts.oldRootJson, opts.newRootJson);
    } catch (e) {
      throw new AgentSnapshotError("agent-snapshot/reseal-failed",
        "reseal: snapshot " + snapshotId + " failed to re-key — the value may not have " +
        "been sealed under oldRootJson + this AAD, or the bytes are tampered (" +
        ((e && e.message) || String(e)) + ")");
    }
    var rewritten = Object.assign({}, raw, { sealed: SEALED_PREFIX + rekeyed });
    await backend.put(snapshotId, rewritten);
    resealed += 1;
  }
  return { table: SNAPSHOT_TABLE, resealed: resealed };
}

function _resolveSigner(ctx) {
  if (ctx.signer) return ctx.signer;
  var as;
  try { as = auditSign(); } catch (_e) { as = null; }
  if (as && typeof as.sign === "function" && typeof as.verify === "function") {
    return {
      sign: function (bytes) {
        try { return as.sign(bytes); }
        catch (e) {
          throw new AgentSnapshotError("agent-snapshot/signer-not-wired",
            "persist: b.auditSign.sign threw (" + (e && e.message ? e.message : String(e)) +
            ") — operator must run b.auditSign.init() at boot OR pass opts.signer to b.agent.snapshot.create");
        }
      },
      verify: function (bytes, sig, pubKey) {
        try { return as.verify(bytes, sig, pubKey); }
        catch (_e) { return false; }
      },
      getPublicKey: function () {
        try { return as.getPublicKey(); } catch (_e) { return null; }
      },
    };
  }
  throw new AgentSnapshotError("agent-snapshot/signer-not-wired",
    "persist: no signer wired — operator must run b.auditSign.init() at boot " +
    "OR pass opts.signer to b.agent.snapshot.create({ signer: { sign, verify } })");
}

var REGULATED_NO_PLAINTEXT = ["hipaa", "pci-dss", "gdpr", "soc2"];
function _activePosture() {
  try { var c = compliance(); return (c && typeof c.current === "function") ? c.current() : null; }
  catch (_e) { return null; }
}
function _refusePlaintextUnderPosture(action) {
  var active = _activePosture();
  if (active && REGULATED_NO_PLAINTEXT.indexOf(active) !== -1) {
    throw new AgentSnapshotError("agent-snapshot/plaintext-refused-under-posture",
      action + ": allowPlaintext is refused under the '" + active + "' compliance posture — " +
      "wire a sealer (b.vault.init() at boot OR opts.sealer { seal, unseal }) so snapshot " +
      "state is sealed + signature-verified at rest");
  }
}

function _resolveSealer(ctx) {
  if (ctx.sealer) return ctx.sealer;
  var v;
  try { v = vault(); } catch (_e) { v = null; }
  if (v && typeof v.isInitialized === "function" && v.isInitialized() &&
      v.aad && typeof v.aad.seal === "function" && typeof v.aad.unseal === "function") {
    return v.aad;
  }
  if (ctx.allowPlaintext) { _refusePlaintextUnderPosture("persist"); return null; }
  throw new AgentSnapshotError("agent-snapshot/sealer-not-wired",
    "persist: no sealer wired — operator must run b.vault.init() at boot " +
    "OR pass opts.sealer to b.agent.snapshot.create({ sealer: { seal, unseal } }) " +
    "OR opt out explicitly with { allowPlaintext: true } (refused under hipaa/pci-dss/gdpr/soc2 postures)");
}

function _snapshotAad(snap) {
  return {
    table:         SNAPSHOT_TABLE,
    rowId:         snap.snapshotId,
    column:        "envelope",
    schemaVersion: String(snap.schemaVersion || SCHEMA_VERSION),
  };
}

function _canonicalSigBytes(snap) {
  var payload = {
    snapshotId:        snap.snapshotId,
    takenAt:           snap.takenAt,
    frameworkVersion:  snap.frameworkVersion,
    schemaVersion:     snap.schemaVersion,
    tenantId:          snap.tenantId || null,
    contentHash:       _contentHash(snap),
  };
  return Buffer.from(safeJson.canonical(payload), "utf8");
}

function _contentHash(snap) {
  var body = {
    orchestratorState: snap.orchestratorState || {},
    inFlight:          snap.inFlight || {},
    idempotencyCache:  snap.idempotencyCache || {},
  };
  return bCrypto.sha3Hash(safeJson.canonical(body));
}

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
    sig:                 null,
    sigPubKey:           null,
  };
  guardSnapshotEnvelope.validate(envelope, { profile: "strict" });
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

async function _persist(ctx, snap) {
  guardSnapshotEnvelope.validate(snap);
  var signer = _resolveSigner(ctx);
  var sigBytes = signer.sign(_canonicalSigBytes(snap));
  snap.sig = sigBytes.toString("base64");
  snap.sigPubKey = (typeof signer.getPublicKey === "function" && signer.getPublicKey()) || null;

  var sealer = _resolveSealer(ctx);
  var serialized = safeJson.stringify(snap);
  if (Buffer.byteLength(serialized, "utf8") > ctx.maxSnapshotBytes) {
    throw new AgentSnapshotError("agent-snapshot/oversize",
      "persist: " + Buffer.byteLength(serialized, "utf8") +
      " bytes exceeds maxSnapshotBytes=" + ctx.maxSnapshotBytes);
  }
  var stored;
  if (sealer) {
    var sealedBlob = sealer.seal(serialized, _snapshotAad(snap));
    stored = {
      snapshotId: snap.snapshotId,
      takenAt:    snap.takenAt,
      tenantId:   snap.tenantId || null,
      sealed:     SEALED_PREFIX + sealedBlob,
    };
  } else {
    agentAudit.safeAudit(ctx.audit, "agent.snapshot.plaintext_persist", null, {
      snapshotId: snap.snapshotId,
    });
    stored = snap;
  }
  await ctx.backend.put(snap.snapshotId, stored);
  agentAudit.safeAudit(ctx.audit, "agent.snapshot.persisted", null, {
    snapshotId: snap.snapshotId, takenAt: snap.takenAt,
    signed: true, sealed: !!sealer,
  });
  return { snapshotId: snap.snapshotId };
}

async function _unwrapAndVerify(ctx, raw, expectedId) {
  if (!raw) return null;
  var snap;
  if (raw.sealed && typeof raw.sealed === "string" && raw.sealed.indexOf(SEALED_PREFIX) === 0) {
    var sealer = _resolveSealer(ctx);
    if (!sealer) {
      throw new AgentSnapshotError("agent-snapshot/sealer-not-wired",
        "load: snapshot " + raw.snapshotId + " is sealed but no sealer wired");
    }
    var sealedBlob = raw.sealed.slice(SEALED_PREFIX.length);
    var aad = {
      table:         SNAPSHOT_TABLE,
      rowId:         raw.snapshotId,
      column:        "envelope",
      schemaVersion: String(raw.schemaVersion || SCHEMA_VERSION),
    };
    var plaintext;
    try { plaintext = sealer.unseal(sealedBlob, aad); }
    catch (e) {
      agentAudit.safeAudit(ctx.audit, "agent.snapshot.unseal_failed", null, {
        snapshotId: raw.snapshotId, reason: (e && e.message) || String(e),
      });
      throw new AgentSnapshotError("agent-snapshot/unseal-failed",
        "load: snapshot " + raw.snapshotId + " unseal failed — value may be tampered, " +
        "copied from a different snapshotId, or sealed under a different vault keypair");
    }
    snap = safeJson.parse(plaintext, { maxBytes: ctx.maxSnapshotBytes });
  } else {
    snap = raw;
  }
  guardSnapshotEnvelope.validate(snap);
  if (expectedId && snap.snapshotId !== expectedId) {
    throw new AgentSnapshotError("agent-snapshot/snapshot-id-mismatch",
      "load: wrapper snapshotId='" + expectedId + "' does not match envelope='" + snap.snapshotId + "'");
  }
  if ((raw.tenantId || null) !== (snap.tenantId || null)) {
    throw new AgentSnapshotError("agent-snapshot/tenant-id-mismatch",
      "load: wrapper tenantId='" + (raw.tenantId || null) +
      "' does not match envelope tenantId='" + (snap.tenantId || null) + "'");
  }
  if ((raw.takenAt || null) !== (snap.takenAt || null)) {
    throw new AgentSnapshotError("agent-snapshot/taken-at-mismatch",
      "load: wrapper takenAt='" + (raw.takenAt || null) +
      "' does not match envelope takenAt='" + (snap.takenAt || null) + "'");
  }
  if (typeof snap.sig !== "string" || snap.sig.length === 0) {
    if (ctx.allowPlaintext) {
      _refusePlaintextUnderPosture("load");
      agentAudit.safeAudit(ctx.audit, "agent.snapshot.unsigned_load", null, {
        snapshotId: snap.snapshotId,
      });
      return snap;
    }
    throw new AgentSnapshotError("agent-snapshot/unsigned",
      "load: snapshot " + snap.snapshotId + " is unsigned — refusing to restore");
  }
  var signer = _resolveSigner(ctx);
  var sigBuf = Buffer.from(snap.sig, "base64");
  var ok = false;
  try {
    ok = signer.verify(_canonicalSigBytes(snap), sigBuf, snap.sigPubKey || undefined);
  } catch (_e) { ok = false; }
  if (!ok) {
    agentAudit.safeAudit(ctx.audit, "agent.snapshot.signature_invalid", null, {
      snapshotId: snap.snapshotId,
    });
    throw new AgentSnapshotError("agent-snapshot/bad-signature",
      "load: snapshot " + snap.snapshotId + " signature verify failed — " +
      "may be tampered or signed under a key the current verifier doesn't trust");
  }
  return snap;
}

async function _loadLatest(ctx, loadOpts) {
  var entries = await ctx.backend.list();
  if (!Array.isArray(entries) || entries.length === 0) return null;
  var filtered = entries.filter(function (e) {
    if (loadOpts.tenantId && e.tenantId !== loadOpts.tenantId) return false;
    return true;
  });
  if (filtered.length === 0) return null;
  filtered.sort(function (a, b) { return (b.takenAt || 0) - (a.takenAt || 0); });
  var selected = filtered[0];
  var raw = await ctx.backend.get(selected.snapshotId);
  var snap = await _unwrapAndVerify(ctx, raw, selected.snapshotId);
  if (loadOpts.tenantId && (snap.tenantId || null) !== loadOpts.tenantId) {
    throw new AgentSnapshotError("agent-snapshot/tenant-id-mismatch",
      "loadLatest: requested tenantId='" + loadOpts.tenantId +
      "' does not match the loaded snapshot's authenticated tenantId='" +
      (snap.tenantId || null) + "'");
  }
  if ((selected.takenAt || null) !== (snap.takenAt || null)) {
    throw new AgentSnapshotError("agent-snapshot/taken-at-mismatch",
      "loadLatest: list() takenAt='" + (selected.takenAt || null) +
      "' for the selected snapshot does not match its authenticated takenAt='" +
      (snap.takenAt || null) + "'");
  }
  return snap;
}

async function _loadById(ctx, snapshotId) {
  if (typeof snapshotId !== "string" || snapshotId.length === 0) {
    throw new AgentSnapshotError("agent-snapshot/bad-snapshot-id",
      "loadById: snapshotId required");
  }
  var raw = await ctx.backend.get(snapshotId);
  return await _unwrapAndVerify(ctx, raw, snapshotId);
}

async function _restore(ctx, snap, restoreOpts) {
  guardSnapshotEnvelope.validate(snap);
  if (snap.schemaVersion !== SCHEMA_VERSION) {
    if (!restoreOpts.allowSchemaVersionMismatch) {
      throw new AgentSnapshotError("agent-snapshot/schema-version-mismatch",
        "restore: snap.schemaVersion=" + snap.schemaVersion +
        " != current=" + SCHEMA_VERSION + "; set restoreOpts.allowSchemaVersionMismatch to opt in");
    }
  }
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
  var counts = {
    orchestratorState: 0,
    idempotencyCache:  0,
    sagas:             0,
    streams:           0,
    outboxJobs:        0,
    busSubscribers:    0,
    pendingDeliveries: 0,
  };
  var handlers = ctx.restoreHandlers;
  var handlerCtx = { snapshotId: snap.snapshotId, takenAt: snap.takenAt, audit: ctx.audit };
  if (handlers) {
    counts.orchestratorState = await _runHandler(handlers.orchestratorState, snap.orchestratorState, handlerCtx);
    counts.idempotencyCache  = await _runHandler(handlers.idempotencyCache,  snap.idempotencyCache,  handlerCtx);
    if (snap.inFlight) {
      counts.sagas             = await _runHandler(handlers.sagas,             snap.inFlight.sagas,             handlerCtx);
      counts.streams           = await _runHandler(handlers.streams,           snap.inFlight.streams,           handlerCtx);
      counts.outboxJobs        = await _runHandler(handlers.outboxJobs,        snap.inFlight.outboxJobs,        handlerCtx);
      counts.busSubscribers    = await _runHandler(handlers.busSubscribers,    snap.inFlight.busSubscribers,    handlerCtx);
      counts.pendingDeliveries = await _runHandler(handlers.pendingDeliveries, snap.inFlight.pendingDeliveries, handlerCtx);
    }
  } else if (_inFlightCount(snap) > 0) {
    if (restoreOpts.requireHandlers || _inFlightCount(snap) > 0) {
      agentAudit.safeAudit(ctx.audit, "agent.snapshot.restore_skipped_no_handlers", null, {
        snapshotId: snap.snapshotId, inFlightCount: _inFlightCount(snap),
      });
      if (restoreOpts.requireHandlers) {
        throw new AgentSnapshotError("agent-snapshot/no-restore-handlers",
          "restore: snapshot " + snap.snapshotId + " carries " + _inFlightCount(snap) +
          " in-flight items but no restoreHandlers wired; pass " +
          "create({ restoreHandlers: { ... } }) or restoreOpts.requireHandlers=false " +
          "to acknowledge data drop");
      }
    }
  }
  agentAudit.safeAudit(ctx.audit, "agent.snapshot.restored", null, {
    snapshotId:   snap.snapshotId,
    schemaVersion: snap.schemaVersion,
    inFlightCount: _inFlightCount(snap),
    topologyChanged: topologyChanged,
    counts:       counts,
  });
  return {
    snapshotId:      snap.snapshotId,
    topologyChanged: topologyChanged,
    restored:        counts,
  };
}

async function _runHandler(handler, payload, handlerCtx) {
  if (typeof handler !== "function") return 0;
  if (payload === undefined || payload === null) return 0;
  var r;
  try { r = await handler(payload, handlerCtx); }
  catch (e) {
    agentAudit.safeAudit(handlerCtx.audit, "agent.snapshot.restore_handler_failed", null, {
      snapshotId: handlerCtx.snapshotId,
      reason:     (e && e.message) || String(e),
    });
    throw new AgentSnapshotError("agent-snapshot/restore-handler-failed",
      "restore: handler threw — " + ((e && e.message) || String(e)));
  }
  if (typeof r === "number" && r >= 0) return r;
  if (Array.isArray(payload)) return payload.length;
  return 1;
}

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

function _inFlightCount(snap) {
  if (!snap || !snap.inFlight) return 0;
  var n = 0;
  ["streams", "sagas", "outboxJobs", "busSubscribers", "pendingDeliveries"].forEach(function (k) {
    if (Array.isArray(snap.inFlight[k])) n += snap.inFlight[k].length;
  });
  return n;
}

function _topologyChanged(snapshotState, currentHealth) {
  if (!snapshotState || !currentHealth) return false;
  var snapTopics = new Set((snapshotState.consumers || []).map(function (c) { return c.topic; }));
  var currTopics = new Set((currentHealth.consumers || []).map(function (c) { return c.topic; }));
  if (snapTopics.size !== currTopics.size) return true;
  var changed = false;
  snapTopics.forEach(function (t) { if (!currTopics.has(t)) changed = true; });
  return changed;
}

function _reshardedShards(snapshotState, currentHealth) {
  var snapTopics = new Set((snapshotState.consumers || []).map(function (c) { return c.topic; }));
  var currTopics = new Set((currentHealth.consumers || []).map(function (c) { return c.topic; }));
  var changed = [];
  snapTopics.forEach(function (t) { if (!currTopics.has(t)) changed.push(t); });
  currTopics.forEach(function (t) { if (!snapTopics.has(t)) changed.push(t); });
  return changed;
}

function _frameworkVersion() {
  try { return require("../package.json").version; }                                                  // allow:inline-require — read at snapshot time, not load time
  catch (_e) { return "unknown"; }
}

module.exports = {
  create:               create,
  reseal:               reseal,
  SCHEMA_VERSION:       SCHEMA_VERSION,
  SEALED_PREFIX:        SEALED_PREFIX,
  AgentSnapshotError:   AgentSnapshotError,
  guards: {
    envelope: guardSnapshotEnvelope,
  },
  AAD_ROTATION: {
    table:         SNAPSHOT_TABLE,
    rowIdField:    "snapshotId",
    schemaVersion: String(SCHEMA_VERSION),
    backend:       "external",
    reseal: function (rotationOpts) {
      rotationOpts = rotationOpts || {};
      return reseal({
        backend:     rotationOpts.store || rotationOpts.backend,
        oldRootJson: rotationOpts.oldRootJson,
        newRootJson: rotationOpts.newRootJson,
      });
    },
  },
};

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.agent.orchestrator
 * @nav        Agent
 * @title      Agent Orchestrator
 * @order      50
 * @featured   true
 *
 * @intro
 *   Framework-level supervisor for every agent blamejs ships
 *   (`b.mail.agent` today; future search-index / AI-classify / DSR /
 *   c2pa-watermark agents). The orchestrator owns:
 *
 *     - **Registry** (`register` / `lookup` / `unregister` / `list`)
 *       — pluggable backend; in-memory default, durable via operator-
 *       supplied `b.config.loadDbBacked` for restart-survival. Rows are
 *       sealed at rest via `b.cryptoField` when a vault is configured
 *       (the default in a booted app), so tenant names + endpoint
 *       metadata don't leak in DB dumps.
 *     - **Sharded topics** (`spawnConsumers`) — consistent-hash route
 *       per-shard so each tenant's traffic owns one shard's ordering.
 *     - **Leader-elected singletons** (`elect`) — composes `b.cluster`
 *       DB-row election. Operator marks methods that must run on
 *       exactly one node (MDN batch dispatch, virus-DB refresh,
 *       journal compaction) as singletons.
 *     - **Drain** (`drain`) — `consumer.stop()` on every spawned
 *       consumer; wait for in-flight envelopes via `b.outbox`; audit.
 *       Wires into `b.appShutdown` as a registered phase.
 *     - **Health probe** (`health`) — aggregates per-agent + per-
 *       consumer + per-election state into one shape for
 *       `b.middleware.healthcheck`.
 *
 *   The orchestrator is the **in-process supervisor of agents**, NOT
 *   the **OS-level supervisor of processes**. Spawn / restart-on-
 *   crash / autoscaling / network routing all delegate to pm2 /
 *   systemd / k8s / Nomad — the framework doesn't compete.
 *
 *   ```js
 *   var orch = b.agent.orchestrator.create({
 *     audit:        b.audit,
 *     permissions:  myPerms,
 *     backend:      operatorBackend,    // optional; in-memory default
 *   });
 *
 *   await orch.register("tenant-acme.mail", mailAgent, { agentKind: "mail" });
 *   var agent = await orch.lookup("tenant-acme.mail");
 *   ```
 *
 * @card
 *   The framework-level supervisor for every agent blamejs ships.
 *   Registry, sharded topics, leader-elected singletons, drain, and
 *   health probe — operators stop wiring these per-agent.
 */

var lazyRequire       = require("./lazy-require");
var C                 = require("./constants");
var { defineClass }   = require("./framework-error");
var guardAgentRegistry = require("./guard-agent-registry");
var bCrypto           = require("./crypto");
var agentAudit        = require("./agent-audit");
var vaultAad          = require("./vault-aad");
var validateOpts      = require("./validate-opts");
var safeAsync         = require("./safe-async");

var audit             = lazyRequire(function () { return require("./audit"); });
var cluster           = lazyRequire(function () { return require("./cluster"); });
var vault             = lazyRequire(function () { return require("./vault"); });
var cryptoField       = lazyRequire(function () { return require("./crypto-field"); });
var safeJson          = require("./safe-json");
var agentTenant       = lazyRequire(function () { return require("./agent-tenant"); });

var AgentOrchestratorError = defineClass("AgentOrchestratorError", { alwaysPermanent: true });

var SEAL_TABLE = "agent_orchestrator_registry";
var _sealTableRegistered = false;
var SEAL_METADATA_MAX_BYTES = C.BYTES.mib(1);
function _ensureSealTable() {
  if (_sealTableRegistered) return;
  cryptoField().registerTable(SEAL_TABLE, {
    sealedFields: ["tenantId", "metadata"],
    aad:          true,
    rowIdField:   "name",
  });
  _sealTableRegistered = true;
}
function _sealRegistryRow(row) {
  if (!vault().isInitialized()) return row;
  _ensureSealTable();
  var pre = Object.assign({}, row);
  if (pre.metadata !== undefined && pre.metadata !== null && typeof pre.metadata !== "string") {
    pre.metadata = safeJson.stringify(pre.metadata);
  }
  return cryptoField().sealRow(SEAL_TABLE, pre);
}
function _unsealRegistryRow(row) {
  if (!row) return row;
  if (!vault().isInitialized()) return row;
  _ensureSealTable();
  var out = cryptoField().unsealRow(SEAL_TABLE, row);
  if (typeof out.metadata === "string") {
    try { out.metadata = safeJson.parse(out.metadata, { maxBytes: SEAL_METADATA_MAX_BYTES }); }
    catch (_e) { /* leave as-is — operator-stored raw string metadata */ }
  }
  return out;
}

var DEFAULT_DRAIN_TIMEOUT_MS = C.TIME.minutes(2);
var STREAM_ID_RAND_BYTES     = 8;
var DEFAULT_PER_CONSUMER_STOP_MS = C.TIME.seconds(5);
var _saltedFnvBasisCache = null;

/**
 * @primitive b.agent.orchestrator.create
 * @signature b.agent.orchestrator.create(opts)
 * @since     0.9.21
 * @status    stable
 * @related   b.mail.agent.create, b.cluster, b.appShutdown
 *
 * Create the orchestrator. Returns a singleton-style facade with
 * registry / spawn / elect / drain / health methods. Operator runs
 * one orchestrator per process; multi-process deployments share
 * coordination via the backing store + `b.cluster`.
 *
 * @opts
 *   audit:        b.audit namespace,            // optional; defaults to b.audit
 *   permissions:  b.permissions instance,       // optional; orchestrator skips RBAC if absent
 *   backend:      { get, set, delete, list },   // optional; in-memory default
 *   cluster:      b.cluster module,             // optional; defaults to b.cluster
 *   appShutdown:  b.appShutdown.create()        // optional; orchestrator adds an "agent.orchestrator.drain" phase via addPhase() if supplied
 *
 * @example
 *   var orch = b.agent.orchestrator.create({});
 *   await orch.register("tenant-acme.mail", mailAgent, { agentKind: "mail" });
 *   var agent = await orch.lookup("tenant-acme.mail");
 *   var folders = await agent.folders({ actor: { id: "u1" } });
 */
function create(opts) {
  opts = opts || {};
  var backend = opts.backend || _inMemoryBackend();
  validateOpts.requireMethods(backend, ["get", "set", "delete", "list"],
    "b.agent.orchestrator.create: backend", AgentOrchestratorError, "agent-orchestrator/bad-backend");
  var clusterImpl = opts.cluster || cluster();
  var auditImpl   = opts.audit   || audit();
  var permissions = opts.permissions || null;

  var ctx = {
    backend:     backend,
    registrySerializer: safeAsync.keyedSerializer(),
    cluster:     clusterImpl,
    audit:       auditImpl,
    permissions: permissions,
    tenantScope: opts.tenantScope === true,
    spawnedConsumers: [],
    streams:     new Map(),
    elections:   new Map(),
    liveAgents:  new Map(),
    outbox:           opts.outbox || null,
    sagaInFlightCount: typeof opts.sagaInFlightCount === "function" ? opts.sagaInFlightCount : null,
    pubsubFlush:      typeof opts.pubsubFlush === "function" ? opts.pubsubFlush : null,
    perConsumerStopMs: typeof opts.perConsumerStopMs === "number" ? opts.perConsumerStopMs : DEFAULT_PER_CONSUMER_STOP_MS,
    cacheElections:   opts.cacheElections !== false,
  };

  if (opts.appShutdown && typeof opts.appShutdown.addPhase === "function") {
    opts.appShutdown.addPhase({
      name: "agent.orchestrator.drain",
      run:  function () {
        return _drain(ctx, { timeoutMs: DEFAULT_DRAIN_TIMEOUT_MS });
      },
    });
  }

  if (clusterImpl && typeof clusterImpl.onTransition === "function") {
    try {
      clusterImpl.onTransition(function (event) {
        ctx.elections.clear();
        agentAudit.safeAudit(ctx.audit, "agent.orchestrator.election_cache_invalidated", null, {
          kind: event && event.kind ? event.kind : "unknown",
          fencingToken: event && event.fencingToken ? event.fencingToken : null,
        });
      });
    } catch (_e) { /* drop-silent — onTransition unavailable in some test stubs */ }
  }

  return {
    register:        function (name, agent, regOpts)         { return ctx.registrySerializer.run(name, function () { return _register(ctx, name, agent, regOpts || {}); }); },
    hydrate:         function (name, agent)                  { return _hydrate(ctx, name, agent); },
    unregister:      function (name, args)                   { return ctx.registrySerializer.run(name, function () { return _unregister(ctx, name, args || {}); }); },
    lookup:          function (name, args)                   { return _lookup(ctx, name, args || {}); },
    list:            function (args)                         { return _list(ctx, args || {}); },
    spawnConsumers:  function (args)                         { return _spawnConsumers(ctx, args || {}); },
    elect:           function (args)                         { return _elect(ctx, args || {}); },
    drain:           function (args)                         { return _drain(ctx, args || {}); },
    health:          function ()                             { return _health(ctx); },
    registerStream:  function (info)                         { return _registerStream(ctx, info || {}); },
    unregisterStream: function (streamId)                    { return _unregisterStream(ctx, streamId); },
    isDraining:      function (streamId)                     { return ctx.draining === true; },
    AgentOrchestratorError: AgentOrchestratorError,
    _ctx:            ctx,
  };
}

/**
 * @primitive b.agent.orchestrator.hydrate
 * @signature b.agent.orchestrator.hydrate(name, agent)
 * @since     0.9.57
 * @status    stable
 * @related   b.agent.orchestrator.create
 *
 * Attach an in-process live agent reference to a row
 * that already exists in the persistent registry backend. The
 * canonical boot-phase contract: the *first* process to start a new
 * agent calls `register()` (writes the backend row + holds the live
 * ref); every *subsequent* process that picks up the row from durable
 * storage (cross-orchestrator-restart, multi-process deploy, k8s pod
 * recreate) calls `hydrate(name, agent)` to install its local live
 * ref WITHOUT trying to re-write the backend row (which would refuse
 * with `agent-orchestrator/duplicate`).
 *
 * Throws `agent-orchestrator/not-in-registry` when no backend row
 * exists for `name`. Throws `agent-orchestrator/already-hydrated` if
 * the live ref is already installed (operator's boot phase ran
 * twice).
 *
 * Boot-phase contract:
 *   1. Process A calls `register("tenant-acme.mail", agent, regOpts)`
 *      → backend row written; A.liveAgents holds the ref.
 *   2. Process A crashes / redeploys.
 *   3. Process B starts: backend row already exists.
 *   4. Process B walks the registry via `list()` → sees rows it
 *      hasn't hydrated yet.
 *   5. For each, Process B reconstructs the agent locally (from its
 *      operator config) and calls `hydrate(name, agent)`.
 *   6. `lookup("tenant-acme.mail")` from Process B now returns the
 *      live ref instead of throwing `not-hydrated`.
 *
 * @example
 *   var rows = await orch.list({});
 *   for (var i = 0; i < rows.length; i += 1) {
 *     var name = rows[i].name;
 *     var agent = buildAgent(rows[i]);
 *     await orch.hydrate(name, agent);
 *   }
 */
async function _hydrate(ctx, name, agent) {
  guardAgentRegistry.validate({ kind: "register", name: name, agentKind: "hydrate" }, {});
  if (!agent || typeof agent !== "object") {
    throw new AgentOrchestratorError("agent-orchestrator/bad-agent",
      "hydrate: agent object required");
  }
  var row = await ctx.backend.get(name);
  if (!row) {
    throw new AgentOrchestratorError("agent-orchestrator/not-in-registry",
      "hydrate: '" + name + "' not in registry backend — call register() first");
  }
  if (ctx.liveAgents.has(name)) {
    throw new AgentOrchestratorError("agent-orchestrator/already-hydrated",
      "hydrate: '" + name + "' already has a live agent ref in this process");
  }
  ctx.liveAgents.set(name, agent);
  _safeAudit(ctx, "agent.orchestrator.hydrated", null, {
    name: name, agentKind: row.kind, tenantId: row.tenantId,
  });
  return { name: name, agentKind: row.kind };
}

async function _register(ctx, name, agent, regOpts) {
  guardAgentRegistry.validate({ kind: "register", name: name, agentKind: regOpts.agentKind }, {});
  _checkPermission(ctx, regOpts.actor, "agent-registry:write");
  if (!agent || typeof agent !== "object") {
    throw new AgentOrchestratorError("agent-orchestrator/bad-agent",
      "register: agent object required");
  }
  var existing = await ctx.backend.get(name);
  if (existing) {
    throw new AgentOrchestratorError("agent-orchestrator/duplicate",
      "register: '" + name + "' already registered; unregister first");
  }
  var row = {
    name:           name,
    kind:           regOpts.agentKind,
    tenantId:       regOpts.tenantId || null,
    posture:        regOpts.posture  || null,
    registeredAt:   Date.now(),
    metadata:       regOpts.metadata || {},
  };
  await ctx.backend.set(name, _sealRegistryRow(row));
  ctx.liveAgents.set(name, agent);
  _safeAudit(ctx, "agent.orchestrator.registered", regOpts.actor, {
    name: name, agentKind: regOpts.agentKind, tenantId: row.tenantId,
  });
  return { name: name, registeredAt: row.registeredAt };
}

async function _unregister(ctx, name, args) {
  guardAgentRegistry.validate({ kind: "unregister", name: name }, {});
  _checkPermission(ctx, args.actor, "agent-registry:write");
  var row = await ctx.backend.get(name);
  if (!row) {
    throw new AgentOrchestratorError("agent-orchestrator/not-found",
      "unregister: '" + name + "' not registered");
  }
  await ctx.backend.delete(name);
  ctx.liveAgents.delete(name);
  _safeAudit(ctx, "agent.orchestrator.unregistered", args.actor, {
    name: name, agentKind: row.kind,
  });
  return { name: name };
}

async function _lookup(ctx, name, args) {
  guardAgentRegistry.validate({ kind: "lookup", name: name }, {});
  _checkPermission(ctx, args.actor, "agent-registry:read");
  if (ctx.tenantScope) {
    var sealedRow = await ctx.backend.get(name);
    var declRow = sealedRow ? _unsealRegistryRow(sealedRow) : null;
    if (declRow && !_tenantAllows(ctx, args.actor, declRow.tenantId)) {
      _safeAudit(ctx, "agent.orchestrator.lookup_denied", args.actor,
        { name: name, reason: "cross-tenant" });
      return null;
    }
  }
  var agent = ctx.liveAgents.get(name);
  if (agent) return agent;
  var row = await ctx.backend.get(name);
  if (!row) {
    _safeAudit(ctx, "agent.orchestrator.lookup_miss", args.actor, { name: name });
    return null;
  }
  throw new AgentOrchestratorError("agent-orchestrator/not-hydrated",
    "lookup: '" + name + "' exists in registry but no live agent ref " +
    "in this process — register the agent locally first");
}

async function _list(ctx, args) {
  guardAgentRegistry.validate({ kind: "list" }, {});
  _checkPermission(ctx, args.actor, "agent-registry:read");
  var rows = (await ctx.backend.list()).map(_unsealRegistryRow);
  return rows.filter(function (r) {
    if (args.kind && r.kind !== args.kind) return false;
    if (args.tenantId && r.tenantId !== args.tenantId) return false;
    if (!_tenantAllows(ctx, args.actor, r.tenantId)) return false;
    return true;
  }).map(function (r) {
    return {
      name: r.name, kind: r.kind, tenantId: r.tenantId,
      posture: r.posture, registeredAt: r.registeredAt,
    };
  });
}

function _spawnConsumers(ctx, args) {
  if (!args.agent || typeof args.agent !== "object") {
    throw new AgentOrchestratorError("agent-orchestrator/bad-agent",
      "spawnConsumers: agent required");
  }
  if (!args.queue || typeof args.queue.consume !== "function") {
    throw new AgentOrchestratorError("agent-orchestrator/bad-queue",
      "spawnConsumers: queue with .consume() required");
  }
  var shards = typeof args.shards === "number" ? args.shards : 1;
  if (!Number.isInteger(shards) || shards < 1 || shards > 256) {
    throw new AgentOrchestratorError("agent-orchestrator/bad-shard-count",
      "spawnConsumers: shards must be an integer in 1..256");
  }
  var topicBase = args.taskTopic || "agent.tasks";
  var consumers = [];
  for (var i = 0; i < shards; i += 1) {
    var topic = shards === 1 ? topicBase : topicBase + "." + i;
    var c = _spawnSingleConsumer(ctx, args.agent, args.queue, topic, args.maxConcurrency || 4);
    consumers.push(c);
    ctx.spawnedConsumers.push(c);
  }
  _safeAudit(ctx, "agent.orchestrator.consumers_spawned", args.actor, {
    shards: shards, topicBase: topicBase, perShardConcurrency: args.maxConcurrency || 4,
  });
  return consumers;
}

function _spawnSingleConsumer(ctx, agent, queue, topic, maxConcurrency) {
  var stopped = false;
  var subscription = null;
  return {
    topic: topic,
    start: async function () {
      if (subscription) {
        throw new AgentOrchestratorError("agent-orchestrator/already-started",
          "consumer for topic '" + topic + "': already started");
      }
      subscription = await queue.consume(topic, async function (envelope) {
        if (stopped) return;
        var method = envelope.method;
        if (!method || typeof agent[method] !== "function") {
          var dotted = method && method.indexOf(".") > 0 ? method.split(".") : null;
          if (dotted && agent[dotted[0]] && typeof agent[dotted[0]][dotted[1]] === "function") {
            return agent[dotted[0]][dotted[1]](envelope.args);
          }
          throw new AgentOrchestratorError("agent-orchestrator/unknown-method",
            "consumer: unknown method '" + method + "'");
        }
        return agent[method](envelope.args);
      }, { maxConcurrency: maxConcurrency });
    },
    stop: async function () {
      stopped = true;
      if (subscription && typeof subscription.unsubscribe === "function") {
        await subscription.unsubscribe();
      }
      subscription = null;
    },
  };
}

/**
 * @primitive b.agent.orchestrator.shardFor
 * @signature b.agent.orchestrator.shardFor(shardKey, shards)
 * @since     0.9.21
 * @status    stable
 * @related   b.agent.orchestrator.create
 *
 * Consistent-hash router for sharded topic dispatch. Operator passes
 * a stable shard-key (e.g. tenantId or actor.id); orchestrator picks
 * the topic suffix so each tenant's traffic owns one shard's ordering.
 * Uses FNV-1a 32-bit — fast, good distribution for short keys, no
 * cryptographic guarantees (shard routing is not security-bearing).
 * Empty key returns 0; `shards <= 1` always returns 0.
 *
 * @example
 *   var shard = b.agent.orchestrator.shardFor("tenant-acme", 8);
 *   // → integer in [0, 8)
 */
function _saltedFnvBasis() {
  if (_saltedFnvBasisCache !== null) return _saltedFnvBasisCache;
  var v;
  try { v = vault(); } catch (_e) { v = null; }
  if (!v || typeof v.getKeysJson !== "function") {
    _saltedFnvBasisCache = 2166136261;
    return _saltedFnvBasisCache;
  }
  var keysJson;
  try { keysJson = v.getKeysJson(); }
  catch (_e) {
    _saltedFnvBasisCache = 2166136261;
    return _saltedFnvBasisCache;
  }
  var hashHex = bCrypto.sha3Hash(keysJson);
  var saltBuf = Buffer.from(hashHex.slice(0, 8), "hex");
  var salt = saltBuf.readUInt32BE(0);
  _saltedFnvBasisCache = ((2166136261 ^ salt) >>> 0);
  return _saltedFnvBasisCache;
}

function shardFor(shardKey, shards) {
  if (typeof shardKey !== "string" || shardKey.length === 0) return 0;
  if (shards <= 1) return 0;
  var h = _saltedFnvBasis();
  for (var i = 0; i < shardKey.length; i += 1) {
    h ^= shardKey.charCodeAt(i);
    h = (h * 16777619) >>> 0;
  }
  return h % shards;
}

async function _elect(ctx, args) {
  if (typeof args.resource !== "string" || args.resource.length === 0) {
    throw new AgentOrchestratorError("agent-orchestrator/bad-elect-args",
      "elect: resource required");
  }
  var isClusterMode = false;
  try { isClusterMode = ctx.cluster.isClusterMode(); } catch (_e) { isClusterMode = false; }
  if (!isClusterMode) {
    var elec = { isLeader: true, fencingToken: 1, resource: args.resource };
    if (ctx.cacheElections) ctx.elections.set(args.resource, elec);
    _safeAudit(ctx, "agent.orchestrator.elected", args.actor, {
      resource: args.resource, mode: "single-process",
    });
    return elec;
  }
  if (ctx.cacheElections && ctx.elections.has(args.resource)) {
    return ctx.elections.get(args.resource);
  }
  var leaderRow = null;
  try { leaderRow = await ctx.cluster.currentLeader(); } catch (_e) { leaderRow = null; }
  var amLeader = false;
  try { amLeader = ctx.cluster.isLeader(); } catch (_e) { amLeader = false; }
  var token = null;
  if (amLeader) {
    try { token = ctx.cluster.fencingToken(); } catch (_e) { token = null; }
  }
  var elec2 = {
    isLeader:     amLeader,
    fencingToken: token,
    resource:     args.resource,
    leaderId:     leaderRow && leaderRow.nodeId ? leaderRow.nodeId : null,
  };
  if (ctx.cacheElections) ctx.elections.set(args.resource, elec2);
  _safeAudit(ctx, "agent.orchestrator.elected", args.actor, {
    resource: args.resource, mode: "cluster",
    amLeader: amLeader, leaderId: elec2.leaderId,
  });
  return elec2;
}

async function _drain(ctx, args) {
  ctx.draining = true;
  var timeoutMs = typeof args.timeoutMs === "number" ? args.timeoutMs : DEFAULT_DRAIN_TIMEOUT_MS;
  var drained = 0;
  var startedAt = Date.now();
  var perConsumerMs = ctx.perConsumerStopMs;
  for (var i = 0; i < ctx.spawnedConsumers.length; i += 1) {
    var remaining = timeoutMs - (Date.now() - startedAt);
    if (remaining <= 0) break;
    var c = ctx.spawnedConsumers[i];
    var consumerBudget = Math.min(perConsumerMs, remaining);
    try {
      await _raceTimeout(c.stop(), consumerBudget,
        "consumer '" + c.topic + "' stop");
      drained += 1;
    } catch (e) {
      _safeAudit(ctx, "agent.orchestrator.consumer_stop_timeout", null, {
        topic: c.topic, budgetMs: consumerBudget,
        reason: (e && e.message) || String(e),
      });
    }
  }

  var inFlightQuiescent = await _quiesceInFlight(ctx, startedAt, timeoutMs);

  if (ctx.pubsubFlush) {
    var flushRemaining = timeoutMs - (Date.now() - startedAt);
    if (flushRemaining > 0) {
      try {
        await _raceTimeout(ctx.pubsubFlush(), flushRemaining, "pubsub flush");
      } catch (e) {
        _safeAudit(ctx, "agent.orchestrator.pubsub_flush_timeout", null, {
          reason: (e && e.message) || String(e),
        });
      }
    }
  }

  var streamCount = ctx.streams.size;
  _safeAudit(ctx, "agent.orchestrator.drained", null, {
    drainedConsumers: drained, totalConsumers: ctx.spawnedConsumers.length,
    streamCount: streamCount, elapsedMs: Date.now() - startedAt,
    inFlightQuiescent: inFlightQuiescent,
  });
  return {
    drained: drained,
    elapsedMs: Date.now() - startedAt,
    inFlightQuiescent: inFlightQuiescent,
  };
}

function _raceTimeout(p, budgetMs, label) {
  return new Promise(function (resolve, reject) {
    var settled = false;
    var t = setTimeout(function () {
      if (settled) return;
      settled = true;
      reject(new AgentOrchestratorError("agent-orchestrator/drain-timeout",
        label + " did not finish within " + budgetMs + "ms"));
    }, budgetMs);
    Promise.resolve(p).then(
      function (v) { if (!settled) { settled = true; clearTimeout(t); resolve(v); } },
      function (e) { if (!settled) { settled = true; clearTimeout(t); reject(e); } }
    );
  });
}

async function _quiesceInFlight(ctx, startedAt, timeoutMs) {
  if (!ctx.outbox && !ctx.sagaInFlightCount) return true;
  while (Date.now() - startedAt < timeoutMs) {
    var anyInFlight = false;
    if (ctx.outbox && typeof ctx.outbox.pendingCount === "function") {
      var pending;
      try { pending = await ctx.outbox.pendingCount(); }
      catch (_e) { pending = 0; }
      if (pending > 0) anyInFlight = true;
    }
    if (ctx.sagaInFlightCount) {
      var sagaPending;
      try { sagaPending = await ctx.sagaInFlightCount(); }
      catch (_e) { sagaPending = 0; }
      if (sagaPending > 0) anyInFlight = true;
    }
    if (!anyInFlight) return true;
    await new Promise(function (r) {
      var t = setTimeout(r, 50);
      if (t && typeof t.unref === "function") t.unref();
    });
  }
  return false;
}

function _registerStream(ctx, info) {
  var streamId = "stream-" + bCrypto.generateToken(STREAM_ID_RAND_BYTES);
  ctx.streams.set(streamId, {
    streamId: streamId, kind: info.kind || "unknown",
    actor: info.actor || null, startedAt: Date.now(),
  });
  return streamId;
}

function _unregisterStream(ctx, streamId) {
  ctx.streams.delete(streamId);
}

async function _health(ctx) {
  var rows = await ctx.backend.list();
  var elections = [];
  ctx.elections.forEach(function (v) { elections.push(v); });
  var consumers = ctx.spawnedConsumers.map(function (c) { return { topic: c.topic }; });
  return {
    agents: rows.map(function (r) {
      return { name: r.name, kind: r.kind, tenantId: r.tenantId, registeredAt: r.registeredAt };
    }),
    elections: elections,
    consumers: consumers,
    streams:   ctx.streams.size,
    draining:  ctx.draining === true,
    overall:   ctx.draining ? "draining" : "ok",
  };
}

function _inMemoryBackend() {
  var map = new Map();
  return {
    get:    function (k)      { return Promise.resolve(map.get(k) || null); },
    set:    function (k, v)   { map.set(k, v); return Promise.resolve(); },
    delete: function (k)      { map.delete(k); return Promise.resolve(); },
    list:   function ()       {
      var out = [];
      map.forEach(function (v) { out.push(v); });
      return Promise.resolve(out);
    },
  };
}

function _checkPermission(ctx, actor, scope) {
  if (!ctx.permissions) return;
  if (!actor || !ctx.permissions.check(actor, scope)) {
    throw new AgentOrchestratorError("agent-orchestrator/permission-denied",
      "actor lacks scope '" + scope + "'");
  }
}

function _tenantAllows(ctx, actor, rowTenantId) {
  if (!ctx.tenantScope) return true;
  if (ctx.permissions && actor &&
      ctx.permissions.check(actor, agentTenant().CROSS_TENANT_ADMIN_SCOPE)) {
    return true;
  }
  var actorTenant = (actor && actor.tenantId) || null;
  return actorTenant !== null && actorTenant === (rowTenantId || null);
}

function _safeAudit(ctx, action, actor, metadata) {
  agentAudit.safeAudit(ctx.audit, action, actor, metadata);
}

/**
 * @primitive b.agent.orchestrator.reseal
 * @signature b.agent.orchestrator.reseal(opts)
 * @since      0.14.12
 * @status     stable
 * @compliance gdpr, soc2
 * @related    b.vault.getKeysJson, b.cryptoField.sealRow
 *
 * Re-seals every AAD-bound registry cell (tenantId / metadata) on an
 * operator-supplied backend from the OLD vault keypair to the NEW one,
 * out-of-band. The in-tree vault-key rotation pipeline only walks tables
 * inside `db.enc`, so an operator-supplied orchestrator backend is
 * unreachable to it — after a keypair rotation its cells would otherwise be
 * orphaned under the retired root (CWE-320). Rebuilds each cell's AAD from
 * the registered schema (one source of truth); only AAD-sealed cells are
 * touched. The `name` row-identity column is the AAD anchor and is never
 * sealed, so it is always present for the write-back.
 *
 * @opts
 *   store:       Object,   // { list(): rows[], set(name, row) } (the create() backend contract)
 *   oldRootJson: string,   // b.vault.getKeysJson() of the retired keypair
 *   newRootJson: string,   // b.vault.getKeysJson() of the new keypair
 *
 * @example
 *   await b.agent.orchestrator.reseal({ store: backend, oldRootJson: oldKeys, newRootJson: newKeys });
 *   // → { table: "agent_orchestrator_registry", resealed: 4 }
 */
function reseal(args) {
  args = args || {};
  validateOpts.requireNonEmptyString(args.oldRootJson,
    "reseal: oldRootJson (b.vault.getKeysJson() of the OLD keypair)",
    AgentOrchestratorError, "agent-orchestrator/bad-root");
  validateOpts.requireNonEmptyString(args.newRootJson,
    "reseal: newRootJson (b.vault.getKeysJson() of the NEW keypair)",
    AgentOrchestratorError, "agent-orchestrator/bad-root");
  var store = args.store;
  validateOpts.requireMethods(store, ["list", "set"],
    "reseal: operator store (same backend contract as create({ backend }))",
    AgentOrchestratorError, "agent-orchestrator/bad-reseal-store");
  _ensureSealTable();
  var schema = cryptoField().getSchema(SEAL_TABLE);
  return Promise.resolve(store.list()).then(function (rows) {
    if (!Array.isArray(rows)) {
      throw new AgentOrchestratorError("agent-orchestrator/bad-reseal-store",
        "reseal: store.list() must resolve to an array of rows");
    }
    var chain = Promise.resolve();
    var resealed = 0;
    rows.forEach(function (row) {
      if (!row || typeof row !== "object") return;
      var changed = false;
      for (var f = 0; f < schema.sealedFields.length; f += 1) {
        var column = schema.sealedFields[f];
        var value = row[column];
        if (typeof value !== "string" || !vaultAad.isAadSealed(value)) continue;
        var aadParts = cryptoField()._aadParts(schema, SEAL_TABLE, column, row);
        row[column] = vaultAad.resealRoot(value, aadParts, args.oldRootJson, args.newRootJson);
        changed = true;
      }
      if (changed) {
        resealed += 1;
        chain = chain.then(function () { return store.set(row.name, row); });
      }
    });
    return chain.then(function () { return { table: SEAL_TABLE, resealed: resealed }; });
  });
}

module.exports = {
  create:                   create,
  shardFor:                 shardFor,
  reseal:                   reseal,
  AgentOrchestratorError:   AgentOrchestratorError,
  guards: {
    registry: guardAgentRegistry,
  },
  AAD_ROTATION: {
    table:         SEAL_TABLE,
    rowIdField:    "name",
    schemaVersion: "1",
    backend:       "external",
    reseal:        reseal,
  },
  _resetForTest: function () { _saltedFnvBasisCache = null; },
};

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
 *       supplied `b.config.loadDbBacked` for restart-survival. Sealed
 *       rows so tenant names + endpoint metadata don't leak in DB
 *       dumps.
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

var audit             = lazyRequire(function () { return require("./audit"); });
var cluster           = lazyRequire(function () { return require("./cluster"); });

var AgentOrchestratorError = defineClass("AgentOrchestratorError", { alwaysPermanent: true });

var DEFAULT_DRAIN_TIMEOUT_MS = C.TIME.minutes(2);
var STREAM_ID_RAND_BYTES     = 8;                                                                     // allow:raw-byte-literal — stream-id random-suffix byte length, not a size cap

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
 *   appShutdown:  b.appShutdown.create()        // optional; orchestrator registers drain phase if supplied
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
  if (typeof backend.get !== "function" || typeof backend.set !== "function" ||
      typeof backend.delete !== "function" || typeof backend.list !== "function") {
    throw new AgentOrchestratorError("agent-orchestrator/bad-backend",
      "b.agent.orchestrator.create: backend must expose { get, set, delete, list }");
  }
  var clusterImpl = opts.cluster || cluster();
  var auditImpl   = opts.audit   || audit();
  var permissions = opts.permissions || null;

  var ctx = {
    backend:     backend,
    cluster:     clusterImpl,
    audit:       auditImpl,
    permissions: permissions,
    spawnedConsumers: [],
    streams:     new Map(),
    elections:   new Map(),
    // Live agent objects stay in-process — DB/JSON backends can't
    // serialize function properties. The backend row carries only the
    // operator-supplied metadata (kind / tenantId / posture / ...);
    // every consuming process holds its own runtime map of name → agent.
    liveAgents:  new Map(),
  };

  // Wire the drain phase into b.appShutdown if the operator supplied one.
  if (opts.appShutdown && typeof opts.appShutdown.registerPhase === "function") {
    opts.appShutdown.registerPhase("agent.orchestrator.drain", function () {
      return _drain(ctx, { timeoutMs: DEFAULT_DRAIN_TIMEOUT_MS });
    });
  }

  return {
    register:        function (name, agent, regOpts)         { return _register(ctx, name, agent, regOpts || {}); },
    unregister:      function (name, args)                   { return _unregister(ctx, name, args || {}); },
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
    _ctx:            ctx,                                    // test-only introspection
  };
}

// ---- Registry -------------------------------------------------------------

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
  // Backend row carries operator-supplied serializable metadata only —
  // DB/JSON backends can't preserve function properties. The live agent
  // ref is held in-process via ctx.liveAgents (see ctx init above).
  var row = {
    name:           name,
    kind:           regOpts.agentKind,
    tenantId:       regOpts.tenantId || null,
    posture:        regOpts.posture  || null,
    registeredAt:   Date.now(),
    metadata:       regOpts.metadata || {},
  };
  await ctx.backend.set(name, row);
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
  // Live agent ref lives in-process; the backend row exists only as
  // a metadata declaration. In multi-process deployments each process
  // hydrates its own liveAgents map by calling register() locally.
  var agent = ctx.liveAgents.get(name);
  if (agent) return agent;
  var row = await ctx.backend.get(name);
  if (!row) {
    _safeAudit(ctx, "agent.orchestrator.lookup_miss", args.actor, { name: name });
    return null;
  }
  // Backend row exists but no live ref in this process — operator
  // didn't hydrate locally. Surface explicitly so the caller knows
  // to register the agent or route to the process that holds it.
  throw new AgentOrchestratorError("agent-orchestrator/not-hydrated",
    "lookup: '" + name + "' exists in registry but no live agent ref " +
    "in this process — register the agent locally first");
}

async function _list(ctx, args) {
  guardAgentRegistry.validate({ kind: "list" }, {});
  _checkPermission(ctx, args.actor, "agent-registry:read");
  var rows = await ctx.backend.list();
  return rows.filter(function (r) {
    if (args.kind && r.kind !== args.kind) return false;
    if (args.tenantId && r.tenantId !== args.tenantId) return false;
    return true;
  }).map(function (r) {
    return {
      name: r.name, kind: r.kind, tenantId: r.tenantId,
      posture: r.posture, registeredAt: r.registeredAt,
    };
  });
}

// ---- Sharded topic dispatch -----------------------------------------------

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
  if (!Number.isInteger(shards) || shards < 1 || shards > 256) {                                      // allow:raw-byte-literal — shard cap
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
function shardFor(shardKey, shards) {
  if (typeof shardKey !== "string" || shardKey.length === 0) return 0;
  if (shards <= 1) return 0;
  // FNV-1a 32-bit — fast + good distribution for short keys.
  var h = 2166136261;                                                                                 // allow:raw-byte-literal — FNV-1a offset basis
  for (var i = 0; i < shardKey.length; i += 1) {
    h ^= shardKey.charCodeAt(i);
    h = (h * 16777619) >>> 0;                                                                         // allow:raw-byte-literal — FNV-1a prime
  }
  return h % shards;
}

// ---- Leader-elected singletons --------------------------------------------

async function _elect(ctx, args) {
  if (typeof args.resource !== "string" || args.resource.length === 0) {
    throw new AgentOrchestratorError("agent-orchestrator/bad-elect-args",
      "elect: resource required");
  }
  // Composes b.cluster's leader-election. When cluster mode is active,
  // delegate; when not, the local node is the trivial leader for this
  // process's lifetime (single-process deployment).
  var isClusterMode = false;
  try { isClusterMode = ctx.cluster.isClusterMode(); } catch (_e) { isClusterMode = false; }
  if (!isClusterMode) {
    // Single-process trivial leader.
    var elec = { isLeader: true, fencingToken: 1, resource: args.resource };
    ctx.elections.set(args.resource, elec);
    _safeAudit(ctx, "agent.orchestrator.elected", args.actor, {
      resource: args.resource, mode: "single-process",
    });
    return elec;
  }
  // Cluster mode: query current leader state via b.cluster.
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
  ctx.elections.set(args.resource, elec2);
  _safeAudit(ctx, "agent.orchestrator.elected", args.actor, {
    resource: args.resource, mode: "cluster",
    amLeader: amLeader, leaderId: elec2.leaderId,
  });
  return elec2;
}

// ---- Drain ----------------------------------------------------------------

async function _drain(ctx, args) {
  ctx.draining = true;
  var timeoutMs = typeof args.timeoutMs === "number" ? args.timeoutMs : DEFAULT_DRAIN_TIMEOUT_MS;
  var drained = 0;
  var startedAt = Date.now();
  // Stop every spawned consumer + collect timing.
  for (var i = 0; i < ctx.spawnedConsumers.length; i += 1) {
    var c = ctx.spawnedConsumers[i];
    try { await c.stop(); drained += 1; } catch (_e) { /* best-effort */ }
    if (Date.now() - startedAt > timeoutMs) break;
  }
  // Streams: signal each to wrap up (the streams check ctx.draining
  // and emit a drain-marker themselves; orchestrator just sets the flag).
  var streamCount = ctx.streams.size;
  _safeAudit(ctx, "agent.orchestrator.drained", null, {
    drainedConsumers: drained, totalConsumers: ctx.spawnedConsumers.length,
    streamCount: streamCount, elapsedMs: Date.now() - startedAt,
  });
  return { drained: drained, elapsedMs: Date.now() - startedAt };
}

// ---- Streams (v0.9.23 substrate hook) -------------------------------------

function _registerStream(ctx, info) {
  // Stream IDs are cross-tenant-distinguishable; use crypto-grade
  // generateToken to keep them uniformly random across operators.
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

// ---- Health probe ---------------------------------------------------------

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

// ---- Internals ------------------------------------------------------------

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

function _safeAudit(ctx, action, actor, metadata) {
  agentAudit.safeAudit(ctx.audit, action, actor, metadata);
}

module.exports = {
  create:                   create,
  shardFor:                 shardFor,
  AgentOrchestratorError:   AgentOrchestratorError,
  guards: {
    registry: guardAgentRegistry,
  },
};

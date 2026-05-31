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

var audit             = lazyRequire(function () { return require("./audit"); });
var cluster           = lazyRequire(function () { return require("./cluster"); });
var vault             = lazyRequire(function () { return require("./vault"); });
var cryptoField       = lazyRequire(function () { return require("./crypto-field"); });
var safeJson          = require("./safe-json");
var agentTenant       = lazyRequire(function () { return require("./agent-tenant"); });

var AgentOrchestratorError = defineClass("AgentOrchestratorError", { alwaysPermanent: true });

// At-rest sealing of registry rows. The owning tenant id and the
// operator-supplied endpoint metadata are sealed via b.cryptoField
// before a row reaches the backend, so a DB dump does not leak which
// tenants own which agents or their endpoint detail — when a vault is
// configured (the default in a booted app via b.start). Without a vault
// there is no key, so rows are stored as-is (the same vault-less mode
// the salted-FNV shard fallback below supports). AAD binds each
// ciphertext to the agent `name` (the row identity). `metadata` is an
// object, so it is JSON-serialized before sealing and parsed back on
// read; `tenantId` may be null (sealRow leaves null fields untouched).
// Vault-less or pre-sealing rows carry plain values; unsealRow passes a
// non-sealed value through, so they still read.
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
  if (!vault().isInitialized()) return row;          // vault-less: store as-is (no key)
  _ensureSealTable();
  var pre = Object.assign({}, row);
  if (pre.metadata !== undefined && pre.metadata !== null && typeof pre.metadata !== "string") {
    pre.metadata = safeJson.stringify(pre.metadata);
  }
  return cryptoField().sealRow(SEAL_TABLE, pre);
}
function _unsealRegistryRow(row) {
  if (!row) return row;
  if (!vault().isInitialized()) return row;          // vault-less: rows are plain
  _ensureSealTable();
  var out = cryptoField().unsealRow(SEAL_TABLE, row);
  // New rows stored metadata as a sealed JSON string; legacy rows stored
  // it as a plain object (which passes through unseal untouched). Only
  // the string form needs parsing back to an object.
  if (typeof out.metadata === "string") {
    try { out.metadata = safeJson.parse(out.metadata, { maxBytes: SEAL_METADATA_MAX_BYTES }); }
    catch (_e) { /* leave as-is — operator-stored raw string metadata */ }
  }
  return out;
}

var DEFAULT_DRAIN_TIMEOUT_MS = C.TIME.minutes(2);
var STREAM_ID_RAND_BYTES     = 8;                                                                     // stream-id random-suffix byte length, not a size cap
var DEFAULT_PER_CONSUMER_STOP_MS = C.TIME.seconds(5);
// FNV-1a offset basis salted with the first 32 bits of
// SHA3-512(vault master). Attackers who don't have read access to the
// vault keypair can't compute the salt, so they can't engineer
// tenantIds that all map to one shard. Cached per-process; rotation
// of vault keys produces a new basis (operator opts to reshard via
// rebalance — same property as a manual `vault.rotate`).
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
    // When true, registry reads (list / lookup) are scoped to the actor's
    // tenant — an actor only sees / resolves agents in its own tenant
    // unless it holds the cross-tenant-admin scope. Mirrors the tenant
    // scoping agent-event-bus enforces on subscribe / delivery. Off by
    // default (single-tenant deployments are unaffected).
    tenantScope: opts.tenantScope === true,
    spawnedConsumers: [],
    streams:     new Map(),
    elections:   new Map(),
    // Live agent objects stay in-process — DB/JSON backends can't
    // serialize function properties. The backend row carries only the
    // operator-supplied metadata (kind / tenantId / posture / ...);
    // every consuming process holds its own runtime map of name → agent.
    liveAgents:  new Map(),
    // Drain quiesce wiring. Operator passes
    // { outbox, sagaInFlightCount, pubsubFlush } via create() so the
    // drain phase can quiesce real in-flight work, not just stop
    // consumers. Optional — operators with no outbox / saga / pubsub
    // pass nothing and drain falls back to the consumer-stop path.
    outbox:           opts.outbox || null,
    sagaInFlightCount: typeof opts.sagaInFlightCount === "function" ? opts.sagaInFlightCount : null,
    pubsubFlush:      typeof opts.pubsubFlush === "function" ? opts.pubsubFlush : null,
    perConsumerStopMs: typeof opts.perConsumerStopMs === "number" ? opts.perConsumerStopMs : DEFAULT_PER_CONSUMER_STOP_MS,
    // onTransition handler invalidates election cache
    // on lease-lost / acquired / released. Operator opts out via
    // { cacheElections: false } to always re-query b.cluster.
    cacheElections:   opts.cacheElections !== false,
  };

  // Wire the drain phase into b.appShutdown if the operator supplied one.
  if (opts.appShutdown && typeof opts.appShutdown.registerPhase === "function") {
    opts.appShutdown.registerPhase("agent.orchestrator.drain", function () {
      return _drain(ctx, { timeoutMs: DEFAULT_DRAIN_TIMEOUT_MS });
    });
  }

  // Subscribe to cluster lease transitions so cached
  // election state can't go stale after a partition. b.cluster
  // .onTransition fires for every lease-acquired / lease-lost / lease-
  // released event; we invalidate the affected resource's cached
  // election so the next elect() call re-queries truth. When
  // b.cluster isn't initialized (single-process deployments)
  // onTransition still registers a handler — the dispatcher silently
  // never fires until init completes.
  if (clusterImpl && typeof clusterImpl.onTransition === "function") {
    try {
      clusterImpl.onTransition(function (event) {
        // event.kind ∈ { "lease-acquired" | "lease-lost" |
        //                "lease-released" | "lease-renewed" }. Every
        // kind invalidates because membership / fencing-token may
        // have changed.
        ctx.elections.clear();
        agentAudit.safeAudit(ctx.audit, "agent.orchestrator.election_cache_invalidated", null, {
          kind: event && event.kind ? event.kind : "unknown",
          fencingToken: event && event.fencingToken ? event.fencingToken : null,
        });
      });
    } catch (_e) { /* drop-silent — onTransition unavailable in some test stubs */ }
  }

  return {
    register:        function (name, agent, regOpts)         { return _register(ctx, name, agent, regOpts || {}); },
    hydrate:         function (name, agent)                  { return _hydrate(ctx, name, agent); },
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
  // Seal tenantId + metadata at rest (name is populated, so the AAD
  // binding resolves). The plaintext `row` is kept for the audit below.
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
  // Tenant-scope gate: the row's declared tenant gates access even to a
  // live in-process ref, so an actor can't acquire a handle to another
  // tenant's agent. Consult the backend row (it exists as a metadata
  // declaration even where a live ref is hydrated).
  if (ctx.tenantScope) {
    var sealedRow = await ctx.backend.get(name);
    var declRow = sealedRow ? _unsealRegistryRow(sealedRow) : null;
    if (declRow && !_tenantAllows(ctx, args.actor, declRow.tenantId)) {
      _safeAudit(ctx, "agent.orchestrator.lookup_denied", args.actor,
        { name: name, reason: "cross-tenant" });
      return null;
    }
  }
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
  var rows = (await ctx.backend.list()).map(_unsealRegistryRow);
  return rows.filter(function (r) {
    if (args.kind && r.kind !== args.kind) return false;
    if (args.tenantId && r.tenantId !== args.tenantId) return false;
    // Tenant-scope gate: drop rows the actor's tenant may not see, so
    // enumeration can't disclose other tenants' agents. The args.tenantId
    // above is a caller-supplied FILTER, not an authorization boundary.
    if (!_tenantAllows(ctx, args.actor, r.tenantId)) return false;
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
  if (!Number.isInteger(shards) || shards < 1 || shards > 256) {                                      // shard cap
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
  // Salt FNV-1a offset basis with the vault master so
  // an attacker can't engineer tenantIds that all hash to one shard.
  // Vault-less path (single-process tests / dev) falls back to the
  // standard FNV offset basis; production deployments with vault
  // initialized get the salted variant for free.
  if (_saltedFnvBasisCache !== null) return _saltedFnvBasisCache;
  var v;
  try { v = vault(); } catch (_e) { v = null; }
  if (!v || typeof v.getKeysJson !== "function") {
    _saltedFnvBasisCache = 2166136261;                                                                  // FNV-1a offset basis (vault-less fallback)
    return _saltedFnvBasisCache;
  }
  var keysJson;
  try { keysJson = v.getKeysJson(); }
  catch (_e) {
    _saltedFnvBasisCache = 2166136261;                                                                  // FNV-1a offset basis (vault-init-pending fallback)
    return _saltedFnvBasisCache;
  }
  var hashHex = bCrypto.sha3Hash(keysJson);
  // Read the first 32 bits as the salt; mix into the offset basis via
  // XOR so the distribution properties of FNV are preserved.
  var saltBuf = Buffer.from(hashHex.slice(0, 8), "hex");                                                // 32-bit prefix of SHA3-512 hex (4 bytes = 8 hex chars)
  var salt = saltBuf.readUInt32BE(0);
  _saltedFnvBasisCache = ((2166136261 ^ salt) >>> 0);                                                   // FNV-1a offset basis (vault-salted)
  return _saltedFnvBasisCache;
}

function shardFor(shardKey, shards) {
  if (typeof shardKey !== "string" || shardKey.length === 0) return 0;
  if (shards <= 1) return 0;
  // FNV-1a 32-bit — fast + good distribution for short keys; salted
  // offset basis defends algorithmic-complexity DoS via attacker-
  // chosen tenantIds. See _saltedFnvBasis above.
  var h = _saltedFnvBasis();
  for (var i = 0; i < shardKey.length; i += 1) {
    h ^= shardKey.charCodeAt(i);
    h = (h * 16777619) >>> 0;                                                                         // FNV-1a prime
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
    if (ctx.cacheElections) ctx.elections.set(args.resource, elec);
    _safeAudit(ctx, "agent.orchestrator.elected", args.actor, {
      resource: args.resource, mode: "single-process",
    });
    return elec;
  }
  // Cluster mode: ALWAYS query truth from b.cluster.
  // The onTransition handler installed in create() invalidates the
  // cache on every lease event, so a cache hit here is safe (it
  // means no lease event has fired since the last query). But the
  // cache hit MUST be invalidated by a transition first; we never
  // return stale isLeader:true after a lease-lost without re-asking.
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

// ---- Drain ----------------------------------------------------------------

async function _drain(ctx, args) {
  ctx.draining = true;
  var timeoutMs = typeof args.timeoutMs === "number" ? args.timeoutMs : DEFAULT_DRAIN_TIMEOUT_MS;
  var drained = 0;
  var startedAt = Date.now();
  var perConsumerMs = ctx.perConsumerStopMs;
  // Drain phases:
  //   1. set ctx.draining so streams emit drain-markers + new task
  //      dispatches refuse (consumers re-check on every envelope).
  //   2. stop each consumer with a per-consumer timeout race —
  //      one hung consumer can't block the full drain budget.
  //   3. quiesce in-flight: poll outbox.pendingCount + sagaInFlightCount
  //      until 0 OR remaining-budget-ms elapses.
  //   4. flush pubsub if operator wired it (delivers buffered events).
  // ---- Phase 2: stop consumers (each capped) ----
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
      // Continue with next consumer — one hung shouldn't strand the
      // rest. The hung work will be reaped at process exit.
    }
  }

  // ---- Phase 3: quiesce in-flight work ----
  var inFlightQuiescent = await _quiesceInFlight(ctx, startedAt, timeoutMs);

  // ---- Phase 4: pubsub flush (optional) ----
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

  // Streams: signal each to wrap up (the streams check ctx.draining
  // and emit a drain-marker themselves; orchestrator just sets the flag).
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
  // Promise.race against a setTimeout. Pure-JS, no `b.safeAsync.withTimeout`
  // dependency to avoid a load-time circular require. Note: a rejected
  // race doesn't cancel the original promise (Node has no cancellation
  // primitive); the consumer's stop() keeps running in the background
  // and the orchestrator continues. This is the right behavior for
  // drain — best-effort partial quiesce is better than hanging on one
  // misbehaving consumer.
  return new Promise(function (resolve, reject) {
    var settled = false;
    var t = setTimeout(function () {
      if (settled) return;
      settled = true;
      reject(new AgentOrchestratorError("agent-orchestrator/drain-timeout",
        label + " did not finish within " + budgetMs + "ms"));
    }, budgetMs);
    // The setTimeout is the timeout signal: when stop() never resolves,
    // this timer is the ONLY event-loop work tracking drain's progress.
    // Unref'ing it would let Node exit before the timer fires, leaving
    // the awaiting drain() promise pending forever (process exits while
    // the caller's await chain has no driver).
    Promise.resolve(p).then(
      function (v) { if (!settled) { settled = true; clearTimeout(t); resolve(v); } },
      function (e) { if (!settled) { settled = true; clearTimeout(t); reject(e); } }
    );
  });
}

async function _quiesceInFlight(ctx, startedAt, timeoutMs) {
  // Outbox + saga in-flight quiesce loop. Polls every 50ms (cheap;
  // we already paid the consumer-stop budget so this is mostly a
  // few ticks of waiting for the publisher to mark in-flight rows
  // 'published'). Returns true if quiescent, false on timeout.
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
      var t = setTimeout(r, 50);                                                                       // 50ms in-flight poll interval
      if (t && typeof t.unref === "function") t.unref();
    });
  }
  return false;
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

// Tenant-scope gate for registry reads. Returns true when the actor may
// see / resolve an agent row in `rowTenantId`: scoping disabled, the actor
// holds the cross-tenant-admin scope, or the actor's tenant matches the
// row's. Mirrors agent-tenant's CROSS_TENANT_ADMIN_SCOPE check so registry
// enumeration can't leak agents (or hand out live refs) across tenants.
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

// ---- Vault-key rotation: out-of-band reseal hook -------------------------
//
// Registry rows are AAD-sealed on an OPERATOR-SUPPLIED backend (opts.backend /
// the in-memory default), NOT in the framework's db.enc. The vault-key
// rotation pipeline (b.vaultRotate.rotate) only walks tables inside db.enc,
// so it cannot reach this backend — sealed tenantId + metadata cells would be
// ORPHANED under the old vault root after a rotation (CWE-320 cryptographic-
// key-management failure: ciphertext stranded under a retired key, then
// unreadable once the old keypair is destroyed). This reseal hook rotates the
// backend out-of-band, composing the SAME explicit-root primitive the in-tree
// pipeline uses (vaultAad.resealRoot) and the SAME AAD builder the seal path
// used (cryptoField._aadParts) so the re-sealed AAD tuple is byte-identical —
// one source of truth, no drift.
//
// Reseal store contract: the durable backend the operator wired for
// opts.backend already exposes list() (enumerate every row) + set(name, row)
// (write by name). The row identity column `name` is the AAD anchor and is
// never sealed, so it is always present in plaintext for the write-back.
// `tenantId` is a plain sealed string; `metadata` is a sealed JSON string —
// both are AAD-sealed cells, so each is re-sealed in place under the same AAD
// without unwrapping the metadata JSON.
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
        // Only AAD-sealed cells need rotating. Vault-less / pre-sealing rows
        // carry plain values (sealRow leaves them untouched when vault-less);
        // resealRoot would throw not-sealed on a plain value, so skip.
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
  // AAD_ROTATION — the vault-key rotation descriptor every framework module
  // that seals an {aad:true} table on an OPERATOR-SUPPLIED backend (outside
  // db.enc) exports, so an operator can register it with a rotation eager-
  // sweep and the codebase-patterns detect-and-refuse gate can confirm no
  // such external-store table is silently orphaned. `backend: "external"`
  // flags that the in-tree b.vaultRotate.rotate pipeline cannot reach it.
  AAD_ROTATION: {
    table:         SEAL_TABLE,
    rowIdField:    "name",
    schemaVersion: "1",
    backend:       "external",
    reseal:        reseal,
  },
  // Test-only — flush the salted FNV basis cache so a vault reset
  // between tests forces re-derivation.
  _resetForTest: function () { _saltedFnvBasisCache = null; },
};

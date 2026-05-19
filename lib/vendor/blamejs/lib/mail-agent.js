"use strict";
/**
 * @module     b.mail.agent
 * @nav        Mail
 * @title      Mail Agent
 * @order      100
 * @featured   true
 *
 * @intro
 *   The standardization contract for every mail protocol blamejs ships.
 *   JMAP (v0.9.27), IMAP (v0.9.28), POP3 (v0.9.29), ManageSieve (v0.9.30),
 *   the inbound MX listener (v0.9.24), and the submission listener
 *   (v0.9.25) all translate their protocol calls into `agent.X(args)`.
 *   The agent owns RBAC, posture enforcement, audit emission,
 *   dispatch, and worker isolation; every protocol on top is a thin
 *   shell.
 *
 *   `agent.create()` returns the facade. Methods backed by v0.9.19's
 *   `b.mailStore` run immediately; methods that depend on later slices
 *   throw `mail-agent/not-implemented` with a `wiredAt` tag naming the
 *   version that lights them up (defer-with-condition — operator can
 *   match against the tag to scope their integration).
 *
 *   ```js
 *   var agent = b.mail.agent.create({
 *     store, audit, permissions,
 *     posture: "hipaa",
 *     identity: function (actorId) {
 *       return { email: actorId + "@hospital.example", name: actorId };
 *     },
 *     dispatch: { mode: "auto" },
 *   });
 *
 *   var folders = await agent.folders({ actor: { id: "u1", roles: ["clinician"], purposeOfUse: "TREATMENT" } });
 *   ```
 *
 *   ## Dispatch modes
 *
 *   - `local` (default when no queue) — every method runs in-process.
 *     Fast-path ops (fetch / folders / flag / quota) bypass worker
 *     dispatch; heavy ops (search / export / sieve-on-bulk) run on the
 *     supplied `workerPool` when configured.
 *   - `queue` — every method publishes to the queue topic; an
 *     `agent.consumer()` running in a dedicated process (or replicas
 *     across hosts) pulls and executes. The consumer carries its own
 *     `store` reference; the queue payload carries actor + posture
 *     metadata, which the consumer re-validates against its local
 *     posture before unseal (no posture downgrade across the boundary).
 *   - `auto` — fast-path ops local, heavy ops to queue if configured
 *     else workerPool else local.
 *
 *   ## Posture enforcement
 *
 *   When `posture` is set, every actor passed to every method must
 *   carry the posture-required fields (HIPAA → `purposeOfUse`,
 *   PCI-DSS → `pciScope`, GDPR → `lawfulBasis`). `b.guardMailQuery.
 *   validateActor` is the canonical check; the agent invokes it
 *   on every entrypoint.
 *
 * @card
 *   The standardization contract for every mail protocol — JMAP / IMAP /
 *   POP3 all translate into `agent.X(args)`. RBAC + posture + audit +
 *   dispatch owned here; protocols on top are thin shells.
 */

var lazyRequire        = require("./lazy-require");
var validateOpts       = require("./validate-opts");
var C                  = require("./constants");
var { defineClass }    = require("./framework-error");
var guardMailQuery     = require("./guard-mail-query");
var guardMailCompose   = require("./guard-mail-compose");
var guardMailReply     = require("./guard-mail-reply");
var guardMailMove      = require("./guard-mail-move");
var guardMailSieve     = require("./guard-mail-sieve");
var guardMessageId     = require("./guard-message-id");

var audit              = lazyRequire(function () { return require("./audit"); });

var MailAgentError = defineClass("MailAgentError", { alwaysPermanent: true });

var DEFAULT_QUEUE_TOPIC = "mail.agent.tasks";
var DEFAULT_TASK_TIMEOUT_MS = C.TIME.seconds(30);
var DEFAULT_QUEUE_DEPTH_CAP = 1024;                                                                   // allow:raw-byte-literal — queue depth, not bytes

// Methods that route to worker / queue dispatch under "auto" mode. The
// rest are fast-path single-row ops that stay local even under "auto".
var HEAVY_METHODS = Object.freeze({
  search: true, export: true,
});

// Scope vocabulary the agent enforces via the operator-supplied
// permissions instance. Operators map their existing role table onto
// these scopes; the agent never invents its own roles.
var SCOPE_FOR_METHOD = Object.freeze({
  search:           "mail:read",
  fetch:            "mail:read",
  thread:           "mail:read",
  folders:          "mail:read",
  quota:            "mail:read",
  compose:          "mail:write",
  send:             "mail:write",
  reply:            "mail:write",
  forward:          "mail:write",
  move:             "mail:move",
  flag:             "mail:move",
  delete:           "mail:move",
  "sieve.list":     "mail:sieve",
  "sieve.put":      "mail:sieve",
  "sieve.activate": "mail:sieve",
  "identity.set":   "mail:identity",
  "vacation.set":   "mail:identity",
  "mdn.send":       "mail:mdn",
  "mdn.parse":      "mail:mdn",
  "mdn.allowList":  "mail:mdn",
  export:           "mail:export",
  job:              "mail:read",
  import:           "mail:import",
});

// Methods deferred behind a `wiredAt` version. Operator gets a clear
// error pointing at the slice that lights them up — defer-with-
// condition per the v1-defensible-scope rule.
var WIRED_AT = Object.freeze({
  compose:          "v0.9.25",
  send:             "v0.9.25",
  reply:            "v0.9.25",
  forward:          "v0.9.25",
  "sieve.list":     "v0.9.26",
  "sieve.put":      "v0.9.26",
  "sieve.activate": "v0.9.26",
  "identity.set":   "v0.9.25",
  "vacation.set":   "v0.9.25",
  "mdn.send":       "v0.9.25",
  "mdn.parse":      "v0.9.25",
  "mdn.allowList":  "v0.9.25",
  export:           "v0.9.34a",
  job:              "v0.9.34a",
  import:           "v0.9.34",
});

/**
 * @primitive b.mail.agent.create
 * @signature b.mail.agent.create(opts)
 * @since     0.9.20
 * @status    stable
 * @related   b.mailStore, b.mail.agent.consumer
 *
 * Create the agent facade. Returns an object with read / write / sieve
 * / identity / mdn / export / import / consumer methods. Reads stay
 * synchronous-shaped via promises; writes audit on completion.
 *
 * @opts
 *   store:        b.mailStore instance,    // required
 *   audit:        b.audit namespace,        // optional; defaults to b.audit
 *   permissions:  b.permissions instance,   // optional; agent skips RBAC if absent (operator's choice)
 *   posture:      "hipaa"|"pci-dss"|"gdpr"|"soc2"|null,
 *   identity:     function(actorId) → { email, name }   // OR object map
 *   dispatch:     { mode, queue, workerPool, queueTopic, taskTimeoutMs, queueDepthCap, vaultKeyDelivery },
 *
 * @example
 *   var agent = b.mail.agent.create({ store: myStore });
 *   var folders = await agent.folders({ actor: { id: "u1" } });
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MailAgentError("mail-agent/bad-opts",
      "b.mail.agent.create: opts required");
  }
  validateOpts.requireObject(opts.store, "b.mail.agent.create: opts.store", MailAgentError, "mail-agent/bad-store");
  if (typeof opts.store.fetchByObjectId !== "function") {
    throw new MailAgentError("mail-agent/bad-store",
      "b.mail.agent.create: opts.store does not look like a b.mailStore instance");
  }
  var posture = opts.posture || null;
  if (posture && !Object.prototype.hasOwnProperty.call(guardMailQuery.COMPLIANCE_POSTURES, posture)) {
    throw new MailAgentError("mail-agent/bad-posture",
      "b.mail.agent.create: unknown posture '" + posture + "'");
  }
  var dispatch = _validateDispatch(opts.dispatch || {});
  var identityFn = _identityResolver(opts.identity);
  var auditEmit = _auditEmitter(opts.audit);
  var permissions = opts.permissions || null;

  var ctx = {
    store: opts.store,
    posture: posture,
    dispatch: dispatch,
    identity: identityFn,
    auditEmit: auditEmit,
    permissions: permissions,
  };

  return {
    // Read surface — backed by v0.9.19 store immediately. Routed
    // through _dispatchOrLocal so dispatch.mode is actually consulted.
    search:    function (args) { return _dispatchOrLocal(ctx, "search",  args, _search); },
    fetch:     function (args) { return _dispatchOrLocal(ctx, "fetch",   args, _fetch); },
    thread:    function (args) { return _dispatchOrLocal(ctx, "thread",  args, _thread); },
    folders:   function (args) { return _dispatchOrLocal(ctx, "folders", args, _folders); },
    quota:     function (args) { return _dispatchOrLocal(ctx, "quota",   args, _quota); },

    // Write surface — needs v0.9.25 submission listener.
    compose:   function (args) { return _notImplemented(ctx, "compose", args); },
    send:      function (args) { return _notImplemented(ctx, "send", args); },
    reply:     function (args) { return _notImplemented(ctx, "reply", args); },
    forward:   function (args) { return _notImplemented(ctx, "forward", args); },

    // Move / flag / delete — backed by store, routed via dispatch.
    move:      function (args) { return _dispatchOrLocal(ctx, "move",   args, _move); },
    flag:      function (args) { return _dispatchOrLocal(ctx, "flag",   args, _flag); },
    delete:    function (args) { return _dispatchOrLocal(ctx, "delete", args, _delete); },

    // Sieve — needs v0.9.26 interpreter.
    sieve:     {
      list:     function (args) { return _notImplemented(ctx, "sieve.list",     args); },
      put:      function (args) { return _sievePut(ctx, args); },
      activate: function (args) { return _notImplemented(ctx, "sieve.activate", args); },
    },

    // Identity / vacation — needs v0.9.25 submission identity store.
    identity:  {
      set:      function (args) { return _notImplemented(ctx, "identity.set", args); },
    },
    vacation:  {
      set:      function (args) { return _notImplemented(ctx, "vacation.set", args); },
    },

    // MDN — needs v0.9.25 submission listener.
    mdn:       {
      send:     function (args) { return _notImplemented(ctx, "mdn.send",      args); },
      parse:    function (args) { return _notImplemented(ctx, "mdn.parse",     args); },
      allowList: function (args) { return _notImplemented(ctx, "mdn.allowList", args); },
    },

    // DSR / regulated export — needs v0.9.34a E2EE for sealed-export
    // (sealed columns can't ship across an export boundary without
    // posture-aware re-encryption to operator-supplied recipient).
    export:    function (args) { return _notImplemented(ctx, "export", args); },
    job:       function (args) { return _notImplemented(ctx, "job",    args); },

    // Migration import — needs v0.9.34 scan + v0.9.19+ b.safeMboxFormat / b.safeMailDir.
    import:    function (args) { return _notImplemented(ctx, "import", args); },

    // For testing / introspection.
    _ctx:      ctx,
  };
}

/**
 * @primitive b.mail.agent.consumer
 * @signature b.mail.agent.consumer(opts)
 * @since     0.9.20
 * @status    stable
 * @related   b.mail.agent.create, b.queue
 *
 * Create a queue consumer that pulls `mail.agent.tasks` envelopes and
 * runs them against an operator-supplied agent. Each replica runs in
 * its own process / host for multi-host load-spreading; queue payload
 * carries actor + posture; consumer re-validates against its local
 * posture before unseal.
 *
 * @opts
 *   agent:       a b.mail.agent.create() instance,   // required
 *   queue:       b.queue / b.queueRedis,             // required
 *   taskTopic:   string,                              // default "mail.agent.tasks"
 *   maxConcurrency: number,                           // default 4
 *
 * @example
 *   var consumer = b.mail.agent.consumer({ agent: localAgent, queue: redisQueue });
 *   await consumer.start();
 */
function consumer(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MailAgentError("mail-agent/bad-opts",
      "b.mail.agent.consumer: opts required");
  }
  if (!opts.agent || typeof opts.agent.fetch !== "function") {
    throw new MailAgentError("mail-agent/bad-agent",
      "b.mail.agent.consumer: opts.agent must be a b.mail.agent.create() instance");
  }
  if (!opts.queue || typeof opts.queue.consume !== "function") {
    throw new MailAgentError("mail-agent/bad-queue",
      "b.mail.agent.consumer: opts.queue must look like b.queue (consume function required)");
  }
  var taskTopic = opts.taskTopic || DEFAULT_QUEUE_TOPIC;
  var maxConcurrency = typeof opts.maxConcurrency === "number" ? opts.maxConcurrency : 4;
  if (!isFinite(maxConcurrency) || maxConcurrency < 1) {
    throw new MailAgentError("mail-agent/bad-max-concurrency",
      "b.mail.agent.consumer: maxConcurrency must be a positive number");
  }
  var stopped = false;
  var subscription = null;

  return {
    start: async function () {
      if (subscription) {
        throw new MailAgentError("mail-agent/already-started",
          "b.mail.agent.consumer: already started");
      }
      subscription = await opts.queue.consume(taskTopic, async function (envelope) {
        if (stopped) return;
        var method = envelope.method;
        var args = envelope.args;
        if (!method || typeof opts.agent[method] !== "function") {
          var dotted = method && method.indexOf(".") > 0 ? method.split(".") : null;
          if (dotted && opts.agent[dotted[0]] && typeof opts.agent[dotted[0]][dotted[1]] === "function") {
            return opts.agent[dotted[0]][dotted[1]](args);
          }
          throw new MailAgentError("mail-agent/unknown-method",
            "consumer: unknown method '" + method + "'");
        }
        return opts.agent[method](args);
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

// ---- Dispatch routing -----------------------------------------------------

// Honor dispatch.mode on every facade call. v0.9.20 ships the contract
// shape; full result-bus delivery for queue mode wires at v0.9.21
// with `b.agent.orchestrator` (defer-with-condition per the v1-
// defensible-scope rule).
//
//   "local"  → run localFn (default fallback)
//   "queue"  → enqueue + return { enqueued: true, jobId }; operator
//              polls via the orchestrator's job-id facade once that
//              ships. Methods that need a sync response under queue
//              mode refuse with `mail-agent/queue-result-bus-deferred`
//              until v0.9.21 wires the result-bus.
//   "auto"   → HEAVY_METHODS routes to queue when configured; rest local
async function _dispatchOrLocal(ctx, method, args, localFn) {
  var mode = ctx.dispatch.mode;
  if (mode === "local") return localFn(ctx, args);
  if (mode === "auto") {
    if (HEAVY_METHODS[method] && ctx.dispatch.queue) return _enqueueMethod(ctx, method, args);
    return localFn(ctx, args);
  }
  // mode === "queue" — explicit queue dispatch.
  if (!ctx.dispatch.queue) {
    throw new MailAgentError("mail-agent/no-queue",
      "agent." + method + ": dispatch.mode='queue' requires opts.dispatch.queue");
  }
  // Sync-result methods refuse until orchestrator's result-bus lands.
  if (!HEAVY_METHODS[method]) {
    throw new MailAgentError("mail-agent/queue-result-bus-deferred",
      "agent." + method + ": queue mode for sync-result methods wires at v0.9.21 " +
      "(b.agent.orchestrator). Use mode='local' or mode='auto' until then.");
  }
  return _enqueueMethod(ctx, method, args);
}

async function _enqueueMethod(ctx, method, args) {
  var envelope = {
    method:  method,
    args:    args,
    posture: ctx.posture,
    enqueuedAt: Date.now(),
  };
  var r = await ctx.dispatch.queue.enqueue(ctx.dispatch.queueTopic, envelope, {});
  ctx.auditEmit("mail.agent.enqueued", args && args.actor, {
    method: method, topic: ctx.dispatch.queueTopic, jobId: r && r.jobId,
  });
  return { enqueued: true, jobId: r && r.jobId, topic: ctx.dispatch.queueTopic };
}

// ---- Method implementations -----------------------------------------------

async function _search(ctx, args) {
  _entry(ctx, "search", args);
  guardMailQuery.validate(args.filter || {}, { profile: _profileFor(ctx), posture: ctx.posture, project: args.project });
  var folder = args.folder || "INBOX";
  // For v0.9.20: queryByModseq + post-filter against the unsealed row.
  // Future v0.9.27 with full-text indexing will replace this with an
  // index-side filter. Current scope: sinceModseq + flag filter only,
  // with a simple `from_addr` equality match via cryptoField.lookupHash
  // (the same hash computed at append time).
  var sinceModseq = (args.filter && args.filter.modseq && args.filter.modseq.gt) || 0;
  var limit = args.limit || 100;
  var rows = ctx.store.queryByModseq(folder, { sinceModseq: sinceModseq, limit: limit });
  ctx.auditEmit("mail.agent.search.success", args.actor, { folder: folder, rowCount: rows.length });
  return { rows: rows, nextModseq: rows.length > 0 ? rows[rows.length - 1].modseq : sinceModseq };
}

async function _fetch(ctx, args) {
  _entry(ctx, "fetch", args);
  if (typeof args.folder !== "string" || typeof args.objectId !== "string") {
    throw new MailAgentError("mail-agent/bad-args",
      "agent.fetch: { folder, objectId } required");
  }
  var msg = ctx.store.fetchByObjectId(args.folder, args.objectId);
  if (!msg) {
    ctx.auditEmit("mail.agent.fetch.miss", args.actor, { folder: args.folder, objectId: args.objectId });
    return null;
  }
  ctx.auditEmit("mail.agent.fetch.success", args.actor, { folder: args.folder, objectId: args.objectId });
  return msg;
}

async function _thread(ctx, args) {
  _entry(ctx, "thread", args);
  if (typeof args.objectId !== "string") {
    throw new MailAgentError("mail-agent/bad-args",
      "agent.thread: { objectId } required");
  }
  var chain = ctx.store.threadFor(args.objectId);
  ctx.auditEmit("mail.agent.thread.success", args.actor, { objectId: args.objectId, hopCount: chain.length });
  return { thread: chain };
}

async function _folders(ctx, args) {
  _entry(ctx, "folders", args);
  var rows = ctx.store.listFolders();
  ctx.auditEmit("mail.agent.folders.success", args.actor, { count: rows.length });
  return { folders: rows };
}

async function _quota(ctx, args) {
  _entry(ctx, "quota", args);
  var folder = args.folder || "INBOX";
  var q = ctx.store.quota(folder);
  ctx.auditEmit("mail.agent.quota.success", args.actor, { folder: folder });
  return q;
}

async function _move(ctx, args) {
  _entry(ctx, "move", args);
  guardMailMove.validate({
    actor: args.actor, fromFolder: args.fromFolder,
    toFolder: args.toFolder, objectIds: args.objectIds,
  }, { profile: _profileFor(ctx), posture: ctx.posture });
  var r = ctx.store.moveMessages(args.fromFolder, args.toFolder, args.objectIds);
  ctx.auditEmit("mail.agent.move.success", args.actor, {
    fromFolder: args.fromFolder, toFolder: args.toFolder, count: r.changed,
  });
  return r;
}

async function _flag(ctx, args) {
  _entry(ctx, "flag", args);
  if (typeof args.folder !== "string" || !Array.isArray(args.objectIds)) {
    throw new MailAgentError("mail-agent/bad-args",
      "agent.flag: { folder, objectIds, set?, unset? } required");
  }
  var r = ctx.store.setFlags(args.folder, args.objectIds, { set: args.set || [], unset: args.unset || [] });
  ctx.auditEmit("mail.agent.flag.success", args.actor, {
    folder: args.folder, count: args.objectIds.length, set: args.set, unset: args.unset,
  });
  return r;
}

async function _delete(ctx, args) {
  // Soft-delete: move to Trash + tag with \Deleted. Hard expunge is
  // explicitly out of scope at v0.9.20; v0.9.28 IMAP EXPUNGE wires the
  // hard-delete path with retention floor enforcement (b.retention.
  // complianceFloor refuses purge of mail still inside the regulated
  // retention window).
  _entry(ctx, "delete", args);
  if (typeof args.folder !== "string" || !Array.isArray(args.objectIds)) {
    throw new MailAgentError("mail-agent/bad-args",
      "agent.delete: { folder, objectIds } required");
  }
  if (args.folder === "Trash") {
    // Already in Trash; just mark deleted. Hard expunge at v0.9.28.
    var r0 = ctx.store.setFlags("Trash", args.objectIds, { set: ["\\Deleted"] });
    ctx.auditEmit("mail.agent.delete.flagged", args.actor, { folder: "Trash", count: args.objectIds.length });
    return r0;
  }
  guardMailMove.validate({
    actor: args.actor, fromFolder: args.folder, toFolder: "Trash", objectIds: args.objectIds,
  }, { profile: _profileFor(ctx), posture: ctx.posture });
  ctx.store.setFlags(args.folder, args.objectIds, { set: ["\\Deleted"] });
  var r = ctx.store.moveMessages(args.folder, "Trash", args.objectIds);
  ctx.auditEmit("mail.agent.delete.success", args.actor, {
    folder: args.folder, count: args.objectIds.length,
  });
  return r;
}

async function _sievePut(ctx, args) {
  // Two-stage validation: agent-level shape guard for RBAC + name +
  // size, then the full RFC 5228 grammar parse via b.safeSieve. The
  // grammar parse refuses unknown / not-yet-implemented capabilities
  // at `require` time (RFC 5228 §3.2) so the operator's persistence
  // step never gets a script the framework can't actually execute.
  _entry(ctx, "sieve.put", args);
  guardMailSieve.validate({
    kind: "put", actor: args.actor, name: args.name, script: args.script,
  }, { profile: _profileFor(ctx), posture: ctx.posture, ownedNames: args.ownedNames });
  var safeSieve = require("./safe-sieve");                                                            // allow:inline-require — lazy-load until first sieve.put call
  var rv = safeSieve.validate(args.script, {
    profile:           _profileFor(ctx),
    compliancePosture: ctx.posture,
  });
  if (!rv.ok) {
    throw new MailAgentError("mail-agent/sieve-parse-error",
      "agent.sieve.put: Sieve script refused — " +
      (rv.issues[0] && rv.issues[0].snippet ? rv.issues[0].snippet : "parse failed"));
  }
  ctx.auditEmit("mail.agent.sieve.put", args && args.actor, {
    name:         args.name,
    requiredCaps: rv.requiredCaps,
  });
  return { ok: true, requiredCaps: rv.requiredCaps };
}

function _notImplemented(ctx, method, args) {
  // Even for not-implemented methods, validate actor + permission at
  // the entry — operators integrating against the not-yet-wired
  // surface still get the same auth error semantics they'll see when
  // the slice lights up.
  if (ctx.posture) guardMailQuery.validateActor(args && args.actor, ctx.posture);
  _checkPermission(ctx, method, args);
  ctx.auditEmit("mail.agent.not_implemented", args && args.actor, { method: method, wiredAt: WIRED_AT[method] });
  return Promise.reject(new MailAgentError("mail-agent/not-implemented",
    "agent." + method + ": wired at " + WIRED_AT[method] + " (defer-with-condition)"));
}

// ---- Internals ------------------------------------------------------------

function _entry(ctx, method, args) {
  if (!args || typeof args !== "object") {
    throw new MailAgentError("mail-agent/bad-args",
      "agent." + method + ": args object required");
  }
  guardMailQuery.validateActor(args.actor, ctx.posture);
  _checkPermission(ctx, method, args);
}

function _checkPermission(ctx, method, args) {
  if (!ctx.permissions) return;
  var scope = SCOPE_FOR_METHOD[method];
  if (!scope) return;
  if (!args || !args.actor) {
    throw new MailAgentError("mail-agent/no-actor",
      "agent." + method + ": actor required");
  }
  if (!ctx.permissions.check(args.actor, scope)) {
    ctx.auditEmit("mail.agent.permission_denied", args.actor, { method: method, scope: scope });
    throw new MailAgentError("mail-agent/permission-denied",
      "agent." + method + ": actor lacks scope '" + scope + "'");
  }
}

function _profileFor(ctx) {
  // Posture pins strict; otherwise default to strict (the framework's
  // security-defaults-on rule applies here too — operators opt down
  // explicitly when needed).
  return ctx.posture ? "strict" : "strict";
}

function _validateDispatch(d) {
  var mode = d.mode || "auto";
  if (mode !== "local" && mode !== "queue" && mode !== "auto") {
    throw new MailAgentError("mail-agent/bad-dispatch-mode",
      "b.mail.agent.create: dispatch.mode must be 'local' | 'queue' | 'auto'");
  }
  if (mode === "queue" && (!d.queue || typeof d.queue.enqueue !== "function")) {
    throw new MailAgentError("mail-agent/no-queue",
      "b.mail.agent.create: dispatch.mode='queue' requires opts.dispatch.queue with .enqueue()");
  }
  if (d.workerPool && typeof d.workerPool.run !== "function") {
    throw new MailAgentError("mail-agent/bad-worker-pool",
      "b.mail.agent.create: dispatch.workerPool must expose .run()");
  }
  var topic = d.queueTopic || DEFAULT_QUEUE_TOPIC;
  var taskTimeoutMs = typeof d.taskTimeoutMs === "number" ? d.taskTimeoutMs : DEFAULT_TASK_TIMEOUT_MS;
  if (!isFinite(taskTimeoutMs) || taskTimeoutMs <= 0) {
    throw new MailAgentError("mail-agent/bad-task-timeout",
      "b.mail.agent.create: dispatch.taskTimeoutMs must be a positive finite number");
  }
  var queueDepthCap = typeof d.queueDepthCap === "number" ? d.queueDepthCap : DEFAULT_QUEUE_DEPTH_CAP;
  if (!isFinite(queueDepthCap) || queueDepthCap < 0) {
    throw new MailAgentError("mail-agent/bad-queue-depth-cap",
      "b.mail.agent.create: dispatch.queueDepthCap must be a non-negative finite number");
  }
  var vaultKeyDelivery = d.vaultKeyDelivery || "in-worker";
  if (vaultKeyDelivery !== "in-worker" && vaultKeyDelivery !== "main-only") {
    throw new MailAgentError("mail-agent/bad-vault-key-delivery",
      "b.mail.agent.create: dispatch.vaultKeyDelivery must be 'in-worker' | 'main-only'");
  }
  return {
    mode: mode,
    queue: d.queue || null,
    workerPool: d.workerPool || null,
    queueTopic: topic,
    taskTimeoutMs: taskTimeoutMs,
    queueDepthCap: queueDepthCap,
    vaultKeyDelivery: vaultKeyDelivery,
  };
}

function _identityResolver(spec) {
  if (typeof spec === "function") return spec;
  if (spec && typeof spec === "object") {
    return function (actorId) { return spec[actorId] || null; };
  }
  return function () { return null; };
}

function _auditEmitter(auditOverride) {
  if (auditOverride && typeof auditOverride.safeEmit === "function") {
    return function (event, actor, metadata) {
      auditOverride.safeEmit({
        action: event,
        actor: _actorShape(actor),
        outcome: event.indexOf("denied") >= 0 || event.indexOf("not_implemented") >= 0 ? "failure" : "success",
        metadata: metadata || {},
      });
    };
  }
  return function (event, actor, metadata) {
    audit().safeEmit({
      action: event,
      actor: _actorShape(actor),
      outcome: event.indexOf("denied") >= 0 || event.indexOf("not_implemented") >= 0 ? "failure" : "success",
      metadata: metadata || {},
    });
  };
}

function _actorShape(actor) {
  if (!actor || typeof actor !== "object") return { id: "<unknown>" };
  return { id: actor.id, roles: actor.roles || [] };
}

module.exports = {
  create:           create,
  consumer:         consumer,
  MailAgentError:   MailAgentError,
  SCOPE_FOR_METHOD: SCOPE_FOR_METHOD,
  WIRED_AT:         WIRED_AT,
  HEAVY_METHODS:    HEAVY_METHODS,
  // Re-export the guard family so callers can introspect without
  // separate requires.
  guards: {
    query:    guardMailQuery,
    compose:  guardMailCompose,
    reply:    guardMailReply,
    move:     guardMailMove,
    sieve:    guardMailSieve,
    messageId: guardMessageId,
  },
};

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.agent
 * @nav        Mail
 * @title      Mail Agent
 * @order      100
 * @featured   true
 *
 * @intro
 *   A mailbox-access facade that owns RBAC, posture enforcement, audit
 *   emission, dispatch (local / worker-pool / queue), and worker
 *   isolation around a mail store, so a protocol server built on top
 *   can stay a thin shell. It is designed to be the shared dispatch
 *   layer mail-protocol servers route through; today the read surface
 *   and the mailbox-mutation + Sieve-upload methods are wired, while the
 *   compose/send and identity/vacation/MDN/export verbs are not yet
 *   wired into the facade (see below).
 *
 *   `agent.create()` returns the facade. Methods backed by
 *   `b.mailStore` (folders / fetch / search / move / flag / delete /
 *   expunge, plus `sieve.put`) run immediately. The remaining verbs —
 *   compose / send / reply / forward, sieve.list / sieve.activate,
 *   identity / vacation / mdn.*, export / job / import — throw
 *   `mail-agent/not-implemented`: they are not yet routed through the
 *   agent. Until they are, compose the underlying primitive directly
 *   (`b.mail.send.deliver` for outbound, `b.mail.sieve` for Sieve,
 *   `b.mailMdn` for MDN, etc.) — which is what the framework's own JMAP
 *   `emailSubmissionSet` handler does. They wire into the facade when a
 *   protocol server adopts the agent as its dispatch layer.
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
 *   Mailbox-access facade — RBAC + posture + audit + dispatch around a
 *   mail store, so a protocol server on top stays a thin shell. Read +
 *   mailbox-mutation + Sieve-upload methods are wired; compose/send and
 *   identity/vacation/MDN/export verbs compose the underlying primitive
 *   directly until a protocol server routes them through the agent.
 */

var lazyRequire        = require("./lazy-require");
var numericBounds      = require("./numeric-bounds");
var validateOpts       = require("./validate-opts");
var C                  = require("./constants");
var agentAudit         = require("./agent-audit");
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
var DEFAULT_QUEUE_DEPTH_CAP = 1024;

var HEAVY_METHODS = Object.freeze({
  search: true, export: true,
});

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
  expunge:          "mail:expunge",
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

var COMPOSE_HINT = Object.freeze({
  compose:          "b.mail.send.deliver",
  send:             "b.mail.send.deliver",
  reply:            "b.mail.send.deliver",
  forward:          "b.mail.send.deliver",
  "sieve.list":     "b.mail.sieve",
  "sieve.activate": "b.mail.sieve",
  "identity.set":   "your identity store + b.mail.sieve",
  "vacation.set":   "b.mail.sieve (vacation extension)",
  "mdn.send":       "b.mailMdn",
  "mdn.parse":      "b.mailMdn",
  "mdn.allowList":  "b.mailMdn",
  export:           "b.mailStore / b.auditTools",
  job:              "the dispatch queue directly",
  import:           "b.mailStore",
});

/**
 * @primitive b.mail.agent.create
 * @signature b.mail.agent.create(opts)
 * @since     0.9.20
 * @status    stable
 * @related   b.mailStore, b.mail.agent.consumer
 *
 * Create the agent facade. Returns an object with read / write / sieve
 * / identity / mdn / export / import methods. Reads stay
 * synchronous-shaped via promises; writes audit on completion. (The
 * queue consumer is the sibling export <code>b.mail.agent.consumer</code>,
 * not a method on this object.)
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
    search:    function (args) { return _dispatchOrLocal(ctx, "search",  args, _search); },
    fetch:     function (args) { return _dispatchOrLocal(ctx, "fetch",   args, _fetch); },
    thread:    function (args) { return _dispatchOrLocal(ctx, "thread",  args, _thread); },
    folders:   function (args) { return _dispatchOrLocal(ctx, "folders", args, _folders); },
    quota:     function (args) { return _dispatchOrLocal(ctx, "quota",   args, _quota); },

    compose:   function (args) { return _notImplemented(ctx, "compose", args); },
    send:      function (args) { return _notImplemented(ctx, "send", args); },
    reply:     function (args) { return _notImplemented(ctx, "reply", args); },
    forward:   function (args) { return _notImplemented(ctx, "forward", args); },

    move:      function (args) { return _dispatchOrLocal(ctx, "move",   args, _move); },
    flag:      function (args) { return _dispatchOrLocal(ctx, "flag",   args, _flag); },
    delete:    function (args) { return _dispatchOrLocal(ctx, "delete", args, _delete); },
    expunge:   function (args) { return _dispatchOrLocal(ctx, "expunge", args, _expunge); },

    sieve:     {
      list:     function (args) { return _notImplemented(ctx, "sieve.list",     args); },
      put:      function (args) { return _sievePut(ctx, args); },
      activate: function (args) { return _notImplemented(ctx, "sieve.activate", args); },
    },

    identity:  {
      set:      function (args) { return _notImplemented(ctx, "identity.set", args); },
    },
    vacation:  {
      set:      function (args) { return _notImplemented(ctx, "vacation.set", args); },
    },

    mdn:       {
      send:     function (args) { return _notImplemented(ctx, "mdn.send",      args); },
      parse:    function (args) { return _notImplemented(ctx, "mdn.parse",     args); },
      allowList: function (args) { return _notImplemented(ctx, "mdn.allowList", args); },
    },

    export:    function (args) { return _notImplemented(ctx, "export", args); },
    job:       function (args) { return _notImplemented(ctx, "job",    args); },

    import:    function (args) { return _notImplemented(ctx, "import", args); },

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

async function _dispatchOrLocal(ctx, method, args, localFn) {
  var mode = ctx.dispatch.mode;
  if (mode === "local") return localFn(ctx, args);
  if (mode === "auto") {
    if (Object.prototype.hasOwnProperty.call(HEAVY_METHODS, method) && ctx.dispatch.queue) return _enqueueMethod(ctx, method, args);
    return localFn(ctx, args);
  }
  if (!ctx.dispatch.queue) {
    throw new MailAgentError("mail-agent/no-queue",
      "agent." + method + ": dispatch.mode='queue' requires opts.dispatch.queue");
  }
  if (!Object.prototype.hasOwnProperty.call(HEAVY_METHODS, method)) {
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

async function _search(ctx, args) {
  _entry(ctx, "search", args);
  guardMailQuery.validate(args.filter || {}, { profile: _profileFor(ctx), posture: ctx.posture, project: args.project });
  var folder = args.folder || "INBOX";
  var filter = args.filter || {};
  var sinceModseq = (filter.modseq && filter.modseq.gt) || filter.sinceModseq || 0;
  var limit = args.limit || filter.limit || 100;
  var storeFilter = {
    sinceModseq: sinceModseq,
    limit:       limit,
    text:        filter.text,
    subject:     filter.subject,
    body:        filter.body,
    from:        filter.from,
    to:          filter.to,
  };
  var result = ctx.store.search(folder, storeFilter);
  ctx.auditEmit("mail.agent.search.success", args.actor, {
    folder:    folder,
    rowCount:  result.rows.length,
    hasText:   Boolean(filter.text || filter.subject || filter.body || filter.from || filter.to),
  });
  return { rows: result.rows, nextModseq: result.nextModseq };
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
  _entry(ctx, "delete", args);
  if (typeof args.folder !== "string" || !Array.isArray(args.objectIds)) {
    throw new MailAgentError("mail-agent/bad-args",
      "agent.delete: { folder, objectIds } required");
  }
  if (args.folder === "Trash") {
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

async function _expunge(ctx, args) {
  _entry(ctx, "expunge", args);
  if (typeof args.folder !== "string" || !Array.isArray(args.objectIds)) {
    throw new MailAgentError("mail-agent/bad-args",
      "agent.expunge: { folder, objectIds, [candidateTtlMs] } required");
  }

  var retentionModule = require("./retention");                                                    // allow:inline-require — lazy-load until first expunge call
  var posture = (ctx && ctx.posture) || (args && args.posture) || null;
  var floorMs = 0;
  if (typeof posture === "string" && posture.length > 0) {
    try {
      floorMs = retentionModule.complianceFloor(posture);
    } catch (e) {
      throw new MailAgentError("mail-agent/unknown-posture",
        "expunge: posture '" + posture + "' is not a posture the framework knows, " +
        "so no retention floor can be established and the hard delete is refused " +
        "rather than run unbounded: " + ((e && e.message) || String(e)));
    }
  }

  var nowMs = Date.now();
  var refused = [];
  var candidates = [];
  for (var i = 0; i < args.objectIds.length; i += 1) {
    var oid = args.objectIds[i];
    var meta = ctx.store.fetchByObjectId(args.folder, oid);
    if (!meta) {
      refused.push({ id: oid, reason: "not-in-folder" });
      continue;
    }
    if (meta.legalHold) {
      refused.push({ id: oid, reason: "legal-hold" });
      continue;
    }
    if (floorMs > 0) {
      var receivedAt = numericBounds.isNonNegativeSafeInt(meta.receivedAt)
        ? meta.receivedAt
        : null;
      if (receivedAt === null) {
        refused.push({ id: oid, reason: "retention-floor-unknown-arrival",
                       floorMs: floorMs, posture: posture });
        continue;
      }
      var ageMs = nowMs - receivedAt;
      if (ageMs < floorMs) {
        refused.push({ id: oid, reason: "retention-floor",
                       floorMs: floorMs, ageMs: ageMs, posture: posture });
        continue;
      }
    }
    candidates.push(oid);
  }

  var result = candidates.length > 0
    ? ctx.store.hardExpunge(args.folder, candidates)
    : { rows: [], deleted: [], refused: [] };

  ctx.auditEmit("mail.agent.expunge.success", args.actor, {
    folder:        args.folder,
    requested:     args.objectIds.length,
    deleted:       result.deleted.length,
    refused:       refused.length,
    refusedReasons: refused.reduce(function (acc, r) {
      acc[r.reason] = (acc[r.reason] || 0) + 1; return acc;
    }, {}),
    posture:       posture,
    floorMs:       floorMs,
  });
  return {
    deleted: result.deleted,
    refused: refused,
  };
}

async function _sievePut(ctx, args) {
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
  if (ctx.posture) guardMailQuery.validateActor(args && args.actor, ctx.posture);
  _checkPermission(ctx, method, args);
  ctx.auditEmit("mail.agent.not_implemented", args && args.actor, { method: method, composeDirectly: COMPOSE_HINT[method] });
  return Promise.reject(new MailAgentError("mail-agent/not-implemented",
    "agent." + method + " is not yet routed through the agent facade — compose " +
    COMPOSE_HINT[method] + " directly"));
}

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

var _actorShape = agentAudit.actorShape;

module.exports = {
  create:           create,
  consumer:         consumer,
  MailAgentError:   MailAgentError,
  SCOPE_FOR_METHOD: SCOPE_FOR_METHOD,
  COMPOSE_HINT:     COMPOSE_HINT,
  HEAVY_METHODS:    HEAVY_METHODS,
  guards: {
    query:    guardMailQuery,
    compose:  guardMailCompose,
    reply:    guardMailReply,
    move:     guardMailMove,
    sieve:    guardMailSieve,
    messageId: guardMessageId,
  },
};

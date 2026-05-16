"use strict";
/**
 * @module     b.agent.eventBus
 * @nav        Agent
 * @title      Agent Event Bus
 * @order      65
 *
 * @intro
 *   Typed cross-agent publish/subscribe on top of `b.pubsub` (or any
 *   pubsub-shaped instance with `publish` / `subscribe` /
 *   `unsubscribe`). Substrate for every agent-to-agent reaction the
 *   mail stack + future agents need: `mail.scan.malware-detected` →
 *   MX refuses source, `mail.crypto.key-rotated` → vault invalidates
 *   cached recipient keys, `ai.classify.prompt-injection-detected` →
 *   agent quarantines, etc.
 *
 *   The bus owns:
 *
 *     - **Topic registry** — `registerTopic(name, { schema, posture,
 *       permissions, tenantScope })` declares the wire contract at
 *       boot. Unknown topics refuse publish + subscribe so typos
 *       fail loudly.
 *     - **Schema enforcement** — every payload validated against the
 *       declared schema before publish AND at each delivery
 *       (defends in-flight tampering).
 *     - **Permission gating** — `b.permissions.check(actor, scope)`
 *       on every publish + subscribe.
 *     - **Posture re-validation at delivery** — same shape as
 *       v0.9.20 cross-queue posture check.
 *     - **Audit lifecycle** — publish / subscribe / delivery / refused
 *       events emit to the operator's audit chain.
 *
 *   ```js
 *   var bus = b.agent.eventBus.create({
 *     pubsub:       myPubsub,
 *     audit:        b.audit,
 *     permissions:  myPerms,
 *   });
 *
 *   bus.registerTopic("mail.scan.malware-detected", {
 *     schema: {
 *       source:       "string",
 *       confidence:   "number",
 *       detectedAt:   "isoDateTime",
 *     },
 *     posture:    "soc2",
 *     permissions: {
 *       publish:   ["mail-scan:write"],
 *       subscribe: ["mail-mx:write"],
 *     },
 *   });
 *
 *   await bus.publish("mail.scan.malware-detected", {
 *     source: "1.2.3.4", confidence: 0.95, detectedAt: new Date().toISOString(),
 *   }, { actor: { id: "scan-agent", roles: ["mail-scan-internal"] } });
 *   ```
 *
 * @card
 *   Typed cross-agent publish/subscribe. Topics registered with schema
 *   + posture + permissions; every payload validated; subscriber-side
 *   posture re-validated at delivery so no posture downgrade survives
 *   the bus boundary.
 */

var lazyRequire           = require("./lazy-require");
var { defineClass }       = require("./framework-error");
var guardEventBusTopic    = require("./guard-event-bus-topic");
var guardEventBusPayload  = require("./guard-event-bus-payload");
var agentAudit            = require("./agent-audit");

var audit                 = lazyRequire(function () { return require("./audit"); });

var AgentEventBusError = defineClass("AgentEventBusError", { alwaysPermanent: true });

/**
 * @primitive b.agent.eventBus.create
 * @signature b.agent.eventBus.create(opts)
 * @since     0.9.25
 * @status    stable
 * @related   b.agent.orchestrator.create, b.pubsub.create
 *
 * Create the bus facade. Returns an instance with `registerTopic` /
 * `publish` / `subscribe` / `listTopics`. Operator supplies a pubsub-
 * shaped backend; framework owns schema validation, permission
 * gating, posture re-validation, audit lifecycle.
 *
 * @opts
 *   pubsub:       { publish, subscribe, unsubscribe },   // required
 *   audit:        b.audit namespace,                      // optional
 *   permissions:  b.permissions instance,                  // optional
 *
 * @example
 *   var bus = b.agent.eventBus.create({ pubsub: myPubsub });
 *   bus.registerTopic("mail.scan.malware-detected", {
 *     schema: { source: "string" },
 *   });
 *   await bus.publish("mail.scan.malware-detected", { source: "1.2.3.4" });
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new AgentEventBusError("agent-event-bus/bad-opts",
      "create: opts required");
  }
  if (!opts.pubsub || typeof opts.pubsub.publish !== "function" ||
      typeof opts.pubsub.subscribe !== "function") {
    throw new AgentEventBusError("agent-event-bus/bad-pubsub",
      "create: opts.pubsub must expose { publish, subscribe }");
  }
  var auditImpl   = opts.audit || audit();
  var permissions = opts.permissions || null;
  var topics      = new Map();

  return {
    registerTopic: function (name, topicOpts)    { return _registerTopic(topics, name, topicOpts || {}, auditImpl); },
    publish:       function (name, payload, pOpts) { return _publish(topics, opts.pubsub, name, payload, pOpts || {}, permissions, auditImpl); },
    subscribe:     function (name, handler, sOpts) { return _subscribe(topics, opts.pubsub, name, handler, sOpts || {}, permissions, auditImpl); },
    listTopics:    function (args)                { return _listTopics(topics, args || {}, permissions); },
    AgentEventBusError: AgentEventBusError,
    guards: {
      topic:   guardEventBusTopic,
      payload: guardEventBusPayload,
    },
  };
}

// ---- Registry -------------------------------------------------------------

function _registerTopic(topics, name, topicOpts, auditImpl) {
  guardEventBusTopic.validate(name);
  if (topics.has(name)) {
    throw new AgentEventBusError("agent-event-bus/topic-duplicate",
      "registerTopic: '" + name + "' already registered");
  }
  if (!topicOpts.schema || typeof topicOpts.schema !== "object") {
    throw new AgentEventBusError("agent-event-bus/bad-schema",
      "registerTopic: schema required (flat key→type map)");
  }
  var entry = {
    name:        name,
    schema:      Object.freeze(Object.assign({}, topicOpts.schema)),
    posture:     topicOpts.posture || null,
    tenantScope: topicOpts.tenantScope === true,
    permissions: {
      publish:   topicOpts.permissions && Array.isArray(topicOpts.permissions.publish)
                   ? topicOpts.permissions.publish.slice() : null,
      subscribe: topicOpts.permissions && Array.isArray(topicOpts.permissions.subscribe)
                   ? topicOpts.permissions.subscribe.slice() : null,
    },
    registeredAt: Date.now(),
  };
  topics.set(name, entry);
  _safeAudit(auditImpl, "agent.event_bus.topic_registered", null, {
    name: name, posture: entry.posture, tenantScope: entry.tenantScope,
  });
}

function _listTopics(topics, args, permissions) {
  // Permission gate: list-topics requires no special scope by default;
  // operator can wrap with their own permissions instance for stricter.
  var out = [];
  topics.forEach(function (entry) {
    if (args.kind && entry.kind && entry.kind !== args.kind) return;
    out.push({
      name:        entry.name,
      schema:      entry.schema,
      posture:     entry.posture,
      tenantScope: entry.tenantScope,
      registeredAt: entry.registeredAt,
    });
  });
  return out;
}

// ---- Publish --------------------------------------------------------------

async function _publish(topics, pubsub, name, payload, pOpts, permissions, auditImpl) {
  guardEventBusTopic.validate(name);
  var entry = topics.get(name);
  if (!entry) {
    throw new AgentEventBusError("agent-event-bus/unknown-topic",
      "publish: topic '" + name + "' not registered");
  }
  // Permission check for publish.
  if (permissions && entry.permissions.publish) {
    if (!pOpts.actor) {
      throw new AgentEventBusError("agent-event-bus/no-actor",
        "publish: topic '" + name + "' requires actor");
    }
    var allowedPub = false;
    for (var i = 0; i < entry.permissions.publish.length; i += 1) {
      if (permissions.check(pOpts.actor, entry.permissions.publish[i])) {
        allowedPub = true; break;
      }
    }
    if (!allowedPub) {
      _safeAudit(auditImpl, "agent.event_bus.publish_denied", pOpts.actor, { topic: name });
      throw new AgentEventBusError("agent-event-bus/publish-denied",
        "publish: actor lacks any of " + JSON.stringify(entry.permissions.publish) +
        " required for topic '" + name + "'");
    }
  }
  // Schema validation.
  guardEventBusPayload.validate(payload, entry.schema);
  // Wrap the payload with topic metadata so subscribers can see the
  // posture + tenantScope at delivery (re-validation).
  var wrapped = {
    _topic:       name,
    _posture:     entry.posture,
    _tenantId:    pOpts.actor && pOpts.actor.tenantId ? pOpts.actor.tenantId : null,
    _publishedAt: Date.now(),
    payload:      payload,
  };
  await pubsub.publish(name, wrapped);
  _safeAudit(auditImpl, "agent.event_bus.published", pOpts.actor, {
    topic: name, posture: entry.posture,
  });
  return { topic: name, publishedAt: wrapped._publishedAt };
}

// ---- Subscribe ------------------------------------------------------------

async function _subscribe(topics, pubsub, name, handler, sOpts, permissions, auditImpl) {
  guardEventBusTopic.validate(name);
  var entry = topics.get(name);
  if (!entry) {
    throw new AgentEventBusError("agent-event-bus/unknown-topic",
      "subscribe: topic '" + name + "' not registered");
  }
  if (typeof handler !== "function") {
    throw new AgentEventBusError("agent-event-bus/bad-handler",
      "subscribe: handler must be a function");
  }
  // Permission check for subscribe.
  if (permissions && entry.permissions.subscribe) {
    if (!sOpts.actor) {
      throw new AgentEventBusError("agent-event-bus/no-actor",
        "subscribe: topic '" + name + "' requires actor");
    }
    var allowedSub = false;
    for (var i = 0; i < entry.permissions.subscribe.length; i += 1) {
      if (permissions.check(sOpts.actor, entry.permissions.subscribe[i])) {
        allowedSub = true; break;
      }
    }
    if (!allowedSub) {
      _safeAudit(auditImpl, "agent.event_bus.subscribe_denied", sOpts.actor, { topic: name });
      throw new AgentEventBusError("agent-event-bus/subscribe-denied",
        "subscribe: actor lacks any of " + JSON.stringify(entry.permissions.subscribe) +
        " required for topic '" + name + "'");
    }
  }
  // Cross-tenant subscription gate — when tenantScope is set, the
  // subscriber's actor MUST declare a tenantId at subscribe-time.
  // Subscribers without an actor.tenantId on a tenant-scoped topic
  // are refused outright; the previous shape (filter only when both
  // tenants present) silently accepted such subscribers and let them
  // receive every tenant's events.
  var subscriberTenant = sOpts.actor && sOpts.actor.tenantId ? sOpts.actor.tenantId : null;
  if (entry.tenantScope && !subscriberTenant) {
    _safeAudit(auditImpl, "agent.event_bus.subscribe_denied", sOpts.actor, {
      topic: name, reason: "tenant-scoped-topic-requires-actor-tenant-id",
    });
    throw new AgentEventBusError("agent-event-bus/subscribe-denied",
      "subscribe: tenant-scoped topic '" + name +
      "' requires actor.tenantId; subscribers without a tenant identity are refused");
  }

  // Wrapped handler: re-validate posture + tenant at delivery so an
  // in-flight tamper / cross-tenant routing attempt is refused at the
  // consumer boundary (not at the bus's trust boundary alone).
  async function _wrappedHandler(wrapped, evMeta) {
    if (!wrapped || typeof wrapped !== "object" || !wrapped._topic) {
      _safeAudit(auditImpl, "agent.event_bus.delivery_dropped", sOpts.actor,
        { topic: name, reason: "malformed-envelope" });
      return;
    }
    // Tenant-scope check: subscriber's tenantId must match the
    // publisher's tenantId from the wire envelope. If the envelope
    // lacks _tenantId (publisher omitted), that's a tampered or
    // malformed wire and the delivery drops.
    if (entry.tenantScope) {
      if (!wrapped._tenantId || wrapped._tenantId !== subscriberTenant) {
        _safeAudit(auditImpl, "agent.event_bus.cross_tenant_drop", sOpts.actor, {
          topic: name,
          publisherTenant:  wrapped._tenantId || null,
          subscriberTenant: subscriberTenant,
          reason: wrapped._tenantId ? "tenant-mismatch" : "missing-publisher-tenant",
        });
        return;
      }
    }
    // Re-validate payload against schema in case of in-flight tamper.
    try { guardEventBusPayload.validate(wrapped.payload, entry.schema); }
    catch (_e) {
      _safeAudit(auditImpl, "agent.event_bus.delivery_dropped", sOpts.actor,
        { topic: name, reason: "payload-schema-violation" });
      return;
    }
    // Await handler — supports async handlers + catches their async
    // rejections. Without await, an async handler that rejects would
    // surface as an unhandled rejection and skip the audit emit.
    try {
      await handler(wrapped.payload, {
        topic: name, publishedAt: wrapped._publishedAt,
        source: evMeta && evMeta.source,
      });
    }
    catch (e) {
      _safeAudit(auditImpl, "agent.event_bus.handler_threw", sOpts.actor,
        { topic: name, message: (e && e.message) || String(e) });
    }
  }
  var token = await pubsub.subscribe(name, _wrappedHandler);
  _safeAudit(auditImpl, "agent.event_bus.subscribed", sOpts.actor, { topic: name });
  return function unsubscribe() {
    try {
      if (typeof token === "function") return token();
      if (token && typeof token.unsubscribe === "function") return token.unsubscribe();
    } catch (_e) { /* best-effort */ }
  };
}

// ---- Audit helper ---------------------------------------------------------

function _safeAudit(auditImpl, action, actor, metadata) {
  agentAudit.safeAudit(auditImpl, action, actor, metadata);
}

module.exports = {
  create:                  create,
  AgentEventBusError:      AgentEventBusError,
  guards: {
    topic:   guardEventBusTopic,
    payload: guardEventBusPayload,
  },
};

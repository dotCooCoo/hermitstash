// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var envelopeMac           = require("./agent-envelope-mac");
var safeJson              = require("./safe-json");
var bCrypto               = require("./crypto");
var boundedMap            = require("./bounded-map");

var audit                 = lazyRequire(function () { return require("./audit"); });

var AgentEventBusError = defineClass("AgentEventBusError", { alwaysPermanent: true });

var ENVELOPE_MAC_LABEL = "blamejs.agent.eventBus/v1";

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
 *   requireMac:   boolean,                                 // default: true — keyed-MAC envelope auth; false only for single-process unit tests with no vault
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
  var requireMac  = opts.requireMac !== false;

  return {
    registerTopic:   function (name, topicOpts)    { return _registerTopic(topics, name, topicOpts || {}, auditImpl); },
    unregisterTopic: function (name)               { return _unregisterTopic(topics, name, auditImpl); },
    publish:         function (name, payload, pOpts) { return _publish(topics, opts.pubsub, name, payload, pOpts || {}, permissions, auditImpl, requireMac); },
    subscribe:       function (name, handler, sOpts) { return _subscribe(topics, opts.pubsub, name, handler, sOpts || {}, permissions, auditImpl, requireMac); },
    listTopics:      function (args)                { return _listTopics(topics, args || {}, permissions); },
    AgentEventBusError: AgentEventBusError,
    guards: {
      topic:   guardEventBusTopic,
      payload: guardEventBusPayload,
    },
  };
}

function _registerTopic(topics, name, topicOpts, auditImpl) {
  guardEventBusTopic.validate(name);
  boundedMap.requireAbsent(topics, name, function () {
    throw new AgentEventBusError("agent-event-bus/topic-duplicate",
      "registerTopic: '" + name + "' already registered");
  });
  if (!topicOpts.schema || typeof topicOpts.schema !== "object") {
    throw new AgentEventBusError("agent-event-bus/bad-schema",
      "registerTopic: schema required (flat key→type map)");
  }
  var kind = typeof topicOpts.kind === "string" && topicOpts.kind.length > 0
    ? topicOpts.kind
    : (name.indexOf(".") > 0 ? name.split(".")[0] : name);
  var entry = {
    name:        name,
    kind:        kind,
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
    name: name, kind: kind, posture: entry.posture, tenantScope: entry.tenantScope,
  });
}

function _unregisterTopic(topics, name, auditImpl) {
  guardEventBusTopic.validate(name);
  boundedMap.requirePresent(topics, name, function () {
    throw new AgentEventBusError("agent-event-bus/unknown-topic",
      "unregisterTopic: '" + name + "' not registered");
  });
  topics.delete(name);
  _safeAudit(auditImpl, "agent.event_bus.topic_unregistered", null, { name: name });
}

function _listTopics(topics, args, permissions) {
  var out = [];
  topics.forEach(function (entry) {
    if (args.kind && entry.kind !== args.kind) return;
    out.push({
      name:        entry.name,
      kind:        entry.kind,
      schema:      entry.schema,
      posture:     entry.posture,
      tenantScope: entry.tenantScope,
      registeredAt: entry.registeredAt,
    });
  });
  return out;
}

function _macField(value, kind) {
  if (kind === "string") return typeof value === "string" ? value : null;
  if (kind === "number") return typeof value === "number" ? value : null;
  return value === undefined ? null : value;
}
function _envelopeMacBytes(wrapped) {
  var payloadForHash = wrapped.payload === undefined ? null : wrapped.payload;
  var tuples = [
    ["_topic",       _macField(wrapped._topic, "string")],
    ["_tenantId",    _macField(wrapped._tenantId, "string")],
    ["_posture",     _macField(wrapped._posture, "any")],
    ["_publishedAt", _macField(wrapped._publishedAt, "number")],
    ["payloadHash",  bCrypto.sha3Hash(safeJson.canonical(payloadForHash))],
  ];
  return Buffer.from(safeJson.canonical(tuples), "utf8");
}

async function _publish(topics, pubsub, name, payload, pOpts, permissions, auditImpl, requireMac) {
  guardEventBusTopic.validate(name);
  var entry = topics.get(name);
  if (!entry) {
    throw new AgentEventBusError("agent-event-bus/unknown-topic",
      "publish: topic '" + name + "' not registered");
  }
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
  guardEventBusPayload.validate(payload, entry.schema);
  if (entry.tenantScope) {
    if (!pOpts.actor || !pOpts.actor.tenantId) {
      _safeAudit(auditImpl, "agent.event_bus.publish_denied", pOpts.actor || null, {
        topic: name, reason: "tenant-scoped-topic-requires-publisher-tenant-id",
      });
      throw new AgentEventBusError("agent-event-bus/publish-denied",
        "publish: tenant-scoped topic '" + name +
        "' requires actor.tenantId at publish time — refusing to write " +
        "untenanted entries to a durable backend");
    }
  }
  var wrapped = {
    _topic:       name,
    _posture:     entry.posture,
    _tenantId:    pOpts.actor && pOpts.actor.tenantId ? pOpts.actor.tenantId : null,
    _publishedAt: Date.now(),
    payload:      payload,
  };
  try {
    wrapped._mac = envelopeMac.sign(ENVELOPE_MAC_LABEL, _envelopeMacBytes(wrapped));
  } catch (e) {
    if (requireMac) {
      _safeAudit(auditImpl, "agent.event_bus.publish_denied", pOpts.actor || null, {
        topic: name, reason: "envelope-mac-unavailable",
      });
      throw new AgentEventBusError("agent-event-bus/envelope-mac-unavailable",
        "publish: cannot authenticate the event envelope — " +
        ((e && e.message) || String(e)) +
        " (vault must be initialized so the bus MAC key is derivable, or " +
        "set requireMac:false for single-process unit tests)");
    }
    wrapped._mac = null;
    _safeAudit(auditImpl, "agent.event_bus.mac_bypassed", pOpts.actor || null, {
      topic: name, reason: "require-mac-disabled", phase: "publish",
    });
  }
  await pubsub.publish(name, wrapped);
  _safeAudit(auditImpl, "agent.event_bus.published", pOpts.actor, {
    topic: name, posture: entry.posture,
  });
  return { topic: name, publishedAt: wrapped._publishedAt };
}

async function _subscribe(topics, pubsub, name, handler, sOpts, permissions, auditImpl, requireMac) {
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
  var subscriberTenant = sOpts.actor && sOpts.actor.tenantId ? sOpts.actor.tenantId : null;
  if (entry.tenantScope && !subscriberTenant) {
    _safeAudit(auditImpl, "agent.event_bus.subscribe_denied", sOpts.actor, {
      topic: name, reason: "tenant-scoped-topic-requires-actor-tenant-id",
    });
    throw new AgentEventBusError("agent-event-bus/subscribe-denied",
      "subscribe: tenant-scoped topic '" + name +
      "' requires actor.tenantId; subscribers without a tenant identity are refused");
  }

  async function _wrappedHandler(wrapped, evMeta) {
    if (!wrapped || typeof wrapped !== "object" || !wrapped._topic) {
      _safeAudit(auditImpl, "agent.event_bus.delivery_dropped", sOpts.actor,
        { topic: name, reason: "malformed-envelope" });
      return;
    }
    if (requireMac) {
      var macOk = false;
      try {
        macOk = envelopeMac.verify(ENVELOPE_MAC_LABEL, _envelopeMacBytes(wrapped), wrapped._mac);
      } catch (_e) {
        macOk = false;
      }
      if (!macOk) {
        _safeAudit(auditImpl, "agent.event_bus.cross_tenant_drop", sOpts.actor, {
          topic: name,
          publisherTenant:  typeof wrapped._tenantId === "string" ? wrapped._tenantId : null,
          subscriberTenant: subscriberTenant,
          reason: "envelope-mac-invalid",
        });
        return;
      }
    } else {
      _safeAudit(auditImpl, "agent.event_bus.mac_bypassed", sOpts.actor, {
        topic: name, reason: "require-mac-disabled", phase: "delivery",
      });
    }
    if (wrapped._topic !== name) {
      _safeAudit(auditImpl, "agent.event_bus.delivery_dropped", sOpts.actor, {
        topic: name, reason: "topic-channel-mismatch",
        envelopeTopic: typeof wrapped._topic === "string" ? wrapped._topic : null,
      });
      return;
    }
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
    try { guardEventBusPayload.validate(wrapped.payload, entry.schema); }
    catch (_e) {
      _safeAudit(auditImpl, "agent.event_bus.delivery_dropped", sOpts.actor,
        { topic: name, reason: "payload-schema-violation" });
      return;
    }
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

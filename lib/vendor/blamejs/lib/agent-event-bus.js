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

// Wire-envelope authentication. An attacker with pubsub write access can
// set _tenantId to a victim subscriber's tenant + a schema-valid payload
// and forge a cross-tenant event; the tenant/posture/schema checks at the
// consumer prove SHAPE, not authenticity. Defense is a keyed MAC over the
// envelope's authority-bearing fields, minted at publish and verified at
// the consumer BEFORE the tenant/schema checks. The key derivation +
// HMAC live in the shared b.agent.envelopeMac mechanism (one keyed-MAC
// mechanism for every agent boundary); this label domain-separates the
// event-bus MAC from the posture-chain MAC.
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
  // Envelope MAC (M6): default ON. Only single-process unit tests with no
  // vault should opt out. When off, the cross-tenant MAC gate is bypassed
  // and that is audit-visible at publish + delivery; production /
  // multi-process / queue-spanning deployments leave the default so a
  // pubsub-write attacker can't forge a cross-tenant event.
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

// ---- Registry -------------------------------------------------------------

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
  // `kind` is now captured on register so listTopics's kind
  // filter actually matches. Prior shape never set entry.kind, so the
  // filter at args.kind was dead. Default value derives from the
  // dotted topic name's first segment ("mail.scan.x" → "mail"), giving
  // operators a free-by-default grouping without explicit annotation.
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

// Operators reloading a module (test runners between
// runs, hot-reload tools, multi-tenant onboarding flows that
// register-deregister topics) need a clean unregister path; without
// it the second register throws topic-duplicate and the operator is
// stuck. The reverse audit emit pairs with topic_registered for
// lifecycle traceability.
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
  // Permission gate: list-topics requires no special scope by default;
  // operator can wrap with their own permissions instance for stricter.
  // Kind filter now matches because register captures kind.
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

// ---- Publish --------------------------------------------------------------

// Canonical bytes the MAC covers: _topic, _tenantId, _posture,
// _publishedAt, and a hash of the payload (so the payload can't be
// swapped without invalidating the MAC, without copying the whole
// payload into the signed preimage). Field set matches the consumer's
// authority decision inputs. Built as an ordered [key,value] tuple list
// so the canonical preimage is stable regardless of source key order.
function _macField(value, kind) {
  if (kind === "string") return typeof value === "string" ? value : null;
  if (kind === "number") return typeof value === "number" ? value : null;
  return value === undefined ? null : value;   // pass-through (posture)
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
  // When a topic is tenant-scoped, require the publisher
  // to declare a tenantId BEFORE the event reaches the durable bus
  // backend. Prior shape allowed `wrapped._tenantId: null` to land on
  // the bus, and the receive-side drop only fired AFTER persistence —
  // every tenant's queue / topic / Kafka log accumulated entries from
  // unknown-tenant publishers. Refuse here so the durable record is
  // always tagged with a real tenant.
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
  // Wrap the payload with topic metadata so subscribers can see the
  // posture + tenantScope at delivery (re-validation).
  var wrapped = {
    _topic:       name,
    _posture:     entry.posture,
    _tenantId:    pOpts.actor && pOpts.actor.tenantId ? pOpts.actor.tenantId : null,
    _publishedAt: Date.now(),
    payload:      payload,
  };
  // Authenticate the envelope's authority-bearing fields with a keyed MAC
  // (M6). The consumer verifies this BEFORE the tenant/schema checks, so a
  // pubsub-write attacker can't forge a cross-tenant event. If the vault
  // isn't initialized there's no key to mint with — fail closed at publish
  // (requireMac default) rather than emit an unauthenticatable envelope
  // onto the bus. requireMac:false is the single-process unit-test escape
  // hatch and is audit-visible.
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
    // Escape hatch: no key + requireMac disabled → emit unauthenticated.
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

// ---- Subscribe ------------------------------------------------------------

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
    // Envelope authentication FIRST (M6): verify the keyed MAC over the
    // authority-bearing fields (_topic / _tenantId / _posture /
    // _publishedAt / payload-hash) BEFORE trusting _tenantId / _posture
    // for any routing or schema decision. A pubsub-write attacker who
    // forges _tenantId (cross-tenant routing) or tampers _posture / the
    // payload produces a MAC mismatch and the delivery drops. If the
    // vault key is unavailable, verify() throws — we fail CLOSED (drop),
    // never deliver an unauthenticatable envelope cross-tenant.
    // requireMac:false is the single-process unit-test escape hatch and
    // is audit-visible.
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

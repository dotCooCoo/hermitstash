// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;

// The shape-only tests below run single-process with no vault, so they
// pass requireMac:false (the documented escape hatch). The keyed-MAC
// envelope authentication (M6) is exercised against a real vault in the
// testEnvelopeMac* tests at the bottom of this file.
function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-evbus-")); }

function _fakePubsub() {
  var subs = new Map();
  return {
    publish: async function (channel, payload) {
      var handlers = subs.get(channel) || [];
      handlers.forEach(function (h) { h(payload, { source: "fake" }); });
    },
    subscribe: async function (channel, handler) {
      var list = subs.get(channel) || [];
      list.push(handler);
      subs.set(channel, list);
      return function unsubscribe() {
        var L = subs.get(channel) || [];
        var idx = L.indexOf(handler);
        if (idx >= 0) L.splice(idx, 1);
      };
    },
    unsubscribe: function () {},
    _subs: subs,
  };
}

function expectRejection(label, p, codeMatch) {
  return p.then(
    function () { check(label + " (did not reject)", false); },
    function (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
  );
}

function testSurface() {
  check("create is fn",         typeof b.agent.eventBus.create === "function");
  check("AgentEventBusError",   typeof b.agent.eventBus.AgentEventBusError === "function");
  check("guards.topic",          b.agent.eventBus.guards.topic === b.guardEventBusTopic);
  check("guards.payload",        b.agent.eventBus.guards.payload === b.guardEventBusPayload);
  var e = new b.agent.eventBus.AgentEventBusError("agent-event-bus/test", "t");
  check("error carries code",    e.code === "agent-event-bus/test");
}

async function testRegisterPublishSubscribe() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  bus.registerTopic("mail.scan.malware-detected", {
    schema: { source: "string", confidence: "number" },
  });
  var received = [];
  await bus.subscribe("mail.scan.malware-detected", function (payload, meta) {
    received.push({ payload: payload, meta: meta });
  });
  await bus.publish("mail.scan.malware-detected", { source: "1.2.3.4", confidence: 0.95 });
  check("delivery: 1 event",        received.length === 1);
  check("delivery: payload intact", received[0].payload.source === "1.2.3.4");
  check("delivery: meta carries topic", received[0].meta.topic === "mail.scan.malware-detected");
}

async function testUnknownTopic() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  await expectRejection("publish refuses unknown topic",
    bus.publish("mail.unknown.event", {}),
    "agent-event-bus/unknown-topic");
  await expectRejection("subscribe refuses unknown topic",
    bus.subscribe("mail.unknown.event", function () {}),
    "agent-event-bus/unknown-topic");
}

async function testDuplicateTopic() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  bus.registerTopic("mail.a.b", { schema: { x: "string" } });
  var threw = null;
  try { bus.registerTopic("mail.a.b", { schema: { x: "string" } }); }
  catch (e) { threw = e; }
  check("refuses duplicate topic",
    threw && (threw.code || "").indexOf("agent-event-bus/topic-duplicate") !== -1);
}

async function testBadTopicShape() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  var threw = null;
  try { bus.registerTopic("malware", { schema: { x: "string" } }); }
  catch (e) { threw = e; }
  check("refuses topic without enough dots",
    threw && (threw.code || "").indexOf("event-bus-topic/insufficient-dots") !== -1);
}

async function testSchemaValidation() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  bus.registerTopic("mail.scan.detected", {
    schema: { source: "string", confidence: "number" },
  });
  // Missing required field:
  await expectRejection("refuses missing field",
    bus.publish("mail.scan.detected", { source: "x" }),
    "event-bus-payload/missing-field");
  // Type mismatch:
  await expectRejection("refuses type mismatch",
    bus.publish("mail.scan.detected", { source: "x", confidence: "not-a-number" }),
    "event-bus-payload/type-mismatch");
  // Unknown field:
  await expectRejection("refuses unknown field",
    bus.publish("mail.scan.detected", { source: "x", confidence: 0.5, extra: 1 }),
    "event-bus-payload/unknown-field");
}

async function testPermissions() {
  var perms = b.permissions.create({
    roles: {
      publisher:  { permissions: ["mail-scan:write"] },
      subscriber: { permissions: ["mail-mx:write"] },
    },
    auditFailures: false, auditSuccess: false,
  });
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), permissions: perms, requireMac: false });
  bus.registerTopic("mail.scan.detected", {
    schema: { source: "string" },
    permissions: { publish: ["mail-scan:write"], subscribe: ["mail-mx:write"] },
  });
  // publisher can publish
  await bus.publish("mail.scan.detected", { source: "x" }, {
    actor: { id: "p1", roles: ["publisher"] },
  });
  // subscriber can subscribe but not publish
  await bus.subscribe("mail.scan.detected", function () {}, {
    actor: { id: "s1", roles: ["subscriber"] },
  });
  await expectRejection("publish denied for non-publisher",
    bus.publish("mail.scan.detected", { source: "x" }, {
      actor: { id: "s1", roles: ["subscriber"] },
    }),
    "agent-event-bus/publish-denied");
}

async function testTenantScope() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  bus.registerTopic("mail.tenant.event", {
    schema:      { source: "string" },
    tenantScope: true,
  });
  var receivedA = [];
  var receivedB = [];
  await bus.subscribe("mail.tenant.event", function (p) { receivedA.push(p); }, {
    actor: { id: "u-a", tenantId: "acme" },
  });
  await bus.subscribe("mail.tenant.event", function (p) { receivedB.push(p); }, {
    actor: { id: "u-b", tenantId: "globex" },
  });
  // Publish from acme tenant
  await bus.publish("mail.tenant.event", { source: "x" }, {
    actor: { id: "p1", tenantId: "acme" },
  });
  check("tenant-scope: same-tenant subscriber delivered", receivedA.length === 1);
  check("tenant-scope: cross-tenant subscriber dropped",   receivedB.length === 0);
}

async function testTenantScopeRefusesSubscriberWithoutTenantId() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  bus.registerTopic("mail.scoped.event", {
    schema:      { source: "string" },
    tenantScope: true,
  });
  await expectRejection("tenant-scope: subscriber without tenantId refused",
    bus.subscribe("mail.scoped.event", function () {}, {
      actor: { id: "u-no-tenant" },
    }),
    "agent-event-bus/subscribe-denied");
  await expectRejection("tenant-scope: subscribe without actor refused",
    bus.subscribe("mail.scoped.event", function () {}, {}),
    "agent-event-bus/subscribe-denied");
}

async function testAsyncHandlerErrors() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  bus.registerTopic("mail.async.event", { schema: { x: "string" } });
  var crashed = false;
  var origHandler = process.listeners("unhandledRejection").slice();
  process.removeAllListeners("unhandledRejection");
  process.once("unhandledRejection", function () { crashed = true; });
  await bus.subscribe("mail.async.event", async function () {
    throw new Error("async-boom");
  });
  await bus.publish("mail.async.event", { x: "data" });
  await helpers.passiveObserve(25, "agent-event-bus: unhandledRejection NOT fired for swallowed async reject");
  process.removeAllListeners("unhandledRejection");
  origHandler.forEach(function (h) { process.on("unhandledRejection", h); });
  check("async handler reject swallowed (no unhandledRejection)", !crashed);
}

async function testRefusesBadOpts() {
  var threw = null;
  try { b.agent.eventBus.create({}); } catch (e) { threw = e; }
  check("create refuses missing pubsub",
    threw && (threw.code || "").indexOf("agent-event-bus/bad-pubsub") !== -1);
}

async function testListTopics() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  bus.registerTopic("mail.a.b", { schema: { x: "string" }, posture: "soc2" });
  bus.registerTopic("mail.c.d", { schema: { y: "number" } });
  var list = bus.listTopics({});
  check("listTopics: 2 entries", list.length === 2);
  check("listTopics: name present", list[0].name === "mail.a.b" || list[1].name === "mail.a.b");
}

async function testPublishRefusesUntenantedOnTenantTopic() {
  // SUBSTRATE-6 — tenant-scoped topic refuses publish without
  // actor.tenantId so the durable bus never accumulates untenanted
  // entries that get filtered out at subscribe-time.
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  bus.registerTopic("mail.scan.malware", {
    schema: { source: "string" }, tenantScope: true,
  });
  var threw = null;
  try { await bus.publish("mail.scan.malware", { source: "1.2.3.4" }, { actor: { id: "scan-agent" } }); }
  catch (e) { threw = e; }
  check("SUBSTRATE-6: publish refused for tenant-scoped topic with no tenantId",
    threw && (threw.code || "").indexOf("agent-event-bus/publish-denied") !== -1);
  // Publish with tenantId works.
  var r = await bus.publish("mail.scan.malware", { source: "1.2.3.4" },
    { actor: { id: "scan-agent", tenantId: "acme" } });
  check("SUBSTRATE-6: publish accepted with tenantId", r.topic === "mail.scan.malware");
}

async function testUnregisterTopic() {
  // SUBSTRATE-22 / BUG-12 — unregisterTopic exists; the kind filter
  // matches because register captures the kind.
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), requireMac: false });
  bus.registerTopic("mail.scan.A", { schema: { x: "string" } });
  bus.registerTopic("mail.scan.B", { schema: { y: "number" } });
  bus.registerTopic("ai.classify.C", { schema: { z: "boolean" } });
  var byMail = bus.listTopics({ kind: "mail" });
  check("BUG-12: kind filter matches", byMail.length === 2);
  var byAi = bus.listTopics({ kind: "ai" });
  check("BUG-12: kind filter narrows correctly", byAi.length === 1);

  bus.unregisterTopic("mail.scan.A");
  check("SUBSTRATE-22: unregister works", bus.listTopics({}).length === 2);
  // Re-register after unregister works (no topic-duplicate refusal).
  bus.registerTopic("mail.scan.A", { schema: { x: "string" } });
  check("SUBSTRATE-22: re-register after unregister", bus.listTopics({}).length === 3);
}

// ---- M6 — keyed-MAC envelope authentication (real vault) ----
//
// A pubsub-write attacker can set _tenantId to a victim's tenant + a
// schema-valid payload and forge a cross-tenant event; the tenant/schema
// checks prove SHAPE, not authenticity. The keyed MAC over the envelope's
// authority-bearing fields, verified at the consumer BEFORE the tenant
// check, refuses the forgery and any in-flight tamper. requireMac is on
// by default; these tests use the default with a real vault.

// A pubsub that captures the published envelope AND exposes the
// subscriber handler, so a test can deliver an arbitrary (forged /
// tampered) envelope directly to the consumer — exactly a pubsub-write
// attacker's capability.
function _capturingPubsub() {
  var handlers = new Map();
  var published = [];
  return {
    publish: async function (channel, envelope) {
      published.push({ channel: channel, envelope: envelope });
      (handlers.get(channel) || []).forEach(function (h) { h(envelope, { source: "fake" }); });
    },
    subscribe: async function (channel, handler) {
      var list = handlers.get(channel) || [];
      list.push(handler);
      handlers.set(channel, list);
      return function () {};
    },
    unsubscribe: function () {},
    // Test affordance: deliver an attacker-controlled envelope straight to
    // the consumer, bypassing publish() (the bus's own MAC mint).
    _deliver: function (channel, envelope) {
      (handlers.get(channel) || []).forEach(function (h) { h(envelope, { source: "attacker" }); });
    },
    _lastEnvelope: function () { return published.length ? published[published.length - 1].envelope : null; },
  };
}

async function testEnvelopeMacForgedRefused() {
  var tmpDir = _tmp();
  await helpers.setupVaultOnly(tmpDir);
  try {
    var pubsub = _capturingPubsub();
    var bus = b.agent.eventBus.create({ pubsub: pubsub });   // requireMac default ON
    bus.registerTopic("mail.tenant.event", { schema: { source: "string" }, tenantScope: true });
    var received = [];
    await bus.subscribe("mail.tenant.event", function (p) { received.push(p); }, {
      actor: { id: "victim", tenantId: "globex" },
    });
    // Attacker forges an envelope: victim's tenant, schema-valid payload,
    // NO valid MAC. Delivered straight onto the bus (pubsub-write access).
    pubsub._deliver("mail.tenant.event", {
      _topic:       "mail.tenant.event",
      _posture:     undefined,
      _tenantId:    "globex",                 // victim's tenant — forged
      _publishedAt: Date.now(),
      payload:      { source: "attacker-injected" },
      _mac:         "AAAA",                   // bogus MAC
    });
    await helpers.passiveObserve(25, "M6: forged envelope must NOT be delivered");
    check("forged cross-tenant envelope refused at consumer (MAC invalid)", received.length === 0);
  } finally {
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function testEnvelopeMacHonestDelivered() {
  var tmpDir = _tmp();
  await helpers.setupVaultOnly(tmpDir);
  try {
    var pubsub = _capturingPubsub();
    var bus = b.agent.eventBus.create({ pubsub: pubsub });
    bus.registerTopic("mail.tenant.event", { schema: { source: "string" }, tenantScope: true });
    var received = [];
    await bus.subscribe("mail.tenant.event", function (p) { received.push(p); }, {
      actor: { id: "u-acme", tenantId: "acme" },
    });
    // Honest publish through the bus — it mints a valid MAC.
    await bus.publish("mail.tenant.event", { source: "legit" }, {
      actor: { id: "p1", tenantId: "acme" },
    });
    await helpers.waitUntil(function () { return received.length >= 1; }, {
      timeoutMs: 5000, label: "M6: honestly-published event delivered",
    });
    check("honestly-published event delivered (valid MAC)", received.length === 1);
    check("honest event payload intact", received[0].source === "legit");
  } finally {
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function testEnvelopeMacTamperFails() {
  var tmpDir = _tmp();
  await helpers.setupVaultOnly(tmpDir);
  try {
    var pubsub = _capturingPubsub();
    var bus = b.agent.eventBus.create({ pubsub: pubsub });
    bus.registerTopic("mail.scan.event", { schema: { source: "string" }, posture: "soc2" });
    var receivedTopic = [];
    await bus.subscribe("mail.scan.event", function (p) { receivedTopic.push(p); });

    // Capture a genuine envelope, then tamper each authority field and
    // re-deliver — every tamper must fail the MAC.
    await bus.publish("mail.scan.event", { source: "ok" }, { actor: { id: "p1" } });
    await helpers.waitUntil(function () { return receivedTopic.length >= 1; }, {
      timeoutMs: 5000, label: "M6: baseline honest delivery",
    });
    var genuine = pubsub._lastEnvelope();
    check("baseline honest envelope carries a MAC", typeof genuine._mac === "string" && genuine._mac.length > 0);

    function _clone(env) { return JSON.parse(JSON.stringify(env)); }

    // Tamper _posture (posture downgrade attempt).
    var gotPosture = [];
    await bus.subscribe("mail.scan.event", function (p) { gotPosture.push(p); });
    var tPosture = _clone(genuine); tPosture._posture = "none"; tPosture.payload = { source: "ok" };
    pubsub._deliver("mail.scan.event", tPosture);

    // Tamper _topic.
    var tTopic = _clone(genuine); tTopic._topic = "mail.scan.event"; tTopic.payload = { source: "ok" };
    tTopic._tenantId = "injected";   // change a signed field
    pubsub._deliver("mail.scan.event", tTopic);

    // Tamper payload.
    var tPayload = _clone(genuine); tPayload.payload = { source: "tampered" };
    pubsub._deliver("mail.scan.event", tPayload);

    await helpers.passiveObserve(40, "M6: tampered envelopes must NOT reach the second subscriber");
    check("tampered _posture / _tenantId / payload all fail the MAC (none delivered)",
          gotPosture.length === 0);
  } finally {
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function testCrossTopicReplayDropped() {
  // A genuinely-MAC'd envelope for topic A, replayed verbatim onto topic B's
  // channel, must NOT be delivered to B's handler — even when A and B share
  // a schema + tenant. The MAC binds _topic=A (so it cannot be forged), but
  // the subscriber must additionally bind the authenticated _topic to the
  // channel it was registered for.
  var tmpDir = _tmp();
  await helpers.setupVaultOnly(tmpDir);
  try {
    var pubsub = _capturingPubsub();
    var bus = b.agent.eventBus.create({ pubsub: pubsub });
    bus.registerTopic("mail.scan.alpha", { schema: { source: "string" }, posture: "soc2" });
    bus.registerTopic("mail.scan.beta", { schema: { source: "string" }, posture: "soc2" });
    var gotA = [], gotB = [];
    await bus.subscribe("mail.scan.alpha", function (p) { gotA.push(p); });
    await bus.subscribe("mail.scan.beta", function (p) { gotB.push(p); });

    await bus.publish("mail.scan.alpha", { source: "from-a" }, { actor: { id: "p1" } });
    await helpers.waitUntil(function () { return gotA.length >= 1; }, {
      timeoutMs: 5000, label: "cross-topic: baseline A delivery",
    });
    var genuineA = pubsub._lastEnvelope();
    check("genuine A envelope carries _topic=mail.scan.alpha + a MAC",
          genuineA._topic === "mail.scan.alpha" && typeof genuineA._mac === "string");

    // Replay the verbatim, MAC-valid A envelope onto B's channel.
    pubsub._deliver("mail.scan.beta", JSON.parse(JSON.stringify(genuineA)));
    await helpers.passiveObserve(40, "cross-topic: A-event replayed onto B must NOT reach B's handler");
    check("cross-topic replay (A envelope on B channel) is dropped", gotB.length === 0);
    check("the legitimate A subscriber still got exactly its one event", gotA.length === 1);
  } finally {
    helpers.teardownVaultOnly(tmpDir);
  }
}

async function testEnvelopeMacPublishFailsClosedWithoutVault() {
  // requireMac default ON + no vault → publish refuses (fail-closed)
  // rather than emitting an unauthenticatable envelope.
  b.vault._resetForTest();
  if (b.agent.postureChain && b.agent.postureChain._resetForTest) b.agent.postureChain._resetForTest();
  var bus = b.agent.eventBus.create({ pubsub: _capturingPubsub() });
  bus.registerTopic("mail.scan.noVault", { schema: { source: "string" } });
  var threw = null;
  try { await bus.publish("mail.scan.noVault", { source: "x" }, { actor: { id: "p1" } }); }
  catch (e) { threw = e; }
  check("publish fails closed when no MAC key (requireMac default)",
        threw && (threw.code || "").indexOf("agent-event-bus/envelope-mac-unavailable") !== -1);
}

async function run() {
  testSurface();
  await testRegisterPublishSubscribe();
  await testUnknownTopic();
  await testDuplicateTopic();
  await testBadTopicShape();
  await testSchemaValidation();
  await testPermissions();
  await testTenantScope();
  await testTenantScopeRefusesSubscriberWithoutTenantId();
  await testPublishRefusesUntenantedOnTenantTopic();
  await testAsyncHandlerErrors();
  await testRefusesBadOpts();
  await testListTopics();
  await testUnregisterTopic();
  // M6 — keyed-MAC envelope authentication (real vault). The no-vault
  // fail-closed test runs LAST (it tears the vault down).
  await testEnvelopeMacForgedRefused();
  await testEnvelopeMacHonestDelivered();
  await testEnvelopeMacTamperFails();
  await testCrossTopicReplayDropped();
  await testEnvelopeMacPublishFailsClosedWithoutVault();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

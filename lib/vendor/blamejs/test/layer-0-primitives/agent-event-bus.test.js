"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

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
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub() });
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
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub() });
  await expectRejection("publish refuses unknown topic",
    bus.publish("mail.unknown.event", {}),
    "agent-event-bus/unknown-topic");
  await expectRejection("subscribe refuses unknown topic",
    bus.subscribe("mail.unknown.event", function () {}),
    "agent-event-bus/unknown-topic");
}

async function testDuplicateTopic() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub() });
  bus.registerTopic("mail.a.b", { schema: { x: "string" } });
  var threw = null;
  try { bus.registerTopic("mail.a.b", { schema: { x: "string" } }); }
  catch (e) { threw = e; }
  check("refuses duplicate topic",
    threw && (threw.code || "").indexOf("agent-event-bus/topic-duplicate") !== -1);
}

async function testBadTopicShape() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub() });
  var threw = null;
  try { bus.registerTopic("malware", { schema: { x: "string" } }); }
  catch (e) { threw = e; }
  check("refuses topic without enough dots",
    threw && (threw.code || "").indexOf("event-bus-topic/insufficient-dots") !== -1);
}

async function testSchemaValidation() {
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub() });
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
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub(), permissions: perms });
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
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub() });
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
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub() });
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
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub() });
  bus.registerTopic("mail.async.event", { schema: { x: "string" } });
  var crashed = false;
  var origHandler = process.listeners("unhandledRejection").slice();
  process.removeAllListeners("unhandledRejection");
  process.once("unhandledRejection", function () { crashed = true; });
  await bus.subscribe("mail.async.event", async function () {
    throw new Error("async-boom");
  });
  await bus.publish("mail.async.event", { x: "data" });
  await new Promise(function (r) { setTimeout(r, 25); });
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
  var bus = b.agent.eventBus.create({ pubsub: _fakePubsub() });
  bus.registerTopic("mail.a.b", { schema: { x: "string" }, posture: "soc2" });
  bus.registerTopic("mail.c.d", { schema: { y: "number" } });
  var list = bus.listTopics({});
  check("listTopics: 2 entries", list.length === 2);
  check("listTopics: name present", list[0].name === "mail.a.b" || list[1].name === "mail.a.b");
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
  await testAsyncHandlerErrors();
  await testRefusesBadOpts();
  await testListTopics();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

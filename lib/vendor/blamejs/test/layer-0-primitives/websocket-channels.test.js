"use strict";
/**
 * websocket-channels — channel/room hub layered over lib/websocket.js.
 *
 * Run standalone: `node test/layer-0-primitives/websocket-channels.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var EventEmitter = require("node:events").EventEmitter;
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _waitMicrotasks(n) {
  var p = Promise.resolve();
  for (var i = 0; i < (n || 5); i++) p = p.then(function () { return new Promise(function (r) { setImmediate(r); }); });
  return p;
}

function _waitMs(ms) {
  return new Promise(function (r) { setTimeout(r, ms); });
}

// Minimal connection mock — EventEmitter with .send() that captures
// what was sent. Mirrors the WebSocketConnection surface that
// websocket-channels actually touches (.send + .on('close')).
function _fakeConn() {
  var ee = new EventEmitter();
  ee.sent = [];
  ee.send = function (msg) { ee.sent.push(msg); };
  ee.dead = false;
  ee.killSend = function () { ee.send = function () { throw new Error("conn closed"); }; };
  return ee;
}

async function testSurface() {
  check("b.websocketChannels exposed",           typeof b.websocketChannels === "object");
  check("b.websocketChannels.create is fn",      typeof b.websocketChannels.create === "function");
  check("WebSocketChannelsError is a class",     typeof b.websocketChannels.WebSocketChannelsError === "function");
}

async function testLocalBackendSubscribePublish() {
  var hub = b.websocketChannels.create();
  check("default backend is 'local'",            hub.backend === "local");

  var a = _fakeConn();
  var b1 = _fakeConn();
  hub.attach(a);
  hub.attach(b1);
  hub.subscribe(a, "room:1");
  hub.subscribe(b1, "room:1");

  var result = await hub.publish("room:1", { user: "alice", text: "hi" });
  check("publish returns localDelivered=2",      result.localDelivered === 2);
  check("publish returns remoteSent=false",      result.remoteSent === false);
  check("subscriber a received message",         a.sent.length === 1);
  check("subscriber b received message",         b1.sent.length === 1);
  var parsed = JSON.parse(a.sent[0]);
  check("message has channel + payload shape",   parsed.channel === "room:1" && parsed.payload.user === "alice");
}

async function testIndependentChannels() {
  var hub = b.websocketChannels.create();
  var a = _fakeConn();
  var b1 = _fakeConn();
  hub.attach(a);
  hub.attach(b1);
  hub.subscribe(a, "room:1");
  hub.subscribe(b1, "room:2");

  await hub.publish("room:1", { msg: "a" });
  await hub.publish("room:2", { msg: "b" });

  check("a got room:1 only",                     a.sent.length === 1);
  check("b got room:2 only",                     b1.sent.length === 1);
  check("a received 'a' payload",                JSON.parse(a.sent[0]).payload.msg === "a");
  check("b received 'b' payload",                JSON.parse(b1.sent[0]).payload.msg === "b");
}

async function testUnsubscribe() {
  var hub = b.websocketChannels.create();
  var a = _fakeConn();
  hub.attach(a);
  hub.subscribe(a, "room:1");
  hub.unsubscribe(a, "room:1");
  await hub.publish("room:1", { msg: "x" });
  check("unsubscribed conn receives nothing",    a.sent.length === 0);
  check("channels() drops empty channel",        hub.channels().indexOf("room:1") === -1);
}

async function testAutoDetachOnClose() {
  var hub = b.websocketChannels.create();
  var a = _fakeConn();
  hub.attach(a);
  hub.subscribe(a, "room:1");
  check("attached count = 1",                    hub.attachedCount() === 1);
  check("connectionChannels reflects sub",       hub.connectionChannels(a)[0] === "room:1");

  a.emit("close");
  check("attached count = 0 after close",        hub.attachedCount() === 0);
  check("channel cleared after auto-detach",     hub.channels().indexOf("room:1") === -1);

  // Re-attach with a different conn — independent of the closed one
  var b1 = _fakeConn();
  hub.attach(b1);
  hub.subscribe(b1, "room:1");
  await hub.publish("room:1", { msg: "y" });
  check("dead conn doesn't receive (gone)",      a.sent.length === 0);
  check("new conn receives",                     b1.sent.length === 1);
}

async function testDeadSendDoesNotBreakDispatch() {
  var hub = b.websocketChannels.create();
  var a = _fakeConn();
  var b1 = _fakeConn();
  var c = _fakeConn();
  hub.attach(a);
  hub.attach(b1);
  hub.attach(c);
  hub.subscribe(a, "room:1");
  hub.subscribe(b1, "room:1");
  hub.subscribe(c, "room:1");
  // b1 has gone dead but hasn't emitted close yet — its send throws.
  b1.killSend();

  var result = await hub.publish("room:1", { msg: "fan" });
  check("a received despite b dead",              a.sent.length === 1);
  check("c received despite b dead",              c.sent.length === 1);
  // localDelivered counts only successful sends.
  check("localDelivered counts surviving sends",  result.localDelivered === 2);
}

async function testSubscribeRequiresAttach() {
  var hub = b.websocketChannels.create();
  var a = _fakeConn();
  var threw = null;
  try { hub.subscribe(a, "x"); } catch (e) { threw = e; }
  check("subscribe before attach throws",         threw && threw.code === "NOT_ATTACHED");
}

async function testInvalidChannelRejected() {
  var hub = b.websocketChannels.create();
  var a = _fakeConn();
  hub.attach(a);
  var threw = null;
  try { hub.subscribe(a, ""); } catch (e) { threw = e; }
  check("empty channel rejected on subscribe",    threw && threw.code === "INVALID_CHANNEL");
  threw = null;
  try { await hub.publish("", {}); } catch (e) { threw = e; }
  check("empty channel rejected on publish",      threw && threw.code === "INVALID_CHANNEL");
}

async function testNonSerializablePayloadRejected() {
  var hub = b.websocketChannels.create();
  var a = _fakeConn();
  hub.attach(a);
  hub.subscribe(a, "room:1");
  var circular = {};
  circular.self = circular;
  var threw = null;
  try { await hub.publish("room:1", circular); } catch (e) { threw = e; }
  check("circular payload rejected",              threw && threw.code === "INVALID_PAYLOAD");
}

async function testClusterBackendFanOut() {
  // Two hubs sharing the same DB simulate two cluster nodes. A
  // publish on hub A is observed by hub B's poll loop and dispatched
  // to B's local subscribers.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-wsch-"));
  try {
    await setupTestDb(tmpDir);

    var nodeAClusterMock = {
      currentNodeId: function () { return "node-A"; },
      isLeader:      function () { return true; },
    };
    var nodeBClusterMock = {
      currentNodeId: function () { return "node-B"; },
      isLeader:      function () { return false; },
    };

    var hubA = b.websocketChannels.create({
      backend:        "cluster",
      cluster:        nodeAClusterMock,
      pollIntervalMs: 30,
    });
    var hubB = b.websocketChannels.create({
      backend:        "cluster",
      cluster:        nodeBClusterMock,
      pollIntervalMs: 30,
    });

    // Wait for both nodes' first poll to prime lastSeenId past any
    // existing rows from prior tests.
    await _waitMs(80);

    var subA = _fakeConn();
    var subB = _fakeConn();
    hubA.attach(subA); hubA.subscribe(subA, "room:1");
    hubB.attach(subB); hubB.subscribe(subB, "room:1");

    var result = await hubA.publish("room:1", { from: "A" });
    check("publish returned remoteSent=true",       result.remoteSent === true);
    check("A subscriber received locally",          subA.sent.length === 1);

    // Poll on hub B picks up the row and dispatches.
    await _waitMs(150);
    check("B subscriber received via fan-out",      subB.sent.length === 1);
    check("B got the same payload",                 JSON.parse(subB.sent[0]).payload.from === "A");

    // Reverse direction: B publishes, A picks it up.
    await hubB.publish("room:1", { from: "B" });
    await _waitMs(150);
    check("A picks up B's publish",                 subA.sent.length === 2);

    // Self-publish doesn't double-deliver (publishedBy=self filter).
    var selfBefore = subA.sent.length;
    await hubA.publish("room:1", { from: "A2" });
    await _waitMs(150);
    check("A's own publish only delivered locally", subA.sent.length === selfBefore + 1);

    hubA.close();
    hubB.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testCustomBackend() {
  // Operator wires a Redis-shaped backend (or any other pubsub).
  var remoteBus = []; // captures published messages
  var custom = {
    publishRemote: function (channel, payload) {
      remoteBus.push({ channel: channel, payload: payload });
      return Promise.resolve();
    },
    start: function (onRemoteMessage) {
      // Custom backend would normally connect to Redis here. For the
      // test we just record that start() got called and store the
      // dispatch function for later injection.
      custom._dispatch = onRemoteMessage;
    },
    stop: function () { /* nothing */ },
  };

  var hub = b.websocketChannels.create({ backend: custom });
  check("custom backend reports name='custom'",   hub.backend === "custom");
  var a = _fakeConn();
  hub.attach(a);
  hub.subscribe(a, "room:1");

  await hub.publish("room:1", { from: "self" });
  check("custom backend received publishRemote",  remoteBus.length === 1);
  check("custom publishRemote got channel",       remoteBus[0].channel === "room:1");

  // Simulate a remote message arriving from another node via the
  // custom transport's onRemoteMessage callback.
  custom._dispatch("room:1", { from: "remote-node" });
  check("custom remote dispatch reaches sub",     a.sent.length === 2);
  check("custom remote payload preserved",        JSON.parse(a.sent[1]).payload.from === "remote-node");

  hub.close();
}

async function testUnknownBackendRejected() {
  var threw = null;
  try { b.websocketChannels.create({ backend: "made-up-backend" }); } catch (e) { threw = e; }
  check("unknown backend rejected at create()",
        threw && threw.code === "UNKNOWN_BACKEND");
}

async function testAuditEmit() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-wsch-"));
  try {
    await setupTestDb(tmpDir);
    var hub = b.websocketChannels.create({ audit: true });
    var a = _fakeConn();
    hub.attach(a);
    hub.subscribe(a, "room:1");
    await hub.publish("room:1", { msg: "audited" });

    await b.audit.flush();
    var rows = await b.audit.query({ action: "system.ws.publish" });
    check("audit row written for publish",         rows.length === 1);
    var meta = typeof rows[0].metadata === "string"
      ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("audit metadata carries channel",        meta.channel === "room:1");
    check("audit metadata carries localDelivered", meta.localDelivered === 1);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testMultipleSubscriptionsPerConn() {
  var hub = b.websocketChannels.create();
  var a = _fakeConn();
  hub.attach(a);
  hub.subscribe(a, "room:1");
  hub.subscribe(a, "room:2");
  hub.subscribe(a, "presence:user-1");

  check("connectionChannels lists 3",            hub.connectionChannels(a).length === 3);
  await hub.publish("room:1", { x: 1 });
  await hub.publish("room:2", { x: 2 });
  await hub.publish("presence:user-1", { x: 3 });
  check("conn received from all 3 channels",    a.sent.length === 3);

  // Detach should clear all of them.
  hub.detach(a);
  await hub.publish("room:1", { x: 999 });
  check("after detach, no further dispatch",    a.sent.length === 3);
  check("channels() empty after sole conn detached", hub.channels().length === 0);
}

async function testCloseClearsSubscriptions() {
  var hub = b.websocketChannels.create();
  var a = _fakeConn();
  var b1 = _fakeConn();
  hub.attach(a); hub.attach(b1);
  hub.subscribe(a, "x"); hub.subscribe(b1, "y");
  check("attachedCount = 2 before close",        hub.attachedCount() === 2);
  hub.close();
  check("attachedCount = 0 after close",         hub.attachedCount() === 0);
  check("channels() empty after close",          hub.channels().length === 0);
}

async function run() {
  await testSurface();
  await testLocalBackendSubscribePublish();
  await testIndependentChannels();
  await testUnsubscribe();
  await testAutoDetachOnClose();
  await testDeadSendDoesNotBreakDispatch();
  await testSubscribeRequiresAttach();
  await testInvalidChannelRejected();
  await testNonSerializablePayloadRejected();
  await testCustomBackend();
  await testUnknownBackendRejected();
  await testMultipleSubscriptionsPerConn();
  await testCloseClearsSubscriptions();
  await testAuditEmit();
  await testClusterBackendFanOut();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}

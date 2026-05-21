"use strict";
/**
 * pubsub primitive — local + cluster backends.
 *
 * The redis backend is exercised in test/integration/pubsub.test.js
 * against the docker redis container; this file covers the pieces a
 * pure smoke-suite can hit without external services.
 */
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var { setupTestDb, teardownTestDb } = require("../helpers/db");

async function testSurface() {
  check("b.pubsub exposed",        typeof b.pubsub === "object");
  check("b.pubsub.create is fn",   typeof b.pubsub.create === "function");
  check("PubsubError class",       typeof b.pubsub.PubsubError === "function");
}

async function testLocalSubscribePublish() {
  var ps = b.pubsub.create();
  check("default backend is 'local'", ps.backend() === "local");

  var seen = [];
  var token = ps.subscribe("user:42", function (payload, ev) {
    seen.push({ payload: payload, ev: ev });
  });

  var rv = await ps.publish("user:42", { tag: "delete" });
  check("publish reports local=1", rv.local === 1);
  check("publish reports remote=0 on local backend", rv.remote === 0);
  check("subscriber received payload", seen.length === 1 && seen[0].payload.tag === "delete");
  check("event meta carries channel", seen[0].ev.channel === "user:42");
  check("event meta carries source='local'", seen[0].ev.source === "local");

  ps.unsubscribe(token);
  await ps.publish("user:42", { tag: "noop" });
  check("post-unsubscribe: no further dispatch", seen.length === 1);

  await ps.close();
}

async function testMultipleSubscribersPerChannel() {
  var ps = b.pubsub.create();
  var aSeen = 0, bSeen = 0;
  var ta = ps.subscribe("c1", function () { aSeen++; });
  var tb = ps.subscribe("c1", function () { bSeen++; });

  await ps.publish("c1", { x: 1 });
  check("both subscribers received",   aSeen === 1 && bSeen === 1);

  ps.unsubscribe(ta);
  await ps.publish("c1", { x: 2 });
  check("after unsubscribe a only b receives", aSeen === 1 && bSeen === 2);

  ps.unsubscribe(tb);
  await ps.close();
}

async function testHandlerErrorIsolation() {
  var ps = b.pubsub.create();
  var bSeen = 0;
  ps.subscribe("c1", function () { throw new Error("boom"); });
  ps.subscribe("c1", function () { bSeen++; });

  // The throwing handler must not block dispatch to the other one.
  await ps.publish("c1", null);
  check("throwing handler did not block dispatch", bSeen === 1);
  await ps.close();
}

async function testTopicPrefixIsolation() {
  // Two pubsub instances with different topicPrefix values should NOT
  // exchange messages even on the same backend.
  var psA = b.pubsub.create({ topicPrefix: "ns-a" });
  var psB = b.pubsub.create({ topicPrefix: "ns-b" });
  var aSeen = 0, bSeen = 0;
  psA.subscribe("shared", function () { aSeen++; });
  psB.subscribe("shared", function () { bSeen++; });

  await psA.publish("shared", null);
  check("A's subscribe sees A's publish", aSeen === 1);
  check("B is isolated by topicPrefix",   bSeen === 0);

  await psA.close();
  await psB.close();
}

async function testPatternSubscribe() {
  var ps = b.pubsub.create();
  var hits = [];
  ps.subscribePattern("user:*", function (_payload, ev) {
    hits.push(ev.channel);
  });

  await ps.publish("user:42", null);
  await ps.publish("user:99", null);
  await ps.publish("post:1",  null);
  check("pattern matched user:42", hits.indexOf("user:42") !== -1);
  check("pattern matched user:99", hits.indexOf("user:99") !== -1);
  check("pattern did NOT match post:1", hits.indexOf("post:1") === -1);

  await ps.close();
}

async function testClusterFanOut() {
  // Two pubsub instances sharing the same cluster DB simulate two
  // nodes. A publish on instance A is observed by instance B's poll
  // and dispatched to its local subscriber.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-pubsub-"));
  try {
    await setupTestDb(tmpDir);

    var nodeA = { currentNodeId: function () { return "node-A"; } };
    var nodeB = { currentNodeId: function () { return "node-B"; } };

    var psA = b.pubsub.create({ backend: "cluster", cluster: nodeA, pollIntervalMs: 30 });
    var psB = b.pubsub.create({ backend: "cluster", cluster: nodeB, pollIntervalMs: 30 });

    // Wait for both nodes' first poll cycle (pollIntervalMs=30) to
    // prime lastSeenId past any existing rows. Real-time observation;
    // the prime is internal and not externally observable.
    await helpers.passiveObserve(80, "pubsub-cluster: both nodes' first poll cycle primed lastSeenId");

    var bSeen = [];
    psB.subscribe("c1", function (p) { bSeen.push(p); });

    var rv = await psA.publish("c1", { from: "A" });
    check("cluster publishRemote remote count >= 1", rv.remote >= 1);

    // Poll on B picks up the row.
    await helpers.waitUntil(function () {
      return bSeen.length >= 1 && bSeen[0].from === "A";
    }, { label: "pubsub-cluster: B observed A's publish via fan-out" });
    check("B observed A's publish via fan-out", bSeen.length === 1 && bSeen[0].from === "A");

    // Self-poll filter — A's own publish doesn't loop back to A's
    // local handlers via the polling path (publishedBy=self filter).
    var aSeen = [];
    psA.subscribe("c1", function (p) { aSeen.push(p); });
    await psA.publish("c1", { from: "A2" });
    check("A's local handler dispatched synchronously", aSeen.length === 1);
    // Verify A's poll cycle does NOT redeliver its own row (passive
    // observation — looking for ABSENCE of an event).
    await helpers.passiveObserve(150, "pubsub-cluster: A's poll did NOT redeliver own row");
    check("A's poll did NOT redeliver own row", aSeen.length === 1);

    await psA.close();
    await psB.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClosedRejectsPublishSubscribe() {
  var ps = b.pubsub.create();
  await ps.close();

  var threwSubscribe = null;
  try { ps.subscribe("c", function () {}); }
  catch (e) { threwSubscribe = e; }
  check("subscribe after close throws",
        threwSubscribe && threwSubscribe.code === "CLOSED");

  var threwPublish = null;
  try { await ps.publish("c", null); }
  catch (e) { threwPublish = e; }
  check("publish after close throws",
        threwPublish && threwPublish.code === "CLOSED");
}

async function testCacheInvalidationFanOut() {
  // Two memory-backed cache instances on different "namespaces sharing
  // the same name", connected via a shared local-backend pubsub. A
  // tag invalidation on one should propagate to the other locally.
  var ps = b.pubsub.create();
  var c1 = b.cache.create({
    namespace: "shared",
    backend:   "memory",
    invalidationPubsub: ps,
  });
  var c2 = b.cache.create({
    namespace: "shared",
    backend:   "memory",
    invalidationPubsub: ps,
  });

  await c1.set("k1", "v1", { tags: ["t-a"] });
  await c2.set("k1", "v1", { tags: ["t-a"] });
  check("c1 has k1 before invalidate",  await c1.has("k1"));
  check("c2 has k1 before invalidate",  await c2.has("k1"));

  await c1.invalidateTag("t-a");
  // Local sync dispatch — c2 already received the invalidation via
  // the same-process pubsub by the time invalidateTag resolved.
  check("c1 lost k1 after own invalidateTag", !(await c1.has("k1")));
  check("c2 lost k1 via pubsub fan-out",      !(await c2.has("k1")));

  // del() also fans out.
  await c1.set("k2", "v2");
  await c2.set("k2", "v2");
  await c1.del("k2");
  check("c2 lost k2 via pubsub fan-out",      !(await c2.has("k2")));

  await c1.close();
  await c2.close();
  await ps.close();
}

async function run() {
  await testSurface();
  await testLocalSubscribePublish();
  await testMultipleSubscribersPerChannel();
  await testHandlerErrorIsolation();
  await testTopicPrefixIsolation();
  await testPatternSubscribe();
  await testClosedRejectsPublishSubscribe();
  await testClusterFanOut();
  await testCacheInvalidationFanOut();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[pubsub] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

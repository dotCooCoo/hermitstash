// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

// pubsub caps channel names at 1 KiB (lib/pubsub.js _MAX_CHANNEL_LEN).
var C_KIB = 1024;

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

async function testClusterNumericConfigValidation() {
  // pollIntervalMs / retentionMs / pruneEveryMs are config-time numeric
  // knobs on the cluster backend. A typo (NaN-coercing string / negative /
  // fractional) must THROW at create rather than silently coercing to the
  // default and shipping a mis-tuned poll loop. The throw happens before
  // any DB is touched, so no test-db setup is needed.
  var nodeA = { currentNodeId: function () { return "node-A"; } };
  function shouldThrow(label, overrides) {
    var threw = null;
    try {
      b.pubsub.create(Object.assign(
        { backend: "cluster", cluster: nodeA }, overrides));
    } catch (e) { threw = e; }
    check("cluster-config: " + label,
          threw && (threw.code === "BAD_OPT" || /BAD_OPT/.test(threw.code || "")));
  }

  shouldThrow("rejects NaN-coercing pollIntervalMs", { pollIntervalMs: "30ms" });
  shouldThrow("rejects negative pollIntervalMs", { pollIntervalMs: -1 });
  shouldThrow("rejects fractional pollIntervalMs", { pollIntervalMs: 1.5 });
  shouldThrow("rejects zero pollIntervalMs", { pollIntervalMs: 0 });
  shouldThrow("rejects NaN-coercing retentionMs", { retentionMs: "1m" });
  shouldThrow("rejects negative retentionMs", { retentionMs: -100 });
  shouldThrow("rejects NaN-coercing pruneEveryMs", { pruneEveryMs: {} });
  shouldThrow("rejects negative pruneEveryMs", { pruneEveryMs: -5 });

  // Absent keeps the default — create succeeds (returns a live instance).
  var ok = null;
  try {
    ok = b.pubsub.create({ backend: "cluster", cluster: nodeA });
  } catch (e) { ok = e; }
  check("cluster-config: absent numeric knobs keep defaults",
        ok && typeof ok.publish === "function");
  if (ok && typeof ok.close === "function") { await ok.close(); }

  // Valid positive integers flow through.
  var ok2 = null;
  try {
    ok2 = b.pubsub.create({
      backend: "cluster", cluster: nodeA,
      pollIntervalMs: 50, retentionMs: 120000, pruneEveryMs: 300000,
    });
  } catch (e) { ok2 = e; }
  check("cluster-config: valid numeric knobs accepted",
        ok2 && typeof ok2.publish === "function");
  if (ok2 && typeof ok2.close === "function") { await ok2.close(); }
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

// A minimal in-process custom backend implementing the documented
// { publishRemote, start, stop } contract (plus optional subscribeRemote
// / unsubscribeRemote). It captures the remote-message callback so the
// test can inject cross-node deliveries, and records every remote call so
// ref-counting and scoping are observable. No external broker involved.
function makeCaptureBackend(cfg) {
  cfg = cfg || {};
  var state = {
    started: false, stopped: false, onRemote: null,
    published: [], subscribed: [], unsubscribed: [],
  };
  var backend = {
    start: function (onRemote) { state.started = true; state.onRemote = onRemote; },
    stop:  function () { state.stopped = true; },
    publishRemote: async function (scopedChannel, payload) {
      if (cfg.throwOnPublish) throw new Error("publishRemote boom");
      state.published.push({ channel: scopedChannel, payload: payload });
      return cfg.publishRemoteReturn;
    },
    subscribeRemote: async function (scopedChannel, isPattern) {
      if (cfg.throwOnSubscribe) throw new Error("subscribeRemote boom");
      state.subscribed.push({ channel: scopedChannel, isPattern: isPattern });
    },
    unsubscribeRemote: async function (scopedChannel, isPattern) {
      state.unsubscribed.push({ channel: scopedChannel, isPattern: isPattern });
    },
  };
  return { backend: backend, state: state };
}

async function testSingleSegmentPatternMatchesDottedChannel() {
  // The flagship documented pattern: '*' matches ONE '.'-delimited
  // segment inside a dotted channel. Driven through the real
  // subscribePattern → publish consumer path, not just the matcher.
  var ps = b.pubsub.create();
  var hits = [];
  ps.subscribePattern("orders.*.created", function (_p, ev) { hits.push(ev.channel); });
  ps.subscribePattern("a.*.b.*.c",        function (_p, ev) { hits.push(ev.channel); });

  await ps.publish("orders.eu.created", null);       // must match (one segment)
  await ps.publish("orders.eu.us.created", null);    // must NOT (two segments)
  await ps.publish("a.X.b.Y.c", null);               // two single-segment wildcards
  check("single-* pattern matches dotted channel",  hits.indexOf("orders.eu.created") !== -1);
  check("single-* pattern rejects two-segment span", hits.indexOf("orders.eu.us.created") === -1);
  check("multi single-* pattern matches",            hits.indexOf("a.X.b.Y.c") !== -1);
  await ps.close();
}

async function testMatcherEdgeBranches() {
  var ps = b.pubsub.create();
  var m = ps._matchPatternForTest;
  check("exact equality without wildcard matches", m("a.b.c", "a.b.c") === true);
  check("no-wildcard non-equal pattern rejects",   m("a.b.c", "a.b.d") === false);
  check("'**' suffix matches any tail",            m("audit.**", "audit.x.y.z") === true);
  check("empty middle segment matches '*'",        m("x.*.y", "x..y") === true);
  check("non-string channel rejected",             m("a.*", 12345) === false);

  // Channel/pattern length bound (1 KiB) short-circuits to false.
  var huge = "a".repeat(C_KIB + 8);
  check("over-length channel rejected", m("a*", huge) === false);
  check("over-length pattern rejected", m(huge + "*", "short") === false);
  await ps.close();
}

async function testInputValidation() {
  var ps = b.pubsub.create();
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }

  check("subscribe non-string channel throws BAD_OPT",
        (threw(function () { ps.subscribe(42, function () {}); }) || {}).code === "BAD_OPT");
  check("subscribe empty channel throws BAD_OPT",
        (threw(function () { ps.subscribe("", function () {}); }) || {}).code === "BAD_OPT");
  check("subscribe non-function handler throws BAD_OPT",
        (threw(function () { ps.subscribe("c", "nope"); }) || {}).code === "BAD_OPT");
  check("subscribePattern empty pattern throws BAD_OPT",
        (threw(function () { ps.subscribePattern("", function () {}); }) || {}).code === "BAD_OPT");
  check("subscribePattern non-function handler throws BAD_OPT",
        (threw(function () { ps.subscribePattern("a.*", 7); }) || {}).code === "BAD_OPT");

  var pubErr = null;
  try { await ps.publish(null, {}); } catch (e) { pubErr = e; }
  check("publish non-string channel throws BAD_OPT", pubErr && pubErr.code === "BAD_OPT");
  var pubErr2 = null;
  try { await ps.publish("", {}); } catch (e) { pubErr2 = e; }
  check("publish empty channel throws BAD_OPT", pubErr2 && pubErr2.code === "BAD_OPT");
  await ps.close();
}

async function testPatternHandlerErrorIsolation() {
  // A throwing PATTERN handler must not abort dispatch to sibling
  // handlers (exact or pattern) for the same channel.
  var ps = b.pubsub.create();
  var exactSeen = 0, patternSeen = 0;
  ps.subscribePattern("c.*", function () { throw new Error("pattern boom"); });
  ps.subscribePattern("c.*", function () { patternSeen++; });
  ps.subscribe("c.x", function () { exactSeen++; });

  await ps.publish("c.x", null);
  check("throwing pattern handler did not block sibling pattern", patternSeen === 1);
  check("throwing pattern handler did not block exact handler",   exactSeen === 1);
  await ps.close();
}

async function testUnsubscribeEdgeCases() {
  var ps = b.pubsub.create();
  // No-op branches: falsy / non-object / unknown token.
  ps.unsubscribe(null);
  ps.unsubscribe(undefined);
  ps.unsubscribe("not-an-object");
  ps.unsubscribe({ channel: "ghost", isPattern: false });   // never subscribed
  check("unsubscribe garbage tokens are safe no-ops", ps._state().exactChannels === 0);

  var seen = 0;
  var pat = ps.subscribePattern("p.*", function () { seen++; });
  check("pattern subscribe reflected in _state", ps._state().patternCount === 1);
  ps.unsubscribe(pat);
  ps.unsubscribe(pat);   // double-unsubscribe: second is a no-op
  await ps.publish("p.x", null);
  check("pattern unsubscribe stops dispatch", seen === 0);
  check("pattern unsubscribe clears _state",  ps._state().patternCount === 0);

  var seen2 = 0;
  var ex = ps.subscribe("e1", function () { seen2++; });
  check("exact channel present in _state", ps._state().exactChannels === 1);
  ps.unsubscribe(ex);
  check("last-handler unsubscribe drops the channel map entry", ps._state().exactChannels === 0);
  await ps.publish("e1", null);
  check("exact unsubscribe stops dispatch", seen2 === 0);
  await ps.close();
}

async function testBackendResolution() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }
  check("unknown backend string throws UNKNOWN_BACKEND",
        (threw(function () { b.pubsub.create({ backend: "bogus" }); }) || {}).code === "UNKNOWN_BACKEND");
  check("custom backend missing methods throws BAD_BACKEND",
        (threw(function () { b.pubsub.create({ backend: { publishRemote: function () {} } }); }) || {}).code === "BAD_BACKEND");

  var cap = makeCaptureBackend();
  var ps = b.pubsub.create({ backend: cap.backend });
  check("custom backend name is 'custom'", ps.backend() === "custom");
  check("custom backend start() invoked with remote callback",
        cap.state.started === true && typeof cap.state.onRemote === "function");
  await ps.close();
  check("custom backend stop() invoked on close", cap.state.stopped === true);
}

async function testCustomBackendPublishRemote() {
  // remote count derives from publishRemote's return: {remote:N} → N;
  // anything non-{remote:finite} → 1.
  async function remoteCountFor(ret) {
    var cap = makeCaptureBackend({ publishRemoteReturn: ret });
    var ps = b.pubsub.create({ backend: cap.backend });
    var seenLocal = 0;
    ps.subscribe("c1", function () { seenLocal++; });
    var rv = await ps.publish("c1", { k: 1 });
    check("local dispatch happens regardless of backend", seenLocal === 1 && rv.local === 1);
    check("publishRemote received the (scoped) channel + payload",
          cap.state.published.length === 1 &&
          cap.state.published[0].channel === "c1" &&
          cap.state.published[0].payload.k === 1);
    await ps.close();
    return rv.remote;
  }
  check("remote count from {remote:3}", (await remoteCountFor({ remote: 3 })) === 3);
  check("remote count defaults to 1 on undefined return", (await remoteCountFor(undefined)) === 1);
  check("remote count defaults to 1 on non-object return", (await remoteCountFor("nope")) === 1);
  check("remote count defaults to 1 on {remote:NaN}", (await remoteCountFor({ remote: NaN })) === 1);
}

async function testCustomBackendPublishRemoteThrows() {
  var cap = makeCaptureBackend({ throwOnPublish: true });
  var ps = b.pubsub.create({ backend: cap.backend, audit: true });
  var seen = 0;
  ps.subscribe("c1", function () { seen++; });
  var err = null;
  try { await ps.publish("c1", { k: 1 }); } catch (e) { err = e; }
  check("publish rejects when publishRemote throws", err && /publishRemote boom/.test(err.message));
  check("local dispatch still ran before the remote failure", seen === 1);
  await ps.close();
}

async function testTopicPrefixScopingAndRemoteInbound() {
  var cap = makeCaptureBackend({ publishRemoteReturn: { remote: 1 } });
  var ps = b.pubsub.create({ backend: cap.backend, topicPrefix: "svc" });
  var seen = [];
  ps.subscribe("orders", function (payload, ev) { seen.push({ p: payload, ev: ev }); });

  await ps.publish("orders", { id: 1 });
  check("publishRemote gets the topic-prefixed channel",
        cap.state.published.length === 1 && cap.state.published[0].channel === "svc:orders");

  // Inbound remote deliveries via the captured callback (scoped channel).
  cap.state.onRemote("svc:orders", JSON.stringify({ id: 2 }), {});
  cap.state.onRemote("svc:orders", Buffer.from(JSON.stringify({ id: 3 }), "utf8"), {});
  cap.state.onRemote("svc:orders", { id: 4 }, {});         // object passthrough
  check("remote string payload parsed + unscoped + dispatched",
        seen.length === 4 && seen[1].p.id === 2 && seen[1].ev.channel === "orders");
  check("remote source tagged 'remote'", seen[1].ev.source === "remote");
  check("remote Buffer payload parsed", seen[2].p.id === 3);
  check("remote object payload passed through", seen[3].p.id === 4);

  // Malformed remote JSON drops silently — no dispatch, no throw.
  cap.state.onRemote("svc:orders", "{not-valid-json", {});
  check("malformed remote payload dropped silently", seen.length === 4);
  await ps.close();
}

async function testRemotePatternDelivery() {
  var cap = makeCaptureBackend();
  var ps = b.pubsub.create({ backend: cap.backend });
  var hits = [];
  ps.subscribePattern("orders.*.created", function (_p, ev) { hits.push(ev.channel); });
  cap.state.onRemote("orders.eu.created", JSON.stringify({ id: 1 }), {});
  check("remote message dispatches to matching pattern handler",
        hits.length === 1 && hits[0] === "orders.eu.created");
  await ps.close();
}

async function testRemoteRefCounting() {
  var cap = makeCaptureBackend();
  var ps = b.pubsub.create({ backend: cap.backend });
  var t1 = ps.subscribe("c1", function () {});
  var t2 = ps.subscribe("c1", function () {});
  // subscribeRemote is fire-and-forget; only the FIRST local handler for a
  // scoped channel triggers a single remote subscribe.
  await helpers.waitUntil(function () { return cap.state.subscribed.length >= 1; },
    { label: "pubsub: first subscribe triggers one remote subscribeRemote" });
  check("only one remote subscribe for two local handlers",
        cap.state.subscribed.length === 1 && cap.state.subscribed[0].channel === "c1");

  ps.unsubscribe(t1);
  check("remote unsubscribe not yet called while a handler remains",
        cap.state.unsubscribed.length === 0);
  ps.unsubscribe(t2);
  await helpers.waitUntil(function () { return cap.state.unsubscribed.length >= 1; },
    { label: "pubsub: last unsubscribe triggers one remote unsubscribeRemote" });
  check("remote unsubscribe fires when last local handler goes away",
        cap.state.unsubscribed.length === 1 && cap.state.unsubscribed[0].channel === "c1");
  await ps.close();
}

async function testSubscribeRemoteFailureSwallowed() {
  // A rejecting subscribeRemote must not surface synchronously from
  // subscribe(); local dispatch keeps working.
  var cap = makeCaptureBackend({ throwOnSubscribe: true });
  var ps = b.pubsub.create({ backend: cap.backend });
  var seen = 0;
  var err = null;
  try { ps.subscribe("c1", function () { seen++; }); } catch (e) { err = e; }
  check("subscribe does not throw when subscribeRemote rejects", err === null);
  await ps.publish("c1", null);
  check("local dispatch still works after remote-subscribe failure", seen === 1);
  await ps.close();
}

async function testCloseIdempotentAndState() {
  var cap = makeCaptureBackend();
  var ps = b.pubsub.create({ backend: cap.backend });
  ps.subscribe("c1", function () {});
  ps.subscribePattern("p.*", function () {});
  var st = ps._state();
  check("_state reports backend name", st.backend === "custom");
  check("_state reports exact + pattern counts", st.exactChannels === 1 && st.patternCount === 1);
  check("_state reports not-closed", st.closed === false);

  await ps.close();
  await ps.close();   // idempotent — second close is a no-op, no throw
  check("_state reports closed after close", ps._state().closed === true);
  check("close cleared subscription maps", ps._state().exactChannels === 0 && ps._state().patternCount === 0);

  var perr = null;
  try { await ps.publish("c1", null); } catch (e) { perr = e; }
  check("publish after close throws CLOSED", perr && perr.code === "CLOSED");
  var serr = null;
  try { ps.subscribePattern("x.*", function () {}); } catch (e) { serr = e; }
  check("subscribePattern after close throws CLOSED", serr && serr.code === "CLOSED");
}

async function run() {
  await testSurface();
  await testLocalSubscribePublish();
  await testMultipleSubscribersPerChannel();
  await testHandlerErrorIsolation();
  await testTopicPrefixIsolation();
  await testPatternSubscribe();
  await testSingleSegmentPatternMatchesDottedChannel();
  await testMatcherEdgeBranches();
  await testInputValidation();
  await testPatternHandlerErrorIsolation();
  await testUnsubscribeEdgeCases();
  await testBackendResolution();
  await testCustomBackendPublishRemote();
  await testCustomBackendPublishRemoteThrows();
  await testTopicPrefixScopingAndRemoteInbound();
  await testRemotePatternDelivery();
  await testRemoteRefCounting();
  await testSubscribeRemoteFailureSwallowed();
  await testCloseIdempotentAndState();
  await testClosedRejectsPublishSubscribe();
  await testClusterNumericConfigValidation();
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live pubsub redis-backend test against the docker redis-plain
 * instance (port 6379). Exercises:
 *   - SUBSCRIBE / PUBLISH round-trip via lib/redis-client.js's new
 *     setOnPushMessage demultiplexer
 *   - PSUBSCRIBE pattern matching
 *   - Cross-instance fan-out (two pubsub instances on the same
 *     connection see each other's publishes)
 *   - close() teardown of both subscriber and publisher connections
 *   - Cache invalidationPubsub on the redis backend
 */
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

async function run() {
  var redisSvc = await services.requireService("redis");
  if (!redisSvc.ok) throw new Error("redis unreachable: " + redisSvc.reason);

  // ---- single-instance subscribe/publish round-trip ----
  var ps = b.pubsub.create({ backend: "redis", redisUrl: "redis://127.0.0.1:6379/0" });
  check("backend reports redis",        ps.backend() === "redis");

  var seen = [];
  ps.subscribe("integration:user:42", function (payload, ev) {
    seen.push({ payload: payload, ev: ev });
  });
  // PSUBSCRIBE pattern
  var patHits = [];
  ps.subscribePattern("integration:order:*", function (payload, ev) {
    patHits.push({ channel: ev.channel, payload: payload });
  });
  // SUBSCRIBE acks land asynchronously. Probe a DIFFERENT channel
  // (one with no subscribers in this test) until Redis returns a
  // PUBLISH response — that response means the dispatcher has finished
  // processing the prior SUBSCRIBE commands queued on the same
  // connection (Redis serializes per-connection). After the probe
  // resolves, the real `integration:user:42` SUBSCRIBE is active and
  // a SINGLE publish populates `seen` exactly once.
  await helpers.waitUntil(async function () {
    var probe = await ps.publish("integration:probe:warmup:" + Date.now(), {});
    return probe && typeof probe.remote === "number";
  }, { label: "pubsub: redis backend ready (SUBSCRIBE queue drained)" });
  var rv = await ps.publish("integration:user:42", { tag: "delete", id: 42 });
  check("publish remote count >= 1",   rv.remote >= 1);
  await helpers.waitUntil(function () {
    return seen.length >= 1 && seen[0].payload.id === 42;
  }, { label: "pubsub: subscriber received local dispatch" });
  // Same-instance publishes dispatch locally synchronously
  // (source='local'); the redis backend stamps a per-instance nonce
  // and skips the SUBSCRIBE-loopback to prevent double dispatch.
  // Cross-instance fan-out (source='remote') is exercised separately
  // below.
  check("subscriber received via local dispatch",
        seen.length === 1 && seen[0].payload.id === 42);
  check("event meta source === 'local' (own publish)",
        seen[0].ev.source === "local");

  // Pattern subscribe round-trip — also dispatches locally on
  // same-instance publish per the same dedup rule.
  await ps.publish("integration:order:99", { ok: true });
  await helpers.waitUntil(function () {
    return patHits.length >= 1 && patHits[0].channel === "integration:order:99";
  }, { label: "pubsub: PSUBSCRIBE pattern matched" });
  check("PSUBSCRIBE matched integration:order:99",
        patHits.length === 1 && patHits[0].channel === "integration:order:99");

  await ps.close();

  // ---- cross-instance fan-out ----
  var psA = b.pubsub.create({ backend: "redis", redisUrl: "redis://127.0.0.1:6379/0" });
  var psB = b.pubsub.create({ backend: "redis", redisUrl: "redis://127.0.0.1:6379/0" });
  var bSeen = [];
  psB.subscribe("crossnode", function (p) { bSeen.push(p); });
  // Wait for psB's SUBSCRIBE to be active by probing a no-subscriber
  // channel on the SAME connection (psB.publish to a different channel
  // resolves once psB's pending SUBSCRIBE has drained).
  await helpers.waitUntil(async function () {
    var probe = await psB.publish("crossnode:probe:" + Date.now(), {});
    return probe && typeof probe.remote === "number";
  }, { label: "pubsub crossnode: psB SUBSCRIBE drained" });
  await psA.publish("crossnode", { from: "A" });
  await helpers.waitUntil(function () {
    return bSeen.length >= 1 && bSeen[0].from === "A";
  }, { label: "pubsub crossnode: psB received psA's publish" });
  check("instance B received instance A's publish",
        bSeen.length === 1 && bSeen[0].from === "A");
  await psA.close();
  await psB.close();

  // ---- cache invalidation fan-out via redis pubsub ----
  // Two memory-backed cache instances on different processes (here
  // simulated as two cache.create calls in this process) fan out
  // tag invalidations to each other through redis PUB/SUB.
  var ips1 = b.pubsub.create({ backend: "redis", redisUrl: "redis://127.0.0.1:6379/0" });
  var ips2 = b.pubsub.create({ backend: "redis", redisUrl: "redis://127.0.0.1:6379/0" });
  var cA = b.cache.create({
    namespace: "redis-fanout-test",
    backend:   "memory",
    invalidationPubsub: ips1,
  });
  var cB = b.cache.create({
    namespace: "redis-fanout-test",
    backend:   "memory",
    invalidationPubsub: ips2,
  });

  await cA.set("u:1", "alice", { tags: ["t-user"] });
  await cB.set("u:1", "alice", { tags: ["t-user"] });
  check("cA has u:1", await cA.has("u:1"));
  check("cB has u:1", await cB.has("u:1"));

  // cache.create() issues cB's SUBSCRIBE on ips2 fire-and-forget; the
  // remote SUBSCRIBE drains asynchronously. Redis PUB/SUB has no
  // buffering for not-yet-subscribed channels — a single invalidateTag
  // published before cB's subscription is active on the server is lost
  // forever. Probe a no-subscriber channel on ips2's connection until
  // Redis answers PUBLISH; that ack means ips2's queued SUBSCRIBE has
  // drained and cB is registered for the invalidation channel. (Real
  // deploys subscribe at boot, long before invalidations flow; this
  // reproduces that steady state.)
  await helpers.waitUntil(async function () {
    var probe = await ips2.publish("cache:fanout:probe:" + Date.now(), {});
    return probe && typeof probe.remote === "number";
  }, { label: "cache fan-out: ips2 SUBSCRIBE drained (cB registered)" });

  await cA.invalidateTag("t-user");
  // The publish goes through redis; ips2 subscribes to the channel,
  // forwards to cB. Poll until cB has observed the eviction.
  await helpers.waitUntil(async function () {
    return !(await cB.has("u:1"));
  }, { label: "cache fan-out: cB evicted u:1 via redis pubsub" });
  check("cA evicted u:1 locally",          !(await cA.has("u:1")));
  check("cB evicted u:1 via redis fan-out", !(await cB.has("u:1")));

  await cA.close();
  await cB.close();
  await ips1.close();
  await ips2.close();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

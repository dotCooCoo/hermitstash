// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * observability — combined metrics + tracing tap.
 *
 * Run standalone: `node test/layer-0-primitives/observability.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b               = helpers.b;
var check           = helpers.check;
var makeFakeOtelApi = helpers.makeFakeOtelApi;

function _resetRegistries() {
  b.metrics._resetForTest();
  b.tracing._resetForTest();
}

function testObservabilitySurface() {
  check("b.observability is exposed",          typeof b.observability === "object");
  check("observability.tap is a function",     typeof b.observability.tap === "function");
  check("observability.event is a function",   typeof b.observability.event === "function");
}

function testObservabilityTapRunsFnWithoutRegistries() {
  _resetRegistries();
  var ran = false;
  var ret = b.observability.tap("smoke.test", { x: 1 }, function (span) {
    ran = true;
    return span;
  });
  check("tap: fn ran without registries",  ran === true);
  check("tap: span arg is null pass-through", ret === null);
}

function testObservabilityTapReturnsValue() {
  _resetRegistries();
  var v = b.observability.tap("smoke.test", function () { return 42; });
  check("tap: return value preserved (no attrs)", v === 42);
  var w = b.observability.tap("smoke.test", { k: "v" }, function () { return "ok"; });
  check("tap: return value preserved (with attrs)", w === "ok");
}

async function testObservabilityTapAsyncReturn() {
  _resetRegistries();
  var v = await b.observability.tap("smoke.test", function () {
    return Promise.resolve("async-ok");
  });
  check("tap: async return value preserved", v === "async-ok");
}

function testObservabilityTapMetricsFiresOnSuccess() {
  _resetRegistries();
  var m = b.metrics.create();
  b.observability.tap("audit.record",
    { action: "test.action", outcome: "success" },
    function () { return "ok"; });
  var auditCounter = m.metrics.get("framework_audit_events_total");
  check("tap: metrics fired on success path",
        auditCounter.get({ action: "test.action", outcome: "success" }) === 1);
  m.deactivate();
}

function testObservabilityTapMetricsFiresOnFailure() {
  _resetRegistries();
  var m = b.metrics.create();
  var threw = null;
  try {
    b.observability.tap("audit.record",
      { action: "test.action", outcome: "failure" },
      function () { throw new Error("boom"); });
  } catch (e) { threw = e; }
  check("tap: throw propagates after metrics fire", threw && threw.message === "boom");
  var auditCounter = m.metrics.get("framework_audit_events_total");
  check("tap: metrics fired on sync-throw failure path",
        auditCounter.get({ action: "test.action", outcome: "failure" }) === 1);
  m.deactivate();
}

async function testObservabilityTapMetricsFiresOnAsyncRejection() {
  _resetRegistries();
  var m = b.metrics.create();
  var threw = null;
  try {
    await b.observability.tap("audit.record",
      { action: "test.action", outcome: "failure" },
      function () { return Promise.reject(new Error("async-boom")); });
  } catch (e) { threw = e; }
  check("tap: rejection propagates after metrics fire",
        threw && threw.message === "async-boom");
  var auditCounter = m.metrics.get("framework_audit_events_total");
  check("tap: metrics fired on async-reject failure path",
        auditCounter.get({ action: "test.action", outcome: "failure" }) === 1);
  m.deactivate();
}

function testObservabilityTapTracingProducesSpan() {
  _resetRegistries();
  var fake = makeFakeOtelApi();
  b.tracing._setOtelForTest(fake);
  var t = b.tracing.create();
  b.observability.tap("smoke.span",
    { foo: "bar" },
    function () { return 1; });
  check("tap: tracing produced 1 span",          fake._spans.length === 1);
  check("tap: span name matches tap name",       fake._spans[0]._name === "smoke.span");
  check("tap: span attrs include passed attrs",  fake._spans[0]._attrs.foo === "bar");
  t.deactivate();
}

function testObservabilityEventRoutesIntoMetricsOnly() {
  _resetRegistries();
  var m = b.metrics.create();
  b.observability.event("queue.enqueue", 1, { queueName: "outbox" });
  var counter = m.metrics.get("framework_queue_enqueue_total");
  check("event: metrics counter incremented",
        counter.get({ queueName: "outbox" }) === 1);
  m.deactivate();
}

function testObservabilityEventNoOpWhenNoRegistry() {
  _resetRegistries();
  var threw = null;
  try { b.observability.event("anything", 1, { a: 1 }); }
  catch (e) { threw = e; }
  check("event: no-op without registry — no throw", threw === null);
}

function testObservabilityTapRejectsBadFn() {
  _resetRegistries();
  var threw = null;
  try { b.observability.tap("smoke", "not-a-function"); }
  catch (e) { threw = e; }
  check("tap: rejects non-function fn", threw && /must be a function/.test(threw.message));
}

function testObservabilityTapRejectsBadName() {
  _resetRegistries();
  var threwUndef = null;
  try { b.observability.tap(undefined, function () {}); }
  catch (e) { threwUndef = e; }
  check("tap: rejects undefined name (throws)",
        threwUndef instanceof TypeError && /name must be/.test(threwUndef.message));
  var threwEmpty = null;
  try { b.observability.tap("", function () {}); }
  catch (e) { threwEmpty = e; }
  check("tap: rejects empty-string name", threwEmpty instanceof TypeError);
  var threwNumeric = null;
  try { b.observability.tap(42, function () {}); }
  catch (e) { threwNumeric = e; }
  check("tap: rejects number name", threwNumeric instanceof TypeError);
}

function testObservabilityEventDropsBadName() {
  _resetRegistries();
  var m = b.metrics.create();
  var threw = null;
  try {
    b.observability.event(undefined, 1, { x: 1 });
    b.observability.event("", 1);
    b.observability.event(null);
  } catch (e) { threw = e; }
  check("event: silently drops malformed name", threw === null);
  m.deactivate();
}

function testObservabilitySemconvResourceAttributes() {
  var S = b.observability.SEMCONV;
  check("SEMCONV is frozen", Object.isFrozen(S));
  // Resource / general additions (OTel semconv).
  check("SEMCONV.PEER_SERVICE", S.PEER_SERVICE === "peer.service");
  check("SEMCONV.DEPLOYMENT_ENVIRONMENT_NAME",
        S.DEPLOYMENT_ENVIRONMENT_NAME === "deployment.environment.name");
  check("SEMCONV.TELEMETRY_DISTRO_NAME",
        S.TELEMETRY_DISTRO_NAME === "telemetry.distro.name");
  check("SEMCONV.TELEMETRY_DISTRO_VERSION",
        S.TELEMETRY_DISTRO_VERSION === "telemetry.distro.version");
  check("SEMCONV.OTEL_SCOPE_NAME", S.OTEL_SCOPE_NAME === "otel.scope.name");
  check("SEMCONV.OTEL_SCOPE_VERSION", S.OTEL_SCOPE_VERSION === "otel.scope.version");
  // FaaS (serverless).
  check("SEMCONV.FAAS_NAME", S.FAAS_NAME === "faas.name");
  check("SEMCONV.FAAS_VERSION", S.FAAS_VERSION === "faas.version");
  check("SEMCONV.FAAS_INSTANCE", S.FAAS_INSTANCE === "faas.instance");
  check("SEMCONV.FAAS_TRIGGER", S.FAAS_TRIGGER === "faas.trigger");
}

function testObservabilitySemconvK8sAttributes() {
  var S = b.observability.SEMCONV;
  // Pre-existing trio kept.
  check("SEMCONV.K8S_NAMESPACE_NAME", S.K8S_NAMESPACE_NAME === "k8s.namespace.name");
  check("SEMCONV.K8S_POD_NAME", S.K8S_POD_NAME === "k8s.pod.name");
  check("SEMCONV.K8S_DEPLOYMENT_NAME", S.K8S_DEPLOYMENT_NAME === "k8s.deployment.name");
  // New workload + node + cluster subset.
  check("SEMCONV.K8S_NODE_NAME", S.K8S_NODE_NAME === "k8s.node.name");
  check("SEMCONV.K8S_CLUSTER_NAME", S.K8S_CLUSTER_NAME === "k8s.cluster.name");
  check("SEMCONV.K8S_CONTAINER_NAME", S.K8S_CONTAINER_NAME === "k8s.container.name");
  check("SEMCONV.K8S_STATEFULSET_NAME", S.K8S_STATEFULSET_NAME === "k8s.statefulset.name");
  check("SEMCONV.K8S_DAEMONSET_NAME", S.K8S_DAEMONSET_NAME === "k8s.daemonset.name");
  check("SEMCONV.K8S_JOB_NAME", S.K8S_JOB_NAME === "k8s.job.name");
  check("SEMCONV.K8S_CRONJOB_NAME", S.K8S_CRONJOB_NAME === "k8s.cronjob.name");
  check("SEMCONV.K8S_REPLICASET_NAME", S.K8S_REPLICASET_NAME === "k8s.replicaset.name");
}

// b.observability.namespaced — the drop-silent prefixed metric emitter every
// primitive used to hand-roll as a private _emitMetric closure.
function testObservabilityNamespaced() {
  check("b.observability.namespaced is a function",
        typeof b.observability.namespaced === "function");
  var seen = [];
  var orig = b.observability.safeEvent;            // late-bound — the stub is observed
  b.observability.safeEvent = function (name, n, labels) {
    seen.push({ name: name, n: n, labels: labels });
  };
  try {
    var emit = b.observability.namespaced("network.byte_quota");
    emit("exceeded", 5, { key: "k" });
    emit("reset");                                 // value → 1, labels → {}
    var gated = b.observability.namespaced("middleware.tusUpload", false);
    gated("create.ok");                            // gateFlag false → no-op
  } finally {
    b.observability.safeEvent = orig;
  }
  check("namespaced prefixes the name + passes value/labels through",
        seen[0].name === "network.byte_quota.exceeded" && seen[0].n === 5 && seen[0].labels.key === "k");
  check("namespaced defaults value to 1 and labels to {}",
        seen[1].name === "network.byte_quota.reset" && seen[1].n === 1 &&
        JSON.stringify(seen[1].labels) === "{}");
  check("namespaced(prefix, false) is a no-op",
        !seen.some(function (e) { return e.name === "middleware.tusUpload.create.ok"; }));
}

// b.observability.makeCounterEmitter — the per-instance counter sibling of
// namespaced, every primitive used to hand-roll as a private _emitObs closure.
function testObservabilityMakeCounterEmitter() {
  check("b.observability.makeCounterEmitter is a function",
        typeof b.observability.makeCounterEmitter === "function");
  var sinkSeen = [];
  var sink = { event: function (name, value, labels) { sinkSeen.push({ name: name, value: value, labels: labels }); } };
  var emit = b.observability.makeCounterEmitter(sink);
  emit("auth.lockout.tripped", { actor: "alice" });
  check("makeCounterEmitter emits value 1 + name + labels to the sink",
        sinkSeen.length === 1 && sinkSeen[0].name === "auth.lockout.tripped" &&
        sinkSeen[0].value === 1 && sinkSeen[0].labels.actor === "alice");
  var threw = false;
  try { b.observability.makeCounterEmitter({ event: function () { throw new Error("sink down"); } })("x"); }
  catch (_e) { threw = true; }
  check("makeCounterEmitter is drop-silent on a sink throw", threw === false);
}

async function run() {
  testObservabilitySurface();
  testObservabilityTapRunsFnWithoutRegistries();
  testObservabilityTapReturnsValue();
  await testObservabilityTapAsyncReturn();
  testObservabilityTapMetricsFiresOnSuccess();
  testObservabilityTapMetricsFiresOnFailure();
  await testObservabilityTapMetricsFiresOnAsyncRejection();
  testObservabilityTapTracingProducesSpan();
  testObservabilityEventRoutesIntoMetricsOnly();
  testObservabilityEventNoOpWhenNoRegistry();
  testObservabilityTapRejectsBadFn();
  testObservabilityTapRejectsBadName();
  testObservabilityEventDropsBadName();
  testObservabilitySemconvResourceAttributes();
  testObservabilitySemconvK8sAttributes();
  testObservabilityNamespaced();
  testObservabilityMakeCounterEmitter();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("observability tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}

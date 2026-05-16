"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeTracing() {
  // Minimal tracing-shaped stub. startSpan returns a controllable span.
  return {
    startSpan: function (name) {
      var ended  = false;
      var status = null;
      var attrs  = {};
      return {
        name:         name,
        setAttribute: function (k, v) { attrs[k] = v; },
        setStatus:    function (s)    { status = s; },
        end:          function ()      { ended = true; },
        _isEnded:     function ()      { return ended; },
        _getStatus:   function ()      { return status; },
        _getAttrs:    function ()      { return attrs; },
      };
    },
    contextHeaders: function () {
      return {
        traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
      };
    },
  };
}

function expectThrows(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function testSurface() {
  check("create is fn",       typeof b.agent.trace.create === "function");
  check("AgentTraceError",    typeof b.agent.trace.AgentTraceError === "function");
  check("guards.context",     b.agent.trace.guards.context === b.guardTraceContext);
  var e = new b.agent.trace.AgentTraceError("agent-trace/test", "t");
  check("error carries code", e.code === "agent-trace/test");
}

async function testCreateRequiresTracing() {
  expectThrows("create refuses missing tracing",
    function () { b.agent.trace.create({}); },
    "agent-trace/bad-tracing");
}

async function testStartSpan() {
  var trace = b.agent.trace.create({ tracing: _fakeTracing() });
  var span = trace.startSpan("mail.agent.fetch", { actor: { id: "u1" } });
  check("startSpan: returns span object", span && span.name === "mail.agent.fetch");
}

async function testRecordResult() {
  var trace = b.agent.trace.create({ tracing: _fakeTracing() });
  var span = trace.startSpan("mail.agent.search");
  trace.recordResult(span, { rows: [] });
  check("recordResult: span ended on success",     span._isEnded());
  check("recordResult: status set OK",              span._getStatus() && span._getStatus().code === 1);

  var span2 = trace.startSpan("mail.agent.fetch");
  trace.recordResult(span2, null, new Error("boom"));
  check("recordResult: span ended on error",       span2._isEnded());
  check("recordResult: status set ERROR",           span2._getStatus() && span2._getStatus().code === 2);
}

async function testInjectExtract() {
  var trace = b.agent.trace.create({ tracing: _fakeTracing() });
  var envelope = { method: "send", args: {} };
  var withTrace = trace.injectIntoEnvelope(envelope, null);
  check("inject: traceparent injected",            withTrace._trace && withTrace._trace.traceparent.length === 55);

  var ctx = trace.extractFromEnvelope(withTrace);
  check("extract: traceparent extracted",          ctx.traceparent === withTrace._trace.traceparent);

  var noTrace = trace.extractFromEnvelope({});
  check("extract: no _trace returns null",         noTrace === null);

  expectThrows("extract refuses bad traceparent",
    function () { trace.extractFromEnvelope({ _trace: { traceparent: "bad" } }); },
    "agent-trace/bad-envelope-trace");
}

async function testShouldSample() {
  // sampleRate 1.0 → always true
  var alwaysTrace = b.agent.trace.create({ tracing: _fakeTracing(), sampleRate: 1.0 });
  check("sample 1.0: always true", alwaysTrace.shouldSample("any") === true);

  // sampleRate 0 → always false
  var neverTrace = b.agent.trace.create({ tracing: _fakeTracing(), sampleRate: 0 });
  check("sample 0: always false", neverTrace.shouldSample("any") === false);

  // perMethod override
  var perMethodTrace = b.agent.trace.create({
    tracing: _fakeTracing(),
    sampleRate: 0,                        // global never
    perMethod: { send: 1.0 },              // send always
  });
  check("perMethod override active", perMethodTrace.shouldSample("send") === true);
  check("perMethod fallback to global", perMethodTrace.shouldSample("other") === false);
}

async function testBadSampleRate() {
  expectThrows("refuses sampleRate > 1",
    function () { b.agent.trace.create({ tracing: _fakeTracing(), sampleRate: 1.5 }); },
    "agent-trace/bad-sample-rate");
  expectThrows("refuses negative sampleRate",
    function () { b.agent.trace.create({ tracing: _fakeTracing(), sampleRate: -0.1 }); },
    "agent-trace/bad-sample-rate");
}

async function testFormatAttributes() {
  var trace = b.agent.trace.create({ tracing: _fakeTracing() });
  var attrs = trace.formatAttributes({
    method:       "send",
    dispatchMode: "queue",
    tenantId:     "acme",
    postureSet:   ["hipaa", "pci-dss"],
    shard:        3,
    resultStatus: "success",
    elapsedMs:    42,
  });
  check("formatAttributes: method",       attrs["agent.method"] === "send");
  check("formatAttributes: dispatch_mode", attrs["agent.dispatch_mode"] === "queue");
  check("formatAttributes: tenant",        attrs["agent.tenant_id"] === "acme");
  check("formatAttributes: posture json", attrs["agent.posture"] === "[\"hipaa\",\"pci-dss\"]");
  check("formatAttributes: shard",        attrs["agent.shard"] === 3);
  check("formatAttributes: elapsed",       attrs["agent.elapsed_ms"] === 42);
}

async function run() {
  testSurface();
  await testCreateRequiresTracing();
  await testStartSpan();
  await testRecordResult();
  await testInjectExtract();
  await testShouldSample();
  await testBadSampleRate();
  await testFormatAttributes();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

"use strict";
/**
 * b.notify — generic notification dispatcher.
 *
 * Verifies notify composes existing primitives (b.retry, b.safeAsync,
 * b.observability, b.audit, b.httpClient, b.safeUrl, b.redact) instead
 * of re-implementing retry/timeout/breaker/redaction.
 *
 * Run standalone: `node test/layer-0-primitives/notify.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _mockReq  = helpers._mockReq;

// ---- Surface ----

function testSurface() {
  check("b.notify namespace present",         typeof b.notify === "object");
  check("b.notify.create is a function",      typeof b.notify.create === "function");
  check("b.notify.NotifyError class",         typeof b.notify.NotifyError === "function");
  check("b.notify.DEFAULTS frozen",           Object.isFrozen(b.notify.DEFAULTS));
  check("DEFAULTS.auditSuccess true",         b.notify.DEFAULTS.auditSuccess === true);
  check("DEFAULTS.auditFailures true",        b.notify.DEFAULTS.auditFailures === true);
  check("DEFAULTS.defaultTimeoutMs is positive",
        typeof b.notify.DEFAULTS.defaultTimeoutMs === "number" &&
        b.notify.DEFAULTS.defaultTimeoutMs > 0);
  check("transports.httpJson fn",             typeof b.notify.transports.httpJson === "function");
  check("transports.log fn",                  typeof b.notify.transports.log === "function");
  check("transports.test fn",                 typeof b.notify.transports.test === "function");

  var test = b.notify.transports.test();
  var n = b.notify.create({ channels: { test: test } });
  check("instance.send fn",                   typeof n.send === "function");
  check("instance.sendBatch fn",              typeof n.sendBatch === "function");
  check("instance.queue fn",                  typeof n.queue === "function");
  check("instance.addChannel fn",             typeof n.addChannel === "function");
  check("instance.channels fn",               typeof n.channels === "function");
  check("instance.transport fn",              typeof n.transport === "function");
  check("instance.channels() lists registered",
        n.channels().length === 1 && n.channels()[0] === "test");
}

// ---- Input validation (rejects bad opts at create time) ----

function testValidation() {
  var threwNoOpts = false;
  try { b.notify.create(); } catch (_e) { threwNoOpts = true; }
  check("create() with no opts throws",       threwNoOpts);

  var threwNoChannels = false;
  try { b.notify.create({}); } catch (_e) { threwNoChannels = true; }
  check("create() without channels throws",   threwNoChannels);

  var threwEmptyChannels = false;
  try { b.notify.create({ channels: {} }); } catch (_e) { threwEmptyChannels = true; }
  check("create() with empty channels throws", threwEmptyChannels);

  var threwBadTransport = false;
  try { b.notify.create({ channels: { x: { /* no send */ } } }); } catch (_e) { threwBadTransport = true; }
  check("create() with bad transport (no send fn) throws", threwBadTransport);

  var threwBadAudit = false;
  try {
    b.notify.create({
      channels: { x: { send: async function () {} } },
      audit:    { /* no safeEmit */ },
    });
  } catch (_e) { threwBadAudit = true; }
  check("create() with bad audit shape throws", threwBadAudit);

  var threwBadTimeout = false;
  try {
    b.notify.create({
      channels:         { x: { send: async function () {} } },
      defaultTimeoutMs: NaN,
    });
  } catch (_e) { threwBadTimeout = true; }
  check("create() with NaN defaultTimeoutMs throws", threwBadTimeout);

  // send() input validation
  var n = b.notify.create({ channels: { x: { send: async function () {} } } });

  var awaiters = [];
  awaiters.push(n.send().then(function () { return false; }, function () { return true; }));
  awaiters.push(n.send({ channel: "x" }).then(function () { return false; }, function () { return true; }));
  awaiters.push(n.send({ channel: "missing", message: {} }).then(function () { return false; }, function () { return true; }));

  return Promise.all(awaiters).then(function (results) {
    check("send() with no input rejects",       results[0] === true);
    check("send() without message rejects",     results[1] === true);
    check("send() with unknown channel rejects", results[2] === true);
  });
}

// ---- Basic send via test transport ----

async function testBasicSend() {
  var test = b.notify.transports.test();
  var n = b.notify.create({ channels: { dev: test } });
  var result = await n.send({ channel: "dev", message: { text: "hello" } });
  check("send returns delivered status",      result.status === "delivered");
  check("send returns channel echo",          result.channel === "dev");
  check("test transport captured exactly one", test.sent.length === 1);
  check("captured message preserved",         test.sent[0].message.text === "hello");
}

// ---- Multi-channel routing ----

async function testMultiChannelRouting() {
  var slack = b.notify.transports.test();
  var sms   = b.notify.transports.test();
  var n = b.notify.create({ channels: { slack: slack, sms: sms } });
  await n.send({ channel: "slack", message: { text: "to slack" } });
  await n.send({ channel: "sms",   message: { text: "to sms" } });
  check("slack channel got slack message",
        slack.sent.length === 1 && slack.sent[0].message.text === "to slack");
  check("sms channel got sms message",
        sms.sent.length === 1 && sms.sent[0].message.text === "to sms");
  check("slack didn't receive sms",           slack.sent.find(function (s) { return s.message.text === "to sms"; }) === undefined);
}

// ---- Retry composition (uses b.retry.withRetry) ----

async function testRetryViaBRetry() {
  var attempts = 0;
  var flakyTransport = {
    name: "flaky",
    send: async function () {
      attempts += 1;
      if (attempts < 3) {
        var err = new Error("transient 503");
        err.statusCode = 503;       // b.retry.RETRYABLE_HTTP_STATUS includes 503
        throw err;
      }
      return { status: "delivered" };
    },
  };
  var n = b.notify.create({
    channels: {
      flaky: {
        transport: flakyTransport,
        retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 },
      },
    },
  });
  var result = await n.send({ channel: "flaky", message: { x: 1 } });
  check("transient errors retried until success", attempts === 3);
  check("send eventually returns delivered",  result.status === "delivered");
}

async function testNonRetryablePermanent() {
  var attempts = 0;
  var permTransport = {
    name: "perm",
    send: async function () {
      attempts += 1;
      var err = new Error("forbidden");
      err.statusCode = 403;       // NON_RETRYABLE_HTTP_STATUS
      throw err;
    },
  };
  var n = b.notify.create({
    channels: {
      perm: {
        transport: permTransport,
        retry: { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 },
      },
    },
  });
  var threw = false;
  try { await n.send({ channel: "perm", message: { x: 1 } }); } catch (_e) { threw = true; }
  check("permanent error throws after one attempt (no retry)",
        threw && attempts === 1);
}

async function testRetryableNetError() {
  var attempts = 0;
  var transport = {
    name: "neterr",
    send: async function () {
      attempts += 1;
      if (attempts < 2) {
        var err = new Error("connection reset");
        err.code = "ECONNRESET";       // b.retry.RETRYABLE_NET_ERRORS includes this
        throw err;
      }
      return { status: "delivered" };
    },
  };
  var n = b.notify.create({
    channels: {
      neterr: {
        transport: transport,
        retry:     { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 },
      },
    },
  });
  await n.send({ channel: "neterr", message: { x: 1 } });
  check("ECONNRESET routed through retry as transient", attempts === 2);
}

// ---- Timeout via b.safeAsync.withTimeout ----

async function testTimeoutViaSafeAsync() {
  var transport = {
    name: "slow",
    send: function () {
      // Never resolves — only timeout will end the wait.
      return new Promise(function () {});
    },
  };
  var n = b.notify.create({
    channels: {
      slow: {
        transport: transport,
        timeoutMs: 30,
        retry:     { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 },
      },
    },
  });
  var threw = false;
  var startedAt = Date.now();
  try { await n.send({ channel: "slow", message: { x: 1 } }); } catch (_e) { threw = true; }
  var elapsed = Date.now() - startedAt;
  check("timeout fires within reasonable bound", threw && elapsed < 500);
}

async function testTimeoutZeroDisables() {
  var transport = {
    name: "fast",
    send: async function () {
      // Returns synchronously — even with 0ms timeout (which would fail
      // the safeAsync.withTimeout validator), the code path must NOT
      // call withTimeout.
      return { status: "delivered" };
    },
  };
  var n = b.notify.create({
    channels: {
      fast: {
        transport: transport,
        timeoutMs: 0,        // 0 disables the wrap
      },
    },
  });
  var result = await n.send({ channel: "fast", message: { x: 1 } });
  check("timeoutMs: 0 disables timeout (send completes)",
        result.status === "delivered");
}

// ---- Circuit breaker via b.retry.CircuitBreaker ----

async function testCircuitBreakerOpens() {
  var attempts = 0;
  var transport = {
    name: "broken",
    send: async function () {
      attempts += 1;
      var err = new Error("backend dead");
      err.statusCode = 503;
      throw err;
    },
  };
  // breaker trips after 2 consecutive failures (default is 5; tighten for test)
  var n = b.notify.create({
    channels: {
      broken: {
        transport: transport,
        retry:     { maxAttempts: 1, baseDelayMs: 1 },     // no retry inside the call
        breaker:   { failureThreshold: 2, cooldownMs: 1000, successThreshold: 1 },
      },
    },
  });
  // First two calls fail and feed the breaker
  var fails = 0;
  try { await n.send({ channel: "broken", message: { x: 1 } }); } catch (_e) { fails++; }
  try { await n.send({ channel: "broken", message: { x: 2 } }); } catch (_e) { fails++; }
  // Third call: breaker should be OPEN — fast-fail without invoking transport
  try { await n.send({ channel: "broken", message: { x: 3 } }); } catch (_e) { fails++; }
  check("first two fails reached transport",  attempts === 2);
  check("third fail short-circuited (breaker OPEN)", fails === 3);
}

// ---- Audit emission ----

async function testAuditSuccess() {
  var audit = b.testing.captureAudit();
  var test = b.notify.transports.test();
  var n = b.notify.create({
    channels: { test: test },
    audit:    audit,
  });
  var fakeReq = b.testing.mockReq({
    ip:        "10.0.0.5",
    userAgent: "tester/1.0",
    requestId: "req-42",
    method:    "POST",
    url:       "/admin/notify",
  });
  await n.send({ channel: "test", message: { text: "hi" }, req: fakeReq });
  var ev = audit.byAction("notify.send.success")[0];
  check("audit emits notify.send.success",    !!ev);
  check("audit carries 5 W's via extractActorContext",
        ev.actor.ip === "10.0.0.5" &&
        ev.actor.userAgent === "tester/1.0" &&
        ev.actor.requestId === "req-42" &&
        ev.actor.method === "POST" &&
        ev.actor.route === "/admin/notify");
  check("audit metadata names the channel",   ev.metadata.channel === "test");
  check("audit metadata records attempts",    ev.metadata.attempts === 1);
}

async function testAuditFailureWithCause() {
  var audit = b.testing.captureAudit();
  var transport = {
    name: "broken",
    send: async function () {
      var err = new Error("nope");
      err.statusCode = 401;       // permanent (NON_RETRYABLE_HTTP_STATUS)
      throw err;
    },
  };
  var n = b.notify.create({
    channels: { broken: { transport: transport, retry: { maxAttempts: 1 } } },
    audit:    audit,
  });
  try { await n.send({ channel: "broken", message: { x: 1 } }); } catch (_e) {}
  var ev = audit.byAction("notify.send.failure")[0];
  check("failure audit emitted",              !!ev);
  check("failure audit outcome=failure",      ev.outcome === "failure");
  check("failure audit captures cause message",
        ev.metadata.message_ === "nope");
}

async function testAuditOptOuts() {
  var audit = b.testing.captureAudit();
  var test = b.notify.transports.test();
  var n = b.notify.create({
    channels:     { test: test },
    audit:        audit,
    auditSuccess: false,
    auditFailures: false,
  });
  await n.send({ channel: "test", message: { x: 1 } });
  check("auditSuccess: false suppresses success audit",
        audit.captured.length === 0);

  // Even with auditFailures: false, observability still fires (just not the audit chain)
  var transport = {
    name: "broken",
    send: async function () { var e = new Error("x"); e.statusCode = 401; throw e; },
  };
  var n2 = b.notify.create({
    channels:     { x: { transport: transport, retry: { maxAttempts: 1 } } },
    audit:        audit,
    auditFailures: false,
  });
  try { await n2.send({ channel: "x", message: { y: 1 } }); } catch (_e) {}
  check("auditFailures: false suppresses failure audit",
        audit.byAction("notify.send.failure").length === 0);
}

// ---- Redaction via b.redact.redact ----

async function testRedactionViaBRedact() {
  var audit = b.testing.captureAudit();
  var test = b.notify.transports.test();
  var n = b.notify.create({
    channels: { test: test },
    audit:    audit,
  });
  await n.send({
    channel: "test",
    message: {
      text: "Reset link",
      // b.redact strips on field name patterns AND value detectors.
      // "password" is a sensitive field-name; the framework's existing
      // detectors strip its value from the audit metadata.
      password: "secret123",
    },
  });
  var ev = audit.byAction("notify.send.success")[0];
  check("audit metadata.message has password redacted (b.redact applied)",
        ev.metadata.message.password !== "secret123");
}

async function testCustomRedactor() {
  var audit = b.testing.captureAudit();
  var test = b.notify.transports.test();
  var n = b.notify.create({
    channels: { test: test },
    audit:    audit,
    redact:   function (m) { return { _scrubbed: true }; },
  });
  await n.send({ channel: "test", message: { secret: "x" } });
  var ev = audit.byAction("notify.send.success")[0];
  check("custom redact fn used in audit metadata",
        ev.metadata.message._scrubbed === true);
}

// ---- httpJson built-in transport ----

// Local _fakeHttpClient was the original copy of this pattern; v0.2.38
// consolidated it into b.testing.fakeHttpClient so every primitive's
// tests can share the same shape. Aliased here to keep call-sites
// unchanged while demonstrating the migration.
var _fakeHttpClient = b.testing.fakeHttpClient;

async function testHttpJsonBasic() {
  var hc = _fakeHttpClient(function () { return { statusCode: 200, body: Buffer.from("ok") }; });
  var transport = b.notify.transports.httpJson({
    url:        "https://hooks.example.com/webhook",
    httpClient: hc,
  });
  var n = b.notify.create({ channels: { hook: transport } });
  await n.send({ channel: "hook", message: { text: "hi" } });
  check("httpJson posts to URL via injected httpClient",
        hc.calls.length === 1 && hc.calls[0].url === "https://hooks.example.com/webhook");
  check("httpJson posts JSON body",
        hc.calls[0].method === "POST" && /"text":"hi"/.test(hc.calls[0].body));
  check("httpJson sets Content-Type: application/json",
        hc.calls[0].headers["Content-Type"] === "application/json");
}

async function testHttpJsonBadUrl() {
  var threw = false;
  try {
    b.notify.transports.httpJson({ url: "javascript:alert(1)" });
  } catch (_e) { threw = true; }
  check("httpJson rejects bad URL (safeUrl.parse fired)", threw);
}

async function testHttpJsonNon2xxRetryable() {
  var calls = 0;
  var hc = _fakeHttpClient(function () {
    calls++;
    if (calls < 3) return { statusCode: 429, body: Buffer.from("rate limited") };
    return { statusCode: 200, body: Buffer.from("ok") };
  });
  var transport = b.notify.transports.httpJson({
    url:        "https://hooks.example.com/webhook",
    httpClient: hc,
  });
  var n = b.notify.create({
    channels: {
      hook: {
        transport: transport,
        retry:     { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 },
      },
    },
  });
  await n.send({ channel: "hook", message: { x: 1 } });
  check("429 classified retryable via b.retry.isRetryable", calls === 3);
}

async function testHttpJsonNon2xxPermanent() {
  var calls = 0;
  var hc = _fakeHttpClient(function () {
    calls++;
    return { statusCode: 401, body: Buffer.from("unauthorized") };
  });
  var transport = b.notify.transports.httpJson({
    url:        "https://hooks.example.com/webhook",
    httpClient: hc,
  });
  var n = b.notify.create({
    channels: {
      hook: {
        transport: transport,
        retry:     { maxAttempts: 5, baseDelayMs: 1, maxDelayMs: 5, jitterFactor: 0 },
      },
    },
  });
  var threw = false;
  try { await n.send({ channel: "hook", message: { x: 1 } }); } catch (_e) { threw = true; }
  check("401 classified permanent (no retry)", threw && calls === 1);
}

async function testHttpJsonSigning() {
  var hc = _fakeHttpClient(function () { return { statusCode: 200, body: Buffer.from("ok") }; });
  var signing = {
    sign: function (body) {
      // Mimic webhook.signer header-shape output.
      return { headers: { "X-Signature": "sig-of-" + Buffer.from(body).length } };
    },
  };
  var transport = b.notify.transports.httpJson({
    url:        "https://hooks.example.com/webhook",
    httpClient: hc,
    signing:    signing,
  });
  var n = b.notify.create({ channels: { hook: transport } });
  await n.send({ channel: "hook", message: { x: 1 } });
  check("signing.sign output added as headers to httpJson request",
        /^sig-of-\d+$/.test(hc.calls[0].headers["X-Signature"] || ""));
}

// ---- log transport ----

async function testLogTransport() {
  var logged = [];
  var transport = b.notify.transports.log({
    logger: {
      info:  function (m) { logged.push({ level: "info",  msg: m }); },
      error: function (m) { logged.push({ level: "error", msg: m }); },
    },
  });
  var n = b.notify.create({ channels: { log: transport } });
  var r = await n.send({ channel: "log", message: { text: "dev info" } });
  check("log transport returns delivered",    r.status === "delivered");
  check("log transport invoked logger.info",  logged.length === 1 && logged[0].level === "info");
}

// ---- sendBatch ----

async function testSendBatch() {
  var test = b.notify.transports.test();
  var perm = {
    name: "perm",
    send: async function () { var e = new Error("nope"); e.statusCode = 401; throw e; },
  };
  var n = b.notify.create({
    channels: {
      ok:   test,
      bad:  { transport: perm, retry: { maxAttempts: 1 } },
    },
  });
  var results = await n.sendBatch([
    { channel: "ok",  message: { x: 1 } },
    { channel: "bad", message: { x: 2 } },
    { channel: "ok",  message: { x: 3 } },
  ]);
  check("sendBatch returns same-length array", results.length === 3);
  check("sendBatch ok results carry status",   results[0].status === "delivered" && results[2].status === "delivered");
  check("sendBatch one-failed-doesn't-fail-others",
        results[1] && results[1].isNotifyError === true);
  check("test transport saw the two ok inputs", test.sent.length === 2);
}

// ---- addChannel + duplicate ----

async function testAddChannel() {
  var test1 = b.notify.transports.test();
  var test2 = b.notify.transports.test();
  var n = b.notify.create({ channels: { a: test1 } });
  n.addChannel("b", test2);
  check("addChannel registers new channel",
        n.channels().indexOf("b") !== -1);
  await n.send({ channel: "b", message: { x: 1 } });
  check("addChannel: send routed to new transport", test2.sent.length === 1);

  var threw = false;
  try { n.addChannel("a", test1); } catch (_e) { threw = true; }
  check("addChannel: duplicate name throws",  threw);
}

// ---- Custom transport object form ----

async function testCustomTransportObject() {
  var calls = 0;
  var custom = {
    name: "custom",
    send: async function (message) {
      calls++;
      return { status: "delivered", id: "custom-" + calls };
    },
  };
  var n = b.notify.create({ channels: { custom: custom } });
  var r = await n.send({ channel: "custom", message: { x: 1 } });
  check("custom transport called",             calls === 1);
  check("custom transport id propagated",      r.id === "custom-1");
}

// ---- Observability via b.observability.tap (span+counter) ----

async function testObservabilityEmission() {
  var cap = b.testing.captureMetricsTap();
  try {
    var test = b.notify.transports.test();
    var n = b.notify.create({ channels: { test: test } });
    await n.send({ channel: "test", message: { x: 1 } });
  } finally {
    cap.restore();
  }
  check("emits notify.send (via observability.tap)",
        cap.byName("notify.send").length > 0);
  check("emits notify.send.attempt",
        cap.byName("notify.send.attempt").length > 0);
  check("emits notify.send.success",
        cap.byName("notify.send.success").length > 0);
  // The notify.send tap event should carry channel label
  var sendEvt = cap.byName("notify.send")[0];
  check("notify.send labels include channel",
        sendEvt && sendEvt.labels.channel === "test");
}

// ---- Queue integration ----

async function testQueueIntegration() {
  var enqueued = [];
  var fakeQueue = {
    enqueue: async function (queueName, payload) {
      enqueued.push({ queueName: queueName, payload: payload });
      return "job-" + enqueued.length;
    },
    registerHandler: function (_qn, _fn) { /* operator's worker */ },
  };
  var test = b.notify.transports.test();
  var n = b.notify.create({
    channels: { test: test },
    queue:    fakeQueue,
  });
  var r = await n.queue({ channel: "test", message: { text: "later" } });
  check("queue returned jobId",                r.jobId === "job-1");
  check("queue.enqueue called with queueName + payload",
        enqueued.length === 1 &&
        enqueued[0].queueName === "notify" &&
        enqueued[0].payload.channel === "test");
}

async function testQueueWithoutHandle() {
  var test = b.notify.transports.test();
  var n = b.notify.create({ channels: { test: test } });
  var threw = false;
  try {
    await n.queue({ channel: "test", message: { x: 1 } });
  } catch (e) {
    threw = (e && /NO_QUEUE/.test(e.code || ""));
  }
  check("queue() without queue handle throws NO_QUEUE", threw);
}

// ---- Serialize via b.safeAsync.Mutex ----

async function testSerializeMutex() {
  var inflight = 0;
  var maxInflight = 0;
  var transport = {
    name: "serial",
    send: async function () {
      inflight++;
      if (inflight > maxInflight) maxInflight = inflight;
      await helpers.passiveObserve(20, "notify-serialize: simulated transport latency");
      inflight--;
      return { status: "delivered" };
    },
  };
  var n = b.notify.create({
    channels: {
      s: { transport: transport, serialize: true },
    },
  });
  // Fire 3 sends concurrently — with serialize: true they should run one
  // at a time, so max inflight stays at 1.
  await Promise.all([
    n.send({ channel: "s", message: { x: 1 } }),
    n.send({ channel: "s", message: { x: 2 } }),
    n.send({ channel: "s", message: { x: 3 } }),
  ]);
  check("serialize: true serializes concurrent sends (max inflight === 1)",
        maxInflight === 1);
}

// ---- run ----

async function run() {
  testSurface();
  await testValidation();
  await testBasicSend();
  await testMultiChannelRouting();
  await testRetryViaBRetry();
  await testNonRetryablePermanent();
  await testRetryableNetError();
  await testTimeoutViaSafeAsync();
  await testTimeoutZeroDisables();
  await testCircuitBreakerOpens();
  await testAuditSuccess();
  await testAuditFailureWithCause();
  await testAuditOptOuts();
  await testRedactionViaBRedact();
  await testCustomRedactor();
  await testHttpJsonBasic();
  await testHttpJsonBadUrl();
  await testHttpJsonNon2xxRetryable();
  await testHttpJsonNon2xxPermanent();
  await testHttpJsonSigning();
  await testLogTransport();
  await testSendBatch();
  await testAddChannel();
  await testCustomTransportObject();
  await testObservabilityEmission();
  await testQueueIntegration();
  await testQueueWithoutHandle();
  await testSerializeMutex();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

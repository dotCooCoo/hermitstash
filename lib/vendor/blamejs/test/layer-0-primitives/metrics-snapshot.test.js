// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.metrics.snapshot — out-of-process metrics export for long-running
 * daemons. Writer flushes JSON snapshot atomically every N ms; CLI
 * reader parses + renders.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = require("node:fs");
var os      = require("node:os");
var path    = require("node:path");

function _scratchPath(label) {
  var d = fs.mkdtempSync(path.join(os.tmpdir(), "snap-" + label + "-"));
  return { dir: d, path: path.join(d, "metrics.json") };
}

function testSurface() {
  var s = b.metrics.snapshot;
  check("snapshot.startWriter is fn", typeof s.startWriter === "function");
  check("snapshot.read is fn",        typeof s.read === "function");
  check("snapshot.render is fn",      typeof s.render === "function");
}

function testWriterValidatesOpts() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("startWriter: missing path",
              function () { b.metrics.snapshot.startWriter({ intervalMs: 1000, fields: function () { return {}; } }); },
              "metrics-snapshot/bad-path");
  expectThrow("startWriter: bad interval",
              function () { b.metrics.snapshot.startWriter({ path: "/tmp/x", intervalMs: 50, fields: function () { return {}; } }); },
              "metrics-snapshot/bad-interval");
  expectThrow("startWriter: non-fn fields",
              function () { b.metrics.snapshot.startWriter({ path: "/tmp/x", intervalMs: 1000, fields: "not-fn" }); },
              "metrics-snapshot/bad-fields");
}

async function testWriterAndReader() {
  var fx = _scratchPath("rw");
  try {
    var calls = 0;
    var stop = b.metrics.snapshot.startWriter({
      path:       fx.path,
      intervalMs: 100,
      fields:     function () {
        calls += 1;
        return { uptimeMs: 12345, queueDepth: calls, name: "test" };
      },
    });
    // First flush is synchronous — file should exist right away.
    check("startWriter: file exists after sync first flush", fs.existsSync(fx.path));
    var snap1 = b.metrics.snapshot.read(fx.path);
    check("read: snap has writtenAt",        typeof snap1.writtenAt === "string");
    check("read: snap has fields object",    snap1.fields && typeof snap1.fields === "object");
    check("read: queueDepth carries through", snap1.fields.queueDepth === 1);
    check("read: uptimeMs carries through",  snap1.fields.uptimeMs === 12345);
    check("read: name carries through",      snap1.fields.name === "test");
    stop();
    check("startWriter: final-flush captured stop() count",
          b.metrics.snapshot.read(fx.path).fields.queueDepth >= 1);
  } finally {
    fs.rmSync(fx.dir, { recursive: true });
  }
}

function testReadRefusesBadInputs() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("read: missing file",
              function () { b.metrics.snapshot.read("/nonexistent/snap.json"); },
              "metrics-snapshot/not-found");

  var fx = _scratchPath("bad");
  try {
    fs.writeFileSync(fx.path, "not valid json");
    expectThrow("read: malformed JSON",
                function () { b.metrics.snapshot.read(fx.path); },
                "metrics-snapshot/bad-json");

    fs.writeFileSync(fx.path, '{"some": "shape"}');
    expectThrow("read: missing writtenAt/fields",
                function () { b.metrics.snapshot.read(fx.path); },
                "metrics-snapshot/bad-shape");
  } finally {
    fs.rmSync(fx.dir, { recursive: true });
  }
}

function testRenderText() {
  var snap = {
    writtenAt: "2026-05-13T00:00:00.000Z",
    fields:    { uptimeMs: 1000, count: 7, name: "hello" },
  };
  var out = b.metrics.snapshot.render(snap);
  check("render text: has writtenAt header", out.indexOf("snapshot written-at: 2026-05-13") !== -1);
  check("render text: sorted keys (count before name before uptimeMs)",
        out.indexOf("count: 7") < out.indexOf("name: hello") &&
        out.indexOf("name: hello") < out.indexOf("uptimeMs: 1000"));
}

function testRenderPrometheus() {
  var snap = {
    writtenAt: "2026-05-13T00:00:00.000Z",
    fields:    {
      uptimeMs:   1000,
      queueDepth: 7,
      name:       "hello",                // string — skipped
      bad_name:   1,                      // valid prom name
      "1bad":     1,                      // invalid prom name — skipped
      naninf:     Number.POSITIVE_INFINITY, // non-finite — skipped
    },
  };
  var out = b.metrics.snapshot.render(snap, { format: "prometheus", prefix: "myapp" });
  check("prom: contains uptimeMs gauge",
        out.indexOf("# TYPE myapp_uptimeMs gauge") !== -1 &&
        out.indexOf("myapp_uptimeMs 1000") !== -1);
  check("prom: contains queueDepth",
        out.indexOf("myapp_queueDepth 7") !== -1);
  // bad_name (valid prom name, number) is emitted as "myapp_bad_name 1" —
  // ensure the bare metric `myapp_name <value>` (from the string field) is
  // NOT present. Substring check on "name" would collide with "bad_name".
  check("prom: omits string field",
        out.indexOf("myapp_name ") === -1 && out.indexOf("# TYPE myapp_name ") === -1);
  check("prom: keeps valid bad_name field", out.indexOf("myapp_bad_name 1") !== -1);
  check("prom: omits invalid-name field", out.indexOf("myapp_1bad") === -1);
  check("prom: omits non-finite field",   out.indexOf("myapp_naninf") === -1);
}

function testRenderPrometheusFieldTypes() {
  var snap = {
    writtenAt: "2026-05-15T00:00:00.000Z",
    fields:    {
      // _total suffix → auto-detected as counter (Prometheus naming
      // convention + OpenMetrics 1.0.0 §6.2)
      http_requests_total: 42,
      bytes_sent_total:    9999,
      // no _total suffix → gauge
      queue_depth:         5,
      uptime_seconds:      120,
      // override target: gauge named with _total suffix
      ratio_total:         1,
      // override target: counter without conventional suffix
      events_seen:         7,
    },
  };
  var out = b.metrics.snapshot.render(snap, {
    format:     "prometheus",
    prefix:     "myapp",
    fieldTypes: {
      ratio_total: "gauge",     // override the auto-detected counter
      events_seen: "counter",   // override the auto-detected gauge
    },
  });
  check("prom: _total auto-detected as counter",
        out.indexOf("# TYPE myapp_http_requests_total counter") !== -1 &&
        out.indexOf("myapp_http_requests_total 42") !== -1);
  check("prom: another _total field also counter",
        out.indexOf("# TYPE myapp_bytes_sent_total counter") !== -1);
  check("prom: no-suffix is gauge",
        out.indexOf("# TYPE myapp_queue_depth gauge") !== -1 &&
        out.indexOf("myapp_queue_depth 5") !== -1);
  check("prom: another no-suffix is gauge",
        out.indexOf("# TYPE myapp_uptime_seconds gauge") !== -1);
  check("prom: override flips _total → gauge",
        out.indexOf("# TYPE myapp_ratio_total gauge") !== -1);
  check("prom: override flips no-suffix → counter",
        out.indexOf("# TYPE myapp_events_seen counter") !== -1);
}

async function testRenderLabeledRegistrySnapshot() {
  // Real consumer path: registry → startWriter(registry) file →
  // snapshot.read → snapshot.render. A sidecar that renders a snapshot
  // written by another process must get the labeled registry series —
  // with names identical to the live exposition() endpoint — without
  // re-implementing the exposition encoder (issue #430).
  var fx = _scratchPath("labeled");
  try {
    var registry = b.metrics.create();
    var c = registry.counter("http_requests_total", { help: "reqs", labelNames: ["route", "code"] });
    c.inc({ route: "/x", code: "200" }, 3);
    var g = registry.gauge("queue_depth", { help: "depth", labelNames: ["queue"] });
    g.set({ queue: "ma\"il\n" }, 5);   // hostile label value — must escape, never forge lines
    var h = registry.histogram("op_latency_seconds", { help: "lat", labelNames: ["op"], buckets: [0.01, 0.1, 1] });
    h.observe({ op: "read" }, 0.05);
    // Colon-named metric — valid per the registry's METRIC_NAME_RE and
    // emitted by the live exposition; the snapshot render must carry it
    // under the same name contract, not a stricter one.
    var rc = registry.counter("rpc:requests_total", { help: "rpc reqs", labelNames: ["method"] });
    rc.inc({ method: "get" }, 2);

    var stop = b.metrics.snapshot.startWriter({
      path:       fx.path,
      intervalMs: 100000,
      registry:   registry,
      fields:     function () { return { uptimeMs: 9 }; },
    });
    stop();
    var snap = b.metrics.snapshot.read(fx.path);
    check("labeled: snapshot carries metrics field", snap.metrics && typeof snap.metrics === "object");

    var out = b.metrics.snapshot.render(snap, { format: "prometheus", prefix: "myapp" });
    check("labeled prom: flat field still renders", out.indexOf("myapp_uptimeMs 9") !== -1);
    check("labeled prom: counter TYPE line", out.indexOf("# TYPE http_requests_total counter") !== -1);
    check("labeled prom: labeled counter sample",
          out.indexOf("http_requests_total{code=\"200\",route=\"/x\"} 3") !== -1);
    check("labeled prom: gauge label value escaped",
          out.indexOf("queue_depth{queue=\"ma\\\"il\\n\"} 5") !== -1);
    check("labeled prom: histogram bucket lines",
          out.indexOf("op_latency_seconds_bucket{le=\"0.1\",op=\"read\"} 1") !== -1 &&
          out.indexOf("op_latency_seconds_bucket{le=\"+Inf\",op=\"read\"} 1") !== -1);
    check("labeled prom: histogram sum and count",
          out.indexOf("op_latency_seconds_sum{op=\"read\"} 0.05") !== -1 &&
          out.indexOf("op_latency_seconds_count{op=\"read\"} 1") !== -1);
    check("labeled prom: colon-named family renders (live name contract)",
          out.indexOf("rpc:requests_total{method=\"get\"} 2") !== -1);

    // Indirect proof of the one-encoder contract: every sample line the
    // live exposition() emits for these families appears verbatim in the
    // snapshot render.
    var live = registry.exposition().split("\n").filter(function (l) {
      return l.indexOf("http_requests_total") === 0 ||
             l.indexOf("queue_depth") === 0 ||
             l.indexOf("op_latency_seconds") === 0 ||
             l.indexOf("rpc:requests_total") === 0;
    });
    var missing = live.filter(function (l) { return out.indexOf(l) === -1; });
    check("labeled prom: snapshot render carries every live-exposition sample line (" +
          live.length + " lines)", live.length >= 8 && missing.length === 0);

    // Text format renders the labeled series as name{label="value"} rows.
    var text = b.metrics.snapshot.render(snap);
    check("labeled text: labeled counter row",
          text.indexOf("http_requests_total{code=\"200\",route=\"/x\"}: 3") !== -1);
    check("labeled text: histogram count row",
          text.indexOf("op_latency_seconds_count{op=\"read\"}: 1") !== -1);

    // Garbage families in a hand-edited snapshot file must not forge
    // exposition lines: bad metric name skipped, bad label name dropped.
    var forged = {
      writtenAt: snap.writtenAt,
      fields:    {},
      metrics:   {
        "bad name\nfake_metric 1": { type: "gauge", help: "", labelNames: [],
                                     observations: [{ labels: {}, value: 1 }] },
        "ok_metric": { type: "gauge", help: "", labelNames: ["good", "bad name"],
                       observations: [{ labels: { good: "1", "bad name\n": "x" }, value: 2 }] },
      },
    };
    var fOut = b.metrics.snapshot.render(forged, { format: "prometheus" });
    check("labeled prom: forged metric name skipped", fOut.indexOf("fake_metric") === -1);
    check("labeled prom: forged label name dropped, metric survives",
          fOut.indexOf("ok_metric{good=\"1\"} 2") !== -1 && fOut.indexOf("bad name") === -1);
  } finally {
    fs.rmSync(fx.dir, { recursive: true });
  }
}

function testRenderBadInputs() {
  function expectThrow(label, fn, codeMatch) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
  }
  expectThrow("render: bad snap",
              function () { b.metrics.snapshot.render(null); },
              "metrics-snapshot/bad-snap");
  expectThrow("render: bad format",
              function () { b.metrics.snapshot.render({ writtenAt: "x", fields: {} }, { format: "yaml" }); },
              "metrics-snapshot/bad-format");
  expectThrow("render: prom bad prefix",
              function () { b.metrics.snapshot.render({ writtenAt: "x", fields: {} }, { format: "prometheus", prefix: "1bad" }); },
              "metrics-snapshot/bad-prefix");
  expectThrow("render: prom fieldTypes must be object",
              function () { b.metrics.snapshot.render({ writtenAt: "x", fields: { x: 1 } },
                { format: "prometheus", fieldTypes: "counter" }); },
              "metrics-snapshot/bad-field-types");
  expectThrow("render: prom fieldTypes rejects array",
              function () { b.metrics.snapshot.render({ writtenAt: "x", fields: { x: 1 } },
                { format: "prometheus", fieldTypes: ["counter"] }); },
              "metrics-snapshot/bad-field-types");
  expectThrow("render: prom fieldTypes value must be counter/gauge",
              function () { b.metrics.snapshot.render({ writtenAt: "x", fields: { x: 1 } },
                { format: "prometheus", fieldTypes: { x: "histogram" } }); },
              "metrics-snapshot/bad-field-type");
}

async function run() {
  testSurface();
  testWriterValidatesOpts();
  await testWriterAndReader();
  testReadRefusesBadInputs();
  testRenderPrometheusFieldTypes();
  testRenderText();
  testRenderPrometheus();
  await testRenderLabeledRegistrySnapshot();
  testRenderBadInputs();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

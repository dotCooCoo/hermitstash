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
}

async function run() {
  testSurface();
  testWriterValidatesOpts();
  await testWriterAndReader();
  testReadRefusesBadInputs();
  testRenderText();
  testRenderPrometheus();
  testRenderBadInputs();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("node:path");

var projectRoot = path.join(__dirname, "..", "..");
var logger = require(path.join(projectRoot, "app/shared/logger"));
var b = require(path.join(projectRoot, "lib/vendor/blamejs"));

// Capture stdout/stderr writes during fn, returning the parsed JSON lines.
function capture(stream, fn) {
  var lines = [];
  var orig = process[stream].write.bind(process[stream]);
  process[stream].write = function (s) {
    try { lines.push(JSON.parse(s)); } catch (e) { /* non-JSON boot noise */ }
    return true;
  };
  try { fn(); } finally { process[stream].write = orig; }
  return lines;
}

describe("app/shared/logger (b.log.create wrapper)", function () {
  it("exposes the stable wrapper surface", function () {
    ["debug", "info", "warn", "error", "fatal", "runWithRequestId", "getRequestId"].forEach(function (k) {
      assert.strictEqual(typeof logger[k], "function", k + " should be a function");
    });
  });

  it("emits a structured JSON line with level + message", function () {
    var lines = capture("stdout", function () { logger.info("hello", { component: "test" }); });
    var entry = lines.find(function (l) { return l.message === "hello"; });
    assert.ok(entry, "info line should be emitted to stdout");
    assert.strictEqual(entry.level, "info");
    assert.strictEqual(entry.component, "test");
  });

  it("routes error/fatal to stderr, debug/info/warn to stdout", function () {
    var out = capture("stdout", function () {
      capture("stderr", function () {
        logger.info("to-stdout");
        logger.error("to-stderr");
      });
    });
    assert.ok(out.some(function (l) { return l.message === "to-stdout"; }), "info on stdout");
    assert.ok(!out.some(function (l) { return l.message === "to-stderr"; }), "error not on stdout");
  });

  it("binds requestId via AsyncLocalStorage inside runWithRequestId", function () {
    var lines = capture("stdout", function () {
      logger.runWithRequestId("rid-test-1", function () { logger.info("in-context"); });
      logger.info("out-of-context");
    });
    var inCtx = lines.find(function (l) { return l.message === "in-context"; });
    var outCtx = lines.find(function (l) { return l.message === "out-of-context"; });
    assert.strictEqual(inCtx.requestId, "rid-test-1", "in-context line carries the requestId");
    assert.strictEqual(outCtx.requestId, undefined, "out-of-context line has no requestId");
  });

  it("getRequestId reflects the active context", function () {
    assert.strictEqual(logger.getRequestId(), null, "no id outside a context");
    var seen = logger.runWithRequestId("rid-test-2", function () { return logger.getRequestId(); });
    assert.strictEqual(seen, "rid-test-2");
  });

  it("redacts secret-shaped fields in the extra object (b.redact default)", function () {
    var lines = capture("stdout", function () {
      logger.info("auth", { token: "super-secret-value", userId: "u-1" });
    });
    var entry = lines.find(function (l) { return l.message === "auth"; });
    assert.strictEqual(entry.userId, "u-1", "non-secret field passes through");
    assert.notStrictEqual(entry.token, "super-secret-value", "token value must not appear verbatim");
  });

  it("is built on b.log.create — the framework primitive HS consumes", function () {
    assert.strictEqual(typeof b.log.create, "function");
  });
});

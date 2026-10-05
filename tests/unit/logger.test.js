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

describe("app/shared/logger keeps share IDs and tokens out of log lines", function () {
  var share = b.crypto.generateToken(32);
  var fileShare = b.crypto.generateToken(32);

  it("requestPath returns the route pattern once a route has matched", function () {
    var req = {
      routePattern: "/b/:shareId/download",
      pathname: "/b/" + share + "/download",
      url: "/b/" + share + "/download?path=" + share,
    };
    assert.strictEqual(logger.requestPath(req), "/b/:shareId/download");
    assert.strictEqual(logger.requestPath(req), b.requestHelpers.resolveRoute(req));
  });

  it("requestPath replaces token segments and drops the query before a route has matched", function () {
    assert.strictEqual(
      logger.requestPath({ pathname: "/b/" + share + "/file/" + fileShare, url: "/b/" + share + "/file/" + fileShare + "?ref=" + share }),
      "/b/:token/file/:token");
    assert.strictEqual(logger.requestPath({ url: "/auth/reset-password/" + share + "?next=/x" }), "/auth/reset-password/:token");
    assert.strictEqual(logger.requestPath({ pathname: "/stash/acme-uploads/init" }), "/stash/acme-uploads/init");
    assert.strictEqual(logger.requestPath({ pathname: "/b/" + share + ".zip" }), "/b/[redacted].zip");
  });

  it("requestPath returns / for a request it cannot read", function () {
    var hostile = {};
    Object.defineProperty(hostile, "routePattern", { get: function () { throw new Error("unreadable"); } });
    assert.strictEqual(logger.requestPath(hostile), "/");
    assert.strictEqual(logger.requestPath(null), "/");
  });

  it("redactTokens replaces share IDs in a storage key and keeps a SHA3-512 checksum", function () {
    var key = "bundles/" + share + "/1727900000000-" + fileShare + ".pdf";
    assert.strictEqual(logger.redactTokens("key not found: " + key),
      "key not found: bundles/[redacted]/1727900000000-[redacted].pdf");
    assert.strictEqual(logger.redactTokens("id=z" + share), "id=z[redacted]");
    var checksum = b.crypto.sha3Hash("report");
    assert.strictEqual(logger.redactTokens("checksum " + checksum), "checksum " + checksum);
  });

  it("masks the message, text fields and share-named fields, and keeps fields named for a record", function () {
    var recordId = b.crypto.generateToken(32);
    var lines = capture("stderr", function () {
      logger.error("Download failed for /s/" + share, {
        error: "EACCES: permission denied, open '/data/uploads/bundles/" + share + "/1-" + fileShare + ".bin'",
        shareId: share,
        bundle: share,
        nested: { path: "/b/" + share },
        bundleId: recordId,
      });
    });
    var entry = lines.find(function (l) { return l.message.indexOf("Download failed for") === 0; });
    assert.ok(entry, "the error line is written");
    var text = JSON.stringify(entry);
    assert.strictEqual(text.indexOf(share), -1, "a share ID reached the line");
    assert.strictEqual(text.indexOf(fileShare), -1, "a file share ID reached the line");
    assert.strictEqual(entry.shareId, "[redacted]");
    assert.strictEqual(entry.bundleId, recordId, "a field named for a record is written unchanged");
  });

  it("passes a byte array to b.redact unchanged, and b.redact masks it", function () {
    var lines = capture("stdout", function () {
      logger.info("bytes", { payload: new Uint8Array([7, 8, 9]) });
    });
    var entry = lines.find(function (l) { return l.message === "bytes"; });
    assert.ok(entry, "the line is written");
    assert.strictEqual(typeof entry.payload, "string", "the bytes are masked, not written as an object: " + JSON.stringify(entry.payload));
  });
});

"use strict";
/**
 * A request that fails on a share route writes no share ID to stdout or
 * stderr, either in the router's own lines or in the server's log lines. Each
 * case records everything written to both streams while its request runs.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("node:path");
var b = require("../../lib/vendor/blamejs");
var testServer = require("../helpers/test-server");
var { TestClient } = require("../helpers/http-client");

var client;

// The server's logger reads LOG_LEVEL when testServer.start() loads it, and the
// "Request refused" line is written at debug level.
process.env.LOG_LEVEL = "debug";

before(async function () {
  await testServer.start();
  client = new TestClient(testServer.baseUrl());
});
after(function () { return testServer.stop(); });

// Records what is written to stdout and stderr while fn runs, and still
// writes it.
async function captureOutput(fn) {
  var chunks = [];
  var stdoutWrite = process.stdout.write;
  var stderrWrite = process.stderr.write;
  process.stdout.write = function (chunk) {
    chunks.push(String(chunk));
    return stdoutWrite.apply(process.stdout, arguments);
  };
  process.stderr.write = function (chunk) {
    chunks.push(String(chunk));
    return stderrWrite.apply(process.stderr, arguments);
  };
  try {
    await fn();
  } finally {
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
  }
  return chunks.join("");
}

// Replaces obj[name] with fn and returns a function that restores it.
function stub(obj, name, fn) {
  var hadOwn = Object.prototype.hasOwnProperty.call(obj, name);
  var original = obj[name];
  obj[name] = fn;
  return function restore() {
    if (hadOwn) obj[name] = original;
    else delete obj[name];
  };
}

// text with every copy of secret replaced, for an assertion message. A failure
// message is written to stdout, where it would show up in the next capture.
function shown(text, secret) {
  return String(text).split(secret).join("<share ID>");
}

// Every line that b.router writes includes this field.
var ROUTER_LINE = "\"component\":\"router\"";

describe("share IDs in log output when a request fails", function () {
  var share = b.crypto.generateToken(32);

  it("logs a failing route handler with its route pattern and a redacted error message", async function () {
    var bundlesRepo = require(path.join(testServer.projectRoot, "app", "data", "repositories", "bundles.repo"));
    var restore = stub(bundlesRepo, "findCompleteByShareId", function () {
      throw new Error("forced lookup failure for bundles/" + share + "/1-x.bin");
    });
    var res;
    var output;
    try {
      output = await captureOutput(async function () {
        res = await client.get("/b/" + share + "?ref=" + share);
      });
    } finally {
      restore();
    }
    assert.strictEqual(res.status, 500);
    assert.strictEqual(output.indexOf(share), -1, "a share ID reached the log output:\n" + shown(output, share));
    assert.ok(output.indexOf("Unhandled server error") !== -1, "the failure is logged:\n" + shown(output, share));
    assert.ok(output.indexOf("/b/:shareId") !== -1, "with its route pattern:\n" + shown(output, share));
    assert.ok(output.indexOf("bundles/[redacted]/1-x.bin") !== -1, "with the share ID in the message redacted:\n" + shown(output, share));
    assert.strictEqual(output.indexOf(ROUTER_LINE), -1, "the router writes no line of its own:\n" + shown(output, share));
  });

  it("logs a failing global middleware with the route pattern the request matches", async function () {
    var db = require(path.join(testServer.projectRoot, "lib", "db"));
    var restore = stub(db.apiKeys, "findOne", function () {
      throw new Error("forced key lookup failure");
    });
    var res;
    var output;
    try {
      output = await captureOutput(async function () {
        res = await client.get("/b/" + share + "/folder?path=" + share, {
          headers: { authorization: "Bearer hs_" + b.crypto.generateToken(32) },
        });
      });
    } finally {
      restore();
    }
    assert.strictEqual(res.status, 500);
    assert.strictEqual(output.indexOf(share), -1, "a share ID reached the log output:\n" + shown(output, share));
    assert.ok(output.indexOf("Unhandled server error") !== -1, "the failure is logged:\n" + shown(output, share));
    assert.ok(output.indexOf("\"path\":\"/b/:shareId/folder\"") !== -1, "with the route pattern:\n" + shown(output, share));
    assert.strictEqual(output.indexOf(ROUTER_LINE), -1, "the router writes no line of its own:\n" + shown(output, share));
  });

  it("logs a failing global middleware on a path no route matches with its token segments replaced", async function () {
    var db = require(path.join(testServer.projectRoot, "lib", "db"));
    var restore = stub(db.apiKeys, "findOne", function () {
      throw new Error("forced key lookup failure");
    });
    var res;
    var output;
    try {
      output = await captureOutput(async function () {
        res = await client.get("/nope/" + share + "/x?t=" + share, {
          headers: { authorization: "Bearer hs_" + b.crypto.generateToken(32) },
        });
      });
    } finally {
      restore();
    }
    assert.strictEqual(res.status, 500);
    assert.strictEqual(output.indexOf(share), -1, "a share ID reached the log output:\n" + shown(output, share));
    assert.ok(output.indexOf("\"path\":\"/nope/:token/x\"") !== -1, "with the token segment replaced:\n" + shown(output, share));
    assert.strictEqual(output.indexOf(ROUTER_LINE), -1, "the router writes no line of its own:\n" + shown(output, share));
  });

  it("logs a refused request at debug level with its route pattern and writes no router line", async function () {
    var saved = process.env.BLAMEJS_BOOT_LOG_LEVEL;
    process.env.BLAMEJS_BOOT_LOG_LEVEL = "debug";
    var res;
    var output;
    try {
      output = await captureOutput(async function () {
        res = await client.post("/b/" + share + "/unlock", { json: { password: "not-the-password" } });
      });
    } finally {
      if (saved === undefined) delete process.env.BLAMEJS_BOOT_LOG_LEVEL;
      else process.env.BLAMEJS_BOOT_LOG_LEVEL = saved;
    }
    assert.strictEqual(res.status, 404);
    assert.strictEqual(output.indexOf(share), -1, "a share ID reached the log output:\n" + shown(output, share));
    assert.ok(output.indexOf("Request refused") !== -1, "the refusal is logged:\n" + shown(output, share));
    assert.ok(output.indexOf("/b/:shareId/unlock") !== -1, "with its route pattern:\n" + shown(output, share));
    assert.strictEqual(output.indexOf(ROUTER_LINE), -1, "the router writes no line of its own:\n" + shown(output, share));
  });

  it("answers a refused password check with 503 and writes no error line", async function () {
    var passwordGate = require(path.join(testServer.projectRoot, "lib", "password-gate"));
    var { ServiceUnavailableError } = require(path.join(testServer.projectRoot, "app", "shared", "errors"));
    var refusing = new TestClient(testServer.baseUrl());
    await refusing.initApiKey();
    var saved = process.env.BLAMEJS_BOOT_LOG_LEVEL;
    process.env.BLAMEJS_BOOT_LOG_LEVEL = "debug";
    var restore = stub(passwordGate, "verify", async function () {
      throw new ServiceUnavailableError("Too many password checks are in progress. Try again in a few seconds.", 5);
    });
    var res;
    var output;
    try {
      output = await captureOutput(async function () {
        res = await refusing.post("/auth/login", { json: { email: "nobody@example.com", password: "not-the-password-1" } });
      });
    } finally {
      restore();
      if (saved === undefined) delete process.env.BLAMEJS_BOOT_LOG_LEVEL;
      else process.env.BLAMEJS_BOOT_LOG_LEVEL = saved;
    }
    assert.strictEqual(res.status, 503);
    assert.strictEqual(res.headers["retry-after"], "5");
    assert.strictEqual(output.indexOf("\"level\":\"error\""), -1, "a refused password check is not logged as an error:\n" + output);
    assert.strictEqual(output.indexOf(ROUTER_LINE), -1, "the router writes no line of its own:\n" + output);
  });

  it("stores a refused unlock with the route pattern in details and the full path in path", async function () {
    await client.initApiKey();
    var init = await client.post("/drop/init", {
      json: { uploaderName: "Log Tester", fileCount: 0, skippedCount: 0, skippedFiles: [], password: "correct-horse" },
    });
    assert.strictEqual(init.status, 200);
    var fin = await client.post("/drop/finalize/" + init.json.bundleId, {
      json: { finalizeToken: init.json.finalizeToken },
    });
    assert.strictEqual(fin.status, 200);

    var shareId = init.json.shareId;
    var res = await client.post("/b/" + shareId + "/unlock", { json: { password: "wrong-password" } });
    assert.strictEqual(res.status, 401);

    var audit = require(path.join(testServer.projectRoot, "lib", "audit"));
    var db = require(path.join(testServer.projectRoot, "lib", "db"));
    await audit.drainChain();
    var refused = db.auditLog.raw().find({})
      .map(function (row) { return audit.unsealEntry(row); })
      .filter(function (e) { return e.action === audit.ACTIONS.AUTH_FAILED_PAGE; });
    var entry = refused[refused.length - 1];
    assert.ok(entry, "the refusal is audited");
    assert.strictEqual(entry.details.indexOf(shareId), -1, "details carry no share ID: " + shown(entry.details, shareId));
    assert.ok(entry.details.indexOf("/b/:shareId/unlock") !== -1, shown(entry.details, shareId));
    assert.strictEqual(entry.path, "/b/" + shareId + "/unlock",
      "the stored path keeps the share link, so an administrator can search for it");
  });

  it("ends the request when a middleware calls next() and then fails", async function () {
    var app = new b.router.Router({ logErrors: false });
    var routeRan = false;
    app.use(async function nextThenFail(req, res, next) {
      next();
      throw new Error("failed after next");
    });
    app.get("/y", function (req, res) {
      routeRan = true;
      if (!res.writableEnded) res.end("route ran");
    });
    // The handler answers on the next turn, so the response has not ended when
    // the middleware's failure is handled.
    app.onError(function (err, req, res) {
      setImmediate(function () {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("handled");
      });
    });
    var server = await new Promise(function (resolve) {
      var s = app.listen(0, function () { resolve(s); });
    });
    var res;
    try {
      res = await new TestClient("http://localhost:" + server.address().port).get("/y");
    } finally {
      await new Promise(function (resolve) {
        server.close(function () { resolve(); });
        if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      });
    }
    assert.strictEqual(res.status, 500);
    assert.strictEqual(res.text, "handled");
    assert.strictEqual(routeRan, false, "the route must not run after the middleware failed");
  });

  it("ends the request when a middleware passes an error to next", async function () {
    var app = new b.router.Router({ logErrors: false });
    var routeRan = false;
    app.use(function passesError(req, res, next) {
      next(new Error("passed to next"));
    });
    app.get("/z", function (req, res) {
      routeRan = true;
      if (!res.writableEnded) res.end("route ran");
    });
    app.onError(function (err, req, res) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("handled: " + err.message);
    });
    var server = await new Promise(function (resolve) {
      var s = app.listen(0, function () { resolve(s); });
    });
    var res;
    try {
      res = await new TestClient("http://localhost:" + server.address().port).get("/z");
    } finally {
      await new Promise(function (resolve) {
        server.close(function () { resolve(); });
        if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      });
    }
    assert.strictEqual(res.status, 500);
    assert.strictEqual(res.text, "handled: passed to next");
    assert.strictEqual(routeRan, false, "the route must not run after next(err)");
  });

  it("answers a request with an error when the session store fails", async function () {
    var bServer = require(path.join(testServer.projectRoot, "lib", "vendor", "blamejs"));
    var restore = stub(bServer.session, "verify", async function () {
      throw new Error("forced session store failure");
    });
    var res;
    var output;
    try {
      output = await captureOutput(async function () {
        res = await new TestClient(testServer.baseUrl()).get("/b/" + share, {
          headers: { cookie: "hs_sid=" + b.crypto.generateToken(24) },
        });
      });
    } finally {
      restore();
    }
    assert.strictEqual(res.status, 500);
    assert.ok(output.indexOf("forced session store failure") !== -1, "the failure is logged:\n" + shown(output, share));
    assert.strictEqual(output.indexOf(share), -1, "a share ID reached the log output:\n" + shown(output, share));
  });

  it("logs a failing error handler and answers a plain 500", async function () {
    var errorHandler = require(path.join(testServer.projectRoot, "middleware", "error-handler"));
    var app = new b.router.Router({ logErrors: false });
    app.get("/x/:id", function () { throw new Error("route failed"); });
    // routeErrorHandler, as server-main.js registers it, given a response whose
    // writes throw, so errorHandler itself fails. The router then answers on
    // the real response.
    app.onError(function (err, req, res) {
      var broken = Object.create(res);
      ["writeHead", "setHeader", "end", "write"].forEach(function (m) {
        broken[m] = function () { throw new Error("handler failed"); };
      });
      return errorHandler.routeErrorHandler(err, req, broken);
    });
    var server = await new Promise(function (resolve) {
      var s = app.listen(0, function () { resolve(s); });
    });
    var res;
    var output;
    try {
      output = await captureOutput(async function () {
        res = await new TestClient("http://localhost:" + server.address().port).get("/x/" + share);
      });
    } finally {
      await new Promise(function (resolve) {
        server.close(function () { resolve(); });
        if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      });
    }
    // b.requestHelpers.failAfterHeaders(res) is false before any byte is sent,
    // so the plain 500 is written.
    assert.strictEqual(res.status, 500);
    assert.strictEqual(res.text, "Internal Server Error");
    assert.ok(output.indexOf("Error handler failed") !== -1, "the handler failure is logged:\n" + shown(output, share));
    assert.ok(output.indexOf("/x/:id") !== -1, "with the route pattern:\n" + shown(output, share));
    assert.strictEqual(output.indexOf(share), -1, "a share ID reached the log output:\n" + shown(output, share));
  });
});

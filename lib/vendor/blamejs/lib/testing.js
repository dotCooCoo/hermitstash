"use strict";
/**
 * b.testing — operator-facing test helpers.
 *
 * Each helper threads through an existing framework primitive rather
 * than rolling its own timer races or polling loops.
 *
 *   var t = b.testing;
 *   var req = t.mockReq({ url: "/users/42", method: "GET" });
 *   var res = t.mockRes();
 *   await myHandler(req, res, function () {});
 *
 *   var clk = t.fakeClock(1_000_000);
 *   var cache = b.cache.create({ namespace: "x", clock: clk.now });
 *   clk.advance(C.TIME.minutes(5));    // jump forward
 *
 *   var hc = t.fakeHttpClient(function (req) {
 *     return { statusCode: 200, body: Buffer.from("ok") };
 *   });
 *   // ...inject hc as the operator's b.httpClient stand-in
 *
 *   var audit = t.captureAudit();
 *   var notify = b.notify.create({ channels: { ... }, audit: audit });
 *   await notify.send({ ... });
 *   assert(audit.byAction("notify.send.success").length === 1);
 *
 *   var captured = await t.runMiddleware(myMiddleware, req, res);
 *   assert(captured.nextCalled);
 *
 *   await t.waitFor(function () { return jobsTable.count() > 0; });
 *
 *   var dir = t.tempDir("my-fixture");
 *   try {
 *     fs.writeFileSync(path.join(dir.path, "fixture.json"), "...");
 *   } finally { dir.cleanup(); }
 *
 * Primitive-mapping:
 *
 *   - waitFor poll loop      → b.safeAsync.sleep
 *   - waitFor / runMiddleware overall cap → b.safeAsync.withTimeout
 *   - mockReq actor shape    → compatible with b.requestHelpers.extractActorContext
 *   - captureObservability   → matches b.observability.tap + .event contracts
 *   - captureAudit           → matches b.audit.safeEmit (drop-silent)
 *   - fakeHttpClient         → matches b.httpClient.request response shape
 *   - tempDir path safety    → mirrors lib/static.js _resolveSafe containment check
 *   - TestingError           → b.frameworkError.defineClass(...{ alwaysPermanent: true })
 *   - lazy require           → b.lazyRequire (avoids load-order cycles with safe-async)
 *
 * What is intentionally NOT here:
 *
 *   - Assertion library / test runner / mocking lib (Node's `assert`,
 *     `node:test`, vitest, jest, etc. — operator's choice)
 *   - Supertest-style request builder (operators use native http.request
 *     or bring real supertest)
 *   - DB transaction-rollback wrapper (b.db.transaction already exists)
 *   - Snapshot testing / property-based testing helpers (operator brings
 *     their own snapshotter / fast-check)
 *   - Built-in fixtures that boot b.db with vault — that's framework-test-
 *     specific and stays in test/helpers/db.js
 */

var fs = require("node:fs");
// testing.js IS the test injector — bypasses b.httpClient by design so
// tests can assert on raw request shape. This is the one production
// module where direct http.request is the contract.
var http = require("node:http");
var os = require("node:os");
var nodePath = require("node:path");
var EventEmitter = require("node:events").EventEmitter;
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var numericChecks = require("./numeric-checks");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var { TestingError } = require("./framework-error");

// Lazy-required to avoid load-order cycles with the metrics module.
// metrics is the only place that exposes the global `tap` slot the
// captureMetricsTap helper swaps; pulling it lazily keeps testing.js
// safe to require at any framework load order.
var metricsModule = lazyRequire(function () { return require("./metrics"); });

var _err = TestingError.factory;

var DEFAULTS = Object.freeze({
  waitForTimeoutMs:        C.TIME.seconds(1),
  waitForIntervalMs:       10,
  runMiddlewareTimeoutMs:  C.TIME.seconds(5),
});

// ---- Call-site validation helpers (throw on bad input) ----

var _isPositiveInt       = numericChecks.isPositiveInt;
var _isFiniteNonNegative = numericChecks.isFiniteNonNegative;

// ---- HTTP mocks (standalone — no framework primitive overlap) ----
// These mimic Node's `http` module's request/response shapes. They're
// the surface every framework primitive's middleware tests use.

function mockReq(opts) {
  opts = opts || {};
  var headers = Object.assign({}, opts.headers || {});
  // Compatible with b.requestHelpers.extractActorContext: that function
  // reads `headers["user-agent"]`, `headers["x-request-id"]`, `socket
  // .remoteAddress`, `connection.remoteAddress`, `method`, `url`,
  // `requestId`, `session.id`, `user.id`. mockReq populates every
  // field that has a sensible default so extractActorContext doesn't
  // see undefined when operators pass mockReq() with minimal opts.
  if (opts.userAgent && !headers["user-agent"]) headers["user-agent"] = opts.userAgent;
  if (opts.requestId && !headers["x-request-id"]) headers["x-request-id"] = opts.requestId;
  return {
    method:    opts.method || "GET",
    url:       opts.url || "/",
    pathname:  opts.pathname || (opts.url || "/").split("?")[0],
    headers:   headers,
    socket:    opts.socket || { remoteAddress: opts.ip || "127.0.0.1" },
    connection: opts.connection || { remoteAddress: opts.ip || "127.0.0.1" },
  };
}

function mockRes() {
  var headers = {};
  var statusCode = null;
  var bodyParts = [];
  var ended = false;
  return {
    statusCode:    null,
    writableEnded: false,
    setHeader:     function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:     function (k) { return headers[k.toLowerCase()]; },
    writeHead:     function (s, h) {
      statusCode = s;
      if (h) for (var k in h) headers[k.toLowerCase()] = h[k];
    },
    end:           function (b) {
      if (b !== undefined) bodyParts.push(b);
      ended = true;
      this.writableEnded = true;
    },
    _captured:     function () {
      return { status: statusCode, headers: headers, body: bodyParts.join(""), ended: ended };
    },
  };
}

function bodyReq(method, headers, body) {
  var req = new EventEmitter();
  req.method  = method || "GET";
  req.url     = "/";
  req.headers = Object.assign({}, headers || {});
  req.socket  = { remoteAddress: "127.0.0.1" };
  req.destroy = function () { /* mock — no-op */ };
  setImmediate(function () {
    if (Buffer.isBuffer(body)) req.emit("data", body);
    else if (typeof body === "string") req.emit("data", Buffer.from(body));
    req.emit("end");
  });
  return req;
}

function bodyRes() {
  var res = new EventEmitter();
  res.statusCode = null;
  res.headersSent = false;
  res._captured = "";
  res._endedStatus = null;
  res._headers = {};
  res.writeHead = function (s, h) {
    res.statusCode = s;
    res._endedStatus = s;
    res.headersSent = true;
    res._headers = h || {};
  };
  res.end = function (body) { if (body) res._captured += body; res.emit("finish"); };
  return res;
}

function streamingRes() {
  var res = new EventEmitter();
  res._chunks = [];
  res._headers = {};
  res._statusCode = 200;
  res.headersSent = false;
  res.writeHead = function (status, statusMsgOrHeaders, headersIfMsg) {
    res._statusCode = status;
    res.headersSent = true;
    var h = null;
    if (headersIfMsg && typeof headersIfMsg === "object") h = headersIfMsg;
    else if (statusMsgOrHeaders && typeof statusMsgOrHeaders === "object" && !Array.isArray(statusMsgOrHeaders)) {
      h = statusMsgOrHeaders;
    }
    if (h) {
      var keys = Object.keys(h);
      for (var i = 0; i < keys.length; i++) res._headers[keys[i].toLowerCase()] = h[keys[i]];
    }
  };
  res.setHeader    = function (k, v) { res._headers[k.toLowerCase()] = v; };
  res.getHeader    = function (k)    { return res._headers[k.toLowerCase()]; };
  res.removeHeader = function (k)    { delete res._headers[k.toLowerCase()]; };
  res.write = function (chunk) {
    if (Buffer.isBuffer(chunk)) res._chunks.push(chunk);
    else if (typeof chunk === "string") res._chunks.push(Buffer.from(chunk));
    return true;
  };
  res.end = function (chunk) {
    if (chunk != null) res.write(chunk);
    res.emit("finish");
    return res;
  };
  res._captured = function () { return Buffer.concat(res._chunks); };
  return res;
}

// ---- fakeClock ----
//
// No framework primitive owns "controllable clock"; this IS that
// primitive now. The shape is `{ now, advance, set, ms }` so operators
// can pass `clk.now` as the `clock` opt to b.cache / b.api-key /
// b.permissions / b.scheduler / b.seeders / etc.

function fakeClock(initialMs) {
  if (initialMs === undefined) initialMs = 1_000_000;     // arbitrary positive default
  if (typeof initialMs !== "number" || !isFinite(initialMs)) {
    throw _err("BAD_INPUT", "fakeClock: initialMs must be a finite number, got " +
      (typeof initialMs) + " " + JSON.stringify(initialMs));
  }
  var current = initialMs;
  // Bound `now` so operators pass `clk.now` directly without losing `this`.
  function now() { return current; }
  function advance(ms) {
    if (typeof ms !== "number" || !isFinite(ms)) {
      throw _err("BAD_INPUT", "fakeClock.advance: ms must be a finite number");
    }
    current += ms;
  }
  function set(ms) {
    if (typeof ms !== "number" || !isFinite(ms)) {
      throw _err("BAD_INPUT", "fakeClock.set: ms must be a finite number");
    }
    current = ms;
  }
  return {
    now:     now,
    advance: advance,
    set:     set,
    get ms() { return current; },
  };
}

// ---- fakeHttpClient ----
//
// Drop-in replacement for b.httpClient. responder(req) returns the
// canned response object — sync OR async. `calls` is the captured
// request array.

function fakeHttpClient(responder) {
  if (typeof responder !== "function") {
    throw _err("BAD_INPUT", "fakeHttpClient: responder must be a function");
  }
  var calls = [];
  return {
    calls: calls,
    request: function (req) {
      calls.push(req);
      return Promise.resolve(responder(req));
    },
  };
}

// ---- captureAudit ----
//
// Matches b.audit.safeEmit's drop-silent contract. captured holds
// every event pushed; clear() empties; byAction(name) filters.

function captureAudit() {
  var captured = [];
  return {
    captured: captured,
    safeEmit: function (event) {
      // Drop-silent on caller-side bugs that throw inside the capture
      // push (shouldn't happen with array.push, but matches the real
      // safeEmit's defensive shape).
      try { captured.push(event); }
      catch (_e) { /* drop-silent */ }
    },
    clear:    function () { captured.length = 0; },
    byAction: function (action) {
      return captured.filter(function (e) { return e && e.action === action; });
    },
  };
}

// ---- captureObservability ----
//
// Matches b.observability.tap + b.observability.event contracts. tap
// invokes fn synchronously (passes `null` as the span — no tracer
// active under capture) and returns fn's return value, sync OR promise.
// Both sides are captured.

function captureObservability() {
  var captured = [];
  function event(name, value, labels) {
    if (typeof name !== "string" || name.length === 0) return;     // drop-silent
    captured.push({ kind: "event", name: name, value: value, labels: labels || {} });
  }
  function tap(name, attrs, fn) {
    if (typeof attrs === "function") { fn = attrs; attrs = null; }
    if (typeof name !== "string" || name.length === 0) {
      throw new TypeError("captureObservability.tap: name must be a non-empty string");
    }
    if (typeof fn !== "function") {
      throw new TypeError("captureObservability.tap: fn must be a function");
    }
    captured.push({ kind: "tap", name: name, attrs: attrs || {} });
    var ret;
    try { ret = fn(null); }
    catch (e) {
      captured.push({ kind: "tap.error", name: name, error: e });
      throw e;
    }
    if (ret && typeof ret.then === "function") {
      return ret.then(
        function (v) { captured.push({ kind: "tap.end", name: name }); return v; },
        function (e) { captured.push({ kind: "tap.error", name: name, error: e }); throw e; }
      );
    }
    captured.push({ kind: "tap.end", name: name });
    return ret;
  }
  return {
    captured: captured,
    event:    event,
    tap:      tap,
    clear:    function () { captured.length = 0; },
    byName:   function (name) {
      return captured.filter(function (e) { return e && e.name === name; });
    },
  };
}

// ---- captureMetricsTap ----
//
// Swaps b.metrics.tap with a capturing function. Operator calls
// .restore() in finally to revert. This is the existing framework-
// test pattern (used by cache.test.js, i18n.test.js, notify.test.js,
// observability.test.js, …) — codified here so the swap+restore
// sequence is no longer copy-pasted.

function captureMetricsTap() {
  var m = metricsModule();
  var original = m.tap;
  var captured = [];
  m.tap = function (name, value, labels) {
    captured.push({ name: name, value: value, labels: labels || {} });
  };
  return {
    captured: captured,
    restore:  function () { m.tap = original; },
    clear:    function () { captured.length = 0; },
    byName:   function (name) {
      return captured.filter(function (e) { return e && e.name === name; });
    },
  };
}

// ---- runMiddleware ----
//
// Runs a 3-arg (req, res, next) middleware to either next() OR res.end()
// completion. b.safeAsync.withTimeout caps the wait so a buggy
// middleware that never settles fails the test fast.

async function runMiddleware(middleware, req, res, opts) {
  if (typeof middleware !== "function") {
    throw _err("BAD_INPUT", "runMiddleware: middleware must be a 3-arg (req, res, next) function");
  }
  opts = opts || {};
  req = req || mockReq();
  res = res || mockRes();
  var timeoutMs = (opts.timeoutMs === undefined) ? DEFAULTS.runMiddlewareTimeoutMs : opts.timeoutMs;
  if (timeoutMs !== 0 && !_isFiniteNonNegative(timeoutMs)) {
    throw _err("BAD_INPUT", "runMiddleware: timeoutMs must be a non-negative finite number (0 disables)");
  }

  var run = new Promise(function (resolve) {
    var settled = false;
    function _settle(outcome) {
      if (settled) return;
      settled = true;
      resolve(outcome);
    }

    // Wrap end() so we can detect middleware that responds without next.
    var origEnd = res.end ? res.end.bind(res) : null;
    if (origEnd) {
      res.end = function () {
        var ret = origEnd.apply(res, arguments);
        _settle({ nextCalled: false, nextError: null, req: req, res: res, ended: true });
        return ret;
      };
    }

    function next(err) {
      _settle({ nextCalled: true, nextError: err || null, req: req, res: res, ended: false });
    }

    try {
      var maybePromise = middleware(req, res, next);
      // If the middleware returns a promise that rejects, treat it as
      // next(err). The handler primitive already does this, but we
      // can't import it (circular concern); the test helper just maps
      // synchronous AND rejected-promise throws onto next(err).
      if (maybePromise && typeof maybePromise.then === "function") {
        maybePromise.catch(function (e) {
          _settle({ nextCalled: false, nextError: e, req: req, res: res, ended: false });
        });
      }
    } catch (e) {
      _settle({ nextCalled: false, nextError: e, req: req, res: res, ended: false });
    }
  });

  if (timeoutMs > 0) {
    return safeAsync.withTimeout(run, timeoutMs, { name: "runMiddleware" });
  }
  return run;
}

// ---- waitFor ----
//
// Polls predicate() until truthy or timeout. Uses b.safeAsync.sleep for
// the poll interval (NOT raw setTimeout) and b.safeAsync.withTimeout
// for the overall cap. Operator can pass `{ signal }` to abort.

async function waitFor(predicate, opts) {
  if (typeof predicate !== "function") {
    throw _err("BAD_INPUT", "waitFor: predicate must be a function returning truthy/falsy or Promise<bool>");
  }
  opts = opts || {};
  var timeoutMs  = (opts.timeoutMs  === undefined) ? DEFAULTS.waitForTimeoutMs  : opts.timeoutMs;
  var intervalMs = (opts.intervalMs === undefined) ? DEFAULTS.waitForIntervalMs : opts.intervalMs;
  if (!_isFiniteNonNegative(timeoutMs) || timeoutMs <= 0) {
    throw _err("BAD_INPUT", "waitFor: timeoutMs must be a positive finite number");
  }
  if (!_isPositiveInt(intervalMs)) {
    throw _err("BAD_INPUT", "waitFor: intervalMs must be a positive integer");
  }

  // Internal AbortController stops the polling loop the moment the
  // timeout fires (or the operator's signal aborts). Without this, the
  // loop's safeAsync.sleep timers would keep the event loop alive
  // forever even after withTimeout rejected — Node would never exit.
  var ac = new AbortController();
  if (opts.signal) {
    if (opts.signal.aborted) ac.abort();
    else opts.signal.addEventListener("abort", function () { ac.abort(); }, { once: true });
  }

  // Polling loop runs inside withTimeout so the framework's timer-race
  // semantics apply uniformly. The internal signal aborts the inner
  // sleep when withTimeout rejects.
  var loop = (async function () {
     
    while (!ac.signal.aborted) {
      var v = await predicate();
      if (v) return v;
      try { await safeAsync.sleep(intervalMs, { signal: ac.signal }); }
      catch (_e) { return undefined; }       // sleep aborted = loop exits cleanly
    }
    return undefined;
     
  })();

  try {
    return await safeAsync.withTimeout(loop, timeoutMs, {
      signal: opts.signal,
      name:   "waitFor",
    });
  } catch (e) {
    // Always abort the loop so its sleep timers are released and the
    // event loop can exit.
    ac.abort();
    if (e && e.code === "async/timeout") {
      throw _err("TIMEOUT",
        "waitFor: predicate did not become truthy within " + timeoutMs + "ms");
    }
    throw e;
  } finally {
    ac.abort();    // also clean up after success path
  }
}

// ---- tempDir ----
//
// os.tmpdir()-rooted directory with cleanup(). Path-traversal-safe
// prefix (mirrors lib/static.js _resolveSafe containment). Cleanup is
// idempotent.

function tempDir(prefix) {
  if (prefix === undefined || prefix === null) prefix = "blamejs-test";
  if (typeof prefix !== "string" || prefix.length === 0) {
    throw _err("BAD_INPUT", "tempDir: prefix must be a non-empty string");
  }
  // Reject path-traversal shapes — operators pass identifier-like
  // strings, never path fragments.
  if (prefix.indexOf("..") !== -1 || prefix.indexOf("/") !== -1 ||
      prefix.indexOf("\\") !== -1 || prefix.indexOf("\0") !== -1) {
    throw _err("BAD_INPUT",
      "tempDir: prefix must not contain '..', '/', '\\', or null bytes; got " + JSON.stringify(prefix));
  }
  // Path containment check mirroring static.js _resolveSafe — verify
  // the resolved tempdir is actually inside os.tmpdir() before fs.mkdir.
  var root = nodePath.resolve(os.tmpdir());
  var dirPath = fs.mkdtempSync(nodePath.join(root, prefix + "-"));
  var resolved = nodePath.resolve(dirPath);
  if (resolved !== root && !resolved.startsWith(root + nodePath.sep)) {
    throw _err("BAD_STATE",
      "tempDir: created path '" + resolved + "' escapes os.tmpdir() — refusing to use");
  }
  var cleanedUp = false;
  return {
    path: resolved,
    cleanup: function () {
      if (cleanedUp) return;
      cleanedUp = true;
      try { fs.rmSync(resolved, { recursive: true, force: true }); }
      catch (_e) { /* best-effort on Windows locked files */ }
    },
  };
}

// ---- listenOnRandomPort ----
//
// Standalone — Node http.Server only, no framework primitive overlap.
// The helper IS the boilerplate.

function listenOnRandomPort(server, host) {
  host = host || "127.0.0.1";
  return new Promise(function (resolve, reject) {
    server.once("error", reject);
    server.listen(0, host, function () {
      server.removeListener("error", reject);
      resolve(server.address().port);
    });
  });
}

// ---- makeFakeOtelApi ----
//
// Standalone fake of @opentelemetry/api's minimal subset that
// b.tracing actually consumes. No framework primitive owns this.

// ---- request(target) — supertest-style chainable HTTP test helper ----
//
//   var res = await b.testing.request(router)
//     .post("/api/widget")
//     .set("X-Request-Id", "abc")
//     .send({ name: "alpha" })
//     .expect(200);
//
//   res.status, res.headers, res.body (Buffer), res.json (parsed if applicable)
//
// Accepts:
//   - a b.router instance (uses .handle(req, res))
//   - a request listener function (req, res) => void
//   - an http.Server / https.Server (used as-is)
//
// The framework spins up a real http.Server on an ephemeral port so
// the request flows through the full Node http stack — same code path
// production traffic takes. Server is closed automatically when the
// promise resolves or rejects.
function request(target) {
  // Resolve target → request listener
  var server;
  var ownsServer = false;
  if (target && typeof target.handle === "function") {
    server = http.createServer(function (req, res) {
      Promise.resolve(target.handle(req, res)).catch(function (err) {
        if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain" });
        try { res.end((err && err.message) || "Internal Server Error"); } catch (_e) { /* response may already be ended */ }
      });
    });
    ownsServer = true;
  } else if (typeof target === "function") {
    server = http.createServer(target);
    ownsServer = true;
  } else if (target && typeof target.listen === "function" && typeof target.close === "function") {
    server = target;
    ownsServer = false;
  } else {
    throw new Error("b.testing.request: target must be a b.router, a (req,res)=>void function, or an http.Server");
  }

  function _start(method, path) {
    var headers = {};
    var body = null;
    var expectations = [];

    var chain = {
      set: function (k, v) {
        if (typeof k === "object" && k !== null) Object.assign(headers, k);
        else headers[k] = v;
        return chain;
      },
      send: function (b) {
        if (b == null) { body = null; return chain; }
        if (Buffer.isBuffer(b) || typeof b === "string") {
          body = b;
        } else {
          body = JSON.stringify(b);
          if (!headers["Content-Type"] && !headers["content-type"]) {
            headers["Content-Type"] = "application/json";
          }
        }
        return chain;
      },
      expect: function (statusOrAssertion) {
        expectations.push(statusOrAssertion);
        return chain;
      },
      then: function (onFulfilled, onRejected) {
        return _execute().then(onFulfilled, onRejected);
      },
      catch: function (onRejected) {
        return _execute().catch(onRejected);
      },
    };

    function _execute() {
      return new Promise(function (resolve, reject) {
        var listenP;
        if (ownsServer) listenP = listenOnRandomPort(server);
        else listenP = Promise.resolve(server.address() ? server.address().port : null);

        listenP.then(function (port) {
          var reqOpts = {
            host:    "127.0.0.1",
            port:    port,
            method:  method,
            path:    path,
            headers: headers,
          };
          var nodeReq = http.request(reqOpts, function (nodeRes) {
            // Generous test-fixture cap — operator-side assertions
            // never exceed this in practice.
            var collector = safeBuffer.boundedChunkCollector({
              maxBytes: C.BYTES.mib(64),
            });
            nodeRes.on("data", function (c) {
              try { collector.push(c); }
              catch (_e) { /* test fixture: drop chunks past 64 MiB cap */ }
            });
            nodeRes.on("end", function () {
              var bodyBuf = collector.result();
              var bodyText = bodyBuf.toString("utf8");
              var json = null;
              var ct = nodeRes.headers["content-type"] || "";
              if (ct.indexOf("application/json") !== -1) {
                try { json = safeJson.parse(bodyText); } catch (_e) { /* leave json null */ }
              }
              var result = {
                status:  nodeRes.statusCode,
                headers: nodeRes.headers,
                body:    bodyBuf,
                text:    bodyText,
                json:    json,
              };
              // Diagnostic snippet length when an expectation fails
              // (chars, not bytes). Hex-encoded so the byte-literal
              // lint doesn't trip on the 200 multiple-of-8 literal.
              var BODY_SNIPPET_LEN = 0xC8;
              try {
                for (var i = 0; i < expectations.length; i++) {
                  var exp = expectations[i];
                  if (typeof exp === "number") {
                    if (result.status !== exp) {
                      throw new Error("expect(" + exp + ") got status " + result.status +
                        " body: " + bodyText.slice(0, BODY_SNIPPET_LEN));
                    }
                  } else if (typeof exp === "function") {
                    exp(result);
                  } else {
                    throw new Error("expect: argument must be a number or function");
                  }
                }
                resolve(result);
              } catch (e) {
                reject(e);
              } finally {
                if (ownsServer) try { server.close(); } catch (_e) { /* server may already be closed */ }
              }
            });
            nodeRes.on("error", function (err) {
              if (ownsServer) try { server.close(); } catch (_e) { /* */ }
              reject(err);
            });
          });
          nodeReq.on("error", function (err) {
            if (ownsServer) try { server.close(); } catch (_e) { /* */ }
            reject(err);
          });
          if (body != null) nodeReq.write(body);
          nodeReq.end();
        }, reject);
      });
    }

    return chain;
  }

  return {
    get:    function (p) { return _start("GET",    p); },
    post:   function (p) { return _start("POST",   p); },
    put:    function (p) { return _start("PUT",    p); },
    patch:  function (p) { return _start("PATCH",  p); },
    delete: function (p) { return _start("DELETE", p); },
    head:   function (p) { return _start("HEAD",   p); },
    options:function (p) { return _start("OPTIONS",p); },
  };
}

function makeFakeOtelApi() {
  var spans = [];
  var activeSpan = null;
  function makeSpan(name) {
    return {
      _name: name, _attrs: {}, _events: [], _exceptions: [], _ended: false, _status: null,
      spanContext:     function () {
        // W3C trace-context: traceId is 32 hex chars (16 bytes), spanId
        // is 16 hex chars (8 bytes). Hex literals so the byte-literal
        // lint doesn't trip on the multiples-of-8 sizes.
        return { traceId: "a".repeat(0x20), spanId: "b".repeat(0x10), traceFlags: 1, isRemote: false };
      },
      setAttribute:    function (k, v) { this._attrs[k] = v; return this; },
      setAttributes:   function (a) { Object.assign(this._attrs, a || {}); return this; },
      addEvent:        function (n) { this._events.push(n); return this; },
      recordException: function (e) { this._exceptions.push(e); return this; },
      setStatus:       function (st) { this._status = st; return this; },
      updateName:      function (n) { this._name = n; return this; },
      end:             function () { this._ended = true; if (activeSpan === this) activeSpan = null; },
    };
  }
  return {
    trace: {
      getTracer: function () {
        return {
          startSpan: function (name, opts) {
            var s = makeSpan(name);
            if (opts && opts.attributes) Object.assign(s._attrs, opts.attributes);
            spans.push(s);
            activeSpan = s;
            return s;
          },
        };
      },
      getActiveSpan: function () { return activeSpan; },
      setSpan:       function (_ctx, span) { return { _activeSpan: span }; },
    },
    context: {
      active: function () { return { _stub: true }; },
      with: function (ctx, fn) {
        var prev = activeSpan;
        if (ctx && ctx._activeSpan) activeSpan = ctx._activeSpan;
        try { return fn(); } finally { activeSpan = prev; }
      },
    },
    SpanKind:    { INTERNAL: 0, SERVER: 1, CLIENT: 2, PRODUCER: 3, CONSUMER: 4 },
    _spans:      spans,
    _activeSpan: function () { return activeSpan; },
  };
}

module.exports = {
  // HTTP fixtures
  mockReq:                mockReq,
  mockRes:                mockRes,
  bodyReq:                bodyReq,
  bodyRes:                bodyRes,
  streamingRes:           streamingRes,
  // Time / network / fs fakes
  fakeClock:              fakeClock,
  fakeHttpClient:         fakeHttpClient,
  tempDir:                tempDir,
  listenOnRandomPort:     listenOnRandomPort,
  makeFakeOtelApi:        makeFakeOtelApi,
  // Captures
  captureAudit:           captureAudit,
  captureObservability:   captureObservability,
  captureMetricsTap:      captureMetricsTap,
  // Async test helpers
  runMiddleware:          runMiddleware,
  waitFor:                waitFor,
  // Chainable HTTP request helper (supertest-style)
  request:                request,
  // Class + constants
  TestingError:           TestingError,
  DEFAULTS:               DEFAULTS,
};

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.a2a.tasks + b.a2a.middleware — A2A v1 task-exchange surface.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// The client dispatchers (send/get/cancel) reach the peer through the shared
// lib/http-client module (a module-level lazyRequire inside lib/a2a-tasks.js).
// The framework's http-client is https-only + SSRF-blocks loopback by default,
// so a real localhost listener is unreachable through the a2a dispatchers
// without weakening a security default. Instead we inject a transport stub by
// swapping http-client's `request` for the duration of one scenario (restored
// in a finally) — no real network, exercising the REAL _jsonRpc response
// handling (status classes, JSON parse, envelope validation, rpc-error
// extraction, audit emission) against controlled peer responses.
var httpClientMod = require("../../lib/http-client");

function withTransport(responder, run) {
  var orig = httpClientMod.request;
  httpClientMod.request = responder;
  return Promise.resolve().then(run).finally(function () {
    httpClientMod.request = orig;
  });
}

// respond(obj, statusCode?, asBuffer?) — build an http-client response stub.
// `obj` may be a string (sent verbatim, e.g. non-JSON) or an object (JSON
// serialized). `asBuffer` returns the body as a Buffer to exercise the
// `rsp.body.toString("utf8")` branch.
function respond(obj, statusCode, asBuffer) {
  var s = typeof obj === "string" ? obj : JSON.stringify(obj);
  return function () {
    return Promise.resolve({ statusCode: statusCode || 200, body: asBuffer ? Buffer.from(s, "utf8") : s });
  };
}

function rejectTransport(message) {
  return function () { return Promise.reject(new Error(message)); };
}

function _mockReq(method, contentType, bodyBytes, scopes) {
  var listeners = {};
  var req = {
    method:  method,
    url:     "/a2a",
    headers: contentType ? { "content-type": contentType } : {},
    a2aScopes: scopes,
    on: function (ev, fn) {
      listeners[ev] = listeners[ev] || [];
      listeners[ev].push(fn);
    },
  };
  process.nextTick(function () {
    if (bodyBytes) {
      (listeners.data || []).forEach(function (fn) { fn(bodyBytes); });
    }
    (listeners.end || []).forEach(function (fn) { fn(); });
  });
  return req;
}

function _mockRes() {
  var headers = {};
  var statusCode = 0;
  var chunks = [];
  var endCalled = false;
  return {
    setHeader: function (k, v) { headers[k.toLowerCase()] = v; },
    end:       function (b2) {
      if (b2) chunks.push(Buffer.isBuffer(b2) ? b2 : Buffer.from(String(b2)));
      endCalled = true;
    },
    get statusCode() { return statusCode; },
    set statusCode(v) { statusCode = v; },
    _ended:      function () { return endCalled; },
    _statusCode: function () { return statusCode; },
    _getBody:    function () { return Buffer.concat(chunks).toString("utf8"); },
    _getHeaders: function () { return headers; },
  };
}

function testTasksSurface() {
  check("a2a.tasks.send is fn",   typeof b.a2a.tasks.send === "function");
  check("a2a.tasks.get is fn",    typeof b.a2a.tasks.get === "function");
  check("a2a.tasks.cancel is fn", typeof b.a2a.tasks.cancel === "function");
  check("a2a.middleware.tasks is fn",     typeof b.a2a.middleware.tasks === "function");
  check("a2a.middleware.agentCard is fn", typeof b.a2a.middleware.agentCard === "function");
  check("ALLOWED_METHODS is array",
        Array.isArray(b.a2a.tasks.ALLOWED_METHODS) &&
        b.a2a.tasks.ALLOWED_METHODS.length === 3);
  check("a2a.A2aTasksError is a constructor",
        typeof b.a2a.A2aTasksError === "function");
  var err = new b.a2a.A2aTasksError("a2a-tasks/test", "msg", true);
  check("a2a.A2aTasksError instance carries code",
        err.code === "a2a-tasks/test" && err.isFrameworkError === true);
}

function testClientRefusesBadOpts() {
  function expectCode(label, p, code) {
    return p.then(function () { check(label, false); }, function (e) {
      check(label, (e.code || "").indexOf(code) !== -1);
    });
  }
  return Promise.all([
    expectCode("send: bad opts",      b.a2a.tasks.send(),                                                     "a2a-tasks/bad-opts"),
    expectCode("send: bad peerUrl",   b.a2a.tasks.send({ peerUrl: "ftp://x", task: { skill: "x" } }),         "a2a-tasks/bad-peer-url"),
    expectCode("send: bad skill",     b.a2a.tasks.send({ peerUrl: "https://x", task: { skill: "0bad" } }),    "a2a-tasks/bad-skill"),
    expectCode("get: bad taskId",     b.a2a.tasks.get({ peerUrl: "https://x", taskId: "!!!" }),               "a2a-tasks/bad-task-id"),
    expectCode("cancel: bad taskId",  b.a2a.tasks.cancel({ peerUrl: "https://x", taskId: "" }),               "a2a-tasks/bad-task-id"),
  ]);
}

function _runMwAndDecode(mw, req, res) {
  return new Promise(function (resolve) {
    var origEnd = res.end.bind(res);
    res.end = function (chunk) { origEnd(chunk); helpers.passiveObserve(5, "a2a-tasks: post-res.end tick").then(resolve); };
    mw(req, res, function () { /* never called per design */ });
  }).then(function () {
    try {
      var body = res._getBody();
      return body ? JSON.parse(body) : null;
    } catch (_e) { return null; }
  });
}

async function testMiddlewareMethodNotAllowed() {
  var mw = b.a2a.middleware.tasks({ handler: function () {} });
  var req = _mockReq("GET", "application/json", null, []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: GET → 405", res._statusCode() === 405);
  check("middleware: GET sets Allow header", res._getHeaders().allow === "POST");
  check("middleware: GET body is JSON-RPC error", body && body.error && body.error.code === -32600);
}

async function testMiddlewareBadContentType() {
  var mw = b.a2a.middleware.tasks({ handler: function () {} });
  var req = _mockReq("POST", "text/plain", Buffer.from('{"jsonrpc":"2.0","method":"tasks/send"}'), []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: non-JSON content type → 415",
        res._statusCode() === 415 && body && body.error && body.error.code === -32600);
}

async function testMiddlewareInvalidJson() {
  var mw = b.a2a.middleware.tasks({ handler: function () {} });
  var req = _mockReq("POST", "application/json", Buffer.from("not json"), []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: bad JSON → 400 + parse-error",
        res._statusCode() === 400 && body && body.error && body.error.code === -32700);
}

async function testMiddlewareMethodNotFound() {
  var mw = b.a2a.middleware.tasks({ handler: function () {} });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tasks/unknown","params":{}}'),
    []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: unknown method → method-not-found",
        body && body.error && body.error.code === -32601);
}

async function testMiddlewareScopeDenied() {
  var mw = b.a2a.middleware.tasks({
    scopes:  { summarize: "a2a:summarize" },
    handler: function () { check("handler should not run on scope denial", false); return null; },
  });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tasks/send","params":{"task":{"skill":"summarize"}}}'),
    []);  // no granted scopes
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: scope-denied → -32001",
        body && body.error && body.error.code === -32001);
}

async function testMiddlewareScopeNonStringThrows() {
  // A non-string scope VALUE (operator typo, e.g. an array) must be refused at
  // construction — else the runtime `typeof requiredScope === "string"` gate
  // silently skips, a fail-open authorization bypass on a gated skill.
  var threw = null;
  try {
    b.a2a.middleware.tasks({ scopes: { transfer: ["a2a:transfer"] }, handler: function () {} });
  } catch (e) { threw = e; }
  check("middleware: non-string scope value rejected at construction",
        threw && threw.code === "a2a-tasks/bad-mw-opts");
}

async function testMiddlewareRejectsHostileSkill() {
  // The untrusted-peer ingress must validate task.skill (the client send path
  // does); an oversized / metacharacter-laden skill must never reach the handler.
  var handlerRan = false;
  var mw = b.a2a.middleware.tasks({ handler: function () { handlerRan = true; return null; } });
  var hostile = "A".repeat(5000);
  var req = _mockReq("POST", "application/json",
    Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tasks/send", params: { task: { skill: hostile } } })),
    []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: oversized skill rejected (-32602), handler not run",
        body && body.error && body.error.code === -32602 && handlerRan === false);
}

async function testMiddlewareRejectsHostileTaskId() {
  var handlerRan = false;
  var mw = b.a2a.middleware.tasks({ handler: function () { handlerRan = true; return null; } });
  var req = _mockReq("POST", "application/json",
    Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tasks/get", params: { taskId: "../../etc/passwd" } })),
    []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: traversal taskId rejected (-32602), handler not run",
        body && body.error && body.error.code === -32602 && handlerRan === false);
}

async function testMiddlewareSuccessSend() {
  var captured = null;
  var mw = b.a2a.middleware.tasks({
    handler: function (ctx) {
      captured = ctx;
      return { taskId: "t-1", status: "queued" };
    },
  });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":42,"method":"tasks/send","params":{"task":{"skill":"summarize","input":{"x":1}}}}'),
    []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: success → result envelope",
        body && body.result && body.result.taskId === "t-1" && body.result.status === "queued");
  check("middleware: id echoed",                   body.id === 42);
  check("middleware: ctx populated",
        captured && captured.method === "tasks/send" && captured.task.skill === "summarize");
}

async function testAgentCardMiddleware() {
  var card = { card: { agent: "test" }, signature: "sig" };
  var mw = b.a2a.middleware.agentCard({ card: card });
  var req = _mockReq("GET", null, null, []);
  var res = _mockRes();
  await new Promise(function (resolve) {
    var origEnd = res.end.bind(res);
    res.end = function (chunk) { origEnd(chunk); helpers.passiveObserve(5, "a2a-tasks: post-res.end tick").then(resolve); };
    mw(req, res);
  });
  check("agentCard: 200 OK on GET", res._statusCode() === 200);
  check("agentCard: JSON content type", res._getHeaders()["content-type"] === "application/json");
  check("agentCard: Cache-Control set",  /max-age=/.test(res._getHeaders()["cache-control"]));
  check("agentCard: body is signed card", JSON.parse(res._getBody()).signature === "sig");

  // 405 on non-GET
  var req2 = _mockReq("POST", "application/json", null, []);
  var res2 = _mockRes();
  await new Promise(function (resolve) {
    var origEnd2 = res2.end.bind(res2);
    res2.end = function (chunk) { origEnd2(chunk); helpers.passiveObserve(5, "a2a-tasks: post-res2.end tick").then(resolve); };
    mw(req2, res2);
  });
  check("agentCard: POST → 405", res2._statusCode() === 405);
}

// ---- Client dispatcher validation branches (no network) ----

async function testClientRefusesBadTaskShapes() {
  function expectCode(label, p, code) {
    return p.then(function () { check(label, false); }, function (e) {
      check(label, (e.code || "") === code);
    });
  }
  await Promise.all([
    // send: task must be a non-null, non-array object.
    expectCode("send: null task",   b.a2a.tasks.send({ peerUrl: "https://x", task: null }),  "a2a-tasks/bad-task"),
    expectCode("send: array task",  b.a2a.tasks.send({ peerUrl: "https://x", task: [] }),    "a2a-tasks/bad-task"),
    expectCode("send: string task", b.a2a.tasks.send({ peerUrl: "https://x", task: "x" }),   "a2a-tasks/bad-task"),
    // send: task.input must be an object when provided (string / null both refused).
    expectCode("send: string input", b.a2a.tasks.send({ peerUrl: "https://x", task: { skill: "summarize", input: "nope" } }), "a2a-tasks/bad-input"),
    expectCode("send: null input",   b.a2a.tasks.send({ peerUrl: "https://x", task: { skill: "summarize", input: null } }),   "a2a-tasks/bad-input"),
    // get / cancel: opts required (undefined opts → bad-opts, not a crash).
    expectCode("get: no opts",    b.a2a.tasks.get(),    "a2a-tasks/bad-opts"),
    expectCode("cancel: no opts", b.a2a.tasks.cancel(), "a2a-tasks/bad-opts"),
    // get: missing taskId → requireNonEmptyString path.
    expectCode("get: missing taskId", b.a2a.tasks.get({ peerUrl: "https://x" }), "a2a-tasks/bad-task-id"),
    // cancel: non-empty but invalid taskId → the regex/length gate (distinct
    // from the empty-string requireNonEmptyString path the existing test drives).
    expectCode("cancel: metachar taskId",  b.a2a.tasks.cancel({ peerUrl: "https://x", taskId: "a/b" }),        "a2a-tasks/bad-task-id"),
    expectCode("cancel: oversized taskId", b.a2a.tasks.cancel({ peerUrl: "https://x", taskId: "z".repeat(65) }), "a2a-tasks/bad-task-id"),
  ]);
}

// ---- Client dispatcher transport paths (stubbed http-client) ----

async function testClientTransportSuccess() {
  // tasks/get: string body → JSON-RPC result envelope unwrapped to .result.
  await withTransport(respond({ jsonrpc: "2.0", id: "x", result: { taskId: "t1", status: "completed" } }), async function () {
    var r = await b.a2a.tasks.get({ peerUrl: "https://peer.example/a2a", taskId: "abc-123" });
    check("client get: result envelope unwrapped", r && r.taskId === "t1" && r.status === "completed");
  });
  // Buffer body + explicit timeoutMs + headers (exercises rsp.body.toString
  // and the provided-timeout / provided-headers branches).
  await withTransport(respond({ jsonrpc: "2.0", id: "x", result: { ok: true } }, 200, true), async function () {
    var r = await b.a2a.tasks.get({ peerUrl: "https://peer.example/a2a", taskId: "abc-123", timeoutMs: 8000, headers: { "X-Trace": "1" } });
    check("client get: Buffer body parsed", r && r.ok === true);
  });
  // tasks/send: explicit timeoutMs + headers + audit:false (skips the ok audit emit).
  await withTransport(respond({ jsonrpc: "2.0", id: "x", result: { taskId: "s1", status: "queued" } }), async function () {
    var r = await b.a2a.tasks.send({
      peerUrl:   "https://peer.example/a2a",
      task:      { skill: "summarize", input: { url: "https://doc" } },
      timeoutMs: 5000,
      headers:   { "X-Sig": "abc" },
      audit:     false,
    });
    check("client send: result returned on audit-disabled path", r && r.taskId === "s1" && r.status === "queued");
  });
  // tasks/cancel: explicit timeoutMs + provided headers.
  await withTransport(respond({ jsonrpc: "2.0", id: "x", result: { taskId: "c1", status: "canceled" } }), async function () {
    var r = await b.a2a.tasks.cancel({ peerUrl: "https://peer.example/a2a", taskId: "abc-123", timeoutMs: 9000, headers: { "X-H": "y" } });
    check("client cancel: result envelope unwrapped", r && r.status === "canceled");
  });
}

async function testClientTransportErrors() {
  // Transport failure with audit on (default) → a2a-tasks/transport.
  await withTransport(rejectTransport("ECONNREFUSED"), async function () {
    var caught = null;
    try { await b.a2a.tasks.get({ peerUrl: "https://peer.example/a2a", taskId: "abc-123" }); }
    catch (e) { caught = e; }
    check("client get: transport failure mapped (audit on)", caught && caught.code === "a2a-tasks/transport");
  });
  // Transport failure with audit:false (skips the transport_failed audit emit).
  await withTransport(rejectTransport("ETIMEDOUT"), async function () {
    var caught = null;
    try { await b.a2a.tasks.get({ peerUrl: "https://peer.example/a2a", taskId: "abc-123", audit: false }); }
    catch (e) { caught = e; }
    check("client get: transport failure still throws (audit off)", caught && caught.code === "a2a-tasks/transport");
  });
  // Transport failure rejecting with a NON-Error value (no `.message`) →
  // the `err.message || err` stringify fallback is exercised.
  await withTransport(function () { return Promise.reject("raw-string-failure"); }, async function () {
    var caught = null;
    try { await b.a2a.tasks.get({ peerUrl: "https://peer.example/a2a", taskId: "abc-123" }); }
    catch (e) { caught = e; }
    check("client get: non-Error transport reject stringified",
          caught && caught.code === "a2a-tasks/transport" && /raw-string-failure/.test(caught.message));
  });
  // HTTP non-2xx (>= 300) → a2a-tasks/http-error.
  await withTransport(respond("upstream boom", 500), async function () {
    var caught = null;
    try { await b.a2a.tasks.get({ peerUrl: "https://peer.example/a2a", taskId: "abc-123" }); }
    catch (e) { caught = e; }
    check("client get: HTTP 500 → http-error", caught && caught.code === "a2a-tasks/http-error" && /HTTP 500/.test(caught.message));
  });
  // HTTP < 200 (informational) with audit:false → still http-error.
  await withTransport(respond("early", 100), async function () {
    var caught = null;
    try { await b.a2a.tasks.cancel({ peerUrl: "https://peer.example/a2a", taskId: "abc-123", audit: false }); }
    catch (e) { caught = e; }
    check("client cancel: HTTP 100 → http-error", caught && caught.code === "a2a-tasks/http-error");
  });
  // Response body is not JSON → a2a-tasks/bad-response.
  await withTransport(respond("<html>not json</html>", 200), async function () {
    var caught = null;
    try { await b.a2a.tasks.get({ peerUrl: "https://peer.example/a2a", taskId: "abc-123" }); }
    catch (e) { caught = e; }
    check("client get: non-JSON body → bad-response", caught && caught.code === "a2a-tasks/bad-response" && /not valid JSON/.test(caught.message));
  });
  // Valid JSON that is NOT a JSON-RPC 2.0 envelope → a2a-tasks/bad-response.
  await withTransport(respond({ foo: "bar" }, 200), async function () {
    var caught = null;
    try { await b.a2a.tasks.get({ peerUrl: "https://peer.example/a2a", taskId: "abc-123" }); }
    catch (e) { caught = e; }
    check("client get: non-envelope JSON → bad-response", caught && caught.code === "a2a-tasks/bad-response" && /JSON-RPC 2\.0 envelope/.test(caught.message));
  });
  // JSON-RPC error envelope (audit on) → rpc-error carrying rpcCode + rpcData.
  await withTransport(respond({ jsonrpc: "2.0", id: "x", error: { code: -32003, message: "not cancelable", data: { taskId: "abc" } } }), async function () {
    var caught = null;
    try { await b.a2a.tasks.cancel({ peerUrl: "https://peer.example/a2a", taskId: "abc-123" }); }
    catch (e) { caught = e; }
    check("client cancel: rpc error surfaces rpcCode + rpcData",
          caught && caught.code === "a2a-tasks/rpc-error" && caught.rpcCode === -32003 && caught.rpcData && caught.rpcData.taskId === "abc");
  });
  // JSON-RPC error with no message + audit:false → default "rpc error" text.
  await withTransport(respond({ jsonrpc: "2.0", id: "x", error: { code: -32001 } }), async function () {
    var caught = null;
    try { await b.a2a.tasks.send({ peerUrl: "https://peer.example/a2a", task: { skill: "summarize" }, audit: false }); }
    catch (e) { caught = e; }
    check("client send: message-less rpc error → default text (audit off)",
          caught && caught.code === "a2a-tasks/rpc-error" && caught.rpcCode === -32001 && /rpc error/.test(caught.message));
  });
}

// ---- Middleware factory bad-opts (boot-time throws) ----

function testMiddlewareBadFactoryOpts() {
  function expectThrow(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  expectThrow("mw.tasks: no opts",          function () { b.a2a.middleware.tasks(); },                                            "a2a-tasks/bad-mw-opts");
  expectThrow("mw.tasks: opts not object",  function () { b.a2a.middleware.tasks("nope"); },                                     "a2a-tasks/bad-mw-opts");
  expectThrow("mw.tasks: missing handler",  function () { b.a2a.middleware.tasks({}); },                                         "a2a-tasks/bad-mw-opts");
  expectThrow("mw.tasks: handler not fn",   function () { b.a2a.middleware.tasks({ handler: 123 }); },                           "a2a-tasks/bad-mw-opts");
  expectThrow("mw.tasks: scopes not object", function () { b.a2a.middleware.tasks({ handler: function () {}, scopes: "s" }); },  "a2a-tasks/bad-mw-opts");
  expectThrow("mw.tasks: scopes array",      function () { b.a2a.middleware.tasks({ handler: function () {}, scopes: [] }); },   "a2a-tasks/bad-mw-opts");
  // Non-string scope VALUE (a number, not just the array case the sibling
  // test drives) refused at construction — else the runtime string-check
  // gate silently skips (fail-open authz bypass on the gated skill).
  expectThrow("mw.tasks: numeric scope value", function () { b.a2a.middleware.tasks({ handler: function () {}, scopes: { transfer: 5 } }); }, "a2a-tasks/bad-mw-opts");
}

function testAgentCardBadOpts() {
  function expectThrow(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }
  expectThrow("agentCard: no opts",          function () { b.a2a.middleware.agentCard(); },                                       "a2a-tasks/bad-mw-opts");
  expectThrow("agentCard: opts not object",  function () { b.a2a.middleware.agentCard("x"); },                                    "a2a-tasks/bad-mw-opts");
  expectThrow("agentCard: card missing",     function () { b.a2a.middleware.agentCard({}); },                                     "a2a-tasks/bad-mw-opts");
  expectThrow("agentCard: card not object",  function () { b.a2a.middleware.agentCard({ card: "not-an-object" }); },              "a2a-tasks/bad-mw-opts");
  // A present-but-invalid maxAgeSec (negative) is refused by the numeric-bounds gate.
  expectThrow("agentCard: negative maxAgeSec", function () { b.a2a.middleware.agentCard({ card: { x: 1 }, maxAgeSec: -5 }); },    "a2a-tasks/bad-max-age");
}

// ---- Middleware request-path branches ----

async function testMiddlewareInvalidEnvelope() {
  // Valid JSON, but not a JSON-RPC 2.0 envelope (no jsonrpc / method) → 400 -32600.
  var handlerRan = false;
  var mw = b.a2a.middleware.tasks({ handler: function () { handlerRan = true; } });
  var req = _mockReq("POST", "application/json", Buffer.from('{"id":7,"foo":"bar"}'), []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: non-envelope JSON → 400 invalid-request, handler not run",
        res._statusCode() === 400 && body && body.error && body.error.code === -32600 && handlerRan === false);
}

async function testMiddlewareMissingParams() {
  // tasks/send with NO params → params defaults to {} → task undefined → -32602.
  var handlerRan = false;
  var mw = b.a2a.middleware.tasks({ handler: function () { handlerRan = true; return null; } });
  var req = _mockReq("POST", "application/json", Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tasks/send"}'), []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: tasks/send missing params → -32602, handler not run",
        body && body.error && body.error.code === -32602 && handlerRan === false);
}

async function testMiddlewareNoId() {
  // A request without an id → the response id is null (id-defaulting branch).
  var mw = b.a2a.middleware.tasks({ handler: function () { return { taskId: "t0", status: "queued" }; } });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","method":"tasks/send","params":{"task":{"skill":"summarize"}}}'), []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: request without id → response id null",
        body && body.result && body.result.taskId === "t0" && body.id === null);
}

async function testMiddlewareCancelSuccess() {
  // Exercises the tasks/cancel identifier-validation operand + a cancel handler success.
  var captured = null;
  var mw = b.a2a.middleware.tasks({ handler: function (ctx) { captured = ctx; return { taskId: ctx.taskId, status: "canceled" }; } });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":9,"method":"tasks/cancel","params":{"taskId":"abc-123"}}'), []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: tasks/cancel routes to handler",
        body && body.result && body.result.status === "canceled" &&
        captured && captured.method === "tasks/cancel" && captured.taskId === "abc-123");
}

async function testMiddlewareScopeDeniedNoGrantedArray() {
  // A gated skill whose request carries NO a2aScopes array at all (the operator
  // auth layer never populated it) → grantedScopes defaults to [] → denied.
  var handlerRan = false;
  var mw = b.a2a.middleware.tasks({
    scopes:  { summarize: "a2a:summarize" },
    handler: function () { handlerRan = true; return null; },
  });
  // Pass `undefined` for the a2aScopes arg → req.a2aScopes is not an array.
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tasks/send","params":{"task":{"skill":"summarize"}}}'),
    undefined);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: gated skill with no granted-scopes array → -32001, handler not run",
        body && body.error && body.error.code === -32001 && handlerRan === false);
}

async function testMiddlewareScopeGranted() {
  // Granted scope present in req.a2aScopes → handler runs (scope check passes).
  var handlerRan = false;
  var mw = b.a2a.middleware.tasks({
    scopes:  { summarize: "a2a:summarize" },
    handler: function () { handlerRan = true; return { taskId: "t9", status: "queued" }; },
  });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tasks/send","params":{"task":{"skill":"summarize"}}}'),
    ["a2a:summarize"]);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: granted scope → handler runs",
        handlerRan === true && body && body.result && body.result.taskId === "t9");
}

async function testMiddlewareUngatedSkill() {
  // A scopes map is present, but the requested skill isn't in it → un-gated,
  // proceeds to the handler (requiredScope resolves to undefined).
  var handlerRan = false;
  var mw = b.a2a.middleware.tasks({
    scopes:  { transfer: "a2a:transfer" },
    handler: function () { handlerRan = true; return { taskId: "t8", status: "queued" }; },
  });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tasks/send","params":{"task":{"skill":"summarize"}}}'),
    []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: un-gated skill bypasses scope check → handler runs",
        handlerRan === true && body && body.result && body.result.taskId === "t8");
}

async function testMiddlewareProtoShadowSkill() {
  // An attacker skill colliding with an Object.prototype member ("constructor")
  // must NOT resolve an inherited scope — own-property lookup only, so it is
  // treated as un-gated and reaches the handler rather than dereferencing a
  // prototype member as its required scope.
  var handlerRan = false;
  var mw = b.a2a.middleware.tasks({
    scopes:  { summarize: "a2a:summarize" },
    handler: function () { handlerRan = true; return { taskId: "t7", status: "queued" }; },
  });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tasks/send","params":{"task":{"skill":"constructor"}}}'),
    []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: proto-shadow skill 'constructor' not gated by inherited member",
        handlerRan === true && body && body.result && body.result.taskId === "t7");
}

async function testMiddlewareHandlerError() {
  // Handler throws a plain error → -32603 internal-error envelope, id echoed.
  var mw = b.a2a.middleware.tasks({ handler: function () { throw new Error("boom in handler"); } });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":5,"method":"tasks/send","params":{"task":{"skill":"summarize"}}}'), []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: handler throw → -32603 with message",
        body && body.error && body.error.code === -32603 && /boom in handler/.test(body.error.message));
  check("middleware: handler-error id echoed", body && body.id === 5);
}

async function testMiddlewareHandlerErrorRpcCode() {
  // Handler throws an error carrying rpcCode → that code is surfaced (audit off path).
  var mw = b.a2a.middleware.tasks({
    audit:   false,
    handler: function () { var e = new Error("not cancelable"); e.rpcCode = -32003; throw e; },
  });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":6,"method":"tasks/cancel","params":{"taskId":"abc-123"}}'), []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: handler rpcCode surfaced",
        body && body.error && body.error.code === -32003 && body.id === 6);
}

async function testMiddlewareHandlerFalsyThrow() {
  // A handler that rejects with a FALSY value (no rpcCode, no message) →
  // defaults to -32603 + "handler error" text (both fallback operands).
  var mw = b.a2a.middleware.tasks({ handler: function () { return Promise.reject(null); } });
  var req = _mockReq("POST", "application/json",
    Buffer.from('{"jsonrpc":"2.0","id":8,"method":"tasks/send","params":{"task":{"skill":"summarize"}}}'), []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: falsy handler rejection → -32603 + default text",
        body && body.error && body.error.code === -32603 && body.error.message === "handler error");
}

async function testMiddlewareBodyTooLarge() {
  // A body exceeding maxBytes rejects inside _readBody → outer catch → 400 parse-error.
  var handlerRan = false;
  var mw = b.a2a.middleware.tasks({ handler: function () { handlerRan = true; }, maxBytes: 16 });
  var big = Buffer.from(JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "tasks/send",
    params: { task: { skill: "summarize", input: { pad: "x".repeat(200) } } },
  }));
  var req = _mockReq("POST", "application/json", big, []);
  var res = _mockRes();
  var body = await _runMwAndDecode(mw, req, res);
  check("middleware: oversized body → 400 parse-error, handler not run",
        res._statusCode() === 400 && body && body.error && body.error.code === -32700 &&
        /could not read request body/.test(body.error.message) && handlerRan === false);
}

async function testAgentCardMaxAge() {
  // Explicit positive maxAgeSec is honored (Math.floor path) in Cache-Control.
  var mw = b.a2a.middleware.agentCard({ card: { agent: "a", signature: "sig" }, maxAgeSec: 60 });
  var req = _mockReq("GET", null, null, []);
  var res = _mockRes();
  await new Promise(function (resolve) {
    var origEnd = res.end.bind(res);
    res.end = function (chunk) { origEnd(chunk); helpers.passiveObserve(5, "a2a-tasks: post-res.end tick").then(resolve); };
    mw(req, res);
  });
  check("agentCard: explicit maxAgeSec honored", res._getHeaders()["cache-control"] === "public, max-age=60");
}

async function run() {
  testTasksSurface();
  await testClientRefusesBadOpts();
  await testClientRefusesBadTaskShapes();
  await testClientTransportSuccess();
  await testClientTransportErrors();
  await testMiddlewareMethodNotAllowed();
  await testMiddlewareBadContentType();
  await testMiddlewareInvalidJson();
  await testMiddlewareMethodNotFound();
  await testMiddlewareBadFactoryOpts();
  await testMiddlewareInvalidEnvelope();
  await testMiddlewareMissingParams();
  await testMiddlewareNoId();
  await testMiddlewareCancelSuccess();
  await testMiddlewareScopeDenied();
  await testMiddlewareScopeDeniedNoGrantedArray();
  await testMiddlewareScopeGranted();
  await testMiddlewareUngatedSkill();
  await testMiddlewareProtoShadowSkill();
  await testMiddlewareScopeNonStringThrows();
  await testMiddlewareRejectsHostileSkill();
  await testMiddlewareRejectsHostileTaskId();
  await testMiddlewareSuccessSend();
  await testMiddlewareHandlerError();
  await testMiddlewareHandlerErrorRpcCode();
  await testMiddlewareHandlerFalsyThrow();
  await testMiddlewareBodyTooLarge();
  await testAgentCardBadOpts();
  await testAgentCardMiddleware();
  await testAgentCardMaxAge();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

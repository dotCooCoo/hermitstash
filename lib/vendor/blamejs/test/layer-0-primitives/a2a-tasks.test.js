"use strict";
/**
 * b.a2a.tasks + b.a2a.middleware — A2A v1 task-exchange surface.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

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

async function run() {
  testTasksSurface();
  await testClientRefusesBadOpts();
  await testMiddlewareMethodNotAllowed();
  await testMiddlewareBadContentType();
  await testMiddlewareInvalidJson();
  await testMiddlewareMethodNotFound();
  await testMiddlewareScopeDenied();
  await testMiddlewareScopeNonStringThrows();
  await testMiddlewareRejectsHostileSkill();
  await testMiddlewareRejectsHostileTaskId();
  await testMiddlewareSuccessSend();
  await testAgentCardMiddleware();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

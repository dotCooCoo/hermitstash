"use strict";
/**
 * b.middleware.idempotencyKey — draft-ietf-httpapi-idempotency-key.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockReq(method, url, key, body) {
  return {
    method:  method,
    url:     url,
    headers: key ? { "idempotency-key": key } : {},
    body:    body,
  };
}

function _mockRes() {
  var headers = {};
  var chunks = [];
  var statusCode = 200;
  var endCalled = false;
  return {
    setHeader: function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader: function (k) { return headers[k.toLowerCase()]; },
    getHeaders: function () { return Object.assign({}, headers); },
    write:     function (chunk) { chunks.push(Buffer.from(chunk)); },
    end:       function (chunk) {
      if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      endCalled = true;
    },
    get statusCode() { return statusCode; },
    set statusCode(v) { statusCode = v; },
    _getBody:    function () { return Buffer.concat(chunks).toString("utf8"); },
    _getHeaders: function () { return headers; },
    _ended:      function () { return endCalled; },
    _statusCode: function () { return statusCode; },
  };
}

function testSurface() {
  check("idempotencyKey is a function",            typeof b.middleware.idempotencyKey === "function");
  check("idempotencyKey.memoryStore is a function", typeof b.middleware.idempotencyKey.memoryStore === "function");
  check("idempotencyKey.DEFAULT_METHODS is array",  Array.isArray(b.middleware.idempotencyKey.DEFAULT_METHODS));
}

function testBadOpts() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("idempotencyKey: bad opts null", function () { b.middleware.idempotencyKey(null); }, "idempotency/bad-opts");
  expectCode("idempotencyKey: missing store", function () { b.middleware.idempotencyKey({}); }, "idempotency/bad-store");
  expectCode("idempotencyKey: bad store interface", function () { b.middleware.idempotencyKey({ store: {} }); }, "idempotency/bad-store");
}

function testMethodSkipsGet() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });
  var req = _mockReq("GET", "/x");
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("GET is pass-through (skips middleware)", nextCalled === true);
}

function testMissingKeyDefault() {
  // Without requireIdempotencyKey, missing key is a pass-through.
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });
  var req = _mockReq("POST", "/x");
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("POST without key + require:false → next()", nextCalled === true);
}

function testMissingKeyRequired() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, requireIdempotencyKey: true });
  var req = _mockReq("POST", "/x");
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("POST without key + require:true → 400 problem-details, no next()",
        !nextCalled && res._statusCode() === 400 &&
        res._getHeaders()["content-type"] === "application/problem+json");
  var body = JSON.parse(res._getBody());
  check("missing-key problem type",
        /\/idempotency\/missing-key$/.test(body.type));
}

function testBadKeyShape() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });
  var req = _mockReq("POST", "/x", "bad\x01key");  // control char
  var res = _mockRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  check("bad-key control char → 400 problem-details",
        !nextCalled && res._statusCode() === 400);
  var body = JSON.parse(res._getBody());
  check("bad-key problem type",
        /\/idempotency\/bad-key$/.test(body.type));
}

function testMissThenReplay() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store, ttlMs: 60000 });

  // First call — miss. Handler runs.
  var req1 = _mockReq("POST", "/x", "key-abc-123");
  req1._rawBody = Buffer.from('{"a":1}');
  var res1 = _mockRes();
  var nextCalled = false;
  mw(req1, res1, function () { nextCalled = true; });
  check("miss: handler invoked via next()", nextCalled);
  // Simulate handler writing a response.
  res1.statusCode = 201;
  res1.setHeader("Content-Type", "application/json");
  res1.end('{"id":"42"}');

  check("miss: response written", res1._getBody() === '{"id":"42"}');
  check("miss: cache stored", store._size() === 1);

  // Second call — same key + same body → replay.
  var req2 = _mockReq("POST", "/x", "key-abc-123");
  req2._rawBody = Buffer.from('{"a":1}');
  var res2 = _mockRes();
  var next2Called = false;
  mw(req2, res2, function () { next2Called = true; });
  check("replay: handler NOT invoked",   !next2Called);
  check("replay: statusCode restored",   res2._statusCode() === 201);
  check("replay: body restored",         res2._getBody() === '{"id":"42"}');
  check("replay: Content-Type restored", res2._getHeaders()["content-type"] === "application/json");
}

function testFingerprintMismatch() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });

  // First call
  var req1 = _mockReq("POST", "/x", "key-conflict");
  req1._rawBody = Buffer.from('{"v":1}');
  var res1 = _mockRes();
  mw(req1, res1, function () {});
  res1.statusCode = 200;
  res1.end("ok");

  // Second call same key, DIFFERENT body
  var req2 = _mockReq("POST", "/x", "key-conflict");
  req2._rawBody = Buffer.from('{"v":2}');
  var res2 = _mockRes();
  var nextCalled = false;
  mw(req2, res2, function () { nextCalled = true; });
  check("fingerprint mismatch: 422 not handler",
        !nextCalled && res2._statusCode() === 422);
  var body = JSON.parse(res2._getBody());
  check("fingerprint mismatch: problem type",
        /\/idempotency\/key-reuse-mismatch$/.test(body.type));
}

function testSkip5xx() {
  var store = b.middleware.idempotencyKey.memoryStore();
  var mw = b.middleware.idempotencyKey({ store: store });

  var req = _mockReq("POST", "/x", "key-server-err");
  req._rawBody = Buffer.from('{}');
  var res = _mockRes();
  mw(req, res, function () {});
  res.statusCode = 500;
  res.end("server error");

  check("5xx not cached (transient infra failure)", store._size() === 0);
}

function testMemoryStoreFIFO() {
  var store = b.middleware.idempotencyKey.memoryStore({ maxEntries: 2 });
  store.set("a", { fingerprint: "f1", statusCode: 200, headers: {}, body: "" }, 60000);
  store.set("b", { fingerprint: "f2", statusCode: 200, headers: {}, body: "" }, 60000);
  store.set("c", { fingerprint: "f3", statusCode: 200, headers: {}, body: "" }, 60000);
  check("memoryStore FIFO: oldest evicted",
        store._size() === 2 && store.get("a") === null && store.get("c") !== null);
}

function testMemoryStoreTtlExpiry() {
  var store = b.middleware.idempotencyKey.memoryStore();
  store.set("expiring", { fingerprint: "f1", statusCode: 200, headers: {}, body: "" }, 1);
  // Force a small wait so TTL passes.
  var start = Date.now();
  while (Date.now() - start < 5) { /* spin briefly */ }
  check("memoryStore TTL: expired returns null", store.get("expiring") === null);
}

async function run() {
  testSurface();
  testBadOpts();
  testMethodSkipsGet();
  testMissingKeyDefault();
  testMissingKeyRequired();
  testBadKeyShape();
  testMissThenReplay();
  testFingerprintMismatch();
  testSkip5xx();
  testMemoryStoreFIFO();
  testMemoryStoreTtlExpiry();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

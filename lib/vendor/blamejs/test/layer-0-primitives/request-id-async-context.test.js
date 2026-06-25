"use strict";
/**
 * b.middleware.requestId({ asyncContext: true }) — #353.
 *
 * The b.router dispatch model is boolean-`next`: the router awaits each
 * middleware, then runs the route handler in its own loop AFTER the middleware
 * returns. A middleware that wraps `next()` in an AsyncLocalStorage callback
 * (`als.run(store, () => next())`) therefore loses the binding the instant
 * `next()` returns — before any awaited handler code runs — so
 * `b.log.getRequestId()` reads null inside the handler. asyncContext:true binds
 * the id with `AsyncLocalStorage.enterWith` (via b.log.enterRequestId) so it
 * persists forward across the awaited route chain, while each request stays
 * isolated because the HTTP server runs each request in its own async context.
 *
 * Every request below goes through a real http.Server so the enterWith binding
 * is scoped to the request's own async context (driving app.handle() directly
 * from the test would leak the binding into the test runner's context — the
 * exact non-isolated manual-dispatch case enterWith is NOT meant for).
 */

var helpers = require("../helpers");
var http    = require("node:http");
var b       = helpers.b;
var check   = helpers.check;

// Spin up a one-route app on an ephemeral port, fire a single GET with the
// given inbound id, resolve { body, hdr }, then close the server.
function _serveOnce(mwOpts, id) {
  var app = b.router.create();
  app.use(b.middleware.requestId(mwOpts));
  app.get("/x", async function (req, res) {
    // Cross an event-loop turn (a real awaited gap) before reading the ALS, so
    // this exercises the boolean-next-dispatch survival the issue is about.
    await new Promise(function (r) { setImmediate(r); });
    res.end(JSON.stringify({ reqField: req.requestId, als: b.log.getRequestId() }));
  });
  var srv = http.createServer(function (req, res) { app.handle(req, res); });
  return new Promise(function (resolve, reject) {
    srv.listen(0, function () {
      var port = srv.address().port;
      http.get({ port: port, path: "/x", agent: false, headers: id ? { "x-request-id": id } : {} }, function (r) {
        var d = ""; r.on("data", function (c) { d += c; });
        // Await the server close so the listening handle is released before the
        // test resolves — a fire-and-forget srv.close() leaves a TCPServerWrap
        // lingering (the leak the harness audit flags).
        r.on("end", function () { srv.close(function () { resolve({ body: JSON.parse(d), hdr: r.headers["x-request-id"] }); }); });
      }).on("error", function (e) { srv.close(function () { reject(e); }); });
    });
  });
}

function testSurface() {
  check("b.log.enterRequestId is a function", typeof b.log.enterRequestId === "function");
  check("requestId factory is a function",    typeof b.middleware.requestId === "function");
}

// asyncContext:true binds the id into the log ALS so an awaited handler reads
// it via b.log.getRequestId().
async function testAsyncContextBindsAls() {
  var r = await _serveOnce({ asyncContext: true }, "abcdefgh-async-1");
  check("asyncContext: req.requestId set",                       r.body.reqField === "abcdefgh-async-1");
  check("asyncContext: getRequestId() works in awaited handler", r.body.als === "abcdefgh-async-1");
  check("asyncContext: response header reflected",               r.hdr === "abcdefgh-async-1");
}

// Default mode binds nothing — req.requestId is set but the ALS stays null.
async function testDefaultModeDoesNotBindAls() {
  var r = await _serveOnce({}, "plain-no-async-2");
  check("default: req.requestId still set", r.body.reqField === "plain-no-async-2");
  check("default: ALS NOT bound (null)",    r.body.als === null);
}

// The correctness crux: concurrent requests through a real server each see
// their OWN id via the ALS, with no cross-request bleed.
async function testConcurrentRequestsIsolated() {
  var app = b.router.create();
  app.use(b.middleware.requestId({ asyncContext: true }));
  app.get("/x", async function (req, res) {
    // A real awaited gap; the concurrency comes from the concurrent http.get
    // calls below (each request its own async context on a real server).
    await new Promise(function (r) { setImmediate(r); });
    res.end(JSON.stringify({ als: b.log.getRequestId() }));
  });
  var srv = http.createServer(function (req, res) { app.handle(req, res); });
  await new Promise(function (r) { srv.listen(0, r); });
  var port = srv.address().port;
  function get(id) {
    return new Promise(function (resolve) {
      http.get({ port: port, path: "/x", agent: false, headers: { "x-request-id": id } }, function (r) {
        var d = ""; r.on("data", function (c) { d += c; });
        r.on("end", function () { resolve({ id: id, body: JSON.parse(d), hdr: r.headers["x-request-id"] }); });
      });
    });
  }
  var results = await Promise.all([
    get("req-AAAAAA01"), get("req-BBBBBB02"), get("req-CCCCCC03"),
    get("req-DDDDDD04"), get("req-EEEEEE05"),
  ]);
  await new Promise(function (r) { srv.close(r); });   // release the listening handle
  var allIsolated = results.every(function (r) { return r.body.als === r.id; });
  check("concurrent: every request's ALS id is its own (no bleed)", allIsolated);
  var hdrsMatch = results.every(function (r) { return r.hdr === r.id; });
  check("concurrent: every response header matches its request", hdrsMatch);
}

async function run() {
  testSurface();
  await testAsyncContextBindsAls();
  await testDefaultModeDoesNotBindAls();
  await testConcurrentRequestsIsolated();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

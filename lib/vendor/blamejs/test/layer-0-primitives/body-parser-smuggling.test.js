"use strict";
/**
 * body-parser HTTP request-smuggling defense (RFC 9112 §6.1).
 *
 * Covers: TE+CL coexistence rejected (CVE-2022-31394 / CVE-2024-27316
 * class); multiple Content-Length values rejected; Transfer-Encoding
 * with non-`chunked` final coding rejected; duplicate `chunked` token
 * rejected (TE.TE smuggling). Each rejected request returns 400 with
 * Connection: close so the upstream proxy doesn't reuse the socket.
 */

var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var _bodyReq  = helpers._bodyReq;
var _bodyRes  = helpers._bodyRes;

function _runMiddleware(req, res) {
  var bp = b.middleware.bodyParser();
  return new Promise(function (resolve) {
    var settled = false;
    bp(req, res, function () {
      if (settled) return;
      settled = true;
      resolve({ next: true, status: res._endedStatus });
    });
    res.on("finish", function () {
      if (settled) return;
      settled = true;
      resolve({ next: false, status: res._endedStatus });
    });
    // Safety timeout so a missing finish/next doesn't hang the suite.
    setTimeout(function () {
      if (settled) return;
      settled = true;
      resolve({ next: false, status: res._endedStatus, timeout: true });
    }, 1500);
  });
}

async function testTeAndClConflictRejected() {
  var req = _bodyReq("POST", {
    "content-length":     "5",
    "transfer-encoding":  "chunked",
    "content-type":       "application/json",
  }, "");
  var res = _bodyRes();
  var rv = await _runMiddleware(req, res);
  check("TE+CL conflict → request rejected (no next())",
        rv.next === false);
  check("TE+CL conflict → 400 Bad Request",
        rv.status === 400);
  check("TE+CL conflict → Connection: close set",
        res._headers["Connection"] === "close" ||
        res._headers["connection"] === "close");
}

async function testMultipleContentLengthRejected() {
  // Node collapses duplicate Content-Length headers into a comma-
  // separated string. The smuggling defense MUST refuse.
  var req = _bodyReq("POST", {
    "content-length":  "5, 7",
    "content-type":    "application/json",
  }, "");
  var res = _bodyRes();
  var rv = await _runMiddleware(req, res);
  check("multiple CL → request rejected",
        rv.next === false && rv.status === 400);
}

async function testTeNotChunkedRejected() {
  var req = _bodyReq("POST", {
    "transfer-encoding": "gzip",
    "content-type":      "application/json",
  }, "");
  var res = _bodyRes();
  var rv = await _runMiddleware(req, res);
  check("TE final coding != chunked → rejected",
        rv.next === false && rv.status === 400);
}

async function testTeDuplicateChunkedRejected() {
  // TE.TE smuggling — `chunked, chunked` is RFC 9112 §6.1 forbidden.
  var req = _bodyReq("POST", {
    "transfer-encoding": "chunked, chunked",
    "content-type":      "application/json",
  }, "");
  var res = _bodyRes();
  var rv = await _runMiddleware(req, res);
  check("duplicate chunked token → rejected",
        rv.next === false && rv.status === 400);
}

async function testCleanRequestPasses() {
  var req = _bodyReq("POST", {
    "content-length": "13",
    "content-type":   "application/json",
  }, '{"hello":"x"}');
  var res = _bodyRes();
  var rv = await _runMiddleware(req, res);
  check("clean request (CL only, no smuggling shape) → next()",
        rv.next === true);
}

async function run() {
  await testTeAndClConflictRejected();
  await testMultipleContentLengthRejected();
  await testTeNotChunkedRejected();
  await testTeDuplicateChunkedRejected();
  await testCleanRequestPasses();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

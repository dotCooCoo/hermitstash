// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

async function _runMiddleware(req, res, bp) {
  bp = bp || b.middleware.bodyParser();
  // bodyParser settles by calling next() (parse succeeded) or by writing
  // the error response (res.writeHead/end → _endedStatus set, "finish"
  // emitted). Both can happen synchronously inside bp(), so the next()
  // flag is captured by callback and the response-write path is read off
  // res._endedStatus rather than relying on catching the finish event.
  // Poll the settled condition instead of racing a fixed sleep that
  // drifts under runner contention.
  var nextCalled = false;
  bp(req, res, function () { nextCalled = true; });
  await helpers.waitUntil(function () {
    return nextCalled || res._endedStatus !== null;
  }, {
    timeoutMs: 5000,
    label:     "body-parser-smuggling: bodyParser settled (next or response written)",
  });
  return { next: nextCalled, status: res._endedStatus };
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

// A malformed-JSON 400 flows through the generic _writeError path (not
// the smuggling/chunked inline writers). It must also carry Connection:
// close so an upstream proxy can't reuse a socket whose request stream
// the parser abandoned mid-body (RFC 9112 §9.6).
async function testGenericErrorSetsConnectionClose() {
  var body = "{ not valid json";
  var req = _bodyReq("POST", {
    "content-length": String(Buffer.byteLength(body)),
    "content-type":   "application/json",
  }, body);
  var res = _bodyRes();
  var rv = await _runMiddleware(req, res);
  check("malformed JSON → 400 via _writeError",
        rv.next === false && rv.status === 400);
  check("malformed JSON 400 → Connection: close set",
        res._headers["Connection"] === "close" ||
        res._headers["connection"] === "close");
}

// RFC 5987 / 2231 filename* charset gating. utf-8 is always decoded; a
// `filename*=ISO-8859-1''...` part is refused by default (falls back to
// the legacy `filename=` companion) and decoded only when the operator
// opts iso-8859-1 into multipart.filenameCharsets.
function _multipartIso8859Body(boundary) {
  // filename* uses ISO-8859-1 percent-encoding: r%E9sum%E9 → "résumé".
  // A legacy filename= companion provides the default-path fallback.
  return Buffer.from(
    "--" + boundary + "\r\n" +
    "Content-Disposition: form-data; name=\"doc\"; " +
      "filename=\"fallback.txt\"; filename*=ISO-8859-1''r%E9sum%E9.txt\r\n" +
    "Content-Type: text/plain\r\n" +
    "\r\n" +
    "hello\r\n" +
    "--" + boundary + "--\r\n",
    "latin1"
  );
}

async function _runMultipart(bp, boundary, body) {
  var req = _bodyReq("POST", {
    "content-type":   "multipart/form-data; boundary=" + boundary,
    "content-length": String(body.length),
  }, body);
  var res = _bodyRes();
  // bodyParser settles by calling next() (parse succeeded) or by writing
  // the error response (res "finish"). Poll the settled flag instead of
  // racing a fixed sleep that drifts under runner contention.
  var settled = false;
  bp(req, res, function () { settled = true; });
  res.on("finish", function () { settled = true; });
  await helpers.waitUntil(function () { return settled; }, {
    timeoutMs: 5000,
    label:     "body-parser-smuggling: bodyParser settled (next or response finish)",
  });
  return req;
}

async function testFilenameCharsetsDefaultRefusesIso8859() {
  var boundary = "bptest1";
  var bp = b.middleware.bodyParser({ multipart: { storage: "memory" } });
  var req = await _runMultipart(bp, boundary, _multipartIso8859Body(boundary));
  check("default: a file part was parsed",
        Array.isArray(req.files) && req.files.length === 1);
  check("default: iso-8859-1 filename* refused → legacy filename= wins",
        req.files[0].filename === "fallback.txt");
}

async function testFilenameCharsetsOptInDecodesIso8859() {
  var boundary = "bptest2";
  var bp = b.middleware.bodyParser({
    multipart: { storage: "memory", filenameCharsets: ["utf-8", "iso-8859-1"] },
  });
  var req = await _runMultipart(bp, boundary, _multipartIso8859Body(boundary));
  check("opt-in: a file part was parsed",
        Array.isArray(req.files) && req.files.length === 1);
  check("opt-in: iso-8859-1 filename* decoded to résumé.txt",
        req.files[0].filename === "résumé.txt");
}

async function run() {
  await testTeAndClConflictRejected();
  await testMultipleContentLengthRejected();
  await testTeNotChunkedRejected();
  await testTeDuplicateChunkedRejected();
  await testCleanRequestPasses();
  await testGenericErrorSetsConnectionClose();
  await testFilenameCharsetsDefaultRefusesIso8859();
  await testFilenameCharsetsOptInDecodesIso8859();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

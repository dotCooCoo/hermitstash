// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * body-parser malformed-chunked-encoding close hook.
 *
 * RFC 9112 §7.1 — when a server rejects a chunked-decoded body (Node's
 * HTTP parser surfaces HPE_INVALID_CHUNK_SIZE / HPE_INVALID_TRANSFER_
 * ENCODING / HPE_INVALID_EOF_STATE) it MUST close the connection so a
 * downstream proxy cannot reuse the socket with the next request's
 * bytes still in flight. The body parser closes the response with
 * Connection: close + audits http.chunked.malformed.refused + tears
 * down the socket via req.destroy().
 */

var EventEmitter = require("events").EventEmitter;
var helpers      = require("../helpers");
var b            = helpers.b;
var check        = helpers.check;
var _bodyRes     = helpers._bodyRes;

// Build a body-shaped req that does NOT auto-emit end — leaves the
// parser awaiting bytes so the test can synthesize an HPE_* error
// from a fake Node HTTP-parser failure.
function _chunkedReq(headers) {
  var req = new EventEmitter();
  req.method  = "POST";
  req.url     = "/";
  req.headers = Object.assign({}, headers || {});
  req.socket  = { remoteAddress: "127.0.0.1" };
  req._destroyed = false;
  req.destroy = function () { req._destroyed = true; };
  return req;
}

function _runWithError(headers, parserError) {
  var bp  = b.middleware.bodyParser();
  var req = _chunkedReq(headers);
  var res = _bodyRes();
  // The parser settles by calling next() or by ending the response after the
  // emitted error. Wrap in withTestTimeout so a parser that hangs becomes a
  // hard "test timed out" reject (1500ms budget) instead of stalling the
  // suite — its guard timer clears on settle, so no Timeout handle lingers.
  return helpers.withTestTimeout("body-parser: malformed-body parser settles", function () {
    return new Promise(function (resolve) {
      var settled = false;
      function _settle(value) {
        if (settled) return;
        settled = true;
        resolve(value);
      }
      bp(req, res, function () {
        _settle({ next: true, status: res._endedStatus, req: req });
      });
      res.on("finish", function () {
        _settle({ next: false, status: res._endedStatus, headers: res._headers, req: req });
      });
      setImmediate(function () { req.emit("error", parserError); });
    });
  }, { timeoutMs: 1500 });                                                        // allow:raw-byte-literal — parser-settle budget ms
}

async function testInvalidChunkSizeRefused() {
  var err = new Error("Parse Error: Invalid character in chunk size header");
  err.code = "HPE_INVALID_CHUNK_SIZE";
  var rv = await _runWithError(
    { "content-type": "application/json", "transfer-encoding": "chunked" },
    err
  );
  check("HPE_INVALID_CHUNK_SIZE -> request refused (no next)",
        rv.next === false);
  check("HPE_INVALID_CHUNK_SIZE -> 400 Bad Request",
        rv.status === 400);
  check("HPE_INVALID_CHUNK_SIZE -> Connection: close",
        rv.headers && (rv.headers["Connection"] === "close" ||
                       rv.headers["connection"] === "close"));
  check("HPE_INVALID_CHUNK_SIZE -> req.destroy() called",
        rv.req && rv.req._destroyed === true);
}

async function testInvalidTransferEncodingRefused() {
  var err = new Error("Parse Error: Invalid Transfer-Encoding chunk");
  err.code = "HPE_INVALID_TRANSFER_ENCODING";
  var rv = await _runWithError(
    { "content-type": "application/json", "transfer-encoding": "chunked" },
    err
  );
  check("HPE_INVALID_TRANSFER_ENCODING -> Connection: close + 400",
        rv.next === false && rv.status === 400 &&
        rv.headers && (rv.headers["Connection"] === "close" ||
                       rv.headers["connection"] === "close"));
}

async function testInvalidEofStateRefused() {
  var err = new Error("Parse Error: Premature EOF inside chunk");
  err.code = "HPE_INVALID_EOF_STATE";
  var rv = await _runWithError(
    { "content-type": "application/json", "transfer-encoding": "chunked" },
    err
  );
  check("HPE_INVALID_EOF_STATE -> Connection: close + 400",
        rv.next === false && rv.status === 400 &&
        rv.headers && (rv.headers["Connection"] === "close" ||
                       rv.headers["connection"] === "close"));
}

async function testNonChunkedErrorAlsoClosesConnection() {
  // A generic body-parse 4xx (here a read-abort routed through the
  // generic _writeError) also sets Connection: close — defense in depth
  // against an upstream proxy reusing a socket whose request stream the
  // parser abandoned mid-body (RFC 9112 §9.6), matching the chunked
  // writers above rather than leaving the generic path uncovered.
  var err = new Error("read aborted");
  err.code = "ECONNRESET";
  var rv = await _runWithError(
    { "content-type": "application/json", "content-length": "5" },
    err
  );
  check("non-chunked 4xx error -> 400 with Connection: close",
        rv.next === false && rv.status === 400 &&
        rv.headers && (rv.headers["Connection"] === "close" ||
                       rv.headers["connection"] === "close"));
}

async function run() {
  await testInvalidChunkSizeRefused();
  await testInvalidTransferEncodingRefused();
  await testInvalidEofStateRefused();
  await testNonChunkedErrorAlsoClosesConnection();
  // The malformed-body rejects emit an audit event, which schedules the
  // audit handler's age-flush timer. Drain it so no timer lingers past run().
  await b.audit.flush();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

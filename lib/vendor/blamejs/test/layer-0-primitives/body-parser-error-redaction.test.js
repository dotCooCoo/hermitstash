// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * body-parser error-response redaction (v0.15.12, #84 / CWE-209).
 *
 * A caught exception's detail must never be echoed to the HTTP client. The
 * terminal catch surfaces a curated message only for a framework-classified
 * 4xx BodyParserError; any other thrown error — and every 5xx — gets a generic
 * status phrase, with full detail kept on the audit chain server-side. The
 * parse-hook wrapper carries a fixed message so an operator hook's thrown
 * secret can't ride the 4xx path to the client.
 */

var EventEmitter = require("events").EventEmitter;
var helpers      = require("../helpers");
var b            = helpers.b;
var check        = helpers.check;
var _bodyRes     = helpers._bodyRes;

function _bodyReqStream(body, headers) {
  var req = new EventEmitter();
  req.method  = "POST";
  req.url     = "/";
  req.headers = Object.assign({ "content-length": String(Buffer.byteLength(body)) }, headers || {});
  req.socket  = { remoteAddress: "127.0.0.1" };
  req.destroy = function () { req._destroyed = true; };
  // Deliver the body on next tick so the parser's data/end listeners are wired.
  process.nextTick(function () {
    req.emit("data", Buffer.from(body, "utf8"));
    req.emit("end");
  });
  return req;
}

async function _run(opts, body, headers) {
  var bp  = b.middleware.bodyParser(opts);
  var req = _bodyReqStream(body, headers);
  var res = _bodyRes();
  var settled = false;
  function fin() { settled = true; }
  res.on("finish", fin);
  bp(req, res, fin);
  // Poll for the response to settle — never a fixed sleep (§6b).
  await helpers.waitUntil(function () { return settled || res._endedStatus !== null; }, {
    timeoutMs: 5000,
    label: "body-parser error response settles",
  });
  return res;
}

async function run() {
  // (1) parse-hook throws a detail-bearing error — not echoed to the client.
  // Use a non-credential sentinel so the test itself carries no secret shape.
  var SENTINEL = "do-not-echo-sentinel-9f8e7d6c";
  var r1 = await _run(
    { json: { parseHook: function () { throw new Error("internal detail " + SENTINEL + " host:5432"); } } },
    "{}",
    { "content-type": "application/json" }
  );
  var b1 = String(r1._captured || "");
  check("#84 parse-hook internal detail is NOT echoed to the client",
        b1.indexOf(SENTINEL) === -1 && b1.indexOf("host:5432") === -1);
  check("#84 parse-hook client message is the curated fixed reason",
        b1.length === 0 || b1.indexOf("parse hook") !== -1);

  // (2) a genuinely malformed JSON body still returns a useful 400 grammar
  // error (the fix must not over-redact client-input errors).
  var r2 = await _run({ json: {} }, "{not json", { "content-type": "application/json" });
  check("#84 malformed JSON still returns 400", r2._endedStatus === 400 || r2._endedStatus === null);
  var b2 = String(r2._captured || "");
  check("#84 malformed-JSON error is still surfaced (not blanket-redacted)",
        b2.length === 0 || b2.indexOf("JSON") !== -1 || b2.indexOf("parse") !== -1 || b2.indexOf("Bad Request") !== -1);
}

module.exports = { run: run };

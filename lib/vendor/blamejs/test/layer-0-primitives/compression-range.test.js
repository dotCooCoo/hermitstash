// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.middleware.compression — range/partial-content pass-through.
 *
 * A 206 Partial Content or any Content-Range response must NOT be
 * transformed (RFC 7233 §4.1): compressing it drops Content-Length but
 * leaves Content-Range advertising an uncompressed byte interval over a
 * now-compressed body, corrupting range-assembling clients.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _fakeRes() {
  var headers = {};
  var chunks  = [];
  var ended   = false;
  return {
    statusCode: 200,
    writeHead: function (status, a, c) {
      this.statusCode = status;
      var hdrs = (c && typeof c === "object") ? c
               : (a && typeof a === "object" && !Array.isArray(a)) ? a : null;
      if (hdrs) {
        var keys = Object.keys(hdrs);
        for (var i = 0; i < keys.length; i++) headers[keys[i].toLowerCase()] = hdrs[keys[i]];
      }
      return this;
    },
    write: function (chunk) {
      if (chunk != null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      return true;
    },
    end: function (chunk) {
      if (chunk != null) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      ended = true;
      return this;
    },
    setHeader:    function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:    function (k) { return headers[k.toLowerCase()]; },
    removeHeader: function (k) { delete headers[k.toLowerCase()]; },
    emit:         function () {},
    _headers: headers,
    _body:    function () { return Buffer.concat(chunks); },
    _ended:   function () { return ended; },
  };
}

function testPartialContent206NotCompressed() {
  var mw   = b.middleware.compression({ threshold: 0 });
  var req  = { headers: { "accept-encoding": "gzip" } };
  var res  = _fakeRes();
  var body = Buffer.from("X".repeat(4096));
  mw(req, res, function () {});
  res.writeHead(206, {
    "Content-Type":   "text/plain",
    "Content-Range":  "bytes 0-4095/100000",
    "Content-Length": String(body.length),
  });
  res.end(body);
  check("206 response carries no Content-Encoding", !res.getHeader("content-encoding"));
  check("206 body passes through verbatim (uncompressed)", res._body().equals(body));
}

function testContentRange200NotCompressed() {
  // A 200 that still carries a Content-Range header (multi-range / explicit
  // single range over 200) must also pass through untransformed.
  var mw   = b.middleware.compression({ threshold: 0 });
  var req  = { headers: { "accept-encoding": "gzip" } };
  var res  = _fakeRes();
  var body = Buffer.from("Y".repeat(4096));
  mw(req, res, function () {});
  res.writeHead(200, {
    "Content-Type":  "text/plain",
    "Content-Range": "bytes 0-4095/8192",
  });
  res.end(body);
  check("Content-Range 200 carries no Content-Encoding", !res.getHeader("content-encoding"));
  check("Content-Range 200 body passes through verbatim", res._body().equals(body));
}

async function testPlain200StillCompresses() {
  // Control: a normal compressible 200 still gets compressed, so the
  // range guard isn't disabling compression wholesale.
  var mw   = b.middleware.compression({ threshold: 0 });
  var req  = { headers: { "accept-encoding": "gzip" } };
  var res  = _fakeRes();
  var body = Buffer.from("Z".repeat(4096));
  mw(req, res, function () {});
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end(body);
  check("plain compressible 200 sets Content-Encoding: gzip",
    res.getHeader("content-encoding") === "gzip");
  // zlib flushes asynchronously; wait for the wrapped end before asserting.
  await helpers.waitUntil(function () { return res._ended(); }, {
    timeoutMs: 5000,
    label: "compression-range: compressed response flushed",
  });
  check("plain compressible 200 body is transformed (smaller than source)",
    res._body().length > 0 && res._body().length < body.length);
}

async function run() {
  testPartialContent206NotCompressed();
  testContentRange200NotCompressed();
  await testPlain200StillCompresses();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK compression-range — " + helpers.getChecks() + " checks"); })
       .catch(function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); });
}

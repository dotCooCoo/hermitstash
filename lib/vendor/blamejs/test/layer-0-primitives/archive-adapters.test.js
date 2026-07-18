// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.archive.adapters source-bytes adapter contract.
 *
 * Exercises the random-access adapters through the real consumer path:
 *   - b.archive.adapters.fs      — local-file fd + range() reads, close,
 *                                  out-of-range / bad-arg / abort refusals.
 *   - b.archive.adapters.http    — HTTP Range requests against a real
 *                                  loopback server (never a real network),
 *                                  driven through the documented opts.client
 *                                  seam. The framework's b.httpClient refuses
 *                                  loopback via the SSRF guard by design, so a
 *                                  shape-compatible real loopback client is
 *                                  injected — it performs genuine 127.0.0.1
 *                                  round-trips, exercising the adapter's real
 *                                  Range-header / Accept-Ranges / 206 path.
 *   - b.archive.adapters.isRandomAccessAdapter  — shape predicate.
 *   - b.archive.adapters.isTrustedStreamAdapter — shape predicate.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var b       = helpers.b;
var os      = require("node:os");
var path    = require("node:path");
var fs      = require("node:fs");
var http    = require("node:http");
var stream  = require("node:stream");

// A real loopback HTTP client in the shape b.archive.adapters.http expects
// of opts.client (documented override seam: "client: b.httpClient"). Does
// genuine 127.0.0.1 I/O — not a response fake — so the adapter's HEAD +
// Range-GET code path runs end-to-end without weakening the SSRF guard.
function _loopbackClient() {
  return {
    request: function (o) {
      return new Promise(function (resolve, reject) {
        var u = new URL(o.url);
        var req = http.request({
          hostname: u.hostname,
          port:     u.port,
          path:     u.pathname,
          method:   o.method,
          headers:  o.headers,
        }, function (res) {
          var chunks = [];
          res.on("data", function (c) { chunks.push(c); });
          res.on("end", function () {
            resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
          });
        });
        req.on("error", reject);
        req.end();
      });
    },
  };
}

// Loopback server: HEAD advertises Accept-Ranges + Content-Length; GET with
// a `Range: bytes=a-b` header returns 206 Partial Content sliced from the
// payload. `opts.noAcceptRanges` omits the header so the adapter's no-range
// refusal can be exercised.
function _makeRangeServer(payload, opts) {
  opts = opts || {};
  return http.createServer(function (req, res) {
    if (req.method === "HEAD") {
      var h = { "content-length": String(payload.length) };
      if (!opts.noAcceptRanges) h["accept-ranges"] = "bytes";
      res.writeHead(200, h);
      res.end();
      return;
    }
    var m = /bytes=(\d+)-(\d+)/.exec(req.headers.range || "");
    if (m) {
      var start = Number(m[1]);
      var end   = Number(m[2]);
      var slice = payload.slice(start, end + 1);
      res.writeHead(206, {
        "content-length": String(slice.length),
        "content-range":  "bytes " + start + "-" + end + "/" + payload.length,
      });
      res.end(slice);
      return;
    }
    res.writeHead(200, { "content-length": String(payload.length) });
    res.end(payload);
  });
}

async function _expectReject(label, promise, codeRe) {
  var threw = null;
  try { await promise; } catch (e) { threw = e; }
  check("archive.adapters " + label,
    !!threw && codeRe.test(threw.code || ""));
}

async function testFsAdapter() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-adp-fs-"));
  var fp  = path.join(dir, "payload.bin");
  var payload = Buffer.from("0123456789ABCDEF-the-quick-brown-fox");
  fs.writeFileSync(fp, payload);

  var adapter = b.archive.adapters.fs(fp);
  try {
    check("adapters.fs: kind random-access", adapter.kind === "random-access");
    check("adapters.fs: name",               adapter.name === "fs");
    check("adapters.fs: size fstat'd",       adapter.size === payload.length);

    var head = await adapter.range(0, 10);
    check("adapters.fs: range(0,10) bytes",  head.toString() === payload.slice(0, 10).toString());
    var mid = await adapter.range(10, 6);
    check("adapters.fs: range(offset,len) bytes",
      mid.toString() === payload.slice(10, 16).toString());
    // Reusing the same fd across calls returns the whole trailer too.
    var tail = await adapter.range(payload.length - 4, 4);
    check("adapters.fs: trailing range bytes",
      tail.toString() === payload.slice(payload.length - 4).toString());

    // Refusals — read-past-EOF, bad offset, non-positive length.
    await _expectReject("fs: read past EOF refused",
      adapter.range(payload.length - 2, 8), /adapter\/out-of-range/);
    await _expectReject("fs: negative offset refused",
      adapter.range(-1, 4), /adapter\/bad-arg/);
    await _expectReject("fs: zero length refused",
      adapter.range(0, 0), /adapter\/bad-arg/);
    await _expectReject("fs: non-integer length refused",
      adapter.range(0, 1.5), /adapter\/bad-arg/);

    // Predicate coverage against the live fs adapter.
    check("adapters.isRandomAccessAdapter(fs) → true",
      b.archive.adapters.isRandomAccessAdapter(adapter) === true);
    check("adapters.isTrustedStreamAdapter(fs) → false",
      b.archive.adapters.isTrustedStreamAdapter(adapter) === false);

    // close() is idempotent; a range() after close fails closed.
    adapter.close();
    adapter.close();
    await _expectReject("fs: range after close refused",
      adapter.range(0, 4), /adapter\/closed/);
  } finally {
    adapter.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testFsAbortSignal() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "bjs-adp-abort-"));
  var fp  = path.join(dir, "payload.bin");
  fs.writeFileSync(fp, Buffer.from("abcdefghij"));
  var ac = new AbortController();
  var adapter = b.archive.adapters.fs(fp, { signal: ac.signal });
  try {
    ac.abort();
    var threw = null;
    try { await adapter.range(0, 4); } catch (e) { threw = e; }
    check("adapters.fs: aborted signal rejects range", !!threw);
  } finally {
    adapter.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function testHttpAdapter() {
  var payload = Buffer.from("THE-QUICK-BROWN-FOX-0123456789-JUMPS");
  var server = _makeRangeServer(payload);
  var port = await helpers.listenOnRandomPort(server);
  var url = "http://127.0.0.1:" + port + "/release.zip";
  try {
    var adapter = b.archive.adapters.http(url, { client: _loopbackClient() });
    check("adapters.http: kind random-access", adapter.kind === "random-access");
    check("adapters.http: name",               adapter.name === "http");

    // First interaction resolves size via HEAD + Accept-Ranges probe.
    var size = await adapter.resolveSize();
    check("adapters.http: HEAD resolves size", size === payload.length);
    check("adapters.http: size accessor now set", adapter.size === payload.length);

    var head = await adapter.range(0, 9);
    check("adapters.http: Range 206 head bytes",
      head.toString() === payload.slice(0, 9).toString());
    var mid = await adapter.range(20, 6);
    check("adapters.http: Range 206 mid bytes",
      mid.toString() === payload.slice(20, 26).toString());

    await _expectReject("http: read past EOF refused",
      adapter.range(payload.length - 2, 10), /adapter\/out-of-range/);
    await _expectReject("http: zero length refused",
      adapter.range(0, 0), /adapter\/bad-arg/);

    check("adapters.isRandomAccessAdapter(http) → true",
      b.archive.adapters.isRandomAccessAdapter(adapter) === true);
  } finally {
    await new Promise(function (r) { server.close(r); });
  }
}

async function testHttpNoRangeSupport() {
  var payload = Buffer.from("no-range-support-here");
  var server = _makeRangeServer(payload, { noAcceptRanges: true });
  var port = await helpers.listenOnRandomPort(server);
  var url = "http://127.0.0.1:" + port + "/norange.zip";
  try {
    var adapter = b.archive.adapters.http(url, { client: _loopbackClient() });
    // Server omits Accept-Ranges: bytes → adapter must refuse.
    await _expectReject("http: server without Accept-Ranges refused",
      adapter.resolveSize(), /adapter\/no-range/);
  } finally {
    await new Promise(function (r) { server.close(r); });
  }
}

function testShapePredicates() {
  // Random-access shape produced by fs / buffer / objectStore / http.
  var bufAdapter = b.archive.adapters.buffer(Buffer.from("hello-buffer"));
  check("adapters.isRandomAccessAdapter(buffer) → true",
    b.archive.adapters.isRandomAccessAdapter(bufAdapter) === true);
  check("adapters.isTrustedStreamAdapter(buffer) → false",
    b.archive.adapters.isTrustedStreamAdapter(bufAdapter) === false);

  // Trusted-sequential shape produced by trustedStream.
  var pt = new stream.PassThrough();
  var tsAdapter = b.archive.adapters.trustedStream(pt);
  try {
    check("adapters.isTrustedStreamAdapter(trustedStream) → true",
      b.archive.adapters.isTrustedStreamAdapter(tsAdapter) === true);
    check("adapters.isRandomAccessAdapter(trustedStream) → false",
      b.archive.adapters.isRandomAccessAdapter(tsAdapter) === false);
  } finally {
    tsAdapter.close();
  }

  // Garbage / partial shapes are rejected by both predicates — the
  // predicates require BOTH the kind tag AND the discriminating member.
  check("isRandomAccessAdapter(null) → false",
    b.archive.adapters.isRandomAccessAdapter(null) === false);
  check("isRandomAccessAdapter(kind-only, no range) → false",
    b.archive.adapters.isRandomAccessAdapter({ kind: "random-access" }) === false);
  check("isRandomAccessAdapter(trusted shape) → false",
    b.archive.adapters.isRandomAccessAdapter(tsAdapterShape()) === false);
  check("isTrustedStreamAdapter({}) → false",
    b.archive.adapters.isTrustedStreamAdapter({}) === false);
  check("isTrustedStreamAdapter(kind-only, no readable) → false",
    b.archive.adapters.isTrustedStreamAdapter({ kind: "trusted-sequential" }) === false);
  check("isTrustedStreamAdapter(random-access adapter) → false",
    b.archive.adapters.isTrustedStreamAdapter(bufAdapter) === false);
}

// A plain trusted-sequential-shaped object (no range fn) — used to prove
// isRandomAccessAdapter refuses it even though it has a kind tag.
function tsAdapterShape() {
  return { kind: "trusted-sequential", readable: {} };
}

async function run() {
  await testFsAdapter();
  await testFsAbortSignal();
  await testHttpAdapter();
  await testHttpNoRangeSupport();
  testShapePredicates();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}

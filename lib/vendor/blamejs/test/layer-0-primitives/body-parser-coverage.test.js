// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * body-parser branch-coverage closer.
 *
 * Drives the real bodyParser middleware (and b.parsers.* where a branch
 * only surfaces there) over edge / hostile inputs the four existing
 * body-parser-*.test.js suites don't reach:
 *
 *   - RFC 5987 `filename*=UTF-8''…` extended-parameter decode — the
 *     success path and the malformed-percent-escape fallback to a legacy
 *     `filename=` companion.
 *   - multipart tmp-dir creation failure (disk mode, unwritable tmpDir).
 *   - part headers and part body split across multiple `data` events
 *     (the "need more data" continuations).
 *   - a fileFilter-discarded file body pushing the running total over
 *     totalSize.
 *   - a field name repeated three times (the array-append branch).
 *   - a multipart request stream `error` mid-parse.
 *   - an unexpected internal throw inside the multipart state machine
 *     converted to a redacted 500.
 *   - the keepRawBody JSON parseHook-throw redaction path.
 *
 * Same idiom as body-parser-content-types.test.js: a Readable-stream
 * request carries the raw body bytes plus the matching headers; every
 * assertion is on the parsed result / response status, never on parser
 * internals.
 */

var EventEmitter = require("events").EventEmitter;
var nodeFs       = require("fs");
var nodeOs       = require("os");
var nodePath     = require("path");
var helpers      = require("../helpers");
var b            = helpers.b;
var check        = helpers.check;
var _bodyReq     = helpers._bodyReq;
var _bodyRes     = helpers._bodyRes;

var BYTES = b.constants.BYTES;

// ---- request/response drivers (mirrors the sibling suite) ----

// Multi-chunk request — delivers the body across several `data` events so
// the parser exercises its "need more data" continuations (headers / body
// spanning event boundaries).
function _streamReq(method, headers, chunks) {
  var req = new EventEmitter();
  req.method  = method;
  req.url     = "/";
  req.headers = Object.assign({}, headers || {});
  req.socket  = { remoteAddress: "127.0.0.1" };
  req.destroy = function () { req._destroyed = true; };
  process.nextTick(function () {
    for (var i = 0; i < chunks.length; i++) {
      var c = chunks[i];
      req.emit("data", Buffer.isBuffer(c) ? c : Buffer.from(c));
    }
    req.emit("end");
  });
  return req;
}

// A body-shaped request that does NOT auto-end — the test drives the
// lifecycle (e.g. emits `error`) explicitly.
function _manualReq(method, headers) {
  var req = new EventEmitter();
  req.method  = method;
  req.url     = "/";
  req.headers = Object.assign({}, headers || {});
  req.socket  = { remoteAddress: "127.0.0.1" };
  req._destroyed = false;
  req.destroy = function () { req._destroyed = true; };
  return req;
}

// Run the middleware and resolve once it settles — either next() fired or
// the error/success response was written. Poll rather than race a sleep.
async function _run(bp, req, res, label) {
  var nextCalled = false;
  bp(req, res, function () { nextCalled = true; });
  await helpers.waitUntil(function () {
    return nextCalled || res._endedStatus !== null;
  }, {
    timeoutMs: 5000,
    label:     "body-parser-coverage: " + label + " settled",
  });
  return { next: nextCalled, status: res._endedStatus, req: req, res: res };
}

async function _drive(opts, method, headers, body, label) {
  var bp  = b.middleware.bodyParser(opts);
  var req = _bodyReq(method, headers, body);
  var res = _bodyRes();
  return _run(bp, req, res, label);
}

// ---- multipart body builders (RFC 7578 wire shape) ----

function _mpFieldPart(bd, name, value) {
  return "--" + bd + "\r\n" +
    "Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n";
}
function _mpEnd(bd) { return "--" + bd + "--\r\n"; }
function _mpBody(bd, parts) { return parts.join("") + _mpEnd(bd); }
function _mpHeaders(bd, body) {
  return {
    "content-type":   "multipart/form-data; boundary=" + bd,
    "content-length": String(Buffer.isBuffer(body) ? body.length : Buffer.byteLength(body)),
  };
}
// File part with a caller-supplied Content-Disposition parameter tail
// (so `filename*=…` extended params can be injected verbatim).
function _mpFilePartRawDisposition(bd, dispositionParams, ctype, body) {
  return "--" + bd + "\r\n" +
    "Content-Disposition: form-data; " + dispositionParams + "\r\n" +
    (ctype ? ("Content-Type: " + ctype + "\r\n") : "") +
    "\r\n" + body + "\r\n";
}

// ---- RFC 5987 filename* extended-parameter decode ----

async function testFilenameStarUtf8Decoded() {
  var bd   = "fnstar1";
  var body = _mpBody(bd, [
    _mpFilePartRawDisposition(bd, "name=\"f\"; filename*=UTF-8''hello%20world.txt", "text/plain", "PAYLOAD"),
  ]);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "filename-star-utf8");
  check("filename*=UTF-8'': percent-encoded name decoded to a space-bearing filename",
        rv.next === true && rv.req.files.length === 1 &&
        rv.req.files[0].filename === "hello world.txt");
  check("filename*=UTF-8'': the file payload bytes survive the ext-value decode intact",
        rv.req.files[0].buffer.toString() === "PAYLOAD");
}

async function testFilenameStarMalformedFallsBackToLegacy() {
  var bd   = "fnstar2";
  // Malformed percent-escape (`%A` truncated) -> decodeURIComponent throws ->
  // the ext-value is refused (null) and the legacy `filename=` companion is
  // used instead. Both the bad ext-value and the good legacy name are present.
  var body = _mpBody(bd, [
    _mpFilePartRawDisposition(bd,
      "name=\"f\"; filename=\"fallback.txt\"; filename*=UTF-8''%E0%A4%A", "text/plain", "KEEP"),
  ]);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "filename-star-malformed");
  check("filename* malformed escape: refused, legacy filename= used as the name",
        rv.next === true && rv.req.files.length === 1 &&
        rv.req.files[0].filename === "fallback.txt");
  check("filename* malformed escape: the legacy-named file still carries its payload",
        rv.req.files[0].buffer.toString() === "KEEP");
}

// ---- multipart tmp-dir creation failure (disk mode) ----

async function testMultipartTmpDirCreateFailure() {
  var probe = nodePath.join(nodeOs.tmpdir(), "bp-cov-tmpdir-" + process.pid + "-" + Date.now());
  nodeFs.writeFileSync(probe, "x");                 // a regular FILE, not a dir
  try {
    // tmpDir sits UNDER a regular file -> ensureDir()'s mkdir fails ENOTDIR ->
    // structured 500 rather than a deferred fs throw.
    var bd   = "tmpdirbd";
    var body = _mpBody(bd, [_mpFieldPart(bd, "f", "v")]);
    var rv = await _drive(
      { multipart: { storage: "disk", tmpDir: nodePath.join(probe, "sub") } }, "POST",
      _mpHeaders(bd, body), body, "tmpdir-fail");
    check("multipart disk: un-creatable tmpDir -> 500 (no next), not an uncaught fs throw",
          rv.next === false && rv.status === 500);
    // Positively assert the curated generic phrase rendered (redaction
    // happened) — independent of the platform's mkdir errno (ENOTDIR on
    // Linux, but ENOENT/EEXIST/EPERM elsewhere), AND that no raw fs errno
    // leaked. The absence check alone would pass on any other wrong errno.
    check("multipart disk: tmpDir-failure response is the generic 5xx phrase, not the raw fs errno",
          rv.res._captured.indexOf("Internal Server Error") !== -1 &&
          rv.res._captured.indexOf("ENOTDIR") === -1 &&
          rv.res._captured.indexOf("ENOENT") === -1 &&
          rv.res._captured.indexOf("EEXIST") === -1);
  } finally {
    try { nodeFs.unlinkSync(probe); } catch (_e) { /* best-effort */ }
  }
}

// ---- part headers spanning multiple data events ----

async function testMultipartHeadersSpanDataEvents() {
  var bd = "hdrspan";
  // First event stops mid-header (no \r\n\r\n terminator yet), so the parser
  // takes the "headers incomplete, need more data" continuation; the second
  // event completes the part.
  var chunk1 = "--" + bd + "\r\nContent-Disposition: form-data; name=\"f\"";
  var chunk2 = "\r\n\r\nspanned-value\r\n" + _mpEnd(bd);
  var bp  = b.middleware.bodyParser({ multipart: { storage: "memory" } });
  var req = _streamReq("POST",
    { "content-type": "multipart/form-data; boundary=" + bd, "transfer-encoding": "chunked" },
    [chunk1, chunk2]);
  var res = _bodyRes();
  var rv  = await _run(bp, req, res, "headers-span");
  check("multipart: part headers split across data events still parse the field",
        rv.next === true && rv.req.body.f === "spanned-value");
}

// ---- part body emitted across data events (partial-emit look-ahead) ----

async function testMultipartBodyPartialEmitAcrossEvents() {
  var bd = "bodyspan";
  // Deliver a field body larger than the boundary look-ahead window BEFORE the
  // closing boundary arrives, so the parser emits a partial body chunk on the
  // first event and the remainder on the second — the full value must survive
  // the split reassembly.
  var value = "A".repeat(40);
  var head  = "--" + bd + "\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n";
  var chunk1 = head + value;                    // no closing boundary yet
  var chunk2 = "\r\n" + _mpEnd(bd);
  var bp  = b.middleware.bodyParser({ multipart: { storage: "memory" } });
  var req = _streamReq("POST",
    { "content-type": "multipart/form-data; boundary=" + bd, "transfer-encoding": "chunked" },
    [chunk1, chunk2]);
  var res = _bodyRes();
  var rv  = await _run(bp, req, res, "body-partial-emit");
  check("multipart: body split across data events reassembles the complete value",
        rv.next === true && rv.req.body.f === value && rv.req.body.f.length === 40);
}

// ---- fileFilter-discarded body enforcing the request total cap ----

async function testMultipartDiscardedBodyOverTotalSize() {
  var bd = "discardbd";
  // fileFilter rejects the file (bytes are read-past but never stored); the
  // discarded body must still count toward totalSize as a per-request DoS
  // guard, so a large discarded body over totalSize -> 413.
  var fileBody = "Z".repeat(500);
  var body = _mpBody(bd, [
    _mpFilePartRawDisposition(bd, "name=\"f\"; filename=\"a.txt\"", "text/plain", fileBody),
  ]);
  var rv = await _drive({
    multipart: {
      storage:    "memory",
      fileFilter: function () { return false; },
      fileSize:   BYTES.mib(1),      // large, so the per-file cap is NOT what trips
      totalSize:  BYTES.bytes(200),  // header (~90B) fits; the 500B discarded body overruns
    },
  }, "POST", _mpHeaders(bd, body), body, "discard-over-total");
  check("multipart: fileFilter-discarded body over totalSize -> 413 (no next)",
        rv.next === false && rv.status === 413);
  check("multipart: the 413 is the request-total guard, not a per-file cap",
        rv.res._captured.indexOf("total request size") !== -1);
}

// ---- field name repeated three times (array append) ----

async function testMultipartFieldRepeatedThriceArrayAppend() {
  var bd   = "thricebd";
  var body = _mpBody(bd, [
    _mpFieldPart(bd, "tag", "a"),
    _mpFieldPart(bd, "tag", "b"),
    _mpFieldPart(bd, "tag", "c"),
    _mpFieldPart(bd, "other", "keep"),
  ]);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "field-thrice");
  check("multipart: a field repeated 3x appends into a 3-element array in order",
        rv.next === true && Array.isArray(rv.req.body.tag) &&
        rv.req.body.tag.length === 3 &&
        rv.req.body.tag[0] === "a" && rv.req.body.tag[1] === "b" && rv.req.body.tag[2] === "c");
  check("multipart: the unrelated field survives the repeated-key accumulation",
        rv.req.body.other === "keep");
}

// ---- multipart request stream error mid-parse ----

async function testMultipartStreamErrorRefused() {
  var bd  = "errbd";
  var bp  = b.middleware.bodyParser({ multipart: { storage: "memory" } });
  var req = _manualReq("POST",
    { "content-type": "multipart/form-data; boundary=" + bd, "transfer-encoding": "chunked" });
  var res = _bodyRes();
  // Feed a valid part prefix, then error the stream before the final boundary.
  process.nextTick(function () {
    req.emit("data", Buffer.from("--" + bd + "\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nhalf"));
    req.emit("error", new Error("upstream stream broke"));
  });
  var rv = await _run(bp, req, res, "stream-error");
  check("multipart: a request stream error mid-parse -> 400 refusal (no next)",
        rv.next === false && rv.status === 400);
  check("multipart: stream-error refusal sets Connection: close (anti-smuggling)",
        rv.res._headers && (rv.res._headers["Connection"] === "close" ||
                            rv.res._headers["connection"] === "close"));
}

// ---- unexpected internal throw inside the state machine -> redacted 500 ----

async function testMultipartInternalThrowRedacted500() {
  var bd = "getterbd";
  // A per-field rule lookup keyed by the request-controlled field name throws
  // synchronously (operator opts.fields carrying a throwing accessor). The
  // parser must convert this unexpected internal throw into a redacted 500,
  // not crash the request — the thrown detail is never echoed to the client.
  var throwingFields = {};
  Object.defineProperty(throwingFields, "f", {
    enumerable: true,
    get: function () { throw new Error("perfield-accessor-boom-9f3a"); },
  });
  var body = _mpBody(bd, [
    _mpFilePartRawDisposition(bd, "name=\"f\"; filename=\"a.txt\"", "text/plain", "data"),
  ]);
  var rv = await _drive({ multipart: { storage: "memory", fields: throwingFields } }, "POST",
    _mpHeaders(bd, body), body, "internal-throw");
  check("multipart: an unexpected internal throw -> 500 (no next), request not crashed",
        rv.next === false && rv.status === 500);
  check("multipart: the internal throw's detail is redacted, not echoed to the client",
        rv.res._captured.indexOf("perfield-accessor-boom-9f3a") === -1);
}

// ---- keepRawBody JSON parseHook throw redaction ----

async function testKeepRawBodyParseHookThrowRedacted() {
  var SENTINEL = "keepraw-hook-secret-8b21c";
  var rv = await _drive(
    { keepRawBody: true, json: { parseHook: function () { throw new Error(SENTINEL + " db:5432"); } } },
    "POST",
    { "content-type": "application/json", "content-length": "7" },
    '{"a":1}', "keepraw-hook-throw");
  check("keepRawBody: parseHook throw on the buffered path -> 400 (no next)",
        rv.next === false && rv.status === 400);
  check("keepRawBody: parseHook throw detail is not echoed to the client",
        rv.res._captured.indexOf(SENTINEL) === -1 && rv.res._captured.indexOf("db:5432") === -1);
  check("keepRawBody: parseHook throw surfaces the curated 'parse hook' message",
        rv.res._captured.indexOf("parse hook") !== -1);
}

async function run() {
  await testFilenameStarUtf8Decoded();
  await testFilenameStarMalformedFallsBackToLegacy();
  await testMultipartTmpDirCreateFailure();
  await testMultipartHeadersSpanDataEvents();
  await testMultipartBodyPartialEmitAcrossEvents();
  await testMultipartDiscardedBodyOverTotalSize();
  await testMultipartFieldRepeatedThriceArrayAppend();
  await testMultipartStreamErrorRefused();
  await testMultipartInternalThrowRedacted500();
  await testKeepRawBodyParseHookThrowRedacted();
  // The 4xx/5xx rejects emit body-parser audit events, which schedule the
  // audit handler's age-flush timer. Drain it so no timer lingers past run().
  await b.audit.flush();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

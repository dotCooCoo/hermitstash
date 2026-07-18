// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * body-parser middleware — content-type dispatch, size caps, charset,
 * malformed JSON / urlencoded / multipart, request-smuggling defense,
 * per-sub-parser option defaults, and the 400 / 413 / 415 / 500 error
 * branches.
 *
 * Drives the real `b.middleware.bodyParser(opts)` consumer path with
 * EventEmitter-backed request streams (via the shared bodyReq/bodyRes
 * mocks) so every assertion runs the shipped middleware, not an
 * internal helper in isolation. The standalone `b.parsers.{json,
 * multipart}` surface (the same pipelines, exposed for lazy-parse
 * handlers) is exercised alongside it.
 */

var EventEmitter = require("events").EventEmitter;
var helpers      = require("../helpers");
var b            = helpers.b;
var check        = helpers.check;
var fs           = helpers.fs;
var os           = helpers.os;
var path         = helpers.path;
var _bodyRes     = helpers._bodyRes;
var _bodyReq     = helpers._bodyReq;

var BYTES        = b.constants.BYTES;
var bodyParserLib = require("../../lib/middleware/body-parser.js");

// ---- shared fixtures ----

// A request that does NOT auto-emit data/end — the test controls the
// stream so it can synthesize truncation, a mid-stream error, or a
// deferred single chunk. Mirrors the shape lib/testing.bodyReq builds
// but hands emission control to the caller.
function _manualReq(method, headers) {
  var req = new EventEmitter();
  req.method  = method || "POST";
  req.url     = "/";
  req.headers = Object.assign({}, headers || {});
  req.socket  = { remoteAddress: "127.0.0.1" };
  req._destroyed = false;
  req.destroy = function () { req._destroyed = true; };
  return req;
}

// Drive the middleware to a single settled outcome: either it called
// next() (body parsed / skipped) or it wrote a terminal error response
// (finish fired). Wrapped in withTestTimeout so a parser that never
// settles surfaces as a hard failure rather than hanging the suite.
function _run(opts, req) {
  var bp  = b.middleware.bodyParser(opts);
  var res = _bodyRes();
  return helpers.withTestTimeout("body-parser: middleware settles", function () {
    return new Promise(function (resolve) {
      var settled = false;
      function settle(v) {
        if (settled) return;
        settled = true;
        resolve(Object.assign({ req: req, res: res }, v));
      }
      res.on("finish", function () {
        settle({
          nexted:  false,
          status:  res._endedStatus,
          headers: res._headers,
          body:    res._captured,
        });
      });
      bp(req, res, function (err) {
        settle({ nexted: true, err: err });
      });
    });
  }, { timeoutMs: 3000 });                                                     // allow:raw-byte-literal — settle budget ms
}

function _bodyJson(rv) {
  try { return JSON.parse(String(rv.body || "")); }
  catch (_e) { return {}; }
}

// Build a multipart/form-data body. Each part is either
// { headers: { name: value }, body } or { headerBlock: "verbatim", body }
// (headerBlock lets a test inject an obs-fold / bad-header shape).
var CRLF = "\r\n";
function _mpBody(boundary, parts) {
  var segs = [Buffer.from("--" + boundary + CRLF)];
  parts.forEach(function (p, i) {
    var hdr;
    if (typeof p.headerBlock === "string") {
      hdr = p.headerBlock + CRLF + CRLF;
    } else {
      hdr = "";
      var hs = p.headers || {};
      Object.keys(hs).forEach(function (h) { hdr += h + ": " + hs[h] + CRLF; });
      hdr += CRLF;
    }
    segs.push(Buffer.from(hdr, "binary"));
    segs.push(Buffer.isBuffer(p.body) ? p.body : Buffer.from(String(p.body)));
    segs.push(Buffer.from(
      i === parts.length - 1
        ? CRLF + "--" + boundary + "--" + CRLF
        : CRLF + "--" + boundary + CRLF));
  });
  return Buffer.concat(segs);
}

function _mpHeaders(boundary, extra) {
  return Object.assign({
    "content-type": "multipart/form-data; boundary=" + boundary,
  }, extra || {});
}

// A shared tmp dir for disk-mode multipart tests; removed in run()'s finally.
var TMP_ROOT = path.join(os.tmpdir(), "blamejs-bp-test-" + process.pid + "-" + Date.now());

// ---- content-type dispatch + option defaults ----

async function testNonBodyMethodSkips() {
  var req = _bodyReq("GET", { "content-type": "application/json" }, '{"a":1}');
  var rv  = await _run({}, req);
  check("GET (non-body-bearing) skips the parser via next()", rv.nexted === true);
  check("GET leaves req.body untouched", req.body === undefined);
}

async function testAlreadyParsedShortCircuits() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "7" }, '{"a":1}');
  req.body = { preParsed: true };
  var rv  = await _run({}, req);
  check("a body already on req short-circuits to next()", rv.nexted === true);
  check("pre-parsed req.body is not overwritten", req.body.preParsed === true);
}

async function testContentLengthZeroIsNoBody() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "0" }, "");
  var rv  = await _run({}, req);
  check("Content-Length: 0 is treated as no body → next()", rv.nexted === true);
  check("Content-Length: 0 leaves req.body undefined", req.body === undefined);
}

async function testJsonHappyPath() {
  var req = _bodyReq("POST", { "content-type": "application/json; charset=utf-8", "content-length": "13" }, '{"name":"al"}');
  var rv  = await _run({ json: {} }, req);
  check("application/json parses to req.body object", rv.nexted === true && req.body && req.body.name === "al");
}

async function testJsonParseHookTransforms() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "7" }, '{"a":1}');
  var rv  = await _run({ json: { parseHook: function (parsed) { return { wrapped: parsed }; } } }, req);
  check("json parseHook transform is applied to req.body",
        rv.nexted === true && req.body && req.body.wrapped && req.body.wrapped.a === 1);
}

async function testUrlencodedHappyAndArray() {
  // Three repeated values so the accumulator crosses scalar → 2-array →
  // array.push (exercises each repeat-key branch).
  var body = "name=al&tag=a&tag=b&tag=c";
  var req  = _bodyReq("POST", { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length) }, body);
  var rv   = await _run({ urlencoded: {} }, req);
  check("urlencoded single value parses to string", req.body && req.body.name === "al");
  check("urlencoded repeated key collapses to array (3 values → push)",
        Array.isArray(req.body.tag) && req.body.tag.join("") === "abc");
  check("urlencoded consumer path reaches next()", rv.nexted === true);
}

async function testTextParser() {
  var req = _bodyReq("POST", { "content-type": "text/plain", "content-length": "5" }, "hello");
  var rv  = await _run({ text: {} }, req);
  check("text/plain parses to a string body", rv.nexted === true && req.body === "hello");
}

async function testRawParser() {
  var payload = Buffer.from("binary\x00bytes");
  var req = _bodyReq("POST", { "content-type": "application/octet-stream", "content-length": String(payload.length) }, payload);
  var rv  = await _run({ raw: {} }, req);
  check("application/octet-stream parses to a Buffer body",
        rv.nexted === true && Buffer.isBuffer(req.body) && req.body.equals(payload));
}

async function testEmptyBodiesReturnDefaults() {
  // Body-bearing (transfer-encoding present) but zero bytes delivered:
  // JSON → undefined, urlencoded → {}.
  var jr = _bodyReq("POST", { "content-type": "application/json", "transfer-encoding": "chunked" }, undefined);
  var jrv = await _run({ json: {} }, jr);
  check("empty JSON body yields req.body === undefined", jrv.nexted === true && jr.body === undefined);

  var ur = _bodyReq("POST", { "content-type": "application/x-www-form-urlencoded", "transfer-encoding": "chunked" }, undefined);
  var urv = await _run({ urlencoded: {} }, ur);
  check("empty urlencoded body yields req.body === {}",
        urv.nexted === true && ur.body && Object.keys(ur.body).length === 0);
}

// ---- 415 unsupported / disabled sub-parser ----

async function testUnsupportedContentType415() {
  var req = _bodyReq("POST", { "content-type": "application/vnd.custom", "content-length": "3" }, "abc");
  var rv  = await _run({ json: {}, urlencoded: {}, multipart: false, text: false, raw: false }, req);
  check("unmatched Content-Type with a body → 415", rv.nexted === false && rv.status === 415);
  check("415 carries the unsupported-content-type code", _bodyJson(rv).code === "body-parser/unsupported-content-type");
}

async function testDisabledSubParserFallsThroughTo415() {
  // json disabled; a JSON body now has no enabled matcher → 415.
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "7" }, '{"a":1}');
  var rv  = await _run({ json: false, urlencoded: {}, multipart: false, text: false, raw: false }, req);
  check("disabling the json sub-parser routes its body to 415", rv.nexted === false && rv.status === 415);
}

// ---- size caps: 413 / bad content-length: 400 ----

async function testContentLengthOverLimitPreflight413() {
  // Content-Length declares more than the limit → reject before reading bytes.
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "5000" }, "{}");
  var rv  = await _run({ json: { limit: BYTES.bytes(100) } }, req);
  check("Content-Length over limit → 413 preflight", rv.nexted === false && rv.status === 413);
  check("413 preflight carries the too-large code", _bodyJson(rv).code === "body-parser/too-large");
}

async function testStreamOverflow413() {
  // No honest Content-Length (transfer-encoding) so the preflight can't
  // catch it; the collectStream drain guard trips the 413 instead.
  var big = Buffer.alloc(500, 0x61);
  var req = _bodyReq("POST", { "content-type": "application/json", "transfer-encoding": "chunked" }, big);
  var rv  = await _run({ json: { limit: BYTES.bytes(50) } }, req);
  check("body exceeding limit with no Content-Length → 413 (drain guard)",
        rv.nexted === false && rv.status === 413);
}

async function testMalformedContentLength400() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "12abc" }, '{"a":1}');
  var rv  = await _run({ json: {} }, req);
  check("non-decimal Content-Length → 400", rv.nexted === false && rv.status === 400);
  check("400 carries the bad-content-length code", _bodyJson(rv).code === "body-parser/bad-content-length");
}

// ---- JSON adversarial ----

async function testJsonStrictRejectsScalar() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "5" }, '"hi"');
  var rv  = await _run({ json: { strict: true } }, req);
  check("strict JSON rejects a non-{/[ body with 400", rv.nexted === false && rv.status === 400);
  check("strict rejection carries json-strict code", _bodyJson(rv).code === "body-parser/json-strict");
}

async function testJsonNonStrictScalar() {
  // strict:false lets a bare scalar through the JSON pipeline.
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "3" }, "123");
  var rv  = await _run({ json: { strict: false } }, req);
  check("non-strict JSON accepts a bare scalar body", rv.nexted === true && req.body === 123);
}

async function testJsonMalformed400() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "8" }, '{"a":1,,}');
  var rv  = await _run({ json: {} }, req);
  check("malformed JSON → 400", rv.nexted === false && rv.status === 400);
  check("malformed JSON carries json-malformed code", _bodyJson(rv).code === "body-parser/json-malformed");
}

async function testJsonParseHookThrow400() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "2" }, "{}");
  var rv  = await _run({ json: { parseHook: function () { throw new Error("nope"); } } }, req);
  check("parseHook throw → 400 json-hook", rv.nexted === false && rv.status === 400 &&
        _bodyJson(rv).code === "body-parser/json-hook");
}

// ---- urlencoded adversarial ----

async function testUrlencodedPoisonedKey400() {
  var body = "__proto__=x";
  var req  = _bodyReq("POST", { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length) }, body);
  var rv   = await _run({ urlencoded: {} }, req);
  check("urlencoded __proto__ key → 400 (pollution defense)",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/urlencoded-poisoned-key");
}

async function testUrlencodedArrayLimit413() {
  var body = "tag=a&tag=b&tag=c";
  var req  = _bodyReq("POST", { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length) }, body);
  var rv   = await _run({ urlencoded: { arrayLimit: 2 } }, req);
  check("urlencoded array over arrayLimit → 413",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/urlencoded-array-too-large");
}

async function testUrlencodedTooManyFields413() {
  var pieces = [];
  for (var i = 0; i <= 1100; i++) pieces.push("f" + i + "=1");    // > arrayLimit(100) + headroom(1000)
  var body = pieces.join("&");
  var req  = _bodyReq("POST", { "content-type": "application/x-www-form-urlencoded", "content-length": String(body.length) }, body);
  var rv   = await _run({ urlencoded: {} }, req);
  check("urlencoded key-bomb over the field cap → 413",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/urlencoded-too-many-fields");
}

// ---- request smuggling (runs before _hasBody) ----

async function testSmugglingClTeConflict() {
  var req = _manualReq("POST", { "content-type": "application/json", "content-length": "5", "transfer-encoding": "chunked" });
  var rv  = await _run({ json: {} }, req);
  check("CL + TE present → 400 smuggling reject", rv.nexted === false && rv.status === 400);
  check("CL+TE reject carries the te-cl-conflict code", _bodyJson(rv).code === "smuggling/te-cl-conflict");
  check("smuggling reject sets Connection: close",
        rv.headers && (rv.headers.Connection === "close" || rv.headers.connection === "close"));
}

async function testSmugglingMultipleContentLength() {
  var req = _manualReq("POST", { "content-type": "application/json", "content-length": "5, 6" });
  var rv  = await _run({ json: {} }, req);
  check("multiple Content-Length values → 400 smuggling",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "smuggling/multiple-content-length");
}

async function testSmugglingTeNotChunked() {
  var req = _manualReq("POST", { "content-type": "application/json", "transfer-encoding": "gzip" });
  var rv  = await _run({ json: {} }, req);
  check("Transfer-Encoding not ending in chunked → 400 smuggling",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "smuggling/te-not-chunked");
}

async function testSmugglingDuplicateChunked() {
  var req = _manualReq("POST", { "content-type": "application/json", "transfer-encoding": "chunked, chunked" });
  var rv  = await _run({ json: {} }, req);
  check("Transfer-Encoding: chunked, chunked → 400 smuggling",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "smuggling/duplicate-chunked");
}

// ---- chunked malformed close hook (RFC 9112 §7.1) ----

function _runWithStreamError(headers, parserError) {
  var bp  = b.middleware.bodyParser();
  var req = _manualReq("POST", headers);
  var res = _bodyRes();
  return helpers.withTestTimeout("body-parser: chunked-error settles", function () {
    return new Promise(function (resolve) {
      var settled = false;
      function settle(v) { if (settled) return; settled = true; resolve(Object.assign({ req: req, res: res }, v)); }
      res.on("finish", function () { settle({ nexted: false, status: res._endedStatus, headers: res._headers, body: res._captured }); });
      bp(req, res, function () { settle({ nexted: true }); });
      setImmediate(function () { req.emit("error", parserError); });
    });
  }, { timeoutMs: 2000 });                                                     // allow:raw-byte-literal — settle budget ms
}

async function testChunkedMalformedRefused() {
  var err = new Error("Parse Error: Invalid character in chunk size header");
  err.code = "HPE_INVALID_CHUNK_SIZE";
  var rv = await _runWithStreamError(
    { "content-type": "application/json", "transfer-encoding": "chunked" }, err);
  check("HPE_INVALID_CHUNK_SIZE → 400 + Connection: close + req.destroy()",
        rv.nexted === false && rv.status === 400 && rv.req._destroyed === true &&
        rv.headers && (rv.headers.Connection === "close" || rv.headers.connection === "close"));
  check("chunked-malformed body carries the http/chunked-malformed code", _bodyJson(rv).code === "http/chunked-malformed");
}

async function testChunkedExtensionOverflowRefused() {
  var err = new Error("Parse Error: chunk extensions overflow");
  err.code = "HPE_CHUNK_EXTENSIONS_OVERFLOW";
  var rv = await _runWithStreamError(
    { "content-type": "application/json", "transfer-encoding": "chunked" }, err);
  check("HPE_CHUNK_EXTENSIONS_OVERFLOW → 400 + connection torn down",
        rv.nexted === false && rv.status === 400 && rv.req._destroyed === true);
}

async function testGenericStreamErrorClosesConnection() {
  var err = new Error("read aborted");
  err.code = "ECONNRESET";
  var rv = await _runWithStreamError(
    { "content-type": "application/json", "content-length": "5" }, err);
  check("non-chunked stream error still returns 400 + Connection: close",
        rv.nexted === false && rv.status === 400 &&
        rv.headers && (rv.headers.Connection === "close" || rv.headers.connection === "close"));
}

// ---- multipart happy paths (disk + memory) ----

async function testMultipartDiskHappyPath() {
  var bd = "BoUnDaRy01";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="title"' }, body: "hello world" },
    { headers: { "Content-Disposition": 'form-data; name="avatar"; filename="pic.png"', "Content-Type": "image/png" },
      body: Buffer.from("PNGDATA") },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var tmpDir = path.join(TMP_ROOT, "disk1");
  var rv  = await _run({ multipart: { tmpDir: tmpDir } }, req);
  check("multipart disk: text field lands on req.body", rv.nexted === true && req.body && req.body.title === "hello world");
  check("multipart disk: file lands on req.files with path + hash + size",
        Array.isArray(req.files) && req.files.length === 1 &&
        req.files[0].field === "avatar" && req.files[0].filename === "pic.png" &&
        typeof req.files[0].path === "string" && req.files[0].buffer === null &&
        req.files[0].size === 7 && typeof req.files[0].hash === "string" && req.files[0].hash.length === 128);
  check("multipart disk: tmp file exists on disk before cleanup", fs.existsSync(req.files[0].path));
  // Fire the response-close cleanup hook the middleware wired.
  var savedPath = req.files[0].path;
  rv.res.emit("close");
  check("multipart disk: response-close cleanup unlinks the tmp file", !fs.existsSync(savedPath));
}

async function testMultipartMemoryStorage() {
  var bd = "BoUnDaRy02";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="doc"; filename="a.bin"', "Content-Type": "application/octet-stream" },
      body: Buffer.from("MEMBYTES") },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart memory: file exposes buffer, no path",
        rv.nexted === true && req.files.length === 1 &&
        req.files[0].path === null && Buffer.isBuffer(req.files[0].buffer) &&
        req.files[0].buffer.toString() === "MEMBYTES");
}

async function testMultipartRepeatedFieldArray() {
  var bd = "BoUnDaRy03";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="tag"' }, body: "x" },
    { headers: { "Content-Disposition": 'form-data; name="tag"' }, body: "y" },
    { headers: { "Content-Disposition": 'form-data; name="tag"' }, body: "z" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart repeated text field collapses to an array",
        rv.nexted === true && Array.isArray(req.body.tag) &&
        req.body.tag.join("") === "xyz");
}

async function testMultipartRfc5987Filename() {
  var bd = "BoUnDaRy04";
  // filename* extended parameter (RFC 5987) takes precedence over legacy filename.
  var body = _mpBody(bd, [
    { headers: {
        "Content-Disposition": "form-data; name=\"f\"; filename=\"legacy.txt\"; filename*=UTF-8''na%C3%AFve.txt",
        "Content-Type": "text/plain" },
      body: "data" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart filename* (RFC 5987 utf-8) decodes + wins over legacy filename=",
        rv.nexted === true && req.files.length === 1 && req.files[0].filename === "naïve.txt");
}

async function testMultipartFileNoContentType() {
  var bd = "BoUnDaRy42";
  // A file part with no Content-Type header defaults to application/octet-stream.
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="x.dat"' }, body: "bytes" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart file part with no Content-Type defaults mimeType to octet-stream",
        rv.nexted === true && req.files.length === 1 && req.files[0].mimeType === "application/octet-stream");
}

// ---- multipart adversarial ----

async function testMultipartNoBoundary400() {
  var req = _bodyReq("POST", { "content-type": "multipart/form-data", "content-length": "10" }, "----junk--");
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart with no boundary parameter → 400",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-no-boundary");
}

async function testMultipartBadBoundary400() {
  var req = _bodyReq("POST", { "content-type": 'multipart/form-data; boundary="has space"', "content-length": "10" }, "----junk--");
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart boundary violating RFC 2046 grammar → 400",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-bad-boundary");
}

async function testMultipartPoisonedField400() {
  var bd = "BoUnDaRy05";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="__proto__"' }, body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart __proto__ field name → 400 (pollution defense)",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-poisoned-field");
}

async function testMultipartBadDisposition400() {
  var bd = "BoUnDaRy06";
  var body = _mpBody(bd, [
    { headers: { "Content-Type": "text/plain" }, body: "x" },   // no Content-Disposition
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart part missing form-data disposition → 400",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-bad-disposition");
}

async function testMultipartTraversalFilename400() {
  var bd = "BoUnDaRy07";
  // A filename that sanitizes to empty (pure traversal) is refused.
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename=".."', "Content-Type": "text/plain" }, body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart filename that doesn't survive sanitization → 400",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-bad-filename");
}

async function testMultipartObsFoldHeader400() {
  var bd = "BoUnDaRy08";
  var body = _mpBody(bd, [
    { headerBlock: 'Content-Disposition: form-data; name="f"' + CRLF + " obs-fold-continuation", body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart obsolete line folding → 400",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-obs-fold");
}

async function testMultipartBadHeaderValue400() {
  var bd = "BoUnDaRy09";
  var body = _mpBody(bd, [
    { headerBlock: 'Content-Disposition: form-data; name="f"' + CRLF + "X-Bad: a\x00b", body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart header value with a NUL byte → 400",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-bad-header-value");
}

async function testMultipartMimeNotAllowed415() {
  var bd = "BoUnDaRy10";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="x.exe"', "Content-Type": "application/x-msdownload" }, body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory", mimeAllowlist: ["image/png"] } }, req);
  check("multipart file MIME not on the global allowlist → 415",
        rv.nexted === false && rv.status === 415 && _bodyJson(rv).code === "body-parser/multipart-mime-not-allowed");
}

async function testMultipartPerFieldMime415() {
  var bd = "BoUnDaRy11";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="avatar"; filename="x.gif"', "Content-Type": "image/gif" }, body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory", fields: { avatar: { mimeTypes: ["image/png"] } } } }, req);
  check("multipart per-field MIME allowlist rejects a non-listed type → 415",
        rv.nexted === false && rv.status === 415 && _bodyJson(rv).code === "body-parser/multipart-mime-not-allowed");
}

async function testMultipartTooManyFiles413() {
  var bd = "BoUnDaRy12";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="a"; filename="1.bin"', "Content-Type": "application/octet-stream" }, body: "x" },
    { headers: { "Content-Disposition": 'form-data; name="b"; filename="2.bin"', "Content-Type": "application/octet-stream" }, body: "y" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory", fileCount: 1 } }, req);
  check("multipart over fileCount → 413",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/multipart-too-many-files");
}

async function testMultipartTooManyFields413() {
  var bd = "BoUnDaRy13";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="a"' }, body: "x" },
    { headers: { "Content-Disposition": 'form-data; name="b"' }, body: "y" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory", fieldCount: 1 } }, req);
  check("multipart over fieldCount → 413",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/multipart-too-many-fields");
}

async function testMultipartFileTooLarge413() {
  var bd = "BoUnDaRy14";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="big.bin"', "Content-Type": "application/octet-stream" },
      body: Buffer.alloc(200, 0x41) },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory", fileSize: BYTES.bytes(50) } }, req);
  check("multipart file over fileSize → 413",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/multipart-file-too-large");
}

async function testMultipartPerFieldMaxBytes413() {
  var bd = "BoUnDaRy15";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="avatar"; filename="big.bin"', "Content-Type": "application/octet-stream" },
      body: Buffer.alloc(200, 0x41) },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory", fields: { avatar: { maxBytes: BYTES.bytes(20) } } } }, req);
  check("multipart per-field maxBytes over cap → 413 (per-field message)",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/multipart-file-too-large");
}

async function testMultipartFieldTooLarge413() {
  var bd = "BoUnDaRy16";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"' }, body: Buffer.alloc(200, 0x41) },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory", fieldSize: BYTES.bytes(50) } }, req);
  check("multipart text field over fieldSize → 413",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/multipart-field-too-large");
}

async function testMultipartHeadersTooLarge413() {
  var bd = "BoUnDaRy17";
  // > 16 KiB of header bytes with no CRLFCRLF terminator.
  var huge = "--" + bd + CRLF + "X-Pad: " + "A".repeat(BYTES.kib(17));
  var req = _manualReq("POST", _mpHeaders(bd, { "content-length": String(huge.length) }));
  var promise = _run({ multipart: { storage: "memory" } }, req);
  setImmediate(function () { req.emit("data", Buffer.from(huge)); });
  var rv = await promise;
  check("multipart part headers over 16 KiB → 413",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/multipart-headers-too-large");
}

async function testMultipartTotalTooLarge413() {
  var bd = "BoUnDaRy18";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"' }, body: Buffer.alloc(300, 0x41) },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  // fieldSize generous, totalSize small so the body-loop total guard trips.
  var rv  = await _run({ multipart: { storage: "memory", fieldSize: BYTES.mib(1), totalSize: BYTES.bytes(120) } }, req);
  check("multipart total request over totalSize → 413",
        rv.nexted === false && rv.status === 413 &&
        (_bodyJson(rv).code === "body-parser/multipart-total-too-large" ||
         _bodyJson(rv).code === "body-parser/multipart-too-large"));
}

async function testMultipartTruncated400() {
  var bd = "BoUnDaRy19";
  // A part with no closing --boundary-- then end.
  var partial = Buffer.from("--" + bd + CRLF +
    'Content-Disposition: form-data; name="f"' + CRLF + CRLF + "value");
  var req = _manualReq("POST", _mpHeaders(bd, { "content-length": String(partial.length) }));
  var promise = _run({ multipart: { storage: "memory" } }, req);
  setImmediate(function () { req.emit("data", partial); req.emit("end"); });
  var rv = await promise;
  check("multipart stream ending before the final boundary → 400 truncated",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-truncated");
}

async function testMultipartStreamError400() {
  var bd = "BoUnDaRy20";
  var req = _manualReq("POST", _mpHeaders(bd, { "content-length": "50" }));
  var promise = _run({ multipart: { storage: "memory" } }, req);
  setImmediate(function () {
    req.emit("data", Buffer.from("--" + bd + CRLF));
    req.emit("error", new Error("socket reset"));
  });
  var rv = await promise;
  check("multipart underlying stream error → 400",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-stream");
}

// ---- multipart fileFilter ----

async function testMultipartFileFilterRejectFalse() {
  var bd = "BoUnDaRy21";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="reject.bin"', "Content-Type": "application/octet-stream" }, body: "skipme" },
    { headers: { "Content-Disposition": 'form-data; name="g"; filename="keep.bin"', "Content-Type": "application/octet-stream" }, body: "keepme" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var audit = b.testing.captureAudit();
  var rv = await _run({ multipart: { storage: "memory", audit: audit,
    fileFilter: function (part) { return part.field !== "f"; } } }, req);
  check("fileFilter false rejects the part into req.filesRejected, keeps the other",
        rv.nexted === true && req.files.length === 1 && req.files[0].field === "g" &&
        req.filesRejected.length === 1 && req.filesRejected[0].field === "f" &&
        req.filesRejected[0].code === "fileFilter");
  check("fileFilter rejection emits the audit event",
        audit.byAction("body-parser.multipart.file_rejected").length === 1);
}

async function testMultipartFileFilterRejectObject() {
  var bd = "BoUnDaRy22";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="x.bin"', "Content-Type": "application/octet-stream" }, body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv = await _run({ multipart: { storage: "memory",
    fileFilter: function () { return { reject: true, code: "too-risky", message: "nope" }; } } }, req);
  check("fileFilter reject-object carries custom code + message into filesRejected",
        rv.nexted === true && req.files.length === 0 && req.filesRejected.length === 1 &&
        req.filesRejected[0].code === "too-risky" && req.filesRejected[0].message === "nope");
}

async function testMultipartFileFilterThrow500() {
  var bd = "BoUnDaRy23";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="x.bin"', "Content-Type": "application/octet-stream" }, body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv = await _run({ multipart: { storage: "memory",
    fileFilter: function () { throw new Error("filter boom"); } } }, req);
  check("fileFilter throw → 500 with a generic reason (no internal detail echoed)",
        rv.nexted === false && rv.status === 500);
  check("fileFilter-throw 500 body carries the generic status phrase, not the throw detail",
        String(rv.body).indexOf("filter boom") === -1 && _bodyJson(rv).error === "Internal Server Error");
}

async function testMultipartTmpDirFailure500() {
  var bd = "BoUnDaRy24";
  // tmpDir whose parent is a regular file → ensureDir throws ENOTDIR → 500.
  var blocker = path.join(TMP_ROOT, "blocker-file");
  fs.mkdirSync(TMP_ROOT, { recursive: true });
  fs.writeFileSync(blocker, "x");
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="x.bin"', "Content-Type": "application/octet-stream" }, body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv = await _run({ multipart: { storage: "disk", tmpDir: path.join(blocker, "sub") } }, req);
  check("multipart tmp-dir creation failure → 500", rv.nexted === false && rv.status === 500);
  check("tmp-dir 500 does not echo the internal fs path to the client",
        String(rv.body).indexOf("blocker-file") === -1 && _bodyJson(rv).error === "Internal Server Error");
}

// ---- keepRawBody path ----

async function testKeepRawBodyStashesBytes() {
  var raw = '{"hook":true}';
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": String(raw.length) }, raw);
  var rv  = await _run({ keepRawBody: true, json: {} }, req);
  check("keepRawBody stashes the raw bytes AND parses req.body",
        rv.nexted === true && Buffer.isBuffer(req.bodyRaw) && req.bodyRaw.toString() === raw &&
        req.body && req.body.hook === true);
}

async function testKeepRawBodyEmpty() {
  var req = _bodyReq("POST", { "content-type": "application/json", "transfer-encoding": "chunked" }, undefined);
  var rv  = await _run({ keepRawBody: true, json: {} }, req);
  check("keepRawBody with an empty body → req.body undefined, empty bodyRaw",
        rv.nexted === true && req.body === undefined && Buffer.isBuffer(req.bodyRaw) && req.bodyRaw.length === 0);
}

async function testKeepRawBodyStrictReject() {
  var raw = '"scalar"';
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": String(raw.length) }, raw);
  var rv  = await _run({ keepRawBody: true, json: { strict: true } }, req);
  check("keepRawBody strict-mode scalar → 400 json-strict",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/json-strict");
}

async function testKeepRawBodyHookThrow() {
  var raw = "{}";
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": String(raw.length) }, raw);
  var rv  = await _run({ keepRawBody: true, json: { parseHook: function () { throw new Error("secret 5432"); } } }, req);
  check("keepRawBody parseHook throw → 400 json-hook, no detail echoed",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/json-hook" &&
        String(rv.body).indexOf("5432") === -1);
}

// ---- config-time validation ----

function testCreateRejectsUnknownOpt() {
  var threw = false;
  try { b.middleware.bodyParser({ nope: true }); }
  catch (_e) { threw = true; }
  check("bodyParser({ unknownOpt }) throws at construction", threw === true);
}

function testCreateRejectsBadStorage() {
  var threw = false;
  try { b.middleware.bodyParser({ multipart: { storage: "s3" } }); }
  catch (e) { threw = e instanceof TypeError; }
  check("multipart.storage other than disk/memory throws TypeError", threw === true);
}

// ---- raw() convenience factory ----

async function testRawFactoryCapturesAnyType() {
  var payload = Buffer.from("webhook-bytes");
  var req = _bodyReq("POST", { "content-type": "application/x-weird", "content-length": String(payload.length) }, payload);
  var bp  = b.middleware.bodyParser.raw({ limit: BYTES.mib(1) });
  var res = _bodyRes();
  var rv  = await helpers.withTestTimeout("body-parser: raw factory settles", function () {
    return new Promise(function (resolve) {
      var settled = false;
      function settle(v) { if (settled) return; settled = true; resolve(v); }
      res.on("finish", function () { settle({ nexted: false, status: res._endedStatus }); });
      bp(req, res, function () { settle({ nexted: true }); });
    });
  }, { timeoutMs: 3000 });                                                     // allow:raw-byte-literal — settle budget ms
  check("bodyParser.raw() captures any Content-Type as a Buffer body",
        rv.nexted === true && Buffer.isBuffer(req.body) && req.body.equals(payload));
}

// ---- standalone b.parsers.{json,multipart} ----

async function testStandaloneJsonHappy() {
  var raw = '{"ok":1}';
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": String(raw.length) }, raw);
  var parsed = await b.parsers.json(req, {});
  check("b.parsers.json parses a request body directly", parsed && parsed.ok === 1);
}

async function testStandaloneJsonBadMaxBytes() {
  var threw = false;
  var req = _bodyReq("POST", { "content-type": "application/json" }, "{}");
  try { await b.parsers.json(req, { maxBytes: -5 }); }
  catch (e) { threw = e && e.code === "body-parser/bad-max-bytes"; }
  check("b.parsers.json rejects a negative maxBytes at resolve", threw === true);
}

async function testStandaloneMultipartNotMultipart() {
  var threw = false;
  var req = _bodyReq("POST", { "content-type": "application/json" }, "{}");
  try { await b.parsers.multipart(req, {}); }
  catch (e) { threw = e && e.code === "body-parser/standalone-not-multipart"; }
  check("b.parsers.multipart on a non-multipart request throws", threw === true);
}

async function testStandaloneMultipartBadMaxFiles() {
  var bd = "BoUnDaRy30";
  var threw = false;
  var req = _bodyReq("POST", _mpHeaders(bd), "");
  try { await b.parsers.multipart(req, { maxFiles: -1 }); }
  catch (e) { threw = e && e.code === "body-parser/bad-max-files"; }
  check("b.parsers.multipart rejects a negative maxFiles", threw === true);
}

async function testStandaloneMultipartHappy() {
  var bd = "BoUnDaRy31";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="s.bin"', "Content-Type": "application/octet-stream" }, body: "standalone" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var result = await b.parsers.multipart(req, { tmpDir: path.join(TMP_ROOT, "standalone") });
  check("b.parsers.multipart returns { fields, files, filesRejected }",
        result && Array.isArray(result.files) && result.files.length === 1 && result.files[0].field === "f");
  if (result.files[0].path) { try { fs.unlinkSync(result.files[0].path); } catch (_e) { /* already gone */ } }
}

// ---- multipart RFC 5987 filename* charset edge cases ----

async function testMultipartRfc5987CharsetEdges() {
  var bd = "BoUnDaRy32";
  var body = _mpBody(bd, [
    // iso-8859-1 opt-in: %e9 → é (Latin-1 byte maps directly to code point).
    { headers: { "Content-Disposition": "form-data; name=\"a\"; filename*=iso-8859-1''caf%e9.txt", "Content-Type": "text/plain" }, body: "1" },
    // utf-8 ext-value that fails decodeURIComponent → dropped → legacy filename wins.
    { headers: { "Content-Disposition": "form-data; name=\"b\"; filename=\"fallback.txt\"; filename*=UTF-8''%C3", "Content-Type": "text/plain" }, body: "2" },
    // charset neither utf-8 nor an opted-in one → dropped → legacy filename wins.
    { headers: { "Content-Disposition": "form-data; name=\"c\"; filename=\"legacy2.txt\"; filename*=Shift_JIS''x", "Content-Type": "text/plain" }, body: "3" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory", filenameCharsets: ["iso-8859-1"] } }, req);
  check("multipart filename* iso-8859-1 (opted in) percent-decodes to Latin-1",
        rv.nexted === true && req.files.length === 3 && req.files[0].filename === "café.txt");
  check("multipart filename* utf-8 malformed → falls back to legacy filename=",
        req.files[1].filename === "fallback.txt");
  check("multipart filename* unsupported charset → falls back to legacy filename=",
        req.files[2].filename === "legacy2.txt");
}

// ---- multipart preamble drop + chunk-split body (multi-chunk delivery) ----

async function testMultipartPreambleDrop() {
  var bd = "BoUnDaRy33";
  // A large preamble (> boundary.length + 100) with no boundary in the first
  // chunk forces the INITIAL-state memory-bound drop before the real body.
  var preamble = Buffer.from("P".repeat(200));
  var rest = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"' }, body: "hi" },
  ]);
  var req = _manualReq("POST", _mpHeaders(bd, { "content-length": String(preamble.length + rest.length) }));
  var promise = _run({ multipart: { storage: "memory" } }, req);
  setImmediate(function () {
    req.emit("data", preamble);
    setImmediate(function () { req.emit("data", rest); req.emit("end"); });
  });
  var rv = await promise;
  check("multipart preamble drop then real body parses the field",
        rv.nexted === true && req.body && req.body.f === "hi");
}

async function testMultipartChunkSplitBody() {
  var bd = "BoUnDaRy34";
  // Deliver a field body split across two chunks so the MP_BODY emit-without-
  // marker branch (emit all but the trailing look-ahead window) runs.
  var chunk1 = Buffer.from("--" + bd + CRLF + 'Content-Disposition: form-data; name="f"' + CRLF + CRLF + "A".repeat(40));
  var chunk2 = Buffer.from("B".repeat(10) + CRLF + "--" + bd + "--" + CRLF);
  var req = _manualReq("POST", _mpHeaders(bd, { "content-length": String(chunk1.length + chunk2.length) }));
  var promise = _run({ multipart: { storage: "memory" } }, req);
  setImmediate(function () {
    req.emit("data", chunk1);
    setImmediate(function () { req.emit("data", chunk2); req.emit("end"); });
  });
  var rv = await promise;
  check("multipart chunk-split field body reassembles across chunks",
        rv.nexted === true && req.body.f === "A".repeat(40) + "B".repeat(10));
}

// ---- multipart boundary-terminator tolerances ----

async function testMultipartBareLfTolerated() {
  var bd = "BoUnDaRy35";
  // Transport replaced the CRLF after the opening boundary with a bare LF.
  var body = Buffer.from("--" + bd + "\n" +
    'Content-Disposition: form-data; name="f"' + CRLF + CRLF + "hello" +
    CRLF + "--" + bd + "--" + CRLF);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart tolerates a bare LF after the boundary", rv.nexted === true && req.body.f === "hello");
}

async function testMultipartGarbageAfterBoundary400() {
  var bd = "BoUnDaRy36";
  var body = Buffer.from("--" + bd + "XY");   // neither --, CRLF, nor LF after boundary
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  var rv  = await _run({ multipart: { storage: "memory" } }, req);
  check("multipart garbage after the boundary → 400 malformed",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/multipart-malformed");
}

// ---- multipart total-size guards (headers-phase + file-body-phase + discard) ----

async function testMultipartTotalTooLargeInHeaders413() {
  var bd = "BoUnDaRy37";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"' }, body: "x" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  // totalSize smaller than the first part's header bytes → trip in MP_HEADERS.
  var rv  = await _run({ multipart: { storage: "memory", totalSize: BYTES.bytes(10) } }, req);
  check("multipart header bytes alone over totalSize → 413 (headers-phase guard)",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/multipart-too-large");
}

async function testMultipartFileBodyTotalTooLarge413() {
  var bd = "BoUnDaRy38";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="x.bin"', "Content-Type": "application/octet-stream" },
      body: Buffer.alloc(200, 0x41) },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  // Per-file cap generous, request total small → trip on the file-body total guard.
  var rv  = await _run({ multipart: { storage: "memory", fileSize: BYTES.mib(1), totalSize: BYTES.bytes(150) } }, req);
  check("multipart file body over totalSize (per-file cap generous) → 413 total",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/multipart-total-too-large");
}

async function testMultipartDiscardTotalTooLarge413() {
  var bd = "BoUnDaRy39";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="x.bin"', "Content-Type": "application/octet-stream" },
      body: Buffer.alloc(200, 0x41) },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  // fileFilter discards the part; the discard path still counts bytes toward
  // totalSize as a per-request DoS guard.
  var rv  = await _run({ multipart: { storage: "memory", totalSize: BYTES.bytes(150),
    fileFilter: function () { return false; } } }, req);
  check("multipart discarded-part bytes over totalSize → 413 total",
        rv.nexted === false && rv.status === 413 && _bodyJson(rv).code === "body-parser/multipart-total-too-large");
}

// ---- keepRawBody malformed JSON ----

async function testKeepRawBodyMalformedJson() {
  var raw = "{bad json";
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": String(raw.length) }, raw);
  var rv  = await _run({ keepRawBody: true, json: {} }, req);
  check("keepRawBody malformed JSON → 400 json-malformed (raw-buf pipeline)",
        rv.nexted === false && rv.status === 400 && _bodyJson(rv).code === "body-parser/json-malformed");
}

// ---- standalone multipart maxBytes clamp ----

async function testStandaloneMultipartMaxBytesClamp() {
  var bd = "BoUnDaRy41";
  var body = _mpBody(bd, [
    { headers: { "Content-Disposition": 'form-data; name="f"; filename="s.bin"', "Content-Type": "application/octet-stream" }, body: "tiny" },
  ]);
  var req = _bodyReq("POST", _mpHeaders(bd, { "content-length": String(body.length) }), body);
  // maxBytes below the default fileSize clamps the per-file cap down to it.
  var result = await b.parsers.multipart(req, { maxBytes: BYTES.bytes(500), tmpDir: path.join(TMP_ROOT, "clamp") });
  check("b.parsers.multipart maxBytes clamps totalSize + fileSize and still parses",
        result && result.files.length === 1 && result.files[0].size === 4);
  if (result.files[0].path) { try { fs.unlinkSync(result.files[0].path); } catch (_e) { /* already gone */ } }
}

// ---- exported pure helpers ----

function testExportedContentType() {
  var ct = bodyParserLib._contentType({ headers: { "content-type": 'multipart/form-data; boundary="a;b"; charset=utf-8' } });
  check("_contentType lowercases the type", ct.type === "multipart/form-data");
  check("_contentType quote-aware splitter keeps a quoted boundary intact", ct.params.boundary === "a;b");
  check("_contentType parses a second parameter", ct.params.charset === "utf-8");
  var none = bodyParserLib._contentType({ headers: {} });
  check("_contentType with no header → empty type + params", none.type === "" && Object.keys(none.params).length === 0);
}

function testExportedContentTypeDropsPoisonedParam() {
  var ct = bodyParserLib._contentType({ headers: { "content-type": "text/plain; __proto__=x; charset=utf-8" } });
  check("_contentType drops a poisoned parameter name", !("__proto__" in ct.params) && ct.params.charset === "utf-8");
  check("_contentType params map carries no prototype chain", Object.getPrototypeOf(ct.params) === null);
}

function testExportedHasBody() {
  check("_hasBody false for GET", bodyParserLib._hasBody({ method: "GET", headers: {} }) === false);
  check("_hasBody false for POST Content-Length 0",
        bodyParserLib._hasBody({ method: "POST", headers: { "content-length": "0" } }) === false);
  check("_hasBody true for POST with a positive Content-Length",
        bodyParserLib._hasBody({ method: "POST", headers: { "content-length": "5" } }) === true);
  check("_hasBody true for POST with Transfer-Encoding",
        bodyParserLib._hasBody({ method: "POST", headers: { "transfer-encoding": "chunked" } }) === true);
  check("_hasBody true for a malformed Content-Length (routes to the 400 path)",
        bodyParserLib._hasBody({ method: "POST", headers: { "content-length": "abc" } }) === true);
  check("_hasBody false for a body-bearing method with neither CL nor TE",
        bodyParserLib._hasBody({ method: "POST", headers: {} }) === false);
}

function testExportedSanitizeFilename() {
  check("_sanitizeFilename strips POSIX path components",
        bodyParserLib._sanitizeFilename("/etc/passwd") === "passwd");
  check("_sanitizeFilename strips Windows path components",
        bodyParserLib._sanitizeFilename("C:\\Users\\x\\report.pdf") === "report.pdf");
  check("_sanitizeFilename strips BiDi override codepoints",
        bodyParserLib._sanitizeFilename("Photo‮gpj.png") === "Photogpj.png");
  check("_sanitizeFilename strips leading/trailing dots",
        bodyParserLib._sanitizeFilename("...name...") === "name");
  check("_sanitizeFilename returns null for a pure-traversal name",
        bodyParserLib._sanitizeFilename("..") === null);
  check("_sanitizeFilename returns null for non-string input",
        bodyParserLib._sanitizeFilename(42) === null);
  check("_sanitizeFilename caps length at 255",
        bodyParserLib._sanitizeFilename("a".repeat(400)).length === 255);
}

function testPoisonedKeysExport() {
  check("POISONED_KEYS export is a Set including __proto__",
        bodyParserLib.POISONED_KEYS instanceof Set && bodyParserLib.POISONED_KEYS.has("__proto__"));
}

// ---- runner ----

async function run() {
  try {
    // dispatch + defaults
    await testNonBodyMethodSkips();
    await testAlreadyParsedShortCircuits();
    await testContentLengthZeroIsNoBody();
    await testJsonHappyPath();
    await testJsonParseHookTransforms();
    await testUrlencodedHappyAndArray();
    await testTextParser();
    await testRawParser();
    await testEmptyBodiesReturnDefaults();

    // 415 / disabled
    await testUnsupportedContentType415();
    await testDisabledSubParserFallsThroughTo415();

    // size caps + bad content-length
    await testContentLengthOverLimitPreflight413();
    await testStreamOverflow413();
    await testMalformedContentLength400();

    // JSON adversarial
    await testJsonStrictRejectsScalar();
    await testJsonNonStrictScalar();
    await testJsonMalformed400();
    await testJsonParseHookThrow400();

    // urlencoded adversarial
    await testUrlencodedPoisonedKey400();
    await testUrlencodedArrayLimit413();
    await testUrlencodedTooManyFields413();

    // smuggling
    await testSmugglingClTeConflict();
    await testSmugglingMultipleContentLength();
    await testSmugglingTeNotChunked();
    await testSmugglingDuplicateChunked();

    // chunked malformed close hook
    await testChunkedMalformedRefused();
    await testChunkedExtensionOverflowRefused();
    await testGenericStreamErrorClosesConnection();

    // multipart happy
    await testMultipartDiskHappyPath();
    await testMultipartMemoryStorage();
    await testMultipartRepeatedFieldArray();
    await testMultipartRfc5987Filename();
    await testMultipartRfc5987CharsetEdges();
    await testMultipartPreambleDrop();
    await testMultipartChunkSplitBody();
    await testMultipartBareLfTolerated();
    await testMultipartFileNoContentType();

    // multipart adversarial
    await testMultipartNoBoundary400();
    await testMultipartBadBoundary400();
    await testMultipartPoisonedField400();
    await testMultipartBadDisposition400();
    await testMultipartTraversalFilename400();
    await testMultipartObsFoldHeader400();
    await testMultipartBadHeaderValue400();
    await testMultipartMimeNotAllowed415();
    await testMultipartPerFieldMime415();
    await testMultipartTooManyFiles413();
    await testMultipartTooManyFields413();
    await testMultipartFileTooLarge413();
    await testMultipartPerFieldMaxBytes413();
    await testMultipartFieldTooLarge413();
    await testMultipartHeadersTooLarge413();
    await testMultipartTotalTooLarge413();
    await testMultipartTotalTooLargeInHeaders413();
    await testMultipartFileBodyTotalTooLarge413();
    await testMultipartGarbageAfterBoundary400();
    await testMultipartTruncated400();
    await testMultipartStreamError400();

    // fileFilter
    await testMultipartFileFilterRejectFalse();
    await testMultipartFileFilterRejectObject();
    await testMultipartFileFilterThrow500();
    await testMultipartTmpDirFailure500();
    await testMultipartDiscardTotalTooLarge413();

    // keepRawBody
    await testKeepRawBodyStashesBytes();
    await testKeepRawBodyEmpty();
    await testKeepRawBodyStrictReject();
    await testKeepRawBodyHookThrow();
    await testKeepRawBodyMalformedJson();

    // config-time validation
    testCreateRejectsUnknownOpt();
    testCreateRejectsBadStorage();

    // raw factory
    await testRawFactoryCapturesAnyType();

    // standalone parsers
    await testStandaloneJsonHappy();
    await testStandaloneJsonBadMaxBytes();
    await testStandaloneMultipartNotMultipart();
    await testStandaloneMultipartBadMaxFiles();
    await testStandaloneMultipartHappy();
    await testStandaloneMultipartMaxBytesClamp();

    // exported pure helpers
    testExportedContentType();
    testExportedContentTypeDropsPoisonedParam();
    testExportedHasBody();
    testExportedSanitizeFilename();
    testPoisonedKeysExport();
  } finally {
    // The 4xx/5xx/chunked rejects emit on the real audit chain, scheduling
    // its age-flush timer; drain it so no timer lingers past run().
    await b.audit.flush();
    // Remove the disk-mode multipart tmp root.
    try { fs.rmSync(TMP_ROOT, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

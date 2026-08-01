// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * body-parser Content-Type dispatch + per-parser behavior.
 *
 * Exercises the five sub-parsers through the real middleware and the
 * standalone b.parsers.* surface: JSON (strict, parseHook, keepRawBody,
 * empty), urlencoded (repeated-key arrays, poisoned keys, array +
 * field-count caps), text/plain, raw octet-stream, and multipart/form-data
 * (disk + memory storage, per-file/field/total caps, MIME allowlists,
 * fileFilter, filename sanitization, header validation, boundary framing).
 * Also covers the size-limit / 413, malformed / missing Content-Length,
 * 415 unsupported-type, and body-bearing-method dispatch branches.
 *
 * Every case drives a Readable-stream request carrying the raw body bytes
 * plus the matching Content-Type / Content-Length / Transfer-Encoding
 * headers, and asserts on the parsed result (req.body / req.files / the
 * response status) — never on parser internals.
 */

var EventEmitter = require("events").EventEmitter;
var nodeFs       = require("fs");
var nodeCrypto   = require("crypto");
var helpers      = require("../helpers");
var b            = helpers.b;
var check        = helpers.check;
var _bodyReq     = helpers._bodyReq;
var _bodyRes     = helpers._bodyRes;

var BYTES = b.constants.BYTES;

// ---- request/response drivers ----

// Multi-chunk request — _bodyReq emits the whole body in one `data` event,
// so a test that needs the parser to see a boundary-less prefix (preamble
// dropping) delivers the bytes across several events via this builder.
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

// Run the middleware and resolve once it settles — either next() fired
// (parse succeeded / skipped) or the error response was written. Poll the
// settled condition rather than racing a fixed sleep (§6b).
async function _run(bp, req, res, label) {
  var nextCalled = false;
  bp(req, res, function () { nextCalled = true; });
  await helpers.waitUntil(function () {
    return nextCalled || res._endedStatus !== null;
  }, {
    timeoutMs: 5000,
    label:     "body-parser-content-types: " + label + " settled",
  });
  return { next: nextCalled, status: res._endedStatus, req: req, res: res };
}

// Convenience: build the request from a single body buffer + headers and run.
async function _drive(opts, method, headers, body, label) {
  var bp  = b.middleware.bodyParser(opts);
  var req = _bodyReq(method, headers, body);
  var res = _bodyRes();
  return _run(bp, req, res, label);
}

// ---- multipart body builders (RFC 7578 wire shape) ----

function _mpFilePart(bd, name, filename, ctype, body) {
  return "--" + bd + "\r\n" +
    "Content-Disposition: form-data; name=\"" + name + "\"; filename=\"" + filename + "\"\r\n" +
    (ctype ? ("Content-Type: " + ctype + "\r\n") : "") +
    "\r\n" + body + "\r\n";
}
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

// ================= JSON =================

async function testJsonHappyPath() {
  var rv = await _drive({ json: {} }, "POST",
    { "content-type": "application/json", "content-length": "13" },
    '{"hello":"x"}', "json-happy");
  check("json: object body parsed to req.body",
        rv.next === true && rv.req.body && rv.req.body.hello === "x");
}

async function testJsonStrictRejectsBareString() {
  var body = '"just a string"';
  var rv = await _drive({ json: {} }, "POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body, "json-strict-bare-string");
  check("json strict: body not starting with {/[ rejected 400 (no next)",
        rv.next === false && rv.status === 400);
}

async function testJsonStrictAcceptsArrayWithLeadingWhitespace() {
  var body = "  \n[1,2,3]";
  var rv = await _drive({ json: {} }, "POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body, "json-strict-array-ws");
  check("json strict: leading whitespace then '[' accepted",
        rv.next === true && Array.isArray(rv.req.body) && rv.req.body.length === 3);
}

async function testJsonNonStrictAcceptsBareValue() {
  var body = '"bare"';
  var rv = await _drive({ json: { strict: false } }, "POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body, "json-nonstrict-bare");
  check("json strict:false: bare JSON value accepted",
        rv.next === true && rv.req.body === "bare");
}

async function testJsonEmptyBodyIsUndefined() {
  // transfer-encoding: chunked makes _hasBody true with zero buffered bytes,
  // so _parseJson hits the empty-buffer branch and leaves req.body undefined.
  var rv = await _drive({ json: {} }, "POST",
    { "content-type": "application/json", "transfer-encoding": "chunked" },
    "", "json-empty");
  check("json: empty body -> next() with req.body undefined",
        rv.next === true && rv.req.body === undefined);
}

async function testJsonMalformedRejected() {
  var body = "{ not valid json";
  var rv = await _drive({ json: {} }, "POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body, "json-malformed");
  check("json: malformed body -> 400", rv.next === false && rv.status === 400);
  check("json: malformed 400 surfaces a JSON grammar message (not blanket-redacted)",
        rv.res._captured.indexOf("JSON") !== -1);
}

async function testJsonParseHookSuccess() {
  var rv = await _drive({ json: { parseHook: function (p) { return { wrapped: p }; } } }, "POST",
    { "content-type": "application/json", "content-length": "7" },
    '{"a":1}', "json-hook-ok");
  check("json parseHook: transformed value replaces req.body",
        rv.next === true && rv.req.body && rv.req.body.wrapped && rv.req.body.wrapped.a === 1);
}

async function testJsonParseHookThrowRedacted() {
  var SENTINEL = "hook-secret-detail-3c2b1a";
  var rv = await _drive(
    { json: { parseHook: function () { throw new Error(SENTINEL + " host:5432"); } } }, "POST",
    { "content-type": "application/json", "content-length": "7" },
    '{"a":1}', "json-hook-throw");
  check("json parseHook throw -> 400", rv.next === false && rv.status === 400);
  check("json parseHook throw: internal detail is not echoed to the client",
        rv.res._captured.indexOf(SENTINEL) === -1 && rv.res._captured.indexOf("host:5432") === -1);
  check("json parseHook throw: curated 'parse hook' message surfaced",
        rv.res._captured.indexOf("parse hook") !== -1);
}

async function testKeepRawBodyExposesBytesAndParses() {
  var rv = await _drive({ keepRawBody: true, json: {} }, "POST",
    { "content-type": "application/json", "content-length": "9" },
    '{"a":123}', "keepraw");
  check("keepRawBody: req.bodyRaw is the raw Buffer",
        rv.next === true && Buffer.isBuffer(rv.req.bodyRaw) && rv.req.bodyRaw.length === 9);
  check("keepRawBody: req.body is still the parsed object",
        rv.req.body && rv.req.body.a === 123);
}

async function testKeepRawBodyEmptyBodyUndefined() {
  var rv = await _drive({ keepRawBody: true, json: {} }, "POST",
    { "content-type": "application/json", "transfer-encoding": "chunked" },
    "", "keepraw-empty");
  check("keepRawBody: empty body -> req.body undefined, bodyRaw empty Buffer",
        rv.next === true && rv.req.body === undefined &&
        Buffer.isBuffer(rv.req.bodyRaw) && rv.req.bodyRaw.length === 0);
}

async function testKeepRawBodyStrictReject() {
  var body = '"nope"';
  var rv = await _drive({ keepRawBody: true, json: {} }, "POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body, "keepraw-strict");
  check("keepRawBody: strict rejection still returns 400",
        rv.next === false && rv.status === 400);
}

// ================= urlencoded =================

async function testUrlencodedHappyPath() {
  var rv = await _drive({}, "POST",
    { "content-type": "application/x-www-form-urlencoded", "content-length": "7" },
    "a=1&b=2", "urlenc-happy");
  check("urlencoded: fields parsed to req.body",
        rv.next === true && rv.req.body.a === "1" && rv.req.body.b === "2");
}

async function testUrlencodedRepeatedKeyBecomesArray() {
  var body = "tag=a&tag=b&tag=c&x=1";
  var rv = await _drive({}, "POST",
    { "content-type": "application/x-www-form-urlencoded", "content-length": String(Buffer.byteLength(body)) },
    body, "urlenc-array");
  check("urlencoded: repeated key collects into an array",
        rv.next === true && Array.isArray(rv.req.body.tag) &&
        rv.req.body.tag.length === 3 && rv.req.body.tag[2] === "c" &&
        rv.req.body.x === "1");
}

async function testUrlencodedEmptyBodyIsEmptyObject() {
  var rv = await _drive({}, "POST",
    { "content-type": "application/x-www-form-urlencoded", "transfer-encoding": "chunked" },
    "", "urlenc-empty");
  check("urlencoded: empty body -> req.body {}",
        rv.next === true && rv.req.body && Object.keys(rv.req.body).length === 0);
}

async function testUrlencodedPoisonedKeyRejected() {
  var body = "__proto__=x";
  var rv = await _drive({}, "POST",
    { "content-type": "application/x-www-form-urlencoded", "content-length": String(Buffer.byteLength(body)) },
    body, "urlenc-poisoned");
  check("urlencoded: poisoned key (__proto__) rejected 400",
        rv.next === false && rv.status === 400);
}

async function testUrlencodedArrayTooLargeRejected() {
  var rv = await _drive({ urlencoded: { arrayLimit: 2 } }, "POST",
    { "content-type": "application/x-www-form-urlencoded", "content-length": "11" },
    "k=1&k=2&k=3", "urlenc-array-cap");
  check("urlencoded: array exceeding arrayLimit -> 413",
        rv.next === false && rv.status === 413);
}

async function testUrlencodedTooManyFieldsRejected() {
  // Total-key soft cap is arrayLimit + ~1000 headroom; default arrayLimit 100
  // => threshold 1100. 1102 distinct keys trips it.
  var parts = [];
  for (var i = 0; i < 1102; i++) parts.push("k" + i + "=1");
  var body = parts.join("&");
  var rv = await _drive({}, "POST",
    { "content-type": "application/x-www-form-urlencoded", "content-length": String(Buffer.byteLength(body)) },
    body, "urlenc-toomany");
  check("urlencoded: too many total fields -> 413",
        rv.next === false && rv.status === 413);
}

// ================= text =================

async function testTextPlainParsed() {
  var rv = await _drive({}, "POST",
    { "content-type": "text/plain", "content-length": "11" },
    "hello world", "text-plain");
  check("text/plain: body decoded to a string on req.body",
        rv.next === true && rv.req.body === "hello world");
}

// ================= raw =================

async function testRawOctetStreamBuffer() {
  var buf = Buffer.from([1, 2, 3, 4, 5]);
  var rv = await _drive({}, "POST",
    { "content-type": "application/octet-stream", "content-length": "5" },
    buf, "raw-octet");
  check("raw: octet-stream body exposed as a Buffer",
        rv.next === true && Buffer.isBuffer(rv.req.body) && rv.req.body.length === 5 &&
        rv.req.body[0] === 1);
}

async function testRawFactoryCapturesAnyType() {
  var bp  = b.middleware.bodyParser.raw();
  var buf = Buffer.from([9, 8, 7]);
  var req = _bodyReq("POST", { "content-type": "application/vnd.custom+cbor", "content-length": "3" }, buf);
  var res = _bodyRes();
  var rv  = await _run(bp, req, res, "raw-factory");
  check("bodyParser.raw(): any Content-Type captured as raw Buffer bytes",
        rv.next === true && Buffer.isBuffer(rv.req.body) && rv.req.body.length === 3 &&
        rv.req.body[0] === 9);
}

async function testRawFactoryHonorsLimit() {
  var bp  = b.middleware.bodyParser.raw({ limit: BYTES.bytes(4) });
  var req = _bodyReq("POST", { "content-type": "application/octet-stream", "content-length": "10" }, Buffer.alloc(10));
  var res = _bodyRes();
  var rv  = await _run(bp, req, res, "raw-factory-limit");
  check("bodyParser.raw({limit}): oversize Content-Length -> 413",
        rv.next === false && rv.status === 413);
}

// ================= dispatch / limits / methods =================

async function testUnsupportedContentTypeIs415() {
  var body = "<a/>";
  var rv = await _drive(
    { json: {}, urlencoded: false, text: false, raw: false, multipart: false }, "POST",
    { "content-type": "application/xml", "content-length": String(Buffer.byteLength(body)) },
    body, "415");
  check("dispatch: body with no matching enabled parser -> 415",
        rv.next === false && rv.status === 415);
}

async function testContentLengthOverLimitIs413() {
  var rv = await _drive({ json: { limit: BYTES.bytes(10) } }, "POST",
    { "content-type": "application/json", "content-length": "9999" },
    '{"a":1}', "cl-too-large");
  check("limit: Content-Length over limit rejected 413 before buffering",
        rv.next === false && rv.status === 413);
}

async function testMalformedContentLengthIs400() {
  var rv = await _drive({ json: {} }, "POST",
    { "content-type": "application/json", "content-length": "12abc" },
    '{"a":1}', "cl-malformed");
  check("limit: non-decimal Content-Length rejected 400",
        rv.next === false && rv.status === 400);
}

async function testGetWithBodyHeadersSkipsParsing() {
  var rv = await _drive({ json: {} }, "GET",
    { "content-type": "application/json", "content-length": "7" },
    '{"z":1}', "get-skip");
  check("dispatch: non-body-bearing method (GET) -> next() without parsing",
        rv.next === true && rv.req.body === undefined);
}

async function testDeleteWithBodyIsParsed() {
  var rv = await _drive({ json: {} }, "DELETE",
    { "content-type": "application/json", "content-length": "7" },
    '{"z":1}', "delete-parse");
  check("dispatch: DELETE is body-bearing and parses JSON",
        rv.next === true && rv.req.body && rv.req.body.z === 1);
}

async function testAlreadyParsedBodyIsLeftAlone() {
  var bp  = b.middleware.bodyParser({ json: {} });
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "7" }, '{"z":9}');
  req.body = { pre: 1 };
  var res = _bodyRes();
  var rv  = await _run(bp, req, res, "already-parsed");
  check("dispatch: pre-set req.body short-circuits to next() without reparse",
        rv.next === true && rv.req.body && rv.req.body.pre === 1);
}

// ================= multipart — happy paths =================

async function testMultipartDiskFileWrittenAndCleanedUp() {
  var bd   = "diskbd1";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "HELLO")]);
  var bp   = b.middleware.bodyParser({ multipart: { storage: "disk" } });
  var req  = _bodyReq("POST", _mpHeaders(bd, body), body);
  var res  = _bodyRes();
  var rv   = await _run(bp, req, res, "mp-disk");
  check("multipart disk: one file parsed with a tmp path",
        rv.next === true && Array.isArray(rv.req.files) && rv.req.files.length === 1 &&
        typeof rv.req.files[0].path === "string" && rv.req.files[0].buffer === null);
  var f = rv.req.files[0];
  var expectedHash = nodeCrypto.createHash("sha3-512").update(Buffer.from("HELLO")).digest("hex");
  check("multipart disk: tmp file exists with the streamed bytes on disk",
        nodeFs.existsSync(f.path) && nodeFs.readFileSync(f.path, "utf8") === "HELLO");
  check("multipart disk: size + SHA3-512 hash computed during streaming",
        f.size === 5 && f.hash === expectedHash);
  // Cleanup fires on response finish.
  res.emit("finish");
  check("multipart disk: tmp file unlinked when the response finishes",
        nodeFs.existsSync(f.path) === false);
}

async function testMultipartMemoryFileBuffered() {
  var bd   = "membd1";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "MEMDATA")]);
  var rv   = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-memory");
  check("multipart memory: file exposed as a Buffer, no tmp path",
        rv.next === true && rv.req.files.length === 1 &&
        rv.req.files[0].path === null &&
        Buffer.isBuffer(rv.req.files[0].buffer) &&
        rv.req.files[0].buffer.toString() === "MEMDATA");
}

async function testMultipartFieldAndRepeatedField() {
  var bd   = "fldbd1";
  var body = _mpBody(bd, [
    _mpFieldPart(bd, "greeting", "hi there"),
    _mpFieldPart(bd, "tag", "a"),
    _mpFieldPart(bd, "tag", "b"),
  ]);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-fields");
  check("multipart: text field decoded onto req.body",
        rv.next === true && rv.req.body.greeting === "hi there");
  check("multipart: repeated field name collects into an array",
        Array.isArray(rv.req.body.tag) && rv.req.body.tag.length === 2 &&
        rv.req.body.tag[0] === "a" && rv.req.body.tag[1] === "b");
}

async function testMultipartFileWithoutContentTypeDefaultsOctet() {
  var bd   = "octbd1";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.bin", null, "RAW")]);
  var rv   = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-nodefault-ct");
  check("multipart: file part with no Content-Type defaults to application/octet-stream",
        rv.next === true && rv.req.files.length === 1 &&
        rv.req.files[0].mimeType === "application/octet-stream");
}

async function testMultipartBareLineFeedAfterBoundaryTolerated() {
  var bd = "barebd1";
  // First boundary followed by a bare \n (transport-added) before headers;
  // body still terminated by the canonical \r\n--boundary delimiter.
  var body = "--" + bd + "\nContent-Disposition: form-data; name=\"f\"\r\n\r\nval\r\n" + _mpEnd(bd);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-bare-lf");
  check("multipart: bare \\n after a boundary tolerated (transport normalization)",
        rv.next === true && rv.req.body.f === "val");
}

async function testMultipartPreambleDropped() {
  var bd = "prebd1";
  // Deliver a boundary-less 200-byte preamble first, then the real part, so
  // the parser exercises its preamble-trimming path across data events.
  var pre  = "P".repeat(200);
  var rest = "--" + bd + "\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nval\r\n" + _mpEnd(bd);
  var bp   = b.middleware.bodyParser({ multipart: { storage: "memory" } });
  var req  = _streamReq("POST",
    { "content-type": "multipart/form-data; boundary=" + bd, "transfer-encoding": "chunked" },
    [pre, rest]);
  var res  = _bodyRes();
  var rv   = await _run(bp, req, res, "mp-preamble");
  check("multipart: leading preamble bytes dropped, part still parsed",
        rv.next === true && rv.req.body.f === "val");
}

// ================= multipart — rejections + caps =================

async function testMultipartNoBoundaryRejected() {
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    { "content-type": "multipart/form-data", "content-length": "3" },
    "abc", "mp-no-boundary");
  check("multipart: missing boundary parameter -> 400",
        rv.next === false && rv.status === 400);
}

async function testMultipartBadBoundaryRejected() {
  var bd   = "a".repeat(71); // > 70 chars violates RFC 2046 §5.1.1
  var body = _mpBody(bd, [_mpFieldPart(bd, "f", "v")]);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-bad-boundary");
  check("multipart: boundary violating the length/grammar cap -> 400",
        rv.next === false && rv.status === 400);
}

async function testMultipartTruncatedStreamRejected() {
  var bd = "trunc1";
  // No closing boundary — stream ends mid-part.
  var body = "--" + bd + "\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nval";
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-truncated");
  check("multipart: stream ending before the final boundary -> 400",
        rv.next === false && rv.status === 400);
}

async function testMultipartMalformedAfterBoundaryRejected() {
  var bd   = "afterbd1";
  var body = "--" + bd + "XX\r\n";
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-after-bd");
  check("multipart: garbage after a boundary (not --/CRLF/LF) -> 400",
        rv.next === false && rv.status === 400);
}

async function testMultipartBadDispositionRejected() {
  var bd   = "dispbd1";
  var body = "--" + bd + "\r\nContent-Disposition: attachment; name=\"f\"\r\n\r\nv\r\n" + _mpEnd(bd);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-bad-disp");
  check("multipart: part without form-data Content-Disposition -> 400",
        rv.next === false && rv.status === 400);
}

async function testMultipartPoisonedFieldRejected() {
  var bd   = "poisbd1";
  var body = _mpBody(bd, [_mpFieldPart(bd, "__proto__", "x")]);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-poisoned");
  check("multipart: poisoned field name (__proto__) -> 400",
        rv.next === false && rv.status === 400);
}

async function testMultipartTraversalFilenameRejected() {
  var bd   = "travbd1";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "..", "text/plain", "x")]);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-traversal");
  check("multipart: filename that sanitizes to empty/traversal -> 400",
        rv.next === false && rv.status === 400);
}

async function testMultipartObsFoldHeaderRejected() {
  var bd = "foldbd1";
  var body = "--" + bd + "\r\nContent-Disposition: form-data; name=\"f\"\r\n foldline\r\n\r\nx\r\n" + _mpEnd(bd);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-obsfold");
  check("multipart: obsolete header line folding (RFC 9112 §5.2) -> 400",
        rv.next === false && rv.status === 400);
}

async function testMultipartHeaderValueWithNulRejected() {
  var bd = "nulbd1";
  var raw = "--" + bd + "\r\nContent-Disposition: form-data; name=\"f\"\r\nX-Test: a\x00b\r\n\r\nv\r\n" + _mpEnd(bd);
  var body = Buffer.from(raw, "latin1");
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-nul-header");
  check("multipart: NUL in a part header value (RFC 9110 §5.5) -> 400",
        rv.next === false && rv.status === 400);
}

async function testMultipartHeadersTooLargeRejected() {
  var bd = "hdrbd1";
  // 17 KiB of header bytes with no \r\n\r\n terminator trips the 16 KiB cap.
  var body = "--" + bd + "\r\n" + "X".repeat(17 * 1024);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-headers-large");
  check("multipart: part headers exceeding 16 KiB -> 413",
        rv.next === false && rv.status === 413);
}

async function testMultipartGlobalMimeAllowlistRejects() {
  var bd   = "mimebd1";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "hi")]);
  var rv = await _drive({ multipart: { storage: "memory", mimeAllowlist: ["image/png"] } }, "POST",
    _mpHeaders(bd, body), body, "mp-mime-global");
  check("multipart: file MIME off the global allowlist -> 415",
        rv.next === false && rv.status === 415);
}

async function testMultipartPerFieldMimeAllowlistRejects() {
  var bd   = "mimebd2";
  var body = _mpBody(bd, [_mpFilePart(bd, "avatar", "a.txt", "text/plain", "x")]);
  var rv = await _drive({ multipart: { storage: "memory", fields: { avatar: { mimeTypes: ["image/png"] } } } }, "POST",
    _mpHeaders(bd, body), body, "mp-mime-field");
  check("multipart: file MIME off the per-field allowlist -> 415",
        rv.next === false && rv.status === 415);
}

async function testMultipartFileCountCapRejects() {
  var bd   = "fcbd1";
  var body = _mpBody(bd, [
    _mpFilePart(bd, "a", "a.txt", "text/plain", "x"),
    _mpFilePart(bd, "b", "b.txt", "text/plain", "y"),
  ]);
  var rv = await _drive({ multipart: { storage: "memory", fileCount: 1 } }, "POST",
    _mpHeaders(bd, body), body, "mp-filecount");
  check("multipart: files beyond fileCount -> 413",
        rv.next === false && rv.status === 413);
}

async function testMultipartFieldCountCapRejects() {
  var bd   = "fldcbd1";
  var body = _mpBody(bd, [_mpFieldPart(bd, "a", "1"), _mpFieldPart(bd, "b", "2")]);
  var rv = await _drive({ multipart: { storage: "memory", fieldCount: 1 } }, "POST",
    _mpHeaders(bd, body), body, "mp-fieldcount");
  check("multipart: fields beyond fieldCount -> 413",
        rv.next === false && rv.status === 413);
}

async function testMultipartFileSizeCapRejects() {
  var bd   = "fsbd1";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "Z".repeat(50))]);
  var rv = await _drive({ multipart: { storage: "memory", fileSize: BYTES.bytes(10) } }, "POST",
    _mpHeaders(bd, body), body, "mp-filesize");
  check("multipart: file exceeding fileSize -> 413",
        rv.next === false && rv.status === 413);
}

async function testMultipartFieldSizeCapRejects() {
  var bd   = "fldsbd1";
  var body = _mpBody(bd, [_mpFieldPart(bd, "f", "C".repeat(50))]);
  var rv = await _drive({ multipart: { storage: "memory", fieldSize: BYTES.bytes(10) } }, "POST",
    _mpHeaders(bd, body), body, "mp-fieldsize");
  check("multipart: text field exceeding fieldSize -> 413",
        rv.next === false && rv.status === 413);
}

async function testMultipartFileTotalSizeCapRejectsViaBodyPath() {
  var bd   = "totbd1";
  // Header fits under totalSize (90 B); the 200-byte file body pushes the
  // running total over it, exercising the file body-path total-size guard
  // (fileSize is left large so the per-file cap is not what trips).
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "D".repeat(200))]);
  var rv = await _drive(
    { multipart: { storage: "memory", fileSize: BYTES.mib(1), totalSize: BYTES.bytes(90) } }, "POST",
    _mpHeaders(bd, body), body, "mp-total-file");
  check("multipart: file body pushing running total over totalSize -> 413",
        rv.next === false && rv.status === 413);
}

async function testMultipartFileFilterRejectRecorded() {
  var bd   = "ffbd1";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "hi")]);
  var rv = await _drive({ multipart: { storage: "memory", fileFilter: function () { return false; } } }, "POST",
    _mpHeaders(bd, body), body, "mp-filter-reject");
  check("multipart fileFilter=false: part skipped, request still succeeds",
        rv.next === true && rv.req.files.length === 0);
  check("multipart fileFilter=false: rejection recorded in req.filesRejected",
        Array.isArray(rv.req.filesRejected) && rv.req.filesRejected.length === 1 &&
        rv.req.filesRejected[0].field === "f" && rv.req.filesRejected[0].code === "fileFilter");
}

async function testMultipartFileFilterCustomRejectInfo() {
  var bd   = "ffbd2";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "hi")]);
  var rv = await _drive({
    multipart: {
      storage: "memory",
      fileFilter: function () { return { reject: true, code: "policy", message: "denied by policy" }; },
    },
  }, "POST", _mpHeaders(bd, body), body, "mp-filter-custom");
  check("multipart fileFilter object-reject: custom code/message carried into filesRejected",
        rv.next === true && rv.req.files.length === 0 &&
        rv.req.filesRejected.length === 1 &&
        rv.req.filesRejected[0].code === "policy" &&
        rv.req.filesRejected[0].message === "denied by policy");
}

async function testMultipartFileFilterAcceptKeepsFile() {
  var bd   = "ffbd3";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "keep")]);
  var rv = await _drive({ multipart: { storage: "memory", fileFilter: function () { return true; } } }, "POST",
    _mpHeaders(bd, body), body, "mp-filter-accept");
  check("multipart fileFilter=true: file kept in req.files",
        rv.next === true && rv.req.files.length === 1 &&
        rv.req.files[0].buffer.toString() === "keep" &&
        (rv.req.filesRejected || []).length === 0);
}

async function testMultipartFileFilterThrow500() {
  var bd   = "ffbd4";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "hi")]);
  var rv = await _drive({ multipart: { storage: "memory", fileFilter: function () { throw new Error("boom-detail"); } } }, "POST",
    _mpHeaders(bd, body), body, "mp-filter-throw");
  check("multipart fileFilter throw -> 500", rv.next === false && rv.status === 500);
  check("multipart fileFilter throw: internal detail not echoed to client",
        rv.res._captured.indexOf("boom-detail") === -1);
}

async function testMultipartPerFieldMaxBytesFileRejects() {
  var bd   = "pfbd1";
  var body = _mpBody(bd, [_mpFilePart(bd, "doc", "a.txt", "text/plain", "0123456789ABCDEF")]);
  var rv = await _drive({ multipart: { storage: "memory", fields: { doc: { maxBytes: 5 } } } }, "POST",
    _mpHeaders(bd, body), body, "mp-perfield-maxbytes");
  check("multipart: per-field maxBytes overrides fileSize and rejects -> 413",
        rv.next === false && rv.status === 413);
}

// ================= standalone b.parsers.* =================

async function testStandaloneJsonParses() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "9" }, '{"a":123}');
  var v = await b.parsers.json(req, {});
  check("b.parsers.json: standalone parse returns the object",
        v && v.a === 123);
}

async function testStandaloneJsonHonorsOpts() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "9" }, '{"a":123}');
  var v = await b.parsers.json(req, {
    maxBytes: BYTES.mib(1), strict: false, charset: "utf-8",
    parseHook: function (p) { p.b = 1; return p; },
  });
  check("b.parsers.json: maxBytes/strict/charset/parseHook honored",
        v && v.a === 123 && v.b === 1);
}

async function testStandaloneJsonBadMaxBytesThrows() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "2" }, "{}");
  var threw = null;
  try { await b.parsers.json(req, { maxBytes: -5 }); }
  catch (e) { threw = e; }
  check("b.parsers.json: negative maxBytes rejected at the call",
        threw && threw.code === "body-parser/bad-max-bytes");
}

async function testStandaloneMultipartParses() {
  var bd   = "sabd1";
  var body = _mpBody(bd, [_mpFieldPart(bd, "g", "hi"), _mpFilePart(bd, "f", "a.txt", "text/plain", "DATA")]);
  var req  = _bodyReq("POST", _mpHeaders(bd, body), body);
  var v = await b.parsers.multipart(req, { storage: "memory" });
  check("b.parsers.multipart: returns { fields, files, filesRejected }",
        v && v.fields.g === "hi" && Array.isArray(v.files) && v.files.length === 1 &&
        v.files[0].buffer.toString() === "DATA" && Array.isArray(v.filesRejected));
}

async function testStandaloneMultipartMaxBytesAndMaxFiles() {
  var bd   = "sabd2";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "DATA")]);
  var req  = _bodyReq("POST", _mpHeaders(bd, body), body);
  var v = await b.parsers.multipart(req, { storage: "memory", maxBytes: BYTES.mib(1), maxFiles: 5 });
  check("b.parsers.multipart: maxBytes + maxFiles honored on the happy path",
        v && v.files.length === 1);
}

async function testStandaloneMultipartMaxBytesBodyPathRejects() {
  var bd   = "sabd3";
  var body = _mpBody(bd, [_mpFieldPart(bd, "f", "B".repeat(200))]);
  var req  = _bodyReq("POST", _mpHeaders(bd, body), body);
  var threw = null;
  try { await b.parsers.multipart(req, { storage: "memory", maxBytes: BYTES.bytes(80) }); }
  catch (e) { threw = e; }
  check("b.parsers.multipart: maxBytes (=totalSize) enforced on the field body path -> 413",
        threw && threw.statusCode === 413);
}

async function testStandaloneMultipartBadStorageThrows() {
  var bd  = "sabd4";
  var req = _bodyReq("POST", { "content-type": "multipart/form-data; boundary=" + bd, "content-length": "3" }, "abc");
  var threw = null;
  try { await b.parsers.multipart(req, { storage: "nope" }); }
  catch (e) { threw = e; }
  check("b.parsers.multipart: invalid storage enum -> TypeError at the call",
        threw && threw instanceof TypeError);
}

async function testStandaloneMultipartBadMaxFilesThrows() {
  var bd  = "sabd5";
  var req = _bodyReq("POST", { "content-type": "multipart/form-data; boundary=" + bd, "content-length": "3" }, "abc");
  var threw = null;
  try { await b.parsers.multipart(req, { maxFiles: -1 }); }
  catch (e) { threw = e; }
  check("b.parsers.multipart: non-positive maxFiles rejected at the call",
        threw && threw.code === "body-parser/bad-max-files");
}

async function testStandaloneMultipartNonMultipartRejected() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "2" }, "{}");
  var threw = null;
  try { await b.parsers.multipart(req, {}); }
  catch (e) { threw = e; }
  check("b.parsers.multipart: non-multipart Content-Type -> BodyParserError 400",
        threw && threw.code === "body-parser/standalone-not-multipart" && threw.statusCode === 400);
}

async function testStandaloneMultipartPassesThroughKnob() {
  // fileSize is a DEFAULTS.multipart knob passed straight through — a 50-byte
  // file with fileSize 10 must reject, proving the passthrough is live.
  var bd   = "sabd6";
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "Z".repeat(50))]);
  var req  = _bodyReq("POST", _mpHeaders(bd, body), body);
  var threw = null;
  try { await b.parsers.multipart(req, { storage: "memory", fileSize: BYTES.bytes(10) }); }
  catch (e) { threw = e; }
  check("b.parsers.multipart: DEFAULTS.multipart knobs (fileSize) pass through",
        threw && threw.statusCode === 413);
}

// ================= dispatch edge branches =================

async function testZeroContentLengthSkipsParsing() {
  var rv = await _drive({ json: {} }, "POST",
    { "content-type": "application/json", "content-length": "0" },
    "", "cl-zero");
  check("dispatch: Content-Length 0 -> no body, next() without parsing",
        rv.next === true && rv.req.body === undefined);
}

async function testPostWithoutBodyHeadersSkipsParsing() {
  var rv = await _drive({ json: {} }, "POST",
    { "content-type": "application/json" },
    "ignored", "no-cl-no-te");
  check("dispatch: POST with neither Content-Length nor Transfer-Encoding -> next()",
        rv.next === true && rv.req.body === undefined);
}

async function testMissingContentTypeWithBodyIs415() {
  var rv = await _drive({ json: {} }, "POST",
    { "transfer-encoding": "chunked" },
    "{}", "no-ct");
  check("dispatch: body with no Content-Type header -> 415",
        rv.next === false && rv.status === 415);
}

async function testChunkedBodyOverLimitIs413() {
  // No Content-Length (chunked), so the size cap is enforced by the
  // stream-drain overflow guard rather than the preflight check.
  var rv = await _drive({ json: { limit: BYTES.bytes(5) } }, "POST",
    { "content-type": "application/json", "transfer-encoding": "chunked" },
    '{"aaaaaaaaaaaa":1}', "chunked-over-limit");
  check("limit: chunked body over limit rejected 413 by the drain guard",
        rv.next === false && rv.status === 413);
}

async function testContentTypePoisonedParamDropped() {
  var rv = await _drive({ json: {} }, "POST",
    { "content-type": "application/json; __proto__=x", "content-length": "7" },
    '{"a":1}', "ct-poisoned-param");
  check("dispatch: poisoned Content-Type parameter name dropped, body parses",
        rv.next === true && rv.req.body && rv.req.body.a === 1);
}

async function testMultipartPoisonedPartHeaderDropped() {
  var bd = "phbd1";
  var body = "--" + bd + "\r\nContent-Disposition: form-data; name=\"f\"\r\n__proto__: evil\r\n\r\nval\r\n" + _mpEnd(bd);
  var rv = await _drive({ multipart: { storage: "memory" } }, "POST",
    _mpHeaders(bd, body), body, "mp-poisoned-header");
  check("multipart: poisoned part-header name dropped, part still parses cleanly",
        rv.next === true && rv.req.body.f === "val");
}

async function testMultipartDiskMultiFileCleanupOnError() {
  var bd = "dmbd1";
  // First file writes to a tmp file; the second exceeds fileSize and rejects,
  // driving the multi-file cleanup path that unlinks the already-written file.
  var body = _mpBody(bd, [
    _mpFilePart(bd, "a", "a.txt", "text/plain", "OK"),
    _mpFilePart(bd, "b", "b.txt", "text/plain", "Z".repeat(50)),
  ]);
  var rv = await _drive({ multipart: { storage: "disk", fileSize: BYTES.bytes(10) } }, "POST",
    _mpHeaders(bd, body), body, "mp-disk-multi");
  check("multipart disk: a later part exceeding a cap rejects 413 (earlier tmp files cleaned up)",
        rv.next === false && rv.status === 413);
}

async function testKeepRawBodyMalformedJson() {
  var body = "{bad json";
  var rv = await _drive({ keepRawBody: true, json: {} }, "POST",
    { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) },
    body, "keepraw-malformed");
  check("keepRawBody: malformed JSON still rejected 400 through the buffered path",
        rv.next === false && rv.status === 400);
}

async function testKeepRawBodyParseHookSuccess() {
  var rv = await _drive({ keepRawBody: true, json: { parseHook: function (p) { return { w: p }; } } }, "POST",
    { "content-type": "application/json", "content-length": "7" },
    '{"a":1}', "keepraw-hook");
  check("keepRawBody: parseHook transforms the buffered-path parse result",
        rv.next === true && rv.req.body && rv.req.body.w && rv.req.body.w.a === 1);
}

async function testStandaloneMultipartHeaderPathTotalRejects() {
  var bd   = "sahbd1";
  var body = _mpBody(bd, [_mpFieldPart(bd, "f", "v")]);
  var req  = _bodyReq("POST", _mpHeaders(bd, body), body);
  var threw = null;
  try { await b.parsers.multipart(req, { storage: "memory", maxBytes: BYTES.bytes(5) }); }
  catch (e) { threw = e; }
  check("b.parsers.multipart: part-header bytes alone exceeding total -> 413",
        threw && threw.statusCode === 413);
}

async function testMiddlewareBadStorageThrowsAtConstruction() {
  var threw = null;
  try { b.middleware.bodyParser({ multipart: { storage: "bad" } }); }
  catch (e) { threw = e; }
  check("create: invalid multipart.storage enum rejected with TypeError at construction",
        threw && threw instanceof TypeError);
}

async function testStandaloneJsonWithoutOpts() {
  var req = _bodyReq("POST", { "content-type": "application/json", "content-length": "7" }, '{"a":1}');
  var v = await b.parsers.json(req);
  check("b.parsers.json: callable with no opts (defaults applied)",
        v && v.a === 1);
}

async function testMultipartAuditWiredRejectionEmits() {
  var bd     = "audbd1";
  var events = [];
  var fakeAudit = { safeEmit: function (ev) { events.push(ev.action); } };
  var body = _mpBody(bd, [_mpFilePart(bd, "f", "a.txt", "text/plain", "hi")]);
  var req  = _bodyReq("POST", _mpHeaders(bd, body), body);
  var v = await b.parsers.multipart(req, {
    storage: "memory", audit: fakeAudit, fileFilter: function () { return false; },
  });
  check("multipart: wired audit emits file_rejected on a fileFilter rejection",
        v.filesRejected.length === 1 &&
        events.indexOf("body-parser.multipart.file_rejected") !== -1);
}

async function run() {
  // JSON
  await testJsonHappyPath();
  await testJsonStrictRejectsBareString();
  await testJsonStrictAcceptsArrayWithLeadingWhitespace();
  await testJsonNonStrictAcceptsBareValue();
  await testJsonEmptyBodyIsUndefined();
  await testJsonMalformedRejected();
  await testJsonParseHookSuccess();
  await testJsonParseHookThrowRedacted();
  await testKeepRawBodyExposesBytesAndParses();
  await testKeepRawBodyEmptyBodyUndefined();
  await testKeepRawBodyStrictReject();
  // urlencoded
  await testUrlencodedHappyPath();
  await testUrlencodedRepeatedKeyBecomesArray();
  await testUrlencodedEmptyBodyIsEmptyObject();
  await testUrlencodedPoisonedKeyRejected();
  await testUrlencodedArrayTooLargeRejected();
  await testUrlencodedTooManyFieldsRejected();
  // text / raw
  await testTextPlainParsed();
  await testRawOctetStreamBuffer();
  await testRawFactoryCapturesAnyType();
  await testRawFactoryHonorsLimit();
  // dispatch / limits / methods
  await testUnsupportedContentTypeIs415();
  await testContentLengthOverLimitIs413();
  await testMalformedContentLengthIs400();
  await testGetWithBodyHeadersSkipsParsing();
  await testDeleteWithBodyIsParsed();
  await testAlreadyParsedBodyIsLeftAlone();
  // multipart happy
  await testMultipartDiskFileWrittenAndCleanedUp();
  await testMultipartMemoryFileBuffered();
  await testMultipartFieldAndRepeatedField();
  await testMultipartFileWithoutContentTypeDefaultsOctet();
  await testMultipartBareLineFeedAfterBoundaryTolerated();
  await testMultipartPreambleDropped();
  // multipart rejections + caps
  await testMultipartNoBoundaryRejected();
  await testMultipartBadBoundaryRejected();
  await testMultipartTruncatedStreamRejected();
  await testMultipartMalformedAfterBoundaryRejected();
  await testMultipartBadDispositionRejected();
  await testMultipartPoisonedFieldRejected();
  await testMultipartTraversalFilenameRejected();
  await testMultipartObsFoldHeaderRejected();
  await testMultipartHeaderValueWithNulRejected();
  await testMultipartHeadersTooLargeRejected();
  await testMultipartGlobalMimeAllowlistRejects();
  await testMultipartPerFieldMimeAllowlistRejects();
  await testMultipartFileCountCapRejects();
  await testMultipartFieldCountCapRejects();
  await testMultipartFileSizeCapRejects();
  await testMultipartFieldSizeCapRejects();
  await testMultipartFileTotalSizeCapRejectsViaBodyPath();
  await testMultipartFileFilterRejectRecorded();
  await testMultipartFileFilterCustomRejectInfo();
  await testMultipartFileFilterAcceptKeepsFile();
  await testMultipartFileFilterThrow500();
  await testMultipartPerFieldMaxBytesFileRejects();
  // standalone parsers
  await testStandaloneJsonParses();
  await testStandaloneJsonHonorsOpts();
  await testStandaloneJsonBadMaxBytesThrows();
  await testStandaloneMultipartParses();
  await testStandaloneMultipartMaxBytesAndMaxFiles();
  await testStandaloneMultipartMaxBytesBodyPathRejects();
  await testStandaloneMultipartBadStorageThrows();
  await testStandaloneMultipartBadMaxFilesThrows();
  await testStandaloneMultipartNonMultipartRejected();
  await testStandaloneMultipartPassesThroughKnob();
  await testStandaloneMultipartHeaderPathTotalRejects();
  // dispatch edge branches
  await testZeroContentLengthSkipsParsing();
  await testPostWithoutBodyHeadersSkipsParsing();
  await testMissingContentTypeWithBodyIs415();
  await testChunkedBodyOverLimitIs413();
  await testContentTypePoisonedParamDropped();
  await testMultipartPoisonedPartHeaderDropped();
  await testMultipartDiskMultiFileCleanupOnError();
  await testKeepRawBodyMalformedJson();
  await testKeepRawBodyParseHookSuccess();
  await testMiddlewareBadStorageThrowsAtConstruction();
  await testStandaloneJsonWithoutOpts();
  await testMultipartAuditWiredRejectionEmits();
  // The 4xx/5xx rejects emit body-parser audit events, which schedule the
  // audit handler's age-flush timer. Drain it so no timer lingers past run().
  await b.audit.flush();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

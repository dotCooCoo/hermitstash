"use strict";
/**
 * b.parsers.json(req, opts) / b.parsers.multipart(req, opts) — standalone
 * async wrappers around the body-parser pipeline. Handlers that lazy-parse
 * (route-shape dispatch, streaming endpoints that bypass the middleware)
 * call these inline; the middleware composes the same parsing path.
 *
 * Run standalone: `node test/layer-0-primitives/parsers-standalone.test.js`
 */

var EventEmitter = require("events");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
// _contentType is the internal Content-Type parameter parser the
// middleware + standalone helpers share; exposed for tests.
var _contentType = require("../../lib/middleware/body-parser")._contentType;

function _streamReq(opts) {
  opts = opts || {};
  var req = new EventEmitter();
  req.method  = opts.method || "POST";
  req.url     = opts.url || "/";
  req.headers = Object.assign({}, opts.headers || {});
  req.socket  = { remoteAddress: "127.0.0.1" };
  req.destroy = function () { /* mock — no-op */ };
  setImmediate(function () {
    var body = opts.body;
    if (Buffer.isBuffer(body))      req.emit("data", body);
    else if (typeof body === "string") req.emit("data", Buffer.from(body));
    else if (Array.isArray(body))      body.forEach(function (chunk) { req.emit("data", Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)); });
    req.emit("end");
  });
  return req;
}

// ---- parsers.json ----

async function testJsonParsesValidObject() {
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": "13" },
    body: '{"hello":1}',
  });
  var parsed = await b.parsers.json(req, { maxBytes: b.constants.BYTES.kib(1) });
  check("parsers.json parses valid JSON", parsed && parsed.hello === 1);
}

async function testJsonRefusesOverMaxBytes() {
  var big = '{"x":"' + "a".repeat(2000) + '"}';
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": String(big.length) },
    body: big,
  });
  var threw = false;
  try { await b.parsers.json(req, { maxBytes: 100 }); }
  catch (e) { threw = e.code === "body-parser/too-large"; }
  check("parsers.json refuses over maxBytes", threw);
}

async function testJsonRefusesPrototypePollution() {
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": "32" },
    body: '{"__proto__":{"polluted":true}}',
  });
  var parsed = await b.parsers.json(req, { maxBytes: b.constants.BYTES.kib(1) });
  // safeJson strips __proto__ — parsed object has no polluted attr.
  check("parsers.json strips __proto__", !({}).polluted);
  check("parsers.json returns sanitized object", parsed && Object.keys(parsed).length === 0);
}

async function testJsonStrictRefusesNonObjectStart() {
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": "5" },
    body: '"hi"',
  });
  var threw = false;
  try { await b.parsers.json(req, { maxBytes: b.constants.BYTES.kib(1), strict: true }); }
  catch (e) { threw = e.code === "body-parser/json-strict"; }
  check("parsers.json strict refuses non-object/array head", threw);
}

async function testJsonRefusesBadOpts() {
  var threw1 = false;
  try { await b.parsers.json(_streamReq(), { maxBytes: 0 }); }
  catch (e) { threw1 = e.code === "body-parser/bad-max-bytes"; }
  check("parsers.json throws on maxBytes=0", threw1);
  var threw2 = false;
  try { await b.parsers.json(_streamReq(), { maxBytes: Infinity }); }
  catch (e) { threw2 = e.code === "body-parser/bad-max-bytes"; }
  check("parsers.json throws on non-finite maxBytes", threw2);
}

// ---- parsers.multipart ----

function _multipartBody(boundary, parts) {
  var chunks = [];
  parts.forEach(function (p) {
    chunks.push("--" + boundary + "\r\n");
    var headers = 'Content-Disposition: form-data; name="' + p.name + '"';
    if (p.filename) headers += '; filename="' + p.filename + '"';
    chunks.push(headers + "\r\n");
    if (p.contentType) chunks.push("Content-Type: " + p.contentType + "\r\n");
    chunks.push("\r\n");
    chunks.push(p.value);
    chunks.push("\r\n");
  });
  chunks.push("--" + boundary + "--\r\n");
  return chunks.join("");
}

async function testMultipartParsesFieldsAndFiles() {
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [
    { name: "title",  value: "hello world" },
    { name: "upload", filename: "data.txt", contentType: "text/plain", value: "file-bytes-here" },
  ]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var result = await b.parsers.multipart(req, {
    maxBytes: b.constants.BYTES.mib(1),
    maxFiles: 5,
  });
  check("parsers.multipart returns fields", result.fields && result.fields.title === "hello world");
  check("parsers.multipart returns files",  Array.isArray(result.files) && result.files.length === 1);
  check("parsers.multipart file metadata",  result.files[0].filename === "data.txt" && result.files[0].size === 15);
  check("parsers.multipart hash present",   typeof result.files[0].hash === "string" && result.files[0].hash.length > 0);
  // Cleanup tmp file (handler-owned).
  try { require("fs").unlinkSync(result.files[0].path); } catch (_e) { /* tmp file already removed */ }
}

async function testMultipartRefusesNonMultipartType() {
  var req = _streamReq({
    headers: { "content-type": "application/json", "content-length": "2" },
    body: "{}",
  });
  var threw = false;
  try { await b.parsers.multipart(req, { maxBytes: 1024, maxFiles: 1 }); }
  catch (e) { threw = e.code === "body-parser/standalone-not-multipart"; }
  check("parsers.multipart refuses non-multipart Content-Type", threw);
}

async function testMultipartEnforcesMaxFiles() {
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [
    { name: "f1", filename: "a.txt", contentType: "text/plain", value: "x" },
    { name: "f2", filename: "b.txt", contentType: "text/plain", value: "y" },
  ]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var threw = false;
  try { await b.parsers.multipart(req, { maxBytes: b.constants.BYTES.mib(1), maxFiles: 1 }); }
  catch (e) { threw = e.code === "body-parser/multipart-too-many-files"; }
  check("parsers.multipart enforces maxFiles", threw);
}

async function testMultipartRefusesBadOpts() {
  var threw1 = false;
  try { await b.parsers.multipart(_streamReq({ headers: { "content-type": "multipart/form-data; boundary=x" } }), { maxBytes: 0, maxFiles: 1 }); }
  catch (e) { threw1 = e.code === "body-parser/bad-max-bytes"; }
  check("parsers.multipart throws on maxBytes=0", threw1);
  var threw2 = false;
  try { await b.parsers.multipart(_streamReq({ headers: { "content-type": "multipart/form-data; boundary=x" } }), { maxBytes: 1024, maxFiles: 0 }); }
  catch (e) { threw2 = e.code === "body-parser/bad-max-files"; }
  check("parsers.multipart throws on maxFiles=0", threw2);
  var threw3 = false;
  try { await b.parsers.multipart(_streamReq({ headers: { "content-type": "multipart/form-data; boundary=x" } }), { maxBytes: 1024, maxFiles: 2.5 }); }
  catch (e) { threw3 = e.code === "body-parser/bad-max-files"; }
  check("parsers.multipart throws on non-integer maxFiles", threw3);
}

// ---- Composition seam — middleware uses the same internals ----

async function testMiddlewareAndStandaloneShareImpl() {
  // The middleware's req.body for a JSON route must equal the standalone
  // result for the same input — verifies they share one parsing pipeline.
  var bodyText = '{"a":1,"b":[1,2,3]}';

  var req1 = _streamReq({
    headers: { "content-type": "application/json", "content-length": String(bodyText.length) },
    body: bodyText,
  });
  var standalone = await b.parsers.json(req1, { maxBytes: b.constants.BYTES.kib(1) });

  var req2 = _streamReq({
    headers: { "content-type": "application/json", "content-length": String(bodyText.length) },
    body: bodyText,
  });
  var res2 = b.testing.bodyRes();
  var mw = b.middleware.bodyParser({ json: { limit: b.constants.BYTES.kib(1) } });
  await new Promise(function (resolve) { mw(req2, res2, resolve); });
  var middlewareParsed = req2.body;

  check("standalone + middleware return identical shape",
        JSON.stringify(standalone) === JSON.stringify(middlewareParsed));
}

// ---- Prototype-pollution defense (CWE-915 / CWE-1321) ----
//
// Header/parameter/field names are request-controlled. The parsers build
// their maps from [key, value] pairs through Object.fromEntries instead
// of a computed-write (`target[key] = value`) sink, dropping the
// __proto__ / constructor / prototype names so a hostile name can never
// reach Object.prototype.

function testContentTypeIgnoresPoisonedParam() {
  // A Content-Type parameter literally named `__proto__` must not pollute
  // the prototype chain, and the legitimate boundary/charset must still
  // parse to the same shape.
  var ct = _contentType({
    headers: {
      "content-type":
        'multipart/form-data; boundary=----abc; __proto__=evil; charset=utf-8',
    },
  });
  check("content-type: type parsed", ct.type === "multipart/form-data");
  check("content-type: boundary parsed", ct.params.boundary === "----abc");
  check("content-type: charset parsed", ct.params.charset === "utf-8");
  check("content-type: __proto__ param dropped (no own prop)",
        !Object.prototype.hasOwnProperty.call(ct.params, "__proto__"));
  check("content-type: Object.prototype not polluted",
        ({}).evil === undefined && Object.prototype.evil === undefined);
}

async function testMultipartRefusesPoisonedFieldName() {
  // A multipart field whose Content-Disposition name is `__proto__` is
  // refused at the parse boundary (400) and never reaches the field map.
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [
    { name: "__proto__", value: '{"polluted":true}' },
  ]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var threw = false;
  try { await b.parsers.multipart(req, { maxBytes: b.constants.BYTES.mib(1), maxFiles: 5 }); }
  catch (e) { threw = e.code === "body-parser/multipart-poisoned-field"; }
  check("multipart: __proto__ field name refused with 400", threw);
  check("multipart: Object.prototype not polluted by field name",
        ({}).polluted === undefined && Object.prototype.polluted === undefined);
}

async function testMultipartRepeatedFieldShapeUnchanged() {
  // Success path: repeated field name → array; single → scalar. The
  // entries-merge accumulation must produce the same shape the prior
  // computed-write accumulation did.
  var boundary = "----blamejstest" + Date.now();
  var body = _multipartBody(boundary, [
    { name: "tag", value: "a" },
    { name: "tag", value: "b" },
    { name: "tag", value: "c" },
    { name: "title", value: "solo" },
  ]);
  var req = _streamReq({
    headers: {
      "content-type":   "multipart/form-data; boundary=" + boundary,
      "content-length": String(Buffer.byteLength(body)),
    },
    body: body,
  });
  var result = await b.parsers.multipart(req, { maxBytes: b.constants.BYTES.mib(1), maxFiles: 5 });
  check("multipart: repeated field collapses to array in order",
        Array.isArray(result.fields.tag) &&
        result.fields.tag.length === 3 &&
        result.fields.tag[0] === "a" &&
        result.fields.tag[1] === "b" &&
        result.fields.tag[2] === "c");
  check("multipart: single field stays scalar", result.fields.title === "solo");
}

async function run() {
  await testJsonParsesValidObject();
  await testJsonRefusesOverMaxBytes();
  await testJsonRefusesPrototypePollution();
  await testJsonStrictRefusesNonObjectStart();
  await testJsonRefusesBadOpts();
  await testMultipartParsesFieldsAndFiles();
  await testMultipartRefusesNonMultipartType();
  await testMultipartEnforcesMaxFiles();
  await testMultipartRefusesBadOpts();
  await testMiddlewareAndStandaloneShareImpl();
  testContentTypeIgnoresPoisonedParam();
  await testMultipartRefusesPoisonedFieldName();
  await testMultipartRepeatedFieldShapeUnchanged();
  console.log("OK — parsers-standalone tests");
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });

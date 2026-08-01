// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.cloudEvents (CloudEvents 1.0.2).
 * Covers the existing wrap / parse envelope helpers plus the JSON event
 * format (toJSON / fromJSON + batch), the non-throwing validate / isValid
 * check, and the HTTP protocol binding (binary + structured + batch +
 * auto-detect decode). Oracle: the normative example events from the
 * CloudEvents JSON Event Format 1.0.2 spec and the HTTP binding's
 * binary-mode example request.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

// Spec JSON-format example events (json-format.md), with data_base64
// replaced by real canonical base64 for byte-exact round-trips.
var EX_JSON_OBJECT = {
  specversion: "1.0", type: "com.example.someevent", source: "/mycontext",
  id: "C234-1234-1234", time: "2018-04-05T17:31:00Z",
  comexampleextension1: "value", comexampleothervalue: 5,
  datacontenttype: "application/json",
  data: { appinfoA: "abc", appinfoB: 123, appinfoC: true },
};
var EX_XML_STRING = {
  specversion: "1.0", type: "com.example.someevent", source: "/mycontext",
  id: "B234-1234-1234", time: "2018-04-05T17:31:00Z",
  comexampleextension1: "value", unsetextension: null,
  datacontenttype: "application/xml", data: "<much wow=\"xml\"/>",
};

function testWrapParse() {
  var ce = b.cloudEvents.wrap({ source: "/services/orders", type: "com.example.order.created", subject: "order/o-1234", data: { id: "o-1234" } });
  check("wrap sets specversion 1.0", ce.specversion === "1.0");
  check("wrap auto-fills UUID id", /^[0-9a-f-]{36}$/.test(ce.id));
  check("wrap sets application/json for object data", ce.datacontenttype === "application/json");
  var bin = b.cloudEvents.wrap({ source: "/x", type: "t", data: Buffer.from([1, 2, 3]) });
  check("wrap routes Buffer to data_base64", bin.data_base64 === Buffer.from([1, 2, 3]).toString("base64"));
  var rec = b.cloudEvents.parse(EX_JSON_OBJECT);
  check("parse surfaces extensions separately", rec.extensions.comexampleothervalue === 5 && rec.data.appinfoA === "abc");
  check("parse rejects missing required", code(function () { b.cloudEvents.parse({ specversion: "1.0", id: "1", source: "/x" }); }) === "cloud-events/missing-required");
}

function testValidate() {
  check("isValid true for conformant", b.cloudEvents.isValid(EX_JSON_OBJECT));
  check("validate flags bad specversion", b.cloudEvents.validate({ specversion: "0.3", id: "1", source: "/x", type: "t" }).some(function (i) { return i.attribute === "specversion"; }));
  check("validate flags bad time", b.cloudEvents.validate({ specversion: "1.0", id: "1", source: "/x", type: "t", time: "not-a-time" }).some(function (i) { return i.attribute === "time"; }));
  check("validate flags float extension", b.cloudEvents.validate({ specversion: "1.0", id: "1", source: "/x", type: "t", frac: 1.5 }).some(function (i) { return i.attribute === "frac"; }));
  check("validate flags uppercase ext name", b.cloudEvents.validate({ specversion: "1.0", id: "1", source: "/x", type: "t", Foo: "v" }).some(function (i) { return i.attribute === "Foo"; }));
  check("validate flags data + data_base64", b.cloudEvents.validate({ specversion: "1.0", id: "1", source: "/x", type: "t", data: 1, data_base64: "AA==" }).some(function (i) { return i.attribute === "data"; }));
}

function testJsonFormat() {
  var rt = b.cloudEvents.fromJSON(b.cloudEvents.toJSON(EX_JSON_OBJECT));
  check("toJSON/fromJSON round-trip JSON data", JSON.stringify(rt.data) === JSON.stringify(EX_JSON_OBJECT.data));
  var rtx = b.cloudEvents.fromJSON(b.cloudEvents.toJSON(EX_XML_STRING));
  check("xml-string data round-trips", rtx.data === "<much wow=\"xml\"/>" && rtx.unsetextension === null);
  var binEvt = b.cloudEvents.wrap({ source: "/x", type: "t", data: Buffer.from([0, 1, 254, 255]) });
  var binRt = b.cloudEvents.fromJSON(b.cloudEvents.toJSON(binEvt));
  check("binary data_base64 round-trips", binRt.data_base64 === Buffer.from([0, 1, 254, 255]).toString("base64"));
  check("fromJSON rejects non-canonical base64", code(function () { b.cloudEvents.fromJSON(JSON.stringify({ specversion: "1.0", id: "1", source: "/x", type: "t", data_base64: "!!!!" })); }) === "cloud-events/invalid");
  check("fromJSON rejects malformed JSON", code(function () { b.cloudEvents.fromJSON("{nope"); }) === "cloud-events/bad-json");
}

function testBatch() {
  var body = b.cloudEvents.toJSONBatch([EX_JSON_OBJECT, EX_XML_STRING]);
  check("batch serializes a JSON array", Array.isArray(JSON.parse(body)) && JSON.parse(body).length === 2);
  var evts = b.cloudEvents.fromJSONBatch(body);
  check("batch round-trips two events", evts.length === 2 && evts[0].id === "C234-1234-1234");
  check("empty batch valid both ways", b.cloudEvents.fromJSONBatch("[]").length === 0 && b.cloudEvents.toJSONBatch([]) === "[]");
  check("non-array batch refused", code(function () { b.cloudEvents.fromJSONBatch("{}"); }) === "cloud-events/invalid");
}

function testHttpBinary() {
  var enc = b.cloudEvents.http.encodeBinary(EX_JSON_OBJECT);
  check("binary maps id to ce-id", enc.headers["ce-id"] === "C234-1234-1234");
  check("binary maps specversion to ce-specversion", enc.headers["ce-specversion"] === "1.0");
  check("binary does NOT prefix datacontenttype", enc.headers["content-type"] === "application/json" && enc.headers["ce-datacontenttype"] === undefined);
  check("binary maps extension int to ce header string", enc.headers["ce-comexampleothervalue"] === "5");
  check("binary body is JSON data", JSON.parse(enc.body).appinfoA === "abc");
  // Spec HTTP binding binary-mode example request.
  var dec = b.cloudEvents.http.decodeBinary({
    "ce-specversion": "1.0", "ce-type": "com.example.someevent",
    "ce-time": "2018-04-05T03:56:24Z", "ce-id": "1234-1234-1234",
    "ce-source": "/mycontext/subcontext", "Content-Type": "application/json; charset=utf-8",
  }, "{\"hello\":\"world\"}");
  check("binary decode reads ce-id + body", dec.id === "1234-1234-1234" && dec.data.hello === "world");
  check("binary decode maps Content-Type to datacontenttype", dec.datacontenttype === "application/json; charset=utf-8");
  // Percent-encoding round-trip (space / quote / non-ASCII).
  var pe = b.cloudEvents.http.encodeBinary(b.cloudEvents.wrap({ source: "/x", type: "t", subject: "a b\"cé" }));
  check("header percent-encodes space/quote/unicode", /%20/.test(pe.headers["ce-subject"]) && /%22/.test(pe.headers["ce-subject"]) && /%C3%A9/.test(pe.headers["ce-subject"]));
  check("percent-decode round-trips", b.cloudEvents.http.decodeBinary(pe.headers, "").subject === "a b\"cé");
  // JSON-media string payloads must be JSON-encoded in the body so they
  // re-parse — a bare string under application/json (or absent, which
  // defaults to JSON) round-trips through binary mode.
  var strEvt = b.cloudEvents.wrap({ source: "/x", type: "t", datacontenttype: "application/json", data: "hello" });
  var strEnc = b.cloudEvents.http.encodeBinary(strEvt);
  check("json string payload is JSON-encoded in body", strEnc.body === "\"hello\"");
  check("json string payload round-trips through binary", b.cloudEvents.http.decodeBinary(strEnc.headers, strEnc.body).data === "hello");
  // Opaque binary body becomes data_base64.
  var ob = b.cloudEvents.http.decodeBinary({ "ce-specversion": "1.0", "ce-id": "1", "ce-source": "/x", "ce-type": "t", "content-type": "application/octet-stream" }, Buffer.from([9, 8, 7]));
  check("opaque body decodes to data_base64", ob.data_base64 === Buffer.from([9, 8, 7]).toString("base64"));
}

function testHttpStructuredAndDetect() {
  var s = b.cloudEvents.http.encodeStructured(EX_JSON_OBJECT);
  check("structured uses cloudevents+json", /^application\/cloudevents\+json/.test(s.headers["content-type"]));
  check("auto-detect decodes structured", b.cloudEvents.http.decode(s.headers, s.body).id === "C234-1234-1234");
  var bn = b.cloudEvents.http.encodeBinary(EX_JSON_OBJECT);
  check("auto-detect decodes binary", !Array.isArray(b.cloudEvents.http.decode(bn.headers, bn.body)) && b.cloudEvents.http.decode(bn.headers, bn.body).id === "C234-1234-1234");
  var ba = b.cloudEvents.http.encodeBatch([EX_JSON_OBJECT, EX_XML_STRING]);
  check("batch uses cloudevents-batch+json", /^application\/cloudevents-batch\+json/.test(ba.headers["content-type"]));
  check("auto-detect decodes batch to array", Array.isArray(b.cloudEvents.http.decode(ba.headers, ba.body)) && b.cloudEvents.http.decode(ba.headers, ba.body).length === 2);
}

function testWrapBranches() {
  // extensions: null is accepted as a no-op.
  var e0 = b.cloudEvents.wrap({ source: "/x", type: "t", extensions: null });
  check("wrap accepts extensions:null", e0.specversion === "1.0" && e0.traceid === undefined);
  // Valid extensions are copied verbatim onto the envelope.
  var e1 = b.cloudEvents.wrap({ source: "/x", type: "t", extensions: { traceid: "abc", seq: 7 } });
  check("wrap copies valid extensions onto envelope", e1.traceid === "abc" && e1.seq === 7);
  check("wrap rejects non-conforming extension name",
        code(function () { b.cloudEvents.wrap({ source: "/x", type: "t", extensions: { "Bad-Name": 1 } }); }) === "cloud-events/bad-extension-name");
  check("wrap rejects extension colliding with a spec attribute",
        code(function () { b.cloudEvents.wrap({ source: "/x", type: "t", extensions: { id: "nope" } }); }) === "cloud-events/extension-conflicts-with-spec");
  var e2 = b.cloudEvents.wrap({ source: "/x", type: "t", dataschema: "https://schema/x" });
  check("wrap sets dataschema attribute", e2.dataschema === "https://schema/x");
  // Buffer data WITH an explicit datacontenttype (left arm of the || default).
  var e3 = b.cloudEvents.wrap({ source: "/x", type: "t", data: Buffer.from("pdf"), datacontenttype: "application/pdf" });
  check("wrap Buffer honors explicit datacontenttype", e3.datacontenttype === "application/pdf" && typeof e3.data_base64 === "string");
  // Object data WITH an explicit datacontenttype.
  var e4 = b.cloudEvents.wrap({ source: "/x", type: "t", data: { a: 1 }, datacontenttype: "application/vnd.acme+json" });
  check("wrap object honors explicit datacontenttype", e4.datacontenttype === "application/vnd.acme+json");
  // datacontenttype supplied without any data.
  var e5 = b.cloudEvents.wrap({ source: "/x", type: "t", datacontenttype: "text/plain" });
  check("wrap sets datacontenttype without data", e5.datacontenttype === "text/plain" && e5.data === undefined);
}

function testParseBranches() {
  check("parse rejects null envelope", code(function () { b.cloudEvents.parse(null); }) === "cloud-events/bad-envelope");
  check("parse rejects array envelope", code(function () { b.cloudEvents.parse([]); }) === "cloud-events/bad-envelope");
  check("parse rejects string envelope", code(function () { b.cloudEvents.parse("nope"); }) === "cloud-events/bad-envelope");
  check("parse rejects unsupported specversion",
        code(function () { b.cloudEvents.parse({ specversion: "0.3", id: "1", source: "/x", type: "t" }); }) === "cloud-events/unsupported-specversion");
  check("parse rejects data + data_base64 conflict",
        code(function () { b.cloudEvents.parse({ specversion: "1.0", id: "1", source: "/x", type: "t", data: {}, data_base64: "AA==" }); }) === "cloud-events/data-conflict");
  check("parse rejects non-string data_base64",
        code(function () { b.cloudEvents.parse({ specversion: "1.0", id: "1", source: "/x", type: "t", data_base64: 123 }); }) === "cloud-events/bad-data-base64");
  var decoded = b.cloudEvents.parse({ specversion: "1.0", id: "1", source: "/x", type: "t", data_base64: Buffer.from("hi").toString("base64") });
  check("parse decodes data_base64 to a Buffer", Buffer.isBuffer(decoded.data) && decoded.data.toString() === "hi");
  var minimal = b.cloudEvents.parse({ specversion: "1.0", id: "1", source: "/x", type: "t" });
  check("parse defaults absent optionals to null",
        minimal.time === null && minimal.subject === null && minimal.datacontenttype === null && minimal.dataschema === null);
}

function testValidateBranches() {
  check("validate: non-object event flagged",
        b.cloudEvents.validate(null).some(function (i) { return i.message === "event must be an object"; }));
  var missing = b.cloudEvents.validate({ specversion: "1.0" });
  check("validate: missing id/source/type flagged",
        missing.some(function (i) { return i.attribute === "id"; }) &&
        missing.some(function (i) { return i.attribute === "source"; }) &&
        missing.some(function (i) { return i.attribute === "type"; }));
  var v = { specversion: "1.0", id: "1", source: "/x", type: "t" };
  check("validate: non-string datacontenttype flagged",
        b.cloudEvents.validate(Object.assign({}, v, { datacontenttype: 123 })).some(function (i) { return i.attribute === "datacontenttype"; }));
  check("validate: non-string dataschema flagged",
        b.cloudEvents.validate(Object.assign({}, v, { dataschema: 123 })).some(function (i) { return i.attribute === "dataschema"; }));
  check("validate: non-string subject flagged",
        b.cloudEvents.validate(Object.assign({}, v, { subject: 123 })).some(function (i) { return i.attribute === "subject"; }));
  check("validate: extension integer out of 32-bit range flagged",
        b.cloudEvents.validate(Object.assign({}, v, { big: 4294967296 })).some(function (i) { return i.attribute === "big"; }));
  check("validate: extension of object type flagged",
        b.cloudEvents.validate(Object.assign({}, v, { obj: { nested: 1 } })).some(function (i) { return i.attribute === "obj"; }));
  check("validate: conformant minimal event has zero issues", b.cloudEvents.validate(v).length === 0);
}

function testJsonFormatBranches() {
  check("fromJSON rejects non-string/Buffer input",
        code(function () { b.cloudEvents.fromJSON(12345); }) === "cloud-events/bad-input");
  check("fromJSON rejects oversized input",
        code(function () { b.cloudEvents.fromJSON(JSON.stringify({ specversion: "1.0", id: "1", source: "/x", type: "t", data: "x".repeat(5000) }), { maxBytes: 100 }); }) === "cloud-events/too-large");
  check("fromJSON rejects a non-object JSON document",
        code(function () { b.cloudEvents.fromJSON("\"just a string\""); }) === "cloud-events/invalid");
  check("fromJSON accepts a Buffer document",
        b.cloudEvents.fromJSON(Buffer.from(JSON.stringify({ specversion: "1.0", id: "1", source: "/x", type: "t" }))).id === "1");
  check("toJSONBatch rejects a non-array",
        code(function () { b.cloudEvents.toJSONBatch("nope"); }) === "cloud-events/bad-input");
  check("fromJSONBatch rejects a non-array body",
        code(function () { b.cloudEvents.fromJSONBatch("{}"); }) === "cloud-events/invalid");
  check("fromJSONBatch rejects a non-object element",
        code(function () { b.cloudEvents.fromJSONBatch("[1,2,3]"); }) === "cloud-events/invalid");
  // Explicit maxBytes exercises the non-default arm of the byte cap.
  check("fromJSONBatch honors an explicit maxBytes",
        b.cloudEvents.fromJSONBatch("[]", { maxBytes: 5000 }).length === 0);
}

function testHttpBranches() {
  // Boolean extension → header string "true" via _headerValueFor.
  var boolEnc = b.cloudEvents.http.encodeBinary(b.cloudEvents.wrap({ source: "/x", type: "t", extensions: { flag: true } }));
  check("encodeBinary renders boolean extension as 'true'", boolEnc.headers["ce-flag"] === "true");
  // Object data with NO datacontenttype → JSON body + defaulted content-type.
  var enc603 = b.cloudEvents.http.encodeBinary({ specversion: "1.0", id: "1", source: "/x", type: "t", data: { a: 1 } });
  check("encodeBinary defaults content-type for typeless object data",
        enc603.headers["content-type"] === "application/json" && JSON.parse(enc603.body).a === 1);
  // Boolean-false extension → header string "false".
  var falseEnc = b.cloudEvents.http.encodeBinary(b.cloudEvents.wrap({ source: "/x", type: "t", extensions: { flag: false } }));
  check("encodeBinary renders boolean-false extension as 'false'", falseEnc.headers["ce-flag"] === "false");
  // Non-JSON media string data carried as-is.
  var enc600 = b.cloudEvents.http.encodeBinary({ specversion: "1.0", id: "1", source: "/x", type: "t", datacontenttype: "text/plain", data: "raw text" });
  check("encodeBinary keeps non-JSON string body verbatim", enc600.body === "raw text");
  // Non-JSON media with a non-string payload → JSON-stringified body.
  var encObjBin = b.cloudEvents.http.encodeBinary({ specversion: "1.0", id: "1", source: "/x", type: "t", datacontenttype: "application/octet-stream", data: { a: 1 } });
  check("encodeBinary JSON-stringifies non-string data under non-JSON media", encObjBin.body === JSON.stringify({ a: 1 }));
  // data_base64 event → Buffer body.
  var binEnc = b.cloudEvents.http.encodeBinary(b.cloudEvents.wrap({ source: "/x", type: "t", data: Buffer.from([5, 6, 7]) }));
  check("encodeBinary emits Buffer body for a data_base64 event", Buffer.isBuffer(binEnc.body) && binEnc.body.length === 3);
  // Null-valued attribute is skipped when emitting headers.
  var encNull = b.cloudEvents.http.encodeBinary({ specversion: "1.0", id: "1", source: "/x", type: "t", subject: null });
  check("encodeBinary skips a null-valued attribute", encNull.headers["ce-subject"] === undefined);
  // Array-valued header is joined before ce-* extraction.
  var decArr = b.cloudEvents.http.decodeBinary({ "ce-specversion": ["1.0"], "ce-id": "1", "ce-source": "/x", "ce-type": "t" }, "");
  check("decodeBinary joins an array-valued header", decArr.specversion === "1.0");
  // Null body → empty payload.
  var decEmpty = b.cloudEvents.http.decodeBinary({ "ce-specversion": "1.0", "ce-id": "1", "ce-source": "/x", "ce-type": "t" }, null);
  check("decodeBinary treats a null body as empty", decEmpty.data === undefined && decEmpty.data_base64 === undefined);
  check("decodeBinary rejects a non-string/Buffer body",
        code(function () { b.cloudEvents.http.decodeBinary({ "ce-specversion": "1.0", "ce-id": "1", "ce-source": "/x", "ce-type": "t" }, 12345); }) === "cloud-events/bad-input");
  check("decodeBinary rejects an oversized body",
        code(function () { b.cloudEvents.http.decodeBinary({ "ce-specversion": "1.0", "ce-id": "1", "ce-source": "/x", "ce-type": "t", "content-type": "application/json" }, "x".repeat(5000), { maxBytes: 100 }); }) === "cloud-events/too-large");
  check("decodeBinary rejects a malformed JSON body",
        code(function () { b.cloudEvents.http.decodeBinary({ "ce-specversion": "1.0", "ce-id": "1", "ce-source": "/x", "ce-type": "t", "content-type": "application/json" }, "{nope"); }) === "cloud-events/bad-json");
  var decText = b.cloudEvents.http.decodeBinary({ "ce-specversion": "1.0", "ce-id": "1", "ce-source": "/x", "ce-type": "t", "content-type": "text/plain" }, "hello text");
  check("decodeBinary reads a text/* body as a string", decText.data === "hello text");
}

function run() {
  testWrapParse();
  testValidate();
  testJsonFormat();
  testBatch();
  testHttpBinary();
  testHttpStructuredAndDetect();
  testWrapBranches();
  testParseBranches();
  testValidateBranches();
  testJsonFormatBranches();
  testHttpBranches();
}
if (require.main === module) {
  try { run(); console.log("[cloud-events] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
}
module.exports = { run: run };

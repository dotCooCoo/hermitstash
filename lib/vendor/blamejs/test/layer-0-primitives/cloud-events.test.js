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

function run() {
  testWrapParse();
  testValidate();
  testJsonFormat();
  testBatch();
  testHttpBinary();
  testHttpStructuredAndDetect();
}
if (require.main === module) {
  try { run(); console.log("[cloud-events] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
}
module.exports = { run: run };

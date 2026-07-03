// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.jsonApi — JSON:API v1.1 response builders + query parser.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testDataResponse() {
  var out = b.jsonApi.dataResponse({
    type: "users", id: "1", attributes: { name: "alice" },
  });
  check("dataResponse wraps in top-level data",
    out && out.data && out.data.type === "users" && out.data.id === "1");
}

function testErrorResponse() {
  var out = b.jsonApi.errorResponse([
    { status: "422", title: "Invalid email" },
  ]);
  check("errorResponse wraps in top-level errors",
    out && Array.isArray(out.errors) && out.errors.length === 1);
  check("errorResponse error has status + title",
    out.errors[0].status === "422" && out.errors[0].title === "Invalid email");
}

function testErrorResponseRefusesEmpty() {
  var threw = null;
  try { b.jsonApi.errorResponse([]); }
  catch (e) { threw = e.code; }
  check("errorResponse refuses empty array", threw === "json-api/no-errors");
}

function testParseQuery() {
  var q = b.jsonApi.parseQuery("include=author&sort=-created,name&page[number]=2");
  check("parseQuery returns include array", Array.isArray(q.include) && q.include.indexOf("author") !== -1);
  check("parseQuery returns sort array",
    Array.isArray(q.sort) && q.sort.length === 2);
}

function testJsonApiErrorClass() {
  check("JsonApiError exported", typeof b.jsonApi.JsonApiError === "function");
  var e = new b.jsonApi.JsonApiError("json-api/test", "synthetic");
  check("JsonApiError carries code", e.code === "json-api/test");
}

function run() {
  testDataResponse();
  testErrorResponse();
  testErrorResponseRefusesEmpty();
  testParseQuery();
  testJsonApiErrorClass();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };

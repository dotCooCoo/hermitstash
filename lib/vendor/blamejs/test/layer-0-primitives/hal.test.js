// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// b.hal — HAL hypermedia resource builder.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testResourceShape() {
  var r = b.hal.resource(
    { title: "Hello" },
    { links: { self: "/articles/1" } }
  );
  check("resource includes payload",        r.title === "Hello");
  check("resource includes _links",         r._links && r._links.self);
  check("link normalized to LinkObject",    typeof r._links.self.href === "string");
}

function testEmbedded() {
  var r = b.hal.resource(
    { title: "Index" },
    { embedded: { items: [{ id: 1 }, { id: 2 }] } }
  );
  check("resource includes _embedded array",
    Array.isArray(r._embedded.items) && r._embedded.items.length === 2);
}

function testRefusesReservedKey() {
  var threw = null;
  try { b.hal.resource({ _links: {} }); }
  catch (e) { threw = e.code; }
  check("resource refuses payload containing _links", threw === "hal/reserved-key");
}

function testHalErrorClass() {
  check("HalError exported", typeof b.hal.HalError === "function");
  var e = new b.hal.HalError("hal/test", "synthetic");
  check("HalError carries code", e.code === "hal/test");
}

function run() {
  testResourceShape();
  testEmbedded();
  testRefusesReservedKey();
  testHalErrorClass();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };

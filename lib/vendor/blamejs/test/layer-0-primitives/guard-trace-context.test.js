// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectRefused(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function testSurface() {
  check("validate fn",          typeof b.guardTraceContext.validate === "function");
  check("compliancePosture fn", typeof b.guardTraceContext.compliancePosture === "function");
  check("NAME = traceContext",  b.guardTraceContext.NAME === "traceContext");
  check("KIND = trace-context", b.guardTraceContext.KIND === "trace-context");
  check("PROFILES frozen",      Object.isFrozen(b.guardTraceContext.PROFILES));
  check("GuardTraceContextError",
    typeof b.guardTraceContext.GuardTraceContextError === "function");
  var e = new b.guardTraceContext.GuardTraceContextError("trace-context/test", "t");
  check("error carries code",   e.code === "trace-context/test");
  check("compliancePosture hipaa",   b.guardTraceContext.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardTraceContext.compliancePosture("nope") === null);
}

function testValid() {
  b.guardTraceContext.validate({
    traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
  });
  // With tracestate
  b.guardTraceContext.validate({
    traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
    tracestate:  "vendor=value,other=value2",
  });
}

function testRefuses() {
  expectRefused("refuses non-object",
    function () { b.guardTraceContext.validate(null); },
    "trace-context/bad-input");
  expectRefused("refuses no traceparent",
    function () { b.guardTraceContext.validate({}); },
    "trace-context/no-traceparent");
  expectRefused("refuses wrong length",
    function () { b.guardTraceContext.validate({ traceparent: "00-short-foo-01" }); },
    "trace-context/bad-traceparent-length");
  expectRefused("refuses non-hex characters",
    function () {
      b.guardTraceContext.validate({
        traceparent: "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b7ad6b7169203331-01",
      });
    }, "trace-context/bad-traceparent-shape");
  expectRefused("refuses zero trace-id",
    function () {
      b.guardTraceContext.validate({
        traceparent: "00-00000000000000000000000000000000-b7ad6b7169203331-01",
      });
    }, "trace-context/zero-trace-id");
  expectRefused("refuses zero span-id",
    function () {
      b.guardTraceContext.validate({
        traceparent: "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",
      });
    }, "trace-context/zero-span-id");
  expectRefused("refuses ff version",
    function () {
      b.guardTraceContext.validate({
        traceparent: "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
      });
    }, "trace-context/forbidden-version");
  expectRefused("refuses v01 under strict",
    function () {
      b.guardTraceContext.validate({
        traceparent: "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
      });
    }, "trace-context/version-not-allowed");
  // balanced profile allows v01
  b.guardTraceContext.validate({
    traceparent: "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
  }, { profile: "balanced" });
  expectRefused("refuses oversized tracestate",
    function () {
      var big = "k=" + "v".repeat(600);                                                               // allow:raw-byte-literal — test
      b.guardTraceContext.validate({
        traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        tracestate:  big,
      });
    }, "trace-context/tracestate-too-big");
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

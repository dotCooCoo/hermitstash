"use strict";
// b.lro — AIP-151 Long-Running Operations.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testCreateShape() {
  var lro = b.lro.create();
  check("create returns submit",   typeof lro.submit === "function");
  check("create returns status",   typeof lro.status === "function");
  check("create returns list",     typeof lro.list   === "function");
  check("create returns cancel",   typeof lro.cancel === "function");
}

async function testSubmitAndStatus() {
  var lro = b.lro.create();
  var op = lro.submit({ work: function () { return Promise.resolve({ ok: true }); } });
  check("submit returns operation with name", typeof op.name === "string" && op.name.length > 0);
  check("submit returns operation not-yet-done", op.done === false);
  // Wait briefly for the microtask queue to drain.
  await helpers.waitUntil(function () { return lro.status(op.name).done; },
    { timeoutMs: 2000, label: "lro op completes" });
  var st = lro.status(op.name);
  check("status returns done=true after work resolves", st.done === true);
  check("status returns response on success",
    st.response && st.response.ok === true);
}

async function testWorkFailureSurfacesError() {
  var lro = b.lro.create();
  var op = lro.submit({ work: function () { return Promise.reject(new Error("boom")); } });
  await helpers.waitUntil(function () { return lro.status(op.name).done; },
    { timeoutMs: 2000, label: "lro failure surfaces" });
  var st = lro.status(op.name);
  check("status returns error on failure",
    st.error && st.error.code === 13 && /boom/.test(st.error.message));                            // allow:raw-byte-literal — google.rpc.Code.INTERNAL = 13
}

function testCancelUnknownThrows() {
  var lro = b.lro.create();
  var threw = null;
  try { lro.cancel("operations/does-not-exist"); }
  catch (e) { threw = e.code; }
  check("cancel refuses unknown name", threw === "lro/not-found");
}

function testLroErrorClass() {
  check("LroError exported", typeof b.lro.LroError === "function");
  var e = new b.lro.LroError("lro/test", "synthetic");
  check("LroError carries code", e.code === "lro/test");
}

async function run() {
  testCreateShape();
  await testSubmitAndStatus();
  await testWorkFailureSurfacesError();
  testCancelUnknownThrows();
  testLroErrorClass();
}

if (require.main === module) {
  run().catch(function (e) { console.error(e); process.exit(1); });
}
module.exports = { run: run };

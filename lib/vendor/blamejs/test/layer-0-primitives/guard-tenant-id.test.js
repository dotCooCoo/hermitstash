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
  check("validate fn",          typeof b.guardTenantId.validate === "function");
  check("compliancePosture fn", typeof b.guardTenantId.compliancePosture === "function");
  check("NAME = tenantId",      b.guardTenantId.NAME === "tenantId");
  check("KIND = tenant-id",     b.guardTenantId.KIND === "tenant-id");
  check("PROFILES frozen",      Object.isFrozen(b.guardTenantId.PROFILES));
  check("RESERVED frozen",      Object.isFrozen(b.guardTenantId.RESERVED));
  check("GuardTenantIdError",   typeof b.guardTenantId.GuardTenantIdError === "function");
  var e = new b.guardTenantId.GuardTenantIdError("tenant-id/test", "t");
  check("error carries code",   e.code === "tenant-id/test");
  check("compliancePosture hipaa",   b.guardTenantId.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardTenantId.compliancePosture("nope") === null);
}

function testValid() {
  b.guardTenantId.validate("acme-clinic");
  b.guardTenantId.validate("tenant-123");
  b.guardTenantId.validate("a.b.c");
}

function testRefuses() {
  expectRefused("refuses empty",
    function () { b.guardTenantId.validate(""); }, "tenant-id/bad-input");
  expectRefused("refuses non-string",
    function () { b.guardTenantId.validate(42); }, "tenant-id/bad-input");
  expectRefused("refuses ROOT reserved",
    function () { b.guardTenantId.validate("ROOT"); }, "tenant-id/reserved");
  expectRefused("refuses FRAMEWORK reserved",
    function () { b.guardTenantId.validate("FRAMEWORK"); }, "tenant-id/reserved");
  expectRefused("refuses leading dot",
    function () { b.guardTenantId.validate(".hidden"); }, "tenant-id/hidden");
  expectRefused("refuses path-traversal",
    function () { b.guardTenantId.validate("a..b"); }, "tenant-id/path-traversal");
  expectRefused("refuses slash",
    function () { b.guardTenantId.validate("a/b"); }, "tenant-id/bad-char");
  expectRefused("refuses non-ascii",
    function () { b.guardTenantId.validate("tenant-français"); }, "tenant-id/non-ascii");
  expectRefused("refuses control char",
    function () { b.guardTenantId.validate("a\rb"); }, "tenant-id/bad-char");
  expectRefused("refuses oversize",
    function () {
      var big = "x"; for (var i = 0; i < 7; i += 1) big += big;
      b.guardTenantId.validate(big);
    }, "tenant-id/oversize");
}

// A tenant id that collides with an inherited Object.prototype member
// ("toString", "constructor", "hasOwnProperty", …) is a legitimate id —
// only ROOT / FRAMEWORK / * are framework-reserved. The reserved check
// must consult RESERVED's own keys, not the prototype chain, so these
// validate instead of being spuriously refused as reserved.
function testInheritedKeyNotReserved() {
  // Harmless inherited-member names only SHADOW the member on the store object
  // (no pollution), so they are legitimate tenant ids.
  ["toString", "hasOwnProperty", "valueOf", "isPrototypeOf",
   "propertyIsEnumerable", "toLocaleString"].forEach(function (id) {
    check("inherited-key id '" + id + "' validates (not reserved)",
      b.guardTenantId.validate(id) === id);
  });
  // ...but the prototype-pollution key names ARE refused: `store["__proto__"] = row`
  // sets the store's prototype, and constructor/prototype collide with the chain.
  ["__proto__", "constructor", "prototype"].forEach(function (id) {
    expectRefused("prototype-pollution id '" + id + "' refused",
      function () { b.guardTenantId.validate(id); }, "tenant-id/reserved");
  });
  // The genuinely-reserved names still refuse — the fix must not narrow.
  expectRefused("'*' still reserved",
    function () { b.guardTenantId.validate("*"); }, "tenant-id/reserved");
  expectRefused("ROOT still reserved",
    function () { b.guardTenantId.validate("ROOT"); }, "tenant-id/reserved");
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
  testInheritedKeyNotReserved();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

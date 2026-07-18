// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Own-property membership class.
//
// A guard that tests membership in a plain-object table with a bare
// `TABLE[key]` truthiness read walks the prototype chain: a key that collides
// with an inherited Object.prototype member — `constructor` is the only
// all-lowercase data property, so it survives a lowercased key — reads the
// inherited value as truthy and is misclassified. Depending on the table's
// meaning this over-rejects (a reserved/forbidden/void table: the key is
// wrongly refused) or fails open (an allowlist/catalogue: the key wrongly
// passes). Every case resolves the same way: Object.prototype.hasOwnProperty
// .call(TABLE, key) so only the table's own keys match. This locks the guard
// family the campaign has been converting off the truthiness read.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

// ---- guardAgentRegistry: a reserved-name table must not flag `constructor` ----
function testAgentRegistryReservedName() {
  // `constructor` is NOT a framework-reserved name; it must validate on its
  // own merits, not be refused because RESERVED_EXACT["constructor"] inherits
  // the Object constructor. (A genuinely reserved name still throws.)
  var ok = null;
  try { b.guardAgentRegistry.validate({ kind: "register", name: "constructor", agentKind: "mail" }); ok = true; }
  catch (e) { ok = e.code; }
  check("guardAgentRegistry accepts a 'constructor' name (not misflagged reserved)", ok === true);
}

// ---- guardListUnsubscribe: reserved-local-host + dangerous-scheme tables ----
function testListUnsubscribeReservedHostAndScheme() {
  // A 'constructor' host is not a reserved localhost name — the one-click URI
  // must stay eligible, not be dropped as reserved-local-host.
  var vHost = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<https://constructor/unsub>",
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("guardListUnsubscribe does not flag a 'constructor' host as reserved-local-host",
    Array.isArray(vHost.uris) && vHost.uris.length === 1 && vHost.uris[0].oneClickEligible === true);

  // A 'constructor:' scheme is not on the dangerous-scheme denylist; it must
  // not be auto-refused (a real dangerous scheme still is — below).
  var vScheme = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<constructor:foo>, <https://x.com/u>",
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("guardListUnsubscribe does not refuse a 'constructor:' scheme as dangerous",
    vScheme.action === "accept");

  // Regression guard: a genuinely dangerous scheme is still refused (the
  // own-property change does not weaken the denylist for real entries).
  var vJs = b.guardListUnsubscribe.validate({
    listUnsubscribe:     "<javascript:alert(1)>",
    listUnsubscribePost: "List-Unsubscribe=One-Click",
  });
  check("guardListUnsubscribe still refuses a real dangerous scheme (javascript:)",
    vJs.action === "refuse" && vJs.reason.indexOf("always-refused") !== -1);
}

// ---- htmlBalance: the void-element table (open + close paths) ----
function testHtmlBalanceVoidTable() {
  // `<constructor>` is not a void element: the opening tag must be pushed and
  // matched by its close (balanced), not skipped as void (which orphaned the
  // close). Both the open-path and close-path membership tests are covered.
  check("htmlBalance treats <constructor> as a normal (balanced) element",
    b.htmlBalance.check("<constructor></constructor>") === null);

  // Regression guard: a real void element is still not pushed (no false
  // unclosed error) and a stray void close is still flagged.
  check("htmlBalance still treats <br> as void (no unclosed error)",
    b.htmlBalance.check("<br>text") === null);
  var voidClose = b.htmlBalance.check("</br>");
  check("htmlBalance still flags a stray void-element close",
    voidClose !== null && voidClose.code === "html/void-close");
}

// ---- mail.bimi: the Tiny-PS forbidden-element table ----
function testBimiForbiddenTable() {
  function _codes(rv) { return (rv.violations || []).map(function (v) { return v.code || v; }); }
  var svgHead = '<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1" xmlns="http://www.w3.org/2000/svg">';
  // A <constructor> element is not on the Tiny-PS forbidden list; it must not
  // be flagged element-forbidden via a prototype-member truthiness read.
  var vProto = b.mail.bimi.validateTinyPsSvg(svgHead + "<constructor></constructor></svg>");
  check("mail.bimi does not flag a <constructor> element as forbidden",
    _codes(vProto).indexOf("element-forbidden") === -1);
  // Regression guard: a real forbidden element (<script>) is still flagged.
  var vScript = b.mail.bimi.validateTinyPsSvg(svgHead + "<script>x</script></svg>");
  check("mail.bimi still flags a real forbidden element (<script>)",
    _codes(vScript).indexOf("element-forbidden") !== -1);
}

function run() {
  var before = helpers.getChecks();
  testAgentRegistryReservedName();
  testListUnsubscribeReservedHostAndScheme();
  testHtmlBalanceVoidTable();
  testBimiForbiddenTable();
  if (require.main === module) {
    console.log("OK — own-property membership guards — " + (helpers.getChecks() - before) + " checks");
  }
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };

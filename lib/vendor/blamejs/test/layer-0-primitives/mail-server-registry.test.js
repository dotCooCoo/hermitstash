"use strict";
/**
 * b.mail.serverRegistry — shared dispatch registry for IMAP / JMAP /
 * ManageSieve listeners. Tests cover the registration contract,
 * dispatch path, and refusal classes.
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function _baseEntry(fn) {
  return { fn: fn, maxHandlerBytes: 8 * 1024, maxHandlerMs: 5 * 1000 };
}

function testCreateValidatesProtocol() {
  var threw = false;
  try { b.mail.serverRegistry.create({ protocol: "ftp" }); } catch (_e) { threw = true; }
  check("unknown protocol refused", threw);
}

function testBuiltinAndOverride() {
  var reg = b.mail.serverRegistry.create({
    protocol: "imap",
    defaults: { NOOP: _baseEntry(function () { return "default"; }) },
    overrides: { NOOP: _baseEntry(function () { return "override"; }) },
  });
  check("override shadows default",  reg.dispatch("NOOP") === "override");
  check("source is operator-override", reg.source("NOOP") === "operator-override");
}

function testNotConfiguredFallback() {
  var reg = b.mail.serverRegistry.create({
    protocol: "imap",
    defaults: {},
    notFoundHandler: function (name) { return "missing:" + name; },
  });
  check("notFoundHandler fires", reg.dispatch("FETCH") === "missing:FETCH");
}

function testBudgetRefusalAtRegister() {
  var threw;
  threw = false;
  try {
    b.mail.serverRegistry.create({
      protocol: "imap",
      defaults: { NOOP: { fn: function () {} } },   // no budgets
    });
  } catch (_e) { threw = true; }
  check("missing maxHandlerBytes refused", threw);

  threw = false;
  try {
    b.mail.serverRegistry.create({
      protocol: "imap",
      defaults: { NOOP: { fn: function () {}, maxHandlerBytes: 1024 } },   // no ms
    });
  } catch (_e) { threw = true; }
  check("missing maxHandlerMs refused", threw);
}

function testCatalogueGate() {
  var threw = false;
  try {
    b.mail.serverRegistry.create({
      protocol: "imap",
      defaults: { NONSENSE_VERB: _baseEntry(function () {}) },
    });
  } catch (_e) { threw = true; }
  check("catalogue rejects unknown method without allowExperimental", threw);

  // With allowExperimental: true the registration succeeds.
  var reg = b.mail.serverRegistry.create({
    protocol: "imap",
    defaults: {
      EXPERIMENTAL_VERB: Object.assign(_baseEntry(function () { return "ok"; }),
        { allowExperimental: true }),
    },
  });
  check("allowExperimental opt-in works", reg.dispatch("EXPERIMENTAL_VERB") === "ok");
}

async function testTimeoutWraps() {
  var reg = b.mail.serverRegistry.create({
    protocol: "imap",
    defaults: {
      NOOP: {
        fn: function () { return new Promise(function () { /* never */ }); },
        maxHandlerBytes: 8 * 1024,
        maxHandlerMs:    100,
      },
    },
  });
  var threw = false;
  var caught = null;
  try { await reg.dispatch("NOOP"); }
  catch (e) { threw = true; caught = e; }
  check("Promise handler past maxHandlerMs times out", threw);
  if (caught) {
    check("timeout error is typed",
      caught.code === "mail-server-registry/handler-timeout" ||
      /timeout/i.test(caught.message || "") ||
      caught.name === "MailServerRegistryError");
  }
}

function testListAndHas() {
  var reg = b.mail.serverRegistry.create({
    protocol: "managesieve",
    defaults: { NOOP: _baseEntry(function () {}) },
  });
  check("has() works",      reg.has("NOOP") === true);
  check("has() false miss", reg.has("PUTSCRIPT") === false);
  check("list() returns one", reg.list().length === 1);
  check("list entry has source", reg.list()[0].source === "builtin");
}

async function run() {
  testCreateValidatesProtocol();
  testBuiltinAndOverride();
  testNotConfiguredFallback();
  testBudgetRefusalAtRegister();
  testCatalogueGate();
  await testTimeoutWraps();
  testListAndHas();
}

if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
module.exports = { run: run };

"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var mailServerManageSieve = require("../../lib/mail-server-managesieve");

function _stubMailStore() {
  return {
    sieveScripts: {
      put:       async function () { return; },
      list:      async function () { return []; },
      get:       async function () { return null; },
      setActive: async function () { return; },
      delete:    async function () { return; },
      rename:    async function () { return; },
      haveSpace: async function () { return { ok: true }; },
    },
  };
}

function testSurface() {
  check("namespace",   typeof mailServerManageSieve === "object");
  check("create fn",   typeof mailServerManageSieve.create === "function");
  check("error class",
    typeof mailServerManageSieve.MailServerManageSieveError === "function");
}

function testRequiresTlsContext() {
  var threw = null;
  try {
    mailServerManageSieve.create({ mailStore: _stubMailStore() });
  } catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-managesieve/no-tls-context");
  check("error message points at b.mail.server.tls.context",
    threw && /b\.mail\.server\.tls\.context/.test(threw.message));
  check("error message names allowPlaintext opt-in",
    threw && /allowPlaintext/.test(threw.message));
}

function testAllowPlaintextOpt() {
  // Explicit allowPlaintext + no tlsContext is accepted (operator
  // opted into plaintext mode + audit emits warning at boot).
  var rv = null;
  try {
    rv = mailServerManageSieve.create({
      mailStore:      _stubMailStore(),
      allowPlaintext: true,
    });
  } catch (e) { rv = e; }
  check("create accepts allowPlaintext=true with no tlsContext",
    rv && typeof rv.listen === "function" && typeof rv.close === "function");
}

function testRequiresMailStore() {
  var threw = null;
  try { mailServerManageSieve.create({ tlsContext: {} }); }
  catch (e) { threw = e; }
  check("create refuses missing mailStore",
    threw && threw.code === "mail-server-managesieve/no-mail-store");
}

function testRequiresMailStoreSieveScripts() {
  var threw = null;
  try { mailServerManageSieve.create({ tlsContext: {}, mailStore: {} }); }
  catch (e) { threw = e; }
  check("create refuses mailStore without sieveScripts",
    threw && threw.code === "mail-server-managesieve/no-mail-store");

  // sieveScripts present but missing the `put` method.
  var threw2 = null;
  try {
    mailServerManageSieve.create({
      tlsContext: {},
      mailStore: { sieveScripts: { list: function () {} } },
    });
  } catch (e) { threw2 = e; }
  check("create refuses sieveScripts without put method",
    threw2 && threw2.code === "mail-server-managesieve/no-mail-store");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { mailServerManageSieve.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-managesieve/") === 0);
  }
  expectBad("refuses negative maxLineBytes",
    { tlsContext: {}, mailStore: _stubMailStore(), maxLineBytes: -1 });
  expectBad("refuses Infinity idleTimeoutMs",
    { tlsContext: {}, mailStore: _stubMailStore(), idleTimeoutMs: Infinity });
  expectBad("refuses NaN maxLineBytes",
    { tlsContext: {}, mailStore: _stubMailStore(), maxLineBytes: NaN });
}

function testRefusesNonObjectOpts() {
  var threw = null;
  try { mailServerManageSieve.create(null); } catch (e) { threw = e; }
  check("create refuses null opts",
    threw && (threw.code || "").indexOf("mail-server-managesieve/") === 0);
}

function testHandleSurface() {
  var handle = mailServerManageSieve.create({
    tlsContext: {},
    mailStore:  _stubMailStore(),
  });
  check("handle.listen is a function",  typeof handle.listen === "function");
  check("handle.close is a function",   typeof handle.close === "function");
}

function run() {
  testSurface();
  testRequiresTlsContext();
  testAllowPlaintextOpt();
  testRequiresMailStore();
  testRequiresMailStoreSieveScripts();
  testBadBoundsRefused();
  testRefusesNonObjectOpts();
  testHandleSurface();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-server-managesieve] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}

void helpers;

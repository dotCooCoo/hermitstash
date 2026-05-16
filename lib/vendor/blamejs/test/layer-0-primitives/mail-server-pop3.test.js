"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("namespace",    typeof b.mail.server.pop3 === "object");
  check("create fn",    typeof b.mail.server.pop3.create === "function");
  check("error class",  typeof b.mail.server.pop3.MailServerPop3Error === "function");
}

function _stubMailStore() {
  return {
    openPop3Drop:    async function () { return { dropId: "drop-1", count: 0, totalBytes: 0 }; },
    commitPop3Drop:  async function () { return { deleted: 0 }; },
    listMessages:    async function () { return []; },
    getMessage:      async function () { return null; },
    markDelete:      async function () { return; },
  };
}

function testRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.pop3.create({ mailStore: _stubMailStore() }); }
  catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-pop3/no-tls-context");
  check("error message points at b.mail.server.tls.context",
    threw && /b\.mail\.server\.tls\.context/.test(threw.message));
}

function testRequiresMailStore() {
  var threw = null;
  try { b.mail.server.pop3.create({ tlsContext: {} }); }
  catch (e) { threw = e; }
  check("create refuses missing mailStore",
    threw && threw.code === "mail-server-pop3/no-mail-store");
}

function testRequiresMailStoreOpenPop3Drop() {
  var threw = null;
  try { b.mail.server.pop3.create({ tlsContext: {}, mailStore: {} }); }
  catch (e) { threw = e; }
  check("create refuses mailStore without openPop3Drop",
    threw && threw.code === "mail-server-pop3/no-mail-store");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.pop3.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-pop3/") === 0);
  }
  expectBad("refuses negative maxLineBytes",
    { tlsContext: {}, mailStore: _stubMailStore(), maxLineBytes: -1 });
  expectBad("refuses Infinity idleTimeoutMs",
    { tlsContext: {}, mailStore: _stubMailStore(), idleTimeoutMs: Infinity });
}

function run() {
  testSurface();
  testRequiresTlsContext();
  testRequiresMailStore();
  testRequiresMailStoreOpenPop3Drop();
  testBadBoundsRefused();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-server-pop3] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}

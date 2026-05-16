"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;

function testSurface() {
  check("b.mail.server.imap namespace",   typeof b.mail.server.imap === "object");
  check("create is fn",                    typeof b.mail.server.imap.create === "function");
  check("error class",                     typeof b.mail.server.imap.MailServerImapError === "function");
}

function testRequiresTlsContext() {
  var threw = null;
  try { b.mail.server.imap.create({ mailStore: { appendMessage: function () {} } }); }
  catch (e) { threw = e; }
  check("create refuses missing tlsContext",
    threw && threw.code === "mail-server-imap/no-tls-context");
  check("error message points at b.mail.server.tls.context",
    threw && /b\.mail\.server\.tls\.context/.test(threw.message));
}

function testRequiresMailStore() {
  var threw = null;
  try { b.mail.server.imap.create({ tlsContext: {} }); }
  catch (e) { threw = e; }
  check("create refuses missing mailStore",
    threw && threw.code === "mail-server-imap/no-mail-store");
}

function testBadBoundsRefused() {
  function expectBad(label, opts) {
    var threw = null;
    try { b.mail.server.imap.create(opts); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("mail-server-imap/") === 0);
  }
  expectBad("refuses negative maxLineBytes",
    { tlsContext: {}, mailStore: { appendMessage: function () {} }, maxLineBytes: -1 });
  expectBad("refuses Infinity idleTimeoutMs",
    { tlsContext: {}, mailStore: { appendMessage: function () {} }, idleTimeoutMs: Infinity });
}

function run() {
  testSurface();
  testRequiresTlsContext();
  testRequiresMailStore();
  testBadBoundsRefused();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-server-imap] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}

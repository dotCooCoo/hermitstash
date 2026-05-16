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
  check("validate fn",          typeof b.guardMailCompose.validate === "function");
  check("compliancePosture fn", typeof b.guardMailCompose.compliancePosture === "function");
  check("NAME = mailCompose",   b.guardMailCompose.NAME === "mailCompose");
  check("KIND = mail-compose",  b.guardMailCompose.KIND === "mail-compose");
  check("GuardMailComposeError is fn", typeof b.guardMailCompose.GuardMailComposeError === "function");
  var e = new b.guardMailCompose.GuardMailComposeError("mail-compose/test", "test");
  check("GuardMailComposeError instances carry code", e.code === "mail-compose/test");
}

function testValid() {
  var d = b.guardMailCompose.validate({
    from:    "alice@example.com",
    to:      ["bob@example.com"],
    subject: "hello",
    body:    { text: "hi" },
  });
  check("valid passes", d && d.from === "alice@example.com");
}

function testRefuses() {
  expectRefused("refuses no draft", function () { b.guardMailCompose.validate(null); }, "mail-compose/bad-input");
  expectRefused("refuses no from",
    function () { b.guardMailCompose.validate({ to: ["x@y"], body: { text: "x" } }); },
    "mail-compose/no-from");
  expectRefused("refuses no recipients",
    function () { b.guardMailCompose.validate({ from: "a@x", body: { text: "x" } }); },
    "mail-compose/no-recipient");
  expectRefused("refuses no body",
    function () { b.guardMailCompose.validate({ from: "a@x", to: ["b@y"] }); },
    "mail-compose/no-body");
  expectRefused("refuses empty body",
    function () { b.guardMailCompose.validate({ from: "a@x", to: ["b@y"], body: {} }); },
    "mail-compose/empty-body");
  expectRefused("refuses CR in subject",
    function () {
      b.guardMailCompose.validate({ from: "a@x", to: ["b@y"], subject: "x\rinjected", body: { text: "x" } });
    },
    "mail-compose/control-char-in-header");
  expectRefused("refuses duplicate recipient",
    function () {
      b.guardMailCompose.validate({
        from: "a@x", to: ["b@y"], cc: ["b@y"], body: { text: "x" },
      });
    },
    "mail-compose/duplicate-recipient");
  expectRefused("refuses identity mismatch",
    function () {
      b.guardMailCompose.validate({
        from: "alice@example.com", to: ["b@y"], body: { text: "x" },
      }, { identity: { email: "bob@example.com" } });
    },
    "mail-compose/identity-mismatch");
  expectRefused("refuses multipart-alt without opt-in",
    function () {
      b.guardMailCompose.validate({
        from: "a@x", to: ["b@y"], body: { text: "x", html: "<p>x</p>" },
      });
    },
    "mail-compose/multipart-alternative-disallowed");
  // With opt-in:
  b.guardMailCompose.validate({
    from: "a@x", to: ["b@y"], body: { text: "x", html: "<p>x</p>" },
  }, { allowMultipartAlternative: true });
}

function testAttachments() {
  b.guardMailCompose.validate({
    from: "a@x", to: ["b@y"], body: { text: "x", attachments: [{ sizeBytes: 1000 }] },
  });
  expectRefused("refuses attachment over cap",
    function () {
      b.guardMailCompose.validate({
        from: "a@x", to: ["b@y"],
        body:  { text: "x", attachments: [{ sizeBytes: 26214401 }] },                                 // allow:raw-byte-literal — 25MiB + 1
      });
    },
    "mail-compose/attachment-too-big");
}

function testIdentityAlignmentAngleBrackets() {
  b.guardMailCompose.validate({
    from: "Alice <alice@example.com>", to: ["b@y"], body: { text: "x" },
  }, { identity: { email: "alice@example.com" } });
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
  testAttachments();
  testIdentityAlignmentAngleBrackets();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

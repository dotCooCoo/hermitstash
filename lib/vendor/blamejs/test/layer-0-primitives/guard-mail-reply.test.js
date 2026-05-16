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
  check("validate fn",         typeof b.guardMailReply.validate === "function");
  check("NAME = mailReply",    b.guardMailReply.NAME === "mailReply");
  check("KIND = mail-reply",   b.guardMailReply.KIND === "mail-reply");
  check("GuardMailReplyError is fn", typeof b.guardMailReply.GuardMailReplyError === "function");
  var e = new b.guardMailReply.GuardMailReplyError("mail-reply/test", "test");
  check("GuardMailReplyError instances carry code", e.code === "mail-reply/test");
  check("compliancePosture hipaa", b.guardMailReply.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardMailReply.compliancePosture("nope") === null);
}

function testValid() {
  b.guardMailReply.validate({
    inReplyTo:  "<a@x>",
    references: ["<root@x>", "<a@x>"],
  });
}

function testRefuses() {
  expectRefused("refuses no inReplyTo",
    function () { b.guardMailReply.validate({}); },
    "mail-reply/no-in-reply-to");
  expectRefused("refuses bad inReplyTo (no brackets)",
    function () { b.guardMailReply.validate({ inReplyTo: "a@x" }); },
    "message-id/unbracketed");
  expectRefused("refuses chain too long",
    function () {
      var refs = [];
      for (var i = 0; i < 200; i += 1) refs.push("<m" + i + "@x>");
      b.guardMailReply.validate({ inReplyTo: refs[refs.length - 1], references: refs });
    },
    "mail-reply/chain-too-long");
  expectRefused("refuses discontinuity",
    function () {
      b.guardMailReply.validate({
        inReplyTo: "<a@x>",
        references: ["<root@x>", "<b@x>"],  // last != inReplyTo
      });
    },
    "mail-reply/discontinuity");
  expectRefused("refuses quoted-original too big",
    function () {
      var big = new Array(600000).join("x");                                                          // allow:raw-byte-literal — > 512 KiB
      b.guardMailReply.validate({ inReplyTo: "<a@x>", quotedOriginal: big });
    },
    "mail-reply/quoted-too-big");
}

function testForwardAttachments() {
  b.guardMailReply.validate({
    inReplyTo: "<a@x>",
    forwardedAttachments: [{ name: "f.pdf", size_bytes: 100 }],                                       // allow:raw-byte-literal — test fixture
  });
  expectRefused("refuses too many forwarded attachments",
    function () {
      var atts = [];
      for (var i = 0; i < 50; i += 1) atts.push({ name: "x" + i });
      b.guardMailReply.validate({ inReplyTo: "<a@x>", forwardedAttachments: atts });
    },
    "mail-reply/too-many-fwd-attach");
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
  testForwardAttachments();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

"use strict";
/**
 * b.safeMime — bounded MIME parser substrate for the mail stack.
 * Foundation for b.mailStore + every mail-server primitive (MX,
 * submission, IMAP, JMAP). Tests the parser surface + every cap.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _msg(headerLines, body) {
  var headers = headerLines.join("\r\n");
  return headers + "\r\n\r\n" + (body || "");
}

function testSurface() {
  check("safeMime.parse is fn",              typeof b.safeMime.parse === "function");
  check("safeMime.walk is fn",               typeof b.safeMime.walk === "function");
  check("safeMime.findFirst is fn",          typeof b.safeMime.findFirst === "function");
  check("safeMime.extractText is fn",        typeof b.safeMime.extractText === "function");
  check("safeMime.extractAttachments is fn", typeof b.safeMime.extractAttachments === "function");
  check("safeMime.SafeMimeError is fn",      typeof b.safeMime.SafeMimeError === "function");
  check("safeMime.DEFAULTS frozen",          Object.isFrozen(b.safeMime.DEFAULTS));
}

function testSimpleTextParse() {
  var tree = b.safeMime.parse(_msg(
    ["From: alice@example.com", "Subject: Hi", "Content-Type: text/plain; charset=utf-8"],
    "Hello, world!"
  ));
  check("simple: subject decoded",        tree.headers.get("subject") === "Hi");
  check("simple: from decoded",           tree.headers.get("from") === "alice@example.com");
  check("simple: leaf contentType",       tree.leaf.contentType === "text/plain");
  check("simple: leaf charset",           tree.leaf.charset === "utf-8");
  check("simple: leaf encoding default",  tree.leaf.encoding === "7bit");
  check("simple: body bytes match",       tree.leaf.body.toString("utf8") === "Hello, world!");
  check("simple: no parts",               tree.parts === null);
}

function testRfc2047EncodedSubject() {
  // RFC 2047 Q-encoded subject — "Subject: =?utf-8?Q?Hello_World?="
  var tree = b.safeMime.parse(_msg(
    ["Subject: =?utf-8?Q?Hello_World?=", "Content-Type: text/plain"],
    "body"
  ));
  check("rfc2047 Q: subject decoded", tree.headers.get("subject") === "Hello World");
}

function testRfc2047BEncodedSubject() {
  // RFC 2047 B-encoded — base64("Hello!") == "SGVsbG8h"
  var tree = b.safeMime.parse(_msg(
    ["Subject: =?utf-8?B?SGVsbG8h?=", "Content-Type: text/plain"],
    "body"
  ));
  check("rfc2047 B: subject decoded", tree.headers.get("subject") === "Hello!");
}

function testMultipartAlternative() {
  var msg = [
    "From: alice", "Subject: T",
    "Content-Type: multipart/alternative; boundary=B",
    "",
    "--B",
    "Content-Type: text/plain",
    "",
    "Plain version",
    "--B",
    "Content-Type: text/html",
    "",
    "<p>HTML version</p>",
    "--B--",
  ].join("\r\n");
  var tree = b.safeMime.parse(msg);
  check("multipart: contentType",     tree._contentType === "multipart/alternative");
  check("multipart: 2 parts",         tree.parts.length === 2);
  check("multipart: part 0 text",     tree.parts[0].leaf.body.toString().trim() === "Plain version");
  check("multipart: part 1 html",     tree.parts[1].leaf.body.toString().trim() === "<p>HTML version</p>");

  // extractText prefer=plain → first text/plain
  var txtPlain = b.safeMime.extractText(tree, { prefer: "plain" });
  check("extractText plain", txtPlain.body.trim() === "Plain version" && txtPlain.contentType === "text/plain");

  // extractText prefer=html → text/html (RFC 2046 §5.1.4 last-wins also picks html)
  var txtHtml = b.safeMime.extractText(tree, { prefer: "html" });
  check("extractText html", txtHtml.body.trim() === "<p>HTML version</p>" && txtHtml.contentType === "text/html");
}

function testNestedMultipart() {
  // multipart/mixed { multipart/alternative { text/plain, text/html }, application/pdf }
  var msg = [
    "Content-Type: multipart/mixed; boundary=OUT",
    "",
    "--OUT",
    "Content-Type: multipart/alternative; boundary=IN",
    "",
    "--IN",
    "Content-Type: text/plain",
    "",
    "plain",
    "--IN",
    "Content-Type: text/html",
    "",
    "<b>html</b>",
    "--IN--",
    "--OUT",
    "Content-Type: application/pdf",
    "Content-Disposition: attachment; filename=\"report.pdf\"",
    "Content-Transfer-Encoding: base64",
    "",
    "SGVsbG8h",
    "--OUT--",
  ].join("\r\n");
  var tree = b.safeMime.parse(msg);
  check("nested: outer is multipart", tree._contentType === "multipart/mixed");
  check("nested: 2 outer parts",      tree.parts.length === 2);
  check("nested: inner is multipart", tree.parts[0]._contentType === "multipart/alternative");
  check("nested: pdf leaf",           tree.parts[1].leaf.contentType === "application/pdf");
  check("nested: pdf body decoded",   tree.parts[1].leaf.body.toString() === "Hello!");

  var atts = b.safeMime.extractAttachments(tree);
  check("attachments: count",      atts.length === 1);
  check("attachments: filename",   atts[0].filename === "report.pdf");
  check("attachments: contentType", atts[0].contentType === "application/pdf");
}

function testBase64TransferEncoding() {
  // base64("Hello, world!") == "SGVsbG8sIHdvcmxkIQ=="
  var tree = b.safeMime.parse(_msg(
    ["Content-Type: text/plain", "Content-Transfer-Encoding: base64"],
    "SGVsbG8sIHdvcmxkIQ=="
  ));
  check("base64: body decoded", tree.leaf.body.toString("utf8") === "Hello, world!");
}

function testQuotedPrintableTransferEncoding() {
  // qp("café") with é → "=C3=A9"
  var tree = b.safeMime.parse(_msg(
    ["Content-Type: text/plain", "Content-Transfer-Encoding: quoted-printable"],
    "caf=C3=A9"
  ));
  check("qp: body decoded", tree.leaf.body.toString("utf8") === "café");
}

function testWalkVisitor() {
  var msg = [
    "Content-Type: multipart/mixed; boundary=X",
    "",
    "--X",
    "Content-Type: text/plain",
    "",
    "a",
    "--X",
    "Content-Type: text/html",
    "",
    "<p>b</p>",
    "--X--",
  ].join("\r\n");
  var tree = b.safeMime.parse(msg);
  var visited = [];
  b.safeMime.walk(tree, function (part, path) {
    visited.push((part.leaf ? part.leaf.contentType : part._contentType) + ":" + path.join("."));
  });
  check("walk: visits 3 parts (root + 2 leaves)", visited.length === 3);
  check("walk: root first", visited[0] === "multipart/mixed:");
}

function testFindFirstShortCircuits() {
  var msg = [
    "Content-Type: multipart/mixed; boundary=X",
    "",
    "--X",
    "Content-Type: text/plain",
    "",
    "a",
    "--X",
    "Content-Type: text/plain",
    "",
    "b",
    "--X--",
  ].join("\r\n");
  var tree = b.safeMime.parse(msg);
  var first = b.safeMime.findFirst(tree, function (p) { return p.leaf && p.leaf.contentType === "text/plain"; });
  check("findFirst: returns first match", first.leaf.body.toString() === "a");
}

function expectRefused(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function testRefusesOversizePartCount() {
  // Build a multipart with 65 parts (default cap is 64; cap includes the root).
  var lines = ["Content-Type: multipart/mixed; boundary=B", ""];
  for (var i = 0; i < 70; i += 1) {
    lines.push("--B", "Content-Type: text/plain", "", "p" + i);
  }
  lines.push("--B--");
  expectRefused("refuses > maxParts (CVE-2024-39929 class)",
    function () { b.safeMime.parse(lines.join("\r\n")); },
    "safe-mime/oversize-part-count");
}

function testRefusesOversizeNesting() {
  // Build a properly-nested multipart 3 levels deep, then refuse with
  // maxNestingDepth=2 to verify the cap fires. (Trying to build 17+
  // levels by string concatenation flat-out doesn't construct a valid
  // nested tree — each level needs its own --boundary inside the
  // preceding part's body.)
  var msg = [
    "Content-Type: multipart/mixed; boundary=L0",
    "",
    "--L0",
    "Content-Type: multipart/mixed; boundary=L1",
    "",
    "--L1",
    "Content-Type: multipart/mixed; boundary=L2",
    "",
    "--L2",
    "Content-Type: text/plain",
    "",
    "leaf",
    "--L2--",
    "--L1--",
    "--L0--",
  ].join("\r\n");
  expectRefused("refuses nesting > maxNestingDepth",
    function () { b.safeMime.parse(msg, { maxNestingDepth: 2 }); },
    "safe-mime/oversize-nesting");
}

function testRefusesOversizeBoundary() {
  // Boundary > 70 chars (RFC 2046 §5.1.1 cap).
  var bigBoundary = new Array(72).join("a");
  expectRefused("refuses > maxBoundary (RFC 2046 §5.1.1)",
    function () { b.safeMime.parse(_msg(
      ["Content-Type: multipart/mixed; boundary=" + bigBoundary], "")); },
    "safe-mime/oversize-boundary");
}

function testRefusesUnknownTransferEncoding() {
  expectRefused("refuses non-allowlisted CTE",
    function () { b.safeMime.parse(_msg(
      ["Content-Type: text/plain", "Content-Transfer-Encoding: x-evil"], "body")); },
    "safe-mime/unknown-transfer-encoding");
}

function testRefusesUnknownCharset() {
  expectRefused("refuses non-allowlisted charset",
    function () { b.safeMime.parse(_msg(
      ["Content-Type: text/plain; charset=invalid-charset-x"], "body")); },
    "safe-mime/unknown-charset");
}

function testRefusesControlCharInHeader() {
  // Manually inject NUL into a header value.
  var msg = "Subject: hello world\r\nContent-Type: text/plain\r\n\r\nbody";
  expectRefused("refuses NUL in header (header-injection defense)",
    function () { b.safeMime.parse(msg); },
    "safe-mime/control-char-in-header");
}

function testRefusesMissingBoundary() {
  expectRefused("refuses multipart without boundary param",
    function () { b.safeMime.parse(_msg(["Content-Type: multipart/mixed"], "stuff")); },
    "safe-mime/malformed-boundary");
}

function testRefusesOversizeMessage() {
  // Tiny opt-tweak to make the test fast.
  expectRefused("refuses message exceeding maxMessageBytes",
    function () { b.safeMime.parse(Buffer.alloc(2048), { maxMessageBytes: 1024 }); },
    "safe-mime/oversize-message");
}

function testRefusesBadInput() {
  expectRefused("refuses number input",
    function () { b.safeMime.parse(42); },
    "safe-mime/bad-input");
  expectRefused("refuses bad opt type",
    function () { b.safeMime.parse("Subject: x\r\n\r\nbody", { maxParts: -1 }); },
    "safe-mime/bad-opt");
}

function testHeaderFolding() {
  // RFC 5322 §2.2.3 — folded continuation lines join the prior line.
  var msg = "Subject: this is a\r\n very long subject\r\nContent-Type: text/plain\r\n\r\nbody";
  var tree = b.safeMime.parse(msg);
  check("folding: subject joined", tree.headers.get("subject") === "this is a very long subject");
}

function testMultiOccurrenceHeaders() {
  // Received headers stack.
  var msg = "Received: hop1\r\nReceived: hop2\r\nReceived: hop3\r\nContent-Type: text/plain\r\n\r\nbody";
  var tree = b.safeMime.parse(msg);
  check("multi: getAll returns all 3", tree.headers.getAll("received").length === 3);
  check("multi: get returns first", tree.headers.get("received") === "hop1");
}

function testPrototypePollutionDefense() {
  // Header named __proto__ must not poison Object.prototype.
  var msg = "__proto__: polluted\r\nContent-Type: text/plain\r\n\r\nbody";
  var tree = b.safeMime.parse(msg);
  check("proto: not poisoned",      ({}).polluted === undefined);
  check("proto: header skipped",    tree.headers.get("__proto__") === null);
}

async function run() {
  testSurface();
  testSimpleTextParse();
  testRfc2047EncodedSubject();
  testRfc2047BEncodedSubject();
  testMultipartAlternative();
  testNestedMultipart();
  testBase64TransferEncoding();
  testQuotedPrintableTransferEncoding();
  testWalkVisitor();
  testFindFirstShortCircuits();
  testRefusesOversizePartCount();
  testRefusesOversizeNesting();
  testRefusesOversizeBoundary();
  testRefusesUnknownTransferEncoding();
  testRefusesUnknownCharset();
  testRefusesControlCharInHeader();
  testRefusesMissingBoundary();
  testRefusesOversizeMessage();
  testRefusesBadInput();
  testHeaderFolding();
  testMultiOccurrenceHeaders();
  testPrototypePollutionDefense();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

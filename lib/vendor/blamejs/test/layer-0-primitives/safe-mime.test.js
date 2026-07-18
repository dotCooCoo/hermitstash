// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

// ---- Walk / findFirst guard clauses ---------------------------------------

function testWalkAndFindFirstGuards() {
  var tree = b.safeMime.parse(_msg(["Content-Type: text/plain"], "x"));
  // walk(null) is a documented no-op (returns undefined, no throw).
  var r = b.safeMime.walk(null, function () {});
  check("walk: null tree is a no-op", r === undefined);
  // Non-function visitor is a caller error → TypeError (config-time throw).
  var threwW = null;
  try { b.safeMime.walk(tree, "not-a-function"); } catch (e) { threwW = e; }
  check("walk: non-function visitor throws TypeError", threwW instanceof TypeError);
  // findFirst with a non-function predicate → TypeError.
  var threwF = null;
  try { b.safeMime.findFirst(tree, 123); } catch (e) { threwF = e; }
  check("findFirst: non-function predicate throws TypeError", threwF instanceof TypeError);
}

// ---- extractText outside multipart/alternative ----------------------------

function testExtractTextNonAlternativePaths() {
  // A bare text/plain leaf (not multipart/alternative) → the findFirst
  // "preferred" branch.
  var leafTree = b.safeMime.parse(_msg(["Content-Type: text/plain; charset=utf-8"], "just plain"));
  var t1 = b.safeMime.extractText(leafTree, { prefer: "plain" });
  check("extractText: single leaf plain", t1 && t1.body === "just plain" && t1.contentType === "text/plain");

  // multipart/mixed carrying only text/html, prefer=plain → no preferred
  // match, falls through to the any-text branch.
  var htmlOnly = [
    "Content-Type: multipart/mixed; boundary=M", "",
    "--M", "Content-Type: text/html", "", "<b>hi</b>", "--M--",
  ].join("\r\n");
  var t2 = b.safeMime.extractText(b.safeMime.parse(htmlOnly), { prefer: "plain" });
  check("extractText: falls back to any text/*", t2 && t2.contentType === "text/html" && t2.body.trim() === "<b>hi</b>");

  // multipart/mixed with no text part at all → null.
  var noText = [
    "Content-Type: multipart/mixed; boundary=M", "",
    "--M", "Content-Type: application/octet-stream", "Content-Transfer-Encoding: base64", "", "AAAA", "--M--",
  ].join("\r\n");
  var t3 = b.safeMime.extractText(b.safeMime.parse(noText), { prefer: "plain" });
  check("extractText: no text part returns null", t3 === null);
}

function testExtractTextAlternativeFallback() {
  // multipart/alternative but prefer=plain with only a text/html child:
  // the last-wins loop misses, the fallback loop returns the html.
  var altHtmlOnly = [
    "Content-Type: multipart/alternative; boundary=A", "",
    "--A", "Content-Type: text/html", "", "<i>x</i>", "--A--",
  ].join("\r\n");
  var t1 = b.safeMime.extractText(b.safeMime.parse(altHtmlOnly), { prefer: "plain" });
  check("extractText alt: fallback to text/html", t1 && t1.contentType === "text/html" && t1.body.trim() === "<i>x</i>");

  // multipart/alternative with no text parts → null.
  var altNoText = [
    "Content-Type: multipart/alternative; boundary=A", "",
    "--A", "Content-Type: application/json", "", "{}", "--A--",
  ].join("\r\n");
  var t2 = b.safeMime.extractText(b.safeMime.parse(altNoText), { prefer: "plain" });
  check("extractText alt: no text returns null", t2 === null);
}

// ---- LF-only line endings (CRLF is not the only wire form) -----------------

function testLfOnlyLineEndings() {
  // A message with bare-LF separators exercises the LF (not CRLF) branch
  // of both the header/body split and the header-section skip.
  var tree = b.safeMime.parse("Subject: y\n\nbody-here");
  check("LF-only: subject parsed", tree.headers.get("subject") === "y");
  check("LF-only: body parsed",    tree.leaf.body.toString("utf8") === "body-here");
}

function testMultipartLfLineEndings() {
  // LF-only multipart exercises the LF-trim of the byte before each
  // boundary delimiter (both the interior and the final one).
  var msg =
    "Content-Type: multipart/mixed; boundary=B\n\n" +
    "--B\nContent-Type: text/plain\n\naaa\n" +
    "--B\nContent-Type: text/plain\n\nbbb\n" +
    "--B--";
  var tree = b.safeMime.parse(msg);
  check("multipart LF: 2 parts", tree.parts.length === 2);
  check("multipart LF: part 0",  tree.parts[0].leaf.body.toString().trim() === "aaa");
  check("multipart LF: part 1",  tree.parts[1].leaf.body.toString().trim() === "bbb");
}

// ---- Structural edge cases in the splitter ---------------------------------

function testNoBlankLineSeparator() {
  // No blank-line separator at all: the whole buffer is the header
  // section, the body is empty.
  var tree = b.safeMime.parse("Subject: only-headers");
  check("no-sep: subject parsed", tree.headers.get("subject") === "only-headers");
  check("no-sep: empty body",     tree.leaf.body.length === 0);
}

function testMultipartUnclosedLastPart() {
  // No final "--B--" closing delimiter: the last part stays open and is
  // materialized from its start offset to end-of-buffer.
  var msg = "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nonly-part\r\n";
  var tree = b.safeMime.parse(msg);
  check("unclosed: one part",     tree.parts.length === 1);
  check("unclosed: body captured", tree.parts[0].leaf.body.toString().indexOf("only-part") !== -1);
}

function testMultipartBoundaryNoTrailingNewline() {
  // A boundary line at end-of-buffer with no terminating newline: the
  // line-end scan returns -1 and the split stops cleanly.
  var msg = "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nx\r\n--B";
  var tree = b.safeMime.parse(msg);
  check("no-trailing-nl: at least one part", tree.parts.length >= 1);
  check("no-trailing-nl: first body captured", tree.parts[0].leaf.body.toString().indexOf("x") !== -1);
}

function testMultipartBoundaryShapeMidLine() {
  // A "--B" sequence appearing mid-line (not at a line start) MUST NOT be
  // treated as a boundary delimiter (RFC 2046 §5.1.1). The preamble junk
  // is skipped and only the real line-start boundary splits.
  var msg = "Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
            "preamble--Bjunk\r\n--B\r\nContent-Type: text/plain\r\n\r\nreal\r\n--B--";
  var tree = b.safeMime.parse(msg);
  check("midline-boundary: one real part", tree.parts.length === 1);
  check("midline-boundary: real body",     tree.parts[0].leaf.body.toString().trim() === "real");
}

// ---- Cap / refusal branches not yet exercised ------------------------------

function testRefusesOversizeHeaderSection() {
  expectRefused("refuses header section > maxHeaderBytes",
    function () { b.safeMime.parse("Subject: hello there\r\nContent-Type: text/plain\r\n\r\nbody", { maxHeaderBytes: 5 }); },
    "safe-mime/oversize-headers");
}

function testRefusesOversizeBodyRaw() {
  var body = new Array(101).join("a"); // 100 raw bytes, 7bit (no decode)
  expectRefused("refuses raw body > maxBodyBytes",
    function () { b.safeMime.parse(_msg(["Content-Type: text/plain"], body), { maxBodyBytes: 10 }); },
    "safe-mime/oversize-body");
}

function testRefusesTooManyHeaders() {
  expectRefused("refuses header count > maxHeaderCount (DoS bound)",
    function () { b.safeMime.parse("A: 1\r\nB: 2\r\nC: 3\r\nContent-Type: text/plain\r\n\r\nbody", { maxHeaderCount: 2 }); },
    "safe-mime/too-many-headers");
}

function testRefusesOversizeHeaderLine() {
  var longVal = new Array(60).join("x"); // 59 chars → line well over 10 bytes
  expectRefused("refuses header line > maxHeaderLineBytes (RFC 5322 §2.1.1)",
    function () { b.safeMime.parse("Subject: " + longVal + "\r\n\r\nbody", { maxHeaderLineBytes: 10 }); },
    "safe-mime/oversize-header-line");
}

function testRefusesHeaderMissingColon() {
  // A long (>64 char) header line with no colon: malformed-headers, and
  // the error's byte-preview is truncated with an ellipsis.
  var longNoColon = "ThisIsAHeaderLineWithNoColonAtAllAndItIsDefinitelyLongerThanSixtyFourCharacters";
  var threw = null;
  try { b.safeMime.parse(longNoColon + "\r\nContent-Type: text/plain\r\n\r\nbody"); }
  catch (e) { threw = e; }
  check("missing-colon: refused",             threw && (threw.code || "").indexOf("safe-mime/malformed-headers") !== -1);
  check("missing-colon: preview truncated",   threw && threw.message.indexOf("...") !== -1);
}

function testRefusesMalformedBoundaryGrammar() {
  // A boundary within the length cap but containing a char outside the
  // RFC 2046 §5.1.1 bchars set ("!") must be refused.
  expectRefused("refuses boundary violating RFC 2046 bchars grammar",
    function () { b.safeMime.parse(_msg(["Content-Type: multipart/mixed; boundary=bad!boundary"], "x")); },
    "safe-mime/malformed-boundary");
}

// ---- Content-Type quoted parameter value -----------------------------------

function testQuotedContentTypeParams() {
  var tree = b.safeMime.parse(_msg(["Content-Type: text/plain; charset=\"utf-8\""], "hi"));
  check("quoted param: charset unquoted", tree.leaf.charset === "utf-8");
}

// ---- RFC 2047 encoded-word header injection --------------------------------

function testRefusesRfc2047HeaderInjection() {
  // RFC 2047 §5 — an encoded-word whose decoded bytes carry CR/LF/NUL is a
  // header-injection attempt (a smuggled Bcc:) and must be refused.
  var payload = Buffer.from("\r\nBcc: attacker@evil.example").toString("base64");
  var msg = "Subject: =?utf-8?B?" + payload + "?=\r\nContent-Type: text/plain\r\n\r\nbody";
  expectRefused("refuses RFC 2047 encoded-word header injection",
    function () { b.safeMime.parse(msg); },
    "safe-mime/rfc2047-header-injection");
}

// ---- Charset decoders: utf-16 family + fall-through ------------------------

function testCharsetDecodingBranches() {
  function decodedFor(charset, rawBuf) {
    var tree = b.safeMime.parse(_msg(
      ["Content-Type: text/plain; charset=" + charset, "Content-Transfer-Encoding: base64"],
      rawBuf.toString("base64")));
    return tree.decoded;
  }
  var le = Buffer.from("Hi", "utf16le");        // [0x48,0x00,0x69,0x00]
  var be = Buffer.from(le); be.swap16();        // [0x00,0x48,0x00,0x69] — UTF-16BE
  check("charset utf-16le",                 decodedFor("utf-16le", le) === "Hi");
  check("charset utf-16be",                 decodedFor("utf-16be", be) === "Hi");
  check("charset utf-16 LE BOM",            decodedFor("utf-16", Buffer.concat([Buffer.from([0xff, 0xfe]), le])) === "Hi");
  check("charset utf-16 BE BOM",            decodedFor("utf-16", Buffer.concat([Buffer.from([0xfe, 0xff]), be])) === "Hi");
  check("charset utf-16 no BOM (BE default)", decodedFor("utf-16", be) === "Hi");
  // windows-1252 is allowlisted but has no dedicated decoder branch → the
  // utf-8 fall-through is used.
  check("charset windows-1252 fall-through", decodedFor("windows-1252", Buffer.from("hi", "ascii")) === "hi");
}

// ---- Attachment filename derivation ----------------------------------------

function testRfc2231ExtendedFilename() {
  // RFC 2231 extended-parameter filename*=<charset>'<lang>'<pct-encoded>.
  var msg = [
    "Content-Type: multipart/mixed; boundary=B", "",
    "--B",
    "Content-Type: application/octet-stream",
    "Content-Disposition: attachment; filename*=UTF-8''r%C3%A9port.pdf",
    "Content-Transfer-Encoding: base64", "",
    "AAAA",
    "--B--",
  ].join("\r\n");
  var atts = b.safeMime.extractAttachments(b.safeMime.parse(msg));
  check("rfc2231: filename percent-decoded", atts.length === 1 && atts[0].filename === "réport.pdf");
}

function testFilenameFromContentTypeName() {
  // No filename in Content-Disposition → fall back to the Content-Type
  // name= parameter (quoted form unwrapped).
  var withName = [
    "Content-Type: multipart/mixed; boundary=B", "",
    "--B",
    "Content-Type: application/octet-stream; name=\"doc.bin\"",
    "Content-Disposition: attachment",
    "Content-Transfer-Encoding: base64", "",
    "AAAA",
    "--B--",
  ].join("\r\n");
  var a1 = b.safeMime.extractAttachments(b.safeMime.parse(withName));
  check("name-fallback: quoted name used", a1.length === 1 && a1[0].filename === "doc.bin");

  // Neither filename nor name present → null filename.
  var noName = [
    "Content-Type: multipart/mixed; boundary=B", "",
    "--B",
    "Content-Type: application/octet-stream",
    "Content-Disposition: attachment",
    "Content-Transfer-Encoding: base64", "",
    "AAAA",
    "--B--",
  ].join("\r\n");
  var a2 = b.safeMime.extractAttachments(b.safeMime.parse(noName));
  check("name-fallback: null when neither present", a2.length === 1 && a2[0].filename === null);
}

function testRfc2231MalformedFilenameNoThrow() {
  // A hostile `filename*=<charset>'<lang>'<pct>` whose percent-escape is
  // malformed (truncated `%`, non-hex digits) or decodes to invalid UTF-8
  // must NOT crash extractAttachments with a raw URIError — the parser
  // family's contract is that only typed SafeMimeError escapes, and every
  // other decodeURIComponent site in the framework guards this. Degrade to
  // the still-encoded segment (best-effort; downstream filename guards own
  // the raw form) rather than throwing.
  function attFor(fnParam) {
    var msg = [
      "Content-Type: multipart/mixed; boundary=B", "",
      "--B",
      "Content-Type: application/octet-stream",
      "Content-Disposition: attachment; filename*=" + fnParam,
      "Content-Transfer-Encoding: base64", "",
      "AAAA",
      "--B--",
    ].join("\r\n");
    return b.safeMime.extractAttachments(b.safeMime.parse(msg));
  }
  // Truncated `%` with no following hex — decodeURIComponent throws URIError.
  var a1 = attFor("UTF-8''%");
  check("rfc2231 malformed: truncated % does not crash",
    a1.length === 1 && a1[0].filename === "%");
  // `%ZZ` — non-hex escape digits.
  var a2 = attFor("UTF-8''bad%ZZname.pdf");
  check("rfc2231 malformed: non-hex % escape does not crash",
    a2.length === 1 && a2[0].filename === "bad%ZZname.pdf");
  // `%FF%FE` — well-formed escapes that decode to invalid UTF-8.
  var a3 = attFor("UTF-8''%FF%FE");
  check("rfc2231 malformed: invalid-UTF-8 % escape does not crash",
    a3.length === 1 && a3[0].filename === "%FF%FE");
  // Regression guard — a valid ext-value still percent-decodes.
  var a4 = attFor("UTF-8''r%65port.pdf");
  check("rfc2231 valid: still decodes after guard",
    a4.length === 1 && a4[0].filename === "report.pdf");
}

// ---- Transfer-encoding allowlist edges -------------------------------------

function testCustomTransferEncodingAllowlist() {
  // RFC 3030 BINARYMIME opt-in — "binary" decodes to the raw bytes
  // (identity) once the operator adds it to the allowlist.
  var tree = b.safeMime.parse(
    _msg(["Content-Type: text/plain", "Content-Transfer-Encoding: binary"], "rawbytes"),
    { transferEncodingAllowlist: ["7bit", "binary"] });
  check("binary opt-in: identity decode", tree.leaf.body.toString() === "rawbytes");

  // An encoding allowlisted by the operator but with no decoder branch
  // fails closed at the decoder rather than decoding as something else.
  expectRefused("allowlisted-but-unimplemented encoding fails closed",
    function () { b.safeMime.parse(
      _msg(["Content-Type: text/plain", "Content-Transfer-Encoding: x-uuencode"], "data"),
      { transferEncodingAllowlist: ["7bit", "x-uuencode"] }); },
    "safe-mime/unknown-transfer-encoding");
}

// ---- Charset name normalization aliases ------------------------------------

function testCharsetAliasNormalization() {
  function decodedFor(charset, rawBuf) {
    return b.safeMime.parse(_msg(
      ["Content-Type: text/plain; charset=" + charset, "Content-Transfer-Encoding: base64"],
      rawBuf.toString("base64"))).decoded;
  }
  var ascii = Buffer.from("hey", "ascii");
  check("charset utf8 alias",      decodedFor("utf8", Buffer.from("hi", "utf8")) === "hi");
  check("charset ascii alias",     decodedFor("ascii", ascii) === "hey");
  check("charset latin1 alias",    decodedFor("latin1", ascii) === "hey");
  check("charset cp1252 alias",    decodedFor("cp1252", ascii) === "hey");
  check("charset shift-jis alias", decodedFor("shift-jis", ascii) === "hey");
}

// ---- extractText / extractAttachments option branches ----------------------

function testExtractTextExtraBranches() {
  var altTree = b.safeMime.parse([
    "Content-Type: multipart/alternative; boundary=A", "",
    "--A", "Content-Type: text/plain", "", "P",
    "--A", "Content-Type: text/html", "", "<p>H</p>",
    "--A--",
  ].join("\r\n"));
  // No opts argument → prefer defaults to "plain".
  var d = b.safeMime.extractText(altTree);
  check("extractText: default prefer=plain", d && d.contentType === "text/plain");
  // prefer=any on multipart/alternative → last-wins picks the last text/*.
  var anyPick = b.safeMime.extractText(altTree, { prefer: "any" });
  check("extractText: prefer any picks last text/*", anyPick && anyPick.contentType === "text/html");

  // Non-alternative tree, prefer=html → the html arm of the findFirst.
  var mixedHtml = b.safeMime.parse([
    "Content-Type: multipart/mixed; boundary=M", "",
    "--M", "Content-Type: text/plain", "", "p",
    "--M", "Content-Type: text/html", "", "<b>h</b>",
    "--M--",
  ].join("\r\n"));
  var h = b.safeMime.extractText(mixedHtml, { prefer: "html" });
  check("extractText: non-alt prefer html", h && h.contentType === "text/html");

  // multipart/alternative whose FIRST child is itself a multipart (no
  // leaf): the reverse last-wins loop visits the non-leaf child and skips
  // it before matching the text/plain sibling.
  var altNested = b.safeMime.parse([
    "Content-Type: multipart/alternative; boundary=A", "",
    "--A", "Content-Type: text/plain", "", "outer",
    "--A", "Content-Type: multipart/mixed; boundary=N", "",
    "--N", "Content-Type: text/plain", "", "inner", "--N--",
    "--A--",
  ].join("\r\n"));
  var nested = b.safeMime.extractText(altNested, { prefer: "plain" });
  check("extractText: skips non-leaf alt child", nested && nested.body.trim() === "outer");
}

function testExtractAttachmentsInline() {
  var msg = [
    "Content-Type: multipart/mixed; boundary=B", "",
    "--B", "Content-Type: text/plain", "Content-Disposition: inline", "", "inline-body",
    "--B", "Content-Type: application/pdf", "Content-Disposition: attachment; filename=a.pdf",
    "Content-Transfer-Encoding: base64", "", "AAAA",
    "--B--",
  ].join("\r\n");
  var tree = b.safeMime.parse(msg);
  // Default excludes inline parts.
  var d = b.safeMime.extractAttachments(tree);
  check("attachments: inline excluded by default", d.length === 1 && d[0].filename === "a.pdf");
  // includeInline:true pulls inline in alongside the attachment.
  var w = b.safeMime.extractAttachments(tree, { includeInline: true });
  check("attachments: includeInline pulls inline too", w.length === 2);
}

// ---- Header accessor + input-shape branches --------------------------------

function testHeaderGetAllMissing() {
  var tree = b.safeMime.parse(_msg(["Content-Type: text/plain"], "x"));
  check("getAll missing header → empty array", tree.headers.getAll("x-absent").length === 0);
}

function testUint8ArrayInput() {
  var bytes = new Uint8Array(Buffer.from(_msg(["Content-Type: text/plain"], "u8")));
  var tree = b.safeMime.parse(bytes);
  check("Uint8Array input parsed", tree.leaf.body.toString() === "u8");
}

function testShortMalformedHeaderPreview() {
  // A short (<64 char) header line with no colon: refused, and the
  // byte-preview is returned untruncated (no ellipsis).
  var threw = null;
  try { b.safeMime.parse("nocolon\r\nContent-Type: text/plain\r\n\r\nbody"); }
  catch (e) { threw = e; }
  check("short missing-colon: refused",       threw && (threw.code || "").indexOf("safe-mime/malformed-headers") !== -1);
  check("short missing-colon: no ellipsis",   threw && threw.message.indexOf("...") === -1);
}

// ---- Boundary grammar first/last-char rejection ----------------------------

function testBoundaryInvalidFirstLastChar() {
  // Quoted boundary whose FIRST char is outside bcharsnospace.
  expectRefused("boundary invalid first char refused",
    function () { b.safeMime.parse(_msg(["Content-Type: multipart/mixed; boundary=\"!bad\""], "x")); },
    "safe-mime/malformed-boundary");
  // Quoted boundary whose LAST char is outside bcharsnospace.
  expectRefused("boundary invalid last char refused",
    function () { b.safeMime.parse(_msg(["Content-Type: multipart/mixed; boundary=\"bad!\""], "x")); },
    "safe-mime/malformed-boundary");
}

// ---- Content-Type poisoned parameter key -----------------------------------

function testContentTypePoisonedParamSkipped() {
  var tree = b.safeMime.parse(_msg(["Content-Type: text/plain; __proto__=x; charset=utf-8"], "hi"));
  check("ct poisoned param skipped", tree.leaf.charset === "utf-8" && ({}).x === undefined);
}

// ---- Malformed multipart bodies: empty-part slice clamps -------------------

function testMultipartEmptyPartClampsSlice() {
  // A part opening immediately followed by the FINAL boundary (no body
  // bytes between) clamps to a well-formed zero-length slice (RFC 2046
  // §5.1.1 malformed-body handling).
  var tree = b.safeMime.parse("Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n--B--");
  check("empty-part clamp: one part",   tree.parts.length === 1);
  check("empty-part clamp: empty body", tree.parts[0].leaf.body.length === 0);
}

function testMultipartEmptyInteriorPartClamps() {
  // A part opening immediately followed by a NON-final boundary clamps the
  // same way, then a real second part follows.
  var tree = b.safeMime.parse(
    "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n--B\r\nContent-Type: text/plain\r\n\r\nsecond\r\n--B--");
  check("interior clamp: 2 parts",       tree.parts.length === 2);
  check("interior clamp: first empty",   tree.parts[0].leaf.body.length === 0);
  check("interior clamp: second body",   tree.parts[1].leaf.body.toString().trim() === "second");
}

// ---- extractText on a null/absent tree -------------------------------------

function testExtractTextNullTree() {
  // extractText is commonly called on the result of a lookup that may be
  // absent; a falsy tree must return null (not throw). Drives the
  // `tree &&` short-circuit false arm plus the findFirst(null) → walk(null)
  // no-op path.
  check("extractText: null tree returns null",      b.safeMime.extractText(null) === null);
  check("extractText: undefined tree returns null", b.safeMime.extractText(undefined) === null);
  check("extractText: null tree prefer=html null",  b.safeMime.extractText(null, { prefer: "html" }) === null);
}

// ---- RFC 2046 §5.1.1 70-char boundary hard cap -----------------------------

function testBoundaryHardCapIndependentOfMaxBoundary() {
  // The RFC 2046 §5.1.1 70-char boundary ceiling is enforced by the grammar
  // validator itself, independent of the tunable `maxBoundary` opt. Raising
  // maxBoundary above 70 does NOT permit a >70-char boundary: a 71-char
  // otherwise-valid boundary still refuses as malformed. maxBoundary can
  // only tighten the cap below 70, never loosen the RFC hard ceiling.
  var boundary71 = new Array(72).join("a"); // 71 chars, all valid bchars
  check("boundary71 is 71 chars", boundary71.length === 71);
  expectRefused("71-char boundary refused even with maxBoundary raised to 200 (RFC 2046 §5.1.1 hard cap)",
    function () {
      b.safeMime.parse(
        _msg(["Content-Type: multipart/mixed; boundary=" + boundary71], "x"),
        { maxBoundary: 200 });
    },
    "safe-mime/malformed-boundary");
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
  testWalkAndFindFirstGuards();
  testExtractTextNonAlternativePaths();
  testExtractTextAlternativeFallback();
  testLfOnlyLineEndings();
  testMultipartLfLineEndings();
  testNoBlankLineSeparator();
  testMultipartUnclosedLastPart();
  testMultipartBoundaryNoTrailingNewline();
  testMultipartBoundaryShapeMidLine();
  testRefusesOversizeHeaderSection();
  testRefusesOversizeBodyRaw();
  testRefusesTooManyHeaders();
  testRefusesOversizeHeaderLine();
  testRefusesHeaderMissingColon();
  testRefusesMalformedBoundaryGrammar();
  testQuotedContentTypeParams();
  testRefusesRfc2047HeaderInjection();
  testCharsetDecodingBranches();
  testRfc2231ExtendedFilename();
  testFilenameFromContentTypeName();
  testRfc2231MalformedFilenameNoThrow();
  testCustomTransferEncodingAllowlist();
  testCharsetAliasNormalization();
  testExtractTextExtraBranches();
  testExtractAttachmentsInline();
  testHeaderGetAllMissing();
  testUint8ArrayInput();
  testShortMalformedHeaderPreview();
  testBoundaryInvalidFirstLastChar();
  testContentTypePoisonedParamSkipped();
  testMultipartEmptyPartClampsSlice();
  testMultipartEmptyInteriorPartClamps();
  testExtractTextNullTree();
  testBoundaryHardCapIndependentOfMaxBoundary();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

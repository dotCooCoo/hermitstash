// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-markdown — Markdown content-safety primitive (b.guardMarkdown).
 *
 * Covers: surface; registry parity; raw HTML detection; whitespace-tag
 * bypass (CVE-2026-30838); javascript:/data:/vbscript: link schemes;
 * autolink scheme detection; reference-link smuggling; image scheme
 * bypass; HTML-entity scheme decode bypass; HTML comments; front-matter;
 * code-fence language injection; catastrophic emphasis runs; list +
 * blockquote depth caps; bidi/null/control char detection; sanitize
 * discipline; gate composition; profile + posture vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardMarkdownSurface() {
  check("guardMarkdown is an object",                   typeof b.guardMarkdown === "object");
  check("guardMarkdown.NAME === 'markdown'",            b.guardMarkdown.NAME === "markdown");
  check("guardMarkdown.KIND === 'content'",             b.guardMarkdown.KIND === "content");
  check("guardMarkdown.MIME_TYPES has text/markdown",   b.guardMarkdown.MIME_TYPES.indexOf("text/markdown") !== -1);
  check("guardMarkdown.EXTENSIONS has .md",             b.guardMarkdown.EXTENSIONS.indexOf(".md") !== -1);
  check("guardMarkdown.PROFILES has strict",            !!b.guardMarkdown.PROFILES["strict"]);
  check("guardMarkdown.PROFILES has balanced",          !!b.guardMarkdown.PROFILES["balanced"]);
  check("guardMarkdown.PROFILES has permissive",        !!b.guardMarkdown.PROFILES["permissive"]);
  check("guardMarkdown.COMPLIANCE_POSTURES has hipaa",  !!b.guardMarkdown.COMPLIANCE_POSTURES["hipaa"]);
  check("guardMarkdown.validate is a function",         typeof b.guardMarkdown.validate === "function");
  check("guardMarkdown.sanitize is a function",         typeof b.guardMarkdown.sanitize === "function");
  check("guardMarkdown.gate is a function",             typeof b.guardMarkdown.gate === "function");
  check("frameworkError.GuardMarkdownError exposed",    typeof b.frameworkError.GuardMarkdownError === "function");
}

function testGuardMarkdownRegistryParity() {
  check("guardMarkdown registered in guardAll",
        b.guardAll.list().some(function (g) { return g.name === "markdown"; }));
}

function testGuardMarkdownDangerousScheme() {
  var rv = b.guardMarkdown.validate(
    "# x\n\n[click](javascript:alert(1))\n",
    { profile: "strict" });
  check("javascript: link scheme detected (CVE-2025-9540 class)",
        rv.ok === false &&
        rv.issues.some(function (i) { return i.kind === "link-scheme"; }));

  var rvData = b.guardMarkdown.validate(
    "[x](data:text/html,<script>alert(1)</script>)\n",
    { profile: "strict" });
  check("data:text/html link scheme detected",
        rvData.issues.some(function (i) { return i.kind === "link-scheme"; }));

  var rvVbs = b.guardMarkdown.validate(
    "[x](vbscript:msgbox)\n", { profile: "strict" });
  check("vbscript: link scheme detected",
        rvVbs.issues.some(function (i) { return i.kind === "link-scheme"; }));
}

function testGuardMarkdownEntityBypass() {
  // `&#x6A;avascript:` decodes to `javascript:` in the URL — the gate
  // must decode HTML entities before scheme-matching.
  var rv = b.guardMarkdown.validate(
    "[x](&#x6A;avascript:alert(1))\n", { profile: "strict" });
  check("HTML-entity-encoded javascript: scheme detected",
        rv.issues.some(function (i) { return i.kind === "link-scheme"; }));

  var rvDec = b.guardMarkdown.validate(
    "[x](&#106;avascript:alert(1))\n", { profile: "strict" });
  check("decimal-entity javascript: scheme detected",
        rvDec.issues.some(function (i) { return i.kind === "link-scheme"; }));

  // Named entities + entity-encoded leading space: a browser resolves &Tab; /
  // &NewLine; and trims a leading C0-control-or-space run before parsing the URL,
  // so `java&Tab;script:` and `&#32;javascript:` navigate as javascript:. Decoding
  // numeric-only, or not trimming the entity space, let these bypass -> fail-open.
  var mdWs = [
    ["named &Tab;",         "[x](java&Tab;script:alert(1))"],
    ["named &NewLine;",     "[x](java&NewLine;script:alert(1))"],
    ["entity space &#32;",  "[x](&#32;javascript:alert(1))"],
    ["entity space &#x20;", "[x](&#x20;javascript:alert(1))"],
  ];
  for (var w = 0; w < mdWs.length; w++) {
    var rvW = b.guardMarkdown.validate(mdWs[w][1], { profile: "strict" });
    check("markdown whitespace/entity-hidden scheme (" + mdWs[w][0] + ") detected",
          rvW.issues.some(function (i) { return i.kind === "link-scheme"; }));
  }
}

function testGuardMarkdownAutolinkScheme() {
  var rv = b.guardMarkdown.validate(
    "<javascript:alert(1)>\n", { profile: "strict" });
  check("autolink javascript: scheme detected (NuGetGallery / MDC class)",
        rv.issues.some(function (i) { return i.kind === "autolink-scheme"; }));
}

function testGuardMarkdownReferenceLinkSmuggling() {
  var rv = b.guardMarkdown.validate(
    "[click][ref]\n\n[ref]: javascript:alert(1)\n",
    { profile: "strict" });
  check("reference-link definition with javascript: detected",
        rv.issues.some(function (i) { return i.kind === "reference-link-scheme"; }));
}

function testGuardMarkdownImageScheme() {
  var rv = b.guardMarkdown.validate(
    "![alt](javascript:alert(1))\n", { profile: "strict" });
  check("image with javascript: scheme detected",
        rv.issues.some(function (i) { return i.kind === "image-scheme"; }));
}

function testGuardMarkdownDangerousTag() {
  var rv = b.guardMarkdown.validate(
    "<script>alert(1)</script>\n", { profile: "strict" });
  check("raw <script> tag detected",
        rv.issues.some(function (i) { return i.kind === "dangerous-tag"; }));
}

function testGuardMarkdownWhitespaceTagBypass() {
  // CVE-2026-30838 — naive `<script>` matchers miss `<script\n>`.
  var rv = b.guardMarkdown.validate(
    "<script\n>alert(1)</script>\n", { profile: "strict" });
  check("whitespace-tolerant <script\\n> bypass detected (CVE-2026-30838)",
        rv.issues.some(function (i) { return i.kind === "dangerous-tag"; }));

  var rvTab = b.guardMarkdown.validate(
    "<\tiframe src=x>\n", { profile: "strict" });
  check("leading-whitespace <\\tiframe> bypass detected",
        rvTab.issues.some(function (i) { return i.kind === "dangerous-tag"; }));
}

function testGuardMarkdownHtmlComment() {
  var rv = b.guardMarkdown.validate(
    "Some text <!-- payload --> more.\n", { profile: "strict" });
  check("HTML comment block detected",
        rv.issues.some(function (i) { return i.kind === "html-comment"; }));
}

function testGuardMarkdownFrontMatter() {
  var rv = b.guardMarkdown.validate(
    "---\ntitle: x\n---\n\n# Body\n", { profile: "strict" });
  check("YAML front-matter detected",
        rv.issues.some(function (i) { return i.kind === "front-matter"; }));

  var rvToml = b.guardMarkdown.validate(
    "+++\ntitle = \"x\"\n+++\n\n# Body\n", { profile: "strict" });
  check("TOML front-matter detected",
        rvToml.issues.some(function (i) { return i.kind === "front-matter"; }));
}

function testGuardMarkdownCodeFenceLang() {
  var rv = b.guardMarkdown.validate(
    "```\"><script>alert(1)</script>\nx\n```\n", { profile: "strict" });
  check("code-fence language tag with attribute-breaking chars detected",
        rv.issues.some(function (i) { return i.kind === "code-fence-lang"; }));
}

function testGuardMarkdownEmphasisRun() {
  var rv = b.guardMarkdown.validate(
    "x" + new Array(50).join("*") + "y\n", { profile: "strict" });
  check("catastrophic emphasis run detected (CVE-2025-6493 class)",
        rv.issues.some(function (i) { return i.kind === "emphasis-run"; }));
}

function testGuardMarkdownDoctype() {
  var rv = b.guardMarkdown.validate(
    "<!DOCTYPE html>\n# x\n", { profile: "strict" });
  check("inline DOCTYPE detected",
        rv.issues.some(function (i) { return i.kind === "doctype"; }));
}

function testGuardMarkdownBidiNull() {
  var bidi = String.fromCharCode(0x202E);
  var rv = b.guardMarkdown.validate(
    "# t\n\nhello" + bidi + "world\n", { profile: "strict" });
  check("bidi override detected",
        rv.issues.some(function (i) { return i.kind === "bidi-override"; }));

  var nb = String.fromCharCode(0);
  var rvNull = b.guardMarkdown.validate(
    "# t\n\nhello" + nb + "world\n", { profile: "strict" });
  check("null byte detected",
        rvNull.issues.some(function (i) { return i.kind === "null-byte"; }));
}

function testGuardMarkdownClean() {
  var rv = b.guardMarkdown.validate(
    "# Title\n\nA [link](https://example.com) and *emphasis*.\n",
    { profile: "strict" });
  check("clean markdown → ok=true with no issues",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardMarkdownLinkCap() {
  var src = "# x\n";
  for (var i = 0; i < 300; i++) src += "[a](https://x.com)\n";
  var rv = b.guardMarkdown.validate(src, { profile: "strict" });
  check("link cap detected (strict maxLinks 256)",
        rv.issues.some(function (i) { return i.kind === "link-cap"; }));
}

function testGuardMarkdownListDepthCap() {
  var src = "# x\n";
  for (var i = 0; i < 20; i++) {
    src += new Array(i * 2 + 1).join(" ") + "- item\n";
  }
  var rv = b.guardMarkdown.validate(src, { profile: "strict" });
  check("list depth cap detected (strict maxListDepth 16)",
        rv.issues.some(function (i) { return i.kind === "list-depth-cap"; }));
}

function testGuardMarkdownBlockquoteDepthCap() {
  var src = "# x\n" + new Array(20).join(">") + " deeply quoted\n";
  var rv = b.guardMarkdown.validate(src, { profile: "strict" });
  check("blockquote depth cap detected (strict maxBlockquoteDepth 16)",
        rv.issues.some(function (i) { return i.kind === "blockquote-depth-cap"; }));
}

function testGuardMarkdownByteCap() {
  // maxBytes is a BYTE limit. A multibyte string can stay under the cap by
  // UTF-16 code-unit count (.length) while its UTF-8 encoding blows past it,
  // so the cap must measure Buffer.byteLength, never .length. "é" (U+00E9)
  // is 1 code unit but 2 UTF-8 bytes: 8 of them = .length 8 (under a 10-byte
  // cap by char count) yet 16 bytes (over it).
  var multibyte = "é".repeat(8);
  check("multibyte input is 8 UTF-16 units but 16 UTF-8 bytes",
        multibyte.length === 8 && Buffer.byteLength(multibyte, "utf8") === 16);

  var rvOver = b.guardMarkdown.validate(multibyte, { maxBytes: 10 });
  var cap = rvOver.issues.filter(function (i) { return i.kind === "too-large"; });
  check("multibyte over the BYTE cap fires too-large (not char-count-gated)",
        cap.length === 1);
  check("too-large snippet reports the BYTE length, not the char count",
        cap.length === 1 && /16 bytes exceeds maxBytes 10/.test(cap[0].snippet));
  check("too-large carries ruleId markdown.too-large",
        cap.length === 1 && cap[0].ruleId === "markdown.too-large");

  // ASCII is unaffected: byte length equals char length, so the cap behaves
  // identically before and after the fix.
  var rvAsciiUnder = b.guardMarkdown.validate("aaaaaaaa", { maxBytes: 10 });
  check("ASCII under the byte cap → no too-large",
        !rvAsciiUnder.issues.some(function (i) { return i.kind === "too-large"; }));
  var rvAsciiOver = b.guardMarkdown.validate("aaaaaaaaaaaaaaaa", { maxBytes: 10 });
  check("ASCII over the byte cap → too-large still fires",
        rvAsciiOver.issues.some(function (i) { return i.kind === "too-large"; }));
}

function testGuardMarkdownSanitizeRefusesCritical() {
  var threw = null;
  try { b.guardMarkdown.sanitize(
    "[x](javascript:alert(1))\n", { profile: "balanced" }); }
  catch (e) { threw = e; }
  check("sanitize refuses javascript: link (no safe sanitization)",
        threw && /scheme|refused/.test(threw.code || threw.message || ""));
}

function testGuardMarkdownSanitizeRefusesBadInput() {
  // A non-string/Buffer sanitize input is unprocessable — it must throw a typed
  // markdown.bad-input, NEVER silently return the garbage. (sanitizeSeverities
  // is ["critical"], so the high-severity bad-input issue is not a content
  // refusal; the generated sanitize refuses a `bad-input` KIND unconditionally.)
  [123, null, {}, [1, 2, 3], true].forEach(function (bad) {
    var threw = null;
    try { b.guardMarkdown.sanitize(bad, { profile: "strict" }); }
    catch (e) { threw = e; }
    check("sanitize(" + JSON.stringify(bad) + ") throws markdown.bad-input (no silent pass)",
          threw && threw.code === "markdown.bad-input");
  });
}

async function testGuardMarkdownGate() {
  var g = b.guardMarkdown.gate({ profile: "strict" });
  var clean = await g.check({
    contentType: "text/markdown",
    bytes:       Buffer.from("# t\n\nhello [w](https://w.com)\n", "utf8"),
  });
  check("gate clean → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({
    contentType: "text/markdown",
    bytes:       Buffer.from("# x\n\n[click](javascript:alert(1))\n", "utf8"),
  });
  check("gate javascript: link → action !== serve",
        hostile.action !== "serve");
}

function testGuardMarkdownCompliancePosture() {
  var hipaa = b.guardMarkdown.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.dangerousTagPolicy === "reject" &&
        hipaa.dangerousSchemePolicy === "reject");
  var threw = null;
  try { b.guardMarkdown.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

async function run() {
  testGuardMarkdownSurface();
  testGuardMarkdownRegistryParity();
  testGuardMarkdownDangerousScheme();
  testGuardMarkdownEntityBypass();
  testGuardMarkdownAutolinkScheme();
  testGuardMarkdownReferenceLinkSmuggling();
  testGuardMarkdownImageScheme();
  testGuardMarkdownDangerousTag();
  testGuardMarkdownWhitespaceTagBypass();
  testGuardMarkdownHtmlComment();
  testGuardMarkdownFrontMatter();
  testGuardMarkdownCodeFenceLang();
  testGuardMarkdownEmphasisRun();
  testGuardMarkdownDoctype();
  testGuardMarkdownBidiNull();
  testGuardMarkdownClean();
  testGuardMarkdownLinkCap();
  testGuardMarkdownListDepthCap();
  testGuardMarkdownBlockquoteDepthCap();
  testGuardMarkdownByteCap();
  testGuardMarkdownSanitizeRefusesCritical();
  testGuardMarkdownSanitizeRefusesBadInput();
  testGuardMarkdownCompliancePosture();
  await testGuardMarkdownGate();
}

module.exports = { run: run };

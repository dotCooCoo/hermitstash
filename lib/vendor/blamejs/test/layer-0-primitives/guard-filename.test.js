"use strict";
/**
 * guard-filename — filename content-safety primitive (b.guardFilename).
 *
 * Covers: surface; path traversal (raw + percent-encoded + double-
 * encoded + UTF-8 overlong); null-byte truncation; Windows reserved
 * device names (CON / PRN / AUX / NUL / COM1-9 / LPT1-9, with and
 * without extensions); NTFS alternate data streams; leading/trailing
 * whitespace + trailing dots; bidi / RTLO file-name spoofing; zero-
 * width chars; homoglyph mixing; reserved characters; UNC paths; length
 * caps; multi-dot / single-dot policy; extension allowlist; shell-
 * shortcut + executable extension detection; double-extension bypass;
 * sanitize round-trip; gate decision shapes; profile + posture
 * vocabulary.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testGuardFilenameSurface() {
  check("guardFilename is an object",                typeof b.guardFilename === "object");
  check("guardFilename.NAME === 'filename'",         b.guardFilename.NAME === "filename");
  check("guardFilename.PROFILES has strict",         !!b.guardFilename.PROFILES["strict"]);
  check("guardFilename.PROFILES has balanced",       !!b.guardFilename.PROFILES["balanced"]);
  check("guardFilename.PROFILES has permissive",     !!b.guardFilename.PROFILES["permissive"]);
  check("guardFilename.COMPLIANCE_POSTURES has hipaa", !!b.guardFilename.COMPLIANCE_POSTURES["hipaa"]);
  check("guardFilename.validate is a function",      typeof b.guardFilename.validate === "function");
  check("guardFilename.sanitize is a function",      typeof b.guardFilename.sanitize === "function");
  check("guardFilename.gate is a function",          typeof b.guardFilename.gate === "function");
  check("guardFilename.GuardFilenameError is a function",
        typeof b.guardFilename.GuardFilenameError === "function");
  check("frameworkError.GuardFilenameError exposed",
        typeof b.frameworkError.GuardFilenameError === "function");
}

function testGuardFilenameStandalonePrimitive() {
  // guard-filename is intentionally a STANDALONE primitive — it does
  // NOT register into b.guardAll's content-type-routed dispatch. It
  // operates on filename strings, not content bytes; operators wire it
  // separately via b.fileUpload's filenameSafety opt.
  check("guardFilename NOT in guardAll registry",
        !b.guardAll.list().some(function (g) { return g.name === "filename"; }));
}

function testGuardFilenamePathTraversal() {
  var inputs = [
    "../etc/passwd",
    "..\\windows\\system32",
    "subdir/../../etc/shadow",
    "..",
    ".",
  ];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardFilename.validate(inputs[i], { profile: "strict" });
    check("path traversal rejected: " + JSON.stringify(inputs[i]),
          rv.ok === false &&
          rv.issues.some(function (issue) {
            return issue.kind === "path-traversal" ||
                   issue.kind === "path-separator-in-leaf" ||
                   issue.kind === "dot-leaf";
          }));
  }
}

function testGuardFilenamePercentEncodedTraversal() {
  var inputs = [
    "%2e%2e%2fpasswd",
    "%252e%252e%252fpasswd",
    "%c0%aepasswd",     // overlong UTF-8 of dot
  ];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardFilename.validate(inputs[i], { profile: "strict" });
    check("percent-encoded traversal detected: " + JSON.stringify(inputs[i]),
          rv.issues.some(function (issue) {
            return issue.kind === "path-traversal-encoded" ||
                   issue.kind === "url-encoded-separator";
          }));
  }
}

function testGuardFilenameNullByte() {
  var nb = String.fromCharCode(0);
  var rv = b.guardFilename.validate("file.txt" + nb + ".exe", { profile: "strict" });
  check("null byte truncation detected",
        rv.ok === false &&
        rv.issues.some(function (issue) { return issue.kind === "null-byte"; }));
}

function testGuardFilenameWindowsReservedNames() {
  var names = ["CON", "PRN", "AUX", "NUL",
               "COM1", "COM9", "LPT1", "LPT9",
               "con.txt", "PRN.log", "aux.dat", "Nul.bin"];
  for (var i = 0; i < names.length; i++) {
    var rv = b.guardFilename.validate(names[i], { profile: "strict" });
    check("Windows reserved name " + JSON.stringify(names[i]) + " rejected",
          rv.ok === false &&
          rv.issues.some(function (issue) { return issue.kind === "reserved-name"; }));
  }
}

function testGuardFilenameNtfsAds() {
  var rv = b.guardFilename.validate("file.txt:hidden.exe", { profile: "strict" });
  check("NTFS alternate data stream detected",
        rv.issues.some(function (issue) { return issue.kind === "ntfs-ads"; }));
}

function testGuardFilenameLeadingTrailing() {
  var inputs = [" leading.txt", "trailing.txt ", "trailing.txt.",
                "  multiple  .txt"];
  for (var i = 0; i < inputs.length; i++) {
    var rv = b.guardFilename.validate(inputs[i], { profile: "strict" });
    check("leading/trailing rejected: " + JSON.stringify(inputs[i]),
          rv.issues.some(function (issue) {
            return issue.kind === "leading-trailing-strip";
          }));
  }
}

function testGuardFilenameBidiRtlo() {
  // U+202E RLO + made-up extension swap. Memento-RTLO weaponized shape.
  var rtlo = String.fromCharCode(0x202E);
  var rv = b.guardFilename.validate("Photo01By" + rtlo + "gpj.SCR",
                                    { profile: "strict" });
  check("bidi RTLO file-name spoofing detected",
        rv.ok === false &&
        rv.issues.some(function (issue) { return issue.kind === "bidi-override"; }));
}

function testGuardFilenameReservedChars() {
  var chars = ["<", ">", ":", "\"", "|", "?", "*"];
  for (var i = 0; i < chars.length; i++) {
    var rv = b.guardFilename.validate("file" + chars[i] + "name.txt",
                                      { profile: "strict" });
    check("reserved char " + JSON.stringify(chars[i]) + " detected",
          rv.issues.some(function (issue) { return issue.kind === "reserved-char"; }));
  }
}

function testGuardFilenameUncPath() {
  var rv = b.guardFilename.validate("\\\\server\\share\\file.txt",
                                    { profile: "strict" });
  check("UNC path detected",
        rv.ok === false &&
        rv.issues.some(function (issue) { return issue.kind === "unc-path"; }));
}

function testGuardFilenamePathSeparatorsInLeaf() {
  var rv1 = b.guardFilename.validate("subdir/file.txt", { profile: "strict" });
  check("forward-slash in leaf detected (strict)",
        rv1.issues.some(function (issue) {
          return issue.kind === "path-separator-in-leaf" ||
                 issue.kind === "reserved-char";
        }));

  var rv2 = b.guardFilename.validate("subdir\\file.txt", { profile: "strict" });
  check("backslash in leaf detected (strict)",
        rv2.issues.some(function (issue) {
          return issue.kind === "path-separator-in-leaf" ||
                 issue.kind === "reserved-char";
        }));
}

function testGuardFilenameLengthCap() {
  var long = "x".repeat(100) + ".txt";
  var rv = b.guardFilename.validate(long, { profile: "strict" });
  check("length-cap (strict 64-byte) detected",
        rv.issues.some(function (issue) { return issue.kind === "too-long"; }));
}

function testGuardFilenameSingleDotPolicy() {
  var rv = b.guardFilename.validate("archive.tar.gz", { profile: "strict" });
  check("multi-dot detected under strict",
        rv.issues.some(function (issue) { return issue.kind === "multiple-dots"; }));

  var rv2 = b.guardFilename.validate("archive.tar.gz", { profile: "balanced" });
  check("multi-dot allowed under balanced",
        !rv2.issues.some(function (issue) { return issue.kind === "multiple-dots"; }));
}

function testGuardFilenameExtensionAllowlist() {
  var rv = b.guardFilename.validate("photo.gif", {
    profile:            "balanced",
    extensionAllowlist: [".png", ".jpg", ".jpeg"],
  });
  check("ext allowlist: gif rejected when only png/jpg allowed",
        rv.issues.some(function (issue) { return issue.kind === "ext-not-allowlisted"; }));

  var rv2 = b.guardFilename.validate("photo.png", {
    profile:            "balanced",
    extensionAllowlist: [".png", ".jpg", ".jpeg"],
  });
  check("ext allowlist: png accepted",
        !rv2.issues.some(function (issue) { return issue.kind === "ext-not-allowlisted"; }));
}

function testGuardFilenameShellExecExt() {
  var exts = [".exe", ".bat", ".cmd", ".vbs", ".scr", ".lnk", ".js",
              ".ps1", ".dll", ".so", ".dmg"];
  for (var i = 0; i < exts.length; i++) {
    var rv = b.guardFilename.validate("file" + exts[i], { profile: "strict" });
    check("shell-exec ext " + JSON.stringify(exts[i]) + " detected",
          rv.issues.some(function (issue) { return issue.kind === "shell-exec-ext"; }));
  }
}

function testGuardFilenameDoubleExtension() {
  var rv = b.guardFilename.validate("invoice.pdf.exe", { profile: "balanced" });
  check("double-extension with executable last-segment detected",
        rv.issues.some(function (issue) { return issue.kind === "double-extension"; }));
}

function testGuardFilenameOverlongUtf8() {
  // 0xC0 0xAE encodes `.` via non-shortest UTF-8 (RFC 3629 §3 prohibits).
  var buf = Buffer.from([0xC0, 0xAE, 0x66, 0x69, 0x6C, 0x65]);
  var rv = b.guardFilename.validate(buf, { profile: "strict" });
  check("overlong UTF-8 detected at buffer level",
        rv.ok === false &&
        rv.issues.some(function (issue) { return issue.kind === "overlong-utf8"; }));
}

function testGuardFilenameAsciiOnlyStrict() {
  var rv = b.guardFilename.validate("café.txt", { profile: "strict" });
  check("strict requireAscii: non-ASCII detected",
        rv.issues.some(function (issue) { return issue.kind === "non-ascii"; }));

  var rv2 = b.guardFilename.validate("café.txt", { profile: "balanced" });
  check("balanced allows non-ASCII",
        !rv2.issues.some(function (issue) { return issue.kind === "non-ascii"; }));
}

function testGuardFilenameClean() {
  var rv = b.guardFilename.validate("safe.txt", { profile: "strict" });
  check("clean filename → ok=true with no issues", rv.ok === true && rv.issues.length === 0);
}

function testGuardFilenameSanitize() {
  var clean = b.guardFilename.sanitize("  weird name.txt.  ", { profile: "balanced" });
  check("sanitize strips leading/trailing whitespace + trailing dot",
        clean === "weird name.txt");

  var threwTraversal = null;
  try { b.guardFilename.sanitize("../etc/passwd", { profile: "balanced" }); }
  catch (e) { threwTraversal = e; }
  check("sanitize refuses path traversal even with sanitize requested",
        threwTraversal && /traversal/.test(threwTraversal.message));

  var threwNullByte = null;
  try { b.guardFilename.sanitize("file" + String.fromCharCode(0) + ".exe",
                                 { profile: "strict" }); }
  catch (e) { threwNullByte = e; }
  check("sanitize refuses null-byte truncation",
        threwNullByte && /null/.test(threwNullByte.message));
}

async function testGuardFilenameGate() {
  var g = b.guardFilename.gate({ profile: "strict" });
  var clean = await g.check({ filename: "report.txt" });
  check("gate: clean filename → action=serve",
        clean.ok === true && clean.action === "serve");

  var hostile = await g.check({ filename: "../etc/passwd" });
  check("gate: traversal → action !== serve",
        hostile.action !== "serve");

  var nb = await g.check({ filename: "file.txt" + String.fromCharCode(0) + ".exe" });
  check("gate: null byte → action !== serve",
        nb.action !== "serve");
}

function testGuardFilenameSanitizeStripMode() {
  // Control char (CR) replaced with "_" — operator wants to put the
  // sanitized name into a Content-Disposition header where CR/LF would
  // enable response splitting. Default mode would throw; strip mode
  // returns a usable string.
  var crName = "report" + String.fromCharCode(0x0D) + ".txt";
  var stripped = b.guardFilename.sanitize(crName, { mode: "strip", profile: "balanced" });
  check("strip mode: CR replaced with underscore",
        stripped === "report_.txt");

  // Bidi RTLO replaced.
  var rtlo = "file" + String.fromCharCode(0x202E) + "txt.exe";
  var rtloStripped = b.guardFilename.sanitize(rtlo, { mode: "strip", profile: "balanced" });
  check("strip mode: RTLO bidi replaced with underscore",
        rtloStripped.indexOf(String.fromCharCode(0x202E)) === -1 &&
        rtloStripped.indexOf("_") !== -1);

  // Zero-width also stripped.
  var zw = "ab" + String.fromCharCode(0x200B) + "cd.txt";
  var zwStripped = b.guardFilename.sanitize(zw, { mode: "strip", profile: "balanced" });
  check("strip mode: zero-width replaced",
        zwStripped.indexOf(String.fromCharCode(0x200B)) === -1);

  // Path traversal STILL throws even in strip mode (security floor).
  var threwTraversal = null;
  try { b.guardFilename.sanitize("../etc/passwd", { mode: "strip", profile: "balanced" }); }
  catch (e) { threwTraversal = e; }
  check("strip mode: path traversal still throws",
        threwTraversal && /traversal/.test(threwTraversal.message));

  // Null-byte STILL throws.
  var threwNull = null;
  try { b.guardFilename.sanitize("file" + String.fromCharCode(0) + ".exe",
                                  { mode: "strip", profile: "balanced" }); }
  catch (e) { threwNull = e; }
  check("strip mode: null byte still throws",
        threwNull && /null/.test(threwNull.message));

  // UNC path STILL throws.
  var threwUnc = null;
  try { b.guardFilename.sanitize("\\\\server\\share\\file.txt",
                                  { mode: "strip", profile: "balanced" }); }
  catch (e) { threwUnc = e; }
  check("strip mode: UNC path still throws",
        threwUnc && /UNC/i.test(threwUnc.message));

  // NTFS ADS STILL throws.
  var threwAds = null;
  try { b.guardFilename.sanitize("file.txt:hidden.exe",
                                  { mode: "strip", profile: "balanced" }); }
  catch (e) { threwAds = e; }
  check("strip mode: NTFS ADS still throws",
        threwAds && /ADS|alternate data stream/i.test(threwAds.message));

  // Audit emit observed.
  var captured = [];
  var fakeAudit = {
    safeEmit: function (event) { captured.push(event); },
  };
  b.guardFilename.sanitize(crName, { mode: "strip", profile: "balanced", audit: fakeAudit });
  check("strip mode: audit emits guardfilename.sanitize.stripped",
        captured.length === 1 && captured[0].action === "guardfilename.sanitize.stripped" &&
        captured[0].outcome === "success");
}

function testGuardFilenameCompliancePosture() {
  var hipaa = b.guardFilename.compliancePosture("hipaa");
  check("compliancePosture('hipaa') sets reject policies",
        hipaa.bidiPolicy === "reject" &&
        hipaa.traversalPolicy === "reject" &&
        hipaa.shellExecExtPolicy === "reject");

  var threw = null;
  try { b.guardFilename.compliancePosture("unknown"); }
  catch (e) { threw = e; }
  check("compliancePosture: unknown name throws",
        threw && /unknown/.test(threw.message));
}

function testGuardFilenameBadProfile() {
  var threw = null;
  try { b.guardFilename.validate("x.txt", { profile: "made-up" }); }
  catch (e) { threw = e; }
  check("validate: unknown profile throws",
        threw && /unknown profile/i.test(threw.message));
}

async function run() {
  testGuardFilenameSurface();
  testGuardFilenameStandalonePrimitive();
  testGuardFilenamePathTraversal();
  testGuardFilenamePercentEncodedTraversal();
  testGuardFilenameNullByte();
  testGuardFilenameWindowsReservedNames();
  testGuardFilenameNtfsAds();
  testGuardFilenameLeadingTrailing();
  testGuardFilenameBidiRtlo();
  testGuardFilenameReservedChars();
  testGuardFilenameUncPath();
  testGuardFilenamePathSeparatorsInLeaf();
  testGuardFilenameLengthCap();
  testGuardFilenameSingleDotPolicy();
  testGuardFilenameExtensionAllowlist();
  testGuardFilenameShellExecExt();
  testGuardFilenameDoubleExtension();
  testGuardFilenameOverlongUtf8();
  testGuardFilenameAsciiOnlyStrict();
  testGuardFilenameClean();
  testGuardFilenameSanitize();
  testGuardFilenameSanitizeStripMode();
  testGuardFilenameCompliancePosture();
  testGuardFilenameBadProfile();
  await testGuardFilenameGate();
}

module.exports = { run: run };

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;

// Small assertion helper for the many "this hostile shape must throw with
// exactly this GuardFilenameError code" cases below. Not a mock — a thin
// try/catch wrapper around the real b.guardFilename call the test drives.
function _expectThrowCode(label, code, fn) {
  var threw = null;
  try { fn(); }
  catch (e) { threw = e; }
  check(label + " throws " + code,
        threw && threw.code === code &&
        threw instanceof b.guardFilename.GuardFilenameError);
}

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

  // v0.15.12 (#78) — reservedCharPolicy:"strip" (set by the permissive profile)
  // must strip EVERY reserved char, not just the first. The old non-global
  // RESERVED_CHARS_RE left the 2nd/3rd path separators in place.
  var multiSep = b.guardFilename.sanitize("a/b/c/d", { profile: "permissive" });
  check("sanitize permissive strips ALL path separators (#78)",
        multiSep.indexOf("/") === -1 && multiSep === "a_b_c_d");
  var multiBack = b.guardFilename.sanitize("x\\y\\z", { profile: "permissive" });
  check("sanitize permissive strips ALL backslashes (#78)", multiBack.indexOf("\\") === -1);
  check("sanitize permissive leaves a clean name unchanged (#78)",
        b.guardFilename.sanitize("clean.txt", { profile: "permissive" }) === "clean.txt");

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

function testGdprPostureMatchesBalancedTier() {
  // gdpr is the balanced tier for a filename guard: it allows non-ASCII
  // (data-minimization keeps the value usable) rather than inheriting the
  // strict tier's requireAscii:true. The drift was a partial gdpr posture
  // object that omitted requireAscii, so resolved opts silently backfilled
  // it from the strict-derived defaults — making gdpr a strict/balanced
  // hybrid. Drive the real consumer path: a non-ASCII leaf must NOT raise
  // a non-ascii issue under gdpr.
  var rv = b.guardFilename.validate("café.txt", { compliancePosture: "gdpr" });
  check("gdpr (balanced tier) does not flag non-ascii on a filename leaf",
        !rv.issues.some(function (issue) { return issue.kind === "non-ascii"; }));

  // The deliberate per-posture overlay survives the routing: gdpr strips
  // bidi / control on leaf names (data-minimization) where the balanced
  // profile would reject them. Both together prove balanced-tier base +
  // intended overlay.
  check("gdpr posture overlay keeps bidiPolicy=strip",
        b.guardFilename.COMPLIANCE_POSTURES.gdpr.bidiPolicy === "strip");
  check("gdpr posture overlay keeps controlPolicy=strip",
        b.guardFilename.COMPLIANCE_POSTURES.gdpr.controlPolicy === "strip");
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

function testGuardFilenameEmptyInput() {
  // Empty string / empty Buffer reach _detectIssues and surface an
  // "empty" issue rather than throwing (validate never throws).
  var rvStr = b.guardFilename.validate("", { profile: "strict" });
  check("validate empty string → empty issue",
        rvStr.ok === false &&
        rvStr.issues.some(function (i) { return i.kind === "empty"; }));

  var rvBuf = b.guardFilename.validate(Buffer.alloc(0), { profile: "strict" });
  check("validate empty Buffer → empty issue",
        rvBuf.issues.some(function (i) { return i.kind === "empty"; }));

  // Non-string / non-Buffer input is rejected by the "bytes" input
  // contract before the detector runs — a bad-input issue, not a crash.
  var rvNum = b.guardFilename.validate(12345, { profile: "strict" });
  check("validate non-string/Buffer → bad-input issue",
        rvNum.ok === false &&
        rvNum.issues.some(function (i) { return i.kind === "bad-input"; }));
}

function testGuardFilenameBenignBufferNoOverlong() {
  // A well-formed UTF-8 Buffer must NOT raise overlong-utf8 — exercises
  // the buffer scan completing without a non-shortest sequence.
  var rv = b.guardFilename.validate(Buffer.from("report-2026.txt", "utf8"),
                                    { profile: "strict" });
  check("benign Buffer → no overlong-utf8 issue",
        !rv.issues.some(function (i) { return i.kind === "overlong-utf8"; }));
  check("benign ASCII Buffer → clean",
        rv.ok === true && rv.issues.length === 0);
}

function testGuardFilenameHomoglyph() {
  // Cyrillic small a (U+0430) mixed with ASCII letters — visual-confusable
  // spoof. Under balanced (homoglyphPolicy:"audit") it surfaces a warn-
  // severity homoglyph issue.
  var cyrA = String.fromCharCode(0x0430);
  var rv = b.guardFilename.validate("p" + cyrA + "ypal.txt", { profile: "balanced" });
  check("balanced: homoglyph mixed with ASCII detected (audit=warn)",
        rv.issues.some(function (i) {
          return i.kind === "homoglyph" && i.severity === "warn";
        }));

  // Under strict (homoglyphPolicy:"reject") the same char is critical.
  var rvStrict = b.guardFilename.validate("p" + cyrA + "ypal.txt", { profile: "strict" });
  check("strict: homoglyph severity is critical",
        rvStrict.issues.some(function (i) {
          return i.kind === "homoglyph" && i.severity === "critical";
        }));

  // No ASCII letters present → homoglyph rule short-circuits (nothing to
  // confuse against), so a pure-Cyrillic leaf raises no homoglyph issue.
  var rvPure = b.guardFilename.validate(cyrA + String.fromCharCode(0x0431),
                                        { profile: "balanced" });
  check("pure non-ASCII leaf → no homoglyph issue (no ASCII to mix)",
        !rvPure.issues.some(function (i) { return i.kind === "homoglyph"; }));
}

function testGuardFilenameSuperscriptReservedName() {
  // Windows folds superscript digits U+00B9/00B2/00B3 to 1/2/3 when
  // matching COM/LPT devices — "COM<sup1>" resolves to COM1. Exercises the
  // superscript-fold branch in _isWinReserved.
  var sup1 = String.fromCharCode(0xB9);
  var rv = b.guardFilename.validate("COM" + sup1, { profile: "balanced" });
  check("superscript-digit COM device spoof → reserved-name",
        rv.issues.some(function (i) { return i.kind === "reserved-name"; }));
}

function testGuardFilenameExtAllowlistNoExtension() {
  // A name with NO extension against an allowlist → ext-not-allowlisted
  // (the empty-extension branch of the allowlist check).
  var rv = b.guardFilename.validate("readme", {
    profile:            "balanced",
    extensionAllowlist: [".txt", ".md"],
  });
  check("no-extension name against allowlist → ext-not-allowlisted",
        rv.issues.some(function (i) { return i.kind === "ext-not-allowlisted"; }));
}

function testGuardFilenameSanitizeEnforceRejections() {
  // sanitize() default (enforce) mode — every reject/throw path below is a
  // security-floor or profile-policy refusal the operator relies on.

  _expectThrowCode("sanitize empty string", "filename.empty", function () {
    b.guardFilename.sanitize("", { profile: "balanced" });
  });

  _expectThrowCode("sanitize overlong-UTF-8 Buffer", "filename.overlong-utf8", function () {
    b.guardFilename.sanitize(Buffer.from([0xC0, 0xAE, 0x66]), { profile: "balanced" });
  });

  _expectThrowCode("sanitize UNC path", "filename.unc", function () {
    b.guardFilename.sanitize("//server/share/file.txt", { profile: "balanced" });
  });

  // strict leadingTrailingPolicy:"reject" — leading whitespace refuses
  // rather than being stripped.
  _expectThrowCode("sanitize strict leading whitespace", "filename.leading-trailing", function () {
    b.guardFilename.sanitize("  report.txt", { profile: "strict" });
  });

  _expectThrowCode("sanitize reserved char (reject)", "filename.reserved-char", function () {
    b.guardFilename.sanitize("a<b.txt", { profile: "balanced" });
  });

  // balanced reservedCharPolicy:"reject" + pathSeparatorsPolicy:"reject" —
  // the "/" is not a reserved char, so the path-separator branch refuses it.
  _expectThrowCode("sanitize path separator (reject)", "filename.path-separator", function () {
    b.guardFilename.sanitize("a/b.txt", { profile: "balanced" });
  });

  _expectThrowCode("sanitize reserved device name (reject)", "filename.reserved-name", function () {
    b.guardFilename.sanitize("CON", { profile: "balanced" });
  });

  // permissive reservedNamePolicy:"audit" — disambiguates by prefixing "_"
  // rather than throwing.
  check("sanitize permissive reserved name → underscore-prefixed",
        b.guardFilename.sanitize("CON", { profile: "permissive" }) === "_CON");

  // NTFS ADS refusal in enforce mode. The ":" is normally caught by the
  // reserved-char pass first, so opt that off to drive the dedicated ADS
  // branch: reservedCharPolicy:"allow" keeps the colon, adsPolicy:"reject"
  // refuses the stream syntax.
  _expectThrowCode("sanitize NTFS ADS (dedicated branch)", "filename.ntfs-ads", function () {
    b.guardFilename.sanitize("file.txt:stream", {
      profile:            "permissive",
      reservedCharPolicy: "allow",
      adsPolicy:          "reject",
    });
  });

  _expectThrowCode("sanitize over-length leaf", "filename.length", function () {
    b.guardFilename.sanitize("x".repeat(300) + ".txt", { profile: "balanced" });
  });

  // Whitespace-only leaf strips to empty under permissive → post-strip
  // empty refusal.
  _expectThrowCode("sanitize strips to empty", "filename.empty", function () {
    b.guardFilename.sanitize("   ", { profile: "permissive" });
  });
}

function testGuardFilenameSanitizeBadInput() {
  _expectThrowCode("sanitize non-string/Buffer input", "filename.bad-input", function () {
    b.guardFilename.sanitize(12345, { profile: "balanced" });
  });
}

function testGuardFilenameSanitizeStripModeFloor() {
  // Strip-mode security floor branches not covered by the round-trip test.
  _expectThrowCode("strip-mode overlong-UTF-8 Buffer", "filename.overlong-utf8", function () {
    b.guardFilename.sanitize(Buffer.from([0xC0, 0xAE, 0x66]),
                             { mode: "strip", profile: "balanced" });
  });

  _expectThrowCode("strip-mode empty string", "filename.empty", function () {
    b.guardFilename.sanitize("", { mode: "strip", profile: "balanced" });
  });

  _expectThrowCode("strip-mode over-length leaf", "filename.length", function () {
    b.guardFilename.sanitize("x".repeat(300), { mode: "strip", profile: "balanced" });
  });
}

async function testGuardFilenameGateSanitizeAction() {
  // The gate's "sanitize" action fires only when EVERY reject-policy is off
  // and a strip-eligible high/critical issue is present. Drive it with an
  // all-policies-non-reject config and a leading-whitespace name (a "high"
  // leading-trailing issue that sanitize repairs to "report.txt").
  var g = b.guardFilename.gate({
    profile:               "permissive",
    bidiPolicy:            "strip",
    controlPolicy:         "strip",
    nullBytePolicy:        "allow",
    traversalPolicy:       "audit",
    reservedCharPolicy:    "strip",
    reservedNamePolicy:    "audit",
    adsPolicy:             "audit",
    pathSeparatorsPolicy:  "audit",
    leadingTrailingPolicy: "strip",
  });
  var v = await g.check({ filename: " report.txt" });
  check("gate: sanitize-eligible issue → action=sanitize",
        v.ok === true && v.action === "sanitize");

  // audit-only: a warn-severity-only issue (no high/critical) resolves to
  // action=audit-only. A homoglyph under audit policy is warn-only.
  var gAudit = b.guardFilename.gate({ profile: "permissive", homoglyphPolicy: "audit" });
  var vAudit = await gAudit.check({ filename: "p" + String.fromCharCode(0x0430) + "y" });
  check("gate: warn-only issue → action=audit-only",
        vAudit.action === "audit-only");
}

function testVerifyExtractionPathStringRefusals() {
  var root = "/var/quarantine";
  _expectThrowCode("vep empty entryName", "filename.extraction-empty", function () {
    b.guardFilename.verifyExtractionPath("", root);
  });
  _expectThrowCode("vep non-string entryName", "filename.extraction-empty", function () {
    b.guardFilename.verifyExtractionPath(123, root);
  });
  _expectThrowCode("vep empty extractionRoot", "filename.extraction-bad-root", function () {
    b.guardFilename.verifyExtractionPath("ok.txt", "");
  });
  _expectThrowCode("vep non-string extractionRoot", "filename.extraction-bad-root", function () {
    b.guardFilename.verifyExtractionPath("ok.txt", 123);
  });
  _expectThrowCode("vep PATH_MAX overflow", "filename.extraction-path-max", function () {
    b.guardFilename.verifyExtractionPath("a".repeat(4097), root);
  });
  _expectThrowCode("vep null byte", "filename.extraction-null-byte", function () {
    b.guardFilename.verifyExtractionPath("file" + String.fromCharCode(0) + ".txt", root);
  });
  _expectThrowCode("vep absolute path", "filename.extraction-absolute", function () {
    b.guardFilename.verifyExtractionPath("/etc/passwd", root);
  });
  _expectThrowCode("vep drive-letter prefix", "filename.extraction-drive-prefix", function () {
    b.guardFilename.verifyExtractionPath("C:/Windows/system32", root);
  });
  _expectThrowCode("vep .. leading segment", "filename.extraction-traversal", function () {
    b.guardFilename.verifyExtractionPath("../etc/passwd", root);
  });
  _expectThrowCode("vep .. interior segment", "filename.extraction-traversal", function () {
    b.guardFilename.verifyExtractionPath("a/../b", root);
  });
  _expectThrowCode("vep backslash .. segment", "filename.extraction-traversal", function () {
    b.guardFilename.verifyExtractionPath("a\\..\\b", root);
  });
  _expectThrowCode("vep percent-encoded ..", "filename.extraction-traversal-encoded", function () {
    b.guardFilename.verifyExtractionPath("docs/%2e%2e/x", root);
  });
  _expectThrowCode("vep overlong-encoded ..", "filename.extraction-traversal-encoded", function () {
    b.guardFilename.verifyExtractionPath("docs/%c0%ae/x", root);
  });
  _expectThrowCode("vep reserved device segment", "filename.extraction-reserved-name", function () {
    b.guardFilename.verifyExtractionPath("docs/CON/x.txt", root);
  });
  _expectThrowCode("vep NTFS ADS segment", "filename.extraction-ntfs-ads", function () {
    b.guardFilename.verifyExtractionPath("docs/file.txt:stream", root);
  });
  _expectThrowCode("vep trailing-dot segment", "filename.extraction-leading-trailing", function () {
    b.guardFilename.verifyExtractionPath("docs/secret.txt.", root);
  });
  _expectThrowCode("vep leading-whitespace segment", "filename.extraction-leading-trailing", function () {
    b.guardFilename.verifyExtractionPath(" leading/x.txt", root);
  });
}

function testVerifyExtractionPathOptOuts() {
  // Non-existent root so the fs realpath block is skipped; each opt-out
  // flips a Windows-hazard segment check off and the call succeeds.
  var root = path.join(os.tmpdir(), "gfn-none-" + Date.now() + "-" + Math.random().toString(36).slice(2));
  var r1 = b.guardFilename.verifyExtractionPath("docs/CON/x.txt", root,
                                                { reservedNamePolicy: "allow" });
  check("vep reservedNamePolicy:allow permits CON segment",
        typeof r1 === "string" && r1.indexOf("x.txt") !== -1);

  var r2 = b.guardFilename.verifyExtractionPath("docs/file.txt:stream", root,
                                                { adsPolicy: "allow" });
  check("vep adsPolicy:allow permits name:stream segment",
        typeof r2 === "string" && r2.indexOf("stream") !== -1);

  var r3 = b.guardFilename.verifyExtractionPath("docs/secret.txt.", root,
                                                { leadingTrailingPolicy: "allow" });
  check("vep leadingTrailingPolicy:allow permits trailing dot",
        typeof r3 === "string");
}

function testVerifyExtractionPathSuccess() {
  // Non-existent root: string-containment passes, realpath block skipped,
  // resolved path returned.
  var noneRoot = path.join(os.tmpdir(), "gfn-none-" + Date.now() + "-" + Math.random().toString(36).slice(2));
  var resolved = b.guardFilename.verifyExtractionPath("docs/readme.txt", noneRoot);
  check("vep benign entry (no root on disk) → resolved path returned",
        typeof resolved === "string" &&
        resolved === path.resolve(noneRoot, "docs/readme.txt"));

  // Existing root on disk: exercises the realpath-agreement block — every
  // existing ancestor must realpath inside the realpath of the root.
  var realRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gfn-root-"));
  try {
    var r = b.guardFilename.verifyExtractionPath("sub/dir/file.txt", realRoot);
    check("vep existing root → realpath-agreement passes, resolved returned",
          r === path.resolve(realRoot, "sub/dir/file.txt"));
  } finally {
    try { fs.rmSync(realRoot, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

function testVerifyExtractionPathRealpathEscape() {
  // A symlink/junction inside the root whose realpath escapes the root is
  // the CVE-2025-4517 PATH_MAX-TOCTOU class: string containment passes
  // (no ".." literal) but fs.realpath resolves outside. Junction on
  // Windows (no admin needed) / symlink on POSIX.
  var realRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gfn-root-"));
  var outside  = fs.mkdtempSync(path.join(os.tmpdir(), "gfn-out-"));
  var linkMade = false;
  try {
    var link = path.join(realRoot, "link");
    try { fs.symlinkSync(outside, link, "junction"); linkMade = true; }
    catch (_e1) {
      try { fs.symlinkSync(outside, link, "dir"); linkMade = true; }
      catch (_e2) { linkMade = false; }
    }
    if (linkMade) {
      _expectThrowCode("vep symlink escaping root", "filename.extraction-realpath-escape", function () {
        b.guardFilename.verifyExtractionPath("link/evil.txt", realRoot);
      });
    }
  } finally {
    try { fs.rmSync(realRoot, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
    try { fs.rmSync(outside, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
  check("vep realpath-escape test wired (symlink/junction created)", linkMade === true);
}

function testGuardFilenameOverlongVariants() {
  // 3-byte overlong (0xE0 0x80-0x9F) and 4-byte overlong (0xF0 0x80-0x8F)
  // are non-shortest forms alongside the 2-byte 0xC0/0xC1 class.
  var three = b.guardFilename.validate(Buffer.from([0xE0, 0x80, 0xAE, 0x78]),
                                       { profile: "strict" });
  check("3-byte overlong UTF-8 detected",
        three.issues.some(function (i) { return i.kind === "overlong-utf8"; }));

  var four = b.guardFilename.validate(Buffer.from([0xF0, 0x80, 0x80, 0xAE]),
                                      { profile: "strict" });
  check("4-byte overlong UTF-8 detected",
        four.issues.some(function (i) { return i.kind === "overlong-utf8"; }));
}

function testGuardFilenameSanitizeBufferInput() {
  // A well-formed Buffer flows through the Buffer arm of both sanitize
  // modes' name-extraction and round-trips to its UTF-8 text.
  check("sanitize enforce accepts a benign Buffer",
        b.guardFilename.sanitize(Buffer.from("okname.txt", "utf8"),
                                 { profile: "balanced" }) === "okname.txt");
  check("sanitize strip accepts a benign Buffer",
        b.guardFilename.sanitize(Buffer.from("okname.txt", "utf8"),
                                 { mode: "strip", profile: "balanced" }) === "okname.txt");
}

function testGuardFilenameStripAuditEdge() {
  // Buffer input through strip-mode audit — the originalLength computation
  // takes its Buffer arm.
  var captured = [];
  var okAudit = { safeEmit: function (ev) { captured.push(ev); } };
  var crBuf = Buffer.from("report" + String.fromCharCode(0x0D) + ".txt", "utf8");
  var out = b.guardFilename.sanitize(crBuf, { mode: "strip", profile: "balanced", audit: okAudit });
  check("strip-mode audit with Buffer input emits + strips CR",
        out === "report_.txt" && captured.length === 1 &&
        captured[0].action === "guardfilename.sanitize.stripped");

  // A throwing audit sink must NOT propagate — the sink is drop-silent so
  // a crashing audit backend never breaks the producer.
  var throwingAudit = { safeEmit: function () { throw new Error("audit backend down"); } };
  var stillOut = b.guardFilename.sanitize("report" + String.fromCharCode(0x0D) + ".txt",
                                          { mode: "strip", profile: "balanced", audit: throwingAudit });
  check("strip-mode audit sink error is swallowed (drop-silent)",
        stillOut === "report_.txt");
}

async function testGuardFilenameGateCtxShapes() {
  var g = b.guardFilename.gate({ profile: "strict" });

  // ctx.name (not ctx.filename) is the fallback identity key.
  var byName = await g.check({ name: "report.txt" });
  check("gate reads ctx.name when ctx.filename absent → serve",
        byName.ok === true && byName.action === "serve");

  // No filename at all → serve (nothing to guard).
  var empty = await g.check({});
  check("gate with no filename → serve",
        empty.ok === true && empty.action === "serve");
}

function testVerifyExtractionPathDotSegment() {
  // Current-dir "." and empty segments are skipped by the per-segment
  // walk; a benign path carrying them still resolves cleanly.
  var root = path.join(os.tmpdir(), "gfn-none-" + Date.now() + "-" + Math.random().toString(36).slice(2));
  var resolved = b.guardFilename.verifyExtractionPath("a/./b.txt", root);
  check("vep skips '.' segment and resolves",
        resolved === path.resolve(root, "a/b.txt"));
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
  testGdprPostureMatchesBalancedTier();
  testGuardFilenameClean();
  testGuardFilenameSanitize();
  testGuardFilenameSanitizeStripMode();
  testGuardFilenameCompliancePosture();
  testGuardFilenameBadProfile();
  testGuardFilenameEmptyInput();
  testGuardFilenameBenignBufferNoOverlong();
  testGuardFilenameHomoglyph();
  testGuardFilenameSuperscriptReservedName();
  testGuardFilenameExtAllowlistNoExtension();
  testGuardFilenameSanitizeEnforceRejections();
  testGuardFilenameSanitizeBadInput();
  testGuardFilenameSanitizeStripModeFloor();
  testGuardFilenameOverlongVariants();
  testGuardFilenameSanitizeBufferInput();
  testGuardFilenameStripAuditEdge();
  testVerifyExtractionPathDotSegment();
  testVerifyExtractionPathStringRefusals();
  testVerifyExtractionPathOptOuts();
  testVerifyExtractionPathSuccess();
  testVerifyExtractionPathRealpathEscape();
  await testGuardFilenameGate();
  await testGuardFilenameGateSanitizeAction();
  await testGuardFilenameGateCtxShapes();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[guard-filename] OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

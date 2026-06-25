"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function testHappyPath() {
  var p = b.safePath.resolve("/srv/uploads", "user/avatar.png");
  // Host-platform-specific absolute prefix (Windows adds a drive
  // letter, POSIX doesn't); compare the trailing relative portion.
  var normalized = p.replace(/\\/g, "/");
  check("happy-path includes base", normalized.indexOf("srv/uploads/user/avatar.png") !== -1);
  check("happy-path is absolute",   require("node:path").isAbsolute(p));
}

function testRefusalClasses() {
  var cases = [
    { name: "absolute-rel posix",   args: ["/srv", "/etc/passwd"],            code: "safe-path/absolute-rel" },
    { name: "absolute-rel drive",   args: ["/srv", "C:\\Windows\\x"],         code: "safe-path/absolute-rel" },
    { name: "absolute-rel UNC",     args: ["/srv", "\\\\server\\share"],      code: "safe-path/absolute-rel" },
    { name: "null byte",            args: ["/srv", "a\0b"],                   code: "safe-path/null-byte" },
    { name: "control char",         args: ["/srv", "a\x01b"],                 code: "safe-path/control-char" },
    { name: "bidi codepoint",       args: ["/srv", "a‮b"],               code: "safe-path/bidi" },
    { name: "encoded slash",        args: ["/srv", "a%2Fb"],                  code: "safe-path/separator-in-segment" },
    { name: "fullwidth slash",      args: ["/srv", "a／b"],               code: "safe-path/separator-in-segment" },
    { name: "win reserved CON",     args: ["/srv", "CON"],                    code: "safe-path/win-reserved" },
    { name: "win reserved con.txt", args: ["/srv", "con.txt"],                code: "safe-path/win-reserved" },
    { name: "NTFS ADS marker",      args: ["/srv", "foo:bar"],                code: "safe-path/ads-marker" },
    { name: "escapes base",         args: ["/srv", "../etc/passwd"],          code: "safe-path/escapes-base" },
  ];
  for (var i = 0; i < cases.length; i += 1) {
    var c = cases[i];
    var caught = null;
    try { b.safePath.resolve(c.args[0], c.args[1]); }
    catch (e) { caught = e; }
    check(c.name + " throws " + c.code,
      caught !== null && (caught.code === c.code || (caught.message || "").indexOf(c.code) !== -1));
  }
}

function testWindowsTrailing() {
  var caught = null;
  try { b.safePath.resolve("/srv", "foo.txt.", { platform: "windows" }); }
  catch (e) { caught = e; }
  check("win-trailing dot throws",
    caught !== null && (caught.code === "safe-path/win-trailing" || (caught.message || "").indexOf("win-trailing") !== -1));
}

function testResolveOrNullReturnsNull() {
  var p = b.safePath.resolveOrNull("/srv", "../etc/passwd");
  check("resolveOrNull returns null on refusal", p === null);
  var ok = b.safePath.resolveOrNull("/srv", "ok.txt");
  check("resolveOrNull returns path on success", typeof ok === "string" && ok.indexOf("ok.txt") !== -1);
}

function testValidateReturnsVerdict() {
  var bad = b.safePath.validate("/srv", "../etc/passwd");
  check("validate(refused) ok=false", bad.ok === false);
  check("validate(refused) carries code", typeof bad.code === "string");
  var good = b.safePath.validate("/srv", "data/x.json");
  check("validate(ok) ok=true", good.ok === true);
  check("validate(ok) carries resolved", typeof good.resolved === "string");
}

function testErrorClassExported() {
  check("SafePathError exported", typeof b.safePath.SafePathError === "function");
}

// #371 — opts.platform gates the per-segment naming rules AND the lexical
// containment resolution. The lexical resolve + boundary use the TARGET
// platform's path module (nodePath.win32 / nodePath.posix) so the resolved
// output's separator matches the boundary slice. Validating against the
// OPPOSITE platform's rules (the recommended cross-platform pattern) used to
// refuse every in-base path with safe-path/escapes-base because the boundary
// slice compared the runtime-separated nodePath.resolve output against the
// opts.platform separator. With target-platform resolution the in-base path is
// accepted AND a genuine traversal is still refused under any override.
function testCrossPlatformContainment() {
  var nodePath = require("node:path");
  var other = process.platform === "win32" ? "linux" : "windows";
  var pathMod = other === "windows" ? nodePath.win32 : nodePath.posix;
  // Drive-prefixed base on Windows, posix base elsewhere.
  var base = process.platform === "win32" ? "C:/srv/uploads" : "/srv/uploads";

  var inBase = b.safePath.resolveOrNull(base, "file.txt", { platform: other });
  check("opposite-platform override resolves an in-base file (not null)",
    typeof inBase === "string" && inBase.indexOf("file.txt") !== -1);
  var nested = b.safePath.resolveOrNull(base, "a/b/file.txt", { platform: other });
  check("opposite-platform override resolves a nested in-base path",
    typeof nested === "string" && nested.indexOf("file.txt") !== -1);
  var v = b.safePath.validate(base, "data/x.json", { platform: other });
  check("opposite-platform override validate() ok=true", v.ok === true && typeof v.resolved === "string");
  // Containment is still ENFORCED under the override — a real traversal refused.
  check("opposite-platform override still refuses a forward-slash traversal",
    b.safePath.resolveOrNull(base, "../../etc/passwd", { platform: other }) === null);
  // The containment boundary uses the TARGET platform's separator, so the
  // resolved path begins with the target-resolved base.
  check("resolved path begins with the target-resolved base",
    typeof inBase === "string" && inBase.indexOf(pathMod.resolve(base)) === 0);
}

// #371 P1 — cross-platform backslash traversal. A POSIX host validating with
// opts.platform: "windows" must collapse Windows separators (\) and `..` the
// SAME way the per-segment walk does. The lexical resolve previously used the
// runtime path module: on POSIX, node:path treats \ as an ordinary filename
// character, so `ok\..\..\outside` slipped past containment and resolved to
// `<base>/ok\..\..\outside` — a path that escapes the base once a Windows
// consumer interprets the backslashes. Validating FOR windows now resolves with
// nodePath.win32 on every host, so the traversal is refused. (On a Windows host
// win32 IS the runtime, so this also guards the same case there.)
function testCrossPlatformBackslashTraversalRefused() {
  var BS = String.fromCharCode(92); // backslash without source-escaping ambiguity
  var base = "/srv/uploads";
  var trav = "ok" + BS + ".." + BS + ".." + BS + "outside"; // ok\..\..\outside
  check("windows-target backslash traversal refused (resolveOrNull → null)",
    b.safePath.resolveOrNull(base, trav, { platform: "windows" }) === null);
  var v = b.safePath.validate(base, trav, { platform: "windows" });
  check("windows-target backslash traversal refused (validate ok=false)",
    v.ok === false && v.code === "safe-path/escapes-base");
  var threw = false, code = null;
  try { b.safePath.resolve(base, trav, { platform: "windows" }); }
  catch (e) { threw = true; code = e && e.code; }
  check("windows-target backslash traversal refused (resolve throws escapes-base)",
    threw === true && code === "safe-path/escapes-base");
  // A nested-but-in-base Windows path with backslashes still resolves.
  var ok = b.safePath.resolveOrNull(base, "a" + BS + "b" + BS + "c.txt", { platform: "windows" });
  check("windows-target in-base backslash path resolves",
    typeof ok === "string" && ok.indexOf("c.txt") !== -1);
}

function run() {
  testHappyPath();
  testRefusalClasses();
  testWindowsTrailing();
  testResolveOrNullReturnsNull();
  testValidateReturnsVerdict();
  testErrorClassExported();
  testCrossPlatformContainment();
  testCrossPlatformBackslashTraversalRefused();
}

if (require.main === module) run();
module.exports = { run: run };

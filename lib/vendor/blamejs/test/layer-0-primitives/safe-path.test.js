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

function run() {
  testHappyPath();
  testRefusalClasses();
  testWindowsTrailing();
  testResolveOrNullReturnsNull();
  testValidateReturnsVerdict();
  testErrorClassExported();
}

if (require.main === module) run();
module.exports = { run: run };

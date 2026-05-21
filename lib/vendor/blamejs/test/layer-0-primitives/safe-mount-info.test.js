"use strict";
/**
 * b.safeMountInfo — canonical /proc/self/mountinfo parser.
 *
 * Covers: parse + bestMatch + isBindMount semantics, malformed-line
 * skip vs strict-throw, read on non-Linux fallback, line cap.
 *
 * Run standalone: `node test/layer-0-primitives/safe-mount-info.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Canonical mountinfo sample. The bind-mount line (id=42) has root
// `/Users/me/data` — that's what bind-mount detection MUST consult.
var FIXTURE_TEXT =
  "23 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw\n" +
  "24 28 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw\n" +
  "28 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
  "42 28 8:1 /Users/me/data /data rw,relatime shared:99 - ext4 /dev/sda1 rw\n";

function testSurface() {
  check("b.safeMountInfo.parse is a function",      typeof b.safeMountInfo.parse      === "function");
  check("b.safeMountInfo.read is a function",       typeof b.safeMountInfo.read       === "function");
  check("b.safeMountInfo.bestMatch is a function",  typeof b.safeMountInfo.bestMatch  === "function");
  check("b.safeMountInfo.isBindMount is a function",typeof b.safeMountInfo.isBindMount=== "function");
  check("b.safeMountInfo.SafeMountInfoError is a class",
        typeof b.safeMountInfo.SafeMountInfoError === "function");
}

function testParseFixture() {
  var entries = b.safeMountInfo.parse(FIXTURE_TEXT);
  check("parse: yields 4 entries", entries.length === 4);

  var rootMount = entries[2];
  check("rootMount.mountPoint === '/'",  rootMount.mountPoint === "/");
  check("rootMount.root === '/'",        rootMount.root === "/");
  check("rootMount.fstype === 'ext4'",   rootMount.fstype === "ext4");

  var bindMount = entries[3];
  check("bindMount.mountPoint === '/data'",            bindMount.mountPoint === "/data");
  check("bindMount.root === '/Users/me/data'",         bindMount.root === "/Users/me/data");
  check("bindMount.options carries rw,relatime",       /rw,relatime/.test(bindMount.options));
}

function testIsBindMount() {
  var entries  = b.safeMountInfo.parse(FIXTURE_TEXT);
  var root     = entries[2];                          // root mount, root='/'
  var bind     = entries[3];                          // bind, root='/Users/me/data'

  check("isBindMount(root)  → false", b.safeMountInfo.isBindMount(root)  === false);
  check("isBindMount(bind)  → true",  b.safeMountInfo.isBindMount(bind)  === true);
  check("isBindMount(null)  → false", b.safeMountInfo.isBindMount(null)  === false);
  check("isBindMount({})    → false", b.safeMountInfo.isBindMount({})    === false);
}

function testBestMatchLongestPrefix() {
  var entries = b.safeMountInfo.parse(FIXTURE_TEXT);
  // /data should match the bind-mount (longest prefix beats / root).
  var atData  = b.safeMountInfo.bestMatch(entries, "/data");
  check("bestMatch(/data) → bind-mount entry",     atData && atData.mountPoint === "/data");

  // /data/foo also matches the bind-mount.
  var atSub   = b.safeMountInfo.bestMatch(entries, "/data/foo");
  check("bestMatch(/data/foo) → bind-mount entry", atSub && atSub.mountPoint === "/data");

  // /home/bob falls back to /.
  var atHome  = b.safeMountInfo.bestMatch(entries, "/home/bob");
  check("bestMatch(/home/bob) → root mount",       atHome && atHome.mountPoint === "/");

  // Bad input → null.
  check("bestMatch([], '/x') → null",  b.safeMountInfo.bestMatch([], "/x") === null);
  check("bestMatch(null, '/x') → null",b.safeMountInfo.bestMatch(null, "/x") === null);
}

function testMalformedLineSkipDefault() {
  var bad = FIXTURE_TEXT + "this is not a valid mountinfo line\n";
  var entries = b.safeMountInfo.parse(bad);
  check("parse: malformed line silently skipped by default",
        entries.length === 4);
}

function testStrictThrowsOnMalformed() {
  var bad = FIXTURE_TEXT + "this is not a valid mountinfo line\n";
  var threw = null;
  try { b.safeMountInfo.parse(bad, { strict: true }); } catch (e) { threw = e; }
  check("parse({strict:true}) → throws on malformed line",
        threw && /safe-mount-info\/parse-failed/.test(threw.code || ""));
}

function testLineCap() {
  // Synth a huge mountinfo. Default cap 4096.
  var lines = [];
  for (var i = 0; i < 5000; i += 1) lines.push("dummy");                              // allow:raw-byte-literal — well over the default 4096 cap
  var big = lines.join("\n");
  var threw = null;
  try { b.safeMountInfo.parse(big); } catch (e) { threw = e; }
  check("parse({default cap}) → throws on > 4096 lines",
        threw && /too-many-lines/.test(threw.code || ""));
}

function testLineCapBoundaryWithTrailingNewline() {
  // Codex P2 regression check (PR #111): exactly `maxLines` valid
  // records followed by a trailing newline. `text.split("\n")`
  // produces N+1 segments (the last is "") — pre-fix the cap
  // misfired here and refused legitimate full-cap inputs.
  var lines = [];
  for (var i = 0; i < 16; i += 1) {                                                   // allow:raw-byte-literal — small synthetic budget
    lines.push("23 28 0:21 / /sys" + i + " rw shared:7 - sysfs sysfs rw");
  }
  var text = lines.join("\n") + "\n";                                                  // trailing newline mimics /proc/self/mountinfo
  var entries = b.safeMountInfo.parse(text, { maxLines: 16 });                        // allow:raw-byte-literal — matches synthetic record count
  check("parse({maxLines: N}) accepts exactly N records + trailing newline",
        entries.length === 16);

  // One more record + trailing newline → over cap.
  lines.push("99 28 0:21 / /sys99 rw shared:7 - sysfs sysfs rw");
  var bigger = lines.join("\n") + "\n";
  var threw = null;
  try { b.safeMountInfo.parse(bigger, { maxLines: 16 }); } catch (e) { threw = e; }   // allow:raw-byte-literal — matches synthetic record count
  check("parse({maxLines: 16}) refuses 17 records",
        threw && /too-many-lines/.test(threw.code || ""));
}

function testBadInputRefused() {
  var threw = null;
  try { b.safeMountInfo.parse(null); } catch (e) { threw = e; }
  check("parse(null) → refused", threw && /bad-input/.test(threw.code || ""));

  threw = null;
  try { b.safeMountInfo.parse(42); } catch (e) { threw = e; }                         // allow:raw-byte-literal — arbitrary non-string
  check("parse(42) → refused",   threw && /bad-input/.test(threw.code || ""));
}

function testReadNonExistentPath() {
  // Reading a path that doesn't exist returns the fallback rather
  // than throwing (cross-platform — tests run on Windows / macOS too).
  var out = b.safeMountInfo.read({ path: "/no/such/mountinfo/exists" });
  check("read({path: nonexistent}) → null fallback", out === null);

  var sentinel = { ok: true };
  var withFb = b.safeMountInfo.read({ path: "/no/such/mountinfo/exists", fallback: sentinel });
  check("read with custom fallback returns it",      withFb === sentinel);
}

function testAuditEmittedOnReadFailed() {
  var captured = [];
  var auditFake = { safeEmit: function (e) { captured.push(e); } };
  b.safeMountInfo.read({ path: "/no/such/mountinfo/exists", audit: auditFake });
  check("audit event captured on read-failed",   captured.length === 1);
  if (captured.length === 1) {
    check("event action is system.safe_mount_info.refused",
          captured[0].action === "system.safe_mount_info.refused");
    check("event metadata names read-failed code",
          captured[0].metadata && captured[0].metadata.code === "safe-mount-info/read-failed");
  }
}

async function run() {
  testSurface();
  testParseFixture();
  testIsBindMount();
  testBestMatchLongestPrefix();
  testMalformedLineSkipDefault();
  testStrictThrowsOnMalformed();
  testLineCap();
  testLineCapBoundaryWithTrailingNewline();
  testBadInputRefused();
  testReadNonExistentPath();
  testAuditEmittedOnReadFailed();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

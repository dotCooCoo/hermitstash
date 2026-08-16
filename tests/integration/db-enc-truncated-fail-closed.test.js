"use strict";

/**
 * A truncated db.enc stops the server instead of emptying it.
 *
 * hermitstash.db.enc is the only durable copy of the database — the plaintext
 * lives on tmpfs and is gone at every restart. Boot used to answer a file too
 * short to be an envelope with a bare `return`: no log, no refusal. There is
 * nothing else to load, so the server came up on an empty database, and the
 * re-encrypt that runs every five minutes and again at exit then wrote that
 * empty database over the file. Whatever the truncated one still held went with
 * it, along with the evidence.
 *
 * encryptDbFile's own comment names this outcome — "a torn .db.enc (truncated
 * past the 26-byte guard) fails to decrypt on boot → permanent data loss" —
 * which is why it writes atomically. That prevents this process tearing the
 * file. It does nothing about one torn by a full disk, an interrupted copy or a
 * partial restore, and that is the case boot has to survive.
 *
 * getDbEncKey already treats the same length test as fatal. This makes the two
 * agree.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var { spawnSync } = require("node:child_process");

var projectRoot = path.join(__dirname, "..", "..");
var tmpRoot;

before(function () { tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hs-dbenc-")); });
after(function () {
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

// Boot lib/db against a data directory we control and report how it went.
// A child process because the refusal is process.exit(1), which cannot be
// caught in-process — the same reason db-key-fail-closed.test.js does it.
function bootWithDbEnc(bytes) {
  var dir = fs.mkdtempSync(path.join(tmpRoot, "case-"));
  if (bytes !== null) fs.writeFileSync(path.join(dir, "hermitstash.db.enc"), bytes);

  var script = [
    "var db = require(" + JSON.stringify(path.join(projectRoot, "lib", "db").replace(/\\/g, "/")) + ");",
    "process.stdout.write('BOOTED');",
  ].join("\n");

  var res = spawnSync(process.execPath, ["-e", script], {
    cwd: projectRoot,
    encoding: "utf8",
    env: Object.assign({}, process.env, {
      HERMITSTASH_DATA_DIR: dir,
      HERMITSTASH_ALLOW_DISK_DB: "true",
    }),
  });
  return {
    booted: String(res.stdout || "").indexOf("BOOTED") !== -1,
    status: res.status,
    said: String(res.stderr || "") + String(res.stdout || ""),
    dir: dir,
  };
}

describe("a truncated encrypted database refuses the boot", function () {
  [0, 1, 10, 25].forEach(function (n) {
    it("refuses a " + n + "-byte db.enc", function () {
      var out = bootWithDbEnc(Buffer.alloc(n));
      assert.equal(out.booted, false,
        "boot must not continue on a db.enc too short to be an envelope");
      assert.equal(out.status, 1, "and must exit non-zero");
      assert.match(out.said, /too short to be an\s+encrypted database/i, out.said.slice(0, 400));
    });
  });

  it("says what to do about it, including the fresh-install case", function () {
    var said = bootWithDbEnc(Buffer.alloc(10)).said;
    assert.match(said, /Restore hermitstash\.db\.enc/i, "the recovery instruction must be a restore");
    assert.match(said, /fresh install/i,
      "and an operator whose stray empty file is not a backup needs the escape hatch named");
  });

  it("does not disturb the file it refused over", function () {
    // The point of refusing is that the bytes survive to be examined or
    // recovered. If boot rewrote them, refusing would be pointless.
    var out = bootWithDbEnc(Buffer.from("0123456789"));
    var after = fs.readFileSync(path.join(out.dir, "hermitstash.db.enc"));
    assert.equal(after.length, 10, "the truncated file must be left exactly as it was");
    assert.equal(after.toString(), "0123456789");
  });

  it("still boots normally when there is no db.enc at all", function () {
    // A genuine first run. The guard must not turn an ordinary fresh install
    // into a refusal.
    var out = bootWithDbEnc(null);
    assert.equal(out.booted, true,
      "a first run with no encrypted database must start: " + out.said.slice(0, 400));
  });
});

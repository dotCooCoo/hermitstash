"use strict";

/**
 * A refused read must not tell you whether the file was there.
 *
 * lib/storage.js opens local objects with O_NOFOLLOW and maps both ELOOP (a
 * planted symlink) and ENOENT (nothing there) onto one error, deliberately: on a
 * request-reachable read path, a distinguishable symlink refusal is an existence
 * oracle. Point it at a path, watch which error comes back, and you learn
 * whether an object exists without being allowed to read it.
 *
 * Nothing covered that mapping, so the two could drift apart — different codes,
 * different messages — and the oracle would reopen with every test still green.
 *
 * The symlink half needs a symlink, which Windows refuses without Developer Mode
 * or elevation. It is gated on the capability rather than on the platform, so it
 * runs wherever one can actually be made, including CI.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var scratch = fs.mkdtempSync(path.join(os.tmpdir(), "hs-storage-oracle-"));
process.env.HERMITSTASH_DATA_DIR = scratch;
process.env.UPLOAD_DIR = path.join(scratch, "uploads");
fs.mkdirSync(process.env.UPLOAD_DIR, { recursive: true });

// The helper points the database at a uniquely named file under data/; its
// cleanup() removes that file and the WAL/SHM beside it. Without calling it,
// every run of this file leaves three more behind.
var testEnv = require("../helpers/test-env");
var vault = require("../../lib/vault");
var storage = require("../../lib/storage");

// Can this machine make a symlink at all?
var canSymlink = (function () {
  try {
    var probeDir = fs.mkdtempSync(path.join(scratch, "probe-"));
    fs.writeFileSync(path.join(probeDir, "t"), "x");
    fs.symlinkSync(path.join(probeDir, "t"), path.join(probeDir, "l"));
    return true;
  } catch (_e) { return false; }
})();

before(async function () { await vault.init(); });
after(function () {
  if (testEnv && typeof testEnv.cleanup === "function") testEnv.cleanup();
  try { fs.rmSync(scratch, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

// Both read paths map the same two conditions; neither may be the odd one out.
var READERS = [
  ["getRawBuffer", function (p) { return storage.getRawBuffer(p); }],
  ["getFileStream", function (p) { return storage.getFileStream(p, null); }],
];

async function errorFrom(fn, p) {
  try {
    await fn(p);
    return null;
  } catch (e) { return e; }
}

describe("a refused storage read is not an existence oracle", function () {
  READERS.forEach(function (pair) {
    var name = pair[0], read = pair[1];

    it(name + " reports a missing object as not found", async function () {
      var e = await errorFrom(read, "absent-" + name + ".bin");
      assert.ok(e, "reading nothing must fail");
      assert.strictEqual(e.code, "ENOENT");
      assert.match(e.message, /storage object not found/);
    });

    it(name + " reports a planted symlink exactly as it reports a missing object",
      { skip: canSymlink ? false : "this machine cannot create symlinks" },
      async function () {
        // The point of the mapping: these two must be indistinguishable.
        var secret = path.join(scratch, "outside-the-root.txt");
        fs.writeFileSync(secret, "not yours");
        var linkName = "planted-" + name + ".bin";
        fs.symlinkSync(secret, path.join(process.env.UPLOAD_DIR, linkName));

        var viaLink = await errorFrom(read, linkName);
        var viaMissing = await errorFrom(read, "absent-again-" + name + ".bin");

        assert.ok(viaLink, "a symlink must not be followed out of the upload root");
        assert.strictEqual(viaLink.code, viaMissing.code,
          "the codes must match, or the difference answers 'does this exist?'");
        assert.strictEqual(viaLink.message, viaMissing.message,
          "and so must the messages");
        assert.ok(!/not yours/.test(String(viaLink.message)), "and no target content may leak");
      });
  });

  it("refuses a path that climbs out of the upload directory", async function () {
    // Checked lexically before any filesystem call, so it holds whether or not
    // the target exists.
    var r = storage.resolveLocalPath("../../etc/passwd");
    assert.strictEqual(r.ok, false);
    assert.match(r.reason, /escapes upload directory/);
  });

  it("refuses an absolute path outside the root, and a sibling-prefix path", async function () {
    assert.strictEqual(storage.resolveLocalPath(path.join(scratch, "elsewhere.bin")).ok, false);
    assert.strictEqual(storage.resolveLocalPath(process.env.UPLOAD_DIR + "-evil/x.bin").ok, false,
      "a directory whose name merely starts with the root is still outside it");
  });

  it("accepts an ordinary path inside the root", async function () {
    // The refusals above are worth nothing if everything is refused.
    var r = storage.resolveLocalPath("bundle-1/file.bin");
    assert.strictEqual(r.ok, true);
    assert.ok(r.absPath.indexOf(path.resolve(process.env.UPLOAD_DIR)) === 0,
      "and resolves inside the upload root");
  });

  it("refuses an empty path rather than resolving it to the root", async function () {
    assert.strictEqual(storage.resolveLocalPath("").ok, false);
    assert.strictEqual(storage.resolveLocalPath(null).ok, false);
  });
});

"use strict";

/**
 * The chunk-staging area's containment checks, which nothing was exercising.
 *
 * removeDirByPath is a recursive delete taking a path from a caller. It is fed
 * from listStaleBundleChunkDirs today, so the paths are ones this module just
 * produced — which is exactly why the refusal branch had never run, and why a
 * change to that guard would not have failed anything. It is the kind of check
 * that only matters on the day something else calls it.
 *
 * The chunk path components come from a bundle share id and a file id, both of
 * which arrive on the request. A component that walks upwards would stage — and
 * later delete — outside the scratch directory, so they are refused rather than
 * sanitised: silently rewriting "../x" to "x" would put one upload's chunks
 * where another's are looked for.
 */

require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var root = fs.mkdtempSync(path.join(os.tmpdir(), "hs-storage-contain-"));
process.env.UPLOAD_DIR = path.join(root, "uploads");
fs.mkdirSync(process.env.UPLOAD_DIR, { recursive: true });

var storage = require("../../lib/storage");
var vault = require("../../lib/vault");

before(async function () { await vault.init(); });
after(function () {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

describe("removeDirByPath will only delete inside the scratch directory", function () {
  it("removes a directory that is inside it", function () {
    var victim = path.join(storage.scratchDir, "bundle-to-remove");
    fs.mkdirSync(path.join(victim, "nested"), { recursive: true });
    fs.writeFileSync(path.join(victim, "nested", "chunk"), "x");
    assert.ok(fs.existsSync(victim));

    storage.removeDirByPath(victim);
    assert.strictEqual(fs.existsSync(victim), false, "a stale bundle directory must be removable");
  });

  it("refuses a path that climbs out", function () {
    var outside = path.join(root, "not-scratch");
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(outside, "keep"), "x");

    assert.throws(function () {
      storage.removeDirByPath(path.join(storage.scratchDir, "..", "not-scratch"));
    }, /outside scratch dir/);
    assert.ok(fs.existsSync(path.join(outside, "keep")), "and must not have deleted it anyway");
  });

  it("refuses an unrelated absolute path", function () {
    var elsewhere = path.join(root, "elsewhere");
    fs.mkdirSync(elsewhere, { recursive: true });
    assert.throws(function () { storage.removeDirByPath(elsewhere); }, /outside scratch dir/);
    assert.ok(fs.existsSync(elsewhere));
  });

  it("refuses a sibling whose name merely starts with the scratch directory's", function () {
    // The check appends a separator for this reason: a plain startsWith would
    // accept "<scratch>-evil" as being inside "<scratch>".
    var sibling = storage.scratchDir + "-evil";
    fs.mkdirSync(sibling, { recursive: true });
    fs.writeFileSync(path.join(sibling, "keep"), "x");
    try {
      assert.throws(function () { storage.removeDirByPath(sibling); }, /outside scratch dir/);
      assert.ok(fs.existsSync(path.join(sibling, "keep")));
    } finally {
      try { fs.rmSync(sibling, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
    }
  });

  it("tolerates a path that has already gone", function () {
    // The caller lists directories and then removes them; one can disappear in
    // between, and that is not an error worth failing a cleanup pass over.
    assert.doesNotThrow(function () {
      storage.removeDirByPath(path.join(storage.scratchDir, "never-existed"));
    });
  });
});

describe("chunk path components are refused rather than sanitised", function () {
  // Rewriting a bad component instead of refusing it would land one upload's
  // chunks where another's are looked for.
  var BAD = ["..", "../evil", "a/b", "a\\b", "", "."];

  BAD.forEach(function (bad, i) {
    it("case " + (i + 1) + ": a bundle id of " + JSON.stringify(bad) + " is refused", function () {
      assert.throws(function () { storage.deleteChunk(bad, "file-1", 0); },
        /Invalid chunk path component/);
    });
    it("case " + (i + 1) + ": a file id of " + JSON.stringify(bad) + " is refused", function () {
      assert.throws(function () { storage.deleteChunk("bundle-1", bad, 0); },
        /Invalid chunk path component/);
    });
  });

  it("a non-string component is refused too", function () {
    assert.throws(function () { storage.deleteChunk(null, "file-1", 0); },
      /Invalid chunk path component/);
    assert.throws(function () { storage.deleteChunk(42, "file-1", 0); },
      /Invalid chunk path component/);
  });

  it("an ordinary id is accepted", function () {
    assert.doesNotThrow(function () { storage.deleteChunk("bundle-1", "file-1", 0); });
  });
});

describe("the chunk index has to be a whole non-negative number", function () {
  // It reaches the filesystem as a directory entry name, so a fractional or
  // negative value would create an entry no reader looks for.
  // The last five coerce to 0. Checking the type before the coercion is what
  // stops an absent index from meaning "the first chunk".
  [-1, 1.5, NaN, Infinity, "two", undefined, {}, null, "", "   ", false, []]
    .forEach(function (bad, i) {
      it("case " + (i + 1) + ": " + JSON.stringify(String(bad)) + " is refused", function () {
        assert.throws(function () { storage.deleteChunk("bundle-1", "file-1", bad); },
          /Invalid chunk index/);
      });
    });

  it("zero and a numeric string are both accepted", function () {
    assert.doesNotThrow(function () { storage.deleteChunk("bundle-1", "file-1", 0); });
    assert.doesNotThrow(function () { storage.deleteChunk("bundle-1", "file-1", "3"); });
  });

  it("deleting a chunk that is not there is not an error", function () {
    assert.doesNotThrow(function () { storage.deleteChunk("bundle-1", "file-1", 99); });
  });
});

describe("statChunk refuses the same inputs rather than reporting them missing", function () {
  // It shares the path builder with deleteChunk, and shared a defect with it:
  // both computed the path inside their own catch, so a refused component came
  // back as "no such chunk". A caller reading that as "not uploaded yet" would
  // wait for a chunk that can never arrive.
  it("a component that would escape is refused, not reported absent", function () {
    assert.throws(function () { storage.statChunk("../evil", "file-1", 0); },
      /Invalid chunk path component/);
    assert.throws(function () { storage.statChunk("bundle-1", "..", 0); },
      /Invalid chunk path component/);
  });

  it("an index that is not a whole number is refused", function () {
    assert.throws(function () { storage.statChunk("bundle-1", "file-1", -1); },
      /Invalid chunk index/);
    assert.throws(function () { storage.statChunk("bundle-1", "file-1", 1.5); },
      /Invalid chunk index/);
  });

  it("a well-formed request for a chunk that is not there still answers null", function () {
    assert.strictEqual(storage.statChunk("bundle-1", "file-1", 99), null);
  });
});

describe("an S3 storage path yields the object key beneath its bucket", function () {
  it("strips the scheme and the bucket, and nothing else", function () {
    assert.strictEqual(storage.s3KeyFromPath("s3://my-bucket/bundle-1/file.bin"), "bundle-1/file.bin");
    assert.strictEqual(storage.s3KeyFromPath("s3://my.bucket.with.dots/a/b/c.bin"), "a/b/c.bin");
  });

  it("keeps a key that itself contains the bucket's name", function () {
    // Only the FIRST segment is the bucket; a naive replace-all would corrupt
    // the key of an object stored under a similarly named prefix.
    assert.strictEqual(storage.s3KeyFromPath("s3://backups/backups/2026/x.bin"), "backups/2026/x.bin");
  });

  it("leaves a local path alone, since callers gate on isS3Path first", function () {
    assert.strictEqual(storage.s3KeyFromPath("bundle-1/file.bin"), "bundle-1/file.bin");
  });
});

/**
 * lib/rotation-swap.js: the in-place swap of a vault-key rotation.
 *
 * Every rename the swap makes goes through b.atomicFile.renameWithRetry. The
 * crash tests replace it with a version that throws after N renames, for every
 * N from 0 to the number of renames a clean run makes, and then check that
 * running the same direction again, or the opposite one, ends in the expected
 * state. That is what boot recovery does after a crash.
 */
var { describe, it, after, afterEach } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var os = require("os");

var REPO_ROOT = path.resolve(__dirname, "..", "..");
var b = require(path.join(REPO_ROOT, "lib", "vendor", "blamejs"));
var C = require(path.join(REPO_ROOT, "lib", "constants"));
var rotationSwap = require(path.join(REPO_ROOT, "lib", "rotation-swap"));

var NAMES = C.DATA_DIR_INTERNAL;
var realRename = b.atomicFile.renameWithRetry;
// Created at load: the crash tests count the renames of a clean run while the
// suite is being defined, before any hook runs.
var testRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rotation-swap-"));
var seq = 0;

after(function () {
  fs.rmSync(testRoot, { recursive: true, force: true });
});
afterEach(function () {
  b.atomicFile.renameWithRetry = realRename;
});

function writeTree(root, tree) {
  Object.keys(tree).forEach(function (rel) {
    var p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, tree[rel]);
  });
}

// relative path → contents, for every file under root
function snapshot(root, skipTop) {
  var out = {};
  (function walk(rel) {
    fs.readdirSync(path.join(root, rel), { withFileTypes: true }).forEach(function (ent) {
      if (!rel && skipTop && skipTop(ent.name)) return;
      var r = rel ? rel + "/" + ent.name : ent.name;
      if (ent.isDirectory()) walk(r);
      else out[r] = fs.readFileSync(path.join(root, r), "utf8");
    });
  })("");
  return out;
}

var LIVE = {
  "hermitstash.db.enc": "old database",
  "db.key.enc": "old db key",
  "vault.key": "old vault key",
  "tls/privkey.pem": "old tls key",
  "audit-archives/2026.bundle": "archive",
  "revocations.json": "[]",
};
var STAGED = {
  "hermitstash.db.enc": "new database",
  "db.key.enc": "new db key",
  "vault.key": "new vault key",
  "tls/privkey.pem": "new tls key",
  "audit-archives/2026.bundle": "archive",
  "vault.derived-hash-salt": "salt",
};

// A data directory with a built staging directory and a stale server lease.
function fixture() {
  var dataDir = path.join(testRoot, "d" + (seq++));
  writeTree(dataDir, LIVE);
  writeTree(rotationSwap.stagingPath(dataDir), STAGED);
  fs.writeFileSync(path.join(dataDir, NAMES.SERVER_LEASE), "{}");
  var marker = rotationSwap.planSwap(dataDir, "2026-10-27T10:00:00.000Z");
  rotationSwap.writeMarker(dataDir, marker);
  return { dataDir: dataDir, marker: marker, oldDir: path.join(dataDir, marker.oldDir) };
}

function crashAfter(n) {
  var calls = 0;
  b.atomicFile.renameWithRetry = function (from, to) {
    if (calls >= n) throw Object.assign(new Error("injected crash after " + n + " renames"), { code: "EIO" });
    calls++;
    return realRename(from, to);
  };
}

function countRenames(fn) {
  var calls = 0;
  b.atomicFile.renameWithRetry = function (from, to) { calls++; return realRename(from, to); };
  fn();
  b.atomicFile.renameWithRetry = realRename;
  return calls;
}

function liveView(dataDir) {
  return snapshot(dataDir, rotationSwap.isInternal);
}

function assertForwardDone(f) {
  assert.deepStrictEqual(liveView(f.dataDir), STAGED, "the data directory holds the staged entries");
  assert.deepStrictEqual(snapshot(f.oldDir), LIVE, "the old directory holds the pre-rotation entries");
  assert.ok(!fs.existsSync(rotationSwap.stagingPath(f.dataDir)), "the staging directory is gone");
  assert.strictEqual(fs.readFileSync(path.join(f.dataDir, NAMES.SERVER_LEASE), "utf8"), "{}", "the lease is not moved");
}

function assertBackDone(f) {
  assert.deepStrictEqual(liveView(f.dataDir), LIVE, "the data directory holds the pre-rotation entries again");
  assert.ok(!fs.existsSync(f.oldDir), "the old directory is gone");
  assert.ok(!fs.existsSync(rotationSwap.stagingPath(f.dataDir)), "the staging directory is gone");
  assert.strictEqual(fs.readFileSync(path.join(f.dataDir, NAMES.SERVER_LEASE), "utf8"), "{}", "the lease is not moved");
}

describe("rotation-swap: planSwap and the marker", function () {
  it("lists the live and staged entries and excludes the internal ones", function () {
    var f = fixture();
    assert.deepStrictEqual(f.marker.live, ["audit-archives", "db.key.enc", "hermitstash.db.enc", "revocations.json", "tls", "vault.key"]);
    assert.deepStrictEqual(f.marker.staged, ["audit-archives", "db.key.enc", "hermitstash.db.enc", "tls", "vault.derived-hash-salt", "vault.key"]);
    assert.strictEqual(f.marker.oldDir, NAMES.ROTATION_OLD_PREFIX + "2026-10-27T10-00-00-000Z");
    assert.deepStrictEqual(rotationSwap.readMarker(f.dataDir), f.marker);
  });

  it("refuses a marker whose entry names leave the data directory or name internal entries", function () {
    var f = fixture();
    ["../outside", "a/b", "..", "", NAMES.SERVER_LEASE, NAMES.ROTATION_OLD_PREFIX + "x"].forEach(function (bad) {
      var m = Object.assign({}, f.marker, { live: [bad] });
      assert.throws(function () { rotationSwap.rollForward(f.dataDir, m); }, /invalid entry name/, JSON.stringify(bad));
    });
    var badOld = Object.assign({}, f.marker, { oldDir: "../elsewhere" });
    assert.throws(function () { rotationSwap.rollForward(f.dataDir, badOld); }, /oldDir/);
    var badDir = Object.assign({}, f.marker, { direction: "sideways" });
    assert.throws(function () { rotationSwap.rollForward(f.dataDir, badDir); }, /direction/);
  });
});

describe("rotation-swap: clean runs", function () {
  it("rollForward swaps every entry and keeps the originals in the old directory", function () {
    var f = fixture();
    rotationSwap.rollForward(f.dataDir, f.marker);
    assertForwardDone(f);
    assert.ok(rotationSwap.hasMarker(f.dataDir), "the marker stays until clearMarker");
    rotationSwap.clearMarker(f.dataDir);
    assert.ok(!rotationSwap.hasMarker(f.dataDir));
  });

  it("rollForward run twice is a no-op the second time", function () {
    var f = fixture();
    rotationSwap.rollForward(f.dataDir, f.marker);
    assert.strictEqual(countRenames(function () { rotationSwap.rollForward(f.dataDir, f.marker); }), 0);
    assertForwardDone(f);
  });

  it("rollBack after a complete rollForward restores the original entries", function () {
    var f = fixture();
    rotationSwap.rollForward(f.dataDir, f.marker);
    rotationSwap.rollBack(f.dataDir, f.marker);
    assertBackDone(f);
  });

  it("rollBack clears the marker before it deletes the staging directory", function () {
    var f = fixture();
    rotationSwap.rollForward(f.dataDir, f.marker);
    var realRm = fs.rmSync;
    var markerAtDelete = null;
    fs.rmSync = function (p, o) {
      if (p === rotationSwap.stagingPath(f.dataDir)) markerAtDelete = rotationSwap.hasMarker(f.dataDir);
      return realRm.call(fs, p, o);
    };
    try { rotationSwap.rollBack(f.dataDir, f.marker); } finally { fs.rmSync = realRm; }
    assert.strictEqual(markerAtDelete, false);
    assertBackDone(f);
  });

  it("rollBack run again with the same marker after it finished leaves the originals in place", function () {
    var f = fixture();
    rotationSwap.rollForward(f.dataDir, f.marker);
    f.marker.direction = "backward";
    rotationSwap.writeMarker(f.dataDir, f.marker);
    rotationSwap.rollBack(f.dataDir, f.marker);
    // a stop between the moves and the marker removal leaves this marker behind
    rotationSwap.writeMarker(f.dataDir, f.marker);
    rotationSwap.rollBack(f.dataDir, f.marker);
    assertBackDone(f);
  });

  it("rollBack before any move discards the staging directory and leaves the data directory alone", function () {
    var f = fixture();
    rotationSwap.rollBack(f.dataDir, f.marker);
    assertBackDone(f);
  });
});

describe("rotation-swap: a crash after every rename", function () {
  var forwardRenames = countRenames(function () {
    var f = fixture();
    rotationSwap.rollForward(f.dataDir, f.marker);
  });

  it("a clean forward swap makes one rename per live entry and per staged entry", function () {
    // 6 top-level live entries and 6 top-level staged entries
    assert.strictEqual(forwardRenames, 12);
  });

  for (var n = 0; n < forwardRenames; n++) {
    (function (n) {
      it("forward crash after " + n + " renames: running forward again completes the swap", function () {
        var f = fixture();
        crashAfter(n);
        assert.throws(function () { rotationSwap.rollForward(f.dataDir, f.marker); }, /injected crash/);
        b.atomicFile.renameWithRetry = realRename;
        rotationSwap.rollForward(f.dataDir, rotationSwap.readMarker(f.dataDir));
        assertForwardDone(f);
      });

      it("forward crash after " + n + " renames: running backward restores the original entries", function () {
        var f = fixture();
        crashAfter(n);
        assert.throws(function () { rotationSwap.rollForward(f.dataDir, f.marker); }, /injected crash/);
        b.atomicFile.renameWithRetry = realRename;
        rotationSwap.rollBack(f.dataDir, f.marker);
        assertBackDone(f);
      });
    })(n);
  }

  it("a crash during rollBack, after every rename, is finished by running rollBack again", function () {
    var probe = fixture();
    rotationSwap.rollForward(probe.dataDir, probe.marker);
    var backRenames = countRenames(function () { rotationSwap.rollBack(probe.dataDir, probe.marker); });
    assert.ok(backRenames > 0);
    for (var m = 0; m < backRenames; m++) {
      var f = fixture();
      rotationSwap.rollForward(f.dataDir, f.marker);
      crashAfter(m);
      assert.throws(function () { rotationSwap.rollBack(f.dataDir, f.marker); }, /injected crash/);
      b.atomicFile.renameWithRetry = realRename;
      rotationSwap.rollBack(f.dataDir, f.marker);
      assertBackDone(f);
    }
  });
});

describe("rotation-swap: entries the marker does not account for", function () {
  it("rollForward refuses to move a staged entry over a file that appeared after the marker", function () {
    var f = fixture();
    fs.writeFileSync(path.join(f.dataDir, "vault.derived-hash-salt"), "foreign");
    assert.throws(function () { rotationSwap.rollForward(f.dataDir, f.marker); }, /is not an entry the rotation moved aside/);
    assert.strictEqual(fs.readFileSync(path.join(f.dataDir, "vault.derived-hash-salt"), "utf8"), "foreign");
  });

  it("rollForward refuses to delete a staging directory that holds unlisted entries", function () {
    var f = fixture();
    fs.writeFileSync(path.join(rotationSwap.stagingPath(f.dataDir), "unlisted"), "x");
    assert.throws(function () { rotationSwap.rollForward(f.dataDir, f.marker); }, /does not list: unlisted/);
    assert.ok(fs.existsSync(path.join(rotationSwap.stagingPath(f.dataDir), "unlisted")));
  });
});

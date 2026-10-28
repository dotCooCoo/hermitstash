/**
 * Boot-time rotation-marker recovery — all 5 dispatch rows from spec §6.1.
 *
 * Exercises the full lib/vault.js init() path via child_process (the only
 * way to observe process.exit(1) in FATAL branches without killing the
 * test runner).
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var os = require("os");
var crypto = require("crypto");
var b = require("../../lib/vendor/blamejs");
var { spawnSync } = require("child_process");

var testRoot = path.join(os.tmpdir(), "vault-rotate-recovery-test-" + b.crypto.generateToken(4));

before(function () {
  fs.rmSync(testRoot, { recursive: true, force: true });
  fs.mkdirSync(testRoot, { recursive: true });
});

after(function () {
  fs.rmSync(testRoot, { recursive: true, force: true });
});

var repoRoot = path.join(__dirname, "..", "..");

function hashListing(dir) {
  var { sha3Hash } = require(path.join(repoRoot, "lib", "crypto"));
  var names = fs.readdirSync(dir).slice().sort();
  return sha3Hash(names.join("\n"));
}

function runInit(dataDir) {
  // Run vault.init() in a fresh process. In plaintext mode with an existing
  // vault.key (or neither file), init() either succeeds or process.exit(1)s
  // from a FATAL recovery branch.
  var result = spawnSync(
    "node",
    ["-e",
      "var vault = require(" + JSON.stringify(path.join(repoRoot, "lib", "vault")) + ");" +
      "vault.init().then(function(){console.log('INIT_OK');}).catch(function(e){console.error('INIT_THROW:'+e.message);process.exit(2);});"
    ],
    {
      env: Object.assign({}, process.env, { HERMITSTASH_DATA_DIR: dataDir }),
      encoding: "utf8",
      timeout: 30000,
    }
  );
  return { code: result.status, stdout: result.stdout || "", stderr: result.stderr || "" };
}

describe("vault-rotate boot recovery dispatch (spec §6.1)", function () {

  it("Row 1: marker + rotating/ + data/ → crash before swap → discards rotating/ and marker", function () {
    var dataDir = path.join(testRoot, "row1");
    var rotating = dataDir + ".rotating";
    var marker = dataDir + ".rotation-pending";
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(rotating, { recursive: true });
    fs.writeFileSync(path.join(rotating, "db.key.enc"), "stub");
    fs.writeFileSync(marker, JSON.stringify({ format: 1, stagingHash: hashListing(rotating), startedAt: new Date().toISOString() }));

    var r = runInit(dataDir);
    // After recovery: rotating and marker gone; original data/ preserved
    assert.ok(fs.existsSync(dataDir), "data/ should still exist");
    assert.ok(!fs.existsSync(rotating), "rotating/ should be cleaned up");
    assert.ok(!fs.existsSync(marker), "marker should be cleaned up");
  });

  it("Row 2: marker + rotating/ + no data/ → crash between renames → completes swap", function () {
    var dataDir = path.join(testRoot, "row2");
    var rotating = dataDir + ".rotating";
    var marker = dataDir + ".rotation-pending";
    fs.mkdirSync(rotating, { recursive: true });
    fs.writeFileSync(path.join(rotating, "db.key.enc"), "stub");
    fs.writeFileSync(marker, JSON.stringify({ format: 1, stagingHash: hashListing(rotating), startedAt: new Date().toISOString() }));

    runInit(dataDir);
    // After recovery: swap completed, rotating renamed to data, marker gone
    assert.ok(fs.existsSync(dataDir), "data/ should exist (swap completed)");
    assert.ok(!fs.existsSync(rotating), "rotating/ should no longer exist");
    assert.ok(!fs.existsSync(marker), "marker should be gone");
  });

  it("Row 3: marker + no rotating/ + data/ → crash after swap → clears marker", function () {
    var dataDir = path.join(testRoot, "row3");
    var marker = dataDir + ".rotation-pending";
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.key.enc"), "stub");
    fs.writeFileSync(marker, JSON.stringify({ format: 1, stagingHash: hashListing(dataDir), startedAt: new Date().toISOString() }));

    runInit(dataDir);
    assert.ok(fs.existsSync(dataDir), "data/ preserved");
    assert.ok(!fs.existsSync(marker), "marker should be gone");
  });

  it("Row 4: marker + neither → FATAL (data missing, no auto-recovery)", function () {
    var dataDir = path.join(testRoot, "row4");
    var marker = dataDir + ".rotation-pending";
    fs.writeFileSync(marker, JSON.stringify({ format: 1, stagingHash: "x", startedAt: new Date().toISOString() }));

    var r = runInit(dataDir);
    assert.notStrictEqual(r.code, 0, "should exit non-zero");
    assert.match(r.stderr, /data directory has been lost/);
  });

  it("Row 5: no marker + both dirs → FATAL (invariant violation)", function () {
    var dataDir = path.join(testRoot, "row5");
    var rotating = dataDir + ".rotating";
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(rotating, { recursive: true });

    var r = runInit(dataDir);
    assert.notStrictEqual(r.code, 0, "should exit non-zero");
    assert.match(r.stderr, /no rotation marker/);
  });

  it("Row 2 tamper detection: stagingHash mismatch → FATAL", function () {
    var dataDir = path.join(testRoot, "row2-tamper");
    var rotating = dataDir + ".rotating";
    var marker = dataDir + ".rotation-pending";
    fs.mkdirSync(rotating, { recursive: true });
    fs.writeFileSync(path.join(rotating, "db.key.enc"), "stub");
    // Marker with WRONG hash — simulates tampering between crash and restart
    fs.writeFileSync(marker, JSON.stringify({
      format: 1,
      stagingHash: "0000000000000000000000000000000000000000000000000000000000000000",
      startedAt: new Date().toISOString(),
    }));

    var r = runInit(dataDir);
    assert.notStrictEqual(r.code, 0, "should refuse to complete swap with hash mismatch");
    assert.match(r.stderr, /fingerprint does not match/);
    // rotating/ should still be there (we didn't complete the swap)
    assert.ok(fs.existsSync(rotating), "tampered rotating/ left intact for manual inspection");
  });
});

describe("vault-rotate boot recovery: in-place swap inside the data directory", function () {
  var rotationSwap = require(path.join(repoRoot, "lib", "rotation-swap"));

  // A data directory whose rotated copy is built, with the swap marker written.
  function swapFixture(name) {
    var dataDir = path.join(testRoot, name);
    fs.mkdirSync(path.join(dataDir, "tls"), { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.key.enc"), "old");
    fs.writeFileSync(path.join(dataDir, "tls", "privkey.pem"), "old tls");
    fs.writeFileSync(path.join(dataDir, "revocations.json"), "[]");
    var staging = rotationSwap.stagingPath(dataDir);
    fs.mkdirSync(path.join(staging, "tls"), { recursive: true });
    fs.writeFileSync(path.join(staging, "db.key.enc"), "new");
    fs.writeFileSync(path.join(staging, "tls", "privkey.pem"), "new tls");
    fs.writeFileSync(path.join(staging, "revocations.json"), "[]");
    var marker = rotationSwap.planSwap(dataDir, "2026-10-27T10:00:00.000Z");
    rotationSwap.writeMarker(dataDir, marker);
    return { dataDir: dataDir, staging: staging, marker: marker, oldDir: path.join(dataDir, marker.oldDir) };
  }

  it("a forward marker after a partial swap: boot finishes the swap and clears the marker", function () {
    var f = swapFixture("inplace-forward");
    // the tool stopped after moving db.key.enc aside and the staged one in
    fs.mkdirSync(f.oldDir);
    fs.renameSync(path.join(f.dataDir, "db.key.enc"), path.join(f.oldDir, "db.key.enc"));
    fs.renameSync(path.join(f.staging, "db.key.enc"), path.join(f.dataDir, "db.key.enc"));

    var r = runInit(f.dataDir);
    assert.match(r.stdout, /Rotation-recovery: finishing an interrupted rotation swap/);
    assert.strictEqual(fs.readFileSync(path.join(f.dataDir, "db.key.enc"), "utf8"), "new");
    assert.strictEqual(fs.readFileSync(path.join(f.dataDir, "tls", "privkey.pem"), "utf8"), "new tls");
    assert.strictEqual(fs.readFileSync(path.join(f.oldDir, "db.key.enc"), "utf8"), "old");
    assert.strictEqual(fs.readFileSync(path.join(f.oldDir, "tls", "privkey.pem"), "utf8"), "old tls");
    assert.ok(!fs.existsSync(f.staging), "staging is gone");
    assert.ok(!rotationSwap.hasMarker(f.dataDir), "marker is gone");
  });

  it("a backward marker: boot moves the original entries back and discards the rotated copy", function () {
    var f = swapFixture("inplace-backward");
    rotationSwap.rollForward(f.dataDir, f.marker);
    // the tool failed its post-swap check and stopped after recording the move back
    f.marker.direction = "backward";
    rotationSwap.writeMarker(f.dataDir, f.marker);
    fs.mkdirSync(f.staging);
    fs.renameSync(path.join(f.dataDir, "tls"), path.join(f.staging, "tls"));

    var r = runInit(f.dataDir);
    assert.match(r.stdout, /Rotation-recovery: moving the pre-rotation entries back/);
    assert.strictEqual(fs.readFileSync(path.join(f.dataDir, "db.key.enc"), "utf8"), "old");
    assert.strictEqual(fs.readFileSync(path.join(f.dataDir, "tls", "privkey.pem"), "utf8"), "old tls");
    assert.ok(!fs.existsSync(f.oldDir), "old directory is gone");
    assert.ok(!fs.existsSync(f.staging), "staging is gone");
    assert.ok(!rotationSwap.hasMarker(f.dataDir), "marker is gone");
  });

  it("a staging directory without a marker: boot deletes it and leaves the data directory alone", function () {
    var dataDir = path.join(testRoot, "inplace-nomarker");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "db.key.enc"), "old");
    var staging = rotationSwap.stagingPath(dataDir);
    fs.mkdirSync(staging);
    fs.writeFileSync(path.join(staging, "db.key.enc"), "half-built");

    var r = runInit(dataDir);
    assert.match(r.stdout, /deleting .*\.rotation-staging, an incomplete rotated copy/);
    assert.ok(!fs.existsSync(staging));
    assert.strictEqual(fs.readFileSync(path.join(dataDir, "db.key.enc"), "utf8"), "old");
  });

  it("a rotation that still holds a fresh tool lease: boot refuses and leaves the staging directory", function () {
    var f = swapFixture("inplace-tool-lease");
    rotationSwap.clearMarker(f.dataDir);
    fs.writeFileSync(path.join(f.dataDir, ".server-lease"), JSON.stringify({ kind: "tool", name: "vault-key-rotate.js",
      pid: 4242, hostname: "rotator", token: "t", startedAt: "x", heartbeatAt: new Date().toISOString() }));

    var r = runInit(f.dataDir);
    assert.strictEqual(r.code, 1, "stdout: " + r.stdout + "\nstderr: " + r.stderr);
    assert.match(r.stderr, /vault-key-rotate\.js \(pid 4242 on rotator, .*\) is using /);
    assert.ok(fs.existsSync(path.join(f.staging, "db.key.enc")), "the rotated copy being built is left alone");
  });

  it("an unusable marker: boot refuses to start and changes nothing", function () {
    var f = swapFixture("inplace-badmarker");
    var bad = Object.assign({}, f.marker, { staged: ["../outside"] });
    fs.writeFileSync(rotationSwap.markerPath(f.dataDir), JSON.stringify(bad));

    var r = runInit(f.dataDir);
    assert.strictEqual(r.code, 1, "stdout: " + r.stdout + "\nstderr: " + r.stderr);
    assert.match(r.stderr, /rotation swap marker at .* cannot be used: .*invalid entry name/);
    assert.strictEqual(fs.readFileSync(path.join(f.dataDir, "db.key.enc"), "utf8"), "old");
    assert.ok(fs.existsSync(f.staging), "the rotated copy is left for inspection");
  });

  it("a swap the tool could not finish moving: boot refuses and names both directories", function () {
    var f = swapFixture("inplace-conflict");
    fs.mkdirSync(f.oldDir);
    fs.renameSync(path.join(f.dataDir, "db.key.enc"), path.join(f.oldDir, "db.key.enc"));
    // something recreated db.key.enc after the original was moved aside
    fs.writeFileSync(path.join(f.dataDir, "db.key.enc"), "foreign");

    var r = runInit(f.dataDir);
    assert.strictEqual(r.code, 1, "stdout: " + r.stdout + "\nstderr: " + r.stderr);
    assert.match(r.stderr, /could not finish the interrupted rotation swap/);
    assert.match(r.stderr, /pre-rotation entries are in .*\.rotation-old-/);
    assert.ok(rotationSwap.hasMarker(f.dataDir), "the marker is kept for the next attempt");
  });
});

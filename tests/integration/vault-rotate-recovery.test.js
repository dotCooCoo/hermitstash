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

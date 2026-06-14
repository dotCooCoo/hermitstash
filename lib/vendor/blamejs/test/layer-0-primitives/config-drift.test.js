"use strict";

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;
var setupTestDb = require("../helpers/db").setupTestDb;
var teardownTestDb = require("../helpers/db").teardownTestDb;

function _tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "config-drift-test-"));
}

async function run() {
  check("configDrift namespace present",   typeof b.configDrift === "object");
  check("configDrift.create is fn",        typeof b.configDrift.create === "function");

  // Boot a real framework instance so audit-sign is initialized — the
  // primitive depends on it for the signature.
  var tmpDir = _tmp();
  await setupTestDb(tmpDir);
  try {
    var drift = b.configDrift.create({ dataDir: tmpDir, audit: b.audit });

    var snapshot1 = {
      allowedOrigins: ["https://app.example.com"],
      csp:            "default-src 'self'",
      vaultMode:      "wrapped",
    };
    var first = await drift.checkpoint(snapshot1);
    check("first checkpoint: signed",        first.signed === true);
    check("first checkpoint: not drifted",   first.drifted === false);
    check("first checkpoint: previousAt null", first.previousAt === null);

    // Sidecar exists on disk
    check("sidecar written to disk",        fs.existsSync(path.join(tmpDir, "config-baseline.sig")));

    // Re-checkpoint same snapshot — no drift
    var same = await drift.checkpoint(snapshot1);
    check("repeat checkpoint: not drifted",  same.drifted === false);
    check("repeat checkpoint: previousAt set", typeof same.previousAt === "number");

    // Drift detected on changed snapshot
    var snapshot2 = {
      allowedOrigins: ["https://app.example.com", "https://newbie.example.com"],
      csp:            "default-src 'self'",
      vaultMode:      "wrapped",
    };
    var drifted = await drift.checkpoint(snapshot2);
    check("changed snapshot: drifted true",   drifted.drifted === true);
    check("changed snapshot: diff names changed key",
          drifted.diff && drifted.diff.changed.indexOf("allowedOrigins") !== -1);

    // Tamper detection: corrupt the sidecar
    var sidecarPath = path.join(tmpDir, "config-baseline.sig");
    var raw = fs.readFileSync(sidecarPath, "utf8");
    var parsed = JSON.parse(raw);
    parsed.snapshot.allowedOrigins.push("https://attacker.example.com");  // tamper without re-signing
    fs.writeFileSync(sidecarPath, JSON.stringify(parsed));

    var tampered = await drift.checkpoint(snapshot2);
    check("tampered sidecar: tamper:true",   tampered.tamper === true);
    check("tampered sidecar: not auto-rewritten", tampered.signed === false);

    // read() surfaces verified=false
    var readBack = drift.read();
    check("read: surfaces verified=false on tamper", readBack && readBack.verified === false);

    // Rejects non-object snapshot
    var threwBadSnap = null;
    try { await drift.checkpoint("not-an-object"); }
    catch (e) { threwBadSnap = e; }
    check("checkpoint rejects non-object snapshot", threwBadSnap !== null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function _testVerifyVendorIntegrity() {
  var result = b.configDrift.verifyVendorIntegrity();
  check("configDrift.verifyVendorIntegrity returns ok shape",
    result && typeof result.ok === "boolean" && Array.isArray(result.mismatches));
  check("configDrift.verifyVendorIntegrity: vendored files match manifest",
    result.ok === true && result.mismatches.length === 0);

  // #321: the check must be cwd-INDEPENDENT — per-file manifest paths resolve
  // under the framework's vendor dir (or an explicit libVendorDir), not
  // process.cwd(). Run it from a different working directory and it must still
  // verify the actual loaded tree (the old code read-failed every entry, or
  // under a crafted cwd could hash a different tree).
  var origCwd = process.cwd();
  var elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "config-drift-cwd-"));
  try {
    process.chdir(elsewhere);
    var fromElsewhere = b.configDrift.verifyVendorIntegrity();
    check("configDrift.verifyVendorIntegrity is cwd-independent (default vendor dir)",
      fromElsewhere.ok === true &&
      fromElsewhere.checkedCount === result.checkedCount &&
      fromElsewhere.mismatches.length === 0);
  } finally {
    process.chdir(origCwd);
    try { fs.rmSync(elsewhere, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

module.exports = { run: async function () { await run(); await _testVerifyVendorIntegrity(); } };

if (require.main === module) {
  module.exports.run().then(
    function () { console.log("[config-drift] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}

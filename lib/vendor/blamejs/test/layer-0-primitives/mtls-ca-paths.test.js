"use strict";
/**
 * b.mtlsCa.create — opts.paths resolution.
 *
 * Pre-v0.8.58 _resolvePaths always joined every entry under dataDir,
 * silently overriding an operator-supplied absolute path. v0.8.58
 * preserves absolute paths (Node `path.join` semantics) so an
 * operator can point caKey / caCert at a fixed mount outside the
 * dataDir without the framework rewriting the location.
 */

var helpers = require("../helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;

function _mkDir(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)); }

async function testAbsolutePathHonored() {
  var dataDir = _mkDir("mtls-d-");
  var certDir = _mkDir("mtls-c-");
  // Pre-create files at the absolute path so .exists() can confirm.
  fs.writeFileSync(path.join(certDir, "ca.crt"), "TEST CRT");
  fs.writeFileSync(path.join(certDir, "ca.key"), "TEST KEY");
  var ca = b.mtlsCa.create({
    dataDir:          dataDir,
    caKeySealedMode:  "disabled",
    paths: {
      caKey:  path.join(certDir, "ca.key"),
      caCert: path.join(certDir, "ca.crt"),
    },
  });
  check("absolute caCert path passes through unchanged",
    ca.paths.caCert === path.join(certDir, "ca.crt"));
  check("absolute caKey path passes through unchanged",
    ca.paths.caKey === path.join(certDir, "ca.key"));
  check("exists() returns true when CA files are at the resolved absolute paths",
    ca.exists() === true);
}

async function testRelativePathStillJoinsUnderDataDir() {
  var dataDir = _mkDir("mtls-d-");
  var ca = b.mtlsCa.create({
    dataDir:          dataDir,
    caKeySealedMode:  "disabled",
    paths: {
      caKey:  "ca.key",
      caCert: "ca.crt",
    },
  });
  check("relative caCert joins under dataDir (back-compat)",
    ca.paths.caCert === path.join(dataDir, "ca.crt"));
  check("relative caKey joins under dataDir (back-compat)",
    ca.paths.caKey === path.join(dataDir, "ca.key"));
}

async function testMixedAbsoluteRelative() {
  var dataDir = _mkDir("mtls-d-");
  var keyDir  = _mkDir("mtls-k-");
  var ca = b.mtlsCa.create({
    dataDir:          dataDir,
    caKeySealedMode:  "disabled",
    paths: {
      caKey:  path.join(keyDir, "rotated.key"),   // absolute → honored
      caCert: "ca.crt",                            // relative → joins
    },
  });
  check("absolute caKey honored",
    ca.paths.caKey === path.join(keyDir, "rotated.key"));
  check("relative caCert joined under dataDir",
    ca.paths.caCert === path.join(dataDir, "ca.crt"));
}

async function run() {
  await testAbsolutePathHonored();
  await testRelativePathStillJoinsUnderDataDir();
  await testMixedAbsoluteRelative();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}

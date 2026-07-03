// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * object-store versioned-delete surface — the cross-backend contract for the
 * S3 Object-Lock erasure workflow (#88), exercised WITHOUT a live S3. The
 * full enforcement proof (a COMPLIANCE-retained version's delete is refused)
 * lives in test/integration/object-store-worm-lock.test.js against MinIO;
 * this layer-0 test pins the parts that hold on any host:
 *
 *   - sigv4 exposes listVersions + a versionId-aware delete;
 *   - non-S3 backends (local) have NO version surface and REFUSE a versioned
 *     delete loudly (VERSIONID_UNSUPPORTED) rather than silently dropping the
 *     current object — a silent drop on an erasure path is the footgun;
 *   - the facade feature-detects listVersions (null on backends without it).
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var os = require("../../lib/object-store");
var nodeOs = require("os");
var nodePath = require("path");
var nodeFs = require("fs");

function _sigv4() {
  return os.buildBackend({
    name: "t", protocol: "sigv4", endpoint: "https://s3.local", region: "us-east-1",
    bucket: "b", accessKeyId: "AK", secretAccessKey: "SK", allowInternal: true,
    forcePathStyle: true, classifications: ["operational"], residencyTag: "unrestricted",
  });
}
function _local() {
  return os.buildBackend({
    name: "l", protocol: "local",
    rootDir: nodePath.join(nodeOs.tmpdir(), "bjv-" + process.pid + "-" + Math.floor(Math.random() * 1e6)),
    classifications: ["operational"], residencyTag: "unrestricted",
  });
}

async function run() {
  var sig = _sigv4();
  check("sigv4 facade exposes listVersions()", typeof sig.listVersions === "function");
  check("sigv4 raw deleteKey is versionId-aware (arity 2)", sig.raw.delete.length === 2);
  check("sigv4 raw exposes listVersions()", typeof sig.raw.listVersions === "function");

  var loc = _local();
  check("local facade reports no listVersions (feature-detect → null)", loc.listVersions === null);

  // http-put is the fifth backend (a bare PUT/DELETE target, no version
  // surface) — it must refuse a versioned delete loudly too, not forward a
  // dropped versionId to a plain DELETE (the gap Codex P2 caught on PR #319).
  var httpPut = os.buildBackend({
    name: "h", protocol: "http-put", baseUrl: "https://up.invalid/bucket",
    classifications: ["operational"], residencyTag: "unrestricted",
  });
  check("http-put facade reports no listVersions (feature-detect → null)", httpPut.listVersions === null);
  var hpThrew = null;
  try { await httpPut.delete("some-key", { versionId: "v1" }); }
  catch (e) { hpThrew = e; }
  check("http-put versioned delete REFUSES loudly (VERSIONID_UNSUPPORTED)",
    hpThrew && hpThrew.code === "VERSIONID_UNSUPPORTED");

  // A versioned delete on a backend with no version surface must THROW, not
  // silently unlink the single on-disk file and report a version erased.
  var threw = null;
  try { await loc.delete("some-key", { versionId: "v1" }); }
  catch (e) { threw = e; }
  check("local versioned delete REFUSES loudly (VERSIONID_UNSUPPORTED)",
    threw && threw.code === "VERSIONID_UNSUPPORTED");

  // An UNVERSIONED local delete still works normally (returns false for a
  // missing key) — the guard only fires when versionId is actually passed.
  var missing = await loc.delete("definitely-absent-" + process.pid);
  check("local unversioned delete still works (false for a missing key)", missing === false);

  // b.storage.listVersions — the routed public facade. Against a local
  // backend (no version surface) it refuses loudly with VERSIONS_UNSUPPORTED,
  // the same contract as the backend level, so an erasure workflow can never
  // mistake a single-version backend for a fully-enumerated one.
  var sdir = nodePath.join(nodeOs.tmpdir(), "bjv-storage-" + process.pid + "-" + Math.floor(Math.random() * 1e6));
  nodeFs.mkdirSync(sdir, { recursive: true });
  b.storage.init({ backend: "local", uploadDir: sdir });
  var lvThrew = null;
  try { await b.storage.listVersions("any/prefix/"); }
  catch (e) { lvThrew = e; }
  check("b.storage.listVersions refuses on a no-version backend (VERSIONS_UNSUPPORTED)",
    lvThrew && lvThrew.code === "VERSIONS_UNSUPPORTED");
  b.storage._resetForTest();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

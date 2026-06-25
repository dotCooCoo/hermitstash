"use strict";
/**
 * b.selfUpdate.poll — the GitHub release asset `digest` field must reach
 * the returned asset object.
 *
 * The GitHub releases API includes `assets[].digest` (e.g.
 * "sha256:<hex>") on each asset. poll() returned each matched asset as
 * { name, url, size } and dropped digest, so a consumer could not do a
 * defense-in-depth in-flight integrity check against the release-
 * published digest. This drives the real b.selfUpdate.poll consumer
 * path against a local http.Server fixture (no live GitHub) and asserts
 * the returned asset / signature objects expose `digest`.
 *
 * Run standalone: `node test/layer-0-primitives/self-update-poll-asset-digest.test.js`
 */

var http    = require("http");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _serveJson(payload) {
  return http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(payload));
  });
}

var ASSET_DIGEST = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
var SIG_DIGEST   = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

async function testPollExposesAssetDigest() {
  var server = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "blamejs-2.0.0.tar.gz",     browser_download_url: "https://example.invalid/asset.tgz", size: 1024, digest: ASSET_DIGEST },
      { name: "blamejs-2.0.0.tar.gz.sig", browser_download_url: "https://example.invalid/asset.sig", size: 64,   digest: SIG_DIGEST },
    ],
  });
  var port = await b.testing.listenOnRandomPort(server);
  try {
    var r = await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port + "/releases/latest",
      currentVersion:   "v1.0.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
    check("poll: available=true",          r.available === true);
    check("poll: asset selected",          r.asset && r.asset.name === "blamejs-2.0.0.tar.gz");
    check("poll: asset.digest exposed",     r.asset && r.asset.digest === ASSET_DIGEST);
    check("poll: signature selected",      r.signature && r.signature.name === "blamejs-2.0.0.tar.gz.sig");
    check("poll: signature.digest exposed", r.signature && r.signature.digest === SIG_DIGEST);
  } finally { server.close(); }
}

async function testPollDigestNullWhenAbsent() {
  // Upstream omits digest — the returned object must expose digest: null
  // (the field is present, defense-in-depth check is skipped).
  var server = _serveJson({
    tag_name: "v2.0.0",
    assets: [
      { name: "blamejs-2.0.0.tar.gz", browser_download_url: "https://example.invalid/asset.tgz", size: 1024 },
    ],
  });
  var port = await b.testing.listenOnRandomPort(server);
  try {
    var r = await b.selfUpdate.poll({
      releasesUrl:      "http://127.0.0.1:" + port + "/releases/latest",
      currentVersion:   "v1.0.0",
      allowedProtocols: ["http:"],
      allowInternal:    true,
    });
    check("poll: asset selected (no digest upstream)", r.asset && r.asset.name === "blamejs-2.0.0.tar.gz");
    check("poll: asset.digest is null when absent",    r.asset && r.asset.digest === null);
  } finally { server.close(); }
}

async function run() {
  await testPollExposesAssetDigest();
  await testPollDigestNullWhenAbsent();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e.message); process.exit(1); }
  );
}

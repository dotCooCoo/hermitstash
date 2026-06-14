"use strict";
/**
 * Live GCS object-store round-trip against the docker-compose fake-gcs
 * fixture (fsouza/fake-gcs-server, TLS-terminated with the test CA).
 *
 * What this proves: the framework's GCS JSON-API client
 * (lib/object-store/gcs.js) marshals create-bucket / upload / download /
 * list / head / delete onto the real GCS wire shape, routes them to a
 * configurable endpoint, parses the real JSON responses, and round-trips
 * bytes unchanged — over TLS, trusting the test CA with no
 * rejectUnauthorized override anywhere.
 *
 * The OAuth2 hop. The framework ALWAYS exchanges the service-account
 * RSA-SHA256-signed JWT for an access token before any storage call
 * (gcs.js _ensureToken). fake-gcs has no token endpoint (POST /token →
 * 404), so it cannot be targeted on its own — the client would fail at
 * AUTH_FAILED before reaching the storage API. The framework exposes
 * `config.tokenEndpoint` to point the OAuth2 leg elsewhere; this test
 * stands up a tiny in-process HTTPS token issuer using the test CA's
 * own gcs.crt / gcs.key (valid for 127.0.0.1, CA-signed, so the
 * framework's http-client trusts it via NODE_EXTRA_CA_CERTS — no
 * bypass). The framework's real OAuth2 wire exchange (JWT assertion
 * POST, x-www-form-urlencoded, parse access_token) runs end-to-end over
 * TLS against that issuer; every storage call then carries the issued
 * bearer to fake-gcs.
 *
 * Honest scope — what is NOT proven here:
 *   - fake-gcs does NOT verify the bearer token or any signature; the
 *     in-test issuer does NOT verify the JWT assertion. So this is a
 *     wire / URL / JSON-marshalling / TLS-trust / endpoint-routing /
 *     OAuth2-exchange-shape proof, NOT a token- or signature-CORRECTNESS
 *     proof (RSA-SHA256 JWT signing + V4 presign signing stay covered by
 *     unit vectors in the layer-0 suite).
 *   - bucket DELETE: real GCS returns 204; fake-gcs returns 200 on an
 *     existing bucket (an emulator quirk). The framework correctly
 *     accepts 204 / 404 and refuses the unexpected 200, so we assert the
 *     correct delete-missing path (404 → false) against fake-gcs and
 *     leave the created bucket for the container reset to sweep rather
 *     than assert against the emulator's non-spec status.
 */
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var https = require("node:https");
var nodeCrypto = require("node:crypto");
var child = require("node:child_process");
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

// A service account whose RSA keypair is generated fresh per run — the
// JWT signing path in gcs.js is exercised for real even though neither
// the local issuer nor fake-gcs verifies the assertion.
function _serviceAccount() {
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    type:           "service_account",
    project_id:     "blamejs-emu-project",
    client_email:   "emu-sa@blamejs-emu-project.iam.gserviceaccount.com",
    private_key:    pair.privateKey,
    private_key_id: "emu-key-001",
  };
}

// Copy a file out of the certs volume into the host tmpdir via a running
// container (dev tooling — same mechanism services.exportCaCert uses).
function _exportCert(name, dest) {
  return new Promise(function (resolve, reject) {
    var p = child.spawn("docker", ["cp", "blamejs-test-gcs:/certs/" + name, dest], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    var err = "";
    p.stderr.on("data", function (d) { err += d.toString(); });
    p.on("close", function (code) {
      if (code !== 0) return reject(new Error("docker cp " + name + " failed (exit " + code + "): " + err.trim()));
      resolve(dest);
    });
    p.on("error", reject);
  });
}

// In-process HTTPS token issuer using the CA-signed gcs cert (valid for
// 127.0.0.1). Returns { url, hits(), close() }. The framework's
// http-client trusts it via NODE_EXTRA_CA_CERTS; no rejectUnauthorized
// override is set anywhere.
async function _startTokenIssuer() {
  var tmp = os.tmpdir();
  var crtPath = path.join(tmp, "blamejs-gcs-issuer.crt");
  var keyPath = path.join(tmp, "blamejs-gcs-issuer.key");
  await _exportCert("gcs.crt", crtPath);
  await _exportCert("gcs.key", keyPath);
  var hits = 0;
  var lastAssertionSeen = false;
  var srv = https.createServer({
    cert: fs.readFileSync(crtPath),
    key:  fs.readFileSync(keyPath),
  }, function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var body = Buffer.concat(chunks).toString("utf8");
      // Confirm the framework actually sent the JWT-bearer assertion the
      // real OAuth2 service-account flow requires.
      if (/grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer/.test(body) &&
          /assertion=/.test(body)) {
        lastAssertionSeen = true;
      }
      hits++;
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ access_token: "emu-access-token", expires_in: 3600 }));
    });
  });
  await new Promise(function (resolve) { srv.listen(0, "127.0.0.1", resolve); });
  var port = srv.address().port;
  return {
    url:      "https://127.0.0.1:" + port + "/token",
    hits:     function () { return hits; },
    sawJwtAssertion: function () { return lastAssertionSeen; },
    close:    function () { return new Promise(function (r) { srv.close(r); }); },
  };
}

async function _runRoundTrip(issuer) {
  var sa = _serviceAccount();
  var endpoint = services.URLS.gcs;            // https://127.0.0.1:4443
  var bucket   = "blamejs-gcs-live-" + Date.now();
  var common = {
    serviceAccount: sa,
    endpoint:       endpoint,
    tokenEndpoint:  issuer.url,
    allowInternal:  true,
    timeoutMs:      8000,
  };

  // ---- bucket create ----
  var ops = b.objectStore.bucketOps.create(Object.assign({
    protocol:  "gcs",
    projectId: sa.project_id,
  }, common));
  var created = await ops.create(bucket, { location: "US" });
  check("bucketOps.create returns the bucket name", created.name === bucket);
  check("OAuth2 token exchange happened before the storage call",
        issuer.hits() >= 1);
  check("framework sent the JWT-bearer assertion on the OAuth2 leg",
        issuer.sawJwtAssertion() === true);

  // ---- backend put / get / list / head / delete ----
  var backend = b.objectStore.buildBackend(Object.assign({
    name:            "gcs-live",
    protocol:        "gcs",
    bucket:          bucket,
    classifications: ["operational"],
    residencyTag:    "unrestricted",
  }, common));

  var key     = "obj-" + Math.floor(Math.random() * 1e6) + ".bin";
  var payload = nodeCrypto.randomBytes(4096);

  var putRv = await backend.put(key, payload, { contentType: "application/octet-stream" });
  check("put: returned a size", putRv && putRv.size === payload.length);

  var got = await backend.get(key);
  var gotBuf = Buffer.isBuffer(got) ? got : (got && got.body);
  check("get: bytes round-trip exactly (byte-identical)",
        Buffer.isBuffer(gotBuf) && Buffer.compare(gotBuf, payload) === 0);

  var listing = await backend.list("obj-");
  check("list: returns { items } shape",
        listing && Array.isArray(listing.items));
  check("list: surfaces the just-put object key",
        listing.items.some(function (it) { return it.key === key; }));
  check("list: item size matches the payload length",
        listing.items.some(function (it) { return it.key === key && it.size === payload.length; }));

  var emptyListing = await backend.list("does-not-exist-prefix-");
  check("list: non-matching prefix returns empty items",
        emptyListing && Array.isArray(emptyListing.items) && emptyListing.items.length === 0);

  var meta = await backend.head(key);
  check("head: size matches the payload length", meta && meta.size === payload.length);

  var del = await backend.delete(key);
  check("delete: returned true", del === true);

  var afterDelete = await backend.list("obj-");
  check("list after delete: object is gone",
        !afterDelete.items.some(function (it) { return it.key === key; }));

  // get on the deleted key surfaces a 404 — the framework rejects with
  // an ObjectStoreError carrying statusCode 404 (not a silent empty).
  var notFound = null;
  try { await backend.get(key); } catch (e) { notFound = e; }
  check("get on deleted key throws (404 surfaced, not swallowed)",
        notFound && (notFound.statusCode === 404 ||
                     /404|not.?found/i.test(String(notFound.message || notFound.code || ""))));

  // ---- bucket delete-missing path (correct against fake-gcs: 404 → false) ----
  var delMissing = await ops.delete("blamejs-gcs-never-existed-" + Date.now());
  check("bucketOps.delete on a missing bucket returns false (404 path)",
        delMissing === false);

  // Best-effort cleanup of the created bucket. Real GCS returns 204 on
  // bucket DELETE; fake-gcs returns 200 (an emulator quirk the framework
  // correctly refuses as UNEXPECTED_STATUS), so this throw is expected
  // against the emulator and is NOT a framework defect. The bucket name
  // carries Date.now() so re-runs don't collide; the container reset
  // sweeps it.
  try { await ops.delete(bucket); } catch (_e) { /* fake-gcs 200-on-delete quirk */ }
}

async function run() {
  var svc = await services.requireService("gcs");
  if (!svc.ok) throw new Error("fake-gcs unreachable: " + svc.reason);
  // exportCaCert is what the runner already relies on for NODE_EXTRA_CA_CERTS;
  // calling it keeps this test self-contained if run directly.
  await services.exportCaCert();

  var issuer = await _startTokenIssuer();
  try {
    await _runRoundTrip(issuer);
  } finally {
    await issuer.close();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

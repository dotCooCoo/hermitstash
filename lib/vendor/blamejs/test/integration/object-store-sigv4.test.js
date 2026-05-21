"use strict";
/**
 * Live S3 round-trip against the docker-compose MinIO fixtures.
 * Covers BOTH the plain HTTP listener (minio:9000) and the TLS listener
 * (minio-tls:9443) so the framework's sigv4 signer + S3 client are
 * exercised end-to-end against real AWS-compatible servers.
 *
 * No security bypass: the TLS leg pins the test CA via opts.ca on
 * the request layer (rejectUnauthorized stays on by default).
 */
var fs = require("node:fs");
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

var REGION = "us-east-1";
var ACCESS = "blamejs";
var SECRET = "blamejs_test_password";

function _runOnEndpoint(label, endpoint, extraConfig) {
  var bucket = "blamejs-test-" + label + "-" + Date.now();
  var key    = "obj-" + Math.floor(Math.random() * 1e6) + ".txt";
  var payload = Buffer.from("integration payload " + new Date().toISOString(), "utf8");

  return (async function () {
    var opsCfg = Object.assign({
      protocol:        "sigv4",
      endpoint:        endpoint,
      region:          REGION,
      accessKeyId:     ACCESS,
      secretAccessKey: SECRET,
      allowInternal:   true,
      forcePathStyle:  true,
    }, extraConfig);
    var ops = b.objectStore.bucketOps.create(opsCfg);
    await ops.create(bucket);
    check("[" + label + "] bucketOps.create: bucket created", true);

    var beCfg = Object.assign({
      name:            "minio-" + label,
      protocol:        "sigv4",
      endpoint:        endpoint,
      region:          REGION,
      bucket:          bucket,
      accessKeyId:     ACCESS,
      secretAccessKey: SECRET,
      allowInternal:   true,
      forcePathStyle:  true,
      classifications: ["operational"],
      residencyTag:    "unrestricted",
    }, extraConfig);
    var backend = b.objectStore.buildBackend(beCfg);

    // ---- put + get round-trip ----
    var putRv = await backend.put(key, payload, { contentType: "text/plain" });
    check("[" + label + "] put: returned (no throw)", true);
    check("[" + label + "] put: surfaced an etag or key",
          !!(putRv && (putRv.key === key || putRv.etag || putRv.location)));

    var got = await backend.get(key);
    var gotBuf = Buffer.isBuffer(got) ? got : (got && got.body);
    check("[" + label + "] get: bytes round-trip exactly",
          Buffer.isBuffer(gotBuf) && Buffer.compare(gotBuf, payload) === 0);

    // ---- list (correct signature: list(prefix, opts), prefix is a string) ----
    var listing = await backend.list("obj-");
    check("[" + label + "] list: returns { items } shape",
          listing && Array.isArray(listing.items));
    check("[" + label + "] list: surfaces the just-put object",
          listing.items.some(function (it) { return it.key === key; }));
    check("[" + label + "] list: item has size matching the payload",
          listing.items.some(function (it) {
            return it.key === key && it.size === payload.length;
          }));

    // ---- list with non-matching prefix returns empty ----
    var emptyListing = await backend.list("does-not-exist-");
    check("[" + label + "] list: non-matching prefix returns empty items",
          emptyListing && Array.isArray(emptyListing.items) && emptyListing.items.length === 0);

    // ---- delete + verify gone ----
    await backend.delete(key);
    check("[" + label + "] delete: returned (no throw)", true);
    var afterDelete = await backend.list("obj-");
    check("[" + label + "] list after delete: object gone",
          !afterDelete.items.some(function (it) { return it.key === key; }));

    // ---- multipart upload + round-trip (covers the v0.6.50 ?uploads
    // wire-form fix; until now multipart had only mock-server coverage). ----
    var bigBackendCfg = Object.assign({}, beCfg, {
      name:                    "minio-mp-" + label,
      multipartThresholdBytes: 1,                   // force multipart for any > 0 byte
      partSizeBytes:           5 * 1024 * 1024,     // S3 minimum
    });
    var bigBackend = b.objectStore.buildBackend(bigBackendCfg);
    var bigKey     = "mp-" + Math.floor(Math.random() * 1e6) + ".bin";
    // 6 MiB → 2 parts (5 MiB + 1 MiB) so we exercise the multi-part loop
    // not the single-part edge case.
    var bigPayload = Buffer.alloc(6 * 1024 * 1024, 0x55);
    await bigBackend.put(bigKey, bigPayload, { contentType: "application/octet-stream" });
    check("[" + label + "] multipart put: returned (no throw)", true);
    var bigGot = await bigBackend.get(bigKey);
    var bigBuf = Buffer.isBuffer(bigGot) ? bigGot : (bigGot && bigGot.body);
    check("[" + label + "] multipart get: bytes round-trip exactly",
          Buffer.isBuffer(bigBuf) && Buffer.compare(bigBuf, bigPayload) === 0);
    await bigBackend.delete(bigKey);

    // v0.6.51 — getObjectLockConfiguration on a non-lock-enabled bucket
    // returns clean { enabled: false, ... } instead of throwing the
    // underlying S3 ObjectLockConfigurationNotFoundError. Run this
    // before delete (bucket must still exist).
    var nonLockOps = b.objectStore.bucketOps.create(opsCfg);
    var nonLockBucket = "blamejs-nolock-" + label + "-" + Date.now();
    await nonLockOps.create(nonLockBucket);
    var nonLockCfg = await nonLockOps.getObjectLockConfiguration(nonLockBucket);
    check("[" + label + "] getObjectLockConfiguration on non-lock bucket: enabled=false",
          nonLockCfg.enabled === false);
    check("[" + label + "] getObjectLockConfiguration on non-lock bucket: mode=null",
          nonLockCfg.mode === null);
    await nonLockOps.delete(nonLockBucket);

    await ops.delete(bucket);
    check("[" + label + "] bucketOps.delete: bucket dropped", true);
  })();
}

// Object Lock surface — bucket created with objectLockEnabled: true.
// Exercises the v0.6.47 surface (setObjectLockConfiguration / set+get
// ObjectRetention / set+get ObjectLegalHold) AND the v0.6.49 wire-form
// fix where the trailing `=` after subresource queries (`?retention=`,
// `?legal-hold=`, `?object-lock=`) caused MinIO + strict S3 to interpret
// the request as a body PUT and reject it with "Object is WORM
// protected and cannot be overwritten" instead of routing to the
// retention/legal-hold handler.
function _runObjectLockOnEndpoint(label, endpoint, extraConfig) {
  var bucket = "blamejs-lock-" + label + "-" + Date.now();
  return (async function () {
    var opsCfg = Object.assign({
      protocol:        "sigv4",
      endpoint:        endpoint,
      region:          REGION,
      accessKeyId:     ACCESS,
      secretAccessKey: SECRET,
      allowInternal:   true,
      forcePathStyle:  true,
    }, extraConfig);
    var ops = b.objectStore.bucketOps.create(opsCfg);

    await ops.create(bucket, { objectLockEnabled: true });
    check("[lock-" + label + "] create with objectLockEnabled", true);

    // v0.6.51 — get*-on-unset-state returns clean defaults instead of
    // throwing. Lock-enabled bucket but no default-rule → enabled:true,
    // mode:null. Object that's never had retention/legal-hold set → null
    // / "OFF".
    var initialLockCfg = await ops.getObjectLockConfiguration(bucket);
    check("[lock-" + label + "] no-default-rule lock-bucket: enabled=true",
          initialLockCfg.enabled === true);
    check("[lock-" + label + "] no-default-rule lock-bucket: mode=null",
          initialLockCfg.mode === null);

    var beCfg = Object.assign({
      name:            "minio-lock-" + label,
      protocol:        "sigv4",
      endpoint:        endpoint,
      region:          REGION,
      bucket:          bucket,
      accessKeyId:     ACCESS,
      secretAccessKey: SECRET,
      allowInternal:   true,
      forcePathStyle:  true,
      classifications: ["operational"],
      residencyTag:    "unrestricted",
    }, extraConfig);
    var backend = b.objectStore.buildBackend(beCfg);

    // Put an object first so we have a target for retention + legal hold
    // before we configure bucket-level retention (otherwise auto-applied
    // retention from the bucket config makes the object immutable).
    var key = "compliance-doc.txt";
    await backend.put(key, Buffer.from("filing-2026-Q1"));
    check("[lock-" + label + "] put object", true);

    // v0.6.51 — pre-set state, get*-on-object returns clean defaults.
    var preRet = await ops.getObjectRetention(bucket, key);
    check("[lock-" + label + "] no-retention object: mode=null",
          preRet.mode === null && preRet.retainUntil === null);
    var preLh = await ops.getObjectLegalHold(bucket, key);
    check("[lock-" + label + "] no-legal-hold object: status=OFF",
          preLh.status === "OFF");

    // Per-object retention.
    var retainUntil = new Date(Date.now() + 5000);  // 5 s
    var setRet = await ops.setObjectRetention(bucket, key, {
      mode:        "GOVERNANCE",
      retainUntil: retainUntil,
    });
    check("[lock-" + label + "] setObjectRetention applied",
          setRet.applied === true);

    var gotRet = await ops.getObjectRetention(bucket, key);
    check("[lock-" + label + "] getObjectRetention mode echoed",
          gotRet.mode === "GOVERNANCE");
    check("[lock-" + label + "] getObjectRetention retainUntil is Date",
          gotRet.retainUntil instanceof Date && !isNaN(gotRet.retainUntil.getTime()));

    // Per-object legal hold.
    var setLh = await ops.setObjectLegalHold(bucket, key, "ON");
    check("[lock-" + label + "] setObjectLegalHold ON applied",
          setLh.applied === true);
    var gotLh = await ops.getObjectLegalHold(bucket, key);
    check("[lock-" + label + "] getObjectLegalHold reads ON",
          gotLh.status === "ON");

    // (We don't assert that delete() blocks while legal hold is ON
    // because Object-Lock buckets are versioned — `delete()` creates a
    // delete-marker version regardless of legal hold; the *actual* data
    // version remains protected. Asserting framework-level success is
    // not the right WORM test; real protection is verified by the
    // setObjectLegalHold round-trip + getObjectLegalHold readback above.)

    // Bucket-level default retention.
    var setLockCfg = await ops.setObjectLockConfiguration(bucket, {
      mode:  "GOVERNANCE",
      days:  1,
    });
    check("[lock-" + label + "] setObjectLockConfiguration applied",
          setLockCfg.applied === true);
    var gotLockCfg = await ops.getObjectLockConfiguration(bucket);
    check("[lock-" + label + "] getObjectLockConfiguration enabled",
          gotLockCfg.enabled === true);
    check("[lock-" + label + "] getObjectLockConfiguration mode echoed",
          gotLockCfg.mode === "GOVERNANCE");
    check("[lock-" + label + "] getObjectLockConfiguration days echoed",
          gotLockCfg.days === 1);

    // Cleanup: legal hold OFF, bypassGovernance to shorten retention,
    // wait for retention to lapse, then delete object + bucket.
    await ops.setObjectLegalHold(bucket, key, "OFF");
    await ops.setObjectRetention(bucket, key, {
      mode:               "GOVERNANCE",
      retainUntil:        new Date(Date.now() + 1500),
      bypassGovernance:   true,
    });
    check("[lock-" + label + "] bypassGovernance shortens retention", true);
    // 1.5s retention was set above + bypassGovernance; wait past it so
    // the subsequent delete is permitted under the shortened lock.
    await helpers.passiveObserve(2000, "object-store-sigv4: WORM retention expires for delete");
    await backend.delete(key);
    // Object-Lock buckets are versioned, so the delete above creates a
    // delete-marker rather than removing the versioned data — `bucketOps
    // .delete` (DELETE /bucket) refuses to drop a bucket with noncurrent
    // versions or delete-markers (S3 spec). The framework doesn't expose
    // a recursive delete (operators with that need reach for `aws s3 rb
    // --force` or Terraform), so leave the bucket. The test bucket name
    // includes Date.now() so re-runs don't collide; MinIO container reset
    // sweeps it.
    try { await ops.delete(bucket); } catch (_e) { /* expected on WORM bucket */ }
    check("[lock-" + label + "] cleanup OK", true);
  })();
}

// Presigned download URL with response-header overrides
// (v0.8.53 — `responseHeaders: { contentDisposition?, contentType?,
// contentLanguage?, contentEncoding?, cacheControl?, expires? }` adds
// the S3 response-* query-param overrides to the signed URL so a
// presigned GET overrides Content-Disposition / Content-Type /
// Cache-Control etc. on the wire regardless of how the object was
// stored. Round-trip against the live MinIO endpoint to confirm both
// (a) the framework's signing math stays valid with the extra params
// in canonicalQueryString, and (b) the server actually honors the
// overrides on the response).
function _runPresignResponseHeadersOnEndpoint(label, endpoint, extraConfig) {
  var bucket = "blamejs-test-presign-rh-" + label + "-" + Date.now();
  return (async function () {
    var opsCfg = Object.assign({
      protocol:        "sigv4",
      endpoint:        endpoint,
      region:          REGION,
      accessKeyId:     ACCESS,
      secretAccessKey: SECRET,
      allowInternal:   true,
      forcePathStyle:  true,
    }, extraConfig);
    var ops = b.objectStore.bucketOps.create(opsCfg);
    await ops.create(bucket);

    var beCfg = Object.assign({
      name:            "minio-presign-rh-" + label,
      protocol:        "sigv4",
      endpoint:        endpoint,
      region:          REGION,
      bucket:          bucket,
      accessKeyId:     ACCESS,
      secretAccessKey: SECRET,
      allowInternal:   true,
      forcePathStyle:  true,
      classifications: ["operational"],
      residencyTag:    "unrestricted",
    }, extraConfig);
    var backend = b.objectStore.buildBackend(beCfg);

    var key = "presign-rh-" + Math.floor(Math.random() * 1e6) + ".bin";
    var payload = Buffer.from("hello presign", "utf8");
    await backend.put(key, payload, { contentType: "application/octet-stream" });

    var presigned = backend.presignedDownloadUrl({
      key:           key,
      expiresIn:     300,
      responseHeaders: {
        contentDisposition: 'attachment; filename="invoice.pdf"',
        contentType:        "application/pdf",
        cacheControl:       "no-store",
      },
    });
    check("[presign-rh-" + label + "] response-content-disposition in URL",
      presigned.url.indexOf("response-content-disposition=") !== -1);
    check("[presign-rh-" + label + "] response-content-type in URL",
      presigned.url.indexOf("response-content-type=") !== -1);
    check("[presign-rh-" + label + "] response-cache-control in URL",
      presigned.url.indexOf("response-cache-control=") !== -1);
    var plain = backend.presignedDownloadUrl({ key: key, expiresIn: 300 });
    check("[presign-rh-" + label + "] response-headers signature differs from no-overrides path",
      new URL(plain.url).searchParams.get("X-Amz-Signature") !==
      new URL(presigned.url).searchParams.get("X-Amz-Signature"));

    // Live GET — confirm the server actually honors the overrides
    // and the SigV4 signature stays valid with the extra params. The
    // runner (scripts/test-integration.js) sets NODE_EXTRA_CA_CERTS so
    // the TLS handshake against minio-tls:9443 trusts the docker
    // volume's CA without a rejectUnauthorized override.
    var rh = await b.httpClient.request({
      url: presigned.url,
      method: "GET",
      allowedProtocols: ["http:", "https:"],
      allowInternal: true,
    });
    check("[presign-rh-" + label + "] GET succeeds (signature valid)",
      rh.statusCode === 200);
    check("[presign-rh-" + label + "] server honors response-content-type",
      String(rh.headers["content-type"] || "") === "application/pdf");
    check("[presign-rh-" + label + "] server honors response-content-disposition",
      String(rh.headers["content-disposition"] || "")
        .indexOf('attachment; filename="invoice.pdf"') !== -1);
    check("[presign-rh-" + label + "] server honors response-cache-control",
      String(rh.headers["cache-control"] || "").indexOf("no-store") !== -1);
    check("[presign-rh-" + label + "] bytes round-trip unchanged",
      Buffer.compare(Buffer.from(rh.body || rh.bodyBytes || []), payload) === 0);

    await backend.delete(key);
    await ops.delete(bucket);
  })();
}

async function run() {
  var svc = await services.requireService("minio");
  if (!svc.ok) throw new Error("minio unreachable: " + svc.reason);
  var svcTls = await services.requireService("minioTls");
  if (!svcTls.ok) throw new Error("minio-tls unreachable: " + svcTls.reason);

  var caPath = await services.exportCaCert();
  var caPem = fs.readFileSync(caPath, "utf8");

  // ---- plain HTTP variant ----
  await _runOnEndpoint("http", "http://127.0.0.1:9000", {
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
  });

  // ---- TLS variant — strict CA pinning, no rejectUnauthorized override ----
  // Endpoint uses "localhost" so SNI works (cert SAN covers localhost +
  // 127.0.0.1; node:tls forbids IP literals as servername).
  await _runOnEndpoint("tls", "https://localhost:9443", {
    ca: caPem,
  });

  // ---- Object Lock variant (HTTP only — no benefit from doing it twice
  //      and the WORM cleanup adds 2s of sleep which we don't want
  //      duplicated). Exercises the v0.6.47 lib + v0.6.49 wire-form fix
  //      against live MinIO. ----
  await _runObjectLockOnEndpoint("http", "http://127.0.0.1:9000", {
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
  });

  // ---- Presigned response-header overrides (v0.8.53). HTTP first;
  //      TLS second to confirm signing math + Object.assign(ca) on
  //      the framework's httpClient request path. ----
  await _runPresignResponseHeadersOnEndpoint("http", "http://127.0.0.1:9000", {
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
  });
  await _runPresignResponseHeadersOnEndpoint("tls", "https://localhost:9443", {
    ca: caPem,
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

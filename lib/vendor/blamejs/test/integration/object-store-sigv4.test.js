// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live S3 round-trip against the docker-compose MinIO fixtures.
 * Covers BOTH the plain HTTP listener (minio:9000) and the TLS listener
 * (minio-tls:9443) so the framework's sigv4 signer + S3 client are
 * exercised end-to-end against real AWS-compatible servers.
 *
 * No security bypass: the TLS leg trusts the test CA via the runner's
 * NODE_EXTRA_CA_CERTS (scripts/test-integration.js), so the framework's
 * own TLS verification stays fully on with no rejectUnauthorized override
 * and no per-request CA threading.
 */
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

    // ---- special-character key round-trip (the v0.15.2 SigV4 single-encode
    // fix). A key with a space / + / & / () previously double-encoded the
    // canonical path → the signature was computed over a path the wire never
    // carried → SignatureDoesNotMatch (403). Every prior test used ASCII keys,
    // so the bug shipped green; this drives a real special-char key end-to-end.
    // put() throws on a non-2xx, so reaching the asserts proves no 403. ----
    // Includes a non-BMP code point (emoji) so the round-trip also proves the
    // encoder iterates by code point — a UTF-16-unit split would throw URIError
    // before signing.
    var specialKey = "obj report (v2)+final & draft \u{1F600}-" + Math.floor(Math.random() * 1e6) + ".txt";
    var specialPayload = Buffer.from("special-char-key payload", "utf8");
    await backend.put(specialKey, specialPayload, { contentType: "text/plain" });
    check("[" + label + "] special-char key put: signed + accepted (no 403)", true);
    var specialGot = await backend.get(specialKey);
    var specialBuf = Buffer.isBuffer(specialGot) ? specialGot : (specialGot && specialGot.body);
    check("[" + label + "] special-char key get: bytes round-trip exactly",
          Buffer.isBuffer(specialBuf) && Buffer.compare(specialBuf, specialPayload) === 0);
    var specialListing = await backend.list("obj report");
    check("[" + label + "] special-char key list: surfaces the object",
          specialListing.items.some(function (it) { return it.key === specialKey; }));
    await backend.delete(specialKey);
    check("[" + label + "] special-char key delete: returned (no throw)", true);

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

// Versioned listing + pagination against live MinIO.
//
// list()/listVersions() had only single-page, no-marker coverage here: every
// prior call passed a bare prefix, so max-keys / continuation-token /
// key-marker / version-id-marker were never on the wire, and no assertion
// proved a paged walk returns each object exactly once. listVersions had
// never been exercised against a bucket holding MULTIPLE versions of one key
// plus a delete-marker, which is the shape the WORM erasure workflow reads.
//
// The bucket is created with objectLockEnabled so MinIO turns versioning on;
// no retention rule is configured, so every version stays deletable and
// cleanup is unconditional.
function _runVersionedListingOnEndpoint(label, endpoint, extraConfig) {
  var bucket = "blamejs-test-versions-" + label + "-" + Date.now();
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

    var backend = b.objectStore.buildBackend(Object.assign({
      name:            "minio-versions-" + label,
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
    }, extraConfig));
    var P = "[versions-" + label + "] ";

    // ---- two versions of one key ----
    var vkey = "versioned/doc.txt";
    var v1Payload = Buffer.from("first revision", "utf8");
    var v2Payload = Buffer.from("second revision, deliberately longer", "utf8");
    var put1 = await backend.put(vkey, v1Payload, { contentType: "text/plain" });
    var put2 = await backend.put(vkey, v2Payload, { contentType: "text/plain" });
    check(P + "put returns a versionId on a versioning-enabled bucket",
          typeof put1.versionId === "string" && put1.versionId.length > 0 &&
          typeof put2.versionId === "string" && put2.versionId.length > 0);
    check(P + "the two puts created DISTINCT versions",
          put1.versionId !== put2.versionId);

    var lv = await backend.listVersions(vkey);
    var rows = lv.items.filter(function (it) { return it.key === vkey; });
    check(P + "listVersions enumerates both versions", rows.length === 2);
    check(P + "neither row is flagged as a delete-marker",
          rows.every(function (r) { return r.deleteMarker === false; }));
    var latest = rows.filter(function (r) { return r.isLatest; });
    check(P + "exactly one row is isLatest", latest.length === 1);
    check(P + "isLatest is the SECOND put's version",
          latest[0].versionId === put2.versionId);
    var byId = {};
    rows.forEach(function (r) { byId[r.versionId] = r; });
    check(P + "each version's size matches the payload it was written with",
          byId[put1.versionId] && byId[put1.versionId].size === v1Payload.length &&
          byId[put2.versionId] && byId[put2.versionId].size === v2Payload.length);
    check(P + "every version row carries an etag and a parsed lastModified",
          rows.every(function (r) {
            return typeof r.etag === "string" && r.etag.length > 0 &&
                   typeof r.lastModified === "number" && !isNaN(r.lastModified);
          }));

    // ---- head(key, { versionId }) targets the exact version ----
    // The sizes differ, so a versionId that never reached the wire would
    // return the CURRENT version's size for both calls.
    var h1 = await backend.head(vkey, { versionId: put1.versionId });
    var h2 = await backend.head(vkey, { versionId: put2.versionId });
    check(P + "head(versionId) reads the first version's size",
          h1.size === v1Payload.length);
    check(P + "head(versionId) reads the second version's size",
          h2.size === v2Payload.length);
    check(P + "the two versions have distinct etags", h1.etag !== h2.etag);

    // ---- get(key, { versionId }) returns the superseded bytes ----
    var oldBytes = await backend.get(vkey, { versionId: put1.versionId });
    check(P + "get(versionId) returns the SUPERSEDED bytes byte-for-byte",
          Buffer.isBuffer(oldBytes) && Buffer.compare(oldBytes, v1Payload) === 0);
    var currentBytes = await backend.get(vkey);
    check(P + "an unversioned get still returns the CURRENT bytes",
          Buffer.isBuffer(currentBytes) && Buffer.compare(currentBytes, v2Payload) === 0);

    // ---- an unversioned delete writes a tombstone, it does not erase ----
    var deleted = await backend.delete(vkey);
    check(P + "unversioned delete reports success", deleted === true);
    var afterDelete = await backend.listVersions(vkey);
    var afterRows = afterDelete.items.filter(function (it) { return it.key === vkey; });
    var markers = afterRows.filter(function (it) { return it.deleteMarker === true; });
    check(P + "unversioned delete produced exactly one delete-marker",
          markers.length === 1);
    check(P + "the delete-marker carries a versionId of its own",
          typeof markers[0].versionId === "string" && markers[0].versionId.length > 0);
    check(P + "the delete-marker reports size null (it holds no data)",
          markers[0].size === null);
    check(P + "the delete-marker reports etag null",  markers[0].etag === null);
    check(P + "the delete-marker is now the latest version",
          markers[0].isLatest === true);
    // The data versions MUST survive a delete-marker write - that distinction
    // is the whole reason the erasure workflow needs versionIds.
    check(P + "both data versions SURVIVE the delete-marker",
          afterRows.filter(function (it) { return !it.deleteMarker; }).length === 2);

    // ---- delete of a never-written key ----
    // S3 DELETE Object is idempotent: MinIO answers 204 for a key that never
    // existed. So `true` here does NOT mean "the object existed" - the
    // adapter's 404 -> false arm is unreachable against MinIO and only fires
    // on S3-compatible stores that answer 404. Pin the real contract so no
    // caller starts reading the boolean as an existence probe (head() is the
    // existence probe; it reports NOT_FOUND).
    var absentKey = "versioned/never-written-" + Math.floor(Math.random() * 1e9) + ".txt";
    var absent = await backend.delete(absentKey);
    check(P + "delete of a never-written key resolves without throwing",
          typeof absent === "boolean");
    check(P + "MinIO treats DELETE as idempotent (reports success, not 404)",
          absent === true);
    // What the store does with that idempotent DELETE is NOT uniform across
    // S3 implementations, so this pins the behaviour of the store under test
    // rather than a general S3 contract: MinIO records nothing for a key that
    // never existed (verified against the live server — delete returns true
    // and listVersions reports zero rows for the key). AWS S3 is documented to
    // write a delete-marker even for an absent key in a versioning-enabled
    // bucket, so a run against real S3 would legitimately see one row here.
    // Kept as a strict equality rather than "0 or 1" because a tolerant
    // assertion would pass whatever the adapter did and prove nothing.
    var absentRows = (await backend.listVersions(absentKey)).items
      .filter(function (it) { return it.key === absentKey; });
    check(P + "MinIO records no version and no delete-marker for the never-written key",
          absentRows.length === 0);
    var headThrew = null;
    try {
      await backend.head(absentKey);
      check(P + "head of a never-written key should have thrown", false);
    } catch (e) { headThrew = e; }
    check(P + "head is the existence probe: NOT_FOUND for the never-written key",
          headThrew && headThrew.code === "NOT_FOUND");

    // ---- list() paged walk: max-keys + continuation-token ----
    var prefix = "page/";
    var pageKeys = ["page/a.txt", "page/b.txt", "page/c.txt"];
    for (var pi = 0; pi < pageKeys.length; pi += 1) {
      await backend.put(pageKeys[pi], Buffer.from("body-" + pi, "utf8"));
    }
    var pg1 = await backend.list(prefix, { maxResults: 2 });
    check(P + "list(maxResults:2) returns exactly 2 items", pg1.items.length === 2);
    check(P + "list(maxResults:2) reports truncated", pg1.truncated === true);
    check(P + "list(maxResults:2) surfaces a continuation token",
          typeof pg1.continuationToken === "string" && pg1.continuationToken.length > 0);
    var pg2 = await backend.list(prefix, {
      maxResults: 2, continuationToken: pg1.continuationToken,
    });
    check(P + "list(continuationToken) returns the remaining item",
          pg2.items.length === 1);
    check(P + "the final page is not truncated", pg2.truncated === false);
    check(P + "the final page surfaces no continuation token",
          pg2.continuationToken === null);
    // The paged walk must cover each key exactly once - a token that resets
    // would duplicate, one that overshoots would drop.
    var walked = pg1.items.concat(pg2.items).map(function (it) { return it.key; }).sort();
    check(P + "the paged walk visits every key exactly once",
          walked.length === pageKeys.length &&
          walked.join("|") === pageKeys.slice().sort().join("|"));

    // ---- listVersions() paged walk: key-marker + version-id-marker ----
    // Page size 1 across a key that has several versions, so MinIO has to
    // resume MID-KEY and both markers are exercised.
    var allVersions = await backend.listVersions(vkey);
    var allIds = allVersions.items.map(function (it) { return it.versionId; }).sort();
    var seenIds = [];
    var cursor = { maxResults: 1 };
    var pages = 0;
    for (;;) {
      var vp = await backend.listVersions(vkey, cursor);
      pages += 1;
      vp.items.forEach(function (it) { seenIds.push(it.versionId); });
      if (!vp.truncated) {
        check(P + "listVersions final page reports truncated false", true);
        break;
      }
      check(P + "a truncated listVersions page surfaces a keyMarker",
            typeof vp.keyMarker === "string" && vp.keyMarker.length > 0);
      cursor = {
        maxResults:      1,
        keyMarker:       vp.keyMarker,
        versionIdMarker: vp.versionIdMarker,
      };
      if (pages > 10) throw new Error("listVersions pagination did not terminate");
    }
    check(P + "listVersions paged walk took one page per version + marker",
          pages === allIds.length);
    check(P + "listVersions paged walk visited every versionId exactly once",
          seenIds.slice().sort().join("|") === allIds.join("|"));

    // ---- cleanup: erase every version, then drop the bucket ----
    var everything = await backend.listVersions("");
    for (var ei = 0; ei < everything.items.length; ei += 1) {
      await backend.delete(everything.items[ei].key,
        { versionId: everything.items[ei].versionId });
    }
    var residual = await backend.listVersions("");
    check(P + "every version erased by versionId (bucket is empty)",
          residual.items.length === 0);
    await ops.delete(bucket);
    check(P + "bucket dropped once no versions remain", true);
  })();
}

async function run() {
  var svc = await services.requireService("minio");
  if (!svc.ok) throw new Error("minio unreachable: " + svc.reason);
  var svcTls = await services.requireService("minioTls");
  if (!svcTls.ok) throw new Error("minio-tls unreachable: " + svcTls.reason);

  // ---- plain HTTP variant ----
  await _runOnEndpoint("http", "http://127.0.0.1:9000", {
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
  });

  // ---- TLS variant — full verification, no rejectUnauthorized override ----
  // Trust for the test CA comes from the runner's NODE_EXTRA_CA_CERTS.
  // Endpoint uses "localhost" so SNI works (cert SAN covers localhost +
  // 127.0.0.1; node:tls forbids IP literals as servername). https is in
  // the default allowedProtocols so no extra config is needed.
  await _runOnEndpoint("tls", "https://localhost:9443", {});

  // ---- Object Lock variant (HTTP only — no benefit from doing it twice
  //      and the WORM cleanup adds 2s of sleep which we don't want
  //      duplicated). Exercises the v0.6.47 lib + v0.6.49 wire-form fix
  //      against live MinIO. ----
  await _runObjectLockOnEndpoint("http", "http://127.0.0.1:9000", {
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
  });

  // ---- Presigned response-header overrides (v0.8.53). HTTP first;
  //      TLS second to confirm the signing math + the live presigned GET
  //      stay valid over a fully-verified TLS handshake. ----
  await _runPresignResponseHeadersOnEndpoint("http", "http://127.0.0.1:9000", {
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
  });
  await _runPresignResponseHeadersOnEndpoint("tls", "https://localhost:9443", {});

  // ---- Versioned listing + paged list/listVersions walks. HTTP only:
  //      the wire contract under test is S3 semantics, not transport, and
  //      the TLS leg is already proven by the round-trips above. ----
  await _runVersionedListingOnEndpoint("http", "http://127.0.0.1:9000", {
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
  });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

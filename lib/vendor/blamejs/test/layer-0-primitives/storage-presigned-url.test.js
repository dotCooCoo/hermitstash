"use strict";
/**
 * storage — presigned upload URL.
 *
 * Operators handing browser/mobile clients a direct path to object
 * storage need a signed PUT URL the client can use without holding
 * AWS credentials. SigV4 backends (S3, R2, MinIO, Wasabi, Tigris,
 * DO Spaces, IDrive e2, Linode, Storj) implement query-string SigV4
 * presigning; gcs implements POST policy via service-account RSA
 * signing; local + http-put + azure-blob throw PRESIGN_NOT_SUPPORTED
 * with guidance (azure SAS has no body-size cap, local + http-put
 * have no signing convention).
 *
 * Run standalone: `node test/layer-0-primitives/storage-presigned-url.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var nodeCrypto     = require("crypto");
var sigv4Internal  = require("../../lib/object-store/sigv4");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var SIGV4_CONFIG = {
  protocol:        "sigv4",
  region:          "us-east-1",
  bucket:          "blamejs-test",
  accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  classifications: ["operational"],
};

async function testSurface() {
  check("storage.presignedUploadUrl is a function",
        typeof b.storage.presignedUploadUrl === "function");
  check("storage.presignedDownloadUrl is a function",
        typeof b.storage.presignedDownloadUrl === "function");
}

async function testSigv4ProducesPresignedUrl() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" }); // re-init after _resetForTest reset vault
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    // Fixed date so the signature is deterministic for assertion.
    var fixed = new Date("2026-04-27T12:34:56Z");
    var result = b.storage.presignedUploadUrl("uploads/abc.bin", {
      classification: "operational",
      expiresIn:      900,
      contentType:    "application/octet-stream",
      date:           fixed,
    });

    check("returns object",                          typeof result === "object" && result !== null);
    check("method is PUT",                           result.method === "PUT");
    check("expiresAt = date + expiresIn*1000",       result.expiresAt === fixed.getTime() + 900000);
    check("Content-Type header propagated",          result.headers["Content-Type"] === "application/octet-stream");

    var url = new URL(result.url);
    check("URL targets the bucket virtual host",     url.hostname.startsWith("blamejs-test."));
    check("URL path encodes the key",                url.pathname === "/uploads/abc.bin");
    check("X-Amz-Algorithm = AWS4-HMAC-SHA256",      url.searchParams.get("X-Amz-Algorithm") === "AWS4-HMAC-SHA256");
    check("X-Amz-Expires reflects expiresIn",        url.searchParams.get("X-Amz-Expires") === "900");
    check("X-Amz-SignedHeaders = content-type;host",
                                                      url.searchParams.get("X-Amz-SignedHeaders") === "content-type;host");
    check("X-Amz-Date is iso compact form",          url.searchParams.get("X-Amz-Date") === "20260427T123456Z");
    var cred = url.searchParams.get("X-Amz-Credential") || "";
    check("X-Amz-Credential includes accessKeyId",   cred.indexOf("AKIAIOSFODNN7EXAMPLE/") === 0);
    check("X-Amz-Credential ends with aws4_request", cred.endsWith("/aws4_request"));
    check("X-Amz-Signature is 64 hex chars",         /^[0-9a-f]{64}$/.test(url.searchParams.get("X-Amz-Signature")));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testSigv4SignatureIsDeterministic() {
  // Two calls with identical inputs must produce identical URLs — the
  // signature is a pure function of (key, date, secret, region, expiry).
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    var fixed = new Date("2026-04-27T00:00:00Z");
    var a = b.storage.presignedUploadUrl("k.bin",
      { classification: "operational", expiresIn: 600, date: fixed });
    var c = b.storage.presignedUploadUrl("k.bin",
      { classification: "operational", expiresIn: 600, date: fixed });
    check("same inputs → same URL",                  a.url === c.url);

    // Different expiry → different signature
    var d = b.storage.presignedUploadUrl("k.bin",
      { classification: "operational", expiresIn: 601, date: fixed });
    check("different expiresIn → different URL",     a.url !== d.url);
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testInvalidExpiresInRejected() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    var threw = null;
    try { b.storage.presignedUploadUrl("k.bin", { expiresIn: 0 }); } catch (e) { threw = e; }
    check("expiresIn = 0 rejected",                  threw && /between 1 and 604800/.test(threw.message));

    threw = null;
    try { b.storage.presignedUploadUrl("k.bin", { expiresIn: 604801 }); } catch (e) { threw = e; }
    check("expiresIn > 7 days rejected",             threw && /between 1 and 604800/.test(threw.message));

    threw = null;
    try { b.storage.presignedUploadUrl("", {}); } catch (e) { threw = e; }
    check("empty key rejected",                      threw && /key is required/i.test(threw.message));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testLocalBackendThrowsNotSupported() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({ backend: "local", uploadDir: path.join(tmpDir, "uploads") });

    var threw = null;
    try { b.storage.presignedUploadUrl("k.bin", {}); } catch (e) { threw = e; }
    check("local backend rejects presigned",         threw && threw.code === "PRESIGN_NOT_SUPPORTED");
    check("error message mentions local + saveFile", threw && /local backend/i.test(threw.message) && /saveFile/i.test(threw.message));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testHttpPutBackendThrowsNotSupported() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: {
        "edge": {
          protocol:        "http-put",
          baseUrl:         "https://upload.example.com",
          classifications: ["operational"],
        },
      },
      defaultClassification: "operational",
    });

    var threw = null;
    try { b.storage.presignedUploadUrl("k.bin", {}); } catch (e) { threw = e; }
    check("http-put backend rejects presigned upload",      threw && threw.code === "PRESIGN_NOT_SUPPORTED");
    check("error message points to sigv4 alternative",      threw && /sigv4/i.test(threw.message));

    threw = null;
    try { b.storage.presignedDownloadUrl("k.bin", {}); } catch (e) { threw = e; }
    check("http-put backend rejects presigned download",    threw && threw.code === "PRESIGN_NOT_SUPPORTED");
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testSigv4ContentTypeIsSigned() {
  // When opts.contentType is supplied the SigV4 signature must include
  // content-type in SignedHeaders so the upstream rejects mismatched
  // uploads — turning the hint into real server-side enforcement.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    var fixed = new Date("2026-04-27T12:34:56Z");
    var withCt = b.storage.presignedUploadUrl("ct.bin",
      { classification: "operational", expiresIn: 600, date: fixed,
        contentType: "image/png" });
    var withoutCt = b.storage.presignedUploadUrl("ct.bin",
      { classification: "operational", expiresIn: 600, date: fixed });

    var u1 = new URL(withCt.url);
    var u2 = new URL(withoutCt.url);
    check("contentType supplied → SignedHeaders includes content-type",
          u1.searchParams.get("X-Amz-SignedHeaders") === "content-type;host");
    check("contentType absent → SignedHeaders is host only",
          u2.searchParams.get("X-Amz-SignedHeaders") === "host");
    check("contentType changes the signature",
          u1.searchParams.get("X-Amz-Signature") !== u2.searchParams.get("X-Amz-Signature"));
    check("returned headers carry Content-Type for the client",
          withCt.headers["Content-Type"] === "image/png");
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testSigv4PresignedDownloadUrl() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    var fixed = new Date("2026-04-27T12:34:56Z");
    var dl = b.storage.presignedDownloadUrl("dl.bin",
      { classification: "operational", expiresIn: 600, date: fixed });
    check("presignedDownloadUrl method = GET",       dl.method === "GET");
    var url = new URL(dl.url);
    check("download URL has X-Amz-Signature",        /^[0-9a-f]{64}$/.test(url.searchParams.get("X-Amz-Signature")));
    // Same key + same date but different method → different signature
    var ul = b.storage.presignedUploadUrl("dl.bin",
      { classification: "operational", expiresIn: 600, date: fixed });
    check("PUT and GET produce different signatures",
          new URL(ul.url).searchParams.get("X-Amz-Signature") !==
          url.searchParams.get("X-Amz-Signature"));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

function _generateRsaKeyPair() {
  return nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

async function testGcsV4Presigning() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });

    var keys = _generateRsaKeyPair();
    var sa = {
      client_email: "blamejs-test@example.iam.gserviceaccount.com",
      private_key:  keys.privateKey,
      project_id:   "blamejs-test",
    };
    b.storage.init({
      backends: {
        "gcs": {
          protocol:        "gcs",
          bucket:          "blamejs-test-bucket",
          serviceAccount:  sa,
          classifications: ["operational"],
        },
      },
      defaultClassification: "operational",
    });

    var fixed = new Date("2026-04-27T12:34:56Z");
    var up = b.storage.presignedUploadUrl("uploads/g.bin",
      { classification: "operational", expiresIn: 900, date: fixed,
        contentType: "application/octet-stream" });

    check("gcs presigned method = PUT",              up.method === "PUT");
    check("gcs Content-Type returned for client",    up.headers["Content-Type"] === "application/octet-stream");

    var url = new URL(up.url);
    check("gcs URL targets storage.googleapis.com",  url.hostname === "storage.googleapis.com");
    check("gcs URL has bucket + key in path",        url.pathname === "/blamejs-test-bucket/uploads/g.bin");
    check("X-Goog-Algorithm = GOOG4-RSA-SHA256",     url.searchParams.get("X-Goog-Algorithm") === "GOOG4-RSA-SHA256");
    check("X-Goog-Credential includes client_email", (url.searchParams.get("X-Goog-Credential") || "").indexOf(sa.client_email + "/") === 0);
    check("X-Goog-Expires reflects expiresIn",       url.searchParams.get("X-Goog-Expires") === "900");
    check("X-Goog-SignedHeaders includes content-type",
          url.searchParams.get("X-Goog-SignedHeaders") === "content-type;host");
    check("X-Goog-Signature is hex (RSA-SHA256/2048 = 512 hex chars)",
          /^[0-9a-f]{512}$/.test(url.searchParams.get("X-Goog-Signature")));

    // Verify the RSA signature is real by reconstructing the canonical
    // request from the URL and validating against the public key.
    var sigHex = url.searchParams.get("X-Goog-Signature");
    // Strip the signature param so the canonical query string matches.
    var verifyUrl = new URL(up.url);
    verifyUrl.searchParams.delete("X-Goog-Signature");
    var headers = { host: verifyUrl.host, "content-type": "application/octet-stream" };
    var canon = sigv4Internal.canonicalRequest("PUT", verifyUrl, headers, "UNSIGNED-PAYLOAD");
    var amzDate = verifyUrl.searchParams.get("X-Goog-Date");
    var credential = verifyUrl.searchParams.get("X-Goog-Credential");
    var credentialScope = credential.split("/").slice(1).join("/");
    var stringToSign = ["GOOG4-RSA-SHA256", amzDate, credentialScope,
                        sigv4Internal.sha256Hex(canon)].join("\n");
    var verifier = nodeCrypto.createVerify("RSA-SHA256");
    verifier.update(stringToSign);
    verifier.end();
    var ok = verifier.verify(keys.publicKey, Buffer.from(sigHex, "hex"));
    check("gcs RSA signature verifies against public key", ok === true);

    // Download presign
    var dl = b.storage.presignedDownloadUrl("uploads/g.bin",
      { classification: "operational", expiresIn: 900, date: fixed });
    check("gcs download method = GET",               dl.method === "GET");
    check("gcs download URL has X-Goog-Signature",   /^[0-9a-f]{512}$/.test(new URL(dl.url).searchParams.get("X-Goog-Signature")));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testAzureSasPresigning() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });

    // Account key must be valid base64; the SAS signer base64-decodes it
    // before HMAC-ing. 32 random bytes encoded.
    var accountKey = nodeCrypto.randomBytes(32).toString("base64");
    b.storage.init({
      backends: {
        "az": {
          protocol:        "azure-blob",
          accountName:     "blamejstest",
          accountKey:      accountKey,
          container:       "uploads",
          classifications: ["operational"],
        },
      },
      defaultClassification: "operational",
    });

    var fixed = new Date("2026-04-27T12:34:56Z");
    var up = b.storage.presignedUploadUrl("a.bin",
      { classification: "operational", expiresIn: 600, date: fixed,
        contentType: "image/jpeg" });

    check("azure presigned method = PUT",            up.method === "PUT");
    check("azure URL targets account host",          new URL(up.url).hostname === "blamejstest.blob.core.windows.net");
    check("azure URL has container + blob in path",  new URL(up.url).pathname === "/uploads/a.bin");
    var qs = new URL(up.url).searchParams;
    check("azure SAS sp = cw (create+write)",        qs.get("sp") === "cw");
    check("azure SAS sr = b (blob)",                 qs.get("sr") === "b");
    check("azure SAS spr = https",                   qs.get("spr") === "https");
    check("azure SAS rsct = signed content type",    qs.get("rsct") === "image/jpeg");
    check("azure SAS sig is base64",                 /^[A-Za-z0-9+/=]+$/.test(qs.get("sig")));
    check("azure client headers include x-ms-blob-type for PUT",
          up.headers["x-ms-blob-type"] === "BlockBlob");
    check("azure client Content-Type forwarded",     up.headers["Content-Type"] === "image/jpeg");

    var dl = b.storage.presignedDownloadUrl("a.bin",
      { classification: "operational", expiresIn: 600, date: fixed });
    check("azure download method = GET",             dl.method === "GET");
    check("azure download SAS sp = r (read)",        new URL(dl.url).searchParams.get("sp") === "r");
    check("azure download omits x-ms-blob-type",     !dl.headers["x-ms-blob-type"]);
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testPresignedUploadPolicySigv4() {
  // SigV4 POST policy: builds an AWS S3-style policy document with a
  // content-length-range condition, base64-encodes, signs with the
  // HMAC chain. Server rejects bodies outside the declared range.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    var fixed = new Date("2026-04-27T12:34:56Z");
    var policy = b.storage.presignedUploadPolicy("uploads/big.bin", {
      classification: "operational",
      expiresIn:      900,
      maxBytes:       10 * 1024 * 1024,    // 10 MiB
      contentType:    "image/png",
      date:           fixed,
    });

    check("sigv4 policy: method = POST",         policy.method === "POST");
    check("sigv4 policy: maxBytes echoed",       policy.maxBytes === 10 * 1024 * 1024);
    check("sigv4 policy: enforcement = content-length-range",
                                                  policy.enforcement === "content-length-range");
    check("sigv4 policy: fields object present", typeof policy.fields === "object" && policy.fields !== null);

    var f = policy.fields;
    check("sigv4 policy: key field",             f.key === "uploads/big.bin");
    check("sigv4 policy: x-amz-algorithm",       f["x-amz-algorithm"] === "AWS4-HMAC-SHA256");
    check("sigv4 policy: x-amz-credential",      (f["x-amz-credential"] || "").indexOf("AKIAIOSFODNN7EXAMPLE/") === 0);
    check("sigv4 policy: x-amz-date",            f["x-amz-date"] === "20260427T123456Z");
    check("sigv4 policy: content-type",          f["content-type"] === "image/png");
    check("sigv4 policy: signature is hex",      /^[0-9a-f]{64}$/.test(f["x-amz-signature"]));
    check("sigv4 policy: policy is base64",      typeof f.policy === "string" && f.policy.length > 0);

    // Decode the policy document and confirm the conditions are correct.
    var policyJson = Buffer.from(f.policy, "base64").toString("utf8");
    var policyDoc = JSON.parse(policyJson);
    check("sigv4 policy: expiration is ISO",     /^\d{4}-\d{2}-\d{2}T/.test(policyDoc.expiration));
    check("sigv4 policy: conditions array",      Array.isArray(policyDoc.conditions));
    var hasRange = policyDoc.conditions.some(function (c) {
      return Array.isArray(c) && c[0] === "content-length-range" && c[2] === 10 * 1024 * 1024;
    });
    check("sigv4 policy: content-length-range condition present", hasRange);
    var hasBucket = policyDoc.conditions.some(function (c) {
      return c && typeof c === "object" && !Array.isArray(c) && c.bucket === "blamejs-test";
    });
    check("sigv4 policy: bucket condition",      hasBucket);

    // Verify the signature: HMAC-SHA256(signingKey, policyB64)
    var nodeCrypto = require("crypto");
    var signingKey = sigv4Internal.deriveSigningKey(
      SIGV4_CONFIG.secretAccessKey,
      "20260427",
      SIGV4_CONFIG.region,
      "s3"
    );
    var expected = nodeCrypto.createHmac("sha256", signingKey).update(f.policy).digest("hex");
    check("sigv4 policy: signature reconstructs", f["x-amz-signature"] === expected);
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testPresignedUploadPolicyMaxBytesRequired() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    var threw = null;
    try { b.storage.presignedUploadPolicy("k.bin", {}); } catch (e) { threw = e; }
    check("policy: missing maxBytes rejected",   threw && threw.code === "INVALID_MAX_BYTES");

    threw = null;
    try { b.storage.presignedUploadPolicy("k.bin", { maxBytes: 0 }); } catch (e) { threw = e; }
    check("policy: maxBytes = 0 rejected",       threw && threw.code === "INVALID_MAX_BYTES");

    threw = null;
    try { b.storage.presignedUploadPolicy("k.bin", { maxBytes: -1 }); } catch (e) { threw = e; }
    check("policy: negative maxBytes rejected",  threw && threw.code === "INVALID_MAX_BYTES");
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testPresignedUploadPolicyGcs() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    var keys = nodeCrypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding:  { type: "spki",  format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    var sa = {
      client_email: "blamejs-test@example.iam.gserviceaccount.com",
      private_key:  keys.privateKey,
      project_id:   "blamejs-test",
    };
    b.storage.init({
      backends: {
        "gcs": {
          protocol:        "gcs",
          bucket:          "blamejs-test-bucket",
          serviceAccount:  sa,
          classifications: ["operational"],
        },
      },
      defaultClassification: "operational",
    });

    var fixed = new Date("2026-04-27T12:34:56Z");
    var policy = b.storage.presignedUploadPolicy("uploads/g.bin", {
      classification: "operational",
      expiresIn:      900,
      maxBytes:       5 * 1024 * 1024,
      contentType:    "application/octet-stream",
      date:           fixed,
    });

    check("gcs policy: method = POST",            policy.method === "POST");
    check("gcs policy: enforcement",              policy.enforcement === "content-length-range");
    check("gcs policy: maxBytes echoed",          policy.maxBytes === 5 * 1024 * 1024);

    var f = policy.fields;
    check("gcs policy: x-goog-algorithm",         f["x-goog-algorithm"] === "GOOG4-RSA-SHA256");
    check("gcs policy: x-goog-credential",        (f["x-goog-credential"] || "").indexOf(sa.client_email + "/") === 0);
    check("gcs policy: signature is hex (RSA-SHA256/2048 = 512 hex chars)",
                                                  /^[0-9a-f]{512}$/.test(f["x-goog-signature"]));

    // Verify RSA signature: signed value is the base64 policy.
    var verifier = nodeCrypto.createVerify("RSA-SHA256");
    verifier.update(f.policy);
    verifier.end();
    var ok = verifier.verify(keys.publicKey, Buffer.from(f["x-goog-signature"], "hex"));
    check("gcs policy: RSA signature verifies",   ok === true);

    // Decode the policy and check content-length-range
    var policyDoc = JSON.parse(Buffer.from(f.policy, "base64").toString("utf8"));
    var hasRange = policyDoc.conditions.some(function (c) {
      return Array.isArray(c) && c[0] === "content-length-range" && c[2] === 5 * 1024 * 1024;
    });
    check("gcs policy: content-length-range condition", hasRange);
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testPresignedUploadPolicyAzureClientOnly() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    var accountKey = nodeCrypto.randomBytes(32).toString("base64");
    b.storage.init({
      backends: {
        "az": {
          protocol:        "azure-blob",
          accountName:     "blamejstest",
          accountKey:      accountKey,
          container:       "uploads",
          classifications: ["operational"],
        },
      },
      defaultClassification: "operational",
    });

    var azureThrew = null;
    try {
      b.storage.presignedUploadPolicy("a.bin", {
        classification: "operational",
        expiresIn:      600,
        maxBytes:       2 * 1024 * 1024,
        contentType:    "image/jpeg",
      });
    } catch (e) { azureThrew = e; }
    check("azure policy: throws PRESIGN_NOT_SUPPORTED (Azure SAS has no body-size cap)",
      azureThrew && azureThrew.code === "PRESIGN_NOT_SUPPORTED");
    check("azure policy: error message names presignedUploadUrl as the alternative",
      azureThrew && /presignedUploadUrl/i.test(azureThrew.message));
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testPresignedUploadPolicyLocalAndHttpPutThrow() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({ backend: "local", uploadDir: path.join(tmpDir, "uploads") });

    var threw = null;
    try { b.storage.presignedUploadPolicy("k.bin", { maxBytes: 1024 }); } catch (e) { threw = e; }
    check("policy: local backend rejects",        threw && threw.code === "PRESIGN_NOT_SUPPORTED");

    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: {
        "edge": {
          protocol:        "http-put",
          baseUrl:         "https://upload.example.com",
          classifications: ["operational"],
        },
      },
      defaultClassification: "operational",
    });
    threw = null;
    try { b.storage.presignedUploadPolicy("k.bin", { maxBytes: 1024 }); } catch (e) { threw = e; }
    check("policy: http-put backend rejects",     threw && threw.code === "PRESIGN_NOT_SUPPORTED");
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function testAuditEventEmitted() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-presign-"));
  try {
    await setupTestDb(tmpDir);
    b.storage._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    b.storage.init({
      backends: { "s3": SIGV4_CONFIG },
      defaultClassification: "operational",
    });

    b.storage.presignedUploadUrl("audited.bin", { classification: "operational", expiresIn: 60 });
    await b.audit.flush();
    var rows = await b.audit.query({ action: "system.storage.presign" });
    check("system.storage.presign audit emitted",    rows.length === 1);
    var meta = typeof rows[0].metadata === "string" ? JSON.parse(rows[0].metadata) : rows[0].metadata;
    check("audit row carries backend metadata",      meta && meta.backend === "s3");
    check("audit row carries key",                   meta && meta.key === "audited.bin");
  } finally {
    b.storage._resetForTest();
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testSurface();
  await testSigv4ProducesPresignedUrl();
  await testSigv4SignatureIsDeterministic();
  await testInvalidExpiresInRejected();
  await testLocalBackendThrowsNotSupported();
  await testHttpPutBackendThrowsNotSupported();
  await testSigv4ContentTypeIsSigned();
  await testSigv4PresignedDownloadUrl();
  await testGcsV4Presigning();
  await testAzureSasPresigning();
  await testPresignedUploadPolicyMaxBytesRequired();
  await testPresignedUploadPolicySigv4();
  await testPresignedUploadPolicyGcs();
  await testPresignedUploadPolicyAzureClientOnly();
  await testPresignedUploadPolicyLocalAndHttpPutThrow();
  await testAuditEventEmitted();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}

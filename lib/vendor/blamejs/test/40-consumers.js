"use strict";
/**
 * Layer 4 — consumer modules.
 *
 * Layer 4 — consumer modules sit on top of audit + db + chain
 * primitives.
 *
 *   session           — session lifecycle
 *   data-residency    — db + storage residency rules
 *   storage           — local + multi-backend object stores +
 *                       classification routing + retry/breaker +
 *                       sigv4 / GCS / Azure adapters
 *   queue             — local queue lifecycle (consume / retry / lease)
 *   log-stream        — log fan-out (local, webhook, bidirectional)
 *   external-db       — dispatcher (basic / pool / transaction /
 *                       residency / classification)
 *   middleware        — request-id / security headers / error handler /
 *                       bot-guard / cors / rate-limit
 *   env-load          — full lifecycle (consumes env-parse + atomicFile)
 *
 * Layers 0–3 must run first.
 *
 * Usage from smoke.js:
 *   var consumersLayer = require("./40-consumers");
 *   await consumersLayer.run();
 */

var helpers = require("./_helpers");
var b      = helpers.b;
var fs     = helpers.fs;
var os     = helpers.os;
var path   = helpers.path;
var check  = helpers.check;
var setupTestDb              = helpers.setupTestDb;
var teardownTestDb           = helpers.teardownTestDb;
var setupTestDbForMW         = helpers.setupTestDbForMW;
var teardownMW               = helpers.teardownMW;
var listenOnRandomPort       = helpers.listenOnRandomPort;
var _makeFakeDriver          = helpers._makeFakeDriver;
var _makeSqliteDriver        = helpers._makeSqliteDriver;
var _makeFakeServiceAccount  = helpers._makeFakeServiceAccount;
var _mockReq                 = helpers._mockReq;
var _mockRes                 = helpers._mockRes;

async function testSession() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-session-"));
  try {
    await setupTestDb(tmpDir);

    // Create + verify
    var s1 = await b.session.create({ userId: "u-1", data: { csrfToken: "abc" } });
    check("create returns sealed token",            typeof s1.token === "string" && s1.token.indexOf("vault:") === 0);
    check("create returns expiresAt > now",         s1.expiresAt > Date.now());

    var v1 = await b.session.verify(s1.token);
    check("verify returns the session",             v1 && v1.userId === "u-1");
    check("verify decrypts data field",             v1 && v1.data && v1.data.csrfToken === "abc");

    // The plaintext sid should NEVER be in the DB — only its hash
    var rawRows = b.db.prepare("SELECT sidHash FROM _blamejs_sessions").all();
    check("only sidHash stored, never plaintext sid",
          rawRows.every(r => r.sidHash !== s1.token && r.sidHash.length === 128));

    // verify on garbage token returns null
    check("verify on garbage token returns null",   (await b.session.verify("not-a-real-token")) === null);
    check("verify on empty token returns null",     (await b.session.verify("")) === null);

    // touch
    var beforeTouch = await b.session.verify(s1.token);
    var t0 = beforeTouch.lastActivity;
    // Sleep briefly to ensure lastActivity changes
    await new Promise(function (r) { setTimeout(r, 10); });
    var ok = await b.session.touch(s1.token);
    check("touch returns true",                     ok === true);
    var afterTouch = await b.session.verify(s1.token);
    check("touch updates lastActivity",             afterTouch.lastActivity > t0);

    // touch's extendBy is bounded by the same MAX_TTL_MS as create / rotate
    // (10 years). Repeated touches with arbitrary extendBy values
    // can't push expiresAt past that bound.
    var extendThrew = null;
    try { await b.session.touch(s1.token, { extendBy: 1000 * 60 * 60 * 24 * 365 * 100 }); }
    catch (e) { extendThrew = e; }
    check("touch rejects extendBy beyond MAX_TTL_MS",
          extendThrew && /exceeds maximum/.test(extendThrew.message || ""));
    var negThrew = null;
    try { await b.session.touch(s1.token, { extendBy: -1 }); }
    catch (e) { negThrew = e; }
    check("touch rejects negative extendBy",        negThrew !== null);
    var nanThrew = null;
    try { await b.session.touch(s1.token, { extendBy: NaN }); }
    catch (e) { nanThrew = e; }
    check("touch rejects NaN extendBy",             nanThrew !== null);

    // destroyAllForUser
    var s2 = await b.session.create({ userId: "u-1" });
    var s3 = await b.session.create({ userId: "u-2" });
    check("count includes all active sessions",     (await b.session.count()) === 3);
    var nDel = await b.session.destroyAllForUser("u-1");
    check("destroyAllForUser returns count",        nDel === 2);
    check("u-1's sessions all gone",
          (await b.session.verify(s1.token)) === null && (await b.session.verify(s2.token)) === null);
    check("u-2's session survives",                 (await b.session.verify(s3.token)) !== null);

    // destroy single
    check("destroy returns true on success",        (await b.session.destroy(s3.token)) === true);
    check("destroy returns false on missing",       (await b.session.destroy(s3.token)) === false);

    // Expired session auto-cleans on verify
    var sExp = await b.session.create({ userId: "u-3", ttlMs: 50 });
    await new Promise(function (r) { setTimeout(r, 100); });
    check("verify on expired session returns null", (await b.session.verify(sExp.token)) === null);

    // purgeExpired
    var sExp2 = await b.session.create({ userId: "u-4", ttlMs: 50 });
    void sExp2;
    await new Promise(function (r) { setTimeout(r, 100); });
    var purged = await b.session.purgeExpired();
    check("purgeExpired returns count",             purged >= 1);

    // Invalid input — session.create rejects synchronously before
    // returning a Promise, so the throw is observable via try/catch
    // around the awaited call (the rejected Promise raises in await).
    var rejected = false;
    try { await b.session.create({}); } catch (_) { rejected = true; }
    check("session.create requires userId",         rejected);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testDataResidency() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-dr-"));
  try {
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      auditSigning: { mode: "plaintext" },
      schema:  [{ name: "x", columns: { _id: "TEXT PRIMARY KEY" } }],
      dataResidency: { region: "EU", allowedStorageRegions: ["eu-west-1"] },
    });
    var dr = b.db.getDataResidency();
    check("getDataResidency returns config",         dr && dr.region === "EU");
    check("dataResidency includes allowedRegions",   dr.allowedStorageRegions[0] === "eu-west-1");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testStorage() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-storage-"));
  try {
    await setupTestDb(tmpDir);
    b.storage.init({ backend: "local", uploadDir: path.join(tmpDir, "uploads") });

    var content = Buffer.from("hello blamejs storage " + Date.now(), "utf8");
    var saved = await b.storage.saveFile(content, "user-1/welcome.txt");
    check("saveFile returns storedPath",            saved.storedPath === "user-1/welcome.txt");
    check("saveFile returns sealed encryptionKey",
          typeof saved.encryptionKey === "string" && saved.encryptionKey.startsWith("vault:"));

    // The on-disk file must NOT contain the plaintext content
    var onDisk = fs.readFileSync(path.join(tmpDir, "uploads", "user-1/welcome.txt"));
    check("on-disk file is encrypted (not plaintext)",  onDisk.indexOf(content) === -1);
    check("on-disk file starts with format byte 0x02",  onDisk[0] === b.constants.FORMAT.XCHACHA20_POLY1305);

    // Round-trip
    var decrypted = await b.storage.getFileBuffer("user-1/welcome.txt", saved.encryptionKey);
    check("getFileBuffer round-trip preserves content", decrypted.equals(content));

    // Stream form
    var stream = await b.storage.getFileStream("user-1/welcome.txt", saved.encryptionKey);
    var chunks = [];
    for await (var chunk of stream) chunks.push(chunk);
    var streamed = Buffer.concat(chunks);
    check("getFileStream round-trip preserves content", streamed.equals(content));

    // Wrong key fails
    var wrongRejected = false;
    try { await b.storage.getFileBuffer("user-1/welcome.txt", b.vault.seal("not-the-real-key")); }
    catch (_) { wrongRejected = true; }
    check("getFileBuffer with wrong key throws",       wrongRejected);

    // No key required throws
    var noKeyRejected = false;
    try { await b.storage.getFileBuffer("user-1/welcome.txt", null); }
    catch (_) { noKeyRejected = true; }
    check("getFileBuffer without key throws",          noKeyRejected);

    // exists
    check("exists returns true on present file",       (await b.storage.exists("user-1/welcome.txt")) === true);
    check("exists returns false on missing",           (await b.storage.exists("does/not/exist.txt")) === false);

    // saveRaw / getRawBuffer (no encryption)
    var rawContent = Buffer.from("already-encrypted-or-not-sensitive", "utf8");
    await b.storage.saveRaw(rawContent, "raw/blob.bin");
    var rawBack = await b.storage.getRawBuffer("raw/blob.bin");
    check("saveRaw / getRawBuffer round-trip",        rawBack.equals(rawContent));

    // deleteFile
    check("deleteFile returns true on existing",       (await b.storage.deleteFile("user-1/welcome.txt")) === true);
    check("deleteFile returns false on missing",       (await b.storage.deleteFile("user-1/welcome.txt")) === false);
    check("file no longer exists after delete",        (await b.storage.exists("user-1/welcome.txt")) === false);

    // Path traversal rejected
    var traversalRejected = false;
    try { await b.storage.saveFile(content, "../escape.txt"); }
    catch (_) { traversalRejected = true; }
    check("path traversal via .. rejected",            traversalRejected);

    var absRejected = false;
    try { await b.storage.saveFile(content, "/etc/passwd"); }
    catch (_) { absRejected = true; }
    check("absolute path rejected",                    absRejected);

    var nullByteRejected = false;
    try { await b.storage.saveFile(content, "ok injected"); }
    catch (_) { nullByteRejected = true; }
    check("null-byte in path rejected",                nullByteRejected);

    // S3 backend not yet available
    b.storage._resetForTest();
    var s3Rejected = false;
    try { b.storage.init({ backend: "s3", bucket: "x" }); }
    catch (e) { s3Rejected = /sigv4|deferred|not yet/i.test(e.message); }
    check("storage backend 's3' deferred with clear message", s3Rejected);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testMultiBackend() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-multi-"));
  try {
    await setupTestDb(tmpDir);
    b.storage.init({
      backends: {
        "primary": {
          protocol:        "local",
          rootDir:         path.join(tmpDir, "primary"),
          classifications: ["personal"],
          residencyTag:    "unrestricted",
        },
        "ops": {
          protocol:        "local",
          rootDir:         path.join(tmpDir, "ops"),
          classifications: ["operational", "public"],
          residencyTag:    "unrestricted",
        },
      },
      defaultClassification: "personal",
      refuseUnclassified:    true,
    });

    var listed = b.storage.listBackends();
    check("listBackends returns 2 entries",            listed.length === 2);
    check("backend names enumerated",                  listed.some(b => b.name === "primary") && listed.some(b => b.name === "ops"));

    // Save personal data → routes to 'primary'
    var content1 = Buffer.from("private medical record", "utf8");
    var saved1 = await b.storage.saveFile(content1, "patient/123.json", { classification: "personal" });
    check("personal data routes to primary",           saved1.backend === "primary");

    // Save operational data → routes to 'ops'
    var content2 = Buffer.from("nginx access log line", "utf8");
    var saved2 = await b.storage.saveFile(content2, "logs/2026-04-25.log", { classification: "operational" });
    check("operational data routes to ops",            saved2.backend === "ops");

    // File lands in the right physical directory
    check("personal file in primary tree",             fs.existsSync(path.join(tmpDir, "primary", "patient/123.json")));
    check("operational file in ops tree",              fs.existsSync(path.join(tmpDir, "ops", "logs/2026-04-25.log")));
    check("personal NOT in ops tree",                  !fs.existsSync(path.join(tmpDir, "ops", "patient/123.json")));

    // Round-trip with explicit backend opt
    var back = await b.storage.getFileBuffer("patient/123.json", saved1.encryptionKey, { backend: "primary" });
    check("explicit-backend round-trip works",         back.equals(content1));

    // Unknown classification → fails
    var unknownClsRejected = false;
    try { await b.storage.saveFile(content1, "test", { classification: "unknown" }); }
    catch (e) { unknownClsRejected = e.code === "NO_BACKEND_FOR_CLASSIFICATION"; }
    check("unknown classification rejected",           unknownClsRejected);

    // refuseUnclassified: missing classification rejected
    var noClsRejected = false;
    try { await b.storage.saveFile(content1, "test"); }
    catch (e) { noClsRejected = e.code === "UNCLASSIFIED"; }
    check("refuseUnclassified rejects missing classification", noClsRejected);

    // Wrong-backend-for-classification rejected
    var wrongBackendRejected = false;
    try { await b.storage.saveFile(content1, "test", { backend: "ops", classification: "personal" }); }
    catch (e) { wrongBackendRejected = e.code === "CLASSIFICATION_MISMATCH"; }
    check("backend that doesn't serve classification rejected", wrongBackendRejected);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClassificationRouting() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cls-"));
  try {
    await setupTestDb(tmpDir);
    // Wildcard backend serves any classification
    b.storage.init({
      backends: {
        "any": {
          protocol:        "local",
          rootDir:         path.join(tmpDir, "any"),
          classifications: ["*"],
          residencyTag:    "unrestricted",
        },
      },
    });

    var c1 = Buffer.from("a", "utf8");
    var s1 = await b.storage.saveFile(c1, "x", { classification: "personal" });
    check("wildcard backend accepts personal",         s1.backend === "any");
    var s2 = await b.storage.saveFile(c1, "y", { classification: "audit-archive" });
    check("wildcard backend accepts custom class",     s2.backend === "any");
    var s3 = await b.storage.saveFile(c1, "z");
    check("wildcard backend accepts no-classification", s3.backend === "any");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testResidencyEnforcement() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-residency-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      auditSigning: { mode: "plaintext" },
      schema:  [],
      dataResidency: { region: "EU", allowedStorageRegions: ["EU"] },
    });

    // Configuring a personal-data backend tagged US should refuse to init
    var residencyViolation = false;
    try {
      b.storage.init({
        backends: {
          "us-bad": {
            protocol:        "local",
            rootDir:         path.join(tmpDir, "us"),
            classifications: ["personal"],
            residencyTag:    "US",   // ← violation
          },
        },
      });
    } catch (e) {
      residencyViolation = e.code === "RESIDENCY_VIOLATION";
    }
    check("personal-data backend outside region refused", residencyViolation);

    // EU-tagged backend is fine
    b.storage._resetForTest();
    b.storage.init({
      backends: {
        "eu-ok": {
          protocol:        "local",
          rootDir:         path.join(tmpDir, "eu"),
          classifications: ["personal"],
          residencyTag:    "EU",
        },
      },
    });
    var listed = b.storage.listBackends();
    check("EU-tagged backend accepted",                listed.length === 1 && listed[0].residencyTag === "EU");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testRetryAndBreaker() {
  // Retry policy unit tests — exercise withRetry directly without backend setup
  var attempts = 0;
  var transientErr = function () {
    attempts += 1;
    var e = new Error("transient");
    e.statusCode = 503;
    e.isObjectStoreError = true;
    e.permanent = false;
    throw e;
  };

  // Retries 5xx
  var caught = false;
  attempts = 0;
  try {
    await b.retry.withRetry(transientErr, { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5 });
  } catch (_) { caught = true; }
  check("retry exhausts maxAttempts on transient",     caught && attempts === 3);

  // Does NOT retry permanent (4xx)
  attempts = 0;
  var permErr = function () {
    attempts += 1;
    var e = new Error("forbidden");
    e.statusCode = 403;
    e.isObjectStoreError = true;
    e.permanent = true;
    throw e;
  };
  var permCaught = false;
  try { await b.retry.withRetry(permErr, { maxAttempts: 5 }); }
  catch (_) { permCaught = true; }
  check("retry does NOT retry permanent errors",       permCaught && attempts === 1);

  // Retryable classification
  check("isRetryable: 503 → true",                     b.retry.isRetryable({ statusCode: 503 }));
  check("isRetryable: 403 → false",                    !b.retry.isRetryable({ statusCode: 403 }));
  check("isRetryable: ECONNRESET → true",              b.retry.isRetryable({ code: "ECONNRESET" }));
  check("isRetryable: ENOENT → false (not in retry set)", !b.retry.isRetryable({ code: "ENOENT" }));

  // Circuit breaker
  var breaker = new b.retry.CircuitBreaker("test", { failureThreshold: 3, cooldownMs: 50, successThreshold: 1 });
  check("breaker starts closed",                       breaker.getState() === "closed");
  // Trip it
  for (var i = 0; i < 3; i++) {
    try { await breaker.wrap(function () { throw Object.assign(new Error("fail"), { code: "ECONNRESET" }); }); }
    catch (_) {}
  }
  check("breaker opens after threshold",               breaker.getState() === "open");

  // Open breaker fails fast (CIRCUIT_OPEN code)
  var fastFail = false;
  try { await breaker.wrap(function () { return Promise.resolve("never-runs"); }); }
  catch (e) { fastFail = e.code === "CIRCUIT_OPEN"; }
  check("open breaker fails fast",                     fastFail);

  // Wait for cooldown then half-open + success closes
  await new Promise(function (r) { setTimeout(r, 60); });
  await breaker.wrap(function () { return Promise.resolve("ok"); });
  check("breaker closes after successful probe",       breaker.getState() === "closed");
}

function testSigv4Primitives() {
  var sigv4 = require("../lib/object-store/sigv4");

  // AWS-published test vector for signing-key derivation
  // (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html)
  var key = sigv4.deriveSigningKey(
    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    "20150830",
    "us-east-1",
    "iam"
  );
  var hex = key.toString("hex");
  check("sigv4 deriveSigningKey matches AWS test vector",
        hex === "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");

  // awsUriEncode
  check("awsUriEncode preserves alphanumerics and unreserved",
        sigv4.awsUriEncode("hello-world.txt", true) === "hello-world.txt");
  check("awsUriEncode encodes spaces",
        sigv4.awsUriEncode("a b", true) === "a%20b");
  check("awsUriEncode preserves slashes when encodeSlash=false",
        sigv4.awsUriEncode("foo/bar", false) === "foo/bar");
  check("awsUriEncode encodes slashes when encodeSlash=true",
        sigv4.awsUriEncode("foo/bar", true) === "foo%2Fbar");

  // canonicalQueryString — sorted, encoded
  var u = new (require("url").URL)("https://x/?b=2&a=1&c=3");
  check("canonicalQueryString sorts keys",
        sigv4.canonicalQueryString(u.searchParams) === "a=1&b=2&c=3");

  // canonicalHeaders — lowercase keys, sorted, signed list
  var ch = sigv4.canonicalHeaders({ "X-Foo": "bar", host: "example.com", "Z-Last": "  trim  " });
  check("canonicalHeaders has trailing newline per pair",
        /host:example\.com\n/.test(ch.canonical));
  check("canonicalHeaders lowercases + sorts",
        ch.signed === "host;x-foo;z-last");
  check("canonicalHeaders trims + collapses whitespace",
        /z-last:trim\n/.test(ch.canonical));

  // signRequest produces an Authorization header with the right shape
  var signed = sigv4.signRequest({
    method:          "GET",
    url:             "https://test-bucket.s3.us-east-1.amazonaws.com/key1",
    headers:         {},
    payloadHash:     sigv4.sha256Hex(Buffer.alloc(0)),
    region:          "us-east-1",
    accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    date:            new Date(Date.UTC(2026, 3, 25, 12, 34, 56)),  // 2026-04-25T12:34:56Z
  });
  check("signRequest produces AWS4-HMAC-SHA256 Authorization",
        /^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/20260425\/us-east-1\/s3\/aws4_request, SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$/.test(signed.headers["Authorization"]));
  check("signRequest sets host header",         signed.headers["host"] === "test-bucket.s3.us-east-1.amazonaws.com");
  check("signRequest sets x-amz-date",          signed.headers["x-amz-date"] === "20260425T123456Z");
  check("signRequest sets x-amz-content-sha256",
        signed.headers["x-amz-content-sha256"] === sigv4.sha256Hex(Buffer.alloc(0)));
  check("signRequest signature is deterministic for same inputs",
        signed.signature.length === 64);

  // Same inputs → same signature
  var signed2 = sigv4.signRequest({
    method:          "GET",
    url:             "https://test-bucket.s3.us-east-1.amazonaws.com/key1",
    headers:         {},
    payloadHash:     sigv4.sha256Hex(Buffer.alloc(0)),
    region:          "us-east-1",
    accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    date:            new Date(Date.UTC(2026, 3, 25, 12, 34, 56)),
  });
  check("signRequest deterministic across calls",  signed.signature === signed2.signature);
}

async function testSigv4MockServer() {
  var http = require("http");
  var sigv4 = require("../lib/object-store/sigv4");

  // In-process mock S3 server. Validates request shape (Authorization +
  // x-amz-date + x-amz-content-sha256) and stores PUT bodies in memory
  // so subsequent GET/HEAD/LIST/DELETE can return them.
  var stored = {};
  var server = http.createServer(function (req, res) {
    var auth = req.headers["authorization"] || "";
    if (!/^AWS4-HMAC-SHA256 /.test(auth)) {
      res.writeHead(401); res.end("missing AWS4-HMAC-SHA256"); return;
    }
    if (!req.headers["x-amz-date"]) {
      res.writeHead(400); res.end("missing x-amz-date"); return;
    }
    if (!req.headers["x-amz-content-sha256"]) {
      res.writeHead(400); res.end("missing x-amz-content-sha256"); return;
    }
    // Strip query for routing; URL parse needs Host header
    var pathname = req.url.split("?")[0];
    // Path-style: /bucket/key  → key extraction
    var m = pathname.match(/^\/[^/]+\/(.+)$/);
    var key = m ? m[1] : null;

    if (req.method === "PUT" && key) {
      var bufs = [];
      req.on("data", function (c) { bufs.push(c); });
      req.on("end", function () {
        stored[key] = Buffer.concat(bufs);
        res.writeHead(200, { ETag: '"' + sigv4.sha256Hex(stored[key]).slice(0, 32) + '"' });
        res.end();
      });
      return;
    }
    if (req.method === "GET" && key && stored[key]) {
      res.writeHead(200, { "Content-Length": stored[key].length });
      res.end(stored[key]);
      return;
    }
    if (req.method === "GET" && pathname === "/test-bucket/" || (req.url || "").indexOf("list-type=2") !== -1) {
      // List request
      var xml = "<?xml version=\"1.0\"?><ListBucketResult>";
      Object.keys(stored).forEach(function (k) {
        xml += "<Contents><Key>" + k + "</Key><Size>" + stored[k].length + "</Size>" +
               "<LastModified>2026-04-25T00:00:00.000Z</LastModified></Contents>";
      });
      xml += "<IsTruncated>false</IsTruncated></ListBucketResult>";
      res.writeHead(200, { "Content-Type": "application/xml" });
      res.end(xml);
      return;
    }
    if (req.method === "HEAD" && key && stored[key]) {
      res.writeHead(200, { "Content-Length": stored[key].length });
      res.end();
      return;
    }
    if (req.method === "DELETE" && key) {
      if (stored[key]) {
        delete stored[key];
        res.writeHead(204); res.end();
      } else {
        res.writeHead(404); res.end();
      }
      return;
    }
    res.writeHead(404); res.end();
  });

  var port = await listenOnRandomPort(server);
  try {
    var client = sigv4.create({
      endpoint:         "http://127.0.0.1:" + port,
      region:           "us-east-1",
      bucket:           "test-bucket",
      accessKeyId:      "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey:  "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      pathStyle:        true,   // 127.0.0.1 doesn't support virtual-hosted
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,   // local mock — opt in to cleartext
      allowInternal:    true,
    });

    // PUT
    var content = Buffer.from("sigv4 test payload " + Date.now(), "utf8");
    var putResult = await client.put("dir/object.bin", content);
    check("sigv4 put returns size + etag", putResult.size === content.length && typeof putResult.etag === "string");

    // GET round-trip
    var got = await client.get("dir/object.bin");
    check("sigv4 get round-trips bytes", got.equals(content));

    // HEAD
    var meta = await client.head("dir/object.bin");
    check("sigv4 head returns size",     meta.size === content.length);

    // LIST
    var listed = await client.list("");
    check("sigv4 list returns 1 item",   listed.items.length === 1);
    check("sigv4 list returns the key",  listed.items[0].key === "dir/object.bin");

    // DELETE
    var del = await client.delete("dir/object.bin");
    check("sigv4 delete returns true",   del === true);
    var del2 = await client.delete("dir/object.bin");
    check("sigv4 delete on missing returns false", del2 === false);
  } finally {
    server.close();
  }
}

function testGcsPrimitives() {
  var gcs = require("../lib/object-store/gcs");

  // base64url encoding (no padding, '+'→'-', '/'→'_')
  var b1 = gcs._base64UrlEncode(Buffer.from("hello"));
  check("gcs base64url encodes basic input",         b1 === "aGVsbG8");
  var b2 = gcs._base64UrlEncode(Buffer.from([0xff, 0xff, 0xff]));
  check("gcs base64url has no padding",              !/=/.test(b2));
  check("gcs base64url uses '-' and '_'",            !/\+|\//.test(b2));

  // JWT signing with a real keypair
  var sa = _makeFakeServiceAccount();
  var jwt = gcs._signJwt(sa, "test-scope", "https://oauth2.googleapis.com/token");
  var parts = jwt.split(".");
  check("JWT has 3 parts",                           parts.length === 3);
  // Header is base64url(JSON({ alg, typ }))
  var headerJson = JSON.parse(Buffer.from(parts[0].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  check("JWT header alg is RS256",                   headerJson.alg === "RS256");
  check("JWT header typ is JWT",                     headerJson.typ === "JWT");
  var claimJson = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  check("JWT iss is service-account email",          claimJson.iss === sa.client_email);
  check("JWT scope is honored",                      claimJson.scope === "test-scope");
  check("JWT aud is token endpoint",                 claimJson.aud === "https://oauth2.googleapis.com/token");
  check("JWT exp - iat = 3600",                      claimJson.exp - claimJson.iat === 3600);
}

async function testGcsMockServer() {
  var http = require("http");
  var url = require("url");
  var gcs = require("../lib/object-store/gcs");
  var sa = _makeFakeServiceAccount();

  var stored = {};
  var tokenIssued = 0;

  // Mock OAuth2 token endpoint + storage JSON API on the same server,
  // routed by pathname.
  var server = http.createServer(function (req, res) {
    var u = new url.URL(req.url, "http://x");
    var path = u.pathname;

    // Token exchange
    if (req.method === "POST" && path === "/token") {
      var bufs = [];
      req.on("data", function (c) { bufs.push(c); });
      req.on("end", function () {
        var body = Buffer.concat(bufs).toString("utf8");
        if (!/grant_type=urn/.test(body) || !/assertion=/.test(body)) {
          res.writeHead(400); res.end("bad request"); return;
        }
        tokenIssued += 1;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "mock-access-token-" + tokenIssued, expires_in: 3600, token_type: "Bearer" }));
      });
      return;
    }

    // All storage operations require Bearer auth
    if (!/^Bearer mock-access-token-/.test(req.headers["authorization"] || "")) {
      res.writeHead(401); res.end("missing bearer"); return;
    }

    // PUT object: POST /upload/storage/v1/b/<bucket>/o?uploadType=media&name=<key>
    if (req.method === "POST" && /^\/upload\/storage\/v1\/b\/[^/]+\/o$/.test(path)) {
      var name = u.searchParams.get("name");
      var bufs2 = [];
      req.on("data", function (c) { bufs2.push(c); });
      req.on("end", function () {
        stored[name] = Buffer.concat(bufs2);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ name: name, size: String(stored[name].length), etag: "\"" + name + "\"", updated: "2026-04-25T00:00:00.000Z" }));
      });
      return;
    }

    // GET / HEAD: /storage/v1/b/<bucket>/o/<encoded-key>
    var objectMatch = path.match(/^\/storage\/v1\/b\/[^/]+\/o\/(.+)$/);
    if (objectMatch && req.method === "GET") {
      var key = decodeURIComponent(objectMatch[1]);
      if (u.searchParams.get("alt") === "media") {
        if (stored[key]) {
          res.writeHead(200); res.end(stored[key]);
        } else {
          res.writeHead(404); res.end();
        }
      } else {
        // metadata
        if (stored[key]) {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ name: key, size: String(stored[key].length), etag: "\"" + key + "\"", updated: "2026-04-25T00:00:00.000Z" }));
        } else {
          res.writeHead(404); res.end();
        }
      }
      return;
    }
    if (objectMatch && req.method === "DELETE") {
      var dkey = decodeURIComponent(objectMatch[1]);
      if (stored[dkey]) { delete stored[dkey]; res.writeHead(204); res.end(); }
      else { res.writeHead(404); res.end(); }
      return;
    }

    // LIST: /storage/v1/b/<bucket>/o (no /<key>)
    if (req.method === "GET" && /^\/storage\/v1\/b\/[^/]+\/o$/.test(path)) {
      var prefix = u.searchParams.get("prefix") || "";
      var items = Object.keys(stored).filter(function (k) { return k.indexOf(prefix) === 0; }).map(function (k) {
        return { name: k, size: String(stored[k].length), updated: "2026-04-25T00:00:00.000Z" };
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ items: items }));
      return;
    }

    res.writeHead(404); res.end();
  });

  var port = await listenOnRandomPort(server);
  try {
    var client = gcs.create({
      bucket:           "test-bucket",
      serviceAccount:   sa,
      endpoint:         "http://127.0.0.1:" + port,
      tokenEndpoint:    "http://127.0.0.1:" + port + "/token",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });

    var content = Buffer.from("gcs test payload " + Date.now(), "utf8");
    var putResult = await client.put("dir/object.bin", content);
    check("gcs put returns size",                    putResult.size === content.length);

    var got = await client.get("dir/object.bin");
    check("gcs get round-trips bytes",               got.equals(content));

    var meta = await client.head("dir/object.bin");
    check("gcs head returns size",                   meta.size === content.length);

    var listed = await client.list("");
    check("gcs list returns 1 item",                 listed.items.length === 1);
    check("gcs list returns the key",                listed.items[0].key === "dir/object.bin");

    var del = await client.delete("dir/object.bin");
    check("gcs delete returns true",                 del === true);

    // Token caching: should have only issued ONE token across all calls
    check("gcs token issued once and cached across calls",  tokenIssued === 1);
  } finally {
    server.close();
  }
}

function testAzureBlobPrimitives() {
  var az = require("../lib/object-store/azure-blob");

  // signRequest produces SharedKey-format Authorization
  var s = az.signRequest({
    method:      "PUT",
    url:         "https://test.blob.core.windows.net/c/key1",
    headers:     { "Content-Type": "application/octet-stream", "Content-Length": "5", "x-ms-blob-type": "BlockBlob" },
    accountName: "test",
    accountKey:  Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "utf8").toString("base64"),
  });
  check("azure signRequest produces SharedKey auth",      /^SharedKey test:/.test(s.headers["Authorization"]));
  check("azure signRequest sets x-ms-version",            !!s.headers["x-ms-version"]);
  check("azure signRequest sets x-ms-date",               !!s.headers["x-ms-date"]);
  check("azure signature is base64",                      /^[A-Za-z0-9+/=]+$/.test(s.signature));

  // Same inputs at same time produce same signature
  var date = new Date(Date.UTC(2026, 3, 25, 12, 34, 56));
  var dateStr = date.toUTCString();
  var s1 = az.signRequest({
    method:      "GET",
    url:         "https://test.blob.core.windows.net/c/key2",
    headers:     { "x-ms-date": dateStr },
    accountName: "test",
    accountKey:  Buffer.from("ZZZZZZZZ", "base64").toString("base64"),
  });
  var s2 = az.signRequest({
    method:      "GET",
    url:         "https://test.blob.core.windows.net/c/key2",
    headers:     { "x-ms-date": dateStr },
    accountName: "test",
    accountKey:  Buffer.from("ZZZZZZZZ", "base64").toString("base64"),
  });
  check("azure signature deterministic for same inputs",  s1.signature === s2.signature);
}

async function testAzureBlobMockServer() {
  var http = require("http");
  var az = require("../lib/object-store/azure-blob");

  var stored = {};
  var server = http.createServer(function (req, res) {
    if (!/^SharedKey /.test(req.headers["authorization"] || "")) {
      res.writeHead(401); res.end("missing SharedKey"); return;
    }
    if (!req.headers["x-ms-version"]) { res.writeHead(400); res.end("missing x-ms-version"); return; }
    if (!req.headers["x-ms-date"])    { res.writeHead(400); res.end("missing x-ms-date"); return; }

    var path = req.url.split("?")[0];
    var keyMatch = path.match(/^\/[^/]+\/(.+)$/);
    var key = keyMatch ? keyMatch[1] : null;

    if (req.method === "PUT" && key) {
      if (req.headers["x-ms-blob-type"] !== "BlockBlob") { res.writeHead(400); res.end("bad blob type"); return; }
      var bufs = [];
      req.on("data", function (c) { bufs.push(c); });
      req.on("end", function () {
        stored[key] = Buffer.concat(bufs);
        res.writeHead(201, { ETag: "\"" + key + "\"" });
        res.end();
      });
      return;
    }
    if (req.method === "GET" && key && stored[key]) {
      res.writeHead(200, { "Content-Length": stored[key].length });
      res.end(stored[key]);
      return;
    }
    if (req.method === "HEAD" && key && stored[key]) {
      res.writeHead(200, { "Content-Length": stored[key].length });
      res.end();
      return;
    }
    if (req.method === "DELETE" && key) {
      if (stored[key]) { delete stored[key]; res.writeHead(202); res.end(); }
      else { res.writeHead(404); res.end(); }
      return;
    }
    if (req.method === "GET" && (req.url || "").indexOf("comp=list") !== -1) {
      var xml = "<?xml version=\"1.0\"?><EnumerationResults><Blobs>";
      Object.keys(stored).forEach(function (k) {
        xml += "<Blob><Name>" + k + "</Name><Properties><Content-Length>" + stored[k].length + "</Content-Length><Last-Modified>Sat, 25 Apr 2026 00:00:00 GMT</Last-Modified></Properties></Blob>";
      });
      xml += "</Blobs><NextMarker/></EnumerationResults>";
      res.writeHead(200, { "Content-Type": "application/xml" });
      res.end(xml);
      return;
    }
    res.writeHead(404); res.end();
  });

  var port = await listenOnRandomPort(server);
  try {
    var client = az.create({
      accountName:      "test",
      accountKey:       Buffer.from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "utf8").toString("base64"),
      container:        "test-container",
      endpoint:         "http://127.0.0.1:" + port,
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });

    var content = Buffer.from("azure test payload " + Date.now(), "utf8");
    var putResult = await client.put("dir/blob.bin", content);
    check("azure put returns size",                  putResult.size === content.length);

    var got = await client.get("dir/blob.bin");
    check("azure get round-trips bytes",             got.equals(content));

    var meta = await client.head("dir/blob.bin");
    check("azure head returns size",                 meta.size === content.length);

    var listed = await client.list("");
    check("azure list returns 1 item",               listed.items.length === 1);
    check("azure list returns the key",              listed.items[0].key === "dir/blob.bin");

    var del = await client.delete("dir/blob.bin");
    check("azure delete returns true",               del === true);
  } finally {
    server.close();
  }
}

async function testQueueLocal() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-queue-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    check("queue namespace present",                  typeof b.queue === "object");
    check("queue.listBackends has 1 entry",           b.queue.listBackends().length === 1);

    // Enqueue
    var result = await b.queue.enqueue("send-welcome", { userId: "u-1", email: "a@b.com" }, {
      classification: "personal",
      traceId:        "trace-123",
    });
    check("enqueue returns jobId",                     typeof result.jobId === "string");
    check("enqueue returns queueName",                 result.queueName === "send-welcome");
    check("enqueue returns classification",            result.classification === "personal");

    // size reflects pending
    check("size returns 1 after one enqueue",          (await b.queue.size("send-welcome")) === 1);

    // payload sealed on disk
    var rawRow = b.db.prepare("SELECT payload FROM _blamejs_jobs WHERE _id = ?").get(result.jobId);
    check("queue payload sealed in DB",                rawRow.payload.startsWith("vault:"));

    // unrelated queue is independent
    check("size returns 0 for empty queue",            (await b.queue.size("other-queue")) === 0);

    // purge clears
    var purged = await b.queue.purge("send-welcome");
    check("purge returns count of deleted",            purged === 1);
    check("size returns 0 after purge",                (await b.queue.size("send-welcome")) === 0);

    // Reserved table name protection still works
    check("_blamejs_jobs is reserved",                 b.db.RESERVED_TABLE_NAMES.has("_blamejs_jobs"));
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueConsume() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qcons-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var processed = [];
    var consumer = b.queue.consume("test-job", function (job) {
      processed.push(job.payload);
      return Promise.resolve();
    }, { concurrency: 2, pollIntervalMs: 50, fastPollMs: 20, leaseDurationMs: 5000 });

    await b.queue.enqueue("test-job", { msg: "hello-1" });
    await b.queue.enqueue("test-job", { msg: "hello-2" });
    await b.queue.enqueue("test-job", { msg: "hello-3" });

    // Wait for processing (poll up to 3s)
    var deadline = Date.now() + 3000;
    while (processed.length < 3 && Date.now() < deadline) {
      await new Promise(function (r) { setTimeout(r, 50); });
    }
    check("consume processed all 3 jobs",              processed.length === 3);
    check("payloads decoded correctly",                processed.some(p => p.msg === "hello-1"));
    check("queue size 0 after consume",                (await b.queue.size("test-job")) === 0);

    // All jobs should be in 'done' status
    var doneCount = b.db.prepare("SELECT COUNT(*) AS n FROM _blamejs_jobs WHERE queueName = ? AND status = ?").get("test-job", "done");
    check("all jobs marked done",                      doneCount.n === 3);

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit chain has system.queue.enqueue + .consume.start + .consume.success
    var enqRows = await b.audit.query({ action: "system.queue.enqueue" });
    check("audit recorded enqueue events",             enqRows.length === 3);
    var sucRows = await b.audit.query({ action: "system.queue.consume.success" });
    check("audit recorded consume.success events",     sucRows.length === 3);

    consumer.cancel();
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueRetryAndFail() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qfail-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var attempts = 0;
    var consumer = b.queue.consume("fail-job", function (_job) {
      attempts += 1;
      throw new Error("simulated failure attempt " + attempts);
    }, { concurrency: 1, pollIntervalMs: 50, fastPollMs: 20, leaseDurationMs: 5000 });

    await b.queue.enqueue("fail-job", { x: 1 }, { maxAttempts: 3 });

    // Wait until job is finally failed (3 attempts × ~exponential backoff = up to ~7s)
    var deadline = Date.now() + 12000;
    var lastStatus;
    while (Date.now() < deadline) {
      var row = b.db.prepare("SELECT status FROM _blamejs_jobs WHERE queueName = ?").get("fail-job");
      lastStatus = row && row.status;
      if (lastStatus === "failed") break;
      await new Promise(function (r) { setTimeout(r, 100); });
    }
    check("job ends up in 'failed' status after maxAttempts",  lastStatus === "failed");
    check("handler invoked maxAttempts times",                 attempts === 3);

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit chain has consume.failure events
    var failRows = await b.audit.query({ action: "system.queue.consume.failure" });
    check("audit recorded consume.failure events",             failRows.length === 3);

    consumer.cancel();
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueLeaseExpiry() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qlease-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    // Manually call lease via the backend to simulate a crashed handler
    // (lease the job, never complete or fail it).
    var localBackend = require("../lib/queue-local").create({});
    await b.queue.enqueue("orphan-job", { x: 1 });
    var leased = await localBackend.lease("orphan-job", 100, 1);  // 100ms lease
    check("lease returned the job",                    leased.length === 1);
    check("after lease, job status is inflight",
          b.db.prepare("SELECT status FROM _blamejs_jobs WHERE queueName = ?").get("orphan-job").status === "inflight");

    // Wait for lease to expire, then sweep
    await new Promise(function (r) { setTimeout(r, 200); });
    var swept = await localBackend.sweepExpired();
    check("sweepExpired returned 1 unstuck job",       swept === 1);
    check("unstuck job is back to pending",
          b.db.prepare("SELECT status FROM _blamejs_jobs WHERE queueName = ?").get("orphan-job").status === "pending");
  } finally {
    try { await b.queue.shutdown({ timeoutMs: 1000 }); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testQueueShutdown() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-qsh-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });

    var processed = 0;
    var consumer = b.queue.consume("shutdown-job", async function (_job) {
      // Long-running handler
      await new Promise(function (r) { setTimeout(r, 200); });
      processed += 1;
    }, { concurrency: 2, pollIntervalMs: 30, fastPollMs: 10, leaseDurationMs: 5000 });

    for (var i = 0; i < 3; i++) await b.queue.enqueue("shutdown-job", { i: i });
    await new Promise(function (r) { setTimeout(r, 100) }); // let some lease

    var t0 = Date.now();
    await b.queue.shutdown({ timeoutMs: 5000 });
    var elapsed = Date.now() - t0;

    check("shutdown waits for in-flight handlers",     processed >= 1);
    check("shutdown completes under timeout",          elapsed < 5000);
    void consumer;
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testJobsDefineAndEnqueue() {
  // Surface tests + a single-job round-trip. Uses the framework's
  // built-in 'local' queue protocol (SQLite via the framework DB).
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-jobs-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jobs = b.jobs.create();
    var processed = [];
    jobs.define("welcome", async function (job) {
      processed.push(job.payload.userId);
    });

    // stats() pre-start
    var s0 = jobs.stats();
    check("jobs.stats: defined names listed",          s0.defined.length === 1 && s0.defined[0] === "welcome");
    check("jobs.stats: started=false before start",    s0.started === false);

    // enqueue before start is fine — queue persists rows
    var enq = await jobs.enqueue("welcome", { userId: "u-1" });
    check("jobs.enqueue returns jobId",                typeof enq.jobId === "string");

    await jobs.start();
    check("jobs.stats: started=true after start",      jobs.stats().started === true);

    // Wait for the consumer to drain
    var t0 = Date.now();
    while (processed.length === 0 && Date.now() - t0 < 5000) {
      await new Promise(function (r) { setTimeout(r, 50); });
    }
    check("jobs: handler ran for enqueued job",        processed.length === 1 && processed[0] === "u-1");

    await jobs.shutdown({ timeoutMs: 2000 });
    check("jobs.shutdown: started=false after",         jobs.stats().started === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testJobsValidation() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-jobs-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jobs = b.jobs.create();

    // Invalid name / handler
    var threw = null;
    try { jobs.define("", async function () {}); } catch (e) { threw = e; }
    check("jobs.define: empty name rejected",          threw && threw.code === "INVALID_NAME");

    threw = null;
    try { jobs.define("x", "not-a-fn"); } catch (e) { threw = e; }
    check("jobs.define: non-function handler rejected", threw && threw.code === "INVALID_HANDLER");

    // Duplicate
    jobs.define("dup", async function () {});
    threw = null;
    try { jobs.define("dup", async function () {}); } catch (e) { threw = e; }
    check("jobs.define: duplicate name rejected",      threw && threw.code === "DUPLICATE_NAME");

    // enqueue without define
    threw = null;
    try { await jobs.enqueue("never-defined", {}); } catch (e) { threw = e; }
    check("jobs.enqueue: undefined name rejected",     threw && threw.code === "UNDEFINED_NAME");

    // allowUnregistered: true bypasses
    var permissive = b.jobs.create({ allowUnregisteredEnqueue: true });
    var enqOk = await permissive.enqueue("late-binding", { x: 1 });
    check("jobs.enqueue: allowUnregistered passes",    typeof enqOk.jobId === "string");

    // define after start rejected
    await jobs.start();
    threw = null;
    try { jobs.define("post-start", async function () {}); } catch (e) { threw = e; }
    check("jobs.define after start rejected",          threw && threw.code === "ALREADY_STARTED");

    await jobs.shutdown({ timeoutMs: 2000 });
    await permissive.shutdown({ timeoutMs: 2000 });
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testJobsMultipleHandlers() {
  // Two handlers, each consuming its own queue, dispatched correctly.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-jobs-"));
  try {
    await setupTestDb(tmpDir);
    b.queue.init({ backends: { primary: { protocol: "local" } } });
    var jobs = b.jobs.create({
      consumerDefaults: { pollIntervalMs: 30, fastPollMs: 10 },
    });
    var emails = [];
    var rebuilds = [];
    jobs.define("send-email",     async function (job) { emails.push(job.payload.to); });
    jobs.define("rebuild-index",  async function (job) { rebuilds.push(job.payload.what); });

    await jobs.start();
    await jobs.enqueue("send-email",     { to: "alice@example.com" });
    await jobs.enqueue("send-email",     { to: "bob@example.com" });
    await jobs.enqueue("rebuild-index",  { what: "users" });

    var t0 = Date.now();
    while ((emails.length < 2 || rebuilds.length < 1) && Date.now() - t0 < 5000) {
      await new Promise(function (r) { setTimeout(r, 50); });
    }
    check("jobs: both email handlers ran",             emails.length === 2);
    check("jobs: rebuild handler ran",                 rebuilds.length === 1);
    // Cross-handler isolation
    check("jobs: email handler didn't see rebuild payload",
          emails.indexOf("users") === -1);

    await jobs.shutdown({ timeoutMs: 2000 });
  } finally {
    await teardownTestDb(tmpDir);
  }
}

function testJobsSurface() {
  check("b.jobs namespace present",                    typeof b.jobs === "object");
  check("b.jobs.create is a function",                 typeof b.jobs.create === "function");
}

async function testLogStreamLocal() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-log-"));
  try {
    await setupTestDb(tmpDir);
    b.logStream.init({
      sinks: { primary: { protocol: "local", dir: path.join(tmpDir, "logs"), maxFileBytes: 1024 } },
      minLevel: "debug",
    });

    check("logStream namespace present",                  typeof b.logStream === "object");
    check("logStream.LEVELS includes debug/info/warn/error",
          b.logStream.LEVELS.length === 4);

    b.logStream.info("hello world", { user: "alice" });
    b.logStream.warn("watch out", { password: "should-be-redacted" });
    b.logStream.error("kaboom", { jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaa.bbbb" });

    // Allow async writes to complete
    await new Promise(function (r) { setTimeout(r, 50); });
    await b.logStream.shutdown();

    var logPath = path.join(tmpDir, "logs", "blamejs.log");
    check("log file exists",                              fs.existsSync(logPath));
    var content = fs.readFileSync(logPath, "utf8");
    var lines = content.trim().split("\n").filter(Boolean);
    check("3 events emitted as JSON lines",               lines.length === 3);

    var infoRecord = JSON.parse(lines[0]);
    check("first record has level=info",                  infoRecord.level === "info");
    check("first record has message",                     infoRecord.message === "hello world");
    check("first record has meta.user",                   infoRecord.meta.user === "alice");

    var warnRecord = JSON.parse(lines[1]);
    check("warn record password is redacted",             warnRecord.meta.password === "[REDACTED]");

    var errRecord = JSON.parse(lines[2]);
    check("error record JWT-shaped value redacted",       errRecord.meta.jwt === "[REDACTED-JWT]");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testLogStreamWebhook() {
  var http = require("http");
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-loghook-"));
  try {
    await setupTestDb(tmpDir);

    var received = [];
    var server = http.createServer(function (req, res) {
      if (req.headers["authorization"] !== "Bearer test-token") {
        res.writeHead(401); res.end("missing auth"); return;
      }
      var bufs = [];
      req.on("data", function (c) { bufs.push(c); });
      req.on("end", function () {
        try {
          var batch = JSON.parse(Buffer.concat(bufs).toString("utf8"));
          batch.forEach(function (ev) { received.push(ev); });
          res.writeHead(200); res.end("ok");
        } catch (e) { res.writeHead(400); res.end(e.message); }
      });
    });
    var port = await listenOnRandomPort(server);

    try {
      b.logStream.init({
        sinks: {
          siem: {
            protocol:         "webhook",
            url:              "http://127.0.0.1:" + port + "/ingest",
            auth:             "bearer",
            token:            "test-token",
            batchSize:        2,
            maxBatchAgeMs:    100,
            bodyShape:        "array",
            retry:            { maxAttempts: 1 },
            allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
            allowInternal:    true,
          },
        },
      });

      b.logStream.info("first",  { x: 1 });
      b.logStream.info("second", { x: 2 });
      // batchSize=2 should trigger immediate flush
      await new Promise(function (r) { setTimeout(r, 200); });

      check("webhook received 2 events",                   received.length === 2);
      check("first event message",                         received[0].message === "first");
      check("second event message",                        received[1].message === "second");

      // Auth failure path: send another event after server stops accepting
      b.logStream.info("third",  { x: 3 });
      await new Promise(function (r) { setTimeout(r, 200); });
      check("third event delivered (under batch size, flushed by age)", received.length >= 3);

      await b.logStream.shutdown();
    } finally {
      server.close();
    }
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testLogStreamBidirectional() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-logbidi-"));
  try {
    await setupTestDb(tmpDir);
    b.logStream.init({
      sinks: { primary: { protocol: "local", dir: path.join(tmpDir, "logs") } },
    });

    var received = [];
    var unregister = b.logStream.onIncoming(async function (payload, opts) {
      received.push({ payload: payload, opts: opts });
      return "ack-" + (received.length);
    });

    var results = await b.logStream.deliverIncoming({ command: "block-user", userId: "u-123" }, { source: "siem-test" });
    check("deliverIncoming routes to handler",            received.length === 1);
    check("payload preserved",                            received[0].payload.command === "block-user");
    check("opts.source preserved",                        received[0].opts.source === "siem-test");
    check("handler return value captured in results",     results[0].ok === true && results[0].value === "ack-1");

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit: incoming command logged
    var incRows = await b.audit.query({ action: "system.log.incoming" });
    check("audit recorded system.log.incoming",           incRows.length === 1);

    // Unregister and verify no further dispatch
    unregister();
    await b.logStream.deliverIncoming({ command: "second" });
    check("after unregister, handler no longer called",   received.length === 1);

    await b.logStream.shutdown();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testExternalDbBasic() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdb-"));
  try {
    await setupTestDb(tmpDir);
    var driver = _makeFakeDriver();
    b.externalDb.init({
      backends: {
        "primary": {
          connect:  driver.connect,
          query:    driver.query,
          close:    driver.close,
          ping:     driver.ping,
        },
      },
    });

    check("externalDb namespace present",                typeof b.externalDb === "object");

    var listed = b.externalDb.listBackends();
    check("listBackends returns 1 entry",                listed.length === 1);

    var insertResult = await b.externalDb.query(
      "INSERT INTO kv (id, value) VALUES ($1, $2)", ["k1", "v1"]
    );
    check("insert returns rowCount = 1",                 insertResult.rowCount === 1);

    var selectResult = await b.externalDb.query(
      "SELECT id, value FROM kv WHERE id = $1", ["k1"]
    );
    check("select returns the inserted row",             selectResult.rows[0].value === "v1");

    var miss = await b.externalDb.query(
      "SELECT id, value FROM kv WHERE id = $1", ["missing"]
    );
    check("miss returns 0 rows",                         miss.rowCount === 0);

    // Health check
    var hc = await b.externalDb.healthCheck();
    check("healthCheck returns ok for primary",          hc.primary && hc.primary.ok === true);
    check("healthCheck returns breakerState",            hc.primary.breakerState === "closed");

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit recorded
    var qRows = await b.audit.query({ action: "system.externaldb.query" });
    check("audit recorded externaldb.query events",      qRows.length >= 3);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testExternalDbPool() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdbpool-"));
  try {
    await setupTestDb(tmpDir);
    var driver = _makeFakeDriver();
    b.externalDb.init({
      backends: {
        "primary": {
          connect: driver.connect, query: driver.query, close: driver.close,
          pool:    { min: 0, max: 3, idleTimeoutMs: 60000 },
        },
      },
    });

    // Sequential queries reuse the same connection
    await b.externalDb.query("SELECT 1");
    await b.externalDb.query("SELECT 1");
    await b.externalDb.query("SELECT 1");
    var s = driver.getStats();
    check("pool reuses idle connection",                 s.connectCount === 1);

    // Concurrent queries open up to max
    var promises = [];
    for (var i = 0; i < 5; i++) promises.push(b.externalDb.query("SELECT 1"));
    await Promise.all(promises);
    var s2 = driver.getStats();
    check("concurrent queries open up to pool.max",      s2.connectCount <= 3);

    // listBackends shows pool stats
    var listed = b.externalDb.listBackends();
    check("listBackends includes pool stats",            typeof listed[0].pool === "object");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testExternalDbTransaction() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdbtx-"));
  try {
    await setupTestDb(tmpDir);
    var driver = _makeFakeDriver();
    b.externalDb.init({
      backends: {
        "primary": {
          connect: driver.connect, query: driver.query, close: driver.close,
        },
      },
    });

    // Successful transaction commits
    var commitResult = await b.externalDb.transaction(async function (tx) {
      await tx.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["tx1", "a"]);
      await tx.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["tx2", "b"]);
      return "all-good";
    });
    check("transaction returns fn's return value",       commitResult === "all-good");
    var got1 = await b.externalDb.query("SELECT id, value FROM kv WHERE id = $1", ["tx1"]);
    check("committed rows visible",                      got1.rows[0].value === "a");

    // Failed transaction (handler throws) — rollback
    var caught = false;
    try {
      await b.externalDb.transaction(async function (tx) {
        await tx.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["tx3", "c"]);
        throw new Error("simulated");
      });
    } catch (e) { caught = e.message === "simulated"; }
    check("transaction error propagates",                caught);

    // External-db's audit emissions buffer in the handler; flush
    // explicitly to make them durable before querying.
    await b.audit.flush();
    var txRows = await b.audit.query({ action: "system.externaldb.transaction" });
    check("transaction events audit-logged",             txRows.length >= 2);
    var failRows = txRows.filter(function (r) { return r.outcome === "failure"; });
    check("rollback event recorded as failure",          failRows.length === 1);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testExternalDbResidency() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdbres-"));
  try {
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    process.env.BLAMEJS_AUDIT_SIGNING_MODE = "plaintext";
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: tmpDir, mode: "plaintext" });
    await b.db.init({
      dataDir: tmpDir,
      atRest:  "plain",
      auditSigning: { mode: "plaintext" },
      schema:  [],
      dataResidency: { region: "EU", allowedStorageRegions: ["EU"] },
    });

    var driver = _makeFakeDriver();
    var residencyViolation = false;
    try {
      b.externalDb.init({
        backends: {
          "us-bad": {
            connect: driver.connect, query: driver.query, close: driver.close,
            classifications: ["personal"],
            residencyTag:    "US",        // ← violation
          },
        },
      });
    } catch (e) { residencyViolation = e.code === "RESIDENCY_VIOLATION"; }
    check("external DB residency violation refused",     residencyViolation);

    // EU-tagged backend OK
    b.externalDb._resetForTest();
    b.externalDb.init({
      backends: {
        "eu-ok": {
          connect: driver.connect, query: driver.query, close: driver.close,
          classifications: ["personal"],
          residencyTag:    "EU",
        },
      },
    });
    var listed = b.externalDb.listBackends();
    check("EU backend accepted",                          listed.length === 1 && listed[0].residencyTag === "EU");
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testExternalDbClassification() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-extdbcls-"));
  try {
    await setupTestDb(tmpDir);
    var personalDriver    = _makeFakeDriver();
    var operationalDriver = _makeFakeDriver();
    b.externalDb.init({
      backends: {
        "personal-db": {
          connect: personalDriver.connect, query: personalDriver.query, close: personalDriver.close,
          classifications: ["personal"],
        },
        "ops-db": {
          connect: operationalDriver.connect, query: operationalDriver.query, close: operationalDriver.close,
          classifications: ["operational"],
        },
      },
    });

    await b.externalDb.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["x", "y"], { classification: "personal" });
    await b.externalDb.query("INSERT INTO kv (id, value) VALUES ($1, $2)", ["a", "b"], { classification: "operational" });

    check("personal query routed to personal-db",        personalDriver.getStats().queryCount === 1);
    check("operational query routed to ops-db",          operationalDriver.getStats().queryCount === 1);

    // Wrong-classification rejection
    var rejected = false;
    try {
      await b.externalDb.query("SELECT 1", [], { backend: "ops-db", classification: "personal" });
    } catch (e) { rejected = e.code === "CLASSIFICATION_MISMATCH"; }
    check("backend that doesn't serve classification rejected",  rejected);

    // No backend serves a missing classification
    var noBackendRejected = false;
    try { await b.externalDb.query("SELECT 1", [], { classification: "nonexistent" }); }
    catch (e) { noBackendRejected = e.code === "NO_BACKEND_FOR_CLASSIFICATION"; }
    check("missing classification rejected",             noBackendRejected);
  } finally {
    try { await b.externalDb.shutdown(); } catch (_e) {}
    await teardownTestDb(tmpDir);
  }
}

async function testMiddlewareRequestId() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.requestId();
    var nextCalled = false;

    // Generates fresh ID
    var req1 = _mockReq();
    var res1 = _mockRes();
    mw(req1, res1, function () { nextCalled = true; });
    check("requestId calls next()",                         nextCalled);
    check("requestId sets req.requestId (32 hex chars)",    typeof req1.requestId === "string" && req1.requestId.length === 32);
    check("requestId sets X-Request-Id response header",    res1._captured().headers["x-request-id"] === req1.requestId);

    // Propagates upstream value when format matches
    var req2 = _mockReq({ headers: { "x-request-id": "trace-abc-123_xyz" } });
    var res2 = _mockRes();
    mw(req2, res2, function () {});
    check("requestId propagates valid upstream id",         req2.requestId === "trace-abc-123_xyz");

    // Rejects malformed and generates fresh
    var req3 = _mockReq({ headers: { "x-request-id": "bad id with spaces!@#" } });
    var res3 = _mockRes();
    mw(req3, res3, function () {});
    check("requestId rejects malformed upstream id",        req3.requestId !== "bad id with spaces!@#");
  } finally { teardownMW(); }
}

async function testMiddlewareSecurityHeaders() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.securityHeaders();
    // Mark the request socket as TLS so the v0.5.3 HSTS-only-on-HTTPS
    // gate engages — operators on plain HTTP won't get HSTS, which
    // matches RFC 6797 §7.2.
    var req = _mockReq();
    req.socket = { encrypted: true };
    var res = _mockRes();
    mw(req, res, function () {});
    var h = res._captured().headers;
    check("security: HSTS set",                          /max-age=63072000.+includeSubDomains/.test(h["strict-transport-security"]));
    check("security: X-Content-Type-Options nosniff",    h["x-content-type-options"] === "nosniff");
    check("security: X-Frame-Options DENY",              h["x-frame-options"] === "DENY");
    check("security: Referrer-Policy no-referrer",       h["referrer-policy"] === "no-referrer");
    check("security: Permissions-Policy disables camera", /camera=\(\)/.test(h["permissions-policy"]));
    check("security: COOP same-origin",                  h["cross-origin-opener-policy"] === "same-origin");
    check("security: CORP same-origin",                  h["cross-origin-resource-policy"] === "same-origin");
    check("security: Origin-Agent-Cluster ?1",           h["origin-agent-cluster"] === "?1");
    check("security: X-DNS-Prefetch-Control off",        h["x-dns-prefetch-control"] === "off");
    check("security: CSP includes default-src 'self'",   /default-src 'self'/.test(h["content-security-policy"]));
    check("security: CSP no longer ships 'unsafe-inline'",
          h["content-security-policy"].indexOf("'unsafe-inline'") === -1);
    check("security: CSP keeps style-src 'self'",        /style-src 'self'(?!\s+'unsafe-inline')/.test(h["content-security-policy"]));

    // Override + disable
    var mw2 = b.middleware.securityHeaders({
      frameOptions:       "SAMEORIGIN",
      originAgentCluster: false,
      dnsPrefetchControl: "on",
      csp:                false,
    });
    var req2 = _mockReq();
    var res2 = _mockRes();
    mw2(req2, res2, function () {});
    var h2 = res2._captured().headers;
    check("security: frameOptions override applied",     h2["x-frame-options"] === "SAMEORIGIN");
    check("security: csp disabled when false",           h2["content-security-policy"] === undefined);
    check("security: Origin-Agent-Cluster disabled when false",
                                                         h2["origin-agent-cluster"] === undefined);
    check("security: DNS-Prefetch-Control on override",  h2["x-dns-prefetch-control"] === "on");

    var threwUnknownOpt = false;
    try { b.middleware.securityHeaders({ NOT_A_REAL_OPT: true }); }
    catch (_e) { threwUnknownOpt = true; }
    check("security: rejects unknown opt",               threwUnknownOpt);
  } finally { teardownMW(); }
}

async function testMiddlewareErrorHandler() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.errorHandler({ exposeStackInDev: false });

    // Simple error → 500
    var req = _mockReq({ url: "/x" });
    var res = _mockRes();
    mw(new Error("boom"), req, res, function () {});
    var captured = res._captured();
    check("errorHandler: default → 500",                 captured.status === 500);
    var body = JSON.parse(captured.body);
    check("errorHandler: generic message on 500",        body.error.message === "Internal Server Error");
    check("errorHandler: error code present",            !!body.error.code);

    // statusCode-bearing error → that status
    var customErr = new Error("not found");
    customErr.statusCode = 404;
    customErr.code = "not_found";
    var req2 = _mockReq();
    var res2 = _mockRes();
    mw(customErr, req2, res2, function () {});
    var c2 = res2._captured();
    check("errorHandler: respects statusCode on error",  c2.status === 404);
    var b2 = JSON.parse(c2.body);
    check("errorHandler: 4xx exposes message",           b2.error.message === "not found");

    // SafeJsonError → 400 + path
    var jse = new b.safeJson.SafeJsonError("validation failed", "json/validation", "$.email");
    var req3 = _mockReq();
    var res3 = _mockRes();
    mw(jse, req3, res3, function () {});
    var c3 = res3._captured();
    check("errorHandler: SafeJsonError → 400",           c3.status === 400);
    var b3 = JSON.parse(c3.body);
    check("errorHandler: 400 body includes path",        b3.error.path === "$.email");

    // Drain buffered audit emissions before reading audit_log.
    await b.audit.flush();
    // Audit recorded
    var errRows = await b.audit.query({ action: "system.http.error" });
    check("errorHandler: audit-recorded errors",          errRows.length === 3);
  } finally { teardownMW(); }
}

async function testMiddlewareBotGuard() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.botGuard();

    // curl UA in 'block' mode → 403
    var req = _mockReq({ headers: { "user-agent": "curl/8.0.0", "accept-language": "en", "sec-fetch-mode": "navigate" } });
    var res = _mockRes();
    var nextCalled = false;
    mw(req, res, function () { nextCalled = true; });
    check("botGuard: curl UA blocked",                    res._captured().status === 403 && !nextCalled);

    // Real-browser-shaped request → pass
    var req2 = _mockReq({ headers: { "user-agent": "Mozilla/5.0", "accept-language": "en-US", "sec-fetch-mode": "navigate" } });
    var res2 = _mockRes();
    var next2 = false;
    mw(req2, res2, function () { next2 = true; });
    check("botGuard: browser request passes",            next2);

    // Tag mode marks req but doesn't block
    var mwTag = b.middleware.botGuard({ mode: "tag" });
    var req3 = _mockReq({ headers: { "user-agent": "curl/8.0.0", "accept-language": "en" } });
    var res3 = _mockRes();
    var next3 = false;
    mwTag(req3, res3, function () { next3 = true; });
    check("botGuard tag mode: passes through",            next3);
    check("botGuard tag mode: req.suspectedBot set",     req3.suspectedBot === "blocked-agent");

    // Skip path
    var mwSkip = b.middleware.botGuard({ skipPaths: ["/healthz"] });
    var req4 = _mockReq({ url: "/healthz", pathname: "/healthz", headers: { "user-agent": "curl/8.0.0" } });
    var res4 = _mockRes();
    var next4 = false;
    mwSkip(req4, res4, function () { next4 = true; });
    check("botGuard: skipPaths bypassed",                next4);

    // API path is exempt from missing-Accept-Language by default (onlyForHtml)
    var req5 = _mockReq({ url: "/api/x", pathname: "/api/x", headers: { "user-agent": "Mozilla" } });
    var res5 = _mockRes();
    var next5 = false;
    mw(req5, res5, function () { next5 = true; });
    check("botGuard: onlyForHtml exempts /api/*",        next5);
  } finally { teardownMW(); }
}

async function testMiddlewareCors() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.cors({
      origins:     ["https://app.example.com", /^https:\/\/.+\.staging\.example\.com$/],
      credentials: true,
    });

    // Allowed origin → CORS headers set
    var req = _mockReq({ headers: { origin: "https://app.example.com" } });
    var res = _mockRes();
    var nextCalled = false;
    mw(req, res, function () { nextCalled = true; });
    check("cors: allowed origin → next called",          nextCalled);
    check("cors: ACAO set",                               res._captured().headers["access-control-allow-origin"] === "https://app.example.com");
    check("cors: ACAC set when credentials:true",        res._captured().headers["access-control-allow-credentials"] === "true");

    // Regex origin → match
    var req2 = _mockReq({ headers: { origin: "https://feature-1.staging.example.com" } });
    var res2 = _mockRes();
    mw(req2, res2, function () {});
    check("cors: regex origin matched",                   res2._captured().headers["access-control-allow-origin"] === "https://feature-1.staging.example.com");

    // Disallowed origin → 403 (refuseUnknown default)
    var req3 = _mockReq({ headers: { origin: "https://evil.example.com" } });
    var res3 = _mockRes();
    var n3 = false;
    mw(req3, res3, function () { n3 = true; });
    check("cors: unknown origin blocked",                 res3._captured().status === 403 && !n3);

    // No Origin header → pass through
    var req4 = _mockReq();
    var res4 = _mockRes();
    var n4 = false;
    mw(req4, res4, function () { n4 = true; });
    check("cors: no Origin header → passes through",     n4 && !res4._captured().headers["access-control-allow-origin"]);

    // Preflight (OPTIONS + Access-Control-Request-Method) → 204 with allow-headers
    var req5 = _mockReq({ method: "OPTIONS", headers: { origin: "https://app.example.com", "access-control-request-method": "PUT" } });
    var res5 = _mockRes();
    mw(req5, res5, function () {});
    check("cors preflight: 204",                          res5._captured().status === 204);
    check("cors preflight: ACAM set",                     /PUT/.test(res5._captured().headers["access-control-allow-methods"]));
  } finally { teardownMW(); }
}

async function testMiddlewareRateLimit() {
  await setupTestDbForMW();
  try {
    var mw = b.middleware.rateLimit({ burst: 3, refillPerSecond: 1 });

    function fire() {
      var req = _mockReq();
      var res = _mockRes();
      var nextCalled = false;
      mw(req, res, function () { nextCalled = true; });
      return { passed: nextCalled, status: res._captured().status };
    }

    // First 3 pass (burst=3)
    check("rateLimit: 1st request passes",                 fire().passed);
    check("rateLimit: 2nd request passes",                 fire().passed);
    check("rateLimit: 3rd request passes",                 fire().passed);
    var blocked = fire();
    check("rateLimit: 4th request blocked with 429",      !blocked.passed && blocked.status === 429);

    // Different key → independent bucket
    var mw2 = b.middleware.rateLimit({ burst: 2, refillPerSecond: 0.5, keyFn: function (req) { return req.headers["x-key"] || "default"; } });
    function fireKey(k) {
      var req = _mockReq({ headers: { "x-key": k } });
      var res = _mockRes();
      var ok = false;
      mw2(req, res, function () { ok = true; });
      return ok;
    }
    check("rateLimit: keyA 1st passes",                    fireKey("a"));
    check("rateLimit: keyA 2nd passes",                    fireKey("a"));
    check("rateLimit: keyA 3rd blocked",                   !fireKey("a"));
    check("rateLimit: keyB independent — 1st passes",      fireKey("b"));

    // Skip path
    var mwSkip = b.middleware.rateLimit({ burst: 1, refillPerSecond: 0.1, skipPaths: ["/healthz"] });
    function fireWithPath(p) {
      var req = _mockReq({ url: p, pathname: p });
      var res = _mockRes();
      var ok = false;
      mwSkip(req, res, function () { ok = true; });
      return ok;
    }
    check("rateLimit: 1st /healthz passes",                fireWithPath("/healthz"));
    check("rateLimit: 2nd /healthz passes (skipped)",      fireWithPath("/healthz"));
    check("rateLimit: 1st /api passes",                    fireWithPath("/api"));
    check("rateLimit: 2nd /api blocked",                   !fireWithPath("/api"));
  } finally { teardownMW(); }
}

async function testMiddlewareCsrfProtect() {
  // End-to-end via a real http server. Token is stored in a fake
  // session under req.expectedCsrfToken so the middleware's tokenLookup
  // can return it without dragging the real session module into this
  // test fixture (which is about CSRF gating, not session lifecycle).
  await setupTestDbForMW();
  try {
    var http = require("http");

    var EXPECTED = b.forms.generateCsrfToken();

    function _captureBody(req) {
      return new Promise(function (resolve) {
        var chunks = [];
        req.on("data", function (c) { chunks.push(c); });
        req.on("end", function () { resolve(Buffer.concat(chunks).toString("utf8")); });
      });
    }

    var bodyParser = b.middleware.bodyParser();
    var protect = b.middleware.csrfProtect({
      tokenLookup: function (req) { return EXPECTED; },
    });
    var server = http.createServer(async function (req, res) {
      // bodyParser runs first so urlencoded form posts populate req.body
      // for csrf-protect to read. Header path still works without it.
      await new Promise(function (resolve) {
        bodyParser(req, res, function () {
          protect(req, res, function () {
            res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": 2 });
            res.end("ok");
            resolve();
          });
        });
      });
    });
    var port = await listenOnRandomPort(server);
    try {
      // 1. Safe method (GET) → middleware passes through, even with no token
      var safe = await b.httpClient.request({
        url: "http://127.0.0.1:" + port + "/protected",
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      });
      check("csrfProtect: GET passes through",          safe.statusCode === 200);

      // 2. POST without token → 403
      var noTok = await b.httpClient.request({
        method: "POST",
        url: "http://127.0.0.1:" + port + "/protected",
        body: Buffer.from(""),
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
        errorClass: b.frameworkError.ObjectStoreError,
      }).catch(function (e) { return e; });
      check("csrfProtect: POST without token → 403",    noTok.statusCode === 403);

      // 3. POST with token in X-CSRF-Token header → 200
      var hdrOk = await b.httpClient.request({
        method: "POST",
        url: "http://127.0.0.1:" + port + "/protected",
        headers: { "x-csrf-token": EXPECTED, "Content-Type": "application/json" },
        body: Buffer.from("{}"),
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      });
      check("csrfProtect: POST with header token → 200", hdrOk.statusCode === 200);

      // 4. POST with token in urlencoded body → 200
      var bodyOk = await b.httpClient.request({
        method: "POST",
        url: "http://127.0.0.1:" + port + "/protected",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: Buffer.from("_csrf=" + encodeURIComponent(EXPECTED) + "&name=Alice"),
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      });
      check("csrfProtect: POST with urlencoded body token → 200", bodyOk.statusCode === 200);

      // 5. POST with WRONG token → 403
      var wrong = await b.httpClient.request({
        method: "POST",
        url: "http://127.0.0.1:" + port + "/protected",
        headers: { "x-csrf-token": "wrong-token" },
        body: Buffer.from(""),
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
        errorClass: b.frameworkError.ObjectStoreError,
      }).catch(function (e) { return e; });
      check("csrfProtect: POST with wrong token → 403", wrong.statusCode === 403);
    } finally { server.close(); }

    // 6. Custom methods + custom headerName
    var protectCustom = b.middleware.csrfProtect({
      tokenLookup: function () { return EXPECTED; },
      methods:     ["DELETE"],
      headerName:  "X-My-CSRF",
    });
    var server2 = http.createServer(async function (req, res) {
      await new Promise(function (resolve) {
        protectCustom(req, res, function () {
          res.writeHead(200, { "Content-Type": "text/plain", "Content-Length": 2 });
          res.end("ok");
          resolve();
        });
      });
    });
    var port2 = await listenOnRandomPort(server2);
    try {
      // POST is now NOT in the protected methods → passes through
      var postPass = await b.httpClient.request({
        method: "POST",
        url: "http://127.0.0.1:" + port2 + "/x",
        body: Buffer.from(""),
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      });
      check("csrfProtect: custom methods exclude POST",  postPass.statusCode === 200);

      // DELETE without token → 403
      var del403 = await b.httpClient.request({
        method: "DELETE",
        url: "http://127.0.0.1:" + port2 + "/x",
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
        errorClass: b.frameworkError.ObjectStoreError,
      }).catch(function (e) { return e; });
      check("csrfProtect: DELETE in custom methods gated",  del403.statusCode === 403);

      // DELETE with token in custom header → 200
      var del200 = await b.httpClient.request({
        method: "DELETE",
        url: "http://127.0.0.1:" + port2 + "/x",
        headers: { "x-my-csrf": EXPECTED },
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
      });
      check("csrfProtect: custom headerName honored",   del200.statusCode === 200);
    } finally { server2.close(); }

    // 7. tokenLookup returns null → 403 (no expected token to compare)
    var protectNullLookup = b.middleware.csrfProtect({
      tokenLookup: function () { return null; },
    });
    var server3 = http.createServer(async function (req, res) {
      await new Promise(function (resolve) {
        protectNullLookup(req, res, function () {
          res.writeHead(200); res.end("should not reach"); resolve();
        });
      });
    });
    var port3 = await listenOnRandomPort(server3);
    try {
      var nullLookup = await b.httpClient.request({
        method: "POST",
        url: "http://127.0.0.1:" + port3 + "/x",
        headers: { "x-csrf-token": EXPECTED },
        body: Buffer.from(""),
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
        errorClass: b.frameworkError.ObjectStoreError,
      }).catch(function (e) { return e; });
      check("csrfProtect: tokenLookup null → 403",       nullLookup.statusCode === 403);
    } finally { server3.close(); }

    // 8. Validation: tokenLookup required
    var threw = null;
    try { b.middleware.csrfProtect({}); }
    catch (e) { threw = e; }
    check("csrfProtect: tokenLookup is required",        threw && /tokenLookup is required/.test(threw.message));
  } finally { teardownMW(); }
}

async function testMiddlewareAttachUser() {
  // attachUser populates req.user via session.verify + operator-supplied
  // userLoader. Validates token-source dispatch (cookie + Bearer header),
  // graceful failure modes (no token / invalid token / userLoader nulls /
  // userLoader throws), and that the middleware never throws or
  // short-circuits — gating is downstream's job.
  await setupTestDbForMW();
  try {
    // Create a real session; we'll exercise verify through the middleware.
    var s = await b.session.create({ userId: "u-1", data: { role: "member" } });
    var goodToken = s.token;

    var loaderCalls = [];
    var userLoader = async function (verified) {
      loaderCalls.push(verified.userId);
      if (verified.userId === "u-1") return { _id: "u-1", email: "alice@example.com" };
      if (verified.userId === "u-suspended") return null;       // user record exists but loader rejects
      if (verified.userId === "u-throws") throw new Error("DB blew up");
      return null;
    };

    // userLoader is required
    var threw = null;
    try { b.middleware.attachUser({}); }
    catch (e) { threw = e; }
    check("attachUser: throws when userLoader missing",
          threw && /userLoader is required/.test(threw.message));

    var mw = b.middleware.attachUser({ userLoader: userLoader });

    // 1. No token in either source → req.user = null, next() called
    var req1 = _mockReq();
    var res1 = _mockRes();
    var n1 = false;
    await mw(req1, res1, function () { n1 = true; });
    check("attachUser: no token → next() called",          n1 === true);
    check("attachUser: no token → req.user is null",       req1.user === null);
    check("attachUser: no token → res not written",        res1._captured().ended === false);

    // 2. Valid cookie token → req.user populated, req.session set
    var req2 = _mockReq({ headers: { cookie: "blamejs_session=" + goodToken } });
    var res2 = _mockRes();
    var n2 = false;
    await mw(req2, res2, function () { n2 = true; });
    check("attachUser: valid cookie → next() called",      n2 === true);
    check("attachUser: valid cookie → req.user set",       req2.user && req2.user._id === "u-1");
    check("attachUser: valid cookie → req.session set",    req2.session && req2.session.userId === "u-1");

    // 3. Valid Bearer header → req.user populated
    var req3 = _mockReq({ headers: { authorization: "Bearer " + goodToken } });
    var res3 = _mockRes();
    await mw(req3, res3, function () {});
    check("attachUser: valid Bearer → req.user set",       req3.user && req3.user._id === "u-1");

    // 4. Cookie wins over Bearer when both present (cookie tried first)
    var anotherSession = await b.session.create({ userId: "u-1" });
    var req4 = _mockReq({ headers: {
      cookie: "blamejs_session=" + goodToken + "; foo=bar",
      authorization: "Bearer " + anotherSession.token,
    } });
    var res4 = _mockRes();
    await mw(req4, res4, function () {});
    check("attachUser: cookie precedes Bearer when both present",
          req4.user && req4.user._id === "u-1");

    // 5. Invalid token → req.user = null
    var req5 = _mockReq({ headers: { authorization: "Bearer not-a-real-token" } });
    var res5 = _mockRes();
    var n5 = false;
    await mw(req5, res5, function () { n5 = true; });
    check("attachUser: invalid token → next() called",     n5 === true);
    check("attachUser: invalid token → req.user is null",  req5.user === null);

    // 6. Valid session but userLoader returns null (deleted/suspended)
    var sSuspended = await b.session.create({ userId: "u-suspended" });
    var req6 = _mockReq({ headers: { authorization: "Bearer " + sSuspended.token } });
    var res6 = _mockRes();
    await mw(req6, res6, function () {});
    check("attachUser: userLoader returns null → req.user is null",
          req6.user === null);

    // 7. userLoader throws → req.user = null, no propagation
    var sThrows = await b.session.create({ userId: "u-throws" });
    var req7 = _mockReq({ headers: { authorization: "Bearer " + sThrows.token } });
    var res7 = _mockRes();
    var n7 = false;
    await mw(req7, res7, function () { n7 = true; });
    check("attachUser: userLoader throw → next() still called", n7 === true);
    check("attachUser: userLoader throw → req.user is null",    req7.user === null);

    // 8. tokenFrom 'cookie' ignores Bearer
    var mwCookieOnly = b.middleware.attachUser({ userLoader: userLoader, tokenFrom: "cookie" });
    var req8 = _mockReq({ headers: { authorization: "Bearer " + goodToken } });
    await mwCookieOnly(req8, _mockRes(), function () {});
    check("attachUser: tokenFrom='cookie' ignores Bearer header",
          req8.user === null);

    // 9. tokenFrom 'header' ignores cookie
    var mwHeaderOnly = b.middleware.attachUser({ userLoader: userLoader, tokenFrom: "header" });
    var req9 = _mockReq({ headers: { cookie: "blamejs_session=" + goodToken } });
    await mwHeaderOnly(req9, _mockRes(), function () {});
    check("attachUser: tokenFrom='header' ignores cookie",
          req9.user === null);
  } finally { teardownMW(); }
}

async function testMiddlewareRequireAuth() {
  // requireAuth gates routes. With req.user populated, next() runs.
  // Without it: 401 JSON, 401 text, or 302 redirect depending on
  // request shape + opts.
  await setupTestDbForMW();
  try {
    var mw = b.middleware.requireAuth();

    // 1. Authenticated request → next() called, no response written
    var req1 = _mockReq();
    req1.user = { _id: "u-1" };
    var res1 = _mockRes();
    var n1 = false;
    mw(req1, res1, function () { n1 = true; });
    check("requireAuth: authenticated → next() called",    n1 === true);
    check("requireAuth: authenticated → res not written",  res1._captured().ended === false);

    // 2. Unauthenticated JSON-preferring request → 401 JSON
    var req2 = _mockReq({ headers: { accept: "application/json" } });
    var res2 = _mockRes();
    var n2 = false;
    mw(req2, res2, function () { n2 = true; });
    var cap2 = res2._captured();
    check("requireAuth: unauth + JSON → next() NOT called", n2 === false);
    check("requireAuth: unauth + JSON → 401 status",        cap2.status === 401);
    check("requireAuth: unauth + JSON → Content-Type JSON",
          cap2.headers["content-type"].indexOf("application/json") === 0);
    var body2 = JSON.parse(cap2.body);
    check("requireAuth: unauth + JSON → error body",        body2.error === "Authentication required.");

    // 3. Unauthenticated XHR (X-Requested-With) → 401 JSON
    var req3 = _mockReq({ headers: { "x-requested-with": "XMLHttpRequest" } });
    var res3 = _mockRes();
    mw(req3, res3, function () {});
    check("requireAuth: unauth + XHR → 401 status",        res3._captured().status === 401);

    // 4. Unauthenticated browser-y request → 401 text/plain
    var req4 = _mockReq({ headers: { accept: "text/html" } });
    var res4 = _mockRes();
    mw(req4, res4, function () {});
    var cap4 = res4._captured();
    check("requireAuth: unauth browser → 401 status",      cap4.status === 401);
    check("requireAuth: unauth browser → text/plain",
          cap4.headers["content-type"].indexOf("text/plain") === 0);

    // 4b. Content-Type: application/json on the REQUEST body is NOT
    // a signal — it describes what the client SENT, not what they
    // want back. Server-to-server POST with no Accept header lands
    // on the default text/plain branch (or the redirect branch when
    // opts.redirectTo is set).
    var req4c = _mockReq({ headers: { "content-type": "application/json" } });
    var res4c = _mockRes();
    mw(req4c, res4c, function () {});
    var cap4c = res4c._captured();
    check("requireAuth: req Content-Type JSON alone → text/plain (not JSON)",
          cap4c.status === 401 &&
          cap4c.headers["content-type"].indexOf("text/plain") === 0);

    // 5. Unauthenticated browser-y request WITH redirectTo → 302
    var mwRedirect = b.middleware.requireAuth({ redirectTo: "/auth/login" });
    var req5 = _mockReq({ headers: { accept: "text/html" } });
    var res5 = _mockRes();
    mwRedirect(req5, res5, function () {});
    var cap5 = res5._captured();
    check("requireAuth: unauth + redirectTo → 302 status",  cap5.status === 302);
    check("requireAuth: unauth + redirectTo → Location set",
          cap5.headers.location === "/auth/login");

    // 6. JSON-preferring still gets 401 JSON even with redirectTo set
    var req6 = _mockReq({ headers: { accept: "application/json" } });
    var res6 = _mockRes();
    mwRedirect(req6, res6, function () {});
    check("requireAuth: JSON-prefer + redirectTo → 401 (not redirect)",
          res6._captured().status === 401);

    // 7. Custom errorMessage propagates
    var mwCustom = b.middleware.requireAuth({ errorMessage: "Sign in to continue." });
    var req7 = _mockReq({ headers: { accept: "application/json" } });
    var res7 = _mockRes();
    mwCustom(req7, res7, function () {});
    check("requireAuth: custom errorMessage propagates",
          JSON.parse(res7._captured().body).error === "Sign in to continue.");

    // 8. Custom prefersJson override
    var mwForce = b.middleware.requireAuth({ prefersJson: function () { return false; } });
    var req8 = _mockReq({ headers: { accept: "application/json" } });   // would normally be JSON
    var res8 = _mockRes();
    mwForce(req8, res8, function () {});
    check("requireAuth: prefersJson override forces text/plain",
          res8._captured().headers["content-type"].indexOf("text/plain") === 0);
  } finally { teardownMW(); }
}

function testEnvLoadDiffAndAudit() {
  // Use real file I/O via atomicFile — exercises load() end-to-end.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-env-"));
  try {
    var envPath = path.join(tmpDir, ".env");
    var snapPath = path.join(tmpDir, "env.snapshot.json");

    fs.writeFileSync(envPath, "DATABASE_URL=postgres://A\nFEATURE_FOO=true\n");
    var res1 = b.parsers.env.load(envPath, {
      snapshotPath: snapPath,
      audit:        false,    // no framework db wired in this test fixture
    });
    check("env.load returns values",                 res1.values.DATABASE_URL === "postgres://A");
    check("env.load first call: 2 added",            res1.diff.added.length === 2);
    check("env.load first call: nothing removed",    res1.diff.removed.length === 0);
    check("env.load first call: nothing changed",    res1.diff.changed.length === 0);

    // Now change one and add another
    fs.writeFileSync(envPath, "DATABASE_URL=postgres://B\nFEATURE_FOO=true\nNEW_KEY=hello\n");
    var res2 = b.parsers.env.load(envPath, { snapshotPath: snapPath, audit: false });
    check("env.load second call: 1 added",           res2.diff.added.length === 1 && res2.diff.added[0] === "NEW_KEY");
    check("env.load second call: nothing removed",   res2.diff.removed.length === 0);
    check("env.load second call: 1 changed",         res2.diff.changed.length === 1);
    check("env.load second call: changed key",       res2.diff.changed[0].key === "DATABASE_URL");

    // Now remove one
    fs.writeFileSync(envPath, "DATABASE_URL=postgres://B\nNEW_KEY=hello\n");
    var res3 = b.parsers.env.load(envPath, { snapshotPath: snapPath, audit: false });
    check("env.load third call: 1 removed",          res3.diff.removed.length === 1 && res3.diff.removed[0] === "FEATURE_FOO");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testEnvLoadSchemaAndTypos() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-env-"));
  try {
    var envPath = path.join(tmpDir, ".env");
    fs.writeFileSync(envPath,
      "DATABSE_URL=oops\n" +              // typo of DATABASE_URL
      "feature_flag=true\n");             // case mismatch — wait, this is rejected by keyShape
    // Actually case-mismatch must use keys that pass shape. Use uppercase
    // mismatch instead — rewrite.
    fs.writeFileSync(envPath,
      "DATABSE_URL=oops\n" +              // typo (missing 'A')
      "FEATURE_FLAG=true\n" +             // exact match for registered
      "TOTALLY_UNKNOWN=other\n");
    var expected = {
      DATABASE_URL: { type: "string", sensitivity: "breaking" },
      FEATURE_FLAG: { type: "boolean", sensitivity: "runtime" },
    };
    var res = b.parsers.env.load(envPath, {
      expected: expected,
      audit:    false,
    });
    check("env: schema coerces type when registered",  res.values.FEATURE_FLAG === true);

    // Find the typo entry in suspicious
    var typo = res.diff.suspicious.find(function (s) { return s.key === "DATABSE_URL"; });
    check("env: typo flagged as suspicious",            typo && typo.suggestion === "DATABASE_URL");
    check("env: typo reason is single-char-typo",       typo && typo.reason === "single-char-typo");

    var unknown = res.diff.suspicious.find(function (s) { return s.key === "TOTALLY_UNKNOWN"; });
    check("env: unrelated unknown flagged",             unknown && unknown.reason === "unknown");

    // rejectUnknown mode refuses
    var threwRejectUnknown = false;
    try { b.parsers.env.load(envPath, { expected: expected, audit: false, rejectUnknown: true }); }
    catch (e) { threwRejectUnknown = e.code === "env/unknown-keys"; }
    check("env: rejectUnknown surfaces error",         threwRejectUnknown);

    // Required key missing
    fs.writeFileSync(envPath, "FEATURE_FLAG=true\n");
    var threwRequired = false;
    try {
      b.parsers.env.load(envPath, {
        expected: { DATABASE_URL: { type: "string", required: true } },
        audit:    false,
      });
    } catch (e) { threwRequired = e.code === "env/missing-required"; }
    check("env: missing required key rejected",         threwRequired);

    // Bad type coercion
    fs.writeFileSync(envPath, "FEATURE_FLAG=yes\n");
    var threwBadBool = false;
    try {
      b.parsers.env.load(envPath, {
        expected: { FEATURE_FLAG: { type: "boolean" } },
        audit:    false,
      });
    } catch (e) { threwBadBool = e.code === "env/bad-type"; }
    check("env: 'yes' for boolean rejected (no Norway)", threwBadBool);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

function testEnvLoadBreakingChange() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-env-"));
  try {
    var envPath = path.join(tmpDir, ".env");
    var snapPath = path.join(tmpDir, "env.snapshot.json");
    var expected = {
      DATABASE_URL: { type: "string", sensitivity: "breaking" },
    };

    fs.writeFileSync(envPath, "DATABASE_URL=postgres://A\n");
    b.parsers.env.load(envPath, { expected: expected, snapshotPath: snapPath, audit: false });

    // Try to change without acknowledgement
    fs.writeFileSync(envPath, "DATABASE_URL=postgres://B\n");
    var threwBreaking = false;
    try {
      b.parsers.env.load(envPath, { expected: expected, snapshotPath: snapPath, audit: false });
    } catch (e) { threwBreaking = e.code === "env/breaking-change"; }
    check("env: breaking-sensitivity change refused",   threwBreaking);

    // With explicit allow, succeeds
    var ok = b.parsers.env.load(envPath, {
      expected:     expected,
      snapshotPath: snapPath,
      audit:        false,
      allow:        ["DATABASE_URL"],
    });
    check("env: { allow: [...] } authorises breaking change",
          ok.values.DATABASE_URL === "postgres://B");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ---- run() ----

async function run() {
  // session
  await testSession();

  // data residency (db + storage)
  await testDataResidency();

  // storage + object-store
  await testStorage();
  await testMultiBackend();
  await testClassificationRouting();
  await testResidencyEnforcement();
  await testRetryAndBreaker();
  testSigv4Primitives();
  await testSigv4MockServer();
  testGcsPrimitives();
  await testGcsMockServer();
  testAzureBlobPrimitives();
  await testAzureBlobMockServer();

  // queue
  await testQueueLocal();
  await testQueueConsume();
  await testQueueRetryAndFail();
  await testQueueLeaseExpiry();
  await testQueueShutdown();
  testJobsSurface();
  await testJobsDefineAndEnqueue();
  await testJobsValidation();
  await testJobsMultipleHandlers();

  // log-stream
  await testLogStreamLocal();
  await testLogStreamWebhook();
  await testLogStreamBidirectional();

  // external-db
  await testExternalDbBasic();
  await testExternalDbPool();
  await testExternalDbTransaction();
  await testExternalDbResidency();
  await testExternalDbClassification();

  // middleware
  await testMiddlewareRequestId();
  await testMiddlewareSecurityHeaders();
  await testMiddlewareErrorHandler();
  await testMiddlewareBotGuard();
  await testMiddlewareCors();
  await testMiddlewareRateLimit();
  await testMiddlewareAttachUser();
  await testMiddlewareRequireAuth();
  await testMiddlewareCsrfProtect();

  // env-safe.load() — full lifecycle (depends on audit chain)
  await testEnvLoadDiffAndAudit();
  await testEnvLoadSchemaAndTypos();
  await testEnvLoadBreakingChange();
}

module.exports = {
  name: "Layer 4 — consumers (session, storage, queue, log-stream, external-db, middleware, env-load)",
  run:  run,
  testSession:                              testSession,
  testMiddlewareAttachUser:                 testMiddlewareAttachUser,
  testMiddlewareRequireAuth:                testMiddlewareRequireAuth,
  testMiddlewareCsrfProtect:                testMiddlewareCsrfProtect,
  testDataResidency:                        testDataResidency,
  testStorage:                              testStorage,
  testMultiBackend:                         testMultiBackend,
  testClassificationRouting:                testClassificationRouting,
  testResidencyEnforcement:                 testResidencyEnforcement,
  testRetryAndBreaker:                      testRetryAndBreaker,
  testSigv4Primitives:                      testSigv4Primitives,
  testSigv4MockServer:                      testSigv4MockServer,
  testGcsPrimitives:                        testGcsPrimitives,
  testGcsMockServer:                        testGcsMockServer,
  testAzureBlobPrimitives:                  testAzureBlobPrimitives,
  testAzureBlobMockServer:                  testAzureBlobMockServer,
  testQueueLocal:                           testQueueLocal,
  testQueueConsume:                         testQueueConsume,
  testQueueRetryAndFail:                    testQueueRetryAndFail,
  testQueueLeaseExpiry:                     testQueueLeaseExpiry,
  testQueueShutdown:                        testQueueShutdown,
  testJobsSurface:                          testJobsSurface,
  testJobsDefineAndEnqueue:                 testJobsDefineAndEnqueue,
  testJobsValidation:                       testJobsValidation,
  testJobsMultipleHandlers:                 testJobsMultipleHandlers,
  testLogStreamLocal:                       testLogStreamLocal,
  testLogStreamWebhook:                     testLogStreamWebhook,
  testLogStreamBidirectional:               testLogStreamBidirectional,
  testExternalDbBasic:                      testExternalDbBasic,
  testExternalDbPool:                       testExternalDbPool,
  testExternalDbTransaction:                testExternalDbTransaction,
  testExternalDbResidency:                  testExternalDbResidency,
  testExternalDbClassification:             testExternalDbClassification,
  testMiddlewareRequestId:                  testMiddlewareRequestId,
  testMiddlewareSecurityHeaders:            testMiddlewareSecurityHeaders,
  testMiddlewareErrorHandler:               testMiddlewareErrorHandler,
  testMiddlewareBotGuard:                   testMiddlewareBotGuard,
  testMiddlewareCors:                       testMiddlewareCors,
  testMiddlewareRateLimit:                  testMiddlewareRateLimit,
  testEnvLoadDiffAndAudit:                  testEnvLoadDiffAndAudit,
  testEnvLoadSchemaAndTypos:                testEnvLoadSchemaAndTypos,
  testEnvLoadBreakingChange:                testEnvLoadBreakingChange,
};

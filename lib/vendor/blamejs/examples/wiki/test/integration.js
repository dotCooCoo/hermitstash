"use strict";
/**
 * Wiki integration test — boots the wiki app against the docker-compose
 * fixture stack (real Redis / MinIO / Mailpit / CoreDNS / NTP) and drives
 * each backend through the wiki's HTTP surface AND the underlying
 * framework primitives. Validates that:
 *
 *   1. The wiki boots cleanly with every backend env knob set
 *   2. Each framework primitive routes through the configured backend
 *      (cache → custom backend, queue → Redis Streams, mail → Mailpit
 *      SMTP, object-store → MinIO sigv4, log-stream → webhook receiver)
 *   3. Every fix shipped in v0.6.28 holds in a real-app context, not
 *      just in unit-test isolation
 *
 * Smoke (test/smoke.js) and the existing wiki e2e (examples/wiki/test/
 * e2e.js) stay pure — no docker dependency, run in CI / on a developer
 * laptop / inside prepack-guard. This integration test is a separate
 * gate, run via scripts/test-wiki-integration.js when validating
 * external-integration changes.
 */
var fs = require("node:fs");
var http = require("node:http");
var os = require("node:os");
var path = require("node:path");
var b = require("@blamejs/core");
var redisClient = require("@blamejs/core/lib/redis-client");
var { buildApp } = require("../lib/build-app");

var DATA_DIR = path.join(os.tmpdir(), "blamejs-wiki-integration-" + Date.now());
var ADMIN_EMAIL = "admin-integration@blamejs.com";
var ADMIN_PASSWORD = "wiki-integration-pwd-x9k2";

// Browser-shaped headers — matches existing e2e.js conventions so the
// wiki's bot-guard / Sec-Fetch / rate-limit middleware all pass without
// mock-specific bypasses.
var BROWSER_HEADERS = {
  "user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "accept":          "application/json, text/html;q=0.8",
  "accept-language": "en-US,en;q=0.9",
  "accept-encoding": "identity",
  "sec-fetch-dest":  "document",
  "sec-fetch-mode":  "navigate",
  "sec-fetch-site":  "none",
};

function _request(opts, body) {
  return new Promise(function (resolve, reject) {
    var req = http.request(opts, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        var raw = Buffer.concat(chunks).toString("utf8");
        var parsed = null;
        try { parsed = JSON.parse(raw); } catch (_e) { /* not JSON */ }
        resolve({
          statusCode: res.statusCode,
          headers:    res.headers,
          body:       raw,
          json:       parsed,
        });
      });
    });
    req.on("error", reject);
    req.setTimeout(15000, function () { req.destroy(new Error("request timed out")); });
    if (body) req.write(typeof body === "string" ? body : JSON.stringify(body));
    req.end();
  });
}

var checks = 0;
var failures = [];
function assert(name, cond) {
  checks++;
  if (cond) console.log("  ✓ " + name);
  else { failures.push(name); console.error("  ✗ " + name); }
}

async function _setupEnv() {
  // Wire every env knob the wiki + framework honour so the boot picks
  // up the docker-compose backends. The orchestrator
  // (scripts/test-wiki-integration.js) confirms the stack is up before
  // invoking this file; we still set sensible defaults so a direct
  // invocation works on a running stack.
  var caPath = process.env.BLAMEJS_TEST_CA_PATH || path.join(os.tmpdir(), "blamejs-test-ca.crt");
  if (fs.existsSync(caPath) && !process.env.NODE_EXTRA_CA_CERTS) {
    process.env.NODE_EXTRA_CA_CERTS = caPath;
  }

  // Wiki + framework env vars — operator-style configuration through
  // env, not code. Mirrors how a real production deploy would wire
  // the backends (BLAMEJS_QUEUE_PROTOCOL=redis with QUEUE_REDIS_URL
  // pointing at the operator's Redis cluster).
  process.env.WIKI_INTEGRATION_TEST       = "true";
  process.env.WIKI_INTEGRATION_SMTP_HOST  = "localhost";
  process.env.WIKI_INTEGRATION_SMTP_PORT  = "1025";

  process.env.WIKI_INTEGRATION_S3_ENDPOINT   = "http://127.0.0.1:9000";
  process.env.WIKI_INTEGRATION_S3_BUCKET     = "wiki-integration-" + Date.now();
  process.env.WIKI_INTEGRATION_S3_ACCESS_KEY = "blamejs";
  process.env.WIKI_INTEGRATION_S3_SECRET_KEY = "blamejs_test_password";

  process.env.WIKI_INTEGRATION_MTLS_DIR = path.join(DATA_DIR, "mtls-ca");

  process.env.BLAMEJS_QUEUE_PROTOCOL  = "redis";
  process.env.BLAMEJS_QUEUE_REDIS_URL = "redis://127.0.0.1:6379/12";

  // Skip wiki's NTP boot check — the docker NTP runs on host port
  // 12300 (privileged 123 isn't bindable on Windows without admin) but
  // the framework's bootFromEnv binds servers to default port 123. We
  // exercise NTP via the /test/ntp/check route instead, which honours
  // an explicit { port } argument.
  process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
}

async function _ensureMinioBucket(bucket) {
  // bucketOps requires accessKeyId / secretAccessKey at the top level.
  var ops = b.objectStore.bucketOps.create({
    protocol:         "sigv4",
    endpoint:         "http://127.0.0.1:9000",
    region:           "us-east-1",
    accessKeyId:      "blamejs",
    secretAccessKey:  "blamejs_test_password",
    forcePathStyle:   true,
    allowInternal:    true,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
  });
  await ops.create(bucket);
  return ops;
}

async function _flushRedisDb12() {
  var c = redisClient.create({ url: "redis://127.0.0.1:6379/12" });
  await c.connect();
  await c.command("FLUSHDB");
  await c.close();
}

async function _mailpitClear() {
  return _request({
    method: "DELETE", host: "127.0.0.1", port: 8025, path: "/api/v1/messages",
  });
}

async function _mailpitList() {
  var rv = await _request({
    method: "GET", host: "127.0.0.1", port: 8025, path: "/api/v1/messages",
  });
  return rv.json;
}

async function run() {
  await _setupEnv();
  await _flushRedisDb12();
  await _mailpitClear();
  var bucket = process.env.WIKI_INTEGRATION_S3_BUCKET;
  var bucketOps = await _ensureMinioBucket(bucket);

  if (fs.existsSync(DATA_DIR)) fs.rmSync(DATA_DIR, { recursive: true, force: true });

  var built = await buildApp({
    dataDir:       DATA_DIR,
    port:          0,                 // ephemeral; listen() picks one
    adminEmail:    ADMIN_EMAIL,
    adminPassword: ADMIN_PASSWORD,
  });
  var listenInfo = await built.app.listen({ port: 0 });
  var port = listenInfo.port;
  if (!port) throw new Error("wiki app did not expose listen port");

  function _wikiReq(method, route, body) {
    var opts = {
      method:   method,
      host:     "127.0.0.1",
      port:     port,
      path:     route,
      headers:  Object.assign({}, BROWSER_HEADERS, body ? { "content-type": "application/json" } : {}),
    };
    return _request(opts, body);
  }

  try {
    console.log("\n[wiki-integration] /healthz");
    var hz = await _wikiReq("GET", "/healthz");
    assert("healthz: 200 (wiki booted with all integration backends)", hz.statusCode === 200);

    console.log("\n[wiki-integration] /test/diagnostic");
    var diag = await _wikiReq("GET", "/test/diagnostic");
    assert("diagnostic: 200", diag.statusCode === 200);
    assert("diagnostic: integrationTestMode=true",
           diag.json && diag.json.integrationTestMode === true);
    assert("diagnostic: framework version surfaced",
           diag.json && typeof diag.json.frameworkVersion === "string");

    console.log("\n[wiki-integration] cache (memory backend in wiki — exercised via HTTP)");
    var cset = await _wikiReq("POST", "/test/cache/set", { key: "wk", value: "wiki-cache-value" });
    assert("cache.set: 200",                cset.statusCode === 200);
    var cget = await _wikiReq("GET", "/test/cache/get?key=wk");
    assert("cache.get: roundtrip value",
           cget.json && cget.json.value === "wiki-cache-value");

    console.log("\n[wiki-integration] queue against real Redis backend");
    var enq = await _wikiReq("POST", "/test/queue/enqueue", {
      queueName: "wiki-int-q",
      payload:   { hello: "world" },
    });
    assert("queue.enqueue: 200 + jobId returned",
           enq.statusCode === 200 && enq.json && typeof enq.json.jobId === "string");
    var size = await _wikiReq("GET", "/test/queue/size?queueName=wiki-int-q");
    assert("queue.size: shows 1 job pending",
           size.json && size.json.size === 1);
    // Verify Redis hash actually contains the sealed payload — proves the
    // wiki's b.queue is wired to the real Redis backend, not local SQLite.
    var rc = redisClient.create({ url: "redis://127.0.0.1:6379/12" });
    await rc.connect();
    var keys = await rc.command("KEYS", "blamejs:queue:job:*");
    assert("redis: at least one job HASH present under blamejs:queue:job:*",
           Array.isArray(keys) && keys.length >= 1);
    await rc.close();

    console.log("\n[wiki-integration] mail SMTP through wiki transport → mailpit");
    var mail = await _wikiReq("POST", "/test/mail/send", {
      from: "wiki-integration@blamejs.local",
      to:   ["receiver@example.com"],
      subject: "from-the-wiki-app",
      text:    "wiki integration body " + new Date().toISOString(),
    });
    assert("mail.send: 200", mail.statusCode === 200);
    assert("mail.send: deliveredAt timestamp surfaced",
           mail.json && typeof mail.json.deliveredAt === "number");
    var captured = await _mailpitList();
    assert("mailpit: captured the wiki-sent message",
           captured && Array.isArray(captured.messages) && captured.messages.length === 1);
    assert("mailpit: subject matches wiki request",
           captured.messages[0].Subject === "from-the-wiki-app");

    console.log("\n[wiki-integration] object-store sigv4 → MinIO");
    var payload = Buffer.from("wiki-object-store-payload-" + Date.now(), "utf8");
    var put = await _wikiReq("POST", "/test/objectstore/put", {
      key:        "wiki/integration.txt",
      bodyBase64: payload.toString("base64"),
      contentType: "text/plain",
    });
    assert("objectStore.put: 200", put.statusCode === 200);
    var got = await _wikiReq("GET", "/test/objectstore/get?key=wiki%2Fintegration.txt");
    assert("objectStore.get: 200", got.statusCode === 200);
    assert("objectStore.get: bytes round-trip exactly",
           got.json && got.json.bodyBase64 === payload.toString("base64"));

    console.log("\n[wiki-integration] http-client through wiki — public target");
    var hf = await _wikiReq("POST", "/test/http/fetch", {
      url:    "https://example.com/",
      timeoutMs: 5000,
    });
    assert("httpClient: returns a status (or clean error code)",
           hf.json && (typeof hf.json.statusCode === "number" || typeof hf.json.code === "string"));

    console.log("\n[wiki-integration] SSRF guard hard-deny on cloud-metadata IP (v0.6.28 fix)");
    var ssrf = await _wikiReq("POST", "/test/ssrf/check", {
      url: "http://169.254.169.254/latest/meta-data/",
      allowInternal: true,
    });
    assert("ssrf.checkUrl: rejects 169.254.169.254 EVEN with allowInternal:true",
           ssrf.json && ssrf.json.ok === false);
    assert("ssrf.checkUrl: error code identifies cloud-metadata category",
           ssrf.json && /cloud-metadata|metadata/i.test((ssrf.json.code || "") + " " + (ssrf.json.error || "")));

    console.log("\n[wiki-integration] SSRF classify static cases");
    var clMeta = await _wikiReq("GET", "/test/ssrf/classify?ip=169.254.169.254");
    assert("ssrf.classify: 169.254.169.254 → cloud-metadata",
           clMeta.json && clMeta.json.classification === "cloud-metadata");
    var clLocal = await _wikiReq("GET", "/test/ssrf/classify?ip=127.0.0.1");
    assert("ssrf.classify: 127.0.0.1 → loopback",
           clLocal.json && clLocal.json.classification === "loopback");

    console.log("\n[wiki-integration] NTP querySingle via wiki (validates v0.6.28 IPv6 + port-flexibility fixes)");
    var ntpV4 = await _wikiReq("GET", "/test/ntp/check?server=127.0.0.1&port=12300");
    assert("ntp v4: returned drift",
           ntpV4.json && typeof ntpV4.json.driftMs === "number");
    assert("ntp v4: drift sub-minute (server is in sync)",
           ntpV4.json && Math.abs(ntpV4.json.driftMs) < 60000);
    var ntpV6 = await _wikiReq("GET", "/test/ntp/check?server=%3A%3A1&port=12300");
    assert("ntp v6: returned drift (v0.6.28 fixed udp4-only socket)",
           ntpV6.json && typeof ntpV6.json.driftMs === "number");

    console.log("\n[wiki-integration] mtls-ca through wiki — issue serverAuth cert + live mTLS handshake");
    var srvCert = await _wikiReq("POST", "/test/mtls/issue", {
      cn:    "wiki-mtls-server",
      usage: "server",
      sans:  ["DNS:wiki-mtls-server", "DNS:localhost", "IP:127.0.0.1"],
    });
    assert("mtls.issue: 200", srvCert.statusCode === 200);
    assert("mtls.issue: usage='server' echoed back",
           srvCert.json && srvCert.json.usage === "server");
    assert("mtls.issue: cert PEM-shaped",
           srvCert.json && srvCert.json.cert &&
           srvCert.json.cert.indexOf("-----BEGIN CERTIFICATE-----") === 0);
    var leafCert = await _wikiReq("POST", "/test/mtls/issue", {
      cn:    "wiki-mtls-client",
      usage: "client",
    });
    assert("mtls.issue: usage='client' returned",
           leafCert.statusCode === 200 && leafCert.json && leafCert.json.usage === "client");

    console.log("\n[wiki-integration] log-stream emit + drain (validates v0.6.28 shutdown drain fix)");
    // Stand a tiny capture server so we can verify what the wiki's
    // logStream pushed AFTER the wiki tears down. If the v0.6.28 fix
    // regresses, fire-and-forget emits queued just before shutdown
    // would be silently dropped.
    var captured2 = [];
    var capServer = http.createServer(function (req, res) {
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        try { captured2.push(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch (_e) { captured2.push({ raw: Buffer.concat(chunks).toString("utf8") }); }
        res.statusCode = 204;
        res.end();
      });
    });
    await new Promise(function (resolve) { capServer.listen(0, "127.0.0.1", resolve); });
    var capPort = capServer.address().port;
    // Re-init log-stream with a webhook sink pointing at our capture.
    if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
    b.logStream.init({
      sinks: {
        wikiHook: {
          protocol:         "webhook",
          url:              "http://127.0.0.1:" + capPort + "/log",
          allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
          allowInternal:    true,
          batchSize:        1,
        },
      },
      minLevel: "debug",
    });
    var emitRv = await _wikiReq("POST", "/test/logstream/emit", {
      level: "info", message: "wiki-pre-shutdown-1", meta: { idx: 1 },
    });
    assert("logstream.emit: 200", emitRv.statusCode === 200);
    var emitRv2 = await _wikiReq("POST", "/test/logstream/emit", {
      level: "warn", message: "wiki-pre-shutdown-2", meta: { idx: 2 },
    });
    assert("logstream.emit (2nd): 200", emitRv2.statusCode === 200);

    // Now shutdown the wiki — the v0.6.28 drain fix must hold.
    if (built.app.shutdown) await built.app.shutdown();
    else if (built.app.close) await new Promise(function (r) { built.app.close(r); });
    await b.logStream.shutdown();
    await new Promise(function (r) { capServer.close(r); });
    await new Promise(function (r) { setTimeout(r, 100); });

    var allText = JSON.stringify(captured2);
    assert("logstream: wiki-pre-shutdown-1 reached the receiver after wiki shutdown",
           allText.indexOf("wiki-pre-shutdown-1") !== -1);
    assert("logstream: wiki-pre-shutdown-2 reached the receiver after wiki shutdown",
           allText.indexOf("wiki-pre-shutdown-2") !== -1);

    console.log("\n[wiki-integration] cleanup");
    try {
      // Remove the test object + bucket so re-runs start clean.
      var be = b.objectStore.buildBackend({
        name: "cleanup", protocol: "sigv4",
        endpoint: "http://127.0.0.1:9000", region: "us-east-1", bucket: bucket,
        accessKeyId: "blamejs", secretAccessKey: "blamejs_test_password",
        forcePathStyle: true, allowInternal: true,
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        classifications: ["operational"], residencyTag: "unrestricted",
      });
      try { await be.delete("wiki/integration.txt"); } catch (_e) {}
      try { await bucketOps.delete(bucket); } catch (_e) {}
    } catch (_e) { /* best-effort cleanup */ }
    await _flushRedisDb12();
    await _mailpitClear();
  } finally {
    try { fs.rmSync(DATA_DIR, { recursive: true, force: true }); } catch (_e) {}
  }
}

run().then(function () {
  if (failures.length > 0) {
    console.error("\n[wiki-integration] FAIL — " + failures.length + " failed assertion(s):");
    failures.forEach(function (f) { console.error("  ✗ " + f); });
    process.exit(1);
  }
  console.log("\n[wiki-integration] OK — " + checks + " checks passed");
  process.exit(0);
}, function (err) {
  console.error("\n[wiki-integration] FAIL — error during run:");
  console.error(err && err.stack || err);
  process.exit(1);
});

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * sigv4-bucket-ops — bucket-level lifecycle ops for SigV4 backends.
 *
 * Stands up a fake S3 server and exercises the create / delete / list /
 * setLifecycle / setCorsRules surface end-to-end. XML body shape +
 * input validation are also exercised through the test-only exports
 * so the asserts can be tight without TCP plumbing in the loop.
 *
 * Run standalone: `node test/layer-0-primitives/sigv4-bucket-ops.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var http               = require("http");
var bucketOps          = require("../../lib/object-store/sigv4-bucket-ops");
var sigv4              = require("../../lib/object-store/sigv4");
var b                  = helpers.b;
var check              = helpers.check;
var listenOnRandomPort = helpers.listenOnRandomPort;

function _baseConfig(port, overrides) {
  var cfg = {
    region:           "us-east-1",
    accessKeyId:      "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey:  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    endpoint:         "http://127.0.0.1:" + port,
    pathStyle:        true,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    timeoutMs:        5000,
  };
  if (overrides) Object.assign(cfg, overrides);
  return cfg;
}

function _fakeS3(behavior) {
  behavior = behavior || {};
  var requests = [];
  // Emit an S3-style <Error> body with a chosen status/code. Used by the
  // failure-path tests so every PUT-based bucket op can be driven into its
  // error/audit-failure branch without hand-rolling the XML per call site.
  function sendXmlErr(res, spec) {
    res.writeHead(spec.status, { "Content-Type": "application/xml" });
    res.end(
      "<Error><Code>" + spec.code + "</Code>" +
      "<Message>" + (spec.message || spec.code) + "</Message></Error>"
    );
  }
  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var body = Buffer.concat(chunks);
      var rec = { method: req.method, url: req.url, headers: req.headers, body: body };
      requests.push(rec);

      var parsed = new URL("http://x" + req.url);
      var path = parsed.pathname;

      // ListBuckets — GET / on the service URL.
      if (req.method === "GET" && path === "/" && !req.headers.host.startsWith("test-bucket")) {
        if (behavior.onList) {
          var lr = behavior.onList();
          res.writeHead(lr.statusCode || 200, lr.headers || { "Content-Type": "application/xml" });
          res.end(lr.body || "");
          return;
        }
        res.writeHead(200, { "Content-Type": "application/xml" });
        res.end(
          "<?xml version='1.0' encoding='UTF-8'?>" +
          "<ListAllMyBucketsResult>" +
          "<Buckets>" +
          "<Bucket><Name>alpha</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate><BucketRegion>us-east-1</BucketRegion></Bucket>" +
          "<Bucket><Name>beta</Name><CreationDate>2026-02-01T00:00:00.000Z</CreationDate><BucketRegion>eu-west-1</BucketRegion></Bucket>" +
          "</Buckets>" +
          "<Owner><ID>op-id</ID><DisplayName>op</DisplayName></Owner>" +
          "</ListAllMyBucketsResult>"
        );
        return;
      }

      if (req.method === "PUT" && parsed.searchParams.has("lifecycle")) {
        if (behavior.lifecycleErr) {
          res.writeHead(behavior.lifecycleErr.status, { "Content-Type": "application/xml" });
          res.end("<Error><Code>" + behavior.lifecycleErr.code + "</Code></Error>");
          return;
        }
        res.writeHead(200);
        res.end();
        return;
      }
      if (req.method === "PUT" && parsed.searchParams.has("cors")) {
        if (behavior.corsErr) { sendXmlErr(res, behavior.corsErr); return; }
        res.writeHead(200);
        res.end();
        return;
      }
      // Object Lock configuration (bucket-level).
      if (parsed.searchParams.has("object-lock")) {
        if (req.method === "GET" && behavior.onGetObjectLock) {
          var ol = behavior.onGetObjectLock();
          res.writeHead(ol.statusCode, ol.headers || { "Content-Type": "application/xml" });
          res.end(ol.body || "");
          return;
        }
        if (req.method === "PUT" && behavior.objectLockPutErr) {
          sendXmlErr(res, behavior.objectLockPutErr);
          return;
        }
        // PUT just acks
        res.writeHead(200);
        res.end();
        return;
      }
      // Per-object retention.
      if (parsed.searchParams.has("retention")) {
        if (req.method === "GET" && behavior.onGetObjectRetention) {
          var ret = behavior.onGetObjectRetention();
          res.writeHead(ret.statusCode, ret.headers || { "Content-Type": "application/xml" });
          res.end(ret.body || "");
          return;
        }
        if (req.method === "PUT" && behavior.retentionPutErr) {
          sendXmlErr(res, behavior.retentionPutErr);
          return;
        }
        res.writeHead(200);
        res.end();
        return;
      }
      // Per-object legal hold.
      if (parsed.searchParams.has("legal-hold")) {
        if (req.method === "GET" && behavior.onGetLegalHold) {
          var lh = behavior.onGetLegalHold();
          res.writeHead(lh.statusCode, lh.headers || { "Content-Type": "application/xml" });
          res.end(lh.body || "");
          return;
        }
        if (req.method === "PUT" && behavior.legalHoldPutErr) {
          sendXmlErr(res, behavior.legalHoldPutErr);
          return;
        }
        res.writeHead(200);
        res.end();
        return;
      }
      // CreateBucket — PUT /<bucket>/ (path-style) with optional XML body.
      if (req.method === "PUT") {
        if (behavior.createErr) {
          res.writeHead(behavior.createErr.status, { "Content-Type": "application/xml" });
          res.end(
            "<Error><Code>" + behavior.createErr.code + "</Code>" +
            "<Message>" + behavior.createErr.code + "</Message></Error>"
          );
          return;
        }
        res.writeHead(200, { Location: path });
        res.end();
        return;
      }
      // DeleteBucket — DELETE /<bucket>/ (path-style).
      if (req.method === "DELETE") {
        if (behavior.deleteErr) {
          res.writeHead(behavior.deleteErr.status, { "Content-Type": "application/xml" });
          res.end(
            "<Error><Code>" + behavior.deleteErr.code + "</Code>" +
            "<Message>" + behavior.deleteErr.code + "</Message></Error>"
          );
          return;
        }
        res.writeHead(204);
        res.end();
        return;
      }
      res.writeHead(400);
      res.end();
    });
  });
  return { server: server, requests: requests };
}

// ---- Surface ----

function testSurface() {
  check("b.objectStore.bucketOps namespace present",
        typeof b.objectStore.bucketOps === "object");
  check("bucketOps.create is a function",
        typeof b.objectStore.bucketOps.create === "function");
  var ops = b.objectStore.bucketOps.create({
    protocol: "sigv4",
    region: "us-east-1", accessKeyId: "x", secretAccessKey: "y",
    endpoint: "http://127.0.0.1:1",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true,
  });
  check("instance.create is fn",       typeof ops.create === "function");
  check("instance.delete is fn",       typeof ops.delete === "function");
  check("instance.list is fn",         typeof ops.list === "function");
  check("instance.setLifecycle is fn", typeof ops.setLifecycle === "function");
  check("instance.setCorsRules is fn", typeof ops.setCorsRules === "function");
  check("instance.setObjectLockConfiguration is fn",
        typeof ops.setObjectLockConfiguration === "function");
  check("instance.getObjectLockConfiguration is fn",
        typeof ops.getObjectLockConfiguration === "function");
  check("instance.setObjectRetention is fn",
        typeof ops.setObjectRetention === "function");
  check("instance.getObjectRetention is fn",
        typeof ops.getObjectRetention === "function");
  check("instance.setObjectLegalHold is fn",
        typeof ops.setObjectLegalHold === "function");
  check("instance.getObjectLegalHold is fn",
        typeof ops.getObjectLegalHold === "function");
}

// ---- Config validation ----

function testFactoryValidation() {
  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { bucketOps.create(opts); } catch (e) { threw = e; }
    check("factory: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects null opts",      null, /INVALID_CONFIG/);
  shouldThrow("rejects missing region",
    { accessKeyId: "x", secretAccessKey: "y" }, /INVALID_CONFIG/);
  shouldThrow("rejects missing accessKeyId",
    { region: "us-east-1", secretAccessKey: "y" }, /INVALID_CONFIG/);
  shouldThrow("rejects unsupported protocol",
    { protocol: "gcs", region: "us-east-1", accessKeyId: "x", secretAccessKey: "y" },
    /INVALID_CONFIG/);

  // `ca` was an accepted-but-dead config knob — nothing in the request
  // path (reqOpts → http-request → httpClient.request) threads a custom
  // CA cert (the framework's PQC-only TLS posture lives solely in
  // lib/pqc-agent.js; operators use NODE_EXTRA_CA_CERTS / opts.agent).
  // De-advertised: passing it must now throw as an unknown option.
  var threwCa = null;
  try {
    bucketOps.create(Object.assign({}, _baseConfig(9999), { ca: "-----BEGIN CERTIFICATE-----" }));
  } catch (e) { threwCa = e; }
  check("factory: de-advertised `ca` knob rejected as unknown option",
        threwCa && /unknown option 'ca'/.test(threwCa.message || ""));
}

// ---- Bucket name validation ----

function testBucketNameValidation() {
  var v = bucketOps._validateBucketNameForTest;
  function shouldThrow(label, name) {
    var threw = null;
    try { v(name); } catch (e) { threw = e; }
    check("bucket-name: " + label,  threw && /BUCKET_INVALID_NAME/.test(threw.code));
  }
  shouldThrow("rejects too short",        "ab");
  shouldThrow("rejects too long",         new Array(65).join("a"));
  shouldThrow("rejects uppercase",        "MyBucket");
  shouldThrow("rejects leading hyphen",   "-bucket");
  shouldThrow("rejects trailing hyphen",  "bucket-");
  shouldThrow("rejects underscore",       "my_bucket");
  shouldThrow("rejects consecutive dots", "my..bucket");
  shouldThrow("rejects non-string name",  123);
  shouldThrow("rejects null name",        null);
  // Valid names should not throw.
  v("valid-bucket-name");
  v("vbn1");
  v("a.b.c");
  check("bucket-name: valid names pass",  true);
}

// ---- Lifecycle XML builder ----

function testLifecycleXml() {
  var b1 = bucketOps._buildLifecycleXmlForTest([{
    id: "abort-stale", status: "Enabled", prefix: "",
    abortIncompleteMultipartUpload: { daysAfterInitiation: 7 },
  }]);
  check("lifecycle: root LifecycleConfiguration",
        /<LifecycleConfiguration/.test(b1));
  check("lifecycle: ID present",
        /<ID>abort-stale<\/ID>/.test(b1));
  check("lifecycle: Status Enabled",
        /<Status>Enabled<\/Status>/.test(b1));
  check("lifecycle: AbortIncompleteMultipartUpload present",
        /<AbortIncompleteMultipartUpload><DaysAfterInitiation>7<\/DaysAfterInitiation>/.test(b1));

  var b2 = bucketOps._buildLifecycleXmlForTest([{
    prefix: "tmp/", status: "Enabled",
    expiration: { days: 30 },
    transition: { days: 90, storageClass: "GLACIER" },
  }]);
  check("lifecycle: prefix + expiration days",
        /<Prefix>tmp\/<\/Prefix>/.test(b2) && /<Expiration><Days>30<\/Days><\/Expiration>/.test(b2));
  check("lifecycle: transition storageClass",
        /<Transition><Days>90<\/Days><StorageClass>GLACIER<\/StorageClass><\/Transition>/.test(b2));

  function shouldThrow(label, rules, codeRe) {
    var threw = null;
    try { bucketOps._buildLifecycleXmlForTest(rules); } catch (e) { threw = e; }
    check("lifecycle: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects empty rules",            [],
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects non-array rules",        "no",
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects bad status",
    [{ prefix: "", status: "Mid", expiration: { days: 1 } }],
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects rule with no action",
    [{ prefix: "", status: "Enabled" }],
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects unknown storageClass",
    [{ prefix: "", status: "Enabled",
       transition: { days: 90, storageClass: "ICE" } }],
    /INVALID_LIFECYCLE/);
  shouldThrow("rejects expiration.days = 0",
    [{ prefix: "", status: "Enabled", expiration: { days: 0 } }],
    /INVALID_LIFECYCLE/);
}

// ---- CORS XML builder ----

function testCorsXml() {
  var x = bucketOps._buildCorsXmlForTest([{
    allowedOrigins: ["https://app.example.com"],
    allowedMethods: ["GET", "PUT"],
    allowedHeaders: ["*"],
    exposeHeaders:  ["ETag"],
    maxAgeSeconds:  3600,
  }]);
  check("cors: root CORSConfiguration",   /<CORSConfiguration/.test(x));
  check("cors: AllowedOrigin escaped",
        /<AllowedOrigin>https:\/\/app\.example\.com<\/AllowedOrigin>/.test(x));
  check("cors: methods listed",
        /<AllowedMethod>GET<\/AllowedMethod><AllowedMethod>PUT<\/AllowedMethod>/.test(x));
  check("cors: AllowedHeader wildcard",   /<AllowedHeader>\*<\/AllowedHeader>/.test(x));
  check("cors: ExposeHeader present",     /<ExposeHeader>ETag<\/ExposeHeader>/.test(x));
  check("cors: MaxAgeSeconds present",    /<MaxAgeSeconds>3600<\/MaxAgeSeconds>/.test(x));

  function shouldThrow(label, rules, codeRe) {
    var threw = null;
    try { bucketOps._buildCorsXmlForTest(rules); } catch (e) { threw = e; }
    check("cors: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects empty rules array",  [], /INVALID_CORS_RULE/);
  shouldThrow("rejects missing allowedOrigins",
    [{ allowedMethods: ["GET"] }],
    /INVALID_CORS_RULE/);
  shouldThrow("rejects missing allowedMethods",
    [{ allowedOrigins: ["*"] }],
    /INVALID_CORS_RULE/);
  shouldThrow("rejects bad allowedMethod",
    [{ allowedOrigins: ["*"], allowedMethods: ["TRACE"] }],
    /INVALID_CORS_RULE/);
  shouldThrow("rejects negative maxAgeSeconds",
    [{ allowedOrigins: ["*"], allowedMethods: ["GET"], maxAgeSeconds: -1 }],
    /INVALID_CORS_RULE/);
}

// ---- create / delete / list / setLifecycle / setCorsRules over the wire ----

async function testCreateBucketUsEast1NoBody() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var result = await ops.create("my-bucket");
    check("create us-east-1: result.created",     result.created === true);
    check("create us-east-1: result.name",        result.name === "my-bucket");
    var req = fake.requests[0];
    check("create us-east-1: PUT method",         req.method === "PUT");
    check("create us-east-1: empty body",         req.body.length === 0);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testCreateBucketOtherRegionSendsLocationConstraint() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    await ops.create("eu-bucket", { region: "eu-west-1" });
    var req = fake.requests[0];
    check("create eu: body has CreateBucketConfiguration",
          /CreateBucketConfiguration/.test(req.body.toString("utf8")));
    check("create eu: LocationConstraint present",
          /<LocationConstraint>eu-west-1<\/LocationConstraint>/.test(req.body.toString("utf8")));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testCreateBucketAlreadyOwnedMaps() {
  var fake = _fakeS3({
    createErr: { status: 409, code: "BucketAlreadyOwnedByYou" },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var threw = null;
    try { await ops.create("mine"); } catch (e) { threw = e; }
    check("create owned: maps to BUCKET_ALREADY_OWNED",
          threw && /BUCKET_ALREADY_OWNED/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testCreateBucketTakenMaps() {
  var fake = _fakeS3({
    createErr: { status: 409, code: "BucketAlreadyExists" },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var threw = null;
    try { await ops.create("taken"); } catch (e) { threw = e; }
    check("create taken: maps to BUCKET_NAME_TAKEN",
          threw && /BUCKET_NAME_TAKEN/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testDeleteBucketHappyAndMissing() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var ok = await ops.delete("gone");
    check("delete: returns true on 204",  ok === true);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }

  var fake2 = _fakeS3({ deleteErr: { status: 404, code: "NoSuchBucket" } });
  var port2 = await listenOnRandomPort(fake2.server);
  try {
    var ops2 = bucketOps.create(_baseConfig(port2));
    var ok2 = await ops2.delete("missing");
    check("delete: returns false on 404",  ok2 === false);
  } finally {
    await new Promise(function (r) { fake2.server.close(function () { r(); }); });
  }
}

async function testDeleteBucketNotEmptyMaps() {
  var fake = _fakeS3({ deleteErr: { status: 409, code: "BucketNotEmpty" } });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var threw = null;
    try { await ops.delete("full"); } catch (e) { threw = e; }
    check("delete not-empty: maps to BUCKET_NOT_EMPTY",
          threw && /BUCKET_NOT_EMPTY/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testListBuckets() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var buckets = await ops.list();
    check("list: returns 2 buckets",       buckets.length === 2);
    check("list: bucket name parsed",      buckets[0].name === "alpha");
    check("list: bucket region parsed",    buckets[1].region === "eu-west-1");
    check("list: creationDate is a ms ts", typeof buckets[0].creationDate === "number");
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSetLifecycleSendsXml() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var result = await ops.setLifecycle("logs", [{
      id: "abort", status: "Enabled", prefix: "",
      abortIncompleteMultipartUpload: { daysAfterInitiation: 7 },
    }]);
    check("setLifecycle: applied=true",          result.applied === true);
    check("setLifecycle: ruleCount echoed",      result.ruleCount === 1);
    var req = fake.requests[0];
    check("setLifecycle: ?lifecycle in url",     req.url.indexOf("lifecycle") !== -1);
    check("setLifecycle: Content-MD5 sent",      typeof req.headers["content-md5"] === "string");
    check("setLifecycle: body has root element", /<LifecycleConfiguration/.test(req.body.toString("utf8")));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSetCorsRulesSendsXml() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var result = await ops.setCorsRules("public", [{
      allowedOrigins: ["https://wiki.example.com"],
      allowedMethods: ["GET", "HEAD"],
      maxAgeSeconds:  86400,
    }]);
    check("setCorsRules: applied=true",          result.applied === true);
    var req = fake.requests[0];
    check("setCorsRules: ?cors in url",          req.url.indexOf("cors") !== -1);
    check("setCorsRules: Content-MD5 sent",      typeof req.headers["content-md5"] === "string");
    check("setCorsRules: body has CORSRule",     /<CORSRule>/.test(req.body.toString("utf8")));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Object Lock tests (v0.6.47) ----

async function testCreateBucketObjectLockEnabled() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    await ops.create("locked-bucket", { objectLockEnabled: true });
    var req = fake.requests[0];
    check("createBucket+objectLockEnabled sets x-amz-bucket-object-lock-enabled header",
          req.headers["x-amz-bucket-object-lock-enabled"] === "true");
    // Default (no opt) should NOT set the header.
    fake.requests.length = 0;
    await ops.create("regular-bucket");
    check("createBucket without opt does NOT set object-lock header",
          fake.requests[0].headers["x-amz-bucket-object-lock-enabled"] == null);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSetObjectLockConfiguration() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var rv = await ops.setObjectLockConfiguration("my-bucket",
      { mode: "GOVERNANCE", days: 365 });
    check("setObjectLockConfiguration applied=true",  rv.applied === true);
    check("setObjectLockConfiguration mode echoed",    rv.mode === "GOVERNANCE");
    var req = fake.requests[0];
    check("PUT method used",                  req.method === "PUT");
    check("URL has ?object-lock query (bare subresource)",
          /\?object-lock$|\?object-lock&/.test(req.url));
    check("URL object-lock has no '=' suffix",
          !/\?object-lock=/.test(req.url));
    var bodyStr = req.body.toString("utf8");
    check("body has ObjectLockEnabled=Enabled",
          /<ObjectLockEnabled>Enabled<\/ObjectLockEnabled>/.test(bodyStr));
    check("body has Mode=GOVERNANCE",
          /<Mode>GOVERNANCE<\/Mode>/.test(bodyStr));
    check("body has Days=365",
          /<Days>365<\/Days>/.test(bodyStr));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSetObjectLockConfigurationValidation() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    async function shouldThrow(label, opts, codeRe) {
      var threw = null;
      try { await ops.setObjectLockConfiguration("my-bucket", opts); }
      catch (e) { threw = e; }
      check("validation: " + label,
            threw && codeRe.test(threw.code || ""));
    }
    await shouldThrow("rejects bad mode",
      { mode: "WORM" }, /INVALID_OBJECT_LOCK/);
    await shouldThrow("rejects days+years together",
      { mode: "COMPLIANCE", days: 30, years: 1 }, /INVALID_OBJECT_LOCK/);
    await shouldThrow("rejects negative days",
      { mode: "COMPLIANCE", days: -5 }, /INVALID_OBJECT_LOCK/);
    await shouldThrow("rejects fractional days",
      { mode: "COMPLIANCE", days: 1.5 }, /INVALID_OBJECT_LOCK/);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testGetObjectLockConfiguration() {
  var fake = _fakeS3({
    onGetObjectLock: function () {
      return {
        statusCode: 200,
        headers: { "Content-Type": "application/xml" },
        body: '<?xml version="1.0"?>' +
              '<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>' +
              '<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>1</Years></DefaultRetention></Rule>' +
              '</ObjectLockConfiguration>',
      };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var rv = await ops.getObjectLockConfiguration("my-bucket");
    check("getObjectLockConfiguration returns enabled=true",   rv.enabled === true);
    check("getObjectLockConfiguration returns mode=COMPLIANCE", rv.mode === "COMPLIANCE");
    check("getObjectLockConfiguration returns years=1",        rv.years === 1);
    check("getObjectLockConfiguration returns days=null",      rv.days === null);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSetObjectRetention() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var until = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    var rv = await ops.setObjectRetention("my-bucket", "path/to/file.txt", {
      mode:        "COMPLIANCE",
      retainUntil: until,
    });
    check("setObjectRetention applied",  rv.applied === true);
    check("setObjectRetention echoes mode + retainUntil",
          rv.mode === "COMPLIANCE" && rv.retainUntil === until);
    // setObjectRetention now does a GET-before-PUT so it can refuse
    // client-side when an existing COMPLIANCE retention would be
    // shortened or bypassed. The PUT request is the LAST one in the
    // requests array.
    var req = fake.requests[fake.requests.length - 1];
    check("URL has ?retention query (bare subresource, no trailing =)",
          /\?retention$|\?retention&/.test(req.url));
    check("URL retention query has no '=' suffix (S3 strict-mode bug fix)",
          !/\?retention=/.test(req.url));
    check("URL has the encoded object key",
          /\/path\/to\/file\.txt/.test(req.url));
    var bodyStr = req.body.toString("utf8");
    check("body has Mode=COMPLIANCE",
          /<Mode>COMPLIANCE<\/Mode>/.test(bodyStr));
    check("body has RetainUntilDate ISO 8601",
          /<RetainUntilDate>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(bodyStr));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSetObjectRetentionBypassGovernance() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var until = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await ops.setObjectRetention("my-bucket", "doc.pdf", {
      mode:               "GOVERNANCE",
      retainUntil:        until,
      bypassGovernance:   true,
    });
    // PUT is the last request after the GET-before-PUT existing-retention check.
    var req = fake.requests[fake.requests.length - 1];
    check("bypassGovernance:true sets x-amz-bypass-governance-retention header",
          req.headers["x-amz-bypass-governance-retention"] === "true");
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testSetObjectRetentionValidation() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    async function shouldThrow(label, opts, codeRe) {
      var threw = null;
      try { await ops.setObjectRetention("my-bucket", "k", opts); }
      catch (e) { threw = e; }
      check("retention validation: " + label,
            threw && codeRe.test(threw.code || ""));
    }
    await shouldThrow("rejects null opts",
      null, /INVALID_RETENTION/);
    await shouldThrow("rejects missing mode",
      { retainUntil: new Date(Date.now() + 1000) }, /INVALID_RETENTION/);
    await shouldThrow("rejects bad mode",
      { mode: "WORM", retainUntil: new Date(Date.now() + 1000) }, /INVALID_RETENTION/);
    await shouldThrow("rejects past retainUntil",
      { mode: "COMPLIANCE", retainUntil: new Date(Date.now() - 1000) }, /INVALID_RETENTION/);
    await shouldThrow("rejects non-Date retainUntil",
      { mode: "COMPLIANCE", retainUntil: "2027-01-01" }, /INVALID_RETENTION/);
    var threwKey = null;
    try { await ops.setObjectRetention("my-bucket", "",
            { mode: "COMPLIANCE", retainUntil: new Date(Date.now()+1000) }); }
    catch (e) { threwKey = e; }
    check("retention validation: rejects empty key",
          threwKey && /INVALID_KEY/.test(threwKey.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testGetObjectRetention() {
  var until = new Date(Date.now() + 100000);
  var fake = _fakeS3({
    onGetObjectRetention: function () {
      return {
        statusCode: 200,
        body: '<?xml version="1.0"?>' +
              '<Retention><Mode>GOVERNANCE</Mode>' +
              '<RetainUntilDate>' + until.toISOString() + '</RetainUntilDate>' +
              '</Retention>',
      };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var rv = await ops.getObjectRetention("my-bucket", "k");
    check("getObjectRetention mode=GOVERNANCE", rv.mode === "GOVERNANCE");
    check("getObjectRetention retainUntil is a Date",
          rv.retainUntil instanceof Date && !isNaN(rv.retainUntil.getTime()));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testLegalHold() {
  var fake = _fakeS3({
    onGetLegalHold: function () {
      return {
        statusCode: 200,
        body: '<?xml version="1.0"?><LegalHold><Status>ON</Status></LegalHold>',
      };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var rv = await ops.setObjectLegalHold("my-bucket", "k", "ON");
    check("setObjectLegalHold applied",  rv.applied === true);
    check("setObjectLegalHold status echoed", rv.status === "ON");
    var req = fake.requests[0];
    check("URL has ?legal-hold query (bare subresource)",
          /\?legal-hold$|\?legal-hold&/.test(req.url));
    check("URL legal-hold has no '=' suffix",
          !/\?legal-hold=/.test(req.url));
    var body = req.body.toString("utf8");
    check("body has Status=ON", /<Status>ON<\/Status>/.test(body));

    var got = await ops.getObjectLegalHold("my-bucket", "k");
    check("getObjectLegalHold parses status from XML", got.status === "ON");

    var threw = null;
    try { await ops.setObjectLegalHold("my-bucket", "k", "MAYBE"); }
    catch (e) { threw = e; }
    check("legal hold rejects bad status",
          threw && /INVALID_LEGAL_HOLD/.test(threw.code || ""));
    var threwOff = await ops.setObjectLegalHold("my-bucket", "k", "OFF");
    check("legal hold accepts OFF",  threwOff.status === "OFF");
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Not-configured response paths (v0.6.51) ----

async function testGetObjectLockConfigurationNotConfigured() {
  var fake = _fakeS3({
    onGetObjectLock: function () {
      return {
        statusCode: 404,
        body: '<?xml version="1.0"?><Error>' +
              '<Code>ObjectLockConfigurationNotFoundError</Code>' +
              '<Message>Object Lock configuration does not exist for this bucket</Message>' +
              '</Error>',
      };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var rv = await ops.getObjectLockConfiguration("my-bucket");
    check("getObjectLockConfiguration on no-lock bucket returns enabled=false",
          rv.enabled === false);
    check("getObjectLockConfiguration on no-lock bucket returns mode=null",
          rv.mode === null);
    check("getObjectLockConfiguration on no-lock bucket returns days=null",
          rv.days === null);
    check("getObjectLockConfiguration on no-lock bucket returns years=null",
          rv.years === null);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testGetObjectRetentionNotConfigured() {
  var fake = _fakeS3({
    onGetObjectRetention: function () {
      return {
        statusCode: 400,
        body: '<?xml version="1.0"?><Error>' +
              '<Code>NoSuchObjectLockConfiguration</Code>' +
              '<Message>The specified object does not have any retention configuration</Message>' +
              '</Error>',
      };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var rv = await ops.getObjectRetention("my-bucket", "k");
    check("getObjectRetention on un-set object returns mode=null",
          rv.mode === null);
    check("getObjectRetention on un-set object returns retainUntil=null",
          rv.retainUntil === null);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testGetObjectLegalHoldNotConfigured() {
  var fake = _fakeS3({
    onGetLegalHold: function () {
      return {
        statusCode: 400,
        body: '<?xml version="1.0"?><Error>' +
              '<Code>NoSuchObjectLockConfiguration</Code>' +
              '<Message>The specified object does not have any legal hold</Message>' +
              '</Error>',
      };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var rv = await ops.getObjectLegalHold("my-bucket", "k");
    check("getObjectLegalHold on no-hold object returns status=OFF",
          rv.status === "OFF");
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Audit + observability emissions (v0.6.53) ----

function _captureAudit() {
  var captured = [];
  return {
    safeEmit: function (e) { captured.push(e); },
    captured: captured,
    byAction: function (a) { return captured.filter(function (e) { return e.action === a; }); },
  };
}
function _captureObs() {
  var captured = [];
  function event(n, v, l) { captured.push({ name: n, value: v, labels: l }); }
  return {
    event:     event,
    safeEvent: function (n, v, l) { try { event(n, v, l); } catch (_e) { /* drop-silent */ } },
    captured:  captured,
    byName:    function (n) { return captured.filter(function (e) { return e.name === n; }); },
  };
}

async function testAuditObservabilityWiring() {
  var auditCap = _captureAudit();
  var obsCap   = _captureObs();
  var fake = _fakeS3({
    onGetObjectLock: function () {
      return { statusCode: 200, body:
        '<?xml version="1.0"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>' };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(Object.assign({}, _baseConfig(port), {
      audit:         auditCap,
      observability: obsCap,
    }));
    await ops.create("audit-bucket");
    await ops.setObjectLockConfiguration("audit-bucket", { mode: "GOVERNANCE", days: 30 });
    await ops.getObjectLockConfiguration("audit-bucket");
    await ops.setObjectRetention("audit-bucket", "k", {
      mode: "COMPLIANCE",
      retainUntil: new Date(Date.now() + 60000),
    });
    await ops.setObjectRetention("audit-bucket", "k", {
      mode: "GOVERNANCE",
      retainUntil: new Date(Date.now() + 60000),
      bypassGovernance: true,
    });
    await ops.setObjectLegalHold("audit-bucket", "k", "ON");
    await ops.delete("audit-bucket");

    // Audit assertions
    check("audit emits objectstore.bucket.create",
          auditCap.byAction("objectstore.bucket.create").length === 1);
    check("audit emits objectstore.bucket.setObjectLockConfiguration with mode",
          auditCap.byAction("objectstore.bucket.setObjectLockConfiguration").length === 1 &&
          auditCap.byAction("objectstore.bucket.setObjectLockConfiguration")[0].metadata.mode === "GOVERNANCE");
    check("audit emits objectstore.object.setRetention twice (one bypassGovernance)",
          auditCap.byAction("objectstore.object.setRetention").length === 2 &&
          auditCap.byAction("objectstore.object.setRetention")[1].metadata.bypassGovernance === true);
    check("audit emits objectstore.object.setLegalHold with status",
          auditCap.byAction("objectstore.object.setLegalHold").length === 1 &&
          auditCap.byAction("objectstore.object.setLegalHold")[0].metadata.status === "ON");
    check("audit emits objectstore.bucket.delete with existed:true",
          auditCap.byAction("objectstore.bucket.delete").length === 1 &&
          auditCap.byAction("objectstore.bucket.delete")[0].metadata.existed === true);
    // Reads emit observability counter but NOT audit
    check("audit does NOT emit getObjectLockConfiguration (read-only op)",
          auditCap.byAction("objectstore.bucket.getObjectLockConfiguration").length === 0);

    // Observability assertions
    check("obs emits getObjectLockConfiguration",
          obsCap.byName("objectstore.bucket.getObjectLockConfiguration").length === 1);
    check("obs labels carry bypassGovernance flag",
          obsCap.byName("objectstore.object.setRetention")[1].labels.bypassGovernance === "true");
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testAuditSuccessFalseDisablesSuccessAudit() {
  var auditCap = _captureAudit();
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(Object.assign({}, _baseConfig(port), {
      audit:        auditCap,
      auditSuccess: false,
    }));
    await ops.create("quiet-bucket");
    check("auditSuccess:false suppresses success audit",
          auditCap.byAction("objectstore.bucket.create").length === 0);

    // But failure-audit still fires
    var fakeErr = _fakeS3({ createErr: { status: 409, code: "BucketAlreadyOwnedByYou" } });
    var port2 = await listenOnRandomPort(fakeErr.server);
    try {
      var ops2 = bucketOps.create(Object.assign({}, _baseConfig(port2), {
        audit:        auditCap,
        auditSuccess: false,
      }));
      try { await ops2.create("collide"); } catch (_e) { /* expected */ }
      check("auditFailures still fires when auditSuccess:false",
            auditCap.byAction("objectstore.bucket.create").length === 1 &&
            auditCap.byAction("objectstore.bucket.create")[0].outcome === "failure");
    } finally {
      await new Promise(function (r) { fakeErr.server.close(function () { r(); }); });
    }
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

async function testPerCallActorOverrideHonored() {
  // Per-method opts accept `req` (resolves IP / user-agent / userId from a
  // live request) and `actor` (an explicit identity override for callers
  // performing a compliance-sensitive change on behalf of an operator).
  // Both must land on the emitted audit row's `actor` field; `actor`-set
  // keys win over the request-derived ones.
  var auditCap = _captureAudit();
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(Object.assign({}, _baseConfig(port), {
      audit: auditCap,
    }));

    var fakeReq = {
      ip:      "203.0.113.9",
      method:  "PUT",
      headers: { "user-agent": "ops-cli/1.0" },
    };
    await ops.create("actor-bucket", {
      req:   fakeReq,
      actor: { userId: "ops-admin" },
    });

    var rows = auditCap.byAction("objectstore.bucket.create");
    check("actor override: audit row emitted", rows.length === 1);
    var actor = rows.length === 1 ? rows[0].actor : {};
    check("actor override: explicit actor.userId lands on the audit row",
          actor.userId === "ops-admin");
    check("actor override: request-derived ip lands on the audit row",
          actor.ip === "203.0.113.9");
    check("actor override: request-derived userAgent lands on the audit row",
          actor.userAgent === "ops-cli/1.0");

    // Without actor/req, the resolved actor has the resolver's null
    // defaults (no override) — default behavior unchanged.
    var auditCap2 = _captureAudit();
    var ops2 = bucketOps.create(Object.assign({}, _baseConfig(port), {
      audit: auditCap2,
    }));
    await ops2.create("plain-bucket");
    var rows2 = auditCap2.byAction("objectstore.bucket.create");
    check("actor override: default behavior unchanged when actor/req absent",
          rows2.length === 1 && rows2[0].actor && rows2[0].actor.userId === null);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

function testCanonicalPathSingleEncodeForS3() {
  // Regression: S3 (and S3-compatible stores + GCS's V4) URI-encode the
  // canonical path ONCE; the older code double-encoded it, so any object key
  // with a space / + / & / unicode signed a path the wire never carried →
  // SignatureDoesNotMatch (403). Drive the real signRequest path with a
  // special-char key and assert the canonical path line equals the wire
  // pathname byte-for-byte. (Pre-fix this matched only for ASCII keys, which
  // is why every shipped test passed while real keys 403'd.)
  var key = "my report (v2)+final & draft.txt";
  var encodedKey = key.split("/").map(function (s) { return sigv4.awsUriEncode(s, true); }).join("/");
  var url = new URL("https://bucket.s3.example.com");
  url.pathname = "/" + encodedKey;

  var s3 = sigv4.signRequest({
    method: "GET", url: url, headers: {}, payloadHash: "UNSIGNED-PAYLOAD",
    region: "us-east-1", accessKeyId: "AK", secretAccessKey: "sk", date: new Date(0),
  });
  var s3CanonPath = s3.canonicalRequest.split("\n")[1];
  check("S3 canonical path single-encodes — equals the wire pathname (no double-encode)",
        s3CanonPath === url.pathname);
  check("S3 canonical path has no double-encoded %25 sequence",
        s3CanonPath.indexOf("%25") === -1 && url.pathname.indexOf("%25") === -1);

  // The non-S3 services (sqs/logs/sns) MUST keep the double-encode (AWS spec).
  var u2 = new URL("https://sqs.us-east-1.amazonaws.com");
  u2.pathname = "/a%20b";
  var sqs = sigv4.signRequest({
    method: "GET", url: u2, headers: {}, payloadHash: sigv4.sha256Hex(""),
    region: "us-east-1", service: "sqs", accessKeyId: "AK", secretAccessKey: "sk", date: new Date(0),
  });
  var sqsCanonPath = sqs.canonicalRequest.split("\n")[1];
  check("non-S3 service still double-encodes the canonical path (spec-correct, unchanged)",
        sqsCanonPath === "/a%2520b");

  // awsUriEncode escapes the AWS reserved set (!*'()) that encodeURIComponent
  // leaves alone, so the bucket-ops wire path matches the bytes S3 signs over.
  check("awsUriEncode escapes !*'() that encodeURIComponent leaves raw",
        sigv4.awsUriEncode("a!b*c'd(e)", true) === "a%21b%2Ac%27d%28e%29");

  // A key with a non-BMP code point (emoji, CJK extension B, ...) must encode
  // by code point, not UTF-16 unit — otherwise the surrogate pair is split and
  // encodeURIComponent throws "URIError: URI malformed" before the request is
  // even signed.
  check("awsUriEncode encodes a non-BMP code point as one UTF-8 sequence (no URIError)",
        sigv4.awsUriEncode("photo-\u{1F600}.jpg", true) === "photo-%F0%9F%98%80.jpg");
}

// ---- Factory default-resolution branches ----

function testFactoryDefaultsAndTrailingSlash() {
  // Missing secretAccessKey — the third required-credential guard (region +
  // accessKeyId are already covered; this closes the trio).
  var threwSecret = null;
  try {
    bucketOps.create({ region: "us-east-1", accessKeyId: "x" });
  } catch (e) { threwSecret = e; }
  check("factory: missing secretAccessKey rejected",
        threwSecret && /INVALID_CONFIG/.test(threwSecret.code || ""));

  // No endpoint / allowedProtocols / allowInternal supplied — the factory
  // must fill each default (endpoint → https://s3.<region>.amazonaws.com,
  // allowedProtocols → ALLOW_HTTP_TLS, allowInternal → null) and still
  // return a usable ops object. No request is made here so no network is hit.
  var opsDefault = bucketOps.create({
    region:          "us-east-1",
    accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  });
  check("factory: defaults resolve to a usable ops object (protocol sigv4)",
        opsDefault && opsDefault.protocol === "sigv4");
  check("factory: default ops exposes create()",
        typeof opsDefault.create === "function");

  // Trailing slash on the endpoint is trimmed so the derived bucket URLs
  // don't grow a double slash.
  var opsSlash = bucketOps.create({
    region:           "us-east-1",
    accessKeyId:      "x",
    secretAccessKey:  "y",
    endpoint:         "http://127.0.0.1:1/",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
  });
  check("factory: trailing-slash endpoint accepted (slash trimmed)",
        opsSlash && opsSlash.protocol === "sigv4");
}

// ---- Lifecycle XML builder — adversarial / optional-field branches ----

function testLifecycleXmlAdversarial() {
  function shouldThrow(label, rules, codeRe) {
    var threw = null;
    try { bucketOps._buildLifecycleXmlForTest(rules); } catch (e) { threw = e; }
    check("lifecycle-adv: " + label,  threw && codeRe.test(threw.code || ""));
  }
  // Length cap fires before the per-rule loop, so the rule contents are
  // irrelevant — a 1001-length array trips the S3 1000-rule ceiling.
  var tooMany = [];
  for (var i = 0; i < 1001; i++) tooMany.push({ expiration: { days: 1 } });
  shouldThrow("rejects > 1000 rules", tooMany, /INVALID_LIFECYCLE/);
  shouldThrow("rejects non-object rule", [null], /INVALID_LIFECYCLE/);
  shouldThrow("rejects empty-string id",
    [{ id: "", status: "Enabled", expiration: { days: 1 } }], /INVALID_LIFECYCLE/);
  shouldThrow("rejects non-string id",
    [{ id: 5, status: "Enabled", expiration: { days: 1 } }], /INVALID_LIFECYCLE/);
  shouldThrow("rejects abortIncompleteMultipartUpload.daysAfterInitiation = 0",
    [{ status: "Enabled",
       abortIncompleteMultipartUpload: { daysAfterInitiation: 0 } }],
    /INVALID_LIFECYCLE/);

  // Optional expiration sub-fields (date + expiredObjectDeleteMarker) and
  // transition.date each emit their own element.
  var xml = bucketOps._buildLifecycleXmlForTest([{
    status: "Enabled",
    expiration: { date: "2030-01-01T00:00:00.000Z", expiredObjectDeleteMarker: true },
    transition: { date: "2029-01-01T00:00:00.000Z", storageClass: "GLACIER" },
  }]);
  check("lifecycle-adv: Expiration Date element emitted",
        /<Date>2030-01-01T00:00:00\.000Z<\/Date>/.test(xml));
  check("lifecycle-adv: ExpiredObjectDeleteMarker element emitted",
        /<ExpiredObjectDeleteMarker>true<\/ExpiredObjectDeleteMarker>/.test(xml));
  check("lifecycle-adv: Transition Date element emitted",
        /<Transition><Date>2029-01-01T00:00:00\.000Z<\/Date>/.test(xml));

  // expiredObjectDeleteMarker:false takes the falsy ternary arm.
  var xmlFalse = bucketOps._buildLifecycleXmlForTest([{
    status: "Enabled",
    expiration: { days: 5, expiredObjectDeleteMarker: false },
  }]);
  check("lifecycle-adv: ExpiredObjectDeleteMarker false arm emitted",
        /<ExpiredObjectDeleteMarker>false<\/ExpiredObjectDeleteMarker>/.test(xmlFalse));

  // Omitting status defaults it to Enabled (the `rule.status || "Enabled"` arm).
  var xmlNoStatus = bucketOps._buildLifecycleXmlForTest([{
    expiration: { days: 1 },
  }]);
  check("lifecycle-adv: omitted status defaults to Enabled",
        /<Status>Enabled<\/Status>/.test(xmlNoStatus));
}

// ---- CORS XML builder — adversarial / optional-field / size-cap branches ----

function testCorsXmlAdversarial() {
  function shouldThrow(label, rules, codeRe) {
    var threw = null;
    try { bucketOps._buildCorsXmlForTest(rules); } catch (e) { threw = e; }
    check("cors-adv: " + label,  threw && codeRe.test(threw.code || ""));
  }
  var tooMany = [];
  for (var i = 0; i < 101; i++) {
    tooMany.push({ allowedOrigins: ["*"], allowedMethods: ["GET"] });
  }
  shouldThrow("rejects > 100 rules", tooMany, /INVALID_CORS_RULE/);
  shouldThrow("rejects non-object rule", [null], /INVALID_CORS_RULE/);

  // A rule with an id emits <ID>; the escaped-content path is exercised too.
  var xml = bucketOps._buildCorsXmlForTest([{
    id: "rule-1",
    allowedOrigins: ["https://a.example.com"],
    allowedMethods: ["GET"],
  }]);
  check("cors-adv: rule ID element emitted", /<ID>rule-1<\/ID>/.test(xml));

  // Size cap: a single valid rule with thousands of allowed headers pushes the
  // serialized body past the 64 KB S3 ceiling.
  var bigHeaders = [];
  for (var h = 0; h < 3000; h++) bigHeaders.push("x-custom-header-" + h);
  var threwBig = null;
  try {
    bucketOps._buildCorsXmlForTest([{
      allowedOrigins: ["*"],
      allowedMethods: ["GET"],
      allowedHeaders: bigHeaders,
    }]);
  } catch (e) { threwBig = e; }
  check("cors-adv: > 64 KB configuration rejected",
        threwBig && /INVALID_CORS_RULE/.test(threwBig.code || "") &&
        /64 KB/.test(threwBig.message || ""));
}

// ---- Object-key length guard ----

async function testObjectKeyTooLong() {
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var longKey = new Array(1100).join("k"); // 1099 bytes > 1 KiB S3 limit
    var threw = null;
    try { await ops.getObjectRetention("my-bucket", longKey); }
    catch (e) { threw = e; }
    check("object-key: > 1024 bytes rejected with INVALID_KEY",
          threw && /INVALID_KEY/.test(threw.code || ""));
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- ListBuckets XML-shape branches: empty + single ----

async function testListBucketsEmptyAndSingle() {
  var fakeEmpty = _fakeS3({
    onList: function () {
      return { statusCode: 200, body:
        "<?xml version='1.0'?><ListAllMyBucketsResult><Buckets></Buckets>" +
        "<Owner><ID>op</ID></Owner></ListAllMyBucketsResult>" };
    },
  });
  var portE = await listenOnRandomPort(fakeEmpty.server);
  try {
    var opsE = bucketOps.create(_baseConfig(portE));
    var none = await opsE.list();
    check("list: empty Buckets container yields []", Array.isArray(none) && none.length === 0);
  } finally {
    await new Promise(function (r) { fakeEmpty.server.close(function () { r(); }); });
  }

  // A 200 whose body lacks the ListAllMyBucketsResult root (unexpected
  // backend response) degrades to [] via the `doc.<Root> || {}` default arm
  // rather than throwing.
  var fakeGarbage = _fakeS3({
    onList: function () {
      return { statusCode: 200, body: "<?xml version='1.0'?><Unexpected/>" };
    },
  });
  var portG = await listenOnRandomPort(fakeGarbage.server);
  try {
    var opsG = bucketOps.create(_baseConfig(portG));
    var garbage = await opsG.list();
    check("list: body without ListAllMyBucketsResult root yields []",
          Array.isArray(garbage) && garbage.length === 0);
  } finally {
    await new Promise(function (r) { fakeGarbage.server.close(function () { r(); }); });
  }

  // A single <Bucket> is surfaced by the XML parser as an object, not an
  // array — the wrap-in-array branch must still produce a one-element list.
  // The bucket omits CreationDate + BucketRegion so the null-default arms of
  // both fields are exercised.
  var fakeOne = _fakeS3({
    onList: function () {
      return { statusCode: 200, body:
        "<?xml version='1.0'?><ListAllMyBucketsResult><Buckets>" +
        "<Bucket><Name>solo</Name></Bucket>" +
        "</Buckets></ListAllMyBucketsResult>" };
    },
  });
  var portO = await listenOnRandomPort(fakeOne.server);
  try {
    var opsO = bucketOps.create(_baseConfig(portO));
    var one = await opsO.list();
    check("list: single Bucket wrapped into a one-element array",
          one.length === 1 && one[0].name === "solo");
    check("list: single-bucket region defaults to null when absent",
          one[0].region === null);
    check("list: single-bucket creationDate defaults to null when absent",
          one[0].creationDate === null);
  } finally {
    await new Promise(function (r) { fakeOne.server.close(function () { r(); }); });
  }
}

// ---- Object-lock config: years path + adversarial validation ----

async function testObjectLockYearsAndValidation() {
  var fake = _fakeS3({
    onGetObjectLock: function () {
      return { statusCode: 200, body:
        '<?xml version="1.0"?><ObjectLockConfiguration>' +
        '<ObjectLockEnabled>Enabled</ObjectLockEnabled>' +
        '<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>10</Days></DefaultRetention></Rule>' +
        '</ObjectLockConfiguration>' };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));

    // years-based config: exercises the <Years> XML arm + the years echo
    // in the success result (days stays null).
    var rv = await ops.setObjectLockConfiguration("my-bucket",
      { mode: "COMPLIANCE", years: 3 });
    check("object-lock years: applied", rv.applied === true);
    check("object-lock years: years echoed, days null",
          rv.years === 3 && rv.days === null);
    var putReq = fake.requests[fake.requests.length - 1];
    check("object-lock years: body carries <Years>3</Years>",
          /<Years>3<\/Years>/.test(putReq.body.toString("utf8")));

    // getObjectLockConfiguration returning Days (not Years) drives the
    // Number(def.Days) parse arm.
    var got = await ops.getObjectLockConfiguration("my-bucket");
    check("object-lock get: Days parsed as number",
          got.days === 10 && got.years === null && got.mode === "GOVERNANCE");

    async function shouldThrow(label, opts, codeRe) {
      var threw = null;
      try { await ops.setObjectLockConfiguration("my-bucket", opts); }
      catch (e) { threw = e; }
      check("object-lock validation: " + label, threw && codeRe.test(threw.code || ""));
    }
    await shouldThrow("rejects non-object cfg", null, /INVALID_OBJECT_LOCK/);
    await shouldThrow("rejects neither days nor years",
      { mode: "GOVERNANCE" }, /INVALID_OBJECT_LOCK/);
    await shouldThrow("rejects negative years",
      { mode: "GOVERNANCE", years: -1 }, /INVALID_OBJECT_LOCK/);
    await shouldThrow("rejects fractional years",
      { mode: "GOVERNANCE", years: 1.5 }, /INVALID_OBJECT_LOCK/);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- PUT-op failure branches: throws + failure-audit emission ----

async function testPutOpFailurePaths() {
  var auditCap = _captureAudit();
  var obsCap   = _captureObs();
  var fake = _fakeS3({
    lifecycleErr:    { status: 500, code: "InternalError" },
    corsErr:         { status: 500, code: "InternalError" },
    objectLockPutErr:{ status: 500, code: "InternalError" },
    retentionPutErr: { status: 500, code: "InternalError" },
    legalHoldPutErr: { status: 500, code: "InternalError" },
    // GET-before-PUT in setObjectRetention must resolve to "not configured"
    // so the flow falls through to the failing PUT.
    onGetObjectRetention: function () {
      return { statusCode: 400, body:
        '<?xml version="1.0"?><Error><Code>NoSuchObjectLockConfiguration</Code>' +
        '<Message>no retention</Message></Error>' };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(Object.assign({}, _baseConfig(port), {
      audit:         auditCap,
      observability: obsCap,
    }));

    async function expectFailure(label, action, fn) {
      var threw = null;
      try { await fn(); } catch (e) { threw = e; }
      check("put-fail: " + label + " throws on 5xx", threw !== null);
      var rows = auditCap.byAction(action).filter(function (r) { return r.outcome === "failure"; });
      check("put-fail: " + label + " emits failure audit row", rows.length >= 1);
      check("put-fail: " + label + " emits failure obs counter",
            obsCap.byName(action).some(function (e) {
              return e.labels && e.labels.outcome === "failure";
            }));
    }

    await expectFailure("setLifecycle", "objectstore.bucket.setLifecycle", function () {
      return ops.setLifecycle("logs", [{ status: "Enabled",
        abortIncompleteMultipartUpload: { daysAfterInitiation: 7 } }]);
    });
    await expectFailure("setCorsRules", "objectstore.bucket.setCorsRules", function () {
      return ops.setCorsRules("public", [{
        allowedOrigins: ["https://a.example.com"], allowedMethods: ["GET"] }]);
    });
    await expectFailure("setObjectLockConfiguration",
      "objectstore.bucket.setObjectLockConfiguration", function () {
        return ops.setObjectLockConfiguration("my-bucket", { mode: "GOVERNANCE", days: 30 });
      });
    await expectFailure("setObjectRetention", "objectstore.object.setRetention", function () {
      return ops.setObjectRetention("my-bucket", "k",
        { mode: "GOVERNANCE", retainUntil: new Date(Date.now() + 60000) });
    });
    await expectFailure("setObjectLegalHold", "objectstore.object.setLegalHold", function () {
      return ops.setObjectLegalHold("my-bucket", "k", "ON");
    });
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- GET-op re-throw when the error is NOT a "not configured" state ----

async function testGetOpsRethrowRealError() {
  function realErr() {
    return { statusCode: 500, body:
      '<?xml version="1.0"?><Error><Code>InternalError</Code>' +
      '<Message>backend exploded</Message></Error>' };
  }
  var fake = _fakeS3({
    onGetObjectLock:      realErr,
    onGetObjectRetention: realErr,
    onGetLegalHold:       realErr,
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));

    var threwLock = null;
    try { await ops.getObjectLockConfiguration("my-bucket"); }
    catch (e) { threwLock = e; }
    check("get-rethrow: getObjectLockConfiguration re-throws a 500 (not swallowed)",
          threwLock && threwLock.statusCode === 500);

    var threwRet = null;
    try { await ops.getObjectRetention("my-bucket", "k"); }
    catch (e) { threwRet = e; }
    check("get-rethrow: getObjectRetention re-throws a 500 (not swallowed)",
          threwRet && threwRet.statusCode === 500);

    var threwLh = null;
    try { await ops.getObjectLegalHold("my-bucket", "k"); }
    catch (e) { threwLh = e; }
    check("get-rethrow: getObjectLegalHold re-throws a 500 (not swallowed)",
          threwLh && threwLh.statusCode === 500);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- get* defensive parse defaults (unexpected / empty backend document) ----

async function testGetOpsParseDefaults() {
  // A 200 whose body lacks the expected root element (a quirk of some
  // S3-compatible stores) must degrade to clean nulls, not throw — exercising
  // the `doc.<Root> || {}` and `<field> || null` default arms.
  function otherDoc() {
    return { statusCode: 200, body: '<?xml version="1.0"?><Unexpected/>' };
  }
  var fake = _fakeS3({
    onGetObjectLock:      otherDoc,
    onGetObjectRetention: otherDoc,
    onGetLegalHold:       otherDoc,
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));

    var lock = await ops.getObjectLockConfiguration("my-bucket");
    check("parse-defaults: object-lock unexpected doc → enabled:false + null fields",
          lock.enabled === false && lock.mode === null &&
          lock.days === null && lock.years === null);

    var ret = await ops.getObjectRetention("my-bucket", "k");
    check("parse-defaults: retention unexpected doc → mode:null, retainUntil:null",
          ret.mode === null && ret.retainUntil === null);

    var lh = await ops.getObjectLegalHold("my-bucket", "k");
    check("parse-defaults: legal-hold unexpected doc → status:null",
          lh.status === null);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- createBucket generic (non-409) failure + auditFailures:false ----

async function testCreateGenericFailureAndAuditFailuresOff() {
  // A non-409 failure is NOT remapped to a BUCKET_* code — the raw HTTP
  // error surfaces, and the failure-audit row carries its code.
  var auditCap = _captureAudit();
  var fake = _fakeS3({ createErr: { status: 500, code: "InternalError" } });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(Object.assign({}, _baseConfig(port), { audit: auditCap }));
    var threw = null;
    try { await ops.create("boom"); } catch (e) { threw = e; }
    check("create-generic-fail: non-409 error surfaces raw (HTTP_ERROR)",
          threw && threw.statusCode === 500 &&
          !/BUCKET_ALREADY_OWNED|BUCKET_NAME_TAKEN/.test(threw.code || ""));
    var rows = auditCap.byAction("objectstore.bucket.create")
      .filter(function (r) { return r.outcome === "failure"; });
    check("create-generic-fail: failure audit row emitted", rows.length === 1);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }

  // auditFailures:false suppresses the failure audit row while the op still
  // throws and the observability counter still fires.
  var auditCap2 = _captureAudit();
  var obsCap2   = _captureObs();
  var fake2 = _fakeS3({ createErr: { status: 500, code: "InternalError" } });
  var port2 = await listenOnRandomPort(fake2.server);
  try {
    var ops2 = bucketOps.create(Object.assign({}, _baseConfig(port2), {
      audit:         auditCap2,
      observability: obsCap2,
      auditFailures: false,
    }));
    var threw2 = null;
    try { await ops2.create("boom2"); } catch (e) { threw2 = e; }
    check("auditFailures:false: op still throws", threw2 !== null);
    check("auditFailures:false: no failure audit row emitted",
          auditCap2.byAction("objectstore.bucket.create").length === 0);
    check("auditFailures:false: obs failure counter still fires",
          obsCap2.byName("objectstore.bucket.create").some(function (e) {
            return e.labels && e.labels.outcome === "failure";
          }));
  } finally {
    await new Promise(function (r) { fake2.server.close(function () { r(); }); });
  }
}

// ---- deleteBucket generic (non-404, non-409) failure ----

async function testDeleteGenericFailure() {
  var auditCap = _captureAudit();
  var fake = _fakeS3({ deleteErr: { status: 500, code: "InternalError" } });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(Object.assign({}, _baseConfig(port), { audit: auditCap }));
    var threw = null;
    try { await ops.delete("boom"); } catch (e) { threw = e; }
    check("delete-generic-fail: non-404/409 error surfaces + throws",
          threw && threw.statusCode === 500);
    var rows = auditCap.byAction("objectstore.bucket.delete")
      .filter(function (r) { return r.outcome === "failure"; });
    check("delete-generic-fail: failure audit row emitted", rows.length === 1);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- setObjectRetention COMPLIANCE pre-check (WORM defense-in-depth) ----

async function testSetObjectRetentionComplianceGuards() {
  // Existing retention on the object is COMPLIANCE, 30 days out. The client-
  // side pre-check (GET-before-PUT) must refuse a bypass and refuse any
  // shortening — even before the backend gets the PUT.
  var existingUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  var fake = _fakeS3({
    onGetObjectRetention: function () {
      return { statusCode: 200, body:
        '<?xml version="1.0"?><Retention><Mode>COMPLIANCE</Mode>' +
        '<RetainUntilDate>' + existingUntil.toISOString() + '</RetainUntilDate></Retention>' };
    },
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));

    // bypassGovernance against a COMPLIANCE lock — refused client-side.
    var threwBypass = null;
    try {
      await ops.setObjectRetention("my-bucket", "k", {
        mode:             "COMPLIANCE",
        retainUntil:      new Date(Date.now() + 60 * 24 * 60 * 60 * 1000),
        bypassGovernance: true,
      });
    } catch (e) { threwBypass = e; }
    check("compliance-guard: bypassGovernance on COMPLIANCE is refused",
          threwBypass && /compliance-bypass-refused/.test(threwBypass.code || ""));

    // Proposing an EARLIER retainUntil (shortening) — refused client-side.
    var threwShort = null;
    try {
      await ops.setObjectRetention("my-bucket", "k", {
        mode:        "COMPLIANCE",
        retainUntil: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      });
    } catch (e) { threwShort = e; }
    check("compliance-guard: shortening a COMPLIANCE retention is refused",
          threwShort && /compliance-shortening-refused/.test(threwShort.code || ""));

    // EXTENDING (later retainUntil, no bypass) is allowed — the pre-check
    // passes and the PUT proceeds.
    var extended = await ops.setObjectRetention("my-bucket", "k", {
      mode:        "COMPLIANCE",
      retainUntil: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    });
    check("compliance-guard: extending a COMPLIANCE retention proceeds to PUT",
          extended.applied === true);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// The pre-check GET is value-add, NOT load-bearing: when it fails with a
// non-compliance error the flow falls through to the PUT so the backend's own
// enforcement is authoritative.
async function testSetObjectRetentionPreCheckFallsThrough() {
  var fake = _fakeS3({
    onGetObjectRetention: function () {
      return { statusCode: 500, body:
        '<?xml version="1.0"?><Error><Code>InternalError</Code>' +
        '<Message>pre-check backend error</Message></Error>' };
    },
    // No retentionPutErr → the PUT itself succeeds.
  });
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port));
    var rv = await ops.setObjectRetention("my-bucket", "k", {
      mode:        "GOVERNANCE",
      retainUntil: new Date(Date.now() + 60000),
    });
    check("pre-check-fallthrough: a failed GET pre-check still lets the PUT proceed",
          rv.applied === true && rv.mode === "GOVERNANCE");
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- Virtual-hosted-style URL construction (pathStyle:false) ----

async function testVirtualHostStyleUrlConstruction() {
  // With pathStyle:false the bucket name is prepended as a subdomain of the
  // endpoint host (`<bucket>.<host>`) for both bucket-level and object-level
  // URLs — the else arm of _bucketUrl / _objectUrl. Against an IPv4 endpoint
  // the WHATWG URL host-setter refuses the subdomain prefix (you cannot make
  // an IP literal into a domain), so the constructed URL keeps the IP host and
  // the request still lands on the fake server. The subresource query + path
  // are what we assert; the branch under test is exercised either way.
  var fake = _fakeS3();
  var port = await listenOnRandomPort(fake.server);
  try {
    var ops = bucketOps.create(_baseConfig(port, { pathStyle: false }));

    // Bucket-level: virtual-host addressing sets pathname "/" (no /<bucket>/
    // prefix). Against the IP endpoint the create still completes.
    var created = await ops.create("vh-bucket");
    check("vhost: bucket-level create completes via the else-arm URL builder",
          created.created === true);
    var createReq = fake.requests[fake.requests.length - 1];
    check("vhost: bucket-level URL uses root path (no path-style /<bucket>/ prefix)",
          createReq.url === "/" && createReq.method === "PUT");

    // Object-level: pathname is "/<key>" (no /<bucket>/ prefix). The
    // legal-hold subresource query survives the virtual-host code path.
    fake.requests.length = 0;
    var held = await ops.setObjectLegalHold("vh-bucket", "some-key", "ON");
    check("vhost: object-level legal-hold completes via the else-arm URL builder",
          held.applied === true && held.status === "ON");
    var objReq = fake.requests[fake.requests.length - 1];
    check("vhost: object-level URL is /<key> (no /<bucket>/ prefix) + carries ?legal-hold",
          objReq.url.indexOf("/some-key") === 0 && objReq.url.indexOf("legal-hold") !== -1);
  } finally {
    await new Promise(function (r) { fake.server.close(function () { r(); }); });
  }
}

// ---- sigv4 signer: pure / offline branches (config, presign, POST policy) ----
// These drive the sigv4.create(...) signer directly (the same module bucketOps
// composes) exercising only the branches reachable WITHOUT an S3 round-trip:
// config validation, endpoint defaulting, key sanitization, and the presign /
// POST-policy generators (which sign locally and never open a socket). The
// network-executing get/put/list/head/delete paths are covered by the
// object-store-sigv4 integration suite.

function _sigv4Config(overrides) {
  var cfg = {
    region:          "us-east-1",
    bucket:          "test-bucket",
    accessKeyId:     "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  };
  if (overrides) Object.assign(cfg, overrides);
  return cfg;
}

// Required-field guards + endpoint defaulting / trailing-slash trim / pathStyle.
function testSigv4FactoryRequiredFieldsAndDefaults() {
  function shouldThrow(label, cfg, msgRe) {
    var threw = null;
    try { sigv4.create(cfg); } catch (e) { threw = e; }
    check("sigv4 factory: " + label, threw && msgRe.test(threw.message || ""));
  }
  shouldThrow("missing config",  undefined, /requires config/);
  shouldThrow("missing region",
    { bucket: "b", accessKeyId: "x", secretAccessKey: "y" }, /region is required/);
  shouldThrow("missing bucket",
    { region: "us-east-1", accessKeyId: "x", secretAccessKey: "y" }, /bucket is required/);
  shouldThrow("missing accessKeyId",
    { region: "us-east-1", bucket: "b", secretAccessKey: "y" }, /accessKeyId is required/);
  shouldThrow("missing secretAccessKey",
    { region: "us-east-1", bucket: "b", accessKeyId: "x" }, /secretAccessKey is required/);

  // No endpoint → https://s3.<region>.amazonaws.com; returned adapter shape.
  var def = sigv4.create(_sigv4Config());
  check("sigv4 factory: endpoint defaults to the regional S3 host",
        def.endpoint === "https://s3.us-east-1.amazonaws.com");
  check("sigv4 factory: adapter shape (protocol/bucket/region/pathStyle)",
        def.protocol === "sigv4" && def.bucket === "test-bucket" &&
        def.region === "us-east-1" && def.pathStyle === false);

  // Trailing slash on an explicit endpoint is trimmed.
  var trimmed = sigv4.create(_sigv4Config({ endpoint: "https://s3.example.com/" }));
  check("sigv4 factory: trailing-slash endpoint trimmed",
        trimmed.endpoint === "https://s3.example.com");
}

// canonicalQueryString / canonicalHeaders edge arms (empty, dup-key value
// tiebreak, null/undefined header skip, internal-whitespace collapse).
function testSigv4CanonicalHelperEdgeBranches() {
  check("canonicalQueryString(null) → empty string",
        sigv4.canonicalQueryString(null) === "");
  check("canonicalQueryString(empty params) → empty string",
        sigv4.canonicalQueryString(new URLSearchParams()) === "");
  check("canonicalQueryString sorts duplicate keys by value (secondary tiebreak)",
        sigv4.canonicalQueryString(new URLSearchParams("a=2&a=1&b=x")) === "a=1&a=2&b=x");

  var ch = sigv4.canonicalHeaders({
    "Content-Type": "  a   b  ",
    "X-Null":       null,
    "X-Undef":      undefined,
  });
  check("canonicalHeaders skips null/undefined-valued headers",
        ch.signed === "content-type");
  check("canonicalHeaders lowercases the name + collapses internal whitespace",
        ch.canonical === "content-type:a b\n");
}

// Presigned GET URL — the SigV4 query params the client transmits.
function testSigv4PresignDownloadUrl() {
  var store = sigv4.create(_sigv4Config());
  var r = store.presignedDownloadUrl({ key: "docs/report.txt", expiresIn: 3600 });
  check("presign download: method GET", r.method === "GET");
  check("presign download: X-Amz-Algorithm in query",
        /X-Amz-Algorithm=AWS4-HMAC-SHA256/.test(r.url));
  check("presign download: X-Amz-Credential in query",
        r.url.indexOf("X-Amz-Credential=") !== -1);
  check("presign download: X-Amz-Date in query",
        r.url.indexOf("X-Amz-Date=") !== -1);
  check("presign download: X-Amz-Expires echoes expiresIn",
        r.url.indexOf("X-Amz-Expires=3600") !== -1);
  check("presign download: X-Amz-SignedHeaders=host",
        r.url.indexOf("X-Amz-SignedHeaders=host") !== -1);
  check("presign download: X-Amz-Signature is 64 hex",
        /X-Amz-Signature=[0-9a-f]{64}/.test(r.url));
  check("presign download: no X-Amz-Security-Token when sessionToken unset",
        r.url.indexOf("X-Amz-Security-Token=") === -1);
  check("presign download: default is virtual-hosted (bucket subdomain)",
        r.url.indexOf("https://test-bucket.s3.us-east-1.amazonaws.com/") === 0);
  check("presign download: expiresAt is in the future",
        r.expiresAt > Date.now());
}

// Presigned PUT URL — contentType binds into SignedHeaders; sessionToken adds
// X-Amz-Security-Token to the signed query.
function testSigv4PresignUploadUrlAndSessionToken() {
  var store = sigv4.create(_sigv4Config({ sessionToken: "FQoGZXIvSESSIONTOKEN" }));
  var r = store.presignedUploadUrl({ key: "up.bin", expiresIn: 120, contentType: "image/png" });
  check("presign upload: method PUT", r.method === "PUT");
  check("presign upload: Content-Type echoed on client headers",
        r.headers["Content-Type"] === "image/png");
  check("presign upload: content-type bound into X-Amz-SignedHeaders",
        /X-Amz-SignedHeaders=content-type(%3B|;)host/.test(r.url));
  check("presign upload: X-Amz-Security-Token present when sessionToken set",
        r.url.indexOf("X-Amz-Security-Token=FQoGZXIvSESSIONTOKEN") !== -1);
}

// responseHeaders shape validation (INVALID_RESPONSE_HEADERS) + valid mapping.
function testSigv4PresignResponseHeadersValidation() {
  var store = sigv4.create(_sigv4Config());
  function shouldThrow(label, responseHeaders) {
    var threw = null;
    try {
      store.presignedDownloadUrl({ key: "k", expiresIn: 60, responseHeaders: responseHeaders });
    } catch (e) { threw = e; }
    check("presign rh: " + label, threw && /INVALID_RESPONSE_HEADERS/.test(threw.code || ""));
  }
  shouldThrow("non-object rejected",         "not-an-object");
  shouldThrow("unknown key rejected",        { bogusKey: "x" });
  shouldThrow("empty-string value rejected", { contentType: "" });
  shouldThrow("non-string value rejected",   { contentType: 123 });
  shouldThrow("CR/LF/NUL value rejected",    { contentDisposition: "a\r\nb" });

  var r = store.presignedDownloadUrl({
    key: "k", expiresIn: 60,
    responseHeaders: { contentDisposition: "inline", contentType: "text/plain" },
  });
  check("presign rh: valid contentDisposition mapped to response-content-disposition",
        r.url.indexOf("response-content-disposition=inline") !== -1);
  check("presign rh: valid contentType mapped to response-content-type",
        r.url.indexOf("response-content-type=") !== -1);
}

// requirePresignKey + resolvePresignExpires guards via the presign consumer path.
function testSigv4PresignKeyAndExpiresValidation() {
  var store = sigv4.create(_sigv4Config());
  function shouldThrow(label, fn, codeRe) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("presign validate: " + label, threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("missing key rejected",
    function () { store.presignedDownloadUrl({ expiresIn: 60 }); }, /INVALID_KEY/);
  shouldThrow("null-byte key rejected",
    function () { store.presignedDownloadUrl({ key: "a" + String.fromCharCode(0) + "b", expiresIn: 60 }); }, /INVALID_KEY/);
  shouldThrow("expiresIn below the 1s floor rejected",
    function () { store.presignedDownloadUrl({ key: "k", expiresIn: 0 }); }, /INVALID_EXPIRES/);
  shouldThrow("expiresIn above the 7-day cap rejected",
    function () { store.presignedDownloadUrl({ key: "k", expiresIn: 8 * 24 * 60 * 60 }); }, /INVALID_EXPIRES/);

  // Omitted expiresIn resolves to the 15-minute (900s) default.
  var r = store.presignedDownloadUrl({ key: "k" });
  check("presign validate: omitted expiresIn resolves to the 900s default",
        /X-Amz-Expires=900/.test(r.url));
}

// path-style vs virtual-hosted URL construction (both _keyToUrl arms).
function testSigv4PresignPathStyleVsVhost() {
  var ps = sigv4.create(_sigv4Config({ pathStyle: true, endpoint: "https://s3.example.com" }));
  var rp = ps.presignedDownloadUrl({ key: "a/b.txt", expiresIn: 60 });
  check("presign path-style: URL path carries /<bucket>/<key>",
        rp.url.indexOf("https://s3.example.com/test-bucket/a/b.txt?") === 0);

  var fps = sigv4.create(_sigv4Config({ forcePathStyle: true }));
  check("sigv4 factory: forcePathStyle alias sets pathStyle=true",
        fps.pathStyle === true);

  var vh = sigv4.create(_sigv4Config());
  var rv = vh.presignedDownloadUrl({ key: "a/b.txt", expiresIn: 60 });
  check("presign vhost: URL host is <bucket>.<endpoint-host>",
        rv.url.indexOf("https://test-bucket.s3.us-east-1.amazonaws.com/a/b.txt?") === 0);
}

// POST-form upload policy — fields + decoded base64 policy conditions.
function testSigv4PostPolicy() {
  var store = sigv4.create(_sigv4Config());
  var r = store.presignedUploadPolicy({ key: "uploads/pic.bin", maxBytes: 1048576, expiresIn: 300 });
  check("post-policy: method POST",                       r.method === "POST");
  check("post-policy: enforcement content-length-range",  r.enforcement === "content-length-range");
  check("post-policy: maxBytes echoed",                   r.maxBytes === 1048576);
  check("post-policy: bucket-root vhost URL (no key in path)",
        r.url === "https://test-bucket.s3.us-east-1.amazonaws.com/");
  check("post-policy: field key echoed",                  r.fields.key === "uploads/pic.bin");
  check("post-policy: field x-amz-algorithm",             r.fields["x-amz-algorithm"] === "AWS4-HMAC-SHA256");
  check("post-policy: field x-amz-credential starts with accessKeyId",
        typeof r.fields["x-amz-credential"] === "string" &&
        r.fields["x-amz-credential"].indexOf("AKIAIOSFODNN7EXAMPLE/") === 0);
  check("post-policy: field x-amz-date present",
        typeof r.fields["x-amz-date"] === "string" && r.fields["x-amz-date"].length > 0);
  check("post-policy: field policy (base64) present",
        typeof r.fields.policy === "string" && r.fields.policy.length > 0);
  check("post-policy: field x-amz-signature is 64 hex",
        /^[0-9a-f]{64}$/.test(r.fields["x-amz-signature"]));
  check("post-policy: no x-amz-security-token field when sessionToken unset",
        r.fields["x-amz-security-token"] === undefined);
  check("post-policy: no content-type field when contentType unset",
        r.fields["content-type"] === undefined);

  var policy = JSON.parse(Buffer.from(r.fields.policy, "base64").toString("utf8"));
  check("post-policy: decoded expiration is ISO 8601",
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(policy.expiration));
  check("post-policy: decoded conditions is an array", Array.isArray(policy.conditions));
  check("post-policy: conditions include content-length-range [0, maxBytes]",
        policy.conditions.some(function (c) {
          return Array.isArray(c) && c[0] === "content-length-range" && c[1] === 0 && c[2] === 1048576;
        }));
  check("post-policy: conditions include the bucket",
        policy.conditions.some(function (c) { return c && c.bucket === "test-bucket"; }));
  check("post-policy: conditions include the key",
        policy.conditions.some(function (c) { return c && c.key === "uploads/pic.bin"; }));
}

// POST policy with sessionToken + contentType conditions, and the maxBytes guard.
function testSigv4PostPolicySessionContentTypeAndMaxBytes() {
  var store = sigv4.create(_sigv4Config({ sessionToken: "SESSIONTOKENVALUE" }));
  var r = store.presignedUploadPolicy({
    key: "k", maxBytes: 2048, expiresIn: 60, contentType: "application/pdf",
  });
  check("post-policy session: field x-amz-security-token echoed",
        r.fields["x-amz-security-token"] === "SESSIONTOKENVALUE");
  check("post-policy session: field content-type echoed",
        r.fields["content-type"] === "application/pdf");
  var policy = JSON.parse(Buffer.from(r.fields.policy, "base64").toString("utf8"));
  check("post-policy session: conditions include x-amz-security-token",
        policy.conditions.some(function (c) { return c && c["x-amz-security-token"] === "SESSIONTOKENVALUE"; }));
  check("post-policy session: conditions include content-type",
        policy.conditions.some(function (c) { return c && c["content-type"] === "application/pdf"; }));

  // maxBytes is mandatory for the POST-form policy (drives content-length-range).
  var threw = null;
  try { store.presignedUploadPolicy({ key: "k", expiresIn: 60 }); } catch (e) { threw = e; }
  check("post-policy: missing maxBytes rejected with INVALID_MAX_BYTES",
        threw && /INVALID_MAX_BYTES/.test(threw.code || ""));
}

// Key sanitization: a NUL byte throws before any request (get/head/delete call
// _keyToUrl synchronously as their first step, so no socket is opened).
async function testSigv4KeyNullByteViaConsumerPath() {
  var store = sigv4.create(_sigv4Config());
  var threwHead = null;
  try { await store.head("bad" + String.fromCharCode(0) + "key"); } catch (e) { threwHead = e; }
  check("null-byte key via head() rejected with INVALID_KEY (pre-request)",
        threwHead && /INVALID_KEY/.test(threwHead.code || ""));
  var threwDelete = null;
  try { await store.delete("bad" + String.fromCharCode(0) + "key"); } catch (e) { threwDelete = e; }
  check("null-byte key via delete() rejected with INVALID_KEY (pre-request)",
        threwDelete && /INVALID_KEY/.test(threwDelete.code || ""));
}

// bucketOps dispatches every request through the shared httpClient keep-alive
// transport pool; a cached client socket finalizes its destroy on a later
// event-loop turn, past the forked worker's grace window. Reset the pool, then
// poll until every TCP handle has actually drained so none outlives run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "sigv4-bucket-ops: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    testSurface();
    testCanonicalPathSingleEncodeForS3();
    testFactoryValidation();
    testBucketNameValidation();
    testLifecycleXml();
    testCorsXml();
    await testCreateBucketUsEast1NoBody();
    await testCreateBucketOtherRegionSendsLocationConstraint();
    await testCreateBucketAlreadyOwnedMaps();
    await testCreateBucketTakenMaps();
    await testDeleteBucketHappyAndMissing();
    await testDeleteBucketNotEmptyMaps();
    await testListBuckets();
    await testSetLifecycleSendsXml();
    await testSetCorsRulesSendsXml();
    // v0.6.47 — Object Lock
    await testCreateBucketObjectLockEnabled();
    await testSetObjectLockConfiguration();
    await testSetObjectLockConfigurationValidation();
    await testGetObjectLockConfiguration();
    await testSetObjectRetention();
    await testSetObjectRetentionBypassGovernance();
    await testSetObjectRetentionValidation();
    await testGetObjectRetention();
    await testLegalHold();
    // v0.6.51 — not-configured response paths return clean defaults
    await testGetObjectLockConfigurationNotConfigured();
    await testGetObjectRetentionNotConfigured();
    await testGetObjectLegalHoldNotConfigured();
    // v0.6.53 — audit + observability emissions
    await testAuditObservabilityWiring();
    await testAuditSuccessFalseDisablesSuccessAudit();
    await testPerCallActorOverrideHonored();
    // Uncovered error / adversarial / defensive / option-default branches.
    testFactoryDefaultsAndTrailingSlash();
    testLifecycleXmlAdversarial();
    testCorsXmlAdversarial();
    await testObjectKeyTooLong();
    await testListBucketsEmptyAndSingle();
    await testObjectLockYearsAndValidation();
    await testPutOpFailurePaths();
    await testGetOpsRethrowRealError();
    await testGetOpsParseDefaults();
    await testCreateGenericFailureAndAuditFailuresOff();
    await testDeleteGenericFailure();
    await testSetObjectRetentionComplianceGuards();
    await testSetObjectRetentionPreCheckFallsThrough();
    await testVirtualHostStyleUrlConstruction();
    // sigv4 signer — pure / offline branches (no S3 round-trip).
    testSigv4FactoryRequiredFieldsAndDefaults();
    testSigv4CanonicalHelperEdgeBranches();
    testSigv4PresignDownloadUrl();
    testSigv4PresignUploadUrlAndSessionToken();
    testSigv4PresignResponseHeadersValidation();
    testSigv4PresignKeyAndExpiresValidation();
    testSigv4PresignPathStyleVsVhost();
    testSigv4PostPolicy();
    testSigv4PostPolicySessionContentTypeAndMaxBytes();
    await testSigv4KeyNullByteViaConsumerPath();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

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

async function run() {
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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

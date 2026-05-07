"use strict";
/**
 * gcs-bucket-ops — bucket-level operations.
 *
 * Layer-0 mock-based tests: HTTP mock server records request shape;
 * auth comes from a fake service-account JSON (RSA-2048 keypair
 * generated per test) so the JWT signing path is exercised even
 * though the mock token endpoint just returns a stub access_token.
 */
var http = require("node:http");
var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var bucketOps = require("../../lib/object-store/gcs-bucket-ops");

function _fakeServiceAccount() {
  var pair = nodeCrypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    type:           "service_account",
    project_id:     "blamejs-test-project",
    client_email:   "test-sa@blamejs-test-project.iam.gserviceaccount.com",
    private_key:    pair.privateKey,
    private_key_id: "test-key-id-001",
  };
}

function listenOnRandomPort(handler) {
  return new Promise(function (resolve) {
    var requests = [];
    var server = http.createServer(function (req, res) {
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        var body = Buffer.concat(chunks);
        var entry = {
          method:  req.method,
          url:     req.url,
          headers: req.headers,
          body:    body,
        };
        requests.push(entry);
        handler(entry, res);
      });
    });
    server.listen(0, "127.0.0.1", function () {
      resolve({
        port:     server.address().port,
        server:   server,
        requests: requests,
        close:    function () { return new Promise(function (r) { server.close(r); }); },
      });
    });
  });
}

// One mock server handles BOTH the storage API and the token endpoint
// — the bucket-ops factory is configured to point both at the same URL
// (storage path prefixed with /storage/v1/b, token at /token).
function _mockServer(routes) {
  return listenOnRandomPort(function (entry, res) {
    res.setHeader("Content-Type", "application/json");
    if (entry.url === "/token" || /\/token\?/.test(entry.url)) {
      res.statusCode = 200;
      res.end(JSON.stringify({ access_token: "fake-access-token", expires_in: 3600 }));
      return;
    }
    var route = routes(entry);
    res.statusCode = route.status || 200;
    res.end(typeof route.body === "string" ? route.body : JSON.stringify(route.body || {}));
  });
}

function _baseConfig(port, sa) {
  return {
    serviceAccount:   sa,
    projectId:        sa.project_id,
    endpoint:         "http://127.0.0.1:" + port,
    tokenEndpoint:    "http://127.0.0.1:" + port + "/token",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    timeoutMs:        5000,
  };
}

async function testSurface() {
  var sa = _fakeServiceAccount();
  var l = await _mockServer(function () { return { status: 200 }; });
  try {
    var ops = bucketOps.create(_baseConfig(l.port, sa));
    check("ops.protocol === 'gcs'",          ops.protocol === "gcs");
    check("ops.create is fn",                typeof ops.create === "function");
    check("ops.delete is fn",                typeof ops.delete === "function");
    check("ops.list is fn",                  typeof ops.list === "function");
    check("ops.setLifecycle is fn",          typeof ops.setLifecycle === "function");
    check("ops.setCorsRules is fn",          typeof ops.setCorsRules === "function");
  } finally { await l.close(); }
}

async function testFactoryValidation() {
  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { bucketOps.create(opts); } catch (e) { threw = e; }
    check("factory: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects null opts",                 null, /BAD_OPT/);
  shouldThrow("rejects missing serviceAccount",    {}, /BAD_OPT/);
  shouldThrow("rejects partial serviceAccount",
    { serviceAccount: { client_email: "x" } }, /BAD_OPT/);

  var sa = _fakeServiceAccount();
  delete sa.project_id;
  shouldThrow("rejects missing projectId when SA has no project_id",
    { serviceAccount: sa }, /BAD_OPT/);
}

async function testBucketNameValidation() {
  var sa = _fakeServiceAccount();
  var l = await _mockServer(function () { return { status: 200 }; });
  try {
    var ops = bucketOps.create(_baseConfig(l.port, sa));
    async function shouldRejectName(label, name) {
      var threw = null;
      try { await ops.create(name); } catch (e) { threw = e; }
      check("rejects " + label, threw && /BUCKET_INVALID_NAME/.test(threw.code || ""));
    }
    await shouldRejectName("UPPERCASE",       "MyBucket");
    await shouldRejectName("too short",       "ab");
    await shouldRejectName("starts with dot", ".abc");
    await shouldRejectName("consecutive dots", "a..b");
    await shouldRejectName("starts with goog", "goog123");
    await shouldRejectName("starts with dash", "-abc");
  } finally { await l.close(); }
}

async function testCreateBucketWireShape() {
  var sa = _fakeServiceAccount();
  var l = await _mockServer(function (entry) {
    if (/\/storage\/v1\/b/.test(entry.url) && entry.method === "POST") {
      return { status: 200, body: { name: "my-bucket", location: "US", storageClass: "STANDARD" } };
    }
    return { status: 404 };
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port, sa));
    var rv = await ops.create("my-bucket", { location: "US", storageClass: "STANDARD" });
    check("create returns bucket name",  rv.name === "my-bucket");
    check("create returns location",     rv.location === "US");
    check("create returns storageClass", rv.storageClass === "STANDARD");
    var creates = l.requests.filter(function (r) {
      return r.method === "POST" && /\/storage\/v1\/b/.test(r.url);
    });
    check("POST issued to /storage/v1/b",        creates.length === 1);
    check("URL has project= param",              /project=blamejs-test-project/.test(creates[0].url));
    check("Authorization Bearer set",
          /^Bearer fake-access-token$/.test(creates[0].headers["authorization"]));
    var body = JSON.parse(creates[0].body.toString("utf8"));
    check("body has name",                       body.name === "my-bucket");
    check("body has location",                   body.location === "US");
    check("body has storageClass",               body.storageClass === "STANDARD");
  } finally { await l.close(); }
}

async function testCreateBucketConflict() {
  var sa = _fakeServiceAccount();
  var l = await _mockServer(function (entry) {
    if (entry.method === "POST" && /\/storage\/v1\/b/.test(entry.url)) {
      return { status: 409, body: { error: { code: 409, message: "exists" } } };
    }
    return { status: 200 };
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port, sa));
    var threw = null;
    try { await ops.create("existing"); } catch (e) { threw = e; }
    check("409 surfaces as BUCKET_ALREADY_OWNED",
          threw && /BUCKET_ALREADY_OWNED/.test(threw.code || ""));
  } finally { await l.close(); }
}

async function testDeleteBucket() {
  var sa = _fakeServiceAccount();
  var l = await _mockServer(function (entry) {
    if (entry.method === "DELETE") return { status: 204 };
    return { status: 200 };
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port, sa));
    var rv = await ops.delete("my-bucket");
    check("delete returns true on 204",  rv === true);
    var deletes = l.requests.filter(function (r) { return r.method === "DELETE"; });
    check("DELETE method used",          deletes.length === 1);
    check("URL targets /storage/v1/b/my-bucket",
          deletes[0].url === "/storage/v1/b/my-bucket");
  } finally { await l.close(); }

  var l404 = await _mockServer(function (entry) {
    if (entry.method === "DELETE") return { status: 404 };
    return { status: 200 };
  });
  try {
    var ops404 = bucketOps.create(_baseConfig(l404.port, sa));
    var rv404 = await ops404.delete("missing");
    check("delete returns false on 404",  rv404 === false);
  } finally { await l404.close(); }
}

async function testListBuckets() {
  var sa = _fakeServiceAccount();
  var l = await _mockServer(function (entry) {
    if (entry.method === "GET" && /\/storage\/v1\/b/.test(entry.url)) {
      return { status: 200, body: {
        items: [
          { name: "alpha", location: "US",     storageClass: "STANDARD",
            timeCreated: "2026-01-01T00:00:00Z", updated: "2026-01-02T00:00:00Z" },
          { name: "beta",  location: "EU",     storageClass: "NEARLINE",
            timeCreated: "2026-02-01T00:00:00Z", updated: "2026-02-02T00:00:00Z" },
        ],
      }};
    }
    return { status: 200 };
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port, sa));
    var result = await ops.list();
    check("list returns 2 entries",       result.length === 2);
    check("list[0] name = alpha",         result[0].name === "alpha");
    check("list[0] location = US",        result[0].location === "US");
    check("list[1] name = beta",          result[1].name === "beta");
    check("list[1] storageClass=NEARLINE", result[1].storageClass === "NEARLINE");
  } finally { await l.close(); }
}

async function testSetLifecycleValidationAndShape() {
  var sa = _fakeServiceAccount();
  var l = await _mockServer(function (entry) {
    if (entry.method === "PATCH") return { status: 200, body: {} };
    return { status: 200 };
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port, sa));

    async function shouldThrow(label, rules) {
      var threw = null;
      try { await ops.setLifecycle("my-bucket", rules); } catch (e) { threw = e; }
      check("setLifecycle rejects: " + label,
            threw && /INVALID_LIFECYCLE/.test(threw.code || ""));
    }
    await shouldThrow("non-array",                          "x");
    await shouldThrow("rule with no action",                [{ condition: { age: 30 } }]);
    await shouldThrow("rule with bad action.type",          [{ action: { type: "Nuke" }, condition: { age: 30 } }]);
    await shouldThrow("SetStorageClass without class",      [{ action: { type: "SetStorageClass" }, condition: { age: 30 } }]);
    await shouldThrow("rule with no condition",             [{ action: { type: "Delete" } }]);

    var rv = await ops.setLifecycle("my-bucket", [
      { action: { type: "Delete" }, condition: { age: 365 } },
      { action: { type: "SetStorageClass", storageClass: "ARCHIVE" }, condition: { age: 90 } },
    ]);
    check("setLifecycle returns rulesApplied=2", rv.rulesApplied === 2);
    var patches = l.requests.filter(function (r) { return r.method === "PATCH"; });
    check("PATCH issued",                          patches.length === 1);
    check("PATCH targets /storage/v1/b/my-bucket", patches[0].url === "/storage/v1/b/my-bucket");
    var body = JSON.parse(patches[0].body.toString("utf8"));
    check("body.lifecycle.rule has 2 entries",     body.lifecycle.rule.length === 2);
    check("body.lifecycle.rule[0].action.type=Delete",
          body.lifecycle.rule[0].action.type === "Delete");
  } finally { await l.close(); }
}

async function testSetCorsRulesShape() {
  var sa = _fakeServiceAccount();
  var l = await _mockServer(function (entry) {
    if (entry.method === "PATCH") return { status: 200, body: {} };
    return { status: 200 };
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port, sa));
    var rv = await ops.setCorsRules("my-bucket", [
      { origin: ["https://app.example.com"], method: ["GET", "PUT"],
        responseHeader: ["Content-Type"], maxAgeSeconds: 3600 },
    ]);
    check("setCorsRules returns rulesApplied=1", rv.rulesApplied === 1);
    var patches = l.requests.filter(function (r) { return r.method === "PATCH"; });
    check("PATCH issued",                          patches.length === 1);
    var body = JSON.parse(patches[0].body.toString("utf8"));
    check("body.cors[0].origin set",
          Array.isArray(body.cors) && body.cors[0].origin[0] === "https://app.example.com");
    check("body.cors[0].method=GET,PUT",
          body.cors[0].method.length === 2 && body.cors[0].method[0] === "GET");

    var threw = null;
    try { await ops.setCorsRules("my-bucket", "not-array"); } catch (e) { threw = e; }
    check("setCorsRules rejects non-array",
          threw && /INVALID_CORS_RULE/.test(threw.code || ""));
  } finally { await l.close(); }
}

async function run() {
  await testSurface();
  await testFactoryValidation();
  await testBucketNameValidation();
  await testCreateBucketWireShape();
  await testCreateBucketConflict();
  await testDeleteBucket();
  await testListBuckets();
  await testSetLifecycleValidationAndShape();
  await testSetCorsRulesShape();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[gcs-bucket-ops] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

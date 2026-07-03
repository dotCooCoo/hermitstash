// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * azure-blob-bucket-ops — container-level operations.
 *
 * Layer-0 mock-based tests: HTTP mock server records request shape;
 * signing comes from the production lib/object-store/azure-blob.js
 * `signRequest` helper so the on-the-wire bytes match what an Azure
 * Storage account would actually verify.
 */
var http = require("node:http");
var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var bucketOps = require("../../lib/object-store/azure-blob-bucket-ops");

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
        if (handler) handler(entry, res);
        else { res.statusCode = 200; res.end(); }
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

function _baseConfig(port, overrides) {
  // Azure Shared Key requires a base64 account key; any base64 will do
  // for tests since the mock server doesn't verify the signature.
  var key = Buffer.from("test-shared-key-32-bytes-padded__", "utf8").toString("base64");
  return Object.assign({
    accountName:      "blamejstest",
    accountKey:       key,
    endpoint:         "http://127.0.0.1:" + port,
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
    timeoutMs:        5000,
  }, overrides || {});
}

async function testSurface() {
  var l = await listenOnRandomPort();
  try {
    var ops = bucketOps.create(_baseConfig(l.port));
    check("ops.protocol === 'azure-blob'",       ops.protocol === "azure-blob");
    check("ops.create is fn",                    typeof ops.create === "function");
    check("ops.delete is fn",                    typeof ops.delete === "function");
    check("ops.list is fn",                      typeof ops.list === "function");
    check("ops.setCorsRules is fn",              typeof ops.setCorsRules === "function");
    check("ops.setLifecycle is fn (throws)",     typeof ops.setLifecycle === "function");
  } finally { await l.close(); }
}

async function testFactoryValidation() {
  function shouldThrow(label, opts, codeRe) {
    var threw = null;
    try { bucketOps.create(opts); } catch (e) { threw = e; }
    check("factory: " + label,  threw && codeRe.test(threw.code || ""));
  }
  shouldThrow("rejects null opts", null, /BAD_OPT/);
  shouldThrow("rejects missing accountName", { accountKey: "x" }, /BAD_OPT/);
  shouldThrow("rejects missing accountKey", { accountName: "x" }, /BAD_OPT/);
}

async function testContainerNameValidation() {
  var l = await listenOnRandomPort();
  try {
    var ops = bucketOps.create(_baseConfig(l.port));
    async function shouldRejectName(label, name) {
      var threw = null;
      try { await ops.create(name); } catch (e) { threw = e; }
      check("rejects " + label, threw && /BUCKET_INVALID_NAME/.test(threw.code || ""));
    }
    await shouldRejectName("UPPERCASE",       "MyBucket");
    await shouldRejectName("too short",       "ab");
    await shouldRejectName("too long (64)",   new Array(65).join("a"));
    await shouldRejectName("consecutive dashes", "a--b");
    await shouldRejectName("starts with dash",   "-abc");
    await shouldRejectName("ends with dash",     "abc-");
    await shouldRejectName("with dot",           "a.b");
    await shouldRejectName("with underscore",    "a_b");
  } finally { await l.close(); }
}

async function testCreateContainerWireShape() {
  var l = await listenOnRandomPort(function (req, res) {
    res.statusCode = 201; res.end();
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port));
    await ops.create("my-uploads", { publicAccess: "blob" });
    check("PUT method used",              l.requests[0].method === "PUT");
    check("URL has restype=container",    /\?restype=container/.test(l.requests[0].url));
    check("URL has /my-uploads",          /\/my-uploads\?/.test(l.requests[0].url));
    check("Authorization SharedKey set",
          /^SharedKey blamejstest:/.test(l.requests[0].headers["authorization"]));
    check("x-ms-version header set",
          typeof l.requests[0].headers["x-ms-version"] === "string");
    check("x-ms-blob-public-access set on opts",
          l.requests[0].headers["x-ms-blob-public-access"] === "blob");
  } finally { await l.close(); }
}

async function testCreateContainerConflict() {
  var l = await listenOnRandomPort(function (req, res) {
    res.statusCode = 409; res.end();
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port));
    var threw = null;
    try { await ops.create("existing"); } catch (e) { threw = e; }
    check("409 surfaces as BUCKET_ALREADY_OWNED",
          threw && /BUCKET_ALREADY_OWNED/.test(threw.code || ""));
  } finally { await l.close(); }
}

async function testDeleteContainer() {
  var l = await listenOnRandomPort(function (req, res) {
    res.statusCode = 202; res.end();
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port));
    var rv = await ops.delete("uploads");
    check("delete returns true on 202",   rv === true);
    check("DELETE method used",           l.requests[0].method === "DELETE");
    check("URL has restype=container",    /\?restype=container/.test(l.requests[0].url));
  } finally { await l.close(); }

  var l404 = await listenOnRandomPort(function (req, res) {
    res.statusCode = 404; res.end();
  });
  try {
    var ops404 = bucketOps.create(_baseConfig(l404.port));
    var rv404 = await ops404.delete("missing");
    check("delete returns false on 404",  rv404 === false);
  } finally { await l404.close(); }
}

async function testListContainers() {
  var xml =
    '<?xml version="1.0"?>' +
    '<EnumerationResults>' +
    '<Containers>' +
      '<Container><Name>alpha</Name><Properties><Last-Modified>Wed, 01 Jan 2026 12:00:00 GMT</Last-Modified><Etag>"0x1"</Etag></Properties></Container>' +
      '<Container><Name>beta</Name><Properties><Last-Modified>Wed, 02 Jan 2026 12:00:00 GMT</Last-Modified><Etag>"0x2"</Etag></Properties></Container>' +
    '</Containers>' +
    '</EnumerationResults>';
  var l = await listenOnRandomPort(function (req, res) {
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/xml");
    res.end(xml);
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port));
    var result = await ops.list();
    check("list returns 2 entries",       result.length === 2);
    check("list[0] name = alpha",         result[0].name === "alpha");
    check("list[1] name = beta",          result[1].name === "beta");
    check("URL has comp=list",            /\?comp=list/.test(l.requests[0].url));
    check("GET method used",              l.requests[0].method === "GET");
  } finally { await l.close(); }
}

async function testSetCorsRulesValidation() {
  var l = await listenOnRandomPort();
  try {
    var ops = bucketOps.create(_baseConfig(l.port));
    async function shouldThrow(label, rules) {
      var threw = null;
      try { await ops.setCorsRules(rules); } catch (e) { threw = e; }
      check("setCorsRules rejects: " + label,
            threw && /INVALID_CORS_RULE/.test(threw.code || ""));
    }
    await shouldThrow("non-array",                "not an array");
    await shouldThrow("rule with empty origins",  [{ allowedOrigins: [], allowedMethods: ["GET"] }]);
    await shouldThrow("rule with bad method",     [{ allowedOrigins: ["*"], allowedMethods: ["FOO"] }]);
    await shouldThrow("rule with bad maxAge",     [{ allowedOrigins: ["*"], allowedMethods: ["GET"], maxAgeInSeconds: -5 }]);
  } finally { await l.close(); }
}

async function testSetCorsRulesWireShape() {
  var l = await listenOnRandomPort(function (req, res) {
    res.statusCode = 202; res.end();
  });
  try {
    var ops = bucketOps.create(_baseConfig(l.port));
    var rv = await ops.setCorsRules([{
      allowedOrigins: ["https://app.example.com"],
      allowedMethods: ["GET", "PUT"],
      allowedHeaders: ["*"],
      exposedHeaders: ["ETag"],
      maxAgeInSeconds: 3600,
    }]);
    check("setCorsRules returns rulesApplied",  rv.rulesApplied === 1);
    check("PUT method used",                    l.requests[0].method === "PUT");
    check("URL has restype=service",            /\?restype=service/.test(l.requests[0].url));
    check("URL has comp=properties",            /comp=properties/.test(l.requests[0].url));
    var body = l.requests[0].body.toString("utf8");
    check("body contains <CorsRule>",           body.indexOf("<CorsRule>") !== -1);
    check("body contains origin",               body.indexOf("https://app.example.com") !== -1);
    check("body contains methods",              /<AllowedMethods>GET,PUT<\/AllowedMethods>/.test(body));
    check("body contains MaxAgeInSeconds",      /<MaxAgeInSeconds>3600<\/MaxAgeInSeconds>/.test(body));
  } finally { await l.close(); }
}

async function testSetLifecycleNotSupported() {
  var l = await listenOnRandomPort();
  try {
    var ops = bucketOps.create(_baseConfig(l.port));
    var threw = null;
    try { ops.setLifecycle("any", []); } catch (e) { threw = e; }
    check("setLifecycle throws NOT_SUPPORTED",
          threw && /NOT_SUPPORTED/.test(threw.code || ""));
    check("setLifecycle error mentions ARM",
          threw && /Resource Manager/.test(threw.message || ""));
  } finally { await l.close(); }
}

// bucketOps.create issues its requests through the shared b.httpClient
// keep-alive agent, whose cached client sockets (and the mock servers they
// keep open) would otherwise outlive run() and hold the forked worker's
// event loop open. Tear the pool down and poll until the TCP handles have
// actually closed — agent.destroy() schedules the teardown asynchronously,
// so polling drives the event-loop turns needed to complete it inside run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "azure-blob-bucket-ops: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    await testSurface();
    await testFactoryValidation();
    await testContainerNameValidation();
    await testCreateContainerWireShape();
    await testCreateContainerConflict();
    await testDeleteContainer();
    await testListContainers();
    await testSetCorsRulesValidation();
    await testSetCorsRulesWireShape();
    await testSetLifecycleNotSupported();
  } finally {
    await _drainTcpHandles();
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[azure-blob-bucket-ops] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

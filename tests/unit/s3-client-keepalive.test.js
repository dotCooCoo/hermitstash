require("../helpers/isolate-db"); // must precede every HermitStash require
/**
 * lib/s3-client.js: trustS3Configs lists the origins the configured S3 clients
 * send requests to in b.httpClient's trustedKeepAliveOrigins, so connections
 * to the configured object stores are pooled. Constructing an S3Client does
 * not touch the pool, because configurePool drops connections in flight.
 */
var { describe, it, afterEach } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var path = require("node:path");

var b = require("../../lib/vendor/blamejs");
var S3Client = require("../../lib/s3-client");

var realConfigurePool = b.httpClient.configurePool;
afterEach(function () { b.httpClient.configurePool = realConfigurePool; });

function recordCalls() {
  var calls = [];
  b.httpClient.configurePool = function (opts) { calls.push(opts); };
  return calls;
}

describe("s3-client keep-alive origins", function () {
  it("names the endpoint and the virtual-hosted bucket host", function () {
    assert.deepStrictEqual(S3Client.s3Origins("https://s3.us-west-002.backblazeb2.com", "us-west-002", "hs-files"),
      ["https://s3.us-west-002.backblazeb2.com", "https://hs-files.s3.us-west-002.backblazeb2.com"]);
    assert.deepStrictEqual(S3Client.s3Origins(undefined, "eu-central-1", "Bucket"),
      ["https://s3.eu-central-1.amazonaws.com", "https://bucket.s3.eu-central-1.amazonaws.com"]);
    assert.deepStrictEqual(S3Client.s3Origins("https://minio.example.com:9000/", "us-east-1", "b1"),
      ["https://minio.example.com:9000", "https://b1.minio.example.com:9000"]);
  });

  it("names no origin for an http endpoint, and only the endpoint for an IP literal", function () {
    assert.deepStrictEqual(S3Client.s3Origins("http://minio.local:9000", "us-east-1", "b1"), []);
    assert.deepStrictEqual(S3Client.s3Origins("https://192.0.2.10:9000", "us-east-1", "b1"), ["https://192.0.2.10:9000"]);
    assert.deepStrictEqual(S3Client.s3Origins("not a url", "us-east-1", "b1"), []);
  });

  it("trustS3Configs sets the union of the storage and backup origins in one call", function () {
    var calls = recordCalls();
    var list = S3Client.trustS3Configs([
      { bucket: "files", region: "us-east-1", endpoint: "https://objects.example.com" },
      { bucket: "backups", region: "us-east-1", endpoint: "https://objects.example.com" },
      null,
      { bucket: "", endpoint: "https://ignored.example.com" },
    ]);
    assert.strictEqual(calls.length, 1);
    assert.deepStrictEqual(calls[0].trustedKeepAliveOrigins, list);
    assert.deepStrictEqual(list.slice().sort(), [
      "https://backups.objects.example.com", "https://files.objects.example.com", "https://objects.example.com",
    ]);
  });

  it("the list it passes is one b.httpClient accepts", function () {
    var calls = recordCalls();
    S3Client.trustS3Configs([{ bucket: "accept-test", region: "us-east-1", endpoint: "https://accept.example.com" }]);
    b.httpClient.configurePool = realConfigurePool;
    assert.doesNotThrow(function () { b.httpClient.configurePool(calls[0]); });
  });

  it("constructing a client does not reconfigure the pool", function () {
    var calls = recordCalls();
    new S3Client({ bucket: "no-reconfigure", region: "us-east-1", accessKey: "a", secretKey: "s",
      endpoint: "https://objects.example.com" });
    assert.strictEqual(calls.length, 0);
  });

  it("is called at boot and when a backup or restore worker starts", function () {
    var root = path.join(__dirname, "..", "..");
    [["server-main.js", /s3Client\.trustS3Configs\(/], ["lib/backup-worker.js", /S3Client\.trustS3Configs\(/],
      ["lib/restore-worker.js", /S3Client\.trustS3Configs\(/]].forEach(function (pair) {
      assert.match(fs.readFileSync(path.join(root, pair[0]), "utf8"), pair[1], pair[0]);
    });
  });
});

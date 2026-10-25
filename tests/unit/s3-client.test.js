require("../helpers/isolate-db"); // must precede every HermitStash require
/**
 * lib/s3-client.js sends every put() body through one sigv4 backend with the
 * framework's default retry. Against an S3 endpoint that fails one request, that
 * backend refuses a stream put and stores no object, because a stream is read
 * once and is not retried, and it sends a Buffer again on the retry.
 */
var http = require("node:http");
var { Readable } = require("node:stream");
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var b = require("../../lib/vendor/blamejs");
var C = require("../../lib/constants");

describe("b.objectStore sigv4 put() against an S3 endpoint that fails one request", function () {
  var server;
  var port;
  var objects = {};
  var uploads = {};
  var failNext = null;
  var nextUpload = 0;

  function reply(res, status, body, headers) {
    res.writeHead(status, Object.assign({ "Content-Type": "application/xml" }, headers || {}));
    res.end(body || "");
  }

  before(function () {
    server = http.createServer(function (req, res) {
      var u = new URL(req.url, "http://127.0.0.1");
      var key = u.pathname.split("/").slice(2).join("/");
      var chunks = [];
      req.on("data", function (c) { chunks.push(c); });
      req.on("end", function () {
        var body = Buffer.concat(chunks);
        var kind = req.method === "POST" && u.searchParams.has("uploads") ? "initiate"
          : req.method === "PUT" && u.searchParams.has("partNumber") ? "part"
          : req.method === "POST" && u.searchParams.has("uploadId") ? "complete"
          : req.method === "DELETE" && u.searchParams.has("uploadId") ? "abort"
          : req.method === "PUT" ? "put" : "other";
        if (failNext === kind) {
          failNext = null;
          reply(res, 503, "<Error><Code>SlowDown</Code></Error>");
          return;
        }
        if (kind === "initiate") {
          nextUpload += 1;
          var id = "upload-" + nextUpload;
          uploads[id] = {};
          reply(res, 200, "<InitiateMultipartUploadResult><Bucket>bkt</Bucket><Key>" + key +
            "</Key><UploadId>" + id + "</UploadId></InitiateMultipartUploadResult>");
        } else if (kind === "part") {
          uploads[u.searchParams.get("uploadId")][Number(u.searchParams.get("partNumber"))] = body;
          reply(res, 200, "", { ETag: "\"part-" + u.searchParams.get("partNumber") + "\"" });
        } else if (kind === "complete") {
          var parts = uploads[u.searchParams.get("uploadId")];
          objects[key] = Buffer.concat(Object.keys(parts).sort(function (x, y) { return x - y; }).map(function (n) { return parts[n]; }));
          reply(res, 200, "<CompleteMultipartUploadResult><Key>" + key + "</Key><ETag>\"done\"</ETag></CompleteMultipartUploadResult>");
        } else if (kind === "abort") {
          delete uploads[u.searchParams.get("uploadId")];
          reply(res, 204);
        } else if (kind === "put") {
          objects[key] = body;
          reply(res, 200, "", { ETag: "\"put\"" });
        } else {
          reply(res, 404, "<Error><Code>NoSuchKey</Code></Error>");
        }
      });
    });
    return new Promise(function (resolve) {
      server.listen(0, "127.0.0.1", function () { port = server.address().port; resolve(); });
    });
  });

  after(function () { return new Promise(function (resolve) { server.close(resolve); }); });

  // The same options lib/s3-client.js passes, plus what a plain-HTTP loopback
  // endpoint needs. No retry option: the framework's default applies.
  function backend() {
    return b.objectStore.buildBackend({
      protocol: "sigv4", endpoint: "http://127.0.0.1:" + port, region: "us-east-1", bucket: "bkt",
      accessKeyId: "test-access", secretAccessKey: "test-secret", pathStyle: true,
      allowedProtocols: ["http:"], allowInternal: true, timeoutMs: C.TIME.seconds(10),
    });
  }

  it("refuses a stream put whose CompleteMultipartUpload fails, and stores no object", async function () {
    failNext = "complete";
    await assert.rejects(backend().put("stream.bin", Readable.from([Buffer.alloc(C.BYTES.kib(1), 1)])));
    assert.strictEqual(objects["stream.bin"], undefined, "no object is stored");
  });

  it("refuses a stream put whose part upload fails, and stores no object", async function () {
    failNext = "part";
    await assert.rejects(backend().put("stream2.bin", Readable.from([Buffer.alloc(C.BYTES.kib(1), 3)])));
    assert.strictEqual(objects["stream2.bin"], undefined, "no object is stored");
  });

  it("sends the whole Buffer again when it retries a failed upload", async function () {
    failNext = "put";
    var result = await backend().put("buffer.bin", Buffer.alloc(C.BYTES.kib(1), 2));
    assert.strictEqual(result.size, C.BYTES.kib(1));
    assert.ok(objects["buffer.bin"].equals(Buffer.alloc(C.BYTES.kib(1), 2)), "the stored object holds every byte");
  });
});

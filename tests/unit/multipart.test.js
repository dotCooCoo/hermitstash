const { describe, it } = require("node:test");
const assert = require("node:assert");
var { EventEmitter } = require("events");

var { parseMultipart } = require("../../lib/multipart");

/**
 * Helper: create a mock request (EventEmitter) that emits data/end events.
 * @param {Buffer|string} body - the body to emit as data
 * @param {object} headers - request headers
 */
function mockRequest(body, headers) {
  var req = new EventEmitter();
  req.headers = headers || {};
  req.destroy = function () {};
  process.nextTick(function () {
    var buf = Buffer.isBuffer(body) ? body : Buffer.from(body || "");
    req.emit("data", buf);
    req.emit("end");
  });
  return req;
}

/**
 * Helper: build a raw multipart body with a given boundary.
 */
function buildMultipart(boundary, parts) {
  var segments = [];
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i];
    segments.push("--" + boundary + "\r\n");
    if (p.filename) {
      segments.push(
        'Content-Disposition: form-data; name="' + p.name + '"; filename="' + p.filename + '"\r\n'
      );
      if (p.contentType) {
        segments.push("Content-Type: " + p.contentType + "\r\n");
      }
    } else {
      segments.push('Content-Disposition: form-data; name="' + p.name + '"\r\n');
    }
    segments.push("\r\n");
    segments.push(p.value || "");
    segments.push("\r\n");
  }
  segments.push("--" + boundary + "--\r\n");
  return Buffer.from(segments.join(""));
}

// JSON body parsing moved to b.parsers.json — covered by blamejs's own
// test suite. HermitStash callers use it directly:
//   var body = (await b.parsers.json(req)) || {};

// =============================================================================
// parseMultipart
// =============================================================================
describe("multipart — parseMultipart", function () {
  describe("field parsing", function () {
    it("parses a single text field", async function () {
      var boundary = "----TestBoundary123";
      var body = buildMultipart(boundary, [
        { name: "username", value: "hermit" },
      ]);
      var req = mockRequest(body, {
        "content-type": "multipart/form-data; boundary=" + boundary,
      });
      var result = await parseMultipart(req, 10 * 1024 * 1024);
      assert.strictEqual(result.fields.username, "hermit");
      assert.strictEqual(result.files.length, 0);
    });

    it("parses multiple text fields", async function () {
      var boundary = "----Multi";
      var body = buildMultipart(boundary, [
        { name: "first", value: "Alice" },
        { name: "second", value: "Bob" },
      ]);
      var req = mockRequest(body, {
        "content-type": "multipart/form-data; boundary=" + boundary,
      });
      var result = await parseMultipart(req, 10 * 1024 * 1024);
      assert.strictEqual(result.fields.first, "Alice");
      assert.strictEqual(result.fields.second, "Bob");
    });
  });

  describe("file extraction", function () {
    it("extracts a file with correct filename and mimetype", async function () {
      var boundary = "----FileBound";
      var fileContent = "Hello, this is file content!";
      var body = buildMultipart(boundary, [
        {
          name: "upload",
          filename: "test.txt",
          contentType: "text/plain",
          value: fileContent,
        },
      ]);
      var req = mockRequest(body, {
        "content-type": "multipart/form-data; boundary=" + boundary,
      });
      var result = await parseMultipart(req, 10 * 1024 * 1024);
      assert.strictEqual(result.files.length, 1);
      assert.strictEqual(result.files[0].fieldname, "upload");
      assert.strictEqual(result.files[0].filename, "test.txt");
      assert.strictEqual(result.files[0].mimetype, "text/plain");
      assert.strictEqual(result.files[0].data.toString(), fileContent);
      assert.strictEqual(result.files[0].size, Buffer.byteLength(fileContent));
    });

    it("defaults mimetype to application/octet-stream when missing", async function () {
      var boundary = "----NoMime";
      // Build raw multipart without Content-Type header for the file part
      var raw = "--" + boundary + "\r\n" +
        'Content-Disposition: form-data; name="file"; filename="data.bin"\r\n' +
        "\r\n" +
        "binary-data" +
        "\r\n" +
        "--" + boundary + "--\r\n";
      var req = mockRequest(Buffer.from(raw), {
        "content-type": "multipart/form-data; boundary=" + boundary,
      });
      var result = await parseMultipart(req, 10 * 1024 * 1024);
      assert.strictEqual(result.files.length, 1);
      assert.strictEqual(result.files[0].mimetype, "application/octet-stream");
    });
  });

  describe("mixed fields and files", function () {
    it("parses fields and files together", async function () {
      var boundary = "----MixedBound";
      var body = buildMultipart(boundary, [
        { name: "description", value: "A test upload" },
        {
          name: "attachment",
          filename: "photo.jpg",
          contentType: "image/jpeg",
          value: "fake-jpeg-bytes",
        },
      ]);
      var req = mockRequest(body, {
        "content-type": "multipart/form-data; boundary=" + boundary,
      });
      var result = await parseMultipart(req, 10 * 1024 * 1024);
      assert.strictEqual(result.fields.description, "A test upload");
      assert.strictEqual(result.files.length, 1);
      assert.strictEqual(result.files[0].filename, "photo.jpg");
    });
  });

  describe("missing boundary", function () {
    it("rejects when content-type has no boundary", async function () {
      var req = mockRequest("some body", {
        "content-type": "multipart/form-data",
      });
      await assert.rejects(
        function () { return parseMultipart(req, 10 * 1024 * 1024); },
        function (err) {
          assert.strictEqual(err.code, "body-parser/multipart-no-boundary");
          return true;
        }
      );
    });
  });

  describe("wrong content-type", function () {
    it("rejects when content-type is not multipart/form-data", async function () {
      var req = mockRequest("some body", {
        "content-type": "application/json",
      });
      await assert.rejects(
        function () { return parseMultipart(req, 10 * 1024 * 1024); },
        function (err) {
          assert.strictEqual(err.code, "body-parser/standalone-not-multipart");
          return true;
        }
      );
    });

    it("rejects when content-type header is missing", async function () {
      var req = mockRequest("some body", {});
      await assert.rejects(
        function () { return parseMultipart(req, 10 * 1024 * 1024); },
        function (err) {
          assert.strictEqual(err.code, "body-parser/standalone-not-multipart");
          return true;
        }
      );
    });
  });

  describe("size limit enforcement", function () {
    it("rejects when upload exceeds maxSize", async function () {
      var boundary = "----SizeLimit";
      var bigContent = "x".repeat(5000);
      var body = buildMultipart(boundary, [
        {
          name: "bigfile",
          filename: "big.bin",
          contentType: "application/octet-stream",
          value: bigContent,
        },
      ]);
      var req = mockRequest(body, {
        "content-type": "multipart/form-data; boundary=" + boundary,
      });
      await assert.rejects(
        function () { return parseMultipart(req, 100); },
        function (err) {
          // blamejs throws either body-parser/multipart-too-large (totalSize)
          // or body-parser/multipart-file-too-large (per-file fileSize).
          // The HS adapter sets both opts to maxSize, so either matches.
          assert.match(err.code, /multipart-(file-)?too-large/);
          assert.strictEqual(err.statusCode, 413);
          return true;
        }
      );
    });
  });

  describe("binary file data", function () {
    it("handles binary content correctly", async function () {
      var boundary = "----BinaryBound";
      var binaryData = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
      // Build raw multipart with binary data
      var header = "--" + boundary + "\r\n" +
        'Content-Disposition: form-data; name="binfile"; filename="raw.bin"\r\n' +
        "Content-Type: application/octet-stream\r\n" +
        "\r\n";
      var footer = "\r\n--" + boundary + "--\r\n";
      var body = Buffer.concat([
        Buffer.from(header),
        binaryData,
        Buffer.from(footer),
      ]);
      var req = mockRequest(body, {
        "content-type": "multipart/form-data; boundary=" + boundary,
      });
      var result = await parseMultipart(req, 10 * 1024 * 1024);
      assert.strictEqual(result.files.length, 1);
      assert.strictEqual(result.files[0].filename, "raw.bin");
      assert.ok(Buffer.isBuffer(result.files[0].data), "file data should be a Buffer");
    });
  });
});

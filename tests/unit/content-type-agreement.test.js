const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");

const b = require(path.join(__dirname, "..", "..", "lib", "vendor", "blamejs"));
const { detectContentType } = require(path.join(__dirname, "..", "..", "app", "http", "validators", "upload.validator"));

// Drift guard: HS's upload-time magic-byte detector (detectContentType, returns an
// extension) and the serve-time detector (b.fileType.detect, returns a MIME +
// extension) must AGREE on the common risky types. If they ever diverge — e.g. a
// vendored-framework update changes b.fileType.detect's classification — an upload
// validated as one type could be served as another. safeServeMime already fails
// safe (downgrades to octet-stream / forced-download with nosniff), but the drift
// is worth catching in CI so the two detectors stay in lock-step.
describe("upload/serve content-type detector agreement", function () {
  var samples = [
    { name: "png",  buf: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) },
    { name: "jpg",  buf: Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0]) },
    { name: "gif",  buf: Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0, 0]) },
    { name: "pdf",  buf: Buffer.from("%PDF-1.4 minimal document body") },
    { name: "zip",  buf: Buffer.from([0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0]) },
    { name: "webp", buf: Buffer.concat([Buffer.from("RIFF"), Buffer.from([0, 0, 0, 0]), Buffer.from("WEBP")]) },
  ];

  samples.forEach(function (s) {
    it("detectContentType and b.fileType.detect agree for " + s.name, function () {
      var ext = detectContentType(s.buf);
      var ft = b.fileType.detect(s.buf);
      assert.ok(ext, s.name + ": the upload-time detector must recognize it");
      assert.ok(ft && ft.extension, s.name + ": the serve-time detector must recognize it");
      assert.strictEqual(ext, "." + ft.extension, s.name + ": upload-time and serve-time detectors must return the same type (no drift)");
    });
  });
});

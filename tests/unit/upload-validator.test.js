const { describe, it } = require("node:test");
const assert = require("node:assert");
const b = require("../../lib/vendor/blamejs");

const { validateMagicBytes, safeServeMime } = require("../../app/http/validators/upload.validator");

// Pad each fixture past the 8-byte minimum validateMagicBytes enforces.
const PAD = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

// A clean single-format PNG: 89 50 4E 47 0D 0A 1A 0A.
const PNG = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A].concat(PAD));
// A clean single-format JPEG: FF D8 FF.
const JPEG = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0].concat(PAD));
// A clean single-format BMP: 42 4D.
const BMP = Buffer.from([0x42, 0x4D, 0x10, 0x00].concat(PAD));

// A crafted polyglot: BMP magic (42 4D) at offset 0 AND HEIC `ftypheic` at
// offset 4. The two signatures occupy disjoint byte ranges, so the buffer
// satisfies both magics at once — the polyglot-file class (e.g. a raster
// header smuggling a second container format past a first-match detector).
const POLYGLOT = Buffer.from([
  0x42, 0x4D, 0x00, 0x00,                          // BMP magic at offset 0
  0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63,  // `ftypheic` (HEIC) at offset 4
  0x00, 0x00, 0x00, 0x00,
]);

describe("upload-validator — validateMagicBytes: clean single-format images pass", function () {
  it("accepts a clean PNG declared as .png", function () {
    assert.deepStrictEqual(validateMagicBytes("logo.png", PNG), { valid: true });
  });

  it("accepts a clean JPEG declared as .jpg and .jpeg", function () {
    assert.deepStrictEqual(validateMagicBytes("photo.jpg", JPEG), { valid: true });
    assert.deepStrictEqual(validateMagicBytes("photo.jpeg", JPEG), { valid: true });
  });

  it("does not false-positive a legitimate single-format raster image", function () {
    // A clean BMP carries exactly one magic-byte signature — the new
    // guardImage pass must let it through.
    assert.deepStrictEqual(validateMagicBytes("ok.bmp", BMP), { valid: true });
    assert.deepStrictEqual(validateMagicBytes("logo.png", PNG), { valid: true });
  });
});

describe("upload-validator — validateMagicBytes: polyglot rejection (guardImage pass)", function () {
  it("rejects a buffer that satisfies two image magics even when the extension agrees", function () {
    // The first-match detector labels this .bmp (extension agrees), so the
    // legacy check would pass it — guardImage walks every signature and refuses.
    const rv = validateMagicBytes("evil.bmp", POLYGLOT);
    assert.strictEqual(rv.valid, false);
    assert.strictEqual(rv.reason, "Image failed polyglot/format-integrity check.");
  });
});

describe("upload-validator — guardImage primitive contract (what the new pass relies on)", function () {
  it("inspectMagic returns more than one hit for a dual-magic buffer", function () {
    const hits = b.guardImage.inspectMagic(POLYGLOT);
    assert.ok(Array.isArray(hits));
    assert.ok(hits.length > 1, "expected >1 magic hit, got " + JSON.stringify(hits));
    assert.ok(hits.indexOf("image/bmp") !== -1);
    assert.ok(hits.indexOf("image/heic") !== -1);
  });

  it("validate flags the polyglot kind and passes a clean single-format image", function () {
    const poly = b.guardImage.validate({ bytes: POLYGLOT, declaredMime: "image/bmp" });
    assert.strictEqual(poly.ok, false);
    assert.ok(poly.issues.some(function (i) { return i.kind === "polyglot"; }));

    const clean = b.guardImage.validate({ bytes: PNG, declaredMime: "image/png" });
    assert.strictEqual(clean.ok, true);
  });
});

describe("upload-validator — safeServeMime binds the stored MIME to sniffed content", function () {
  const PNG = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0]);
  const NOT_PNG = Buffer.from("this is really text, not a PNG image at all");

  it("keeps a declared inline type when the magic bytes agree", function () {
    assert.strictEqual(safeServeMime("image/png", PNG), "image/png");
  });

  it("downgrades a spoofed inline type to application/octet-stream when bytes disagree", function () {
    // A file the client declared image/png that is NOT a PNG must not be stored as
    // image/png — otherwise the serve-time inline/preview gate would render it inline.
    assert.strictEqual(safeServeMime("image/png", NOT_PNG), "application/octet-stream");
  });

  it("passes through a non-inline declared type unchanged (only inline types are bound)", function () {
    assert.strictEqual(safeServeMime("application/zip", NOT_PNG), "application/zip");
  });

  it("returns application/octet-stream for a missing declared type", function () {
    assert.strictEqual(safeServeMime("", PNG), "application/octet-stream");
    assert.strictEqual(safeServeMime(null, PNG), "application/octet-stream");
  });
});

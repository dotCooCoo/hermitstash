const { describe, it } = require("node:test");
const assert = require("node:assert");
const b = require("../../lib/vendor/blamejs");

const {
  validateMagicBytes, safeServeMime,
  validateFile, validateChunk, validateBundleLimits,
} = require("../../app/http/validators/upload.validator");

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

// A clean single-format GIF: 47 49 46 38 ("GIF8").
const GIF = Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61].concat(PAD));
// Long enough to be inspected, matching no signature this detector knows.
const UNRECOGNIZED = Buffer.alloc(16);

describe("upload-validator — validateMagicBytes: the rejection paths", function () {
  it("rejects content whose format disagrees with a risky extension", function () {
    // The whole point of the check: the name claims one format and the bytes
    // are another. Both sides are recognized here, so this is the disagreement
    // path rather than the unrecognized-content one below.
    var out = validateMagicBytes("payload.gif", PNG);
    assert.strictEqual(out.valid, false);
    assert.match(out.reason, /does not match \.gif format/);
  });

  it("rejects content it cannot recognize at all under a risky extension", function () {
    var out = validateMagicBytes("payload.png", UNRECOGNIZED);
    assert.strictEqual(out.valid, false);
    assert.match(out.reason, /does not match \.png format/);
  });

  it("rejects a file too short to carry a signature", function () {
    var out = validateMagicBytes("tiny.png", Buffer.from([0x89, 0x50, 0x4E, 0x47]));
    assert.strictEqual(out.valid, false);
    assert.match(out.reason, /too small/i);
  });

  it("accepts a GIF declared as .gif", function () {
    assert.deepStrictEqual(validateMagicBytes("anim.gif", GIF), { valid: true });
  });

  it("treats .jpg and .jpeg as the same format in both directions", function () {
    // Interchangeability is supplied by the compatibility map, which folds
    // .jpeg to .jpg before the comparison — the detector itself only ever
    // reports .jpg. Pinned here because the comparison used to carry a second,
    // unreachable special case for the same thing.
    assert.deepStrictEqual(validateMagicBytes("photo.jpg", JPEG), { valid: true });
    assert.deepStrictEqual(validateMagicBytes("photo.jpeg", JPEG), { valid: true });
    assert.strictEqual(validateMagicBytes("photo.jpeg", PNG).valid, false);
    assert.strictEqual(validateMagicBytes("photo.jpg", PNG).valid, false);
  });

  it("does not inspect an extension with no signature to check", function () {
    assert.deepStrictEqual(validateMagicBytes("notes.txt", UNRECOGNIZED), { valid: true });
  });

  it("has nothing to check without a filename or a buffer", function () {
    assert.deepStrictEqual(validateMagicBytes("", PNG), { valid: true });
    assert.deepStrictEqual(validateMagicBytes("logo.png", null), { valid: true });
  });
});

describe("upload-validator — validateFile", function () {
  it("accepts a permitted file", function () {
    assert.deepStrictEqual(validateFile("report.pdf", 1024, [".pdf"], 4096), { valid: true });
  });

  it("refuses a missing filename", function () {
    assert.strictEqual(validateFile("", 10, null, null).reason, "Missing filename.");
  });

  it("refuses an empty file", function () {
    assert.strictEqual(validateFile("a.pdf", 0, null, null).reason, "Empty file.");
  });

  it("refuses a file over the size limit, and allows it when there is none", function () {
    assert.strictEqual(validateFile("a.pdf", 5000, null, 4096).reason, "File too large.");
    assert.deepStrictEqual(validateFile("a.pdf", 5000, null, 0), { valid: true });
  });

  it("refuses a name with no extension", function () {
    assert.strictEqual(validateFile("README", 10, null, null).reason, "No file extension.");
  });

  it("refuses an extension outside the allowlist, case-insensitively", function () {
    assert.match(validateFile("a.exe", 10, [".pdf"], null).reason, /not allowed: \.exe/);
    assert.deepStrictEqual(validateFile("a.PDF", 10, [".pdf"], null), { valid: true });
  });

  it("allows any extension when the allowlist is empty or absent", function () {
    assert.deepStrictEqual(validateFile("a.exe", 10, [], null), { valid: true });
    assert.deepStrictEqual(validateFile("a.exe", 10, null, null), { valid: true });
  });
});

describe("upload-validator — validateChunk", function () {
  // Guards the chunked-upload parameters, which arrive as form fields on an
  // unauthenticated public upload. Every refusal here is the one that keeps a
  // caller from steering reassembly with an index it chose.
  it("accepts a well-formed chunk", function () {
    assert.deepStrictEqual(validateChunk(0, 4, "abc123"), { valid: true });
    assert.deepStrictEqual(validateChunk(3, 4, "abc123"), { valid: true });
  });

  it("refuses a missing chunk index, but not index zero", function () {
    assert.strictEqual(validateChunk(undefined, 4, "a1").reason, "Missing chunk index.");
    assert.strictEqual(validateChunk(null, 4, "a1").reason, "Missing chunk index.");
    assert.deepStrictEqual(validateChunk(0, 4, "a1"), { valid: true });
  });

  it("refuses a non-positive or missing total", function () {
    assert.strictEqual(validateChunk(0, 0, "a1").reason, "Invalid total chunks.");
    assert.strictEqual(validateChunk(0, -1, "a1").reason, "Invalid total chunks.");
    assert.strictEqual(validateChunk(0, undefined, "a1").reason, "Invalid total chunks.");
  });

  it("caps the number of chunks", function () {
    assert.deepStrictEqual(validateChunk(0, 10000, "a1"), { valid: true });
    assert.strictEqual(validateChunk(0, 10001, "a1").reason, "Too many chunks.");
  });

  it("refuses an index outside the declared range", function () {
    assert.strictEqual(validateChunk(-1, 4, "a1").reason, "Chunk index out of range.");
    assert.strictEqual(validateChunk(4, 4, "a1").reason, "Chunk index out of range.");
    assert.strictEqual(validateChunk(99, 4, "a1").reason, "Chunk index out of range.");
  });

  it("refuses a file id that is missing or not alphanumeric", function () {
    // Path separators and traversal are the reason the id is constrained at
    // all — it names a spool file on disk.
    assert.strictEqual(validateChunk(0, 4, "").reason, "Invalid file ID.");
    assert.strictEqual(validateChunk(0, 4, "../../etc/passwd").reason, "Invalid file ID.");
    assert.strictEqual(validateChunk(0, 4, "a/b").reason, "Invalid file ID.");
    assert.strictEqual(validateChunk(0, 4, "a.b").reason, "Invalid file ID.");
    assert.strictEqual(validateChunk(0, 4, "a b").reason, "Invalid file ID.");
    // Rejected here even though the caller's own second check would allow them.
    assert.strictEqual(validateChunk(0, 4, "a-b").reason, "Invalid file ID.");
    assert.strictEqual(validateChunk(0, 4, "a_b").reason, "Invalid file ID.");
  });
});

describe("upload-validator — validateBundleLimits", function () {
  it("accepts a bundle inside both limits", function () {
    assert.deepStrictEqual(validateBundleLimits(3, 10, 100, 1000), { valid: true });
  });

  it("refuses too many files and names the limit", function () {
    assert.match(validateBundleLimits(11, 10, 100, 1000).reason, /Too many files \(max 10\)/);
  });

  it("refuses a bundle over the size limit", function () {
    assert.strictEqual(validateBundleLimits(1, 10, 2000, 1000).reason, "Bundle too large.");
  });

  it("treats a zero or absent limit as no limit", function () {
    assert.deepStrictEqual(validateBundleLimits(9999, 0, 9e9, 0), { valid: true });
    assert.deepStrictEqual(validateBundleLimits(9999, null, 9e9, null), { valid: true });
  });
});

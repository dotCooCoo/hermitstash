"use strict";

/**
 * Every magic signature the upload guard recognises, pinned to its specification.
 *
 * detectContentType is what stops a file whose extension lies about its bytes:
 * validateMagicBytes sniffs the buffer and refuses the upload when the two
 * disagree. Most of its signatures had nothing exercising them, and a signature
 * with one wrong byte does not fail loudly — it simply never matches, the sniff
 * reports "unrecognised", and every upload claiming that extension is refused
 * (or, for the pairs that fold together through the compatibility map, quietly
 * accepted). Both failures look like ordinary behaviour from outside.
 *
 * The byte sequences below are the ones the formats define, checked against the
 * specification rather than recalled:
 *
 *   .png    RFC 2083 §3.1 — 89 50 4E 47 0D 0A 1A 0A
 *   .gz     RFC 1952 §2.3.1 — ID1 31 (0x1F), ID2 139 (0x8B)
 *   .tiff   TIFF 6.0 §2 — "II" 42 0 little-endian, "MM" 0 42 big-endian
 *   .ole2   MS-CFB §2.2 — D0 CF 11 E0 A1 B1 1A E1
 *   .7z     7-Zip format — 37 7A BC AF 27 1C
 *   .rar    RAR — "Rar!" 1A 07 (shared prefix of RAR4 and RAR5)
 *   .bz2    bzip2 — "BZh"
 *   .zip    APPNOTE — "PK"
 *   .ico    ICONDIR — reserved 0, type 1
 *   .webp   RIFF container with a "WEBP" form type at offset 8
 *
 * The point of the table is that a change to any one line fails one case and
 * names it, rather than shifting a total.
 */

require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it } = require("node:test");
var assert = require("node:assert");
var validator = require("../../app/http/validators/upload.validator");

function bytes() {
  return Buffer.from(Array.prototype.slice.call(arguments));
}
// Signatures are checked against a short prefix; pad so nothing is rejected for
// being too small to inspect, and so the pad cannot itself look like a format.
function padded(head, size) {
  var buf = Buffer.alloc(size || 64, 0x5A);
  Buffer.from(head).copy(buf, 0);
  return buf;
}

var SIGNATURES = [
  [".png", padded(bytes(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))],
  [".jpg", padded(bytes(0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46))],
  [".gif", padded(Buffer.from("GIF89a", "latin1"))],
  [".gif", padded(Buffer.from("GIF87a", "latin1"))],
  [".bmp", padded(Buffer.from("BM", "latin1"))],
  [".ico", padded(bytes(0x00, 0x00, 0x01, 0x00))],
  [".tiff", padded(bytes(0x49, 0x49, 0x2A, 0x00))],       // little-endian
  [".tiff", padded(bytes(0x4D, 0x4D, 0x00, 0x2A))],       // big-endian
  [".webp", padded(Buffer.concat([
    Buffer.from("RIFF", "latin1"), bytes(0x20, 0x00, 0x00, 0x00), Buffer.from("WEBP", "latin1"),
  ]))],
  [".pdf", padded(Buffer.from("%PDF-1.7", "latin1"))],
  [".zip", padded(bytes(0x50, 0x4B, 0x03, 0x04))],
  [".rar", padded(bytes(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00))],
  [".rar", padded(bytes(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00))],   // RAR5
  [".7z", padded(bytes(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C))],
  [".gz", padded(bytes(0x1F, 0x8B, 0x08, 0x00))],
  [".bz2", padded(Buffer.from("BZh9", "latin1"))],
  [".ole2", padded(bytes(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1))],
  [".svg", padded(Buffer.from("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>", "latin1"))],
  [".svg", padded(Buffer.from("<?xml version=\"1.0\"?><svg></svg>", "latin1"))],
];

describe("every recognised signature is detected", function () {
  SIGNATURES.forEach(function (pair, i) {
    it("case " + (i + 1) + " detects " + pair[0], function () {
      assert.strictEqual(validator.detectContentType(pair[1]), pair[0],
        "the signature for " + pair[0] + " must match its specification");
    });
  });
});

describe("what is not a known format is reported as unknown", function () {
  it("a buffer too short to carry any signature", function () {
    assert.strictEqual(validator.detectContentType(bytes(0x89, 0x50, 0x4E)), null,
      "fewer than four bytes cannot be identified");
    assert.strictEqual(validator.detectContentType(Buffer.alloc(0)), null);
    assert.strictEqual(validator.detectContentType(null), null);
  });

  it("bytes that match nothing", function () {
    // Deliberately not a near-miss of any entry above.
    assert.strictEqual(validator.detectContentType(padded(bytes(0x11, 0x22, 0x33, 0x44))), null);
  });

  it("a near-miss of a signature is not a match", function () {
    // One byte away from PNG, and from OLE2. A sniffer that compared a prefix
    // loosely would accept both.
    assert.strictEqual(validator.detectContentType(padded(bytes(0x89, 0x50, 0x4E, 0x48))), null);
    assert.strictEqual(validator.detectContentType(
      padded(bytes(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE2))), null);
  });

  it("BM and BZh are told apart despite sharing a first byte", function () {
    assert.strictEqual(validator.detectContentType(padded(Buffer.from("BM", "latin1"))), ".bmp");
    assert.strictEqual(validator.detectContentType(padded(Buffer.from("BZh9", "latin1"))), ".bz2");
  });
});

describe("a declared extension is checked against the bytes", function () {
  var PNG = padded(bytes(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A));
  var GIF = padded(Buffer.from("GIF89a", "latin1"));
  var ZIP = padded(bytes(0x50, 0x4B, 0x03, 0x04));
  var OLE2 = padded(bytes(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1));
  var GZ = padded(bytes(0x1F, 0x8B, 0x08, 0x00));

  it("accepts a name that agrees with the content", function () {
    assert.strictEqual(validator.validateMagicBytes("photo.png", PNG).valid, true);
  });

  it("refuses a name that disagrees with the content", function () {
    var r = validator.validateMagicBytes("photo.png", GIF);
    assert.strictEqual(r.valid, false);
    assert.match(r.reason, /does not match \.png/);
  });

  it("refuses content it cannot identify at all under a checked extension", function () {
    var r = validator.validateMagicBytes("photo.png", padded(bytes(0x11, 0x22, 0x33, 0x44)));
    assert.strictEqual(r.valid, false);
  });

  it("skips an extension that has no signature to check", function () {
    // A text format has no magic bytes; refusing it for "not matching" would
    // reject every ordinary .txt upload.
    assert.strictEqual(validator.validateMagicBytes("notes.txt", GIF).valid, true);
    assert.strictEqual(validator.validateMagicBytes("data.csv", GIF).valid, true);
  });

  it("refuses a checked extension whose file is too small to identify", function () {
    var r = validator.validateMagicBytes("tiny.png", bytes(0x89, 0x50, 0x4E, 0x47));
    assert.strictEqual(r.valid, false);
    assert.match(r.reason, /too small/i);
  });

  it("treats the two JPEG spellings as one format", function () {
    var JPG = padded(bytes(0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46));
    assert.strictEqual(validator.validateMagicBytes("a.jpg", JPG).valid, true);
    assert.strictEqual(validator.validateMagicBytes("a.jpeg", JPG).valid, true);
  });

  it("accepts the Office containers for what they actually are", function () {
    // OOXML is a ZIP; the legacy formats are OLE2 compound files. Both sides
    // fold through the compatibility map, and getting that wrong rejects every
    // document upload.
    [".docx", ".xlsx", ".pptx"].forEach(function (ext) {
      assert.strictEqual(validator.validateMagicBytes("report" + ext, ZIP).valid, true, ext);
    });
    [".doc", ".xls", ".ppt"].forEach(function (ext) {
      assert.strictEqual(validator.validateMagicBytes("report" + ext, OLE2).valid, true, ext);
    });
  });

  it("refuses a legacy Office name carrying OOXML bytes, and the reverse", function () {
    assert.strictEqual(validator.validateMagicBytes("report.doc", ZIP).valid, false);
    assert.strictEqual(validator.validateMagicBytes("report.docx", OLE2).valid, false);
  });

  it("accepts .tar.gz as gzip", function () {
    // extname() sees ".gz" here, and the compatibility map folds ".tar.gz" too;
    // both spellings have to reach the same answer.
    assert.strictEqual(validator.validateMagicBytes("backup.tar.gz", GZ).valid, true);
    assert.strictEqual(validator.validateMagicBytes("backup.gz", GZ).valid, true);
  });

  it("passes when either argument is absent", function () {
    // The caller has nothing to check; refusing here would fail uploads that
    // never claimed an extension.
    assert.strictEqual(validator.validateMagicBytes(null, PNG).valid, true);
    assert.strictEqual(validator.validateMagicBytes("photo.png", null).valid, true);
  });
});

describe("archive inspection follows the bytes, not the name", function () {
  // A 22-byte end-of-central-directory record is a valid empty ZIP.
  var EMPTY_ZIP = Buffer.concat([Buffer.from([0x50, 0x4B, 0x05, 0x06]), Buffer.alloc(18)]);

  it("inspects an archive whose extension says it is something else", async function () {
    // The property that matters: renaming an archive must not route it past the
    // guard. If this ever starts gating on the extension, a zip bomb named
    // .pdf walks through and every test here still passes but this one.
    var asZip = await validator.validateArchive("bundle.zip", EMPTY_ZIP);
    var asPdf = await validator.validateArchive("bundle.pdf", EMPTY_ZIP);
    var asNothing = await validator.validateArchive("", EMPTY_ZIP);
    assert.deepStrictEqual(asPdf, asZip,
      "the verdict must not depend on what the file was called");
    assert.deepStrictEqual(asNothing, asZip,
      "nor on there being a name at all");
  });

  it("leaves a non-archive alone", async function () {
    var png = padded(bytes(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A));
    assert.strictEqual((await validator.validateArchive("photo.png", png)).valid, true);
  });

  it("refuses an archive whose structure cannot be read", async function () {
    // The magic says zip; the directory is nonsense. Accepting what could not be
    // read is how an archive gets past a check a real extractor would open.
    var brokenZip = Buffer.concat([
      Buffer.from([0x50, 0x4B, 0x03, 0x04]), Buffer.alloc(120, 0xFF),
    ]);
    var r = await validator.validateArchive("broken.zip", brokenZip);
    assert.strictEqual(r.valid, false);
    assert.match(r.reason, /could not be read/i);
  });

  it("passes a buffer too small to be an archive", async function () {
    assert.strictEqual((await validator.validateArchive("x.zip", Buffer.alloc(4))).valid, true);
    assert.strictEqual((await validator.validateArchive("x.zip", null)).valid, true);
  });
});

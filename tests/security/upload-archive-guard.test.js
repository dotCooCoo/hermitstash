"use strict";

/**
 * Uploaded archives are inspected, not just sniffed.
 *
 * validateMagicBytes establishes that a file claiming to be a .zip is one. It
 * says nothing about what is inside. This server never extracts an upload, so a
 * traversal path cannot hurt the server — but the archive is served back to
 * whoever downloads it, and they extract it. Refusing here is refusing to pass
 * the attack on.
 *
 * The cases that matter are in both directions, and the false-rejection half is
 * the one that would actually be noticed: an Office document is a zip, and
 * refusing .docx would break ordinary use of a file-sharing service.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert");
var stream = require("node:stream");
var b = require("../../lib/vendor/blamejs");
var uploadValidator = require("../../app/http/validators/upload.validator");

function zipOf(paths) {
  var z = b.archive.zip();
  paths.forEach(function (p) { z.addFile(p, Buffer.from("x")); });
  return new Promise(function (resolve, reject) {
    var chunks = [];
    var sink = new stream.Writable({ write: function (c, e, cb) { chunks.push(c); cb(); } });
    sink.on("error", reject);
    z.toStream(sink).then(function () { resolve(Buffer.concat(chunks)); }, reject);
  });
}

// Hand-built because the framework's own writer refuses a `..` segment — which
// is the point: this entry cannot be produced by the writer, only received.
function zipWithRawEntryName(name) {
  var nameBuf = Buffer.from(name, "utf8");
  var data = Buffer.from("x", "utf8");
  var lf = Buffer.alloc(30);
  lf.writeUInt32LE(0x04034b50, 0); lf.writeUInt16LE(20, 4);
  lf.writeUInt32LE(data.length, 18); lf.writeUInt32LE(data.length, 22);
  lf.writeUInt16LE(nameBuf.length, 26);
  var local = Buffer.concat([lf, nameBuf, data]);
  var cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6);
  cd.writeUInt32LE(data.length, 20); cd.writeUInt32LE(data.length, 24);
  cd.writeUInt16LE(nameBuf.length, 28); cd.writeUInt32LE(0, 42);
  var central = Buffer.concat([cd, nameBuf]);
  var eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(central.length, 12); eocd.writeUInt32LE(local.length, 16);
  return Buffer.concat([local, central, eocd]);
}

describe("uploaded archives are inspected for hostile entries", function () {
  it("refuses an entry that escapes the extraction directory", async function () {
    var buf = zipWithRawEntryName("../../etc/passwd");
    var res = await uploadValidator.validateArchive("payload.zip", buf);
    assert.equal(res.valid, false, "a zip-slip entry must be refused");
    assert.match(res.detail || "", /zip-slip|traversal/i,
      "the audit detail should name what was wrong, got: " + res.detail);
  });

  it("does not return the attacker's entry name to the uploader", async function () {
    var res = await uploadValidator.validateArchive("payload.zip", zipWithRawEntryName("../../etc/passwd"));
    assert.equal(res.valid, false);
    assert.ok(res.reason.indexOf("..") === -1 && res.reason.indexOf("passwd") === -1,
      "the message shown to the uploader must not echo attacker-authored text: " + res.reason);
  });

  it("accepts an Office document, which is a zip", async function () {
    // Every .docx/.xlsx/.pptx has this shape. Refusing it would break ordinary
    // use of the product, which is the failure this test exists to prevent.
    var buf = await zipOf(["[Content_Types].xml", "_rels/.rels", "word/document.xml",
                           "word/_rels/document.xml.rels", "docProps/core.xml"]);
    var res = await uploadValidator.validateArchive("report.docx", buf);
    assert.equal(res.valid, true, "an OOXML layout must pass: " + JSON.stringify(res));
  });

  it("accepts an ordinary folder archive and a source tree with dotfiles", async function () {
    var folder = await zipOf(["report/summary.txt", "report/data/q1.csv"]);
    assert.equal((await uploadValidator.validateArchive("r.zip", folder)).valid, true);
    var source = await zipOf([".gitignore", ".github/workflows/ci.yml", "src/deep/nested/f.js"]);
    assert.equal((await uploadValidator.validateArchive("s.zip", source)).valid, true);
  });

  it("accepts an ordinary archive with more than a hundred files", async function () {
    // The guard's bare defaults are its STRICT profile, which caps an archive at
    // 100 entries. Calling it with no options therefore refused any project zip
    // or photo folder past that — a false rejection that the small fixtures in
    // the tests above could never have surfaced, because none of them had
    // enough files to reach the cap.
    var many = [];
    for (var i = 0; i < 150; i++) many.push("src/module" + i + ".js");
    var res = await uploadValidator.validateArchive("project.zip", await zipOf(many));
    assert.equal(res.valid, true, "a 150-file archive is ordinary and must pass: " + JSON.stringify(res));
  });

  it("passes through anything that is not a readable archive", async function () {
    // A PNG, and a format with no reader here (.7z/.rar are magic-checked but
    // their contents cannot be walked). Neither should be refused BY THIS check.
    var png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(64)]);
    assert.equal((await uploadValidator.validateArchive("a.png", png)).valid, true);
    assert.equal((await uploadValidator.validateArchive("tiny.zip", Buffer.from("PK"))).valid, true);
  });

  it("inspects a gzipped tar, which reports its own magic and not the tar inside", async function () {
    // .tar.gz and .gz are accepted extensions. A gzip stream's magic says
    // "gzip", so a guard that only knew zip and tar would let "compress the tar
    // first" walk straight past it — the guard would look present and cover
    // nothing for a whole accepted format.
    var zlib = require("node:zlib");
    var tar = b.archive.tar();
    tar.addFile("safe/notes.txt", Buffer.from("x"));
    var tarBuf = await new Promise(function (resolve, reject) {
      var chunks = [];
      var sink = new stream.Writable({ write: function (c, e, cb) { chunks.push(c); cb(); } });
      sink.on("error", reject);
      tar.toStream(sink).then(function () { resolve(Buffer.concat(chunks)); }, reject);
    });
    var gz = zlib.gzipSync(tarBuf);
    assert.equal(b.guardArchive.inspectMagic(gz).format, "gzip",
      "precondition: a gzipped tar must report gzip, not tar");
    var res = await uploadValidator.validateArchive("bundle.tar.gz", gz);
    assert.equal(res.valid, true, "a benign gzipped tar must pass: " + JSON.stringify(res));
  });

  it("refuses a traversal entry hidden inside a gzipped tar", async function () {
    // The case that matters: "compress the tar first" was a way past the guard
    // entirely, because a gzip stream's magic says gzip and the tar is only
    // visible after decompression. Hand-built, since the tar writer refuses the
    // name — as with the zip case, this entry can only be received, not authored.
    var zlib = require("node:zlib");
    var header = Buffer.alloc(512, 0);
    header.write("../../etc/passwd", 0, "utf8");          // name[100]
    header.write("0000644\0", 100, "utf8");               // mode
    header.write("0000000\0", 108, "utf8");               // uid
    header.write("0000000\0", 116, "utf8");               // gid
    header.write("00000000001\0", 124, "utf8");           // size = 1 octal
    header.write("00000000000\0", 136, "utf8");           // mtime
    header.write("        ", 148, "utf8");                // chksum: spaces while summing
    header.write("0", 156, "utf8");                       // typeflag: regular file
    header.write("ustar\0", 257, "utf8");                 // magic
    header.write("00", 263, "utf8");                      // version
    var sum = 0;
    for (var i = 0; i < 512; i++) sum += header[i];
    header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "utf8");
    var body = Buffer.alloc(512, 0);
    body.write("x", 0, "utf8");
    var tarBuf = Buffer.concat([header, body, Buffer.alloc(1024, 0)]); // + end-of-archive
    var gz = zlib.gzipSync(tarBuf);

    assert.equal(b.guardArchive.inspectMagic(gz).format, "gzip",
      "precondition: the hostile tar must be disguised as gzip");
    var res = await uploadValidator.validateArchive("payload.tar.gz", gz);
    assert.equal(res.valid, false,
      "a traversal entry inside a .tar.gz must be refused, not waved through: " + JSON.stringify(res));
  });

  it("refuses a traversal entry in a legacy tar that carries no ustar marker", async function () {
    // A V7 tar header has no "ustar" magic at offset 257. Magic-byte sniffing
    // therefore identifies nothing, and a guard that keys only on the sniff
    // waves the file through — while ordinary extractors read V7 quite happily.
    var header = Buffer.alloc(512, 0);
    header.write("../../etc/passwd", 0, "utf8");
    header.write("0000644\0", 100, "utf8");
    header.write("0000000\0", 108, "utf8");
    header.write("0000000\0", 116, "utf8");
    header.write("00000000001\0", 124, "utf8");
    header.write("00000000000\0", 136, "utf8");
    header.write("        ", 148, "utf8");
    header.write("0", 156, "utf8");
    // deliberately NO ustar magic / version — this is the V7 shape
    var sum = 0;
    for (var i = 0; i < 512; i++) sum += header[i];
    header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "utf8");
    var body = Buffer.alloc(512, 0);
    body.write("x", 0, "utf8");
    var v7 = Buffer.concat([header, body, Buffer.alloc(1024, 0)]);

    var res = await uploadValidator.validateArchive("legacy.tar", v7);
    assert.equal(res.valid, false,
      "a V7 tar carrying a traversal entry must not pass merely because it has no ustar marker: " + JSON.stringify(res));
  });

  it("refuses a symlink entry pointing outside the archive", async function () {
    // The readers describe a link as typeflag/linkname; the guard looks for
    // isSymlink/linkTarget. Handing the reader's own shape over leaves the link
    // checks inert — the guard returns ok and the protection exists only in the
    // release note. This is the case that catches that.
    function tarEntry(name, typeflag, linkname) {
      var h = Buffer.alloc(512, 0);
      h.write(name, 0, "utf8");
      h.write("0000777\0", 100, "utf8");
      h.write("0000000\0", 108, "utf8");
      h.write("0000000\0", 116, "utf8");
      h.write("00000000000\0", 124, "utf8");   // size 0 — a link carries no body
      h.write("00000000000\0", 136, "utf8");
      h.write("        ", 148, "utf8");
      h.write(typeflag, 156, "utf8");
      if (linkname) h.write(linkname, 157, "utf8");
      h.write("ustar\0", 257, "utf8");
      h.write("00", 263, "utf8");
      var sum = 0;
      for (var i = 0; i < 512; i++) sum += h[i];
      h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "utf8");
      return h;
    }
    var tarBuf = Buffer.concat([tarEntry("innocent-looking", "2", "../../../etc/passwd"),
                                Buffer.alloc(1024, 0)]);
    var res = await uploadValidator.validateArchive("links.tar", tarBuf);
    assert.equal(res.valid, false,
      "a symlink escaping the archive must be refused: " + JSON.stringify(res));
    // Refused AS A SYMLINK, not incidentally as an unreadable archive — the
    // difference between the link check working and the archive merely failing
    // to parse for some other reason.
    assert.match(res.detail || "", /symlink/i,
      "expected a symlink finding, got: " + res.detail);
  });

  it("accepts a plain .gz holding a single file, not a tar", async function () {
    // .gz is an accepted extension and gzipping one document is ordinary. There
    // is no entry list to inspect, so there is nothing to refuse — treating it
    // as an unreadable archive would reject a whole legitimate upload shape.
    var zlib = require("node:zlib");
    var gz = zlib.gzipSync(Buffer.from("just a document, no tar in sight\n".repeat(20)));
    var res = await uploadValidator.validateArchive("notes.txt.gz", gz);
    assert.equal(res.valid, true, "a single-file gzip must pass: " + JSON.stringify(res));
  });

  it("refuses a malformed tar inside a gzip instead of calling it a plain file", async function () {
    // The trap when adding single-file .gz support: if any tar-read failure is
    // read as "this was not a tar", then a tar that is deliberately malformed —
    // or one that trips the entry cap — is accepted as an ordinary compressed
    // file and skips inspection entirely. Tar-ness has to be decided before
    // parsing, so a parse failure on a real tar still refuses.
    var zlib = require("node:zlib");
    var h = Buffer.alloc(512, 0);
    h.write("file.txt", 0, "utf8");
    h.write("        ", 148, "utf8");
    h.write("ustar\0", 257, "utf8");
    var sum = 0;
    for (var i = 0; i < 512; i++) sum += h[i];
    h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "utf8");
    // Valid header, then garbage where the next header belongs.
    var broken = Buffer.concat([h, Buffer.alloc(512, 0x41), Buffer.from("not-a-header-at-all")]);
    var res = await uploadValidator.validateArchive("crafted.tar.gz", zlib.gzipSync(broken));
    assert.equal(res.valid, false,
      "a malformed tar inside a gzip must be refused, not accepted as a plain file: " + JSON.stringify(res));
  });

  it("refuses an archive it cannot read rather than passing it through", async function () {
    // Magic says zip; the structure is nonsense. Accepting what we could not
    // walk is how a crafted archive gets past a check that a real extractor
    // will happily open.
    var junk = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(400, 0xab)]);
    var res = await uploadValidator.validateArchive("broken.zip", junk);
    assert.equal(res.valid, false, "an unreadable archive must be refused, got: " + JSON.stringify(res));
  });

  it("refuses a small gzip that expands past the inspection ceiling", async function () {
    // Inspecting a .gz means materialising the decompressed bytes. Left on the
    // framework's 1 GiB default, a few hundred KB of upload could allocate a
    // gigabyte per concurrent request on top of the plaintext the handler is
    // already holding — a memory-exhaustion path reachable by anyone who can
    // upload. Refusing as un-inspectable is the deliberate trade: a genuinely
    // huge archive is turned away rather than inspected at any cost.
    var zlib = require("node:zlib");
    var gz = zlib.gzipSync(Buffer.alloc(300 * 1024 * 1024, 0x41)); // ~300 KB -> 300 MiB
    assert.ok(gz.length < 5 * 1024 * 1024, "precondition: the compressed form is small");
    var res = await uploadValidator.validateArchive("bomb.gz", gz);
    assert.equal(res.valid, false,
      "a gzip expanding past the inspection ceiling must be refused: " + JSON.stringify(res));
  });

  it("refuses a link whose destination cannot be read", async function () {
    // A tar names a link's destination in the header, so the escape check can
    // run. A ZIP keeps it in the entry body and the reader's entry list has no
    // field for it — the guard is handed nothing, objects to nothing, and
    // returns ok. Without this the ZIP symlink case would silently pass the
    // very check the tar case proves works.
    var uv = uploadValidator;
    assert.equal(typeof uv.validateArchive, "function");
    // Drive the projection directly: an entry marked as a link with no target
    // is the shape a ZIP symlink produces.
    var tarBuf = (function () {
      var h = Buffer.alloc(512, 0);
      h.write("linky", 0, "utf8");
      h.write("0000777\0", 100, "utf8");
      h.write("0000000\0", 108, "utf8");
      h.write("0000000\0", 116, "utf8");
      h.write("00000000000\0", 124, "utf8");
      h.write("00000000000\0", 136, "utf8");
      h.write("        ", 148, "utf8");
      h.write("2", 156, "utf8");          // symlink typeflag, EMPTY linkname
      h.write("ustar\0", 257, "utf8");
      h.write("00", 263, "utf8");
      var s = 0;
      for (var i = 0; i < 512; i++) s += h[i];
      h.write(s.toString(8).padStart(6, "0") + "\0 ", 148, "utf8");
      return Buffer.concat([h, Buffer.alloc(1024, 0)]);
    })();
    var res = await uv.validateArchive("blind.tar", tarBuf);
    assert.equal(res.valid, false,
      "a link with no readable destination must be refused: " + JSON.stringify(res));
    assert.match(res.detail || "", /link-target-unreadable|symlink/i,
      "expected the unreadable-link finding, got: " + res.detail);
  });

  it("is reached by BOTH ingest paths", function () {
    // A guard on one path only is the way in. Pin that both call sites exist
    // rather than trusting that a future path remembers to call it.
    var src = require("node:fs").readFileSync(
      require("node:path").join(__dirname, "..", "..", "app", "domain", "uploads", "upload.handler.js"), "utf8");
    var calls = src.match(/validateArchive\(/g) || [];
    assert.ok(calls.length >= 2,
      "expected validateArchive on both the single-shot and chunked paths; found " + calls.length);
  });
});

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.hashFile + b.crypto.hashStream — streaming digest from
 * disk and arbitrary Readables. Exercises algorithm allowlist,
 * buffer-shaped digest output, and round-trip equivalence with
 * the synchronous hash path.
 */

var fs   = require("fs");
var os   = require("os");
var path = require("path");
var nodeCrypto = require("crypto");
var { Readable } = require("stream");

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  // ---- Surface ----
  check("crypto.hashFile is fn",   typeof b.crypto.hashFile === "function");
  check("crypto.hashStream is fn", typeof b.crypto.hashStream === "function");

  // ---- Default algorithm = sha3-512 → 64-byte digest ----
  var tmp = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-hashfile-")), "payload.txt");
  var payload = "hello blamejs streaming hash";
  fs.writeFileSync(tmp, payload);

  try {
    var fileDigest = await b.crypto.hashFile(tmp);
    check("hashFile returns Buffer",                 Buffer.isBuffer(fileDigest));
    check("hashFile sha3-512 default → 64 bytes",    fileDigest.length === 64);

    // Cross-check against direct nodeCrypto SHA3-512 of the same bytes.
    var expected = nodeCrypto.createHash("sha3-512").update(payload).digest();
    check("hashFile digest matches direct sha3-512", fileDigest.equals(expected));

    // ---- Explicit algorithm: sha512 (interop) ----
    var sha512Digest = await b.crypto.hashFile(tmp, "sha512");
    check("hashFile sha512 → 64 bytes",              sha512Digest.length === 64);
    check("hashFile sha512 differs from sha3-512",   !sha512Digest.equals(fileDigest));

    // ---- hashStream over a synthetic Readable ----
    var streamDigest = await b.crypto.hashStream(Readable.from([Buffer.from(payload)]));
    check("hashStream digest matches hashFile",      streamDigest.equals(fileDigest));

    // ---- shake256 produces 64-byte digest by default ----
    var shakeDigest = await b.crypto.hashStream(Readable.from([Buffer.from(payload)]), "shake256");
    check("hashStream shake256 → 64 bytes",          shakeDigest.length === 64);

    // ---- Algorithm allowlist rejects md5/sha1/sha256 ----
    var weakErr;
    try { await b.crypto.hashStream(Readable.from(["x"]), "md5"); }
    catch (e) { weakErr = e; }
    check("hashStream rejects md5",                  weakErr && /unsupported algorithm/.test(weakErr.message));

    var sha1Err;
    try { await b.crypto.hashFile(tmp, "sha1"); }
    catch (e) { sha1Err = e; }
    check("hashFile rejects sha1",                   sha1Err && /unsupported algorithm/.test(sha1Err.message));

    var sha256Err;
    try { await b.crypto.hashFile(tmp, "sha256"); }
    catch (e) { sha256Err = e; }
    check("hashFile rejects sha256",                 sha256Err && /unsupported algorithm/.test(sha256Err.message));

    // ---- Bad arg: empty path ----
    var badPathErr;
    try { await b.crypto.hashFile(""); }
    catch (e) { badPathErr = e; }
    check("hashFile rejects empty path",             badPathErr instanceof TypeError);

    // ---- Bad arg: non-stream readable ----
    var badStreamErr;
    try { await b.crypto.hashStream({ not: "a stream" }); }
    catch (e) { badStreamErr = e; }
    check("hashStream rejects non-stream",           badStreamErr instanceof TypeError);

    // ---- Missing file → rejection (not silent default) ----
    var missingErr;
    try { await b.crypto.hashFile(tmp + ".does-not-exist"); }
    catch (e) { missingErr = e; }
    check("hashFile rejects missing path",           !!missingErr);
  } finally {
    try { fs.unlinkSync(tmp); } catch (_e) { /* best-effort cleanup */ }
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () {
    console.log("OK — crypto.hashFile / hashStream — " + helpers.getChecks() + " checks");
  }, function (e) {
    console.error(e && e.stack || e);
    process.exit(1);
  });
}

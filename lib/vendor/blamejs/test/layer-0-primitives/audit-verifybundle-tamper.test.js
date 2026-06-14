"use strict";
/**
 * b.auditTools.verifyBundle — tamper detection on a REAL archive bundle.
 *
 * The clean path only runs incidentally inside purge(); the only other
 * bundle test seeds fake dummy hashes and never drives verifyBundle, so
 * the rows-checksum-mismatch (rows.enc / manifest checksum) and
 * checkpoint-signature-failed branches were unproven.
 *
 * This test builds a real bundle the production way: seed audit rows
 * through the chain writer, anchor a covering SLH-DSA checkpoint, then
 * archive() to disk. It first proves verifyBundle(clean) -> { ok: true },
 * then for each independent tamper proves the bundle is REJECTED — either
 * a typed read-time throw or { ok: false }:
 *
 *   (1) flip a byte in rows.enc                  -> checksum guard
 *   (2) corrupt manifest.checksum.rowsSha3_512   -> manifest checksum guard
 *   (3) corrupt the covering checkpoint's
 *       SLH-DSA signature (manifest checksum kept
 *       consistent so the signature branch is the
 *       thing under test)                        -> signature verify
 *
 * Every tamper operates on a fresh copy of the clean bundle so the
 * cases stay independent and a missed catch is unambiguous.
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

var backupCrypto = require("../../lib/backup/crypto");

var PASS = Buffer.from("operator-bundle-passphrase-not-secret");

async function _seedAuditRows(count) {
  b.audit.registerNamespace("test");
  for (var i = 0; i < count; i++) {
    await b.audit.record({
      actor:    { userId: "u-" + i },
      action:   "test.seeded",
      outcome:  "success",
      metadata: { i: i },
    });
  }
  // Drain the chain writer so every row is durable before we archive.
  await b.audit.flush();
}

// Recursively copy a bundle directory so each tamper works on a fresh,
// independent clean bundle.
function _copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  var entries = fs.readdirSync(src, { withFileTypes: true });
  for (var i = 0; i < entries.length; i++) {
    var ent = entries[i];
    var s = path.join(src, ent.name);
    var d = path.join(dest, ent.name);
    if (ent.isDirectory()) _copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

// Drive verifyBundle and normalize the two legitimate rejection shapes
// (typed read-time throw OR { ok:false }) into a single descriptor so
// each tamper case can assert "rejected" uniformly.
async function _verify(dir) {
  try {
    var res = await b.auditTools.verifyBundle({ in: dir, passphrase: PASS });
    return { rejected: res.ok === false, threw: false, ok: res.ok, reason: res.reason, kind: res.kind, result: res };
  } catch (e) {
    return { rejected: true, threw: true, code: e && e.code, message: e && e.message };
  }
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vb-tamper-"));
  try {
    await setupTestDb(dir);
    await _seedAuditRows(6);
    var ckpt = await b.audit.checkpoint();
    check("a covering checkpoint was anchored", ckpt && ckpt.atMonotonicCounter >= 6);

    var cleanDir = path.join(dir, "bundles", "archive-clean");
    var arch = await b.auditTools.archive({
      before:     Date.now() + 60000,
      out:        cleanDir,
      passphrase: PASS,
    });
    check("archive produced an archive-kind bundle", arch.manifest.kind === "archive");
    check("archive carried the seeded rows", arch.rowCount >= 6);

    // The bundle must physically be the 3-file archive shape.
    check("clean bundle has rows.enc",       fs.existsSync(path.join(cleanDir, "rows.enc")));
    check("clean bundle has checkpoint.enc", fs.existsSync(path.join(cleanDir, "checkpoint.enc")));
    check("clean bundle has manifest.json",  fs.existsSync(path.join(cleanDir, "manifest.json")));

    // ---- Baseline: the clean bundle verifies ok. ----
    var clean = await _verify(cleanDir);
    check("clean bundle: verifyBundle -> { ok: true }", clean.threw === false && clean.ok === true);
    check("clean bundle: kind is archive", clean.kind === "archive");
    check("clean bundle: rowsVerified covers the slice", clean.result.rowsVerified >= 6);

    // ---- Tamper 1: flip a byte in rows.enc. ----
    var t1 = path.join(dir, "bundles", "tamper-rows");
    _copyDir(cleanDir, t1);
    var rowsPath = path.join(t1, "rows.enc");
    var rowsBuf = fs.readFileSync(rowsPath);
    // Flip the last byte (inside the ciphertext / auth tag, well past the
    // nonce) so the manifest checksum over the file no longer matches.
    var before1 = rowsBuf[rowsBuf.length - 1];
    rowsBuf[rowsBuf.length - 1] = before1 ^ 0xff;
    fs.writeFileSync(rowsPath, rowsBuf);
    check("tamper-rows: rows.enc byte actually changed",
      fs.readFileSync(rowsPath)[rowsBuf.length - 1] !== before1);
    var r1 = await _verify(t1);
    check("tamper-rows: bundle is REJECTED (typed throw or { ok:false })", r1.rejected === true);
    check("tamper-rows: failure points at the rows blob tamper",
      (r1.threw && r1.code === "audit-tools/rows-checksum-mismatch") ||
      (r1.threw && /tamper|checksum|decrypt/i.test(r1.message || "")) ||
      (!r1.threw && /chain|rowHash|checksum/i.test(r1.reason || "")));

    // ---- Tamper 2: corrupt the manifest's rows checksum. ----
    var t2 = path.join(dir, "bundles", "tamper-manifest");
    _copyDir(cleanDir, t2);
    var m2Path = path.join(t2, "manifest.json");
    var m2 = JSON.parse(fs.readFileSync(m2Path, "utf8"));
    var origChecksum = m2.checksum.rowsSha3_512;
    // Flip one hex nibble so the stored checksum no longer matches the
    // (untouched) rows.enc bytes.
    var firstChar = origChecksum.charAt(0);
    var swapped = firstChar === "0" ? "1" : "0";
    m2.checksum.rowsSha3_512 = swapped + origChecksum.slice(1);
    fs.writeFileSync(m2Path, JSON.stringify(m2));
    check("tamper-manifest: manifest checksum actually changed",
      JSON.parse(fs.readFileSync(m2Path, "utf8")).checksum.rowsSha3_512 !== origChecksum);
    var r2 = await _verify(t2);
    check("tamper-manifest: bundle is REJECTED (typed throw or { ok:false })", r2.rejected === true);
    check("tamper-manifest: failure points at the manifest/rows checksum mismatch",
      (r2.threw && r2.code === "audit-tools/rows-checksum-mismatch") ||
      (r2.threw && /tamper|checksum/i.test(r2.message || "")) ||
      (!r2.threw && /checksum|chain|rowHash/i.test(r2.reason || "")));

    // ---- Tamper 3: corrupt the covering checkpoint's SLH-DSA signature. ----
    // Decrypt checkpoint.enc, flip a byte inside the signature, re-encrypt
    // with a fresh salt, and update BOTH manifest.salts.checkpoint and
    // manifest.checksum.checkpointSha3_512 so the checkpoint-checksum guard
    // passes — isolating the signature-verification branch as the thing
    // that must reject the forged checkpoint.
    var t3 = path.join(dir, "bundles", "tamper-sig");
    _copyDir(cleanDir, t3);
    var m3Path = path.join(t3, "manifest.json");
    var m3 = JSON.parse(fs.readFileSync(m3Path, "utf8"));
    var ckptEncPath = path.join(t3, "checkpoint.enc");
    var ckptEnc = fs.readFileSync(ckptEncPath);
    var ckptPlain = (await backupCrypto.decryptWithPassphrase(
      ckptEnc, PASS, m3.salts.checkpoint)).toString("utf8");
    var ckptWire = JSON.parse(ckptPlain);
    check("tamper-sig: checkpoint wire form carries a hex signature",
      typeof ckptWire.signature === "string" && ckptWire.signature.indexOf("hex:") === 0);
    // Flip the final hex nibble of the signature — keeps it valid hex /
    // same length, but the SLH-DSA verify must fail.
    var sigHex = ckptWire.signature;
    var lastNibble = sigHex.charAt(sigHex.length - 1);
    var newNibble = lastNibble === "0" ? "1" : "0";
    var tamperedSigHex = sigHex.slice(0, -1) + newNibble;
    check("tamper-sig: signature hex actually changed", tamperedSigHex !== sigHex);
    ckptWire.signature = tamperedSigHex;
    // The bundle canonicalizes checkpoint JSON; plain JSON.stringify here
    // is fine — verifyBundle re-decrypts + re-parses, it doesn't compare
    // the checkpoint blob byte-for-byte against the manifest beyond the
    // checksum we recompute below.
    var reEnc = await backupCrypto.encryptWithFreshSalt(JSON.stringify(ckptWire), PASS);
    fs.writeFileSync(ckptEncPath, reEnc.encrypted);
    m3.salts.checkpoint = reEnc.salt;
    m3.checksum.checkpointSha3_512 = backupCrypto.checksum(reEnc.encrypted);
    fs.writeFileSync(m3Path, JSON.stringify(m3));

    var r3 = await _verify(t3);
    check("tamper-sig: bundle is REJECTED (typed throw or { ok:false })", r3.rejected === true);
    check("tamper-sig: failure is the checkpoint signature verification, not an earlier guard",
      (!r3.threw && /signature/i.test(r3.reason || "")) ||
      (r3.threw && /signature/i.test(r3.message || "")));
    // Stronger: the signature branch returns { ok:false } (not a throw),
    // and the chain math + checksums all passed to get there.
    check("tamper-sig: reached the signature branch via a clean read (ok:false, not a throw)",
      r3.threw === false && r3.ok === false &&
      /signature/i.test(r3.reason || ""));

    console.log("OK — audit verifyBundle tamper-detection (" + helpers.getChecks() + " checks)");
  } finally {
    await teardownTestDb(dir);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

module.exports = { run: run };

if (require.main === module) {
  // Rethrow on failure so Node exits non-zero; logging the caught error
  // would let a taint analyzer trace it back to the non-secret passphrase
  // fixture and raise a false clear-text-logging alert.
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}

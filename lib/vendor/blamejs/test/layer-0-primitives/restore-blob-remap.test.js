// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.restore — blob-remap / signature-enforcement integrity (CWE-347).
 *
 * The documented attack: an attacker with write access to a bundle in storage
 * copies one valid blob over another manifest entry (reusing its
 * salt/checksum/size), strips manifest.signature, and restore.run() applies
 * it with NO integrity error — writing one file's plaintext into another's
 * slot (e.g. db.enc's bytes into db.key.enc). Two defenses:
 *   1. each blob is sealed with its relativePath as AEAD associated data, so a
 *      remapped blob fails the Poly1305 tag on restore (manifest.aadBound);
 *   2. restore.create accepts a requireSignature policy (threaded into
 *      extract) operators opt into to mandate a verified signer.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;

function _seed() {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-remap-"));
  var dataDir = path.join(root, "data");
  fs.mkdirSync(dataDir);
  fs.writeFileSync(path.join(dataDir, "db.enc"), "ORIG-DB-CONTENT");
  fs.writeFileSync(path.join(dataDir, "db.key.enc"), "SEALED-DEK");
  return { root: root, dataDir: dataDir, storageRoot: path.join(root, "store") };
}

async function run() {
  var pp = Buffer.from("operator-passphrase-not-secret");

  // --- Build a bundle. ---
  var fx = _seed();
  try {
    function storage() { return b.backup.diskStorage({ root: fx.storageRoot }); }
    var r = await b.backup.create({
      dataDir: fx.dataDir, storage: storage(), passphrase: pp,
      files: [
        { relativePath: "db.enc",     kind: "raw", required: true },
        { relativePath: "db.key.enc", kind: "raw", required: true },
      ],
      vaultKeyJson: '{"vault":"orig"}', audit: false,
    }).run();
    var bdir = path.join(fx.storageRoot, r.bundleId);
    var manifest = JSON.parse(fs.readFileSync(path.join(bdir, "manifest.json"), "utf8"));
    check("backup: new bundle is marked aadBound", manifest.aadBound === true);

    // --- Clean round-trip still restores (no regression). ---
    fs.writeFileSync(path.join(fx.dataDir, "db.enc"), "MUTATED");
    var rr = await b.restore.create({
      dataDir: fx.dataDir, storage: storage(), passphrase: pp,
      rollbackRoot: path.join(fx.root, "rb"), audit: false,
    }).run({ bundleId: r.bundleId });
    check("restore: clean round-trip succeeds", rr.fileCount === 2);
    check("restore: db.enc restored to bundle bytes",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "ORIG-DB-CONTENT");

    // --- Blob-remap attack: point db.key.enc's entry at db.enc's blob
    // (reuse its salt/checksum/size), strip the signature, restore. ---
    var dbEnc = manifest.files.filter(function (f) { return f.relativePath === "db.enc"; })[0];
    var dbKey = manifest.files.filter(function (f) { return f.relativePath === "db.key.enc"; })[0];
    dbKey.encryptedPath = dbEnc.encryptedPath;
    dbKey.salt          = dbEnc.salt;
    dbKey.checksum      = dbEnc.checksum;
    dbKey.size          = dbEnc.size;
    dbKey.encryptedSize = dbEnc.encryptedSize;
    delete manifest.signature;
    fs.writeFileSync(path.join(bdir, "manifest.json"), JSON.stringify(manifest));

    var threw = null;
    try {
      await b.restore.create({
        dataDir: fx.dataDir, storage: storage(), passphrase: pp,
        rollbackRoot: path.join(fx.root, "rb2"), audit: false,
      }).run({ bundleId: r.bundleId });
    } catch (e) { threw = e; }
    check("restore: blob-remap attack is REFUSED (AEAD path-binding)",
          threw && /^restore\/(decrypt-failed|extract-failed)$/.test(threw.code || ""));
  } finally {
    fs.rmSync(fx.root, { recursive: true, force: true });
  }

  // --- requireSignature policy: an unsigned bundle is refused when the
  // operator mandates a signature (HIPAA/PCI), and restores when not. ---
  var fx2 = _seed();
  try {
    function storage2() { return b.backup.diskStorage({ root: fx2.storageRoot }); }
    var r2 = await b.backup.create({
      dataDir: fx2.dataDir, storage: storage2(), passphrase: pp,
      files: [{ relativePath: "db.enc", kind: "raw", required: true }],
      vaultKeyJson: '{"vault":"orig"}', audit: false,
    }).run();
    var m2 = JSON.parse(fs.readFileSync(path.join(fx2.storageRoot, r2.bundleId, "manifest.json"), "utf8"));
    check("backup: best-effort bundle is unsigned (no audit-sign)", !m2.signature);

    var threwReq = null;
    try {
      await b.restore.create({
        dataDir: fx2.dataDir, storage: storage2(), passphrase: pp,
        rollbackRoot: path.join(fx2.root, "rb"), audit: false, requireSignature: true,
      }).run({ bundleId: r2.bundleId });
    } catch (e) { threwReq = e; }
    check("restore: requireSignature:true refuses an unsigned bundle",
          threwReq && threwReq.code === "restore/missing-signature");

    // Default (requireSignature not set) restores the unsigned best-effort
    // bundle — the framework's documented CLI/standalone case.
    var okRun = await b.restore.create({
      dataDir: fx2.dataDir, storage: storage2(), passphrase: pp,
      rollbackRoot: path.join(fx2.root, "rb3"), audit: false,
    }).run({ bundleId: r2.bundleId });
    check("restore: default restores an unsigned best-effort bundle", okRun.fileCount === 1);
  } finally {
    fs.rmSync(fx2.root, { recursive: true, force: true });
  }

  console.log("OK — restore blob-remap + signature policy (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}

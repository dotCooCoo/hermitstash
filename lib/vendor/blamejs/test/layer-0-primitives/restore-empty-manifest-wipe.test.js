// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.restore — empty-manifest silent-wipe defense.
 *
 * The bundle writer refuses to emit a bundle with zero file entries
 * (backup-bundle/empty). The shared manifest validator — the guard the
 * restore path relies on when it parses an untrusted / tampered
 * manifest — must mirror that refusal. Otherwise an attacker with write
 * access to an unsigned bundle in storage strips every file entry from
 * the manifest (keeping the legitimate vaultKeyEnc, which still
 * decrypts), and the operator's next restore succeeds with fileCount 0,
 * swapping an EMPTY staging dir into place — a silent destructive wipe
 * of the live dataDir with no error signal.
 *
 * Root: b.backupManifest.validate accepts files: []. Fix it there (the
 * single guard parse() / create() / serialize() all route through) so a
 * zero-entry manifest is refused before it can reach the restore swap.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var fs      = helpers.fs;
var os      = helpers.os;
var path    = helpers.path;

function _validManifestArgs() {
  return {
    vaultKeySalt: "ab12",
    vaultKeyEnc:  Buffer.from("wrapped-vault-key").toString("base64"),
    files: [{
      relativePath:  "db.enc",
      encryptedPath: "files/db.enc.enc",
      size:          10,
      encryptedSize: 50,
      checksum:      "a".repeat(128),
      salt:          "cd34",
      kind:          "raw",
    }],
  };
}

function _seed() {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-empty-manifest-"));
  var dataDir = path.join(root, "data");
  fs.mkdirSync(dataDir);
  fs.writeFileSync(path.join(dataDir, "db.enc"), "ORIG-DB-CONTENT");
  fs.writeFileSync(path.join(dataDir, "db.key.enc"), "SEALED-DEK");
  return { root: root, dataDir: dataDir, storageRoot: path.join(root, "store") };
}

async function run() {
  // --- 1. The shared validator refuses a zero-entry files array. ---
  var argsEmpty = _validManifestArgs();
  argsEmpty.files = [];
  var vEmpty = b.backupManifest.validate({
    version: 1, framework: "blamejs", frameworkVersion: "0.0.0",
    createdAt: new Date().toISOString(),
    vaultKeySalt: argsEmpty.vaultKeySalt, vaultKeyEnc: argsEmpty.vaultKeyEnc,
    files: [],
  });
  check("validate: zero-entry files array is REFUSED",
        vEmpty.ok === false &&
        vEmpty.errors.some(function (e) { return /files/.test(e); }));

  // A non-empty valid manifest still validates (no false-positive).
  var vOk = b.backupManifest.validate(Object.assign(
    { version: 1, framework: "blamejs", frameworkVersion: "0.0.0",
      createdAt: new Date().toISOString() },
    _validManifestArgs()));
  check("validate: non-empty valid manifest still passes", vOk.ok === true);

  // --- 2. parse() of an empty-files manifest throws. ---
  var mkEmptyJson = JSON.stringify({
    version: 1, framework: "blamejs", frameworkVersion: "0.0.0",
    createdAt: new Date().toISOString(),
    vaultKeySalt: "ab12", vaultKeyEnc: Buffer.from("x").toString("base64"),
    files: [],
  });
  var parseThrew = null;
  try { b.backupManifest.parse(mkEmptyJson); } catch (e) { parseThrew = e; }
  check("parse: empty-files manifest is rejected",
        parseThrew && parseThrew.code === "backup-manifest/invalid");

  // --- 3. End-to-end: a tampered empty-files bundle must NOT wipe the
  //        live dataDir; restore must fail-closed. ---
  var pp = Buffer.from("operator-passphrase-not-secret");
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

    // Belt-and-suspenders: a valid (signed, non-empty) bundle restored with an
    // opts.filter that matches NO manifest entry yields a zero-file extract.
    // The manifest parses fine, but swapping the empty staging dir over the
    // live dataDir would wipe it — restore.run must refuse rather than destroy.
    var filterThrew = null;
    try {
      await b.restore.create({
        dataDir: fx.dataDir, storage: storage(), passphrase: pp,
        rollbackRoot: path.join(fx.root, "rb-filter"), audit: false,
      }).run({ bundleId: r.bundleId, filter: function () { return false; } });
    } catch (e) { filterThrew = e; }
    check("restore: a filter matching no manifest entry is REFUSED (no zero-file wipe)",
          filterThrew && filterThrew.code === "restore/empty-extract-refused");
    check("restore: live dataDir INTACT after the refused zero-file filter restore",
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "ORIG-DB-CONTENT" &&
          fs.readFileSync(path.join(fx.dataDir, "db.key.enc")).toString() === "SEALED-DEK");

    var bdir = path.join(fx.storageRoot, r.bundleId);
    var manifest = JSON.parse(fs.readFileSync(path.join(bdir, "manifest.json"), "utf8"));

    // Attacker strips every file entry (keeps the legit vaultKeyEnc that
    // still decrypts under the operator passphrase) and drops the signature.
    manifest.files = [];
    delete manifest.signature;
    fs.writeFileSync(path.join(bdir, "manifest.json"), JSON.stringify(manifest));

    var threw = null;
    try {
      await b.restore.create({
        dataDir: fx.dataDir, storage: storage(), passphrase: pp,
        rollbackRoot: path.join(fx.root, "rb"), audit: false,
      }).run({ bundleId: r.bundleId });
    } catch (e) { threw = e; }

    check("restore: tampered empty-files bundle is REFUSED (fail-closed)",
          threw && /^restore\//.test(threw.code || ""));
    check("restore: live dataDir is INTACT after the refused restore",
          fs.existsSync(path.join(fx.dataDir, "db.enc")) &&
          fs.existsSync(path.join(fx.dataDir, "db.key.enc")) &&
          fs.readFileSync(path.join(fx.dataDir, "db.enc")).toString() === "ORIG-DB-CONTENT");
  } finally {
    fs.rmSync(fx.root, { recursive: true, force: true });
  }

  console.log("OK — restore empty-manifest wipe defense (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}

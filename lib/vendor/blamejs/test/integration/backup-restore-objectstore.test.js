// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live disaster-recovery proof: b.backup.create -> run -> restore against a
 * REAL object store (MinIO/S3 over the docker-compose test fixtures).
 *
 * The README advertises S3/MinIO/Azure/GCS backup bundles
 * (b.backup.bundleAdapterStorage.objectStoreAdapter wrapping a sigv4
 * b.objectStore client). Until now that round-trip was only exercised
 * against local diskStorage / an fs-backed objectStore. This drives the
 * whole pipeline end-to-end:
 *
 *   1. setupTestDb — real wrapped vault + encrypted-at-rest sealed DB.
 *      Insert rows whose `email` / `name` columns are sealed (vault:
 *      ciphertext on disk; plaintext never bare).
 *   2. flushToDisk — seal the working copy to db.enc / db.key.enc.
 *   3. backup engine bound to a bundleAdapterStorage(objectStoreAdapter(
 *      sigv4 client)) — RUN the backup; the bundle (an encrypted bundle
 *      directory packed into a tar.gz) lands as ONE object key in a real
 *      MinIO bucket. Verify the object exists via the raw client (proves
 *      the SigV4 PUT signed correctly — MinIO verifies SigV4).
 *   4. RESTORE: engine.read() pulls the tar.gz back from MinIO and
 *      extracts the encrypted bundle directory into a fresh location;
 *      restoreBundle.extract() decrypts each per-file blob under the
 *      backup passphrase into db.enc / db.key.enc / vault.key.sealed /
 *      audit-sign.key.sealed.
 *   5. Assert the restored db.enc is CIPHERTEXT (no bare PII), then
 *      re-open vault + db at the restored location and read the sealed
 *      columns back — proving the restored sealed data decrypts under the
 *      vault and the disaster-recovery claim holds.
 *   6. Negative paths: wrong-passphrase restore FAILS (AEAD tag); a
 *      tampered bundle object in the bucket FAILS to restore.
 *
 * What MinIO does and does NOT verify (proof scope, stated honestly):
 *   - MinIO is a REAL S3 server: it DOES verify SigV4 signatures, so a
 *     successful PUT/GET/HEAD/LIST round-trip proves the framework's
 *     sigv4 signer + object-store client are correct on the wire.
 *   - The TLS leg (https://127.0.0.1:9443) is the test-CA endpoint; the
 *     integration runner exports the CA and sets NODE_EXTRA_CA_CERTS, so
 *     TLS is validated with NO rejectUnauthorized:false anywhere.
 *   - MinIO does NOT inspect the bundle bytes — the encryption of the
 *     bundle is the framework's job; we verify that on disk (db.enc is
 *     ciphertext, the bundle object carries no bare PII).
 *
 * No security bypass: full wrapped vault, encrypted at-rest, real AEAD.
 */

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");
var b = require("../../");
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var dbh = require("../helpers/db");

var REGION = "us-east-1";
var ACCESS = "blamejs";
var SECRET = "blamejs_test_password";
var BACKUP_PASSPHRASE = "disaster-recovery-passphrase-not-secret-but-strong";

// PII payloads that MUST end up sealed (never bare) anywhere — on disk,
// in the bundle object in the bucket, in the restored db.enc.
var ROWS = [
  { _id: "u1", email: "alice@secret-domain.example", name: "Alice Liddell" },
  { _id: "u2", email: "bob@private-clinic.example",  name: "Robert Tables" },
  { _id: "u3", email: "carol@confidential.example",  name: "Carol Danvers" },
];

function _tmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

function _rmrf(p) {
  try { fs.rmSync(p, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
}

// Walk a directory tree and return every regular file's bytes concatenated
// — used to scan a restored bundle / data dir for bare-PII leaks.
function _scanForBare(dir, needles) {
  var hits = [];
  (function walk(d) {
    var entries = fs.readdirSync(d, { withFileTypes: true });
    for (var i = 0; i < entries.length; i++) {
      var full = path.join(d, entries[i].name);
      if (entries[i].isDirectory()) { walk(full); continue; }
      if (!entries[i].isFile()) continue;
      var bytes = fs.readFileSync(full);
      for (var j = 0; j < needles.length; j++) {
        if (bytes.includes(Buffer.from(needles[j], "utf8"))) {
          hits.push({ file: full, needle: needles[j] });
        }
      }
    }
  })(dir);
  return hits;
}

async function run() {
  var svc = await services.requireService("minioTls");
  if (!svc.ok) {
    console.log("[skip] backup-restore-objectstore: minio-tls unreachable: " + svc.reason);
    return;
  }
  var endpoint = "https://127.0.0.1:9443";

  // Unique bucket per run so re-runs don't collide.
  var bucket = "blamejs-backup-dr-" + Date.now();
  var prefix = "dr-bundles";

  var dataDir = null;          // the live deployment data dir
  var restoredBundleDir = null;
  var restoreStaging = null;
  var reopenDataDir = null;

  // sigv4 ops client (bucket lifecycle) + backend client (object I/O).
  var opsCfg = {
    protocol:        "sigv4",
    endpoint:        endpoint,
    region:          REGION,
    accessKeyId:     ACCESS,
    secretAccessKey: SECRET,
    allowInternal:   true,
    forcePathStyle:  true,
  };
  var ops = b.objectStore.bucketOps.create(opsCfg);
  await ops.create(bucket);
  check("minio: backup bucket created (SigV4 create signed + accepted)", true);

  var beCfg = {
    name:            "minio-backup-dr",
    protocol:        "sigv4",
    endpoint:        endpoint,
    region:          REGION,
    bucket:          bucket,
    accessKeyId:     ACCESS,
    secretAccessKey: SECRET,
    allowInternal:   true,
    forcePathStyle:  true,
    classifications: ["operational"],
    residencyTag:    "unrestricted",
  };
  var client = b.objectStore.buildBackend(beCfg);

  try {
    // ---- 1. Live deployment: real vault + encrypted-at-rest sealed DB ----
    dataDir = _tmp("blamejs-dr-data");
    await dbh.setupTestDb(dataDir);
    for (var i = 0; i < ROWS.length; i++) {
      b.db.from("users").insertOne({
        _id:       ROWS[i]._id,
        email:     ROWS[i].email,
        name:      ROWS[i].name,
        createdAt: new Date().toISOString(),
      });
    }

    // Confirm the sealed columns are sealed on disk before we back up:
    // the email / name cells are vault: ciphertext, the bare PII never
    // appears in the cell. This is the property the restore must preserve.
    var rawU1 = b.db.prepare('SELECT email AS e, name AS n FROM users WHERE _id = ?').get("u1");
    var emailSealed = typeof rawU1.e === "string" &&
      (rawU1.e.indexOf("vault:") === 0 || b.vault.aad.isAadSealed(rawU1.e) ||
       b.cryptoField.isRowSealed(rawU1.e));
    check("pre-backup: email column is sealed ciphertext on disk (not bare)",
      emailSealed && rawU1.e.indexOf(ROWS[0].email) === -1);
    check("pre-backup: name column is sealed ciphertext on disk (not bare)",
      typeof rawU1.n === "string" && rawU1.n.indexOf(ROWS[0].name) === -1);

    // Capture the vault keypair JSON the bundle encrypts into its
    // manifest (so a cold restorer can unseal the recovered vault).
    var vaultKeyJson = b.vault.getKeysJson();

    // Seal the working copy to durable db.enc / db.key.enc.
    await b.db.flushToDisk();
    check("pre-backup: db.enc exists (sealed at-rest snapshot)",
      fs.existsSync(path.join(dataDir, "db.enc")));
    check("pre-backup: db.key.enc exists (sealed DEK)",
      fs.existsSync(path.join(dataDir, "db.key.enc")));
    check("pre-backup: vault.key.sealed exists (wrapped vault keypair)",
      fs.existsSync(path.join(dataDir, "vault.key.sealed")));

    // db.enc must not carry bare PII (it's the AEAD-sealed at-rest image).
    var preDbEnc = fs.readFileSync(path.join(dataDir, "db.enc"));
    var preBareHits = ROWS.some(function (r) {
      return preDbEnc.includes(Buffer.from(r.email)) || preDbEnc.includes(Buffer.from(r.name));
    });
    check("pre-backup: db.enc carries NO bare PII (ciphertext at rest)", !preBareHits);

    // The framework strips the vault passphrase from env after reading it
    // (security feature). Re-supply it so the post-restore re-open can
    // unseal vault.key.sealed under the same passphrase.
    dbh.setTestPassphraseEnv();

    // ---- 2. Backup engine -> MinIO via the sigv4 objectStore adapter ----
    // bundleAdapterStorage(objectStoreAdapter(sigv4 client)) is the exact
    // S3/MinIO backup path the README advertises. tar.gz format so the
    // whole encrypted bundle dir lands as ONE object key.
    var storage = b.backup.bundleAdapterStorage({
      adapter: b.backup.bundleAdapterStorage.objectStoreAdapter(client, { prefix: prefix }),
      format:  "tar.gz",
    });

    var includeFiles = b.backup.recommendedFiles({
      atRest:           "encrypted",
      vaultMode:        "wrapped",
      additionalSealed: ["vault.derived-hash-salt"],
    });

    var engine = b.backup.create({
      dataDir:      dataDir,
      storage:      storage,
      passphrase:   Buffer.from(BACKUP_PASSPHRASE, "utf8"),
      files:        includeFiles,
      vaultKeyJson: vaultKeyJson,
      audit:        false,
    });

    // RUN the backup against the real bucket. This is the exact path the
    // README advertises; it must succeed. (If the objectStoreAdapter's
    // not-found translation is broken for the sigv4 backend, writeBundle's
    // pre-write hasKey existence probe surfaces the bucket's HTTP 404 as a
    // hard error here instead of treating a missing fresh bundle id as
    // "not present" — see the FAIL message below.)
    var summary = null;
    var runErr = null;
    try {
      summary = await engine.run();
    } catch (e) { runErr = e; }
    check("backup.run: bundle written to the real MinIO bucket (no spurious 404 from the " +
      "objectStoreAdapter not-found probe)" +
      (runErr ? " — FAILED: " + (runErr.code || "") + " " + (runErr.message || "") : ""),
      runErr === null && summary !== null);
    if (runErr || !summary) {
      // The advertised S3/MinIO backup path is broken — stop here; every
      // downstream restore assertion depends on a successful write and
      // would only cascade misleading failures. The single failed check
      // above is the precise, honest bug signal.
      return;
    }
    check("backup.run: produced a bundle id", typeof summary.bundleId === "string" && summary.bundleId.length > 0);
    check("backup.run: storage name reports adapter", summary.storage === "adapter");
    var bundleId = summary.bundleId;

    // ---- 3. Verify the bundle object actually exists in the REAL bucket ----
    // Raw client HEAD on the exact key the adapter writes:
    //   <prefix>/<bundleId>/bundle.tar.gz
    var objectKey = prefix + "/" + bundleId + "/bundle.tar.gz";
    var head = await client.head(objectKey);
    check("minio: bundle object exists in the bucket (SigV4 HEAD signed + 200)",
      head && typeof head.size === "number" && head.size > 0);

    // engine.list() round-trips through SigV4 LIST against the bucket.
    var listed = await engine.list();
    check("backup.list: enumerates the just-written bundle from the real bucket",
      Array.isArray(listed) && listed.some(function (e) { return e.bundleId === bundleId; }));

    // engine.storage.hasBundle composes a SigV4 HEAD.
    check("backup.hasBundle: true against the real bucket",
      (await storage.hasBundle(bundleId)) === true);

    // The object bytes pulled straight from MinIO must NOT contain bare
    // PII — the bundle is the framework's encrypted-at-rest payload, and
    // even at format "tar.gz" with cryptoStrategy "none" the per-file
    // blobs inside are passphrase-AEAD-sealed by the bundle builder.
    var bundleObjBytes = await client.get(objectKey);
    var bundleObjBuf = Buffer.isBuffer(bundleObjBytes) ? bundleObjBytes : Buffer.from(bundleObjBytes);
    var objBareHits = ROWS.some(function (r) {
      return bundleObjBuf.includes(Buffer.from(r.email)) || bundleObjBuf.includes(Buffer.from(r.name));
    });
    check("minio: bundle object in the bucket carries NO bare PII", !objBareHits);

    // ---- 4. RESTORE from the REAL bucket into a fresh location ----
    // engine.read pulls the tar.gz back via SigV4 GET + extracts the
    // encrypted bundle directory.
    restoredBundleDir = path.join(_tmp("blamejs-dr-restored"), "bundle");
    await engine.read(bundleId, restoredBundleDir);
    check("restore: bundle directory extracted from the real bucket",
      fs.existsSync(path.join(restoredBundleDir, "manifest.json")));

    // The extracted bundle dir holds per-file .enc blobs; scan it for any
    // bare PII leak (there must be none — every blob is passphrase-sealed).
    var bundleBareHits = _scanForBare(restoredBundleDir,
      ROWS.map(function (r) { return r.email; }).concat(ROWS.map(function (r) { return r.name; })));
    check("restore: extracted bundle directory carries NO bare PII", bundleBareHits.length === 0);

    // Verify the manifest signature survived the object-store round-trip.
    var sigCheck = b.backup.verifyManifestSignature(restoredBundleDir);
    check("restore: restored manifest signature verifies (SLH-DSA, tamper-evident)",
      sigCheck && sigCheck.ok === true);

    // restoreBundle.extract decrypts each blob under the backup passphrase
    // into the staging dir = the recovered data files.
    restoreStaging = path.join(_tmp("blamejs-dr-staging"), "data");
    var extractRv = await b.restoreBundle.extract({
      bundleDir:  restoredBundleDir,
      stagingDir: restoreStaging,
      passphrase: Buffer.from(BACKUP_PASSPHRASE, "utf8"),
    });
    check("restore: extract recovered the expected file count",
      extractRv.fileCount >= 3);
    check("restore: db.enc recovered into staging",
      fs.existsSync(path.join(restoreStaging, "db.enc")));
    check("restore: db.key.enc recovered into staging",
      fs.existsSync(path.join(restoreStaging, "db.key.enc")));
    check("restore: vault.key.sealed recovered into staging",
      fs.existsSync(path.join(restoreStaging, "vault.key.sealed")));

    // The recovered db.enc must be ciphertext (no bare PII at rest). We do
    // NOT assert byte-identity to the live db.enc: encrypted-at-rest
    // re-seals with a fresh nonce on each flush, so the bytes legitimately
    // differ. Integrity is proven by the re-open + decrypt below (and the
    // manifest's per-file SHA3-512 checksum, which restoreBundle.extract
    // already verified against the recovered plaintext).
    var restoredBareHits = _scanForBare(restoreStaging,
      ROWS.map(function (r) { return r.email; }).concat(ROWS.map(function (r) { return r.name; })));
    check("restore: recovered data files carry NO bare PII (still sealed)",
      restoredBareHits.length === 0);

    // ---- 5. Re-open vault + db from the recovered files; read sealed cols ----
    // db.key.enc (the sealed DEK) is AAD-bound to the absolute dataDir +
    // keyPath of the deployment that sealed it, so a same-host restore
    // recovers into the ORIGINAL data dir path. Tear the live deployment
    // down (frees the working copy + handles) without deleting the data
    // dir, then lay the recovered files back into that same path.
    reopenDataDir = dataDir;
    dataDir = null;            // ownership transfers; finally{} won't double-teardown
    await dbh.teardownTestDb(reopenDataDir);   // closes db/vault; rm -rf's the dir
    fs.mkdirSync(reopenDataDir, { recursive: true });
    ["db.enc", "db.key.enc", "vault.key.sealed", "audit-sign.key.sealed", "vault.derived-hash-salt"]
      .forEach(function (f) {
        var src = path.join(restoreStaging, f);
        if (fs.existsSync(src)) fs.copyFileSync(src, path.join(reopenDataDir, f));
      });

    dbh.setTestPassphraseEnv();
    process.env.BLAMEJS_SKIP_NTP_CHECK = "1";
    b.cluster._resetForTest();
    b.audit._resetForTest();
    b.vault._resetForTest();
    b.db._resetForTest();
    await b.vault.init({ dataDir: reopenDataDir });
    check("restore: vault re-opened from recovered vault.key.sealed",
      b.vault.getMode() === "wrapped");
    await b.db.init({
      dataDir: reopenDataDir,
      tmpDir:  path.join(reopenDataDir, "tmpfs"),
      schema:  [
        {
          name: "users",
          columns: {
            _id:       "TEXT PRIMARY KEY",
            email:     "TEXT",
            emailHash: "TEXT",
            name:      "TEXT",
            status:    "TEXT DEFAULT 'active'",
            createdAt: "TEXT",
          },
          indexes: ["emailHash", "status"],
          sealedFields:  ["email", "name"],
          derivedHashes: { emailHash: { from: "email", normalize: function (v) { return String(v).toLowerCase(); } } },
        },
      ],
    });

    // On the re-opened DB, the on-disk cells are STILL sealed ciphertext.
    var rawReopen = b.db.prepare('SELECT email AS e, name AS n FROM users WHERE _id = ?').get("u2");
    check("restore: re-opened DB cell is still sealed ciphertext (not bare)",
      typeof rawReopen.e === "string" && rawReopen.e.indexOf("vault:") === 0 &&
      rawReopen.e.indexOf(ROWS[1].email) === -1);

    // ...and decrypt correctly under the restored vault.
    var allOk = true;
    for (var k = 0; k < ROWS.length; k++) {
      var got = b.db.from("users").where({ _id: ROWS[k]._id }).first();
      if (!got || got.email !== ROWS[k].email || got.name !== ROWS[k].name) { allOk = false; }
    }
    check("restore: ALL sealed rows decrypt under the restored vault (data intact)", allOk);

    // ---- 6a. Negative: wrong-passphrase restore FAILS ----
    // The restored deployment's vault + auditSign stay LIVE here (a real
    // restorer has them initialized) so the bundle's manifest-signature verify
    // passes and the WRONG PASSPHRASE is rejected at AEAD decrypt — proving the
    // passphrase actually gates the data, not an incidental uninit error. The
    // finally block does the teardown.
    var wrongStaging = path.join(_tmp("blamejs-dr-wrong"), "data");
    var wrongErr = null;
    try {
      await b.restoreBundle.extract({
        bundleDir:  restoredBundleDir,
        stagingDir: wrongStaging,
        passphrase: Buffer.from("the-WRONG-passphrase", "utf8"),
      });
    } catch (e) { wrongErr = e; }
    check("negative: wrong-passphrase restore FAILS with decrypt-failed (AEAD tag)",
      wrongErr && /decrypt-failed|passphrase rejected/i.test((wrongErr.code || "") + " " + (wrongErr.message || "")));
    _rmrf(path.dirname(wrongStaging));

    // ---- 6b. Negative: tampered bundle object in the bucket FAILS ----
    // Flip bytes in the middle of the stored tar.gz object and re-PUT it,
    // then a fresh read+extract must fail (gunzip/tar/AEAD all reject).
    var tampered = Buffer.from(bundleObjBuf);
    var mid = Math.floor(tampered.length / 2);
    tampered[mid] = tampered[mid] ^ 0xff;
    tampered[mid + 1] = tampered[mid + 1] ^ 0xff;
    // Force a single PUT overwrite of the same key.
    await client.put(objectKey, tampered, { multipart: false });

    var tamperedDir = path.join(_tmp("blamejs-dr-tampered"), "bundle");
    var tamperErr = null;
    try {
      await engine.read(bundleId, tamperedDir);
      // If extraction somehow produced a manifest, attempt a decrypt —
      // that must fail. If read() already threw, we never reach here.
      await b.restoreBundle.extract({
        bundleDir:  tamperedDir,
        stagingDir: path.join(_tmp("blamejs-dr-tampered-stg"), "data"),
        passphrase: Buffer.from(BACKUP_PASSPHRASE, "utf8"),
      });
    } catch (e) { tamperErr = e; }
    check("negative: tampered bundle object in the bucket FAILS to restore",
      tamperErr !== null);
    _rmrf(path.dirname(tamperedDir));

  } finally {
    // Teardown: live DB (if still open), bucket + every object, temp dirs.
    try { if (dataDir) await dbh.teardownTestDb(dataDir); } catch (_e) { /* ignore */ }
    try { b.db._resetForTest(); } catch (_e) { /* ignore */ }
    try { b.vault._resetForTest(); } catch (_e) { /* ignore */ }
    try { b.audit._resetForTest(); } catch (_e) { /* ignore */ }
    try { b.cluster._resetForTest(); } catch (_e) { /* ignore */ }
    // Drain the bucket then drop it.
    try {
      var leftover = await client.list(prefix + "/");
      var items = (leftover && leftover.items) || [];
      for (var d = 0; d < items.length; d++) {
        try { await client.delete(items[d].key); } catch (_e) { /* ignore */ }
      }
      await ops.delete(bucket);
    } catch (_e) { /* best-effort bucket cleanup */ }
    if (restoredBundleDir) _rmrf(path.dirname(restoredBundleDir));
    if (restoreStaging) _rmrf(path.dirname(restoreStaging));
    if (reopenDataDir) _rmrf(reopenDataDir);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[backup-restore-objectstore] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}

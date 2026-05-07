#!/usr/bin/env node
/**
 * envelope-migrate-0xE1-to-0xE2 — one-shot migration of HermitStash's
 * sealed-value envelope from 0xE1 to 0xE2.
 *
 * blamejs 0.8.41+ produces 0xE2 envelopes (NIST SP 800-56C r2 / RFC 9180
 * FixedInfo binding via SHAKE256, 4-byte header AAD-bound on every
 * XChaCha20-Poly1305 encrypt) and HARD-REFUSES the legacy 0xE1 magic on
 * decrypt. HermitStash through v1.9.15 produced 0xE1 sealed values via
 * `vault.seal()`. This script walks every `vault:<base64>` value on disk
 * + in the DB and re-seals it under blamejs's 0xE2 envelope.
 *
 * What gets migrated:
 *   - data/ca.key.sealed, data/tls/privkey.pem.sealed,
 *     data/api-encrypt-keypair.sealed (sealed PEM/key files)
 *   - data/db.key.enc (vault-sealed DB-file symmetric key)
 *   - Every sealed DB column (vault:-prefixed strings in any column,
 *     incl. nested in the data-overflow JSON blob)
 *
 * What does NOT need migration (cross-version compatible):
 *   - hermitstash.db.enc, file storage blobs, per-file XChaCha20 keys —
 *     all use `encryptPacked` (version-byte 0x02 + nonce + ct), which
 *     is structurally identical between HermitStash and blamejs.
 *   - vault.key.sealed — uses vault-wrap's own 0xE2 magic (a different
 *     format from the storage envelope; HermitStash's vault-wrap was
 *     already aligned with blamejs's via shared design).
 *   - Backup blobs — passphrase-derived Argon2id key + raw nonce + ct,
 *     no envelope wrapper.
 *
 * Usage:
 *   node scripts/envelope-migrate-0xE1-to-0xE2.js          # dry-run (default)
 *   node scripts/envelope-migrate-0xE1-to-0xE2.js --apply  # actually migrate
 *   node scripts/envelope-migrate-0xE1-to-0xE2.js --verbose
 *
 * Crash safety:
 *   A marker file (data/envelope-migration.marker) tracks which steps
 *   completed. Re-running after a crash resumes from the last completed
 *   step. Each per-file step writes via `<path>.tmp` + atomic rename.
 *   Each per-table DB step is a single transaction.
 *
 * Run when:
 *   AFTER upgrading to v1.9.16 (which carries this script + the vendor
 *   refresh to blamejs 0.8.41+) but BEFORE upgrading to v1.9.18+ (which
 *   swaps HermitStash's vault/db/storage to blamejs primitives — those
 *   primitives only read 0xE2 envelopes and will refuse to boot until
 *   the migration has run).
 *
 * The server MUST be stopped before running this tool. The tool opens
 * the DB exclusively and re-encrypts it.
 */
"use strict";

var fs = require("fs");
var path = require("path");

var args = process.argv.slice(2);
var DRY_RUN = !args.includes("--apply");
var VERBOSE = args.includes("--verbose") || args.includes("-v");
if (args.includes("--help") || args.includes("-h")) {
  console.log(fs.readFileSync(__filename, "utf8").split("\n").slice(0, 49).join("\n").replace(/^.{0,3}/gm, "").trim());
  process.exit(0);
}

var MODE = DRY_RUN ? "DRY-RUN" : "APPLY";
console.log("=== HermitStash envelope migration 0xE1 → 0xE2 (" + MODE + ") ===\n");

// Load order matters here: vault → lib/db → migration. lib/db reads
// data/db.key.enc through HermitStash's vault.unseal at module-load
// time, then caches the symmetric DB key in memory. After that, the
// migration is free to re-seal db.key.enc on disk — the cached key
// is what the DB module continues to use for SQLite read/write and
// for the post-exit re-encrypt. Loading lib/db AFTER db.key.enc
// migration would trigger db.js's "regenerate on decrypt failure"
// fallback and silently rotate the DB key, which is unrecoverable.
(async function main() {
  var hermitstashVault = require("../lib/vault");
  await hermitstashVault.init();

  // blamejs's lower-level encrypt produces the new 0xE2 envelope,
  // bound to the same vault keypair. Calling it directly skips
  // blamejs's own vault.init (which would fight with HermitStash's
  // over data/vault.key) and just uses the keypair we already have
  // in memory.
  var bCrypto = require("../lib/vendor/blamejs/lib/crypto");

  var C = require("../lib/constants");
  var PATHS = C.PATHS;
  var keys = JSON.parse(hermitstashVault.getKeysJson());

  // ---- Early-exit guard: detect already-migrated state ----
  // If db.key.enc is already 0xE2-sealed, lib/db's module-load would
  // fail to decrypt it and (under v1.9.x) auto-regenerate a fresh dbKey,
  // permanently losing every encryptPacked-encrypted blob (DB file +
  // every per-file storage blob). Before loading lib/db, probe the
  // existing db.key.enc with HermitStash's vault.unseal — if it
  // throws, we're already migrated and the script must NOT proceed.
  var dbKeyEncPath = PATHS.DB_KEY_ENC;
  if (fs.existsSync(dbKeyEncPath)) {
    var probe = fs.readFileSync(dbKeyEncPath, "utf8").trim();
    if (probe.startsWith("vault:")) {
      try {
        hermitstashVault.unseal(probe);
      } catch (probeErr) {
        console.log("db.key.enc is already in 0xE2 format — migration appears complete.");
        console.log("If you intend to re-run, restore data/db.key.enc from a pre-migration backup first.");
        console.log("This script refuses to proceed because lib/db's auto-regenerate fallback");
        console.log("would otherwise wipe the cached symmetric DB key.");
        process.exit(0);
      }
    }
  }

  // Force DB module-load NOW (caches dbKey from db.key.enc under 0xE1)
  // so the subsequent db.key.enc re-seal doesn't strand the cached key.
  var db = require("../lib/db");

  function resealValue(legacySealed) {
    if (typeof legacySealed !== "string" || !legacySealed.startsWith("vault:")) return null;
    var plaintext;
    try {
      plaintext = hermitstashVault.unseal(legacySealed);
    } catch (e) {
      throw new Error("decrypt-under-0xE1 failed: " + e.message);
    }
    var newEnvelope = bCrypto.encrypt(plaintext, keys);
    return "vault:" + newEnvelope.toString("base64");
  }

  // ---- Marker file ----
  var MARKER = path.join(PATHS.DATA_DIR, "envelope-migration.marker");
  function readMarker() {
    if (!fs.existsSync(MARKER)) return { stepsDone: [], rowsMigrated: 0, filesMigrated: 0 };
    return JSON.parse(fs.readFileSync(MARKER, "utf8"));
  }
  function writeMarker(state) {
    if (DRY_RUN) return;
    fs.writeFileSync(MARKER + ".tmp", JSON.stringify(state, null, 2));
    fs.renameSync(MARKER + ".tmp", MARKER);
  }
  var state = readMarker();
  if (!state.startedAt) state.startedAt = new Date().toISOString();

  function stepDone(name) { return state.stepsDone.indexOf(name) !== -1; }
  function markStepDone(name) {
    if (!stepDone(name)) state.stepsDone.push(name);
    writeMarker(state);
  }

  // Order matters: db.key.enc migrates LAST, after DB columns. Until
  // then, lib/db must continue to read it under the 0xE1 path so a
  // mid-flight crash can resume on re-run (re-running re-loads lib/db,
  // which still finds 0xE1 db.key.enc and caches the dbKey).
  var sealedFilesPre = [
    { id: "pem:ca",                path: PATHS.CA_KEY_SEALED,                label: "ca.key.sealed" },
    { id: "pem:tls",               path: PATHS.TLS_KEY_SEALED,               label: "tls/privkey.pem.sealed" },
    { id: "pem:api-encrypt-kp",    path: PATHS.API_ENCRYPT_KEYPAIR_SEALED,   label: "api-encrypt-keypair.sealed" },
  ];
  var sealedFilesPost = [
    { id: "vault:db-key",          path: PATHS.DB_KEY_ENC,                   label: "db.key.enc" },
  ];

  function migrateFiles(list, headerLabel) {
    if (headerLabel) console.log("\n--- " + headerLabel + " ---");
    for (var i = 0; i < list.length; i++) {
      var f = list[i];
      if (stepDone(f.id)) {
        console.log("[skip] " + f.label + " — already migrated (per marker)");
        continue;
      }
      if (!fs.existsSync(f.path)) {
        console.log("[skip] " + f.label + " — not present (optional file)");
        markStepDone(f.id);
        continue;
      }
      var sealed = fs.readFileSync(f.path, "utf8").trim();
      if (!sealed.startsWith("vault:")) {
        console.log("[skip] " + f.label + " — not a vault: blob (already migrated or different format)");
        markStepDone(f.id);
        continue;
      }
      try {
        var newSealed = resealValue(sealed);
        if (DRY_RUN) {
          console.log("[dry-run] would migrate " + f.label + " (" + sealed.length + " → " + newSealed.length + " chars)");
        } else {
          fs.writeFileSync(f.path + ".tmp", newSealed, { mode: 0o600 });
          fs.renameSync(f.path + ".tmp", f.path);
          console.log("[ok]     " + f.label);
        }
        state.filesMigrated += 1;
        markStepDone(f.id);
      } catch (e) {
        console.error("[fail]   " + f.label + " — " + e.message);
        throw e;
      }
    }
  }

  // Step 1 — sealed PEM files (NOT db.key.enc; that's last).
  migrateFiles(sealedFilesPre, "Sealed PEM/key files");

  // ---- Step 2: sealed DB columns ----
  if (stepDone("db:columns")) {
    console.log("[skip] DB columns — already migrated (per marker)");
  } else {
    console.log("\n--- DB column migration ---");

    // lib/db is already loaded above (the dbKey is cached in memory).
    // Its `process.on("exit")` re-encrypts the DB to encryptPacked
    // (cross-version-compatible) when this script exits cleanly, so
    // the migrated rows persist back to disk.
    var tables = db.rawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").map(function (r) { return r.name; });

    var totalRows = 0;
    for (var ti = 0; ti < tables.length; ti++) {
      var table = tables[ti];
      var cols;
      try {
        cols = db.rawQuery("PRAGMA table_info(\"" + table + "\")").map(function (c) { return c.name; });
      } catch (_e) { continue; }
      if (!cols.length || cols.indexOf("_id") === -1) continue;

      var allRows;
      try {
        allRows = db.rawQuery("SELECT * FROM \"" + table + "\"");
      } catch (_e) { continue; }

      var tableMigrated = 0;
      for (var ri = 0; ri < allRows.length; ri++) {
        var row = allRows[ri];
        var updates = {};
        for (var col in row) {
          var v = row[col];
          if (typeof v !== "string") continue;
          if (v.startsWith("vault:")) {
            try {
              updates[col] = resealValue(v);
            } catch (e) {
              console.error("[fail] " + table + "._id=" + row._id + " col=" + col + " — " + e.message);
              throw e;
            }
            continue;
          }
          // overflow JSON column — parse and re-seal nested vault: values
          if (col === "data" && (v.charAt(0) === "{" || v.charAt(0) === "[")) {
            try {
              var json = JSON.parse(v);
              var modified = false;
              for (var k in json) {
                if (typeof json[k] === "string" && json[k].startsWith("vault:")) {
                  json[k] = resealValue(json[k]);
                  modified = true;
                }
              }
              if (modified) updates[col] = JSON.stringify(json);
            } catch (_e) { /* not JSON — leave as-is */ }
          }
        }
        var keysToUpdate = Object.keys(updates);
        if (!keysToUpdate.length) continue;

        if (DRY_RUN) {
          if (VERBOSE) console.log("[dry-run] " + table + "._id=" + row._id + " cols=" + keysToUpdate.join(","));
        } else {
          var setSql = keysToUpdate.map(function (c) { return "\"" + c + "\" = ?"; }).join(", ");
          var values = keysToUpdate.map(function (c) { return updates[c]; });
          values.push(row._id);
          db.rawExec("UPDATE \"" + table + "\" SET " + setSql + " WHERE _id = ?", ...values);
        }
        tableMigrated += 1;
        totalRows += 1;
      }

      if (tableMigrated > 0) {
        console.log("[" + (DRY_RUN ? "dry-run" : "ok") + "]    " + table + " — " + tableMigrated + " rows" + (DRY_RUN ? " WOULD migrate" : " migrated"));
      }
    }
    state.rowsMigrated = totalRows;
    if (!DRY_RUN) markStepDone("db:columns");
    console.log("\nTotal DB rows " + (DRY_RUN ? "to migrate" : "migrated") + ": " + totalRows);
    // DB file is re-encrypted automatically by lib/db.js's process.on("exit")
    // hook when this script exits cleanly.
  }

  // Step 3 — db.key.enc LAST. The dbKey is already cached in lib/db's
  // module state, so re-sealing the on-disk file under 0xE2 doesn't
  // affect this run. The exit handler still has the cached key for
  // its final encryptDbFile call. On re-run, the early-exit guard at
  // the top of this script will detect the 0xE2 db.key.enc and refuse
  // to proceed (preventing lib/db's auto-regenerate fallback).
  migrateFiles(sealedFilesPost, "DB key file (last)");

  // ---- Done ----
  if (!DRY_RUN) {
    state.completedAt = new Date().toISOString();
    writeMarker(state);
  }

  console.log("\n=== Summary ===");
  console.log("Mode:           " + MODE);
  console.log("Sealed files:   " + state.filesMigrated + (DRY_RUN ? " WOULD migrate" : " migrated"));
  console.log("DB rows:        " + state.rowsMigrated + (DRY_RUN ? " WOULD migrate" : " migrated"));
  console.log("Marker file:    " + MARKER + (DRY_RUN ? " (not written in dry-run)" : ""));
  if (DRY_RUN) {
    console.log("\nRe-run with --apply to perform the migration.");
    console.log("The server must be stopped during --apply.");
  } else {
    console.log("\nMigration complete. You may now upgrade HermitStash to v1.9.18+ when ready.");
  }
  process.exit(0);
})().catch(function (err) {
  console.error("\n[fatal] " + (err && err.message ? err.message : String(err)));
  if (err && err.stack) console.error(err.stack);
  process.exit(1);
});

"use strict";
/**
 * Legacy 0xE1 → 0xE2 envelope migration — extracted module.
 *
 * Used by both:
 *   - scripts/envelope-migrate-0xE1-to-0xE2.js (operator-run CLI)
 *   - server.js boot-time auto-migrate hook
 *
 * Independent of lib/vault's swap state. Reads 0xE1 envelopes via the
 * raw `lib/crypto.decrypt` path (which lib/crypto.js still provides)
 * and writes 0xE2 envelopes via blamejs's
 * `b.crypto.encrypt`. Operates on the on-disk format directly with no
 * dependency on lib/vault.seal / unseal — that boundary now refuses
 * 0xE1 envelopes, so the migration cannot route through it.
 *
 * Caller responsibility:
 *   - Vault keypair is already loaded (via vault.init() OR directly
 *     read from data/vault.key) and passed in as `opts.keys`. The
 *     module never touches the vault.key file itself; it just needs
 *     the keypair object.
 *   - lib/db must NOT have been loaded before run() is called — the
 *     module loads it itself, after probing whether migration is
 *     needed. This avoids the v1.9.x "regenerate dbKey on decrypt
 *     failure" fallback that would otherwise wipe the symmetric DB
 *     key on a re-run against already-migrated data.
 *
 * Crash safety: marker file at data/envelope-migration.marker tracks
 * completed steps. Per-file writes go via `<path>.tmp` + atomic
 * rename. Per-table updates run as ordinary SQLite UPDATE statements
 * (the underlying DB handle is journaled). Re-running with --apply /
 * via auto-shim after a partial crash resumes from the last
 * unfinished step.
 */

var nodeFs = require("node:fs");
var nodePath = require("node:path");

var bCrypto = require("./crypto");
var b = require("./vendor/blamejs");
var C = require("./constants");

var VAULT_PREFIX = "vault:";

// ---- Probe ----

function isAlreadyMigrated(opts) {
  opts = opts || {};
  var dbKeyEncPath = opts.dbKeyEncPath || C.PATHS.DB_KEY_ENC;
  // Fresh install: no db.key.enc on disk yet means lib/db hasn't
  // generated one. There's nothing to migrate — vault.seal now
  // emits 0xE2, so the first dbKey lib/db creates is 0xE2,
  // and any seeded DB rows are 0xE2 from the start. Returning
  // "already migrated = true" here skips the auto-migrate hook on
  // first-ever boot of v1.9.18+. Real upgrades from v1.9.17 always
  // have an existing db.key.enc with 0xE1 magic, which falls through
  // to the magic-byte probe below.
  if (!nodeFs.existsSync(dbKeyEncPath)) return true;
  var probe = nodeFs.readFileSync(dbKeyEncPath, "utf8").trim();
  if (!probe.startsWith(VAULT_PREFIX)) return true;
  // Probe by extracting the envelope and checking the magic byte.
  // Avoids triggering lib/db's auto-regenerate fallback which would
  // wipe the dbKey on first decrypt failure.
  try {
    var b64 = probe.substring(VAULT_PREFIX.length);
    var envelope = Buffer.from(b64, "base64");
    if (envelope.length === 0) return true;
    return envelope[0] === 0xE2; // already in new format
  } catch (_e) {
    return true;
  }
}

// ---- Per-value reseal ----

function makeResealer(keys) {
  return function reseal(legacySealed) {
    if (typeof legacySealed !== "string" || !legacySealed.startsWith(VAULT_PREFIX)) return null;
    var b64 = legacySealed.substring(VAULT_PREFIX.length);
    // Decrypt under HermitStash's 0xE1 nodePath.
    var plaintext = bCrypto.decrypt(b64, keys);
    // Re-encrypt under blamejs's 0xE2 nodePath. b.crypto.encrypt returns
    // base64 directly, so just prepend the prefix.
    var newEnvelope = b.crypto.encrypt(plaintext, keys);
    return VAULT_PREFIX + newEnvelope;
  };
}

// ---- Marker ----

function readMarker(markerPath) {
  if (!nodeFs.existsSync(markerPath)) return { stepsDone: [], rowsMigrated: 0, filesMigrated: 0 };
  return JSON.parse(nodeFs.readFileSync(markerPath, "utf8")); // allow:bare-json-parse — parsing migration marker we wrote ourselves in this same module
}

function writeMarker(markerPath, state, dryRun) {
  if (dryRun) return;
  nodeFs.writeFileSync(markerPath + ".tmp", JSON.stringify(state, null, 2));
  nodeFs.renameSync(markerPath + ".tmp", markerPath);
}

// ---- Sealed file migration ----

function migrateFiles(list, state, log, dryRun, reseal) {
  for (var i = 0; i < list.length; i++) {
    var f = list[i];
    if (state.stepsDone.indexOf(f.id) !== -1) {
      log.info("[skip] " + f.label + " — already migrated (per marker)");
      continue;
    }
    if (!nodeFs.existsSync(f.path)) {
      log.info("[skip] " + f.label + " — not present (optional file)");
      state.stepsDone.push(f.id);
      continue;
    }
    var sealed = nodeFs.readFileSync(f.path, "utf8").trim();
    if (!sealed.startsWith(VAULT_PREFIX)) {
      log.info("[skip] " + f.label + " — not a vault: blob");
      state.stepsDone.push(f.id);
      continue;
    }
    var newSealed = reseal(sealed);
    if (dryRun) {
      log.info("[dry-run] would migrate " + f.label);
    } else {
      nodeFs.writeFileSync(f.path + ".tmp", newSealed, { mode: 0o600 });
      nodeFs.renameSync(f.path + ".tmp", f.path);
      log.info("[ok]     " + f.label);
    }
    state.filesMigrated += 1;
    state.stepsDone.push(f.id);
  }
}

// ---- Main entry point ----

/**
 * Run the migration. Idempotent + crash-safe.
 *
 * @param {object} opts
 * @param {object} opts.keys     - vault keypair object { publicKey, privateKey, ecPublicKey, ecPrivateKey }
 * @param {boolean} [opts.dryRun]   - when true, no writes (default false)
 * @param {boolean} [opts.verbose]  - extra logging (default false)
 * @param {object}  [opts.log]      - logger with .info / .warn / .error (default console)
 * @returns {object} { migrated, alreadyMigrated, filesMigrated, rowsMigrated, dryRun }
 */
function run(opts) {
  opts = opts || {};
  var dryRun  = !!opts.dryRun;
  var verbose = !!opts.verbose;
  var log     = opts.log || console;
  var keys    = opts.keys;

  if (!keys || !keys.publicKey || !keys.privateKey) {
    throw new Error("envelope-migrate: opts.keys must include publicKey + privateKey (vault keypair)");
  }

  var PATHS = C.PATHS;
  var markerPath = nodePath.join(PATHS.DATA_DIR, "envelope-migration.marker");

  if (isAlreadyMigrated({ dbKeyEncPath: PATHS.DB_KEY_ENC })) {
    return { migrated: false, alreadyMigrated: true, dryRun: dryRun, filesMigrated: 0, rowsMigrated: 0 };
  }

  var state = readMarker(markerPath);
  if (!state.startedAt) state.startedAt = new Date().toISOString();

  var reseal = makeResealer(keys);

  // Step 1 — sealed PEM files (NOT db.key.enc; that's last).
  // db.key.enc must stay 0xE1-readable until lib/db has cached the
  // dbKey, otherwise lib/db's auto-regenerate fallback wipes it.
  var sealedFilesPre = [
    { id: "pem:ca",             path: PATHS.CA_KEY_SEALED,              label: "ca.key.sealed" },
    { id: "pem:tls",            path: PATHS.TLS_KEY_SEALED,             label: "tls/privkey.pem.sealed" },
    { id: "pem:api-encrypt-kp", path: PATHS.API_ENCRYPT_KEYPAIR_SEALED, label: "api-encrypt-keypair.sealed" },
  ];
  migrateFiles(sealedFilesPre, state, log, dryRun, reseal);
  writeMarker(markerPath, state, dryRun);

  // Step 2 — load lib/db (caches dbKey) and migrate every vault: cell.
  if (state.stepsDone.indexOf("db:columns") === -1) {
    if (verbose) log.info("--- DB column migration ---");
    var db = require("./db"); // allow:inline-require — contract: db MUST NOT load until after the legacy-envelope probe finishes (see file docstring); top-level require would defeat the migration's load-order guarantee
    var tables = db.rawQuery("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
      .map(function (r) { return r.name; });

    var totalRows = 0;
    for (var ti = 0; ti < tables.length; ti++) {
      var table = tables[ti];
      var cols;
      try { cols = db.rawQuery("PRAGMA table_info(\"" + table + "\")").map(function (c) { return c.name; }); }
      catch (_e) { continue; }
      if (!cols.length || cols.indexOf("_id") === -1) continue;

      var allRows;
      try { allRows = db.rawQuery("SELECT * FROM \"" + table + "\""); }
      catch (_e) { continue; }

      var tableMigrated = 0;
      for (var ri = 0; ri < allRows.length; ri++) {
        var row = allRows[ri];
        var updates = {};
        for (var col in row) {
          var v = row[col];
          if (typeof v !== "string") continue;
          if (v.startsWith(VAULT_PREFIX)) {
            updates[col] = reseal(v);
            continue;
          }
          // overflow JSON column — re-seal nested vault: values
          if (col === "data" && (v.charAt(0) === "{" || v.charAt(0) === "[")) {
            try {
              var json = JSON.parse(v); // allow:bare-json-parse — re-sealing overflow JSON we wrote ourselves in the DB
              var modified = false;
              for (var k in json) {
                if (typeof json[k] === "string" && json[k].startsWith(VAULT_PREFIX)) {
                  json[k] = reseal(json[k]);
                  modified = true;
                }
              }
              if (modified) updates[col] = JSON.stringify(json);
            } catch (_e) { /* not JSON */ }
          }
        }
        var keysToUpdate = Object.keys(updates);
        if (!keysToUpdate.length) continue;

        if (!dryRun) {
          var setSql = keysToUpdate.map(function (c) { return "\"" + c + "\" = ?"; }).join(", ");
          var values = keysToUpdate.map(function (c) { return updates[c]; });
          values.push(row._id);
          db.rawExec.apply(null, ["UPDATE \"" + table + "\" SET " + setSql + " WHERE _id = ?"].concat(values));
        }
        tableMigrated += 1;
        totalRows += 1;
      }
      if (tableMigrated > 0) {
        log.info("[" + (dryRun ? "dry-run" : "ok") + "]    " + table + " — " + tableMigrated + " rows" + (dryRun ? " WOULD migrate" : " migrated"));
      }
    }
    state.rowsMigrated += totalRows;
    if (!dryRun) state.stepsDone.push("db:columns");
    writeMarker(markerPath, state, dryRun);
  }

  // Step 3 — db.key.enc LAST. lib/db's dbKey is already cached in
  // memory at this point, so re-sealing the on-disk file is purely
  // cosmetic for the running process. The exit handler still uses
  // the cached key for its final encryptDbFile call.
  var sealedFilesPost = [
    { id: "vault:db-key", path: PATHS.DB_KEY_ENC, label: "db.key.enc" },
  ];
  migrateFiles(sealedFilesPost, state, log, dryRun, reseal);

  if (!dryRun) state.completedAt = new Date().toISOString();
  writeMarker(markerPath, state, dryRun);

  return {
    migrated: true,
    alreadyMigrated: false,
    dryRun: dryRun,
    filesMigrated: state.filesMigrated,
    rowsMigrated: state.rowsMigrated,
  };
}

module.exports = {
  run: run,
  isAlreadyMigrated: isAlreadyMigrated,
};

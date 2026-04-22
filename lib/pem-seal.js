/**
 * PEM at-rest sealing — shared primitive (v1.9.4).
 *
 * Sealed file format: a single line `vault:<base64-of-envelope>`, identical
 * to how DB columns are sealed. This is intentional — operators can `cat`
 * either a sealed PEM or a sealed DB column and immediately recognize the
 * `vault:` prefix as "needs the vault key to read." No new envelope magic
 * byte is needed; we're already inside the v1.9.0 envelope (0xE1) once the
 * base64 is decoded by vault.unseal().
 *
 * Used by:
 *   - lib/mtls-ca.js                — CA private key (lazy load)
 *   - server-main.js                — TLS server private key (boot load)
 *   - scripts/ca-key-seal.js        — operator migration tool
 *   - scripts/ca-key-unseal.js      — reverse direction
 *   - scripts/tls-key-seal.js       — same for TLS, with --reload flag
 *   - scripts/tls-key-unseal.js     — same
 *
 * Crash safety: atomic .tmp + fsync + rename + marker pattern, identical to
 * v1.9.0's vault.key.sealed setup. Boot-time recovery walks any pending
 * marker and either completes or aborts the operation depending on observed
 * state; never leaves a half-sealed file usable.
 */
"use strict";

var fs = require("fs");
var vault = require("./vault");
var { sha3Hash } = require("./crypto");
var { VAULT_PREFIX } = require("./constants");

// ---- PEM content sanity check ----

// Refuse to seal arbitrary bytes — sealing garbage that an operator THOUGHT
// was a PEM is a footgun. Catch the obvious case where the input has no
// "-----BEGIN " header at all. We don't validate the inner content (key
// type, ASN.1 well-formedness) — that's the consumer's job.
function isPemContent(buf) {
  var head = buf.toString("utf8", 0, Math.min(buf.length, 256));
  return /-----BEGIN [A-Z ]+-----/.test(head);
}

// ---- fsync helpers (mirror vault.js's pattern; best-effort cross-platform) ----

function _fsyncFile(filePath) {
  try {
    var fd = fs.openSync(filePath, "r+");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* fsync isn't supported on every platform/path; best-effort */ }
}

function _fsyncDir(dirPath) {
  try {
    var fd = fs.openSync(dirPath, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch (_e) { /* same */ }
}

function _parentDirOf(p) { return require("path").dirname(p); }

// ---- Marker recovery ----
//
// Mirrors the v1.9.0 vault.js pattern. Marker JSON:
//   { format: 1, startedAt: ISO, sealedSha3: hex, hashAlg: "sha3-512" }
//
// targetFilePath is the file the operation was producing (e.g. .sealed for
// seal-setup, .pem for unseal-remove). otherFilePath is the file that
// should be deleted to finalize the operation. The dispatch table:
//
//   target | other | hash matches | Action
//   -------|-------|--------------|---------------------------------------
//     no   |  no   |     n/a      | crash before rename — drop marker, no-op
//     no   | yes   |     n/a      | drop marker (rare; log it)
//    yes   |  no   |    yes       | drop marker, recovery complete
//    yes   |  no   |    no        | FATAL — tampering or corruption
//    yes   | yes   |    yes       | finish: unlink other, drop marker
//    yes   | yes   |    no        | FATAL — tampering or corruption

function recoverFromMarker(markerPath, targetFilePath, otherFilePath) {
  var marker;
  try {
    marker = JSON.parse(fs.readFileSync(markerPath, "utf8"));
  } catch (e) {
    throw new Error("Migration marker at " + markerPath + " is unreadable: " + e.message);
  }
  if (!marker || marker.format !== 1 || !marker.sealedSha3) {
    throw new Error("Unknown migration marker format at " + markerPath);
  }

  var targetExists = fs.existsSync(targetFilePath);
  var otherExists = fs.existsSync(otherFilePath);

  if (!targetExists) {
    fs.unlinkSync(markerPath);
    return { recovered: true, message: "marker without target — discarded marker" };
  }

  var actualSha3 = sha3Hash(fs.readFileSync(targetFilePath));
  if (actualSha3 !== marker.sealedSha3) {
    throw new Error(
      targetFilePath + " hash does not match migration marker. " +
      "Possible tampering between crash and restart. Expected: " + marker.sealedSha3 +
      "  Actual: " + actualSha3 + ". Investigate manually before continuing."
    );
  }

  if (otherExists) {
    fs.unlinkSync(otherFilePath);
  }
  fs.unlinkSync(markerPath);
  _fsyncDir(_parentDirOf(markerPath));
  return { recovered: true, message: "migration completed via recovery" };
}

// Sweep both possible marker files for a (plain, sealed) pair. Always
// runs at the top of loadPemDispatch so observed state is post-recovery.
function _sweepMarkers(plainPath, sealedPath) {
  var migrPath = sealedPath + ".migration-pending";
  var unsPath = plainPath + ".unseal-pending";
  if (fs.existsSync(migrPath)) recoverFromMarker(migrPath, sealedPath, plainPath);
  if (fs.existsSync(unsPath)) recoverFromMarker(unsPath, plainPath, sealedPath);
}

// ---- Public: seal a PEM file ----
//
// Reads plaintext PEM at plainPath, vault-seals the bytes, writes the sealed
// content to sealedPath atomically. By default deletes the plaintext on
// success. Crash-safe: leaves either pre-seal-intact or post-seal-complete.
function sealPemFile(plainPath, sealedPath, opts) {
  opts = opts || {};
  if (!fs.existsSync(plainPath)) throw new Error("Plaintext PEM does not exist: " + plainPath);
  if (fs.existsSync(sealedPath)) throw new Error("Sealed file already exists; refusing to overwrite: " + sealedPath);

  var plain = fs.readFileSync(plainPath);
  if (!isPemContent(plain)) throw new Error("Input does not look like a PEM file (no -----BEGIN header): " + plainPath);

  var sealed = vault.seal(plain.toString("utf8"));

  // Round-trip verify in-memory before any disk writes — never write a
  // sealed blob we can't immediately decrypt back to the original bytes.
  var verify = vault.unseal(sealed);
  if (verify !== plain.toString("utf8")) {
    throw new Error("In-memory round-trip verification failed; refusing to write sealed file");
  }

  // Atomic write: .tmp + fsync + marker + rename + unlink-plain + drop-marker
  var tmp = sealedPath + ".tmp";
  fs.writeFileSync(tmp, sealed, { mode: 0o600 });
  _fsyncFile(tmp);

  var marker = {
    format: 1,
    startedAt: new Date().toISOString(),
    sealedSha3: sha3Hash(sealed),
    hashAlg: "sha3-512",
  };
  var markerPath = sealedPath + ".migration-pending";
  var markerTmp = markerPath + ".tmp";
  fs.writeFileSync(markerTmp, JSON.stringify(marker, null, 2), { mode: 0o600 });
  _fsyncFile(markerTmp);
  fs.renameSync(markerTmp, markerPath);
  _fsyncDir(_parentDirOf(sealedPath));

  fs.renameSync(tmp, sealedPath);
  _fsyncDir(_parentDirOf(sealedPath));

  if (!opts.keepPlaintext) {
    fs.unlinkSync(plainPath);
    _fsyncDir(_parentDirOf(plainPath));
  }

  fs.unlinkSync(markerPath);
  _fsyncDir(_parentDirOf(markerPath));

  return { sealedPath: sealedPath, plaintextDeleted: !opts.keepPlaintext };
}

// ---- Public: unseal a sealed PEM file ----

function unsealPemFile(sealedPath, plainPath) {
  if (!fs.existsSync(sealedPath)) throw new Error("Sealed file does not exist: " + sealedPath);
  if (fs.existsSync(plainPath)) throw new Error("Plaintext file already exists; refusing to overwrite: " + plainPath);

  var sealed = fs.readFileSync(sealedPath, "utf8").trim();
  if (sealed.indexOf(VAULT_PREFIX) !== 0) {
    throw new Error("Sealed file does not start with '" + VAULT_PREFIX + "': " + sealedPath);
  }
  var plainStr = vault.unseal(sealed);
  var plain = Buffer.from(plainStr, "utf8");
  if (!isPemContent(plain)) {
    throw new Error("Decrypted content does not look like a PEM (no -----BEGIN header)");
  }

  var tmp = plainPath + ".tmp";
  fs.writeFileSync(tmp, plain, { mode: 0o600 });
  _fsyncFile(tmp);

  var marker = {
    format: 1,
    startedAt: new Date().toISOString(),
    sealedSha3: sha3Hash(plain),
    hashAlg: "sha3-512",
  };
  var markerPath = plainPath + ".unseal-pending";
  var markerTmp = markerPath + ".tmp";
  fs.writeFileSync(markerTmp, JSON.stringify(marker, null, 2), { mode: 0o600 });
  _fsyncFile(markerTmp);
  fs.renameSync(markerTmp, markerPath);
  _fsyncDir(_parentDirOf(plainPath));

  fs.renameSync(tmp, plainPath);
  _fsyncDir(_parentDirOf(plainPath));

  fs.unlinkSync(sealedPath);
  _fsyncDir(_parentDirOf(sealedPath));

  fs.unlinkSync(markerPath);
  _fsyncDir(_parentDirOf(markerPath));

  return { plainPath: plainPath };
}

// ---- Public: load dispatch (used by mtls-ca.js and server-main.js) ----
//
// 6-state dispatch table mirroring v1.9.0 vault.js. Returns a Buffer of
// PEM bytes, or null if neither file exists (caller handles bootstrap).
// Throws on FATAL conditions; caller decides whether to log+exit or
// surface the error differently.
function loadPemDispatch(plainPath, sealedPath, modeEnvVarName) {
  // Sweep recovery markers BEFORE inspecting state — observed state must
  // be post-recovery, otherwise mid-crash files trigger false invariant
  // violations.
  _sweepMarkers(plainPath, sealedPath);

  var mode = (process.env[modeEnvVarName] || "auto").toLowerCase();
  var hasPlain = fs.existsSync(plainPath);
  var hasSealed = fs.existsSync(sealedPath);

  if (hasPlain && hasSealed) {
    throw new Error(
      "Invariant violation: both " + plainPath + " and " + sealedPath +
      " exist. Manual interference suspected. Resolve by deleting the file " +
      "you do NOT want to keep, then restart."
    );
  }
  if (hasSealed && mode === "disabled") {
    throw new Error(
      "Config mismatch: " + sealedPath + " exists but " + modeEnvVarName +
      "=disabled. Set " + modeEnvVarName + "=required, or run the unseal tool."
    );
  }
  if (hasPlain && mode === "required") {
    throw new Error(
      "Config mismatch: " + plainPath + " is plaintext but " + modeEnvVarName +
      "=required. Run the seal tool to migrate, or unset " + modeEnvVarName + "."
    );
  }

  if (hasSealed) {
    var raw = fs.readFileSync(sealedPath, "utf8").trim();
    return Buffer.from(vault.unseal(raw), "utf8");
  }
  if (hasPlain) {
    return fs.readFileSync(plainPath);
  }
  return null; // neither file — caller is responsible for bootstrap
}

module.exports = {
  isPemContent: isPemContent,
  sealPemFile: sealPemFile,
  unsealPemFile: unsealPemFile,
  loadPemDispatch: loadPemDispatch,
  recoverFromMarker: recoverFromMarker,
};

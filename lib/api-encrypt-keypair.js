/**
 * api-encrypt-keypair — server-side keypair for blamejs's per-session
 * apiEncrypt protocol.
 *
 * Generated once at first boot, vault-sealed on disk, loaded for every
 * subsequent boot. The pubkey half is published via blamejs's
 * publishPublicKey() route handler at `/.well-known/blamejs-pubkey`;
 * the privkey half decrypts per-session bootstrap envelopes (`_ek`)
 * received from clients.
 *
 * The keypair is a **separate** long-lived asset from the mTLS server
 * cert keypair. Tying the two together would force an apiEncrypt key
 * rotation on every ACME renewal (30–60 days), invalidating active
 * sessions. The vault is the rotation boundary instead.
 *
 * Keypair shape (matches `b.crypto.generateEncryptionKeyPair()`):
 *   { publicKey, privateKey, ecPublicKey, ecPrivateKey }   — all PEM
 *
 *   - publicKey / privateKey   = ML-KEM-1024 (post-quantum KEM)
 *   - ecPublicKey / ecPrivateKey = P-384 ECDH (classical hybrid leg)
 *
 * On-disk format: the 4-field JSON object runs through `vault.seal()`,
 * producing a single `vault:<base64>` line. Without the vault key, the
 * keypair is opaque ciphertext at rest.
 *
 * Crash-safe write protocol (mirrors lib/vault-wrap.js + cert-utils):
 *   1. Write `<path>.tmp` with mode 0o600
 *   2. Atomic rename `<path>.tmp` → `<path>`
 *
 * Vault rotation: registered in `lib/vault-rotate.js` so a full vault
 * key rotation re-seals this file with the new vault key. Without that
 * registration the file would become unreadable post-rotation.
 */
"use strict";

var fs = require("fs");
var vault = require("./vault");
var b = require("./vendor/blamejs");
var C = require("./constants");
var logger = require("../app/shared/logger");

var KEYPAIR_PATH = C.PATHS.API_ENCRYPT_KEYPAIR_SEALED;
var KEYPAIR_PATH_TMP = KEYPAIR_PATH + ".tmp";

var cached = null;

function _generate() {
  return b.crypto.generateEncryptionKeyPair();
}

function _writeSealedAtomic(json) {
  var sealed = vault.seal(json);
  fs.writeFileSync(KEYPAIR_PATH_TMP, sealed, { mode: 0o600 });
  fs.renameSync(KEYPAIR_PATH_TMP, KEYPAIR_PATH);
}

function _validateShape(pair) {
  if (!pair || typeof pair !== "object") return false;
  return typeof pair.publicKey === "string" &&
         typeof pair.privateKey === "string" &&
         typeof pair.ecPublicKey === "string" &&
         typeof pair.ecPrivateKey === "string";
}

function loadOrGenerate() {
  if (cached) return cached;

  if (fs.existsSync(KEYPAIR_PATH)) {
    var sealed = fs.readFileSync(KEYPAIR_PATH, "utf8");
    var json = vault.unseal(sealed);
    var parsed = JSON.parse(json);
    if (!_validateShape(parsed)) {
      throw new Error("api-encrypt-keypair: on-disk keypair has invalid shape");
    }
    cached = parsed;
    return cached;
  }

  var pair = _generate();
  if (!_validateShape(pair)) {
    throw new Error("api-encrypt-keypair: generated keypair has invalid shape");
  }
  _writeSealedAtomic(JSON.stringify(pair));
  logger.info("api-encrypt-keypair generated", { path: KEYPAIR_PATH });
  cached = pair;
  return cached;
}

module.exports = {
  loadOrGenerate: loadOrGenerate,
  _resetForTest: function () { cached = null; },
};

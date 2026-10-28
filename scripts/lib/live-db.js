"use strict";
/**
 * Read the live encrypted database the way lib/db.js does at boot, for the
 * offline vault tools (vault-key-rotate, vault-key-verify).
 *
 * db.key.enc is unsealed by its envelope's magic byte, as lib/vault.js unseal
 * does, and hermitstash.db.enc is decrypted through lib/db-enc-codec.js, which
 * tries the data-directory binding the server writes before the unbound form.
 * The plaintext database is written owner-only (0o600, O_EXCL | O_NOFOLLOW)
 * with an unpredictable name in the working directory tempDir() names, and is
 * removed by removeTempDb or when the process exits.
 */
var fs = require("fs");
var os = require("os");
var path = require("path");

var C = require("../../lib/constants");
var b = require("../../lib/vendor/blamejs");
var cryptoLib = require("../../lib/crypto");
var dbEncCodec = require("../../lib/db-enc-codec");

var LEGACY_ENVELOPE_MAGIC = 0xE1;
var DB_ENC_NAME = path.basename(C.PATHS.DB_ENC);
var DB_KEY_ENC_NAME = path.basename(C.PATHS.DB_KEY_ENC);

class LiveDbError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "LiveDbError";
    this.code = code;
  }
}

function present(dataDir) {
  return fs.existsSync(path.join(dataDir, DB_ENC_NAME)) &&
    fs.existsSync(path.join(dataDir, DB_KEY_ENC_NAME));
}

function unsealDbKey(dataDir, keys) {
  var sealed = fs.readFileSync(path.join(dataDir, DB_KEY_ENC_NAME), "utf8").trim();
  if (sealed.indexOf(C.VAULT_PREFIX) !== 0) {
    throw new LiveDbError("live-db/not-sealed", "db.key.enc is not vault-sealed");
  }
  var payload = sealed.substring(C.VAULT_PREFIX.length);
  var first = Buffer.from(payload.substring(0, 4), "base64")[0];
  var b64;
  try {
    b64 = first === LEGACY_ENVELOPE_MAGIC ? cryptoLib.decrypt(payload, keys) : b.crypto.decrypt(payload, keys);
  } catch (e) {
    throw new LiveDbError("live-db/db-key-unsealable", "db.key.enc cannot be unsealed with this vault keypair: " + (e && e.message));
  }
  return Buffer.from(b64, "base64");
}

function decrypt(dataDir, dbKey) {
  var packed = fs.readFileSync(path.join(dataDir, DB_ENC_NAME));
  try { return dbEncCodec.decryptDbEnc(packed, dbKey, dataDir); }
  catch (e) {
    throw new LiveDbError("live-db/db-undecryptable",
      "hermitstash.db.enc cannot be decrypted with the key in db.key.enc for " + dataDir + ": " + (e && e.message));
  }
}

// The same working directory lib/db.js uses for its plaintext database
// (HERMITSTASH_TMPDIR, else /dev/shm), else the OS temp directory. None of them
// is the data directory, so a copy left behind by a killed process is never
// carried into a rotation or onto the data volume.
function tempDir() {
  if (process.env.HERMITSTASH_TMPDIR) return process.env.HERMITSTASH_TMPDIR;
  if (fs.existsSync("/dev/shm")) return "/dev/shm";
  return os.tmpdir();
}

var _temps = Object.create(null);
var _exitHooked = false;

function writeTempDb(plain, label) {
  // Not "hermitstash-*.db": lib/db.js sweeps working files of that name whose
  // owner has exited.
  var tmpPath = path.join(tempDir(), "hs-vault-tool-" + label + "-" + b.crypto.generateToken(16) + ".db");
  b.atomicFile.writeSync(tmpPath, plain, { fileMode: 0o600 });
  _temps[tmpPath] = true;
  if (!_exitHooked) {
    _exitHooked = true;
    process.on("exit", function () { Object.keys(_temps).forEach(removeTempDb); });
  }
  return tmpPath;
}

function removeTempDb(tmpPath) {
  ["", "-wal", "-shm"].forEach(function (suffix) {
    try { fs.unlinkSync(tmpPath + suffix); } catch (_e) { /* already gone */ }
  });
  delete _temps[tmpPath];
}

module.exports = {
  LiveDbError: LiveDbError,
  present: present,
  unsealDbKey: unsealDbKey,
  decrypt: decrypt,
  writeTempDb: writeTempDb,
  removeTempDb: removeTempDb,
};

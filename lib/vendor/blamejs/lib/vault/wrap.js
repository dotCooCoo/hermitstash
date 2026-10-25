// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.vaultWrap
 * @nav    Crypto
 * @title  Vault Wrap
 * @slug   vault-wrap
 *
 * @intro
 *   The sealed-file format the vault keeps its keypair in: an Argon2id
 *   derivation from the operator's passphrase, then XChaCha20-Poly1305 over
 *   the plaintext, with the derivation's own parameters written into the
 *   header.
 *
 *   Recording the parameters is what makes an old file readable after the
 *   defaults change. Unsealing derives at the cost the file names rather than
 *   the cost this build would choose, so raising the default does not orphan
 *   the files already written. The parameters are bounded on the way in, so a
 *   file cannot ask the reader for a four-gigabyte derivation.
 *
 *   Every header and parameter check raises its own code, and an unreadable
 *   file is distinguishable from a rejected passphrase. A truncated or
 *   misversioned file is an operator pointing at the wrong path or a damaged
 *   disk, which is a different problem from a wrong passphrase and wants a
 *   different answer.
 *
 * @card
 *   The vault's sealed-file format: Argon2id from the passphrase,
 *   XChaCha20-Poly1305 over the bytes, and the derivation parameters in the
 *   header so an old file stays readable.
 */

var nodeTypes = require("node:util").types;
var argon2 = require("../argon2-builtin");
var C = require("../constants");
var { xchacha20poly1305 } = require("../vendor/noble-ciphers.cjs");
var { generateBytes } = require("../crypto");
var safeBuffer = require("../safe-buffer");

var MAGIC = 0xE2;
var FORMAT_VERSION = 0x01;
var KDF_ARGON2ID = 0x01;
var CIPHER_XCHACHA20_POLY = 0x02;
var NONCE_LENGTH = C.BYTES.bytes(24);

var DEFAULT_ARGON2 = Object.freeze({
  memoryCost:  C.BYTES.mib(64) / C.BYTES.kib(1),
  timeCost:    3,
  parallelism: 4,
  saltLength:  C.BYTES.bytes(16),
  hashLength:  C.BYTES.bytes(32),
});

var MIN_SALT_LENGTH = C.BYTES.bytes(8);
var MAX_SALT_LENGTH = C.BYTES.bytes(64);
var MAX_PASSPHRASE_LENGTH = C.BYTES.kib(4);
var MIN_ARGON2_MEMORY = C.BYTES.mib(1)  / C.BYTES.kib(1);
var MAX_ARGON2_MEMORY = C.BYTES.gib(4)  / C.BYTES.kib(1);
var MAX_ARGON2_TIME = 100;
var MAX_ARGON2_PARALLELISM = 0x20;

function _badInput(code, message) {
  var e = new Error(message);
  e.code = "vault-wrap/" + code;
  return e;
}

function _unreadable(code, message) {
  var e = new Error(message);
  e.code = "vault-wrap/" + code;
  e.vaultWrapUnreadable = true;
  return e;
}

/**
 * @primitive b.vaultWrap.isUnreadableFile
 * @signature b.vaultWrap.isUnreadableFile(err)
 * @since     0.21.1
 * @status    stable
 * @related   b.vaultWrap.unwrap, b.vaultWrap.parseHeader
 *
 * Answer whether an error from `unwrap` or `parseHeader` means the sealed file
 * could not be read, rather than that the passphrase was rejected or that a
 * derivation bound refused the work. Every parse failure carries a
 * `vault-wrap/*` code, so separating the file from the passphrase by code alone
 * means restating the list of parse codes, and that list grows with each new
 * check.
 *
 * A passphrase rejection, `vault-wrap/passphrase-rejected`, and a derivation
 * refusal such as `argon2/cost-over-ceiling` both answer false: the file was
 * read, and something else failed.
 *
 * @example
 *   try {
 *     b.vaultWrap.unwrap(sealedBytes, passphrase);
 *   } catch (err) {
 *     b.vaultWrap.isUnreadableFile(err);   // → true when the file is the problem
 *   }
 */
function isUnreadableFile(err) {
  return !!(err && err.vaultWrapUnreadable === true);
}

function _assertSaltBounds(salt) {
  if (!nodeTypes.isUint8Array(salt)) {
    throw _badInput("bad-salt", "salt must be a Buffer/Uint8Array");
  }
  if (salt.length < MIN_SALT_LENGTH || salt.length > MAX_SALT_LENGTH) {
    throw _badInput("bad-salt",
      "salt length out of range [" + MIN_SALT_LENGTH + "," + MAX_SALT_LENGTH + "]: " + salt.length);
  }
}

/**
 * @primitive b.vaultWrap.buildHeader
 * @signature b.vaultWrap.buildHeader(params)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultWrap.parseHeader, b.vaultWrap.wrap
 *
 * Build the header a sealed file starts with: the magic byte, the format
 * version, the KDF and cipher identifiers, the Argon2id cost, and the salt and
 * nonce with their lengths.
 *
 * `wrap` calls this, and it is exported for a tool that writes or inspects the
 * format directly. `salt` and `nonce` must be byte arrays, each raising
 * `vault-wrap/bad-salt` or `vault-wrap/bad-nonce` otherwise, and the nonce has
 * to be the cipher's 24 bytes.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var header = b.vaultWrap.buildHeader({
 *     salt:             Buffer.alloc(16),
 *     nonce:            Buffer.alloc(b.vaultWrap.NONCE_LENGTH),
 *     memoryCost:       b.vaultWrap.DEFAULT_ARGON2.memoryCost,
 *     timeCost:         b.vaultWrap.DEFAULT_ARGON2.timeCost,
 *     parallelism:      b.vaultWrap.DEFAULT_ARGON2.parallelism,
 *     ciphertextLength: 48,
 *   });
 *   header[0] === b.vaultWrap.MAGIC;   // → true
 */
function buildHeader(params) {
  var salt = params.salt;
  var nonce = params.nonce;
  _assertSaltBounds(salt);
  if (!nodeTypes.isUint8Array(nonce)) {
    throw _badInput("bad-nonce", "nonce must be a Buffer/Uint8Array");
  }
  if (nonce.length !== NONCE_LENGTH) {
    throw _badInput("bad-nonce",
      "nonce must be " + NONCE_LENGTH + " bytes, got " + nonce.length);
  }
  var saltLen = salt.length;
  var headerLen = 12 + saltLen + 2 + NONCE_LENGTH + 4;
  var h = Buffer.alloc(headerLen);
  h[0] = MAGIC;
  h[1] = FORMAT_VERSION;
  h[2] = KDF_ARGON2ID;
  h[3] = 0x00;
  h.writeUInt32BE(params.memoryCost >>> 0, 4);
  h.writeUInt16BE(params.timeCost & 0xffff, C.BYTES.bytes(8));
  h[10] = params.parallelism & 0xff;
  h[11] = saltLen;
  Buffer.from(salt).copy(h, 12);
  var pos = 12 + saltLen;
  h[pos] = CIPHER_XCHACHA20_POLY;
  h[pos + 1] = NONCE_LENGTH;
  Buffer.from(nonce).copy(h, pos + 2);
  pos += 2 + NONCE_LENGTH;
  h.writeUInt32BE(params.ciphertextLength >>> 0, pos);
  return h;
}

/**
 * @primitive b.vaultWrap.parseHeader
 * @signature b.vaultWrap.parseHeader(buf)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultWrap.buildHeader, b.vaultWrap.unwrap
 *
 * Read a sealed file's header and return its parameters, including where the
 * ciphertext begins and how long it is.
 *
 * Each check has its own code, so a reader can say what is wrong with the
 * file: `vault-wrap/too-short`, `/bad-magic`, `/unsupported-version`,
 * `/unsupported-kdf`, `/unsupported-cipher`, `/bad-memory-cost`,
 * `/bad-time-cost`, `/bad-parallelism`, `/bad-salt-length`,
 * `/bad-nonce-length`, `/ciphertext-too-short` and `/truncated`.
 *
 * The cost bounds are checked here rather than at derivation time, so a file
 * claiming a four-gigabyte derivation is refused before any memory is
 * allocated for it.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var parsed = b.vaultWrap.parseHeader(sealed);
 *   parsed.params.memoryCost;      // → the cost this file was written at
 */
function parseHeader(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  if (buf.length < 12) {
    throw _unreadable("too-short", "wrapped vault file too short (< 12 bytes)");
  }
  if (buf[0] !== MAGIC) {
    throw _unreadable("bad-magic",
      "not a wrapped vault file (magic byte 0x" + buf[0].toString(0x10) +
      " != 0x" + MAGIC.toString(0x10) + ")");
  }
  if (buf[1] !== FORMAT_VERSION) {
    throw _unreadable("unsupported-version",
      "unsupported wrapped-vault format version " + buf[1] + " — upgrade blamejs");
  }
  if (buf[2] !== KDF_ARGON2ID) {
    throw _unreadable("unsupported-kdf", "unsupported KDF ID " + buf[2] + " — upgrade blamejs");
  }

  var memoryCost = buf.readUInt32BE(4);
  var timeCost = buf.readUInt16BE(C.BYTES.bytes(8));
  var parallelism = buf[10];
  var saltLen = buf[11];

  if (memoryCost < MIN_ARGON2_MEMORY || memoryCost > MAX_ARGON2_MEMORY) {
    throw _unreadable("bad-memory-cost", "argon2 memory cost out of bounds: " + memoryCost + " KiB");
  }
  if (timeCost < 1 || timeCost > MAX_ARGON2_TIME) {
    throw _unreadable("bad-time-cost", "argon2 time cost out of bounds: " + timeCost);
  }
  if (parallelism < 1 || parallelism > MAX_ARGON2_PARALLELISM) {
    throw _unreadable("bad-parallelism", "argon2 parallelism out of bounds: " + parallelism);
  }
  if (saltLen < MIN_SALT_LENGTH || saltLen > MAX_SALT_LENGTH) {
    throw _unreadable("bad-salt-length", "salt length out of bounds: " + saltLen);
  }

  var saltEnd = 12 + saltLen;
  if (buf.length < saltEnd + 2 + NONCE_LENGTH + 4) {
    throw _unreadable("truncated", "wrapped vault file truncated (header incomplete)");
  }

  var salt = Buffer.from(buf.subarray(12, saltEnd));
  var cipherId = buf[saltEnd];
  if (cipherId !== CIPHER_XCHACHA20_POLY) {
    throw _unreadable("unsupported-cipher",
      "unsupported cipher ID " + cipherId + " — upgrade blamejs");
  }
  var nonceLen = buf[saltEnd + 1];
  if (nonceLen !== NONCE_LENGTH) {
    throw _unreadable("bad-nonce-length",
      "invalid nonce length " + nonceLen + " (expected " + NONCE_LENGTH + ")");
  }
  var nonce = Buffer.from(buf.subarray(saltEnd + 2, saltEnd + 2 + NONCE_LENGTH));
  var ctLenPos = saltEnd + 2 + NONCE_LENGTH;
  var ciphertextLength = buf.readUInt32BE(ctLenPos);
  var headerEnd = ctLenPos + 4;

  if (ciphertextLength < C.BYTES.bytes(16)) {
    throw _unreadable("ciphertext-too-short",
      "ciphertext length too short (< Poly1305 tag): " + ciphertextLength);
  }
  if (buf.length < headerEnd + ciphertextLength) {
    throw _unreadable("truncated",
      "wrapped vault file truncated (ciphertext length " + ciphertextLength +
      " exceeds remaining " + (buf.length - headerEnd) + ")");
  }

  return {
    params: {
      memoryCost:       memoryCost,
      timeCost:         timeCost,
      parallelism:      parallelism,
      salt:             salt,
      nonce:            nonce,
      ciphertextLength: ciphertextLength,
    },
    headerEnd:   headerEnd,
    headerBytes: Buffer.from(buf.subarray(0, headerEnd)),
  };
}

/**
 * @primitive b.vaultWrap.deriveWrappingKey
 * @signature b.vaultWrap.deriveWrappingKey(passphrase, salt, argonParams?)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultWrap.wrap, b.auth.password.gate
 *
 * Derive the 32-byte wrapping key from a passphrase and salt, through the
 * Argon2id gate. Missing parameters fall back to the format's defaults.
 *
 * `wrap` and `unwrap` both go through this, which is why both are subject to
 * the gate's concurrency bound and to the cost ceiling: a sealed read is an
 * Argon2id derivation like any other, and a deployment that bounds its login
 * path has bounded this too.
 *
 * An empty passphrase, or one over 4 KiB, raises
 * `vault-wrap/bad-passphrase`, and a salt outside 8 to 64 bytes raises
 * `vault-wrap/bad-salt`.
 *
 * @opts
 *   memoryCost:  number,   // KiB; default 65536
 *   timeCost:    number,   // passes; default 3
 *   parallelism: number,   // lanes; default 4
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var key = await b.vaultWrap.deriveWrappingKey("passphrase", Buffer.alloc(16));
 *   key.length;                    // → 32
 */
async function deriveWrappingKey(passphrase, salt, argonParams) {
  argonParams = argonParams || {};
  var weOwnPwBuf = !Buffer.isBuffer(passphrase);
  var pwBuf = Buffer.isBuffer(passphrase) ? passphrase : Buffer.from(String(passphrase), "utf8");
  if (pwBuf.length === 0) {
    if (weOwnPwBuf) safeBuffer.secureZero(pwBuf);
    throw _badInput("bad-passphrase", "passphrase must not be empty");
  }
  if (pwBuf.length > MAX_PASSPHRASE_LENGTH) {
    if (weOwnPwBuf) safeBuffer.secureZero(pwBuf);
    throw _badInput("bad-passphrase",
      "passphrase exceeds " + MAX_PASSPHRASE_LENGTH + " byte sanity limit");
  }
  try {
    _assertSaltBounds(salt);
  } catch (e) {
    if (weOwnPwBuf) safeBuffer.secureZero(pwBuf);
    throw e;
  }
  var raw;
  try {
    raw = await argon2.hash(pwBuf, {
      type:        argon2.argon2id,
      salt:        Buffer.from(salt),
      memoryCost:  argonParams.memoryCost  || DEFAULT_ARGON2.memoryCost,
      timeCost:    argonParams.timeCost    || DEFAULT_ARGON2.timeCost,
      parallelism: argonParams.parallelism || DEFAULT_ARGON2.parallelism,
      hashLength:  C.BYTES.bytes(32),
      raw:         true,
    });
  } finally {
    if (weOwnPwBuf) safeBuffer.secureZero(pwBuf);
  }
  if (!raw || raw.length !== C.BYTES.bytes(32)) {
    safeBuffer.secureZero(raw);
    throw _badInput("derive-failed",
      "Argon2 returned unexpected hash length: " + (raw && raw.length));
  }
  var out = Buffer.from(raw);
  safeBuffer.secureZero(raw);
  return out;
}

/**
 * @primitive b.vaultWrap.wrap
 * @signature b.vaultWrap.wrap(plaintext, passphrase, opts?)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultWrap.unwrap, b.vault.init, b.auth.password.costCeiling
 *
 * Seal bytes under a passphrase and resolve with the sealed file: header,
 * salt, nonce and ciphertext in one Buffer.
 *
 * The defaults are 64 MiB of memory, three passes and four lanes, and they are
 * written into the header so `unwrap` can reproduce them. Raising them here
 * changes what new files cost to open without affecting the files already
 * written.
 *
 * The derivation runs through the Argon2id gate, so a sealed write under load
 * can be refused with `argon2/busy` rather than queuing without limit, and it
 * is bounded by the cost ceiling. An empty passphrase, or one over 4 KiB,
 * raises `vault-wrap/bad-passphrase`.
 *
 * `salt` and `nonce` are generated unless supplied; supplying them is for
 * reproducing a known vector in a test, not for production, since reusing a
 * nonce under one key breaks the cipher's guarantee.
 *
 * @opts
 *   memoryCost:  number,   // KiB; default 65536 (64 MiB)
 *   timeCost:    number,   // passes; default 3
 *   parallelism: number,   // lanes; default 4
 *   saltLength:  number,   // bytes; default 16
 *   salt:        string,   // fixed salt; tests only
 *   nonce:       string,   // fixed nonce; tests only
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var sealed = await b.vaultWrap.wrap("the-plaintext", "correct horse battery");
 *   sealed.slice(0, 1)[0] === b.vaultWrap.MAGIC;   // → true
 */
async function wrap(plaintext, passphrase, opts) {
  opts = opts || {};
  var weOwnPlaintextBuf = !Buffer.isBuffer(plaintext);
  var plaintextBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, "utf8");

  var memoryCost  = opts.memoryCost  || DEFAULT_ARGON2.memoryCost;
  var timeCost    = opts.timeCost    || DEFAULT_ARGON2.timeCost;
  var parallelism = opts.parallelism || DEFAULT_ARGON2.parallelism;
  var saltLength  = opts.saltLength  || DEFAULT_ARGON2.saltLength;

  var salt  = opts.salt  ? Buffer.from(opts.salt)  : generateBytes(saltLength);
  var nonce = opts.nonce ? Buffer.from(opts.nonce) : generateBytes(NONCE_LENGTH);

  try {
    var wrappingKey = await deriveWrappingKey(passphrase, salt, {
      memoryCost:  memoryCost,
      timeCost:    timeCost,
      parallelism: parallelism,
    });

    try {
      var ciphertextLength = plaintextBuf.length + C.BYTES.bytes(16);
      var header = buildHeader({
        memoryCost:       memoryCost,
        timeCost:         timeCost,
        parallelism:      parallelism,
        salt:             salt,
        nonce:            nonce,
        ciphertextLength: ciphertextLength,
      });

      var ct = xchacha20poly1305(wrappingKey, nonce, header).encrypt(plaintextBuf);
      var ctBuf = Buffer.from(ct);
      if (ctBuf.length !== ciphertextLength) {
        throw _badInput("length-mismatch",
          "internal: ciphertext length mismatch (" + ctBuf.length + " != " + ciphertextLength + ")");
      }
      return Buffer.concat([header, ctBuf]);
    } finally {
      safeBuffer.secureZero(wrappingKey);
    }
  } finally {
    if (weOwnPlaintextBuf) safeBuffer.secureZero(plaintextBuf);
  }
}

/**
 * @primitive b.vaultWrap.unwrap
 * @signature b.vaultWrap.unwrap(sealed, passphrase)
 * @since     0.1.96
 * @status    stable
 * @related   b.vaultWrap.wrap, b.vaultWrap.parseHeader
 *
 * Open a sealed file and resolve with the plaintext Buffer.
 *
 * The derivation uses the parameters recorded in the file, not this build's
 * defaults, which is how a file written under an older cost still opens. The
 * cost ceiling still applies, so a header naming more work than the ceiling
 * allows raises `argon2/cost-over-ceiling` rather than being honored.
 *
 * A file that is not readable as a sealed file raises its own code and sets a
 * marker the callers read, so an operator pointed at the wrong path, or
 * holding a file a full disk truncated, is told that rather than being told
 * the passphrase was wrong. A wrong passphrase fails the AEAD tag, which
 * cannot be told apart from tampering, so that error says both.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var plain = await b.vaultWrap.unwrap(sealed, "correct horse battery");
 *   plain.toString("utf8");        // → "the-plaintext"
 */
async function unwrap(sealed, passphrase) {
  var parsed = parseHeader(sealed);
  var ciphertext = sealed.subarray(parsed.headerEnd, parsed.headerEnd + parsed.params.ciphertextLength);

  var wrappingKey = await deriveWrappingKey(passphrase, parsed.params.salt, {
    memoryCost:  parsed.params.memoryCost,
    timeCost:    parsed.params.timeCost,
    parallelism: parsed.params.parallelism,
  });

  try {
    var pt = xchacha20poly1305(wrappingKey, parsed.params.nonce, parsed.headerBytes).decrypt(ciphertext);
    return Buffer.from(pt);
  } catch (_e) {
    var rejected = new Error("Passphrase rejected or wrapped file corrupted");
    rejected.code = "vault-wrap/passphrase-rejected";
    throw rejected;
  } finally {
    safeBuffer.secureZero(wrappingKey);
  }
}

module.exports = {
  wrap:                  wrap,
  unwrap:                unwrap,
  buildHeader:           buildHeader,
  parseHeader:           parseHeader,
  deriveWrappingKey:     deriveWrappingKey,
  isUnreadableFile:      isUnreadableFile,
  MAGIC:                 MAGIC,
  FORMAT_VERSION:        FORMAT_VERSION,
  KDF_ARGON2ID:          KDF_ARGON2ID,
  CIPHER_XCHACHA20_POLY: CIPHER_XCHACHA20_POLY,
  NONCE_LENGTH:          NONCE_LENGTH,
  DEFAULT_ARGON2:        DEFAULT_ARGON2,
};

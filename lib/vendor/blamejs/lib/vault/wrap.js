// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Vault-key wrapping — passphrase-derived AEAD wrap for the framework's vault key.
 *
 * Format (magic 0xE2):
 *   byte 0:      0xE2 magic
 *   byte 1:      format version (0x01)
 *   byte 2:      KDF ID (0x01 Argon2id)
 *   byte 3:      reserved (0x00)
 *   bytes 4-7:   Argon2 memory cost (KiB, uint32 BE)
 *   bytes 8-9:   Argon2 time cost (uint16 BE)
 *   byte  10:    Argon2 parallelism (uint8)
 *   byte  11:    salt length (uint8)
 *   bytes 12..:  salt
 *   byte  N:     cipher ID (0x02 XChaCha20-Poly1305)
 *   byte  N+1:   nonce length (uint8, must be 24)
 *   bytes N+2..: nonce (24 bytes)
 *   bytes N+26..N+29: ciphertext length (uint32 BE)
 *   bytes N+30..: XChaCha20-Poly1305 ciphertext + tag
 *
 * The entire header (bytes 0 through N+29) is bound as AAD on the AEAD tag.
 * Any header-byte flip therefore fails AEAD verification — prevents
 * downgrade-in-header attacks on KDF params or cipher ID.
 *
 * This module is PURE — no filesystem I/O. Callers handle reading/writing.
 * wrap() and unwrap() are async because Argon2 is async via its native binding.
 */
var argon2 = require("../argon2-builtin");
var C = require("../constants");
var { xchacha20poly1305 } = require("../vendor/noble-ciphers.cjs");
var { generateBytes } = require("../crypto");
var safeBuffer = require("../safe-buffer");

// ---- Format constants ----
var MAGIC = 0xE2;
var FORMAT_VERSION = 0x01;
var KDF_ARGON2ID = 0x01;
var CIPHER_XCHACHA20_POLY = 0x02;
var NONCE_LENGTH = C.BYTES.bytes(24);

// ---- Default Argon2id parameters ----
// 64 MiB / t=3 / p=4 targets ~1s derivation on commodity 2026 hardware —
// painful for offline brute force, tolerable for an operator-initiated boot.
// memoryCost is denominated in KiB per RFC 9106 §3.1, so the 64 MiB target
// expresses as MiB→KiB through the framework's byte helpers.
var DEFAULT_ARGON2 = Object.freeze({
  memoryCost:  C.BYTES.mib(64) / C.BYTES.kib(1),
  timeCost:    3,
  parallelism: 4,
  saltLength:  C.BYTES.bytes(16),
  hashLength:  C.BYTES.bytes(32),
});

// ---- Hard bounds — reject malformed or adversarial headers ----
var MIN_SALT_LENGTH = C.BYTES.bytes(8);
var MAX_SALT_LENGTH = C.BYTES.bytes(64);
var MAX_PASSPHRASE_LENGTH = C.BYTES.kib(4);
// argon2 memoryCost is denominated in KiB per RFC 9106 §3.1, not bytes.
// Express the bound as a byte-quantity divided by KiB so the framework's
// C.BYTES helpers stay the single source of truth for the underlying scale.
var MIN_ARGON2_MEMORY = C.BYTES.mib(1)  / C.BYTES.kib(1);  // 1 MiB-in-KiB
var MAX_ARGON2_MEMORY = C.BYTES.gib(4)  / C.BYTES.kib(1);  // 4 GiB-in-KiB
var MAX_ARGON2_TIME = 100;
// Argon2 lane count cap. Hex form because the literal isn't a byte
// quantity — using C.BYTES.* would mis-name the unit at the call site.
var MAX_ARGON2_PARALLELISM = 0x20;

function buildHeader(params) {
  var salt = params.salt;
  var nonce = params.nonce;
  if (!Buffer.isBuffer(salt) && !(salt instanceof Uint8Array)) {
    throw new Error("salt must be a Buffer/Uint8Array");
  }
  if (!Buffer.isBuffer(nonce) && !(nonce instanceof Uint8Array)) {
    throw new Error("nonce must be a Buffer/Uint8Array");
  }
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error("nonce must be " + NONCE_LENGTH + " bytes, got " + nonce.length);
  }
  if (salt.length < MIN_SALT_LENGTH || salt.length > MAX_SALT_LENGTH) {
    throw new Error("salt length out of range [" + MIN_SALT_LENGTH + "," + MAX_SALT_LENGTH + "]: " + salt.length);
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

function parseHeader(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  if (buf.length < 12) throw new Error("wrapped vault file too short (< 12 bytes)");
  if (buf[0] !== MAGIC) {
    throw new Error("not a wrapped vault file (magic byte 0x" + buf[0].toString(0x10) +
      " != 0x" + MAGIC.toString(0x10) + ")");
  }
  if (buf[1] !== FORMAT_VERSION) {
    throw new Error("unsupported wrapped-vault format version " + buf[1] + " — upgrade blamejs");
  }
  if (buf[2] !== KDF_ARGON2ID) {
    throw new Error("unsupported KDF ID " + buf[2] + " — upgrade blamejs");
  }
  // byte 3 reserved

  var memoryCost = buf.readUInt32BE(4);
  var timeCost = buf.readUInt16BE(C.BYTES.bytes(8));
  var parallelism = buf[10];
  var saltLen = buf[11];

  if (memoryCost < MIN_ARGON2_MEMORY || memoryCost > MAX_ARGON2_MEMORY) {
    throw new Error("argon2 memory cost out of bounds: " + memoryCost + " KiB");
  }
  if (timeCost < 1 || timeCost > MAX_ARGON2_TIME) {
    throw new Error("argon2 time cost out of bounds: " + timeCost);
  }
  if (parallelism < 1 || parallelism > MAX_ARGON2_PARALLELISM) {
    throw new Error("argon2 parallelism out of bounds: " + parallelism);
  }
  if (saltLen < MIN_SALT_LENGTH || saltLen > MAX_SALT_LENGTH) {
    throw new Error("salt length out of bounds: " + saltLen);
  }

  var saltEnd = 12 + saltLen;
  if (buf.length < saltEnd + 2 + NONCE_LENGTH + 4) {
    throw new Error("wrapped vault file truncated (header incomplete)");
  }

  var salt = Buffer.from(buf.subarray(12, saltEnd));
  var cipherId = buf[saltEnd];
  if (cipherId !== CIPHER_XCHACHA20_POLY) {
    throw new Error("unsupported cipher ID " + cipherId + " — upgrade blamejs");
  }
  var nonceLen = buf[saltEnd + 1];
  if (nonceLen !== NONCE_LENGTH) {
    throw new Error("invalid nonce length " + nonceLen + " (expected " + NONCE_LENGTH + ")");
  }
  var nonce = Buffer.from(buf.subarray(saltEnd + 2, saltEnd + 2 + NONCE_LENGTH));
  var ctLenPos = saltEnd + 2 + NONCE_LENGTH;
  var ciphertextLength = buf.readUInt32BE(ctLenPos);
  var headerEnd = ctLenPos + 4;

  if (ciphertextLength < C.BYTES.bytes(16)) {
    throw new Error("ciphertext length too short (< Poly1305 tag): " + ciphertextLength);
  }
  if (buf.length < headerEnd + ciphertextLength) {
    throw new Error("wrapped vault file truncated (ciphertext length " + ciphertextLength +
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

async function deriveWrappingKey(passphrase, salt, argonParams) {
  argonParams = argonParams || {};
  // Track whether we own pwBuf (we allocated it from a string). When the
  // caller passed a Buffer directly we don't own it — zeroing would
  // mutate caller state.
  var weOwnPwBuf = !Buffer.isBuffer(passphrase);
  var pwBuf = Buffer.isBuffer(passphrase) ? passphrase : Buffer.from(String(passphrase), "utf8");
  if (pwBuf.length === 0) {
    if (weOwnPwBuf) safeBuffer.secureZero(pwBuf);
    throw new Error("passphrase must not be empty");
  }
  if (pwBuf.length > MAX_PASSPHRASE_LENGTH) {
    if (weOwnPwBuf) safeBuffer.secureZero(pwBuf);
    throw new Error("passphrase exceeds " + MAX_PASSPHRASE_LENGTH + " byte sanity limit");
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
    throw new Error("Argon2 returned unexpected hash length: " + (raw && raw.length));
  }
  // Buffer.from(raw) copies bytes — the original `raw` Uint8Array can be
  // zeroed without affecting the returned Buffer.
  var out = Buffer.from(raw);
  safeBuffer.secureZero(raw);
  return out;
}

async function wrap(plaintext, passphrase, opts) {
  opts = opts || {};
  // We own plaintextBuf only if we converted from a string. When the
  // caller passed a Buffer directly we don't own it.
  var weOwnPlaintextBuf = !Buffer.isBuffer(plaintext);
  var plaintextBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, "utf8");

  var memoryCost  = opts.memoryCost  || DEFAULT_ARGON2.memoryCost;
  var timeCost    = opts.timeCost    || DEFAULT_ARGON2.timeCost;
  var parallelism = opts.parallelism || DEFAULT_ARGON2.parallelism;
  var saltLength  = opts.saltLength  || DEFAULT_ARGON2.saltLength;

  var salt  = opts.salt  ? Buffer.from(opts.salt)  : generateBytes(saltLength);
  var nonce = opts.nonce ? Buffer.from(opts.nonce) : generateBytes(NONCE_LENGTH);

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
      throw new Error("internal: ciphertext length mismatch (" + ctBuf.length + " != " + ciphertextLength + ")");
    }
    return Buffer.concat([header, ctBuf]);
  } finally {
    safeBuffer.secureZero(wrappingKey);
    if (weOwnPlaintextBuf) safeBuffer.secureZero(plaintextBuf);
  }
}

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
    // Any AEAD failure — wrong passphrase, header tampered, ciphertext tampered.
    // Deliberately do not expose which to the caller.
    throw new Error("Passphrase rejected or wrapped file corrupted");
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
  MAGIC:                 MAGIC,
  FORMAT_VERSION:        FORMAT_VERSION,
  KDF_ARGON2ID:          KDF_ARGON2ID,
  CIPHER_XCHACHA20_POLY: CIPHER_XCHACHA20_POLY,
  NONCE_LENGTH:          NONCE_LENGTH,
  DEFAULT_ARGON2:        DEFAULT_ARGON2,
};

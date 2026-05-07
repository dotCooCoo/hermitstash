"use strict";
// bench symmetric XChaCha20-Poly1305 round-trip via crypto.encryptPacked /
// decryptPacked. This is the hot path the vault.seal call lands on after
// the KEM has handed off a per-blob symmetric key.

var nodeCrypto = require("node:crypto");
var crypto = require("../lib/crypto");

var key32  = nodeCrypto.randomBytes(32);
var small  = Buffer.from("user@example.com");
var medium = Buffer.alloc(1024).fill(0x41);
var large  = Buffer.alloc(16 * 1024).fill(0x41);

var smallEnc  = crypto.encryptPacked(small,  key32);
var mediumEnc = crypto.encryptPacked(medium, key32);
var largeEnc  = crypto.encryptPacked(large,  key32);

module.exports = {
  name: "crypto-symmetric",
  benchmarks: {
    "encryptPacked 16 bytes":  function () { crypto.encryptPacked(small,  key32); },
    "decryptPacked 16 bytes":  function () { crypto.decryptPacked(smallEnc,  key32); },
    "encryptPacked 1 KB":      function () { crypto.encryptPacked(medium, key32); },
    "decryptPacked 1 KB":      function () { crypto.decryptPacked(mediumEnc, key32); },
    "encryptPacked 16 KB":     function () { crypto.encryptPacked(large,  key32); },
    "decryptPacked 16 KB":     function () { crypto.decryptPacked(largeEnc,  key32); },
  },
};

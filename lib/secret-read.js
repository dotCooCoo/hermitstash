/**
 * Shared TOCTOU/symlink-safe read for the small sealed-secret and crash-recovery
 * marker files HermitStash writes itself (vault key, sealed PEMs, migration /
 * rotation markers, the sealed apiEncrypt keypair).
 *
 * Single source of truth so the seal/unseal/boot-recovery paths can't drift
 * apart: refuse a symlink source and any inode swap between open and read
 * (CWE-367 / CWE-59), capped at 1 MiB (every file in scope is tiny). Pass
 * { encoding: "utf8" } for text, omit for a Buffer; any opt overrides the
 * defaults (callers wire their own errorFor where they need a typed result).
 *
 * Not a `safe-*` parser primitive — it ships no bytes-parser of its own; the
 * framework's b.atomicFile.fdSafeReadSync does the actual TOCTOU/symlink work.
 */
"use strict";

var b = require("./vendor/blamejs");
var C = require("./constants");

function safeReadSecretFile(path, opts) {
  return b.atomicFile.fdSafeReadSync(path, Object.assign({
    refuseSymlink: true, inodeCheck: true, maxBytes: C.BYTES.mib(1),
  }, opts || {}));
}

module.exports = { safeReadSecretFile: safeReadSecretFile };

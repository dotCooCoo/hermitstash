"use strict";
/**
 * @module b.safeArchive
 * @nav    Tools
 * @title  Safe Archive
 *
 * @intro
 *   One-liner safe-extract orchestrator for adversarial archives.
 *   Combines `b.archive.read` + `b.guardArchive.inspect` + `b.guardFilename.
 *   verifyExtractionPath` + zip-bomb + entry-type policy + audit chain
 *   into a single call.
 *
 *   The 90%-case workflow — operator receives a hostile-shaped archive
 *   from an upload / external system / pipeline, wants to extract it
 *   into a quarantine directory with every defense default-on, and
 *   doesn't want to learn the read/guard/safeDecompress composition
 *   surface to do it.
 *
 *   `b.safeArchive.extract({ source, destination, ... })` does the
 *   composition for them. Operators with fine-grained control needs
 *   reach for `b.archive.read.zip(adapter)` directly + assemble the
 *   pipeline manually.
 *
 *   Format auto-detection sniffs the first ~512 bytes for magic
 *   signatures: ZIP (LFH magic `0x04034b50` + EOCD magic `0x06054b50`),
 *   tar (`ustar` at offset 257), gzip / tar.gz (RFC 1952 magic), and
 *   `b.crypto.encryptPacked`-wrapped envelopes (auto-unwrapped before
 *   format detection). Unrecognized inputs are flagged
 *   `safe-archive/format-unsupported`.
 *
 *   The orchestrator refuses the WHOLE archive on any single critical
 *   guard issue — no partial extraction. Cleanup is `fs.rm`-recursive
 *   on the destination if extraction was interrupted, so a failed
 *   extract leaves no half-state on disk.
 *
 * @card
 *   One-liner safe-extract orchestrator — read + guard + path-safety + bomb caps + audit.
 */

var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var C = require("./constants");
var { defineClass } = require("./framework-error");

var SafeArchiveError = defineClass("SafeArchiveError", { alwaysPermanent: true });

var archiveRead = lazyRequire(function () { return require("./archive-read"); });
var archiveAdapters = lazyRequire(function () { return require("./archive-adapters"); });
var archiveTarRead = lazyRequire(function () { return require("./archive-tar-read"); });
var archiveGz = lazyRequire(function () { return require("./archive-gz"); });
var archiveWrap = lazyRequire(function () { return require("./archive-wrap"); });

// ---- Format sniffing ----------------------------------------------------

// ZIP local file header magic per APPNOTE §4.3.7.
// ZIP empty-archive EOCD magic per APPNOTE §4.3.16.
var MAGIC_ZIP_LFH  = 0x04034b50;
var MAGIC_ZIP_EOCD = 0x06054b50;
// GZIP magic per RFC 1952 §2.3.1.
var MAGIC_GZIP_BE  = 0x1f8b;
// b.crypto.encryptPacked envelope magic — the prefix the framework's
// PQ envelope writes. (Sentinel value for v0.12.10+ Flavor 1 unwrap.)
var MAGIC_ENCPACKED = "EPACK";

async function _sniffMagic(adapter) {
  // For random-access adapters, the format sniffer reads the first
  // 512 bytes — enough for ZIP + GZIP + b.crypto.encryptPacked magic
  // detection. tar magic lives at offset 257 inside the first 512-
  // byte header block, so we need at least 263 bytes; 512 covers it.
  if (adapter.kind !== "random-access") {
    throw new SafeArchiveError("safe-archive/sniff-unsupported-adapter",
      "format sniffing requires a random-access adapter (got " + adapter.kind + ")");
  }
  var size = adapter.size;
  if (size == null && typeof adapter.resolveSize === "function") {
    size = await adapter.resolveSize();
  }
  if (typeof size !== "number" || size < 4) {
    throw new SafeArchiveError("safe-archive/too-small",
      "archive too small to determine format (size=" + size + ")");
  }
  var head = await adapter.range(0, Math.min(C.BYTES.bytes(512), size));
  // ZIP — LFH at offset 0 (most common) OR empty-archive EOCD at offset 0.
  if (head.length >= 4) {
    var first4 = head.readUInt32LE(0);
    if (first4 === MAGIC_ZIP_LFH) return { format: "zip", subkind: "lfh" };
    if (first4 === MAGIC_ZIP_EOCD) return { format: "zip", subkind: "empty" };
  }
  // GZIP — 2-byte BE magic.
  if (head.length >= 2) {
    var be2 = head.readUInt16BE(0);
    if (be2 === MAGIC_GZIP_BE) return { format: "gzip" };
  }
  // b.crypto.encryptPacked — 5-byte ASCII prefix.
  if (head.length >= 5) {
    var prefix = head.slice(0, 5).toString("utf8");
    if (prefix === MAGIC_ENCPACKED) return { format: "encryptPacked" };
    // v0.12.15 — archive-wrap recipient envelope (v0.12.10 / BAWRP).
    if (prefix === "BAWRP") return { format: "wrap-recipient" };
    // v0.12.15 — archive-wrap passphrase envelope (v0.12.11 / BAWPP).
    if (prefix === "BAWPP") return { format: "wrap-passphrase" };
  }
  // tar — "ustar" at offset 257 within the first 512-byte header.
  if (head.length >= 263) {
    var tarMagic = head.slice(257, 262).toString("utf8");
    if (tarMagic === "ustar") return { format: "tar" };
  }
  return { format: "unknown" };
}

// Collect a random-access adapter's bytes into a Buffer. Used by
// the v0.12.15 auto-unwrap path so the envelope can be decrypted
// inline + the inner bytes re-fed to a buffer adapter for format
// re-sniffing. Adapters expose `size` + `range(offset, length)`.
async function _collectSourceBytes(source) {
  var size = source.size;
  if (size == null && typeof source.resolveSize === "function") {
    size = await source.resolveSize();
  }
  if (typeof size !== "number" || size < 0) {
    throw new SafeArchiveError("safe-archive/bad-source",
      "_collectSourceBytes: source adapter did not report a numeric size");
  }
  return source.range(0, size);
}

// ---- Public extract orchestrator ----------------------------------------

/**
 * @primitive b.safeArchive.extract
 * @signature b.safeArchive.extract(opts)
 * @since     0.12.7
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.archive.read.zip, b.guardArchive.inspect, b.guardFilename.verifyExtractionPath
 *
 * Safe-extract orchestrator. Combines read + guard + path-safety +
 * bomb caps + audit in one call.
 *
 * Refuses the whole archive on:
 *   - Format auto-detect mismatch (unknown / unsupported format).
 *   - Any critical guard issue (CVE-2025-3445 Zip Slip class + path
 *     traversal + symlink-escape + nested archive + encrypted entry).
 *   - PATH_MAX overflow on any entry name (CVE-2025-4517 defense).
 *   - Bomb-policy breach (entry-count / per-entry size / total size /
 *     expansion ratio).
 *   - LFH/CD skew on any entry.
 *
 * @opts
 *   source:           b.archive.adapters.* | Buffer | string,
 *   destination:      string (target directory; created if missing),
 *   format:           "auto" | "zip" | "tar" | "tar.gz",
 *   bombPolicy:       b.guardArchive.zipBombPolicy(...) | { ... },
 *   entryTypePolicy:  b.guardArchive.entryTypePolicy(...) | { ... },
 *   guardProfile:     "strict" | "balanced" | "permissive" | "hipaa" | ...,
 *   audit:            b.audit,
 *   signal:           AbortSignal,
 *
 * @example
 *   var result = await b.safeArchive.extract({
 *     source:      b.archive.adapters.fs("/var/uploads/payload.zip"),
 *     destination: "/var/quarantine",
 *     guardProfile: "strict",
 *   });
 *   // → { entries: [{ name, bytesWritten, path }, ...], bytesExtracted, format }
 */
async function extract(opts) {
  opts = opts || {};
  validateOpts.requireNonEmptyString(opts.destination,
    "b.safeArchive.extract: opts.destination", SafeArchiveError, "safe-archive/no-destination");
  // Resolve source → adapter. Strings become fs adapters; Buffers
  // become buffer adapters; anything else is assumed to BE an adapter
  // already.
  var source = opts.source;
  if (typeof source === "string") {
    source = archiveAdapters().fs(source, { signal: opts.signal });
  } else if (Buffer.isBuffer(source)) {
    source = archiveAdapters().buffer(source, { signal: opts.signal });
  } else if (archiveAdapters().isTrustedStreamAdapter(source)) {
    // Trusted-stream adapters are accepted by the contract but the
    // orchestrator's extract path needs random-access (CD-walk +
    // LFH/CD skew defense). Refuse upfront with a typed safe-archive
    // error so the operator sees the constraint at the entry point
    // rather than an `archive-read/wrong-entry-point` thrown by the
    // downstream reader. Trusted-stream extract via
    // `b.archive.read.zip.fromTrustedStream` is deferred to v0.12.8
    // alongside the tar reader's sequential mode.
    throw new SafeArchiveError("safe-archive/trusted-stream-unsupported",
      "extract: trusted-stream adapter sources are not supported by the orchestrator " +
      "(the adversarial-safe CD-walk requires random-access). Collect the bytes via " +
      "`b.archive.adapters.buffer(await collect(readable))` and pass that, or use " +
      "`b.archive.read.zip.fromTrustedStream` directly when the v0.12.8 sequential " +
      "extract path lands");
  } else if (!archiveAdapters().isRandomAccessAdapter(source)) {
    throw new SafeArchiveError("safe-archive/bad-source",
      "extract: opts.source must be a string path, Buffer, or b.archive.adapters.* result");
  }

  try {
    var format = opts.format || "auto";
    if (format === "auto") {
      var sniff = await _sniffMagic(source);
      format = sniff.format;
    }
    // v0.12.15 — auto-unwrap path. When the sniffer identifies a
    // wrap envelope, unwrap inline + re-sniff the inner bytes so
    // operators get a single extract() call regardless of envelope
    // shape. Operator must supply opts.recipient or opts.passphrase
    // matching the envelope kind.
    if (format === "wrap-recipient" || format === "wrap-passphrase") {
      var sealedBytes = await _collectSourceBytes(source);
      var inner;
      if (format === "wrap-recipient") {
        if (!opts.recipient) {
          throw new SafeArchiveError("safe-archive/no-recipient-for-wrap",
            "extract: source is a wrap-recipient envelope (BAWRP) but opts.recipient was not supplied. " +
            "Pass `{ recipient: { privateKey, ecPrivateKey } }` (or peer-cert form) to unwrap inline.");
        }
        inner = archiveWrap().unwrap(sealedBytes, { recipient: opts.recipient });
      } else {
        if (typeof opts.passphrase !== "string" && !Buffer.isBuffer(opts.passphrase)) {
          throw new SafeArchiveError("safe-archive/no-passphrase-for-wrap",
            "extract: source is a wrap-passphrase envelope (BAWPP) but opts.passphrase was not supplied. " +
            "Pass `{ passphrase: <string|Buffer> }` to unwrap inline.");
        }
        inner = await archiveWrap().unwrapWithPassphrase(sealedBytes, { passphrase: opts.passphrase });
      }
      // Close the original source
      // adapter BEFORE replacing it. When opts.source was a string
      // path, the fs adapter opened a file descriptor; overwriting
      // `source` loses the close reference and the descriptor
      // leaks across repeated extract() calls (eventually EMFILE
      // under load). The outer finally still closes whatever
      // `source` points at, but the original handle needs explicit
      // release here.
      if (typeof source.close === "function" && typeof opts.source === "string") {
        try { source.close(); } catch (_e) { /* drop-silent */ }
      }
      // Forward opts.signal to the
      // inner buffer adapter so abort propagation stays intact
      // across the unwrap boundary. Without it, an abort raised
      // after unwrapping would no longer cancel inner range()
      // calls, breaking the documented signal contract for
      // large wrapped archives.
      source = archiveAdapters().buffer(inner, { signal: opts.signal });
      var innerSniff = await _sniffMagic(source);
      format = innerSniff.format;
    }
    var reader;
    if (format === "zip") {
      reader = archiveRead().zip(source, {
        bombPolicy:      opts.bombPolicy,
        entryTypePolicy: opts.entryTypePolicy,
        guardProfile:    opts.guardProfile,
        audit:           opts.audit,
      });
    } else if (format === "tar") {
      reader = archiveTarRead().tar(source, {
        bombPolicy:      opts.bombPolicy,
        entryTypePolicy: opts.entryTypePolicy,
        guardProfile:    opts.guardProfile,
        audit:           opts.audit,
      });
    } else if (format === "tar.gz") {
      // gzip envelope around tar — safeDecompress caps run on the gz
      // layer before the tar walker ever sees a decompressed byte.
      reader = archiveGz().read.gz(source, {
        maxDecompressedBytes: opts.maxDecompressedBytes,
        maxExpansionRatio:    opts.maxExpansionRatio,
        audit:                opts.audit,
      }).asTar({
        bombPolicy:      opts.bombPolicy,
        entryTypePolicy: opts.entryTypePolicy,
        guardProfile:    opts.guardProfile,
        audit:           opts.audit,
      });
    } else {
      throw new SafeArchiveError("safe-archive/format-unsupported",
        "extract: format=" + JSON.stringify(format) + " — supported formats are " +
        "zip, tar, tar.gz; b.crypto.encryptPacked-wrapped archives are auto-unwrapped first");
    }
    var result = await reader.extract({
      destination:    opts.destination,
      allowDangerous: opts.allowDangerous,
    });
    return Object.assign({ format: format }, result);
  } finally {
    if (typeof source.close === "function" && typeof opts.source === "string") {
      try { source.close(); } catch (_e) { /* drop-silent */ }
    }
  }
}

/**
 * @primitive b.safeArchive.inspect
 * @signature b.safeArchive.inspect(opts)
 * @since     0.12.7
 * @status    stable
 * @related   b.safeArchive.extract, b.guardArchive.validateEntries
 *
 * Read-only inspect: format sniffing + entry-list enumeration without
 * decompression. Operators previewing an uploaded archive before
 * committing to extraction reach for this primitive.
 *
 * @opts
 *   source:          b.archive.adapters.* | Buffer | string,
 *   format:          "auto" | "zip",
 *   bombPolicy:      { ... },
 *   audit:           b.audit,
 *
 * @example
 *   var summary = await b.safeArchive.inspect({
 *     source: b.archive.adapters.fs("/var/uploads/payload.zip"),
 *   });
 *   // → { format: "zip", entries: [...], totalCompressedBytes, totalUncompressedBytes }
 */
async function inspect(opts) {
  opts = opts || {};
  var source = opts.source;
  if (typeof source === "string") {
    source = archiveAdapters().fs(source, { signal: opts.signal });
  } else if (Buffer.isBuffer(source)) {
    source = archiveAdapters().buffer(source, { signal: opts.signal });
  } else if (!archiveAdapters().isRandomAccessAdapter(source)) {
    throw new SafeArchiveError("safe-archive/bad-source",
      "inspect: opts.source must be a string path, Buffer, or random-access adapter");
  }
  try {
    var format = opts.format || "auto";
    if (format === "auto") {
      var sniff = await _sniffMagic(source);
      format = sniff.format;
    }
    // v0.12.16 — auto-unwrap path for inspect, parallel to the
    // v0.12.15 extract path. Wrap envelopes (BAWRP / BAWPP) are
    // unwrapped inline + re-sniffed so operators can enumerate
    // entries of a sealed archive in a single inspect() call.
    if (format === "wrap-recipient" || format === "wrap-passphrase") {
      var sealedBytes = await _collectSourceBytes(source);
      var inner;
      if (format === "wrap-recipient") {
        if (!opts.recipient) {
          throw new SafeArchiveError("safe-archive/no-recipient-for-wrap",
            "inspect: source is a wrap-recipient envelope (BAWRP) but opts.recipient was not supplied. " +
            "Pass `{ recipient: { privateKey, ecPrivateKey } }` (or peer-cert form) to unwrap inline.");
        }
        inner = archiveWrap().unwrap(sealedBytes, { recipient: opts.recipient });
      } else {
        if (typeof opts.passphrase !== "string" && !Buffer.isBuffer(opts.passphrase)) {
          throw new SafeArchiveError("safe-archive/no-passphrase-for-wrap",
            "inspect: source is a wrap-passphrase envelope (BAWPP) but opts.passphrase was not supplied. " +
            "Pass `{ passphrase: <string|Buffer> }` to unwrap inline.");
        }
        inner = await archiveWrap().unwrapWithPassphrase(sealedBytes, { passphrase: opts.passphrase });
      }
      // v0.12.15 P1 — close the original fs adapter (if string-
      // backed) BEFORE replacing the source reference. v0.12.15 P2
      // — forward opts.signal to the inner buffer adapter.
      if (typeof source.close === "function" && typeof opts.source === "string") {
        try { source.close(); } catch (_e) { /* drop-silent */ }
      }
      source = archiveAdapters().buffer(inner, { signal: opts.signal });
      var innerSniff = await _sniffMagic(source);
      format = innerSniff.format;
    }
    var reader;
    if (format === "zip") {
      reader = archiveRead().zip(source, {
        bombPolicy: opts.bombPolicy,
        audit:      opts.audit,
      });
    } else if (format === "tar") {
      reader = archiveTarRead().tar(source, {
        bombPolicy: opts.bombPolicy,
        audit:      opts.audit,
      });
    } else if (format === "tar.gz") {
      // v0.12.19 — inspect parity with extract for tar.gz format.
      // gz envelope auto-decompresses + the inner tar walker
      // enumerates entries without writing to disk.
      reader = archiveGz().read.gz(source, {
        maxDecompressedBytes: opts.maxDecompressedBytes,
        maxExpansionRatio:    opts.maxExpansionRatio,
        audit:                opts.audit,
      }).asTar({
        bombPolicy: opts.bombPolicy,
        audit:      opts.audit,
      });
    } else {
      throw new SafeArchiveError("safe-archive/format-unsupported",
        "inspect: format=" + JSON.stringify(format) + " — v0.12.19 ships ZIP + tar + tar.gz; auto-unwraps wrap envelopes");
    }
    var entries = await reader.inspect();
    var totalCompressed = 0;
    var totalUncompressed = 0;
    for (var i = 0; i < entries.length; i += 1) {
      totalCompressed += entries[i].compressedSize;
      totalUncompressed += entries[i].size;
    }
    return {
      format:                 format,
      entries:                entries,
      totalCompressedBytes:   totalCompressed,
      totalUncompressedBytes: totalUncompressed,
    };
  } finally {
    if (typeof source.close === "function" && typeof opts.source === "string") {
      try { source.close(); } catch (_e) { /* drop-silent */ }
    }
  }
}

module.exports = {
  extract:           extract,
  inspect:           inspect,
  SafeArchiveError:  SafeArchiveError,
  // Exposed for tests + sibling modules.
  _sniffMagic:       _sniffMagic,
};

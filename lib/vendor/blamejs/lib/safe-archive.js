// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   `b.archive.wrap` recipient (`BAWRP`) / passphrase (`BAWPP`)
 *   envelopes (auto-unwrapped before format detection). Unrecognized
 *   inputs are flagged `safe-archive/format-unsupported`.
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

async function _sniffMagic(adapter) {
  // For random-access adapters, the format sniffer reads the first
  // 512 bytes — enough for ZIP + GZIP + wrap-envelope magic
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
  // archive-wrap envelopes — 5-byte ASCII prefix. BAWRP (recipient) and
  // BAWPP (passphrase) are the only wrap envelopes the framework produces
  // (b.archive.wrap / b.archive.wrapWithPassphrase) and the only ones
  // b.archive.sniffEnvelope recognizes.
  if (head.length >= 5) {
    var prefix = head.slice(0, 5).toString("utf8");
    if (prefix === "BAWRP") return { format: "wrap-recipient" };
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

// Shared source→adapter resolution + envelope auto-unwrap for the three
// orchestrator entry points (extract / extractToMemory / inspect). Returns
// { source, format } — `source` is a random-access adapter positioned at the
// (possibly unwrapped) archive and `format` is the sniffed inner format. The
// CALLER owns closing the returned source in its own `finally`; this helper
// performs the pre-unwrap fd-close-before-replace + the signal-forward-to-
// inner-adapter discipline internally, and closes a string-opened descriptor
// if it throws mid-resolve so a sniff/unwrap failure can't leak it.
async function _resolveAndUnwrap(opts, label, refuseTrustedStream) {
  var openedFromString = typeof opts.source === "string";
  var source = opts.source;
  if (openedFromString) {
    source = archiveAdapters().fs(source, { signal: opts.signal });
  } else if (Buffer.isBuffer(source)) {
    source = archiveAdapters().buffer(source, { signal: opts.signal });
  } else if (refuseTrustedStream && archiveAdapters().isTrustedStreamAdapter(source)) {
    // Trusted-stream adapters satisfy the adapter contract, but the
    // orchestrator's adversarial-safe central-directory walk + LFH/CD skew
    // defense needs random access. Refuse upfront with a typed error so the
    // operator sees the constraint at the entry point rather than a
    // downstream `archive-read/wrong-entry-point`.
    throw new SafeArchiveError("safe-archive/trusted-stream-unsupported",
      label + ": trusted-stream adapter sources are not supported by the orchestrator " +
      "(the adversarial-safe central-directory walk requires random access). Collect the " +
      "bytes into a buffer adapter — `b.archive.adapters.buffer(await collect(readable))` — " +
      "and pass that, or read with `b.archive.read.zip.fromTrustedStream` directly.");
  } else if (!archiveAdapters().isRandomAccessAdapter(source)) {
    throw new SafeArchiveError("safe-archive/bad-source",
      label + ": opts.source must be a string path, Buffer, or b.archive.adapters.* result");
  }
  try {
    var format = opts.format || "auto";
    if (format === "auto") {
      format = (await _sniffMagic(source)).format;
    }
    // Auto-unwrap path: when the sniffer identifies a wrap envelope, unwrap
    // inline + re-sniff the inner bytes so operators get a single call
    // regardless of envelope shape. Operator supplies opts.recipient or
    // opts.passphrase matching the envelope kind.
    if (format === "wrap-recipient" || format === "wrap-passphrase") {
      var sealedBytes = await _collectSourceBytes(source);
      var inner;
      if (format === "wrap-recipient") {
        if (!opts.recipient) {
          throw new SafeArchiveError("safe-archive/no-recipient-for-wrap",
            label + ": source is a wrap-recipient envelope (BAWRP) but opts.recipient was not supplied. " +
            "Pass `{ recipient: { privateKey, ecPrivateKey } }` (or peer-cert form) to unwrap inline.");
        }
        inner = archiveWrap().unwrap(sealedBytes, { recipient: opts.recipient });
      } else {
        if (typeof opts.passphrase !== "string" && !Buffer.isBuffer(opts.passphrase)) {
          throw new SafeArchiveError("safe-archive/no-passphrase-for-wrap",
            label + ": source is a wrap-passphrase envelope (BAWPP) but opts.passphrase was not supplied. " +
            "Pass `{ passphrase: <string|Buffer> }` to unwrap inline.");
        }
        inner = await archiveWrap().unwrapWithPassphrase(sealedBytes, { passphrase: opts.passphrase });
      }
      // Close the original string-opened descriptor BEFORE replacing the
      // source reference (overwriting it would leak the fd across repeated
      // calls → EMFILE under load), then forward opts.signal to the inner
      // buffer adapter so abort propagation survives the unwrap boundary.
      if (typeof source.close === "function" && openedFromString) {
        try { source.close(); } catch (_e) { /* drop-silent */ }
      }
      source = archiveAdapters().buffer(inner, { signal: opts.signal });
      format = (await _sniffMagic(source)).format;
    }
    return { source: source, format: format };
  } catch (e) {
    if (typeof source.close === "function" && openedFromString) {
      try { source.close(); } catch (_e2) { /* drop-silent */ }
    }
    throw e;
  }
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
  var resolved = await _resolveAndUnwrap(opts, "extract", true);
  var source = resolved.source;
  var format = resolved.format;
  try {
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
        "zip, tar, tar.gz; b.archive.wrap recipient/passphrase envelopes are auto-unwrapped first");
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
 * @primitive b.safeArchive.extractToMemory
 * @signature b.safeArchive.extractToMemory(opts)
 * @since     0.14.13
 * @status    stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related   b.safeArchive.extract, b.archive.read.zip, b.archive.read.tar
 *
 * In-memory counterpart to `b.safeArchive.extract` for read-only /
 * serverless filesystems. Resolves the source, sniffs the format,
 * auto-unwraps recipient (`BAWRP`) / passphrase (`BAWPP`) envelopes, and
 * dispatches to the zip / tar / tar.gz reader's in-memory `extractEntries`
 * — an async generator that yields each regular file entry's decompressed
 * bytes without ever writing to disk. Takes no `destination`; the caller
 * owns where, if anywhere, the bytes land.
 *
 * Every defense the disk `extract` runs applies unchanged: the zip-bomb
 * caps (entry-count / per-entry / total / expansion-ratio), the
 * `b.guardArchive` metadata cascade (Zip-Slip / path-traversal / symlink-
 * escape / encrypted-entry refusal — CVE-2025-3445 class), and the
 * entry-type policy. Directory entries carry no bytes and are skipped. The
 * disk-only realpath-agreement check (CVE-2025-4517 PATH_MAX TOCTOU
 * defense) is intentionally absent — there is no extraction root — so the
 * archive-level name refusals carry the containment guarantee here.
 *
 * Trusted-stream adapter sources are refused upfront: the adversarial-safe
 * central-directory walk requires random access. Collect the bytes into a
 * buffer adapter, or read with `b.archive.read.zip.fromTrustedStream`
 * directly.
 *
 * @opts
 *   source:           b.archive.adapters.* | Buffer | string,
 *   format:           "auto" | "zip" | "tar" | "tar.gz",
 *   bombPolicy:       b.guardArchive.zipBombPolicy(...) | { ... },
 *   entryTypePolicy:  b.guardArchive.entryTypePolicy(...) | { ... },
 *   guardProfile:     "strict" | "balanced" | "permissive" | "hipaa" | ...,
 *   recipient:        { privateKey, ecPrivateKey },  // for BAWRP envelopes
 *   passphrase:       string | Buffer,               // for BAWPP envelopes
 *   audit:            b.audit,
 *   signal:           AbortSignal,
 *
 * @example
 *   for await (var entry of b.safeArchive.extractToMemory({
 *     source:       b.archive.adapters.fs("/var/uploads/payload.zip"),
 *     guardProfile: "strict",
 *   })) {
 *     // entry → { name, bytes, size } — never touches disk
 *     await store.put(entry.name, entry.bytes);
 *   }
 */
async function* extractToMemory(opts) {
  opts = opts || {};
  var resolved = await _resolveAndUnwrap(opts, "extractToMemory", true);
  var source = resolved.source;
  var format = resolved.format;
  var extractOpts = { allowDangerous: opts.allowDangerous, allowEncrypted: opts.allowEncrypted };
  try {
    if (format === "zip") {
      var zr = archiveRead().zip(source, {
        bombPolicy:      opts.bombPolicy,
        entryTypePolicy: opts.entryTypePolicy,
        guardProfile:    opts.guardProfile,
        audit:           opts.audit,
      });
      for await (var ze of zr.extractEntries(extractOpts)) { yield ze; }
    } else if (format === "tar") {
      var tr = archiveTarRead().tar(source, {
        bombPolicy:      opts.bombPolicy,
        entryTypePolicy: opts.entryTypePolicy,
        guardProfile:    opts.guardProfile,
        audit:           opts.audit,
      });
      for await (var te of tr.extractEntries(extractOpts)) { yield te; }
    } else if (format === "tar.gz") {
      // The gz reader's asTar() shim exposes inspect + extract but NOT
      // extractEntries, so materialize the gz layer to a Buffer (the gz
      // bomb caps still run during toBuffer()) and walk a fresh tar reader
      // over it — the tar bomb / guard / entry-type caps run on the inner
      // walk, so no defense is dropped.
      var tarBytes = await archiveGz().read.gz(source, {
        maxDecompressedBytes: opts.maxDecompressedBytes,
        maxExpansionRatio:    opts.maxExpansionRatio,
        audit:                opts.audit,
      }).toBuffer();
      var gtr = archiveTarRead().tar(archiveAdapters().buffer(tarBytes, { signal: opts.signal }), {
        bombPolicy:      opts.bombPolicy,
        entryTypePolicy: opts.entryTypePolicy,
        guardProfile:    opts.guardProfile,
        audit:           opts.audit,
      });
      for await (var ge of gtr.extractEntries(extractOpts)) { yield ge; }
    } else {
      throw new SafeArchiveError("safe-archive/format-unsupported",
        "extractToMemory: format=" + JSON.stringify(format) + " — supported formats are " +
        "zip, tar, tar.gz; b.archive.wrap recipient/passphrase envelopes are auto-unwrapped first");
    }
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
  var resolved = await _resolveAndUnwrap(opts, "inspect", false);
  var source = resolved.source;
  var format = resolved.format;
  try {
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
        "inspect: format=" + JSON.stringify(format) + " — supported formats are zip, tar, tar.gz; wrap envelopes are auto-unwrapped first");
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
  extractToMemory:   extractToMemory,
  inspect:           inspect,
  SafeArchiveError:  SafeArchiveError,
  // Exposed for tests + sibling modules.
  _sniffMagic:       _sniffMagic,
};

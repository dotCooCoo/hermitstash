"use strict";
/**
 * archive-gz — gzip composition primitives. Sibling of lib/archive.js
 * (ZIP write), lib/archive-read.js (ZIP read), lib/archive-tar.js (tar
 * write), and lib/archive-tar-read.js (tar read). The @module block
 * lives on lib/archive.js; this file declares only @primitive entries
 * under the b.archive namespace (`b.archive.gz` write, `b.archive.read.gz`
 * read). Bomb defenses ride with the read path: every read.gz call
 * composes b.safeDecompress with the framework's default caps (1 GiB
 * output / 100× ratio).
 */

var zlib = require("node:zlib");
var nodeCrypto = require("node:crypto");
var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var { defineClass } = require("./framework-error");

var ArchiveGzError = defineClass("ArchiveGzError", { alwaysPermanent: true });

var safeDecompress = lazyRequire(function () { return require("./safe-decompress"); });
var archiveAdapters = lazyRequire(function () { return require("./archive-adapters"); });
var archiveRead = lazyRequire(function () { return require("./archive-read"); });
var archiveTarRead = lazyRequire(function () { return require("./archive-tar-read"); });

// gzip magic — RFC 1952 §2.2 ("ID1=0x1f, ID2=0x8b").
var GZIP_MAGIC_0 = 0x1f;                                                              // RFC 1952 §2.2 ID1
var GZIP_MAGIC_1 = 0x8b;                                                              // RFC 1952 §2.2 ID2

var DEFAULT_MAX_OUTPUT_BYTES = C.BYTES.gib(1);
var DEFAULT_MAX_RATIO = 100;

function _isGzipMagic(buf) {
  return buf.length >= 2 && buf[0] === GZIP_MAGIC_0 && buf[1] === GZIP_MAGIC_1;
}

/**
 * @primitive b.archive.gz
 * @signature b.archive.gz(bytes, opts?)
 * @since     0.12.9
 * @status    stable
 * @related   b.archive.read.gz, b.safeDecompress
 *
 * Wrap a buffer in a gzip envelope. Returns a builder with the same
 * write surface as the other `b.archive` builders — `toBuffer()` /
 * `toAdapter(adapter)` / `digest()` — so gzip slots into the same
 * downstream sinks (object-store + filesystem + http adapters).
 *
 * `b.archive.tar().toGzip(adapter)` composes this primitive after
 * materializing the tar bytes (the canonical `.tar.gz`). There is no
 * `zip().toGzip()` — a ZIP is already DEFLATE-compressed per entry, so
 * gzip-wrapping it would compress already-compressed data for no gain;
 * gzip the uncompressed tar stream instead.
 *
 * @opts
 *   level:  number,    // 0-9, default 6 (zlib default).
 *
 * @example
 *   var compressed = b.archive.gz(Buffer.from("hello world")).toBuffer();
 *   // → 31-byte gzip stream
 */
function gz(bytes, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new ArchiveGzError("archive-gz/bad-input",
      "gz: input must be a Buffer or Uint8Array");
  }
  var input = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  var level = opts.level;
  if (level !== undefined &&
      (typeof level !== "number" || level < 0 || level > 9)) {
    throw new ArchiveGzError("archive-gz/bad-arg",
      "gz: opts.level must be a number 0-9; got " + JSON.stringify(level));
  }
  var compressed = null;
  function _materialize() {
    if (compressed !== null) return compressed;
    var zopts = {};
    if (typeof level === "number") zopts.level = level;
    compressed = zlib.gzipSync(input, zopts);
    return compressed;
  }
  return {
    toBuffer: function () { return _materialize(); },
    toAdapter: async function (adapter) {
      if (!adapter || typeof adapter.write !== "function") {
        throw new ArchiveGzError("archive-gz/bad-adapter",
          "gz.toAdapter: adapter must be writable (no .write method)");
      }
      var buf = _materialize();
      await adapter.write(buf);
      if (typeof adapter.close === "function") await adapter.close();
    },
    digest: function () {
      return nodeCrypto.createHash("sha3-512")
        .update(_materialize())
        .digest("hex");
    },
    get compressedBytes() { return _materialize().length; },
  };
}

/**
 * @primitive b.archive.read.gz
 * @signature b.archive.read.gz(adapter, opts)
 * @since     0.12.9
 * @status    stable
 * @related   b.archive.gz, b.safeDecompress, b.archive.read.tar, b.archive.read.zip
 *
 * Read a gzip stream from an adapter, surface it as either raw bytes
 * (`toBuffer()`) or as a hand-off to a downstream archive reader
 * (`asTar()` / `asZip()`). Every decompression composes
 * `b.safeDecompress` with framework-default caps — `maxOutputBytes`
 * (1 GiB) and `maxExpansionRatio` (100×) — so a hostile `tar.gz`
 * fails the gz gate before any tar parsing happens.
 *
 * @opts
 *   maxDecompressedBytes:  number,   // default 1 GiB
 *   maxExpansionRatio:     number,   // default 100×
 *   audit:                 object,
 *
 * @example
 *   var reader = b.archive.read.gz(b.archive.adapters.fs("./bundle.tar.gz"));
 *   var tarReader = reader.asTar();
 *   var result = await tarReader.extract({ destination: "./out" });
 */
function readGz(adapter, opts) {
  opts = opts || {};
  if (!adapter || typeof adapter !== "object") {
    throw new ArchiveGzError("archive-gz/bad-adapter",
      "read.gz: adapter is required");
  }
  var maxOutputBytes = opts.maxDecompressedBytes !== undefined
    ? opts.maxDecompressedBytes
    : DEFAULT_MAX_OUTPUT_BYTES;
  var maxRatio = opts.maxExpansionRatio !== undefined
    ? opts.maxExpansionRatio
    : DEFAULT_MAX_RATIO;
  var decompressed = null;

  async function _collect() {
    if (adapter.kind === "random-access") {
      var size = adapter.size;
      if (size == null && typeof adapter.resolveSize === "function") {
        size = await adapter.resolveSize();
      }
      if (typeof size !== "number" || size === 0) {
        throw new ArchiveGzError("archive-gz/empty-input",
          "read.gz: adapter reports empty payload");
      }
      // Cap the raw COMPRESSED read before allocating — `adapter.range(0, size)`
      // does Buffer.allocUnsafe(size) of an fstat/HEAD-reported length, which a
      // hostile .gz (or an objectStore/HTTP source advertising a huge size) can
      // drive to OOM. maxOutputBytes bounds the DECOMPRESSED output only; this
      // bounds the compressed read too, matching archive-tar-read's _collectAdapterBytes.
      if (typeof maxOutputBytes === "number" && size > maxOutputBytes) {
        throw new ArchiveGzError("archive-gz/source-too-large",
          "read.gz: random-access source size=" + size + " exceeds the read cap " + maxOutputBytes);
      }
      return adapter.range(0, size);
    }
    if (adapter.kind === "trusted-sequential") {
      var collector = safeBuffer.boundedChunkCollector({
        maxBytes:   maxOutputBytes,
        errorClass: ArchiveGzError,
        sizeCode:   "archive-gz/trusted-stream-too-large",
      });
      for await (var chunk of adapter.readable) collector.push(chunk);
      return collector.result();
    }
    throw new ArchiveGzError("archive-gz/bad-adapter",
      "read.gz: adapter kind " + JSON.stringify(adapter.kind) + " not supported");
  }

  async function _materialize() {
    if (decompressed !== null) return decompressed;
    var compressed = await _collect();
    if (!_isGzipMagic(compressed)) {
      throw new ArchiveGzError("archive-gz/bad-magic",
        "read.gz: input does not start with gzip magic 0x1f 0x8b");
    }
    decompressed = safeDecompress().safeDecompress(compressed, {
      algorithm:          "gzip",
      maxOutputBytes:     maxOutputBytes,
      maxCompressedBytes: compressed.length,
      maxRatio:           maxRatio,
      audit:              opts.audit,
    });
    return decompressed;
  }

  return {
    toBuffer: async function () { return _materialize(); },
    asTar: function (tarOpts) {
      tarOpts = tarOpts || {};
      return {
        inspect: async function () {
          var bytes = await _materialize();
          var reader = archiveTarRead().tar(
            archiveAdapters().buffer(bytes), tarOpts);
          return reader.inspect();
        },
        extract: async function (extractOpts) {
          var bytes = await _materialize();
          var reader = archiveTarRead().tar(
            archiveAdapters().buffer(bytes), tarOpts);
          return reader.extract(extractOpts);
        },
      };
    },
    asZip: function (zipOpts) {
      zipOpts = zipOpts || {};
      return {
        inspect: async function () {
          var bytes = await _materialize();
          var reader = archiveRead().zip(
            archiveAdapters().buffer(bytes), zipOpts);
          return reader.inspect();
        },
        extract: async function (extractOpts) {
          var bytes = await _materialize();
          var reader = archiveRead().zip(
            archiveAdapters().buffer(bytes), zipOpts);
          return reader.extract(extractOpts);
        },
      };
    },
  };
}

module.exports = {
  gz:                gz,
  read:              { gz: readGz },
  ArchiveGzError:    ArchiveGzError,
  // Exposed for sibling modules
  _isGzipMagic:      _isGzipMagic,
  GZIP_MAGIC_0:      GZIP_MAGIC_0,
  GZIP_MAGIC_1:      GZIP_MAGIC_1,
};

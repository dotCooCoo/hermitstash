"use strict";
/**
 * Fuzz target: b.safeDecompress
 *
 * Feeds adversarial bytes into the four-algorithm allowlist. The
 * fuzzer probes the bomb-class surface (oversize input, ratio-bomb,
 * malformed deflate headers, truncated streams, bogus brotli
 * dictionary references) and asserts the primitive surfaces typed
 * `safe-decompress/*` codes for every refusal — no OOM, no hang, no
 * uncaught error class outside the documented surface.
 *
 * Seed corpus: `fuzz/safe-decompress_seed_corpus/` carries (a) a
 * legitimate gzip-of-text payload, (b) a 100KB-zero gzip bomb, (c) a
 * raw deflate stream, (d) a brotli sample. Coverage-guided fuzzing
 * mutates around those seeds.
 */

var b        = require("..");
var expected = require("./_expected");

var ALGS = ["gzip", "deflate", "deflate-raw", "brotli"];

module.exports.fuzz = function (data) {
  if (!Buffer.isBuffer(data) || data.length === 0) return;
  // Pick the algorithm by the first byte mod 4 — gives the fuzzer
  // coverage of every decoder. Strip that byte from the rest so the
  // selector doesn't pollute the body.
  var algoIdx = data[0] & 0x03;                                                        // allow:raw-byte-literal — 4-way alternation per first-byte
  var body    = data.slice(1);
  if (body.length === 0) return;

  // Vary the absolute cap and ratio cap based on later bytes — gives
  // the fuzzer reach into both refusal paths.
  var capByte   = body.length > 0 ? body[0] : 0;
  var ratioByte = body.length > 1 ? body[1] : 0;
  var maxOutputBytes = (capByte + 1) * 1024;                                           // allow:raw-byte-literal — 1..256 KiB output cap (capByte: 0..255)
  var maxRatio       = ratioByte === 0 ? 0 : (ratioByte & 0x7F) + 1;                   // allow:raw-byte-literal — 0=unlimited, else 1..128 ratio

  try {
    b.safeDecompress(body, {
      algorithm:      ALGS[algoIdx],
      maxOutputBytes: maxOutputBytes,
      maxRatio:       maxRatio,
    });
  } catch (e) {
    if (expected.isExpected(e)) return;
    throw e;
  }
};

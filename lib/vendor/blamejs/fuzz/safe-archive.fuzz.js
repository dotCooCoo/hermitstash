// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.safeArchive
 *
 * Feeds adversarial bytes into `b.safeArchive.inspect` (the read-only
 * path that walks EOCD + CD + LFH skew checks). The fuzzer probes
 * the malformed-ZIP class — EOCD pointers past EOF, CD-claimed sizes
 * that don't match LFH, ZIP64 sentinels (refused in v0.12.7),
 * truncated headers, comments containing fake EOCD signatures,
 * negative byte offsets — and asserts the primitive surfaces typed
 * `archive-read/* | safe-archive/* | filename.extraction-*` codes
 * for every refusal: no OOM, no hang, no uncaught error class outside
 * the documented surface.
 *
 * Seed corpus: a single valid ZIP produced by `b.archive.zip()` so
 * the fuzzer mutates around a known-good baseline rather than starting
 * from random noise.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  if (!Buffer.isBuffer(data) || data.length === 0) return;
  // The fuzzer can't usefully drive an async function under jazzer.js
  // without an await; we lean on the format sniffer + EOCD locator which
  // are the parsing-heavy phases. Both run inside b.safeArchive.inspect.
  return b.safeArchive.inspect({
    source: data,
  }).then(
    function () { /* legitimate ZIP-shaped input → no finding */ },
    function (err) {
      if (expected.isExpected(err)) return;
      throw err;     // re-throw unexpected error class so libFuzzer records it
    }
  );
};

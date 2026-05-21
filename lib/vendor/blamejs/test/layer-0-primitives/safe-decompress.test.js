"use strict";
/**
 * b.safeDecompress — bomb-resistant decompression.
 *
 * Covers: algorithm allowlist, maxOutputBytes refusal, maxRatio
 * refusal (the post-decompress check that defeats compressed
 * input < absolute-cap but ratio > maxRatio), audit emission on
 * refusal, bad-arg refusal paths.
 *
 * Run standalone: `node test/layer-0-primitives/safe-decompress.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var zlib = require("node:zlib");
var C    = b.constants;

// ---- Surface ----

function testSurface() {
  check("b.safeDecompress is a function",
        typeof b.safeDecompress === "function");
}

// ---- Algorithm allowlist ----

function testAlgorithmRequired() {
  var threw = null;
  try { b.safeDecompress(Buffer.from("x"), { maxOutputBytes: 1024 }); }
  catch (e) { threw = e; }
  check("missing algorithm → refused",
        threw && /safe-decompress\/unsupported-algorithm/.test(threw.code || ""));
}

function testAlgorithmAllowlistRefusesUnknown() {
  var threw = null;
  try { b.safeDecompress(Buffer.from("x"), { algorithm: "zstd", maxOutputBytes: 1024 }); }
  catch (e) { threw = e; }
  check("unknown algorithm → refused (zstd not in allowlist)",
        threw && /unsupported-algorithm/.test(threw.code || ""));
}

// ---- Happy path ----

function testGzipRoundTrip() {
  var plain = "hello world ".repeat(50);
  var gz = zlib.gzipSync(Buffer.from(plain, "utf8"));
  var out = b.safeDecompress(gz, {
    algorithm: "gzip", maxOutputBytes: C.BYTES.kib(64),
  });
  check("gzip round-trip preserves bytes", out.toString("utf8") === plain);
}

function testDeflateRawRoundTrip() {
  var plain = "hello world ".repeat(50);
  var def = zlib.deflateRawSync(Buffer.from(plain, "utf8"));
  var out = b.safeDecompress(def, {
    algorithm: "deflate-raw", maxOutputBytes: C.BYTES.kib(64),
  });
  check("deflate-raw round-trip preserves bytes", out.toString("utf8") === plain);
}

function testBrotliRoundTrip() {
  var plain = "hello world ".repeat(50);
  var br = zlib.brotliCompressSync(Buffer.from(plain, "utf8"));
  var out = b.safeDecompress(br, {
    algorithm: "brotli", maxOutputBytes: C.BYTES.kib(64),
  });
  check("brotli round-trip preserves bytes", out.toString("utf8") === plain);
}

// ---- maxOutputBytes refusal (pre-allocation, via zlib's maxOutputLength) ----

function testMaxOutputBytesRefusal() {
  // 100 KB of zeros → ~100 bytes compressed → expands far past a 1 KB cap
  var plain = Buffer.alloc(C.BYTES.kib(100), 0);
  var gz = zlib.gzipSync(plain);
  var threw = null;
  try {
    b.safeDecompress(gz, { algorithm: "gzip", maxOutputBytes: C.BYTES.kib(1) });
  } catch (e) { threw = e; }
  check("output > maxOutputBytes → refused before allocation",
        threw && /decompress-failed|output-too-large/.test(threw.code || ""));
}

// ---- maxRatio refusal (post-decompress, the new defense vs status quo) ----

function testMaxRatioRefusal() {
  // 50 KB of zeros compresses to a few hundred bytes → ratio ~200:1.
  // With maxRatio: 50 the framework refuses even though the output
  // size is well under any reasonable absolute cap.
  var plain = Buffer.alloc(C.BYTES.kib(50), 0);
  var gz = zlib.gzipSync(plain);
  var threw = null;
  try {
    b.safeDecompress(gz, {
      algorithm:      "gzip",
      maxOutputBytes: C.BYTES.mib(1),                          // absolute cap is generous
      maxRatio:       50,                                       // ratio cap refuses
    });
  } catch (e) { threw = e; }
  check("ratio > maxRatio → refused even when output fits maxOutputBytes",
        threw && /safe-decompress\/ratio-exceeded/.test(threw.code || ""));
}

function testMaxRatioZeroUnlimited() {
  // maxRatio: 0 (unlimited) — same payload that tripped above passes.
  var plain = Buffer.alloc(C.BYTES.kib(50), 0);
  var gz = zlib.gzipSync(plain);
  var out = b.safeDecompress(gz, {
    algorithm: "gzip", maxOutputBytes: C.BYTES.mib(1), maxRatio: 0,
  });
  check("maxRatio: 0 → unlimited expansion accepted",
        out.length === plain.length);
}

// ---- Input cap ----

function testMaxCompressedBytesRefusal() {
  var plain = Buffer.alloc(C.BYTES.kib(50), "x");                                    // text compresses less
  var gz = zlib.gzipSync(plain);
  var threw = null;
  try {
    b.safeDecompress(gz, {
      algorithm:          "gzip",
      maxOutputBytes:     C.BYTES.mib(1),
      maxCompressedBytes: 10,                                                         // far below the actual compressed size
    });
  } catch (e) { threw = e; }
  check("compressed input > maxCompressedBytes → refused",
        threw && /oversized-input/.test(threw.code || ""));
}

// ---- Bad-arg refusal paths ----

function testEmptyInput() {
  var threw = null;
  try {
    b.safeDecompress(Buffer.alloc(0), { algorithm: "gzip", maxOutputBytes: 1024 });
  } catch (e) { threw = e; }
  check("empty input → refused", threw && /empty-input/.test(threw.code || ""));
}

function testBadInputShape() {
  var threw = null;
  try {
    b.safeDecompress("not a buffer", { algorithm: "gzip", maxOutputBytes: 1024 });
  } catch (e) { threw = e; }
  check("non-Buffer input → refused", threw && /bad-input/.test(threw.code || ""));
}

function testBadMaxOutputBytes() {
  var threw = null;
  try {
    b.safeDecompress(Buffer.from("x"), { algorithm: "gzip", maxOutputBytes: -1 });
  } catch (e) { threw = e; }
  check("negative maxOutputBytes → refused", threw && /bad-arg/.test(threw.code || ""));
}

function testMissingMaxOutputBytes() {
  var threw = null;
  try { b.safeDecompress(Buffer.from("x"), { algorithm: "gzip" }); }
  catch (e) { threw = e; }
  check("missing maxOutputBytes → refused", threw && /bad-arg/.test(threw.code || ""));
}

// ---- maxCompressedBytes alignment for caller-configurable caps ----

function testMaxCompressedBytesAlignsWithMaxOutputBytes() {
  // Codex P1 regression check (PR #110): if a caller's
  // `maxOutputBytes` exceeds the safeDecompress default
  // `maxCompressedBytes` of 4 MiB AND the caller forgets to pass
  // `maxCompressedBytes`, the silent 4 MiB cap refuses legitimate
  // large inputs. Verify the explicit-pass shape used by WS works.
  //
  // 5 MiB of zeros → ~5 KB compressed (~1000:1 ratio). Fits under
  // a 6 MiB maxOutputBytes; compressed bytes well under any cap.
  var plain = Buffer.alloc(C.BYTES.mib(5), 0);
  var gz = zlib.gzipSync(plain);
  var out = b.safeDecompress(gz, {
    algorithm:          "gzip",
    maxOutputBytes:     C.BYTES.mib(6),
    maxCompressedBytes: C.BYTES.mib(6),                              // explicit alignment
    maxRatio:           0,                                            // unlimited (legitimate high compression)
  });
  check("5 MiB compressed roundtrip with aligned caller bound", out.length === plain.length);
}

// ---- Audit emission on refusal ----

function testAuditEmittedOnRatioRefusal() {
  var captured = [];
  var auditFake = {
    safeEmit: function (e) { captured.push(e); },
  };
  var plain = Buffer.alloc(C.BYTES.kib(50), 0);
  var gz = zlib.gzipSync(plain);
  try {
    b.safeDecompress(gz, {
      algorithm:      "gzip",
      maxOutputBytes: C.BYTES.mib(1),
      maxRatio:       50,
      audit:          auditFake,
      ctx:            "test-ctx",
    });
  } catch (_e) { /* expected */ }

  check("audit event captured on ratio refusal", captured.length === 1);
  if (captured.length === 1) {
    var ev = captured[0];
    check("audit event action is system.safe_decompress.refused",
          ev.action === "system.safe_decompress.refused");
    check("audit event outcome is denied", ev.outcome === "denied");
    check("audit metadata names the ratio code",
          ev.metadata && ev.metadata.code === "safe-decompress/ratio-exceeded");
    check("audit metadata carries operator ctx",
          ev.metadata && ev.metadata.ctx === "test-ctx");
  }
}

async function run() {
  testSurface();
  testAlgorithmRequired();
  testAlgorithmAllowlistRefusesUnknown();
  testGzipRoundTrip();
  testDeflateRawRoundTrip();
  testBrotliRoundTrip();
  testMaxOutputBytesRefusal();
  testMaxRatioRefusal();
  testMaxRatioZeroUnlimited();
  testMaxCompressedBytesRefusal();
  testEmptyInput();
  testBadInputShape();
  testBadMaxOutputBytes();
  testMissingMaxOutputBytes();
  testMaxCompressedBytesAlignsWithMaxOutputBytes();
  testAuditEmittedOnRatioRefusal();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

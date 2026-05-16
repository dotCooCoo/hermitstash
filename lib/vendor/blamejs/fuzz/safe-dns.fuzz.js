"use strict";
/**
 * Fuzz target: b.safeDns.parseResponse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite + OSS-Fuzz consume
 * `module.exports.fuzz = function (data)` where `data` is a Buffer
 * the engine mutates. Seeds for the initial corpus live in
 * `fuzz/safe-dns_seed_corpus/`.
 *
 * Targets the DNS-parser-bypass + amplification class:
 *   - CVE-2022-3204 (NRDelegationAttack — oversized authority + additional)
 *   - CVE-2023-50387 (KeyTrap — DNSKEY+RRSIG combinatorial input to validator)
 *   - CVE-2023-50868 (NSEC3-encloser companion)
 *   - CVE-2024-1737 (BIND9 resource exhaustion via large RRsets)
 *   - RFC 1035 §4.1.4 compression-pointer loop class (generic).
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  try {
    b.safeDns.parseResponse(data);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("safe-dns/") === 0) return;
    throw e;
  }
};

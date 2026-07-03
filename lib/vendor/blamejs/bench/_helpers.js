// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// bench/_helpers.js — small benchmark harness using node:perf_hooks.
// No npm deps. Deliberately simple: one-shot benches + percentile latency
// summary. Operator-facing artifacts read by `bench/run.js` aggregate
// the per-bench results into bench/baseline.json.

var perf = require("node:perf_hooks");

var DEFAULT_WARMUP_ITERS = 5000;
var DEFAULT_RUN_MS       = 1000;
var ABSOLUTE_MAX_ITERS   = 10000000;

function _now() { return perf.performance.now(); }

function _percentile(sortedNs, p) {
  if (sortedNs.length === 0) return 0;
  var idx = Math.min(sortedNs.length - 1, Math.floor(sortedNs.length * p));
  return sortedNs[idx];
}

// Run `fn` repeatedly for ~runMs milliseconds (after a warmup of
// warmupIters calls). Records a per-iteration latency sample for the
// run phase and returns aggregate stats.
function bench(fn, opts) {
  opts = opts || {};
  var warmupIters = opts.warmupIters || DEFAULT_WARMUP_ITERS;
  var runMs       = opts.runMs       || DEFAULT_RUN_MS;

  // Warmup — JIT, allocate, settle.
  for (var i = 0; i < warmupIters; i++) fn();

  // Run phase — sample p50/p95/p99 latency in nanoseconds.
  var samples = [];
  var start = _now();
  var deadline = start + runMs;
  var iters = 0;
  while (iters < ABSOLUTE_MAX_ITERS) {
    var t0 = perf.performance.now();
    fn();
    var t1 = perf.performance.now();
    samples.push((t1 - t0) * 1e6); // ms → ns
    iters++;
    if (t1 >= deadline) break;
  }
  var elapsedMs = _now() - start;

  samples.sort(function (a, b) { return a - b; });
  var opsPerSec = Math.round(iters / (elapsedMs / 1000));
  return {
    iterations:  iters,
    elapsedMs:   Math.round(elapsedMs),
    opsPerSec:   opsPerSec,
    p50ns:       Math.round(_percentile(samples, 0.50)),
    p95ns:       Math.round(_percentile(samples, 0.95)),
    p99ns:       Math.round(_percentile(samples, 0.99)),
  };
}

function format(label, result) {
  return label.padEnd(48) +
    String(result.opsPerSec.toLocaleString()).padStart(14) + " ops/s" +
    "  p50=" + String(result.p50ns).padStart(7) + "ns" +
    "  p95=" + String(result.p95ns).padStart(7) + "ns" +
    "  p99=" + String(result.p99ns).padStart(7) + "ns";
}

module.exports = {
  bench:  bench,
  format: format,
};

# Benchmark suite

Microbenchmarks for the framework's hot paths. Operator-facing — run before every release to catch unintended regressions in primitives that sit in the request critical path.

## Run all benchmarks

```bash
node bench/run.js
```

Default settings: 5,000-iteration warmup per benchmark, 1,000 ms run window per benchmark, written to `bench/baseline.json`.

## Filter

```bash
node bench/run.js --filter crypto-symmetric
node bench/run.js --filter "encryptPacked 1 KB"
```

## Compare against the committed baseline

```bash
node bench/run.js --compare
```

Runs the suite, reports per-benchmark `p50` + `ops/s` deltas vs the saved `bench/baseline.json`, exits non-zero if any benchmark regresses by more than 30 % p50 latency. Wire this into CI as a soft gate (machine-to-machine variance can trip it; treat repeated regressions as signal, single-run noise as noise).

## Update the baseline

Re-run the suite and commit the new file:

```bash
node bench/run.js
git add bench/baseline.json
git commit -m "..."
```

## Override defaults

```bash
node bench/run.js --warmup 10000 --runMs 2000     # longer warmup + run window
node bench/run.js --out /tmp/custom.json          # write somewhere else
```

## What's covered

The suite intentionally stays small — one bench file per primitive cluster, sync only.

| File                              | Covers                                                                |
|-----------------------------------|-----------------------------------------------------------------------|
| `safe-json.bench.js`              | `b.safeJson.stringify` + `parse` for small + medium payloads          |
| `crypto-hash.bench.js`            | `b.crypto.sha3Hash` (11 B / 1 KB / 64 KB) and `generateBytes`         |
| `crypto-symmetric.bench.js`       | `b.crypto.encryptPacked` + `decryptPacked` round-trip (XChaCha20-Poly1305) |

Async primitives (router dispatch, vault seal/unseal, audit emit) aren't included yet — the harness is sync-only by design. They'll land when there's a clean async harness to pair with them.

## Adding a new bench

A bench file exports `{ name, benchmarks: { label: fn, ... } }`. The runner discovers any `bench/*.bench.js` file and walks its `benchmarks` keys.

```js
"use strict";
var something = require("../lib/something");
module.exports = {
  name: "something",
  benchmarks: {
    "fast path":  function () { something.do(/* hot args */); },
    "slow path":  function () { something.doSlow(/* args */); },
  },
};
```

Each benchmark function is called repeatedly; do all the setup at module-load time (top of file), keep the benchmark body tight.

## Reading the numbers

`baseline.json` records the machine info (platform, arch, Node version, CPU model, RAM) alongside the results. Compare results from the *same* machine — cross-machine comparisons don't mean much. Operators reading the file should treat the numbers as an order-of-magnitude reference, not an SLA. The `--compare` gate is the durable contract: each release shouldn't make the framework's core primitives noticeably slower without an accompanying explanation.

"use strict";
// bench/run.js — discovers bench/*.bench.js files, runs every entry,
// emits a flat JSON record to bench/baseline.json (or --out <path>).
//
// Usage:
//   node bench/run.js                       run all, print to stderr, write JSON
//   node bench/run.js --filter <substring>  run only matching benches
//   node bench/run.js --out <path>          write to a different JSON file
//   node bench/run.js --compare             compare against bench/baseline.json
//                                           and exit non-zero on regression
//   node bench/run.js --warmup <n>          override warmup iters per bench
//   node bench/run.js --runMs <n>           override per-bench run duration

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var harness = require("./_helpers");

var ROOT     = path.resolve(__dirname, "..");
var BENCH_DIR = __dirname;
var DEFAULT_OUT = path.join(BENCH_DIR, "baseline.json");
var REGRESS_THRESHOLD = 0.30; // 30% slowdown trips the gate

function _parseArgs(argv) {
  var out = { filter: null, outPath: DEFAULT_OUT, compare: false, warmup: null, runMs: null };
  for (var i = 0; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--filter")  out.filter  = argv[++i] || null;
    else if (a === "--out")     out.outPath = argv[++i] || DEFAULT_OUT;
    else if (a === "--compare") out.compare = true;
    else if (a === "--warmup")  out.warmup  = Number(argv[++i]);
    else if (a === "--runMs")   out.runMs   = Number(argv[++i]);
  }
  return out;
}

function _discover() {
  return fs.readdirSync(BENCH_DIR)
    .filter(function (f) { return f.endsWith(".bench.js"); })
    .sort()
    .map(function (f) { return path.join(BENCH_DIR, f); });
}

function _machineInfo() {
  var cpus = os.cpus();
  return {
    platform:   process.platform,
    arch:       process.arch,
    node:       process.version,
    cpuModel:   cpus[0] ? cpus[0].model : "unknown",
    cpuCount:   cpus.length,
    totalMemMB: Math.round(os.totalmem() / 1024 / 1024),
  };
}

function _runFile(filePath, opts, args) {
  var mod = require(filePath);
  if (!mod || !mod.benchmarks || typeof mod.benchmarks !== "object") {
    process.stderr.write("[bench] " + filePath + ": no benchmarks export, skipped\n");
    return [];
  }
  var rows = [];
  Object.keys(mod.benchmarks).forEach(function (label) {
    var fullLabel = mod.name + " / " + label;
    if (args.filter && fullLabel.indexOf(args.filter) < 0) return;
    var fn = mod.benchmarks[label];
    var result = harness.bench(fn, opts);
    rows.push({ label: fullLabel, result: result });
    process.stderr.write(harness.format(fullLabel, result) + "\n");
  });
  return rows;
}

function _compareAgainstBaseline(current, baselinePath) {
  if (!fs.existsSync(baselinePath)) {
    process.stderr.write("[bench] no baseline at " + baselinePath + "; nothing to compare\n");
    return 0;
  }
  var baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
  var bMap = {};
  baseline.results.forEach(function (r) { bMap[r.label] = r.result; });

  var regressed = [];
  process.stderr.write("\n=== compare vs " + baselinePath + " ===\n");
  current.results.forEach(function (r) {
    var b = bMap[r.label];
    if (!b) {
      process.stderr.write(r.label.padEnd(48) + "  NEW (no baseline entry)\n");
      return;
    }
    var deltaP50 = (r.result.p50ns - b.p50ns) / b.p50ns;
    var deltaOps = (r.result.opsPerSec - b.opsPerSec) / b.opsPerSec;
    var sign = deltaP50 >= 0 ? "+" : "";
    process.stderr.write(r.label.padEnd(48) +
      "  p50: " + sign + (deltaP50 * 100).toFixed(1).padStart(7) + "%" +
      "   ops: " + (deltaOps >= 0 ? "+" : "") + (deltaOps * 100).toFixed(1).padStart(7) + "%\n");
    if (deltaP50 > REGRESS_THRESHOLD) regressed.push(r.label + " (+" + (deltaP50 * 100).toFixed(1) + "% p50)");
  });
  if (regressed.length > 0) {
    process.stderr.write("\nREGRESSION (>" + (REGRESS_THRESHOLD * 100) + "% p50 slowdown):\n");
    regressed.forEach(function (r) { process.stderr.write("  " + r + "\n"); });
    return 1;
  }
  process.stderr.write("\nno regressions vs baseline (>" + (REGRESS_THRESHOLD * 100) + "% p50)\n");
  return 0;
}

function main() {
  var args = _parseArgs(process.argv.slice(2));
  var benchOpts = {};
  if (args.warmup) benchOpts.warmupIters = args.warmup;
  if (args.runMs)  benchOpts.runMs       = args.runMs;

  var allRows = [];
  _discover().forEach(function (f) {
    allRows = allRows.concat(_runFile(f, benchOpts, args));
  });

  var record = {
    schemaVersion: 1,
    machine:       _machineInfo(),
    recordedAt:    new Date().toISOString(),
    benchOpts:     {
      warmupIters: benchOpts.warmupIters || null,
      runMs:       benchOpts.runMs       || null,
    },
    results:       allRows,
  };

  if (args.compare) {
    var rc = _compareAgainstBaseline(record, args.outPath);
    process.exit(rc);
  }

  fs.writeFileSync(args.outPath, JSON.stringify(record, null, 2) + "\n", "utf8");
  process.stderr.write("\n[bench] wrote " + path.relative(ROOT, args.outPath) + " (" + allRows.length + " benchmarks)\n");
}

main();

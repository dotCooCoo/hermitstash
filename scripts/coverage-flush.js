"use strict";
/**
 * Write V8 coverage periodically, for processes that never get to exit.
 *
 * Preloaded with `--require`, never imported by the application. It does
 * nothing at all unless NODE_V8_COVERAGE is set, so it is inert outside a
 * coverage run and there is no branch in the product that knows it exists.
 *
 * Why it is needed: V8 writes its coverage when a process exits cleanly. The
 * end-to-end suite stops each server with SIGTERM, and Windows has no signals —
 * Node turns that call into an unconditional termination, so the server dies
 * with everything it recorded still in memory. The result was server-main.js
 * reporting 0% while the suite drove hundreds of requests through it.
 *
 * v8.takeCoverage() writes the current counts to the coverage directory on
 * demand, and what it has written survives a later kill. Calling it on a timer
 * means the most a hard-killed process can lose is the last interval.
 *
 * Each call writes another file. That is fine for correctness — the counts are
 * cumulative per process, and a report only asks whether a branch was taken at
 * all, not how often — but it is why the interval is seconds rather than
 * milliseconds.
 */
if (process.env.NODE_V8_COVERAGE) {
  var v8 = require("node:v8");

  var flush = function () {
    try { v8.takeCoverage(); } catch (_e) { /* nothing useful to do from a preload */ }
  };

  // A first write soon after boot, because plenty of these servers live only a
  // few seconds and would otherwise contribute nothing at all.
  var first = setTimeout(flush, 1000);
  var repeat = setInterval(flush, 3000);

  // unref so neither timer keeps the process alive: a server that would have
  // exited must still exit, or the suite that spawned it hangs waiting.
  if (first.unref) first.unref();
  if (repeat.unref) repeat.unref();

  // A clean exit already writes coverage, so this is only for the paths that
  // bypass that — and it costs one call.
  process.on("exit", flush);
}

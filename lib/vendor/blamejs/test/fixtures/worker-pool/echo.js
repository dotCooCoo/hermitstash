"use strict";
// Test fixture for b.workerPool — minimal echo / arithmetic worker.
// ASCII-only per fixture rule.
//
// Wire format expected by the pool:
//   message in : { kind, ... }
//   reply  out : { ok: true, result } | { ok: false, message }
//
// Supported kinds:
//   "echo"   - reply with the same payload
//   "double" - reply with payload.n * 2
//   "throw"  - throw synchronously to surface as ok:false
//   "loop"   - busy-loop forever to exercise the per-task timeout
//   "bad"    - reply with a non-envelope shape so the pool surfaces
//              workerpool/worker-bad-message
var workerThreads = require("node:worker_threads");
var parentPort = workerThreads.parentPort;
if (!parentPort) {
  throw new Error("worker-pool/echo fixture must run as a worker thread");
}
parentPort.on("message", function (msg) {
  try {
    if (!msg || typeof msg !== "object") {
      parentPort.postMessage({ ok: false, message: "expected object message" });
      return;
    }
    if (msg.kind === "echo") {
      parentPort.postMessage({ ok: true, result: msg.payload });
      return;
    }
    if (msg.kind === "double") {
      var n = (msg && typeof msg.n === "number") ? msg.n : 0;
      parentPort.postMessage({ ok: true, result: n * 2 });
      return;
    }
    if (msg.kind === "throw") {
      throw new Error("fixture-thrown: " + (msg.reason || "no-reason"));
    }
    if (msg.kind === "loop") {
      // Spin until the host terminates this worker. Used to exercise
      // taskTimeoutMs.
      while (true) { /* busy */ }
    }
    if (msg.kind === "bad") {
      parentPort.postMessage("not-an-envelope");
      return;
    }
    parentPort.postMessage({ ok: false, message: "unknown kind: " + msg.kind });
  } catch (e) {
    parentPort.postMessage({ ok: false, message: (e && e.message) || String(e) });
  }
});

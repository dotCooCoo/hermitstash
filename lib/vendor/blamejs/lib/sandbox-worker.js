"use strict";
/**
 * sandbox-worker — bootstrap module loaded inside the worker_threads
 * Worker spawned by lib/sandbox.js. Runs UNTRUSTED operator-supplied
 * source against a pre-stripped global scope.
 *
 * NOT operator-facing — operators interact via b.sandbox.run().
 *
 * Wire format:
 *   workerData: {
 *     source:          string,    // operator-supplied JS — function body
 *     input:           any,       // pass-through input
 *     allowedGlobals:  string[],  // intersected with KNOWN_SAFE_BUILTINS
 *     maxResultBytes:  number,    // hard-cap on JSON.stringify(result)
 *   }
 *
 * Posts back via parentPort:
 *   { ok: true,  resultJson, runtimeMs, peakBytes }
 *   { ok: false, code, message, runtimeMs, peakBytes }
 *
 * Containment summary:
 *   - require / process / Buffer / setTimeout / setInterval / setImmediate /
 *     queueMicrotask / global are deleted off globalThis before the
 *     operator code is compiled.
 *   - The operator source is compiled via the JS language's
 *     string-to-callable primitive — the compiled function's outer
 *     scope is GLOBAL (stripped) and CANNOT see the bootstrap's
 *     own locals (require, workerThreads, parentPort).
 *   - Resource limits (maxOldGenerationSizeMb / maxYoungGenerationSizeMb /
 *     codeRangeSizeMb / stackSizeMb) are set by the host on Worker
 *     construction; v8 kills the worker on heap overflow.
 *   - Output is JSON-serialized; the worker refuses any result whose
 *     stringified form exceeds maxResultBytes.
 */

var workerThreads = require("node:worker_threads");

(function () {
  var data = workerThreads.workerData || {};
  var allowed = Array.isArray(data.allowedGlobals) ? data.allowedGlobals : [];
  var maxResultBytes = (typeof data.maxResultBytes === "number") ? data.maxResultBytes : null;

  // Capture the real UTF-8 byte counter BEFORE the global strip below deletes
  // `Buffer`. The result cap is a BYTE budget — measuring the serialized
  // result with `String.length` (UTF-16 code units) under-enforces it on
  // multibyte output. A detached `Buffer.byteLength` keeps working after
  // `delete globalThis.Buffer`.
  var byteLength = Buffer.byteLength;

  var ALWAYS_AVAILABLE = [
    "Object", "Array", "String", "Number", "Boolean", "Symbol",
    "Promise", "Error", "TypeError", "RangeError", "RegExp",
  ];

  var keep = Object.create(null);
  for (var i = 0; i < ALWAYS_AVAILABLE.length; i += 1) keep[ALWAYS_AVAILABLE[i]] = true;
  for (var j = 0; j < allowed.length; j += 1) keep[allowed[j]] = true;

  var NODE_BUILTINS = [
    "process", "Buffer",
    "setImmediate", "clearImmediate",
    "setTimeout", "clearTimeout",
    "setInterval", "clearInterval",
    "queueMicrotask",
    "global",
  ];
  for (var k = 0; k < NODE_BUILTINS.length; k += 1) {
    var nm = NODE_BUILTINS[k];
    if (!keep[nm]) {
      try { delete globalThis[nm]; }
      catch (_e1) { try { globalThis[nm] = undefined; } catch (_e2) { /* best-effort */ } }
    }
  }

  try { delete globalThis.require; } catch (_e) { /* best-effort */ }

  var startedAt = Date.now();
  var peakBytes = 0;

  function snapshotPeak() {
    try {
      var proc = (typeof process !== "undefined") ? process : null;
      if (proc && typeof proc.memoryUsage === "function") {
        var u = proc.memoryUsage();
        if (u && typeof u.heapUsed === "number" && u.heapUsed > peakBytes) peakBytes = u.heapUsed;
      }
    } catch (_e) { /* process gone or stripped */ }
  }

  snapshotPeak();

  // Compile operator source via the JS language's string-to-callable
  // primitive. The compiled function's outer scope is GLOBAL (already
  // stripped above); it cannot see this bootstrap's own locals.
  var Compiler = (function () { return Function; }());

  var fn;
  try {
    fn = new Compiler("input", data.source);
  } catch (eParse) {
    workerThreads.parentPort.postMessage({
      ok: false, code: "sandbox/parse-error",
      message: "sandbox source did not parse: " + (eParse && eParse.message),
      runtimeMs: Date.now() - startedAt, peakBytes: peakBytes,
    });
    return;
  }

  try {
    var result = fn(data.input);
    snapshotPeak();
    var runtimeMs = Date.now() - startedAt;
    var serialized;
    try { serialized = (result === undefined) ? undefined : JSON.stringify(result); }
    catch (eSer) {
      workerThreads.parentPort.postMessage({
        ok: false, code: "sandbox/result-not-serializable",
        message: "sandbox result is not JSON-serializable: " + (eSer && eSer.message),
        runtimeMs: runtimeMs, peakBytes: peakBytes,
      });
      return;
    }
    if (maxResultBytes !== null && serialized && byteLength(serialized, "utf8") > maxResultBytes) {
      workerThreads.parentPort.postMessage({
        ok: false, code: "sandbox/oversized-result",
        message: "sandbox result exceeded maxResultBytes (" + byteLength(serialized, "utf8") + " > " + maxResultBytes + ")",
        runtimeMs: runtimeMs, peakBytes: peakBytes,
      });
      return;
    }
    workerThreads.parentPort.postMessage({
      ok: true, resultJson: serialized, runtimeMs: runtimeMs, peakBytes: peakBytes,
    });
  } catch (eRun) {
    snapshotPeak();
    workerThreads.parentPort.postMessage({
      ok: false, code: "sandbox/runtime-error",
      message: "sandbox transform threw: " + (eRun && eRun.message ? eRun.message : String(eRun)),
      runtimeMs: Date.now() - startedAt, peakBytes: peakBytes,
    });
  }
}());

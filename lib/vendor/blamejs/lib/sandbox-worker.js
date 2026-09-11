// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var workerThreads = require("node:worker_threads");

(function () {
  var data = workerThreads.workerData || {};
  var allowed = Array.isArray(data.allowedGlobals) ? data.allowedGlobals : [];
  var maxResultBytes = (typeof data.maxResultBytes === "number") ? data.maxResultBytes : null;

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
    "WebAssembly",
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

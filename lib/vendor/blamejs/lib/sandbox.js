// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodePath = require("node:path");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var C = require("./constants");
var { SandboxError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var KNOWN_SAFE_BUILTINS = Object.freeze({
  JSON:         true, Math:         true, Date:         true,
  Map:          true, Set:          true, WeakMap:      true, WeakSet: true,
  RegExp:       true, Error:        true, TypeError:    true, RangeError: true,
  Number:       true, String:       true, Boolean:      true,
  Array:        true, Object:       true, ArrayBuffer:  true,
  Uint8Array:   true, Uint16Array:  true, Uint32Array:  true,
  Int8Array:    true, Int16Array:   true, Int32Array:   true,
  Float32Array: true, Float64Array: true,
  DataView:     true, Symbol:       true, Promise:      true,
});

var ALWAYS_AVAILABLE = Object.freeze([
  "Object", "Array", "String", "Number", "Boolean", "Symbol",
  "Promise", "Error", "TypeError", "RangeError", "RegExp",
]);

var WORKER_PATH = nodePath.resolve(__dirname, "sandbox-worker.js");

var DEFAULT_TIMEOUT_MS = 250;
var MAX_TIMEOUT_MS = C.TIME.seconds(10);
var DEFAULT_MAX_BYTES = C.BYTES.mib(64);
var MAX_MAX_BYTES = C.BYTES.gib(1);
var MIN_MAX_BYTES = C.BYTES.mib(4);

function _validateAllowed(allowed) {
  if (allowed === undefined || allowed === null) return [];
  if (!Array.isArray(allowed)) {
    throw new SandboxError("sandbox/bad-allowed",
      "sandbox.run: opts.allowed must be an array of identifier strings");
  }
  var out = [];
  for (var i = 0; i < allowed.length; i += 1) {
    var name = allowed[i];
    if (typeof name !== "string" || name.length === 0) {
      throw new SandboxError("sandbox/bad-allowed",
        "sandbox.run: opts.allowed[" + i + "] must be a non-empty identifier string");
    }
    if (!Object.prototype.hasOwnProperty.call(KNOWN_SAFE_BUILTINS, name)) {
      throw new SandboxError("sandbox/bad-allowed",
        "sandbox.run: opts.allowed[" + i + "] = " + JSON.stringify(name) +
        " is not in the sandbox built-in allowlist " +
        "(known-safe: " + Object.keys(KNOWN_SAFE_BUILTINS).join(", ") + ")");
    }
    if (out.indexOf(name) === -1) out.push(name);
  }
  return out;
}

function _emitAudit(action, outcome, metadata) {
  try {
    audit().safeEmit({
      action:   action,
      outcome:  outcome,
      metadata: metadata,
    });
  } catch (_e) { /* drop-silent - audit best-effort */ }
}

function run(opts) {
  opts = opts || {};
  try {
    validateOpts(opts, ["source", "input", "timeoutMs", "maxBytes", "allowed"], "sandbox.run");
  } catch (e) { return Promise.reject(new SandboxError("sandbox/bad-opts", e.message)); }

  try {
    validateOpts.requireNonEmptyString(opts.source,
      "sandbox.run: opts.source", SandboxError, "sandbox/bad-source");
  } catch (e) { return Promise.reject(e); }
  var sourceBytes = Buffer.byteLength(opts.source, "utf8");

  var timeoutMs;
  try {
    timeoutMs = (opts.timeoutMs === undefined) ? DEFAULT_TIMEOUT_MS : opts.timeoutMs;
    numericBounds.requirePositiveFiniteIntIfPresent(timeoutMs,
      "sandbox.run: opts.timeoutMs", SandboxError, "sandbox/bad-timeout");
  } catch (e) { return Promise.reject(e); }
  if (timeoutMs > MAX_TIMEOUT_MS) {
    return Promise.reject(new SandboxError("sandbox/bad-timeout",
      "sandbox.run: opts.timeoutMs (" + timeoutMs + ") exceeds the framework cap of " + MAX_TIMEOUT_MS + " ms"));
  }

  var maxBytes;
  try {
    maxBytes = (opts.maxBytes === undefined) ? DEFAULT_MAX_BYTES : opts.maxBytes;
    numericBounds.requirePositiveFiniteIntIfPresent(maxBytes,
      "sandbox.run: opts.maxBytes", SandboxError, "sandbox/bad-max-bytes");
  } catch (e) { return Promise.reject(e); }
  if (maxBytes < MIN_MAX_BYTES) {
    return Promise.reject(new SandboxError("sandbox/bad-max-bytes",
      "sandbox.run: opts.maxBytes (" + maxBytes + ") below the framework floor of " + MIN_MAX_BYTES + " bytes"));
  }
  if (maxBytes > MAX_MAX_BYTES) {
    return Promise.reject(new SandboxError("sandbox/bad-max-bytes",
      "sandbox.run: opts.maxBytes (" + maxBytes + ") exceeds the framework cap of " + MAX_MAX_BYTES + " bytes"));
  }

  var allowedGlobals;
  try { allowedGlobals = _validateAllowed(opts.allowed); }
  catch (e) { return Promise.reject(e); }

  var inputJson;
  try { inputJson = (opts.input === undefined) ? null : JSON.stringify(opts.input); }
  catch (eSer) {
    return Promise.reject(new SandboxError("sandbox/bad-input",
      "sandbox.run: opts.input is not JSON-serializable: " + (eSer && eSer.message)));
  }
  if (inputJson !== null && safeBuffer.byteLengthOf(inputJson) > maxBytes) {
    return Promise.reject(new SandboxError("sandbox/input-too-large",
      "sandbox.run: opts.input serialized to " + safeBuffer.byteLengthOf(inputJson) + " bytes (>" + maxBytes + ")"));
  }

  var workerThreads;
  try { workerThreads = require("node:worker_threads"); }
  catch (_e) {
    return Promise.reject(new SandboxError("sandbox/no-worker-threads",
      "sandbox.run: node:worker_threads is unavailable in this runtime"));
  }

  var oneMib = C.BYTES.mib(1);
  var minHeapFloorMib = 64;
  var youngGenCapMib  = 32;
  var youngGenFloorMib = 8;
  var codeRangeCapMib = 16;
  var codeRangeFloorMib = 8;
  var stackMib = 4;
  var heapMib = Math.max(minHeapFloorMib, Math.floor(maxBytes / oneMib));
  var resourceLimits = {
    maxOldGenerationSizeMb:   heapMib,
    maxYoungGenerationSizeMb: Math.max(youngGenFloorMib, Math.min(heapMib, youngGenCapMib)),
    codeRangeSizeMb:          Math.max(codeRangeFloorMib, Math.min(heapMib, codeRangeCapMib)),
    stackSizeMb:              stackMib,
  };

  var maxResultBytes = Math.min(Math.floor(maxBytes / 4), safeJson.ABSOLUTE_MAX_BYTES);

  return new Promise(function (resolve, reject) {
    var startedAt = Date.now();
    var settled = false;
    var worker;
    try {
      worker = new workerThreads.Worker(WORKER_PATH, {
        workerData: {
          source:          opts.source,
          input:           opts.input,
          allowedGlobals:  allowedGlobals,
          maxResultBytes:  maxResultBytes,
        },
        resourceLimits: resourceLimits,
        stdout: true,
        stderr: true,
      });
    } catch (eSpawn) {
      var spawnRuntimeMs = Date.now() - startedAt;
      _emitAudit("sandbox.run.refused", "failure", {
        reason: "sandbox/spawn-failed", runtimeMs: spawnRuntimeMs, peakBytes: 0, sourceBytes: sourceBytes,
      });
      reject(new SandboxError("sandbox/spawn-failed",
        "sandbox.run: failed to spawn worker: " + (eSpawn && eSpawn.message)));
      return;
    }

    function _terminateThen(finish) {
      var done = false;
      function _once() { if (done) return; done = true; finish(); }
      var p;
      try { p = worker.terminate(); } catch (_e) { p = null; }
      if (p && typeof p.then === "function") { p.then(_once, _once); }
      else { _once(); }
    }

    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      var elapsed = Date.now() - startedAt;
      _emitAudit("sandbox.run.refused", "failure", {
        reason: "sandbox/timeout", runtimeMs: elapsed, peakBytes: 0, sourceBytes: sourceBytes,
      });
      _terminateThen(function () {
        reject(new SandboxError("sandbox/timeout",
          "sandbox.run: worker exceeded timeoutMs=" + timeoutMs + " (elapsed " + elapsed + "ms)"));
      });
    }, timeoutMs);

    worker.on("message", function (msg) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      _terminateThen(function () { _handleMessage(msg); });
    });

    function _handleMessage(msg) {
      if (!msg || typeof msg !== "object") {
        _emitAudit("sandbox.run.refused", "failure", {
          reason: "sandbox/bad-worker-message", runtimeMs: Date.now() - startedAt, peakBytes: 0, sourceBytes: sourceBytes,
        });
        return reject(new SandboxError("sandbox/bad-worker-message",
          "sandbox.run: worker returned a non-object message"));
      }
      var runtimeMs = (typeof msg.runtimeMs === "number") ? msg.runtimeMs : (Date.now() - startedAt);
      var peakBytes = (typeof msg.peakBytes === "number") ? msg.peakBytes : 0;
      if (msg.ok) {
        var parsed;
        try { parsed = (msg.resultJson === undefined) ? undefined : safeJson.parse(msg.resultJson, { maxBytes: maxResultBytes }); }
        catch (eParse) {
          _emitAudit("sandbox.run.refused", "failure", {
            reason: "sandbox/bad-result-json", runtimeMs: runtimeMs, peakBytes: peakBytes, sourceBytes: sourceBytes,
          });
          return reject(new SandboxError("sandbox/bad-result-json",
            "sandbox.run: worker result was not parseable JSON: " + (eParse && eParse.message)));
        }
        _emitAudit("sandbox.run", "success", {
          runtimeMs: runtimeMs, peakBytes: peakBytes, sourceBytes: sourceBytes,
        });
        return resolve({ result: parsed, runtimeMs: runtimeMs, peakBytes: peakBytes });
      }
      _emitAudit("sandbox.run.refused", "failure", {
        reason: msg.code || "sandbox/runtime-error", runtimeMs: runtimeMs, peakBytes: peakBytes, sourceBytes: sourceBytes,
      });
      return reject(new SandboxError(msg.code || "sandbox/runtime-error",
        msg.message || "sandbox.run: worker reported a refusal"));
    }

    worker.on("error", function (err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      var elapsed = Date.now() - startedAt;
      _emitAudit("sandbox.run.refused", "failure", {
        reason: "sandbox/worker-error", runtimeMs: elapsed, peakBytes: 0, sourceBytes: sourceBytes,
      });
      reject(new SandboxError("sandbox/worker-error",
        "sandbox.run: worker errored: " + (err && err.message ? err.message : String(err))));
    });

    worker.on("exit", function (code) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      var elapsed = Date.now() - startedAt;
      var reason = (code === 0) ? "sandbox/no-result" : "sandbox/worker-nonzero-exit";
      var message = (code === 0)
        ? "sandbox.run: worker exited without posting a result (heap cap or premature return)"
        : "sandbox.run: worker exited with code " + code + " (likely resource-limit kill)";
      _emitAudit("sandbox.run.refused", "failure", {
        reason: reason, runtimeMs: elapsed, peakBytes: 0, sourceBytes: sourceBytes,
      });
      reject(new SandboxError(reason, message));
    });
  });
}

module.exports = {
  run:                  run,
  KNOWN_SAFE_BUILTINS:  KNOWN_SAFE_BUILTINS,
  ALWAYS_AVAILABLE:     ALWAYS_AVAILABLE,
  DEFAULT_TIMEOUT_MS:   DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS:       MAX_TIMEOUT_MS,
  DEFAULT_MAX_BYTES:    DEFAULT_MAX_BYTES,
  MAX_MAX_BYTES:        MAX_MAX_BYTES,
  MIN_MAX_BYTES:        MIN_MAX_BYTES,
  WORKER_PATH:          WORKER_PATH,
  SandboxError:         SandboxError,
};

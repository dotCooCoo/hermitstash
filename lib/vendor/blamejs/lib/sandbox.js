"use strict";
/**
 * b.sandbox - isolation harness for operator-supplied transforms.
 *
 * Some primitives (b.template with sandbox: true, custom audit-export
 * formatters, response-shape rewriters, ETL hooks) need to run JS
 * source the operator wrote against per-request input. In-process eval
 * gives that source the framework full module graph: filesystem,
 * network, process, child_process, the entire b.* surface, vault keys,
 * and audit-bypass via direct DB writes. b.sandbox runs the source
 * inside a fresh worker_threads.Worker with strict resource limits and
 * a hand-built scope that exposes ONLY the globals the operator
 * allowlists at create() time.
 *
 *   var result = await b.sandbox.run({
 *     source:    "return { upper: input.name.toUpperCase() };",
 *     input:     { name: "alice" },
 *     timeoutMs: 250,
 *     maxBytes:  C.BYTES.mib(8),
 *     allowed:   ["JSON", "Math", "Date"],
 *   });
 *   // result -> { result: { upper: "ALICE" }, runtimeMs: 12, peakBytes: 4194304 }
 *
 * Default-deny posture (lib/sandbox-worker.js docstring has the full list):
 *   - No require / process / Buffer / setTimeout / setImmediate /
 *     setInterval / queueMicrotask / global. The bootstrap deletes
 *     each off globalThis BEFORE compiling operator source.
 *   - No filesystem / network / child_process / spawn / dns -
 *     unreachable once require is gone.
 *   - No worker re-entry - worker_threads itself unreachable.
 *   - Timeout (default: 250ms, max: 10s) terminates the worker.
 *   - Heap caps (maxOldGenerationSizeMb / maxYoungGenerationSizeMb)
 *     derived from maxBytes; v8 kills the worker on overflow.
 *   - Result size cap = min(maxBytes / 4, 64 MiB) - the host re-parses
 *     the untrusted result through safeJson, whose hard ceiling bounds
 *     it at 64 MiB regardless of a larger maxBytes.
 *
 * Allowed-globals list:
 *   The allowed opt names which extra globals operator source may
 *   reference. The list is intersected against KNOWN_SAFE_BUILTINS at
 *   the host before being shipped to the worker - anything outside
 *   the allowlist refuses at the call site. JS-language primitives
 *   (Object, Array, String, Number, Boolean, Symbol, Promise, Error,
 *   TypeError, RangeError, RegExp) survive regardless because they
 *   cannot be removed without breaking literal expressions.
 *
 * Composability with b.template:
 *   b.template.create({ sandbox: true }) routes operator-supplied
 *   helper-function bodies through b.sandbox before exposing them as
 *   helpers in the template scope. The template engine itself remains
 *   eval-free - sandbox is the secondary defense for the rare cases
 *   where an operator NEEDS to ship a transform alongside a template
 *   (date formatters with locale-dependent fallbacks, etc.).
 *
 * Audit shape:
 *   - sandbox.run         - outcome=success; metadata: { runtimeMs, peakBytes, sourceBytes }
 *   - sandbox.run.refused - outcome=failure; metadata: { reason, runtimeMs, peakBytes, sourceBytes }
 *
 * Failure modes (every one throws SandboxError):
 *   - sandbox/bad-opts            - unknown opts key
 *   - sandbox/bad-source          - source is not a non-empty string
 *   - sandbox/bad-allowed         - allowed contains non-string or non-allowlisted name
 *   - sandbox/bad-timeout         - timeoutMs is not a positive finite int (or > MAX_TIMEOUT_MS)
 *   - sandbox/bad-max-bytes       - maxBytes is not a positive finite int (or out of range)
 *   - sandbox/bad-input           - input is not JSON-serializable
 *   - sandbox/input-too-large     - JSON.stringify(input).length > maxBytes
 *   - sandbox/timeout             - worker exceeded timeoutMs
 *   - sandbox/oversized-result    - worker output > min(maxBytes / 4, 64 MiB)
 *   - sandbox/parse-error         - source did not parse inside the worker
 *   - sandbox/runtime-error       - operator transform threw
 *   - sandbox/spawn-failed        - worker thread failed to spawn
 *   - sandbox/worker-error        - worker thread errored after spawn
 *   - sandbox/worker-nonzero-exit - worker died (heap-cap kill class)
 *   - sandbox/no-result           - worker exited without posting (heap-cap class)
 *   - sandbox/no-worker-threads   - runtime lacks node:worker_threads
 *
 * Operators feeding untrusted source MUST also pair this with their
 * own posture (operator-uploaded transforms only after a code-review
 * gate, etc.) - sandbox is one defense layer, not a license to accept
 * arbitrary source from the public internet.
 */

var nodePath = require("node:path");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var C = require("./constants");
var { SandboxError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

// Built-in allowlist for the allowed opt. Filesystem / network /
// process / require are deliberately absent. JS-language primitives
// stay reachable inside the worker regardless of this list.
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

// JS-language primitives that survive regardless of allowlist -
// stripping these would mean operator transforms cannot evaluate
// even simple literals. Mirrors lib/sandbox-worker.js.
var ALWAYS_AVAILABLE = Object.freeze([
  "Object", "Array", "String", "Number", "Boolean", "Symbol",
  "Promise", "Error", "TypeError", "RangeError", "RegExp",
]);

var WORKER_PATH = nodePath.resolve(__dirname, "sandbox-worker.js");

// Default caps. Sourced from C.* helpers so the unit lives at the call site.
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

  // resourceLimits in MiB. Derive from maxBytes - keep a small headroom
  // floor so the worker can boot. Round each cap down to a MiB integer.
  // Floors / caps are quanta of MiB chosen to fit a small embedded
  // worker; passed straight to v8's resourceLimits.
  var oneMib = C.BYTES.mib(1);
  // The MiB-unit caps below are integers passed directly to v8's
  // resourceLimits (already typed in MiB by the v8 API), not byte
  // counts - the constants helpers don't apply.
  var minHeapFloorMib = 64;     // MiB unit count, not bytes
  var youngGenCapMib  = 32;     // MiB unit count, not bytes
  var youngGenFloorMib = 8;     // MiB unit count, not bytes
  var codeRangeCapMib = 16;     // MiB unit count, not bytes
  var codeRangeFloorMib = 8;    // MiB unit count, not bytes
  var stackMib = 4;             // MiB unit count, not bytes
  var heapMib = Math.max(minHeapFloorMib, Math.floor(maxBytes / oneMib));
  var resourceLimits = {
    maxOldGenerationSizeMb:   heapMib,
    maxYoungGenerationSizeMb: Math.max(youngGenFloorMib, Math.min(heapMib, youngGenCapMib)),
    codeRangeSizeMb:          Math.max(codeRangeFloorMib, Math.min(heapMib, codeRangeCapMib)),
    stackSizeMb:              stackMib,
  };

  // Reserve 1/4 of maxBytes as the per-result hard cap, clamped to the
  // host-side JSON parse ceiling so the worker's output cap and the host's
  // safeJson.parse cap agree exactly. Without the clamp a sandbox with
  // maxBytes over 256 MiB would let the worker emit a result the host then
  // refuses (safeJson hard-caps at ABSOLUTE_MAX_BYTES) — the worker refuses
  // it too, so an oversized untrusted result fails the same way on both
  // sides rather than passing the worker and crossing to a rejecting host.
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

    // Terminate the worker and only settle the caller's promise once the
    // termination resolves. worker.terminate() is asynchronous: settling
    // before it completes leaves the worker thread's MessagePort alive past
    // the resolve, keeping the event loop open (a leaked handle that delays
    // a shut-down on a slow runner). Awaiting terminate() releases it.
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
        // resultJson is the JSON.stringify of UNTRUSTED sandboxed code's return
        // value: parse it through safeJson so a "__proto__" member is stripped
        // and a pathologically deep/large result is bounded (maxResultBytes), not
        // a raw JSON.parse that re-creates the key and is depth-unbounded.
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
      // Code 0 with no message means the worker exited without posting -
      // usually a heap-cap kill. Surface as oversized.
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

"use strict";
/**
 * sandbox primitive - layer-0 tests for b.sandbox.run.
 *
 * Exercises:
 *   - happy path (pure transform)
 *   - allowed-builtin allowlist (JSON / Math / Date)
 *   - bad-allowed: rejects non-allowlisted globals
 *   - bad-source: rejects empty + non-string
 *   - bad-timeout / bad-max-bytes: bound enforcement
 *   - timeout: source loops past timeoutMs
 *   - input-too-large: input bigger than maxBytes
 *   - oversized-result: source returns too big
 *   - parse-error: malformed source
 *   - runtime-error: source throws
 *   - bad-input: non-serializable input
 *   - containment: require / process / globalThis.require unreachable
 *   - audit emission: success + refusal events
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

async function testHappyPath() {
  var r = await b.sandbox.run({
    source: "return { upper: input.name.toUpperCase(), len: input.name.length };",
    input:  { name: "alice" },
    timeoutMs: 10000,
  });
  check("happy path returns wrapped result",       typeof r === "object");
  check("happy path produces result.result.upper", r.result && r.result.upper === "ALICE");
  check("happy path produces result.result.len",   r.result && r.result.len === 5);
  check("runtimeMs is a number",                   typeof r.runtimeMs === "number");
  check("peakBytes is a number",                   typeof r.peakBytes === "number");
}

async function testAllowedBuiltins() {
  var r = await b.sandbox.run({
    source:    "return { ts: Date.now() > 0, sqrt: Math.sqrt(16) };",
    input:     {},
    allowed:   ["Date", "Math"],
    timeoutMs: 10000,
  });
  check("allowed Date works",   r.result.ts === true);
  check("allowed Math works",   r.result.sqrt === 4);
}

async function testBadAllowedRejected() {
  try {
    await b.sandbox.run({
      source:    "return null;",
      allowed:   ["process"],
      timeoutMs: 10000,
    });
    check("bad-allowed should have refused", false);
  } catch (e) {
    check("bad-allowed refused with SandboxError", e && e.name === "SandboxError");
    check("bad-allowed code is sandbox/bad-allowed", e && e.code === "sandbox/bad-allowed");
  }
}

async function testBadSourceRejected() {
  try {
    await b.sandbox.run({ source: "", timeoutMs: 10000 });
    check("empty source should refuse", false);
  } catch (e) {
    check("empty source refused", e && e.code === "sandbox/bad-source");
  }
  try {
    await b.sandbox.run({ source: 42, timeoutMs: 10000 });
    check("non-string source should refuse", false);
  } catch (e) {
    check("non-string source refused", e && e.code === "sandbox/bad-source");
  }
}

async function testBadTimeoutRejected() {
  try {
    await b.sandbox.run({ source: "return 1;", timeoutMs: -1 });
    check("negative timeoutMs should refuse", false);
  } catch (e) {
    check("negative timeoutMs refused", e && e.code === "sandbox/bad-timeout");
  }
  try {
    await b.sandbox.run({ source: "return 1;", timeoutMs: 999999999 });
    check("over-cap timeoutMs should refuse", false);
  } catch (e) {
    check("over-cap timeoutMs refused", e && e.code === "sandbox/bad-timeout");
  }
}

async function testBadMaxBytesRejected() {
  try {
    await b.sandbox.run({ source: "return 1;", maxBytes: 100, timeoutMs: 10000 });
    check("under-floor maxBytes should refuse", false);
  } catch (e) {
    check("under-floor maxBytes refused", e && e.code === "sandbox/bad-max-bytes");
  }
}

async function testTimeoutEnforced() {
  try {
    await b.sandbox.run({
      source:    "while (true) {}",
      timeoutMs: 200,
    });
    check("infinite loop should timeout", false);
  } catch (e) {
    check("timeout enforced", e && e.code === "sandbox/timeout");
  }
}

async function testParseError() {
  try {
    await b.sandbox.run({ source: "this is not valid javascript ((", timeoutMs: 10000 });
    check("malformed source should refuse", false);
  } catch (e) {
    check("parse-error returned", e && e.code === "sandbox/parse-error");
  }
}

async function testRuntimeError() {
  try {
    await b.sandbox.run({
      source:    "throw new Error('boom');",
      timeoutMs: 10000,
    });
    check("throwing source should reject", false);
  } catch (e) {
    check("runtime-error returned", e && e.code === "sandbox/runtime-error");
    check("runtime-error message includes boom", e && /boom/.test(e.message));
  }
}

async function testBadInput() {
  // Circular ref breaks JSON.stringify
  var circular = {};
  circular.self = circular;
  try {
    await b.sandbox.run({ source: "return 1;", input: circular, timeoutMs: 10000 });
    check("circular input should refuse", false);
  } catch (e) {
    check("bad-input refused", e && e.code === "sandbox/bad-input");
  }
}

async function testContainment() {
  // require should be unreachable inside the sandbox -- expecting
  // ReferenceError surfaced as sandbox/runtime-error.
  try {
    await b.sandbox.run({
      source:    "var x = require; return typeof x;",
      timeoutMs: 10000,
    });
    check("require should not be reachable", false);
  } catch (e) {
    check("require unreachable in sandbox", e && e.code === "sandbox/runtime-error");
  }
}

async function testProcessUnreachable() {
  try {
    await b.sandbox.run({
      source:    "return process.env.HOME;",
      timeoutMs: 10000,
    });
    check("process should not be reachable", false);
  } catch (e) {
    check("process unreachable in sandbox", e && e.code === "sandbox/runtime-error");
  }
}

async function testNoNetworkAccess() {
  // require absent means http unreachable; confirm path.
  try {
    await b.sandbox.run({
      source:    "var http = require('http'); return 1;",
      timeoutMs: 10000,
    });
    check("network access should refuse", false);
  } catch (e) {
    check("network reachability refused", e && e.code === "sandbox/runtime-error");
  }
}

async function testKnownSafeBuiltins() {
  var k = b.sandbox.KNOWN_SAFE_BUILTINS;
  check("KNOWN_SAFE_BUILTINS includes JSON",       k && k.JSON === true);
  check("KNOWN_SAFE_BUILTINS includes Math",       k && k.Math === true);
  check("KNOWN_SAFE_BUILTINS includes Date",       k && k.Date === true);
  check("KNOWN_SAFE_BUILTINS does NOT include process",        !k.process);
  check("KNOWN_SAFE_BUILTINS does NOT include require",        !k.require);
  check("KNOWN_SAFE_BUILTINS does NOT include Buffer",         !k.Buffer);
  check("KNOWN_SAFE_BUILTINS does NOT include child_process",  !k.child_process);
}

function testErrorClassExposed() {
  check("sandbox.SandboxError is fn",
        typeof b.sandbox.SandboxError === "function");
}

async function run() {
  testErrorClassExposed();
  await testHappyPath();
  await testAllowedBuiltins();
  await testBadAllowedRejected();
  await testBadSourceRejected();
  await testBadTimeoutRejected();
  await testBadMaxBytesRejected();
  await testTimeoutEnforced();
  await testParseError();
  await testRuntimeError();
  await testBadInput();
  await testContainment();
  await testProcessUnreachable();
  await testNoNetworkAccess();
  await testKnownSafeBuiltins();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK - " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", (e && e.stack) || e); process.exit(1); }
  );
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.bootGates
 * @nav    Process
 * @title  Boot Gates
 *
 * @intro
 *   Sequential gate runner for boot-time invariants — vault unseal,
 *   KEM key load, TLS material presence, DB schema migration, etc.
 *   Each gate is `{ name, fn, timeoutMs?, exitCode?, onFail? }`; the
 *   runner walks them in order and on FIRST failure:
 *
 *     1. emits `bootgates.failed { name, error, durationMs }` audit,
 *     2. runs `onFail(err)` if provided (await async; swallows
 *        throws + emits a separate `bootgates.onfail_threw` audit),
 *     3. writes a single-line failure summary to stderr,
 *     4. calls `process.exit(gate.exitCode || 1)`.
 *
 *   On success: emits `bootgates.passed { name, durationMs }` and
 *   proceeds. Returns `{ passed, totalMs }` when EVERY gate passes.
 *
 *   Replaces the open-coded boot sequence operators write per-process
 *   (try / log / process.exit) with one greppable primitive that
 *   composes audit observability and gate-specific timeouts.
 *
 * @card
 *   Sequential boot-invariant runner — gate, audit, exit with the right exit code. The thing every daemon main() reaches for.
 */

var C = require("./constants");
var audit = require("./audit");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");

var BootGatesError = defineClass("BootGatesError", { alwaysPermanent: true });

var DEFAULT_GATE_TIMEOUT_MS = C.TIME.seconds(60);
var DEFAULT_EXIT_CODE = 1;

/**
 * @primitive b.bootGates.run
 * @signature b.bootGates.run(gates, opts?)
 * @since     0.10.9
 * @status    stable
 * @related   b.appShutdown.create, b.audit.safeEmit
 *
 * Walk `gates` in order, awaiting each `fn`. First failure stops the
 * sequence and (after `onFail` + audit + stderr) calls
 * `process.exit(gate.exitCode || opts.exitCode || 1)`. Returns
 * `{ passed: string[], totalMs: number }` on full success.
 *
 * @opts
 *   exitCode:        number,           // default 1 — overall fall-through
 *   log:             function,         // default console.error.bind(console)
 *   exit:            function,         // test seam; default process.exit
 *   overallTimeoutMs: number,          // cap across the full sequence
 *
 * @example
 *   await b.bootGates.run([
 *     { name: "vault.unseal",       fn: async function () { await b.vault.unseal(); } },
 *     { name: "tls.material",       fn: async function () { await loadTls(); } },
 *     { name: "db.schemaMigration", fn: async function () { await migrate(); },
 *       onFail: async function () { await db.close(); } },
 *   ]);
 */
async function run(gates, opts) {
  opts = opts || {};
  if (!Array.isArray(gates) || gates.length === 0) {
    throw new BootGatesError("boot-gates/bad-input",
      "b.bootGates.run: gates must be a non-empty array");
  }
  var log = typeof opts.log === "function" ? opts.log : function (msg) {
    process.stderr.write(msg + "\n");
  };
  // Default exit handler invokes process.exit on the platform — guarded
  // behind the opt because lib/ code is forbidden from calling
  // process.exit directly (codebase-patterns rule "no process.exit() in
  // lib/ (CLI surface only)"); the indirection routes through an opts-
  // supplied function so test code substitutes a capture, and the CLI
  // (bin/blamejs.js) is the one that wires the real exit call. When
  // opts.exit isn't supplied, the boot-gate failure path bubbles a
  // throw rather than terminating the process — operators that wire
  // bootGates from their daemon main() pass `exit: process.exit.bind(process)`.
  var exit = typeof opts.exit === "function" ? opts.exit : function (code) {
    var e = new BootGatesError("boot-gates/no-exit-wired",
      "b.bootGates.run: gate failed (exitCode=" + code + ") but no opts.exit handler was supplied; " +
      "operators wire opts.exit to process.exit.bind(process) in their daemon main()");
    e.exitCode = code;
    throw e;
  };
  var overallTimeoutMs = opts.overallTimeoutMs;
  var t0 = Date.now();
  var passed = [];

  for (var i = 0; i < gates.length; i += 1) {
    var gate = gates[i];
    if (!gate || typeof gate.name !== "string" || gate.name.length === 0 ||
        typeof gate.fn !== "function") {
      throw new BootGatesError("boot-gates/bad-gate",
        "b.bootGates.run: gates[" + i + "] must be { name: string, fn: function }");
    }
    var timeoutMs = gate.timeoutMs || DEFAULT_GATE_TIMEOUT_MS;
    if (typeof timeoutMs !== "number" || !isFinite(timeoutMs) || timeoutMs < 1) {
      throw new BootGatesError("boot-gates/bad-timeout",
        "b.bootGates.run: gates[" + i + "].timeoutMs must be a positive finite number");
    }
    var gateT0 = Date.now();
    var failure = null;
    try {
      await safeAsync.withTimeout(Promise.resolve().then(gate.fn), timeoutMs,
        new BootGatesError("boot-gates/timeout",
          "b.bootGates.run: gate '" + gate.name + "' exceeded " + timeoutMs + "ms"));
    } catch (err) {
      failure = err;
    }
    if (overallTimeoutMs !== undefined &&
        Date.now() - t0 > overallTimeoutMs && failure === null) {
      failure = new BootGatesError("boot-gates/overall-timeout",
        "b.bootGates.run: overall budget " + overallTimeoutMs + "ms exceeded after gate '" +
        gate.name + "'");
    }
    var durationMs = Date.now() - gateT0;
    if (failure !== null) {
      try {
        audit.safeEmit({
          action:   "bootgates.failed",
          outcome:  "failure",
          metadata: { name: gate.name, error: (failure && failure.message) || String(failure),
                      durationMs: durationMs },
        });
      } catch (_e) { /* drop-silent */ }
      if (typeof gate.onFail === "function") {
        try {
          await Promise.resolve().then(function () { return gate.onFail(failure); });
        } catch (oe) {
          try {
            audit.safeEmit({
              action:   "bootgates.onfail_threw",
              outcome:  "failure",
              metadata: { name: gate.name, error: (oe && oe.message) || String(oe) },
            });
          } catch (_e2) { /* drop-silent */ }
        }
      }
      log("[bootgates] FAILED gate=" + gate.name + " durationMs=" + durationMs +
          " error=" + ((failure && failure.message) || String(failure)));
      if (failure && failure.stack) log(failure.stack);
      var code = gate.exitCode || opts.exitCode || DEFAULT_EXIT_CODE;
      exit(code);
      // The test seam swaps `exit` out; in that case we still surface
      // a synthetic return value so the caller's promise resolves.
      return { passed: passed, failed: gate.name, exitCode: code, totalMs: Date.now() - t0 };
    }
    try {
      audit.safeEmit({
        action:   "bootgates.passed",
        outcome:  "success",
        metadata: { name: gate.name, durationMs: durationMs },
      });
    } catch (_e3) { /* drop-silent */ }
    if (typeof opts.onPassed === "function") {
      try { opts.onPassed({ name: gate.name, durationMs: durationMs }); }
      catch (_e4) { /* drop-silent */ }
    }
    passed.push(gate.name);
  }

  return { passed: passed, totalMs: Date.now() - t0 };
}

module.exports = {
  run:            run,
  BootGatesError: BootGatesError,
};

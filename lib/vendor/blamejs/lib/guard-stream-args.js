// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.guardStreamArgs
 * @nav        Guards
 * @title      Guard Stream Args
 * @order      437
 *
 * @intro
 *   Validates `b.agent.stream.create` opts (and the operator-supplied
 *   stream args). Refuses non-positive batch sizes, non-integer batch
 *   sizes (silent shard-style routing drift class — same shape Codex
 *   caught on v0.9.21), oversized batch sizes (back-pressure becomes
 *   meaningless), and structured-clone-unsafe filter shapes (functions
 *   / regex / Buffer in the cursor opts — same shape `b.guardMailQuery`
 *   refuses).
 *
 * @card
 *   Validates `b.agent.stream.create` opts + cursor args. Integer-only
 *   batchSize, structured-clone-safe filter shapes, sensible caps.
 */

var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");
var pick = require("./pick");

var GuardStreamArgsError = defineClass("GuardStreamArgsError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxBatchSize: 1024,  minBatchSize: 1, maxOpenStreams: 4   },
  balanced:   { maxBatchSize: 4096,  minBatchSize: 1, maxOpenStreams: 16  },
  permissive: { maxBatchSize: 16384, minBatchSize: 1, maxOpenStreams: 64  },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardStreamArgsError,
  codePrefix: "stream-args",
});

/**
 * @primitive b.guardStreamArgs.validate
 * @signature b.guardStreamArgs.validate(args, opts?)
 * @since     0.9.24
 * @status    stable
 * @related   b.agent.stream.create
 *
 * Validate `b.agent.stream.create` opts shape. Returns the input on
 * success; throws `GuardStreamArgsError` on refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardStreamArgs.validate({
 *     batchSize: 256,
 *     kind:      "search",
 *   });
 */
function validate(args, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!args || typeof args !== "object") {
    throw new GuardStreamArgsError("stream-args/bad-input",
      "guardStreamArgs.validate: args required");
  }
  if (typeof args.batchSize !== "undefined") {
    if (!Number.isInteger(args.batchSize)) {
      throw new GuardStreamArgsError("stream-args/bad-batch-size",
        "guardStreamArgs.validate: batchSize must be an integer");
    }
    if (args.batchSize < profile.minBatchSize || args.batchSize > profile.maxBatchSize) {
      throw new GuardStreamArgsError("stream-args/batch-size-out-of-range",
        "guardStreamArgs.validate: batchSize " + args.batchSize +
        " not in [" + profile.minBatchSize + ", " + profile.maxBatchSize + "]");
    }
  }
  if (typeof args.kind !== "undefined") {
    if (typeof args.kind !== "string" || args.kind.length === 0) {
      throw new GuardStreamArgsError("stream-args/bad-kind",
        "guardStreamArgs.validate: kind must be a non-empty string");
    }
  }
  // Cursor opts can't carry function / regex / Buffer — they must
  // cross the structured-clone boundary into a worker thread.
  if (typeof args.cursorOpts !== "undefined") {
    _checkCursorOpts(args.cursorOpts);
  }
  return args;
}

function _checkCursorOpts(cursorOpts, depth) {
  depth = depth || 0;
  if (depth > 8) {                                                                                    // recursion depth cap
    throw new GuardStreamArgsError("stream-args/cursor-opts-too-deep",
      "guardStreamArgs.validate: cursorOpts nesting depth exceeds 8");
  }
  // Function check FIRST — `typeof function === "function"` not
  // "object", so a function value would silently skip the non-object
  // early-return below.
  if (typeof cursorOpts === "function") {
    throw new GuardStreamArgsError("stream-args/function-not-allowed",
      "guardStreamArgs.validate: functions refused in cursorOpts (structured-clone-unsafe)");
  }
  if (cursorOpts === null || typeof cursorOpts !== "object") return;
  if (cursorOpts instanceof RegExp) {
    throw new GuardStreamArgsError("stream-args/regex-not-allowed",
      "guardStreamArgs.validate: RegExp refused in cursorOpts");
  }
  if (Buffer.isBuffer(cursorOpts)) {
    throw new GuardStreamArgsError("stream-args/buffer-not-allowed",
      "guardStreamArgs.validate: Buffer refused in cursorOpts");
  }
  if (Array.isArray(cursorOpts)) {
    for (var i = 0; i < cursorOpts.length; i += 1) _checkCursorOpts(cursorOpts[i], depth + 1);
    return;
  }
  var keys = Object.keys(cursorOpts);
  for (var k = 0; k < keys.length; k += 1) {
    if (pick.isPoisonedKey(keys[k])) {
      throw new GuardStreamArgsError("stream-args/proto-key",
        "guardStreamArgs.validate: forbidden key '" + keys[k] + "' in cursorOpts");
    }
    _checkCursorOpts(cursorOpts[keys[k]], depth + 1);
  }
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.
module.exports = gateContract.defineParser({
  name:       "stream-args",
  entry:      validate,
  errorClass: GuardStreamArgsError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    NAME: "streamArgs",
    KIND: "stream-args",
  },
});

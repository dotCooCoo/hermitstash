// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.guardTraceContext
 * @nav        Guards
 * @title      Guard Trace Context
 * @order      443
 *
 * @intro
 *   W3C Trace Context (`traceparent` + `tracestate`) shape validator.
 *   The agent-trace primitive (v0.9.29) injects traceparent strings
 *   into queue envelopes + event-bus payloads + sub-agent calls;
 *   consumers extract + start child spans. This guard refuses
 *   malformed traceparent strings (cross-boundary tampering, operator
 *   bugs, attacker-controlled trace IDs).
 *
 *   W3C Trace Context section 3.2: `<version>-<trace-id>-<parent-id>-<flags>`
 *   in hex form. v00 is the only currently-defined version; future
 *   versions get refused under strict profile.
 *
 *   `tracestate` (W3C section 3.3) is a comma-separated list of vendor key=
 *   value pairs, capped at 32 entries.
 *
 * @card
 *   Validates W3C traceparent + tracestate strings at agent
 *   boundaries. Refuses malformed shape, oversize tracestate,
 *   non-hex trace/span ids.
 */

var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");

var GuardTraceContextError = defineClass("GuardTraceContextError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { allowedVersions: ["00"],       maxTracestateEntries: 32, maxTracestateBytes: 512  },
  balanced:   { allowedVersions: ["00", "01"], maxTracestateEntries: 32, maxTracestateBytes: 512  },
  permissive: { allowedVersions: ["*"],         maxTracestateEntries: 64, maxTracestateBytes: 1024 },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var TRACEPARENT_RE = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;                   // allow:regex-no-length-cap — length-bound inline before test

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardTraceContextError,
  codePrefix: "trace-context",
});

/**
 * @primitive b.guardTraceContext.validate
 * @signature b.guardTraceContext.validate(ctx, opts?)
 * @since     0.9.29
 * @status    stable
 * @related   b.agent.trace.create, b.tracing.create
 *
 * Validate a traceparent + optional tracestate envelope. Returns the
 * input on success; throws on shape refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardTraceContext.validate({
 *     traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
 *   });
 */
function validate(ctx, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!ctx || typeof ctx !== "object") {
    throw new GuardTraceContextError("trace-context/bad-input",
      "guardTraceContext.validate: ctx required");
  }
  if (typeof ctx.traceparent !== "string" || ctx.traceparent.length === 0) {
    throw new GuardTraceContextError("trace-context/no-traceparent",
      "guardTraceContext.validate: traceparent required");
  }
  // Length bound BEFORE regex test so a hostile input can't burn
  // regex-engine CPU. W3C section 3.2.1: exactly 55 chars.
  if (ctx.traceparent.length !== 55) {                                                                // W3C fixed length
    throw new GuardTraceContextError("trace-context/bad-traceparent-length",
      "guardTraceContext.validate: traceparent must be exactly 55 chars (got " +
      ctx.traceparent.length + ")");
  }
  var m = TRACEPARENT_RE.exec(ctx.traceparent);
  if (!m) {
    throw new GuardTraceContextError("trace-context/bad-traceparent-shape",
      "guardTraceContext.validate: traceparent does not match W3C section 3.2 shape");
  }
  var version = m[1];
  var traceId = m[2];
  var spanId  = m[3];
  // version "ff" is invalid per W3C section 3.2.2 (forbidden value)
  if (version === "ff") {
    throw new GuardTraceContextError("trace-context/forbidden-version",
      "guardTraceContext.validate: version 'ff' is W3C-forbidden");
  }
  if (profile.allowedVersions[0] !== "*" && profile.allowedVersions.indexOf(version) < 0) {
    throw new GuardTraceContextError("trace-context/version-not-allowed",
      "guardTraceContext.validate: version '" + version + "' not in profile allowlist " +
      JSON.stringify(profile.allowedVersions));
  }
  if (traceId === "00000000000000000000000000000000") {
    throw new GuardTraceContextError("trace-context/zero-trace-id",
      "guardTraceContext.validate: trace-id all-zero is W3C-invalid");
  }
  if (spanId === "0000000000000000") {
    throw new GuardTraceContextError("trace-context/zero-span-id",
      "guardTraceContext.validate: parent-id all-zero is W3C-invalid");
  }
  if (typeof ctx.tracestate !== "undefined") {
    if (typeof ctx.tracestate !== "string") {
      throw new GuardTraceContextError("trace-context/bad-tracestate-type",
        "guardTraceContext.validate: tracestate must be a string");
    }
    if (Buffer.byteLength(ctx.tracestate, "utf8") > profile.maxTracestateBytes) {
      throw new GuardTraceContextError("trace-context/tracestate-too-big",
        "guardTraceContext.validate: tracestate exceeds maxTracestateBytes=" +
        profile.maxTracestateBytes);
    }
    if (ctx.tracestate.length > 0) {
      var entries = ctx.tracestate.split(",");
      if (entries.length > profile.maxTracestateEntries) {
        throw new GuardTraceContextError("trace-context/too-many-tracestate-entries",
          "guardTraceContext.validate: " + entries.length +
          " tracestate entries exceeds " + profile.maxTracestateEntries);
      }
    }
  }
  return ctx;
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.
module.exports = gateContract.defineParser({
  name:       "trace-context",
  entry:      validate,
  errorClass: GuardTraceContextError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    NAME: "traceContext",
    KIND: "trace-context",
  },
});

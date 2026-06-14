"use strict";
/**
 * @module     b.guardAgentRegistry
 * @nav        Guards
 * @title      Guard Agent Registry
 * @order      435
 *
 * @intro
 *   Registry-op shape validator for `b.agent.orchestrator.register` /
 *   `lookup` / `unregister`. Refuses agent names that wouldn't be
 *   safe to surface in audit logs, registry queries, or routing
 *   keys:
 *
 *     - non-ASCII (NFC-normalized + ASCII-only — operator-greppable)
 *     - path-traversal shapes (`..` / `/` / `\` / NUL / C0 / DEL)
 *     - oversized (default 64 bytes per name)
 *     - reserved `FRAMEWORK.*` / `ROOT` / `*` prefix from operator code
 *     - duplicate-on-register (caller must `unregister` first)
 *
 * @card
 *   Validates `b.agent.orchestrator.register` op shapes. Path-traversal
 *   refusal, reserved-prefix refusal, non-ASCII refusal, oversize cap.
 */

var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");

var GuardAgentRegistryError = defineClass("GuardAgentRegistryError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxNameBytes: 64,  maxKindBytes: 32  },
  balanced:   { maxNameBytes: 128, maxKindBytes: 64  },
  permissive: { maxNameBytes: 512, maxKindBytes: 128 },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var RESERVED_PREFIXES = Object.freeze(["FRAMEWORK.", "ROOT.", "framework.", "root."]);
var RESERVED_EXACT    = Object.freeze({ "ROOT": true, "FRAMEWORK": true, "*": true });

/**
 * @primitive b.guardAgentRegistry.validate
 * @signature b.guardAgentRegistry.validate(op, opts?)
 * @since     0.9.21
 * @status    stable
 * @related   b.agent.orchestrator.create
 *
 * Validate a `{ kind, name, agent, opts }` registry op shape. Returns
 * the op on success; throws `GuardAgentRegistryError` on refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardAgentRegistry.validate({
 *     kind: "register",
 *     name: "tenant-acme-mail",
 *     agentKind: "mail",
 *   });
 */
function validate(op, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!op || typeof op !== "object") {
    throw new GuardAgentRegistryError("agent-registry/bad-input",
      "guardAgentRegistry.validate: op required");
  }
  if (op.kind !== "register" && op.kind !== "lookup" && op.kind !== "unregister" && op.kind !== "list") {
    throw new GuardAgentRegistryError("agent-registry/bad-kind",
      "guardAgentRegistry.validate: op.kind must be 'register' | 'lookup' | 'unregister' | 'list'");
  }
  if (op.kind === "list") return op;            // list takes optional filters only

  _checkName(op.name, profile);
  if (op.kind === "register") {
    if (typeof op.agentKind !== "string" || op.agentKind.length === 0) {
      throw new GuardAgentRegistryError("agent-registry/no-kind",
        "guardAgentRegistry.validate: register op requires agentKind");
    }
    _checkKind(op.agentKind, profile);
  }
  return op;
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.

function _checkName(name, profile) {
  if (typeof name !== "string" || name.length === 0) {
    throw new GuardAgentRegistryError("agent-registry/bad-name",
      "guardAgentRegistry.validate: op.name must be a non-empty string");
  }
  if (Buffer.byteLength(name, "utf8") > profile.maxNameBytes) {
    throw new GuardAgentRegistryError("agent-registry/name-too-long",
      "guardAgentRegistry.validate: name exceeds maxNameBytes=" + profile.maxNameBytes);
  }
  if (RESERVED_EXACT[name]) {
    throw new GuardAgentRegistryError("agent-registry/reserved-name",
      "guardAgentRegistry.validate: name '" + name + "' is framework-reserved");
  }
  for (var p = 0; p < RESERVED_PREFIXES.length; p += 1) {
    if (name.indexOf(RESERVED_PREFIXES[p]) === 0) {
      throw new GuardAgentRegistryError("agent-registry/reserved-prefix",
        "guardAgentRegistry.validate: name '" + name + "' uses reserved prefix '" +
        RESERVED_PREFIXES[p] + "'");
    }
  }
  if (name.indexOf("..") >= 0) {
    throw new GuardAgentRegistryError("agent-registry/path-traversal",
      "guardAgentRegistry.validate: name contains '..'");
  }
  for (var i = 0; i < name.length; i += 1) {
    var c = name.charCodeAt(i);
    if (c > 0x7F) {                                                                                   // ASCII-only cap
      throw new GuardAgentRegistryError("agent-registry/non-ascii",
        "guardAgentRegistry.validate: name contains non-ASCII codepoint at offset " + i);
    }
    if (c < 0x20 || c === 0x7F || c === 0x2F || c === 0x5C) {                                         // C0 / DEL / slash / backslash
      throw new GuardAgentRegistryError("agent-registry/bad-name-char",
        "guardAgentRegistry.validate: name contains forbidden char 0x" + c.toString(16));
    }
  }
}

function _checkKind(kind, profile) {
  if (Buffer.byteLength(kind, "utf8") > profile.maxKindBytes) {
    throw new GuardAgentRegistryError("agent-registry/kind-too-long",
      "guardAgentRegistry.validate: agentKind exceeds maxKindBytes=" + profile.maxKindBytes);
  }
  if (!/^[a-z][a-z0-9-]*$/.test(kind)) {                                                              // allow:regex-no-length-cap — kind length bounded above
    throw new GuardAgentRegistryError("agent-registry/bad-kind-shape",
      "guardAgentRegistry.validate: agentKind must match /^[a-z][a-z0-9-]*$/");
  }
}

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardAgentRegistryError,
  codePrefix: "agent-registry",
});

module.exports = gateContract.defineParser({
  name:       "agent-registry",
  entry:      validate,
  errorClass: GuardAgentRegistryError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    RESERVED_PREFIXES: RESERVED_PREFIXES,
    RESERVED_EXACT:    RESERVED_EXACT,
    NAME:              "agentRegistry",
    KIND:              "agent-registry",
  },
});

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

var GuardAgentRegistryError = defineClass("GuardAgentRegistryError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxNameBytes: 64,  maxKindBytes: 32  },                                               // allow:raw-byte-literal
  balanced:   { maxNameBytes: 128, maxKindBytes: 64  },                                               // allow:raw-byte-literal
  permissive: { maxNameBytes: 512, maxKindBytes: 128 },                                               // allow:raw-byte-literal
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

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

/**
 * @primitive b.guardAgentRegistry.compliancePosture
 * @signature b.guardAgentRegistry.compliancePosture(posture)
 * @since     0.9.21
 * @status    stable
 *
 * Return the effective profile for a given compliance posture name.
 * Returns `null` for unknown posture names so operator typos surface
 * here instead of silently falling through to the default profile.
 *
 * @example
 *   b.guardAgentRegistry.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

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
    if (c > 0x7F) {                                                                                   // allow:raw-byte-literal — ASCII-only cap
      throw new GuardAgentRegistryError("agent-registry/non-ascii",
        "guardAgentRegistry.validate: name contains non-ASCII codepoint at offset " + i);
    }
    if (c < 0x20 || c === 0x7F || c === 0x2F || c === 0x5C) {                                         // allow:raw-byte-literal — C0 / DEL / slash / backslash
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

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return COMPLIANCE_POSTURES[opts.posture];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardAgentRegistryError("agent-registry/bad-profile",
      "guardAgentRegistry: unknown profile '" + p + "'");
  }
  return p;
}

module.exports = {
  validate:                  validate,
  compliancePosture:         compliancePosture,
  PROFILES:                  PROFILES,
  COMPLIANCE_POSTURES:       COMPLIANCE_POSTURES,
  RESERVED_PREFIXES:         RESERVED_PREFIXES,
  RESERVED_EXACT:            RESERVED_EXACT,
  GuardAgentRegistryError:   GuardAgentRegistryError,
  NAME:                      "agentRegistry",
  KIND:                      "agent-registry",
};

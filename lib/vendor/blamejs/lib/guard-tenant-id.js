"use strict";
/**
 * @module     b.guardTenantId
 * @nav        Guards
 * @title      Guard Tenant Id
 * @order      440
 *
 * @intro
 *   Tenant-id shape validator. Tenant ids surface in audit log lines,
 *   sealed registry rows, derived-key context labels, and routing
 *   keys — they have to be ASCII-greppable across the whole framework
 *   stack. Refuses:
 *
 *     - non-ASCII (NFC + ASCII-only)
 *     - path-traversal shapes (`..` / `/` / `\` / NUL / C0 / DEL)
 *     - oversized (default 64 bytes)
 *     - reserved `ROOT` / `FRAMEWORK` / `*` / empty
 *     - leading `.` (hidden-folder shape)
 *
 * @card
 *   Validates tenant-id strings. ASCII-only, bounded, no path-
 *   traversal, no reserved names.
 */

var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");

var GuardTenantIdError = defineClass("GuardTenantIdError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxBytes: 64  },
  balanced:   { maxBytes: 128 },
  permissive: { maxBytes: 512 },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var RESERVED = Object.freeze({ "ROOT": true, "FRAMEWORK": true, "*": true });

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardTenantIdError,
  codePrefix: "tenant-id",
});

/**
 * @primitive b.guardTenantId.validate
 * @signature b.guardTenantId.validate(tenantId, opts?)
 * @since     0.9.26
 * @status    stable
 * @related   b.agent.tenant.create
 *
 * Validate a tenant-id string. Returns the id on success; throws
 * `GuardTenantIdError` on refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardTenantId.validate("acme-clinic");
 */
function validate(tenantId, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (typeof tenantId !== "string" || tenantId.length === 0) {
    throw new GuardTenantIdError("tenant-id/bad-input",
      "guardTenantId.validate: tenantId must be a non-empty string");
  }
  if (Buffer.byteLength(tenantId, "utf8") > profile.maxBytes) {
    throw new GuardTenantIdError("tenant-id/oversize",
      "guardTenantId.validate: tenantId exceeds maxBytes=" + profile.maxBytes);
  }
  if (RESERVED[tenantId]) {
    throw new GuardTenantIdError("tenant-id/reserved",
      "guardTenantId.validate: tenantId '" + tenantId + "' is framework-reserved");
  }
  if (tenantId.charAt(0) === ".") {
    throw new GuardTenantIdError("tenant-id/hidden",
      "guardTenantId.validate: tenantId cannot start with '.'");
  }
  if (tenantId.indexOf("..") >= 0) {
    throw new GuardTenantIdError("tenant-id/path-traversal",
      "guardTenantId.validate: tenantId contains '..'");
  }
  for (var i = 0; i < tenantId.length; i += 1) {
    var c = tenantId.charCodeAt(i);
    if (c > 0x7F) {                                                                                   // ASCII-only cap
      throw new GuardTenantIdError("tenant-id/non-ascii",
        "guardTenantId.validate: non-ASCII codepoint at offset " + i);
    }
    if (c < 0x20 || c === 0x7F || c === 0x2F || c === 0x5C) {                                         // C0/DEL/slash/backslash
      throw new GuardTenantIdError("tenant-id/bad-char",
        "guardTenantId.validate: forbidden char 0x" + c.toString(16) + " at offset " + i);
    }
  }
  return tenantId;
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.
module.exports = gateContract.defineParser({
  name:       "tenant-id",
  entry:      validate,
  errorClass: GuardTenantIdError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    RESERVED: RESERVED,
    NAME:     "tenantId",
    KIND:     "tenant-id",
  },
});

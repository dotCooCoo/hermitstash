"use strict";
/**
 * @module     b.guardIdempotencyKey
 * @nav        Guards
 * @title      Guard Idempotency Key
 * @order      436
 *
 * @intro
 *   Operator-supplied idempotency key shape validator. Refuses keys
 *   that wouldn't be safe to surface in audit logs, persist in the
 *   sealed dbStore, or replay across processes:
 *
 *     - oversized (default 256 bytes — operators sometimes pass full
 *       JMAP request envelopes as keys; 256 is plenty for any
 *       reasonable correlation id without blowing storage)
 *     - control chars (C0 / NUL / DEL — defends audit-log injection
 *       when the key is rendered in a log message)
 *     - non-ASCII (NFC-normalized + ASCII-only; operator-greppable
 *       in audit logs across stack boundaries)
 *     - path-traversal shapes (`..` / `/` / `\` — defends operators
 *       who route idempotency keys through a filesystem-shaped path)
 *
 *   Permissive profile opts down the non-ASCII refusal for operators
 *   with legacy systems that include Unicode tenant IDs in keys.
 *
 * @card
 *   Validates operator-supplied `args.idempotencyKey` strings. Bounded
 *   length, control-char refusal, path-traversal refusal, ASCII-only
 *   under strict.
 */

var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");

var GuardIdempotencyKeyError = defineClass("GuardIdempotencyKeyError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxBytes: 256,  asciiOnly: true  },
  balanced:   { maxBytes: 512,  asciiOnly: true  },
  permissive: { maxBytes: 2048, asciiOnly: false },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

/**
 * @primitive b.guardIdempotencyKey.validate
 * @signature b.guardIdempotencyKey.validate(value, opts?)
 * @since     0.9.22
 * @status    stable
 * @related   b.agent.idempotency.create
 *
 * Validate an operator-supplied idempotency key. Returns the input
 * on success; throws `GuardIdempotencyKeyError` on refusal.
 *
 * @opts
 *   profile:    "strict" | "balanced" | "permissive",   // default "strict"
 *   posture:    "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   maxBytes:   number,                                  // per-profile default
 *
 * @example
 *   b.guardIdempotencyKey.validate("jmap-req-abc-123");
 */
function validate(value, opts) {
  opts = opts || {};
  var profileName = _resolveProfile(opts);
  var profile = PROFILES[profileName];
  var maxBytes = typeof opts.maxBytes === "number" ? opts.maxBytes : profile.maxBytes;

  if (typeof value !== "string") {
    throw new GuardIdempotencyKeyError("idempotency-key/bad-input",
      "guardIdempotencyKey.validate: value must be a string (got " + typeof value + ")");
  }
  if (value.length === 0) {
    throw new GuardIdempotencyKeyError("idempotency-key/empty",
      "guardIdempotencyKey.validate: empty key refused");
  }
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new GuardIdempotencyKeyError("idempotency-key/oversize",
      "guardIdempotencyKey.validate: " + Buffer.byteLength(value, "utf8") +
      " bytes exceeds maxBytes=" + maxBytes);
  }
  // Path-traversal refusal — defends operators routing keys through
  // filesystem paths.
  if (value.indexOf("..") >= 0) {
    throw new GuardIdempotencyKeyError("idempotency-key/path-traversal",
      "guardIdempotencyKey.validate: key contains '..'");
  }
  // C0 / DEL / slash refusal.
  for (var i = 0; i < value.length; i += 1) {
    var c = value.charCodeAt(i);
    if (c < 0x20 || c === 0x7F) {                                                                     // C0 + DEL refusal
      throw new GuardIdempotencyKeyError("idempotency-key/control-char",
        "guardIdempotencyKey.validate: control char 0x" + c.toString(16) + " at offset " + i);
    }
    if (c === 0x2F || c === 0x5C) {                                                                   // / and \ refusal
      throw new GuardIdempotencyKeyError("idempotency-key/slash",
        "guardIdempotencyKey.validate: key contains '/' or '\\' at offset " + i);
    }
    if (profile.asciiOnly && c > 0x7F) {                                                              // ASCII-only cap
      throw new GuardIdempotencyKeyError("idempotency-key/non-ascii",
        "guardIdempotencyKey.validate: non-ASCII codepoint at offset " + i +
        " (use profile='permissive' to allow)");
    }
  }
  return value;
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardIdempotencyKeyError,
  codePrefix: "idempotency-key",
});

module.exports = gateContract.defineParser({
  name:       "idempotency-key",
  entry:      validate,
  errorClass: GuardIdempotencyKeyError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    NAME: "idempotencyKey",
    KIND: "idempotency-key",
  },
});

"use strict";
/**
 * @module     b.guardMailSieve
 * @nav        Guards
 * @title      Guard Mail Sieve
 * @order      434
 *
 * @intro
 *   Validator for `b.mail.agent.sieve.put` / `.activate`. The full
 *   Sieve parser + bytecode + runtime lands at v0.9.26 as
 *   `b.safeSieve`; this guard handles the agent-side actor + script-
 *   envelope checks that apply BEFORE parsing:
 *
 *     - actor-scope check — only the owner of a script (or
 *       `mailScope: "admin"`) may edit it
 *     - script-byte cap — refuses scripts larger than `maxScriptBytes`
 *       (default 65536 — same cap v0.9.26's `b.safeSieve` will use)
 *     - script-name shape — RFC 5804 §2.3 script names are bounded
 *       UTF-8; the guard enforces the byte cap (default 256) and
 *       refuses NUL / control / slash / path-traversal shapes
 *     - line-count cap — defends scripts that are technically under
 *       the byte cap but pathological (one-character lines)
 *
 *   When v0.9.26 ships, `b.safeSieve.validate(script)` will be
 *   invoked AFTER this guard — operators who want to bytecode-
 *   validate at agent.sieve.put time pass `requireParse: true` and
 *   the agent calls into v0.9.26's parser.
 *
 * @card
 *   Validates `b.mail.agent.sieve` operations. Actor-scope check,
 *   script-byte cap, name shape, line-count cap. Pre-parser checks
 *   only — full Sieve parse lands at v0.9.26 (`b.safeSieve`).
 */

var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");

var GuardMailSieveError = defineClass("GuardMailSieveError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxScriptBytes: 65536,   maxNameBytes: 256,  maxLines: 2000  },
  balanced:   { maxScriptBytes: 262144,  maxNameBytes: 256,  maxLines: 10000 },
  permissive: { maxScriptBytes: 1048576, maxNameBytes: 1024, maxLines: 50000 },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardMailSieveError,
  codePrefix: "mail-sieve",
});

/**
 * @primitive b.guardMailSieve.validate
 * @signature b.guardMailSieve.validate(op, opts?)
 * @since     0.9.20
 * @status    stable
 * @related   b.mail.agent.create
 *
 * Validate a sieve-management op shape. `op.kind` is one of `"put"` /
 * `"activate"` / `"delete"`; `op.actor` carries the actor; for `"put"`
 * the `op.name` and `op.script` are validated; for `"activate"` /
 * `"delete"` only `op.name` is required.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   ownedNames: Array<string>,    // names the actor owns (operator-supplied)
 *
 * @example
 *   b.guardMailSieve.validate({
 *     kind: "put",
 *     actor: { id: "u1", mailScope: "user" },
 *     name:  "my-filter",
 *     script: "require [\"fileinto\"];\nif address :is \"From\" \"x@x\" { fileinto \"Junk\"; }",
 *   }, { ownedNames: ["my-filter"] });
 */
function validate(op, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!op || typeof op !== "object") {
    throw new GuardMailSieveError("mail-sieve/bad-input",
      "guardMailSieve.validate: op required");
  }
  if (op.kind !== "put" && op.kind !== "activate" && op.kind !== "delete") {
    throw new GuardMailSieveError("mail-sieve/bad-kind",
      "guardMailSieve.validate: op.kind must be 'put' | 'activate' | 'delete'");
  }
  if (!op.actor || typeof op.actor !== "object" || typeof op.actor.id !== "string") {
    throw new GuardMailSieveError("mail-sieve/no-actor",
      "guardMailSieve.validate: op.actor with .id required");
  }
  _checkName(op.name, profile);

  if (op.kind === "put") {
    if (typeof op.script !== "string") {
      throw new GuardMailSieveError("mail-sieve/bad-script",
        "guardMailSieve.validate: op.script must be a string");
    }
    var bytes = Buffer.byteLength(op.script, "utf8");
    if (bytes === 0) {
      throw new GuardMailSieveError("mail-sieve/empty-script",
        "guardMailSieve.validate: script must be non-empty");
    }
    if (bytes > profile.maxScriptBytes) {
      throw new GuardMailSieveError("mail-sieve/script-too-big",
        "guardMailSieve.validate: script " + bytes + " bytes exceeds maxScriptBytes=" +
        profile.maxScriptBytes);
    }
    // Line-count cap (a one-byte-line bomb stays under maxScriptBytes
    // but blows up later parser stages; refuse here).
    var lineCount = 1;
    for (var i = 0; i < op.script.length; i += 1) {
      if (op.script.charCodeAt(i) === 0x0A) lineCount += 1;                                           // LF
    }
    if (lineCount > profile.maxLines) {
      throw new GuardMailSieveError("mail-sieve/too-many-lines",
        "guardMailSieve.validate: " + lineCount + " lines exceeds maxLines=" + profile.maxLines);
    }
    // Control-char refusal in script (NUL is always refused; other
    // C0 except CR/LF/TAB are refused too — Sieve scripts are
    // text-only per RFC 5228 §1.4).
    for (var j = 0; j < op.script.length; j += 1) {
      var c = op.script.charCodeAt(j);
      if (c === 0x00 || (c < 0x20 && c !== 0x09 && c !== 0x0A && c !== 0x0D) || c === 0x7F) {         // NUL / C0 except TAB/LF/CR / DEL refusal
        throw new GuardMailSieveError("mail-sieve/control-char-in-script",
          "guardMailSieve.validate: control char 0x" + c.toString(16) + " at offset " + j);
      }
    }
  }

  // Actor-scope check — non-admin actors may only edit / activate /
  // delete scripts whose name is in their owned-names list. Operator
  // supplies the list via opts.ownedNames (looked up from RBAC table).
  var isAdmin = op.actor.mailScope === "admin";
  if (!isAdmin) {
    var owned = Array.isArray(opts.ownedNames) ? opts.ownedNames : [];
    if (owned.indexOf(op.name) < 0) {
      throw new GuardMailSieveError("mail-sieve/not-owner",
        "guardMailSieve.validate: actor does not own script '" + op.name +
        "' (use mailScope:'admin' or supply opts.ownedNames)");
    }
  }
  return op;
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.

function _checkName(name, profile) {
  if (typeof name !== "string" || name.length === 0) {
    throw new GuardMailSieveError("mail-sieve/bad-name",
      "guardMailSieve.validate: op.name must be a non-empty string");
  }
  if (Buffer.byteLength(name, "utf8") > profile.maxNameBytes) {
    throw new GuardMailSieveError("mail-sieve/name-too-long",
      "guardMailSieve.validate: op.name exceeds maxNameBytes=" + profile.maxNameBytes);
  }
  if (name.indexOf("..") >= 0) {
    throw new GuardMailSieveError("mail-sieve/path-traversal",
      "guardMailSieve.validate: op.name contains '..'");
  }
  for (var i = 0; i < name.length; i += 1) {
    var c = name.charCodeAt(i);
    if (c < 0x20 || c === 0x7F || c === 0x2F || c === 0x5C) {                                         // C0 / DEL / slash / backslash refusal
      throw new GuardMailSieveError("mail-sieve/bad-name-char",
        "guardMailSieve.validate: op.name contains forbidden char 0x" + c.toString(16));
    }
  }
}

module.exports = gateContract.defineParser({
  name:       "mail-sieve",
  entry:      validate,
  errorClass: GuardMailSieveError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    NAME: "mailSieve",
    KIND: "mail-sieve",
  },
});

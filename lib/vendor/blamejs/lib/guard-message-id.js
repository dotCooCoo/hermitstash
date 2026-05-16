"use strict";
/**
 * @module     b.guardMessageId
 * @nav        Guards
 * @title      Guard Message-Id
 * @order      420
 *
 * @intro
 *   RFC 5322 §3.6.4 Message-Id validator. Gates Message-Id /
 *   In-Reply-To / References header values at the entry to
 *   `b.mailStore.appendMessage` (v0.9.19), `b.mail.server.mx` (v0.9.23),
 *   and the outbound submission path (v0.9.25).
 *
 *   Refuses:
 *
 *     - oversized (default 998-byte cap per RFC 5322 §2.1.1 line cap)
 *     - bare CR / LF / NUL / C0 control chars (header-injection
 *       defense — defends `From:` / `Bcc:` smuggling via folded
 *       Message-Id continuation)
 *     - DEL (0x7F) anywhere
 *     - unbracketed under `strict` profile (the wire form per RFC
 *       5322 §3.6.4 is `<unique-token@domain>` — operator with
 *       legacy mail can opt down to `balanced` to accept bare tokens)
 *     - empty value
 *     - bidi codepoints in the local-part / domain (RFC 5322 + EAI
 *       allow non-ASCII per RFC 6532 + RFC 5335 but bidi-marker
 *       codepoints are operator-unfriendly and refused outright)
 *
 *   Profile vocabulary follows the existing guard-family convention:
 *
 *     - `strict` (default) — bracketed `<token@domain>`, length cap,
 *       no control chars, no bidi
 *     - `balanced` — accepts unbracketed tokens (legacy mail compat)
 *     - `permissive` — minimal validation (NUL + CR/LF refused; rest
 *       passes); use only for forensic-only flows
 *
 *   Posture vocabulary:
 *
 *     - `hipaa` / `pci-dss` / `gdpr` / `soc2` — each pins the
 *       active profile to `strict` regardless of operator's profile
 *       opt; refuses to relax under regulated postures.
 *
 *   Composes the framework's existing guard-family pattern via
 *   `b.gateContract` (the same shape `b.guardEmail` / `b.guardCsv` /
 *   `b.guardArchive` use). Registers in `b.guardAll`'s
 *   `STANDALONE_GUARDS` map.
 *
 * @card
 *   RFC 5322 §3.6.4 Message-Id validator — bounded length, no CRLF/NUL/control chars, bracketed shape under strict profile. Gates header-injection at the mail-store / MX / submission entry points.
 */

var { defineClass } = require("./framework-error");

var GuardMessageIdError = defineClass("GuardMessageIdError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { requireBrackets: true,  maxBytes: 998 },                                          // allow:raw-byte-literal
  balanced:   { requireBrackets: false, maxBytes: 998 },                                          // allow:raw-byte-literal
  permissive: { requireBrackets: false, maxBytes: 4096 },                                         // allow:raw-byte-literal — permissive cap, not bytes-as-storage
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

// Bidi codepoints refused — same set the framework's address-bidi
// defense uses (RFC 5322 §3.6.4 doesn't speak EAI codepoints, but RTL
// codepoints in Message-Ids are operator-unfriendly + defend the
// CVE-2021-42574 RTLO class in mail header context).
var BIDI_RE = /[؜‎‏‪-‮⁦-⁩]/;

/**
 * @primitive b.guardMessageId.validate
 * @signature b.guardMessageId.validate(value, opts?)
 * @since     0.9.19
 * @status    stable
 * @related   b.guardMessageId.validateList, b.safeMime.parse, b.guardEmail
 *
 * Validate a Message-Id / In-Reply-To / References header value.
 * Returns the input value on success; throws `GuardMessageIdError`
 * on refusal.
 *
 * @opts
 *   profile:    "strict" | "balanced" | "permissive",     // default "strict"
 *   posture:    "hipaa" | "pci-dss" | "gdpr" | "soc2",    // pins profile to strict
 *   maxBytes:   number,                                    // per-profile default
 *
 * @example
 *   b.guardMessageId.validate("<abc@example.com>");
 *   // → "<abc@example.com>"
 *
 *   try { b.guardMessageId.validate("abc@example.com"); }
 *   catch (e) { e.code; }
 *   // → "message-id/unbracketed" (strict profile)
 */
function validate(value, opts) {
  opts = opts || {};
  var profileName = _resolveProfile(opts);
  var profile = PROFILES[profileName];
  var maxBytes = typeof opts.maxBytes === "number" ? opts.maxBytes : profile.maxBytes;

  if (typeof value !== "string") {
    throw new GuardMessageIdError("message-id/bad-input",
      "guardMessageId.validate: value must be a string (got " + typeof value + ")");
  }
  if (value.length === 0) {
    throw new GuardMessageIdError("message-id/empty",
      "guardMessageId.validate: empty Message-Id refused");
  }
  if (Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new GuardMessageIdError("message-id/oversize",
      "guardMessageId.validate: " + Buffer.byteLength(value, "utf8") +
      " bytes exceeds maxBytes=" + maxBytes + " (RFC 5322 §2.1.1)");
  }

  // C0 control chars + NUL + DEL — always refused at every profile
  // (defends mail-header-injection class — operator can't smuggle
  // CR/LF into a Message-Id to fold an attacker-chosen From: line).
  for (var i = 0; i < value.length; i += 1) {
    var c = value.charCodeAt(i);
    if (c < 0x20 || c === 0x7F) {                                                                 // allow:raw-byte-literal — C0 + DEL refusal
      throw new GuardMessageIdError("message-id/control-char",
        "guardMessageId.validate: control char 0x" + c.toString(16) + " at offset " + i);
    }
  }

  // Bidi codepoints — refused at strict + balanced; permissive lets
  // them through. Length-bounded by the maxBytes check above so a
  // hostile input can't burn regex-engine CPU; the bidi codepoint set
  // is tiny so the test is constant-time anyway.
  if (profileName !== "permissive" && BIDI_RE.test(value)) {                                       // allow:regex-no-length-cap — value length-bounded by Buffer.byteLength check above
    throw new GuardMessageIdError("message-id/bidi",
      "guardMessageId.validate: bidi codepoint refused (CVE-2021-42574 RTLO class in mail-header context)");
  }

  // Bracketed shape — required under strict.
  if (profile.requireBrackets) {
    if (value.charAt(0) !== "<" || value.charAt(value.length - 1) !== ">") {
      throw new GuardMessageIdError("message-id/unbracketed",
        "guardMessageId.validate: strict profile requires `<token@domain>` shape (RFC 5322 §3.6.4)");
    }
    var inner = value.slice(1, -1);
    var at = inner.indexOf("@");
    if (at <= 0 || at === inner.length - 1) {
      throw new GuardMessageIdError("message-id/no-at",
        "guardMessageId.validate: Message-Id must contain `@` between local-part and domain");
    }
    if (inner.indexOf("<") >= 0 || inner.indexOf(">") >= 0) {
      throw new GuardMessageIdError("message-id/nested-brackets",
        "guardMessageId.validate: nested angle brackets refused");
    }
  }

  return value;
}

/**
 * @primitive b.guardMessageId.validateList
 * @signature b.guardMessageId.validateList(value, opts?)
 * @since     0.9.19
 * @status    stable
 * @related   b.guardMessageId.validate
 *
 * Validate a Message-Id-list header value (References / In-Reply-To
 * may carry multiple ids separated by whitespace per RFC 5322 §3.6.4).
 * Returns the array of validated Message-Ids; throws on any single
 * refusal.
 *
 * @opts
 *   profile:        same as validate
 *   posture:        same as validate
 *   maxBytes:       per-id cap
 *   maxIds:         number,    // default 100 — References-chain cap
 *
 * @example
 *   b.guardMessageId.validateList("<a@x> <b@x> <c@x>");
 *   // → ["<a@x>", "<b@x>", "<c@x>"]
 */
function validateList(value, opts) {
  opts = opts || {};
  var maxIds = typeof opts.maxIds === "number" ? opts.maxIds : 100;                              // allow:raw-byte-literal — References-chain cap, not bytes
  if (typeof value !== "string") {
    throw new GuardMessageIdError("message-id/bad-input",
      "guardMessageId.validateList: value must be a string");
  }
  var ids = value.split(/\s+/).filter(function (s) { return s.length > 0; });
  if (ids.length > maxIds) {
    throw new GuardMessageIdError("message-id/chain-too-long",
      "guardMessageId.validateList: " + ids.length + " ids exceeds maxIds=" + maxIds);
  }
  for (var i = 0; i < ids.length; i += 1) {
    validate(ids[i], opts);
  }
  return ids;
}

/**
 * @primitive b.guardMessageId.compliancePosture
 * @signature b.guardMessageId.compliancePosture(posture)
 * @since     0.9.19
 * @status    stable
 *
 * Return the effective profile for a given compliance posture.
 * Composed by `b.compliance.set` to surface "what posture is active
 * for which guard" in audit rows.
 *
 * @example
 *   b.guardMessageId.compliancePosture("hipaa");      // → "strict"
 *   b.guardMessageId.compliancePosture("unknown");    // → null
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return COMPLIANCE_POSTURES[opts.posture];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardMessageIdError("message-id/bad-profile",
      "guardMessageId: unknown profile '" + p + "' (use strict / balanced / permissive)");
  }
  return p;
}

module.exports = {
  validate:           validate,
  validateList:       validateList,
  compliancePosture:  compliancePosture,
  PROFILES:           PROFILES,
  COMPLIANCE_POSTURES: COMPLIANCE_POSTURES,
  GuardMessageIdError: GuardMessageIdError,
  NAME:               "messageId",
  KIND:               "identifier",
};

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
var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");

var GuardMessageIdError = defineClass("GuardMessageIdError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { requireBrackets: true,  maxBytes: 998 },
  balanced:   { requireBrackets: false, maxBytes: 998 },
  permissive: { requireBrackets: false, maxBytes: 4096 },                                         // permissive cap, not bytes-as-storage
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

// Bidi codepoints refused — same set the framework's address-bidi
// defense uses (RFC 5322 §3.6.4 doesn't speak EAI codepoints, but RTL
// codepoints in Message-Ids are operator-unfriendly + defend the
// CVE-2021-42574 RTLO class in mail header context).
var BIDI_RE = /[؜‎‏‪-‮⁦-⁩]/;

// RFC 5322 §3.2.3 dot-atom-text — used at strict profile to validate
// the id-left and id-right shape inside the bracketed Message-Id.
// `atext` = ALPHA / DIGIT / "!#$%&'*+-/=?^_`{|}~"; `dot-atom-text` is
// 1*atext *("." 1*atext). Length-bounded by the maxBytes cap above so
// the regex CPU is amortised; pattern is single-pass linear.
var DOT_ATOM_TEXT_RE = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/;

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
  var _ctlOff = codepointClass.firstControlCharOffset(value, { forbidTab: true });               // C0 + DEL refusal
  if (_ctlOff !== -1) {
    throw new GuardMessageIdError("message-id/control-char",
      "guardMessageId.validate: control char 0x" + value.charCodeAt(_ctlOff).toString(16) + " at offset " + _ctlOff);
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
    // RFC 5322 §3.6.4: id-left and id-right MUST conform to
    // dot-atom-text shape (§3.2.3). A second `@` inside id-left or
    // id-right falls out of dot-atom-text and is refused here. The
    // last `@` is the local/domain separator — `lastIndexOf` rather
    // than `indexOf` handles `a@b@c` correctly: id-left would be
    // `a@b` which fails dot-atom-text on the `@` character.
    var atLast = inner.lastIndexOf("@");
    var idLeft = inner.slice(0, atLast);
    var idRight = inner.slice(atLast + 1);
    if (!DOT_ATOM_TEXT_RE.test(idLeft)) {                                                            // allow:regex-no-length-cap — idLeft length-bounded by maxBytes above
      throw new GuardMessageIdError("message-id/id-left-shape",
        "guardMessageId.validate: id-left '" + idLeft +
        "' not dot-atom-text shape (RFC 5322 §3.2.3 / §3.6.4)");
    }
    if (!DOT_ATOM_TEXT_RE.test(idRight)) {                                                           // allow:regex-no-length-cap — idRight length-bounded by maxBytes above
      throw new GuardMessageIdError("message-id/id-right-shape",
        "guardMessageId.validate: id-right '" + idRight +
        "' not dot-atom-text shape (RFC 5322 §3.2.3 / §3.6.4)");
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
  var maxIds = typeof opts.maxIds === "number" ? opts.maxIds : 100;                              // References-chain cap, not bytes
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

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardMessageIdError,
  codePrefix: "message-id",
});

module.exports = gateContract.defineParser({
  name:       "message-id",
  entry:      validate,
  errorClass: GuardMessageIdError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    validateList: validateList,
    NAME:         "messageId",
    KIND:         "identifier",
  },
});

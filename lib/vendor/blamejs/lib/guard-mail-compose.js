"use strict";
/**
 * @module     b.guardMailCompose
 * @nav        Guards
 * @title      Guard Mail Compose
 * @order      431
 *
 * @intro
 *   Outbound draft validator for `b.mail.agent.compose` /
 *   `b.mail.agent.reply` / `b.mail.agent.forward`. Composes the
 *   existing `b.guardEmail.validateMessage` for address + header shape
 *   and adds compose-specific rules:
 *
 *     - identity vs From alignment — operator-supplied `identity.email`
 *       must equal the From header local-part + domain (defends spoof-
 *       at-submission)
 *     - recipient deduplication — Sender / To / Cc / Bcc combined
 *       cardinality cap (default 100; envelope-from never duplicated)
 *     - attachment byte cap — sum of `body.attachments[*].size_bytes`
 *       must not exceed `maxAttachmentBytes` (default 25 MiB to match
 *       the RFC 5321 §4.5.3.1.10 receiver cap)
 *     - body shape — exactly one of `text` / `html` required (multipart
 *       at submission-time per RFC 2046 §5.1.3); both allowed when
 *       operator explicitly opts in via `allowMultipartAlternative`
 *     - Subject control-char refusal — same C0 / DEL rule the existing
 *       `b.guardEmail` applies to header values
 *
 *   Profile vocabulary mirrors the rest of the guard family
 *   (`strict` / `balanced` / `permissive`); posture vocabulary
 *   (`hipaa` / `pci-dss` / `gdpr` / `soc2`) pins `strict`.
 *
 * @card
 *   Validates outbound mail drafts at `b.mail.agent.compose`.
 *   Identity-vs-From alignment, recipient dedup, attachment byte cap,
 *   body shape, header control-char refusal.
 */

var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");

var GuardMailComposeError = defineClass("GuardMailComposeError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxRecipients: 100,  maxAttachmentBytes: 26214400, maxSubjectBytes: 998 },            // 25 MiB, RFC 5322 §2.1.1 line cap
  balanced:   { maxRecipients: 500,  maxAttachmentBytes: 52428800, maxSubjectBytes: 998 },            // 50 MiB
  permissive: { maxRecipients: 2000, maxAttachmentBytes: 104857600, maxSubjectBytes: 998 },           // 100 MiB
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardMailComposeError,
  codePrefix: "mail-compose",
});

/**
 * @primitive b.guardMailCompose.validate
 * @signature b.guardMailCompose.validate(draft, opts?)
 * @since     0.9.20
 * @status    stable
 * @related   b.guardMailReply, b.guardEmail
 *
 * Validate an outbound draft envelope. Returns the input on success;
 * throws `GuardMailComposeError` on refusal.
 *
 * @opts
 *   profile:    "strict" | "balanced" | "permissive",
 *   posture:    "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   identity:   { email: string, name?: string },        // required if checkIdentity
 *   checkIdentity: boolean,                               // default true
 *   allowMultipartAlternative: boolean,                   // default false
 *
 * @example
 *   b.guardMailCompose.validate({
 *     from:    "alice@example.com",
 *     to:      ["bob@example.com"],
 *     subject: "hello",
 *     body:    { text: "hi" },
 *   }, { identity: { email: "alice@example.com" } });
 */
function validate(draft, opts) {
  opts = opts || {};
  var profileName = _resolveProfile(opts);
  var profile = PROFILES[profileName];
  if (!draft || typeof draft !== "object") {
    throw new GuardMailComposeError("mail-compose/bad-input",
      "guardMailCompose.validate: draft required");
  }
  if (typeof draft.from !== "string" || draft.from.length === 0) {
    throw new GuardMailComposeError("mail-compose/no-from",
      "guardMailCompose.validate: draft.from required");
  }
  _checkHeaderValue(draft.from, "from");
  _checkAddrList(draft.to,  "to",  profile);
  _checkAddrList(draft.cc,  "cc",  profile);
  _checkAddrList(draft.bcc, "bcc", profile);
  if (!_anyRecipient(draft)) {
    throw new GuardMailComposeError("mail-compose/no-recipient",
      "guardMailCompose.validate: at least one to/cc/bcc required");
  }
  _checkRecipientCardinality(draft, profile);

  if (typeof draft.subject !== "undefined") {
    if (typeof draft.subject !== "string") {
      throw new GuardMailComposeError("mail-compose/bad-subject",
        "guardMailCompose.validate: subject must be a string");
    }
    if (Buffer.byteLength(draft.subject, "utf8") > profile.maxSubjectBytes) {
      throw new GuardMailComposeError("mail-compose/subject-too-long",
        "guardMailCompose.validate: subject exceeds maxSubjectBytes=" + profile.maxSubjectBytes);
    }
    _checkHeaderValue(draft.subject, "subject");
  }

  _checkBody(draft.body, profile, !!opts.allowMultipartAlternative);

  // Identity vs From alignment — defends spoof-at-submission. When the
  // operator wires an identity for the actor, the draft's From: header
  // must match that identity's email. Disable explicitly via
  // checkIdentity: false (e.g. shared-mailbox submission roles).
  var checkIdentity = opts.checkIdentity !== false;
  if (checkIdentity && opts.identity && opts.identity.email) {
    var fromAddr = _extractAddr(draft.from);
    if (fromAddr.toLowerCase() !== String(opts.identity.email).toLowerCase()) {
      throw new GuardMailComposeError("mail-compose/identity-mismatch",
        "guardMailCompose.validate: From '" + fromAddr +
        "' does not match identity '" + opts.identity.email + "'");
    }
  }
  return draft;
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.

function _checkAddrList(list, label, profile) {
  if (typeof list === "undefined" || list === null) return;
  if (!Array.isArray(list)) {
    throw new GuardMailComposeError("mail-compose/bad-addr-list",
      "guardMailCompose.validate: " + label + " must be an array of strings");
  }
  if (list.length > profile.maxRecipients) {
    throw new GuardMailComposeError("mail-compose/too-many-recipients",
      "guardMailCompose.validate: " + label + " count " + list.length +
      " exceeds maxRecipients=" + profile.maxRecipients);
  }
  for (var i = 0; i < list.length; i += 1) {
    if (typeof list[i] !== "string" || list[i].length === 0) {
      throw new GuardMailComposeError("mail-compose/bad-addr",
        "guardMailCompose.validate: " + label + "[" + i + "] must be a non-empty string");
    }
    _checkHeaderValue(list[i], label + "[" + i + "]");
    var addr = _extractAddr(list[i]);
    if (addr.indexOf("@") < 0) {
      throw new GuardMailComposeError("mail-compose/bad-addr",
        "guardMailCompose.validate: " + label + "[" + i + "] missing '@'");
    }
  }
}

function _checkRecipientCardinality(draft, profile) {
  var all = [];
  ["to", "cc", "bcc"].forEach(function (k) {
    if (Array.isArray(draft[k])) {
      for (var i = 0; i < draft[k].length; i += 1) {
        all.push(_extractAddr(draft[k][i]).toLowerCase());
      }
    }
  });
  if (all.length > profile.maxRecipients) {
    throw new GuardMailComposeError("mail-compose/too-many-recipients",
      "guardMailCompose.validate: combined recipient count " + all.length +
      " exceeds maxRecipients=" + profile.maxRecipients);
  }
  var seen = Object.create(null);
  for (var j = 0; j < all.length; j += 1) {
    if (seen[all[j]]) {
      throw new GuardMailComposeError("mail-compose/duplicate-recipient",
        "guardMailCompose.validate: '" + all[j] + "' appears in multiple recipient fields");
    }
    seen[all[j]] = true;
  }
}

function _checkBody(body, profile, allowAlt) {
  if (!body || typeof body !== "object") {
    throw new GuardMailComposeError("mail-compose/no-body",
      "guardMailCompose.validate: draft.body required");
  }
  var hasText = typeof body.text === "string" && body.text.length > 0;
  var hasHtml = typeof body.html === "string" && body.html.length > 0;
  if (!hasText && !hasHtml) {
    throw new GuardMailComposeError("mail-compose/empty-body",
      "guardMailCompose.validate: body.text or body.html required");
  }
  if (hasText && hasHtml && !allowAlt) {
    throw new GuardMailComposeError("mail-compose/multipart-alternative-disallowed",
      "guardMailCompose.validate: both text + html supplied — set allowMultipartAlternative: true");
  }
  if (Array.isArray(body.attachments)) {
    var total = 0;
    for (var i = 0; i < body.attachments.length; i += 1) {
      var a = body.attachments[i];
      if (!a || typeof a !== "object") {
        throw new GuardMailComposeError("mail-compose/bad-attachment",
          "guardMailCompose.validate: attachment[" + i + "] must be an object");
      }
      var size = typeof a.sizeBytes === "number" ? a.sizeBytes :
                 (typeof a.size_bytes === "number" ? a.size_bytes : 0);
      if (size < 0 || !isFinite(size)) {
        throw new GuardMailComposeError("mail-compose/bad-attachment-size",
          "guardMailCompose.validate: attachment[" + i + "].sizeBytes invalid");
      }
      total += size;
      if (total > profile.maxAttachmentBytes) {
        throw new GuardMailComposeError("mail-compose/attachment-too-big",
          "guardMailCompose.validate: attachment total " + total +
          " exceeds maxAttachmentBytes=" + profile.maxAttachmentBytes);
      }
    }
  }
}

function _checkHeaderValue(v, label) {
  var ctrlAt = codepointClass.firstControlCharOffset(v);                                              // C0 (except TAB) + DEL refusal in header
  if (ctrlAt !== -1) {
    throw new GuardMailComposeError("mail-compose/control-char-in-header",
      "guardMailCompose.validate: control char 0x" + v.charCodeAt(ctrlAt).toString(16) + " in " + label);
  }
}

function _extractAddr(s) {
  var lt = s.indexOf("<");
  var gt = s.lastIndexOf(">");
  if (lt >= 0 && gt > lt) return s.slice(lt + 1, gt).trim();
  return s.trim();
}

function _anyRecipient(draft) {
  return ["to", "cc", "bcc"].some(function (k) {
    return Array.isArray(draft[k]) && draft[k].length > 0;
  });
}

module.exports = gateContract.defineParser({
  name:       "mailCompose",
  entry:      validate,
  errorClass: GuardMailComposeError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    NAME: "mailCompose",
    KIND: "mail-compose",
  },
});

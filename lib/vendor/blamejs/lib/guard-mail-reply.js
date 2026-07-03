// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.guardMailReply
 * @nav        Guards
 * @title      Guard Mail Reply
 * @order      432
 *
 * @intro
 *   Reply-thread shape validator for `b.mail.agent.reply` /
 *   `b.mail.agent.forward`. Composes `b.guardMessageId` (v0.9.19) for
 *   each Message-Id in the chain and adds reply-specific rules:
 *
 *     - References-chain cap — `maxChainLength` (default 100) defends
 *       infinite-loop forwards and References-bomb DoS
 *     - In-Reply-To continuity — when both `inReplyTo` and `references`
 *       are supplied, the last element of References must match
 *       In-Reply-To (RFC 5322 §3.6.4)
 *     - Quoted-original byte cap — when `quotedOriginal` is set, the
 *       byte cap defends pathological reply-of-reply chains that grow
 *       linearly with each hop
 *     - Forwarded-attachment cardinality — forwards may include the
 *       original's attachments by reference; cap at `maxForwardedAttachments`
 *       (default 32) to prevent attachment-bomb forwards
 *
 * @card
 *   Validates reply / forward shape. References-chain cap (defends
 *   infinite-loop forwards), In-Reply-To continuity (RFC 5322 §3.6.4),
 *   quoted-original byte cap.
 */

var { defineClass } = require("./framework-error");
var guardMessageId = require("./guard-message-id");
var gateContract = require("./gate-contract");

var GuardMailReplyError = defineClass("GuardMailReplyError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxChainLength: 100,  maxQuotedBytes: 524288,   maxForwardedAttachments: 32 },        // chain count + 512 KiB
  balanced:   { maxChainLength: 500,  maxQuotedBytes: 2097152,  maxForwardedAttachments: 128 },       // chain count + 2 MiB
  permissive: { maxChainLength: 2000, maxQuotedBytes: 10485760, maxForwardedAttachments: 512 },       // chain count + 10 MiB
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardMailReplyError,
  codePrefix: "mail-reply",
});

/**
 * @primitive b.guardMailReply.validate
 * @signature b.guardMailReply.validate(reply, opts?)
 * @since     0.9.20
 * @status    stable
 * @related   b.guardMessageId, b.guardMailCompose
 *
 * Validate a reply / forward envelope. `reply.inReplyTo` is the
 * Message-Id of the parent; `reply.references` is the chain (oldest
 * first); `reply.quotedOriginal` is the optional included original
 * body (already redacted by the caller — guard validates byte cap
 * only, not content).
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardMailReply.validate({
 *     inReplyTo:  "<a@x>",
 *     references: ["<root@x>", "<a@x>"],
 *   });
 */
function validate(reply, opts) {
  opts = opts || {};
  var profile = PROFILES[_resolveProfile(opts)];
  if (!reply || typeof reply !== "object") {
    throw new GuardMailReplyError("mail-reply/bad-input",
      "guardMailReply.validate: reply required");
  }
  if (typeof reply.inReplyTo !== "string" || reply.inReplyTo.length === 0) {
    throw new GuardMailReplyError("mail-reply/no-in-reply-to",
      "guardMailReply.validate: inReplyTo required");
  }
  guardMessageId.validate(reply.inReplyTo, { profile: "strict" });

  if (typeof reply.references !== "undefined") {
    if (!Array.isArray(reply.references)) {
      throw new GuardMailReplyError("mail-reply/bad-references",
        "guardMailReply.validate: references must be an array");
    }
    if (reply.references.length > profile.maxChainLength) {
      throw new GuardMailReplyError("mail-reply/chain-too-long",
        "guardMailReply.validate: chain length " + reply.references.length +
        " exceeds maxChainLength=" + profile.maxChainLength);
    }
    for (var i = 0; i < reply.references.length; i += 1) {
      guardMessageId.validate(reply.references[i], { profile: "strict" });
    }
    if (reply.references.length > 0) {
      var last = reply.references[reply.references.length - 1];
      if (last !== reply.inReplyTo) {
        throw new GuardMailReplyError("mail-reply/discontinuity",
          "guardMailReply.validate: last References '" + last +
          "' does not match inReplyTo '" + reply.inReplyTo + "' (RFC 5322 §3.6.4)");
      }
    }
  }

  if (typeof reply.quotedOriginal !== "undefined") {
    if (typeof reply.quotedOriginal !== "string") {
      throw new GuardMailReplyError("mail-reply/bad-quoted",
        "guardMailReply.validate: quotedOriginal must be a string");
    }
    if (Buffer.byteLength(reply.quotedOriginal, "utf8") > profile.maxQuotedBytes) {
      throw new GuardMailReplyError("mail-reply/quoted-too-big",
        "guardMailReply.validate: quotedOriginal exceeds maxQuotedBytes=" + profile.maxQuotedBytes);
    }
  }

  if (typeof reply.forwardedAttachments !== "undefined") {
    if (!Array.isArray(reply.forwardedAttachments)) {
      throw new GuardMailReplyError("mail-reply/bad-fwd-attach",
        "guardMailReply.validate: forwardedAttachments must be an array");
    }
    if (reply.forwardedAttachments.length > profile.maxForwardedAttachments) {
      throw new GuardMailReplyError("mail-reply/too-many-fwd-attach",
        "guardMailReply.validate: forwarded attachment count " +
        reply.forwardedAttachments.length + " exceeds " + profile.maxForwardedAttachments);
    }
  }
  return reply;
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.

module.exports = gateContract.defineParser({
  name:       "mail-reply",
  entry:      validate,
  errorClass: GuardMailReplyError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    NAME: "mailReply",
    KIND: "mail-reply",
  },
});

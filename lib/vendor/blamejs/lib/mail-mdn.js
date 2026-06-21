"use strict";
/**
 * @module b.mailMdn
 * @nav    Communication
 * @title  MDN
 *
 * @intro
 *   RFC 3798 / RFC 8098 Message Disposition Notification builder +
 *   parser. An MDN is the "I read your message" return-receipt — a
 *   multipart/report MIME body with a `message/disposition-notification`
 *   segment that names what the user-agent did with the original
 *   message (displayed / deleted / dispatched / processed / failed).
 *
 *   Auto-generation discipline: the framework refuses to auto-build an
 *   MDN unless the operator explicitly opts in via
 *   `requireUserConfirmation: false`. RFC 3798 §2.1 plus RFC 8098
 *   require user opt-in for MDN delivery — accidental automatic
 *   generation leaks behavioural metadata and is a known privacy
 *   regression in mail clients. The framework defaults to refusal so
 *   the operator codepath has to actively choose to send.
 *
 *   Parser tolerates both bare RFC 3798 reports and the RFC 8098
 *   updated shape (action / sending / disposition modes), surfaces
 *   the original-message-id binding, the reporting user-agent string,
 *   and the optional original-message attachment.
 *
 * @card
 *   RFC 3798 / RFC 8098 Message Disposition Notification builder + parser — generate "message read" return-receipts and parse inbound MDNs into a normalized event shape. Auto-generation refuses without explicit operator opt-in to prevent accidental privacy leaks.
 */

var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var mimeParse = require("./mime-parse");
var structuredFields = require("./structured-fields");
var audit = lazyRequire(function () { return require("./audit"); });
var C = require("./constants");
var validateOpts = require("./validate-opts");
var { MailMdnError } = require("./framework-error");

// Body cap for the MDN parser — same rationale as the DSN cap. RFC
// 3798 doesn't specify a maximum, but real-world MDNs are tiny;
// anything above 1 MiB is pathological and will pin the regex
// scanner if accepted.
var MDN_MAX_BYTES = C.BYTES.mib(1);

// RFC 3798 §3.2.6 disposition-types.
var DISPOSITION_TYPES = {
  "displayed":  true,
  "deleted":    true,
  "dispatched": true,
  "processed":  true,
  "failed":     true,
  "denied":     true,
};

// RFC 3798 §3.2.6.1 action-modes.
var ACTION_MODES = {
  "manual-action":    true,
  "automatic-action": true,
};

// RFC 3798 §3.2.6.2 sending-modes.
var SENDING_MODES = {
  "mdn-sent-manually":    true,
  "mdn-sent-automatically": true,
};

function _err(code, message) {
  return new MailMdnError(code, message);
}

function _parseDisposition(value) {
  // RFC 3798 §3.2.6 — `disposition-mode; disposition-type/<modifier>`
  // examples:
  //   manual-action/MDN-sent-manually; displayed
  //   automatic-action/MDN-sent-automatically; processed/error
  if (typeof value !== "string") return null;
  var semi = value.indexOf(";");
  if (semi === -1) {
    return {
      actionMode:  null,
      sendingMode: null,
      type:        value.trim().toLowerCase(),
    };
  }
  var modePart = value.slice(0, semi).trim();
  var typePart = value.slice(semi + 1).trim();
  var mkv = structuredFields.parseKeyValuePiece(modePart, "/");
  var actionMode = mkv.key;
  var sendingMode = mkv.value === null ? null : mkv.value.trim().toLowerCase();
  var type = typePart.toLowerCase();
  // Strip /modifier off the type token.
  var typeSlash = type.indexOf("/");
  if (typeSlash !== -1) type = type.slice(0, typeSlash).trim();
  return {
    actionMode:  actionMode,
    sendingMode: sendingMode,
    type:        type,
  };
}

function _generateBoundary() {
  return "blamejs-mdn-" + bCrypto.generateToken(C.BYTES.bytes(12));
}

/**
 * @primitive b.mailMdn.build
 * @signature b.mailMdn.build(opts)
 * @since     0.8.53
 * @status    stable
 * @related   b.mailMdn.parse, b.mailBounce.parse
 *
 * Build an RFC 3798 / RFC 8098 multipart/report message body carrying
 * a `message/disposition-notification` segment. The result is a raw
 * RFC 5322 message body ready for SMTP relay back to the sender.
 *
 * The framework refuses to auto-generate an MDN (emits the audit row
 * `mailmdn.suppressed` instead) when:
 *
 *   - The original message's `Disposition-Notification-Options`
 *     header asserted `important=required` AND
 *   - `opts.requireUserConfirmation` is not explicitly `false`
 *
 * RFC 3798 §2.1 requires user opt-in for MDN delivery; the default is
 * refusal so accidental automatic generation by an unattended mail
 * processor cannot leak behavioural metadata. Operators with an
 * explicit "the user clicked send-receipt" code path pass
 * `requireUserConfirmation: false` to skip the gate.
 *
 * @opts
 *   originalMessageId:        string,         // required — Message-Id of the message being acknowledged
 *   originalRecipient:        string,         // optional — RFC 5322 address of the original recipient
 *   finalRecipient:           string,         // required — RFC 5322 address of the final-recipient (may differ after forwarding)
 *   disposition:              "displayed" | "deleted" | "dispatched" | "processed" | "failed" | "denied",
 *   actionMode:               "manual-action" | "automatic-action",   // default: manual-action
 *   sendingMode:              "MDN-sent-manually" | "MDN-sent-automatically", // default: MDN-sent-manually
 *   reportingUserAgent:       string,         // optional — RFC 3798 §3.2.1 reporting agent name/version
 *   originalMessage:          string,         // optional — raw RFC 5322 message body to attach as message/rfc822
 *   from:                     string,         // optional — From: header for the MDN envelope
 *   to:                       string,         // optional — To: header for the MDN envelope (typically the original sender)
 *   subject:                  string,         // optional — Subject: header
 *   dispositionNotificationOptions: string,   // RFC 3798 Disposition-Notification-Options value from the inbound message
 *   requireUserConfirmation:  boolean,        // default: true — refuse to auto-build unless the operator explicitly opts out
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var mdn = b.mailMdn.build({
 *     originalMessageId:       "<orig-1@sender.example>",
 *     finalRecipient:          "user@example.com",
 *     disposition:             "displayed",
 *     reportingUserAgent:      "blamejs/0.8.53",
 *     requireUserConfirmation: false,
 *   });
 *   typeof mdn;                                            // -> "string"
 *   /multipart\/report/.test(mdn);                         // -> true
 *   /message\/disposition-notification/.test(mdn);         // -> true
 */
function build(opts) {
  validateOpts.requireObject(opts, "mailMdn.build", MailMdnError, "mdn/missing-required-field");
  validateOpts.requireNonEmptyString(opts.originalMessageId,
    "mailMdn.build: opts.originalMessageId", MailMdnError, "mdn/missing-required-field");
  validateOpts.requireNonEmptyString(opts.finalRecipient,
    "mailMdn.build: opts.finalRecipient", MailMdnError, "mdn/missing-required-field");
  var disposition = String(opts.disposition || "").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(DISPOSITION_TYPES, disposition)) {
    throw _err("mdn/missing-required-field",
      "mailMdn.build: opts.disposition must be one of " +
      Object.keys(DISPOSITION_TYPES).join(" / ") +
      "; got '" + String(opts.disposition) + "'");
  }
  var actionMode = String(opts.actionMode || "manual-action").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(ACTION_MODES, actionMode)) {
    throw _err("mdn/missing-required-field",
      "mailMdn.build: opts.actionMode must be one of " +
      Object.keys(ACTION_MODES).join(" / ") +
      "; got '" + String(opts.actionMode) + "'");
  }
  var sendingMode = String(opts.sendingMode || "mdn-sent-manually").toLowerCase();
  // Accept the canonical mixed-case form too — RFC 3798 §3.2.6.2 uses
  // `MDN-sent-manually` / `MDN-sent-automatically`. Compare lower-case
  // for robustness; emit canonical mixed-case in the output.
  if (!Object.prototype.hasOwnProperty.call(SENDING_MODES, sendingMode)) {
    throw _err("mdn/missing-required-field",
      "mailMdn.build: opts.sendingMode must be one of " +
      "MDN-sent-manually / MDN-sent-automatically; got '" +
      String(opts.sendingMode) + "'");
  }

  // Auto-generation gate. RFC 3798 §2.1 — when the inbound message's
  // Disposition-Notification-Options header asserts important=required,
  // an auto-processor must not emit an MDN without explicit user
  // confirmation. The framework defaults to requiring opt-in
  // (requireUserConfirmation defaults to true) so accidental
  // automatic generation is a typed refusal.
  var requireConfirmation = opts.requireUserConfirmation !== false;
  var dnOpts = String(opts.dispositionNotificationOptions || "").toLowerCase();
  var requestRequiresConfirmation = /important\s*=\s*required/.test(dnOpts);
  if (requestRequiresConfirmation && requireConfirmation) {
    audit().safeEmit({
      action:   "mailmdn.suppressed",
      outcome:  "denied",
      metadata: {
        originalMessageId: opts.originalMessageId,
        finalRecipient:    opts.finalRecipient,
        reason:            "auto-generation refused: Disposition-Notification-Options demands user confirmation",
      },
    });
    throw _err("mdn/auto-generation-refused",
      "mailMdn.build: inbound Disposition-Notification-Options asserts important=required " +
      "and opts.requireUserConfirmation is not explicitly false (RFC 3798 §2.1)");
  }

  var boundary = _generateBoundary();
  var recipType = mimeParse.addressType(opts.finalRecipient);
  var origRecipType = opts.originalRecipient ? mimeParse.addressType(opts.originalRecipient) : recipType;

  // Canonical sendingMode casing for the output (RFC 3798 §3.2.6.2).
  var sendingModeOut = sendingMode === "mdn-sent-automatically"
    ? "MDN-sent-automatically"
    : "MDN-sent-manually";

  var lines = [];
  lines.push("MIME-Version: 1.0");
  lines.push('Content-Type: multipart/report; report-type=disposition-notification; boundary="' + boundary + '"');
  if (opts.from)    lines.push("From: " + opts.from);
  if (opts.to)      lines.push("To: " + opts.to);
  if (opts.subject) lines.push("Subject: " + opts.subject);
  lines.push("");

  // Part 1 — human-readable description.
  lines.push("--" + boundary);
  lines.push("Content-Type: text/plain; charset=utf-8");
  lines.push("Content-Transfer-Encoding: 8bit");
  lines.push("");
  lines.push("This is a Message Disposition Notification.");
  lines.push("");
  lines.push("The message sent on " + new Date().toUTCString());
  lines.push("to " + opts.finalRecipient);
  lines.push("with subject of (none) was " + disposition + ".");
  lines.push("");

  // Part 2 — message/disposition-notification.
  lines.push("--" + boundary);
  lines.push("Content-Type: message/disposition-notification");
  lines.push("");
  if (opts.reportingUserAgent) {
    lines.push("Reporting-UA: " + opts.reportingUserAgent);
  }
  if (opts.originalRecipient) {
    lines.push("Original-Recipient: " + origRecipType + ";" + opts.originalRecipient);
  }
  lines.push("Final-Recipient: " + recipType + ";" + opts.finalRecipient);
  lines.push("Original-Message-ID: " + opts.originalMessageId);
  lines.push("Disposition: " + actionMode + "/" + sendingModeOut + "; " + disposition);
  lines.push("");

  // Part 3 (optional) — original message attached as message/rfc822.
  if (opts.originalMessage && typeof opts.originalMessage === "string") {
    lines.push("--" + boundary);
    lines.push("Content-Type: message/rfc822");
    lines.push("");
    lines.push(opts.originalMessage);
    lines.push("");
  }

  lines.push("--" + boundary + "--");
  lines.push("");

  audit().safeEmit({
    action:   "mailmdn.generated",
    outcome:  "success",
    metadata: {
      originalMessageId: opts.originalMessageId,
      finalRecipient:    opts.finalRecipient,
      disposition:       disposition,
      actionMode:        actionMode,
      sendingMode:       sendingModeOut,
    },
  });

  return lines.join("\r\n");
}

/**
 * @primitive b.mailMdn.parse
 * @signature b.mailMdn.parse(rawMessage)
 * @since     0.8.53
 * @status    stable
 * @related   b.mailMdn.build, b.mailBounce.parse
 *
 * Parse a raw RFC 3798 / RFC 8098 multipart/report message into a
 * normalized event shape:
 *
 *   {
 *     messageId:           string | null,   // outer Message-ID of the MDN itself
 *     originalMessageId:   string,          // Original-Message-ID field
 *     originalRecipient:   string | null,   // Original-Recipient field
 *     finalRecipient:      string,          // Final-Recipient field (required)
 *     disposition: {
 *       actionMode:        "manual-action" | "automatic-action",
 *       sendingMode:       "mdn-sent-manually" | "mdn-sent-automatically" | null,
 *       type:              "displayed" | "deleted" | "dispatched" | "processed" | "failed" | "denied",
 *     },
 *     reportingUserAgent:  string | null,
 *     originalMessage:     string | null,   // attached message/rfc822 body, when present
 *   }
 *
 * Throws `MailMdnError` on missing top-level Content-Type, non-
 * multipart/report content type, missing message/disposition-
 * notification segment, missing Final-Recipient, or oversized payload.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var mdn = b.mailMdn.build({
 *     originalMessageId:       "<orig-1@sender.example>",
 *     finalRecipient:          "user@example.com",
 *     disposition:             "displayed",
 *     reportingUserAgent:      "blamejs/0.8.53",
 *     requireUserConfirmation: false,
 *   });
 *   var parsed = b.mailMdn.parse(mdn);
 *   parsed.disposition.type;       // -> "displayed"
 *   parsed.finalRecipient;         // -> "user@example.com"
 *   parsed.originalMessageId;      // -> "<orig-1@sender.example>"
 */
function parse(rawMessage) {
  if (typeof rawMessage !== "string" || rawMessage.length === 0) {
    throw _err("mdn/parse-failed",
      "mailMdn.parse: rawMessage must be a non-empty string");
  }
  if (rawMessage.length > MDN_MAX_BYTES) {
    throw _err("mdn/parse-failed",
      "mailMdn.parse: message exceeds " + MDN_MAX_BYTES + " bytes");
  }

  var top = mimeParse.splitHeadersAndBody(rawMessage);
  var ctRaw = mimeParse.findHeader(top.headers, "Content-Type");
  if (!ctRaw) {
    throw _err("mdn/parse-failed",
      "mailMdn.parse: missing top-level Content-Type");
  }
  var ct = mimeParse.parseContentType(ctRaw);
  if (ct.type !== "multipart/report") {
    throw _err("mdn/parse-failed",
      "mailMdn.parse: top-level Content-Type must be multipart/report; got " + ct.type);
  }
  if (ct.params["report-type"] && ct.params["report-type"].toLowerCase() !== "disposition-notification") {
    throw _err("mdn/parse-failed",
      "mailMdn.parse: report-type must be disposition-notification; got " + ct.params["report-type"]);
  }
  var boundary = ct.params.boundary;
  if (!boundary) {
    throw _err("mdn/parse-failed",
      "mailMdn.parse: multipart/report missing boundary parameter");
  }

  var parts = mimeParse.splitMimeParts(top.body, boundary);
  if (parts.length < 2) {
    throw _err("mdn/parse-failed",
      "mailMdn.parse: multipart/report needs at least 2 parts; got " + parts.length);
  }

  var notification = null;
  var originalMessage = null;
  for (var i = 0; i < parts.length; i += 1) {
    var partSplit = mimeParse.splitHeadersAndBody(parts[i].replace(/^\r?\n/, ""));
    var partCtRaw = mimeParse.findHeader(partSplit.headers, "Content-Type") || "text/plain";
    var partCt = mimeParse.parseContentType(partCtRaw);
    if (partCt.type === "message/disposition-notification") {
      notification = mimeParse.parseHeaderBlock(partSplit.body);
    } else if (partCt.type === "message/rfc822" || partCt.type === "text/rfc822-headers") {
      originalMessage = partSplit.body;
    }
  }

  if (!notification) {
    throw _err("mdn/parse-failed",
      "mailMdn.parse: no message/disposition-notification part found");
  }

  // Index notification fields by lowercase name.
  var fields = {};
  for (var j = 0; j < notification.length; j += 1) {
    fields[notification[j].name.toLowerCase()] = notification[j].value;
  }

  var finalRecipient = mimeParse.stripAddressType(fields["final-recipient"]);
  if (!finalRecipient) {
    throw _err("mdn/missing-required-field",
      "mailMdn.parse: message/disposition-notification missing Final-Recipient");
  }
  var dispositionField = fields["disposition"];
  if (!dispositionField) {
    throw _err("mdn/missing-required-field",
      "mailMdn.parse: message/disposition-notification missing Disposition");
  }
  var disposition = _parseDisposition(dispositionField);
  // hasOwnProperty: the Disposition token comes from an untrusted inbound MDN, so
  // a bracket lookup lets "constructor"/"__proto__" pass as a valid type (proto
  // shadowing).
  if (!disposition || typeof disposition.type !== "string" ||
      !Object.prototype.hasOwnProperty.call(DISPOSITION_TYPES, disposition.type)) {
    throw _err("mdn/parse-failed",
      "mailMdn.parse: Disposition type token not in RFC 3798 §3.2.6 vocabulary; got '" +
      (disposition && disposition.type) + "'");
  }

  return {
    messageId:           mimeParse.findHeader(top.headers, "Message-ID"),
    originalMessageId:   fields["original-message-id"] || null,
    originalRecipient:   mimeParse.stripAddressType(fields["original-recipient"]),
    finalRecipient:      finalRecipient,
    disposition:         disposition,
    reportingUserAgent:  fields["reporting-ua"] || null,
    originalMessage:     originalMessage,
  };
}

module.exports = {
  build:         build,
  parse:         parse,
  MailMdnError:  MailMdnError,
  // Vocabulary tables surfaced for tests + advanced operator code
  // (e.g. operators wiring an inbound MDN router that switches on
  // disposition.type).
  DISPOSITION_TYPES: Object.keys(DISPOSITION_TYPES),
  ACTION_MODES:      Object.keys(ACTION_MODES),
  SENDING_MODES:     Object.keys(SENDING_MODES),
};

"use strict";
/**
 * @module     b.guardDsn
 * @nav        Guards
 * @title      Guard DSN
 * @order      460
 *
 * @intro
 *   RFC 3464 Delivery Status Notification parser. Reads the
 *   `multipart/report; report-type=delivery-status` structure that
 *   bounces, delayed-delivery notices, and successful-delivery
 *   confirmations carry and surfaces the per-recipient action +
 *   enhanced status code so operator-side delivery-failure routing
 *   (`b.mail.bounce` retry curve, address-book invalidation, mailing-
 *   list cleanup, transactional-mail dead-letter handling) reads a
 *   stable shape regardless of MTA wording.
 *
 *   ## RFC 3464 structure
 *
 *   `multipart/report` per RFC 6522 §3:
 *
 *     1. `text/plain` (or text/html) — human-readable wording
 *        ("Your message could not be delivered to alice@example.com");
 *        the framework does NOT route on this prose.
 *     2. **`message/delivery-status`** (RFC 3464 §2) — the
 *        machine-readable DSN body the framework parses.
 *     3. Optional `message/rfc822` (or `text/rfc822-headers`) —
 *        the original message (or its headers) that bounced.
 *
 *   ## Required fields the parser extracts
 *
 *   **Per-message fields (RFC 3464 §2.2)**:
 *     - `Reporting-MTA` — MTA that issued the DSN. Mandatory.
 *     - `Original-Envelope-Id` (optional) — DSN-tied envelope id.
 *     - `Arrival-Date` (optional) — when the original message
 *       arrived at the reporting MTA.
 *
 *   **Per-recipient fields (RFC 3464 §2.3)** — repeated, one block
 *   per recipient:
 *     - `Final-Recipient` — recipient address as the reporting MTA
 *       knows it. Mandatory.
 *     - `Action` — `failed` / `delayed` / `delivered` / `relayed` /
 *       `expanded`. Mandatory.
 *     - `Status` — RFC 3463 enhanced status code, format
 *       `D.D[D[D]].D[D[D]]` (e.g. `5.1.1` = bad address).
 *     - `Original-Recipient` (optional).
 *     - `Diagnostic-Code` (optional) — raw MTA error line.
 *
 *   ## RFC 3463 status-class semantics
 *
 *   The first digit classifies the verdict and drives the framework's
 *   downstream routing:
 *
 *     - **`2.x.y`** — success (delivered / relayed / expanded). Used
 *       by mailing-list `verp` tracking + delivery-receipt auditing.
 *     - **`4.x.y`** — persistent transient failure. Operator's
 *       `b.outbox` retry curve applies; address stays valid.
 *     - **`5.x.y`** — permanent failure. Address-book invalidation
 *       trigger; mailing-list cleanup; no further retries.
 *
 *   The framework surfaces `statusClass` (`success` / `temporary` /
 *   `permanent`) so operator routing reads one shape regardless of
 *   the exact subcode.
 *
 *   ## Defenses
 *
 *   - **Oversize DSN** — bounded body cap (default 256 KiB strict)
 *     per the profile; legitimate DSNs are KB-scale, multi-MB DSNs
 *     are pathological / DoS-shaped.
 *   - **Recipient-count cap** — per-DSN recipient cap (default 256
 *     strict). A DSN with thousands of recipients is forged or
 *     misconfigured; operator opts permissive for mailing-list
 *     blast-bounces.
 *   - **Header-line cap** — each field-line capped at 998 bytes
 *     per RFC 5322 §2.1.1.
 *   - **CRLF + control-char refusal** — header injection defense
 *     for fields that propagate to operator's audit log /
 *     monitoring dashboard.
 *
 *   ## CVE / threat model
 *
 *   - **Bounce-flood / backscatter** — operator's MX should refuse
 *     mail with envelope-from that doesn't pass SPF before
 *     generating a DSN (the existing `b.mail.bounce` primitive does
 *     this); this guard parses INBOUND DSNs and gates the parse
 *     surface bounds, not the bounce-generation policy.
 *   - **DSN header-injection class** (CVE-2026-32178 — .NET CWE-138
 *     special-element / header-injection spoofing, the System.Net.Mail
 *     vector per MSRC, at outbound; the inbound parse path here)
 *     — refuses CR/LF/NUL/C0 in header lines.
 *   - **CSAF / iSchedule prose tampering** — operator inspecting
 *     the prose part for the original recipient runs into the
 *     ambiguous wording that DSNs vary across MTAs (Postfix vs
 *     Exchange vs SES vs Gmail). The parser surfaces the
 *     STRUCTURED fields so operator routing doesn't have to
 *     regex MTA-specific prose.
 *
 * @card
 *   RFC 3464 DSN parser. Walks message/delivery-status per-message + per-recipient blocks, surfaces Action / Status / Final-Recipient + the RFC 3463 status-class verdict (success / temporary / permanent). Bounded recipient count + body size + header-line length; CRLF / NUL / C0 refusal. Operator delivery-failure routing reads one shape regardless of MTA wording.
 */

var C                  = require("./constants");
var { defineClass }    = require("./framework-error");

var GuardDsnError = defineClass("GuardDsnError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict:     { maxBytes: C.BYTES.kib(256), maxRecipients: 256, maxHeaderLine: 998 },                    // RFC 5322 §2.1.1 header line cap; RFC 3464 recipient count
  balanced:   { maxBytes: C.BYTES.mib(1),   maxRecipients: 1024, maxHeaderLine: 998 },                   // RFC 5322 §2.1.1 line cap; mailing-list blast bounces
  permissive: { maxBytes: C.BYTES.mib(4),   maxRecipients: 4096, maxHeaderLine: 998 },                   // RFC 5322 §2.1.1 line cap; large-blast bounce class
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

var KNOWN_ACTIONS = Object.freeze({
  failed:    true,
  delayed:   true,
  delivered: true,
  relayed:   true,
  expanded:  true,
});

// RFC 3463 §3.1: status code is digit . digit{1,3} . digit{1,3}.
var STATUS_RE = /^([245])\.(\d{1,3})\.(\d{1,3})$/;                                                       // allow:regex-no-length-cap — anchored + per-component repeat cap

/**
 * @primitive b.guardDsn.parse
 * @signature b.guardDsn.parse(deliveryStatusBody, opts?)
 * @since     0.9.37
 * @status    stable
 * @related   b.safeMime.parse, b.guardEnvelope.check
 *
 * Parse a `message/delivery-status` body (the MIME part body, not
 * the entire RFC 3464 multipart/report — extract that via
 * `b.safeMime.parse` first). Returns `{ perMessage, perRecipients,
 * worstStatusClass, action }`.
 *
 * Throws `GuardDsnError` on oversize body / recipient count /
 * header-line length / malformed status code / required-field
 * missing / control-char in field value.
 *
 * @opts
 *   profile:  "strict" | "balanced" | "permissive",
 *   posture:  "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var mime = b.safeMime.parse(rawBouncedMessage);
 *   var deliveryStatusPart = b.safeMime.findFirst(mime, function (p) {
 *     return p.leaf && p.leaf.contentType === "message/delivery-status";
 *   });
 *   var dsn = b.guardDsn.parse(deliveryStatusPart.leaf.body);
 *   if (dsn.worstStatusClass === "permanent") {
 *     dsn.perRecipients.forEach(function (r) { invalidateAddress(r.finalRecipient); });
 *   }
 */
function parse(deliveryStatusBody, opts) {
  opts = opts || {};
  var caps = _resolveProfile(opts);
  var bytes;
  if (Buffer.isBuffer(deliveryStatusBody)) {
    bytes = deliveryStatusBody;
  } else if (typeof deliveryStatusBody === "string") {
    bytes = Buffer.from(deliveryStatusBody, "utf8");
  } else {
    throw new GuardDsnError("guard-dsn/bad-input",
      "parse: deliveryStatusBody must be a Buffer or string");
  }
  if (bytes.length > caps.maxBytes) {
    throw new GuardDsnError("guard-dsn/oversize-body",
      "parse: body " + bytes.length + " bytes exceeds maxBytes=" + caps.maxBytes);
  }

  // RFC 3464 §2.1: the delivery-status body is per-message fields,
  // a blank line, then per-recipient field groups separated by
  // blank lines.
  var text = bytes.toString("utf8");
  var blocks = _splitBlocks(text);
  if (blocks.length === 0) {
    throw new GuardDsnError("guard-dsn/empty",
      "parse: delivery-status body has no field blocks");
  }
  var perMessageFields = _parseFieldBlock(blocks[0], caps.maxHeaderLine);

  // Reporting-MTA is mandatory per RFC 3464 §2.2.2.
  if (!perMessageFields["reporting-mta"]) {
    throw new GuardDsnError("guard-dsn/missing-reporting-mta",
      "parse: required per-message field Reporting-MTA missing (RFC 3464 §2.2.2)");
  }

  var perRecipients = [];
  for (var i = 1; i < blocks.length; i += 1) {
    if (perRecipients.length >= caps.maxRecipients) {
      throw new GuardDsnError("guard-dsn/too-many-recipients",
        "parse: per-recipient count exceeds maxRecipients=" + caps.maxRecipients);
    }
    var fields = _parseFieldBlock(blocks[i], caps.maxHeaderLine);
    if (Object.keys(fields).length === 0) continue;        // empty trailing block
    if (!fields["final-recipient"]) {
      throw new GuardDsnError("guard-dsn/missing-final-recipient",
        "parse: per-recipient block missing Final-Recipient (RFC 3464 §2.3.2)");
    }
    if (!fields["action"]) {
      throw new GuardDsnError("guard-dsn/missing-action",
        "parse: per-recipient block missing Action (RFC 3464 §2.3.3)");
    }
    var action = fields["action"].toLowerCase();
    if (!KNOWN_ACTIONS[action]) {
      throw new GuardDsnError("guard-dsn/bad-action",
        "parse: Action '" + action + "' not in RFC 3464 §2.3.3 vocabulary");
    }
    if (!fields["status"]) {
      throw new GuardDsnError("guard-dsn/missing-status",
        "parse: per-recipient block missing Status (RFC 3464 §2.3.4)");
    }
    var statusMatch = fields["status"].match(STATUS_RE);
    if (!statusMatch) {
      throw new GuardDsnError("guard-dsn/bad-status",
        "parse: Status '" + fields["status"] + "' not RFC 3463 D.D.D form");
    }
    perRecipients.push({
      finalRecipient:     _stripRecipientType(fields["final-recipient"]),
      originalRecipient:  fields["original-recipient"] ? _stripRecipientType(fields["original-recipient"]) : null,
      action:             action,
      status:             fields["status"],
      statusClass:        _statusClass(statusMatch[1]),
      diagnosticCode:     fields["diagnostic-code"] || null,
      remoteMta:          fields["remote-mta"] || null,
      lastAttemptDate:    fields["last-attempt-date"] || null,
    });
  }

  if (perRecipients.length === 0) {
    throw new GuardDsnError("guard-dsn/no-recipients",
      "parse: delivery-status has no per-recipient blocks (RFC 3464 §2.1 requires at least one)");
  }

  // Worst status class across recipients: permanent > temporary > success.
  var worst = "success";
  for (var r = 0; r < perRecipients.length; r += 1) {
    if (perRecipients[r].statusClass === "permanent") { worst = "permanent"; break; }
    if (perRecipients[r].statusClass === "temporary") worst = "temporary";
  }

  return {
    perMessage: {
      reportingMta:       perMessageFields["reporting-mta"],
      originalEnvelopeId: perMessageFields["original-envelope-id"] || null,
      arrivalDate:        perMessageFields["arrival-date"] || null,
      receivedFromMta:    perMessageFields["received-from-mta"] || null,
    },
    perRecipients:    perRecipients,
    worstStatusClass: worst,
    action:           worst === "permanent" ? "invalidate" :
                      worst === "temporary" ? "retry" :
                      "deliver",
  };
}

/**
 * @primitive b.guardDsn.compliancePosture
 * @signature b.guardDsn.compliancePosture(posture)
 * @since     0.9.37
 * @status    stable
 *
 * Return the effective profile name for a compliance posture, or
 * `null` for unknown posture names.
 *
 * @example
 *   b.guardDsn.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _splitBlocks(text) {
  // RFC 3464 §2.1.1: block separator is `CRLF CRLF` only — a "blank
  // line" in message-syntax terms. `\n\s*\n` admits `\v` / `\f` /
  // mixed whitespace which a hostile sender can use to bend the
  // block boundary (folded fields drift between per-message and
  // per-recipient blocks). Normalize CR(LF)? → LF, then split on
  // strict `\n\n` (an LF, an empty line, an LF) — anything else is
  // either intra-block CFWS or an intra-field continuation.
  var normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");                                    // allow:regex-no-length-cap — input length already capped
  return normalized.split("\n\n");
}

function _parseFieldBlock(block, maxHeaderLine) {
  // RFC 5322 §2.2: header field = name ":" value; continuation
  // lines start with whitespace.
  var lines = block.split("\n");
  var fields = Object.create(null);
  var current = null;
  for (var i = 0; i < lines.length; i += 1) {
    var raw = lines[i];
    if (raw.length > maxHeaderLine) {
      throw new GuardDsnError("guard-dsn/oversize-header-line",
        "parse: header line " + raw.length + " bytes exceeds maxHeaderLine=" + maxHeaderLine + " (RFC 5322 §2.1.1)");
    }
    if (raw.length === 0) continue;
    _checkControlChars(raw);
    if (/^[ \t]/.test(raw) && current) {                                                                 // allow:regex-no-length-cap — single-char check on capped line
      // Continuation.
      fields[current] += " " + raw.replace(/^[ \t]+/, "");                                               // allow:regex-no-length-cap — trim on capped line // allow:duplicate-regex — leading-WS-trim shape common to RFC 5322 header continuation parsers
      continue;
    }
    var colon = raw.indexOf(":");
    if (colon === -1) {
      throw new GuardDsnError("guard-dsn/malformed-field",
        "parse: line '" + raw + "' missing ':' field-name terminator");
    }
    var name = raw.slice(0, colon).trim().toLowerCase();
    var value = raw.slice(colon + 1).trim();
    if (name.length === 0) {
      throw new GuardDsnError("guard-dsn/malformed-field",
        "parse: empty field name on line '" + raw + "'");
    }
    fields[name] = value;
    current = name;
  }
  return fields;
}

function _checkControlChars(line) {
  // Refuse NUL, C0 controls (except TAB which is valid in
  // continuation), DEL. Bare CR and LF can't appear because we
  // already split on \n; this catches forms that survive the
  // split (e.g. backslash + literal sequence).
  for (var i = 0; i < line.length; i += 1) {
    var c = line.charCodeAt(i);
    if (c === 0x00 || c === 0x7f || (c < 0x20 && c !== 0x09)) {                                          // RFC 5322 control char + TAB allow
      throw new GuardDsnError("guard-dsn/control-char",
        "parse: control char 0x" + c.toString(16) + " in field line refused (header-injection defense)");
    }
  }
}

function _stripRecipientType(value) {
  // RFC 3464 §2.3.2: "rfc822;alice@example.com" — type prefix
  // before semicolon classifies the address. Strip for the common
  // case of rfc822, surface the raw value otherwise.
  var semi = value.indexOf(";");
  if (semi === -1) return value;
  var type = value.slice(0, semi).trim().toLowerCase();
  if (type === "rfc822") return value.slice(semi + 1).trim();
  return value;
}

function _statusClass(firstDigit) {
  if (firstDigit === "2") return "success";
  if (firstDigit === "4") return "temporary";
  if (firstDigit === "5") return "permanent";
  return "unknown";
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return PROFILES[COMPLIANCE_POSTURES[opts.posture]];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardDsnError("guard-dsn/bad-profile",
      "guardDsn: unknown profile '" + p + "'");
  }
  return PROFILES[p];
}

module.exports = {
  parse:                   parse,
  compliancePosture:       compliancePosture,
  PROFILES:                PROFILES,
  COMPLIANCE_POSTURES:     COMPLIANCE_POSTURES,
  KNOWN_ACTIONS:           KNOWN_ACTIONS,
  GuardDsnError:           GuardDsnError,
  NAME:                    "dsn",
  KIND:                    "delivery-status",
};

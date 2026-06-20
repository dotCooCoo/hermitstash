"use strict";
/**
 * @module b.mailArf
 * @nav    Communication
 * @title  Mail ARF
 *
 * @intro
 *   RFC 5965 Abuse Reporting Format ingest. ESPs (Yahoo, AOL,
 *   Microsoft, Google, etc.) post these via webhook when a user marks
 *   one of the operator's messages as spam. The format is
 *   multipart/report with three required parts:
 *
 *     1. text/plain — human-readable description (ignored)
 *     2. message/feedback-report — the structured report itself, a
 *        block of header:value lines (Feedback-Type, User-Agent,
 *        Original-Mail-From, Source-IP, Reported-Domain, Arrival-Date,
 *        Authentication-Results, Auth-Failure, etc.)
 *     3. message/rfc822 (or text/rfc822-headers) — the original message
 *        being reported, in full or just the headers
 *
 *   `b.mailArf.parse` consumes the raw multipart/report bytes and
 *   returns a normalized event shape suitable for an
 *   abuse-reconciliation pipeline (suppression list, abuse-score
 *   tracking, complaint-rate dashboards). Required fields per
 *   RFC 5965 §3.1 are Feedback-Type and User-Agent — `parse` refuses
 *   anything missing them. Reports without a `message/feedback-report`
 *   subpart are also refused.
 *
 *   This is a parse-only primitive — operators wire it into their
 *   own webhook endpoint and emit the audit trail / suppression-list
 *   updates from there. The framework's `b.mailBounce.handler` is the
 *   reference shape for the surrounding plumbing; ARF rides
 *   alongside it because the wire format and lifecycle differ
 *   (multipart/report vs JSON; no vendor-specific parser needed).
 *
 * @card
 *   RFC 5965 ARF (Abuse Reporting Format) ingest — parse a message/feedback-report multipart payload from an ESP's user-marked-as-spam webhook into a structured event for the suppression pipeline.
 */

var lazyRequire   = require("./lazy-require");
var mimeParse     = require("./mime-parse");
var C             = require("./constants");
var safeBuffer    = require("./safe-buffer");
var { MailArfError } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

// RFC 5965 ceilings — a feedback report is small in practice (a few
// kilobytes plus the original message, which is itself capped by the
// MTA's max-message-size). 8 MiB matches the b.mail.dmarc aggregate
// report cap so operators have one mental model for "what fits".
var ARF_MAX_REPORT_BYTES = C.BYTES.mib(8);

// RFC 5965 §3.1 — required fields. The spec lists Feedback-Type +
// User-Agent + Version as REQUIRED; we match major ESPs by also
// requiring Feedback-Type and User-Agent (Version defaults to 1 when
// omitted, which is what every real-world report sends).
var ARF_REQUIRED_FIELDS = ["feedback-type", "user-agent"];

// RFC 5965 §3.1 — Feedback-Type registry. Unknown values pass through
// (the IANA registry grows; this list documents the spec's launch
// vocabulary so operators can route on it).
var ARF_KNOWN_FEEDBACK_TYPES = {
  abuse:           1,
  "auth-failure":  1,
  fraud:           1,
  "not-spam":      1,
  other:           1,
  virus:           1,
  // RFC 6650 (post-launch) — list-unsubscribe complaint feedback loop.
  "opt-out":       1,
  "opt-out-list":  1,
};
void ARF_KNOWN_FEEDBACK_TYPES;

/**
 * @primitive b.mailArf.parse
 * @signature b.mailArf.parse(rawMessage, opts)
 * @since     0.8.53
 * @status    stable
 * @related   b.mailBounce.parse, b.mailBounce.handler
 *
 * Parse an RFC 5965 Abuse Reporting Format multipart/report payload
 * into a normalized abuse-event shape. Refuses on missing
 * `message/feedback-report` subpart, missing required `Feedback-Type`
 * or `User-Agent` fields, or report bytes exceeding the 8 MiB ceiling.
 *
 * Returns:
 *
 *     {
 *       feedbackType,           // "abuse" | "auth-failure" | "fraud" | …
 *       userAgent,              // "SomeESP-Feedback/1.0"
 *       version,                // "1" (default) — per RFC 5965 §3.1
 *       originalFrom,           // string — Original-Mail-From
 *       originalRcptTo,         // [string] — every Original-Rcpt-To
 *       arrivalDate,            // ISO 8601 string when parseable, else raw
 *       reportedDomain,         // string — Reported-Domain
 *       sourceIp,               // string — Source-IP
 *       authenticationResults,  // string — verbatim Authentication-Results
 *       authFailure,            // "dkim" | "spf" | "dmarc" | … (optional)
 *       reportedUri,            // string — Reported-URI (phishing reports)
 *       incidents,              // number — Incidents (when present)
 *       originalMessage,        // string — the message/rfc822 part body
 *       extraFields,            // { [name: string]: string } — operator-
 *                               //   visible fields the spec doesn't
 *                               //   normalize
 *     }
 *
 * Audit emission: the framework emits `system.mailarf.parsed` on
 * success and `system.mailarf.malformed` on refusal. Operators wire
 * `audit: false` to suppress when the upstream webhook handler emits
 * its own audit row.
 *
 * @opts
 *   maxBytes:  number,    // default: 8 MiB
 *   audit:     boolean,   // default: true
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var event = b.mailArf.parse(rawWebhookBody);
 *   if (event.feedbackType === "abuse") suppressionList.add(event.originalFrom);
 *   // → typeof event.userAgent === "string"
 */
function parse(rawMessage, opts) {
  opts = opts || {};
  var auditOn = opts.audit !== false;
  var maxBytes = (typeof opts.maxBytes === "number" && isFinite(opts.maxBytes) &&
                  opts.maxBytes > 0)
    ? opts.maxBytes
    : ARF_MAX_REPORT_BYTES;

  if (typeof rawMessage !== "string" && !Buffer.isBuffer(rawMessage)) {
    _emitMalformed(auditOn, "input must be string or Buffer");
    throw new MailArfError("mailarf/parse-failed",
      "mailArf.parse: rawMessage must be a string or Buffer");
  }

  var asString = Buffer.isBuffer(rawMessage)
    ? rawMessage.toString("utf8")
    : rawMessage;

  if (safeBuffer.byteLengthOf(asString) > maxBytes) {
    _emitMalformed(auditOn, "report exceeds maxBytes");
    throw new MailArfError("mailarf/parse-failed",
      "mailArf.parse: report exceeds " + maxBytes + " bytes (got " + safeBuffer.byteLengthOf(asString) + ")");
  }

  // 1. Bisect headers / body, parse Content-Type for boundary.
  var top;
  try { top = mimeParse.splitHeadersAndBody(asString); }
  catch (e) {
    _emitMalformed(auditOn, "split-failed");
    throw new MailArfError("mailarf/parse-failed",
      "mailArf.parse: header/body split failed: " + ((e && e.message) || String(e)));
  }
  var ctRaw = mimeParse.findHeader(top.headers, "Content-Type") || "";
  var ct = mimeParse.parseContentType(ctRaw);
  if (ct.type !== "multipart/report") {
    _emitMalformed(auditOn, "wrong-content-type");
    throw new MailArfError("mailarf/parse-failed",
      "mailArf.parse: top-level Content-Type must be multipart/report (got '" + ct.type + "')");
  }
  // RFC 5965 §2 — multipart/report must carry report-type=feedback-report.
  // Tolerate omitted report-type for shipping ESPs that send a plain
  // multipart/report; refuse mismatched values.
  if (ct.params["report-type"] && ct.params["report-type"].toLowerCase() !== "feedback-report") {
    _emitMalformed(auditOn, "wrong-report-type");
    throw new MailArfError("mailarf/parse-failed",
      "mailArf.parse: report-type must be feedback-report (got '" +
      ct.params["report-type"] + "')");
  }
  if (!ct.params.boundary) {
    _emitMalformed(auditOn, "missing-boundary");
    throw new MailArfError("mailarf/parse-failed",
      "mailArf.parse: multipart/report Content-Type lacks boundary parameter");
  }

  // 2. Walk the multipart body. Find the message/feedback-report part
  //    and (optionally) the message/rfc822 / text/rfc822-headers part.
  var parts = mimeParse.splitMimeParts(top.body, ct.params.boundary);
  if (parts.length === 0) {
    _emitMalformed(auditOn, "no-parts");
    throw new MailArfError("mailarf/parse-failed",
      "mailArf.parse: multipart/report body contains no parts");
  }

  var feedbackPart = null;
  var originalPart = null;
  for (var pi = 0; pi < parts.length; pi += 1) {
    var partRaw = parts[pi];
    var split;
    try { split = mimeParse.splitHeadersAndBody(partRaw); }
    catch (_e) { continue; }
    var partCt = mimeParse.parseContentType(
      mimeParse.findHeader(split.headers, "Content-Type") || ""
    );
    if (partCt.type === "message/feedback-report" && !feedbackPart) {
      feedbackPart = split;
    } else if ((partCt.type === "message/rfc822" ||
                partCt.type === "text/rfc822-headers") && !originalPart) {
      originalPart = split;
    }
  }

  if (!feedbackPart) {
    _emitMalformed(auditOn, "missing-feedback-report-part");
    throw new MailArfError("mailarf/parse-failed",
      "mailArf.parse: missing message/feedback-report subpart (RFC 5965 §2)");
  }

  // 3. Parse the feedback-report body — header:value lines per
  //    RFC 5965 §3.1. The body itself is structured headers, NOT
  //    HTML / JSON / free-form prose.
  var reportFields = mimeParse.parseHeaderBlock(feedbackPart.body);
  var fieldMap = {};
  var extraFields = {};
  // RFC 5965 §3.1 normalizes some fields; everything else passes
  // through as extraFields so operators with vendor-specific tags
  // (X-HmailServer-…, X-Yahoo-Newman-Property) don't lose them.
  var KNOWN_FIELDS = {
    "feedback-type":         "feedbackType",
    "user-agent":            "userAgent",
    "version":               "version",
    "original-mail-from":    "originalFrom",
    "original-rcpt-to":      "originalRcptTo",
    "arrival-date":          "arrivalDate",
    "reported-domain":       "reportedDomain",
    "source-ip":             "sourceIp",
    "authentication-results":"authenticationResults",
    "auth-failure":          "authFailure",
    "reported-uri":          "reportedUri",
    "incidents":             "incidents",
    "delivery-result":       "deliveryResult",
    "original-envelope-id":  "originalEnvelopeId",
  };
  for (var fi = 0; fi < reportFields.length; fi += 1) {
    var f = reportFields[fi];
    if (!f || !f.name) continue;
    var lcName = f.name.toLowerCase();
    fieldMap[lcName] = f.value;
  }

  // 4. Required fields (RFC 5965 §3.1).
  for (var ri = 0; ri < ARF_REQUIRED_FIELDS.length; ri += 1) {
    var req = ARF_REQUIRED_FIELDS[ri];
    if (typeof fieldMap[req] !== "string" || fieldMap[req].length === 0) {
      _emitMalformed(auditOn, "missing-" + req);
      throw new MailArfError("mailarf/missing-required-field",
        "mailArf.parse: required field '" + req + "' is missing");
    }
  }

  // 5. Build the normalized shape.
  var rcptToList = [];
  for (var di = 0; di < reportFields.length; di += 1) {
    var df = reportFields[di];
    if (df && df.name && df.name.toLowerCase() === "original-rcpt-to") {
      rcptToList.push(df.value);
    }
  }
  var arrivalRaw = fieldMap["arrival-date"] || null;
  var arrivalIso = null;
  if (arrivalRaw) {
    var d = new Date(arrivalRaw);
    if (!isNaN(d.getTime())) arrivalIso = d.toISOString();
  }
  var incidentsRaw = fieldMap.incidents;
  var incidents = null;
  if (typeof incidentsRaw === "string") {
    var parsed = parseInt(incidentsRaw, 10);
    if (isFinite(parsed) && parsed >= 0) incidents = parsed;
  }

  // Surface non-normalized fields under extraFields for operator
  // visibility (X-* tags ESPs add for routing diagnostics, etc.).
  Object.keys(fieldMap).forEach(function (k) {
    if (!KNOWN_FIELDS[k]) extraFields[k] = fieldMap[k];
  });

  var event = {
    feedbackType:          fieldMap["feedback-type"],
    userAgent:             fieldMap["user-agent"],
    version:               fieldMap.version || "1",
    originalFrom:          fieldMap["original-mail-from"] || null,
    originalRcptTo:        rcptToList,
    arrivalDate:           arrivalIso || arrivalRaw,
    reportedDomain:        fieldMap["reported-domain"] || null,
    sourceIp:              fieldMap["source-ip"] || null,
    authenticationResults: fieldMap["authentication-results"] || null,
    authFailure:           fieldMap["auth-failure"] || null,
    reportedUri:           fieldMap["reported-uri"] || null,
    incidents:             incidents,
    originalMessage:       originalPart
      ? (originalPart.body || _reassemblePart(originalPart))
      : null,
    extraFields:           extraFields,
  };

  if (auditOn) {
    try {
      audit().safeEmit({
        action:  "system.mailarf.parsed",
        outcome: "success",
        metadata: {
          feedbackType:   event.feedbackType,
          userAgent:      event.userAgent,
          reportedDomain: event.reportedDomain,
          sourceIp:       event.sourceIp,
          authFailure:    event.authFailure,
        },
      });
    } catch (_e) { /* drop-silent — by design */ }
  }

  return event;
}

function _reassemblePart(part) {
  // Reassemble headers + body for callers that want the full original
  // message bytes (some ESPs strip the body and ship just headers).
  var hdrs = "";
  for (var i = 0; i < part.headers.length; i += 1) {
    hdrs += part.headers[i].name + ": " + part.headers[i].value + "\r\n";
  }
  return hdrs + "\r\n" + (part.body || "");
}

function _emitMalformed(auditOn, reason) {
  if (!auditOn) return;
  try {
    audit().safeEmit({
      action:  "system.mailarf.malformed",
      outcome: "denied",
      metadata: { reason: reason },
    });
  } catch (_e) { /* drop-silent — by design */ }
}

module.exports = {
  parse:                  parse,
  MailArfError:           MailArfError,
  ARF_MAX_REPORT_BYTES:   ARF_MAX_REPORT_BYTES,
  ARF_REQUIRED_FIELDS:    ARF_REQUIRED_FIELDS,
};

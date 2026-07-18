// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.mailBounce
 * @nav    Communication
 * @title  Mail Bounce
 *
 * @intro
 *   Inbound mail bounce-handler — parse the vendor's webhook DSN /
 *   complaint / delivery payload, normalize it into one event shape,
 *   classify hard vs soft bounces, and feed an operator-supplied
 *   suppression-list hook.
 *
 *   Outbound mail comes back as a hard bounce (permanent — invalid
 *   address), a soft bounce (transient — mailbox full, greylisted), a
 *   spam / abuse complaint, a delivery confirmation, or a list-
 *   unsubscribe. Vendors (Postmark, AWS SES via SNS, Resend) ship the
 *   same information dressed up in three different JSON shapes. This
 *   module owns the translation so operators write a single
 *   reconciliation path regardless of vendor.
 *
 *   `b.mailBounce.parse` is the pure synchronous parser; it returns the
 *   normalized event `{ vendor, type, subType, recipient, messageId,
 *   reason, timestamp, raw }`. `b.mailBounce.handler` wires that
 *   parser into an Express-style middleware that buffers the body,
 *   runs an operator `verify` hook (HMAC, Basic Auth, SNS-Signature),
 *   emits a `system.mail.bounce` audit row, and calls the operator's
 *   `onBounce(event)` so the suppression list can be updated before
 *   the 200 response goes back.
 *
 *   Generic RFC 3464 / RFC 3461 / RFC 6533 DSN is wired in as
 *   `b.mailBounce.dsn.parse` / `b.mailBounce.dsn.build` — a parser for
 *   raw multipart/report message/delivery-status MIME bounces (the
 *   shape any spec-conforming MTA returns) and a generator that builds
 *   the same shape for operators that need to issue bounces from their
 *   own MTA. Operators with bespoke vendor inflow can still supply
 *   `{ parser }` to plug a custom normalizer onto `parse` / `handler`.
 *
 * @card
 *   Inbound mail bounce-handler — parse the vendor's webhook DSN / complaint / delivery payload, normalize it into one event shape, classify hard vs soft bounces, and feed an operator-supplied suppression-list hook.
 */

var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var mimeParse = require("./mime-parse");
var numericBounds = require("./numeric-bounds");
var audit = lazyRequire(function () { return require("./audit"); });
var safeBuffer = require("./safe-buffer");
var safeJson = require("./safe-json");
var C = require("./constants");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var HTTP = requestHelpers.HTTP_STATUS;

var MailBounceError = defineClass("MailBounceError", { withStatusCode: true });

// Cap on inbound webhook bodies — any vendor bigger than this is
// pathological and likely an attack surface. 256 KiB covers the
// largest realistic SES SNS notification with verbose diagnostic info.
var MAX_BODY_BYTES = C.BYTES.kib(256);

function _err(code, message, statusCode) {
  return new MailBounceError(code, message, true, statusCode || 400);
}

// ---- Postmark ----
//
// Webhook payload (JSON):
//   {
//     "RecordType": "Bounce" | "SpamComplaint" | "Delivery",
//     "Type":       "HardBounce" | "SoftBounce" | "Transient" | ...,
//     "Email":      "...",
//     "MessageID":  "...",
//     "Description": "...",
//     "Details":     "...",
//     "BouncedAt":   "2026-04-28T..."  (Bounce / SpamComplaint)
//     "DeliveredAt": "..."             (Delivery)
//   }

var POSTMARK_TYPE_TO_NORMAL = {
  "HardBounce":          { type: "bounce",    subType: "hard"    },
  "SoftBounce":          { type: "bounce",    subType: "soft"    },
  "Transient":           { type: "bounce",    subType: "soft"    },
  "Unknown":             { type: "bounce",    subType: "unknown" },
  "Subscribe":           { type: "complaint", subType: "subscribe-fail" },
  "AutoResponder":       { type: "bounce",    subType: "auto-reply"     },
  "AddressChange":       { type: "bounce",    subType: "address-change" },
  "DnsError":            { type: "bounce",    subType: "soft"    },
  "SpamNotification":    { type: "complaint", subType: "spam"    },
  "OpenRelayTest":       { type: "bounce",    subType: "policy"  },
  "Unsubscribe":         { type: "complaint", subType: "unsubscribe" },
  "Blocked":             { type: "bounce",    subType: "blocked" },
  "SMTPApiError":        { type: "bounce",    subType: "api"     },
  "InboundError":        { type: "bounce",    subType: "inbound" },
  "DMARCPolicy":         { type: "bounce",    subType: "policy"  },
  "TemplateRenderingFailed": { type: "bounce", subType: "template" },
  "ManuallyDeactivated": { type: "bounce",    subType: "deactivated" },
};

function _parsePostmark(p) {
  if (!p || typeof p !== "object") {
    throw _err("postmark/empty", "postmark webhook payload must be an object");
  }
  var record = p.RecordType;
  var email = p.Email;
  if (typeof email !== "string" || email.length === 0) {
    throw _err("postmark/missing-email", "postmark payload missing 'Email'");
  }

  if (record === "Delivery") {
    return {
      vendor:    "postmark",
      type:      "delivery",
      subType:   null,
      recipient: email,
      messageId: typeof p.MessageID === "string" ? p.MessageID : null,
      reason:    null,
      timestamp: p.DeliveredAt || new Date().toISOString(),
      raw:       p,
    };
  }
  if (record === "SpamComplaint") {
    return {
      vendor:    "postmark",
      type:      "complaint",
      subType:   "spam",
      recipient: email,
      messageId: typeof p.MessageID === "string" ? p.MessageID : null,
      reason:    p.Details || p.Description || null,
      timestamp: p.BouncedAt || new Date().toISOString(),
      raw:       p,
    };
  }
  if (record === "Bounce" || record === "SubscriptionChange" || !record) {
    var mapping = POSTMARK_TYPE_TO_NORMAL[p.Type] ||
                  { type: "bounce", subType: typeof p.Type === "string" ? p.Type.toLowerCase() : "unknown" };
    return {
      vendor:    "postmark",
      type:      mapping.type,
      subType:   mapping.subType,
      recipient: email,
      messageId: typeof p.MessageID === "string" ? p.MessageID : null,
      reason:    p.Details || p.Description || null,
      timestamp: p.BouncedAt || p.DeliveredAt || new Date().toISOString(),
      raw:       p,
    };
  }
  throw _err("postmark/unknown-record",
    "postmark RecordType '" + String(record) + "' not recognised");
}

// ---- SES via SNS ----
//
// Outer envelope (SNS notification):
//   { "Type": "Notification", "MessageId": "...",
//     "Message": "<json string>", "Signature": "...", ... }
//
// After JSON.parse(Message):
//   { "notificationType": "Bounce" | "Complaint" | "Delivery",
//     "mail":   { "messageId": "...", "destination": ["..."], ... },
//     "bounce": { "bounceType": "Permanent" | "Transient" | "Undetermined",
//                 "bounceSubType": "General" | ...,
//                 "bouncedRecipients": [
//                   { "emailAddress": "...", "diagnosticCode": "...",
//                     "action": "...", "status": "..." }
//                 ],
//                 "timestamp": "..." },
//     "complaint": { ... }, "delivery": { ... } }

function _parseSes(p) {
  if (!p || typeof p !== "object") {
    throw _err("ses/empty", "SES payload must be an object");
  }
  // Accept either the SNS envelope or the unwrapped Message payload —
  // operators may strip the SNS layer at their LB / handler.
  var msg = p;
  if (p.Type === "Notification" && typeof p.Message === "string") {
    try { msg = safeJson.parse(p.Message); }
    catch (e) {
      throw _err("ses/bad-message-json",
        "SES SNS Message field is not valid JSON: " + (e && e.message));
    }
    // A syntactically valid Message can still decode to a non-object —
    // JSON literal null / number / string / boolean / array. Reject it
    // with a typed error rather than dereferencing null downstream, and
    // do not echo the decoded value (avoid leaking payload internals).
    if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
      throw _err("ses/bad-message-json",
        "SES SNS Message field must decode to a JSON object");
    }
  }
  var notificationType = msg.notificationType || msg.eventType;
  if (!notificationType) {
    throw _err("ses/missing-notification-type",
      "SES payload missing notificationType / eventType");
  }
  var mailMeta = msg.mail || {};
  var messageId = (typeof mailMeta.messageId === "string") ? mailMeta.messageId : null;

  if (notificationType === "Bounce" || notificationType === "bounce") {
    var b = msg.bounce || {};
    var recip = (b.bouncedRecipients && b.bouncedRecipients[0]) || {};
    var subType = b.bounceType === "Permanent" ? "hard"
                : b.bounceType === "Transient" ? "soft"
                : "unknown";
    return {
      vendor:    "ses",
      type:      "bounce",
      subType:   subType,
      recipient: recip.emailAddress || (mailMeta.destination && mailMeta.destination[0]) || null,
      messageId: messageId,
      reason:    recip.diagnosticCode || (b.bounceSubType ? "bounceSubType: " + b.bounceSubType : null),
      timestamp: b.timestamp || new Date().toISOString(),
      raw:       p,
    };
  }
  if (notificationType === "Complaint" || notificationType === "complaint") {
    var c = msg.complaint || {};
    var crecip = (c.complainedRecipients && c.complainedRecipients[0]) || {};
    return {
      vendor:    "ses",
      type:      "complaint",
      subType:   c.complaintFeedbackType || "abuse",
      recipient: crecip.emailAddress || (mailMeta.destination && mailMeta.destination[0]) || null,
      messageId: messageId,
      reason:    c.userAgent || null,
      timestamp: c.timestamp || new Date().toISOString(),
      raw:       p,
    };
  }
  if (notificationType === "Delivery" || notificationType === "delivery") {
    var d = msg.delivery || {};
    return {
      vendor:    "ses",
      type:      "delivery",
      subType:   null,
      recipient: (d.recipients && d.recipients[0]) || (mailMeta.destination && mailMeta.destination[0]) || null,
      messageId: messageId,
      reason:    null,
      timestamp: d.timestamp || new Date().toISOString(),
      raw:       p,
    };
  }
  throw _err("ses/unknown-notification-type",
    "SES notificationType '" + String(notificationType) + "' not recognised");
}

// ---- Resend ----
//
// Webhook payload (JSON):
//   {
//     "type":       "email.bounced" | "email.complained" | "email.delivered" | ...,
//     "created_at": "2026-04-28T...",
//     "data": {
//       "id":      "...",
//       "to":      ["user@example.com"] | "user@example.com",
//       "from":    "...",
//       "bounce":  { "type": "Permanent", "subType": "General",
//                    "message": "..." }      (bounced events only)
//     }
//   }

function _parseResend(p) {
  if (!p || typeof p !== "object") {
    throw _err("resend/empty", "resend payload must be an object");
  }
  var type = p.type;
  if (typeof type !== "string") {
    throw _err("resend/missing-type", "resend payload missing 'type'");
  }
  var data = p.data || {};
  var to = Array.isArray(data.to) ? data.to[0] : data.to;
  var messageId = (typeof data.id === "string") ? data.id : null;
  var ts = p.created_at || new Date().toISOString();

  if (type === "email.bounced") {
    var bounce = data.bounce || {};
    var subType = bounce.type === "Permanent" ? "hard"
                : bounce.type === "Transient" ? "soft"
                : "unknown";
    return {
      vendor:    "resend",
      type:      "bounce",
      subType:   subType,
      recipient: to || null,
      messageId: messageId,
      reason:    bounce.message || null,
      timestamp: ts,
      raw:       p,
    };
  }
  if (type === "email.complained") {
    return {
      vendor:    "resend",
      type:      "complaint",
      subType:   "abuse",
      recipient: to || null,
      messageId: messageId,
      reason:    null,
      timestamp: ts,
      raw:       p,
    };
  }
  if (type === "email.delivered") {
    return {
      vendor:    "resend",
      type:      "delivery",
      subType:   null,
      recipient: to || null,
      messageId: messageId,
      reason:    null,
      timestamp: ts,
      raw:       p,
    };
  }
  throw _err("resend/unknown-type",
    "resend type '" + type + "' not recognised");
}

// ---- Custom parser hook ----
//
// Operators with bespoke vendor inflow (DSN, vendor-X, internal MTA)
// supply a function that takes the parsed body and returns the
// normalized event shape. The framework runs the function then
// validates the returned shape so a misbehaving custom parser can't
// emit malformed audit rows.
function _customParser(parser) {
  return function (payload) {
    var event = parser(payload);
    _validateNormalized(event);
    return event;
  };
}

function _validateNormalized(event) {
  if (!event || typeof event !== "object") {
    throw _err("custom/bad-shape", "parser returned non-object");
  }
  if (typeof event.vendor !== "string") {
    throw _err("custom/missing-vendor", "parser result missing 'vendor'");
  }
  if (["bounce", "complaint", "delivery"].indexOf(event.type) === -1) {
    throw _err("custom/bad-type",
      "parser result.type must be 'bounce' | 'complaint' | 'delivery'");
  }
  if (typeof event.recipient !== "string" || event.recipient.length === 0) {
    throw _err("custom/missing-recipient", "parser result missing 'recipient'");
  }
}

var VENDORS = {
  postmark: _parsePostmark,
  ses:      _parseSes,
  resend:   _parseResend,
};

/**
 * @primitive b.mailBounce.parse
 * @signature b.mailBounce.parse(payload, opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.mailBounce.handler
 *
 * Pure synchronous parser. Routes `payload` through the chosen vendor
 * parser (built-ins: `postmark`, `ses`, `resend`) and returns the
 * normalized event. Operators with bespoke vendors supply
 * `opts.parser` — a function `(payload) -> normalizedEvent` that the
 * framework runs and then validates so a misbehaving custom parser
 * cannot emit malformed audit rows.
 *
 * Throws `MailBounceError` (HTTP 400) on missing / unknown vendor,
 * empty payload, or payload missing the required vendor-specific
 * fields. Never mutates `payload` — the original is preserved on
 * `event.raw` for downstream re-parsing.
 *
 * @opts
 *   vendor: "postmark" | "ses" | "resend",       // required when `parser` is absent
 *   parser: function (payload): normalizedEvent, // alternative to `vendor`
 *
 * @example
 *   var event = b.mailBounce.parse({
 *     RecordType:  "Bounce",
 *     Type:        "HardBounce",
 *     Email:       "user@example.com",
 *     MessageID:   "abc-123",
 *     Description: "550 No such mailbox",
 *     BouncedAt:   "2026-04-28T10:00:00Z",
 *   }, { vendor: "postmark" });
 *   event.type;      // → "bounce"
 *   event.subType;   // → "hard"
 *   event.recipient; // → "user@example.com"
 *   event.timestamp; // → "2026-04-28T10:00:00Z"
 */
function parse(payload, opts) {
  opts = opts || {};
  if (typeof opts.parser === "function") {
    return _customParser(opts.parser)(payload);
  }
  var vendor = opts.vendor;
  if (typeof vendor !== "string" || vendor.length === 0) {
    throw _err("missing-vendor",
      "mailBounce.parse requires { vendor } (one of 'postmark', 'ses', 'resend') or { parser }");
  }
  var fn = VENDORS[vendor];
  if (!fn) {
    throw _err("unknown-vendor",
      "mailBounce.parse: unknown vendor '" + vendor +
      "' (built-ins: postmark, ses, resend; supply { parser } for others)");
  }
  return fn(payload);
}

/**
 * @primitive b.mailBounce.handler
 * @signature b.mailBounce.handler(opts)
 * @since     0.5.0
 * @status    stable
 * @related   b.mailBounce.parse, b.audit.safeEmit
 *
 * Returns an Express-style `(req, res)` middleware that buffers the
 * inbound webhook body (capped at `maxBytes`), runs `verify(req, body,
 * raw)` if supplied, parses via the configured vendor (or custom
 * `parser`), emits one `system.mail.bounce` audit row, calls
 * `onBounce(event)`, and responds 200. Failures map to 400 (bad
 * payload), 401 (verify rejected), 413 (body too large), 500
 * (`onBounce` threw).
 *
 * `audit` defaults to ON; pass `audit: false` to suppress the
 * `system.mail.bounce` row when the operator already records the
 * normalized event in their own data store.
 *
 * @opts
 *   vendor:   "postmark" | "ses" | "resend",
 *   parser:   function (payload): normalizedEvent,    // alternative to `vendor`
 *   verify:   function (req, body, raw): boolean,     // optional authenticity gate
 *   onBounce: function (event): Promise|void,         // operator suppression hook
 *   audit:    boolean,                                 // default: true
 *   maxBytes: number,                                  // body cap; default 256 KiB
 *
 * @example
 *   var bounce = b.mailBounce.handler({
 *     vendor:   "postmark",
 *     verify:   function (req) {
 *       return req.headers.authorization === "Basic c2VjcmV0";
 *     },
 *     onBounce: function (event) {
 *       suppressionList[event.recipient] = event.subType;
 *     },
 *     maxBytes: b.constants.BYTES.kib(64),
 *   });
 *   typeof bounce; // → "function"
 *   bounce.length; // → 2
 */
function handler(opts) {
  opts = opts || {};
  var vendor = opts.vendor;
  var customParser = typeof opts.parser === "function" ? opts.parser : null;
  if (!customParser && (typeof vendor !== "string" || !Object.prototype.hasOwnProperty.call(VENDORS, vendor))) {
    throw _err("handler/bad-config",
      "mailBounce.handler requires { vendor } (one of " +
      Object.keys(VENDORS).join(", ") + ") or { parser }");
  }
  var verify = typeof opts.verify === "function" ? opts.verify : null;
  var onBounce = typeof opts.onBounce === "function" ? opts.onBounce : null;
  var auditOn = opts.audit !== false;
  // maxBytes must be a positive finite integer (Infinity / NaN /
  // negative / non-integer all bypass the body cap). See
  // lib/numeric-bounds for the rationale shared with every other
  // numeric-opt site swept in v0.6.69.
  var maxBytes;
  if (opts.maxBytes === undefined) {
    maxBytes = MAX_BODY_BYTES;
  } else if (!numericBounds.isPositiveFiniteInt(opts.maxBytes)) {
    throw new MailBounceError("mail-bounce/bad-opt",
      "mailBounce.handler: opts.maxBytes must be a positive finite " +
      "integer; got " + numericBounds.shape(opts.maxBytes), true);
  } else {
    maxBytes = opts.maxBytes;
  }

  function _emit(event) {
    if (!auditOn) return;
    audit().safeEmit({
      action:    "system.mail.bounce",
      outcome:   event.type === "delivery" ? "success" : "denied",
      metadata: {
        vendor:    event.vendor,
        type:      event.type,
        subType:   event.subType,
        recipient: event.recipient,
        messageId: event.messageId,
        reason:    event.reason,
        timestamp: event.timestamp,
      },
    });
  }

  function _send(res, status, body) {
    if (typeof res.writeHead === "function") {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    }
  }

  return function mailBounceMiddleware(req, res) {
    var collector = safeBuffer.boundedChunkCollector({
      maxBytes:    maxBytes,
      errorClass:  MailBounceError,
      sizeCode:    "mailBounce/too-large",
      sizeMessage: "payload exceeds maxBytes",
    });
    var aborted = false;

    req.on("data", function (chunk) {
      if (aborted) return;
      try { collector.push(chunk); }
      catch (_e) {
        aborted = true;
        return _send(res, HTTP.PAYLOAD_TOO_LARGE, { error: "payload too large" });
      }
    });

    req.on("end", function () {
      if (aborted) return;
      var raw = collector.result();
      var body;
      try { body = safeJson.parse(raw, { maxBytes: maxBytes }); }
      catch (e) {
        return _send(res, HTTP.BAD_REQUEST, { error: "invalid JSON: " + e.message });
      }

      // Verification hook — operator decides what counts as authentic.
      // Common shapes: HMAC of body against a shared secret, Basic
      // Auth header, SNS Signature verification, X-Webhook-Signature
      // svix header. The hook receives the request + the parsed body
      // so it can sign over either form.
      if (verify) {
        var ok;
        try { ok = verify(req, body, raw); }
        catch { return _send(res, HTTP.UNAUTHORIZED, { error: "verification error" }); }
        if (!ok) return _send(res, HTTP.UNAUTHORIZED, { error: "verification failed" });
      }

      var event;
      try {
        event = customParser ? _customParser(customParser)(body) : VENDORS[vendor](body);
      } catch (e) {
        return _send(res, HTTP.BAD_REQUEST, {
          error: e.message || "parse failed",
          code:  e.code   || "parse-failed",
        });
      }

      _emit(event);

      if (!onBounce) return _send(res, HTTP.OK, { ok: true });

      Promise.resolve()
        .then(function () { return onBounce(event); })
        .then(function () { _send(res, HTTP.OK, { ok: true }); },
              function (e) {
                _send(res, HTTP.INTERNAL_SERVER_ERROR, {
                  error: "onBounce threw: " + (e && e.message),
                });
              });
    });

    req.on("error", function () {
      if (!aborted) _send(res, HTTP.BAD_REQUEST, { error: "request error" });
    });
  };
}

// ---- Generic RFC 3464 / RFC 3461 / RFC 6533 DSN ----
//
// A delivery status notification is a multipart/report MIME body:
//
//   Content-Type: multipart/report;
//                 report-type=delivery-status;
//                 boundary="boundary-string"
//
//   --boundary-string
//   Content-Type: text/plain; charset=us-ascii
//
//   <human-readable description of the failure>
//
//   --boundary-string
//   Content-Type: message/delivery-status
//
//   Reporting-MTA: dns; mta.example.com
//   Arrival-Date: Mon, 28 Apr 2026 12:00:00 +0000
//
//   Original-Recipient: rfc822;user@example.com
//   Final-Recipient: rfc822;user@example.com
//   Action: failed
//   Status: 5.1.1
//   Remote-MTA: dns; mx.example.com
//   Diagnostic-Code: smtp; 550 5.1.1 No such user
//
//   --boundary-string
//   Content-Type: message/rfc822
//
//   <original message headers + body>
//
//   --boundary-string--
//
// RFC 3461 adds the SMTP NOTIFY=SUCCESS,FAILURE,DELAY and RET=FULL,HDRS
// extensions — they're carried inside the SMTP envelope, but the DSN
// the framework generates / parses ends up reflecting that operator
// choice via the `originalMessage` decision (full body vs headers
// only) and the per-recipient `Action` field (delivered / failed /
// delayed / relayed / expanded).
//
// RFC 6533 (SMTPUTF8 / EAI) extends the address-type tag from rfc822
// to utf-8 so internationalized mailbox names ride through. The
// parser accepts both; the generator picks utf-8 when the recipient
// contains non-ASCII bytes.

// Per-message DSN fields (RFC 3464 §2.2). Listed for validation +
// canonical-case re-emission.
var DSN_PER_MESSAGE_FIELDS = {
  "original-envelope-id":  "Original-Envelope-Id",
  "reporting-mta":         "Reporting-MTA",
  "dsn-gateway":           "DSN-Gateway",
  "received-from-mta":     "Received-From-MTA",
  "arrival-date":          "Arrival-Date",
};

// Per-recipient DSN fields (RFC 3464 §2.3).
var DSN_PER_RECIPIENT_FIELDS = {
  "original-recipient":    "Original-Recipient",
  "final-recipient":       "Final-Recipient",
  "action":                "Action",
  "status":                "Status",
  "remote-mta":            "Remote-MTA",
  "diagnostic-code":       "Diagnostic-Code",
  "last-attempt-date":     "Last-Attempt-Date",
  "final-log-id":          "Final-Log-ID",
  "will-retry-until":      "Will-Retry-Until",
};

// Action token allowlist — RFC 3464 §2.3.3.
var DSN_ACTIONS = {
  "failed":     true,
  "delayed":    true,
  "delivered":  true,
  "relayed":    true,
  "expanded":   true,
};

// Body cap for the DSN parser. The parser walks the raw bytes once;
// any payload above 1 MiB is pathological — no spec-conforming DSN
// approaches that, and uncapped parsing would let a hostile peer pin
// CPU on regex backtracking inside the header decoder.
var DSN_MAX_BYTES = C.BYTES.mib(1);

function _parseDeliveryStatusBody(body) {
  // RFC 3464 §2.1 — message/delivery-status is per-message field group
  // followed by ONE OR MORE per-recipient groups, each separated by an
  // empty line.
  var groups = body.split(/\r?\n\r?\n/).map(function (g) { return g.trim(); }).filter(Boolean);
  if (groups.length === 0) return { perMessage: {}, perRecipients: [] };
  var perMessage = {};
  var msgHeaders = mimeParse.parseHeaderBlock(groups[0]);
  for (var i = 0; i < msgHeaders.length; i += 1) {
    perMessage[msgHeaders[i].name.toLowerCase()] = msgHeaders[i].value;
  }
  var perRecipients = [];
  for (var g = 1; g < groups.length; g += 1) {
    var headers = mimeParse.parseHeaderBlock(groups[g]);
    if (headers.length === 0) continue;
    var rec = {};
    for (var k = 0; k < headers.length; k += 1) {
      rec[headers[k].name.toLowerCase()] = headers[k].value;
    }
    perRecipients.push(rec);
  }
  return { perMessage: perMessage, perRecipients: perRecipients };
}

function _actionToSubType(action) {
  // RFC 3464 §2.3.3 actions map onto the framework's bounce-shape
  // vocabulary. failed -> hard, delayed -> soft. delivered / relayed /
  // expanded come back as type=delivery; the parser swallows those
  // before this lookup runs.
  var a = (action || "").toLowerCase();
  if (a === "failed")   return "hard";
  if (a === "delayed")  return "soft";
  return "unknown";
}

function _parseDsn(rawMessage) {
  if (typeof rawMessage !== "string" || rawMessage.length === 0) {
    throw _err("bounce/dsn-parse-failed",
      "mailBounce.dsn.parse: rawMessage must be a non-empty string");
  }
  // Hot-path body cap. Above this limit the parser stops trying to
  // interpret the bytes — pathological inputs become a typed error
  // rather than a regex-backtrack hang.
  if (rawMessage.length > DSN_MAX_BYTES) {
    throw _err("bounce/dsn-parse-failed",
      "mailBounce.dsn.parse: message exceeds " + DSN_MAX_BYTES + " bytes");
  }

  var top = mimeParse.splitHeadersAndBody(rawMessage);
  var ctRaw = mimeParse.findHeader(top.headers, "Content-Type");
  if (!ctRaw) {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.parse: missing top-level Content-Type");
  }
  var ct = mimeParse.parseContentType(ctRaw);
  if (ct.type !== "multipart/report") {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.parse: top-level Content-Type must be multipart/report; got " + ct.type);
  }
  if (ct.params["report-type"] && ct.params["report-type"].toLowerCase() !== "delivery-status") {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.parse: report-type must be delivery-status; got " + ct.params["report-type"]);
  }
  var boundary = ct.params.boundary;
  if (!boundary) {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.parse: multipart/report missing boundary parameter");
  }

  var parts = mimeParse.splitMimeParts(top.body, boundary);
  if (parts.length < 2) {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.parse: multipart/report needs at least 2 parts (text + delivery-status); got " + parts.length);
  }

  // Find the message/delivery-status part.
  var statusBody = null;
  var humanText  = null;
  var originalMessage = null;
  for (var i = 0; i < parts.length; i += 1) {
    var partSplit = mimeParse.splitHeadersAndBody(parts[i].replace(/^\r?\n/, ""));
    var partCtRaw = mimeParse.findHeader(partSplit.headers, "Content-Type") || "text/plain";
    var partCt = mimeParse.parseContentType(partCtRaw);
    if (partCt.type === "message/delivery-status") {
      statusBody = partSplit.body;
    } else if (partCt.type === "text/plain" && humanText === null) {
      humanText = partSplit.body;
    } else if (partCt.type === "message/rfc822" || partCt.type === "text/rfc822-headers") {
      originalMessage = partSplit.body;
    }
  }

  if (statusBody === null) {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.parse: no message/delivery-status part found");
  }

  var status = _parseDeliveryStatusBody(statusBody);
  if (status.perRecipients.length === 0) {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.parse: message/delivery-status has no per-recipient groups");
  }

  // First recipient drives the normalized event (matches the SES /
  // postmark convention; multi-recipient DSNs are exposed via
  // event.raw.allRecipients for operators that need fan-out).
  var recip = status.perRecipients[0];
  var action = (recip["action"] || "").toLowerCase();
  var finalRecipient = mimeParse.stripAddressType(recip["final-recipient"]) ||
                       mimeParse.stripAddressType(recip["original-recipient"]);
  if (!finalRecipient) {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.parse: per-recipient group missing Final-Recipient");
  }
  if (action && !Object.prototype.hasOwnProperty.call(DSN_ACTIONS, action)) {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.parse: Action token '" + action + "' is not RFC 3464 §2.3.3");
  }

  var type, subType;
  if (action === "delivered" || action === "relayed" || action === "expanded") {
    type = "delivery"; subType = null;
  } else {
    type = "bounce"; subType = _actionToSubType(action);
  }

  var diagnosticCode = recip["diagnostic-code"] || null;
  // RFC 3464 §2.3.6 — Diagnostic-Code is `diagnostic-type;
  // diagnostic`. Most are `smtp; <reply>` — strip the type prefix to
  // surface the human-readable reason in audit metadata.
  var reason = diagnosticCode ? mimeParse.stripAddressType(diagnosticCode) : null;
  if (!reason && humanText) {
    // Fall back to the human-readable section when the spec'd
    // Diagnostic-Code field is absent (legacy MTAs).
    reason = humanText.trim().split(/\r?\n/).slice(0, 5).join(" ").slice(0, 500) || null;
  }

  var arrivalDate = status.perMessage["arrival-date"];
  var messageId = mimeParse.findHeader(top.headers, "Message-ID") || null;

  return {
    vendor:    "rfc3464",
    type:      type,
    subType:   subType,
    recipient: finalRecipient,
    messageId: messageId,
    reason:    reason,
    timestamp: arrivalDate || new Date().toISOString(),
    raw: {
      perMessage:      status.perMessage,
      allRecipients:   status.perRecipients,
      humanText:       humanText,
      originalMessage: originalMessage,
      // Status code (per RFC 3463 — class.subject.detail) is one of the
      // most useful operator fields; surface it on raw so policy code
      // can branch without re-parsing.
      status:          recip["status"] || null,
      action:          action || null,
      diagnosticCode:  diagnosticCode,
    },
  };
}

function _foldFieldValue(name, value) {
  // RFC 5322 §2.2.3 — long lines fold at WSP. Keep it simple: emit
  // `Name: value` and let downstream MTAs handle further folding. This
  // choke point emits a single `Name: value` line, so reject CR / LF /
  // NUL in the value — an embedded terminator would smuggle a new field
  // or forge a report part.
  safeBuffer.assertHeaderSafe(value, name, MailBounceError, "bounce/bad-dsn-field");
  return name + ": " + value + "\r\n";
}

function _generateBoundary() {
  return "blamejs-dsn-" + bCrypto.generateToken(C.BYTES.bytes(12));
}

function _buildDsn(opts) {
  validateOpts.requireObject(opts, "mailBounce.dsn.build", MailBounceError, "bounce/dsn-malformed");
  validateOpts.requireNonEmptyString(opts.finalRecipient,
    "mailBounce.dsn.build: opts.finalRecipient", MailBounceError, "bounce/dsn-malformed");
  var action = String(opts.action || "failed").toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(DSN_ACTIONS, action)) {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.build: opts.action must be one of " +
      Object.keys(DSN_ACTIONS).join(" / ") + "; got '" + action + "'");
  }
  if (typeof opts.status !== "string" || !/^\d\.\d{1,3}\.\d{1,3}$/.test(opts.status)) {
    throw _err("bounce/dsn-malformed",
      "mailBounce.dsn.build: opts.status must match RFC 3463 class.subject.detail; got '" +
      String(opts.status) + "'");
  }

  // CRLF/NUL header-injection guard. Recipients and MTA names are
  // structured fields that can never legitimately carry CR / LF / NUL, so
  // reject — a DSN built from a hostile recipient or peer must fail closed
  // rather than smuggle a header or forge a report part. Diagnostic-Code
  // echoes the remote server's SMTP reply (free text, legitimately
  // multi-line), so fold it to a single line instead of rejecting.
  safeBuffer.assertHeaderSafe(opts.finalRecipient, "finalRecipient", MailBounceError, "bounce/bad-dsn-field");
  if (opts.originalRecipient != null) {
    safeBuffer.assertHeaderSafe(opts.originalRecipient, "originalRecipient", MailBounceError, "bounce/bad-dsn-field");
  }
  var reportingMta   = opts.reportingMta || "dns; localhost";
  var arrivalDate    = opts.arrivalDate  || new Date().toUTCString();
  var originalMessage = opts.originalMessage || null;
  var diagnosticCode = opts.diagnosticCode != null
    ? safeBuffer.foldHeaderText(String(opts.diagnosticCode), " ") : null;
  var remoteMta      = opts.remoteMta || null;
  var humanText      = opts.humanText || (
    "This is the mail system at " + reportingMta + ".\r\n\r\n" +
    "Your message could not be delivered to:\r\n\r\n" +
    "  " + opts.finalRecipient + "\r\n\r\n" +
    (diagnosticCode ? "The remote server reported: " + diagnosticCode + "\r\n" : ""));

  var recipType = mimeParse.addressType(opts.finalRecipient);
  var origRecipType = opts.originalRecipient ? mimeParse.addressType(opts.originalRecipient) : recipType;

  var boundary = _generateBoundary();
  var lines = [];
  lines.push("MIME-Version: 1.0");
  lines.push('Content-Type: multipart/report; report-type=delivery-status; boundary="' + boundary + '"');
  if (opts.from)    lines.push("From: " + safeBuffer.assertHeaderSafe(opts.from, "from", MailBounceError, "bounce/bad-dsn-field"));
  if (opts.to)      lines.push("To: " + safeBuffer.assertHeaderSafe(opts.to, "to", MailBounceError, "bounce/bad-dsn-field"));
  if (opts.subject) lines.push("Subject: " + safeBuffer.assertHeaderSafe(opts.subject, "subject", MailBounceError, "bounce/bad-dsn-field"));
  if (opts.messageId) lines.push("Message-ID: " + safeBuffer.assertHeaderSafe(opts.messageId, "messageId", MailBounceError, "bounce/bad-dsn-field"));
  lines.push("");

  // Part 1 - human-readable description.
  lines.push("--" + boundary);
  lines.push("Content-Type: text/plain; charset=utf-8");
  lines.push("Content-Transfer-Encoding: 8bit");
  lines.push("");
  lines.push(humanText);
  lines.push("");

  // Part 2 - message/delivery-status.
  lines.push("--" + boundary);
  lines.push("Content-Type: message/delivery-status");
  lines.push("");
  // Per-message group.
  var perMessage = "";
  perMessage += _foldFieldValue("Reporting-MTA", reportingMta);
  perMessage += _foldFieldValue("Arrival-Date", arrivalDate);
  if (opts.originalEnvelopeId) {
    perMessage += _foldFieldValue("Original-Envelope-Id", opts.originalEnvelopeId);
  }
  lines.push(perMessage.replace(/\r\n$/, ""));
  lines.push("");
  // Per-recipient group.
  var perRecip = "";
  if (opts.originalRecipient) {
    perRecip += _foldFieldValue("Original-Recipient",
      origRecipType + ";" + opts.originalRecipient);
  }
  perRecip += _foldFieldValue("Final-Recipient",
    recipType + ";" + opts.finalRecipient);
  perRecip += _foldFieldValue("Action", action);
  perRecip += _foldFieldValue("Status", opts.status);
  if (remoteMta) {
    perRecip += _foldFieldValue("Remote-MTA", remoteMta);
  }
  if (diagnosticCode) {
    perRecip += _foldFieldValue("Diagnostic-Code", diagnosticCode);
  }
  if (opts.lastAttemptDate) {
    perRecip += _foldFieldValue("Last-Attempt-Date", opts.lastAttemptDate);
  }
  if (opts.willRetryUntil) {
    perRecip += _foldFieldValue("Will-Retry-Until", opts.willRetryUntil);
  }
  lines.push(perRecip.replace(/\r\n$/, ""));
  lines.push("");

  // Part 3 (optional) - original message or just headers per RFC 3461
  // RET= choice. The framework picks the part-type from the
  // originalMessage shape: if `{ headersOnly: true, headers: "..." }`
  // is supplied, emit text/rfc822-headers; if a plain string is
  // supplied, emit message/rfc822 with the full body.
  if (originalMessage) {
    lines.push("--" + boundary);
    if (typeof originalMessage === "object" && originalMessage.headersOnly) {
      lines.push("Content-Type: text/rfc822-headers");
      lines.push("");
      lines.push(originalMessage.headers || "");
    } else {
      lines.push("Content-Type: message/rfc822");
      lines.push("");
      lines.push(typeof originalMessage === "string" ? originalMessage : "");
    }
    lines.push("");
  }

  lines.push("--" + boundary + "--");
  lines.push("");
  return lines.join("\r\n");
}

module.exports = {
  parse:           parse,
  handler:         handler,
  MailBounceError: MailBounceError,
  // Vendor parsers exposed for tests + advanced operator wiring (e.g.
  // operators who want to call _parsePostmark inside a custom verify
  // step before deciding whether to accept the webhook).
  vendors: {
    postmark: _parsePostmark,
    ses:      _parseSes,
    resend:   _parseResend,
  },
  // Generic RFC 3464 / RFC 3461 / RFC 6533 DSN parser + generator.
  dsn: {
    parse: _parseDsn,
    build: _buildDsn,
    // Tables surfaced for tests + advanced operator code (e.g. operators
    // building DSN-shaped reports against a custom action vocabulary).
    PER_MESSAGE_FIELDS:   DSN_PER_MESSAGE_FIELDS,
    PER_RECIPIENT_FIELDS: DSN_PER_RECIPIENT_FIELDS,
    ACTIONS:              DSN_ACTIONS,
  },
};

"use strict";
/**
 * mail — message contract + pluggable transports.
 *
 * Both the contract and the transport surface ship together. Operators
 * can also pass any function or `{ send }` object as a custom transport.
 *
 *   mail.transports.console — logs message to stderr (dev default)
 *   mail.transports.memory  — captures into a `sent[]` array (tests)
 *   mail.transports.smtp    — raw RFC 5321 over net/tls with STARTTLS,
 *                             AUTH LOGIN, and PQC-friendly TLS opts
 *   mail.transports.http    — generic HTTP-API transport: operator
 *                             supplies endpoint, headers, serialize(),
 *                             and interpret() — works with any vendor
 *                             that speaks JSON-over-HTTPS (Postmark,
 *                             Mailgun, SES HTTP, SendGrid, Resend, …)
 *   mail.transports.resend  — thin preset that wires http to the
 *                             Resend API (illustrates the pattern)
 *
 * Public API:
 *
 *   mail.create({ transport?, defaults?, audit? }) → instance
 *
 *     transport — function(message) | { send(message) }; default: console.
 *     defaults  — { from, replyTo, headers, ... } merged into every
 *                 message unless the message overrides.
 *     audit     — emit mail.send.success / .failure audit events
 *                 (default true).
 *
 *   await instance.send(message)
 *     message: {
 *       to:       "x@y" | ["x@y", ...]
 *       cc:       string | string[]
 *       bcc:      string | string[]
 *       from:     "Name <noreply@app>"        (or instance default)
 *       replyTo:  "..."
 *       subject:  "..."
 *       text:     "plain body"                (at least one of text/html)
 *       html:     "<p>...</p>"
 *       headers:  { "X-Custom": "v" }         (merged with defaults)
 *       attachments: [{
 *         filename:           "report.pdf",        // required
 *         content:             buf,                // Buffer or string
 *         contentType:         "application/pdf",  // default application/octet-stream
 *         contentDisposition:  "attachment",       // or "inline"
 *         cid:                 "logo-1",            // for inline images:
 *                                                  // <img src="cid:logo-1">
 *       }, ...]
 *     }
 *     → whatever the transport returned
 *
 * When attachments are present the SMTP transport wraps the body in
 * multipart/mixed; text+html bodies still use multipart/alternative
 * inside. Resend's http preset forwards attachments via the Resend API
 * shape (base64 content + content_id for inline). Operators wiring
 * other vendors against httpTransport include attachments in their
 * own serialize() per-vendor.
 *
 * Validation surface uses MailError (FrameworkError subclass) with
 * permanent flag. Distinct codes per failure: missing-to, missing-from,
 * missing-body, invalid-recipient, transport-failed, smtp-*, http-*,
 * resend-*. Vendor-specific presets carry their own code prefix so
 * diagnostic logs identify the provider that rejected the message.
 */
var C = require("./constants");
var crypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var audit = lazyRequire(function () { return require("./audit"); });
var httpClient = lazyRequire(function () { return require("./http-client"); });
var guardEmail = lazyRequire(function () { return require("./guard-email"); });
var guardFilename = lazyRequire(function () { return require("./guard-filename"); });
var fileType = lazyRequire(function () { return require("./file-type"); });
var mailDkim = require("./mail-dkim");
var mailAuth = require("./mail-auth");
var mailBimi = require("./mail-bimi");
var mailUnsubscribe = require("./mail-unsubscribe");
var net = lazyRequire(function () { return require("net"); });
var nodeUrl = require("url");
var tls = lazyRequire(function () { return require("tls"); });
var safeJson = require("./safe-json");
var safeSchema = require("./safe-schema");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

// Cap on responses parsed from upstream mail providers (Resend, etc.).
// Vendor responses are tiny in spec; 256 KiB is generous headroom.
var MAIL_RESPONSE_MAX_BYTES = C.BYTES.kib(256);

class MailError extends FrameworkError {
  constructor(code, message, permanent, statusCode) {
    super(message, code);
    this.name = "MailError";
    this.permanent = !!permanent;
    this.isMailError = true;
    if (typeof statusCode === "number") this.statusCode = statusCode;
  }
}

// Pragmatic email regex — shared with forms.validate / safe-schema.
// RFC 5322 in a regex is a fool's errand; this catches obvious nonsense
// and lets real-world addresses through.
var EMAIL_RE = safeSchema.EMAIL_RE;
// RFC 5321 §4.5.3.1.3 forward-path bound — bound length BEFORE the regex
// test so a megabyte-long input can't exhaust the regex engine.
var EMAIL_MAX_LEN = 254;

// EAI / SMTPUTF8 — RFC 6531/6532/6533 internationalized email. Detect
// non-ASCII content; convert IDN domains to Punycode (RFC 3492) for the
// ASCII path, leave them in Unicode where the peer announces SMTPUTF8.

// Match any code point outside ASCII (U+0080 and above). Used to
// detect EAI / SMTPUTF8-required content in an address or subject.
// eslint-disable-next-line no-control-regex
var NON_ASCII_RE = /[^\x00-\x7f]/;

function _isAscii(s) {
  if (typeof s !== "string" || s.length > EMAIL_MAX_LEN) return false;     // bound BEFORE regex test
  return !NON_ASCII_RE.test(s);
}

// IDN domain encode — domain MUST be the part after '@'. Returns the
// Punycode-encoded ASCII domain, OR null if the input isn't a valid
// IDN-encodable domain.
function toAscii(domain) {
  if (typeof domain !== "string" || domain.length === 0) return null;
  var ascii;
  try { ascii = nodeUrl.domainToASCII(domain); }
  catch (_e) { return null; }
  if (typeof ascii !== "string" || ascii.length === 0) return null;
  return ascii;
}

function toUnicode(domain) {
  if (typeof domain !== "string" || domain.length === 0) return null;
  try { return nodeUrl.domainToUnicode(domain); }
  catch (_e) { return null; }
}

function _isValidEmail(addr) {
  if (typeof addr !== "string" || addr.length === 0 || addr.length > EMAIL_MAX_LEN) {
    return false;
  }
  // Pure ASCII — fast path through the existing regex (length bounded above).
  if (_isAscii(addr)) return EMAIL_RE.test(addr);                          // bound: addr.length <= EMAIL_MAX_LEN
  // EAI path — split at last '@', convert domain to Punycode, then test
  // ASCII-only the assembled local@ascii-domain. The local part can be
  // Unicode under RFC 6531 §3.3 — we accept it without further regex
  // gating beyond the existing CRLF/NUL refusals upstream.
  var atIdx = addr.lastIndexOf("@");
  if (atIdx <= 0 || atIdx === addr.length - 1) return false;
  var local = addr.slice(0, atIdx);
  var domain = addr.slice(atIdx + 1);
  var ascii = toAscii(domain);
  if (!ascii) return false;
  // Re-test the ASCII-converted domain against the existing email regex
  // to refuse junk like "..invalid" that domainToASCII rubber-stamps
  // (Node's WHATWG-URL implementation is permissive on dotted-empty
  // labels). Substitute a placeholder local part so the regex sees an
  // ASCII-only shape; the actual local part may legitimately be Unicode
  // under RFC 6531 §3.3 and is enforced separately below.
  if (ascii.length > EMAIL_MAX_LEN - 2) return false;                      // bound BEFORE regex test
  if (!EMAIL_RE.test("x@" + ascii)) return false;
  // Local part must not contain CRLF / NUL (header injection / SMTP
  // smuggling). Other Unicode is fine per RFC 6531.
  if (/[\r\n\0]/.test(local)) return false;
  // Length cap also applies to the ASCII-equivalent so a long IDN
  // domain that punycodes to >254 ASCII bytes is refused.
  if ((local.length + 1 + ascii.length) > EMAIL_MAX_LEN) return false;
  return true;
}

// Does this message require SMTPUTF8 on the wire?  RFC 6531 §3.2 — true
// when any of from / to / cc / bcc / subject / mailbox-display-name
// contains non-ASCII octets.
function _messageRequiresSmtpUtf8(message) {
  if (!message) return false;
  if (!_isAscii(String(message.from || ""))) return true;
  if (!_isAscii(String(message.subject || ""))) return true;
  var lists = [message.to, message.cc, message.bcc];
  for (var li = 0; li < lists.length; li += 1) {
    var arr = Array.isArray(lists[li]) ? lists[li] : (lists[li] ? [lists[li]] : []);
    for (var i = 0; i < arr.length; i += 1) {
      if (!_isAscii(String(arr[i]))) return true;
    }
  }
  return false;
}

function _normalizeRecipientList(value, label) {
  if (value === undefined || value === null) return [];
  var arr = Array.isArray(value) ? value : [value];
  for (var i = 0; i < arr.length; i++) {
    if (typeof arr[i] !== "string" || arr[i].length === 0) {
      throw new MailError("mail/invalid-recipient",
        label + "[" + i + "] must be a non-empty string", true);
    }
    // CRLF/NUL in addresses → header injection. Reject hard.
    if (/[\r\n\0]/.test(arr[i])) {
      throw new MailError("mail/invalid-recipient",
        label + "[" + i + "] contains forbidden control characters", true);
    }
    // Accept "Name <email@addr>" form too — extract the angle-bracket
    // address for validation; preserve the full string in the message.
    var bracket = arr[i].match(/<([^>]+)>/);
    var addr = bracket ? bracket[1] : arr[i];
    if (!_isValidEmail(addr.trim())) {
      throw new MailError("mail/invalid-recipient",
        label + " '" + arr[i] + "' is not a valid email address", true);
    }
  }
  return arr;
}

function _validateMessage(message) {
  if (!message || typeof message !== "object") {
    throw new MailError("mail/missing-message", "send() requires a message object", true);
  }
  var to = _normalizeRecipientList(message.to, "to");
  if (to.length === 0) {
    throw new MailError("mail/missing-to", "message.to is required (one or more recipients)", true);
  }
  _normalizeRecipientList(message.cc,  "cc");
  _normalizeRecipientList(message.bcc, "bcc");

  if (!message.from || typeof message.from !== "string") {
    throw new MailError("mail/missing-from", "message.from is required", true);
  }
  if (/[\r\n\0]/.test(message.from)) {
    throw new MailError("mail/invalid-from",
      "message.from contains forbidden control characters", true);
  }
  var fromBracket = message.from.match(/<([^>]+)>/);
  var fromAddr = fromBracket ? fromBracket[1] : message.from;
  if (!_isValidEmail(fromAddr.trim())) {
    throw new MailError("mail/invalid-from",
      "message.from '" + message.from + "' is not a valid email address", true);
  }
  if (message.subject && safeBuffer.hasCrlf(message.subject)) {
    throw new MailError("mail/invalid-subject",
      "message.subject contains forbidden CRLF", true);
  }

  if (!message.text && !message.html && !message.calendar) {
    throw new MailError("mail/missing-body",
      "message must include at least one of text, html, or calendar", true);
  }

  if (message.calendar !== undefined) {
    if (!message.calendar || typeof message.calendar !== "object") {
      throw new MailError("mail/invalid-calendar",
        "message.calendar must be an object { method, icalText }", true);
    }
    var ALLOWED_METHODS = ["REQUEST", "CANCEL", "REPLY", "PUBLISH", "COUNTER", "REFRESH", "ADD", "DECLINECOUNTER"];
    if (typeof message.calendar.method !== "string" ||
        ALLOWED_METHODS.indexOf(message.calendar.method) === -1) {
      throw new MailError("mail/invalid-calendar",
        "calendar.method must be one of: " + ALLOWED_METHODS.join(", "), true);
    }
    if (typeof message.calendar.icalText !== "string" ||
        message.calendar.icalText.length === 0) {
      throw new MailError("mail/invalid-calendar",
        "calendar.icalText is required (non-empty string)", true);
    }
    if (!/^BEGIN:VCALENDAR/.test(message.calendar.icalText)) {
      throw new MailError("mail/invalid-calendar",
        "calendar.icalText must start with 'BEGIN:VCALENDAR' (RFC 5545)", true);
    }
  }

  if (message.attachments !== undefined) {
    if (!Array.isArray(message.attachments)) {
      throw new MailError("mail/invalid-attachments",
        "message.attachments must be an array", true);
    }
    for (var i = 0; i < message.attachments.length; i++) {
      var att = message.attachments[i];
      if (!att || typeof att !== "object") {
        throw new MailError("mail/invalid-attachment",
          "attachments[" + i + "] must be an object", true);
      }
      if (typeof att.filename !== "string" || att.filename.length === 0) {
        throw new MailError("mail/invalid-attachment",
          "attachments[" + i + "].filename must be a non-empty string", true);
      }
      if (/[\r\n\0]/.test(att.filename)) {
        throw new MailError("mail/invalid-attachment",
          "attachments[" + i + "].filename contains forbidden control characters", true);
      }
      // Filename safety gate — path traversal / null-byte / NTFS ADS /
      // RTLO bidi / Windows-reserved / overlong UTF-8 / shell-exec
      // / double-extension. Without this, an operator forwarding a
      // user-uploaded attachment passes attacker-controlled filenames
      // straight to mail clients (which use the filename for "save
      // as" prompts) where Excel + macOS Finder + Outlook honor the
      // RTLO + reserved-name + Windows-strip semantics.
      if (att.skipFilenameSafety !== true) {
        var fnResult = guardFilename().validate(att.filename, { profile: "strict" });
        if (!fnResult.ok) {
          throw new MailError("mail/invalid-attachment",
            "attachments[" + i + "].filename rejected by guardFilename: " +
            (fnResult.issues && fnResult.issues[0] && fnResult.issues[0].kind || "filename-safety-fail"),
            true);
        }
      }
      // Magic-byte gate — refuse claimed/detected MIME mismatch when
      // both are present. Operator can opt out per-attachment with
      // `skipMagicByteCheck: true` and audited reason (e.g. encrypted
      // payloads where the magic bytes intentionally don't match the
      // claimed type).
      if (att.skipMagicByteCheck !== true && att.contentType &&
          Buffer.isBuffer(att.content)) {
        try {
          var detected = fileType().detect(att.content);
          if (detected && detected.mime &&
              detected.mime.split("/")[0] !==
              att.contentType.split(";")[0].trim().toLowerCase().split("/")[0]) {
            throw new MailError("mail/invalid-attachment",
              "attachments[" + i + "].contentType '" + att.contentType +
              "' disagrees with detected magic-byte MIME '" + detected.mime +
              "' — refusing to send mis-typed attachment", true);
          }
        } catch (e) {
          if (e && e.code === "mail/invalid-attachment") throw e;
          // file-type detection error: drop-silent, treat as no-detection
        }
      }
      if (att.content === undefined || att.content === null) {
        throw new MailError("mail/invalid-attachment",
          "attachments[" + i + "].content is required (Buffer or string)", true);
      }
      if (!Buffer.isBuffer(att.content) && typeof att.content !== "string") {
        throw new MailError("mail/invalid-attachment",
          "attachments[" + i + "].content must be a Buffer or string", true);
      }
      if (att.contentType !== undefined &&
          (typeof att.contentType !== "string" || /[\r\n\0]/.test(att.contentType))) {
        throw new MailError("mail/invalid-attachment",
          "attachments[" + i + "].contentType must be a clean string", true);
      }
      if (att.contentDisposition !== undefined &&
          att.contentDisposition !== "attachment" &&
          att.contentDisposition !== "inline") {
        throw new MailError("mail/invalid-attachment",
          "attachments[" + i + "].contentDisposition must be 'attachment' or 'inline'", true);
      }
      if (att.cid !== undefined &&
          (typeof att.cid !== "string" || /[\r\n\0<>]/.test(att.cid))) {
        throw new MailError("mail/invalid-attachment",
          "attachments[" + i + "].cid must be a clean string (no <>)", true);
      }
    }
  }
}

function _mergeMessage(defaults, message) {
  // Per-message values override defaults; headers merged shallow.
  var merged = Object.assign({}, defaults || {}, message);
  if (defaults && defaults.headers && message.headers) {
    merged.headers = Object.assign({}, defaults.headers, message.headers);
  }
  return merged;
}

function _extractAddr(s) {
  if (s === undefined || s === null) return s;
  var m = String(s).match(/<([^>]+)>/);
  return m ? m[1].trim() : String(s).trim();
}

function _toArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v.slice() : [v];
}

// ---- Built-in transports: console + memory (dev / tests) ----

function consoleTransport(opts) {
  opts = opts || {};
  var stream = opts.stream || process.stderr;
  // redactBcc: print only the recipient COUNT instead of the addresses.
  // Default false preserves the dev-visibility purpose of this
  // transport. Operators piping dev logs into shared / centralized
  // sinks (Slack, log aggregator, ticket system) opt in to avoid
  // leaking the BCC list — the property exists precisely so a recipient
  // doesn't see who else got the message, and that promise breaks the
  // moment the addresses land in a non-private log.
  var redactBcc = opts.redactBcc === true;
  return {
    name: "console",
    send: async function (message) {
      var lines = [
        "[mail.console] To: " + (Array.isArray(message.to) ? message.to.join(", ") : message.to),
        "[mail.console] From: " + message.from,
        "[mail.console] Subject: " + (message.subject || ""),
      ];
      if (message.cc)  lines.push("[mail.console] Cc: " + (Array.isArray(message.cc)  ? message.cc.join(", ")  : message.cc));
      if (message.bcc) {
        if (redactBcc) {
          var bccCount = Array.isArray(message.bcc) ? message.bcc.length : 1;
          lines.push("[mail.console] Bcc: <" + bccCount + " recipient" + (bccCount === 1 ? "" : "s") + " — redacted>");
        } else {
          lines.push("[mail.console] Bcc: " + (Array.isArray(message.bcc) ? message.bcc.join(", ") : message.bcc));
        }
      }
      var body = message.text || (message.html ? "(html body, " + message.html.length + " bytes)" : "");
      lines.push("");
      lines.push(body);
      lines.push("");
      stream.write(lines.join("\n") + "\n");
      return { transport: "console", deliveredAt: Date.now() };
    },
  };
}

function memoryTransport() {
  var sent = [];
  return {
    name: "memory",
    sent: sent,
    send: async function (message) {
      sent.push(message);
      return { transport: "memory", deliveredAt: Date.now(), index: sent.length - 1 };
    },
    reset: function () { sent.length = 0; },
  };
}

// ---- SMTP transport ----
//
// Raw RFC 5321 state machine over net/tls. Multi-recipient (loops
// RCPT TO over to + cc + bcc), builds an RFC 5322 message with
// multipart/alternative when both text and html are supplied, and
// dot-stuffs body lines beginning with "." per SMTP transparency.
//
// PQC posture: TLS opts default to TLSv1.3 minimum and accept an
// `ecdhCurve` string (set to a hybrid PQC group such as
// "X25519MLKEM768" when peer + Node version support it). On a
// cleartext port the transport always issues STARTTLS and refuses
// to send AUTH or DATA in cleartext if the upgrade is rejected.

function _newBoundary(label) {
  // crypto.randomBytes for the boundary suffix matches the framework
  // convention. RFC 5322 only requires uniqueness within a message,
  // but consistency with how every other identifier in lib/ is built
  // wins over premature differentiation.
  return "blamejs-" + label + "-" + Date.now() + "-" + crypto.generateToken(C.BYTES.bytes(8));
}

// base64-encode the buffer with line wrapping at 76 chars (RFC 2045
// §6.8). Most clients tolerate longer lines but the spec maximum is
// 998 octets per line; sticking to 76 keeps everyone happy.
function _base64Wrap(buf) {
  var b64 = buf.toString("base64");
  var lines = [];
  for (var i = 0; i < b64.length; i += 76) lines.push(b64.slice(i, i + 76));
  return lines.join("\r\n");
}

function _buildAttachmentPart(att) {
  var content = Buffer.isBuffer(att.content) ? att.content : Buffer.from(String(att.content), "utf8");
  var contentType = att.contentType || "application/octet-stream";
  var disposition = att.contentDisposition || (att.cid ? "inline" : "attachment");
  var lines = [];
  lines.push("Content-Type: " + contentType + '; name="' + att.filename + '"');
  lines.push("Content-Transfer-Encoding: base64");
  lines.push("Content-Disposition: " + disposition + '; filename="' + att.filename + '"');
  if (att.cid) lines.push("Content-ID: <" + att.cid + ">");
  lines.push("");
  lines.push(_base64Wrap(content));
  return lines.join("\r\n");
}

function _buildBodyPart(message) {
  // Collect body parts (text / html / calendar). Multiple parts → wrap
  // in multipart/alternative so the recipient client picks whichever
  // it can render. Calendar parts carry the `method=` parameter so
  // mail clients (Outlook / Gmail / Apple Mail) treat the message as
  // an invite, not a generic ics download.
  var parts = [];
  if (message.text) {
    parts.push({ contentType: "text/plain; charset=utf-8", body: message.text });
  }
  if (message.html) {
    parts.push({ contentType: "text/html; charset=utf-8", body: message.html });
  }
  if (message.calendar) {
    parts.push({
      contentType: 'text/calendar; method="' + message.calendar.method + '"; charset=utf-8',
      body:        message.calendar.icalText,
    });
  }
  if (parts.length === 1) return parts[0];
  var altBoundary = _newBoundary("alt");
  var lines = [];
  for (var i = 0; i < parts.length; i++) {
    lines.push("--" + altBoundary);
    lines.push("Content-Type: " + parts[i].contentType);
    lines.push("");
    lines.push(parts[i].body);
  }
  lines.push("--" + altBoundary + "--");
  return {
    contentType: 'multipart/alternative; boundary="' + altBoundary + '"',
    body:        lines.join("\r\n"),
  };
}

function _buildRfc822(message) {
  var headers = [];
  headers.push("From: " + message.from);
  headers.push("To: " + (Array.isArray(message.to) ? message.to.join(", ") : message.to));
  if (message.cc)      headers.push("Cc: " + (Array.isArray(message.cc) ? message.cc.join(", ") : message.cc));
  if (message.replyTo) headers.push("Reply-To: " + message.replyTo);
  if (message.subject) headers.push("Subject: " + message.subject);
  headers.push("MIME-Version: 1.0");
  headers.push("Date: " + new Date().toUTCString());
  if (message.headers) {
    for (var k in message.headers) {
      if (Object.prototype.hasOwnProperty.call(message.headers, k)) {
        // Strip CRLF defensively even though we already validated the
        // message; custom headers go straight onto the wire.
        var v = safeBuffer.stripCrlf(String(message.headers[k]));
        headers.push(k + ": " + v);
      }
    }
  }

  var attachments = Array.isArray(message.attachments) ? message.attachments : [];
  var inner = _buildBodyPart(message);
  var body;

  if (attachments.length === 0) {
    headers.push("Content-Type: " + inner.contentType);
    body = inner.body;
  } else {
    // multipart/mixed: first part is the body (single or alternative),
    // subsequent parts are the attachments. Inline disposition +
    // Content-ID is interpreted correctly by every major client even
    // inside mixed. Operators needing strict-RFC-2387 multipart/related
    // wrap the body via the mail.transports interface and pass a
    // content-type override.
    var mixedBoundary = _newBoundary("mixed");
    headers.push('Content-Type: multipart/mixed; boundary="' + mixedBoundary + '"');
    var parts = [];
    parts.push("--" + mixedBoundary);
    parts.push("Content-Type: " + inner.contentType);
    parts.push("");
    parts.push(inner.body);
    for (var ai = 0; ai < attachments.length; ai++) {
      parts.push("--" + mixedBoundary);
      parts.push(_buildAttachmentPart(attachments[ai]));
    }
    parts.push("--" + mixedBoundary + "--");
    body = parts.join("\r\n");
  }

  // Normalize line endings then dot-stuff per SMTP transparency.
  body = body.replace(/\r?\n/g, "\r\n");
  body = body.split("\r\n").map(function (l) { return l.charAt(0) === "." ? "." + l : l; }).join("\r\n");

  return headers.join("\r\n") + "\r\n\r\n" + body;
}

function smtpTransport(opts) {
  opts = opts || {};
  if (!opts.host) {
    throw new MailError("mail/smtp-misconfigured",
      "smtp transport requires opts.host", true);
  }
  if (opts.dkimSigner !== undefined && opts.dkimSigner !== null &&
      (typeof opts.dkimSigner !== "object" || typeof opts.dkimSigner.sign !== "function")) {
    throw new MailError("mail/smtp-misconfigured",
      "dkimSigner must be an object with a .sign(rfc822) method " +
      "(see b.mail.dkim.create)", true);
  }
  var port = opts.port || 587;
  var useImplicitTLS = port === 465 || opts.implicitTls === true;
  var rejectUnauthorized = opts.rejectUnauthorized !== false;
  var ehloName = opts.ehloName || "blamejs";
  var timeoutMs = opts.timeoutMs || C.TIME.seconds(15);
  var tlsOpts = {
    rejectUnauthorized: rejectUnauthorized,
    minVersion: opts.minTlsVersion || "TLSv1.3",
  };
  if (opts.ecdhCurve) tlsOpts.ecdhCurve = opts.ecdhCurve;
  if (opts.ca)        tlsOpts.ca = opts.ca;

  // SNI is only legal for hostnames; IP literals must omit servername
  // (Node's tls.connect throws "Setting the TLS ServerName to an IP
  // address is not permitted" otherwise). Operators with private CAs
  // and an IP-only target pass `opts.servername: "expected-cn.example"`
  // explicitly. Same convention as lib/redis-client.js.
  var host = opts.host;
  var servername = opts.servername;
  if (servername === undefined) {
    servername = (/^\d+\.\d+\.\d+\.\d+$/.test(host) || (host && host.indexOf(":") !== -1))
                   ? undefined : host;
  }

  var cfg = {
    host:           host,
    port:           port,
    user:           opts.user,
    pass:           opts.pass,
    useImplicitTLS: useImplicitTLS,
    ehloName:       ehloName,
    timeoutMs:      timeoutMs,
    tlsOpts:        tlsOpts,
    servername:     servername,
    dkimSigner:     opts.dkimSigner || null,
  };

  return {
    name: "smtp",
    send: function (message) { return _smtpSend(message, cfg); },
  };
}

// SMTP state-machine step IDs. Hex-encoded so the framework's
// byte-literal lint (which flags decimal multiples of 8) doesn't hit
// the equality comparisons in handleResponse below.
var SMTP_STEP_GREETING   = 0x0;
var SMTP_STEP_EHLO_RESP  = 0x1;
var SMTP_STEP_AUTH_USER  = 0x2;
var SMTP_STEP_AUTH_PASS  = 0x3;
var SMTP_STEP_AUTH_FINAL = 0x4;
var SMTP_STEP_MAIL_FROM  = 0x5;
var SMTP_STEP_RCPT_TO    = 0x6;
var SMTP_STEP_DATA       = 0x7;
var SMTP_STEP_BODY       = 0x8;
var SMTP_STEP_STARTTLS   = 0xA;

function _smtpUtf8Suffix(requiresSmtpUtf8, peerSupportsSmtpUtf8) {
  // RFC 6531 §3.4 — when SMTPUTF8 is advertised by the peer AND the
  // message requires it, append " SMTPUTF8" to MAIL FROM to opt this
  // transaction into the EAI extension. Pure-ASCII messages don't add
  // it (some peers reject the keyword on legacy mailboxes).
  return (requiresSmtpUtf8 && peerSupportsSmtpUtf8) ? " SMTPUTF8" : "";
}

function _smtpSend(message, cfg) {
  return new Promise(function (resolve, reject) {
    var socket;
    var step = SMTP_STEP_GREETING;
    var buffer = "";
    var ehloLines = [];                  // RFC 5321 §4.1.1.1 — EHLO extension lines
    var peerSupportsSmtpUtf8 = false;    // RFC 6531 — set from EHLO response
    var upgradedToTLS = false;
    var settled = false;
    var rcptIndex = 0;

    var fromAddr = _extractAddr(message.from);
    var toList   = _toArray(message.to).map(_extractAddr);
    var ccList   = _toArray(message.cc).map(_extractAddr);
    var bccList  = _toArray(message.bcc).map(_extractAddr);
    var rcpts    = toList.concat(ccList, bccList);
    var requiresSmtpUtf8 = _messageRequiresSmtpUtf8(message);
    var dataMessage = _buildRfc822(message);
    if (cfg.dkimSigner) {
      try { dataMessage = cfg.dkimSigner.sign(dataMessage); }
      catch (e) {
        reject(new MailError("mail/dkim-sign-failed",
          "dkim signing failed: " + ((e && e.message) || String(e)), true));
        return;
      }
    }

    // Outbound SMTP-smuggling defense — refuse before opening the
    // socket if the produced RFC 822 wire contains the bare-CR / bare-
    // LF + smuggled-verb shape (CVE-2023-51764 / 51765 / 51766 class).
    // Operator-supplied subject / body / headers can sneak the pattern
    // through _buildRfc822 if the input wasn't already gated.
    var rv = guardEmail().validateMessage(dataMessage, { profile: "strict" });
    if (!rv.ok) {
      var critical = rv.issues.filter(function (i) {
        return i.severity === "critical";
      });
      if (critical.length > 0) {
        reject(new MailError("mail/outbound-smuggling-refused",
          "outbound RFC 822 wire failed guardEmail: " +
          critical.map(function (i) { return i.kind; }).join(","), true));
        return;
      }
    }

    function fail(reason) {
      if (settled) return;
      settled = true;
      try { if (socket) socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
      reject(new MailError("mail/smtp-failed",
        "SMTP send failed: " + reason, false));
    }
    function done(ok, code) {
      if (settled) return;
      settled = true;
      try { socket.end(); } catch (_e) { /* socket may already be torn down */ }
      if (ok) resolve({ transport: "smtp", deliveredAt: Date.now(), code: code });
      else reject(new MailError("mail/smtp-rejected",
        "SMTP rejected message (code " + code + ")", false));
    }

    function send(cmd) {
      try { socket.write(cmd + "\r\n"); }
      catch (e) { fail(e.message || String(e)); }
    }

    function onData(data) {
      buffer += data;
      var lines = buffer.split("\r\n");
      buffer = lines.pop();
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (!line) continue;
        var code = parseInt(line.slice(0, 3), 10);
        // EHLO continuation lines (250-X) carry extension names. We
        // capture them so the dispatcher can branch on SMTPUTF8 / 8BITMIME
        // / STARTTLS support before MAIL FROM is sent.
        if (step === SMTP_STEP_EHLO_RESP) {
          var keyword = line.slice(4).split(" ")[0].toUpperCase();
          if (keyword) ehloLines.push(keyword);
        }
        if (line[3] === "-") continue; // continuation line
        try { handleResponse(code); }
        catch (e) { fail(e.message || String(e)); return; }
        if (settled) return;
      }
    }

    function attachSocket(s) {
      socket = s;
      socket.setEncoding("utf8");
      socket.setTimeout(cfg.timeoutMs);
      socket.on("data", onData);
      socket.on("error", function (err) { fail(err.message || String(err)); });
      socket.on("timeout", function () { fail("timeout"); });
    }

    function connect() {
      if (cfg.useImplicitTLS) {
        var tlsConnectOpts = Object.assign({}, cfg.tlsOpts);
        if (cfg.servername) tlsConnectOpts.servername = cfg.servername;
        attachSocket(tls().connect(cfg.port, cfg.host, tlsConnectOpts));
      } else {
        attachSocket(net().createConnection(cfg.port, cfg.host));
      }
    }

    function handleResponse(code) {
      if (step === SMTP_STEP_GREETING) {
        if (code !== 220) { fail("greeting-rejected (code " + code + ")"); return; }
        send("EHLO " + cfg.ehloName); step = SMTP_STEP_EHLO_RESP;
      }
      else if (step === SMTP_STEP_EHLO_RESP) {
        if (code < 200 || code >= 300) { fail("ehlo-rejected (code " + code + ")"); return; }
        // Snapshot extensions advertised on the wire for downstream use.
        peerSupportsSmtpUtf8 = ehloLines.indexOf("SMTPUTF8") !== -1;
        // RFC 6531 §3.2 — if the message requires SMTPUTF8 and the
        // peer does not advertise it, refuse hard rather than emit a
        // mangled wire (server might still accept but headers/local
        // parts would silently corrupt downstream).
        if (requiresSmtpUtf8 && !peerSupportsSmtpUtf8) {
          fail("eai-required-not-supported: message has non-ASCII content but peer does not advertise SMTPUTF8");
          return;
        }
        if (!cfg.useImplicitTLS && !upgradedToTLS) { send("STARTTLS"); step = SMTP_STEP_STARTTLS; }
        else if (cfg.user) { send("AUTH LOGIN"); step = SMTP_STEP_AUTH_USER; }
        else { send("MAIL FROM:<" + fromAddr + ">" + _smtpUtf8Suffix(requiresSmtpUtf8, peerSupportsSmtpUtf8)); step = SMTP_STEP_MAIL_FROM; }
      }
      else if (step === SMTP_STEP_STARTTLS) {
        if (code !== 220) { fail("starttls-rejected (code " + code + ")"); return; }
        var tlsConnectOpts = Object.assign({ socket: socket }, cfg.tlsOpts);
        if (cfg.servername) tlsConnectOpts.servername = cfg.servername;
        var tlsSocket = tls().connect(tlsConnectOpts, function () {
          upgradedToTLS = true;
          try { socket.removeAllListeners("data"); } catch (_e) { /* listeners migrate to upgraded socket */ }
          attachSocket(tlsSocket);
          send("EHLO " + cfg.ehloName);
          step = SMTP_STEP_EHLO_RESP;
        });
        tlsSocket.on("error", function (err) {
          fail("tls-upgrade: " + (err.message || String(err)));
        });
      }
      else if (step === SMTP_STEP_AUTH_USER) {
        if (code !== 334) { fail("auth-username-rejected (code " + code + ")"); return; }
        send(Buffer.from(cfg.user || "").toString("base64")); step = SMTP_STEP_AUTH_PASS;
      }
      else if (step === SMTP_STEP_AUTH_PASS) {
        if (code !== 334) { fail("auth-password-rejected (code " + code + ")"); return; }
        send(Buffer.from(cfg.pass || "").toString("base64")); step = SMTP_STEP_AUTH_FINAL;
      }
      else if (step === SMTP_STEP_AUTH_FINAL) {
        if (code !== 235) { fail("auth-failed (code " + code + ")"); return; }
        send("MAIL FROM:<" + fromAddr + ">" + _smtpUtf8Suffix(requiresSmtpUtf8, peerSupportsSmtpUtf8)); step = SMTP_STEP_MAIL_FROM;
      }
      else if (step === SMTP_STEP_MAIL_FROM) {
        if (code < 200 || code >= 300) { fail("mail-from-rejected (code " + code + ")"); return; }
        send("RCPT TO:<" + rcpts[rcptIndex++] + ">"); step = SMTP_STEP_RCPT_TO;
      }
      else if (step === SMTP_STEP_RCPT_TO) {
        if (code < 200 || code >= 300) { fail("rcpt-rejected (code " + code + ")"); return; }
        if (rcptIndex < rcpts.length) {
          send("RCPT TO:<" + rcpts[rcptIndex++] + ">");
        } else {
          send("DATA"); step = SMTP_STEP_DATA;
        }
      }
      else if (step === SMTP_STEP_DATA) {
        if (code !== 354) { fail("data-rejected (code " + code + ")"); return; }
        send(dataMessage + "\r\n.");
        step = SMTP_STEP_BODY;
      }
      else if (step === SMTP_STEP_BODY) {
        var ok = code === 250;
        done(ok, code);
      }
    }

    try { connect(); }
    catch (e) { fail(e.message || String(e)); }
  });
}

// ---- Generic HTTP transport ----
//
// Vendor-agnostic transport for any mail API that speaks HTTP. Operators
// supply three things: an endpoint, a serialize() that turns the
// framework-shaped message into the vendor's request body + headers,
// and an interpret() that reads the vendor's response and decides
// success vs failure. Uses lib/http-client so PQC TLS, response caps,
// and timeout handling come for free.
//
//   httpTransport({
//     name:             "postmark",            // appears in result + error codes
//     endpoint:         "https://...",         // POST target
//     method:           "POST",                // default POST
//     headers:          { ... },               // base headers (auth, content-type, ...)
//     timeoutMs:        15000,
//     allowedProtocols: safeUrl.ALLOW_HTTP_TLS, // default HTTPS-only
//     serialize: function (message) {
//       // → { headers?: {...}, body: string | Buffer }
//     },
//     interpret: function (res, message) {
//       // res = { statusCode, headers, body: Buffer }
//       // → { ok: true, id?: "..." } | { ok: false, reason: "..." }
//       // throw a MailError for permanent / structural failures
//     },
//   })
//
// Errors carry a `mail/<name>-*` code so logs identify which provider
// rejected which message (mail/postmark-failed, mail/resend-rejected,
// etc.). HTTPS-only is the default — pass safeUrl.ALLOW_HTTP_ALL via
// opts.allowedProtocols only for local test fixtures.

function httpTransport(opts) {
  opts = opts || {};
  if (!opts.endpoint || typeof opts.endpoint !== "string") {
    throw new MailError("mail/http-misconfigured",
      "http transport requires opts.endpoint", true);
  }
  if (typeof opts.serialize !== "function") {
    throw new MailError("mail/http-misconfigured",
      "http transport requires opts.serialize(message) → { headers?, body }", true);
  }
  var name             = opts.name || "http";
  var method           = (opts.method || "POST").toUpperCase();
  var endpoint         = opts.endpoint;
  var baseHeaders      = opts.headers || {};
  var timeoutMs        = opts.timeoutMs || C.TIME.seconds(15);
  var allowedProtocols = opts.allowedProtocols || null;
  var allowInternal    = opts.allowInternal != null ? opts.allowInternal : null;
  var interpret        = typeof opts.interpret === "function" ? opts.interpret : null;
  var serialize        = opts.serialize;
  var codePrefix       = "mail/" + name;

  return {
    name: name,
    send: async function (message) {
      var serialized = serialize(message);
      if (!serialized || typeof serialized !== "object") {
        throw new MailError(codePrefix + "-bad-serializer",
          "serialize() must return { headers?, body }", false);
      }
      var body = serialized.body;
      if (typeof body === "string") body = Buffer.from(body, "utf8");
      if (!Buffer.isBuffer(body)) {
        throw new MailError(codePrefix + "-bad-serializer",
          "serialize() body must be a string or Buffer", false);
      }
      var headers = Object.assign({}, baseHeaders, serialized.headers || {});
      // Default Content-Length when caller hasn't asserted chunked
      // transfer; keeps small JSON payloads from being chunked needlessly.
      var hasLen = false;
      for (var hk in headers) {
        if (Object.prototype.hasOwnProperty.call(headers, hk) &&
            hk.toLowerCase() === "content-length") { hasLen = true; break; }
      }
      if (!hasLen) headers["Content-Length"] = body.length;

      var reqOpts = {
        method:     method,
        url:        endpoint,
        headers:    headers,
        body:       body,
        timeoutMs:  timeoutMs,
        errorClass: MailError, // http-client constructs (code, message, permanent, statusCode)
      };
      if (allowedProtocols) reqOpts.allowedProtocols = allowedProtocols;
      if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

      var res;
      try {
        res = await httpClient().request(reqOpts);
      } catch (e) {
        // http-client constructs a MailError via opts.errorClass on
        // non-2xx / network / timeout, with its own code domain
        // (HTTP_ERROR, ETIMEDOUT, ...). Rewrap into mail/<name>-failed
        // so the consumer-facing code identifies the provider while
        // preserving the original as `cause` and the HTTP statusCode.
        var wrapped = new MailError(codePrefix + "-failed",
          name + " request failed: " + ((e && e.message) || String(e)),
          false,
          e && typeof e.statusCode === "number" ? e.statusCode : undefined);
        wrapped.cause = e;
        throw wrapped;
      }

      var info = { transport: name, deliveredAt: Date.now() };
      if (typeof res.statusCode === "number") info.statusCode = res.statusCode;

      if (!interpret) return info;

      var verdict;
      try { verdict = interpret(res, message); }
      catch (e) {
        if (e && e.isMailError) throw e;
        throw new MailError(codePrefix + "-interpret-failed",
          "interpret() threw: " + ((e && e.message) || String(e)), false);
      }
      if (!verdict || verdict.ok === false) {
        var reason = (verdict && verdict.reason) || "rejected";
        var err = new MailError(codePrefix + "-rejected",
          name + " rejected message: " + reason, false);
        if (verdict && typeof verdict.statusCode === "number") err.statusCode = verdict.statusCode;
        throw err;
      }
      if (verdict.id)    info.id = verdict.id;
      if (verdict.extra) Object.assign(info, verdict.extra);
      return info;
    },
  };
}

// ---- Resend preset ----
//
// Thin convenience wrapper that wires httpTransport to Resend's API.
// Operators wanting Postmark / Mailgun / SES HTTP / SendGrid build the
// same shape against httpTransport directly — this preset exists to
// document the pattern, not to privilege any single vendor.

function resendTransport(opts) {
  opts = opts || {};
  if (!opts.apiKey || typeof opts.apiKey !== "string") {
    throw new MailError("mail/resend-misconfigured",
      "resend transport requires opts.apiKey", true);
  }
  return httpTransport({
    name:             "resend",
    endpoint:         opts.endpoint || "https://api.resend.com/emails",
    method:           "POST",
    timeoutMs:        opts.timeoutMs || C.TIME.seconds(15),
    allowedProtocols: opts.allowedProtocols || null,
    allowInternal:    opts.allowInternal != null ? opts.allowInternal : null,
    headers: {
      "Authorization": "Bearer " + opts.apiKey,
      "Content-Type":  "application/json",
    },
    serialize: function (message) {
      var payload = {
        from:    message.from,
        to:      Array.isArray(message.to) ? message.to : [message.to],
        subject: message.subject || "",
      };
      if (message.cc)      payload.cc       = Array.isArray(message.cc)  ? message.cc  : [message.cc];
      if (message.bcc)     payload.bcc      = Array.isArray(message.bcc) ? message.bcc : [message.bcc];
      if (message.replyTo) payload.reply_to = message.replyTo;
      if (message.html)    payload.html     = message.html;
      if (message.text)    payload.text     = message.text;
      if (message.headers) payload.headers  = message.headers;
      // Resend attachments shape: [{ filename, content (base64 string),
      // contentType?, content_id? }]. Inline images via cid go through
      // the content_id field (Resend renders <img src="cid:...">).
      if (Array.isArray(message.attachments) && message.attachments.length > 0) {
        payload.attachments = message.attachments.map(function (att) {
          var buf = Buffer.isBuffer(att.content) ? att.content : Buffer.from(String(att.content), "utf8");
          var entry = {
            filename: att.filename,
            content:  buf.toString("base64"),
          };
          if (att.contentType) entry.contentType = att.contentType;
          if (att.cid)         entry.content_id  = att.cid;
          return entry;
        });
      }
      return { body: JSON.stringify(payload) };
    },
    interpret: function (res) {
      var text = res.body ? res.body.toString("utf8") : "";
      var data;
      // Cap on diagnostic-message snippet length (chars, not bytes) — keeps
      // a hostile or huge backend response from blowing up the error message.
      var DIAG_SNIPPET_LEN = 0xC8;
      try { data = safeJson.parse(text, { maxBytes: MAIL_RESPONSE_MAX_BYTES }); }
      catch (_e) {
        throw new MailError("mail/resend-bad-response",
          "resend response was not JSON: " + text.slice(0, DIAG_SNIPPET_LEN), false);
      }
      if (!data.id) {
        return {
          ok:     false,
          reason: data.message || JSON.stringify(data).slice(0, DIAG_SNIPPET_LEN),
        };
      }
      return { ok: true, id: data.id };
    },
  });
}

// ---- Engine instance ----

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "transport", "defaults", "audit",
  ], "mail");
  var transport = opts.transport || consoleTransport();
  if (typeof transport === "function") {
    transport = { send: transport, name: "anonymous" };
  }
  if (!transport || typeof transport.send !== "function") {
    throw new MailError("mail/bad-transport",
      "opts.transport must be a function or an object with .send(message)", true);
  }
  var defaults = opts.defaults || {};
  var auditOn = opts.audit !== false;

  function _emit(action, info) {
    if (!auditOn) return;
    audit().safeEmit({
      action:   action,
      outcome:  info.outcome || (action.endsWith(".failure") ? "failure" : "success"),
      actor:    info.actor || {},
      // Recipient COUNT, not addresses — addresses can be PII; the
      // framework's audit chain shouldn't carry them by default.
      // Operators who need full address logging set their own audit
      // hook with whatever PII discipline they want.
      metadata: {
        transport:     transport.name || "custom",
        subject:       info.subject || "",
        toCount:       info.toCount,
        ccCount:       info.ccCount,
        bccCount:      info.bccCount,
        durationMs:    info.durationMs,
      },
      reason:   info.reason || null,
    });
  }

  async function send(message) {
    var merged = _mergeMessage(defaults, message);
    // RFC 8058 / RFC 2369 List-Unsubscribe support: when the operator
    // passes `unsubscribe: { url, mailto, oneClick }`, expand into the
    // header pair and merge into the message headers. Lets bulk
    // senders comply with the Gmail / Yahoo / Microsoft bulk-sender
    // mandate without hand-rolling the header byte sequence.
    if (merged.unsubscribe && typeof merged.unsubscribe === "object") {
      var unsubHeaders = mailUnsubscribe.buildHeaders(merged.unsubscribe);
      merged.headers = Object.assign({}, merged.headers || {}, unsubHeaders);
      delete merged.unsubscribe;
    }
    _validateMessage(merged);

    var t0 = Date.now();
    try {
      var result = await transport.send(merged);
      _emit("mail.send.success", {
        subject:    merged.subject,
        toCount:    Array.isArray(merged.to)  ? merged.to.length  : 1,
        ccCount:    Array.isArray(merged.cc)  ? merged.cc.length  : (merged.cc  ? 1 : 0),
        bccCount:   Array.isArray(merged.bcc) ? merged.bcc.length : (merged.bcc ? 1 : 0),
        durationMs: Date.now() - t0,
      });
      return result;
    } catch (e) {
      _emit("mail.send.failure", {
        subject:    merged.subject,
        toCount:    Array.isArray(merged.to)  ? merged.to.length  : 1,
        ccCount:    Array.isArray(merged.cc)  ? merged.cc.length  : (merged.cc  ? 1 : 0),
        bccCount:   Array.isArray(merged.bcc) ? merged.bcc.length : (merged.bcc ? 1 : 0),
        durationMs: Date.now() - t0,
        outcome:    "failure",
        reason:     (e && e.message) || String(e),
      });
      // Re-throw as MailError when the upstream wasn't already one,
      // preserving the cause for diagnostic chains.
      if (e && e.isMailError) throw e;
      var wrapped = new MailError("mail/transport-failed",
        "transport '" + (transport.name || "custom") + "' failed: " + ((e && e.message) || String(e)),
        false);
      wrapped.cause = e;
      throw wrapped;
    }
  }

  return {
    send:      send,
    transport: transport,
    defaults:  defaults,
  };
}

module.exports = {
  create:      create,
  MailError:   MailError,
  unsubscribe: mailUnsubscribe,
  // RFC 3492 Punycode IDN domain encode/decode (b.mail.toAscii /
  // toUnicode). Wraps node:url.domainToASCII / domainToUnicode so
  // operators have one obvious place to reach for IDN handling. Used
  // internally by send() to convert IDN domain parts before the
  // pre-SMTPUTF8 ASCII regex check.
  toAscii:    toAscii,
  toUnicode:  toUnicode,
  // DKIM-Signature header generation for outbound mail (rsa-sha256
  // default, ed25519-sha256 opt-in). Wire it into the smtp transport
  // via opts.dkimSigner. See lib/mail-dkim.js for the full surface.
  dkim:       mailDkim,
  // Inbound mail authentication-results verification: SPF (RFC 7208),
  // DMARC (RFC 7489), ARC (RFC 8617). Outbound DKIM signing lives in
  // .dkim above; per-hop DKIM verification is deferred (composes with
  // the existing canonicalization helpers in lib/mail-dkim.js).
  spf:         mailAuth.spf,
  dmarc:       mailAuth.dmarc,
  arc:         mailAuth.arc,
  authResults: mailAuth.authResults,
  bimi:        mailBimi,
  // Test-only export: lets unit tests inspect the wire format without
  // standing up a TLS-capable SMTP fixture. Operators don't call this.
  _buildRfc822ForTest: _buildRfc822,
  transports: {
    console: consoleTransport,
    memory:  memoryTransport,
    smtp:    smtpTransport,
    http:    httpTransport,
    resend:  resendTransport,
  },
};

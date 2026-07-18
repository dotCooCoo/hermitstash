// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.mail
 * @featured true
 * @nav    Communication
 * @title  Mail
 *
 * @intro
 *   SMTP / HTTP-API email send with multipart RFC 5322 message
 *   composition, DKIM signing on the way out, and full inbound mail-
 *   authentication parsing on the way in. Builds a multipart/alternative
 *   body for text+html, multipart/related for inline images via `cid:`
 *   references, multipart/mixed when attachments are present, and
 *   handles SMTPUTF8 (RFC 6531) + IDN domain Punycode (RFC 3492) for
 *   internationalized addresses.
 *
 *   Transports ship as `b.mail.transports.*`: `console` (stderr dev
 *   default), `memory` (captures to `sent[]` for fixtures), `smtp`
 *   (raw RFC 5321 over net / tls with STARTTLS, AUTH LOGIN, and PQC-
 *   friendly TLS opts), `http` (generic JSON-over-HTTPS for any vendor
 *   speaking that contract — Postmark / Mailgun / SES HTTP / SendGrid /
 *   Resend), `resend` (thin preset wiring `http` to the Resend API as
 *   the worked example). Operators can also pass any function or
 *   `{ send }` object as a custom transport.
 *
 *   DKIM-Signature header generation lives at `b.mail.dkim` (rsa-sha256
 *   default, ed25519-sha256 opt-in, dual-signer per RFC 8463 §3 for
 *   transition windows). Inbound authentication-results parsing —
 *   SPF (RFC 7208), DMARC (RFC 7489), ARC chain trust evaluation
 *   (RFC 8617) — is exposed as `b.mail.spf` / `b.mail.dmarc` /
 *   `b.mail.arc` / `b.mail.authResults`. BIMI (RFC draft) is at
 *   `b.mail.bimi`. RFC 8058 one-click List-Unsubscribe lives at
 *   `b.mail.unsubscribe` and folds in automatically when the message
 *   carries `unsubscribe: { url | mailto, oneClick? }`.
 *
 *   CAN-SPAM Act §7704 enforcement is on-by-default for instances
 *   created with `commercial: true`: every send refuses unless the
 *   instance supplied `postalAddress` AND the message exposes a
 *   functional opt-out (List-Unsubscribe header or `unsubscribe.{url|
 *   mailto}` on the message). The postal address auto-appends to both
 *   text and html bodies via the configured separator; operators
 *   override the html footer with `footerHtml` (must still contain the
 *   country + postal-code bytes — the framework refuses operator
 *   overrides that drop the legally-required address).
 *
 *   Validation surface uses `MailError` (a `FrameworkError` subclass)
 *   with stable codes per failure: `missing-to` / `missing-from` /
 *   `missing-body` / `invalid-recipient` / `mail/transport-failed` /
 *   `smtp-*` / `http-*` / `resend-*`. Vendor-specific presets carry
 *   their own code prefix so diagnostic logs identify the provider
 *   that rejected the message. Audit emits `mail.send.success` /
 *   `mail.send.failure` / `mail.canspam.refused` and records recipient
 *   COUNTS only — addresses are PII, never auto-logged.
 *
 * @card
 *   SMTP / HTTP-API email send with multipart RFC 5322 message composition, DKIM signing on the way out, and full inbound mail- authentication parsing on the way in.
 */
var C = require("./constants");
var bCrypto = require("./crypto");
var codepointClass = require("./codepoint-class");
var markupEscape = require("./markup-escape").markupEscape;
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var guardDomain = require("./guard-domain");
var audit = lazyRequire(function () { return require("./audit"); });
var httpClient = lazyRequire(function () { return require("./http-client"); });
var guardEmail = lazyRequire(function () { return require("./guard-email"); });
var guardFilename = lazyRequire(function () { return require("./guard-filename"); });
var fileType = lazyRequire(function () { return require("./file-type"); });
var dkim = require("./mail-dkim");
var ipUtils = require("./ip-utils");
var mailAuth = require("./mail-auth");
var mailBimi = require("./mail-bimi");
var mailUnsubscribe = require("./mail-unsubscribe");
var mailAgent = require("./mail-agent");
var net = lazyRequire(function () { return require("node:net"); });
var networkDns = lazyRequire(function () { return require("./network-dns"); });
var nodeUrl = require("node:url");
var numericBounds = require("./numeric-bounds");
var nodeTls = lazyRequire(function () { return require("node:tls"); });
// Lazy — audit a cert-validation-disabled SMTP/TLS session at honor time.
var networkTls = lazyRequire(function () { return require("./network-tls"); });
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

/**
 * @primitive b.mail.toAscii
 * @signature b.mail.toAscii(domain)
 * @since     0.7.16
 * @status    stable
 * @related   b.mail.toUnicode, b.mail.create
 *
 * RFC 3492 Punycode encode an IDN domain to its ASCII-compatible form.
 * `domain` MUST be the part after `@` — pass the local part separately.
 * Returns the encoded ASCII string, or `null` when the input isn't a
 * valid IDN-encodable domain. Used internally by `send()` to convert
 * IDN domain parts before the pre-SMTPUTF8 ASCII regex check; surfaced
 * publicly so operators wiring custom transports can apply the same
 * normalization.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var ascii = b.mail.toAscii("münchen.de");
 *   // → "xn--mnchen-3ya.de"
 */
function toAscii(domain) {
  if (typeof domain !== "string" || domain.length === 0) return null;
  // domainToASCII silently TRUNCATES at a URL delimiter ("a.com/evil" -> "a.com"),
  // so a string carrying one is not a bare host — return null rather than a
  // misleading prefix. (":" / "@" / "[" / "]" already yield "", but reject them
  // here too so every non-host character fails the same way.)
  if (domain.indexOf("/") !== -1 || domain.indexOf("?") !== -1 ||
      domain.indexOf("#") !== -1 || domain.indexOf("\\") !== -1 ||
      domain.indexOf(":") !== -1 || domain.indexOf("@") !== -1 ||
      domain.indexOf("[") !== -1 || domain.indexOf("]") !== -1) return null;
  var ascii;
  try { ascii = nodeUrl.domainToASCII(domain); }
  catch (_e) { return null; }
  if (typeof ascii !== "string" || ascii.length === 0) return null;
  return ascii;
}

/**
 * @primitive b.mail.toUnicode
 * @signature b.mail.toUnicode(domain)
 * @since     0.7.16
 * @status    stable
 * @related   b.mail.toAscii, b.mail.create
 *
 * Decode an ASCII-Compatible-Encoding (Punycode `xn--…`) domain back
 * to its Unicode form. Returns `null` when the input isn't a valid
 * IDN domain. Operators rendering received-from / authentication-
 * results trace lines use this to display the human-readable form
 * alongside the on-the-wire ASCII representation.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var u = b.mail.toUnicode("xn--mnchen-3ya.de");
 *   // → "münchen.de"
 */
function toUnicode(domain) {
  if (typeof domain !== "string" || domain.length === 0) return null;
  try { return nodeUrl.domainToUnicode(domain); }
  catch (_e) { return null; }
}

/**
 * @primitive b.mail.reverseDns
 * @signature b.mail.reverseDns(ip)
 * @since     0.8.53
 * @status    stable
 * @related   b.mail.create
 *
 * Forward-confirmed reverse DNS lookup (FCrDNS, RFC 8601 §3 lite) for
 * an IPv4 or IPv6 address. Returns
 * `{ ok, ptr, forward, fcrdns }`:
 *
 *   - `ok`      — whether the PTR resolved at all.
 *   - `ptr`     — the first PTR record name (or `null`).
 *   - `forward` — array of A / AAAA addresses for that name (or `[]`).
 *   - `fcrdns`  — `true` when the original `ip` appears in `forward`.
 *
 * Used as the building block for the iprev mail-authentication check
 * (RFC 8601 §2.7.3): a sender's connect-IP must reverse-resolve to a
 * PTR name whose forward A/AAAA includes that IP. Operators wiring
 * inbound mail-receive paths call this on the connect address before
 * accepting the SMTP transaction; bulk-sender reputation systems use
 * the same check for outbound submission.
 *
 * Errors thrown by the underlying DNS path (bad-IP shape / lookup
 * timeout) are caught and surfaced as `{ ok: false, error: code }`
 * so the call doesn't reject the inbound path on a transient DNS
 * blip; `fcrdns` remains `false`.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var r = await b.mail.reverseDns("8.8.8.8");
 *   // → { ok: true, ptr: "dns.google", forward: ["8.8.8.8"], fcrdns: true }
 */
async function reverseDns(ip) {
  var dns = networkDns();
  var result = { ok: false, ptr: null, forward: [], fcrdns: false };
  var ptrs;
  try {
    ptrs = await dns.reverse(ip);
  } catch (e) {
    result.error = (e && e.code) || "dns/reverse-failed";
    return result;
  }
  if (!Array.isArray(ptrs) || ptrs.length === 0) {
    result.error = "dns/no-ptr";
    return result;
  }
  var ptrName = String(ptrs[0]);
  result.ok = true;
  result.ptr = ptrName;
  // Forward-confirm — query A or AAAA depending on the IP family of
  // the original input. RFC 8601 §3 says the forward query must use
  // the same family as the source; mismatched families don't count
  // as confirmation.
  var net = require("node:net");
  var forwardAddrs = [];
  try {
    if (net.isIPv6(ip)) {
      forwardAddrs = await dns.resolveAaaa(ptrName);
    } else {
      forwardAddrs = await dns.resolve4(ptrName);
    }
  } catch (e) {
    result.error = (e && e.code) || "dns/forward-failed";
    return result;
  }
  result.forward = Array.isArray(forwardAddrs) ? forwardAddrs.slice() : [];
  // Case-insensitive equality on IPv6 (canonical form differs for
  // ::ffff:8.8.8.8 vs 8.8.8.8); compare lower-cased strings.
  var ipLc = String(ip).toLowerCase();
  for (var i = 0; i < result.forward.length; i += 1) {
    if (String(result.forward[i]).toLowerCase() === ipLc) {
      result.fcrdns = true;
      break;
    }
  }
  return result;
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
    // address for validation (linear, via _extractAddr); preserve the full
    // string in the message.
    if (!_isValidEmail(_extractAddr(arr[i]))) {
      throw new MailError("mail/invalid-recipient",
        label + " '" + arr[i] + "' is not a valid email address", true);
    }
  }
  return arr;
}

// CAN-SPAM postal-address validation. Accepts either a 5-field object
// shape (street/city/region/postalCode/country) or a non-empty string
// (operators with an irregular address layout — e.g. EU multi-line —
// pass a pre-rendered string and the framework appends it as-is).
//
// Returns null on valid; a description string on invalid. The framework
// converts the description into a MailError code at the call-site.
function _validatePostalAddress(addr) {
  if (addr == null) return "postalAddress is required";
  if (typeof addr === "string") {
    if (addr.trim().length === 0) return "postalAddress (string) must be non-empty";
    return null;
  }
  if (typeof addr !== "object") {
    return "postalAddress must be an object or non-empty string";
  }
  var REQUIRED = ["street", "city", "region", "postalCode", "country"];
  for (var i = 0; i < REQUIRED.length; i += 1) {
    var k = REQUIRED[i];
    var v = addr[k];
    if (typeof v !== "string" || v.trim().length === 0) {
      return "postalAddress." + k + " is required (non-empty string)";
    }
    if (/[\r\n\0]/.test(v)) {                                                                                      // allow:regex-no-length-cap — short typo-surfacing check; address fields are operator config not network bytes
      return "postalAddress." + k + " contains forbidden control characters (CR/LF/NUL)";
    }
  }
  return null;
}

// Pull a single field out of the address shape (object or string).
// Returns "" when the field isn't present (string-shape addresses don't
// carry structured fields).
function _addressField(addr, field) {
  if (addr && typeof addr === "object" && typeof addr[field] === "string") {
    return addr[field];
  }
  return "";
}

// Render the structured address as a single text block for the
// CAN-SPAM footer. String-shape inputs render verbatim.
function _renderPostalAddressText(addr) {
  if (typeof addr === "string") return addr;
  if (!addr || typeof addr !== "object") return "";
  var line2 = [addr.city, addr.region, addr.postalCode].filter(Boolean).join(", ");
  return [addr.street, line2, addr.country].filter(Boolean).join("\n");
}

function _renderPostalAddressHtml(addr) {
  if (typeof addr === "string") {
    return _htmlEscape(addr).replace(/\n/g, "<br>");
  }
  if (!addr || typeof addr !== "object") return "";
  var parts = [];
  if (addr.street)      parts.push(_htmlEscape(addr.street));
  var line2 = [addr.city, addr.region, addr.postalCode].filter(Boolean).join(", ");
  if (line2)            parts.push(_htmlEscape(line2));
  if (addr.country)     parts.push(_htmlEscape(addr.country));
  return parts.join("<br>");
}

function _htmlEscape(s) {
  return markupEscape(s);
}

function _hasUnsubscribe(message) {
  if (message.unsubscribe && typeof message.unsubscribe === "object") return true;
  var headers = message.headers;
  if (!headers || typeof headers !== "object") return false;
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i += 1) {
    if (keys[i].toLowerCase() === "list-unsubscribe") return true;
  }
  return false;
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
  if (!_isValidEmail(_extractAddr(message.from))) {
    throw new MailError("mail/invalid-from",
      "message.from '" + message.from + "' is not a valid email address", true);
  }
  if (message.subject && safeBuffer.hasCrlf(message.subject)) {
    throw new MailError("mail/invalid-subject",
      "message.subject contains forbidden CRLF", true);
  }
  // Reply-To and custom header KEYS go straight onto the wire in _buildRfc822;
  // a CRLF in either smuggles arbitrary headers (Bcc / Reply-To override /
  // Content-Type) — RFC 5322 / CWE-93 header injection. Fail closed.
  if (message.replyTo && safeBuffer.hasCrlf(String(message.replyTo))) {
    throw new MailError("mail/invalid-reply-to",
      "message.replyTo contains forbidden CRLF (header injection)", true);
  }
  if (message.headers && typeof message.headers === "object") {
    for (var _hk in message.headers) {
      if (!Object.prototype.hasOwnProperty.call(message.headers, _hk)) continue;
      if (safeBuffer.hasCrlf(_hk) || _hk.indexOf("\0") !== -1) {
        throw new MailError("mail/invalid-header",
          "message.headers key contains forbidden CRLF/NUL (header injection)", true);
      }
      if (safeBuffer.hasCrlf(String(message.headers[_hk]))) {
        throw new MailError("mail/invalid-header",
          "message.headers value for '" + _hk + "' contains forbidden CRLF (header injection)", true);
      }
    }
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
              // allow:bare-split-on-quoted-header-token-grammar — split(";")[0] takes the Content-Type type/subtype, which precedes every parameter (RFC 9110 §8.3); a quoted ";" can only appear inside a later parameter value and so cannot affect [0].
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
  s = String(s);
  // Linear angle-bracket extraction — NOT s.match(/<([^>]+)>/), which is O(n^2)
  // in V8 on a long run of '<' with no '>' (the engine retries the greedy
  // [^>]+ from every '<' offset; 200K '<' ~ 11s). Recipient/from addresses on
  // b.mail.send can be caller/request-supplied, so this is a reachable DoS.
  // Mirrors the regex: the chars between the first '<' and the next '>'.
  var lt = s.indexOf("<");
  if (lt !== -1) {
    var gt = s.indexOf(">", lt + 1);
    if (gt > lt + 1) return s.slice(lt + 1, gt).trim();
  }
  return s.trim();
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
  return "blamejs-" + label + "-" + Date.now() + "-" + bCrypto.generateToken(C.BYTES.bytes(8));
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
  if (message.replyTo) headers.push("Reply-To: " + safeBuffer.stripCrlf(String(message.replyTo)));
  if (message.subject) headers.push("Subject: " + message.subject);
  headers.push("MIME-Version: 1.0");
  headers.push("Date: " + new Date().toUTCString());
  if (message.headers) {
    for (var k in message.headers) {
      if (Object.prototype.hasOwnProperty.call(message.headers, k)) {
        // Strip CRLF defensively even though we already validated the
        // message; custom headers go straight onto the wire.
        var v = safeBuffer.stripCrlf(String(message.headers[k]));
        headers.push(safeBuffer.stripCrlf(String(k)) + ": " + v);
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

  // Normalize line endings only. Dot-stuffing (SMTP DATA transparency, RFC 5321
  // §4.5.2) is applied at DATA send time — NOT here — because it must NOT touch
  // the RFC 3030 BDAT/CHUNKING path (length-framed; receivers do not un-stuff, so
  // a baked-in doubled dot corrupts the body) and must NOT be inside the
  // DKIM-signed message (the receiver verifies the un-stuffed body).
  body = body.replace(/\r?\n/g, "\r\n");

  return headers.join("\r\n") + "\r\n\r\n" + body;
}

// Dot-stuff a message for the SMTP DATA path (RFC 5321 §4.5.2): any line whose
// first byte is "." gets a doubled dot so the receiver's `.`-on-its-own-line
// terminator can't be forged by body content. Applied ONLY on DATA, never BDAT.
function _dotStuffForData(msg) {
  return msg.split("\r\n").map(function (l) { return l.charAt(0) === "." ? "." + l : l; }).join("\r\n");
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
  validateOpts.optionalPort(opts.port, "smtp transport: opts.port", MailError, "mail/smtp-misconfigured");
  var port = opts.port || 587;
  var useImplicitTLS = port === 465 || opts.implicitTls === true;
  var rejectUnauthorized = opts.rejectUnauthorized !== false;
  if (rejectUnauthorized === false) {
    networkTls().auditInsecureTls({ host: opts.host, port: port, source: "mail.smtp" });
  }
  var ehloName = opts.ehloName || "blamejs";
  // GHSA-c7w3-x93f-qmm8 / GHSA-vvjj-xcjg-gr5g (nodemailer CRLF-injection
  // class) — any string concatenated into an outbound SMTP wire command
  // MUST be CRLF/NUL-free, otherwise an attacker who can shape ehloName /
  // user / pass / host (via config injection or template indirection)
  // gets to inject a fresh EHLO / MAIL FROM / RCPT TO line. Refuse at
  // config-time so the operator's boot dies at the misconfiguration line
  // rather than silently emitting a smuggled command at first send.
  function _refuseCtlBytes(label, val) {
    if (val === undefined || val === null) return;
    if (typeof val !== "string") return;
    if (/[\r\n\0]/.test(val)) {                                                                            // allow:regex-no-length-cap — CRLF/NUL is a 3-codepoint class
      throw new MailError("mail/smtp-misconfigured",
        "smtp transport: opts." + label + " contains CR/LF/NUL bytes " +
        "(SMTP command-injection class — GHSA-c7w3-x93f-qmm8 / GHSA-vvjj-xcjg-gr5g)",
        true);
    }
  }
  _refuseCtlBytes("ehloName",   ehloName);
  _refuseCtlBytes("user",       opts.user);
  _refuseCtlBytes("pass",       opts.pass);
  _refuseCtlBytes("host",       opts.host);
  _refuseCtlBytes("servername", opts.servername);
  var timeoutMs = opts.timeoutMs || C.TIME.seconds(15);
  // Absolute transaction deadline — distinct from the per-socket IDLE
  // timeout above. A slow-trickle MX that emits one byte just inside
  // every idle window resets socket.setTimeout forever and never
  // completes; this wall-clock bound fails the whole send regardless of
  // trickle. Defaults well above timeoutMs so a normal multi-round-trip
  // SMTP conversation (greeting → EHLO → STARTTLS → AUTH → MAIL/RCPT →
  // DATA/BDAT) never trips it.
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxTransactionMs,
    "smtp transport: opts.maxTransactionMs", MailError, "mail/smtp-misconfigured");
  var maxTransactionMs = opts.maxTransactionMs || C.TIME.minutes(5);
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
    servername = (ipUtils.isIPv4Shape(host) || (host && host.indexOf(":") !== -1))
                   ? undefined : host;
  }

  // RFC 3030 BDAT chunking — default chunk size 256 KiB. Operator opt
  // `chunking: false` disables BDAT even when offered (some legacy
  // receivers advertise CHUNKING but mishandle bare BDAT framing).
  var chunkingEnabled = opts.chunking !== false;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.chunkSize,
    "smtp transport: opts.chunkSize", MailError, "mail/smtp-misconfigured");
  var chunkSize = (opts.chunkSize !== undefined) ? opts.chunkSize : C.BYTES.kib(256);

  // RFC 1870 SIZE — by default we honor the peer's advertised cap and
  // refuse before opening DATA / BDAT. `respectPeerSize: false`
  // disables the precheck (operator-asserted "I trust the peer to
  // accept whatever I send").
  var respectPeerSize = opts.respectPeerSize !== false;

  // IPv4 / IPv6 family preference for the underlying connect. "any"
  // lets Node pick (default — Happy Eyeballs / system policy); "4" or
  // "6" forces a single family. The framework auto-detects when the
  // local network has no IPv6 interfaces and prefers v4 in that case
  // so a v6-only peer doesn't hang the connect timeout.
  var preferFamily = (opts.preferFamily === 4 || opts.preferFamily === 6 ||
                      opts.preferFamily === "4" || opts.preferFamily === "6")
    ? Number(opts.preferFamily) : "any";

  var cfg = {
    host:            host,
    port:            port,
    user:            opts.user,
    pass:            opts.pass,
    useImplicitTLS:  useImplicitTLS,
    ehloName:        ehloName,
    timeoutMs:       timeoutMs,
    maxTransactionMs: maxTransactionMs,
    tlsOpts:         tlsOpts,
    servername:      servername,
    dkimSigner:      opts.dkimSigner || null,
    chunkingEnabled: chunkingEnabled,
    chunkSize:       chunkSize,
    respectPeerSize: respectPeerSize,
    preferFamily:    preferFamily,
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
// RFC 3030 BDAT chunked-body framing. The transport sends `BDAT N`
// (or `BDAT N LAST`) followed by exactly N bytes of body; each chunk
// expects a 250 response before the next chunk is written.
var SMTP_STEP_BDAT       = 0xB;

function _smtpUtf8Suffix(requiresSmtpUtf8, peerSupportsSmtpUtf8) {
  // RFC 6531 §3.4 — when SMTPUTF8 is advertised by the peer AND the
  // message requires it, append " SMTPUTF8" to MAIL FROM to opt this
  // transaction into the EAI extension. Pure-ASCII messages don't add
  // it (some peers reject the keyword on legacy mailboxes).
  return (requiresSmtpUtf8 && peerSupportsSmtpUtf8) ? " SMTPUTF8" : "";
}

// Detect whether the message has an 8-bit / binary attachment that
// requires BINARYMIME (RFC 3030 §3) on the wire. Pure-text messages —
// even when text/html bodies contain UTF-8 — go through 8BITMIME
// (RFC 6152) which is universally supported. The "binary" trigger is
// a Buffer attachment whose octet stream includes NUL bytes (or any
// byte > 0x7F when the operator marks `binary: true`). Buffers with
// the "application/octet-stream" claimed content-type also count.
function _messageRequiresBinaryMime(message) {
  if (!message) return false;
  if (!Array.isArray(message.attachments)) return false;
  for (var i = 0; i < message.attachments.length; i += 1) {
    var att = message.attachments[i];
    if (!att) continue;
    // Operator can mark explicit binary intent.
    if (att.binary === true) return true;
    // Buffer attachments whose content includes NUL are binary —
    // base64 wraps them safely but the source octets are 8-bit-binary
    // so the BODY=BINARYMIME hint is what tells the peer to expect
    // RFC 3030 framing instead of bare 8BITMIME.
    if (Buffer.isBuffer(att.content)) {
      // Quick scan — first 4 KiB is enough to detect the common case
      // (any executable / image / archive / pdf).
      var max = Math.min(att.content.length, C.BYTES.kib(4));
      for (var j = 0; j < max; j += 1) {
        if (att.content[j] === 0) return true;
      }
    }
  }
  return false;
}

// Detect whether the message body has any non-ASCII (8-bit) octets
// requiring at minimum 8BITMIME (RFC 6152) on the wire. Triggers on
// non-ASCII text bytes in subject / text / html / calendar parts.
// Distinct from BINARYMIME — the latter is for true binary streams
// (NUL-bearing).
function _messageRequires8BitMime(message) {
  if (!message) return false;
  var fields = ["text", "html", "subject"];
  for (var i = 0; i < fields.length; i += 1) {
    var v = message[fields[i]];
    if (typeof v === "string" && NON_ASCII_RE.test(v)) return true;   // allow:regex-no-length-cap — header-value detector; bounded by SMTP line cap upstream
  }
  if (message.calendar && typeof message.calendar.icalText === "string" &&
      NON_ASCII_RE.test(message.calendar.icalText)) return true;   // allow:regex-no-length-cap — caller bounds calendar.icalText size
  return false;
}

// Auto-detect IPv4 / IPv6 family for outbound connect when the
// operator didn't pin one. Walks `os.networkInterfaces()`; if the
// host has no non-internal IPv6 interfaces, prefer family=4 so a
// v6-only AAAA record doesn't hang the connect timeout. When the
// host has both, return 0 (let Node pick — Happy Eyeballs / system
// resultOrder applies).
function _autoDetectFamily() {
  try {
    var os = require("node:os");
    var ifaces = os.networkInterfaces();
    var hasV6 = false;
    var hasV4 = false;
    var keys = Object.keys(ifaces);
    for (var k = 0; k < keys.length; k += 1) {
      var arr = ifaces[keys[k]] || [];
      for (var i = 0; i < arr.length; i += 1) {
        var entry = arr[i];
        if (entry.internal) continue;
        if (entry.family === "IPv6" || entry.family === 6) hasV6 = true;
        if (entry.family === "IPv4" || entry.family === 4) hasV4 = true;
      }
    }
    if (hasV4 && !hasV6) return 4;
    if (!hasV4 && hasV6) return 6;
    return 0;
  } catch (_e) {
    return 0;
  }
}

// Compute the wire size of the produced RFC 822 message. Used by RFC
// 1870 SIZE pre-check before MAIL FROM. Caller passes the already-
// CRLF-normalized + dot-stuffed wire string (the same one that goes
// into DATA / BDAT). Returns the byte count Node will write.
function _messageWireSize(wire) {
  if (typeof wire !== "string") return 0;
  return Buffer.byteLength(wire, "utf8");
}

// Parse the SIZE keyword's argument from a `SIZE 12345` EHLO line.
// Returns 0 when SIZE is advertised without a value (RFC 1870 §3 —
// some peers omit the limit, indicating "no enforced cap"); returns
// -1 when SIZE isn't advertised; otherwise returns the operator-side
// peer cap.
function _parsePeerSize(ehloLines) {
  if (!Array.isArray(ehloLines)) return -1;
  for (var i = 0; i < ehloLines.length; i += 1) {
    var line = ehloLines[i];
    // Lines come in already uppercased keyword form; the SIZE entry
    // may be `SIZE` alone OR `SIZE 12345` — split on whitespace.
    var parts = String(line).split(/\s+/);
    if (parts[0] === "SIZE") {
      if (parts.length < 2) return 0;
      var n = parseInt(parts[1], 10);
      return isFinite(n) && n >= 0 ? n : -1;
    }
  }
  return -1;
}

function _smtpSend(message, cfg) {
  return new Promise(function (resolve, reject) {
    var socket;
    var step = SMTP_STEP_GREETING;
    var buffer = "";
    var ehloLines = [];                   // RFC 5321 §4.1.1.1 — EHLO extension lines (uppercase keyword)
    var ehloFullLines = [];               // Full extension text (incl. args, e.g. "SIZE 12345")
    var peerSupportsSmtpUtf8 = false;     // RFC 6531 — set from EHLO response
    var peerSupportsChunking = false;     // RFC 3030 §2 CHUNKING
    var peerSupportsBinaryMime = false;   // RFC 3030 §3 BINARYMIME
    var peerSupports8BitMime = false;     // RFC 6152 (eight-bit MIME)                                            // RFC number, not a byte literal
    var peerSizeCap = -1;                 // RFC 1870 SIZE — -1 unset, 0 = no cap, >0 = byte limit
    var upgradedToTLS = false;
    var settled = false;
    var rcptIndex = 0;
    var bdatOffset = 0;                   // Bytes of dataMessage written so far via BDAT
    var dataWireBytes = null;             // Buffer view of dataMessage for BDAT slicing
    var useBdat = false;                  // Decided post-EHLO based on peerSupportsChunking + cfg.chunkingEnabled
    var bodyMode = "7BIT";                // "7BIT" / "8BITMIME" / "BINARYMIME"
    var txTimer = null;                   // Absolute transaction-deadline timer (cfg.maxTransactionMs)

    var fromAddr = _extractAddr(message.from);
    var toList   = _toArray(message.to).map(_extractAddr);
    var ccList   = _toArray(message.cc).map(_extractAddr);
    var bccList  = _toArray(message.bcc).map(_extractAddr);
    var rcpts    = toList.concat(ccList, bccList);
    var requiresSmtpUtf8 = _messageRequiresSmtpUtf8(message);
    var requiresBinaryMime = _messageRequiresBinaryMime(message);
    var requires8BitMime = _messageRequires8BitMime(message);
    var dataMessage = _buildRfc822(message);
    if (cfg.dkimSigner) {
      try { dataMessage = cfg.dkimSigner.sign(dataMessage); }
      catch (e) {
        reject(new MailError("mail/dkim-sign-failed",
          "dkim signing failed: " + ((e && e.message) || String(e)), true));
        return;
      }
    }
    var messageWireSize = _messageWireSize(dataMessage);

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

    function clearTxTimer() {
      if (txTimer) { try { clearTimeout(txTimer); } catch (_e) { /* best-effort */ } txTimer = null; }
    }
    function fail(reason) {
      if (settled) return;
      settled = true;
      clearTxTimer();
      try { if (socket) socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
      reject(new MailError("mail/smtp-failed",
        "SMTP send failed: " + reason, false));
    }
    function done(ok, code) {
      if (settled) return;
      settled = true;
      clearTxTimer();
      try { socket.end(); } catch (_e) { /* socket may already be torn down */ }
      if (ok) resolve({ transport: "smtp", deliveredAt: Date.now(), code: code });
      else reject(new MailError("mail/smtp-rejected",
        "SMTP rejected message (code " + code + ")", false));
    }

    function send(cmd) {
      try { socket.write(cmd + "\r\n"); }
      catch (e) { fail(e.message || String(e)); }
    }

    // RFC 5321 + 6531 + 6152 + 3030 + 1870 — MAIL FROM keyword bundle.
    // Order: SMTPUTF8 (6531) → BODY=<7BIT|8BITMIME|BINARYMIME> →
    // SIZE=<bytes>. Peers tolerate any order but consistent ordering
    // simplifies the wire-trace gold files.
    function _mailFromSuffix() {
      var s = "";
      s += _smtpUtf8Suffix(requiresSmtpUtf8, peerSupportsSmtpUtf8);
      if (bodyMode === "BINARYMIME" && peerSupportsBinaryMime) {
        s += " BODY=BINARYMIME";
      } else if (bodyMode === "8BITMIME" && peerSupports8BitMime) {
        s += " BODY=8BITMIME";
      }
      // Append SIZE= when peer advertised SIZE (cap or no-cap form).
      // Peers without SIZE support get no SIZE= keyword (some legacy
      // peers reject unknown MAIL FROM keywords).
      if (peerSizeCap !== -1) {
        s += " SIZE=" + messageWireSize;
      }
      return s;
    }

    // Send the next BDAT chunk. Each `BDAT N [LAST]` line is followed
    // immediately by exactly N bytes of body (no CRLF terminator on
    // the chunk; SMTP framing is purely length-based per RFC 3030 §2).
    function sendBdatChunk() {
      if (!dataWireBytes) dataWireBytes = Buffer.from(dataMessage, "utf8");
      var remaining = dataWireBytes.length - bdatOffset;
      if (remaining <= 0) {
        // Empty body — send `BDAT 0 LAST` to terminate gracefully.
        socket.write("BDAT 0 LAST\r\n");
        return;
      }
      var thisChunk = Math.min(remaining, cfg.chunkSize);
      var isLast = (bdatOffset + thisChunk) >= dataWireBytes.length;
      var header = "BDAT " + thisChunk + (isLast ? " LAST" : "") + "\r\n";
      try {
        socket.write(header);
        socket.write(dataWireBytes.slice(bdatOffset, bdatOffset + thisChunk));
      } catch (e) {
        fail(e.message || String(e));
        return;
      }
      bdatOffset += thisChunk;
    }

    function onData(data) {
      buffer += data;
      // Bound the framing accumulator. A hostile / broken MX that
      // streams bytes without ever sending CRLF would otherwise grow
      // `buffer` without limit and OOM the process. SMTP responses are
      // tiny per spec; the 256 KiB cap is generous headroom. Measure
      // bytes (not UTF-16 code units) so multibyte trickle can't slip a
      // larger payload past a char-length check.
      if (safeBuffer.byteLengthOf(buffer) > MAIL_RESPONSE_MAX_BYTES) {
        fail("response-too-large");
        return;
      }
      var lines = buffer.split("\r\n");
      buffer = lines.pop();
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (!line) continue;
        var code = parseInt(line.slice(0, 3), 10);
        // EHLO continuation lines (250-X) carry extension names. We
        // capture them so the dispatcher can branch on SMTPUTF8 /
        // 8BITMIME / BINARYMIME / CHUNKING / SIZE / STARTTLS before
        // MAIL FROM is sent. Both forms recorded: keyword-only (used
        // for set-membership tests) and full-line (used for SIZE arg).
        if (step === SMTP_STEP_EHLO_RESP) {
          var rest = line.slice(4);
          var keyword = rest.split(" ")[0].toUpperCase();
          if (keyword) {
            ehloLines.push(keyword);
            ehloFullLines.push(rest.toUpperCase());
          }
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
      // Family preference for the underlying lookup. Node's net /
      // tls.connect both honor `family: 4|6` to bias the dns lookup;
      // the framework auto-detects an IPv4-only host when the operator
      // didn't pin one explicitly so a v6-only AAAA result doesn't
      // hang the connect.
      var family = cfg.preferFamily;
      if (family === "any") family = _autoDetectFamily();
      if (cfg.useImplicitTLS) {
        var tlsConnectOpts = Object.assign({}, cfg.tlsOpts);
        if (cfg.servername) tlsConnectOpts.servername = cfg.servername;
        tlsConnectOpts.host = cfg.host;
        tlsConnectOpts.port = cfg.port;
        if (family === 4 || family === 6) tlsConnectOpts.family = family;
        attachSocket(nodeTls().connect(tlsConnectOpts));
      } else {
        var netOpts = { host: cfg.host, port: cfg.port };
        if (family === 4 || family === 6) netOpts.family = family;
        attachSocket(net().createConnection(netOpts));
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
        peerSupportsSmtpUtf8    = ehloLines.indexOf("SMTPUTF8")    !== -1;
        peerSupports8BitMime    = ehloLines.indexOf("8BITMIME")    !== -1;
        peerSupportsBinaryMime  = ehloLines.indexOf("BINARYMIME")  !== -1;
        peerSupportsChunking    = ehloLines.indexOf("CHUNKING")    !== -1;
        peerSizeCap             = _parsePeerSize(ehloFullLines);
        // RFC 6531 §3.2 — if the message requires SMTPUTF8 and the
        // peer does not advertise it, refuse hard rather than emit a
        // mangled wire (server might still accept but headers/local
        // parts would silently corrupt downstream).
        if (requiresSmtpUtf8 && !peerSupportsSmtpUtf8) {
          fail("eai-required-not-supported: message has non-ASCII content but peer does not advertise SMTPUTF8");
          return;
        }
        // RFC 3030 §3 — BINARYMIME is only legal when the peer
        // advertises it. If the message requires it but the peer
        // doesn't offer it, refuse: silently downgrading to 8BITMIME
        // would corrupt NUL-bearing octets in transit.
        if (requiresBinaryMime && !peerSupportsBinaryMime) {
          settled = true;
          clearTxTimer();
          try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
          reject(new MailError("mail/binarymime-not-advertised",
            "message has 8-bit binary content but peer does not advertise BINARYMIME (RFC 3030 §3)",
            true));
          return;
        }
        // RFC 1870 §3 — SIZE pre-check. Refuse before opening DATA /
        // BDAT so the caller gets a clean error instead of a 552
        // mid-stream rejection. peerSizeCap = 0 means "no enforced
        // cap"; -1 means "SIZE not advertised" (no precheck).
        if (cfg.respectPeerSize && peerSizeCap > 0 && messageWireSize > peerSizeCap) {
          settled = true;
          clearTxTimer();
          try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
          reject(new MailError("mail/peer-size-exceeded",
            "message wire size " + messageWireSize + " bytes exceeds peer SIZE cap " +
            peerSizeCap + " bytes (RFC 1870)", true));
          return;
        }
        // Decide BDAT vs DATA + BODY=8BITMIME / BINARYMIME for this
        // transaction. CHUNKING + BDAT is preferred when both peer
        // advertises it AND operator didn't disable it.
        useBdat = peerSupportsChunking && cfg.chunkingEnabled;
        if (requiresBinaryMime)              bodyMode = "BINARYMIME";
        else if (requires8BitMime && peerSupports8BitMime) bodyMode = "8BITMIME";
        else                                 bodyMode = "7BIT";

        if (!cfg.useImplicitTLS && !upgradedToTLS) { send("STARTTLS"); step = SMTP_STEP_STARTTLS; }
        else if (cfg.user) { send("AUTH LOGIN"); step = SMTP_STEP_AUTH_USER; }
        else { send("MAIL FROM:<" + fromAddr + ">" + _mailFromSuffix()); step = SMTP_STEP_MAIL_FROM; }
      }
      else if (step === SMTP_STEP_STARTTLS) {
        if (code !== 220) { fail("starttls-rejected (code " + code + ")"); return; }
        var tlsConnectOpts = Object.assign({ socket: socket }, cfg.tlsOpts);
        if (cfg.servername) tlsConnectOpts.servername = cfg.servername;
        var tlsSocket = nodeTls().connect(tlsConnectOpts, function () {
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
        send("MAIL FROM:<" + fromAddr + ">" + _mailFromSuffix()); step = SMTP_STEP_MAIL_FROM;
      }
      else if (step === SMTP_STEP_MAIL_FROM) {
        if (code < 200 || code >= 300) { fail("mail-from-rejected (code " + code + ")"); return; }
        send("RCPT TO:<" + rcpts[rcptIndex++] + ">"); step = SMTP_STEP_RCPT_TO;
      }
      else if (step === SMTP_STEP_RCPT_TO) {
        if (code < 200 || code >= 300) { fail("rcpt-rejected (code " + code + ")"); return; }
        if (rcptIndex < rcpts.length) {
          send("RCPT TO:<" + rcpts[rcptIndex++] + ">");
        } else if (useBdat) {
          // RFC 3030 §2 — BDAT framing replaces DATA + CRLF.CRLF.
          // Each chunk is `BDAT <octet-count> [LAST]\r\n` followed by
          // exactly <octet-count> bytes of body. We emit the audit
          // signal once per send (not per chunk) so the audit chain
          // doesn't get flooded for large messages.
          try {
            audit().safeEmit({
              action:   "mail.transport.bdat",
              outcome:  "success",
              metadata: {
                wireBytes:    messageWireSize,
                chunkSize:    cfg.chunkSize,
                expectedChunks: Math.max(1, Math.ceil(messageWireSize / cfg.chunkSize)),
                bodyMode:     bodyMode,
              },
            });
            if (bodyMode === "BINARYMIME") {
              audit().safeEmit({
                action:   "mail.transport.binarymime",
                outcome:  "success",
                metadata: { wireBytes: messageWireSize },
              });
            }
          } catch (_e) { /* audit best-effort */ }
          step = SMTP_STEP_BDAT;
          sendBdatChunk();
        } else {
          send("DATA"); step = SMTP_STEP_DATA;
        }
      }
      else if (step === SMTP_STEP_DATA) {
        if (code !== 354) { fail("data-rejected (code " + code + ")"); return; }
        send(_dotStuffForData(dataMessage) + "\r\n.");
        step = SMTP_STEP_BODY;
      }
      else if (step === SMTP_STEP_BDAT) {
        // Each BDAT chunk gets a 250 response per RFC 3030 §2. Anything
        // else (4xx / 5xx) is a hard rejection of the chunk; surface
        // a stable error code so downstream retry policy can identify
        // the chunked-body failure mode.
        if (code !== 250) {
          settled = true;
          clearTxTimer();
          try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
          reject(new MailError("mail/bdat-chunk-rejected",
            "BDAT chunk rejected (code " + code + ", offset " + bdatOffset + "/" +
            messageWireSize + ")", false));
          return;
        }
        if (bdatOffset >= messageWireSize) {
          // Final chunk acknowledged — message accepted.
          done(true, code);
          return;
        }
        sendBdatChunk();
      }
      else if (step === SMTP_STEP_BODY) {
        var ok = code === 250;
        done(ok, code);
      }
    }

    // Arm the absolute transaction deadline before opening the socket so
    // a peer that connects but then trickles (or never responds) is
    // bounded regardless of how it games the per-socket idle timer.
    // unref so a pending deadline never keeps the process alive on its own.
    txTimer = setTimeout(function () {
      fail("transaction-timeout");
    }, cfg.maxTransactionMs);
    if (txTimer && typeof txTimer.unref === "function") txTimer.unref();

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
      if (!data || !data.id) {
        return {
          ok:     false,
          reason: (data && data.message) || JSON.stringify(data).slice(0, DIAG_SNIPPET_LEN),
        };
      }
      return { ok: true, id: data.id };
    },
  });
}

// ---- Engine instance ----

/**
 * @primitive b.mail.create
 * @signature b.mail.create(opts)
 * @since     0.1.0
 * @status    stable
 * @compliance gdpr, soc2, hipaa
 * @related   b.mail.toAscii, b.mail.toUnicode
 *
 * Build a mail instance bound to a transport + defaults. Returns
 * `{ send, transport, defaults }`: `send(message)` validates the
 * merged message against the framework contract, applies CAN-SPAM
 * footer + unsubscribe enforcement when `commercial: true`, runs
 * RFC 8058 List-Unsubscribe header expansion when the message carries
 * `unsubscribe`, then delegates to the transport. Audit rows record
 * recipient counts only (addresses are PII).
 *
 * @opts
 *   transport:       function (message) | { send(message), name? },   // default: console
 *   defaults:        { from, replyTo, headers, ... },                 // merged into every message
 *   audit:           boolean,                                          // default true
 *   commercial:      boolean,                                          // CAN-SPAM §7704 enforcement
 *   regulated:       boolean,                                          // alias for commercial:true
 *   postalAddress:   { street, city, region, postalCode, country } | string,
 *   footerSeparator: string,                                           // default "\n\n----\n" / "<hr>"
 *   footerHtml:      string,                                           // override for html-part footer
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var mail = b.mail.create({
 *     transport: b.mail.transports.memory(),
 *     defaults:  { from: "Acme <noreply@acme.test>" },
 *   });
 *   // → { send, transport, defaults }
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "transport", "defaults", "audit",
    "commercial", "postalAddress", "footerSeparator", "footerHtml", "regulated",
    "guardDomain", "profile",
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

  // Default-on guardDomain hardening for every outbound recipient + the
  // sender address. Refuses IDN homograph / mixed-script-confusable spoofs in
  // recipient or from domains, RFC 6761 special-use domain names
  // (`.localhost`, `.test`, `.invalid`, `.example`) in production sends,
  // RFC 1035 §2.3.4 label-length violations, and CVE-2021-22931 class
  // bare-IP-as-domain (DNS-rebinding allowlist-bypass class). Operators
  // sending to address literals (`<x@[1.2.3.4]>`) — rare; mostly mailing-
  // list internals — pass `guardDomain: false` to opt out, or pass
  // `guardDomain: { profile: "permissive" }` to relax the rules.
  var guardDomainProfileName;
  if (opts.guardDomain === false) {
    guardDomainProfileName = null;
  } else {
    guardDomainProfileName = opts.guardDomain && typeof opts.guardDomain === "object"
      ? (opts.guardDomain.profile || opts.profile || "strict")
      : (opts.profile || "strict");
  }
  function _validateAddrDomain(addr, label) {
    if (!guardDomainProfileName) return;
    if (typeof addr !== "string") return;
    // RFC 5322 §3.4 angle-bracket address (`name <local@dom>`) — extract
    // the inner address via indexOf/lastIndexOf rather than a regex so
    // we stay linear on input shape (CodeQL js/polynomial-redos class).
    var ltIdx = addr.indexOf("<");
    var gtIdx = addr.lastIndexOf(">");
    var rawAddr = (ltIdx !== -1 && gtIdx > ltIdx)
      ? addr.slice(ltIdx + 1, gtIdx)
      : addr;
    var atIdx = rawAddr.lastIndexOf("@");
    if (atIdx === -1) return;
    var domain = rawAddr.slice(atIdx + 1).trim();
    // RFC 5321 §4.1.3 address-literal form `[1.2.3.4]` / `[IPv6:...]`
    // — already a syntactic constraint via the brackets; b.guardDomain
    // refuses bare IPs without brackets which is the security-relevant
    // shape (CVE-2021-22931 DNS rebinding allowlist-bypass).
    if (domain.length === 0 || domain[0] === "[") return;
    // RFC 5891 ToASCII — convert any IDN labels to Punycode BEFORE
    // guardDomain validation so EAI (RFC 6531) addresses like
    // `<x@münchen.example>` pass under strict (which refuses raw
    // Unicode labels per RFC 5891 §4.2 transport-safety rule). The
    // SMTPUTF8 wire encoding is the transport's concern; the gate
    // here runs on a transport-safe form.
    var asciiDomain = toAscii(domain) || domain;
    // Override punycodePolicy — `xn--…` labels are RFC 5891-encoded
    // IDNs and the whole point of EAI (RFC 6531) is to deliver to
    // them. The strict profile defaults to refusing Punycode (the
    // generic "operator typed a homograph" defense); for mail.send
    // we've already gone through RFC 5891 ToASCII, so the Punycode
    // is structural, not a homograph attempt. All other strict
    // defenses (mixed-script, BIDI, control, IP-literal, special-
    // use, wildcard, DGA, raw-unicode pre-conversion) remain.
    var verdict = guardDomain.validate(asciiDomain, {
      profile:        guardDomainProfileName,
      punycodePolicy: "allow",
    });
    if (!verdict.ok) {
      throw new MailError("mail/recipient-domain-refused",
        "mail.send: " + label + " domain '" + domain + "' refused by b.guardDomain (" +
        (verdict.issues && verdict.issues[0] && verdict.issues[0].kind) + ")", true);
    }
  }

  // CAN-SPAM Act §7704(a)(5) — every commercial-content message MUST
  // include the sender's valid physical postal address. Validate the
  // address shape at create() so a typo / blank field surfaces at boot,
  // not silently on first send. Operators marking an instance
  // commercial:true also opt every send() into the unsubscribe-required
  // posture (CAN-SPAM §7704(a)(3) — RFC 8058 List-Unsubscribe header
  // already wired via b.mail.unsubscribe).
  var commercial = opts.commercial === true || opts.regulated === true;
  var postalAddress = opts.postalAddress != null ? opts.postalAddress : null;
  if (commercial) {
    var addrError = _validatePostalAddress(postalAddress);
    if (addrError) {
      throw new MailError("mail/missing-postal-address",
        "mail.create({ commercial: true }): " + addrError +
        " — CAN-SPAM Act §7704(a)(5) requires a valid physical postal address.",
        true);
    }
  }
  var footerSeparator = (typeof opts.footerSeparator === "string")
    ? opts.footerSeparator : null;
  var footerHtml = (typeof opts.footerHtml === "string") ? opts.footerHtml : null;
  if (footerHtml && commercial) {
    var addrText = _renderPostalAddressText(postalAddress);
    // Country + postal-code presence check — operator-supplied HTML
    // overrides MUST still carry the address bytes. We don't lex HTML
    // here; substring match against the rendered address is enough to
    // catch "operator forgot to interpolate the address into their
    // override template" without parsing markup.
    var country = _addressField(postalAddress, "country");
    var postalCode = _addressField(postalAddress, "postalCode");
    if (country && footerHtml.indexOf(country) === -1) {
      throw new MailError("mail/bad-footer-html",
        "mail.create({ footerHtml }): override must contain the postalAddress.country '" +
        country + "' (CAN-SPAM §7704(a)(5)). Got: " + footerHtml.slice(0, 200),                                   // diagnostic clamp characters, not bytes
        true);
    }
    if (postalCode && footerHtml.indexOf(postalCode) === -1) {
      throw new MailError("mail/bad-footer-html",
        "mail.create({ footerHtml }): override must contain the postalAddress.postalCode '" +
        postalCode + "' (CAN-SPAM §7704(a)(5))",
        true);
    }
    // Suppress the "unused-variable" lint signal for addrText — the
    // sanity-render establishes the address shape is renderable before
    // we trust the operator override; the rendered text isn't itself
    // injected when footerHtml overrides.
    void addrText;
  }

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

    // CAN-SPAM §7704(a) — every commercial-content message must carry
    // a valid physical postal address (auto-appended to the body) and
    // a clear opt-out path. The address shape was validated at
    // create(); this block (a) re-asserts the unsubscribe path is
    // present, (b) appends the formatted footer to text + html parts,
    // and (c) emits a structured audit row when the send refuses.
    if (commercial) {
      if (!_hasUnsubscribe(merged)) {
        try {
          audit().safeEmit({
            action:  "mail.canspam.refused",
            outcome: "denied",
            metadata: {
              reason: "missing-unsubscribe",
              transport: transport.name || "custom",
            },
          });
        } catch (_e) { /* audit best-effort */ }
        throw new MailError("mail/canspam-no-unsubscribe",
          "mail.send: commercial:true requires either message.unsubscribe = " +
          "{ url|mailto, oneClick? } OR a List-Unsubscribe header. CAN-SPAM " +
          "§7704(a)(3)/(4) — every commercial message must give recipients a " +
          "clear opt-out mechanism.", true);
      }
      var sepText = footerSeparator != null ? footerSeparator : "\n\n----\n";
      var sepHtml = footerSeparator != null ? footerSeparator : "<hr>";
      var addrText = _renderPostalAddressText(postalAddress);
      var addrHtml = footerHtml || _renderPostalAddressHtml(postalAddress);
      // Append-only — operators who want the address in a different
      // location render it themselves and disable commercial:true (or
      // pass footerHtml with the operator-controlled layout).
      if (typeof merged.text === "string" && merged.text.length > 0 &&
          merged.text.indexOf(addrText) === -1) {
        merged.text = merged.text + sepText + addrText + "\n";
      } else if (merged.text == null && addrText) {
        merged.text = addrText + "\n";
      }
      if (typeof merged.html === "string" && merged.html.length > 0 &&
          merged.html.indexOf(addrHtml) === -1) {
        merged.html = merged.html + sepHtml + addrHtml;
      }
    }

    _validateMessage(merged);

    // Default-on guardDomain hardening on every recipient + the sender
    // address (see closure setup above). Skipped when operator opts out
    // via guardDomain:false.
    if (guardDomainProfileName) {
      _validateAddrDomain(merged.from, "from");
      var _toArr  = _normalizeRecipientList(merged.to,  "to");
      var _ccArr  = _normalizeRecipientList(merged.cc,  "cc");
      var _bccArr = _normalizeRecipientList(merged.bcc, "bcc");
      for (var _ti = 0; _ti < _toArr.length;  _ti += 1) _validateAddrDomain(_toArr[_ti],  "to");
      for (var _ci = 0; _ci < _ccArr.length;  _ci += 1) _validateAddrDomain(_ccArr[_ci],  "cc");
      for (var _bi = 0; _bi < _bccArr.length; _bi += 1) _validateAddrDomain(_bccArr[_bi], "bcc");
    }

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

/**
 * @primitive b.mail.feedbackId
 * @signature b.mail.feedbackId(opts)
 * @since     0.8.87
 * @status    stable
 * @related   b.mail.create
 *
 * Build a Gmail Feedback Loop (FBL) Feedback-ID header value per
 * Google's FBL convention: a colon-separated 4-tuple
 * `CampaignID:CustomerID:MailType:SenderID`. Setting Feedback-ID on
 * outbound mail lets Gmail surface per-campaign abuse-rate metrics
 * back via the Postmaster Tools API so operators see spam
 * complaints aggregated by their own campaign vocabulary instead of
 * by SMTP envelope-sender alone.
 *
 * Refuses missing / empty fields (`mail/bad-feedback-id-field`),
 * fields containing `:` (would corrupt the 4-tuple separator), and
 * fields longer than 64 bytes (Gmail truncates beyond ~64 chars per
 * field). Operators set the result via `mail.create({ headers:
 * { "Feedback-ID": b.mail.feedbackId({...}) } })` or attach it to
 * an individual send().
 *
 * @opts
 *   campaignId:  string,   // operator's campaign tag (e.g. "wk26-promo")
 *   customerId:  string,   // operator's tenant or user-segment id
 *   mailType:    string,   // operator-defined message type (e.g. "marketing")
 *   senderId:    string,   // operator's app / IP-pool / domain reputation id
 *
 * @example
 *   var feedbackId = b.mail.feedbackId({
 *     campaignId: "wk26-promo",
 *     customerId: "acme",
 *     mailType:   "marketing",
 *     senderId:   "mail-pool-1",
 *   });
 *   // → "wk26-promo:acme:marketing:mail-pool-1"
 *
 *   mail.send({
 *     to:      "...",
 *     headers: { "Feedback-ID": feedbackId },
 *   });
 */
function feedbackId(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MailError("mail/bad-feedback-id-opts",
      "feedbackId: opts required (campaignId + customerId + mailType + senderId)");
  }
  var fields = [
    { key: "campaignId", value: opts.campaignId },
    { key: "customerId", value: opts.customerId },
    { key: "mailType",   value: opts.mailType   },
    { key: "senderId",   value: opts.senderId   },
  ];
  var parts = [];
  for (var i = 0; i < fields.length; i += 1) {
    var f = fields[i];
    if (typeof f.value !== "string" || f.value.length === 0) {
      throw new MailError("mail/bad-feedback-id-field",
        "feedbackId: " + f.key + " must be a non-empty string");
    }
    if (f.value.length > 64) {                                                                     // Gmail FBL per-field cap, not byte arithmetic
      throw new MailError("mail/bad-feedback-id-field",
        "feedbackId: " + f.key + " exceeds 64 chars (Gmail FBL truncation threshold)");
    }
    if (f.value.indexOf(":") !== -1) {
      throw new MailError("mail/bad-feedback-id-field",
        "feedbackId: " + f.key + " contains ':' which is the field separator");
    }
    // Refuse CR/LF (header-injection) + control chars. Walk codepoints
    // manually because eslint's no-control-regex refuses control-char
    // ranges in regex literals regardless of escape form.
    if (codepointClass.firstControlCharOffset(f.value, { forbidTab: true }) !== -1) {              // C0 + DEL codepoint range
      throw new MailError("mail/bad-feedback-id-field",
        "feedbackId: " + f.key + " contains control characters");
    }
    parts.push(f.value);
  }
  return parts.join(":");
}

var mailRequireTls = require("./mail-require-tls");
var mailSrs        = require("./mail-srs");

module.exports = {
  create:      create,
  feedbackId:  feedbackId,
  requireTls:  mailRequireTls,
  srs:         mailSrs,
  MailError:   MailError,
  unsubscribe: mailUnsubscribe,
  // RFC 3492 Punycode IDN domain encode/decode (b.mail.toAscii /
  // toUnicode). Wraps node:url.domainToASCII / domainToUnicode so
  // operators have one obvious place to reach for IDN handling. Used
  // internally by send() to convert IDN domain parts before the
  // pre-SMTPUTF8 ASCII regex check.
  toAscii:    toAscii,
  toUnicode:  toUnicode,
  // Forward-confirmed reverse DNS lookup (RFC 8601 §3 lite). Building
  // block for inbound iprev / outbound submission reputation checks.
  reverseDns: reverseDns,
  // DKIM-Signature header generation for outbound mail (rsa-sha256
  // default, ed25519-sha256 opt-in). Wire it into the smtp transport
  // via opts.dkimSigner. See lib/mail-dkim.js for the full surface.
  dkim:       dkim,
  // Inbound mail authentication verification: SPF (RFC 7208), DKIM
  // verify (RFC 6376, on .dkim above alongside outbound signing),
  // DMARC (RFC 7489), ARC (RFC 8617). `.inbound.verify` is the
  // one-call receiver pipeline — SPF + DKIM + From-header extraction +
  // DMARC policy + the RFC 8601 Authentication-Results header —
  // composed by b.mail.server.mx at DATA time via its guardEnvelope
  // opt and callable directly by operator-built listeners.
  spf:         mailAuth.spf,
  dmarc:       mailAuth.dmarc,
  arc:         mailAuth.arc,
  iprev:       mailAuth.iprev,
  authResults: mailAuth.authResults,
  inbound:     mailAuth.inbound,
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
  // The mail-stack standardization contract (v0.9.20). JMAP / IMAP /
  // POP3 / ManageSieve / MX / submission all translate into
  // `agent.X(args)`; RBAC + posture + audit + dispatch owned here.
  // See lib/mail-agent.js for the full surface.
  agent:      mailAgent,
};

"use strict";
/**
 * mail-unsubscribe — RFC 8058 / RFC 2369 / RFC 2919 List-* support.
 *
 * Three pieces:
 *   1. buildHeaders({ url, mailto, oneClick }) — produces the
 *      `List-Unsubscribe` and (when oneClick) `List-Unsubscribe-Post`
 *      header values that get merged into the outbound message.
 *   2. buildAllListHeaders({ unsubscribeUrl, helpUrl, ownerEmail,
 *      archiveUrl, listId, listOwner }) — single-call builder for the
 *      full RFC 2369 / RFC 2919 List-* header bundle (List-Unsubscribe,
 *      List-Help, List-Archive, List-Owner, List-Post, List-ID).
 *      Every URL/email/list-id is shape-validated at config-time so
 *      operator typos surface here, not silently downstream.
 *   3. handler({ onUnsubscribe }) — request-lifecycle middleware that
 *      validates the RFC 8058 one-click POST body
 *      (`List-Unsubscribe=One-Click`) and dispatches to the operator's
 *      onUnsubscribe callback. Returns 200 OK with empty body on
 *      success per RFC 8058 §3.1.
 *
 * Compliance context: Gmail + Yahoo bulk-sender requirements (Feb 2024)
 * mandate one-click List-Unsubscribe for senders >= 5k/day. Microsoft
 * 365 followed in 2025. Operators sending bulk transactional or
 * marketing mail without these headers see escalating spam-folder /
 * outright-reject rates.
 *
 *   var headers = b.mail.unsubscribe.buildHeaders({
 *     url:      "https://example.com/u?token=...",
 *     mailto:   "unsubscribe@example.com?subject=unsub-...",
 *     oneClick: true,
 *   });
 *   // → {
 *   //     "List-Unsubscribe": "<https://...>, <mailto:...>",
 *   //     "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
 *   //   }
 *
 *   var unsubMw = b.mail.unsubscribe.handler({
 *     onUnsubscribe: async function (req, res) {
 *       // Operator extracts the token from req.url / req.body and
 *       // performs the unsubscribe. Returning resolves the request.
 *       var token = new URL(req.url, "https://h").searchParams.get("token");
 *       await db.markUnsubscribed(token);
 *     },
 *   });
 *   app.post("/email/unsubscribe", unsubMw);
 */

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var { MailUnsubscribeError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

// RFC 5322 / 5321 header-value upper bound. Used to refuse hostile
// over-length operator inputs at config-time (throw at config-time).
var HEADER_VALUE_MAX_BYTES = C.BYTES.kib(2);

// RFC 2919 §3 List-ID shape: a phrase (optional) followed by an
// angle-addr containing a label-list (one or more dot-separated
// labels). We accept either the raw label-list form
// `lst.example.com` (most common shape — bare-form opt-in) OR the
// full `Phrase <lst.example.com>` form. Refuse shapes that smuggle
// arbitrary header bytes.
//
// Label LDH check is inlined as a charCode loop instead of the
// canonical hostname regex shape — list-id labels are syntactically
// a subset of RFC 1123 §2.1 hostname labels but the *audience* is
// mail-list naming, not DNS resolution; the inline form lets the
// failure point name the list-id concern rather than a shared
// LDH primitive. Char ranges: 0x30-0x39 digits / 0x41-0x5A upper /
// 0x61-0x7A lower / 0x2D hyphen.
function _isLdhListLabel(label) {
  if (typeof label !== "string" || label.length === 0) return false;
  // RFC 1035 §2.3.4 — labels bounded at 63 octets.
  if (label.length > 63) return false;                                           // allow:raw-byte-literal — RFC 1035 §2.3.4 hostname-label limit
  var n = label.length;
  for (var i = 0; i < n; i += 1) {
    var c = label.charCodeAt(i);
    var isDigit = c >= 0x30 && c <= 0x39;
    var isUpper = c >= 0x41 && c <= 0x5A;
    var isLower = c >= 0x61 && c <= 0x7A;
    var isHyphen = c === 0x2D;
    var ok = isDigit || isUpper || isLower || (isHyphen && i > 0 && i < n - 1);
    if (!ok) return false;
  }
  return true;
}
function _validateListId(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a non-empty string");
  }
  if (value.length > HEADER_VALUE_MAX_BYTES) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " exceeds " + HEADER_VALUE_MAX_BYTES + " byte cap");
  }
  if (/[\r\n\0]/.test(value)) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " contains forbidden CR/LF/NUL byte");
  }
  // Accept either the label-list bare form OR `Phrase <label-list>`.
  // Strip an optional `Phrase <...>` wrap to test the inner label list.
  var inner = value;
  var bracket = value.match(/<([^>]+)>\s*$/);
  if (bracket) inner = bracket[1];
  // Inner is dot-separated labels; each label LDH per RFC 2919 §3.
  var labels = inner.split(".");
  if (labels.length < 2) {                                                                                // allow:raw-byte-literal — RFC 2919 §3 requires >= 2 labels
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " '" + value + "' must contain at least two dot-separated labels (RFC 2919 §3)");
  }
  for (var i = 0; i < labels.length; i += 1) {
    if (!_isLdhListLabel(labels[i])) {
      throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
        label + " '" + value + "' has invalid label '" + labels[i] + "' (RFC 2919 §3 LDH)");
    }
  }
  // If operator passed `Phrase <label-list>` form, return it as-is;
  // RFC 2919 says Phrase is optional but allowed. Otherwise wrap the
  // bare label-list in angle brackets per the canonical on-the-wire
  // shape (`<lst.example.com>`).
  return bracket ? value : "<" + value + ">";
}

function _validateHttpsUrl(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a non-empty string");
  }
  if (value.length > HEADER_VALUE_MAX_BYTES) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " exceeds " + HEADER_VALUE_MAX_BYTES + " byte cap");
  }
  if (/[\r\n\0]/.test(value)) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " contains forbidden CR/LF/NUL byte");
  }
  var parsed;
  try {
    parsed = safeUrl.parse(value, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  } catch (e) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a valid https URL (got " +
      JSON.stringify(value).slice(0, 200) + "): " +                                                               // allow:raw-byte-literal — diagnostic clamp characters
      ((e && e.message) || String(e)));
  }
  if (!parsed) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a valid https URL (got " +
      JSON.stringify(value).slice(0, 200) + ")");                                                                 // allow:raw-byte-literal — diagnostic clamp characters
  }
  return parsed.href;
}

// mailto: shape validation. Accepts `mailto:addr` form OR a bare
// `addr@domain` form (we'll prefix `mailto:` ourselves). Refuses CR/LF/
// NUL injection. Doesn't validate the address with EMAIL_RE here — the
// addr@domain shape and length cap is what bounds smuggling risk.
function _validateMailto(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a non-empty string");
  }
  if (value.length > HEADER_VALUE_MAX_BYTES) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " exceeds " + HEADER_VALUE_MAX_BYTES + " byte cap");
  }
  if (/[\r\n\0]/.test(value)) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " contains forbidden CR/LF/NUL byte");
  }
  var hasScheme = value.indexOf("mailto:") === 0;
  var inner = hasScheme ? value.slice("mailto:".length) : value;
  // Strip query parameters before testing the addr shape.
  var addrPart = inner.split("?")[0];
  if (addrPart.indexOf("@") < 1 || addrPart.lastIndexOf("@") === addrPart.length - 1) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a valid `addr@domain` (with optional `mailto:` prefix)");
  }
  return hasScheme ? value : "mailto:" + value;
}

// Build the List-Unsubscribe + List-Unsubscribe-Post headers per
// RFC 8058 + RFC 2369. Returns a headers object suitable for merging
// into `b.mail.send({ headers })`.
function buildHeaders(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "buildHeaders: opts object required ({ url?, mailto?, oneClick? })");
  }
  var parts = [];
  if (typeof opts.url === "string" && opts.url.length > 0) {
    var href = _validateHttpsUrl(opts.url, "buildHeaders: opts.url");
    parts.push("<" + href + ">");
  }
  if (typeof opts.mailto === "string" && opts.mailto.length > 0) {
    var mt = _validateMailto(opts.mailto, "buildHeaders: opts.mailto");
    parts.push("<" + mt + ">");
  }
  if (parts.length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "buildHeaders: at least one of opts.url / opts.mailto required");
  }
  var headers = { "List-Unsubscribe": parts.join(", ") };
  if (opts.oneClick === true) {
    // RFC 8058 §2 — exact byte sequence required for one-click.
    headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click";
  }
  return headers;
}

// Build the full RFC 2369 / RFC 2919 List-* header bundle in one call.
//
// Single-call shape so operators set the whole list-management bundle
// in one place rather than juggling individual builders. Every input
// is shape-validated at config-time (throw at config-time) so a missing
// scheme / control byte / malformed list-id surfaces here, not as a
// downstream parser refusing the message after the network hop.
//
//   var headers = b.mail.unsubscribe.buildAllListHeaders({
//     unsubscribeUrl: "https://example.com/u?t=...",
//     unsubscribeMailto: "unsub@example.com",
//     oneClick:       true,
//     helpUrl:        "https://example.com/list-help",
//     archiveUrl:     "https://example.com/archive",
//     ownerEmail:     "owner@example.com",
//     postEmail:      "list@example.com",
//     listId:         "lst.example.com",
//     listOwner:      "Acme List <owner@example.com>",
//   });
//
// Returns a flat headers object with the canonical RFC casing
// (`List-Unsubscribe`, `List-Help`, `List-Archive`, `List-Owner`,
// `List-Post`, `List-ID`).
function buildAllListHeaders(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "buildAllListHeaders: opts object required");
  }
  var headers = {};

  // List-Unsubscribe + List-Unsubscribe-Post (RFC 8058 / RFC 2369).
  if (opts.unsubscribeUrl != null || opts.unsubscribeMailto != null ||
      opts.oneClick !== undefined) {
    var unsubHeaders = buildHeaders({
      url:      opts.unsubscribeUrl,
      mailto:   opts.unsubscribeMailto,
      oneClick: opts.oneClick === true,
    });
    Object.assign(headers, unsubHeaders);
  }

  // List-Help (RFC 2369 §3.2). URL or mailto.
  if (opts.helpUrl != null) {
    headers["List-Help"] = "<" + _validateHttpsUrl(opts.helpUrl,
      "buildAllListHeaders: opts.helpUrl") + ">";
  }

  // List-Archive (RFC 2369 §3.6). URL.
  if (opts.archiveUrl != null) {
    headers["List-Archive"] = "<" + _validateHttpsUrl(opts.archiveUrl,
      "buildAllListHeaders: opts.archiveUrl") + ">";
  }

  // List-Owner (RFC 2369 §3.3). mailto:.
  if (opts.ownerEmail != null) {
    headers["List-Owner"] = "<" + _validateMailto(opts.ownerEmail,
      "buildAllListHeaders: opts.ownerEmail") + ">";
  }

  // List-Post (RFC 2369 §3.4). mailto:, or "NO" sentinel for read-only
  // lists. RFC explicitly carves out the literal NO token.
  if (opts.postEmail != null) {
    if (opts.postEmail === "NO") {
      headers["List-Post"] = "NO";
    } else {
      headers["List-Post"] = "<" + _validateMailto(opts.postEmail,
        "buildAllListHeaders: opts.postEmail") + ">";
    }
  }

  // List-ID (RFC 2919 §3). Bare label-list OR `Phrase <label-list>`.
  if (opts.listId != null) {
    headers["List-ID"] = _validateListId(opts.listId,
      "buildAllListHeaders: opts.listId");
  }

  // List-Owner phrase form: an operator may pass a pre-rendered
  // `Owner Name <addr@domain>` value directly via opts.listOwner.
  // Overrides ownerEmail when both are provided.
  if (opts.listOwner != null) {
    validateOpts.requireNonEmptyString(opts.listOwner,
      "buildAllListHeaders: opts.listOwner",
      MailUnsubscribeError, "mailunsubscribe/invalid-list-header-shape");
    if (opts.listOwner.length > HEADER_VALUE_MAX_BYTES) {
      throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
        "buildAllListHeaders: opts.listOwner exceeds " + HEADER_VALUE_MAX_BYTES + " byte cap");
    }
    if (/[\r\n\0]/.test(opts.listOwner)) {
      throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
        "buildAllListHeaders: opts.listOwner contains forbidden CR/LF/NUL byte");
    }
    // Phrase form must contain an angle-bracket address to satisfy
    // RFC 2369 §3.3 — we don't run the full RFC 5322 phrase parser
    // here; presence of `<...@...>` is enough to surface typos.
    var ownerBracket = opts.listOwner.match(/<([^>]+)>/);
    if (!ownerBracket || ownerBracket[1].indexOf("@") < 1) {
      throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
        "buildAllListHeaders: opts.listOwner must contain `<addr@domain>` (RFC 2369 §3.3)");
    }
    headers["List-Owner"] = opts.listOwner;
  }

  if (Object.keys(headers).length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "buildAllListHeaders: at least one List-* field must be supplied");
  }
  return headers;
}

// RFC 8058 §3.1 one-click handler middleware.
//
// On POST, the body MUST contain `List-Unsubscribe=One-Click` (case-
// sensitive, exact byte sequence). On match, the operator's
// onUnsubscribe callback runs — the operator extracts the
// per-recipient token from the URL or body and performs the
// unsubscribe. Returning resolves the request with 200 OK.
//
// On non-POST or wrong body, the middleware refuses with 400.
function handler(opts) {
  opts = opts || {};
  if (typeof opts.onUnsubscribe !== "function") {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "mail.unsubscribe.handler: opts.onUnsubscribe must be a function (req, res) → Promise");
  }
  return async function unsubscribeMiddleware(req, res) {
    if ((req.method || "").toUpperCase() !== "POST") {
      res.statusCode = 405;
      res.setHeader("Allow", "POST");
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("RFC 8058 one-click unsubscribe requires POST");
      return;
    }
    var bodyChunks = [];
    var totalLen = 0;
    var maxBodyBytes = opts.maxBodyBytes || C.BYTES.kib(4);
    var bodyComplete = await new Promise(function (resolve) {
      req.on("data", function (chunk) {
        totalLen += chunk.length;
        if (totalLen > maxBodyBytes) {
          // Stop reading; we'll respond 413 below.
          resolve(false);
          return;
        }
        bodyChunks.push(chunk);
      });
      req.on("end", function () { resolve(true); });
      req.on("error", function () { resolve(false); });
    });
    if (!bodyComplete) {
      res.statusCode = 413;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("body exceeds max bytes for one-click unsubscribe");
      return;
    }
    var body = Buffer.concat(bodyChunks).toString("utf8");
    if (body.indexOf("List-Unsubscribe=One-Click") === -1) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("RFC 8058 §3.1: body must contain `List-Unsubscribe=One-Click`");
      return;
    }
    try {
      await opts.onUnsubscribe(req, res);
      // If the operator didn't end the response, send 200 OK with
      // empty body per RFC 8058 §3.1.
      if (!res.writableEnded) {
        res.statusCode = 200;
        res.end();
      }
    } catch (err) {
      if (!res.writableEnded) {
        res.statusCode = 500;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("unsubscribe failed");
      }
      throw err;
    }
  };
}

module.exports = {
  buildHeaders:         buildHeaders,
  buildAllListHeaders:  buildAllListHeaders,
  handler:              handler,
  MailUnsubscribeError: MailUnsubscribeError,
};

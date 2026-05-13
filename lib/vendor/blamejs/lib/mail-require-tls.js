"use strict";
/**
 * @module     b.mail.requireTls
 * @nav        Mail
 * @title      REQUIRETLS — RFC 8689
 * @order      460
 *
 * @intro
 *   RFC 8689 SMTP REQUIRETLS — per-message TLS-requirement signaling
 *   between sender and receiver MTAs. The sender advertises that the
 *   message MUST NOT be relayed over a cleartext (non-TLS) hop; if
 *   no downstream MTA can deliver under TLS, the message bounces
 *   instead of falling back to cleartext. Complements MTA-STS / DANE
 *   (which are policy-side, domain-scoped) with a per-message
 *   knob that overrides the policy when the operator wants
 *   stricter-than-policy delivery.
 *
 *   Wire surface (RFC 8689 §3):
 *
 *     EHLO peer advertises:  250 REQUIRETLS
 *     Client sends:          MAIL FROM:<sender> REQUIRETLS
 *     Server replies:        250 OK             (or 550 if it can't honor)
 *
 *   Header surface (RFC 8689 §5):
 *
 *     TLS-Required: No       Explicit operator override; sender
 *                            requests REQUIRETLS-style behavior be
 *                            DISABLED for this message even if the
 *                            policy infrastructure (MTA-STS / DANE)
 *                            says otherwise. Use sparingly — primary
 *                            use case is delivery to legacy peers
 *                            during a controlled migration.
 *
 *   This module ships:
 *
 *     b.mail.requireTls.peerSupports(ehloLines) → boolean
 *       Walks EHLO response lines and returns true when the peer
 *       advertised the REQUIRETLS keyword.
 *
 *     b.mail.requireTls.mailFromExtension({ requireTls }) → string
 *       Returns the trailing " REQUIRETLS" token (or empty string)
 *       to append to a MAIL FROM line.
 *
 *     b.mail.requireTls.parseTlsRequiredHeader(headerValue) → "yes" | "no" | null
 *       Parses the TLS-Required header field per §5. Returns "no"
 *       only when the value is the literal token "no" (case-
 *       insensitive); any other value returns "yes" (the conservative
 *       default — operators must opt OUT explicitly, never default to
 *       fall-back-to-cleartext). null when the header is absent.
 *
 * @card
 *   RFC 8689 REQUIRETLS — per-message TLS-requirement signaling between MTAs (EHLO keyword + MAIL FROM extension + TLS-Required header parser).
 */

var structuredFields = require("./structured-fields");
var validateOpts     = require("./validate-opts");
var { defineClass } = require("./framework-error");

var RequireTlsError = defineClass("RequireTlsError", { alwaysPermanent: true });

var REQUIRETLS_TOKEN = "REQUIRETLS";

/**
 * @primitive b.mail.requireTls.peerSupports
 * @signature b.mail.requireTls.peerSupports(ehloLines)
 * @since     0.8.90
 * @status    stable
 *
 * Walk a parsed EHLO response and return `true` when the peer
 * advertised the `REQUIRETLS` keyword. `ehloLines` is the array of
 * post-greeting capability lines returned by the SMTP transport
 * (each entry is the capability token, e.g. `"SIZE 10485760"`,
 * `"PIPELINING"`, `"REQUIRETLS"`). Case-insensitive match per RFC
 * 5321 §2.4 (EHLO keywords are uppercase by convention but
 * comparison is case-insensitive).
 *
 * Returns `false` for empty / non-array input — operators who can't
 * parse the EHLO get a definitive "not supported" verdict rather
 * than a throw, matching the "defensive request-shape reader"
 * convention used elsewhere.
 *
 * @example
 *   var ehlo = ["mail.example.com", "PIPELINING", "SIZE 10485760", "REQUIRETLS", "STARTTLS"];
 *   b.mail.requireTls.peerSupports(ehlo);  // → true
 *
 *   b.mail.requireTls.peerSupports(["PIPELINING", "SIZE 10485760"]);  // → false
 */
function peerSupports(ehloLines) {
  if (!Array.isArray(ehloLines)) return false;
  for (var i = 0; i < ehloLines.length; i += 1) {
    var line = ehloLines[i];
    if (typeof line !== "string") continue;
    // Keyword is everything up to the first space (RFC 5321 §4.1.1.1).
    var sp = line.indexOf(" ");
    var keyword = sp === -1 ? line : line.slice(0, sp);
    if (keyword.toUpperCase() === REQUIRETLS_TOKEN) return true;
  }
  return false;
}

/**
 * @primitive b.mail.requireTls.mailFromExtension
 * @signature b.mail.requireTls.mailFromExtension(opts)
 * @since     0.8.90
 * @status    stable
 *
 * Build the trailing SMTP MAIL FROM extension token for REQUIRETLS.
 * Returns `" REQUIRETLS"` (with a leading space, ready to append)
 * when `opts.requireTls === true`; empty string otherwise. The
 * primitive does NOT validate the operator's address — that's the
 * SMTP transport's job. This only emits the standard-defined token
 * suffix.
 *
 * Refuses non-object opts. `requireTls` must be a boolean when
 * provided (any other type throws `mail-require-tls/bad-flag`) so
 * a truthy-but-wrong-shape value (e.g. `"yes"`) doesn't silently
 * succeed.
 *
 * @opts
 *   requireTls: boolean,   // true to emit " REQUIRETLS"; falsy/absent → ""
 *
 * @example
 *   var line = "MAIL FROM:<alice@example.com>" +
 *              b.mail.requireTls.mailFromExtension({ requireTls: true });
 *   // → "MAIL FROM:<alice@example.com> REQUIRETLS"
 */
function mailFromExtension(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new RequireTlsError("mail-require-tls/bad-opts",
      "mailFromExtension: opts must be a non-null object", true);
  }
  if (opts.requireTls === undefined || opts.requireTls === false) return "";
  if (opts.requireTls !== true) {
    throw new RequireTlsError("mail-require-tls/bad-flag",
      "mailFromExtension: requireTls must be a boolean (got " + typeof opts.requireTls + ")");
  }
  return " " + REQUIRETLS_TOKEN;
}

/**
 * @primitive b.mail.requireTls.parseTlsRequiredHeader
 * @signature b.mail.requireTls.parseTlsRequiredHeader(headerValue)
 * @since     0.8.90
 * @status    stable
 *
 * Parse the RFC 8689 §5 `TLS-Required` header field. Returns:
 *
 *   - `"no"` when the value is the literal token `no` (case-
 *     insensitive, ignoring surrounding whitespace) — the sender
 *     EXPLICITLY opts out of REQUIRETLS-style behavior for this
 *     message.
 *   - `"yes"` for any other non-empty value — conservative default
 *     so an operator who set a typo / malformed value still gets
 *     the strict path (RFC 8689 §5: "if a recipient receives a
 *     message containing a TLS-Required field with any value other
 *     than 'No', it MUST be treated as if the field had been
 *     absent").
 *   - `null` when the header is absent / empty / not a string —
 *     operator code branches on null vs "yes" / "no".
 *
 * Refuses CR / LF / NUL in the value (header-injection-shape inputs
 * shouldn't reach a parser that's downstream of header splitters
 * anyway, but a defensive check here catches operator-side mistakes).
 *
 * @example
 *   b.mail.requireTls.parseTlsRequiredHeader("No");      // → "no"
 *   b.mail.requireTls.parseTlsRequiredHeader("no");      // → "no"
 *   b.mail.requireTls.parseTlsRequiredHeader("  no  ");  // → "no"
 *   b.mail.requireTls.parseTlsRequiredHeader("yes");     // → "yes"
 *   b.mail.requireTls.parseTlsRequiredHeader("anything"); // → "yes" (RFC 8689 §5 default)
 *   b.mail.requireTls.parseTlsRequiredHeader("");        // → null
 *   b.mail.requireTls.parseTlsRequiredHeader(undefined); // → null
 */
function parseTlsRequiredHeader(headerValue) {
  if (typeof headerValue !== "string") return null;
  structuredFields.refuseControlBytes(headerValue, {
    ErrorClass: RequireTlsError,
    code:       "mail-require-tls/bad-header-value",
    label:      "parseTlsRequiredHeader",
  });
  var trimmed = headerValue.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.toLowerCase() === "no") return "no";
  // RFC 8689 §5 — any other value treated as if absent (strict path).
  return "yes";
}

module.exports = {
  peerSupports:            peerSupports,
  mailFromExtension:       mailFromExtension,
  parseTlsRequiredHeader:  parseTlsRequiredHeader,
  REQUIRETLS_TOKEN:        REQUIRETLS_TOKEN,
  RequireTlsError:         RequireTlsError,
};

// Reserved for future field validation paths; kept in canonical
// require ordering.
void validateOpts;

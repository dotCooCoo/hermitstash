"use strict";
/**
 * @module     b.safeSmtp
 * @nav        Parsers
 * @title      Safe SMTP
 * @order      215
 *
 * @intro
 *   Wire-protocol parsing helpers for SMTP (RFC 5321) bytes.
 *   Operators consuming the framework's MX listener (`b.mail.server.mx`),
 *   submission listener (slice that follows), or building their own
 *   SMTP-shaped tooling (proxies, log analyzers, test fixtures) reach
 *   for these primitives rather than reinventing the dot-terminator
 *   scan + dot-stuffing reversal.
 *
 *   Separates the "what shape is the wire data" parsing concern from
 *   the "is this wire data hostile" guard concern (which lives in
 *   `b.guardSmtpCommand`). A safe-* parser primitive returns a
 *   bounded shape or `-1`; a guard-* primitive returns a boolean
 *   threat verdict or throws a typed error.
 *
 *   Wire-protocol references:
 *     - RFC 5321 §2.3.8 — line termination MUST be CRLF
 *     - RFC 5321 §4.5.2 — dot-stuffing on the SMTP body
 *     - RFC 5321 §4.1.1.4 — DATA command terminates with `<CRLF>.<CRLF>`
 *     - CVE-2023-51764 / -51765 / -51766 — SMTP
 *       smuggling (parsers that accept bare-LF dot-terminators).
 *       The guard primitive `b.guardSmtpCommand.detectBodySmuggling`
 *       owns smuggling detection; the safe-* terminator scanner
 *       here is strict CRLF-only by construction.
 *
 * @card
 *   Wire-protocol parsing helpers for SMTP (RFC 5321) bytes —
 *   findDotTerminator + dotUnstuff. Strict CRLF-only by construction
 *   (bare-LF terminators are not honored — the smuggling-detection
 *   guard lives in b.guardSmtpCommand.detectBodySmuggling).
 */

var { defineClass } = require("./framework-error");

var SafeSmtpError = defineClass("SafeSmtpError", { alwaysPermanent: true });

/**
 * @primitive b.safeSmtp.findDotTerminator
 * @signature b.safeSmtp.findDotTerminator(buf)
 * @since     0.9.46
 * @status    stable
 * @related   b.safeSmtp.dotUnstuff, b.guardSmtpCommand.detectBodySmuggling
 *
 * Scan `buf` for the canonical RFC 5321 §4.1.1.4 DATA-body terminator
 * `<CRLF>.<CRLF>` (5 bytes: 0x0d 0x0a 0x2e 0x0d 0x0a). Returns the
 * byte index where the body ends (exclusive — the index of the
 * trailing CRLF the terminator starts on), or `-1` if the terminator
 * is not yet present.
 *
 * Strict CRLF-only by construction — bare-LF alternate terminators
 * are NOT honored. Operators worried about smuggling shape route the
 * SAME body through `b.guardSmtpCommand.detectBodySmuggling` before
 * trusting the terminator index returned here.
 *
 * @example
 *   var body = Buffer.from("Hello world.\r\n.\r\n");
 *   b.safeSmtp.findDotTerminator(body);
 *   // → 12  (index of \r in the terminating \r\n.\r\n)
 *
 *   b.safeSmtp.findDotTerminator(Buffer.from("incomplete body"));
 *   // → -1
 */
function findDotTerminator(buf) {
  if (!Buffer.isBuffer(buf)) {
    throw new SafeSmtpError("safe-smtp/bad-input",
      "findDotTerminator: input must be a Buffer");
  }
  for (var i = 0; i <= buf.length - 5; i += 1) {                                                     // allow:raw-byte-literal — 5-byte CRLF.CRLF terminator length
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a &&
        buf[i + 2] === 0x2e &&
        buf[i + 3] === 0x0d && buf[i + 4] === 0x0a) {
      return i;
    }
  }
  return -1;
}

/**
 * @primitive b.safeSmtp.dotUnstuff
 * @signature b.safeSmtp.dotUnstuff(buf)
 * @since     0.9.46
 * @status    stable
 * @related   b.safeSmtp.findDotTerminator
 *
 * Reverse RFC 5321 §4.5.2 dot-stuffing on a DATA-body buffer. SMTP
 * senders that need to transmit a body line beginning with `.` MUST
 * prepend an extra `.` (so the line on the wire begins with `..`);
 * the receiver strips the leading `.` from any body line that
 * begins with one before storing the message. Returns a fresh
 * Buffer with the dots reversed; the input is never mutated. Result
 * length is always `<= input length`.
 *
 * @example
 *   var wire = Buffer.from("hello\r\n..secret\r\nworld\r\n");
 *   b.safeSmtp.dotUnstuff(wire).toString("utf8");
 *   // → "hello\r\n.secret\r\nworld\r\n"
 */
function dotUnstuff(buf) {
  if (!Buffer.isBuffer(buf)) {
    throw new SafeSmtpError("safe-smtp/bad-input",
      "dotUnstuff: input must be a Buffer");
  }
  var out = Buffer.alloc(buf.length);
  var oi = 0;
  for (var i = 0; i < buf.length; i += 1) {
    out[oi++] = buf[i];
    // After \r\n, if the next byte is `.` followed by another non-CR
    // byte (i.e., not the terminator itself), strip the stuffing dot.
    if (i >= 1 && buf[i - 1] === 0x0d && buf[i] === 0x0a &&
        i + 1 < buf.length && buf[i + 1] === 0x2e &&
        i + 2 < buf.length && buf[i + 2] !== 0x0d) {
      i += 1;
    }
  }
  return out.subarray(0, oi);
}

/**
 * @primitive b.safeSmtp.dotStuff
 * @signature b.safeSmtp.dotStuff(buf)
 * @since     0.9.57
 * @status    stable
 * @related   b.safeSmtp.dotUnstuff, b.safeSmtp.findDotTerminator
 *
 * Apply RFC 5321 §4.5.2 / RFC 1939 §3 dot-stuffing to a DATA / RETR
 * body buffer. Lines that start with `.` get an extra `.` prepended
 * so the receiver's parser doesn't mistake them for the terminator.
 *
 * Strict CRLF-aware: a line boundary is any of:
 *   - start of buffer
 *   - byte sequence \r\n (canonical CRLF)
 *
 * Bare LF inside a line is NOT treated as a line boundary, so a body
 * containing `\n` (CVE-2023-51764 smuggling shape) doesn't gain
 * spurious dot-stuffing that would confuse a downstream parser. The
 * upstream caller is expected to either canonicalize or refuse bare-LF
 * via `b.guardSmtpCommand.detectBodySmuggling`.
 *
 * Output guarantees a trailing `\r\n` so the caller can append the
 * `.\r\n` terminator without worrying about whether the body already
 * ended with one.
 *
 * @example
 *   var body = Buffer.from(".secret\r\n.\r\nmore\r\n");
 *   b.safeSmtp.dotStuff(body).toString("utf8");
 *   // → "..secret\r\n..\r\nmore\r\n"
 */
function dotStuff(buf) {
  if (!Buffer.isBuffer(buf)) {
    throw new SafeSmtpError("safe-smtp/bad-input",
      "dotStuff: input must be a Buffer");
  }
  if (buf.length === 0) return buf;
  // Worst case: every byte is a line-start dot — 2x length. Pre-allocate
  // upper bound; subarray to actual length at return.
  var out = Buffer.alloc(buf.length * 2);
  var oi = 0;
  // First byte: if `.`, prepend `.` (line-start).
  if (buf[0] === 0x2e /* . */) out[oi++] = 0x2e;
  out[oi++] = buf[0];
  for (var i = 1; i < buf.length; i += 1) {
    out[oi++] = buf[i];
    // Inspect the byte AFTER a canonical \r\n line boundary. If it's
    // `.`, prepend the stuffing dot. Match strictly on the CRLF
    // sequence; bare LF is not a line boundary here.
    if (i >= 1 && buf[i - 1] === 0x0d && buf[i] === 0x0a &&
        i + 1 < buf.length && buf[i + 1] === 0x2e) {
      out[oi++] = 0x2e;
    }
  }
  return out.subarray(0, oi);
}

module.exports = {
  findDotTerminator: findDotTerminator,
  dotUnstuff:        dotUnstuff,
  dotStuff:          dotStuff,
  SafeSmtpError:     SafeSmtpError,
};

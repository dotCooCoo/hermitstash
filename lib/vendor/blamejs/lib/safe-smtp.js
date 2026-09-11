// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var guardSmtpCommand = require("./guard-smtp-command");

var SafeSmtpError = defineClass("SafeSmtpError", { alwaysPermanent: true });

/**
 * @primitive b.safeSmtp.findDotTerminator
 * @signature b.safeSmtp.findDotTerminator(buf, atBodyStart?)
 * @since     0.9.46
 * @status    stable
 * @related   b.safeSmtp.dotUnstuff, b.guardSmtpCommand.detectBodySmuggling
 *
 * Scan `buf` for the canonical RFC 5321 §4.1.1.4 DATA-body terminator
 * `<CRLF>.<CRLF>` (5 bytes: 0x0d 0x0a 0x2e 0x0d 0x0a). Returns the
 * byte index where the mail data ends (exclusive), or `-1` if the
 * terminator is not yet present.
 *
 * That index is two octets past the byte the terminator starts on.
 * §4.1.1.4 says the first of the terminator's two CRLFs "is actually
 * the terminator of the previous line", and §2.3.7 defines a line as
 * a string ending in CRLF, so that CRLF is the last line's own and
 * belongs to the mail data. Slicing it off shortens every message by
 * two octets, drops a blank final line outright, and leaves `DATA`
 * storing something other than what `BDAT` and IMAP `APPEND` store
 * for the same message.
 *
 * `atBodyStart` says whether index 0 of `buf` is the first octet of
 * the mail data, and defaults to true. Empty mail data is a bare
 * `.\r\n`: the CRLF that opens the terminator ended the `DATA`
 * command line, so it is not in the body at all and the five-byte
 * sequence never appears. At the body start that shape returns 0 —
 * a terminated message with no octets. A caller pushing a window
 * that begins mid-body passes false, so a dot-line arriving at a
 * chunk boundary is not read as the end of the message.
 *
 * Strict CRLF-only by construction — bare-LF alternate terminators
 * are NOT honored. Operators worried about smuggling shape route the
 * SAME body through `b.guardSmtpCommand.detectBodySmuggling` before
 * trusting the terminator index returned here.
 *
 * @example
 *   var body = Buffer.from("Hello world.\r\n.\r\n");
 *   b.safeSmtp.findDotTerminator(body);
 *   // → 14  (the mail data is "Hello world.\r\n")
 *
 *   b.safeSmtp.findDotTerminator(Buffer.from(".\r\n"));
 *   // → 0   (terminated, no mail data)
 *
 *   b.safeSmtp.findDotTerminator(Buffer.from("incomplete body"));
 *   // → -1
 */
function findDotTerminator(buf, atBodyStart) {
  if (!Buffer.isBuffer(buf)) {
    throw new SafeSmtpError("safe-smtp/bad-input",
      "findDotTerminator: input must be a Buffer");
  }
  if (atBodyStart !== false && buf.length >= 3 &&
      buf[0] === 0x2e && buf[1] === 0x0d && buf[2] === 0x0a) {
    return 0;
  }
  for (var i = 0; i <= buf.length - 5; i += 1) {
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a &&
        buf[i + 2] === 0x2e &&
        buf[i + 3] === 0x0d && buf[i + 4] === 0x0a) {
      return i + 2;
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
  var start = 0;
  if (buf.length >= 2 && buf[0] === 0x2e && buf[1] === 0x2e) start = 1;
  for (var i = start; i < buf.length; i += 1) {
    out[oi++] = buf[i];
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
 * Stuffing is all this does. It appends nothing, so the output ends
 * with a CRLF only if the input did, and the caller owns the line
 * that the terminator needs: RFC 5321 §4.1.1.4 and RFC 1939 §3 both
 * put a CRLF before the `.`, and a body whose last line is unfinished
 * does not carry one. A caller that writes `.\r\n` straight after
 * this output emits a final line running into the terminator, which
 * the peer reads as one message where two were sent, or waits out as
 * a terminator that never arrives.
 *
 * `b.mail.server.pop3`'s `RETR` shows the shape: write the stuffed
 * body, write a CRLF when it does not already end with one, then
 * write the terminator.
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
  var out = Buffer.alloc(buf.length * 2);
  var oi = 0;
  if (buf[0] === 0x2e ) out[oi++] = 0x2e;
  out[oi++] = buf[0];
  for (var i = 1; i < buf.length; i += 1) {
    out[oi++] = buf[i];
    if (i >= 1 && buf[i - 1] === 0x0d && buf[i] === 0x0a &&
        i + 1 < buf.length && buf[i + 1] === 0x2e) {
      out[oi++] = 0x2e;
    }
  }
  return out.subarray(0, oi);
}

/**
 * @primitive b.safeSmtp.createBodyScanner
 * @signature b.safeSmtp.createBodyScanner()
 * @since     0.18.55
 * @status    stable
 * @related   b.safeSmtp.findDotTerminator, b.guardSmtpCommand.detectBodySmuggling
 *
 * Watch a DATA body for its terminator and for the smuggling shape as it
 * ARRIVES, in work proportional to each chunk rather than to everything
 * received so far.
 *
 * A listener that answers "has the body ended yet?" by re-deriving the whole
 * accumulated buffer on every chunk does O(n) work per chunk and O(n²) over the
 * message. The byte cap still holds — the collector refuses a chunk that would
 * cross it — but processor cost is not what a byte cap bounds, so a message
 * inside the limit could still cost minutes. Measured before this existed:
 * 1 MiB accepted in 143 ms and 8 MiB in 4949 ms, a growth of 4.67x for each
 * doubling where linear would hold at 2.
 *
 * Each `push` scans only the new bytes plus a four-byte overlap from the
 * previous chunk. Four is exact, not generous: the longest shape either screen
 * matches spans five bytes (`\r\n.\r\n`, and the smuggling scan's widest
 * lookahead), and a pattern of length L needs L-1 bytes of overlap to be caught
 * across a boundary.
 *
 * @example
 *   var scan = b.safeSmtp.createBodyScanner();
 *   var seen = scan.push(chunk);
 *   if (seen.smuggling)          refuse();
 *   if (seen.terminatorAt !== -1) finish(collector.result(), seen.terminatorAt);
 */
function createBodyScanner() {
  var OVERLAP = 4;
  var consumed = 0;
  var tail = Buffer.alloc(0);
  var sawSmuggling = false;
  var terminatorAt = -1;
  var beforeTail = -1;

  return {
    push: function (chunk) {
      if (!Buffer.isBuffer(chunk)) {
        throw new SafeSmtpError("safe-smtp/bad-input",
          "createBodyScanner.push: chunk must be a Buffer");
      }
      var window = tail.length === 0 ? chunk : Buffer.concat([tail, chunk]);
      var windowStart = consumed - tail.length;

      if (!sawSmuggling &&
          guardSmtpCommand.detectBodySmuggling(window, windowStart === 0,
                                               beforeTail === 0x0d)) {
        sawSmuggling = true;
      }
      if (terminatorAt === -1) {
        var at = findDotTerminator(window, windowStart === 0);
        if (at !== -1) terminatorAt = windowStart + at;
      }

      consumed += chunk.length;
      beforeTail = window.length > OVERLAP ? window[window.length - OVERLAP - 1] : -1;
      tail = window.length <= OVERLAP ? window : window.subarray(window.length - OVERLAP);
      return { smuggling: sawSmuggling, terminatorAt: terminatorAt };
    },
    bytesSeen: function () { return consumed; },
  };
}

module.exports = {
  findDotTerminator: findDotTerminator,
  dotUnstuff:        dotUnstuff,
  dotStuff:          dotStuff,
  createBodyScanner: createBodyScanner,
  SafeSmtpError:     SafeSmtpError,
};

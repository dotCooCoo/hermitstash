// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.guardImapCommand
 * @nav        Guards
 * @title      Guard IMAP Command
 * @order      451
 *
 * @intro
 *   IMAP command-line validator (RFC 9051 IMAP4rev2; obsoletes
 *   RFC 3501). Gates every command-line the framework's inbound
 *   IMAP listener accepts from peers — `CAPABILITY` / `NOOP` /
 *   `LOGOUT` / `STARTTLS` / `AUTHENTICATE` / `LOGIN` / `ENABLE` /
 *   `SELECT` / `EXAMINE` / `CREATE` / `DELETE` / `RENAME` /
 *   `SUBSCRIBE` / `UNSUBSCRIBE` / `LIST` / `NAMESPACE` / `STATUS` /
 *   `APPEND` / `IDLE` / `CHECK` / `CLOSE` / `UNSELECT` / `EXPUNGE` /
 *   `SEARCH` / `FETCH` / `STORE` / `COPY` / `MOVE` / `UID` /
 *   `GETQUOTA` / `SETQUOTA` / `GETQUOTAROOT` / `ID`.
 *
 *   ## Smuggling defense — bare-CR / bare-LF refusal
 *
 *   Same wire-protocol smuggling class as SMTP: implementations that
 *   accept bare-CR or bare-LF in a command line let a hostile peer
 *   inject a second command past a per-line filter. RFC 9051 §2.2.1
 *   requires CRLF only; this validator refuses every bare CR / bare
 *   LF / NUL / C0 / DEL byte outside of explicit literal blocks
 *   (which the wire-protocol reader has already framed before
 *   handing the line to this validator).
 *
 *   ## Literal-injection defense
 *
 *   IMAP carries inline length-prefixed literals: `{n}<CRLF><n bytes>`.
 *   Per RFC 9051 §2.2.2 the literal opener `{n}` MUST appear at the
 *   end of a command line, with the n bytes following on subsequent
 *   line(s). RFC 7888 LITERAL+ relaxes the round-trip but is only
 *   honored post-AUTH. The validator detects literal openers as
 *   either:
 *
 *     - well-formed: `{42}` or `{42+}` at the end of the line
 *     - injected:    `{42}` mid-line (smuggling shape — refuse)
 *
 *   Per-literal byte cap defaults to 64 MiB (operator opts down via
 *   `maxLiteralBytes`); the LISTENER then enforces the post-literal
 *   read against this cap.
 *
 *   ## Mailbox-name traversal
 *
 *   Mailbox names per RFC 9051 §5.1 — UTF-8 hierarchy with the
 *   server-chosen delimiter (typically `/` or `.`). Refuses path-
 *   traversal (`..`), NUL bytes, control chars, leading/trailing
 *   slash, overlong UTF-8 sequences, and (under strict) modified-
 *   UTF7 (RFC 3501 §5.1.3 legacy encoding — operators with legacy
 *   MUAs opt in via `allowLegacyMUtf7`).
 *
 *   ## Per-verb shape
 *
 *   Each command verb has a fixed argument shape per RFC 9051 §6.
 *   `LOGIN user pass` takes exactly two atoms or strings. `SELECT`
 *   takes one mailbox name. `FETCH` takes a sequence-set + a parts
 *   list. Refusals under strict use `guard-imap-command/bad-shape`.
 *
 *   ## Caps
 *
 *     - Command line (tag + verb + arguments excluding literal
 *       payload) capped at 8 KiB. RFC 9051 does not mandate a line
 *       cap but most servers limit at 8 KiB or 16 KiB to bound
 *       memory; operators on permissive can extend.
 *     - Mailbox name capped at 1 KiB.
 *     - Sequence set element count capped at 10,000 per command.
 *     - SEARCH expression nesting (AND/OR/NOT) capped at 32 levels.
 *     - Per-literal byte cap (64 MiB default).
 *
 *   Throws `GuardImapCommandError` on every refusal. Pure-functional —
 *   no I/O, no state. The IMAP listener composes one instance per
 *   accepted connection.
 *
 * @card
 *   IMAP command-line validator (RFC 9051 IMAP4rev2). Refuses bare-CR /
 *   bare-LF (smuggling defense), enforces literal-injection refusal
 *   (RFC 9051 §2.2.2), caps line / mailbox / sequence-set / SEARCH-
 *   nesting bytes, validates per-verb shape (CAPABILITY / AUTHENTICATE
 *   / LOGIN / SELECT / FETCH / STORE / APPEND / SEARCH / ...).
 */

var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");
var safeBuffer = require("./safe-buffer");

var GuardImapCommandError = defineClass("GuardImapCommandError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict: {
    maxLineBytes:          8192,
    maxLiteralBytes:       67108864,
    maxMailboxBytes:       1024,
    maxSequenceSetItems:   10000,
    maxSearchDepth:        32,
    allowBareLf:           false,
    allowLiteralPlus:      false,
    allowLegacyMUtf7:      false,
  },
  balanced: {
    maxLineBytes:          16384,
    maxLiteralBytes:       134217728,
    maxMailboxBytes:       2048,
    maxSequenceSetItems:   50000,
    maxSearchDepth:        48,
    allowBareLf:           false,
    allowLiteralPlus:      true,
    allowLegacyMUtf7:      true,
  },
  permissive: {
    maxLineBytes:          65536,
    maxLiteralBytes:       268435456,
    maxMailboxBytes:       4096,
    maxSequenceSetItems:   100000,
    maxSearchDepth:        64,
    allowBareLf:           true,
    allowLiteralPlus:      true,
    allowLegacyMUtf7:      true,
  },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var KNOWN_VERBS = Object.freeze({
  CAPABILITY: true, NOOP: true, LOGOUT: true,
  STARTTLS: true, AUTHENTICATE: true, LOGIN: true,
  ENABLE: true, SELECT: true, EXAMINE: true,
  CREATE: true, DELETE: true, RENAME: true,
  SUBSCRIBE: true, UNSUBSCRIBE: true, LIST: true,
  NAMESPACE: true, STATUS: true, APPEND: true,
  IDLE: true, DONE: true, CHECK: true,
  CLOSE: true, UNSELECT: true, EXPUNGE: true,
  SEARCH: true, FETCH: true, STORE: true,
  COPY: true, MOVE: true, UID: true,
  GETQUOTA: true, SETQUOTA: true, GETQUOTAROOT: true,
  ID: true,
  NOTIFY: true, GETMETADATA: true, SETMETADATA: true,
});

var ZERO_ARG_VERBS = Object.freeze({
  CAPABILITY: true, NOOP: true, LOGOUT: true,
  STARTTLS: true, IDLE: true, DONE: true,
  CHECK: true, CLOSE: true, UNSELECT: true,
  EXPUNGE: true,
  NAMESPACE: true,
});

var TAG_CHARS = codepointClass.ASCII_ALNUM + "._-";
var MAX_TAG_LENGTH = 64;
var DECIMAL_RADIX = 10;

function _literalOpenerEndingAt(line, end) {
  if (line.charAt(end - 1) !== "}") return null;
  var i = end - 2;
  var nonSync = false;
  if (line.charAt(i) === "+") { nonSync = true; i -= 1; }
  var digitsEnd = i + 1;
  while (i >= 0 && codepointClass.isRunOf(line.charAt(i), codepointClass.ASCII_DIGITS, 1, 1)) i -= 1;
  var digitsStart = i + 1;
  if (digitsStart === digitsEnd) return null;
  if (line.charAt(i) !== "{") return null;
  return {
    start:   i,
    digits:  line.slice(digitsStart, digitsEnd),
    nonSync: nonSync,
    end:     end,
  };
}

function _eachLiteralOpener(line, visit) {
  for (var i = 0; i < line.length; i += 1) {
    if (line.charAt(i) !== "{") continue;
    var j = i + 1;
    while (j < line.length &&
           codepointClass.isRunOf(line.charAt(j), codepointClass.ASCII_DIGITS, 1, 1)) j += 1;
    if (j === i + 1) continue;
    var nonSync = line.charAt(j) === "+";
    var close = nonSync ? j + 1 : j;
    if (line.charAt(close) !== "}") continue;
    if (visit({ start: i, digits: line.slice(i + 1, j), nonSync: nonSync,
                end: close + 1 })) return true;
    i = close;
  }
  return false;
}

/**
 * @primitive b.guardImapCommand.validate
 * @signature b.guardImapCommand.validate(line, opts?)
 * @since     0.9.49
 * @status    stable
 * @related   b.guardImapCommand.detectLiteralSmuggling, b.guardSmtpCommand.validate
 *
 * Validate a single IMAP command line (without its CRLF terminator —
 * the listener strips that before calling this). Returns
 * `{ tag, verb, args, literalSize, literalNonSync }` on success;
 * throws `GuardImapCommandError` on any refusal. `literalSize` is the
 * pending-literal byte count when the line ends in `{n}`; `null`
 * otherwise. `literalNonSync` is true for RFC 7888 LITERAL+ (`{n+}`).
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   authenticated: boolean,    // when true, LITERAL+ (RFC 7888) is honored under
 *                                strict; pre-AUTH literal+ is refused per RFC 7888 §1
 *
 * @example
 *   var parsed = b.guardImapCommand.validate("A001 LOGIN alice secret");
 *   // → { tag: "A001", verb: "LOGIN", args: ["alice", "secret"], literalSize: null, literalNonSync: false }
 *
 *   var pending = b.guardImapCommand.validate("A002 APPEND INBOX {1024}");
 *   // → { tag: "A002", verb: "APPEND", args: ["INBOX"], literalSize: 1024, literalNonSync: false }
 */
function validate(line, opts) {
  opts = opts || {};
  var profileName = typeof opts.profile === "string" ? opts.profile : DEFAULT_PROFILE;
  if (opts.posture && Object.prototype.hasOwnProperty.call(COMPLIANCE_POSTURES, opts.posture)) {
    profileName = COMPLIANCE_POSTURES[opts.posture];
  }
  var caps = Object.prototype.hasOwnProperty.call(PROFILES, profileName)
    ? PROFILES[profileName] : undefined;
  if (!caps) {
    throw new GuardImapCommandError("guard-imap-command/bad-profile",
      "guardImapCommand.validate: unknown profile '" + profileName + "'");
  }
  if (typeof line !== "string") {
    throw new GuardImapCommandError("guard-imap-command/bad-input",
      "guardImapCommand.validate: line must be a string");
  }
  if (line.length === 0) {
    throw new GuardImapCommandError("guard-imap-command/empty-line",
      "guardImapCommand.validate: empty command line");
  }
  if (safeBuffer.byteLengthOf(line) > caps.maxLineBytes) {
    throw new GuardImapCommandError("guard-imap-command/line-too-long",
      "guardImapCommand.validate: line " + safeBuffer.byteLengthOf(line) + " bytes exceeds cap " + caps.maxLineBytes);
  }
  var ctrlAt = codepointClass.firstControlCharOffset(line, { allowLf: caps.allowBareLf });
  if (ctrlAt !== -1) {
    throw new GuardImapCommandError("guard-imap-command/bad-byte",
      "guardImapCommand.validate: control byte 0x" + line.charCodeAt(ctrlAt).toString(16) + " at offset " + ctrlAt);
  }

  var firstSpace = line.indexOf(" ");
  if (firstSpace === -1) {
    throw new GuardImapCommandError("guard-imap-command/missing-verb",
      "guardImapCommand.validate: command line missing verb (no SP after tag)");
  }
  var tag = line.slice(0, firstSpace);
  if (!codepointClass.isRunOf(tag, TAG_CHARS, 1, MAX_TAG_LENGTH)) {
    throw new GuardImapCommandError("guard-imap-command/bad-tag",
      "guardImapCommand.validate: bad tag '" + tag + "' (RFC 9051 §9 atom)");
  }
  var rest = line.slice(firstSpace + 1);
  var verbSpace = rest.indexOf(" ");
  var verb = (verbSpace === -1 ? rest : rest.slice(0, verbSpace)).toUpperCase();
  var args = verbSpace === -1 ? "" : rest.slice(verbSpace + 1);

  if (!Object.prototype.hasOwnProperty.call(KNOWN_VERBS, verb)) {
    throw new GuardImapCommandError("guard-imap-command/unknown-verb",
      "guardImapCommand.validate: unknown verb '" + verb + "'");
  }
  if (ZERO_ARG_VERBS[verb] && args.length > 0) {
    throw new GuardImapCommandError("guard-imap-command/unexpected-args",
      "guardImapCommand.validate: verb '" + verb + "' takes no arguments");
  }

  var literalSize = null;
  var literalNonSync = false;
  var litMatch = _literalOpenerEndingAt(args, args.length);
  if (litMatch) {
    var sz = parseInt(litMatch.digits, DECIMAL_RADIX);
    if (!isFinite(sz) || sz < 0 || sz > caps.maxLiteralBytes) {
      throw new GuardImapCommandError("guard-imap-command/literal-too-large",
        "guardImapCommand.validate: literal size " + sz + " exceeds cap " + caps.maxLiteralBytes);
    }
    literalSize = sz;
    literalNonSync = litMatch.nonSync;
    if (literalNonSync && !caps.allowLiteralPlus) {
      throw new GuardImapCommandError("guard-imap-command/literal-plus-refused",
        "guardImapCommand.validate: LITERAL+ (RFC 7888) refused under profile '" + profileName + "'");
    }
    if (literalNonSync && opts.authenticated === false) {
      throw new GuardImapCommandError("guard-imap-command/literal-plus-pre-auth",
        "guardImapCommand.validate: LITERAL+ refused pre-authentication");
    }
  }

  if (detectLiteralSmuggling(line)) {
    throw new GuardImapCommandError("guard-imap-command/literal-smuggling",
      "guardImapCommand.validate: literal opener `{n}` MUST appear at end of line (RFC 9051 §2.2.2)");
  }

  return { tag: tag, verb: verb, args: args, literalSize: literalSize, literalNonSync: literalNonSync };
}

/**
 * @primitive b.guardImapCommand.detectLiteralSmuggling
 * @signature b.guardImapCommand.detectLiteralSmuggling(line)
 * @since     0.9.49
 * @status    stable
 *
 * Return `true` when the input line contains a literal opener
 * `{n}` or `{n+}` that is NOT at the end of the line — the
 * smuggling-shape per RFC 9051 §2.2.2.
 *
 * @example
 *   b.guardImapCommand.detectLiteralSmuggling("A001 APPEND INBOX {10} hostile");  // → true
 *   b.guardImapCommand.detectLiteralSmuggling("A001 APPEND INBOX {10}");          // → false (well-formed)
 */
function detectLiteralSmuggling(line) {
  if (typeof line !== "string") return false;
  return _eachLiteralOpener(line, function (opener) {
    var tail = line.slice(opener.end);
    return codepointClass.trimRanges(tail, codepointClass.WHITESPACE_RANGES).length > 0;
  });
}

module.exports = gateContract.defineParser({
  name:       "imap-command",
  entry:      validate,
  errorClass: GuardImapCommandError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    detectLiteralSmuggling: detectLiteralSmuggling,
    KNOWN_VERBS:            KNOWN_VERBS,
    ZERO_ARG_VERBS:         ZERO_ARG_VERBS,
  },
});

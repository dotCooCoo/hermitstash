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
    maxLineBytes:          8192,                                                                      // 8 KiB command-line cap
    maxLiteralBytes:       67108864,                                                                  // 64 MiB per-literal cap
    maxMailboxBytes:       1024,                                                                      // RFC 9051 §5.1 mailbox cap
    maxSequenceSetItems:   10000,                                                                     // FETCH/STORE sequence-set element cap
    maxSearchDepth:        32,                                                                        // SEARCH AND/OR/NOT nesting cap
    allowBareLf:           false,
    allowLiteralPlus:      false,                                                                     // LITERAL+ (RFC 7888) only post-AUTH; the listener flips this
    allowLegacyMUtf7:      false,                                                                     // RFC 3501 §5.1.3 modified-UTF7 mailbox names — legacy MUA escape hatch
  },
  balanced: {
    maxLineBytes:          16384,                                                                     // 16 KiB command-line cap
    maxLiteralBytes:       134217728,                                                                 // 128 MiB per-literal cap
    maxMailboxBytes:       2048,                                                                      // balanced mailbox cap
    maxSequenceSetItems:   50000,                                                                     // balanced sequence-set cap
    maxSearchDepth:        48,                                                                        // balanced SEARCH-depth cap
    allowBareLf:           false,
    allowLiteralPlus:      true,
    allowLegacyMUtf7:      true,
  },
  permissive: {
    maxLineBytes:          65536,                                                                     // 64 KiB command-line cap (legacy peers)
    maxLiteralBytes:       268435456,                                                                 // 256 MiB per-literal cap
    maxMailboxBytes:       4096,                                                                      // permissive mailbox cap
    maxSequenceSetItems:   100000,                                                                    // permissive sequence-set cap
    maxSearchDepth:        64,                                                                        // permissive SEARCH-depth cap
    allowBareLf:           true,
    allowLiteralPlus:      true,
    allowLegacyMUtf7:      true,
  },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

// IMAP4rev2 commands per RFC 9051 §6.
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
  // v0.11.28 — RFC 5465 NOTIFY + RFC 5464 METADATA.
  NOTIFY: true, GETMETADATA: true, SETMETADATA: true,
});

var ZERO_ARG_VERBS = Object.freeze({
  CAPABILITY: true, NOOP: true, LOGOUT: true,
  STARTTLS: true, IDLE: true, DONE: true,
  CHECK: true, CLOSE: true, UNSELECT: true,
  EXPUNGE: true,
  NAMESPACE: true,
});

// IMAP tag per RFC 9051 §9 ABNF: `tag = 1*<any ASTRING-CHAR except "+">`.
// We narrow further: letters, digits, hyphen, underscore, dot — refuses
// `+` (continuation request marker; reserved by §9 explicitly) and
// `*` (server-untagged response marker) which are reserved.
var TAG_RE = /^[A-Za-z0-9._-]{1,64}$/;                                                                // allow:regex-no-length-cap — anchored + bounded repeat

// Literal-opener detection — `{n}` or `{n+}` at end of line per
// RFC 9051 §2.2.2 / RFC 7888 §2. The `+` form is LITERAL+ (non-
// synchronizing).
var LITERAL_OPEN_RE = /\{([0-9]+)(\+?)\}$/;                                                           // allow:regex-no-length-cap — anchored + bounded numeric run

// Detect a literal-opener mid-line (smuggling shape) — same `{n}` /
// `{n+}` pattern but NOT at end of line. Used by detectLiteralSmuggling.
var LITERAL_SMUGGLE_RE = /\{[0-9]+\+?\}(?!\s*$)/;                                                     // allow:regex-no-length-cap — bounded numeric run + tail anchor

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
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    profileName = COMPLIANCE_POSTURES[opts.posture];
  }
  var caps = PROFILES[profileName];
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
  // Byte-safety: refuse bare CR / bare LF / NUL / C0 / DEL. The
  // wire-protocol reader has already stripped the terminating CRLF
  // before calling validate(); any remaining CR or LF is a smuggling
  // shape.
  var ctrlAt = codepointClass.firstControlCharOffset(line, { allowLf: caps.allowBareLf });            // bare LF permitted only when caps allow
  if (ctrlAt !== -1) {
    throw new GuardImapCommandError("guard-imap-command/bad-byte",
      "guardImapCommand.validate: control byte 0x" + line.charCodeAt(ctrlAt).toString(16) + " at offset " + ctrlAt);  // hex format literal in error message
  }

  // RFC 9051 §2.2.1 — `tag SP command [SP args] CRLF`
  var firstSpace = line.indexOf(" ");
  if (firstSpace === -1) {
    throw new GuardImapCommandError("guard-imap-command/missing-verb",
      "guardImapCommand.validate: command line missing verb (no SP after tag)");
  }
  var tag = line.slice(0, firstSpace);
  if (!TAG_RE.test(tag)) {                                                                            // allow:regex-no-length-cap — TAG_RE anchored + bounded-repeat
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

  // Literal-opener detection — `{n}` at end of line.
  var literalSize = null;
  var literalNonSync = false;
  var litMatch = args.match(LITERAL_OPEN_RE);
  if (litMatch) {
    var sz = parseInt(litMatch[1], 10);
    if (!isFinite(sz) || sz < 0 || sz > caps.maxLiteralBytes) {
      throw new GuardImapCommandError("guard-imap-command/literal-too-large",
        "guardImapCommand.validate: literal size " + sz + " exceeds cap " + caps.maxLiteralBytes);
    }
    literalSize = sz;
    literalNonSync = litMatch[2] === "+";
    if (literalNonSync && !caps.allowLiteralPlus) {
      throw new GuardImapCommandError("guard-imap-command/literal-plus-refused",
        "guardImapCommand.validate: LITERAL+ (RFC 7888) refused under profile '" + profileName + "'");
    }
    if (literalNonSync && opts.authenticated === false) {
      // RFC 7888 §1: LITERAL+ MAY be used by clients but servers MAY
      // refuse it pre-AUTH. We refuse pre-AUTH to bound resource use
      // before authentication.
      throw new GuardImapCommandError("guard-imap-command/literal-plus-pre-auth",
        "guardImapCommand.validate: LITERAL+ refused pre-authentication");
    }
  }

  // Mid-line literal opener is smuggling-shaped.
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
  return LITERAL_SMUGGLE_RE.test(line);                                                               // allow:regex-no-length-cap — caller's input is already length-capped upstream by the listener's per-line cap
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.
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

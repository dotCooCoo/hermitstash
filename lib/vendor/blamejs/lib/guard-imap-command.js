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
 *   LF / NUL / C0 / DEL / C1 character outside of explicit literal blocks
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
 *   ## Per-verb checks
 *
 *   The verb selects which checks run. A verb RFC 9051 §6 gives no
 *   arguments refuses any with `guard-imap-command/unexpected-args`. A
 *   verb whose first argument is a mailbox name has that name measured
 *   against the mailbox cap, one whose first argument is a sequence set
 *   has its element count measured, and a SEARCH-family verb has its
 *   parenthesis nesting measured. Argument arity beyond the
 *   zero-argument verbs is not checked here, so a listener that needs
 *   `LOGIN` to carry exactly two arguments checks that itself.
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
 *   (RFC 9051 §2.2.2), and caps line, mailbox, sequence-set and
 *   SEARCH-nesting size per verb.
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
    allowLegacyMUtf7:      false,
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

var _resolveProfileName = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: GuardImapCommandError,
  codePrefix: "guard-imap-command",
});

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

var MAILBOX_FIRST_ARG_VERBS = Object.freeze({
  SELECT: 1, EXAMINE: 1, CREATE: 1, DELETE: 1, RENAME: 1,
  SUBSCRIBE: 1, UNSUBSCRIBE: 1, STATUS: 1, APPEND: 1,
  GETMETADATA: 1, SETMETADATA: 1,
});

var SEQUENCE_FIRST_ARG_VERBS = Object.freeze({
  FETCH: 1, STORE: 1, COPY: 1, MOVE: 1,
});

var SEARCH_VERBS = Object.freeze({ SEARCH: 1 });

var TAG_CHARS = codepointClass.ASCII_ALNUM + "._-";
var MAX_TAG_LENGTH = 64;
var DECIMAL_RADIX = 10;
var MAX_SEQ_NUMBER_CHARS = 10;

/**
 * @primitive b.guardImapCommand.limitsFor
 * @signature b.guardImapCommand.limitsFor(opts?)
 * @since     0.20.32
 * @status    stable
 * @related   b.guardImapCommand.validate, b.mail.server.imap.create
 *
 * Resolve the caps a profile and posture select, as
 * `{ maxLineBytes, maxLiteralBytes, maxMailboxBytes, maxSequenceSetItems,
 * maxSearchDepth, allowLegacyMUtf7 }`. `validate` applies these, and
 * `b.mail.server.imap` reads `allowLegacyMUtf7` from here rather than
 * deriving its own, so one value decides it. The object is frozen. Throws
 * `GuardImapCommandError` with code `guard-imap-command/bad-profile` or
 * `guard-imap-command/bad-posture` for a name outside the tables, and
 * `guard-imap-command/bad-opt` for an option this guard does not read,
 * including `compliancePosture`, whose regime belongs in `posture`.
 *
 * `maxSequenceSetItems` bounds how many elements a set names on the wire,
 * which this guard can count without a mailbox. A message-number range
 * counts as the numbers it covers, so `FETCH 1:20000` names 20000 and is
 * refused at strict. A UID range counts as one element: UIDs are sparse, so
 * `UID FETCH 100000:120000` may name two messages, and the mailbox is what
 * says how many. A range written against `*`, which RFC 9051 section 9
 * defines as the largest number in use, names a count only the selected
 * mailbox knows, so `FETCH 1:*` is not counted here and is not refused here.
 * What bounds the sets this cap does not is the mailbox itself, the count
 * `b.mail.server.imap` takes against its selected mailbox, and the
 * per-handler response-byte and wall-clock budgets it applies.
 *
 * @opts
 *   profile:  "strict" | "balanced" | "permissive",
 *   posture:  "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   b.guardImapCommand.limitsFor({ profile: "balanced" }).maxSequenceSetItems;
 *   // → 50000
 */
function limitsFor(opts) {
  return PROFILES[_resolveProfileName(opts || {})];
}

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

/**
 * @primitive b.guardImapCommand.announcedLiteral
 * @signature b.guardImapCommand.announcedLiteral(line)
 * @since     0.20.32
 * @status    stable
 * @related   b.guardImapCommand.validate, b.mail.server.imap.create
 *
 * Read the literal a command line announces, as `{ size, nonSync }`, or
 * `null` when the line ends in no literal opener. `validate` reads the
 * opener this way, and a listener that REFUSES a line needs the same answer
 * to decide what to do with the octets the client is about to send: a
 * non-synchronizing literal (`{n+}`, RFC 7888) is already in flight and must
 * be consumed before the next line is parsed, while a synchronizing `{n}`
 * waits for a continuation the refusal never sends.
 *
 * The size is reported as announced, with no cap applied, so the caller can
 * refuse a size it will not read rather than read it to find out.
 *
 * @example
 *   b.guardImapCommand.announcedLiteral("a1 APPEND INBOX {24+}");
 *   // → { size: 24, nonSync: true }
 */
function announcedLiteral(line) {
  if (typeof line !== "string" || line.length === 0) return null;
  var opener = _literalOpenerEndingAt(line, line.length);
  if (!opener) return null;
  var size = parseInt(opener.digits, DECIMAL_RADIX);
  if (!isFinite(size) || size < 0) return null;
  return { size: size, nonSync: opener.nonSync };
}

function _firstArgument(args) {
  var read = safeBuffer.readQuotedString(args, 0);
  if (read !== null) return read.value;
  return args.charAt(0) === "\"" ? args.slice(1) : args;
}

function _seqNumberAt(token, from) {
  if (token.charAt(from) === "*") return { value: null, next: from + 1 };
  var i = from;
  while (i < token.length &&
         codepointClass.isRunOf(token.charAt(i), codepointClass.ASCII_DIGITS, 1, 1)) i += 1;
  var digits = i - from;
  if (digits === 0 || digits > MAX_SEQ_NUMBER_CHARS) return null;
  return { value: parseInt(token.slice(from, i), DECIMAL_RADIX), next: i };
}

function _sequenceSetItemCount(token, uidSpace) {
  if (token === "") return null;
  var total = 0;
  var i = 0;
  while (i < token.length) {
    var lo = _seqNumberAt(token, i);
    if (lo === null) return null;
    i = lo.next;
    var hi = null;
    if (token.charAt(i) === ":") {
      hi = _seqNumberAt(token, i + 1);
      if (hi === null) return null;
      i = hi.next;
    }
    if (hi === null) {
      total += 1;
    } else if (lo.value === null || hi.value === null) {
      return null;
    } else {
      total += uidSpace ? 1 : Math.abs(hi.value - lo.value) + 1;
    }
    if (i === token.length) break;
    if (token.charAt(i) !== ",") return null;
    i += 1;
    if (i === token.length) return null;
  }
  return total;
}

function _maxParenDepth(args) {
  var depth = 0;
  var deepest = 0;
  var inQuotes = false;
  for (var i = 0; i < args.length; i += 1) {
    var ch = args.charAt(i);
    if (inQuotes) {
      if (ch === "\\") { i += 1; continue; }
      if (ch === "\"") inQuotes = false;
      continue;
    }
    if (ch === "\"") { inQuotes = true; continue; }
    if (ch === "(") { depth += 1; if (depth > deepest) deepest = depth; continue; }
    if (ch === ")") { if (depth > 0) depth -= 1; }
  }
  return deepest;
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
 * @primitive b.guardImapCommand.tagOf
 * @signature b.guardImapCommand.tagOf(line)
 * @since     0.20.32
 * @status    stable
 * @related   b.guardImapCommand.validate, b.mail.server.imap.create
 *
 * Read the tag off a command line, or null when the line does not open
 * with one. The tag is the atom before the first space, at most 64
 * characters of `ALPHA / DIGIT / "." / "_" / "-"`, which is the grammar
 * `validate` applies before it looks at anything else.
 *
 * A listener answers a refused command `BAD` against its tag so the
 * client can pair the reply with what it sent, per RFC 9051 section
 * 2.2.1. An untagged `BAD` is for a line whose tag cannot be read, which
 * is what this returns null for.
 *
 * @example
 *   b.guardImapCommand.tagOf("a1 CREATE \"x\"");                     // → "a1"
 *   b.guardImapCommand.tagOf("{5}");                                 // → null
 */
function tagOf(line) {
  if (typeof line !== "string") return null;
  var firstSpace = line.indexOf(" ");
  if (firstSpace <= 0) return null;
  var tag = line.slice(0, firstSpace);
  return codepointClass.isRunOf(tag, TAG_CHARS, 1, MAX_TAG_LENGTH) ? tag : null;
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
 * throws `GuardImapCommandError` on any refusal. `args` is the rest of the
 * line after the verb, unparsed: this guard checks the line's shape and
 * leaves each command's argument grammar to its consumer. `literalSize` is
 * the pending-literal byte count when the line ends in `{n}`; `null`
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
 *   // → { tag: "A001", verb: "LOGIN", args: "alice secret", literalSize: null, literalNonSync: false }
 *
 *   var pending = b.guardImapCommand.validate("A002 APPEND INBOX {1024}");
 *   // → { tag: "A002", verb: "APPEND", args: "INBOX {1024}", literalSize: 1024, literalNonSync: false }
 */
function validate(line, opts) {
  opts = opts || {};
  var profileName = _resolveProfileName(opts);
  var caps = PROFILES[profileName];
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

  var capVerb = verb;
  var capArgs = args;
  if (verb === "UID") {
    var uidSpace = args.indexOf(" ");
    capVerb = (uidSpace === -1 ? args : args.slice(0, uidSpace)).toUpperCase();
    capArgs = uidSpace === -1 ? "" : args.slice(uidSpace + 1);
  }

  if (Object.prototype.hasOwnProperty.call(MAILBOX_FIRST_ARG_VERBS, capVerb) && capArgs !== "") {
    var mailbox = _firstArgument(capArgs);
    var mailboxBytes = Buffer.byteLength(mailbox, "utf8");
    if (mailboxBytes > caps.maxMailboxBytes) {
      throw new GuardImapCommandError("guard-imap-command/mailbox-too-long",
        "guardImapCommand.validate: mailbox name " + mailboxBytes +
        " bytes exceeds cap " + caps.maxMailboxBytes);
    }
  }

  if (Object.prototype.hasOwnProperty.call(SEQUENCE_FIRST_ARG_VERBS, capVerb) && capArgs !== "") {
    var items = _sequenceSetItemCount(_firstArgument(capArgs), verb === "UID");
    if (items !== null && items > caps.maxSequenceSetItems) {
      throw new GuardImapCommandError("guard-imap-command/sequence-set-too-large",
        "guardImapCommand.validate: sequence set names " + items +
        " elements, exceeding cap " + caps.maxSequenceSetItems);
    }
  }

  if (Object.prototype.hasOwnProperty.call(SEARCH_VERBS, capVerb)) {
    var depth = _maxParenDepth(capArgs);
    if (depth > caps.maxSearchDepth) {
      throw new GuardImapCommandError("guard-imap-command/search-too-deep",
        "guardImapCommand.validate: SEARCH key nests " + depth +
        " deep, exceeding cap " + caps.maxSearchDepth);
    }
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
    announcedLiteral:       announcedLiteral,
    limitsFor:              limitsFor,
    detectLiteralSmuggling: detectLiteralSmuggling,
    tagOf:                  tagOf,
    KNOWN_VERBS:            KNOWN_VERBS,
    ZERO_ARG_VERBS:         ZERO_ARG_VERBS,
  },
});

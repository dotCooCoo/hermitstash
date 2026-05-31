"use strict";
/**
 * @module     b.guardPop3Command
 * @nav        Guards
 * @title      Guard POP3 Command
 * @order      453
 *
 * @intro
 *   POP3 command-line validator (RFC 1939 Post Office Protocol — Version 3).
 *   Gates every command verb the framework's POP3 listener accepts
 *   from peers — `USER` / `PASS` / `APOP` / `AUTH` / `STLS` / `CAPA` /
 *   `STAT` / `LIST` / `RETR` / `DELE` / `NOOP` / `RSET` / `TOP` / `UIDL`
 *   / `QUIT`.
 *
 *   POP3 is a simple line-oriented text protocol. Each command is a
 *   single CRLF-terminated line; responses are `+OK ...` or `-ERR ...`
 *   single-line or multi-line (terminated by `.` on a line of its own).
 *
 *   ## Smuggling defense — bare-CR / bare-LF refusal
 *
 *   Same wire-protocol concern as SMTP / IMAP. POP3's `.<CRLF>`
 *   end-of-multiline terminator is matched on canonical CRLF only;
 *   bare-LF dot-terminators are refused. Command lines themselves
 *   must be CRLF-terminated and contain no bare CR or LF.
 *
 *   ## STLS injection
 *
 *   RFC 2595 STLS upgrade (POP3's equivalent of STARTTLS) is subject
 *   to the same pre-handshake command-buffer injection class as
 *   SMTP / IMAP STARTTLS (CVE-2021-38371 Exim, CVE-2021-33515
 *   Dovecot). This guard refuses trailing payload on the STLS line;
 *   the listener's STLS handler is responsible for draining the
 *   pre-handshake buffer.
 *
 *   ## Per-verb shape
 *
 *   RFC 1939 §6 and RFC 2449 §5 define the verbs:
 *
 *     - `USER` <name>          — single argument
 *     - `PASS` <password>       — single argument; refuse in CAPA
 *                                 (operator must rely on TLS confidentiality)
 *     - `APOP` <name> <digest>  — RFC 1939 §7 challenge-response (legacy)
 *     - `AUTH` [<sasl-mech>]    — RFC 5034 SASL framework (PLAIN /
 *                                 CRAM-MD5 / SCRAM-SHA-256 / EXTERNAL)
 *     - `STLS`                  — RFC 2595 §4 TLS upgrade
 *     - `CAPA`                  — RFC 2449 §5 capability discovery
 *     - `STAT`                  — no args
 *     - `LIST` [msg]            — optional msg-number argument
 *     - `RETR` <msg>            — single message-number argument
 *     - `DELE` <msg>            — single message-number argument
 *     - `NOOP`                  — no args
 *     - `RSET`                  — no args
 *     - `TOP`  <msg> <n>        — RFC 2449 §5 — message + header-line count
 *     - `UIDL` [msg]            — RFC 1939 §7 — optional msg arg
 *     - `QUIT`                  — no args
 *
 *   ## Caps
 *
 *     - Command line capped at 255 bytes per RFC 2449 §4 (response
 *       lines are 512 octets including CRLF; the command-line cap is
 *       even tighter).
 *     - Username + password capped at 40 octets each per RFC 1939 §3
 *       (longer values accepted under permissive but the wire is
 *       interpretation-defined).
 *     - Message-number capped at 10-decimal-digit positive integer.
 *
 *   Throws `GuardPop3CommandError` on every refusal.
 *
 * @card
 *   POP3 command-line validator (RFC 1939 + RFC 2449 capabilities +
 *   RFC 2595 STLS + RFC 5034 AUTH). Refuses bare-CR / bare-LF
 *   (smuggling defense), caps command-line / username / password / msg
 *   bytes, validates per-verb shape.
 */

var { defineClass } = require("./framework-error");

var GuardPop3CommandError = defineClass("GuardPop3CommandError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict: {
    maxLineBytes:       255,                                                                         // RFC 2449 §4 cap
    maxUsernameBytes:   40,                                                                          // RFC 1939 §3 cap
    maxPasswordBytes:   40,                                                                          // RFC 1939 §3 cap
    allowBareLf:        false,
    allowApop:          false,                                                                       // RFC 1939 §7 — legacy challenge-response with MD5; refuse under strict (M³AAWG)
  },
  balanced: {
    maxLineBytes:       512,                                                                         // RFC 2449 §4 response cap
    maxUsernameBytes:   128,                                                                         // balanced username cap
    maxPasswordBytes:   128,                                                                         // balanced password cap
    allowBareLf:        false,
    allowApop:          true,
  },
  permissive: {
    maxLineBytes:       1024,                                                                        // permissive cap for legacy peers
    maxUsernameBytes:   256,                                                                         // permissive username cap
    maxPasswordBytes:   256,                                                                         // permissive password cap
    allowBareLf:        true,
    allowApop:          true,
  },
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

// POP3 verbs per RFC 1939 §6 + RFC 2449 §5 + RFC 2595 §4 + RFC 5034.
var KNOWN_VERBS = Object.freeze({
  USER: true, PASS: true, APOP: true, AUTH: true, STLS: true,
  CAPA: true, STAT: true, LIST: true, RETR: true, DELE: true,
  NOOP: true, RSET: true, TOP:  true, UIDL: true, QUIT: true,
});

var ZERO_ARG_VERBS = Object.freeze({
  STLS: true, CAPA: true, STAT: true, NOOP: true, RSET: true, QUIT: true,
});

var MSG_NUM_RE = /^[1-9][0-9]{0,9}$/;                                                                 // allow:regex-no-length-cap — anchored + bounded repeat

/**
 * @primitive b.guardPop3Command.validate
 * @signature b.guardPop3Command.validate(line, opts?)
 * @since     0.9.52
 * @status    stable
 * @related   b.guardSmtpCommand.validate, b.guardImapCommand.validate
 *
 * Validate a single POP3 command line (without its CRLF terminator).
 * Returns `{ verb, args }` on success; throws `GuardPop3CommandError`
 * on refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   tls:       boolean,    // when false + verb is USER/PASS under
 *                            strict, refuse with `guard-pop3-command/
 *                            cleartext-auth` (TLS required for credentials)
 *
 * @example
 *   var parsed = b.guardPop3Command.validate("USER alice", { tls: true });
 *   // → { verb: "USER", args: ["alice"] }
 *
 *   var pending = b.guardPop3Command.validate("RETR 12");
 *   // → { verb: "RETR", args: ["12"] }
 */
function validate(line, opts) {
  opts = opts || {};
  var profileName = typeof opts.profile === "string" ? opts.profile : DEFAULT_PROFILE;
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    profileName = COMPLIANCE_POSTURES[opts.posture];
  }
  var caps = PROFILES[profileName];
  if (!caps) {
    throw new GuardPop3CommandError("guard-pop3-command/bad-profile",
      "guardPop3Command.validate: unknown profile '" + profileName + "'");
  }
  if (typeof line !== "string") {
    throw new GuardPop3CommandError("guard-pop3-command/bad-input",
      "guardPop3Command.validate: line must be a string");
  }
  if (line.length === 0) {
    throw new GuardPop3CommandError("guard-pop3-command/empty-line",
      "guardPop3Command.validate: empty command line");
  }
  if (line.length > caps.maxLineBytes) {
    throw new GuardPop3CommandError("guard-pop3-command/line-too-long",
      "guardPop3Command.validate: line " + line.length + " bytes exceeds cap " + caps.maxLineBytes);
  }
  for (var i = 0; i < line.length; i += 1) {
    var c = line.charCodeAt(i);
    if (c === 0x00 || c === 0x7F || (c < 0x20 && c !== 0x09)) {                                       // control-byte refusal
      if (c === 0x0A && caps.allowBareLf) continue;
      throw new GuardPop3CommandError("guard-pop3-command/bad-byte",
        "guardPop3Command.validate: control byte 0x" + c.toString(16) + " at offset " + i);          // hex format literal in error message
    }
  }

  var firstSpace = line.indexOf(" ");
  var verb = (firstSpace === -1 ? line : line.slice(0, firstSpace)).toUpperCase();
  var rest = firstSpace === -1 ? "" : line.slice(firstSpace + 1);

  if (!KNOWN_VERBS[verb]) {
    throw new GuardPop3CommandError("guard-pop3-command/unknown-verb",
      "guardPop3Command.validate: unknown verb '" + verb + "' (RFC 1939 §6)");
  }
  if (ZERO_ARG_VERBS[verb] && rest.length > 0) {
    throw new GuardPop3CommandError("guard-pop3-command/unexpected-args",
      "guardPop3Command.validate: verb '" + verb + "' takes no arguments");
  }

  // Per-verb shape — switch dispatch (statically resolved, not
  // dynamic; CodeQL accepts switch as a fixed call graph).
  var args = [];
  switch (verb) {
  case "USER":
    if (!rest) throw new GuardPop3CommandError("guard-pop3-command/missing-username",
      "guardPop3Command.validate: USER requires a name argument");
    if (rest.length > caps.maxUsernameBytes) {
      throw new GuardPop3CommandError("guard-pop3-command/username-too-long",
        "guardPop3Command.validate: USER name " + rest.length + " bytes exceeds cap " + caps.maxUsernameBytes);
    }
    if (opts.tls === false && profileName === "strict") {
      throw new GuardPop3CommandError("guard-pop3-command/cleartext-auth",
        "guardPop3Command.validate: USER refused over cleartext (use STLS first; RFC 2595)");
    }
    args = [rest];
    break;
  case "PASS":
    if (!rest) throw new GuardPop3CommandError("guard-pop3-command/missing-password",
      "guardPop3Command.validate: PASS requires a password argument");
    if (rest.length > caps.maxPasswordBytes) {
      throw new GuardPop3CommandError("guard-pop3-command/password-too-long",
        "guardPop3Command.validate: PASS argument " + rest.length + " bytes exceeds cap " + caps.maxPasswordBytes);
    }
    if (opts.tls === false && profileName === "strict") {
      throw new GuardPop3CommandError("guard-pop3-command/cleartext-auth",
        "guardPop3Command.validate: PASS refused over cleartext (use STLS first; RFC 2595)");
    }
    args = [rest];
    break;
  case "APOP":
    if (!caps.allowApop) {
      throw new GuardPop3CommandError("guard-pop3-command/apop-refused",
        "guardPop3Command.validate: APOP refused under profile '" + profileName +
        "' (RFC 1939 §7 uses MD5 challenge-response; deprecated by M³AAWG)");
    }
    var apopParts = rest.split(" ");
    if (apopParts.length !== 2) {
      throw new GuardPop3CommandError("guard-pop3-command/bad-apop",
        "guardPop3Command.validate: APOP requires `name digest`");
    }
    args = apopParts;
    break;
  case "AUTH":
    // RFC 5034 — `AUTH` alone lists supported mechanisms; `AUTH MECH`
    // initiates a mechanism. Allow either shape.
    args = rest ? rest.split(" ") : [];
    // RFC 2595 §2.1 + RFC 5034 §4 — credentials over cleartext are
    // refused under strict identically to USER/PASS. `AUTH` with no
    // mech argument is a CAPA-style enumeration and stays allowed
    // pre-TLS; a mech-bearing AUTH initiates the credential exchange
    // and MUST be over TLS.
    if (args.length > 0 && opts.tls === false && profileName === "strict") {
      throw new GuardPop3CommandError("guard-pop3-command/cleartext-auth",
        "guardPop3Command.validate: AUTH " + args[0] + " refused over cleartext (use STLS first; RFC 2595 §2.1 + RFC 5034 §4)");
    }
    break;
  case "LIST":
  case "UIDL":
    // Optional msg-number argument.
    if (rest) {
      if (!MSG_NUM_RE.test(rest)) {                                                                  // allow:regex-no-length-cap — MSG_NUM_RE anchored + bounded
        throw new GuardPop3CommandError("guard-pop3-command/bad-msg-number",
          "guardPop3Command.validate: " + verb + " msg-number must be a positive decimal integer");
      }
      args = [rest];
    }
    break;
  case "RETR":
  case "DELE":
    if (!rest || !MSG_NUM_RE.test(rest)) {                                                            // allow:regex-no-length-cap — MSG_NUM_RE anchored + bounded
      throw new GuardPop3CommandError("guard-pop3-command/bad-msg-number",
        "guardPop3Command.validate: " + verb + " requires a positive decimal message-number");
    }
    args = [rest];
    break;
  case "TOP":
    // `TOP msg n` — message + non-negative line-count.
    var topParts = rest.split(" ");
    if (topParts.length !== 2 ||
        !MSG_NUM_RE.test(topParts[0]) ||                                                              // allow:regex-no-length-cap — MSG_NUM_RE anchored + bounded
        !/^[0-9]{1,10}$/.test(topParts[1])) {                                                         // allow:regex-no-length-cap — anchored + bounded line-count
      throw new GuardPop3CommandError("guard-pop3-command/bad-top",
        "guardPop3Command.validate: TOP requires `msg-num line-count` (both decimal)");
    }
    args = topParts;
    break;
  default:
    // STLS / CAPA / STAT / NOOP / RSET / QUIT — ZERO_ARG_VERBS guard
    // above already enforced no-args. Empty args.
    args = [];
    break;
  }

  return { verb: verb, args: args };
}

/**
 * @primitive b.guardPop3Command.compliancePosture
 * @signature b.guardPop3Command.compliancePosture(posture)
 * @since     0.9.52
 * @status    stable
 *
 * Return the effective profile for a compliance posture, or `null`
 * for unknown names.
 *
 * @example
 *   b.guardPop3Command.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

module.exports = {
  validate:                 validate,
  compliancePosture:        compliancePosture,
  PROFILES:                 PROFILES,
  COMPLIANCE_POSTURES:      COMPLIANCE_POSTURES,
  KNOWN_VERBS:              KNOWN_VERBS,
  ZERO_ARG_VERBS:           ZERO_ARG_VERBS,
  GuardPop3CommandError:    GuardPop3CommandError,
};

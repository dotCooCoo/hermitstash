// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.guardManageSieveCommand
 * @nav        Guards
 * @title      Guard ManageSieve Command
 * @order      454
 *
 * @intro
 *   ManageSieve command-line validator (RFC 5804 — "A Protocol for
 *   Remotely Managing Sieve Scripts"). Gates every verb the framework's
 *   ManageSieve listener accepts from peers — `AUTHENTICATE` /
 *   `STARTTLS` / `LOGOUT` / `CAPABILITY` / `HAVESPACE` / `PUTSCRIPT` /
 *   `LISTSCRIPTS` / `SETACTIVE` / `GETSCRIPT` / `DELETESCRIPT` /
 *   `RENAMESCRIPT` / `NOOP`.
 *
 *   ManageSieve is a line-oriented text protocol that mixes simple
 *   single-line commands with literal-syntax payloads (`{N}` / `{N+}`)
 *   carrying script bytes verbatim. Responses are `OK ...` / `NO ...` /
 *   `BYE ...` per RFC 5804 §1.2.
 *
 *   ## Smuggling defense — bare-CR / bare-LF refusal
 *
 *   Same wire-protocol concern as SMTP / IMAP / POP3. Command lines
 *   MUST be canonical CRLF-terminated; bare-CR or bare-LF inside a
 *   command (outside the literal-payload window) is refused. The
 *   listener clears the receive buffer at STARTTLS upgrade to defend
 *   the same pre-handshake injection class that affected STARTTLS in
 *   Exim (CVE-2021-38371) / Dovecot (CVE-2021-33515) / Postfix
 *   (CVE-2011-0411).
 *
 *   ## Cleartext-AUTH refusal under strict
 *
 *   RFC 5804 §1.1 + RFC 4954 §4 — `AUTHENTICATE` with credential-
 *   bearing mechanisms (PLAIN / LOGIN) over a cleartext channel
 *   exposes the password to passive observation. Strict + balanced
 *   refuse `AUTHENTICATE PLAIN` / `AUTHENTICATE LOGIN` pre-TLS; the
 *   listener composes this gate at the validate boundary AND
 *   re-checks at the dispatch boundary as defense-in-depth.
 *
 *   `AUTHENTICATE EXTERNAL` (RFC 4422 §4) is exempt — the credential
 *   is the TLS client certificate already presented, so cleartext is
 *   not the concern. `AUTHENTICATE SCRAM-SHA-256` (RFC 7677) and
 *   `AUTHENTICATE OAUTHBEARER` (RFC 7628) are mechanism-side
 *   credential-protected and may run pre-TLS under permissive; strict
 *   still requires TLS (defense-in-depth + active-MITM resistance).
 *
 *   ## Script-name shape (RFC 5804 §2.1)
 *
 *   Script names are UTF-8 strings of 1-512 octets containing no NUL
 *   (0x00), CR (0x0D), LF (0x0A), forward-slash (0x2F), backslash
 *   (0x5C), or double-quote (0x22). The forward-slash + backslash
 *   refusal blocks path-traversal-style storage-backend collisions;
 *   the NUL/CR/LF refusal blocks wire-protocol smuggling.
 *
 *   ## Literal syntax (RFC 5804 §2.3 + RFC 7888 LITERAL+)
 *
 *   `PUTSCRIPT name {N}` / `PUTSCRIPT name {N+}` introduces an N-byte
 *   script payload. The bare `{N}` form is synchronizing (server
 *   replies with a continuation request before the client sends the
 *   payload); `{N+}` (RFC 7888) is non-synchronizing. The validator
 *   refuses N values above the per-profile script-byte cap (matching
 *   `b.safeSieve`'s `maxScriptBytes`: 64 KiB strict / 256 KiB balanced
 *   / 1 MiB permissive).
 *
 *   ## Per-verb shape
 *
 *   RFC 5804 §2.1-§2.10:
 *
 *     - `AUTHENTICATE` "<mech>" [<literal-initial-response>]
 *     - `STARTTLS`                — no args
 *     - `LOGOUT`                  — no args
 *     - `CAPABILITY`              — no args
 *     - `NOOP` [string]           — optional echo-tag arg
 *     - `HAVESPACE` "<name>" <N>  — name + non-negative integer
 *     - `PUTSCRIPT` "<name>" <literal-script>
 *     - `LISTSCRIPTS`             — no args
 *     - `SETACTIVE` "<name>"      — single script-name arg (empty
 *                                   string deactivates all per §2.8)
 *     - `GETSCRIPT` "<name>"      — single script-name arg
 *     - `DELETESCRIPT` "<name>"   — single script-name arg
 *     - `RENAMESCRIPT` "<old>" "<new>"  — two script-name args
 *
 *   ## Caps
 *
 *     - Per-line cap (excluding the literal payload itself): 8 KiB
 *       strict / 16 KiB balanced / 64 KiB permissive. ManageSieve's
 *       command lines are LONGER than POP3/IMAP because script names
 *       may carry UTF-8 + the literal-payload announcement.
 *     - Script-byte cap (literal `{N}` value): same as
 *       `b.safeSieve.PROFILES.<profile>.maxScriptBytes` — 64 KiB /
 *       256 KiB / 1 MiB.
 *     - Script name: RFC 5804 §2.1 1-512 octets.
 *
 *   Throws `GuardManageSieveCommandError` on every refusal.
 *
 * @card
 *   ManageSieve command-line validator (RFC 5804 + RFC 7888 LITERAL+).
 *   Refuses bare-CR / bare-LF (smuggling defense), caps per-line +
 *   script-name + literal-script bytes, refuses cleartext AUTHENTICATE
 *   under strict (RFC 4954 §4 class), validates per-verb shape.
 */

var C = require("./constants");
var { defineClass } = require("./framework-error");
var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");
var safeBuffer = require("./safe-buffer");

var GuardManageSieveCommandError = defineClass("GuardManageSieveCommandError",
  { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

var MAX_SASL_TOKEN_BYTES = C.BYTES.kib(4);

var PROFILES = Object.freeze({
  strict: {
    maxLineBytes:        8192,
    maxScriptBytes:      65536,
    maxScriptNameBytes:  512,
    allowBareLf:         false,
    allowCleartextAuth:  false,
    allowLiteralPlus:    true,
  },
  balanced: {
    maxLineBytes:        16384,
    maxScriptBytes:      262144,
    maxScriptNameBytes:  512,
    allowBareLf:         false,
    allowCleartextAuth:  false,
    allowLiteralPlus:    true,
  },
  permissive: {
    maxLineBytes:        65536,
    maxScriptBytes:      1048576,
    maxScriptNameBytes:  512,
    allowBareLf:         true,
    allowCleartextAuth:  true,
    allowLiteralPlus:    true,
  },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var KNOWN_VERBS = Object.freeze({
  AUTHENTICATE: true, STARTTLS:    true, LOGOUT:       true,
  CAPABILITY:   true, NOOP:        true, HAVESPACE:    true,
  PUTSCRIPT:    true, LISTSCRIPTS: true, SETACTIVE:    true,
  GETSCRIPT:    true, DELETESCRIPT: true, RENAMESCRIPT: true,
});

var ZERO_ARG_VERBS = Object.freeze({
  STARTTLS:    true,
  LOGOUT:      true,
  CAPABILITY:  true,
  LISTSCRIPTS: true,
});

var CLEARTEXT_VULNERABLE_MECHS = Object.freeze({
  PLAIN: true,
  LOGIN: true,
});

var MAX_NUM_DIGITS = 10;
var DECIMAL_RADIX = 10;

function _isNumericArg(s) {
  return codepointClass.isRunOf(s, codepointClass.ASCII_DIGITS, 1, MAX_NUM_DIGITS);
}

function _parseLiteral(s) {
  if (s.charAt(0) !== "{" || s.charAt(s.length - 1) !== "}") return null;
  var body = s.slice(1, s.length - 1);
  var nonSync = body.charAt(body.length - 1) === "+";
  var digits = nonSync ? body.slice(0, -1) : body;
  if (!_isNumericArg(digits)) return null;
  return { digits: digits, nonSync: nonSync };
}

/**
 * @primitive b.guardManageSieveCommand.validate
 * @signature b.guardManageSieveCommand.validate(line, opts?)
 * @since     0.9.57
 * @status    stable
 * @related   b.guardPop3Command.validate, b.guardImapCommand.validate, b.safeSieve.parse
 *
 * Validate a single ManageSieve command line (without its CRLF
 * terminator, and without the literal-script payload that may follow).
 * Returns a shape describing the parsed verb + arguments + (when
 * applicable) the trailing literal-byte count the listener must read
 * from the wire. Throws `GuardManageSieveCommandError` on refusal.
 *
 * @opts
 *   profile:   "strict" | "balanced" | "permissive",
 *   posture:   "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   tls:       boolean,    // when false + AUTHENTICATE PLAIN/LOGIN
 *                            under strict, refuse with
 *                            `guard-managesieve-command/cleartext-auth`
 *                            (RFC 4954 §4 + RFC 5804 §1.1)
 *
 * @example
 *   var p = b.guardManageSieveCommand.validate('PUTSCRIPT "myscript" {52+}', { tls: true });
 *   // → { verb: "PUTSCRIPT", args: ["myscript"], literalBytes: 52, literalPlus: true }
 *
 *   var c = b.guardManageSieveCommand.validate("CAPABILITY", { tls: true });
 *   // → { verb: "CAPABILITY", args: [] }
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
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-profile",
      "guardManageSieveCommand.validate: unknown profile '" + profileName + "'");
  }
  if (typeof line !== "string") {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-input",
      "guardManageSieveCommand.validate: line must be a string");
  }
  if (line.length === 0) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/empty-line",
      "guardManageSieveCommand.validate: empty command line");
  }
  if (safeBuffer.byteLengthOf(line) > caps.maxLineBytes) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/line-too-long",
      "guardManageSieveCommand.validate: line " + safeBuffer.byteLengthOf(line) +
      " bytes exceeds cap " + caps.maxLineBytes);
  }

  var inQuote = false;
  for (var i = 0; i < line.length; i += 1) {
    var c = line.charCodeAt(i);
    if (c === 0x22 && !_isEscaped(line, i)) {
      inQuote = !inQuote;
      continue;
    }
    if (inQuote) continue;
    if (codepointClass.isForbiddenControlChar(c, { allowLf: caps.allowBareLf })) {
      throw new GuardManageSieveCommandError("guard-managesieve-command/bad-byte",
        "guardManageSieveCommand.validate: control byte 0x" +
        c.toString(16) + " at offset " + i);
    }
  }
  if (inQuote) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/unterminated-string",
      "guardManageSieveCommand.validate: unterminated quoted string");
  }

  var firstSpace = line.indexOf(" ");
  var verb = (firstSpace === -1 ? line : line.slice(0, firstSpace)).toUpperCase();
  var rest = firstSpace === -1 ? "" : line.slice(firstSpace + 1);

  if (!Object.prototype.hasOwnProperty.call(KNOWN_VERBS, verb)) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/unknown-verb",
      "guardManageSieveCommand.validate: unknown verb '" + verb + "' (RFC 5804 §2)");
  }
  if (ZERO_ARG_VERBS[verb] && rest.length > 0) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/unexpected-args",
      "guardManageSieveCommand.validate: verb '" + verb + "' takes no arguments");
  }

  switch (verb) {
  case "AUTHENTICATE": return _validateAuthenticate(rest, caps, profileName, opts);
  case "NOOP":         return _validateNoop(rest, caps);
  case "HAVESPACE":    return _validateHavespace(rest, caps);
  case "PUTSCRIPT":    return _validatePutscript(rest, caps);
  case "SETACTIVE":    return _validateSingleName(verb, rest, caps, { allowEmpty: true });
  case "GETSCRIPT":    return _validateSingleName(verb, rest, caps, { allowEmpty: false });
  case "DELETESCRIPT": return _validateSingleName(verb, rest, caps, { allowEmpty: false });
  case "RENAMESCRIPT": return _validateRenamescript(rest, caps);
  default:
    return { verb: verb, args: [] };
  }
}

function _validateAuthenticate(rest, caps, profileName, opts) {
  if (!rest) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/missing-mechanism",
      "guardManageSieveCommand.validate: AUTHENTICATE requires a mechanism");
  }
  var parsed = _parseQuotedString(rest);
  if (parsed === null) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-mechanism",
      "guardManageSieveCommand.validate: AUTHENTICATE mechanism must be a quoted string");
  }
  var mech = parsed.value.toUpperCase();
  var trailing = parsed.rest;
  if (opts.tls === false && !caps.allowCleartextAuth) {
    if (CLEARTEXT_VULNERABLE_MECHS[mech] || profileName === "strict") {
      if (mech !== "EXTERNAL") {
        throw new GuardManageSieveCommandError("guard-managesieve-command/cleartext-auth",
          "guardManageSieveCommand.validate: AUTHENTICATE " + mech +
          " refused over cleartext (use STARTTLS first; RFC 5804 §1.1 + RFC 4954 §4)");
      }
    }
  }
  var literalBytes    = null;
  var literalPlus     = false;
  var initialResponse = null;
  if (trailing) {
    var lit = _parseLiteral(trailing);
    if (lit) {
      var n = parseInt(lit.digits, DECIMAL_RADIX);
      var isPlus = lit.nonSync;
      if (isPlus && !caps.allowLiteralPlus) {
        throw new GuardManageSieveCommandError("guard-managesieve-command/literal-plus-refused",
          "guardManageSieveCommand.validate: LITERAL+ refused under profile '" + profileName + "'");
      }
      if (n > MAX_SASL_TOKEN_BYTES) {
        throw new GuardManageSieveCommandError("guard-managesieve-command/literal-too-large",
          "guardManageSieveCommand.validate: AUTHENTICATE initial-response " +
          n + " bytes exceeds " + MAX_SASL_TOKEN_BYTES + "-byte cap");
      }
      literalBytes = n;
      literalPlus  = isPlus;
    } else {
      var inner = _parseQuotedString(trailing);
      if (inner === null || inner.rest.length > 0) {
        throw new GuardManageSieveCommandError("guard-managesieve-command/bad-initial-response",
          "guardManageSieveCommand.validate: AUTHENTICATE initial-response must be a " +
          "literal `{N}` / `{N+}` or quoted base64 string");
      }
      if (inner.value.length > MAX_SASL_TOKEN_BYTES) {
        throw new GuardManageSieveCommandError("guard-managesieve-command/literal-too-large",
          "guardManageSieveCommand.validate: AUTHENTICATE initial-response " +
          inner.value.length + " bytes exceeds " + MAX_SASL_TOKEN_BYTES + "-byte cap");
      }
      initialResponse = inner.value;
    }
  }
  return {
    verb:            "AUTHENTICATE",
    args:            [mech],
    literalBytes:    literalBytes,
    literalPlus:     literalPlus,
    initialResponse: initialResponse,
  };
}

function _validateNoop(rest, caps) {
  if (!rest) return { verb: "NOOP", args: [] };
  var parsed = _parseQuotedString(rest);
  if (parsed === null || parsed.rest.length > 0) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-noop-arg",
      "guardManageSieveCommand.validate: NOOP optional arg must be a quoted string");
  }
  _checkScriptNameBytes(parsed.value, caps);
  return { verb: "NOOP", args: [parsed.value] };
}

function _validateHavespace(rest, caps) {
  if (!rest) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-havespace",
      "guardManageSieveCommand.validate: HAVESPACE requires `\"name\" size`");
  }
  var parsed = _parseQuotedString(rest);
  if (parsed === null) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-havespace",
      "guardManageSieveCommand.validate: HAVESPACE script-name must be a quoted string");
  }
  _checkScriptName(parsed.value, caps);
  var sizeStr = parsed.rest;
  if (!sizeStr || !_isNumericArg(sizeStr)) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-havespace",
      "guardManageSieveCommand.validate: HAVESPACE size must be a positive decimal integer");
  }
  var size = parseInt(sizeStr, 10);
  if (size > caps.maxScriptBytes) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/script-too-large",
      "guardManageSieveCommand.validate: HAVESPACE size " + size +
      " bytes exceeds cap " + caps.maxScriptBytes);
  }
  return { verb: "HAVESPACE", args: [parsed.value, size] };
}

function _validatePutscript(rest, caps) {
  if (!rest) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-putscript",
      "guardManageSieveCommand.validate: PUTSCRIPT requires `\"name\" {N[+]}`");
  }
  var parsed = _parseQuotedString(rest);
  if (parsed === null) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-putscript",
      "guardManageSieveCommand.validate: PUTSCRIPT script-name must be a quoted string");
  }
  _checkScriptName(parsed.value, caps);
  var litStr = parsed.rest;
  if (!litStr) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-putscript",
      "guardManageSieveCommand.validate: PUTSCRIPT requires a literal `{N}` or `{N+}` payload announcement");
  }
  var m = _parseLiteral(litStr);
  if (!m) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-literal",
      "guardManageSieveCommand.validate: PUTSCRIPT literal must match `{N}` or `{N+}` (RFC 5804 §2.3 + RFC 7888)");
  }
  var n = parseInt(m.digits, DECIMAL_RADIX);
  var isPlus = m.nonSync;
  if (isPlus && !caps.allowLiteralPlus) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/literal-plus-refused",
      "guardManageSieveCommand.validate: LITERAL+ refused under current profile");
  }
  if (n > caps.maxScriptBytes) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/script-too-large",
      "guardManageSieveCommand.validate: PUTSCRIPT script " + n +
      " bytes exceeds cap " + caps.maxScriptBytes);
  }
  return {
    verb:         "PUTSCRIPT",
    args:         [parsed.value],
    literalBytes: n,
    literalPlus:  isPlus,
  };
}

function _validateSingleName(verb, rest, caps, nameOpts) {
  if (!rest) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/missing-name",
      "guardManageSieveCommand.validate: " + verb + " requires a quoted script-name argument");
  }
  var parsed = _parseQuotedString(rest);
  if (parsed === null || parsed.rest.length > 0) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-name",
      "guardManageSieveCommand.validate: " + verb + " script-name must be a quoted string");
  }
  if (parsed.value.length === 0) {
    if (!nameOpts.allowEmpty) {
      throw new GuardManageSieveCommandError("guard-managesieve-command/empty-name",
        "guardManageSieveCommand.validate: " + verb + " script-name must be non-empty");
    }
    return { verb: verb, args: [parsed.value] };
  }
  _checkScriptName(parsed.value, caps);
  return { verb: verb, args: [parsed.value] };
}

function _validateRenamescript(rest, caps) {
  if (!rest) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-rename",
      "guardManageSieveCommand.validate: RENAMESCRIPT requires `\"old\" \"new\"`");
  }
  var first = _parseQuotedString(rest);
  if (first === null || !first.rest) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-rename",
      "guardManageSieveCommand.validate: RENAMESCRIPT requires two quoted script-name arguments");
  }
  _checkScriptName(first.value, caps);
  var second = _parseQuotedString(first.rest);
  if (second === null || second.rest.length > 0) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/bad-rename",
      "guardManageSieveCommand.validate: RENAMESCRIPT second arg must be a quoted script-name");
  }
  _checkScriptName(second.value, caps);
  return { verb: "RENAMESCRIPT", args: [first.value, second.value] };
}

/**
 * @primitive  b.guardManageSieveCommand.parseQuotedString
 * @signature  b.guardManageSieveCommand.parseQuotedString(s)
 * @since      0.18.54
 * @status     stable
 * @related    b.guardManageSieveCommand.validate, b.mail.server.managesieve.create
 *
 * Read a leading RFC 5804 §1.2 quoted string off `s` and return
 * `{ value, rest }`, where `value` is the unescaped content and `rest` is
 * what follows with leading whitespace removed. Returns `null` when `s` does
 * not begin with a double quote.
 *
 * The production honors the `\"` and `\\` escapes, and refuses NUL, CR and
 * LF inside the quotes: those end a line-oriented protocol record, so a
 * string carrying one would split the command it appears in.
 *
 * Exposed because a `string` also arrives outside a command, as the client's
 * reply to a SASL challenge. That line never reaches `validate`, and a second
 * hand-rolled unquoting there would be free to lose the escape handling and
 * the control-byte refusal this one has. `b.mail.server.managesieve` reads
 * its SASL responses through this.
 *
 * @example
 *   b.guardManageSieveCommand.parseQuotedString('"PLAIN" {12+}');
 *   // → { value: "PLAIN", rest: "{12+}" }
 *   b.guardManageSieveCommand.parseQuotedString("PLAIN");
 *   // → null
 */
function _parseQuotedString(s) {
  if (s.length === 0 || s.charCodeAt(0) !== 0x22) return null;
  var out = "";
  var i = 1;
  while (i < s.length) {
    var c = s.charCodeAt(i);
    if (c === 0x5C) {
      if (i + 1 >= s.length) return null;
      var esc = s.charCodeAt(i + 1);
      if (esc === 0x22) { out += '"'; i += 2; continue; }
      if (esc === 0x5C) { out += "\\"; i += 2; continue; }
      return null;
    }
    if (c === 0x22) {
      var rest = s.slice(i + 1);
      var k = 0;
      while (k < rest.length && (rest.charCodeAt(k) === 0x20 || rest.charCodeAt(k) === 0x09)) k += 1;
      return { value: out, rest: rest.slice(k) };
    }
    if (c === 0x00 || c === 0x0D || c === 0x0A) return null;
    out += s[i];
    i += 1;
  }
  return null;
}

function _isEscaped(line, i) {
  var n = 0;
  var j = i - 1;
  while (j >= 0 && line.charCodeAt(j) === 0x5C) { n += 1; j -= 1; }
  return (n & 1) === 1;
}

function _checkScriptName(name, caps) {
  if (name.length === 0) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/empty-name",
      "guardManageSieveCommand.validate: script-name must be non-empty (RFC 5804 §2.1)");
  }
  _checkScriptNameBytes(name, caps);
  for (var i = 0; i < name.length; i += 1) {
    var c = name.charCodeAt(i);
    if (c === 0x2F || c === 0x5C) {
      throw new GuardManageSieveCommandError("guard-managesieve-command/bad-name-byte",
        "guardManageSieveCommand.validate: script-name byte 0x" +
        c.toString(16) + " refused (RFC 5804 §2.1)");
    }
    if (c === 0x00) {
      throw new GuardManageSieveCommandError("guard-managesieve-command/bad-name-byte",
        "guardManageSieveCommand.validate: NUL byte refused in script-name (RFC 5804 §2.1)");
    }
  }
}

function _checkScriptNameBytes(name, caps) {
  var byteLen = Buffer.byteLength(name, "utf8");
  if (byteLen > caps.maxScriptNameBytes) {
    throw new GuardManageSieveCommandError("guard-managesieve-command/name-too-long",
      "guardManageSieveCommand.validate: script-name " + byteLen +
      " UTF-8 bytes exceeds cap " + caps.maxScriptNameBytes + " (RFC 5804 §2.1)");
  }
}

module.exports = gateContract.defineParser({
  name:       "managesieve-command",
  entry:      validate,
  errorClass: GuardManageSieveCommandError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    KNOWN_VERBS:    KNOWN_VERBS,
    ZERO_ARG_VERBS: ZERO_ARG_VERBS,
    MAX_SASL_TOKEN_BYTES: MAX_SASL_TOKEN_BYTES,
    parseQuotedString: _parseQuotedString,
  },
});

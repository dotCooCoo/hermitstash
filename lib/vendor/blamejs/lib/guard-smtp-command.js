"use strict";
/**
 * @module     b.guardSmtpCommand
 * @nav        Guards
 * @title      Guard SMTP Command
 * @order      450
 *
 * @intro
 *   SMTP command-line validator. Gates every command verb the framework's
 *   inbound MX listener (v0.9.34) and outbound submission listener
 *   (v0.9.35) accept from peers — `EHLO` / `HELO` / `MAIL FROM` /
 *   `RCPT TO` / `DATA` / `BDAT` / `VRFY` / `EXPN` / `NOOP` / `RSET` /
 *   `QUIT` / `AUTH` / `STARTTLS` / `HELP`.
 *
 *   ## Smuggling defense — bare-CR / bare-LF refusal
 *
 *   The SMTP smuggling class (`CVE-2023-51764` Postfix, `CVE-2023-51765`
 *   Sendmail, `CVE-2023-51766` Exim, `CVE-2026-32178` .NET
 *   `System.Net.Mail`) exploits implementations that accept the
 *   non-standard end-of-data sequence `<LF>.<LF>` or `<LF>.<CR><LF>`
 *   instead of the standard `<CR><LF>.<CR><LF>`. The introduced break-
 *   out lets a malicious peer inject a second message past SPF / DMARC
 *   checks performed only on the outer envelope.
 *
 *   At the command-line level the defense is the same: every command
 *   line MUST be CRLF-terminated; bare `\r` or `\n` anywhere inside a
 *   command line is refused. Operators with peers that legitimately
 *   speak bare-LF (rare; legacy Sendmail-to-Sendmail) opt into
 *   `permissive` profile with audit emit per accepted bare-LF line.
 *
 *   ## STARTTLS command-buffer injection
 *
 *   `CVE-2021-38371` (Exim STARTTLS response injection) and
 *   `CVE-2021-33515` (Dovecot lib-smtp STARTTLS command injection)
 *   exploit implementations that don't drain the pre-STARTTLS receive
 *   buffer when negotiating TLS — commands queued by an MitM before
 *   the handshake get applied to the post-handshake (TLS-protected)
 *   stream. The fix is stateful (drain the buffer on STARTTLS), so
 *   this guard alone can't fully defend; it surfaces the requirement
 *   to the v0.9.34 listener via `validate({ verb: "STARTTLS" })`
 *   refusing trailing payload on the STARTTLS line and the listener's
 *   pipelining-after-STARTTLS check enforcing buffer drain.
 *
 *   ## Per-verb shape
 *
 *   Each verb has a fixed argument shape (RFC 5321 §3 / §4.1):
 *
 *     - `EHLO` / `HELO` — exactly one arg (domain or address literal).
 *     - `MAIL` — `FROM:<reverse-path>` (RFC 5321 §3.3) + optional
 *       `SIZE=` / `BODY=` / `RET=` / `ENVID=` / `AUTH=` extension
 *       params.
 *     - `RCPT` — `TO:<forward-path>` (RFC 5321 §3.3) + optional
 *       `NOTIFY=` / `ORCPT=` extension params.
 *     - `DATA` — no args.
 *     - `BDAT` — single decimal chunk size + optional `LAST` keyword
 *       (RFC 3030 CHUNKING).
 *     - `VRFY` / `EXPN` — single mailbox arg.
 *     - `NOOP` — optional opaque string.
 *     - `RSET` / `QUIT` / `STARTTLS` — no args.
 *     - `AUTH` — SASL mechanism name + optional initial-response
 *       (RFC 4954).
 *     - `HELP` — optional argument.
 *
 *   Anything not matching the shape under `strict` profile is refused
 *   with `guard-smtp-command/bad-shape`.
 *
 *   ## Caps
 *
 *     - Command line (path + arguments + CRLF) capped at 512 bytes
 *       per RFC 5321 §4.5.3.1.1. SMTPUTF8 / EAI peers (RFC 6531) may
 *       send longer command lines for non-ASCII addresses; `balanced`
 *       profile bumps the cap to 1024.
 *     - Forward-path / reverse-path mailbox capped at 256 bytes per
 *       RFC 5321 §4.5.3.1.3.
 *     - Domain part of a path capped at 255 bytes per RFC 1035
 *       §2.3.4.
 *     - Local part capped at 64 bytes per RFC 5321 §4.5.3.1.1.
 *
 *   Throws `GuardSmtpCommandError` on every refusal. Pure-functional —
 *   no I/O, no state. The MX / submission listener composes one
 *   instance per accepted connection.
 *
 * @card
 *   SMTP command-line validator. Refuses bare-CR / bare-LF (smuggling
 *   defense, CVE-2023-51764/51765/51766/2026-32178), caps line + path
 *   + domain + local-part byte lengths (RFC 5321 §4.5.3.1), per-verb
 *   shape check (EHLO / HELO / MAIL FROM / RCPT TO / DATA / BDAT /
 *   VRFY / EXPN / NOOP / RSET / QUIT / AUTH / STARTTLS / HELP).
 */

var { defineClass } = require("./framework-error");
var gateContract    = require("./gate-contract");

var GuardSmtpCommandError = defineClass("GuardSmtpCommandError", { alwaysPermanent: true });

var DEFAULT_PROFILE = "strict";

// RFC 5321 §4.5.3.1.1 — 512-octet line cap (excluding the trailing
// CRLF). SMTPUTF8 / EAI extends this in practice; balanced/permissive
// raise the cap accordingly.
var PROFILES = Object.freeze({
  strict:     { maxLineBytes: 512, maxMailbox: 256, maxLocalPart: 64, maxDomain: 255, allowBareLf: false, allowSmtpUtf8: false },                                                                          // allow:raw-byte-literal — RFC 5321 §4.5.3.1.1 caps
  balanced:   { maxLineBytes: 1024, maxMailbox: 320, maxLocalPart: 64, maxDomain: 255, allowBareLf: false, allowSmtpUtf8: true },                                                                          // allow:raw-byte-literal — SMTPUTF8 (RFC 6531) line cap
  permissive: { maxLineBytes: 4096, maxMailbox: 512, maxLocalPart: 64, maxDomain: 255, allowBareLf: true,  allowSmtpUtf8: true },                                                                          // allow:raw-byte-literal — permissive cap for legacy peers
});

var COMPLIANCE_POSTURES = Object.freeze({
  hipaa:     "strict",
  "pci-dss": "strict",
  gdpr:      "strict",
  soc2:      "strict",
});

// Verbs we know — anything else is refused under strict, accepted as
// opaque under permissive (operator's responsibility to handle).
var KNOWN_VERBS = Object.freeze({
  EHLO: true, HELO: true, MAIL: true, RCPT: true, DATA: true,
  BDAT: true, VRFY: true, EXPN: true, NOOP: true, RSET: true,
  QUIT: true, AUTH: true, STARTTLS: true, HELP: true,
});

// Verbs that take exactly zero arguments (anything trailing the verb
// itself is refused). DATA's trailing CRLF is the end-of-command, not
// an argument.
var ZERO_ARG_VERBS = Object.freeze({ DATA: true, RSET: true, QUIT: true, STARTTLS: true });

// Address-literal shape per RFC 5321 §4.1.3 (very loose — full
// validation lives in safeUrl / IP-address parsing; here we just
// gate the SMTP-side bracket shape).
var ADDR_LIT_RE   = /^\[(?:IPv6:)?[0-9A-Fa-f:.]+\]$/;                                                                                                                                                     // allow:regex-no-length-cap — caller's command line is already maxLineBytes-capped
var DOMAIN_RE     = /^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/;                                                                                                                                        // allow:regex-no-length-cap — domain length is checked separately against maxDomain
var DECIMAL_RE    = /^[1-9][0-9]{0,9}$|^0$/;                                                                                                                                                              // allow:regex-no-length-cap — bounded by anchor + repeat-cap

/**
 * @primitive b.guardSmtpCommand.validate
 * @signature b.guardSmtpCommand.validate(line, opts?)
 * @since     0.9.32
 * @status    stable
 * @related   b.guardEmail.validateMessage, b.safeMime.parse
 *
 * Validate a single SMTP command line (without its CRLF terminator —
 * the listener strips that before calling this). Returns a structured
 * `{ verb, args, params }` shape on success; throws
 * `GuardSmtpCommandError` on any refusal.
 *
 * @opts
 *   profile:  "strict" | "balanced" | "permissive",
 *   posture:  "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var parsed = b.guardSmtpCommand.validate("MAIL FROM:<alice@example.com> SIZE=12345");
 *   // → { verb: "MAIL", args: ["FROM:<alice@example.com>"], params: { SIZE: "12345" } }
 */
function validate(line, opts) {
  opts = opts || {};
  var caps = _resolveProfile(opts);
  if (typeof line !== "string") {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-input",
      "guardSmtpCommand.validate: line must be a string; got " + (typeof line));
  }
  if (line.length === 0) {
    throw new GuardSmtpCommandError("guard-smtp-command/empty",
      "guardSmtpCommand.validate: empty command line");
  }
  if (Buffer.byteLength(line, caps.allowSmtpUtf8 ? "utf8" : "ascii") > caps.maxLineBytes) {
    throw new GuardSmtpCommandError("guard-smtp-command/oversize-line",
      "guardSmtpCommand.validate: line exceeds maxLineBytes=" + caps.maxLineBytes +
      " (RFC 5321 §4.5.3.1.1)");
  }
  // Smuggling defense — refuse bare CR / bare LF anywhere in the line.
  // Listener has already stripped the terminating CRLF before calling.
  if (line.indexOf("\r") !== -1) {
    throw new GuardSmtpCommandError("guard-smtp-command/bare-cr",
      "guardSmtpCommand.validate: bare CR in command line (RFC 5321 §2.3.8; " +
      "smuggling defense CVE-2023-51764/51765/51766)");
  }
  if (line.indexOf("\n") !== -1 && !caps.allowBareLf) {
    throw new GuardSmtpCommandError("guard-smtp-command/bare-lf",
      "guardSmtpCommand.validate: bare LF in command line (RFC 5321 §2.3.8; " +
      "smuggling defense CVE-2023-51764/51765/51766/2026-32178)");
  }
  if (line.indexOf("\u0000") !== -1) {
    throw new GuardSmtpCommandError("guard-smtp-command/nul",
      "guardSmtpCommand.validate: NUL byte refused");
  }
  // C0 controls (except SP=0x20, HTAB=0x09 not legal in commands, and
  // LF=0x0a when allowBareLf is true under permissive profile per
  // legacy Sendmail compat) plus DEL.
  for (var i = 0; i < line.length; i += 1) {
    var c = line.charCodeAt(i);
    // LF under permissive: allowed by profile, already passed the
    // bare-LF refusal earlier in this fn. Skip the control-char throw
    // so the documented allowBareLf path actually accepts LF (Codex
    // caught this: permissive profile was effectively broken).
    if (c === 0x0a && caps.allowBareLf) continue;                                                                                                                                                            // allow:raw-byte-literal — RFC 5321 §2.3.8 LF, permissive bypass
    if (c < 0x20 || c === 0x7f) {                                                                                                                                                                          // allow:raw-byte-literal — RFC 5321 §2.3.8 forbids C0 / DEL
      throw new GuardSmtpCommandError("guard-smtp-command/control-char",
        "guardSmtpCommand.validate: control char 0x" + c.toString(16) + " refused");
    }
    if (!caps.allowSmtpUtf8 && c > 0x7e) {                                                                                                                                                                 // allow:raw-byte-literal — RFC 5321 §2.3.1 7-bit ASCII; SMTPUTF8 relaxes
      throw new GuardSmtpCommandError("guard-smtp-command/non-ascii",
        "guardSmtpCommand.validate: non-ASCII byte refused (no SMTPUTF8 negotiated)");
    }
  }
  var firstSpace = line.indexOf(" ");
  var verb = (firstSpace === -1 ? line : line.slice(0, firstSpace)).toUpperCase();
  var rest = firstSpace === -1 ? "" : line.slice(firstSpace + 1);

  if (!KNOWN_VERBS[verb]) {
    throw new GuardSmtpCommandError("guard-smtp-command/unknown-verb",
      "guardSmtpCommand.validate: unknown verb '" + verb + "' (RFC 5321 §3)");
  }
  if (ZERO_ARG_VERBS[verb] && rest.length > 0) {
    throw new GuardSmtpCommandError("guard-smtp-command/unexpected-args",
      "guardSmtpCommand.validate: verb '" + verb + "' takes no arguments");
  }

  // Verb→parser dispatch via switch — the switch arms are not a
  // dynamic call: each `case` invokes a statically-resolved function
  // by name, so CodeQL's js/unvalidated-dynamic-method-call tracker
  // sees a fixed call graph rather than user-controlled dispatch.
  // (KNOWN_VERBS gates `verb` upstream to the closed set below; the
  // KNOWN_VERBS check itself is a property read on a frozen
  // Object.create(null)-equivalent table, which CodeQL accepts as
  // boolean data access.)
  switch (verb) {
  case "EHLO":
  case "HELO":     return _validateGreeting(verb, rest, caps);
  case "MAIL":     return _validatePath(verb, rest, caps, "FROM:");
  case "RCPT":     return _validatePath(verb, rest, caps, "TO:");
  case "BDAT":     return _validateBdat(rest);
  case "VRFY":
  case "EXPN":     return _validateMailbox(verb, rest, caps);
  case "AUTH":     return _parseAuthCommandSyntax(rest);
  case "NOOP":
  case "HELP":     return { verb: verb, args: rest ? [rest] : [], params: {} };
  default:         return { verb: verb, args: [], params: {} };
  }
}

/**
 * @primitive b.guardSmtpCommand.compliancePosture
 * @signature b.guardSmtpCommand.compliancePosture(posture)
 * @since     0.9.32
 * @status    stable
 *
 * Return the effective profile name for a compliance posture, or
 * `null` for unknown posture names.
 *
 * @example
 *   b.guardSmtpCommand.compliancePosture("hipaa");   // → "strict"
 */
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

function _validateGreeting(verb, rest, caps) {
  if (rest.length === 0) {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      verb + " requires a domain or address literal argument (RFC 5321 §4.1.1.1)");
  }
  // RFC 5321 §4.1.1.1: HELO/EHLO accepts a domain. Real-world MTAs
  // (Postfix, Exim, sendmail) tolerate a single trailing space after
  // the domain — the framework refused it because the DOMAIN_RE
  // doesn't match a domain with trailing whitespace. Strip a single
  // trailing space before the leading-space / double-space check so a
  // legitimate "HELO mail.example.com " passes while abusive multi-
  // space shapes still refuse.
  if (rest.charAt(rest.length - 1) === " " &&
      rest.charAt(rest.length - 2) !== " ") {
    rest = rest.slice(0, -1);
  }
  // Trim trailing-space tolerance — most peers send a single space; we
  // accept it but refuse multiple spaces or leading spaces.
  if (rest.charAt(0) === " " || rest.indexOf("  ") !== -1) {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-whitespace",
      verb + " greeting has anomalous whitespace");
  }
  var arg = rest;
  if (ADDR_LIT_RE.test(arg)) return { verb: verb, args: [arg], params: {} };                            // allow:regex-no-length-cap — line is maxLineBytes-capped upstream
  if (Buffer.byteLength(arg, "utf8") > caps.maxDomain) {
    throw new GuardSmtpCommandError("guard-smtp-command/oversize-domain",
      verb + ": domain exceeds maxDomain=" + caps.maxDomain + " (RFC 1035 §2.3.4)");
  }
  if (!DOMAIN_RE.test(arg)) {                                                                            // allow:regex-no-length-cap — domain just length-checked above
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      verb + ": domain '" + arg + "' does not match LDH shape (RFC 5321 §4.1.2)");
  }
  return { verb: verb, args: [arg], params: {} };
}

function _validatePath(verb, rest, caps, requiredPrefix) {
  // SMTP allows OPTIONAL whitespace between e.g. MAIL and FROM:<...>
  // per RFC 5321 §4.1.1.2; we accept a single space (consumed above)
  // and refuse multiple spaces around the colon.
  if (rest.indexOf(requiredPrefix) !== 0) {
    // Allow a single leading SP — but our caller already split on the
    // first SP; rest is post-SP. Some implementations send the path
    // prefix verbatim. Refuse anything else.
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      verb + " must begin with '" + requiredPrefix + "' (RFC 5321 §3.3)");
  }
  var after = rest.slice(requiredPrefix.length);
  var pathEnd = after.indexOf(">");
  if (after.charAt(0) !== "<" || pathEnd === -1) {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      verb + " path missing angle brackets (RFC 5321 §3.3)");
  }
  var pathRaw = after.slice(0, pathEnd + 1);
  if (Buffer.byteLength(pathRaw, "utf8") > caps.maxMailbox) {
    throw new GuardSmtpCommandError("guard-smtp-command/oversize-path",
      verb + ": path '" + pathRaw + "' exceeds maxMailbox=" + caps.maxMailbox +
      " (RFC 5321 §4.5.3.1.3)");
  }
  var pathBody = pathRaw.slice(1, -1);
  // Reverse-path can be empty (`MAIL FROM:<>` per RFC 5321 §3.3 bounce
  // sender). Forward-path can't be empty.
  if (pathBody.length === 0) {
    if (verb === "MAIL") return { verb: verb, args: [pathRaw], params: _parseExtParams(after.slice(pathEnd + 1)) };
    throw new GuardSmtpCommandError("guard-smtp-command/empty-path",
      verb + " path must not be empty");
  }
  // Validate mailbox local-part and domain caps.
  var atIdx = pathBody.lastIndexOf("@");
  if (atIdx === -1) {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      verb + ": mailbox missing '@' (RFC 5321 §4.1.2)");
  }
  var localPart = pathBody.slice(0, atIdx);
  var domain    = pathBody.slice(atIdx + 1);
  if (Buffer.byteLength(localPart, "utf8") > caps.maxLocalPart) {
    throw new GuardSmtpCommandError("guard-smtp-command/oversize-local-part",
      verb + ": local-part exceeds maxLocalPart=" + caps.maxLocalPart);
  }
  if (Buffer.byteLength(domain, "utf8") > caps.maxDomain) {
    throw new GuardSmtpCommandError("guard-smtp-command/oversize-domain",
      verb + ": domain exceeds maxDomain=" + caps.maxDomain);
  }
  if (!ADDR_LIT_RE.test(domain) && !DOMAIN_RE.test(domain)) {                                            // allow:regex-no-length-cap — domain length-checked above
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      verb + ": domain '" + domain + "' does not match LDH or address-literal shape");
  }
  return {
    verb:   verb,
    args:   [pathRaw],
    params: _parseExtParams(after.slice(pathEnd + 1)),
  };
}

function _parseExtParams(tail) {
  // RFC 5321 §4.1.1.11 — esmtp-keyword + optional '=' + esmtp-value.
  // Caller passes the post-path slice; leading SP is allowed and
  // separates params from each other.
  var params = {};
  var parts = tail.trim().split(/\s+/).filter(Boolean);
  for (var i = 0; i < parts.length; i += 1) {
    var eq = parts[i].indexOf("=");
    var key = (eq === -1 ? parts[i] : parts[i].slice(0, eq)).toUpperCase();
    var val = eq === -1 ? true : parts[i].slice(eq + 1);
    if (!/^[A-Za-z0-9-]+$/.test(key)) {                                                                                                                                                                    // allow:regex-no-length-cap — bounded by maxLineBytes via line cap
      throw new GuardSmtpCommandError("guard-smtp-command/bad-ext-param",
        "esmtp-keyword '" + key + "' not in [A-Za-z0-9-] (RFC 5321 §4.1.1.11)");
    }
    params[key] = val;
  }
  return params;
}

function _validateBdat(rest) {
  // RFC 3030 §2: `BDAT <chunk-size> [LAST]`
  var parts = rest.split(/\s+/).filter(Boolean);
  if (parts.length === 0 || parts.length > 2) {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      "BDAT requires chunk-size and optional LAST (RFC 3030)");
  }
  if (!DECIMAL_RE.test(parts[0])) {                                                                      // allow:regex-no-length-cap — DECIMAL_RE has built-in repeat cap
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      "BDAT chunk-size must be a decimal number");
  }
  if (parts.length === 2 && parts[1].toUpperCase() !== "LAST") {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      "BDAT second arg must be LAST (RFC 3030)");
  }
  return {
    verb:   "BDAT",
    args:   [parts[0]],
    params: parts.length === 2 ? { LAST: true } : {},
  };
}

function _validateMailbox(verb, rest, caps) {
  if (rest.length === 0) {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      verb + " requires a mailbox argument (RFC 5321 §4.1.1.7/§4.1.1.8)");
  }
  if (Buffer.byteLength(rest, "utf8") > caps.maxMailbox) {
    throw new GuardSmtpCommandError("guard-smtp-command/oversize-path",
      verb + ": mailbox exceeds maxMailbox=" + caps.maxMailbox);
  }
  return { verb: verb, args: [rest], params: {} };
}

function _parseAuthCommandSyntax(rest) {
  // RFC 4954: `AUTH <SASL-mech> [<initial-response>]`
  var parts = rest.split(/\s+/).filter(Boolean);
  if (parts.length === 0 || parts.length > 2) {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      "AUTH requires mechanism and optional initial-response (RFC 4954)");
  }
  // SASL mechanism names are RFC 4422 — ALPHA + DIGIT + "-" + "_", up
  // to 20 octets. We accept the 4422 charset and a 32-byte cap so
  // operator-extension mechanisms have room.
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(parts[0])) {                                                                                                                                                           // allow:regex-no-length-cap — anchored + repeat-cap
    throw new GuardSmtpCommandError("guard-smtp-command/bad-shape",
      "AUTH: SASL mechanism '" + parts[0] + "' not in RFC 4422 charset or too long");
  }
  return {
    verb:   "AUTH",
    args:   [parts[0].toUpperCase()],
    params: parts.length === 2 ? { initialResponse: parts[1] } : {},
  };
}

function _resolveProfile(opts) {
  if (opts.posture && COMPLIANCE_POSTURES[opts.posture]) {
    return PROFILES[COMPLIANCE_POSTURES[opts.posture]];
  }
  var p = opts.profile || DEFAULT_PROFILE;
  if (!PROFILES[p]) {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-profile",
      "guardSmtpCommand: unknown profile '" + p + "'");
  }
  return PROFILES[p];
}

/**
 * @primitive b.guardSmtpCommand.gate
 * @signature b.guardSmtpCommand.gate(opts?)
 * @since     0.9.32
 * @status    stable
 *
 * Build a guard gate compatible with `b.guardAll.allGuards()`. The
 * gate's `decide(ctx)` reads `ctx.identifier` (or `ctx.commandLine`)
 * and routes through `validate()`; refuse on any thrown
 * `GuardSmtpCommandError`, serve otherwise.
 *
 * @opts
 *   profile:  "strict" | "balanced" | "permissive",
 *   posture:  "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   name:     string,                              // gate identity label
 *
 * @example
 *   var gate = b.guardSmtpCommand.gate({ profile: "strict" });
 *   await gate.decide({ identifier: "EHLO mail.example.com" });
 *   // → { ok: true, action: "serve" }
 */
function gate(opts) {
  opts = opts || {};
  // Resolve profile eagerly so a bad profile / posture surfaces here
  // rather than inside the first gate.check() call.
  _resolveProfile(opts);
  var name = opts.name || "guardSmtpCommand:" + (opts.profile || opts.posture || "default");
  return gateContract.buildGuardGate(name, opts, async function (ctx) {
    var line = ctx && (ctx.identifier || ctx.commandLine || "");
    if (!line) return { ok: true, action: "serve" };
    try {
      validate(line, opts);
      return { ok: true, action: "serve" };
    } catch (e) {
      if (e && typeof e.code === "string" && e.code.indexOf("guard-smtp-command/") === 0) {
        return {
          ok:     false,
          action: "refuse",
          issues: [{
            kind:     e.code.split("/")[1],
            severity: "critical",
            ruleId:   "smtp-command." + e.code.split("/")[1],
            snippet:  e.message,
          }],
        };
      }
      throw e;
    }
  });
}

/**
 * @primitive b.guardSmtpCommand.detectBodySmuggling
 * @signature b.guardSmtpCommand.detectBodySmuggling(buf)
 * @since     0.9.46
 * @status    stable
 * @related   b.guardSmtpCommand.validate, b.safeSmtp.findDotTerminator
 *
 * Scan a DATA-body byte buffer for the SMTP smuggling shape per
 * CVE-2023-51764 (Postfix), CVE-2023-51765 (Sendmail), CVE-2023-51766
 * (Exim). RFC 5321 §2.3.8
 * mandates canonical CRLF line termination; the smuggling exploit
 * relies on parsers that accept `\n.\n` (bare LF before / after the
 * dot) as an alternate body terminator and then resume parsing the
 * NEXT bytes as a new SMTP transaction.
 *
 * Returns `true` if the buffer contains a bare-LF dot-line (a `\n`
 * NOT preceded by `\r`, immediately followed by `.\n`), `false`
 * otherwise. Operators wiring an MX / submission listener call this
 * on every DATA chunk + refuse the whole transaction on `true` per
 * the framework's strict-CRLF posture.
 *
 * @example
 *   b.guardSmtpCommand.detectBodySmuggling(Buffer.from("body\r\n.\r\n"));
 *   // → false
 *
 *   b.guardSmtpCommand.detectBodySmuggling(Buffer.from("body\n.\n"));
 *   // → true (bare-LF dot-line — CVE-2023-51764 shape)
 */
function detectBodySmuggling(buf) {
  if (!Buffer.isBuffer(buf)) {
    throw new GuardSmtpCommandError("guard-smtp-command/bad-input",
      "detectBodySmuggling: input must be a Buffer");
  }
  // The CVE-2023-51764 / 51765 / 51766 class is any
  // dot-line whose line boundary is anything OTHER than canonical
  // \r\n on BOTH sides of the dot. The canonical-and-only terminator
  // is `\r\n.\r\n`. Every other shape that some receiver might honor
  // is a smuggling vector:
  //
  //   shape           leading      .   trailing
  //   --------------  -----------  -   -------------
  //   bare-LF/bare-LF  \n          .   \n           ← original detector
  //   bare-LF/CRLF     \n          .   \r\n
  //   CRLF/bare-LF     \r\n        .   \n           ← bare-LF terminator
  //   bare-CR/anything \r (no LF)  .   *            ← bare CR (RFC violations)
  //
  // Standalone `.\n` or `\n.\n` at the START of the buffer also
  // count: a dot at byte 0 followed by `\n` would terminate any
  // receiver that accepts bare-LF dot.
  //   0x0a = LF, 0x0d = CR, 0x2e = `.`
  if (buf.length >= 2 && buf[0] === 0x2e && buf[1] === 0x0a) return true;
  // Walk every LF in the buffer. The previous byte must be CR for the
  // line boundary to be canonical; otherwise the line started with
  // bare-LF. If the next bytes are `.` followed by ANY of (LF, CRLF),
  // the shape is a smuggling candidate.
  for (var i = 0; i < buf.length - 1; i += 1) {
    if (buf[i] !== 0x0a) continue;
    var leadingBareLf = (i === 0) || (buf[i - 1] !== 0x0d);
    if (buf[i + 1] !== 0x2e) continue;
    // Trailing terminator shape after the dot:
    //   buf[i+2] == LF        → bare-LF terminator (always smuggling)
    //   buf[i+2] == CR && buf[i+3] == LF → CRLF after dot
    //                                       (only smuggling when the
    //                                        leading boundary was bare-LF)
    if (i + 2 < buf.length && buf[i + 2] === 0x0a) {
      // `.\n` after a bare-LF or CRLF line boundary — both
      // smuggling vectors (CRLF.\n is the v0.9.x-audit case).
      return true;
    }
    if (leadingBareLf && i + 3 < buf.length &&
        buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
      // bare-LF.\r\n — smuggling shape (CVE-2023-51764 Postfix).
      return true;
    }
  }
  // Also check for bare-CR-only dot terminators: `\r.\r` (no LF).
  // Some legacy parsers honor bare CR as line terminator.
  for (var j = 0; j < buf.length - 2; j += 1) {
    if (buf[j] === 0x0d && (j + 1 >= buf.length || buf[j + 1] !== 0x0a) &&
        buf[j + 1] === 0x2e && j + 2 < buf.length && buf[j + 2] === 0x0d) {
      return true;
    }
  }
  return false;
}

module.exports = {
  validate:                  validate,
  detectBodySmuggling:       detectBodySmuggling,
  gate:                      gate,
  compliancePosture:         compliancePosture,
  PROFILES:                  PROFILES,
  COMPLIANCE_POSTURES:       COMPLIANCE_POSTURES,
  KNOWN_VERBS:               KNOWN_VERBS,
  GuardSmtpCommandError:     GuardSmtpCommandError,
  NAME:                      "smtpCommand",
  KIND:                      "identifier",
  INTEGRATION_FIXTURES:      Object.freeze({
    kind:        "identifier",
    // Benign: standard EHLO greeting.
    benignBytes: Buffer.from("EHLO mail.example.com", "ascii"),
    // Hostile: CRLF smuggling attempt — bare CR inside a command line
    // (CVE-2023-51764 / 51765 / 51766 class).
    hostileBytes: Buffer.from("MAIL FROM:<a@b.com>\r\n.\r\nMAIL FROM:<evil@x.com>", "ascii"),
    benignIdentifier:  "EHLO mail.example.com",
    hostileIdentifier: "MAIL FROM:<a@b.com>\r\n.\r\nMAIL FROM:<evil@x.com>",
  }),
};

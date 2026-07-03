// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.server.submission
 * @nav        Mail
 * @title      Mail Submission Server
 * @order      542
 *
 * @intro
 *   Outbound SMTP submission listener per RFC 6409 (port 587) and
 *   RFC 8314 implicit-TLS submissions (port 465). Where the MX
 *   listener (`b.mail.server.mx`) accepts inbound mail from the
 *   internet to local mailboxes, the submission listener accepts
 *   outbound mail from authenticated MUAs / app-side mail-senders
 *   and routes it to upstream MXs via `b.mail.send`.
 *
 *   Differences from the MX listener:
 *
 *   - **AUTH required** — operator-supplied authenticator validates
 *     SASL credentials (PLAIN / LOGIN / SCRAM-SHA-256 / EXTERNAL /
 *     XOAUTH2). MAIL FROM is refused until AUTH succeeds.
 *
 *   - **Identity binding** — under strict profile, `MAIL FROM:<x@y>`
 *     MUST match the authenticated actor's mailbox set; refused with
 *     553 5.7.1 Sender address rejected. Permissive logs the
 *     mismatch but allows.
 *
 *   - **TLS required for AUTH** (RFC 4954 §4) — pre-STARTTLS AUTH
 *     refused with 538 5.7.11 Encryption required for AUTH
 *     mechanism. Permissive profile allows plaintext AUTH for
 *     legacy operator-acknowledged downgrade.
 *
 *   - **Implicit-TLS mode** — `implicitTls: true` wraps every
 *     connection in TLS from the SYN (port 465 per RFC 8314); no
 *     STARTTLS advertised because the connection is already secure.
 *
 *   - **Outbound routing** — successful DATA hands off to the
 *     operator-supplied `agent.handoff({ ... })` for relay through
 *     `b.mail.send` to upstream MXs. The listener doesn't perform
 *     MX lookup or outbound delivery itself.
 *
 *   ## Wire-protocol defenses (inherited from MX listener pattern)
 *
 *   - SMTP smuggling (CVE-2023-51764 / -51765 / -51766 /
 *     RFC 5321 §2.3.8): every wire line through
 *     `b.guardSmtpCommand.validate`; DATA-body terminator scan
 *     through `b.safeSmtp.findDotTerminator` (strict-CRLF);
 *     smuggling shape detected via
 *     `b.guardSmtpCommand.detectBodySmuggling`.
 *
 *   - STARTTLS-injection (CVE-2021-38371 Exim, CVE-2021-33515
 *     Dovecot): command buffer cleared at upgrade time.
 *
 *   - Resource exhaustion: per-command line cap (1 KiB), DATA body
 *     cap (50 MiB per RFC 5321 §4.5.3.1.7), per-message recipient
 *     cap (100 per RFC 5321 §4.5.3.1.8), idle timeout (5 minutes
 *     per RFC 5321 §4.5.3.2.7).
 *
 *   ## SMTP AUTH (RFC 4954)
 *
 *   - Mechanisms negotiated per RFC 4422 (SASL) — the operator
 *     opts the list `auth.mechanisms` into the EHLO advertisement.
 *   - Initial-response variant `AUTH MECH <base64>` (RFC 4954 §4)
 *     supported.
 *   - Failed AUTH emits `mail.server.submission.auth_failed` with
 *     mechanism + reason; operator's rate-limit wired via
 *     `auth.rateLimit` (composes `b.middleware.rateLimit`) trips
 *     421 4.7.0 Too many failed AUTH after the operator-configured
 *     budget.
 *
 *   ## Audit lifecycle (in addition to the MX listener's)
 *
 *   - `mail.server.submission.auth_attempt` — mechanism, actor-hash, remote
 *   - `mail.server.submission.auth_success` — mechanism, tenantId, scopes
 *   - `mail.server.submission.auth_failed`  — mechanism, reason
 *   - `mail.server.submission.identity_mismatch` — auth identity vs MAIL FROM
 *   - `mail.server.submission.outbound_routed` — delivery agent ack
 *
 *   ## What v1 does NOT ship
 *
 *   - **DKIM signing pre-relay** — operator wires `b.mail.dkim.sign`
 *     in their outbound agent.
 *   - **Per-actor outbound quota** — operator implements via
 *     `b.dailyByteQuota` against the authenticated actor.
 *
 *   (CHUNKING / BDAT, RFC 3030, IS supported — advertised in EHLO and
 *   handled alongside DATA.)
 *
 *   ## Composition contract
 *
 *   Every gate is a primitive that already exists. Submission listener
 *   composes `b.guardSmtpCommand` (wire-protocol gate + smuggling
 *   defense), `b.safeSmtp` (wire-protocol parser), the operator's
 *   authenticator (SASL verify), `b.mail.send` (outbound MX routing),
 *   and the framework's TLS posture via `b.network.tls.context`.
 *
 * @card
 *   Outbound SMTP submission listener (RFC 6409 / RFC 8314). AUTH-
 *   required before MAIL FROM; identity-binding under strict profile;
 *   TLS-required-for-AUTH (RFC 4954 §4); implicit-TLS mode for
 *   port 465. Composes b.guardSmtpCommand + b.safeSmtp + operator
 *   SASL authenticator + b.mail.send for outbound routing.
 */

var net   = require("node:net");
var nodeTls   = require("node:tls");
var C         = require("./constants");
var bCrypto   = require("./crypto");
var numericBounds = require("./numeric-bounds");
var safeAsync = require("./safe-async");
var safeBuffer = require("./safe-buffer");
var safeSmtp = require("./safe-smtp");
var validateOpts = require("./validate-opts");
var guardSmtpCommand = require("./guard-smtp-command");
var guardDomain = require("./guard-domain");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerTls = require("./mail-server-tls");
var mailServerNet = require("./mail-server-net");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var MailServerSubmissionError = defineClass("MailServerSubmissionError", { alwaysPermanent: true });

var DEFAULT_MAX_LINE_BYTES        = C.BYTES.kib(1);
var DEFAULT_MAX_MESSAGE_BYTES     = C.BYTES.mib(50);
var DEFAULT_MAX_RCPTS_PER_MESSAGE = 100;                                                              // RFC 5321 §4.5.3.1.8 recipient cap
var DEFAULT_IDLE_TIMEOUT_MS       = C.TIME.minutes(5);
var DEFAULT_GREETING              = "blamejs Submission";
var DEFAULT_AUTH_MECHANISMS       = Object.freeze(["PLAIN", "LOGIN"]);

var REPLY_220_READY              = "220";
var REPLY_221_BYE                = "221";
var REPLY_235_AUTH_OK            = "235";                                                             // SMTP AUTH success code
var REPLY_250_OK                 = "250";
var REPLY_334_AUTH_CHALLENGE     = "334";                                                             // SMTP AUTH challenge code
var REPLY_354_START_INPUT        = "354";
var REPLY_421_SERVICE_NOT_AVAIL  = "421";                                                             // SMTP transient code
var REPLY_451_LOCAL_ERROR        = "451";                                                             // SMTP transient code
var REPLY_452_INSUFFICIENT_STG   = "452";                                                             // SMTP transient code
var REPLY_500_SYNTAX             = "500";                                                             // SMTP permanent code
var REPLY_501_BAD_ARGS           = "501";                                                             // SMTP permanent code
var REPLY_502_NOT_IMPLEMENTED    = "502";                                                             // SMTP permanent code
var REPLY_503_BAD_SEQUENCE       = "503";                                                             // SMTP permanent code
var REPLY_530_AUTH_REQUIRED      = "530";                                                             // SMTP permanent code
var REPLY_535_AUTH_FAILED        = "535";                                                             // RFC 4954 §6 AUTH refusal
var REPLY_538_AUTH_NEEDS_TLS     = "538";                                                             // RFC 4954 §4 AUTH-needs-TLS
var REPLY_550_MAILBOX_UNAVAIL    = "550";                                                             // SMTP permanent code (recipient-policy refusal shape)
var REPLY_552_SIZE_EXCEEDED      = "552";                                                             // SMTP permanent code
var REPLY_553_SENDER_REJECTED    = "553";                                                             // identity-binding mismatch
var REPLY_554_TRANSACTION_FAILED = "554";                                                             // SMTP permanent code

var RE_MAIL_FROM = /^MAIL\s+FROM:\s*<([^>]*)>(?:\s+(.*))?$/i;
var RE_RCPT_TO   = /^RCPT\s+TO:\s*<([^>]+)>(?:\s+.*)?$/i;
var RE_SIZE      = /SIZE=(\d+)/i;
var RE_AUTH      = /^AUTH\s+([A-Za-z0-9_-]{1,32})(?:\s+(.*))?$/i;

// Header/body boundary scanner. RFC 5322 §2.1 — header section ends
// at the first empty line (CRLF CRLF). `Buffer#indexOf` runs a
// SIMD-accelerated needle scan over the haystack without an
// interpreter-level char-by-char walk, and the 4-byte literal
// `_CRLF_CRLF` is a module-level singleton so the JIT folds it.
var _CRLF_CRLF = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a]);                                                 // RFC 5322 §2.1 header/body separator
function _findHeaderEnd(buf) {
  return buf.indexOf(_CRLF_CRLF);
}

// Walk a header block and return every unfolded `DKIM-Signature:`
// value. RFC 5322 §2.2.3 / RFC 6376 §3.5 — DKIM signatures are
// permitted to fold and a message MAY carry multiple signatures.
function _extractDkimSignatures(headerBlock) {
  var lines = headerBlock.replace(/\r\n/g, "\n").split("\n");                                           // allow:regex-no-length-cap — headerBlock length bounded by maxMessageBytes
  var result = [];
  var current = null;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0) break;   // end of header block
    if (line.charAt(0) === " " || line.charAt(0) === "\t") {
      if (current !== null) current += " " + line.replace(/^[ \t]+/, "");                                // allow:regex-no-length-cap — line length bounded by maxLineBytes // allow:duplicate-regex — RFC 5322 header continuation trim
      continue;
    }
    if (current !== null) {
      result.push(current);
      current = null;
    }
    if (/^DKIM-Signature\s*:/i.test(line)) {                                                            // allow:regex-no-length-cap — line length bounded by maxLineBytes
      current = line.slice(line.indexOf(":") + 1).replace(/^\s+/, "");                                  // allow:regex-no-length-cap — line length bounded by maxLineBytes // allow:duplicate-regex — leading-WS trim
    }
  }
  if (current !== null) result.push(current);
  return result;
}

// Pull the `d=` (signing domain) tag out of a DKIM-Signature value.
// RFC 6376 §3.5 — tag-list `tag=value` separated by `;`. Returns
// null if not present.
function _extractDkimDTag(sigValue) {
  var tags = sigValue.split(";");
  for (var i = 0; i < tags.length; i += 1) {
    var t = tags[i].replace(/^\s+|\s+$/g, "");                                                          // allow:regex-no-length-cap — tag length bounded by header line cap // allow:duplicate-regex — trim shape
    if (t.length > 2 && t.charAt(0) === "d" && t.charAt(1) === "=") {
      return t.slice(2).replace(/\s+/g, "");                                                            // allow:regex-no-length-cap — value length bounded by tag length // allow:duplicate-regex — internal-WS strip
    }
  }
  return null;
}

// Domain part of the authenticated identity, falling back to the
// envelope-sender domain when the actor doesn't carry one.
function _actorDomain(actor, mailFrom) {
  if (actor && typeof actor.domain === "string" && actor.domain.length > 0) return actor.domain;
  if (actor && typeof actor.id === "string" && actor.id.indexOf("@") !== -1) {
    return actor.id.slice(actor.id.lastIndexOf("@") + 1);
  }
  if (typeof mailFrom === "string" && mailFrom.indexOf("@") !== -1) {
    return mailFrom.slice(mailFrom.lastIndexOf("@") + 1);
  }
  return null;
}

/**
 * @primitive b.mail.server.submission.create
 * @signature b.mail.server.submission.create(opts)
 * @since     0.9.47
 * @status    stable
 * @related   b.mail.server.mx.create, b.guardSmtpCommand.detectBodySmuggling, b.safeSmtp.findDotTerminator
 *
 * Build the submission listener. Returns
 * `{ listen({ port?, address? }), close({ timeoutMs? }),
 *    connectionCount(), _portForTest() }`.
 *
 * @opts
 *   tlsContext:      TlsContext,   // required — b.network.tls.context() output
 *   implicitTls:     boolean,      // wrap connection in TLS from the SYN (port 465); default false
 *   greeting:        string,       // EHLO/220 banner; default "blamejs Submission"
 *   auth:            object,       // SASL config (required unless permissive profile)
 *     mechanisms:    string[],     // SASL mechs to advertise; default ["PLAIN","LOGIN"]
 *     verify:        function,     // async (mechanism, credentials) => { ok, actor }
 *     rateLimit:     object,       // optional b.middleware.rateLimit instance for failure budget
 *   agent:           object,       // outbound delivery handoff (handoff({ ... }) → ack)
 *   identityBinding: "strict" | "permissive",  // MAIL FROM must match auth identity (default strict)
 *   maxLineBytes:    number,       // default 1 KiB
 *   maxMessageBytes: number,       // default 50 MiB
 *   maxRcptsPerMessage: number,    // default 100
 *   idleTimeoutMs:   number,       // default 5 minutes
 *   profile:         string,       // "strict" | "balanced" | "permissive"; default "strict"
 *
 * @example
 *   var tls = b.network.tls.context({ cert: certPem, key: keyPem });
 *   var server = b.mail.server.submission.create({
 *     tlsContext: tls,
 *     greeting:   "smtp.example.com Submission blamejs",
 *     auth: {
 *       mechanisms: ["PLAIN", "SCRAM-SHA-256"],
 *       verify: async function (mech, creds) {
 *         var actor = await myAuthService.verify(mech, creds);
 *         return actor ? { ok: true, actor: actor } : { ok: false };
 *       },
 *     },
 *     agent: b.mail.agent.create({ outboundSend: b.mail.send }),
 *   });
 *   await server.listen({ port: 587 });
 */
function create(opts) {
  validateOpts.requireObject(opts, "mail.server.submission.create",
    MailServerSubmissionError, "mail-server-submission/bad-opts");
  if (!opts.tlsContext) {
    throw new MailServerSubmissionError("mail-server-submission/no-tls-context",
      "mail.server.submission.create: tlsContext is required");
  }
  // b.agent.tenant shape validation at create() time — a malformed
  // scope object would refuse every auth as cross-tenant, masking the
  // configuration error as an auth outage.
  if (opts.tenantScope && typeof opts.tenantScope.check !== "function") {
    throw new MailServerSubmissionError("mail-server-submission/bad-tenant-scope",
      "create: opts.tenantScope must be a b.agent.tenant.create() instance " +
      "(missing .check); a malformed scope would refuse every auth as cross-tenant");
  }
  if (opts.tenantScope && !opts.agentTenantId) {
    throw new MailServerSubmissionError("mail-server-submission/no-agent-tenant-id",
      "create: opts.tenantScope requires opts.agentTenantId");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "maxMessageBytes", "maxRcptsPerMessage", "idleTimeoutMs"],
    "mail.server.submission.", MailServerSubmissionError, "mail-server-submission/bad-bound");

  var profile = opts.profile || "strict";
  // SMTPUTF8 (RFC 6531) — single switch threaded end-to-end into
  // `guardSmtpCommand.validate`. Defaults `false`; submission
  // operators that accept EAI envelopes flip this `true`.
  var allowSmtpUtf8 = opts.allowSmtpUtf8 === true;

  // Outbound DKIM-required gate (Yahoo / Google 2024 bulk-sender
  // alignment + RFC 6376 §1). Under `strict` profile the listener
  // refuses outbound DATA that doesn't carry at least one
  // `DKIM-Signature:` header; `dkimRequireMode` chooses whether the
  // signer must match the authenticated identity's domain (`self`)
  // or just be present (`any`). Operators that act as a smarthost
  // relay for downstream MTAs that DKIM-sign themselves want `any`;
  // primary senders want `self`. Default-off outside strict so
  // unauthenticated `permissive` profiles don't break.
  var requireDkim = opts.requireDkim === undefined
    ? (profile === "strict")
    : opts.requireDkim === true;
  var dkimRequireMode = opts.dkimRequireMode || "any";
  if (dkimRequireMode !== "self" && dkimRequireMode !== "any" && dkimRequireMode !== "off") {
    throw new MailServerSubmissionError("mail-server-submission/bad-dkim-require-mode",
      "mail.server.submission.create: dkimRequireMode must be 'self', 'any', or 'off' (got '" +
      dkimRequireMode + "')");
  }
  if (dkimRequireMode === "off") requireDkim = false;

  if (profile !== "permissive" && !opts.auth) {
    throw new MailServerSubmissionError("mail-server-submission/no-auth",
      "mail.server.submission.create: opts.auth required under strict / balanced profiles " +
      "(submission listener is authenticated by design; opt down to 'permissive' for legacy plaintext)");
  }
  if (opts.auth) {
    if (typeof opts.auth.verify !== "function") {
      throw new MailServerSubmissionError("mail-server-submission/bad-auth",
        "mail.server.submission.create: opts.auth.verify must be an async function (mechanism, credentials) => { ok, actor }");
    }
    if (opts.auth.mechanisms !== undefined &&
        (!Array.isArray(opts.auth.mechanisms) || opts.auth.mechanisms.length === 0)) {
      throw new MailServerSubmissionError("mail-server-submission/bad-auth",
        "mail.server.submission.create: opts.auth.mechanisms must be a non-empty array if provided");
    }
  }

  var greeting          = opts.greeting          || DEFAULT_GREETING;
  var maxLineBytes      = opts.maxLineBytes      || DEFAULT_MAX_LINE_BYTES;
  var maxMessageBytes   = opts.maxMessageBytes   || DEFAULT_MAX_MESSAGE_BYTES;
  var maxRcptsPerMsg    = opts.maxRcptsPerMessage || DEFAULT_MAX_RCPTS_PER_MESSAGE;
  var idleTimeoutMs     = opts.idleTimeoutMs     || DEFAULT_IDLE_TIMEOUT_MS;
  var authConfig        = opts.auth || null;
  var authMechanisms    = authConfig && authConfig.mechanisms
                            ? authConfig.mechanisms.map(function (m) { return String(m).toUpperCase(); })
                            : DEFAULT_AUTH_MECHANISMS.slice();
  var identityBinding   = opts.identityBinding   || "strict";
  var implicitTls       = opts.implicitTls === true;

  // Default-on per-IP rate limit (see lib/mail-server-rate-limit.js).
  // Operators pass `rateLimit: false` to disable, a rate-limit handle
  // to share across listeners, or an opts object to override defaults.
  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

  // Default-on guardDomain hardening for HELO / MAIL FROM / RCPT TO.
  // Same posture as mail-server-mx — IDN homograph / Punycode-spoof
  // (mixed-script confusable class), special-use-domain refusal (RFC 6761), label-length cap
  // (RFC 1035 §2.3.4), bare-IP-as-domain refusal (CVE-2021-22931
  // class). Operators with a closed-network deployment pass
  // `guardDomain: false` to skip; the default keeps protection on.
  var guardDomainProfile;
  if (opts.guardDomain === false) {
    guardDomainProfile = null;
  } else {
    guardDomainProfile = guardDomain.buildProfile({
      profile: opts.guardDomain && typeof opts.guardDomain === "object"
        ? (opts.guardDomain.profile || profile)
        : profile,
    });
  }
  function _validateDomainHardened(d, label) {
    return mailServerNet.validateDomainHardened(d, label, {
      guardDomainProfile: guardDomainProfile,
      guardDomain:        guardDomain,
      emit:               _emit,
      refusedEvent:       "mail.server.submission.domain_refused",
    });
  }

  var connections  = new Set();

  var _emit = auditEmit.emit;

  function _handleConnection(rawSocket) {
    // 421 4.7.0 — transient; sender retries elsewhere.
    var remoteAddress = mailServerNet.admitConnection(rawSocket, rateLimit, _emit, {
      refusedEvent: "mail.server.submission.rate_limit_refused",
      refusalLine:  "421 4.7.0 Too many connections from your IP\r\n",
    });
    if (remoteAddress === null) return;
    rawSocket.once("close", function () { rateLimit.releaseConnection(remoteAddress); });

    var connectionId = "submitconn-" + bCrypto.generateToken(8);                                      // connection-id length
    var socket = implicitTls
      ? new nodeTls.TLSSocket(rawSocket, { isServer: true, secureContext: opts.tlsContext })
      : rawSocket;
    connections.add(socket);

    var state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      remotePort:    rawSocket.remotePort || null,
      tls:           implicitTls,
      stage:         "connect",
      helo:          null,
      authenticated: false,
      actor:         null,
      mailFrom:      null,
      rcpts:         [],
      // Pending AUTH state (multi-step mechanisms).
      authPending:   null,
    };

    // RAW byte buffer — NOT a string. The BDAT-CHUNKING path (RFC 3030)
    // requires lossless byte preservation when the BDAT command line +
    // payload arrive in the same TCP segment, and DATA-body 8BITMIME
    // payloads can contain bytes that are invalid UTF-8. Decoding the
    // socket-bytes through a string layer replaces invalid sequences
    // with U+FFFD and corrupts the body. Keep the raw bytes; decode to
    // string only for the per-command parse.
    var lineBuffer = Buffer.alloc(0);
    var bodyCollector = null;
    var inDataBody = false;
    // RFC 3030 CHUNKING — state for the BDAT command. `bdatCollector`
    // accumulates the message body across multiple BDAT chunks; it lives
    // for the lifetime of the SMTP transaction (i.e., between MAIL FROM
    // and the BDAT ... LAST that finalises). `bdatRemaining` counts down
    // bytes still owed by the current BDAT chunk; `bdatIsLast` flags
    // whether the current chunk is the terminator.
    var inBdatChunk    = false;
    var bdatRemaining  = 0;
    var bdatIsLast     = false;
    var bdatCollector  = null;
    var bdatTotalBytes = 0;

    socket.setTimeout(idleTimeoutMs);
    socket.on("timeout", function () {
      _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL, "4.4.2 Idle timeout");
      _closeConnection(socket);
    });
    socket.on("error", function (err) {
      _emit("mail.server.submission.socket_error",
        { connectionId: state.id, code: (err && err.code) || "unknown" }, "warning");
      _closeConnection(socket);
    });
    socket.on("close", function () { connections.delete(socket); });

    _emit("mail.server.submission.connect", {
      connectionId:  state.id,
      remoteAddress: state.remoteAddress,
      remotePort:    state.remotePort,
      tls:           state.tls,
    });

    _writeReply(socket, REPLY_220_READY, greeting + " ready");

    socket.on("data", function (chunk) {
      try { _ingestBytes(state, socket, chunk); }
      catch (err) {
        _emit("mail.server.submission.handler_threw",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        try { _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL, "4.3.0 Server error"); }
        catch (_e) { /* socket already gone */ }
        _closeConnection(socket);
      }
    });

    function _ingestBytes(state, socket, chunk) {
      // RFC 3030 — when a BDAT chunk is in progress we consume exactly
      // `bdatRemaining` bytes off the wire, no dot-stuffing, no end-of-
      // data marker. Any excess bytes in the chunk after the BDAT
      // payload completes get fed back through the command line buffer
      // (typical when a pipelined `BDAT N LAST\r\n<payload>\r\nNOOP\r\n`
      // arrives in a single TCP segment).
      if (inBdatChunk) {
        var consumeN = Math.min(chunk.length, bdatRemaining);
        var consumed = chunk.subarray(0, consumeN);
        try { bdatCollector.push(consumed); }
        catch (_e) {
          _emit("mail.server.submission.bdat_refused",
            { connectionId: state.id, reason: "body-too-large", maxBytes: maxMessageBytes },
            "denied");
          _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
            "5.3.4 BDAT body exceeds maxMessageBytes (" + maxMessageBytes + " bytes)");
          _resetTransaction(state);
          inBdatChunk = false; bdatCollector = null; bdatRemaining = 0; bdatTotalBytes = 0;
          return;
        }
        bdatRemaining -= consumeN;
        bdatTotalBytes += consumeN;
        if (bdatRemaining === 0) {
          var wasLast = bdatIsLast;
          inBdatChunk = false;
          if (wasLast) {
            // RFC 3030 §2.2 — ONE reply per BDAT command. When LAST,
            // the single reply is the "message queued" finalize reply
            // (emitted from _finalizeAcceptedBody), not the per-chunk
            // "<N> octets received" reply. Emitting both would
            // desynchronise the client (the second 250 would be
            // consumed as the response to the next command).
            // No dot-unstuff for BDAT — RFC 3030 §3 explicitly defines
            // BDAT payloads as opaque byte streams.
            var bdatBody = bdatCollector.result();
            bdatCollector = null;
            bdatTotalBytes = 0;
            _finalizeAcceptedBody(state, socket, bdatBody, "BDAT");
          } else {
            // Non-final chunk — per-chunk acknowledgement only.
            _writeReply(socket, REPLY_250_OK,
              "2.0.0 " + bdatTotalBytes + " octets received");
          }
          // Any tail bytes after this BDAT chunk get re-fed as commands.
          if (consumeN < chunk.length) {
            var tail = chunk.subarray(consumeN);
            _ingestBytes(state, socket, tail);
          }
        }
        return;
      }
      if (inDataBody) {
        try { bodyCollector.push(chunk); }
        catch (_e) {
          _emit("mail.server.submission.data_refused",
            { connectionId: state.id, reason: "body-too-large", maxBytes: maxMessageBytes },
            "denied");
          _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
            "5.3.4 Message size exceeds fixed maximum (" + maxMessageBytes + " bytes)");
          _resetTransaction(state);
          inDataBody = false; bodyCollector = null;
          return;
        }
        var collected = bodyCollector.result();
        if (guardSmtpCommand.detectBodySmuggling(collected)) {
          _emit("mail.server.submission.smtp_smuggling_detected",
            { connectionId: state.id, mailFrom: state.mailFrom, rcptCount: state.rcpts.length },
            "denied");
          _writeReply(socket, REPLY_554_TRANSACTION_FAILED,
            "5.7.0 Bare-LF in DATA body refused (RFC 5321 §2.3.8; CVE-2023-51764 SMTP smuggling)");
          _resetTransaction(state);
          inDataBody = false; bodyCollector = null;
          return;
        }
        var endIdx = safeSmtp.findDotTerminator(collected);
        if (endIdx !== -1) {
          var body = collected.subarray(0, endIdx);
          // DATA path dot-unstuffs here; BDAT path skips this step.
          var dedotted = safeSmtp.dotUnstuff(body);
          _finalizeAcceptedBody(state, socket, dedotted, "DATA");
          inDataBody = false; bodyCollector = null;
        }
        return;
      }

      lineBuffer = lineBuffer.length === 0 ? chunk : Buffer.concat([lineBuffer, chunk]);
      if (safeBuffer.byteLengthOf(lineBuffer) > maxLineBytes * 4) {
        _writeReply(socket, REPLY_500_SYNTAX,
          "5.5.6 Line too long (>" + maxLineBytes + " bytes)");
        _closeConnection(socket);
        return;
      }
      var crlf;
      var crlfNeedle = Buffer.from("\r\n", "ascii");
      while ((crlf = lineBuffer.indexOf(crlfNeedle)) !== -1) {
        // Decode just the per-command line to a string — keeps the
        // wire-protocol parser working in UTF-8 while leaving the
        // RAW lineBuffer intact for any binary payload that follows.
        var line = lineBuffer.subarray(0, crlf).toString("utf8");
        lineBuffer = lineBuffer.subarray(crlf + 2);
        _handleCommand(state, socket, line);
        if (inDataBody) return;
        if (inBdatChunk) {
          // RFC 3030 — `BDAT <N> [LAST]\r\n` is immediately followed by
          // exactly <N> raw bytes (no dot-stuffing, no terminator). When
          // those bytes arrived in the SAME TCP segment as the BDAT
          // command, drain them straight from the raw byte buffer
          // (NOT through a UTF-8 string round-trip — would corrupt
          // 8-bit / binary payloads).
          if (lineBuffer.length > 0) {
            var pendingBytes = lineBuffer;
            lineBuffer = Buffer.alloc(0);
            _ingestBytes(state, socket, pendingBytes);
          }
          return;
        }
      }
    }

    function _handleCommand(state, socket, line) {
      // Pending multi-step AUTH challenge — operator-supplied
      // mechanism may need additional roundtrips. We delegate to
      // authConfig.verify with the new client response.
      if (state.authPending) {
        return _continueAuthExchange(state, socket, line);
      }

      // guardSmtpCommand check (smuggling + shape).
      try {
        guardSmtpCommand.validate(line, {
          profile:        profile,
          maxLineBytes:   maxLineBytes,
          allowSmtpUtf8:  allowSmtpUtf8,
        });
      } catch (err) {
        if (err.code === "guard-smtp-command/bare-lf" ||
            err.code === "guard-smtp-command/bare-cr" ||
            err.code === "guard-smtp-command/nul-byte") {
          _emit("mail.server.submission.smtp_smuggling_detected",
            { connectionId: state.id, code: err.code, line: line.slice(0, 200) },                     // audit-log line truncation
            "denied");
        }
        _writeReply(socket, REPLY_500_SYNTAX, "5.5.2 Syntax error (" + (err.code || "bad-line") + ")");
        return;
      }

      var verb = line.split(/\s+/)[0].toUpperCase();
      switch (verb) {
        case "EHLO":
        case "HELO":
          return _handleEhlo(state, socket, line, verb);
        case "STARTTLS":
          return _handleStartTls(state, socket);
        case "AUTH":
          return _handleAuth(state, socket, line);
        case "MAIL":
          return _handleMailFrom(state, socket, line);
        case "RCPT":
          return _handleRcptTo(state, socket, line);
        case "DATA":
          return _handleData(state, socket);
        case "BDAT":
          return _handleBdat(state, socket, line);
        case "NOOP":
          return _writeReply(socket, REPLY_250_OK, "2.0.0 OK");
        case "RSET":
          _resetTransaction(state);
          return _writeReply(socket, REPLY_250_OK, "2.0.0 Reset");
        case "QUIT":
          _writeReply(socket, REPLY_221_BYE, "2.0.0 Bye");
          return _closeConnection(socket);
        case "VRFY":
        case "EXPN":
          return _writeReply(socket, REPLY_502_NOT_IMPLEMENTED, "5.5.1 Command not implemented");
        default:
          _writeReply(socket, REPLY_500_SYNTAX, "5.5.2 Unknown command");
      }
    }

    function _handleEhlo(state, socket, line, verb) {
      var helo = line.slice(verb.length).trim();
      if (!helo) {
        _writeReply(socket, REPLY_501_BAD_ARGS, "5.5.4 " + verb + " requires a domain argument");
        return;
      }
      // Skip guardDomain on address literals (RFC 5321 §4.1.3 valid
      // bracket-form; already constrained by b.guardSmtpCommand).
      // Bare-IP refused — CVE-2021-22931 class.
      if (helo[0] !== "[" && guardDomainProfile) {
        var __heloVerdict = _validateDomainHardened(helo, "helo");
        if (!__heloVerdict.ok) {
          _writeReply(socket, REPLY_501_BAD_ARGS,
            "5.5.4 " + verb + " domain refused (" +
            (__heloVerdict.issues && __heloVerdict.issues[0] && __heloVerdict.issues[0].kind) + ")");
          return;
        }
      }
      state.helo  = helo;
      state.stage = "ehlo";
      if (verb === "EHLO") {
        var caps = ["PIPELINING", "SIZE " + maxMessageBytes, "8BITMIME", "ENHANCEDSTATUSCODES", "CHUNKING"];
        // STARTTLS advertised only on explicit-STARTTLS port (587),
        // not on implicit-TLS (465 already wrapped). RFC 8314 §3.3.
        if (!state.tls && !implicitTls) caps.unshift("STARTTLS");
        // AUTH advertised only when authConfig wired AND we're on a
        // TLS-protected connection (or operator opted to permissive).
        if (authConfig && (state.tls || profile === "permissive")) {
          caps.push("AUTH " + authMechanisms.join(" "));
        }
        var lines = [greeting + " greets " + helo];
        for (var i = 0; i < caps.length; i += 1) lines.push(caps[i]);
        _writeMultiline(socket, REPLY_250_OK, lines);
      } else {
        _writeReply(socket, REPLY_250_OK, greeting + " greets " + helo);
      }
      _emit("mail.server.submission.helo",
        { connectionId: state.id, verb: verb, helo: helo, tls: state.tls });
    }

    function _handleStartTls(state, socket) {
      if (state.tls) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 TLS already active");
        return;
      }
      if (implicitTls) {
        _writeReply(socket, REPLY_502_NOT_IMPLEMENTED,
          "5.5.1 STARTTLS not available on implicit-TLS port (RFC 8314)");
        return;
      }
      _writeReply(socket, REPLY_220_READY, "2.0.0 Ready to start TLS");
      // CVE-2021-38371 (Exim) / CVE-2021-33515 (Dovecot) STARTTLS-
      // injection defense: clear the pre-handshake command buffer +
      // body collector AND strip the plain-socket "data" listener
      // before wrapping in TLSSocket so bytes the peer pipelined
      // pre-handshake cannot reach the post-TLS state machine.
      lineBuffer = Buffer.alloc(0); bodyCollector = null; inDataBody = false;
      // BDAT-side state cleared on STARTTLS upgrade too — same threat
      // model as CVE-2021-38371 (Exim) / CVE-2021-33515 (Dovecot):
      // pre-handshake bytes the peer pipelined MUST NOT reach the
      // post-TLS state machine via the BDAT collector either.
      inBdatChunk = false; bdatRemaining = 0; bdatCollector = null; bdatTotalBytes = 0;
      mailServerTls.upgradeSocket({
        plainSocket:   socket,
        secureContext: opts.tlsContext,
        idleTimeoutMs: idleTimeoutMs,
        onSecure: function (_tlsSocket) {
          state.tls = true; state.stage = "ehlo"; state.helo = null;
          // Authenticated state SURVIVES STARTTLS upgrade — credentials
          // verified pre-STARTTLS under permissive remain valid post-
          // STARTTLS. Operator opts down to permissive only with this
          // tradeoff acknowledged.
        },
        onData: function (tlsSocket, chunk) {
          try { _ingestBytes(state, tlsSocket, chunk); }
          catch (err) {
            _emit("mail.server.submission.handler_threw",
              { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
            _closeConnection(tlsSocket);
          }
        },
        onError: function (err) {
          _emit("mail.server.submission.tls_handshake_failed",
            { connectionId: state.id, code: (err && err.code) || "unknown" }, "failure");
          _closeConnection(socket);
        },
        onTimeout: function (tlsSocket) {
          _writeReply(tlsSocket, REPLY_421_SERVICE_NOT_AVAIL, "4.4.2 Idle timeout");
          _closeConnection(tlsSocket);
        },
      });
    }

    function _handleAuth(state, socket, line) {
      if (!authConfig) {
        _writeReply(socket, REPLY_502_NOT_IMPLEMENTED, "5.5.1 AUTH not configured on this listener");
        return;
      }
      if (!state.tls && profile !== "permissive") {
        // RFC 4954 §4 — AUTH MUST NOT be advertised or accepted on
        // unencrypted connections (strict + balanced enforce; permissive
        // opts down).
        _writeReply(socket, REPLY_538_AUTH_NEEDS_TLS,
          "5.7.11 Encryption required for AUTH (RFC 4954 §4)");
        return;
      }
      if (!state.tls && profile === "permissive") {
        // Permissive profile accepts cleartext AUTH for legacy
        // operator-acknowledged downgrade per RFC 4954 §4 commentary,
        // but the operator MUST see the event in the audit trail so
        // a downgraded posture is visible without sniffing the wire.
        // Emits before the verify call so a credential exposure on the
        // cleartext channel is still attributed in the audit timeline.
        _emit("mail.server.submission.auth_cleartext_accepted",
          { connectionId: state.id, remoteAddress: state.remoteAddress,
            profile: profile }, "warning");
      }
      if (state.authenticated) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 Already authenticated");
        return;
      }
      // Per-IP AUTH-failure budget — credential-stuffing class
      // defense. Refuse new AUTH attempts when the rolling 15-min
      // failure count for this IP has tripped the cap. 421 4.7.0 is
      // transient; the sender either backs off or retries from a
      // different IP (the desired behavior on a stuffing attack —
      // shifts the attacker workload onto IP rotation).
      var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
      if (!authAdmit.ok) {
        _emit("mail.server.submission.auth_rate_limit_refused",
          { connectionId: state.id, remoteAddress: state.remoteAddress,
            reason: authAdmit.reason }, "denied");
        _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL,
          "4.7.0 Too many AUTH failures from your IP");
        _closeConnection(socket);
        return;
      }
      var match = line.match(RE_AUTH);
      if (!match) {
        _writeReply(socket, REPLY_501_BAD_ARGS,
          "5.5.4 Syntax: AUTH <SASL-mechanism> [<initial-response>] (RFC 4954)");
        return;
      }
      var mech = match[1].toUpperCase();
      var initial = match[2] || null;
      if (authMechanisms.indexOf(mech) === -1) {
        _writeReply(socket, REPLY_535_AUTH_FAILED,
          "5.7.8 Mechanism '" + mech + "' not advertised");
        return;
      }
      _emit("mail.server.submission.auth_attempt",
        { connectionId: state.id, mechanism: mech, remoteAddress: state.remoteAddress });

      // For PLAIN / LOGIN / EXTERNAL the verify call is single-step.
      // SCRAM-SHA-256 / GS2-* family use multi-step challenges; the
      // operator's verify returns { ok, actor, challenge, pending }
      // — when `pending: true` we send 334 + the challenge and wait
      // for the client response.
      state.authPending = { mechanism: mech, step: 0 };
      _runAuthStep(state, socket, initial);
    }

    function _continueAuthExchange(state, socket, line) {
      _runAuthStep(state, socket, line.trim());
    }

    function _runAuthStep(state, socket, clientResponse) {
      Promise.resolve()
        .then(function () {
          return authConfig.verify(state.authPending.mechanism, {
            step:          state.authPending.step,
            clientResponse: clientResponse,
            tls:           state.tls,
            remoteAddress: state.remoteAddress,
          });
        })
        .then(function (result) {
          state.authPending.step += 1;
          if (result && result.pending && typeof result.challenge === "string") {
            _writeReply(socket, REPLY_334_AUTH_CHALLENGE, result.challenge);
            return;
          }
          if (result && result.ok === true && result.actor) {
            // Capture the mechanism BEFORE nulling authPending — the
            // audit event reports the mechanism that produced the
            // successful verify, not whatever state.authPending happens
            // to be at the post-null read (which is always null).
            var successfulMechanism = state.authPending && state.authPending.mechanism;
            // b.agent.tenant gate (v0.10.12). When the listener is
            // wired with `opts.tenantScope` + `opts.agentTenantId`,
            // every authenticated actor must belong to the listener's
            // tenant. Cross-tenant authentication surfaces here as a
            // `535 5.7.0` refusal — the actor never reaches authenticated
            // state, mail submission never begins under the wrong tenant.
            if (opts.tenantScope && opts.agentTenantId) {
              try { opts.tenantScope.check(result.actor, opts.agentTenantId); }
              catch (tenantErr) {
                state.authPending = null;
                _emit("mail.server.submission.cross_tenant_refused",
                  { connectionId: state.id,
                    actorTenant:  (result.actor && result.actor.tenantId) || null,
                    agentTenant:  opts.agentTenantId,
                    code:         (tenantErr && tenantErr.code) || null },
                  "denied");
                _writeReply(socket, REPLY_535_AUTH_FAILED,
                  "5.7.0 Authentication rejected (cross-tenant)");
                return;
              }
            }
            state.authenticated = true;
            state.actor         = result.actor;
            state.authPending   = null;
            _emit("mail.server.submission.auth_success", {
              connectionId: state.id,
              mechanism:    successfulMechanism,
              tenantId:     result.actor.tenantId || null,
              scopes:       Array.isArray(result.actor.scopes) ? result.actor.scopes : [],
            });
            _writeReply(socket, REPLY_235_AUTH_OK, "2.7.0 Authentication successful");
            return;
          }
          state.authPending = null;
          rateLimit.noteAuthFailure(state.remoteAddress);
          _emit("mail.server.submission.auth_failed", {
            connectionId: state.id, reason: (result && result.reason) || "verify-returned-fail",
          }, "denied");
          _writeReply(socket, REPLY_535_AUTH_FAILED, "5.7.8 Authentication credentials invalid");
        })
        .catch(function (err) {
          state.authPending = null;
          rateLimit.noteAuthFailure(state.remoteAddress);
          _emit("mail.server.submission.auth_failed", {
            connectionId: state.id, reason: (err && err.message) || String(err),
          }, "failure");
          _writeReply(socket, REPLY_535_AUTH_FAILED, "5.7.8 Authentication failed");
        });
    }

    function _handleMailFrom(state, socket, line) {
      if (!state.tls && profile !== "permissive") {
        _writeReply(socket, REPLY_530_AUTH_REQUIRED, "5.7.0 Must issue a STARTTLS command first");
        return;
      }
      if (!state.authenticated && profile !== "permissive") {
        _writeReply(socket, REPLY_530_AUTH_REQUIRED,
          "5.7.0 Authentication required (submission listener requires AUTH per RFC 6409)");
        return;
      }
      if (state.stage !== "ehlo" && state.stage !== "mail") {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 EHLO/HELO first");
        return;
      }
      var match = line.match(RE_MAIL_FROM);
      if (!match) {
        _writeReply(socket, REPLY_501_BAD_ARGS,
          "5.5.4 Syntax: MAIL FROM:<address> [SIZE=n]");
        return;
      }
      var mailFrom = match[1].toLowerCase();
      // Domain hardening on MAIL FROM. Skip address-literal + empty
      // reverse-path (RFC 5321 §4.5.5).
      var __mfAt = mailFrom.lastIndexOf("@");
      var mailFromDomain = __mfAt === -1 ? "" : mailFrom.slice(__mfAt + 1);
      if (mailFromDomain && mailFromDomain[0] !== "[" && guardDomainProfile) {
        var __mfVerdict = _validateDomainHardened(mailFromDomain, "mail_from");
        if (!__mfVerdict.ok) {
          _writeReply(socket, REPLY_501_BAD_ARGS,
            "5.5.4 MAIL FROM domain refused (" +
            (__mfVerdict.issues && __mfVerdict.issues[0] && __mfVerdict.issues[0].kind) + ")");
          return;
        }
      }
      var paramStr = match[2] || "";
      var sizeMatch = paramStr.match(RE_SIZE);
      if (sizeMatch) {
        var declaredSize = parseInt(sizeMatch[1], 10);
        if (declaredSize > maxMessageBytes) {
          _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
            "5.3.4 Message size exceeds fixed maximum (" + maxMessageBytes + " bytes)");
          return;
        }
      }

      // Identity binding — under strict profile, MAIL FROM MUST match
      // an entry in the authenticated actor's mailbox set. An actor
      // whose mailbox set is empty MUST also be refused: an empty
      // allowlist is "no mailboxes" (account has no send-as identity
      // assigned), NOT "all mailboxes." The earlier shape allowed any
      // MAIL FROM when allowed.length === 0, turning a missing-config
      // case (operator hasn't assigned mailboxes to the actor) into
      // an open relay binding.
      if (state.authenticated && identityBinding === "strict") {
        var allowed = _actorMailboxes(state.actor);
        if (allowed.length === 0 || allowed.indexOf(mailFrom) === -1) {
          _emit("mail.server.submission.identity_mismatch", {
            connectionId: state.id, authIdentity: state.actor.id || null,
            mailFrom: mailFrom, allowed: allowed,
            reason: allowed.length === 0 ? "actor-has-no-mailboxes" : "mail-from-not-in-actor-set",
          }, "denied");
          _writeReply(socket, REPLY_553_SENDER_REJECTED,
            allowed.length === 0
              ? "5.7.1 Sender address rejected: authenticated identity has no assigned mailboxes"
              : "5.7.1 Sender address rejected: not owned by authenticated identity");
          return;
        }
      }

      state.mailFrom = mailFrom;
      state.stage    = "rcpt";
      state.rcpts    = [];
      // Track in-flight async recipientPolicy verdicts so the cap-check
      // counts BOTH committed + in-flight against `maxRcptsPerMsg`. Under
      // SMTP PIPELINING (RFC 2920) a client can send many RCPT TO commands
      // back-to-back; without this counter each one sees `state.rcpts.length`
      // == 0 because the prior pushes haven't landed inside the .then() yet,
      // so the cap-check passes for every command and `state.rcpts` grows
      // past the limit once the verdicts resolve.
      state.rcptsPending = 0;
      _emit("mail.server.submission.mail_from",
        { connectionId: state.id, mailFrom: mailFrom,
          actor: state.actor && state.actor.id });
      _writeReply(socket, REPLY_250_OK, "2.1.0 Sender OK");
    }

    function _handleRcptTo(state, socket, line) {
      if (state.stage !== "rcpt") {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 MAIL FROM first");
        return;
      }
      // Cap-check counts BOTH committed (state.rcpts.length) AND in-flight
      // (state.rcptsPending) — under PIPELINING (RFC 2920) the prior
      // commands haven't pushed yet by the time the next cap-check runs.
      if ((state.rcpts.length + (state.rcptsPending || 0)) >= maxRcptsPerMsg) {
        _writeReply(socket, REPLY_452_INSUFFICIENT_STG,
          "4.5.3 Too many recipients (limit " + maxRcptsPerMsg + ")");
        return;
      }
      var match = line.match(RE_RCPT_TO);
      if (!match) {
        _writeReply(socket, REPLY_501_BAD_ARGS, "5.5.4 Syntax: RCPT TO:<address>");
        return;
      }
      var rcpt = match[1].toLowerCase();

      // Domain hardening on RCPT TO. Skip address-literal form.
      var __rcptAt = rcpt.lastIndexOf("@");
      var __rcptDomain = __rcptAt === -1 ? "" : rcpt.slice(__rcptAt + 1);
      if (__rcptDomain && __rcptDomain[0] !== "[" && guardDomainProfile) {
        var __rcptVerdict = _validateDomainHardened(__rcptDomain, "rcpt_to");
        if (!__rcptVerdict.ok) {
          _writeReply(socket, REPLY_501_BAD_ARGS,
            "5.5.4 RCPT TO domain refused (" +
            (__rcptVerdict.issues && __rcptVerdict.issues[0] && __rcptVerdict.issues[0].kind) + ")");
          return;
        }
      }

      // Operator-supplied recipient policy — async predicate that
      // decides whether the authenticated actor may send to this
      // destination. Wires policy decisions like "block *.gov from
      // this tenant" / "this actor's outbound budget is exhausted" /
      // "destination is in the operator's deny list". Returns
      // `{ ok: true }` on accept OR `{ ok: false, reason }` on refuse.
      // When not wired, every syntactically-valid RCPT TO is accepted
      // — the agent.handoff is the operator's last chance to reject.
      if (typeof opts.recipientPolicy === "function") {
        state.rcptsPending = (state.rcptsPending || 0) + 1;
        Promise.resolve()
          .then(function () {
            return opts.recipientPolicy({
              actor:        state.actor,
              mailFrom:     state.mailFrom,
              rcptTo:       rcpt,
              connectionId: state.id,
              remoteAddress: state.remoteAddress,
              tls:          state.tls,
            });
          })
          .then(function (verdict) {
            state.rcptsPending -= 1;
            if (verdict && verdict.ok === true) {
              // Re-check the cap before commit — under PIPELINING the
              // verdict may resolve after other in-flight RCPT TO have
              // pushed, so the previously-reserved slot could already
              // be over-committed. Defense-in-depth on top of the
              // in-flight-aware cap-check above.
              if (state.rcpts.length >= maxRcptsPerMsg) {
                _emit("mail.server.submission.recipient_refused", {
                  connectionId: state.id, rcptTo: rcpt,
                  reason: "cap-exceeded-post-policy",
                  actor: state.actor && state.actor.id,
                }, "denied");
                _writeReply(socket, REPLY_452_INSUFFICIENT_STG,
                  "4.5.3 Too many recipients (limit " + maxRcptsPerMsg + ")");
                return;
              }
              state.rcpts.push(rcpt);
              _emit("mail.server.submission.rcpt_to",
                { connectionId: state.id, rcptTo: rcpt, rcptCount: state.rcpts.length });
              _writeReply(socket, REPLY_250_OK, "2.1.5 Recipient OK");
              return;
            }
            _emit("mail.server.submission.recipient_refused", {
              connectionId: state.id, rcptTo: rcpt,
              reason: (verdict && verdict.reason) || "policy-refused",
              actor: state.actor && state.actor.id,
            }, "denied");
            _writeReply(socket, REPLY_550_MAILBOX_UNAVAIL,
              "5.7.1 " + ((verdict && verdict.reason) || "Recipient policy refused"));
          })
          .catch(function (err) {
            state.rcptsPending -= 1;
            _emit("mail.server.submission.recipient_policy_threw", {
              connectionId: state.id, rcptTo: rcpt,
              error: (err && err.message) || String(err),
            }, "failure");
            // Recipient-policy hook failure is treated as transient
            // (the operator's policy engine may be temporarily
            // unavailable); 451 4.7.1 lets the sender retry.
            _writeReply(socket, REPLY_451_LOCAL_ERROR,
              "4.7.1 Recipient policy temporarily unavailable");
          });
        return;
      }

      state.rcpts.push(rcpt);
      _emit("mail.server.submission.rcpt_to",
        { connectionId: state.id, rcptTo: rcpt, rcptCount: state.rcpts.length });
      _writeReply(socket, REPLY_250_OK, "2.1.5 Recipient OK");
    }

    function _handleData(state, socket) {
      if (state.stage !== "rcpt" || state.rcpts.length === 0) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 No valid recipients");
        return;
      }
      // RFC 2920 PIPELINING race: a client may emit RCPT TO + DATA
      // in the same TCP segment. The recipientPolicy callback is
      // async; without this gate, `state.rcptsPending` > 0 means at
      // least one recipient verdict has not yet returned, and DATA
      // proceeding here would commit the message to a partially-
      // resolved recipient set (refuse outcomes that arrive after
      // the dot-terminator would be silently dropped because the
      // transaction has already moved past the `rcpt` stage). 451
      // 4.5.0 is transient — the sender retries; PIPELINING-aware
      // clients receive the pipelined replies and reissue DATA
      // cleanly.
      if ((state.rcptsPending || 0) > 0) {
        _emit("mail.server.submission.pipelining_data_race", {
          connectionId: state.id, rcptsPending: state.rcptsPending,
          rcptsCommitted: state.rcpts.length,
        }, "denied");
        _writeReply(socket, REPLY_451_LOCAL_ERROR,
          "4.5.0 RCPT TO verdicts pending; reissue DATA after recipient replies");
        return;
      }
      _writeReply(socket, REPLY_354_START_INPUT, "End data with <CR><LF>.<CR><LF>");
      state.stage    = "data-body";
      inDataBody     = true;
      bodyCollector  = safeBuffer.boundedChunkCollector({
        maxBytes:    maxMessageBytes,
        errorClass:  MailServerSubmissionError,
        sizeCode:    "mail-server-submission/body-too-large",
        sizeMessage: "DATA body exceeded maxMessageBytes (" + maxMessageBytes + ")",
      });
    }

    function _finalizeAcceptedBody(state, socket, dedotted, source) {

      // Outbound DKIM-required gate. Scan the header block for a
      // `DKIM-Signature:` line; under `self` mode also require at
      // least one signature whose `d=` tag matches the authenticated
      // identity's domain part.
      if (requireDkim) {
        var headerEnd = _findHeaderEnd(dedotted);
        var headerBlock = headerEnd === -1
          ? dedotted.toString("utf8")
          : dedotted.subarray(0, headerEnd).toString("utf8");
        var dkimSigs = _extractDkimSignatures(headerBlock);
        var dkimOk = false;
        if (dkimSigs.length > 0) {
          if (dkimRequireMode === "any") {
            dkimOk = true;
          } else if (dkimRequireMode === "self") {
            var actorDomain = _actorDomain(state.actor, state.mailFrom);
            for (var i = 0; i < dkimSigs.length; i += 1) {
              var d = _extractDkimDTag(dkimSigs[i]);
              if (d && actorDomain && d.toLowerCase() === actorDomain.toLowerCase()) {
                dkimOk = true;
                break;
              }
            }
          }
        }
        if (!dkimOk) {
          _emit("mail.server.submission.data_refused", {
            connectionId:    state.id,
            reason:          "dkim-required",
            dkimRequireMode: dkimRequireMode,
            mailFrom:        state.mailFrom,
            sigCount:        dkimSigs.length,
            actor:           state.actor && state.actor.id,
          }, "denied");
          _writeReply(socket, REPLY_550_MAILBOX_UNAVAIL,
            "5.7.20 DKIM-Signature required on outbound submission " +
            "(dkimRequireMode='" + dkimRequireMode + "'; RFC 6376; bulk-sender 2024)");
          _resetTransaction(state);
          return;
        }
      }

      if (opts.agent && typeof opts.agent.handoff === "function") {
        opts.agent.handoff({
          mailFrom: state.mailFrom,
          rcpts:    state.rcpts.slice(),
          body:     dedotted,
          actor:    state.actor,
          remote:   { address: state.remoteAddress, port: state.remotePort },
          tls:      state.tls,
          helo:     state.helo,
          connectionId: state.id,
          direction:    "outbound",
        }).then(function (ack) {
          _emit("mail.server.submission.outbound_routed", {
            connectionId: state.id, messageId: ack && ack.messageId,
            sizeBytes: dedotted.length, actor: state.actor && state.actor.id,
          });
          _writeReply(socket, REPLY_250_OK,
            "2.6.0 Message accepted" + (ack && ack.messageId ? " <" + ack.messageId + ">" : ""));
          _resetTransaction(state);
        }).catch(function (err) {
          _emit("mail.server.submission.data_refused",
            { connectionId: state.id, reason: "agent-handoff-failed",
              error: (err && err.message) || String(err) }, "failure");
          _writeReply(socket, REPLY_451_LOCAL_ERROR, "4.3.0 Local delivery error");
          _resetTransaction(state);
        });
        return;
      }
      _emit("mail.server.submission.data_accepted",
        { connectionId: state.id, mailFrom: state.mailFrom,
          rcptCount: state.rcpts.length, sizeBytes: dedotted.length, source: source || "DATA" });
      _writeReply(socket, REPLY_250_OK, "2.6.0 Message queued (audit-only)");
      _resetTransaction(state);
    }

    // RFC 3030 §2 — BDAT <chunk-size> [LAST]. Reads exactly chunk-size
    // bytes off the wire (no dot-stuffing, no end-of-data marker). The
    // size is a non-negative integer; LAST keyword (case-insensitive)
    // terminates the message body. Mixing DATA + BDAT within the same
    // transaction is forbidden — the server returns 503 once the first
    // BDAT lands and forces the client to RSET.
    function _handleBdat(state, socket, line) {
      if (state.stage !== "rcpt" && state.stage !== "bdat") {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 BDAT requires MAIL FROM + RCPT TO");
        return;
      }
      if (state.rcpts.length === 0) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 No valid recipients");
        return;
      }
      // Pipelining race — same gate as DATA.
      if ((state.rcptsPending || 0) > 0) {
        _emit("mail.server.submission.pipelining_bdat_race", {
          connectionId: state.id, rcptsPending: state.rcptsPending,
          rcptsCommitted: state.rcpts.length,
        }, "denied");
        _writeReply(socket, REPLY_451_LOCAL_ERROR,
          "4.5.0 RCPT TO verdicts pending; reissue BDAT after recipient replies");
        return;
      }
      // Parse `BDAT <size>[ LAST]`.
      var parts = line.split(/\s+/);
      if (parts.length < 2 || parts.length > 3) {
        _writeReply(socket, REPLY_501_BAD_ARGS, "5.5.4 BDAT requires <chunk-size> [LAST]");
        return;
      }
      var sizeStr = parts[1];
      var sizeN = parseInt(sizeStr, 10);
      if (!/^\d+$/.test(sizeStr) || !isFinite(sizeN) || sizeN < 0) {
        _writeReply(socket, REPLY_501_BAD_ARGS, "5.5.4 BDAT chunk-size must be a non-negative integer");
        return;
      }
      var isLast = parts.length === 3 && parts[2].toUpperCase() === "LAST";
      if (parts.length === 3 && !isLast) {
        _writeReply(socket, REPLY_501_BAD_ARGS, "5.5.4 BDAT third arg must be 'LAST' (RFC 3030 §2)");
        return;
      }
      // Cumulative-size cap. The collector is bounded too, but checking
      // up-front lets us refuse the chunk before reading bytes off the
      // socket — important when sizeN >> maxMessageBytes.
      if (bdatTotalBytes + sizeN > maxMessageBytes) {
        _emit("mail.server.submission.bdat_refused",
          { connectionId: state.id, reason: "body-too-large",
            requestedTotal: bdatTotalBytes + sizeN, maxBytes: maxMessageBytes }, "denied");
        _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
          "5.3.4 BDAT cumulative size " + (bdatTotalBytes + sizeN) +
          " exceeds maxMessageBytes (" + maxMessageBytes + ")");
        _resetTransaction(state);
        bdatCollector = null; bdatTotalBytes = 0;
        return;
      }
      if (!bdatCollector) {
        bdatCollector = safeBuffer.boundedChunkCollector({
          maxBytes:    maxMessageBytes,
          errorClass:  MailServerSubmissionError,
          sizeCode:    "mail-server-submission/body-too-large",
          sizeMessage: "BDAT body exceeded maxMessageBytes (" + maxMessageBytes + ")",
        });
      }
      state.stage   = "bdat";
      bdatRemaining = sizeN;
      bdatIsLast    = isLast;
      // size=0 + LAST is a valid sequence — finalises the message
      // body (the LAST chunk may carry zero bytes when the prior chunk
      // was the final payload). RFC 3030 §2.2 — ONE reply per command:
      // emit the "0 octets" ack for size=0 NOT-LAST, but defer to
      // _finalizeAcceptedBody for size=0 LAST.
      if (sizeN === 0) {
        if (isLast) {
          var emptyBody = bdatCollector ? bdatCollector.result() : Buffer.alloc(0);
          bdatCollector = null; bdatTotalBytes = 0;
          _finalizeAcceptedBody(state, socket, emptyBody, "BDAT");
        } else {
          _writeReply(socket, REPLY_250_OK, "2.0.0 0 octets received");
        }
        return;
      }
      inBdatChunk = true;
    }

    function _resetTransaction(state) {
      state.mailFrom     = null;
      state.rcpts        = [];
      state.rcptsPending = 0;
      state.stage        = "ehlo";
      // BDAT-side state lives at the connection level, not on `state`.
      // Reset it here so a RSET / failed BDAT can't leak collected
      // bytes into the next transaction.
      inBdatChunk    = false;
      bdatRemaining  = 0;
      bdatIsLast     = false;
      bdatCollector  = null;
      bdatTotalBytes = 0;
    }
  }

  // Port 0 (ephemeral, test mode) must NOT fall back to the protocol default —
  // the `|| <default>` short-circuit was a footgun on the test path;
  // createTcpListener honors an explicit 0 (only an OMITTED port defaults). The
  // listening event reports implicitTls so an operator can confirm the wire mode.
  var _tcpListener = mailServerNet.createTcpListener(net, {
    defaultPort:      implicitTls ? 465 : 587,                                                        // RFC 8314 implicit-TLS / RFC 6409 submission ports
    handleConnection: _handleConnection,
    errorFactory:     function (code, message) { return new MailServerSubmissionError("mail-server-submission/" + code, message); },
    emit:             _emit,
    listeningEvent:   "mail.server.submission.listening",
    listeningExtra:   function () { return { implicitTls: implicitTls }; },
  });

  async function close(closeOpts) {
    closeOpts = closeOpts || {};
    if (!_tcpListener.isListening()) return;
    var timeoutMs = closeOpts.timeoutMs || C.TIME.seconds(30);
    _tcpListener.markClosed();
    _tcpListener.getServer().close();
    connections.forEach(function (sock) {
      try { _writeReply(sock, REPLY_421_SERVICE_NOT_AVAIL, "4.3.0 Server shutting down"); }
      catch (_e) { /* socket already gone */ }
    });
    var deadline = Date.now() + timeoutMs;
    while (connections.size > 0 && Date.now() < deadline) {
      await safeAsync.sleep(100);
    }
    connections.forEach(function (sock) {
      try { sock.destroy(); } catch (_e) { /* best-effort */ }
    });
    connections.clear();
    _emit("mail.server.submission.closed", {});
  }

  function connectionCount() { return connections.size; }

  return {
    listen:           _tcpListener.listen,
    close:            close,
    connectionCount:  connectionCount,
    _portForTest:     function () { var s = _tcpListener.getServer(); return s ? s.address().port : null; },
  };
}

function _actorMailboxes(actor) {
  if (!actor) return [];
  if (Array.isArray(actor.mailboxes)) return actor.mailboxes.map(function (m) { return String(m).toLowerCase(); });
  if (typeof actor.mailbox === "string") return [actor.mailbox.toLowerCase()];
  return [];
}

function _writeReply(socket, code, text) {
  try { socket.write(code + " " + text + "\r\n"); }
  catch (_e) { /* socket already closed */ }
}

function _writeMultiline(socket, code, lines) {
  for (var i = 0; i < lines.length; i += 1) {
    var sep = i === lines.length - 1 ? " " : "-";
    try { socket.write(code + sep + lines[i] + "\r\n"); }
    catch (_e) { /* socket already closed */ }
  }
}

function _closeConnection(socket) {
  try { socket.end(); } catch (_e) { /* best-effort */ }
  try { socket.destroy(); } catch (_e) { /* best-effort */ }
}

module.exports = {
  create:                    create,
  MailServerSubmissionError: MailServerSubmissionError,
};

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
 *   - `mail.server.submission.sender_policy_threw` — senderPolicy failed; the sender is refused (553 5.7.1)
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
var C         = require("./constants");
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
var time = require("./time");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var MailServerSubmissionError = defineClass("MailServerSubmissionError", { alwaysPermanent: true });

var DEFAULT_MAX_LINE_BYTES        = C.BYTES.kib(1);
var DEFAULT_MAX_MESSAGE_BYTES     = C.BYTES.mib(50);
var DEFAULT_MAX_RCPTS_PER_MESSAGE = 100;
var DEFAULT_IDLE_TIMEOUT_MS       = C.TIME.minutes(5);
var DEFAULT_GREETING              = "blamejs Submission";
var DEFAULT_AUTH_MECHANISMS       = Object.freeze(["PLAIN", "LOGIN"]);

var REPLY_220_READY              = "220";
var REPLY_221_BYE                = "221";
var REPLY_235_AUTH_OK            = "235";
var REPLY_250_OK                 = "250";
var REPLY_334_AUTH_CHALLENGE     = "334";
var REPLY_354_START_INPUT        = "354";
var REPLY_421_SERVICE_NOT_AVAIL  = "421";
var REPLY_451_LOCAL_ERROR        = "451";
var REPLY_452_INSUFFICIENT_STG   = "452";
var REPLY_500_SYNTAX             = "500";
var REPLY_501_BAD_ARGS           = "501";
var REPLY_502_NOT_IMPLEMENTED    = "502";
var REPLY_503_BAD_SEQUENCE       = "503";
var REPLY_530_AUTH_REQUIRED      = "530";
var REPLY_535_AUTH_FAILED        = "535";
var REPLY_538_AUTH_NEEDS_TLS     = "538";
var REPLY_550_MAILBOX_UNAVAIL    = "550";
var REPLY_552_SIZE_EXCEEDED      = "552";
var REPLY_553_SENDER_REJECTED    = "553";
var REPLY_554_TRANSACTION_FAILED = "554";

var RE_MAIL_FROM = /^MAIL\s+FROM:\s*<([^>]*)>(?:\s+(.*))?$/i;
var RE_RCPT_TO   = /^RCPT\s+TO:\s*<([^>]+)>(?:\s+.*)?$/i;
var RE_SIZE      = /SIZE=(\d+)/i;
var RE_AUTH      = /^AUTH\s+([A-Za-z0-9_-]{1,32})(?:\s+(.*))?$/i;

var _CRLF_CRLF = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a]);
function _findHeaderEnd(buf) {
  return buf.indexOf(_CRLF_CRLF);
}

function _extractDkimSignatures(headerBlock) {
  var lines = headerBlock.replace(/\r\n/g, "\n").split("\n");                                           // allow:regex-no-length-cap — headerBlock length bounded by maxMessageBytes
  var result = [];
  var current = null;
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0) break;
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

function _extractDkimDTag(sigValue) {
  var tags = sigValue.split(";");
  for (var i = 0; i < tags.length; i += 1) {
    var t = tags[i].trim();
    if (t.length > 2 && t.charAt(0) === "d" && t.charAt(1) === "=") {
      return t.slice(2).replace(/\s+/g, "");                                                            // allow:regex-no-length-cap — value length bounded by tag length // allow:duplicate-regex — internal-WS strip
    }
  }
  return null;
}

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
 *   agent:           object,       // outbound delivery handoff (handoff({ ... }) → ack). A rejection may
 *                                  // carry smtpCode ("550"), enhancedStatus ("5.7.1") and replyText to
 *                                  // choose its own refusal; without them the reply is 451 4.3.0
 *   identityBinding: "strict" | "permissive",  // MAIL FROM must match auth identity (default strict)
 *   subaddressDelimiter: string,   // RFC 5233 local-part separator the identity check folds on ("+" on most systems, "-" on qmail-derived ones). OFF unless set: subaddressing is a delivery convention, and folding where plus-addresses are distinct mailboxes would grant send-as authority over another account
 *   senderPolicy:    function (ctx) → { ok } | { ok: false },   // optional, asked only when the actor's mailbox set does not already cover MAIL FROM — for aliases and anything else resolved at request time. Fails CLOSED: a policy that throws or rejects refuses the sender
 *   maxLineBytes:    number,       // default 1 KiB
 *   maxMessageBytes: number,       // default 50 MiB
 *   maxRcptsPerMessage: number,    // default 100
 *   idleTimeoutMs:   number,       // default 5 minutes
 *   maxConnections:  number,       // default 1024 — listener-wide ceiling
 *   profile:         string,       // "strict" | "balanced" | "permissive"; default "strict"
 *
 * @example
 *   var tls = require("node:tls").createSecureContext(
 *     b.network.tls.buildOptions({ cert: certPem, key: keyPem }));
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
var CREATE_OPTS = [
  "tlsContext", "implicitTls", "greeting", "auth", "rateLimit", "agent",
  "identityBinding", "subaddressDelimiter", "senderPolicy", "maxLineBytes",
  "maxMessageBytes", "maxRcptsPerMessage", "idleTimeoutMs", "maxConnections",
  "profile", "agentTenantId", "tenantScope", "allowSmtpUtf8", "guardDomain",
  "recipientPolicy", "requireDkim", "dkimRequireMode",
];

function create(opts) {
  validateOpts.requireObject(opts, "mail.server.submission.create",
    MailServerSubmissionError, "mail-server-submission/bad-opts");
  validateOpts.checkOrThrow(opts, CREATE_OPTS, "mail.server.submission.create",
    MailServerSubmissionError, "mail-server-submission/bad-opts");
  if (!opts.tlsContext) {
    throw new MailServerSubmissionError("mail-server-submission/no-tls-context",
      "mail.server.submission.create: tlsContext is required");
  }
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
    ["maxLineBytes", "maxMessageBytes", "maxRcptsPerMessage", "idleTimeoutMs", "maxConnections"],
    "mail.server.submission.", MailServerSubmissionError, "mail-server-submission/bad-bound");

  var profile = opts.profile || "strict";
  var allowSmtpUtf8 = opts.allowSmtpUtf8 === true;

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
  var subaddressDelimiter = typeof opts.subaddressDelimiter === "string" &&
    opts.subaddressDelimiter.length > 0 ? opts.subaddressDelimiter : null;
  var senderPolicy = validateOpts.definedFunction(opts.senderPolicy,
    "b.mail.server.submission.create: senderPolicy", MailServerSubmissionError,
    "mail-server-submission/bad-opts");

  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

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
    var accepted = mailServerNet.acceptConnection(rawSocket, {
      rateLimit:    rateLimit,
      connections:  connections,
      emit:         _emit,
      refusedEvent: "mail.server.submission.rate_limit_refused",
      refusalLine:  "421 4.7.0 Too many connections from your IP\r\n",
      idPrefix:     "submitconn-",
      wrap: mailServerTls.implicitTlsWrap(opts.tlsContext, implicitTls),
    });
    if (accepted === null) return;
    var remoteAddress = accepted.remoteAddress;
    var connectionId  = accepted.connectionId;
    var socket        = accepted.socket;

    var state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      remotePort:    rawSocket.remotePort || null,
      tls:           implicitTls,
      stage:         "connect",
      closed:        false,
      helo:          null,
      authenticated: false,
      actor:         null,
      mailFrom:      null,
      rcpts:         [],
      authPending:   null,
    };

    var lineBuffer = Buffer.alloc(0);
    var bodyCollector = null;
    var bodyScanner = null;
    var bodyRateWindow = mailServerNet.createBodyRateWindow(rateLimit);
    var inDataBody = false;
    var inBdatChunk    = false;
    var bdatRateStarted = false;
    var wireBytes = 0;
    var bdatRemaining  = 0;
    var bdatIsLast     = false;
    var bdatCollector  = null;
    var bdatTotalBytes = 0;

    socket.setTimeout(idleTimeoutMs);
    socket.on("timeout", function () {
      _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL, "4.4.2 Idle timeout");
      _closeSession(state, socket);
    });
    socket.on("error", function (err) {
      _emit("mail.server.submission.socket_error",
        { connectionId: state.id, code: (err && err.code) || "unknown" }, "warning");
      _closeSession(state, socket);
    });

    rawSocket.on("close", function () { _closeSession(state, socket); });

    _emit("mail.server.submission.connect", {
      connectionId:  state.id,
      remoteAddress: state.remoteAddress,
      remotePort:    state.remotePort,
      tls:           state.tls,
    });

    _writeReply(socket, REPLY_220_READY, greeting + " ready");

    function _feedChunk(activeSock, chunk) {
      wireBytes += chunk.length;
      try { _ingestBytes(state, activeSock, chunk); }
      catch (err) {
        _emit("mail.server.submission.handler_threw",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        try { _writeReply(activeSock, REPLY_421_SERVICE_NOT_AVAIL, "4.3.0 Server error"); }
        catch (_e) { /* socket already gone */ }
        _closeSession(state, activeSock);
      }
    }

    socket.on("data", function (chunk) { _feedChunk(socket, chunk); });

    function _ingestBytes(state, socket, chunk) {
      if (state.closed) return;
      if (bdatRateStarted || inDataBody) {
        if (bodyRateWindow.starved(wireBytes, time.monotonicMs())) {
          _emit("mail.server.submission.data_refused",
            { connectionId: state.id, reason: "body-rate-below-floor",
              minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
          _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL,
            "4.7.0 Message body arriving below the minimum rate; closing connection");
          _resetTransaction(state);
          inDataBody = false; bodyCollector = null; bodyScanner = null;
          _closeSession(state, socket);
          return;
        }
      }
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
            var bdatBody = bdatCollector.result();
            bdatCollector = null;
            bdatTotalBytes = 0;
            if (_refuseSmuggledBdatBody(state, socket, bdatBody)) return;
            _finalizeAcceptedBody(state, socket, bdatBody, "BDAT");
          } else {
            _writeReply(socket, REPLY_250_OK,
              "2.0.0 " + bdatTotalBytes + " octets received");
          }
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
          inDataBody = false; bodyCollector = null; bodyScanner = null;
          return;
        }
        var seen = bodyScanner.push(chunk);
        if (seen.smuggling) {
          _emit("mail.server.submission.smtp_smuggling_detected",
            { connectionId: state.id, mailFrom: state.mailFrom, rcptCount: state.rcpts.length },
            "denied");
          _writeReply(socket, REPLY_554_TRANSACTION_FAILED,
            "5.7.0 Bare-LF in DATA body refused (RFC 5321 §2.3.8; CVE-2023-51764 SMTP smuggling)");
          _resetTransaction(state);
          inDataBody = false; bodyCollector = null; bodyScanner = null;
          return;
        }
        if (seen.terminatorAt !== -1) {
          var body = bodyCollector.result().subarray(0, seen.terminatorAt);
          var dedotted = safeSmtp.dotUnstuff(body);
          _finalizeAcceptedBody(state, socket, dedotted, "DATA");
          inDataBody = false; bodyCollector = null; bodyScanner = null;
        }
        return;
      }

      lineBuffer = lineBuffer.length === 0 ? chunk : Buffer.concat([lineBuffer, chunk]);
      if (_longestLineBytes(lineBuffer) > maxLineBytes * 4) {
        _writeReply(socket, REPLY_500_SYNTAX,
          "5.5.6 Line too long (>" + maxLineBytes + " bytes)");
        _closeSession(state, socket);
        return;
      }
      if (_backlogRefused(state, socket)) return;
      if (state.commandPending) return;
      _drainLines(state, socket);
    }

    function _backlogRefused(state, socket) {
      if (!state.commandPending) return false;
      if (safeBuffer.byteLengthOf(lineBuffer) <= maxLineBytes * (maxRcptsPerMsg + 4)) return false;
      _writeReply(socket, REPLY_500_SYNTAX,
        "5.5.6 Too many pipelined bytes awaiting the previous command's verdict");
      _closeSession(state, socket);
      return true;
    }

    function _longestLineBytes(buf) {
      var longest = 0;
      var start = 0;
      var crlfAt;
      var needle = Buffer.from("\r\n", "ascii");
      while ((crlfAt = buf.indexOf(needle, start)) !== -1) {
        if (crlfAt - start > longest) longest = crlfAt - start;
        start = crlfAt + 2;
      }
      var tail = safeBuffer.byteLengthOf(buf) - start;
      return tail > longest ? tail : longest;
    }

    function _closeSession(state, socket) {
      state.closed = true;
      lineBuffer = Buffer.alloc(0);
      mailServerNet.destroySocketAfterFlush(socket);
    }

    function _drainLines(state, socket) {
      if (state.closed) return;
      var crlf;
      var crlfNeedle = Buffer.from("\r\n", "ascii");
      while ((crlf = lineBuffer.indexOf(crlfNeedle)) !== -1) {
        var line = lineBuffer.subarray(0, crlf).toString("utf8");
        lineBuffer = lineBuffer.subarray(crlf + 2);
        _handleCommand(state, socket, line);
        if (inDataBody) return;
        if (state.commandPending) { _backlogRefused(state, socket); return; }
        if (inBdatChunk) {
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
      if (state.authPending) {
        return _continueAuthExchange(state, socket, line);
      }

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
            { connectionId: state.id, code: err.code, line: line.slice(0, 200) },
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
          return _closeSession(state, socket);
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
        if (!state.tls && !implicitTls) caps.unshift("STARTTLS");
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
      lineBuffer = Buffer.alloc(0); bodyCollector = null; bodyScanner = null; inDataBody = false;
      inBdatChunk = false; bdatRemaining = 0; bdatCollector = null; bdatTotalBytes = 0;
      bdatRateStarted = false;
      mailServerTls.upgradeSocket({
        plainSocket:   socket,
        secureContext: opts.tlsContext,
        idleTimeoutMs: idleTimeoutMs,
        onSecure: function (_tlsSocket) {
          state.tls = true; state.stage = "ehlo"; state.helo = null;
        },
        onData: function (tlsSocket, chunk) {
          _feedChunk(tlsSocket, chunk);
        },
        onError: function (err) {
          _emit("mail.server.submission.tls_handshake_failed",
            { connectionId: state.id, code: (err && err.code) || "unknown" }, "failure");
          _closeSession(state, socket);
        },
        onTimeout: function (tlsSocket) {
          _writeReply(tlsSocket, REPLY_421_SERVICE_NOT_AVAIL, "4.4.2 Idle timeout");
          _closeSession(state, tlsSocket);
        },
      });
    }

    function _handleAuth(state, socket, line) {
      if (!authConfig) {
        _writeReply(socket, REPLY_502_NOT_IMPLEMENTED, "5.5.1 AUTH not configured on this listener");
        return;
      }
      if (!state.tls && profile !== "permissive") {
        _writeReply(socket, REPLY_538_AUTH_NEEDS_TLS,
          "5.7.11 Encryption required for AUTH (RFC 4954 §4)");
        return;
      }
      if (!state.tls && profile === "permissive") {
        _emit("mail.server.submission.auth_cleartext_accepted",
          { connectionId: state.id, remoteAddress: state.remoteAddress,
            profile: profile }, "warning");
      }
      if (state.authenticated) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 Already authenticated");
        return;
      }
      var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
      if (!authAdmit.ok) {
        _emit("mail.server.submission.auth_rate_limit_refused",
          { connectionId: state.id, remoteAddress: state.remoteAddress,
            reason: authAdmit.reason }, "denied");
        _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL,
          "4.7.0 Too many AUTH failures from your IP");
        _closeSession(state, socket);
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

      state.authPending = { mechanism: mech, step: 0 };
      _runAuthStep(state, socket, initial);
    }

    function _continueAuthExchange(state, socket, line) {
      _runAuthStep(state, socket, line.trim());
    }

    function _runAuthStep(state, socket, clientResponse) {
      state.commandPending = true;
      return Promise.resolve()
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
            var safeChallenge = mailServerNet.saslChallengeOrNull(result.challenge);
            if (safeChallenge === null) {
              state.authPending = null;
              rateLimit.noteAuthFailure(state.remoteAddress);
              _emit("mail.server.submission.auth_failed",
                { connectionId: state.id, reason: "challenge-contains-line-terminator" },
                "denied");
              _writeReply(socket, REPLY_535_AUTH_FAILED, "5.7.8 Authentication failed");
              return;
            }
            _writeReply(socket, REPLY_334_AUTH_CHALLENGE, safeChallenge);
            return;
          }
          if (result && result.ok === true && result.actor) {
            var successfulMechanism = state.authPending && state.authPending.mechanism;
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
        })
        .then(function () {
          state.commandPending = false;
          return _drainLines(state, socket);
        });
    }

    async function _senderPolicyAllows(socket, state, mailFrom, deliveredTo, allowed) {
      var verdict;
      try {
        verdict = await senderPolicy({
          actor:         state.actor,
          mailFrom:      mailFrom,
          deliveredTo:   deliveredTo,
          mailboxes:     allowed.slice(),
          connectionId:  state.id,
          remoteAddress: state.remoteAddress,
          tls:           state.tls,
        });
      } catch (e) {
        _emit("mail.server.submission.sender_policy_threw", {
          connectionId: state.id, authIdentity: (state.actor && state.actor.id) || null,
          mailFrom: mailFrom, error: (e && e.message) || String(e),
        }, "failure");
        _writeReply(socket, REPLY_553_SENDER_REJECTED,
          "5.7.1 Sender address rejected: not owned by authenticated identity");
        return null;
      }
      return !!(verdict && verdict.ok === true);
    }

    async function _handleMailFrom(state, socket, line) {
      if (!state.tls && profile !== "permissive") {
        _writeReply(socket, REPLY_530_AUTH_REQUIRED, "5.7.0 Must issue a STARTTLS command first");
        return;
      }
      if (!state.authenticated && profile !== "permissive") {
        _writeReply(socket, REPLY_530_AUTH_REQUIRED,
          "5.7.0 Authentication required (submission listener requires AUTH per RFC 6409)");
        return;
      }
      if (state.mailFrom !== null && state.mailFrom !== undefined) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 Sender already specified");
        return;
      }
      if (state.stage !== "ehlo") {
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

      if (state.authenticated && identityBinding === "strict") {
        var allowed = _actorMailboxes(state.actor);
        var deliveredTo = mailServerNet.foldSubaddress(mailFrom, subaddressDelimiter);
        var matched = false;
        if (allowed.length !== 0) {
          matched = allowed.indexOf(mailFrom) !== -1 ||
            allowed.some(function (m) {
              return mailServerNet.foldSubaddress(m, subaddressDelimiter) === deliveredTo;
            });
        }
        if (!matched && typeof senderPolicy === "function") {
          state.commandPending = true;
          try {
            matched = await _senderPolicyAllows(socket, state, mailFrom, deliveredTo, allowed);
          } finally {
            state.commandPending = false;
          }
          if (matched === null) return _drainLines(state, socket);
          if (!matched) {
            _refuseSender(state, socket, mailFrom, allowed);
            return _drainLines(state, socket);
          }
          _acceptSender(state, socket, mailFrom);
          return _drainLines(state, socket);
        }
        if (!matched) return _refuseSender(state, socket, mailFrom, allowed);
      }

      _acceptSender(state, socket, mailFrom);
    }

    function _refuseSender(state, socket, mailFrom, allowed) {
      _emit("mail.server.submission.identity_mismatch", {
        connectionId: state.id, authIdentity: state.actor.id || null,
        mailFrom: mailFrom, allowed: allowed,
        reason: allowed.length === 0 ? "actor-has-no-mailboxes" : "mail-from-not-in-actor-set",
      }, "denied");
      _writeReply(socket, REPLY_553_SENDER_REJECTED,
        allowed.length === 0
          ? "5.7.1 Sender address rejected: authenticated identity has no assigned mailboxes"
          : "5.7.1 Sender address rejected: not owned by authenticated identity");
    }

    function _acceptSender(state, socket, mailFrom) {
      state.mailFrom = mailFrom;
      state.stage    = "rcpt";
      state.rcpts    = [];
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
              "5.7.1 " + mailServerNet.replyTextOrFallback(
                verdict && verdict.reason, "Recipient policy refused"));
          })
          .catch(function (err) {
            state.rcptsPending -= 1;
            _emit("mail.server.submission.recipient_policy_threw", {
              connectionId: state.id, rcptTo: rcpt,
              error: (err && err.message) || String(err),
            }, "failure");
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
      bodyScanner    = safeSmtp.createBodyScanner();
      bodyRateWindow.start(time.monotonicMs(), wireBytes);
    }

    function _refuseSmuggledBdatBody(state, socket, body) {
      if (!guardSmtpCommand.detectBodySmuggling(body)) return false;
      _emit("mail.server.submission.smtp_smuggling_detected",
        { connectionId: state.id, mailFrom: state.mailFrom,
          rcptCount: state.rcpts.length, framing: "BDAT" },
        "denied");
      _writeReply(socket, REPLY_554_TRANSACTION_FAILED,
        "5.7.0 Bare-LF in BDAT body refused (RFC 5321 §2.3.8; CVE-2023-51764 SMTP smuggling)");
      _resetTransaction(state);
      return true;
    }

    function _finalizeAcceptedBody(state, socket, dedotted, source) {

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
          var refusal = mailServerNet.agentRefusalReply(err, "Local delivery error");
          _emit("mail.server.submission.data_refused",
            { connectionId: state.id, reason: "agent-handoff-failed",
              smtpCode: refusal.code,
              error: (err && err.message) || String(err) }, "failure");
          _writeReply(socket, refusal.code, refusal.text);
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

    function _handleBdat(state, socket, line) {
      if (state.stage !== "rcpt" && state.stage !== "bdat") {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 BDAT requires MAIL FROM + RCPT TO");
        return;
      }
      if (state.rcpts.length === 0) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 No valid recipients");
        return;
      }
      if ((state.rcptsPending || 0) > 0) {
        _emit("mail.server.submission.pipelining_bdat_race", {
          connectionId: state.id, rcptsPending: state.rcptsPending,
          rcptsCommitted: state.rcpts.length,
        }, "denied");
        _writeReply(socket, REPLY_451_LOCAL_ERROR,
          "4.5.0 RCPT TO verdicts pending; reissue BDAT after recipient replies");
        return;
      }
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
      if (!bdatRateStarted) {
        bodyRateWindow.start(time.monotonicMs(), wireBytes);
        bdatRateStarted = true;
      }
      bdatRemaining = sizeN;
      bdatIsLast    = isLast;
      if (sizeN === 0) {
        if (isLast) {
          var emptyBody = bdatCollector ? bdatCollector.result() : Buffer.alloc(0);
          bdatCollector = null; bdatTotalBytes = 0;
          if (_refuseSmuggledBdatBody(state, socket, emptyBody)) return;
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
      inBdatChunk    = false;
      bdatRemaining  = 0;
      bdatIsLast     = false;
      bdatCollector  = null;
      bdatTotalBytes = 0;
      bdatRateStarted = false;
    }
  }

  var _tcpListener = mailServerNet.createTcpListener(net, {
    defaultPort:      implicitTls ? 465 : 587,
    maxConnections:   opts.maxConnections,
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


module.exports = {
  create:                    create,
  MailServerSubmissionError: MailServerSubmissionError,
};

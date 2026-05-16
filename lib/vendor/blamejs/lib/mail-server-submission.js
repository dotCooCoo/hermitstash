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
 *   - SMTP smuggling (CVE-2023-51764 / -51765 / -51766 / 2024-32178 /
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
 *   - **CHUNKING (BDAT) extension** — RFC 3030 BDAT not yet
 *     supported on submission; clients use DATA instead.
 *   - **Per-actor outbound quota** — operator implements via
 *     `b.dailyByteQuota` against the authenticated actor.
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
var lazyRequire = require("./lazy-require");
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
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var MailServerSubmissionError = defineClass("MailServerSubmissionError", { alwaysPermanent: true });

var DEFAULT_MAX_LINE_BYTES        = C.BYTES.kib(1);
var DEFAULT_MAX_MESSAGE_BYTES     = C.BYTES.mib(50);
var DEFAULT_MAX_RCPTS_PER_MESSAGE = 100;                                                              // allow:raw-byte-literal — RFC 5321 §4.5.3.1.8 recipient cap
var DEFAULT_IDLE_TIMEOUT_MS       = C.TIME.minutes(5);
var DEFAULT_GREETING              = "blamejs Submission";
var DEFAULT_AUTH_MECHANISMS       = Object.freeze(["PLAIN", "LOGIN"]);

var REPLY_220_READY              = "220";
var REPLY_221_BYE                = "221";
var REPLY_235_AUTH_OK            = "235";                                                             // allow:raw-byte-literal — SMTP AUTH success code
var REPLY_250_OK                 = "250";
var REPLY_334_AUTH_CHALLENGE     = "334";                                                             // allow:raw-byte-literal — SMTP AUTH challenge code
var REPLY_354_START_INPUT        = "354";
var REPLY_421_SERVICE_NOT_AVAIL  = "421";                                                             // allow:raw-byte-literal — SMTP transient code
var REPLY_451_LOCAL_ERROR        = "451";                                                             // allow:raw-byte-literal — SMTP transient code
var REPLY_452_INSUFFICIENT_STG   = "452";                                                             // allow:raw-byte-literal — SMTP transient code
var REPLY_500_SYNTAX             = "500";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_501_BAD_ARGS           = "501";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_502_NOT_IMPLEMENTED    = "502";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_503_BAD_SEQUENCE       = "503";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_530_AUTH_REQUIRED      = "530";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_535_AUTH_FAILED        = "535";                                                             // allow:raw-byte-literal — RFC 4954 §6 AUTH refusal
var REPLY_538_AUTH_NEEDS_TLS     = "538";                                                             // allow:raw-byte-literal — RFC 4954 §4 AUTH-needs-TLS
var REPLY_550_MAILBOX_UNAVAIL    = "550";                                                             // allow:raw-byte-literal — SMTP permanent code (recipient-policy refusal shape)
var REPLY_552_SIZE_EXCEEDED      = "552";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_553_SENDER_REJECTED    = "553";                                                             // allow:raw-byte-literal — identity-binding mismatch
var REPLY_554_TRANSACTION_FAILED = "554";                                                             // allow:raw-byte-literal — SMTP permanent code

var RE_MAIL_FROM = /^MAIL\s+FROM:\s*<([^>]*)>(?:\s+(.*))?$/i;
var RE_RCPT_TO   = /^RCPT\s+TO:\s*<([^>]+)>(?:\s+.*)?$/i;
var RE_SIZE      = /SIZE=(\d+)/i;
var RE_AUTH      = /^AUTH\s+([A-Za-z0-9_-]{1,32})(?:\s+(.*))?$/i;

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
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "maxMessageBytes", "maxRcptsPerMessage", "idleTimeoutMs"],
    "mail.server.submission.", MailServerSubmissionError, "mail-server-submission/bad-bound");

  var profile = opts.profile || "strict";

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
  var rateLimit;
  if (opts.rateLimit === false) {
    rateLimit = mailServerRateLimit.create({ disabled: true });
  } else if (opts.rateLimit && typeof opts.rateLimit.admitConnection === "function") {
    rateLimit = opts.rateLimit;
  } else {
    rateLimit = mailServerRateLimit.create(opts.rateLimit || {});
  }

  // Default-on guardDomain hardening for HELO / MAIL FROM / RCPT TO.
  // Same posture as mail-server-mx — IDN homograph (CVE-2017-5469
  // class), special-use-domain refusal (RFC 6761), label-length cap
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
    if (!guardDomainProfile) return { ok: true };
    var verdict = guardDomain.validate(d, guardDomainProfile);
    if (!verdict.ok) {
      _emit("mail.server.submission.domain_refused", {
        reason: verdict.issues && verdict.issues[0] && verdict.issues[0].kind,
        domain: d,
        label:  label,
      }, "denied");
    }
    return verdict;
  }

  var tcpServer    = null;
  var listening    = false;
  var connections  = new Set();

  function _emit(action, metadata, outcome) {
    try {
      audit().safeEmit({
        action:   action,
        outcome:  outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  function _handleConnection(rawSocket) {
    var remoteAddress = rawSocket.remoteAddress || "0.0.0.0";
    var admit = rateLimit.admitConnection(remoteAddress);
    if (!admit.ok) {
      // 421 4.7.0 — transient; sender retries elsewhere.
      _emit("mail.server.submission.rate_limit_refused",
        { remoteAddress: remoteAddress, reason: admit.reason }, "denied");
      try {
        rawSocket.write("421 4.7.0 Too many connections from your IP\r\n");
      } catch (_e) { /* socket may already be torn down */ }
      try { rawSocket.destroy(); } catch (_e2) { /* idempotent */ }
      return;
    }
    rawSocket.once("close", function () { rateLimit.releaseConnection(remoteAddress); });

    var connectionId = "submitconn-" + bCrypto.generateToken(8);                                      // allow:raw-byte-literal — connection-id length
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

    var lineBuffer = "";
    var bodyCollector = null;
    var inDataBody = false;

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
          _finalizeDataBody(state, socket, body);
          inDataBody = false; bodyCollector = null;
        }
        return;
      }

      lineBuffer += chunk.toString("utf8");
      if (lineBuffer.length > maxLineBytes * 4) {
        _writeReply(socket, REPLY_500_SYNTAX,
          "5.5.6 Line too long (>" + maxLineBytes + " bytes)");
        _closeConnection(socket);
        return;
      }
      var crlf;
      while ((crlf = lineBuffer.indexOf("\r\n")) !== -1) {
        var line = lineBuffer.slice(0, crlf);
        lineBuffer = lineBuffer.slice(crlf + 2);
        _handleCommand(state, socket, line);
        if (inDataBody) return;
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
        guardSmtpCommand.validate(line, { profile: profile, maxLineBytes: maxLineBytes });
      } catch (err) {
        if (err.code === "guard-smtp-command/bare-lf" ||
            err.code === "guard-smtp-command/bare-cr" ||
            err.code === "guard-smtp-command/nul-byte") {
          _emit("mail.server.submission.smtp_smuggling_detected",
            { connectionId: state.id, code: err.code, line: line.slice(0, 200) },                     // allow:raw-byte-literal — audit-log line truncation
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
        var caps = ["PIPELINING", "SIZE " + maxMessageBytes, "8BITMIME", "ENHANCEDSTATUSCODES"];
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
      // CVE-2021-38371 / CVE-2021-33515 defense: clear pre-handshake
      // buffer at upgrade time.
      lineBuffer = ""; bodyCollector = null; inDataBody = false;
      var tlsSocket = new nodeTls.TLSSocket(socket, {
        isServer: true, secureContext: opts.tlsContext,
      });
      tlsSocket.on("secure", function () {
        state.tls = true; state.stage = "ehlo"; state.helo = null;
        // Authenticated state SURVIVES STARTTLS upgrade — credentials
        // verified pre-STARTTLS under permissive remain valid post-
        // STARTTLS. Operator opts down to permissive only with this
        // tradeoff acknowledged.
      });
      tlsSocket.on("error", function (err) {
        _emit("mail.server.submission.tls_handshake_failed",
          { connectionId: state.id, code: (err && err.code) || "unknown" }, "failure");
        _closeConnection(socket);
      });
      tlsSocket.on("data", function (chunk) {
        try { _ingestBytes(state, tlsSocket, chunk); }
        catch (err) {
          _emit("mail.server.submission.handler_threw",
            { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
          _closeConnection(tlsSocket);
        }
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
            state.authenticated = true;
            state.actor         = result.actor;
            state.authPending   = null;
            _emit("mail.server.submission.auth_success", {
              connectionId: state.id,
              mechanism:    state.authPending && state.authPending.mechanism,
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
      // an entry in the authenticated actor's mailbox set.
      if (state.authenticated && identityBinding === "strict") {
        var allowed = _actorMailboxes(state.actor);
        if (allowed.length > 0 && allowed.indexOf(mailFrom) === -1) {
          _emit("mail.server.submission.identity_mismatch", {
            connectionId: state.id, authIdentity: state.actor.id || null,
            mailFrom: mailFrom, allowed: allowed,
          }, "denied");
          _writeReply(socket, REPLY_553_SENDER_REJECTED,
            "5.7.1 Sender address rejected: not owned by authenticated identity");
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

    function _finalizeDataBody(state, socket, body) {
      var dedotted = safeSmtp.dotUnstuff(body);
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
          rcptCount: state.rcpts.length, sizeBytes: dedotted.length });
      _writeReply(socket, REPLY_250_OK, "2.6.0 Message queued (audit-only)");
      _resetTransaction(state);
    }

    function _resetTransaction(state) {
      state.mailFrom     = null;
      state.rcpts        = [];
      state.rcptsPending = 0;
      state.stage        = "ehlo";
    }
  }

  async function listen(listenOpts) {
    listenOpts = listenOpts || {};
    if (listening) {
      throw new MailServerSubmissionError("mail-server-submission/already-listening",
        "listen: already listening");
    }
    // Port 0 (ephemeral, test mode) must NOT fall back to the protocol
    // default — the `|| <default>` short-circuit was a footgun on the
    // test path.
    var defaultPort = implicitTls ? 465 : 587;                                                        // allow:raw-byte-literal — RFC 8314 implicit-TLS / RFC 6409 submission ports
    var port    = listenOpts.port    === undefined ? defaultPort : listenOpts.port;
    var address = listenOpts.address || "0.0.0.0";
    tcpServer = net.createServer(function (socket) { _handleConnection(socket); });
    return new Promise(function (resolve, reject) {
      tcpServer.once("error", reject);
      tcpServer.listen(port, address, function () {
        listening = true;
        tcpServer.removeListener("error", reject);
        _emit("mail.server.submission.listening",
          { port: port, address: address, implicitTls: implicitTls });
        resolve({ port: tcpServer.address().port, address: address });
      });
    });
  }

  async function close(closeOpts) {
    closeOpts = closeOpts || {};
    if (!listening) return;
    var timeoutMs = closeOpts.timeoutMs || C.TIME.seconds(30);
    listening = false;
    tcpServer.close();
    connections.forEach(function (sock) {
      try { _writeReply(sock, REPLY_421_SERVICE_NOT_AVAIL, "4.3.0 Server shutting down"); }
      catch (_e) { /* socket already gone */ }
    });
    var deadline = Date.now() + timeoutMs;
    while (connections.size > 0 && Date.now() < deadline) {
      await safeAsync.sleep(100);                                                                    // allow:raw-time-literal — sub-second drain poll
    }
    connections.forEach(function (sock) {
      try { sock.destroy(); } catch (_e) { /* best-effort */ }
    });
    connections.clear();
    _emit("mail.server.submission.closed", {});
  }

  function connectionCount() { return connections.size; }

  return {
    listen:           listen,
    close:            close,
    connectionCount:  connectionCount,
    _portForTest:     function () { return tcpServer ? tcpServer.address().port : null; },
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

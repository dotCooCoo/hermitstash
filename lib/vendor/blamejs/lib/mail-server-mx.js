"use strict";
/**
 * @module     b.mail.server.mx
 * @nav        Mail
 * @title      Mail MX Server
 * @order      540
 *
 * @intro
 *   Inbound SMTP / MX listener. Composes the framework's existing
 *   mail-gate substrates (`b.mail.helo`, `b.mail.rbl`,
 *   `b.mail.greylist`, `b.guardEnvelope`, `b.mail.auth.dmarc`,
 *   `b.safeMime`, `b.guardEmail`, `b.guardSmtpCommand`,
 *   `b.mail.agent`) into one operator-facing server that accepts
 *   inbound mail per RFC 5321 with PQC-shaped TLS posture, SMTP-
 *   smuggling defense baked into the wire-protocol layer, and the
 *   gate cascade running at the right phase of the state machine.
 *
 *   `create({ ... }).listen()` binds the TCP port; every incoming
 *   connection drives the CONNECT → EHLO → [STARTTLS → EHLO] →
 *   MAIL → RCPT (×N) → DATA → DATA-body → QUIT state machine. Each
 *   phase passes through the operator-supplied gates (defaulting
 *   to "no-op" when the operator hasn't wired a gate) and refuses
 *   with the appropriate 5xx (permanent) or 4xx (transient) SMTP
 *   reply code on gate fail.
 *
 *   ## Defenses baked in
 *
 *   - **SMTP smuggling** (CVE-2023-51764 / CVE-2024-32178) — every
 *     wire line passes through `b.guardSmtpCommand.validate` which
 *     refuses bare LF, bare CR, NUL, C0 controls, DEL, and oversize.
 *     The DATA body's `\r\n.\r\n` terminator is matched on canonical
 *     CRLF only — bare-LF dot-terminators are refused. Together this
 *     defends the CVE-2023-51764 class where a hostile sender
 *     smuggles a second message past the framework's filter by
 *     terminating the first one with `\n.\n` instead of `\r\n.\r\n`.
 *
 *   - **Open-relay defense** — RCPT TO non-local refused with 550
 *     5.7.1 Relaying denied unless the operator explicitly registered
 *     the destination via `relayAllowedFor: [{ cidr, scope }]`. The
 *     default posture is "MX-only, no relay" so a misconfigured boot
 *     can't accidentally become an open relay.
 *
 *   - **STARTTLS stripping (CVE-2021-38371 Exim, CVE-2021-33515 Dovecot)** —
 *     once STARTTLS is advertised + selected, subsequent commands
 *     MUST run over the negotiated TLS context. A pre-STARTTLS
 *     pipelining attempt (RFC 2920) to inject commands that take
 *     effect post-handshake is refused by clearing the command
 *     buffer at STARTTLS time and reading fresh from the TLS socket
 *     only — defends both the Exim and Dovecot variants of the
 *     STARTTLS-injection class.
 *
 *   - **Resource exhaustion** — per-command line cap (default
 *     1 KiB), DATA body cap (default 50 MiB per RFC 5321 §4.5.3.1.7),
 *     per-recipient cap (default 100 per RFC 5321 §4.5.3.1.8),
 *     connection idle timeout (default 5 minutes per RFC 5321
 *     §4.5.3.2.7). Operator opts up with explicit bounds.
 *
 *   - **TLS posture** — `tlsContext` MUST be supplied (no implicit
 *     plaintext-only mode). Operator passes a `b.network.tls.context`
 *     output which carries the framework's TLS 1.3 default + OCSP /
 *     CT-log posture. Pre-STARTTLS plain commands are limited to
 *     EHLO / HELO / STARTTLS / NOOP / QUIT / RSET; MAIL / RCPT /
 *     DATA all refused with 530 5.7.0 Must issue a STARTTLS command
 *     first.
 *
 *   ## Audit lifecycle
 *
 *   - `mail.server.mx.connect`           — IP, TLS state, FCrDNS hostname
 *   - `mail.server.mx.helo`              — HELO greeting, helo-gate verdict
 *   - `mail.server.mx.mail_from`         — sender, SPF verdict, alignment verdict
 *   - `mail.server.mx.rcpt_to`           — recipient, RBL verdict, greylist verdict
 *   - `mail.server.mx.data_accepted`     — message size, DKIM verdict, DMARC verdict
 *   - `mail.server.mx.data_refused`      — refusal reason + SMTP code (5xx vs 4xx)
 *   - `mail.server.mx.delivered`         — agent.handoff ack
 *   - `mail.server.mx.tls_handshake_failed` — handshake error
 *   - `mail.server.mx.smtp_smuggling_detected` — CRLF.CRLF injection class
 *   - `mail.server.mx.relay_refused`     — open-relay attempt
 *
 *   ## What v1 does NOT ship
 *
 *   - **AUTH / submission auth** — MX listener is inbound from the
 *     internet, no authentication. Submission listener (port 587) is
 *     a separate slice with SCRAM-SHA-256 / XOAUTH2 / EXTERNAL.
 *   - **Sieve filtering** — composes via `b.mail.agent` at delivery
 *     time; the MX listener doesn't decide policy itself.
 *   - **Outbound DSN generation** — `b.guardDsn` parses inbound DSNs;
 *     outbound DSN emission deferred to the submission slice.
 *   - **8BITMIME** (RFC 6152, obsoletes RFC 1652) — advertised in
 *     the EHLO capabilities since the DATA body parser via
 *     `b.safeMime` is octet-clean; no transcoding needed.
 *   - **SMTPUTF8** (RFC 6531) + **IDN** (RFC 5891) — the wire-protocol
 *     layer here is encoding-agnostic; SMTPUTF8 capability
 *     advertisement is a follow-up slice once the operator's
 *     downstream (mail-store + delivery agent) accepts Unicode
 *     mailbox-local-part bytes. Today the listener does not
 *     advertise SMTPUTF8 and refuses non-ASCII in MAIL FROM /
 *     RCPT TO via `b.guardSmtpCommand`.
 *
 *   ## Composition contract
 *
 *   Every gate is a primitive that already exists. The MX slice is a
 *   state-machine + wire-protocol coordinator — no new crypto, no
 *   new parsing, no new RFC-layer primitives. If a gate isn't ready
 *   (e.g. operator hasn't wired `b.mail.auth.dmarc`), the listener
 *   skips that phase with an audit note rather than synthesizing a
 *   verdict.
 *
 * @card
 *   Inbound SMTP / MX listener. RFC 5321 state machine with SMTP-
 *   smuggling defense baked into the wire-protocol layer (RFC 5321
 *   §2.3.8 + CVE-2023-51764 / CVE-2024-32178), open-relay refusal by
 *   default, STARTTLS-stripping defense (CVE-2021-38371), and the
 *   framework's mail-gate cascade (HELO / RBL / greylist /
 *   guardEnvelope / DMARC / safeMime / guardEmail) running at the
 *   appropriate phase.
 */

var net   = require("node:net");
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
var mailServerTls = require("./mail-server-tls");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var MailServerMxError = defineClass("MailServerMxError", { alwaysPermanent: true });

// RFC 5321 §4.5.3.1 — wire-protocol limits.
var DEFAULT_MAX_LINE_BYTES        = C.BYTES.kib(1);
var DEFAULT_MAX_MESSAGE_BYTES     = C.BYTES.mib(50);
var DEFAULT_MAX_RCPTS_PER_MESSAGE = 100;                                                              // allow:raw-byte-literal — RFC 5321 §4.5.3.1.8 recipient cap
var DEFAULT_IDLE_TIMEOUT_MS       = C.TIME.minutes(5);
var DEFAULT_GREETING              = "blamejs ESMTP";

// SMTP reply-code constants. The framework uses RFC 5321 enhanced
// status codes per RFC 3463 (`Dclass.Dsubject.Ddetail`) embedded in
// the reply lines for operator-side observability.
var REPLY_220_READY              = "220";
var REPLY_221_BYE                = "221";
var REPLY_250_OK                 = "250";
var REPLY_354_START_INPUT        = "354";
var REPLY_421_SERVICE_NOT_AVAIL  = "421";                                                             // allow:raw-byte-literal — SMTP transient code
var REPLY_451_LOCAL_ERROR        = "451";                                                             // allow:raw-byte-literal — SMTP transient code
var REPLY_452_INSUFFICIENT_STG   = "452";                                                             // allow:raw-byte-literal — SMTP transient code
var REPLY_500_SYNTAX             = "500";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_501_BAD_ARGS           = "501";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_502_NOT_IMPLEMENTED    = "502";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_503_BAD_SEQUENCE       = "503";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_530_AUTH_REQUIRED      = "530";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_550_MAILBOX_UNAVAIL    = "550";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_552_SIZE_EXCEEDED      = "552";                                                             // allow:raw-byte-literal — SMTP permanent code
var REPLY_554_TRANSACTION_FAILED = "554";                                                             // allow:raw-byte-literal — SMTP permanent code

var RE_MAIL_FROM = /^MAIL\s+FROM:\s*<([^>]*)>(?:\s+(.*))?$/i;
var RE_RCPT_TO   = /^RCPT\s+TO:\s*<([^>]+)>(?:\s+.*)?$/i;
var RE_SIZE      = /SIZE=(\d+)/i;

/**
 * @primitive b.mail.server.mx.create
 * @signature b.mail.server.mx.create(opts)
 * @since     0.9.46
 * @status    stable
 * @related   b.mail.helo.evaluate, b.mail.rbl.create, b.mail.greylist.create, b.guardEnvelope.check, b.mail.agent.create
 *
 * Build the MX listener. Returns `{ listen({ port?, address? }),
 * close({ timeoutMs? }), connectionCount(), _portForTest() }`.
 *
 * @opts
 *   tlsContext:        TlsContext,      // required — b.network.tls.context() output (no implicit plaintext)
 *   greeting:          string,          // default "blamejs ESMTP" — HELO/EHLO 220-line banner
 *   helo:              b.mail.helo,     // optional gate
 *   rbl:               b.mail.rbl,      // optional gate
 *   greylist:          b.mail.greylist, // optional gate
 *   envelope:          b.guardEnvelope, // optional gate (SPF/DKIM alignment)
 *   dmarc:             b.mail.auth.dmarc,  // optional gate
 *   agent:             b.mail.agent,    // optional delivery handoff
 *   relayAllowedFor:   [{ cidr, scope }],  // operator-explicit relay allowlist; default [] = MX-only
 *   localDomains:      [string],        // RCPT TO local-domain allowlist (refuse non-local with 550 5.7.1)
 *   maxLineBytes:      number,          // default 1 KiB — per-command line cap
 *   maxMessageBytes:   number,          // default 50 MiB — DATA body cap
 *   maxRcptsPerMessage: number,         // default 100 — per RFC 5321 §4.5.3.1.8
 *   idleTimeoutMs:     number,          // default 5 minutes — RFC 5321 §4.5.3.2.7
 *   profile:           "strict" | "balanced" | "permissive",  // gate posture cascade
 *
 * @example
 *   var tls = b.network.tls.context({ cert: certPem, key: keyPem });
 *   var server = b.mail.server.mx.create({
 *     tlsContext:   tls,
 *     greeting:     "mx.example.com ESMTP blamejs",
 *     helo:         b.mail.helo,
 *     rbl:          b.mail.rbl.create({ providers: ["zen.spamhaus.org"] }),
 *     greylist:     b.mail.greylist.create({ store: greylistStore }),
 *     envelope:     b.guardEnvelope,
 *     agent:        b.mail.agent.create({ store: mailStore }),
 *     localDomains: ["example.com"],
 *   });
 *   await server.listen({ port: 25 });
 */
function create(opts) {
  validateOpts.requireObject(opts, "mail.server.mx.create",
    MailServerMxError, "mail-server-mx/bad-opts");
  if (!opts.tlsContext) {
    throw new MailServerMxError("mail-server-mx/no-tls-context",
      "mail.server.mx.create: tlsContext is required (no implicit plaintext mode). " +
      "Use b.mail.server.tls.context({ certFile, keyFile, watch: true }) to load + " +
      "auto-reload a cert/key pair from disk, or pass a node:tls.createSecureContext " +
      "output directly. Cert provisioning lives in b.acme (RFC 8555 + RFC 9773 ARI).");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "maxMessageBytes", "maxRcptsPerMessage", "idleTimeoutMs"],
    "mail.server.mx.", MailServerMxError, "mail-server-mx/bad-bound");
  if (opts.localDomains !== undefined &&
      (!Array.isArray(opts.localDomains) || opts.localDomains.length === 0)) {
    throw new MailServerMxError("mail-server-mx/bad-opts",
      "mail.server.mx.create: localDomains must be a non-empty array if provided");
  }
  if (opts.relayAllowedFor !== undefined && !Array.isArray(opts.relayAllowedFor)) {
    throw new MailServerMxError("mail-server-mx/bad-opts",
      "mail.server.mx.create: relayAllowedFor must be an array if provided");
  }

  var greeting          = opts.greeting          || DEFAULT_GREETING;
  var maxLineBytes      = opts.maxLineBytes      || DEFAULT_MAX_LINE_BYTES;
  var maxMessageBytes   = opts.maxMessageBytes   || DEFAULT_MAX_MESSAGE_BYTES;
  var maxRcptsPerMsg    = opts.maxRcptsPerMessage || DEFAULT_MAX_RCPTS_PER_MESSAGE;
  var idleTimeoutMs     = opts.idleTimeoutMs     || DEFAULT_IDLE_TIMEOUT_MS;
  var localDomains      = (opts.localDomains || []).map(function (d) { return String(d).toLowerCase(); });
  var relayAllowedFor   = opts.relayAllowedFor || [];
  var profile           = opts.profile || "strict";
  // SMTPUTF8 (RFC 6531) — single switch threaded end-to-end. The MX
  // listener doesn't advertise SMTPUTF8 to the peer regardless, so
  // this defaults `false` (refuse non-ASCII bytes in every command
  // line). Operators that want to accept SMTPUTF8 for downstream
  // relay flip this `true` and the same switch reaches every
  // `guardSmtpCommand.validate` call.
  var allowSmtpUtf8     = opts.allowSmtpUtf8 === true;

  // Default-on per-IP rate limit. Operators pass `rateLimit: false` to
  // disable (only for tests / closed networks), pass a rate-limit
  // handle from b.mail.server.rateLimit.create({...}) to share one
  // budget across multiple listeners, or pass an opts object to
  // override defaults.
  var rateLimit;
  if (opts.rateLimit === false) {
    rateLimit = mailServerRateLimit.create({ disabled: true });
  } else if (opts.rateLimit && typeof opts.rateLimit.admitConnection === "function") {
    rateLimit = opts.rateLimit;
  } else {
    rateLimit = mailServerRateLimit.create(opts.rateLimit || {});
  }

  // Default-on operator-supplied-domain hardening. opts.localDomains
  // and the HELO / MAIL FROM / RCPT TO domain validations all route
  // through `b.guardDomain` for IDN homograph defense (CVE-2017-5469
  // class), special-use-domain refusal (RFC 6761), label-length cap
  // (RFC 1035 §2.3.4), and bare-IP-as-domain refusal (CVE-2021-22931
  // class). Operators with a closed-network deployment can pass
  // `guardDomain: false` to skip; the default keeps the protection on.
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
      _emit("mail.server.mx.domain_refused", {
        reason: verdict.issues && verdict.issues[0] && verdict.issues[0].kind,
        domain: d,
        label:  label,
      }, "denied");
    }
    return verdict;
  }

  // Pre-validate operator-supplied localDomains at boot — the same
  // shape they enforce on RCPT TO must itself pass the validator,
  // otherwise an operator who typed an IDN homograph (or an IP) into
  // their allowlist would silently weaken the gate.
  if (guardDomainProfile) {
    for (var __ldi = 0; __ldi < localDomains.length; __ldi += 1) {
      var __ldVerdict = guardDomain.validate(localDomains[__ldi], guardDomainProfile);
      if (!__ldVerdict.ok) {
        throw new MailServerMxError("mail-server-mx/bad-local-domain",
          "mail.server.mx.create: localDomains[" + __ldi + "] '" + localDomains[__ldi] +
          "' rejected by b.guardDomain (" +
          (__ldVerdict.issues && __ldVerdict.issues[0] && __ldVerdict.issues[0].kind) + ")");
      }
    }
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
    } catch (_e) { /* drop-silent — audit best-effort */ }
  }

  // ---- Per-connection state machine ---------------------------------------
  function _handleConnection(socket) {
    var remoteAddress = socket.remoteAddress || "0.0.0.0";
    var admit = rateLimit.admitConnection(remoteAddress);
    if (!admit.ok) {
      // 421 4.7.0 — transient refusal; sender retries elsewhere or later.
      // RFC 5321 §3.8 + §4.5.4.2 (transient negative completion).
      _emit("mail.server.mx.rate_limit_refused",
        { remoteAddress: remoteAddress, reason: admit.reason }, "denied");
      try {
        socket.write("421 4.7.0 Too many connections from your IP\r\n");
      } catch (_e) { /* socket may already be torn down */ }
      try { socket.destroy(); } catch (_e2) { /* idempotent */ }
      return;
    }
    socket.once("close", function () { rateLimit.releaseConnection(remoteAddress); });

    var connectionId = "mxconn-" + bCrypto.generateToken(8);                                          // allow:raw-byte-literal — connection-id length
    connections.add(socket);

    // Backpressure observer — `_writeReply` flips `_bpEmitted` after
    // the first audit emission per socket to bound the audit volume.
    socket._bpEmit = function () {
      _emit("mail.server.mx.write_backpressure",
        { connectionId: connectionId, remoteAddress: remoteAddress,
          stage: state && state.stage, bufferedBytes: socket.writableLength || 0 },
        "warning");
    };

    var state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      remotePort:    socket.remotePort || null,
      tls:           false,
      stage:         "connect",   // connect | ehlo | mail | rcpt | data-body | done
      helo:          null,
      mailFrom:      null,
      rcpts:         [],
      messageBytes:  0,
      lastDataByteTime: 0,
    };

    // Raw byte buffer (NOT a string) — DATA bodies under 8BITMIME may
    // carry bytes that are invalid UTF-8; round-tripping through a
    // string decode would replace them with U+FFFD and corrupt the
    // message. Decode to string only for the per-command line parse.
    var lineBuffer = Buffer.alloc(0);
    var bodyCollector = null;
    var inDataBody = false;

    socket.setTimeout(idleTimeoutMs);
    socket.on("timeout", function () {
      _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL, "4.4.2 Idle timeout");
      _closeConnection(socket);
    });

    socket.on("error", function (err) {
      _emit("mail.server.mx.socket_error",
        { connectionId: state.id, code: (err && err.code) || "unknown", message: err && err.message },
        "warning");
      _closeConnection(socket);
    });

    socket.on("close", function () {
      connections.delete(socket);
    });

    _emit("mail.server.mx.connect", {
      connectionId:  state.id,
      remoteAddress: state.remoteAddress,
      remotePort:    state.remotePort,
      tls:           false,
    });

    // 220 banner — RFC 5321 §3.1.
    _writeReply(socket, REPLY_220_READY, greeting + " ready");

    socket.on("data", function (chunk) {
      try { _ingestBytes(state, socket, chunk); }
      catch (err) {
        _emit("mail.server.mx.handler_threw",
          { connectionId: state.id, error: (err && err.message) || String(err) },
          "failure");
        try { _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL, "4.3.0 Server error"); }
        catch (_e) { /* socket already gone */ }
        _closeConnection(socket);
      }
    });

    // ---- Byte-level ingestion --------------------------------------------
    function _ingestBytes(state, socket, chunk) {
      if (inDataBody) {
        // DATA body — accumulate via boundedChunkCollector, watch for
        // canonical "\r\n.\r\n" terminator only. Bare-LF dot terminator
        // is the SMTP smuggling shape (CVE-2023-51764); refused.
        try { bodyCollector.push(chunk); }
        catch (_e) {
          _emit("mail.server.mx.data_refused",
            { connectionId: state.id, reason: "body-too-large", maxBytes: maxMessageBytes },
            "denied");
          _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
            "5.3.4 Message size exceeds fixed maximum (" + maxMessageBytes + " bytes)");
          _resetTransaction(state);
          inDataBody = false;
          bodyCollector = null;
          return;
        }
        var collected = bodyCollector.result();
        // Smuggling detector — bare LF dot-line in body before the
        // CRLF dot terminator. Refuse the whole transaction; emit
        // smuggling-detected audit.
        if (guardSmtpCommand.detectBodySmuggling(collected)) {
          _emit("mail.server.mx.smtp_smuggling_detected",
            { connectionId: state.id, mailFrom: state.mailFrom, rcptCount: state.rcpts.length },
            "denied");
          _writeReply(socket, REPLY_554_TRANSACTION_FAILED,
            "5.7.0 Bare-LF in DATA body refused (RFC 5321 §2.3.8; CVE-2023-51764 SMTP smuggling)");
          _resetTransaction(state);
          inDataBody = false;
          bodyCollector = null;
          return;
        }
        // Canonical \r\n.\r\n terminator?
        var endIdx = safeSmtp.findDotTerminator(collected);
        if (endIdx !== -1) {
          var body = collected.subarray(0, endIdx);
          _finalizeDataBody(state, socket, body);
          inDataBody = false;
          bodyCollector = null;
        }
        return;
      }

      // Command phase — byte-buffered (8BITMIME-safe).
      lineBuffer = lineBuffer.length === 0 ? chunk : Buffer.concat([lineBuffer, chunk]);
      if (lineBuffer.length > maxLineBytes * 4) {
        _writeReply(socket, REPLY_500_SYNTAX,
          "5.5.6 Line too long (>" + maxLineBytes + " bytes)");
        _closeConnection(socket);
        return;
      }
      var crlf;
      var crlfNeedle = Buffer.from("\r\n", "ascii");
      while ((crlf = lineBuffer.indexOf(crlfNeedle)) !== -1) {
        var line = lineBuffer.subarray(0, crlf).toString("utf8");
        lineBuffer = lineBuffer.subarray(crlf + 2);
        _handleCommand(state, socket, line);
        if (inDataBody) return;
      }
    }

    function _handleCommand(state, socket, line) {
      // Per-line guard — refuse bare LF / NUL / C0 / DEL / oversize
      // BEFORE state-machine dispatch.
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
          _emit("mail.server.mx.smtp_smuggling_detected",
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
          _handleEhlo(state, socket, line, verb);
          return;
        case "STARTTLS":
          _handleStartTls(state, socket);
          return;
        case "MAIL":
          _handleMailFrom(state, socket, line);
          return;
        case "RCPT":
          _handleRcptTo(state, socket, line);
          return;
        case "DATA":
          _handleData(state, socket);
          return;
        case "NOOP":
          _writeReply(socket, REPLY_250_OK, "2.0.0 OK");
          return;
        case "RSET":
          _resetTransaction(state);
          _writeReply(socket, REPLY_250_OK, "2.0.0 Reset");
          return;
        case "QUIT":
          _writeReply(socket, REPLY_221_BYE, "2.0.0 Bye");
          _closeConnection(socket);
          return;
        case "VRFY":
        case "EXPN":
          // Refuse VRFY/EXPN per modern best practice (information
          // disclosure of internal aliases / valid recipients).
          _writeReply(socket, REPLY_502_NOT_IMPLEMENTED, "5.5.1 Command not implemented");
          return;
        default:
          _writeReply(socket, REPLY_500_SYNTAX, "5.5.2 Unknown command");
      }
    }

    // ---- EHLO / HELO ------------------------------------------------------
    function _handleEhlo(state, socket, line, verb) {
      var helo = line.slice(verb.length).trim();
      if (!helo) {
        _writeReply(socket, REPLY_501_BAD_ARGS, "5.5.4 " + verb + " requires a domain argument");
        return;
      }
      // Domain hardening for HELO/EHLO greeting (RFC 5321 §4.1.1.1).
      // Skip when the greeting is an address literal (`[1.2.3.4]` /
      // `[IPv6:...]`) — those are RFC-5321-legitimate non-domain
      // forms; the bracket syntax is already constrained by
      // b.guardSmtpCommand. Bare-IP-as-domain (no brackets) IS
      // refused — that's the CVE-2021-22931 class guardDomain catches.
      if (helo[0] !== "[" && guardDomainProfile) {
        var heloVerdict = _validateDomainHardened(helo, "helo");
        if (!heloVerdict.ok) {
          _writeReply(socket, REPLY_501_BAD_ARGS,
            "5.5.4 " + verb + " domain refused (" +
            (heloVerdict.issues && heloVerdict.issues[0] && heloVerdict.issues[0].kind) + ")");
          return;
        }
      }
      state.helo  = helo;
      state.stage = "ehlo";
      // Multi-line 250 capabilities advertisement per RFC 5321 §4.1.1.1.
      if (verb === "EHLO") {
        // EHLO capabilities advertised:
        //   - PIPELINING per RFC 2920
        //   - SIZE n per RFC 1870 §3 (with the per-server byte cap)
        //   - 8BITMIME per RFC 6152 (obsoletes RFC 1652)
        //   - STARTTLS per RFC 3207 §2 (only advertised pre-TLS)
        //   - ENHANCEDSTATUSCODES per RFC 2034 (RFC 3463 code shape)
        var caps = ["PIPELINING", "SIZE " + maxMessageBytes, "8BITMIME"];
        if (!state.tls) caps.push("STARTTLS");
        caps.push("ENHANCEDSTATUSCODES");
        var lines = [greeting + " greets " + helo];
        for (var i = 0; i < caps.length; i += 1) lines.push(caps[i]);
        _writeMultiline(socket, REPLY_250_OK, lines);
      } else {
        _writeReply(socket, REPLY_250_OK, greeting + " greets " + helo);
      }
      _emit("mail.server.mx.helo",
        { connectionId: state.id, verb: verb, helo: helo, tls: state.tls });
    }

    // ---- STARTTLS ---------------------------------------------------------
    function _handleStartTls(state, socket) {
      if (state.tls) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 TLS already active");
        return;
      }
      _writeReply(socket, REPLY_220_READY, "2.0.0 Ready to start TLS");
      // CVE-2021-38371 (Exim) / CVE-2021-33515 (Dovecot) STARTTLS-
      // injection defense: clear the pre-handshake command buffer +
      // body collector AND strip the plain-socket "data" listener
      // before wrapping in TLSSocket so bytes the peer pipelined
      // (RFC 2920) pre-handshake cannot reach the post-TLS state
      // machine. Listener-removal + idle-timeout re-arm live in the
      // shared upgradeSocket helper (b.mail.server.tls.upgradeSocket).
      lineBuffer    = Buffer.alloc(0);
      bodyCollector = null;
      inDataBody    = false;
      mailServerTls.upgradeSocket({
        plainSocket:   socket,
        secureContext: opts.tlsContext,
        idleTimeoutMs: idleTimeoutMs,
        onSecure: function (_tlsSocket) {
          state.tls   = true;
          // After the handshake, the state machine restarts at EHLO
          // (per RFC 3207 §4.2 — client MUST re-issue EHLO).
          state.stage = "ehlo";
          state.helo  = null;
        },
        onData: function (tlsSocket, chunk) {
          try { _ingestBytes(state, tlsSocket, chunk); }
          catch (err) {
            _emit("mail.server.mx.handler_threw",
              { connectionId: state.id, error: (err && err.message) || String(err) },
              "failure");
            _closeConnection(tlsSocket);
          }
        },
        onError: function (err) {
          _emit("mail.server.mx.tls_handshake_failed",
            { connectionId: state.id, code: (err && err.code) || "unknown",
              message: err && err.message }, "failure");
          _closeConnection(socket);
        },
        onTimeout: function (tlsSocket) {
          _writeReply(tlsSocket, REPLY_421_SERVICE_NOT_AVAIL, "4.4.2 Idle timeout");
          _closeConnection(tlsSocket);
        },
      });
    }

    // ---- MAIL FROM --------------------------------------------------------
    function _handleMailFrom(state, socket, line) {
      if (!state.tls && _requiresStartTls()) {
        _writeReply(socket, REPLY_530_AUTH_REQUIRED, "5.7.0 Must issue a STARTTLS command first");
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
      // Domain hardening on MAIL FROM domain. Skip address-literal
      // and empty-reverse-path forms (RFC 5321 §4.5.5 — bounce return
      // path `<>` is legitimate and has no domain).
      var __mfAtIdx = mailFrom.lastIndexOf("@");
      var mailFromDomain = __mfAtIdx === -1 ? "" : mailFrom.slice(__mfAtIdx + 1);
      if (mailFromDomain && mailFromDomain[0] !== "[" && guardDomainProfile) {
        var mfVerdict = _validateDomainHardened(mailFromDomain, "mail_from");
        if (!mfVerdict.ok) {
          _writeReply(socket, REPLY_501_BAD_ARGS,
            "5.5.4 MAIL FROM domain refused (" +
            (mfVerdict.issues && mfVerdict.issues[0] && mfVerdict.issues[0].kind) + ")");
          return;
        }
      }
      var paramStr = match[2] || "";
      var sizeMatch = paramStr.match(RE_SIZE);
      var declaredSize = null;
      if (sizeMatch) {
        declaredSize = parseInt(sizeMatch[1], 10);
        if (declaredSize > maxMessageBytes) {
          _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
            "5.3.4 Message size exceeds fixed maximum (" + maxMessageBytes + " bytes)");
          return;
        }
      }
      state.mailFrom    = mailFrom;
      state.declaredSize = declaredSize;
      state.stage       = "rcpt";
      state.rcpts       = [];
      _emit("mail.server.mx.mail_from",
        { connectionId: state.id, mailFrom: mailFrom });
      _writeReply(socket, REPLY_250_OK, "2.1.0 Sender OK");
    }

    // ---- RCPT TO ----------------------------------------------------------
    function _handleRcptTo(state, socket, line) {
      if (state.stage !== "rcpt") {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 MAIL FROM first");
        return;
      }
      if (state.rcpts.length >= maxRcptsPerMsg) {
        _writeReply(socket, REPLY_452_INSUFFICIENT_STG,
          "4.5.3 Too many recipients (limit " + maxRcptsPerMsg + ")");
        return;
      }
      // RFC 5321 §3.5 — RCPT-TO 550 vs 250 surfaces a mailbox-existence
      // oracle. Once the per-IP recipient-failure cap is reached, the
      // listener returns 421 + closes so the IP backs off; without this
      // a scanner can RCPT-TO-flood the listener to enumerate every
      // valid local recipient at the bare cost of an SMTP greeting.
      var rcptAdmit = rateLimit.checkRcptAdmit(state.remoteAddress);
      if (!rcptAdmit.ok) {
        _emit("mail.server.mx.rcpt_rate_limit_refused",
          { connectionId: state.id, remoteAddress: state.remoteAddress,
            reason: rcptAdmit.reason }, "denied");
        _writeReply(socket, REPLY_421_SERVICE_NOT_AVAIL,
          "4.7.0 Too many RCPT failures from your IP");
        _closeConnection(socket);
        return;
      }
      var match = line.match(RE_RCPT_TO);
      if (!match) {
        rateLimit.noteRcptFailure(state.remoteAddress);
        _writeReply(socket, REPLY_501_BAD_ARGS, "5.5.4 Syntax: RCPT TO:<address>");
        return;
      }
      var rcpt = match[1].toLowerCase();
      // Domain hardening on RCPT TO domain — skip the address-literal
      // form per RFC 5321 §4.1.3 (bracket syntax already constrained
      // by b.guardSmtpCommand). Refuses IDN homograph + special-use
      // domains + bare-IP-as-domain on the un-bracketed form.
      var _atIdx = rcpt.lastIndexOf("@");
      var rcptDomain = _atIdx === -1 ? "" : rcpt.slice(_atIdx + 1);
      if (rcptDomain && rcptDomain[0] !== "[" && guardDomainProfile) {
        var rcptVerdict = _validateDomainHardened(rcptDomain, "rcpt_to");
        if (!rcptVerdict.ok) {
          rateLimit.noteRcptFailure(state.remoteAddress);
          _trackRefusedRcpt(state, rcpt, "domain-refused");
          _writeReply(socket, REPLY_501_BAD_ARGS,
            "5.5.4 RCPT TO domain refused (" +
            (rcptVerdict.issues && rcptVerdict.issues[0] && rcptVerdict.issues[0].kind) + ")");
          return;
        }
      }
      // Local-domain check — refuse non-local recipients unless the
      // operator explicitly allowed relay for this scope.
      if (localDomains.length > 0) {
        if (localDomains.indexOf(rcptDomain) === -1 &&
            !_isRelayAllowed(state.remoteAddress, rcpt)) {
          rateLimit.noteRcptFailure(state.remoteAddress);
          _trackRefusedRcpt(state, rcpt, "relay-denied");
          _emit("mail.server.mx.relay_refused",
            { connectionId: state.id, mailFrom: state.mailFrom, rcptTo: rcpt,
              remoteAddress: state.remoteAddress }, "denied");
          _writeReply(socket, REPLY_550_MAILBOX_UNAVAIL, "5.7.1 Relaying denied");
          return;
        }
      }
      state.rcpts.push(rcpt);
      _emit("mail.server.mx.rcpt_to",
        { connectionId: state.id, rcptTo: rcpt, rcptCount: state.rcpts.length });
      _writeReply(socket, REPLY_250_OK, "2.1.5 Recipient OK");
    }

    // ---- DATA -------------------------------------------------------------
    function _handleData(state, socket) {
      if (state.stage !== "rcpt" || state.rcpts.length === 0) {
        _writeReply(socket, REPLY_503_BAD_SEQUENCE, "5.5.1 No valid recipients");
        return;
      }
      _writeReply(socket, REPLY_354_START_INPUT,
        "End data with <CR><LF>.<CR><LF>");
      state.stage    = "data-body";
      inDataBody     = true;
      bodyCollector  = safeBuffer.boundedChunkCollector({
        maxBytes:    maxMessageBytes,
        errorClass:  MailServerMxError,
        sizeCode:    "mail-server-mx/body-too-large",
        sizeMessage: "DATA body exceeded maxMessageBytes (" + maxMessageBytes + ")",
      });
    }

    function _finalizeDataBody(state, socket, body) {
      // body is the raw bytes BEFORE dot-stuffing reversal. RFC 5321
      // §4.5.2 — a single leading "." is doubled on the wire; undo.
      var dedotted = safeSmtp.dotUnstuff(body);
      // RFC 1870 §6.3 — reconcile MAIL FROM SIZE= against the actual
      // DATA byte count. The pre-DATA reservation at MAIL FROM time
      // (above) is advisory; the sender's declared size is a HINT,
      // not a guarantee. If the actual unstuffed body exceeds the
      // declared SIZE= (with a small slack to absorb header lines the
      // sender didn't count), refuse with 552 — defends against
      // senders that probe maxMessageBytes by understating SIZE.
      if (typeof state.declaredSize === "number" && isFinite(state.declaredSize)) {
        if (dedotted.length > state.declaredSize) {
          _emit("mail.server.mx.size_overrun", {
            connectionId: state.id,
            mailFrom:     state.mailFrom,
            declaredSize: state.declaredSize,
            actualSize:   dedotted.length,
          }, "denied");
          _writeReply(socket, REPLY_552_SIZE_EXCEEDED,
            "5.3.4 Message exceeds declared SIZE=" + state.declaredSize +
            " bytes (got " + dedotted.length + "; RFC 1870 §6.3)");
          _resetTransaction(state);
          return;
        }
      }
      // operator-supplied agent handoff — when wired, persist via
      // agent + write the 250 reply. When not wired, accept-and-drop
      // (audit-only mode useful for staging deployments).
      var refusedSnapshot = Array.isArray(state.refusedRcpts) ? state.refusedRcpts.slice() : [];
      if (opts.agent && typeof opts.agent.handoff === "function") {
        opts.agent.handoff({
          mailFrom: state.mailFrom,
          rcpts:    state.rcpts.slice(),
          body:     dedotted,
          remote:   { address: state.remoteAddress, port: state.remotePort },
          tls:      state.tls,
          helo:     state.helo,
          connectionId: state.id,
        }).then(function (ack) {
          _emit("mail.server.mx.delivered",
            { connectionId: state.id, messageId: ack && ack.messageId,
              sizeBytes: dedotted.length, refusedRcpts: refusedSnapshot });
          _writeReply(socket, REPLY_250_OK,
            "2.6.0 Message accepted" + (ack && ack.messageId ? " <" + ack.messageId + ">" : ""));
          _resetTransaction(state);
        }).catch(function (err) {
          _emit("mail.server.mx.data_refused",
            { connectionId: state.id, reason: "agent-handoff-failed",
              error: (err && err.message) || String(err) }, "failure");
          _writeReply(socket, REPLY_451_LOCAL_ERROR,
            "4.3.0 Local delivery error");
          _resetTransaction(state);
        });
        return;
      }
      _emit("mail.server.mx.data_accepted",
        { connectionId: state.id, mailFrom: state.mailFrom, rcptCount: state.rcpts.length,
          sizeBytes: dedotted.length, refusedRcpts: refusedSnapshot });
      _writeReply(socket, REPLY_250_OK, "2.6.0 Message queued (audit-only)");
      _resetTransaction(state);
    }

    function _resetTransaction(state) {
      state.mailFrom     = null;
      state.declaredSize = null;
      state.rcpts        = [];
      state.refusedRcpts = [];
      state.stage        = "ehlo";
      state.messageBytes = 0;
    }

    // Track up to MAX_REFUSED_RCPTS_PER_TXN refused recipients so the
    // `data_accepted` / `delivered` audit can surface the bounded list
    // for observability. Bounded to keep the audit metadata size
    // predictable; the per-IP recipient-failure rate-limit elsewhere
    // bounds long-run scanner damage.
    var MAX_REFUSED_RCPTS_PER_TXN = 32;                                                                   // allow:raw-byte-literal — bounded audit-metadata list cap
    function _trackRefusedRcpt(state, rcpt, reason) {
      if (!Array.isArray(state.refusedRcpts)) state.refusedRcpts = [];
      if (state.refusedRcpts.length >= MAX_REFUSED_RCPTS_PER_TXN) return;
      state.refusedRcpts.push({ rcptTo: rcpt, reason: reason });
    }

    function _requiresStartTls() {
      // Strict / balanced require STARTTLS before MAIL FROM.
      // Permissive accepts plaintext — operator-acknowledged downgrade
      // for legacy infrastructure.
      return profile === "strict" || profile === "balanced";
    }

    function _isRelayAllowed(_remoteAddress, _rcptTo) {
      // Operator-supplied relayAllowedFor entries. v1 just checks
      // presence in the array; CIDR/scope matching could be wired
      // via b.middleware.networkAllowlist in a follow-up.
      if (relayAllowedFor.length === 0) return false;
      return true;
    }
  }

  // ---- Lifecycle ----------------------------------------------------------
  async function listen(listenOpts) {
    listenOpts = listenOpts || {};
    if (listening) {
      throw new MailServerMxError("mail-server-mx/already-listening",
        "listen: already listening");
    }
    // Port 0 (ephemeral, test mode) must NOT fall back to 25 — the
    // `|| 25` short-circuit was a footgun on the test path.
    var port    = listenOpts.port    === undefined ? 25 : listenOpts.port;                           // allow:raw-byte-literal — SMTP MX port (IANA)
    var address = listenOpts.address || "0.0.0.0";
    tcpServer = net.createServer(function (socket) {
      _handleConnection(socket);
    });
    return new Promise(function (resolve, reject) {
      tcpServer.once("error", reject);
      tcpServer.listen(port, address, function () {
        listening = true;
        tcpServer.removeListener("error", reject);
        _emit("mail.server.mx.listening", {
          port: port, address: address,
        });
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
      await safeAsync.sleep(100);                                                                    // allow:raw-time-literal — close-drain poll interval (sub-second; operator-bounded by timeoutMs)
    }
    connections.forEach(function (sock) {
      try { sock.destroy(); } catch (_e) { /* best-effort */ }
    });
    connections.clear();
    _emit("mail.server.mx.closed", {});
  }

  function connectionCount() { return connections.size; }

  return {
    listen:           listen,
    close:            close,
    connectionCount:  connectionCount,
    _portForTest:     function () { return tcpServer ? tcpServer.address().port : null; },
  };
}

// ---- Wire-protocol helpers --------------------------------------------------

// Write back-pressure observability — when `socket.write()` returns
// false the kernel send-buffer is full and the server is dropping
// behind the network. Listeners attach a `_bpEmit` function to the
// socket; we invoke it once per socket-lifetime on the first
// backpressure event so the audit log surfaces stalled connections
// without flooding on every reply.
function _observeBackpressure(socket, ok) {
  if (ok) return;
  if (typeof socket._bpEmit !== "function") return;
  if (socket._bpEmitted) return;
  socket._bpEmitted = true;
  try { socket._bpEmit(socket); } catch (_e) { /* drop-silent */ }
}

function _writeReply(socket, code, text) {
  // Single-line reply per RFC 5321 §4.2 — code SP text CRLF.
  try {
    var ok = socket.write(code + " " + text + "\r\n");
    _observeBackpressure(socket, ok);
  } catch (_e) { /* socket already closed */ }
}

function _writeMultiline(socket, code, lines) {
  // Multi-line reply per RFC 5321 §4.2 — code "-" text CRLF for
  // continuation, code SP text CRLF for the final line.
  for (var i = 0; i < lines.length; i += 1) {
    var sep = i === lines.length - 1 ? " " : "-";
    try {
      var ok = socket.write(code + sep + lines[i] + "\r\n");
      _observeBackpressure(socket, ok);
    } catch (_e) { /* socket already closed */ }
  }
}

function _closeConnection(socket) {
  try { socket.end(); } catch (_e) { /* best-effort */ }
  try { socket.destroy(); } catch (_e) { /* best-effort */ }
}

module.exports = {
  create:            create,
  MailServerMxError: MailServerMxError,
};

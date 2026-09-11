// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.server.pop3
 * @nav        Mail
 * @title      Mail POP3 Server
 * @order      550
 *
 * @intro
 *   POP3 mailbox-access listener (RFC 1939 + RFC 2449 capabilities +
 *   RFC 2595 STLS + RFC 5034 SASL AUTH). Opt-in legacy fallback for
 *   MUAs that don't speak IMAP — the framework's blamepost roadmap
 *   makes JMAP primary and IMAP/POP3 opt-ins; this listener exists
 *   so operators with last-decade MUAs (older Outlook profiles,
 *   legacy mobile clients, simple device firmware) can still
 *   authenticate + pull messages.
 *
 *   ## State machine (RFC 1939 §3)
 *
 *   ```
 *   AUTHORIZATION → TRANSACTION → UPDATE → (close)
 *   ```
 *
 *   - **AUTHORIZATION**: STLS / CAPA / USER / PASS / APOP / AUTH /
 *     QUIT. After successful USER+PASS / APOP / AUTH the connection
 *     enters TRANSACTION.
 *   - **TRANSACTION**: STAT / LIST / RETR / DELE / NOOP / RSET / TOP /
 *     UIDL / QUIT. DELE marks messages for deletion; actual deletion
 *     happens in UPDATE state on QUIT.
 *   - **UPDATE**: triggered by QUIT from TRANSACTION; the listener
 *     calls `mailStore.commitPop3Drop(actor, dropId)` to apply the
 *     pending deletes atomically, then closes.
 *
 *   ## Wire-protocol defenses
 *
 *   - **Cleartext-auth refusal under strict** — RFC 1939 USER/PASS
 *     sends the password in plaintext. Strict + balanced profiles
 *     refuse USER/PASS pre-TLS; operators with legacy clients pass
 *     `profile: "permissive"`.
 *
 *   - **STLS injection (CVE-2021-33515 class)** — STLS upgrade clears
 *     pre-handshake receive buffer; any pipelined command queued
 *     before TLS is dropped.
 *
 *   - **APOP refusal under strict** — RFC 1939 §7 APOP uses MD5
 *     challenge-response. M³AAWG / NIST SP 800-131A r2 phase out
 *     MD5; the strict profile refuses APOP.
 *
 *   - **Per-IP rate limit + AUTH-failure budget** — composes
 *     `b.mail.server.rateLimit` (default-on). The submission listener's
 *     `authFailuresPerIpPer15Min` cap applies to USER+PASS / APOP /
 *     AUTH refusals.
 *
 *   - **Slow-loris** — per-connection `idleTimeoutMs` bounds a peer that
 *     stops making progress, in either direction: a client that sends no
 *     further command, and one that stops taking a RETR / TOP response.
 *     `maxLineBytes` bounds a command line that never ends.
 *
 *   ## Audit lifecycle
 *
 *   - `mail.server.pop3.connect`             — IP, TLS state
 *   - `mail.server.pop3.auth_attempt`        — verb, actor-hash
 *   - `mail.server.pop3.auth_success`        — verb, tenantId
 *   - `mail.server.pop3.auth_failed`         — verb, reason
 *   - `mail.server.pop3.auth_rate_limit_refused`
 *   - `mail.server.pop3.transaction_start`   — drop count, total size
 *   - `mail.server.pop3.retr`                — msg-num
 *   - `mail.server.pop3.dele`                — msg-num (marked-for-delete)
 *   - `mail.server.pop3.update_commit`       — final-deleted count
 *   - `mail.server.pop3.rate_limit_refused`  — IP, reason
 *
 *   ## What v1 does NOT ship
 *
 *   - **APOP** — refused under strict + balanced; permissive opts in.
 *     APOP uses MD5; modern deployments use TLS + USER/PASS or SASL
 *     instead.
 *   - **SASL mechanisms beyond PLAIN** — CRAM-MD5 / SCRAM-SHA-256 /
 *     OAUTHBEARER all wire through operator's `auth.verify`. v1
 *     advertises PLAIN only; operators add via `auth.mechanisms`.
 *   - **Multi-step SASL exchange** — single-step PLAIN is sufficient
 *     for the v1 surface; SCRAM round-trip ships when an operator
 *     surfaces demand.
 *   - **Per-message lock** — POP3 has no native message-id beyond
 *     UIDL; concurrent connections from the same actor compete via
 *     `mailStore.openPop3Drop({ exclusive: true })`.
 *
 *   ## Composition contract
 *
 *   - `b.guardPop3Command` — wire-protocol gate
 *   - `b.mail.server.rateLimit` — DoS defense
 *   - `b.mailStore` — operator-supplied backend (must expose
 *     `openPop3Drop(actor, opts)` / `commitPop3Drop(actor, dropId)` /
 *     `getMessage(actor, dropId, msgNum, { headersOnly?, headerLines? })` /
 *     `listMessages(actor, dropId)` / `markDelete(actor, dropId, msgNum)`)
 *   - operator's `auth.verify(mechanism, credentials)` async predicate
 *   - `b.network.tls.context` — TLS posture
 *
 * @card
 *   POP3 mailbox-access listener (RFC 1939 + RFC 2449 + RFC 2595 +
 *   RFC 5034). Opt-in legacy fallback; state machine AUTH → TRANS →
 *   UPDATE. Composes b.guardPop3Command + b.mail.server.rateLimit +
 *   operator-supplied mailStore + SASL authenticator. STLS-injection
 *   defense + AUTH-failure budget + cleartext-auth refusal under
 *   strict.
 */

var net = require("node:net");
var safeBuffer = require("./safe-buffer");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardPop3Command = require("./guard-pop3-command");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerTls = require("./mail-server-tls");
var mailServerNet = require("./mail-server-net");
var safeSmtp = require("./safe-smtp");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var MailServerPop3Error = defineClass("MailServerPop3Error", { alwaysPermanent: true });

var DEFAULT_MAX_LINE_BYTES   = 1024;
var PIPELINE_LINE_ALLOWANCE  = 8;
var CRLF_BYTES               = 2;
var DEFAULT_IDLE_TIMEOUT_MS  = C.TIME.minutes(10);
var DEFAULT_COMMIT_TIMEOUT_MS = C.TIME.seconds(30);
var DEFAULT_GREETING_VENDOR  = "blamejs POP3";

var ERR_CLAMP = 200;

/**
 * @primitive b.mail.server.pop3.create
 * @signature b.mail.server.pop3.create(opts)
 * @since     0.9.52
 * @status    stable
 * @related   b.mail.server.imap.create, b.mail.server.submission.create, b.mailStore.create
 *
 * Build a POP3 listener (RFC 1939). Returns a handle exposing
 * `listen({ port, address })` and `close()`. POP3 is opt-in legacy —
 * deployments should prefer `b.mail.server.imap` + `b.mail.server.jmap`
 * for new MUAs.
 *
 * @opts
 *   tlsContext:        SecureContext,           // required (no plaintext)
 *   implicitTls:       boolean,                 // RFC 8314 §3 — TLS from the SYN on 995 (the default port becomes 995). STLS is neither advertised nor accepted on it. Default false
 *   greeting:          string,                   // default "blamejs POP3"
 *   maxLineBytes:      number,                   // default 1024
 *   idleTimeoutMs:     number,                   // default 10 min
 *   maxConnections:    number,                   // default 1024 — listener-wide ceiling
 *   commitTimeoutMs:   number,                   // default 30 s (UPDATE-state mailStore.commitPop3Drop cap)
 *   profile:           "strict" | "balanced" | "permissive",
 *   auth: {
 *     mechanisms:      ["PLAIN"],                 // SASL mechs to advertise
 *     verify:          async function (mech, credentials) → { ok, actor },
 *   },
 *   mailStore:         b.mailStore handle,
 *   onSessionEnd:      function (actor, sessionId),         // optional. Fired once when the session ends by ANY route — QUIT, idle timeout, or a link that dropped without one. A maildrop is leased to one session (RFC 1939 §3), and this is the signal to release it; without it the only release available is a timer, which cannot tell a finished session from a slow one and locks the account holder out of their own mailbox after a network blip
 *   onSessionActivity: function (actor, sessionId, verb),   // optional. Fired for every command, NOOP included — the listener answers NOOP itself, so a consumer aging an idle lease would otherwise never see the keepalive the protocol defines for it and would reap the lease under a live connection
 *   rateLimit:         b.mail.server.rateLimit handle | opts | false,
 *   audit:             b.audit
 *
 * @example
 *   var pop3 = b.mail.server.pop3.create({
 *     tlsContext: b.mail.server.tls.context({ certFile, keyFile }).secureContext,
 *     auth: {
 *       mechanisms: ["PLAIN"],
 *       verify:     async function (mech, creds) {
 *         return { ok: true, actor: { username: creds.authzid, tenantId: "t1" } };
 *       },
 *     },
 *     mailStore: b.mailStore.create({ backend: b.db }),
 *   });
 *   await pop3.listen({ port: 110 });
 */
var CREATE_OPTS = [
  "tlsContext", "implicitTls", "greeting", "maxLineBytes", "idleTimeoutMs",
  "maxConnections", "commitTimeoutMs", "profile", "auth", "mailStore",
  "onSessionEnd", "onSessionActivity", "rateLimit", "audit",
  "agentTenantId", "tenantScope",
];

function create(opts) {
  validateOpts.requireObject(opts, "mail.server.pop3.create",
    MailServerPop3Error, "mail-server-pop3/bad-opts");
  validateOpts.checkOrThrow(opts, CREATE_OPTS, "mail.server.pop3.create",
    MailServerPop3Error, "mail-server-pop3/bad-opts");
  validateOpts.auditShape(opts.audit, "mail.server.pop3.create",
    MailServerPop3Error, "mail-server-pop3/bad-opts");
  if (!opts.tlsContext) {
    throw new MailServerPop3Error("mail-server-pop3/no-tls-context",
      "mail.server.pop3.create: tlsContext is required (no implicit plaintext mode). " +
      "Use b.mail.server.tls.context({ certFile, keyFile, watch: true }).");
  }
  if (!opts.mailStore || typeof opts.mailStore.openPop3Drop !== "function") {
    throw new MailServerPop3Error("mail-server-pop3/no-mail-store",
      "mail.server.pop3.create: mailStore is required (must expose openPop3Drop/commitPop3Drop/" +
      "getMessage/listMessages/markDelete; compose b.mailStore.create or operator-supplied backend)");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "idleTimeoutMs", "commitTimeoutMs", "maxConnections"],
    "mail.server.pop3.", MailServerPop3Error, "mail-server-pop3/bad-bound");

  var greeting        = opts.greeting        || DEFAULT_GREETING_VENDOR;
  var maxLineBytes    = opts.maxLineBytes    || DEFAULT_MAX_LINE_BYTES;
  var maxPipelinedBytes = (maxLineBytes + CRLF_BYTES) * PIPELINE_LINE_ALLOWANCE;
  var idleTimeoutMs   = opts.idleTimeoutMs   || DEFAULT_IDLE_TIMEOUT_MS;
  var commitTimeoutMs = opts.commitTimeoutMs || DEFAULT_COMMIT_TIMEOUT_MS;
  var profile         = opts.profile         || "strict";
  var authConfig      = opts.auth            || null;
  var implicitTls     = opts.implicitTls === true;
  var mailStore       = opts.mailStore;
  var tenantScope     = opts.tenantScope     || null;
  var agentTenantId   = opts.agentTenantId   || null;
  if (tenantScope && typeof tenantScope.check !== "function") {
    throw new MailServerPop3Error("mail-server-pop3/bad-tenant-scope",
      "create: opts.tenantScope must be a b.agent.tenant.create() instance " +
      "(missing .check); a malformed scope would refuse every auth as cross-tenant");
  }
  if (tenantScope && !agentTenantId) {
    throw new MailServerPop3Error("mail-server-pop3/no-agent-tenant-id",
      "create: opts.tenantScope requires opts.agentTenantId");
  }

  function _assertTenantOrRefuse(state, socket, result) {
    if (!tenantScope || !agentTenantId) return true;
    try { tenantScope.check(result.actor, agentTenantId); return true; }
    catch (tenantErr) {
      _emit("mail.server.pop3.cross_tenant_refused",
        { connectionId: state.id,
          actorTenant:  (result.actor && result.actor.tenantId) || null,
          agentTenant:  agentTenantId,
          code:         (tenantErr && tenantErr.code) || null },
        "denied");
      _writeErr(socket, "Authentication rejected (cross-tenant)");
      return false;
    }
  }

  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

  var connections = new Set();

  var _emit = auditEmit.dualEmitter(opts);

  var onSessionEnd = validateOpts.definedFunction(opts.onSessionEnd,
    "b.mail.server.pop3.create: onSessionEnd", MailServerPop3Error, "mail-server-pop3/bad-opts");
  var onSessionActivity = validateOpts.definedFunction(opts.onSessionActivity,
    "b.mail.server.pop3.create: onSessionActivity", MailServerPop3Error, "mail-server-pop3/bad-opts");

  // control, so both go through mailServerNet.fireConsumerHook and DROP SILENT
  function _fireSessionEnd(state) {
    if (!onSessionEnd || state.sessionEndFired) return;
    state.sessionEndFired = true;
    if (!state.storeWork) return _emitSessionEnd(state);
    state.storeWork.then(function () { _emitSessionEnd(state); },
      function () { _emitSessionEnd(state); });
  }

  function _storeWork(state, promise) {
    var settled = Promise.resolve(promise)
      .catch(function () { /* the call site reports it */ });
    state.storeWork = state.storeWork
      ? state.storeWork.then(function () { return settled; }, function () { return settled; })
      : settled;
    return promise;
  }

  function _emitSessionEnd(state) {
    mailServerNet.fireConsumerHook(onSessionEnd, [state.actor, state.id],
      { emit: _emit, event: "mail.server.pop3.session_end_hook_failed", connectionId: state.id });
  }

  function _fireSessionActivity(state, verb) {
    mailServerNet.fireConsumerHook(onSessionActivity, [state.actor, state.id, verb],
      { emit: _emit, event: "mail.server.pop3.session_activity_hook_failed", connectionId: state.id });
  }

  function _handleConnection(rawSocket) {
    var state = null;
    var accepted = mailServerNet.acceptConnection(rawSocket, {
      rateLimit:    rateLimit,
      connections:  connections,
      emit:         _emit,
      refusedEvent: "mail.server.pop3.rate_limit_refused",
      refusalLine:  "-ERR Too many connections from your IP\r\n",
      idPrefix:     "pop3conn-",
      wrap:         mailServerTls.implicitTlsWrap(opts.tlsContext, implicitTls),
      onClose:      function () {
        if (!state) return;
        state.closed = true;
        _fireSessionEnd(state);
      },
    });
    if (accepted === null) return;
    var remoteAddress = accepted.remoteAddress;
    var connectionId  = accepted.connectionId;
    var socket        = accepted.socket;

    state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      tls:           implicitTls,
      stage:         "authorization",
      closed:        false,
      actor:         null,
      tentativeUser: null,
      authPending:   null,
      dropId:        null,
      lineBuffer:    Buffer.alloc(0),
    };

    _emit("mail.server.pop3.connect",
      { connectionId: connectionId, remoteAddress: remoteAddress });

    mailServerNet.wireLineSocket(socket, {
      idleTimeoutMs: idleTimeoutMs,
      state:         state,
      drain:         _drainBuffer,
      onIdleTimeout: function () { _writeErr(socket, "Idle timeout"); },
      onError:       function (err) {
        _emit("mail.server.pop3.socket_error",
          { connectionId: connectionId, error: (err && err.message) || String(err) }, "failure");
      },
      close:         function () { _close(socket, state); },
    });

    _writeOk(socket, greeting + " ready");
  }

  function _takeLine(state, socket) {
    var crlf = state.lineBuffer.indexOf("\r\n");
    if (crlf === -1) {
      if (safeBuffer.byteLengthOf(state.lineBuffer) > maxLineBytes) {
        _writeErr(socket, "Line too long (cap " + maxLineBytes + ")");
        _close(socket, state);
      }
      return null;
    }
    var rawLine = state.lineBuffer.subarray(0, crlf).toString("utf8");
    state.lineBuffer = state.lineBuffer.subarray(crlf + 2);
    return rawLine;
  }

  function _drainBuffer(state, socket) {
    if (safeBuffer.byteLengthOf(state.lineBuffer) > maxPipelinedBytes) {
      _writeErr(socket, "Too much pipelined data awaiting execution (cap " +
        maxPipelinedBytes + " bytes)");
      _close(socket, state);
      return;
    }
    if (state.pumping) return;
    state.pumping = true;
    function step() {
      if (state.closed) { state.pumping = false; return; }
      var line = _takeLine(state, socket);
      if (line === null) { state.pumping = false; return; }
      var pending;
      try { pending = _handleLine(state, socket, line); }
      catch (e) { state.pumping = false; _pumpFailed(state, socket, e); return; }
      Promise.resolve(pending).then(step, function (e) {
        state.pumping = false;
        _pumpFailed(state, socket, e);
      });
    }
    step();
  }

  function _pumpFailed(state, socket, err) {
    _emit("mail.server.pop3.handler_threw",
      { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
    try { _writeErr(socket, "Server error"); } catch (_e) { /* socket already gone */ }
    _close(socket, state);
  }

  function _handleLine(state, socket, line) {
    if (state.authPending) {
      return _continueAuthExchange(state, socket, line);
    }
    var parsed;
    try {
      parsed = guardPop3Command.validate(line, {
        profile: profile,
        tls:     state.tls,
      });
    } catch (e) {
      _writeErr(socket, (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return undefined;
    }
    return _dispatch(state, socket, parsed);
  }

  function _dispatch(state, socket, parsed) {
    var verb = parsed.verb;
    var args = parsed.args;
    _fireSessionActivity(state, verb);
    switch (verb) {
    case "CAPA":   return _handleCapa(state, socket);
    case "STLS":   return _handleStls(state, socket);
    case "USER":   return _handleUser(state, socket, args);
    case "PASS":   return _handlePass(state, socket, args);
    case "APOP":   return _handleApop(state, socket, args);
    case "AUTH":   return _handleAuth(state, socket, args);
    case "QUIT":   return _handleQuit(state, socket);
    case "STAT":   return _handleStat(state, socket);
    case "LIST":   return _handleList(state, socket, args);
    case "RETR":   return _handleRetr(state, socket, args);
    case "DELE":   return _handleDele(state, socket, args);
    case "NOOP":   return _writeOk(socket, "noop");
    case "RSET":   return _handleRset(state, socket);
    case "TOP":    return _handleTop(state, socket, args);
    case "UIDL":   return _handleUidl(state, socket, args);
    default:       return _writeErr(socket, "Verb '" + verb + "' not implemented");
    }
  }

  function _handleCapa(state, socket) {
    _writeOk(socket, "Capability list follows");
    socket.write("TOP\r\n");
    socket.write("UIDL\r\n");
    socket.write("RESP-CODES\r\n");
    if (!state.tls) socket.write("STLS\r\n");
    if (authConfig && Array.isArray(authConfig.mechanisms) && authConfig.mechanisms.length > 0) {
      var mechs = authConfig.mechanisms.map(function (m) {
        return String(m).toUpperCase();
      }).join(" ");
      socket.write("SASL " + mechs + "\r\n");
    }
    socket.write("IMPLEMENTATION blamejs\r\n");
    socket.write(".\r\n");
  }

  function _handleStls(state, socket) {
    if (implicitTls) {
      _writeErr(socket, "STLS not available on implicit-TLS port (RFC 8314)");
      return;
    }
    if (state.tls) {
      _writeErr(socket, "STLS already negotiated");
      return;
    }
    if (state.stage !== "authorization") {
      _writeErr(socket, "STLS only valid in AUTHORIZATION (RFC 2595 §4)");
      return;
    }
    _writeOk(socket, "Begin TLS negotiation");
    mailServerTls.upgradeLineProtocol({
      state:         state,
      socket:        socket,
      secureContext: opts.tlsContext,
      idleTimeoutMs: idleTimeoutMs,
      clearFields:   ["tentativeUser"],
      drain:         _drainBuffer,
      onError: function (err) {
        _emit("mail.server.pop3.tls_handshake_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _close(socket, state);
      },
      onTimeout: function (tlsSocket) {
        _writeErr(tlsSocket, "Idle timeout");
        _close(tlsSocket, state);
      },
    });
  }

  function _refusedByAuthBudget(state, socket) {
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (authAdmit.ok) return false;
    _emit("mail.server.pop3.auth_rate_limit_refused",
      { connectionId: state.id, remoteAddress: state.remoteAddress, reason: authAdmit.reason },
      "denied");
    _writeErr(socket, "Too many AUTH failures from your IP");
    _close(socket, state);
    return true;
  }

  function _handleUser(state, socket, args) {
    if (state.stage !== "authorization") {
      _writeErr(socket, "USER only valid in AUTHORIZATION");
      return;
    }
    if (state.actor) {
      _writeErr(socket, "Already authenticated");
      return;
    }
    if (!state.tls && profile !== "permissive") {
      if (_refusedByAuthBudget(state, socket)) return;
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "USER", remoteAddress: state.remoteAddress },
        "denied");
      rateLimit.noteAuthFailure(state.remoteAddress);
      _writeErr(socket, "USER refused over cleartext (use STLS first; RFC 2595 §2.1)");
      return;
    }
    state.tentativeUser = args[0];
    _writeOk(socket, "Send password");
  }

  function _handlePass(state, socket, args) {
    if (state.stage !== "authorization" || !state.tentativeUser) {
      _writeErr(socket, "PASS only valid after USER");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeErr(socket, "AUTH not configured on this listener");
      return;
    }
    if (_refusedByAuthBudget(state, socket)) return;
    if (!state.tls && profile !== "permissive") {
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "PASS", remoteAddress: state.remoteAddress },
        "denied");
      rateLimit.noteAuthFailure(state.remoteAddress);
      _writeErr(socket, "PASS refused over cleartext (use STLS first; RFC 2595 §2.1)");
      return;
    }
    var username = state.tentativeUser;
    state.tentativeUser = null;
    var password = args[0];
    _emit("mail.server.pop3.auth_attempt",
      { connectionId: state.id, verb: "PASS", remoteAddress: state.remoteAddress });
    return Promise.resolve()
      .then(function () {
        return authConfig.verify("PLAIN", {
          username:      username,
          password:      password,
          tls:           state.tls,
          remoteAddress: state.remoteAddress,
        });
      })
      .then(function (result) {
        if (result && result.ok && result.actor) {
          if (!_assertTenantOrRefuse(state, socket, result)) return;
          state.actor = result.actor;
          return _enterTransaction(state, socket, "PASS");
        }
        rateLimit.noteAuthFailure(state.remoteAddress);
        _emit("mail.server.pop3.auth_failed",
          { connectionId: state.id, verb: "PASS", reason: "verify-returned-fail" }, "denied");
        _writeErr(socket, "Authentication failed");
      })
      .catch(function () {
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeErr(socket, "Authentication failed");
      });
  }

  function _handleApop(state, socket, args) {
    if (state.stage !== "authorization") {
      _writeErr(socket, "APOP only valid in AUTHORIZATION");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeErr(socket, "AUTH not configured");
      return;
    }
    if (_refusedByAuthBudget(state, socket)) return;
    if (!state.tls && profile !== "permissive") {
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "APOP", remoteAddress: state.remoteAddress },
        "denied");
      rateLimit.noteAuthFailure(state.remoteAddress);
      _writeErr(socket, "APOP refused over cleartext (use STLS first; RFC 1939 §7)");
      return;
    }
    return Promise.resolve()
      .then(function () {
        return authConfig.verify("APOP", {
          username:      args[0],
          digest:        args[1],
          tls:           state.tls,
          remoteAddress: state.remoteAddress,
        });
      })
      .then(function (result) {
        if (result && result.ok && result.actor) {
          if (!_assertTenantOrRefuse(state, socket, result)) return;
          state.actor = result.actor;
          return _enterTransaction(state, socket, "APOP");
        }
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeErr(socket, "Authentication failed");
      })
      .catch(function () {
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeErr(socket, "Authentication failed");
      });
  }

  function _handleAuth(state, socket, args) {
    if (state.stage !== "authorization") {
      _writeErr(socket, "AUTH only valid in AUTHORIZATION");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeErr(socket, "AUTH not configured");
      return;
    }
    if (args.length === 0) {
      _writeOk(socket, "Supported mechanisms follow");
      var mechs = (authConfig.mechanisms || ["PLAIN"]).map(function (m) {
        return String(m).toUpperCase();
      });
      for (var i = 0; i < mechs.length; i += 1) socket.write(mechs[i] + "\r\n");
      socket.write(".\r\n");
      return;
    }
    if (_refusedByAuthBudget(state, socket)) return;
    if (!state.tls && profile === "strict") {
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "AUTH", mech: args[0] }, "denied");
      _writeErr(socket, "AUTH refused over cleartext (use STLS first; RFC 2595 §2.1)");
      return;
    }
    var mech = args[0].toUpperCase();
    var initialResp = args.length > 1 ? args.slice(1).join(" ") : null;
    state.authPending = { mech: mech, step: 0 };
    return _runAuthStep(state, socket, initialResp);
  }

  function _runAuthStep(state, socket, clientResponse) {
    var pending = state.authPending;
    function _fail(reason, outcome) {
      state.authPending = null;
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.pop3.auth_failed",
        { connectionId: state.id, verb: "AUTH", mech: pending.mech, reason: reason },
        outcome);
      _writeErr(socket, "Authentication failed");
    }
    return mailServerNet.runSaslStep({
      exchange:       pending,
      verify:         authConfig.verify,
      credentials:    { tls: state.tls, remoteAddress: state.remoteAddress },
      clientResponse: clientResponse,
      writeChallenge: function (ch) { return _writeContinuation(socket, ch); },
      onChallengeUnsafe: function () { _fail("challenge-contains-line-terminator", "denied"); },
      onSuccess: function (result) {
        state.authPending = null;
        if (!_assertTenantOrRefuse(state, socket, result)) return undefined;
        state.actor = result.actor;
        return _enterTransaction(state, socket, "AUTH/" + pending.mech);
      },
      onFailure: function (result) {
        _fail((result && result.reason) || "verify-returned-fail", "denied");
      },
      onError: function (err) { _fail((err && err.message) || String(err), "failure"); },
    });
  }

  function _continueAuthExchange(state, socket, line) {
    if (line === "*") {
      state.authPending = null;
      _writeErr(socket, "Authentication cancelled");
      return undefined;
    }
    return _runAuthStep(state, socket, line);
  }

  function _enterTransaction(state, socket, verb) {
    if (state.closed) {
      _emit("mail.server.pop3.auth_after_close",
        { connectionId: state.id, verb: verb }, "denied");
      return undefined;
    }
    if (typeof mailStore.openPop3Drop !== "function") {
      _writeErr(socket, "Backend missing openPop3Drop");
      return undefined;
    }
    return _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.openPop3Drop(state.actor, {}); }))
      .then(function (drop) {
        state.dropId = drop && drop.dropId;
        state.stage = "transaction";
        _emit("mail.server.pop3.auth_success",
          { connectionId: state.id, verb: verb, tenantId: state.actor.tenantId || null });
        _emit("mail.server.pop3.transaction_start",
          { connectionId: state.id, dropCount: (drop && drop.count) || 0,
            totalBytes: (drop && drop.totalBytes) || 0 });
        _writeOk(socket, "Logged in");
      })
      .catch(function (err) {
        _writeErr(socket, "Cannot open drop: " + ((err && err.message) || "backend error").slice(0, ERR_CLAMP));
      });
  }

  function _handleQuit(state, socket) {
    if (state.stage !== "transaction") {
      _writeOk(socket, "Goodbye");
      _close(socket, state);
      return;
    }
    state.stage = "update";
    var commitInFlight = Promise.resolve().then(function () {
      return mailStore.commitPop3Drop(state.actor, state.dropId);
    });
    _storeWork(state, commitInFlight);
    return safeAsync.withTimeout(commitInFlight, commitTimeoutMs,
      { label: "mail.server.pop3.commitPop3Drop" })
      .then(function (info) {
        _emit("mail.server.pop3.update_commit",
          { connectionId: state.id, deleted: (info && info.deleted) || 0 });
        _writeOk(socket, "Goodbye");
        _close(socket, state);
      })
      .catch(function (err) {
        _emit("mail.server.pop3.update_commit_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _writeErr(socket, "Commit failed: " + ((err && err.message) || "backend error").slice(0, ERR_CLAMP));
        _close(socket, state);
      });
  }

  function _requireTrans(state, socket) {
    if (state.stage !== "transaction") {
      _writeErr(socket, "Not authorized; USER+PASS first");
      return false;
    }
    return true;
  }

  function _handleStat(state, socket) {
    if (!_requireTrans(state, socket)) return;
    return _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.listMessages(state.actor, state.dropId); }))
      .then(function (msgs) {
        var ms = msgs || [];
        var totalBytes = 0;
        for (var i = 0; i < ms.length; i += 1) totalBytes += ms[i].size || 0;
        _writeOk(socket, ms.length + " " + totalBytes);
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "stat failed").slice(0, ERR_CLAMP)); });
  }

  function _handleList(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    return _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.listMessages(state.actor, state.dropId); }))
      .then(function (msgs) {
        var ms = msgs || [];
        if (args.length === 1) {
          var n = parseInt(args[0], 10);
          var found = null;
          for (var i = 0; i < ms.length; i += 1) {
            if (ms[i].msgNum === n) { found = ms[i]; break; }
          }
          if (!found) { _writeErr(socket, "no such message"); return; }
          _writeOk(socket, n + " " + found.size);
          return;
        }
        _writeOk(socket, ms.length + " messages");
        for (var j = 0; j < ms.length; j += 1) {
          socket.write(ms[j].msgNum + " " + ms[j].size + "\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "list failed").slice(0, ERR_CLAMP)); });
  }

  function _handleRetr(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    var msgNum = parseInt(args[0], 10);
    return _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.getMessage(state.actor, state.dropId, msgNum, {}); }))
      .then(function (msg) {
        if (!msg) { _writeErr(socket, "no such message"); return; }
        _emit("mail.server.pop3.retr",
          { connectionId: state.id, msgNum: msgNum, size: msg.size });
        _writeOk(socket, msg.size + " octets");
        var bodyBuf = msg.rawBytes
          ? msg.rawBytes
          : Buffer.from(msg.text || "", "utf8");
        var stuffed = safeSmtp.dotStuff(bodyBuf);
        socket.write(stuffed);
        if (stuffed.length === 0 ||
            stuffed[stuffed.length - 2] !== 0x0d  ||
            stuffed[stuffed.length - 1] !== 0x0a ) {
          socket.write("\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "retr failed").slice(0, ERR_CLAMP)); });
  }

  function _handleDele(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    var msgNum = parseInt(args[0], 10);
    return _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.markDelete(state.actor, state.dropId, msgNum); }))
      .then(function () {
        _emit("mail.server.pop3.dele",
          { connectionId: state.id, msgNum: msgNum });
        _writeOk(socket, "marked deleted");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "dele failed").slice(0, ERR_CLAMP)); });
  }

  function _handleRset(state, socket) {
    if (!_requireTrans(state, socket)) return;
    return _storeWork(state, Promise.resolve()
      .then(function () {
        if (typeof mailStore.resetPop3Drop === "function") {
          return mailStore.resetPop3Drop(state.actor, state.dropId);
        }
      }))
      .then(function () { _writeOk(socket, "delete marks cleared"); })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "rset failed").slice(0, ERR_CLAMP)); });
  }

  function _handleTop(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    var msgNum = parseInt(args[0], 10);
    var headerLines = parseInt(args[1], 10);
    return _storeWork(state, Promise.resolve()
      .then(function () {
        return mailStore.getMessage(state.actor, state.dropId, msgNum,
          { headersOnly: true, headerLines: headerLines });
      }))
      .then(function (msg) {
        if (!msg) { _writeErr(socket, "no such message"); return; }
        _writeOk(socket, "headers + " + headerLines + " body lines");
        var bodyBuf = msg.rawBytes
          ? msg.rawBytes
          : Buffer.from(msg.text || "", "utf8");
        var stuffed = safeSmtp.dotStuff(bodyBuf);
        socket.write(stuffed);
        if (stuffed.length === 0 ||
            stuffed[stuffed.length - 2] !== 0x0d  ||
            stuffed[stuffed.length - 1] !== 0x0a ) {
          socket.write("\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "top failed").slice(0, ERR_CLAMP)); });
  }

  function _handleUidl(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    return _storeWork(state, Promise.resolve()
      .then(function () { return mailStore.listMessages(state.actor, state.dropId); }))
      .then(function (msgs) {
        var ms = msgs || [];
        if (args.length === 1) {
          var n = parseInt(args[0], 10);
          var found = null;
          for (var i = 0; i < ms.length; i += 1) {
            if (ms[i].msgNum === n) { found = ms[i]; break; }
          }
          if (!found) { _writeErr(socket, "no such message"); return; }
          _writeOk(socket, n + " " + (found.uid || found.uidl || ""));
          return;
        }
        _writeOk(socket, "unique-id listing follows");
        for (var j = 0; j < ms.length; j += 1) {
          socket.write(ms[j].msgNum + " " + (ms[j].uid || ms[j].uidl || "") + "\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "uidl failed").slice(0, ERR_CLAMP)); });
  }

  function _writeOk(socket, msg)  { try { socket.write("+OK "  + msg + "\r\n"); } catch (_e) { /* socket down */ } }
  function _writeErr(socket, msg) { try { socket.write("-ERR " + msg + "\r\n"); } catch (_e) { /* socket down */ } }
  function _writeContinuation(socket, challenge) {
    var b64 = mailServerNet.saslChallengeOrNull(challenge);
    if (b64 === null) return false;
    try { socket.write(b64.length > 0 ? "+ " + b64 + "\r\n" : "+\r\n"); }
    catch (_e) { /* socket down */ }
    return true;
  }
  function _close(socket, state) {
    if (state) {
      state.closed = true;
      state.lineBuffer = Buffer.alloc(0);
    }
    mailServerNet.destroySocketAfterFlush(socket);
  }

  return mailServerNet.createStoreServer(net, {
    defaultPort:      implicitTls ? 995 : 110,
    maxConnections:   opts.maxConnections,
    listeningExtra:   function () { return { implicitTls: implicitTls }; },
    handleConnection: _handleConnection,
    errorClass:       MailServerPop3Error,
    errorCodePrefix:  "mail-server-pop3/",
    emit:             _emit,
    connections:      connections,
    eventBase:        "mail.server.pop3",
  });
}

module.exports = {
  create:               create,
  MailServerPop3Error:  MailServerPop3Error,
};

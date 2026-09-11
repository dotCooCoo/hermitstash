// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.server.managesieve
 * @nav        Mail
 * @title      Mail ManageSieve Server
 * @order      560
 *
 * @intro
 *   ManageSieve listener (RFC 5804 — "A Protocol for Remotely Managing
 *   Sieve Scripts"). Lets MUAs upload, replace, list, activate, fetch,
 *   delete, and rename Sieve filter scripts on the server. Composes
 *   `b.safeSieve.validate` for pre-storage validation per RFC 5804 §2.3:
 *   "An implementation MUST verify the script's validity ... and MUST
 *   reject scripts which fail validity tests."
 *
 *   ## State machine (RFC 5804 §1)
 *
 *   ```
 *   NOT-AUTHENTICATED → STARTTLS → AUTHENTICATED → LOGOUT
 *   ```
 *
 *   - **NOT-AUTHENTICATED**: CAPABILITY / NOOP / STARTTLS /
 *     AUTHENTICATE / LOGOUT. The listener sends an unsolicited
 *     capability banner on connect (RFC 5804 §1.7).
 *   - **STARTTLS** (transient): triggered by `STARTTLS`. Pre-handshake
 *     receive buffer is drained before the TLS upgrade to defend the
 *     STARTTLS-injection class (CVE-2021-38371 / CVE-2021-33515 /
 *     CVE-2011-0411). Capabilities are re-emitted post-TLS so the
 *     client sees the post-TLS mechanism list (RFC 5804 §2.2).
 *   - **AUTHENTICATED**: HAVESPACE / PUTSCRIPT / LISTSCRIPTS /
 *     SETACTIVE / GETSCRIPT / DELETESCRIPT / RENAMESCRIPT / NOOP /
 *     CAPABILITY / LOGOUT.
 *
 *   ## Wire-protocol defenses
 *
 *   - **No-implicit-plaintext** — `opts.tlsContext` is required at
 *     `create()`. Operators that genuinely need plaintext (intra-rack
 *     testing) explicitly pass `allowPlaintext: true`, which emits a
 *     `mail.server.managesieve.plaintext_warning` audit on every boot.
 *
 *   - **AUTHENTICATE-mechanism advertisement parity** — `CAPABILITY`
 *     output advertises ONLY the mechanisms listed in
 *     `opts.auth.mechanisms`. The framework hardcodes no defaults; an
 *     operator who omits `mechanisms` gets a listener that refuses
 *     every AUTHENTICATE attempt with "mechanism not advertised"
 *     (otherwise advertising AUTH=PLAIN
 *     when authConfig is null sets clients up to attempt PLAIN against
 *     a listener that hasn't wired the verifier).
 *
 *   - **Cleartext-AUTH refusal under strict** — RFC 5804 §1.1 + RFC
 *     4954 §4. `AUTHENTICATE PLAIN` / `LOGIN` / `SCRAM*` pre-TLS under
 *     strict refused at both the validator and the dispatch boundary.
 *     `AUTHENTICATE EXTERNAL` exempt (TLS client-cert credential, not
 *     a password).
 *
 *   - **STARTTLS injection (CVE-2021-33515 class)** — STARTTLS upgrade
 *     clears the per-connection receive buffer; any pipelined command
 *     queued before the upgrade is discarded. Capabilities are
 *     re-emitted on the post-TLS socket per RFC 5804 §2.2.
 *
 *   - **PUTSCRIPT pre-validation (RFC 5804 §2.3)** — every PUTSCRIPT
 *     payload is parsed via `b.safeSieve.validate` before
 *     `mailStore.sieveScripts.put`. Invalid scripts are refused with
 *     `NO (QUOTA/MAXSCRIPTS) "..."` per §2.3 + audited with the
 *     `safe-sieve/...` issue code so operators can correlate refusals.
 *
 *   - **Per-IP rate limit + AUTH-failure budget** — composes
 *     `b.mail.server.rateLimit` (default-on). Brute-force protection
 *     applies to AUTHENTICATE failures identically to POP3/IMAP.
 *
 *   ## Audit lifecycle
 *
 *   - `mail.server.managesieve.connect`                — IP, TLS state
 *   - `mail.server.managesieve.auth_attempt`           — mech
 *   - `mail.server.managesieve.auth_success`           — mech, tenantId
 *   - `mail.server.managesieve.auth_failed`            — mech, reason
 *   - `mail.server.managesieve.auth_refused_cleartext` — mech
 *   - `mail.server.managesieve.starttls_upgraded`
 *   - `mail.server.managesieve.starttls_handshake_failed`
 *   - `mail.server.managesieve.putscript`              — name, bytes
 *   - `mail.server.managesieve.putscript_refused`      — name, reason (safeSieve issue code)
 *   - `mail.server.managesieve.getscript`              — name
 *   - `mail.server.managesieve.listscripts`            — count
 *   - `mail.server.managesieve.setactive`              — name (empty == deactivate-all)
 *   - `mail.server.managesieve.delete`                 — name
 *   - `mail.server.managesieve.rename`                 — old, new
 *   - `mail.server.managesieve.havespace`              — name, size, ok
 *   - `mail.server.managesieve.logout`
 *   - `mail.server.managesieve.listening`              — port, address
 *   - `mail.server.managesieve.closed`
 *   - `mail.server.managesieve.socket_error`
 *   - `mail.server.managesieve.handler_threw`          — verb, error
 *
 *   ## What v1 does NOT ship
 *
 *   - **CHECKSCRIPT** (RFC 5804 §2.12) — parse-only verb. Operators
 *     who want it compose `b.safeSieve.validate` directly via JMAP
 *     `SieveScript/validate` (RFC 9661). The MTA-side ManageSieve
 *     surface is `PUTSCRIPT` + `HAVESPACE`; CHECKSCRIPT adds a third
 *     entry point with no operator demand yet.
 *   - **UNAUTHENTICATE** (RFC 5804 §2.14) — exotic. Operators close
 *     the TCP connection or send `LOGOUT` + reconnect.
 *
 *   ## Composition contract
 *
 *   - `b.guardManageSieveCommand` — wire-protocol gate
 *   - `b.safeSieve.validate`      — PUTSCRIPT pre-validation
 *   - `b.mail.server.rateLimit`   — DoS defense
 *   - `b.mailStore` — operator-supplied backend (must expose
 *     `sieveScripts.put(actor, name, body)` /
 *     `sieveScripts.list(actor)` /
 *     `sieveScripts.get(actor, name)` /
 *     `sieveScripts.setActive(actor, name)` /
 *     `sieveScripts.delete(actor, name)` /
 *     `sieveScripts.rename(actor, oldName, newName)` /
 *     `sieveScripts.haveSpace(actor, name, size)`)
 *   - operator's `auth.verify(mechanism, credentials)` async predicate
 *   - `b.network.tls.context` — TLS posture
 *
 * @card
 *   ManageSieve listener (RFC 5804). State machine NOT-AUTH → STARTTLS
 *   → AUTH → LOGOUT. Composes b.guardManageSieveCommand +
 *   b.safeSieve.validate (PUTSCRIPT pre-validation per §2.3) +
 *   b.mail.server.rateLimit + operator-supplied mailStore + SASL
 *   authenticator. STARTTLS-injection defense + AUTH-failure budget +
 *   cleartext-AUTH refusal under strict + LITERAL+ support (RFC 7888).
 */

var net = require("node:net");
var safeBuffer = require("./safe-buffer");
var mailServerTls = require("./mail-server-tls");
var mailServerNet = require("./mail-server-net");
var time = require("./time");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardManageSieveCommand = require("./guard-managesieve-command");
var safeSieve = require("./safe-sieve");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerRegistry = require("./mail-server-registry");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var MailServerManageSieveError = defineClass("MailServerManageSieveError",
  { alwaysPermanent: true });

var DEFAULT_PORT             = 4190;
var DEFAULT_MAX_LINE_BYTES   = 8192;
var PIPELINE_LINE_ALLOWANCE  = 8;
var CRLF_BYTES               = 2;
var LITERAL_DEADLINE_GRACE_MS = C.TIME.seconds(1);

var DEFAULT_IDLE_TIMEOUT_MS  = C.TIME.minutes(5);
var DEFAULT_GREETING_VENDOR  = "blamejs ManageSieve";

var ERR_CLAMP                = 200;

/**
 * @primitive b.mail.server.managesieve.create
 * @signature b.mail.server.managesieve.create(opts)
 * @since     0.9.57
 * @status    stable
 * @related   b.mail.server.imap.create, b.mail.server.pop3.create, b.safeSieve.parse, b.guardManageSieveCommand.validate
 *
 * Build a ManageSieve listener (RFC 5804). Returns a handle exposing
 * `listen({ port, address })` and `close()`. Composes `b.safeSieve`
 * for PUTSCRIPT pre-validation per RFC 5804 §2.3.
 *
 * @opts
 *   tlsContext:        SecureContext,                       // required (no implicit plaintext)
 *   implicitTls:       boolean,                             // RFC 8314 §3 — TLS from the SYN. RFC 5804 names one port, so the mode changes how 4190 speaks rather than which port it is. STARTTLS is neither advertised nor accepted on it; requires tlsContext. Default false
 *   allowPlaintext:    boolean,                              // explicit opt-in; emits warning audit
 *   greeting:          string,                               // default "blamejs ManageSieve"
 *   maxLineBytes:      number,                               // default 8192
 *   idleTimeoutMs:     number,                               // default 5 min
 *   maxConnections:    number,                               // default 1024 — listener-wide ceiling
 *   profile:           "strict" | "balanced" | "permissive", // default "strict"
 *   auth: {
 *     mechanisms:      ["SCRAM-SHA-256", "OAUTHBEARER", ...], // SASL mechs to advertise
 *     verify:          async function (mech, credentials) → { ok, actor },
 *   },
 *   mailStore:         b.mailStore handle,                    // must expose sieveScripts.*
 *   rateLimit:         b.mail.server.rateLimit handle | opts | false,
 *   audit:             b.audit
 *
 * @example
 *   var msv = b.mail.server.managesieve.create({
 *     tlsContext: b.mail.server.tls.context({ certFile, keyFile }).secureContext,
 *     auth: {
 *       mechanisms: ["SCRAM-SHA-256", "OAUTHBEARER", "EXTERNAL"],
 *       verify:     async function (mech, creds) {
 *         return { ok: true, actor: { username: creds.authzid, tenantId: "t1" } };
 *       },
 *     },
 *     mailStore: b.mailStore.create({ backend: b.db }),
 *   });
 *   await msv.listen({ port: 4190 });
 */
var CREATE_OPTS = [
  "tlsContext", "implicitTls", "allowPlaintext", "greeting", "maxLineBytes",
  "idleTimeoutMs", "maxConnections", "profile", "auth", "mailStore",
  "rateLimit", "audit", "overrides", "agentTenantId", "tenantScope",
];

function create(opts) {
  validateOpts.requireObject(opts, "mail.server.managesieve.create",
    MailServerManageSieveError, "mail-server-managesieve/bad-opts");
  validateOpts.checkOrThrow(opts, CREATE_OPTS, "mail.server.managesieve.create",
    MailServerManageSieveError, "mail-server-managesieve/bad-opts");
  validateOpts.auditShape(opts.audit, "mail.server.managesieve.create",
    MailServerManageSieveError, "mail-server-managesieve/bad-opts");
  if (!opts.tlsContext && !opts.allowPlaintext) {
    throw new MailServerManageSieveError("mail-server-managesieve/no-tls-context",
      "mail.server.managesieve.create: tlsContext is required (no implicit plaintext mode). " +
      "Use b.mail.server.tls.context({ certFile, keyFile, watch: true }) to load + " +
      "auto-reload a cert/key pair from disk. Operators that genuinely need plaintext " +
      "(intra-rack testing) explicitly pass allowPlaintext: true.");
  }
  if (!opts.mailStore || !opts.mailStore.sieveScripts ||
      typeof opts.mailStore.sieveScripts.put !== "function") {
    throw new MailServerManageSieveError("mail-server-managesieve/no-mail-store",
      "mail.server.managesieve.create: mailStore.sieveScripts is required (must expose " +
      "put/list/get/setActive/delete/rename/haveSpace; compose b.mailStore.create or " +
      "operator-supplied backend)");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "idleTimeoutMs", "maxConnections"],
    "mail.server.managesieve.", MailServerManageSieveError, "mail-server-managesieve/bad-bound");

  var greeting       = opts.greeting       || DEFAULT_GREETING_VENDOR;
  var maxLineBytes   = opts.maxLineBytes   || DEFAULT_MAX_LINE_BYTES;
  var maxPipelinedBytes = (maxLineBytes + CRLF_BYTES) * PIPELINE_LINE_ALLOWANCE;
  var idleTimeoutMs  = opts.idleTimeoutMs  || DEFAULT_IDLE_TIMEOUT_MS;
  var profile        = opts.profile        || "strict";
  var authConfig     = opts.auth           || null;
  var mailStore      = opts.mailStore;
  var allowPlaintext = opts.allowPlaintext === true;

  function _tlsContext() { return opts.tlsContext || null; }

  var implicitTls = opts.implicitTls === true;
  if (implicitTls && !_tlsContext()) {
    throw new MailServerManageSieveError("mail-server-managesieve/no-tls-context",
      "mail.server.managesieve.create: implicitTls requires tlsContext — without one " +
      "the port would serve plaintext under a name that says otherwise");
  }

  var safeSieveProfile = profile;

  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

  var connections = new Set();

  var _emit = auditEmit.dualEmitter(opts);

  function _handleConnection(rawSocket) {
    var accepted = mailServerNet.acceptConnection(rawSocket, {
      rateLimit:    rateLimit,
      connections:  connections,
      emit:         _emit,
      refusedEvent: "mail.server.managesieve.rate_limit_refused",
      refusalLine:  'NO "Too many connections from your IP"\r\n',
      idPrefix:     "msvconn-",
      wrap:         mailServerTls.implicitTlsWrap(_tlsContext(), implicitTls),
    });
    if (accepted === null) return;
    var remoteAddress = accepted.remoteAddress;
    var connectionId  = accepted.connectionId;
    var socket        = accepted.socket;

    var state = {
      id:              connectionId,
      remoteAddress:   remoteAddress,
      tls:             implicitTls,
      stage:           "not-authenticated",
      closed:          false,
      actor:           null,
      pendingLiteral:  null,
      pendingAuth:     null,
      saslExchange:    null,
      awaitingLiteralTerminator: false,
      lineBuffer:      Buffer.alloc(0),
      bodyRateWindow:  mailServerNet.createBodyRateWindow(rateLimit),
      wireBytes:       0,
      literalDeadline: null,
    };

    _emit("mail.server.managesieve.connect",
      { connectionId: connectionId, remoteAddress: remoteAddress });

    mailServerNet.wireLineSocket(socket, {
      idleTimeoutMs: idleTimeoutMs,
      state:         state,
      onIdleTimeout: function () { _writeBye(socket, "Idle timeout"); },
      onError:       function (err) {
        _emit("mail.server.managesieve.socket_error",
          { connectionId: connectionId, error: (err && err.message) || String(err) }, "failure");
      },
      close:         function () { _close(socket, state); },
    });
    socket.on("close", function () { _clearLiteralDeadline(state); });

    _emitCapabilityBanner(state, socket);
    _writeOk(socket, greeting + " ready");

    if (allowPlaintext && !_tlsContext()) {
      _emit("mail.server.managesieve.plaintext_warning",
        { connectionId: connectionId,
          remark: "allowPlaintext=true; no STARTTLS available — operators MUST gate at network layer" },
        "warning");
    }

    socket.on("data", function (chunk) {
      state.wireBytes += chunk.length;
      var transferring = state.pendingLiteral ||
        (state.pendingAuth && state.pendingAuth.irBytes !== null &&
         state.pendingAuth.irBytes !== undefined);
      if (transferring && state.bodyRateWindow.starved(state.wireBytes, time.monotonicMs())) {
        _emit("mail.server.managesieve.literal_refused",
          { connectionId: state.id, reason: "body-rate-below-floor",
            minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
        _writeNo(socket, "Literal arriving below the minimum rate; closing connection");
        _close(socket, state);
        return;
      }
      state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
      _drainBuffer(state, socket);
    });
  }

  function _armLiteralDeadline(state, socket) {
    _clearLiteralDeadline(state);
    state.literalDeadline = setTimeout(function () {
      state.literalDeadline = null;
      var open = state.pendingLiteral ||
        (state.pendingAuth && state.pendingAuth.irBytes !== null &&
         state.pendingAuth.irBytes !== undefined);
      if (!open) return;
      if (!state.bodyRateWindow.starved(state.wireBytes, time.monotonicMs())) {
        _armLiteralDeadline(state, socket);
        return;
      }
      _emit("mail.server.managesieve.literal_refused",
        { connectionId: state.id, reason: "body-rate-below-floor",
          minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
      _writeNo(socket, "Literal arriving below the minimum rate; closing connection");
      _close(socket, state);
    }, rateLimit.bodyRateWindowMs() + LITERAL_DEADLINE_GRACE_MS);
    if (typeof state.literalDeadline.unref === "function") state.literalDeadline.unref();
  }
  function _clearLiteralDeadline(state) {
    if (state.literalDeadline) { clearTimeout(state.literalDeadline); state.literalDeadline = null; }
  }

  function _consumeLiteralTerminator(state) {
    if (state.lineBuffer.length >= 2 &&
        state.lineBuffer[0] === 0x0d && state.lineBuffer[1] === 0x0a) {
      state.lineBuffer = state.lineBuffer.subarray(2);
    } else {
      state.awaitingLiteralTerminator = true;
    }
  }

  function _decodesAsUtf8(body) {
    return Buffer.from(body.toString("utf8"), "utf8").equals(body);
  }

  function _openerBytes(state, line) {
    var parsed;
    try {
      parsed = guardManageSieveCommand.validate(line, { profile: profile, tls: state.tls });
    } catch (_e) { return null; }
    if (!parsed || parsed.literalBytes === null || parsed.literalBytes === undefined) return null;
    return parsed.literalBytes;
  }

  function _backlogRefused(state, socket) {
    var held = safeBuffer.byteLengthOf(state.lineBuffer);
    if (held <= maxPipelinedBytes) return false;
    var outstanding;
    if (state.pendingAuth && state.pendingAuth.irBytes !== null &&
        state.pendingAuth.irBytes !== undefined) {
      outstanding = Math.max(0, state.pendingAuth.irBytes - state.pendingAuth.irBody.length);
    } else {
      outstanding = mailServerNet.announcedLiteralBytes(state.lineBuffer, {
        pending:           state.pendingLiteral,
        maxLineBytes:      maxLineBytes,
        maxPipelinedBytes: maxPipelinedBytes,
        openerBytes:       function (line) { return _openerBytes(state, line); },
      });
    }
    if (held - outstanding <= maxPipelinedBytes) return false;
    _writeNo(socket, "Too much pipelined data awaiting execution (cap " +
      maxPipelinedBytes + " bytes)");
    _close(socket, state);
    return true;
  }

  function _drainBuffer(state, socket) {
    if (_backlogRefused(state, socket)) return;
    if (state.pumping) return;
    state.pumping = true;
    function done() { state.pumping = false; }
    function fail(e) {
      state.pumping = false;
      _emit("mail.server.managesieve.handler_threw",
        { connectionId: state.id, error: (e && e.message) || String(e) }, "failure");
      try { _writeNo(socket, "Server error"); } catch (_e) { /* socket already gone */ }
      _close(socket, state);
    }
    function after(pending) { Promise.resolve(pending).then(step, fail); }

    function step() {
      if (state.closed) return done();
      if (!state.pendingLiteral && !state.pendingAuth &&
          _backlogRefused(state, socket)) return done();
      if (state.pendingLiteral) {
        var pl = state.pendingLiteral;
        var need = pl.size - pl.body.length;
        if (state.lineBuffer.length < need) {
          pl.body = Buffer.concat([pl.body, state.lineBuffer]);
          state.lineBuffer = Buffer.alloc(0);
          return done();
        }
        pl.body = Buffer.concat([pl.body, state.lineBuffer.subarray(0, need)]);
        state.lineBuffer = state.lineBuffer.subarray(need);
        _consumeLiteralTerminator(state);
        state.pendingLiteral = null;
        _clearLiteralDeadline(state);
        return after(_completePutscript(state, socket, pl));
      }
      if (state.pendingAuth && state.pendingAuth.irBytes !== null) {
        var pa = state.pendingAuth;
        var needA = pa.irBytes - pa.irBody.length;
        if (state.lineBuffer.length < needA) {
          pa.irBody = Buffer.concat([pa.irBody, state.lineBuffer]);
          state.lineBuffer = Buffer.alloc(0);
          return done();
        }
        pa.irBody = Buffer.concat([pa.irBody, state.lineBuffer.subarray(0, needA)]);
        state.lineBuffer = state.lineBuffer.subarray(needA);
        _consumeLiteralTerminator(state);
        pa.irBytes = null;
        return after(_completeAuthenticate(state, socket));
      }
      var crlf = state.lineBuffer.indexOf("\r\n");
      if (crlf === -1) {
        if (safeBuffer.byteLengthOf(state.lineBuffer) > maxLineBytes) {
          _writeNo(socket, "Line too long (cap " + maxLineBytes + ")");
          _close(socket, state);
        }
        return done();
      }
      var rawLine = state.lineBuffer.subarray(0, crlf).toString("utf8");
      state.lineBuffer = state.lineBuffer.subarray(crlf + 2);
      if (state.awaitingLiteralTerminator) {
        state.awaitingLiteralTerminator = false;
        if (rawLine.length === 0) return after(undefined);
      }
      return after(_handleLine(state, socket, rawLine));
    }
    step();
  }

  function _handleLine(state, socket, line) {
    if (state.saslExchange) {
      return _continueSaslExchange(state, socket, line);
    }
    var parsed;
    try {
      parsed = guardManageSieveCommand.validate(line, {
        profile: profile,
        tls:     state.tls,
      });
    } catch (e) {
      _writeNo(socket, (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return;
    }
    try {
      var result = _dispatch(state, socket, parsed);
      if (result && typeof result.then === "function") {
        return result.then(
          function () { /* OK reply already written by handler */ },
          function (e) {
            try {
              _emit("mail.server.managesieve.handler_rejected",
                { connectionId: state.id, verb: parsed && parsed.verb,
                  error: (e && e.message) || String(e) }, "failure");
            } catch (_ae) { /* drop-silent */ }
            try { _writeNo(socket, "Internal error"); }
            catch (_we) { /* socket may already be gone */ }
          }
        );
      }
    } catch (e) {
      _emit("mail.server.managesieve.handler_threw",
        { connectionId: state.id, verb: parsed && parsed.verb,
          error: (e && e.message) || String(e) }, "failure");
      _writeNo(socket, "Internal error");
    }
  }

  var _registry = null;
  function _ensureRegistry() {
    if (_registry !== null) return _registry;
    var SHORT_MS  = 5 * 1000;                                                                        // allow:raw-time-literal — 5s short-command budget
    var MEDIUM_MS = 30 * 1000;                                                                       // allow:raw-time-literal — 30s medium-command budget
    var LONG_MS   = 2 * 60 * 1000;                                                                   // allow:raw-time-literal — 2 min PUTSCRIPT / GETSCRIPT budget
    var SHORT_B   = 8 * 1024;                                                                        // allow:raw-byte-literal — 8 KiB short-command cap
    var MEDIUM_B  = 1024 * 1024;                                                                     // allow:raw-byte-literal — 1 MiB medium-command cap
    var LONG_B    = 16 * 1024 * 1024;                                                                // allow:raw-byte-literal — 16 MiB PUTSCRIPT cap
    var defaults = {
      CAPABILITY:   { fn: function (s, so)    { return _handleCapability(s, so); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      NOOP:         { fn: function (s, so, p) { return _handleNoop(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      STARTTLS:     { fn: function (s, so)    { return _handleStartTls(s, so); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      LOGOUT:       { fn: function (s, so)    { return _handleLogout(s, so); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      AUTHENTICATE: { fn: function (s, so, p) { return _handleAuthenticate(s, so, p); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      HAVESPACE:    { fn: function (s, so, p) { return _handleHaveSpace(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      PUTSCRIPT:    { fn: function (s, so, p) { return _handlePutScript(s, so, p); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      LISTSCRIPTS:  { fn: function (s, so)    { return _handleListScripts(s, so); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      SETACTIVE:    { fn: function (s, so, p) { return _handleSetActive(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      GETSCRIPT:    { fn: function (s, so, p) { return _handleGetScript(s, so, p); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      DELETESCRIPT: { fn: function (s, so, p) { return _handleDeleteScript(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      RENAMESCRIPT: { fn: function (s, so, p) { return _handleRenameScript(s, so, p); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
    };
    _registry = mailServerRegistry.create({
      protocol:        "managesieve",
      defaults:        defaults,
      overrides:       opts.overrides || {},
      tenantScope:     opts.tenantScope    || null,
      agentTenantId:   opts.agentTenantId  || null,
      notFoundHandler: function (verb, _state, socket) {
        return _writeNo(socket, "Unknown verb '" + verb + "'");
      },
    });
    return _registry;
  }

  function _dispatch(state, socket, parsed) {
    return _ensureRegistry().dispatch(parsed.verb, state, socket, parsed);
  }

  function _emitCapabilityBanner(state, socket) {
    socket.write('"IMPLEMENTATION" "blamejs"\r\n');
    socket.write('"VERSION" "1.0"\r\n');
    var sieveCaps = [];
    var known = safeSieve.KNOWN_CAPABILITIES;
    var names = Object.keys(known);
    for (var i = 0; i < names.length; i += 1) {
      if (known[names[i]] === true && names[i].indexOf("comparator-") !== 0) {
        sieveCaps.push(names[i]);
      }
    }
    socket.write('"SIEVE" "' + sieveCaps.join(" ") + '"\r\n');
    if (authConfig && Array.isArray(authConfig.mechanisms) && authConfig.mechanisms.length > 0) {
      var mechs = authConfig.mechanisms.map(function (m) {
        return String(m).toUpperCase();
      }).join(" ");
      socket.write('"SASL" "' + mechs + '"\r\n');
    } else {
      socket.write('"SASL" ""\r\n');
    }
    if (!state.tls && _tlsContext()) {
      socket.write('"STARTTLS"\r\n');
    }
  }

  function _handleCapability(state, socket) {
    _emitCapabilityBanner(state, socket);
    _writeOk(socket, "Capability completed");
  }

  function _handleNoop(state, socket, parsed) {
    void state;
    if (parsed.args.length > 0) {
      _writeOkWithTag(socket, parsed.args[0], "NOOP completed");
    } else {
      _writeOk(socket, "NOOP completed");
    }
  }

  function _handleStartTls(state, socket) {
    if (implicitTls) {
      _writeNo(socket, "STARTTLS not available on implicit-TLS port (RFC 8314)");
      return;
    }
    if (state.tls) {
      _writeNo(socket, "STARTTLS already negotiated");
      return;
    }
    if (state.stage !== "not-authenticated") {
      _writeNo(socket, "STARTTLS only valid pre-AUTH (RFC 5804 §2.2)");
      return;
    }
    var startTlsContext = _tlsContext();
    if (!startTlsContext) {
      _writeNo(socket, "STARTTLS unavailable (listener configured with allowPlaintext=true and no tlsContext)");
      return;
    }
    _writeOk(socket, "Begin TLS negotiation now");
    mailServerTls.upgradeLineProtocol({
      state:         state,
      socket:        socket,
      secureContext: startTlsContext,
      idleTimeoutMs: idleTimeoutMs,
      clearFields:   ["pendingLiteral", "pendingAuth"],
      drain:         _drainBuffer,
      onTimeout: function (tlsSocket) {
        _writeBye(tlsSocket, "Idle timeout");
        _close(tlsSocket, state);
      },
      onSecure: function (tlsSocket) {
        _emit("mail.server.managesieve.starttls_upgraded",
          { connectionId: state.id });
        _emitCapabilityBanner(state, tlsSocket);
        _writeOk(tlsSocket, "TLS negotiation successful");
      },
      onError: function (err) {
        _emit("mail.server.managesieve.starttls_handshake_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _close(socket, state);
      },
    });
  }

  function _handleLogout(state, socket) {
    _emit("mail.server.managesieve.logout",
      { connectionId: state.id });
    _writeOk(socket, "Logout completed");
    _close(socket, state);
  }

  function _handleAuthenticate(state, socket, parsed) {
    if (state.stage !== "not-authenticated") {
      _writeNo(socket, "AUTHENTICATE only valid in NOT-AUTHENTICATED");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeNo(socket, "AUTHENTICATE not configured on this listener");
      return;
    }
    var mech = parsed.args[0];
    var advertised = (authConfig.mechanisms || []).map(function (m) {
      return String(m).toUpperCase();
    });
    if (advertised.indexOf(mech) === -1) {
      _writeNo(socket, "Mechanism '" + mech + "' not advertised");
      return;
    }
    if (!state.tls && profile === "strict" && mech !== "EXTERNAL") {
      _emit("mail.server.managesieve.auth_refused_cleartext",
        { connectionId: state.id, mech: mech }, "denied");
      _writeNo(socket, "AUTHENTICATE " + mech +
        " refused over cleartext (use STARTTLS first; RFC 5804 §1.1 + RFC 4954 §4)");
      return;
    }
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (!authAdmit.ok) {
      _emit("mail.server.managesieve.auth_rate_limit_refused",
        { connectionId: state.id, remoteAddress: state.remoteAddress, reason: authAdmit.reason },
        "denied");
      _writeNo(socket, "Too many AUTH failures from your IP");
      _close(socket, state);
      return;
    }
    state.pendingAuth = {
      mech:    mech,
      irBytes: parsed.literalBytes,
      irPlus:  parsed.literalPlus,
      irBody:  parsed.initialResponse === null || parsed.initialResponse === undefined
        ? Buffer.alloc(0)
        : Buffer.from(parsed.initialResponse, "utf8"),
    };
    if (parsed.literalBytes !== null) {
      state.bodyRateWindow.start(time.monotonicMs(), state.wireBytes - state.lineBuffer.length);
      _armLiteralDeadline(state, socket);
    }
    if (parsed.literalBytes === null) {
      return _completeAuthenticate(state, socket);
    }
    if (!parsed.literalPlus) {
      socket.write("OK\r\n");
    }
  }

  function _parseLiteralMarker(line) {
    if (line.length < 3 || line.charAt(0) !== "{") return null;
    var i = 1;
    var digits = "";
    while (i < line.length && line.charCodeAt(i) >= 0x30 && line.charCodeAt(i) <= 0x39) {
      digits += line.charAt(i);
      i += 1;
      if (digits.length > 9) return null;
    }
    if (digits.length === 0) return null;
    var plus = false;
    if (line.charAt(i) === "+") { plus = true; i += 1; }
    if (line.charAt(i) !== "}" || i !== line.length - 1) return null;
    return { bytes: Number(digits), plus: plus };
  }

  function _completeAuthenticate(state, socket) {
    var pa = state.pendingAuth;
    state.pendingAuth = null;
    _clearLiteralDeadline(state);
    if (!pa) return;
    if (pa.irBody && !_decodesAsUtf8(pa.irBody)) {
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.managesieve.auth_failed",
        { connectionId: state.id, mech: pa.mech, reason: "response-not-utf8" }, "denied");
      _writeNo(socket, "Authentication response is not valid UTF-8");
      return;
    }
    if (pa.resume && state.saslExchange) {
      return _runAuthStep(state, socket, pa.irBody.toString("utf8"));
    }
    _emit("mail.server.managesieve.auth_attempt",
      { connectionId: state.id, mech: pa.mech, remoteAddress: state.remoteAddress });
    state.saslExchange = { mech: pa.mech, step: 0 };
    return _runAuthStep(state, socket,
      pa.irBody.length > 0 ? pa.irBody.toString("utf8") : null);
  }

  function _runAuthStep(state, socket, clientResponse) {
    var ex = state.saslExchange;
    function _fail(reason) {
      state.saslExchange = null;
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.managesieve.auth_failed",
        { connectionId: state.id, mech: ex.mech, reason: reason }, "denied");
      _writeNo(socket, "Authentication failed");
    }
    return mailServerNet.runSaslStep({
      exchange:       ex,
      verify:         authConfig.verify,
      credentials:    { tls: state.tls, remoteAddress: state.remoteAddress },
      clientResponse: clientResponse,
      writeChallenge: function (ch) { return _writeChallenge(socket, ch); },
      onChallengeUnsafe: function () { _fail("challenge-contains-line-terminator"); },
      onSuccess: function (result) {
        state.saslExchange = null;
        state.actor = result.actor;
        state.stage = "authenticated";
        _emit("mail.server.managesieve.auth_success",
          { connectionId: state.id, mech: ex.mech, tenantId: state.actor.tenantId || null });
        _writeOk(socket, "Authenticated");
      },
      onFailure: function (result) { _fail((result && result.reason) || "verify-returned-fail"); },
      onError:   function (err) { _fail((err && err.message) || String(err)); },
    });
  }

  function _writeChallenge(socket, challenge) {
    var safe = mailServerNet.saslChallengeOrNull(challenge);
    if (safe === null) return false;
    try { socket.write("{" + Buffer.byteLength(safe, "utf8") + "}\r\n" + safe + "\r\n"); }
    catch (_e) { /* socket down */ }
    return true;
  }

  function _continueSaslExchange(state, socket, line) {
    var lit = _parseLiteralMarker(line);
    if (lit) {
      if (lit.bytes > guardManageSieveCommand.MAX_SASL_TOKEN_BYTES) {
        var oversizeMech = state.saslExchange.mech;
        state.saslExchange = null;
        rateLimit.noteAuthFailure(state.remoteAddress);
        _emit("mail.server.managesieve.auth_failed",
          { connectionId: state.id, mech: oversizeMech,
            reason: "continuation-literal-too-large" }, "denied");
        _writeNo(socket, "Authentication response too long (cap " +
          guardManageSieveCommand.MAX_SASL_TOKEN_BYTES + ")");
        return;
      }
      state.pendingAuth = {
        mech:    state.saslExchange.mech,
        irBytes: lit.bytes,
        irPlus:  lit.plus,
        irBody:  Buffer.alloc(0),
        resume:  true,
      };
      state.bodyRateWindow.start(time.monotonicMs(), state.wireBytes - state.lineBuffer.length);
      _armLiteralDeadline(state, socket);
      if (!lit.plus) socket.write("OK\r\n");
      return;
    }
    var quoted = guardManageSieveCommand.parseQuotedString(line);
    var body = quoted ? quoted.value : line;
    if (body === "*") {
      state.saslExchange = null;
      _writeNo(socket, "Authentication cancelled");
      return undefined;
    }
    return _runAuthStep(state, socket, body);
  }

  function _requireAuth(state, socket) {
    if (state.stage !== "authenticated") {
      _writeNo(socket, "AUTHENTICATE first");
      return false;
    }
    return true;
  }

  function _handleHaveSpace(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    var size = parsed.args[1];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.haveSpace(state.actor, name, size); })
      .then(function (result) {
        var ok = result && result.ok !== false;
        _emit("mail.server.managesieve.havespace",
          { connectionId: state.id, name: name, size: size, ok: ok });
        if (ok) {
          _writeOk(socket, "Have space");
        } else {
          _writeNo(socket, "(QUOTA/MAXSIZE) " + ((result && result.reason) || "no space"));
        }
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "haveSpace failed").slice(0, ERR_CLAMP));
      });
  }

  function _handlePutScript(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    var size = parsed.literalBytes;
    var plus = parsed.literalPlus;
    state.pendingLiteral = {
      verb: "PUTSCRIPT",
      name: name,
      size: size,
      plus: plus,
      body: Buffer.alloc(0),
    };
    state.bodyRateWindow.start(time.monotonicMs(), state.wireBytes - state.lineBuffer.length);
    _armLiteralDeadline(state, socket);
    if (!plus) {
      socket.write("OK\r\n");
    }
  }

  function _completePutscript(state, socket, literal) {
    var bodyText = literal.body.toString("utf8");
    if (!_decodesAsUtf8(literal.body)) {
      _emit("mail.server.managesieve.putscript_refused",
        { connectionId: state.id, name: literal.name,
          reason: "script-not-utf8" }, "denied");
      _writeNo(socket, "Script is not valid UTF-8 (RFC 5804 section 1.6)");
      return;
    }
    var v;
    try {
      v = safeSieve.validate(bodyText, { profile: safeSieveProfile });
    } catch (e) {
      _emit("mail.server.managesieve.putscript_refused",
        { connectionId: state.id, name: literal.name,
          reason: (e && e.code) || "safe-sieve/parse-error" }, "denied");
      _writeNo(socket, "(QUOTA/MAXSIZE) " + ((e && e.message) || "validation failed").slice(0, ERR_CLAMP));
      return;
    }
    if (!v.ok) {
      var issue = (v.issues && v.issues[0]) || { ruleId: "safe-sieve/parse-error", snippet: "invalid" };
      _emit("mail.server.managesieve.putscript_refused",
        { connectionId: state.id, name: literal.name, reason: issue.ruleId }, "denied");
      _writeNo(socket, "Script validation failed: " + (issue.snippet || issue.ruleId).slice(0, ERR_CLAMP));
      return;
    }
    return Promise.resolve()
      .then(function () {
        return mailStore.sieveScripts.put(state.actor, literal.name, bodyText, {
          requiredCaps: v.requiredCaps,
        });
      })
      .then(function () {
        _emit("mail.server.managesieve.putscript",
          { connectionId: state.id, name: literal.name, bytes: literal.size,
            requiredCaps: v.requiredCaps });
        _writeOk(socket, "PUTSCRIPT completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "PUTSCRIPT failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleListScripts(state, socket) {
    if (!_requireAuth(state, socket)) return;
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.list(state.actor); })
      .then(function (scripts) {
        var list = Array.isArray(scripts) ? scripts : [];
        for (var i = 0; i < list.length; i += 1) {
          var s = list[i];
          var nm = String(s.name || "");
          var active = s.active === true ? " ACTIVE" : "";
          socket.write(safeBuffer.quoteString(nm) + active + "\r\n");
        }
        _emit("mail.server.managesieve.listscripts",
          { connectionId: state.id, count: list.length });
        _writeOk(socket, "LISTSCRIPTS completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "LISTSCRIPTS failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleSetActive(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.setActive(state.actor, name); })
      .then(function () {
        _emit("mail.server.managesieve.setactive",
          { connectionId: state.id, name: name });
        _writeOk(socket, "SETACTIVE completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "SETACTIVE failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleGetScript(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.get(state.actor, name); })
      .then(function (script) {
        if (!script) {
          _writeNo(socket, "(NONEXISTENT) Script not found");
          return;
        }
        var body = String(script.body || "");
        var bytes = Buffer.byteLength(body, "utf8");
        socket.write("{" + bytes + "}\r\n");
        socket.write(body);
        socket.write("\r\n");
        _emit("mail.server.managesieve.getscript",
          { connectionId: state.id, name: name, bytes: bytes });
        _writeOk(socket, "GETSCRIPT completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "GETSCRIPT failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleDeleteScript(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var name = parsed.args[0];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.delete(state.actor, name); })
      .then(function () {
        _emit("mail.server.managesieve.delete",
          { connectionId: state.id, name: name });
        _writeOk(socket, "DELETESCRIPT completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "DELETESCRIPT failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleRenameScript(state, socket, parsed) {
    if (!_requireAuth(state, socket)) return;
    var oldName = parsed.args[0];
    var newName = parsed.args[1];
    return Promise.resolve()
      .then(function () { return mailStore.sieveScripts.rename(state.actor, oldName, newName); })
      .then(function () {
        _emit("mail.server.managesieve.rename",
          { connectionId: state.id, old: oldName, "new": newName });
        _writeOk(socket, "RENAMESCRIPT completed");
      })
      .catch(function (err) {
        _writeNo(socket, ((err && err.message) || "RENAMESCRIPT failed").slice(0, ERR_CLAMP));
      });
  }

  function _writeOk(socket, msg) {
    try { socket.write("OK " + safeBuffer.quoteString(msg) + "\r\n"); } catch (_e) { /* socket down */ }
  }
  function _writeOkWithTag(socket, tag, msg) {
    try { socket.write("OK (TAG " + safeBuffer.quoteString(tag) + ") " + safeBuffer.quoteString(msg) + "\r\n"); }
    catch (_e) { /* socket down */ }
  }
  function _writeNo(socket, msg) {
    try { socket.write("NO " + safeBuffer.quoteString(msg) + "\r\n"); } catch (_e) { /* socket down */ }
  }
  function _writeBye(socket, msg) {
    try { socket.write("BYE " + safeBuffer.quoteString(msg) + "\r\n"); } catch (_e) { /* socket down */ }
  }
  function _close(socket, state) {
    if (state) {
      state.closed = true;
      state.lineBuffer = Buffer.alloc(0);
    }
    mailServerNet.destroySocketAfterFlush(socket);
  }

  return mailServerNet.createStoreServer(net, {
    defaultPort:      DEFAULT_PORT,
    listeningExtra:   function () { return { implicitTls: implicitTls }; },
    maxConnections:   opts.maxConnections,
    handleConnection: _handleConnection,
    errorClass:       MailServerManageSieveError,
    errorCodePrefix:  "mail-server-managesieve/",
    emit:             _emit,
    connections:      connections,
    eventBase:        "mail.server.managesieve",
  });
}

module.exports = {
  create:                       create,
  MailServerManageSieveError:   MailServerManageSieveError,
};

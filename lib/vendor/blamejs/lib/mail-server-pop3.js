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
 *   - **Slow-loris on RETR / TOP** — per-connection `idleTimeoutMs`
 *     bounds dead connections; `b.mail.server.rateLimit.minBytesPerSecond`
 *     bounds trickle-receive class.
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
var lazyRequire = require("./lazy-require");
var C = require("./constants");
var bCrypto = require("./crypto");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardPop3Command = require("./guard-pop3-command");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerTls = require("./mail-server-tls");
var safeSmtp = require("./safe-smtp");
var safeAsync = require("./safe-async");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var MailServerPop3Error = defineClass("MailServerPop3Error", { alwaysPermanent: true });

var DEFAULT_MAX_LINE_BYTES   = 1024;                                                                  // RFC 2449 §4 line cap (permissive)
var DEFAULT_IDLE_TIMEOUT_MS  = C.TIME.minutes(10);
// RFC 1939 §6 — UPDATE-state commit (the actual delete on QUIT) is
// the only place the backend writes; a hung commitPop3Drop leaves
// the connection in update-state forever, defeating the idle timeout
// (the socket is awaiting the .then(), not blocked on socket I/O).
// Bound the commit; on timeout the connection closes with -ERR and
// the next session re-attempts the commit.
var DEFAULT_COMMIT_TIMEOUT_MS = C.TIME.seconds(30);
var DEFAULT_GREETING_VENDOR  = "blamejs POP3";

var ERR_CLAMP = 200;                                                                                  // protocol-reply error-message clamp

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
 *   greeting:          string,                   // default "blamejs POP3"
 *   maxLineBytes:      number,                   // default 1024
 *   idleTimeoutMs:     number,                   // default 10 min
 *   commitTimeoutMs:   number,                   // default 30 s (UPDATE-state mailStore.commitPop3Drop cap)
 *   profile:           "strict" | "balanced" | "permissive",
 *   auth: {
 *     mechanisms:      ["PLAIN"],                 // SASL mechs to advertise
 *     verify:          async function (mech, credentials) → { ok, actor },
 *   },
 *   mailStore:         b.mailStore handle,
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
 *     mailStore: b.mailStore.create({ backend: b.db.handle() }),
 *   });
 *   await pop3.listen({ port: 110 });
 */
function create(opts) {
  validateOpts.requireObject(opts, "mail.server.pop3.create",
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
    ["maxLineBytes", "idleTimeoutMs", "commitTimeoutMs"],
    "mail.server.pop3.", MailServerPop3Error, "mail-server-pop3/bad-bound");

  var greeting        = opts.greeting        || DEFAULT_GREETING_VENDOR;
  var maxLineBytes    = opts.maxLineBytes    || DEFAULT_MAX_LINE_BYTES;
  var idleTimeoutMs   = opts.idleTimeoutMs   || DEFAULT_IDLE_TIMEOUT_MS;
  var commitTimeoutMs = opts.commitTimeoutMs || DEFAULT_COMMIT_TIMEOUT_MS;
  var profile         = opts.profile         || "strict";
  var authConfig      = opts.auth            || null;
  var mailStore       = opts.mailStore;
  // b.agent.tenant adoption (v0.10.12) — cross-tenant authentication
  // is refused at the AUTH-success boundary BEFORE the listener
  // accepts the actor into transaction state. The scope's `.check`
  // method is validated at create() time so a malformed scope object
  // surfaces as a configuration error rather than rejecting every
  // otherwise-valid auth as "cross-tenant".
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

  var rateLimit;
  if (opts.rateLimit === false) {
    rateLimit = mailServerRateLimit.create({ disabled: true });
  } else if (opts.rateLimit && typeof opts.rateLimit.admitConnection === "function") {
    rateLimit = opts.rateLimit;
  } else {
    rateLimit = mailServerRateLimit.create(opts.rateLimit || {});
  }

  var tcpServer = null;
  var listening = false;
  var connections = new Set();

  function _emit(action, metadata, outcome) {
    try {
      audit().safeEmit({
        action: action,
        outcome: outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  function _handleConnection(rawSocket) {
    var remoteAddress = rawSocket.remoteAddress || "0.0.0.0";
    var admit = rateLimit.admitConnection(remoteAddress);
    if (!admit.ok) {
      _emit("mail.server.pop3.rate_limit_refused",
        { remoteAddress: remoteAddress, reason: admit.reason }, "denied");
      try { rawSocket.write("-ERR Too many connections from your IP\r\n"); }
      catch (_e) { /* socket may be down */ }
      try { rawSocket.destroy(); } catch (_e2) { /* idempotent */ }
      return;
    }
    var connectionId = "pop3conn-" + bCrypto.generateToken(8);                                       // connection-id length
    var socket = rawSocket;
    connections.add(socket);
    // Single close handler covers BOTH operator-driven `_close(socket)`
    // and client-initiated disconnects (TCP FIN / RST without a
    // server-side close call) — releases the rate-limit slot AND
    // removes the socket from the tracking set so it can't accumulate
    // stale entries across long-lived deployments.
    rawSocket.once("close", function () {
      rateLimit.releaseConnection(remoteAddress);
      connections.delete(socket);
    });

    var state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      tls:           false,
      stage:         "authorization",
      actor:         null,
      tentativeUser: null,           // USER name pending PASS
      dropId:        null,           // mailStore-issued drop handle on TRANSACTION entry
      lineBuffer:    Buffer.alloc(0),
    };

    _emit("mail.server.pop3.connect",
      { connectionId: connectionId, remoteAddress: remoteAddress });

    socket.setTimeout(idleTimeoutMs);
    socket.on("timeout", function () {
      _writeErr(socket, "Idle timeout");
      _close(socket);
    });
    socket.on("error", function (err) {
      _emit("mail.server.pop3.socket_error",
        { connectionId: connectionId, error: (err && err.message) || String(err) }, "failure");
    });

    _writeOk(socket, greeting + " ready");

    socket.on("data", function (chunk) {
      state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
      _drainBuffer(state, socket);
    });
  }

  function _drainBuffer(state, socket) {
    while (true) {
      var crlf = state.lineBuffer.indexOf("\r\n");
      if (crlf === -1) {
        if (state.lineBuffer.length > maxLineBytes) {
          _writeErr(socket, "Line too long (cap " + maxLineBytes + ")");
          _close(socket);
        }
        return;
      }
      var rawLine = state.lineBuffer.subarray(0, crlf).toString("utf8");
      state.lineBuffer = state.lineBuffer.subarray(crlf + 2);
      _handleLine(state, socket, rawLine);
      if (state.stage === "closed") return;
    }
  }

  function _handleLine(state, socket, line) {
    var parsed;
    try {
      parsed = guardPop3Command.validate(line, {
        profile: profile,
        tls:     state.tls,
      });
    } catch (e) {
      _writeErr(socket, (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return;
    }
    _dispatch(state, socket, parsed);
  }

  function _dispatch(state, socket, parsed) {
    var verb = parsed.verb;
    var args = parsed.args;
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
    // Advertise AUTH mechanisms ONLY when wired
    // (do not hardcode SASL mechs in caps).
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
    if (state.tls) {
      _writeErr(socket, "STLS already negotiated");
      return;
    }
    // RFC 2595 §4 — STLS is only valid in AUTHORIZATION state. Once
    // a session has reached TRANSACTION (authenticated, with a drop
    // lock against the mailbox), a TLS upgrade mid-session would
    // re-key without re-authenticating and produce undefined
    // behaviour against open mailbox state.
    if (state.stage !== "authorization") {
      _writeErr(socket, "STLS only valid in AUTHORIZATION (RFC 2595 §4)");
      return;
    }
    _writeOk(socket, "Begin TLS negotiation");
    // Drain pre-handshake buffer (RFC 2595 §4 + CVE-2021-33515 class
    // STLS-injection defense — any pipelined commands the client
    // queued before the upgrade are discarded; post-TLS reads fresh).
    // Listener-removal + idle-timeout re-arm live in the shared
    // upgradeSocket helper (b.mail.server.tls.upgradeSocket).
    state.lineBuffer = Buffer.alloc(0);
    // POP3 doesn't have an authPending shape (the SASL state is local
    // to _handleAuth), but reset tentativeUser so a USER pipelined
    // pre-handshake cannot bind a post-handshake PASS.
    state.tentativeUser = null;
    mailServerTls.upgradeSocket({
      plainSocket:   socket,
      secureContext: opts.tlsContext,
      idleTimeoutMs: idleTimeoutMs,
      onSecure: function (_tlsSocket) { state.tls = true; },
      onData: function (tlsSocket, chunk) {
        state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
        _drainBuffer(state, tlsSocket);
      },
      onError: function (err) {
        _emit("mail.server.pop3.tls_handshake_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _close(socket);
      },
      onTimeout: function (tlsSocket) {
        _writeErr(tlsSocket, "Idle timeout");
        _close(tlsSocket);
      },
    });
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
    // RFC 2595 §2.1 defense-in-depth — the guardPop3Command validator
    // refuses USER over cleartext under strict at the wire boundary,
    // but balanced/permissive operators previously reached this path
    // and accepted a plaintext password. Refuse here too so a guard
    // relax doesn't open (cleartext credentials in
    // POP3 USER/PASS) by composition. Permissive operators opt out
    // by explicitly setting profile: "permissive".
    if (!state.tls && profile !== "permissive") {
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
    // refuse PASS over cleartext when not permissive.
    // USER already gated above, but this is defense-in-depth in case the
    // USER guard was bypassed by a future codepath.
    if (!state.tls && profile !== "permissive") {
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "PASS", remoteAddress: state.remoteAddress },
        "denied");
      rateLimit.noteAuthFailure(state.remoteAddress);
      _writeErr(socket, "PASS refused over cleartext (use STLS first; RFC 2595 §2.1)");
      return;
    }
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (!authAdmit.ok) {
      _emit("mail.server.pop3.auth_rate_limit_refused",
        { connectionId: state.id, remoteAddress: state.remoteAddress, reason: authAdmit.reason },
        "denied");
      _writeErr(socket, "Too many AUTH failures from your IP");
      _close(socket);
      return;
    }
    var username = state.tentativeUser;
    state.tentativeUser = null;
    var password = args[0];
    _emit("mail.server.pop3.auth_attempt",
      { connectionId: state.id, verb: "PASS", remoteAddress: state.remoteAddress });
    Promise.resolve()
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
          _enterTransaction(state, socket, "PASS");
          return;
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
    // The validator already refuses APOP under strict; this just
    // means the operator opted into balanced/permissive. Treat as
    // username+digest and delegate to authConfig.verify with the APOP
    // mechanism name.
    if (state.stage !== "authorization") {
      _writeErr(socket, "APOP only valid in AUTHORIZATION");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeErr(socket, "AUTH not configured");
      return;
    }
    // Defense-in-depth, symmetric with USER / PASS. APOP transmits
    // MD5(timestamp+secret), not cleartext, but an
    // attacker who captures the digest + the known greeting timestamp
    // can mount an offline dictionary attack against the shared secret.
    // RFC 1939 §7 explicitly warns about this; balanced/permissive
    // operators reach this path only when they opted in, but the
    // wire MUST be TLS-protected to deny the offline-attack vector.
    if (!state.tls && profile !== "permissive") {
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "APOP", remoteAddress: state.remoteAddress },
        "denied");
      rateLimit.noteAuthFailure(state.remoteAddress);
      _writeErr(socket, "APOP refused over cleartext (use STLS first; RFC 1939 §7)");
      return;
    }
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (!authAdmit.ok) {
      _writeErr(socket, "Too many AUTH failures from your IP");
      _close(socket);
      return;
    }
    Promise.resolve()
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
          _enterTransaction(state, socket, "APOP");
          return;
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
      // RFC 5034 — `AUTH` alone enumerates mechanisms
      _writeOk(socket, "Supported mechanisms follow");
      var mechs = (authConfig.mechanisms || ["PLAIN"]).map(function (m) {
        return String(m).toUpperCase();
      });
      for (var i = 0; i < mechs.length; i += 1) socket.write(mechs[i] + "\r\n");
      socket.write(".\r\n");
      return;
    }
    // RFC 2595 §2.1 + RFC 5034 §4 — refuse mech-bearing AUTH over
    // cleartext under strict (defense-in-depth — guardPop3Command
    // refuses at the validate boundary, this catches any
    // configuration where the gate was relaxed but the AUTH path
    // still receives traffic).
    if (!state.tls && profile === "strict") {
      // Count cleartext-AUTH refusal against the auth-failure budget
      // so scanners that probe for plaintext-mech tolerance hit the
      // same per-IP cap that protects PASS / APOP. Without this, a
      // scanner could enumerate auth mechanisms freely (the refusal
      // itself was free) and shop for the first wire-protocol path
      // the listener honored.
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.pop3.auth_refused_cleartext",
        { connectionId: state.id, verb: "AUTH", mech: args[0] }, "denied");
      _writeErr(socket, "AUTH refused over cleartext (use STLS first; RFC 2595 §2.1)");
      return;
    }
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (!authAdmit.ok) {
      _writeErr(socket, "Too many AUTH failures from your IP");
      _close(socket);
      return;
    }
    var mech = args[0].toUpperCase();
    var initialResp = args.length > 1 ? args.slice(1).join(" ") : null;
    Promise.resolve()
      .then(function () {
        return authConfig.verify(mech, {
          clientResponse: initialResp,
          tls:            state.tls,
          remoteAddress:  state.remoteAddress,
        });
      })
      .then(function (result) {
        if (result && result.ok && result.actor) {
          if (!_assertTenantOrRefuse(state, socket, result)) return;
          state.actor = result.actor;
          _enterTransaction(state, socket, "AUTH/" + mech);
          return;
        }
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeErr(socket, "Authentication failed");
      })
      .catch(function () {
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeErr(socket, "Authentication failed");
      });
  }

  function _enterTransaction(state, socket, verb) {
    if (typeof mailStore.openPop3Drop !== "function") {
      _writeErr(socket, "Backend missing openPop3Drop");
      return;
    }
    Promise.resolve()
      .then(function () { return mailStore.openPop3Drop(state.actor, {}); })
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
      _close(socket);
      return;
    }
    state.stage = "update";
    // RFC 1939 §6 — bound the UPDATE-state commit. A hung backend
    // (DB row-lock / replica failover / sealed-row unseal stuck on a
    // KMS call) otherwise leaves the connection in update-state past
    // the socket idleTimeoutMs (which guards inbound bytes, not
    // pending Promises).
    safeAsync.withTimeout(
      Promise.resolve().then(function () {
        return mailStore.commitPop3Drop(state.actor, state.dropId);
      }),
      commitTimeoutMs,
      { label: "mail.server.pop3.commitPop3Drop" }
    )
      .then(function (info) {
        _emit("mail.server.pop3.update_commit",
          { connectionId: state.id, deleted: (info && info.deleted) || 0 });
        _writeOk(socket, "Goodbye");
        _close(socket);
      })
      .catch(function (err) {
        _emit("mail.server.pop3.update_commit_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _writeErr(socket, "Commit failed: " + ((err && err.message) || "backend error").slice(0, ERR_CLAMP));
        _close(socket);
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
    Promise.resolve()
      .then(function () { return mailStore.listMessages(state.actor, state.dropId); })
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
    Promise.resolve()
      .then(function () { return mailStore.listMessages(state.actor, state.dropId); })
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
    Promise.resolve()
      .then(function () { return mailStore.getMessage(state.actor, state.dropId, msgNum, {}); })
      .then(function (msg) {
        if (!msg) { _writeErr(socket, "no such message"); return; }
        _emit("mail.server.pop3.retr",
          { connectionId: state.id, msgNum: msgNum, size: msg.size });
        _writeOk(socket, msg.size + " octets");
        // RFC 1939 §3 dot-stuffing — lines starting with `.` get a
        // doubled `.` so the receiver doesn't mistake them for the
        // CRLF.CRLF terminator. The `/^\./gm` regex on a JS string
        // treats bare LF as a line boundary (matches `\n.` and
        // `\r\n.`), so a body containing a bare-LF line that starts
        // with `.` gained spurious stuffing that didn't match the
        // receiver's strict-CRLF parser. Route through safeSmtp.dotStuff
        // which inspects the raw Buffer and only treats canonical
        // \r\n as a line boundary (bare LF is left alone — the
        // guardSmtpCommand.detectBodySmuggling layer catches bare-LF
        // smuggling at the upstream parse).
        var bodyBuf = msg.rawBytes
          ? msg.rawBytes
          : Buffer.from(msg.text || "", "utf8");
        var stuffed = safeSmtp.dotStuff(bodyBuf);
        socket.write(stuffed);
        // RFC 1939 §3 requires a CRLF before the terminator. The body
        // may already end with CRLF; write one only when it doesn't.
        if (stuffed.length === 0 ||
            stuffed[stuffed.length - 2] !== 0x0d /* CR */ ||
            stuffed[stuffed.length - 1] !== 0x0a /* LF */) {
          socket.write("\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "retr failed").slice(0, ERR_CLAMP)); });
  }

  function _handleDele(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    var msgNum = parseInt(args[0], 10);
    Promise.resolve()
      .then(function () { return mailStore.markDelete(state.actor, state.dropId, msgNum); })
      .then(function () {
        _emit("mail.server.pop3.dele",
          { connectionId: state.id, msgNum: msgNum });
        _writeOk(socket, "marked deleted");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "dele failed").slice(0, ERR_CLAMP)); });
  }

  function _handleRset(state, socket) {
    if (!_requireTrans(state, socket)) return;
    Promise.resolve()
      .then(function () {
        if (typeof mailStore.resetPop3Drop === "function") {
          return mailStore.resetPop3Drop(state.actor, state.dropId);
        }
      })
      .then(function () { _writeOk(socket, "delete marks cleared"); })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "rset failed").slice(0, ERR_CLAMP)); });
  }

  function _handleTop(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    var msgNum = parseInt(args[0], 10);
    var headerLines = parseInt(args[1], 10);
    Promise.resolve()
      .then(function () {
        return mailStore.getMessage(state.actor, state.dropId, msgNum,
          { headersOnly: true, headerLines: headerLines });
      })
      .then(function (msg) {
        if (!msg) { _writeErr(socket, "no such message"); return; }
        _writeOk(socket, "headers + " + headerLines + " body lines");
        // see _handleRetr; same byte-level CRLF-aware
        // dot-stuffing primitive for the TOP partial-body path.
        var bodyBuf = msg.rawBytes
          ? msg.rawBytes
          : Buffer.from(msg.text || "", "utf8");
        var stuffed = safeSmtp.dotStuff(bodyBuf);
        socket.write(stuffed);
        if (stuffed.length === 0 ||
            stuffed[stuffed.length - 2] !== 0x0d /* CR */ ||
            stuffed[stuffed.length - 1] !== 0x0a /* LF */) {
          socket.write("\r\n");
        }
        socket.write(".\r\n");
      })
      .catch(function (err) { _writeErr(socket, ((err && err.message) || "top failed").slice(0, ERR_CLAMP)); });
  }

  function _handleUidl(state, socket, args) {
    if (!_requireTrans(state, socket)) return;
    Promise.resolve()
      .then(function () { return mailStore.listMessages(state.actor, state.dropId); })
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
  function _close(socket) {
    try { socket.end(); } catch (_e) { /* idempotent */ }
    try { socket.destroy(); } catch (_e2) { /* idempotent */ }
    connections.delete(socket);
  }

  // ---- Lifecycle ----------------------------------------------------------
  async function listen(listenOpts) {
    listenOpts = listenOpts || {};
    if (listening) {
      throw new MailServerPop3Error("mail-server-pop3/already-listening",
        "listen: already listening");
    }
    var port    = listenOpts.port    === undefined ? 110 : listenOpts.port;                          // RFC 1939 POP3 port (IANA)
    var address = listenOpts.address || "0.0.0.0";
    tcpServer = net.createServer(function (socket) { _handleConnection(socket); });
    return new Promise(function (resolve, reject) {
      tcpServer.once("error", reject);
      tcpServer.listen(port, address, function () {
        listening = true;
        tcpServer.removeListener("error", reject);
        _emit("mail.server.pop3.listening", { port: port, address: address });
        resolve({ port: tcpServer.address().port, address: address });
      });
    });
  }

  async function close() {
    if (!listening) return;
    listening = false;
    for (var s of connections) { try { s.destroy(); } catch (_e) { /* idempotent */ } }
    connections.clear();
    return new Promise(function (resolve) {
      tcpServer.close(function () {
        _emit("mail.server.pop3.closed", {});
        resolve();
      });
    });
  }

  return {
    listen:               listen,
    close:                close,
  };
}

module.exports = {
  create:               create,
  MailServerPop3Error:  MailServerPop3Error,
};

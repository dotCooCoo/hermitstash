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
 *     (avoids the IMAP v0.9.49 Codex P2 class — advertising AUTH=PLAIN
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
 *     `SieveScript/validate` (RFC 9404). The MTA-side ManageSieve
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
var mailServerTls = require("./mail-server-tls");
var lazyRequire = require("./lazy-require");
var C = require("./constants");
var bCrypto = require("./crypto");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardManageSieveCommand = require("./guard-managesieve-command");
var safeSieve = require("./safe-sieve");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerRegistry = require("./mail-server-registry");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var MailServerManageSieveError = defineClass("MailServerManageSieveError",
  { alwaysPermanent: true });

// RFC 5804 §1 default port (IANA-assigned).
var DEFAULT_PORT             = 4190;                                                                    // allow:raw-byte-literal — RFC 5804 §1 / IANA managesieve port
var DEFAULT_MAX_LINE_BYTES   = 8192;                                                                    // allow:raw-byte-literal — matches guardManageSieveCommand strict cap
var DEFAULT_IDLE_TIMEOUT_MS  = C.TIME.minutes(5);
var DEFAULT_GREETING_VENDOR  = "blamejs ManageSieve";

var ERR_CLAMP                = 200;                                                                     // allow:raw-byte-literal — protocol-reply error-message clamp

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
 *   allowPlaintext:    boolean,                              // explicit opt-in; emits warning audit
 *   greeting:          string,                               // default "blamejs ManageSieve"
 *   maxLineBytes:      number,                               // default 8192
 *   idleTimeoutMs:     number,                               // default 5 min
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
 *     mailStore: b.mailStore.create({ backend: b.db.handle() }),
 *   });
 *   await msv.listen({ port: 4190 });
 */
function create(opts) {
  validateOpts.requireObject(opts, "mail.server.managesieve.create",
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
    ["maxLineBytes", "idleTimeoutMs"],
    "mail.server.managesieve.", MailServerManageSieveError, "mail-server-managesieve/bad-bound");

  var greeting       = opts.greeting       || DEFAULT_GREETING_VENDOR;
  var maxLineBytes   = opts.maxLineBytes   || DEFAULT_MAX_LINE_BYTES;
  var idleTimeoutMs  = opts.idleTimeoutMs  || DEFAULT_IDLE_TIMEOUT_MS;
  var profile        = opts.profile        || "strict";
  var authConfig     = opts.auth           || null;
  var mailStore      = opts.mailStore;
  var allowPlaintext = opts.allowPlaintext === true;
  var tlsContext     = opts.tlsContext     || null;

  // safeSieve cap matches the guard's per-profile script cap (the
  // guard caps the literal-byte announcement; safeSieve.parse caps
  // the actual script bytes — same cap on both sides).
  var safeSieveProfile = profile;

  var rateLimit;
  if (opts.rateLimit === false) {
    rateLimit = mailServerRateLimit.create({ disabled: true });
  } else if (opts.rateLimit && typeof opts.rateLimit.admitConnection === "function") {
    rateLimit = opts.rateLimit;
  } else {
    rateLimit = mailServerRateLimit.create(opts.rateLimit || {});
  }

  var tcpServer   = null;
  var listening   = false;
  var connections = new Set();

  function _emit(action, metadata, outcome) {
    try {
      audit().safeEmit({
        action:   action,
        outcome:  outcome || "success",
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent — audit best-effort */ }
  }

  function _handleConnection(rawSocket) {
    var remoteAddress = rawSocket.remoteAddress || "0.0.0.0";
    var admit = rateLimit.admitConnection(remoteAddress);
    if (!admit.ok) {
      _emit("mail.server.managesieve.rate_limit_refused",
        { remoteAddress: remoteAddress, reason: admit.reason }, "denied");
      try { rawSocket.write('NO "Too many connections from your IP"\r\n'); }
      catch (_e) { /* socket may be down */ }
      try { rawSocket.destroy(); } catch (_e2) { /* idempotent */ }
      return;
    }
    var connectionId = "msvconn-" + bCrypto.generateToken(8);                                            // allow:raw-byte-literal — connection-id length
    var socket = rawSocket;
    connections.add(socket);
    // Single close handler covers BOTH operator-driven `_close(socket)`
    // and client-initiated disconnects (TCP FIN / RST). Releases the
    // rate-limit slot AND removes the socket from the tracking set so
    // long-lived deployments don't accumulate stale entries.
    rawSocket.once("close", function () {
      rateLimit.releaseConnection(remoteAddress);
      connections.delete(socket);
    });

    var state = {
      id:              connectionId,
      remoteAddress:   remoteAddress,
      tls:             false,
      stage:           "not-authenticated",
      actor:           null,
      pendingLiteral:  null,         // { verb, name, size, body, plus }
      pendingAuth:     null,         // { mech, irBytes, irPlus, irBody }
      lineBuffer:      Buffer.alloc(0),
    };

    _emit("mail.server.managesieve.connect",
      { connectionId: connectionId, remoteAddress: remoteAddress });

    socket.setTimeout(idleTimeoutMs);
    socket.on("timeout", function () {
      _writeBye(socket, "Idle timeout");
      _close(socket);
    });
    socket.on("error", function (err) {
      _emit("mail.server.managesieve.socket_error",
        { connectionId: connectionId, error: (err && err.message) || String(err) }, "failure");
    });

    // Unsolicited capability banner per RFC 5804 §1.7 — capabilities
    // first, then `OK "<greeting>"`.
    _emitCapabilityBanner(state, socket);
    _writeOk(socket, greeting + " ready");

    if (allowPlaintext && !tlsContext) {
      _emit("mail.server.managesieve.plaintext_warning",
        { connectionId: connectionId,
          remark: "allowPlaintext=true; no STARTTLS available — operators MUST gate at network layer" },
        "warning");
    }

    socket.on("data", function (chunk) {
      state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
      _drainBuffer(state, socket);
    });
  }

  // _drainBuffer — line-oriented dispatch with literal-payload windows.
  // When the previous command opened a literal (PUTSCRIPT, or
  // AUTHENTICATE with a non-synchronizing initial-response), the next
  // N bytes are the literal-payload; accumulate them before resuming
  // line-mode dispatch.
  function _drainBuffer(state, socket) {
    while (true) {
      if (state.pendingLiteral) {
        var pl = state.pendingLiteral;
        var need = pl.size - pl.body.length;
        if (state.lineBuffer.length < need) {
          pl.body = Buffer.concat([pl.body, state.lineBuffer]);
          state.lineBuffer = Buffer.alloc(0);
          return;
        }
        pl.body = Buffer.concat([pl.body, state.lineBuffer.subarray(0, need)]);
        state.lineBuffer = state.lineBuffer.subarray(need);
        state.pendingLiteral = null;
        _completePutscript(state, socket, pl);
        if (state.stage === "closed") return;
        continue;
      }
      if (state.pendingAuth && state.pendingAuth.irBytes !== null) {
        var pa = state.pendingAuth;
        var needA = pa.irBytes - pa.irBody.length;
        if (state.lineBuffer.length < needA) {
          pa.irBody = Buffer.concat([pa.irBody, state.lineBuffer]);
          state.lineBuffer = Buffer.alloc(0);
          return;
        }
        pa.irBody = Buffer.concat([pa.irBody, state.lineBuffer.subarray(0, needA)]);
        state.lineBuffer = state.lineBuffer.subarray(needA);
        // After literal-IR is gathered, expect CRLF terminator.
        pa.irBytes = null;
        _completeAuthenticate(state, socket);
        if (state.stage === "closed") return;
        continue;
      }
      var crlf = state.lineBuffer.indexOf("\r\n");
      if (crlf === -1) {
        if (state.lineBuffer.length > maxLineBytes) {
          _writeNo(socket, "Line too long (cap " + maxLineBytes + ")");
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
      // Registry dispatch may return a Promise (async override handler
      // or safeAsync.withTimeout-wrapped Promise). The synchronous
      // try/catch above only catches throw-during-dispatch; Promise
      // rejections need an attached catch to avoid unhandled-rejection
      // termination + missing NO reply.
      if (result && typeof result.then === "function") {
        result.then(
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
      // b.agent.tenant adoption (v0.10.12) — see imap factory for the
      // shape.
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

  // _emitCapabilityBanner — RFC 5804 §1.7 capability banner. Lines
  // are quoted-string identifiers, optionally followed by a quoted-
  // string value. The framework emits IMPLEMENTATION / SASL / SIEVE /
  // VERSION / STARTTLS (when pre-TLS) — no terminator line; the
  // listener emits a closing `OK` per §1.7.
  function _emitCapabilityBanner(state, socket) {
    socket.write('"IMPLEMENTATION" "blamejs"\r\n');
    socket.write('"VERSION" "1.0"\r\n');
    // Advertise the Sieve extensions safeSieve currently implements.
    // Keep in lockstep with safeSieve.KNOWN_CAPABILITIES — any entry
    // with `true` is exposed.
    var sieveCaps = [];
    var known = safeSieve.KNOWN_CAPABILITIES;
    var names = Object.keys(known);
    for (var i = 0; i < names.length; i += 1) {
      if (known[names[i]] === true && names[i].indexOf("comparator-") !== 0) {
        sieveCaps.push(names[i]);
      }
    }
    socket.write('"SIEVE" "' + sieveCaps.join(" ") + '"\r\n');
    // Advertise SASL mechanisms — ONLY the mechs the operator wired
    // in opts.auth.mechanisms (Codex P2 IMAP lesson: don't hardcode).
    if (authConfig && Array.isArray(authConfig.mechanisms) && authConfig.mechanisms.length > 0) {
      var mechs = authConfig.mechanisms.map(function (m) {
        return String(m).toUpperCase();
      }).join(" ");
      socket.write('"SASL" "' + mechs + '"\r\n');
    } else {
      socket.write('"SASL" ""\r\n');
    }
    if (!state.tls && tlsContext) {
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
    if (state.tls) {
      _writeNo(socket, "STARTTLS already negotiated");
      return;
    }
    if (state.stage !== "not-authenticated") {
      _writeNo(socket, "STARTTLS only valid pre-AUTH (RFC 5804 §2.2)");
      return;
    }
    if (!tlsContext) {
      _writeNo(socket, "STARTTLS unavailable (listener configured with allowPlaintext=true and no tlsContext)");
      return;
    }
    _writeOk(socket, "Begin TLS negotiation now");
    // RFC 5804 §2.2 — discard any bytes the client queued before the
    // upgrade so pre-handshake injection can't survive into the post-
    // TLS session. The shared upgradeSocket helper handles the
    // CVE-2021-33515 / CVE-2021-38371 listener-strip + pause; the
    // pending-protocol state still belongs to managesieve.
    state.lineBuffer = Buffer.alloc(0);
    state.pendingLiteral = null;
    state.pendingAuth    = null;
    mailServerTls.upgradeSocket({
      plainSocket:   socket,
      secureContext: tlsContext,
      idleTimeoutMs: idleTimeoutMs,
      onSecure: function (tlsSocket) {
        state.tls = true;
        _emit("mail.server.managesieve.starttls_upgraded",
          { connectionId: state.id });
        // RFC 5804 §2.2 — server MUST re-emit capabilities on the
        // post-TLS socket so the client sees the post-TLS mechanism
        // list (which may now include PLAIN, etc.).
        _emitCapabilityBanner(state, tlsSocket);
        _writeOk(tlsSocket, "TLS negotiation successful");
      },
      onData: function (tlsSocket, chunk) {
        state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
        _drainBuffer(state, tlsSocket);
      },
      onError: function (err) {
        _emit("mail.server.managesieve.starttls_handshake_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _close(socket);
      },
    });
  }

  function _handleLogout(state, socket) {
    _emit("mail.server.managesieve.logout",
      { connectionId: state.id });
    _writeOk(socket, "Logout completed");
    _close(socket);
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
    // Defense-in-depth: re-check cleartext refusal at the dispatch
    // boundary even though the validator already gated it (operator
    // could have configured a relaxed profile but the listener still
    // wants to enforce strict at AUTH).
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
      _close(socket);
      return;
    }
    state.pendingAuth = {
      mech:    mech,
      irBytes: parsed.literalBytes,
      irPlus:  parsed.literalPlus,
      irBody:  Buffer.alloc(0),
    };
    if (parsed.literalBytes === null) {
      // No initial-response — call verify with empty client response.
      _completeAuthenticate(state, socket);
      return;
    }
    if (!parsed.literalPlus) {
      // Synchronizing literal — server sends continuation request
      // before client transmits the bytes.
      socket.write("OK\r\n");
    }
    // Loop drains the literal-IR bytes; _completeAuthenticate runs
    // after.
  }

  function _completeAuthenticate(state, socket) {
    var pa = state.pendingAuth;
    state.pendingAuth = null;
    if (!pa) return;
    _emit("mail.server.managesieve.auth_attempt",
      { connectionId: state.id, mech: pa.mech, remoteAddress: state.remoteAddress });
    Promise.resolve()
      .then(function () {
        return authConfig.verify(pa.mech, {
          clientResponse: pa.irBody.length > 0 ? pa.irBody.toString("utf8") : null,
          tls:            state.tls,
          remoteAddress:  state.remoteAddress,
        });
      })
      .then(function (result) {
        if (result && result.ok && result.actor) {
          state.actor = result.actor;
          state.stage = "authenticated";
          _emit("mail.server.managesieve.auth_success",
            { connectionId: state.id, mech: pa.mech, tenantId: state.actor.tenantId || null });
          _writeOk(socket, "Authenticated");
          return;
        }
        rateLimit.noteAuthFailure(state.remoteAddress);
        _emit("mail.server.managesieve.auth_failed",
          { connectionId: state.id, mech: pa.mech, reason: "verify-returned-fail" }, "denied");
        _writeNo(socket, "Authentication failed");
      })
      .catch(function () {
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeNo(socket, "Authentication failed");
      });
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
    Promise.resolve()
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
    if (!plus) {
      // Synchronizing literal — RFC 5804 §2.3: server sends
      // continuation before client transmits payload.
      socket.write("OK\r\n");
    }
    // _completePutscript runs after the literal is fully drained.
  }

  function _completePutscript(state, socket, literal) {
    var bodyText = literal.body.toString("utf8");
    // RFC 5804 §2.3 — implementation MUST verify script validity
    // before accepting it. Refuse with the safeSieve issue code so
    // operators can correlate refusals to specific parse errors.
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
    Promise.resolve()
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
    Promise.resolve()
      .then(function () { return mailStore.sieveScripts.list(state.actor); })
      .then(function (scripts) {
        var list = Array.isArray(scripts) ? scripts : [];
        for (var i = 0; i < list.length; i += 1) {
          var s = list[i];
          var nm = String(s.name || "");
          var active = s.active === true ? " ACTIVE" : "";
          socket.write('"' + _quoteEscape(nm) + '"' + active + "\r\n");
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
    Promise.resolve()
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
    Promise.resolve()
      .then(function () { return mailStore.sieveScripts.get(state.actor, name); })
      .then(function (script) {
        if (!script) {
          _writeNo(socket, "(NONEXISTENT) Script not found");
          return;
        }
        var body = String(script.body || "");
        var bytes = Buffer.byteLength(body, "utf8");
        // RFC 5804 §2.9 — return the script as a synchronizing
        // literal followed by the body and CRLF, then OK.
        socket.write("{" + bytes + "}\r\n");
        socket.write(body);
        if (!body.endsWith("\r\n")) socket.write("\r\n");
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
    Promise.resolve()
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
    Promise.resolve()
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

  // RFC 5804 §1.2 quoted-string escaping: backslash + DQUOTE inside
  // the value get escaped with a leading backslash.
  function _quoteEscape(s) {
    return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');                                               // allow:regex-no-length-cap — backslash + DQUOTE escape on bounded-input
  }

  function _writeOk(socket, msg) {
    try { socket.write('OK "' + _quoteEscape(msg) + '"\r\n'); } catch (_e) { /* socket down */ }
  }
  function _writeOkWithTag(socket, tag, msg) {
    try { socket.write('OK (TAG "' + _quoteEscape(tag) + '") "' + _quoteEscape(msg) + '"\r\n'); }
    catch (_e) { /* socket down */ }
  }
  function _writeNo(socket, msg) {
    try { socket.write('NO "' + _quoteEscape(msg) + '"\r\n'); } catch (_e) { /* socket down */ }
  }
  function _writeBye(socket, msg) {
    try { socket.write('BYE "' + _quoteEscape(msg) + '"\r\n'); } catch (_e) { /* socket down */ }
  }
  function _close(socket) {
    try { socket.end(); } catch (_e) { /* idempotent */ }
    try { socket.destroy(); } catch (_e2) { /* idempotent */ }
    connections.delete(socket);
  }

  // ---- Lifecycle ----------------------------------------------------------
  async function listen(listenOpts) {
    listenOpts = listenOpts || {};
    if (listening) {
      throw new MailServerManageSieveError("mail-server-managesieve/already-listening",
        "listen: already listening");
    }
    var port    = listenOpts.port    === undefined ? DEFAULT_PORT : listenOpts.port;
    var address = listenOpts.address || "0.0.0.0";
    tcpServer = net.createServer(function (socket) { _handleConnection(socket); });
    return new Promise(function (resolve, reject) {
      tcpServer.once("error", reject);
      tcpServer.listen(port, address, function () {
        listening = true;
        tcpServer.removeListener("error", reject);
        _emit("mail.server.managesieve.listening", { port: port, address: address });
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
        _emit("mail.server.managesieve.closed", {});
        resolve();
      });
    });
  }

  return {
    listen: listen,
    close:  close,
  };
}

module.exports = {
  create:                       create,
  MailServerManageSieveError:   MailServerManageSieveError,
};

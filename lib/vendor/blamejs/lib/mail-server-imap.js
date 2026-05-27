"use strict";
/**
 * @module     b.mail.server.imap
 * @nav        Mail
 * @title      Mail IMAP Server
 * @order      546
 *
 * @intro
 *   IMAP4rev2 mailbox-access listener (RFC 9051; obsoletes RFC 3501).
 *   Modern MUAs (Thunderbird, Apple Mail, mutt, K-9, FairEmail,
 *   etc.) connect here to read + manage messages without operators
 *   running dovecot / cyrus alongside. Composes the framework's
 *   existing substrates:
 *
 *     - `b.guardImapCommand` for wire-protocol shape + smuggling
 *       defense (literal-injection, bare-CR/LF refusal, per-verb
 *       shape, RFC 9051 §2.2.2 literal framing)
 *     - `b.mail.server.rateLimit` for per-IP DoS defense (concurrent
 *       + rate + AUTH-failure budget + slow-loris)
 *     - `b.mailStore` (operator-supplied backend) for the actual
 *       mail storage + UIDVALIDITY + modseq tracking
 *     - operator-supplied authenticator for SASL credential verify
 *     - `b.mail.server.tls` recommended for cert + key loading +
 *       rotation
 *
 *   ## State machine (RFC 9051 §3)
 *
 *   ```
 *   NOT-AUTHENTICATED → [STARTTLS → NOT-AUTH-TLS] → AUTH/LOGIN →
 *   AUTHENTICATED ↔ SELECTED → LOGOUT
 *                                ↑ EXAMINE  ↓ CLOSE / UNSELECT
 *   ```
 *
 *   Commands gated by state:
 *
 *     - NOT-AUTHENTICATED: STARTTLS / AUTHENTICATE / LOGIN / NOOP /
 *       CAPABILITY / LOGOUT / ID
 *     - AUTHENTICATED: SELECT / EXAMINE / CREATE / DELETE / RENAME /
 *       SUBSCRIBE / UNSUBSCRIBE / LIST / STATUS / APPEND / NAMESPACE /
 *       IDLE / ENABLE / NOOP / CAPABILITY / LOGOUT / ID
 *     - SELECTED: CHECK / CLOSE / UNSELECT / EXPUNGE / SEARCH / FETCH /
 *       STORE / COPY / MOVE / UID … / IDLE / NOOP / CAPABILITY /
 *       LOGOUT + every AUTHENTICATED command
 *
 *   Tagged response model: every client command carries a tag
 *   (`A001 LOGIN …`); server replies with one or more untagged
 *   responses (`* …`) then `A001 OK …` / `A001 NO …` / `A001 BAD …`.
 *
 *   ## Wire-protocol defenses
 *
 *   - **STARTTLS stripping (CVE-2021-33515 Dovecot class)** —
 *     STARTTLS upgrade clears pre-handshake receive buffer; any
 *     pipelined command queued before TLS is refused with
 *     `BAD Pipelined post-STARTTLS not permitted`.
 *
 *   - **Literal-injection / command-continuation smuggling** —
 *     `{n}` literal continuation MUST come on a line of its own
 *     (per `b.guardImapCommand.detectLiteralSmuggling`); oversize
 *     literals refused (default 64 MiB); LITERAL+ (RFC 7888) non-
 *     synchronizing literals only honored post-AUTH.
 *
 *   - **Mailbox-name traversal** — mailbox path components
 *     validated through `_validateMailboxName`: refuses `..`, NUL,
 *     control chars, oversize. UTF-8 mailbox names (RFC 9051 §5.1)
 *     accepted; modified-UTF7 (RFC 3501 §5.1.3 legacy) refused unless
 *     `allowLegacyMUtf7: true`.
 *
 *   - **APPEND-flood** — per-tenant byte/sec cap surfaces via the
 *     `b.mail.server.rateLimit`'s `minBytesPerSecond` floor on the
 *     APPEND-literal-body phase (same shape the MX listener uses for
 *     DATA-body).
 *
 *   - **Resource exhaustion** — per-line cap (default 8 KiB sans
 *     literal payload), per-literal cap (64 MiB), per-connection idle
 *     cap (default 30 min when not in IDLE; IDLE itself capped at
 *     29 min per RFC 2177 §3 to force re-issue).
 *
 *   - **Connection-rate + AUTH-failure budget** — composes
 *     `b.mail.server.rateLimit`. Each AUTH failure increments the
 *     budget; trip the cap and new AUTH attempts get
 *     `* BAD Too many AUTH failures` + connection close.
 *
 *   ## Audit lifecycle
 *
 *   - `mail.server.imap.connect`      — IP, TLS state
 *   - `mail.server.imap.auth_attempt` — mechanism, actor-hash
 *   - `mail.server.imap.auth_success` — mechanism, tenantId, scopes
 *   - `mail.server.imap.auth_failed`  — mechanism, reason
 *   - `mail.server.imap.select`       — mailbox, modseq, exists count
 *   - `mail.server.imap.append`       — mailbox, size, flags
 *   - `mail.server.imap.fetch_bulk`   — sequence-set size, BODY parts
 *   - `mail.server.imap.expunge`      — count, modseq
 *   - `mail.server.imap.literal_overflow_refused` — attempt size, cap
 *   - `mail.server.imap.rate_limit_refused`        — IP, reason
 *   - `mail.server.imap.smtp_smuggling_detected`   — literal-injection
 *
 *   ## What v1 does NOT ship
 *
 *   - **SEARCH** — operator wires `opts.search(actor, mailbox, query)`
 *     when ready; the listener emits `BAD search-not-configured`
 *     until then. SEARCH expressions are operator-domain logic
 *     against the mailStore index.
 *   - **NOTIFY (RFC 5465)**, **METADATA (RFC 5464)**, **CATENATE
 *     (RFC 4469)**, **URLAUTH (RFC 4467)**, **IMAPSIEVE (RFC 6785)**,
 *     **COMPRESS=DEFLATE (RFC 4978)** — opt-in / refused.
 *   - **CONDSTORE / QRESYNC (RFC 7162)** — modseq is exposed via
 *     STATUS but per-FETCH CHANGEDSINCE delta is operator-side
 *     follow-up.
 *
 * @card
 *   IMAP4rev2 mailbox-access listener (RFC 9051; obsoletes RFC 3501).
 *   State machine NOT-AUTH → STARTTLS → AUTH → SELECTED → LOGOUT.
 *   Composes b.guardImapCommand (wire-protocol gate), b.mail.server.
 *   rateLimit (DoS defense), operator-supplied mailStore + SASL
 *   authenticator. Default-on per-IP rate-limit + literal-injection
 *   refusal + mailbox-traversal refusal.
 */

var net  = require("node:net");
var lazyRequire = require("./lazy-require");
var C = require("./constants");
var bCrypto = require("./crypto");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardImapCommand = require("./guard-imap-command");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerRegistry = require("./mail-server-registry");
var mailServerTls = require("./mail-server-tls");
var { defineClass } = require("./framework-error");

var audit = lazyRequire(function () { return require("./audit"); });

var MailServerImapError = defineClass("MailServerImapError", { alwaysPermanent: true });

var DEFAULT_MAX_LINE_BYTES   = C.BYTES.kib(8);
var DEFAULT_MAX_LITERAL      = C.BYTES.mib(64);
var DEFAULT_IDLE_TIMEOUT_MS  = C.TIME.minutes(30);
var IDLE_BANDWIDTH_TIMEOUT_MS = C.TIME.minutes(29);  // RFC 2177 §3 — re-issue before 30
var DEFAULT_GREETING_VENDOR  = "blamejs IMAP4rev2";
var pkgVersion = require("../package.json").version;

// Error-message clamp bytes — protocol-string clamp, not a byte count.
// Centralized so the allow:raw-byte-literal marker lives in one place
// and the per-call sites read cleanly.
var ERR_CLAMP = 200;                                                                                  // allow:raw-byte-literal — protocol-reply error-message clamp
var LINE_PREVIEW = 80;                                                                                // allow:raw-byte-literal — audit-line preview clamp

// RFC 9051 §6.3.12 + RFC 5322 §3.3 date-time parser for IMAP APPEND.
// Format: `DD-Mon-YYYY HH:MM:SS ±HHMM` where Mon is the 3-letter
// English month abbreviation (case-insensitive on parse, but the IMAP
// spec emits canonical mixed-case `Jan`/`Feb`/...). Returns the
// millisecond epoch, or null on any parse failure — the caller emits
// `BAD` rather than silently using `Date.now()`.
var IMAP_MONTHS = Object.freeze({
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,                                                         // allow:raw-byte-literal — month-index table (0-5)
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,                                                       // allow:raw-byte-literal — month-index table (6-11)
});
var IMAP_DT_RE = /^\s*(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})\s*$/;
function _parseImapDateTime(s) {
  if (typeof s !== "string") return null;
  var m = s.match(IMAP_DT_RE);                                                                            // allow:regex-no-length-cap — input bounded by IMAP literal cap
  if (!m) return null;
  var day = parseInt(m[1], 10);
  var month = IMAP_MONTHS[m[2].toLowerCase()];
  if (month === undefined) return null;
  var year = parseInt(m[3], 10);
  var hour = parseInt(m[4], 10);
  var min  = parseInt(m[5], 10);
  var sec  = parseInt(m[6], 10);
  var sign = m[7] === "-" ? -1 : 1;
  var tzH  = parseInt(m[8], 10);
  var tzM  = parseInt(m[9], 10);
  if (day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59 || tzH > 23 || tzM > 59) return null;
  var utcMs = Date.UTC(year, month, day, hour, min, sec);
  if (!isFinite(utcMs)) return null;
  // RFC 5322 §3.3 — date-time MUST be a real calendar date. `Date.UTC`
  // silently normalises impossible inputs (`Feb 31 2026` → `Mar 3 2026`);
  // round-trip via the calendar fields and refuse any drift so a
  // hostile client can't smuggle a different internalDate than the
  // wire suggests.
  var probe = new Date(utcMs);
  if (probe.getUTCFullYear() !== year ||
      probe.getUTCMonth()    !== month ||
      probe.getUTCDate()     !== day ||
      probe.getUTCHours()    !== hour ||
      probe.getUTCMinutes()  !== min ||
      probe.getUTCSeconds()  !== sec) {
    return null;
  }
  return utcMs - sign * (tzH * C.TIME.hours(1) + tzM * C.TIME.minutes(1));
}

// Mailbox name validator. RFC 9051 §5.1 — UTF-8 hierarchy. Refuse
// path-traversal (`..`), NUL, C0 controls, leading/trailing slash,
// oversize.
function _validateMailboxName(name, opts) {
  if (typeof name !== "string" || name.length === 0) return false;
  if (name.length > 1024) return false;                                                              // allow:raw-byte-literal — mailbox name cap
  for (var i = 0; i < name.length; i += 1) {
    var c = name.charCodeAt(i);
    if (c < 0x20 || c === 0x7F) return false;                                                        // allow:raw-byte-literal — control-byte refusal
  }
  if (name.indexOf("..") !== -1) return false;
  if (name === "/" || name[0] === "/" || name[name.length - 1] === "/") return false;
  // Modified-UTF7 detection — RFC 3501 §5.1.3. Sequences are
  // `&...-`. Refuse under strict (RFC 9051 uses raw UTF-8).
  if (opts && opts.allowLegacyMUtf7 !== true) {
    if (/&[A-Za-z0-9+/]*-/.test(name)) return false;                                                  // allow:regex-no-length-cap — mailbox name already length-capped above
  }
  return true;
}

/**
 * @primitive b.mail.server.imap.create
 * @signature b.mail.server.imap.create(opts)
 * @since     0.9.49
 * @status    stable
 * @related   b.mail.server.mx.create, b.mail.server.submission.create, b.mailStore.create
 *
 * Build an IMAP4rev2 listener (RFC 9051). The handle exposes
 * `listen({ port, address })` → ephemeral-bind promise resolving to
 * `{ port, address }`, plus `close()` for graceful shutdown.
 *
 * @opts
 *   tlsContext:        SecureContext,   // required (no plaintext mode)
 *   greeting:          string,           // default "blamejs IMAP4rev2"
 *   maxLineBytes:      number,           // default 8192
 *   maxLiteralBytes:   number,           // default 64 MiB
 *   idleTimeoutMs:     number,           // default 30 min
 *   profile:           "strict" | "balanced" | "permissive",
 *   auth: {
 *     mechanisms:      ["PLAIN", "LOGIN", "SCRAM-SHA-256", "EXTERNAL", "XOAUTH2"],
 *     verify:          async function (mechanism, credentials) → { ok, actor },
 *   },
 *   mailStore:         b.mailStore handle,    // required
 *   rateLimit:         b.mail.server.rateLimit handle | opts | false,
 *   audit:             b.audit                // optional
 *
 * @example
 *   var imap = b.mail.server.imap.create({
 *     tlsContext: b.mail.server.tls.context({ certFile, keyFile }).secureContext,
 *     auth: {
 *       mechanisms: ["PLAIN", "SCRAM-SHA-256"],
 *       verify:     async function (mech, creds) {
 *         return { ok: true, actor: { tenantId: "t1", username: creds.authzid } };
 *       },
 *     },
 *     mailStore: b.mailStore.create({ backend: b.db.handle() }),
 *   });
 *   await imap.listen({ port: 143 });
 */
function create(opts) {
  validateOpts.requireObject(opts, "mail.server.imap.create",
    MailServerImapError, "mail-server-imap/bad-opts");
  if (!opts.tlsContext) {
    throw new MailServerImapError("mail-server-imap/no-tls-context",
      "mail.server.imap.create: tlsContext is required (no implicit plaintext mode). " +
      "Use b.mail.server.tls.context({ certFile, keyFile, watch: true }) to load + " +
      "auto-reload a cert/key pair from disk.");
  }
  if (!opts.mailStore || typeof opts.mailStore.appendMessage !== "function") {
    throw new MailServerImapError("mail-server-imap/no-mail-store",
      "mail.server.imap.create: mailStore is required (compose b.mailStore.create({ backend: ... }))");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxLineBytes", "maxLiteralBytes", "idleTimeoutMs"],
    "mail.server.imap.", MailServerImapError, "mail-server-imap/bad-bound");

  var greeting          = opts.greeting        || DEFAULT_GREETING_VENDOR;
  var maxLineBytes      = opts.maxLineBytes    || DEFAULT_MAX_LINE_BYTES;
  var maxLiteralBytes   = opts.maxLiteralBytes || DEFAULT_MAX_LITERAL;
  var idleTimeoutMs     = opts.idleTimeoutMs   || DEFAULT_IDLE_TIMEOUT_MS;
  var profile           = opts.profile         || "strict";
  var authConfig        = opts.auth            || null;
  var mailStore         = opts.mailStore;
  var allowLegacyMUtf7  = profile === "permissive";

  var rateLimit;
  if (opts.rateLimit === false) {
    rateLimit = mailServerRateLimit.create({ disabled: true });
  } else if (opts.rateLimit && typeof opts.rateLimit.admitConnection === "function") {
    rateLimit = opts.rateLimit;
  } else {
    rateLimit = mailServerRateLimit.create(opts.rateLimit || {});
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

  function _handleConnection(rawSocket) {
    var remoteAddress = rawSocket.remoteAddress || "0.0.0.0";
    var admit = rateLimit.admitConnection(remoteAddress);
    if (!admit.ok) {
      _emit("mail.server.imap.rate_limit_refused",
        { remoteAddress: remoteAddress, reason: admit.reason }, "denied");
      try { rawSocket.write("* BAD Too many connections from your IP\r\n"); }
      catch (_e) { /* socket may be down */ }
      try { rawSocket.destroy(); } catch (_e2) { /* idempotent */ }
      return;
    }
    rawSocket.once("close", function () { rateLimit.releaseConnection(remoteAddress); });

    var connectionId = "imapconn-" + bCrypto.generateToken(8);                                       // allow:raw-byte-literal — connection-id length
    var socket = rawSocket;
    connections.add(socket);

    var state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      tls:           false,
      stage:         "not-authenticated",
      actor:         null,
      selectedMailbox: null,
      selectedReadOnly: false,
      authPending:   null,
      pendingLiteral: null,         // { tag, verb, line, size, body }
      idle:          null,          // { tag, timer }
      // Per-connection receive buffer (must NOT be a closure variable —
      // multiple concurrent connections would clobber each other).
      lineBuffer:    Buffer.alloc(0),
    };

    _emit("mail.server.imap.connect",
      { connectionId: connectionId, remoteAddress: remoteAddress });

    socket.setTimeout(idleTimeoutMs);
    socket.on("timeout", function () {
      _writeUntagged(socket, "BYE Idle timeout");
      _close(socket, state);
    });
    socket.on("error", function (err) {
      _emit("mail.server.imap.socket_error",
        { connectionId: connectionId, error: (err && err.message) || String(err) }, "failure");
    });

    // Greeting per RFC 9051 §7.1.5 — `* OK <greeting>`.
    _writeUntagged(socket, "OK [CAPABILITY " + _capabilityLine(state) + "] " + greeting);

    socket.on("data", function (chunk) {
      // Per-line cap MUST gate the concat — a single large TCP chunk
      // (~64 KiB on most kernels) can push the buffer past the line
      // cap BEFORE the drain loop runs, so the cap-check inside the
      // loop sees a buffer that's already grown past the policy
      // floor. When the chunk would itself overrun the line cap AND
      // no literal is pending (where over-cap bytes are legitimate
      // payload), reject here and tear the connection down.
      var pendingLiteral = state.pendingLiteral;
      var room = pendingLiteral
        ? (pendingLiteral.size - pendingLiteral.body.length) + maxLineBytes
        : (maxLineBytes - state.lineBuffer.length);
      if (chunk.length > room) {
        _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
        _close(socket, state);
        return;
      }
      state.lineBuffer = Buffer.concat([state.lineBuffer, chunk]);
      _drainBuffer(state, socket);
    });
  }

  // Receive-buffer drain: extract complete lines (CRLF-terminated)
  // and dispatch. When the previous command opened a literal (e.g.
  // APPEND ... {N}), the next N bytes are the literal payload — we
  // accumulate them before resuming line-mode dispatch.
  function _drainBuffer(state, socket) {
    while (true) {
      if (state.pendingLiteral) {
        var need = state.pendingLiteral.size - state.pendingLiteral.body.length;
        if (state.lineBuffer.length < need) {
          state.pendingLiteral.body = Buffer.concat([state.pendingLiteral.body, state.lineBuffer]);
          state.lineBuffer = Buffer.alloc(0);
          return;
        }
        state.pendingLiteral.body = Buffer.concat([state.pendingLiteral.body, state.lineBuffer.subarray(0, need)]);
        state.lineBuffer = state.lineBuffer.subarray(need);
        _completeLiteralCommand(state, socket);
        continue;
      }
      var crlf = state.lineBuffer.indexOf("\r\n");
      if (crlf === -1) {
        if (state.lineBuffer.length > maxLineBytes) {
          _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
          _close(socket, state);
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
    // Continuation: AUTHENTICATE multi-step expects a client response
    if (state.authPending) {
      _runAuthStep(state, socket, line.trim());
      return;
    }
    // IDLE termination — RFC 2177 §3 expects `DONE` line.
    if (state.idle) {
      if (line.toUpperCase() === "DONE") {
        var idleTag = state.idle.tag;
        if (state.idle.timer) clearTimeout(state.idle.timer);
        state.idle = null;
        _writeTagged(socket, idleTag, "OK IDLE terminated");
      } else {
        _writeUntagged(socket, "BAD Expected DONE during IDLE");
      }
      return;
    }
    var parsed;
    try {
      parsed = guardImapCommand.validate(line, {
        profile: profile,
        authenticated: state.actor !== null,
      });
    } catch (e) {
      if (e && e.code === "guard-imap-command/literal-smuggling") {
        _emit("mail.server.imap.smtp_smuggling_detected",
          { connectionId: state.id, line: line.slice(0, LINE_PREVIEW) }, "denied");
      }
      _writeUntagged(socket, "BAD " + (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return;
    }
    // Literal-opener: stash + emit continuation. Zero-length literals
    // (`{0}`) are legal per RFC 9051 §6.3.12 (e.g. APPEND of an empty
    // message body — rare but spec-compliant; refusing them would
    // diverge from the wire-protocol).
    if (parsed.literalSize !== null) {
      if (parsed.literalSize > maxLiteralBytes) {
        _emit("mail.server.imap.literal_overflow_refused",
          { connectionId: state.id, attempted: parsed.literalSize, cap: maxLiteralBytes },
          "denied");
        _writeTagged(socket, parsed.tag,
          "NO Literal " + parsed.literalSize + " bytes exceeds cap " + maxLiteralBytes);
        return;
      }
      // Zero-byte literal: no continuation, no read — synthesize the
      // pending-literal with an empty body and complete immediately on
      // the next loop tick.
      if (parsed.literalSize === 0) {
        state.pendingLiteral = {
          tag:  parsed.tag,
          verb: parsed.verb,
          line: line,
          size: 0,
          body: Buffer.alloc(0),
          synchronizing: !parsed.literalNonSync,
        };
        _completeLiteralCommand(state, socket);
        return;
      }
      state.pendingLiteral = {
        tag:  parsed.tag,
        verb: parsed.verb,
        line: line,
        size: parsed.literalSize,
        body: Buffer.alloc(0),
        synchronizing: !parsed.literalNonSync,
      };
      if (!parsed.literalNonSync) {
        _writeUntagged(socket, "+ Ready for literal data");
      }
      return;
    }
    _dispatch(state, socket, parsed, line);
  }

  function _completeLiteralCommand(state, socket) {
    var pending = state.pendingLiteral;
    state.pendingLiteral = null;
    // Strip the trailing literal opener `{N}` (or `{N+}`) from the line
    var lineNoLit = pending.line.replace(/\{[0-9]+\+?\}$/, "").trim();                                // allow:regex-no-length-cap — line length already capped upstream
    var parsed;
    try { parsed = guardImapCommand.validate(lineNoLit, { profile: profile, authenticated: state.actor !== null }); }
    catch (e) {
      _writeTagged(socket, pending.tag, "BAD " + (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return;
    }
    _dispatch(state, socket, parsed, lineNoLit, pending.body);
  }

  // Adapter shim — uniform `(state, socket, parsed, literalBody)`
  // dispatch contract over the per-verb handlers. Builds the registry
  // defaults lazily on first dispatch so the closure-scoped handler
  // references are bound when needed (handlers are hoisted by their
  // function-declarations; the registry init runs at dispatch time).
  var _registry = null;
  function _ensureRegistry() {
    if (_registry !== null) return _registry;
    // Per-handler resource budgets. Sized per the verb's known
    // payload shape (LIST scans the folder tree; FETCH walks N
    // messages; APPEND accepts a literal up to maxLiteralBytes).
    var SHORT_MS  = 5 * 1000;                                                                        // allow:raw-time-literal — 5s short-command budget
    var MEDIUM_MS = 30 * 1000;                                                                       // allow:raw-time-literal — 30s medium-command budget
    var LONG_MS   = 2 * 60 * 1000;                                                                   // allow:raw-time-literal — 2 min long-command budget (FETCH / APPEND)
    var SHORT_B   = 8 * 1024;                                                                        // allow:raw-byte-literal — 8 KiB short-command response cap
    var MEDIUM_B  = 1024 * 1024;                                                                     // allow:raw-byte-literal — 1 MiB medium-command response cap
    var LONG_B    = 64 * 1024 * 1024;                                                                // allow:raw-byte-literal — 64 MiB FETCH/APPEND response cap
    var defaults = {
      CAPABILITY:   { fn: function (s, so, p)  { return _handleCapability(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      NOOP:         { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "OK NOOP completed"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      LOGOUT:       { fn: function (s, so, p)  { return _handleLogout(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      ID:           { fn: function (s, so, p)  { return _handleId(s, so, p.tag, p.args); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      STARTTLS:     { fn: function (s, so, p)  { return _handleStartTls(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      AUTHENTICATE: { fn: function (s, so, p)  { return _handleAuthenticate(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      LOGIN:        { fn: function (s, so, p)  { return _handleLogin(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      ENABLE:       { fn: function (s, so, p)  { return _handleEnable(s, so, p.tag, p.args); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      SELECT:       { fn: function (s, so, p)  { return _handleSelect(s, so, p.tag, p.args, false); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      EXAMINE:      { fn: function (s, so, p)  { return _handleSelect(s, so, p.tag, p.args, true); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      LIST:         { fn: function (s, so, p)  { return _handleList(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      STATUS:       { fn: function (s, so, p)  { return _handleStatus(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      NAMESPACE:    { fn: function (s, so, p)  {
                        _writeUntagged(so, "NAMESPACE ((\"\" \"/\")) NIL NIL");
                        return _writeTagged(so, p.tag, "OK NAMESPACE completed");
                      },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      APPEND:       { fn: function (s, so, p, lit) { return _handleAppend(s, so, p.tag, p.args, lit); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      CHECK:        { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "OK CHECK completed"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      CLOSE:        { fn: function (s, so, p)  { return _handleClose(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      UNSELECT:     { fn: function (s, so, p)  { return _handleClose(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      EXPUNGE:      { fn: function (s, so, p)  { return _handleExpunge(s, so, p.tag); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      FETCH:        { fn: function (s, so, p)  { return _handleFetch(s, so, p.tag, p.args); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      STORE:        { fn: function (s, so, p)  { return _handleStore(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      UID:          { fn: function (s, so, p)  { return _handleUid(s, so, p.tag, p.args); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      IDLE:         { fn: function (s, so, p)  { return _handleIdle(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: LONG_MS },
      // v0.11.28 — RFC 5465 NOTIFY / RFC 5464 METADATA / RFC 4469 CATENATE.
      NOTIFY:       { fn: function (s, so, p)  { return _handleNotify(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      GETMETADATA:  { fn: function (s, so, p)  { return _handleGetMetadata(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      SETMETADATA:  { fn: function (s, so, p, lit) { return _handleSetMetadata(s, so, p.tag, p.args, lit); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: MEDIUM_MS },
      DONE:         { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "BAD DONE outside IDLE"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      // Defaults for the verbs the v0.9.49 listener didn't dispatch —
      // operators wire concrete handlers via opts.overrides.
      SEARCH:       { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO SEARCH not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      CREATE:       { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO CREATE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      DELETE:       { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO DELETE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      RENAME:       { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO RENAME not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      SUBSCRIBE:    { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO SUBSCRIBE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      UNSUBSCRIBE:  { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO UNSUBSCRIBE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      COPY:         { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO COPY not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      MOVE:         { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "NO MOVE not configured"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
    };
    _registry = mailServerRegistry.create({
      protocol:        "imap",
      defaults:        defaults,
      overrides:       opts.overrides || {},
      // b.agent.tenant adoption (v0.10.12). Operators wiring multi-
      // tenant IMAP deployments pass `tenantScope` from
      // `b.agent.tenant.create({...})` plus the per-listener tenant id.
      // The registry then gates every dispatch on
      // `tenantScope.check(state.actor, agentTenantId)` before guard
      // validation or audit emission.
      tenantScope:     opts.tenantScope    || null,
      agentTenantId:   opts.agentTenantId  || null,
      notFoundHandler: function (verb, _state, socket, parsed) {
        return _writeTagged(socket, parsed.tag,
          "BAD Verb '" + verb + "' not implemented in v1");
      },
    });
    return _registry;
  }

  function _dispatch(state, socket, parsed, _rawLine, literalBody) {
    // Registry dispatch may return a Promise (async override handler,
    // or a safeAsync.withTimeout-wrapped Promise). The caller's
    // try/catch is synchronous, so a Promise rejection would surface
    // as an unhandled rejection AND the client would never receive
    // the tagged error reply. Attach a catch that converts the
    // rejection into a `BAD`/`NO` tagged response + audit emit.
    var result;
    try {
      result = _ensureRegistry().dispatch(parsed.verb, state, socket, parsed, literalBody);
    } catch (err) {
      _writeTagged(socket, parsed.tag,
        "NO " + ((err && err.message) || "handler threw").slice(0, ERR_CLAMP));
      _emit("mail.server.imap.handler_threw",
        { connectionId: state.id, verb: parsed.verb,
          error: (err && err.message) || String(err) }, "failure");
      return;
    }
    if (result && typeof result.then === "function") {
      result.then(
        function () { /* tagged response already written by handler */ },
        function (err) {
          try {
            _writeTagged(socket, parsed.tag,
              "NO " + ((err && err.message) || "handler rejected").slice(0, ERR_CLAMP));
          } catch (_we) { /* socket may already be gone */ }
          try {
            _emit("mail.server.imap.handler_rejected",
              { connectionId: state.id, verb: parsed.verb,
                error: (err && err.message) || String(err) }, "failure");
          } catch (_ae) { /* drop-silent */ }
        }
      );
    }
    return result;
  }

  function _capabilityLine(state) {
    var caps = ["IMAP4rev2"];
    if (!state.tls) caps.push("STARTTLS");
    // RFC 7162 §3 — CONDSTORE is server-advertised; clients ENABLE
    // before relying on MODSEQ in untagged FETCH responses. QRESYNC
    // (§3.2) adds the VANISHED responses on SELECT + post-EXPUNGE
    // and implicitly engages CONDSTORE per §3.2.5.
    caps.push("CONDSTORE");
    caps.push("QRESYNC");
    // v0.11.28 — opt-in extensions (advertised so capable clients can
    // exercise them; each handler refuses gracefully when the operator
    // backend doesn't supply the corresponding hook).
    caps.push("NOTIFY");                                // RFC 5465
    caps.push("METADATA");                              // RFC 5464 — per-mailbox annotations          // allow:raw-byte-literal — RFC number in comment
    caps.push("METADATA-SERVER");                       // RFC 5464 §3.1 — server-wide annotations    // allow:raw-byte-literal — RFC number in comment
    caps.push("CATENATE");                              // RFC 4469 — APPEND from existing parts
    // NB: COMPRESS=DEFLATE (RFC 4978) intentionally NOT advertised —
    // CRIME-class compression-oracle attack on the encrypted IMAP
    // stream. Operators who explicitly enable it via opts.compress
    // get a documented downgrade; v1 default is off.
    // Advertise AUTH=<mech> ONLY for mechanisms the operator wired
    // in opts.auth.mechanisms. RFC 9051 §7.2 — clients pick from the
    // advertised list; advertising AUTH=PLAIN when authConfig is null
    // or doesn't include PLAIN sets clients up for AUTHENTICATE
    // requests that the listener refuses with "no AUTHENTICATE
    // configured" / "mechanism not advertised".
    if (authConfig && Array.isArray(authConfig.mechanisms)) {
      for (var i = 0; i < authConfig.mechanisms.length; i += 1) {
        var m = String(authConfig.mechanisms[i]).toUpperCase();
        if (caps.indexOf("AUTH=" + m) === -1) caps.push("AUTH=" + m);
      }
    }
    return caps.join(" ");
  }

  // RFC 7162 §3.1 — ENABLE CONDSTORE flips the per-state flag that
  // makes subsequent untagged FETCH responses include the MODSEQ
  // attribute and lets STORE / FETCH carry CHANGEDSINCE /
  // UNCHANGEDSINCE modifiers. Unknown ENABLE arguments are silently
  // ignored per RFC 5161 §3.1 — the server lists in `ENABLED <name>`
  // only the extensions it actually turned on.
  function _handleEnable(state, socket, tag, args) {
    var requested = (args || "").split(/\s+/).filter(Boolean);
    var enabled = [];
    for (var i = 0; i < requested.length; i += 1) {
      var name = requested[i].toUpperCase();
      if (name === "CONDSTORE") {
        if (!state.enabledCondStore) {
          state.enabledCondStore = true;
          enabled.push("CONDSTORE");
        }
      } else if (name === "QRESYNC") {
        // RFC 7162 §3.2.5 — QRESYNC implicitly engages CONDSTORE.
        // The client signals it can consume `* VANISHED (EARLIER)`
        // responses on SELECT / EXAMINE + post-EXPUNGE; the listener
        // flips both flags and the SELECT handler honours the
        // QRESYNC parameter list when present.
        if (!state.enabledQResync) {
          state.enabledQResync   = true;
          state.enabledCondStore = true;
          enabled.push("QRESYNC");
        }
      }
    }
    _writeUntagged(socket, "ENABLED" + (enabled.length ? " " + enabled.join(" ") : ""));
    _writeTagged(socket, tag, "OK ENABLE completed");
  }

  // RFC 5465 NOTIFY — `NOTIFY SET [STATUS] (<filter-set> (<event>...))*`
  // / `NOTIFY NONE`. Subscribes the connection to mailbox / message
  // events on a filter set. Actual event emission is operator-side
  // (the backend's `subscribeNotify(actor, spec, emitFn)` hook); this
  // handler stores the parsed subscription on `state.notifySpec` so
  // the backend can read it on later mutations. NOTIFY NONE clears.
  function _handleNotify(state, socket, tag, args) {
    if (!_requireAuth(state, socket, tag)) return;
    var raw = (args || "").trim();
    if (/^NONE\b/i.test(raw)) {
      state.notifySpec = null;
      if (typeof mailStore.subscribeNotify === "function") {
        try { mailStore.subscribeNotify(state.actor, null, null); }
        catch (_e) { /* drop-silent — operator hook may refuse mid-life */ }
      }
      _writeTagged(socket, tag, "OK NOTIFY completed");
      return;
    }
    var setMatch = raw.match(/^SET\s+(?:STATUS\s+)?(.+)$/i);                                          // allow:regex-no-length-cap — args length already capped upstream
    if (!setMatch) {
      _writeTagged(socket, tag, "BAD NOTIFY syntax (RFC 5465 §6)");
      return;
    }
    // Store the spec verbatim; the backend parses the filter-set
    // vocabulary (`SELECTED`, `SELECTED-DELAYED`, `INBOXES`,
    // `PERSONAL`, `SUBSCRIBED`, `MAILBOXES <list>`, `SUBTREE <list>`)
    // since the event semantics live there. The listener's job is to
    // hand the wire string to the backend.
    state.notifySpec = setMatch[1];
    if (typeof mailStore.subscribeNotify === "function") {
      Promise.resolve()
        .then(function () {
          return mailStore.subscribeNotify(state.actor, state.notifySpec, function (event) {
            // Backend pushes events as { kind, mailbox, payload }; we
            // emit them as untagged responses on the same connection.
            if (!event || typeof event.kind !== "string") return;
            try {
              if (event.kind === "STATUS") {
                _writeUntagged(socket, "STATUS " + event.payload);
              } else if (event.kind === "LIST") {
                _writeUntagged(socket, "LIST " + event.payload);
              } else if (event.kind === "FETCH") {
                _writeUntagged(socket, (event.seq || "") + " FETCH (" + (event.payload || "") + ")");
              }
            } catch (_e) { /* drop-silent — socket may already be closed */ }
          });
        })
        .then(function () { _writeTagged(socket, tag, "OK NOTIFY completed"); })
        .catch(function (err) {
          _writeTagged(socket, tag, "NO " + ((err && err.message) || "NOTIFY refused").slice(0, ERR_CLAMP));
        });
      return;
    }
    // Backend doesn't expose the subscribe hook — accept the wire
    // command but emit no events. RFC 5465 §6 says NO is the right
    // refusal shape when the server cannot fulfil the subscription.
    _writeTagged(socket, tag, "NO NOTIFY backend not configured");
  }

  // RFC 5464 §4.1 GETMETADATA — `GETMETADATA [opts] mailbox entries`.
  // `mailbox` may be `""` for server-wide annotations (METADATA-SERVER).
  // Entries are slash-prefixed names (`/private/foo` / `/shared/bar`).
  // Backend hook: `mailStore.getMetadata(actor, mailbox, names) →
  // [{ entry, value }]`.
  function _handleGetMetadata(state, socket, tag, args) {
    if (!_requireAuth(state, socket, tag)) return;
    if (typeof mailStore.getMetadata !== "function") {
      _writeTagged(socket, tag, "NO GETMETADATA backend not configured");
      return;
    }
    // Strip optional MAXSIZE / DEPTH opts: GETMETADATA (MAXSIZE 1024) "" ("/foo")
    var rest = (args || "").trim();
    var opts = {};
    var optsMatch = rest.match(/^\(([^)]+)\)\s+(.+)$/);                                                // allow:regex-no-length-cap — args length already capped upstream
    if (optsMatch) {
      var optBody = optsMatch[1];
      var maxMatch = optBody.match(/MAXSIZE\s+(\d+)/i);                                                // allow:regex-no-length-cap — optBody bounded by parens
      if (maxMatch) opts.maxSize = parseInt(maxMatch[1], 10);
      var depthMatch = optBody.match(/DEPTH\s+(\w+)/i);                                                // allow:regex-no-length-cap — optBody bounded
      if (depthMatch) opts.depth = depthMatch[1];
      rest = optsMatch[2];
    }
    var partsMatch = rest.match(/^(\S+|"[^"]*")\s+(\(([^)]+)\)|(\/\S+))$/);                            // allow:regex-no-length-cap — args length already capped upstream
    if (!partsMatch) {
      _writeTagged(socket, tag, "BAD GETMETADATA syntax (RFC 5464 §4.1)");
      return;
    }
    var mailbox = _unquote(partsMatch[1]);
    var entries = partsMatch[3]
      ? partsMatch[3].split(/\s+/).filter(Boolean)
      : [partsMatch[4]];
    if (mailbox !== "" && !_validateMailboxName(mailbox, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    Promise.resolve()
      .then(function () { return mailStore.getMetadata(state.actor, mailbox, entries, opts); })
      .then(function (rows) {
        if (Array.isArray(rows) && rows.length > 0) {
          var pairs = rows.map(function (r) {
            var v = r.value === null || r.value === undefined ? "NIL" : '"' + String(r.value).replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + '"';
            return r.entry + " " + v;
          }).join(" ");
          _writeUntagged(socket, "METADATA " + (mailbox === "" ? '""' : mailbox) + " (" + pairs + ")");
        }
        _writeTagged(socket, tag, "OK GETMETADATA completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "GETMETADATA failed").slice(0, ERR_CLAMP));
      });
  }

  // RFC 5464 §4.3 SETMETADATA — `SETMETADATA mailbox (entry value ...)`.
  // Setting `value = NIL` clears the entry. Backend hook:
  // `mailStore.setMetadata(actor, mailbox, entries)`. The wire format
  // delivers each value as a quoted-string or NIL atom; the parser
  // here handles the simple single-line shape (no literals across
  // SETMETADATA — operators using >1 KiB metadata go through APPEND).
  function _handleSetMetadata(state, socket, tag, args, _literalBody) {
    if (!_requireAuth(state, socket, tag)) return;
    if (typeof mailStore.setMetadata !== "function") {
      _writeTagged(socket, tag, "NO SETMETADATA backend not configured");
      return;
    }
    var match = (args || "").trim().match(/^(\S+|"[^"]*")\s+\((.+)\)$/);                              // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD SETMETADATA syntax (RFC 5464 §4.3)");
      return;
    }
    var mailbox = _unquote(match[1]);
    var body = match[2];
    if (mailbox !== "" && !_validateMailboxName(mailbox, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    // Tokenise `<entry> <value> <entry> <value> ...`. Values are
    // `"..."` quoted-string OR `NIL`. Entries are `/private/...` /
    // `/shared/...` slash-prefixed names.
    var entries = [];
    var i = 0;
    while (i < body.length) {
      while (i < body.length && /\s/.test(body[i])) i++;
      if (i >= body.length) break;
      var entryStart = i;
      while (i < body.length && !/\s/.test(body[i])) i++;
      var entryName = body.slice(entryStart, i);
      while (i < body.length && /\s/.test(body[i])) i++;
      if (i >= body.length) {
        _writeTagged(socket, tag, "BAD SETMETADATA entry '" + entryName + "' missing value");
        return;
      }
      var valStart = i;
      var value;
      if (body[i] === '"') {
        i++;
        var v = "";
        while (i < body.length && body[i] !== '"') {
          if (body[i] === "\\" && i + 1 < body.length) { v += body[i + 1]; i += 2; }
          else { v += body[i]; i++; }
        }
        if (body[i] !== '"') {
          _writeTagged(socket, tag, "BAD SETMETADATA unterminated quoted value");
          return;
        }
        i++;
        value = v;
      } else {
        while (i < body.length && !/\s/.test(body[i])) i++;
        var tok = body.slice(valStart, i);
        value = tok.toUpperCase() === "NIL" ? null : tok;
      }
      entries.push({ entry: entryName, value: value });
    }
    if (entries.length === 0) {
      _writeTagged(socket, tag, "BAD SETMETADATA empty entry list");
      return;
    }
    Promise.resolve()
      .then(function () { return mailStore.setMetadata(state.actor, mailbox, entries); })
      .then(function () { _writeTagged(socket, tag, "OK SETMETADATA completed"); })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "SETMETADATA failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleCapability(state, socket, tag) {
    _writeUntagged(socket, "CAPABILITY " + _capabilityLine(state));
    _writeTagged(socket, tag, "OK CAPABILITY completed");
  }

  function _handleId(state, socket, tag, args) {
    // RFC 2971 — clients send a key/value list, server replies with
    // its own. We accept anything (validator caps line size) and reply
    // with a minimal identifier.
    void args;
    _writeUntagged(socket, "ID (\"name\" \"blamejs\" \"version\" \"" + pkgVersion + "\")");
    _writeTagged(socket, tag, "OK ID completed");
  }

  function _handleLogout(state, socket, tag) {
    _writeUntagged(socket, "BYE Logging out");
    _writeTagged(socket, tag, "OK LOGOUT completed");
    _close(socket, state);
  }

  function _handleStartTls(state, socket, tag) {
    if (state.tls) {
      _writeTagged(socket, tag, "BAD TLS already negotiated");
      return;
    }
    _writeTagged(socket, tag, "OK Begin TLS negotiation now");
    // Drain EVERY pre-handshake state field that could carry attacker-
    // controlled bytes past the upgrade boundary (RFC 9051 §11.1 /
    // CVE-2021-33515 class STARTTLS-injection defense):
    //   - lineBuffer:    unparsed bytes pipelined before the handshake.
    //   - pendingLiteral: half-collected APPEND/AUTHENTICATE literal
    //     bytes; if not cleared, the literal completes after upgrade
    //     using bytes the peer sent in plaintext.
    //   - authPending:   the AUTHENTICATE step token; a dangling token
    //     would let the post-TLS state machine resume an exchange that
    //     started in plaintext, conflating cleartext + TLS-protected
    //     phases of the same SASL run.
    // Listener-removal + idle-timeout re-arm live in the shared
    // upgradeSocket helper (b.mail.server.tls.upgradeSocket).
    state.lineBuffer    = Buffer.alloc(0);
    state.pendingLiteral = null;
    state.authPending    = null;
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
        _emit("mail.server.imap.tls_handshake_failed",
          { connectionId: state.id, error: (err && err.message) || String(err) }, "failure");
        _close(socket, state);
      },
      onTimeout: function (tlsSocket) {
        _writeUntagged(tlsSocket, "BYE Idle timeout");
        _close(tlsSocket, state);
      },
    });
  }

  function _handleAuthenticate(state, socket, tag, args) {
    if (state.actor) {
      _writeTagged(socket, tag, "BAD Already authenticated");
      return;
    }
    if (!state.tls && profile !== "permissive") {
      _writeTagged(socket, tag, "BAD AUTHENTICATE requires TLS (use STARTTLS first)");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeTagged(socket, tag, "NO AUTHENTICATE not configured on this listener");
      return;
    }
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (!authAdmit.ok) {
      _emit("mail.server.imap.auth_rate_limit_refused",
        { connectionId: state.id, remoteAddress: state.remoteAddress, reason: authAdmit.reason },
        "denied");
      _writeTagged(socket, tag, "NO [ALERT] Too many AUTH failures from your IP");
      _close(socket, state);
      return;
    }
    var mechName = args.split(" ")[0].toUpperCase();
    var initialResp = args.indexOf(" ") === -1 ? null : args.slice(args.indexOf(" ") + 1).trim();
    var mechanisms = (authConfig.mechanisms || ["PLAIN", "LOGIN"]).map(function (m) {
      return String(m).toUpperCase();
    });
    if (mechanisms.indexOf(mechName) === -1) {
      _writeTagged(socket, tag, "NO Mechanism '" + mechName + "' not advertised");
      return;
    }
    _emit("mail.server.imap.auth_attempt",
      { connectionId: state.id, mechanism: mechName, remoteAddress: state.remoteAddress });
    state.authPending = { mechanism: mechName, tag: tag, step: 0 };
    _runAuthStep(state, socket, initialResp);
  }

  function _runAuthStep(state, socket, clientResp) {
    var pending = state.authPending;
    Promise.resolve()
      .then(function () {
        return authConfig.verify(pending.mechanism, {
          step:           pending.step,
          clientResponse: clientResp,
          tls:            state.tls,
          remoteAddress:  state.remoteAddress,
        });
      })
      .then(function (result) {
        pending.step += 1;
        if (result && result.pending && typeof result.challenge === "string") {
          // Server-side challenge — `+ <base64>` per RFC 9051 §6.2.2.
          _writeContinuation(socket, result.challenge);
          return;
        }
        if (result && result.ok === true && result.actor) {
          state.actor = result.actor;
          state.stage = "authenticated";
          var savedTag = pending.tag;
          state.authPending = null;
          _emit("mail.server.imap.auth_success",
            { connectionId: state.id, mechanism: pending.mechanism,
              tenantId: result.actor.tenantId || null });
          _writeTagged(socket, savedTag, "OK [CAPABILITY " + _capabilityLine(state) + "] AUTHENTICATE completed");
          return;
        }
        var failTag = pending.tag;
        state.authPending = null;
        rateLimit.noteAuthFailure(state.remoteAddress);
        _emit("mail.server.imap.auth_failed",
          { connectionId: state.id, mechanism: pending.mechanism,
            reason: (result && result.reason) || "verify-returned-fail" }, "denied");
        _writeTagged(socket, failTag, "NO Authentication credentials invalid");
      })
      .catch(function (err) {
        var failTag = pending.tag;
        state.authPending = null;
        rateLimit.noteAuthFailure(state.remoteAddress);
        _emit("mail.server.imap.auth_failed",
          { connectionId: state.id, mechanism: pending.mechanism,
            reason: (err && err.message) || String(err) }, "failure");
        _writeTagged(socket, failTag, "NO Authentication failed");
      });
  }

  function _handleLogin(state, socket, tag, args) {
    // RFC 9051 §6.3.4 — LOGIN is deprecated; new MUAs use AUTHENTICATE.
    if (state.actor) {
      _writeTagged(socket, tag, "BAD Already authenticated");
      return;
    }
    if (profile === "strict") {
      _writeTagged(socket, tag, "BAD LOGIN deprecated under strict profile; use AUTHENTICATE");
      return;
    }
    if (!state.tls && profile !== "permissive") {
      _writeTagged(socket, tag, "BAD LOGIN requires TLS (use STARTTLS first)");
      return;
    }
    if (!authConfig || typeof authConfig.verify !== "function") {
      _writeTagged(socket, tag, "NO AUTH not configured");
      return;
    }
    var authAdmit = rateLimit.checkAuthAdmit(state.remoteAddress);
    if (!authAdmit.ok) {
      _writeTagged(socket, tag, "NO [ALERT] Too many AUTH failures from your IP");
      _close(socket, state);
      return;
    }
    // LOGIN args: `user pass` (quoted or atom).
    var parts = _parseLoginArgs(args);
    if (!parts) {
      _writeTagged(socket, tag, "BAD LOGIN expects user + pass");
      return;
    }
    Promise.resolve()
      .then(function () {
        return authConfig.verify("LOGIN", {
          step: 0,
          username:       parts[0],
          password:       parts[1],
          tls:            state.tls,
          remoteAddress:  state.remoteAddress,
        });
      })
      .then(function (result) {
        if (result && result.ok && result.actor) {
          state.actor = result.actor;
          state.stage = "authenticated";
          _emit("mail.server.imap.auth_success",
            { connectionId: state.id, mechanism: "LOGIN", tenantId: result.actor.tenantId || null });
          _writeTagged(socket, tag, "OK [CAPABILITY " + _capabilityLine(state) + "] LOGIN completed");
          return;
        }
        rateLimit.noteAuthFailure(state.remoteAddress);
        _emit("mail.server.imap.auth_failed",
          { connectionId: state.id, mechanism: "LOGIN", reason: "verify-returned-fail" }, "denied");
        _writeTagged(socket, tag, "NO LOGIN credentials invalid");
      })
      .catch(function () {
        rateLimit.noteAuthFailure(state.remoteAddress);
        _writeTagged(socket, tag, "NO LOGIN failed");
      });
  }

  function _parseLoginArgs(args) {
    if (typeof args !== "string") return null;
    // Quoted or atom — RFC 9051 §5.1 quoted ABNF. Inside a quoted
    // string `\"` and `\\` are escape sequences for `"` and `\`
    // respectively; any other `\<chr>` is invalid. The earlier shape
    // terminated the quoted string at the first `"`, so a hostile
    // client passing `LOGIN "alice\"@example.com" "pw"` would have
    // its username truncated at `alice` and the rest of the line
    // reparsed as the password / literal — wrong identity bound to
    // the AUTH state.
    var rest = args.trim();
    function _take() {
      if (rest[0] === "\"") {
        // Walk the quoted-string body, accumulating into `out` while
        // honoring the `\"` / `\\` escape pairs. A bare `\` followed
        // by any other character is refused (parse fails → null).
        var out = "";
        var i = 1;
        while (i < rest.length) {
          var ch = rest.charAt(i);
          if (ch === "\\") {
            var esc = rest.charAt(i + 1);
            if (esc !== "\"" && esc !== "\\") return null;
            out += esc;
            i += 2;
            continue;
          }
          if (ch === "\"") {
            rest = rest.slice(i + 1).trim();
            return out;
          }
          out += ch;
          i += 1;
        }
        return null;   // unterminated quoted string
      }
      var sp = rest.indexOf(" ");
      var v2 = sp === -1 ? rest : rest.slice(0, sp);
      rest = sp === -1 ? "" : rest.slice(sp + 1).trim();
      return v2;
    }
    var user = _take(); if (user === null) return null;
    var pass = _take(); if (pass === null) return null;
    return [user, pass];
  }

  function _requireAuth(state, socket, tag) {
    if (!state.actor) {
      _writeTagged(socket, tag, "NO Login first");
      return false;
    }
    return true;
  }

  function _handleSelect(state, socket, tag, args, examine) {
    if (!_requireAuth(state, socket, tag)) return;
    var trimmed = (args || "").trim();
    // RFC 7162 §3.2.4 — `SELECT mailbox (QRESYNC (<uidvalidity>
    // <modseq> [<knownUids>] [<knownSequenceMatchData>]))`. The
    // QRESYNC parameter is wrapped in an outer parenthesis pair after
    // the mailbox name. Extract it before parsing the mailbox so the
    // mailbox-name validator sees just the name.
    var qresyncParam = null;
    var qresyncMatch = trimmed.match(/^(\S+|"[^"]+")\s+\(\s*QRESYNC\s*\(\s*([^)]+)\)\s*(?:\(\s*([^)]+)\)\s*)?\)\s*$/i);  // allow:regex-no-length-cap — args length already capped upstream
    if (qresyncMatch) {
      var inner = qresyncMatch[2].trim().split(/\s+/);
      qresyncParam = {
        uidvalidity: parseInt(inner[0], 10),
        modseq:      parseInt(inner[1], 10),
        knownUids:   inner[2] || null,
        knownSeq:    qresyncMatch[3] || null,
      };
      if (!isFinite(qresyncParam.uidvalidity) || !isFinite(qresyncParam.modseq)) {
        _writeTagged(socket, tag, "BAD SELECT QRESYNC params must be (<uidvalidity> <modseq> ...) numerics");
        return;
      }
      trimmed = qresyncMatch[1];
    }
    var name = _unquote(trimmed);
    if (!_validateMailboxName(name, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    // QRESYNC requires CONDSTORE to be engaged; if the client sent
    // the parameter without having issued ENABLE first, RFC 7162
    // §3.2.4 lets the server flip the flags implicitly.
    if (qresyncParam && !state.enabledQResync) {
      state.enabledQResync   = true;
      state.enabledCondStore = true;
    }
    Promise.resolve()
      .then(function () {
        if (typeof mailStore.selectFolder === "function") {
          return mailStore.selectFolder(state.actor, name, {
            readOnly:    examine,
            qresync:     qresyncParam,
          });
        }
        // RFC 9051 §2.3.1.1 — UIDVALIDITY MUST be strictly increasing
        // and 32-bit unique across the mailbox lifetime. The earlier
        // fallback returned a sentinel `uidvalidity: 1` to keep tests
        // green when the operator hadn't wired `selectFolder`, but the
        // sentinel value collides with any real UIDVALIDITY=1 from a
        // legitimate backend and tricks clients into believing they
        // have a valid synced state. Refuse SELECT instead — operators
        // MUST wire `mailStore.selectFolder` to expose mailboxes.
        var err = new Error("mailStore.selectFolder is not configured (RFC 9051 §2.3.1.1 requires a unique strictly-increasing UIDVALIDITY)");
        err.code = "mail-server-imap/no-select-backend";
        throw err;
      })
      .then(function (info) {
        state.selectedMailbox = name;
        state.selectedReadOnly = !!examine;
        state.stage = "selected";
        var flagsStr = (info.flags && info.flags.length) ? info.flags.join(" ") : "\\Seen \\Answered \\Flagged \\Deleted \\Draft";
        _writeUntagged(socket, info.exists + " EXISTS");
        _writeUntagged(socket, info.recent + " RECENT");
        _writeUntagged(socket, "FLAGS (" + flagsStr + ")");
        _writeUntagged(socket, "OK [UIDVALIDITY " + info.uidvalidity + "] UIDs valid");
        _writeUntagged(socket, "OK [UIDNEXT " + info.uidnext + "] Predicted next UID");
        if (info.modseq !== undefined) {
          _writeUntagged(socket, "OK [HIGHESTMODSEQ " + info.modseq + "]");
        }
        // RFC 7162 §3.2.5 — when SELECT carried a QRESYNC parameter
        // AND the client's UIDVALIDITY matches, emit a single
        // `* VANISHED (EARLIER) <uid-set>` listing UIDs the server
        // expunged since the client's snapshot. The backend supplies
        // this via `info.vanishedEarlier` (sequence-set string) — the
        // listener does the wire emission. Mismatched UIDVALIDITY
        // means the client's cache is stale and MUST re-SELECT; we
        // skip the VANISHED line in that case so the client falls
        // through to a full re-sync. RFC 7162 §3.2.5.2 says the
        // server MAY also include changed-since-modseq FETCH lines
        // — those flow through the normal FETCH path with
        // CHANGEDSINCE so we leave them to the operator.
        if (qresyncParam && info.vanishedEarlier &&
            info.uidvalidity === qresyncParam.uidvalidity) {
          _writeUntagged(socket, "VANISHED (EARLIER) " + info.vanishedEarlier);
        }
        _emit("mail.server.imap.select", {
          connectionId: state.id, mailbox: name,
          modseq: info.modseq || 0, exists: info.exists,
          qresync: qresyncParam !== null,
        });
        _writeTagged(socket, tag, "OK [" + (examine ? "READ-ONLY" : "READ-WRITE") + "] " +
          (examine ? "EXAMINE" : "SELECT") + " completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Select failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleList(state, socket, tag, args) {
    if (!_requireAuth(state, socket, tag)) return;
    // RFC 9051 §6.3.9 — LIST reference mailbox-pattern. Minimal
    // implementation delegates to mailStore.listFolders if present.
    void args;
    Promise.resolve()
      .then(function () {
        if (typeof mailStore.listFolders === "function") {
          return mailStore.listFolders(state.actor);
        }
        return [{ name: "INBOX", attributes: [] }];
      })
      .then(function (folders) {
        for (var i = 0; i < folders.length; i += 1) {
          var f = folders[i];
          var attrs = (f.attributes || []).map(function (a) { return "\\" + a; }).join(" ");
          _writeUntagged(socket, "LIST (" + attrs + ") \"/\" " + _quote(f.name));
        }
        _writeTagged(socket, tag, "OK LIST completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "List failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleStatus(state, socket, tag, args) {
    if (!_requireAuth(state, socket, tag)) return;
    var match = args.match(/^(\S+|"[^"]+")\s+\(([^)]+)\)$/);                                          // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD STATUS expects mailbox + paren-list of items");
      return;
    }
    var name = _unquote(match[1]);
    var items = match[2].split(/\s+/);
    if (!_validateMailboxName(name, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    Promise.resolve()
      .then(function () {
        if (typeof mailStore.statusFolder === "function") {
          return mailStore.statusFolder(state.actor, name, items);
        }
        return { MESSAGES: 0, UIDNEXT: 1, UIDVALIDITY: 1, UNSEEN: 0 };
      })
      .then(function (info) {
        var parts = [];
        for (var k = 0; k < items.length; k += 1) {
          var key = items[k].toUpperCase();
          if (info[key] !== undefined) parts.push(key + " " + info[key]);
        }
        _writeUntagged(socket, "STATUS " + _quote(name) + " (" + parts.join(" ") + ")");
        _writeTagged(socket, tag, "OK STATUS completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Status failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleAppend(state, socket, tag, args, literalBody) {
    if (!_requireAuth(state, socket, tag)) return;
    // RFC 4469 CATENATE — `APPEND mailbox [(flags)] [date-time] CATENATE
    // (TEXT {literal} URL "imap://...")`. The CATENATE keyword turns the
    // command body into a list of parts the server stitches into a
    // single message; backends supply the `appendCatenate(actor,
    // mailbox, parts, opts) → meta` hook. Without CATENATE, fall
    // through to the bare APPEND path that already exists.
    var catenateMatch = args.match(/^(\S+|"[^"]+")(?:\s+\(([^)]*)\))?(?:\s+("[^"]+"))?\s+CATENATE\s+(.+)$/i);   // allow:regex-no-length-cap — args length already capped upstream
    if (catenateMatch) {
      if (typeof mailStore.appendCatenate !== "function") {
        _writeTagged(socket, tag, "NO CATENATE backend not configured");
        return;
      }
      var catMailbox = _unquote(catenateMatch[1]);
      var catFlags = catenateMatch[2] ? catenateMatch[2].split(/\s+/).filter(Boolean) : [];
      var catDateArg = catenateMatch[3] ? _unquote(catenateMatch[3]) : null;
      var catInternalDate = null;
      if (catDateArg) {
        catInternalDate = _parseImapDateTime(catDateArg);
        if (catInternalDate === null) {
          _writeTagged(socket, tag, "BAD APPEND CATENATE date-time invalid");
          return;
        }
      }
      if (!_validateMailboxName(catMailbox, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
        _writeTagged(socket, tag, "BAD Mailbox name refused");
        return;
      }
      // Validate the parens are well-formed BEFORE we touch the
      // backend. The wire-format parts list MUST start with `(` and
      // end with `)`; a truncated list (e.g. `(TEXT {3}` arriving as
      // a single literal-completion before the rest of the parts
      // streams in) is refused. Order-preserving left-to-right token
      // walk replaces the prior URL-then-TEXT split — CATENATE
      // semantics depend on the SEQUENCE of parts.
      var partsBodyRaw = catenateMatch[4];
      if (partsBodyRaw[0] !== "(" || partsBodyRaw[partsBodyRaw.length - 1] !== ")") {
        _writeTagged(socket, tag, "BAD APPEND CATENATE parts list missing parens (RFC 4469 §3)");
        return;
      }
      var partsBody = partsBodyRaw.slice(1, -1);
      var parts = [];
      var hadTextPart = false;
      // Tokenise sequentially. Each part is one of:
      //   URL "imap://..."
      //   TEXT {<n>}   (literal — multi-literal CATENATE deferred to a
      //                 later slice; defer-with-condition: refused
      //                 with NO until the multi-literal protocol path
      //                 lands).
      var pi = 0;
      while (pi < partsBody.length) {
        while (pi < partsBody.length && /\s/.test(partsBody[pi])) pi += 1;
        if (pi >= partsBody.length) break;
        if (/^URL\b/i.test(partsBody.slice(pi))) {
          pi += 3;                                                                                     // allow:raw-byte-literal — length of literal "URL" keyword
          while (pi < partsBody.length && /\s/.test(partsBody[pi])) pi += 1;
          if (partsBody[pi] !== "\"") {
            _writeTagged(socket, tag, "BAD APPEND CATENATE URL value must be quoted-string");
            return;
          }
          pi += 1;
          var urlStart = pi;
          while (pi < partsBody.length && partsBody[pi] !== "\"") pi += 1;
          if (partsBody[pi] !== "\"") {
            _writeTagged(socket, tag, "BAD APPEND CATENATE URL value unterminated quoted-string");
            return;
          }
          parts.push({ kind: "URL", url: partsBody.slice(urlStart, pi) });
          pi += 1;
        } else if (/^TEXT\b/i.test(partsBody.slice(pi))) {
          hadTextPart = true;
          break;
        } else {
          _writeTagged(socket, tag, "BAD APPEND CATENATE unknown part (RFC 4469 §3 only URL/TEXT)");
          return;
        }
      }
      if (hadTextPart) {
        // Multi-literal CATENATE TEXT parts need a streaming-literal
        // protocol path the listener doesn't currently expose. RFC
        // 4469 §3 explicitly permits servers to refuse parts they
        // can't honour; refusing is correct (better than reordering
        // and corrupting the message body the client requested).
        _writeTagged(socket, tag, "NO CATENATE TEXT-literal parts not yet implemented; use APPEND with a single literal");
        return;
      }
      if (parts.length === 0) {
        _writeTagged(socket, tag, "BAD APPEND CATENATE empty parts list");
        return;
      }
      Promise.resolve()
        .then(function () {
          return mailStore.appendCatenate(catMailbox, parts, {
            actor: state.actor, flags: catFlags, internalDate: catInternalDate });
        })
        .then(function (meta) {
          var ok = "OK APPEND completed";
          if (meta && meta.uid && meta.uidValidity) {
            ok = "OK [APPENDUID " + meta.uidValidity + " " + meta.uid + "] APPEND completed";
          }
          _writeTagged(socket, tag, ok);
        })
        .catch(function (err) {
          _writeTagged(socket, tag, "NO " + ((err && err.message) || "CATENATE failed").slice(0, ERR_CLAMP));
        });
      return;
    }
    if (!literalBody) {
      _writeTagged(socket, tag, "BAD APPEND requires a literal {N} message");
      return;
    }
    // RFC 9051 §6.3.12 — APPEND mailbox [(flags)] [date-time] literal
    var match = args.match(/^(\S+|"[^"]+")(?:\s+\(([^)]*)\))?(?:\s+("[^"]+"))?$/);                    // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD APPEND syntax");
      return;
    }
    var name = _unquote(match[1]);
    var flags = match[2] ? match[2].split(/\s+/).filter(Boolean) : [];
    // RFC 9051 §6.3.12 — optional date-time argument sets INTERNALDATE
    // on the appended message. Earlier shape captured the token but
    // never threaded it; backends now receive it as `internalDate`
    // (ms-since-epoch) and the mail-store applies it instead of the
    // append-time clock. Refused as syntax error when the date-time
    // can't be parsed (rather than silently using the clock).
    var dateTimeArg = match[3] ? _unquote(match[3]) : null;
    var internalDate = null;
    if (dateTimeArg) {
      internalDate = _parseImapDateTime(dateTimeArg);
      if (internalDate === null) {
        _writeTagged(socket, tag, "BAD APPEND date-time '" + dateTimeArg +
          "' not in RFC 9051 §6.3.12 / RFC 5322 §3.3 date-time grammar");
        return;
      }
    }
    if (!_validateMailboxName(name, { allowLegacyMUtf7: allowLegacyMUtf7 })) {
      _writeTagged(socket, tag, "BAD Mailbox name refused");
      return;
    }
    Promise.resolve()
      .then(function () {
        // RFC 9208 — when the backend exposes a per-mailbox / per-user
        // quota, APPEND MUST check against it BEFORE writing the
        // message. The earlier shape called `appendMessage` directly,
        // leaving quota enforcement entirely up to the backend; an
        // operator wiring a bare `appendMessage` without quota plumbing
        // could be DoS'd via unbounded APPENDs filling the mailbox
        // beyond the advertised QUOTA limit. Honor `mailStore.quota`
        // (RFC 9208 GETQUOTA / IMAP-QUOTA returns the same shape) and
        // surface 5.7.4 OVERQUOTA per §5.
        if (typeof mailStore.quota === "function") {
          // mailStore.quota(folderName) returns
          // { usedBytes, usedCount, capBytes, capCount } per the
          // lib/mail-store.js contract. capBytes is null when no
          // quota is configured for the folder; honor it only when
          // it's a positive number.
          return Promise.resolve(mailStore.quota(name))
            .then(function (q) {
              if (q && typeof q.usedBytes === "number" &&
                  typeof q.capBytes === "number" &&
                  q.capBytes > 0 &&
                  q.usedBytes + literalBody.length > q.capBytes) {
                var err = new Error("APPEND would exceed quota (used " + q.usedBytes +
                  " + " + literalBody.length + " > cap " + q.capBytes + ")");
                err.code = "mail-server-imap/overquota";
                err.overquota = true;
                err.limit = q.capBytes;
                throw err;
              }
              return mailStore.appendMessage(name, literalBody, {
                actor: state.actor, flags: flags, internalDate: internalDate });
            });
        }
        return mailStore.appendMessage(name, literalBody, {
          actor: state.actor, flags: flags, internalDate: internalDate });
      })
      .then(function (info) {
        _emit("mail.server.imap.append",
          { connectionId: state.id, mailbox: name, size: literalBody.length, flags: flags });
        var token = info && info.uid ? "[APPENDUID " + (info.uidvalidity || 0) + " " + info.uid + "] " : "";
        _writeTagged(socket, tag, "OK " + token + "APPEND completed");
      })
      .catch(function (err) {
        if (err && err.overquota) {
          _writeTagged(socket, tag, "NO [OVERQUOTA] Quota exceeded (RFC 9208 §5)");
          return;
        }
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Append failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleClose(state, socket, tag) {
    state.selectedMailbox = null;
    state.selectedReadOnly = false;
    state.stage = "authenticated";
    _writeTagged(socket, tag, "OK CLOSE completed");
  }

  function _handleExpunge(state, socket, tag) {
    if (!state.selectedMailbox) {
      _writeTagged(socket, tag, "NO No mailbox selected");
      return;
    }
    Promise.resolve()
      .then(function () {
        if (typeof mailStore.expungeFolder === "function") {
          return mailStore.expungeFolder(state.actor, state.selectedMailbox);
        }
        return { expunged: [], modseq: 0 };
      })
      .then(function (info) {
        var ex = info.expunged || [];
        for (var i = 0; i < ex.length; i += 1) {
          _writeUntagged(socket, ex[i] + " EXPUNGE");
        }
        _emit("mail.server.imap.expunge",
          { connectionId: state.id, mailbox: state.selectedMailbox,
            count: ex.length, modseq: info.modseq || 0 });
        _writeTagged(socket, tag, "OK EXPUNGE completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Expunge failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleFetch(state, socket, tag, args, useUid) {
    if (!state.selectedMailbox) {
      // RFC 9051 §6.4.5 — FETCH outside of Selected state is a
      // protocol-context violation, not a server-policy refusal.
      // BAD signals the client to fix its dialog rather than retry.
      _writeTagged(socket, tag, "BAD FETCH only valid in Selected state (RFC 9051 §6.4.5)");
      return;
    }
    if (typeof mailStore.fetchRange !== "function") {
      _writeTagged(socket, tag, "BAD FETCH backend not configured");
      return;
    }
    var match = args.match(/^(\S+)\s+(.+)$/);                                                          // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD FETCH expects sequence-set + parts");
      return;
    }
    var seqSet = match[1];
    var partsSpec = match[2];
    // RFC 7162 §3.1.4 — FETCH may carry a CHANGEDSINCE modifier in a
    // trailing parenthesised list:
    //   FETCH 1:* (FLAGS) (CHANGEDSINCE 12345)
    // and/or VANISHED (QRESYNC) which is deferred to a later slice.
    // The modifier list is parsed off the END of partsSpec; what
    // remains is handed to the backend as the fetch-att spec.
    var changedSince = null;
    var includeVanished = false;
    var modMatch = partsSpec.match(/\s*\(([^)]*)\)\s*$/);                                              // allow:regex-no-length-cap — partsSpec already bounded upstream
    if (modMatch && /\b(CHANGEDSINCE|VANISHED)\b/i.test(modMatch[1])) {
      var modBody = modMatch[1];
      var changedMatch = modBody.match(/CHANGEDSINCE\s+(\d+)/i);                                       // allow:regex-no-length-cap — modBody already bounded
      if (changedMatch) {
        var csN = parseInt(changedMatch[1], 10);
        if (isFinite(csN) && csN >= 0) changedSince = csN;
      }
      includeVanished = /\bVANISHED\b/i.test(modBody);
      partsSpec = partsSpec.slice(0, partsSpec.length - modMatch[0].length).trim();
    }
    // RFC 7162 §3.1.2 — any FETCH that uses CHANGEDSINCE implicitly
    // engages CONDSTORE for the session; the client expects MODSEQ
    // in responses even without a prior `ENABLE CONDSTORE`. RFC 7162
    // §3.1.4.1 — when CONDSTORE is engaged (explicit ENABLE OR
    // implicit via CHANGEDSINCE) OR the client requested MODSEQ as a
    // fetch-att, every untagged FETCH response includes the MODSEQ
    // attribute. Engaging CONDSTORE via CHANGEDSINCE also sticks for
    // the rest of the session.
    if (changedSince !== null && !state.enabledCondStore) {
      state.enabledCondStore = true;
    }
    var includeModseq = state.enabledCondStore === true ||
                        changedSince !== null ||
                        /\bMODSEQ\b/i.test(partsSpec);
    Promise.resolve()
      .then(function () {
        return mailStore.fetchRange(state.actor, state.selectedMailbox, seqSet, partsSpec,
          { useUid: useUid === true, changedSince: changedSince, includeVanished: includeVanished,
            includeModseq: includeModseq });
      })
      .then(function (rows) {
        var rs = rows || [];
        _emit("mail.server.imap.fetch_bulk",
          { connectionId: state.id, mailbox: state.selectedMailbox, count: rs.length,
            changedSince: changedSince, condStore: state.enabledCondStore === true });
        for (var i = 0; i < rs.length; i += 1) {
          var r = rs[i];
          var payload = r.payload || "";
          if (includeModseq && r.modseq !== undefined && !/MODSEQ\s*\(/.test(payload)) {
            payload = (payload ? payload + " " : "") + "MODSEQ (" + r.modseq + ")";
          }
          _writeUntagged(socket, r.seq + " FETCH (" + payload + ")");
        }
        _writeTagged(socket, tag, "OK FETCH completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Fetch failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleStore(state, socket, tag, args, useUid) {
    if (!state.selectedMailbox) {
      // RFC 9051 §6.4.6 — STORE outside of Selected state is a
      // protocol-context violation. BAD (not NO) is the correct
      // response per the IMAP grammar; UID STORE has the same rule
      // since the verb is just a `UID` prefix on STORE.
      _writeTagged(socket, tag, "BAD STORE only valid in Selected state (RFC 9051 §6.4.6)");
      return;
    }
    if (state.selectedReadOnly) {
      _writeTagged(socket, tag, "NO Mailbox is read-only");
      return;
    }
    if (typeof mailStore.storeFlags !== "function") {
      _writeTagged(socket, tag, "BAD STORE backend not configured");
      return;
    }
    // RFC 7162 §3.1.3 — STORE may carry a parenthesised UNCHANGEDSINCE
    // modifier between the sequence-set and the FLAGS op:
    //   STORE 1:* (UNCHANGEDSINCE 12345) +FLAGS (\Deleted)
    // The backend's response shape is { rows, modified } — `modified`
    // is the seq-set string of message ids whose modseq advanced past
    // unchangedSince before this STORE ran. We surface those via
    // [MODIFIED <set>] OK response (RFC 7162 §3.1.3).
    var unchangedSince = null;
    var unchangedMatch = args.match(/^(\S+)\s+\(UNCHANGEDSINCE\s+(\d+)\)\s+(.+)$/i);                   // allow:regex-no-length-cap — args length already capped upstream
    if (unchangedMatch) {
      var usN = parseInt(unchangedMatch[2], 10);
      if (isFinite(usN) && usN >= 0) unchangedSince = usN;
      args = unchangedMatch[1] + " " + unchangedMatch[3];
    }
    var match = args.match(/^(\S+)\s+([+-]?FLAGS(?:\.SILENT)?)\s+\(([^)]*)\)$/i);                     // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD STORE expects seq-set FLAGS (...)");
      return;
    }
    var seqSet = match[1];
    var op = match[2].toUpperCase();
    var flagsArr = match[3].split(/\s+/).filter(Boolean);
    var silent = /\.SILENT$/i.test(op);
    var mode = op[0] === "+" ? "add" : op[0] === "-" ? "remove" : "replace";
    // RFC 7162 §3.1.2 — UNCHANGEDSINCE in STORE engages CONDSTORE for
    // the session (same implicit-enable rule as FETCH CHANGEDSINCE).
    if (unchangedSince !== null && !state.enabledCondStore) {
      state.enabledCondStore = true;
    }
    var includeModseqStore = state.enabledCondStore === true || unchangedSince !== null;
    Promise.resolve()
      .then(function () {
        return mailStore.storeFlags(state.actor, state.selectedMailbox, seqSet, mode, flagsArr,
          { useUid: useUid === true, unchangedSince: unchangedSince, includeModseq: includeModseqStore });
      })
      .then(function (result) {
        // Backend may return either an array of rows (legacy shape)
        // OR an object `{ rows, modified }`. Normalise.
        var rs, modifiedSet;
        if (Array.isArray(result)) { rs = result; modifiedSet = null; }
        else if (result && typeof result === "object") {
          rs = result.rows || [];
          modifiedSet = result.modified || null;
        } else { rs = []; modifiedSet = null; }
        // RFC 7162 §3.1.3 — under CONDSTORE / UNCHANGEDSINCE, the
        // server MUST emit a FETCH response carrying the new MODSEQ
        // for every successfully-updated message EVEN UNDER .SILENT.
        // Without it, CONDSTORE clients cannot refresh their local
        // modseq state and drift out of sync. Under non-CONDSTORE
        // .SILENT, the legacy behaviour stays (no untagged FETCH).
        var emitFlags = !silent;
        var emitModseqOnly = silent && includeModseqStore;
        if (emitFlags || emitModseqOnly) {
          for (var i = 0; i < rs.length; i += 1) {
            var r = rs[i];
            var payload;
            if (emitFlags) {
              payload = "FLAGS (" + (r.flags || []).join(" ") + ")";
              if (includeModseqStore && r.modseq !== undefined) {
                payload = payload + " MODSEQ (" + r.modseq + ")";
              }
            } else if (r.modseq !== undefined) {
              // SILENT + CONDSTORE — emit MODSEQ alone (no FLAGS).
              payload = "MODSEQ (" + r.modseq + ")";
            } else {
              continue;
            }
            _writeUntagged(socket, r.seq + " FETCH (" + payload + ")");
          }
        }
        var okTag = "OK STORE completed";
        // RFC 7162 §3.1.3 — MODIFIED carries the set of ids the
        // conditional STORE refused to update because their modseq
        // advanced past unchangedSince. Clients re-issue FETCH against
        // the set to refresh state before retry.
        if (modifiedSet && String(modifiedSet).length > 0) {
          okTag = "OK [MODIFIED " + modifiedSet + "] STORE completed";
        }
        _writeTagged(socket, tag, okTag);
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Store failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleUid(state, socket, tag, args) {
    // UID FETCH / UID STORE / UID SEARCH / UID COPY / UID MOVE per
    // RFC 9051 §6.4.9. The sub-command's sequence-set is interpreted
    // as UIDs (not message-sequence-numbers); we pass `useUid: true`
    // to the sub-handler which threads it through to the backend's
    // mailStore.fetchRange / storeFlags via opts. Without this, the
    // backend treats the seq-set as msg-numbers and a client's
    // `UID FETCH 12345 (BODY[])` returns the WRONG message.
    var sub = args.match(/^(\S+)\s+(.+)$/);                                                            // allow:regex-no-length-cap — args length already capped upstream
    if (!sub) {
      _writeTagged(socket, tag, "BAD UID expects a sub-command");
      return;
    }
    var subVerb = sub[1].toUpperCase();
    var subArgs = sub[2];
    if (subVerb === "FETCH") return _handleFetch(state, socket, tag, subArgs, true);
    if (subVerb === "STORE") return _handleStore(state, socket, tag, subArgs, true);
    // RFC 9051 §6.4.9 also defines UID SEARCH / UID COPY / UID MOVE /
    // UID EXPUNGE; deferred from the initial listener slice.
    //
    //   SEARCH:  composes with the existing _handleSearch path; needs
    //            the searchRange path threaded through `useUid: true`.
    //   COPY:    composes with the existing _handleCopy path; needs
    //            the mailStore.copyRange opt accepted.
    //   MOVE:    RFC 6851; same shape as COPY plus an atomic-delete
    //            step on the source mailbox.
    //   EXPUNGE: RFC 4315 UIDPLUS; expunges by uid-set instead of by
    //            \Deleted-flag scan.
    //
    // Re-open condition: operator surfaces a real IMAP client that
    // refuses to fall back to seq-number variants (most modern
    // clients — mutt / Thunderbird / Apple Mail / Outlook — already
    // use the seq-number forms when UID variants are unavailable).
    //
    // Operator escape hatch today: clients that issue these UID
    // sub-commands receive `BAD` and retry against the seq-number
    // variant (SEARCH / COPY / MOVE / EXPUNGE) which the listener
    // does serve.
    _writeTagged(socket, tag, "BAD UID " + subVerb +
                 " is not yet implemented; client may retry with the seq-number form");
  }

  function _handleIdle(state, socket, tag) {
    if (!_requireAuth(state, socket, tag)) return;
    _writeContinuation(socket, "idling");
    // RFC 2177 §3 — IDLE must be terminated with DONE before
    // bandwidth-timeout. We schedule a soft cutoff 1 min before the
    // hard 30-min cutoff to force client re-issue.
    var timer = setTimeout(function () {
      if (state.idle) {
        _writeUntagged(socket, "BYE IDLE timed out — re-issue");
        state.idle = null;
        _close(socket, state);
      }
    }, IDLE_BANDWIDTH_TIMEOUT_MS);
    state.idle = { tag: tag, timer: timer };
  }

  function _writeTagged(socket, tag, msg) {
    try { socket.write(tag + " " + msg + "\r\n"); }
    catch (_e) { /* socket may be down */ }
  }
  function _writeUntagged(socket, msg) {
    try { socket.write("* " + msg + "\r\n"); }
    catch (_e) { /* socket may be down */ }
  }
  function _writeContinuation(socket, msg) {
    try { socket.write("+ " + msg + "\r\n"); }
    catch (_e) { /* socket may be down */ }
  }
  function _close(socket, state) {
    // The drain loop's `if (state.stage === "closed") return;` guard
    // (around the bottom of _drainBuffer) was dead before this —
    // _close never wrote the sentinel, so the drain loop kept
    // processing buffered bytes after the socket was destroyed.
    // Setting stage="closed" here makes the guard reachable so a
    // close mid-loop short-circuits the next command dispatch
    // (defense-in-depth against an exception thrown by a handler
    // that doesn't tear down the loop).
    if (state && typeof state === "object") state.stage = "closed";
    try { socket.end(); } catch (_e) { /* idempotent */ }
    try { socket.destroy(); } catch (_e2) { /* idempotent */ }
    connections.delete(socket);
  }
  function _quote(s) { return '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + '"'; }
  function _unquote(s) {
    if (typeof s !== "string") return "";
    if (s[0] === "\"" && s[s.length - 1] === "\"") return s.slice(1, -1);
    return s;
  }

  // ---- Lifecycle ----------------------------------------------------------
  async function listen(listenOpts) {
    listenOpts = listenOpts || {};
    if (listening) {
      throw new MailServerImapError("mail-server-imap/already-listening",
        "listen: already listening");
    }
    var port    = listenOpts.port    === undefined ? 143 : listenOpts.port;                           // allow:raw-byte-literal — RFC 9051 IMAP port (IANA)
    var address = listenOpts.address || "0.0.0.0";
    tcpServer = net.createServer(function (socket) { _handleConnection(socket); });
    return new Promise(function (resolve, reject) {
      tcpServer.once("error", reject);
      tcpServer.listen(port, address, function () {
        listening = true;
        tcpServer.removeListener("error", reject);
        _emit("mail.server.imap.listening",
          { port: port, address: address });
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
        _emit("mail.server.imap.closed", {});
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
  MailServerImapError:  MailServerImapError,
};

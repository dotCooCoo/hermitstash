// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   - **SEARCH / COPY / MOVE** — operator-domain logic against the
 *     mailStore index, supplied through `opts.overrides`; until then
 *     the listener answers `NO <verb> not configured`. A handler
 *     supplied once serves BOTH the plain and the `UID` form: the UID
 *     verb dispatches back through the same registry entry and sets
 *     `parsed.useUid`, which the handler reads to answer in unique
 *     identifiers per RFC 9051 §6.4.9.
 *   - **UID EXPUNGE (RFC 4315)** — refused unless the operator
 *     supplies an EXPUNGE handler that reads the uid-set. The shipped
 *     EXPUNGE takes no set and expunges every message flagged
 *     `\Deleted`, so serving the UID form from it would delete
 *     messages the client did not name.
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
var safeBuffer = require("./safe-buffer");
var C = require("./constants");
var numericBounds = require("./numeric-bounds");
var validateOpts = require("./validate-opts");
var guardImapCommand = require("./guard-imap-command");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerRegistry = require("./mail-server-registry");
var mailServerTls = require("./mail-server-tls");
var mailServerNet = require("./mail-server-net");
var time = require("./time");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");

var MailServerImapError = defineClass("MailServerImapError", { alwaysPermanent: true });

var IMAP_ATOM_PRINTABLE = /^[\x21-\x7e]+$/;                                                             // allow:raw-byte-literal — RFC 9051 §9 CHAR range
var IMAP_ATOM_SPECIAL   = /[()%*"\\\]{]/;

function _isCapabilityAtom(value) {
  return IMAP_ATOM_PRINTABLE.test(value) && !IMAP_ATOM_SPECIAL.test(value);
}

var DEFAULT_MAX_LINE_BYTES   = C.BYTES.kib(8);
var PIPELINE_LINE_ALLOWANCE  = 8;
var CRLF_BYTE_LEN            = 2;
var DEFAULT_MAX_LITERAL      = C.BYTES.mib(64);
var PRE_AUTH_LITERAL_VERBS = Object.freeze({
  AUTHENTICATE: true,
  LOGIN:        true,
  ID:           true,
});

var LITERAL_DEADLINE_GRACE_MS = C.TIME.seconds(1);

var DEFAULT_IDLE_TIMEOUT_MS  = C.TIME.minutes(30);
var IDLE_BANDWIDTH_TIMEOUT_MS = C.TIME.minutes(29);
var DEFAULT_GREETING_VENDOR  = "blamejs IMAP4rev2";
var pkgVersion = require("../package.json").version;
var codepointClass = require("./codepoint-class");

var ERR_CLAMP = 200;
var CRLF_BYTES = Buffer.from("\r\n", "latin1");
var LINE_PREVIEW = 80;

var IMAP_MONTHS = Object.freeze({
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
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

var _IMAP_WS_RE = /\s/;

function _trailingParenGroup(s) {
  var e = s.length - 1;
  while (e >= 0 && _IMAP_WS_RE.test(s.charAt(e))) e -= 1;
  if (e < 0 || s.charAt(e) !== ")") return null;
  var open = -1;
  for (var i = e - 1; i >= 0; i -= 1) {
    var c = s.charAt(i);
    if (c === ")") break;
    if (c === "(") open = i;
  }
  if (open === -1) return null;
  var start = open;
  while (start > 0 && _IMAP_WS_RE.test(s.charAt(start - 1))) start -= 1;
  return { body: s.slice(open + 1, e), matchLength: s.length - start };
}

function _validateMailboxName(name, opts) {
  if (typeof name !== "string" || name.length === 0) return false;
  if (name.length > 1024) return false;
  if (codepointClass.firstControlCharOffset(name, { forbidTab: true }) !== -1) return false;
  if (name.indexOf("..") !== -1) return false;
  if (name === "/" || name[0] === "/" || name[name.length - 1] === "/") return false;
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
 *   implicitTls:       boolean,         // RFC 8314 §3 — TLS from the SYN on 993 (the default port becomes 993). STARTTLS is neither advertised nor accepted on it. Default false
 *   greeting:          string,           // default "blamejs IMAP4rev2"
 *   maxLineBytes:      number,           // default 8192
 *   maxLiteralBytes:   number,           // default 64 MiB
 *   idleTimeoutMs:     number,           // default 30 min
 *   maxConnections:    number,           // default 1024 — listener-wide ceiling
 *   profile:           "strict" | "balanced" | "permissive",
 *   auth: {
 *     mechanisms:      ["PLAIN", "LOGIN", "SCRAM-SHA-256", "EXTERNAL", "XOAUTH2"],
 *     verify:          async function (mechanism, credentials) → { ok, actor },
 *   },
 *   mailStore:         b.mailStore handle,    // required
 *   rateLimit:         b.mail.server.rateLimit handle | opts | false,
 *   capabilities:      function (caps, state) → string[],   // optional. The advertised capability list, applied where it is COMPUTED — so the greeting, the CAPABILITY answer and the code completing AUTHENTICATE / LOGIN all carry the same thing. IMAP4rev2 is re-added if dropped (RFC 9051 §6.1.1)
 *   audit:             b.audit                // optional
 *
 * `fetchRange` may return each row's `payload` as a Buffer, and should whenever
 * the row carries message content. RFC 9051 §4.3 makes a literal a counted
 * sequence of octets, and a string cannot hold one: a message octet that is not
 * valid UTF-8 does not survive being encoded on the way to the socket, and the
 * count the response announced stops matching the number of octets it wrote —
 * which is what tells a client where the response ends. A Buffer payload is
 * framed and written as the octets it holds. A string payload is unchanged and
 * remains right for the rows that carry only attributes, such as `FLAGS (\Seen)`.
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
 *     mailStore: b.mailStore.create({ backend: b.db }),
 *   });
 *   await imap.listen({ port: 143 });
 */
var CREATE_OPTS = [
  "tlsContext", "implicitTls", "greeting", "maxLineBytes", "maxLiteralBytes",
  "idleTimeoutMs", "maxConnections", "profile", "auth", "mailStore",
  "rateLimit", "capabilities", "allowLegacyMUtf7", "overrides",
  "agentTenantId", "tenantScope", "audit",
];

function create(opts) {
  validateOpts.requireObject(opts, "mail.server.imap.create",
    MailServerImapError, "mail-server-imap/bad-opts");
  validateOpts.checkOrThrow(opts, CREATE_OPTS, "mail.server.imap.create",
    MailServerImapError, "mail-server-imap/bad-opts");
  validateOpts.auditShape(opts.audit, "mail.server.imap.create",
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
    ["maxLineBytes", "maxLiteralBytes", "idleTimeoutMs", "maxConnections"],
    "mail.server.imap.", MailServerImapError, "mail-server-imap/bad-bound");

  var greeting          = opts.greeting        || DEFAULT_GREETING_VENDOR;
  var maxLineBytes      = opts.maxLineBytes    || DEFAULT_MAX_LINE_BYTES;
  var maxPipelinedBytes = (maxLineBytes + CRLF_BYTE_LEN) * PIPELINE_LINE_ALLOWANCE;
  var maxLiteralBytes   = opts.maxLiteralBytes || DEFAULT_MAX_LITERAL;
  var idleTimeoutMs     = opts.idleTimeoutMs   || DEFAULT_IDLE_TIMEOUT_MS;
  var profile           = opts.profile         || "strict";
  var authConfig        = opts.auth            || null;
  var implicitTls       = opts.implicitTls === true;
  var capabilitiesHook  = validateOpts.definedFunction(opts.capabilities,
    "b.mail.server.imap.create: capabilities", MailServerImapError,
    "mail-server-imap/bad-opts");
  var mailStore         = opts.mailStore;
  var allowLegacyMUtf7  = profile === "permissive";

  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

  var connections  = new Set();

  var _emit = auditEmit.dualEmitter(opts);

  function _handleConnection(rawSocket) {
    var accepted = mailServerNet.acceptConnection(rawSocket, {
      rateLimit:    rateLimit,
      connections:  connections,
      emit:         _emit,
      refusedEvent: "mail.server.imap.rate_limit_refused",
      refusalLine:  "* BAD Too many connections from your IP\r\n",
      idPrefix:     "imapconn-",
      wrap:         mailServerTls.implicitTlsWrap(opts.tlsContext, implicitTls),
    });
    if (accepted === null) return;
    var remoteAddress = accepted.remoteAddress;
    var connectionId  = accepted.connectionId;
    var socket        = accepted.socket;

    var state = {
      id:            connectionId,
      remoteAddress: remoteAddress,
      tls:           implicitTls,
      stage:         "not-authenticated",
      closed:        false,
      actor:         null,
      selectedMailbox: null,
      selectedReadOnly: false,
      authPending:   null,
      pendingLiteral: null,
      idle:          null,
      lineBuffer:    Buffer.alloc(0),
      bodyRateWindow: mailServerNet.createBodyRateWindow(rateLimit),
      wireBytes:      0,
      literalDeadline: null,
    };

    _emit("mail.server.imap.connect",
      { connectionId: connectionId, remoteAddress: remoteAddress });

    mailServerNet.wireLineSocket(socket, {
      idleTimeoutMs: idleTimeoutMs,
      state:         state,
      onIdleTimeout: function () { _writeUntagged(socket, "BYE Idle timeout"); },
      onError:       function (err) {
        _emit("mail.server.imap.socket_error",
          { connectionId: connectionId, error: (err && err.message) || String(err) }, "failure");
      },
      close:         function () { _close(socket, state); },
    });
    socket.on("close", function () { _clearLiteralDeadline(state); });

    _writeUntagged(socket, "OK [CAPABILITY " + _capabilityLine(state) + "] " + greeting);

    socket.on("data", function (chunk) {
      var pendingLiteral = state.pendingLiteral;
      if (pendingLiteral) {
        var room = (pendingLiteral.size - pendingLiteral.body.length) + maxPipelinedBytes;
        if (chunk.length > room) {
          _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
          _close(socket, state);
          return;
        }
      }
      state.wireBytes += chunk.length;
      if (state.pendingLiteral && state.pendingLiteral.size > 0 &&
          state.bodyRateWindow.starved(state.wireBytes, time.monotonicMs())) {
        _emit("mail.server.imap.literal_refused",
          { connectionId: state.id, reason: "body-rate-below-floor",
            minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
        _writeUntagged(socket, "BYE Literal arriving below the minimum rate; closing connection");
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
      if (!state.pendingLiteral) return;
      if (!state.bodyRateWindow.starved(state.wireBytes, time.monotonicMs())) {
        _armLiteralDeadline(state, socket);
        return;
      }
      _emit("mail.server.imap.literal_refused",
        { connectionId: state.id, reason: "body-rate-below-floor",
          minBytesPerSecond: rateLimit.minBytesPerSecond() }, "denied");
      _writeUntagged(socket, "BYE Literal arriving below the minimum rate; closing connection");
      _close(socket, state);
    }, rateLimit.bodyRateWindowMs() + LITERAL_DEADLINE_GRACE_MS);
    if (typeof state.literalDeadline.unref === "function") state.literalDeadline.unref();
  }
  function _clearLiteralDeadline(state) {
    if (state.literalDeadline) { clearTimeout(state.literalDeadline); state.literalDeadline = null; }
  }

  function _openerBytes(line) {
    var parsed;
    try {
      parsed = guardImapCommand.validate(line, { profile: profile, authenticated: true });
    } catch (_e) { return null; }
    if (parsed.literalSize === null || parsed.literalSize > maxLiteralBytes) return null;
    return parsed.literalSize;
  }

  function _announcedLiteralBytes(state) {
    return mailServerNet.announcedLiteralBytes(state.lineBuffer, {
      pending:           state.pendingLiteral,
      maxLineBytes:      maxLineBytes,
      maxPipelinedBytes: maxPipelinedBytes,
      openerBytes:       _openerBytes,
    });
  }

  function _backlogRefused(state, socket) {
    var held = safeBuffer.byteLengthOf(state.lineBuffer);
    if (held <= maxPipelinedBytes) return false;
    if (held - _announcedLiteralBytes(state) <= maxPipelinedBytes) return false;
    _writeUntagged(socket, "BAD Too much pipelined data awaiting execution (cap " +
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
      _emit("mail.server.imap.handler_threw",
        { connectionId: state.id, error: (e && e.message) || String(e) }, "failure");
      try { _writeUntagged(socket, "BAD Server error"); } catch (_e) { /* socket gone */ }
      _close(socket, state);
    }
    function after(pending) { Promise.resolve(pending).then(step, fail); }

    function step() {
      if (state.closed) return done();
      if (!state.pendingLiteral && _backlogRefused(state, socket)) return done();
      if (state.pendingLiteral) {
        var need = state.pendingLiteral.size - state.pendingLiteral.body.length;
        if (state.lineBuffer.length < need) {
          state.pendingLiteral.body = Buffer.concat([state.pendingLiteral.body, state.lineBuffer]);
          state.lineBuffer = Buffer.alloc(0);
          return done();
        }
        state.pendingLiteral.body = Buffer.concat([state.pendingLiteral.body, state.lineBuffer.subarray(0, need)]);
        state.lineBuffer = state.lineBuffer.subarray(need);
        var tail = state.lineBuffer.indexOf("\r\n");
        if (tail === -1) {
          if (safeBuffer.byteLengthOf(state.lineBuffer) > maxLineBytes) {
            _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
            _close(socket, state);
          }
          return done();
        }
        var rest = state.lineBuffer.subarray(0, tail).toString("utf8");
        state.lineBuffer = state.lineBuffer.subarray(tail + 2);
        return after(_completeLiteralCommand(state, socket, rest));
      }
      var crlf = state.lineBuffer.indexOf("\r\n");
      if (crlf === -1) {
        if (safeBuffer.byteLengthOf(state.lineBuffer) > maxLineBytes) {
          _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
          _close(socket, state);
        }
        return done();
      }
      if (crlf > maxLineBytes) {
        _writeUntagged(socket, "BAD Line too long (cap " + maxLineBytes + ")");
        _close(socket, state);
        return done();
      }
      var rawLine = state.lineBuffer.subarray(0, crlf).toString("utf8");
      state.lineBuffer = state.lineBuffer.subarray(crlf + 2);
      state.literalAbsorbed = 0;
      state.literalSyntaxBytes = 0;
      return after(_handleLine(state, socket, rawLine));
    }
    step();
  }

  function _handleLine(state, socket, line) {
    if (state.authPending) {
      return _runAuthStep(state, socket, line.trim());
    }
    if (state.idle) {
      if (line.toUpperCase() === "DONE") {
        var idleTag = state.idle.tag;
        if (state.idle.timer) clearTimeout(state.idle.timer);
        state.idle = null;
        _writeTagged(socket, idleTag, "OK IDLE terminated");
      } else {
        _writeUntagged(socket, "BAD Expected DONE during IDLE");
      }
      return undefined;
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
    if (parsed.literalSize !== null) {
      if (parsed.literalSize > maxLiteralBytes) {
        _emit("mail.server.imap.literal_overflow_refused",
          { connectionId: state.id, attempted: parsed.literalSize, cap: maxLiteralBytes },
          "denied");
        _writeTagged(socket, parsed.tag,
          "NO Literal " + parsed.literalSize + " bytes exceeds cap " + maxLiteralBytes);
        return;
      }
      if (!state.actor &&
          !Object.prototype.hasOwnProperty.call(PRE_AUTH_LITERAL_VERBS, parsed.verb)) {
        _emit("mail.server.imap.literal_refused_pre_auth",
          { connectionId: state.id, verb: parsed.verb, size: parsed.literalSize },
          "denied");
        _writeTagged(socket, parsed.tag,
          "NO " + parsed.verb + " requires authentication; no literal accepted before LOGIN");
        return;
      }
      if (parsed.literalSize === 0) {
        state.pendingLiteral = {
          tag:  parsed.tag,
          verb: parsed.verb,
          line: line,
          size: 0,
          body: Buffer.alloc(0),
          synchronizing: !parsed.literalNonSync,
        };
        if (!parsed.literalNonSync) _writeContinuation(socket, "Ready for literal data");
        return undefined;
      }
      state.pendingLiteral = {
        tag:  parsed.tag,
        verb: parsed.verb,
        line: line,
        size: parsed.literalSize,
        body: Buffer.alloc(0),
        synchronizing: !parsed.literalNonSync,
      };
      state.bodyRateWindow.start(time.monotonicMs(), state.wireBytes - state.lineBuffer.length);
      _armLiteralDeadline(state, socket);
      if (!parsed.literalNonSync) {
        _writeContinuation(socket, "Ready for literal data");
      }
      return;
    }
    return _dispatch(state, socket, parsed, line);
  }

  function _quoteAstring(body) {
    for (var i = 0; i < body.length; i += 1) {
      var c = body[i];
      if (c === 0x0D || c === 0x0A || c === 0x00) return null;
    }
    var text = body.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(body)) return null;
    var out = "\"";
    for (var j = 0; j < text.length; j += 1) {
      var ch = text.charAt(j);
      if (ch === "\\" || ch === "\"") out += "\\";
      out += ch;
    }
    return out + "\"";
  }

  function _completeLiteralCommand(state, socket, rest) {
    var pending = state.pendingLiteral;
    state.pendingLiteral = null;
    _clearLiteralDeadline(state);
    var lineNoLit = pending.line.replace(/\{[0-9]+\+?\}$/, "").trim();                                // allow:regex-no-length-cap — line length already capped upstream
    var tail = rest === undefined ? "" : rest;

    if (tail !== "" && tail.charAt(0) !== " " && tail.charAt(0) !== ")") {
      _writeTagged(socket, pending.tag,
        "BAD Expected end of command or a further argument after the literal");
      return undefined;
    }

    if (tail !== "") {
      var quoted = _quoteAstring(pending.body);
      if (quoted === null) {
        _writeTagged(socket, pending.tag,
          "BAD A literal before further arguments must be a quotable string: " +
          "no CR, LF or NUL, and decodable as UTF-8");
        return undefined;
      }
      var syntaxBytes = safeBuffer.byteLengthOf(lineNoLit) + safeBuffer.byteLengthOf(tail) -
        (state.literalSyntaxBytes || 0);
      if (syntaxBytes > maxLineBytes) {
        _writeTagged(socket, pending.tag, "BAD Line too long (cap " + maxLineBytes + ")");
        return undefined;
      }
      state.literalAbsorbed = (state.literalAbsorbed || 0) +
        safeBuffer.byteLengthOf(pending.body);
      if (state.literalAbsorbed > maxLiteralBytes) {
        _writeTagged(socket, pending.tag,
          "BAD Literals in one command exceed " + maxLiteralBytes + " bytes");
        return undefined;
      }
      state.literalSyntaxBytes = (state.literalSyntaxBytes || 0) +
        safeBuffer.byteLengthOf(" " + quoted);
      return _handleLine(state, socket, lineNoLit + " " + quoted + tail);
    }

    state.literalAbsorbed = (state.literalAbsorbed || 0) +
      safeBuffer.byteLengthOf(pending.body);
    if (state.literalAbsorbed > maxLiteralBytes) {
      _writeTagged(socket, pending.tag,
        "BAD Literals in one command exceed " + maxLiteralBytes + " bytes");
      return undefined;
    }

    var parsed;
    try { parsed = guardImapCommand.validate(lineNoLit, { profile: profile, authenticated: state.actor !== null }); }
    catch (e) {
      _writeTagged(socket, pending.tag, "BAD " + (e && e.message ? e.message.slice(0, ERR_CLAMP) : "syntax"));
      return undefined;
    }
    return _dispatch(state, socket, parsed, lineNoLit, pending.body);
  }

  var _registry = null;
  function _ensureRegistry() {
    if (_registry !== null) return _registry;
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
      LOGIN:        { fn: function (s, so, p, lit) { return _handleLogin(s, so, p.tag, p.args, lit); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      ENABLE:       { fn: function (s, so, p)  { return _handleEnable(s, so, p.tag, p.args); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
      SELECT:       { fn: function (s, so, p, lit) { return _handleSelect(s, so, p.tag, lit != null ? String(lit) : p.args, false); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      EXAMINE:      { fn: function (s, so, p, lit) { return _handleSelect(s, so, p.tag, lit != null ? String(lit) : p.args, true); },
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
      UID:          { fn: function (s, so, p, lit) { return _handleUid(s, so, p.tag, p.args, lit); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: LONG_MS },
      IDLE:         { fn: function (s, so, p)  { return _handleIdle(s, so, p.tag); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: LONG_MS },
      NOTIFY:       { fn: function (s, so, p)  { return _handleNotify(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      GETMETADATA:  { fn: function (s, so, p)  { return _handleGetMetadata(s, so, p.tag, p.args); },
                      maxHandlerBytes: MEDIUM_B, maxHandlerMs: MEDIUM_MS },
      SETMETADATA:  { fn: function (s, so, p, lit) { return _handleSetMetadata(s, so, p.tag, p.args, lit); },
                      maxHandlerBytes: LONG_B,   maxHandlerMs: MEDIUM_MS },
      DONE:         { fn: function (s, so, p)  { return _writeTagged(so, p.tag, "BAD DONE outside IDLE"); },
                      maxHandlerBytes: SHORT_B,  maxHandlerMs: SHORT_MS },
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
      return result.then(
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

  function _atomsOf(supplied, state) {
    var atoms = [];
    for (var si = 0; si < supplied.length; si += 1) {
      var atom = String(supplied[si]);
      if (_isCapabilityAtom(atom)) {
        atoms.push(atom);
      } else if (atom.length > 0) {
        _emit("mail.server.imap.capability_refused",
          { connectionId: state.id, capability: atom.slice(0, 64) }, "denied");
      }
    }
    return atoms;
  }

  function _capabilityLine(state) {
    var caps = ["IMAP4rev2"];
    if (!state.tls) caps.push("STARTTLS");
    caps.push("CONDSTORE");
    caps.push("QRESYNC");
    caps.push("NOTIFY");
    caps.push("METADATA");
    caps.push("METADATA-SERVER");
    caps.push("CATENATE");
    if (authConfig && Array.isArray(authConfig.mechanisms)) {
      for (var i = 0; i < authConfig.mechanisms.length; i += 1) {
        var m = String(authConfig.mechanisms[i]).toUpperCase();
        if (caps.indexOf("AUTH=" + m) === -1) caps.push("AUTH=" + m);
      }
    }
    if (capabilitiesHook) {
      var advertised = null;
      try {
        var supplied = capabilitiesHook(caps.slice(), state);
        if (Array.isArray(supplied)) advertised = _atomsOf(supplied, state);
      } catch (e) {
        _emit("mail.server.imap.capabilities_hook_failed",
          { connectionId: state.id, error: (e && e.message) || String(e) }, "failure");
        advertised = null;
      }
      if (advertised) {
        if (advertised.indexOf("IMAP4rev2") === -1) advertised.unshift("IMAP4rev2");
        if (implicitTls || state.tls) {
          advertised = advertised.filter(function (c) { return c.toUpperCase() !== "STARTTLS"; });
        }
        caps = advertised;
      }
    }
    return caps.join(" ");
  }

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
    var setMatch = raw.match(/^SET\s+(?:STATUS\s+)?(\S.*)$/i);                                        // allow:regex-no-length-cap — args length already capped upstream
    if (!setMatch) {
      _writeTagged(socket, tag, "BAD NOTIFY syntax (RFC 5465 §6)");
      return;
    }
    state.notifySpec = setMatch[1];
    if (typeof mailStore.subscribeNotify === "function") {
      return Promise.resolve()
        .then(function () {
          return mailStore.subscribeNotify(state.actor, state.notifySpec, function (event) {
            if (!event || typeof event.kind !== "string") return;
            try {
              if (event.kind === "STATUS") {
                _writeUntagged(socket, "STATUS " + event.payload);
              } else if (event.kind === "LIST") {
                _writeUntagged(socket, "LIST " + event.payload);
              } else if (event.kind === "FETCH") {
                _writeUntagged(socket, _fetchResponse(event.seq || "", event.payload));
              }
            } catch (_e) { /* drop-silent — socket may already be closed */ }
          });
        })
        .then(function () { _writeTagged(socket, tag, "OK NOTIFY completed"); })
        .catch(function (err) {
          _writeTagged(socket, tag, "NO " + ((err && err.message) || "NOTIFY refused").slice(0, ERR_CLAMP));
        });
    }
    _writeTagged(socket, tag, "NO NOTIFY backend not configured");
  }

  function _handleGetMetadata(state, socket, tag, args) {
    if (!_requireAuth(state, socket, tag)) return;
    if (typeof mailStore.getMetadata !== "function") {
      _writeTagged(socket, tag, "NO GETMETADATA backend not configured");
      return;
    }
    var rest = (args || "").trim();
    var opts = {};
    var optsMatch = rest.match(/^\(([^)]+)\)\s+(\S.*)$/);                                              // allow:regex-no-length-cap — args length already capped upstream
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
    return Promise.resolve()
      .then(function () { return mailStore.getMetadata(state.actor, mailbox, entries, opts); })
      .then(function (rows) {
        if (Array.isArray(rows) && rows.length > 0) {
          var pairs = rows.map(function (r) {
            var v = r.value === null || r.value === undefined ? "NIL" : safeBuffer.quoteString(r.value);
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
    return Promise.resolve()
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
    if (implicitTls) {
      _writeTagged(socket, tag, "BAD STARTTLS not available on implicit-TLS port (RFC 8314)");
      return;
    }
    if (state.tls) {
      _writeTagged(socket, tag, "BAD TLS already negotiated");
      return;
    }
    _writeTagged(socket, tag, "OK Begin TLS negotiation now");
    mailServerTls.upgradeLineProtocol({
      state:         state,
      socket:        socket,
      secureContext: opts.tlsContext,
      idleTimeoutMs: idleTimeoutMs,
      clearFields:   ["pendingLiteral", "authPending"],
      drain:         _drainBuffer,
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
    state.authPending = { mech: mechName, tag: tag, step: 0 };
    return _runAuthStep(state, socket, initialResp);
  }

  function _runAuthStep(state, socket, clientResp) {
    var pending = state.authPending;
    function _fail(reason, outcome, reply) {
      var failTag = pending.tag;
      state.authPending = null;
      rateLimit.noteAuthFailure(state.remoteAddress);
      _emit("mail.server.imap.auth_failed",
        { connectionId: state.id, mechanism: pending.mech, reason: reason }, outcome);
      _writeTagged(socket, failTag, reply);
    }
    return mailServerNet.runSaslStep({
      exchange:       pending,
      verify:         authConfig.verify,
      credentials:    { tls: state.tls, remoteAddress: state.remoteAddress },
      clientResponse: clientResp,
      writeChallenge: function (ch) { return _writeContinuation(socket, ch); },
      onChallengeUnsafe: function () {
        _fail("challenge-contains-line-terminator", "denied", "NO Authentication failed");
      },
      onSuccess: function (result) {
        state.actor = result.actor;
        state.stage = "authenticated";
        var savedTag = pending.tag;
        state.authPending = null;
        _emit("mail.server.imap.auth_success",
          { connectionId: state.id, mechanism: pending.mech,
            tenantId: result.actor.tenantId || null });
        _writeTagged(socket, savedTag,
          "OK [CAPABILITY " + _capabilityLine(state) + "] AUTHENTICATE completed");
      },
      onFailure: function (result) {
        _fail((result && result.reason) || "verify-returned-fail", "denied",
              "NO Authentication credentials invalid");
      },
      onError: function (err) {
        _fail((err && err.message) || String(err), "failure", "NO Authentication failed");
      },
    });
  }

  function _handleLogin(state, socket, tag, args, literalBody) {
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
    var parts = _parseLoginArgs(args, literalBody);
    if (!parts) {
      _writeTagged(socket, tag, "BAD LOGIN expects user + pass");
      return;
    }
    return Promise.resolve()
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

  function _parseLoginArgs(args, trailingLiteral) {
    if (typeof args !== "string") return null;
    var rest = args.trim();
    function _take() {
      if (rest[0] === "\"") {
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
        return null;
      }
      var sp = rest.indexOf(" ");
      var v2 = sp === -1 ? rest : rest.slice(0, sp);
      rest = sp === -1 ? "" : rest.slice(sp + 1).trim();
      return v2;
    }
    var user = _take(); if (user === null) return null;
    if (trailingLiteral != null) {
      if (rest.trim() !== "") return null;
      return [user, String(trailingLiteral)];
    }
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
    if (qresyncParam && !state.enabledQResync) {
      state.enabledQResync   = true;
      state.enabledCondStore = true;
    }
    return Promise.resolve()
      .then(function () {
        if (typeof mailStore.selectFolder === "function") {
          return mailStore.selectFolder(state.actor, name, {
            readOnly:    examine,
            qresync:     qresyncParam,
          });
        }
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
    void args;
    return Promise.resolve()
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
          _writeUntagged(socket, "LIST (" + attrs + ") \"/\" " + safeBuffer.quoteString(f.name));
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
    return Promise.resolve()
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
        _writeUntagged(socket, "STATUS " + safeBuffer.quoteString(name) + " (" + parts.join(" ") + ")");
        _writeTagged(socket, tag, "OK STATUS completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Status failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleAppend(state, socket, tag, args, literalBody) {
    if (!_requireAuth(state, socket, tag)) return;
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
      var partsBodyRaw = catenateMatch[4];
      if (partsBodyRaw[0] !== "(" || partsBodyRaw[partsBodyRaw.length - 1] !== ")") {
        _writeTagged(socket, tag, "BAD APPEND CATENATE parts list missing parens (RFC 4469 §3)");
        return;
      }
      var partsBody = partsBodyRaw.slice(1, -1);
      var parts = [];
      var hadTextPart = false;
      var pi = 0;
      while (pi < partsBody.length) {
        while (pi < partsBody.length && /\s/.test(partsBody[pi])) pi += 1;
        if (pi >= partsBody.length) break;
        if (/^URL\b/i.test(partsBody.slice(pi))) {
          pi += 3;
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
        _writeTagged(socket, tag, "NO CATENATE TEXT-literal parts not yet implemented; use APPEND with a single literal");
        return;
      }
      if (parts.length === 0) {
        _writeTagged(socket, tag, "BAD APPEND CATENATE empty parts list");
        return;
      }
      return Promise.resolve()
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
    }
    if (!literalBody) {
      _writeTagged(socket, tag, "BAD APPEND requires a literal {N} message");
      return;
    }
    var match = args.match(/^(\S+|"[^"]+")(?:\s+\(([^)]*)\))?(?:\s+("[^"]+"))?$/);                    // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD APPEND syntax");
      return;
    }
    var name = _unquote(match[1]);
    var flags = match[2] ? match[2].split(/\s+/).filter(Boolean) : [];
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
    return Promise.resolve()
      .then(function () {
        if (typeof mailStore.quota === "function") {
          return Promise.resolve(mailStore.quota(name))
            .then(function (q) {
              if (q && typeof q.usedBytes === "number" &&
                  typeof q.capBytes === "number" &&
                  q.capBytes > 0 &&
                  q.usedBytes + safeBuffer.byteLengthOf(literalBody) > q.capBytes) {
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
    return Promise.resolve()
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
      _writeTagged(socket, tag, "BAD FETCH only valid in Selected state (RFC 9051 §6.4.5)");
      return;
    }
    if (typeof mailStore.fetchRange !== "function") {
      _writeTagged(socket, tag, "BAD FETCH backend not configured");
      return;
    }
    var match = args.match(/^(\S+)\s+(\S.*)$/);                                                        // allow:regex-no-length-cap — args length already capped upstream
    if (!match) {
      _writeTagged(socket, tag, "BAD FETCH expects sequence-set + parts");
      return;
    }
    var seqSet = match[1];
    var partsSpec = match[2];
    var changedSince = null;
    var includeVanished = false;
    var modMatch = _trailingParenGroup(partsSpec);
    if (modMatch && /\b(CHANGEDSINCE|VANISHED)\b/i.test(modMatch.body)) {
      var modBody = modMatch.body;
      var changedMatch = modBody.match(/CHANGEDSINCE\s+(\d+)/i);                                       // allow:regex-no-length-cap — modBody already bounded
      if (changedMatch) {
        var csN = parseInt(changedMatch[1], 10);
        if (isFinite(csN) && csN >= 0) changedSince = csN;
      }
      includeVanished = /\bVANISHED\b/i.test(modBody);
      partsSpec = partsSpec.slice(0, partsSpec.length - modMatch.matchLength).trim();
    }
    if (changedSince !== null && !state.enabledCondStore) {
      state.enabledCondStore = true;
    }
    var includeModseq = state.enabledCondStore === true ||
                        changedSince !== null ||
                        /\bMODSEQ\b/i.test(partsSpec);
    return Promise.resolve()
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
          var octets = Buffer.isBuffer(payload);
          var asText = octets ? payload.toString("latin1") : String(payload);
          if (includeModseq && r.modseq !== undefined && !/MODSEQ\s*\(/.test(asText)) {
            var modseqAttr = (asText ? " " : "") + "MODSEQ (" + r.modseq + ")";
            payload = octets
              ? Buffer.concat([payload, Buffer.from(modseqAttr, "latin1")])
              : asText + modseqAttr;
          }
          _writeUntagged(socket, _fetchResponse(r.seq, payload));
        }
        _writeTagged(socket, tag, "OK FETCH completed");
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Fetch failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleStore(state, socket, tag, args, useUid) {
    if (!state.selectedMailbox) {
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
    if (unchangedSince !== null && !state.enabledCondStore) {
      state.enabledCondStore = true;
    }
    var includeModseqStore = state.enabledCondStore === true || unchangedSince !== null;
    return Promise.resolve()
      .then(function () {
        return mailStore.storeFlags(state.actor, state.selectedMailbox, seqSet, mode, flagsArr,
          { useUid: useUid === true, unchangedSince: unchangedSince, includeModseq: includeModseqStore });
      })
      .then(function (result) {
        var rs, modifiedSet;
        if (Array.isArray(result)) { rs = result; modifiedSet = null; }
        else if (result && typeof result === "object") {
          rs = result.rows || [];
          modifiedSet = result.modified || null;
        } else { rs = []; modifiedSet = null; }
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
              payload = "MODSEQ (" + r.modseq + ")";
            } else {
              continue;
            }
            _writeUntagged(socket, r.seq + " FETCH (" + payload + ")");
          }
        }
        var okTag = "OK STORE completed";
        if (modifiedSet && String(modifiedSet).length > 0) {
          okTag = "OK [MODIFIED " + modifiedSet + "] STORE completed";
        }
        _writeTagged(socket, tag, okTag);
      })
      .catch(function (err) {
        _writeTagged(socket, tag, "NO " + ((err && err.message) || "Store failed").slice(0, ERR_CLAMP));
      });
  }

  function _handleUid(state, socket, tag, args, literalBody) {
    var sub = args.match(/^(\S+)\s+(\S.*)$/);                                                          // allow:regex-no-length-cap — args length already capped upstream
    if (!sub) {
      _writeTagged(socket, tag, "BAD UID expects a sub-command");
      return;
    }
    var subVerb = sub[1].toUpperCase();
    var subArgs = sub[2];
    if (subVerb === "FETCH") return _handleFetch(state, socket, tag, subArgs, true);
    if (subVerb === "STORE") return _handleStore(state, socket, tag, subArgs, true);
    if (subVerb !== "SEARCH" && subVerb !== "COPY" &&
        subVerb !== "MOVE"   && subVerb !== "EXPUNGE") {
      _writeTagged(socket, tag, "BAD UID " + subVerb + " is not a UID sub-command");
      return;
    }
    if (subVerb === "EXPUNGE" && _registry.source("EXPUNGE") !== "operator-override") {
      _writeTagged(socket, tag,
        "NO UID EXPUNGE needs a uid-set-aware EXPUNGE handler; " +
        "the default expunges by \\Deleted flag and would exceed the set");
      return;
    }
    return _registry.dispatch(subVerb, state, socket,
      { tag: tag, args: subArgs, useUid: true }, literalBody);
  }

  function _handleIdle(state, socket, tag) {
    if (!_requireAuth(state, socket, tag)) return;
    _writeContinuation(socket, "idling");
    var timer = setTimeout(function () {
      if (state.idle) {
        _writeUntagged(socket, "BYE IDLE timed out — re-issue");
        state.idle = null;
        _close(socket, state);
      }
    }, IDLE_BANDWIDTH_TIMEOUT_MS);
    state.idle = { tag: tag, timer: timer };
  }

  function _writeLine(socket, prefix, msg) {
    try {
      if (Buffer.isBuffer(msg)) {
        socket.write(Buffer.concat([Buffer.from(prefix, "latin1"), msg, CRLF_BYTES]));
      } else {
        socket.write(prefix + msg + "\r\n");
      }
    } catch (_e) { /* socket may be down */ }
  }
  function _fetchResponse(seq, payload) {
    if (Buffer.isBuffer(payload)) {
      return Buffer.concat([
        Buffer.from(seq + " FETCH (", "latin1"), payload, Buffer.from(")", "latin1"),
      ]);
    }
    return seq + " FETCH (" + (payload || "") + ")";
  }

  function _writeTagged(socket, tag, msg) {
    _writeLine(socket, tag + " ", msg);
  }
  function _writeUntagged(socket, msg) {
    _writeLine(socket, "* ", msg);
  }
  function _writeContinuation(socket, msg) {
    var safe = mailServerNet.saslChallengeOrNull(msg);
    if (safe === null) return false;
    _writeLine(socket, "+ ", safe);
    return true;
  }
  function _close(socket, state) {
    if (state && typeof state === "object") state.closed = true;
    if (state && typeof state === "object") _clearLiteralDeadline(state);
    mailServerNet.destroySocketAfterFlush(socket);
  }
  function _unquote(s) {
    if (typeof s !== "string") return "";
    if (s[0] === "\"" && s[s.length - 1] === "\"") return s.slice(1, -1);
    return s;
  }

  return mailServerNet.createStoreServer(net, {
    defaultPort:      implicitTls ? 993 : 143,
    maxConnections:   opts.maxConnections,
    listeningExtra:   function () { return { implicitTls: implicitTls }; },
    handleConnection: _handleConnection,
    errorClass:       MailServerImapError,
    errorCodePrefix:  "mail-server-imap/",
    emit:             _emit,
    connections:      connections,
    eventBase:        "mail.server.imap",
  });
}

module.exports = {
  create:               create,
  MailServerImapError:  MailServerImapError,
};

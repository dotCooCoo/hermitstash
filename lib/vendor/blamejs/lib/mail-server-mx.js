// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
 *   - **SMTP smuggling** (CVE-2023-51764 Postfix / CVE-2023-51765 Sendmail / CVE-2023-51766 Exim) — every
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
 *   - `mail.server.mx.helo_gate_refused` — HELO identity refused (gate action)
 *   - `mail.server.mx.mail_from`         — sender address
 *   - `mail.server.mx.rcpt_to`           — recipient, rblListed flag, greylist action
 *   - `mail.server.mx.rbl_refused`       — connecting IP on a DNS blocklist (zones)
 *   - `mail.server.mx.greylist_deferred` — (ip, from, rcpt) first-seen 450 deferral
 *   - `mail.server.mx.data_refused`      — refusal reason + SMTP code (5xx vs 4xx)
 *   - `mail.server.mx.envelope_verdict`  — DATA-phase SPF/DKIM/DMARC results + action (accept / quarantine / reject / defer) + gate mode
 *   - `mail.server.mx.envelope_error`    — DATA-phase authentication pipeline failure or timeout (disposition follows onTemperror)
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
 *   new parsing, no new RFC-layer primitives. When the operator
 *   doesn't wire a gate (e.g. omits `opts.greylist`), the listener
 *   skips that phase rather than synthesizing a verdict.
 *
 *   Connection-level gates are wired into the live state machine:
 *   `opts.helo` (HELO identity) evaluates at HELO/EHLO; `opts.rbl`
 *   (connecting-IP DNS blocklist, evaluated once per connection) and
 *   `opts.greylist` ((ip, from, rcpt) first-seen deferral) evaluate at
 *   RCPT TO and surface their verdicts on the `rcpt_to` event. The
 *   message-authentication gate (`opts.guardEnvelope`) runs at DATA
 *   completion through `b.mail.inbound.verify` — SPF (RFC 7208) on the
 *   envelope identity, DKIM (RFC 6376) on the message bytes, DMARC
 *   (RFC 7489) policy + alignment on the From-header domain — and in
 *   enforce mode refuses before the agent handoff: 550 5.7.26
 *   (RFC 7372) when the sender's published policy says reject, 550
 *   5.7.1 on the RFC 7489 §6.6.1 multi-From spoofing shape, 451 4.7.0
 *   on DNS temperror or pipeline timeout (operator-tunable via
 *   `onTemperror` / `timeoutMs`). Accepted messages carry the verdict
 *   to the agent handoff as `auth` and gain the receiver's RFC 8601
 *   Authentication-Results header — any sender-attached header forging
 *   this receiver's authserv-id is stripped first (§5) — so downstream
 *   consumers act on authenticated results instead of re-verifying;
 *   monitor mode annotates without refusing.
 *
 * @card
 *   Inbound SMTP / MX listener. RFC 5321 state machine with SMTP-
 *   smuggling defense baked into the wire-protocol layer (RFC 5321
 *   §2.3.8 + CVE-2023-51764 / 51765 / 51766), open-relay refusal by
 *   default, STARTTLS-stripping defense (CVE-2021-38371), and the
 *   connection-level gate cascade (HELO identity / RBL / greylist)
 *   running at the appropriate phase.
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
var guardCidr = require("./guard-cidr");
var ssrfGuard = require("./ssrf-guard");
var mailServerRateLimit = require("./mail-server-rate-limit");
var mailServerTls = require("./mail-server-tls");
var mailServerNet = require("./mail-server-net");
var { defineClass } = require("./framework-error");

var auditEmit = require("./audit-emit");
// Lazy like the sibling host primitives' guard loads — the inbound
// authentication pipeline (and the DKIM verifier whose range
// constants the boot validation mirrors) only loads when an operator
// wires opts.guardEnvelope.
var mailAuth = lazyRequire(function () { return require("./mail-auth"); });
var dkim = lazyRequire(function () { return require("./mail-dkim"); });

var MailServerMxError = defineClass("MailServerMxError", { alwaysPermanent: true });

// RFC 5321 §4.5.3.1 — wire-protocol limits.
var DEFAULT_MAX_LINE_BYTES        = C.BYTES.kib(1);
var DEFAULT_MAX_MESSAGE_BYTES     = C.BYTES.mib(50);
var DEFAULT_MAX_RCPTS_PER_MESSAGE = 100;                                                              // RFC 5321 §4.5.3.1.8 recipient cap
var DEFAULT_IDLE_TIMEOUT_MS       = C.TIME.minutes(5);
var DEFAULT_GREETING              = "blamejs ESMTP";

// SMTP reply-code constants. The framework uses RFC 5321 enhanced
// status codes per RFC 3463 (`Dclass.Dsubject.Ddetail`) embedded in
// the reply lines for operator-side observability.
var REPLY_220_READY              = "220";
var REPLY_221_BYE                = "221";
var REPLY_250_OK                 = "250";
var REPLY_354_START_INPUT        = "354";
var REPLY_421_SERVICE_NOT_AVAIL  = "421";                                                             // SMTP transient code
var REPLY_450_MAILBOX_BUSY       = "450";                                                             // SMTP transient code (greylist tempfail)
var REPLY_451_LOCAL_ERROR        = "451";                                                             // SMTP transient code
var REPLY_452_INSUFFICIENT_STG   = "452";                                                             // SMTP transient code
var REPLY_500_SYNTAX             = "500";                                                             // SMTP permanent code
var REPLY_501_BAD_ARGS           = "501";                                                             // SMTP permanent code
var REPLY_502_NOT_IMPLEMENTED    = "502";                                                             // SMTP permanent code
var REPLY_503_BAD_SEQUENCE       = "503";                                                             // SMTP permanent code
var REPLY_530_AUTH_REQUIRED      = "530";                                                             // SMTP permanent code
var REPLY_550_MAILBOX_UNAVAIL    = "550";                                                             // SMTP permanent code
var REPLY_552_SIZE_EXCEEDED      = "552";                                                             // SMTP permanent code
var REPLY_554_TRANSACTION_FAILED = "554";                                                             // SMTP permanent code

var RE_MAIL_FROM = /^MAIL\s+FROM:\s*<([^>]*)>(?:\s+(.*))?$/i;
var RE_RCPT_TO   = /^RCPT\s+TO:\s*<([^>]+)>(?:\s+.*)?$/i;
var RE_SIZE      = /SIZE=(\d+)/i;

// A relayAllowedFor entry's `cidr` must be an `<ip>/<prefix>` range so the
// relay-authorization decision can match the connecting peer against it via
// b.ssrfGuard.cidrContains (the same range arithmetic the HTTP
// b.middleware.networkAllowlist fence uses). Shape-validated by composing
// b.guardCidr.validate rather than a hand-rolled parse: a mask is REQUIRED
// (a bare IP never matches in cidrContains, so it is refused at boot rather
// than silently disabling the entry), reserved / private ranges are ALLOWED
// (a relay allowlist legitimately names 10.0.0.0/8 and friends), and a
// non-canonical-but-functional network address (host bits set) is audited,
// not rejected — cidrContains masks it off at match time.
var _RELAY_CIDR_OPTS = Object.freeze({
  requireMaskPolicy:      "reject-bare-ip",
  reservedRangesPolicy:   "allow",
  ipv4MappedIpv6Policy:   "allow",
  networkAlignmentPolicy: "audit",
  family:                 "either",
});

// _normalizeRelayCidr — fold a DOTTED IPv4-mapped IPv6 relay CIDR
// (::ffff:a.b.c.d/N, N in 96..128) to its plain IPv4 CIDR (a.b.c.d/(N-96)).
// guardCidr.validate parses hex-group IPv6 but not the dotted-mapped spelling,
// so an operator naming a mapped range that way would be refused at boot even
// though cidrContains accepts it. Folding to plain IPv4 both validates AND
// makes the entry match every peer form: a genuine IPv4 peer directly, and an
// IPv4-mapped peer via the _isRelayAllowed fold. Storing the mapped CIDR as-is
// would instead match a mapped peer but NOT a genuine IPv4 peer (the inverse
// asymmetry). Every other spelling (plain IPv4, hex-group IPv6) is unchanged.
function _normalizeRelayCidr(cidr) {
  if (typeof cidr !== "string") return cidr;
  var m = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,3})$/i.exec(cidr);
  if (!m) return cidr;
  var prefix = parseInt(m[2], 10);
  if (prefix < 96 || prefix > 128) return cidr;   // outside the ::ffff:0:0/96 block — a genuine IPv6 range
  return m[1] + "/" + (prefix - 96);
}

// Map the b.mail.inbound.verify verdict to the DATA-phase gate action.
// The sender's published DMARC policy drives it (RFC 7489 §6.3 p= /
// §6.6.2 disposition): reject → refuse at the wire; quarantine →
// deliver annotated (an MX cannot spam-folder — the downstream agent
// owns disposition); none / pass → accept. DNS temperror defers or
// accepts per the operator's onTemperror choice. permerror carries a
// reject recommendation only for the multi-From spoofing shape
// (RFC 7489 §6.6.1), set by the pipeline itself.
function _envelopeActionFor(inbound, gate) {
  var dmarc = inbound.dmarc || {};
  if (dmarc.result === "temperror") {
    return gate.onTemperror === "accept" ? "accept" : "defer";
  }
  if (dmarc.recommendedAction === "reject") return "reject";
  if (dmarc.recommendedAction === "quarantine") return "quarantine";
  return "accept";
}

// RFC 8601 §5 — an MTA adding its own Authentication-Results header
// MUST first remove any existing instance claiming its authserv-id: a
// sender can pre-attach a forged header carrying the receiver's name
// ("Authentication-Results: mx.example.com; dmarc=pass") and downstream
// consumers that trust the receiver's A-R header would read the forged
// verdict instead of the computed one. Headers naming OTHER
// authserv-ids are prior-hop information and stay. Operates on the
// header block only — the block is decoded as latin1 (byte-preserving
// round-trip) and the body bytes are never decoded at all, so 8-bit
// content is untouched.
function _stripForgedAuthResults(messageBuf, authservId) {
  if (!authservId) return messageBuf;
  var sepIdx = messageBuf.indexOf("\r\n\r\n");
  var headerEnd = sepIdx === -1 ? messageBuf.length : sepIdx + 2;
  var head = messageBuf.slice(0, headerEnd).toString("latin1");
  var rest = messageBuf.slice(headerEnd);
  if (head.toLowerCase().indexOf("authentication-results:") === -1) return messageBuf;
  var lines = head.split("\r\n");
  var out = [];
  var skipping = false;
  var prefix = "authentication-results:";
  var wantId = authservId.toLowerCase();
  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (skipping && (line.charAt(0) === " " || line.charAt(0) === "\t")) continue;  // folded continuation
    skipping = false;
    if (line.slice(0, prefix.length).toLowerCase() === prefix) {
      var idTok = line.slice(prefix.length).trim().split(/[;\s]/)[0].toLowerCase();
      if (idTok === wantId) { skipping = true; continue; }
    }
    out.push(line);
  }
  return Buffer.concat([Buffer.from(out.join("\r\n"), "latin1"), rest]);
}

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
 *   helo:              b.mail.helo,            // optional gate — HELO identity (FCrDNS / shape / self-name)
 *   rbl:               b.mail.rbl.create(…),   // optional gate — DNS blocklist on the connecting IP
 *   greylist:          b.mail.greylist.create(…), // optional gate — defer first-seen (ip, from, rcpt)
 *   agent:             b.mail.agent,    // optional delivery handoff
 *   relayAllowedFor:   [{ cidr, scope }],  // operator-explicit relay allowlist; default [] = MX-only
 *   localDomains:      [string],        // RCPT TO local-domain allowlist (refuse non-local with 550 5.7.1)
 *   maxLineBytes:      number,          // default 1 KiB — per-command line cap
 *   maxMessageBytes:   number,          // default 50 MiB — DATA body cap
 *   maxRcptsPerMessage: number,         // default 100 — per RFC 5321 §4.5.3.1.8
 *   idleTimeoutMs:     number,          // default 5 minutes — RFC 5321 §4.5.3.2.7
 *   profile:           "strict" | "balanced" | "permissive",  // gate posture cascade
 *   guardEnvelope:     true | {        // optional gate — DATA-phase SPF/DKIM/DMARC via b.mail.inbound.verify
 *     mode?:          "enforce" | "monitor",   // default: enforce (monitor when profile is permissive)
 *     onTemperror?:   "defer" | "accept",      // DNS temperror disposition; default "defer" (451 4.7.5)
 *     authservId?:    string,                  // RFC 8601 authserv-id; default localDomains[0]
 *     dnsLookup?:     function,                // async (qname, type) override for SPF/DKIM/DMARC lookups
 *     maxSignatures?: number,                  // DKIM verify cap (1-16)
 *     clockSkewMs?:   number,                  // DKIM timestamp skew tolerance
 *     minRsaBits?:    number,                  // DKIM minimum RSA key size
 *     timeoutMs?:     number,                  // pipeline wall-clock ceiling; default 20s (timeout → temperror disposition)
 *   },
 *
 * @example
 *   var tls = b.network.tls.context({ cert: certPem, key: keyPem });
 *   var server = b.mail.server.mx.create({
 *     tlsContext:   tls,
 *     greeting:     "mx.example.com ESMTP blamejs",
 *     helo:         b.mail.helo,
 *     rbl:          b.mail.rbl.create({ providers: ["zen.spamhaus.org"] }),
 *     greylist:     b.mail.greylist.create({ store: greylistStore }),
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
  // Every relay-allowlist entry MUST carry a valid `<ip>/<prefix>` CIDR:
  // relay is granted only to a peer whose address falls inside an allowlisted
  // range. Refuse a malformed / mask-less entry at boot so an operator typo
  // can't silently leave the relay decision mis-scoped (open relay is the
  // failure this closes — pre-fix any non-empty relayAllowedFor admitted
  // every peer regardless of source address).
  if (Array.isArray(opts.relayAllowedFor)) {
    for (var __ri = 0; __ri < opts.relayAllowedFor.length; __ri += 1) {
      var __re = opts.relayAllowedFor[__ri];
      var __reOk = __re && typeof __re === "object" && !Array.isArray(__re) &&
        guardCidr.validate(_normalizeRelayCidr(__re.cidr), _RELAY_CIDR_OPTS).ok;
      if (!__reOk) {
        throw new MailServerMxError("mail-server-mx/bad-relay-cidr",
          "mail.server.mx.create: relayAllowedFor[" + __ri + "] must be an object with a " +
          "valid CIDR string (e.g. { cidr: \"10.0.0.0/8\", scope: \"internal\" }); relay is " +
          "granted only to peers whose source address falls inside an allowlisted range");
      }
    }
  }

  var greeting          = opts.greeting          || DEFAULT_GREETING;
  var maxLineBytes      = opts.maxLineBytes      || DEFAULT_MAX_LINE_BYTES;
  var maxMessageBytes   = opts.maxMessageBytes   || DEFAULT_MAX_MESSAGE_BYTES;
  var maxRcptsPerMsg    = opts.maxRcptsPerMessage || DEFAULT_MAX_RCPTS_PER_MESSAGE;
  var idleTimeoutMs     = opts.idleTimeoutMs     || DEFAULT_IDLE_TIMEOUT_MS;
  var localDomains      = (opts.localDomains || []).map(function (d) { return String(d).toLowerCase(); });
  var relayAllowedFor   = (opts.relayAllowedFor || []).map(function (__e) {
    return (__e && typeof __e === "object" && !Array.isArray(__e))
      ? Object.assign({}, __e, { cidr: _normalizeRelayCidr(__e.cidr) })
      : __e;
  });
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
  var rateLimit = mailServerRateLimit.resolve(opts.rateLimit);

  // DATA-phase message-authentication gate. `guardEnvelope: true`
  // gates with defaults; an object tunes it. Like the sibling gates
  // (helo / rbl / greylist) the phase is skipped when the operator
  // doesn't wire it — the gate needs live DNS to evaluate the
  // sender's published policy, which closed-network deployments may
  // not have.
  var envelopeGate = null;
  if (opts.guardEnvelope !== undefined && opts.guardEnvelope !== false) {
    if (opts.guardEnvelope !== true &&
        (typeof opts.guardEnvelope !== "object" || opts.guardEnvelope === null ||
         Array.isArray(opts.guardEnvelope))) {
      throw new MailServerMxError("mail-server-mx/bad-opts",
        "mail.server.mx.create: guardEnvelope must be true, false, or a config object");
    }
    var ge = opts.guardEnvelope === true ? {} : opts.guardEnvelope;
    validateOpts(ge, ["mode", "onTemperror", "authservId", "dnsLookup",
                      "maxSignatures", "clockSkewMs", "minRsaBits", "timeoutMs"],
                 "mail.server.mx.guardEnvelope");
    var geMode = (ge.mode === undefined || ge.mode === null)
      ? (profile === "permissive" ? "monitor" : "enforce")
      : ge.mode;
    if (geMode !== "enforce" && geMode !== "monitor") {
      throw new MailServerMxError("mail-server-mx/bad-opts",
        "mail.server.mx.create: guardEnvelope.mode must be 'enforce' or 'monitor'");
    }
    var geOnTemperror = (ge.onTemperror === undefined || ge.onTemperror === null)
      ? "defer" : ge.onTemperror;
    if (geOnTemperror !== "defer" && geOnTemperror !== "accept") {
      throw new MailServerMxError("mail-server-mx/bad-opts",
        "mail.server.mx.create: guardEnvelope.onTemperror must be 'defer' or 'accept'");
    }
    if (ge.authservId !== undefined && ge.authservId !== null) {
      validateOpts.requireNonEmptyString(ge.authservId,
        "mail.server.mx.create: guardEnvelope.authservId",
        MailServerMxError, "mail-server-mx/bad-opts");
    }
    if (ge.dnsLookup !== undefined && ge.dnsLookup !== null &&
        typeof ge.dnsLookup !== "function") {
      throw new MailServerMxError("mail-server-mx/bad-opts",
        "mail.server.mx.create: guardEnvelope.dnsLookup must be a function");
    }
    // DKIM bounds caught at boot, not at the first DATA — mirroring
    // the exact ranges b.mail.dkim.verify enforces per call, so an
    // operator typo fails startup instead of turning every live
    // message into an envelope_error + temperror disposition.
    numericBounds.requireAllPositiveFiniteIntIfPresent(ge,
      ["maxSignatures", "clockSkewMs", "minRsaBits", "timeoutMs"],
      "mail.server.mx.guardEnvelope.", MailServerMxError, "mail-server-mx/bad-bound");
    if (ge.maxSignatures !== undefined && ge.maxSignatures !== null &&
        ge.maxSignatures > dkim().DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING) {
      throw new MailServerMxError("mail-server-mx/bad-bound",
        "mail.server.mx.create: guardEnvelope.maxSignatures " + ge.maxSignatures +
        " exceeds the DKIM verifier ceiling " +
        dkim().DKIM_MAX_SIGNATURES_PER_MESSAGE_CEILING +
        " (RFC 6376 §6.1 fan-out DoS bound)");
    }
    if (ge.clockSkewMs !== undefined && ge.clockSkewMs !== null &&
        ge.clockSkewMs > dkim().DKIM_CLOCK_SKEW_MS_MAX) {
      throw new MailServerMxError("mail-server-mx/bad-bound",
        "mail.server.mx.create: guardEnvelope.clockSkewMs " + ge.clockSkewMs +
        " exceeds the DKIM verifier ceiling " + dkim().DKIM_CLOCK_SKEW_MS_MAX +
        " (RFC 6376 §3.5 back-dating replay defense)");
    }
    envelopeGate = Object.freeze({
      mode:          geMode,
      onTemperror:   geOnTemperror,
      // RFC 8601 authserv-id — the receiver's own name on the
      // Authentication-Results header. Defaults to the first local
      // domain; with neither, the header is skipped (the verdict
      // still reaches the agent handoff).
      authservId:    ge.authservId || localDomains[0] || null,
      dnsLookup:     ge.dnsLookup || undefined,
      maxSignatures: ge.maxSignatures,
      clockSkewMs:   ge.clockSkewMs,
      minRsaBits:    ge.minRsaBits,
      // Wall-clock ceiling for the whole pipeline (SPF include chains
      // + per-signature DKIM key fetches + DMARC policy walk). A
      // message stuffed with signatures pointing at slow resolvers
      // must not pin the connection slot — on timeout the message
      // takes the temperror disposition (defer / accept per
      // onTemperror).
      timeoutMs:     (ge.timeoutMs === undefined || ge.timeoutMs === null)
        ? C.TIME.seconds(20) : ge.timeoutMs,
    });
  }

  // Default-on operator-supplied-domain hardening. opts.localDomains
  // and the HELO / MAIL FROM / RCPT TO domain validations all route
  // through `b.guardDomain` for IDN homograph / Punycode-spoof defense
  // (mixed-script confusable class), special-use-domain refusal (RFC 6761), label-length cap
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
    return mailServerNet.validateDomainHardened(d, label, {
      guardDomainProfile: guardDomainProfile,
      guardDomain:        guardDomain,
      emit:               _emit,
      refusedEvent:       "mail.server.mx.domain_refused",
    });
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

  var connections  = new Set();

  var _emit = auditEmit.emit;

  // ---- Per-connection state machine ---------------------------------------
  function _handleConnection(socket) {
    // 421 4.7.0 — transient refusal; sender retries elsewhere or later.
    // RFC 5321 §3.8 + §4.5.4.2 (transient negative completion).
    var remoteAddress = mailServerNet.admitConnection(socket, rateLimit, _emit, {
      refusedEvent: "mail.server.mx.rate_limit_refused",
      refusalLine:  "421 4.7.0 Too many connections from your IP\r\n",
    });
    if (remoteAddress === null) return;
    socket.once("close", function () { rateLimit.releaseConnection(remoteAddress); });

    var connectionId = "mxconn-" + bCrypto.generateToken(8);                                          // connection-id length
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
    // Async command pump: gates (HELO / RBL / greylist / envelope /
    // DMARC) may await DNS or a store, so command handling is async.
    // `pumpChain` FIFO-serializes per-chunk processing so a gate
    // resolving cannot let a later pipelined command (RFC 2920) jump
    // ahead of an earlier one — reply ordering + the per-command
    // smuggling defenses stay intact. `connClosed` short-circuits any
    // chunk queued before a teardown.
    var pumpChain = Promise.resolve();
    var connClosed = false;

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
      connClosed = true;
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

    // Feed a chunk into the per-connection command pump. Chains each
    // chunk behind the previous one's full (async) processing so command
    // handlers + their gates run strictly in arrival order. Used by BOTH
    // the plaintext `socket.on("data")` path AND the post-STARTTLS
    // TLSSocket onData path — otherwise gate awaits on the upgraded
    // socket would overlap later TLS chunks (the default strict/balanced
    // profiles require STARTTLS before MAIL, so the gates run there) and
    // async gate rejections would go unhandled instead of producing the
    // 421 path. `activeSock` is whichever socket is current (plaintext or
    // TLS) so the 421/close lands on the right transport.
    function _feedChunk(activeSock, chunk) {
      pumpChain = pumpChain.then(function () {
        if (connClosed) return undefined;
        return _ingestBytes(state, activeSock, chunk);
      }).catch(function (err) {
        if (connClosed) return;
        _emit("mail.server.mx.handler_threw",
          { connectionId: state.id, error: (err && err.message) || String(err) },
          "failure");
        try { _writeReply(activeSock, REPLY_421_SERVICE_NOT_AVAIL, "4.3.0 Server error"); }
        catch (_e) { /* socket already gone */ }
        _closeConnection(activeSock);
      });
    }

    socket.on("data", function (chunk) { _feedChunk(socket, chunk); });

    // ---- Byte-level ingestion --------------------------------------------
    async function _ingestBytes(state, socket, chunk) {
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
          inDataBody = false;
          bodyCollector = null;
          await _finalizeDataBody(state, socket, body);
        }
        return;
      }

      // Command phase — byte-buffered (8BITMIME-safe).
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
        var line = lineBuffer.subarray(0, crlf).toString("utf8");
        lineBuffer = lineBuffer.subarray(crlf + 2);
        await _handleCommand(state, socket, line);
        if (inDataBody) return;
        if (connClosed) return;
      }
    }

    async function _handleCommand(state, socket, line) {
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
            err.code === "guard-smtp-command/nul") {
          _emit("mail.server.mx.smtp_smuggling_detected",
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
          await _handleEhlo(state, socket, line, verb);
          return;
        case "STARTTLS":
          _handleStartTls(state, socket);
          return;
        case "MAIL":
          await _handleMailFrom(state, socket, line);
          return;
        case "RCPT":
          await _handleRcptTo(state, socket, line);
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
    async function _handleEhlo(state, socket, line, verb) {
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
      // Operator HELO-identity gate (b.mail.helo) — FCrDNS / HELO-shape /
      // self-name spoofing checks. Composed when the operator wires
      // `opts.helo`; skipped silently otherwise (no synthesized verdict).
      // Hard-reject actions (reject-shape / match-self-refused /
      // literal-mismatch) refuse the connection; "accept" and the
      // advisory "soft-*" actions pass (the soft verdict rides the event).
      if (opts.helo && typeof opts.helo.evaluate === "function") {
        var heloGate = await opts.helo.evaluate(
          { claimedName: helo, ip: state.remoteAddress, tls: state.tls }, {});
        state.heloVerdict = heloGate && heloGate.action;
        if (heloGate && heloGate.action && heloGate.action !== "accept" &&
            heloGate.action.indexOf("soft") !== 0) {
          _emit("mail.server.mx.helo_gate_refused",
            { connectionId: state.id, helo: helo, action: heloGate.action }, "denied");
          _writeReply(socket, REPLY_550_MAILBOX_UNAVAIL,
            "5.7.1 " + verb + " identity refused (" + heloGate.action + ")");
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
        { connectionId: state.id, verb: verb, helo: helo, tls: state.tls,
          heloVerdict: state.heloVerdict || null });
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
          // Route the upgraded socket through the SAME serialized pump as
          // the plaintext path — post-STARTTLS is where the gates run in
          // the default strict/balanced profiles, so it MUST be serialized
          // and its async rejections MUST hit the 421 path.
          _feedChunk(tlsSocket, chunk);
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
    async function _handleMailFrom(state, socket, line) {
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
    async function _handleRcptTo(state, socket, line) {
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
      // RBL gate (b.mail.rbl) — DNS blocklist check on the connecting
      // IP. The verdict is per-connection, so it's evaluated once and
      // cached on state; a listed IP refuses with 554. Skipped silently
      // when opts.rbl isn't wired.
      if (opts.rbl && typeof opts.rbl.query === "function") {
        if (state.rblVerdict === undefined) {
          state.rblVerdict = await opts.rbl.query(state.remoteAddress);
        }
        if (state.rblVerdict && Array.isArray(state.rblVerdict.listed) &&
            state.rblVerdict.listed.length > 0) {
          _trackRefusedRcpt(state, rcpt, "rbl-listed");
          _emit("mail.server.mx.rbl_refused",
            { connectionId: state.id, remoteAddress: state.remoteAddress,
              zones: state.rblVerdict.listed.map(function (l) { return l.zone; }) }, "denied");
          _writeReply(socket, REPLY_554_TRANSACTION_FAILED,
            "5.7.1 Connecting IP is on a DNS blocklist");
          return;
        }
      }
      // Greylist gate (b.mail.greylist) — defer first sight of an
      // (ip, mailFrom, rcpt) tuple with a 450 tempfail; legitimate
      // senders retry and pass. "defer" → 450; "accept" → continue.
      // Skipped silently when opts.greylist isn't wired.
      var greyVerdict = null;
      if (opts.greylist && typeof opts.greylist.check === "function") {
        greyVerdict = await opts.greylist.check(
          { ip: state.remoteAddress, mailFrom: state.mailFrom || "", rcptTo: rcpt });
        if (greyVerdict && greyVerdict.action === "defer") {
          _emit("mail.server.mx.greylist_deferred",
            { connectionId: state.id, remoteAddress: state.remoteAddress,
              mailFrom: state.mailFrom, rcptTo: rcpt,
              reason: greyVerdict.reason }, "denied");
          _writeReply(socket, REPLY_450_MAILBOX_BUSY,
            "4.7.1 Greylisted — please retry shortly");
          return;
        }
      }
      state.rcpts.push(rcpt);
      _emit("mail.server.mx.rcpt_to",
        { connectionId: state.id, rcptTo: rcpt, rcptCount: state.rcpts.length,
          rblListed: !!(state.rblVerdict && Array.isArray(state.rblVerdict.listed) &&
            state.rblVerdict.listed.length > 0),
          greylist: greyVerdict ? greyVerdict.action : null });
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

    async function _finalizeDataBody(state, socket, body) {
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
      // DATA-phase message authentication (opts.guardEnvelope) — SPF /
      // DKIM / DMARC through b.mail.inbound.verify, refusing before the
      // agent handoff so a policy-failing message never reaches storage.
      var inboundAuth = null;
      if (envelopeGate) {
        var inboundVerdict = null;
        try {
          // Wall-clock ceiling around the whole pipeline — a message
          // stuffed with signatures pointing at slow resolvers must
          // not pin the connection slot. Timeout surfaces as
          // SafeAsyncError(async/timeout) into the catch below.
          inboundVerdict = await safeAsync.withTimeout(
            mailAuth().inbound.verify({
              ip:            state.remoteAddress,
              helo:          state.helo || undefined,
              mailFrom:      state.mailFrom || undefined,
              message:       dedotted,
              dnsLookup:     envelopeGate.dnsLookup,
              maxSignatures: envelopeGate.maxSignatures,
              clockSkewMs:   envelopeGate.clockSkewMs,
              minRsaBits:    envelopeGate.minRsaBits,
              authservId:    envelopeGate.authservId || undefined,
            }),
            envelopeGate.timeoutMs,
            { name: "mail.server.mx.guardEnvelope" });
        } catch (err) {
          // Pipeline infrastructure failure or wall-clock timeout (not
          // an authentication verdict). Same disposition as a DNS
          // temperror: defer so the sender retries, or accept
          // unauthenticated when the operator chose availability via
          // onTemperror.
          _emit("mail.server.mx.envelope_error", {
            connectionId: state.id,
            mailFrom:     state.mailFrom,
            error:        (err && err.message) || String(err),
          }, "failure");
          if (envelopeGate.mode === "enforce" && envelopeGate.onTemperror === "defer") {
            _writeReply(socket, REPLY_451_LOCAL_ERROR,
              "4.7.0 Message authentication could not be completed; try again later");
            _resetTransaction(state);
            return;
          }
        }
        if (inboundVerdict) {
          var envAction = _envelopeActionFor(inboundVerdict, envelopeGate);
          var dkimSummary = inboundVerdict.dkim.some(function (d) { return d.result === "pass"; })
            ? "pass"
            : (inboundVerdict.dkim[0] ? inboundVerdict.dkim[0].result : "none");
          _emit("mail.server.mx.envelope_verdict", {
            connectionId: state.id,
            mailFrom:     state.mailFrom,
            fromDomain:   inboundVerdict.from.domain,
            spf:          inboundVerdict.spf.result,
            dkim:         dkimSummary,
            dmarc:        inboundVerdict.dmarc.result,
            action:       envAction,
            mode:         envelopeGate.mode,
          }, (envAction === "reject" || envAction === "defer") ? "denied" : "success");
          if (envelopeGate.mode === "enforce" && envAction === "reject") {
            // RFC 7372 §3.2 — 5.7.26 ("multiple authentication checks
            // failed") for a DMARC evaluation that failed; the
            // multi-From / unparsable-author permerror shape is a
            // message-acceptability refusal and keeps the generic
            // 5.7.1.
            var enhanced = inboundVerdict.dmarc.result === "fail" ? "5.7.26" : "5.7.1";
            _writeReply(socket, REPLY_550_MAILBOX_UNAVAIL,
              enhanced + " Message refused by sender authentication policy (DMARC " +
              inboundVerdict.dmarc.result + "; SPF " + inboundVerdict.spf.result +
              ", DKIM " + dkimSummary + ")");
            _resetTransaction(state);
            return;
          }
          if (envelopeGate.mode === "enforce" && envAction === "defer") {
            _writeReply(socket, REPLY_451_LOCAL_ERROR,
              "4.7.0 Sender authentication temporarily unavailable (DNS); try again later");
            _resetTransaction(state);
            return;
          }
          // Accept / quarantine / monitor mode: the verdict rides to
          // the agent handoff as `auth`, and the receiver's RFC 8601
          // Authentication-Results header is prepended so downstream
          // consumers (spam-foldering quarantined mail included) act
          // on authenticated results instead of re-verifying.
          if (inboundVerdict.authResults) {
            // RFC 8601 §5 — strip any sender-attached A-R header
            // claiming this receiver's authserv-id before prepending
            // the computed one (forged-verdict shadowing defense).
            dedotted = _stripForgedAuthResults(dedotted, envelopeGate.authservId);
            dedotted = Buffer.concat([
              Buffer.from(inboundVerdict.authResults + "\r\n", "utf8"),
              dedotted,
            ]);
          }
          inboundAuth = {
            spf:        inboundVerdict.spf,
            dkim:       inboundVerdict.dkim,
            dmarc:      inboundVerdict.dmarc,
            from:       inboundVerdict.from,
            action:     envAction,
            mode:       envelopeGate.mode,
            quarantine: envAction === "quarantine",
          };
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
          auth:     inboundAuth,
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
    var MAX_REFUSED_RCPTS_PER_TXN = 32;                                                                   // bounded audit-metadata list cap
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

    function _isRelayAllowed(remoteAddress, _rcptTo) {
      // Relay is admitted ONLY when the connecting peer's source address
      // falls inside one of the operator's allowlisted CIDR ranges — the
      // same range arithmetic (b.ssrfGuard.cidrContains) the HTTP
      // b.middleware.networkAllowlist fence uses. Every entry's `cidr` was
      // shape-validated at create() time; a peer outside every range (or a
      // non-string / empty peer address) is refused, so a misconfigured
      // relayAllowedFor fails closed instead of turning the listener into an
      // open relay. `scope` is an operator-facing annotation on the entry;
      // the network boundary is the authorization control.
      if (relayAllowedFor.length === 0) return false;
      if (typeof remoteAddress !== "string" || remoteAddress.length === 0) return false;
      // Node reports an IPv4 client as an IPv4-mapped IPv6 address
      // (::ffff:a.b.c.d) when the listener binds the IPv6 wildcard `::` (the
      // common dual-stack deployment). cidrContains refuses a mixed-family
      // compare, so a documented IPv4 relay CIDR (10.0.0.0/8) would deny every
      // intended IPv4 client on that listener. Fold the mapped form to its
      // IPv4 dotted address (ssrfGuard.canonicalizeHost, which folds only the
      // ::ffff:0:0/96 block) and match EITHER the peer as reported OR the
      // folded form — so an IPv4 CIDR matches a mapped peer and an IPv6 CIDR
      // still matches a genuine IPv6 peer.
      var canonPeer;
      try { canonPeer = ssrfGuard.canonicalizeHost(remoteAddress); }
      catch (_e) { canonPeer = remoteAddress; }
      for (var i = 0; i < relayAllowedFor.length; i += 1) {
        var entry = relayAllowedFor[i];
        if (!entry || typeof entry !== "object") continue;
        if (ssrfGuard.cidrContains(entry.cidr, remoteAddress)) return true;
        if (canonPeer !== remoteAddress && ssrfGuard.cidrContains(entry.cidr, canonPeer)) return true;
      }
      return false;
    }
  }

  // ---- Lifecycle ----------------------------------------------------------
  // Port 0 (ephemeral, test mode) must NOT fall back to 25 — the `|| 25`
  // short-circuit was a footgun on the test path; createTcpListener honors an
  // explicit 0 (only an OMITTED port falls back to the default).
  var _tcpListener = mailServerNet.createTcpListener(net, {
    defaultPort:      25,                                                                             // SMTP MX port (IANA)
    handleConnection: _handleConnection,
    errorFactory:     function (code, message) { return new MailServerMxError("mail-server-mx/" + code, message); },
    emit:             _emit,
    listeningEvent:   "mail.server.mx.listening",
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
    _emit("mail.server.mx.closed", {});
  }

  function connectionCount() { return connections.size; }

  return {
    listen:           _tcpListener.listen,
    close:            close,
    connectionCount:  connectionCount,
    _portForTest:     function () { var s = _tcpListener.getServer(); return s ? s.address().port : null; },
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

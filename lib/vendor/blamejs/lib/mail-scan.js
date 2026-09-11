// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.scan
 * @nav        Mail
 * @title      Mail Scan
 * @order      555
 *
 * @intro
 *   Anti-virus / content-scan facade for inbound + outbound mail.
 *   Operators wire `b.mail.scan.create({...})` once at boot, then call
 *   `.scan(messageBytes, opts)` from the MX listener (v0.9.45),
 *   submission listener (v0.9.47), or any custom pipeline that needs a
 *   verdict before delivering / forwarding a message.
 *
 *   ## Backends
 *
 *   Two transport shapes are supported out of the box:
 *
 *     - **ICAP** (`protocol: "icap"` — default) — RFC 3507 Internet
 *       Content Adaptation Protocol. The framework speaks to a c-icap
 *       (or commercial) daemon over TCP, sends a REQMOD or RESPMOD
 *       request with the message body encapsulated, and parses the
 *       response through `b.safeIcap.parse`. The de-facto standard for
 *       Sophos / Symantec / Trend Micro / McAfee ICAP integrations.
 *
 *     - **ClamAV INSTREAM** (`protocol: "clamav-instream"`) — the
 *       native ClamAV daemon protocol (no ICAP layer). Operator points
 *       at a clamd instance; the framework sends `zINSTREAM\0`, framed
 *       4-byte-length-prefix chunks, then a zero-length terminator, and
 *       parses the line-shaped `<id>: stream: OK` / `<id>: stream:
 *       <virus> FOUND` response.
 *       See https://docs.clamav.net/manual/Usage/Configuration.html#instream
 *
 *   ## Composition
 *
 *     - **`b.safeIcap`** owns the ICAP wire-protocol bounded parser
 *       (CRLF discipline, status-allowlist, body cap). Every ICAP byte
 *       routes through it before any field is trusted.
 *     - **`b.guardArchive`** is composed when `opts.archiveEntries` is
 *       supplied — the scanner refuses an archive with hostile entry
 *       metadata BEFORE shipping bytes to the AV daemon, so a zip-bomb
 *       can't reach the scanner's parser. Recursion-depth cap is the
 *       guard's profile-default.
 *     - **`b.audit`** receives every request / verdict / error /
 *       timeout via `audit.safeEmit` (the audit failure is drop-silent
 *       per the hot-path rule).
 *
 *   ## Threat model
 *
 *   - **ICAP-response-injection (raw bytes → header injection)**:
 *     defended by `b.safeIcap` — bare-CR / bare-LF / NUL refused;
 *     status-code allowlist; bounded header / body / count caps.
 *   - **Parser-bomb on Encapsulated res-body** (hostile daemon ships
 *     arbitrary body length): defended by profile-tunable
 *     `maxBodyBytes` cap on the safeIcap parse path.
 *   - **DoS via slow daemon**: per-request wall-clock timeout (default
 *     30s strict / 60s balanced / 120s permissive). After the timeout
 *     the scan resolves with `{ verdict: "error" }` and the listener
 *     fails the message-handling step (operator's choice: tempfail /
 *     reject / accept-with-tag).
 *   - **Archive-bomb / zip-slip pre-AV**: defended by optional
 *     `b.guardArchive.validateEntries` composition when the operator
 *     enumerates entries before the AV scan.
 *
 *   ## Why not "vendor an AV signature engine"?
 *
 *   AV signature databases are operator state, not framework state.
 *   ClamAV's signature set changes hourly; commercial scanners refresh
 *   their state through their own update channel. The framework's job
 *   is the wire-protocol parser + the operator-facing facade — the AV
 *   intelligence belongs to whatever daemon the operator deploys.
 *
 * @card
 *   ICAP (RFC 3507) + ClamAV-INSTREAM AV-scan facade. Composes
 *   b.safeIcap for wire-bytes hardening, b.guardArchive for pre-scan
 *   archive-metadata refusal, b.audit for verdict emission. Two
 *   built-in backends; operator points at their existing daemon.
 */

var net           = require("node:net");
var safeBuffer    = require("./safe-buffer");
var C                 = require("./constants");
var { defineClass }   = require("./framework-error");
var lazyRequire       = require("./lazy-require");
var validateOpts      = require("./validate-opts");
var numericBounds     = require("./numeric-bounds");
var safeIcap          = require("./safe-icap");
var gateContract = require("./gate-contract");
var codepointClass = require("./codepoint-class");

var audit             = lazyRequire(function () { return require("./audit"); });
var guardArchive      = lazyRequire(function () { return require("./guard-archive"); });

var MailScanError = defineClass("MailScanError", { alwaysPermanent: true });

var DEFAULT_PROFILE      = "strict";
var DEFAULT_PROTOCOL     = "icap";
var DEFAULT_ICAP_SERVICE = "srv_clamav";

var CLAMAV_LENGTH_PREFIX_BYTES = 4;

var CLAMAV_CHUNK_BYTES = 65536;

var REPLY_EXCERPT_CHARS = 200;

var REPLY_ELLIPSIS = "...";

function _replyExcerpt(reply) {
  var s = reply === undefined || reply === null ? "" : String(reply);
  if (s.length <= REPLY_EXCERPT_CHARS) return s;
  return s.slice(0, REPLY_EXCERPT_CHARS - REPLY_ELLIPSIS.length) +
    REPLY_ELLIPSIS;
}

function _clamErrorVerdict(reply) {
  // allow:regex-no-length-cap — anchored to the fixed size-limit token
  var oversize = /size limit exceeded/i.test(reply);
  return {
    verdict:      "error",
    threats:      [],
    errorCode:    oversize ? "mail-scan/clamav-size-limit" : "mail-scan/clamav-error",
    errorMessage: _replyExcerpt(reply),
  };
}

function _classifyClamReply(reply) {
  var threat = _clamThreatName(reply);
  if (threat !== null) return { verdict: "infected", threats: [threat] };
  if (/ERROR/i.test(reply)) return _clamErrorVerdict(reply);                                       // allow:regex-no-length-cap — anchored to fixed ERROR token
  if (/stream:\s+OK\b/.test(reply)) return { verdict: "clean", threats: [] };                      // allow:regex-no-length-cap — anchored to fixed token
  return null;
}

function _icapVerdictFrom(parsed) {
  var threats = [];
  if (parsed.threatName) threats.push(parsed.threatName);
  var verdict = parsed.threatFound ? "infected"
    : (parsed.statusCode === 200 || parsed.statusCode === 204 ? "clean" : "error");
  var out = { verdict: verdict, icapResponse: parsed, threats: threats };
  if (verdict === "error") {
    out.errorCode = "mail-scan/icap-status";
    out.errorMessage = _replyExcerpt(
      String(parsed.statusCode) + " " + String(parsed.statusText || ""));
  }
  return out;
}

function _clamVerdictFor(reply) {
  var classified = _classifyClamReply(reply);
  return classified !== null ? classified : {
    verdict:      "error",
    threats:      [],
    errorCode:    "mail-scan/clamav-unparsed-reply",
    errorMessage: _replyExcerpt(reply),
  };
}

function _bufferedClamVerdict(collector) {
  var raw;
  try { raw = collector.result(); }
  catch (_e) { return null; }
  if (!raw || raw.length === 0) return null;
  var last = raw[raw.length - 1];
  if (last !== 0x00 && last !== 0x0A && last !== 0x0D) return null;
  var reply = _stripTrailingEol(raw.toString("utf8"));
  if (reply.length === 0) return null;
  return _clamVerdictFor(reply);
}

function _stripTrailingEol(s) {
  var end = s.length;
  while (end > 0) {
    var c = s.charCodeAt(end - 1);
    if (c !== 0x0D && c !== 0x0A && c !== 0x00) break;
    end -= 1;
  }
  return end === s.length ? s : s.slice(0, end);
}

function _isReplySpace(cc) {
  if (cc === 0x20 || (cc >= 0x09 && cc <= 0x0D)) return true;
  if (cc < 0x00A0) return false;
  return codepointClass.inRanges(cc, codepointClass.WHITESPACE_RANGES);
}

function _isReplyLineBreak(cc) {
  if (cc === 0x0A || cc === 0x0D) return true;
  if (cc < 0x2028) return false;
  return codepointClass.inRanges(cc, codepointClass.LINE_TERMINATOR_RANGES);
}

function _isReplyWordChar(cc) {
  return (cc >= 0x30 && cc <= 0x39) || (cc >= 0x41 && cc <= 0x5A) ||
         (cc >= 0x61 && cc <= 0x7A) || cc === 0x5F;
}

function _clamThreatName(reply) {
  var n = reply.length;
  var nameStart = -1;
  var breakAt = -1;
  var pendingAfterLabel = -1;
  var lastAfterLabel = -1;
  var spaceOnlySinceLabel = false;
  var fallbackAt = -1;
  var i = 0;
  while (i < n) {
    var cc = reply.charCodeAt(i);

    if (cc === 0x46 && reply.startsWith("FOUND", i)) {
      var after = i + 5;
      if (after >= n || !_isReplyWordChar(reply.charCodeAt(after))) {
        if (nameStart !== -1 && i > nameStart) {
          var end = i - 1;
          while (end >= nameStart && _isReplySpace(reply.charCodeAt(end))) end -= 1;
          if (end < i - 1 && end >= nameStart &&
              (breakAt === -1 || breakAt > end)) {
            return reply.slice(nameStart, end + 1);
          }
        }
        if (fallbackAt === -1 && spaceOnlySinceLabel && i - lastAfterLabel >= 3) {
          var w = i - 2;
          while (w > lastAfterLabel &&
                 _isReplyLineBreak(reply.charCodeAt(w))) w -= 1;
          if (w > lastAfterLabel) fallbackAt = w;
        }
      }
    }

    if (_isReplyLineBreak(cc)) {
      if (nameStart !== -1 && breakAt === -1 && i > nameStart) breakAt = i;
      i += 1;
      continue;
    }

    if (!_isReplySpace(cc)) spaceOnlySinceLabel = false;

    if (!_isReplySpace(cc) && breakAt !== -1 && i > breakAt) {
      if (fallbackAt !== -1) return reply.slice(fallbackAt, fallbackAt + 1);
      var revived = -1;
      if (pendingAfterLabel !== -1) {
        var rs = pendingAfterLabel;
        while (rs < n && _isReplySpace(reply.charCodeAt(rs))) rs += 1;
        if (rs > pendingAfterLabel && rs < n && rs > breakAt) revived = rs;
      }
      nameStart = revived;
      breakAt = -1;
      pendingAfterLabel = -1;
    }

    if (cc === 0x73 && reply.startsWith("stream:", i)) {
      var afterLabel = i + 7;
      lastAfterLabel = afterLabel;
      spaceOnlySinceLabel = true;
      if (nameStart === -1) {
        var ns = afterLabel;
        while (ns < n && _isReplySpace(reply.charCodeAt(ns))) ns += 1;
        if (ns > afterLabel && ns < n) {
          nameStart = ns;
          breakAt = -1;
        }
      } else {
        pendingAfterLabel = afterLabel;
      }
      i = afterLabel;
      continue;
    }
    i += 1;
  }
  if (fallbackAt !== -1) return reply.slice(fallbackAt, fallbackAt + 1);
  return null;
}

var PROFILES = Object.freeze({
  strict:     { timeoutMs: C.TIME.seconds(30),  maxMessageBytes: C.BYTES.mib(25),  maxResponseBytes: C.BYTES.mib(50) },
  balanced:   { timeoutMs: C.TIME.seconds(60),  maxMessageBytes: C.BYTES.mib(50),  maxResponseBytes: C.BYTES.mib(100) },
  permissive: { timeoutMs: C.TIME.seconds(120), maxMessageBytes: C.BYTES.mib(150), maxResponseBytes: C.BYTES.mib(300) },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var ALLOWED_PROTOCOLS = Object.freeze({
  "icap":            true,
  "clamav-instream": true,
});

/**
 * @primitive b.mail.scan.create
 * @signature b.mail.scan.create(opts)
 * @since     0.9.81
 * @status    stable
 * @related   b.safeIcap.parse, b.guardArchive.validateEntries
 *
 * Build a mail-scan handle. Returns `{ scan(messageBytes, opts),
 * profile, protocol, MailScanError }` where `.scan` resolves to
 * `{ verdict, icapResponse?, threats?, durationMs }`:
 *
 *   - `verdict`: `"clean"` | `"infected"` | `"error"`.
 *   - `icapResponse`: the structured `b.safeIcap.parse` result on
 *     ICAP backend (omitted on clamav-instream).
 *   - `threats`: Array<string> of threat names when infected.
 *   - `durationMs`: round-trip ms (audit / metrics).
 *   - `errorCode` / `errorMessage`: on every `verdict: "error"`, naming which
 *     error it was, so a caller need not know which backend answered.
 *     `mail-scan/icap-status` is an ICAP response the reader classified as
 *     neither clean nor infected, and `icapResponse` carries the parsed
 *     response alongside it. A threat found in the response is `infected`
 *     whatever its status, so a blocked-mail 403 takes the infected path and
 *     carries no error fields. On the clamav-instream backend,
 *     `mail-scan/clamav-size-limit` is a stream past the daemon's
 *     `StreamMaxLength` and will not succeed on retry;
 *     `mail-scan/clamav-error` is a daemon fault, which clears when the
 *     daemon returns; `mail-scan/clamav-unparsed-reply` is a reply the
 *     reader could not classify. `errorMessage` carries the daemon's own
 *     words, truncated to 200 characters.
 *
 * @opts
 *   host:          string — required. ICAP / clamd hostname or IP.
 *   port:          number — required. ICAP port (default 1344) /
 *                  clamd port (default 3310).
 *   service:       string — ICAP service name (default "srv_clamav").
 *   protocol:      "icap" | "clamav-instream" — default "icap".
 *   timeoutMs:     number — per-request wall clock; default per profile.
 *   profile:       "strict" | "balanced" | "permissive".
 *   posture:       "hipaa" | "pci-dss" | "gdpr" | "soc2".
 *   audit:         b.audit instance (drop-silent on failure).
 *
 * @example
 *   var scanner = b.mail.scan.create({
 *     host:    "av.internal",
 *     port:    1344,
 *     service: "srv_clamav",
 *   });
 *   var verdict = await scanner.scan(rawMessage);
 *   if (verdict.verdict === "infected") refuseMessage(verdict.threats);
 */
function create(opts) {
  opts = validateOpts.requireObject(opts || {}, "mail.scan.create", MailScanError, "mail-scan/bad-opts");
  validateOpts(opts, [
    "host", "port", "service", "protocol",
    "timeoutMs", "profile", "posture", "audit",
  ], "mail.scan.create");

  validateOpts.requireNonEmptyString(opts.host, "mail.scan.create.host",
    MailScanError, "mail-scan/bad-host");
  numericBounds.requirePositiveFiniteInt(opts.port, "mail.scan.create.port",
    MailScanError, "mail-scan/bad-port", { max: 65535 });
  var protocol = opts.protocol || DEFAULT_PROTOCOL;
  if (!Object.prototype.hasOwnProperty.call(ALLOWED_PROTOCOLS, protocol)) {
    throw new MailScanError("mail-scan/bad-protocol",
      "mail.scan.create.protocol must be 'icap' or 'clamav-instream'; got '" + protocol + "'");
  }
  var service = opts.service || DEFAULT_ICAP_SERVICE;
  if (protocol === "icap") {
    validateOpts.requireNonEmptyString(service, "mail.scan.create.service",
      MailScanError, "mail-scan/bad-service");
  }
  var profile = gateContract.resolveProfileName(opts, COMPLIANCE_POSTURES, DEFAULT_PROFILE);
  if (!Object.prototype.hasOwnProperty.call(PROFILES, profile)) {
    throw new MailScanError("mail-scan/bad-profile",
      "mail.scan.create.profile: unknown '" + profile + "' (valid: strict / balanced / permissive)");
  }
  var caps = PROFILES[profile];
  numericBounds.requirePositiveFiniteIntIfPresent(opts.timeoutMs,
    "mail.scan.create.timeoutMs", MailScanError, "mail-scan/bad-timeout");
  var timeoutMs = opts.timeoutMs || caps.timeoutMs;
  var auditImpl = opts.audit || audit();

  function scan(messageBytes, scanOpts) {
    scanOpts = scanOpts || {};
    if (!Buffer.isBuffer(messageBytes)) {
      throw new MailScanError("mail-scan/bad-input",
        "mail.scan.scan: messageBytes must be a Buffer; got " + (typeof messageBytes));
    }
    if (messageBytes.length === 0) {
      throw new MailScanError("mail-scan/bad-input",
        "mail.scan.scan: messageBytes must be non-empty");
    }
    if (safeBuffer.byteLengthOf(messageBytes) > caps.maxMessageBytes) {
      throw new MailScanError("mail-scan/oversize-message",
        "mail.scan.scan: messageBytes=" + messageBytes.length + " exceeds maxMessageBytes=" +
        caps.maxMessageBytes);
    }

    if (Array.isArray(scanOpts.archiveEntries)) {
      var gv = guardArchive().validateEntries(scanOpts.archiveEntries, { profile: profile });
      if (gv && gv.issues && gv.issues.length > 0) {
        var infectedThreats = gv.issues.map(function (i) { return "archive:" + (i.code || "unknown"); });
        _emitAudit(auditImpl, "mail.scan.infected", "success", {
          reason: "archive-pre-scan", threats: infectedThreats,
        });
        return Promise.resolve({
          verdict:    "infected",
          threats:    infectedThreats,
          durationMs: 0,
        });
      }
    }

    _emitAudit(auditImpl, "mail.scan.request", "success", {
      protocol: protocol, host: opts.host, port: opts.port, bytes: messageBytes.length,
    });

    var t0 = Date.now();
    if (protocol === "icap") {
      return _scanIcap(messageBytes, scanOpts).then(function (rv) {
        rv.durationMs = Date.now() - t0;
        _emitScanResult(auditImpl, rv);
        return rv;
      }, function (e) {
        var ms = Date.now() - t0;
        return _failTo(auditImpl, e, ms);
      });
    }
    return _scanClamavInstream(messageBytes, scanOpts).then(function (rv) {
      rv.durationMs = Date.now() - t0;
      _emitScanResult(auditImpl, rv);
      return rv;
    }, function (e) {
      var ms = Date.now() - t0;
      return _failTo(auditImpl, e, ms);
    });
  }

  function _scanIcap(messageBytes, scanOpts) {
    return new Promise(function (resolve, reject) {
      var sock = (scanOpts._socket && typeof scanOpts._socket.write === "function")
        ? scanOpts._socket
        : net.createConnection({ host: opts.host, port: opts.port });

      var collector = safeBuffer.boundedChunkCollector({
        maxBytes:   caps.maxResponseBytes,
        errorClass: MailScanError,
        sizeCode:   "mail-scan/icap-response-too-large",
        sizeMessage: "mail.scan.scan: ICAP response exceeded maxResponseBytes",
      });
      var done = false;
      var to = setTimeout(function () {
        if (done) return;
        done = true;
        try { sock.destroy(); } catch (_e) { /* drop */ }
        reject(new MailScanError("mail-scan/timeout",
          "mail.scan.scan: ICAP timeout after " + timeoutMs + "ms"));
      }, timeoutMs);

      sock.on("error", function (e) {
        if (done) return;
        done = true;
        clearTimeout(to);
        reject(new MailScanError("mail-scan/transport",
          "mail.scan.scan: ICAP socket error: " + (e && e.message || e)));
      });

      sock.on("data", function (chunk) {
        try { collector.push(chunk); }
        catch (e) {
          if (done) return;
          done = true;
          clearTimeout(to);
          try { sock.destroy(); } catch (_e) { /* drop */ }
          reject(e);
        }
      });

      sock.on("end", function () {
        if (done) return;
        done = true;
        clearTimeout(to);
        try {
          var raw = collector.result();
          resolve(_icapVerdictFrom(safeIcap.parse(raw, { profile: profile })));
        } catch (e) {
          reject(e);
        }
      });

      var httpHdr = "HTTP/1.1 200 OK\r\nContent-Type: message/rfc822\r\nContent-Length: " +
        messageBytes.length + "\r\n\r\n";
      var resBodyOffset = Buffer.byteLength(httpHdr, "ascii");
      var icapHdr =
        "RESPMOD icap://" + opts.host + ":" + opts.port + "/" + service + " ICAP/1.0\r\n" +
        "Host: " + opts.host + "\r\n" +
        "Allow: 204\r\n" +
        "Encapsulated: res-hdr=0, res-body=" + resBodyOffset + "\r\n" +
        "\r\n";
      try {
        sock.write(icapHdr);
        sock.write(httpHdr);
        var lenHex = messageBytes.length.toString(16);
        sock.write(lenHex + "\r\n");
        sock.write(messageBytes);
        sock.write("\r\n0\r\n\r\n");
        if (typeof sock.end === "function") sock.end();
      } catch (e) {
        if (done) return;
        done = true;
        clearTimeout(to);
        reject(new MailScanError("mail-scan/transport",
          "mail.scan.scan: ICAP write error: " + (e && e.message || e)));
      }
    });
  }

  function _scanClamavInstream(messageBytes, scanOpts) {
    return new Promise(function (resolve, reject) {
      var sock = (scanOpts && scanOpts._socket && typeof scanOpts._socket.write === "function")
        ? scanOpts._socket
        : net.createConnection({ host: opts.host, port: opts.port });
      var collector = safeBuffer.boundedChunkCollector({
        maxBytes:   caps.maxResponseBytes,
        errorClass: MailScanError,
        sizeCode:   "mail-scan/clamav-response-too-large",
        sizeMessage: "mail.scan.scan: clamav reply exceeded maxResponseBytes",
      });
      var done = false;
      var to = setTimeout(function () {
        if (done) return;
        done = true;
        try { sock.destroy(); } catch (_e) { /* drop */ }
        reject(new MailScanError("mail-scan/timeout",
          "mail.scan.scan: clamav-instream timeout after " + timeoutMs + "ms"));
      }, timeoutMs);

      sock.on("error", function (e) {
        if (done) return;
        done = true;
        clearTimeout(to);
        var buffered = _bufferedClamVerdict(collector);
        if (buffered !== null) { resolve(buffered); return; }
        reject(new MailScanError("mail-scan/transport",
          "mail.scan.scan: clamav socket error: " + (e && e.message || e)));
      });

      sock.on("data", function (chunk) {
        try { collector.push(chunk); }
        catch (e) {
          if (done) return;
          done = true;
          clearTimeout(to);
          try { sock.destroy(); } catch (_e) { /* drop */ }
          reject(e);
        }
      });

      sock.on("end", function () {
        if (done) return;
        done = true;
        clearTimeout(to);
        resolve(_clamVerdictFor(
          _stripTrailingEol(collector.result().toString("utf8"))));
      });

      try {
        sock.write("zINSTREAM\0");
        var off = 0;
        while (off < messageBytes.length) {
          var endOff = Math.min(off + CLAMAV_CHUNK_BYTES, messageBytes.length);
          var lenBuf = Buffer.alloc(CLAMAV_LENGTH_PREFIX_BYTES);
          lenBuf.writeUInt32BE(endOff - off, 0);
          sock.write(lenBuf);
          sock.write(messageBytes.slice(off, endOff));
          off = endOff;
        }
        var term = Buffer.alloc(CLAMAV_LENGTH_PREFIX_BYTES);
        term.writeUInt32BE(0, 0);
        sock.write(term);
        if (typeof sock.end === "function") sock.end();
      } catch (e) {
        if (done) return;
        done = true;
        clearTimeout(to);
        reject(new MailScanError("mail-scan/transport",
          "mail.scan.scan: clamav write error: " + (e && e.message || e)));
      }
    });
  }

  return {
    scan:           scan,
    profile:        profile,
    protocol:       protocol,
    host:           opts.host,
    port:           opts.port,
    service:        service,
    timeoutMs:      timeoutMs,
    MailScanError:  MailScanError,
  };
}

/**
 * @primitive b.mail.scan.compliancePosture
 * @signature b.mail.scan.compliancePosture(posture)
 * @since     0.9.81
 * @status    stable
 *
 * Return the effective profile name for a compliance posture, or
 * `null` for unknown posture names.
 *
 * @example
 *   b.mail.scan.compliancePosture("hipaa");   // → "strict"
 */
var compliancePosture = gateContract.makePostureAccessor(COMPLIANCE_POSTURES);

function _emitScanResult(auditImpl, rv) {
  if (rv.verdict === "clean") {
    _emitAudit(auditImpl, "mail.scan.clean", "success", { durationMs: rv.durationMs });
  } else if (rv.verdict === "infected") {
    _emitAudit(auditImpl, "mail.scan.infected", "success", {
      durationMs: rv.durationMs, threats: rv.threats,
    });
  } else {
    _emitAudit(auditImpl, "mail.scan.error", "failure", { durationMs: rv.durationMs });
  }
}

function _failTo(auditImpl, e, ms) {
  if (e && e.code === "mail-scan/timeout") {
    _emitAudit(auditImpl, "mail.scan.timeout", "failure", { durationMs: ms });
  } else {
    _emitAudit(auditImpl, "mail.scan.error", "failure", {
      durationMs: ms, message: (e && e.message) || String(e),
    });
  }
  return { verdict: "error", threats: [], durationMs: ms,
    errorCode: (e && e.code) || "mail-scan/unknown",
    errorMessage: (e && e.message) || String(e) };
}

function _emitAudit(auditImpl, action, outcome, metadata) {
  try {
    if (auditImpl && typeof auditImpl.safeEmit === "function") {
      auditImpl.safeEmit({ action: action, outcome: outcome, metadata: metadata });
    }
  } catch (_e) { /* drop-silent — audit failures don't break scan path */ }
}

module.exports = {
  create:               create,
  compliancePosture:    compliancePosture,
  PROFILES:             PROFILES,
  COMPLIANCE_POSTURES:  COMPLIANCE_POSTURES,
  ALLOWED_PROTOCOLS:    ALLOWED_PROTOCOLS,
  MailScanError:        MailScanError,
};

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

var audit             = lazyRequire(function () { return require("./audit"); });
var guardArchive      = lazyRequire(function () { return require("./guard-archive"); });

var MailScanError = defineClass("MailScanError", { alwaysPermanent: true });

var DEFAULT_PROFILE      = "strict";
var DEFAULT_PROTOCOL     = "icap";
var DEFAULT_ICAP_SERVICE = "srv_clamav";

// ClamAV INSTREAM 4-byte length prefix.
var CLAMAV_LENGTH_PREFIX_BYTES = 4;

// ClamAV INSTREAM chunk size for streaming.
var CLAMAV_CHUNK_BYTES = 65536;

var PROFILES = Object.freeze({
  strict:     { timeoutMs: C.TIME.seconds(30),  maxMessageBytes: C.BYTES.mib(25),  maxResponseBytes: C.BYTES.mib(50) },   // operator-facing default mailbox cap
  balanced:   { timeoutMs: C.TIME.seconds(60),  maxMessageBytes: C.BYTES.mib(50),  maxResponseBytes: C.BYTES.mib(100) },  // operator-facing default mailbox cap
  permissive: { timeoutMs: C.TIME.seconds(120), maxMessageBytes: C.BYTES.mib(150), maxResponseBytes: C.BYTES.mib(300) },  // operator-facing default mailbox cap
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
    MailScanError, "mail-scan/bad-port", { max: 65535 });   // TCP port-number range cap
  var protocol = opts.protocol || DEFAULT_PROTOCOL;
  if (!ALLOWED_PROTOCOLS[protocol]) {
    throw new MailScanError("mail-scan/bad-protocol",
      "mail.scan.create.protocol must be 'icap' or 'clamav-instream'; got '" + protocol + "'");
  }
  var service = opts.service || DEFAULT_ICAP_SERVICE;
  if (protocol === "icap") {
    validateOpts.requireNonEmptyString(service, "mail.scan.create.service",
      MailScanError, "mail-scan/bad-service");
  }
  var profile = opts.profile || (opts.posture && COMPLIANCE_POSTURES[opts.posture]) || DEFAULT_PROFILE;
  if (!PROFILES[profile]) {
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
    if (messageBytes.length > caps.maxMessageBytes) {
      throw new MailScanError("mail-scan/oversize-message",
        "mail.scan.scan: messageBytes=" + messageBytes.length + " exceeds maxMessageBytes=" +
        caps.maxMessageBytes);
    }

    // Optional archive-entries gate — compose b.guardArchive when the
    // operator enumerates entries before scanning. Hostile entry metadata
    // (zip-slip / hardlink-escape / decompression-bomb-ratio) refuses
    // before the AV daemon ever sees the bytes.
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
    return _scanClamavInstream(messageBytes).then(function (rv) {
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
          var parsed = safeIcap.parse(raw, { profile: profile });
          var threats = [];
          if (parsed.threatName) threats.push(parsed.threatName);
          resolve({
            verdict:      parsed.threatFound ? "infected" : (parsed.statusCode === 200 || parsed.statusCode === 204 ? "clean" : "error"),
            icapResponse: parsed,
            threats:      threats,
          });
        } catch (e) {
          reject(e);
        }
      });

      // RFC 3507 §4.3.2 — RESPMOD request: ICAP-Version, Host header,
      // Encapsulated header pointing at res-hdr=0, res-body=N. We send
      // a minimal HTTP-response wrapper around the raw mail bytes; the
      // ICAP daemon scans the body region.
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
        // RFC 3507 §4.4.3 — body is chunked-transfer; we write a single
        // chunk + terminator for simplicity. The wire format is the same
        // as HTTP/1.1 chunked: `<hex-length>\r\n<bytes>\r\n0\r\n\r\n`.
        var lenHex = messageBytes.length.toString(16);                                              // hex radix
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

  function _scanClamavInstream(messageBytes) {
    return new Promise(function (resolve, reject) {
      var sock = net.createConnection({ host: opts.host, port: opts.port });
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
        var reply = collector.result().toString("utf8").replace(/[\r\n\0]+$/g, "");                // allow:regex-no-length-cap — trailing-trim anchored
        // ClamAV INSTREAM reply: "<id>: <verdict>" where verdict is
        // "stream: OK", "stream: <Sig.Name> FOUND", or "INSTREAM size
        // limit exceeded. ERROR".
        if (/stream:\s+OK\b/.test(reply)) {                                                        // allow:regex-no-length-cap — anchored to fixed token
          resolve({ verdict: "clean", threats: [] });
        } else {
          var m = reply.match(/stream:\s+(.+?)\s+FOUND\b/);                                        // allow:regex-no-length-cap — anchored to fixed FOUND token
          if (m) {
            resolve({ verdict: "infected", threats: [m[1]] });
          } else if (/ERROR/i.test(reply)) {                                                       // allow:regex-no-length-cap — anchored to fixed ERROR token
            resolve({ verdict: "error", threats: [] });
          } else {
            // Unrecognized reply shape — treat as error so the caller
            // gets a definite "do not deliver" signal instead of a
            // silent clean verdict.
            resolve({ verdict: "error", threats: [] });
          }
        }
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
function compliancePosture(posture) {
  return COMPLIANCE_POSTURES[posture] || null;
}

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

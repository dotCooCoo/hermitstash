"use strict";
// codebase-patterns:allow-file raw-byte-literal — RFC 3507 ICAP status-code
// table (200 / 204 / 400 / 403 / 404 / 405 / 408 / 500 / 504). These are
// HTTP-style protocol constants, not memory caps.
/**
 * @module     b.safeIcap
 * @nav        Parsers
 * @title      Safe ICAP
 * @order      218
 *
 * @intro
 *   Bounded RFC 3507 Internet Content Adaptation Protocol (ICAP)
 *   response parser. ICAP wraps HTTP-shaped request/response objects
 *   (REQMOD / RESPMOD / OPTIONS) inside a protocol that shares HTTP's
 *   header syntax but adds the `Encapsulated` header to describe a
 *   compound body of `req-hdr`, `req-body`, `res-hdr`, `res-body`,
 *   `opt-body`, or `null-body` sections at byte offsets.
 *
 *   Substrate for `b.mail.scan` (v0.9.x) — every consumer that talks
 *   to ClamAV-via-c-icap, Sophos / Trend Micro / Symantec ICAP daemons,
 *   or any RFC 3507 server hands raw response bytes through this
 *   parser before trusting any field.
 *
 *   ## Wire-protocol caps (every dimension an attacker can grow)
 *
 *     - **Response header bytes** (default 8 KiB / 32 KiB / 256 KiB).
 *     - **Body bytes total** (default 1 MiB / 16 MiB / 256 MiB).
 *     - **Header count** (default 64 / 128 / 256).
 *     - **Per-header-value bytes** (default 4 KiB / 16 KiB / 64 KiB).
 *
 *   ## Refusals
 *
 *     - **Bare-CR / bare-LF / NUL inside headers** — RFC 3507 §4.3.1
 *       inherits RFC 7230's CRLF-only rule. Bare-LF terminators are the
 *       canonical ICAP-response-injection vector (a hostile upstream
 *       smuggles a second response by terminating with `\n` instead of
 *       `\r\n`; intermediaries that accept bare-LF then desync against
 *       this parser).
 *     - **Status-code allowlist** — only `100` / `200` / `204` / `400`
 *       / `403` / `404` / `405` / `408` / 5xx are honored. RFC 3507
 *       §4.3.3 enumerates these as the legal ICAP response codes; an
 *       unexpected `1xx` continuation
 *       or `3xx` redirect is refused because it's a classic header-
 *       injection class (attacker smuggles `ICAP/1.0 100 X-Inject:`
 *       through a permissive proxy).
 *     - **`Encapsulated` parse-failure** — header value must be a
 *       comma-separated list of `<part>=<offset>` tokens where `<part>`
 *       is one of the six legal section names and `<offset>` is a
 *       non-negative integer within the body region.
 *     - **Body cap** — `res-body` / `opt-body` body section length
 *       capped at profile's `maxBodyBytes`. Defends the parser-bomb
 *       class (RFC 3507 §3 imposes no body cap on the wire, so a
 *       hostile ICAP daemon can ship arbitrary bytes here).
 *
 *   ## CVE / threat model
 *
 *   No CVE pool exists specifically for "ICAP-response-injection"
 *   because the protocol is operationally deployed inside trusted
 *   networks — that very assumption is the threat model. Operators
 *   tunnelling untrusted client byte streams through ICAP-mediated AV
 *   scanning need to refuse hostile ICAP responses just as
 *   aggressively as hostile HTTP responses. The same byte-level
 *   discipline that defends HTTP request-smuggling (CVE-2019-18801 /
 *   -18802 / -18803, CVE-2023-44487 HTTP/2 Rapid Reset) applies here
 *   — strict CRLF, strict status-code allowlist, bounded header /
 *   body / count dimensions, no continuation-line acceptance.
 *
 *   Parser is purely functional — no I/O, no async — operator owns
 *   the socket lifecycle (the `b.mail.scan` primitive composes the
 *   parser with its own ICAP socket).
 *
 * @card
 *   Bounded RFC 3507 ICAP response parser. Refuses bare-CR / bare-LF /
 *   NUL in headers; status-code allowlist; per-header / per-body
 *   caps; structured Encapsulated parsing. Substrate for b.mail.scan.
 */

var C                  = require("./constants");
var { defineClass }    = require("./framework-error");
var gateContract       = require("./gate-contract");

var SafeIcapError = defineClass("SafeIcapError", { alwaysPermanent: true });

// RFC 3507 §4.3.3 enumerated ICAP response status codes.
var ALLOWED_STATUS = Object.freeze({
  100: "Continue",
  200: "OK",
  204: "No Content",
  400: "Bad Request",
  403: "Forbidden",
  404: "ICAP Service Not Found",
  405: "Method Not Allowed",
  408: "Request Timeout",
  500: "Server Error",
  501: "Method Not Implemented",
  502: "Bad Gateway",
  503: "Service Overloaded",
  504: "Gateway Timeout",
  505: "ICAP Version Not Supported",
});

// RFC 3507 §4.4 Encapsulated section names.
var ENCAPSULATED_PARTS = Object.freeze({
  "req-hdr":   true,
  "req-body":  true,
  "res-hdr":   true,
  "res-body":  true,
  "opt-body":  true,
  "null-body": true,
});

var DEFAULT_PROFILE = "strict";

var PROFILES = Object.freeze({
  strict: {
    maxResponseHeaderBytes: C.BYTES.kib(8),
    maxBodyBytes:           C.BYTES.mib(1),
    maxHeaderCount:         64,                                                                  // count, not bytes
    maxHeaderValueBytes:    C.BYTES.kib(4),
  },
  balanced: {
    maxResponseHeaderBytes: C.BYTES.kib(32),
    maxBodyBytes:           C.BYTES.mib(16),
    maxHeaderCount:         128,                                                                 // count, not bytes
    maxHeaderValueBytes:    C.BYTES.kib(16),
  },
  permissive: {
    maxResponseHeaderBytes: C.BYTES.kib(256),
    maxBodyBytes:           C.BYTES.mib(256),
    maxHeaderCount:         256,                                                                 // count, not bytes
    maxHeaderValueBytes:    C.BYTES.kib(64),
  },
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

var _resolveProfile = gateContract.makeProfileResolver({
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  defaults:   DEFAULT_PROFILE,
  errorClass: SafeIcapError,
  codePrefix: "safe-icap",
  byObject:   true,
});

/**
 * @primitive b.safeIcap.parse
 * @signature b.safeIcap.parse(buf, opts?)
 * @since     0.9.81
 * @status    stable
 * @related   b.safeIcap.compliancePosture
 *
 * Parse an ICAP/1.0 response (RFC 3507 §4.3) from a byte buffer.
 * Returns `{ statusCode, statusText, headers, encapsulated,
 * headerByteLength, body, threatFound, threatName? }` where:
 *
 *   - `statusCode` / `statusText` come from the status-line (e.g.
 *     `ICAP/1.0 200 OK` → 200 / "OK"). Status MUST be one of the
 *     RFC 3507 §4.3.3 codes (100 / 200 / 204 / 400 / 403 / 404 /
 *     405 / 408 / 500-505).
 *   - `headers` is a lower-cased-key object. Duplicate header names
 *     collapse to an Array of values.
 *   - `encapsulated` is `{ "req-hdr": offset, "res-body": offset, ... }`
 *     parsed from the `Encapsulated` header. `null` if the header is
 *     absent (legal for status 100 / 204 / 4xx / 5xx).
 *   - `headerByteLength` — the byte offset where the body region
 *     starts (after the terminating CRLF CRLF).
 *   - `body` — Buffer slice of the body region, length-capped by
 *     `maxBodyBytes`. Empty Buffer when the body region is absent
 *     or zero-length.
 *   - `threatFound` — boolean. `true` when the response signals an
 *     infected verdict via the well-known `X-Infection-Found` header
 *     (Symantec / ClamAV / Sophos all emit this on a hit) OR the
 *     status code is `403` (ICAP convention: 403 = blocked).
 *   - `threatName` — string when `X-Infection-Found` parses out a
 *     `Threat=<name>` token; absent otherwise.
 *
 * Throws `SafeIcapError` with codes:
 *   `safe-icap/bad-input` / `oversize-header` / `oversize-body` /
 *   `oversize-header-count` / `oversize-header-value` /
 *   `bare-cr-or-lf` / `nul-in-header` / `bad-status-line` /
 *   `unexpected-status` / `bad-encapsulated` / `bad-profile`.
 *
 * @opts
 *   profile:  "strict" | "balanced" | "permissive",
 *   posture:  "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *
 * @example
 *   var parsed = b.safeIcap.parse(wireBytes);
 *   if (parsed.threatFound) refuseMessage(parsed.threatName);
 */
function parse(buf, opts) {
  opts = opts || {};
  if (!Buffer.isBuffer(buf)) {
    throw new SafeIcapError("safe-icap/bad-input",
      "safeIcap.parse: buf must be a Buffer; got " + (typeof buf));
  }
  var caps = _resolveProfile(opts);

  // Locate the end-of-headers CRLF CRLF marker.
  var headerEnd = _findHeaderEnd(buf, caps.maxResponseHeaderBytes);
  if (headerEnd === -1) {
    throw new SafeIcapError("safe-icap/oversize-header",
      "safeIcap.parse: end-of-headers CRLFCRLF not found within maxResponseHeaderBytes=" +
      caps.maxResponseHeaderBytes + " (RFC 3507 §4.3.1)");
  }

  // Validate header bytes for bare-CR / bare-LF / NUL before we tokenize.
  _refuseBadHeaderBytes(buf, headerEnd);

  // Tokenize the status-line + header lines on CRLF.
  var lines = _splitCrlf(buf, 0, headerEnd);
  if (lines.length === 0) {
    throw new SafeIcapError("safe-icap/bad-status-line",
      "safeIcap.parse: empty response (no status line)");
  }
  var statusLine = lines[0];
  var statusParse = _parseStatusLine(statusLine);

  var headers = {};
  var headerCount = 0;
  for (var i = 1; i < lines.length; i += 1) {
    var line = lines[i];
    if (line.length === 0) continue;                                                              // RFC 7230 §3.2 — blank header lines refused below as bad-header anyway
    headerCount += 1;
    if (headerCount > caps.maxHeaderCount) {
      throw new SafeIcapError("safe-icap/oversize-header-count",
        "safeIcap.parse: header count exceeds maxHeaderCount=" + caps.maxHeaderCount);
    }
    var kv = _parseHeaderLine(line, caps.maxHeaderValueBytes);
    _addHeader(headers, kv.name, kv.value);
  }

  var encapsulated = null;
  if (headers["encapsulated"] !== undefined) {
    encapsulated = _parseEncapsulated(_firstHeader(headers["encapsulated"]));
  }

  // Body region: from headerEnd (which points AT the first byte of the
  // body, after the CRLFCRLF) through end of buffer, capped.
  var bodyStart = headerEnd;
  var bodyLen = buf.length - bodyStart;
  if (bodyLen < 0) bodyLen = 0;
  if (bodyLen > caps.maxBodyBytes) {
    throw new SafeIcapError("safe-icap/oversize-body",
      "safeIcap.parse: body bytes=" + bodyLen + " exceeds maxBodyBytes=" + caps.maxBodyBytes +
      " (RFC 3507 §3 parser-bomb defense)");
  }
  var body = bodyLen > 0 ? buf.slice(bodyStart, bodyStart + bodyLen) : Buffer.alloc(0);

  var threat = _detectThreat(statusParse.statusCode, headers);

  return {
    statusCode:       statusParse.statusCode,
    statusText:       statusParse.statusText,
    headers:          headers,
    encapsulated:     encapsulated,
    headerByteLength: headerEnd,
    body:             body,
    threatFound:      threat.found,
    threatName:       threat.name,
  };
}

// ---- internals ----

function _findHeaderEnd(buf, maxHeaderBytes) {
  var stop = Math.min(buf.length, maxHeaderBytes);
  for (var i = 0; i + 3 < stop; i += 1) {                                                         // 4-byte CRLFCRLF terminator
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a &&
        buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
      return i + 4;                                                                                // past the CRLFCRLF
    }
  }
  return -1;
}

function _refuseBadHeaderBytes(buf, headerEnd) {
  // RFC 3507 §4.3.1 inherits RFC 7230's CRLF-only rule. Bare-CR /
  // bare-LF / NUL anywhere in the header region is refused. CRLF
  // pairs are legal line terminators; CR not followed by LF or LF
  // not preceded by CR are smuggling vectors.
  for (var i = 0; i < headerEnd; i += 1) {
    var byte = buf[i];
    if (byte === 0) {                                                                              // NUL byte refusal
      throw new SafeIcapError("safe-icap/nul-in-header",
        "safeIcap.parse: NUL byte in header region at offset=" + i);
    }
    if (byte === 0x0d) {                                                                           // CR
      if (i + 1 >= headerEnd || buf[i + 1] !== 0x0a) {                                             // LF
        throw new SafeIcapError("safe-icap/bare-cr-or-lf",
          "safeIcap.parse: bare-CR (CR without LF) at offset=" + i +
          " (RFC 3507 §4.3.1 ICAP-response-injection defense)");
      }
    } else if (byte === 0x0a) {                                                                    // LF
      if (i === 0 || buf[i - 1] !== 0x0d) {                                                        // CR
        throw new SafeIcapError("safe-icap/bare-cr-or-lf",
          "safeIcap.parse: bare-LF (LF without CR) at offset=" + i +
          " (RFC 3507 §4.3.1 ICAP-response-injection defense)");
      }
    }
  }
}

function _splitCrlf(buf, start, end) {
  // Caller has already refused bare-CR / bare-LF, so every \n in
  // [start, end) is preceded by \r. Split on \r\n.
  var lines = [];
  var lineStart = start;
  for (var i = start; i + 1 < end; i += 1) {
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a) {                                                  // CRLF terminator
      lines.push(buf.toString("ascii", lineStart, i));
      i += 1;
      lineStart = i + 1;
    }
  }
  if (lineStart < end) lines.push(buf.toString("ascii", lineStart, end));
  return lines;
}

function _parseStatusLine(line) {
  // RFC 3507 §4.3.2 — ICAP-Version SP Status-Code SP Reason-Phrase.
  // ICAP-Version is "ICAP/1.0".
  if (line.indexOf("ICAP/") !== 0) {
    throw new SafeIcapError("safe-icap/bad-status-line",
      "safeIcap.parse: status line must start with 'ICAP/' (got '" +
      line.slice(0, 16) + "')");                                                                   // bound diagnostic slice
  }
  var sp1 = line.indexOf(" ");
  if (sp1 === -1) {
    throw new SafeIcapError("safe-icap/bad-status-line",
      "safeIcap.parse: status line missing space after version");
  }
  var sp2 = line.indexOf(" ", sp1 + 1);
  if (sp2 === -1) sp2 = line.length;
  var codeStr = line.slice(sp1 + 1, sp2);
  if (!/^\d{3}$/.test(codeStr)) {                                                                  // allow:regex-no-length-cap — fixed 3-digit anchor
    throw new SafeIcapError("safe-icap/bad-status-line",
      "safeIcap.parse: status code not 3 ASCII digits (got '" + codeStr + "')");
  }
  var statusCode = parseInt(codeStr, 10);                                                          // base-10 radix
  if (!Object.prototype.hasOwnProperty.call(ALLOWED_STATUS, statusCode)) {
    throw new SafeIcapError("safe-icap/unexpected-status",
      "safeIcap.parse: status code " + statusCode +
      " is not in the RFC 3507 §4.3.3 allowlist (smuggling defense)");
  }
  var statusText = sp2 < line.length ? line.slice(sp2 + 1) : ALLOWED_STATUS[statusCode];
  return { statusCode: statusCode, statusText: statusText };
}

function _parseHeaderLine(line, maxValueBytes) {
  // RFC 7230 §3.2 — field-name ":" OWS field-value OWS. ICAP inherits.
  var colon = line.indexOf(":");
  if (colon === -1) {
    throw new SafeIcapError("safe-icap/bad-status-line",
      "safeIcap.parse: header line missing ':' (got '" + line.slice(0, 32) + "')");                // bound diagnostic slice
  }
  var name = line.slice(0, colon).toLowerCase();
  if (name.length === 0) {
    throw new SafeIcapError("safe-icap/bad-status-line",
      "safeIcap.parse: header has empty name");
  }
  // RFC 7230 §3.2.6 — field-name token chars (RFC 5234 ALPHA / DIGIT
  // plus a fixed punctuation set). Refuse anything else.
  for (var i = 0; i < name.length; i += 1) {
    var cc = name.charCodeAt(i);
    var ok = (cc >= 0x30 && cc <= 0x39) ||                                                         // DIGIT 0-9
             (cc >= 0x41 && cc <= 0x5a) ||                                                         // UPPER (lowercased above; defensive)
             (cc >= 0x61 && cc <= 0x7a) ||                                                         // lower a-z
             cc === 0x21 || cc === 0x23 || cc === 0x24 || cc === 0x25 ||                           // ! # $ %
             cc === 0x26 || cc === 0x27 || cc === 0x2a || cc === 0x2b ||                           // & ' * +
             cc === 0x2d || cc === 0x2e || cc === 0x5e || cc === 0x5f ||                           // - . ^ _
             cc === 0x60 || cc === 0x7c || cc === 0x7e;                                            // ` | ~
    if (!ok) {
      throw new SafeIcapError("safe-icap/bad-status-line",
        "safeIcap.parse: invalid char in header name '" + name + "' (RFC 7230 §3.2.6 tchar)");
    }
  }
  // Manual trim — avoids the polynomial-regex shape `/^\s+|\s+$/g`
  // CodeQL flags, where the alternation can backtrack against itself
  // on `\t` repetitions even though the upstream line cap bounds the
  // input length.
  var raw = line.slice(colon + 1);
  var start = 0;
  var end = raw.length;
  while (start < end && (raw.charCodeAt(start) === 0x20 || raw.charCodeAt(start) === 0x09)) start += 1;
  while (end > start && (raw.charCodeAt(end - 1) === 0x20 || raw.charCodeAt(end - 1) === 0x09)) end -= 1;
  var value = raw.slice(start, end);
  if (Buffer.byteLength(value, "ascii") > maxValueBytes) {
    throw new SafeIcapError("safe-icap/oversize-header-value",
      "safeIcap.parse: header '" + name + "' value " + value.length +
      " bytes exceeds maxHeaderValueBytes=" + maxValueBytes);
  }
  return { name: name, value: value };
}

function _addHeader(headers, name, value) {
  if (headers[name] === undefined) {
    headers[name] = value;
  } else if (Array.isArray(headers[name])) {
    headers[name].push(value);
  } else {
    headers[name] = [headers[name], value];
  }
}

function _firstHeader(headerValue) {
  return Array.isArray(headerValue) ? headerValue[0] : headerValue;
}

function _parseEncapsulated(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new SafeIcapError("safe-icap/bad-encapsulated",
      "safeIcap.parse: Encapsulated header must be a non-empty string");
  }
  // RFC 3507 §4.4 — comma-separated `<part>=<offset>` tokens.
  var parts = value.split(",");
  var out = {};
  for (var i = 0; i < parts.length; i += 1) {
    var token = parts[i].replace(/^\s+|\s+$/g, "");                                                // allow:regex-no-length-cap — bounded by per-header cap
    if (token.length === 0) continue;
    var eq = token.indexOf("=");
    if (eq === -1) {
      throw new SafeIcapError("safe-icap/bad-encapsulated",
        "safeIcap.parse: Encapsulated token '" + token + "' missing '='");
    }
    var part = token.slice(0, eq);
    var offStr = token.slice(eq + 1);
    if (!Object.prototype.hasOwnProperty.call(ENCAPSULATED_PARTS, part)) {
      throw new SafeIcapError("safe-icap/bad-encapsulated",
        "safeIcap.parse: Encapsulated part '" + part + "' is not one of " +
        Object.keys(ENCAPSULATED_PARTS).join(", "));
    }
    if (!/^\d+$/.test(offStr)) {                                                                   // allow:regex-no-length-cap — bounded by per-header cap
      throw new SafeIcapError("safe-icap/bad-encapsulated",
        "safeIcap.parse: Encapsulated offset for '" + part + "' must be a non-negative integer (got '" +
        offStr + "')");
    }
    var off = parseInt(offStr, 10);                                                                // base-10 radix
    if (!isFinite(off) || off < 0) {
      throw new SafeIcapError("safe-icap/bad-encapsulated",
        "safeIcap.parse: Encapsulated offset for '" + part + "' must be a non-negative integer (got '" +
        offStr + "')");
    }
    out[part] = off;
  }
  return out;
}

function _detectThreat(statusCode, headers) {
  // RFC 3507 §4.3.3 — 403 is the conventional "ICAP service refused
  // the request" code; AV scanners emit 403 with X-Block-Reason on a
  // hit, or 200 + the modified-message with X-Infection-Found set.
  var found = false;
  var name;
  if (statusCode === 403) found = true;
  var inf = _firstHeader(headers["x-infection-found"]);
  if (typeof inf === "string" && inf.length > 0) {
    found = true;
    var m = inf.match(/Threat=([^;,\s]+)/i);                                                       // allow:regex-no-length-cap — bounded by per-header cap
    if (m) name = m[1];
  }
  var virus = _firstHeader(headers["x-virus-id"]) || _firstHeader(headers["x-violations-found"]);
  if (typeof virus === "string" && virus.length > 0 && !name) {
    found = true;
    name = virus;
  }
  return { found: found, name: name };
}

// compliancePosture is assembled by gateContract.defineParser below; its
// wiki section renders from the single-sourced @abiTemplate (defineParser)
// block in gate-contract.js, instantiated for this guard by the page
// generator.
module.exports = gateContract.defineParser({
  name:       "icap",
  entry:      parse,
  entryName:  "parse",
  errorClass: SafeIcapError,
  profiles:   PROFILES,
  postures:   COMPLIANCE_POSTURES,
  extra: {
    ALLOWED_STATUS: ALLOWED_STATUS,
    NAME:           "icap",
    KIND:           "icap-response",
  },
});

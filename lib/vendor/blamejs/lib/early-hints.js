"use strict";
/**
 * @module     b.earlyHints
 * @nav        HTTP
 * @title      RFC 8297 103 Early Hints
 * @order      320
 *
 * @intro
 *   RFC 8297 103 Early Hints — interim informational response the
 *   server sends BEFORE the final response, telling the browser
 *   which subresources it should start preloading while the server
 *   is still composing the final HTML / JSON. Browsers (Chrome 103+,
 *   Edge 103+, Firefox 120+) honor `Link: rel=preload` /
 *   `rel=preconnect` headers in the 103 to kick off resource fetches
 *   in parallel with the main render.
 *
 *   Operators reach for early-hints when the server has slow upstream
 *   dependencies (DB query, downstream API) but already knows the
 *   final response will reference specific CSS / JS / fonts /
 *   API origins. The 103 turns a single-RTT-bound page load into a
 *   parallel resource-prefetch chain.
 *
 *   `b.earlyHints.send(res, { link, ... })` writes the interim 103
 *   with the supplied headers. The framework wraps Node's built-in
 *   `res.writeEarlyHints()` (Node 18.11+) and adds:
 *
 *     - input validation (link entries must be RFC 8288 Link-header
 *       form: `<uri>; rel=preload[; as=script][; crossorigin=...]`)
 *     - silent no-op when the operator-supplied `res` is not an
 *       HTTP/1.1+ socket-backed response (HTTP/1.0 clients don't
 *       understand 103; serializing one would corrupt the stream)
 *     - validation of cacheable header set per RFC 8297 section 3
 *       (only headers that hint about the FINAL response are
 *       honored; Set-Cookie / authentication-related headers are
 *       refused)
 *
 *   The 103 does NOT replace the final response — the operator's
 *   handler still writes the regular 200/400/etc. status + body.
 *   Multiple 103s before the final response are permitted (Node's
 *   writeEarlyHints can be called repeatedly).
 *
 * @card
 *   RFC 8297 103 Early Hints helper — operator-friendly wrapper around Node's response writeEarlyHints API for browser-side parallel resource-prefetch hints.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var EarlyHintsError = defineClass("EarlyHintsError", { alwaysPermanent: true });

// Headers that are SAFE to surface in a 103 are the ones describing
// the upcoming final response. Refused header names mostly carry
// per-request state (cookies, auth) that a 103 would prematurely
// leak or that a 103 cannot honor (Content-Length, Transfer-
// Encoding, Content-Type all describe THIS interim response, not
// the final).
var REFUSED_HEADERS = Object.freeze([
  "set-cookie",
  "authorization",
  "www-authenticate",
  "content-length",
  "content-type",
  "transfer-encoding",
  "connection",
  "upgrade",
  "trailer",
]);

var LINK_RELATION_RE = /^(preload|preconnect|prefetch|dns-prefetch|modulepreload|prerender|next|prev)$/i;
var LINK_MAX_BYTES = 4096;                                                                         // per-link length cap, not bytes

/**
 * @primitive b.earlyHints.send
 * @signature b.earlyHints.send(res, opts)
 * @since     0.8.88
 * @status    stable
 *
 * Write an RFC 8297 103 Early Hints interim response to `res`.
 * Returns `true` when the 103 was written, `false` when the
 * underlying response does not support early hints (HTTP/1.0, a
 * non-HTTP-shaped object, or the response writeEarlyHints API is
 * missing).
 *
 * `link` is either a single Link-header value string OR an array
 * of strings. Each must follow the RFC 8288 Link-header grammar
 * with a `rel=` parameter naming one of: `preload`, `preconnect`,
 * `prefetch`, `dns-prefetch`, `modulepreload`, `prerender`, `next`,
 * `prev`. Refused: per-link size > 4 KiB, missing `rel=`, unknown
 * relation. Other operator-supplied header keys must NOT be in
 * `REFUSED_HEADERS` (set-cookie / authorization / content-length
 * / etc.) — those carry per-request state a 103 must not surface.
 *
 * @opts
 *   link:         string | string[],   // RFC 8288 Link-header values (REQUIRED)
 *
 * @example
 *   b.earlyHints.send(res, {
 *     link: [
 *       "</style.css>; rel=preload; as=style",
 *       "</app.js>; rel=preload; as=script",
 *       "<https://cdn.example.com>; rel=preconnect",
 *     ],
 *   });
 *   res.statusCode = 200;
 *   res.setHeader("Content-Type", "text/html");
 *   res.end(html);
 */
function send(res, opts) {
  if (!res || typeof res !== "object") {
    throw new EarlyHintsError("early-hints/bad-res",
      "earlyHints.send: res must be an HTTP response object", true);
  }
  if (typeof res.writeEarlyHints !== "function") {
    // Node < 18.11 OR HTTP/1.0 OR mock res — silent no-op so
    // operator code stays the same across deployments.
    return false;
  }
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new EarlyHintsError("early-hints/bad-opts",
      "earlyHints.send: opts required (link + optional header pairs)", true);
  }

  // Lowercase every key up front so case-variants (`Link`, `LINK`,
  // `LiNk`) collapse to the same canonical key. Without this pass
  // a caller could supply both `link` (which gets validated) AND
  // `Link` (which the validator's `if (name === "link") continue;`
  // would skip), then the lowercase rewrite in the trailing loop
  // would overwrite the validated value with unvalidated content.
  // Refuse the collision explicitly rather than silently pick one;
  // operators should pass each header exactly once.
  var canonical = {};
  var rawKeys = Object.keys(opts);
  for (var rk = 0; rk < rawKeys.length; rk += 1) {
    var rawName = rawKeys[rk];
    var lowerName = rawName.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(canonical, lowerName)) {
      throw new EarlyHintsError("early-hints/duplicate-header",
        "earlyHints.send: duplicate header '" + lowerName + "' " +
        "(case-variant supplied twice — pass each header exactly once)");
    }
    canonical[lowerName] = opts[rawName];
  }

  var headers = {};

  if (canonical.link === undefined || canonical.link === null) {
    throw new EarlyHintsError("early-hints/no-link",
      "earlyHints.send: opts.link is required (RFC 8297 §2 requires at least one Link header)", true);
  }
  var linkArr = Array.isArray(canonical.link) ? canonical.link : [canonical.link];
  if (linkArr.length === 0) {
    throw new EarlyHintsError("early-hints/no-link",
      "earlyHints.send: opts.link must contain at least one Link-header value", true);
  }
  for (var i = 0; i < linkArr.length; i += 1) {
    _validateLink(linkArr[i], i);
  }
  headers.link = linkArr;

  var canonicalKeys = Object.keys(canonical);
  for (var k = 0; k < canonicalKeys.length; k += 1) {
    var name = canonicalKeys[k];
    if (name === "link") continue;
    if (REFUSED_HEADERS.indexOf(name) !== -1) {
      throw new EarlyHintsError("early-hints/refused-header",
        "earlyHints.send: header '" + name + "' refused — RFC 8297 §3 prohibits " +
        "per-request state in interim responses (refused set: " + REFUSED_HEADERS.join(", ") + ")");
    }
    if (typeof canonical[name] !== "string" && !Array.isArray(canonical[name])) {
      throw new EarlyHintsError("early-hints/bad-header-value",
        "earlyHints.send: header '" + name + "' must be a string or string[]", true);
    }
    var vals = Array.isArray(canonical[name]) ? canonical[name] : [canonical[name]];
    for (var vi = 0; vi < vals.length; vi += 1) {
      if (typeof vals[vi] === "string" && _hasHeaderInjection(vals[vi])) {
        throw new EarlyHintsError("early-hints/bad-header-value",
          "earlyHints.send: header '" + name + "' value contains a CR/LF/NUL header-injection character", true);
      }
    }
    headers[name] = canonical[name];
  }

  try {
    res.writeEarlyHints(headers);
    return true;
  } catch (writeErr) {
    throw new EarlyHintsError("early-hints/write-failed",
      "earlyHints.send: writeEarlyHints failed: " + (writeErr.message || writeErr));
  }
}

// A header value reaching res.writeEarlyHints must carry no CR/LF/NUL — those
// split the interim response into attacker-chosen headers. Node rejects them
// too, but screen defensively (matching the cookies / security-headers
// boundary) so the framework surfaces a typed error, not a raw Node throw.
function _hasHeaderInjection(s) {
  return s.indexOf("\r") !== -1 || s.indexOf("\n") !== -1 || s.indexOf("\0") !== -1;
}

function _validateLink(linkValue, idx) {
  validateOpts.requireNonEmptyString(linkValue, "earlyHints.send.link[" + idx + "]",
    EarlyHintsError, "early-hints/bad-link");
  if (_hasHeaderInjection(linkValue)) {
    throw new EarlyHintsError("early-hints/bad-link",
      "link[" + idx + "] contains a CR/LF/NUL header-injection character");
  }
  if (linkValue.length > LINK_MAX_BYTES) {
    throw new EarlyHintsError("early-hints/bad-link",
      "link[" + idx + "] exceeds " + LINK_MAX_BYTES + " bytes");
  }
  var relMatch = /;\s*rel\s*=\s*"?([a-zA-Z0-9-]+)"?/i.exec(linkValue);
  if (!relMatch) {
    throw new EarlyHintsError("early-hints/bad-link",
      "link[" + idx + "] missing rel= parameter (RFC 8288)");
  }
  if (relMatch[1].length > 32 || !LINK_RELATION_RE.test(relMatch[1])) {                            // rel-token length cap, not bytes
    throw new EarlyHintsError("early-hints/bad-link",
      "link[" + idx + "].rel '" + relMatch[1] + "' must be one of: " +
      "preload, preconnect, prefetch, dns-prefetch, modulepreload, prerender, next, prev");
  }
  if (linkValue.charAt(0) !== "<" || linkValue.indexOf(">") < 1) {
    throw new EarlyHintsError("early-hints/bad-link",
      "link[" + idx + "] must start with angle-bracketed URI per RFC 8288 (e.g. <https://x.com>; rel=preload)");
  }
}

module.exports = {
  send:             send,
  REFUSED_HEADERS:  REFUSED_HEADERS,
  EarlyHintsError:  EarlyHintsError,
};

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * ai-act-disclosure middleware — auto-inject the EU AI Act Article 50
 * disclosure banner / meta tags into outgoing HTML responses.
 *
 *   var disclose = b.middleware.aiActDisclosure({
 *     kind:         "ai-interaction",
 *     deployerName: "myco",
 *     policyUri:    "https://myco.example.com/ai-policy",
 *   });
 *   router.use(disclose);
 *
 * Two integration modes:
 *
 *   - "header"   (default) — adds the AI-Act-Notice + AI-Act-Article
 *                            response headers. Cheapest; works for JSON
 *                            APIs as well as HTML.
 *
 *   - "html"               — when the response Content-Type is HTML,
 *                            injects a <div role="status" ...> banner
 *                            immediately after the <body> tag plus a
 *                            <meta> tag inside <head>. Handles both a
 *                            string and a Buffer body (the common server-
 *                            render path); a Buffer is decoded under the
 *                            response charset, injected, and re-encoded
 *                            for utf-8 / ascii / latin1. Other charsets
 *                            warn once and serve the original bytes (the
 *                            disclosure headers still carry the notice).
 *                            Skipped when the response is not text/html.
 *
 * The middleware does NOT alter the response when:
 *   - response status >= 400 (operator's error pages stay clean)
 *   - response is a redirect (3xx)
 *   - operator has set the X-Skip-AI-Act header on the request
 *     (test fixtures, internal-traffic carve-out)
 *   - per-request opt-out via res.locals.aiActSkip = true
 *
 * Audit emission: `compliance.aiact.disclosed` on every successful
 * injection. Operators with high-volume traffic can disable via
 * `audit: false`.
 */

var lazyRequire    = require("../lazy-require");
var validateOpts   = require("../validate-opts");
var requestHelpers = require("../request-helpers");

var aiActMod  = lazyRequire(function () { return require("../compliance-ai-act"); });
var audit     = lazyRequire(function () { return require("../audit"); });
var logger    = lazyRequire(function () { return require("../log").boot("ai-act-disclosure"); });

// Charsets whose byte<->string round-trip is lossless for the inject
// operation: utf-8 (and its ascii / latin1 subsets, which Node decodes
// byte-for-byte). Other charsets (utf-16le, big5, gb18030, …) are not
// safe to decode→inject→re-encode without a transcoder we don't vendor,
// so the Buffer path warns once and serves the original bytes untouched
// rather than risk corrupting the page.
var SAFE_INJECT_ENCODINGS = { "utf-8": "utf8", "utf8": "utf8", "us-ascii": "utf8", "ascii": "utf8", "latin1": "latin1", "iso-8859-1": "latin1" };

// Read the charset token out of a Content-Type header, lowercased and
// stripped of surrounding quotes. Returns "" when absent (the caller
// treats a missing charset as the HTML default, utf-8).
function _charsetOf(contentType) {
  if (typeof contentType !== "string") return "";
  var m = /;\s*charset\s*=\s*"?([^";]+)"?/i.exec(contentType);
  return m ? m[1].trim().toLowerCase() : "";
}

/**
 * @primitive b.middleware.aiActDisclosure
 * @signature b.middleware.aiActDisclosure(opts)
 * @since     0.1.0
 * @compliance eu-ai-act
 * @related   b.middleware.botDisclose
 *
 * Injects EU AI Act Article 50 transparency disclosures into outgoing
 * responses. In `mode: "header"` (default) it sets `AI-Act-Notice` and
 * `AI-Act-Article` response headers — cheapest, works for both JSON
 * and HTML. In `mode: "html"` it additionally inserts a status banner
 * after `<body>` for HTML responses, handling both a string and a
 * Buffer body (a Buffer is decoded under the response charset, injected,
 * and re-encoded for utf-8 / ascii / latin1; other charsets warn once
 * and serve the original bytes with the disclosure headers still set).
 * Skips error pages, redirects, requests bearing the configured
 * skip-header, and responses opted out via `res.locals.aiActSkip`.
 * Emits `compliance.aiact.disclosed` audits on success.
 *
 * @opts
 *   {
 *     kind:         "ai-interaction"|"ai-generated-content"|"emotion-recognition"|"biometric-categorisation"|"deep-fake"|"ai-text-public-interest",
 *     deployerName: string,
 *     policyUri:    string,
 *     mode:         "header"|"html",   // default "header"
 *     lang:         string,            // default "en"
 *     skipHeader:   string,            // default "x-skip-ai-act"
 *     headerPrefix: string,            // default "AI-Act-" — prefixes the Notice/Article/Policy disclosure headers
 *     audit:        boolean,           // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.aiActDisclosure({
 *     kind:         "ai-interaction",
 *     deployerName: "myco",
 *     policyUri:    "https://myco.example.com/ai-policy",
 *     mode:         "html",
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "kind", "deployerName", "policyUri", "mode",
    "audit", "lang", "skipHeader", "headerPrefix",
  ], "middleware.aiActDisclosure");

  var mode = (opts.mode === "html") ? "html" : "header";
  // Pre-validate kind via the transparency catalog.
  var probe = aiActMod().transparency.banner({
    kind: opts.kind || "ai-interaction",
    lang: opts.lang || "en",
  });
  // probe throws if kind is bad — operator catches at boot.
  void probe;

  var auditOn    = opts.audit !== false;
  var skipHeader = (typeof opts.skipHeader === "string" && opts.skipHeader.length > 0)
    ? opts.skipHeader.toLowerCase()
    : "x-skip-ai-act";
  // headerPrefix (default "AI-Act-") names the emitted disclosure headers as
  // <prefix>Notice / <prefix>Article / <prefix>Policy. The EU AI Act mandates
  // the disclosure, not the HTTP spelling — operators matching a downstream
  // convention pass their own prefix (e.g. "X-AI-").
  var headerPrefix = (typeof opts.headerPrefix === "string" && opts.headerPrefix.length > 0)
    ? opts.headerPrefix : "AI-Act-";

  return function aiActDisclosureMiddleware(req, res, next) {
    var headers = req.headers || {};
    if (headers[skipHeader] != null) return next();

    // Wrap response.writeHead so we can set headers + decide html mode.
    var origWriteHead = res.writeHead;
    var origEnd       = res.end;
    var injected      = false;

    res.writeHead = function (status, headersOrReason, headersMaybe) {
      // Only inject for 2xx HTML or any 2xx for header mode.
      if (typeof status !== "number" || status < 200 || status >= 300) {
        return origWriteHead.apply(res, arguments);
      }
      if (res.locals && res.locals.aiActSkip === true) {
        return origWriteHead.apply(res, arguments);
      }
      var article = _articleFor(opts.kind || "ai-interaction");
      _setHeader(res, headerPrefix + "Notice",  opts.kind || "ai-interaction");
      _setHeader(res, headerPrefix + "Article", article);
      if (typeof opts.policyUri === "string" && opts.policyUri.length > 0) {
        _setHeader(res, headerPrefix + "Policy", opts.policyUri);
      }
      injected = true;
      return origWriteHead.apply(res, arguments);
    };

    if (mode === "html") {
      res.end = function (chunk, encoding) {
        try {
          var ctype = (res.getHeader && res.getHeader("Content-Type")) || "";
          if (typeof ctype === "string" && ctype.indexOf("text/html") !== -1 && chunk) {
            if (typeof chunk === "string") {
              chunk = _injectBanner(chunk, opts);
            } else if (Buffer.isBuffer(chunk)) {
              // res.end(Buffer.from(html)) is the common server-render path
              // (b.render serves a Buffer). Decode under the response charset,
              // inject the Art. 50 banner, re-encode — but only for charsets
              // whose round-trip is lossless. Unknown charsets warn once and
              // serve the original bytes (no transcoder is vendored).
              var charset = _charsetOf(ctype) || "utf-8";
              var nodeEnc = SAFE_INJECT_ENCODINGS[charset];
              if (nodeEnc) {
                var injected = _injectBanner(chunk.toString(nodeEnc), opts);
                chunk = Buffer.from(injected, nodeEnc);
                // Content-Length, if the operator pre-set it, now understates
                // the body — clear it so the runtime recomputes / chunks.
                if (res.getHeader && res.getHeader("Content-Length") != null &&
                    typeof res.removeHeader === "function") {
                  res.removeHeader("Content-Length");
                }
              } else {
                _warnUnsafeCharset(charset);
              }
            }
          }
        } catch (_e) { /* injection best-effort */ }
        return origEnd.apply(res, [chunk, encoding]);
      };
    }

    if (auditOn) {
      res.on("close", function () {
        if (!injected) return;
        try {
          audit().safeEmit({
            action:   "compliance.aiact.disclosed",
            outcome:  "success",
            actor:    {
              clientIp: requestHelpers.clientIp(req),
              path:     req.url || null,
            },
            metadata: {
              kind:         opts.kind || "ai-interaction",
              mode:         mode,
              deployerName: opts.deployerName || null,
            },
          });
        } catch (_e) { /* drop-silent */ }
      });
    }

    return next();
  };
}

// Insert the EU AI Act Art. 50 status banner into an HTML string. The
// banner goes immediately after the opening <body> tag when present, else
// it is prepended. Returns the original string unchanged on any builder
// error (best-effort injection — the disclosure header still carries the
// machine-readable notice).
function _injectBanner(html, opts) {
  var bannerHtml = aiActMod().transparency.htmlBanner({
    kind: opts.kind || "ai-interaction",
    lang: opts.lang || "en",
  });
  var bodyOpen = html.indexOf("<body");
  if (bodyOpen !== -1) {
    var afterTag = html.indexOf(">", bodyOpen);
    if (afterTag !== -1) {
      return html.slice(0, afterTag + 1) + bannerHtml + html.slice(afterTag + 1);
    }
  }
  return bannerHtml + html;
}

// Warn once per process per charset that a Buffer HTML body in an
// unsupported charset was served without the banner injected, so an
// operator can switch the response to utf-8 (or accept the header-only
// disclosure). Drop-silent if the logger is unavailable.
var _warnedCharsets = Object.create(null);
function _warnUnsafeCharset(charset) {
  if (_warnedCharsets[charset]) return;
  _warnedCharsets[charset] = true;
  try {
    logger().warn("ai-act-disclosure: HTML response body is a Buffer in charset '" +
      charset + "'; the Art. 50 banner was not injected (no transcoder for that " +
      "charset). The disclosure headers are still set. Serve text/html as utf-8 to " +
      "get the in-page banner.");
  } catch (_e) { /* drop-silent — logger optional */ }
}

function _articleFor(kind) {
  switch (kind) {
    case "ai-interaction":            return "Art. 50(1)";
    case "ai-generated-content":      return "Art. 50(2)";
    case "emotion-recognition":       return "Art. 50(3)";
    case "biometric-categorisation":  return "Art. 50(3)";
    case "deep-fake":                 return "Art. 50(4)";
    case "ai-text-public-interest":   return "Art. 50(4)";
    default:                          return null;
  }
}

function _setHeader(res, name, value) {
  if (typeof res.setHeader === "function") {
    res.setHeader(name, value);
    return;
  }
  res._headers = res._headers || {};
  res._headers[name] = value;
}

module.exports = { create: create };

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var lazyRequire    = require("../lazy-require");
var validateOpts   = require("../validate-opts");
var requestHelpers = require("../request-helpers");

var aiActMod  = lazyRequire(function () { return require("../compliance-ai-act"); });
var audit     = lazyRequire(function () { return require("../audit"); });
var logger    = lazyRequire(function () { return require("../log").boot("ai-act-disclosure"); });

var SAFE_INJECT_ENCODINGS = { "utf-8": "utf8", "utf8": "utf8", "us-ascii": "utf8", "ascii": "utf8", "latin1": "latin1", "iso-8859-1": "latin1" };

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
  var probe = aiActMod().transparency.banner({
    kind: opts.kind || "ai-interaction",
    lang: opts.lang || "en",
  });
  void probe;

  var auditOn    = opts.audit !== false;
  var skipHeader = (typeof opts.skipHeader === "string" && opts.skipHeader.length > 0)
    ? opts.skipHeader.toLowerCase()
    : "x-skip-ai-act";
  var headerPrefix = (typeof opts.headerPrefix === "string" && opts.headerPrefix.length > 0)
    ? opts.headerPrefix : "AI-Act-";

  return function aiActDisclosureMiddleware(req, res, next) {
    var headers = req.headers || {};
    if (headers[skipHeader] != null) return next();

    var origWriteHead = res.writeHead;
    var origEnd       = res.end;
    var injected      = false;

    res.writeHead = function (status, headersOrReason, headersMaybe) {
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
              var charset = _charsetOf(ctype) || "utf-8";
              var nodeEnc = SAFE_INJECT_ENCODINGS[charset];
              if (nodeEnc) {
                var injected = _injectBanner(chunk.toString(nodeEnc), opts);
                chunk = Buffer.from(injected, nodeEnc);
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

// Warns once per charset. Drop-silent if the logger is unavailable.
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

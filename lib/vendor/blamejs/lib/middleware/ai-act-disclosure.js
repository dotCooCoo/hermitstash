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
 *                            <meta> tag inside <head>. Skipped when
 *                            response is already past headers OR not
 *                            text/html.
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
 * after `<body>` and a `<meta>` inside `<head>` for HTML responses.
 * Skips error pages, redirects, requests bearing the configured
 * skip-header, and responses opted out via `res.locals.aiActSkip`.
 * Emits `compliance.aiact.disclosed` audits on success.
 *
 * @opts
 *   {
 *     kind:         "ai-interaction"|"deepfake"|"emotion-recognition"|"biometric-categorisation"|"synthetic-content",
 *     deployerName: string,
 *     policyUri:    string,
 *     mode:         "header"|"html",   // default "header"
 *     lang:         string,            // default "en"
 *     skipHeader:   string,            // default "x-skip-ai-act"
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
    "audit", "lang", "skipHeader",
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
      _setHeader(res, "AI-Act-Notice",  opts.kind || "ai-interaction");
      _setHeader(res, "AI-Act-Article", article);
      if (typeof opts.policyUri === "string" && opts.policyUri.length > 0) {
        _setHeader(res, "AI-Act-Policy", opts.policyUri);
      }
      injected = true;
      return origWriteHead.apply(res, arguments);
    };

    if (mode === "html") {
      res.end = function (chunk, encoding) {
        try {
          var ctype = (res.getHeader && res.getHeader("Content-Type")) || "";
          if (typeof ctype === "string" && ctype.indexOf("text/html") !== -1 &&
              chunk && Buffer.isBuffer(chunk) === false &&
              typeof chunk === "string") {
            var bannerHtml = aiActMod().transparency.htmlBanner({
              kind: opts.kind || "ai-interaction",
              lang: opts.lang || "en",
            });
            // Inject after <body> if present, else prepend.
            var bodyOpen = chunk.indexOf("<body");
            if (bodyOpen !== -1) {
              var afterTag = chunk.indexOf(">", bodyOpen);
              if (afterTag !== -1) {
                chunk = chunk.slice(0, afterTag + 1) + bannerHtml + chunk.slice(afterTag + 1);
              }
            } else {
              chunk = bannerHtml + chunk;
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

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * botDisclose middleware — California SB 1001 bot-disclosure.
 *
 * Cal. Bus. & Prof. Code §17941 (SB 1001, effective 2019) requires
 * that any "bot" used to communicate with persons in California for
 * the purpose of incentivizing a sale or influencing an election
 * disclose its non-human nature. Operators serving an automated
 * conversation surface (LLM-backed chat / IVR / SMS) wire this
 * middleware to:
 *
 *   1. Inject a disclosure banner into HTML responses (server-rendered)
 *   2. Set an X-Bot-Disclosure header for API consumers
 *   3. Emit an audit event for every conversation-initiating request
 *
 *   var bot = b.middleware.botDisclose({
 *     audit:        b.audit,
 *     mountPaths:   ["/chat", "/api/chat"],
 *     bannerHtml:   '<div role="status">You are interacting with an automated assistant.</div>',
 *     bannerJson:   { _bot: true, disclosure: "automated-assistant" },
 *   });
 *   router.use(bot);
 *
 * Per SB 1001 §17941(a), the disclosure must be "clear, conspicuous,
 * and reasonably designed to inform"; operators with custom UI wire
 * `bannerHtml` to match their visual design.
 */

var defineClass = require("../framework-error").defineClass;
var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var safeBuffer = require("../safe-buffer");
var requestHelpers = require("../request-helpers");

var audit = lazyRequire(function () { return require("../audit"); });

var BotDiscloseError = defineClass("BotDiscloseError", { alwaysPermanent: true });

var DEFAULT_BANNER_HTML = '<div role="status" data-bot-disclosure="true" ' +
  'style="border:1px solid #888;padding:8px;margin:8px 0;background:#fff8e1;font-size:14px;">' +
  '<strong>Automated assistant.</strong> ' +
  'You are interacting with an automated agent. ' +
  'For California users: this disclosure is provided per Cal. Bus. &amp; Prof. Code §17941.' +
  '</div>';

/**
 * @primitive b.middleware.botDisclose
 * @signature b.middleware.botDisclose(opts)
 * @since     0.1.0
 * @related   b.middleware.aiActDisclosure, b.middleware.botGuard
 *
 * California SB 1001 bot-disclosure (Cal. Bus. & Prof. Code §17941):
 * automated conversation surfaces (LLM chat / IVR / SMS) used to
 * incentivize sales or influence elections must disclose their
 * non-human nature. Injects a disclosure banner into HTML responses,
 * sets `X-Bot-Disclosure` for API consumers, and emits an audit
 * event for every conversation-initiating request. Operator-supplied
 * `bannerHtml` / `bannerJson` carry custom branding while the
 * default copy meets the §17941(a) "clear, conspicuous, reasonably
 * designed" bar.
 *
 * @opts
 *   {
 *     mountPaths:  string[],         // null = apply to all routes
 *     bannerHtml:  string,
 *     bannerJson:  object,
 *     headerName:  string,           // default "X-Bot-Disclosure"
 *     auditAction: string,           // default "middleware.bot_disclose"
 *     audit:       boolean,          // default true
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.botDisclose({
 *     mountPaths: ["/chat", "/api/chat"],
 *     bannerJson: { _bot: true, disclosure: "automated-assistant" },
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "audit", "mountPaths", "bannerHtml", "bannerJson",
    "headerName", "auditAction",
  ], "middleware.botDisclose");

  var mountPaths = Array.isArray(opts.mountPaths) ? opts.mountPaths.slice() : null;
  var bannerHtml = typeof opts.bannerHtml === "string" ? opts.bannerHtml : DEFAULT_BANNER_HTML;
  var bannerJson = (opts.bannerJson && typeof opts.bannerJson === "object")
    ? opts.bannerJson : { _bot: true, disclosure: "automated-assistant" };
  var headerName = typeof opts.headerName === "string" && opts.headerName.length > 0
    ? opts.headerName : "X-Bot-Disclosure";
  var auditOn = opts.audit !== false;
  var actionBase = typeof opts.auditAction === "string" && opts.auditAction.length > 0
    ? opts.auditAction : "middleware.bot_disclose";

  // null mountPaths = apply to every route; otherwise reuse the shared
  // segment-boundary matcher (built once).
  var _mountMatch = mountPaths
    ? requestHelpers.makeSkipMatcher({ skipPaths: mountPaths }, "middleware.botDisclose")
    : null;
  function _matches(req) {
    return _mountMatch ? _mountMatch(req) : true;
  }

  function _emitAudit(action, outcome, metadata) {
    if (!auditOn) return;
    try {
      audit().safeEmit({
        action:   actionBase + "." + action,
        outcome:  outcome,
        metadata: metadata || {},
      });
    } catch (_e) { /* drop-silent */ }
  }

  return function botDiscloseMiddleware(req, res, next) {
    if (!_matches(req)) return next();

    // Always set the header (cheap; API consumers see the disclosure
    // even on JSON endpoints).
    if (typeof res.setHeader === "function") {
      res.setHeader(headerName, "automated-assistant");
    }
    _emitAudit("disclosed", "success", { method: req.method, path: req.url });

    // Patch res.write / res.end so the first text/html response gets
    // the banner injected before <body>'s first child. Operators
    // wanting deeper integration override bannerHtml or set
    // mountPaths to scope where injection happens.
    var origWrite = res.write && res.write.bind(res);
    var origEnd = res.end && res.end.bind(res);
    var injected = false;

    function _maybeInject(chunk, encoding) {
      if (injected) return chunk;
      var ct = typeof res.getHeader === "function" ? res.getHeader("content-type") : "";
      if (typeof ct !== "string" || ct.indexOf("text/html") === -1) return chunk;
      var body = Buffer.isBuffer(chunk) ? chunk.toString("utf8") :
        (typeof chunk === "string" ? chunk : "");
      // Inject after the <body> opening tag if present, else prepend.
      // Linear tag-find — NOT body.match(/<body[^>]*>/i), which is O(n^2)
      // in V8 on a body carrying many `<body` starts with no closing `>`
      // (rendered user content can produce exactly that).
      var idx = safeBuffer.indexAfterOpenTag(body, "body");
      if (idx !== -1) {
        body = body.slice(0, idx) + "\n" + bannerHtml + "\n" + body.slice(idx);
      } else {
        body = bannerHtml + "\n" + body;
      }
      injected = true;
      return Buffer.from(body, "utf8");
    }

    if (origWrite) {
      res.write = function (chunk, encoding, cb) {
        return origWrite(_maybeInject(chunk, encoding), encoding, cb);
      };
    }
    if (origEnd) {
      res.end = function (chunk, encoding, cb) {
        if (chunk) chunk = _maybeInject(chunk, encoding);
        return origEnd(chunk, encoding, cb);
      };
    }

    // For JSON responses, attach the disclosure to res.locals so
    // operator handlers building JSON via res.json(...) can include
    // it explicitly. We don't auto-merge into the JSON body — the
    // header + audit are the load-bearing disclosure surfaces.
    if (res.locals && typeof res.locals === "object") {
      res.locals.botDisclosure = bannerJson;
    }
    return next();
  };
}

module.exports = {
  create:               create,
  BotDiscloseError:     BotDiscloseError,
  DEFAULT_BANNER_HTML:  DEFAULT_BANNER_HTML,
};

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

var audit = lazyRequire(function () { return require("../audit"); });

var BotDiscloseError = defineClass("BotDiscloseError", { alwaysPermanent: true });

var DEFAULT_BANNER_HTML = '<div role="status" data-bot-disclosure="true" ' +
  'style="border:1px solid #888;padding:8px;margin:8px 0;background:#fff8e1;font-size:14px;">' +
  '<strong>Automated assistant.</strong> ' +
  'You are interacting with an automated agent. ' +
  'For California users: this disclosure is provided per Cal. Bus. &amp; Prof. Code §17941.' +
  '</div>';

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

  function _matches(req) {
    if (!mountPaths) return true;                                                        // null = match every path
    var p = req.url || "";
    var qpos = p.indexOf("?");
    if (qpos !== -1) p = p.slice(0, qpos);
    for (var i = 0; i < mountPaths.length; i++) {
      var m = mountPaths[i];
      if (typeof m === "string" && (p === m || p.indexOf(m + "/") === 0)) return true;
      if (m instanceof RegExp && m.test(p)) return true;
    }
    return false;
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
      // Inject after <body> opening tag if present, else after <html>
      // opening tag, else prepend.
      var bodyMatch = body.match(/<body[^>]*>/i);
      if (bodyMatch) {
        var idx = bodyMatch.index + bodyMatch[0].length;
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

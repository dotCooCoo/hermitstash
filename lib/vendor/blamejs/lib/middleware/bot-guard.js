"use strict";
/**
 * Bot-guard middleware — fingerprint-based detection of obviously-non-
 * browser requests. Cheap heuristics; not a substitute for proper
 * authentication, but catches drive-by scrapers and most low-effort bots.
 *
 * Heuristics (all combined):
 *   - Missing Accept-Language header (real browsers always send one)
 *   - Missing Sec-Fetch-Mode header (modern browsers send these on every
 *     navigation; absence is suspicious for HTML routes but not API)
 *   - User-Agent matches known automation libraries (curl, wget, python-
 *     requests, axios, Go-http-client) — operators can add or remove
 *     entries via config
 *
 * Options:
 *   {
 *     mode:            'block' | 'tag'          (default 'block')
 *     onlyForHtml:     true                     (skip checks for /api/*)
 *     allowedAgents:   ['<regex>', ...]         (allow-list overrides)
 *     blockedAgents:   ['<regex>', ...]         (extra deny-list)
 *     skipPaths:       ['/healthz', '/api/...'] (always skip)
 *     statusOnBlock:   403
 *     bodyOnBlock:     'Forbidden'
 *   }
 *
 * In 'tag' mode, suspected bots get req.suspectedBot = true and the
 * request continues — apps can rate-limit them differently.
 *
 * Audit: every block emits system.botguard.block with the matched
 * heuristic; every tag emits system.botguard.tag.
 */
var DEFAULT_BLOCKED_AGENTS = [
  /^curl\//i,
  /^wget\//i,
  /^python-requests\//i,
  /^python-urllib\//i,
  /^axios\//i,
  /^Go-http-client\//i,
  /^node-fetch\//i,
  /^okhttp\//i,
  /^java\//i,
  /^libwww-perl\//i,
  /^Ruby$/i,
  /^Apache-HttpClient\//i,
];

var lazyRequire = require("../lazy-require");
var requestHelpers = require("../request-helpers");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");
var audit = lazyRequire(function () { return require("../audit"); });

var BotGuardError = defineClass("BotGuardError", { alwaysPermanent: true });

// allowedAgents / blockedAgents are operator-supplied at create() time
// (NOT request bytes). The framework requires RegExp instances rather
// than strings — string-to-regex compilation from an operator-supplied
// value is an avoidable ReDoS vector at framework boot. Operators
// constructing patterns dynamically compile at their own call site so
// the pattern source is visible in their code.
function _coerceAgentPattern(r, where) {
  if (r instanceof RegExp) return r;
  throw new BotGuardError("bot-guard/bad-pattern",
    where + " must be a RegExp instance; got " + (typeof r) +
    " (compile the pattern at the call site so the source is visible " +
    "in operator code)");
}

// Bot-guard's "trust the proxy header" semantics for actor.ip — the
// audit event records the apparent source even when behind a CDN, but
// only when the operator opts in to trustProxy. Without the opt, we
// stick to socket.remoteAddress so an attacker-forged XFF can't
// pollute audit attribution.
function _xffIpFor(trustProxy) {
  return function (req) {
    return requestHelpers.clientIp(req, { trustProxy: trustProxy });
  };
}

/**
 * @primitive b.middleware.botGuard
 * @signature b.middleware.botGuard(req, res, next)
 * @since     0.1.0
 * @related   b.middleware.fetchMetadata, b.middleware.botDisclose
 *
 * Cheap fingerprint-based detection of obviously-non-browser requests.
 * Constructed via `b.middleware.botGuard(opts)`; the resulting
 * middleware has the `(req, res, next)` shape shown above.
 * Combines three heuristics: missing `Accept-Language`, missing
 * `Sec-Fetch-Mode` (HTML routes), and User-Agent regex match against
 * a default list (curl / wget / python-requests / axios / etc.). Not
 * a substitute for proper authentication — catches drive-by scrapers
 * and low-effort bots. In `mode: "block"` (default) the request is
 * refused; in `mode: "tag"` `req.suspectedBot = true` is set and the
 * request continues so the application can rate-limit suspected bots
 * separately. Every decision is audited.
 *
 * @opts
 *   {
 *     mode:          "block"|"tag",     // default "block"
 *     onlyForHtml:   boolean,           // default true
 *     allowedAgents: RegExp[],          // override matches
 *     blockedAgents: RegExp[],          // append to defaults
 *     skipPaths:     string[],
 *     statusOnBlock: number,            // default 403
 *     bodyOnBlock:   string,
 *     trustProxy:    boolean|number,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.botGuard({
 *     mode:        "tag",
 *     skipPaths:   ["/healthz"],
 *     onlyForHtml: true,
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "mode", "onlyForHtml", "allowedAgents", "blockedAgents",
    "skipPaths", "statusOnBlock", "bodyOnBlock", "trustProxy",
  ], "middleware.botGuard");
  var trustProxy = opts.trustProxy === true || typeof opts.trustProxy === "number"
    ? opts.trustProxy : false;
  var _xffIp = _xffIpFor(trustProxy);
  var mode = opts.mode || "block";
  var onlyForHtml = opts.onlyForHtml !== false;
  var allowedAgents = (opts.allowedAgents || []).map(function (r, i) {
    return _coerceAgentPattern(r, "middleware.botGuard: allowedAgents[" + i + "]");
  });
  var blockedAgents = DEFAULT_BLOCKED_AGENTS.concat((opts.blockedAgents || []).map(function (r, i) {
    return _coerceAgentPattern(r, "middleware.botGuard: blockedAgents[" + i + "]");
  }));
  var skipPaths = opts.skipPaths || [];
  var statusOnBlock = opts.statusOnBlock || 403;
  var bodyOnBlock = opts.bodyOnBlock !== undefined ? opts.bodyOnBlock : "Forbidden";

  function _shouldSkip(req) {
    var path = req.pathname || req.url || "/";
    for (var i = 0; i < skipPaths.length; i++) {
      if (typeof skipPaths[i] === "string" ? path.indexOf(skipPaths[i]) === 0 : skipPaths[i].test(path)) {
        return true;
      }
    }
    return false;
  }

  function _looksLikeApi(req) {
    var path = req.pathname || req.url || "/";
    return /^\/api\//.test(path);
  }

  function _checkHeuristics(req) {
    var headers = req.headers || {};
    var ua = headers["user-agent"] || "";
    // User-agent allow-list overrides everything
    for (var i = 0; i < allowedAgents.length; i++) {
      if (allowedAgents[i].test(ua)) return null;
    }
    for (var j = 0; j < blockedAgents.length; j++) {
      if (blockedAgents[j].test(ua)) return "blocked-agent";
    }
    if (onlyForHtml && _looksLikeApi(req)) {
      // Skip browser-fingerprint checks for API routes
      return null;
    }
    if (!headers["accept-language"]) return "missing-accept-language";
    if (req.method === "GET" && !headers["sec-fetch-mode"]) return "missing-sec-fetch-mode";
    return null;
  }

  return function botGuard(req, res, next) {
    if (_shouldSkip(req)) return next();
    var hit = _checkHeuristics(req);
    if (!hit) return next();

    if (mode === "tag") {
      req.suspectedBot = hit;
      try {
        audit().emit({
          actor:    requestHelpers.extractActorContext(req, { ip: _xffIp(req) }),
          action:   "system.botguard.tag",
          outcome:  "denied",
          reason:   hit,
          metadata: { method: req.method, path: req.pathname || req.url, requestId: req.requestId },
          requestId: req.requestId,
        });
      } catch (_e) { /* audit best-effort */ }
      return next();
    }

    try {
      audit().emit({
        actor:    requestHelpers.extractActorContext(req, { ip: _xffIp(req) }),
        action:   "system.botguard.block",
        outcome:  "denied",
        reason:   hit,
        metadata: { method: req.method, path: req.pathname || req.url, requestId: req.requestId },
        requestId: req.requestId,
      });
    } catch (_e) { /* audit best-effort */ }

    if (res.writableEnded) return;
    if (typeof res.writeHead === "function") {
      res.writeHead(statusOnBlock, { "Content-Type": "text/plain" });
      res.end(bodyOnBlock);
    }
    // Don't call next() — terminate the chain
  };
}

module.exports = {
  create:                 create,
  DEFAULT_BLOCKED_AGENTS: DEFAULT_BLOCKED_AGENTS,
};

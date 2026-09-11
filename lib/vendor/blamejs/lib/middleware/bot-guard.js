// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
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
var ssrfGuard = require("../ssrf-guard");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var { defineClass } = require("../framework-error");
var audit = lazyRequire(function () { return require("../audit"); });
var guardRegex = lazyRequire(function () { return require("../guard-regex"); });

var BotGuardError = defineClass("BotGuardError", { alwaysPermanent: true });

function _coerceAgentPattern(r, where) {
  if (r instanceof RegExp) {
    guardRegex().assertSafe(r, where, BotGuardError, "bot-guard/unsafe-pattern");
    return r;
  }
  throw new BotGuardError("bot-guard/bad-pattern",
    where + " must be a RegExp instance; got " + (typeof r) +
    " (compile the pattern at the call site so the source is visible " +
    "in operator code)");
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
 * One blocking heuristic — a User-Agent regex match against a default
 * list (curl / wget / python-requests / axios / etc.) — plus two
 * advisory signals that set `req.suspectedBot` in `mode: "tag"` and
 * NEVER block: a missing `Accept-Language` (absent from every major
 * search-engine crawler, so blocking on it makes a site unreachable to
 * them) and a missing `Sec-Fetch-Mode` on a secure-context HTML GET
 * (absent for Safari < 16.4 and every plain-HTTP non-localhost origin).
 * A header a whole client family omits is not evidence of automation.
 * Not
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
 *     onDeny:        function(req, res, info): void,  // own the block response; info = { status, reason }
 *     problemDetails: boolean,          // default false — emit RFC 9457 application/problem+json instead of text/plain
 *     trustedProxies: string|string[],  // CIDRs of your reverse proxies — peer-gates X-Forwarded-For / -Proto
 *     clientIpResolver: function(req): string|null,    // own the audit-actor IP
 *     protocolResolver: function(req): "http"|"https", // own the secure-context decision
 *     trustProxy:    boolean|number,    // legacy; refused unless paired with trustedProxies/resolver (spoofable)
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
    "skipPaths", "statusOnBlock", "bodyOnBlock", "onDeny", "problemDetails",
    "trustProxy", "trustedProxies", "clientIpResolver", "protocolResolver",
  ], "middleware.botGuard");
  var _ipResolver, _proto;
  try {
    _ipResolver = requestHelpers.trustedClientIp({ trustedProxies: opts.trustedProxies, clientIpResolver: opts.clientIpResolver });
    _proto      = requestHelpers.trustedProtocol({ trustedProxies: opts.trustedProxies, protocolResolver: opts.protocolResolver });
  } catch (e) { throw new BotGuardError("bot-guard/bad-opt", e.message); }
  if ((opts.trustProxy === true || typeof opts.trustProxy === "number") && !_ipResolver.peerGated) {
    throw new BotGuardError("bot-guard/bad-opt",
      "trustProxy is spoofable — a direct caller could forge X-Forwarded-For / -Proto. Declare " +
      "your reverse proxies via trustedProxies: [\"10.0.0.0/8\", …] or supply clientIpResolver / protocolResolver.");
  }
  var _xffIp = _ipResolver.resolve;
  var mode = opts.mode || "block";
  var onlyForHtml = opts.onlyForHtml !== false;
  var allowedAgents = (opts.allowedAgents || []).map(function (r, i) {
    return _coerceAgentPattern(r, "middleware.botGuard: allowedAgents[" + i + "]");
  });
  var blockedAgents = DEFAULT_BLOCKED_AGENTS.concat((opts.blockedAgents || []).map(function (r, i) {
    return _coerceAgentPattern(r, "middleware.botGuard: blockedAgents[" + i + "]");
  }));
  var statusOnBlock = opts.statusOnBlock || 403;
  var bodyOnBlock = opts.bodyOnBlock !== undefined ? opts.bodyOnBlock : "Forbidden";
  var onDeny = typeof opts.onDeny === "function" ? opts.onDeny : null;
  var problemMode = opts.problemDetails === true;

  var _shouldSkip = requestHelpers.makeSkipMatcher(opts, "middleware.botGuard");

  function _looksLikeApi(req) {
    var path = req.pathname || req.url || "/";
    return /^\/api\//.test(path);
  }

  function _isSecureContext(req) {
    if (_proto.resolve(req) === "https") return true;
    var host = requestHelpers.requestHost(req) || "";
    host = String(host).toLowerCase().replace(/:\d+$/, "");
    return ssrfGuard.isLoopbackHost(host);
  }

  function _checkHeuristics(req) {
    var headers = req.headers || {};
    var ua = headers["user-agent"] || "";
    for (var i = 0; i < allowedAgents.length; i++) {
      if (allowedAgents[i].test(ua)) return null;
    }
    for (var j = 0; j < blockedAgents.length; j++) {
      if (blockedAgents[j].test(ua)) return "blocked-agent";
    }
    if (onlyForHtml && _looksLikeApi(req)) {
      return null;
    }
    if (mode === "tag" && !headers["accept-language"]) return "missing-accept-language";
    if (mode === "tag" && req.method === "GET" && _isSecureContext(req) && !headers["sec-fetch-mode"]) return "missing-sec-fetch-mode";
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
    denyResponse(req, res, {
      onDeny:        onDeny,
      problem:       problemMode,
      status:        statusOnBlock,
      info:          { status: statusOnBlock, reason: hit },
      problemCode:   "bot-blocked",
      problemTitle:  "Forbidden",
      problemDetail: "The request was identified as automated traffic and refused.",
      contentType:   "text/plain",
      body:          bodyOnBlock,
    });
  };
}

module.exports = {
  create:                 create,
  DEFAULT_BLOCKED_AGENTS: DEFAULT_BLOCKED_AGENTS,
};

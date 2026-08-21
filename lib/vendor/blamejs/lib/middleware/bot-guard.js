// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Bot-guard middleware — fingerprint-based detection of obviously-non-
 * browser requests. Cheap heuristics; not a substitute for proper
 * authentication, but catches drive-by scrapers and most low-effort bots.
 *
 * Heuristics (all combined):
 *   - Missing Accept-Language header — ADVISORY ONLY (never blocks). Tagged
 *     in mode:"tag". It cannot block because the header is absent for entire
 *     client families: every major search-engine crawler omits it (Google
 *     documents that Googlebot "sends HTTP requests without setting
 *     Accept-Language"), as do uptime monitors, link previewers and feed
 *     readers — a 403 on it alone made a site's every page unreachable to
 *     Googlebot while a browser sailed through.
 *   - Missing Sec-Fetch-Mode header — ADVISORY ONLY (never blocks). Tagged
 *     in mode:"tag" on secure-context HTML GETs where a modern browser
 *     would have sent it. It cannot block because the header is absent for
 *     entire browser families (Safari < 16.4) and for every plain-HTTP
 *     non-localhost origin (Umbrel, LAN / *.local proxies) — a 403 on it
 *     alone would refuse real users.
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
var ssrfGuard = require("../ssrf-guard");
var validateOpts = require("../validate-opts");
var denyResponse = require("./deny-response").denyResponse;
var { defineClass } = require("../framework-error");
var audit = lazyRequire(function () { return require("../audit"); });
var guardRegex = lazyRequire(function () { return require("../guard-regex"); });

var BotGuardError = defineClass("BotGuardError", { alwaysPermanent: true });

// allowedAgents / blockedAgents are operator-supplied at create() time
// (NOT request bytes). The framework requires RegExp instances rather
// than strings — string-to-regex compilation from an operator-supplied
// value is an avoidable ReDoS vector at framework boot. Operators
// constructing patterns dynamically compile at their own call site so
// the pattern source is visible in their code.
function _coerceAgentPattern(r, where) {
  if (r instanceof RegExp) {
    // Screen the operator's pattern for catastrophic-backtracking (ReDoS)
    // shapes ONCE at create()-time — it is later .test()'d against the
    // attacker-controlled User-Agent on every request.
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
  // The single trustProxy opt drives two forwarded-header reads: the audit
  // actor.ip (X-Forwarded-For) and the secure-context check (X-Forwarded-Proto,
  // see _isSecureContext). Both are peer-gated — declare your reverse proxies
  // via trustedProxies (CIDRs), or own resolution via clientIpResolver /
  // protocolResolver. A bare trustProxy is refused: it would trust forgeable
  // headers from any caller.
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

  // Path-exemption predicate (string-prefix or RegExp), validated at create().
  var _shouldSkip = requestHelpers.makeSkipMatcher(opts, "middleware.botGuard");

  function _looksLikeApi(req) {
    var path = req.pathname || req.url || "/";
    return /^\/api\//.test(path);
  }

  // Browsers only emit Fetch Metadata (Sec-Fetch-*) in a *secure context*
  // (W3C Secure Contexts): an HTTPS origin, or a localhost-family origin
  // even over plain HTTP. On a plain-HTTP non-localhost origin — an Umbrel
  // app, a LAN / *.local reverse-proxy deployment — the browser omits
  // Sec-Fetch-* entirely, so a missing Sec-Fetch-Mode is NORMAL there and
  // must not be read as a bot signal. The effective scheme honours
  // X-Forwarded-Proto only from a trusted proxy peer (peer-gated), else the
  // real TLS socket — a direct caller's forged header is ignored.
  function _isSecureContext(req) {
    if (_proto.resolve(req) === "https") return true;
    var host = (req.headers && req.headers.host) || "";
    host = String(host).toLowerCase().replace(/:\d+$/, "");   // strip :port
    // Loopback HTTP is a secure context (can't be reached off-box). Compose the
    // canonical hostname-aware classifier — 127/8, ::1 / [::1], localhost, and
    // *.localhost (RFC 6761 §6.3) — instead of re-rolling the triad here.
    return ssrfGuard.isLoopbackHost(host);
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
    // Missing Accept-Language NEVER blocks, for the reason the Sec-Fetch-Mode
    // check below does not either: the header is absent for entire CLIENT
    // families, so a 403 on it alone refuses them wholesale. Every major
    // search-engine crawler omits it — Google documents that Googlebot "sends
    // HTTP requests without setting Accept-Language in the request header",
    // and bingbot behaves the same — so blocking on it made every content page
    // of a blamejs site answer 403 to a crawler while a browser sailed
    // through. Measured on a live deployment: a 337-URL sitemap of which only
    // the cached homepage was reachable. Uptime monitors, link previewers and
    // feed readers are refused the same way.
    //
    // It survives as an advisory TAG, so an operator can still rate-limit or
    // log on it. Automation libraries remain blocked by the User-Agent
    // deny-list, which is what actually distinguishes them; separating a
    // crawler from an abuser is a rate-limiting question, not a header one.
    if (mode === "tag" && !headers["accept-language"]) return "missing-accept-language";
    // Missing Sec-Fetch-Mode NEVER blocks: the header is absent for entire
    // browser families (Safari < 16.4 omits Fetch Metadata even over HTTPS)
    // and for every plain-HTTP non-localhost origin (Umbrel, LAN / *.local
    // reverse proxies), so a 403 on it alone refuses real users. It survives
    // only as an advisory TAG in mode:"tag", and even then only in a secure
    // context where a modern browser would have sent it. Drive-by bots are
    // still blocked by the User-Agent deny-list.
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
    // Don't call next() — terminate the chain
  };
}

module.exports = {
  create:                 create,
  DEFAULT_BLOCKED_AGENTS: DEFAULT_BLOCKED_AGENTS,
};

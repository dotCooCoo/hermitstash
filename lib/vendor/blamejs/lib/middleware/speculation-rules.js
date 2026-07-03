// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.middleware.speculationRules
 * @nav        HTTP
 * @title      Speculation Rules
 * @order      130
 * @card       W3C Speculation Rules emitter — declares which links the
 *             user-agent is allowed to prerender or prefetch ahead of
 *             user navigation. Default emit path is the
 *             `Speculation-Rules` response header pointing at a
 *             JSON-served rules document; an opt-in `inline: true`
 *             mode injects `<script type="speculationrules">` into
 *             text/html bodies.
 *
 * @intro
 *   Speculation Rules (W3C draft) are the modern replacement for
 *   `<link rel="prerender">` / `<link rel="prefetch">`. The browser
 *   reads a JSON document declaring patterns of links the operator
 *   wants speculatively loaded under varying eagerness levels
 *   (`immediate`, `eager`, `moderate`, `conservative`) and
 *   pre-fetches or pre-renders matching anchors as the user hovers /
 *   scrolls / dwells.
 *
 *   Two emit modes:
 *
 *   1. `Speculation-Rules` response header — points at a JSON
 *      document the operator serves elsewhere (typical for shared
 *      rules across many pages):
 *
 *        Speculation-Rules: "/rules/speculation.json"
 *
 *      The header form is the framework's default because it keeps
 *      HTML response bodies clean, lets the rules document be cached
 *      independently, and avoids touching response bodies (zero risk
 *      of body-parse / encoding mishaps).
 *
 *   2. Inline `<script type="speculationrules">` injection — for
 *      operators who want per-page rules, the framework can inject
 *      the JSON into `text/html` responses just before `</head>`
 *      (or, falling back, before the first `<body>` tag). Opt in
 *      with `{ inline: true }`.
 *
 *   Mount AFTER `securityHeaders` and (when used) `cspNonce`. When
 *   `inline: true` is set, an operator-supplied nonce on `req` (via
 *   `cspNonce`) is added to the injected `<script>` tag so a strict
 *   CSP allows the rules to load.
 *
 *     app.use(b.middleware.requestId());
 *     app.use(b.middleware.securityHeaders());
 *     app.use(b.middleware.cspNonce({ always: true }));
 *     app.use(b.middleware.speculationRules({
 *       rules: {
 *         prerender: [
 *           { where: { href_matches: "/articles/*" }, eagerness: "moderate" },
 *         ],
 *         prefetch: [
 *           { where: { href_matches: "/api/*" }, eagerness: "conservative" },
 *         ],
 *       },
 *     }));
 *
 *   Both mode shapes validate the rules object at construct time so
 *   typos surface at boot, never as a silently-ignored speculation
 *   rule three deploys later.
 */

var validateOpts = require("../validate-opts");
var safeBuffer = require("../safe-buffer");
var safeJson = require("../safe-json");

// Per W3C draft + Chromium implementation. `immediate` triggers the
// speculation as soon as the rules are seen; `conservative` waits
// for a strong intent signal (mousedown). The framework permits the
// full set; operators pick per-rule.
var EAGERNESS_LEVELS = {
  "immediate":    true,
  "eager":        true,
  "moderate":     true,
  "conservative": true,
};

// `prerender` fully renders the destination in a hidden tab —
// expensive, fast on activation. `prefetch` pulls bytes only — cheap,
// faster TTFB on activation. Both are arrays of rule objects.
var ACTION_KEYS = ["prerender", "prefetch"];

// Header value — when an operator passes a string instead of a rules
// object, treat it as the URL to a separately-served rules document
// (the simpler header-form path).
function _looksLikeRulesUrl(v) {
  return typeof v === "string" && v.length > 0;
}

// CR/LF/NUL screen — flows into the response header value, where
// header-injection would split into a forged second header.
var INJECTION_RE = /[\r\n\0]/;

function _refuseInjection(value, label) {
  if (typeof value !== "string") return;
  if (INJECTION_RE.test(value)) {  // allow:regex-no-length-cap — CR/LF/NUL injection check, length bounded by caller
    throw new TypeError(
      "middleware.speculationRules: " + label + " contains CR/LF/NUL — refused as a " +
      "header-injection vector");
  }
}

// Validate the operator-supplied rules object. Returns nothing on
// success; throws TypeError with an actionable message at config
// time. Each entry must be a plain object with `where` (object) and
// `eagerness` (one of EAGERNESS_LEVELS).
function _validateRules(rules, label) {
  if (!rules || typeof rules !== "object" || Array.isArray(rules)) {
    throw new TypeError(label + " must be an object with `prerender` and/or `prefetch` arrays");
  }
  var seenAny = false;
  for (var ki = 0; ki < ACTION_KEYS.length; ki += 1) {
    var actionKey = ACTION_KEYS[ki];
    var entries = rules[actionKey];
    if (entries === undefined) continue;
    if (!Array.isArray(entries)) {
      throw new TypeError(label + "." + actionKey + " must be an array of rule objects");
    }
    seenAny = true;
    for (var ei = 0; ei < entries.length; ei += 1) {
      var rule = entries[ei];
      if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
        throw new TypeError(label + "." + actionKey + "[" + ei + "] must be a plain object");
      }
      if (!rule.where || typeof rule.where !== "object" || Array.isArray(rule.where)) {
        throw new TypeError(label + "." + actionKey + "[" + ei +
          "].where must be a `where` clause object (W3C draft, e.g. { href_matches: \"/path/*\" })");
      }
      if (typeof rule.eagerness !== "string" || !Object.prototype.hasOwnProperty.call(EAGERNESS_LEVELS, rule.eagerness)) {
        throw new TypeError(label + "." + actionKey + "[" + ei +
          "].eagerness must be one of: " + Object.keys(EAGERNESS_LEVELS).join(", "));
      }
    }
  }
  if (!seenAny) {
    throw new TypeError(label + " must declare at least one of `prerender` or `prefetch`");
  }
}

/**
 * @primitive b.middleware.speculationRules
 * @signature b.middleware.speculationRules(req, res, next)
 * @since     0.8.53
 * @status    stable
 * @related   b.middleware.cspNonce, b.middleware.securityHeaders
 *
 * Builds middleware that emits W3C Speculation Rules so the user-agent
 * may prerender or prefetch matching links ahead of user navigation.
 * Two emit paths:
 *
 *   - Header form (default): emits `Speculation-Rules: "<url>"` where
 *     `<url>` points at an operator-served rules document.
 *   - Inline form (`inline: true`): injects a
 *     `<script type="speculationrules">{...}</script>` tag into
 *     `text/html` response bodies just before `</head>` (or fallback
 *     before `<body>`). When `cspNonce` middleware has populated
 *     `req.cspNonce`, the injected `<script>` carries that nonce so
 *     strict CSP allows it.
 *
 * The rules object is validated at construct time. Empty / malformed
 * rules throw with a message naming the offending key.
 *
 * @opts
 *   {
 *     rules:   object,    // { prerender: [...], prefetch: [...] }
 *     rulesUrl: string,   // header-mode URL (alternative to rules)
 *     inline:  boolean,   // default false; inject <script> instead of header
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.speculationRules({
 *     rules: {
 *       prerender: [
 *         { where: { href_matches: "/articles/*" }, eagerness: "moderate" },
 *       ],
 *       prefetch: [
 *         { where: { href_matches: "/api/*" }, eagerness: "conservative" },
 *       ],
 *     },
 *   }));
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["rules", "rulesUrl", "inline"], "middleware.speculationRules");

  var inline = !!opts.inline;
  var rulesUrl = opts.rulesUrl;
  var rulesObj = opts.rules;

  // Operators may pass `rules` as a string (URL form) for ergonomics —
  // route that to rulesUrl so the validation logic below stays
  // straightforward.
  if (_looksLikeRulesUrl(rulesObj) && rulesUrl === undefined) {
    rulesUrl = rulesObj;
    rulesObj = undefined;
  }

  if (inline) {
    if (!rulesObj) {
      throw new TypeError(
        "middleware.speculationRules: opts.rules is required when opts.inline is true " +
        "(inline mode injects the rules JSON into the response body)");
    }
    _validateRules(rulesObj, "middleware.speculationRules: opts.rules");
  } else {
    if (rulesObj && rulesUrl !== undefined) {
      throw new TypeError(
        "middleware.speculationRules: pass either opts.rules or opts.rulesUrl, not both");
    }
    if (!rulesObj && (typeof rulesUrl !== "string" || rulesUrl.length === 0)) {
      throw new TypeError(
        "middleware.speculationRules: header mode requires opts.rulesUrl (the URL of " +
        "an operator-served JSON rules document) or opts.rules (which the framework " +
        "renders inline). Pass `inline: true` if you want the framework to embed the " +
        "rules object as a <script type=\"speculationrules\"> tag.");
    }
    if (rulesObj) {
      _validateRules(rulesObj, "middleware.speculationRules: opts.rules");
    }
    if (rulesUrl !== undefined) {
      _refuseInjection(rulesUrl, "opts.rulesUrl");
    }
  }

  // Pre-build the emission payload once.
  // Header value per W3C draft + RFC 8941 (Structured Field Value
  // String — quoted, no internal CR/LF). When the operator supplied
  // `rules` directly in header mode, the framework serializes the
  // JSON as a data: URL so a single primitive can serve both shapes
  // without forcing the operator to wire a separate route.
  var headerValue;
  if (!inline) {
    if (rulesUrl) {
      headerValue = '"' + rulesUrl + '"';
    } else {
      var dataUrl = "data:application/speculationrules+json;base64," +
        Buffer.from(JSON.stringify(rulesObj), "utf8").toString("base64");
      headerValue = '"' + dataUrl + '"';
    }
  }

  // Pre-built inline JSON. The body is small (rules objects are
  // typically ~200 bytes); stringify once and cache. Uses the
  // <script>-safe serializer so a rules value containing "</script>"
  // (or U+2028/U+2029) cannot break out of the injected element.
  var inlineJson = inline ? safeJson.stringifyForScript(rulesObj) : null;

  return function speculationRules(req, res, next) {
    if (!inline) {
      if (typeof res.setHeader === "function") {
        res.setHeader("Speculation-Rules", headerValue);
      }
      return next();
    }

    // Inline mode — patch res.write / res.end so we inject the
    // <script> tag into the first text/html response. Same shape as
    // botDisclose / aiActDisclosure to stay consistent with the
    // framework's response-rewrite convention.
    var origWrite = res.write && res.write.bind(res);
    var origEnd = res.end && res.end.bind(res);
    var injected = false;

    function _scriptTag() {
      var nonceAttr = "";
      // Operator-supplied per-request nonce flows through cspNonce
      // middleware. If absent we still emit the script tag (works
      // under non-strict CSP); under strict CSP without nonce, the
      // browser refuses — visible to operators via cspReport.
      if (req && typeof req.cspNonce === "string" && req.cspNonce.length > 0) {
        nonceAttr = ' nonce="' + req.cspNonce + '"';
      }
      return '<script type="speculationrules"' + nonceAttr + '>' + inlineJson + '</script>';
    }

    function _maybeInject(chunk) {
      if (injected) return chunk;
      var ct = typeof res.getHeader === "function" ? res.getHeader("content-type") : "";
      if (typeof ct !== "string" || ct.indexOf("text/html") === -1) return chunk;
      var body = Buffer.isBuffer(chunk) ? chunk.toString("utf8") :
        (typeof chunk === "string" ? chunk : "");
      if (body.length === 0) return chunk;
      var tag = _scriptTag();
      var headClose = body.search(/<\/head\s*>/i);
      if (headClose !== -1) {
        body = body.slice(0, headClose) + tag + body.slice(headClose);
      } else {
        // Linear tag-find — NOT body.match(/<body[^>]*>/i) (O(n^2) in V8
        // on a body with many `<body` starts and no closing `>`).
        var bodyIdx = safeBuffer.indexAfterOpenTag(body, "body");
        if (bodyIdx !== -1) {
          body = body.slice(0, bodyIdx) + tag + body.slice(bodyIdx);
        } else {
          // No <head> or <body> — prepend so the rules at least
          // reach the parser. This matches the bot-disclose fallback.
          body = tag + body;
        }
      }
      injected = true;
      return Buffer.from(body, "utf8");
    }

    if (origWrite) {
      res.write = function (chunk, encoding, cb) {
        return origWrite(_maybeInject(chunk), encoding, cb);
      };
    }
    if (origEnd) {
      res.end = function (chunk, encoding, cb) {
        if (chunk) chunk = _maybeInject(chunk);
        return origEnd(chunk, encoding, cb);
      };
    }
    return next();
  };
}

module.exports = {
  create:           create,
  EAGERNESS_LEVELS: Object.keys(EAGERNESS_LEVELS),
  ACTION_KEYS:      ACTION_KEYS,
};

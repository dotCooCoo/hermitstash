"use strict";
/**
 * b.aiPref — IETF AIPREF Working Group Content-Usage HTTP response
 * header + robots.txt grammar + Cloudflare Content Signals Policy +
 * Pay-Per-Crawl (HTTP 402) coordination.
 *
 * IETF AIPREF (Authors / Information Providers' Preference for AI
 * Use) draft-ietf-aipref-attach-04 (deadline ⏰ 2026-08) defines a
 * machine-readable Content-Usage HTTP response header that signals
 * the operator's AI-training / AI-inference / AI-snippet preferences
 * to crawlers. Cloudflare's Content Signals Policy + Pay-Per-Crawl
 * (HTTP 402) is the de-facto baseline that Cloudflare adopted ahead
 * of the IETF spec finalizing.
 *
 * Public API:
 *
 *   b.aiPref.middleware(opts) -> middleware(req, res, next)
 *     opts:
 *       train:          "allow" | "deny" | "paid" — default "deny"
 *       infer:          "allow" | "deny" | "paid" — default "allow"
 *       snippet:        "allow" | "deny"          — default "allow"
 *       price:          { amountUsd, perTokens? } when any of
 *                       train/infer is "paid".
 *       cloudflareSignals: bool, default true — emit the Cloudflare
 *                       Content-Signals header alongside Content-Usage.
 *       robotsContext:  "default" | "<user-agent>" — emit
 *                       per-user-agent rules in robots.txt rather
 *                       than the catch-all default.
 *
 *   b.aiPref.robotsBlock(opts) -> string
 *     Returns a robots.txt block per AIPREF §3 grammar:
 *
 *       User-agent: GPTBot
 *       Content-Usage: train=deny, infer=allow, snippet=allow
 *
 *   b.aiPref.serializeHeader(opts) -> string
 *     Returns the Content-Usage HTTP response header value.
 *
 *   b.aiPref.parseHeader(value) -> { train, infer, snippet, price? }
 *     Parses an inbound Content-Usage header (used when the framework
 *     plays the role of crawler: respect declared preferences).
 *
 *   b.aiPref.refusePaidCrawl(req, res, opts)
 *     Convenience: emits HTTP 402 Payment Required with the price
 *     manifest in the Cloudflare-compatible JSON body.
 */

var audit = require("./audit");
var requestHelpers = require("./request-helpers");
var { defineClass } = require("./framework-error");
var AiPrefError = defineClass("AiPrefError", { alwaysPermanent: true });

var TRAIN_VALUES   = ["allow", "deny", "paid"];
var INFER_VALUES   = ["allow", "deny", "paid"];
var SNIPPET_VALUES = ["allow", "deny"];

function _validate(opts) {
  if (!opts || typeof opts !== "object") {
    throw AiPrefError.factory("BAD_OPTS",
      "aiPref: opts required");
  }
  var train   = opts.train   || "deny";
  var infer   = opts.infer   || "allow";
  var snippet = opts.snippet || "allow";
  if (TRAIN_VALUES.indexOf(train) === -1) {
    throw AiPrefError.factory("BAD_TRAIN", "aiPref: train must be one of " + TRAIN_VALUES.join(", "));
  }
  if (INFER_VALUES.indexOf(infer) === -1) {
    throw AiPrefError.factory("BAD_INFER", "aiPref: infer must be one of " + INFER_VALUES.join(", "));
  }
  if (SNIPPET_VALUES.indexOf(snippet) === -1) {
    throw AiPrefError.factory("BAD_SNIPPET", "aiPref: snippet must be one of " + SNIPPET_VALUES.join(", "));
  }
  if ((train === "paid" || infer === "paid") &&
      (!opts.price || typeof opts.price.amountUsd !== "number" ||
       !isFinite(opts.price.amountUsd) || opts.price.amountUsd <= 0)) {
    throw AiPrefError.factory("BAD_PRICE",
      "aiPref: price.amountUsd (positive finite number) required when train or infer is 'paid'");
  }
  return { train: train, infer: infer, snippet: snippet, price: opts.price || null };
}

function serializeHeader(opts) {
  var v = _validate(opts);
  // RFC 8941 structured-fields list of token=token pairs. AIPREF §4.2.
  var parts = [
    "train=" + v.train,
    "infer=" + v.infer,
    "snippet=" + v.snippet,
  ];
  if (v.price) {
    parts.push('price-usd=' + v.price.amountUsd.toFixed(6));
    if (typeof v.price.perTokens === "number" && isFinite(v.price.perTokens) && v.price.perTokens > 0) {
      parts.push("per-tokens=" + Math.floor(v.price.perTokens));
    }
  }
  return parts.join(", ");
}

function parseHeader(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw AiPrefError.factory("BAD_HEADER", "aiPref.parseHeader: value required");
  }
  if (value.length > 1024) {                                                                   // allow:raw-byte-literal — header value cap, not bytes
    throw AiPrefError.factory("HEADER_TOO_LARGE",
      "aiPref.parseHeader: value exceeds 1024 chars");
  }
  var out = { train: null, infer: null, snippet: null, price: null };
  var pairs = value.split(",");
  for (var i = 0; i < pairs.length; i += 1) {
    var p = pairs[i].trim();
    var eq = p.indexOf("=");
    if (eq === -1) continue;
    var k = p.slice(0, eq).trim().toLowerCase();
    var val = p.slice(eq + 1).trim();
    if (k === "train"      && TRAIN_VALUES.indexOf(val) !== -1)   out.train = val;
    else if (k === "infer"   && INFER_VALUES.indexOf(val) !== -1) out.infer = val;
    else if (k === "snippet" && SNIPPET_VALUES.indexOf(val) !== -1) out.snippet = val;
    else if (k === "price-usd") {
      var amt = parseFloat(val);
      if (isFinite(amt) && amt > 0) out.price = Object.assign({ amountUsd: amt }, out.price || {});
    } else if (k === "per-tokens") {
      var pt = parseInt(val, 10);
      if (isFinite(pt) && pt > 0) out.price = Object.assign({ perTokens: pt }, out.price || {});
    }
  }
  return out;
}

function robotsBlock(opts) {
  var v = _validate(opts);
  var ua = opts.userAgent || "*";
  if (typeof ua !== "string" || ua.length === 0 || ua.length > 256) {                          // allow:raw-byte-literal — UA-string cap, not bytes
    throw AiPrefError.factory("BAD_USER_AGENT",
      "aiPref.robotsBlock: userAgent must be 1-256 char string (or omit for *)");
  }
  return "User-agent: " + ua + "\n" +
         "Content-Usage: " + serializeHeader(v) + "\n";
}

function _cfSignalsHeader(v) {
  // Cloudflare Content Signals Policy emits a header named
  // `cf-content-signals` with a similar grammar. As of Cloudflare's
  // 2025-12 beta the canonical key names are: `ai-training`,
  // `ai-inference`, `ai-snippet`. Keep close to that vocabulary.
  var parts = [
    "ai-training=" + v.train,
    "ai-inference=" + v.infer,
    "ai-snippet=" + v.snippet,
  ];
  if (v.price) parts.push("price-usd=" + v.price.amountUsd.toFixed(6));
  return parts.join("; ");
}

function middleware(opts) {
  var v = _validate(opts);
  var emitCf = opts.cloudflareSignals !== false;
  var header = serializeHeader(v);
  var cfHeader = emitCf ? _cfSignalsHeader(v) : null;

  return function aiPrefMw(req, res, next) {
    if (typeof res.setHeader === "function") {
      res.setHeader("Content-Usage", header);
      if (cfHeader) res.setHeader("CF-Content-Signals", cfHeader);
    }
    if (typeof next === "function") next();
  };
}

function refusePaidCrawl(req, res, opts) {
  if (!opts || !opts.price || typeof opts.price.amountUsd !== "number") {
    throw AiPrefError.factory("BAD_PRICE",
      "aiPref.refusePaidCrawl: opts.price.amountUsd required");
  }
  var body = JSON.stringify({
    error:        "payment_required",
    pricingModel: "pay-per-crawl",
    price: {
      amountUsd: opts.price.amountUsd,
      perTokens: opts.price.perTokens || null,
    },
    contact: opts.contact || null,
  });
  if (typeof res.setHeader === "function") {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "no-store");
  }
  res.statusCode = 402;                                                                        // allow:raw-byte-literal — HTTP 402 Payment Required (RFC 9110)
  res.end(body);
  audit.safeEmit({
    action:   "aipref.paid_crawl_refused",
    outcome:  "denied",
    metadata: {
      ip:        requestHelpers.clientIp(req),
      userAgent: req && req.headers && req.headers["user-agent"],
      amountUsd: opts.price.amountUsd,
    },
  });
}

module.exports = {
  middleware:        middleware,
  serializeHeader:   serializeHeader,
  parseHeader:       parseHeader,
  robotsBlock:       robotsBlock,
  refusePaidCrawl:   refusePaidCrawl,
  TRAIN_VALUES:      TRAIN_VALUES.slice(),
  INFER_VALUES:      INFER_VALUES.slice(),
  SNIPPET_VALUES:    SNIPPET_VALUES.slice(),
  AiPrefError:       AiPrefError,
};

"use strict";
/**
 * @module b.aiPref
 * @nav    AI
 * @title  Ai Pref
 *
 * @intro
 *   AIPREF (RFC draft) signal — operators publish a machine-readable
 *   preference about AI training / agent crawling / etc.
 *
 *   Wires three coordinating surfaces into one primitive: the IETF
 *   AIPREF `Content-Usage` HTTP response header
 *   (draft-ietf-aipref-attach-04, deadline 2026-08), the matching
 *   robots.txt grammar, and Cloudflare's Content Signals Policy +
 *   Pay-Per-Crawl (HTTP 402). Operators declare train / infer /
 *   snippet preferences once; the middleware emits both the
 *   `Content-Usage` header and Cloudflare's `CF-Content-Signals`
 *   alongside.
 *
 *   Inbound parsing closes the loop when the framework plays the role
 *   of crawler — `parseHeader` decodes a peer's preferences so the
 *   caller can refuse training / pay the per-crawl price / respect a
 *   snippet=deny.
 *
 * @card
 *   AIPREF (RFC draft) signal — operators publish a machine-readable preference about AI training / agent crawling / etc.
 */

var audit            = require("./audit");
var requestHelpers   = require("./request-helpers");
var structuredFields = require("./structured-fields");
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

/**
 * @primitive b.aiPref.serializeHeader
 * @signature b.aiPref.serializeHeader(opts)
 * @since     0.8.44
 * @related   b.aiPref.middleware, b.aiPref.parseHeader, b.aiPref.robotsBlock
 *
 * Render the AIPREF `Content-Usage` HTTP response header value from
 * an operator preference object. Output is an RFC 8941 structured-
 * fields list of `train=...`, `infer=...`, `snippet=...` pairs, plus
 * `price-usd` / `per-tokens` when any axis is `paid`. Throws when the
 * preferences are inconsistent (e.g. `train=paid` with no price).
 *
 * @opts
 *   train:    "allow" | "deny" | "paid",   // default "deny"
 *   infer:    "allow" | "deny" | "paid",   // default "allow"
 *   snippet:  "allow" | "deny",            // default "allow"
 *   price:    { amountUsd: number, perTokens?: number },
 *
 * @example
 *   var v = b.aiPref.serializeHeader({
 *     train:   "deny",
 *     infer:   "allow",
 *     snippet: "allow",
 *   });
 *   // → "train=deny, infer=allow, snippet=allow"
 *
 *   var paid = b.aiPref.serializeHeader({
 *     train: "paid", infer: "paid", snippet: "allow",
 *     price: { amountUsd: 0.001, perTokens: 1000 },
 *   });
 *   // → "train=paid, infer=paid, snippet=allow, price-usd=0.001000, per-tokens=1000"
 */
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

/**
 * @primitive b.aiPref.parseHeader
 * @signature b.aiPref.parseHeader(value)
 * @since     0.8.44
 * @related   b.aiPref.serializeHeader, b.aiPref.middleware
 *
 * Parse an inbound `Content-Usage` header value into the typed
 * preference shape. Used when the framework acts as a crawler and
 * must respect a publisher's declared preferences. Unknown axes are
 * dropped silently so a forward-compatible publisher can advertise
 * future fields without breaking older clients. Throws when the
 * value is missing or exceeds the 1024-char defensive cap.
 *
 * @example
 *   var p = b.aiPref.parseHeader(
 *     "train=deny, infer=allow, snippet=allow"
 *   );
 *   p.train;     // → "deny"
 *   p.infer;     // → "allow"
 *   p.snippet;   // → "allow"
 *
 *   var paid = b.aiPref.parseHeader(
 *     "train=paid, infer=allow, snippet=allow, price-usd=0.001000, per-tokens=1000"
 *   );
 *   paid.price.amountUsd;   // → 0.001
 *   paid.price.perTokens;   // → 1000
 */
function parseHeader(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw AiPrefError.factory("BAD_HEADER", "aiPref.parseHeader: value required");
  }
  if (value.length > 1024) {                                                                   // allow:raw-byte-literal — header value cap, not bytes
    throw AiPrefError.factory("HEADER_TOO_LARGE",
      "aiPref.parseHeader: value exceeds 1024 chars");
  }
  structuredFields.refuseControlBytes(value, {
    ErrorClass: AiPrefError,
    code:       "BAD_HEADER",
    label:      "aiPref.parseHeader",
  });
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

/**
 * @primitive b.aiPref.robotsBlock
 * @signature b.aiPref.robotsBlock(opts)
 * @since     0.8.44
 * @related   b.aiPref.serializeHeader, b.aiPref.middleware
 *
 * Render an AIPREF §3 robots.txt block: a `User-agent:` line followed
 * by a `Content-Usage:` line carrying the same grammar as the HTTP
 * header. Authors who serve robots.txt as a static file paste the
 * output verbatim. The `userAgent` opt defaults to the catch-all `*`;
 * pass `"GPTBot"` / `"ClaudeBot"` / etc. for per-crawler rules. UA
 * strings are capped at 256 chars.
 *
 * @opts
 *   train:     "allow" | "deny" | "paid",
 *   infer:     "allow" | "deny" | "paid",
 *   snippet:   "allow" | "deny",
 *   price:     { amountUsd: number, perTokens?: number },
 *   userAgent: string,                     // default "*"
 *
 * @example
 *   var block = b.aiPref.robotsBlock({
 *     userAgent: "GPTBot",
 *     train:     "deny",
 *     infer:     "allow",
 *     snippet:   "allow",
 *   });
 *   // → "User-agent: GPTBot\nContent-Usage: train=deny, infer=allow, snippet=allow\n"
 */
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

/**
 * @primitive b.aiPref.middleware
 * @signature b.aiPref.middleware(opts)
 * @since     0.8.44
 * @related   b.aiPref.serializeHeader, b.aiPref.refusePaidCrawl, b.aiPref.robotsBlock
 *
 * Build an HTTP middleware that emits `Content-Usage` (and, by
 * default, the Cloudflare `CF-Content-Signals` mirror) on every
 * response. Wires the operator's AI-training / inference / snippet
 * preferences into the request lifecycle so every page advertises
 * the same posture without per-route plumbing.
 *
 * @opts
 *   train:             "allow" | "deny" | "paid",
 *   infer:             "allow" | "deny" | "paid",
 *   snippet:           "allow" | "deny",
 *   price:             { amountUsd: number, perTokens?: number },
 *   cloudflareSignals: boolean,            // default true
 *
 * @example
 *   var aiPrefMw = b.aiPref.middleware({
 *     train:   "deny",
 *     infer:   "allow",
 *     snippet: "allow",
 *   });
 *   // mount aiPrefMw on every public route — emits Content-Usage +
 *   // CF-Content-Signals headers on each response.
 */
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

/**
 * @primitive b.aiPref.refusePaidCrawl
 * @signature b.aiPref.refusePaidCrawl(req, res, opts)
 * @since     0.8.44
 * @related   b.aiPref.middleware, b.aiPref.serializeHeader
 *
 * Emit HTTP 402 Payment Required with the price manifest in the
 * Cloudflare-compatible JSON body. Operator route handlers detect
 * an unmonetized AI crawler (via UA / signed-token absence / etc.)
 * and call this helper to surface the price + contact channel
 * uniformly. Audits the refusal under
 * `aipref.paid_crawl_refused`.
 *
 * @opts
 *   price:    { amountUsd: number, perTokens?: number },
 *   contact:  string,                      // optional pricing contact
 *
 * @example
 *   function handler(req, res) {
 *     b.aiPref.refusePaidCrawl(req, res, {
 *       price:   { amountUsd: 0.005, perTokens: 1000 },
 *       contact: "https://example.test/ai-licensing",
 *     });
 *   }
 *   // → res.statusCode === 402; body is JSON { error: "payment_required", ... }
 */
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

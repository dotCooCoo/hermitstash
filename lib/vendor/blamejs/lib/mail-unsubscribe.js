"use strict";
/**
 * mail-unsubscribe — RFC 8058 / RFC 2369 List-Unsubscribe support.
 *
 * Two pieces:
 *   1. buildHeaders({ url, mailto, oneClick }) — produces the
 *      `List-Unsubscribe` and (when oneClick) `List-Unsubscribe-Post`
 *      header values that get merged into the outbound message.
 *   2. handler({ onUnsubscribe }) — request-lifecycle middleware that
 *      validates the RFC 8058 one-click POST body
 *      (`List-Unsubscribe=One-Click`) and dispatches to the operator's
 *      onUnsubscribe callback. Returns 200 OK with empty body on
 *      success per RFC 8058 §3.1.
 *
 * Compliance context: Gmail + Yahoo bulk-sender requirements (Feb 2024)
 * mandate one-click List-Unsubscribe for senders >= 5k/day. Microsoft
 * 365 followed in 2025. Operators sending bulk transactional or
 * marketing mail without these headers see escalating spam-folder /
 * outright-reject rates.
 *
 *   var headers = b.mail.unsubscribe.buildHeaders({
 *     url:      "https://example.com/u?token=...",
 *     mailto:   "unsubscribe@example.com?subject=unsub-...",
 *     oneClick: true,
 *   });
 *   // → {
 *   //     "List-Unsubscribe": "<https://...>, <mailto:...>",
 *   //     "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
 *   //   }
 *
 *   var unsubMw = b.mail.unsubscribe.handler({
 *     onUnsubscribe: async function (req, res) {
 *       // Operator extracts the token from req.url / req.body and
 *       // performs the unsubscribe. Returning resolves the request.
 *       var token = new URL(req.url, "https://h").searchParams.get("token");
 *       await db.markUnsubscribed(token);
 *     },
 *   });
 *   app.post("/email/unsubscribe", unsubMw);
 */

var lazyRequire = require("./lazy-require");
var safeUrl = require("./safe-url");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

// Build the List-Unsubscribe + List-Unsubscribe-Post headers per
// RFC 8058 + RFC 2369. Returns a headers object suitable for merging
// into `b.mail.send({ headers })`.
function buildHeaders(opts) {
  if (!opts || typeof opts !== "object") {
    throw new Error("buildHeaders: opts object required " +
      "({ url?, mailto?, oneClick? })");
  }
  var parts = [];
  if (typeof opts.url === "string" && opts.url.length > 0) {
    // Validate URL — refuse non-https / non-http schemes.
    var parsed = safeUrl.parse(opts.url, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
    if (!parsed) {
      throw new Error("buildHeaders: opts.url must be a valid http(s) URL");
    }
    parts.push("<" + parsed.href + ">");
  }
  if (typeof opts.mailto === "string" && opts.mailto.length > 0) {
    // mailto: is `mailto:addr` or `mailto:addr?subject=...&body=...`.
    // Don't run safeUrl on it (mailto isn't in ALLOW_HTTP_TLS); just
    // do a minimal shape check.
    if (opts.mailto.indexOf("mailto:") === 0) {
      parts.push("<" + opts.mailto + ">");
    } else {
      parts.push("<mailto:" + opts.mailto + ">");
    }
  }
  if (parts.length === 0) {
    throw new Error("buildHeaders: at least one of opts.url / opts.mailto required");
  }
  var headers = { "List-Unsubscribe": parts.join(", ") };
  if (opts.oneClick === true) {
    // RFC 8058 §2 — exact byte sequence required for one-click.
    headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click";
  }
  return headers;
}

// RFC 8058 §3.1 one-click handler middleware.
//
// On POST, the body MUST contain `List-Unsubscribe=One-Click` (case-
// sensitive, exact byte sequence). On match, the operator's
// onUnsubscribe callback runs — the operator extracts the
// per-recipient token from the URL or body and performs the
// unsubscribe. Returning resolves the request with 200 OK.
//
// On non-POST or wrong body, the middleware refuses with 400.
function handler(opts) {
  opts = opts || {};
  if (typeof opts.onUnsubscribe !== "function") {
    throw new Error("mail.unsubscribe.handler: opts.onUnsubscribe " +
      "must be a function (req, res) → Promise");
  }
  return async function unsubscribeMiddleware(req, res) {
    if ((req.method || "").toUpperCase() !== "POST") {
      res.statusCode = 405;
      res.setHeader("Allow", "POST");
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("RFC 8058 one-click unsubscribe requires POST");
      return;
    }
    var bodyChunks = [];
    var totalLen = 0;
    var maxBodyBytes = opts.maxBodyBytes || 4096;                                // allow:raw-byte-literal — RFC 8058 §3.1 body is short — `List-Unsubscribe=One-Click` plus operator additions
    var bodyComplete = await new Promise(function (resolve) {
      req.on("data", function (chunk) {
        totalLen += chunk.length;
        if (totalLen > maxBodyBytes) {
          // Stop reading; we'll respond 413 below.
          resolve(false);
          return;
        }
        bodyChunks.push(chunk);
      });
      req.on("end", function () { resolve(true); });
      req.on("error", function () { resolve(false); });
    });
    if (!bodyComplete) {
      res.statusCode = 413;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("body exceeds max bytes for one-click unsubscribe");
      return;
    }
    var body = Buffer.concat(bodyChunks).toString("utf8");
    if (body.indexOf("List-Unsubscribe=One-Click") === -1) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("RFC 8058 §3.1: body must contain `List-Unsubscribe=One-Click`");
      return;
    }
    try {
      await opts.onUnsubscribe(req, res);
      // If the operator didn't end the response, send 200 OK with
      // empty body per RFC 8058 §3.1.
      if (!res.writableEnded) {
        res.statusCode = 200;
        res.end();
      }
    } catch (err) {
      if (!res.writableEnded) {
        res.statusCode = 500;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("unsubscribe failed");
      }
      throw err;
    }
  };
}

module.exports = {
  buildHeaders: buildHeaders,
  handler:      handler,
};

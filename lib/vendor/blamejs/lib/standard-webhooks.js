"use strict";
/**
 * @module b.standardWebhooks
 * @nav    HTTP
 * @title  Standard Webhooks
 * @order  235
 *
 * @intro
 *   StandardWebhooks (standardwebhooks.com) signing + verification —
 *   the consortium spec (Stripe / Svix / Okta / etc.) for inbound
 *   webhook authentication. Three headers:
 *
 *     webhook-id        ULID-ish unique identifier
 *     webhook-timestamp Unix seconds at send time
 *     webhook-signature `v1,<base64-of-HMAC-SHA256-result>` (multi-version)
 *
 *   The signature payload is `<id>.<timestamp>.<body>`, signed with the
 *   shared secret. Verification reproduces the signature and uses
 *   `b.crypto.timingSafeEqual` to compare. Skew tolerated within
 *   `tolerance` seconds (default 5 minutes).
 *
 * @card
 *   StandardWebhooks (standardwebhooks.com) HMAC-SHA256 sign + verify for inbound + outbound webhook delivery. 5-minute skew tolerance + version-prefix header.
 */

var nodeCrypto = require("node:crypto");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var bCrypto    = require("./crypto");
var C          = require("./constants");
var { defineClass } = require("./framework-error");

var StandardWebhooksError = defineClass("StandardWebhooksError", { alwaysPermanent: true });

var DEFAULT_TOLERANCE_SEC = 300;

/**
 * @primitive b.standardWebhooks.sign
 * @signature b.standardWebhooks.sign(opts)
 * @since     0.10.16
 * @status    stable
 *
 * Build the three StandardWebhooks headers for an outbound delivery.
 * Returns `{ headers, body }` where `body` is the raw request body
 * (operators write that to the wire; the headers go on the request).
 *
 * @opts
 *   id:        string,         // auto-minted if omitted (32-byte random)
 *   timestamp: number,         // Unix seconds; defaults to now
 *   body:      Buffer|string,  // request body bytes
 *   secret:    Buffer,         // shared secret (>= 32 bytes)
 *
 * @example
 *   var s = b.standardWebhooks.sign({ body: bodyBuf, secret: secret });
 *   for (var k in s.headers) req.setHeader(k, s.headers[k]);
 */
function sign(opts) {
  opts = validateOpts.requireObject(opts, "standardWebhooks.sign",
    StandardWebhooksError, "standard-webhooks/bad-opts");
  validateOpts(opts, ["id", "timestamp", "body", "secret"], "standardWebhooks.sign");
  if (!Buffer.isBuffer(opts.secret) || opts.secret.length < 32) {                                     // 32-byte HMAC secret floor
    throw new StandardWebhooksError("standard-webhooks/bad-secret",
      "sign: opts.secret must be a Buffer (>= 32 bytes)");
  }
  if (!opts.body || (!Buffer.isBuffer(opts.body) && typeof opts.body !== "string")) {
    throw new StandardWebhooksError("standard-webhooks/bad-body",
      "sign: opts.body must be a non-empty Buffer or string");
  }
  var bodyBuf = Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(opts.body, "utf8");
  var id = opts.id || ("msg_" + bCrypto.generateToken(32));                                           // 32-char id token
  var timestamp = typeof opts.timestamp === "number"
    ? opts.timestamp
    : Math.floor(Date.now() / 1000);
  if (timestamp <= 0 || !isFinite(timestamp)) {
    throw new StandardWebhooksError("standard-webhooks/bad-timestamp",
      "sign: timestamp must be a positive finite integer");
  }
  var toSign = id + "." + timestamp + "." + bodyBuf.toString("utf8");
  var sigB64 = nodeCrypto.createHmac("sha256", opts.secret).update(toSign).digest("base64");
  return {
    headers: {
      "webhook-id":        id,
      "webhook-timestamp": String(timestamp),
      "webhook-signature": "v1," + sigB64,
    },
    body: bodyBuf,
  };
}

/**
 * @primitive b.standardWebhooks.verify
 * @signature b.standardWebhooks.verify(opts)
 * @since     0.10.16
 * @status    stable
 *
 * Verify an inbound webhook against the StandardWebhooks spec.
 * Refuses on missing headers, timestamp skew > tolerance, or
 * HMAC mismatch. Returns `{ valid, id, timestamp }`.
 *
 * @opts
 *   headers:    object,           // request headers
 *   body:       Buffer|string,    // raw request body
 *   secret:     Buffer,           // shared secret
 *   toleranceSec: number,         // default 300s (5 minutes)
 *
 * @example
 *   var v = b.standardWebhooks.verify({
 *     headers: req.headers, body: rawBody, secret: secret,
 *   });
 *   if (!v.valid) throw 401;
 */
function verify(opts) {
  opts = validateOpts.requireObject(opts, "standardWebhooks.verify",
    StandardWebhooksError, "standard-webhooks/bad-opts");
  validateOpts(opts, ["headers", "body", "secret", "toleranceSec"],
    "standardWebhooks.verify");
  if (!opts.headers || typeof opts.headers !== "object") {
    throw new StandardWebhooksError("standard-webhooks/bad-headers",
      "verify: opts.headers required");
  }
  if (!Buffer.isBuffer(opts.secret) || opts.secret.length < 32) {                                     // 32-byte HMAC secret floor
    throw new StandardWebhooksError("standard-webhooks/bad-secret",
      "verify: opts.secret must be a Buffer (>= 32 bytes)");
  }
  var bodyBuf = Buffer.isBuffer(opts.body) ? opts.body
              : typeof opts.body === "string" ? Buffer.from(opts.body, "utf8")
              : null;
  if (!bodyBuf) {
    throw new StandardWebhooksError("standard-webhooks/bad-body",
      "verify: opts.body must be a Buffer or string");
  }
  // Normalise header names — case-insensitive.
  var lower = {};
  var keys = Object.keys(opts.headers);
  for (var i = 0; i < keys.length; i += 1) lower[keys[i].toLowerCase()] = opts.headers[keys[i]];
  var id = lower["webhook-id"];
  var tsStr = lower["webhook-timestamp"];
  var sigHeader = lower["webhook-signature"];
  if (!id || !tsStr || !sigHeader) {
    throw new StandardWebhooksError("standard-webhooks/missing-headers",
      "verify: webhook-id / webhook-timestamp / webhook-signature required");
  }
  var ts = parseInt(tsStr, 10);
  if (!isFinite(ts) || ts <= 0) {
    throw new StandardWebhooksError("standard-webhooks/bad-timestamp",
      "verify: webhook-timestamp is not a positive integer");
  }
  numericBounds.requirePositiveFiniteIntIfPresent(opts.toleranceSec, "toleranceSec",
    StandardWebhooksError, "standard-webhooks/bad-tolerance");
  var tolerance = typeof opts.toleranceSec === "number" ? opts.toleranceSec : DEFAULT_TOLERANCE_SEC;
  var nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > tolerance) {
    throw new StandardWebhooksError("standard-webhooks/timestamp-skew",
      "verify: timestamp skew " + Math.abs(nowSec - ts) + "s exceeds tolerance " + tolerance + "s");
  }
  var toSign = id + "." + ts + "." + bodyBuf.toString("utf8");
  var expected = nodeCrypto.createHmac("sha256", opts.secret).update(toSign).digest("base64");
  // Multi-version: signature header is `v1,<sig> v2,<sig>` etc.
  var parts = sigHeader.split(" ");
  var any = false;
  for (var p = 0; p < parts.length; p += 1) {
    var pair = parts[p].split(",");
    if (pair.length !== 2) continue;
    if (pair[0] !== "v1") continue;
    if (bCrypto.timingSafeEqual(Buffer.from(expected, "utf8"), Buffer.from(pair[1], "utf8"))) {
      any = true;
      break;
    }
  }
  if (!any) {
    throw new StandardWebhooksError("standard-webhooks/bad-signature",
      "verify: no v1 signature matched");
  }
  void C;   // module loaded for future tolerance defaulting; not used directly today
  return { valid: true, id: id, timestamp: ts };
}

module.exports = {
  sign:                       sign,
  verify:                     verify,
  DEFAULT_TOLERANCE_SEC:      DEFAULT_TOLERANCE_SEC,
  StandardWebhooksError:      StandardWebhooksError,
};

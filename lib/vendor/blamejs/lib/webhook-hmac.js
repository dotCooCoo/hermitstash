// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.webhookHmac
 * @nav    HTTP
 * @title  HMAC Webhooks
 * @order  236
 *
 * @intro
 *   Inbound verification for the timestamped-HMAC webhook scheme — a single
 *   header carrying a Unix timestamp and one or more HMAC signatures:
 *
 *     &lt;sig-header&gt;: t=&lt;unix-seconds&gt;,v1=&lt;hmac-sha256-hex&gt;[,v1=&lt;rotated&gt;]
 *
 *   The signed payload is <code>&lt;timestamp&gt;.&lt;raw-body&gt;</code>, keyed on the
 *   endpoint signing secret. This is the scheme Stripe and Tailscale (among
 *   others) use. It is DISTINCT from the StandardWebhooks scheme that
 *   <code>b.standardWebhooks</code> verifies, which uses three separate headers
 *   and an <code>&lt;id&gt;.&lt;ts&gt;.&lt;body&gt;</code> payload.
 *
 *   Verification refuses a timestamp outside the tolerance window (replay
 *   defense), checks EVERY signature value under the version field (so a
 *   rotated secret verifies with no downtime), compares with
 *   <code>b.crypto.timingSafeEqual</code>, and ignores signature versions it
 *   does not understand. Always verify against the EXACT received bytes —
 *   never a re-serialized JSON body.
 *
 * @card
 *   Verify the Stripe-style <code>t=&lt;ts&gt;,v1=&lt;hmac&gt;</code> timestamped-HMAC webhook scheme (Stripe / Tailscale / …) — replay window, key-rotation multi-signature, constant-time compare.
 */

var bCrypto         = require("./crypto");
var safeBuffer      = require("./safe-buffer");
var numericBounds   = require("./numeric-bounds");
var validateOpts    = require("./validate-opts");
var { defineClass } = require("./framework-error");

var WebhookHmacError = defineClass("WebhookHmacError", { alwaysPermanent: true });

var DEFAULT_TOLERANCE_SEC = 300;          // 5 minutes — the Stripe/Tailscale default replay window
var DEFAULT_TS_FIELD      = "t";
var DEFAULT_SIG_FIELD     = "v1";
var DEFAULT_ALG           = "hmac-sha256";

// alg string → node HMAC name. SHA-2 only; SHA-1 is refused (collision-weak,
// and no webhook provider using this scheme needs it).
var ALG_MAP = {
  "hmac-sha256": "sha256",
  "hmac-sha512": "sha512",
};

// Named presets for providers using this exact single-header scheme. Explicit
// opts always override a profile.
var PROFILES = {
  stripe:    { tsField: "t", sigField: "v1", alg: "hmac-sha256" },
  tailscale: { tsField: "t", sigField: "v1", alg: "hmac-sha256" },
};

function _mkErr(code, message) { return new WebhookHmacError(code, message); }

function _requireNonEmptyString(val, name) {
  if (typeof val !== "string" || val.length === 0) {
    throw new WebhookHmacError("webhook-hmac/bad-" + name,
      "verify: opts." + name + " must be a non-empty string");
  }
  return val;
}

/**
 * @primitive b.webhookHmac.verify
 * @signature b.webhookHmac.verify(opts)
 * @since     0.18.8
 * @status    stable
 * @related   b.standardWebhooks.verify, b.crypto.hmac, b.crypto.timingSafeEqual
 *
 * Verify an inbound webhook signed with the timestamped-HMAC scheme
 * (<code>t=&lt;ts&gt;,v1=&lt;hmac&gt;</code>). Refuses on a missing/garbled header, a
 * timestamp outside the tolerance window (replay), or an HMAC mismatch;
 * returns <code>{ valid: true, timestamp }</code> when a signature matches.
 *
 * The signed payload is <code>&lt;timestamp&gt;.&lt;raw-body&gt;</code> — pass the EXACT
 * bytes received, not a parsed-then-re-serialized JSON body, or the HMAC will
 * not reproduce. Every value under the signature field is checked, so a
 * rotated secret (two <code>v1=</code> values) verifies without downtime.
 * Comparison is constant-time; unrecognized signature versions are ignored.
 *
 * @opts
 *   header:       string,          // the raw signature header value ("t=...,v1=...")
 *   rawBody:      Buffer | string, // the exact received body bytes
 *   secret:       Buffer | string, // the endpoint signing secret
 *   profile:      string,          // "stripe" | "tailscale" — sets tsField/sigField/alg
 *   tsField:      string,          // default: "t"
 *   sigField:     string,          // default: "v1"
 *   alg:          string,          // default: "hmac-sha256" (also "hmac-sha512")
 *   toleranceSec: number,          // default: 300 (5 minutes)
 *
 * @example
 *   var v = b.webhookHmac.verify({
 *     header:  req.headers["stripe-signature"],
 *     rawBody: rawBody,
 *     secret:  process.env.WHSEC,
 *   });
 *   // → { valid: true, timestamp: 1614556828 }
 */
function verify(opts) {
  opts = validateOpts.requireObject(opts, "webhookHmac.verify",
    WebhookHmacError, "webhook-hmac/bad-opts");
  validateOpts(opts,
    ["header", "rawBody", "secret", "profile", "tsField", "sigField", "alg", "toleranceSec"],
    "webhookHmac.verify");

  // Resolve profile → field/alg defaults; explicit opts win.
  var prof = {};
  if (opts.profile !== undefined) {
    if (typeof opts.profile !== "string" || !Object.prototype.hasOwnProperty.call(PROFILES, opts.profile)) {
      throw new WebhookHmacError("webhook-hmac/bad-profile",
        "verify: unknown profile '" + opts.profile + "' (known: " + Object.keys(PROFILES).join(", ") + ")");
    }
    prof = PROFILES[opts.profile];
  }
  var tsField  = opts.tsField  !== undefined ? opts.tsField  : (prof.tsField  || DEFAULT_TS_FIELD);
  var sigField = opts.sigField !== undefined ? opts.sigField : (prof.sigField || DEFAULT_SIG_FIELD);
  var algName  = opts.alg      !== undefined ? opts.alg      : (prof.alg      || DEFAULT_ALG);
  _requireNonEmptyString(tsField, "tsField");
  _requireNonEmptyString(sigField, "sigField");
  var nodeAlg = Object.prototype.hasOwnProperty.call(ALG_MAP, algName) ? ALG_MAP[algName] : null;
  if (!nodeAlg) {
    throw new WebhookHmacError("webhook-hmac/bad-alg",
      "verify: unsupported alg '" + String(algName) + "' (supported: " + Object.keys(ALG_MAP).join(", ") + ")");
  }

  _requireNonEmptyString(opts.header, "header");
  var bodyBuf = safeBuffer.toBuffer(opts.rawBody, { typeCode: "webhook-hmac/bad-body", errorFactory: _mkErr });
  var secretBuf = safeBuffer.toBuffer(opts.secret, { typeCode: "webhook-hmac/bad-secret", errorFactory: _mkErr });
  if (secretBuf.length === 0) {
    throw new WebhookHmacError("webhook-hmac/bad-secret", "verify: opts.secret must be non-empty");
  }

  numericBounds.requirePositiveFiniteIntIfPresent(opts.toleranceSec, "toleranceSec",
    WebhookHmacError, "webhook-hmac/bad-tolerance");
  var tolerance = typeof opts.toleranceSec === "number" ? opts.toleranceSec : DEFAULT_TOLERANCE_SEC;

  // Parse "t=<ts>,v1=<sig>,v1=<rotated>" — comma-separated k=v. Collect the ts
  // and EVERY sigField value; ignore any other version keys.
  var tsRaw = null;
  var sigs = [];
  var items = opts.header.split(",");
  for (var i = 0; i < items.length; i += 1) {
    var eq = items[i].indexOf("=");
    if (eq < 0) continue;
    var k = items[i].slice(0, eq).trim();
    var v = items[i].slice(eq + 1).trim();
    if (k === tsField) { if (tsRaw === null) tsRaw = v; }
    else if (k === sigField) { sigs.push(v); }
  }
  if (tsRaw === null) {
    throw new WebhookHmacError("webhook-hmac/missing-timestamp",
      "verify: no '" + tsField + "=' field in the signature header");
  }
  if (sigs.length === 0) {
    throw new WebhookHmacError("webhook-hmac/missing-signature",
      "verify: no '" + sigField + "=' field in the signature header");
  }

  // Strict-integer timestamp (reject "12.3", "0x1", leading zeros, whitespace).
  var ts = parseInt(tsRaw, 10);
  if (!isFinite(ts) || ts <= 0 || String(ts) !== tsRaw) {
    throw new WebhookHmacError("webhook-hmac/bad-timestamp",
      "verify: '" + tsField + "' is not a positive integer");
  }
  var nowSec = Math.floor(Date.now() / 1000);
  var skew = Math.abs(nowSec - ts);
  if (skew > tolerance) {
    throw new WebhookHmacError("webhook-hmac/timestamp-skew",
      "verify: timestamp skew " + skew + "s exceeds tolerance " + tolerance + "s (replay window)");
  }

  // Signed payload is the raw timestamp string + "." + the exact body bytes.
  var signed = Buffer.concat([Buffer.from(tsRaw + ".", "utf8"), bodyBuf]);
  var expected = bCrypto.hmac(secretBuf, signed, nodeAlg);
  var expectedBuf = Buffer.from(expected, "utf8");
  var matched = false;
  for (var s = 0; s < sigs.length; s += 1) {
    // timingSafeEqual requires equal-length inputs; a wrong-length candidate
    // cannot be the digest (the hex length is fixed by the algorithm, and is
    // not secret), so the length pre-check leaks nothing.
    if (sigs[s].length === expected.length &&
        bCrypto.timingSafeEqual(expectedBuf, Buffer.from(sigs[s], "utf8"))) {
      matched = true;
      break;
    }
  }
  if (!matched) {
    throw new WebhookHmacError("webhook-hmac/bad-signature",
      "verify: no '" + sigField + "' signature matched");
  }
  return { valid: true, timestamp: ts };
}

module.exports = {
  verify:                verify,
  PROFILES:              PROFILES,
  DEFAULT_TOLERANCE_SEC: DEFAULT_TOLERANCE_SEC,
  WebhookHmacError:      WebhookHmacError,
};

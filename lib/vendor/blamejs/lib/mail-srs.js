// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.srs
 * @nav        Mail
 * @title      SRS — Sender Rewriting Scheme
 * @order      450
 *
 * @intro
 *   Sender Rewriting Scheme (SRS0 / SRS1) — when a forwarder
 *   retransmits a message it received, SPF on the next hop will
 *   typically fail because the envelope-from sender is the original
 *   sender's domain, but the message is now coming from the
 *   forwarder's IP. SRS rewrites the envelope-from local-part to
 *   encode the original sender + a HMAC signature; the receiver
 *   verifies + reverses to deliver bounces correctly.
 *
 *   Wire format (SRS0):
 *
 *     SRS0=HHH=TT=domain=local@forwarder.example
 *
 *   Where:
 *     - `HHH` is the first 4 chars of base32(HMAC-SHA-256(secret,
 *       lowercase(TT=domain=local))) — short-tag binding the rewrite
 *       to the operator's signing secret
 *     - `TT` is a 2-character base32 day-of-time stamp (mod-1024
 *       day rotation; rejects rewrites older than ~30 days)
 *     - `domain` is the original sender's domain
 *     - `local` is the original sender's local-part
 *     - `forwarder.example` is the rewriting forwarder's domain
 *
 *   Wire format (SRS1 — the multi-hop chain case):
 *
 *     SRS1=HHH=priorForwarder==<SRS0-body>@thisForwarder
 *
 *   When an already-SRS0 (or SRS1) address is forwarded again,
 *   `srs1Rewrite(srsAddress)` wraps it: it keeps the original SRS0
 *   body verbatim, prepends the preceding forwarder's domain, and
 *   binds the pair with this forwarder's own HMAC tag — no new
 *   timestamp, no repeated original local-part. `reverse()` detects
 *   SRS1, verifies this hop's tag, and unwraps exactly one hop back to
 *   the prior forwarder's SRS0 address so the bounce re-routes to it.
 *
 *   `b.mail.srs.create({ secret, forwarderDomain })` returns
 *   `{ rewrite, srs1Rewrite, reverse }`. `rewrite(originalSender)`
 *   produces the SRS0 address; `srs1Rewrite(srsAddress)` chains a
 *   further hop as SRS1; `reverse(srsAddress)` decodes an SRS0 back to
 *   the original sender (verifying HMAC + expiry) or unwraps an SRS1
 *   one hop back to the prior forwarder.
 *
 * @card
 *   SRS Sender Rewriting Scheme — forwarder envelope-from rewriting with HMAC-bound day-rotated tags so the next-hop SPF check passes and bounces route correctly back to the original sender.
 */

var nodeCrypto    = require("node:crypto");
var C             = require("./constants");
var bCrypto = require("./crypto");
var safeBuffer    = require("./safe-buffer");
var validateOpts  = require("./validate-opts");
var { defineClass } = require("./framework-error");

var SrsError = defineClass("SrsError", { alwaysPermanent: true });

var BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

function _base32Encode(buf) {
  var out = "";
  var bits = 0;
  var value = 0;
  for (var i = 0; i < buf.length; i += 1) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      out += BASE32.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32.charAt((value << (5 - bits)) & 31);
  return out;
}

function _hashTag(secret, hashInput) {
  var mac = nodeCrypto.createHmac("sha256", secret).update(hashInput.toLowerCase(), "utf8").digest();
  return _base32Encode(mac.subarray(0, 4)).slice(0, 4);
}

function _dayStamp(nowMs) {
  var days = Math.floor(nowMs / C.TIME.days(1)) % 1024;
  return BASE32.charAt(days >>> 5) + BASE32.charAt(days & 31);
}

function _dayDiff(stamp, nowMs) {
  if (typeof stamp !== "string" || stamp.length !== 2) return Infinity;
  var hi = BASE32.indexOf(stamp.charAt(0));
  var lo = BASE32.indexOf(stamp.charAt(1));
  if (hi < 0 || lo < 0) return Infinity;
  var stampVal = (hi << 5) | lo;
  var nowVal = Math.floor(nowMs / C.TIME.days(1)) % 1024;
  var diff = (nowVal - stampVal + 1024) % 1024;
  return diff;
}

function _parseSrs1(localPart) {
  var rest = localPart.slice(5);
  var firstEq = rest.indexOf("=");
  if (firstEq <= 0) {
    throw new SrsError("srs/malformed",
      "srs.reverse: SRS1 must be SRS1=tag=priorForwarder==<srs0body>");
  }
  var tag = rest.slice(0, firstEq);
  var afterTag = rest.slice(firstEq + 1);
  var sep = afterTag.indexOf("==");
  if (sep <= 0) {
    throw new SrsError("srs/malformed",
      "srs.reverse: SRS1 missing the '==' prior-forwarder separator");
  }
  var srs0Body = afterTag.slice(sep + 2);
  if (!srs0Body) {
    throw new SrsError("srs/malformed",
      "srs.reverse: SRS1 carries an empty inner SRS0 body");
  }
  return { tag: tag, priorForwarder: afterTag.slice(0, sep), srs0Body: srs0Body };
}

/**
 * @primitive b.mail.srs.create
 * @signature b.mail.srs.create(opts)
 * @since     0.8.89
 * @status    stable
 *
 * Build an SRS rewriter bound to the operator's forwarder domain +
 * HMAC signing secret. Returns `{ rewrite, srs1Rewrite, reverse }` —
 * `rewrite` produces an SRS0 origin address, `srs1Rewrite` chains an
 * already-SRS0/SRS1 address as SRS1 for a further forwarding hop, and
 * `reverse` decodes either form (SRS0 → original sender with HMAC +
 * expiry checks; SRS1 → the prior forwarder's address, one hop back).
 *
 * @opts
 *   secret:           string,   // operator's HMAC-SHA-256 signing secret (>=32 bytes recommended)
 *   forwarderDomain:  string,   // the forwarder's own domain (where bounces land)
 *   expiryDays:       number,   // default 30 — reject reverse() of rewrites older than this
 *
 * @example
 *   var srs = b.mail.srs.create({
 *     secret:          b.crypto.generateToken(64),
 *     forwarderDomain: "forwarder.example",
 *   });
 *
 *   // Inbound: alice@bob.com → forwarder → carol@dest.com
 *   var rewritten = srs.rewrite("alice@bob.com");
 *   // → "SRS0=HHHH=TT=bob.com=alice@forwarder.example"
 *
 *   // Bounce arrives back at SRS0=...; decode to deliver
 *   var original = srs.reverse(rewritten);
 *   // → "alice@bob.com"
 *
 *   // A further forwarding hop chains the already-SRS0 address as SRS1
 *   var hop2 = srs.srs1Rewrite(rewritten);
 *   // → "SRS1=HHHH=forwarder.example==HHHH=TT=bob.com=alice@forwarder.example"
 *   srs.reverse(hop2);   // → the prior-hop SRS0 address, re-routed one hop back
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new SrsError("srs/bad-opts",
      "srs.create: opts required (secret + forwarderDomain)", true);
  }
  validateOpts.requireNonEmptyString(
    opts.secret, "srs.create.secret", SrsError, "srs/bad-secret");
  validateOpts.requireNonEmptyString(
    opts.forwarderDomain, "srs.create.forwarderDomain", SrsError, "srs/bad-forwarder");
  if (opts.secret.length < 16) {
    throw new SrsError("srs/bad-secret",
      "srs.create: secret must be >= 16 chars (operator-supplied entropy floor)");
  }
  var expiryDays = opts.expiryDays !== undefined ? opts.expiryDays : 30;
  if (typeof expiryDays !== "number" || !Number.isInteger(expiryDays) ||
      expiryDays < 1 || expiryDays > 1024) {
    throw new SrsError("srs/bad-expiry",
      "srs.create: expiryDays must be an integer 1..1024 (SRS rotation cycle)");
  }
  var secret = opts.secret;
  var forwarderDomain = opts.forwarderDomain;

  function rewrite(originalAddress, nowMs) {
    validateOpts.requireNonEmptyString(
      originalAddress, "srs.rewrite.address", SrsError, "srs/bad-address");
    safeBuffer.assertHeaderSafe(originalAddress, "srs.rewrite.address", SrsError, "srs/bad-address");
    var at = originalAddress.lastIndexOf("@");
    if (at <= 0 || at === originalAddress.length - 1) {
      throw new SrsError("srs/bad-address",
        "srs.rewrite: address must be in localPart@domain form");
    }
    var localPart = originalAddress.slice(0, at);
    var domain    = originalAddress.slice(at + 1);
    if (localPart.length > 64 || domain.length > 253) {
      throw new SrsError("srs/bad-address",
        "srs.rewrite: localPart / domain exceeds RFC 5321 length cap");
    }
    if (/^SRS[01]=/i.test(localPart)) {
      throw new SrsError("srs/already-rewritten",
        "srs.rewrite: address already SRS-encoded; use srs1Rewrite() to chain a further forwarding hop");
    }
    var now = typeof nowMs === "number" ? nowMs : Date.now();
    var ts  = _dayStamp(now);
    var hashInput = ts + "=" + domain + "=" + localPart;
    var tag = _hashTag(secret, hashInput);
    return "SRS0=" + tag + "=" + ts + "=" + domain + "=" + localPart + "@" + forwarderDomain;
  }

  function srs1Rewrite(srsAddress) {
    validateOpts.requireNonEmptyString(
      srsAddress, "srs.srs1Rewrite.address", SrsError, "srs/bad-address");
    safeBuffer.assertHeaderSafe(srsAddress, "srs.srs1Rewrite.address", SrsError, "srs/bad-address");
    var at = srsAddress.lastIndexOf("@");
    if (at <= 0 || at === srsAddress.length - 1) {
      throw new SrsError("srs/bad-address",
        "srs.srs1Rewrite: address must be in localPart@domain form");
    }
    var localPart = srsAddress.slice(0, at);
    var priorForwarder, srs0Body;
    if (/^SRS0=/i.test(localPart)) {
      priorForwarder = srsAddress.slice(at + 1);
      srs0Body = localPart.slice(5);
    } else if (/^SRS1=/i.test(localPart)) {
      var inner = _parseSrs1(localPart);
      priorForwarder = inner.priorForwarder;
      srs0Body = inner.srs0Body;
    } else {
      throw new SrsError("srs/not-srs0",
        "srs.srs1Rewrite: input must be an SRS0 or SRS1 address (use rewrite() for a plain address)");
    }
    if (!priorForwarder || priorForwarder.indexOf("=") !== -1) {
      throw new SrsError("srs/bad-address",
        "srs.srs1Rewrite: prior forwarder domain must be a non-empty domain without '=' (would corrupt SRS1 field parsing)");
    }
    var opaque = priorForwarder + "==" + srs0Body;
    var tag = _hashTag(secret, opaque);
    var result = "SRS1=" + tag + "=" + priorForwarder + "==" + srs0Body + "@" + forwarderDomain;
    if (result.length > 256) {
      throw new SrsError("srs/too-long",
        "srs.srs1Rewrite: rewritten address exceeds the RFC 5321 256-octet path limit (forwarding chain too deep)");
    }
    return result;
  }

  function reverse(srsAddress, nowMs) {
    validateOpts.requireNonEmptyString(
      srsAddress, "srs.reverse.address", SrsError, "srs/bad-address");
    safeBuffer.assertHeaderSafe(srsAddress, "srs.reverse.address", SrsError, "srs/bad-address");
    var at = srsAddress.lastIndexOf("@");
    if (at <= 0 || at === srsAddress.length - 1) {
      throw new SrsError("srs/bad-address",
        "srs.reverse: address must be in srsLocal@forwarder form");
    }
    var localPart  = srsAddress.slice(0, at);
    var rcptDomain = srsAddress.slice(at + 1);
    var isSrs0 = /^SRS0=/i.test(localPart);
    var isSrs1 = /^SRS1=/i.test(localPart);
    if (!isSrs0 && !isSrs1) {
      throw new SrsError("srs/not-srs0",
        "srs.reverse: address local-part does not start with SRS0= or SRS1=");
    }
    if (rcptDomain.toLowerCase() !== forwarderDomain.toLowerCase()) {
      throw new SrsError("srs/wrong-forwarder",
        "srs.reverse: bounce addressed to '" + rcptDomain + "' but rewriter " +
        "is bound to forwarderDomain '" + forwarderDomain + "'");
    }
    if (isSrs1) {
      var s1 = _parseSrs1(localPart);
      if (!_timingSafeStringEqual(s1.tag, _hashTag(secret, s1.priorForwarder + "==" + s1.srs0Body))) {
        throw new SrsError("srs/bad-tag",
          "srs.reverse: SRS1 HMAC tag does not verify (wrong secret or tampered envelope-from)");
      }
      return "SRS0=" + s1.srs0Body + "@" + s1.priorForwarder;
    }
    var rest = localPart.slice(5);
    var parts = rest.split("=");
    if (parts.length < 4) {
      throw new SrsError("srs/malformed",
        "srs.reverse: expected SRS0=tag=ts=domain=local local-part shape (need >= 4 '=' fields)");
    }
    var tag = parts[0];
    var ts  = parts[1];
    var origDomain = parts[2];
    var origLocal  = parts.slice(3).join("=");
    var hashInput = ts + "=" + origDomain + "=" + origLocal;
    var expectedTag = _hashTag(secret, hashInput);
    if (!_timingSafeStringEqual(tag, expectedTag)) {
      throw new SrsError("srs/bad-tag",
        "srs.reverse: HMAC tag does not verify (wrong secret or tampered envelope-from)");
    }
    var now = typeof nowMs === "number" ? nowMs : Date.now();
    var dayDiff = _dayDiff(ts, now);
    if (dayDiff > expiryDays) {
      throw new SrsError("srs/expired",
        "srs.reverse: rewrite is " + dayDiff + " days old; expiry window is " + expiryDays + " days");
    }
    return origLocal + "@" + origDomain;
  }

  return Object.freeze({
    rewrite:      rewrite,
    srs1Rewrite:  srs1Rewrite,
    reverse:      reverse,
    forwarderDomain: forwarderDomain,
  });
}

function _timingSafeStringEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return bCrypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

module.exports = {
  create:   create,
  SrsError: SrsError,
};

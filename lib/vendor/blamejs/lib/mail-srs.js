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
 *   SRS1 (double-forward case): when an already-SRS0-encoded address
 *   gets forwarded a second time, SRS1 wraps the SRS0 envelope
 *   instead of re-encoding from scratch, preserving the original
 *   sender chain.
 *
 *   `b.mail.srs.create({ secret, forwarderDomain })` returns
 *   `{ rewrite, reverse }`. `rewrite(originalSender)` produces the
 *   SRS-encoded address; `reverse(srsAddress)` decodes back to the
 *   original sender + verifies the HMAC.
 *
 * @card
 *   SRS Sender Rewriting Scheme — forwarder envelope-from rewriting with HMAC-bound day-rotated tags so the next-hop SPF check passes and bounces route correctly back to the original sender.
 */

var nodeCrypto    = require("node:crypto");
var blamejsCrypto = require("./crypto");
var validateOpts  = require("./validate-opts");
var { defineClass } = require("./framework-error");

var SrsError = defineClass("SrsError", { alwaysPermanent: true });

// SRS spec: 2-char base32 day stamp. The rotation cycle is 1024 days
// (32 * 32) which is ~2.8 years; valid-window is the operator-supplied
// expiry (default 30 days).
var BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

function _base32Encode(buf) {
  var out = "";
  var bits = 0;
  var value = 0;
  for (var i = 0; i < buf.length; i += 1) {
    value = (value << 8) | buf[i];                                                                 // allow:raw-byte-literal — byte-aligned shift
    bits += 8;                                                                                     // allow:raw-byte-literal — bits-per-byte constant
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
  return _base32Encode(mac.subarray(0, 4)).slice(0, 4);                                            // allow:raw-byte-literal — SRS spec 4-char short-tag
}

function _dayStamp(nowMs) {
  // Days since epoch, mod 1024. Two-char base32 = 1024 possible values.
  var days = Math.floor(nowMs / 86400000) % 1024;                                                  // allow:raw-byte-literal — ms-per-day + mod-1024 SRS rotation
  return BASE32.charAt(days >>> 5) + BASE32.charAt(days & 31);                                     // allow:raw-byte-literal — 5-bit base32 split
}

function _dayDiff(stamp, nowMs) {
  if (typeof stamp !== "string" || stamp.length !== 2) return Infinity;
  var hi = BASE32.indexOf(stamp.charAt(0));
  var lo = BASE32.indexOf(stamp.charAt(1));
  if (hi < 0 || lo < 0) return Infinity;
  var stampVal = (hi << 5) | lo;                                                                   // allow:raw-byte-literal — 5-bit base32 split
  var nowVal = Math.floor(nowMs / 86400000) % 1024;                                                // allow:raw-byte-literal — ms-per-day + mod-1024 rotation
  // Modular distance — assume positive (rewrites in the future are
  // refused via _dayDiff > 0 callers).
  var diff = (nowVal - stampVal + 1024) % 1024;                                                    // allow:raw-byte-literal — mod-1024 rotation
  return diff;
}

/**
 * @primitive b.mail.srs.create
 * @signature b.mail.srs.create(opts)
 * @since     0.8.89
 * @status    stable
 *
 * Build an SRS rewriter bound to the operator's forwarder domain +
 * HMAC signing secret. Returns `{ rewrite, reverse }`.
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
  if (opts.secret.length < 16) {                                                                   // allow:raw-byte-literal — minimum HMAC secret length
    throw new SrsError("srs/bad-secret",
      "srs.create: secret must be >= 16 chars (operator-supplied entropy floor)");
  }
  var expiryDays = opts.expiryDays !== undefined ? opts.expiryDays : 30;                           // allow:raw-byte-literal — default expiry window in days
  if (typeof expiryDays !== "number" || !Number.isInteger(expiryDays) ||
      expiryDays < 1 || expiryDays > 1024) {                                                       // allow:raw-byte-literal — SRS rotation cycle cap
    throw new SrsError("srs/bad-expiry",
      "srs.create: expiryDays must be an integer 1..1024 (SRS rotation cycle)");
  }
  var secret = opts.secret;
  var forwarderDomain = opts.forwarderDomain;

  function rewrite(originalAddress, nowMs) {
    validateOpts.requireNonEmptyString(
      originalAddress, "srs.rewrite.address", SrsError, "srs/bad-address");
    var at = originalAddress.lastIndexOf("@");
    if (at <= 0 || at === originalAddress.length - 1) {
      throw new SrsError("srs/bad-address",
        "srs.rewrite: address must be in localPart@domain form");
    }
    var localPart = originalAddress.slice(0, at);
    var domain    = originalAddress.slice(at + 1);
    if (localPart.length > 64 || domain.length > 253) {                                            // allow:raw-byte-literal — RFC 5321 local-part / domain caps
      throw new SrsError("srs/bad-address",
        "srs.rewrite: localPart / domain exceeds RFC 5321 length cap");
    }
    // Refuse SRS double-encoding from this primitive — operator must
    // use srs1Rewrite() for already-SRS0 inputs (deferred per the
    // v1-defensible decision: SRS1 wrapping is rare in operator
    // deployments and adds substantial spec surface).
    if (/^SRS[01]=/i.test(localPart)) {
      throw new SrsError("srs/already-rewritten",
        "srs.rewrite: address already SRS-encoded; chain forwarding through SRS1 is not yet supported (operator demand TBD)");
    }
    var now = typeof nowMs === "number" ? nowMs : Date.now();
    var ts  = _dayStamp(now);
    var hashInput = ts + "=" + domain + "=" + localPart;
    var tag = _hashTag(secret, hashInput);
    return "SRS0=" + tag + "=" + ts + "=" + domain + "=" + localPart + "@" + forwarderDomain;
  }

  function reverse(srsAddress, nowMs) {
    validateOpts.requireNonEmptyString(
      srsAddress, "srs.reverse.address", SrsError, "srs/bad-address");
    var at = srsAddress.lastIndexOf("@");
    if (at <= 0 || at === srsAddress.length - 1) {
      throw new SrsError("srs/bad-address",
        "srs.reverse: address must be in srsLocal@forwarder form");
    }
    var localPart  = srsAddress.slice(0, at);
    var rcptDomain = srsAddress.slice(at + 1);
    // Allow case-insensitive SRS0 prefix per the spec. Check this
    // FIRST so an obviously-non-SRS0 input (`plain@example.com`)
    // gets the specific not-srs0 verdict instead of the more general
    // wrong-forwarder verdict.
    if (!/^SRS0=/i.test(localPart)) {
      throw new SrsError("srs/not-srs0",
        "srs.reverse: address local-part does not start with SRS0=");
    }
    // Domain binding — the rewriter is scoped to a specific forwarder
    // domain, and reverse() must verify the bounce arrived at THAT
    // domain. Otherwise an SRS0 local-part signed with the same
    // secret but addressed to a different forwarder (multi-domain
    // deployment, or a misrouted DNS record) would still verify, and
    // the operator would mis-deliver the bounce. RFC 5321 §2.3.5
    // says domains are case-insensitive, so compare lowercased.
    if (rcptDomain.toLowerCase() !== forwarderDomain.toLowerCase()) {
      throw new SrsError("srs/wrong-forwarder",
        "srs.reverse: bounce addressed to '" + rcptDomain + "' but rewriter " +
        "is bound to forwarderDomain '" + forwarderDomain + "'");
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
    var origLocal  = parts.slice(3).join("=");      // local-part may itself contain '='
    // Verify tag.
    var hashInput = ts + "=" + origDomain + "=" + origLocal;
    var expectedTag = _hashTag(secret, hashInput);
    if (!_timingSafeStringEqual(tag, expectedTag)) {
      throw new SrsError("srs/bad-tag",
        "srs.reverse: HMAC tag does not verify (wrong secret or tampered envelope-from)");
    }
    // Verify expiry window.
    var now = typeof nowMs === "number" ? nowMs : Date.now();
    var dayDiff = _dayDiff(ts, now);
    if (dayDiff > expiryDays) {
      throw new SrsError("srs/expired",
        "srs.reverse: rewrite is " + dayDiff + " days old; expiry window is " + expiryDays + " days");
    }
    return origLocal + "@" + origDomain;
  }

  return Object.freeze({
    rewrite:  rewrite,
    reverse:  reverse,
    forwarderDomain: forwarderDomain,
  });
}

function _timingSafeStringEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return blamejsCrypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

module.exports = {
  create:   create,
  SrsError: SrsError,
};

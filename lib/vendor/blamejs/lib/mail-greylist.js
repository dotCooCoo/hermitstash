// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.mail.greylist
 * @nav        Mail
 * @title      Mail Greylist
 * @order      545
 *
 * @intro
 *   RFC 6647 email greylisting primitive. Defers first-seen senders
 *   with a 4yz SMTP tempfail so transient connections (spam, snowshoe
 *   campaigns, single-attempt botnets) drop and legitimate MTAs (which
 *   retry per RFC 5321 §4.5.4) re-connect after the operator-configured
 *   minimum delay and pass through.
 *
 *   ## Triplet fingerprint (RFC 6647 §4.4)
 *
 *   Each greylist entry is keyed by the operator-recommended triple:
 *
 *     - **Connection IP** (CIDR-normalized — default `/24` for IPv4,
 *       `/64` for IPv6 so adjacent retry hosts from the same MTA
 *       cluster share a single entry).
 *     - **RFC 5321 MailFrom** (envelope-from; lowercased; bounces
 *       carry `<>` and key as the literal empty string).
 *     - **First RFC 5321 RcptTo** — RFC 6647 §4.4 notes legitimate
 *       MTAs don't reorder recipients on retry, so keying on the
 *       first RcptTo is sufficient.
 *
 *   The triplet is hashed via `b.crypto.namespaceHash("mail.greylist",
 *   ip-cidr + "\\0" + mailfrom + "\\0" + first-rcpt)` so the on-disk
 *   key is unlinkable to the PII triplet (privacy + GDPR Art. 5(1)(c)
 *   data minimization).
 *
 *   ## Window + TTL (RFC 6647 §4.5)
 *
 *   - **`minDelayMs`** — minimum delay between first-seen and
 *     accept-on-retry (default 5 minutes; RFC 6647 §4.5 recommends
 *     "from one minute to 24 hours"). Retries inside the window get
 *     another 4yz tempfail; the existing fingerprint stays in place.
 *   - **`whitelistTtlMs`** — duration to remember a passed-greylist
 *     entry (default 36 days; RFC 6647 §4.5 recommends ≥1 week). On
 *     expiry the entry is gc'd and the next first-seen attempt is
 *     deferred again.
 *   - **`maxEntries`** — operator-configurable upper bound on the
 *     active-fingerprint store (default 1M). Bounds memory for the
 *     in-memory backend; the dbStore backend is bounded by DB row
 *     count.
 *
 *   ## Backend abstraction
 *
 *   `b.mail.greylist.create({ store: <store>, ... })` accepts any
 *   `{ get(key) → entry|null, put(key, entry, ttlMs), delete(key),
 *   gc(olderThanMs) → count }`-shaped backend. In-memory default
 *   ships for single-process MX deployments; the operator wires a
 *   sqlite-backed adapter or external DB for multi-process MX
 *   fleets (a retry landing on a different process needs to see the
 *   fingerprint planted by the first attempt).
 *
 *   ## Verdict
 *
 *   `instance.check({ ip, mailFrom, rcptTo })` → `{ action, reason,
 *   firstSeenAt?, ttlExpiresAt? }`:
 *
 *     - **`"defer"`** — first-seen or retry-too-soon. Operator returns
 *       SMTP `451 4.7.1 <reason>` (RFC 6647 §4.5 + RFC 5321 §4.2.5).
 *     - **`"accept"`** — within the post-acceptance whitelist window;
 *       operator continues the SMTP transaction.
 *     - **`"accept-first-pass"`** — retry after `minDelayMs` elapsed
 *       on a previously-deferred fingerprint; operator continues AND
 *       the framework marks the fingerprint as whitelisted for the
 *       full TTL window.
 *
 *   ## CVE / threat model
 *
 *   - **Snowshoe + single-attempt bot flood** — the defining defense:
 *     transient sources don't retry, so they never reach the message
 *     body. Pre-DKIM / pre-content-scan defense — cheap rejection.
 *   - **Fingerprint-store poisoning** — operator-supplied IPs +
 *     mailfrom strings are hashed (no raw PII on disk) and bounded
 *     (`maxEntries`); a hostile peer that tries to inflate the store
 *     hits the cap and the framework rotates oldest-first.
 *   - **CIDR-aggregation bypass** — operators with retry-aware MTA
 *     clusters (Gmail, Outlook, AWS SES) need /24 IPv4 and /64 IPv6
 *     so the cluster's retry from a different host in the same
 *     subnet passes; the defaults match real-world MTA behavior.
 *
 *   ## When NOT to greylist
 *
 *   - Listserv submissions (operator opts the listserv source out
 *     via `allowedSources` per RFC 6647 §6.2).
 *   - First-time newsletter sign-up confirmations (a single first
 *     attempt would defer the confirmation email; operator opts
 *     submission relay paths out).
 *   - High-priority transactional sources the operator has direct
 *     relationship with (banking, healthcare 2FA, etc.).
 *
 * @card
 *   RFC 6647 SMTP greylisting. Triplet fingerprint (IP CIDR + MailFrom + first RcptTo), namespace-hashed, configurable minDelayMs + whitelistTtlMs windows. Defers first-seen senders with SMTP 451 4.7.1; legitimate retries pass and stay whitelisted. Pluggable backend.
 */

var C                  = require("./constants");
var { defineClass }    = require("./framework-error");
var bCrypto            = require("./crypto");
var lazyRequire        = require("./lazy-require");
var ipUtils            = require("./ip-utils");
var gateContract       = require("./gate-contract");
var { boundedMap }     = require("./bounded-map");

var audit              = lazyRequire(function () { return require("./audit"); });

var MailGreylistError = defineClass("MailGreylistError", { alwaysPermanent: true });

var DEFAULT_MIN_DELAY_MS    = C.TIME.minutes(5);
var DEFAULT_WHITELIST_TTL   = C.TIME.days(36);
var DEFAULT_MAX_ENTRIES     = 1000000;                                                                   // entry-count cap, not bytes
var DEFAULT_IPV4_PREFIX     = 24;                                                                        // RFC 6647 §4.4 IP-clustering granularity
var DEFAULT_IPV6_PREFIX     = 64;                                                                        // RFC 6647 §4.4 IPv6 IP-clustering granularity
var DEFAULT_PROFILE         = "strict";

var PROFILES = Object.freeze({
  // Strict: low delay, modest whitelist TTL. Catches snowshoe but
  // retries from legitimate MTAs (which back off 5-15 min on tempfail)
  // pass quickly.
  strict:     { minDelayMs: C.TIME.minutes(5),  whitelistTtlMs: C.TIME.days(36), ipv4Prefix: 24, ipv6Prefix: 64 },                                                                                          // RFC 6647 §4.4 prefixes
  // Balanced: minimum 1 min delay, shorter TTL for higher churn.
  balanced:   { minDelayMs: C.TIME.minutes(1),  whitelistTtlMs: C.TIME.days(7),  ipv4Prefix: 24, ipv6Prefix: 64 },                                                                                          // RFC 6647 §4.4 prefixes
  // Permissive: 30s delay, 30-day TTL. For operators that want
  // greylisting present but minimally visible.
  permissive: { minDelayMs: C.TIME.seconds(30), whitelistTtlMs: C.TIME.days(30), ipv4Prefix: 32, ipv6Prefix: 128 },                                                                                         // RFC 6647 §4.4 prefixes
});

var COMPLIANCE_POSTURES = gateContract.ALL_STRICT_POSTURES;

/**
 * @primitive b.mail.greylist.create
 * @signature b.mail.greylist.create(opts?)
 * @since     0.9.34
 * @status    stable
 * @related   b.mail.rbl.create
 *
 * Build a greylist instance. Returns an object with `.check(ctx) →
 * Promise<verdict>` and `.gc({ olderThanMs }) → Promise<{ removed }>`.
 *
 * @opts
 *   profile:        "strict" | "balanced" | "permissive",
 *   posture:        "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   store:          { get, put, delete, gc } — pluggable backend
 *   minDelayMs:     number — overrides profile minimum-delay window
 *   whitelistTtlMs: number — overrides profile post-acceptance TTL
 *   maxEntries:     number — in-memory backend's entry cap
 *   allowedSources: Array<string> — IPs / CIDRs that skip greylisting
 *   audit:          b.audit namespace
 *
 * @example
 *   var gl = b.mail.greylist.create({ profile: "strict" });
 *   var v  = await gl.check({
 *     ip:       "203.0.113.42",
 *     mailFrom: "sender@example.com",
 *     rcptTo:   "alice@operator.example",
 *   });
 *   if (v.action === "defer") return reply(451, "4.7.1 " + v.reason);
 */
function create(opts) {
  opts = opts || {};
  var profile = gateContract.resolveProfileName(opts, COMPLIANCE_POSTURES, DEFAULT_PROFILE);
  if (!Object.prototype.hasOwnProperty.call(PROFILES, profile)) {
    throw new MailGreylistError("mail-greylist/bad-profile",
      "create: unknown profile '" + profile + "'");
  }
  var caps = PROFILES[profile];
  var minDelayMs     = typeof opts.minDelayMs === "number" ? opts.minDelayMs : caps.minDelayMs;
  var whitelistTtlMs = typeof opts.whitelistTtlMs === "number" ? opts.whitelistTtlMs : caps.whitelistTtlMs;
  var maxEntries     = typeof opts.maxEntries === "number" ? opts.maxEntries : DEFAULT_MAX_ENTRIES;
  var ipv4Prefix     = caps.ipv4Prefix;
  var ipv6Prefix     = caps.ipv6Prefix;
  var auditImpl      = opts.audit || audit();
  var allowedSources = Array.isArray(opts.allowedSources) ? opts.allowedSources.slice() : [];

  if (!isFinite(minDelayMs) || minDelayMs < 0) {
    throw new MailGreylistError("mail-greylist/bad-input",
      "create: minDelayMs must be a non-negative finite number");
  }
  if (!isFinite(whitelistTtlMs) || whitelistTtlMs <= 0) {
    throw new MailGreylistError("mail-greylist/bad-input",
      "create: whitelistTtlMs must be a positive finite number");
  }
  if (!isFinite(maxEntries) || maxEntries <= 0) {
    throw new MailGreylistError("mail-greylist/bad-input",
      "create: maxEntries must be a positive finite number");
  }

  var store = opts.store || _memoryStore(maxEntries);

  async function check(ctx) {
    if (!ctx || typeof ctx !== "object") {
      throw new MailGreylistError("mail-greylist/bad-input",
        "check: ctx must be a plain object");
    }
    if (typeof ctx.ip !== "string" || ctx.ip.length === 0) {
      throw new MailGreylistError("mail-greylist/bad-input",
        "check: ctx.ip must be a non-empty string");
    }
    if (typeof ctx.mailFrom !== "string") {
      throw new MailGreylistError("mail-greylist/bad-input",
        "check: ctx.mailFrom must be a string (use '' for bounce sender)");
    }
    if (typeof ctx.rcptTo !== "string" || ctx.rcptTo.length === 0) {
      throw new MailGreylistError("mail-greylist/bad-input",
        "check: ctx.rcptTo must be a non-empty string");
    }

    // Allowed-source bypass — operator-supplied IPs / CIDRs that
    // skip greylisting (RFC 6647 §6.2). Listservs, transactional
    // partners, etc.
    if (_isAllowed(ctx.ip, allowedSources)) {
      _emitAudit(auditImpl, "mail.greylist.bypassed", {
        reason: "allowed-source", ip: ctx.ip,
      });
      return { action: "accept", reason: "allowed-source" };
    }

    var cidr = _cidrKey(ctx.ip, ipv4Prefix, ipv6Prefix);
    var fingerprint = _hashFingerprint(cidr, ctx.mailFrom.toLowerCase(), ctx.rcptTo.toLowerCase());

    var now = typeof ctx.now === "number" ? ctx.now : Date.now();
    var existing = await store.get(fingerprint);

    if (!existing) {
      // First-seen: defer + persist fingerprint with firstSeenAt.
      await store.put(fingerprint, {
        firstSeenAt:  now,
        whitelistedAt: null,
        kind:         "deferred",
      }, minDelayMs + whitelistTtlMs);                                                                   // total lifetime so the entry survives the delay window
      _emitAudit(auditImpl, "mail.greylist.deferred", {
        firstSeen: true, cidr: cidr,
      });
      return { action: "defer", reason: "first-seen", firstSeenAt: now };
    }

    if (existing.kind === "whitelisted") {
      if (now > existing.ttlExpiresAt) {
        // TTL elapsed without recent traffic — RFC 6647 §4.5
        // recommends gc'ing and re-greylisting on the next attempt.
        // We do it on read so a low-traffic deployment doesn't carry
        // stale rows.
        await store.delete(fingerprint);
        await store.put(fingerprint, {
          firstSeenAt:   now,
          whitelistedAt: null,
          kind:          "deferred",
        }, minDelayMs + whitelistTtlMs);
        _emitAudit(auditImpl, "mail.greylist.deferred", {
          firstSeen: false, expired: true, cidr: cidr,
        });
        return { action: "defer", reason: "whitelist-expired-resnap", firstSeenAt: now };
      }
      _emitAudit(auditImpl, "mail.greylist.accepted", { cidr: cidr });
      return {
        action:        "accept",
        reason:        "whitelisted",
        ttlExpiresAt:  existing.ttlExpiresAt,
      };
    }

    // Deferred entry — check if retry-after delay elapsed.
    if (now - existing.firstSeenAt < minDelayMs) {
      _emitAudit(auditImpl, "mail.greylist.deferred", {
        firstSeen: false, retryTooSoon: true, cidr: cidr,
      });
      return {
        action:        "defer",
        reason:        "retry-too-soon",
        firstSeenAt:   existing.firstSeenAt,
      };
    }

    // First-pass: retry-after-delay accepted. Mark whitelisted.
    var ttlExpiresAt = now + whitelistTtlMs;
    await store.put(fingerprint, {
      firstSeenAt:   existing.firstSeenAt,
      whitelistedAt: now,
      ttlExpiresAt:  ttlExpiresAt,
      kind:          "whitelisted",
    }, whitelistTtlMs);
    _emitAudit(auditImpl, "mail.greylist.first_pass", {
      delayMs: now - existing.firstSeenAt, cidr: cidr,
    });
    return {
      action:        "accept-first-pass",
      reason:        "retry-after-delay",
      firstSeenAt:   existing.firstSeenAt,
      ttlExpiresAt:  ttlExpiresAt,
    };
  }

  async function gc(gcOpts) {
    gcOpts = gcOpts || {};
    var olderThanMs = typeof gcOpts.olderThanMs === "number" ? gcOpts.olderThanMs : whitelistTtlMs;
    var removed = await store.gc(olderThanMs);
    _emitAudit(auditImpl, "mail.greylist.gc", { removed: removed });
    return { removed: removed };
  }

  return {
    check:                check,
    gc:                   gc,
    profile:              profile,
    minDelayMs:           minDelayMs,
    whitelistTtlMs:       whitelistTtlMs,
    MailGreylistError:    MailGreylistError,
  };
}

/**
 * @primitive b.mail.greylist.compliancePosture
 * @signature b.mail.greylist.compliancePosture(posture)
 * @since     0.9.34
 * @status    stable
 *
 * Return the effective profile name for a compliance posture, or
 * `null` for unknown posture names.
 *
 * @example
 *   b.mail.greylist.compliancePosture("hipaa");   // → "strict"
 */
var compliancePosture = gateContract.makePostureAccessor(COMPLIANCE_POSTURES);

function _hashFingerprint(cidr, mailFrom, rcptTo) {
  // Namespace-hash so the on-disk key is unlinkable to the PII
  // triplet — operator dumps of the greylist table don't leak
  // sender / recipient pairs. The framework's hash primitive
  // (sha3-512 inside namespaceHash) is bound to the "mail.greylist"
  // namespace so a hash never collides with another consumer's hash
  // of the same plaintext.
  return bCrypto.namespaceHash("mail.greylist",
    cidr + "\u0000" + mailFrom + "\u0000" + rcptTo);
}

function _cidrKey(ip, ipv4Prefix, ipv6Prefix) {
  if (ipUtils.isIPv4(ip)) {
    var octets = ip.split(".").map(function (s) { return parseInt(s, 10); });
    var prefix = Math.min(32, Math.max(0, ipv4Prefix));                                                  // IPv4 address bit width
    // Apply prefix: zero out the host bits.
    var int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];                      // IPv4 byte shifts
    var mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;                                           // IPv4 mask construction
    var masked = (int & mask) >>> 0;
    return [
      (masked >>> 24) & 0xff,                                                                            // IPv4 byte extraction
      (masked >>> 16) & 0xff,
      (masked >>> 8)  & 0xff,
      masked & 0xff,
    ].join(".") + "/" + prefix;
  }
  if (ipUtils.looksLikeIPv6Hex(ip)) {
    // Expand IPv6, then mask. Reuse the expansion approach from
    // mail-rbl by inlining since this is a different prefix shape.
    var expanded = ipUtils.expandIpv6Hex(ip);
    if (!expanded) {
      throw new MailGreylistError("mail-greylist/bad-input",
        "IP '" + ip + "' is not a parseable IPv6 address");
    }
    // expanded is 32 hex chars; mask to ipv6Prefix bits.
    var prefixBits = Math.min(128, Math.max(0, ipv6Prefix));                                             // IPv6 address bit width
    var keepNibbles = Math.floor(prefixBits / 4);                                                        // bits-per-hex-nibble
    var keptHex = expanded.slice(0, keepNibbles);
    return keptHex + "*/" + prefixBits;
  }
  throw new MailGreylistError("mail-greylist/bad-input",
    "IP '" + ip + "' is not a parseable IPv4 or IPv6 address");
}

function _isAllowed(ip, allowedSources) {
  // Allowed-source matching — exact IP only for v0.9.34. CIDR
  // matching deferred to the operator's own b.middleware.ipAllowlist
  // when fine-grained subnet rules are needed; this primitive's
  // value-add is the triplet-greylist contract.
  return allowedSources.indexOf(ip) !== -1;
}

function _emitAudit(auditImpl, action, metadata) {
  try {
    if (auditImpl && typeof auditImpl.safeEmit === "function") {
      auditImpl.safeEmit({ action: action, outcome: "success", metadata: metadata });
    }
  } catch (_e) { /* drop-silent — audit failure must not block accept loop */ }
}

function _memoryStore(maxEntries) {
  // The in-memory backend is exactly the bounded-map ceiling primitive: cap
  // the entry count and drop the oldest on insert at capacity. boundedMap owns
  // the insertion-order tracking and eviction; this store layers greylist TTL
  // semantics (putAt/ttlMs) on top.
  var data = boundedMap({ maxEntries: maxEntries, policy: "evict-oldest" });
  return {
    get: async function (key) {
      var entry = data.get(key);
      return entry ? entry.value : null;
    },
    put: async function (key, value, ttlMs) {
      // boundedMap evicts the oldest entry when a NEW key arrives at capacity;
      // updating an existing key neither grows the map nor evicts.
      data.set(key, { value: value, putAt: Date.now(), ttlMs: ttlMs });
    },
    delete: async function (key) {
      data.delete(key);
    },
    gc: async function (olderThanMs) {
      var now = Date.now();
      var expired = [];
      data.forEach(function (entry, key) {
        if (now - entry.putAt > olderThanMs) expired.push(key);
      });
      expired.forEach(function (key) { data.delete(key); });
      return expired.length;
    },
  };
}

module.exports = {
  create:                  create,
  compliancePosture:       compliancePosture,
  PROFILES:                PROFILES,
  COMPLIANCE_POSTURES:     COMPLIANCE_POSTURES,
  MailGreylistError:       MailGreylistError,
  _hashFingerprint:        _hashFingerprint,
  _cidrKey:                _cidrKey,
  _DEFAULT_MIN_DELAY_MS:   DEFAULT_MIN_DELAY_MS,
  _DEFAULT_WHITELIST_TTL:  DEFAULT_WHITELIST_TTL,
  _DEFAULT_IPV4_PREFIX:    DEFAULT_IPV4_PREFIX,
  _DEFAULT_IPV6_PREFIX:    DEFAULT_IPV6_PREFIX,
};

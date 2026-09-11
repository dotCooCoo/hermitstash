// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.mail.send.deliver
 * @nav    Mail
 * @title  Outbound delivery
 * @order  240
 *
 * @intro
 *   Turnkey outbound SMTP composer. Wraps the discovery chain
 *   (MX-lookup → MTA-STS-fetch + MX-allowlist match → DANE TLSA query
 *   → REQUIRETLS handshake hint) around the existing per-host
 *   `b.mail.transports.smtp` wire-layer, plus deferred-retry scheduling
 *   for transient failures and RFC 3464 DSN generation for permanent
 *   ones.
 *
 *   Operators no longer have to glue these pieces by hand:
 *
 *     var deliver = b.mail.send.deliver.create({
 *       hostname: "mta1.example.com",
 *       policy:   { mtaSts: "enforce", dane: "opportunistic" },
 *       dsn:      { from: "mailer-daemon@example.com",
 *                   onPermanentFailure: function (env, hist) { ... } },
 *       resolver: b.network.dns.resolver.create({ ... }),
 *     });
 *
 *     var result = await deliver({
 *       from:   "ops@example.com",
 *       to:     ["alice@recipient.com", "bob@other.com"],
 *       rfc822: messageBuffer,
 *       requireTls: true,
 *     });
 *     // → { delivered: [{ recipient, mxHost, tlsProtocol, ... }],
 *     //     deferred:  [{ recipient, mxHost, reason, retryAfterMs }],
 *     //     failed:    [{ recipient, reason, dsnSent }] }
 *     //   deferred.mxHost is the receiver that refused, or null when the
 *     //   deferral happened before any host was reached (an MX lookup that
 *     //   failed). A queue view without it cannot say which peer to chase.
 *
 *   Composes:
 *     - `b.network.smtp.policy.mtaSts.fetch` + `.matchMx`  → RFC 8461 enforcement
 *     - `b.network.smtp.policy.dane.tlsa` + `.verifyChain` → RFC 7672 TLSA query
 *                                                            and peer authentication
 *     - `b.network.dns.resolver` (operator-supplied)        → caching + DoH posture
 *     - `b.mail.transports.smtp`                            → SMTP wire layer
 *     - `b.mail.requireTls`                                 → RFC 8689 REQUIRETLS
 *     - `b.mailBounce`-style RFC 3464 DSN generation         → permanent-failure
 *                                                              report-mail
 *     - `b.audit`                                            → mail.send.deliver.* events
 *     - `b.safeAsync.repeating` + operator's queue           → retry scheduling
 *                                                              (deferred deliveries
 *                                                              re-enter via the
 *                                                              `retry.scheduleRetry`
 *                                                              callback)
 *
 *   The deferred-retry surface is operator-side: this primitive
 *   classifies a recipient's outcome as "deferred" and emits a
 *   `retryAfterMs` budget; the operator's queue / scheduler re-invokes
 *   `deliver` for the deferred recipient after that elapses. The
 *   primitive does NOT own a background scheduler — that ownership
 *   lives with the operator's job-runner so a single deferred-delivery
 *   tick can't pin a long-lived process.
 *
 * @card
 *   MX → MTA-STS → DANE → SMTP → REQUIRETLS → DSN. The full outbound chain wired once.
 */

var nodeDns       = require("node:dns").promises;
var bCrypto       = require("./crypto");
var safeBuffer    = require("./safe-buffer");
var validateOpts  = require("./validate-opts");
var lazyRequire   = require("./lazy-require");
var { defineClass } = require("./framework-error");
var C             = require("./constants");

var smtpPolicy   = lazyRequire(function () { return require("./network-smtp-policy"); });
var mailModule   = lazyRequire(function () { return require("./mail"); });
var audit        = lazyRequire(function () { return require("./audit"); });

var DeliverError = defineClass("DeliverError");

var DEFAULT_PORT_SMTP            = 25;
var DEFAULT_RETRY_BACKOFF_MS     = Object.freeze([
  C.TIME.minutes(1),
  C.TIME.minutes(5),
  C.TIME.minutes(15),
  C.TIME.hours(1),
  C.TIME.hours(4),
  C.TIME.hours(8),
  C.TIME.hours(12),
  C.TIME.hours(24),
  C.TIME.hours(24),
  C.TIME.hours(24),
]);
var DEFAULT_MX_LOOKUP_TIMEOUT_MS = C.TIME.seconds(10);
var DEFAULT_PER_HOST_TIMEOUT_MS  = C.TIME.seconds(60);
var MAX_RECIPIENTS_PER_CALL      = 1000;

function _classifySmtpOutcome(err, response) {
  if (response && /^2\d\d/.test(String(response.code || ""))) return "delivered";
  if (err && typeof err.statusCode === "number" && typeof err.permanent === "boolean") {
    return err.permanent ? "permanent" : "transient";
  }
  if (response && /^5\d\d/.test(String(response.code || ""))) return "permanent";
  if (response && /^4\d\d/.test(String(response.code || ""))) return "transient";
  if (err) {
    var code = err.code || "";
    if (/^(ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|ENOTFOUND)$/.test(code)) return "transient";
    if (/\bdane\b/i.test(code) || code === "mail/requiretls-not-advertised") return "transient";
    if (/mta-sts|tls-policy/i.test(code)) return "permanent";
  }
  return "transient";
}

function _enhancedStatusFor(response, fallback) {
  var code = response && String(response.code || "");
  if (/^[45]\d\d$/.test(code)) return code.charAt(0) + ".0.0";
  return fallback;
}

function _buildDsnMessage(opts) {
  var from = safeBuffer.assertHeaderSafe(opts.dsnFrom, "dsnFrom", DeliverError, "deliver/bad-dsn-field");
  var to = safeBuffer.assertHeaderSafe(opts.originalFrom, "originalFrom", DeliverError, "deliver/bad-dsn-field");
  var failedRecipient = safeBuffer.assertHeaderSafe(opts.recipient, "recipient", DeliverError, "deliver/bad-dsn-field");
  var reportingMta = safeBuffer.assertHeaderSafe(opts.reportingMta, "reportingMta", DeliverError, "deliver/bad-dsn-field");
  var statusCode = safeBuffer.assertHeaderSafe(opts.statusCode, "statusCode", DeliverError, "deliver/bad-dsn-field");
  var reason = safeBuffer.foldHeaderText(opts.reason || "permanent failure", " ");
  var origHeadersOpt = opts.originalHeaders || "";
  var origHeaders = typeof origHeadersOpt === "string"
    ? origHeadersOpt : String(origHeadersOpt.text || "");
  var origCharset = typeof origHeadersOpt === "string"
    ? "utf-8" : String(origHeadersOpt.charset || "utf-8");
  if (!/^[A-Za-z0-9._-]{1,40}$/.test(origCharset)) {                                                 // allow:regex-no-length-cap — bounded by the quantifier
    throw new DeliverError("deliver/bad-dsn-field",
      "originalHeaders.charset must be a token");
  }
  var origEncoding = typeof origHeadersOpt === "string"
    ? null : (origHeadersOpt.encoding || null);
  if (origEncoding !== null && origEncoding !== "base64") {
    throw new DeliverError("deliver/bad-dsn-field",
      "originalHeaders.encoding must be \"base64\" or absent");
  }
  var boundary = "dsn-" + bCrypto.generateToken(12);
  var nowIso = new Date().toUTCString();
  var dsnBody =
    "From: Mail Delivery System <" + from + ">\r\n" +
    "To: " + to + "\r\n" +
    "Subject: Delivery Status Notification (Failure)\r\n" +
    "Date: " + nowIso + "\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + boundary + "\"\r\n" +
    "Auto-Submitted: auto-replied\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: text/plain; charset=utf-8\r\n" +
    "\r\n" +
    "This is the mail delivery system at " + (reportingMta || from) + ".\r\n" +
    "\r\n" +
    "Your message to " + failedRecipient + " could not be delivered:\r\n" +
    "\r\n" +
    "    " + reason + "\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: message/delivery-status\r\n" +
    "\r\n" +
    // allow:leftmost-domain-informational
    "Reporting-MTA: dns; " + (reportingMta || from.split("@")[1] || "") + "\r\n" +
    "Arrival-Date: " + nowIso + "\r\n" +
    "\r\n" +
    "Final-Recipient: rfc822; " + failedRecipient + "\r\n" +
    "Action: failed\r\n" +
    "Status: " + (statusCode || "5.0.0") + "\r\n" +
    "Diagnostic-Code: smtp; " + reason + "\r\n" +
    "\r\n" +
    "--" + boundary + "\r\n" +
    "Content-Type: text/rfc822-headers; charset=" + origCharset + "\r\n" +
    (origEncoding ? "Content-Transfer-Encoding: " + origEncoding + "\r\n" : "") +
    "\r\n" +
    origHeaders +
    "\r\n" +
    "--" + boundary + "--\r\n";
  return dsnBody;
}

async function _resolveMx(domain, resolver, timeoutMs) {
  var timer;
  var lookup = resolver
    ? resolver.queryMx(domain)
    : nodeDns.resolveMx(domain);
  var timeout = new Promise(function (_resolve, reject) {
    timer = setTimeout(function () {
      reject(new DeliverError("deliver/mx-timeout",
        "MX lookup for " + domain + " timed out after " + timeoutMs + "ms"));
    }, timeoutMs);
  });
  try {
    var mxs = await Promise.race([lookup, timeout]);
    clearTimeout(timer);
    if (mxs && !Array.isArray(mxs) && Array.isArray(mxs.rrs)) {
      mxs = mxs.rrs.map(function (rr) {
        if (rr && rr.decoded && typeof rr.decoded.exchange === "string") {
          return { exchange: rr.decoded.exchange, priority: rr.decoded.preference };
        }
        return rr;
      });
    }
    if (!Array.isArray(mxs) || mxs.length === 0) {
      throw new DeliverError("deliver/no-mx",
        "no MX records published for " + domain);
    }
    if (mxs.length === 1 && (mxs[0].exchange === "" || mxs[0].exchange === ".")) {
      throw new DeliverError("deliver/null-mx",
        "domain " + domain + " publishes a null MX (RFC 7505) — refuses to accept mail");
    }
    return mxs.slice().sort(function (a, b) { return a.priority - b.priority; });
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

async function _applyMtaStsPolicy(domain, mxs, policyMode, auditEmit) {
  if (policyMode === "off") return mxs;
  var sts;
  try {
    sts = await smtpPolicy().mtaSts.fetch(domain);   // allow:raw-outbound-http-framework-internal — method call on b.network.smtp.policy wrapper, not a raw `fetch(`
  } catch (e) {
    if (policyMode === "enforce") {
      throw new DeliverError("deliver/mta-sts-fetch-failed",
        "MTA-STS fetch for " + domain + " failed under enforce policy: " + e.message);
    }
    auditEmit("mail.send.deliver.mtaSts.skip", "warn",
      { domain: domain, mode: policyMode, reason: e.message });
    return mxs;
  }
  if (!sts || sts.mode === "none") {
    auditEmit("mail.send.deliver.mtaSts.none", "info",
      { domain: domain, mode: policyMode });
    return mxs;
  }
  if (sts.mode === "testing") {
    var testingMatched = mxs.filter(function (m) {
      return smtpPolicy().mtaSts.matchMx(m.exchange, sts.mx || []);
    });
    auditEmit("mail.send.deliver.mtaSts.testing", "info",
      { domain: domain, mxPatterns: sts.mx,
        matched: testingMatched.length, total: mxs.length });
    return mxs;
  }
  var filtered = mxs.filter(function (m) {
    return smtpPolicy().mtaSts.matchMx(m.exchange, sts.mx || []);
  });
  if (filtered.length === 0 && sts.mode === "enforce") {
    throw new DeliverError("deliver/mta-sts-mx-mismatch",
      "no MX for " + domain + " matches the published MTA-STS policy (mode=" + sts.mode + ")");
  }
  if (filtered.length === 0) {
    auditEmit("mail.send.deliver.mtaSts.no-match", "warn",
      { domain: domain, mode: sts.mode });
    return mxs;
  }
  return filtered;
}

async function _fetchDaneTlsa(mxHost, port, daneMode, dnssecValidated, resolver, auditEmit) {
  if (daneMode === "off") return null;
  if (!dnssecValidated) return null;
  try {
    var tlsa = await smtpPolicy().dane.tlsa(mxHost, port || DEFAULT_PORT_SMTP,
      { dnssecValidated: true, resolver: resolver || undefined });
    return tlsa && tlsa.length > 0 ? tlsa : null;
  } catch (e) {
    auditEmit("mail.send.deliver.dane.skip", "warn",
      { mxHost: mxHost, mode: daneMode, reason: e.message });
    if (daneMode === "enforce") {
      throw new DeliverError("deliver/dane-fetch-failed",
        "DANE TLSA lookup for " + mxHost + " failed under enforce policy: " + e.message);
    }
    return null;
  }
}

async function _tryHost(envelope, mxHost, hostnameLocal, opts) {
  var factory = opts.transportFactory || mailModule().transports.smtp;
  var transport = factory({
    host:         mxHost,
    port:         opts.port || DEFAULT_PORT_SMTP,
    ehloName:     hostnameLocal,
    timeoutMs:    opts.perHostTimeoutMs || DEFAULT_PER_HOST_TIMEOUT_MS,
    requireTls:   envelope.requireTls === true,
    dane:         envelope.tlsa || undefined,
  });
  return transport.send({
    from: envelope.from,
    to:   [envelope.recipient],
    raw:  envelope.rfc822,
  });
}

async function _deliverOne(envelope, recipient, ctx) {
  if (recipient.indexOf("@") !== recipient.lastIndexOf("@")) {
    return { recipient: recipient, outcome: "permanent",
             reason: "bad-address", reasonCode: "5.1.3" };
  }
  var domain = recipient.split("@")[1];
  if (!domain) {
    return { recipient: recipient, outcome: "permanent",
             reason: "no-domain", reasonCode: "5.1.3" };
  }
  var mxs;
  try {
    mxs = await _resolveMx(domain, ctx.resolver, ctx.mxLookupTimeoutMs);
  } catch (e) {
    var cls = (e.code === "deliver/null-mx" || e.code === "deliver/no-mx") ? "permanent" : "transient";
    return { recipient: recipient, outcome: cls, reason: e.message,
             reasonCode: cls === "permanent" ? "5.1.2" : "4.4.4" };
  }
  try {
    mxs = await _applyMtaStsPolicy(domain, mxs, ctx.policy.mtaSts, ctx.auditEmit);
  } catch (e) {
    return { recipient: recipient, outcome: "permanent",
             reason: e.message, reasonCode: "5.7.10" };
  }
  var lastErr = null;
  var lastResponse = null;
  var lastMxHost = null;
  var _sawRequireTlsRefusal = false;
  var _sawOtherFailure      = false;
  for (var i = 0; i < mxs.length; i += 1) {
    var mx = mxs[i];
    lastMxHost = mx.exchange;
    var mxTlsa = null;
    try {
      mxTlsa = await _fetchDaneTlsa(mx.exchange, ctx.port, ctx.policy.dane,
                                    ctx.policy.dnssecValidated, ctx.resolver,
                                    ctx.auditEmit);
    } catch (daneErr) {
      lastErr = daneErr;
      _sawOtherFailure = true;
      ctx.auditEmit("mail.send.deliver.dane-failover", "warn", {
        recipient: recipient, mxHost: mx.exchange, reason: daneErr.message,
      });
      continue;
    }
    try {
      var rv = await _tryHost({
        from:       envelope.from,
        recipient:  recipient,
        rfc822:     envelope.rfc822,
        requireTls: envelope.requireTls,
        tlsa:       mxTlsa,
      }, mx.exchange, ctx.hostname, ctx);
      ctx.auditEmit("mail.send.deliver.delivered", "success", {
        recipient: recipient, mxHost: mx.exchange, mxPriority: mx.priority,
      });
      return { recipient: recipient, outcome: "delivered", mxHost: mx.exchange,
               mxPriority: mx.priority, transportResponse: rv };
    } catch (e) {
      lastErr = e;
      lastResponse = (e && typeof e.statusCode === "number") ? { code: e.statusCode } : null;
      var smtpCls = _classifySmtpOutcome(e, lastResponse);
      if (smtpCls === "permanent") {
        ctx.auditEmit("mail.send.deliver.permanent-fail", "failure", {
          recipient: recipient, mxHost: mx.exchange, code: lastResponse && lastResponse.code, reason: e.message,
        });
        return { recipient: recipient, outcome: "permanent",
                 reason: e.message, reasonCode: _enhancedStatusFor(lastResponse, "5.0.0"),
                 mxHost: mx.exchange };
      }
      if (envelope.requireTls === true && e && e.code === "mail/requiretls-not-advertised") {
        _sawRequireTlsRefusal = true;
      } else {
        _sawOtherFailure = true;
      }
      ctx.auditEmit("mail.send.deliver.host-failover", "info", {
        recipient: recipient, mxHost: mx.exchange, code: lastResponse && lastResponse.code, reason: e.message,
      });
    }
  }
  if (_sawRequireTlsRefusal && !_sawOtherFailure) {
    ctx.auditEmit("mail.send.deliver.permanent-fail", "failure", {
      recipient: recipient, mxHost: lastMxHost, reason: (lastErr && lastErr.message) || "",
      cause: "requiretls-unsupported-by-every-mx",
    });
    return { recipient: recipient, outcome: "permanent", mxHost: lastMxHost,
             reason: "requireTls was asked for and no MX host for this recipient " +
                     "advertises REQUIRETLS (RFC 8689 §4.1)",
             reasonCode: "5.7.30" };                                                                     // allow:raw-byte-literal — RFC 8689 §4.4 enhanced status
  }
  return { recipient: recipient, outcome: "transient",
           mxHost: lastMxHost,
           reason: (lastErr && lastErr.message) || "all MX hosts failed transiently",
           reasonCode: _enhancedStatusFor(lastResponse, "4.4.4") };
}

/**
 * @primitive b.mail.send.deliver.create
 * @signature b.mail.send.deliver.create(opts)
 * @since     0.11.24
 * @status    stable
 *
 * Build a turnkey delivery handle. Returns a `deliver(envelope)`
 * function that takes a single multi-recipient envelope, resolves
 * MX records per recipient domain, applies the operator's configured
 * MTA-STS / DANE policy, attempts delivery via `b.mail.transports.smtp`,
 * and returns a per-recipient outcome split into `delivered` /
 * `deferred` / `failed` arrays.
 *
 * Deferred recipients carry `retryAfterMs` budgets the operator's
 * queue / scheduler honors by re-invoking `deliver` for that subset
 * after the budget elapses. The primitive does not own a background
 * scheduler — operator job-runner owns the retry lifecycle.
 *
 * DANE (RFC 7672) authenticates the peer, not just its DNS. When the peer
 * publishes TLSA records, they are fetched and the certificate chain it
 * presents during the handshake is matched against them; a peer whose chain
 * matches none of its own records is refused and the next MX is tried.
 *
 * The TLSA lookup goes through `opts.resolver` when one is supplied, because
 * the DNSSEC assertion below is a statement about THAT resolver. A resolver
 * that cannot answer TLSA is refused rather than bypassed.
 *
 * Because RFC 7672 §1.3 forbids using records that were not DNSSEC-validated
 * and node:dns does not expose the AD bit, only the operator can say whether
 * their resolver validates. `policy.dnssecValidated: true` is that statement,
 * and `dane: "enforce"` requires it: without it every peer that publishes TLSA
 * would be refused while every peer that publishes none was delivered to.
 * Under `"opportunistic"` the records are unusable without it, so none are
 * fetched.
 *
 * Failed recipients trigger DSN composition: a RFC 3464 multipart/
 * report message is built per failed recipient and handed to the
 * operator-supplied `dsn.onPermanentFailure(envelope, recipientResult,
 * dsnMessage)` callback. The callback is responsible for delivering
 * the DSN itself (typically by re-entering the same `deliver` handle
 * with the original sender as recipient — but operators who want
 * a separate transport for DSNs wire that here).
 *
 * @opts
 *   hostname:   string,                    // required — local hostname for HELO/EHLO + DSN Reporting-MTA
 *   port:       number,                    // default 25 (IANA SMTP, RFC 5321) — set 587 (RFC 6409 submission) or 465 (RFC 8314 implicit-TLS) for a smarthost relay
 *   resolver:   object | null,             // optional — b.network.dns.resolver handle; falls back to node:dns when omitted
 *   policy: {
 *     mtaSts:   "enforce" | "testing" | "off",  // default "enforce" — RFC 8461 posture
 *     dane:     "opportunistic" | "enforce" | "off",  // default "opportunistic" — RFC 7672
 *     dnssecValidated: boolean,            // default false — assert the resolver DNSSEC-validates; required by dane "enforce"
 *   },
 *   retry: {
 *     maxAttempts:  number,                // default backoffMs.length + 1, so every rung is used
 *     backoffMs:    Array<number>,         // default [1m, 5m, 15m, 1h, 4h, 8h, 12h, 24h, 24h, 24h] — gives up after ~4 days (RFC 5321 §4.5.4.1)
 *   },
 *   dsn: {
 *     from:     string,                    // required when dsn.onPermanentFailure is set
 *     onPermanentFailure: function (envelope, result, dsnMessage) → Promise,
 *   },
 *   timeouts: {
 *     mxLookupMs: number,                  // default 10s
 *     perHostMs:  number,                  // default 60s
 *   },
 *   audit:      boolean,                   // default true
 *
 * @example
 *   var deliver = b.mail.send.deliver.create({
 *     hostname: "mta1.example.com",
 *     policy:   { mtaSts: "enforce", dane: "opportunistic" },
 *     dsn:      { from: "mailer-daemon@example.com",
 *                 onPermanentFailure: function (env, res, dsn) {
 *                   return deliver({ from: env.from, to: [env.from], rfc822: Buffer.from(dsn) });
 *                 } },
 *   });
 *   var result = await deliver({
 *     from:   "ops@example.com",
 *     to:     ["alice@recipient.com"],
 *     rfc822: messageBuffer,
 *   });
 *   typeof result.delivered;   // → "object" (array)
 *   typeof result.deferred;    // → "object" (array)
 *   typeof result.failed;      // → "object" (array)
 */
function create(opts) {
  if (!opts || typeof opts !== "object") {
    throw new DeliverError("deliver/bad-opts", "mail.send.deliver.create: opts is required");
  }
  validateOpts(opts,
    ["hostname", "resolver", "policy", "retry", "dsn", "timeouts", "audit", "transportFactory", "port"],
    "mail.send.deliver.create");
  validateOpts.shape(opts, {
    hostname:         { rule: "required-string", code: "deliver/bad-hostname",
                        label: "mail.send.deliver.create: hostname (local HELO/EHLO + DSN Reporting-MTA)" },
    port:             { rule: "optional-port", code: "deliver/bad-port" },
    resolver:         { rule: "optional-plain-object", code: "deliver/bad-resolver",
                        label: "mail.send.deliver.create: resolver (b.network.dns.resolver handle)" },
    policy:           { rule: "optional-plain-object", code: "deliver/bad-policy" },
    retry:            { rule: "optional-plain-object", code: "deliver/bad-retry" },
    dsn:              { rule: "optional-plain-object", code: "deliver/bad-dsn" },
    timeouts:         { rule: "optional-plain-object", code: "deliver/bad-timeouts" },
    audit:            { rule: "optional-boolean", code: "deliver/bad-audit" },
    transportFactory: { rule: "optional-function", code: "deliver/bad-transport-factory" },
  }, "mail.send.deliver.create", DeliverError, "deliver/bad-opts");
  var port = opts.port || DEFAULT_PORT_SMTP;

  var policy = opts.policy || {};
  validateOpts(policy, ["mtaSts", "dane", "dnssecValidated"], "mail.send.deliver.create.policy");
  var policyMtaSts = policy.mtaSts || "enforce";
  if (["enforce", "testing", "off"].indexOf(policyMtaSts) === -1) {
    throw new DeliverError("deliver/bad-policy-mtaSts",
      "mail.send.deliver.create.policy.mtaSts must be enforce|testing|off");
  }
  var policyDane = policy.dane || "opportunistic";
  if (["opportunistic", "enforce", "off"].indexOf(policyDane) === -1) {
    throw new DeliverError("deliver/bad-policy-dane",
      "mail.send.deliver.create.policy.dane must be opportunistic|enforce|off");
  }
  if (policy.dnssecValidated !== undefined && typeof policy.dnssecValidated !== "boolean") {
    throw new DeliverError("deliver/bad-policy-dnssec",
      "mail.send.deliver.create.policy.dnssecValidated must be a boolean when set");
  }
  var daneDnssecValidated = policy.dnssecValidated === true;
  if (policyDane === "enforce" && !daneDnssecValidated) {
    throw new DeliverError("deliver/dane-no-dnssec",
      "policy.dane \"enforce\" requires policy.dnssecValidated: true — TLSA records " +
      "must be DNSSEC-validated before use (RFC 7672 §1.3), and without that " +
      "assertion enforce can only refuse the peers that publish them. Set it when " +
      "the resolver validates DNSSEC; otherwise use \"opportunistic\" or \"off\"");
  }

  var retryOpts = opts.retry || {};
  validateOpts(retryOpts, ["maxAttempts", "backoffMs"], "mail.send.deliver.create.retry");
  validateOpts.optionalPositiveInt(retryOpts.maxAttempts,
    "mail.send.deliver.create.retry.maxAttempts", DeliverError, "deliver/bad-retry-maxAttempts");
  var backoffMs = Array.isArray(retryOpts.backoffMs) && retryOpts.backoffMs.length > 0
    ? retryOpts.backoffMs.slice() : DEFAULT_RETRY_BACKOFF_MS.slice();
  var maxAttempts = retryOpts.maxAttempts !== undefined
    ? retryOpts.maxAttempts : backoffMs.length + 1;

  var timeouts = opts.timeouts || {};
  validateOpts(timeouts, ["mxLookupMs", "perHostMs"], "mail.send.deliver.create.timeouts");
  validateOpts.shape(timeouts, {
    mxLookupMs: { rule: "optional-positive-int", code: "deliver/bad-timeout-mxLookupMs",
                  label: "mail.send.deliver.create.timeouts.mxLookupMs" },
    perHostMs:  { rule: "optional-positive-int", code: "deliver/bad-timeout-perHostMs",
                  label: "mail.send.deliver.create.timeouts.perHostMs" },
  }, "mail.send.deliver.create.timeouts", DeliverError, "deliver/bad-timeouts");
  var mxLookupTimeoutMs = timeouts.mxLookupMs !== undefined
    ? timeouts.mxLookupMs : DEFAULT_MX_LOOKUP_TIMEOUT_MS;
  var perHostTimeoutMs = timeouts.perHostMs !== undefined
    ? timeouts.perHostMs : DEFAULT_PER_HOST_TIMEOUT_MS;

  var dsnOpts = opts.dsn || null;
  if (dsnOpts) {
    validateOpts(dsnOpts, ["from", "onPermanentFailure"],
      "mail.send.deliver.create.dsn");
    validateOpts.requireNonEmptyString(dsnOpts.from,
      "mail.send.deliver.create.dsn.from", DeliverError, "deliver/bad-dsn-from");
    if (typeof dsnOpts.onPermanentFailure !== "function") {
      throw new DeliverError("deliver/bad-dsn-callback",
        "mail.send.deliver.create.dsn.onPermanentFailure must be a function");
    }
  }

  var auditEnabled = opts.audit !== false;
  var _auditEmit = audit().namespaced(null, { audit: auditEnabled });

  async function deliver(envelope) {
    if (!envelope || typeof envelope !== "object") {
      throw new DeliverError("deliver/bad-envelope",
        "deliver: envelope is required");
    }
    if (typeof envelope.from !== "string") {
      throw new DeliverError("deliver/bad-envelope-from",
        "deliver.envelope.from must be a string — use \"\" for the null " +
        "reverse path (MAIL FROM:<>) that RFC 5321 requires of a DSN");
    }
    if (!Array.isArray(envelope.to) || envelope.to.length === 0) {
      throw new DeliverError("deliver/bad-envelope-to",
        "deliver.envelope.to must be a non-empty array");
    }
    if (envelope.to.length > MAX_RECIPIENTS_PER_CALL) {
      throw new DeliverError("deliver/too-many-recipients",
        "deliver.envelope.to length " + envelope.to.length + " exceeds cap " + MAX_RECIPIENTS_PER_CALL);
    }
    if (!Buffer.isBuffer(envelope.rfc822) && typeof envelope.rfc822 !== "string") {
      throw new DeliverError("deliver/bad-envelope-rfc822",
        "deliver.envelope.rfc822 must be a Buffer or string (raw RFC 822 message bytes)");
    }
    var raw = Buffer.isBuffer(envelope.rfc822) ? envelope.rfc822 : Buffer.from(envelope.rfc822, "utf8");

    var ctx = {
      resolver:           opts.resolver || null,
      policy:             { mtaSts: policyMtaSts, dane: policyDane,
                            dnssecValidated: daneDnssecValidated },
      hostname:           opts.hostname,
      port:               port,
      mxLookupTimeoutMs:  mxLookupTimeoutMs,
      perHostTimeoutMs:   perHostTimeoutMs,
      transportFactory:   opts.transportFactory || null,
      auditEmit:          _auditEmit,
    };

    var delivered = [];
    var deferred  = [];
    var failed    = [];

    for (var i = 0; i < envelope.to.length; i += 1) {
      var recipient = envelope.to[i];
      var res = await _deliverOne({
        from:        envelope.from,
        rfc822:      raw,
        requireTls:  envelope.requireTls === true,
      }, recipient, ctx);

      if (res.outcome === "delivered") {
        delivered.push({
          recipient:         res.recipient,
          mxHost:            res.mxHost,
          mxPriority:        res.mxPriority,
          deliveredAt:       Date.now(),
          transportResponse: res.transportResponse || null,
        });
        continue;
      }
      if (res.outcome === "transient") {
        var attempts = (envelope.attempt || 0) + 1;
        if (attempts >= maxAttempts) {
          res.outcome = "permanent";
          res.reason = (res.reason || "retry exhausted") + " (after " + attempts + " attempts)";
          res.reasonCode = String(res.reasonCode || "").charAt(0) === "4"
            ? "5" + String(res.reasonCode).slice(1)
            : (res.reasonCode || "5.0.0");
        } else {
          var idx = Math.min(attempts - 1, backoffMs.length - 1);
          deferred.push({
            recipient:     res.recipient,
            mxHost:        res.mxHost === undefined ? null : res.mxHost,
            reason:        res.reason,
            reasonCode:    res.reasonCode,
            attempt:       attempts,
            retryAfterMs:  backoffMs[idx],
          });
          continue;
        }
      }
      var dsnSent = false;
      if (dsnOpts && envelope.from !== "") {
        try {
          var dsnMessage = _buildDsnMessage({
            dsnFrom:         dsnOpts.from,
            originalFrom:    envelope.from,
            recipient:       res.recipient,
            reason:          res.reason,
            statusCode:      res.reasonCode,
            reportingMta:    ctx.hostname,
            originalHeaders: _extractHeaderBlock(raw),
          });
          await dsnOpts.onPermanentFailure(envelope, res, dsnMessage);
          dsnSent = true;
        } catch (dsnErr) {
          _auditEmit("mail.send.deliver.dsn-failed", "failure", {
            recipient: res.recipient, error: dsnErr.message,
          });
        }
      }
      failed.push({
        recipient:  res.recipient,
        reason:     res.reason,
        reasonCode: res.reasonCode,
        mxHost:     res.mxHost || null,
        dsnSent:    dsnSent,
      });
    }

    _auditEmit("mail.send.deliver.batch", "success", {
      from:        envelope.from,
      delivered:   delivered.length,
      deferred:    deferred.length,
      failed:      failed.length,
    });

    return {
      delivered: delivered,
      deferred:  deferred,
      failed:    failed,
    };
  }

  deliver.classifyOutcome = _classifySmtpOutcome;
  deliver.buildDsn        = _buildDsnMessage;
  deliver.retryPolicy     = function () {
    var total = 0;
    for (var i = 0; i < maxAttempts - 1; i += 1) {
      total += backoffMs[Math.min(i, backoffMs.length - 1)];
    }
    return { maxAttempts: maxAttempts, backoffMs: backoffMs.slice(), giveUpMs: total };
  };
  return deliver;
}

var HEADER_SEP_CRLF = Buffer.from("\r\n\r\n", "ascii");
var HEADER_SEP_LF   = Buffer.from("\n\n", "ascii");
var BASE64_LINE_CHARS = 76;

function _extractHeaderBlock(raw) {
  var buf;
  if (Buffer.isBuffer(raw)) buf = raw;
  else if (typeof raw === "string") buf = Buffer.from(raw, "utf8");
  else {
    throw new DeliverError("deliver/bad-dsn-field",
      "originalHeaders source must be a Buffer or a string");
  }
  var sep = buf.indexOf(HEADER_SEP_CRLF);
  var width = HEADER_SEP_CRLF.length / 2;
  if (sep === -1) {
    sep = buf.indexOf(HEADER_SEP_LF);
    width = HEADER_SEP_LF.length / 2;
  }
  var block = sep === -1 ? buf : buf.subarray(0, sep + width);
  var text = block.toString("utf8");
  if (Buffer.compare(Buffer.from(text, "utf8"), block) === 0) {
    return { text: text, charset: "utf-8", encoding: null };
  }
  var b64 = block.toString("base64");
  var wrapped = "";
  for (var i = 0; i < b64.length; i += BASE64_LINE_CHARS) {
    wrapped += b64.slice(i, i + BASE64_LINE_CHARS) + "\r\n";
  }
  return { text: wrapped, charset: "iso-8859-1", encoding: "base64" };
}

module.exports = {
  create:        create,
  DeliverError:  DeliverError,
};

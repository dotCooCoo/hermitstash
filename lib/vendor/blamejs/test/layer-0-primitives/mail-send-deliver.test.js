// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.send.deliver — turnkey outbound composer.
 *
 * Tests exercise the operator-facing surface without opening real
 * SMTP sockets:
 *   - factory validation
 *   - outcome classifier (2xx/4xx/5xx + network errors)
 *   - DSN composition (RFC 3464 multipart/report shape)
 *   - per-recipient defer/fail bookkeeping via a stubbed transport
 *
 * Live wire-protocol coverage lives in test/integration/ — this layer
 * mocks the SMTP transport to verify the composer's classify-route-
 * compose logic. Error / adversarial branches are exercised here too:
 * classifier fallthroughs, every create() validation code, resolver
 * shape variance + timeout + node:dns fallback, the MTA-STS / DANE
 * policy matrices (fault-injected by swapping b.network.smtp.policy's
 * mtaSts / dane exports for in-memory stubs, restored in a finally),
 * DSN default fields + callback failure, header-block separator
 * variants, and the retry-budget clamp.
 */

var helpers        = require("../helpers");
var smtpPolicyMod  = require("../../lib/network-smtp-policy");
var dnsPromises    = require("node:dns").promises;

var b     = helpers.b;
var check = helpers.check;

// ---- Surface ----

function testSurface() {
  check("b.mail.send namespace",       typeof b.mail.send === "object");
  check("b.mail.send.deliver fn",      typeof b.mail.send.deliver === "function");
  check("DeliverError class",          typeof b.mail.send.deliver.DeliverError === "function");
}

// ---- Factory validation ----

function testFactoryRefusesBadOpts() {
  function threw(fn) {
    try { fn(); return null; }
    catch (e) { return e; }
  }
  var e1 = threw(function () { b.mail.send.deliver(); });
  check("create() w/o opts → DeliverError", e1 && e1.code === "deliver/bad-opts");

  var e2 = threw(function () { b.mail.send.deliver({}); });
  check("create({}) w/o hostname → DeliverError",
    e2 && e2.code === "deliver/bad-hostname");

  var e3 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { mtaSts: "bogus" } });
  });
  check("bad policy.mtaSts → DeliverError",
    e3 && e3.code === "deliver/bad-policy-mtaSts");

  var e4 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { dane: "lax" } });
  });
  check("bad policy.dane → DeliverError",
    e4 && e4.code === "deliver/bad-policy-dane");

  var e5 = threw(function () {
    b.mail.send.deliver({
      hostname: "m.example",
      dsn:      { from: "mailer@m.example" },                   // missing onPermanentFailure
    });
  });
  check("dsn without onPermanentFailure → DeliverError",
    e5 && e5.code === "deliver/bad-dsn-callback");

  var e6 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", port: 70000 }); // out of [1,65535]
  });
  check("out-of-range port → DeliverError",
    e6 && e6.code === "deliver/bad-port");

  var e7 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", port: 0 });     // 0 is not a connect port
  });
  check("port 0 → DeliverError (connect port must be >=1)",
    e7 && e7.code === "deliver/bad-port");

  // retry.maxAttempts / timeouts.mxLookupMs / timeouts.perHostMs are
  // config-time entry-point opts: a typo must throw at create(), not be
  // swallowed by a valid-or-default fallback. Absent keeps the default.
  var e8 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", retry: { maxAttempts: "5" } });
  });
  check("retry.maxAttempts as string → DeliverError",
    e8 && e8.code === "deliver/bad-retry-maxAttempts");

  var e9 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", retry: { maxAttempts: -1 } });
  });
  check("retry.maxAttempts negative → DeliverError",
    e9 && e9.code === "deliver/bad-retry-maxAttempts");

  var e10 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", retry: { maxAttempts: 0 } });
  });
  check("retry.maxAttempts 0 → DeliverError (must be >= 1)",
    e10 && e10.code === "deliver/bad-retry-maxAttempts");

  var e11 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", timeouts: { mxLookupMs: -1 } });
  });
  check("timeouts.mxLookupMs negative → DeliverError",
    e11 && e11.code === "deliver/bad-timeout-mxLookupMs");

  var e12 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", timeouts: { mxLookupMs: "10000" } });
  });
  check("timeouts.mxLookupMs as string → DeliverError",
    e12 && e12.code === "deliver/bad-timeout-mxLookupMs");

  var e13 = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", timeouts: { perHostMs: 0 } });
  });
  check("timeouts.perHostMs 0 → DeliverError (must be >= 1)",
    e13 && e13.code === "deliver/bad-timeout-perHostMs");

  // Absent retry / timeouts keys keep the defaults — create() succeeds.
  var okDefault = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", retry: {}, timeouts: {}, audit: false });
  });
  check("absent retry/timeouts keys keep defaults (create succeeds)", okDefault === null);

  // Valid integer values are accepted unchanged.
  var okValid = threw(function () {
    b.mail.send.deliver({
      hostname: "m.example",
      retry:    { maxAttempts: 3 },
      timeouts: { mxLookupMs: 2000, perHostMs: 30000 },
      audit:    false,
    });
  });
  check("valid retry/timeouts values accepted (create succeeds)", okValid === null);
}

// ---- Submission/smarthost port ----

// The default is IANA SMTP 25; an operator routing through a submission
// relay sets port 587 (RFC 6409) / 465 (RFC 8314). The configured port
// must reach the transport factory.
async function testPortReachesTransport() {
  var ports = [];
  var fakeResolver = {
    queryMx: async function (domain) {
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var fakeTransport = function (opts) {
    ports.push(opts.port);
    return { send: async function () { return { ok: true, code: 250 }; } };
  };

  var deliverDefault = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver,
    policy: { mtaSts: "off", dane: "off" }, transportFactory: fakeTransport, audit: false,
  });
  await deliverDefault({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
  check("port: default is 25 when unset", ports[ports.length - 1] === 25);

  var deliver587 = b.mail.send.deliver({
    hostname: "mta1.example.com", resolver: fakeResolver, port: 587,
    policy: { mtaSts: "off", dane: "off" }, transportFactory: fakeTransport, audit: false,
  });
  await deliver587({ from: "ops@example.com", to: ["b@recipient.com"], rfc822: Buffer.from("hi") });
  check("port: configured 587 reaches the transport", ports[ports.length - 1] === 587);
}

// ---- Envelope shape validation ----

async function testEnvelopeValidation() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });
  function threwAsync(fn) {
    return fn().then(function () { return null; }, function (e) { return e; });
  }
  check("envelope must be object",
    (await threwAsync(function () { return deliver(); })).code === "deliver/bad-envelope");
  check("envelope.from required",
    (await threwAsync(function () { return deliver({ to: ["a@b"], rfc822: Buffer.from("x") }); })).code === "deliver/bad-envelope-from");
  check("envelope.to required",
    (await threwAsync(function () { return deliver({ from: "x@y", rfc822: Buffer.from("x") }); })).code === "deliver/bad-envelope-to");
  check("envelope.to empty array refused",
    (await threwAsync(function () { return deliver({ from: "x@y", to: [], rfc822: Buffer.from("x") }); })).code === "deliver/bad-envelope-to");
  check("envelope.rfc822 must be Buffer/string",
    (await threwAsync(function () { return deliver({ from: "x@y", to: ["a@b"], rfc822: 42 }); })).code === "deliver/bad-envelope-rfc822");
}

// ---- Outcome classifier ----

function testOutcomeClassifier() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });
  // SMTP response codes.
  check("250 → delivered",  deliver.classifyOutcome(null, { code: 250 }) === "delivered");
  check("220 → delivered",  deliver.classifyOutcome(null, { code: 220 }) === "delivered");
  check("451 → transient",  deliver.classifyOutcome(null, { code: 451 }) === "transient");
  check("452 → transient",  deliver.classifyOutcome(null, { code: 452 }) === "transient");
  check("550 → permanent",  deliver.classifyOutcome(null, { code: 550 }) === "permanent");
  check("554 → permanent",  deliver.classifyOutcome(null, { code: 554 }) === "permanent");
  // Network errors → transient (allow MX-failover).
  check("ECONNREFUSED → transient",
    deliver.classifyOutcome({ code: "ECONNREFUSED" }, null) === "transient");
  check("ETIMEDOUT → transient",
    deliver.classifyOutcome({ code: "ETIMEDOUT" }, null) === "transient");
  check("ENOTFOUND → transient",
    deliver.classifyOutcome({ code: "ENOTFOUND" }, null) === "transient");
  // Policy-class errors → permanent.
  check("mta-sts-mx-mismatch → permanent",
    deliver.classifyOutcome({ code: "deliver/mta-sts-mx-mismatch", message: "" }, null) === "permanent");
  check("dane-fetch-failed (enforce) → permanent",
    deliver.classifyOutcome({ code: "deliver/dane-fetch-failed", message: "" }, null) === "permanent");
}

// ---- DSN composer (RFC 3464 multipart/report) ----

function testDsnComposer() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });
  var dsn = deliver.buildDsn({
    dsnFrom:         "mailer-daemon@m.example",
    originalFrom:    "alice@sender.com",
    recipient:       "bob@dest.com",
    reason:          "550 5.1.1 mailbox not found",
    statusCode:      "5.1.1",
    reportingMta:    "mta1.example.com",
    originalHeaders: "From: alice@sender.com\r\nTo: bob@dest.com\r\nSubject: greetings\r\nMessage-Id: <m@x>\r\n",
  });

  check("DSN: From header carries mailer-daemon",   /^From: Mail Delivery System <mailer-daemon@m\.example>/m.test(dsn));
  check("DSN: To header carries original sender",   /^To: alice@sender\.com/m.test(dsn));
  check("DSN: Subject is failure notification",     /^Subject: Delivery Status Notification \(Failure\)/m.test(dsn));
  check("DSN: Content-Type multipart/report",       /Content-Type: multipart\/report; report-type=delivery-status/m.test(dsn));
  check("DSN: Auto-Submitted header present",       /^Auto-Submitted: auto-replied/m.test(dsn));
  check("DSN: per-recipient Final-Recipient",       /^Final-Recipient: rfc822; bob@dest\.com/m.test(dsn));
  check("DSN: Action: failed",                      /^Action: failed/m.test(dsn));
  check("DSN: enhanced Status code",                /^Status: 5\.1\.1/m.test(dsn));
  check("DSN: Diagnostic-Code carries the smtp reason", /^Diagnostic-Code: smtp; 550 5\.1\.1 mailbox not found/m.test(dsn));
  check("DSN: Reporting-MTA matches the configured hostname",
    /^Reporting-MTA: dns; mta1\.example\.com/m.test(dsn));
  check("DSN: original headers section",            dsn.indexOf("From: alice@sender.com") > 0);
  check("DSN: boundary closes correctly",           /\r\n--dsn-[a-z0-9-]+--\r\n$/m.test(dsn));
}

// ---- DSN CRLF/NUL header-injection guard (RFC 5321/5322 line safety) ----

function testDsnRejectsCrlfHeaderInjection() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });
  function threw(fn) { try { fn(); return null; } catch (e) { return e; } }

  // The 5xx diagnostic `reason` is echoed from the REMOTE peer's SMTP
  // reply — free-form and legitimately multi-line, so it is folded to a
  // single line. A malicious peer returning a reply that carries CR/LF
  // must not be able to start a new header line or forge a report part.
  var folded = deliver.buildDsn({
    dsnFrom:      "mailer-daemon@m.example",
    originalFrom: "alice@sender.com",
    recipient:    "bob@dest.com",
    reason:       "550 mailbox full\r\nX-Injected: evil\r\n--dsn-forged\r\nContent-Type: text/evil",
    statusCode:   "5.2.2",
  });
  check("DSN: injected reason cannot start a new header line",
    !/^X-Injected:/m.test(folded));
  check("DSN: injected reason cannot forge a report part boundary",
    !/^--dsn-forged/m.test(folded));
  check("DSN: injected reason cannot forge a part Content-Type",
    !/^Content-Type: text\/evil/m.test(folded));

  // A NUL in the free-text reason is stripped by the fold, not serialized
  // into the Diagnostic-Code header line (NUL is never valid in an RFC 5322
  // header and downstream SMTP parsers treat it specially).
  var withNul = deliver.buildDsn({
    dsnFrom: "mailer-daemon@m.example", originalFrom: "alice@sender.com",
    recipient: "bob@dest.com", reason: "550 full" + String.fromCharCode(0) + "evil",
  });
  check("DSN: NUL in reason is stripped from the output",
    withNul.indexOf(String.fromCharCode(0)) === -1);

  // Structured fields (addresses, reporting-MTA name, enhanced status)
  // can never legitimately carry CR/LF/NUL — a bounce built from a
  // hostile original sender or peer fails closed instead of smuggling.
  var e1 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com\r\nBcc: victim@evil.test",
      recipient: "bob@dest.com", reason: "550" });
  });
  check("DSN: CRLF in originalFrom throws deliver/bad-dsn-field",
    e1 && e1.code === "deliver/bad-dsn-field");
  var e2 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com",
      recipient: "bob@dest.com\r\nRcpt-To: victim@evil.test", reason: "550" });
  });
  check("DSN: CRLF in recipient throws deliver/bad-dsn-field",
    e2 && e2.code === "deliver/bad-dsn-field");
  var e3 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com", recipient: "bob@dest.com",
      reason: "550", reportingMta: "mta.example\r\nX-Evil: 1" });
  });
  check("DSN: CRLF in reportingMta throws deliver/bad-dsn-field",
    e3 && e3.code === "deliver/bad-dsn-field");
  var e4 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com", recipient: "bob@dest.com",
      reason: "550", statusCode: "5.0.0\r\nX-Evil: 1" });
  });
  check("DSN: CRLF in statusCode throws deliver/bad-dsn-field",
    e4 && e4.code === "deliver/bad-dsn-field");
  var e5 = threw(function () {
    deliver.buildDsn({ dsnFrom: "mailer-daemon@m.example",
      originalFrom: "alice@sender.com" + String.fromCharCode(0) + "evil", recipient: "bob@dest.com",
      reason: "550" });
  });
  check("DSN: NUL in originalFrom throws deliver/bad-dsn-field",
    e5 && e5.code === "deliver/bad-dsn-field");
}

// ---- Delivery happy-path (stubbed MX + transport) ----

async function testDeliveryHappyPathStubbed() {
  // Stub the resolver + the transport factory (via opts.transportFactory)
  // so neither the MX lookup nor the SMTP wire layer reaches the
  // network in this composer-logic test.
  var captured = [];
  var fakeResolver = {
    queryMx: async function (domain) {
      captured.push({ kind: "mx", domain: domain });
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var fakeTransport = function (opts) {
    captured.push({ kind: "transport", host: opts.host });
    return {
      send: async function (msg) {
        captured.push({ kind: "send", to: msg.to });
        return { ok: true, code: 250 };
      },
    };
  };
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    audit:            false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["alice@recipient.com"],
    rfc822: Buffer.from("From: ops@example.com\r\nTo: alice@recipient.com\r\nSubject: hi\r\n\r\nbody"),
  });
  check("happy-path: 1 delivered",                   result.delivered.length === 1);
  check("happy-path: 0 deferred",                    result.deferred.length === 0);
  check("happy-path: 0 failed",                      result.failed.length === 0);
  check("happy-path: delivered.recipient correct",   result.delivered[0].recipient === "alice@recipient.com");
  check("happy-path: delivered.mxHost from resolver", result.delivered[0].mxHost === "mx1.recipient.com");
  check("happy-path: MX lookup happened",            captured.some(function (e) { return e.kind === "mx" && e.domain === "recipient.com"; }));
  check("happy-path: transport opened to MX host",   captured.some(function (e) { return e.kind === "transport" && e.host === "mx1.recipient.com"; }));
}

// ---- Multi-@ recipient is refused before routing ----

async function testMultiAtRecipientRefused() {
  // A recipient with two '@' (victim@internal.host@external.com) must be
  // refused as a permanent bad-address, NOT routed to the LEFTMOST segment's MX
  // (split("@")[1] = internal.host) — that would mis-deliver / exfiltrate to an
  // unintended host (CWE-290).
  var mxDomains = [];
  var fakeResolver = {
    queryMx: async function (domain) {
      mxDomains.push(domain);
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var fakeTransport = function () {
    return { send: async function () { return { ok: true, code: 250 }; } };
  };
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    audit:            false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["victim@internal.host@external.com"],
    rfc822: Buffer.from("From: ops@example.com\r\nSubject: x\r\n\r\nbody"),
  });
  check("multi-@ recipient → permanent failure, not delivered",
        result.failed.length === 1 && result.delivered.length === 0);
  check("multi-@ recipient → no MX lookup on the leftmost segment",
        mxDomains.indexOf("internal.host") === -1);
}

// ---- Defer on transient + DSN on permanent ----

async function testTransientDefersPermanentFails() {
  var fakeResolver = {
    queryMx: async function (domain) {
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var dsnInvocations = [];

  // First recipient: transport returns a 4xx (transient). Second
  // recipient: 5xx (permanent). The classifier routes the first to
  // deferred[], the second to failed[] with a DSN composed + handed
  // to the operator-supplied onPermanentFailure callback.
  var fakeTransport = function () {
    return {
      send: async function (msg) {
        var to = msg.to[0];
        if (to === "transient@example.com") {
          var err = new Error("temporary failure");
          err.smtpResponse = { code: 451 };
          throw err;
        }
        if (to === "permanent@example.com") {
          var err2 = new Error("550 5.1.1 user not found");
          err2.smtpResponse = { code: 550 };
          throw err2;
        }
        return { ok: true, code: 250 };
      },
    };
  };
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    dsn:      {
      from: "mailer-daemon@example.com",
      onPermanentFailure: async function (envelope, result, dsnMessage) {
        dsnInvocations.push({ recipient: result.recipient, dsnHasReport: dsnMessage.indexOf("Content-Type: multipart/report") !== -1 });
      },
    },
    audit:    false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["transient@example.com", "permanent@example.com"],
    rfc822: Buffer.from("From: ops@example.com\r\nTo: transient,permanent\r\nSubject: t\r\n\r\nbody"),
  });
  check("split: 0 delivered", result.delivered.length === 0);
  check("split: 1 deferred",  result.deferred.length === 1);
  check("split: 1 failed",    result.failed.length === 1);
  check("split: deferred is the transient recipient",
    result.deferred[0].recipient === "transient@example.com");
  check("split: deferred carries retryAfterMs budget",
    typeof result.deferred[0].retryAfterMs === "number" && result.deferred[0].retryAfterMs > 0);
  check("split: failed is the permanent recipient",
    result.failed[0].recipient === "permanent@example.com");
  check("split: failed.dsnSent flag",   result.failed[0].dsnSent === true);
  check("split: DSN delivered to operator callback",
    dsnInvocations.length === 1 && dsnInvocations[0].recipient === "permanent@example.com");
  check("split: DSN body carries multipart/report",
    dsnInvocations[0].dsnHasReport === true);
}

// ---- retry.maxAttempts value flows through to the retry budget ----

// A valid maxAttempts must reach the deferred-vs-failed routing, not just
// pass validation. With maxAttempts:1, the first transient failure exhausts
// the budget (attempts 1 >= 1) and converts transient → permanent → failed[]
// rather than landing in deferred[]. The default (5) keeps it deferred.
async function testMaxAttemptsFlowsThrough() {
  var fakeResolver = {
    queryMx: async function (domain) {
      return [{ exchange: "mx1." + domain, priority: 10 }];
    },
  };
  var transientTransport = function () {
    return {
      send: async function () {
        var err = new Error("temporary failure");
        err.smtpResponse = { code: 451 };
        throw err;
      },
    };
  };
  var envelope = {
    from:   "ops@example.com",
    to:     ["transient@example.com"],
    rfc822: Buffer.from("hi"),
  };

  var deliverBudget1 = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: transientTransport,
    retry:            { maxAttempts: 1 },
    audit:            false,
  });
  var r1 = await deliverBudget1(envelope);
  check("maxAttempts:1 exhausts budget on first transient → failed",
    r1.failed.length === 1 && r1.deferred.length === 0);

  var deliverDefault = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: transientTransport,
    audit:            false,
  });
  var r2 = await deliverDefault(envelope);
  check("default maxAttempts keeps a single transient deferred",
    r2.deferred.length === 1 && r2.failed.length === 0);
}

// ---- No-MX (RFC 7505 null MX) ----

async function testNullMx() {
  var fakeResolver = {
    queryMx: async function () {
      // RFC 7505 null MX — single record with empty exchange.
      return [{ exchange: ".", priority: 0 }];
    },
  };
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: fakeResolver,
    policy:   { mtaSts: "off", dane: "off" },
    audit:    false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["alice@refuses-mail.example"],
    rfc822: Buffer.from("From: ops@example.com\r\nTo: alice\r\nSubject: t\r\n\r\nbody"),
  });
  check("null-MX: 1 failed (permanent)",  result.failed.length === 1);
  check("null-MX: reasonCode is 5.1.2",   result.failed[0].reasonCode === "5.1.2");
  check("null-MX: 0 deferred",            result.deferred.length === 0);
}

// ---- MX-failover when first host is transient ----

async function testMxFailover() {
  var fakeResolver = {
    queryMx: async function (domain) {
      return [
        { exchange: "mx1." + domain, priority: 10 },
        { exchange: "mx2." + domain, priority: 20 },
      ];
    },
  };
  var transportCalls = [];
  var fakeTransport = function (opts) {
    transportCalls.push(opts.host);
    return {
      send: async function () {
        if (opts.host === "mx1.example.com") {
          var err = new Error("primary MX refused");
          err.code = "ECONNREFUSED";
          throw err;
        }
        return { ok: true, code: 250 };
      },
    };
  };
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    audit:            false,
  });
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["alice@example.com"],
    rfc822: Buffer.from("hi"),
  });
  check("failover: 1 delivered",                 result.delivered.length === 1);
  check("failover: 0 deferred + 0 failed",       result.deferred.length === 0 && result.failed.length === 0);
  check("failover: tried mx1 first, then mx2",   transportCalls[0] === "mx1.example.com" && transportCalls[1] === "mx2.example.com");
  check("failover: delivered via mx2",            result.delivered[0].mxHost === "mx2.example.com");
}

// ---- local test utilities ----

function threw(fn) {
  try { fn(); return null; } catch (e) { return e; }
}
function okResolver(mxFor) {
  return { queryMx: async function (domain) { return mxFor(domain); } };
}
function okTransport() {
  return function () {
    return { send: async function () { return { ok: true, code: 250 }; } };
  };
}

// Swap b.network.smtp.policy's mtaSts / dane export objects for stubs.
// The top-level exports object is mutable (only the inner objects are
// frozen), so property reassignment is visible to the deliver module's
// cached lazyRequire handle. Restored in finally.
async function withSmtpPolicyStub(overrides, body) {
  var origMta  = smtpPolicyMod.mtaSts;
  var origDane = smtpPolicyMod.dane;
  try {
    if (overrides.mtaSts) smtpPolicyMod.mtaSts = overrides.mtaSts;
    if (overrides.dane)   smtpPolicyMod.dane   = overrides.dane;
    return await body();
  } finally {
    smtpPolicyMod.mtaSts = origMta;
    smtpPolicyMod.dane   = origDane;
  }
}

async function withNodeDnsResolveMx(fake, body) {
  var orig = dnsPromises.resolveMx;
  try {
    dnsPromises.resolveMx = fake;
    return await body();
  } finally {
    dnsPromises.resolveMx = orig;
  }
}

// ---- Outcome classifier — fallthrough / OR-alternative branches ----

function testClassifierFallthroughs() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });

  // No error, no response → the terminal `return "transient"`.
  check("classify(null,null) → transient",
    deliver.classifyOutcome(null, null) === "transient");
  // 3xx is neither 2/4/5xx → falls through to transient.
  check("classify 3xx → transient (fallthrough)",
    deliver.classifyOutcome(null, { code: 354 }) === "transient");
  // Response present but no code → String("") matches nothing → transient.
  check("classify response w/o code → transient",
    deliver.classifyOutcome(null, {}) === "transient");
  // Policy signal in the MESSAGE only (empty code) → the OR alternative
  // of the policy-class regex must still classify permanent.
  check("classify policy-signal via message only → permanent",
    deliver.classifyOutcome({ code: "", message: "REQUIRETLS was not offered" }, null) === "permanent");
  // Generic error code that is neither a network code nor a policy
  // signal → transient (the err-branch fallthrough).
  check("classify generic err code → transient",
    deliver.classifyOutcome({ code: "EPIPE", message: "broken pipe" }, null) === "transient");
  check("classify ENETUNREACH → transient",
    deliver.classifyOutcome({ code: "ENETUNREACH" }, null) === "transient");
  // Response wins over err when both present.
  check("classify 550 response beats err → permanent",
    deliver.classifyOutcome({ code: "ECONNREFUSED" }, { code: 550 }) === "permanent");
}

// ---- create(): remaining shape-validation codes ----

function testCreateValidationCodes() {
  var eUnknown = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", bogusKey: 1 });
  });
  check("unknown top-level opt → throws (unknown option)",
    eUnknown && /unknown option/.test(eUnknown.message || ""));

  var ePolicy = threw(function () { b.mail.send.deliver({ hostname: "m.example", policy: 5 }); });
  check("policy non-object → deliver/bad-policy", ePolicy && ePolicy.code === "deliver/bad-policy");

  var eRetry = threw(function () { b.mail.send.deliver({ hostname: "m.example", retry: 5 }); });
  check("retry non-object → deliver/bad-retry", eRetry && eRetry.code === "deliver/bad-retry");

  var eDsn = threw(function () { b.mail.send.deliver({ hostname: "m.example", dsn: 5 }); });
  check("dsn non-object → deliver/bad-dsn", eDsn && eDsn.code === "deliver/bad-dsn");

  var eTo = threw(function () { b.mail.send.deliver({ hostname: "m.example", timeouts: 5 }); });
  check("timeouts non-object → deliver/bad-timeouts", eTo && eTo.code === "deliver/bad-timeouts");

  var eRes = threw(function () { b.mail.send.deliver({ hostname: "m.example", resolver: 5 }); });
  check("resolver non-object → deliver/bad-resolver", eRes && eRes.code === "deliver/bad-resolver");

  var eTf = threw(function () { b.mail.send.deliver({ hostname: "m.example", transportFactory: 5 }); });
  check("transportFactory non-function → deliver/bad-transport-factory",
    eTf && eTf.code === "deliver/bad-transport-factory");

  var eAudit = threw(function () { b.mail.send.deliver({ hostname: "m.example", audit: "yes" }); });
  check("audit non-boolean → deliver/bad-audit", eAudit && eAudit.code === "deliver/bad-audit");

  var eDsnFrom = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", dsn: { from: 123, onPermanentFailure: function () {} } });
  });
  check("dsn.from non-string → deliver/bad-dsn-from", eDsnFrom && eDsnFrom.code === "deliver/bad-dsn-from");

  var ePerHost = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", timeouts: { perHostMs: "30000" } });
  });
  check("timeouts.perHostMs string → deliver/bad-timeout-perHostMs",
    ePerHost && ePerHost.code === "deliver/bad-timeout-perHostMs");

  var ePolicyKey = threw(function () {
    b.mail.send.deliver({ hostname: "m.example", policy: { mtaSts: "off", nope: 1 } });
  });
  check("unknown policy sub-key → throws (unknown option)",
    ePolicyKey && /unknown option/.test(ePolicyKey.message || ""));

  // Custom backoffMs array is accepted (the truthy branch of the
  // backoffMs default-or-supplied selection).
  var okBackoff = threw(function () {
    b.mail.send.deliver({
      hostname: "m.example",
      retry:    { backoffMs: [b.constants.TIME.seconds(30), b.constants.TIME.minutes(2)] },
      audit:    false,
    });
  });
  check("custom retry.backoffMs accepted", okBackoff === null);
}

// ---- DSN composer — default-field branches ----

function testDsnDefaultFields() {
  var deliver = b.mail.send.deliver({ hostname: "m.example", audit: false });

  // reportingMta / statusCode / reason / originalHeaders all omitted →
  // every `|| default` branch fires.
  var dsn = deliver.buildDsn({
    dsnFrom:      "mailer-daemon@m.example",
    originalFrom: "alice@sender.com",
    recipient:    "bob@dest.com",
  });
  check("DSN default reason is 'permanent failure'",
    /^Diagnostic-Code: smtp; permanent failure/m.test(dsn));
  check("DSN default Status is 5.0.0", /^Status: 5\.0\.0/m.test(dsn));
  check("DSN reportingMta falls back to dsnFrom in the prose line",
    dsn.indexOf("mail delivery system at mailer-daemon@m.example") !== -1);
  check("DSN Reporting-MTA falls back to dsnFrom's domain",
    /^Reporting-MTA: dns; m\.example/m.test(dsn));

  // dsnFrom with no '@' → from.split("@")[1] is undefined → the final
  // `|| ""` fallback produces an empty Reporting-MTA authority.
  var dsn2 = deliver.buildDsn({
    dsnFrom:      "mailerdaemon",
    originalFrom: "alice@sender.com",
    recipient:    "bob@dest.com",
  });
  check("DSN Reporting-MTA empty-authority fallback (dsnFrom has no @)",
    dsn2.indexOf("Reporting-MTA: dns; \r\n") !== -1);
}

// ---- Resolver wrapper shape { rrs: [...] } ----

async function testResolverWrapperShape() {
  var deliver = b.mail.send.deliver({
    hostname:         "mta1.example.com",
    resolver:         { queryMx: async function (domain) {
      return { rrs: [{ exchange: "mx1." + domain, priority: 10 }], ttl: 300, provenance: "doh" };
    } },
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
    audit:            false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
  check("resolver { rrs } wrapper shape is accepted → delivered",
    result.delivered.length === 1 && result.delivered[0].mxHost === "mx1.recipient.com");
}

// ---- Resolver bad shapes → no-mx / null-mx → permanent ----

async function testResolverBadShapes() {
  function deliverForResolver(resolver) {
    return b.mail.send.deliver({
      hostname: "mta1.example.com", resolver: resolver,
      policy: { mtaSts: "off", dane: "off" }, audit: false,
    });
  }
  var msg = Buffer.from("hi");

  var r1 = await deliverForResolver({ queryMx: async function () { return {}; } })(
    { from: "ops@example.com", to: ["a@x.com"], rfc822: msg });
  check("resolver returns non-array/non-rrs → no-mx permanent",
    r1.failed.length === 1 && r1.failed[0].reasonCode === "5.1.2");

  var r2 = await deliverForResolver({ queryMx: async function () { return []; } })(
    { from: "ops@example.com", to: ["a@x.com"], rfc822: msg });
  check("resolver returns empty array → no-mx permanent",
    r2.failed.length === 1 && r2.failed[0].reasonCode === "5.1.2");

  // RFC 7505 null MX signalled with an empty-string exchange (the "."
  // form is exercised by testNullMx above).
  var r3 = await deliverForResolver({ queryMx: async function () { return [{ exchange: "", priority: 0 }]; } })(
    { from: "ops@example.com", to: ["a@x.com"], rfc822: msg });
  check("resolver returns empty-exchange null-MX → permanent 5.1.2",
    r3.failed.length === 1 && r3.failed[0].reasonCode === "5.1.2");
  check("null-MX failed.mxHost is null (no host was tried)",
    r3.failed[0].mxHost === null);
}

// ---- MX lookup timeout → transient → deferred ----

async function testMxLookupTimeout() {
  await helpers.withTestTimeout("mx-lookup timeout branch", async function () {
    var deliver = b.mail.send.deliver({
      hostname: "mta1.example.com",
      // Never-resolving lookup + a 1ms budget forces the internal
      // setTimeout reject path in _resolveMx. `1` is an intentionally
      // tiny timeout to exercise the timeout branch, not a duration.
      resolver: { queryMx: function () { return new Promise(function () {}); } },
      policy:   { mtaSts: "off", dane: "off" },
      timeouts: { mxLookupMs: 1 },
      audit:    false,
    });
    var result = await deliver({ from: "ops@example.com", to: ["a@slow.example"], rfc822: Buffer.from("hi") });
    check("mx-timeout → deferred (transient)", result.deferred.length === 1);
    check("mx-timeout → reasonCode 4.4.4", result.deferred[0].reasonCode === "4.4.4");
  });
}

// ---- No resolver → node:dns fallback path ----

async function testNodeDnsFallback() {
  await withNodeDnsResolveMx(async function (domain) {
    return [{ exchange: "mx.node." + domain, priority: 5 }];
  }, async function () {
    // resolver omitted → ctx.resolver null → _resolveMx uses nodeDns.resolveMx.
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      policy:           { mtaSts: "off", dane: "off" },
      transportFactory: okTransport(),
      audit:            false,
    });
    var result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
    check("no-resolver node:dns fallback → delivered",
      result.delivered.length === 1 && result.delivered[0].mxHost === "mx.node.recipient.com");
  });
}

// ---- Recipient with no usable domain ----

async function testRecipientNoDomain() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
    audit:    false,
  });
  var r1 = await deliver({ from: "ops@example.com", to: ["nodomain"], rfc822: Buffer.from("hi") });
  check("recipient without '@' → permanent no-domain 5.1.3",
    r1.failed.length === 1 && r1.failed[0].reasonCode === "5.1.3");
  var r2 = await deliver({ from: "ops@example.com", to: ["trailingat@"], rfc822: Buffer.from("hi") });
  check("recipient with empty domain (trailing @) → permanent 5.1.3",
    r2.failed.length === 1 && r2.failed[0].reasonCode === "5.1.3");
}

// ---- All MX hosts transient → final transient → deferred ----

async function testAllHostsTransient() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) {
      return [{ exchange: "mx1." + d, priority: 10 }, { exchange: "mx2." + d, priority: 20 }];
    }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        var err = new Error("temporary failure");
        err.smtpResponse = { code: 451 };
        throw err;
      } };
    },
    audit:    false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi") });
  check("all-MX-transient → deferred (no delivery, no permanent fail)",
    result.deferred.length === 1 && result.delivered.length === 0 && result.failed.length === 0);
  check("all-MX-transient carries the last SMTP response code (4xx)",
    result.deferred[0].reasonCode === 451);
}

// ---- Permanent 5xx send failure records the MX host on the result ----

async function testPermanentFailKeepsMxHost() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        var err = new Error("550 5.1.1 no such user");
        err.smtpResponse = { code: 550 };
        throw err;
      } };
    },
    audit:    false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi") });
  check("permanent 5xx → failed with mxHost recorded",
    result.failed.length === 1 && result.failed[0].mxHost === "mx1.example.com");
  check("permanent 5xx reasonCode is the SMTP code",
    result.failed[0].reasonCode === 550);
}

// ---- MTA-STS policy matrix (fault-injected b.network.smtp.policy) ----

async function runMtaStsScenario(sc) {
  var mtaStub = {
    fetch: async function () {
      if (sc.fetchThrows) throw new Error(sc.fetchThrows);
      return sc.fetchResult;
    },
    matchMx:     function () { return !!sc.matchMx; },
    parsePolicy: smtpPolicyMod.mtaSts.parsePolicy,
  };
  var out = { result: null, err: null };
  await withSmtpPolicyStub({ mtaSts: mtaStub }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:           { mtaSts: sc.policyMtaSts, dane: "off" },
      transportFactory: okTransport(),
      audit:            false,
    });
    try {
      out.result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
    } catch (e) { out.err = e; }
  });
  return out;
}

async function testMtaStsMatrix() {
  // fetch throws under enforce → permanent mta-sts-fetch-failed (5.7.10).
  var s1 = await runMtaStsScenario({ policyMtaSts: "enforce", fetchThrows: "network down" });
  check("MTA-STS fetch fail under enforce → permanent 5.7.10",
    s1.result && s1.result.failed.length === 1 && s1.result.failed[0].reasonCode === "5.7.10");

  // fetch throws under testing → skip + continue with original MX → delivered.
  var s2 = await runMtaStsScenario({ policyMtaSts: "testing", fetchThrows: "network down" });
  check("MTA-STS fetch fail under testing → skipped, delivered",
    s2.result && s2.result.delivered.length === 1);

  // null policy → 'none' audit + continue → delivered.
  var s3 = await runMtaStsScenario({ policyMtaSts: "enforce", fetchResult: null });
  check("MTA-STS fetch returns null → delivered (no policy published)",
    s3.result && s3.result.delivered.length === 1);

  // mode 'none' → delivered.
  var s4 = await runMtaStsScenario({ policyMtaSts: "enforce", fetchResult: { mode: "none" } });
  check("MTA-STS mode none → delivered",
    s4.result && s4.result.delivered.length === 1);

  // enforce policy, MX matches → filtered non-empty → delivered.
  var s5 = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "enforce", mx: ["*.recipient.com"] }, matchMx: true });
  check("MTA-STS enforce + MX match → delivered",
    s5.result && s5.result.delivered.length === 1);

  // enforce policy, MX does not match → mismatch → permanent 5.7.10.
  var s6 = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "enforce", mx: ["mail.other.com"] }, matchMx: false });
  check("MTA-STS enforce + no MX match → permanent 5.7.10",
    s6.result && s6.result.failed.length === 1 && s6.result.failed[0].reasonCode === "5.7.10");

  // testing policy + testing local + no match → 'no-match' audit + continue → delivered.
  var s7 = await runMtaStsScenario({
    policyMtaSts: "testing", fetchResult: { mode: "testing", mx: ["mail.other.com"] }, matchMx: false });
  check("MTA-STS testing + no match (local testing) → delivered (report-only)",
    s7.result && s7.result.delivered.length === 1);

  // testing policy + enforce local + match → 'testing' audit + filtered → delivered.
  var s8 = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "testing", mx: ["*.recipient.com"] }, matchMx: true });
  check("MTA-STS testing published + local enforce + match → delivered",
    s8.result && s8.result.delivered.length === 1);
}

// ---- RFC 8461 §5.2: published testing-mode policy is report-only ----
// A domain-published "testing" policy MUST NOT cause a hard failure —
// failures are report-only and delivery proceeds. The default local
// posture (mtaSts:"enforce") cannot promote a domain's testing policy
// to a bounce. RED before the fix (the no-match testing policy threw
// mta-sts-mx-mismatch → permanent bounce under local enforce).
async function testMtaStsTestingNotEnforcedUnderLocalEnforce() {
  var s = await runMtaStsScenario({
    policyMtaSts: "enforce", fetchResult: { mode: "testing", mx: ["mail.other.com"] }, matchMx: false });
  check("testing-mode + local enforce + no MX match → NOT bounced (report-only)",
    s.result && s.result.failed.length === 0 && s.result.deferred.length === 0);
  check("testing-mode + local enforce + no MX match → delivered against full MX set",
    s.result && s.result.delivered.length === 1);
  check("testing-mode report-only does not reject deliver()",
    s.err === null);
}

// ---- DANE lookup matrix (fault-injected b.network.smtp.policy.dane) ----

async function runDaneScenario(sc) {
  var daneStub = {
    tlsa: async function () {
      if (sc.tlsaThrows) throw new Error(sc.tlsaThrows);
      return sc.tlsaResult;
    },
    recordShape: smtpPolicyMod.dane.recordShape,
    verifyChain: smtpPolicyMod.dane.verifyChain,
  };
  var out = { result: null, err: null };
  await withSmtpPolicyStub({ dane: daneStub }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:           { mtaSts: "off", dane: sc.policyDane },
      transportFactory: okTransport(),
      audit:            false,
    });
    try {
      out.result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
    } catch (e) { out.err = e; }
  });
  return out;
}

async function testDaneMatrix() {
  var d1 = await runDaneScenario({ policyDane: "opportunistic",
    tlsaResult: [{ usage: 3, selector: 1, mtype: 1, dataHex: "ab" }] });
  check("DANE opportunistic + TLSA records present → delivered",
    d1.result && d1.result.delivered.length === 1);

  var d2 = await runDaneScenario({ policyDane: "opportunistic", tlsaResult: [] });
  check("DANE opportunistic + empty TLSA → delivered",
    d2.result && d2.result.delivered.length === 1);

  var d3 = await runDaneScenario({ policyDane: "opportunistic", tlsaResult: null });
  check("DANE opportunistic + no TLSA → delivered",
    d3.result && d3.result.delivered.length === 1);

  var d4 = await runDaneScenario({ policyDane: "opportunistic", tlsaThrows: "SERVFAIL" });
  check("DANE opportunistic + TLSA lookup throws → skipped, delivered",
    d4.result && d4.result.delivered.length === 1);
}

// ---- DANE enforce TLSA failure is per-recipient, not batch-fatal ----
// A DANE-enforce TLSA lookup failure must fail (defer) the single
// affected recipient and STILL return the batch result object the
// contract promises — it must NOT throw out of deliver() and discard
// the sibling recipients' outcomes. RED before the fix (the throw
// propagated out of deliver() and rejected the whole call).
async function testDaneEnforceFailsOneRecipientNotBatch() {
  var d = await runDaneScenario({ policyDane: "enforce", tlsaThrows: "SERVFAIL" });
  check("DANE enforce TLSA failure does not reject deliver()",
    d.err === null && d.result !== null);
  check("DANE enforce TLSA failure defers the affected recipient",
    d.result && d.result.deferred.length === 1 && d.result.delivered.length === 0);
}

// A DANE-enforce TLSA failure for ONE recipient's MX must not abort the
// sibling recipient in the same deliver() batch. The DANE stub throws
// only for the "bad" domain's MX host; the "good" domain must still be
// delivered in the same call.
async function testDaneEnforceBatchSurvivesSiblingFailure() {
  var daneStub = {
    tlsa: async function (mxHost) {
      // Fault-inject a TLSA lookup failure for the bad domain's MX only.
      if (String(mxHost).indexOf("bad.example") !== -1) throw new Error("SERVFAIL");
      return null;
    },
    recordShape: smtpPolicyMod.dane.recordShape,
    verifyChain: smtpPolicyMod.dane.verifyChain,
  };
  var out = { result: null, err: null };
  await withSmtpPolicyStub({ dane: daneStub }, async function () {
    var deliver = b.mail.send.deliver({
      hostname:         "mta1.example.com",
      resolver:         okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:           { mtaSts: "off", dane: "enforce" },
      transportFactory: okTransport(),
      audit:            false,
    });
    try {
      out.result = await deliver({
        from:   "ops@example.com",
        to:     ["victim@bad.example", "friend@good.example"],
        rfc822: Buffer.from("hi"),
      });
    } catch (e) { out.err = e; }
  });
  check("mixed DANE batch does not reject deliver()",
    out.err === null && out.result !== null);
  check("mixed DANE batch delivers the healthy sibling recipient",
    out.result && out.result.delivered.length === 1 &&
    out.result.delivered[0].recipient === "friend@good.example");
  check("mixed DANE batch defers the DANE-failed recipient",
    out.result && out.result.deferred.length === 1 &&
    out.result.deferred[0].recipient === "victim@bad.example");
}

// ---- DSN callback failure path ----

async function testDsnCallbackFailure() {
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: function () {
      return { send: async function () {
        var err = new Error("550 5.1.1 no such user");
        err.smtpResponse = { code: 550 };
        throw err;
      } };
    },
    dsn: {
      from: "mailer-daemon@example.com",
      onPermanentFailure: async function () { throw new Error("DSN transport exploded"); },
    },
    audit: false,
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi") });
  check("DSN callback throwing → recipient still recorded as failed",
    result.failed.length === 1);
  check("DSN callback throwing → dsnSent flag stays false",
    result.failed[0].dsnSent === false);
}

// ---- _extractHeaderBlock separator variants (via the DSN path) ----

async function testExtractHeaderBlockVariants() {
  var seen = [];
  function makeDeliver() {
    return b.mail.send.deliver({
      hostname: "mta1.example.com",
      resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
      policy:   { mtaSts: "off", dane: "off" },
      transportFactory: function () {
        return { send: async function () {
          var err = new Error("550 5.1.1 no such user");
          err.smtpResponse = { code: 550 };
          throw err;
        } };
      },
      dsn: {
        from: "mailer-daemon@example.com",
        onPermanentFailure: async function (env, res, dsnMessage) { seen.push(dsnMessage); },
      },
      audit: false,
    });
  }

  // LF-only header separator → the `\n\n` fallback branch.
  await makeDeliver()({ from: "ops@example.com", to: ["a@example.com"],
    rfc822: Buffer.from("Subject: lf-only\nX-Tag: one\n\nbody") });
  check("DSN embeds LF-only-separated original headers",
    seen.length === 1 && seen[0].indexOf("Subject: lf-only") !== -1);

  // No blank-line separator at all → whole string returned.
  await makeDeliver()({ from: "ops@example.com", to: ["a@example.com"],
    rfc822: Buffer.from("Subject: no-separator-single-line") });
  check("DSN embeds header block when message has no blank-line separator",
    seen.length === 2 && seen[1].indexOf("Subject: no-separator-single-line") !== -1);
}

// ---- Retry budget: custom backoff + attempt-index clamp + envelope.attempt ----

async function testRetryBudgetClamp() {
  var backoff = [b.constants.TIME.seconds(30), b.constants.TIME.minutes(2)];
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    retry:    { maxAttempts: 10, backoffMs: backoff },
    transportFactory: function () {
      return { send: async function () {
        var err = new Error("temporary");
        err.smtpResponse = { code: 451 };
        throw err;
      } };
    },
    audit:    false,
  });
  // envelope.attempt: 3 → attempts becomes 4; still < maxAttempts(10) so
  // it defers; idx = min(attempts-1=3, backoffMs.length-1=1) = 1 → clamps
  // to the last backoff entry.
  var result = await deliver({
    from: "ops@example.com", to: ["a@example.com"], rfc822: Buffer.from("hi"), attempt: 3,
  });
  check("retry: prior attempt count carried through → deferred attempt is 4",
    result.deferred.length === 1 && result.deferred[0].attempt === 4);
  check("retry: attempt index clamps to the last backoff entry",
    result.deferred[0].retryAfterMs === backoff[backoff.length - 1]);
}

// ---- Default-audit (audit enabled) path executes cleanly ----

async function testDefaultAuditEnabled() {
  // audit omitted → auditEnabled true branch; the real (best-effort)
  // audit sink runs. Delivery must still succeed.
  var deliver = b.mail.send.deliver({
    hostname: "mta1.example.com",
    resolver: okResolver(function (d) { return [{ exchange: "mx1." + d, priority: 10 }]; }),
    policy:   { mtaSts: "off", dane: "off" },
    transportFactory: okTransport(),
  });
  var result = await deliver({ from: "ops@example.com", to: ["a@recipient.com"], rfc822: Buffer.from("hi") });
  check("audit-enabled default path delivers", result.delivered.length === 1);
}

// ---- b.mail.send.deliver.create — documented factory dotted form ----
//
// The @primitive / @signature / @example advertise
// `b.mail.send.deliver.create(opts)` as the way to build a delivery
// handle. This drives that exact dotted form end-to-end (stubbed MX +
// transport, no real SMTP socket) so the documented operator consumer
// path is verified — not only the collapsed `b.mail.send.deliver(opts)`
// callable the other tests exercise.
async function testDeliverCreateDottedForm() {
  check("b.mail.send.deliver.create is a function",
    typeof b.mail.send.deliver.create === "function");

  var fakeResolver = {
    queryMx: async function (domain) { return [{ exchange: "mx1." + domain, priority: 10 }]; },
  };
  var fakeTransport = function () {
    return { send: async function () { return { ok: true, code: 250 }; } };
  };
  var deliver = b.mail.send.deliver.create({
    hostname:         "mta1.example.com",
    resolver:         fakeResolver,
    policy:           { mtaSts: "off", dane: "off" },
    transportFactory: fakeTransport,
    audit:            false,
  });
  check("create() returns a callable deliver handle", typeof deliver === "function");
  var result = await deliver({
    from:   "ops@example.com",
    to:     ["alice@recipient.com"],
    rfc822: Buffer.from("From: ops@example.com\r\nTo: alice@recipient.com\r\nSubject: hi\r\n\r\nbody"),
  });
  check("create()'d handle delivers via the stubbed transport",
    result.delivered.length === 1 && result.delivered[0].recipient === "alice@recipient.com");

  // The documented factory refuses bad opts the same as the callable form.
  var threw = null;
  try { b.mail.send.deliver.create({}); } catch (e) { threw = e; }
  check("create({}) without hostname → deliver/bad-hostname",
    threw && threw.code === "deliver/bad-hostname");
}

// ---- Run ----

async function run() {
  testSurface();
  testFactoryRefusesBadOpts();
  await testDeliverCreateDottedForm();
  await testEnvelopeValidation();
  testOutcomeClassifier();
  testDsnComposer();
  testDsnRejectsCrlfHeaderInjection();
  await testDeliveryHappyPathStubbed();
  await testMultiAtRecipientRefused();
  await testTransientDefersPermanentFails();
  await testNullMx();
  await testMxFailover();
  await testPortReachesTransport();
  await testMaxAttemptsFlowsThrough();
  testClassifierFallthroughs();
  testCreateValidationCodes();
  testDsnDefaultFields();
  await testResolverWrapperShape();
  await testResolverBadShapes();
  await testMxLookupTimeout();
  await testNodeDnsFallback();
  await testRecipientNoDomain();
  await testAllHostsTransient();
  await testPermanentFailKeepsMxHost();
  await testMtaStsMatrix();
  await testMtaStsTestingNotEnforcedUnderLocalEnforce();
  await testDaneMatrix();
  await testDaneEnforceFailsOneRecipientNotBatch();
  await testDaneEnforceBatchSurvivesSiblingFailure();
  await testDsnCallbackFailure();
  await testExtractHeaderBlockVariants();
  await testRetryBudgetClamp();
  await testDefaultAuditEnabled();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-send-deliver] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

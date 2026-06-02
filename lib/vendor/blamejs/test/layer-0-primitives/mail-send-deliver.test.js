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
 * compose logic.
 */

var helpers = require("../helpers");
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

// ---- Run ----

async function run() {
  testSurface();
  testFactoryRefusesBadOpts();
  await testEnvelopeValidation();
  testOutcomeClassifier();
  testDsnComposer();
  await testDeliveryHappyPathStubbed();
  await testTransientDefersPermanentFails();
  await testNullMx();
  await testMxFailover();
  await testPortReachesTransport();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[mail-send-deliver] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

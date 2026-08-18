"use strict";

/**
 * What actually leaves the building when audit forwarding is on.
 *
 * These events go to an external system the operator runs, so the payload is an
 * egress surface: whatever is in it has left. Two properties matter and neither
 * is visible from the call site.
 *
 * The auth class is carried as `actorKind`. The framework's redactor strips any
 * field whose NAME contains "auth", so the obvious spelling — `authType`, which
 * is what the audit row calls it — arrives at the SIEM stripped, and the loss is
 * silent: forwarding still works, the field is simply gone, and nobody notices
 * until an investigation needs to know whether a session or an API key did
 * something. Renaming it back would look like a tidy-up.
 *
 * `details` is free-form. Call sites are disciplined about it — key prefixes,
 * ids and reasons, never a raw secret — and the scrub is the second layer for
 * the day one of them is not. It has to mask a credential shape without eating
 * the checksums and paths that make the entry useful.
 *
 * The sink is replaced for the duration rather than pointed at a real endpoint,
 * so nothing here opens a socket.
 */

require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it, before, after, beforeEach } = require("node:test");
var assert = require("node:assert");

var b = require("../../lib/vendor/blamejs");
var config = require("../../lib/config");
var siem = require("../../lib/audit-siem");

var realInit, realShutdown, realEmit;
var emitted = [];
var initArgs = [];
var saved = {};

before(async function () {
  realInit = b.logStream.init;
  realShutdown = b.logStream.shutdown;
  realEmit = b.logStream.emit;

  b.logStream.init = function (opts) { initArgs.push(opts); };
  b.logStream.shutdown = function () { return Promise.resolve(); };
  b.logStream.emit = function (level, name, payload) { emitted.push({ level: level, name: name, payload: payload }); };

  ["siemEnabled", "siemUrl", "siemProtocol", "siemWebhookAuth", "siemWebhookToken", "siemMinLevel"]
    .forEach(function (k) { saved[k] = config[k]; });

  config.siemEnabled = true;
  config.siemUrl = "https://siem.example.com/ingest";
  config.siemProtocol = "syslog";
  assert.strictEqual(await siem.initSiem(), true, "forwarding must be active for these cases");
});

after(function () {
  b.logStream.init = realInit;
  b.logStream.shutdown = realShutdown;
  b.logStream.emit = realEmit;
  Object.keys(saved).forEach(function (k) { config[k] = saved[k]; });
});

beforeEach(function () { emitted.length = 0; });

// Clears first, so a case may call it more than once and still assert that each
// call produced exactly one event.
function forwardOne(action, entry) {
  emitted.length = 0;
  siem.forward(action, entry);
  assert.strictEqual(emitted.length, 1, "expected exactly one forwarded event");
  return emitted[0];
}

describe("the forwarded payload", function () {
  it("carries the auth class under a name the redactor leaves alone", function () {
    var ev = forwardOne("user_login", { performedBy: "u1", authType: "apikey" });
    assert.strictEqual(ev.payload.actorKind, "apikey",
      "the auth class must survive to the SIEM");
    Object.keys(ev.payload).forEach(function (k) {
      assert.strictEqual(/auth/i.test(k), false,
        "no field may be named so the framework's redactor strips it — found " + k);
    });
  });

  it("reports every absent field as null rather than leaving it undefined", function () {
    // An undefined value disappears through JSON serialisation, so a field that
    // was meant to say "we did not know" arrives as a missing key instead.
    var ev = forwardOne("user_login", { performedBy: "u1" });
    ["actor", "actorId", "targetEmail", "targetId", "ip", "method", "path",
      "actorKind", "requestId", "userAgent", "details", "at"].forEach(function (k) {
      assert.ok(k in ev.payload, k + " must be present in the payload");
      assert.notStrictEqual(ev.payload[k], undefined, k + " must not be undefined");
    });
    assert.strictEqual(ev.payload.ip, null);
    assert.strictEqual(ev.payload.userAgent, null);
  });

  it("prefers the actor's address but falls back to the id", function () {
    assert.strictEqual(
      forwardOne("user_login", { performedBy: "u1", performedByEmail: "a@example.com" }).payload.actor,
      "a@example.com");
    assert.strictEqual(forwardOne("user_login", { performedBy: "u1" }).payload.actor, "u1");
    assert.strictEqual(forwardOne("user_login", {}).payload.actor, null);
  });

  it("passes the whole request context through", function () {
    var ev = forwardOne("file_download", {
      performedBy: "u1", performedByEmail: "a@example.com",
      targetEmail: "t@example.com", targetId: "f9",
      ip: "203.0.113.9", method: "GET", path: "/files/:shareId",
      authType: "session", requestId: "req-1", userAgent: "curl/8",
      createdAt: "2026-08-17T00:00:00.000Z",
    });
    assert.strictEqual(ev.payload.targetId, "f9");
    assert.strictEqual(ev.payload.ip, "203.0.113.9");
    assert.strictEqual(ev.payload.method, "GET");
    assert.strictEqual(ev.payload.path, "/files/:shareId");
    assert.strictEqual(ev.payload.requestId, "req-1");
    assert.strictEqual(ev.payload.userAgent, "curl/8");
    assert.strictEqual(ev.payload.at, "2026-08-17T00:00:00.000Z");
  });

  it("names the event and classifies its level and outcome", function () {
    var ok = forwardOne("user_login", { performedBy: "u1" });
    assert.strictEqual(ok.name, "audit.user_login");
    assert.strictEqual(ok.level, "info");
    assert.strictEqual(ok.payload.outcome, "success");

    var bad = forwardOne("login_failed", { performedBy: "u1" });
    assert.strictEqual(bad.level, "warn");
    assert.strictEqual(bad.payload.outcome, "failure");
  });
});

describe("the details scrub", function () {
  it("masks a private key that reached a free-form field", function () {
    var pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----";
    var out = siem._scrubDetails("upload failed, key was " + pem);
    assert.ok(out, "the scrub must return something rather than dropping the entry");
    assert.strictEqual(String(out).indexOf("MIIEow=="), -1,
      "the key body must not reach the SIEM: " + out);
  });

  it("leaves the forensic content HermitStash logs on purpose", function () {
    // High entropy but not secret. Stripping these would empty the field of the
    // only things that make an entry investigable.
    var detail = "backend: resend, reason: quota exceeded, "
      + "checksum: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08, "
      + "path: uploads/bundle-42/report.pdf";
    var out = String(siem._scrubDetails(detail));
    assert.ok(out.indexOf("9f86d081884c7d659a2feaa0c55ad015") !== -1, "checksum must survive: " + out);
    assert.ok(out.indexOf("uploads/bundle-42/report.pdf") !== -1, "path must survive: " + out);
    assert.ok(out.indexOf("quota exceeded") !== -1, "reason must survive: " + out);
  });

  it("reports an absent detail as null", function () {
    assert.strictEqual(siem._scrubDetails(null), null);
    assert.strictEqual(siem._scrubDetails(""), null);
    assert.strictEqual(siem._scrubDetails(undefined), null);
  });
});

describe("forwarding never disturbs the request that triggered it", function () {
  it("swallows a sink that throws", function () {
    // audit.log() is fire-and-forget; an outage at the SIEM must not surface as
    // a failed upload or a failed login.
    b.logStream.emit = function () { throw new Error("sink is down"); };
    try {
      assert.doesNotThrow(function () {
        siem.forward("user_login", { performedBy: "u1" });
      });
    } finally {
      b.logStream.emit = function (level, name, payload) { emitted.push({ level: level, name: name, payload: payload }); };
    }
  });

  it("does nothing at all without an entry", function () {
    siem.forward("user_login", null);
    assert.strictEqual(emitted.length, 0);
  });
});

describe("the sink configuration the operator's settings produce", function () {
  async function reinit() { initArgs.length = 0; await siem.initSiem(); return initArgs[0]; }

  it("syslog carries the audit facility", async function () {
    config.siemProtocol = "syslog";
    var sink = (await reinit()).sinks.siem;
    assert.strictEqual(sink.protocol, "syslog");
    assert.strictEqual(sink.facility, 13, "RFC 5424 facility 13 is log audit");
    assert.strictEqual(sink.appName, "hermitstash");
  });

  it("a webhook with bearer authentication", async function () {
    config.siemProtocol = "webhook";
    config.siemWebhookAuth = "bearer";
    config.siemWebhookToken = "s3cr3t";
    var sink = (await reinit()).sinks.siem;
    assert.strictEqual(sink.protocol, "webhook");
    assert.strictEqual(sink.url, "https://siem.example.com/ingest");
  });

  it("a webhook with basic authentication splits the credential on the colon", async function () {
    config.siemProtocol = "webhook";
    config.siemWebhookAuth = "basic";
    config.siemWebhookToken = "operator:hunter2";
    var sink = (await reinit()).sinks.siem;
    assert.strictEqual(sink.auth, "basic");
    assert.strictEqual(sink.username, "operator");
    assert.strictEqual(sink.password, "hunter2");
  });

  it("a basic credential with no colon yields an empty password, not a crash", async function () {
    config.siemProtocol = "webhook";
    config.siemWebhookAuth = "basic";
    config.siemWebhookToken = "operator";
    var sink = (await reinit()).sinks.siem;
    assert.strictEqual(sink.username, "operator");
    assert.strictEqual(sink.password, "");
  });

  it("refuses to enable forwarding without an endpoint", async function () {
    config.siemEnabled = true;
    config.siemUrl = "";
    assert.strictEqual(await siem.initSiem(), false);
    assert.strictEqual(siem.isEnabled(), false);

    var r = await siem.testConnection();
    assert.strictEqual(r.ok, false);
    assert.match(r.error, /disabled or the endpoint URL is missing/);

    config.siemUrl = "https://siem.example.com/ingest";
  });

  it("refuses when the operator has turned it off", async function () {
    config.siemEnabled = false;
    assert.strictEqual(await siem.initSiem(), false);
    assert.strictEqual(siem.isEnabled(), false);
    config.siemEnabled = true;
  });
});

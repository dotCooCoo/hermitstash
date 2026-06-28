const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const dgram = require("node:dgram");
const http = require("node:http");
const { setTimeout: delay } = require("node:timers/promises");
var testServer = require("../helpers/test-server");

var audit, siem, config;
var udp, udpPort, received = [];

before(async function () {
  await testServer.start();
  var root = testServer.projectRoot;
  audit = require(path.join(root, "lib", "audit"));
  siem = require(path.join(root, "lib", "audit-siem"));
  config = require(path.join(root, "lib", "config"));

  udp = dgram.createSocket("udp4");
  udp.on("message", function (m) { received.push(m.toString("utf8")); });
  await new Promise(function (r) { udp.bind(0, "127.0.0.1", r); });
  udpPort = udp.address().port;

  config.auditIpFull = true; // forward the full IP so the test can assert on it
  config.auditCaptureUserAgent = true; // capture UA so the SIEM receives it (SIEM forces this on)
  config.siemEnabled = true;
  config.siemProtocol = "syslog";
  config.siemUrl = "udp://127.0.0.1:" + udpPort;
  config.siemMinLevel = "info";
  await siem.initSiem();
});
after(async function () {
  config.siemEnabled = false; config.auditIpFull = false; config.auditCaptureUserAgent = false;
  try { await siem.initSiem(); } catch (_e) {}
  try { udp.close(); } catch (_e) {}
  return testServer.stop();
});

function reqCtx(over) {
  return Object.assign({ method: "POST", pathname: "/auth/login", headers: { "user-agent": "Mozilla/5.0 TestAgent" }, user: { _id: "u-s", email: "actor@test.com" }, socket: { remoteAddress: "203.0.113.42" }, requestId: "rq-1" }, over || {});
}
// Event-driven wait: resolve the instant a matching datagram arrives — no poll
// sleep. The bounded fallback (a promisified timer, aborted once the listener
// wins) returns null, which the "disabled" case asserts as a non-event.
function waitFor(pred, ms) {
  var existing = received.find(pred);
  if (existing) return Promise.resolve(existing);
  var ac = new AbortController();
  var onMsg;
  var listen = new Promise(function (resolve) {
    onMsg = function (m) { var s = m.toString("utf8"); if (pred(s)) resolve(s); };
    udp.on("message", onMsg);
  });
  var timeout = delay(ms || 1500, null, { signal: ac.signal }).catch(function () { return null; });
  return Promise.race([listen, timeout]).finally(function () {
    ac.abort();
    udp.removeListener("message", onMsg);
  });
}

describe("SIEM forwarding (syslog)", function () {
  it("forwards an audit event as RFC 5424 with the structured fields", async function () {
    received.length = 0;
    audit.log("login_success", { targetId: "s-1", targetEmail: "target@test.com", details: "Signed in", req: reqCtx() });
    var pkt = await waitFor(function (m) { return m.indexOf("audit.login_success") !== -1; });
    assert.ok(pkt, "a syslog packet arrived");
    assert.ok(pkt.indexOf("hermitstash") !== -1, "appName = hermitstash");
    assert.ok(pkt.indexOf("\"action\":\"login_success\"") !== -1, "action in structured meta");
    assert.ok(pkt.indexOf("203.0.113.42") !== -1, "full IP forwarded");
    assert.ok(pkt.indexOf("\"actorKind\":\"session\"") !== -1, "auth class forwarded (under a redaction-safe key)");
    assert.ok(pkt.indexOf("Mozilla/5.0 TestAgent") !== -1, "user-agent forwarded when captured");
    // info severity 6 + facility 13 (log audit) → PRI = 13*8+6 = 110
    assert.ok(pkt.indexOf("<110>1 ") === 0, "PRI = info/log-audit, got " + pkt.slice(0, 8));
  });

  it("maps a security failure to warn severity", async function () {
    received.length = 0;
    audit.log("login_failed_bad_password", { targetId: "s-2", details: "bad pw", req: reqCtx() });
    var pkt = await waitFor(function (m) { return m.indexOf("audit.login_failed_bad_password") !== -1; });
    assert.ok(pkt, "packet arrived");
    // warn severity 4 + facility 13 → PRI = 13*8+4 = 108
    assert.ok(pkt.indexOf("<108>1 ") === 0, "PRI = warn, got " + pkt.slice(0, 8));
    assert.ok(pkt.indexOf("\"outcome\":\"failure\"") !== -1, "outcome = failure");
  });

  it("redacts a secret-shaped value before it leaves the host", async function () {
    received.length = 0;
    var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.s3cr3tSignatureValueHere123";
    audit.log("password_changed", { targetId: "s-3", details: jwt, req: reqCtx() });
    var pkt = await waitFor(function (m) { return m.indexOf("audit.password_changed") !== -1; });
    assert.ok(pkt, "packet arrived");
    assert.ok(pkt.indexOf(jwt) === -1, "the JWT-shaped secret is NOT forwarded verbatim");
    assert.ok(/REDACT/i.test(pkt), "a redaction marker is present");
  });

  it("does not forward when disabled", async function () {
    config.siemEnabled = false; await siem.initSiem();
    received.length = 0;
    audit.log("file_downloaded", { targetId: "s-4", req: reqCtx() });
    var pkt = await waitFor(function (m) { return m.indexOf("audit.file_downloaded") !== -1; }, 400);
    assert.strictEqual(pkt, null, "no packet when forwarding is off");
    config.siemEnabled = true; await siem.initSiem(); // restore
  });

  it("testConnection emits a connectivity probe", async function () {
    received.length = 0;
    var r = await siem.testConnection();
    assert.strictEqual(r.ok, true, "test ok: " + JSON.stringify(r));
    assert.strictEqual(r.protocol, "syslog");
    var pkt = await waitFor(function (m) { return m.indexOf("audit.siem_test") !== -1; });
    assert.ok(pkt, "test event reached the listener");
  });
});

describe("SIEM forwarding (webhook)", function () {
  var server, port, hits = [];
  before(async function () {
    server = http.createServer(function (rq, rs) {
      var chunks = [];
      rq.on("data", function (c) { chunks.push(c); });
      rq.on("end", function () {
        hits.push({ auth: rq.headers.authorization || null, body: Buffer.concat(chunks).toString("utf8") });
        rs.writeHead(200); rs.end("ok");
      });
    });
    await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
    port = server.address().port;
    config.siemEnabled = true;
    config.siemProtocol = "webhook";
    config.siemUrl = "http://127.0.0.1:" + port + "/ingest";
    config.siemWebhookAuth = "bearer";
    config.siemWebhookToken = "hook-secret";
    config.siemMinLevel = "info";
    await siem.initSiem();
  });
  after(async function () {
    config.siemEnabled = false; config.siemProtocol = "syslog";
    config.siemWebhookAuth = "none"; config.siemWebhookToken = "";
    try { await siem.initSiem(); } catch (_e) {}
    await new Promise(function (r) { server.close(r); });
  });

  it("POSTs audit events to the webhook with the configured bearer auth", async function () {
    hits.length = 0;
    audit.log("login_success", { targetId: "w-1", targetEmail: "wh@test.com", details: "ok", req: reqCtx() });
    // maxBatchAgeMs is ~2s; poll the collected POSTs until the batch flushes.
    var end = Date.now() + 4000, hit = null;
    while (Date.now() < end && !hit) {
      hit = hits.find(function (h) { return h.body.indexOf("audit.login_success") !== -1; });
      if (!hit) await delay(50);
    }
    assert.ok(hit, "webhook received the audit event");
    assert.strictEqual(hit.auth, "Bearer hook-secret", "bearer auth header sent, got " + hit.auth);
    assert.ok(hit.body.indexOf("\"action\":\"login_success\"") !== -1, "event action present in body");
  });
});

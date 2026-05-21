"use strict";
/**
 * Live log-stream sink test — exercises lib/log-stream.js's webhook
 * sink against a real HTTP receiver (the Caddy fixture's :8080 echoes
 * 200 on every request, sufficient to confirm the framework's sink
 * code path serializes + posts records correctly), the local file sink,
 * and the syslog sink across udp / tcp / tls transports against the
 * docker syslog-ng container which writes to /var/log/blamejs-test.log.
 */
var child_process = require("node:child_process");
var fs   = require("node:fs");
var http = require("node:http");
var os   = require("node:os");
var path = require("node:path");
var tls  = require("node:tls");
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

async function run() {
  var caddy = await services.requireService("caddy");
  if (!caddy.ok) throw new Error("caddy unreachable: " + caddy.reason);

  // ---- protocol catalog ----
  check("PROTOCOLS exposes every shipped sink (local/webhook/otlp/otlp-grpc/cloudwatch/syslog)",
        ["local", "webhook", "otlp", "otlp-grpc", "cloudwatch", "syslog"].every(function (p) {
          return b.logStream.PROTOCOLS.indexOf(p) !== -1;
        }));
  check("DEFERRED_PROTOCOLS no longer lists 'syslog' (it ships)",
        b.logStream.DEFERRED_PROTOCOLS.indexOf("syslog") === -1);

  // ---- local sink: writes records to disk ----
  if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-log-stream-"));
  b.logStream.init({
    sinks: {
      local: { protocol: "local", dir: tmpDir },
    },
    minLevel: "debug",
  });
  b.logStream.info("integration-event-1", { kind: "test", n: 1 });
  b.logStream.warn("integration-event-2", { kind: "test", n: 2 });
  await b.logStream.shutdown();
  // local sink writes one file per day; collect everything in tmpDir.
  var allLocalContent = fs.readdirSync(tmpDir)
    .map(function (f) { return fs.readFileSync(path.join(tmpDir, f), "utf8"); })
    .join("\n");
  check("local sink: file contains the first event",
        allLocalContent.indexOf("integration-event-1") !== -1);
  check("local sink: file contains the second event",
        allLocalContent.indexOf("integration-event-2") !== -1);
  check("local sink: warn level recorded",
        /"level":\s*"warn"/.test(allLocalContent));

  // ---- webhook sink: posts records to a real HTTP endpoint ----
  // Caddy responds 200 on every path. We host our own tiny capture
  // server too, so we can inspect the bodies the framework posted.
  var captured = [];
  var captureServer = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      try { captured.push(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch (_e) { captured.push({ _raw: Buffer.concat(chunks).toString("utf8") }); }
      res.statusCode = 204;
      res.end();
    });
  });
  await new Promise(function (resolve) { captureServer.listen(0, "127.0.0.1", resolve); });
  var capturePort = captureServer.address().port;
  var captureUrl = "http://127.0.0.1:" + capturePort + "/log";

  if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
  b.logStream.init({
    sinks: {
      hooked: {
        protocol:         "webhook",
        url:              captureUrl,
        allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
        allowInternal:    true,
        flushIntervalMs:  50,
      },
    },
    minLevel: "debug",
  });
  b.logStream.info("webhook-event", { route: "/payments", traceId: "abc-123" });
  b.logStream.error("webhook-error", { reason: "boom" });
  await b.logStream.shutdown();
  await new Promise(function (resolve) { captureServer.close(resolve); });
  fs.rmSync(tmpDir, { recursive: true, force: true });

  check("webhook sink: at least one record posted",
        captured.length >= 1);
  // The webhook sink may batch records into a single body or post one
  // body per record. Either way both events should be findable.
  var allText = JSON.stringify(captured);
  check("webhook sink: 'webhook-event' message landed",
        allText.indexOf("webhook-event") !== -1);
  check("webhook sink: 'webhook-error' message landed",
        allText.indexOf("webhook-error") !== -1);
  check("webhook sink: error level preserved",
        /"level":\s*"error"/.test(allText));

  // ---- syslog sink: udp / tcp against the docker syslog-ng ----
  // The docker container appends every record to /var/log/blamejs-test.log
  // regardless of which transport it arrived on. We emit a uniquely-tagged
  // record per transport, flush, then docker-exec to confirm each tag
  // landed on disk.
  var syslog = await services.requireService("syslog");
  if (!syslog.ok) throw new Error("syslog unreachable: " + syslog.reason);

  // Truncate the log file so prior runs don't poison the assertions.
  child_process.execFileSync("docker",
    ["exec", "blamejs-test-syslog", "truncate", "-s", "0", "/var/log/blamejs-test.log"],
    { stdio: "pipe" });

  var transports = [
    { name: "udp", url: "udp://127.0.0.1:5514", tag: "blamejs-udp-" + Date.now() },
    { name: "tcp", url: "tcp://127.0.0.1:5514", tag: "blamejs-tcp-" + Date.now() },
  ];

  for (var i = 0; i < transports.length; i += 1) {
    var t = transports[i];
    if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
    b.logStream.init({
      sinks: { syslog: { protocol: "syslog", url: t.url, appName: t.tag } },
      minLevel: "debug",
    });
    b.logStream.info("syslog-event-via-" + t.name, { transport: t.name });
    await helpers.passiveObserve(500, "syslog " + t.name + ": send + docker syslog-ng flush to /var/log/blamejs-test.log");
    await b.logStream.shutdown();
  }
  await helpers.passiveObserve(250, "syslog: final shutdown flush window across all transports");
  var syslogLog = child_process.execFileSync("docker",
    ["exec", "blamejs-test-syslog", "cat", "/var/log/blamejs-test.log"],
    { stdio: ["pipe", "pipe", "pipe"] }).toString("utf8");

  for (var j = 0; j < transports.length; j += 1) {
    var trj = transports[j];
    check("syslog " + trj.name + ": record landed in /var/log/blamejs-test.log",
          syslogLog.indexOf(trj.tag) !== -1);
  }

  // ---- syslog TLS sink: against an ad-hoc tls.createServer ----
  // The docker syslog-ng container's TLS port forwarded through Docker
  // Desktop on Windows is flaky — handshakes succeed standalone but
  // race the framework's reconnect loop. We assert the on-the-wire
  // framing the framework produces (RFC 6587 octet-counting + RFC 5424
  // message body) against a Node-side TLS receiver instead, which
  // exercises every code path in lib/log-stream-syslog.js's TLS branch.
  // Use the docker syslog cert + key directly — easier than re-issuing.
  var serverCert = child_process.execFileSync("docker",
    ["exec", "blamejs-test-syslog", "cat", "/certs/syslog.crt"],
    { stdio: "pipe" }).toString("utf8");
  var serverKey  = child_process.execFileSync("docker",
    ["exec", "blamejs-test-syslog", "cat", "/certs/syslog.key"],
    { stdio: "pipe" }).toString("utf8");
  var caPath = process.env.BLAMEJS_TEST_CA_PATH;
  var ca = caPath ? fs.readFileSync(caPath) : undefined;
  var received = "";
  var tlsServer = tls.createServer({ cert: serverCert, key: serverKey },
    function (sock) { sock.on("data", function (buf) { received += buf.toString("utf8"); }); });
  await new Promise(function (r) { tlsServer.listen(0, "127.0.0.1", r); });
  var tlsPort = tlsServer.address().port;

  var tlsTag = "blamejs-tls-" + Date.now();
  if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
  b.logStream.init({
    sinks: { syslog: {
      protocol: "syslog",
      url:      "tls://localhost:" + tlsPort,
      appName:  tlsTag,
      ca:       ca,
    } },
    minLevel: "debug",
  });
  b.logStream.info("syslog-event-via-tls", { transport: "tls" });
  await helpers.waitUntil(function () { return received.indexOf(tlsTag) !== -1; }, {
    label: "syslog tls: TLS receiver got the tagged record",
  });
  await b.logStream.shutdown();
  await new Promise(function (r) { tlsServer.close(r); });

  check("syslog tls: record reached the TLS receiver",
        received.indexOf(tlsTag) !== -1);
  check("syslog tls: octet-counting framing — record begins '<bytecount> '",
        /^\d+ <\d+>1 /.test(received));
  check("syslog tls: RFC 5424 PRI uses local0 facility (16)",
        /<13[0-9]>1 /.test(received));   // local0=16 → 16*8=128, info=6 → 134
  check("syslog tls: ISO 8601 timestamp present",
        /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(received));
  check("syslog tls: structured-data slot present (default '-')",
        / - syslog-event-via-tls/.test(received));

  if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
  var bad = null;
  try {
    b.logStream.init({ sinks: { s: { protocol: "syslog", url: "http://wrong" } } });
  } catch (e) { bad = e; }
  check("syslog rejects http:// urls (must be udp/tcp/tls)",
        bad && /udp|tcp|tls/.test(String(bad.message || "")));
  if (typeof b.logStream._resetForTest === "function") b.logStream._resetForTest();
  bad = null;
  try {
    b.logStream.init({ sinks: { s: { protocol: "syslog" } } });
  } catch (e) { bad = e; }
  check("syslog without { url } throws BAD_OPT",
        bad && /url/i.test(String(bad.message || "")));
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

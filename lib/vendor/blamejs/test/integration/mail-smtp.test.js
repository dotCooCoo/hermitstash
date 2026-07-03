// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live SMTP round-trip against the docker-compose Mailpit fixture.
 * Exercises lib/mail.js's smtpTransport over the same RFC 5321 wire
 * format operators get in production. Mailpit captures every message
 * and surfaces it through an HTTP API on :8025 — that's the assertion
 * surface for what landed.
 *
 * No security bypass — the test exports the pki-init CA from the docker
 * volume and passes it via opts.ca so STARTTLS verification stays on.
 */
var fs = require("node:fs");
var http = require("node:http");
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

function _httpJson(url) {
  return new Promise(function (resolve, reject) {
    var req = http.get(url, function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        var body = Buffer.concat(chunks).toString("utf8");
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error("HTTP " + res.statusCode + " " + body.slice(0, 200)));
        }
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error("bad JSON: " + e.message)); }
      });
    });
    req.once("error", reject);
  });
}

function _httpDelete(url) {
  return new Promise(function (resolve, reject) {
    var u = new URL(url);
    var req = http.request({
      method: "DELETE", host: u.hostname, port: u.port, path: u.pathname,
    }, function (res) {
      res.on("data", function () {});
      res.on("end", function () {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error("DELETE HTTP " + res.statusCode));
        }
        resolve();
      });
    });
    req.once("error", reject);
    req.end();
  });
}

async function run() {
  var svc = await services.requireService("mailpit");
  if (!svc.ok) throw new Error("mailpit unreachable: " + svc.reason);

  var caPath = await services.exportCaCert();
  var caPem = fs.readFileSync(caPath, "utf8");

  // Cert covers DNS:mailpit, DNS:blamejs-test-mailpit, DNS:localhost.
  // SNI rejects IP literals, so use "localhost" — it's in the SAN list.
  var transport = b.mail.transports.smtp({
    host:           "localhost",
    port:           1025,
    ehloName:       "blamejs-test",
    timeoutMs:      5000,
    minTlsVersion:  "TLSv1.3",
    ca:             caPem,
    // Verification stays on: the CA we just pinned anchors the chain,
    // so no rejectUnauthorized: false bypass anywhere.
  });

  await _httpDelete("http://127.0.0.1:8025/api/v1/messages");

  // ---- single-recipient, full STARTTLS with strict cert verification ----
  var subject = "blamejs-integration " + Date.now();
  var body = "Hello from the integration suite at " + new Date().toISOString();
  var rv = await transport.send({
    from:    "test@blamejs.local",
    to:      ["recipient@example.com"],
    subject: subject,
    text:    body,
  });
  check("smtp.send: returns transport='smtp'", rv && rv.transport === "smtp");
  check("smtp.send: returns deliveredAt timestamp",
        typeof rv.deliveredAt === "number" && rv.deliveredAt > 0);

  var listing = await _httpJson("http://127.0.0.1:8025/api/v1/messages");
  check("mailpit: captured exactly one message",
        listing && Array.isArray(listing.messages) && listing.messages.length === 1);
  var captured = listing.messages[0];
  check("mailpit: subject matches exactly",
        captured.Subject === subject);
  check("mailpit: From correct",
        captured.From && captured.From.Address === "test@blamejs.local");
  check("mailpit: single To recipient",
        Array.isArray(captured.To) && captured.To.length === 1 &&
        captured.To[0].Address === "recipient@example.com");

  var detail = await _httpJson("http://127.0.0.1:8025/api/v1/message/" + captured.ID);
  check("mailpit: body text round-trip",
        detail && detail.Text && detail.Text.indexOf(body) !== -1);

  // ---- multi-recipient (to + cc) + dot-stuffing edge case ----
  await _httpDelete("http://127.0.0.1:8025/api/v1/messages");
  var bodyWithDot = "first line\n.dotline\nlast line";
  await transport.send({
    from:    "test@blamejs.local",
    to:      ["a@example.com", "b@example.com"],
    cc:      ["c@example.com"],
    subject: "multi-rcpt + dot-stuff",
    text:    bodyWithDot,
  });
  var listing2 = await _httpJson("http://127.0.0.1:8025/api/v1/messages");
  check("mailpit: multi-rcpt captured",
        listing2.messages.length === 1);
  var multi = listing2.messages[0];
  var allRcpts = (multi.To || []).concat(multi.Cc || []).map(function (a) { return a.Address; });
  check("smtp: all 3 recipients delivered (to+cc)",
        allRcpts.indexOf("a@example.com") !== -1 &&
        allRcpts.indexOf("b@example.com") !== -1 &&
        allRcpts.indexOf("c@example.com") !== -1);
  var detail2 = await _httpJson("http://127.0.0.1:8025/api/v1/message/" + multi.ID);
  check("smtp: dot-stuffing transparency works (leading-dot line preserved)",
        detail2 && detail2.Text && detail2.Text.indexOf(".dotline") !== -1);

  // ---- bad CA: cert verification fails cleanly with a real error ----
  var transportBadCa = b.mail.transports.smtp({
    host:           "localhost",
    port:           1025,
    ehloName:       "blamejs-test",
    timeoutMs:      5000,
    ca:             "-----BEGIN CERTIFICATE-----\nMIIB-not-a-real-cert\n-----END CERTIFICATE-----\n",
  });
  var threw = null;
  try {
    await transportBadCa.send({
      from:    "test@blamejs.local",
      to:      ["x@example.com"],
      subject: "should fail",
      text:    "blocked by cert verify",
    });
  } catch (e) { threw = e; }
  check("smtp: bogus CA causes a MailError (verification not bypassed)",
        threw && threw.code && /smtp|tls|cert|verify/i.test(threw.code + " " + (threw.message || "")));

  // ---- final cleanup ----
  await _httpDelete("http://127.0.0.1:8025/api/v1/messages");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

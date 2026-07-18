// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Live DKIM-signed SMTP delivery against the docker-compose Mailpit
 * fixture. Exercises lib/mail-dkim.js wiring through smtpTransport's
 * dkimSigner option — the captured message's RFC 5322 body must
 * include a syntactically-valid DKIM-Signature header that mailpit
 * preserves verbatim.
 *
 * Covers both signature algorithms the framework supports: rsa-sha256
 * (RFC 6376) and ed25519-sha256 (RFC 8463). PQC DKIM is forward-looking
 * — the framework's dkim docstring carries that intent already.
 *
 * The simple/simple canonicalization stage goes further than header
 * presence: it fetches the RAW captured source back out of mailpit and
 * cryptographically verifies the signature over the bytes that actually
 * traversed the SMTP wire — simple canonicalization tolerates zero byte
 * drift, so any framing change between sign and capture fails it.
 */
var fs = require("node:fs");
var http = require("node:http");
var crypto = require("node:crypto");
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
          return reject(new Error("HTTP " + res.statusCode));
        }
        try { resolve(JSON.parse(body)); }
        catch (_e) { reject(new Error("bad JSON")); }
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
      res.on("end", resolve);
    });
    req.once("error", reject);
    req.end();
  });
}

async function _runWithAlgorithm(algorithm, privateKey, label) {
  await _httpDelete("http://127.0.0.1:8025/api/v1/messages");

  var caPem = fs.readFileSync(process.env.BLAMEJS_TEST_CA_PATH, "utf8");
  var signer = b.mail.dkim.create({
    domain:     "example.com",
    selector:   "test",
    privateKey: privateKey,
    algorithm:  algorithm,
    headersToSign: ["From", "To", "Subject", "Date"],
  });
  var transport = b.mail.transports.smtp({
    host:       "localhost",
    port:       1025,
    ehloName:   "blamejs-test",
    timeoutMs:  5000,
    ca:         caPem,
    dkimSigner: signer,
  });

  var subject = "dkim-" + algorithm + "-" + Date.now();
  await transport.send({
    from:    "test@example.com",
    to:      ["dkim@blamejs.local"],
    subject: subject,
    text:    "DKIM-signed test body for " + label,
  });

  var listing = await _httpJson("http://127.0.0.1:8025/api/v1/messages");
  check("[" + label + "] mailpit captured the dkim-signed message",
        listing.messages.length === 1);
  var captured = listing.messages[0];
  // mailpit's API doesn't surface DKIM-Signature in the summary listing —
  // need the raw source via /raw to inspect signature headers.
  var raw = await new Promise(function (resolve, reject) {
    http.get("http://127.0.0.1:8025/api/v1/message/" + captured.ID + "/raw", function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () { resolve(Buffer.concat(chunks).toString("utf8")); });
    }).once("error", reject);
  });
  check("[" + label + "] raw source contains DKIM-Signature header",
        /^DKIM-Signature:\s/m.test(raw));
  check("[" + label + "] DKIM-Signature has v=1 tag",
        /v=1/.test(raw));
  check("[" + label + "] DKIM-Signature has correct a= algorithm",
        new RegExp("a=" + algorithm).test(raw));
  check("[" + label + "] DKIM-Signature has d=example.com domain",
        /d=example\.com/.test(raw));
  check("[" + label + "] DKIM-Signature has s=test selector",
        /s=test/.test(raw));
  check("[" + label + "] DKIM-Signature has bh= body hash",
        /bh=[A-Za-z0-9+/=]+/.test(raw));
  check("[" + label + "] DKIM-Signature has b= signature",
        /b=[A-Za-z0-9+/=\s]+/.test(raw));
}

// Sign with simple/simple canonicalization, deliver through the live SMTP
// transport, then VERIFY the signature on the raw bytes mailpit captured.
// Simple canonicalization signs the headers and body verbatim (RFC 6376
// sections 3.4.1 and 3.4.3), so this only passes when the exact signed
// bytes survive smtpTransport framing, the SMTP hop, and mailpit capture.
async function _runSimpleCanonWireVerify() {
  await _httpDelete("http://127.0.0.1:8025/api/v1/messages");

  var caPem = fs.readFileSync(process.env.BLAMEJS_TEST_CA_PATH, "utf8");
  var kp = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding:  { type: "spki",  format: "pem" },
  });
  var signer = b.mail.dkim.create({
    domain:           "example.com",
    selector:         "test",
    privateKey:       kp.privateKey,
    canonicalization: "simple/simple",
    headersToSign:    ["From", "To", "Subject", "Date"],
  });
  var transport = b.mail.transports.smtp({
    host:       "localhost",
    port:       1025,
    ehloName:   "blamejs-test",
    timeoutMs:  5000,
    ca:         caPem,
    dkimSigner: signer,
  });

  await transport.send({
    from:    "test@example.com",
    to:      ["dkim-simple@blamejs.local"],
    subject: "dkim-simple-simple-" + Date.now(),
    text:    "Simple-canon wire-interop body line one.\r\nLine two.",
  });

  var listing = await _httpJson("http://127.0.0.1:8025/api/v1/messages");
  check("[simple/simple] mailpit captured the dkim-signed message",
        listing.messages.length === 1);
  var captured = listing.messages[0];
  var raw = await new Promise(function (resolve, reject) {
    http.get("http://127.0.0.1:8025/api/v1/message/" + captured.ID + "/raw", function (res) {
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () { resolve(Buffer.concat(chunks).toString("utf8")); });
    }).once("error", reject);
  });
  check("[simple/simple] captured signature declares c=simple/simple",
        /c=simple\/simple/.test(raw));

  var pubB64 = kp.publicKey.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  var dnsLookup = async function () { return [["v=DKIM1; k=rsa; p=" + pubB64]]; };
  b.mail.dkim._resetDkimKeyCacheForTest();
  var rv = await b.mail.dkim.verify(raw, { dnsLookup: dnsLookup });
  check("[simple/simple] wire-captured message verifies: result pass",
        Array.isArray(rv) && rv.length === 1 && rv[0].result === "pass");
  check("[simple/simple] wire verify reports zero errors",
        rv[0] && Array.isArray(rv[0].errors) && rv[0].errors.length === 0);

  // Control: the pass above is cryptographic, not vacuous — one flipped
  // body byte in the captured source must flip the verdict to fail.
  var tampered = raw.replace("wire-interop body line one", "wire-interop body line 0ne");
  check("[simple/simple] tamper control mutated the captured body",
        tampered !== raw);
  b.mail.dkim._resetDkimKeyCacheForTest();
  var rvTampered = await b.mail.dkim.verify(tampered, { dnsLookup: dnsLookup });
  check("[simple/simple] tampered wire body fails verification",
        rvTampered[0] && rvTampered[0].result === "fail");
}

async function run() {
  var svc = await services.requireService("mailpit");
  if (!svc.ok) throw new Error("mailpit unreachable: " + svc.reason);

  // ---- rsa-sha256 (RFC 6376 default) ----
  var rsa = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding:  { type: "spki",  format: "pem" },
  });
  await _runWithAlgorithm("rsa-sha256", rsa.privateKey, "rsa");

  // ---- ed25519-sha256 (RFC 8463) ----
  var ed = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding:  { type: "spki",  format: "pem" },
  });
  await _runWithAlgorithm("ed25519-sha256", ed.privateKey, "ed25519");

  // ---- simple/simple canonicalization verified on the wire bytes ----
  await _runSimpleCanonWireVerify();

  // ---- bad algorithm rejected at signer build time ----
  var threw = null;
  try {
    b.mail.dkim.create({
      domain:     "example.com",
      selector:   "test",
      privateKey: "not-real",
      algorithm:  "rsa-sha1",
    });
  } catch (e) { threw = e; }
  check("dkim.create: rejects unsupported algorithm",
        threw && threw.code && /algorithm/i.test(threw.message));

  await _httpDelete("http://127.0.0.1:8025/api/v1/messages");
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

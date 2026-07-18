// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.scan — ICAP / ClamAV-INSTREAM AV-scan facade.
 *
 * Mocks the socket I/O via an EventEmitter shim so tests don't need a
 * live ICAP daemon. Surface coverage + bad-input + audit-emit shape.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var mailScan = require("../../lib/mail-scan");

var EventEmitter = require("node:events").EventEmitter;

function _fakeAudit() {
  var emitted = [];
  return {
    emitted: emitted,
    safeEmit: function (rec) { emitted.push(rec); },
  };
}

function _fakeSocket(scriptedResponse) {
  var sock = new EventEmitter();
  var writes = [];
  sock.write = function (chunk) {
    writes.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "ascii"));
    return true;
  };
  sock.end = function () {
    // Defer the data → end so the consumer's `data` handler attaches first.
    setImmediate(function () {
      if (scriptedResponse) sock.emit("data", scriptedResponse);
      sock.emit("end");
    });
  };
  sock.destroy = function () { sock.emit("close"); };
  sock._writes = writes;
  return sock;
}

// A socket that never replies — end() is a no-op, so the only way the
// scan promise settles is the lib's own wall-clock timeout timer.
function _fakeSilentSocket() {
  var sock = new EventEmitter();
  sock.write = function () { return true; };
  sock.end = function () { /* never emits data/end — force the timeout path */ };
  sock.destroy = function () { sock.emit("close"); };
  return sock;
}

// A socket that surfaces a transport error instead of a reply.
function _fakeErrorSocket(errMsg) {
  var sock = new EventEmitter();
  sock.write = function () { return true; };
  sock.end = function () {
    setImmediate(function () { sock.emit("error", new Error(errMsg || "ECONNRESET")); });
  };
  sock.destroy = function () { sock.emit("close"); };
  return sock;
}

function testSurface() {
  check("create is fn",              typeof mailScan.create === "function");
  check("compliancePosture is fn",   typeof mailScan.compliancePosture === "function");
  check("MailScanError is fn",       typeof mailScan.MailScanError === "function");
  check("PROFILES has strict",       !!mailScan.PROFILES.strict);
  check("PROFILES has balanced",     !!mailScan.PROFILES.balanced);
  check("PROFILES has permissive",   !!mailScan.PROFILES.permissive);
  check("ALLOWED_PROTOCOLS has icap", mailScan.ALLOWED_PROTOCOLS["icap"] === true);
  check("ALLOWED_PROTOCOLS has clamav-instream",
    mailScan.ALLOWED_PROTOCOLS["clamav-instream"] === true);
  check("posture hipaa → strict",    mailScan.compliancePosture("hipaa") === "strict");
}

function expectThrow(label, fn, expectedCodePrefix) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && typeof threw.code === "string" &&
    threw.code.indexOf(expectedCodePrefix) === 0);
}

function testRefuseMissingHost() {
  expectThrow("refuses missing host",
    function () { mailScan.create({ port: 1344 }); },
    "mail-scan/bad-host");
}

function testRefuseBadPort() {
  expectThrow("refuses bad port (0)",
    function () { mailScan.create({ host: "av.example.test", port: 0 }); },
    "mail-scan/bad-port");
  expectThrow("refuses bad port (Infinity)",
    function () { mailScan.create({ host: "av.example.test", port: Infinity }); },
    "mail-scan/bad-port");
  expectThrow("refuses bad port (NaN)",
    function () { mailScan.create({ host: "av.example.test", port: NaN }); },
    "mail-scan/bad-port");
  expectThrow("refuses bad port (>65535)",
    function () { mailScan.create({ host: "av.example.test", port: 70000 }); },
    "mail-scan/bad-port");
}

function testRefuseBadProtocol() {
  expectThrow("refuses unknown protocol",
    function () {
      mailScan.create({ host: "av.example.test", port: 1344, protocol: "bogus" });
    },
    "mail-scan/bad-protocol");
}

function testRefuseBadProfile() {
  expectThrow("refuses unknown profile",
    function () {
      mailScan.create({ host: "av.example.test", port: 1344, profile: "loose" });
    },
    "mail-scan/bad-profile");
}

function testRefuseUnknownOpt() {
  var threw = null;
  try {
    mailScan.create({ host: "av.example.test", port: 1344, bogusOpt: 1 });
  } catch (e) { threw = e; }
  check("refuses unknown opt", threw && /unknown option/i.test(threw.message || ""));
}

function testHandleSurface() {
  var h = mailScan.create({ host: "av.example.test", port: 1344 });
  check("handle has scan fn",         typeof h.scan === "function");
  check("handle.profile = strict",    h.profile === "strict");
  check("handle.protocol = icap",     h.protocol === "icap");
  check("handle.service defaults",    h.service === "srv_clamav");
  check("handle.host preserved",      h.host === "av.example.test");
  check("handle.port preserved",      h.port === 1344);
}

function testScanRefusesBadInput() {
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit });
  var threw = null;
  try { h.scan(null); } catch (e) { threw = e; }
  check("refuses non-Buffer messageBytes",
    threw && threw.code === "mail-scan/bad-input");
  var threw2 = null;
  try { h.scan(Buffer.alloc(0)); } catch (e) { threw2 = e; }
  check("refuses empty Buffer",
    threw2 && threw2.code === "mail-scan/bad-input");
}

function testScanRefusesOversizeMessage() {
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit });
  var big = Buffer.alloc(26 * 1024 * 1024, 0x41);                                                  // 26 MiB > 25 MiB strict cap
  var threw = null;
  try { h.scan(big); } catch (e) { threw = e; }
  check("refuses oversize message",
    threw && threw.code === "mail-scan/oversize-message");
}

async function testScanIcapCleanVerdictViaInjectedSocket() {
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit });
  var icapClean = Buffer.from(
    "ICAP/1.0 204 No Content\r\nISTag: \"clean\"\r\n\r\n", "ascii");
  var sock = _fakeSocket(icapClean);
  var rv = await h.scan(Buffer.from("Test message body"), { _socket: sock });
  check("ICAP 204 → clean verdict",   rv.verdict === "clean");
  check("ICAP returns icapResponse",  rv.icapResponse && rv.icapResponse.statusCode === 204);
  check("ICAP threats array empty",   Array.isArray(rv.threats) && rv.threats.length === 0);

  var seen = audit.emitted.map(function (e) { return e.action; });
  check("audit emitted mail.scan.request",
    seen.indexOf("mail.scan.request") !== -1);
  check("audit emitted mail.scan.clean",
    seen.indexOf("mail.scan.clean") !== -1);
}

async function testScanIcapInfectedVerdict() {
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit });
  var icapInfected = Buffer.from(
    "ICAP/1.0 200 OK\r\n" +
    "X-Infection-Found: Type=0; Resolution=2; Threat=EICAR-Test-File\r\n" +
    "Encapsulated: res-hdr=0, res-body=0\r\n" +
    "\r\n", "ascii");
  var sock = _fakeSocket(icapInfected);
  var rv = await h.scan(Buffer.from("Body with EICAR signature"), { _socket: sock });
  check("ICAP X-Infection-Found → infected verdict", rv.verdict === "infected");
  check("ICAP threat name surfaced", rv.threats[0] === "EICAR-Test-File");
  var seen = audit.emitted.map(function (e) { return e.action; });
  check("audit emitted mail.scan.infected",
    seen.indexOf("mail.scan.infected") !== -1);
}

async function testScanArchiveEntriesGate() {
  // When operator passes archiveEntries containing a path-traversal
  // entry, the scanner refuses BEFORE invoking the ICAP daemon (zip-
  // slip pre-AV defense via b.guardArchive).
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit });
  // No _socket needed — the pre-scan gate fires synchronously and
  // resolves with infected verdict.
  var rv = await h.scan(Buffer.from("payload"), {
    archiveEntries: [{ name: "../etc/passwd", size: 100, compressedSize: 50 }],
  });
  check("archive zip-slip pre-scan → infected verdict",
    rv.verdict === "infected");
  check("archive threats prefixed 'archive:'",
    rv.threats[0] && rv.threats[0].indexOf("archive:") === 0);
}

// ---- create() adversarial / omitted-input branches ----

function testCreateRefusesNonObjectOpts() {
  expectThrow("refuses non-object opts (number)",
    function () { mailScan.create(42); },
    "mail-scan/bad-opts");
}

function testCreateRefusesBadService() {
  // service defaults to "srv_clamav", but an operator who passes a
  // non-string truthy service on the ICAP backend must be refused, not
  // silently coerced into the request line.
  expectThrow("refuses non-string service on icap",
    function () {
      mailScan.create({ host: "av.example.test", port: 1344, service: 123 });
    },
    "mail-scan/bad-service");
}

function testCreateRefusesBadTimeout() {
  expectThrow("refuses negative timeoutMs",
    function () {
      mailScan.create({ host: "av.example.test", port: 1344, timeoutMs: -5 });
    },
    "mail-scan/bad-timeout");
  expectThrow("refuses non-finite timeoutMs",
    function () {
      mailScan.create({ host: "av.example.test", port: 1344, timeoutMs: Infinity });
    },
    "mail-scan/bad-timeout");
}

function _clamHandle(audit, extra) {
  var o = { host: "clamd.example.test", port: 3310, protocol: "clamav-instream", audit: audit };
  if (extra) { for (var k in extra) { if (Object.prototype.hasOwnProperty.call(extra, k)) o[k] = extra[k]; } }
  return mailScan.create(o);
}

// ---- ClamAV INSTREAM reply-classifier branches (previously untestable:
// the clamav path had no socket-injection seam, so none of its
// verdict branches had coverage). ----

async function testClamavCleanVerdict() {
  var audit = _fakeAudit();
  var h = _clamHandle(audit);
  var sock = _fakeSocket(Buffer.from("stream: OK\n", "ascii"));
  var rv = await h.scan(Buffer.from("clean body"), { _socket: sock });
  check("clamav stream: OK -> clean", rv.verdict === "clean");
  check("clamav clean threats empty", Array.isArray(rv.threats) && rv.threats.length === 0);
  var seen = audit.emitted.map(function (e) { return e.action; });
  check("clamav clean emits request+clean",
    seen.indexOf("mail.scan.request") !== -1 && seen.indexOf("mail.scan.clean") !== -1);
  // Wire-format sanity: the first frame must be the zINSTREAM command.
  check("clamav sends zINSTREAM command first",
    sock._writes.length > 0 && sock._writes[0].toString("ascii").indexOf("zINSTREAM") === 0);
}

async function testClamavInfectedVerdict() {
  var audit = _fakeAudit();
  var h = _clamHandle(audit);
  var sock = _fakeSocket(Buffer.from("stream: Eicar-Test-Signature FOUND\n", "ascii"));
  var rv = await h.scan(Buffer.from("body with signature"), { _socket: sock });
  check("clamav FOUND -> infected", rv.verdict === "infected");
  check("clamav threat name surfaced", rv.threats[0] === "Eicar-Test-Signature");
  var seen = audit.emitted.map(function (e) { return e.action; });
  check("clamav infected emits mail.scan.infected", seen.indexOf("mail.scan.infected") !== -1);
}

async function testClamavErrorReplyVerdict() {
  var audit = _fakeAudit();
  var h = _clamHandle(audit);
  var sock = _fakeSocket(Buffer.from("INSTREAM size limit exceeded. ERROR\n", "ascii"));
  var rv = await h.scan(Buffer.from("oversize-at-daemon"), { _socket: sock });
  check("clamav ERROR reply -> error verdict", rv.verdict === "error");
}

async function testClamavUnrecognizedReplyFailsClosed() {
  // An unparseable reply must NOT be treated as clean — fail closed so
  // the listener gets a definite do-not-deliver signal.
  var audit = _fakeAudit();
  var h = _clamHandle(audit);
  var sock = _fakeSocket(Buffer.from("garbled daemon banner without a verdict\n", "ascii"));
  var rv = await h.scan(Buffer.from("payload"), { _socket: sock });
  check("clamav unrecognized reply -> error (fail closed)", rv.verdict === "error");
}

// RED before the fix: a reply that carries BOTH a benign "stream: OK"
// token and a malign "... FOUND" token (a coalesced / stale-then-fresh
// reply, or an intermediary that concatenates two responses) must never
// downgrade an infection to "clean". The classifier is fail-closed: the
// FOUND signal dominates the OK signal.
async function testClamavCoalescedReplyDoesNotFailOpen() {
  var audit = _fakeAudit();
  var h = _clamHandle(audit);
  var sock = _fakeSocket(
    Buffer.from("stream: OK\nstream: Eicar-Test-Signature FOUND\n", "ascii"));
  var rv = await h.scan(Buffer.from("body"), { _socket: sock });
  check("clamav coalesced OK+FOUND -> infected (no fail-open)",
    rv.verdict === "infected");
  check("clamav coalesced surfaces the FOUND threat",
    rv.threats[0] === "Eicar-Test-Signature");
}

// ---- ICAP verdict / error-path branches ----

async function testIcapErrorStatusVerdict() {
  // A 5xx ICAP response with no infection header is neither clean nor
  // infected — the scanner must surface "error", not silently "clean".
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit });
  var sock = _fakeSocket(Buffer.from("ICAP/1.0 500 Server Error\r\n\r\n", "ascii"));
  var rv = await h.scan(Buffer.from("body"), { _socket: sock });
  check("ICAP 500 -> error verdict", rv.verdict === "error");
  var seen = audit.emitted.map(function (e) { return e.action; });
  check("ICAP error emits mail.scan.error", seen.indexOf("mail.scan.error") !== -1);
}

async function testIcapBlockedStatusInfected() {
  // RFC 3507 convention: 403 = the ICAP service blocked the request
  // (AV hit). safeIcap flags threatFound; the scanner reports infected
  // even when no threat name is present.
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit });
  var sock = _fakeSocket(Buffer.from("ICAP/1.0 403 Forbidden\r\n\r\n", "ascii"));
  var rv = await h.scan(Buffer.from("body"), { _socket: sock });
  check("ICAP 403 -> infected verdict", rv.verdict === "infected");
  check("ICAP 403 threats array present", Array.isArray(rv.threats));
}

async function testIcapMalformedResponseFailsToError() {
  // A disallowed status code (302) makes b.safeIcap.parse throw; the
  // scanner must convert that rejection into an error verdict carrying
  // the underlying error code, never crash or resolve clean.
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit });
  var sock = _fakeSocket(Buffer.from("ICAP/1.0 302 Found\r\n\r\n", "ascii"));
  var rv = await h.scan(Buffer.from("body"), { _socket: sock });
  check("ICAP disallowed-status parse throw -> error verdict", rv.verdict === "error");
  check("ICAP error surfaces underlying errorCode",
    typeof rv.errorCode === "string" && rv.errorCode.indexOf("safe-icap/") === 0);
}

async function testIcapSocketErrorFailsToError() {
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit });
  var sock = _fakeErrorSocket("ECONNRESET");
  var rv = await h.scan(Buffer.from("body"), { _socket: sock });
  check("ICAP socket error -> error verdict", rv.verdict === "error");
  check("ICAP socket error code is transport",
    rv.errorCode === "mail-scan/transport");
}

async function testIcapTimeoutFailsToError() {
  // Silent daemon: the only settle path is the per-request wall-clock
  // timeout. Await the scan promise (the lib timer, not a test sleep).
  var audit = _fakeAudit();
  var h = mailScan.create({ host: "av.example.test", port: 1344, audit: audit, timeoutMs: 60 });
  var sock = _fakeSilentSocket();
  var rv = await h.scan(Buffer.from("body"), { _socket: sock });
  check("ICAP silent daemon -> timeout error verdict", rv.verdict === "error");
  check("ICAP timeout errorCode", rv.errorCode === "mail-scan/timeout");
  var seen = audit.emitted.map(function (e) { return e.action; });
  check("ICAP timeout emits mail.scan.timeout", seen.indexOf("mail.scan.timeout") !== -1);
}

function run(cb) {
  testSurface();
  testRefuseMissingHost();
  testRefuseBadPort();
  testRefuseBadProtocol();
  testRefuseBadProfile();
  testRefuseUnknownOpt();
  testCreateRefusesNonObjectOpts();
  testCreateRefusesBadService();
  testCreateRefusesBadTimeout();
  testHandleSurface();
  testScanRefusesBadInput();
  testScanRefusesOversizeMessage();

  return Promise.resolve()
    .then(testScanIcapCleanVerdictViaInjectedSocket)
    .then(testScanIcapInfectedVerdict)
    .then(testScanArchiveEntriesGate)
    .then(testClamavCleanVerdict)
    .then(testClamavInfectedVerdict)
    .then(testClamavErrorReplyVerdict)
    .then(testClamavUnrecognizedReplyFailsClosed)
    .then(testClamavCoalescedReplyDoesNotFailOpen)
    .then(testIcapErrorStatusVerdict)
    .then(testIcapBlockedStatusInfected)
    .then(testIcapMalformedResponseFailsToError)
    .then(testIcapSocketErrorFailsToError)
    .then(testIcapTimeoutFailsToError)
    .then(function () { if (cb) cb(); });
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("[mail-scan] OK"); },
    function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); });
}

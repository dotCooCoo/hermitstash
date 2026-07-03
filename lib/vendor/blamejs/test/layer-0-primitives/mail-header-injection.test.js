// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail — outbound header injection (CWE-93 / RFC 5322). Reply-To and custom
 * header KEYS reach the wire in _buildRfc822; a CRLF in either smuggles
 * arbitrary headers (Bcc / Reply-To override / Content-Type). _validateMessage
 * must fail closed on CRLF in replyTo, header keys, and header values.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mailer() {
  return b.mail.create({
    transport: function () { return Promise.resolve({ ok: true }); },
    audit:     false,
  });
}
function _base() {
  return { from: "sender@example.com", to: "rcpt@example.com", subject: "hi", text: "hello" };
}
async function _expectThrow(label, message, codeMatch) {
  var m = _mailer();
  try { await m.send(message); check(label + " (did not throw)", false); }
  catch (e) { check(label, (e && e.code || "").indexOf(codeMatch) !== -1); }
}

async function testCleanSends() {
  var m = _mailer();
  var sent = true;
  try { await m.send(_base()); } catch (_e) { sent = false; }
  check("clean message sends", sent === true);
}
async function testReplyToCrlfRefused() {
  await _expectThrow("Reply-To CRLF refused (header injection)",
    Object.assign(_base(), { replyTo: "a@b.com\r\nBcc: evil@x.com" }), "mail/invalid-reply-to");
}
async function testHeaderKeyCrlfRefused() {
  await _expectThrow("header KEY CRLF refused (header injection)",
    Object.assign(_base(), { headers: { "X-Foo\r\nBcc: evil@x.com": "v" } }), "mail/invalid-header");
}
async function testHeaderValueCrlfRefused() {
  await _expectThrow("header VALUE CRLF refused (header injection)",
    Object.assign(_base(), { headers: { "X-Foo": "v\r\nBcc: evil@x.com" } }), "mail/invalid-header");
}

async function run() {
  await testCleanSends();
  await testReplyToCrlfRefused();
  await testHeaderKeyCrlfRefused();
  await testHeaderValueCrlfRefused();
  console.log("[mail-header-injection] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {}, function (e) { console.error("FAIL: " + helpers.formatErr(e)); process.exit(1); });
}

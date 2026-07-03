// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.requireTls — RFC 8689 REQUIRETLS SMTP extension.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("requireTls.peerSupports is fn",            typeof b.mail.requireTls.peerSupports === "function");
  check("requireTls.mailFromExtension is fn",       typeof b.mail.requireTls.mailFromExtension === "function");
  check("requireTls.parseTlsRequiredHeader is fn",  typeof b.mail.requireTls.parseTlsRequiredHeader === "function");
  check("requireTls.REQUIRETLS_TOKEN is REQUIRETLS",
        b.mail.requireTls.REQUIRETLS_TOKEN === "REQUIRETLS");
}

function testPeerSupports() {
  check("peerSupports: keyword present",
        b.mail.requireTls.peerSupports(["PIPELINING", "SIZE 10485760", "REQUIRETLS", "STARTTLS"]) === true);
  check("peerSupports: case-insensitive match",
        b.mail.requireTls.peerSupports(["requiretls"]) === true);
  check("peerSupports: keyword absent",
        b.mail.requireTls.peerSupports(["PIPELINING", "STARTTLS"]) === false);
  check("peerSupports: empty array",
        b.mail.requireTls.peerSupports([]) === false);
  check("peerSupports: non-array → false",
        b.mail.requireTls.peerSupports(null) === false);
  check("peerSupports: non-string entries skipped",
        b.mail.requireTls.peerSupports([null, 5, "REQUIRETLS"]) === true);

  // Defensive: a token that contains REQUIRETLS as substring of a
  // larger keyword (e.g. "FOO-REQUIRETLS-BAR") must NOT match.
  check("peerSupports: substring match refused",
        b.mail.requireTls.peerSupports(["FOO-REQUIRETLS-BAR"]) === false);

  // EHLO keyword + parameter shape: "REQUIRETLS\r\n" or
  // "SIZE 10485760" — the keyword is everything up to the first
  // space.
  check("peerSupports: keyword with parameter still matches",
        b.mail.requireTls.peerSupports(["REQUIRETLS some-future-param"]) === true);
}

function testMailFromExtension() {
  check("mailFromExtension: true → ' REQUIRETLS'",
        b.mail.requireTls.mailFromExtension({ requireTls: true }) === " REQUIRETLS");
  check("mailFromExtension: false → empty",
        b.mail.requireTls.mailFromExtension({ requireTls: false }) === "");
  check("mailFromExtension: undefined → empty",
        b.mail.requireTls.mailFromExtension({}) === "");

  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("mailFromExtension: null opts refused",
             function () { b.mail.requireTls.mailFromExtension(null); }, "mail-require-tls/bad-opts");
  expectCode("mailFromExtension: array opts refused",
             function () { b.mail.requireTls.mailFromExtension([]); }, "mail-require-tls/bad-opts");
  expectCode("mailFromExtension: non-boolean flag refused (truthy string)",
             function () { b.mail.requireTls.mailFromExtension({ requireTls: "yes" }); }, "mail-require-tls/bad-flag");
  expectCode("mailFromExtension: non-boolean flag refused (number)",
             function () { b.mail.requireTls.mailFromExtension({ requireTls: 1 }); }, "mail-require-tls/bad-flag");
}

function testParseTlsRequiredHeader() {
  check("parse: 'No' → 'no'",
        b.mail.requireTls.parseTlsRequiredHeader("No") === "no");
  check("parse: 'no' → 'no'",
        b.mail.requireTls.parseTlsRequiredHeader("no") === "no");
  check("parse: '  no  ' → 'no'",
        b.mail.requireTls.parseTlsRequiredHeader("  no  ") === "no");
  check("parse: 'NO' → 'no'",
        b.mail.requireTls.parseTlsRequiredHeader("NO") === "no");
  check("parse: 'yes' → 'yes' (RFC 8689 §5 default)",
        b.mail.requireTls.parseTlsRequiredHeader("yes") === "yes");
  check("parse: 'whatever' → 'yes' (conservative)",
        b.mail.requireTls.parseTlsRequiredHeader("whatever") === "yes");
  check("parse: 'NoMaybe' → 'yes' (only literal 'no' opts out)",
        b.mail.requireTls.parseTlsRequiredHeader("NoMaybe") === "yes");
  check("parse: empty → null",
        b.mail.requireTls.parseTlsRequiredHeader("") === null);
  check("parse: whitespace-only → null",
        b.mail.requireTls.parseTlsRequiredHeader("   ") === null);
  check("parse: undefined → null",
        b.mail.requireTls.parseTlsRequiredHeader(undefined) === null);
  check("parse: non-string → null",
        b.mail.requireTls.parseTlsRequiredHeader(5) === null);

  // Control-char refusal — must scan the RAW value, not the trimmed
  // one. A leading/trailing CR/LF must NOT be stripped by trim() before
  // the control-char gate fires, or "\nno" / "no\r" silently parses as
  // "no" and the contract (and changelog claim) is broken.
  function expectControlRefusal(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && /bad-header-value/.test(threw.code || ""));
  }
  expectControlRefusal("parse: CR/LF in middle refused",
                       function () { b.mail.requireTls.parseTlsRequiredHeader("no\r\nattacker: yes"); });
  expectControlRefusal("parse: leading \\n + 'no' refused (pre-trim scan)",
                       function () { b.mail.requireTls.parseTlsRequiredHeader("\nno"); });
  expectControlRefusal("parse: 'no' + trailing \\r refused (pre-trim scan)",
                       function () { b.mail.requireTls.parseTlsRequiredHeader("no\r"); });
  expectControlRefusal("parse: leading NUL refused",
                       function () { b.mail.requireTls.parseTlsRequiredHeader("\x00no"); });
  expectControlRefusal("parse: trailing DEL refused",
                       function () { b.mail.requireTls.parseTlsRequiredHeader("no\x7F"); });
  // HT (\t) is structural folding whitespace per HTTP/email headers;
  // accept and let trim() absorb it so the value still parses.
  check("parse: leading/trailing HT absorbed → 'no'",
        b.mail.requireTls.parseTlsRequiredHeader("\tno\t") === "no");
}

async function run() {
  testSurface();
  testPeerSupports();
  testMailFromExtension();
  testParseTlsRequiredHeader();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

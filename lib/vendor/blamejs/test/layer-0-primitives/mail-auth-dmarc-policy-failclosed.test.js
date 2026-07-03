// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.dmarc.evaluate — a DMARC record that lacks a valid required p=
 * tag (RFC 7489 §6.3) must NOT recommend "deliver" for a failing/unaligned
 * message.
 *
 * Regression: _parseDmarcRecord took p= / sp= verbatim and never required
 * p=, so the disposition ternary mapped any policy.p that was not exactly
 * "reject"/"quarantine" — including null (no p=) and typos ("rejct") —
 * to recommendedAction "deliver". A spoofed sender with a
 * failing SPF and no DKIM therefore got result:"fail" +
 * recommendedAction:"deliver" (fail-open). The fix validates p=/sp= against
 * {none,quarantine,reject}, requires a valid p= for the record to count,
 * and fails closed (permerror, no "deliver") on an absent/invalid policy.
 *
 * Network-free: DNS is supplied via an operator dnsLookup mock.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// Failing/unaligned auth for a spoofed sender: SPF fail, no DKIM, From a
// domain whose published DMARC record is the one under test.
var SPOOF = {
  from: "ceo@victim.example",
  spf:  { result: "fail", domain: "attacker.invalid" },
  dkim: [],
};

function dnsReturning(record) {
  return async function (host) {
    if (host === "_dmarc.victim.example") {
      return [[record]];
    }
    var err = new Error("ENOTFOUND"); err.code = "ENOTFOUND"; throw err;
  };
}

async function testNoPolicyTagFailsClosed() {
  // RFC 7489 §6.3 — p= is REQUIRED. A record without it carries no usable
  // policy; the receiver must treat it as none/permerror, NOT deliver.
  var rv = await b.mail.dmarc.evaluate(Object.assign({}, SPOOF, {
    dnsLookup: dnsReturning("v=DMARC1; adkim=s; aspf=s"),
  }));
  check("dmarc.evaluate: missing p= → NOT deliver",
        rv.recommendedAction !== "deliver");
  check("dmarc.evaluate: missing p= → permerror",
        rv.result === "permerror");
}

async function testTypoPolicyTagFailsClosed() {
  // "rejct" is not a recognized policy; must not silently fall through to
  // deliver.
  var rv = await b.mail.dmarc.evaluate(Object.assign({}, SPOOF, {
    dnsLookup: dnsReturning("v=DMARC1; p=rejct"),
  }));
  check("dmarc.evaluate: typo p=rejct → NOT deliver",
        rv.recommendedAction !== "deliver");
  check("dmarc.evaluate: typo p=rejct → permerror",
        rv.result === "permerror");
}

async function testWhitespacePaddedPolicyTag() {
  // RFC 7489 §6.4 tag-list grammar permits whitespace around the value;
  // "p= reject " is a legitimate reject policy once the grammar's trim
  // applies — it must NOT deliver the spoofed/failing message.
  var rv = await b.mail.dmarc.evaluate(Object.assign({}, SPOOF, {
    dnsLookup: dnsReturning("v=DMARC1; p= reject "),
  }));
  check("dmarc.evaluate: whitespace-padded p= reject → NOT deliver",
        rv.recommendedAction !== "deliver");
  check("dmarc.evaluate: whitespace-padded p= reject → fail + reject",
        rv.result === "fail" && rv.recommendedAction === "reject");
}

async function testBadSpTagFailsClosed() {
  // sp= feeds policy.p on the organizational-domain path; an invalid sp=
  // value must fail closed there too (validated like p=).
  var policy;
  var threw = false;
  try {
    policy = b.mail.dmarc.parseRecord("v=DMARC1; p=reject; sp=quarntine");
  } catch (e) {
    threw = true;
    check("dmarc.parseRecord: bad sp= throws dmarcbis-bad-tag",
          e && e.code === "mail-auth/dmarcbis-bad-tag");
  }
  check("dmarc.parseRecord: bad sp= rejected", threw === true && !policy);
}

async function testMissingPolicyParseThrows() {
  // parseRecord must reject a record missing the required p= outright.
  var threw = false;
  try {
    b.mail.dmarc.parseRecord("v=DMARC1; adkim=s");
  } catch (e) {
    threw = true;
    check("dmarc.parseRecord: missing p= throws dmarc-missing-policy",
          e && e.code === "mail-auth/dmarc-missing-policy");
  }
  check("dmarc.parseRecord: missing p= rejected", threw === true);
}

async function testValidRejectStillFailsClosed() {
  // Control: a well-formed p=reject for the same spoofed/failing message
  // still reaches the reject disposition (the fix doesn't over-broaden).
  var rv = await b.mail.dmarc.evaluate(Object.assign({}, SPOOF, {
    dnsLookup: dnsReturning("v=DMARC1; p=reject"),
  }));
  check("dmarc.evaluate: valid p=reject + spoof → fail + reject",
        rv.result === "fail" && rv.recommendedAction === "reject");
}

async function testValidNoneDelivers() {
  // Control: p=none is monitor-only → deliver is the correct disposition.
  var rv = await b.mail.dmarc.evaluate(Object.assign({}, SPOOF, {
    dnsLookup: dnsReturning("v=DMARC1; p=none"),
  }));
  check("dmarc.evaluate: valid p=none + spoof → fail + deliver (monitor)",
        rv.result === "fail" && rv.recommendedAction === "deliver");
}

async function run() {
  await testNoPolicyTagFailsClosed();
  await testTypoPolicyTagFailsClosed();
  await testWhitespacePaddedPolicyTag();
  await testBadSpTagFailsClosed();
  await testMissingPolicyParseThrows();
  await testValidRejectStillFailsClosed();
  await testValidNoneDelivers();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

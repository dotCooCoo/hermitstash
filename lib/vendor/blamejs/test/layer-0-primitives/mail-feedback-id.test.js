// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.feedbackId — Gmail FBL Feedback-ID header builder.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testHappyPath() {
  var id = b.mail.feedbackId({
    campaignId: "wk26-promo",
    customerId: "acme",
    mailType:   "marketing",
    senderId:   "mail-pool-1",
  });
  check("feedbackId: 4-tuple joined by ':'",
        id === "wk26-promo:acme:marketing:mail-pool-1");
}

function testRefusesBadShape() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("no opts",        function () { b.mail.feedbackId(); }, "mail/bad-feedback-id-opts");
  expectCode("missing campaignId",
             function () { b.mail.feedbackId({ customerId: "a", mailType: "b", senderId: "c" }); },
             "mail/bad-feedback-id-field");
  expectCode("empty customerId",
             function () { b.mail.feedbackId({ campaignId: "a", customerId: "", mailType: "b", senderId: "c" }); },
             "mail/bad-feedback-id-field");
  expectCode("colon in mailType",
             function () { b.mail.feedbackId({ campaignId: "a", customerId: "b", mailType: "m:t", senderId: "c" }); },
             "mail/bad-feedback-id-field");
  expectCode("control-char in senderId",
             function () { b.mail.feedbackId({ campaignId: "a", customerId: "b", mailType: "c", senderId: "x\r\ny" }); },
             "mail/bad-feedback-id-field");
  var bigField = new Array(70).join("x");
  expectCode("field > 64 chars",
             function () { b.mail.feedbackId({ campaignId: bigField, customerId: "b", mailType: "c", senderId: "d" }); },
             "mail/bad-feedback-id-field");
}

async function run() {
  testHappyPath();
  testRefusesBadShape();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

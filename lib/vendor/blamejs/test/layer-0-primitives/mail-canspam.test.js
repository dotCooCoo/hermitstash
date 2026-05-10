"use strict";
/**
 * b.mail commercial:true posture — CAN-SPAM Act §7704(a)(5) physical
 * postal address enforcement + §7704(a)(3)/(4) unsubscribe gating.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testCreateRefusesWithoutAddress() {
  var threw = false;
  try { b.mail.create({ commercial: true, audit: false }); }
  catch (e) { threw = e.code === "mail/missing-postal-address"; }
  check("commercial:true without postalAddress -> create refuses",
        threw === true);
}

function testCreateRefusesIncompleteAddressShape() {
  var threw = false;
  try {
    b.mail.create({
      commercial:    true,
      audit:         false,
      postalAddress: { street: "123 Main", city: "X", region: "Y", country: "US" }, // missing postalCode
    });
  } catch (e) { threw = e.code === "mail/missing-postal-address"; }
  check("commercial:true with shape-incomplete address -> refuses",
        threw === true);
}

function testCreateAcceptsValidAddress() {
  var mailer = b.mail.create({
    transport:     function () { return Promise.resolve({ ok: true }); },
    commercial:    true,
    audit:         false,
    defaults:      { from: "shop@example.com" },
    postalAddress: {
      street:     "123 Main St",
      city:       "Springfield",
      region:     "IL",
      postalCode: "62701",
      country:    "US",
    },
  });
  check("commercial:true with full postalAddress -> create succeeds",
        typeof mailer.send === "function");
}

async function testSendRefusesWithoutUnsubscribe() {
  var mailer = b.mail.create({
    transport:     function () { return Promise.resolve({ ok: true }); },
    commercial:    true,
    audit:         false,
    defaults:      { from: "shop@example.com" },
    postalAddress: {
      street: "1 St", city: "X", region: "Y", postalCode: "12345", country: "US",
    },
  });
  var refused = false;
  try {
    await mailer.send({ to: "u@example.com", subject: "promo", text: "buy now" });
  } catch (e) { refused = e.code === "mail/canspam-no-unsubscribe"; }
  check("commercial:true send w/o unsubscribe -> refused (CAN-SPAM §7704(a)(3))",
        refused === true);
}

async function testSendAppendsAddressFooter() {
  var captured = [];
  var mailer = b.mail.create({
    transport:     function (msg) { captured.push(msg); return Promise.resolve({ ok: true }); },
    commercial:    true,
    audit:         false,
    defaults:      { from: "shop@example.com" },
    postalAddress: {
      street:     "123 Main St",
      city:       "Springfield",
      region:     "IL",
      postalCode: "62701",
      country:    "US",
    },
  });
  await mailer.send({
    to:          "u@example.com",
    subject:     "promo",
    text:        "Hello",
    html:        "<p>Hello</p>",
    unsubscribe: { url: "https://example.com/unsub" },
  });
  var sent = captured[0];
  check("text body has postal-address footer (street)",
        sent.text.indexOf("123 Main St") !== -1);
  check("text body has country line",
        sent.text.indexOf("US") !== -1);
  check("html body has postal-address footer",
        sent.html.indexOf("123 Main St") !== -1);
  check("html body has separator <hr>",
        sent.html.indexOf("<hr>") !== -1);
}

async function testNonCommercialPathUnchanged() {
  var captured = [];
  var mailer = b.mail.create({
    transport: function (msg) { captured.push(msg); return Promise.resolve({ ok: true }); },
    audit:     false,
    defaults:  { from: "from@example.com" },
  });
  await mailer.send({ to: "u@example.com", subject: "hi", text: "hello" });
  var sent = captured[0];
  check("non-commercial send -> no address-footer mutation",
        sent.text === "hello");
}

async function run() {
  testCreateRefusesWithoutAddress();
  testCreateRefusesIncompleteAddressShape();
  testCreateAcceptsValidAddress();
  await testSendRefusesWithoutUnsubscribe();
  await testSendAppendsAddressFooter();
  await testNonCommercialPathUnchanged();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

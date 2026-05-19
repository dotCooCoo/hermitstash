"use strict";
// b.standardWebhooks — standardwebhooks.com consortium spec sign + verify.

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var nodeCrypto = require("node:crypto");

function testSignShape() {
  var s = b.standardWebhooks.sign({
    body:   "hello",
    secret: nodeCrypto.randomBytes(32),                                                            // allow:raw-byte-literal — 32-byte secret floor
  });
  check("sign returns headers",                  s.headers && typeof s.headers === "object");
  check("sign emits webhook-id",                 typeof s.headers["webhook-id"] === "string");
  check("sign emits webhook-timestamp",          /^\d+$/.test(s.headers["webhook-timestamp"]));
  check("sign emits v1,-prefixed signature",     s.headers["webhook-signature"].indexOf("v1,") === 0);
}

function testRoundtrip() {
  var secret = nodeCrypto.randomBytes(32);                                                         // allow:raw-byte-literal — 32-byte secret floor
  var s = b.standardWebhooks.sign({ body: "payload", secret: secret });
  var v = b.standardWebhooks.verify({
    headers: s.headers, body: s.body, secret: secret,
  });
  check("verify accepts roundtripped delivery", v.valid === true);
}

function testTamperedRefused() {
  var secret = nodeCrypto.randomBytes(32);                                                         // allow:raw-byte-literal — 32-byte secret floor
  var s = b.standardWebhooks.sign({ body: "payload", secret: secret });
  var threw = null;
  try {
    b.standardWebhooks.verify({
      headers: s.headers, body: "tampered", secret: secret,
    });
  } catch (e) { threw = e.code; }
  check("verify refuses tampered body", threw === "standard-webhooks/bad-signature");
}

function testShortSecretRefused() {
  var threw = null;
  try { b.standardWebhooks.sign({ body: "x", secret: Buffer.from("short") }); }
  catch (e) { threw = e.code; }
  check("sign refuses < 32-byte secret", threw === "standard-webhooks/bad-secret");
}

function testErrorClass() {
  check("StandardWebhooksError exported",
    typeof b.standardWebhooks.StandardWebhooksError === "function");
  var e = new b.standardWebhooks.StandardWebhooksError("standard-webhooks/test", "synthetic");
  check("StandardWebhooksError carries code", e.code === "standard-webhooks/test");
}

function run() {
  testSignShape();
  testRoundtrip();
  testTamperedRefused();
  testShortSecretRefused();
  testErrorClass();
}

if (require.main === module) {
  try { run(); }
  catch (e) { console.error(e); process.exit(1); }
}
module.exports = { run: run };

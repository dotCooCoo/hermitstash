"use strict";
/**
 * b.webhook — outbound signing + inbound verification.
 *
 * Run standalone: `node test/layer-0-primitives/webhook.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var http = require("http");
var helpers = require("../helpers");
var b         = helpers.b;
var check     = helpers.check;
var C         = b.constants;
var _bodyRes  = helpers._bodyRes;

// ---- Surface ----

function testWebhookSurface() {
  check("b.webhook namespace present",         typeof b.webhook === "object");
  check("b.webhook.signer is a function",      typeof b.webhook.signer === "function");
  check("b.webhook.verifier is a function",    typeof b.webhook.verifier === "function");
  check("b.webhook.ALGOS frozen",              Object.isFrozen(b.webhook.ALGOS));
  check("ALGOS.HMAC_SHA3_512",                 b.webhook.ALGOS.HMAC_SHA3_512 === "hmac-sha3-512");
  check("ALGOS.PQC_PEM",                       b.webhook.ALGOS.PQC_PEM === "pqc-pem");
  check("HEADER.SIGNATURE",                    b.webhook.HEADER.SIGNATURE === "Webhook-Signature");
  check("DEFAULTS frozen",                     Object.isFrozen(b.webhook.DEFAULTS));
  check("DEFAULTS.toleranceMs",                b.webhook.DEFAULTS.toleranceMs === C.TIME.minutes(5));
  check("DEFAULTS.clockSkewMs",                b.webhook.DEFAULTS.clockSkewMs === C.TIME.minutes(1));
  check("WebhookError class",                  typeof b.webhook.WebhookError === "function");
}

// ---- HMAC roundtrip ----

async function testHmacRoundtrip() {
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "secret" } });
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "secret" } });
  var signed = s.sign("hello world");
  check("sign returns headers",       typeof signed.headers === "object");
  check("sign returns timestamp",     typeof signed.timestamp === "number");
  check("sign returns id",            typeof signed.id === "string" && signed.id.length > 0);
  check("sign returns kid",           signed.kid === "v1");
  check("sign returns signature",     typeof signed.signature === "string");
  check("Webhook-Signature header set", typeof signed.headers["Webhook-Signature"] === "string");

  var info = await v.verify({ body: "hello world", headers: signed.headers });
  check("verify returns algo",        info.algo === "hmac-sha3-512");
  check("verify returns kid",         info.kid === "v1");
  check("verify returns timestamp",   info.timestamp === signed.timestamp);
  check("verify returns id",          info.id === signed.id);
}

async function testHmacBufferBody() {
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "secret" } });
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "secret" } });
  var body = Buffer.from([1, 2, 3, 4, 0, 255]);
  var signed = s.sign(body);
  var info = await v.verify({ body: body, headers: signed.headers });
  check("HMAC roundtrip with Buffer body", info.kid === "v1");
}

async function testHmacTampered() {
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "secret" } });
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "secret" } });
  var signed = s.sign("hello world");
  var threw = null;
  try { await v.verify({ body: "hello WORLD", headers: signed.headers }); }
  catch (e) { threw = e; }
  check("tampered body → BAD_SIGNATURE", threw && threw.code === "BAD_SIGNATURE");
}

async function testHmacTamperedHeader() {
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "secret" } });
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "secret" } });
  var signed = s.sign("hello world");
  // Flip the last hex char of the signature
  var hdr = signed.headers["Webhook-Signature"];
  var flipped = hdr.slice(0, -1) + (hdr.slice(-1) === "0" ? "1" : "0");
  var threw = null;
  try { await v.verify({ body: "hello world", headers: { "Webhook-Signature": flipped } }); }
  catch (e) { threw = e; }
  check("tampered signature → BAD_SIGNATURE", threw && threw.code === "BAD_SIGNATURE");
}

// ---- Multi-key rotation ----

async function testHmacRotation() {
  var oldSigner = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "old-secret" } });
  var newSigner = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v2: "new-secret" } });
  var verifier = b.webhook.verifier({
    algo: "hmac-sha3-512",
    keys: { v1: "old-secret", v2: "new-secret" },
  });

  var oldSigned = oldSigner.sign("body");
  var newSigned = newSigner.sign("body");

  var oldInfo = await verifier.verify({ body: "body", headers: oldSigned.headers });
  check("rotation: old key still verifies",  oldInfo.kid === "v1");

  var newInfo = await verifier.verify({ body: "body", headers: newSigned.headers });
  check("rotation: new key verifies",        newInfo.kid === "v2");
}

async function testHmacUnknownKid() {
  var signer = b.webhook.signer({ algo: "hmac-sha3-512", keys: { vForeign: "x" } });
  var verifier = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { vKnown: "y" } });
  var signed = signer.sign("body");
  var threw = null;
  try { await verifier.verify({ body: "body", headers: signed.headers }); }
  catch (e) { threw = e; }
  check("unknown kid → UNKNOWN_KID",
        threw && threw.code === "UNKNOWN_KID");
}

// ---- Timestamp window ----

async function testTimestampExpired() {
  var clk = b.testing.fakeClock(2_000_000_000_000);
  var s = b.webhook.signer({
    algo: "hmac-sha3-512",
    keys: { v1: "s" },
    now: clk.now,
  });
  var future = b.testing.fakeClock(clk.ms + C.TIME.minutes(5));
  var v = b.webhook.verifier({
    algo: "hmac-sha3-512",
    keys: { v1: "s" },
    toleranceMs: C.TIME.minutes(1),
    now: future.now,
  });
  var signed = s.sign("body");
  var threw = null;
  try { await v.verify({ body: "body", headers: signed.headers }); }
  catch (e) { threw = e; }
  check("expired timestamp → EXPIRED", threw && threw.code === "EXPIRED");
}

async function testTimestampFuture() {
  var clk = b.testing.fakeClock(2_000_000_000_000);
  var signerClk = b.testing.fakeClock(clk.ms + C.TIME.minutes(10));
  var s = b.webhook.signer({
    algo: "hmac-sha3-512",
    keys: { v1: "s" },
    now: signerClk.now,
  });
  var v = b.webhook.verifier({
    algo: "hmac-sha3-512",
    keys: { v1: "s" },
    clockSkewMs: C.TIME.minutes(1),
    now: clk.now,
  });
  var signed = s.sign("body");
  var threw = null;
  try { await v.verify({ body: "body", headers: signed.headers }); }
  catch (e) { threw = e; }
  check("future timestamp → FUTURE", threw && threw.code === "FUTURE");
}

// ---- Header format ----

async function testMissingHeader() {
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var threw = null;
  try { await v.verify({ body: "body", headers: {} }); }
  catch (e) { threw = e; }
  check("no signature header → MISSING_HEADER",
        threw && threw.code === "MISSING_HEADER");
}

async function testBadHeaderFormat() {
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var threw = null;
  try {
    await v.verify({ body: "body", headers: { "Webhook-Signature": "garbage-no-equals" } });
  } catch (e) { threw = e; }
  check("garbage header → BAD_HEADER_FORMAT",
        threw && threw.code === "BAD_HEADER_FORMAT");
}

async function testMissingFields() {
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" } });

  var threw = null;
  try {
    await v.verify({ body: "body",
      headers: { "Webhook-Signature": "id=abc,v1=ff" } });
  } catch (e) { threw = e; }
  check("no t= → MISSING_TIMESTAMP", threw && threw.code === "MISSING_TIMESTAMP");

  threw = null;
  try {
    await v.verify({ body: "body",
      headers: { "Webhook-Signature": "t=abc,id=x,v1=ff" } });
  } catch (e) { threw = e; }
  check("non-numeric t → BAD_TIMESTAMP", threw && threw.code === "BAD_TIMESTAMP");

  threw = null;
  try {
    await v.verify({ body: "body",
      headers: { "Webhook-Signature": "t=" + Math.floor(Date.now()/1000) + ",v1=ff" } });
  } catch (e) { threw = e; }
  check("no id= → MISSING_ID", threw && threw.code === "MISSING_ID");

  threw = null;
  try {
    await v.verify({ body: "body",
      headers: { "Webhook-Signature": "t=" + Math.floor(Date.now()/1000) + ",id=abc" } });
  } catch (e) { threw = e; }
  check("no v<kid>= → MISSING_SIGNATURE", threw && threw.code === "MISSING_SIGNATURE");
}

async function testHeaderCaseInsensitive() {
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var signed = s.sign("body");
  // Node's req.headers lowercases keys; verifier must accept that.
  var lowercased = {};
  Object.keys(signed.headers).forEach(function (k) { lowercased[k.toLowerCase()] = signed.headers[k]; });
  var info = await v.verify({ body: "body", headers: lowercased });
  check("verify accepts lowercased header keys", info.kid === "v1");
}

// ---- Nonce store / replay ----

async function testNonceStoreReplay() {
  var seen = new Map();
  var ns = {
    checkAndInsert: function (nonce, expireAt) {
      if (seen.has(nonce)) return false;
      seen.set(nonce, expireAt);
      return true;
    },
  };
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" }, nonceStore: ns });

  var signed = s.sign("body");
  var info = await v.verify({ body: "body", headers: signed.headers });
  check("first delivery accepted", info.kid === "v1");

  var threw = null;
  try { await v.verify({ body: "body", headers: signed.headers }); }
  catch (e) { threw = e; }
  check("replay → REPLAY", threw && threw.code === "REPLAY");
}

async function testNonceStoreErrorPropagates() {
  var ns = { checkAndInsert: function () { throw new Error("redis down"); } };
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" }, nonceStore: ns });
  var signed = s.sign("body");
  var threw = null;
  try { await v.verify({ body: "body", headers: signed.headers }); }
  catch (e) { threw = e; }
  check("nonce store error propagates (fail-closed)",
        threw && /redis down/.test(threw.message));
}

async function testStripeVerifyReplayAtomic() {
  // #328: b.webhook.verify (Stripe HMAC-SHA-256) speaks the SAME atomic
  // checkAndInsert nonce contract as b.webhook.verifier / b.nonceStore — so the
  // framework's own replay store drops in, and concurrent redeliveries can't
  // race a non-atomic check-then-set.
  var secret = "whsec_test_328";
  var body = '{"id":"evt_328"}';
  var header = b.webhook.sign({ alg: "hmac-sha256-stripe", secret: secret, body: body });
  var seen = new Map();
  var ns = { checkAndInsert: function (nonce, expireAt) { if (seen.has(nonce)) return false; seen.set(nonce, expireAt); return true; } };
  var base = { alg: "hmac-sha256-stripe", secret: secret, body: body, header: header, nonceStore: ns };

  var first = await b.webhook.verify(base);
  check("Stripe verify: first delivery accepted", first && first.ok === true);

  var threw = null;
  try { await b.webhook.verify(base); } catch (e) { threw = e; }
  check("Stripe verify: replay → webhook/replay", threw && threw.code === "webhook/replay");

  // The framework's own b.nonceStore plugs in directly, no adapter.
  var fwStore = b.nonceStore.create({ backend: "memory" });
  var body2 = '{"id":"evt_328b"}';
  var header2 = b.webhook.sign({ alg: "hmac-sha256-stripe", secret: secret, body: body2 });
  var okFw = await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, body: body2, header: header2, nonceStore: fwStore });
  check("Stripe verify: b.nonceStore drops in (no adapter)", okFw && okFw.ok === true);

  // A legacy { has, set } store (no checkAndInsert) is refused at construction.
  var threw2 = null;
  try {
    await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, body: body, header: header,
      nonceStore: { has: function () {}, set: function () {} } });
  } catch (e) { threw2 = e; }
  check("Stripe verify: non-checkAndInsert store → bad-nonce-store",
        threw2 && threw2.code === "webhook/bad-nonce-store");
}

async function testSignerSendRefusesSsrf() {
  // signer.send refuses a private / cloud-metadata destination (SSRF) up front,
  // before the retry loop and any network — webhook-layer gate + the transport's.
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "secret" } });
  var threw = null;
  try { await s.send({ url: "https://169.254.169.254/hook", body: "{}", kid: "v1" }); }
  catch (e) { threw = e; }
  check("signer.send refuses cloud-metadata IP (SSRF)",
        threw && (threw.code === "SSRF_REFUSED" ||
                  /ssrf|metadata|blocked|internal|private/i.test((threw.code || "") + " " + (threw.message || ""))));
}

// ---- Middleware ----

async function testMiddlewareSuccess() {
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var mw = v.middleware();
  var body = "hello";
  var signed = s.sign(body);

  var req = {
    bodyRaw: Buffer.from(body, "utf8"),
    headers: signed.headers,
  };
  var res = _bodyRes();
  var nextCalled = false;
  await new Promise(function (resolve) {
    mw(req, res, function () { nextCalled = true; resolve(); });
    helpers.passiveObserve(100, "webhook valid-sig: middleware short-circuit window").then(resolve);
  });
  check("middleware: next() called on valid sig", nextCalled === true);
  check("middleware: req.webhook populated",
        req.webhook && req.webhook.kid === "v1");
}

async function testMiddlewareMissingRawBody() {
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var mw = v.middleware();
  var req = { headers: { "Webhook-Signature": "t=1,id=2,v1=ff" } };   // no bodyRaw, no body
  var res = _bodyRes();
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  // synchronous error path
  check("middleware: 401 without raw body",     res._endedStatus === 401);
  check("middleware: next() not called",        nextCalled === false);
  check("middleware: error code in body",
        /MISSING_RAW_BODY/.test(res._captured || ""));
}

async function testMiddlewareBadSignature() {
  var v = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  var mw = v.middleware();
  var ts = Math.floor(Date.now() / 1000);
  var req = {
    bodyRaw: Buffer.from("body", "utf8"),
    headers: { "Webhook-Signature": "t=" + ts + ",id=x,v1=" + "00".repeat(64) },
  };
  var res = _bodyRes();
  var nextCalled = false;
  await new Promise(function (resolve) {
    mw(req, res, function () { nextCalled = true; resolve(); });
    helpers.passiveObserve(100, "webhook bad-sig: middleware short-circuit window").then(resolve);
  });
  check("middleware: 401 on bad sig",        res._endedStatus === 401);
  check("middleware: next() not called",     nextCalled === false);
  check("middleware: BAD_SIGNATURE in body",
        /BAD_SIGNATURE/.test(res._captured || ""));
}

// ---- PQC-PEM roundtrip ----

async function testPqcPemRoundtrip() {
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var s = b.webhook.signer({
    algo: "pqc-pem",
    keys: { v1: { privateKey: pair.privateKey, publicKey: pair.publicKey } },
  });
  var v = b.webhook.verifier({
    algo: "pqc-pem",
    keys: { v1: pair.publicKey },
  });
  var signed = s.sign("body");
  var info = await v.verify({ body: "body", headers: signed.headers });
  check("PQC-PEM: roundtrip verifies", info.kid === "v1");
}

async function testPqcPemTampered() {
  var pair = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var s = b.webhook.signer({
    algo: "pqc-pem",
    keys: { v1: { privateKey: pair.privateKey, publicKey: pair.publicKey } },
  });
  var v = b.webhook.verifier({ algo: "pqc-pem", keys: { v1: pair.publicKey } });
  var signed = s.sign("body");
  var threw = null;
  try { await v.verify({ body: "tampered", headers: signed.headers }); }
  catch (e) { threw = e; }
  check("PQC-PEM: tampered body → BAD_SIGNATURE",
        threw && threw.code === "BAD_SIGNATURE");
}

async function testPqcPemMultipleVerifierKeys() {
  var p1 = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var p2 = b.crypto.generateSigningKeyPair("ml-dsa-87");
  var s = b.webhook.signer({
    algo: "pqc-pem",
    keys: { v2: { privateKey: p2.privateKey, publicKey: p2.publicKey } },
  });
  var v = b.webhook.verifier({
    algo: "pqc-pem",
    keys: { v1: p1.publicKey, v2: p2.publicKey },
  });
  var signed = s.sign("body");
  var info = await v.verify({ body: "body", headers: signed.headers });
  check("PQC-PEM: rotation verifies via v2 key", info.kid === "v2");
}

// ---- send() integration via ephemeral local HTTP server ----

async function testSendEndToEnd() {
  var pair = "test-secret-2024";
  var verifier = b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: pair } });
  var receivedInfo = null;

  var server = http.createServer(function (req, res) {
    var chunks = [];
    req.on("data", function (c) { chunks.push(c); });
    req.on("end", function () {
      var raw = Buffer.concat(chunks);
      verifier.verify({ body: raw, headers: req.headers }).then(
        function (info) {
          receivedInfo = info;
          res.statusCode = 200;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ ok: true }));
        },
        function (err) {
          res.statusCode = 401;
          res.end(err.code);
        }
      );
    });
  });
  await new Promise(function (r) { server.listen(0, "127.0.0.1", r); });
  var port = server.address().port;
  var url = "http://127.0.0.1:" + port + "/webhook";

  var signer = b.webhook.signer({
    algo: "hmac-sha3-512",
    keys: { v1: pair },
    http: { allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL, allowInternal: true },
  });

  try {
    var res = await signer.send({ url: url, body: '{"event":"ping"}' });
    check("send: status 200", res.status === 200 || res.statusCode === 200);
    check("send: server verified the signature",
          receivedInfo && receivedInfo.kid === "v1");
  } finally {
    await new Promise(function (r) { server.close(r); });
  }
}

// ---- Input validation (rejects bad opts at call site) ----

function testRejectsBadOpts() {
  function expectThrow(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && threw.code === code);
  }

  expectThrow("signer: bad algo",
    function () { b.webhook.signer({ algo: "rsa-sha1", keys: { v1: "s" } }); },
    "BAD_OPT");
  expectThrow("signer: missing keys",
    function () { b.webhook.signer({ algo: "hmac-sha3-512" }); },
    "BAD_OPT");
  expectThrow("signer: empty keys",
    function () { b.webhook.signer({ algo: "hmac-sha3-512", keys: {} }); },
    "BAD_OPT");
  expectThrow("signer: bad kid (contains comma)",
    function () { b.webhook.signer({ algo: "hmac-sha3-512", keys: { "v,1": "s" } }); },
    "BAD_OPT");
  expectThrow("signer: reserved kid 't'",
    function () { b.webhook.signer({ algo: "hmac-sha3-512", keys: { t: "s" } }); },
    "BAD_OPT");
  expectThrow("signer: reserved kid 'id'",
    function () { b.webhook.signer({ algo: "hmac-sha3-512", keys: { id: "s" } }); },
    "BAD_OPT");
  expectThrow("signer: defaultKid not in keys",
    function () { b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "s" }, defaultKid: "v9" }); },
    "BAD_OPT");
  expectThrow("signer: multiple keys without defaultKid",
    function () { b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "s", v2: "t" } }); },
    "BAD_OPT");

  expectThrow("verifier: bad toleranceMs",
    function () { b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" }, toleranceMs: -1 }); },
    "BAD_OPT");
  expectThrow("verifier: nonceStore without checkAndInsert",
    function () { b.webhook.verifier({ algo: "hmac-sha3-512", keys: { v1: "s" }, nonceStore: {} }); },
    "BAD_OPT");

  // Body validation
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "s" } });
  expectThrow("sign(undefined) → BAD_BODY",
    function () { s.sign(undefined); }, "BAD_BODY");
  expectThrow("sign(42) → BAD_BODY",
    function () { s.sign(42); }, "BAD_BODY");
  expectThrow("sign({}) → BAD_BODY",
    function () { s.sign({}); }, "BAD_BODY");
}

async function testSendBadUrl() {
  var s = b.webhook.signer({ algo: "hmac-sha3-512", keys: { v1: "x" } });
  // safeUrl rejects non-HTTPS by default
  var threw = null;
  try { await s.send({ url: "http://example.com", body: "x" }); }
  catch (e) { threw = e; }
  check("send: rejects http:// when ALLOW_HTTP_TLS",
        threw && (threw.code === "BAD_URL" || /protocol/i.test(threw.message)));
}

// ---- Run ----

// ---- Stripe HMAC-SHA-256 verifier (v0.11.25) ----

function _stripeFixture(body, ts, secret) {
  // Compute the canonical Stripe signature for a given (body, ts,
  // secret) so the tests can assert verify-success against a header
  // we built ourselves (using sign() OR direct HMAC-SHA-256 via
  // node:crypto for cross-verification).
  var crypto = require("node:crypto");
  var hex = crypto.createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(ts + "." + body, "utf8").digest("hex");
  return { header: "t=" + ts + ",v1=" + hex, hex: hex };
}

async function testStripeHappyPath() {
  var body   = '{"id":"evt_1","type":"checkout.session.completed"}';
  var ts     = Math.floor(Date.now() / 1000);
  var secret = "whsec_test_abcdefghijklmnopqrstuvwxyz0123456";
  var fx     = _stripeFixture(body, ts, secret);
  var r = await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body });
  check("stripe happy path → ok=true",       r.ok === true);
  check("stripe scheme v1",                   r.scheme === "v1");
  check("stripe timestamp echoed",            r.timestamp === ts);
}

async function testStripeWrongSecret() {
  var body = '{"x":1}';
  var ts   = Math.floor(Date.now() / 1000);
  var fx   = _stripeFixture(body, ts, "whsec_correct_secret");
  var thrown = false;
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: "whsec_wrong_secret", header: fx.header, body: body }); }
  catch (e) { thrown = true; check("wrong secret → bad-signature code", e.code === "webhook/bad-signature"); }
  check("stripe wrong secret → throws",       thrown);
}

async function testStripeTamperedBody() {
  var body = '{"x":1}';
  var ts   = Math.floor(Date.now() / 1000);
  var fx   = _stripeFixture(body, ts, "whsec_x");
  var thrown = false;
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: "whsec_x", header: fx.header, body: '{"x":2}' }); }
  catch (_e) { thrown = true; }
  check("stripe tampered body → throws",      thrown);
}

async function testStripeStaleTimestamp() {
  var body = '{"x":1}';
  // 10 minutes ago — outside default 5-minute window.
  var ts   = Math.floor(Date.now() / 1000) - 600;
  var fx   = _stripeFixture(body, ts, "whsec_x");
  var thrown = false;
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: "whsec_x", header: fx.header, body: body }); }
  catch (e) { thrown = true; check("stale → stale-timestamp code", e.code === "webhook/stale-timestamp"); }
  check("stripe stale → throws",              thrown);
}

async function testStripeMultipleV1() {
  // Stripe sends multiple v1=<hex> entries during rotation. The verifier
  // accepts the request if ANY one matches.
  var body = '{"x":1}';
  var ts   = Math.floor(Date.now() / 1000);
  var goodFx = _stripeFixture(body, ts, "whsec_real");
  var header = "t=" + ts + ",v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,v1=" + goodFx.hex;
  var r = await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: "whsec_real", header: header, body: body });
  check("stripe v1-rotation accepts good one", r.ok === true);
}

async function testStripeMissingFields() {
  var body = '{}';
  var ts   = Math.floor(Date.now() / 1000);
  var fx   = _stripeFixture(body, ts, "whsec_x");
  var thrownT = false, thrownV1 = false;
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: "whsec_x", header: "v1=" + fx.hex, body: body }); }
  catch (_e) { thrownT = true; }
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: "whsec_x", header: "t=" + ts, body: body }); }
  catch (_e) { thrownV1 = true; }
  check("missing t → throws",                 thrownT);
  check("missing v1 → throws",                thrownV1);
}

async function testStripePrefixPreserved() {
  // The whsec_ prefix is part of the HMAC key bytes per Stripe's spec.
  // Stripping it produces a different MAC; the verifier MUST NOT strip.
  var body = '{"x":1}';
  var ts   = Math.floor(Date.now() / 1000);
  var withPrefix    = _stripeFixture(body, ts, "whsec_test123");
  var withoutPrefix = _stripeFixture(body, ts, "test123");
  check("whsec prefix changes MAC",            withPrefix.hex !== withoutPrefix.hex);
  var r = await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: "whsec_test123", header: withPrefix.header, body: body });
  check("verify accepts whsec_-prefixed key",  r.ok === true);
}

async function testStripeRoundTrip() {
  var body = '{"id":"evt_42"}';
  var secret = "whsec_round_trip_secret_value_xyz";
  var header = b.webhook.sign({ alg: "hmac-sha256-stripe", secret: secret, body: body });
  check("sign returns Stripe-Signature shape", /^t=\d+,v1=[0-9a-f]{64}$/.test(header));
  var r = await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: header, body: body });
  check("round-trip verify ok",                r.ok === true);
}

async function testStripeOverlongSignature() {
  var body = '{}';
  var ts   = Math.floor(Date.now() / 1000);
  var longHex = "a".repeat(300);
  var thrown = false;
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: "whsec_x", header: "t=" + ts + ",v1=" + longHex, body: body }); }
  catch (_e) { thrown = true; }
  check("overlong v1 hex → throws",            thrown);
}

async function testStripeBadAlg() {
  var thrown = false;
  try { await b.webhook.verify({ alg: "wrong-alg", secret: "x", header: "t=1,v1=ab", body: "{}" }); }
  catch (e) { thrown = true; check("bad alg → bad-alg code", e.code === "webhook/bad-alg"); }
  check("bad alg → throws",                    thrown);
}

// b.webhook.verify speaks the SAME atomic { checkAndInsert(nonce, expireAt)
// → bool } replay contract as b.webhook.verifier and b.nonceStore — one
// interface across the whole b.webhook surface, no racy check-then-set.
async function testStripeNonceReplay() {
  var body = '{"x":1}';
  var ts   = Math.floor(Date.now() / 1000);
  var secret = "whsec_replay_test";
  var fx = _stripeFixture(body, ts, secret);
  var seen = Object.create(null);
  // Atomic check-and-insert: returns true only the first time a key is seen.
  var store = { checkAndInsert: function (k) {
    if (seen[k]) return false;
    seen[k] = true;
    return true;
  } };
  var r1 = await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body, nonceStore: store });
  check("first call ok",                       r1.ok === true);
  var thrown = false;
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body, nonceStore: store }); }
  catch (e) { thrown = true; check("replay → replay code", e.code === "webhook/replay"); }
  check("replay throws",                       thrown);
}

async function testStripeAsyncNonceStore() {
  // checkAndInsert MAY return a Promise (Redis / KV / cluster SQL backend);
  // verify MUST await it before deciding fresh-vs-replay.
  var body = '{"x":1}';
  var ts   = Math.floor(Date.now() / 1000);
  var secret = "whsec_async_test";
  var fx = _stripeFixture(body, ts, secret);
  var seen = Object.create(null);
  var asyncStore = { checkAndInsert: function (k) {
    return new Promise(function (resolve) {
      var fresh = !seen[k];
      seen[k] = true;
      resolve(fresh);
    });
  } };
  var r1 = await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body, nonceStore: asyncStore });
  check("async store first call ok",           r1.ok === true);
  var thrown = false;
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body, nonceStore: asyncStore }); }
  catch (e) { thrown = true; check("async store replay caught", e.code === "webhook/replay"); }
  check("async store replay throws",           thrown);
}

// Headline: the framework's OWN replay store (b.nonceStore.create) drops
// straight into the framework's OWN Stripe verifier — no adapter object.
async function testStripeNonceStoreFromPrimitive() {
  var body = '{"x":1}';
  var ts   = Math.floor(Date.now() / 1000);
  var secret = "whsec_primitive_store";
  var fx = _stripeFixture(body, ts, secret);
  var ns = b.nonceStore.create({ backend: "memory" });
  var r1 = await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body, nonceStore: ns });
  check("b.nonceStore plugs into verify (1st ok)", r1.ok === true);
  var thrown = false;
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body, nonceStore: ns }); }
  catch (e) { thrown = true; check("b.nonceStore replay → replay code", e.code === "webhook/replay"); }
  check("b.nonceStore dedupes replay",         thrown);
  if (ns.close) await ns.close();
}

// A store that exposes the legacy { has, set } shape but no checkAndInsert is
// refused config-time — the racy check-then-set contract is gone.
async function testStripeNonceStoreBadShapeRefused() {
  var body = '{"x":1}';
  var ts   = Math.floor(Date.now() / 1000);
  var secret = "whsec_bad_shape";
  var fx = _stripeFixture(body, ts, secret);
  var legacyStore = { has: function () { return false; }, set: function () {} };
  var thrown = false;
  try { await b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body, nonceStore: legacyStore }); }
  catch (e) { thrown = true; check("bad nonce-store → bad-nonce-store code", e.code === "webhook/bad-nonce-store"); }
  check("nonceStore without checkAndInsert refused", thrown);
}

// checkAndInsert is the atomic gate: of two concurrent verifies of the same
// signature, exactly one is accepted (the other is a replay) — no TOCTOU
// window where both observe "unseen".
async function testStripeNonceStoreConcurrentAtomic() {
  var body = '{"x":1}';
  var ts   = Math.floor(Date.now() / 1000);
  var secret = "whsec_concurrent";
  var fx = _stripeFixture(body, ts, secret);
  var ns = b.nonceStore.create({ backend: "memory" });
  var calls = [
    b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body, nonceStore: ns }),
    b.webhook.verify({ alg: "hmac-sha256-stripe", secret: secret, header: fx.header, body: body, nonceStore: ns }),
  ];
  var settled = await Promise.allSettled(calls);
  var ok = settled.filter(function (s) { return s.status === "fulfilled"; }).length;
  var replay = settled.filter(function (s) {
    return s.status === "rejected" && s.reason && s.reason.code === "webhook/replay";
  }).length;
  check("concurrent: exactly one accepted",    ok === 1);
  check("concurrent: exactly one replay",      replay === 1);
  if (ns.close) await ns.close();
}

// The webhook module is the Worker/edge-safe import for inbound verification:
// require it directly (e.g. require("@blamejs/core/lib/webhook")) rather than
// the framework's aggregate entry, which eagerly initializes the Node
// networking stack. b.webhook.verify is HMAC + timing-safe compare only, so the
// module must NOT pull the outbound http-client (node:http / node:https /
// node:http2 chain) at load — directly, OR transitively through the
// webhook-dispatcher delivery store. This child process requires the module in
// isolation and verifies a Stripe signature; the edge guarantee holds iff no
// Node networking builtin appears in process.moduleLoadList on that path. RED on
// a top-level `require("./http-client")` in either module (node:http loads at
// module eval); GREEN once both lazyRequire it and only the delivery path
// resolves it. moduleLoadList records a loaded builtin as "NativeModule http",
// so the filter must match that form (not only "node:http").
function testVerifyLoadableWithoutHttpClient() {
  var cp = require("node:child_process");
  var nodePath = require("node:path");
  var repoRoot = nodePath.resolve(__dirname, "..", "..");
  var webhookPath = nodePath.join(repoRoot, "lib", "webhook.js");
  var script =
    "var crypto = require('node:crypto');" +
    "var webhook = require(" + JSON.stringify(webhookPath) + ");" +
    "var secret = 'whsec_edgeruntime';" +
    "var body = '{\"id\":\"evt_edge\"}';" +
    "var t = Math.floor(Date.now() / 1000);" +
    "var sig = crypto.createHmac('sha256', secret).update(t + '.' + body).digest('hex');" +
    "webhook.verify({ alg: 'hmac-sha256-stripe', secret: secret, header: 't=' + t + ',v1=' + sig, body: body })" +
    "  .then(function (r) {" +
    "    if (!r || r.ok !== true) { process.stderr.write('verify-not-ok'); process.exit(3); }" +
    // process.moduleLoadList records a loaded networking builtin as
    // "NativeModule http" (Node 20+) or "node:http" (older) — match both forms.
    "    var net = process.moduleLoadList.filter(function (m) { return /^(?:NativeModule |node:)(net|tls|http|https|http2)$/.test(m); });" +
    "    if (net.length) { process.stderr.write('net-loaded:' + net.join(',')); }" +
    "    process.exit(net.length ? 1 : 0);" +
    "  })" +
    "  .catch(function (e) { process.stderr.write(String(e && e.message)); process.exit(2); });";
  var code = 0;
  var stderr = "";
  try {
    cp.execFileSync(process.execPath, ["-e", script], { stdio: ["ignore", "ignore", "pipe"], timeout: 30000 });
  } catch (e) {
    code = (e && typeof e.status === "number") ? e.status : -1;
    stderr = (e && e.stderr) ? e.stderr.toString() : "";
  }
  check("webhook.verify composes with no node networking builtin loaded (edge-runtime safe) [exit=" +
        code + (stderr ? " stderr=" + stderr.slice(0, 120).replace(/\n/g, " ") : "") + "]",
        code === 0);
}

// signer.send dispatches through the shared httpClient keep-alive transport
// pool; a cached client socket finalizes its destroy on a later event-loop
// turn, past the forked worker's grace window. Reset the pool, then poll until
// every TCP handle has actually drained so none outlives run().
async function _drainTcpHandles() {
  b.httpClient._resetForTest();
  if (typeof process.getActiveResourcesInfo !== "function") return;
  await helpers.waitUntil(function () {
    return process.getActiveResourcesInfo().filter(function (t) {
      return t === "TCPSocketWrap" || t === "TCPServerWrap";
    }).length === 0;
  }, { timeoutMs: 5000, label: "webhook: TCP handle drain after _resetForTest" });
}

async function run() {
  try {
    await _runTests();
  } finally {
    await _drainTcpHandles();
  }
}

async function _runTests() {
  testWebhookSurface();
  await testHmacRoundtrip();
  await testHmacBufferBody();
  await testHmacTampered();
  await testHmacTamperedHeader();
  await testHmacRotation();
  await testHmacUnknownKid();
  await testTimestampExpired();
  await testTimestampFuture();
  await testMissingHeader();
  await testBadHeaderFormat();
  await testMissingFields();
  await testHeaderCaseInsensitive();
  await testNonceStoreReplay();
  await testNonceStoreErrorPropagates();
  await testStripeVerifyReplayAtomic();
  await testSignerSendRefusesSsrf();
  await testMiddlewareSuccess();
  await testMiddlewareMissingRawBody();
  await testMiddlewareBadSignature();
  await testPqcPemRoundtrip();
  await testPqcPemTampered();
  await testPqcPemMultipleVerifierKeys();
  await testSendEndToEnd();
  testRejectsBadOpts();
  await testSendBadUrl();
  // v0.11.25 — Stripe HMAC-SHA-256 inbound verifier.
  await testStripeHappyPath();
  await testStripeWrongSecret();
  await testStripeTamperedBody();
  await testStripeStaleTimestamp();
  await testStripeMultipleV1();
  await testStripeMissingFields();
  await testStripePrefixPreserved();
  await testStripeRoundTrip();
  await testStripeOverlongSignature();
  await testStripeBadAlg();
  await testStripeNonceReplay();
  await testStripeAsyncNonceStore();
  await testStripeNonceStoreFromPrimitive();
  await testStripeNonceStoreBadShapeRefused();
  await testStripeNonceStoreConcurrentAtomic();
  // #378 — verify path must stay free of the Node networking chain.
  testVerifyLoadableWithoutHttpClient();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}

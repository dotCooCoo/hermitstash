"use strict";
/**
 * Pre-auth parse/verify hardening — each test drives the shipped consumer
 * path with the adversarial input that triggers the failure.
 *
 *   - cbor: O(1) duplicate-key detection (was O(n²) — pre-auth DoS on every
 *     COSE/CWT/EAT/mdoc verify); duplicates still refused.
 *   - crypto.decrypt: a truncated envelope throws the documented envelope Error,
 *     not a raw RangeError.
 *   - mdoc.verifyIssuerSigned: issuer trust is enforced by default (the x5chain
 *     signer cert is attacker-controlled) — refuses without trustAnchorsPem
 *     unless allowUntrustedIssuer is set.
 *   - cose: RFC 9053 alg↔curve binding — refuses ES512 over a P-256 key.
 *   - jsonPath: a deeply-nested filter throws JsonPathError, not a raw
 *     stack-overflow RangeError.
 *   - bodyParser.raw(): the default match-all wildcard contentTypes accepts a
 *     real Content-Type (was 415 on every request).
 */

var nodeCrypto = require("node:crypto");
var EventEmitter = require("events").EventEmitter;
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var _bodyRes = helpers._bodyRes;

function _codeOf(fn) {
  try { fn(); return null; } catch (e) { return (e && e.code) || (e && e.message) || "threw"; }
}

async function _codeOfAsync(p) {
  try { await p; return null; } catch (e) { return (e && e.code) || (e && e.message) || "threw"; }
}

function testCborDuplicateKeyAndLinearSpeed() {
  // Duplicates still refused.
  var dup = Buffer.from([0xa2, 0x01, 0x01, 0x01, 0x02]);   // {1:1, 1:2}
  check("cbor.decode refuses a duplicate map key",
    _codeOf(function () { b.cbor.decode(dup); }) === "cbor/duplicate-key");

  // A large distinct-key map decodes in linear time. The old O(n²) per-key
  // Buffer.compare scan over a 20k-key map is ~4e8 comparisons (many seconds);
  // the Set-based guard is milliseconds.
  var m = new Map();
  for (var i = 0; i < 20000; i++) m.set(i, i);
  var encoded = b.cbor.encode(m);
  var t0 = Date.now();
  var decoded = b.cbor.decode(encoded, { maxBytes: 4 * 1024 * 1024 });
  var ms = Date.now() - t0;
  check("cbor.decode of a 20k distinct-key map is correct", decoded instanceof Map && decoded.size === 20000);
  check("cbor.decode of a 20k-key map is linear-fast (<3s), not O(n²)", ms < 3000);
}

function testCryptoDecryptTruncatedEnvelope() {
  // A truncated envelope must surface the documented "Invalid envelope" Error,
  // never a raw Node RangeError from an out-of-bounds readUInt16BE.
  [Buffer.from([0xe2, 1]), Buffer.from([0xe2, 1, 1, 1])].forEach(function (buf, idx) {
    var msg = null;
    try { b.crypto.decrypt(buf, "no-key"); } catch (e) { msg = e.message || ""; }
    check("crypto.decrypt truncated envelope #" + idx + " → documented envelope Error",
      msg !== null && msg.indexOf("Invalid envelope") === 0);
  });
}

async function testMdocRequiresTrustAnchorByDefault() {
  // Issuer authentication is fail-closed by default: without trustAnchorsPem
  // (and without the explicit opt-out) the call is refused BEFORE trusting the
  // attacker-supplied x5chain signer.
  var code = await _codeOfAsync(
    b.mdoc.verifyIssuerSigned(Buffer.from([0xa0]), { algorithms: ["ES256"] }));
  check("mdoc.verifyIssuerSigned refuses without a trust anchor",
    code === "mdoc/trust-anchors-required");

  // The explicit opt-out gets past the trust gate (it then fails later on the
  // garbage payload — a DIFFERENT, non-trust error), proving the gate is the
  // only thing the default adds.
  var code2 = await _codeOfAsync(
    b.mdoc.verifyIssuerSigned(Buffer.from([0xa0]), { algorithms: ["ES256"], allowUntrustedIssuer: true }));
  check("mdoc allowUntrustedIssuer opt-out bypasses the trust gate (fails later, not on trust)",
    code2 !== "mdoc/trust-anchors-required" && code2 !== null);
}

async function testCoseAlgCurveBinding() {
  var p256 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  // ES256 over a P-256 key is the correct binding — succeeds.
  var signedOk = null;
  try { await b.cose.sign(Buffer.from("hi"), { alg: "ES256", privateKey: p256.privateKey }); signedOk = true; }
  catch (_e) { signedOk = false; }
  check("cose.sign ES256 over a P-256 key succeeds (correct binding)", signedOk === true);

  // ES512 over a P-256 key violates RFC 9053 §2 — refused.
  var mismatch = null;
  try { await b.cose.sign(Buffer.from("hi"), { alg: "ES512", privateKey: p256.privateKey }); }
  catch (e) { mismatch = e && e.code; }
  check("cose.sign ES512 over a P-256 key is refused (alg/curve binding)",
    mismatch === "cose/alg-curve-mismatch");
}

function testJsonPathFilterDepthCap() {
  // A pathologically nested filter must throw a typed JsonPathError, never a
  // raw V8 RangeError ("Maximum call stack size exceeded").
  var deep = "$[?(" + "(".repeat(500) + "@.a==1" + ")".repeat(500) + ")]";
  var err = null;
  try { b.jsonPath.query({ a: 1 }, deep); } catch (e) { err = e; }
  check("jsonPath deeply-nested filter throws JsonPathError, not a raw RangeError",
    err !== null && err.name !== "RangeError" &&
    ((err.code || "").indexOf("json-path/") === 0));
}

function testBodyParserRawWildcardMatchesRealType() {
  // bodyParser.raw() defaults contentTypes to ["*/*"]; that wildcard must match
  // a real Content-Type (it never did → 415 on every request).
  var bp = b.middleware.bodyParser.raw();
  var req = new EventEmitter();
  req.method = "POST"; req.url = "/hooks";
  req.headers = { "content-type": "application/json", "content-length": "2" };
  req.socket = { remoteAddress: "127.0.0.1" };
  var res = _bodyRes();
  // The parser settles by calling next() or by ending the response. Wrap in
  // withTestTimeout so a parser that hangs becomes a hard "test timed out"
  // reject (1500ms budget) instead of stalling the suite — its guard timer
  // clears on settle, so no Timeout handle lingers past run().
  return helpers.withTestTimeout("parser-verify: bodyParser.raw() settles", function () {
    return new Promise(function (resolve) {
      var settled = false;
      bp(req, res, function () {
        if (settled) return; settled = true;
        check("bodyParser.raw() */* accepts application/json → next() runs", true);
        check("bodyParser.raw() exposes the raw body as a Buffer", Buffer.isBuffer(req.body));
        resolve();
      });
      res.on("finish", function () {
        if (settled) return; settled = true;
        check("bodyParser.raw() */* did NOT 415 a real Content-Type (status=" + res._endedStatus + ")",
          res._endedStatus !== 415);
        resolve();
      });
      setImmediate(function () { req.emit("data", Buffer.from("{}")); req.emit("end"); });
    });
  }, { timeoutMs: 1500 });                                                        // allow:raw-byte-literal — parser-settle budget ms
}

async function testPromiseToStreamWrapsPromise() {
  // The object-store remote backends' getStream() wraps a Promise<Buffer> via
  // sharedRequest.promiseToStream. A bare Readable.from(promise) throws
  // ERR_INVALID_ARG_TYPE — the helper must return a Readable that yields the
  // resolved bytes and surfaces a rejection as a stream 'error'.
  var sharedRequest = require("../../lib/object-store/http-request");
  var s = sharedRequest.promiseToStream(Promise.resolve(Buffer.from("hello-stream")));
  var chunks = [];
  await new Promise(function (resolve, reject) {
    s.on("data", function (c) { chunks.push(c); });
    s.on("end", resolve); s.on("error", reject);
  });
  check("promiseToStream yields the resolved buffer", Buffer.concat(chunks).toString() === "hello-stream");

  var s2 = sharedRequest.promiseToStream(Promise.reject(new Error("upstream boom")));
  var errored = false;
  await new Promise(function (resolve) {
    s2.on("error", function () { errored = true; resolve(); });
    s2.on("end", resolve);
    s2.resume();
  });
  check("promiseToStream surfaces a rejected promise as a stream 'error'", errored === true);
}

async function testSchedulerFarFutureNoImmediateFire() {
  // A task whose first fire is ~40 days out (> the 2147483647 ms setTimeout
  // ceiling) must NOT fire now. Pre-fix, Node coerced the over-max delay to 1ms
  // and the task fired immediately (and re-armed into a tight loop).
  var sched = b.scheduler.create({ audit: false });
  var fired = 0;
  sched.schedule({ name: "far", every: 40 * 24 * 60 * 60 * 1000, run: function () { fired += 1; } });
  await sched.start();
  await helpers.passiveObserve(600, "scheduler far-future: no immediate fire");
  check("scheduler far-future task does not fire immediately (setTimeout overflow clamped)", fired === 0);
  await sched.stop();
}

async function run() {
  testCborDuplicateKeyAndLinearSpeed();
  await testPromiseToStreamWrapsPromise();
  await testSchedulerFarFutureNoImmediateFire();
  testCryptoDecryptTruncatedEnvelope();
  await testMdocRequiresTrustAnchorByDefault();
  await testCoseAlgCurveBinding();
  testJsonPathFilterDepthCap();
  await testBodyParserRawWildcardMatchesRealType();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

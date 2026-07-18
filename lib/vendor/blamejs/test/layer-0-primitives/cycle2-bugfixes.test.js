// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Behavioral regression tests for the error/adversarial-branch defects found
 * while raising coverage on metrics / safe-buffer / tus-upload / guard-sql /
 * mcp / safe-yaml / content-credentials. Each assertion reproduces a specific
 * failure: it fails on the pre-fix tree (RED) and passes on the fixed tree.
 *
 * Run standalone: `node test/layer-0-primitives/cycle2-bugfixes.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers    = require("../helpers");
var b          = helpers.b;
var check      = helpers.check;
var nodeCrypto = require("crypto");
var Readable   = require("stream").Readable;

function threwCode(fn) {
  try { fn(); return null; } catch (e) { return e.code || null; }
}
function threw(fn) {
  try { fn(); return false; } catch (_e) { return true; }
}

async function main() {
  // ---- metrics: credential redaction reaches the exposition stream (HIGH) ----
  var m1 = b.metrics.create({ namespace: "p" });
  var c1 = m1.counter("logins_total", { labelNames: ["authorization"] });
  c1.inc({ authorization: "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
  var out = m1.exposition();
  check("metrics: credential label redacted in exposition, not just the map key",
    out.indexOf("[REDACTED-CREDENTIAL]") !== -1 && out.indexOf("Bearer aaaa") === -1);

  // ---- metrics: +/-Infinity rejected as non-finite (was isNaN-only) ----
  var m2 = b.metrics.create({ namespace: "q" });
  check("metrics: gauge.set(Infinity) rejected", threw(function () { m2.gauge("g", {}).set(Infinity); }));
  check("metrics: counter.inc(Infinity) rejected", threw(function () { m2.counter("c", {}).inc(Infinity); }));
  check("metrics: histogram.observe(Infinity) rejected",
    threw(function () { m2.histogram("h", { buckets: [0.5] }).observe(Infinity); }));
  check("metrics: gauge.set(42) still accepted", !threw(function () { m2.gauge("g2", {}).set(42); }));

  // ---- safe-buffer.collectStream: a defineClass errorClass keeps code/message
  //      the right way round (was swapped -> callers branching on e.code missed) ----
  var MyError = b.frameworkError.defineClass("CollectProbeError", { alwaysPermanent: true });
  var stream = new Readable({ read: function () {} });
  var caught = null;
  var p = b.safeBuffer.collectStream(stream, {
    maxBytes: b.constants.BYTES.bytes(4), errorClass: MyError,
    sizeCode: "probe/too-large", sizeMessage: "body exceeded max",
  }).then(function () { /* unexpected */ }, function (e) { caught = e; });
  stream.push(Buffer.from("way too many bytes"));
  stream.push(null);
  await p;
  check("safe-buffer: collectStream defineClass error keeps .code = sizeCode (not swapped)",
    !!caught && caught.code === "probe/too-large" && caught.message === "body exceeded max");

  // ---- guard-sql: fragment embedded-literal floor covers dollar-quotes + lone ; ----
  function frag(s) { return b.guardSql.validate(s, { contextMode: "fragment", profile: "strict" }).ok; }
  check("guard-sql: $tag$ dollar-quote refused in fragment", frag("x = $tag$secret$tag$") === false);
  check("guard-sql: $$ empty-tag dollar-quote refused", frag("x = $$secret$$") === false);
  check("guard-sql: lone trailing ; refused in fragment", frag("x = 1;") === false);
  check("guard-sql: single-quote literal still refused", frag("x = 'secret'") === false);
  check("guard-sql: ? placeholder still passes", frag("x = ?") === true);

  // ---- mcp: validation gates enforce without an explicit top-level type:object ----
  var inferredObjSchema = { properties: { path: { type: "string" } }, required: ["path"] };
  check("mcp: validateToolInput enforces required with no type:object (fail-open closed)",
    threw(function () { b.mcp.validateToolInput("t", {}, inferredObjSchema); }));
  check("mcp: validateToolInput rejects a scalar for an inferred object schema",
    threw(function () { b.mcp.validateToolInput("t", "oops", inferredObjSchema); }));
  check("mcp: validateToolInput rejects an array for an inferred object schema",
    threw(function () { b.mcp.validateToolInput("t", ["x"], inferredObjSchema); }));
  check("mcp: validateToolInput rejects null for an inferred object schema",
    threw(function () { b.mcp.validateToolInput("t", null, inferredObjSchema); }));
  check("mcp: validateToolInput still accepts a valid object for an inferred object schema",
    !threw(function () { b.mcp.validateToolInput("t", { path: "ok" }, inferredObjSchema); }));
  check("mcp: assertProtocolVersion honors explicit empty accepted:[]",
    threw(function () {
      b.mcp.assertProtocolVersion({ headers: { "mcp-protocol-version": "2024-11-05" } }, { accepted: [] });
    }));
  var sg = b.mcp.sampling.guard({ maxTokensPerRequest: 100 });
  check("mcp: sampling.guard rejects a string maxTokens (type-confusion)",
    threw(function () { sg.enforce({ messages: [{ role: "user", content: "x" }], maxTokens: "999999" }, "sid"); }));

  // ---- mcp serverGuard middleware (async): /register/ refusal + 401 challenge ----
  async function drive(guard, req) {
    var captured = { status: 200, headers: {}, nexted: false };
    var res = {
      statusCode: 200,
      setHeader: function (k, v) { captured.headers[k.toLowerCase()] = v; },
      end: function () { captured.status = this.statusCode; },
    };
    await guard(req, res, function () { captured.nexted = true; });
    return captured;
  }
  var gReg = b.mcp.serverGuard({ requireBearer: false });
  check("mcp: /register/ (trailing slash) refused like /register",
    (await drive(gReg, { url: "/register/", method: "POST", headers: {} })).nexted === false);
  var gBear = b.mcp.serverGuard({ requireBearer: true, verifyBearer: function () { return { sub: "x" }; } });
  var bearCap = await drive(gBear, { url: "/", method: "POST", headers: {} });
  check("mcp: missing bearer challenge returns 401 (was 400)",
    bearCap.status === 401 && !!bearCap.headers["www-authenticate"]);

  // ---- safe-yaml: flow-style parity with block style + root flow correctness ----
  check("safe-yaml: flow-mapping duplicate key rejected",
    threwCode(function () { b.parsers.yaml.parse("root: {a: 1, a: 2}"); }) === "yaml/duplicate-key");
  check("safe-yaml: flow-mapping merge key '<<' rejected",
    threwCode(function () { b.parsers.yaml.parse("root: {<<: base}"); }) === "yaml/merge-key-banned");
  check("safe-yaml: trailing content after flow collection rejected",
    threwCode(function () { b.parsers.yaml.parse("root: [1, 2] junk"); }) === "yaml/trailing-content");
  check("safe-yaml: root-level JSON object parses correctly (not mis-scanned as block key)",
    JSON.stringify(b.parsers.yaml.parse('{"a": 1, "b": 2}')) === '{"a":1,"b":2}');
  check("safe-yaml: root-level flow sequence still parses",
    JSON.stringify(b.parsers.yaml.parse("[1, 2, 3]")) === "[1,2,3]");

  // ---- content-credentials: immutability + typed rejections ----
  var m = b.contentCredentials.build({ provider: "Acme", system: "s", systemVersion: "1.0.0", contentId: "c" });
  var before = m.content.id;
  try { m.content.id = "HACKED"; } catch (_e) { /* strict-mode throw is fine too */ }
  check("content-credentials: nested claim object is deep-frozen",
    m.content.id === before && Object.isFrozen(m.content));
  check("content-credentials: NaN generatedAt typed-rejected",
    threwCode(function () {
      b.contentCredentials.build({ provider: "x", system: "s", systemVersion: "1.0.0", contentId: "c", generatedAt: NaN });
    }) === "content-credentials/bad-generated-at");
  var kp = nodeCrypto.generateKeyPairSync("ed25519");
  var pem = kp.privateKey.export({ type: "pkcs8", format: "pem" });
  check("content-credentials: non-Buffer certChain entry typed-rejected",
    threwCode(function () {
      b.contentCredentials.signCose(m, { privateKeyPem: pem, timestamp: false, timestampOptOutReason: "x", certChain: ["nope"] });
    }) === "content-credentials/bad-cert-chain");
}

if (require.main === module) {
  main().then(function () {
    console.log("cycle2-bugfixes OK — " + helpers.getChecks() + " checks");
  }, function (e) { console.error(e); process.exit(1); });
}

module.exports = { run: main };

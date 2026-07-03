// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mcp.toolRegistry — signed tool descriptors + signed tool-call envelopes.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _pair() {
  return b.crypto.generateSigningKeyPair("ml-dsa-87");
}

function testSurface() {
  check("toolRegistry.create is fn", typeof b.mcp.toolRegistry.create === "function");
  check("ALLOWED_ALGS includes ml-dsa-87", b.mcp.toolRegistry.ALLOWED_ALGS.indexOf("ml-dsa-87") !== -1);
}

function testCreateRefusesBadOpts() {
  function expectCode(label, fn, code) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf(code) !== -1);
  }
  expectCode("create: no opts",
             function () { b.mcp.toolRegistry.create(); }, "mcp/bad-registry-opts");
  expectCode("create: no tools array",
             function () { b.mcp.toolRegistry.create({ signingKey: "x" }); }, "mcp/bad-registry-opts");
  expectCode("create: no signingKey",
             function () { b.mcp.toolRegistry.create({ tools: [] }); }, "mcp/bad-signing-key");
  var p = _pair();
  expectCode("create: bad alg",
             function () { b.mcp.toolRegistry.create({ tools: [], signingKey: p.privateKey, alg: "rsa" }); }, "mcp/bad-alg");
  expectCode("create: bad tool name",
             function () { b.mcp.toolRegistry.create({ tools: [{ name: "0-bad", inputSchema: { type: "object" } }], signingKey: p.privateKey }); }, "mcp/bad-tool-name");
  expectCode("create: missing inputSchema",
             function () { b.mcp.toolRegistry.create({ tools: [{ name: "ok" }], signingKey: p.privateKey }); }, "mcp/bad-tool-schema");
}

function testRegisterAndList() {
  var p = _pair();
  var reg = b.mcp.toolRegistry.create({
    tools: [
      { name: "search", inputSchema: { type: "object", properties: { q: { type: "string" } } }, description: "Web search" },
      { name: "calc",   inputSchema: { type: "object", properties: { x: { type: "number" } } } },
    ],
    signingKey:   p.privateKey,
    verifyingKey: p.publicKey,
  });
  var rows = reg.list();
  check("list: 2 descriptors", rows.length === 2);
  check("list: sorted by name",
        rows[0].tool === "calc" && rows[1].tool === "search");
  check("descriptor has signature",
        typeof rows[0].signature === "string" && rows[0].signature.length > 0);
  check("descriptor has alg",  rows[0].alg === "ml-dsa-87");

  // get
  check("get(search) returns descriptor",  reg.get("search").tool === "search");
  check("get(nope) returns null",          reg.get("nope") === null);

  // register adds a new tool
  reg.register({ name: "summarize", inputSchema: { type: "object" } });
  check("after register: 3 tools", reg.list().length === 3);
}

function testDescriptorsManifest() {
  var p = _pair();
  var reg = b.mcp.toolRegistry.create({
    tools: [{ name: "search", inputSchema: { type: "object" } }],
    signingKey: p.privateKey,
  });
  var manifest = reg.descriptorsManifest();
  check("manifest has body + signature + alg",
        typeof manifest.body === "string" && typeof manifest.signature === "string" && manifest.alg === "ml-dsa-87");
  var parsed = JSON.parse(manifest.body);
  check("manifest body lists tools",
        Array.isArray(parsed.tools) && parsed.tools[0].tool === "search");
}

function testSignAndVerifyCall() {
  var p = _pair();
  var reg = b.mcp.toolRegistry.create({
    tools: [{ name: "search", inputSchema: { type: "object" } }],
    signingKey:   p.privateKey,
    verifyingKey: p.publicKey,
  });
  var signed = reg.signCall({ toolName: "search", args: { q: "blamejs" } });
  check("signCall envelope.tool",          signed.envelope.tool === "search");
  check("signCall envelope.nonce non-empty", typeof signed.envelope.nonce === "string" && signed.envelope.nonce.length === 32);
  check("signCall envelope.argsHash",      typeof signed.envelope.argsHash === "string");
  check("signCall envelope.iat ISO",       /^\d{4}-\d{2}-\d{2}T/.test(signed.envelope.iat));
  check("signCall envelope.exp ISO",       /^\d{4}-\d{2}-\d{2}T/.test(signed.envelope.exp));
  check("signCall signature non-empty",    typeof signed.signature === "string" && signed.signature.length > 0);

  // Verify round-trip (args optional)
  check("verifyCall: round-trip succeeds",
        reg.verifyCall(signed, { args: { q: "blamejs" } }) === true);

  // Verify without args (skip argsHash binding)
  check("verifyCall: succeeds without args binding",
        reg.verifyCall(signed) === true);
}

function testVerifyArgsMismatch() {
  var p = _pair();
  var reg = b.mcp.toolRegistry.create({
    tools: [{ name: "search", inputSchema: { type: "object" } }],
    signingKey: p.privateKey, verifyingKey: p.publicKey,
  });
  var signed = reg.signCall({ toolName: "search", args: { q: "hello" } });
  var threw = null;
  try { reg.verifyCall(signed, { args: { q: "DIFFERENT" } }); }
  catch (e) { threw = e; }
  check("verifyCall args-mismatch: refuses",
        threw && /call-args-mismatch/.test(threw.code || ""));
}

function testVerifyExpired() {
  var p = _pair();
  var reg = b.mcp.toolRegistry.create({
    tools: [{ name: "search", inputSchema: { type: "object" } }],
    signingKey: p.privateKey, verifyingKey: p.publicKey,
    ttlMs: 1000,
  });
  var signed = reg.signCall({ toolName: "search", args: { q: "h" } });
  // Pass an explicit nowMs far in the future to simulate expiry.
  var futureMs = Date.parse(signed.envelope.exp) + 60_000;
  var threw = null;
  try { reg.verifyCall(signed, { nowMs: futureMs }); }
  catch (e) { threw = e; }
  check("verifyCall: refuses expired",
        threw && /call-expired/.test(threw.code || ""));
}

function testVerifyReplay() {
  var p = _pair();
  var reg = b.mcp.toolRegistry.create({
    tools: [{ name: "search", inputSchema: { type: "object" } }],
    signingKey: p.privateKey, verifyingKey: p.publicKey,
  });
  var signed = reg.signCall({ toolName: "search", args: { q: "h" } });
  var threw = null;
  try { reg.verifyCall(signed, { seen: function () { return true; } }); }
  catch (e) { threw = e; }
  check("verifyCall: refuses replay (seen returned true)",
        threw && /call-replay/.test(threw.code || ""));
}

function testVerifyUnregisteredTool() {
  var p = _pair();
  var reg = b.mcp.toolRegistry.create({
    tools: [{ name: "search", inputSchema: { type: "object" } }],
    signingKey: p.privateKey, verifyingKey: p.publicKey,
  });
  var signed = reg.signCall({ toolName: "search", args: {} });
  // Mutate the envelope.tool to one that's not registered.
  var tampered = {
    envelope:  Object.assign({}, signed.envelope, { tool: "unknown" }),
    signature: signed.signature,
    alg:       signed.alg,
  };
  var threw = null;
  try { reg.verifyCall(tampered); }
  catch (e) { threw = e; }
  check("verifyCall: refuses unregistered tool",
        threw && /call-unregistered-tool/.test(threw.code || ""));
}

function testVerifyNoVerifyingKey() {
  var p = _pair();
  var reg = b.mcp.toolRegistry.create({
    tools: [{ name: "search", inputSchema: { type: "object" } }],
    signingKey: p.privateKey,  // no verifyingKey
  });
  var signed = reg.signCall({ toolName: "search", args: {} });
  var threw = null;
  try { reg.verifyCall(signed); }
  catch (e) { threw = e; }
  check("verifyCall: refuses without verifyingKey",
        threw && /no-verifying-key/.test(threw.code || ""));
}

async function run() {
  testSurface();
  testCreateRefusesBadOpts();
  testRegisterAndList();
  testDescriptorsManifest();
  testSignAndVerifyCall();
  testVerifyArgsMismatch();
  testVerifyExpired();
  testVerifyReplay();
  testVerifyUnregisteredTool();
  testVerifyNoVerifyingKey();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}

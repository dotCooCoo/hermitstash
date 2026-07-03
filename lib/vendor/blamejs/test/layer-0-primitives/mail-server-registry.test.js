// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.mail.serverRegistry — shared dispatch registry for IMAP / JMAP /
 * ManageSieve listeners. Tests cover the registration contract,
 * dispatch path, and refusal classes.
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

function _baseEntry(fn) {
  return { fn: fn, maxHandlerBytes: 8 * 1024, maxHandlerMs: 5 * 1000 };
}

function testCreateValidatesProtocol() {
  var threw = false;
  try { b.mail.serverRegistry.create({ protocol: "ftp" }); } catch (_e) { threw = true; }
  check("unknown protocol refused", threw);
}

function testBuiltinAndOverride() {
  var reg = b.mail.serverRegistry.create({
    protocol: "imap",
    defaults: { NOOP: _baseEntry(function () { return "default"; }) },
    overrides: { NOOP: _baseEntry(function () { return "override"; }) },
  });
  check("override shadows default",  reg.dispatch("NOOP") === "override");
  check("source is operator-override", reg.source("NOOP") === "operator-override");
}

function testNotConfiguredFallback() {
  var reg = b.mail.serverRegistry.create({
    protocol: "imap",
    defaults: {},
    notFoundHandler: function (name) { return "missing:" + name; },
  });
  check("notFoundHandler fires", reg.dispatch("FETCH") === "missing:FETCH");
}

function testBudgetRefusalAtRegister() {
  var threw;
  threw = false;
  try {
    b.mail.serverRegistry.create({
      protocol: "imap",
      defaults: { NOOP: { fn: function () {} } },   // no budgets
    });
  } catch (_e) { threw = true; }
  check("missing maxHandlerBytes refused", threw);

  threw = false;
  try {
    b.mail.serverRegistry.create({
      protocol: "imap",
      defaults: { NOOP: { fn: function () {}, maxHandlerBytes: 1024 } },   // no ms
    });
  } catch (_e) { threw = true; }
  check("missing maxHandlerMs refused", threw);
}

function testCatalogueGate() {
  var threw = false;
  try {
    b.mail.serverRegistry.create({
      protocol: "imap",
      defaults: { NONSENSE_VERB: _baseEntry(function () {}) },
    });
  } catch (_e) { threw = true; }
  check("catalogue rejects unknown method without allowExperimental", threw);

  // With allowExperimental: true the registration succeeds.
  var reg = b.mail.serverRegistry.create({
    protocol: "imap",
    defaults: {
      EXPERIMENTAL_VERB: Object.assign(_baseEntry(function () { return "ok"; }),
        { allowExperimental: true }),
    },
  });
  check("allowExperimental opt-in works", reg.dispatch("EXPERIMENTAL_VERB") === "ok");
}

async function testTimeoutWraps() {
  var reg = b.mail.serverRegistry.create({
    protocol: "imap",
    defaults: {
      NOOP: {
        fn: function () { return new Promise(function () { /* never */ }); },
        maxHandlerBytes: 8 * 1024,
        maxHandlerMs:    100,
      },
    },
  });
  var threw = false;
  var caught = null;
  try { await reg.dispatch("NOOP"); }
  catch (e) { threw = true; caught = e; }
  check("Promise handler past maxHandlerMs times out", threw);
  if (caught) {
    check("timeout error is typed",
      caught.code === "mail-server-registry/handler-timeout" ||
      /timeout/i.test(caught.message || "") ||
      caught.name === "MailServerRegistryError");
  }
}

function testListAndHas() {
  var reg = b.mail.serverRegistry.create({
    protocol: "managesieve",
    defaults: { NOOP: _baseEntry(function () {}) },
  });
  check("has() works",      reg.has("NOOP") === true);
  check("has() false miss", reg.has("PUTSCRIPT") === false);
  check("list() returns one", reg.list().length === 1);
  check("list entry has source", reg.list()[0].source === "builtin");
}

function testTenantScopeGate() {
  // v0.10.12 — b.agent.tenant adoption. When the registry is created
  // with a tenantScope + agentTenantId, every dispatch routes through
  // tenantScope.check(state.actor, agentTenantId) before the handler
  // runs. Cross-tenant dispatch refuses with AgentTenantError.
  var fakeScope = {
    check: function (actor, agentTenantId) {
      if (!actor) throw new Error("agent-tenant/no-actor: actor required");
      if (actor.tenantId !== agentTenantId) {
        var e = new Error("agent-tenant/cross-tenant-access-refused: " +
                          "actor.tenantId='" + actor.tenantId + "' agent='" + agentTenantId + "'");
        e.code = "agent-tenant/cross-tenant-access-refused";
        throw e;
      }
    },
  };
  var ran = 0;
  var reg = b.mail.serverRegistry.create({
    protocol:      "imap",
    defaults:      { NOOP: _baseEntry(function () { ran += 1; return "ok"; }) },
    tenantScope:   fakeScope,
    agentTenantId: "tenant-A",
  });
  // Matching tenant — dispatch reaches the handler.
  reg.dispatch("NOOP", { actor: { tenantId: "tenant-A" } });
  check("matching tenant dispatches", ran === 1);
  // Cross-tenant — dispatch throws BEFORE the handler runs.
  var threw = false;
  try { reg.dispatch("NOOP", { actor: { tenantId: "tenant-B" } }); }
  catch (e) { threw = e.code === "agent-tenant/cross-tenant-access-refused"; }
  check("cross-tenant dispatch refused", threw);
  check("handler did NOT run on refusal", ran === 1);

  // No-scope registries dispatch normally regardless of actor.tenantId.
  var noScope = b.mail.serverRegistry.create({
    protocol: "imap",
    defaults: { NOOP: _baseEntry(function () { return "open"; }) },
  });
  check("no-scope dispatch unaffected", noScope.dispatch("NOOP",
    { actor: { tenantId: "anything" } }) === "open");
}

function testTenantScopeJmapShape() {
  // JMAP dispatches as `registry.dispatch(methodName, actor, args, ctx)`
  // — the first dispatch arg is the actor object itself, not a state
  // wrapper. The registry MUST detect this shape and gate accordingly.
  var fakeScope = {
    check: function (actor, agentTenantId) {
      if (actor.tenantId !== agentTenantId) {
        var e = new Error("agent-tenant/cross-tenant-access-refused");
        e.code = "agent-tenant/cross-tenant-access-refused";
        throw e;
      }
    },
  };
  var ran = 0;
  var reg = b.mail.serverRegistry.create({
    protocol:      "jmap",
    defaults:      { "Core/echo": Object.assign(_baseEntry(function () { ran += 1; return {}; }),
      { allowExperimental: true }) },
    tenantScope:   fakeScope,
    agentTenantId: "tenant-A",
  });
  // JMAP shape — first arg is the actor.
  reg.dispatch("Core/echo", { tenantId: "tenant-A", id: "alice" });
  check("JMAP-shape matching tenant dispatches", ran === 1);
  var threw = false;
  try { reg.dispatch("Core/echo", { tenantId: "tenant-B", id: "mallory" }); }
  catch (e) { threw = e.code === "agent-tenant/cross-tenant-access-refused"; }
  check("JMAP-shape cross-tenant refused", threw);
  check("JMAP handler did NOT run on refusal", ran === 1);
}

function testTenantScopeValidation() {
  var threw;
  threw = false;
  try {
    b.mail.serverRegistry.create({
      protocol:    "imap",
      defaults:    {},
      tenantScope: { /* missing .check */ },
    });
  } catch (_e) { threw = true; }
  check("bad tenantScope shape refused", threw);

  threw = false;
  try {
    b.mail.serverRegistry.create({
      protocol:    "imap",
      defaults:    {},
      tenantScope: { check: function () {} },
      // missing agentTenantId
    });
  } catch (_e) { threw = true; }
  check("tenantScope without agentTenantId refused", threw);
}

async function run() {
  testCreateValidatesProtocol();
  testBuiltinAndOverride();
  testNotConfiguredFallback();
  testBudgetRefusalAtRegister();
  testCatalogueGate();
  await testTimeoutWraps();
  testListAndHas();
  testTenantScopeGate();
  testTenantScopeJmapShape();
  testTenantScopeValidation();
}

if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
module.exports = { run: run };

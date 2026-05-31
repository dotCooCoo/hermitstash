"use strict";
/**
 * b.graphqlFederation — _service.sdl trust-boundary guard.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("graphqlFederation.guardSdl is fn", typeof b.graphqlFederation.guardSdl === "function");
  check("graphqlFederation.queryProbesSdl is fn", typeof b.graphqlFederation.queryProbesSdl === "function");

  // ---- queryProbesSdl ----
  check("probes _service",        b.graphqlFederation.queryProbesSdl("{ _service { sdl } }") === true);
  check("probes _entities",       b.graphqlFederation.queryProbesSdl("{ _entities(representations:[...]) { ... } }") === true);
  check("clean query",            b.graphqlFederation.queryProbesSdl("{ user { name } }") === false);
  check("non-string query",       b.graphqlFederation.queryProbesSdl(null) === false);

  // ---- guardSdl opts validation ----
  var threw = null;
  try { b.graphqlFederation.guardSdl({}); } catch (e) { threw = e; }
  check("guardSdl: requires routerToken", threw && threw.code === "graphql-federation/bad-opts");

  var ok = b.graphqlFederation.guardSdl({ routerToken: "a".repeat(64) });
  check("guardSdl: returns middleware", typeof ok === "function");

  var pub = b.graphqlFederation.guardSdl({ publicSchemaOk: true });
  check("guardSdl: public schema", typeof pub === "function");

  // nonceHeader override — the replay nonce can be read from a custom
  // request header (not just the Apollo-vendor default), for operators
  // fronting the gateway with a non-Apollo router.
  var withNonce = b.graphqlFederation.guardSdl({
    routerToken: "a".repeat(64),
    nonceStore:  { has: function () { return false; }, remember: function () {} },
    nonceHeader: "x-my-nonce",
  });
  check("guardSdl: accepts custom nonceHeader", typeof withNonce === "function");
}

module.exports = { run: run };

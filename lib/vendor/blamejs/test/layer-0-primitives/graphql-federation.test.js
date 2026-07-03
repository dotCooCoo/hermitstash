// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
  // Aliased _service with NO leading whitespace must still probe true — the
  // prefix-char-class form let `query{x:_service{sdl}}` slip the SDL gate.
  check("probes aliased _service (no space)", b.graphqlFederation.queryProbesSdl("query{x:_service{sdl}}") === true);
  check("probes single-char-alias _service",  b.graphqlFederation.queryProbesSdl("{s:_service{sdl}}") === true);
  check("probes aliased _entities (no space)", b.graphqlFederation.queryProbesSdl("{a:_entities(r:[]){__typename}}") === true);
  // \b still excludes substring field names.
  check("does NOT probe my_service substring",  b.graphqlFederation.queryProbesSdl("query{my_service{x}}") === false);
  check("does NOT probe userservice substring", b.graphqlFederation.queryProbesSdl("query{userservice{x}}") === false);

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
  // fronting the gateway with a non-Apollo router. The replay store speaks
  // the framework's ATOMIC checkAndInsert(nonce, expireAt) contract.
  var withNonce = b.graphqlFederation.guardSdl({
    routerToken: "a".repeat(64),
    nonceStore:  { checkAndInsert: function () { return true; } },
    nonceHeader: "x-my-nonce",
  });
  check("guardSdl: accepts custom nonceHeader", typeof withNonce === "function");

  // #328 sibling — the replay nonceStore must speak the framework's ATOMIC
  // checkAndInsert(nonce, expireAt) contract (was a racy non-atomic
  // has()-then-remember() check-then-set). A store lacking checkAndInsert —
  // including the legacy { has, remember } shape — is refused at config time.
  var racyStoreThrew = null;
  try {
    b.graphqlFederation.guardSdl({
      routerToken: "a".repeat(64),
      nonceStore:  { has: function () { return false; }, remember: function () {} },
    });
  } catch (e) { racyStoreThrew = e; }
  check("guardSdl: refuses a nonceStore lacking checkAndInsert (legacy racy has/remember)",
        racyStoreThrew && racyStoreThrew.code === "graphql-federation/bad-nonce-store");

  // The framework's own b.nonceStore.create drops straight in, and a replay of
  // the SAME nonce on a valid bearer _service probe is refused (401) — driving
  // the REAL consumer path through the atomic store.
  var nonceStore = b.nonceStore.create({ backend: "memory" });
  var nguard = b.graphqlFederation.guardSdl({
    routerToken: "a".repeat(64), nonceStore: nonceStore, audit: false,
  });
  function _driveNonce(nonce) {
    return new Promise(function (resolve) {
      var out = { status: null, nextCalled: false };
      var res = {
        statusCode: 200,
        setHeader: function () {}, getHeader: function () { return undefined; },
        writeHead: function (s) { out.status = s; },
        end: function () { if (out.status === null) out.status = res.statusCode; resolve(out); },
      };
      nguard({
        method:  "POST",
        headers: { authorization: "Bearer " + "a".repeat(64),
                   "x-apollographql-router-nonce": nonce },
        body:    { query: "{ _service { sdl } }" },
        on:      function () {},
      }, res, function () { out.nextCalled = true; resolve(out); });
    });
  }
  var freshNonce = await _driveNonce("nonce-aaaaaaaaaaaaaaaa");
  check("guardSdl: fresh nonce on a valid bearer _service probe is forwarded",
        freshNonce.nextCalled === true && freshNonce.status === null);
  var replayNonce = await _driveNonce("nonce-aaaaaaaaaaaaaaaa");
  check("guardSdl: a replayed nonce is refused (401), not forwarded",
        replayNonce.status === 401 && replayNonce.nextCalled === false);

  // ---- guardSdl drives: a batched ARRAY body whose SECOND operation probes
  // _service must be refused (401) without a router token, not forwarded. ----
  function _drive(mw, body) {
    return new Promise(function (resolve) {
      var out = { status: null, nextCalled: false };
      var res = {
        statusCode: 200,
        setHeader: function () {}, getHeader: function () { return undefined; },
        writeHead: function (s) { out.status = s; },
        end: function () { if (out.status === null) out.status = res.statusCode; resolve(out); },
      };
      mw({ method: "POST", headers: {}, body: body, on: function () {} }, res,
        function () { out.nextCalled = true; resolve(out); });
    });
  }
  var guard = b.graphqlFederation.guardSdl({ routerToken: "a".repeat(64) });
  var batched = await _drive(guard, [{ query: "{ ok }" }, { query: "{ _service { sdl } }" }]);
  check("guardSdl: batched-array _service probe is refused (401), not forwarded",
        batched.status === 401 && batched.nextCalled === false);
  var aliased = await _drive(guard, { query: "query{x:_service{sdl}}" });
  check("guardSdl: aliased _service probe is refused (401)",
        aliased.status === 401 && aliased.nextCalled === false);
  var clean = await _drive(guard, { query: "{ user { name } }" });
  check("guardSdl: a clean query is forwarded (next)", clean.nextCalled === true);
}

module.exports = { run: run };

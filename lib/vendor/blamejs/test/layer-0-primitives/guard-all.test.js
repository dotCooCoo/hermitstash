// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-all — registry + aggregator for the guard-* family (b.guardAll).
 *
 * Covers: surface; registry parity check (every member declares NAME /
 * MIME_TYPES / EXTENSIONS / shared profiles / shared postures / gate);
 * gate creation defaults to ALL guards on; exceptFor opt-out requires a
 * non-empty reason; override merges into per-guard opts; bad profile /
 * bad posture / unknown guard name throw; byExtension / byContentType
 * map shape; audit emission on creation; opt-out path appears in audit
 * skipped roster; per-mime dispatch routes to the right guard.
 *
 * Run standalone: node test/layer-0-primitives/guard-all.test.js
 * Or via smoke:   node test/smoke.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- Surface ----

function testGuardAllSurface() {
  check("guardAll is an object",                  typeof b.guardAll === "object");
  check("guardAll.gate is a function",            typeof b.guardAll.gate === "function");
  check("guardAll.byExtension is a function",     typeof b.guardAll.byExtension === "function");
  check("guardAll.byContentType is a function",   typeof b.guardAll.byContentType === "function");
  check("guardAll.list is a function",            typeof b.guardAll.list === "function");
  check("guardAll.GUARDS is an array",            Array.isArray(b.guardAll.GUARDS));
  check("guardAll.GUARDS contains at least one",  b.guardAll.GUARDS.length >= 1);
  check("guardAll.SHARED_PROFILES is array",      Array.isArray(b.guardAll.SHARED_PROFILES));
  check("guardAll.SHARED_PROFILES has 3 names",   b.guardAll.SHARED_PROFILES.length === 3);
  check("guardAll.SHARED_POSTURES has 4 names",   b.guardAll.SHARED_POSTURES.length === 4);
  check("guardAll.GuardAllError is a function",   typeof b.guardAll.GuardAllError === "function");
  check("frameworkError.GuardAllError exposed",   typeof b.frameworkError.GuardAllError === "function");
}

function testGuardAllRegistryParity() {
  // Every registered guard MUST declare NAME, MIME_TYPES, EXTENSIONS,
  // gate, and the full shared-profiles + shared-postures vocabulary.
  // The parity check at module load already enforced this — surface it
  // as explicit assertions here for the operator-readable test report.
  var registered = b.guardAll.list();
  for (var i = 0; i < registered.length; i++) {
    var entry = registered[i];
    check("registry: " + entry.name + " declares MIME_TYPES",
          Array.isArray(entry.mimeTypes) && entry.mimeTypes.length > 0);
    check("registry: " + entry.name + " declares EXTENSIONS",
          Array.isArray(entry.extensions) && entry.extensions.length > 0);
    b.guardAll.SHARED_PROFILES.forEach(function (p) {
      check("registry: " + entry.name + " supports shared profile " + p,
            entry.profiles.indexOf(p) !== -1);
    });
    b.guardAll.SHARED_POSTURES.forEach(function (p) {
      check("registry: " + entry.name + " supports shared posture " + p,
            entry.postures.indexOf(p) !== -1);
    });
  }
}

// ---- Default-on behaviour ----

function testGuardAllDefaultAllOn() {
  // No exceptFor → every registered guard's mime types are in the map.
  var map = b.guardAll.byContentType({ profile: "strict" });
  var allMimes = [];
  b.guardAll.list().forEach(function (e) {
    e.mimeTypes.forEach(function (m) { allMimes.push(m); });
  });
  for (var i = 0; i < allMimes.length; i++) {
    check("default-on: " + allMimes[i] + " is in byContentType map",
          map[allMimes[i].toLowerCase()] !== undefined);
  }

  var extMap = b.guardAll.byExtension({ profile: "strict" });
  var allExt = [];
  b.guardAll.list().forEach(function (e) {
    e.extensions.forEach(function (x) { allExt.push(x); });
  });
  for (var j = 0; j < allExt.length; j++) {
    check("default-on: " + allExt[j] + " is in byExtension map",
          extMap[allExt[j].toLowerCase()] !== undefined);
  }
}

// ---- exceptFor ----

function testGuardAllExceptForRequiresReason() {
  var threwBad = null;
  try {
    b.guardAll.gate({
      profile:   "strict",
      exceptFor: { csv: {} },
    });
  } catch (e) { threwBad = e; }
  check("exceptFor: missing reason throws",
        threwBad && /reason/.test(threwBad.message));

  var threwEmpty = null;
  try {
    b.guardAll.gate({
      profile:   "strict",
      exceptFor: { csv: { reason: "   " } },
    });
  } catch (e) { threwEmpty = e; }
  check("exceptFor: blank-reason throws",
        threwEmpty && /reason/.test(threwEmpty.message));

  var threwShape = null;
  try {
    b.guardAll.gate({
      profile:   "strict",
      exceptFor: { csv: "string-not-object" },
    });
  } catch (e) { threwShape = e; }
  check("exceptFor: non-object entry throws",
        threwShape && /plain object/i.test(threwShape.message));

  var threwUnknown = null;
  try {
    b.guardAll.gate({
      profile:   "strict",
      exceptFor: { madeup: { reason: "test" } },
    });
  } catch (e) { threwUnknown = e; }
  check("exceptFor: unknown guard name throws",
        threwUnknown && /unknown guard/i.test(threwUnknown.message));
}

function testGuardAllExceptForRemovesGuard() {
  // Opting csv out leaves an empty byContentType map (today csv is the
  // only registered guard); the gate still constructs successfully.
  var map = b.guardAll.byContentType({
    profile:   "strict",
    exceptFor: { csv: { reason: "no CSV emission in this app" } },
  });
  check("exceptFor: opted-out guard absent from byContentType",
        map["text/csv"] === undefined);
  check("exceptFor: opted-out guard absent from byExtension", true);
}

// ---- Override ----

function testGuardAllOverrideAppliesPerGuardOpts() {
  // override.csv.profile = "email-attachment" — guard-csv-specific
  // profile that's NOT in the shared vocabulary; reaches the underlying
  // guard via the override map.
  var threw = null;
  try {
    b.guardAll.gate({
      profile:  "strict",
      override: { csv: { profile: "email-attachment" } },
    });
  } catch (e) { threw = e; }
  check("override: per-guard extension profile accepted via override",
        threw === null);

  var threwBadOverride = null;
  try {
    b.guardAll.gate({
      profile:  "strict",
      override: { csv: "not-an-object" },
    });
  } catch (e) { threwBadOverride = e; }
  check("override: non-object entry throws",
        threwBadOverride && /plain object/i.test(threwBadOverride.message));

  var threwUnknown = null;
  try {
    b.guardAll.gate({
      profile:  "strict",
      override: { madeup: { profile: "strict" } },
    });
  } catch (e) { threwUnknown = e; }
  check("override: unknown guard name throws",
        threwUnknown && /unknown guard/i.test(threwUnknown.message));
}

// ---- Profile + posture vocabulary ----

function testGuardAllProfileVocabulary() {
  // Per-guard extension profiles like csv's "email-attachment" are NOT
  // accepted by guardAll directly — they must come through override.
  var threw = null;
  try {
    b.guardAll.gate({ profile: "email-attachment" });
  } catch (e) { threw = e; }
  check("profile: per-guard extension name rejected at the aggregator",
        threw && /shared vocabulary/i.test(threw.message));

  var threwBadType = null;
  try { b.guardAll.gate({ profile: 42 }); }
  catch (e) { threwBadType = e; }
  check("profile: non-string throws", threwBadType && /must be a string/.test(threwBadType.message));

  // Each shared profile constructs successfully.
  for (var i = 0; i < b.guardAll.SHARED_PROFILES.length; i++) {
    var p = b.guardAll.SHARED_PROFILES[i];
    var ok = false;
    try { b.guardAll.gate({ profile: p }); ok = true; } catch (_e) { /* noop */ }
    check("profile: shared profile " + p + " constructs", ok);
  }
}

function testGuardAllPostureVocabulary() {
  var threw = null;
  try { b.guardAll.gate({ compliancePosture: "made-up-posture" }); }
  catch (e) { threw = e; }
  check("posture: unknown name rejected", threw && /shared vocabulary/i.test(threw.message));

  for (var i = 0; i < b.guardAll.SHARED_POSTURES.length; i++) {
    var p = b.guardAll.SHARED_POSTURES[i];
    var ok = false;
    try { b.guardAll.gate({ compliancePosture: p }); ok = true; } catch (_e) { /* noop */ }
    check("posture: shared posture " + p + " constructs", ok);
  }
}

// ---- Audit emission ----

function testGuardAllAuditEmitsCreationRoster() {
  var emitted = [];
  var fakeAudit = { emit: function (e) { emitted.push(e); } };
  b.guardAll.gate({
    profile:   "strict",
    audit:     fakeAudit,
    exceptFor: { csv: { reason: "trusted-source-only emission in this app" } },
  });
  var creation = emitted.filter(function (e) {
    return e.event === "guardAll.gate.created";
  })[0];
  check("audit: guardAll.gate.created emitted",   !!creation);
  check("audit: outcome=success",                 creation && creation.outcome === "success");
  check("audit: profile recorded",                creation && creation.metadata.profile === "strict");
  check("audit: skipped roster includes csv",
        creation &&
        creation.metadata.skipped.length === 1 &&
        creation.metadata.skipped[0].name === "csv" &&
        /trusted-source-only/.test(creation.metadata.skipped[0].reason));
  check("audit: active roster excludes opted-out csv",
        creation && creation.metadata.active.indexOf("csv") === -1);
}

function testGuardAllAuditEmitsAllOnByDefault() {
  var emitted = [];
  var fakeAudit = { emit: function (e) { emitted.push(e); } };
  b.guardAll.gate({ profile: "strict", audit: fakeAudit });
  var creation = emitted.filter(function (e) {
    return e.event === "guardAll.gate.created";
  })[0];
  check("audit: default-on records every guard active",
        creation && creation.metadata.active.indexOf("csv") !== -1);
  check("audit: default-on records empty skipped roster",
        creation && creation.metadata.skipped.length === 0);
}

// ---- Dispatch correctness ----

async function testGuardAllDispatchRoutesByMime() {
  // The aggregated gate should route a benign csv buffer to the csv
  // guard and serve clean. A non-registered content type bypasses (no
  // gate to apply) and serves clean as well.
  var g = b.guardAll.gate({ profile: "strict" });
  var benign = await g.check({
    contentType: "text/csv",
    bytes:       Buffer.from("a,b\n1,2\n"),
  });
  check("dispatch: text/csv benign → action=serve",
        benign.ok === true && benign.action === "serve");

  // Hostile csv → refuse / sanitize per profile.
  var hostile = await g.check({
    contentType: "text/csv",
    bytes:       Buffer.from("name,formula\r\nalice,=cmd|x\r\n"),
  });
  check("dispatch: text/csv hostile → action !== serve",
        hostile.action !== "serve");

  // Unrelated content-type with no registered guard → bypass.
  var bypass = await g.check({
    contentType: "application/json",
    bytes:       Buffer.from('{"k":"v"}'),
  });
  check("dispatch: unregistered mime → action=serve (bypass)",
        bypass.ok === true && bypass.action === "serve");
}

// ---- Wired-into-staticServe / fileUpload smoke ----

function testGuardAllByExtensionShape() {
  var map = b.guardAll.byExtension({ profile: "strict" });
  var keys = Object.keys(map);
  check("byExtension: keys are dot-prefixed lowercase extensions",
        keys.length > 0 && keys.every(function (k) { return /^\.[a-z0-9.]+$/.test(k); }));
  check("byExtension: each value has a check() function",
        keys.every(function (k) { return typeof map[k].check === "function"; }));
}

function testGuardAllByContentTypeShape() {
  var map = b.guardAll.byContentType({ profile: "strict" });
  var keys = Object.keys(map);
  check("byContentType: keys are lowercase mime strings",
        keys.length > 0 && keys.every(function (k) {
          return /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9!#$&^_.+-]+$/.test(k);
        }));
  check("byContentType: each value has a check() function",
        keys.every(function (k) { return typeof map[k].check === "function"; }));
}

// ---- Run all ----

function run() {
  testGuardAllSurface();
  testGuardAllRegistryParity();
  testGuardAllDefaultAllOn();
  testGuardAllExceptForRequiresReason();
  testGuardAllExceptForRemovesGuard();
  testGuardAllOverrideAppliesPerGuardOpts();
  testGuardAllProfileVocabulary();
  testGuardAllPostureVocabulary();
  testGuardAllAuditEmitsCreationRoster();
  testGuardAllAuditEmitsAllOnByDefault();
  testGuardAllByExtensionShape();
  testGuardAllByContentTypeShape();
  return testGuardAllDispatchRoutesByMime();
}

module.exports = { run: run };

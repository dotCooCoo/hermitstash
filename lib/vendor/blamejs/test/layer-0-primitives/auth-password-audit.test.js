// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auth.password.params() — operator-audit visibility for the
 * Argon2id parameter floor.
 *
 * The framework defaults must satisfy OWASP 2026 minimums: m >= 19 MiB
 * (19456 KiB), t >= 2, p >= 1. params() exposes the active values plus
 * the floor so a compliance scan can verify the floor without parsing
 * PHC strings out of the database.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testParamsSurface() {
  check("auth.password.params is a function",
        typeof b.auth.password.params === "function");
  var p = b.auth.password.params();
  check("params() returns active params",
        p && p.algorithm === "argon2id" &&
        p.active && typeof p.active.memoryCostKib === "number");
  check("params() returns OWASP 2026 floor (19 MiB / t>=2 / p>=1)",
        p.owaspFloor &&
        p.owaspFloor.memoryCostKib === b.constants.BYTES.kib(19) &&
        p.owaspFloor.timeCost === 2 && p.owaspFloor.parallelism === 1);
}

function testActiveMeetsFloor() {
  var p = b.auth.password.params();
  check("active memoryCost >= OWASP 2026 floor (19456 KiB)",
        p.active.memoryCostKib >= p.owaspFloor.memoryCostKib);
  check("active timeCost >= OWASP 2026 floor (2)",
        p.active.timeCost >= p.owaspFloor.timeCost);
  check("active parallelism >= OWASP 2026 floor (1)",
        p.active.parallelism >= p.owaspFloor.parallelism);
  check("params().meetsFloor === true",
        p.meetsFloor === true);
}

function testGateSurface() {
  var threw;
  try { b.auth.password.gate("not-a-number"); } catch (e) { threw = e; }
  check("auth.password.gate: non-integer rejected",
    threw && threw.code === "auth-password/bad-gate");
  // Setting an integer is accepted silently.
  b.auth.password.gate(8);
}

async function run() {
  testParamsSurface();
  testActiveMeetsFloor();
  testGateSurface();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

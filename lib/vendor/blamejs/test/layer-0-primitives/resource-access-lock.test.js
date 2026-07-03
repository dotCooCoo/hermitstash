// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.resourceAccessLock — three-mode (open / read-only / locked)
 * lock primitive for non-HTTP resources.
 *
 * Run standalone: `node test/layer-0-primitives/resource-access-lock.test.js`
 */

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  var lock = b.resourceAccessLock.create({
    resource: "data-export-jobs", startMode: "open", audit: false,
  });
  check("resourceAccessLock open: write permitted", lock.permits("write") === true);
  lock.set("read-only", { actor: "alice", reason: "incident-42" });
  check("resourceAccessLock read-only: write refused", lock.permits("write") === false);
  check("resourceAccessLock read-only: read permitted", lock.permits("read") === true);
  lock.set("locked");
  check("resourceAccessLock locked: read refused", lock.permits("read") === false);

  var threw;
  try { lock.assertPermits("write"); } catch (e) { threw = e; }
  check("resourceAccessLock.assertPermits throws ResourceAccessLockError",
    threw && threw.code === "resource-access-lock/refused");

  var threw2;
  try {
    b.resourceAccessLock.create({ resource: "x", startMode: "garbage" });
  } catch (e) { threw2 = e; }
  check("resourceAccessLock: bad startMode throws",
    threw2 && threw2.code === "resource-access-lock/bad-start-mode");

  check("resourceAccessLock.ResourceAccessLockError class registered",
    typeof b.resourceAccessLock.ResourceAccessLockError === "function");
  check("resourceAccessLock.VALID_MODES enumerates the three modes",
    Array.isArray(b.resourceAccessLock.VALID_MODES) &&
    b.resourceAccessLock.VALID_MODES.indexOf("open") !== -1 &&
    b.resourceAccessLock.VALID_MODES.indexOf("read-only") !== -1 &&
    b.resourceAccessLock.VALID_MODES.indexOf("locked") !== -1);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[resource-access-lock] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}

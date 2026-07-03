// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.atomicFile.fdSafeReadSync — errorFor must own EVERY failure KIND (#358).
 *
 * Two regressions:
 *   (A) refuseSymlink lstats the path first; a MISSING file makes lstatSync
 *       throw raw ENOENT BEFORE the openSync branch that consults
 *       errorFor("enoent") — so a caller's enoent mapping silently never
 *       fires when refuseSymlink is on (the missing-file error class then
 *       differs by whether refuseSymlink is set).
 *   (B) The openSync ENOENT branch guards errorFor returning undefined
 *       (throw-if-truthy, else rethrow raw) — but the symlink / too-large /
 *       toctou / short-read / integrity branches threw errorFor(...) raw,
 *       so an errorFor that returns undefined for those throws `undefined`.
 */

var fs   = require("fs");
var path = require("path");

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _dir() { return b.testing.tempDir("fdsaferead-errorfor"); }

function _throws(fn) {
  try { fn(); return null; } catch (e) { return { e: e, threw: true }; }
}

// (A) refuseSymlink + missing file → the caller's errorFor("enoent") fires.
function testRefuseSymlinkMissingRoutesEnoent() {
  var dir = _dir();
  try {
    var missing = path.join(dir.path, "nope.pem");
    function Tagged(msg) { this.message = msg; this.tag = "custom-enoent"; }
    var r = _throws(function () {
      b.atomicFile.fdSafeReadSync(missing, {
        refuseSymlink: true,
        errorFor: function (kind) {
          return kind === "enoent" ? new Tagged("not there") : undefined;
        },
      });
    });
    check("fdSafeReadSync refuseSymlink + missing: caller errorFor(enoent) fires (not raw ENOENT)",
          r !== null && r.e && r.e.tag === "custom-enoent");
  } finally { dir.cleanup(); }
}

// (A) refuseSymlink + missing + errorFor returning undefined → rethrows raw ENOENT
// (same posture the openSync branch already gives), never `undefined`.
function testRefuseSymlinkMissingErrorForUndefinedRethrowsRaw() {
  var dir = _dir();
  try {
    var missing = path.join(dir.path, "nope2.pem");
    var r = _throws(function () {
      b.atomicFile.fdSafeReadSync(missing, {
        refuseSymlink: true,
        errorFor: function () { return undefined; },
      });
    });
    check("fdSafeReadSync refuseSymlink + missing + undefined errorFor rethrows raw ENOENT",
          r !== null && r.e && r.e.code === "ENOENT");
  } finally { dir.cleanup(); }
}

// (B) errorFor returning undefined for "too-large" must throw a REAL error,
// never the literal `undefined`.
function testTooLargeErrorForUndefinedThrowsRealError() {
  var dir = _dir();
  try {
    var p = path.join(dir.path, "big.bin");
    fs.writeFileSync(p, Buffer.alloc(4096), { mode: 0o600 });
    var r = _throws(function () {
      b.atomicFile.fdSafeReadSync(p, {
        maxBytes: 16,
        errorFor: function () { return undefined; },
      });
    });
    check("fdSafeReadSync too-large + undefined errorFor throws a real Error (not undefined)",
          r !== null && r.e instanceof Error);
  } finally { dir.cleanup(); }
}

// (B) errorFor returning undefined for "symlink" must throw a REAL error.
function testSymlinkErrorForUndefinedThrowsRealError() {
  var dir = _dir();
  try {
    var victim = path.join(dir.path, "victim.pem");
    fs.writeFileSync(victim, "SECRET", { mode: 0o600 });
    var link = path.join(dir.path, "link.pem");
    var symlinkOk = true;
    try { fs.symlinkSync(victim, link); } catch (_e) { symlinkOk = false; }
    if (symlinkOk) {
      var r = _throws(function () {
        b.atomicFile.fdSafeReadSync(link, {
          refuseSymlink: true,
          errorFor: function () { return undefined; },
        });
      });
      check("fdSafeReadSync symlink + undefined errorFor throws a real Error (not undefined)",
            r !== null && r.e instanceof Error);
    } else {
      check("fdSafeReadSync symlink case skipped (platform lacks symlink privilege)", true);
    }
  } finally { dir.cleanup(); }
}

// (B) errorFor returning undefined for "integrity" must throw a REAL error.
function testIntegrityErrorForUndefinedThrowsRealError() {
  var dir = _dir();
  try {
    var p = path.join(dir.path, "hashed.bin");
    fs.writeFileSync(p, Buffer.from("integrity"), { mode: 0o600 });
    var r = _throws(function () {
      b.atomicFile.fdSafeReadSync(p, {
        expectedHash: "0".repeat(128),
        errorFor: function () { return undefined; },
      });
    });
    check("fdSafeReadSync integrity + undefined errorFor throws a real Error (not undefined)",
          r !== null && r.e instanceof Error);
  } finally { dir.cleanup(); }
}

async function run() {
  testRefuseSymlinkMissingRoutesEnoent();
  testRefuseSymlinkMissingErrorForUndefinedRethrowsRaw();
  testTooLargeErrorForUndefinedThrowsRealError();
  testSymlinkErrorForUndefinedThrowsRealError();
  testIntegrityErrorForUndefinedThrowsRealError();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e.stack || e); process.exit(1); });
}

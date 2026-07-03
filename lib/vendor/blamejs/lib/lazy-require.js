// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Lazy-require — cached deferred-load helper.
 *
 * Centralizes the pattern used to break circular-load chains between
 * modules that depend on each other through different code paths
 * (audit ↔ db, vault ↔ db, middleware ↔ audit). Every dependent module
 * was carrying its own copy of:
 *
 *   var _db = null;
 *   function db() { if (!_db) _db = require("./db"); return _db; }
 *   // and `_db = null;` in _resetForTest
 *
 * `lazyRequire(loader)` returns a callable getter `db()` that does the
 * cache-on-first-call dance once, plus a `db.reset()` for test
 * teardown. The `loader` is a function (NOT a path string) so the
 * inner `require()` resolves relative to the CALLER's __filename, not
 * lib/lazy-require.js — passing a string here would break relative
 * paths from any module not co-located with lazy-require.js.
 *
 * Usage:
 *
 *   var lazyRequire = require("./lazy-require");
 *   var db = lazyRequire(function () { return require("./db"); });
 *   // ... later ...
 *   db().findOne(...);   // first call resolves + caches
 *   // in _resetForTest:
 *   db.reset();
 */

function lazyRequire(loader) {
  if (typeof loader !== "function") {
    throw new Error("lazyRequire(loader): loader must be a function returning the require() result");
  }
  // Separate `loaded` flag from `cached` so a loader that legitimately
  // returns null/undefined/0/false caches that value instead of re-running
  // on every subsequent call.
  var loaded = false;
  var cached;
  function get() {
    if (!loaded) { cached = loader(); loaded = true; }
    return cached;
  }
  get.reset = function () { loaded = false; cached = undefined; };
  return get;
}

module.exports = lazyRequire;

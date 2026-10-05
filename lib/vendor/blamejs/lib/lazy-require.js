// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.lazyRequire
 * @nav    Primitives
 * @title  Lazy Require
 * @slug   lazy-require
 *
 * @intro
 *   Defer a <code>require</code> until the first call that needs it, and
 *   cache what comes back.
 *
 *   Two modules that need each other cannot both finish loading first: the
 *   second one to be entered sees a half-built <code>module.exports</code>
 *   from the first, and reads whatever happened to be assigned by then.
 *   Deferring the require moves it to call time, when both modules have
 *   finished loading, so the second sees the whole thing.
 *
 *   The argument is a function rather than a path, so the
 *   <code>require</code> inside it resolves against the calling file. A
 *   path string would resolve against this module instead, and every
 *   relative path from anywhere else in the tree would be wrong.
 *
 * @card
 *   Defer a require to first use and cache it, so two modules that need
 *   each other both see a finished export rather than a half-built one.
 *
 * @section Reaching for it
 *   New code requires at the top of the file. This is for a cycle that is
 *   real and commented, not a way to avoid thinking about one.
 */

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

/**
 * @primitive b.lazyRequire
 * @signature b.lazyRequire(loader)
 * @since     0.1.29
 * @status    stable
 * @related   b.constants
 *
 * Answer a getter that calls `loader` the first time it is called and
 * answers the same value every time after. The getter carries `reset()`,
 * which drops the cached value so the next call loads again; a test that
 * swaps a module out calls it in teardown.
 *
 * `loader` is a function that performs the `require` and returns it, so
 * the path inside resolves against the calling file. A value that is not a
 * function throws here rather than at the first use.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var db = b.lazyRequire(function () { return require("./db"); });
 *   db().from("users");   // the first call loads and caches
 *   db.reset();           // teardown
 */
function lazyRequire(loader) {
  if (typeof loader !== "function") {
    throw new Error("lazyRequire(loader): loader must be a function returning the require() result");
  }
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

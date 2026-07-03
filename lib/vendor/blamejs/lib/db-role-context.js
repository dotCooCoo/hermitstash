// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * db-role-context — shared AsyncLocalStorage registry for the request-time
 * DB role binding.
 *
 * The b.middleware.dbRoleFor middleware enters a scope with { role }; the
 * externalDb backend picker reads the same store at query time. Anything
 * deep in the async stack — handler, db query, transaction body, audit
 * write — sees the same role without explicit threading.
 *
 * Out-of-request callers (jobs, schedulers, CLIs) use externalDb.runAs to
 * push a role into the same store for the body of their work.
 *
 * Public API (consumed by externalDb / middleware / permissions):
 *   getRole()                → string | null
 *   runWithRole(role, fn)    → fn() inside the role-bound ALS scope
 *
 * The role string must be a SQL-identifier-shaped value; callers are
 * responsible for validating before pushing into the store. The store
 * holds a frozen { role } shape so consumers can't mutate it sideways.
 */
var { AsyncLocalStorage } = require("node:async_hooks");

var _als = new AsyncLocalStorage();

function getStore() {
  return _als.getStore() || null;
}

function getRole() {
  var s = getStore();
  return s && s.role ? s.role : null;
}

function runWithRole(role, fn) {
  if (typeof fn !== "function") {
    throw new TypeError("db-role-context.runWithRole: fn must be a function");
  }
  // Null / undefined role passes through as "no binding" — useful for
  // explicitly entering a scope that resets any inherited role.
  var store = role ? Object.freeze({ role: String(role) }) : Object.freeze({ role: null });
  return _als.run(store, fn);
}

module.exports = {
  getRole:      getRole,
  runWithRole:  runWithRole,
  // For diagnostic use; consumers should prefer getRole.
  _als:         _als,
};

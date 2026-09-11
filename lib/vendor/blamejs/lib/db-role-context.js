// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
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
  var store = role ? Object.freeze({ role: String(role) }) : Object.freeze({ role: null });
  return _als.run(store, fn);
}

module.exports = {
  getRole:      getRole,
  runWithRole:  runWithRole,
  _als:         _als,
};

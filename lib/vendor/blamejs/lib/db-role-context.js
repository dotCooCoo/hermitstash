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
  var prev = getStore();
  var store = Object.freeze({
    role:            role ? String(role) : null,
    auditChainWrite: !!(prev && prev.auditChainWrite),
  });
  return _als.run(store, fn);
}

function isAuditChainWrite() {
  var s = getStore();
  return !!(s && s.auditChainWrite);
}

function runAsAuditChainWrite(fn) {
  if (typeof fn !== "function") {
    throw new TypeError("db-role-context.runAsAuditChainWrite: fn must be a function");
  }
  var prev = getStore();
  var store = Object.freeze({
    role:            (prev && prev.role) || null,
    auditChainWrite: true,
  });
  return _als.run(store, fn);
}

function outsideAuditChainWrite(fn) {
  if (typeof fn !== "function") {
    throw new TypeError("db-role-context.outsideAuditChainWrite: fn must be a function");
  }
  var prev = getStore();
  if (!prev || !prev.auditChainWrite) return fn();
  return _als.run(Object.freeze({ role: prev.role || null, auditChainWrite: false }), fn);
}

module.exports = {
  getRole:                 getRole,
  runWithRole:             runWithRole,
  isAuditChainWrite:       isAuditChainWrite,
  runAsAuditChainWrite:    runAsAuditChainWrite,
  outsideAuditChainWrite:  outsideAuditChainWrite,
  _als:                    _als,
};

"use strict";
/**
 * Counts the Argon2id runs that reach node:crypto.argon2 in this process.
 *
 * install() replaces node:crypto.argon2 with a wrapper that counts the runs in
 * progress and records the highest count seen. After hold(), a run that starts
 * does not reach node:crypto until release() is called. uninstall() releases
 * any run still held and restores the original function.
 *
 * lib/vendor/blamejs/lib/argon2-builtin.js looks up nodeCrypto.argon2 on each
 * call, so the wrapper also sees runs from the copy of the framework that
 * tests/helpers/test-server.js loads after it clears the require cache.
 */
var nodeCrypto = require("node:crypto");

var original = null;
var running = 0;
var maxRunning = 0;
var calls = 0;
var holding = false;
var held = [];

function _start(args) {
  original.apply(nodeCrypto, args);
}

function install() {
  if (original) return;
  original = nodeCrypto.argon2;
  nodeCrypto.argon2 = function (algorithm, params, callback) {
    calls += 1;
    running += 1;
    if (running > maxRunning) maxRunning = running;
    var args = [algorithm, params, function (err, result) {
      running -= 1;
      callback(err, result);
    }];
    if (holding) { held.push(args); return; }
    _start(args);
  };
}

function release() {
  holding = false;
  var pending = held;
  held = [];
  for (var i = 0; i < pending.length; i++) _start(pending[i]);
}

function uninstall() {
  if (!original) return;
  release();
  nodeCrypto.argon2 = original;
  original = null;
}

function hold() { holding = true; }

function reset() {
  maxRunning = running;
  calls = 0;
}

function stats() {
  return { running: running, maxRunning: maxRunning, calls: calls, held: held.length };
}

module.exports = { install: install, uninstall: uninstall, hold: hold, release: release, reset: reset, stats: stats };

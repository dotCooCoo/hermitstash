// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var CORE_POISONED_KEYS = ["__proto__", "constructor", "prototype"];
var POISONED_KEY_SET = new Set(CORE_POISONED_KEYS);

function registerPoisonedKeys(keys) {
  if (!Array.isArray(keys)) {
    throw new TypeError("pick.registerPoisonedKeys: keys must be an array of strings, got " + (typeof keys));
  }
  for (var i = 0; i < keys.length; i += 1) {
    if (typeof keys[i] !== "string" || keys[i].length === 0) {
      throw new TypeError("pick.registerPoisonedKeys: every key must be a non-empty string");
    }
    POISONED_KEY_SET.add(keys[i]);
  }
}

function isPoisonedKey(key) {
  return typeof key === "string" && POISONED_KEY_SET.has(key);
}

function assertSafeKey(key, onPoisoned) {
  if (typeof onPoisoned !== "function") {
    throw new TypeError("pick.assertSafeKey: onPoisoned must be a function, got " + (typeof onPoisoned));
  }
  if (isPoisonedKey(key)) return onPoisoned(key);
  return undefined;
}

function _isPlainObject(o) {
  return o !== null && typeof o === "object" && !Array.isArray(o) &&
         (Object.getPrototypeOf(o) === Object.prototype ||
          Object.getPrototypeOf(o) === null);
}

function _normalizeAllowList(list) {
  var out = Object.create(null);
  for (var i = 0; i < list.length; i += 1) {
    var entry = list[i];
    if (typeof entry === "string") {
      if (isPoisonedKey(entry)) continue;
      out[entry] = true;
    } else if (Array.isArray(entry) && entry.length === 2 &&
               typeof entry[0] === "string" && Array.isArray(entry[1])) {
      if (isPoisonedKey(entry[0])) continue;
      out[entry[0]] = _normalizeAllowList(entry[1]);
    } else {
      throw new TypeError(
        "b.pick: allowlist entry must be a string or [name, [...]]; got " +
        JSON.stringify(entry));
    }
  }
  return out;
}

function _pickInner(input, normalized, onUnknown, path) {
  if (!_isPlainObject(input)) {
    return _isPlainObject(input) ? {} : input;
  }
  var output = Object.create(null);
  var keys = Object.keys(input);
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    if (isPoisonedKey(k)) continue;
    if (!Object.prototype.hasOwnProperty.call(normalized, k)) {
      if (onUnknown === "throw") {
        throw new TypeError(
          "b.pick: unknown key '" + (path ? path + "." : "") + k +
          "' not in allowlist");
      }
      continue;
    }
    var rule = normalized[k];
    if (rule === true) {
      output[k] = input[k];
    } else {
      output[k] = _isPlainObject(input[k])
        ? _pickInner(input[k], rule, onUnknown, (path ? path + "." : "") + k)
        : input[k];
    }
  }
  return Object.assign({}, output);
}

function pick(input, allowList, opts) {
  opts = opts || {};
  if (!Array.isArray(allowList)) {
    throw new TypeError("b.pick: second argument must be an array of allowed keys");
  }
  var onUnknown = opts.onUnknown === "throw" ? "throw" : "drop";
  var normalized = _normalizeAllowList(allowList);
  return _pickInner(input, normalized, onUnknown, "");
}

module.exports = pick;
module.exports.pick = pick;
module.exports.POISONED_KEYS = Object.freeze(CORE_POISONED_KEYS.slice());
module.exports.isPoisonedKey = isPoisonedKey;
module.exports.assertSafeKey = assertSafeKey;
module.exports.registerPoisonedKeys = registerPoisonedKeys;

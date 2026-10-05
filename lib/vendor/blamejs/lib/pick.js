// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module b.pick
 * @nav    Validation
 * @title  Pick
 * @slug   pick
 *
 * @intro
 *   Build a new object holding only the keys you named. Assigning a
 *   request body onto a record takes every key the request happened to
 *   carry, which is how a form that edits a display name also sets
 *   <code>isAdmin</code>. Naming the keys inverts that: what was not
 *   named is not there.
 *
 *   The keys that move or read a prototype, <code>__proto__</code>,
 *   <code>constructor</code> and <code>prototype</code>, are dropped
 *   whether or not they were named, so an allow-list cannot be written
 *   that lets one through. The result has a null prototype internally and
 *   is copied onto a plain object, so nothing inherited comes with it.
 *
 *   Nesting is by <code>[name, [keys]]</code>, and the same rules apply at
 *   every level. An array is filtered element by element, so a body an
 *   attacker sent as a list is no way around the allow-list, and the shape
 *   of the object does not matter: a class instance and an object from
 *   another realm are filtered the same way a literal is.
 *
 * @card
 *   Copy only the keys you named out of an untrusted object, dropping the
 *   rest and always dropping the prototype-poisoning ones. Nested
 *   allow-lists, and an option to refuse an unknown key instead of
 *   dropping it.
 */

var CORE_POISONED_KEYS = ["__proto__", "constructor", "prototype"];
var POISONED_KEY_SET = new Set(CORE_POISONED_KEYS);

/**
 * @primitive b.pick.registerPoisonedKeys
 * @signature b.pick.registerPoisonedKeys(keys)
 * @since     0.15.13
 * @status    stable
 * @related   b.pick.isPoisonedKey, b.pick
 *
 * Add key names to the set every caller treats as unsafe. A deployment
 * whose object layer gives another name the power `__proto__` has adds it
 * here once, and every `b.pick` call and every `assertSafeKey` check
 * refuses it from then on.
 *
 * The set only grows: there is no removal, so a name registered as unsafe
 * cannot be made safe again by later code.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.pick.registerPoisonedKeys(["$where"]);
 *   b.pick.isPoisonedKey("$where");   // → true
 */
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

/**
 * @primitive b.pick.isPoisonedKey
 * @signature b.pick.isPoisonedKey(key)
 * @since     0.15.13
 * @status    stable
 * @related   b.pick.assertSafeKey, b.pick.registerPoisonedKeys
 *
 * Is this key one of the names that must never be assigned from untrusted
 * input? True for `__proto__`, `constructor` and `prototype`, and for
 * anything `b.pick.registerPoisonedKeys` has added. False for a value that
 * is not a string.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.pick.isPoisonedKey("__proto__");   // → true
 *   b.pick.isPoisonedKey("name");        // → false
 */
function isPoisonedKey(key) {
  return typeof key === "string" && POISONED_KEY_SET.has(key);
}

/**
 * @primitive b.pick.movesThePrototype
 * @signature b.pick.movesThePrototype(key)
 * @since     0.20.32
 * @status    stable
 * @related   b.pick.isPoisonedKey
 *
 * Is this the one key whose assignment replaces an object's prototype?
 * True only for `__proto__`.
 *
 * `constructor` and `prototype` are unsafe to copy and do not by
 * themselves move a prototype, so a caller that has to tell the two apart,
 * to report which happened, asks this rather than `isPoisonedKey`.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.pick.movesThePrototype("__proto__");     // → true
 *   b.pick.movesThePrototype("constructor");   // → false
 */
function movesThePrototype(key) {
  return key === "__proto__";
}

/**
 * @primitive b.pick.assertSafeKey
 * @signature b.pick.assertSafeKey(key, onPoisoned)
 * @since     0.15.13
 * @status    stable
 * @related   b.pick.isPoisonedKey, b.pick
 *
 * Call `onPoisoned(key)` when the key is unsafe, and answer undefined when
 * it is not. The caller decides what happens, because a parser building a
 * value wants to skip the key while an options reader wants to throw.
 *
 * `onPoisoned` must be a function; anything else throws a `TypeError`
 * here, rather than leaving an unsafe key unhandled because the handler
 * was missing.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var refused = [];
 *   b.pick.assertSafeKey("__proto__", function (k) { refused.push(k); });
 *   b.pick.assertSafeKey("name", function (k) { refused.push(k); });
 *   refused;
 *   // → ["__proto__"]
 */
function assertSafeKey(key, onPoisoned) {
  if (typeof onPoisoned !== "function") {
    throw new TypeError("pick.assertSafeKey: onPoisoned must be a function, got " + (typeof onPoisoned));
  }
  if (isPoisonedKey(key)) return onPoisoned(key);
  return undefined;
}

function _isObjectLike(o) {
  return o !== null && typeof o === "object";
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
  if (Array.isArray(input)) {
    var mapped = new Array(input.length);
    for (var ai = 0; ai < input.length; ai += 1) {
      mapped[ai] = _pickInner(input[ai], normalized, onUnknown, path);
    }
    return mapped;
  }
  if (!_isObjectLike(input)) return input;
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
      output[k] = _isObjectLike(input[k])
        ? _pickInner(input[k], rule, onUnknown, (path ? path + "." : "") + k)
        : input[k];
    }
  }
  return Object.assign({}, output);
}

/**
 * @primitive b.pick
 * @signature b.pick(input, allowList, opts?)
 * @since     0.7.21
 * @status    stable
 * @compliance soc2, gdpr
 * @related   b.safeSchema.object, b.guardJson.gate
 *
 * Answer a new object carrying only the allowed keys of `input`. An entry
 * in `allowList` is a key name, or `[name, [keys]]` to allow a nested
 * object and name what may come out of it.
 *
 * A key that is not on the list is dropped, or throws when
 * `onUnknown: "throw"`, which is the choice between accepting a request
 * that carried more than it should and telling the caller it did.
 *
 * `__proto__`, `constructor` and `prototype` never come through, and
 * naming one on the allow-list does not change that.
 *
 * An array is filtered element by element against the same list. Anything
 * that is not an object comes back as it is, so a caller can hand the
 * result of a parse straight in whatever it turned out to be.
 *
 * Every object is filtered, whatever its prototype: a class instance keeps
 * only the allowed own keys and brings none of its prototype, and an
 * object built in another realm, by a `node:vm` context for instance, is
 * treated as the object it is rather than passed through.
 *
 * @opts
 *   onUnknown: string,   // "drop" (default) or "throw"
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.pick({ name: "ada", isAdmin: true }, ["name"]);
 *   // → { name: "ada" }
 *
 *   b.pick({ name: "ada", profile: { bio: "x", role: "root" } },
 *          ["name", ["profile", ["bio"]]]);
 *   // → { name: "ada", profile: { bio: "x" } }
 */
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
module.exports.movesThePrototype = movesThePrototype;
module.exports.assertSafeKey = assertSafeKey;
module.exports.registerPoisonedKeys = registerPoisonedKeys;

"use strict";
/**
 * b.pick — mass-assignment (CWE-915 / OWASP API3:2023) defense.
 *
 * The vulnerability: a route accepting `JSON` body and passing
 * `req.body` straight to a DB write lets an attacker include fields
 * the operator never intended (`isAdmin`, `passwordHash`, `userId`).
 * This primitive is the operator's allowlist of acceptable fields —
 * pass req.body through it before persisting.
 *
 *   var safeUserUpdate = b.pick(req.body, [
 *     "displayName", "bio", "avatarUrl",
 *   ]);
 *   await db.users.update(userId, safeUserUpdate);
 *
 * Returns a NEW object containing only the keys in the allowlist.
 * Keys not present in the input are simply absent from the output —
 * no defaults filled in, no `undefined` values. Prototype-pollution
 * keys (`__proto__` / `constructor` / `prototype`) are ALWAYS
 * stripped, even if the operator accidentally lists them.
 *
 *   var partial = b.pick(req.body, ["a", "b"], { onUnknown: "throw" });
 *   // throws if req.body has any key NOT in ["a", "b"]
 *
 *   var nested = b.pick(req.body, [
 *     "name",
 *     ["profile", ["bio", "url"]],     // nested allowlist for `profile.*`
 *   ]);
 */

var POISONED_KEYS = ["__proto__", "constructor", "prototype"];

function _isPlainObject(o) {
  return o !== null && typeof o === "object" && !Array.isArray(o) &&
         (Object.getPrototypeOf(o) === Object.prototype ||
          Object.getPrototypeOf(o) === null);
}

function _normalizeAllowList(list) {
  // Accept either ["a","b"] or [["nested",["sub1","sub2"]]] — return
  // a Map<key, allowList | true>.
  var out = Object.create(null);
  for (var i = 0; i < list.length; i += 1) {
    var entry = list[i];
    if (typeof entry === "string") {
      if (POISONED_KEYS.indexOf(entry) !== -1) continue;
      out[entry] = true;
    } else if (Array.isArray(entry) && entry.length === 2 &&
               typeof entry[0] === "string" && Array.isArray(entry[1])) {
      if (POISONED_KEYS.indexOf(entry[0]) !== -1) continue;
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
    if (POISONED_KEYS.indexOf(k) !== -1) continue;
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
      // Nested allowlist.
      output[k] = _isPlainObject(input[k])
        ? _pickInner(input[k], rule, onUnknown, (path ? path + "." : "") + k)
        : input[k];
    }
  }
  // Convert to a plain Object (output is currently null-prototype) so
  // downstream JSON serializers / DB drivers see a normal-shape object.
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
module.exports.POISONED_KEYS = Object.freeze(POISONED_KEYS.slice());

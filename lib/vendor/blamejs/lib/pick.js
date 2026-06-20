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

// CORE_POISONED_KEYS — the JavaScript-language prototype-pollution VECTORS: the
// property names that, used as an assignment target on a plain object, reach
// Object.prototype ("__proto__" directly; "constructor"."prototype"
// transitively). This is a LANGUAGE INVARIANT, not an operator policy and not
// an app-specific name like a table/column — "which keys pollute the JS
// prototype" is fixed by the runtime, so the core is a fixed list by design.
// It is also add-ONLY (below): removing any one would open a pollution hole, so
// the safe default can only ever get stricter, never weaker.
var CORE_POISONED_KEYS = ["__proto__", "constructor", "prototype"];
var POISONED_KEY_SET = new Set(CORE_POISONED_KEYS);

// registerPoisonedKeys(keys) — defense-in-depth EXTENSION hook (CWE-1321). An
// operator at boot, or a framework module, may ADD further dangerous property
// names to block everywhere isPoisonedKey is consulted — the accessor methods
// "__defineGetter__" / "__defineSetter__" / "__lookupGetter__" /
// "__lookupSetter__", or an app's own reserved keys. Add-ONLY by design: the
// core vectors can never be removed, so this knob can only tighten the
// framework-wide pollution defense, never weaken it.
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

// isPoisonedKey(key) — the framework's single prototype-pollution key predicate.
// Every parser, decoder, and middleware that builds an object from untrusted
// keys routes its guard through this, so the dangerous-key set lives in ONE
// place rather than being re-declared (a Set per file) or re-spelled (a literal
// `k === "__proto__" || k === "constructor" || k === "prototype"`) at each
// site — where one stale copy is a pollution hole. Consults the core vectors
// plus any operator-registered extensions. Non-string keys are never poisoned
// (a Map/Symbol key can't name an Object.prototype slot via assignment).
function isPoisonedKey(key) {
  return typeof key === "string" && POISONED_KEY_SET.has(key);
}

// assertSafeKey(key, onPoisoned) — throw-guard form for callers that REJECT a
// poisoned key (strict parsers, schema validators) rather than silently skip
// it. When key is poisoned, invokes onPoisoned(key) (the caller throws its own
// typed error from it) and returns the result; otherwise returns undefined.
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
  // Accept either ["a","b"] or [["nested",["sub1","sub2"]]] — return
  // a Map<key, allowList | true>.
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
// POISONED_KEYS — the frozen CORE vectors (a stable snapshot for callers that
// need the canonical list). The live predicate isPoisonedKey() also honors
// operator-registered extensions; this export is the immutable language core.
module.exports.POISONED_KEYS = Object.freeze(CORE_POISONED_KEYS.slice());
module.exports.isPoisonedKey = isPoisonedKey;
module.exports.assertSafeKey = assertSafeKey;
module.exports.registerPoisonedKeys = registerPoisonedKeys;

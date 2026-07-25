// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.safeObject
 * @nav        Validation
 * @title      Safe object access
 * @order      100
 *
 * @intro
 *   Prototype-pollution-safe own-property access. Interpolators, template
 *   engines, and structured readers that look up a key by name on an
 *   attacker-influenced object must treat an inherited / prototype-chain key
 *   (`__proto__`, `constructor`, `toString`) as ABSENT — never read it into
 *   rendered output. This composes that guard into one primitive so every
 *   consumer routes through the same hardened read instead of hand-rolling
 *   `Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined` (which a
 *   `__proto__` accessor property can still defeat).
 *
 * @card
 *   Prototype-pollution-safe own-property get/set — the single guard every
 *   interpolator composes.
 */

/**
 * @primitive  b.safeObject.ownProp
 * @signature  b.safeObject.ownProp(obj, key)
 * @since      0.17.13
 * @status     stable
 * @related    b.safeObject.ownSet
 *
 * Returns the value of `obj`'s OWN property `key`, or `undefined` when `key`
 * is not an own property (inherited / prototype-chain keys read as absent).
 * Uses `Object.getOwnPropertyDescriptor` rather than `hasOwnProperty` + index
 * read, so a `__proto__`-injected accessor property cannot run on read. A
 * defined-but-`undefined` own value returns `undefined` (callers treat that as
 * absent, matching the prior guarded reads).
 *
 * @example
 *   b.safeObject.ownProp({ a: 1 }, "a");          // → 1
 *   b.safeObject.ownProp({}, "toString");         // → undefined  (inherited)
 *   b.safeObject.ownProp({}, "__proto__");        // → undefined
 */
function ownProp(obj, key) {
  if (obj === null || obj === undefined) return undefined;
  var d = Object.getOwnPropertyDescriptor(obj, key);
  return d ? d.value : undefined;
}

/**
 * @primitive  b.safeObject.ownSet
 * @signature  b.safeObject.ownSet(obj, key, value)
 * @since      0.17.13
 * @status     stable
 * @related    b.safeObject.ownProp
 *
 * Sets `obj[key] = value` as a plain own data property via
 * `Object.defineProperty`, so a `__proto__` / `constructor` / accessor key on
 * the prototype chain cannot intercept the write or pollute the prototype.
 * Returns `obj`.
 *
 * @example
 *   var o = {};
 *   b.safeObject.ownSet(o, "__proto__", { polluted: 1 });
 *   ({}).polluted;   // → undefined  (Object.prototype not touched)
 */
function ownSet(obj, key, value) {
  Object.defineProperty(obj, key, {
    value:        value,
    writable:     true,
    enumerable:   true,
    configurable: true,
  });
  return obj;
}

module.exports = {
  ownProp: ownProp,
  ownSet:  ownSet,
};

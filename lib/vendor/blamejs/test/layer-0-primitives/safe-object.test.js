// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeObject — prototype-pollution-safe own-property access.
 */

var b = require("../..");
var helpers = require("../helpers");
var check = helpers.check;

function run() {
  var so = b.safeObject;
  check("b.safeObject.ownProp is a function", typeof so.ownProp === "function");
  check("b.safeObject.ownSet is a function",  typeof so.ownSet === "function");

  // own data property → value
  check("ownProp: own property returns value", so.ownProp({ a: 1 }, "a") === 1);
  check("ownProp: own property valued undefined returns undefined",
    so.ownProp({ a: undefined }, "a") === undefined);
  check("ownProp: missing own property returns undefined",
    so.ownProp({ a: 1 }, "b") === undefined);

  // inherited / prototype-chain keys read as ABSENT (the whole point)
  check("ownProp: inherited toString → undefined", so.ownProp({}, "toString") === undefined);
  check("ownProp: __proto__ → undefined",          so.ownProp({}, "__proto__") === undefined);
  check("ownProp: constructor → undefined",        so.ownProp({}, "constructor") === undefined);
  check("ownProp: valueOf → undefined",            so.ownProp({}, "valueOf") === undefined);

  // an own key SHADOWING an inherited name is returned (it's own)
  check("ownProp: own key shadowing an inherited name returns the own value",
    so.ownProp({ toString: 7 }, "toString") === 7);

  // a __proto__ accessor property cannot run on read (getOwnPropertyDescriptor,
  // not a bracket read)
  var trap = {};
  Object.defineProperty(trap, "x", { get: function () { throw new Error("getter ran"); }, configurable: true });
  var threw = false;
  try { so.ownProp(trap, "x"); } catch (_e) { threw = true; }
  check("ownProp: does not invoke an accessor getter on read", threw === false);

  // null / undefined receivers are tolerated
  check("ownProp: null receiver → undefined",      so.ownProp(null, "a") === undefined);
  check("ownProp: undefined receiver → undefined", so.ownProp(undefined, "a") === undefined);

  // ownSet writes a plain own data property; never pollutes the prototype
  var o = {};
  so.ownSet(o, "__proto__", { polluted: 1 });
  check("ownSet: __proto__ write does not pollute Object.prototype",
    ({}).polluted === undefined);
  check("ownSet: the value lands as an OWN property", so.ownProp(o, "__proto__") &&
    so.ownProp(o, "__proto__").polluted === 1);
  so.ownSet(o, "k", 5);
  check("ownSet: sets a normal own key", o.k === 5);

  console.log("[safe-object] OK");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); } catch (e) { console.error(e); process.exit(1); }
}

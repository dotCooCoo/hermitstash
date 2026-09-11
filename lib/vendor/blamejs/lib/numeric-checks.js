// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

function isPositiveInt(n) {
  return typeof n === "number" && isFinite(n) && n >= 1 && Math.floor(n) === n;
}

function isFiniteNonNegative(n) {
  return typeof n === "number" && isFinite(n) && n >= 0;
}

function isPositiveFinite(n) {
  return typeof n === "number" && isFinite(n) && n > 0;
}

module.exports = {
  isPositiveInt:        isPositiveInt,
  isFiniteNonNegative:  isFiniteNonNegative,
  isPositiveFinite:     isPositiveFinite,
};

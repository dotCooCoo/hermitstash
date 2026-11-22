// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// @internal -- no operator-facing namespace. Constructor and push options
// ('24h', '30m', '7d') are parsed here.
//
// duration -- parse a human duration into milliseconds.
//
// Accepted: a non-negative safe integer (already ms), <count><unit> with unit
// s / m / h / d, or null / undefined ("no duration"). Anything else is a
// config-time TypeError, so a mistyped TTL fails at boot rather than silently
// becoming "no expiry".

import { C } from "./constants.js";

const UNIT_MS = {
  s: C.TIME.SECOND,
  m: C.TIME.MINUTE,
  h: C.TIME.HOUR,
  d: C.TIME.DAY,
};

const DURATION_PATTERN = /^(\d+)(s|m|h|d)$/;

// @enforced-by raw-time-scale-literal
export function parse(value, label = "duration") {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") {
    // Safe integer, not merely finite: a fractional or over-range ms makes
    // expiresAt = createdAt + ms non-exact, which JSON then serializes as a lie.
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError(label + ": expected a non-negative integer number of milliseconds");
    }
    return value;
  }
  if (typeof value === "string") {
    const match = DURATION_PATTERN.exec(value);
    if (match === null) {
      throw new TypeError(label + ": expected a duration like '30m', '24h', or '7d'");
    }
    const ms = Number(match[1]) * UNIT_MS[match[2]];
    // The computed path holds the same exact-integer bound: an overflow would
    // silently change the configured terms.
    if (!Number.isSafeInteger(ms)) {
      throw new TypeError(label + ": duration overflows the exact millisecond range");
    }
    return ms;
  }
  throw new TypeError(label + ": expected a duration string, a number of milliseconds, or null");
}

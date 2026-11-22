// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// @internal -- no operator-facing namespace. Constructor byte bounds
// ('100mb', '1gb') are parsed here.
//
// size -- parse a human byte size into a count of bytes.
//
// Accepted: a non-negative safe integer (already bytes), <count><unit> with unit
// b / kb / mb / gb, or null / undefined ("no size"). Anything else is a
// config-time TypeError, so a mistyped bound fails at boot rather than silently
// disabling the limit.
//
// A sibling to duration.js, deliberately NOT an extension of it: the unit
// letters collide ('m' is minutes there, 'mb' is megabytes here), so one shared
// parser would make '100m' ambiguous.

import { C } from "./constants.js";

const UNIT_BYTES = {
  b: 1,
  kb: C.BYTES.KIB,
  mb: C.BYTES.MIB,
  gb: C.BYTES.GIB,
};

const SIZE_PATTERN = /^(\d+)(b|kb|mb|gb)$/;

// @enforced-by raw-time-scale-literal
export function parse(value, label = "size") {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") {
    // Safe integer, not merely finite: a fractional or over-range count cannot
    // be a real limit and would poison a `count > bound` compare.
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError(label + ": expected a non-negative integer number of bytes");
    }
    return value;
  }
  if (typeof value === "string") {
    const match = SIZE_PATTERN.exec(value);
    if (match === null) {
      throw new TypeError(label + ": expected a size like '64b', '512kb', '100mb', or '1gb'");
    }
    const bytes = Number(match[1]) * UNIT_BYTES[match[2]];
    // The computed path holds the same exact-integer bound: an overflow would
    // silently change the configured bound.
    if (!Number.isSafeInteger(bytes)) {
      throw new TypeError(label + ": size overflows the exact byte range");
    }
    return bytes;
  }
  throw new TypeError(label + ": expected a size string, a number of bytes, or null");
}

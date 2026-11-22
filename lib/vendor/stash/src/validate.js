// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// @internal -- no operator-facing namespace. The documented surface is the
// TypeError each public method throws at config time.
//
// validate -- config-time input-shape validation, defined ONCE.
//
// The policy layer names WHICH options a method accepts; this module owns HOW
// that is enforced, so the mechanics cannot drift apart across methods (an
// option whitelist one method forgets is a silent fail-open).

// @enforced-by validator-shape-reinlined
// @validator-shape expected a plain object
export function plainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(label + ": expected a plain object");
  }
  return value;
}

// spec.allowed: keys the method accepts today. spec.unimplemented: spec'd keys
// whose milestone has not shipped, each throwing rather than sitting silently
// unenforced.
// @enforced-by validator-shape-reinlined
// @validator-shape unknown option
export function options(opts, label, spec) {
  plainObject(opts, label);
  for (const key of spec.unimplemented || []) {
    if (key in opts) {
      throw new TypeError(
        label + ": option '" + key + "' is not implemented yet (SPEC.md 12 is the delivery plan)",
      );
    }
  }
  for (const key of Object.keys(opts)) {
    if (!spec.allowed.includes(key)) {
      throw new TypeError(label + ": unknown option '" + key + "'");
    }
  }
  return opts;
}

// A closed-enum option. The allowed tokens are configuration vocabulary, not
// capabilities, so echoing the permitted set is safe; the failing value is never
// quoted back.
// @enforced-by validator-shape-reinlined
// @validator-shape expected one of
export function oneOf(value, label, allowed) {
  if (!allowed.includes(value)) {
    throw new TypeError(
      label + ": expected one of " + allowed.map((a) => "'" + a + "'").join(", "),
    );
  }
  return value;
}

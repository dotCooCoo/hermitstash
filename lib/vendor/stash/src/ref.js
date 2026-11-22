// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// @internal -- no operator-facing namespace. The documented surface is the
// Stash methods that accept and return refs.
//
// ref -- generate, validate, and compare stash refs.
//
// A ref is a capability, not an address: 'v1_' + 32 random bytes as base64url
// (RFC 4648 section 5), 256 bits of CSPRNG entropy (CWE-330/CWE-340). It is
// never derived from content, because a content hash is an enumeration oracle.
//
// Refs become filenames in the disk backend, so validation here is the
// path-traversal defense (CWE-22/CWE-23, the Zip-Slip class): whitelist only,
// no normalization, no path.resolve rescue.

import { randomBytes, timingSafeEqual } from "node:crypto";

import { C } from "./constants.js";
import { InvalidRef } from "./errors.js";

// Written literally: the whitelist IS the guard, and deriving it would hide it.
// Pinned to C.REF by test.
const REF_PATTERN = /^v1_[A-Za-z0-9_-]{43}$/;

export function generate() {
  return C.REF.PREFIX + randomBytes(C.REF.RANDOM_BYTES).toString("base64url");
}

// Declared here and only here: a second declaration would be a second traversal
// surface to keep correct.
// @enforced-by guard-shape-reinlined
// @guard-shape v1_\[A-Za-z0-9_-\]
export function isValid(ref) {
  return typeof ref === "string" && REF_PATTERN.test(ref);
}

// Every public method routes its ref argument through here BEFORE any backend
// call.
// @enforced-by behavioral -- the reject-before-storage rule has no
//   rename-proof code shape of its own (the pattern shape is isValid's);
//   the zero-backend-calls conformance vector is the guard.
export function assertValid(ref) {
  if (!isValid(ref)) throw new InvalidRef();
  return ref;
}

// Timing-safe string equality for capability and digest comparison (CWE-208).
// Length is not secret; content is.
// @enforced-by guard-shape-reinlined
// @guard-shape \btimingSafeEqual\s*\(
export function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

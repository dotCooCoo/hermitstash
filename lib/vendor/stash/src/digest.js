// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// @internal -- no operator-facing namespace. Operators pick an algorithm
// through the `digest` constructor option; everything else composes this.
//
// digest -- the store's integrity hash. StashJS is crypto-agnostic for
// INTEGRITY, not confidentiality (SPEC.md 1 is untouched: still no key, no
// cipher). The digest verifies bytes read out are the bytes written in; it is
// never a lookup key (SPEC.md 5).
//
// The stored digest is SELF-DESCRIBING -- `"<algo>:<hex>"` -- so a read
// verifies with the algorithm the entry was WRITTEN with. One store may hold
// entries under different algorithms and each still verifies; the construct-time
// option sets the algorithm for NEW writes only.

import { createHash } from "node:crypto";

import { oneOf } from "./validate.js";

// The one algorithm table: pattern, validator, and factory all derive from it,
// so nothing else names an algorithm or a hex length. shake256 is an XOF whose
// length the algorithm does not fix, so it is PINNED here; unpinned, the stored
// hex length would be ambiguous. sha2 is FIPS 180-4; sha3 and shake are FIPS 202.
export const DIGESTS = Object.freeze({
  sha256: Object.freeze({ hash: "sha256", bytes: 32 }),
  sha512: Object.freeze({ hash: "sha512", bytes: 64 }),
  "sha3-256": Object.freeze({ hash: "sha3-256", bytes: 32 }),
  "sha3-512": Object.freeze({ hash: "sha3-512", bytes: 64 }),
  shake256: Object.freeze({
    hash: "shake256",
    bytes: 64,
    opts: Object.freeze({ outputLength: 64 }),
  }),
});

// The algorithm a push gets when `digest` is omitted. Because the stored digest
// is self-describing, changing this is safe for data already on disk: an entry
// written under an older default keeps its own prefix and still verifies with
// the algorithm it was written with. Only NEW entries take the new default, and
// a store may hold both.
//
// It costs throughput. SHA-3 has no hardware acceleration where SHA-2 does, so
// sha3-512 hashes at roughly a sixth of sha256's rate, and the store hashes
// every byte on the way in and again on every verified read. Operators who need
// the throughput back set `digest: 'sha256'` explicitly.
export const DEFAULT_DIGEST = "sha3-512";

// Caller has already validated `algo` (assertDigestAlgo at config time, or a
// stored digest's own prefix on the read path), so the row is always present.
export function digestHash(algo) {
  const d = DIGESTS[algo];
  return createHash(d.hash, d.opts);
}

// The one place the stored form is assembled, so write and read never disagree
// on the shape.
export function finalize(hash, algo) {
  return algo + ":" + hash.digest("hex");
}

// The pending digest `"<algo>:"`: algorithm chosen, hex not yet computed. A
// fresh push carries it so the algorithm travels INSIDE the documented
// `write(id, source, entry)` contract, rather than as an out-of-band argument a
// custom backend may not honor. Same colon shape as finalize(), so algoOf()
// parses both.
export function digestMarker(algo) {
  return algo + ":";
}

// The read-side shape gate (entry.js composes it for the Entry schema). A new
// DIGESTS row extends it with no edit here.
//
// The prefix is UNTRUSTED (a replicated entry, a disk sidecar), so membership is
// Object.hasOwn, never a bare `DIGESTS[prefix]` read: a prefix like "constructor"
// or "__proto__" resolves to an INHERITED Object.prototype member, and treating
// that non-undefined value as a registry hit reads an algorithm the store does
// not define (CWE-1321, prototype-key confusion).
export function isValidDigest(value) {
  if (typeof value !== "string") return false;
  const colon = value.indexOf(":");
  if (colon === -1) return false;
  const algo = value.slice(0, colon);
  if (!Object.hasOwn(DIGESTS, algo)) return false;
  const hex = value.slice(colon + 1);
  return hex.length === DIGESTS[algo].bytes * 2 && /^[0-9a-f]*$/.test(hex);
}

// Drives the SELF-DESCRIBING read: verify/audit hash with the entry's OWN
// algorithm. Resolves a hex-less `"<algo>:"` marker as well as a full stored
// digest, since only the prefix is consulted. Object.hasOwn for the CWE-1321
// reason above -- a phantom inherited name would defeat the write path's
// `algoOf(digest) ?? DEFAULT` fallback.
export function algoOf(stored) {
  if (typeof stored !== "string") return null;
  const colon = stored.indexOf(":");
  if (colon === -1) return null;
  const algo = stored.slice(0, colon);
  return Object.hasOwn(DIGESTS, algo) ? algo : null;
}

// Config-time validation of the `digest` option: a value outside the registry is
// a boot-time typo, not a runtime verdict. The closed-enum "expected one of"
// shape is owned by validate.oneOf, so this composes it.
export function assertDigestAlgo(value, label = "digest") {
  return oneOf(value, label, Object.keys(DIGESTS));
}

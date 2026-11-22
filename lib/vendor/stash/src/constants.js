// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
//
// @internal -- no operator-facing namespace. Operators pass human-readable
// forms ('24h', '100mb'); these are the scale facts they resolve through.
//
// constants -- the one home for scale and shape facts. Nothing else in src/
// multiplies its own time or byte literals (the raw-scale-literal detector
// enforces it). Frozen: a reassignable constant is a config surface nobody
// audits.

function deepFreeze(obj) {
  for (const value of Object.values(obj)) {
    if (value !== null && typeof value === "object") deepFreeze(value);
  }
  return Object.freeze(obj);
}

const TIME = {
  SECOND: 1000,
  MINUTE: 60 * 1000,
  HOUR: 60 * 60 * 1000,
  DAY: 24 * 60 * 60 * 1000,
  // The 2^31-1 ceiling Node's timers accept: a delay above it silently wraps to
  // ~1ms and fires in a busy loop, so a larger sweepInterval is a config error
  // rather than a rounding.
  MAX_TIMER_MS: 2_147_483_647,
};

export const C = deepFreeze({
  TIME,
  BYTES: {
    KIB: 1024,
    MIB: 1024 * 1024,
    GIB: 1024 * 1024 * 1024,
  },
  REF: {
    PREFIX: "v1_",
    RANDOM_BYTES: 32,
    // 32 bytes -> unpadded base64url
    ENCODED_LENGTH: 43,
  },
  AUDIT: {
    // A blobs/<id>.tmp younger than this is a push in flight, not a crash
    // orphan, so an audit racing a live writer cannot delete its half-written
    // blob (CWE-367). One aged past the grace is reported as orphan-tmp.
    TMP_GRACE_MS: TIME.HOUR,
  },
});

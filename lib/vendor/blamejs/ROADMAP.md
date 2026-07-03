# Roadmap

This is the high-level direction for blamejs over roughly the next year. It
describes intent, not a dated commitment; specifics land in
[CHANGELOG.md](CHANGELOG.md) as they ship and in the issue tracker as they are
scoped. The stability guarantees in [SECURITY.md](SECURITY.md) and the support
windows in [LTS-CALENDAR.md](LTS-CALENDAR.md) govern anything below.

## Direction

- **Toward 1.0 — API stabilization.** Continue hardening the public surface
  toward a 1.0 that carries a stable-upgrade guarantee. Until 1.0, minors remain
  additive and deprecations ship at least one minor before removal; breaking
  changes are batched into a major with a prior deprecation minor.
- **Continuous security hardening.** The ongoing correctness-and-hardening pass
  over every primitive continues as the primary cadence — each release closes
  audited gaps with a reproducing test and, where structural, a codebase-pattern
  detector. Findings from CodeQL, OpenSSF Scorecard, ClusterFuzzLite fuzzing, and
  coordinated disclosure are folded in on the timelines in SECURITY.md.
- **Post-quantum completion.** Keep the crypto stack PQC-first (ML-KEM, ML-DSA,
  SLH-DSA, XChaCha20-Poly1305, SHAKE256/SHA3, HKDF-SHA3, Argon2id). Track the
  NIST/IETF PQC standards surface and adopt native platform PQC where it reaches
  proven byte-parity with the vendored implementations without breaking existing
  key material.
- **Node LTS tracking.** Raise the minimum engine as Node LTS lines advance
  (currently `>=24.18`), adopting stabilized platform capabilities (native PQC,
  `node:sqlite`, native WebSocket) only when they reach parity with what the
  framework already ships and without regressing the security defaults.
- **Supply-chain assurance.** Maintain SLSA L3 provenance, Sigstore-signed SBOMs,
  SSH-signed releases, pinned CI actions and Docker digests, and the vendored
  dependency review discipline. Keep the OpenSSF Scorecard and Best Practices
  posture current.

## Explicitly out of scope

- **Classical-only cryptographic defaults** (no AES-GCM / SHA-256 / P-256-ECDH
  as defaults; PQC-first only).
- **npm runtime dependencies** (everything ships vendored under `lib/vendor/`;
  the runtime dependency count stays zero).
- **A build/transpile step for the framework itself** (it runs on Node LTS
  as-shipped; CommonJS, no TypeScript).
- **Silent breaking changes in a minor** (the stable-upgrade policy is a hard
  constraint, not an aspiration).
- **Opt-in security** (CSRF / origin / bot-guard / sealed storage / encrypted
  session / fetch-metadata / cookie prefixes / DoH / Trusted Types stay wired
  into the request lifecycle by default, never behind flags).

## How to influence it

Open an issue or a pull request. Security-sensitive direction is best raised
privately first per the process in [SECURITY.md](SECURITY.md).

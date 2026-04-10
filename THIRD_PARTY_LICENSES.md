# Third-Party Licenses

HermitStash vendors all runtime dependencies directly in the repository
(zero npm packages at runtime). This file documents each vendored package,
its license, and copyright holder to comply with attribution requirements.

See `lib/vendor/MANIFEST.json` for versions and build details.

---

## @noble/ciphers v2.1.1

- **License:** MIT
- **Copyright:** (c) 2023 Paul Miller (paulmillr.com)
- **Source:** https://github.com/paulmillr/noble-ciphers
- **Files:** `lib/vendor/noble-ciphers.cjs`, `public/js/noble-ciphers.js`
- **Used for:** XChaCha20-Poly1305 symmetric encryption

## @noble/hashes v2.0.1

- **License:** MIT
- **Copyright:** (c) 2022 Paul Miller (paulmillr.com)
- **Source:** https://github.com/paulmillr/noble-hashes
- **Files:** `public/js/noble-hashes.js`
- **Used for:** SHAKE256 (FIPS 202 XOF) in browser

## @noble/post-quantum v0.6.0

- **License:** MIT
- **Copyright:** (c) 2024 Paul Miller (paulmillr.com)
- **Source:** https://github.com/paulmillr/noble-post-quantum
- **Files:** `public/js/noble-pq.js`
- **Used for:** ML-KEM-512/768/1024 (FIPS 203) key encapsulation in browser

## @simplewebauthn/server v13.3.0

- **License:** MIT
- **Copyright:** (c) Matthew Miller
- **Source:** https://github.com/MasterKale/SimpleWebAuthn
- **Files:** `lib/vendor/simplewebauthn-server.cjs`
- **Used for:** WebAuthn/passkey registration and authentication
- **Bundled dependencies (included in the .cjs file):**
  - `asn1js` — BSD-3-Clause, (c) 2014-2024 Peculiar Ventures, LLC / GMO GlobalSign
  - `@peculiar/x509`, `pvutils` — MIT, (c) Peculiar Ventures, LLC
  - `tslib` — Apache-2.0, (c) Microsoft Corporation
  - `cbor-x` — MIT

## argon2 v0.44.0

- **License:** MIT
- **Copyright:** (c) Ranieri Althoff
- **Source:** https://github.com/ranisalt/node-argon2
- **Files:** `lib/vendor/argon2/argon2.cjs`, `lib/vendor/argon2/prebuilds/*`
- **Used for:** Argon2id password hashing
- **Bundled dependencies (included in the .cjs file):**
  - `@phc/format` — MIT

---

All vendored packages are bundled with esbuild to eliminate npm runtime
dependencies and supply chain risk. Original source repositories are
linked above for license verification.

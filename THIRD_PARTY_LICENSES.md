# Third-Party Licenses

HermitStash vendors all runtime dependencies directly in the repository
(zero npm packages at runtime). The server-side dependencies are vendored as
a single framework — blamejs — which bundles the nested crypto/identity
packages listed below; the browser bundles ship individually under
`public/js/`. This file documents each vendored package, its license, and
copyright holder to comply with attribution requirements.

See `lib/vendor/MANIFEST.json` for versions and build details.

---

## blamejs v0.14.6

- **License:** Apache-2.0
- **Copyright:** blamejs contributors
- **Source:** https://github.com/blamejs/blamejs
- **Files:** `lib/vendor/blamejs/` (full source tree)
- **Used for:** Server-side framework — crypto, vault, identity, middleware,
  envelope versioning, audit chain
- **Bundled packages (vendored under `lib/vendor/blamejs/lib/vendor/`):** see
  the `@noble/ciphers`, `@noble/post-quantum`, `@simplewebauthn/server`,
  `@peculiar/x509` + `pkijs`, and SecLists entries below.

## @noble/ciphers v2.2.0

- **License:** MIT
- **Copyright:** (c) 2023 Paul Miller (paulmillr.com)
- **Source:** https://github.com/paulmillr/noble-ciphers
- **Files:** `lib/vendor/blamejs/lib/vendor/noble-ciphers.cjs` (server, via blamejs), `public/js/noble-ciphers.js` (browser)
- **Used for:** XChaCha20-Poly1305 symmetric encryption

## @noble/hashes v2.2.0

- **License:** MIT
- **Copyright:** (c) 2022 Paul Miller (paulmillr.com)
- **Source:** https://github.com/paulmillr/noble-hashes
- **Files:** `public/js/noble-hashes.js`
- **Used for:** SHAKE256 (FIPS 202 XOF) in browser

## @noble/post-quantum v0.6.1

- **License:** MIT
- **Copyright:** (c) 2024 Paul Miller (paulmillr.com)
- **Source:** https://github.com/paulmillr/noble-post-quantum
- **Files:** `lib/vendor/blamejs/lib/vendor/noble-post-quantum.cjs` (server), `public/js/noble-pq.js` (browser)
- **Used for:** Server — ML-KEM-1024 (FIPS 203) key encapsulation plus the
  post-quantum signature algorithms ML-DSA-87 (FIPS 204) and
  SLH-DSA-SHAKE-256f / SLH-DSA-SHA2-256f (FIPS 205). Browser —
  ML-KEM-512/768/1024 (FIPS 203) key encapsulation only.

## @simplewebauthn/server v13.3.0

- **License:** MIT
- **Copyright:** (c) Matthew Miller
- **Source:** https://github.com/MasterKale/SimpleWebAuthn
- **Files:** `lib/vendor/blamejs/lib/vendor/simplewebauthn-server.cjs`
- **Used for:** WebAuthn/passkey registration and authentication
- **Bundled dependencies (included in the .cjs file):**
  - `asn1js` — BSD-3-Clause, (c) 2014-2024 Peculiar Ventures, LLC / GMO GlobalSign
  - `@peculiar/x509`, `pvutils` — MIT, (c) Peculiar Ventures, LLC
  - `tslib` — Apache-2.0, (c) Microsoft Corporation
  - `cbor-x` — MIT

## @peculiar/x509 v2.0.0 + pkijs v3.4.0 (peculiar-pki bundle)

- **License:** MIT
- **Copyright:** (c) Peculiar Ventures, LLC
- **Source:** https://github.com/PeculiarVentures
- **Files:** `lib/vendor/blamejs/lib/vendor/pki.cjs`
- **Used for:** Pure-JS mTLS CA + PKCS#12 issuance (no openssl CLI at runtime)
- **Bundled includes:** `reflect-metadata`, `pvutils`, `pvtsutils`, `asn1js`,
  `@peculiar/asn1-schema`, `@peculiar/asn1-x509`, `@peculiar/asn1-ecc`,
  `@peculiar/asn1-rsa`, `@peculiar/asn1-cms`, `@peculiar/asn1-pkcs9`

## SecLists — common-passwords-top-10000

- **License:** CC-BY-3.0 (attribution required)
- **Copyright:** Daniel Miessler / SecLists contributors
- **Source:** https://github.com/danielmiessler/SecLists
- **Files:** `lib/vendor/blamejs/lib/vendor/common-passwords-top-10000.txt`
- **Used for:** Breached/common-password rejection during password validation

Argon2id password hashing uses Node 24+'s built-in `crypto.argon2` (via
blamejs's `lib/argon2-builtin.js` wrapper) — a platform primitive, not a
third-party package, so there is nothing to attribute.

---

The blamejs framework is vendored as a full source tree (shallow git clone of
a release tag). The browser `public/js/noble-*` bundles and the nested
`.cjs` files under `lib/vendor/blamejs/lib/vendor/` are bundled with esbuild
to eliminate npm runtime dependencies and supply chain risk. Original source
repositories are linked above for license verification.

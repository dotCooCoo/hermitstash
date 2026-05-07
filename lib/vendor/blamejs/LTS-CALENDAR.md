# LTS calendar

`@blamejs/core` ships on a published major cadence. Each major receives
**18 months of security-only patches** starting the day the next major is
published. Feature backports are not promised.

| Version       | First release | Security patches through    | Node minimum  | KEM                  | Cipher                | KDF      | Sigs                  |
|---------------|---------------|-----------------------------|---------------|----------------------|-----------------------|----------|-----------------------|
| `v0.x` (pre-1.0) | 2026-04-25  | until v1.0 ships            | 24            | ML-KEM-1024 + P-384  | XChaCha20-Poly1305    | SHAKE256 | SLH-DSA-SHAKE-256f    |
| `v1.x`        | TBD           | first release + 18 months   | current LTS   | ML-KEM-1024 + P-384  | XChaCha20-Poly1305    | SHAKE256 | SLH-DSA-SHAKE-256f    |

## What "security patches" means

- Critical and high-severity vulnerabilities in the framework's own code.
- Vendored-dep CVE refreshes (the SECURITY.md commitment of "vendored-dep refresh release within 7 days of an upstream patch landing for High / Critical CVEs" applies on the LTS line too).
- Crypto envelope updates required by NIST / IETF deprecations of the active KEM / Cipher / KDF / Sig algorithms.
- **Not** included: feature backports, performance improvements, or non-security bug fixes. Operators who want those upgrade to the current major.

## Algorithm posture

The KEM / Cipher / KDF / Sig columns list the active envelope IDs for **new** encryptions on that major. Old data encrypted under prior majors continues to decrypt unchanged via the algorithm-ID-in-envelope-header pattern (see [SECURITY.md → Cryptographic stack](SECURITY.md#cryptographic-stack)). When an algorithm is added or deprecated, the change ships as a minor on the current major and the LTS row is updated in the same commit.

## Node minimum policy

The "Node minimum" column is the lowest Node major the framework supports for that line. It tracks Node's own active-LTS schedule: a new blamejs major adopts whatever Node major is currently the active LTS. Once on the LTS line, the Node minimum is frozen for that major's security-patch window — operators on the LTS line don't get forced onto a newer Node mid-window.

## Pre-1.0 caveat

`v0.x` has no LTS commitment. Every release may change something operators depend on; the algorithm posture is intentionally evolving. Read [CHANGELOG.md](CHANGELOG.md) before upgrading across more than a few patches at a time. The LTS calendar takes effect at v1.0.

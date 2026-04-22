# HermitStash — Cryptographic Design & Threat Model

**Status:** Draft, unaudited. Last updated against v1.8.25 source.

This document describes the cryptographic constructions HermitStash uses, the threats they are intended to defend against, and the limits of what that protection actually means. It is written for security reviewers, cryptographers willing to spend 30 minutes poking holes, and self-hosted operators who want to understand what they are trusting.

Every protocol detail here is cross-referenced to a specific file and line in the codebase. If you find a discrepancy between this document and the code, **the code is ground truth** — please open an issue.

The project maintainer is not a cryptographer. This design takes well-reviewed primitives (ML-KEM-1024, XChaCha20-Poly1305, Argon2id, SHAKE256, ECDH P-384) and composes them. The risk surface is in the *composition*, which has not been independently reviewed. This document exists so that review becomes possible.

---

## 1. Security goals

HermitStash is designed to defend the following properties against the adversary models in §3:

| # | Goal | Meaning |
|---|------|---------|
| G1 | **Confidentiality of data at rest** | An attacker with a snapshot of the `data/` directory and `uploads/` directory, **without** the vault key file, cannot recover any user-visible data: file contents, filenames, emails, audit logs, session state, or settings |
| G2 | **Confidentiality of data in transit** | A passive network attacker cannot read API payloads, file contents, or session cookies |
| G3 | **Integrity of encrypted data** | An attacker who modifies on-disk or in-transit ciphertext cannot make the modified plaintext parse successfully; tampering is detected |
| G4 | **Post-quantum resistance for "harvest-now-decrypt-later"** | A passive network attacker capturing today's traffic cannot decrypt it with a large quantum computer in the future |
| G5 | **Zero-knowledge for vault files** | Files in the user-initiated "personal vault" are encrypted client-side with a key derived from the user's passkey; the server never sees the plaintext or the key material, even in memory |
| G6 | **Authentication of API requests** | An attacker without a valid API key cannot issue API calls that the server accepts |
| G7 | **Authentication of sync clients** | Sync clients are required to present an mTLS client certificate issued by the server's internal CA; API-key-only sync upgrades are off by default |
| G8 | **Authenticity of webhook deliveries** | Webhook receivers can verify that a payload was produced by HermitStash using a shared HMAC secret |
| G9 | **Replay resistance for API payloads** | An attacker recording a valid encrypted API request cannot resubmit it outside a narrow time window |
| G10 | **PQC TLS transport** | Direct-TLS deployments (no reverse proxy) reject TLS connections that don't offer a post-quantum hybrid group at the ClientHello level |

---

## 2. Non-goals

These are properties HermitStash does **not** claim to provide. Several of them are common assumptions and they are listed explicitly so reviewers don't assume protections that aren't there.

| # | Non-goal | Why |
|---|----------|-----|
| N1 | **Defense against a compromised host OS** | The server process needs to read plaintext vault keys to function. Any attacker with root on the host can read `data/vault.key` and recover everything. This is a fundamental constraint of at-rest encryption for a running service |
| N2 | **Defense against a malicious operator** | The operator has the vault key by definition. HermitStash is self-hosted; the trust root is the person running the server |
| N3 | **Forward secrecy for stored data** | Compromise of `data/vault.key` decrypts every historical database field, every historical file, every historical session. The vault key is long-lived; there is no per-session re-keying of at-rest data |
| N4 | **Forward secrecy for session cookies** | Session cookies are sealed with the long-lived vault key, not an ephemeral per-session key. A later vault-key compromise retroactively decrypts captured cookies |
| N5 | **Cryptographic side-channel resistance** | HermitStash runs on V8 JavaScript. Constant-time properties are inherited from the underlying primitives (node:crypto's OpenSSL-backed operations, @noble/ciphers, @noble/post-quantum). Application-level timing leaks from non-crypto code paths are not analyzed or hardened |
| N6 | **Resistance to traffic analysis** | File sizes, upload timing, and response sizes leak information that could be used to fingerprint user behavior. HermitStash does not pad or obfuscate |
| N7 | **Metadata minimization at the HTTP layer** | IP addresses reach the server and are SHA3-hashed-then-sealed in audit logs. The hash is salted with a static prefix (`hs-ip:`), not a per-record salt — an attacker with the vault key can still correlate audit entries by hashed IP. IP enumeration by an attacker with the key is trivial |
| N8 | **Defense against a compromised public CA** | Server TLS certificates are typically Let's Encrypt-issued and validated by the browser's CA store. A compromised or coerced public CA can issue a fraudulent cert. HermitStash does not pin certificates |
| N9 | **Formal verification of protocol compositions** | Nothing in this project has been formally modeled (ProVerif, Tamarin, Cryptol). Composition correctness relies on reasoning, review, and primitive-level soundness |
| N10 | **Hardware-backed key storage on the server** | The vault key is a JSON file on the filesystem. No HSM, no TPM sealing, no enclave |
| N11 | **Defense against first-run credential interception** | On first boot the server prints a randomly-generated admin password to stdout and writes it to `data/initial-admin-password.txt` (mode 0600). An attacker who can read logs or filesystem before the operator logs in can capture it |
| N12 | **Perfect denial-of-service protection** | Rate limiting and request fingerprinting (bot guard) are implemented, but a determined attacker with adequate bandwidth can still disrupt availability |

---

## 3. Adversary model

HermitStash assumes four adversary classes, listed from weakest to strongest. Defenses are designed against the first three; the fourth is explicitly out of scope.

### 3.1 Passive network attacker
Observes all traffic between client and server. Cannot inject, modify, or drop packets.

**Defended against:** G1, G2, G4, G10.

### 3.2 Active network attacker (MITM)
Can inject, modify, drop, and replay packets. Cannot compromise TLS or the underlying primitives.

**Defended against:** G2, G3, G6, G7, G9, G10.

### 3.3 Storage-only attacker (cold)
Obtains a one-time snapshot of `data/` and `uploads/` (for example, a stolen backup or disk image), **but does not have `data/vault.key`**. Does not have ongoing filesystem access.

**Defended against:** G1, G3.

### 3.4 Compromised host (explicitly out of scope)
Has arbitrary read access to the running process's memory, filesystem, or environment variables. HermitStash provides no meaningful defense against this — see N1, N2.

### 3.5 Harvest-now-decrypt-later
A variant of 3.1 that retains captured traffic indefinitely and is assumed to have access to a cryptographically relevant quantum computer at some future date.

**Defended against:** G4. This is the primary motivation for using ML-KEM-1024 + ECDH P-384 hybrid key exchange everywhere classical key exchange would otherwise live.

---

## 4. Cryptographic primitives

All primitives are sourced from vendored libraries — zero npm runtime dependencies. See `lib/vendor/MANIFEST.json` for exact versions.

| Primitive | Algorithm | Source | Rationale |
|-----------|-----------|--------|-----------|
| KEM (post-quantum) | ML-KEM-1024 | `node:crypto` (OpenSSL 3.5+) | NIST FIPS 203. Level 5 parameters (highest available). Level 5 chosen over 768/Level 3 because the performance cost is acceptable for the low request volume of a self-hosted server and the security margin is preferred |
| KEM (classical) | ECDH on NIST P-384 | `node:crypto` | FIPS-approved curve. P-384 over P-256 for 192-bit classical security matching ML-KEM-1024's post-quantum level. X25519 was considered but rejected so that node:crypto's single ECDH path can be used on both the server and in mTLS certificates (P-384 signatures) without two ECC stacks |
| Symmetric AEAD | XChaCha20-Poly1305 | `@noble/ciphers` 2.1.1 | RFC 8439 extended. 192-bit nonce (vs 96-bit for plain ChaCha20-Poly1305) allows random nonces without birthday risk. Constant-time in software, no AES-NI dependency |
| KDF / XOF | SHAKE256 | `node:crypto` (server), `@noble/hashes` 2.0.1 (browser) | FIPS 202. Chosen over HKDF-SHA3 for the storage envelope because it is a single-call extendable-output function with no salt/info complexity — the inputs are already high-entropy KEM shared secrets. HKDF-SHA3-512 is still used inside the hybrid ECIES path where domain separation is needed (see §5.6) |
| Hash | SHA3-512 | `node:crypto` | FIPS 202. Truncated when shorter outputs are needed. SHA-256 was rejected in favor of a SHA-3 family member to avoid length-extension concerns even where they don't technically apply |
| HMAC | HMAC-SHA3-512 | `node:crypto` | FIPS 198-1 over FIPS 202. Used for webhook signatures |
| Password hash | Argon2id | `argon2` 0.44.0 (vendored native) | RFC 9106. Memory-hard. Default parameters: 64 MiB memory, 3 time cost, 4 parallelism. `ARGON2_FAST=1` env flag switches to 1 MiB / 1 / 1 for automated test runs only |
| Signatures | ML-DSA-87 / SLH-DSA-SHAKE-256f | `node:crypto` (OpenSSL 3.5+) | FIPS 204 / 205. Auto-detected from key PEM. Used for signing vendored assets and release verification — not yet used for mTLS certificates (see §5.8) |
| RNG | SHA3-512(node.randomBytes) | `node:crypto` wrapper in `lib/crypto.js:47` | A belt-and-suspenders wrapper hashes `crypto.randomBytes(n)` through SHA3-512 before returning the first `n` bytes. See §9 for the rationale and the associated limitation |

Vendored third-party libraries:
- **@noble/ciphers** (Paul Miller) — XChaCha20-Poly1305, server + browser
- **@noble/hashes** (Paul Miller) — SHAKE256 for the browser (server uses node:crypto)
- **@noble/post-quantum** (Paul Miller) — ML-KEM-1024 for the browser; the server uses node:crypto
- **@peculiar/x509 + pkijs** — pure-JS PKCS#12 generation for browser certificate issuance
- **argon2** — native Node binding with prebuilds for 8 platforms

---

## 5. Protocols

Each subsection describes one cryptographic construction. Code references are to v1.8.25.

### 5.1 Storage envelope format

Every at-rest encrypted blob the server produces starts with a 4-byte header that identifies which algorithms were used. This is what makes algorithm agility possible — any component can be swapped and old blobs remain readable.

Code: `lib/crypto.js:117-150` (encrypt), `lib/crypto.js:154-191` (decrypt).

**Layout:**

```
Offset  Field                        Size    Value
──────  ─────────────────────────    ────    ─────
0       Magic                        1       0xE1
1       KEM ID                       1       0x02 ML-KEM-1024, 0x03 hybrid ML-KEM-1024+P-384
2       Cipher ID                    1       0x02 XChaCha20-Poly1305
3       KDF ID                       1       0x02 SHAKE256
4       KEM ciphertext length        2       uint16 BE
6       KEM ciphertext                       1088 bytes for ML-KEM-1024
6+N     [if hybrid] ECDH pub length  2       uint16 BE
 ...    [if hybrid] ECDH ephemeral pub       SPKI DER of P-384 point
 ...    XChaCha20 nonce              24      random
 ...    XChaCha20-Poly1305 ciphertext        Variable + 16-byte tag
```

**Encrypt (hybrid, default path):**

```
                ┌────────────────────────────────────────────────┐
                │ Recipient public key: (mlkem_pk, p384_pk)      │
                └────────────────────────────────────────────────┘
                            │                          │
             ML-KEM-1024    │                          │   P-384 ECDH
             encapsulate    ▼                          ▼   ephemeral
                    ┌─────────────┐             ┌──────────────┐
                    │ kem.ss_1    │             │ ecdh.ss_2    │
                    │ 32 bytes    │             │ 48 bytes     │
                    │ + kem.ct    │             │ + eph_pub    │
                    └──────┬──────┘             └──────┬───────┘
                           │                           │
                           └──────────┬────────────────┘
                                      │ concat (no domain separator)
                                      ▼
                            ┌──────────────────┐
                            │ SHAKE256(ss1||ss2,│
                            │ 32 bytes)         │ ◄── symmetric key
                            └──────────┬───────┘
                                       │
                          random 24-byte nonce ─┐
                                       │        │
                                       ▼        ▼
                            ┌──────────────────┐
                            │ XChaCha20-Poly1305│
                            │ (key, nonce, pt) │
                            └──────────┬───────┘
                                       │
                                       ▼
                      [magic|kem|cipher|kdf|kem.ct|eph_pub|nonce|ct+tag]
```

**Decrypt:** dispatches on byte 1 (KEM ID). The hybrid path decapsulates ML-KEM, runs ECDH against the embedded ephemeral public key, concatenates, SHAKE256s, and decrypts. The ML-KEM-only path skips the ECDH leg.

**Notes for reviewers:**
- The two shared secrets are concatenated without a domain separator before the KDF (`lib/crypto.js:126`). The inputs come from domain-separated sources (ML-KEM encapsulate output vs ECDH derived key), so first-image resistance isn't formally at risk, but this is worth a look — a reviewer might prefer HKDF with a fixed `info` string here to match the ECIES path in §5.6
- The envelope header bytes are **not authenticated** as AAD. An attacker can flip the KEM/cipher/KDF byte on a ciphertext; if the victim supports multiple decryption paths this could cross-wire them. Today only one cipher and one KDF are supported so the attack surface is nil in practice, but this will matter if a new cipher is added. See §10

### 5.2 Vault — long-lived at-rest key

File: `data/vault.key`. Format: plaintext JSON, `{ publicKey, privateKey, ecPublicKey, ecPrivateKey }`, all PEM-encoded. File mode: `0o600`.

Code: `lib/vault.js`.

The vault key is the root of at-rest encryption. On first boot the server generates:
- ML-KEM-1024 keypair via `node:crypto.generateKeyPairSync("ml-kem-1024")`
- P-384 ECDH keypair via `node:crypto.generateKeyPairSync("ec", { namedCurve: "P-384" })`

`vault.seal(plaintext)` prepends a `vault:` prefix and calls `crypto.encrypt(plaintext, vaultKeys)`, which produces the envelope format from §5.1. `vault.unseal(value)` strips the prefix and inverts.

**Diagram — key hierarchy:**

```
     data/vault.key  (ML-KEM-1024 priv + P-384 priv, plaintext JSON, 0o600)
          │
          │  vault.seal() / vault.unseal()
          │
          ├─► Every database field via field-crypto (§5.3)
          ├─► Session cookie values (§5.5)
          ├─► File encryption keys — wraps per-file random XChaCha20 keys (§5.4)
          ├─► DB file encryption key — wraps the at-rest DB key (see data/db.key.enc)
          └─► Session API encryption keys — wraps per-session XChaCha20 keys (§5.6)
```

**Critical limitation:** Anyone with read access to `data/vault.key` decrypts everything HermitStash has ever stored. This is the largest gap in the default configuration.

**Optional mitigation (v1.9+) — passphrase wrapping.** When `VAULT_PASSPHRASE_MODE=required`, the on-disk file is `data/vault.key.sealed` instead of plaintext `data/vault.key`. Format: 4-byte magic `0xE2` header (see `lib/vault-wrap.js`), Argon2id-derived wrapping key (64 MiB, 3 iterations, 4 parallelism by default), XChaCha20-Poly1305 AEAD with the full header bound as AAD. An attacker with the wrapped file but not the passphrase cannot recover the vault keys. The passphrase is read at boot from one of: `VAULT_PASSPHRASE` env, `VAULT_PASSPHRASE_FILE`, or interactive stdin. This protection addresses the disk-snapshot threat scenarios (N1 listed host compromise is explicitly out of scope — once unwrapped, the plaintext key lives in process memory and is recoverable by any attacker with code execution). See §9 L2 and L15, and the README's "Passphrase protection" section for operator UX.

### 5.3 Field encryption (field-crypto middleware)

Every database field that isn't a raw identifier, counter, or timestamp goes through `vault.seal()` on write and `vault.unseal()` on read, transparently, via a middleware layer around the SQLite wrapper.

Code: `lib/field-crypto.js` (240 lines), `FIELD_SCHEMA` constant.

Each table's fields are classified as:
- **seal** — encrypted per-field via `vault.seal()`. Values stored as `vault:<base64>`
- **hash** — one-way SHA3 hashed for indexed lookups (emails, IP addresses)
- **derived** — auto-computed from another field (e.g. `emailHash` from `email`)
- **raw** — plaintext (IDs, counters, status enums, FK references, timestamps)

The middleware also rewrites queries: `{ email: "x@y.com" }` becomes `{ emailHash: sha3("hs-email:x@y.com") }` transparently so callers use plaintext lookups.

**Security notes:**
- Hash prefixes (`hs-email:`, `hs-ip:`, `hs-share:`, `hs-certfp:`, `hs-slug:`, `hs-access-code:`, `hs-enroll:`, `hs-blockedip:` — full list in `lib/constants.js:38-47`) are static strings. An attacker with vault-decrypted audit log entries can still cross-reference by hash — this is intentional for functionality (indexed lookup) but means the hashes are **not** an anonymization primitive, only a key-separation primitive. See N7
- Every envelope blob for field encryption has a fresh 24-byte nonce. No nonce reuse across fields

### 5.4 File encryption at rest

Each uploaded file gets a fresh 32-byte XChaCha20-Poly1305 key. That per-file key is sealed with the vault (§5.2) and stored in the `files.encryptionKey` column.

Code: `lib/storage.js:41-50`, using `crypto.encryptPacked()` / `decryptPacked()` from `lib/crypto.js:195-204`.

**"Packed" format (different from the storage envelope):**

```
Offset  Field             Size    Value
──────  ──────────────    ────    ─────
0       Version           1       0x02 (XChaCha20-Poly1305)
1       Nonce             24      random
25      Ciphertext+tag            file + Poly1305 tag
```

The packed format does not carry KEM information because there is no key exchange at the file level — the key is wrapped by the vault and stored alongside the file record. On read, the key is unsealed, the file is decrypted, and the plaintext is streamed to the caller.

### 5.5 Session cookies

Session cookies are opaque random 256-bit IDs (`hs_sid` cookie). The session **data** (user ID, role, TOTP state, cert fingerprint) is stored server-side in SQLite on tmpfs and each row's `data` column is vault-sealed.

Code: `lib/session.js`.

Notes:
- The cookie itself is just an ID, not an encrypted token. Stealing the cookie = session hijack (until the session expires or is invalidated)
- Session store lives on tmpfs (`/dev/shm` by default) so sessions are ephemeral across restarts — N4 applies: no forward secrecy, but also nothing to forward-compromise once the host restarts
- Session rows are sealed per-row with fresh nonces via the standard envelope (§5.1)

### 5.6 API payload encryption + hybrid ECIES handshake

Every JSON POST body and every JSON response body is encrypted with XChaCha20-Poly1305 using a **per-session symmetric key**, separate from the vault key.

Code: `middleware/api-encrypt.js`, `lib/api-crypto.js`.

#### 5.6.1 Session key generation

First request per session:
1. Server generates `apiKey = random(32)` as base64url
2. Server stores `apiKey` in `session.apiKey` via `vault.seal()`
3. Subsequent calls unseal it for the request's lifetime

Delivery of `apiKey` to the client depends on client type:
- **Browsers:** the server embeds the apiKey in the response HTML template (`res._apiKey` → template placeholder). No separate key exchange — the browser is already authenticated by the session cookie over TLS
- **Sync clients (mTLS):** the hybrid ECIES handshake below

#### 5.6.2 Hybrid ECIES handshake (mTLS clients)

The concern this solves: a sync client connecting with an API key needs the session XChaCha20 key, and we don't want to send it in plaintext over the wire (even under TLS) in case of future log/trace/proxy leaks.

On the **first** response to a client that:
1. Presented a valid mTLS certificate (source of the P-384 leg), **and**
2. Sent its ML-KEM-1024 public key in the `X-KEM-Public-Key` header (source of the PQC leg)

The server:

```
                 ┌─────────────────────────────────────────────┐
                 │ Client presents:                            │
                 │  - mTLS cert (P-384 pub key on cert)        │
                 │  - X-KEM-Public-Key header (ML-KEM-1024 pub)│
                 └─────────────────────────────────────────────┘
                           │                           │
                           │ ML-KEM-1024               │ generate ephemeral
                           │ encapsulate               │ P-384 keypair, do ECDH
                           ▼                           ▼
                 ┌─────────────────┐          ┌──────────────────┐
                 │ kem.ss (32 B)   │          │ ecdh.ss (48 B)   │
                 │ + kem.ct (1088) │          │ + eph.pub (SPKI) │
                 └────────┬────────┘          └────────┬─────────┘
                          │                            │
                          └──────────────┬─────────────┘
                                         │ concat
                                         ▼
                              ┌───────────────────────────────┐
                              │ HKDF-SHA3-512(                │
                              │   ikm = ss1 || ss2,           │
                              │   salt = "",                  │
                              │   info = "hermitstash-        │
                              │           hybrid-ecies-v1",   │
                              │   length = 32)                │
                              └──────────────┬────────────────┘
                                             │ wrapping key
                                             ▼
                                   random 24-byte nonce ─┐
                                             │           │
                                             ▼           ▼
                              ┌───────────────────────────────┐
                              │ XChaCha20-Poly1305(           │
                              │   key = wrapping_key,         │
                              │   nonce, session_api_key)     │
                              └──────────────┬────────────────┘
                                             │
                                             ▼
                    response JSON { _e, _t, _ek, _epk, _kem }

                _ek = [version(1) | nonce(24) | ct+tag]  ML-KEM-wrapped api key
                _epk = server's ephemeral P-384 public key (SPKI DER, base64url)
                _kem = ML-KEM encapsulation ciphertext (base64url)
```

`_ek` starts with a 1-byte protocol version (currently `0x01`) so future KEMs (HQC, classic McEliece) can be added without ambiguity. The client:
1. Decapsulates `_kem` with its ML-KEM-1024 private key → `ss1`
2. ECDHs its P-384 private key (from its mTLS cert) with the server's ephemeral public key `_epk` → `ss2`
3. HKDF-SHA3-512 the concatenation with the same `info` string
4. Unwraps `_ek` to recover the session API key

From that point the session uses symmetric XChaCha20-Poly1305 for every request body.

#### 5.6.3 Payload encryption (once session key is known)

Code: `lib/api-crypto.js`.

Requests:
```
POST /api/endpoint
Content-Type: application/json

{ "_e": "<base64url(nonce || XChaCha20-Poly1305(session_key, nonce, JSON({ _d, _t })))>" }
```

Responses:
```
Content-Type: application/json

{ "_e": "<base64url(...)>", "_t": <server timestamp> }
```

The plaintext always contains `{ _d, _t }` where `_t` is the client-supplied timestamp. `decryptPayload` enforces `|now - _t| <= REPLAY_WINDOW` (30 seconds) — replay past that window is rejected.

**Notes:**
- The timestamp is inside the authenticated ciphertext, so it can't be manipulated by a network attacker
- 30 seconds is tight enough to make replay impractical but loose enough for clock skew on sync clients
- The session key is rotated whenever a new session is established; it does not rotate within a session

### 5.7 Client-side zero-knowledge vault

A separate encryption path: files the user puts in the "Personal Vault" tab are encrypted in the browser with a key derived from the user's passkey. The server stores only ciphertext and never sees the plaintext or key.

Code: `public/js/vault-pq.js`.

**Two modes:**

| Mode | How seed is produced | Does server know seed? |
|------|----------------------|------------------------|
| **PRF** (default, preferred) | WebAuthn PRF extension with static salt `"hermitstash-vault-prf-v1-salt-00"` | **No** — seed is derived inside the authenticator and never leaves |
| **Passkey-gated** (PRF-unavailable fallback) | Browser generates random 64 bytes and sends to server alongside passkey registration | **Yes** — server stores the seed. Passkey is still required to retrieve it |

**Encryption flow (per file):**

```
              ┌─────────────────────────┐
              │  WebAuthn assertion +   │  (PRF mode)
              │  PRF extension          │
              └────────────┬────────────┘
                           │
                           ▼
                ┌──────────────────┐
                │ 32-byte PRF seed │  (only in PRF mode; passkey mode
                │                  │   retrieves a stored 64-byte seed)
                └──────────┬───────┘
                           │ expand to 64 bytes (d || z per FIPS 203)
                           ▼
                ┌──────────────────────┐
                │ ML-KEM-1024.keygen() │
                │ → (pub 1568, priv)   │
                └──────────┬───────────┘
                           │
         per file ─────────┼──────────────────────────────
                           │
                           ▼
                ┌──────────────────────┐
                │ ML-KEM-1024          │
                │  .encapsulate(pub)   │
                │ → ss (32B), ct (1568)│
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │ SHAKE256(ss, 32)     │ ◄── file key
                └──────────┬───────────┘
                           │
                random 24-byte nonce
                           │
                           ▼
                ┌──────────────────────┐
                │ XChaCha20-Poly1305   │
                │ (key, nonce, file)   │
                └──────────┬───────────┘
                           │
                           ▼
             [encapsulatedKey(1568) | iv(24) | ciphertext+tag]

            (sent to server, stored opaquely in vault file records)
```

Decrypt inverts: `encapsulate` → server-stored ciphertext becomes `decapsulate`, same SHAKE256, same XChaCha20-Poly1305. The server only sees the output blob.

**Notes:**
- The "stealth mode" toggle hides vault operations from the audit log, so an attacker who later reads the audit log (after compromising the vault key) cannot enumerate vault activity. This is an additional privacy property orthogonal to the client-side encryption
- Passkey-gated mode is a pragmatic fallback for authenticators/browsers that don't support PRF (e.g. older iOS WebAuthn). It still requires the passkey to retrieve the seed, but it is **not** zero-knowledge — the server holds the seed. An operator who can read the DB can reconstruct the vault keypair in this mode
- Vault key rotation (PRF mode): user re-registers passkey, server re-emits an encapsulation challenge, client decrypts every file with the old key and re-encrypts with the new one. Atomic — `POST /vault/rotate` in `routes/vault.js:357`

### 5.8 mTLS CA and client certificate issuance

HermitStash acts as its own Certificate Authority for sync clients and (optionally) for enforcing browser mTLS.

Code: `lib/mtls-ca.js` (406 lines).

**Algorithm envelope (current CA generation: 2):**

| Component | Algorithm | Rationale |
|-----------|-----------|-----------|
| CA signature | ECDSA P-384 with SHA-384 | Best available today on all browsers/OS cert stores. ML-DSA-87 is supported in Node 24.8+ but no browser verifies PQ signatures on client certs; issuing PQ-signed certs today would break every mTLS handshake |
| Client cert signature | Same as CA | Chain consistency |
| PKCS#12 key bag | PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA-512 | SHA-512 PRF for consistency with MAC. AES-CBC chosen over AES-GCM because Windows / macOS importers still reject PBES2-AES-GCM key bags on some OS versions (confirmed 2026-04) |
| PKCS#12 outer MAC | HMAC-SHA-512 | Matches key bag KDF |
| PBKDF2 iterations | 2,000,000 | 2M picked in 2026-04 as a conservative modern default, up from 600k in CAv1 |

Code entry points:
- `lib/mtls-ca.js:48-49` — `CA_KEY_ALG`, `CA_SIG_ALG` constants
- `lib/mtls-ca.js:64` — `CA_GENERATION = 2`
- `lib/mtls-ca.js:74-77` — PKCS#12 parameters
- TODO markers for PQ signature migration at `lib/mtls-ca.js:42-47` and PKCS#12 v3 at `lib/mtls-ca.js:66-73`

**Flow:**

```
 ┌────────────────────────┐         ┌────────────────────────────┐
 │ Operator generates     │         │ Sync client enrolls        │
 │ sync token via admin   │────────▶│ (one-time enrollment code) │
 └────────────────────────┘         └─────────────┬──────────────┘
                                                  │
                                      ┌───────────▼───────────┐
                                      │ Server signs client   │
                                      │ cert with CA (P-384)  │
                                      └───────────┬───────────┘
                                                  │
                             ┌────────────────────┴────────────────────┐
                             │                                         │
                             ▼                                         ▼
                   ┌──────────────────┐                   ┌──────────────────────┐
                   │ Returns P12      │                   │ Records cert fpr     │
                   │ bundle to client │                   │ SHA3-512 hash in DB  │
                   └──────────────────┘                   │ (api_keys table)     │
                                                          └──────────────────────┘
```

The client cert's SHA3-512 fingerprint is bound to the API key — at WebSocket upgrade time, both must match. `MTLS_REQUIRED=false` is an explicit escape hatch to let an API-key-only client connect without a cert; per-key binding is still enforced if the key was issued with a cert.

**CA regeneration:** Admin → General → Danger Zone → "Regenerate mTLS CA" creates a new CA and re-issues certs. Active WebSocket clients get a `ca:rotation` message and ack back; the server auto-restarts after. Browser certs must be re-downloaded; offline sync clients must re-enroll. See `lib/mtls-ca.js` `regenerate()` function.

**Revocation:** `cert_revocations` table, keyed by SHA3-512 hashed fingerprint. `lib/cert-utils.js:isCertRevoked()` uses an indexed `findOne()` — not a table scan. Revocation check runs on every WebSocket upgrade and every authenticated API call using a bound cert.

### 5.9 TLS-level PQC enforcement (pqc-gate)

When HermitStash terminates TLS directly (no reverse proxy), a TCP-level gate inspects each incoming connection's ClientHello **before** the TLS handshake completes. If the ClientHello does not offer at least one PQC hybrid group, the connection is rejected with `handshake_failure`.

Code: `lib/pqc-gate.js`.

**Recognized PQC groups (`lib/constants.js:50-53`):**

| Group | IANA ID |
|-------|---------|
| X25519MLKEM768 | 0x11EC |
| SecP384r1MLKEM1024 | 0x11ED |

**Flow:**

```
              Incoming TCP connection
                       │
                       ▼
          ┌────────────────────────────┐
          │ Read up to 16 KB waiting   │
          │ for TLS record header      │
          │ (5s timeout, fail safe)    │
          └──────────────┬─────────────┘
                         │
                         ▼
          ┌────────────────────────────┐
          │ Parse ClientHello          │
          │ (type=0x01, TLS 1.3+)      │
          │ → supported_groups ext     │
          └──────────────┬─────────────┘
                         │
              ┌──────────┴───────────┐
              │                      │
              ▼                      ▼
         ClientHello           Any PQC group?
         malformed /                │
         truncated                  │
              │              ┌──────┴──────┐
              │              │             │
              ▼              yes           no
         handshake_fail      │             │
                             ▼             ▼
                     pipe to internal     handshake_fail
                     HTTPS server         + socket.destroy()
                     (tls.Server on
                      127.0.0.1:PORT+1)
```

**Bypass conditions:**
- Localhost (`127.0.0.1`, `::1`) requests bypass the gate so Docker health checks don't fail
- `PQC_ENFORCE=false` env var disables the gate for transition periods

**Outbound:** `lib/pqc-agent.js` implements a PQC-only HTTPS agent used for all outbound calls (S3, SMTP over TLS, Resend, webhooks, OAuth). `PQC_OUTBOUND_ENFORCE=false` allows classical fallback when remote servers haven't deployed PQC yet.

### 5.10 Webhook HMAC signatures

Outbound webhook POSTs carry an `X-Webhook-Signature` header with an HMAC-SHA3-512 hex digest of the raw JSON body, keyed with the webhook's registered secret.

```
X-Webhook-Signature = hex(HMAC-SHA3-512(secret, body))
```

The secret is generated with 256 bits of entropy (`generateBytes(32)`) and shown to the admin once on creation — never retrievable afterward, only rotatable.

Code: `lib/webhook.js` and `lib/crypto.js:75` for `hmacSha3`.

Receivers verify with `hmac.compare_digest()` (Python) or `crypto.timingSafeEqual` (Node) — sample code in the README.

---

## 6. Key hierarchy summary

```
  data/vault.key  (long-lived, filesystem-only protection)
       │
       │
       ├── vault.seal() ── all DB fields per-row (§5.3)
       │                    │
       │                    └── each field gets a fresh 24B nonce
       │                        via envelope format (§5.1)
       │
       ├── vault.seal() ── session.data rows (§5.5)
       │
       ├── vault.seal() ── per-file XChaCha20 keys stored in files.encryptionKey (§5.4)
       │                    │
       │                    └── file blob uses "packed" format with the per-file key
       │
       └── vault.seal() ── per-session API keys in session.apiKey (§5.6)
                            │
                            ├── session key delivered to mTLS clients via hybrid ECIES
                            │   (HKDF-SHA3-512 with "hermitstash-hybrid-ecies-v1" info)
                            │
                            └── used for per-request XChaCha20-Poly1305 of JSON bodies


  Independent trees:

  data/db.key.enc      — DB file encryption key, vault-sealed on disk
                          Protects the SQLite file at rest when the DB is paused

  mTLS CA private key  — ECDSA P-384, data/mtls/ca.key (plaintext, 0o600)
                          Signs client certs; unrelated to vault

  Browser passkey PRF  — client-side derivation for personal vault (§5.7)
                          Zero-knowledge: server never sees seed in PRF mode

  Webhook secrets      — per-webhook random 32 bytes, vault-sealed
                          HMAC-SHA3-512 of outbound bodies

  Argon2id password     — per-user, stored in users.passwordHash
    hashes               (Argon2id PHC format, $argon2id$v=19$...)
```

---

## 7. Algorithm agility & versioning

Three separate version mechanisms, described in detail in `CLAUDE.md`:

1. **Storage envelope** (`lib/crypto.js`) — 4-byte header identifies KEM/cipher/KDF. Old blobs remain readable when new IDs are added. Current: KEM `0x03`, cipher `0x02`, KDF `0x02`
2. **ECIES protocol** (`middleware/api-encrypt.js`) — 1-byte version on the `_ek` field. Current: `0x01`. Unlike the envelope, sessions are ephemeral so backward-compat on decrypt is not required — both sides must agree
3. **mTLS CA generation** (`lib/mtls-ca.js`) — CAs are tagged with `OU=CAv{N}` in the subject DN. Boot-time banner warns if the on-disk CA is older than the current generation. Migration is operator-initiated via Admin → Danger Zone

Upgrade points are tagged with `TODO(pqc-certs)` and `TODO(pkcs12-upgrade)` in the source for grep-ability.

---

## 8. Randomness

Code: `lib/crypto.js:46-49` (`random` function).

```javascript
function random(byteLength) {
  var n = byteLength || 32;
  return hash(nodeCrypto.randomBytes(n), "sha3-512").subarray(0, n);
}
```

Every call to `random()` (which is used by `generateBytes`, `generateToken`, `generateShareId`, and every nonce generator) hashes `crypto.randomBytes(n)` through SHA3-512 and returns the first `n` bytes.

**Rationale:** defense-in-depth. If `crypto.randomBytes` were ever compromised by a biased seed or broken entropy source, the SHA3-512 pass would mask patterns. This adds negligible cost (SHA3 is fast) and costs nothing security-wise.

**Caveats:**
- For byte lengths above 64, this construction truncates SHA3-512's 64-byte output — callers requesting more than 64 bytes get less entropy than they might assume (specifically: they get 64 bytes of SHA3-stretched randomness repeated across the output). **Check**: code review should verify no caller requests `random(n > 64)`. Quick audit: the largest observed request is 32 bytes (session keys, nonces). Worth enforcing `n <= 64` with an explicit check
- A reviewer might prefer using `crypto.randomBytes` directly and treating the double-hashing as cargo cult. Either position is defensible; the current choice is explicit in the source

---

## 9. Known limitations

Listed honestly for reviewers. In order of perceived importance.

### L1 — No independent cryptographic audit
No external cryptographer has reviewed this design. Primitives are well-reviewed; *compositions* are not.

### L2 — Vault key on disk in plaintext (partially addressable in v1.9+)
By default, `data/vault.key` is a JSON file protected only by filesystem permissions (0o600). There is no HSM, no TPM sealing. An attacker with filesystem read access defeats all at-rest encryption. See N1.

**Partial mitigation:** v1.9+ adds opt-in passphrase wrapping via `VAULT_PASSPHRASE_MODE=required`. See §5.2. When enabled, the disk-snapshot threat (stolen backup, leaked volume dump) is addressed — the attacker needs both the sealed file AND the passphrase. The limitation is NOT fully addressed because:
- The passphrase must be readable by the server at boot (env var, file, or stdin), so *some* secret still lives where the server can access it
- Once the server unwraps the key into memory, a live-host attacker recovers it (see N1, L15)
- The wrapping is operator-initiated; existing deployments stay in the plaintext posture until they opt in

### L3 — No forward secrecy for stored data
Vault key compromise retroactively decrypts every blob ever stored. See N3.

### L4 — No AAD on storage envelope header
The KEM/cipher/KDF bytes of the envelope are not included as AAD in the AEAD tag. Today only one of each is supported so the attack surface is empty, but adding a second cipher without also adding header-as-AAD could enable cross-protocol attacks. **Mitigation:** add envelope header bytes to AEAD's AAD whenever a second cipher is introduced.

### L5 — Hybrid KDF lacks domain separation in §5.1
The storage envelope's hybrid KEM concatenates `ml_kem_ss || ecdh_ss` with no domain separator before SHAKE256. Same hash chain as the ECIES path (§5.6) which uses HKDF with a fixed `info` string. The envelope version is arguably safe because the inputs are different lengths (32 + 48) and SHAKE256 absorbs the full string, but a cleaner construction would be `SHAKE256("hermitstash-storage-v1" || ml_kem_ss || ecdh_ss)`. Worth adopting when the envelope KDF ID changes for any other reason.

### L6 — Hash prefixes are not per-record salts
Email / IP / share-ID hashes use static prefixes (`hs-email:`, `hs-ip:`, etc). This is intentional (indexed lookup requires determinism) but means they are *identifiers*, not anonymizers. See N7.

### L7 — `random()` above 64 bytes degrades
The SHA3-wrapped random function silently truncates SHA3-512's 64-byte output if callers request more. No caller currently asks for more than 32 bytes, but this should be asserted in code rather than relying on external audit. See §8.

### L8 — No formal verification or symbolic model
Nothing has been modeled in ProVerif / Tamarin / Cryptol. See N9.

### L9 — mTLS CA uses classical signatures (ECDSA P-384)
PQ signature algorithms (ML-DSA-87, SLH-DSA-SHAKE-256f) are implemented and available in the project but not used for the CA. Browsers and OS cert stores don't yet verify PQ signatures on client certs. Migration is tagged with `TODO(pqc-certs)` in `lib/mtls-ca.js:42`. When browsers catch up, the CA can be regenerated with a PQ signature algorithm; the CA generation mechanism (§5.8) handles this.

### L10 — @noble and argon2 are single points of trust
The entire browser-side crypto stack depends on Paul Miller's @noble libraries. The server Argon2 path depends on the ranisalt/node-argon2 native binding. Both are well-regarded and audited (noble-pq has been reviewed by Cure53), but they are concentrated dependencies.

### L11 — No AEAD binding on ML-KEM ciphertext in §5.1
The ML-KEM ciphertext carried in the envelope is not authenticated by the outer AEAD tag. An attacker flipping bits in `kem.ct` causes decapsulation to fail (ML-KEM has implicit rejection) but the failure mode is not cryptographically enforced by Poly1305 — it's enforced by ML-KEM's own implicit rejection. This is probably fine (ML-KEM is designed for this) but worth a second opinion.

### L12 — First-run password is weak for concurrent attackers
On first boot the admin password is printed to stdout and written to `data/initial-admin-password.txt`. Any attacker with log access or filesystem access before the operator logs in can capture it. See N11. No easy fix — the alternative (forcing password set before any access) is worse UX.

### L13 — No rate limit on ML-KEM decapsulation
An attacker sending malformed envelopes forces server-side ML-KEM decapsulation per attempt. ML-KEM is fast (~0.1ms) so this isn't a realistic DoS vector, but it's uncapped.

### L14 — Session cookie forward secrecy
Vault-sealed session data means a later vault compromise decrypts all captured cookies. Per-session ephemeral keys would fix this but add complexity and don't match the threat model (see §3 — we don't defend against host compromise, and in-transit protection is already provided by TLS).

### L15 — Passphrase material in process memory (v1.9+ opt-in path)
When passphrase wrapping is enabled (§5.2 opt-in), the passphrase and the derived wrapping key exist in process memory briefly during boot:

1. `passphrase-source.js` reads the passphrase from env/file/stdin as a `Buffer`
2. `vault-wrap.deriveWrappingKey()` passes it to Argon2id
3. The resulting 32-byte wrapping key decrypts the sealed file
4. The plaintext vault key is cached in the vault module's local `keys` variable for the process lifetime

Node.js provides no mechanism to zero a Buffer's backing memory on demand. `delete process.env.VAULT_PASSPHRASE` limits exposure to later env-dump surfaces but doesn't scrub the bytes. The passphrase Buffer and wrapping-key Buffer remain GC-candidates but may persist until the allocator reuses those pages. An attacker with code execution on the running host can read them.

This is unavoidable for any at-rest encryption scheme on a service that boots without human interaction each request. The passphrase wrapping closes the disk-snapshot threat but does not close the live-host-compromise threat (which is already a non-goal — see N1). Operators who need defense against a compromised host need a completely different architecture (HSM, enclave, etc.) which is out of scope for this project.

---

## 10. Assumptions

These are properties HermitStash assumes but does not verify:

- **Node.js 24.8+ OpenSSL 3.5+** correctly implements ML-KEM-1024, ML-DSA-87, ECDH P-384, SHAKE256, and HKDF-SHA3-512. Tested through the Node / OpenSSL test suites; HermitStash adds no independent validation
- **@noble libraries** correctly implement XChaCha20-Poly1305 (server + browser), SHAKE256 (browser), and ML-KEM-1024 (browser). noble-post-quantum was audited by Cure53 in 2024; noble-ciphers and noble-hashes are heavily used across the ecosystem
- **argon2 native binding** correctly implements Argon2id per RFC 9106 with our chosen parameters (64 MiB memory, 3 time, 4 parallelism)
- **Host filesystem permissions are enforced**. `data/vault.key` is created with mode 0o600 and relies on the OS to honor it
- **`/dev/shm` is not readable by other tenants on shared hosts**. On multi-tenant containers, an attacker with access to the same kernel's shared memory can read session data. Single-tenant deployment is assumed
- **TLS CAs in the browser/OS trust store are not compromised** for the server's domain — see N8
- **The `node:sqlite` builtin module** handles corrupted databases safely. We rely on its error surfaces but don't independently fuzz it

---

## 11. Questions for reviewers

If you are a cryptographer willing to spend an hour on this, these are the questions that would most benefit from a second opinion. They are narrow on purpose — broad "is this secure" questions are hard to answer.

1. **Storage envelope hybrid KDF (§5.1, L5):** Is `SHAKE256(ml_kem_ss || ecdh_ss)` safe without domain separation, given the inputs come from domain-separated KEM/ECDH paths? Or should we migrate to HKDF-SHA3-512 with an explicit `info` string to match the ECIES construction?

2. **Envelope header as AAD (§5.1, L4):** Is ignoring the KEM/cipher/KDF header bytes in AEAD's AAD field acceptable given algorithm agility is future-looking, or should we bind them now?

3. **ML-KEM ciphertext integrity (§5.1, L11):** ML-KEM's implicit rejection handles tampered ciphertexts correctly, but should we add a belt-and-suspenders construction (e.g. AEAD with AAD = kem.ct) before the symmetric step?

4. **ECIES construction (§5.6.2):** HKDF-SHA3-512 with `info = "hermitstash-hybrid-ecies-v1"` and empty salt over ML-KEM ss || ECDH ss — is this a safe hybrid KEM-DEM instantiation, or should we be looking at X-Wing or CombinedKEM constructions?

5. **PRF-derived ML-KEM keygen (§5.7):** Deriving an ML-KEM-1024 keypair deterministically from a 32-byte PRF seed expanded to 64 bytes. Is the FIPS 203 `d || z` decomposition correctly handled? Is there any risk from the PRF not being uniform enough for ML-KEM's expected input distribution?

6. **Static salt on WebAuthn PRF (§5.7):** We use `"hermitstash-vault-prf-v1-salt-00"` as the PRF salt, not a per-user value. Is there a reason to prefer per-user? If the user re-registers a passkey against a different account on the same authenticator, they should get a different seed — which they do, because the credential ID itself differs.

7. **Argon2 parameters:** 64 MiB memory, 3 time, 4 parallelism. Adequate for 2026? Too low? Too high? The target is "painful for offline attack, acceptable for 100ms login".

8. **Randomness wrapper (§8):** Cargo cult or defense-in-depth? Happy to remove the SHA3 wrapper if the consensus is it adds no value.

9. **Hash prefix strategy (§5.3, L6):** `hs-email:` / `hs-ip:` / `hs-share-id:` as static prefixes. Are there better patterns for indexed-but-encrypted-at-rest lookups that don't require per-record salts (which would break indexed lookup entirely)?

10. **PKCS#12 parameters (§5.8):** AES-256-CBC + HMAC-SHA-512 + PBKDF2 + 2M iterations. Is the ongoing AES-CBC choice (driven by OS importer compatibility) a reasonable tradeoff, or should we force AES-GCM and accept the importer breakage?

---

## 12. How to report findings

Security reports: **see [SECURITY.md](../SECURITY.md)** for the coordinated-disclosure policy and PGP key. Non-sensitive feedback on this document itself is welcome via GitHub issues.

## 13. Changelog

| Date | Version | Change |
|------|---------|--------|
| 2026-04-21 | v1.8.25 | Initial draft against v1.8.25 |

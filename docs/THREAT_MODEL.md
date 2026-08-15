# HermitStash — Cryptographic Design & Threat Model

**Status:** Draft, unaudited. Last updated against v1.14.x source.

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
| Symmetric AEAD | XChaCha20-Poly1305 | `@noble/ciphers` 2.3.0 | RFC 8439 extended. 192-bit nonce (vs 96-bit for plain ChaCha20-Poly1305) allows random nonces without birthday risk. Constant-time in software, no AES-NI dependency |
| KDF / XOF | SHAKE256 | `node:crypto` (server), `@noble/hashes` 2.3.0 (browser bundle) | FIPS 202. Chosen over HKDF-SHA3 for the storage envelope because it is a single-call extendable-output function with no salt/info complexity — the inputs are already high-entropy KEM shared secrets |
| Hash | SHA3-512 | `node:crypto` | FIPS 202. Truncated when shorter outputs are needed. SHA-256 was rejected in favor of a SHA-3 family member to avoid length-extension concerns even where they don't technically apply |
| Webhook MAC | HMAC-SHA256 (Standard Webhooks) | `node:crypto` | RFC 2104. The scheme's specified construction, for receiver-library interoperability. Symmetric authenticator to an operator-registered endpoint — see §5.10 for why it sits outside the post-quantum requirement |
| Password hash | Argon2id | Node 24+ built-in `crypto.argon2` via blamejs `lib/argon2-builtin.js` | RFC 9106. Memory-hard. Default parameters: 64 MiB memory, 3 time cost, 4 parallelism. `ARGON2_FAST=1` env flag switches to 1 MiB / 1 / 1 for automated test runs only |
| Signatures | SLH-DSA-SHAKE-256f (default) / ML-DSA-87 (legacy) | `node:crypto` (OpenSSL 3.5+) | FIPS 205 / 204. `generateSigningKeyPair()` defaults to SLH-DSA-SHAKE-256f — chosen as the conservative SHAKE-based hash-only signature, robust against future cryptanalytic findings against lattice schemes. ML-DSA-87 remains supported for callers that explicitly request it (smaller key/signature) and for verifying any legacy keys persisted in databases (algorithm auto-detected from key PEM). Used for signing vendored assets and release verification. The mTLS **sync** CA now signs client certs with ML-DSA-87; the **browser** CA stays classical (ECDSA-P384-SHA384) for keystore/handshake compatibility (see §5.8) |
| RNG | SHAKE256(node.randomBytes, n) | `node:crypto` wrapper in `lib/crypto.js:47` | A belt-and-suspenders wrapper post-hashes `crypto.randomBytes(n)` through SHAKE256 (the FIPS 202 XOF) and returns `n` bytes. The XOF variant scales to any `n` — the older SHA3-512 implementation silently truncated to 64 bytes for `n > 64`. See §9 for the rationale |

Vendored third-party libraries:
- **@noble/ciphers** (Paul Miller) — XChaCha20-Poly1305, server + browser
- **@noble/hashes** (Paul Miller) — SHAKE256 for the browser (server uses node:crypto)
- **@noble/post-quantum** (Paul Miller) — ML-KEM-1024 for the browser; the server uses node:crypto
- **@blamejs/pki** — zero-dependency pure-JS X.509 toolkit backing the mTLS CA engine (CA generation, client-cert signing, PKCS#12 packaging, CRL) under ML-DSA-87 (sync CA) or ECDSA-P384-SHA384 (browser CA)
- **Argon2id** — Node 24+'s built-in `crypto.argon2`, wrapped by blamejs's `lib/argon2-builtin.js` (no vendored native binding)

---

## 5. Protocols

Each subsection describes one cryptographic construction. Code references are to v1.14.x.

### 5.1 Storage envelope format

Every at-rest encrypted blob the server produces starts with a 4-byte header that identifies which algorithms were used. This is what makes algorithm agility possible — any component can be swapped and old blobs remain readable.

Code: `lib/vendor/blamejs/lib/crypto.js` `encrypt()` / `decrypt()`, reached via `b.crypto.encrypt` / `b.crypto.decrypt` from `lib/vault.js`. HermitStash's own `lib/crypto.js` (`ENV_MAGIC = 0xE1`) is now the legacy 0xE1 decoder only, invoked from the `vault.unseal` migration fallback.

**Layout:**

```text
Offset  Field                        Size    Value
──────  ─────────────────────────    ────    ─────
0       Magic                        1       0xE2 (FixedInfo/suite-bound; 0xE1 is the legacy pre-migration magic)
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

```text
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
                                      │ concat with suite-binding FixedInfo
                                      ▼
                            ┌────────────────────────────────┐
                            │ SHAKE256(ss1 || ss2 ||         │
                            │   suiteFixedInfo, 32 bytes)    │ ◄── symmetric key
                            └──────────┬─────────────────────┘
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
- The two shared secrets are concatenated with a suite-binding `FixedInfo` before the KDF (`lib/vendor/blamejs/lib/crypto.js:691-696`, `:1105-1107`): SHAKE256 absorbs `ml_kem_ss || ecdh_ss || suiteFixedInfo`, where `suiteFixedInfo = "blamejs/v1" || 0x00 || kemId || cipherId || kdfId || 0x00` (NIST SP 800-56C r2 §4.1 OtherInfo / RFC 9180 §5.1 suite_id binding). A key derived under one suite is not silently usable under another. The legacy 0xE1 path omitted this binding.
- The 4-byte envelope header (magic | KEM | cipher | KDF) **is** authenticated as AEAD additional authenticated data (AAD) on the active 0xE2 envelope (`lib/vendor/blamejs/lib/crypto.js:1109-1113` on encrypt, re-derived at `:1306-1308` on decrypt). An algorithm-substitution flip of any header byte surfaces as a Poly1305 tag verification failure. The legacy 0xE1 path did not bind the header.

### 5.2 Vault — long-lived at-rest key

File: `data/vault.key`. Format: plaintext JSON, `{ publicKey, privateKey, ecPublicKey, ecPrivateKey }`, all PEM-encoded. File mode: `0o600`.

Code: `lib/vault.js`.

The vault key is the root of at-rest encryption. On first boot the server generates:
- ML-KEM-1024 keypair via `node:crypto.generateKeyPairSync("ml-kem-1024")`
- P-384 ECDH keypair via `node:crypto.generateKeyPairSync("ec", { namedCurve: "P-384" })`

`vault.seal(plaintext)` prepends a `vault:` prefix and delegates to `b.crypto.encrypt(plaintext, vaultKeys)`, which produces a 0xE2 envelope (§5.1). `vault.unseal(value)` strips the prefix and dispatches on the magic byte — 0xE2 → `b.crypto.decrypt`, 0xE1 → HermitStash's legacy `lib/crypto.js` decoder for pre-migration blobs (`lib/vault.js:391-397`).

**Diagram — key hierarchy:**

```text
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

**Optional mitigation (v1.9+) — passphrase wrapping.** When `VAULT_PASSPHRASE_MODE=required`, the on-disk file is `data/vault.key.sealed` instead of plaintext `data/vault.key`. Format: 4-byte magic `0xE2` header (wrapping is `b.vaultWrap.wrap()` / `unwrap()`, invoked from `lib/vault.js:332`,`:344`, implemented in `lib/vendor/blamejs/lib/vault/wrap.js`), Argon2id-derived wrapping key (64 MiB, 3 iterations, 4 parallelism by default), XChaCha20-Poly1305 AEAD with the full header bound as AAD. An attacker with the wrapped file but not the passphrase cannot recover the vault keys. The passphrase is read at boot from one of: `VAULT_PASSPHRASE` env, `VAULT_PASSPHRASE_FILE`, or interactive stdin. This protection addresses the disk-snapshot threat scenarios (N1 listed host compromise is explicitly out of scope — once unwrapped, the plaintext key lives in process memory and is recoverable by any attacker with code execution). See §9 L2 and L15, and the README's "Passphrase protection" section for operator UX.

### 5.3 Field encryption (field-crypto middleware)

Every database field that isn't a raw identifier, counter, or timestamp goes through `vault.seal()` on write and `vault.unseal()` on read, transparently, via a middleware layer around the SQLite wrapper.

Code: `lib/field-crypto.js` (255 lines), `FIELD_SCHEMA` constant.

Each table's fields are classified as:
- **seal** — encrypted per-field via `vault.seal()`. Values stored as `vault:<base64>`
- **hash** — keyed blind index for indexed lookups (emails, IP addresses): a keyed MAC (HMAC-SHAKE256) of the namespaced value under a per-deployment secret, not a bare hash
- **argon2** — password hash, handled externally (not auto-processed by this layer)
- **raw** — plaintext (IDs, counters, status enums, FK references, timestamps)

Derived fields such as `emailHash` from `email` are auto-computed from a source field as a keyed MAC of `<prefix>:<value>` under a per-deployment secret (`vault.derived-hash-mac.sealed`, re-sealed — not regenerated — on vault-key rotation, so the index survives a rotation).

The middleware also rewrites queries transparently: `{ email: "user@example.com" }` becomes a match on the keyed `emailHash`, so callers still use plaintext lookups. During the rollover from the previous unkeyed digest, a query matches both the keyed index and the legacy digest; a one-time pass on first boot rewrites existing rows to the keyed form.

**Security notes:**
- Hash prefixes (`hs-email`, `hs-ip`, `hs-share`, `hs-certfp`, `hs-slug`, `hs-access-code`, `hs-enroll`, `hs-blockedip` — full list in `lib/constants.js`) namespace the input before the MAC, so the same value in two columns produces different indexes. Because the MAC key lives only in the deployment's sealed keystore, an attacker holding only the database cannot recompute an index from a guessed plaintext (no confirmation oracle) and cannot correlate indexes across deployments. The index is still deterministic within one database — equal values produce equal indexes, which is what makes the lookup work — so it remains an *identifier*, not an anonymizer. See N7
- Every envelope blob for field encryption has a fresh 24-byte nonce. No nonce reuse across fields

### 5.4 File encryption at rest

Each uploaded file gets a fresh 32-byte XChaCha20-Poly1305 key. That per-file key is sealed with the vault (§5.2) and stored in the `files.encryptionKey` column.

Code: `lib/storage.js:41-50`, using `crypto.encryptPacked()` / `decryptPacked()` from `lib/crypto.js:195-204`.

**"Packed" format (different from the storage envelope):**

```text
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

### 5.6 API payload encryption

For browser (cookie-authenticated) clients, every JSON POST body and every JSON response body is encrypted with XChaCha20-Poly1305 using a **per-session symmetric key**, separate from the vault key. Bearer-authenticated clients (sync / API-key / mTLS) are bypassed out of this path by `middleware/api-encrypt.js` (`if (req.apiKey) return next();`) — their JSON payload protection routes through blamejs apiEncrypt instead (see §5.6.4).

Code: `middleware/api-encrypt.js`, `lib/api-crypto.js`.

#### 5.6.1 Session key generation

First request per session:
1. Server generates `apiKey = random(32)` as base64url
2. Server stores `apiKey` in `session.apiKey` via `vault.seal()`
3. Subsequent calls unseal it for the request's lifetime

Delivery of `apiKey` to the client depends on client type:
- **Browsers:** the server embeds the apiKey in the response HTML template (`res._apiKey` → template placeholder). No separate key exchange — the browser is already authenticated by the session cookie over TLS
- **Sync clients (Bearer / API-key):** the production sync client authenticates via `Authorization: Bearer <API key>` (`middleware/api-auth.js` sets `req.apiKey`), which causes `middleware/api-encrypt.js` to bypass payload-envelope interception entirely — no `_e/_t` body wrap. Its JSON payload protection routes through blamejs apiEncrypt (§5.6.4), which runs its own ML-KEM-1024 exchange against the server's published public key

A response body never carries the session key, wrapped or otherwise; it carries the encrypted payload and its timestamp and nothing else. §5.6.2 records a wrap that used to ride along on the first response and why it is gone.

#### 5.6.2 Retired: hybrid ECIES session-key wrap

Through v1.13.21 the first response to an mTLS client that also sent an `X-KEM-Public-Key` header carried a wrapped copy of the session key, in the fields `_ek`, `_epk` and `_kem`. The wrapping key came from two shared secrets concatenated and run through HKDF-SHA3-512: ML-KEM-1024 encapsulation to the header key, and ECDH against the P-384 public key in the peer certificate.

The concern it addressed was putting a session key on the wire in plaintext, where a future log, trace or proxy leak could recover it.

It no longer exists. From v1.14.0 client certificates are post-quantum (§5.4) and carry an ML-DSA-87 signature key, which has no ECDH counterpart, so the second shared secret could not be computed. That leg was also the only thing binding the wrap to the **authenticated** peer: the ML-KEM public key arrives in a request header, so a wrap derived from it alone would go to whatever key the caller supplied. There was no safe reduction, and the mechanism was removed rather than weakened.

Nothing replaced it, because nothing needed it. A browser receives the session key in its page template over TLS (§5.6.1) and an API-key client bypasses this layer entirely for blamejs apiEncrypt (§5.6.4), whose own ML-KEM-1024 exchange runs against the server's published public key rather than a key supplied by the caller. The property the wrap existed to provide — no session key in plaintext on the wire — now holds because no response carries a session key at all.

Regression coverage: `tests/security/api-encrypt-no-key-in-response.test.js`.

#### 5.6.3 Payload encryption (once session key is known)

Code: `lib/api-crypto.js`.

Requests:
```http
POST /api/endpoint
Content-Type: application/json

{ "_e": "<base64url(nonce || XChaCha20-Poly1305(session_key, nonce, JSON({ _d, _t })))>" }
```

Responses:
```http
Content-Type: application/json

{ "_e": "<base64url(...)>", "_t": <server timestamp> }
```

The plaintext always contains `{ _d, _t }` where `_t` is the client-supplied timestamp. `decryptPayload` enforces `|now - _t| <= REPLAY_WINDOW` (30 seconds) — replay past that window is rejected.

**Notes:**
- The timestamp is inside the authenticated ciphertext, so it can't be manipulated by a network attacker
- 30 seconds is tight enough to make replay impractical but loose enough for clock skew. This replay/timestamp logic applies to the browser legacy envelope path, not the sync path (§5.6.4)
- The session key is rotated whenever a new session is established; it does not rotate within a session

#### 5.6.4 Sync / Bearer client payload encryption (blamejs apiEncrypt)

Sync clients (Bearer auth, `req.apiKey` set) do not use the `_e/_t` envelope. They use blamejs's per-session `apiEncrypt` protocol (ML-KEM-1024 + P-384 ECDH hybrid, SHAKE256 KDF, XChaCha20-Poly1305 wrap). The server keypair lives at `data/api-encrypt-keypair.sealed` (`lib/constants.js:180-183`) and is advertised at `GET /.well-known/blamejs-pubkey`.

This covers a **narrow** carve-out only: JSON POSTs to `/drop/init`, `/drop/finalize/:bundleId`, and `/sync/rename` (`server-main.js:432-438`). All other Bearer-auth paths — `GET /b/:shareId`, `DELETE /files/:fileId`, multipart uploads, binary downloads — travel as plaintext-over-TLS/mTLS with no application-layer payload encryption.

Code: `server-main.js:403-466`, `lib/api-encrypt-keypair.js`, `lib/constants.js:180-183`.

### 5.7 Client-side zero-knowledge vault

A separate encryption path: files the user puts in the "Personal Vault" tab are encrypted in the browser with a key derived from the user's passkey. The server stores only ciphertext and never sees the plaintext or key.

Code: `public/js/vault-pq.js`.

**Two modes:**

| Mode | How seed is produced | Does server know seed? |
|------|----------------------|------------------------|
| **PRF** (default, preferred) | WebAuthn PRF extension with static salt `"hermitstash-vault-prf-v1-salt-00"` | **No** — seed is derived inside the authenticator and never leaves |
| **Passkey-gated** (PRF-unavailable fallback) | Browser generates random 64 bytes and sends to server alongside passkey registration | **Yes** — server stores the seed. Passkey is still required to retrieve it |

**Encryption flow (per file):**

```text
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
- Passkey-gated mode is a pragmatic fallback for authenticators/browsers that don't support PRF, such as older iOS WebAuthn. It still requires the passkey to retrieve the seed, but it is **not** zero-knowledge — the server holds the seed. An operator who can read the DB can reconstruct the vault keypair in this mode
- Vault key rotation (PRF mode): user re-registers passkey, server re-emits an encapsulation challenge, client decrypts every file with the old key and re-encrypts with the new one. Atomic — `POST /vault/rotate` in `routes/vault.js:359`

### 5.8 mTLS CAs and client certificate issuance

HermitStash acts as its own Certificate Authority for mTLS. It runs **two** CAs, because sync clients and browsers have incompatible capabilities:

- **Sync CA** (`data/ca.crt`, `lib/mtls-ca.js`) signs the client certs machine sync clients present. It is **post-quantum by default — ML-DSA-87 (FIPS 204)**. Sync clients run on Node/OpenSSL 3.5, which completes a real ML-DSA mutual-auth TLS handshake (chain verification *and* the client CertificateVerify).
- **Browser CA** (`data/ca-browser.crt`, `lib/mtls-ca-browser.js`) signs the PKCS#12 client certs humans import into a browser / OS keystore to reach the web UI under Enforce mTLS. It is pinned **classical — ECDSA-P384-SHA384** on purpose: today's browsers and OS keystores can neither complete an ML-DSA TLS client-auth handshake nor import a post-quantum (PBMAC1, RFC 9579) PKCS#12.

The TLS server trusts **both** CA certs in its mTLS `ca` trust bundle (`server-main.js`), so a machine sync client and a browser-imported cert both authenticate. During a sync-CA migration the superseded CA (`data/ca.prev.crt`) is trusted too (§5.8.2). Each CA has its own generation counter, on-disk files, and revocation registry, so it rotates and revokes independently.

Code: `lib/mtls-ca.js` / `lib/mtls-ca-browser.js` (process-wide singletons over `b.mtlsCa.create`); the engine is `b.mtlsEngine`, backed by `@blamejs/pki` (`lib/vendor/blamejs/lib/vendor/blamejs-pki.cjs`) — a zero-dependency pure-JS X.509 / PKCS#12 / CRL toolkit.

**Algorithm envelope:**

| Component | Sync CA | Browser CA |
|-----------|---------|------------|
| CA + client cert signature | ML-DSA-87 (FIPS 204) | ECDSA P-384 with SHA-384 |
| PKCS#12 key + cert bags | — (sync certs ship as PEM) | PBES2 + AES-256-CBC + PBKDF2-HMAC-SHA-512, 2,000,000 iterations |
| PKCS#12 outer MAC | — | RFC 7292 App. B HMAC-SHA-512 MacData (legacy-importable) |

The browser CA keeps AES-CBC (not AES-GCM) key bags and the RFC 7292 MacData so the `.p12` imports on OS versions whose importers still reject PBES2-AES-GCM key bags or a PBMAC1 MacData. 2M PBKDF2 iterations is the conservative modern default (up from 600k in an earlier generation).

Code entry points:
- `lib/constants.js` — `CA_GENERATION = 3` (sync CA), `CA_BROWSER_GENERATION = 1` (browser CA)
- `lib/mtls-ca.js` — sync CA singleton; reads the `MTLS_CA_ALGORITHM` pin (unset ⇒ the CA follows its stored algorithm and can migrate)
- `lib/mtls-ca-browser.js` — browser CA singleton, hard-pinned `algorithm: "ECDSA-P384-SHA384"` with its own files (`ca-browser.key[.sealed]`, `ca-browser.crt`, `ca-browser-revocations.json`, `ca-browser.crl`)
- `lib/mtls-migrate.js` — the sync-CA post-quantum migration (§5.8.2)

#### 5.8.1 Issuance flow

```text
 ┌────────────────────────┐         ┌────────────────────────────┐
 │ Operator generates     │         │ Sync client enrolls        │
 │ sync token via admin   │────────▶│ (one-time enrollment code) │
 └────────────────────────┘         └─────────────┬──────────────┘
                                                  │
                                      ┌───────────▼───────────┐
                                      │ Server signs client   │
                                      │ cert with sync CA     │
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

The client cert's SHA3-512 fingerprint is bound to the API key — at WebSocket upgrade time, both must match. `MTLS_REQUIRED=false` is an explicit escape hatch to let an API-key-only client connect without a cert; per-key binding is still enforced if the key was issued with a cert. Browser certs (`routes/browser-certs.js`) are issued by the browser CA, packaged as PKCS#12, and tracked as rows in `api_keys` so the existing revoke flow cascades to `cert_revocations`; those tracking rows carry a `browser:`-prefixed `keyHash` sentinel and no scopes, so they can never function as real API keys.

#### 5.8.2 Sync-CA post-quantum migration

A sync CA generated by an older build is classical (ECDSA-P384). At boot, `lib/mtls-migrate.js` migrates it to the ML-DSA-87 default — but only when the runtime can VERIFY an ML-DSA client chain in a real mTLS handshake. That is a stronger gate than "can issue one": it requires OpenSSL ≥ 3.5 **and** a passing in-process TLSv1.3 loopback probe (`canVerifyMlDsaMtls()` generates an ephemeral ML-DSA-87 CA + server/client leaves and asserts the server-side `socket.authorized`). If the probe fails or times out, the classical sync CA is retained and nothing breaks.

The migration is prepare-in-place:
1. The superseded CA cert is retained at `data/ca.prev.crt` for a 30-day grace window and folded into the TLS trust bundle, so certs it issued keep verifying while their owners re-enroll onto the new CA.
2. A marker (`data/ca-migration.json`) records the grace clock.
3. A fresh CA is generated under the ML-DSA-87 default and committed; subsequent issuance is post-quantum.

When the grace window closes, `closeOutGraceIfExpired()` drops `ca.prev.crt` and revokes — through HermitStash's own `cert_revocations` table — any sync client cert still bound to the old CA. The browser CA is never touched (its tracking rows carry a `browser:` keyHash and are excluded).

The migration is a no-op unless every guard holds: a classical sync CA exists, no `MTLS_CA_ALGORITHM` pin, `MTLS_AUTO_MIGRATE` is not `false`, and the loopback probe passes.

**Operator controls:**
- `MTLS_CA_ALGORITHM=ECDSA-P384-SHA384` pins the sync CA classical and suppresses the migration — for deployments whose sync peers can't verify ML-DSA in TLS. Set it before the CA migrates; a pin that conflicts with an already-migrated CA is refused.
- `MTLS_AUTO_MIGRATE=false` disables the migration without pinning an algorithm; an existing classical CA is left in place, and a fresh install still starts post-quantum.

Browser certs are unaffected by any sync-CA migration or regeneration.

**CA regeneration:** Admin → General → Danger Zone → "Regenerate mTLS CA" rolls the sync CA to the current default and opens the same grace window via `mtls-migrate.beginGrace()`, so certs from the superseded CA keep verifying while their owners re-enroll. Active WebSocket clients get a `ca:rotation` message and ack back; the server auto-restarts after. Offline sync clients must re-enroll; browser certs (signed by the separate browser CA) stay valid.

**Revocation:** each CA has its own registry. The mTLS peer gate consults HermitStash's `cert_revocations` table via `lib/cert-utils.js` (`isPeerCertRevoked()` / `isCertRevoked()`, an indexed `findOne()` — not a table scan). The check runs on every WebSocket upgrade and every authenticated API call using a bound cert.

### 5.9 TLS-level PQC enforcement (pqc-gate)

When HermitStash terminates TLS directly (no reverse proxy), a TCP-level gate inspects each incoming connection's ClientHello **before** the TLS handshake completes. If the ClientHello does not offer at least one PQC hybrid group, the connection is rejected with `handshake_failure`.

Code: HermitStash no longer ships this file — the gate is provided by blamejs (`lib/vendor/blamejs/lib/pqc-gate.js`) and wired in `server-main.js` via `b.pqcGate.create({ internalPort, log })`.

**Recognized PQC groups (`PQC_GROUPS` in `lib/vendor/blamejs/lib/constants.js`; HermitStash re-exports them via `lib/constants.js`):**

| Group | IANA ID |
|-------|---------|
| SecP256r1MLKEM768 | 0x11EB |
| X25519MLKEM768 | 0x11EC |
| SecP384r1MLKEM1024 | 0x11ED |

**Flow:**

```text
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

**Outbound:** `b.pqcAgent` (`lib/vendor/blamejs/lib/pqc-agent.js`) backs every outbound HTTPS dial made through `b.httpClient` — S3, SMTP over TLS, Resend, webhooks, OAuth. It offers the three ML-KEM hybrids ahead of classical X25519 at a TLS 1.3 floor, so a hybrid is preferred on every handshake. Unlike the inbound gate there is no outbound refusal: a peer that offers no hybrid still connects over X25519. Each such connection is recorded as a `tls.classical_downgrade` audit event carrying the negotiated group and peer host, so the audit log is where to see which upstreams are still classical.

### 5.10 Webhook HMAC signatures

Outbound webhook POSTs are signed with the [Standard Webhooks](https://www.standardwebhooks.com/) scheme, which binds a delivery identifier and a timestamp into the MAC rather than covering the body alone.

```text
webhook-id:        msg_<token>
webhook-timestamp: <unix seconds>
webhook-signature: v1,base64(HMAC-SHA256(secret, "<webhook-id>.<webhook-timestamp>.<body>"))
```

A bare body HMAC is replayable forever: the same bytes and the same signature stay valid indefinitely, so an attacker who captures one delivery can resend it. Binding the timestamp lets a receiver bound how old a delivery may be, and the `v1,` prefix leaves room to change algorithm without breaking receivers. The header may carry several space-separated signatures during a secret rotation, so a receiver accepts the delivery if any one of them matches.

HMAC-SHA256 is the scheme's specified construction, chosen here for interoperability with off-the-shelf receiver libraries. This is a symmetric authenticator between the server and an operator-registered endpoint — it protects neither stored data nor anything a quantum adversary could act on retroactively, so it sits outside the post-quantum requirement that governs the rest of the stack.

The secret is generated with 256 bits of entropy (`generateBytes(32)`), shown to the admin once on creation — never retrievable afterward, only rotatable — and its UTF-8 bytes are the MAC key.

Code: `app/domain/integrations/webhook.service.js`, signing via `b.standardWebhooks.sign`.

Receivers verify with `hmac.compare_digest()` (Python) or `crypto.timingSafeEqual` (Node) — sample code in the README.

---

### 5.11 TOTP 2FA (`lib/totp.js`)

**Default for new enrollments (v1.9.11+):** RFC 6238 with HMAC-SHA-512, 128-byte secret, 8-digit codes, 30 s step, ±1 step drift window. The 128-byte secret sits exactly at the HMAC-SHA-512 block size (B=128) — every byte contributes to the inner/outer pads without HMAC pre-hashing them down to L=64 bytes.

**Algorithm choice rationale.** RFC 6238 §1.2 defines SHA-256 and SHA-512 variants alongside SHA-1; the legacy default in many implementations is SHA-1 only because of authenticator-app interop history, not because the spec requires it. SHA-512 is the strongest standardized RFC 6238 variant. SHA-3 / KMAC variants would require a custom URI scheme that no third-party authenticator app verifies, so they are not used.

**Legacy path.** SHA-1 secrets enrolled before v1.9.11 (20-byte, 6-digit) remain verifiable so users can complete one final login. On any successful login that satisfies 2FA against a legacy algorithm, `req.session.requiresTotpReEnroll` is set; a `server-main.js` guard then redirects every subsequent request to `/2fa/re-enroll` (allowing only static assets, the re-enroll endpoints themselves, and the logout route) until the user re-pairs to SHA-512. The stored algorithm is tracked in the `users.totpAlgorithm` column (sealed with all other user fields per §5.3).

**Backup codes.** 10 single-use codes per enrollment, hashed SHA3-512 at rest, algorithm-independent (the codes themselves are 8-character hex tokens; algorithm only affects the TOTP path).

**Replay prevention.** `users.totpLastStep` records the last accepted time-step; subsequent verifies for the same or earlier step are rejected. Reset to NULL on re-enrollment.

**Constant-time comparison.** All code comparisons use `timingSafeEqual` (`lib/crypto.js:60-66`).

---

## 6. Key hierarchy summary

```text
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
                            ├── delivered to browsers in the page template, never in a
                            │   response body (§5.6.1)
                            │
                            └── used for per-request XChaCha20-Poly1305 of JSON bodies


  Independent trees:

  data/db.key.enc      — DB file encryption key, vault-sealed on disk
                          Protects the SQLite file at rest when the DB is paused

  mTLS sync CA priv key — ML-DSA-87 by default (classical ECDSA P-384 until
                          the boot migration in §5.8.2 runs), data/ca.key
                          (plaintext, 0o600) OR data/ca.key.sealed (vault-sealed,
                          v1.9.4+ opt-in via CA_KEY_SEALED=required). Signs sync
                          client certs.

  mTLS browser CA priv  — ECDSA P-384 (classical, pinned), data/ca-browser.key
    key                   (plaintext, 0o600) OR data/ca-browser.key.sealed
                          (CA_KEY_SEALED=required). Signs browser PKCS#12 certs.

  TLS server private key — data/tls/privkey.pem (plaintext, 0o600)
                          OR data/tls/privkey.pem.sealed (vault-sealed,
                          v1.9.4+ opt-in via TLS_KEY_SEALED=required).

  Browser passkey PRF  — client-side derivation for personal vault (§5.7)
                          Zero-knowledge: server never sees seed in PRF mode

  Webhook secrets      — per-webhook random 32 bytes, vault-sealed
                          Standard Webhooks signature (timestamped)

  Argon2id password     — per-user, stored in users.passwordHash
    hashes               (Argon2id PHC format, $argon2id$v=19$...)
```

---

## 7. Algorithm agility & versioning

Two separate version mechanisms:

1. **Storage envelope** (`lib/vendor/blamejs/lib/crypto.js`) — 4-byte header identifies magic/KEM/cipher/KDF and is bound as AEAD AAD. Old blobs remain readable when new IDs are added. Current: magic `0xE2`, KEM `0x03`, cipher `0x02`, KDF `0x02` (legacy `0xE1` blobs decrypt via the migration fallback in `lib/crypto.js`)
2. **mTLS CA generation** (`lib/mtls-ca.js`, `lib/mtls-ca-browser.js`) — the sync and browser CAs each carry their own `OU=CAv{N}` generation tag in the subject DN, and a boot-time banner warns when an on-disk CA is older than its current generation. The sync CA additionally auto-migrates from classical to the ML-DSA-87 default at boot when the runtime can verify an ML-DSA chain in TLS (§5.8.2); operators pin or disable that with `MTLS_CA_ALGORITHM` / `MTLS_AUTO_MIGRATE`. Regeneration is operator-initiated via Admin → Danger Zone

---

## 8. Randomness

Code: `lib/crypto.js:46-54` (`random` function).

```javascript
function random(byteLength) {
  var n = byteLength || 32;
  return hash(nodeCrypto.randomBytes(n), "shake256", n);
}
```

Every call to `random()` (which is used by `generateBytes`, `generateToken`, `generateShareId`, and every nonce generator) post-hashes `crypto.randomBytes(n)` through SHAKE256 (the FIPS 202 XOF) and returns `n` bytes.

**Rationale:** defense-in-depth. If `crypto.randomBytes` were ever compromised by a biased seed or broken entropy source, the SHAKE256 pass would mask patterns. This adds negligible cost (SHAKE256 is fast) and costs nothing security-wise. SHAKE256 doubles as the project's KDF primitive (§5.1, §5.6 use the same XOF for KDF), so the random and KDF paths share one FIPS 202 family member.

**History note:** v1.9.10 and earlier used `createHash("sha3-512").subarray(0, n)`, which silently truncated to 64 bytes for `n > 64`. No caller in tree exceeded 32 bytes at the time, so the bug was latent. v1.9.11 introduced a 128-byte TOTP secret (HMAC-SHA-512 block size) which exercised the cap; the fix replaced SHA3-512 with its native XOF sibling SHAKE256, which has no fixed output length.

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

**Extended mitigation (v1.9.4+) — `ca.key` and `tls/privkey.pem` sealing.** The same wrap-with-the-vault-key pattern extends to the mTLS CA private key (`CA_KEY_SEALED=required` → `data/ca.key.sealed`) and TLS server private key (`TLS_KEY_SEALED=required` → `data/tls/privkey.pem.sealed`). With all three opt-ins enabled, every long-lived key in `data/` is either sealed or downstream of the vault key. The CA case closes a worse disk-snapshot gap than the vault itself — a plaintext-leaked CA key lets an attacker mint trusted client certs forever, and rotation doesn't undo that retroactively. The TLS case is ACME-friendly: the cert watcher auto-seals plaintext renewals (certbot/acme.sh hooks need no changes). v1.9.6+ adds admin UI wizards that walk the operator through enabling these sealing layers without docker-exec'ing. See README's "PEM at-rest sealing" section for operator UX.

### L3 — No forward secrecy for stored data
Vault key compromise retroactively decrypts every blob ever stored. See N3.

**Reactive mitigation (v1.9.3+):** `scripts/vault-key-rotate.js` performs a full vault key rotation that re-encrypts every sealed value in the data directory (DB rows, the SQLite file's wrapping key, every per-file XChaCha20 key index). After rotation, the OLD vault key cannot read live data — closing the door on a compromised key that hasn't yet been used to exfiltrate everything. This does NOT provide forward secrecy in the cryptographic sense (data already exfiltrated under the old key remains compromised), but it does bound the window of usefulness for a stolen vault key. See README "Full vault key rotation" section.

### L4 — AAD on storage envelope header (RESOLVED on the active 0xE2 envelope)
The active 0xE2 envelope binds the 4-byte header (magic | KEM | cipher | KDF) as AEAD AAD (`lib/vendor/blamejs/lib/crypto.js:1109-1113` on encrypt, re-derived at `:1306-1308` on decrypt; reached via `b.crypto.encrypt`/`decrypt` from `lib/vault.js:380`/`:397`), so an algorithm-substitution flip of any header byte surfaces as a Poly1305 tag failure. The legacy 0xE1 path did not bind the header and is decrypt-only during the boot-time migration window.

### L5 — Hybrid KDF domain separation in §5.1 (RESOLVED on the active 0xE2 envelope)
The active 0xE2 storage envelope appends a suite-binding `FixedInfo` to the KDF input: `SHAKE256(ml_kem_ss || ecdh_ss || suiteFixedInfo)`, where `suiteFixedInfo = "blamejs/v1" || 0x00 || kemId || cipherId || kdfId || 0x00` (NIST SP 800-56C r2 §4.1 OtherInfo / RFC 9180 §5.1 suite_id binding; `lib/vendor/blamejs/lib/crypto.js:691-696`, `:1105-1107`). The legacy 0xE1 path concatenated `ml_kem_ss || ecdh_ss` with no domain separator and is decrypt-only during the migration window.

### L6 — Blind indexes are deterministic identifiers, not anonymizers
Email / IP / share-ID indexes use static prefixes (`hs-email:`, `hs-ip:`, etc) plus a per-deployment keyed MAC. The key closes the recompute oracle — an attacker holding only the database can't derive an index from a guessed plaintext — but indexed lookup still requires determinism, so equal values yield equal indexes within one database. They remain *identifiers*, not anonymizers. See N7.

### L7 — `random()` above 64 bytes degrades (FIXED in v1.9.11)
Resolved by switching the post-hash from SHA3-512 to SHAKE256 (variable-length XOF). See §8 for the current implementation. Retained as a numbered limitation only so the L-series numbering remains stable for cross-references in older release notes; new readers can skip to L8.

### L8 — No formal verification or symbolic model
Nothing has been modeled in ProVerif / Tamarin / Cryptol. See N9.

### L9 — Browser mTLS CA is still classical (ECDSA P-384); sync CA is now post-quantum
The **sync** CA now signs client certs with ML-DSA-87 (FIPS 204): machine sync clients run OpenSSL 3.5, which verifies a post-quantum client chain in the TLS handshake, and an existing classical sync CA auto-migrates to it at boot when the runtime can verify one (§5.8.2). The **browser** CA remains classical (ECDSA-P384-SHA384) because browsers and OS keystores still can't verify a PQ signature on a client cert or import a post-quantum PKCS#12 — issuing a PQ-signed browser cert today would break every browser mTLS session. It stays classical until keystores catch up, at which point it can migrate the same way; its generation mechanism is independent of the sync CA's (§5.8).

### L10 — @noble is a single point of trust for browser-side crypto
The entire browser-side crypto stack depends on Paul Miller's @noble libraries. They are well-regarded and audited (noble-pq has been reviewed by Cure53), but a concentrated dependency. The server Argon2id path runs through Node 24+'s built-in `crypto.argon2` (OpenSSL/Node-maintained) rather than a third-party native binding, so it is no longer a separate supply-chain trust surface.

### L11 — No AEAD binding on ML-KEM ciphertext in §5.1
The ML-KEM ciphertext carried in the envelope is not authenticated by the outer AEAD tag. An attacker flipping bits in `kem.ct` causes decapsulation to fail (ML-KEM has implicit rejection) but the failure mode is not cryptographically enforced by Poly1305 — it's enforced by ML-KEM's own implicit rejection. This is probably fine (ML-KEM is designed for this) but worth a second opinion.

### L12 — First-run password is weak for concurrent attackers
On first boot the admin password is printed to stdout and written to `data/initial-admin-password.txt`. Any attacker with log access or filesystem access before the operator logs in can capture it. See N11. No easy fix — the alternative (forcing password set before any access) is worse UX.

### L13 — No rate limit on ML-KEM decapsulation
An attacker sending malformed envelopes forces server-side ML-KEM decapsulation per attempt. ML-KEM is fast (~0.1 ms) so this isn't a realistic DoS vector, but it's uncapped.

### L14 — Session cookie forward secrecy
Vault-sealed session data means a later vault compromise decrypts all captured cookies. Per-session ephemeral keys would fix this but add complexity and don't match the threat model (see §3 — we don't defend against host compromise, and in-transit protection is already provided by TLS).

### L15 — Passphrase material in process memory (v1.9+ opt-in path)
When passphrase wrapping is enabled (§5.2 opt-in), the passphrase and the derived wrapping key exist in process memory briefly during boot:

1. `passphrase-source.js` reads the passphrase from env/file/stdin as a `Buffer`
2. `b.vaultWrap.wrap()` (`lib/vendor/blamejs/lib/vault/wrap.js`) passes it to Argon2id
3. The resulting 32-byte wrapping key decrypts the sealed file
4. The plaintext vault key is cached in the vault module's local `keys` variable for the process lifetime

Node.js provides no mechanism to zero a Buffer's backing memory on demand. `delete process.env.VAULT_PASSPHRASE` limits exposure to later env-dump surfaces but doesn't scrub the bytes. The passphrase Buffer and wrapping-key Buffer remain GC-candidates but may persist until the allocator reuses those pages. An attacker with code execution on the running host can read them.

This is unavoidable for any at-rest encryption scheme on a service that boots without human interaction each request. The passphrase wrapping closes the disk-snapshot threat but does not close the live-host-compromise threat (which is already a non-goal — see N1). Operators who need defense against a compromised host need a completely different architecture — a hardware security module or an enclave — which is out of scope for this project.

---

## 10. Assumptions

These are properties HermitStash assumes but does not verify:

- **Node.js 24.19.0+ OpenSSL 3.5+** correctly implements ML-KEM-1024, SLH-DSA-SHAKE-256f, ML-DSA-87, ECDH P-384, SHAKE256, and HKDF-SHA3-512. Tested through the Node / OpenSSL test suites; HermitStash adds no independent validation
- **@noble libraries** correctly implement XChaCha20-Poly1305 (server + browser), SHAKE256 (browser), and ML-KEM-1024 (browser). noble-post-quantum was audited by Cure53 in 2024; noble-ciphers and noble-hashes are heavily used across the ecosystem
- **Node 24+ built-in `crypto.argon2`** correctly implements Argon2id per RFC 9106 with our chosen parameters (64 MiB memory, 3 time, 4 parallelism)
- **Host filesystem permissions are enforced**. `data/vault.key` is created with mode 0o600 and relies on the OS to honor it
- **`/dev/shm` is not readable by other tenants on shared hosts**. On multi-tenant containers, an attacker with access to the same kernel's shared memory can read session data. Single-tenant deployment is assumed
- **TLS CAs in the browser/OS trust store are not compromised** for the server's domain — see N8
- **The `node:sqlite` builtin module** handles corrupted databases safely. We rely on its error surfaces but don't independently fuzz it

---

## 11. Questions for reviewers

If you are a cryptographer willing to spend an hour on this, these are the questions that would most benefit from a second opinion. They are narrow on purpose — broad "is this secure" questions are hard to answer.

1. **Storage envelope hybrid KDF (§5.1, L5) — RESOLVED:** the active 0xE2 envelope now absorbs a suite-binding `FixedInfo` (`"blamejs/v1" || 0x00 || kemId || cipherId || kdfId || 0x00`) alongside the shared secrets, so `SHAKE256(ml_kem_ss || ecdh_ss || suiteFixedInfo)` carries explicit domain separation (NIST SP 800-56C r2 §4.1 / RFC 9180 §5.1).

2. **Envelope header as AAD (§5.1, L4) — RESOLVED:** the active 0xE2 envelope binds the 4-byte header (magic | KEM | cipher | KDF) as AEAD AAD, so a header flip surfaces as a Poly1305 tag failure.

3. **ML-KEM ciphertext integrity (§5.1, L11):** ML-KEM's implicit rejection handles tampered ciphertexts correctly, but should we add a belt-and-suspenders construction (AEAD with AAD = kem.ct, say) before the symmetric step?

4. **ECIES construction (§5.6.2) — WITHDRAWN:** the construction this asked about no longer exists. It combined an ML-KEM shared secret with an ECDH one under HKDF-SHA3-512, and post-quantum client certificates left no ECDH key to derive the second secret from.

5. **PRF-derived ML-KEM keygen (§5.7):** Deriving an ML-KEM-1024 keypair deterministically from a 32-byte PRF seed expanded to 64 bytes. Is the FIPS 203 `d || z` decomposition correctly handled? Is there any risk from the PRF not being uniform enough for ML-KEM's expected input distribution?

6. **Static salt on WebAuthn PRF (§5.7):** We use `"hermitstash-vault-prf-v1-salt-00"` as the PRF salt, not a per-user value. Is there a reason to prefer per-user? If the user re-registers a passkey against a different account on the same authenticator, they should get a different seed — which they do, because the credential ID itself differs.

7. **Argon2 parameters:** 64 MiB memory, 3 time, 4 parallelism. Adequate for 2026? Too low? Too high? The target is "painful for offline attack, acceptable for 100ms login".

8. **Randomness wrapper (§8):** Cargo cult or defense-in-depth? Happy to remove the SHA3 wrapper if the consensus is it adds no value.

9. **Blind-index strategy (§5.3, L6):** static prefixes plus a per-deployment keyed MAC (HMAC-SHAKE256) give deterministic indexed lookup while closing the plaintext-recompute oracle, without per-record salts (which would break indexed lookup entirely). Is keying off a single per-deployment secret the right granularity, or is there value in per-column keys?

10. **Browser-CA PKCS#12 parameters (§5.8):** AES-256-CBC + HMAC-SHA-512 (RFC 7292 MacData) + PBKDF2 + 2M iterations. The browser CA (and its `.p12` packaging) is deliberately kept classical for keystore/importer compatibility. Is the ongoing AES-CBC + legacy-MacData choice a reasonable tradeoff, or should we force AES-GCM / PBMAC1 and accept the importer breakage?

---

## 12. How to report findings

Security reports: **see [SECURITY.md](../SECURITY.md)** for the coordinated-disclosure policy. Non-sensitive feedback on this document itself is welcome via GitHub issues.

## 13. Changelog

| Date | Version | Change |
|------|---------|--------|
| 2026-04-21 | v1.8.25 | Initial draft against v1.8.25 |
| 2026-08-01 | v1.14.0 | Sync CA moved to ML-DSA-87 (FIPS 204) with a classical-to-post-quantum boot auto-migration and a 30-day grace window; separate classical ECDSA-P384-SHA384 browser CA; certificate engine on the @blamejs/pki toolkit |

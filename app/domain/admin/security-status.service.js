/**
 * The security-posture report behind Admin → Security.
 *
 * An operator reads these rows to decide whether a deployment is safe to
 * expose, so a row that reports the wrong state is worse than no row: it is a
 * green light over an open door. Every value is derived from a handful of
 * booleans, and the combinations are what decide what each row claims.
 *
 * Kept apart from the route for that reason. The route gathers the state — env
 * vars, which key files exist, what the running process recorded — and this
 * decides what to say about it, so the decisions can be exercised across the
 * whole matrix instead of only the one state a live server happens to be in.
 * The TLS row already reported "enabled" on a server running plain HTTP once,
 * because it was reading the key and not the certificate.
 *
 * buildReport() touches no filesystem, no env and no clock. Anything it needs
 * is a field on `state`, which is what makes the matrix testable.
 */

/**
 * @param {object} state
 *   vaultMode            VAULT_PASSPHRASE_MODE, lowercased ("disabled" default)
 *   vaultSealedExists    data/vault.key.sealed present
 *   vaultKeyExists       data/vault.key present
 *   caKeyMode            CA_KEY_SEALED, lowercased ("auto" default)
 *   caSealedExists       data/ca.key.sealed present
 *   caPlainExists        data/ca.key present
 *   caExists             a CA has been generated
 *   tlsKeyMode           TLS_KEY_SEALED, lowercased ("auto" default)
 *   tlsSealedExists      the resolved TLS key's ".sealed" sibling present
 *   tlsPlainExists       the resolved TLS key present
 *   tlsCertExists        the TLS chain present
 *   tlsKeyExists         either TLS key form present
 *   tlsServing           whether the process is actually serving TLS
 *   enforceMtlsStrict    raw ENFORCE_MTLS_STRICT ("true" / "false" / undefined)
 *   mtlsHardEnforced     handshake-level enforcement is in force
 *   mtlsSoftEnforced     app-layer enforcement is in force
 * @returns {{items: object[], notes: string[]}}
 */
function buildReport(state) {
  var vaultMode = state.vaultMode;
  var vaultSealedExists = state.vaultSealedExists;
  var caKeyMode = state.caKeyMode;
  var caSealedExists = state.caSealedExists;
  var caPlainExists = state.caPlainExists;
  var caExists = state.caExists;
  var tlsKeyMode = state.tlsKeyMode;
  var tlsSealedExists = state.tlsSealedExists;
  var tlsPlainExists = state.tlsPlainExists;
  var tlsCertExists = state.tlsCertExists;
  var tlsKeyExists = state.tlsKeyExists;
  var tlsServing = state.tlsServing;
  var enforceMtlsStrict = state.enforceMtlsStrict;
  var mtlsHardEnforced = state.mtlsHardEnforced;
  var mtlsSoftEnforced = state.mtlsSoftEnforced;

  // Each item: a stable key, label, status (ok|warn|info), short description,
  // optional operator guidance. The frontend renders one row per item with an
  // icon based on status.
  //
  // `actions` is each button the UI may render:
  //   { kind: "seal" | "unseal", route, needsPassphrase, label, confirmText }
  // Empty when no action applies — the state is already what the button would
  // produce, or the underlying file is not there.
  var items = [
    {
      key: "vault_passphrase",
      label: "Vault key passphrase wrapping",
      status: vaultMode === "required" && vaultSealedExists ? "ok" : (vaultMode === "required" ? "warn" : "info"),
      value: vaultMode === "required" ? "active (vault.key.sealed)" : "disabled (vault.key plaintext)",
      description: "Encrypts the long-lived vault keypair at rest with an Argon2id-derived key.",
      guidance: vaultMode === "required"
        ? "Set VAULT_PASSPHRASE (env), VAULT_PASSPHRASE_FILE (file path), or use stdin at boot."
        : "RECOMMENDED: enable via VAULT_PASSPHRASE_MODE=required + scripts/vault-passphrase-setup.js",
      actions: vaultSealedExists
        ? [{ kind: "unseal", route: "/admin/security/unseal/vault-passphrase", needsPassphrase: true, label: "Disable", confirmText: "This will unwrap vault.key.sealed back to plaintext. You'll need to unset VAULT_PASSPHRASE_MODE before the next restart." }]
        : (state.vaultKeyExists ? [{ kind: "seal", route: "/admin/security/seal/vault-passphrase", needsPassphrase: true, label: "Enable", confirmText: "After enabling, you MUST add VAULT_PASSPHRASE_FILE=/path to your environment AND drop the passphrase into that file BEFORE the next server restart, OR the next restart will FAIL." }]
            : []),
    },
    {
      key: "ca_key_sealed",
      label: "mTLS CA private key sealing",
      status: caKeyMode === "required" && caSealedExists ? "ok" : (caExists && !caSealedExists ? "info" : "info"),
      value: caSealedExists ? "active (ca.key.sealed)" : (caPlainExists ? "disabled (ca.key plaintext)" : "no CA generated yet"),
      description: "Vault-seals the mTLS root signing key. Compromise of this key allows forging client certs forever.",
      guidance: caSealedExists
        ? "Set CA_KEY_SEALED=required to enforce on subsequent boots."
        : (caExists ? "RECOMMENDED: scripts/ca-key-seal.js (works with server running)" : "Will be configured on first cert-issue operation."),
      actions: caSealedExists
        ? [{ kind: "unseal", route: "/admin/security/unseal/ca-key", needsPassphrase: false, label: "Disable", confirmText: "This will unwrap ca.key.sealed back to plaintext data/ca.key. Unset CA_KEY_SEALED before restart." }]
        : (caPlainExists ? [{ kind: "seal", route: "/admin/security/seal/ca-key", needsPassphrase: false, label: "Enable", confirmText: "Wraps data/ca.key with the vault key. CA loads via dispatch on next cert op — no restart needed. Set CA_KEY_SEALED=required to enforce on subsequent boots." }]
            : []),
    },
    {
      key: "tls_key_sealed",
      label: "TLS server private key sealing",
      status: tlsKeyMode === "required" && tlsSealedExists ? "ok" : (tlsPlainExists && !tlsSealedExists ? "info" : "info"),
      value: tlsSealedExists ? "active (privkey.pem.sealed)" : (tlsPlainExists ? "disabled (privkey.pem plaintext)" : "no TLS key configured"),
      description: "Vault-seals the TLS server private key. Cert watcher auto-seals plaintext renewals from ACME (certbot/acme.sh).",
      guidance: tlsSealedExists
        ? "Set TLS_KEY_SEALED=required to enforce; ACME hooks need no changes."
        : (tlsPlainExists ? "RECOMMENDED: scripts/tls-key-seal.js" : "Configure TLS first (see TLS section)."),
      actions: tlsSealedExists
        ? [{ kind: "unseal", route: "/admin/security/unseal/tls-key", needsPassphrase: false, label: "Disable", confirmText: "Unwraps privkey.pem.sealed. Cert watcher will reload immediately. Unset TLS_KEY_SEALED before restart." }]
        : (tlsPlainExists ? [{ kind: "seal", route: "/admin/security/seal/tls-key", needsPassphrase: false, label: "Enable", confirmText: "Wraps tls/privkey.pem with the vault key. Cert watcher reloads immediately (SIGHUP). ACME renewal hooks need NO changes — future plaintext renewals are auto-sealed." }]
            : []),
    },
    {
      key: "mtls_enforcement",
      label: "mTLS enforcement",
      status: mtlsHardEnforced ? "ok" : (mtlsSoftEnforced ? "info" : "warn"),
      value: enforceMtlsStrict === "false" ? "OFF (escape hatch)" :
        (mtlsHardEnforced ? "hard (TLS layer)" : (mtlsSoftEnforced ? "soft (app layer)" : "off")),
      description: "Hard mode rejects non-mTLS at the TLS handshake; soft mode rejects in middleware. Hard is stricter and faster.",
      guidance: enforceMtlsStrict === "false"
        ? "ENFORCE_MTLS_STRICT=false is the escape hatch for locked-out operators. Remove once recovered."
        : (mtlsHardEnforced ? "Set via ENFORCE_MTLS_STRICT=true (env)."
          // Asked for hard enforcement and cannot have it. Repeating "set
          // ENFORCE_MTLS_STRICT=true" would be advice already followed, and
          // would leave the operator believing client certificates are
          // required. What is true depends on whether the app-layer check is
          // picking up the slack, so the two cases say different things —
          // claiming nothing is enforced while the middleware is enforcing
          // would be the same kind of wrong this row is being fixed for.
          : (enforceMtlsStrict === "true" && caExists && !tlsServing
            ? (mtlsSoftEnforced
              ? "ENFORCE_MTLS_STRICT=true is set, but hard enforcement is a TLS-listener setting and this server is running without TLS, so it is not in force. Client certificates are still required by the app-layer check (ENFORCE_MTLS). Fix the TLS row above to get handshake-level enforcement."
              : "ENFORCE_MTLS_STRICT=true is set, but hard enforcement is a TLS-listener setting and this server is running without TLS — no client certificate is required on any connection. Fix the TLS row above, or set ENFORCE_MTLS=true for app-layer enforcement in the meantime.")
            : "Set ENFORCE_MTLS_STRICT=true for hard enforcement at the TLS layer.")),
      actions: [], // env-only; no UI action available
    },
    {
      key: "tls",
      label: "TLS / HTTPS",
      status: tlsServing ? "ok" : "warn",
      value: tlsServing ? "enabled"
        : (tlsKeyExists && !tlsCertExists ? "disabled (HTTP only) — key present, certificate missing"
          : (tlsCertExists && !tlsKeyExists ? "disabled (HTTP only) — certificate present, key missing"
            : "disabled (HTTP only)")),
      description: "PQC TLS 1.3 with a post-quantum hybrid key exchange (SecP384r1MLKEM1024 preferred, then X25519MLKEM768, then SecP256r1MLKEM768) when both client + server support it.",
      guidance: tlsServing ? null
        : (tlsKeyExists && !tlsCertExists
          ? "The key is in place but the certificate is not, so the server started in HTTP mode. Mount the chain at data/tls/fullchain.pem or set TLS_CERT, then restart."
          : "Mount cert + key into data/tls/ or set TLS_CERT and TLS_KEY env vars."),
      actions: [], // config-only; no UI action available
    },
  ];

  // Two-pattern note: not every env var follows the same convention.
  // Surfacing it here so operators don't get confused looking at the
  // tab and seeing inconsistent flag styles.
  var notes = [
    "Two env-var conventions are in use: (a) *_SEALED / *_MODE = auto/required/disabled (newer); (b) ENFORCE_MTLS_STRICT = true/false/unset (older, with 'false' as escape hatch). Both are intentional.",
    "Boot-time secrets (VAULT_PASSPHRASE, BACKUP_PASSPHRASE) are not displayed here — by design. Set them via env vars OR _FILE-suffix variants for Docker secrets.",
  ];

  return { items: items, notes: notes };
}

module.exports = { buildReport: buildReport };

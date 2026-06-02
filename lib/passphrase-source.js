"use strict";
/**
 * Passphrase source — wraps blamejs's `b.vaultPassphraseSource`.
 *
 * blamejs's primitive defaults to the `BLAMEJS_VAULT_PASSPHRASE_*`
 * env-var namespace; HermitStash has always used the un-prefixed
 * `VAULT_PASSPHRASE_*` names (documented in the deploy README and
 * referenced from docker-compose / Caddy / nginx examples). This
 * wrapper bakes the HermitStash env-var names into the `envVars`
 * option on every call so the public surface, error messages, and
 * caller code (lib/vault.js + scripts/vault-passphrase-*.js +
 * scripts/vault-key-rotate.js + tests) all keep their existing
 * shape across the swap.
 *
 * This wrapper stays a one-line indirection until every caller passes
 * `envVars` explicitly; collapsing it then is cheaper than touching all
 * eight call sites at once.
 */
var b = require("./vendor/blamejs");
var bSource = b.vaultPassphraseSource;

var HERMITSTASH_ENV_VARS = Object.freeze({
  value:  "VAULT_PASSPHRASE",
  file:   "VAULT_PASSPHRASE_FILE",
  source: "VAULT_PASSPHRASE_SOURCE",
});

function _withEnvVars(opts) {
  // Always inject HermitStash's env-var names; caller-supplied envVars
  // win when present (test harnesses + future scripts that need a
  // different namespace). Object.assign right-to-left so opts.envVars
  // overrides the default.
  if (opts && opts.envVars) return opts;
  return Object.assign({ envVars: HERMITSTASH_ENV_VARS }, opts || {});
}

async function getPassphrase(opts) {
  return bSource.getPassphrase(_withEnvVars(opts));
}

async function fromEnv(opts) {
  return bSource.fromEnv(_withEnvVars(opts));
}

async function fromFile(filePath, opts) {
  return bSource.fromFile(filePath, _withEnvVars(opts));
}

async function fromStdin(promptText) {
  // No env-var lookup in the stdin path; pass through.
  return bSource.fromStdin(promptText);
}

function sourceKind(opts) {
  return bSource.sourceKind(_withEnvVars(opts));
}

module.exports = {
  getPassphrase: getPassphrase,
  fromEnv:       fromEnv,
  fromFile:      fromFile,
  fromStdin:     fromStdin,
  sourceKind:    sourceKind,
  // Re-export blamejs's MAX_PASSPHRASE_BYTES so tests asserting against
  // it stay consistent with the underlying primitive.
  MAX_PASSPHRASE_BYTES: bSource.MAX_PASSPHRASE_BYTES,
};

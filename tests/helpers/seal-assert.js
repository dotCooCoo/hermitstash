/**
 * Shared sealing assertions for zero-plaintext / sealed-PII tests.
 *
 * Sealed column values are AEAD-bound to their (table, row, column) identity
 * and carry the "vault.aad:" prefix; legacy "vault:" values still read via
 * dual-read. A bare vault.unseal() only handles the legacy "vault:" prefix
 * (it returns a "vault.aad:" value unchanged), so AAD-bound values must be
 * unsealed through field-crypto's row-aware path.
 */
var path = require("path");
var projectRoot = path.join(__dirname, "..", "..");

var VAULT_PREFIX = "vault:";
var AAD_PREFIX = "vault.aad:";

// True if the value is sealed in either the AAD-bound or legacy envelope.
function isSealed(value) {
  return typeof value === "string" &&
    (value.startsWith(AAD_PREFIX) || value.startsWith(VAULT_PREFIX));
}

// Unseal a single sealed column value, supplying the row identity so an
// AAD-bound cell decrypts. Handles both the legacy and AAD-bound envelopes.
function unsealField(table, rowId, column, value) {
  var fieldCrypto = require(path.join(projectRoot, "lib", "field-crypto"));
  var doc = {};
  doc[column] = value;
  return fieldCrypto.unsealDoc(table, doc, rowId)[column];
}

module.exports = {
  isSealed: isSealed,
  unsealField: unsealField,
  VAULT_PREFIX: VAULT_PREFIX,
  AAD_PREFIX: AAD_PREFIX,
};

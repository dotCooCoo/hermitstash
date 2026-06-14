"use strict";

// framework-files — the single source of truth for the framework's on-disk
// state file names. Centralized (mirroring framework-schema's table-name
// registry) so a rename / relocation is a one-line change and no module
// hardcodes the literal. Every owner resolves its file name through
// fileName(logical) instead of embedding the string; the codebase-patterns
// `no-hardcoded-framework-file-name` detector drives the remaining owners
// onto this registry in reverse (a file that still hardcodes a registered
// name fails the gate once it leaves the migration backlog).
//
// Internal infrastructure (not a public b.* namespace) — consumed by db /
// vault / audit / backup the way constants.js is.

var { FrameworkError } = require("./framework-error");

// Canonical state file names. Each is a BARE file name (no path) joined onto
// the operator's dataDir / a sub-path by the owner. Security-/durability-
// sensitive files only — templated names (e.g. the hashed working-db file)
// are not registered here.
var DEFAULT_FILE_NAMES = Object.freeze({
  dbEnc:         "db.enc",          // encrypted-at-rest database ciphertext
  dbKeyEnc:      "db.key.enc",      // sealed database encryption key
  vaultKey:      "vault.key",       // sealed vault keypair
  auditTip:      "audit.tip",       // audit rollback-detection sidecar
  auditSignKey:  "audit-sign.key",  // sealed audit-signing keypair
  rowsEnc:       "rows.enc",        // archive/backup rows ciphertext member
  checkpointEnc: "checkpoint.enc",  // archive/backup checkpoint ciphertext member
});

var _overrides = {};

// fileName(logical) — resolve a logical file key to its configured (or
// default) bare file name. Defensive request-shape reader: throws on an
// unknown logical key (a typo is a boot-time bug, not a runtime default).
function fileName(logical) {
  if (Object.prototype.hasOwnProperty.call(_overrides, logical)) return _overrides[logical];
  if (Object.prototype.hasOwnProperty.call(DEFAULT_FILE_NAMES, logical)) {
    return DEFAULT_FILE_NAMES[logical];
  }
  throw new FrameworkError(
    "frameworkFiles.fileName: unknown logical file '" + logical + "'",
    "framework-files/unknown");
}

// setFileName(logical, name) — config-time override of a state file name.
// THROW on bad input (entry-point tier): the override must name a known
// logical key and be a bare file name (no path separators, no '..') so it
// can't redirect a sealed-key write outside the data dir.
function setFileName(logical, name) {
  if (!Object.prototype.hasOwnProperty.call(DEFAULT_FILE_NAMES, logical)) {
    throw new FrameworkError(
      "frameworkFiles.setFileName: unknown logical file '" + logical + "'",
      "framework-files/unknown");
  }
  if (typeof name !== "string" || name.length === 0 ||
      name.indexOf("/") !== -1 || name.indexOf("\\") !== -1 || name.indexOf("..") !== -1) {
    throw new FrameworkError(
      "frameworkFiles.setFileName: name must be a non-empty bare file name " +
      "(no path separators or '..')", "framework-files/bad-name");
  }
  _overrides[logical] = name;
}

// Test/boot helper — drop all overrides back to the defaults.
function _resetForTest() { _overrides = {}; }

module.exports = {
  fileName:          fileName,
  setFileName:       setFileName,
  DEFAULT_FILE_NAMES: DEFAULT_FILE_NAMES,
  _resetForTest:     _resetForTest,
};

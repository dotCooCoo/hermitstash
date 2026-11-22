/**
 * The one CommonJS entry point to the vendored @blamejs/stash package.
 *
 * The package is ESM and loads here through require(esm). Every other module
 * imports this file rather than reaching into lib/vendor/stash/, and only
 * lib/storage.js constructs a Stash (both enforced by the codebase-patterns
 * lint gate).
 */
var stash = require("./vendor/stash/src/index.js");
var disk = require("./vendor/stash/src/backends/disk.js");

module.exports = {
  Stash: stash.Stash,
  DiskBackend: disk.DiskBackend,
  StashError: stash.StashError,
  RefNotFound: stash.RefNotFound,
  RefClaimed: stash.RefClaimed,
  IntegrityError: stash.IntegrityError,
  version: stash.version,
};

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * lib/module-loader.js — the single audited entry point for loading an
 * operator-supplied module file (a migration or a seed) by path.
 *
 * Operator modules execute arbitrary code on `require`, so the dynamic
 * `require()` lives here behind ONE `allow:dynamic-require-operator-module` marker rather
 * than scattered across every host-CLI loader (`b.migrations`,
 * `b.seeders`, `b.externalDb.migrate`). The require cache is busted first
 * so a dev / test rewriting a fixture between calls picks up the new
 * content (production deployments restart the process). The dynamic
 * require does not survive SEA / esbuild bundling — operator migrations
 * and seeds are host-CLI scope, not framework-internal scope.
 *
 * The caller owns path construction (it knows its own directory layout)
 * and the typed, domain-specific error it throws on a load failure
 * (parse error, throwing top-level code), so resolution stays identical
 * to the per-loader form it replaces.
 */

/**
 * requireFresh(absPath, onLoadError) — bust the require cache for
 * `absPath`, then require it fresh. `absPath` MUST be absolute (a bare
 * relative path would resolve against node_modules, which is never an
 * operator file). On a load failure, `onLoadError(err)` builds the
 * caller's typed error, which is thrown.
 *
 *   var mod = moduleLoader.requireFresh(path.join(dir, file), function (e) {
 *     return new MigrationError("migrations/load-failed",
 *       "migration '" + file + "' failed to load: " + ((e && e.message) || String(e)), true);
 *   });
 */
function requireFresh(absPath, onLoadError) {
  try { delete require.cache[require.resolve(absPath)]; } catch (_e) { /* not yet cached */ }
  try {
    return require(absPath);   // allow:dynamic-require-operator-module — operator-supplied module (migration / seed)
  } catch (e) {
    throw onLoadError(e);
  }
}

module.exports = {
  requireFresh: requireFresh,
};

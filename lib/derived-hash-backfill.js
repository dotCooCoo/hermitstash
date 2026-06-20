/**
 * Keyed-MAC blind-index backfill.
 *
 * The keyed-MAC migration in lib/field-crypto.js makes every derived blind
 * index (emailHash, shareIdHash, slugHash, codeHash, bundleShareIdHash) a keyed
 * MAC under the vault's per-deployment MAC key instead of an unkeyed,
 * plaintext-recomputable hash. New writes store the keyed digest immediately and
 * reads dual-read both digests, so the migration is already correct WITHOUT this
 * pass. This one-shot boot backfill rewrites the legacy unkeyed digests on
 * existing rows to the keyed form, so the dual-read can later be retired and no
 * recomputable index lingers at rest.
 *
 * Properties:
 *   - Idempotent + resumable: a row already carrying the keyed digest is left
 *     alone; an interrupted run re-processes the remainder on the next boot.
 *   - Non-fatal: a failure leaves the dual-read in place (reads keep working),
 *     so the pass simply retries next boot. It must never block startup.
 *   - Index-preserving: a row whose sealed source cannot be unsealed (tamper /
 *     corruption) keeps its existing index rather than being nulled.
 *   - Marker-gated: a clean pass writes C.PATHS.DERIVED_HASH_BACKFILL_MARKER;
 *     subsequent boots short-circuit. The keyed MAC key is a stable per-
 *     deployment secret (re-sealed, not regenerated, on vault rotation), so a
 *     completed backfill stays valid across rotation.
 */
var nodeFs = require("node:fs");
var b = require("./vendor/blamejs");
var C = require("./constants");
var fieldCrypto = require("./field-crypto");
var db = require("./db");

var MARKER = C.PATHS.DERIVED_HASH_BACKFILL_MARKER;
var PAGE = 500;

function isComplete() {
  try { return nodeFs.existsSync(MARKER); } catch (_e) { return false; }
}

function writeMarker(state) {
  b.atomicFile.writeSync(MARKER, JSON.stringify(state, null, 2), { fileMode: 0o600 });
}

/**
 * Run the backfill. opts: { log, dryRun, force }.
 * Returns { skipped } or { tables, checked, rewritten, sourceUnreadable }.
 */
function run(opts) {
  opts = opts || {};
  var log = opts.log || { info: function () {}, warn: function () {}, error: function () {} };
  var dryRun = !!opts.dryRun;
  if (!opts.force && isComplete()) return { skipped: true };

  var schemas = fieldCrypto.FIELD_SCHEMA;
  var tables = Object.keys(schemas).filter(function (t) { return schemas[t].derived; });

  var checked = 0, rewritten = 0, sourceUnreadable = 0;
  for (var ti = 0; ti < tables.length; ti++) {
    var table = tables[ti];
    var derived = schemas[table].derived;
    var derivedKeys = Object.keys(derived);
    var offset = 0;
    var tableRewritten = 0;
    for (;;) {
      var rows = db.rawQuery("SELECT * FROM \"" + table + "\" LIMIT ? OFFSET ?", PAGE, offset);
      if (!rows.length) break;
      for (var ri = 0; ri < rows.length; ri++) {
        var row = rows[ri];
        checked++;
        var updates = {};
        for (var di = 0; di < derivedKeys.length; di++) {
          var dk = derivedKeys[di];
          var def = derived[dk];
          var sealedSrc = row[def.from];
          if (sealedSrc === undefined || sealedSrc === null || sealedSrc === "") continue;
          var plain;
          try { plain = fieldCrypto.unsealSource(table, def.from, sealedSrc, row._id); }
          catch (_e) { plain = null; }
          if (plain === undefined || plain === null || plain === "") {
            // Source unreadable (tamper / corruption): keep the existing index
            // rather than destroying the row's lookup.
            sourceUnreadable++;
            continue;
          }
          var keyed = fieldCrypto.derivedKeyed(def.prefix, plain, def.lower);
          if (row[dk] !== keyed) updates[dk] = keyed;
        }
        var cols = Object.keys(updates);
        if (cols.length) {
          rewritten++; tableRewritten++;
          if (!dryRun) {
            var setSql = cols.map(function (c) { return "\"" + c + "\" = ?"; }).join(", ");
            var vals = cols.map(function (c) { return updates[c]; });
            vals.push(row._id);
            db.rawExec.apply(null, ["UPDATE \"" + table + "\" SET " + setSql + " WHERE _id = ?"].concat(vals));
          }
        }
      }
      offset += PAGE;
    }
    if (tableRewritten > 0) {
      log.info("[derived-hash] " + table + " — " + tableRewritten + (dryRun ? " rows WOULD be re-keyed" : " rows re-keyed"));
    }
  }

  if (!dryRun) {
    writeMarker({ completedAt: new Date().toISOString(), checked: checked, rewritten: rewritten, sourceUnreadable: sourceUnreadable });
  }
  return { tables: tables.length, checked: checked, rewritten: rewritten, sourceUnreadable: sourceUnreadable };
}

module.exports = { run: run, isComplete: isComplete };

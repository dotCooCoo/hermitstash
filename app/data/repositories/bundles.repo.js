/**
 * Bundles Repository — persistence logic for upload bundles.
 */
var db = require("../../../lib/db");
var { bundles } = db;

function findById(id) { return bundles.findOne({ _id: id }); }
function findByShareId(shareId) { return bundles.findOne({ shareId: shareId }); }
function findAll(query) { return bundles.find(query || {}); }
function findPaginated(query, opts) { return bundles.findPaginated(query, opts); }
function count(query) { return bundles.count(query || {}); }

function create(doc) { return bundles.insert(doc); }
function update(id, ops) { return bundles.update({ _id: id }, ops); }
function remove(id) { return bundles.remove({ _id: id }); }

/**
 * Atomically increment `seq` by 1 and return the new value.
 *
 * Parallel uploads to the same sync bundle previously did
 *   var bundle = findById(id);
 *   await storage.saveFile(...);       // yields event loop
 *   update(id, { seq: (bundle.seq||0)+1 });
 * which under concurrency produced duplicate seq values on the WS stream
 * (downstream clients use `seq > lastSeq` for catch-up and silently drop
 * duplicates). This helper uses SQLite's `UPDATE ... RETURNING` so the
 * read-modify-write happens in one atomic statement.
 *
 * Returns the new seq value as an integer. `seq` is not a vault-sealed
 * column (it's a monotonic counter, not PII), so raw SQL is safe here.
 */
function incrementSeq(id) {
  var row = db.rawGet(
    "UPDATE bundles SET seq = COALESCE(seq, 0) + 1 WHERE _id = ? RETURNING seq",
    id
  );
  return row ? row.seq : null;
}

module.exports = { findById, findByShareId, findAll, findPaginated, count, create, update, remove, incrementSeq };

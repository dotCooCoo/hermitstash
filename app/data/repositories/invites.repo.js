var { invites } = require("../../../lib/db");
var { timingSafeEqual } = require("../../../lib/crypto");

function findAll(query) { return invites.find(query || {}); }
function findOne(query) { return invites.findOne(query); }
function create(doc) { return invites.insert(doc); }
function update(id, ops) { return invites.update({ _id: id }, ops); }
function remove(id) { return invites.remove({ _id: id }); }

// Record that the invite email for one specific token was sent. tokenHash is
// sealed, so the row is read back and compared here; the update is skipped
// when a later resend has replaced the token. Returns true when it updated.
function markEmailed(id, tokenHash) {
  if (!id || typeof tokenHash !== "string" || !tokenHash) return false;
  var row = invites.findOne({ _id: id });
  if (!row || typeof row.tokenHash !== "string" || row.tokenHash.length !== tokenHash.length) return false;
  if (!timingSafeEqual(row.tokenHash, tokenHash)) return false;
  invites.update({ _id: id }, { $set: { delivery: "email" } });
  return true;
}

module.exports = { findAll, findOne, create, update, remove, markEmailed };

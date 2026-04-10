/**
 * Export Service — CSV export with formula injection protection.
 */
var { users, files } = require("../../../lib/db");
var { buildCsv, csvSafe } = require("../../security/csv-policy");

/**
 * Export users as CSV string.
 */
function exportUsersCsv() {
  var allUsers = users.find({});
  return buildCsv(
    ["id", "email", "displayName", "role", "status", "authType", "createdAt", "lastLogin"],
    allUsers,
    function (u) {
      return [u._id, u.email, u.displayName, u.role, u.status || "active", u.authType || "local", u.createdAt || "", u.lastLogin || ""];
    }
  );
}

/**
 * Export files as CSV string.
 */
function exportFilesCsv() {
  var allFiles = files.find({});
  return buildCsv(
    ["id", "shareId", "originalName", "size", "mimeType", "uploadedBy", "uploaderEmail", "status", "downloads", "createdAt"],
    allFiles,
    function (f) {
      return [f._id, f.shareId, f.originalName, f.size || 0, f.mimeType || "", f.uploadedBy || "", f.uploaderEmail || "", f.status || "", f.downloads || 0, f.createdAt || ""];
    }
  );
}

module.exports = { exportUsersCsv, exportFilesCsv };

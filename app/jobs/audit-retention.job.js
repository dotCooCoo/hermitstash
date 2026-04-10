/**
 * Audit Retention Job — purges old audit log entries per retention policy.
 */
var { rawExec } = require("../../lib/db");
var audit = require("../../lib/audit");

/**
 * Delete audit entries older than the given number of days.
 */
function purgeOldEntries(retentionDays) {
  if (!retentionDays || retentionDays <= 0) return 0;
  var cutoff = new Date(Date.now() - retentionDays * 86400000).toISOString();
  try {
    var result = rawExec("DELETE FROM audit_log WHERE createdAt < ?", cutoff);
    var removed = result.changes || 0;
    if (removed > 0) {
      try { audit.log(audit.ACTIONS.AUDIT_RETENTION_CLEANUP, { performedBy: "system", details: "Removed " + removed + " entries older than " + retentionDays + " days" }); } catch (_e) {}
    }
    return removed;
  } catch (e) { console.error("Audit retention cleanup error:", e.message); return 0; }
}

module.exports = { purgeOldEntries };

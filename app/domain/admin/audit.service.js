/**
 * Audit Service — business logic for querying and filtering audit logs.
 * Uses SQL-level filtering for date ranges and action types where possible,
 * falls back to JS filtering for text search (sealed fields can't be searched in SQL).
 */
var auditRepo = require("../../data/repositories/audit.repo");
var audit = require("../../../lib/audit");
var b = require("../../../lib/vendor/blamejs");

// Cap on a single decrypted export. Large exports unseal every row in memory, so
// bound it; the operator narrows the date range for a deeper slice. Surfaced to
// the caller via { truncated } so the UI can warn rather than silently drop rows.
var EXPORT_MAX = 25000;

// Shared post-unseal filter for the viewer + exports. Date range, exact action,
// and free-text across the unsealed fields incl. the WHERE/HOW context (IP, path,
// performer id) so an investigator can pivot on an address or request path.
function applyFilters(entries, opts) {
  var q = (opts.q || "").toLowerCase();
  var actionFilter = opts.action || "";
  var dateFrom = opts.dateFrom || "";
  var dateTo = opts.dateTo || "";
  if (dateFrom || dateTo) {
    entries = entries.filter(function (e) {
      if (!e.createdAt) return false;
      if (dateFrom && e.createdAt < dateFrom) return false;
      if (dateTo && e.createdAt > dateTo + "T23:59:59.999Z") return false;
      return true;
    });
  }
  if (actionFilter) {
    entries = entries.filter(function (e) { return e.action === actionFilter; });
  }
  if (q) {
    entries = entries.filter(function (e) {
      return (e.action || "").toLowerCase().includes(q) ||
        (e.details || "").toLowerCase().includes(q) ||
        (e.targetEmail || "").toLowerCase().includes(q) ||
        (e.performedByEmail || "").toLowerCase().includes(q) ||
        (e.targetId || "").toLowerCase().includes(q) ||
        (e.performedBy || "").toLowerCase().includes(q) ||
        (e.ip || "").toLowerCase().includes(q) ||
        (e.path || "").toLowerCase().includes(q) ||
        (e.userAgent || "").toLowerCase().includes(q);
    });
  }
  return entries;
}

/**
 * Query audit log with filters, search, date range, and pagination.
 * Optimized: date range and action filtering happen in SQL when fields are not sealed.
 * Text search happens in JS after unsealing (unavoidable with field-level encryption).
 */
function queryAuditLog(opts) {
  var q = (opts.q || "").toLowerCase();
  var actionFilter = opts.action || "";
  var dateFrom = opts.dateFrom || "";
  var dateTo = opts.dateTo || "";
  var page = Math.max(1, parseInt(opts.page, 10) || 1);
  var limit = Math.max(1, Math.min(200, parseInt(opts.limit, 10) || 50));

  // Any JS-side filter (text search, action, or date range — all of which run
  // after unseal) means SQL can't paginate for us: fetch a broad window from
  // offset 0 and slice after filtering. With no JS filter, SQL paginates the
  // page directly and COUNT(*) gives the true total.
  var jsFilter = !!(q || actionFilter || dateFrom || dateTo);
  var sqlLimit = jsFilter ? 5000 : limit;
  var sqlOffset = jsFilter ? 0 : (page - 1) * limit;
  var fetchOpts = { limit: sqlLimit, offset: sqlOffset, orderBy: "createdAt", orderDir: "desc" };

  var query = {};
  var all = auditRepo.findPaginated(query, fetchOpts);
  var entries = all.data;

  entries = applyFilters(entries, { q: q, action: actionFilter, dateFrom: dateFrom, dateTo: dateTo });

  // With a JS filter, `entries` holds the full filtered set → slice the page
  // and count it. Without one, SQL already returned exactly the page and
  // COUNT(*) (all.total) is the real total.
  var total = jsFilter ? entries.length : all.total;
  var paged = jsFilter ? entries.slice((page - 1) * limit, page * limit) : entries;
  var pages = Math.ceil(total / limit) || 1;

  return { entries: paged, total: total, page: page, pages: pages, limit: limit };
}

/**
 * Verify the audit tamper-evidence chain end to end. Walks every audit_log row
 * in monotonicCounter order, recomputing each rowHash, and returns the verifier
 * result ({ ok:true, rowsVerified, lastHash } on a clean walk, or { ok:false,
 * breakAt, reason, ... } on the first mismatch). Reuses the SAME query callbacks
 * lib/audit.js writes through so the verify reads the live chain.
 */
function verifyAuditChain() {
  return b.auditChain.verifyChain(audit.chainQueryAll, "audit_log", {});
}

// ---- Decrypt + export ----

// The full filtered, unsealed entry set for a download, bounded by EXPORT_MAX.
// Newest-first; { truncated } true when the cap clipped the set.
function exportAuditLog(opts) {
  opts = opts || {};
  var all = auditRepo.findPaginated({}, { limit: EXPORT_MAX + 1, offset: 0, orderBy: "createdAt", orderDir: "desc" });
  var entries = applyFilters(all.data, opts);
  var truncated = entries.length > EXPORT_MAX;
  if (truncated) entries = entries.slice(0, EXPORT_MAX);
  return { entries: entries, truncated: truncated };
}

// Columns for a decrypted CSV/JSON export — the full who/what/when/where/how.
var EXPORT_FIELDS = ["createdAt", "action", "performedByEmail", "performedBy", "targetEmail",
  "targetId", "details", "ip", "method", "path", "authType", "userAgent", "requestId"];

// Outcome heuristic for CADF from the action verb (failed/denied/rejected/blocked/
// error → failure; else success). CADF only models success|failure|unknown.
function cadfOutcome(action) {
  var a = String(action || "").toLowerCase();
  if (/fail|denied|deny|reject|block|error|invalid|unauthorized|locked/.test(a)) return "failure";
  return "success";
}

// Map an unsealed HS audit entry onto the blamejs row shape b.auditTools.exportCadf
// expects (recordedAt ms, actorUserId, actorIp, resourceId, reason, metadata, chain).
function toCadfRow(e) {
  var meta = {};
  ["method", "path", "authType", "userAgent", "performedByEmail", "targetEmail"].forEach(function (k) {
    if (e[k]) meta[k] = e[k];
  });
  // createdAt is always a server-set ISO string; guard anyway so a malformed value
  // resolves to null (→ epoch downstream) instead of NaN (→ RangeError on toISOString).
  var ts = e.createdAt ? Date.parse(e.createdAt) : NaN;
  return {
    _id: e._id,
    recordedAt: isNaN(ts) ? null : ts,
    action: e.action,
    outcome: cadfOutcome(e.action),
    actorUserId: e.performedBy || undefined,
    actorIp: e.ip || undefined,
    actorSessionId: e.requestId || undefined,
    resourceId: e.targetId || undefined,
    reason: e.details || undefined,
    metadata: Object.keys(meta).length ? meta : undefined,
    monotonicCounter: e.monotonicCounter,
    prevHash: e.prevHash,
    rowHash: e.rowHash,
  };
}

// CADF (Cloud Auditing Data Federation, ISO/IEC 19395) event batch for SIEM/
// compliance tooling. Decrypted — admin-only. Built from the already-unsealed
// entries via the stateless b.auditTools.exportCadf with an injected reader.
function exportCadf(entries, opts) {
  opts = opts || {};
  var rows = entries.map(toCadfRow);
  return b.auditTools.exportCadf({
    from: opts.dateFrom || undefined,
    to: opts.dateTo || undefined,
    action: opts.action || undefined,
    readRows: function () { return rows; },
  });
}

module.exports = {
  queryAuditLog: queryAuditLog,
  verifyAuditChain: verifyAuditChain,
  exportAuditLog: exportAuditLog,
  exportCadf: exportCadf,
  EXPORT_FIELDS: EXPORT_FIELDS,
};

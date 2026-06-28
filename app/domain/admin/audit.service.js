/**
 * Audit Service — business logic for querying and filtering audit logs.
 * Uses SQL-level filtering for date ranges and action types where possible,
 * falls back to JS filtering for text search (sealed fields can't be searched in SQL).
 */
var auditRepo = require("../../data/repositories/audit.repo");
var audit = require("../../../lib/audit");
var b = require("../../../lib/vendor/blamejs");

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

  // Date filtering (JS fallback if not handled by SQL — sealed createdAt)
  if (dateFrom || dateTo) {
    entries = entries.filter(function (e) {
      if (!e.createdAt) return false;
      if (dateFrom && e.createdAt < dateFrom) return false;
      if (dateTo && e.createdAt > dateTo + "T23:59:59.999Z") return false;
      return true;
    });
  }

  // Action filtering (action is sealed, must filter in JS after unseal)
  if (actionFilter) {
    entries = entries.filter(function (e) { return e.action === actionFilter; });
  }

  // Text search across unsealed fields. Includes the WHERE/HOW context (IP, path,
  // performer id) so an investigator can pivot on an address or request path.
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

module.exports = { queryAuditLog, verifyAuditChain };

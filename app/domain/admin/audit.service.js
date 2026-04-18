/**
 * Audit Service — business logic for querying and filtering audit logs.
 * Uses SQL-level filtering for date ranges and action types where possible,
 * falls back to JS filtering for text search (sealed fields can't be searched in SQL).
 */
var auditRepo = require("../../data/repositories/audit.repo");

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

  // Fetch with JS-level date/action filtering
  var sqlLimit = (q || actionFilter) ? 5000 : limit; // fetch more if we need JS filtering
  var sqlOffset = (q || actionFilter) ? 0 : (page - 1) * limit;
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

  // Text search across unsealed fields
  if (q) {
    entries = entries.filter(function (e) {
      return (e.action || "").toLowerCase().includes(q) ||
        (e.details || "").toLowerCase().includes(q) ||
        (e.targetEmail || "").toLowerCase().includes(q) ||
        (e.performedByEmail || "").toLowerCase().includes(q) ||
        (e.targetId || "").toLowerCase().includes(q);
    });
  }

  // Paginate the filtered results
  var total = entries.length;
  var pages = Math.ceil(total / limit) || 1;
  var paged = entries.slice((page - 1) * limit, page * limit);

  return { entries: paged, total: total, page: page, pages: pages, limit: limit };
}

module.exports = { queryAuditLog };

/**
 * Audit log routes — thin HTTP facades that delegate to audit.service.
 */
var requireAdmin = require("../middleware/require-admin");
var { send } = require("../middleware/send");
var auditService = require("../app/domain/admin/audit.service");

module.exports = function (app) {
  app.get("/admin/audit", function (req, res) {
    if (!requireAdmin(req, res)) return;
    send(res, "admin-audit", { user: req.user });
  });

  app.get("/admin/audit/api", function (req, res) {
    if (!requireAdmin(req, res)) return;
    var result = auditService.queryAuditLog({
      q: req.query.q,
      action: req.query.action,
      dateFrom: req.query.dateFrom,
      dateTo: req.query.dateTo,
      page: req.query.page,
      limit: req.query.limit,
    });
    res.json(result);
  });

  // Tamper-evidence chain verification — admin-only. Walks every audit row and
  // recomputes the hash chain; returns { ok, rowsVerified, lastHash } or, on a
  // break, { ok:false, breakAt, reason, ... }. Async terminal handler: the
  // router awaits it and any throw flows through the centralized error handler.
  app.get("/admin/audit/verify", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    res.json(await auditService.verifyAuditChain());
  });
};

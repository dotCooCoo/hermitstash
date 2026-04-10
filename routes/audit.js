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
};

/**
 * Audit log routes — thin HTTP facades that delegate to audit.service.
 */
var requireAdmin = require("../middleware/require-admin");
var { send } = require("../middleware/send");
var auditService = require("../app/domain/admin/audit.service");
var audit = require("../lib/audit");
var { buildCsv } = require("../app/security/csv-policy");

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

  // Decrypt + export — admin-only download of the (decrypted) audit trail, honoring
  // the same filters as the viewer. format=csv (formula-injection-safe), json, or
  // cadf (Cloud Auditing Data Federation, for SIEM/compliance). The export itself is
  // a security-relevant action, so it is audited.
  app.get("/admin/audit/export", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    var format = String(req.query.format || "json").toLowerCase();
    if (format !== "csv" && format !== "json" && format !== "cadf") format = "json";
    var opts = { q: req.query.q, action: req.query.action, dateFrom: req.query.dateFrom, dateTo: req.query.dateTo };
    var result = auditService.exportAuditLog(opts);
    var entries = result.entries;
    audit.log(audit.ACTIONS.AUDIT_EXPORTED, {
      details: format + " export — " + entries.length + " entries" + (result.truncated ? " (truncated at " + entries.length + ")" : ""),
      req: req,
    });
    var stamp = new Date().toISOString().slice(0, 10);

    if (format === "csv") {
      var csv = buildCsv(auditService.EXPORT_FIELDS, entries, function (e) {
        return auditService.EXPORT_FIELDS.map(function (f) { return e[f] == null ? "" : e[f]; });
      });
      res.writeHead(200, { "Content-Type": "text/csv", "Content-Disposition": "attachment; filename=\"audit-export-" + stamp + ".csv\"" });
      res.end(csv);
      return;
    }
    if (format === "cadf") {
      var batch = await auditService.exportCadf(entries, opts);
      res.writeHead(200, { "Content-Type": "application/json", "Content-Disposition": "attachment; filename=\"audit-cadf-" + stamp + ".json\"" });
      res.end(JSON.stringify(batch, null, 2));
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json", "Content-Disposition": "attachment; filename=\"audit-export-" + stamp + ".json\"" });
    res.end(JSON.stringify({ exportedAt: new Date().toISOString(), count: entries.length, truncated: result.truncated, entries: entries }, null, 2));
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

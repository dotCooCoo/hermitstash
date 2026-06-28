/**
 * Audit log routes — thin HTTP facades that delegate to audit.service.
 */
var requireAdmin = require("../middleware/require-admin");
var { send } = require("../middleware/send");
var auditService = require("../app/domain/admin/audit.service");
var auditArchive = require("../lib/audit-archive");
var audit = require("../lib/audit");
var config = require("../lib/config");
var b = require("../lib/vendor/blamejs");
var { buildCsv } = require("../app/security/csv-policy");
var { ValidationError } = require("../app/shared/errors");

// Stream a decrypted entry set as a CSV / JSON / CADF download. Shared by the live
// export and the archive-bundle export. Uses res.writeHead/res.end so it bypasses
// the api-encrypt res.json wrap (the established download pattern).
async function sendExport(res, entries, format, base, opts) {
  opts = opts || {};
  var stamp = new Date().toISOString().slice(0, 10);
  if (format === "csv") {
    var csv = buildCsv(auditService.EXPORT_FIELDS, entries, function (e) {
      return auditService.EXPORT_FIELDS.map(function (f) { return e[f] == null ? "" : e[f]; });
    });
    res.writeHead(200, { "Content-Type": "text/csv", "Content-Disposition": "attachment; filename=\"" + base + "-" + stamp + ".csv\"" });
    res.end(csv);
    return;
  }
  if (format === "cadf") {
    var batch = await auditService.exportCadf(entries, opts);
    res.writeHead(200, { "Content-Type": "application/json", "Content-Disposition": "attachment; filename=\"" + base + "-cadf-" + stamp + ".json\"" });
    res.end(JSON.stringify(batch, null, 2));
    return;
  }
  res.writeHead(200, { "Content-Type": "application/json", "Content-Disposition": "attachment; filename=\"" + base + "-" + stamp + ".json\"" });
  res.end(JSON.stringify({ exportedAt: new Date().toISOString(), count: entries.length, truncated: !!opts.truncated, entries: entries }, null, 2));
}

function normalizeFormat(f) {
  f = String(f || "json").toLowerCase();
  return (f === "csv" || f === "json" || f === "cadf") ? f : "json";
}

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
  // cadf (Cloud Auditing Data Federation, for SIEM/compliance). Audited.
  app.get("/admin/audit/export", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    var format = normalizeFormat(req.query.format);
    var opts = { q: req.query.q, action: req.query.action, dateFrom: req.query.dateFrom, dateTo: req.query.dateTo };
    var result = auditService.exportAuditLog(opts);
    audit.log(audit.ACTIONS.AUDIT_EXPORTED, {
      details: format + " export — " + result.entries.length + " entries" + (result.truncated ? " (truncated at " + result.entries.length + ")" : ""),
      req: req,
    });
    opts.truncated = result.truncated;
    await sendExport(res, result.entries, format, "audit-export", opts);
  });

  // ---- Encrypted on-disk archives ----

  // List archives (metadata only — no decryption).
  app.get("/admin/audit/archives", function (req, res) {
    if (!requireAdmin(req, res)) return;
    res.json({ archives: auditArchive.listArchives(), enabled: !!config.auditArchiveEnabled, hasPassphrase: !!config.auditArchivePassphrase, thresholdRows: config.auditArchiveThresholdRows });
  });

  // Manually trigger an archive run now.
  app.post("/admin/audit/archives/run", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    if (!config.auditArchivePassphrase) throw new ValidationError("Set an archive passphrase in Audit Log settings first.");
    var body = req.body || (await b.parsers.json(req)) || {};
    var result = await auditArchive.archiveNow({ all: body.all === true, performedBy: req.user._id, req: req });
    res.json({ success: true, archived: result.archived, id: result.id, remaining: result.total });
  });

  // Verify an archive bundle (signature + checksum + chain recompute).
  app.post("/admin/audit/archives/verify", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    var body = req.body || (await b.parsers.json(req)) || {};
    var id = String(body.id || "");
    var passphrase = body.passphrase || config.auditArchivePassphrase;
    if (!passphrase) throw new ValidationError("No archive passphrase available.");
    var result;
    try { result = await auditArchive.verifyArchive(id, passphrase); }
    catch (e) { result = { ok: false, reason: e.message }; }
    audit.log(audit.ACTIONS.AUDIT_ARCHIVE_VERIFIED, {
      details: id + ": " + (result.ok ? "verified " + result.rowsVerified + " rows" : "FAILED — " + result.reason),
      req: req,
    });
    res.json(result);
  });

  // Decrypt + export an archive bundle's entries (CSV / JSON / CADF download).
  // The bundle passphrase is taken ONLY from the sealed config, never the query
  // string (a passphrase in a URL leaks to access logs / proxies / Referer — CWE-598).
  app.get("/admin/audit/archives/export", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    var id = String(req.query.id || "");
    var format = normalizeFormat(req.query.format);
    var passphrase = config.auditArchivePassphrase;
    if (!passphrase) throw new ValidationError("No archive passphrase available.");
    var entries = await auditArchive.readArchiveEntries(id, passphrase);
    audit.log(audit.ACTIONS.AUDIT_EXPORTED, {
      details: "archive " + id + " " + format + " export — " + entries.length + " entries",
      req: req,
    });
    await sendExport(res, entries, format, "audit-archive", {});
  });

  // Tamper-evidence chain verification — admin-only. Walks every live audit row and
  // recomputes the hash chain; returns { ok, rowsVerified, lastHash } or, on a
  // break, { ok:false, breakAt, reason, ... }.
  app.get("/admin/audit/verify", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    res.json(await auditService.verifyAuditChain());
  });
};

/**
 * Webhook routes — thin HTTP facades that delegate to webhook.service.
 */
var { parseJson } = require("../lib/multipart");
var logger = require("../app/shared/logger");
var requireAdmin = require("../middleware/require-admin");
var audit = require("../lib/audit");
var webhookService = require("../app/domain/integrations/webhook.service");

module.exports = function (app) {
  app.get("/admin/webhooks/api", function (req, res) {
    if (!requireAdmin(req, res)) return;
    res.json({ webhooks: webhookService.list() });
  });

  app.post("/admin/webhooks/create", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var body = await parseJson(req);
      var result = await webhookService.create(body.url, body.events, req.user._id);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Webhook created: " + body.url, req: req });
      res.json({ success: true, secret: result.secret });
    } catch (e) {
      if (e.isAppError) return res.status(e.statusCode).json({ error: e.message });
      res.status(500).json({ error: "Failed to create webhook." });
    }
  });

  app.post("/admin/webhooks/:id/toggle", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var result = webhookService.toggle(req.params.id);
      res.json({ success: true, active: result.active });
    } catch (e) {
      if (e.isAppError) return res.status(e.statusCode).json({ error: e.message });
      res.status(500).json({ error: "Failed to toggle webhook." });
    }
  });

  app.post("/admin/webhooks/:id/delete", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      webhookService.remove(req.params.id);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Webhook deleted", req: req });
      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) return res.status(e.statusCode).json({ error: e.message });
      res.status(500).json({ error: "Failed to delete webhook." });
    }
  });

  // Webhook delivery log
  app.get("/admin/webhooks/:id/deliveries", function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var deliveries = webhookService.getDeliveries(req.params.id, 20);
      res.json({ deliveries: deliveries });
    } catch (e) {
      logger.error("Webhook deliveries error", { error: e.message || String(e) });
      res.status(500).json({ error: "Failed to load deliveries." });
    }
  });
};

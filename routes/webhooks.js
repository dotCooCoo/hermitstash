/**
 * Webhook routes — thin HTTP facades that delegate to webhook.service.
 */
var b = require("../lib/vendor/blamejs");
var logger = require("../app/shared/logger");
var requireAdmin = require("../middleware/require-admin");
var idempotency = require("../middleware/idempotency");
var audit = require("../lib/audit");
var webhookService = require("../app/domain/integrations/webhook.service");
var { AppError } = require("../app/shared/errors");

module.exports = function (app) {
  app.get("/admin/webhooks/api", function (req, res) {
    if (!requireAdmin(req, res)) return;
    res.json({ webhooks: webhookService.list() });
  });

  app.post("/admin/webhooks/create", idempotency, async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var body = req.body || (await b.parsers.json(req)) || {};
      var result = await webhookService.create(body.url, body.events, req.user._id);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Webhook created: " + body.url, req: req });
      res.json({ success: true, secret: result.secret });
    } catch (e) {
      if (e.isAppError) throw e;
      throw new AppError("Failed to create webhook.", 500);
    }
  });

  app.post("/admin/webhooks/:id/toggle", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var result = webhookService.toggle(req.params.id);
      res.json({ success: true, active: result.active });
    } catch (e) {
      if (e.isAppError) throw e;
      throw new AppError("Failed to toggle webhook.", 500);
    }
  });

  app.post("/admin/webhooks/:id/delete", async function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      webhookService.remove(req.params.id);
      audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "Webhook deleted", req: req });
      res.json({ success: true });
    } catch (e) {
      if (e.isAppError) throw e;
      throw new AppError("Failed to delete webhook.", 500);
    }
  });

  // Webhook delivery log
  app.get("/admin/webhooks/:id/deliveries", function (req, res) {
    if (!requireAdmin(req, res)) return;
    try {
      var deliveries = webhookService.getDeliveries(req.params.id, 20);
      res.json({ deliveries: deliveries });
    } catch (e) {
      if (e.isAppError) throw e;
      logger.error("Webhook deliveries error", { error: e.message || String(e) });
      throw new AppError("Failed to load deliveries.", 500);
    }
  });
};

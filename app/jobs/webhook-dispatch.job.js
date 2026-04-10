/**
 * Webhook Dispatch Job — async webhook delivery with per-hook retry.
 * Dispatches each webhook individually for isolated retry and delivery logging.
 */
var queue = require("./queue");
var webhookService = require("../domain/integrations/webhook.service");

// Per-hook dispatch: each hook is dispatched individually with its own retry
queue.register("webhook-dispatch-single", async function (data) {
  var result = await webhookService.dispatchSingle(data.hookId, data.event, data.payload);
  if (result && result.error) {
    throw new Error(result.error); // Triggers job queue retry
  }
});

// Legacy bulk dispatch (kept for backward compatibility)
queue.register("webhook-dispatch", async function (data) {
  webhookService.fire(data.event, data.payload);
});

/**
 * Enqueue a webhook dispatch.
 */
function dispatch(eventName, payload) {
  queue.enqueue("webhook-dispatch", { event: eventName, payload: payload });
}

module.exports = { dispatch };

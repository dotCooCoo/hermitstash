/**
 * Webhook Service — business logic for webhook CRUD and dispatch.
 * Routes call this; this calls repositories and security policies.
 */
var https = require("https");
var { generateToken, hmacSha3 } = require("../../../lib/crypto");
var webhooksRepo = require("../../data/repositories/webhooks.repo");
var { isPrivateHost, validateOutboundUrl } = require("../../security/ssrf-policy");
var { ValidationError, NotFoundError } = require("../../shared/errors");

/**
 * List all webhooks with secrets masked.
 */
function list() {
  var all = webhooksRepo.findAll();
  return all.map(function (w) {
    return { _id: w._id, url: w.url, events: w.events, active: w.active, lastTriggered: w.lastTriggered, createdAt: w.createdAt, hasSecret: !!w.secret };
  });
}

/**
 * Create a new webhook. Returns { webhook, secret } where secret is shown once.
 */
async function create(url, events, createdBy) {
  if (!url) throw new ValidationError("URL required.");
  if (String(url).length > 2048) throw new ValidationError("URL too long.");

  var check = validateOutboundUrl(url);
  if (!check.valid) throw new ValidationError(check.reason);

  var isPrivate = await isPrivateHost(check.url.hostname);
  if (isPrivate) throw new ValidationError("Cannot use private/internal URLs.");

  var secret = generateToken(32);
  var webhook = webhooksRepo.create({
    url: url,
    events: events || "*",
    secret: secret,
    active: "true",
    createdBy: createdBy,
    createdAt: new Date().toISOString(),
  });
  return { webhook: webhook, secret: secret };
}

/**
 * Toggle a webhook's active state.
 */
function toggle(id) {
  var hook = webhooksRepo.findById(id);
  if (!hook) throw new NotFoundError("Webhook not found.");
  var newState = hook.active === "true" ? "false" : "true";
  webhooksRepo.update(hook._id, { $set: { active: newState } });
  return { active: newState === "true" };
}

/**
 * Delete a webhook.
 */
function remove(id) {
  var hook = webhooksRepo.findById(id);
  if (!hook) throw new NotFoundError("Webhook not found.");
  webhooksRepo.remove(id);
}

/**
 * Fire webhooks for an event. Enqueues individual hook dispatches via the job queue.
 */
function fire(eventName, payload) {
  var queue = require("../../jobs/queue");
  var hooks = webhooksRepo.findActive();
  for (var i = 0; i < hooks.length; i++) {
    var hook = hooks[i];
    var hookEvents = hook.events || "*";
    var events = hookEvents.split(",").map(function (e) { return e.trim(); });
    if (events[0] !== "*" && events.indexOf(eventName) === -1) continue;

    queue.enqueue("webhook-dispatch-single", {
      hookId: hook._id,
      event: eventName,
      payload: payload,
    });
  }
}

/**
 * Dispatch a single webhook. Called by the job queue handler.
 * Returns a promise that resolves with delivery result.
 */
function dispatchSingle(hookId, eventName, payload) {
  var { webhookDeliveries } = require("../../../lib/db");
  var hook = webhooksRepo.findById(hookId);
  if (!hook) return Promise.resolve();

  var check = validateOutboundUrl(hook.url);
  if (!check.valid) {
    webhookDeliveries.insert({
      webhookId: hookId, event: eventName, status: "failed",
      statusCode: 0, error: "Invalid URL: " + (check.reason || "unknown"),
      attempts: 1, createdAt: new Date().toISOString(),
    });
    return Promise.resolve();
  }

  return isPrivateHost(check.url.hostname).then(function (result) {
    if (result === true || (result && result.blocked)) {
      webhookDeliveries.insert({
        webhookId: hookId, event: eventName, status: "failed",
        statusCode: 0, error: "Private/internal host blocked",
        attempts: 1, createdAt: new Date().toISOString(),
      });
      return;
    }

    var body = JSON.stringify({ event: eventName, data: payload, timestamp: new Date().toISOString() });
    var signature = hook.secret ? hmacSha3(hook.secret, body) : "";
    // Pin DNS to the pre-validated IP to prevent TOCTOU rebinding
    var pinnedAddress = result.address;
    var pinnedFamily = result.family;

    return new Promise(function (resolve) {
      try {
        var req = https.request(hook.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body),
            "X-Webhook-Signature": signature,
          },
          timeout: 5000,
          lookup: function (_hostname, _opts, cb) { cb(null, pinnedAddress, pinnedFamily); },
        }, function (res) {
          var statusCode = res.statusCode;
          var ok = statusCode >= 200 && statusCode < 300;
          webhooksRepo.update(hook._id, { $set: { lastTriggered: new Date().toISOString() } });
          webhookDeliveries.insert({
            webhookId: hookId, event: eventName,
            status: ok ? "success" : "failed",
            statusCode: statusCode, error: ok ? null : "HTTP " + statusCode,
            attempts: 1, createdAt: new Date().toISOString(),
          });
          // Consume response body to free socket
          res.resume();
          if (!ok) {
            resolve({ error: "HTTP " + statusCode });
          } else {
            resolve();
          }
        });
        req.on("error", function (err) {
          webhookDeliveries.insert({
            webhookId: hookId, event: eventName, status: "failed",
            statusCode: 0, error: err.message || String(err),
            attempts: 1, createdAt: new Date().toISOString(),
          });
          resolve({ error: err.message });
        });
        req.write(body);
        req.end();
      } catch (e) {
        webhookDeliveries.insert({
          webhookId: hookId, event: eventName, status: "failed",
          statusCode: 0, error: e.message || String(e),
          attempts: 1, createdAt: new Date().toISOString(),
        });
        resolve({ error: e.message });
      }
    });
  });
}

/**
 * Get recent deliveries for a webhook.
 */
function getDeliveries(webhookId, limit) {
  var { webhookDeliveries } = require("../../../lib/db");
  return webhookDeliveries.find({ webhookId: webhookId })
    .sort(function (a, b) { return (b.createdAt || "").localeCompare(a.createdAt || ""); })
    .slice(0, limit || 20);
}

module.exports = { list, create, toggle, remove, fire, dispatchSingle, getDeliveries };

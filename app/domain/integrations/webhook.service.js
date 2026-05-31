/**
 * Webhook Service — business logic for webhook CRUD and dispatch.
 * Routes call this; this calls repositories and security policies.
 */
var b = require("../../../lib/vendor/blamejs");
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

  var hostCheck = await isPrivateHost(check.url.hostname);
  if (hostCheck && hostCheck.blocked) throw new ValidationError("Cannot use private/internal URLs.");

  var secret = b.crypto.generateToken(32);
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
    if (result && result.blocked) {
      webhookDeliveries.insert({
        webhookId: hookId, event: eventName, status: "failed",
        statusCode: 0, error: "Private/internal host blocked",
        attempts: 1, createdAt: new Date().toISOString(),
      });
      return;
    }

    var body = JSON.stringify({ event: eventName, data: payload, timestamp: new Date().toISOString() });
    var signature = hook.secret ? b.crypto.hmacSha3(hook.secret, body) : "";

    // Deliver through the framework HTTP client: it runs its own SSRF gate and
    // pins the TCP connect to the validated address (closing the DNS-rebinding
    // TOCTOU window the manual lookup pin used to cover), enforces HTTPS-only,
    // and caps both wall-clock and idle time. maxRedirects is pinned to 0 — a
    // receiver must not be able to 302 the signed body + X-Webhook-Signature to
    // another origin, and the client does not strip that custom header on a
    // cross-origin redirect. responseMode "always-resolve" keeps a non-2xx as a
    // resolved response so the delivery log records the real status code rather
    // than collapsing it to 0; network/SSRF/timeout failures still reject.
    return b.httpClient.request({
      method: "POST",
      url: hook.url,
      headers: {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
      },
      body: body,
      timeoutMs: 5000,
      idleTimeoutMs: 5000,
      maxRedirects: 0,
      responseMode: "always-resolve",
      allowInternal: false,
    }).then(function (res) {
      var ok = res.statusCode >= 200 && res.statusCode < 300;
      webhooksRepo.update(hook._id, { $set: { lastTriggered: new Date().toISOString() } });
      webhookDeliveries.insert({
        webhookId: hookId, event: eventName,
        status: ok ? "success" : "failed",
        statusCode: res.statusCode, error: ok ? null : "HTTP " + res.statusCode,
        attempts: 1, createdAt: new Date().toISOString(),
      });
      return ok ? undefined : { error: "HTTP " + res.statusCode };
    }, function (err) {
      webhookDeliveries.insert({
        webhookId: hookId, event: eventName, status: "failed",
        statusCode: 0, error: (err && (err.message || String(err))) || "request failed",
        attempts: 1, createdAt: new Date().toISOString(),
      });
      return { error: err && err.message };
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

// Self-register the queue handler at module load so any caller that requires
// this service automatically gets working dispatch. Previously this lived in
// app/jobs/webhook-dispatch.job.js, but that file was never `require()`d
// anywhere, so the registration never ran and every webhook event was
// silently dropped by the queue ("No handler for job type"). Keeping the
// registration here makes the service self-contained.
var queue = require("../../jobs/queue");
queue.register("webhook-dispatch-single", function (data) {
  return dispatchSingle(data.hookId, data.event, data.payload).then(function (r) {
    // Throw on delivery failure so the queue applies its exponential-backoff
    // retry (3 attempts, then dead-letter). dispatchSingle has already
    // recorded the failure to webhook_deliveries either way.
    if (r && r.error) throw new Error(r.error);
  });
});

module.exports = { list, create, toggle, remove, fire, dispatchSingle, getDeliveries };

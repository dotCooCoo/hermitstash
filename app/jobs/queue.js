/**
 * Simple in-process job queue with retry and dead-letter logging.
 * Jobs run asynchronously and don't block the request cycle.
 *
 * Usage:
 *   var queue = require("./queue");
 *   queue.enqueue("webhook-dispatch", { url: "...", payload: {...} });
 *
 * Register handlers:
 *   queue.register("webhook-dispatch", async (data) => { ... });
 */
var logger = require("../shared/logger");
var audit = require("../../lib/audit");

var handlers = {};
var pending = [];
var processing = false;
var MAX_RETRIES = 3;
var RETRY_DELAY = 2000; // 2s base delay, exponential backoff

/**
 * Register a job handler.
 */
function register(jobType, handler) {
  handlers[jobType] = handler;
}

/**
 * Enqueue a job for async processing.
 */
function enqueue(jobType, data) {
  pending.push({ type: jobType, data: data, attempts: 0, createdAt: Date.now() });
  if (!processing) processNext();
}

/**
 * Process the next job in the queue.
 */
async function processNext() {
  if (pending.length === 0) { processing = false; return; }
  processing = true;
  var job = pending.shift();

  var handler = handlers[job.type];
  if (!handler) {
    logger.error("No handler for job type", { jobType: job.type });
    processing = false;
    if (pending.length > 0) processNext();
    return;
  }

  job.attempts++;
  try {
    await handler(job.data);
  } catch (e) {
    if (job.attempts < MAX_RETRIES) {
      // Retry with exponential backoff
      var delay = RETRY_DELAY * Math.pow(2, job.attempts - 1);
      setTimeout(function () {
        pending.push(job);
        if (!processing) processNext();
      }, delay);
    } else {
      // Dead letter — log failure
      try {
        audit.log(audit.ACTIONS.JOB_FAILED, {
          performedBy: "system",
          details: "Job " + job.type + " failed after " + job.attempts + " attempts: " + (e.message || String(e)),
        });
      } catch (_ae) { /* audit log is best-effort — dead-letter still logged below */ }
      logger.error("Job dead-lettered", { jobType: job.type, error: e.message });
    }
  }

  // Process next immediately (or after current tick)
  setImmediate(function () { processNext(); });
}

/**
 * Get queue stats.
 */
function stats() {
  return { pending: pending.length, processing: processing, handlers: Object.keys(handlers) };
}

module.exports = { register, enqueue, stats };

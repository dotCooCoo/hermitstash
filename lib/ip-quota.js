/**
 * In-memory per-IP storage quota tracker for anonymous uploads.
 * Tracks cumulative bytes uploaded per IP within a 24-hour rolling window.
 * Resets on server restart. Cleanup runs every 60s.
 */

var C = require("./constants");

var store = {}; // ip -> { bytes, resetAt }
var WINDOW_MS = C.TIME.ONE_DAY;

var cleanupTimer = setInterval(function () {
  var now = Date.now();
  for (var ip in store) {
    if (now > store[ip].resetAt) delete store[ip];
  }
}, C.TIME.ONE_MIN);
if (cleanupTimer.unref) cleanupTimer.unref();

/**
 * Check whether an IP can upload additional bytes.
 * Returns { allowed, used, remaining }.
 */
function check(ip, fileSize, maxBytes) {
  if (!maxBytes || maxBytes <= 0) return { allowed: true, used: 0, remaining: Infinity };
  if (!ip) return { allowed: true, used: 0, remaining: maxBytes };

  var now = Date.now();
  if (!store[ip] || now > store[ip].resetAt) {
    store[ip] = { bytes: 0, resetAt: now + WINDOW_MS };
  }

  if (store[ip].bytes + fileSize > maxBytes) {
    return { allowed: false, used: store[ip].bytes, remaining: Math.max(0, maxBytes - store[ip].bytes) };
  }

  return { allowed: true, used: store[ip].bytes, remaining: maxBytes - store[ip].bytes - fileSize };
}

/**
 * Record bytes after a successful upload.
 */
function record(ip, fileSize) {
  if (!ip) return;
  var now = Date.now();
  if (!store[ip] || now > store[ip].resetAt) {
    store[ip] = { bytes: 0, resetAt: now + WINDOW_MS };
  }
  store[ip].bytes += fileSize;
}

module.exports = { check, record };

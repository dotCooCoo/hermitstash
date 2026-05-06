"use strict";
/**
 * Shared HTTP-request helper for object-store backends.
 *
 * Every protocol backend (azure-blob / gcs / sigv4 / http-put)
 * previously rolled an identical wrapper around httpClient.request that
 * threaded the same five opts: idleTimeoutMs / maxResponseBytes /
 * errorClass / allowedProtocols / allowInternal. Centralized here so a
 * future change to the call shape (new opt, different error class
 * default, etc.) is a one-file change.
 *
 *   var sharedRequest = require("./http-request");
 *   sharedRequest("PUT", url, headers, body, { timeoutMs: 5000 });
 *
 * The errorClass defaults to ObjectStoreError; backends that need a
 * different class pass `errorClass: SomeError` in opts.
 */

var httpClient = require("../http-client");
var { ObjectStoreError } = require("../framework-error");

function request(method, url, headers, body, opts) {
  opts = opts || {};
  var req = {
    method:           method,
    url:              url,
    headers:          headers,
    body:             body,
    idleTimeoutMs:    opts.timeoutMs,
    errorClass:       opts.errorClass || ObjectStoreError,
    allowedProtocols: opts.allowedProtocols,
  };
  if (opts.maxResponseBytes !== undefined) req.maxResponseBytes = opts.maxResponseBytes;
  if (opts.allowInternal !== undefined) req.allowInternal = opts.allowInternal;
  return httpClient.request(req);
}

module.exports = request;

"use strict";
/**
 * Object-store dispatcher — protocol-agnostic remote (and local) storage.
 *
 * The framework's storage abstraction (lib/storage.js) routes per-classification
 * requests to one or more configured backends. Each backend is constructed
 * here from a config object that picks a protocol and provides its options:
 *
 *   protocol: 'local'                   → lib/object-store/local.js
 *   protocol: 'http-put'                → lib/object-store/http-put.js
 *   protocol: 'sigv4'  (S3 / R2 / B2 / MinIO / Wasabi / Tigris / DO Spaces /
 *                       IDrive e2 / Linode Object Storage / Storj / etc.)
 *                                       → lib/object-store/sigv4.js
 *   protocol: 'gcs'    (Google Cloud Storage native — HMAC + native API)
 *                                       → lib/object-store/gcs.js
 *   protocol: 'azure-blob'              → lib/object-store/azure-blob.js
 *
 * Every backend is wrapped with retry + circuit-breaker so transient
 * failures don't surface as call-site errors and persistent failures
 * don't pile up retry storms.
 *
 * Common API across protocols:
 *   put(key, body, opts?)       → { size, etag? }
 *   get(key)                    → Buffer
 *   getStream(key)              → Readable
 *   head(key)                   → { size, etag?, lastModified? }
 *   delete(key)                 → boolean (true if deleted, false if missing)
 *   list(prefix, opts?)         → { items: [{ key, size, lastModified }], truncated }
 */
var localProto             = require("./local");
var httpPutProto           = require("./http-put");
var sigv4                  = require("./sigv4");
var sigv4BucketOps         = require("./sigv4-bucket-ops");
var gcs                    = require("./gcs");
var gcsBucketOps           = require("./gcs-bucket-ops");
var azureBlob              = require("./azure-blob");
var azureBlobBucketOps     = require("./azure-blob-bucket-ops");
var retryHelper            = require("../retry");
var protocolDispatcher     = require("../protocol-dispatcher");
var { ObjectStoreError }   = require("../framework-error");

// All currently advertised protocols are bundled. The dispatcher's
// `deferred` slot is the hook for adding deferred ones later.
var dispatcher = protocolDispatcher.create({
  name:       "object-store",
  errorClass: ObjectStoreError,
  protocols: {
    "local":      localProto,
    "http-put":   httpPutProto,
    "sigv4":      sigv4,
    "gcs":        gcs,
    "azure-blob": azureBlob,
  },
  deferred:         {},
  fallbackProtocol: "local",
});

var _err = ObjectStoreError.factory;

/**
 * Build a backend instance from a backend config block.
 *
 * config:
 *   {
 *     protocol:        'local' | 'http-put' | 'sigv4' | 'gcs' | 'azure-blob',
 *     // protocol-specific config (rootDir for local, baseUrl for http-put, etc.)
 *     classifications: ['personal' | 'operational' | 'public' | <custom>],
 *     residencyTag:    'EU' | 'US' | 'UK' | 'CA' | 'unrestricted' | <custom>,
 *     retry:           { maxAttempts, baseDelayMs, maxDelayMs, jitterFactor },
 *     breaker:         { failureThreshold, cooldownMs, successThreshold },
 *     name:            <stable-id-for-circuit-breaker>,
 *   }
 */
function buildBackend(config) {
  if (!config) {
    throw new Error("object-store backend requires { protocol }");
  }
  var proto = dispatcher.resolve(config.protocol);
  var raw = proto.create(config);

  // Validate classifications + residencyTag
  var classifications = Array.isArray(config.classifications) && config.classifications.length > 0
    ? config.classifications.slice()
    : ["*"];   // wildcard: backend serves any classification
  var residencyTag = config.residencyTag || "unrestricted";

  // Wrap protocol calls with retry + circuit breaker
  var breaker = new retryHelper.CircuitBreaker(
    config.name || (config.protocol + ":" + (raw.rootDir || raw.baseUrl || "anonymous")),
    config.breaker
  );

  function wrap(name) {
    var inner = raw[name];
    if (typeof inner !== "function") return inner;
    return function () {
      var args = Array.prototype.slice.call(arguments);
      // For sync methods (getStream returns a Readable directly, not a Promise):
      if (name === "getStream") {
        // Apply circuit breaker only — getStream is sync, retry doesn't apply.
        // The Readable will surface its own errors as the consumer reads it.
        return inner.apply(raw, args);
      }
      return retryHelper.withRetry(function () {
        return breaker.wrap(function () {
          return inner.apply(raw, args);
        });
      }, config.retry);
    };
  }

  return {
    name:            config.name || config.protocol,
    protocol:        config.protocol,
    classifications: classifications,
    residencyTag:    residencyTag,
    breaker:         breaker,
    raw:             raw,
    put:             wrap("put"),
    get:             wrap("get"),
    getStream:       wrap("getStream"),
    head:            wrap("head"),
    delete:          wrap("delete"),
    list:            wrap("list"),
    // listVersions is S3/sigv4-only (the ?versions subresource backs the
    // WORM erasure workflow). Backends without it expose null so callers can
    // feature-detect rather than hit a "wrap of undefined" at boot.
    listVersions:    typeof raw.listVersions === "function" ? wrap("listVersions") : null,
    // presigned*Url are sync URL-builders (no network call), so they
    // bypass retry + circuit-breaker — propagate any throw directly.
    presignedUploadUrl: typeof raw.presignedUploadUrl === "function"
      ? raw.presignedUploadUrl.bind(raw) : null,
    presignedDownloadUrl: typeof raw.presignedDownloadUrl === "function"
      ? raw.presignedDownloadUrl.bind(raw) : null,
    presignedUploadPolicy: typeof raw.presignedUploadPolicy === "function"
      ? raw.presignedUploadPolicy.bind(raw) : null,
    servesClassification: function (cls) {
      return classifications.indexOf("*") !== -1 || classifications.indexOf(cls) !== -1;
    },
  };
}

// ---- Bucket-level ops dispatcher ----
//
// Bucket lifecycle (create / delete / list) + lifecycle / CORS rules
// are service-scoped, not bucket-scoped — `b.objectStore.bucketOps`
// resolves a per-cloud factory by protocol. Each cloud's ops shape
// differs (S3 sigv4 vs Azure Shared Key vs GCS OAuth) so the
// per-protocol modules each own their own validation, signing, and
// REST-API translation; this dispatcher just routes.
//
// Operator entry point — unchanged from v0.6.x:
//
//   var ops = b.objectStore.bucketOps.create({
//     protocol: 'sigv4' | 'azure-blob' | 'gcs',
//     // ... protocol-specific creds ...
//   });
//
// Each returned ops object exposes (where supported per-cloud):
//   ops.create(name, opts?)
//   ops.delete(name)
//   ops.list(opts?)
//   ops.setLifecycle(name, rules)
//   ops.setCorsRules(name, rules)   // sigv4 + gcs accept (name, rules);
//                                    // azure-blob accepts (rules) — its
//                                    // CORS is account-level.
var BUCKET_OPS_BY_PROTOCOL = {
  "sigv4":      sigv4BucketOps,
  "gcs":        gcsBucketOps,
  "azure-blob": azureBlobBucketOps,
};
function _bucketOpsCreate(config) {
  if (!config) {
    throw _err("BAD_OPT",
      "objectStore.bucketOps.create: config required (must include " +
      "{ protocol })", true);
  }
  var protoMod = BUCKET_OPS_BY_PROTOCOL[config.protocol];
  if (!protoMod) {
    throw _err("UNKNOWN_PROTOCOL",
      "objectStore.bucketOps.create: unknown protocol '" + config.protocol +
      "' (supported: " + Object.keys(BUCKET_OPS_BY_PROTOCOL).join(", ") +
      ")", true);
  }
  return protoMod.create(config);
}

module.exports = {
  buildBackend:        buildBackend,
  PROTOCOLS:           dispatcher.protocols,
  DEFERRED_PROTOCOLS:  dispatcher.deferred,
  bucketOps:           {
    create:                  _bucketOpsCreate,
    PROTOCOLS:               Object.keys(BUCKET_OPS_BY_PROTOCOL),
    // Per-protocol modules exposed for advanced operators wiring
    // their own dispatch / testing harnesses against a specific cloud.
    sigv4:      sigv4BucketOps,
    gcs:        gcsBucketOps,
    "azure-blob": azureBlobBucketOps,
  },
};

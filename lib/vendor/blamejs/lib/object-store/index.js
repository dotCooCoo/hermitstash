// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.objectStore
 * @nav    Data
 * @title  Object Store
 * @slug   object-store
 *
 * @intro
 *   One object-storage interface over five protocols: a local directory,
 *   a plain HTTP <code>PUT</code> endpoint, S3 and anything speaking SigV4,
 *   Google Cloud Storage, and Azure Blob Storage. A backend is built from a
 *   config naming the protocol, and every backend answers the same calls, so
 *   the protocol is a deployment decision rather than an application one.
 *
 *   Each call is wrapped in the retry policy and a circuit breaker, so a
 *   store that starts failing stops being asked until it recovers rather
 *   than failing every request slowly. <code>getStream</code> is passed
 *   through unwrapped, because a stream cannot be replayed by a retry.
 *
 *   A backend carries the data classifications it may hold and a residency
 *   tag, and answers <code>servesClassification(cls)</code>, which is how a
 *   caller holding regulated data picks a store allowed to keep it.
 *   Every backend carries the three presign functions; a protocol that cannot
 *   presign a request throws <code>objectstore/presign-not-supported</code>
 *   from them. <code>listVersions</code> is <code>null</code> on a protocol
 *   without object versioning. Bucket lifecycle is reached through
 *   <code>b.objectStore.bucketOps.create</code>.
 *
 * @card
 *   One interface over a local directory, HTTP PUT, S3/SigV4, GCS and Azure
 *   Blob, with retry, a circuit breaker and a data-classification check on
 *   every backend.
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
 * @primitive b.objectStore.buildBackend
 * @signature b.objectStore.buildBackend(config)
 * @since     0.1.96
 * @status    stable
 * @related   b.backup.bundleAdapterStorage, b.retry.withRetry
 *
 * Build a backend for one store. `protocol` picks the implementation and is
 * required: omitting it raises `protocol-dispatcher/missing-protocol` rather
 * than selecting a default. A name outside the five raises
 * `protocol-dispatcher/unknown-protocol` listing them, and no config at all
 * raises `objectstore/bad-opt`. The rest of the config is that protocol's
 * own, so a SigV4 store takes its region and credentials here and a local
 * store takes its root directory.
 *
 * The returned backend answers `put`, `get`, `head`, `delete` and `list`
 * through the retry policy and a circuit breaker named after the store.
 * `getStream` is answered directly by the protocol, with neither: a stream
 * cannot be replayed, so a retry would hand back a half-consumed one. A
 * transient failure opening a download reaches the caller as it happened.
 * On the remote protocols, a `get` or `getStream` whose body ends short of
 * its `Content-Length`, or whose HTTP/2 stream is reset before the body ends,
 * fails with `objectstore/truncated-body`, marked transient, over HTTP/1.1
 * and HTTP/2. `listVersions` is present only on a protocol with object versioning
 * (SigV4) and is `null` otherwise. `presignedUploadUrl`,
 * `presignedDownloadUrl` and `presignedUploadPolicy` are present on every
 * backend; a protocol that cannot presign that request throws
 * `objectstore/presign-not-supported`. `raw` is the unwrapped protocol object, for the
 * cases where retrying would be wrong.
 *
 * `name` names the store and the breaker both. Omit it and the backend's
 * `name` is the protocol while the breaker is `protocol:root`, so two local
 * stores under different directories trip independently; pass it and both
 * take the value given.
 *
 * `classifications` lists the data classes the store may hold and defaults to
 * `["*"]`, meaning any. `servesClassification(cls)` answers whether this
 * store accepts a given class, which is the check a caller holding regulated
 * data makes before writing. `residencyTag` records where the bytes come to
 * rest and defaults to `unrestricted`.
 *
 * @opts
 *   protocol:        string,   // required; local | http-put | sigv4 | gcs | azure-blob
 *   name:            string,   // store + breaker name; see above for the defaults
 *   classifications: array,    // data classes this store may hold
 *   residencyTag:    string,   // default: "unrestricted"
 *   retry:           object,   // b.retry.withRetry opts; not applied to a put whose
 *                              //   body is a stream, which cannot be replayed
 *   breaker:         object,   // b.retry.CircuitBreaker opts
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var store = b.objectStore.buildBackend({
 *     protocol: "local",
 *     rootDir:  "./data/objects",
 *     classifications: ["public"],
 *   });
 *   await store.put("notes/one.txt", Buffer.from("hello"));
 *   store.servesClassification("phi");   // → false
 */
function buildBackend(config) {
  if (!config) {
    throw _err("objectstore/bad-opt",
      "objectStore.buildBackend: config required (must include { protocol })", true);
  }
  var proto = dispatcher.resolve(config.protocol);
  var raw = proto.create(config);

  var classifications = Array.isArray(config.classifications) && config.classifications.length > 0
    ? config.classifications.slice()
    : ["*"];
  var residencyTag = config.residencyTag || "unrestricted";

  var breaker = new retryHelper.CircuitBreaker(
    config.name || (config.protocol + ":" + (raw.rootDir || raw.baseUrl || "anonymous")),
    config.breaker
  );

  function _isStreamBody(body) {
    if (!body || typeof body !== "object") return false;
    if (Buffer.isBuffer(body)) return false;
    return typeof body.pipe === "function" ||
           typeof body[Symbol.asyncIterator] === "function";
  }

  function wrap(name) {
    var inner = raw[name];
    if (typeof inner !== "function") return inner;
    return function () {
      var args = Array.prototype.slice.call(arguments);
      if (name === "getStream") {
        return inner.apply(raw, args);
      }
      if (name === "put" && _isStreamBody(args[1])) {
        return breaker.wrap(function () { return inner.apply(raw, args); });
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
    listVersions:    typeof raw.listVersions === "function" ? wrap("listVersions") : null,
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

var BUCKET_OPS_BY_PROTOCOL = {
  "sigv4":      sigv4BucketOps,
  "gcs":        gcsBucketOps,
  "azure-blob": azureBlobBucketOps,
};
function _bucketOpsCreate(config) {
  if (!config) {
    throw _err("objectstore/bad-opt",
      "objectStore.bucketOps.create: config required (must include " +
      "{ protocol })", true);
  }
  var protoMod = BUCKET_OPS_BY_PROTOCOL[config.protocol];
  if (!protoMod) {
    throw _err("objectstore/unknown-protocol",
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
    sigv4:      sigv4BucketOps,
    gcs:        gcsBucketOps,
    "azure-blob": azureBlobBucketOps,
  },
};

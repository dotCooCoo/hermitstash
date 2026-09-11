// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
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

function buildBackend(config) {
  if (!config) {
    throw new Error("object-store backend requires { protocol }");
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

  function wrap(name) {
    var inner = raw[name];
    if (typeof inner !== "function") return inner;
    return function () {
      var args = Array.prototype.slice.call(arguments);
      if (name === "getStream") {
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

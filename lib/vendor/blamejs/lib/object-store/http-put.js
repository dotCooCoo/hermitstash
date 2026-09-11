// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var C = require("../constants");
var { ObjectStoreError } = require("../framework-error");
var safeUrl = require("../safe-url");
var sharedRequest = require("./http-request");
var authHeader = require("../auth-header");

var _err = ObjectStoreError.factory;

function _authHeaders(authConfig) {
  if (authConfig && authConfig.auth === "header") {
    return Object.assign({}, authConfig.headers || {});
  }
  return authHeader.fromConfig(authConfig);
}

function _request(method, url, body, headers, opts) {
  return sharedRequest(method, url, headers, body, opts);
}

function _keyToUrl(baseUrl, key) {
  if (key.includes("..") || key.includes("\0")) {
    throw _err("objectstore/invalid-key", "invalid characters in key", true);
  }
  var b = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  var k = key.startsWith("/") ? key.slice(1) : key;
  var encoded = k.split("/").map(encodeURIComponent).join("/");
  return b + "/" + encoded;
}

function create(config) {
  if (!config || !config.baseUrl) {
    throw new Error("http-put protocol requires { baseUrl }");
  }
  var baseUrl = config.baseUrl;
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = config.allowInternal != null ? config.allowInternal : null;
  safeUrl.parse(baseUrl, {
    allowedProtocols: allowedProtocols,
    errorClass:       ObjectStoreError,
  });
  var headers = _authHeaders(config);
  var timeoutMs = config.timeoutMs;
  var reqOpts = { timeoutMs: timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

  function put(key, body, _opts) {
    var url = _keyToUrl(baseUrl, key);
    var h = Object.assign({ "Content-Type": "application/octet-stream" }, headers);
    return _request("PUT", url, body, h, reqOpts).then(function (res) {
      var size = Buffer.isBuffer(body) ? body.length : null;
      return { size: size, etag: res.headers.etag };
    });
  }

  function get(key) {
    var url = _keyToUrl(baseUrl, key);
    return _request("GET", url, null, headers, reqOpts).then(function (res) {
      return res.body;
    }, function (err) {
      return sharedRequest.rethrowObjectError(err, key);
    });
  }

  function getStream(key) {
    return sharedRequest.promiseToStream(get(key));
  }

  function head(key) {
    var url = _keyToUrl(baseUrl, key);
    return _request("HEAD", url, null, headers, reqOpts).then(function (res) {
      return sharedRequest.mapHeadResponse(res);
    }, function (err) {
      return sharedRequest.rethrowObjectError(err, key);
    });
  }

  function deleteKey(key, opts) {
    opts = opts || {};
    if (opts.versionId) {
      throw _err("objectstore/versionid-unsupported",
        "deleteKey: versioned delete (opts.versionId) is S3/sigv4-only; the http-put " +
        "backend has no version surface. Use a sigv4 backend for Object-Lock version erasure.", true);
    }
    var url = _keyToUrl(baseUrl, key);
    return _request("DELETE", url, null, headers, reqOpts).then(
      function () { return true; },
      function (e) {
        if (e.statusCode === C.HTTP.STATUS.NOT_FOUND) return false;
        throw e;
      }
    );
  }

  function list(_prefix, _opts) {
    return Promise.reject(_err("objectstore/not-supported", "list() not supported by http-put protocol", true));
  }

  function _presignNotSupported(_opts) {
    throw _err("objectstore/presign-not-supported",
      "http-put backend does not support presigned URLs — switch to " +
      "protocol: 'sigv4' for an S3-compatible signing flow", true);
  }

  return {
    protocol:  "http-put",
    baseUrl:   baseUrl,
    put:       put,
    get:       get,
    getStream: getStream,
    head:      head,
    delete:    deleteKey,
    list:      list,
    presignedUploadUrl:    _presignNotSupported,
    presignedDownloadUrl:  _presignNotSupported,
    presignedUploadPolicy: _presignNotSupported,
  };
}

module.exports = { create: create };

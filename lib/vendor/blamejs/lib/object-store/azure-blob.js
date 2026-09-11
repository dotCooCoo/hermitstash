// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeCrypto = require("node:crypto");
var { URL } = require("node:url");
var safeXml = require("../parsers/safe-xml");
var sharedRequest = require("./http-request");
var sigv4 = require("./sigv4");
var C = require("../constants");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");
var time = require("../time");
var safeUrl = require("../safe-url");

var LIST_PARSE_OPTS = {
  maxBytes:    C.BYTES.mib(8),
  maxElements: C.BYTES.bytes(50000),
};

function _internalUrl(input, allowedProtocols) {
  return safeUrl.parse(input, {
    allowedProtocols: allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       ObjectStoreError,
    maxUrlLength:     C.BYTES.kib(32),
  });
}

function _arrayify(value) {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

function _encodeBlobKey(key) {
  if (key.indexOf("\0") !== -1) {
    throw _err("objectstore/invalid-key", "null byte in blob key", true);
  }
  return key.split("/").map(function (s) {
    return sigv4.awsUriEncode(s, true);
  }).join("/");
}

var DEFAULT_API_VERSION = "2024-08-04";

var _err = ObjectStoreError.factory;

var _httpRequest = sharedRequest;

function buildStringToSign(opts) {
  var headers = opts.headers || {};
  var url = opts.url instanceof URL ? opts.url : _internalUrl(opts.url);

  var canonicalHeaders = (function () {
    var pairs = [];
    Object.keys(headers).forEach(function (k) {
      var lk = k.toLowerCase();
      if (lk.indexOf("x-ms-") === 0) {
        pairs.push([lk, String(headers[k]).trim().replace(/\s+/g, " ")]);
      }
    });
    pairs.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
    return pairs.map(function (p) { return p[0] + ":" + p[1]; }).join("\n");
  })();

  var canonicalResource = (function () {
    var resourcePath = "/" + opts.accountName + url.pathname;
    var paramPairs = [];
    url.searchParams.forEach(function (v, k) {
      paramPairs.push([k.toLowerCase(), v]);
    });
    paramPairs.sort(function (a, b) {
      if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
      return a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;
    });
    var grouped = {};
    paramPairs.forEach(function (p) {
      if (!grouped[p[0]]) grouped[p[0]] = [];
      grouped[p[0]].push(p[1]);
    });
    var groupedKeys = [];
    for (var gk in grouped) groupedKeys.push(gk);
    groupedKeys.sort();
    var queryLines = groupedKeys.map(function (name) {
      return "\n" + name + ":" + grouped[name].join(",");
    }).join("");
    return resourcePath + queryLines;
  })();

  return [
    opts.method.toUpperCase(),
    headers["Content-Encoding"]      || "",
    headers["Content-Language"]      || "",
    headers["Content-Length"] && headers["Content-Length"] !== "0"
      ? headers["Content-Length"] : "",
    headers["Content-MD5"]           || "",
    headers["Content-Type"]          || "",
    "",
    headers["If-Modified-Since"]     || "",
    headers["If-Match"]              || "",
    headers["If-None-Match"]         || "",
    headers["If-Unmodified-Since"]   || "",
    headers["Range"]                 || "",
    canonicalHeaders,
    canonicalResource,
  ].join("\n");
}

function signRequest(opts) {
  var headers = Object.assign({}, opts.headers || {});
  if (!headers["x-ms-version"]) headers["x-ms-version"] = opts.apiVersion || DEFAULT_API_VERSION;
  if (!headers["x-ms-date"])    headers["x-ms-date"]    = new Date().toUTCString();

  var url = opts.url instanceof URL ? opts.url : _internalUrl(opts.url);
  if (!headers["host"])         headers["host"]         = url.host;

  var sts = buildStringToSign({
    method:      opts.method,
    url:         url,
    headers:     headers,
    accountName: opts.accountName,
  });
  var keyBytes = Buffer.from(opts.accountKey, "base64");
  var signature = nodeCrypto.createHmac("sha256", keyBytes).update(sts, "utf8").digest("base64");
  headers["Authorization"] = "SharedKey " + opts.accountName + ":" + signature;

  return { headers: headers, stringToSign: sts, signature: signature };
}

function create(config) {
  if (!config) throw new Error("azure-blob protocol requires config");
  if (!config.accountName) throw new Error("azure-blob: accountName is required");
  if (!config.accountKey)  throw new Error("azure-blob: accountKey is required");
  if (!config.container)   throw new Error("azure-blob: container is required");

  var endpoint = config.endpoint || ("https://" + config.accountName + ".blob.core.windows.net");
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var apiVersion = config.apiVersion || DEFAULT_API_VERSION;
  var timeoutMs = config.timeoutMs;
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = config.allowInternal != null ? config.allowInternal : null;
  safeUrl.parse(endpoint, { allowedProtocols: allowedProtocols, errorClass: ObjectStoreError });
  var pathStyle = config.pathStyle === true;
  var pathPrefix = pathStyle ? ("/" + config.accountName) : "";
  var reqOpts = { timeoutMs: timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

  function _blobUrl(key, params) {
    var u = _internalUrl(endpoint + pathPrefix + "/" + config.container + "/" + _encodeBlobKey(key),
                         allowedProtocols);
    if (params) {
      Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
    }
    return u;
  }

  function _containerUrl(params) {
    var u = _internalUrl(endpoint + pathPrefix + "/" + config.container, allowedProtocols);
    if (params) {
      Object.keys(params).forEach(function (k) { u.searchParams.set(k, params[k]); });
    }
    return u;
  }

  function _signed(method, url, headers) {
    var s = signRequest({
      method:      method,
      url:         url,
      headers:     headers || {},
      accountName: config.accountName,
      accountKey:  config.accountKey,
      apiVersion:  apiVersion,
    });
    return s.headers;
  }

  function put(key, body, opts) {
    var url = _blobUrl(key);
    var buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : "", "utf8");
    var contentType = (opts && opts.contentType) || "application/octet-stream";
    var headers = _signed("PUT", url, {
      "Content-Type":   contentType,
      "Content-Length": String(buf.length),
      "x-ms-blob-type": "BlockBlob",
    });
    return _httpRequest("PUT", url, headers, buf, reqOpts).then(function (res) {
      return { size: buf.length, etag: res.headers.etag };
    });
  }

  function get(key, opts) {
    return getResponse(key, opts).then(function (r) { return r.body; });
  }

  function getStream(key, opts) { return sharedRequest.promiseToStream(get(key, opts)); }

  function getResponse(key, opts) {
    opts = opts || {};
    var url = _blobUrl(key);
    var extraHeaders = sharedRequest.applyConditionalGetHeaders({}, opts, "x-ms-range");
    var headers = _signed("GET", url, extraHeaders);
    return _httpRequest("GET", url, headers, null, reqOpts).then(function (res) {
      return sharedRequest.mapGetResponse(res);
    }, function (err) {
      if (err && err.statusCode === requestHelpers.HTTP_STATUS.NOT_MODIFIED) {
        return sharedRequest.notModifiedGetResult();
      }
      return sharedRequest.rethrowObjectError(err, key);
    });
  }

  function head(key) {
    var url = _blobUrl(key);
    var headers = _signed("HEAD", url, {});
    return _httpRequest("HEAD", url, headers, null, reqOpts).then(function (res) {
      return sharedRequest.mapHeadResponse(res);
    }, function (err) {
      return sharedRequest.rethrowObjectError(err, key);
    });
  }

  function deleteKey(key, opts) {
    opts = opts || {};
    if (opts.versionId) {
      throw _err("objectstore/versionid-unsupported",
        "deleteKey: versioned delete (opts.versionId) is S3/sigv4-only; the Azure " +
        "Blob backend has no version surface here. Use a sigv4 backend for " +
        "Object-Lock version erasure.", true);
    }
    var url = _blobUrl(key);
    var headers = _signed("DELETE", url, {});
    return _httpRequest("DELETE", url, headers, null, reqOpts).then(
      function () { return true; },
      function (e) { if (e.statusCode === C.HTTP.STATUS.NOT_FOUND) return false; throw e; }
    );
  }

  function list(prefix, opts) {
    opts = opts || {};
    var params = { restype: "container", comp: "list" };
    if (prefix)                   params.prefix = prefix;
    if (opts.maxResults)          params.maxresults = String(opts.maxResults);
    if (opts.continuationToken)   params.marker = opts.continuationToken;
    var url = _containerUrl(params);
    var headers = _signed("GET", url, {});
    return _httpRequest("GET", url, headers, null, reqOpts).then(function (res) {
      var doc = safeXml.parse(res.body, LIST_PARSE_OPTS);
      var result = doc.EnumerationResults || {};
      var blobsContainer = result.Blobs || {};
      var blobs = _arrayify(blobsContainer.Blob);
      var items = blobs.map(function (b) {
        var props = b.Properties || {};
        var size = props["Content-Length"];
        var lm = props["Last-Modified"];
        return {
          key:          b.Name,
          size:         size != null ? parseInt(size, 10) : null,
          lastModified: lm ? Date.parse(lm) : null,
        };
      }).filter(function (it) { return it.key; });
      var marker = (typeof result.NextMarker === "string") ? result.NextMarker : "";
      return {
        items:             items,
        truncated:         marker.length > 0,
        continuationToken: marker.length > 0 ? marker : null,
      };
    });
  }

  function _buildSasToken(permissions, opts) {
    var expiresIn = sharedRequest.resolvePresignExpires(opts, "presigned URL", "");
    var nowDate = opts.date || new Date();
    var expiry = new Date(nowDate.getTime() + C.TIME.seconds(expiresIn));
    var signedExpiry = time.toIso8601NoMs(expiry);
    var signedStart  = "";
    var signedVersion = apiVersion;
    var signedResource = "b";
    var signedProtocol = "https";
    var canonicalizedResource = "/blob/" + config.accountName + "/" +
                                config.container + "/" + opts.key;
    var signedContentType = opts.contentType || "";

    var stringToSign = [
      permissions,
      signedStart,
      signedExpiry,
      canonicalizedResource,
      "",
      "",
      signedProtocol,
      signedVersion,
      signedResource,
      "",
      "",
      "",
      "",
      "",
      "",
      signedContentType,
    ].join("\n");

    var keyBuf = Buffer.from(config.accountKey, "base64");
    var signature = nodeCrypto.createHmac("sha256", keyBuf)
      .update(stringToSign, "utf8").digest("base64");

    var sas = new URLSearchParams();
    sas.set("sv",  signedVersion);
    sas.set("sr",  signedResource);
    sas.set("sp",  permissions);
    sas.set("se",  signedExpiry);
    sas.set("spr", signedProtocol);
    if (signedContentType) sas.set("rsct", signedContentType);
    sas.set("sig", signature);

    return { sas: sas.toString(), expiresAt: expiry.getTime() };
  }

  function _presign(method, permissions, opts) {
    opts = opts || {};
    if (!opts.key || typeof opts.key !== "string") {
      throw _err("objectstore/invalid-key", "presigned URL: key is required", true);
    }
    if (opts.key.indexOf("\0") !== -1) {
      throw _err("objectstore/invalid-key", "null byte in key", true);
    }

    var token = _buildSasToken(permissions, opts);
    var url = _internalUrl(endpoint + pathPrefix + "/" + config.container + "/" + _encodeBlobKey(opts.key) + "?" + token.sas, allowedProtocols);

    var clientHeaders = {};
    if (opts.contentType) clientHeaders["Content-Type"] = opts.contentType;
    if (method === "PUT") clientHeaders["x-ms-blob-type"] = "BlockBlob";

    return {
      url:       url.toString(),
      method:    method,
      headers:   clientHeaders,
      expiresAt: token.expiresAt,
    };
  }

  function presignedUploadUrl(opts)   { return _presign("PUT", "cw", opts); }
  function presignedDownloadUrl(opts) { return _presign("GET", "r",  opts); }

  function presignedUploadPolicy(_opts) {
    throw _err("objectstore/presign-not-supported",
      "azure-blob backend does not support presigned upload policies — " +
      "Azure SAS has no body-size cap. Use presignedUploadUrl + a server-side " +
      "HEAD-and-delete check, or switch to an S3 / GCS-compatible backend.",
      true);
  }

  return {
    protocol:    "azure-blob",
    endpoint:    endpoint,
    container:   config.container,
    accountName: config.accountName,
    put:         put,
    get:         get,
    getStream:   getStream,
    getResponse: getResponse,
    head:        head,
    delete:      deleteKey,
    list:        list,
    presignedUploadUrl:    presignedUploadUrl,
    presignedDownloadUrl:  presignedDownloadUrl,
    presignedUploadPolicy: presignedUploadPolicy,
  };
}

module.exports = {
  create:             create,
  signRequest:        signRequest,
  buildStringToSign:  buildStringToSign,
  DEFAULT_API_VERSION: DEFAULT_API_VERSION,
};

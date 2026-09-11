// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeCrypto = require("node:crypto");
var { URL } = require("node:url");
var safeXml = require("../parsers/safe-xml");
var sharedRequest = require("./http-request");
var C = require("../constants");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");
var safeUrl = require("../safe-url");

function _internalUrl(input, allowedProtocols) {
  return safeUrl.parse(input, {
    allowedProtocols: allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       ObjectStoreError,
    maxUrlLength:     C.BYTES.kib(32),
  });
}

var LIST_PARSE_OPTS = {
  maxBytes:    C.BYTES.mib(8),
  maxElements: C.BYTES.bytes(50000),
};

function _arrayify(value) {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

var SERVICE = "s3";
var ALGORITHM = "AWS4-HMAC-SHA256";

var _err = ObjectStoreError.factory;

function applyVirtualHostedBucket(url, bucket) {
  var host = url.hostname;
  var want = (bucket + "." + host).toLowerCase();
  url.hostname = want;
  if (url.hostname !== want) {
    throw _err("objectstore/invalid-endpoint",
      "virtual-hosted-style addressing cannot place bucket '" + bucket + "' on endpoint host '" +
      host + "' (an IP literal or otherwise non-composable host) — set pathStyle: true", true);
  }
  return url;
}

function sha256Hex(buf) {
  return nodeCrypto.createHash("sha256").update(buf).digest("hex");
}
function hmacSha256(key, data) {
  return nodeCrypto.createHmac("sha256", key).update(data).digest();
}

function awsUriEncode(str, encodeSlash) {
  var out = "";
  var cps = Array.from(str);
  for (var i = 0; i < cps.length; i++) {
    var ch = cps[i];
    var c = ch.codePointAt(0);
    if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) ||
        (c >= 0x30 && c <= 0x39) ||
        ch === "-" || ch === "_" || ch === "." || ch === "~") {
      out += ch;
    } else if (ch === "/" && !encodeSlash) {
      out += "/";
    } else {
      var enc = encodeURIComponent(ch).replace(/!/g, "%21").replace(/\*/g, "%2A").replace(/'/g, "%27").replace(/\(/g, "%28").replace(/\)/g, "%29");
      out += enc;
    }
  }
  return out;
}

function canonicalQueryString(searchParams) {
  if (!searchParams || searchParams.toString() === "") return "";
  var pairs = [];
  searchParams.forEach(function (v, k) { pairs.push([k, v]); });
  pairs.sort(function (a, b) {
    if (a[0] < b[0]) return -1;
    if (a[0] > b[0]) return 1;
    if (a[1] < b[1]) return -1;
    if (a[1] > b[1]) return 1;
    return 0;
  });
  return pairs.map(function (p) {
    return awsUriEncode(p[0], true) + "=" + awsUriEncode(p[1], true);
  }).join("&");
}

function _alignWireQueryToSigV4(url) {
  var search = url.search;
  if (search.indexOf("+") !== -1) {
    url.search = search.replace(/\+/g, "%20");   // allow:regex-no-length-cap — single-char global replace, input bounded by maxUrlLength
  }
}

function canonicalHeaders(headers) {
  var byName = Object.create(null);
  var byNameRaw = Object.create(null);
  var names = [];
  for (var k in headers) {
    if (headers[k] === undefined || headers[k] === null) continue;
    var lk = k.toLowerCase();
    var raw = String(headers[k]).trim();
    var v = raw.replace(/\s+/g, " ");
    if (byName[lk] === undefined) {
      byName[lk] = v;
      byNameRaw[lk] = raw;
      names.push(lk);
    } else {
      byName[lk] += "," + v;
      byNameRaw[lk] += "," + raw;
    }
  }
  names.sort(function (a, b) { return a < b ? -1 : a > b ? 1 : 0; });
  var canon = "";
  var merged = {};
  for (var i = 0; i < names.length; i++) {
    canon += names[i] + ":" + byName[names[i]] + "\n";
    merged[names[i]] = byNameRaw[names[i]];
  }
  return { canonical: canon, signed: names.join(";"), merged: merged };
}

function canonicalRequest(method, urlObj, headers, payloadHash, doubleEncodePath) {
  var canonHeaders = canonicalHeaders(headers);
  var path = urlObj.pathname;
  if (!path) path = "/";
  var canonicalPath = doubleEncodePath ? awsUriEncode(path, false) : path;
  return [
    method.toUpperCase(),
    canonicalPath,
    canonicalQueryString(urlObj.searchParams),
    canonHeaders.canonical,
    canonHeaders.signed,
    payloadHash,
  ].join("\n");
}

function stringToSign(amzDate, credentialScope, canonicalReq) {
  return [
    ALGORITHM,
    amzDate,
    credentialScope,
    sha256Hex(canonicalReq),
  ].join("\n");
}

function deriveSigningKey(secretAccessKey, dateStamp, region, service) {
  var kDate    = hmacSha256("AWS4" + secretAccessKey, dateStamp);
  var kRegion  = hmacSha256(kDate, region);
  var kService = hmacSha256(kRegion, service);
  return hmacSha256(kService, "aws4_request");
}

function _formatAmzDate(d) {
  var iso = d.toISOString().replace(/[-:]/g, "");
  return iso.slice(0, C.BYTES.bytes(8)) + "T" + iso.slice(9, 15) + "Z";
}
function _formatDateStamp(d) {
  return d.toISOString().slice(0, 10).replace(/-/g, "");
}

function signRequest(opts) {
  var date = opts.date || new Date();
  var amzDate = _formatAmzDate(date);
  var dateStamp = _formatDateStamp(date);
  var url = opts.url instanceof URL ? opts.url
                                    : _internalUrl(opts.url, opts.allowedProtocols);
  var service = opts.service || SERVICE;

  var headers = Object.assign({}, opts.headers || {});
  headers["host"] = url.host;
  headers["x-amz-date"] = amzDate;
  if (!headers["x-amz-content-sha256"]) {
    headers["x-amz-content-sha256"] = opts.payloadHash;
  }
  if (opts.sessionToken) {
    headers["x-amz-security-token"] = opts.sessionToken;
  }

  var canon = canonicalRequest(opts.method, url, headers, opts.payloadHash, service !== "s3");
  var credentialScope = dateStamp + "/" + opts.region + "/" + service + "/aws4_request";
  var sts = stringToSign(amzDate, credentialScope, canon);
  var signingKey = deriveSigningKey(opts.secretAccessKey, dateStamp, opts.region, service);
  var signature = nodeCrypto.createHmac("sha256", signingKey).update(sts).digest("hex");

  var canonHeaders = canonicalHeaders(headers);
  var auth = ALGORITHM +
    " Credential=" + opts.accessKeyId + "/" + credentialScope +
    ", SignedHeaders=" + canonHeaders.signed +
    ", Signature=" + signature;

  var wireHeaders = canonHeaders.merged;
  wireHeaders["Authorization"] = auth;

  _alignWireQueryToSigV4(url);

  return { headers: wireHeaders, signature: signature, canonicalRequest: canon, stringToSign: sts };
}

var _request = sharedRequest;

var MIN_PART_SIZE_BYTES = C.BYTES.mib(5);
var MAX_PARTS = C.BYTES.bytes(10000);
var DEFAULT_MULTIPART_THRESHOLD_BYTES = C.BYTES.mib(64);
var DEFAULT_PART_SIZE_BYTES = C.BYTES.mib(16);
var DEFAULT_PART_CONCURRENCY = 4;

function _resolveSseHeaders(sse) {
  if (sse === undefined || sse === null) return null;
  var type;
  var keyId = null;
  if (typeof sse === "string") {
    type = sse;
  } else if (sse && typeof sse === "object") {
    type = sse.type;
    keyId = sse.keyId || null;
  } else {
    throw _err("objectstore/invalid-sse",
      "opts.sse must be a string ('AES256' | 'aws:kms') or " +
      "{ type, keyId }, got " + typeof sse, true);
  }
  if (type !== "AES256" && type !== "aws:kms") {
    throw _err("objectstore/invalid-sse",
      "opts.sse type must be 'AES256' or 'aws:kms', got '" + type + "'", true);
  }
  var h = { "x-amz-server-side-encryption": type };
  if (type === "aws:kms" && keyId) {
    h["x-amz-server-side-encryption-aws-kms-key-id"] = String(keyId);
  }
  return { type: type, keyId: keyId, headers: h };
}

function _verifySseResponse(sseRequested, resHeaders) {
  if (!sseRequested) return;
  var got = resHeaders["x-amz-server-side-encryption"];
  if (!got) {
    throw _err("objectstore/sse-not-applied",
      "opts.sse was '" + sseRequested.type + "' but server did not " +
      "apply server-side encryption (no x-amz-server-side-encryption " +
      "response header)", true);
  }
  if (got !== sseRequested.type) {
    throw _err("objectstore/sse-mismatch",
      "opts.sse requested '" + sseRequested.type + "' but server " +
      "applied '" + got + "'", true);
  }
}

function _buildCompleteMultipartXml(parts) {
  var body = "<CompleteMultipartUpload>";
  for (var i = 0; i < parts.length; i++) {
    body += "<Part>";
    body += "<PartNumber>" + parts[i].partNumber + "</PartNumber>";
    body += "<ETag>" + parts[i].etag + "</ETag>";
    body += "</Part>";
  }
  body += "</CompleteMultipartUpload>";
  return body;
}

async function _readStreamParts(readable, partSize) {
  var parts = [];
  var pending = [];
  var pendingBytes = 0;
  for await (var chunk of readable) {
    var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    pending.push(buf);
    pendingBytes += buf.length;
    while (pendingBytes >= partSize) {
      var combined = Buffer.concat(pending, pendingBytes);
      parts.push(combined.slice(0, partSize));
      var leftover = combined.slice(partSize);
      pending = leftover.length > 0 ? [leftover] : [];
      pendingBytes = leftover.length;
    }
  }
  if (pendingBytes > 0) {
    parts.push(Buffer.concat(pending, pendingBytes));
  }
  return parts;
}

async function _bounded(items, concurrency, runner) {
  var results = new Array(items.length);
  var i = 0;
  async function worker() {
    while (true) {
      var idx = i++;
      if (idx >= items.length) return;
      results[idx] = await runner(items[idx], idx);
    }
  }
  var workers = [];
  for (var w = 0; w < Math.min(concurrency, items.length); w++) {
    workers.push(worker());
  }
  await Promise.all(workers);
  return results;
}

function create(config) {
  if (!config) throw new Error("sigv4 protocol requires config");
  if (!config.region)          throw new Error("sigv4: region is required");
  if (!config.bucket)          throw new Error("sigv4: bucket is required");
  if (!config.accessKeyId)     throw new Error("sigv4: accessKeyId is required");
  if (!config.secretAccessKey) throw new Error("sigv4: secretAccessKey is required");

  var endpoint = config.endpoint || ("https://s3." + config.region + ".amazonaws.com");
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var pathStyle = !!(config.pathStyle || config.forcePathStyle);

  var partSize = config.partSizeBytes != null
    ? config.partSizeBytes
    : DEFAULT_PART_SIZE_BYTES;
  if (typeof partSize !== "number" || !isFinite(partSize) || partSize < MIN_PART_SIZE_BYTES) {
    throw _err("objectstore/invalid-config",
      "sigv4: partSizeBytes must be a number >= " + MIN_PART_SIZE_BYTES +
      " (S3 minimum part size), got " + partSize, true);
  }
  var multipartThreshold = config.multipartThresholdBytes != null
    ? config.multipartThresholdBytes
    : DEFAULT_MULTIPART_THRESHOLD_BYTES;
  if (typeof multipartThreshold !== "number" || !isFinite(multipartThreshold) || multipartThreshold < 0) {
    throw _err("objectstore/invalid-config",
      "sigv4: multipartThresholdBytes must be a non-negative finite number, got " +
      multipartThreshold, true);
  }
  var partConcurrency = config.partConcurrency != null
    ? config.partConcurrency
    : DEFAULT_PART_CONCURRENCY;
  if (typeof partConcurrency !== "number" || partConcurrency < 1 || !isFinite(partConcurrency)) {
    throw _err("objectstore/invalid-config",
      "sigv4: partConcurrency must be a positive finite number, got " + partConcurrency, true);
  }
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = config.allowInternal != null ? config.allowInternal : null;
  safeUrl.parse(endpoint, {
    allowedProtocols: allowedProtocols,
    errorClass:       ObjectStoreError,
  });
  var reqOpts = { timeoutMs: config.timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

  function _keyToUrl(key) {
    if (key.indexOf("\0") !== -1) throw _err("objectstore/invalid-key", "null byte in key", true);
    var encoded = key.split("/").map(function (s) { return awsUriEncode(s, true); }).join("/");
    if (pathStyle) {
      return _internalUrl(endpoint + "/" + config.bucket + "/" + encoded, allowedProtocols);
    }
    var u = _internalUrl(endpoint, allowedProtocols);
    applyVirtualHostedBucket(u, config.bucket);
    u.pathname = "/" + encoded;
    return u;
  }

  function _bucketUrl(searchParams) {
    var u;
    if (pathStyle) {
      u = _internalUrl(endpoint + "/" + config.bucket + "/", allowedProtocols);
    } else {
      u = _internalUrl(endpoint, allowedProtocols);
      applyVirtualHostedBucket(u, config.bucket);
      u.pathname = "/";
    }
    if (searchParams) {
      Object.keys(searchParams).forEach(function (k) { u.searchParams.set(k, searchParams[k]); });
    }
    return u;
  }

  function _makeSigned(method, url, payloadHash, extraHeaders) {
    var signed = signRequest({
      method:          method,
      url:             url,
      headers:         extraHeaders || {},
      payloadHash:     payloadHash,
      region:          config.region,
      accessKeyId:     config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
      sessionToken:    config.sessionToken,
    });
    return signed.headers;
  }

  function put(key, body, opts) {
    opts = opts || {};
    var sseRequested = _resolveSseHeaders(opts.sse);
    var isStream = body && typeof body === "object" && typeof body.pipe === "function";
    if (isStream) {
      if (opts.multipart === false) {
        return Promise.reject(_err("objectstore/stream-requires-multipart",
          "put(stream) requires multipart upload (set opts.multipart !== false)", true));
      }
      return _multipartPut(key, body, opts, sseRequested);
    }
    if (body !== null && body !== undefined &&
        !Buffer.isBuffer(body) && typeof body !== "string") {
      return Promise.reject(_err("objectstore/invalid-body",
        "put: body must be a Buffer, string, or stream (got " +
        (Array.isArray(body) ? "array" : typeof body) + ")", true));
    }
    var buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : "", "utf8");
    if (opts.multipart !== false &&
        (opts.multipart === true || buf.length > multipartThreshold)) {
      return _multipartPut(key, buf, opts, sseRequested);
    }
    return _singlePut(key, buf, opts, sseRequested);
  }

  function _singlePut(key, buf, opts, sseRequested) {
    var url = _keyToUrl(key);
    var payloadHash = sha256Hex(buf);
    var contentType = opts.contentType || "application/octet-stream";
    var extra = {
      "Content-Type":   contentType,
      "Content-Length": String(buf.length),
    };
    if (sseRequested) Object.assign(extra, sseRequested.headers);
    var headers = _makeSigned("PUT", url, payloadHash, extra);
    return _request("PUT", url, headers, buf, reqOpts).then(function (res) {
      _verifySseResponse(sseRequested, res.headers);
      return {
        size: buf.length,
        etag: res.headers.etag,
        versionId: res.headers && res.headers["x-amz-version-id"] || null,
      };
    });
  }

  async function _multipartPut(key, body, opts, sseRequested) {
    var contentType = opts.contentType || "application/octet-stream";

    var parts;
    if (Buffer.isBuffer(body)) {
      parts = [];
      for (var off = 0; off < body.length; off += partSize) {
        parts.push(body.slice(off, Math.min(off + partSize, body.length)));
      }
      if (parts.length === 0) parts = [Buffer.alloc(0)];
    } else {
      parts = await _readStreamParts(body, partSize);
      if (parts.length === 0) parts = [Buffer.alloc(0)];
    }
    if (parts.length > MAX_PARTS) {
      throw _err("objectstore/too-many-parts",
        "multipart upload would require " + parts.length + " parts " +
        "(S3 max " + MAX_PARTS + "); increase partSizeBytes", true);
    }

    var url = _keyToUrl(key);
    var initiateUrl = _internalUrl(url.href + (url.search ? "&" : "?") + "uploads", allowedProtocols);
    var initiateExtra = {
      "Content-Type":   contentType,
      "Content-Length": "0",
    };
    if (sseRequested) Object.assign(initiateExtra, sseRequested.headers);
    var initiateHeaders = _makeSigned("POST", initiateUrl, sha256Hex(Buffer.alloc(0)), initiateExtra);
    var initRes = await _request("POST", initiateUrl, initiateHeaders, Buffer.alloc(0), reqOpts);
    _verifySseResponse(sseRequested, initRes.headers);
    var initDoc = safeXml.parse(initRes.body, LIST_PARSE_OPTS);
    var uploadId = initDoc.InitiateMultipartUploadResult &&
      initDoc.InitiateMultipartUploadResult.UploadId;
    if (!uploadId) {
      throw _err("objectstore/multipart-init-failed",
        "S3 InitiateMultipartUpload response missing UploadId", false);
    }

    var totalSize = 0;
    var uploadedEtags;

    try {
      uploadedEtags = await _bounded(parts, partConcurrency, async function (partBuf, idx) {
        var partNumber = idx + 1;
        var partUrl = _internalUrl(url.href, allowedProtocols);
        partUrl.searchParams.set("partNumber", String(partNumber));
        partUrl.searchParams.set("uploadId", uploadId);
        var partHeaders = _makeSigned("PUT", partUrl, sha256Hex(partBuf), {
          "Content-Length": String(partBuf.length),
        });
        var partRes = await _request("PUT", partUrl, partHeaders, partBuf, reqOpts);
        if (!partRes.headers.etag) {
          throw _err("objectstore/multipart-part-failed",
            "UploadPart response missing ETag for part " + partNumber, false);
        }
        totalSize += partBuf.length;
        return { partNumber: partNumber, etag: partRes.headers.etag };
      });

      var completeUrl = _internalUrl(url.href, allowedProtocols);
      completeUrl.searchParams.set("uploadId", uploadId);
      var completeBody = Buffer.from(_buildCompleteMultipartXml(uploadedEtags), "utf8");
      var completeHeaders = _makeSigned("POST", completeUrl, sha256Hex(completeBody), {
        "Content-Type":   "application/xml",
        "Content-Length": String(completeBody.length),
      });
      var completeRes = await _request("POST", completeUrl, completeHeaders, completeBody, reqOpts);
      var completeDoc = safeXml.parse(completeRes.body, LIST_PARSE_OPTS);
      if (completeDoc.Error) {
        throw _err("objectstore/multipart-complete-failed",
          "CompleteMultipartUpload returned error: " +
          (completeDoc.Error.Code || "unknown") + " " +
          (completeDoc.Error.Message || ""), false);
      }
      var result = completeDoc.CompleteMultipartUploadResult || {};
      return {
        size: totalSize,
        etag: result.ETag || completeRes.headers.etag,
        multipart: true,
        versionId: completeRes.headers && completeRes.headers["x-amz-version-id"] || null,
      };
    } catch (e) {
      try {
        var abortUrl = _internalUrl(url.href, allowedProtocols);
        abortUrl.searchParams.set("uploadId", uploadId);
        var abortHeaders = _makeSigned("DELETE", abortUrl, sha256Hex(Buffer.alloc(0)));
        await _request("DELETE", abortUrl, abortHeaders, null, reqOpts);
      } catch (_e) { /* primary error wins */ }
      throw e;
    }
  }

  function get(key, opts) {
    return getResponse(key, opts).then(function (r) { return r.body; });
  }

  function getStream(key, opts) {
    return sharedRequest.promiseToStream(get(key, opts));
  }

  function getResponse(key, opts) {
    opts = opts || {};
    var url = _keyToUrl(key);
    if (opts.versionId) url.searchParams.set("versionId", opts.versionId);
    var headers = _makeSigned("GET", url, sha256Hex(Buffer.alloc(0)));
    sharedRequest.applyConditionalGetHeaders(headers, opts, "Range");
    var localReqOpts = Object.assign({}, reqOpts, { _resolveOnRedirect: false });
    return _request("GET", url, headers, null, localReqOpts).then(function (res) {
      return sharedRequest.mapGetResponse(res);
    }, function (err) {
      if (err && err.statusCode === requestHelpers.HTTP_STATUS.NOT_MODIFIED) {
        return sharedRequest.notModifiedGetResult();
      }
      return sharedRequest.rethrowObjectError(err, key);
    });
  }

  function head(key, opts) {
    opts = opts || {};
    var url = _keyToUrl(key);
    if (opts.versionId) url.searchParams.set("versionId", opts.versionId);
    var headers = _makeSigned("HEAD", url, sha256Hex(Buffer.alloc(0)));
    return _request("HEAD", url, headers, null, reqOpts).then(function (res) {
      return sharedRequest.mapHeadResponse(res);
    }, function (e) {
      return sharedRequest.rethrowObjectError(e, key);
    });
  }

  function deleteKey(key, opts) {
    opts = opts || {};
    var url = _keyToUrl(key);
    if (opts.versionId) url.searchParams.set("versionId", opts.versionId);
    var extra = {};
    if (opts.bypassGovernanceRetention) extra["x-amz-bypass-governance-retention"] = "true";
    var headers = _makeSigned("DELETE", url, sha256Hex(Buffer.alloc(0)), extra);
    return _request("DELETE", url, headers, null, reqOpts).then(
      function () { return true; },
      function (e) { if (e.statusCode === C.HTTP.STATUS.NOT_FOUND) return false; throw e; }
    );
  }

  var RESPONSE_HEADER_QUERY_KEYS = {
    contentDisposition: "response-content-disposition",
    contentType:        "response-content-type",
    contentLanguage:    "response-content-language",
    contentEncoding:    "response-content-encoding",
    cacheControl:       "response-cache-control",
    expires:            "response-expires",
  };

  function _presign(method, opts) {
    opts = opts || {};
    sharedRequest.requirePresignKey(opts, "presigned URL");
    var expiresIn = sharedRequest.resolvePresignExpires(opts, "presigned URL", "SigV4");

    var responseHeaders = opts.responseHeaders;
    if (responseHeaders !== undefined && responseHeaders !== null) {
      if (typeof responseHeaders !== "object") {
        throw _err("objectstore/invalid-response-headers",
          "presigned URL: responseHeaders must be an object", true);
      }
      var rhKeys = Object.keys(responseHeaders);
      for (var rhi = 0; rhi < rhKeys.length; rhi += 1) {
        var rhk = rhKeys[rhi];
        if (!Object.prototype.hasOwnProperty.call(RESPONSE_HEADER_QUERY_KEYS, rhk)) {
          throw _err("objectstore/invalid-response-headers",
            "presigned URL: responseHeaders.'" + rhk + "' is not recognised " +
            "(allowed: " + Object.keys(RESPONSE_HEADER_QUERY_KEYS).join(", ") + ")", true);
        }
        var rhv = responseHeaders[rhk];
        if (typeof rhv !== "string" || rhv.length === 0) {
          throw _err("objectstore/invalid-response-headers",
            "presigned URL: responseHeaders.'" + rhk + "' must be a non-empty string", true);
        }
        if (/[\r\n\0]/.test(rhv)) {
          throw _err("objectstore/invalid-response-headers",
            "presigned URL: responseHeaders.'" + rhk + "' contains CR/LF/NUL — refused as a header-injection vector", true);
        }
      }
    }

    var url = _keyToUrl(opts.key);
    var date = opts.date || new Date();
    var amzDate = _formatAmzDate(date);
    var dateStamp = _formatDateStamp(date);
    var credentialScope = dateStamp + "/" + config.region + "/" + SERVICE + "/aws4_request";

    var headers = { host: url.host };
    if (opts.contentType) headers["content-type"] = opts.contentType;
    var signedHeaderKeys = [];
    for (var hk in headers) signedHeaderKeys.push(hk);
    signedHeaderKeys.sort();
    var signedHeadersStr = signedHeaderKeys.join(";");

    url.searchParams.set("X-Amz-Algorithm", ALGORITHM);
    url.searchParams.set("X-Amz-Credential", config.accessKeyId + "/" + credentialScope);
    url.searchParams.set("X-Amz-Date", amzDate);
    url.searchParams.set("X-Amz-Expires", String(expiresIn));
    url.searchParams.set("X-Amz-SignedHeaders", signedHeadersStr);
    if (config.sessionToken) {
      url.searchParams.set("X-Amz-Security-Token", config.sessionToken);
    }
    if (responseHeaders) {
      for (var rhk2 = 0; rhk2 < rhKeys.length; rhk2 += 1) {
        var camel = rhKeys[rhk2];
        url.searchParams.set(RESPONSE_HEADER_QUERY_KEYS[camel], responseHeaders[camel]);
      }
    }

    var canon = canonicalRequest(method, url, headers, "UNSIGNED-PAYLOAD");
    var sts = stringToSign(amzDate, credentialScope, canon);
    var signingKey = deriveSigningKey(config.secretAccessKey, dateStamp, config.region, SERVICE);
    var signature = nodeCrypto.createHmac("sha256", signingKey).update(sts).digest("hex");

    url.searchParams.set("X-Amz-Signature", signature);
    _alignWireQueryToSigV4(url);

    var clientHeaders = {};
    if (opts.contentType) clientHeaders["Content-Type"] = opts.contentType;

    return {
      url:       url.toString(),
      method:    method,
      headers:   clientHeaders,
      expiresAt: date.getTime() + C.TIME.seconds(expiresIn),
    };
  }

  function presignedUploadUrl(opts)   { return _presign("PUT", opts); }
  function presignedDownloadUrl(opts) { return _presign("GET", opts); }

  function presignedUploadPolicy(opts) {
    opts = opts || {};
    sharedRequest.requirePresignKey(opts, "presignedUploadPolicy");
    var minBytes = sharedRequest.resolvePresignUploadMinBytes(opts);
    var expiresIn = sharedRequest.resolvePresignExpires(opts, "presignedUploadPolicy", "SigV4");

    var date = opts.date || new Date();
    var amzDate = _formatAmzDate(date);
    var dateStamp = _formatDateStamp(date);
    var credentialScope = dateStamp + "/" + config.region + "/" + SERVICE + "/aws4_request";
    var credential = config.accessKeyId + "/" + credentialScope;
    var expirationIso = new Date(date.getTime() + C.TIME.seconds(expiresIn)).toISOString();

    var conditions = [
      { "bucket":           config.bucket },
      { "key":              opts.key },
      { "x-amz-algorithm":  ALGORITHM },
      { "x-amz-credential": credential },
      { "x-amz-date":       amzDate },
      ["content-length-range", minBytes, opts.maxBytes],
    ];
    if (config.sessionToken) {
      conditions.push({ "x-amz-security-token": config.sessionToken });
    }
    if (opts.contentType) {
      conditions.push({ "content-type": opts.contentType });
    }

    var policy = { expiration: expirationIso, conditions: conditions };
    var policyJson = JSON.stringify(policy);
    var policyB64 = Buffer.from(policyJson, "utf8").toString("base64");

    var signingKey = deriveSigningKey(config.secretAccessKey, dateStamp, config.region, SERVICE);
    var signature = nodeCrypto.createHmac("sha256", signingKey).update(policyB64).digest("hex");

    var fields = {
      "key":              opts.key,
      "x-amz-algorithm":  ALGORITHM,
      "x-amz-credential": credential,
      "x-amz-date":       amzDate,
      "policy":           policyB64,
      "x-amz-signature":  signature,
    };
    if (config.sessionToken) fields["x-amz-security-token"] = config.sessionToken;
    if (opts.contentType)    fields["content-type"]         = opts.contentType;

    var url = _bucketUrl();

    return {
      url:           url.toString(),
      method:        "POST",
      fields:        fields,
      expiresAt:     date.getTime() + C.TIME.seconds(expiresIn),
      maxBytes:      opts.maxBytes,
      enforcement:   "content-length-range",
    };
  }

  function list(prefix, opts) {
    opts = opts || {};
    var params = { "list-type": "2" };
    if (prefix) params["prefix"] = prefix;
    if (opts.maxResults) params["max-keys"] = String(opts.maxResults);
    if (opts.continuationToken) params["continuation-token"] = opts.continuationToken;

    var url = _bucketUrl(params);
    var headers = _makeSigned("GET", url, sha256Hex(Buffer.alloc(0)));
    return _request("GET", url, headers, null, reqOpts).then(function (res) {
      var doc = safeXml.parse(res.body, LIST_PARSE_OPTS);
      var result = doc.ListBucketResult || {};
      var contents = _arrayify(result.Contents);
      var items = contents.map(function (c) {
        return {
          key:          c.Key,
          size:         c.Size != null ? parseInt(c.Size, 10) : null,
          lastModified: c.LastModified ? Date.parse(c.LastModified) : null,
        };
      }).filter(function (it) { return it.key; });
      return {
        items:             items,
        truncated:         result.IsTruncated === "true",
        continuationToken: result.NextContinuationToken || null,
      };
    });
  }

  function listVersions(prefix, opts) {
    opts = opts || {};
    var params = { versions: "" };
    if (prefix) params["prefix"] = prefix;
    if (opts.maxResults) params["max-keys"] = String(opts.maxResults);
    if (opts.keyMarker) params["key-marker"] = opts.keyMarker;
    if (opts.versionIdMarker) params["version-id-marker"] = opts.versionIdMarker;

    var url = _bucketUrl(params);
    var headers = _makeSigned("GET", url, sha256Hex(Buffer.alloc(0)));
    return _request("GET", url, headers, null, reqOpts).then(function (res) {
      var doc = safeXml.parse(res.body, LIST_PARSE_OPTS);
      var result = doc.ListVersionsResult || {};
      function _mapEntry(e, isDeleteMarker) {
        return {
          key:          e.Key,
          versionId:    e.VersionId != null ? String(e.VersionId) : null,
          isLatest:     e.IsLatest === "true",
          deleteMarker: isDeleteMarker,
          size:         isDeleteMarker ? null : (e.Size != null ? parseInt(e.Size, 10) : null),
          lastModified: e.LastModified ? Date.parse(e.LastModified) : null,
          etag:         isDeleteMarker ? null : (e.ETag || null),
        };
      }
      var versions = _arrayify(result.Version).map(function (v) { return _mapEntry(v, false); });
      var markers = _arrayify(result.DeleteMarker).map(function (m) { return _mapEntry(m, true); });
      var items = versions.concat(markers).filter(function (it) { return it.key; });
      return {
        items:           items,
        truncated:       result.IsTruncated === "true",
        keyMarker:       result.NextKeyMarker || null,
        versionIdMarker: result.NextVersionIdMarker || null,
      };
    });
  }

  return {
    protocol:  "sigv4",
    endpoint:  endpoint,
    bucket:    config.bucket,
    region:    config.region,
    pathStyle: pathStyle,
    put:       put,
    get:       get,
    getStream: getStream,
    getResponse: getResponse,
    head:      head,
    delete:    deleteKey,
    list:      list,
    listVersions: listVersions,
    presignedUploadUrl:    presignedUploadUrl,
    presignedDownloadUrl:  presignedDownloadUrl,
    presignedUploadPolicy: presignedUploadPolicy,
  };
}

module.exports = {
  create:               create,
  applyVirtualHostedBucket: applyVirtualHostedBucket,
  signRequest:          signRequest,
  canonicalRequest:     canonicalRequest,
  stringToSign:         stringToSign,
  deriveSigningKey:     deriveSigningKey,
  canonicalQueryString: canonicalQueryString,
  canonicalHeaders:     canonicalHeaders,
  alignWireQueryToSigV4: _alignWireQueryToSigV4,
  awsUriEncode:         awsUriEncode,
  sha256Hex:            sha256Hex,
  formatAmzDate:        _formatAmzDate,
  formatDateStamp:      _formatDateStamp,
  SERVICE:              SERVICE,
  ALGORITHM:            ALGORITHM,
};

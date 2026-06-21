"use strict";
/**
 * SigV4 protocol adapter — AWS Signature Version 4.
 *
 * One signing implementation covers the entire S3-API-compatible family:
 *   AWS S3, Cloudflare R2, Backblaze B2 (S3 endpoint), MinIO, Wasabi,
 *   Tigris, DigitalOcean Spaces, IDrive e2, Linode Object Storage, Storj
 *   (S3 gateway). Service identifier is always "s3" for object storage.
 *
 * Config:
 *   {
 *     endpoint:        'https://s3.us-west-2.amazonaws.com'  // or R2/MinIO/etc.
 *     region:          'us-west-2'                            // required
 *     bucket:          'my-bucket'                            // required
 *     accessKeyId:     '...'                                  // required
 *     secretAccessKey: '...'                                  // required
 *     sessionToken:    '...'                                  // optional (STS)
 *     pathStyle:       false                                  // virtual-hosted
 *                                                             //  by default
 *     timeoutMs:       C.TIME.seconds(30)
 *   }
 *
 * Reference:
 *   https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
 */
var nodeCrypto = require("node:crypto");
var { URL } = require("node:url");
var safeXml = require("../parsers/safe-xml");
var sharedRequest = require("./http-request");
var C = require("../constants");
var requestHelpers = require("../request-helpers");
var { ObjectStoreError } = require("../framework-error");
var safeUrl = require("../safe-url");

// Internal URL builder — endpoint + path string from validated config /
// framework-encoded keys. Routes through safeUrl.parse so the protocol
// allowlist + length cap apply uniformly. Presigned URLs with many
// query params can approach the 8 KB default; raise the cap to 32 KB
// so a worst-case multipart UploadPart URL still fits.
function _internalUrl(input, allowedProtocols) {
  return safeUrl.parse(input, {
    allowedProtocols: allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       ObjectStoreError,
    maxUrlLength:     C.BYTES.kib(32),
  });
}

// S3 list responses are commonly 1000-key paginated payloads — well above
// the parser's default 1 MiB / 10K element ceilings. These overrides
// give headroom for normal responses without uncapping the parser.
var LIST_PARSE_OPTS = {
  maxBytes:    C.BYTES.mib(8),
  maxElements: C.BYTES.bytes(50000),
};

function _arrayify(value) {
  // xml-safe maps multiple same-tag children to an array; a single child
  // stays as the bare object; zero children means the property is absent.
  // List traversal needs a uniform array, so normalize.
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

var SERVICE = "s3";
var ALGORITHM = "AWS4-HMAC-SHA256";

var _err = ObjectStoreError.factory;

// ---- SigV4 primitives ----

function sha256Hex(buf) {
  return nodeCrypto.createHash("sha256").update(buf).digest("hex");
}
function hmacSha256(key, data) {
  return nodeCrypto.createHmac("sha256", key).update(data).digest();
}

// AWS-style URI encoding: same as RFC 3986 except path '/' may be preserved.
function awsUriEncode(str, encodeSlash) {
  var out = "";
  // Iterate by Unicode code point, not UTF-16 code unit. Array.from() keeps a
  // non-BMP character's surrogate pair together (one element), so a key like
  // "photo-<U+1F600>.jpg" encodes as a single UTF-8 sequence. Iterating by
  // index would hand encodeURIComponent a lone surrogate, which throws
  // "URIError: URI malformed". Output is byte-for-byte identical for the
  // BMP/ASCII keys that are the overwhelming common case.
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

function canonicalHeaders(headers) {
  var pairs = [];
  for (var k in headers) {
    if (headers[k] === undefined || headers[k] === null) continue;
    var lk = k.toLowerCase();
    var v = String(headers[k]).trim().replace(/\s+/g, " ");
    pairs.push([lk, v]);
  }
  pairs.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
  var canon = "";
  var signed = [];
  for (var i = 0; i < pairs.length; i++) {
    canon += pairs[i][0] + ":" + pairs[i][1] + "\n";
    signed.push(pairs[i][0]);
  }
  return { canonical: canon, signed: signed.join(";") };
}

// AWS SigV4 canonical URI. Per the SigV4 spec, S3 (and S3-compatible stores +
// GCS's V4) URI-encode the path EXACTLY ONCE; every other AWS service (sqs,
// logs, sns, ...) encodes it TWICE. Callers build urlObj through the WHATWG URL
// parser, so urlObj.pathname is ALREADY the single-encoded wire form (a key
// "a b.txt" is "/a%20b.txt") and the request sends that pathname verbatim. So
// for S3/GCS the canonical path MUST equal the pathname as-is: a second
// awsUriEncode would sign "/a%2520b.txt", a path the wire never carries, giving
// SignatureDoesNotMatch (403) for any key with a space/+/&/unicode. For the
// double-encode services the second pass is the spec requirement. signRequest
// derives doubleEncodePath from the service; GCS's V4 signer passes false.
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

// SigV4 ISO compact format: YYYYMMDDTHHMMSSZ — slice indices fixed
// by AWS spec.
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
  // signRequest is called by callers signing requests to operator-
  // configured endpoints (cloudwatch, sqs, sns, custom S3-API stores).
  // Honor opts.allowedProtocols so a test-fixture http:// endpoint still
  // signs correctly while production https:// stays the default.
  var url = opts.url instanceof URL ? opts.url
                                    : _internalUrl(opts.url, opts.allowedProtocols);
  // service defaults to s3 for back-compat — every call site predating
  // v0.6.25 was object-store / S3. Other AWS services (logs, sqs, sns,
  // kinesis, etc.) pass opts.service explicitly. The credentialScope
  // and signing-key derivation both incorporate the service name, so
  // this MUST match what the target service expects.
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

  // S3 single-encodes the canonical path; every other AWS service double-encodes
  // it (see canonicalRequest). The path itself is "/" for the non-S3 callers
  // (cloudwatch/sqs put params in the query or body), so this only changes the
  // wire result for S3, where it fixes the long-standing double-encode 403.
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
  headers["Authorization"] = auth;

  return { headers: headers, signature: signature, canonicalRequest: canon, stringToSign: sts };
}

// ---- HTTP request helper ----

var _request = sharedRequest;

// ---- Multipart-upload constants ----

// S3 spec floor for non-final part size. Below this the API rejects
// CompleteMultipartUpload with EntityTooSmall. The framework refuses
// configurations below this floor at create() time so operators don't
// see surprising failures only on large uploads.
var MIN_PART_SIZE_BYTES = C.BYTES.mib(5);
// S3 spec ceiling on part count. CompleteMultipartUpload rejects
// uploads with more than 10000 parts.
var MAX_PARTS = C.BYTES.bytes(10000);
// Auto-multipart trigger: buffered bodies under this stay single-PUT.
// Streams always go multipart since size isn't known up-front.
var DEFAULT_MULTIPART_THRESHOLD_BYTES = C.BYTES.mib(64);
// Conservative default part size — large enough to keep round-trip
// overhead small relative to payload, small enough to fit comfortably
// in a 4-way-concurrent upload's memory footprint.
var DEFAULT_PART_SIZE_BYTES = C.BYTES.mib(16);
var DEFAULT_PART_CONCURRENCY = 4;

// ---- SSE option handling ----

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
    throw _err("INVALID_SSE",
      "opts.sse must be a string ('AES256' | 'aws:kms') or " +
      "{ type, keyId }, got " + typeof sse, true);
  }
  if (type !== "AES256" && type !== "aws:kms") {
    throw _err("INVALID_SSE",
      "opts.sse type must be 'AES256' or 'aws:kms', got '" + type + "'", true);
  }
  var h = { "x-amz-server-side-encryption": type };
  if (type === "aws:kms" && keyId) {
    h["x-amz-server-side-encryption-aws-kms-key-id"] = String(keyId);
  }
  return { type: type, keyId: keyId, headers: h };
}

function _verifySseResponse(sseRequested, resHeaders) {
  // Operators who specified an SSE policy expect the bucket / object to
  // honor it. If the server silently dropped the header (mis-configured
  // bucket policy, unsupported endpoint, etc.) the request looks like a
  // success but the at-rest data is unencrypted. Surface this as a
  // hard failure rather than a silent compliance hole.
  if (!sseRequested) return;
  var got = resHeaders["x-amz-server-side-encryption"];
  if (!got) {
    throw _err("SSE_NOT_APPLIED",
      "opts.sse was '" + sseRequested.type + "' but server did not " +
      "apply server-side encryption (no x-amz-server-side-encryption " +
      "response header)", true);
  }
  if (got !== sseRequested.type) {
    throw _err("SSE_MISMATCH",
      "opts.sse requested '" + sseRequested.type + "' but server " +
      "applied '" + got + "'", true);
  }
}

// ---- Multipart helpers ----

// Build the CompleteMultipartUpload request body. Parts must be in
// ascending PartNumber order. ETags from S3 include surrounding
// quotes — preserve them exactly.
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

// Read a Readable stream into fixed-size buffers. Yields one Buffer
// per part (size <= partSize). The final part may be smaller. The
// stream is consumed exactly once.
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

// Run an array of async tasks with bounded parallelism. Preserves
// result order by index.
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

// ---- Public adapter factory ----

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
    throw _err("INVALID_CONFIG",
      "sigv4: partSizeBytes must be a number >= " + MIN_PART_SIZE_BYTES +
      " (S3 minimum part size), got " + partSize, true);
  }
  var multipartThreshold = config.multipartThresholdBytes != null
    ? config.multipartThresholdBytes
    : DEFAULT_MULTIPART_THRESHOLD_BYTES;
  if (typeof multipartThreshold !== "number" || !isFinite(multipartThreshold) || multipartThreshold < 0) {
    throw _err("INVALID_CONFIG",
      "sigv4: multipartThresholdBytes must be a non-negative finite number, got " +
      multipartThreshold, true);
  }
  var partConcurrency = config.partConcurrency != null
    ? config.partConcurrency
    : DEFAULT_PART_CONCURRENCY;
  if (typeof partConcurrency !== "number" || partConcurrency < 1 || !isFinite(partConcurrency)) {
    throw _err("INVALID_CONFIG",
      "sigv4: partConcurrency must be a positive finite number, got " + partConcurrency, true);
  }
  // HTTPS-only by default — AWS S3, R2, MinIO-over-https. Operators with
  // an internal cleartext S3-compatible endpoint (test fixtures, local
  // dev MinIO) opt in via config.allowedProtocols.
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = config.allowInternal != null ? config.allowInternal : null;
  safeUrl.parse(endpoint, {
    allowedProtocols: allowedProtocols,
    errorClass:       ObjectStoreError,
  });
  var reqOpts = { timeoutMs: config.timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

  function _keyToUrl(key) {
    if (key.indexOf("\0") !== -1) throw _err("INVALID_KEY", "null byte in key", true);
    var encoded = key.split("/").map(function (s) { return awsUriEncode(s, true); }).join("/");
    if (pathStyle) {
      return _internalUrl(endpoint + "/" + config.bucket + "/" + encoded, allowedProtocols);
    }
    var u = _internalUrl(endpoint, allowedProtocols);
    u.hostname = config.bucket + "." + u.hostname;
    u.pathname = "/" + encoded;
    return u;
  }

  function _bucketUrl(searchParams) {
    var u;
    if (pathStyle) {
      u = _internalUrl(endpoint + "/" + config.bucket + "/", allowedProtocols);
    } else {
      u = _internalUrl(endpoint, allowedProtocols);
      u.hostname = config.bucket + "." + u.hostname;
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
    // Streams always go multipart — size isn't known up-front. Buffers
    // dispatch to multipart when they exceed the threshold; operators
    // can force the single-PUT path with `multipart: false` (small
    // bodies in unit tests, or to keep the request count to one).
    var isStream = body && typeof body === "object" && typeof body.pipe === "function";
    if (isStream) {
      if (opts.multipart === false) {
        return Promise.reject(_err("STREAM_REQUIRES_MULTIPART",
          "put(stream) requires multipart upload (set opts.multipart !== false)", true));
      }
      return _multipartPut(key, body, opts, sseRequested);
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
        // On a versioning-enabled (Object-Lock) bucket S3/MinIO returns the
        // version this PUT created. Surface it so callers can target the
        // exact version for a later versioned delete / erasure — without it
        // the only way to find the version is a separate listVersions() call.
        versionId: res.headers && res.headers["x-amz-version-id"] || null,
      };
    });
  }

  async function _multipartPut(key, body, opts, sseRequested) {
    var contentType = opts.contentType || "application/octet-stream";

    // Slice into parts. For Buffers we slice up-front; for streams we
    // read sequentially into part-sized buffers (memory bounded).
    var parts;
    if (Buffer.isBuffer(body)) {
      parts = [];
      for (var off = 0; off < body.length; off += partSize) {
        parts.push(body.slice(off, Math.min(off + partSize, body.length)));
      }
      // Edge case: empty buffer → one zero-length part. S3 rejects
      // multipart with zero parts; rather than handling this corner
      // we route empty buffers through single-PUT instead.
      if (parts.length === 0) parts = [Buffer.alloc(0)];
    } else {
      parts = await _readStreamParts(body, partSize);
      if (parts.length === 0) parts = [Buffer.alloc(0)];
    }
    if (parts.length > MAX_PARTS) {
      throw _err("TOO_MANY_PARTS",
        "multipart upload would require " + parts.length + " parts " +
        "(S3 max " + MAX_PARTS + "); increase partSizeBytes", true);
    }

    // 1. Initiate — `?uploads` is the InitiateMultipartUpload subresource.
    // Build the URL with the bare token (no trailing `=`) for consistency
    // with sigv4-bucket-ops.js — strict S3 implementations route on the
    // bare form; the `URLSearchParams.set("uploads", "")` idiom produces
    // `?uploads=` which is accepted by AWS + MinIO for this specific
    // subresource, but the framework's convention is the bare form
    // everywhere. SigV4 canonicalization reads `url.searchParams` (which
    // still presents `uploads=` per AWS spec) so the signature path is
    // unchanged.
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
      throw _err("MULTIPART_INIT_FAILED",
        "S3 InitiateMultipartUpload response missing UploadId", false);
    }

    var totalSize = 0;
    var uploadedEtags;

    try {
      // 2. Upload parts (concurrency-bounded)
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
          throw _err("MULTIPART_PART_FAILED",
            "UploadPart response missing ETag for part " + partNumber, false);
        }
        totalSize += partBuf.length;
        return { partNumber: partNumber, etag: partRes.headers.etag };
      });

      // 3. Complete
      var completeUrl = _internalUrl(url.href, allowedProtocols);
      completeUrl.searchParams.set("uploadId", uploadId);
      var completeBody = Buffer.from(_buildCompleteMultipartXml(uploadedEtags), "utf8");
      var completeHeaders = _makeSigned("POST", completeUrl, sha256Hex(completeBody), {
        "Content-Type":   "application/xml",
        "Content-Length": String(completeBody.length),
      });
      var completeRes = await _request("POST", completeUrl, completeHeaders, completeBody, reqOpts);
      // S3 may return 200 OK with an error body on CompleteMultipartUpload —
      // surface that as a hard error rather than a silent success.
      var completeDoc = safeXml.parse(completeRes.body, LIST_PARSE_OPTS);
      if (completeDoc.Error) {
        throw _err("MULTIPART_COMPLETE_FAILED",
          "CompleteMultipartUpload returned error: " +
          (completeDoc.Error.Code || "unknown") + " " +
          (completeDoc.Error.Message || ""), false);
      }
      // SSE was already verified on the InitiateMultipartUpload
      // response — that's the request that establishes the upload's
      // encryption policy server-side. The CompleteMultipartUpload
      // response may or may not echo the header depending on vendor;
      // re-verifying here would double-fault on otherwise-fine setups.
      var result = completeDoc.CompleteMultipartUploadResult || {};
      return {
        size: totalSize,
        etag: result.ETag || completeRes.headers.etag,
        multipart: true,
        versionId: completeRes.headers && completeRes.headers["x-amz-version-id"] || null,
      };
    } catch (e) {
      // Abort cleans up server-side storage for the partial upload.
      // Failures here are silently swallowed — the caller's original
      // error is what they need to see, not a secondary cleanup error.
      try {
        var abortUrl = _internalUrl(url.href, allowedProtocols);
        abortUrl.searchParams.set("uploadId", uploadId);
        var abortHeaders = _makeSigned("DELETE", abortUrl, sha256Hex(Buffer.alloc(0)));
        await _request("DELETE", abortUrl, abortHeaders, null, reqOpts);
      } catch (_e) { /* primary error wins */ }
      throw e;
    }
  }

  // get(key, opts?) — opts forwarded to the request as conditional /
  // range headers so operator HTTP routes can pass If-None-Match,
  // If-Match, If-Modified-Since, If-Unmodified-Since, and Range from the
  // client request straight through to S3. Returns just the body buffer
  // for backwards compatibility; operators wanting status + response
  // headers (304 vs 206 vs 200) call getResponse() instead.
  function get(key, opts) {
    return getResponse(key, opts).then(function (r) { return r.body; });
  }

  function getStream(key, opts) {
    return sharedRequest.promiseToStream(get(key, opts));
  }

  // getResponse(key, opts?) — full-fidelity GET. Returns
  // { body, statusCode, etag, lastModified, contentRange, size,
  //   contentType }. Throws on non-2xx EXCEPT 304 (returned as
  // { statusCode: 304, etag, lastModified, body: null }) so operator
  // routes can short-circuit conditional GETs without losing the
  // response headers.
  function getResponse(key, opts) {
    opts = opts || {};
    var url = _keyToUrl(key);
    // Reading a specific version (opts.versionId) is the read half of the
    // WORM erasure workflow — verify a protected version is present before /
    // gone after a versioned delete. Set it before signing so the query
    // param is in the SigV4 canonical request.
    if (opts.versionId) url.searchParams.set("versionId", opts.versionId);
    var headers = _makeSigned("GET", url, sha256Hex(Buffer.alloc(0)));
    sharedRequest.applyConditionalGetHeaders(headers, opts, "Range");
    var localReqOpts = Object.assign({}, reqOpts, { _resolveOnRedirect: false });
    return _request("GET", url, headers, null, localReqOpts).then(function (res) {
      return sharedRequest.mapGetResponse(res);
    }, function (err) {
      // 304 surfaces as a "non-2xx error" via httpClient; propagate it
      // as a structured 304 result instead so operator routes get
      // the conditional-GET short-circuit they expect.
      if (err && err.statusCode === requestHelpers.HTTP_STATUS.NOT_MODIFIED) {
        return sharedRequest.notModifiedGetResult();
      }
      throw err;
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
      // A missing key surfaces as the framework NOT_FOUND code — the same
      // contract local.js head() exposes and that deleteKey already maps 404
      // to — so existence probes via head() (e.g. the backup objectStore
      // adapter's hasKey / statKey) get the uniform missing-key signal instead
      // of a raw HTTP 404 they don't recognize.
      if (e && e.statusCode === 404) {
        throw _err("NOT_FOUND", "key not found: " + key, true);
      }
      throw e;
    });
  }

  // deleteKey(key, opts?) — opts.versionId targets a specific version;
  // opts.bypassGovernanceRetention signs x-amz-bypass-governance-retention so
  // a GOVERNANCE-mode retention can be lifted by a caller with the permission
  // (COMPLIANCE mode is immutable to everyone and stays refused).
  //
  // WORM-awareness: an UNVERSIONED delete on a versioning-enabled bucket only
  // writes a delete-marker — the data version survives and the call still
  // resolves true. To actually erase a version (e.g. crypto-shred / GDPR Art.
  // 17 on an Object-Lock bucket) pass the versionId from put()/listVersions().
  // A delete refused by an active retention surfaces as a thrown error (S3 403
  // / MinIO 400), never a silent success, so the caller learns the version is
  // still protected.
  function deleteKey(key, opts) {
    opts = opts || {};
    var url = _keyToUrl(key);
    if (opts.versionId) url.searchParams.set("versionId", opts.versionId);
    var extra = {};
    if (opts.bypassGovernanceRetention) extra["x-amz-bypass-governance-retention"] = "true";
    var headers = _makeSigned("DELETE", url, sha256Hex(Buffer.alloc(0)), extra);
    return _request("DELETE", url, headers, null, reqOpts).then(
      function () { return true; },
      function (e) { if (e.statusCode === 404) return false; throw e; }
    );
  }

  // S3 response-* override query parameters per AWS S3 GetObject docs:
  // when present on a presigned GET, the named response headers are
  // overridden by these values. The signing math is identical — the
  // params just need to be in url.searchParams before canonicalRequest
  // runs (canonicalQueryString sorts + URL-encodes them deterministically).
  // Map operator-friendly camelCase to the wire-format query keys.
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

    // Validate opts.responseHeaders shape — operators pass camelCase
    // keys; refuse unknown keys at config-time so a typo surfaces at
    // boot. Reject CR/LF/NUL in any value as defense in depth (the
    // values flow into URL query params + the signed canonical request,
    // and a CR/LF could smuggle into a downstream proxy log).
    var responseHeaders = opts.responseHeaders;
    if (responseHeaders !== undefined && responseHeaders !== null) {
      if (typeof responseHeaders !== "object") {
        throw _err("INVALID_RESPONSE_HEADERS",
          "presigned URL: responseHeaders must be an object", true);
      }
      var rhKeys = Object.keys(responseHeaders);
      for (var rhi = 0; rhi < rhKeys.length; rhi += 1) {
        var rhk = rhKeys[rhi];
        if (!Object.prototype.hasOwnProperty.call(RESPONSE_HEADER_QUERY_KEYS, rhk)) {
          throw _err("INVALID_RESPONSE_HEADERS",
            "presigned URL: responseHeaders.'" + rhk + "' is not recognised " +
            "(allowed: " + Object.keys(RESPONSE_HEADER_QUERY_KEYS).join(", ") + ")", true);
        }
        var rhv = responseHeaders[rhk];
        if (typeof rhv !== "string" || rhv.length === 0) {
          throw _err("INVALID_RESPONSE_HEADERS",
            "presigned URL: responseHeaders.'" + rhk + "' must be a non-empty string", true);
        }
        if (/[\r\n\0]/.test(rhv)) {
          throw _err("INVALID_RESPONSE_HEADERS",
            "presigned URL: responseHeaders.'" + rhk + "' contains CR/LF/NUL — refused as a header-injection vector", true);
        }
      }
    }

    var url = _keyToUrl(opts.key);
    var date = opts.date || new Date();
    var amzDate = _formatAmzDate(date);
    var dateStamp = _formatDateStamp(date);
    var credentialScope = dateStamp + "/" + config.region + "/" + SERVICE + "/aws4_request";

    // Build the headers we want to sign. host is always signed; if the
    // caller supplies opts.contentType the value is bound into the
    // signature so the client MUST send Content-Type matching exactly,
    // otherwise S3 rejects with SignatureDoesNotMatch — turning the
    // hint into real server-side enforcement.
    var headers = { host: url.host };
    if (opts.contentType) headers["content-type"] = opts.contentType;
    // SigV4 SignedHeaders: lowercase, semicolon-joined, AWS-spec order.
    var signedHeaderKeys = [];
    for (var hk in headers) signedHeaderKeys.push(hk);
    signedHeaderKeys.sort();
    var signedHeadersStr = signedHeaderKeys.join(";");

    // Query-string SigV4: presigning carries auth in the URL itself.
    // The set order doesn't matter — canonicalQueryString sorts the
    // params before hashing.
    url.searchParams.set("X-Amz-Algorithm", ALGORITHM);
    url.searchParams.set("X-Amz-Credential", config.accessKeyId + "/" + credentialScope);
    url.searchParams.set("X-Amz-Date", amzDate);
    url.searchParams.set("X-Amz-Expires", String(expiresIn));
    url.searchParams.set("X-Amz-SignedHeaders", signedHeadersStr);
    if (config.sessionToken) {
      url.searchParams.set("X-Amz-Security-Token", config.sessionToken);
    }
    // Response-header overrides — set BEFORE canonicalRequest so they
    // become part of the signed query string.
    if (responseHeaders) {
      for (var rhk2 = 0; rhk2 < rhKeys.length; rhk2 += 1) {
        var camel = rhKeys[rhk2];
        url.searchParams.set(RESPONSE_HEADER_QUERY_KEYS[camel], responseHeaders[camel]);
      }
    }

    // Payload hash for query-string presigning is the literal string
    // "UNSIGNED-PAYLOAD" — the body is not part of the signature.
    var canon = canonicalRequest(method, url, headers, "UNSIGNED-PAYLOAD");
    var sts = stringToSign(amzDate, credentialScope, canon);
    var signingKey = deriveSigningKey(config.secretAccessKey, dateStamp, config.region, SERVICE);
    var signature = nodeCrypto.createHmac("sha256", signingKey).update(sts).digest("hex");

    url.searchParams.set("X-Amz-Signature", signature);

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

  // POST-form policy presigning (S3-compatible). Unlike query-string
  // PUT presigning, this lets the operator enforce body-size at the
  // upload endpoint via the `content-length-range` policy condition.
  // Clients upload via multipart/form-data POST to the returned URL,
  // attaching every key in `fields` plus the file as the last field.
  //
  // Reference: AWS S3 "Browser-Based Uploads Using POST".
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

    // Policy conditions. Each entry must MATCH a corresponding form
    // field exactly OR be a structural constraint (content-length-range
    // / starts-with). Order doesn't matter — S3 evaluates the set.
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

    // The bucket-root URL — no key in the path, key is a form field.
    var url = _bucketUrl();

    return {
      url:           url.toString(),
      method:        "POST",
      fields:        fields,
      expiresAt:     date.getTime() + C.TIME.seconds(expiresIn),
      maxBytes:      opts.maxBytes,
      enforcement:   "content-length-range",  // S3-side enforced
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

  // listVersions(prefix, opts?) — enumerate every object VERSION and
  // delete-marker under prefix (S3 ListObjectVersions / the ?versions
  // subresource). Plain list() only sees current versions; to erase prior
  // versions on a versioning / Object-Lock bucket you first need their
  // versionIds, which only this call surfaces. Each item carries
  // { key, versionId, isLatest, deleteMarker, size, lastModified, etag };
  // deleteMarker:true rows are tombstones (no data, size null). Pagination
  // walks (keyMarker, versionIdMarker) the way list() walks continuationToken.
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
  signRequest:          signRequest,
  canonicalRequest:     canonicalRequest,
  stringToSign:         stringToSign,
  deriveSigningKey:     deriveSigningKey,
  canonicalQueryString: canonicalQueryString,
  canonicalHeaders:     canonicalHeaders,
  awsUriEncode:         awsUriEncode,
  sha256Hex:            sha256Hex,
  formatAmzDate:        _formatAmzDate,
  formatDateStamp:      _formatDateStamp,
  SERVICE:              SERVICE,
  ALGORITHM:            ALGORITHM,
};

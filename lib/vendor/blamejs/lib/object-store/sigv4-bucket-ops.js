// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var nodeCrypto = require("node:crypto");
var safeBuffer = require("../safe-buffer");
var C = require("../constants");
var requestHelpers = require("../request-helpers");
var sigv4 = require("./sigv4");
var sharedRequest = require("./http-request");
var safeXml = require("../parsers/safe-xml");
var safeUrl = require("../safe-url");
var template = require("../template");
var validateOpts = require("../validate-opts");
var { ObjectStoreError } = require("../framework-error");

var _err = ObjectStoreError.factory;

function _internalUrl(input, allowedProtocols) {
  return safeUrl.parse(input, {
    allowedProtocols: allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       ObjectStoreError,
    maxUrlLength:     C.BYTES.kib(32),
  });
}

var BUCKET_NAME_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

function _validateBucketName(name) {
  if (typeof name !== "string" || name.length < 3 || name.length > 63) {
    throw _err("objectstore/bucket-invalid-name",
      "bucket name must be a string of length 3..63, got " +
      (typeof name === "string" ? "length " + name.length : typeof name), true);
  }
  if (name.length > 63 || !BUCKET_NAME_RE.test(name)) {
    throw _err("objectstore/bucket-invalid-name",
      "bucket name '" + name + "' violates S3 naming rules " +
      "(lowercase, digits, hyphens, dots — no leading/trailing punct)", true);
  }
  if (name.indexOf("..") !== -1) {
    throw _err("objectstore/bucket-invalid-name",
      "bucket name '" + name + "' contains consecutive dots", true);
  }
}

var _xmlEscape = template.escapeHtml;

function _md5Base64(buf) {
  return nodeCrypto.createHash("md5").update(buf).digest("base64");
}

var ALLOWED_STORAGE_CLASSES = [
  "STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA",
  "INTELLIGENT_TIERING", "GLACIER", "DEEP_ARCHIVE", "GLACIER_IR",
  "EXPRESS_ONEZONE",
];

function _buildLifecycleXml(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw _err("objectstore/invalid-lifecycle",
      "setLifecycle: rules must be a non-empty array", true);
  }
  var MAX_LIFECYCLE_RULES = 1000;
  if (rules.length > MAX_LIFECYCLE_RULES) {
    throw _err("objectstore/invalid-lifecycle",
      "setLifecycle: maximum " + MAX_LIFECYCLE_RULES + " rules per bucket (S3 spec)", true);
  }
  var body = '<?xml version="1.0" encoding="UTF-8"?>';
  body += '<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">';
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i];
    if (!rule || typeof rule !== "object") {
      throw _err("objectstore/invalid-lifecycle",
        "rules[" + i + "] must be an object", true);
    }
    var status = rule.status || "Enabled";
    if (status !== "Enabled" && status !== "Disabled") {
      throw _err("objectstore/invalid-lifecycle",
        "rules[" + i + "].status must be 'Enabled' or 'Disabled'", true);
    }
    if (!rule.expiration && !rule.transition && !rule.abortIncompleteMultipartUpload) {
      throw _err("objectstore/invalid-lifecycle",
        "rules[" + i + "] must specify at least one of " +
        "expiration / transition / abortIncompleteMultipartUpload", true);
    }
    body += "<Rule>";
    if (rule.id !== undefined) {
      if (typeof rule.id !== "string" || rule.id.length === 0) {
        throw _err("objectstore/invalid-lifecycle",
          "rules[" + i + "].id must be a non-empty string when set", true);
      }
      body += "<ID>" + _xmlEscape(rule.id) + "</ID>";
    }
    body += "<Filter><Prefix>" + _xmlEscape(rule.prefix || "") + "</Prefix></Filter>";
    body += "<Status>" + status + "</Status>";
    if (rule.expiration) {
      body += "<Expiration>";
      if (rule.expiration.days !== undefined) {
        if (typeof rule.expiration.days !== "number" || rule.expiration.days < 1) {
          throw _err("objectstore/invalid-lifecycle",
            "rules[" + i + "].expiration.days must be a positive integer", true);
        }
        body += "<Days>" + rule.expiration.days + "</Days>";
      }
      if (rule.expiration.date !== undefined) {
        body += "<Date>" + _xmlEscape(rule.expiration.date) + "</Date>";
      }
      if (rule.expiration.expiredObjectDeleteMarker !== undefined) {
        body += "<ExpiredObjectDeleteMarker>" +
          (rule.expiration.expiredObjectDeleteMarker ? "true" : "false") +
          "</ExpiredObjectDeleteMarker>";
      }
      body += "</Expiration>";
    }
    if (rule.transition) {
      if (ALLOWED_STORAGE_CLASSES.indexOf(rule.transition.storageClass) === -1) {
        throw _err("objectstore/invalid-lifecycle",
          "rules[" + i + "].transition.storageClass must be one of: " +
          ALLOWED_STORAGE_CLASSES.join(", "), true);
      }
      body += "<Transition>";
      if (rule.transition.days !== undefined) {
        body += "<Days>" + rule.transition.days + "</Days>";
      }
      if (rule.transition.date !== undefined) {
        body += "<Date>" + _xmlEscape(rule.transition.date) + "</Date>";
      }
      body += "<StorageClass>" + rule.transition.storageClass + "</StorageClass>";
      body += "</Transition>";
    }
    if (rule.abortIncompleteMultipartUpload) {
      var dai = rule.abortIncompleteMultipartUpload.daysAfterInitiation;
      if (typeof dai !== "number" || dai < 1) {
        throw _err("objectstore/invalid-lifecycle",
          "rules[" + i + "].abortIncompleteMultipartUpload.daysAfterInitiation " +
          "must be a positive integer", true);
      }
      body += "<AbortIncompleteMultipartUpload>";
      body += "<DaysAfterInitiation>" + dai + "</DaysAfterInitiation>";
      body += "</AbortIncompleteMultipartUpload>";
    }
    body += "</Rule>";
  }
  body += "</LifecycleConfiguration>";
  return body;
}

var ALLOWED_CORS_METHODS = ["GET", "PUT", "POST", "DELETE", "HEAD"];

function _buildCorsXml(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw _err("objectstore/invalid-cors-rule",
      "setCorsRules: rules must be a non-empty array", true);
  }
  if (rules.length > 100) {
    throw _err("objectstore/invalid-cors-rule",
      "setCorsRules: maximum 100 rules per bucket (S3 spec)", true);
  }
  var body = '<?xml version="1.0" encoding="UTF-8"?>';
  body += '<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">';
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i];
    if (!rule || typeof rule !== "object") {
      throw _err("objectstore/invalid-cors-rule",
        "rules[" + i + "] must be an object", true);
    }
    if (!Array.isArray(rule.allowedOrigins) || rule.allowedOrigins.length === 0) {
      throw _err("objectstore/invalid-cors-rule",
        "rules[" + i + "].allowedOrigins must be a non-empty array", true);
    }
    if (!Array.isArray(rule.allowedMethods) || rule.allowedMethods.length === 0) {
      throw _err("objectstore/invalid-cors-rule",
        "rules[" + i + "].allowedMethods must be a non-empty array", true);
    }
    for (var m = 0; m < rule.allowedMethods.length; m++) {
      if (ALLOWED_CORS_METHODS.indexOf(rule.allowedMethods[m]) === -1) {
        throw _err("objectstore/invalid-cors-rule",
          "rules[" + i + "].allowedMethods[" + m + "] must be one of: " +
          ALLOWED_CORS_METHODS.join(", "), true);
      }
    }
    body += "<CORSRule>";
    if (rule.id !== undefined) body += "<ID>" + _xmlEscape(rule.id) + "</ID>";
    rule.allowedOrigins.forEach(function (o) {
      body += "<AllowedOrigin>" + _xmlEscape(o) + "</AllowedOrigin>";
    });
    rule.allowedMethods.forEach(function (m) {
      body += "<AllowedMethod>" + _xmlEscape(m) + "</AllowedMethod>";
    });
    if (Array.isArray(rule.allowedHeaders)) {
      rule.allowedHeaders.forEach(function (h) {
        body += "<AllowedHeader>" + _xmlEscape(h) + "</AllowedHeader>";
      });
    }
    if (Array.isArray(rule.exposeHeaders)) {
      rule.exposeHeaders.forEach(function (h) {
        body += "<ExposeHeader>" + _xmlEscape(h) + "</ExposeHeader>";
      });
    }
    if (rule.maxAgeSeconds !== undefined) {
      if (typeof rule.maxAgeSeconds !== "number" || rule.maxAgeSeconds < 0) {
        throw _err("objectstore/invalid-cors-rule",
          "rules[" + i + "].maxAgeSeconds must be a non-negative number", true);
      }
      body += "<MaxAgeSeconds>" + rule.maxAgeSeconds + "</MaxAgeSeconds>";
    }
    body += "</CORSRule>";
  }
  body += "</CORSConfiguration>";
  if (Buffer.byteLength(body, "utf8") > C.BYTES.kib(64)) {
    throw _err("objectstore/invalid-cors-rule",
      "CORS configuration exceeds 64 KB (S3 spec)", true);
  }
  return body;
}

var OBJECT_LOCK_MODES = ["GOVERNANCE", "COMPLIANCE"];
var LEGAL_HOLD_STATES = ["ON", "OFF"];

function _validateObjectLockConfig(cfg) {
  if (!cfg || typeof cfg !== "object") {
    throw _err("objectstore/invalid-object-lock",
      "setObjectLockConfiguration: opts must be an object " +
      "with { mode, days|years }", true);
  }
  if (OBJECT_LOCK_MODES.indexOf(cfg.mode) === -1) {
    throw _err("objectstore/invalid-object-lock",
      "mode must be one of " + OBJECT_LOCK_MODES.join(", ") +
      "; got " + JSON.stringify(cfg.mode), true);
  }
  var hasDays  = cfg.days  != null;
  var hasYears = cfg.years != null;
  if (hasDays && hasYears) {
    throw _err("objectstore/invalid-object-lock",
      "specify either days OR years, not both (S3 rule)", true);
  }
  if (!hasDays && !hasYears) {
    throw _err("objectstore/invalid-object-lock",
      "default retention requires days or years", true);
  }
  if (hasDays) {
    if (typeof cfg.days !== "number" || !Number.isInteger(cfg.days) ||
        cfg.days <= 0) {
      throw _err("objectstore/invalid-object-lock",
        "days must be a positive integer; got " + JSON.stringify(cfg.days), true);
    }
  } else {
    if (typeof cfg.years !== "number" || !Number.isInteger(cfg.years) ||
        cfg.years <= 0) {
      throw _err("objectstore/invalid-object-lock",
        "years must be a positive integer; got " + JSON.stringify(cfg.years), true);
    }
  }
}

function _buildObjectLockConfigXml(cfg) {
  var body = '<?xml version="1.0" encoding="UTF-8"?>';
  body += '<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">';
  body += '<ObjectLockEnabled>Enabled</ObjectLockEnabled>';
  body += '<Rule><DefaultRetention>';
  body += '<Mode>' + cfg.mode + '</Mode>';
  if (cfg.days != null)  body += '<Days>'  + cfg.days  + '</Days>';
  if (cfg.years != null) body += '<Years>' + cfg.years + '</Years>';
  body += '</DefaultRetention></Rule>';
  body += '</ObjectLockConfiguration>';
  return body;
}

function _validateRetention(opts) {
  if (!opts || typeof opts !== "object") {
    throw _err("objectstore/invalid-retention",
      "setObjectRetention: opts must be an object " +
      "with { mode, retainUntil }", true);
  }
  if (OBJECT_LOCK_MODES.indexOf(opts.mode) === -1) {
    throw _err("objectstore/invalid-retention",
      "mode must be one of " + OBJECT_LOCK_MODES.join(", ") +
      "; got " + JSON.stringify(opts.mode), true);
  }
  if (!(opts.retainUntil instanceof Date) || isNaN(opts.retainUntil.getTime())) {
    throw _err("objectstore/invalid-retention",
      "retainUntil must be a valid Date instance", true);
  }
  if (opts.retainUntil.getTime() <= Date.now()) {
    throw _err("objectstore/invalid-retention",
      "retainUntil must be in the future", true);
  }
}

function _buildRetentionXml(opts) {
  return '<?xml version="1.0" encoding="UTF-8"?>' +
         '<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
         '<Mode>' + opts.mode + '</Mode>' +
         '<RetainUntilDate>' + opts.retainUntil.toISOString() + '</RetainUntilDate>' +
         '</Retention>';
}

function _validateLegalHoldStatus(status) {
  if (LEGAL_HOLD_STATES.indexOf(status) === -1) {
    throw _err("objectstore/invalid-legal-hold",
      "legal-hold status must be one of " + LEGAL_HOLD_STATES.join(", ") +
      "; got " + JSON.stringify(status), true);
  }
}

function _buildLegalHoldXml(status) {
  return '<?xml version="1.0" encoding="UTF-8"?>' +
         '<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
         '<Status>' + status + '</Status>' +
         '</LegalHold>';
}

function _isLockNotConfigured(err) {
  if (!err) return false;
  if (err.statusCode !== C.HTTP.STATUS.NOT_FOUND && err.statusCode !== C.HTTP.STATUS.BAD_REQUEST) return false;
  var msg = String(err.message || "");
  return msg.indexOf("ObjectLockConfigurationNotFoundError") !== -1 ||
         msg.indexOf("NoSuchObjectLockConfiguration") !== -1;
}

function _validateObjectKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("objectstore/invalid-key", "object key must be a non-empty string", true);
  }
  if (safeBuffer.byteLengthOf(key) > C.BYTES.kib(1)) {
    throw _err("objectstore/invalid-key", "object key exceeds 1024 bytes (S3 limit)", true);
  }
}

function create(config) {
  if (!config || typeof config !== "object") {
    throw _err("objectstore/invalid-config", "bucketOps.create requires a config object", true);
  }
  validateOpts(config, [
    "protocol", "region", "accessKeyId", "secretAccessKey", "sessionToken",
    "endpoint", "pathStyle", "forcePathStyle",
    "allowedProtocols", "allowInternal", "timeoutMs",
    "audit", "observability", "auditSuccess", "auditFailures",
  ], "bucketOps");
  if (config.protocol && config.protocol !== "sigv4") {
    throw _err("objectstore/invalid-config",
      "bucketOps currently only supports protocol 'sigv4'; got '" +
      config.protocol + "'. GCS and Azure bucket lifecycle differs " +
      "substantially per cloud and is operator-managed (Terraform / " +
      "CDK / Pulumi).", true);
  }
  if (!config.region) throw _err("objectstore/invalid-config", "bucketOps: region is required", true);
  if (!config.accessKeyId) throw _err("objectstore/invalid-config", "bucketOps: accessKeyId is required", true);
  if (!config.secretAccessKey) throw _err("objectstore/invalid-config", "bucketOps: secretAccessKey is required", true);

  var endpoint = config.endpoint || ("https://s3." + config.region + ".amazonaws.com");
  if (endpoint.endsWith("/")) endpoint = endpoint.slice(0, -1);
  var pathStyle = !!(config.pathStyle || config.forcePathStyle);
  var allowedProtocols = config.allowedProtocols || safeUrl.ALLOW_HTTP_TLS;
  var allowInternal    = config.allowInternal != null ? config.allowInternal : null;
  safeUrl.parse(endpoint, {
    allowedProtocols: allowedProtocols,
    errorClass:       ObjectStoreError,
  });
  var reqOpts = { timeoutMs: config.timeoutMs, allowedProtocols: allowedProtocols };
  if (allowInternal !== null) reqOpts.allowInternal = allowInternal;

  var audit         = config.audit         || null;
  var observability = config.observability || null;
  var auditSuccess  = config.auditSuccess  !== false;
  var auditFailures = config.auditFailures !== false;

  var _emit = validateOpts.makeAuditEmitter(audit);

  function _emitEvent(name, value, labels) {
    if (observability) observability.safeEvent(name, value, labels || {});
  }

  function _actor(callerOpts) {
    var seed = (callerOpts && callerOpts.actor && typeof callerOpts.actor === "object")
      ? callerOpts.actor
      : null;
    return requestHelpers.resolveActorWithOverride(callerOpts || {}, seed);
  }

  function _appendQuery(base, query) {
    if (!query) return base;
    var keys = Object.keys(query);
    if (keys.length === 0) return base;
    var parts = keys.map(function (k) {
      var v = query[k];
      if (v === "" || v == null) return encodeURIComponent(k);
      return encodeURIComponent(k) + "=" + encodeURIComponent(v);
    });
    return base + "?" + parts.join("&");
  }

  function _bucketUrl(name, query) {
    var ub = _internalUrl(endpoint, allowedProtocols);
    if (pathStyle) {
      ub.pathname = "/" + name + "/";
    } else {
      sigv4.applyVirtualHostedBucket(ub, name);
      ub.pathname = "/";
    }
    var base = ub.toString();
    return _internalUrl(_appendQuery(base, query), allowedProtocols);
  }

  function _objectUrl(name, key, query) {
    var encKey = key.split("/").map(function (s) { return sigv4.awsUriEncode(s, true); }).join("/");
    var uo = _internalUrl(endpoint, allowedProtocols);
    if (pathStyle) {
      uo.pathname = "/" + name + "/" + encKey;
    } else {
      sigv4.applyVirtualHostedBucket(uo, name);
      uo.pathname = "/" + encKey;
    }
    var base = uo.toString();
    return _internalUrl(_appendQuery(base, query), allowedProtocols);
  }

  function _serviceUrl(query) {
    var u = _internalUrl(endpoint, allowedProtocols);
    u.pathname = "/";
    if (query) {
      Object.keys(query).forEach(function (k) { u.searchParams.set(k, query[k]); });
    }
    return u;
  }

  function _signed(method, url, payloadHash, extraHeaders) {
    var signed = sigv4.signRequest({
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

  function _request(method, url, headers, body) {
    return sharedRequest(method, url, headers, body, reqOpts);
  }

  function createBucket(name, opts) {
    _validateBucketName(name);
    opts = opts || {};
    validateOpts(opts, ["region", "objectLockEnabled", "req", "actor"],
      "bucketOps.create");
    var targetRegion = opts.region || config.region;
    var url = _bucketUrl(name);
    var bodyBuf;
    var extra = {};
    if (targetRegion && targetRegion !== "us-east-1") {
      bodyBuf = Buffer.from(
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' +
        '<LocationConstraint>' + _xmlEscape(targetRegion) + '</LocationConstraint>' +
        '</CreateBucketConfiguration>',
        "utf8"
      );
      extra["Content-Type"] = "application/xml";
      extra["Content-Length"] = String(bodyBuf.length);
    } else {
      bodyBuf = Buffer.alloc(0);
      extra["Content-Length"] = "0";
    }
    if (opts.objectLockEnabled === true) {
      extra["x-amz-bucket-object-lock-enabled"] = "true";
    }
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, extra);
    return _request("PUT", url, headers, bodyBuf).then(
      function () {
        if (auditSuccess) {
          _emit("objectstore.bucket.create", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            metadata: {
              region:            targetRegion,
              objectLockEnabled: opts.objectLockEnabled === true,
            },
          });
        }
        _emitEvent("objectstore.bucket.create", 1,
          { outcome: "success", region: targetRegion });
        return { created: true, name: name, region: targetRegion };
      },
      function (e) {
        var mapped = e;
        if (e.statusCode === C.HTTP.STATUS.CONFLICT && /BucketAlreadyOwnedByYou/.test(e.message || "")) {
          mapped = _err("objectstore/bucket-already-owned",
            "bucket '" + name + "' already exists and is owned by this account", true);
        } else if (e.statusCode === C.HTTP.STATUS.CONFLICT) {
          mapped = _err("objectstore/bucket-name-taken",
            "bucket name '" + name + "' is taken in S3's global namespace", true);
        }
        if (auditFailures) {
          _emit("objectstore.bucket.create", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            outcome:  "failure",
            reason:   mapped.code || "error",
            metadata: { region: targetRegion },
          });
        }
        _emitEvent("objectstore.bucket.create", 1,
          { outcome: "failure", reason: mapped.code || "error" });
        throw mapped;
      }
    );
  }

  function deleteBucket(name, opts) {
    _validateBucketName(name);
    opts = opts || {};
    validateOpts(opts, ["req", "actor"], "bucketOps.delete");
    var url = _bucketUrl(name);
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("DELETE", url, payloadHash);
    return _request("DELETE", url, headers, null).then(
      function () {
        if (auditSuccess) {
          _emit("objectstore.bucket.delete", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            metadata: { existed: true },
          });
        }
        _emitEvent("objectstore.bucket.delete", 1,
          { outcome: "success", existed: "true" });
        return true;
      },
      function (e) {
        if (e.statusCode === C.HTTP.STATUS.NOT_FOUND) {
          if (auditSuccess) {
            _emit("objectstore.bucket.delete", {
              actor:    _actor(opts),
              resource: { kind: "bucket", id: name },
              metadata: { existed: false },
            });
          }
          _emitEvent("objectstore.bucket.delete", 1,
            { outcome: "success", existed: "false" });
          return false;
        }
        var mapped = e;
        if (e.statusCode === C.HTTP.STATUS.CONFLICT && /BucketNotEmpty/.test(e.message || "")) {
          mapped = _err("objectstore/bucket-not-empty",
            "bucket '" + name + "' is not empty; delete all objects + " +
            "noncurrent versions + delete-markers first", true);
        }
        if (auditFailures) {
          _emit("objectstore.bucket.delete", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            outcome:  "failure",
            reason:   mapped.code || "error",
          });
        }
        _emitEvent("objectstore.bucket.delete", 1,
          { outcome: "failure", reason: mapped.code || "error" });
        throw mapped;
      }
    );
  }

  function listBuckets() {
    var url = _serviceUrl();
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("GET", url, payloadHash);
    return _request("GET", url, headers, null).then(function (res) {
      var doc = safeXml.parse(res.body);
      var result = doc.ListAllMyBucketsResult || {};
      var bucketsContainer = result.Buckets || {};
      var raw = bucketsContainer.Bucket;
      var arr;
      if (!raw) arr = [];
      else if (Array.isArray(raw)) arr = raw;
      else arr = [raw];
      _emitEvent("objectstore.bucket.list", arr.length, { outcome: "success" });
      return arr.map(function (b) {
        return {
          name:         b.Name,
          creationDate: b.CreationDate ? Date.parse(b.CreationDate) : null,
          region:       b.BucketRegion || null,
        };
      });
    });
  }

  function setLifecycle(name, rules, opts) {
    _validateBucketName(name);
    opts = opts || {};
    validateOpts(opts, ["req", "actor"], "bucketOps.setLifecycle");
    var bodyXml = _buildLifecycleXml(rules);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _bucketUrl(name, { lifecycle: "" });
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    });
    return _request("PUT", url, headers, bodyBuf).then(
      function () {
        if (auditSuccess) {
          _emit("objectstore.bucket.setLifecycle", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            metadata: { ruleCount: rules.length },
          });
        }
        _emitEvent("objectstore.bucket.setLifecycle", 1,
          { outcome: "success", ruleCount: String(rules.length) });
        return { applied: true, name: name, ruleCount: rules.length };
      },
      function (e) {
        if (auditFailures) {
          _emit("objectstore.bucket.setLifecycle", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            outcome:  "failure",
            reason:   e.code || "error",
          });
        }
        _emitEvent("objectstore.bucket.setLifecycle", 1,
          { outcome: "failure", reason: e.code || "error" });
        throw e;
      }
    );
  }

  function setCorsRules(name, rules, opts) {
    _validateBucketName(name);
    opts = opts || {};
    validateOpts(opts, ["req", "actor"], "bucketOps.setCorsRules");
    var bodyXml = _buildCorsXml(rules);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _bucketUrl(name, { cors: "" });
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    });
    return _request("PUT", url, headers, bodyBuf).then(
      function () {
        if (auditSuccess) {
          _emit("objectstore.bucket.setCorsRules", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            metadata: { ruleCount: rules.length },
          });
        }
        _emitEvent("objectstore.bucket.setCorsRules", 1,
          { outcome: "success", ruleCount: String(rules.length) });
        return { applied: true, name: name, ruleCount: rules.length };
      },
      function (e) {
        if (auditFailures) {
          _emit("objectstore.bucket.setCorsRules", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            outcome:  "failure",
            reason:   e.code || "error",
          });
        }
        _emitEvent("objectstore.bucket.setCorsRules", 1,
          { outcome: "failure", reason: e.code || "error" });
        throw e;
      }
    );
  }

  function setObjectLockConfiguration(name, opts) {
    _validateBucketName(name);
    _validateObjectLockConfig(opts);
    validateOpts(opts, ["mode", "days", "years", "req", "actor"],
      "bucketOps.setObjectLockConfiguration");
    var bodyXml = _buildObjectLockConfigXml(opts);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _bucketUrl(name, { "object-lock": "" });
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    });
    return _request("PUT", url, headers, bodyBuf).then(
      function () {
        if (auditSuccess) {
          _emit("objectstore.bucket.setObjectLockConfiguration", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            metadata: {
              mode:  opts.mode,
              days:  opts.days  != null ? opts.days  : null,
              years: opts.years != null ? opts.years : null,
            },
          });
        }
        _emitEvent("objectstore.bucket.setObjectLockConfiguration", 1,
          { outcome: "success", mode: opts.mode });
        return {
          applied: true, name: name,
          mode:    opts.mode,
          days:    opts.days  != null ? opts.days  : null,
          years:   opts.years != null ? opts.years : null,
        };
      },
      function (e) {
        if (auditFailures) {
          _emit("objectstore.bucket.setObjectLockConfiguration", {
            actor:    _actor(opts),
            resource: { kind: "bucket", id: name },
            outcome:  "failure",
            reason:   e.code || "error",
            metadata: { mode: opts.mode },
          });
        }
        _emitEvent("objectstore.bucket.setObjectLockConfiguration", 1,
          { outcome: "failure", reason: e.code || "error" });
        throw e;
      }
    );
  }

  function getObjectLockConfiguration(name) {
    _validateBucketName(name);
    _emitEvent("objectstore.bucket.getObjectLockConfiguration", 1,
      { outcome: "success" });
    var url = _bucketUrl(name, { "object-lock": "" });
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("GET", url, payloadHash);
    return _request("GET", url, headers, null).then(
      function (res) {
        var doc = safeXml.parse(res.body);
        var olc = doc.ObjectLockConfiguration || {};
        var enabled = olc.ObjectLockEnabled === "Enabled";
        var rule = olc.Rule || {};
        var def  = rule.DefaultRetention || {};
        return {
          enabled: enabled,
          mode:    def.Mode || null,
          days:    def.Days  != null ? Number(def.Days)  : null,
          years:   def.Years != null ? Number(def.Years) : null,
        };
      },
      function (e) {
        if (_isLockNotConfigured(e)) {
          return { enabled: false, mode: null, days: null, years: null };
        }
        throw e;
      }
    );
  }

  function setObjectRetention(name, key, opts) {
    _validateBucketName(name);
    _validateObjectKey(key);
    _validateRetention(opts);
    validateOpts(opts, ["mode", "retainUntil", "bypassGovernance", "req", "actor"],
      "bucketOps.setObjectRetention");
    return getObjectRetention(name, key).then(function (existing) {
      if (existing && existing.mode === "COMPLIANCE") {
        if (opts.bypassGovernance === true) {
          throw new ObjectStoreError("objectstore/compliance-bypass-refused",
            "setObjectRetention: bypassGovernance refused — existing retention mode is COMPLIANCE (cannot be bypassed by anyone, including root)", true);
        }
        if (opts.retainUntil && existing.retainUntil &&
            opts.retainUntil.getTime() < existing.retainUntil.getTime()) {
          throw new ObjectStoreError("objectstore/compliance-shortening-refused",
            "setObjectRetention: cannot shorten COMPLIANCE retention (existing=" +
            existing.retainUntil.toISOString() + ", proposed=" +
            opts.retainUntil.toISOString() + ")", true);
        }
      }
      return _doSetRetention(name, key, opts);
    }, function (e) {
      if (e && typeof e.code === "string" &&
          e.code.indexOf("objectstore/compliance-") === 0) {
        throw e;
      }
      return _doSetRetention(name, key, opts);
    });
  }

  function _doSetRetention(name, key, opts) {
    var bodyXml = _buildRetentionXml(opts);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _objectUrl(name, key, { retention: "" });
    var extra = {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    };
    if (opts.bypassGovernance === true) {
      extra["x-amz-bypass-governance-retention"] = "true";
    }
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, extra);
    return _request("PUT", url, headers, bodyBuf).then(
      function () {
        if (auditSuccess) {
          _emit("objectstore.object.setRetention", {
            actor:    _actor(opts),
            resource: { kind: "object", id: name + "/" + key },
            metadata: {
              bucket:           name,
              key:              key,
              mode:             opts.mode,
              retainUntilIso:   opts.retainUntil.toISOString(),
              bypassGovernance: opts.bypassGovernance === true,
            },
          });
        }
        _emitEvent("objectstore.object.setRetention", 1,
          { outcome: "success", mode: opts.mode,
            bypassGovernance: opts.bypassGovernance === true ? "true" : "false" });
        return {
          applied:     true,
          name:        name,
          key:         key,
          mode:        opts.mode,
          retainUntil: opts.retainUntil,
        };
      },
      function (e) {
        if (auditFailures) {
          _emit("objectstore.object.setRetention", {
            actor:    _actor(opts),
            resource: { kind: "object", id: name + "/" + key },
            outcome:  "failure",
            reason:   e.code || "error",
            metadata: {
              bucket:           name,
              key:              key,
              mode:             opts.mode,
              bypassGovernance: opts.bypassGovernance === true,
            },
          });
        }
        _emitEvent("objectstore.object.setRetention", 1,
          { outcome: "failure", reason: e.code || "error" });
        throw e;
      }
    );
  }

  function getObjectRetention(name, key) {
    _validateBucketName(name);
    _validateObjectKey(key);
    _emitEvent("objectstore.object.getRetention", 1, { outcome: "success" });
    var url = _objectUrl(name, key, { retention: "" });
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("GET", url, payloadHash);
    return _request("GET", url, headers, null).then(
      function (res) {
        var doc = safeXml.parse(res.body);
        var ret = doc.Retention || {};
        var until = ret.RetainUntilDate ? new Date(ret.RetainUntilDate) : null;
        return {
          mode:        ret.Mode || null,
          retainUntil: until,
        };
      },
      function (e) {
        if (_isLockNotConfigured(e)) {
          return { mode: null, retainUntil: null };
        }
        throw e;
      }
    );
  }

  function setObjectLegalHold(name, key, status, opts) {
    _validateBucketName(name);
    _validateObjectKey(key);
    _validateLegalHoldStatus(status);
    opts = opts || {};
    validateOpts(opts, ["req", "actor"], "bucketOps.setObjectLegalHold");
    var bodyXml = _buildLegalHoldXml(status);
    var bodyBuf = Buffer.from(bodyXml, "utf8");
    var url = _objectUrl(name, key, { "legal-hold": "" });
    var payloadHash = sigv4.sha256Hex(bodyBuf);
    var headers = _signed("PUT", url, payloadHash, {
      "Content-Type":   "application/xml",
      "Content-Length": String(bodyBuf.length),
      "Content-MD5":    _md5Base64(bodyBuf),
    });
    return _request("PUT", url, headers, bodyBuf).then(
      function () {
        if (auditSuccess) {
          _emit("objectstore.object.setLegalHold", {
            actor:    _actor(opts),
            resource: { kind: "object", id: name + "/" + key },
            metadata: { bucket: name, key: key, status: status },
          });
        }
        _emitEvent("objectstore.object.setLegalHold", 1,
          { outcome: "success", status: status });
        return { applied: true, name: name, key: key, status: status };
      },
      function (e) {
        if (auditFailures) {
          _emit("objectstore.object.setLegalHold", {
            actor:    _actor(opts),
            resource: { kind: "object", id: name + "/" + key },
            outcome:  "failure",
            reason:   e.code || "error",
            metadata: { bucket: name, key: key, status: status },
          });
        }
        _emitEvent("objectstore.object.setLegalHold", 1,
          { outcome: "failure", reason: e.code || "error" });
        throw e;
      }
    );
  }

  function getObjectLegalHold(name, key) {
    _validateBucketName(name);
    _validateObjectKey(key);
    _emitEvent("objectstore.object.getLegalHold", 1, { outcome: "success" });
    var url = _objectUrl(name, key, { "legal-hold": "" });
    var payloadHash = sigv4.sha256Hex(Buffer.alloc(0));
    var headers = _signed("GET", url, payloadHash);
    return _request("GET", url, headers, null).then(
      function (res) {
        var doc = safeXml.parse(res.body);
        var lh = doc.LegalHold || {};
        return { status: lh.Status || null };
      },
      function (e) {
        if (_isLockNotConfigured(e)) {
          return { status: "OFF" };
        }
        throw e;
      }
    );
  }

  return {
    protocol:                       "sigv4",
    create:                         createBucket,
    delete:                         deleteBucket,
    list:                           listBuckets,
    setLifecycle:                   setLifecycle,
    setCorsRules:                   setCorsRules,
    setObjectLockConfiguration:     setObjectLockConfiguration,
    getObjectLockConfiguration:     getObjectLockConfiguration,
    setObjectRetention:             setObjectRetention,
    getObjectRetention:             getObjectRetention,
    setObjectLegalHold:             setObjectLegalHold,
    getObjectLegalHold:             getObjectLegalHold,
  };
}

module.exports = {
  create: create,
  _buildLifecycleXmlForTest:        _buildLifecycleXml,
  _buildCorsXmlForTest:             _buildCorsXml,
  _validateBucketNameForTest:       _validateBucketName,
};

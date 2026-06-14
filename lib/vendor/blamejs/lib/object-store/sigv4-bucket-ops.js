"use strict";
/**
 * sigv4-bucket-ops — bucket-level operations for SigV4 backends.
 *
 * Per-object ops (put / get / list / delete / multipart) live in
 * lib/object-store/sigv4.js and are bound to a single bucket at
 * create() time. Bucket lifecycle ops are at a different level —
 * they need a service-scoped client that addresses arbitrary
 * buckets — so they get their own factory.
 *
 * Operators with multi-cloud ambitions reach for Terraform / CDK /
 * Pulumi. The framework's bucket-ops surface is the operator-from-app
 * path: create the bucket your app needs at boot, attach a lifecycle
 * rule that aborts incomplete multiparts after a week, etc. Niche ops
 * (Object Lock, Replication, Inventory, Notification) are deferred —
 * they're well into Terraform territory.
 *
 * Public API:
 *
 *   var ops = b.objectStore.bucketOps.create({
 *     protocol:        "sigv4",
 *     region:          "us-east-1",
 *     accessKeyId:     env("AWS_ACCESS_KEY_ID"),
 *     secretAccessKey: env("AWS_SECRET_ACCESS_KEY"),
 *     endpoint:        "https://s3.us-east-1.amazonaws.com",  // optional
 *     pathStyle:       false,
 *     timeoutMs:       30000,
 *   });
 *
 *   await ops.create("my-bucket", { region: "eu-west-1" });
 *   await ops.delete("my-bucket");
 *   var buckets = await ops.list();          // [{ name, creationDate }]
 *   await ops.setLifecycle("my-bucket", [{
 *     id:     "abort-stale-multiparts",
 *     status: "Enabled",
 *     prefix: "",
 *     abortIncompleteMultipartUpload: { daysAfterInitiation: 7 },
 *   }]);
 *   await ops.setCorsRules("my-bucket", [{
 *     allowedOrigins: ["https://app.example.com"],
 *     allowedMethods: ["GET", "PUT", "POST"],
 *     allowedHeaders: ["*"],
 *     exposeHeaders:  ["ETag"],
 *     maxAgeSeconds:  3600,
 *   }]);
 *
 * Validation rejects every bad input shape at the call site rather
 * than producing a server-side 400. Errors surface as ObjectStoreError
 * with codes (BUCKET_INVALID_NAME, INVALID_LIFECYCLE, INVALID_CORS_RULE,
 * BUCKET_ALREADY_OWNED, BUCKET_NOT_EMPTY, etc.).
 */
var nodeCrypto = require("node:crypto");
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

// Internal URL builder — endpoint + path string from validated config.
// Routes through safeUrl.parse so the protocol allowlist + length cap
// apply uniformly. Cap is generous since presigned-style URLs with many
// query params can approach 8 KB.
function _internalUrl(input, allowedProtocols) {
  return safeUrl.parse(input, {
    allowedProtocols: allowedProtocols || safeUrl.ALLOW_HTTP_TLS,
    errorClass:       ObjectStoreError,
    maxUrlLength:     C.BYTES.kib(32),
  });
}

// S3 bucket-name rules (general purpose). Source: AWS docs
// "Bucket naming rules". Lowercase letters, digits, hyphens; 3..63
// chars; no consecutive dots; cannot end in -s3alias / -ol-s3 etc.
// We catch the common-mistake cases at config time; AWS catches the
// rest at request time.
var BUCKET_NAME_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

function _validateBucketName(name) {
  if (typeof name !== "string" || name.length < 3 || name.length > 63) {
    throw _err("BUCKET_INVALID_NAME",
      "bucket name must be a string of length 3..63, got " +
      (typeof name === "string" ? "length " + name.length : typeof name), true);
  }
  // Length is bounded above (3..63) before the regex runs so the
  // pattern can't be driven against an unbounded input.
  if (name.length > 63 || !BUCKET_NAME_RE.test(name)) {
    throw _err("BUCKET_INVALID_NAME",
      "bucket name '" + name + "' violates S3 naming rules " +
      "(lowercase, digits, hyphens, dots — no leading/trailing punct)", true);
  }
  if (name.indexOf("..") !== -1) {
    throw _err("BUCKET_INVALID_NAME",
      "bucket name '" + name + "' contains consecutive dots", true);
  }
}

// XML body strings flow through template.escapeHtml — `&#x27;` (which
// it emits for the apostrophe) is a numeric character reference and
// is valid in both XML and HTML, where `&apos;` is XML-only. AWS S3
// accepts both; using the shared HTML escape keeps the framework
// down to one canonical escape primitive.
var _xmlEscape = template.escapeHtml;

// AWS PutBucketLifecycle / PutBucketCors require a Content-MD5 header
// for body integrity (legacy AWS API requirement; SigV4 already covers
// integrity via x-amz-content-sha256 but the API still validates this).
// MD5 here is NOT a credential or security primitive — it's an AWS API
// shape. b.credentialHash is the wrong tool.
function _md5Base64(buf) {
  return nodeCrypto.createHash("md5").update(buf).digest("base64");
}

// ---- Lifecycle XML ----

var ALLOWED_STORAGE_CLASSES = [
  "STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA",
  "INTELLIGENT_TIERING", "GLACIER", "DEEP_ARCHIVE", "GLACIER_IR",
  "EXPRESS_ONEZONE",
];

function _buildLifecycleXml(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw _err("INVALID_LIFECYCLE",
      "setLifecycle: rules must be a non-empty array", true);
  }
  // S3 spec hard cap on lifecycle rules per bucket.
  var MAX_LIFECYCLE_RULES = 1000;
  if (rules.length > MAX_LIFECYCLE_RULES) {
    throw _err("INVALID_LIFECYCLE",
      "setLifecycle: maximum " + MAX_LIFECYCLE_RULES + " rules per bucket (S3 spec)", true);
  }
  var body = '<?xml version="1.0" encoding="UTF-8"?>';
  body += '<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">';
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i];
    if (!rule || typeof rule !== "object") {
      throw _err("INVALID_LIFECYCLE",
        "rules[" + i + "] must be an object", true);
    }
    var status = rule.status || "Enabled";
    if (status !== "Enabled" && status !== "Disabled") {
      throw _err("INVALID_LIFECYCLE",
        "rules[" + i + "].status must be 'Enabled' or 'Disabled'", true);
    }
    if (!rule.expiration && !rule.transition && !rule.abortIncompleteMultipartUpload) {
      throw _err("INVALID_LIFECYCLE",
        "rules[" + i + "] must specify at least one of " +
        "expiration / transition / abortIncompleteMultipartUpload", true);
    }
    body += "<Rule>";
    if (rule.id !== undefined) {
      if (typeof rule.id !== "string" || rule.id.length === 0) {
        throw _err("INVALID_LIFECYCLE",
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
          throw _err("INVALID_LIFECYCLE",
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
        throw _err("INVALID_LIFECYCLE",
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
        throw _err("INVALID_LIFECYCLE",
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

// ---- CORS XML ----

var ALLOWED_CORS_METHODS = ["GET", "PUT", "POST", "DELETE", "HEAD"];

function _buildCorsXml(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw _err("INVALID_CORS_RULE",
      "setCorsRules: rules must be a non-empty array", true);
  }
  if (rules.length > 100) {
    throw _err("INVALID_CORS_RULE",
      "setCorsRules: maximum 100 rules per bucket (S3 spec)", true);
  }
  var body = '<?xml version="1.0" encoding="UTF-8"?>';
  body += '<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">';
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i];
    if (!rule || typeof rule !== "object") {
      throw _err("INVALID_CORS_RULE",
        "rules[" + i + "] must be an object", true);
    }
    if (!Array.isArray(rule.allowedOrigins) || rule.allowedOrigins.length === 0) {
      throw _err("INVALID_CORS_RULE",
        "rules[" + i + "].allowedOrigins must be a non-empty array", true);
    }
    if (!Array.isArray(rule.allowedMethods) || rule.allowedMethods.length === 0) {
      throw _err("INVALID_CORS_RULE",
        "rules[" + i + "].allowedMethods must be a non-empty array", true);
    }
    for (var m = 0; m < rule.allowedMethods.length; m++) {
      if (ALLOWED_CORS_METHODS.indexOf(rule.allowedMethods[m]) === -1) {
        throw _err("INVALID_CORS_RULE",
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
        throw _err("INVALID_CORS_RULE",
          "rules[" + i + "].maxAgeSeconds must be a non-negative number", true);
      }
      body += "<MaxAgeSeconds>" + rule.maxAgeSeconds + "</MaxAgeSeconds>";
    }
    body += "</CORSRule>";
  }
  body += "</CORSConfiguration>";
  if (Buffer.byteLength(body, "utf8") > C.BYTES.kib(64)) {
    throw _err("INVALID_CORS_RULE",
      "CORS configuration exceeds 64 KB (S3 spec)", true);
  }
  return body;
}

// ---- Object Lock + Retention + LegalHold validators / XML ----

var OBJECT_LOCK_MODES = ["GOVERNANCE", "COMPLIANCE"];
var LEGAL_HOLD_STATES = ["ON", "OFF"];

function _validateObjectLockConfig(cfg) {
  if (!cfg || typeof cfg !== "object") {
    throw _err("INVALID_OBJECT_LOCK",
      "setObjectLockConfiguration: opts must be an object " +
      "with { mode, days|years }", true);
  }
  if (OBJECT_LOCK_MODES.indexOf(cfg.mode) === -1) {
    throw _err("INVALID_OBJECT_LOCK",
      "mode must be one of " + OBJECT_LOCK_MODES.join(", ") +
      "; got " + JSON.stringify(cfg.mode), true);
  }
  var hasDays  = cfg.days  != null;
  var hasYears = cfg.years != null;
  if (hasDays && hasYears) {
    throw _err("INVALID_OBJECT_LOCK",
      "specify either days OR years, not both (S3 rule)", true);
  }
  if (!hasDays && !hasYears) {
    throw _err("INVALID_OBJECT_LOCK",
      "default retention requires days or years", true);
  }
  if (hasDays) {
    if (typeof cfg.days !== "number" || !Number.isInteger(cfg.days) ||
        cfg.days <= 0) {
      throw _err("INVALID_OBJECT_LOCK",
        "days must be a positive integer; got " + JSON.stringify(cfg.days), true);
    }
  } else {
    if (typeof cfg.years !== "number" || !Number.isInteger(cfg.years) ||
        cfg.years <= 0) {
      throw _err("INVALID_OBJECT_LOCK",
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
    throw _err("INVALID_RETENTION",
      "setObjectRetention: opts must be an object " +
      "with { mode, retainUntil }", true);
  }
  if (OBJECT_LOCK_MODES.indexOf(opts.mode) === -1) {
    throw _err("INVALID_RETENTION",
      "mode must be one of " + OBJECT_LOCK_MODES.join(", ") +
      "; got " + JSON.stringify(opts.mode), true);
  }
  if (!(opts.retainUntil instanceof Date) || isNaN(opts.retainUntil.getTime())) {
    throw _err("INVALID_RETENTION",
      "retainUntil must be a valid Date instance", true);
  }
  if (opts.retainUntil.getTime() <= Date.now()) {
    throw _err("INVALID_RETENTION",
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
    throw _err("INVALID_LEGAL_HOLD",
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

// S3 + MinIO surface "this lock-related state was never set" via two
// distinct error codes (and HTTP statuses), depending on whether the
// query is at the bucket level or per-object: bucket-level returns 404 +
// `ObjectLockConfigurationNotFoundError`; per-object retention/legal-hold
// returns 4xx + `NoSuchObjectLockConfiguration`. Both translate to the
// same operator answer: "not set". This helper recognizes both so the
// `get*` methods can surface a clean default instead of throwing.
function _isLockNotConfigured(err) {
  if (!err) return false;
  if (err.statusCode !== 404 && err.statusCode !== 400) return false;
  var msg = String(err.message || "");
  return msg.indexOf("ObjectLockConfigurationNotFoundError") !== -1 ||
         msg.indexOf("NoSuchObjectLockConfiguration") !== -1;
}

function _validateObjectKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw _err("INVALID_KEY", "object key must be a non-empty string", true);
  }
  if (key.length > C.BYTES.kib(1)) {
    throw _err("INVALID_KEY", "object key exceeds 1024 bytes (S3 limit)", true);
  }
}

// ---- Public factory ----

function create(config) {
  if (!config || typeof config !== "object") {
    throw _err("INVALID_CONFIG", "bucketOps.create requires a config object", true);
  }
  validateOpts(config, [
    "protocol", "region", "accessKeyId", "secretAccessKey", "sessionToken",
    "endpoint", "pathStyle", "forcePathStyle",
    "allowedProtocols", "allowInternal", "timeoutMs",
    "audit", "observability", "auditSuccess", "auditFailures",
  ], "bucketOps");
  if (config.protocol && config.protocol !== "sigv4") {
    throw _err("INVALID_CONFIG",
      "bucketOps currently only supports protocol 'sigv4'; got '" +
      config.protocol + "'. GCS and Azure bucket lifecycle differs " +
      "substantially per cloud and is operator-managed (Terraform / " +
      "CDK / Pulumi).", true);
  }
  if (!config.region) throw _err("INVALID_CONFIG", "bucketOps: region is required", true);
  if (!config.accessKeyId) throw _err("INVALID_CONFIG", "bucketOps: accessKeyId is required", true);
  if (!config.secretAccessKey) throw _err("INVALID_CONFIG", "bucketOps: secretAccessKey is required", true);

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

  // Audit + observability are framework-best-practice — wired-on by
  // default (no operator action needed beyond passing `audit: b.audit`),
  // failure-audit always on, success-audit on by default for compliance
  // workloads (SEC 17a-4 / FINRA / HIPAA require a trail of
  // who-changed-the-retention-policy-and-when). Operators with extreme
  // call rates can opt out of success-audit via auditSuccess: false;
  // failures still audit so a forensic reconstruction of "what
  // happened" is always possible.
  var audit         = config.audit         || null;
  var observability = config.observability || null;
  var auditSuccess  = config.auditSuccess  !== false;
  var auditFailures = config.auditFailures !== false;

  var _emit = validateOpts.makeAuditEmitter(audit);

  function _emitEvent(name, value, labels) {
    if (observability) observability.safeEvent(name, value, labels || {});
  }

  function _actor(callerOpts) {
    // `req` resolves IP / user-agent / userId from the live request;
    // `actor` is an explicit override bag (e.g. { userId: "ops-admin" })
    // for callers that perform a compliance-sensitive bucket change on
    // behalf of an operator and want that identity on the audit row.
    // Passed as the override seed: explicit `actor` fields win over the
    // request-derived ones, while request-derived fields fill any key the
    // operator left unset.
    var seed = (callerOpts && callerOpts.actor && typeof callerOpts.actor === "object")
      ? callerOpts.actor
      : null;
    return requestHelpers.resolveActorWithOverride(callerOpts || {}, seed);
  }

  // S3 subresource queries (`?lifecycle`, `?cors`, `?object-lock`,
  // `?retention`, `?legal-hold`) are *bare* tokens on the wire — the
  // trailing `=` produced by `URLSearchParams.set(k, "")` is interpreted
  // by some S3 implementations (MinIO in particular) as "this is a
  // body-write with a query parameter, not a subresource", which routes
  // the request to the wrong handler. The SigV4 canonicalizer always
  // reads `key=value` (with the empty `=`) per AWS spec, so the signature
  // computation is unaffected; only the wire form differs. To preserve
  // both behaviors, we build the URL string manually and pass it to the
  // URL constructor — the constructor preserves the bare token in
  // `url.search` while `url.searchParams` still presents it as `key=`.
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
      ub.hostname = name + "." + ub.hostname;
      ub.pathname = "/";
    }
    var base = ub.toString();
    return _internalUrl(_appendQuery(base, query), allowedProtocols);
  }

  function _objectUrl(name, key, query) {
    // Each key segment is encoded individually so that legitimate "/"
    // separators in the key are preserved (S3 treats keys with slashes
    // as flat names, not directories). Use sigv4.awsUriEncode (not
    // encodeURIComponent, which leaves !*'() unescaped) so the wire path
    // matches the bytes S3 canonicalizes the signature over — same encoder
    // _keyToUrl uses for the put/get path.
    var encKey = key.split("/").map(function (s) { return sigv4.awsUriEncode(s, true); }).join("/");
    var uo = _internalUrl(endpoint, allowedProtocols);
    if (pathStyle) {
      uo.pathname = "/" + name + "/" + encKey;
    } else {
      uo.hostname = name + "." + uo.hostname;
      uo.pathname = "/" + encKey;
    }
    var base = uo.toString();
    return _internalUrl(_appendQuery(base, query), allowedProtocols);
  }

  function _serviceUrl(query) {
    // ListBuckets — service-level, no bucket prefix.
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

  // ---- create ----

  function createBucket(name, opts) {
    _validateBucketName(name);
    opts = opts || {};
    validateOpts(opts, ["region", "objectLockEnabled", "req", "actor"],
      "bucketOps.create");
    var targetRegion = opts.region || config.region;
    var url = _bucketUrl(name);
    var bodyBuf;
    var extra = {};
    // us-east-1 takes an empty body. Other regions need
    // CreateBucketConfiguration with a LocationConstraint.
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
    // Object Lock can ONLY be enabled at create time — flipping it on
    // a live bucket isn\'t an S3 API. Setting the header on PutBucket
    // turns on the underlying versioning + write-once-read-many
    // semantics so subsequent setObjectLockConfiguration / Retention
    // / LegalHold calls actually do something.
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
        // Map S3 conflict response codes into stable framework codes.
        var mapped = e;
        if (e.statusCode === 409 && /BucketAlreadyOwnedByYou/.test(e.message || "")) {
          mapped = _err("BUCKET_ALREADY_OWNED",
            "bucket '" + name + "' already exists and is owned by this account", true);
        } else if (e.statusCode === 409) {
          mapped = _err("BUCKET_NAME_TAKEN",
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

  // ---- delete ----

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
        if (e.statusCode === 404) {
          // Idempotent: missing bucket → false. Audit as success-with-noop
          // so the trail still records "operator attempted delete".
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
        if (e.statusCode === 409 && /BucketNotEmpty/.test(e.message || "")) {
          mapped = _err("BUCKET_NOT_EMPTY",
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

  // ---- list ----

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

  // ---- setLifecycle ----

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

  // ---- setCorsRules ----

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

  // ---- Object Lock configuration (bucket-level) ----

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
        // Compliance-critical event — SEC 17a-4 / FINRA / HIPAA require
        // a trail of who-changed-the-default-retention-policy-and-when.
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
        // S3 + MinIO return 404 + ObjectLockConfigurationNotFoundError
        // when the bucket was created without `objectLockEnabled: true`.
        // That's a "not configured" state, not an error worth bubbling
        // — operators asking "is this bucket lock-enabled?" want a
        // clean false, not a try/catch.
        if (_isLockNotConfigured(e)) {
          return { enabled: false, mode: null, days: null, years: null };
        }
        throw e;
      }
    );
  }

  // ---- Per-object retention ----

  function setObjectRetention(name, key, opts) {
    _validateBucketName(name);
    _validateObjectKey(key);
    _validateRetention(opts);
    validateOpts(opts, ["mode", "retainUntil", "bypassGovernance", "req", "actor"],
      "bucketOps.setObjectRetention");
    // COMPLIANCE-mode defense-in-depth: refuse client-side when the
    // operator (or attacker with the s3:PutObjectRetention permission)
    // tries to shorten an existing COMPLIANCE retention or pass
    // bypassGovernance against COMPLIANCE. Real S3 also refuses but
    // MinIO and other S3-compatible backends are implementation-
    // dependent; the framework's job is defense-in-depth, not
    // passthrough. Adds one RTT (the GET) to every PUT — acceptable.
    //
    // The pre-check is a soft gate: when the backend can't surface the
    // existing retention (parse error, no-such-object, etc.), the
    // framework falls through to the PUT and lets the backend's own
    // enforcement handle it. The pre-check is value-add, not
    // load-bearing.
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
      // Re-throw the framework's own COMPLIANCE refusals; everything
      // else (parse errors, transient network errors, malformed
      // backend responses) falls through to the PUT.
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
        // Compliance trail — bypassGovernance is the high-risk op
        // (operator with s3:BypassGovernanceRetention shortened a
        // GOVERNANCE retention) and operators wire alerting on this
        // metadata field.
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
        // S3 + MinIO return 4xx + NoSuchObjectLockConfiguration when the
        // object has no per-object retention applied. Same UX choice as
        // getObjectLockConfiguration: surface the not-set state cleanly
        // rather than forcing operators to try/catch on a known-good
        // request shape.
        if (_isLockNotConfigured(e)) {
          return { mode: null, retainUntil: null };
        }
        throw e;
      }
    );
  }

  // ---- Per-object legal hold ----

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
        // Object never had a legal hold set — S3 + MinIO surface this
        // as NoSuchObjectLockConfiguration. Return a clean OFF instead
        // of throwing; "no hold ever applied" is operationally
        // identical to "hold is OFF".
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
  // Test-only exports for unit-testing the XML builders without
  // standing up a fake S3 server.
  _buildLifecycleXmlForTest:        _buildLifecycleXml,
  _buildCorsXmlForTest:             _buildCorsXml,
  _validateBucketNameForTest:       _validateBucketName,
};

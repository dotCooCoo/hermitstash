// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("./constants");
var codepointClass = require("./codepoint-class");
var lazyRequire = require("./lazy-require");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var { MailUnsubscribeError } = require("./framework-error");

var observability = lazyRequire(function () { return require("./observability"); });
void observability;

var HEADER_VALUE_MAX_BYTES = C.BYTES.kib(2);

function _isLdhListLabel(label) {
  if (typeof label !== "string" || label.length === 0) return false;
  if (label.length > 63) return false;
  var n = label.length;
  for (var i = 0; i < n; i += 1) {
    var c = label.charCodeAt(i);
    var isDigit = c >= 0x30 && c <= 0x39;
    var isUpper = c >= 0x41 && c <= 0x5A;
    var isLower = c >= 0x61 && c <= 0x7A;
    var isHyphen = c === 0x2D;
    var ok = isDigit || isUpper || isLower || (isHyphen && i > 0 && i < n - 1);
    if (!ok) return false;
  }
  return true;
}
function _validateListId(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a non-empty string");
  }
  if (value.length > HEADER_VALUE_MAX_BYTES) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " exceeds " + HEADER_VALUE_MAX_BYTES + " byte cap");
  }
  if (/[\r\n\0]/.test(value)) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " contains forbidden CR/LF/NUL byte");
  }
  var inner = value;
  var bracket = codepointClass.lastDelimited(value, "<", ">");
  if (bracket) inner = bracket.body;
  var labels = inner.split(".");
  if (labels.length < 2) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " '" + value + "' must contain at least two dot-separated labels (RFC 2919 §3)");
  }
  for (var i = 0; i < labels.length; i += 1) {
    if (!_isLdhListLabel(labels[i])) {
      throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
        label + " '" + value + "' has invalid label '" + labels[i] + "' (RFC 2919 §3 LDH)");
    }
  }
  return bracket ? value : "<" + value + ">";
}

function _validateHttpsUrl(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a non-empty string");
  }
  if (value.length > HEADER_VALUE_MAX_BYTES) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " exceeds " + HEADER_VALUE_MAX_BYTES + " byte cap");
  }
  if (/[\r\n\0]/.test(value)) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " contains forbidden CR/LF/NUL byte");
  }
  var parsed;
  try {
    parsed = safeUrl.parse(value, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  } catch (e) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a valid https URL (got " +
      JSON.stringify(value).slice(0, 200) + "): " +
      ((e && e.message) || String(e)));
  }
  if (!parsed) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a valid https URL (got " +
      JSON.stringify(value).slice(0, 200) + ")");
  }
  return parsed.href;
}

function _validateMailto(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a non-empty string");
  }
  if (value.length > HEADER_VALUE_MAX_BYTES) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " exceeds " + HEADER_VALUE_MAX_BYTES + " byte cap");
  }
  if (/[\r\n\0]/.test(value)) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " contains forbidden CR/LF/NUL byte");
  }
  var hasScheme = value.indexOf("mailto:") === 0;
  var inner = hasScheme ? value.slice("mailto:".length) : value;
  var addrPart = inner.split("?")[0];
  if (addrPart.indexOf("@") < 1 || addrPart.lastIndexOf("@") === addrPart.length - 1) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      label + " must be a valid `addr@domain` (with optional `mailto:` prefix)");
  }
  return hasScheme ? value : "mailto:" + value;
}

function buildHeaders(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "buildHeaders: opts object required ({ url?, mailto?, oneClick? })");
  }
  var parts = [];
  if (typeof opts.url === "string" && opts.url.length > 0) {
    var href = _validateHttpsUrl(opts.url, "buildHeaders: opts.url");
    parts.push("<" + href + ">");
  }
  if (typeof opts.mailto === "string" && opts.mailto.length > 0) {
    var mt = _validateMailto(opts.mailto, "buildHeaders: opts.mailto");
    parts.push("<" + mt + ">");
  }
  if (parts.length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "buildHeaders: at least one of opts.url / opts.mailto required");
  }
  var headers = { "List-Unsubscribe": parts.join(", ") };
  if (opts.oneClick === true) {
    headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click";
  }
  return headers;
}

function buildAllListHeaders(opts) {
  if (!opts || typeof opts !== "object") {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "buildAllListHeaders: opts object required");
  }
  var headers = {};

  if (opts.unsubscribeUrl != null || opts.unsubscribeMailto != null ||
      opts.oneClick !== undefined) {
    var unsubHeaders = buildHeaders({
      url:      opts.unsubscribeUrl,
      mailto:   opts.unsubscribeMailto,
      oneClick: opts.oneClick === true,
    });
    Object.assign(headers, unsubHeaders);
  }

  if (opts.helpUrl != null) {
    headers["List-Help"] = "<" + _validateHttpsUrl(opts.helpUrl,
      "buildAllListHeaders: opts.helpUrl") + ">";
  }

  if (opts.archiveUrl != null) {
    headers["List-Archive"] = "<" + _validateHttpsUrl(opts.archiveUrl,
      "buildAllListHeaders: opts.archiveUrl") + ">";
  }

  if (opts.ownerEmail != null) {
    headers["List-Owner"] = "<" + _validateMailto(opts.ownerEmail,
      "buildAllListHeaders: opts.ownerEmail") + ">";
  }

  if (opts.postEmail != null) {
    if (opts.postEmail === "NO") {
      headers["List-Post"] = "NO";
    } else {
      headers["List-Post"] = "<" + _validateMailto(opts.postEmail,
        "buildAllListHeaders: opts.postEmail") + ">";
    }
  }

  if (opts.listId != null) {
    headers["List-ID"] = _validateListId(opts.listId,
      "buildAllListHeaders: opts.listId");
  }

  if (opts.listOwner != null) {
    validateOpts.requireNonEmptyString(opts.listOwner,
      "buildAllListHeaders: opts.listOwner",
      MailUnsubscribeError, "mailunsubscribe/invalid-list-header-shape");
    if (opts.listOwner.length > HEADER_VALUE_MAX_BYTES) {
      throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
        "buildAllListHeaders: opts.listOwner exceeds " + HEADER_VALUE_MAX_BYTES + " byte cap");
    }
    if (/[\r\n\0]/.test(opts.listOwner)) {
      throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
        "buildAllListHeaders: opts.listOwner contains forbidden CR/LF/NUL byte");
    }
    var ownerBracket = codepointClass.firstDelimited(opts.listOwner, "<", ">");
    if (!ownerBracket || ownerBracket.body.indexOf("@") < 1) {
      throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
        "buildAllListHeaders: opts.listOwner must contain `<addr@domain>` (RFC 2369 §3.3)");
    }
    headers["List-Owner"] = opts.listOwner;
  }

  if (Object.keys(headers).length === 0) {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "buildAllListHeaders: at least one List-* field must be supplied");
  }
  return headers;
}

function handler(opts) {
  opts = opts || {};
  if (typeof opts.onUnsubscribe !== "function") {
    throw new MailUnsubscribeError("mailunsubscribe/invalid-list-header-shape",
      "mail.unsubscribe.handler: opts.onUnsubscribe must be a function (req, res) → Promise");
  }
  return async function unsubscribeMiddleware(req, res) {
    if ((req.method || "").toUpperCase() !== "POST") {
      res.statusCode = 405;
      res.setHeader("Allow", "POST");
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("RFC 8058 one-click unsubscribe requires POST");
      return;
    }
    var bodyChunks = [];
    var totalLen = 0;
    var maxBodyBytes = opts.maxBodyBytes || C.BYTES.kib(4);
    var bodyComplete = await new Promise(function (resolve) {
      req.on("data", function (chunk) {
        totalLen += chunk.length;
        if (totalLen > maxBodyBytes) {
          resolve(false);
          return;
        }
        bodyChunks.push(chunk);
      });
      req.on("end", function () { resolve(true); });
      req.on("error", function () { resolve(false); });
    });
    if (!bodyComplete) {
      res.statusCode = 413;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("body exceeds max bytes for one-click unsubscribe");
      return;
    }
    var body = Buffer.concat(bodyChunks).toString("utf8");
    if (body.indexOf("List-Unsubscribe=One-Click") === -1) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("RFC 8058 §3.1: body must contain `List-Unsubscribe=One-Click`");
      return;
    }
    try {
      await opts.onUnsubscribe(req, res);
      if (!res.writableEnded) {
        res.statusCode = 200;
        res.end();
      }
    } catch (err) {
      if (!res.writableEnded) {
        res.statusCode = 500;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("unsubscribe failed");
      }
      throw err;
    }
  };
}

module.exports = {
  buildHeaders:         buildHeaders,
  buildAllListHeaders:  buildAllListHeaders,
  handler:              handler,
  MailUnsubscribeError: MailUnsubscribeError,
};

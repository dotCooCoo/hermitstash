// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var lazyRequire = require("./lazy-require");
var logModule = require("./log");
var problemDetails = require("./problem-details");
var requestHelpers = require("./request-helpers");
var safeEnv = require("./parsers/safe-env");
var template = require("./template");
var audit = lazyRequire(function () { return require("./audit"); });

var bootLog = logModule.boot("errors-page");

var _esc = template.escapeHtml;
var H = requestHelpers.HTTP_STATUS;

var STATUS_REASONS = {};
STATUS_REASONS[H.BAD_REQUEST]            = "Bad Request";
STATUS_REASONS[H.UNAUTHORIZED]           = "Unauthorized";
STATUS_REASONS[H.FORBIDDEN]              = "Forbidden";
STATUS_REASONS[H.NOT_FOUND]              = "Not Found";
STATUS_REASONS[H.METHOD_NOT_ALLOWED]     = "Method Not Allowed";
STATUS_REASONS[H.CONFLICT]               = "Conflict";
STATUS_REASONS[H.PAYLOAD_TOO_LARGE]      = "Payload Too Large";
STATUS_REASONS[H.UNSUPPORTED_MEDIA_TYPE] = "Unsupported Media Type";
STATUS_REASONS[H.UNPROCESSABLE_CONTENT]  = "Unprocessable Content";
STATUS_REASONS[H.TOO_MANY_REQUESTS]      = "Too Many Requests";
STATUS_REASONS[H.INTERNAL_SERVER_ERROR]  = "Internal Server Error";
STATUS_REASONS[H.BAD_GATEWAY]            = "Bad Gateway";
STATUS_REASONS[H.SERVICE_UNAVAILABLE]    = "Service Unavailable";
STATUS_REASONS[H.GATEWAY_TIMEOUT]        = "Gateway Timeout";

function _classify(err) {
  if (!err || typeof err !== "object") {
    return { status: H.INTERNAL_SERVER_ERROR, code: "error-page/internal-error", message: "Internal Server Error", classified: false };
  }
  if (err.isAppError) {
    return {
      status:  err.statusCode || H.INTERNAL_SERVER_ERROR,
      code:    err.code || "error-page/app-error",
      message: err.message || STATUS_REASONS[err.statusCode || H.INTERNAL_SERVER_ERROR] || "Error",
      classified: true,
    };
  }
  if (err.isAuthError) {
    return { status: H.UNAUTHORIZED, code: err.code || "error-page/auth-failed", message: err.message || "Unauthorized", classified: true };
  }
  if (err.code === "VALIDATION_ERROR" || err.name === "ValidationError") {
    return { status: H.BAD_REQUEST, code: err.code || "VALIDATION_ERROR", message: err.message || "Bad Request", classified: true };
  }
  if (err.isSafeJsonError) {
    return { status: H.BAD_REQUEST, code: err.code || "json/invalid", message: err.message || "Bad Request", path: err.path || null, classified: true };
  }
  if ((err.isStorageError || err.isQueueError || err.isExternalDbError) && err.permanent) {
    return { status: H.BAD_REQUEST, code: err.code || "error-page/error", message: err.message || "Bad Request", classified: true };
  }
  if (typeof err.statusCode === "number") {
    return {
      status:  err.statusCode,
      code:    err.code || "error-page/error",
      message: err.message || STATUS_REASONS[err.statusCode] || "Error",
      classified: true,
    };
  }
  return { status: H.INTERNAL_SERVER_ERROR, code: err.code || "error-page/internal-error", message: err.message || "Internal Server Error", classified: false };
}

function _wantsJson(req, defaultFormat) {
  if (defaultFormat === "json") return true;
  if (defaultFormat === "html") return false;
  var accept = (req && req.headers && req.headers.accept) || "";
  if (accept.indexOf("application/json") !== -1) return true;
  if (accept.indexOf("text/html") !== -1)        return false;
  return req && req.method && req.method.toUpperCase() !== "GET";
}

function _redactHeaders(headers) {
  if (!headers || typeof headers !== "object") return {};
  var out = {};
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var lk = k.toLowerCase();
    if (lk === "cookie" || lk === "authorization" ||
        lk === "x-api-key" || lk === "x-csrf-token" ||
        lk.indexOf("token") !== -1) {
      out[k] = "[REDACTED]";
    } else {
      out[k] = headers[k];
    }
  }
  return out;
}

function _renderProdHtml(info, opts) {
  var brand   = opts.brand   ? _esc(opts.brand)   : "blamejs";
  var contact = opts.contact ? _esc(opts.contact) : null;
  return [
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>", _esc(STATUS_REASONS[info.status] || "Error"), " — ", brand, "</title>",
    "<style>",
    "html,body{height:100%;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#c9d1d9}",
    ".wrap{display:flex;align-items:center;justify-content:center;min-height:100%;padding:2rem}",
    ".card{max-width:520px;text-align:center;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:48px 32px}",
    ".status{font-size:64px;font-weight:700;color:#58a6ff;margin:0;line-height:1}",
    ".title{font-size:18px;font-weight:600;color:#e6edf3;margin:18px 0 6px}",
    ".msg{font-size:14px;color:#8b949e;margin:0 0 24px;line-height:1.5}",
    ".contact{font-size:13px;color:#6e7681}",
    ".brand{font-size:12px;color:#484f58;margin-top:32px;letter-spacing:.05em;text-transform:uppercase}",
    "a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}",
    "</style></head><body><div class=\"wrap\"><div class=\"card\">",
    "<p class=\"status\">", String(info.status), "</p>",
    "<p class=\"title\">", _esc(STATUS_REASONS[info.status] || "Error"), "</p>",
    "<p class=\"msg\">", _esc(info.publicMessage), "</p>",
    contact ? "<p class=\"contact\">Contact <a href=\"mailto:" + contact + "\">" + contact + "</a> if this persists.</p>" : "",
    "<p class=\"brand\">", brand, "</p>",
    "</div></div></body></html>",
  ].join("");
}

function _renderDevHtml(info, opts, ctx) {
  var brand = opts.brand ? _esc(opts.brand) : "blamejs";
  var stackHtml = "";
  if (opts.showStack && info.stack) {
    stackHtml = "<pre class=\"stack\">" + _esc(info.stack) + "</pre>";
  }
  var requestHtml = "";
  if (opts.showRequestInfo && ctx && ctx.req) {
    var req = ctx.req;
    var headers = _redactHeaders(req.headers);
    var headerRows = Object.keys(headers).map(function (k) {
      return "<tr><th>" + _esc(k) + "</th><td>" + _esc(headers[k]) + "</td></tr>";
    }).join("");
    requestHtml = [
      "<section><h2>Request</h2>",
      "<table class=\"kv\">",
      "<tr><th>method</th><td>", _esc(req.method || ""), "</td></tr>",
      "<tr><th>url</th><td>", _esc(req.url || ""), "</td></tr>",
      ctx.requestId ? ("<tr><th>requestId</th><td>" + _esc(ctx.requestId) + "</td></tr>") : "",
      "</table>",
      headerRows ? ("<h3>Headers</h3><table class=\"kv\">" + headerRows + "</table>") : "",
      "</section>",
    ].join("");
  }
  var envHtml = "";
  if (opts.showEnvVars) {
    var envKeys = Object.keys(process.env).filter(function (k) {
      return !/SECRET|TOKEN|KEY|PASS|CRED/i.test(k);
    }).sort();
    var envRows = envKeys.map(function (k) {
      return "<tr><th>" + _esc(k) + "</th><td>" + _esc(process.env[k]) + "</td></tr>";
    }).join("");
    envHtml = "<section><h2>Environment</h2><table class=\"kv\">" + envRows + "</table></section>";
  }
  return [
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
    "<title>", String(info.status), " ", _esc(STATUS_REASONS[info.status] || "Error"),
    " — ", brand, " (dev)</title>",
    "<style>",
    "*{box-sizing:border-box}",
    "body{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#0d1117;color:#c9d1d9;font-size:13px;line-height:1.55}",
    "header{background:#21262d;padding:24px 32px;border-bottom:3px solid #f85149}",
    "header .status{display:inline-block;background:#f85149;color:#fff;padding:4px 10px;border-radius:6px;font-weight:700;margin-right:12px}",
    "header h1{display:inline;font-size:18px;color:#e6edf3;font-weight:600}",
    "header .err-code{margin-top:8px;font-size:12px;color:#8b949e}",
    "main{padding:24px 32px;max-width:1200px}",
    "section{margin-bottom:32px}",
    "h2{font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin:0 0 12px;font-weight:600}",
    "h3{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin:18px 0 8px;font-weight:600}",
    ".stack{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:0;white-space:pre-wrap;word-break:break-word;color:#ffa657;font-size:12px;overflow-x:auto}",
    "table.kv{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}",
    "table.kv th{text-align:left;padding:8px 12px;color:#8b949e;font-weight:500;width:200px;background:#0d1117;border-bottom:1px solid #21262d;border-right:1px solid #21262d;vertical-align:top}",
    "table.kv td{padding:8px 12px;color:#c9d1d9;word-break:break-word;border-bottom:1px solid #21262d}",
    "table.kv tr:last-child th,table.kv tr:last-child td{border-bottom:none}",
    "footer{padding:16px 32px;color:#484f58;font-size:11px;letter-spacing:.05em;text-transform:uppercase;border-top:1px solid #21262d}",
    "</style></head><body>",
    "<header>",
    "<span class=\"status\">", String(info.status), "</span>",
    "<h1>", _esc(STATUS_REASONS[info.status] || "Error"), " — ", _esc(info.devMessage), "</h1>",
    info.code ? ("<div class=\"err-code\">code: " + _esc(info.code) + "</div>") : "",
    "</header>",
    "<main>",
    stackHtml ? ("<section><h2>Stack</h2>" + stackHtml + "</section>") : "",
    requestHtml,
    envHtml,
    "</main>",
    "<footer>", brand, " · dev mode · stack/headers redacted in prod</footer>",
    "</body></html>",
  ].join("");
}

function _writeResponse(res, status, contentType, body) {
  if (res.writableEnded) return;
  if (requestHelpers.failAfterHeaders(res)) return;
  try {
    var headers = { "Content-Type": contentType, "Cache-Control": "no-store" };
    if (typeof res.writeHead === "function") {
      res.writeHead(status, headers);
    } else {
      res.statusCode = status;
      if (typeof res.setHeader === "function") {
        res.setHeader("Content-Type", contentType);
        res.setHeader("Cache-Control", "no-store");
      }
    }
    res.end(body);
  } catch (_e) {
    try { res.end("Internal Server Error"); } catch (_e2) { /* socket gone */ }
  }
}

function create(opts) {
  opts = opts || {};
  var modeOpt = opts.mode;
  var mode;
  if (modeOpt === "dev" || modeOpt === "prod") {
    mode = modeOpt;
  } else {
    var nodeEnv = safeEnv.readVar("NODE_ENV");
    mode = (nodeEnv === "production") ? "prod" : "dev";
  }

  var auditOn     = opts.audit !== false;
  var auditAction = typeof opts.auditAction === "string" && opts.auditAction.length > 0
    ? opts.auditAction
    : "request.error";
  var trustProxy = opts.trustProxy === true || typeof opts.trustProxy === "number"
    ? opts.trustProxy : false;
  var defaultFormat = opts.defaultFormat;
  if (defaultFormat !== undefined &&
      defaultFormat !== "auto" && defaultFormat !== "json" && defaultFormat !== "html") {
    throw new Error("errors-page: opts.defaultFormat must be 'auto', 'json', or 'html'");
  }
  var log         = opts.log || null;
  var brand     = opts.brand || null;
  var contact   = opts.contact || null;
  var showStack       = mode === "dev" && opts.showStack       !== false;
  var showRequestInfo = mode === "dev" && opts.showRequestInfo !== false;
  var showEnvVars     = mode === "dev" && opts.showEnvVars     === true;
  var onErrorHook = typeof opts.onError === "function" ? opts.onError : null;

  if (opts.jsonFormatter !== undefined && opts.jsonFormatter !== null &&
      typeof opts.jsonFormatter !== "function") {
    throw new TypeError("errors-page: opts.jsonFormatter must be a function");
  }
  if (opts.renderHtml !== undefined && opts.renderHtml !== null &&
      typeof opts.renderHtml !== "function") {
    throw new TypeError("errors-page: opts.renderHtml must be a function");
  }
  var jsonFormatter = typeof opts.jsonFormatter === "function" ? opts.jsonFormatter : null;
  var renderHtmlHook = typeof opts.renderHtml === "function" ? opts.renderHtml : null;
  var emitProblemDetails = opts.problemDetails === true;

  var _log = logModule.makeViaOrFallback(log, bootLog);

  function handler(err, req, res) {
    var info = _classify(err);
    info.stack = (err && err.stack) ? err.stack : null;
    info.publicMessage = (info.status >= 500 && !info.classified)
      ? (STATUS_REASONS[info.status] || "Internal Server Error")
      : info.message;
    info.devMessage = info.message;

    if (onErrorHook) {
      var handled = false;
      try { handled = !!onErrorHook(err, req, res, info); }
      catch (e) {
        _log("error", "errors-page onError hook threw", { error: (e && e.message) || String(e) });
      }
      if (handled || (res && res.writableEnded)) return;
    }

    var logFields = {
      status:    info.status,
      code:      info.code,
      method:    req && req.method,
      url:       req && req.url,
      requestId: req && req.id,
    };
    if (info.status >= 500) {
      logFields.stack = info.stack || String(err);
      _log("error", "unhandled error", logFields);
    } else {
      _log("warn", "request error", logFields);
    }

    // and AWS keys. safeEmit is also drop-silent on malformed input,
    if (auditOn) {
      try {
        audit().safeEmit({
          action:   auditAction,
          outcome:  info.status >= 500 ? "failure" : "denied",
          actor:    requestHelpers.extractActorContext(req, {
            ip:        requestHelpers.clientIp(req, { trustProxy: trustProxy }),
            sessionId: req && req.session && (req.session.sid || req.session.id),
          }),
          metadata: {
            status:    info.status,
            code:      info.code,
            method:    req && req.method,
            url:       req && req.url,
            requestId: (req && req.id) || (req && req.requestId),
            stack:     info.status >= 500 ? info.stack : null,
          },
          reason:   info.message,
          requestId: (req && req.id) || (req && req.requestId) || null,
        });
      } catch (_e) { /* audit best-effort */ }
    }

    if (res && res.writableEnded) return;

    var ctx = {
      req:       req,
      requestId: req && req.id,
    };

    if (_wantsJson(req, defaultFormat)) {
      if (jsonFormatter) {
        var shaped = null;
        try { shaped = jsonFormatter(info, req); }
        catch (e) {
          _log("error", "errors-page jsonFormatter threw", { error: (e && e.message) || String(e) });
          shaped = null;
        }
        if (shaped && typeof shaped === "object" && shaped.body !== undefined) {
          var fmtType = typeof shaped.contentType === "string" && shaped.contentType.length > 0
            ? shaped.contentType : "application/json; charset=utf-8";
          var fmtBody = typeof shaped.body === "string" || Buffer.isBuffer(shaped.body)
            ? shaped.body : JSON.stringify(shaped.body);
          _writeResponse(res, info.status, fmtType, fmtBody);
          return;
        }
      }

      if (emitProblemDetails) {
        var problem = problemDetails.create({
          type:   "about:blank",
          title:  STATUS_REASONS[info.status] || "Error",
          status: info.status,
          detail: info.publicMessage,
          code:   info.code || (info.status >= 500 ? "internal_error" : "error"),
        });
        if (res && res.writableEnded) return;
        if (requestHelpers.failAfterHeaders(res)) return;
        try { problemDetails.respond(res, problem, req); }
        catch (_e) {
          try { if (!res.writableEnded && typeof res.end === "function") res.end(); }
          catch (_e2) { /* socket already gone */ }
        }
        return;
      }

      var errorObj = {
        code:    info.code || (info.status >= 500 ? "internal_error" : "error"),
        message: info.publicMessage,
      };
      if (info.path) errorObj.path = info.path;
      if (mode === "dev" && info.stack && showStack && info.status >= 500) {
        errorObj.stack = info.stack;
      }
      var errorBody = { error: errorObj };
      if (req && typeof req.apiEncryptEncode === "function") {
        try { errorBody = req.apiEncryptEncode(errorBody); } catch (_e) { errorBody = { error: errorObj }; }
      }
      _writeResponse(res, info.status, "application/json; charset=utf-8",
        JSON.stringify(errorBody));
      return;
    }

    var html = null;
    if (renderHtmlHook) {
      try {
        var custom = renderHtmlHook(info, req);
        if (typeof custom === "string") html = custom;
      } catch (e) {
        _log("error", "errors-page renderHtml hook threw", { error: (e && e.message) || String(e) });
      }
    }
    if (html === null) {
      html = (mode === "dev")
        ? _renderDevHtml(info, {
            brand:           brand,
            showStack:       showStack,
            showRequestInfo: showRequestInfo,
            showEnvVars:     showEnvVars,
          }, ctx)
        : _renderProdHtml(info, { brand: brand, contact: contact });
    }
    _writeResponse(res, info.status, "text/html; charset=utf-8", html);
  }

  handler.mode = mode;
  return handler;
}

module.exports = {
  create:          create,
  STATUS_REASONS:  STATUS_REASONS,
};

"use strict";
/**
 * Response helpers — render a value into an HTTP response with the
 * right Content-Type, status, and body shape, in one call.
 *
 * Without these helpers every route handler reimplements the same
 * five lines: pick a status code, set Content-Type, JSON.stringify
 * (or render a template), set Content-Length, end the response. With
 * them, each response shape is a single call:
 *
 *   render.json(res, { ok: true })
 *   render.text(res, "OK")
 *   render.redirect(res, "/login")
 *   render.htmlString(res, "<h1>Hi</h1>")
 *   r.html(res, "home", { user: req.user })   // engine-bound (see create())
 *
 * The template engine isn't required to use any of the non-HTML
 * helpers. Operators who never render server-side HTML just import
 * the module-level json/text/redirect.
 *
 * Public API:
 *
 *   render.json(res, body, opts?)
 *     → JSON-stringifies body, sets Content-Type application/json;
 *       opts.status (default 200) + opts.headers merged.
 *
 *   render.text(res, body, opts?)
 *     → text/plain. opts.status / opts.headers / opts.charset (default utf-8).
 *
 *   render.htmlString(res, htmlString, opts?)
 *     → text/html for a pre-rendered string; same opts shape.
 *
 *   render.redirect(res, location, opts?)
 *     → opts.status (default 302; 301/303/307/308 also valid).
 *       Location is set; body empty.
 *
 *   render.create({ engine }) → {
 *     html(res, viewName, data?, opts?)         engine-rendered HTML
 *     json, text, htmlString, redirect          re-exported for one-import ergonomics
 *   }
 *     engine is a template engine instance from
 *     b.template.create({ viewsDir }). html() throws if rendering
 *     fails — wire b.middleware.errorHandler downstream to convert
 *     to a sanitized 500 response.
 *
 * All helpers fall through silently when res is already finished
 * (`writableEnded === true`). Mid-stream double-writes from a route
 * that already sent a response (e.g. a Promise rejection after
 * res.end) won't corrupt the wire.
 */

var DEFAULT_CHARSET = "utf-8";

function _alreadyDone(res) {
  return res && res.writableEnded === true;
}

function _writeResponse(res, status, headers, body) {
  if (_alreadyDone(res)) return;
  if (typeof res.writeHead === "function") {
    res.writeHead(status, headers);
  } else {
    // Plain object response (for tests). Best-effort header set.
    res.statusCode = status;
    if (typeof res.setHeader === "function") {
      for (var k in headers) {
        if (Object.prototype.hasOwnProperty.call(headers, k)) res.setHeader(k, headers[k]);
      }
    }
  }
  if (typeof res.end === "function") res.end(body);
}

function _mergedHeaders(base, extra) {
  if (!extra) return base;
  var out = {};
  for (var k in base)  { if (Object.prototype.hasOwnProperty.call(base,  k)) out[k] = base[k]; }
  for (var j in extra) { if (Object.prototype.hasOwnProperty.call(extra, j)) out[j] = extra[j]; }
  return out;
}

// Default Cache-Control for dynamic responses. Browsers heuristically
// cache HTML responses without explicit headers, which causes "saved
// changes don't appear" bugs after a POST/redirect. `no-cache` permits
// caching but forces revalidation on every access — server returns 200
// with fresh content (or 304 if unchanged) instead of the browser
// silently serving stale. Operators wanting a public CDN cacheable
// response override via `opts.headers["Cache-Control"]`.
var DEFAULT_DYNAMIC_CACHE_CONTROL = "private, no-cache, must-revalidate";

function json(res, body, opts) {
  opts = opts || {};
  var encoded = JSON.stringify(body);
  var headers = _mergedHeaders({
    "Content-Type":   "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(encoded, "utf8"),
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, opts.status || 200, headers, encoded);
}

function text(res, body, opts) {
  opts = opts || {};
  var encoded = body == null ? "" : String(body);
  var charset = opts.charset || DEFAULT_CHARSET;
  var headers = _mergedHeaders({
    "Content-Type":   "text/plain; charset=" + charset,
    "Content-Length": Buffer.byteLength(encoded, charset),
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, opts.status || 200, headers, encoded);
}

function htmlString(res, htmlBody, opts) {
  opts = opts || {};
  var encoded = htmlBody == null ? "" : String(htmlBody);
  var charset = opts.charset || DEFAULT_CHARSET;
  var headers = _mergedHeaders({
    "Content-Type":   "text/html; charset=" + charset,
    "Content-Length": Buffer.byteLength(encoded, charset),
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, opts.status || 200, headers, encoded);
}

function redirect(res, location, opts) {
  opts = opts || {};
  if (typeof location !== "string" || location.length === 0) {
    throw new Error("render.redirect: location is required");
  }
  var status = opts.status || 302;
  if (status < 300 || status > 399) {
    throw new Error("render.redirect: status must be 3xx (got " + status + ")");
  }
  var headers = _mergedHeaders({
    "Location":       location,
    "Content-Length": 0,
    "Cache-Control":  DEFAULT_DYNAMIC_CACHE_CONTROL,
  }, opts.headers);
  _writeResponse(res, status, headers, "");
}

// ---- Engine-bound instance ----

function create(opts) {
  opts = opts || {};
  if (!opts.engine || typeof opts.engine.render !== "function") {
    throw new Error("render.create({ engine }): engine.render must be a function " +
      "(pass a template engine from b.template.create)");
  }
  var engine = opts.engine;

  function html(res, viewName, data, htmlOpts) {
    htmlOpts = htmlOpts || {};
    // Auto-merge res.locals into template data — the framework's
    // request-scoped surface (cspNonce, requestId, current user, etc.)
    // lands in res.locals via middleware (csp-nonce, attach-user, etc.).
    // Operators no longer have to thread these through every render
    // call. Operator-supplied `data` keys take precedence over locals
    // — explicit > implicit.
    var merged;
    if (res && res.locals && typeof res.locals === "object") {
      merged = {};
      var lk = Object.keys(res.locals);
      for (var li = 0; li < lk.length; li++) merged[lk[li]] = res.locals[lk[li]];
      if (data) {
        var dk = Object.keys(data);
        for (var di = 0; di < dk.length; di++) merged[dk[di]] = data[dk[di]];
      }
    } else {
      merged = data || {};
    }
    var body = engine.render(viewName, merged);
    return htmlString(res, body, htmlOpts);
  }

  return {
    html:        html,
    htmlString:  htmlString,
    json:        json,
    text:        text,
    redirect:    redirect,
    engine:      engine,
  };
}

module.exports = {
  create:      create,
  json:        json,
  text:        text,
  htmlString:  htmlString,
  redirect:    redirect,
};

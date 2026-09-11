// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodePath = require("node:path");
var C                = require("./constants");
var atomicFile       = require("./atomic-file");
var numericBounds    = require("./numeric-bounds");
var safeAsync        = require("./safe-async");
var safeJson         = require("./safe-json");
var safeUrl          = require("./safe-url");
var structuredFields = require("./structured-fields");
var validateOpts     = require("./validate-opts");
var { defineClass } = require("./framework-error");

var CookieJarError = defineClass("CookieJarError", { alwaysPermanent: true });
var _err = CookieJarError.factory;

var DEFAULTS = Object.freeze({
  persist:        "memory",
  flushDebounceMs: 100,
});

var VALID_PERSIST = new Set(["memory", "vault", "file"]);
var VALID_SAMESITE = new Set(["Strict", "Lax", "None"]);

function _parseHttpDate(s) {
  var t = Date.parse(s);
  return isNaN(t) ? null : t;
}

function _parseSetCookie(line) {
  if (typeof line !== "string" || line.length === 0) return null;
  var semi = line.indexOf(";");
  var head = (semi === -1 ? line : line.slice(0, semi)).trim();
  var eq = head.indexOf("=");
  if (eq <= 0) return null;
  var name = head.slice(0, eq).trim();
  var value = head.slice(eq + 1).trim();
  if (!name) return null;

  var attrs = {};
  if (semi !== -1) {
    var rest = line.slice(semi + 1);
    var parts = structuredFields.splitTopLevel(rest, ";");
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (!p) continue;
      var pi = p.indexOf("=");
      var k, v;
      if (pi === -1) { k = p; v = ""; }
      else { k = p.slice(0, pi).trim(); v = p.slice(pi + 1).trim(); }
      var _unq = structuredFields.unquoteSfString(v);
      if (_unq !== null) v = _unq;
      attrs[k.toLowerCase()] = v;
    }
  }
  return { name: name, value: value, attrs: attrs };
}

function _domainMatch(host, cookieDomain) {
  if (host === cookieDomain) return true;
  if (host.length > cookieDomain.length &&
      host.endsWith(cookieDomain) &&
      host.charAt(host.length - cookieDomain.length - 1) === ".") {
    return true;
  }
  return false;
}

function _pathMatch(reqPath, cookiePath) {
  if (cookiePath === reqPath) return true;
  if (reqPath.indexOf(cookiePath) === 0) {
    if (cookiePath.charAt(cookiePath.length - 1) === "/") return true;
    if (reqPath.charAt(cookiePath.length) === "/") return true;
  }
  return false;
}

function _defaultPath(reqPath) {
  if (typeof reqPath !== "string" || reqPath.length === 0) return "/";
  var qm = reqPath.indexOf("?");
  var p = qm === -1 ? reqPath : reqPath.slice(0, qm);
  if (p.charAt(0) !== "/") return "/";
  var lastSlash = p.lastIndexOf("/");
  if (lastSlash <= 0) return "/";
  return p.slice(0, lastSlash);
}

function create(opts) {
  opts = opts || {};
  var persist = opts.persist === undefined ? DEFAULTS.persist : opts.persist;
  if (!VALID_PERSIST.has(persist)) {
    throw _err("http-client-cookie-jar/bad-opt", "cookieJar.create: persist must be 'memory' | 'vault' | 'file', got " +
      JSON.stringify(persist));
  }
  var vault = opts.vault || null;
  if (persist === "vault") {
    validateOpts.requireMethods(vault, ["seal", "unseal"],
      "cookieJar.create: persist: 'vault' opts.vault (pass b.vault)", CookieJarError, "http-client-cookie-jar/bad-opt");
  }
  var filePath = null;
  if (persist === "file") {
    validateOpts.requireNonEmptyString(opts.file, "cookieJar.create: persist: 'file' opts.file (absolute path)", CookieJarError, "http-client-cookie-jar/bad-opt");
    filePath = opts.file;
    if (!nodePath.isAbsolute(filePath)) {
      throw _err("http-client-cookie-jar/bad-opt",
        "cookieJar.create: opts.file must be an absolute path, got " + JSON.stringify(filePath));
    }
    if (vault) {
      validateOpts.requireMethods(vault, ["seal", "unseal"],
        "cookieJar.create: persist: 'file' opts.vault (pass b.vault to seal the on-disk bytes)", CookieJarError, "http-client-cookie-jar/bad-opt");
    }
  }
  if (opts.flushDebounceMs !== undefined && !numericBounds.isNonNegativeFiniteInt(opts.flushDebounceMs)) {
    throw _err("http-client-cookie-jar/bad-opt", "cookieJar.create: flushDebounceMs must be a non-negative finite integer; got " +
      numericBounds.shape(opts.flushDebounceMs));
  }
  var flushDebounceMs = opts.flushDebounceMs !== undefined ? opts.flushDebounceMs : DEFAULTS.flushDebounceMs;
  var clock = typeof opts.clock === "function" ? opts.clock : Date.now;

  var store = new Map();

  function _seal(plain) {
    if (persist !== "vault" || plain === undefined || plain === null) return String(plain == null ? "" : plain);
    return vault.seal(String(plain));
  }
  function _unseal(blob) {
    if (persist !== "vault" || blob === undefined || blob === null) return blob == null ? "" : String(blob);
    return String(vault.unseal(blob));
  }

  function _setOne(reqUrl, parsed) {
    var u;
    try { u = safeUrl.parse(reqUrl, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL }); }
    catch (_e) { return; }
    var host = u.hostname.toLowerCase();
    var attrs = parsed.attrs || {};

    var domainAttr = attrs.domain;
    var domain;
    var hostOnly;
    if (domainAttr) {
      var d = String(domainAttr).toLowerCase();
      if (d.charAt(0) === ".") d = d.slice(1);
      if (!_domainMatch(host, d)) return;
      domain = d;
      hostOnly = false;
    } else {
      domain = host;
      hostOnly = true;
    }

    var path = (typeof attrs.path === "string" && attrs.path.charAt(0) === "/")
      ? attrs.path : _defaultPath(u.pathname);

    var now = clock();
    var expiresAt = null;
    if (attrs["max-age"] !== undefined) {
      var maxAge = parseInt(attrs["max-age"], 10);
      if (!isNaN(maxAge)) {
        expiresAt = maxAge <= 0 ? 0 : (now + C.TIME.seconds(maxAge));
      }
    } else if (attrs.expires) {
      expiresAt = _parseHttpDate(attrs.expires);
    }

    var key = domain + "|" + path + "|" + parsed.name;
    if (expiresAt !== null && expiresAt <= now) {
      store.delete(key);
      return;
    }

    var sameSiteRaw = attrs.samesite;
    var sameSite = null;
    if (typeof sameSiteRaw === "string") {
      var ssLc = sameSiteRaw.toLowerCase();
      if (ssLc === "strict") sameSite = "Strict";
      else if (ssLc === "lax") sameSite = "Lax";
      else if (ssLc === "none") sameSite = "None";
    }

    var prior = store.get(key);
    store.set(key, {
      name:      parsed.name,
      value:     _seal(parsed.value),
      domain:    domain,
      path:      path,
      hostOnly:  hostOnly,
      expiresAt: expiresAt,
      httpOnly:  Object.prototype.hasOwnProperty.call(attrs, "httponly"),
      secure:    Object.prototype.hasOwnProperty.call(attrs, "secure"),
      sameSite:  sameSite,
      createdAt: prior ? prior.createdAt : now,
      updatedAt: now,
    });
  }

  function setFromResponse(reqUrl, setCookieHeader) {
    if (!setCookieHeader) return;
    var lines = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    for (var i = 0; i < lines.length; i++) {
      var parsed = _parseSetCookie(lines[i]);
      if (parsed) _setOne(reqUrl, parsed);
    }
  }

  function cookieHeaderFor(reqUrl) {
    var u;
    try { u = safeUrl.parse(reqUrl, { allowedProtocols: safeUrl.ALLOW_HTTP_ALL }); }
    catch (_e) { return null; }
    var host = u.hostname.toLowerCase();
    var path = u.pathname || "/";
    var isSecure = u.protocol === "https:";
    var now = clock();

    var matches = [];
    for (var entry of store.values()) {
      if (entry.expiresAt !== null && entry.expiresAt <= now) continue;
      if (entry.hostOnly) {
        if (entry.domain !== host) continue;
      } else {
        if (!_domainMatch(host, entry.domain)) continue;
      }
      if (!_pathMatch(path, entry.path)) continue;
      if (entry.secure && !isSecure) continue;
      matches.push(entry);
    }
    if (matches.length === 0) return null;

    matches.sort(function (a, b) {
      if (a.path.length !== b.path.length) return b.path.length - a.path.length;
      return a.createdAt - b.createdAt;
    });
    var pieces = matches.map(function (e) {
      return e.name + "=" + _unseal(e.value);
    });
    return pieces.join("; ");
  }

  function getAll() {
    var now = clock();
    var out = [];
    for (var entry of store.values()) {
      if (entry.expiresAt !== null && entry.expiresAt <= now) continue;
      out.push({
        name:      entry.name,
        value:     _unseal(entry.value),
        domain:    entry.domain,
        path:      entry.path,
        hostOnly:  entry.hostOnly,
        expiresAt: entry.expiresAt,
        httpOnly:  entry.httpOnly,
        secure:    entry.secure,
        sameSite:  entry.sameSite,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt,
      });
    }
    return out;
  }

  function clear(filter) {
    if (!filter) {
      var n = store.size;
      store.clear();
      return n;
    }
    if (typeof filter !== "object") {
      throw _err("http-client-cookie-jar/bad-opt", "cookieJar.clear: filter must be an object or undefined");
    }
    var purged = 0;
    var keysToDelete = [];
    for (var pair of store.entries()) {
      var key = pair[0];
      var entry = pair[1];
      if (filter.domain && entry.domain !== filter.domain) continue;
      if (filter.name && entry.name !== filter.name) continue;
      if (filter.path && entry.path !== filter.path) continue;
      keysToDelete.push(key);
    }
    for (var i = 0; i < keysToDelete.length; i++) {
      store.delete(keysToDelete[i]);
      purged++;
    }
    return purged;
  }

  function size() {
    var now = clock();
    var n = 0;
    for (var entry of store.values()) {
      if (entry.expiresAt !== null && entry.expiresAt <= now) continue;
      n++;
    }
    return n;
  }

  function setFromSerialized(rows) {
    if (!Array.isArray(rows)) {
      throw _err("http-client-cookie-jar/bad-opt", "cookieJar.setFromSerialized: rows must be an array");
    }
    var now = clock();
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      if (!r || typeof r.name !== "string" || typeof r.domain !== "string" || typeof r.path !== "string") continue;
      var key = r.domain + "|" + r.path + "|" + r.name;
      if (r.expiresAt !== null && r.expiresAt !== undefined && r.expiresAt <= now) continue;
      store.set(key, {
        name:      r.name,
        value:     _seal(r.value),
        domain:    r.domain,
        path:      r.path,
        hostOnly:  !!r.hostOnly,
        expiresAt: typeof r.expiresAt === "number" ? r.expiresAt : null,
        httpOnly:  !!r.httpOnly,
        secure:    !!r.secure,
        sameSite:  VALID_SAMESITE.has(r.sameSite) ? r.sameSite : null,
        createdAt: typeof r.createdAt === "number" ? r.createdAt : now,
        updatedAt: typeof r.updatedAt === "number" ? r.updatedAt : now,
      });
    }
  }

  function _storeForTest() {
    var rows = [];
    for (var entry of store.values()) {
      rows.push({
        name:      entry.name,
        valueRaw:  entry.value,
        domain:    entry.domain,
        path:      entry.path,
        expiresAt: entry.expiresAt,
      });
    }
    return rows;
  }

  function _flushSync() {
    if (!filePath) return;
    var rows = getAll();
    var serialized = JSON.stringify(rows);
    var blob = vault ? vault.seal(serialized) : serialized;
    atomicFile.writeSync(filePath, blob, { fileMode: 0o600 });
  }
  var flushScheduler = safeAsync.makeScheduledFlush(flushDebounceMs, function () {
    if (!filePath) return;
    try { _flushSync(); } catch (_e) { /* operator can call flush() to retry */ }
  });
  function _scheduleFlush() {
    if (!filePath) return;
    flushScheduler.schedule();
  }
  function flush() {
    flushScheduler.cancel();
    _flushSync();
  }
  function close() {
    flushScheduler.cancel();
    if (filePath) try { _flushSync(); } catch (_e) { /* best-effort */ }
  }

  var setFromResponseAndFlush = function (reqUrl, hdr) {
    setFromResponse(reqUrl, hdr); _scheduleFlush();
  };
  var clearAndFlush = function (filter) {
    var n = clear(filter); _scheduleFlush(); return n;
  };
  var setFromSerializedAndFlush = function (rows) {
    setFromSerialized(rows); _scheduleFlush();
  };

  if (filePath) {
    var raw = null;
    try {
      raw = atomicFile.fdSafeReadSync(filePath, {
        maxBytes: C.BYTES.mib(16), encoding: "utf8", refuseSymlink: true, inodeCheck: true,
      });
    } catch (e) {
      if (e && (e.code === "ENOENT" || e.code === "atomic-file/enoent")) { raw = null; }
      else {
        throw _err("http-client-cookie-jar/load-failed",
          "cookieJar.create: failed to load persist file '" + filePath + "': " +
          (e.message || String(e)));
      }
    }
    if (raw !== null) {
      try {
        var serialized = vault ? vault.unseal(raw) : raw;
        if (serialized && serialized.length > 0) {
          setFromSerialized(safeJson.parse(serialized, { maxBytes: C.BYTES.mib(16) }));
        }
      } catch (e) {
        throw _err("http-client-cookie-jar/load-failed",
          "cookieJar.create: failed to load persist file '" + filePath + "': " +
          (e.message || String(e)));
      }
    }
  }

  return {
    setFromResponse:    filePath ? setFromResponseAndFlush   : setFromResponse,
    cookieHeaderFor:    cookieHeaderFor,
    getAll:             getAll,
    clear:              filePath ? clearAndFlush             : clear,
    size:               size,
    setFromSerialized:  filePath ? setFromSerializedAndFlush : setFromSerialized,
    flush:              flush,
    close:              close,
    persist:            persist,
    file:               filePath,
    _storeForTest:      _storeForTest,
  };
}

module.exports = {
  create:         create,
  CookieJarError: CookieJarError,
  DEFAULTS:       DEFAULTS,
  _parseSetCookie: _parseSetCookie,
};
void safeUrl;

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.httpClient.cookieJar — outbound HTTP cookie store.
 *
 * Holds Set-Cookie state across requests so successive calls in a flow
 * (login → list → mutate → logout, OAuth code-exchange → userinfo, etc.)
 * carry the right Cookie header without operators threading it by hand.
 * RFC 6265 attribute coverage: Domain / Path / Expires / Max-Age /
 * HttpOnly / Secure / SameSite. Public Suffix List (PSL) awareness is
 * out of scope — operators wiring jars against trusted upstream
 * domains don't need it; for cross-eTLD safety in untrusted contexts,
 * use a per-domain jar and validate the host against an allowlist.
 *
 *   var jar = b.httpClient.cookieJar.create();      // in-memory
 *   await b.httpClient.request({ url: loginUrl, method: "POST", body, jar });
 *   await b.httpClient.request({ url: meUrl, jar });   // session cookie attaches
 *
 * Three persistence modes:
 *
 *   memory  — in-process Map. Restart loses everything.
 *   vault   — every cookie value is sealed via b.vault.seal before it
 *             lands in the in-process Map, so a memory dump or core
 *             file doesn't expose plaintext values:
 *
 *               b.httpClient.cookieJar.create({ persist: "vault", vault: b.vault })
 *
 *   file    — on-disk persistence at opts.file (absolute path). Loaded
 *             at create() if the file exists; flushed (debounced via
 *             opts.flushDebounceMs, default 100ms) on every set / clear
 *             / setFromSerialized. Pass `vault` alongside `file` to
 *             seal the on-disk bytes; without vault the file is
 *             plaintext JSON (operator chose the threat model).
 *
 *               b.httpClient.cookieJar.create({
 *                 persist: "file",
 *                 file:    "/var/lib/myapp/jar.json",
 *                 vault:   b.vault,           // optional but recommended
 *               })
 *
 * The file mode survives process restart. Cluster-shared persistence
 * (multiple nodes sharing one jar) is out of scope; operators with
 * that need wire a custom jar via the same shape as the returned
 * object (setFromResponse / cookieHeaderFor / getAll / etc.).
 *
 * Outbound filtering follows RFC 6265 §5.4:
 *   - Domain: exact-host match by default; Domain attribute allows
 *     subdomain match (host must be a suffix of cookie.domain).
 *   - Path: request path must equal cookie.path or be path-below.
 *   - Secure: cookie only attaches when the request URL is https:.
 *   - Expiry: rows past Expires / Max-Age don't attach.
 *   - Sort: longer path first, then earlier creation time.
 *
 * Cookie shape returned from getAll():
 *
 *   {
 *     name, value, domain, path, hostOnly,
 *     expiresAt, // unix ms, or null for session cookies
 *     httpOnly, secure, sameSite, // attributes
 *     createdAt, updatedAt,
 *   }
 */

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

// ---- Set-Cookie parser ----

function _parseHttpDate(s) {
  // node:Date handles RFC 1123 / 850 / asctime — sufficient for HTTP-date.
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
    // RFC 6265 §4.1 attribute values are token-only by spec, but
    // interop reality is that some servers emit quoted attr values
    // (e.g. `; SameSite="Strict"` from older middleware). Quote-aware
    // split preserves a quoted `;` inside an attr value if anyone
    // ever sends one — defensive, not bug-fixing.
    var parts = structuredFields.splitTopLevel(rest, ";");
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (!p) continue;
      var pi = p.indexOf("=");
      var k, v;
      if (pi === -1) { k = p; v = ""; }
      else { k = p.slice(0, pi).trim(); v = p.slice(pi + 1).trim(); }
      // Strip surrounding quotes from attribute value when present
      // (defensive against interop). RFC 6265 §4.1 does not require
      // this, but doesn't forbid the operator's parser absorbing it.
      var _unq = structuredFields.unquoteSfString(v);
      if (_unq !== null) v = _unq;
      attrs[k.toLowerCase()] = v;
    }
  }
  return { name: name, value: value, attrs: attrs };
}

// ---- Domain / Path matching ----

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
  // RFC 6265 §5.1.4: take everything up to the last "/", or "/" if none.
  if (typeof reqPath !== "string" || reqPath.length === 0) return "/";
  var qm = reqPath.indexOf("?");
  var p = qm === -1 ? reqPath : reqPath.slice(0, qm);
  if (p.charAt(0) !== "/") return "/";
  var lastSlash = p.lastIndexOf("/");
  if (lastSlash <= 0) return "/";
  return p.slice(0, lastSlash);
}

// ---- Public create ----

function create(opts) {
  opts = opts || {};
  var persist = opts.persist === undefined ? DEFAULTS.persist : opts.persist;
  if (!VALID_PERSIST.has(persist)) {
    throw _err("BAD_OPT", "cookieJar.create: persist must be 'memory' | 'vault' | 'file', got " +
      JSON.stringify(persist));
  }
  var vault = opts.vault || null;
  if (persist === "vault") {
    validateOpts.requireMethods(vault, ["seal", "unseal"],
      "cookieJar.create: persist: 'vault' opts.vault (pass b.vault)", CookieJarError, "BAD_OPT");
  }
  var filePath = null;
  if (persist === "file") {
    validateOpts.requireNonEmptyString(opts.file, "cookieJar.create: persist: 'file' opts.file (absolute path)", CookieJarError, "BAD_OPT");
    filePath = opts.file;
    // Refuse relative paths so a process running in a different cwd
    // doesn't accidentally serialize to a sibling directory.
    if (!nodePath.isAbsolute(filePath)) {
      throw _err("BAD_OPT",
        "cookieJar.create: opts.file must be an absolute path, got " + JSON.stringify(filePath));
    }
  }
  if (opts.flushDebounceMs !== undefined && !numericBounds.isNonNegativeFiniteInt(opts.flushDebounceMs)) {
    throw _err("BAD_OPT", "cookieJar.create: flushDebounceMs must be a non-negative finite integer; got " +
      numericBounds.shape(opts.flushDebounceMs));
  }
  var flushDebounceMs = opts.flushDebounceMs !== undefined ? opts.flushDebounceMs : DEFAULTS.flushDebounceMs;
  var clock = typeof opts.clock === "function" ? opts.clock : Date.now;

  // Storage map keyed by `<domain>|<path>|<name>` so a (domain, path)
  // tuple can hold multiple cookies, but a same-tuple-same-name update
  // replaces the prior row per RFC 6265 §5.3.
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

    // Domain attribute: lower-case, leading-dot stripped (RFC 6265bis).
    var domainAttr = attrs.domain;
    var domain;
    var hostOnly;
    if (domainAttr) {
      var d = String(domainAttr).toLowerCase();
      if (d.charAt(0) === ".") d = d.slice(1);
      // Don't accept a Domain that the request host doesn't match.
      if (!_domainMatch(host, d)) return;
      domain = d;
      hostOnly = false;
    } else {
      domain = host;
      hostOnly = true;
    }

    var path = (typeof attrs.path === "string" && attrs.path.charAt(0) === "/")
      ? attrs.path : _defaultPath(u.pathname);

    // Expires / Max-Age. Max-Age wins when both present (RFC 6265 §5.2.2).
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

    // Max-Age=0 / past Expires → delete an existing matching row.
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

  // ---- Public API ----

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
      // Expiry
      if (entry.expiresAt !== null && entry.expiresAt <= now) continue;
      // Domain
      if (entry.hostOnly) {
        if (entry.domain !== host) continue;
      } else {
        if (!_domainMatch(host, entry.domain)) continue;
      }
      // Path
      if (!_pathMatch(path, entry.path)) continue;
      // Secure
      if (entry.secure && !isSecure) continue;
      matches.push(entry);
    }
    if (matches.length === 0) return null;

    // Sort: longer path first, then earlier creation time.
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
      throw _err("BAD_OPT", "cookieJar.clear: filter must be an object or undefined");
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

  // Round-trip helpers — operators with restart-survival needs serialize
  // via getAll(), persist however they like, restore via setFromSerialized.
  function setFromSerialized(rows) {
    if (!Array.isArray(rows)) {
      throw _err("BAD_OPT", "cookieJar.setFromSerialized: rows must be an array");
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

  // Raw-store accessor for tests — returns the literal Map entries with
  // the value field as it sits in memory (sealed when persist === "vault").
  // Operators don't call this; if they need stored state, getAll() returns
  // the unsealed form. Exposed so the no-plaintext assertion is verifiable.
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

  // ---- File persistence ----
  // When persist === "file", load on construct + flush on every write
  // (debounced). On-disk format is JSON of getAll() output. If a vault
  // is also passed, the file is sealed via vault.seal so the on-disk
  // bytes are encrypted at rest; otherwise plaintext (operator chose
  // the threat model by passing or omitting vault).
  function _flushSync() {
    if (!filePath) return;
    var rows = getAll();
    var serialized = JSON.stringify(rows);
    var blob = vault ? vault.seal(serialized) : serialized;
    // Atomic, symlink-refusing write: a bare writeFileSync follows a symlink
    // planted at filePath (CWE-59) and can leave a torn jar if the process
    // dies mid-write. writeSync stages into a no-follow exclusive temp + renames.
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

  // Wrap mutating entrypoints so each write schedules a flush. The
  // wrappers go on the returned object — the underlying function
  // declarations stay intact so other internal callers reach them.
  var setFromResponseAndFlush = function (reqUrl, hdr) {
    setFromResponse(reqUrl, hdr); _scheduleFlush();
  };
  var clearAndFlush = function (filter) {
    var n = clear(filter); _scheduleFlush(); return n;
  };
  var setFromSerializedAndFlush = function (rows) {
    setFromSerialized(rows); _scheduleFlush();
  };

  // Initial load from file. Missing file is fine (first run).
  // Persist file may be operator-tampered (or vault-sealed) — route through
  // safeJson with an explicit byte cap so a maliciously-large file can't
  // OOM the process before the parse fails.
  if (filePath) {
    // Capped fd-bound read (no existsSync check-then-read window): the cap now
    // precedes the file allocation so a maliciously-large persist file can't OOM
    // the process before parse. refuseSymlink+inodeCheck: the jar file is
    // operator-local + may hold a vault-sealed (secret) blob, and is never a
    // k8s-style projected-secret mount. A MISSING file is the normal first run.
    var raw = null;
    try {
      raw = atomicFile.fdSafeReadSync(filePath, {
        maxBytes: C.BYTES.mib(16), encoding: "utf8", refuseSymlink: true, inodeCheck: true,
      });
    } catch (e) {
      if (e && e.code === "ENOENT") { raw = null; }   // first run — no persist file yet
      else {
        throw _err("LOAD_FAILED",
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
        throw _err("LOAD_FAILED",
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
  // Exposed for tests + advanced operator wiring.
  _parseSetCookie: _parseSetCookie,
};
// safeUrl reserved for future scheme validation hooks (e.g. operator-supplied
// allowedProtocols filter on cookie attachment paths).
void safeUrl;

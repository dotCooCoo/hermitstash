"use strict";
/**
 * cookies — cookie parse/serialize + access-gated sealed cookies.
 *
 * RFC 6265 cookie plumbing the framework was duplicating across
 * middleware: a parser in attach-user, ad-hoc Set-Cookie strings in
 * route handlers, no shared place for attribute defaults. This is the
 * single primitive.
 *
 * Two surfaces:
 *
 *   1. Module-level (stateless): cookies.parse / cookies.serialize.
 *      Useful in test fixtures and code that doesn't have a vault.
 *
 *   2. Instance (cookies.create): bound defaults for cookie attributes,
 *      a wired vault for sealed reads/writes, and req/res helpers.
 *
 *   var cookies = b.cookies.create({
 *     vault: b.vault,                  // required for sealed* methods
 *     defaults: {
 *       httpOnly: true,
 *       secure:   true,                // default true; HTTPS expected
 *       sameSite: "Lax",
 *       path:     "/",
 *       maxAge:   7 * 86400,           // seconds
 *     },
 *   });
 *
 *   cookies.parse("a=1; b=2")           → { a: "1", b: "2" }
 *   cookies.serialize("name", "v",
 *     { maxAge: 3600 })                 → "name=v; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax; Secure"
 *
 *   cookies.read(req, "name")           → "v" or null
 *   cookies.write(res, "name", "v", {}) // appends to existing Set-Cookie
 *   cookies.clear(res, "name", {})      // expire by Max-Age=0
 *
 *   cookies.writeSealed(res, "session", sid)  // vault.seal then write
 *   cookies.readSealed(req, "session")        // read then vault.unseal
 *
 * Sealed-cookie purpose: the cookie value is a vault.seal of the real
 * value. Without the framework's vault key, no client can hand-craft a
 * valid cookie value, so the API is unreachable via curl-with-arbitrary-
 * cookies or any tool that hasn't been through the framework's crypto
 * flow. The vault prefix is stripped on write and re-added on read so
 * the cookie carries only the base64 envelope.
 *
 * Defense in serialize/parse:
 *   - Cookie name must be a valid token (no CTLs, no separator chars).
 *   - Cookie value must not contain CRLF, semicolon, or comma.
 *   - Value is percent-encoded on write, percent-decoded on read.
 *   - Domain / Path are CRLF-stripped to defeat header injection
 *     attempts via operator-controlled but improperly-escaped inputs.
 */

var C = require("./constants");
var validateOpts = require("./validate-opts");
var { FrameworkError } = require("./framework-error");

class CookieError extends FrameworkError {
  constructor(code, message) {
    super(message, code);
    this.name = "CookieError";
    this.permanent = true;
    this.isCookieError = true;
  }
}

// RFC 6265 cookie-name token: VCHAR minus separators. Reject anything
// outside this range — embeddings of CTLs / separators / whitespace
// would break parsing on the next hop.
var TOKEN_RE = /^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/;
// Reject CRLF, NUL, semicolon, comma in cookie value pre-encoding.
var FORBIDDEN_VALUE_RE = /[\r\n\0;,]/;

// Length caps applied before the regex tests so a hostile caller can't
// stage a pathological-length input against the engine. RFC 6265 doesn't
// pin a name/value length; browsers vary, with a practical 4 KiB total
// envelope. The framework caps name + value to leave headroom.
var MAX_NAME_LENGTH  = C.BYTES.bytes(256);
var MAX_VALUE_LENGTH = C.BYTES.kib(4);

function _validateName(name) {
  if (typeof name !== "string" || name.length === 0) {
    throw new CookieError("cookies/invalid-name",
      "cookie name must be a non-empty string");
  }
  // Length cap before the regex test — bound the engine on hostile
  // input lengths even though the regex is anchored.
  if (name.length > MAX_NAME_LENGTH || !TOKEN_RE.test(name)) {
    throw new CookieError("cookies/invalid-name",
      "cookie name '" + name + "' is empty, too long, or contains forbidden characters");
  }
}

function _validateValue(value) {
  if (typeof value !== "string") {
    throw new CookieError("cookies/invalid-value",
      "cookie value must be a string");
  }
  // Length cap before the regex test (defense in depth — the regex
  // here is a simple character class, but the same discipline that
  // bounds longer regexes elsewhere applies).
  if (value.length > MAX_VALUE_LENGTH || FORBIDDEN_VALUE_RE.test(value)) {
    throw new CookieError("cookies/invalid-value",
      "cookie value is too long or contains forbidden control character (CRLF/NUL/;/,)");
  }
}

// Strip CRLF/NUL defensively from operator-supplied attribute strings
// (Domain, Path, SameSite). Even if the attribute is constant in the
// caller's code, attribute strings flow into Set-Cookie which is a
// header — never trust unscrubbed values reach the wire.
function _scrubAttr(s) {
  if (typeof s !== "string") return s;
  return s.replace(/[\r\n\0]/g, "");                                             // allow:duplicate-regex — CR/LF/NUL header-injection rejection appears in cookies / mail / security-headers; each is the boundary primitive for its domain

}

function parse(cookieHeader) {
  var out = {};
  if (typeof cookieHeader !== "string" || cookieHeader.length === 0) return out;
  var pairs = cookieHeader.split(/;\s*/);
  for (var i = 0; i < pairs.length; i++) {
    var pair = pairs[i];
    if (!pair) continue;
    var eq = pair.indexOf("=");
    if (eq < 0) continue;
    var k = pair.slice(0, eq).trim();
    if (!k) continue;
    var v = pair.slice(eq + 1).trim();
    // Strip surrounding double-quotes per RFC 6265 §5.2.
    if (v.length >= 2 && v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
      v = v.slice(1, -1);
    }
    try { v = decodeURIComponent(v); }
    catch (_e) { /* malformed encoding — keep raw */ }
    // Last write wins per RFC; matches every browser's behavior.
    out[k] = v;
  }
  return out;
}

function serialize(name, value, attrs) {
  _validateName(name);
  _validateValue(value);
  attrs = attrs || {};

  // RFC 6265bis §4.1.3 cookie-prefix invariants — refused at serialize-
  // time so an operator-side typo doesn't ship a broken cookie that
  // browsers silently reject (and the operator wonders why their cookie
  // never sets).
  //
  //   __Secure-* — MUST be Secure
  //   __Host-*   — MUST be Secure, Path=/, NO Domain
  //
  // Caught at the source so every caller (csrf-protect / session /
  // operator) gets the same enforcement.
  if (name.indexOf("__Secure-") === 0) {
    if (attrs.secure !== true) {
      throw new CookieError("cookies/prefix-secure-required",
        "__Secure-* cookies MUST set Secure (RFC 6265bis §4.1.3.1) — got '" +
        name + "' without secure: true");
    }
  }
  if (name.indexOf("__Host-") === 0) {
    if (attrs.secure !== true) {
      throw new CookieError("cookies/prefix-host-secure-required",
        "__Host-* cookies MUST set Secure (RFC 6265bis §4.1.3.2) — got '" +
        name + "' without secure: true");
    }
    if (attrs.path !== "/") {
      throw new CookieError("cookies/prefix-host-path-required",
        "__Host-* cookies MUST set Path=/ (RFC 6265bis §4.1.3.2) — got '" +
        name + "' with path=" + JSON.stringify(attrs.path || "<unset>"));
    }
    if (attrs.domain) {
      throw new CookieError("cookies/prefix-host-no-domain",
        "__Host-* cookies MUST NOT set Domain (RFC 6265bis §4.1.3.2) — got '" +
        name + "' with domain=" + JSON.stringify(attrs.domain));
    }
  }

  var parts = [name + "=" + encodeURIComponent(value)];

  if (attrs.maxAge !== undefined && attrs.maxAge !== null) {
    var maxAge = Number(attrs.maxAge);
    if (!Number.isFinite(maxAge) || Math.floor(maxAge) !== maxAge) {
      throw new CookieError("cookies/invalid-attr",
        "cookie attr maxAge must be an integer (seconds)");
    }
    parts.push("Max-Age=" + maxAge);
  }
  if (attrs.expires !== undefined && attrs.expires !== null) {
    var d = attrs.expires instanceof Date ? attrs.expires : new Date(attrs.expires);
    if (isNaN(d.getTime())) {
      throw new CookieError("cookies/invalid-attr",
        "cookie attr expires must be a Date or parseable date string");
    }
    parts.push("Expires=" + d.toUTCString());
  }
  if (attrs.domain) {
    var dom = _scrubAttr(String(attrs.domain));
    // RFC 6265 §4.1.2.3 + §5.1.3: Domain attribute is a host name.
    // A leading "." is tolerated by browsers (legacy form). Anything
    // else (URLs, paths, spaces, scheme prefixes) makes browsers
    // either ignore the cookie or apply it inconsistently.
    if (!/^\.?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(dom)) {
      throw new CookieError("cookies/invalid-attr",
        "cookie attr domain must be a valid host name " +
        "(letters/digits/dots/hyphens, optional leading dot), got " + JSON.stringify(dom));
    }
    parts.push("Domain=" + dom);
  }
  if (attrs.path !== undefined && attrs.path !== null) {
    parts.push("Path=" + _scrubAttr(String(attrs.path)));
  }
  if (attrs.httpOnly) parts.push("HttpOnly");
  if (attrs.sameSite) {
    var ss = String(attrs.sameSite);
    var ssLow = ss.toLowerCase();
    var ssNorm;
    if      (ssLow === "strict") ssNorm = "Strict";
    else if (ssLow === "lax")    ssNorm = "Lax";
    else if (ssLow === "none")   ssNorm = "None";
    else throw new CookieError("cookies/invalid-attr",
      "cookie attr sameSite must be Strict, Lax, or None");
    parts.push("SameSite=" + ssNorm);
    // SameSite=None requires Secure per spec; force it on so operators
    // don't ship a cookie that browsers silently drop.
    if (ssNorm === "None") attrs = Object.assign({}, attrs, { secure: true });
  }
  if (attrs.secure) parts.push("Secure");
  if (attrs.partitioned) parts.push("Partitioned");
  if (attrs.priority) {
    var p = String(attrs.priority);
    var pLow = p.toLowerCase();
    var pNorm;
    if      (pLow === "low")    pNorm = "Low";
    else if (pLow === "medium") pNorm = "Medium";
    else if (pLow === "high")   pNorm = "High";
    else throw new CookieError("cookies/invalid-attr",
      "cookie attr priority must be Low, Medium, or High");
    parts.push("Priority=" + pNorm);
  }
  return parts.join("; ");
}

// Append a Set-Cookie header preserving any already on the response.
function _appendSetCookie(res, header) {
  if (!res || typeof res.setHeader !== "function") {
    throw new CookieError("cookies/no-set-header",
      "response object has no setHeader (not a Node http.ServerResponse?)");
  }
  var existing;
  if (typeof res.getHeader === "function") existing = res.getHeader("Set-Cookie");
  var arr;
  if (Array.isArray(existing))      arr = existing.slice();
  else if (existing !== undefined)  arr = [existing];
  else                              arr = [];
  arr.push(header);
  res.setHeader("Set-Cookie", arr);
}

function _readCookieFromReq(req, name) {
  if (!req || !req.headers) return null;
  var header = req.headers.cookie;
  if (!header) return null;
  var jar = parse(header);
  return Object.prototype.hasOwnProperty.call(jar, name) ? jar[name] : null;
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, ["vault", "defaults"], "b.cookies");
  var vault = opts.vault || null;
  // Defaults applied on every write unless the per-call attrs override.
  // secure defaults to true: cookies should never be sent in cleartext;
  // operators developing locally over http opt out explicitly.
  var defaults = Object.assign({
    httpOnly: true,
    secure:   true,
    sameSite: "Lax",
    path:     "/",
  }, opts.defaults || {});

  function _mergeAttrs(callerAttrs) {
    return Object.assign({}, defaults, callerAttrs || {});
  }

  function read(req, name)               { return _readCookieFromReq(req, name); }
  function write(res, name, value, attrs) {
    _appendSetCookie(res, serialize(name, value, _mergeAttrs(attrs)));
  }
  function clear(res, name, attrs) {
    // Expire-now cookie. Domain + Path must match the original write
    // for the browser to actually delete it — operators pass the same
    // attrs they used on write (or rely on the same defaults).
    var attrsExp = Object.assign({}, _mergeAttrs(attrs), { maxAge: 0 });
    delete attrsExp.expires;
    _appendSetCookie(res, serialize(name, "", attrsExp));
  }

  function _requireVault() {
    if (!vault || typeof vault.seal !== "function" || typeof vault.unseal !== "function") {
      throw new CookieError("cookies/no-vault",
        "sealed cookies require opts.vault (a value with .seal/.unseal)");
    }
  }

  // Vault.seal returns "vault:<base64>". We strip the constant prefix
  // on the wire to keep cookies short, and re-add it before unseal.
  // Within a vault major version the prefix is stable for the cookie's
  // entire Max-Age window, so this is safe.
  function writeSealed(res, name, value, attrs) {
    _requireVault();
    if (typeof value !== "string") {
      throw new CookieError("cookies/invalid-value",
        "sealed cookie value must be a string before sealing");
    }
    var sealed = vault.seal(value);
    var stripped = sealed.startsWith(C.VAULT_PREFIX)
      ? sealed.substring(C.VAULT_PREFIX.length)
      : sealed;
    write(res, name, stripped, attrs);
  }
  function readSealed(req, name) {
    _requireVault();
    var raw = _readCookieFromReq(req, name);
    if (raw === null) return null;
    try { return vault.unseal(C.VAULT_PREFIX + raw); }
    catch (_e) { return null; }
  }

  return {
    parse:       parse,
    serialize:   function (n, v, a) { return serialize(n, v, _mergeAttrs(a)); },
    read:        read,
    write:       write,
    clear:       clear,
    writeSealed: writeSealed,
    readSealed:  readSealed,
    defaults:    defaults,
  };
}

// parseSafe — threat-detecting inbound-cookie parser. Returns
// { jar, issues } where every detected anomaly surfaces as an issue
// instead of being silently dropped (as the lenient parse() does).
//
// Threat catalog applied to the inbound Cookie header:
//   - Oversized header — total bytes exceed maxHeaderBytes (default 8 KiB).
//   - Oversized pair — name + value exceeds NAME_LENGTH + VALUE_LENGTH cap.
//   - Duplicate cookie name — RFC 6265 last-write-wins is the browser
//     behavior, but two pairs with the same name in one Cookie header
//     usually indicates cookie-tossing (attacker-set parent-domain
//     cookie shadowing the legitimate one).
//   - Malformed pair — missing `=` or empty name.
//   - Forbidden chars in raw header — CR / LF / NUL injected through
//     a downstream proxy.
//   - Empty / non-string input — operator-misuse signal.
//
// Issue shape: { kind, severity: "high"|"warn", snippet, name? }.
//
// Operators wire it through `b.middleware.cookies` (the convenience
// middleware below) or call directly when they want the issues list
// without imposing a request lifecycle.
function parseSafe(cookieHeader, opts) {
  opts = opts || {};
  var maxHeaderBytes = opts.maxHeaderBytes || C.BYTES.kib(8);
  var maxNameBytes   = opts.maxNameBytes   || MAX_NAME_LENGTH;
  var maxValueBytes  = opts.maxValueBytes  || MAX_VALUE_LENGTH;

  if (typeof cookieHeader !== "string") {
    return {
      jar:    {},
      issues: [{ kind: "bad-input", severity: "high",
                 snippet: "cookie header is not a string" }],
    };
  }
  if (cookieHeader.length === 0) return { jar: {}, issues: [] };

  var issues = [];
  var jar = Object.create(null);
  var seen = Object.create(null);

  if (Buffer.byteLength(cookieHeader, "utf8") > maxHeaderBytes) {
    issues.push({
      kind: "header-cap", severity: "high",
      snippet: "Cookie header " + cookieHeader.length + " bytes exceeds " +
               "maxHeaderBytes " + maxHeaderBytes,
    });
    return { jar: jar, issues: issues };
  }
  for (var hi = 0; hi < cookieHeader.length; hi += 1) {
    var ch = cookieHeader.charCodeAt(hi);
    if (ch === 0x0D || ch === 0x0A || ch === 0x00) {                             // allow:raw-byte-literal — CR / LF / NUL forbidden in cookie header
      issues.push({
        kind: "header-control-byte", severity: "high",
        snippet: "Cookie header contains CR / LF / NUL — proxy-side " +
                 "header injection vector",
      });
      return { jar: jar, issues: issues };
    }
  }

  var pairs = cookieHeader.split(/;\s*/);
  for (var i = 0; i < pairs.length; i += 1) {
    var pair = pairs[i];
    if (!pair) continue;
    var eq = pair.indexOf("=");
    if (eq < 0) {
      issues.push({
        kind: "pair-malformed", severity: "warn",
        snippet: "cookie pair " + JSON.stringify(pair) + " missing `=`",
      });
      continue;
    }
    var k = pair.slice(0, eq).trim();
    if (!k) {
      issues.push({
        kind: "pair-empty-name", severity: "warn",
        snippet: "cookie pair has empty name",
      });
      continue;
    }
    var v = pair.slice(eq + 1).trim();
    if (v.length >= 2 && v.charAt(0) === '"' && v.charAt(v.length - 1) === '"') {
      v = v.slice(1, -1);
    }
    try { v = decodeURIComponent(v); }
    catch (_e) { /* malformed encoding — keep raw */ }

    if (Buffer.byteLength(k, "utf8") > maxNameBytes) {
      issues.push({
        kind: "name-cap", severity: "high", name: k,
        snippet: "cookie name exceeds maxNameBytes " + maxNameBytes,
      });
      continue;
    }
    if (Buffer.byteLength(v, "utf8") > maxValueBytes) {
      issues.push({
        kind: "value-cap", severity: "high", name: k,
        snippet: "cookie `" + k + "` value exceeds maxValueBytes " +
                 maxValueBytes,
      });
      continue;
    }
    if (seen[k]) {
      issues.push({
        kind: "duplicate-name", severity: "high", name: k,
        snippet: "cookie name `" + k + "` appears more than once — " +
                 "browser last-write-wins; cookie-tossing class " +
                 "(parent-domain cookie shadowing the legitimate one)",
      });
    }
    seen[k] = true;
    jar[k] = v;
  }
  return { jar: jar, issues: issues };
}

module.exports = {
  create:       create,
  parse:        parse,
  parseSafe:    parseSafe,
  serialize:    serialize,
  CookieError:  CookieError,
};

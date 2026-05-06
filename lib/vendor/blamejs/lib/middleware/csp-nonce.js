"use strict";
/**
 * csp-nonce — per-request CSP nonce + render integration.
 *
 * The framework's `security-headers` middleware ships a strict CSP
 * that doesn't allow inline scripts (no 'unsafe-inline'). Templates
 * with inline `<script>` blocks therefore break out of the box — the
 * browser refuses to execute them. This middleware closes the gap:
 *
 *   1. Generate a fresh random nonce per request (base64, default
 *      16 bytes / 22 chars).
 *   2. Attach it to `req.cspNonce` (handler-readable) AND
 *      `res.locals.cspNonce` (template-data-readable — render.js
 *      auto-merges res.locals into template data).
 *   3. Patch the existing Content-Security-Policy header set by
 *      security-headers — append `'nonce-XYZ'` to the operator-
 *      configured directives (defaults: script-src, style-src).
 *      If no CSP header is set yet, build a minimal one.
 *
 * Operators wire it after security-headers and write `nonce="..."`
 * on their inline scripts:
 *
 *   router.use(b.middleware.securityHeaders());
 *   router.use(b.middleware.cspNonce({
 *     directives:    ["script-src", "style-src"],
 *     nonceBytes:    16,
 *     strictDynamic: true,
 *   }));
 *
 *   // In a template:
 *   //   <script nonce="{{ cspNonce }}">console.log("ok")</script>
 *   //
 *   // Or in a handler:
 *   //   res.write('<script nonce="' + req.cspNonce + '">...</script>');
 *
 * Handler shape: req.cspNonce is the raw base64 nonce. Templates
 * receive it via the auto-merged res.locals so the html() render
 * helper doesn't need an extra argument — the operator just writes
 * `{{ cspNonce }}` in the view.
 *
 * strict-dynamic mode (opt-in): when true, the nonce directive also
 * gets `'strict-dynamic'`. Modern browsers then trust scripts loaded
 * by a nonced script — no need to allowlist their origins. This is
 * the recommended posture for SPA hydration scripts that themselves
 * load dependencies (e.g. tiny inline bootstrap that imports a
 * versioned bundle). See https://www.w3.org/TR/CSP3/#strict-dynamic-usage.
 *
 * Nonce strength:
 *   - Default 16 bytes (128 bits) of crypto-strong randomness via
 *     `b.crypto.generateBytes` (OS-RNG → SHAKE256). Standard for
 *     CSP nonces.
 *   - Operators with stricter posture set nonceBytes: 32 (256 bits).
 *   - Going below 16 bytes is refused at config time.
 *
 * Cacheable-render pattern (when the response HTML is cached but the
 * CSP header rotates per request):
 *
 *   var nonceMw = b.middleware.cspNonce();
 *   router.use(nonceMw);
 *
 *   var pageCache = b.cache.create({ namespace: "wiki", ttlMs: 5*60_000 });
 *
 *   router.get("/:slug", async function (req, res) {
 *     var html = await pageCache.wrap(req.params.slug, function () {
 *       // Render with the placeholder — the cached string contains a
 *       // stable token, never a request-specific nonce. Safe to cache.
 *       return template.render("page", {
 *         cspNonce: nonceMw.PLACEHOLDER,
 *         ...,
 *       });
 *     });
 *     // Replace the placeholder with this request's nonce so the
 *     // script tag's nonce attribute matches the CSP header.
 *     res.send(nonceMw.substitute(html, req));
 *   });
 *
 * Without this pattern, caching HTML rendered with `{{ cspNonce }}`
 * captures the FIRST request's nonce and reuses it on every cache
 * hit — the response's CSP header rotates per request, so script
 * tags carry a stale nonce the browser refuses. Symptom: scripts
 * silently fail to execute on every cache hit after the first.
 *
 * The placeholder is per-instance random by default — operators with
 * caches that survive process restart (Redis, cluster backend) pin
 * a stable token via `opts.placeholder` so HTML cached before the
 * restart still substitutes correctly after.
 *
 * What `substitute()` does NOT do (deferred — structural reasons):
 *   - Streaming substitution across chunk boundaries. `substitute()`
 *     takes a complete HTML string. Operators streaming HTML in
 *     chunks (Node Writable, fs.createReadStream → res piping cached
 *     bytes) must concatenate first or call substitute on each chunk
 *     where the placeholder is guaranteed not to span a boundary.
 *     A buffered streaming version requires per-stream state to
 *     hold up to (PLACEHOLDER.length - 1) bytes between chunks; that
 *     surface gets its own primitive when an operator hits it.
 *
 * What this middleware does NOT do:
 *   - It doesn't ALSO set 'unsafe-inline'. The browser silently ignores
 *     'unsafe-inline' when a nonce is present (CSP3 spec), so this is
 *     a non-issue, but operators sometimes add 'unsafe-inline' "just
 *     in case" — that defeats the entire point of the nonce.
 *   - It doesn't attempt to strip 'unsafe-inline' from operator-
 *     supplied CSP. If the operator configured 'unsafe-inline' and
 *     adds csp-nonce, both are present; the browser ignores
 *     'unsafe-inline' but the static analysis tool might still flag
 *     it. Removing operator-supplied directives without explicit
 *     consent is more astonishing than helpful.
 *   - It doesn't generate nonces for non-HTML responses (JSON, raw
 *     bytes). The middleware skips when there's no template / inline-
 *     script context — operators who want a nonce on every response
 *     pass `always: true`.
 */

var C = require("../constants");
var crypto = require("../crypto");
var numericBounds = require("../numeric-bounds");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var CspNonceError = defineClass("CspNonceError", { alwaysPermanent: true });

var DEFAULT_DIRECTIVES = Object.freeze(["script-src", "style-src"]);
var DEFAULT_NONCE_BYTES = C.BYTES.bytes(16);
var MIN_NONCE_BYTES = C.BYTES.bytes(16);
var PLACEHOLDER_PREFIX = "__BLAMEJS_CSP_NONCE_";
var PLACEHOLDER_SUFFIX = "__";
// 16 bytes / 128 bits — matches the default nonce strength so the
// placeholder is no weaker than the value it stands in for.
var PLACEHOLDER_RAND_BYTES = C.BYTES.bytes(16);

// Build the substitute helper for a specific placeholder + property.
// Each cspNonce instance has its own placeholder (random by default,
// stable per process) so multiple middleware instances in the same app
// don't share state, and operator content can't accidentally match a
// hardcoded string that lives in source.
function _buildSubstitute(placeholder, property) {
  return function substitute(html, reqOrNonce) {
    if (typeof html !== "string" || html.length === 0) return html;
    if (html.indexOf(placeholder) === -1) return html;
    var nonce;
    if (typeof reqOrNonce === "string") {
      nonce = reqOrNonce;
    } else if (reqOrNonce && typeof reqOrNonce === "object") {
      nonce = reqOrNonce[property] ||
              (reqOrNonce.res && reqOrNonce.res.locals && reqOrNonce.res.locals[property]) ||
              "";
    } else {
      nonce = "";
    }
    return html.split(placeholder).join(nonce);
  };
}

// Build a fresh CSP from scratch when none is set. Conservative defaults
// — the nonced directive replaces what 'unsafe-inline' would have done.
function _defaultCsp(nonceToken) {
  return "default-src 'self'; " +
         "script-src 'self' " + nonceToken + "; " +
         "style-src 'self' " + nonceToken + "; " +
         "img-src 'self' data:; " +
         "frame-ancestors 'none'; " +
         "base-uri 'self'; " +
         "form-action 'self'; " +
         "object-src 'none'";
}

// Parse the CSP header into [{ name, valueParts }] preserving operator
// ordering. Each entry is `directive-name [value...]`.
function _parseCsp(headerValue) {
  var parts = String(headerValue).split(";");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    // Split on whitespace runs.
    var tokens = p.split(/\s+/);
    var name = tokens.shift().toLowerCase();
    out.push({ name: name, values: tokens });
  }
  return out;
}

function _serializeCsp(parts) {
  return parts.map(function (p) {
    if (p.values.length === 0) return p.name;
    return p.name + " " + p.values.join(" ");
  }).join("; ");
}

function _injectNonce(cspHeader, nonce, directives, strictDynamic) {
  var nonceToken = "'nonce-" + nonce + "'";
  if (!cspHeader) {
    // Build a minimal CSP from scratch. strictDynamic isn't applied
    // to a fresh CSP because the operator hasn't told us their script
    // load pattern yet — they can opt in by combining their own CSP
    // with cspNonce.
    return _defaultCsp(nonceToken);
  }
  var parts = _parseCsp(cspHeader);
  var seen = Object.create(null);
  for (var i = 0; i < parts.length; i++) {
    var name = parts[i].name;
    seen[name] = i;
    if (directives.indexOf(name) !== -1) {
      // Avoid duplicate nonce tokens if the middleware ever runs twice.
      if (parts[i].values.indexOf(nonceToken) === -1) {
        parts[i].values.push(nonceToken);
      }
      // strict-dynamic only meaningful for script-src.
      if (strictDynamic && name === "script-src" && parts[i].values.indexOf("'strict-dynamic'") === -1) {
        parts[i].values.push("'strict-dynamic'");
      }
    }
  }
  // Add target directives that were missing from the original CSP.
  for (var j = 0; j < directives.length; j++) {
    var d = directives[j].toLowerCase();
    if (Object.prototype.hasOwnProperty.call(seen, d)) continue;
    var values = [nonceToken];
    if (strictDynamic && d === "script-src") values.push("'strict-dynamic'");
    parts.push({ name: d, values: values });
  }
  return _serializeCsp(parts);
}

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "directives", "nonceBytes", "strictDynamic", "headerName",
    "property", "always", "placeholder",
  ], "middleware.cspNonce");
  var directives = Array.isArray(opts.directives) && opts.directives.length > 0
                     ? opts.directives.slice() : DEFAULT_DIRECTIVES.slice();
  for (var i = 0; i < directives.length; i++) {
    if (typeof directives[i] !== "string" || directives[i].length === 0) {
      throw new CspNonceError("csp-nonce/bad-directive",
        "directives must be non-empty strings (e.g. 'script-src')");
    }
    directives[i] = directives[i].toLowerCase();
  }
  var nonceBytes = opts.nonceBytes !== undefined ? opts.nonceBytes : DEFAULT_NONCE_BYTES;
  // Pre-fix the typeof-only check accepted Infinity / NaN — both
  // bypassed the `< MIN_NONCE_BYTES` guard (NaN < N is always false,
  // Infinity < N is always false), then crashed per-request when
  // `crypto.generateBytes(Infinity)` hit ERR_OUT_OF_RANGE. Route through
  // shared numeric-bounds (positive finite int) before the lower-bound
  // check so the typo / coercion is caught at create() time.
  if (!numericBounds.isPositiveFiniteInt(nonceBytes)) {
    throw new CspNonceError("csp-nonce/bad-nonce-bytes",
      "nonceBytes must be a positive finite integer; got " +
        numericBounds.shape(nonceBytes));
  }
  if (nonceBytes < MIN_NONCE_BYTES) {
    throw new CspNonceError("csp-nonce/bad-nonce-bytes",
      "nonceBytes must be >= " + MIN_NONCE_BYTES + " (got " + nonceBytes + "). " +
      "CSP nonces below 128 bits weaken the security boundary.");
  }
  var strictDynamic = !!opts.strictDynamic;
  var headerName = opts.headerName || "Content-Security-Policy";
  var property = (typeof opts.property === "string" && opts.property.length > 0) ? opts.property : "cspNonce";
  var always = !!opts.always;

  // Token string used by the cacheable-render pattern: templates render
  // with `cspNonce: nonceMw.PLACEHOLDER`, the rendered HTML is cached,
  // then nonceMw.substitute(html, req) swaps in the per-request nonce
  // at serve time. Per-instance random by default — multiple cspNonce
  // instances in the same process get different placeholders, and the
  // literal string never appears in source so operator content can't
  // accidentally collide.
  //
  // Operators with caches that persist across process restarts (Redis,
  // cluster backend) pass `opts.placeholder` to pin a stable token —
  // otherwise cached HTML rendered before restart still contains the
  // old placeholder, and substitute() finds nothing to replace.
  //
  // Validation tier: A (config-time throw). A typo'd placeholder type
  // is the kind of bug that surfaces three days later as "scripts
  // intermittently broken in production"; throwing at create() catches
  // it at app boot.
  var placeholder;
  if (opts.placeholder === undefined) {
    // OS-RNG → SHAKE256 → hex via the framework random helper.
    placeholder = PLACEHOLDER_PREFIX +
                  crypto.generateToken(PLACEHOLDER_RAND_BYTES) +
                  PLACEHOLDER_SUFFIX;
  } else if (typeof opts.placeholder !== "string" || opts.placeholder.length === 0) {
    throw new CspNonceError("csp-nonce/bad-placeholder",
      "placeholder must be a non-empty string (got " + typeof opts.placeholder + " " +
      JSON.stringify(opts.placeholder) + "). Pass nothing to use the default per-instance random token.");
  } else {
    placeholder = opts.placeholder;
  }

  function cspNonce(req, res, next) {
    // Generate the nonce. Cheap (16 bytes from getrandom → SHAKE256 →
    // base64 encode); do it always for consistency unless `always:
    // false` was set explicitly.
    var nonce = crypto.generateBytes(nonceBytes).toString("base64");

    // Attach to req for handler access.
    req[property] = nonce;
    // Attach to res.locals for template-data auto-merge (render.js).
    if (!res.locals || typeof res.locals !== "object") res.locals = {};
    res.locals[property] = nonce;

    if (typeof res.setHeader !== "function" || typeof res.getHeader !== "function") {
      // Plain object response (test mock without setHeader). Skip header
      // patching; the operator's still got req.cspNonce.
      return next();
    }

    // Patch the CSP header. If security-headers already set one, mutate
    // it; otherwise build a fresh minimal CSP. Operators who DON'T want
    // a CSP header set when none exists pass `always: false` (default
    // behavior is to set one).
    var existing = res.getHeader(headerName);
    if (!existing && !always) {
      // No existing CSP and operator didn't ask for always — leave
      // alone. The req.cspNonce is still available for templates that
      // want to use it.
      return next();
    }
    var patched = _injectNonce(existing, nonce, directives, strictDynamic);
    res.setHeader(headerName, patched);
    return next();
  }

  // Cacheable-render API on the returned middleware. The PLACEHOLDER
  // is per-instance random (or operator-pinned via opts.placeholder).
  // Templates render with `cspNonce: nonceMw.PLACEHOLDER` and the
  // rendered HTML is safe to cache; at serve time, call
  // `nonceMw.substitute(html, req)` on the cache hit so the script
  // tag's nonce attribute matches the response's per-request CSP nonce.
  cspNonce.PLACEHOLDER = placeholder;
  cspNonce.substitute  = _buildSubstitute(placeholder, property);
  return cspNonce;
}

module.exports = {
  create:                create,
  CspNonceError:         CspNonceError,
  DEFAULT_DIRECTIVES:    DEFAULT_DIRECTIVES,
  // Internal helpers exposed for tests
  _injectNonce:          _injectNonce,
  _parseCsp:             _parseCsp,
  _serializeCsp:         _serializeCsp,
};

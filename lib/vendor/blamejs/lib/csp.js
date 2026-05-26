"use strict";
/**
 * @module     b.csp
 * @nav        Security
 * @title      CSP3 builder
 * @order      150
 * @slug       csp
 *
 * @card
 *   Content Security Policy Level 3 header builder. Composable per-
 *   directive surface with Trusted Types defaults and nonce/hash
 *   helpers. Operators wire the resulting header value into
 *   b.middleware.securityHeaders via the `csp` opt.
 *
 * @intro
 *   Content Security Policy Level 3 (W3C CSP3 / candidate
 *   recommendation 2024-09) directive builder. The framework's
 *   b.middleware.securityHeaders module ships a strict default CSP;
 *   this module exposes the per-directive surface so operators can
 *   build out a policy by composition without hand-concatenating
 *   strings (which is the failure mode behind most CSP-bypass
 *   incidents — a missing `'self'`, an accidental `'unsafe-inline'`,
 *   or quoting that the UA silently ignores).
 *
 *   Posture:
 *     - Refuses `'unsafe-inline'` / `'unsafe-eval'` / `'unsafe-hashes'`
 *       in any script-* directive unless explicitly acknowledged via
 *       `acknowledgeUnsafe: true` with a documented reason. The CSP3
 *       spec defines these as no-ops when `'strict-dynamic'` is
 *       present, but UAs that haven't shipped strict-dynamic full
 *       support still honor the unsafe keywords — refusing at builder
 *       time prevents shipping an unintentional bypass.
 *     - Defaults `require-trusted-types-for 'script'` + the named
 *       Trusted Types policy "default" when operators wire any
 *       script-* source (Trusted Types is the strongest defense
 *       against DOM-XSS available in browsers today).
 *     - Refuses `data:` in img-src / media-src / font-src unless the
 *       operator explicitly opts in (data: URLs sidestep most CSP
 *       defenses and are a common XSS pivot).
 *     - Refuses `https:` / `*` as a source in any directive (catch-all
 *       sources defeat the principle of least privilege).
 *
 *   v0.10.16 light-up: builder + nonce helper + hash helper. Trusted
 *   Types policy declaration helper. CSP-report-uri / report-to wiring
 *   composes with b.middleware.cspReport (existing).
 *
 * Spec citations:
 *   - W3C CSP Level 3 (CR 2024-09)
 *   - W3C Trusted Types (CR 2023-05)
 *   - Reporting API Level 1 (W3C 2024)
 */
var nodeCrypto   = require("node:crypto");
var validateOpts = require("./validate-opts");
var bCrypto      = require("./crypto");
var { defineClass } = require("./framework-error");

var CspError = defineClass("CspError", { alwaysPermanent: true });

// Directives that participate in script execution — operator-facing
// keyword discipline only applies here (refuse 'unsafe-*' unless
// acknowledgeUnsafe is set).
var SCRIPT_DIRECTIVES = ["script-src", "script-src-elem", "script-src-attr",
                         "style-src", "style-src-elem", "style-src-attr",
                         "worker-src", "frame-src", "child-src"];

var ALL_DIRECTIVES = [
  "default-src", "script-src", "script-src-elem", "script-src-attr",
  "style-src", "style-src-elem", "style-src-attr",
  "img-src", "media-src", "font-src", "connect-src", "object-src",
  "frame-src", "child-src", "worker-src", "fenced-frame-src",
  "manifest-src", "prefetch-src",
  "form-action", "frame-ancestors", "navigate-to", "base-uri", "sandbox",
  "webrtc", "report-to", "report-uri",
  "require-trusted-types-for", "trusted-types",
  "upgrade-insecure-requests", "block-all-mixed-content",
];

var UNSAFE_KEYWORDS = ["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'"];
var CATCH_ALL_SOURCES = ["*", "https:"];

/**
 * @primitive b.csp.build
 * @signature b.csp.build(directives, opts?)
 * @since     0.10.16
 * @status    stable
 * @compliance soc2, gdpr
 * @related   b.middleware.securityHeaders, b.csp.nonce, b.csp.hash
 *
 * Build a CSP3 header value from a per-directive object. Each key is
 * a CSP directive name; each value is an array of sources (strings).
 * Returns a single string ready for `Content-Security-Policy:` or
 * `Content-Security-Policy-Report-Only:`.
 *
 * @opts
 *   {
 *     acknowledgeUnsafe?:    boolean,   // default false — refuses 'unsafe-*' otherwise
 *     allowDataImages?:      boolean,   // default false — refuses data: in img-src/media-src/font-src
 *     trustedTypesPolicies?: string[],  // policy names allowed by trusted-types directive
 *     requireTrustedTypes?:  boolean,   // default true when any script-* is set
 *   }
 *
 * @example
 *   var policy = b.csp.build({
 *     "default-src":           ["'self'"],
 *     "script-src":            ["'self'", "'nonce-" + req.cspNonce + "'"],
 *     "style-src":             ["'self'"],
 *     "img-src":               ["'self'"],
 *     "connect-src":           ["'self'"],
 *     "frame-ancestors":       ["'none'"],
 *     "base-uri":              ["'self'"],
 *     "form-action":           ["'self'"],
 *     "object-src":            ["'none'"],
 *     "report-to":             ["default"],
 *   }, { trustedTypesPolicies: ["default", "app-sanitizer"] });
 *   res.setHeader("Content-Security-Policy", policy);
 */
function build(directives, opts) {
  if (!directives || typeof directives !== "object") {
    throw new CspError("csp/bad-directives",
      "csp.build: directives must be an object keyed by CSP directive name");
  }
  opts = opts || {};
  validateOpts(opts, ["acknowledgeUnsafe", "allowDataImages",
                       "trustedTypesPolicies", "requireTrustedTypes"], "csp.build");
  var acknowledgeUnsafe = opts.acknowledgeUnsafe === true;
  var allowDataImages   = opts.allowDataImages   === true;

  var keys = Object.keys(directives);
  var hasScriptDirective = false;
  for (var ki = 0; ki < keys.length; ki += 1) {
    var name = keys[ki];
    if (ALL_DIRECTIVES.indexOf(name) === -1) {
      throw new CspError("csp/unknown-directive",
        "csp.build: '" + name + "' is not a recognized CSP3 directive");
    }
    var values = directives[name];
    if (!Array.isArray(values)) {
      throw new CspError("csp/bad-directive-value",
        "csp.build: directives['" + name + "'] must be an array of source strings");
    }
    if (SCRIPT_DIRECTIVES.indexOf(name) !== -1) hasScriptDirective = true;
    for (var vi = 0; vi < values.length; vi += 1) {
      var src = values[vi];
      if (typeof src !== "string" || src.length === 0) {
        throw new CspError("csp/bad-source",
          "csp.build: directives['" + name + "'][" + vi + "] must be a non-empty string");
      }
      // CR/LF/NUL header-injection rejection.
      if (/[\r\n\0]/.test(src)) {                                                                 // allow:duplicate-regex — CR/LF/NUL header-injection rejection
        throw new CspError("csp/header-injection",
          "csp.build: source '" + src + "' contains CR/LF/NUL");
      }
      if (!acknowledgeUnsafe && SCRIPT_DIRECTIVES.indexOf(name) !== -1 &&
          UNSAFE_KEYWORDS.indexOf(src) !== -1) {
        throw new CspError("csp/unsafe-keyword",
          "csp.build: " + name + " contains " + src + "; pass acknowledgeUnsafe:true with a " +
          "documented justification to allow it (CSP3 §6.2.5.x — unsafe keywords are a " +
          "common XSS bypass surface)");
      }
      if (CATCH_ALL_SOURCES.indexOf(src) !== -1) {
        throw new CspError("csp/catch-all-source",
          "csp.build: " + name + " contains catch-all source '" + src + "'; CSP3 best " +
          "practice refuses these (use an explicit allowlist instead)");
      }
      if (!allowDataImages && (name === "img-src" || name === "media-src" || name === "font-src") &&
          src === "data:") {
        throw new CspError("csp/data-source",
          "csp.build: " + name + " contains 'data:'; pass allowDataImages:true with a " +
          "documented reason (data: URLs sidestep most CSP defenses)");
      }
    }
  }

  // Trusted Types defaults. When operator has any script-* directive
  // and didn't override `requireTrustedTypes`, append the require-
  // trusted-types-for + trusted-types directives.
  var requireTt = opts.requireTrustedTypes !== false && hasScriptDirective &&
                  directives["require-trusted-types-for"] === undefined;
  if (requireTt) {
    directives["require-trusted-types-for"] = ["'script'"];
  }
  if (opts.trustedTypesPolicies && Array.isArray(opts.trustedTypesPolicies) &&
      directives["trusted-types"] === undefined) {
    directives["trusted-types"] = opts.trustedTypesPolicies;
  }

  // Emit in canonical order (ALL_DIRECTIVES order) so operators
  // diffing two policies see structural diffs rather than ordering
  // noise.
  var out = [];
  for (var di = 0; di < ALL_DIRECTIVES.length; di += 1) {
    var d = ALL_DIRECTIVES[di];
    var vals = directives[d];
    if (vals === undefined) continue;
    if (Array.isArray(vals) && vals.length === 0) {
      // Directives like upgrade-insecure-requests accept no value.
      if (d === "upgrade-insecure-requests" || d === "block-all-mixed-content") {
        out.push(d);
        continue;
      }
      continue;
    }
    out.push(d + " " + vals.join(" "));
  }
  return out.join("; ");
}

/**
 * @primitive b.csp.nonce
 * @signature b.csp.nonce(byteLen?)
 * @since     0.10.16
 * @status    stable
 *
 * Generate a CSP3 nonce — base64url-encoded random bytes for use as
 * `'nonce-<value>'` in script-src / style-src. The CSP3 spec
 * recommends at least 128 bits of entropy (16 bytes); this primitive
 * uses 32 bytes by default for a generous margin.
 *
 * @example
 *   req.cspNonce = b.csp.nonce();
 *   res.setHeader("Content-Security-Policy",
 *     b.csp.build({ "script-src": ["'self'", "'nonce-" + req.cspNonce + "'"] }));
 */
function nonce(byteLen) {
  var n = typeof byteLen === "number" ? byteLen : 32;                                              // allow:raw-byte-literal — 256-bit nonce default
  if (!isFinite(n) || n < 16 || n > 64) {                                                          // allow:raw-byte-literal — CSP3 §6.2.x nonce bounds
    throw new CspError("csp/bad-nonce-len",
      "csp.nonce: byteLen must be 16-64 (CSP3 §6.2 recommends ≥16 bytes)");
  }
  return bCrypto.toBase64Url(nodeCrypto.randomBytes(n));
}

/**
 * @primitive b.csp.hash
 * @signature b.csp.hash(scriptBody, alg?)
 * @since     0.10.16
 * @status    stable
 *
 * Compute a CSP3 hash source for an inline script/style. Returns the
 * `'<alg>-<base64>'` token suitable for direct use as a script-src
 * source.
 *
 * @opts
 *   alg?: "sha256" | "sha384" | "sha512"   // default sha384 (matches
 *                                           // b.crypto.sri default)
 *
 * @example
 *   var src = b.csp.hash("console.log('boot');");
 *   // → "'sha384-abcd...'"
 */
function hash(scriptBody, alg) {
  if (typeof scriptBody !== "string" && !Buffer.isBuffer(scriptBody)) {
    throw new CspError("csp/bad-hash-input",
      "csp.hash: scriptBody must be a string or Buffer");
  }
  var algName = alg || "sha384";
  if (algName !== "sha256" && algName !== "sha384" && algName !== "sha512") {
    throw new CspError("csp/bad-hash-alg",
      "csp.hash: alg must be sha256 / sha384 / sha512 (CSP3 §6.2 hash sources)");
  }
  var digest = nodeCrypto.createHash(algName)
    .update(typeof scriptBody === "string" ? Buffer.from(scriptBody, "utf8") : scriptBody)
    .digest("base64");
  return "'" + algName + "-" + digest + "'";
}

module.exports = {
  build:  build,
  nonce:  nonce,
  hash:   hash,
  CspError: CspError,
};

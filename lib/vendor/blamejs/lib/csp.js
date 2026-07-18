// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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
var pick         = require("./pick");
var { defineClass } = require("./framework-error");
// The strict framework defaults the per-route merge derives from. One-
// directional edge: security-headers requires only request-helpers +
// validate-opts, never csp, so this is not a cycle (§9 top-of-file require).
var securityHeaderDefaults = require("./middleware/security-headers");

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

// _parseCspString — split a CSP header value into an ordered
// { directive: [sources] } map. Tolerant reader (defensive tier): a
// malformed base yields whatever directives DO parse. The merge never
// re-validates these base sources (they are the trusted default), so the
// parser only needs to be faithful, not strict. First write wins on a
// duplicate directive (matches UA "honor the first").
function _parseCspString(value) {
  var out = {};
  if (typeof value !== "string") return out;
  var segments = value.split(";");
  for (var i = 0; i < segments.length; i += 1) {
    var tokens = segments[i].trim().split(/\s+/);
    var name = tokens[0];
    if (!name) continue;
    if (Object.prototype.hasOwnProperty.call(out, name)) continue;
    out[name] = tokens.slice(1);
  }
  return out;
}

// _parsePermissionsPolicyString — split a Permissions-Policy header value
// into a { feature: "allowlist" } map plus the feature order, preserving
// each feature's RFC-9651 value-list verbatim ("()" / "*" / "(self ...)").
function _parsePermissionsPolicyString(value) {
  var out = {};
  var order = [];
  if (typeof value !== "string") return { map: out, order: order };
  // Split on the literal comma (linear) — the per-item .trim() below handles
  // the surrounding whitespace, so the prior `/\s*,\s*/` was redundant and
  // ran in O(n^2) on a comma-less run of whitespace (js/polynomial-redos).
  var parts = value.split(",");
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i].trim();
    if (!p) continue;
    var eq = p.indexOf("=");
    if (eq === -1) continue;
    var feature = p.slice(0, eq).trim();
    var allow = p.slice(eq + 1).trim();
    if (!feature) continue;
    if (!Object.prototype.hasOwnProperty.call(out, feature)) order.push(feature);
    out[feature] = allow;
  }
  return { map: out, order: order };
}

// RFC-9651 value-list shape for ONE Permissions-Policy feature value (no
// leading "feature=" — just the allowlist): "*", "()", "self", or a
// parenthesised origin list "(self \"https://x\")". A hostile value with a
// comma / CRLF can't pass (no comma inside, the parens are balanced-only).
var PP_VALUE_RE = /^(?:\*|self|\([^),\r\n]*\))$/;
// Permissions-Policy feature names are RFC-9651 structured-field tokens —
// ASCII lowercase, hyphenated. Reject anything else so a hostile key can't
// inject a comma / CRLF into the header.
var PP_FEATURE_RE = /^[a-z][a-z0-9-]*$/;   // allow:duplicate-regex — generic ASCII lowercase-hyphen token shape; shared shape, distinct domain (Permissions-Policy feature name)

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
      // A CSP source-expression is a single non-whitespace token. The emitter
      // space-joins sources within a directive and ';'-joins directives, so a
      // source containing ';' or ASCII whitespace would inject a brand-new live
      // directive (e.g. "https://x; script-src https://evil") — refuse both.
      if (/[\s;]/.test(src)) {
        throw new CspError("csp/bad-source",
          "csp.build: source '" + src + "' contains whitespace or ';' — a CSP source " +
          "must be a single token (directive-injection defense)");
      }
      // A UA matches CSP source keywords ('unsafe-inline' ...) and scheme
      // sources (https: / data:) ASCII case-INSENSITIVELY (CSP3 §2.3 /
      // §6.7.2). Compare a lowercased copy against the (lowercase) guard sets
      // so a case-variant token ("'Unsafe-Inline'" / "HTTPS:" / "DATA:") can't
      // slip past and be emitted verbatim into a header the browser still
      // honors. The ORIGINAL src is what gets emitted (hosts/paths stay
      // case-preserved); only the guard comparison is normalized.
      var srcLower = src.toLowerCase();
      if (!acknowledgeUnsafe && SCRIPT_DIRECTIVES.indexOf(name) !== -1 &&
          UNSAFE_KEYWORDS.indexOf(srcLower) !== -1) {
        throw new CspError("csp/unsafe-keyword",
          "csp.build: " + name + " contains " + src + "; pass acknowledgeUnsafe:true with a " +
          "documented justification to allow it (CSP3 §6.2.5.x — unsafe keywords are a " +
          "common XSS bypass surface)");
      }
      if (CATCH_ALL_SOURCES.indexOf(srcLower) !== -1) {
        throw new CspError("csp/catch-all-source",
          "csp.build: " + name + " contains catch-all source '" + src + "'; CSP3 best " +
          "practice refuses these (use an explicit allowlist instead)");
      }
      if (!allowDataImages && (name === "img-src" || name === "media-src" || name === "font-src") &&
          srcLower === "data:") {
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

  return _emitCanonical(directives);
}

// Emit a directive map as a CSP header string in canonical (ALL_DIRECTIVES)
// order so operators diffing two policies see structural diffs rather than
// ordering noise. Pure serializer — it does NOT validate sources (build()
// and mergeDirectives() validate before calling it), so a trusted base
// policy round-trips through it untouched.
function _emitCanonical(directives) {
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
  var n = typeof byteLen === "number" ? byteLen : 32;                                              // 256-bit nonce default
  if (!isFinite(n) || n < 16 || n > 64) {                                                          // CSP3 §6.2.x nonce bounds
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

/**
 * @primitive  b.csp.mergeDirectives
 * @signature  b.csp.mergeDirectives(base, additions, opts?)
 * @since      0.15.13
 * @status     stable
 * @related    b.csp.build, b.csp.mergePermissionsPolicy
 *
 * Derive a per-route CSP from a strict base by ADDING hosts to named
 * directives, leaving every other directive exactly as the base. The fix for
 * the "load a third-party SDK on one route" case: take the framework's strict
 * default (pass `base` omitted / `undefined`) and add `https://js.stripe.com`
 * to `script-src` + `frame-src` for the checkout route only, without
 * re-typing the whole policy or relaxing `frame-ancestors` / `object-src` /
 * `base-uri`.
 *
 * Additive only: each `additions[directive]` array is APPENDED (de-duped) to
 * that directive's existing sources; a directive absent from the base is
 * seeded from `default-src` (or `'self'`) first so it never lands wide-open.
 * Only the ADDED sources are validated (CR/LF/NUL, catch-all `*`/`https:`,
 * `data:` in img/media/font, unsafe-* in script directives) — the trusted
 * base round-trips untouched. Returns a policy string for the middleware
 * `csp:` opt. Throws `CspError` on an unknown directive, a hostile directive
 * name, or a rejected added source.
 *
 * @opts
 *   acknowledgeUnsafe:  boolean,   // allow an added 'unsafe-*' in a script directive
 *   allowDataImages:    boolean,   // allow an added data: in img-src/media-src/font-src
 *
 * @example
 *   // Admit Stripe on the checkout route's script + frame directives only.
 *   var routeCsp = b.csp.mergeDirectives(undefined, {
 *     "script-src": ["https://js.stripe.com"],
 *     "frame-src":  ["https://js.stripe.com"],
 *   });
 *   // -> the strict default with those two hosts appended; everything else unchanged
 */
function mergeDirectives(base, additions, opts) {
  var baseString = base === undefined ? securityHeaderDefaults.DEFAULT_CSP : base;
  if (typeof baseString !== "string" || baseString.length === 0) {
    throw new CspError("csp/bad-base",
      "csp.mergeDirectives: base must be a non-empty CSP string (or undefined to " +
      "derive from the framework DEFAULT_CSP)");
  }
  if (!additions || typeof additions !== "object" || Array.isArray(additions)) {
    throw new CspError("csp/bad-additions",
      "csp.mergeDirectives: additions must be an object keyed by CSP directive name, " +
      "each value a non-empty array of source strings to ADD");
  }
  opts = opts || {};
  validateOpts(opts, ["acknowledgeUnsafe", "allowDataImages"], "csp.mergeDirectives");

  var addKeys = Object.keys(additions);
  // Validate directive names (proto-safe) + that each addition is a
  // non-empty array, before touching the base.
  for (var ki = 0; ki < addKeys.length; ki += 1) {
    var nm = addKeys[ki];
    if (pick.isPoisonedKey(nm)) {
      throw new CspError("csp/bad-directive-name",
        "csp.mergeDirectives: '" + nm + "' is not a valid directive name");
    }
    if (ALL_DIRECTIVES.indexOf(nm) === -1) {
      throw new CspError("csp/unknown-directive",
        "csp.mergeDirectives: '" + nm + "' is not a recognized CSP3 directive");
    }
    if (!Array.isArray(additions[nm]) || additions[nm].length === 0) {
      throw new CspError("csp/bad-directive-value",
        "csp.mergeDirectives: additions['" + nm + "'] must be a non-empty array of sources");
    }
  }
  // Validate ONLY the added sources by routing a throwaway additions-only
  // map through build() (reuses every per-source rule). build() may seed
  // Trusted-Types into the copy; we discard its output and keep the original
  // additions for the merge.
  var validationMap = {};
  for (var vk = 0; vk < addKeys.length; vk += 1) validationMap[addKeys[vk]] = additions[addKeys[vk]].slice();
  build(validationMap, { acknowledgeUnsafe: opts.acknowledgeUnsafe === true,
                         allowDataImages: opts.allowDataImages === true,
                         requireTrustedTypes: false });

  var directives = _parseCspString(baseString);
  for (var ai = 0; ai < addKeys.length; ai += 1) {
    var name = addKeys[ai];
    var existing = Object.prototype.hasOwnProperty.call(directives, name)
      ? directives[name].slice()
      : (directives["default-src"] ? directives["default-src"].slice() : ["'self'"]);
    var added = additions[name];
    // A directive value of 'none' MUST stand alone (CSP3 §2.3.1) — appending a
    // host to it emits the malformed "'none' https://x". When merging real
    // sources in, the added sources supersede 'none', so drop it first.
    if (added.length && existing.length === 1 && existing[0] === "'none'") existing = [];
    for (var si = 0; si < added.length; si += 1) {
      if (existing.indexOf(added[si]) === -1) existing.push(added[si]);
    }
    directives[name] = existing;
  }
  return _emitCanonical(directives);
}

/**
 * @primitive  b.csp.mergePermissionsPolicy
 * @signature  b.csp.mergePermissionsPolicy(base, overrides, opts?)
 * @since      0.15.13
 * @status     stable
 * @related    b.csp.mergeDirectives, b.csp.build
 *
 * Derive a per-route Permissions-Policy from a strict base by replacing the
 * allowlist of NAMED features only, leaving every other feature at its `()`
 * deny default. The companion to `mergeDirectives` for the Permissions-Policy
 * header: re-enable `payment` to `(self "https://js.stripe.com")` on the
 * checkout route while `camera` / `microphone` / `geolocation` stay denied.
 *
 * Each override value is validated as an RFC-9651 feature value-list (`*`,
 * `()`, `self`, or a parenthesised origin list) — a value carrying a comma or
 * CR/LF is refused so it can't inject a second feature or a header break. A
 * feature not present in the base is added (opting it in); one present is
 * replaced. Returns a header string for the middleware `permissionsPolicy:`
 * opt. Throws `CspError` on a hostile feature name or a malformed value.
 *
 * @opts
 *   (none)
 *
 * @example
 *   var routePp = b.csp.mergePermissionsPolicy(undefined, {
 *     payment: '(self "https://js.stripe.com")',
 *   });
 *   // -> the strict default with payment re-enabled to that allowlist; all else denied
 */
function mergePermissionsPolicy(base, overrides, opts) {
  var baseString = base === undefined
    ? securityHeaderDefaults.DEFAULT_PERMISSIONS.join(", ")
    : base;
  if (typeof baseString !== "string" || baseString.length === 0) {
    throw new CspError("csp/bad-base",
      "csp.mergePermissionsPolicy: base must be a non-empty Permissions-Policy string " +
      "(or undefined to derive from the framework default)");
  }
  if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) {
    throw new CspError("csp/bad-overrides",
      "csp.mergePermissionsPolicy: overrides must be an object keyed by feature name, " +
      "each value an RFC-9651 allowlist string");
  }
  if (opts !== undefined) validateOpts(opts || {}, [], "csp.mergePermissionsPolicy");

  var parsed = _parsePermissionsPolicyString(baseString);
  var map = parsed.map;
  var order = parsed.order;
  var keys = Object.keys(overrides);
  for (var ki = 0; ki < keys.length; ki += 1) {
    var feature = keys[ki];
    if (pick.isPoisonedKey(feature) ||
        !PP_FEATURE_RE.test(feature)) {                                                          // allow:regex-no-length-cap — anchored token shape (no backtracking); a feature name is a short RFC-9651 token
      throw new CspError("csp/bad-feature-name",
        "csp.mergePermissionsPolicy: '" + feature + "' is not a valid feature name");
    }
    var value = overrides[feature];
    if (typeof value !== "string" || !PP_VALUE_RE.test(value)) {                                  // allow:regex-no-length-cap — anchored alternation (no backtracking); a feature value is a short RFC-9651 value-list
      throw new CspError("csp/bad-feature-value",
        "csp.mergePermissionsPolicy: " + feature + " value must be one of *, (), self, or a " +
        "parenthesised origin list (got " + JSON.stringify(value) + ")");
    }
    if (!Object.prototype.hasOwnProperty.call(map, feature)) order.push(feature);
    map[feature] = value;
  }
  var out = [];
  for (var oi = 0; oi < order.length; oi += 1) out.push(order[oi] + "=" + map[order[oi]]);
  return out.join(", ");
}

module.exports = {
  build:  build,
  mergeDirectives:       mergeDirectives,
  mergePermissionsPolicy: mergePermissionsPolicy,
  nonce:  nonce,
  hash:   hash,
  CspError: CspError,
};

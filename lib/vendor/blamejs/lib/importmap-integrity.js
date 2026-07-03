// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.importmapIntegrity
 * @nav    HTTP
 * @title  Import-Map Integrity
 * @order  175
 *
 * @intro
 *   WICG Import Maps + Subresource Integrity (SRI) extension. When
 *   a page declares `<script type="importmap">`, each mapped module
 *   SHOULD carry an `integrity` hash so the browser refuses to
 *   execute the module if the bytes don't match.
 *
 *   `b.importmapIntegrity.build({ specifiers, sha256, sha384,
 *   sha512 })` hashes each operator-supplied module body and emits
 *   the `<script type="importmap">` JSON with an `integrity` map
 *   alongside the `imports` map. Composes existing `b.crypto.sri`.
 *
 * @card
 *   WICG Import Maps + SRI integrity builder. Emits importmap JSON with module-body SHA-384 hashes so browsers refuse unauthenticated module bytes.
 */

var validateOpts = require("./validate-opts");
var bCrypto      = require("./crypto");
var safeJson     = require("./safe-json");
var { defineClass } = require("./framework-error");

var ImportmapError = defineClass("ImportmapError", { alwaysPermanent: true });

/**
 * @primitive b.importmapIntegrity.build
 * @signature b.importmapIntegrity.build(opts)
 * @since     0.10.16
 * @status    stable
 *
 * Build an import-map JSON shape `{ imports, integrity }` per WICG
 * Import-Maps-SRI. Each module body is hashed with `opts.hash`
 * (default sha384 per current SRI convention).
 *
 * @opts
 *   modules:    { "<specifier>": { url, body: Buffer|string } },
 *   hash:       "sha256"|"sha384"|"sha512",   // default sha384
 *
 * @example
 *   var im = b.importmapIntegrity.build({
 *     modules: {
 *       "@org/lib": { url: "/static/lib.js", body: fileBytes },
 *     },
 *   });
 *   // Embed with the <script>-safe helper — NEVER raw JSON.stringify, which
 *   // does not escape "</script>" in a module url and breaks out of the tag.
 *   res.end(b.importmapIntegrity.scriptTag(im));
 */
function build(opts) {
  opts = validateOpts.requireObject(opts, "importmapIntegrity.build",
    ImportmapError, "importmap/bad-opts");
  validateOpts(opts, ["modules", "hash"], "importmapIntegrity.build");
  if (!opts.modules || typeof opts.modules !== "object" || Array.isArray(opts.modules)) {
    throw new ImportmapError("importmap/no-modules",
      "build: opts.modules must be a non-array object");
  }
  var hash = opts.hash || "sha384";
  if (hash !== "sha256" && hash !== "sha384" && hash !== "sha512") {
    throw new ImportmapError("importmap/bad-hash",
      "build: hash must be sha256 / sha384 / sha512");
  }
  var imports = {};
  var integrity = {};
  var keys = Object.keys(opts.modules);
  for (var i = 0; i < keys.length; i += 1) {
    var spec = keys[i];
    var mod = opts.modules[spec];
    if (!mod || typeof mod.url !== "string") {
      throw new ImportmapError("importmap/bad-module",
        "build: modules['" + spec + "'].url must be a string");
    }
    if (!Buffer.isBuffer(mod.body) && typeof mod.body !== "string") {
      throw new ImportmapError("importmap/bad-module",
        "build: modules['" + spec + "'].body must be a Buffer or string");
    }
    imports[spec] = mod.url;
    // Compose b.crypto.sri — returns the canonical SRI string
    // (e.g. `sha384-<base64>`). b.crypto.sri takes its hash from
    // `opts.algorithm`, not a positional arg.
    integrity[mod.url] = bCrypto.sri(mod.body, { algorithm: hash });
  }
  return { imports: imports, integrity: integrity };
}

/**
 * @primitive b.importmapIntegrity.scriptTag
 * @signature b.importmapIntegrity.scriptTag(importmap, opts?)
 * @since     0.15.14
 * @status    stable
 * @related   b.importmapIntegrity.build, b.safeJson.stringifyForScript
 *
 * Render an import-map object (from `build`) as a ready-to-embed
 * `<script type="importmap">…</script>` tag using the `<script>`-safe
 * JSON serializer. Raw `JSON.stringify` does not escape `</script>` in a
 * module url, so concatenating it into the page lets a `</script>` in a
 * url close the element and inject markup — this escapes `< > &` (and the
 * U+2028 / U+2029 separators) so no url can break out.
 *
 * @opts
 *   nonce:  string,   // CSP nonce added as nonce="…" on the <script>
 *
 * @example
 *   res.end(b.importmapIntegrity.scriptTag(im, { nonce: req.cspNonce }));
 */
function scriptTag(importmap, opts) {
  opts = opts || {};
  var nonceAttr = "";
  if (typeof opts.nonce === "string" && opts.nonce.length > 0) {
    // The nonce is operator-supplied (a CSP per-request token); reject any
    // value that could itself break the attribute rather than escape it.
    if (/[^A-Za-z0-9+/=_-]/.test(opts.nonce)) {
      throw new ImportmapError("importmap/bad-nonce",
        "scriptTag: opts.nonce must be a base64/token string");
    }
    nonceAttr = ' nonce="' + opts.nonce + '"';
  }
  return '<script type="importmap"' + nonceAttr + '>' +
    safeJson.stringifyForScript(importmap) + "</script>";
}

module.exports = {
  build:           build,
  scriptTag:       scriptTag,
  ImportmapError:  ImportmapError,
};

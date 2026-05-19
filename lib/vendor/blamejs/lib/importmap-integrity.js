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
 *   res.end("<script type=\"importmap\">" + JSON.stringify(im) + "</script>");
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

module.exports = {
  build:           build,
  ImportmapError:  ImportmapError,
};

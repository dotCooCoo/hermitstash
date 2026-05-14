"use strict";
/**
 * @module b.bundler
 * @nav    Tools
 * @title  Bundler
 *
 * @intro
 *   Client-side asset bundler — produces content-hashed
 *   `dist/<name>.<hash>.<ext>` files plus a `manifest.json` mapping
 *   logical name to hashed filename. Designed to drop into a static
 *   server (`b.static`) so cache-busting lives at the filename layer
 *   and HTML can long-cache hashed paths.
 *
 *   No-build-step fallback: the default `engine.passthrough` reads
 *   each entry from disk verbatim, hashes it, and writes the hashed
 *   copy. Operators with no module-graph need ship their source files
 *   directly through the bundler and skip the toolchain entirely.
 *
 *   Module-graph / tree-shake / minify / sourcemaps: operators supply
 *   esbuild (devDependency, never vendored) and adapt it via
 *   `engine.fromEsbuild(esbuild, opts)` — the framework owns the
 *   integration seam, the operator brings the heavy machinery. The
 *   ~10 MB esbuild-wasm blob is intentionally not vendored.
 *
 *   Hashes are SHA3-512, first 16 hex chars by default (operators
 *   override via `opts.hashLen` between 4 and 64). Source maps written
 *   by an engine land as `<hashed>.<ext>.map` siblings.
 *
 *   Watch mode: `bundler.watch(callback)` arms `nodeFs.watch` on each
 *   entry's directory, debounces bursts via `opts.graceMs` (default
 *   100 ms), and rebuilds the entire entry set on change.
 *
 *   Manifest format:
 *
 *     { "app": "app.4a8c2f1d9e3b7062.js", "styles": "styles.b29f1e7c.css" }
 *
 *   Integrates with `lib/static.js`: serve `outdir` as a static
 *   directory; `b.static`'s hashed-path detection sets long-cache
 *   headers on files that look hashed, and `integrity()` reads the
 *   manifest to emit Subresource Integrity attributes.
 *
 * @card
 *   Client-side asset bundler — produces content-hashed `dist/<name>.<hash>.<ext>` files plus a `manifest.json` mapping logical name to hashed filename.
 */

var nodePath = require("path");
var nodeFs = require("fs");
var bCrypto = require("./crypto");
var atomicFile = require("./atomic-file");
var logModule = require("./log");
var numericBounds = require("./numeric-bounds");
var safeJson = require("./safe-json");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var BundlerError = defineClass("BundlerError", { alwaysPermanent: true });
var bootLog = logModule.boot("bundler");

// Default content-hash length: 16 hex chars (8 bytes of SHA3-512). Long
// enough that collision probability is negligible for asset cache busting,
// short enough to keep generated filenames readable.
var DEFAULT_HASH_LEN = 0x10;
var MIN_HASH_LEN     = 0x4;
var MAX_HASH_LEN     = 0x40;
var DEFAULT_GRACE_MS = 100;

function _hashContent(buf, hexLen) {
  // SHA3-512 → take the first hexLen hex chars. Same family as the
  // framework's other content fingerprints (no SHA-256 for new code).
  return bCrypto.sha3Hash(buf).slice(0, hexLen);
}

function _hashedName(baseName, hash, ext) {
  return baseName + "." + hash + ext;
}

// outDir mode is 0o755 (world-readable) because the bundler emits
// assets a public HTTP server reads. Other framework dirs default to
// 0o700 via atomicFile.ensureDir.
function _ensureOutDir(p) {
  try { atomicFile.ensureDir(p, 0o755); }
  catch (e) {
    if (e && e.code !== "EEXIST") {
      throw new BundlerError("bundler/mkdir-failed",
        "could not create outdir '" + p + "': " + ((e && e.message) || String(e)));
    }
  }
}

function _validateEntries(entries) {
  if (!entries || typeof entries !== "object" || Array.isArray(entries)) {
    throw new BundlerError("bundler/no-entries",
      "bundler.create requires opts.entries (a { name: path } map)");
  }
  var names = Object.keys(entries);
  if (names.length === 0) {
    throw new BundlerError("bundler/no-entries",
      "bundler.create: opts.entries map must have at least one entry");
  }
  // Reject names with path separators or '..' so operator-supplied
  // logical names can't escape the outdir on write.
  for (var i = 0; i < names.length; i++) {
    var n = names[i];
    if (typeof n !== "string" || n.length === 0 ||
        /[\\/]/.test(n) || n === ".." || n === ".") {
      throw new BundlerError("bundler/bad-entry-name",
        "entry name '" + n + "' must be a non-empty string without path separators");
    }
    var p = entries[n];
    if (typeof p !== "string" || p.length === 0) {
      throw new BundlerError("bundler/bad-entry-path",
        "entry '" + n + "' must map to a non-empty source path");
    }
  }
}

// ---- Engine surface ----
//
// Engines transform an entry's content before the cache-busting / hash
// step. The default `passthrough` engine reads the file verbatim — same
// behavior every pre-v0.6.44 caller got. Operators wanting ESM
// module-graph bundling supply esbuild (or any compatible tool) and
// adapt it via `engine.fromEsbuild(esbuild, opts)`.
var engine = {
  passthrough: {
    name: "passthrough",
    transform: async function (_entryPath, contentBuf) {
      return { content: contentBuf, sourceMap: null };
    },
  },

  fromEsbuild: function (esbuild, esbuildOpts) {
    if (!esbuild || typeof esbuild.build !== "function") {
      throw new BundlerError("bundler/bad-engine",
        "engine.fromEsbuild: pass the esbuild module (require('esbuild')); " +
        "got " + typeof esbuild);
    }
    var baseOpts = Object.assign({
      bundle:     true,
      write:      false,
      format:     "esm",
      platform:   "browser",
      logLevel:   "silent",
    }, esbuildOpts || {});
    return {
      name: "esbuild",
      transform: async function (entryPath, _contentBuf) {
        var rv = await esbuild.build(Object.assign({}, baseOpts, {
          entryPoints: [entryPath],
        }));
        // esbuild { write: false } returns { outputFiles: [{ path, contents }, ...] }.
        // For a single entry without sourcemaps we get one file; with
        // sourcemap we get the .js + .js.map. Match by extension.
        var outFiles = (rv && rv.outputFiles) || [];
        var jsLike = null;
        var map    = null;
        for (var i = 0; i < outFiles.length; i++) {
          var f = outFiles[i];
          if (/\.map$/.test(f.path)) map = f.text;
          else jsLike = f;
        }
        if (!jsLike) {
          throw new BundlerError("bundler/engine-empty",
            "esbuild engine returned no output for " + entryPath);
        }
        return {
          content:   Buffer.from(jsLike.contents),
          sourceMap: map,
        };
      },
    };
  },
};

function _validateEngine(eng) {
  if (eng == null) return engine.passthrough;
  if (typeof eng !== "object") {
    throw new BundlerError("bundler/bad-engine",
      "opts.engine must be an object with { name, transform }, got " + typeof eng);
  }
  if (typeof eng.transform !== "function") {
    throw new BundlerError("bundler/bad-engine",
      "opts.engine.transform must be a function (entryPath, contentBuf) → " +
      "{ content, sourceMap? }");
  }
  if (typeof eng.name !== "string" || eng.name.length === 0) {
    throw new BundlerError("bundler/bad-engine",
      "opts.engine.name must be a non-empty string");
  }
  return eng;
}

/**
 * @primitive b.bundler.create
 * @signature b.bundler.create(opts)
 * @since     0.4.0
 * @status    stable
 * @related   b.static.serve
 *
 * Build a content-hashed asset pipeline for a fixed set of named
 * entries. The returned object exposes `build()` (one-shot rebuild,
 * resolves to `{ outputs, manifestPath, manifest, durationMs }`),
 * `watch(callback)` (arm `nodeFs.watch` and debounce-rebuild on change),
 * and `close()` (drop watchers and pending timers).
 *
 * Throws `BundlerError` at config time on missing / malformed entries,
 * missing `outdir`, an out-of-range `hashLen`, or an engine that does
 * not implement `{ name, transform }`.
 *
 * @opts
 *   entries:  { [name: string]: string },   // logical name → source path
 *   outdir:   string,                        // dist directory (created if missing, mode 0o755)
 *   cwd:      string,                        // resolves relative entries / outdir; defaults to process.cwd()
 *   engine:   { name: string, transform: async (entryPath, contentBuf) => { content, sourceMap?, imports? } },
 *                                            // defaults to engine.passthrough
 *   manifest: string | false,                // manifest filename ("manifest.json"), or false to skip
 *   hash:     boolean,                       // emit <name>.<hash>.<ext>; default true
 *   hashLen:  number,                        // hex chars in the hash, 4..64; default 16
 *   graceMs:  number,                        // watch-mode debounce ms; default 100
 *   log:      object,                        // structured logger ({ info, warn, error })
 *
 * @example
 *   var bundler = b.bundler.create({
 *     entries: { app: "./src/app.js", styles: "./src/styles.css" },
 *     outdir:  "./public/dist",
 *     hashLen: 16,
 *   });
 *
 *   // bundler.build() returns a Promise resolving to:
 *   //   { outputs: [...], manifest: { app: "app.<hash>.js", styles: "styles.<hash>.css" },
 *   //     manifestPath: ".../public/dist/manifest.json", durationMs: <number> }
 *
 *   // Watch mode — rebuild on edits.
 *   bundler.watch(function (err, result) {
 *     if (err) return;
 *     // result.manifest is the freshly-written name→hashed-filename map
 *   });
 *
 *   // Operator-supplied esbuild for module-graph + tree-shake + minify.
 *   // var esbuild = require("esbuild");
 *   // var modGraph = b.bundler.create({
 *   //   entries: { app: "./src/app.js" },
 *   //   outdir:  "./public/dist",
 *   //   engine:  b.bundler.engine.fromEsbuild(esbuild, { minify: true, sourcemap: true }),
 *   // });
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "entries", "outdir", "cwd", "engine",
    "manifest", "hash", "hashLen", "graceMs", "log",
    "_watch", "_setTimeout", "_clearTimeout",
  ], "b.bundler");
  _validateEntries(opts.entries);
  validateOpts.requireNonEmptyString(opts.outdir, "bundler.create: opts.outdir", BundlerError, "bundler/no-outdir");
  var engineImpl = _validateEngine(opts.engine);

  var entries     = Object.assign({}, opts.entries);
  var cwd         = opts.cwd || process.cwd();
  var outdir      = nodePath.isAbsolute(opts.outdir) ? opts.outdir : nodePath.resolve(cwd, opts.outdir);
  var manifestName = (opts.manifest === false || opts.manifest === null)
    ? null
    : (typeof opts.manifest === "string" && opts.manifest.length > 0
        ? opts.manifest
        : "manifest.json");
  var hashOn   = opts.hash !== false;
  var hashLen  = DEFAULT_HASH_LEN;
  if (opts.hashLen !== undefined) {
    if (!numericBounds.isPositiveFiniteInt(opts.hashLen) ||
        opts.hashLen < MIN_HASH_LEN || opts.hashLen > MAX_HASH_LEN) {
      throw new BundlerError("bundler/bad-hash-len",
        "bundler.create: opts.hashLen must be a positive finite integer " +
        "between " + MIN_HASH_LEN + " and " + MAX_HASH_LEN +
        "; got " + numericBounds.shape(opts.hashLen));
    }
    hashLen = opts.hashLen;
  }
  var log      = opts.log || null;

  // Test seam: tests pass a fake watcher so we don't actually nodeFs.watch
  var watchFn = opts._watch || function (dirOrFile, wopts, listener) {
    return nodeFs.watch(dirOrFile, wopts, listener);
  };
  var setTimeoutFn  = opts._setTimeout  || setTimeout;
  var clearTimeoutFn = opts._clearTimeout || clearTimeout;
  numericBounds.requireNonNegativeFiniteIntIfPresent(opts.graceMs,
    "bundler.create: opts.graceMs", BundlerError, "bundler/bad-grace-ms");
  var graceMs = opts.graceMs !== undefined ? opts.graceMs : DEFAULT_GRACE_MS;

  var watchers      = [];
  var debounceTimer = null;
  var watching      = false;

  function _resolveEntry(p) {
    return nodePath.isAbsolute(p) ? p : nodePath.resolve(cwd, p);
  }

  var _logVia = logModule.makeViaOrFallback(log, bootLog);

  async function build() {
    var t0 = Date.now();
    _ensureOutDir(outdir);

    var outputs = [];
    var manifest = {};
    var names = Object.keys(entries);

    for (var i = 0; i < names.length; i++) {
      var name = names[i];
      var entryPath = _resolveEntry(entries[name]);
      var ext = nodePath.extname(entryPath);
      var raw;
      try { raw = nodeFs.readFileSync(entryPath); }
      catch (e) {
        throw new BundlerError("bundler/read-failed",
          "could not read entry '" + name + "' at " + entryPath +
          ": " + ((e && e.message) || String(e)));
      }
      var transformed;
      try { transformed = await engineImpl.transform(entryPath, raw); }
      catch (e) {
        throw new BundlerError("bundler/engine-failed",
          "engine '" + engineImpl.name + "' failed on entry '" + name +
          "': " + ((e && e.message) || String(e)));
      }
      var content = transformed && transformed.content != null ? transformed.content : raw;
      if (typeof content === "string") content = Buffer.from(content, "utf8");
      else if (!Buffer.isBuffer(content)) {
        throw new BundlerError("bundler/engine-bad-output",
          "engine '" + engineImpl.name + "' returned non-Buffer / non-string content for '" +
          name + "'");
      }
      var sourceMap = transformed && transformed.sourceMap;
      var hash = hashOn ? _hashContent(content, hashLen) : null;
      var outName = hashOn ? _hashedName(name, hash, ext) : (name + ext);
      var outPath = nodePath.join(outdir, outName);
      // atomic-file write so a concurrent reader (the http server
      // serving outdir) never sees a partial file
      atomicFile.writeSync(outPath, content, { mode: 0o644 });
      // Sibling .map when the engine produced one. Source maps go
      // unhashed (browsers fetch <hashed.js>.map) — write them
      // alongside as <hashedOutName>.map.
      var sourceMapPath = null;
      if (sourceMap) {
        sourceMapPath = outPath + ".map";
        var mapBuf = Buffer.isBuffer(sourceMap) ? sourceMap : Buffer.from(String(sourceMap), "utf8");
        atomicFile.writeSync(sourceMapPath, mapBuf, { mode: 0o644 });
      }
      outputs.push({
        name:          name,
        entry:         entryPath,
        path:          outPath,
        hash:          hash,
        bytes:         content.length,
        ext:           ext,
        sourceMapPath: sourceMapPath,
      });
      manifest[name] = outName;
    }

    var manifestPath = null;
    if (manifestName) {
      manifestPath = nodePath.join(outdir, manifestName);
      atomicFile.writeSync(
        manifestPath,
        safeJson.stringify(manifest, null, 2) + "\n",
        { mode: 0o644 }
      );
    }

    var result = {
      outputs:      outputs,
      manifestPath: manifestPath,
      manifest:     manifest,
      durationMs:   Date.now() - t0,
    };
    _logVia("info", "build complete",
      { entries: outputs.length, durationMs: result.durationMs });
    return result;
  }

  function _scheduleRebuild(reason, callback) {
    if (debounceTimer) {
      try { clearTimeoutFn(debounceTimer); } catch (_e) { /* timer already cleared */ }
    }
    debounceTimer = setTimeoutFn(function () {
      debounceTimer = null;
      _logVia("info", "rebuilding", { reason: reason });
      build().then(
        function (r) { if (callback) try { callback(null, r); } catch (_e) { /* operator callback threw — logged elsewhere if material */ } },
        function (e) {
          _logVia("error", "rebuild failed", { error: (e && e.message) || String(e) });
          if (callback) try { callback(e, null); } catch (_e) { /* operator callback threw — already logged */ }
        }
      );
    }, graceMs);
    if (debounceTimer && typeof debounceTimer.unref === "function") debounceTimer.unref();
  }

  function watch(callback) {
    if (watching) return;
    watching = true;
    var names = Object.keys(entries);
    for (var i = 0; i < names.length; i++) {
      (function (name) {
        var entryPath = _resolveEntry(entries[name]);
        // Watch the entry's directory (single-file watches are flaky
        // across editors that write-then-rename). Filter events to the
        // entry's basename only.
        var dir = nodePath.dirname(entryPath);
        var base = nodePath.basename(entryPath);
        var w;
        try {
          w = watchFn(dir, { persistent: false }, function (eventType, filename) {
            if (filename && String(filename) === base) {
              _scheduleRebuild(name, callback);
            }
          });
        } catch (e) {
          _logVia("warn", "could not watch " + dir,
            { error: (e && e.message) || String(e) });
          return;
        }
        if (w && typeof w.on === "function") {
          w.on("error", function (err) {
            _logVia("warn", "watcher error",
              { dir: dir, error: (err && err.message) || String(err) });
          });
        }
        watchers.push(w);
      })(names[i]);
    }
  }

  async function close() {
    watching = false;
    if (debounceTimer) {
      try { clearTimeoutFn(debounceTimer); } catch (_e) { /* timer already cleared */ }
      debounceTimer = null;
    }
    for (var i = 0; i < watchers.length; i++) {
      try { if (watchers[i] && typeof watchers[i].close === "function") watchers[i].close(); }
      catch (_e) { /* close best-effort */ }
    }
    watchers = [];
  }

  return {
    build:    build,
    watch:    watch,
    close:    close,
    entries:  entries,
    outdir:   outdir,
  };
}

module.exports = {
  create:        create,
  engine:        engine,
  BundlerError:  BundlerError,
};

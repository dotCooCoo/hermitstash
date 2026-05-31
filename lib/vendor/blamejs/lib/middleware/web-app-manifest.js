"use strict";
/**
 * web-app-manifest middleware — emits the W3C Web App Manifest at
 * `/manifest.webmanifest` (and `/manifest.json` when `alsoAtJsonPath`
 * is true) per the W3C Web App Manifest specification.
 *
 *   var mf = b.middleware.webAppManifest({
 *     name:        "Example App",
 *     short_name:  "Example",
 *     start_url:   "/",
 *     display:     "standalone",
 *     theme_color: "#1976d2",
 *     background_color: "#ffffff",
 *     icons: [
 *       { src: "/icons/192.png", sizes: "192x192", type: "image/png" },
 *       { src: "/icons/512.png", sizes: "512x512", type: "image/png" },
 *     ],
 *   });
 *   router.use(mf);
 *
 * The manifest is JSON-serialized once at create() and served with
 * `Content-Type: application/manifest+json` per the W3C spec.
 *
 * Per W3C — `name`, `start_url`, and at least one icon are required
 * for an installable PWA. The framework throws at create() when any
 * of those are missing.
 */

var lazyRequire = require("../lazy-require");
var safeJson = require("../safe-json");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var WebAppManifestError = defineClass("WebAppManifestError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });

function _isPlainArray(x) { return Array.isArray(x); }

/**
 * @primitive b.middleware.webAppManifest
 * @signature b.middleware.webAppManifest(opts)
 * @since     0.1.0
 * @related   b.middleware.assetlinks, b.middleware.securityTxt
 *
 * Serves the W3C Web App Manifest at `/manifest.webmanifest`
 * (and `/manifest.json` when `alsoAtJsonPath: true`). Manifest is
 * JSON-serialized once at create-time and emitted with
 * `Content-Type: application/manifest+json`. Throws at create-time
 * when `name`, `start_url`, or an icons array is missing — those
 * are the W3C-required fields for an installable PWA. Operator
 * fields outside the W3C allowlist throw at boot so typos surface
 * early.
 *
 * @opts
 *   {
 *     name:                        string,    // required
 *     start_url:                   string,    // required
 *     icons:                       Array<{ src, sizes, type }>,  // required, ≥1
 *     short_name:                  string,
 *     description:                 string,
 *     scope:                       string,
 *     display:                     string,
 *     display_override:            string[],
 *     orientation:                 string,
 *     theme_color:                 string,
 *     background_color:            string,
 *     screenshots:                 array,
 *     shortcuts:                   array,
 *     categories:                  string[],
 *     lang:                        string,
 *     dir:                         string,
 *     id:                          string,
 *     prefer_related_applications: boolean,
 *     related_applications:        array,
 *     alsoAtJsonPath:              boolean,
 *     audit:                       boolean,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.webAppManifest({
 *     name:      "Example App",
 *     start_url: "/",
 *     display:   "standalone",
 *     icons: [
 *       { src: "/icons/192.png", sizes: "192x192", type: "image/png" },
 *       { src: "/icons/512.png", sizes: "512x512", type: "image/png" },
 *     ],
 *   }));
 */
function create(opts) {
  validateOpts.requireObject(opts, "middleware.webAppManifest", WebAppManifestError);
  // Allowlist subset of W3C-spec attributes operators commonly set.
  // Anything outside the list throws at create — typos surface at boot.
  validateOpts(opts, [
    "name", "short_name", "description", "start_url", "scope",
    "display", "display_override", "orientation",
    "theme_color", "background_color",
    "icons", "screenshots", "shortcuts",
    "categories", "lang", "dir", "id",
    "prefer_related_applications", "related_applications",
    "alsoAtJsonPath", "audit",
  ], "middleware.webAppManifest");

  validateOpts.requireNonEmptyString(opts.name,
    "middleware.webAppManifest: name", WebAppManifestError, "manifest/no-name");
  validateOpts.requireNonEmptyString(opts.start_url,
    "middleware.webAppManifest: start_url", WebAppManifestError, "manifest/no-start-url");
  if (!_isPlainArray(opts.icons) || opts.icons.length === 0) {
    throw new WebAppManifestError("manifest/no-icons",
      "middleware.webAppManifest: icons array is required (W3C spec — at least one icon for installability)");
  }

  // Build the JSON body once at create.
  var manifest = {};
  var keys = Object.keys(opts).filter(function (k) {
    return k !== "alsoAtJsonPath" && k !== "audit";
  });
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    if (opts[k] !== undefined && opts[k] !== null) manifest[k] = opts[k];
  }
  var body = safeJson.stringify(manifest, { space: 2 });
  var bodyBuf = Buffer.from(body, "utf8");
  var alsoAtJsonPath = opts.alsoAtJsonPath === true;
  var auditOn = opts.audit !== false;

  return function webAppManifestMiddleware(req, res, next) {
    var url = req.url || "";
    var qIdx = url.indexOf("?");
    var path = qIdx === -1 ? url : url.slice(0, qIdx);
    var matches = (path === "/manifest.webmanifest") ||
                  (alsoAtJsonPath && path === "/manifest.json");
    if (!matches) return next();
    if (req.method !== "GET" && req.method !== "HEAD") {
      var bodyMsg = "Method Not Allowed";
      res.writeHead(405, {                                                       // HTTP 405 status
        "Allow":          "GET, HEAD",
        "Content-Type":   "text/plain; charset=utf-8",
        "Content-Length": Buffer.byteLength(bodyMsg),
      });
      res.end(bodyMsg);
      return;
    }
    res.writeHead(200, {                                                         // HTTP 200 status
      "Content-Type":     "application/manifest+json",
      "Content-Length":   bodyBuf.length,
      "Cache-Control":    "public, max-age=86400",
      "X-Content-Type-Options": "nosniff",
    });
    if (req.method === "HEAD") { res.end(); return; }
    res.end(bodyBuf);
    if (auditOn) {
      try { observability().safeEvent("middleware.webAppManifest.served", 1, { path: path }); }
      catch (_e) { /* obs best-effort */ }
    }
  };
}

module.exports = {
  create: create,
};

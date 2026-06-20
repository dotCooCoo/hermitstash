"use strict";
/**
 * staticServe — server-side download primitive with the same v1-defensible
 * surface as b.fileUpload: permissions integration, audit emission with
 * 5-W's actor context, observability counters, bandwidth + concurrency
 * quotas (cluster-shared via b.cache), Range support (RFC 7233 single-range),
 * the full conditional-request set (If-None-Match / If-Match /
 * If-Modified-Since / If-Unmodified-Since), MIME allowlist with magic-byte
 * verification (composes b.fileType), per-request operator hooks (onServe
 * on the success path, onError on every refusal path), idle-stream
 * timeout, cancellation propagation, force-revoke, and compliance-retention
 * gating.
 *
 *   var serve = b.staticServe.create({ root, ...opts });
 *   await serve.revoke(absUrlPath);                 // operator force-revoke
 *   serve.stats();                                  // bytes / requests / etag-hits
 *   var mw = serve.middleware;                       // (req, res, next)
 *   await b.staticServe.integrity(absFilePath);      // SRI helper (SHA-384)
 *
 *   // onError mirrors onServe for the refusal paths (403 / 404 / 415 /
 *   // 412 / 416 / 429 / 451 / 500): it receives
 *   // { req, res, urlPath, absPath, status, code, actor } AFTER the
 *   // refusal response is written. Observability-only — a throw is
 *   // swallowed so a broken hook can't tear down the socket.
 *
 * Backwards compatible: every existing opt (root, mountPath,
 * hashedPathPattern, indexFile, defaultMaxAge, contentTypes) keeps its
 * original meaning. New opts (permissions, cache, audit, observability,
 * fileType, allowedFileTypes, maxBytesPerActorPerWindowMs, etc.) are all
 * optional with security-on defaults (auditSuccess / auditFailures default
 * true; range support defaults true; ETag is SHA3-512-truncated for PQC
 * posture, the SRI integrity helper keeps SHA-384 because the W3C
 * subresource-integrity spec only allows sha256/sha384/sha512).
 *
 * Backward-compat shape: create(opts) MAY be called for the bare middleware
 * (the v0.6.x shape) — the result is callable as `(req, res, next)` and
 * also exposes the new methods. That keeps existing tests + operator code
 * passing while opening the surface.
 */

var nodeFs = require("node:fs");
var fsp = require("node:fs/promises");
var nodeCrypto = require("node:crypto");
var nodePath = require("node:path");
var C = require("./constants");
var gateContract = require("./gate-contract");
var lazyRequire = require("./lazy-require");
var numericBounds = require("./numeric-bounds");
var requestHelpers = require("./request-helpers");
var validateOpts = require("./validate-opts");
var { StaticServeError } = require("./framework-error");

// observability is lazy-required because it pulls in the metrics tap +
// safeEvent path, and during framework boot static.js may load before
// observability is ready.
var observability = lazyRequire(function () { return require("./observability"); });

// guard-* family is wired on by default; lazy-loaded to avoid eager
// import cycles. Operators opt out via contentSafety: null (audited).
var guardAll = lazyRequire(function () { return require("./guard-all"); });
var guardFilename = lazyRequire(function () { return require("./guard-filename"); });

var _err = StaticServeError.factory;

var HTTP = requestHelpers.HTTP_STATUS;

var DEFAULT_HASHED_PATTERN = /\.[a-fA-F0-9]{8,}\./;
var DEFAULT_INDEX_FILE     = "index.html";
var DEFAULT_MAX_AGE_SEC    = C.TIME.hours(1) / C.TIME.seconds(1);    // 1h non-hashed
var IMMUTABLE_MAX_AGE_SEC  = C.TIME.days(365) / C.TIME.seconds(1);   // 1y hashed
var DEFAULT_BANDWIDTH_WINDOW_MS = C.TIME.minutes(1);
var DEFAULT_MAX_IDLE_MS    = C.TIME.minutes(2);
// SHA3-512 produces 64 bytes / 128 hex chars. ETag uses the first 32 hex
// chars (128 bits) — overkill for collision resistance but cheap; the same
// hash powers content addressing across the framework.
var ETAG_HEX_PREFIX = C.BYTES.bytes(32);

// Minimal MIME table (kept from the v0.6 ship for compat).
var DEFAULT_CONTENT_TYPES = {
  ".html":  "text/html; charset=utf-8",
  ".htm":   "text/html; charset=utf-8",
  ".css":   "text/css; charset=utf-8",
  ".js":    "application/javascript; charset=utf-8",
  ".mjs":   "application/javascript; charset=utf-8",
  ".json":  "application/json; charset=utf-8",
  ".map":   "application/json; charset=utf-8",
  ".txt":   "text/plain; charset=utf-8",
  ".md":    "text/markdown; charset=utf-8",
  ".xml":   "application/xml; charset=utf-8",
  ".svg":   "image/svg+xml",
  ".png":   "image/png",
  ".jpg":   "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif":   "image/gif",
  ".webp":  "image/webp",
  ".avif":  "image/avif",
  ".ico":   "image/x-icon",
  ".woff":  "font/woff",
  ".woff2": "font/woff2",
  ".ttf":   "font/ttf",
  ".otf":   "font/otf",
  ".pdf":   "application/pdf",
  ".wasm":  "application/wasm",
  ".webmanifest": "application/manifest+json",
};

var DEFAULTS = Object.freeze({
  defaultMaxAge:                    DEFAULT_MAX_AGE_SEC,
  acceptRanges:                     true,
  // Per-range byte cap — slowloris-range defense. A single Range
  // request that asks for 1 GiB pins a worker on a long read; many
  // concurrent requests asking for the same exhaust the process pool.
  // The cap rejects ranges larger than maxRangeBytes with 416. Set to
  // Infinity to opt out (audited reason).
  maxRangeBytes:                    C.BYTES.mib(64),
  // Empty array = no MIME allowlist gate.
  allowedFileTypes:                 Object.freeze([]),
  // Bandwidth + concurrency caps default to 0 = "no cap". Operators opt
  // in by setting a positive integer.
  maxBytesPerActorPerWindowMs:      0,
  maxBytesAllActorsPerWindowMs:     0,
  bandwidthWindowMs:                DEFAULT_BANDWIDTH_WINDOW_MS,
  maxConcurrentDownloadsPerActor:   0,
  maxIdleMs:                        DEFAULT_MAX_IDLE_MS,
  // Audit / observability defaults follow the framework's posture: the
  // serve event is the audit-worthy act, not a precursor.
  auditSuccess:                     true,
  auditFailures:                    true,
  // mountType — declares what KIND of content this mount serves, so
  // the stored-XSS-relevant defaults follow the typing instead of being
  // hand-flipped per mount (v0.15.0):
  //   "curated"      (default) — operator-controlled assets (CSS / JS
  //                  bundles / fonts / images). Inline render is required
  //                  and safe because the operator authored the bytes;
  //                  forceAttachmentForNonText defaults OFF.
  //   "user-content" — files written by end users / untrusted uploaders.
  //                  A served .html / .js / .svg here is a stored-XSS
  //                  vector, so forceAttachmentForNonText defaults ON —
  //                  risky inline MIMEs are forced to download unless a
  //                  sanitizer gate vouches for them (see
  //                  `_shouldForceAttachment`). This is the conditional
  //                  flip: a curated asset dir is never blindly forced to
  //                  download; only a mount the operator TYPED as
  //                  user-content gets the strict default.
  // An explicit forceAttachmentForNonText always overrides the
  // mountType-derived default.
  mountType:                        "curated",
  // forceAttachmentForNonText — stored-XSS defense for user-upload
  // directories. Default follows mountType: OFF for "curated" mounts
  // (operator-curated CSS / JS bundles / fonts need inline render), ON for
  // "user-content" mounts so HTML / JS / SVG without a sanitizer / PDF /
  // archives are forced to download. Set explicitly to override the
  // mountType-derived default either way. See `_shouldForceAttachment`
  // below for the safe-render allowlist.
  forceAttachmentForNonText:        false,
  // Companion knobs — when forceAttachmentForNonText is on, allow
  // image/svg+xml inline render IF an SVG sanitizer gate is wired
  // (default true; the framework's default-on contentSafety wiring
  // includes b.guardSvg). PDF inline render defaults OFF — operators
  // who serve a trusted PDF library opt in explicitly.
  safeRenderSvg:                    true,
  safeRenderPdf:                    false,
});

// _assertInsideRoot — the path-confinement barrier (CWE-22 path
// traversal). Every filesystem sink in this module takes the path
// through this helper so the value handed to fs is built by
// `nodePath.join(root, rel)` where `rel` is a normalized, root-relative
// path with every leading `..` segment stripped — the canonical
// path-traversal sanitizer: normalize collapses interior `.`/`..`, the
// leading-`..` strip removes upward navigation, and joining a constant
// root with a sanitized relative segment yields a path that provably
// stays inside the served root. The barrier is intentionally re-applied
// at each sink (not just once at request entry) so the relationship
// between the sanitizer and the fs call is local + explicit.
//
// Returns the joined, confined absolute path on success, or `null` when
// the candidate is not a string, carries a NUL byte, or — after the
// leading-`..` strip — still carries a `..` segment or an absolute /
// drive-letter / UNC prefix that would smuggle outside root. A leading
// `..` escape is clamped into root by the strip (the file then 404s);
// any residual escape that survives normalization is refused. Callers
// MUST treat `null` as a refusal.
function _assertInsideRoot(root, candidate) {
  if (typeof root !== "string" || root.length === 0) return null;
  if (typeof candidate !== "string" || candidate.length === 0) return null;
  if (candidate.indexOf("\0") !== -1) return null;
  var rootResolved = nodePath.resolve(root);
  // Reduce the candidate to a root-relative request, then run the
  // recognized traversal sanitizer: normalize() collapses `.`/`..`
  // segments; the replace strips every leading `..` so no upward
  // navigation survives into the join below.
  var requested = nodePath.isAbsolute(candidate)
    ? nodePath.relative(rootResolved, candidate)
    : candidate;
  var rel = nodePath.normalize(requested).replace(/^(\.\.(\/|\\|$))+/, "");
  if (rel.indexOf("\0") !== -1) return null;
  // After the leading-`..` strip, a surviving `..` segment or an
  // absolute / drive-letter / UNC residue would re-introduce an escape.
  if (rel === ".." ||
      rel.indexOf(".." + nodePath.sep) !== -1 ||
      rel.indexOf(".." + (nodePath.sep === "/" ? "\\" : "/")) !== -1 ||
      nodePath.isAbsolute(rel)) return null;
  var safe = nodePath.join(rootResolved, rel);
  // Defense-in-depth lexical containment alongside the join sanitizer.
  if (safe !== rootResolved &&
      !safe.startsWith(rootResolved + nodePath.sep)) return null;
  return safe;
}

// Module-level metadata cache. Entries hold:
//   { mtimeMs, size, etag, integrity, lastModified, sha3Hex, absPath }
// Invalidated on mtime / size change.
var _metaCache = new Map();

// _readMeta — stat + hash a file for the conditional-request + SRI
// surface. `root` is passed alongside the candidate so the
// path-traversal barrier (CWE-22) is re-asserted at THIS sink: the
// value handed to fs.stat / fs.createReadStream is the confined return
// of `_assertInsideRoot`, not the request-derived candidate. Returns
// null when the candidate escapes root, is not a regular file, or
// cannot be read.
async function _readMeta(root, candidate) {
  var absPath = _assertInsideRoot(root, candidate);
  if (!absPath) return null;

  var stat;
  try { stat = await fsp.stat(absPath); }
  catch (_e) { return null; }
  if (!stat.isFile()) return null;

  var cached = _metaCache.get(absPath);
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
    return cached;
  }

  // Stream both hashes side-by-side: SHA-384 for SRI (W3C spec), SHA3-512
  // for the framework ETag (PQC posture). Two transforms over the same
  // chunk avoids re-reading the file.
  var sri = nodeCrypto.createHash("sha384");
  var sha3 = nodeCrypto.createHash("sha3-512");
  await new Promise(function (resolve, reject) {
    // The path handed to createReadStream is the confined output of
    // `_assertInsideRoot(root, candidate)` above (lexical resolve +
    // root-prefix containment), not the request-derived candidate.
    var s = nodeFs.createReadStream(absPath);
    s.on("data", function (chunk) { sri.update(chunk); sha3.update(chunk); });
    s.on("end", resolve);
    s.on("error", reject);
  });
  var sriDigest = sri.digest("base64");
  var sha3Hex = sha3.digest("hex");

  var entry = {
    mtimeMs:    stat.mtimeMs,
    size:       stat.size,
    etag:       '"' + sha3Hex.slice(0, ETAG_HEX_PREFIX) + '"',
    integrity:  "sha384-" + sriDigest,
    lastModified: new Date(stat.mtimeMs).toUTCString(),
    sha3Hex:    sha3Hex,
    absPath:    absPath,
  };
  _metaCache.set(absPath, entry);
  return entry;
}

function _resolveSafe(root, requestedPath) {
  if (typeof requestedPath !== "string" || requestedPath.length === 0) return null;
  if (requestedPath.indexOf("\0") !== -1) return null;
  // Anchor the request path inside root with a leading "." so an
  // absolute request (`/c:/windows`, `//host/share`, `/etc/passwd`)
  // resolves as a same-named child of root rather than smuggling a
  // fresh root; the containment barrier then proves the result stays
  // inside root, refusing any `..`-driven escape. Drive-letter / UNC /
  // reserved-name shapes that survive the resolve are caught by the
  // guardFilename basename gate below.
  var resolved = _assertInsideRoot(root, nodePath.resolve(root, "." + requestedPath));
  if (!resolved) return null;
  var rootResolved = nodePath.resolve(root);

  // Symlink-escape defense — the lexical resolve above only sees the
  // requested path tokens; a symlink anywhere along `resolved` can
  // still point outside `rootResolved` on disk. Compare via realpath
  // for the escape check ONLY; do NOT substitute the realpath result
  // for `resolved`. Substituting breaks downstream consumers that key
  // on the lexical path (revoke list, ETag cache, audit row) AND
  // breaks deploys where the OS prefix-symlinks the temp dir
  // (macOS: /var/folders/X/Y → /private/var/folders/X/Y).
  try {
    var real = nodeFs.realpathSync(resolved);
    var rootReal = nodeFs.realpathSync(rootResolved);
    if (real !== rootReal && !real.startsWith(rootReal + nodePath.sep)) return null;
  } catch (_e) {
    // Path doesn't exist (or is denied) — fall through with the lexical
    // resolution so the caller's stat() returns the natural ENOENT and
    // 404s. realpath failures from non-existence are NOT a smuggling
    // signal; the lexical bound check above already rejected escapes.
  }

  // Filename safety — the basename gates against path-traversal /
  // null-byte / NTFS ADS / UNC / RTLO bidi / overlong UTF-8 / Windows
  // reserved device names. Uses balanced profile + explicit
  // shellExecExtPolicy: "allow" because static-serve serves operator-
  // deposited disk content: shell-exec extensions (.exe / .bin / .so /
  // legitimate `<name>.<hash>.js` bundler output) are valid here. The
  // other balanced checks still reject the traversal + smuggling
  // surface.
  var fname = nodePath.basename(resolved);
  var rv = guardFilename().validate(fname, {
    profile:             "balanced",
    shellExecExtPolicy:  "allow",
  });
  if (!rv.ok) return null;

  return resolved;
}

function _contentTypeFor(filePath, table) {
  var ext = nodePath.extname(filePath).toLowerCase();
  return (table && table[ext]) || DEFAULT_CONTENT_TYPES[ext] || "application/octet-stream";
}

// Risky MIMEs that the browser executes inline. When safeAttachment is
// on, the framework forces Content-Disposition: attachment so
// drive-by uploads can't be executed in the user's browser. Operators
// serving trusted assets (CSS / JS bundle / SVG icon) opt out by NOT
// setting safeAttachmentForRiskyMimes — leaving the existing inline
// default. The defense is per-CVE-2017-15012 (SVG XSS) /
// CVE-2009-1312 (HTML drive-by) class.
var RISKY_INLINE_MIMES = {
  "text/html":              true,
  "text/xml":               true,
  "application/xml":        true,
  "application/xhtml+xml":  true,
  "image/svg+xml":          true,
  "application/javascript": true,
  "text/javascript":        true,
  "application/x-javascript": true,
};

function _isRiskyInlineMime(contentType) {
  if (typeof contentType !== "string" || contentType.length === 0) return false;
  // Strip parameters like "; charset=utf-8".
  var semi = contentType.indexOf(";");
  var bare = (semi === -1 ? contentType : contentType.slice(0, semi)).trim().toLowerCase();
  return RISKY_INLINE_MIMES[bare] === true;
}

// Safe-render allowlist for `forceAttachmentForNonText`. When the
// operator opts in, every served file whose Content-Type is NOT
// `text/*` AND NOT in this allowlist is forced to download via
// `Content-Disposition: attachment` plus `X-Content-Type-Options:
// nosniff`. The list is intentionally narrow:
//
//   - image/png / jpeg / webp / gif: raster formats — browsers can't
//     interpret as scripts, no inline-execution surface.
//   - image/svg+xml: ONLY when an SVG-sanitizer is wired via
//     `contentSafety` (the default-on `b.guardSvg` covers this) —
//     SVG is XML and can carry `<script>` / event handlers; we
//     refuse to render it inline without sanitization.
//   - application/pdf: ONLY when `safeRenderPdf: true` is explicitly
//     set. PDFs commonly carry JavaScript and can bypass the SOP via
//     embedded forms; default is to force download.
var SAFE_RENDER_RASTER_MIMES = {
  "image/png":   true,
  "image/jpeg":  true,
  "image/webp":  true,
  "image/gif":   true,
};

function _bareMime(contentType) {
  if (typeof contentType !== "string" || contentType.length === 0) return "";
  var semi = contentType.indexOf(";");
  return (semi === -1 ? contentType : contentType.slice(0, semi)).trim().toLowerCase();
}

// _shouldForceAttachment — decide whether the operator's opt-in policy
// forces this content type to download. Returns true when the
// response should carry `Content-Disposition: attachment` +
// `X-Content-Type-Options: nosniff`.
//
// Allowlist intent: text/plain / text/css / text/markdown render
// inline (no execution surface), raster images render inline (no
// execution surface), SVG renders inline ONLY when an SVG sanitizer
// gate is wired AND `safeRenderSvg` is enabled, PDF renders inline
// ONLY when `safeRenderPdf` is explicitly enabled. text/html and
// text/javascript are inside `text/*` but the browser executes them
// — they go through the risky nodePath. Everything else (HTML, JS, MJS,
// XML, executables, archives, fonts when served from a user-upload
// directory) gets forced download to defeat stored-XSS via the
// upload directory.
function _shouldForceAttachment(contentType, ext, contentSafetyMap, allowSvgRender, allowPdfRender) {
  var bare = _bareMime(contentType);
  if (bare.length === 0) return true; // unknown MIME → safest path
  // text/html / text/xml / text/javascript / xhtml are inside `text/*`
  // but the browser executes them — risky nodePath.
  if (bare === "text/html" || bare === "text/xml" ||
      bare === "text/javascript" || bare === "application/xhtml+xml") {
    return true;
  }
  if (bare.indexOf("text/") === 0) return false;
  if (SAFE_RENDER_RASTER_MIMES[bare]) return false;
  if (bare === "image/svg+xml") {
    if (!allowSvgRender) return true;
    if (!contentSafetyMap || typeof contentSafetyMap !== "object") return true;
    var svgGate = contentSafetyMap[".svg"];
    if (!svgGate || typeof svgGate.check !== "function") return true;
    return false;
  }
  if (bare === "application/pdf") {
    return !allowPdfRender;
  }
  // Defense-in-depth: files served with .html / .htm / .xhtml / .js /
  // .mjs / .svg / .xml / .pdf extensions but a generic
  // application/octet-stream MIME still get forced download. The
  // extension check catches misconfigured tables / sniffed-down MIMEs.
  if (ext === ".html" || ext === ".htm" || ext === ".xhtml" ||
      ext === ".js" || ext === ".mjs" || ext === ".svg" ||
      ext === ".xml" || ext === ".pdf") {
    if (ext === ".svg" && allowSvgRender) {
      if (contentSafetyMap && contentSafetyMap[".svg"] &&
          typeof contentSafetyMap[".svg"].check === "function") return false;
    }
    if (ext === ".pdf" && allowPdfRender) return false;
    return true;
  }
  return true;
}

// Build a safe Content-Disposition value for an attachment. The
// filename is RFC 5987-encoded so non-ASCII characters survive without
// allowing CR/LF header injection.
function _attachmentDisposition(filePath) {
  var name = nodePath.basename(filePath);
  // Refuse CR/LF/NUL outright — they're already filtered upstream by
  // the path-traversal guard, but defense-in-depth here.
  if (/[\r\n\0]/.test(name)) name = "download";
  // ASCII-safe filename (replace non-ASCII with _) plus filename* = UTF-8 form.
  var asciiName = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  var encName = encodeURIComponent(name);
  return 'attachment; filename="' + asciiName + '"; filename*=UTF-8\'\'' + encName;
}

// _parseRangeHeader — RFC 7233 single-range parser. Returns null when:
//   - header absent
//   - syntactically malformed (not `bytes=`, multi-range, suffix syntax
//     "-N" handled, end > size, start > end)
//   - the request can be answered as 416 the caller does (start >= size).
//
// Returns { start, end, length } for a valid satisfiable single range.
// Multi-range (`bytes=0-99,200-299`) returns { multi: true } so the
// caller can refuse with 416 — we don't ship multipart/byteranges in v1
// (operators with that need pull bytes via b.objectStore presigned URL).
function _parseRangeHeader(header, size) {
  if (typeof header !== "string" || header.length === 0) return null;
  if (header.indexOf("bytes=") !== 0) return { malformed: true };
  var spec = header.slice(6).trim();
  if (spec.length === 0) return { malformed: true };
  if (spec.indexOf(",") !== -1) return { multi: true };
  var dash = spec.indexOf("-");
  if (dash === -1) return { malformed: true };
  var startStr = spec.slice(0, dash);
  var endStr = spec.slice(dash + 1);
  var start, end;
  if (startStr === "") {
    // Suffix range: "bytes=-N" → last N bytes.
    var suffix = parseInt(endStr, 10);
    if (!isFinite(suffix) || suffix <= 0) return { malformed: true };
    if (suffix > size) suffix = size;
    start = size - suffix;
    end = size - 1;
  } else {
    start = parseInt(startStr, 10);
    if (!isFinite(start) || start < 0) return { malformed: true };
    if (endStr === "") {
      end = size - 1;
    } else {
      end = parseInt(endStr, 10);
      if (!isFinite(end) || end < start) return { malformed: true };
      if (end > size - 1) end = size - 1;
    }
  }
  if (start >= size) return { unsatisfiable: true };
  return { start: start, end: end, length: end - start + 1 };
}

function _httpDate(date) {
  return (date instanceof Date ? date : new Date(date)).toUTCString();
}

function _validateCreateOpts(opts) {
  // Declarative per-field validation. shape() runs requireObject(opts)
  // itself (same "opts must be an object" / BAD_OPT contract the inline
  // requireObject produced), then dispatches each field. A field whose
  // check is one of the rule tokens maps to the token directly; a field
  // with a bespoke message (mountPath / hashedPathPattern), a
  // duck-typed-handle shape (permissions / cache / fileType / retention /
  // revokeStore — each carrying its own operator-facing description), a
  // numeric bound, or an audit/observability shape uses the
  // validator-function hatch so the exact thrown code + message + label
  // are preserved. Cross-field business logic (root existence,
  // allowedFileTypes↔fileType wiring, the contentSafety map, the
  // mountType enum, the quota↔cache requirement) stays below shape.
  validateOpts.shape(opts, {
    root: "required-string",
    mountPath: function (value, _label, errorClass, code) {
      // empty string is operator-permissible: "no mount, root is request URL"
      if (typeof value === "string" && value.length === 0) return;
      if (value !== undefined && value !== null && typeof value !== "string") {
        throw errorClass.factory(code, "staticServe.create: mountPath must be a string");
      }
    },
    hashedPathPattern: function (value, _label, errorClass, code) {
      if (value !== undefined && value !== null && !(value instanceof RegExp)) {
        throw errorClass.factory(code, "staticServe.create: hashedPathPattern must be a RegExp");
      }
    },
    // indexFile === null is the operator's "disable" sentinel; the helper
    // returns null/undefined unchanged so we keep that semantic.
    indexFile: "optional-string",
    defaultMaxAge: function (value, label, errorClass, code) {
      numericBounds.requireNonNegativeFiniteIntIfPresent(value, label, errorClass, code);
    },
    contentTypes: "optional-plain-object",
    // contentSafety — extension-keyed gate map. undefined → the framework
    // wires b.guardAll.byExtension({ profile: "strict" }) so every shipped
    // guard is ON by default; null is the explicit opt-out (audited at
    // create() time); a plain { ext: gate } object validates each value is a
    // gate (a .check fn). The label / code / message match the prior inline
    // check exactly so a test asserting them still holds.
    contentSafety: function (value, _label, errorClass, code) {
      if (value === undefined || value === null) return;
      validateOpts.optionalPlainObject(value,
        "staticServe.create: contentSafety", errorClass, code,
        "must be a plain { ext: gate } object, null to opt out, or " +
        "undefined for the default-on b.guardAll wiring");
      var safetyKeys = Object.keys(value);
      for (var sk = 0; sk < safetyKeys.length; sk++) {
        var ext = safetyKeys[sk];
        var g = value[ext];
        if (!g || typeof g.check !== "function") {
          throw errorClass.factory(code,
            "staticServe.create: contentSafety[" + JSON.stringify(ext) +
            "] must be a gate (b.guardCsv.gate / b.guardHtml.gate / etc.)");
        }
      }
    },
    permissions: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "check", label, errorClass, code,
        "must be a b.permissions instance (check fn)");
    },
    cache: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "get", label, errorClass, code,
        "must be a b.cache instance (used for cluster-shared bandwidth + concurrency tracking)");
    },
    fileType: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "detect", label, errorClass, code,
        "must be a b.fileType instance (magic-byte MIME detection)");
    },
    retention: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "isServable", label, errorClass, code,
        "must expose isServable(absPath, ctx) → boolean (compliance retention check)");
    },
    revokeStore: function (value, label, errorClass, code) {
      validateOpts.optionalObjectWithMethod(value, "isRevoked", label, errorClass, code,
        "must expose isRevoked(key) and revoke(key) for force-revoke support");
    },
    allowedFileTypes: "optional-string-array",
    audit: function (value, _label, errorClass, _code) {
      validateOpts.auditShape(value, "staticServe.create", errorClass);
    },
    observability: function (value, _label, errorClass, _code) {
      validateOpts.observabilityShape(value, "staticServe.create", errorClass);
    },
    onServe: "optional-function",
    onError: "optional-function",
    acceptRanges: "optional-boolean",
    auditSuccess: "optional-boolean",
    auditFailures: "optional-boolean",
    safeAttachmentForRiskyMimes: "optional-boolean",
    forceAttachmentForNonText: "optional-boolean",
    safeRenderSvg: "optional-boolean",
    safeRenderPdf: "optional-boolean",
    maxBytesPerActorPerWindowMs: function (value, label, errorClass, code) {
      numericBounds.requireNonNegativeFiniteIntIfPresent(value, label, errorClass, code);
    },
    maxBytesAllActorsPerWindowMs: function (value, label, errorClass, code) {
      numericBounds.requireNonNegativeFiniteIntIfPresent(value, label, errorClass, code);
    },
    bandwidthWindowMs: function (value, label, errorClass, code) {
      numericBounds.requirePositiveFiniteIntIfPresent(value, label, errorClass, code);
    },
    maxConcurrentDownloadsPerActor: function (value, label, errorClass, code) {
      numericBounds.requireNonNegativeFiniteIntIfPresent(value, label, errorClass, code);
    },
    maxIdleMs: function (value, label, errorClass, code) {
      numericBounds.requirePositiveFiniteIntIfPresent(value, label, errorClass, code);
    },
    // maxRangeBytes — per-range byte cap (slowloris-range defense). A
    // positive finite integer caps Range requests; Infinity is the
    // documented opt-out, so the numericBounds finite-int helpers (which
    // reject Infinity) can't be used directly here.
    maxRangeBytes: function (value, label, errorClass, code) {
      if (value === undefined || value === null || value === Infinity) return;
      numericBounds.requirePositiveFiniteInt(value, label, errorClass, code);
    },
  }, "staticServe.create", StaticServeError, "BAD_OPT", {
    // contentSafetyDisabledReason (audit-row string) and mountType (curated
    // | user-content enum) carry dedicated cross-field validation below
    // shape — the audit reason read and the enum throw whose exact message a
    // test asserts. Listing them here keeps that bespoke logic the single
    // validator rather than re-checking the same key inside shape.
    allow: ["contentSafetyDisabledReason", "mountType"],
  });

  if (!nodeFs.existsSync(opts.root)) {
    throw _err("BAD_OPT", "staticServe.create: root does not exist: " + opts.root);
  }
  if (Array.isArray(opts.allowedFileTypes) && opts.allowedFileTypes.length > 0 &&
      (!opts.fileType || typeof opts.fileType.detect !== "function")) {
    throw _err("BAD_OPT",
      "staticServe.create: allowedFileTypes is set but fileType primitive is not wired " +
      "(pass fileType: b.fileType so the framework can sniff magic bytes before serving)");
  }
  // contentSafety — extension-keyed gate map; validated in the shape above
  // (plain { ext: gate } object / null opt-out / undefined default-on).
  // When undefined, the framework wires b.guardAll.byExtension({ profile:
  // "strict" }) automatically so every shipped guard is ON by default;
  // contentSafety: null is the explicit opt-out, audited at create() time so
  // a security review can reconstruct which deploys disabled the default-on
  // protection.
  // Example: contentSafety: { ".csv": b.guardCsv.gate({ profile: "strict" }) }
  // mountType — config-time enum. A typo ("usercontent", "uploads")
  // would silently fall back to the curated default and serve untrusted
  // HTML inline, so THROW at boot rather than mis-type the mount.
  if (opts.mountType !== undefined &&
      opts.mountType !== "curated" && opts.mountType !== "user-content") {
    throw _err("BAD_OPT",
      "staticServe.create: mountType must be 'curated' (default) or " +
      "'user-content'; got " + JSON.stringify(opts.mountType));
  }
  // Quotas require a cache for cluster-shared coordination.
  if ((opts.maxBytesPerActorPerWindowMs > 0 ||
       opts.maxBytesAllActorsPerWindowMs > 0 ||
       opts.maxConcurrentDownloadsPerActor > 0) &&
      !opts.cache) {
    throw _err("BAD_OPT",
      "staticServe.create: bandwidth / concurrency quotas require opts.cache " +
      "(pass cache: b.cache.create({ backend: 'cluster' }) so multi-replica deploys honor caps globally)");
  }
}

// _checkBandwidthQuota — token-bucket via b.cache. Returns { ok: true } or
// { ok: false, retryAfter, scope: "actor"|"global" }.
async function _checkBandwidthQuota(cache, actorKey, perActorCap, globalCap, windowMs, requestedBytes) {
  if (!cache || (perActorCap === 0 && globalCap === 0)) return { ok: true };
  var now = Date.now();
  var windowStart = now - windowMs;
  if (perActorCap > 0 && actorKey) {
    var aKey = "static:bw:actor:" + actorKey;
    var aUsed = (await cache.get(aKey)) || 0;
    if (aUsed + requestedBytes > perActorCap) {
      return { ok: false, retryAfter: Math.ceil(windowMs / C.TIME.seconds(1)), scope: "actor", used: aUsed, cap: perActorCap };
    }
  }
  if (globalCap > 0) {
    var gKey = "static:bw:global";
    var gUsed = (await cache.get(gKey)) || 0;
    if (gUsed + requestedBytes > globalCap) {
      return { ok: false, retryAfter: Math.ceil(windowMs / C.TIME.seconds(1)), scope: "global", used: gUsed, cap: globalCap };
    }
  }
  return { ok: true, windowStart: windowStart, now: now };
}

async function _consumeBandwidth(cache, actorKey, perActorCap, globalCap, windowMs, bytes) {
  if (!cache) return;
  if (perActorCap > 0 && actorKey) {
    var aKey = "static:bw:actor:" + actorKey;
    var aUsed = (await cache.get(aKey)) || 0;
    await cache.set(aKey, aUsed + bytes, { ttlMs: windowMs });
  }
  if (globalCap > 0) {
    var gKey = "static:bw:global";
    var gUsed = (await cache.get(gKey)) || 0;
    await cache.set(gKey, gUsed + bytes, { ttlMs: windowMs });
  }
}

async function _checkConcurrencyCap(cache, actorKey, cap) {
  if (!cache || cap === 0 || !actorKey) return { ok: true };
  var key = "static:conc:" + actorKey;
  var current = (await cache.get(key)) || 0;
  if (current >= cap) return { ok: false, current: current, cap: cap };
  return { ok: true, current: current };
}

async function _incConcurrency(cache, actorKey) {
  if (!cache || !actorKey) return;
  var key = "static:conc:" + actorKey;
  var current = (await cache.get(key)) || 0;
  await cache.set(key, current + 1, { ttlMs: C.TIME.minutes(10) });
}

async function _decConcurrency(cache, actorKey) {
  if (!cache || !actorKey) return;
  var key = "static:conc:" + actorKey;
  var current = (await cache.get(key)) || 0;
  var next = current > 0 ? current - 1 : 0;
  await cache.set(key, next, { ttlMs: C.TIME.minutes(10) });
}

function _actorKeyFromContext(ctx) {
  if (!ctx) return null;
  if (ctx.userId) return "id:" + ctx.userId;
  if (ctx.ip)     return "ip:" + ctx.ip;
  return null;
}

// _writeError — uniform error response with audit + observability emission.
function _writeError(res, status, code, message, headers) {
  var hdrs = Object.assign({ "Content-Type": "text/plain; charset=utf-8" }, headers || {});
  hdrs["Content-Length"] = Buffer.byteLength(message, "utf8");
  try {
    res.writeHead(status, hdrs);
    res.end(message);
  } catch (_e) {
    // response already torn down — best effort
  }
  void code;
}

// integrity() — module-level helper, kept for compat with the v0.6 SRI
// use. Operates on an operator-supplied absolute path (a config/library
// call, not the request path): the file's own resolved path is both the
// confinement root and the candidate, so `_readMeta` re-applies the same
// barrier shape every other sink uses without narrowing the legitimate
// surface (any single file the operator names).
async function integrity(absPath) {
  if (typeof absPath !== "string" || absPath.length === 0) {
    throw _err("BAD_OPT", "staticServe.integrity: absPath must be a non-empty string");
  }
  var resolved = nodePath.resolve(absPath);
  var meta = await _readMeta(resolved, resolved);
  if (!meta) throw _err("NOT_FOUND", "staticServe.integrity: file not found: " + absPath);
  return meta.integrity;
}

function create(opts) {
  opts = opts || {};
  // The exhaustive shape() in _validateCreateOpts is the authoritative
  // unknown-key gate: any opt not declared in its schema (nor listed in
  // its options.allow pass-through) is rejected as an unknown opt, so the
  // typo-catching the v0.6.x `validateOpts(opts, [...allowed])` call gave
  // is now subsumed by the per-field validation below.
  _validateCreateOpts(opts);
  var cfg = validateOpts.applyDefaults(opts, DEFAULTS);
  var root            = nodePath.resolve(opts.root);
  var mountPath       = opts.mountPath || "";
  var hashedPattern   = opts.hashedPathPattern || DEFAULT_HASHED_PATTERN;
  var indexFile       = opts.indexFile === null ? null : (opts.indexFile || DEFAULT_INDEX_FILE);
  var defaultMaxAge   = cfg.defaultMaxAge;
  var contentTypes    = opts.contentTypes || null;
  var permissions     = opts.permissions || null;
  var cache           = opts.cache || null;
  var fileType        = opts.fileType || null;
  var retention       = opts.retention || null;
  var revokeStore     = opts.revokeStore || null;
  var allowedFileTypes = Array.isArray(opts.allowedFileTypes) ? opts.allowedFileTypes.slice() : [];
  // contentSafety: undefined → wire b.guardAll.byExtension({ profile: "strict" })
  // contentSafety: null      → explicit opt-out, audit row emitted
  // contentSafety: { ... }   → use operator-supplied map
  var contentSafety;
  if (opts.contentSafety === undefined) {
    // Strict profile is the security-correct default. Operators who
    // serve a broader content vocabulary opt up explicitly via
    // contentSafety: b.guardAll.byExtension({ profile: "balanced" |
    // "permissive" }).
    contentSafety = guardAll().byExtension({
      profile:       "strict",
      audit:         opts.audit,
      observability: opts.observability,
    });
  } else if (opts.contentSafety === null) {
    if (opts.audit && typeof opts.audit.safeEmit === "function") {
      try {
        opts.audit.safeEmit({
          action:   "staticServe.contentSafety.disabled",
          actor:    {},
          outcome:  "success",
          metadata: {
            reason: opts.contentSafetyDisabledReason || "operator-explicit-opt-out",
          },
        });
      } catch (_e) { /* audit best-effort */ }
    }
    contentSafety = null;
  } else {
    contentSafety = opts.contentSafety;
  }
  var onServe         = opts.onServe || null;
  var onError         = opts.onError || null;
  var audit           = opts.audit || null;
  var auditSuccess    = cfg.auditSuccess;
  var auditFailures   = cfg.auditFailures;
  var acceptRanges    = cfg.acceptRanges;
  var safeAttachment  = !!cfg.safeAttachmentForRiskyMimes;
  // forceAttachmentForNonText default follows mountType (v0.15.0): a
  // mount TYPED "user-content" forces risky inline MIMEs to download by
  // default (stored-XSS defense for untrusted uploads); a "curated" mount
  // keeps inline render. An explicit forceAttachmentForNonText overrides
  // the mountType-derived default either way. The conditional flip never
  // blindly force-attaches a curated asset dir.
  var mountType       = opts.mountType || "curated";
  var forceAttachmentForNonText = opts.forceAttachmentForNonText !== undefined
    ? !!opts.forceAttachmentForNonText
    : (mountType === "user-content");
  var allowSvgRender  = cfg.safeRenderSvg !== false;
  var allowPdfRender  = !!cfg.safeRenderPdf;
  var perActorCap     = cfg.maxBytesPerActorPerWindowMs;
  var globalCap       = cfg.maxBytesAllActorsPerWindowMs;
  var bandwidthWindowMs = cfg.bandwidthWindowMs;
  var concurrencyCap  = cfg.maxConcurrentDownloadsPerActor;
  var maxIdleMs       = cfg.maxIdleMs;

  var emitAudit = validateOpts.makeAuditEmitter(audit);

  // In-memory revoke set (operator can wire revokeStore for cluster-shared
  // revocation; this Map is only used when no store is wired and gives
  // single-process operators a working force-revoke without requiring cache).
  var localRevoked = new Set();

  function _emitObs(name, value, labels) {
    observability().safeEvent(name, value, labels || {});
  }

  // Per-instance counters for serve.stats(). Cluster-shared counters live in
  // observability; these are local snapshots for a single process.
  var stats = {
    requestsServed:    0,
    bytesServed:       0,
    etagHits:          0,
    rangeRequests:     0,
    permissionDenied:  0,
    quotaRejected:     0,
    failures:          0,
  };

  function _cacheControlFor(urlPath) {
    if (hashedPattern.test(urlPath)) {
      return "public, max-age=" + IMMUTABLE_MAX_AGE_SEC + ", immutable";
    }
    return "public, max-age=" + defaultMaxAge;
  }

  async function _isRevoked(key) {
    if (revokeStore) {
      try { return !!(await revokeStore.isRevoked(key)); }
      catch (_e) { return false; }
    }
    return localRevoked.has(key);
  }

  async function _checkRetention(absPath, ctx) {
    if (!retention) return true;
    try { return !!(await retention.isServable(absPath, ctx)); }
    catch (_e) { return false; }
  }

  async function _checkPermission(req) {
    if (!permissions) return { ok: true };
    try {
      var ok = await permissions.check(req, "static.serve");
      return { ok: !!ok };
    } catch (_e) {
      return { ok: false, error: _e };
    }
  }

  async function _checkMimeAllowlist(absPath, meta) {
    if (allowedFileTypes.length === 0 || !fileType) return { ok: true };
    // Re-assert the root-confinement barrier at this fs read sink
    // (CWE-22): the path passed to readFile is the confined return of
    // `_assertInsideRoot`, not the request-derived candidate.
    var confined = _assertInsideRoot(root, absPath);
    if (!confined) return { ok: false, reason: "read-failed" };
    var sample;
    try { sample = await fsp.readFile(confined, { flag: "r" }); }
    catch (_e) { return { ok: false, reason: "read-failed" }; }
    var detected = fileType.detect(sample.slice(0, C.BYTES.kib(64))) || {};
    if (!detected.mime) return { ok: false, reason: "indeterminate" };
    if (allowedFileTypes.indexOf(detected.mime) === -1) {
      return { ok: false, reason: "not-allowed", detected: detected.mime };
    }
    void meta;
    return { ok: true, detected: detected.mime };
  }

  async function middleware(req, res, next) {
    if (req.method !== "GET" && req.method !== "HEAD") return next();

    var urlPath = (req.url || "").split("?")[0];
    if (mountPath && urlPath.indexOf(mountPath) === 0) {
      urlPath = urlPath.slice(mountPath.length) || "/";
    }
    var decoded;
    try { decoded = decodeURIComponent(urlPath); }
    catch (_e) { return next(); }

    var absPath = _resolveSafe(root, decoded);
    if (!absPath) return next();

    var actorCtx = requestHelpers.extractActorContext(req);
    var actorKey = _actorKeyFromContext(actorCtx);

    // Request-scoped error writer. Wraps the module-level _writeError so
    // every refusal path (403 / 404 / 415 / 412 / 416 / 429 / 451 / 500)
    // also invokes the operator's onError hook — the success-path mirror
    // of onServe. The signature matches _writeError exactly; the `code`
    // argument routes through to the hook so operators can branch on the
    // refusal reason. The hook is observability-only: it runs AFTER the
    // response is written and a throw is swallowed so a broken sink can't
    // turn a 4xx into a torn-down socket.
    function writeErr(r, status, code, message, headers) {
      _writeError(r, status, code, message, headers);
      if (onError) {
        try {
          onError({
            req: req, res: r, urlPath: urlPath, absPath: absPath,
            status: status, code: code, actor: actorCtx,
          });
        } catch (_he) { /* hook best-effort */ }
      }
    }

    // Permission gate (403)
    var perm = await _checkPermission(req);
    if (!perm.ok) {
      stats.permissionDenied += 1;
      _emitObs("staticServe.permission_denied", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "permission_denied", resource: urlPath,
        }, actorCtx));
      }
      return writeErr(res, HTTP.FORBIDDEN, "permission_denied",
        "Forbidden");
    }

    // Stat first to discover directory → index file. The path handed to
    // stat is the confined return of `_resolveSafe` above; re-assert the
    // barrier so CodeQL sees the confinement local to this sink (CWE-22).
    var statTarget = _assertInsideRoot(root, absPath);
    if (!statTarget) return next();
    var stat;
    try { stat = await fsp.stat(statTarget); }
    catch (_e) { return next(); }
    if (stat.isDirectory()) {
      if (!indexFile) return next();
      // Re-confine after appending the index file — keeps every
      // downstream sink (read-meta, content-safety open, serve stream)
      // anchored inside root even if indexFile were ever made operator-
      // overridable per request.
      absPath = _assertInsideRoot(root, nodePath.join(absPath, indexFile));
      if (!absPath) return next();
    }

    // Force-revoke (404 — opaque to clients)
    if (await _isRevoked(absPath)) {
      stats.failures += 1;
      _emitObs("staticServe.revoked", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "revoked", resource: urlPath,
        }, actorCtx));
      }
      return writeErr(res, HTTP.NOT_FOUND, "not_found", "Not Found");
    }

    // Compliance retention (451)
    if (!(await _checkRetention(absPath, actorCtx))) {
      stats.failures += 1;
      _emitObs("staticServe.retention_blocked", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "retention_blocked", resource: urlPath,
        }, actorCtx));
      }
      return writeErr(res, HTTP.UNAVAILABLE_FOR_LEGAL_REASONS,
        "retention_blocked", "Unavailable For Legal Reasons");
    }

    var meta = await _readMeta(root, absPath);
    if (!meta) return next();

    // MIME allowlist (415) — checked before sending bytes so a misnamed
    // .txt holding a binary payload is refused at serve time.
    if (allowedFileTypes.length > 0) {
      var mimeCheck = await _checkMimeAllowlist(absPath, meta);
      if (!mimeCheck.ok) {
        stats.failures += 1;
        _emitObs("staticServe.mime_rejected", 1, { route: urlPath, reason: mimeCheck.reason });
        if (auditFailures) {
          emitAudit("staticServe.serve.failure", Object.assign({
            outcome: "failure", reason: "mime_rejected", resource: urlPath,
            detectedMime: mimeCheck.detected || null,
          }, actorCtx));
        }
        return writeErr(res, HTTP.UNSUPPORTED_MEDIA_TYPE,
          "mime_rejected", "Unsupported Media Type");
      }
    }

    // Content-safety gate — operator-supplied per-extension gate
    // (b.guardCsv.gate / b.guardHtml.gate / etc.). Reads the file once
    // up to maxRuntimeMs and routes the bytes through the gate's
    // check() before serving. The gate's decision is honored:
    //   - serve     → continue with the original bytes
    //   - sanitize  → continue with decision.sanitized
    //   - refuse    → 415 / opaque to clients
    //   - audit-only / warn → continue (gate emits to audit)
    var gateBytesOverride = null;
    if (contentSafety) {
      var ext = nodePath.extname(absPath).toLowerCase();
      var safetyGate = contentSafety[ext];
      if (safetyGate && typeof safetyGate.check === "function") {
        // Single-fd read for the content-safety gate. Two defenses on
        // one open:
        //   - CWE-22 path traversal: the open path is the confined
        //     return of `_assertInsideRoot(root, absPath)`, freshly
        //     re-derived from `nodePath.resolve(root, ...)`, not the
        //     request-derived candidate.
        //   - CWE-367 TOCTOU file-system race: the bytes the gate
        //     inspects come from THIS file descriptor — size and reads
        //     are taken from the same inode the open returned, so a path
        //     swap between the earlier directory stat and this read can't
        //     slip different bytes past the gate. O_NOFOLLOW (when the
        //     platform defines it) additionally refuses to open the path
        //     if its final component became a symlink after confinement.
        var gateConfined = _assertInsideRoot(root, absPath);
        if (!gateConfined) return next();
        var gateBuf;
        var gateHandle = null;
        var gateOpenFlags = nodeFs.constants.O_RDONLY |
          (nodeFs.constants.O_NOFOLLOW || 0);
        try {
          // Explicit owner-only mode (0o600). The flags are read-only
          // (O_RDONLY, no O_CREAT) so the mode is inert on disk, but
          // pinning it owner-only keeps this open out of the insecure-
          // temp-file class (CWE-377): no world/group-accessible
          // creation can ever ride this code path.
          gateHandle = await fsp.open(gateConfined, gateOpenFlags, 0o600);
          var gateStat = await gateHandle.stat();
          gateBuf = Buffer.alloc(gateStat.size);
          var gateRead = 0;
          while (gateRead < gateStat.size) {
            var gateN = await gateHandle.read(gateBuf, gateRead, gateStat.size - gateRead, null);
            if (gateN.bytesRead === 0) break;
            gateRead += gateN.bytesRead;
          }
          if (gateRead < gateStat.size) gateBuf = gateBuf.slice(0, gateRead);
        }
        catch (_e) {
          stats.failures += 1;
          if (gateHandle) { try { await gateHandle.close(); } catch (_ce) { /* close best-effort */ } }
          return writeErr(res, HTTP.INTERNAL_SERVER_ERROR,
            "read_failed", "Internal Server Error");
        }
        try { await gateHandle.close(); } catch (_ce) { /* close best-effort */ }
        var gateDecision;
        try {
          gateDecision = await safetyGate.check({
            bytes:       gateBuf,
            contentType: _contentTypeFor(absPath, contentTypes),
            filename:    nodePath.basename(absPath),
            actor:       actorCtx,
            route:       urlPath,
            direction:   "outbound",
            req:         req,
          });
        } catch (gateErr) {
          stats.failures += 1;
          _emitObs("staticServe.content_safety_threw", 1, { route: urlPath });
          if (auditFailures) {
            emitAudit("staticServe.serve.failure", Object.assign({
              outcome: "failure", reason: "content_safety_threw", resource: urlPath,
              error: gateErr && gateErr.message,
            }, actorCtx));
          }
          return writeErr(res, HTTP.INTERNAL_SERVER_ERROR,
            "content_safety_threw", "Internal Server Error");
        }
        if (!gateDecision.ok || gateDecision.action === "refuse") {
          stats.failures += 1;
          _emitObs("staticServe.content_safety_refused", 1, { route: urlPath });
          if (auditFailures) {
            emitAudit("staticServe.serve.failure", Object.assign({
              outcome: "failure", reason: "content_safety_refused",
              resource: urlPath, ext: ext,
              issues: gateContract.summarizeIssues(gateDecision.issues),
            }, actorCtx));
          }
          return writeErr(res, HTTP.UNSUPPORTED_MEDIA_TYPE,
            "content_safety_refused", "Unsupported Media Type");
        }
        if (gateDecision.action === "sanitize" && gateDecision.sanitized) {
          gateBytesOverride = gateDecision.sanitized;
        }
      }
    }

    var cacheControl = _cacheControlFor(urlPath);

    var headersIn = req.headers || {};

    // Conditional: If-None-Match (304)
    var ifNone = headersIn["if-none-match"];
    if (ifNone && ifNone === meta.etag) {
      stats.etagHits += 1;
      _emitObs("staticServe.etag_hits", 1, { route: urlPath });
      res.writeHead(HTTP.NOT_MODIFIED, {
        "ETag":          meta.etag,
        "Cache-Control": cacheControl,
        "Last-Modified": meta.lastModified,
      });
      return res.end();
    }

    // Conditional: If-Match (412 if no match — strong validator only)
    var ifMatch = headersIn["if-match"];
    if (ifMatch && ifMatch !== "*" && ifMatch !== meta.etag) {
      stats.failures += 1;
      _emitObs("staticServe.precondition_failed", 1, { route: urlPath, header: "if-match" });
      return writeErr(res, HTTP.PRECONDITION_FAILED || 412,
        "precondition_failed", "Precondition Failed");
    }

    // Conditional: If-Modified-Since (304)
    var ifModSince = headersIn["if-modified-since"];
    if (ifModSince) {
      var ims = Date.parse(ifModSince);
      if (isFinite(ims) && Math.floor(meta.mtimeMs / C.TIME.seconds(1)) <= Math.floor(ims / C.TIME.seconds(1))) {
        stats.etagHits += 1;
        _emitObs("staticServe.if_modified_since_hits", 1, { route: urlPath });
        res.writeHead(HTTP.NOT_MODIFIED, {
          "ETag":          meta.etag,
          "Cache-Control": cacheControl,
          "Last-Modified": meta.lastModified,
        });
        return res.end();
      }
    }

    // Conditional: If-Unmodified-Since (412)
    var ifUnmodSince = headersIn["if-unmodified-since"];
    if (ifUnmodSince) {
      var ius = Date.parse(ifUnmodSince);
      if (isFinite(ius) && Math.floor(meta.mtimeMs / C.TIME.seconds(1)) > Math.floor(ius / C.TIME.seconds(1))) {
        stats.failures += 1;
        _emitObs("staticServe.precondition_failed", 1, { route: urlPath, header: "if-unmodified-since" });
        return writeErr(res, HTTP.PRECONDITION_FAILED,
          "precondition_failed", "Precondition Failed");
      }
    }

    // Range parsing
    var range = null;
    if (acceptRanges) {
      var raw = headersIn["range"];
      if (raw) {
        range = _parseRangeHeader(raw, meta.size);
        if (range && (range.malformed || range.multi)) {
          stats.failures += 1;
          _emitObs("staticServe.range_invalid", 1, { route: urlPath });
          return writeErr(res, HTTP.RANGE_NOT_SATISFIABLE, "range_not_satisfiable",
            "Range Not Satisfiable", { "Content-Range": "bytes */" + meta.size });
        }
        if (range && range.unsatisfiable) {
          stats.failures += 1;
          _emitObs("staticServe.range_invalid", 1, { route: urlPath });
          return writeErr(res, HTTP.RANGE_NOT_SATISFIABLE, "range_not_satisfiable",
            "Range Not Satisfiable", { "Content-Range": "bytes */" + meta.size });
        }
        if (range && cfg.maxRangeBytes !== Infinity && range.length > cfg.maxRangeBytes) {
          stats.failures += 1;
          _emitObs("staticServe.range_too_large", 1, { route: urlPath });
          return writeErr(res, HTTP.RANGE_NOT_SATISFIABLE, "range_too_large",
            "Range Not Satisfiable", { "Content-Range": "bytes */" + meta.size });
        }
        if (range) {
          stats.rangeRequests += 1;
          _emitObs("staticServe.range_requests", 1, { route: urlPath });
        }
      }
    }

    var sendBytes = range ? range.length : meta.size;

    // Concurrency gate (429)
    var concCheck = await _checkConcurrencyCap(cache, actorKey, concurrencyCap);
    if (!concCheck.ok) {
      stats.quotaRejected += 1;
      _emitObs("staticServe.concurrency_rejected", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "concurrency_cap", resource: urlPath,
          current: concCheck.current, cap: concCheck.cap,
        }, actorCtx));
      }
      return writeErr(res, HTTP.TOO_MANY_REQUESTS,
        "concurrency_cap", "Too Many Requests",
        { "Retry-After": "5" });
    }

    // Bandwidth gate (429)
    var bwCheck = await _checkBandwidthQuota(cache, actorKey, perActorCap, globalCap, bandwidthWindowMs, sendBytes);
    if (!bwCheck.ok) {
      stats.quotaRejected += 1;
      _emitObs("staticServe.bandwidth_rejected", 1, { route: urlPath, scope: bwCheck.scope });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "bandwidth_quota", resource: urlPath,
          scope: bwCheck.scope, used: bwCheck.used, cap: bwCheck.cap,
        }, actorCtx));
      }
      return writeErr(res, HTTP.TOO_MANY_REQUESTS,
        "bandwidth_quota", "Too Many Requests",
        { "Retry-After": String(bwCheck.retryAfter) });
    }

    var status = range ? 206 : HTTP.OK;
    var headers = {
      "Content-Type":   _contentTypeFor(absPath, contentTypes),
      "Content-Length": sendBytes,
      "ETag":           meta.etag,
      "Cache-Control":  cacheControl,
      "Last-Modified":  meta.lastModified,
      "X-Integrity":    meta.integrity,
    };
    // Drive-by-execution defense — when safeAttachmentForRiskyMimes is
    // on, force Content-Disposition: attachment for HTML / JS / SVG /
    // XML so the browser downloads instead of rendering. Operator's
    // onServe hook can override.
    if (safeAttachment && _isRiskyInlineMime(headers["Content-Type"])) {
      headers["Content-Disposition"] = _attachmentDisposition(absPath);
    }
    // Stored-XSS defense for user-upload directories: when
    // forceAttachmentForNonText is on, force download for every MIME
    // outside the safe-render allowlist (text/* except html/xml/js,
    // image/png|jpeg|webp|gif, image/svg+xml only when an SVG sanitizer
    // gate is wired, application/pdf only when safeRenderPdf is
    // explicitly on). Pairs with X-Content-Type-Options: nosniff so
    // browsers can't sniff the bytes back into an executable type.
    if (forceAttachmentForNonText) {
      var dispoExt = nodePath.extname(absPath).toLowerCase();
      if (_shouldForceAttachment(headers["Content-Type"], dispoExt, contentSafety,
                                 allowSvgRender, allowPdfRender)) {
        headers["Content-Disposition"] = _attachmentDisposition(absPath);
        headers["X-Content-Type-Options"] = "nosniff";
      }
    }
    if (acceptRanges) headers["Accept-Ranges"] = "bytes";
    if (range) headers["Content-Range"] = "bytes " + range.start + "-" + range.end + "/" + meta.size;

    // onServe hook — operator can mutate headers / set extra fields.
    if (onServe) {
      try {
        await onServe({
          req: req, res: res, absPath: absPath, urlPath: urlPath,
          size: meta.size, sendBytes: sendBytes, range: range,
          headers: headers, actor: actorCtx,
        });
      } catch (e) {
        stats.failures += 1;
        _emitObs("staticServe.onServe_threw", 1, { route: urlPath });
        if (auditFailures) {
          emitAudit("staticServe.serve.failure", Object.assign({
            outcome: "failure", reason: "onServe_threw", resource: urlPath,
            error: e && e.message,
          }, actorCtx));
        }
        return writeErr(res, HTTP.INTERNAL_SERVER_ERROR, "onServe_threw",
          "Internal Server Error");
      }
    }

    if (req.method === "HEAD") {
      res.writeHead(status, headers);
      res.end();
      stats.requestsServed += 1;
      _emitObs("staticServe.requests_served", 1, { route: urlPath, method: "HEAD" });
      if (auditSuccess) {
        emitAudit("staticServe.serve.success", Object.assign({
          outcome: "success", resource: urlPath, method: "HEAD",
          size: meta.size, contentType: headers["Content-Type"],
        }, actorCtx));
      }
      return;
    }

    // Sanitized override path — content-safety gate replaced the
    // bytes; emit them directly without re-reading the file. Bypasses
    // range / idle-timer machinery (the override is already in memory
    // and Range over a sanitized variant doesn't have a useful
    // contract — sanitization changes byte offsets).
    if (gateBytesOverride) {
      var overrideHeaders = Object.assign({}, headers, {
        "Content-Length": gateBytesOverride.length,
      });
      delete overrideHeaders["Content-Range"];
      res.writeHead(HTTP.OK, overrideHeaders);
      res.end(gateBytesOverride);
      stats.requestsServed += 1;
      stats.bytesServed += gateBytesOverride.length;
      _emitObs("staticServe.requests_served", 1, { route: urlPath, method: "GET", sanitized: true });
      _emitObs("staticServe.bytes_served", gateBytesOverride.length, { route: urlPath, sanitized: true });
      if (auditSuccess) {
        emitAudit("staticServe.serve.success", Object.assign({
          outcome: "success", resource: urlPath, method: "GET",
          size: gateBytesOverride.length, contentType: overrideHeaders["Content-Type"],
          sanitized: true,
        }, actorCtx));
      }
      return;
    }

    // Re-assert the root-confinement barrier at the serve sink (CWE-22)
    // BEFORE any 200/206 headers go on the wire: the path handed to
    // createReadStream is the confined return of `_assertInsideRoot`,
    // freshly re-derived from `nodePath.resolve(root, ...)`, not the
    // request-derived candidate. A candidate that escapes root refuses
    // opaquely (404) — it cannot reach the stream.
    var streamTarget = _assertInsideRoot(root, absPath);
    if (!streamTarget) {
      stats.failures += 1;
      return writeErr(res, HTTP.NOT_FOUND, "not_found", "Not Found");
    }

    res.writeHead(status, headers);

    // Acquire concurrency slot (released on stream end / error / abort).
    await _incConcurrency(cache, actorKey);
    var slotReleased = false;
    function releaseSlot() {
      if (slotReleased) return;
      slotReleased = true;
      _decConcurrency(cache, actorKey).catch(function () {});
    }

    var streamOpts = range ? { start: range.start, end: range.end } : {};
    var fileStream = nodeFs.createReadStream(streamTarget, streamOpts);

    // Idle timeout — close the connection if the client stalls. Pattern is
    // a deadline-style debounce (clearTimeout + setTimeout) tied directly
    // to the file-stream "data" event lifecycle; the safeAsync.debounce
    // helper isn't yet ship-implemented, and pulling it through here would
    // pre-allocate a closure for every served byte. Tracked for extraction.
    var idleTimer = null;
    function resetIdleTimer() {
      if (idleTimer) clearTimeout(idleTimer); // allow:handrolled-debounce — file-stream idle deadline
      idleTimer = setTimeout(function () {
        try { fileStream.destroy(_err("IDLE_TIMEOUT", "client idle for " + maxIdleMs + "ms")); }
        catch (_) { /* stream already torn down */ }
        try { res.destroy(); } catch (_) { /* response already torn down */ }
      }, maxIdleMs);
    }
    resetIdleTimer();

    // Cancellation propagation: when the client disconnects mid-stream.
    function onClientClose() {
      try { fileStream.destroy(); } catch (_) { /* allow:silent-catch — stream already torn down */ }
      releaseSlot();
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
    }
    req.on("aborted", onClientClose);
    res.on("close", onClientClose);

    var bytesSent = 0;
    fileStream.on("data", function (chunk) {
      bytesSent += chunk.length;
      resetIdleTimer();
    });

    fileStream.on("error", function (e) {
      stats.failures += 1;
      _emitObs("staticServe.stream_error", 1, { route: urlPath });
      if (auditFailures) {
        emitAudit("staticServe.serve.failure", Object.assign({
          outcome: "failure", reason: "stream_error", resource: urlPath,
          error: e && e.message,
        }, actorCtx));
      }
      try { res.destroy(e); } catch (_) { /* allow:silent-catch — response already torn down */ }
      releaseSlot();
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
    });

    fileStream.on("end", function () {
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
      stats.requestsServed += 1;
      stats.bytesServed += bytesSent;
      _emitObs("staticServe.requests_served", 1, { route: urlPath, method: "GET" });
      _emitObs("staticServe.bytes_served", bytesSent, { route: urlPath });
      _consumeBandwidth(cache, actorKey, perActorCap, globalCap, bandwidthWindowMs, bytesSent)
        .catch(function () {});
      if (auditSuccess) {
        emitAudit("staticServe.serve.success", Object.assign({
          outcome: "success", resource: urlPath, method: "GET",
          size: bytesSent, contentType: headers["Content-Type"],
          range: range ? { start: range.start, end: range.end } : null,
        }, actorCtx));
      }
      releaseSlot();
    });

    fileStream.pipe(res);
  }

  // Operator-facing handle: callable as middleware (back-compat) AND
  // exposes serve-instance methods.
  async function fn(req, res, next) { return middleware(req, res, next); }
  fn.middleware = middleware;
  fn.revoke = async function (key) {
    if (revokeStore && typeof revokeStore.revoke === "function") {
      await revokeStore.revoke(key);
      return { ok: true, key: key };
    }
    localRevoked.add(key);
    return { ok: true, key: key };
  };
  fn.unrevoke = async function (key) {
    if (revokeStore && typeof revokeStore.unrevoke === "function") {
      await revokeStore.unrevoke(key);
      return { ok: true, key: key };
    }
    localRevoked.delete(key);
    return { ok: true, key: key };
  };
  fn.stats = function () {
    return Object.assign({}, stats);
  };
  fn.invalidateMeta = function (key) {
    _metaCache.delete(key);
    return { ok: true, key: key };
  };
  return fn;
}

function _resetCacheForTest() { _metaCache.clear(); }

module.exports = {
  create:                 create,
  integrity:              integrity,
  DEFAULT_MAX_AGE_SEC:    DEFAULT_MAX_AGE_SEC,
  IMMUTABLE_MAX_AGE_SEC:  IMMUTABLE_MAX_AGE_SEC,
  DEFAULT_HASHED_PATTERN: DEFAULT_HASHED_PATTERN,
  _resetCacheForTest:     _resetCacheForTest,
  _parseRangeHeader:      _parseRangeHeader,
};

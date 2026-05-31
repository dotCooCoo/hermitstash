"use strict";
/**
 * security-txt middleware — RFC 9116 /.well-known/security.txt emitter.
 *
 * Operators wire this on their app so security researchers know where
 * to find the disclosure policy. The middleware serves a static body
 * at `/.well-known/security.txt` (and root `/security.txt` when
 * opts.alsoAtRoot is true) per RFC 9116 §3 ("Format" — text/plain
 * with one field per line, "Field: value" pairs).
 *
 *   var txt = b.middleware.securityTxt({
 *     contact:   ["mailto:security@example.com", "https://example.com/security/report"],
 *     expires:   "2027-01-01T00:00:00Z",
 *     encryption:["https://example.com/pgp.asc"],
 *     policy:    "https://example.com/security/policy",
 *     ack:       "https://example.com/security/hall-of-fame",
 *     preferredLanguages: ["en"],
 *   });
 *   router.use(txt);
 *
 * Per RFC 9116 §2.5, `Contact:` and `Expires:` are REQUIRED. The
 * middleware throws at config-time when either is missing.
 *
 * Per §2.5.1, `Expires:` MUST be a future timestamp; the framework
 * also throws when the operator-supplied `expires` is in the past.
 */

var lazyRequire = require("../lazy-require");
var validateOpts = require("../validate-opts");
var { defineClass } = require("../framework-error");

var SecurityTxtError = defineClass("SecurityTxtError", { alwaysPermanent: true });

var observability = lazyRequire(function () { return require("../observability"); });

function _arrayOfStrings(value, label) {
  if (value === undefined || value === null) return [];
  var arr = Array.isArray(value) ? value : [value];
  for (var i = 0; i < arr.length; i += 1) {
    if (typeof arr[i] !== "string" || arr[i].length === 0) {
      throw new SecurityTxtError("security-txt/bad-" + label,
        label + "[" + i + "] must be a non-empty string");
    }
    if (/[\r\n\0]/.test(arr[i])) {
      throw new SecurityTxtError("security-txt/bad-" + label,
        label + "[" + i + "] contains forbidden CR/LF/NUL");
    }
  }
  return arr;
}

function _isoFuture(s) {
  if (typeof s !== "string" || s.length === 0) return false;
  var d = new Date(s);
  if (isNaN(d.getTime())) return false;
  return d.getTime() > Date.now();
}

/**
 * @primitive b.middleware.securityTxt
 * @signature b.middleware.securityTxt(opts)
 * @since     0.1.0
 * @related   b.middleware.assetlinks, b.middleware.webAppManifest
 *
 * Serves an RFC 9116 `/.well-known/security.txt` body so security
 * researchers find the disclosure policy. With `alsoAtRoot: true`
 * also serves at `/security.txt`. Required fields per §2.5 are
 * `Contact` and `Expires` — the middleware throws at create-time
 * when either is missing OR `Expires` is in the past, and
 * sanitizes every value against CR / LF / NUL (RFC 9116 forbids
 * those in field values). Operators with PGP keys, hall-of-fame
 * URLs, hiring pages, etc. populate the optional fields.
 *
 * @opts
 *   {
 *     contact:            string[],   // required, ≥1 entry
 *     expires:            string,     // required, future ISO timestamp
 *     encryption:         string[],
 *     policy:             string,
 *     ack:                string,
 *     preferredLanguages: string[],
 *     hiring:             string,
 *     canonical:          string|string[],
 *     alsoAtRoot:         boolean,
 *     audit:              boolean,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var app = b.router.create();
 *   app.use(b.middleware.securityTxt({
 *     contact: ["mailto:security@example.com"],
 *     expires: "2099-01-01T00:00:00Z",
 *     policy:  "https://example.com/security/policy",
 *   }));
 */
function create(opts) {
  validateOpts.requireObject(opts, "middleware.securityTxt", SecurityTxtError);
  validateOpts(opts, [
    "contact", "expires", "encryption", "policy", "ack",
    "preferredLanguages", "hiring", "canonical",
    "alsoAtRoot", "audit",
  ], "middleware.securityTxt");

  var contact = _arrayOfStrings(opts.contact, "contact");
  if (contact.length === 0) {
    throw new SecurityTxtError("security-txt/no-contact",
      "middleware.securityTxt: contact is required (RFC 9116 §2.5.3)");
  }
  validateOpts.requireNonEmptyString(opts.expires,
    "middleware.securityTxt: expires", SecurityTxtError, "security-txt/no-expires");
  if (!_isoFuture(opts.expires)) {
    throw new SecurityTxtError("security-txt/expires-in-past",
      "middleware.securityTxt: expires must be a future ISO 8601 timestamp (got '" + opts.expires + "')");
  }
  var encryption = _arrayOfStrings(opts.encryption, "encryption");
  var policy     = _arrayOfStrings(opts.policy,     "policy");
  var ack        = _arrayOfStrings(opts.ack,        "ack");
  var canonical  = _arrayOfStrings(opts.canonical,  "canonical");
  var hiring     = _arrayOfStrings(opts.hiring,     "hiring");
  var prefLangs  = _arrayOfStrings(opts.preferredLanguages, "preferredLanguages");

  // Build the body once at create time — the response is identical
  // for every request and the Content-Length is known up front.
  var lines = [];
  for (var i = 0; i < contact.length; i += 1) lines.push("Contact: " + contact[i]);
  lines.push("Expires: " + opts.expires);
  for (var ei = 0; ei < encryption.length; ei += 1) lines.push("Encryption: " + encryption[ei]);
  for (var pi = 0; pi < policy.length; pi += 1) lines.push("Policy: " + policy[pi]);
  for (var ai = 0; ai < ack.length; ai += 1) lines.push("Acknowledgments: " + ack[ai]);
  for (var ci = 0; ci < canonical.length; ci += 1) lines.push("Canonical: " + canonical[ci]);
  for (var hi = 0; hi < hiring.length; hi += 1) lines.push("Hiring: " + hiring[hi]);
  if (prefLangs.length > 0) lines.push("Preferred-Languages: " + prefLangs.join(", "));
  var body = lines.join("\n") + "\n";
  var bodyBuf = Buffer.from(body, "utf8");
  var alsoAtRoot = opts.alsoAtRoot === true;

  return function securityTxtMiddleware(req, res, next) {
    var url = req.url || "";
    // Strip query string for the path comparison.
    var qIdx = url.indexOf("?");
    var path = qIdx === -1 ? url : url.slice(0, qIdx);
    var matches = (path === "/.well-known/security.txt") ||
                  (alsoAtRoot && path === "/security.txt");
    if (!matches) return next();
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, {                                                       // HTTP 405 status
        "Allow":          "GET, HEAD",
        "Content-Type":   "text/plain; charset=utf-8",
        "Content-Length": 18,                                                    // len of "Method Not Allowed"
      });
      res.end("Method Not Allowed");
      return;
    }
    res.writeHead(200, {                                                         // HTTP 200 status
      "Content-Type":     "text/plain; charset=utf-8",
      "Content-Length":   bodyBuf.length,
      "Cache-Control":    "public, max-age=86400",
      "X-Content-Type-Options": "nosniff",
    });
    if (req.method === "HEAD") { res.end(); return; }
    res.end(bodyBuf);
    try { observability().safeEvent("middleware.securityTxt.served", 1, { path: path }); }
    catch (_e) { /* obs best-effort */ }
  };
}

module.exports = {
  create: create,
};

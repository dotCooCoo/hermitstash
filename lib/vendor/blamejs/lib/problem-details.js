"use strict";
/**
 * @module     b.problemDetails
 * @nav        HTTP
 * @title      Problem Details
 * @order      300
 *
 * @intro
 *   RFC 9457 Problem Details for HTTP APIs — standardized error
 *   response envelope with `type` / `title` / `status` / `detail` /
 *   `instance` plus operator-supplied extensions. Sets
 *   `Content-Type: application/problem+json` per RFC 9457 §3 so
 *   clients can branch on the content type rather than scanning ad-
 *   hoc JSON shapes. Supersedes RFC 7807 (obsolete).
 *
 *   Operators wire this in three places:
 *     1. `b.problemDetails.create({...})` builds a problem object
 *        with field validation (type URI, status range, etc.).
 *     2. `b.problemDetails.respond(res, problem)` serializes + sends.
 *     3. `b.problemDetails.fromError(err)` converts a thrown
 *        `FrameworkError` into the matching problem document; the
 *        `err.code` (e.g. `csv/invalid-record`) becomes the
 *        `type` URI suffix (`https://blamejs.com/problems/csv/
 *        invalid-record`).
 *
 *   `b.problemDetails.validate(doc)` parses an INBOUND problem
 *   response (e.g. when blamejs is the client of an upstream API
 *   returning RFC 9457) — refuses non-objects, refuses bad type
 *   URIs, refuses status outside 100..599.
 *
 *   Tier choices per `feedback_validation_tier_policy.md`:
 *     - create / fromError / validate — THROW on bad input
 *       (config-time / entry-point shape).
 *     - respond — THROW on bad input (its first call sets the
 *       response shape; silent drop would mask a programming bug).
 *
 * @card
 *   RFC 9457 Problem Details for HTTP APIs — standardized error response envelope with `application/problem+json` content type, supersedes RFC 7807.
 */

var pick         = require("./pick");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var POISONED_KEYS = pick.POISONED_KEYS;

var ProblemDetailsError = defineClass("ProblemDetailsError", { alwaysPermanent: true });

// Default problem-type URI base. Operators override via
// `b.problemDetails.setBase(url)` so deployments running under a
// custom domain emit problem URIs at their own host.
var STATE = {
  baseUri: "https://blamejs.com/problems",
};

// RFC 9457 §3 reserved field names. Extensions land at the top level
// alongside these — RFC 9457 §3.2 explicitly endorses sibling
// extensions ("members SHOULD have unique names within their parent
// object"). Reserved names are NOT allowed as extension keys —
// re-using them silently masks a programming bug.
var RESERVED_FIELDS = Object.freeze([
  "type", "title", "status", "detail", "instance",
]);

/**
 * @primitive b.problemDetails.setBase
 * @signature b.problemDetails.setBase(baseUri)
 * @since     0.8.84
 * @status    stable
 * @related   b.problemDetails.create, b.problemDetails.fromError
 *
 * Override the base URI prepended to error-code-derived `type` URIs.
 * Default is `https://blamejs.com/problems`. Operators running under
 * their own published vocabulary (e.g. an internal status page or
 * an organization-owned problem catalog) point this at the canonical
 * location. Throws `problem-details/bad-base` for non-https / non-
 * absolute / non-string inputs.
 *
 * @example
 *   b.problemDetails.setBase("https://api.example.com/problems");
 *   b.problemDetails.fromError(new Error("csv/invalid-record")).type;
 *   // → "https://api.example.com/problems/csv/invalid-record"
 */
function setBase(baseUri) {
  validateOpts.requireNonEmptyString(
    baseUri, "setBase.baseUri", ProblemDetailsError, "problem-details/bad-base");
  if (!/^https?:\/\//.test(baseUri)) {
    throw new ProblemDetailsError("problem-details/bad-base",
      "setBase: baseUri must be an absolute http(s) URL", true);
  }
  // Strip trailing slash so the create()-path can prefix with "/".
  // Manual loop instead of /\/+$/ regex — CodeQL flags the latter as
  // a polynomial-time ReDoS candidate on operator-supplied input even
  // though `/+` against an anchored tail is genuinely O(n); manual
  // strip moots the warning + keeps O(n) explicit.
  var bu = baseUri;
  while (bu.length > 0 && bu.charAt(bu.length - 1) === "/") {
    bu = bu.slice(0, -1);
  }
  STATE.baseUri = bu;
}

/**
 * @primitive b.problemDetails.getBase
 * @signature b.problemDetails.getBase()
 * @since     0.8.84
 * @status    stable
 * @related   b.problemDetails.setBase
 *
 * Read the currently-configured base URI. Useful for diagnostic
 * logging and tests.
 *
 * @example
 *   b.problemDetails.getBase();   // → "https://blamejs.com/problems"
 */
function getBase() {
  return STATE.baseUri;
}

/**
 * @primitive b.problemDetails.create
 * @signature b.problemDetails.create(opts)
 * @since     0.8.84
 * @status    stable
 * @related   b.problemDetails.respond, b.problemDetails.fromError, b.problemDetails.validate
 *
 * Build a frozen RFC 9457 problem-details object. Validates the
 * standard fields per §3:
 *   - `type` (optional, defaults to `"about:blank"`) must be a URI
 *     reference (string); MAY be relative or absolute.
 *   - `title` (recommended) must be a non-empty string when given.
 *   - `status` (recommended) must be an integer 100..599.
 *   - `detail` (optional) must be a string when given.
 *   - `instance` (optional) must be a URI reference string when given.
 *   - Extensions: every additional top-level key whose name is NOT in
 *     `RESERVED_FIELDS` is preserved at the top level. Reserved-name
 *     collisions throw `problem-details/reserved-extension`;
 *     prototype-pollution-shaped top-level keys throw the same.
 *   - `extensions`: a plain object whose keys are spread as top-level
 *     sibling members (RFC 9457 §3.2) — the literal `extensions`
 *     member is never emitted. Keys colliding with `RESERVED_FIELDS`
 *     are ignored (reserved fields can't be overridden by an
 *     extension); prototype-pollution-shaped keys are dropped
 *     silently. When the same name appears both as a direct top-level
 *     key and inside `extensions`, the direct top-level key wins.
 *
 * Returns a frozen plain object suitable for `JSON.stringify`.
 *
 * @opts
 *   type:       string,   // problem-type URI reference (default "about:blank")
 *   title:      string,   // short summary
 *   status:     number,   // integer 100..599
 *   detail:     string,   // human-readable explanation
 *   instance:   string,   // URI reference for this specific occurrence
 *   extensions: object,   // keys spread as top-level siblings (§3.2); direct top-level key wins on collision
 *   ...extensions         // additional top-level keys preserved as-is
 *
 * @example
 *   var p = b.problemDetails.create({
 *     type:     "https://example.com/problems/out-of-credit",
 *     title:    "You do not have enough credit.",
 *     status:   403,
 *     detail:   "Your current balance is 30, but that costs 50.",
 *     instance: "/account/12345/msgs/abc",
 *     balance:  30,
 *     accounts: ["/account/12345", "/account/67890"],
 *   });
 *   // → {
 *   //     type: "https://example.com/problems/out-of-credit",
 *   //     title: "You do not have enough credit.",
 *   //     status: 403,
 *   //     detail: "Your current balance is 30, but that costs 50.",
 *   //     instance: "/account/12345/msgs/abc",
 *   //     balance: 30,
 *   //     accounts: ["/account/12345", "/account/67890"]
 *   //   }
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new ProblemDetailsError("problem-details/bad-opts",
      "create: opts must be a non-null object", true);
  }
  var out = {};

  // type (RFC 9457 §3.1.1 — default "about:blank")
  var typeIn = validateOpts.optionalNonEmptyString(
    opts.type, "create.type", ProblemDetailsError, "problem-details/bad-type");
  out.type = (typeIn === undefined || typeIn === null) ? "about:blank" : typeIn;

  // title (§3.1.2 — short, human-readable summary)
  var titleIn = validateOpts.optionalNonEmptyString(
    opts.title, "create.title", ProblemDetailsError, "problem-details/bad-title");
  if (titleIn !== undefined && titleIn !== null) {
    out.title = titleIn;
  }

  // status (§3.1.3 — integer 100..599)
  if (opts.status !== undefined) {
    if (typeof opts.status !== "number" || !Number.isInteger(opts.status) ||
        opts.status < 100 || opts.status > 599) {                                                  // HTTP status range bounds
      throw new ProblemDetailsError("problem-details/bad-status",
        "create: status must be an integer 100..599 when provided", true);
    }
    out.status = opts.status;
  }

  // detail (§3.1.4)
  if (opts.detail !== undefined) {
    if (typeof opts.detail !== "string") {
      throw new ProblemDetailsError("problem-details/bad-detail",
        "create: detail must be a string when provided", true);
    }
    out.detail = opts.detail;
  }

  // instance (§3.1.5 — URI reference)
  var instanceIn = validateOpts.optionalNonEmptyString(
    opts.instance, "create.instance", ProblemDetailsError, "problem-details/bad-instance");
  if (instanceIn !== undefined && instanceIn !== null) {
    out.instance = instanceIn;
  }

  // Extensions — every additional key. §3.2 endorses sibling
  // extensions as long as their names don't collide with reserved.
  // The `extensions` key itself is NOT emitted as a literal nested
  // member: a plain-object value is spread so each of its keys lands
  // as a top-level sibling, subject to the same reserved / poisoned
  // guards as direct top-level keys. A direct top-level extension key
  // wins over the same name nested under `extensions`.
  var keys = Object.keys(opts);
  var directKeys = Object.create(null);
  var i, k;
  for (i = 0; i < keys.length; i += 1) {
    k = keys[i];
    if (k === "extensions") continue;
    if (RESERVED_FIELDS.indexOf(k) !== -1) continue;
    if (POISONED_KEYS.indexOf(k) !== -1) {
      throw new ProblemDetailsError("problem-details/reserved-extension",
        "create: extension key '" + k + "' refused (prototype-pollution shape)", true);
    }
    out[k] = opts[k];
    directKeys[k] = true;
  }

  // Spread `extensions` (RFC 9457 §3.2 sibling members). Reserved
  // names can't be overridden by an extension key; poisoned keys are
  // dropped silently (an inbound extension map is a less-trusted shape
  // than a hand-authored top-level key — a direct poisoned key still
  // throws). A direct top-level key already present wins.
  if (opts.extensions !== undefined && opts.extensions !== null) {
    if (typeof opts.extensions !== "object" || Array.isArray(opts.extensions)) {
      throw new ProblemDetailsError("problem-details/bad-extensions",
        "create: extensions must be a plain object when provided", true);
    }
    var extKeys = Object.keys(opts.extensions);
    for (i = 0; i < extKeys.length; i += 1) {
      k = extKeys[i];
      if (RESERVED_FIELDS.indexOf(k) !== -1) continue;
      if (POISONED_KEYS.indexOf(k) !== -1) continue;
      if (directKeys[k]) continue;
      out[k] = opts.extensions[k];
    }
  }

  return Object.freeze(out);
}

/**
 * @primitive b.problemDetails.fromError
 * @signature b.problemDetails.fromError(err, opts?)
 * @since     0.8.84
 * @status    stable
 * @related   b.problemDetails.create, b.problemDetails.respond
 *
 * Convert a thrown `FrameworkError` (or any error with a `code` field)
 * into the matching problem-details object. The error's `code`
 * (e.g. `csv/invalid-record`) becomes the type-URI suffix
 * (`<baseUri>/csv/invalid-record`); the error's `message` becomes
 * `detail`; the error's `statusCode` becomes `status` when present,
 * otherwise defaults to 500. Pass `opts.title` to override the title
 * default (which is the error class name humanized: `CsvError` →
 * "CSV Error"). Pass `opts.instance` to attach a request-instance
 * reference (typically the audit-trail ID).
 *
 * @opts
 *   title:    string,   // override the derived title
 *   instance: string,   // request-instance URI reference
 *   status:   number,   // override err.statusCode / default 500
 *
 * @example
 *   try {
 *     b.csv.parse(badInput);
 *   } catch (err) {
 *     var problem = b.problemDetails.fromError(err, {
 *       instance: "/audit/" + req.auditId,
 *     });
 *     b.problemDetails.respond(res, problem);
 *   }
 */
function fromError(err, opts2) {
  if (!err || typeof err !== "object") {
    throw new ProblemDetailsError("problem-details/bad-error",
      "fromError: err must be a non-null object", true);
  }
  opts2 = opts2 || {};
  if (typeof opts2 !== "object" || Array.isArray(opts2)) {
    throw new ProblemDetailsError("problem-details/bad-opts",
      "fromError: opts must be an object when provided", true);
  }
  var code = typeof err.code === "string" && err.code.length > 0 ? err.code : "internal-error";
  // Sanitize the code into a URI-safe path segment. RFC 3986
  // unreserved chars + `/` for the namespace separator.
  var typeUri = STATE.baseUri + "/" + code.replace(/[^A-Za-z0-9\-._/]/g, "-");

  // Derived title: error.name humanized (CsvError → "Csv Error"),
  // or operator override.
  var title;
  if (typeof opts2.title === "string" && opts2.title.length > 0) {
    title = opts2.title;
  } else if (typeof err.name === "string" && err.name.length > 0) {
    title = err.name
      .replace(/Error$/, " Error")
      .replace(/([a-z])([A-Z])/g, "$1 $2")
      .trim();
  } else {
    title = "Error";
  }

  // Status: opt override > err.statusCode > 500.
  var status;
  if (opts2.status !== undefined) {
    status = opts2.status;
  } else if (typeof err.statusCode === "number" && Number.isInteger(err.statusCode) &&
             err.statusCode >= 100 && err.statusCode <= 599) {                                     // HTTP status range
    status = err.statusCode;
  } else {
    status = 500;                                                                                  // default HTTP status 500 (Internal Server Error)
  }

  var built = {
    type:   typeUri,
    title:  title,
    status: status,
    detail: typeof err.message === "string" ? err.message : String(err),
  };
  if (typeof opts2.instance === "string" && opts2.instance.length > 0) {
    built.instance = opts2.instance;
  }
  return create(built);
}

/**
 * @primitive b.problemDetails.respond
 * @signature b.problemDetails.respond(res, problem, req?)
 * @since     0.8.84
 * @status    stable
 * @related   b.problemDetails.create, b.problemDetails.fromError
 *
 * Write a problem-details object to the response with the correct
 * RFC 9457 §3 content type (`application/problem+json`). Sets
 * `Cache-Control: no-store` (RFC 9111 §5.2.2.5 — error responses
 * are individualized) and writes the JSON body. Status code is
 * taken from `problem.status` (or 500 when missing). Throws
 * `problem-details/bad-res` for non-response objects; throws
 * `problem-details/bad-problem` for non-object problem inputs.
 *
 * @example
 *   var problem = b.problemDetails.create({
 *     type:   "https://blamejs.com/problems/csv/invalid-record",
 *     title:  "CSV record validation failed",
 *     status: 400,
 *     detail: "Row 3 column 5 has an unterminated quoted field",
 *   });
 *   b.problemDetails.respond(res, problem);
 *   // res.headers:  Content-Type: application/problem+json
 *   //               Cache-Control: no-store
 *   // res.body:     <JSON-stringified problem>
 *   // res.statusCode: 400
 */
function respond(res, problem, req) {
  validateOpts.requireMethods(res, ["setHeader", "end"],
    "respond: res (HTTP response object)", ProblemDetailsError, "problem-details/bad-res", true);
  if (!problem || typeof problem !== "object" || Array.isArray(problem)) {
    throw new ProblemDetailsError("problem-details/bad-problem",
      "respond: problem must be a non-null object", true);
  }
  var status = (typeof problem.status === "number" && Number.isInteger(problem.status) &&
                problem.status >= 100 && problem.status <= 599) ? problem.status : 500;            // HTTP status range + default 500
  var body = JSON.stringify(problem);
  // Seal the problem body when an encrypted session is active — the
  // encoder is present only after a request body decrypted, so its
  // envelope decrypts identically on the client. Pre-session paths
  // leave req/encoder absent and keep plaintext problem+json. An
  // encryption failure falls back to plaintext rather than crashing.
  var contentType = "application/problem+json";
  if (req && typeof req.apiEncryptEncode === "function") {
    try {
      body = JSON.stringify(req.apiEncryptEncode(problem));
      contentType = "application/json";
    } catch (_e) { /* keep plaintext problem+json */ }
  }
  res.statusCode = status;
  res.setHeader("Content-Type", contentType);
  res.setHeader("Cache-Control", "no-store");
  res.end(body);
}

/**
 * @primitive b.problemDetails.send
 * @signature b.problemDetails.send(res, fields)
 * @since     0.9.41
 * @status    stable
 * @related   b.problemDetails.create, b.problemDetails.respond
 *
 * Build + emit a problem-details response in one call. Equivalent
 * to `respond(res, create(fields))` but lets routes migrate
 * incrementally from inline `res.status(400).json({ error: "..." })`
 * shapes without restructuring the handler around an error throw.
 *
 * The same RFC 9457 §3 `application/problem+json` content type +
 * `Cache-Control: no-store` are written; status code defaults to
 * 500 when omitted.
 *
 * `extensions` keys are spread as top-level sibling members (RFC 9457
 * §3.2) via `create` — the literal `extensions` member is never
 * emitted. Keys colliding with the reserved `type` / `title` /
 * `status` / `detail` / `instance` are ignored; prototype-pollution-
 * shaped keys are dropped. A direct top-level key wins over the same
 * name nested under `extensions`.
 *
 * @opts
 *   status:    number,           // HTTP status code (100..599); default 500
 *   title:     string,           // operator-supplied short title
 *   detail:    string,           // operator-supplied human-readable explanation
 *   type:      string,           // problem-type URI (defaults to "about:blank")
 *   instance:  string,           // optional per-occurrence URI
 *   extensions: object,          // keys spread as top-level siblings (§3.2); direct top-level key wins on collision
 *
 * @example
 *   // Migrating from inline JSON-error shape:
 *   //   res.status(400).json({ error: "Missing 'name' field" });
 *   // to RFC 9457 problem-details:
 *   b.problemDetails.send(res, {
 *     status: 400,
 *     title:  "Missing required field",
 *     detail: "Body field 'name' is required",
 *   });
 */
function send(res, fields) {
  if (!fields || typeof fields !== "object" || Array.isArray(fields)) {
    throw new ProblemDetailsError("problem-details/bad-fields",
      "send: fields must be a non-null object", true);
  }
  return respond(res, create(fields));
}

/**
 * @primitive b.problemDetails.validate
 * @signature b.problemDetails.validate(doc)
 * @since     0.8.84
 * @status    stable
 * @related   b.problemDetails.create
 *
 * Validate an INBOUND problem-details document (e.g. one received
 * from an upstream API). Returns the doc unchanged on success;
 * throws `problem-details/bad-inbound` on shape violations. Useful
 * when blamejs is the client of a RFC 9457-compliant upstream
 * service — converts a "looks JSON-ish" response into a verified
 * problem object before reading fields.
 *
 *   - Refuses non-object input.
 *   - Refuses `status` outside 100..599 or non-integer.
 *   - Refuses `type` / `title` / `detail` / `instance` of non-string
 *     shape when present.
 *   - Refuses prototype-pollution-shaped extension keys.
 *
 * @example
 *   var rsp = await fetch(url);
 *   if (rsp.headers.get("content-type") === "application/problem+json") {
 *     var doc = b.problemDetails.validate(await rsp.json());
 *     console.log(doc.title, doc.status, doc.detail);
 *   }
 */
function validate(doc) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new ProblemDetailsError("problem-details/bad-inbound",
      "validate: doc must be a non-null object", true);
  }
  validateOpts.optionalNonEmptyString(
    doc.type, "validate.type", ProblemDetailsError, "problem-details/bad-inbound");
  if (doc.title !== undefined && typeof doc.title !== "string") {
    throw new ProblemDetailsError("problem-details/bad-inbound",
      "validate: title must be a string when present", true);
  }
  if (doc.status !== undefined) {
    if (typeof doc.status !== "number" || !Number.isInteger(doc.status) ||
        doc.status < 100 || doc.status > 599) {                                                    // HTTP status range
      throw new ProblemDetailsError("problem-details/bad-inbound",
        "validate: status must be an integer 100..599 when present", true);
    }
  }
  if (doc.detail !== undefined && typeof doc.detail !== "string") {
    throw new ProblemDetailsError("problem-details/bad-inbound",
      "validate: detail must be a string when present", true);
  }
  validateOpts.optionalNonEmptyString(
    doc.instance, "validate.instance", ProblemDetailsError, "problem-details/bad-inbound");
  // Refuse prototype-pollution shape in keys.
  var keys = Object.keys(doc);
  for (var i = 0; i < keys.length; i += 1) {
    if (POISONED_KEYS.indexOf(keys[i]) !== -1) {
      throw new ProblemDetailsError("problem-details/bad-inbound",
        "validate: doc key '" + keys[i] + "' refused (prototype-pollution shape)", true);
    }
  }
  return doc;
}

// Boundary helper for resetting test state between cases.
function _resetForTest() {
  STATE.baseUri = "https://blamejs.com/problems";
}

module.exports = {
  setBase:    setBase,
  getBase:    getBase,
  create:     create,
  fromError:  fromError,
  respond:    respond,
  send:       send,
  validate:   validate,
  RESERVED_FIELDS:     RESERVED_FIELDS,
  ProblemDetailsError: ProblemDetailsError,
  _resetForTest:       _resetForTest,
};

